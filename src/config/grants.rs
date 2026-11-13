//! What approving a project config grants, read off the resolved configuration rather than the
//! text: the same project resolved twice — before and after the approval — and compared on every
//! field the trust gate holds back.
//!
//! The text diff `sbx trust` prints says which lines changed. It does not say what they open: a
//! `*.amazonaws.com` reads like any other line, and a `[secret]` aimed at a new host reads like a
//! comment. This module answers in the policy's own terms, through the resolution engine a launch
//! uses, so the answer cannot describe a policy the launch would not apply.
//!
//! Every [`Grant`] carries a [`Risk`]. The risks are heuristics over the shape of what is granted,
//! never a verdict: nothing here refuses anything, and the decision stays with whoever approves.

use std::collections::BTreeSet;

use super::{GuiPolicy, NetworkPolicy, Resolved};
use crate::allowlist::{DefaultAction, EgressPolicy, Layer, Ports, Reservation, Rule, RuleKind};
use crate::proc_policy::{ProcMode, ProcPolicy};
use crate::sandbox::{AddrRefusal, ip_refusal};

/// How much attention one grant deserves, most first. Ordered so a sorted list leads with the
/// grants a reviewer must not miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Risk {
    /// Hands the cage something that is hard to take back: a credential's new destination, a
    /// writable host path, an unfiltered network, a syscall back.
    High,
    /// Opens a named hole whose cost is written beside it.
    Notable,
    /// A grant worth seeing, with no shape that calls for more.
    Info,
}

/// One thing the approval grants that the configuration before it did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    /// The app overlay the grant belongs to, or `None` for the baseline every launch gets.
    pub(crate) app: Option<String>,
    /// The configuration field, as the config spells it: `network`, `secret`, `binds`, …
    pub(crate) field: &'static str,
    /// What is granted, as the policy displays it: a rule, a path, a port, a key.
    pub(crate) what: String,
    pub(crate) risk: Risk,
    /// Why it carries that risk, in a few words, each trait it shows comma-separated. Empty when the
    /// grant is plain.
    pub(crate) why: String,
}

/// Ports a database, cache or search engine listens on by default. A heuristic: a rule naming one
/// probably reaches a service that was not meant to face the cage.
const SERVICE_PORTS: [u16; 6] = [3306, 5432, 6379, 9200, 11211, 27017];

/// The first port of the ephemeral range, past which a port rarely carries a public service.
const EPHEMERAL_FROM: u16 = 49152;

/// What `after` grants that `before` did not, for the baseline and for every app overlay `after`
/// declares, ordered by risk.
///
/// An app's grants are computed on the app as it launches — the baseline with the overlay folded on
/// — and those the baseline already lists are left out, so a grant is named once, where it lands.
pub(crate) fn grants(before: &Resolved, after: &Resolved) -> Vec<Grant> {
    let mut out = Vec::new();
    delta(before, after, None, &mut out);
    let baseline: BTreeSet<(&'static str, String)> =
        out.iter().map(|g| (g.field, g.what.clone())).collect();
    for (name, app) in &after.apps {
        let mut was = before.clone();
        if let Some(old) = before.apps.get(name) {
            was.merge_app(old.clone());
        }
        let mut now = after.clone();
        now.merge_app(app.clone());
        let mut own = Vec::new();
        delta(&was, &now, Some(name), &mut own);
        if before.apps.get(name).is_none_or(|old| old.cmd != app.cmd) && !app.cmd.is_empty() {
            own.push(grant(
                Some(name),
                "cmd",
                app.cmd.join(" "),
                Risk::Info,
                "the command the app runs",
            ));
        }
        out.extend(
            own.into_iter()
                .filter(|g| !baseline.contains(&(g.field, g.what.clone()))),
        );
    }
    sort_grants(&mut out);
    out
}

/// A [`Grant`] built from its parts, the app borrowed as [`delta`] holds it.
fn grant(app: Option<&String>, field: &'static str, what: String, risk: Risk, why: &str) -> Grant {
    Grant {
        app: app.cloned(),
        field,
        what,
        risk,
        why: why.to_string(),
    }
}

/// The grants of one resolution over another, field by field.
///
/// The destructuring is exhaustive on purpose: a field added to [`Resolved`] fails to compile here
/// until it is classified, so a new security field cannot reach a launch without the review naming
/// it. A field named `_` was weighed and grants nothing: it is free, a display affordance, the
/// global layer's alone, or I/O the pure resolution leaves empty.
fn delta(before: &Resolved, after: &Resolved, app: Option<&String>, out: &mut Vec<Grant>) {
    let Resolved {
        env: _,
        env_layer: _,
        binds,
        bind_layer: _,
        packages,
        accepts_fresh_releases,
        apps_share_install_pools,
        apps_share_install_pools_origin: _,
        apps_read_project_pool,
        apps_read_project_pool_origin: _,
        plugin,
        open,
        service,
        provisions: _,
        nixpkgs_global: _,
        mise_engine: _,
        nixpkgs_project,
        mise: _,
        mise_ignored: _,
        network,
        network_origin: _,
        net_groups: _,
        egress_stats,
        egress_stats_origin: _,
        proc,
        proc_origin: _,
        notify,
        notify_origin: _,
        gui,
        gui_origin: _,
        distro,
        distro_run,
        distro_auth,
        distro_origin: _,
        timezone: _,
        timezone_origin: _,
        gpu,
        gpu_origin: _,
        allow_insecure_http,
        allow_insecure_http_origin: _,
        audio,
        audio_origin: _,
        dbus,
        dbus_origin: _,
        forward,
        forward_origin: _,
        limits,
        limits_origin: _,
        seccomp,
        seccomp_origin: _,
        devices,
        devices_origin: _,
        fs,
        fs_origin: _,
        ssh_agent,
        ssh_agent_origin: _,
        brokers,
        ssh_agent_confirm,
        ssh_agent_confirm_origin: _,
        redact_min_len,
        redact_min_len_origin: _,
        observe_record,
        observe_record_origin: _,
        secrets,
        declared_secrets: _,
        tasks,
        apps: _,
        warnings: _,
        refusals: _,
    } = after;
    let mut push = |field: &'static str, what: String, risk: Risk, why: &str| {
        out.push(grant(app, field, what, risk, why))
    };

    for bind in binds {
        let was = before.binds.iter().find(|b| b.path == bind.path);
        let path = bind.path.display();
        match (was, bind.writable) {
            (None, true) => push(
                "binds",
                format!("{path} (rw)"),
                Risk::High,
                "writable from the cage",
            ),
            (None, false) => push(
                "binds",
                format!("{path} (ro)"),
                Risk::Notable,
                "readable from the cage",
            ),
            (Some(b), true) if !b.writable => push(
                "binds",
                format!("{path} (rw)"),
                Risk::High,
                "now writable from the cage",
            ),
            _ => {}
        }
    }

    // A package from an untrusted layer is carried with its verdict and never provisioned, so only
    // a trusted one is something the approval grants.
    let provisioned = |p: &&super::Package| p.state == crate::trust::TrustState::Trusted;
    for package in packages.iter().filter(provisioned) {
        let had = before
            .packages
            .iter()
            .filter(provisioned)
            .any(|p| p.name == package.name && p.backend == package.backend);
        if !had {
            push(
                "packages",
                package.name.clone(),
                Risk::Info,
                "built or fetched for the cage",
            );
        }
    }
    for name in accepts_fresh_releases {
        if !before.accepts_fresh_releases.contains(name) {
            push(
                "accepts_fresh_releases",
                name.clone(),
                Risk::Notable,
                "installs a release with no cooling-off delay",
            );
        }
    }
    if *apps_share_install_pools && !before.apps_share_install_pools {
        push(
            "[apps] share_install_pools",
            "true".into(),
            Risk::Notable,
            "one app can place a program another runs",
        );
    }
    if *apps_read_project_pool && !before.apps_read_project_pool {
        push(
            "[apps] read_project_pool",
            "true".into(),
            Risk::Notable,
            "the project's `sbx run` shell can place a program its apps run",
        );
    }
    for (name, settings) in plugin {
        if before.plugin.get(name) != Some(settings) {
            push(
                "plugin",
                name.clone(),
                Risk::Info,
                "resolver plugin settings",
            );
        }
    }
    for (scheme, handler) in open {
        if before.open.get(scheme) != Some(handler) {
            push(
                "open",
                scheme.clone(),
                Risk::Notable,
                "decides what runs when a link is opened",
            );
        }
    }
    for (name, spec) in service {
        if before.service.get(name) != Some(spec) {
            push(
                "service",
                name.clone(),
                Risk::Notable,
                "runs at every launch",
            );
        }
    }
    if nixpkgs_project.is_some() && *nixpkgs_project != before.nixpkgs_project {
        let source = nixpkgs_project.clone().unwrap_or_default();
        push(
            "nixpkgs",
            source,
            Risk::Info,
            "the source the project's tools are built from",
        );
    }

    network_grants(&before.network, network, secrets, &mut push);

    if !*egress_stats && before.egress_stats {
        push(
            "network",
            "stats = false".into(),
            Risk::Notable,
            "egress counters off",
        );
    }
    proc_grants(&before.proc, proc, &mut push);
    if *notify != before.notify {
        push(
            "notify",
            "changed".into(),
            Risk::Info,
            "which refusals are announced",
        );
    }
    if gui_rank(*gui) > gui_rank(before.gui) {
        let what = match gui {
            GuiPolicy::Wayland => "wayland",
            GuiPolicy::Offscreen => "offscreen",
            GuiPolicy::None => "none",
        };
        push("gui", what.into(), Risk::Notable, "display access");
    }
    if (distro, distro_run, distro_auth)
        != (&before.distro, &before.distro_run, &before.distro_auth)
        && let Some(locator) = distro
    {
        push(
            "distro",
            locator.clone(),
            Risk::Info,
            "the userland every program comes from",
        );
    }
    for (on, was, field, why) in [
        (
            *gpu,
            before.gpu,
            "gpu",
            "render node and the /sys device tree",
        ),
        (
            *audio,
            before.audio,
            "audio",
            "microphone and every playback stream",
        ),
        (*dbus, before.dbus, "dbus", "an in-cage desktop portal"),
        (
            *allow_insecure_http,
            before.allow_insecure_http,
            "allow_insecure_http",
            "packages may arrive over plaintext http",
        ),
    ] {
        if on && !was {
            push(field, "true".into(), Risk::Notable, why);
        }
    }
    for port in forward {
        if !before.forward.contains(port) {
            push(
                "forward",
                port.to_string(),
                Risk::Notable,
                "host loopback port, reachable by every local user",
            );
        }
    }
    for (name, now, was) in [
        (
            "memory_high",
            &limits.memory_high,
            &before.limits.memory_high,
        ),
        ("memory_max", &limits.memory_max, &before.limits.memory_max),
        ("tasks_max", &limits.tasks_max, &before.limits.tasks_max),
    ] {
        if now != was
            && let Some(value) = now
        {
            push(
                "limits",
                format!("{name} = {value}"),
                Risk::Notable,
                "resource limit changed",
            );
        }
    }
    let lifted = before.seccomp.tokens();
    for token in seccomp.tokens() {
        if !lifted.contains(&token) {
            push("seccomp", token, Risk::High, "syscall re-permitted");
        }
    }
    for device in devices {
        if !before.devices.contains(device) {
            push(
                "devices",
                device.display().to_string(),
                Risk::Notable,
                "host device",
            );
        }
    }
    for (was, now, list) in [
        (&before.fs.deny, &fs.deny, "deny"),
        (&before.fs.readonly, &fs.readonly, "readonly"),
        (&before.fs.scan, &fs.scan, "scan"),
    ] {
        for entry in was.iter().filter(|e| !now.contains(e)) {
            push(
                "fs",
                format!("{list} {entry}"),
                Risk::Notable,
                "a closed path reopens",
            );
        }
    }
    if fs.git_writable == Some(true) && before.fs.git_writable != Some(true) {
        push(
            "fs",
            "git_writable = true".into(),
            Risk::Notable,
            "git hooks writable",
        );
    }
    for key in ssh_agent {
        if !before.ssh_agent.contains(key) {
            push(
                "ssh_agent",
                key.clone(),
                Risk::High,
                "a key the cage can sign with",
            );
        }
    }
    if !*ssh_agent_confirm && before.ssh_agent_confirm {
        push(
            "ssh_agent",
            "confirm = false".into(),
            Risk::Notable,
            "signatures no longer confirmed",
        );
    }
    for broker in brokers {
        if !before.brokers.contains(broker) {
            push(
                "broker",
                broker.name.clone(),
                Risk::Notable,
                "a plugin holds a host connection",
            );
        }
    }
    if redact_min_len > &before.redact_min_len {
        push(
            "redact",
            format!("min_len = {redact_min_len}"),
            Risk::Notable,
            "shorter credentials leave the redaction",
        );
    }
    if *observe_record != before.observe_record {
        push(
            "observe",
            format!("record = {observe_record}"),
            Risk::Info,
            "session record",
        );
    }
    for secret in secrets {
        match before.secrets.iter().find(|s| s.to == secret.to) {
            None => push(
                "secret",
                format!("{} ({})", secret.to, secret.header),
                Risk::High,
                "a credential is injected here",
            ),
            Some(was) if was != secret => match by_change(was, secret) {
                Some(ByChange::Narrowed) => {}
                Some(ByChange::Widened(what, risk, why)) => push(
                    "secret",
                    format!("{} ({}) {what}", secret.to, secret.header),
                    risk,
                    why,
                ),
                None => push(
                    "secret",
                    format!("{} ({})", secret.to, secret.header),
                    Risk::High,
                    "credential source or shape changed",
                ),
            },
            Some(_) => {}
        }
    }
    for task in tasks {
        if !before.tasks.contains(task) {
            push(
                "task",
                task.name.clone(),
                Risk::Notable,
                "a declared operation",
            );
        }
    }
}

/// The tools the project's mise files declare in `after` that `before` did not: a tool new to the
/// files, or one whose requested version changed, each something the cage will install. `None` is
/// the first approval, over a project whose mise files no launch honors yet.
///
/// Only the `[tools]` of each file are read, through the parser provisioning uses
/// ([`parse_nix_tools`](crate::sandbox::nixhub::parse_nix_tools)); the sops files the inputs also
/// carry are skipped. A file that does not parse is a grant of its own, since what it declares is
/// unknown rather than nothing.
pub(crate) fn mise_grants(
    before: Option<&crate::trust::TrustInputs>,
    after: &crate::trust::TrustInputs,
) -> Vec<Grant> {
    let tools = |inputs: &crate::trust::TrustInputs| {
        let mise: Vec<(String, Vec<u8>)> = inputs
            .iter()
            .filter(|(name, _)| !name.starts_with(crate::trust::SOPS_TAG_PREFIX))
            .cloned()
            .collect();
        let declared = crate::sandbox::nixhub::parse_nix_tools(&mise);
        let named = declared
            .nix
            .iter()
            .map(|t| format!("nix:{}@{}", t.pkg, t.version))
            .chain(
                declared
                    .non_nix
                    .iter()
                    .map(|t| format!("{}@{}", t.token, t.version)),
            );
        (named.collect::<BTreeSet<String>>(), declared.unparsed)
    };
    let (had, _) = before.map(tools).unwrap_or_default();
    let (now, unparsed) = tools(after);
    let mut out: Vec<Grant> = now
        .difference(&had)
        .map(|tool| {
            grant(
                None,
                "mise",
                tool.clone(),
                Risk::Info,
                "installed for the cage",
            )
        })
        .collect();
    out.extend(unparsed.into_iter().map(|file| {
        grant(
            None,
            "mise",
            file,
            Risk::Notable,
            "what this file declares is unknown",
        )
    }));
    out
}

/// Order grants most serious first, then baseline before apps, then by field and what, and drop
/// a grant listed twice. The one order every list of grants is shown in.
pub(crate) fn sort_grants(grants: &mut Vec<Grant>) {
    grants.sort_by(|a, b| {
        (a.risk, &a.app, a.field, &a.what).cmp(&(b.risk, &b.app, b.field, &b.what))
    });
    grants.dedup();
}

/// The grants of one network posture over another. Only a widening is a grant: moving to
/// `isolated`, or off `shared`, takes reach away.
fn network_grants(
    before: &NetworkPolicy,
    after: &NetworkPolicy,
    secrets: &[super::HeaderSecret],
    push: &mut impl FnMut(&'static str, String, Risk, &str),
) {
    match (before, after) {
        (NetworkPolicy::Shared, _) | (_, NetworkPolicy::Isolated) => {}
        (_, NetworkPolicy::Shared) => push(
            "network",
            "shared".into(),
            Risk::High,
            "the host network, unfiltered",
        ),
        (NetworkPolicy::Isolated, NetworkPolicy::Allowlist(now)) => {
            policy_grants(None, now, secrets, push)
        }
        (NetworkPolicy::Allowlist(was), NetworkPolicy::Allowlist(now)) => {
            policy_grants(Some(was), now, secrets, push)
        }
    }
}

/// The grants of one egress policy over another (`None`: over no egress at all). The built-in
/// self-equip set is every policy's, so it is never something an approval grants.
fn policy_grants(
    before: Option<&EgressPolicy>,
    after: &EgressPolicy,
    secrets: &[super::HeaderSecret],
    push: &mut impl FnMut(&'static str, String, Risk, &str),
) {
    let was_open = before.is_some_and(|b| b.default_action() == DefaultAction::Allow);
    if after.default_action() == DefaultAction::Allow && !was_open {
        push(
            "network",
            "mode = allow".into(),
            Risk::High,
            "everything not denied is reachable",
        );
    }
    for rule in after.allow_rules() {
        if rule.builtin || before.is_some_and(|b| b.allow_rules().contains(rule)) {
            continue;
        }
        let (risk, mut why) = rule_risk(rule, secrets);
        // A reserved destination opens to its named programs only, which the reviewer is told
        // rather than left to find under `[network.reserve]`.
        let only = reservation_of(after, rule).map(|r| format!("only for {}", r.by().join(", ")));
        why.extend(only.as_deref());
        push("network", format!("allow {rule}"), risk, &why.join(", "));
    }
    if let Some(before) = before {
        for rule in before.deny_rules() {
            if !after.deny_rules().contains(rule) {
                push(
                    "network",
                    format!("deny {rule}"),
                    Risk::Notable,
                    "a refusal is lifted",
                );
            }
        }
        // What still reaches a destination once its reservation is lifted: a posture that does not
        // refuse by default (`allow` admits it, `ask` lets a person admit any program), or an
        // `allow` rule, the built-in self-equip set's included, reaching some of it for any verb,
        // path or plane.
        let builtin = crate::sandbox::builtin_allow_rules();
        let still_reached = |was: &Reservation| {
            after.default_action() != DefaultAction::Deny
                || after
                    .allow_rules()
                    .iter()
                    .chain(&builtin)
                    .any(|r| was.opened_by(r))
        };
        for was in before.reserved() {
            let rule = was.rule();
            match reservation_of(after, rule) {
                // Lifted while the destination is still reached: that part opens to everyone.
                // Lifted with its destination closed, it grants nothing.
                None if still_reached(was) => push(
                    "network",
                    format!("reserve {rule}"),
                    Risk::High,
                    "a destination reserved for named programs opens to every program",
                ),
                None => {}
                Some(now) => {
                    let added: Vec<&str> = now
                        .by()
                        .iter()
                        .filter(|p| !was.by().contains(p))
                        .map(String::as_str)
                        .collect();
                    if !added.is_empty() {
                        push(
                            "network",
                            format!("reserve {rule} by {}", added.join(", ")),
                            Risk::Notable,
                            "more programs may reach a reserved destination",
                        );
                    }
                }
            }
        }
    }
}

/// How a credential changed when only the programs it is held for did.
enum ByChange {
    /// Held for fewer programs, or refusing the others where it let them through: nothing opens.
    Narrowed,
    /// Held for more programs, or letting the others through: what changed, and how far.
    Widened(String, Risk, &'static str),
}

/// The change from `was` to `now` when nothing but `by` and `by_other` differ, or `None` when
/// anything else did.
fn by_change(was: &super::HeaderSecret, now: &super::HeaderSecret) -> Option<ByChange> {
    let only_by = super::HeaderSecret {
        by: was.by.clone(),
        by_other: was.by_other,
        ..now.clone()
    } == *was;
    if !only_by {
        return None;
    }
    let added: Vec<&str> = now
        .by
        .iter()
        .filter(|p| !was.by.contains(p))
        .map(String::as_str)
        .collect();
    Some(if !was.by.is_empty() && now.by.is_empty() {
        ByChange::Widened(
            "by removed".to_string(),
            Risk::High,
            "the credential goes to every program",
        )
    } else if !was.by.is_empty() && !added.is_empty() {
        ByChange::Widened(
            format!("by {}", added.join(", ")),
            Risk::High,
            "the credential goes to more programs",
        )
    } else if was.by_other == crate::config::ByOther::Deny
        && now.by_other == crate::config::ByOther::Bare
        && !now.by.is_empty()
    {
        ByChange::Widened(
            "by_other = bare".to_string(),
            Risk::Notable,
            "other programs reach the host without the credential instead of being refused",
        )
    } else {
        ByChange::Narrowed
    })
}

/// The reservation of `policy` whose destination is `rule`'s, compared by host and port alone: an
/// app's `default_methods` rewrites the method set of the `allow` rule a reservation added, never
/// the destination, and a reservation covers its destination on every plane.
fn reservation_of<'a>(policy: &'a EgressPolicy, rule: &Rule) -> Option<&'a Reservation> {
    policy
        .reserved()
        .iter()
        .find(|r| r.rule().kind == rule.kind)
}

/// The risk of one newly allowed egress rule and every trait that earns it, most serious first: a
/// rule can be a raw splice to a private address on a database port, and a reviewer reading only
/// the first would not know the other two.
fn rule_risk(rule: &Rule, secrets: &[super::HeaderSecret]) -> (Risk, Vec<&'static str>) {
    let mut traits: Vec<(Risk, &'static str)> = Vec::new();
    let every_host = rule.opens_every_host();
    if every_host {
        traits.push((Risk::High, "matches every host"));
    }
    if secrets
        .iter()
        .filter_map(|s| s.to.concrete_host())
        .any(|host| reaches(rule, host))
    {
        traits.push((Risk::High, "widens what an injected credential can do"));
    }
    match rule.layer {
        Layer::L4 => traits.push((Risk::Notable, "raw TCP, not inspected")),
        Layer::L7Clear => traits.push((Risk::Notable, "cleartext HTTP")),
        Layer::L7 => {}
    }
    let ports = match &rule.kind {
        RuleKind::Regex { .. } => {
            if !every_host {
                traits.push((Risk::Notable, "a regex over the whole URL"));
            }
            None
        }
        RuleKind::Subdomain(_, ports) => {
            traits.push((Risk::Notable, "every subdomain"));
            Some(ports)
        }
        RuleKind::Ip(ip, ports) => {
            if matches!(
                ip_refusal(*ip, "", None),
                Some(AddrRefusal::PrivateWithoutExactHost)
            ) {
                traits.push((Risk::Notable, "a private address"));
            }
            Some(ports)
        }
        RuleKind::Host(_, ports) | RuleKind::Url { ports, .. } => Some(ports),
    };
    if ports.is_some_and(reaches_service_port) {
        traits.push((Risk::Notable, "a port an internal service listens on"));
    }
    let risk = traits
        .iter()
        .map(|(risk, _)| *risk)
        .min()
        .unwrap_or(Risk::Info);
    (risk, traits.into_iter().map(|(_, why)| why).collect())
}

/// Whether `rule` reaches `host` by name: names it, or is a `*.domain` it falls under.
fn reaches(rule: &Rule, host: &str) -> bool {
    match &rule.kind {
        RuleKind::Host(h, _) | RuleKind::Url { host: h, .. } => h == host,
        RuleKind::Subdomain(domain, _) => host == domain || host.ends_with(&format!(".{domain}")),
        RuleKind::Ip(..) | RuleKind::Regex { .. } => false,
    }
}

/// Whether a port set admits any port past [`EPHEMERAL_FROM`] or any of [`SERVICE_PORTS`].
fn reaches_service_port(ports: &Ports) -> bool {
    match ports {
        Ports::Any => true,
        Ports::Ranges(ranges) => ranges.iter().any(|&(lo, hi)| {
            hi >= EPHEMERAL_FROM || SERVICE_PORTS.iter().any(|p| (lo..=hi).contains(p))
        }),
    }
}

/// The grants of one process posture over another: a mode that enforces less, a program no longer
/// refused, or one that now runs without being asked about.
fn proc_grants(
    before: &ProcPolicy,
    after: &ProcPolicy,
    push: &mut impl FnMut(&'static str, String, Risk, &str),
) {
    if proc_rank(after.mode) < proc_rank(before.mode) {
        push(
            "proc",
            format!("mode = {}", after.mode.as_str()),
            Risk::Notable,
            "process enforcement loosened",
        );
    }
    for rule in &before.deny {
        if !after.deny.contains(rule) {
            push(
                "proc",
                format!("deny {}", rule.as_str()),
                Risk::Notable,
                "may now run",
            );
        }
    }
    if matches!(after.mode, ProcMode::Ask | ProcMode::Confine) {
        for rule in &after.allow {
            if !before.allow.contains(rule) {
                push(
                    "proc",
                    format!("allow {}", rule.as_str()),
                    Risk::Info,
                    "runs without asking",
                );
            }
        }
    }
}

/// How much a process mode enforces, least first.
fn proc_rank(mode: ProcMode) -> u8 {
    match mode {
        ProcMode::Off => 0,
        ProcMode::Observe => 1,
        ProcMode::Enforce => 2,
        ProcMode::Ask => 3,
        ProcMode::Confine => 4,
    }
}

/// How much of the host display a GUI posture exposes, least first.
fn gui_rank(gui: GuiPolicy) -> u8 {
    match gui {
        GuiPolicy::None => 0,
        GuiPolicy::Offscreen => 1,
        GuiPolicy::Wayland => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::{self, RawConfig};
    use crate::plugins::PluginRegistry;
    use crate::trust::TrustState;

    /// One project layer over an empty global config, under `state`.
    fn resolved(toml: &str, state: TrustState) -> Resolved {
        let raw = schema::parse_layer(toml.as_bytes(), &mut Vec::new()).expect("a valid layer");
        super::super::resolve(
            RawConfig::default(),
            Some((raw, state)),
            &PluginRegistry::default(),
        )
    }

    /// What approving `after` grants over an approved `before`.
    fn over(before: &str, after: &str) -> Vec<Grant> {
        grants(
            &resolved(before, TrustState::Trusted),
            &resolved(after, TrustState::Trusted),
        )
    }

    /// The grants as `(field, what, risk)`, the shape the assertions read.
    fn seen(grants: &[Grant]) -> Vec<(&'static str, &str, Risk)> {
        grants
            .iter()
            .map(|g| (g.field, g.what.as_str(), g.risk))
            .collect()
    }

    #[test]
    fn a_change_to_a_free_field_or_a_comment_grants_nothing() {
        let before = "[network]\nmode = \"deny\"\nallow = [\"example.com\"]\n";
        let after = "# reworded\n[env]\nA = \"1\"\n\n[network]\nmode = \"deny\"\nallow = [\"example.com\"]\n";
        assert_eq!(over(before, after), vec![]);
    }

    #[test]
    fn a_bind_is_high_when_writable_and_notable_when_read_only() {
        let got = over(
            "binds = [\"/srv/a\"]\n",
            "binds = [{ path = \"/srv/a\", mode = \"rw\" }, \"/srv/b\"]\n",
        );
        assert_eq!(
            seen(&got),
            vec![
                ("binds", "/srv/a (rw)", Risk::High),
                ("binds", "/srv/b (ro)", Risk::Notable),
            ]
        );
    }

    #[test]
    fn each_new_egress_rule_carries_the_risk_of_its_shape() {
        let got = over(
            "[network]\nmode = \"deny\"\n",
            "[network]\nmode = \"deny\"\nallow = [\"example.com\", \"*.amazonaws.com\", \
             \"tcp://db.internal:5432\", \"10.0.0.5\", \"example.org:6379\", \"re:.*\"]\n",
        );
        let risk = |what: &str| {
            got.iter()
                .find(|g| g.what.contains(what))
                .map(|g| (g.risk, g.why.as_str()))
                .unwrap_or_else(|| panic!("no grant for {what}: {got:?}"))
        };
        assert_eq!(risk("re:.*"), (Risk::High, "matches every host"));
        assert_eq!(risk("amazonaws"), (Risk::Notable, "every subdomain"));
        assert_eq!(
            risk("db.internal"),
            (
                Risk::Notable,
                "raw TCP, not inspected, a port an internal service listens on"
            )
        );
        assert_eq!(risk("10.0.0.5"), (Risk::Notable, "a private address"));
        assert_eq!(
            risk("example.org"),
            (Risk::Notable, "a port an internal service listens on")
        );
        assert_eq!(risk("example.com"), (Risk::Info, ""));
    }

    #[test]
    fn a_credential_and_any_new_reach_to_its_host_are_high() {
        let secret = "[secret.\"api.github.com\"]\nfrom = \"env://GH\"\nheader = \"Authorization\"\n\
                      type = \"bearer\"\n";
        let before =
            format!("[network]\nmode = \"deny\"\nallow = [\"{{GET}} api.github.com\"]\n\n{secret}");
        let after = format!(
            "[network]\nmode = \"deny\"\nallow = [\"{{GET}} api.github.com\", \"{{POST}} api.github.com\"]\n\n{secret}"
        );
        let got = over(&before, &after);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].risk, Risk::High);
        assert_eq!(got[0].why, "widens what an injected credential can do");

        let none = "[network]\nmode = \"deny\"\nallow = [\"{GET} api.github.com\"]\n";
        let got = over(none, &before);
        assert_eq!(
            seen(&got),
            vec![(
                "secret",
                "https://api.github.com (Authorization)",
                Risk::High
            )]
        );
    }

    #[test]
    fn opening_the_network_is_high_and_closing_it_grants_nothing() {
        let filtered = "[network]\nmode = \"deny\"\nallow = [\"example.com\"]\n";
        assert_eq!(
            seen(&over(filtered, "network = \"shared\"\n")),
            vec![("network", "shared", Risk::High)]
        );
        assert_eq!(
            seen(&over(
                filtered,
                "[network]\nmode = \"allow\"\nallow = [\"example.com\"]\n"
            )),
            vec![("network", "mode = allow", Risk::High)]
        );
        assert_eq!(over("network = \"shared\"\n", filtered), vec![]);
        assert_eq!(over(filtered, "network = \"isolated\"\n"), vec![]);
    }

    #[test]
    fn a_lifted_deny_is_a_grant() {
        let got = over(
            "[network]\nmode = \"allow\"\ndeny = [\"telemetry.example.com\"]\n",
            "[network]\nmode = \"allow\"\n",
        );
        assert_eq!(
            seen(&got),
            vec![(
                "network",
                "deny https://telemetry.example.com",
                Risk::Notable
            )]
        );
    }

    /// A change to the programs a credential is held for is named as such: removing `by` or adding
    /// a program is High, letting the others through is Notable, and narrowing grants nothing.
    #[test]
    fn a_credential_held_for_more_programs_is_named_and_a_narrowed_one_is_not() {
        let secret = |by: &str| {
            format!(
                "[network]\nmode = \"deny\"\nallow = [\"api.github.com\"]\n\n\
                 [secret.\"api.github.com\"]\nfrom = \"env://GH\"\nheader = \"Authorization\"\n\
                 type = \"bearer\"\n{by}"
            )
        };
        let gh = secret("by = [\"gh\"]\nby_other = \"deny\"\n");
        let seen_one = |after: &str| {
            let got = over(&gh, after);
            assert_eq!(got.len(), 1, "{got:?}");
            (got[0].what.clone(), got[0].risk)
        };
        assert_eq!(
            seen_one(&secret("")),
            (
                "https://api.github.com (Authorization) by removed".to_string(),
                Risk::High
            )
        );
        assert_eq!(
            seen_one(&secret("by = [\"gh\", \"curl\"]\nby_other = \"deny\"\n")),
            (
                "https://api.github.com (Authorization) by curl".to_string(),
                Risk::High
            )
        );
        assert_eq!(
            seen_one(&secret("by = [\"gh\"]\n")),
            (
                "https://api.github.com (Authorization) by_other = bare".to_string(),
                Risk::Notable
            )
        );
        assert_eq!(over(&secret("by = [\"gh\"]\n"), &gh), vec![]);
        assert_eq!(
            over(
                &secret("by = [\"gh\", \"git\"]\nby_other = \"deny\"\n"),
                &gh
            ),
            vec![]
        );
    }

    #[test]
    fn a_lifted_or_widened_reservation_is_a_grant() {
        let reserved = "[network]\nmode = \"deny\"\nallow = [\"*.github.com\"]\n\n\
                        [network.reserve.\"codeload.github.com\"]\nby = [\"git\"]\n";
        let got = over(
            "[network]\nmode = \"deny\"\nallow = [\"*.github.com\"]\n",
            reserved,
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].what, "allow https://codeload.github.com");
        assert_eq!(got[0].why, "only for git");

        let got = over(
            reserved,
            "[network]\nmode = \"deny\"\nallow = [\"*.github.com\"]\n",
        );
        assert_eq!(
            seen(&got),
            vec![("network", "reserve https://codeload.github.com", Risk::High)]
        );

        let got = over(
            reserved,
            &reserved.replace("[\"git\"]", "[\"git\", \"curl\"]"),
        );
        assert_eq!(
            seen(&got),
            vec![(
                "network",
                "reserve https://codeload.github.com by curl",
                Risk::Notable
            )]
        );
    }

    /// A lifted reservation is a grant whatever shape the `allow` that still reaches it has: a verb
    /// set, `WS`, a path, a raw splice, the clear or a pattern each opens the destination to every
    /// program, and with no `allow` at all an `allow` or `ask` posture, or the built-in self-equip
    /// set, still reaches it. An `allow` for another host, or a host nothing reaches, leaves nothing
    /// to report. Every shape misread is reported together.
    #[test]
    fn a_lifted_reservation_is_a_grant_whatever_shape_the_allow_has() {
        let lifted = |allow: &str| {
            let base = format!("[network]\nmode = \"deny\"\nallow = [\"{allow}\"]\n");
            let reserved =
                format!("{base}\n[network.reserve.\"api.example.test\"]\nby = [\"git\"]\n");
            seen(&over(&reserved, &base))
                .into_iter()
                .map(|(field, what, risk)| (field, what.to_string(), risk))
                .collect::<Vec<_>>()
        };
        let high = vec![(
            "network",
            "reserve https://api.example.test".to_string(),
            Risk::High,
        )];
        assert_eq!(
            lifted("*.example.test"),
            high,
            "calibration: a wildcard over the host"
        );
        let mut wrong: Vec<String> = [
            "{GET} https://api.example.test",
            "{*,WS} https://api.example.test",
            "https://api.example.test/v1",
            "tcp://api.example.test:443",
            "http://api.example.test:443",
            "re:^https://api\\\\.example\\\\.test/",
        ]
        .into_iter()
        .filter(|allow| lifted(allow) != high)
        .map(|allow| format!("`{allow}` reports nothing"))
        .collect();
        if !lifted("https://other.test").is_empty() {
            wrong.push("an allow for another host reports a grant".to_string());
        }
        // No `allow` rule at all: the posture, or the built-in set, still reaches the host.
        let bare = |mode: &str, host: &str| {
            let base = format!("[network]\nmode = \"{mode}\"\n");
            let reserved = format!("{base}\n[network.reserve.\"{host}\"]\nby = [\"git\"]\n");
            seen(&over(&reserved, &base)).len()
        };
        for (mode, host) in [
            ("allow", "api.example.test"),
            ("ask", "api.example.test"),
            ("deny", "codeload.github.com"),
        ] {
            if bare(mode, host) != 1 {
                wrong.push(format!("`{host}` lifted under `{mode}` reports nothing"));
            }
        }
        if bare("deny", "api.example.test") != 0 {
            wrong.push("a host nothing reaches reports a grant".to_string());
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn the_built_in_self_equip_set_is_never_listed() {
        assert_eq!(
            over("network = \"isolated\"\n", "network = \"deny\"\n"),
            vec![]
        );
    }

    #[test]
    fn a_first_approval_lists_what_the_untrusted_resolution_held_back() {
        let toml = "forward = [1455]\n\n[ssh_agent]\nallow = [\"deploy\"]\n\n[seccomp]\nallow = [\"ptrace\"]\n";
        let got = grants(
            &resolved(toml, TrustState::Untrusted),
            &resolved(toml, TrustState::Trusted),
        );
        assert_eq!(
            seen(&got),
            vec![
                ("seccomp", "ptrace", Risk::High),
                ("ssh_agent", "deploy", Risk::High),
                ("forward", "1455", Risk::Notable),
            ]
        );
    }

    #[test]
    fn an_app_grant_is_named_under_the_app_and_a_baseline_one_once() {
        let before = "[app.demo]\ncmd = [\"bash\"]\n";
        let after = "binds = [\"/srv/a\"]\n\n[app.demo]\ncmd = [\"bash\"]\n\n[app.demo.network]\nmode = \"shared\"\n";
        let got = over(before, after);
        assert_eq!(
            got.iter()
                .map(|g| (g.app.as_deref(), g.field, g.what.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (Some("demo"), "network", "shared"),
                (None, "binds", "/srv/a (ro)"),
            ]
        );
    }

    #[test]
    fn a_rule_lists_every_trait_it_shows() {
        let got = over(
            "[network]\nmode = \"deny\"\n",
            "[network]\nmode = \"deny\"\nallow = [\"tcp://10.0.0.5:5432\"]\n",
        );
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].risk, Risk::Notable);
        assert_eq!(
            got[0].why,
            "raw TCP, not inspected, a private address, a port an internal service listens on"
        );
    }

    fn inputs(files: &[(&str, &str)]) -> crate::trust::TrustInputs {
        files
            .iter()
            .map(|(name, text)| (name.to_string(), text.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn a_mise_tool_added_or_moved_to_another_version_is_a_grant() {
        let was = inputs(&[("mise.toml", "[tools]\nnode = \"20\"\npython = \"3.12\"\n")]);
        let now = inputs(&[
            (
                "mise.toml",
                "[tools]\nnode = \"22\"\npython = \"3.12\"\n\"nix:jq\" = \"1.7\"\n",
            ),
            ("sops:secrets.enc.yaml", "[tools]\nignored = \"1\"\n"),
            (".tool-versions", "ruby 3.3\n"),
        ]);
        assert_eq!(
            seen(&mise_grants(Some(&was), &now)),
            vec![
                ("mise", "nix:jq@1.7", Risk::Info),
                ("mise", "node@22", Risk::Info),
                ("mise", "ruby@3.3", Risk::Info),
            ]
        );
        assert_eq!(mise_grants(Some(&was), &was), vec![]);
    }

    #[test]
    fn a_first_approval_grants_every_mise_tool_and_an_unreadable_file_is_flagged() {
        let now = inputs(&[
            ("mise.toml", "[tools]\nnode = \"22\"\n"),
            (".mise.toml", "not toml ["),
        ]);
        assert_eq!(
            seen(&mise_grants(None, &now)),
            vec![
                ("mise", "node@22", Risk::Info),
                ("mise", ".mise.toml", Risk::Notable),
            ]
        );
    }
}
