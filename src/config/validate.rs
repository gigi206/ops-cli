//! The inter-field rules a configuration file has to satisfy.
//!
//! Separate from the resolution engine next door because the two answer different questions: the
//! engine decides which layer a field comes from and whether the project is trusted enough to set
//! it, while these decide whether a value the layer already carries is one the launch can act on.
//! They reach no further than the value and the notes they are handed, which is what lets each one
//! be read on its own.
//!
//! Every rule reports the same way: a rejected value is dropped with a note naming the field and
//! the reason, and the launch proceeds without it. A refusal at this level is a fact about one
//! entry, never a reason to fail the load, so a single bad line cannot cost a project its whole
//! configuration.

use super::*;

/// Validate a `[limits]` table into the resolved [`cgroup::Limits`](crate::sandbox::cgroup::Limits),
/// dropping any field whose value systemd would not accept (with a warning naming the field) so a
/// bad value can never reach `systemd-run` and brick a launch. A `None` table, or one whose every
/// field is unset or invalid, yields all-`None` — the built-in defaults. The per-field validators
/// mirror systemd's grammar exactly (verified against a live scope in the cgroup tests).
pub(super) fn validate_limits(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawLimits>,
) -> crate::sandbox::cgroup::Limits {
    let mut out = crate::sandbox::cgroup::Limits::default();
    let Some(raw) = raw else {
        return out;
    };
    out.memory_high = validate_memory_limit(warnings, source, "memory_high", raw.memory_high);
    out.memory_max = validate_memory_limit(warnings, source, "memory_max", raw.memory_max);
    out.tasks_max = validate_tasks_limit(warnings, source, raw.tasks_max);
    out
}

/// Validate a `[redact] min_len` into the floor it denotes, or `None` when the value is unusable
/// (warned) and the layer below stands.
///
/// The only refusal is `0`. It is not a stricter setting but a meaningless one: a zero-length needle
/// matches at every offset of every byte stream, so it names nothing and bounds nothing. Everything
/// above it is honored as written, including a floor high enough that few credentials clear it —
/// that is a legitimate choice (scan only for values long enough to be unmistakable), and it does
/// not pass in silence: each declared secret left below the floor says so at launch.
pub(super) fn validate_redact_min_len(
    warnings: &mut Vec<String>,
    source: &str,
    value: u64,
) -> Option<usize> {
    let floor = usize::try_from(value).ok().filter(|n| *n > 0);
    if floor.is_none() {
        warnings.push(format!(
            "{source}: ignoring `[redact] min_len = {value}` — the floor must be at least 1 byte \
             (a zero-length value matches everywhere, so it names nothing); the floor in effect is \
             unchanged"
        ));
    }
    floor
}

/// Validate a `timezone` value into the zone name the cage will link `/etc/localtime` to, dropping
/// a malformed one with a warning (the cage keeps `sandbox::binds::DEFAULT_ZONE`).
///
/// This is the **syntactic** half only: the name is interpolated into a path under the cage's zone
/// database, so it is held to what an IANA zone name can be — one or more `/`-separated segments of
/// letters, digits, `_`, `+` and `-`, each non-empty and none of them `.` or `..`, no leading or
/// trailing slash. That rejects both the traversal (`../../etc/shadow`) and the absolute path
/// (`/etc/shadow`) before either becomes a link target. Whether the database actually carries the
/// zone is the launcher's check, because only the launcher has a database to look in.
pub(super) fn validate_timezone(
    warnings: &mut Vec<String>,
    source: &str,
    value: String,
) -> Option<String> {
    if !is_zone_name(&value) {
        warnings.push(format!(
            "{source}: ignoring `timezone = \"{value}\"` — not an IANA zone name (expected a form \
             like `Europe/Paris` or `UTC`); the cage keeps the zone in effect"
        ));
        return None;
    }
    Some(value)
}

/// Validate one `[devices]` entry lexically: an absolute path *strictly under* `/dev/`, with no `..`
/// component (which could escape `/dev`). Returns the `PathBuf`, or a reason it was rejected. No I/O
/// — the device need not exist here (a portable profile may list a device some hosts lack; a missing
/// one is skipped at launch by `--dev-bind-try`). `/dev` itself (and a bare `/dev/`) is refused:
/// rebinding the whole tree would defeat the cage's minimal, hostless `/dev`.
///
/// The check is on the path *spelling*, not the resolved target: the source is deliberately **not**
/// canonicalized. Canonicalizing would need I/O (breaking this function's — and [`resolve`]'s —
/// purity) and would require the device to exist, defeating the portable-profile property above. So
/// a symlink under `/dev` pointing elsewhere (`/dev/foo -> /etc`) would dev-bind its target. Since
/// `[devices]` is trusted-only, that is **self-harm equivalent to a plain read-write bind of the
/// target** (a trusted config can already write `binds = [{ path = "/etc", mode = "rw" }]`), not a
/// new capability — so the lexical check is the proportionate guard.
pub(super) fn validate_device_path(path: &str) -> Result<PathBuf, &'static str> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("must be an absolute path");
    }
    if p.components().any(|c| c == std::path::Component::ParentDir) {
        return Err("must not contain a `..` component");
    }
    // Strictly under `/dev/`: a `/dev`-prefixed path with a name beyond it. The component count rules
    // out both a non-`/dev` path and the degenerate `/dev` / `/dev/`, which would rebind the whole
    // minimal device tree rather than grant one device.
    if !path.starts_with("/dev/") || p.components().count() <= 2 {
        return Err("must be a path under `/dev/` (e.g. /dev/dri, /dev/kvm)");
    }
    Ok(p.to_path_buf())
}

/// Validate one `forward` list into resolved entries: parse each bare port or `"host:cage"` remap,
/// drop a malformed one with a per-entry warning, and reduce entries sharing a cage port to the
/// last. A collection — the drop-bad-entry, keep-the-rest shape (like a malformed `binds` entry),
/// not the all-or-nothing of a scalar posture — so one bad entry does not void the valid ones.
///
/// Two entries naming the same cage port inside **one** list is not the layering case: no higher
/// layer is speaking, the author simply wrote the same forward twice. Keeping both would wire two
/// in-cage `socat UNIX-LISTEN` on one socket path, where the second loses the race and its host port
/// answers into nothing — a silent black hole. The last entry wins, matching what the layered merge
/// does with the same key, and the warning names both host ports so the dropped one is visible.
pub(super) fn validate_forward(
    warnings: &mut Vec<String>,
    source: &str,
    raw: &[schema::RawForward],
) -> Vec<ForwardPort> {
    let mut out: Vec<ForwardPort> = Vec::with_capacity(raw.len());
    for entry in raw {
        let Some(fwd) = parse_forward_entry(warnings, source, entry) else {
            continue;
        };
        if let Some(prev) = out.iter_mut().find(|f| f.cage == fwd.cage) {
            if prev.host != fwd.host {
                warnings.push(format!(
                    "{source}: `forward` names cage port {cage} twice — keeping host port \
                     {new}, dropping {old}",
                    cage = fwd.cage,
                    new = fwd.host,
                    old = prev.host,
                ));
            }
            *prev = fwd;
        } else {
            out.push(fwd);
        }
    }
    sort_forward(&mut out);
    out
}

/// Validate one memory limit (`memory_high`/`memory_max`): reject a value systemd would not
/// accept, and — the likely-typo guard — reject a *bare small byte count*, which is almost always
/// a percentage written without its `%` (`memory_max = 90` meaning 90 bytes, below the kernel
/// floor, which would brick the launch). Either rejection falls back to the field's default.
pub(super) fn validate_memory_limit(
    warnings: &mut Vec<String>,
    source: &str,
    field: &str,
    value: Option<schema::RawLimit>,
) -> Option<String> {
    use crate::sandbox::cgroup;
    let token = value?.as_token();
    if !cgroup::is_valid_memory_value(&token) {
        warnings.push(format!(
            "{source}: ignoring invalid `limits.{field}` value `{token}`"
        ));
        return None;
    }
    if cgroup::is_bare_byte_count_below_floor(&token) {
        warnings.push(format!(
            "{source}: ignoring `limits.{field} = {token}` — a bare number is bytes, so this is \
             {token} bytes (below the usable minimum); did you mean \"{token}%\" or e.g. \
             \"{token}G\"?"
        ));
        return None;
    }
    Some(token)
}

/// Validate `tasks_max`: accept `infinity` or a positive integer, dropping anything else with a
/// warning so it falls back to the default.
pub(super) fn validate_tasks_limit(
    warnings: &mut Vec<String>,
    source: &str,
    value: Option<schema::RawLimit>,
) -> Option<String> {
    let token = value?.as_token();
    if crate::sandbox::cgroup::is_valid_tasks_value(&token) {
        Some(token)
    } else {
        warnings.push(format!(
            "{source}: ignoring invalid `limits.tasks_max` value `{token}`"
        ));
        None
    }
}

/// Parse an app's `home_scope` string into [`AppHomeScope`]. An unrecognized value is dropped
/// with a warning and the caller keeps the prior (defaulting to `Global`) — fail-safe, never a
/// silent mis-scope.
pub(super) fn validate_home_scope(
    warnings: &mut Vec<String>,
    source: &str,
    raw: &str,
) -> Option<AppHomeScope> {
    match raw {
        "global" => Some(AppHomeScope::Global),
        "project" => Some(AppHomeScope::Project),
        other => {
            warnings.push(format!(
                "{source}: ignoring unknown home_scope `{other}` (expected \"global\" or \"project\")"
            ));
            None
        }
    }
}

/// Validate a `nixpkgs` override source, returning it when well-formed and warning
/// when not. Dropping a malformed source keeps a bad value from reaching nix.
pub(super) fn validate_nixpkgs(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: String,
) -> Option<String> {
    if is_valid_nixpkgs_source(&value) {
        Some(value)
    } else {
        warnings.push(format!(
            "{source_label}: ignoring malformed nixpkgs source `{value}`"
        ));
        None
    }
}

/// Validate a `distro` declaration in either spelling, warning on anything
/// [`super::is_valid_distro_source`] refuses.
///
/// Returns the locator and the credential reference beside it, because the two are one decision:
/// dropping a malformed locator has to drop the credential written for it, and keeping a credential
/// whose image was refused would leave a secret resolved for a registry nothing asks any more.
///
/// `None` leaves the cage on the nix-provisioned userland, which is what a config without the
/// field gets: a malformed locator must not strand the launch, and it must not quietly select a
/// substrate other than the one that was written either.
pub(super) fn validate_distro(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: super::schema::DistroField,
) -> Option<(String, Option<String>)> {
    let (locator, auth) = match value {
        super::schema::DistroField::Locator(locator) => (locator, None),
        super::schema::DistroField::Table(table) => match table.image {
            Some(image) => (image, table.auth),
            None => {
                warnings.push(format!(
                    "{source_label}: ignoring a `distro` table that names no `image`"
                ));
                return None;
            }
        },
    };
    if super::is_valid_distro_source(&locator) {
        Some((locator, auth))
    } else {
        warnings.push(format!(
            "{source_label}: ignoring malformed distro locator `{locator}`"
        ));
        None
    }
}

/// Validate a `[mise] engine` source, warning on anything [`super::is_valid_mise_engine`] refuses.
///
/// `None` leaves the engine following the global `nixpkgs` source, which is the behaviour a config
/// without the field gets: a malformed value must not strand the engine, and it must not silently
/// select something other than what was written either.
pub(super) fn validate_mise_engine(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: String,
) -> Option<String> {
    if super::is_valid_mise_engine(&value) {
        Some(value)
    } else {
        warnings.push(format!(
            "{source_label}: ignoring malformed `[mise] engine` source `{value}` — expected a \
             channel, a 40-hex revision, or `github:<owner>/<repo>/<40-hex revision>[#<attr>]`"
        ));
        None
    }
}

/// Validate a `gui` posture string into [`GuiPolicy`], warning on anything unrecognized. A
/// typo must never silently leave the GUI in the wrong posture; returning `None` keeps the
/// prior (default or global) posture rather than guessing. There is intentionally no `x11`
/// value — X is never offered.
pub(super) fn validate_gui(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: String,
) -> Option<GuiPolicy> {
    match value.as_str() {
        "none" => Some(GuiPolicy::None),
        "offscreen" => Some(GuiPolicy::Offscreen),
        "wayland" => Some(GuiPolicy::Wayland),
        other => {
            warnings.push(format!(
                "{source_label}: ignoring unknown gui posture `{other}` \
                 (expected \"none\", \"offscreen\" or \"wayland\")"
            ));
            None
        }
    }
}

/// Validate a `proc` field — either a bare mode string or a `[proc]` table — mapping it to a
/// [`ProcPolicy`](crate::proc_policy::ProcPolicy) and warning on an unknown mode. A typo must never silently leave enforcement in the
/// wrong posture; returning `None` keeps the prior (default or parent) policy rather than guessing.
/// `parent` is the policy of the layer immediately below: a `[proc]` table that omits `mode` inherits
/// its mode from `parent` while keeping its own `allow`/`deny` rules.
pub(super) fn validate_proc(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: crate::config::schema::ProcField,
    parent: &crate::proc_policy::ProcPolicy,
) -> Option<crate::proc_policy::ProcPolicy> {
    use crate::config::schema::ProcField;
    use crate::proc_policy::{ProcMode, ProcPolicy};
    let (mode_str, allow, deny) = match field {
        ProcField::Mode(m) => (Some(m), Vec::new(), Vec::new()),
        ProcField::Table(t) => (t.mode, t.allow, t.deny),
    };
    let mode = match mode_str {
        Some(m) => match ProcMode::parse(&m) {
            Some(pm) => pm,
            None => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown proc mode `{m}` \
                     (expected \"off\", \"observe\", \"enforce\", or \"ask\")"
                ));
                return None;
            }
        },
        // A table with no mode inherits the parent layer's mode, keeping this table's own rules.
        None => parent.mode,
    };
    Some(ProcPolicy::new(mode, &allow, &deny))
}

/// Validate a `notify` field — either a bare mode string or a `[notify]` table — into a resolved
/// per-event policy, warning on anything unrecognized.
///
/// `parent` is the layer immediately below (the default for the global layer, the resolved baseline
/// for a project or app). A table that omits `mode` inherits `parent` **per event**, so a
/// `[notify.events]` refining one lens leaves the others exactly as the layer below left them.
///
/// Two failure shapes, deliberately different:
/// - an unknown **mode** returns `None`, keeping the layer below rather than guessing — a typo must
///   never silently decide how loud the boundary is;
/// - an unknown **event name** is named in a warning and skipped, since one bad key is no reason to
///   discard the settings written beside it.
pub(super) fn validate_notify(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: crate::config::schema::NotifyField,
    parent: &crate::notify::NotifyPolicy,
) -> Option<crate::notify::NotifyPolicy> {
    use crate::config::schema::{NotifyEvents, NotifyField};
    use crate::notify::{NotifyEvent, NotifyMode, NotifyPolicy};

    /// Parse a mode, naming the offending value and the key it was written under.
    fn mode_of(
        warnings: &mut Vec<String>,
        source_label: &str,
        key: &str,
        s: &str,
    ) -> Option<NotifyMode> {
        match NotifyMode::parse(s) {
            Some(m) => Some(m),
            None => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown notify mode `{s}` for `{key}` \
                     (expected \"off\", \"once\", or \"always\")"
                ));
                None
            }
        }
    }

    let (mode_str, events, repeat_after) = match field {
        NotifyField::Mode(m) => (Some(m), None, None),
        NotifyField::Table(t) => (t.mode, t.events, t.repeat_after),
    };

    // The mode this layer sets for every event, or `None` to keep the parent's per-event modes.
    let base = match mode_str {
        Some(m) => match NotifyMode::parse(&m) {
            Some(mode) => Some(mode),
            None => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown notify mode `{m}` \
                     (expected \"off\", \"once\", or \"always\")"
                ));
                return None;
            }
        },
        None => None,
    };

    let policy = match events {
        // A list is an inclusion: the named events keep speaking, everything else goes quiet. Each
        // named event takes this layer's mode, or — with no `mode` written — the one it already had,
        // so `events = [...]` alone narrows *which* refusals are announced without also changing how
        // often.
        Some(NotifyEvents::List(names)) => {
            let mut policy = NotifyPolicy::uniform(NotifyMode::Off);
            for name in names {
                match NotifyEvent::parse(&name) {
                    Some(event) => {
                        policy = policy.with_event(event, base.unwrap_or(parent.mode_for(event)));
                    }
                    None => warnings.push(unknown_notify_event(source_label, &name)),
                }
            }
            policy
        }
        // A table names a mode per event over this layer's base (or the parent, unchanged).
        Some(NotifyEvents::Map(map)) => {
            let mut policy = base.map(NotifyPolicy::uniform).unwrap_or(*parent);
            for (name, value) in map {
                match NotifyEvent::parse(&name) {
                    Some(event) => {
                        if let Some(mode) = mode_of(warnings, source_label, &name, &value) {
                            policy = policy.with_event(event, mode);
                        }
                    }
                    None => warnings.push(unknown_notify_event(source_label, &name)),
                }
            }
            policy
        }
        None => base.map(NotifyPolicy::uniform).unwrap_or(*parent),
    };

    // The quiet period between repeats. A malformed value keeps the layer below rather than
    // silently announcing every occurrence — the direction a typo must not fail in. Inherited when
    // this layer does not set one, like the modes above.
    let period = match &repeat_after {
        None => parent.repeat_after(),
        Some(raw) => match parse_duration(raw) {
            Ok(period) => period,
            Err(reason) => {
                warnings.push(format!(
                    "{source_label}: ignoring invalid `repeat_after` — {reason}; \
                     keeping the period already in effect"
                ));
                parent.repeat_after()
            }
        },
    };
    // A period is meaningless where nothing ever repeats. Said rather than silently ignored: a
    // reader who set both is expecting one of them to be doing something.
    if repeat_after.is_some()
        && NotifyEvent::ALL
            .iter()
            .all(|e| policy.mode_for(*e) != NotifyMode::Always)
    {
        warnings.push(format!(
            "{source_label}: `repeat_after` has no effect — it spaces out repeats, and no event is \
             set to `always`"
        ));
    }
    Some(policy.with_repeat_after(period))
}

/// How a `[network]` table stands to the layer below it.
///
/// [`Layering::Replace`] is the rule everywhere: the table is rebuilt from its own keys, only an
/// omitted `mode` is inherited, and a setting the layer below carried is named in a warning rather
/// than kept. [`Layering::Amend`] is the one exception the repository intends, for a *mode-less*
/// `[app.<name>.network]` project overlay: with no posture of its own such a table is not a policy
/// but an addition to one, and replacing would silently drop the profile's rules — measured as
/// three rules becoming one on a single `sbx net allow --app`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Layering {
    /// Rebuild from this table alone; warn about what the layer below carried and it does not.
    Replace,
    /// Start from the layer below when this table declares no `mode`: its lists are appended to
    /// the lower layer's and a scalar it omits keeps the lower layer's value.
    Amend,
}

/// Validate a `network` field — either a posture string or a `[network]` table — mapping it to a
/// policy and warning on anything unrecognized. A typo must never silently leave the network in the
/// wrong posture; returning `None` keeps the prior (default or global) posture rather than guessing.
/// `parent` is the network of the layer immediately below (the global default for the baseline
/// global layer, the resolved baseline for a project/app): a `[network]` table that omits `mode`
/// inherits its mode from `parent` (see [`mode_from_parent`]).
pub(super) fn validate_network(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: NetworkField,
    groups: &NetGroups,
    parent: &NetworkPolicy,
) -> Option<NetworkPolicy> {
    validate_network_layered(
        warnings,
        source_label,
        field,
        groups,
        parent,
        Layering::Replace,
    )
}

/// [`validate_network`] for the one layer that amends rather than replaces: a project
/// `[app.<name>.network]` over the app's own profile. See [`Layering`].
pub(super) fn validate_network_amending(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: NetworkField,
    groups: &NetGroups,
    parent: &NetworkPolicy,
) -> Option<NetworkPolicy> {
    validate_network_layered(
        warnings,
        source_label,
        field,
        groups,
        parent,
        Layering::Amend,
    )
}

/// The shared body of [`validate_network`] and [`validate_network_amending`], parameterised by
/// how this table stands to the layer below. Written once because the two differ in that single
/// decision and a second copy could drift from it.
fn validate_network_layered(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: NetworkField,
    groups: &NetGroups,
    parent: &NetworkPolicy,
    layering: Layering,
) -> Option<NetworkPolicy> {
    match field {
        NetworkField::Posture(value) => match value.as_str() {
            "none" => Some(NetworkPolicy::Isolated),
            "shared" => Some(NetworkPolicy::Shared),
            // The filtered-egress modes in bare-string form (no carve-out lists): `deny` =
            // deny-by-default (only the built-in set reaches), `allow` = allow-by-default (a
            // denylist; the proxy stays active). Carve-out lists need the `[network]` table.
            "deny" => Some(NetworkPolicy::Allowlist(Box::default())),
            "allow" => Some(NetworkPolicy::Allowlist(Box::new(
                crate::allowlist::EgressPolicy::default()
                    .with_default(crate::allowlist::DefaultAction::Allow),
            ))),
            // `ask` in bare-string form parks every unmatched request with no timeout (an
            // indefinite wait); a bound needs the `[network]` table's `ask_timeout`.
            "ask" => Some(NetworkPolicy::Allowlist(Box::new(
                crate::allowlist::EgressPolicy::default()
                    .with_default(crate::allowlist::DefaultAction::Ask),
            ))),
            other => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown network policy `{other}` (expected \
                     \"none\", \"shared\", \"deny\", \"allow\", \"ask\", or an `[network]` table)"
                ));
                None
            }
        },
        NetworkField::Table(table) => {
            validate_network_table(warnings, source_label, table, groups, parent, layering)
        }
    }
}

/// Name every `[network]` field a non-filtering posture leaves inert, so a table that reads like a
/// restriction is not taken for one.
///
/// `none` and `shared` stand up no egress proxy: `none` gives the cage no network at all and
/// `shared` gives it the host's, unfiltered. Every other field in the table is addressed to that
/// proxy, so under either posture it decides nothing. The dangerous half is `shared` with an
/// `allow` list, which reads exactly like "only these hosts" and is in fact "every host", and the
/// author of such a table has no other way to find out.
fn warn_inert_under_posture(
    warnings: &mut Vec<String>,
    source_label: &str,
    posture: &str,
    table: &NetworkTable,
) {
    let mut inert: Vec<&str> = Vec::new();
    let mut list = |name: &'static str, present: bool| {
        if present {
            inert.push(name);
        }
    };
    list("allow", !table.allow.is_empty());
    list("deny", !table.deny.is_empty());
    list("mute", !table.mute.is_empty());
    list("http2", !table.http2.is_empty());
    list("dns_cache_ttl", table.dns_cache_ttl.is_some());
    list("pool", table.pool.is_some());
    list("idle_timeout", table.idle_timeout.is_some());
    list("max_connections", table.max_connections.is_some());
    list("body_max_mb", table.body_max_mb.is_some());
    list("ca_roots", table.ca_roots.is_some());
    list("capture", table.capture.is_some());
    list("capture_max_kb", table.capture_max_kb.is_some());
    list("websocket_secret", table.websocket_secret.is_some());
    list("ask_timeout", table.ask_timeout.is_some());
    list("ask_notice", table.ask_notice.is_some());
    list("stats", table.stats.is_some());
    list("default_methods", table.default_methods.is_some());
    list("shared_credential", !table.shared_credential.is_empty());
    if inert.is_empty() {
        return;
    }
    let named = inert.join("`, `");
    let what = if posture == "none" {
        "gives the cage no network at all"
    } else {
        "gives the cage the host's network, unfiltered"
    };
    // Written with `\` continuations like every other message here: an unbroken literal wrapped by
    // the formatter kept its indentation, and the warning reached the user with two ten-space runs
    // in the middle of its sentences.
    warnings.push(format!(
        "{source_label}: ignoring `{named}` under `[network]` — `mode = \"{posture}\"` {what}, so \
         there is no egress proxy for these to address; a rule list here restricts nothing. Use \
         `mode = \"deny\"` or `\"ask\"` to filter."
    ));
}

/// Validate the table form of `network`: `none`/`shared` behave as the string form; `deny`/`allow`/
/// `ask` classify each declared entry (a malformed one is dropped with a warning, fail-closed —
/// that host simply stays unreachable, never silently allowed); and an **omitted** `mode` inherits
/// the filtering mode from `parent` while keeping this table's own rules.
pub(super) fn validate_network_table(
    warnings: &mut Vec<String>,
    source_label: &str,
    table: NetworkTable,
    groups: &NetGroups,
    parent: &NetworkPolicy,
    layering: Layering,
) -> Option<NetworkPolicy> {
    use crate::allowlist::DefaultAction;
    // Report what this table carries and sbx will not apply, before any posture is decided: the
    // `none`/`shared` arms below return early, and a key passed over in silence reads as a rule in
    // force. A `groups` table surviving to here belongs to a layer that may not define one (the
    // global's own is taken out before validation), so it is named as the scope error it is.
    if !table.groups.is_empty() {
        warnings.push(format!(
            "{source_label}: ignoring `groups` under `[network]` — egress groups are defined once \
             in the global config; reference one from this layer with `@<name>`"
        ));
    }
    for key in table.rest.keys() {
        warnings.push(format!(
            "{source_label}: ignoring unknown key `{key}` under `[network]` — sbx does not know \
             this field (check the spelling; a newer sbx's fields are ignored here on purpose)"
        ));
    }
    // The default action: from an explicit `mode`, or — when omitted — inherited from the parent
    // layer. `none`/`shared` are non-filtering postures that carry no rules, so they return early.
    let action = match table.mode.as_deref() {
        Some(posture @ ("none" | "shared")) => {
            warn_inert_under_posture(warnings, source_label, posture, &table);
            return Some(if posture == "none" {
                NetworkPolicy::Isolated
            } else {
                NetworkPolicy::Shared
            });
        }
        // `deny` = deny-by-default (only what `allow` lists reaches). `allow` = the denylist
        // (everything public reaches except the `deny` carve-outs, proxy still active). `ask` parks
        // an unmatched request for a live decision (allow rules auto-pass, deny rules auto-fail).
        Some("deny") => DefaultAction::Deny,
        Some("allow") => DefaultAction::Allow,
        Some("ask") => DefaultAction::Ask,
        Some(other) => {
            warnings.push(format!(
                "{source_label}: ignoring unknown network mode `{other}` (expected \"none\", \
                 \"shared\", \"deny\", \"allow\", or \"ask\")"
            ));
            return None;
        }
        None => mode_from_parent(parent),
    };
    let allow = classify_entries(warnings, source_label, Slot::Allow, table.allow, groups);
    let deny = classify_entries(warnings, source_label, Slot::Deny, table.deny, groups);
    // `mute` (SELinux `dontaudit`) suppresses a *denied* request's log line — never a verdict — so
    // it classifies with the same grammar as `allow`/`deny` (including `@group` expansion) and is
    // carried on the policy for the proxy to consult at logging time.
    let mute = classify_entries(warnings, source_label, Slot::Mute, table.mute, groups);
    // `http2` names the hosts the proxy speaks HTTP/2 to (ALPN `h2`, for gRPC). It is not an egress
    // rule (no path/method/verdict) — just a host[:port] the proxy MITMs as h2 — so it parses on its
    // own, dropping a malformed entry with a warning (fail-closed: that host keeps HTTP/1.1).
    let http2 = parse_http2_hosts(warnings, source_label, table.http2);
    // `shared_credential` groups the hosts that are one service, so a credential the cage acquired
    // on one of them is not refused on its way to another. Not an egress rule either: it grants no
    // reach, and a host named here is unreachable unless an `allow` rule says otherwise.
    let shared_credential =
        parse_shared_credential(warnings, source_label, table.shared_credential);
    // An amending table with no `mode` of its own is an addition to the layer below, not a policy:
    // start from that layer so its rules survive and so a setting this table does not redeclare
    // keeps its value. Every other table is built from its own keys, as the warning at the end of
    // this function says out loud.
    let amends_below = layering == Layering::Amend && table.mode.is_none();
    let mut policy = match parent {
        NetworkPolicy::Allowlist(below) if amends_below => {
            let mut p = below
                .as_ref()
                .clone()
                .with_default(action)
                .amended_with(allow, deny, mute);
            // The two remaining list-shaped settings: appended when this table names any, and left
            // to the layer below when it names none. Written as guards rather than folded into
            // `amended_with` because both are `Option`/empty-shaped rather than plain lists.
            if !http2.is_empty() {
                p = p.with_http2(http2);
            }
            if !shared_credential.is_empty() {
                p = p.with_shared_credential(shared_credential);
            }
            p
        }
        _ => crate::allowlist::EgressPolicy::new(allow, deny)
            .with_default(action)
            .with_mute(mute)
            .with_http2(http2)
            .with_shared_credential(shared_credential),
    };
    if action == DefaultAction::Ask {
        // A configured `ask_timeout` bounds the parked wait; a malformed value falls back to
        // indefinite (warned), never a hard config failure.
        let timeout = match &table.ask_timeout {
            None => None,
            Some(raw) => parse_duration(raw).unwrap_or_else(|reason| {
                warnings.push(format!(
                    "{source_label}: ignoring invalid `ask_timeout` — {reason}; \
                     parked requests will wait indefinitely"
                ));
                None
            }),
        };
        // Declared-only when amending: an overlay that says nothing about the parked wait keeps
        // the wait the layer below chose, rather than resetting it to the built-in.
        if !amends_below || table.ask_timeout.is_some() {
            policy = policy.with_ask_timeout(timeout);
        }
        if !amends_below || table.ask_notice.is_some() {
            policy = policy.with_ask_notice(table.ask_notice.unwrap_or(true));
        }
    } else {
        // `ask_timeout`/`ask_notice` are moot outside the effective `ask` mode — flag them rather
        // than silently drop (the effective mode may be inherited, so key off `action`, not the raw
        // `mode` string).
        if table.ask_timeout.is_some() {
            warnings.push(format!(
                "{source_label}: `ask_timeout` is only meaningful under `mode = \"ask\"` — ignored"
            ));
        }
        if table.ask_notice.is_some() {
            warnings.push(format!(
                "{source_label}: `ask_notice` is only meaningful under `mode = \"ask\"` — ignored"
            ));
        }
    }
    // DNS cache TTL for the proxy's resolver (every filtering posture runs one). The proxy resolves
    // each allowed host once and reuses the address for this long, so a long build fetching from one
    // host thousands of times does not re-hit the resolver each request. Optional; default 60s, `0`
    // disables the cache.
    if let Some(secs) = table.dns_cache_ttl {
        policy = policy.with_dns_cache_ttl(Some(std::time::Duration::from_secs(secs)));
    }
    // Upstream connection reuse. Off unless asked for, and never a verdict — it decides how a
    // permitted request is carried, not whether it is.
    if let Some(pool) = table.pool {
        policy = policy.with_pool(pool);
    }
    // How long an idle connection is kept, on either leg. A zero is refused rather than honored:
    // "hold nothing" is what `pool = false` says, and reading it here as an idle bound would leave
    // a launch reusing connections it closes immediately. Malformed falls back to the default,
    // warned, never a hard config failure — the same shape as `ask_timeout`.
    if let Some(raw) = &table.idle_timeout {
        match parse_duration(raw) {
            Ok(Some(idle)) => policy = policy.with_idle_timeout(Some(idle)),
            Ok(None) => warnings.push(format!(
                "{source_label}: ignoring `idle_timeout = \"{raw}\"` — a zero idle bound is \
                 `pool = false`, which turns connection reuse off on both legs"
            )),
            Err(reason) => warnings.push(format!(
                "{source_label}: ignoring invalid `idle_timeout` — {reason}; the built-in bound \
                 stays"
            )),
        }
    }
    // How many client connections the proxy serves at once. Zero would refuse every connection and
    // is far likelier a typo than an intent, so it is warned and dropped (fail-closed: the built-in
    // cap stays).
    match table.max_connections {
        Some(0) => warnings.push(format!(
            "{source_label}: ignoring `max_connections = 0` — it would refuse every connection; \
             use `network = \"none\"` for a cage with no egress"
        )),
        Some(max) => policy = policy.with_max_connections(Some(max)),
        None => {}
    }
    // The most of one request body the proxy holds. Zero would refuse every `chunked` request and
    // every signed one, which is a typo rather than a posture.
    match table.body_max_mb {
        Some(0) => warnings.push(format!(
            "{source_label}: ignoring `body_max_mb = 0` — it would refuse every streamed upload \
             and every request a signer digests"
        )),
        Some(mb) => {
            policy = policy.with_body_max(Some(mb.saturating_mul(1024 * 1024)));
        }
        None => {}
    }
    // What the cage's CA bundle contains. Never a verdict — it decides which anchors the cage trusts,
    // not which requests are permitted, and dropping the roots only ever narrows that trust. The one
    // case where they are load-bearing is a splice: `tcp://` hands the stream through untouched, so
    // the client authenticates the real server itself and needs the ordinary roots to do it. Keep
    // them there whatever the field says, and say so — a silently ignored setting reads as applied.
    if let Some(ca_roots) = table.ca_roots {
        if !ca_roots && policy.splices_any() {
            warnings.push(format!(
                "{source_label}: `ca_roots = false` is overridden by a `tcp://` rule — a spliced \
                 stream is authenticated against the real server, so the public roots stay"
            ));
        } else {
            policy = policy.with_ca_roots(ca_roots);
        }
    }
    // The traffic capture: how much of each permitted exchange the proxy keeps for
    // `sbx net logs --with-headers/--with-body`. Never a verdict. An unknown level is dropped with a
    // warning and the capture stays off — fail-closed, since the value names how much plaintext the
    // launch retains.
    let mut capture = None;
    if let Some(raw) = &table.capture {
        match crate::sandbox::control::CaptureLevel::parse(raw) {
            Some(level) => {
                policy = policy.with_capture(level, table.capture_max_kb);
                capture = Some(level);
            }
            None => warnings.push(format!(
                "{source_label}: ignoring unknown capture level `{raw}` (expected \"off\", \
                 \"headers\", or \"bodies\") — the traffic capture stays off"
            )),
        }
    }
    // `capture_max_kb` bounds a captured *body*, so it is inert under `off` and `headers` exactly as
    // it is with no `capture` at all. The check keys off the effective level rather than the
    // absence of the key — the same rule `ask_timeout`/`ask_notice` follow above — because the two
    // levels that ignore the ceiling are the ones an author is likeliest to have paired it with.
    if table.capture_max_kb.is_some() && !capture.is_some_and(|level| level.captures_bodies()) {
        warnings.push(format!(
            "{source_label}: `capture_max_kb` is only meaningful with `capture = \"bodies\"` — ignored"
        ));
    }
    // What a secret seen leaving through a WebSocket does. An unknown value keeps the default, and
    // the default is the one that does not tear a live tunnel down: the alternative would end a
    // conversation on a value nobody chose, which is not a safer failure, only a louder one.
    if let Some(raw) = &table.websocket_secret {
        match crate::allowlist::WebsocketSecret::parse(raw) {
            Some(action) => policy = policy.with_websocket_secret(action),
            None => warnings.push(format!(
                "{source_label}: ignoring unknown `websocket_secret` value `{raw}` (expected \
                 \"warn\" or \"block\") — a secret seen leaving a WebSocket is recorded and relayed"
            )),
        }
    }
    // What declaring a table costs, said where it happens. The policy above was *rebuilt* from this
    // table's keys — only an omitted `mode` is inherited — so a setting the layer below carried and
    // this one does not reverts to the built-in value. Every other layered table amends (`[limits]`
    // merges field by field, `seccomp`/`forward`/`devices`/`ssh_agent`/`fs` union, `[notify]`
    // inherits per event), so a reader has no reason to expect this one to replace.
    //
    // It is warned rather than merged because the rules a table declares are its own by design, and
    // because the layer that loses a setting is usually not the one that wrote it: `sbx net allow
    // --local` writes this table for a user whose settings live in the global config.
    if let NetworkPolicy::Allowlist(below) = parent
        && !amends_below
    {
        let dropped = policy.settings_dropped_from(below);
        if !dropped.is_empty() {
            let list = dropped
                .iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(", ");
            let (subject, verb, pronoun) = if dropped.len() == 1 {
                ("setting", "does", "it")
            } else {
                ("settings", "do", "them")
            };
            warnings.push(format!(
                "{source_label}: this `[network]` table replaces the layer below rather than adding \
                 to it, so the {subject} it carried {verb} not apply here: {list} — re-declare \
                 {pronoun} in this table to keep {pronoun}"
            ));
        }
    }
    Some(NetworkPolicy::Allowlist(Box::new(policy)))
}

/// Validate an `[open]` table into resolved handlers, dropping and warning on each entry it cannot
/// honor. Dropping is the right failure here: a URI with no handler prints and continues (the
/// router's undeclared behaviour), while a handler kept despite a value sbx did not understand would
/// route a real sign-in click somewhere unintended.
pub(super) fn validate_open(
    warnings: &mut Vec<String>,
    source: &str,
    raw: BTreeMap<String, schema::RawOpen>,
) -> BTreeMap<String, OpenHandler> {
    let mut out = BTreeMap::new();
    for (scheme, entry) in raw {
        // Schemes are case-insensitive per RFC 3986, and the comparison the router makes is
        // literal, so the key is folded once here rather than at every match.
        let scheme = scheme.to_ascii_lowercase();
        if !is_valid_uri_scheme(&scheme) {
            warnings.push(format!(
                "{source}: ignoring `[open]` entry `{scheme}` — a key is a URI scheme (a letter, \
                 then letters, digits, `+`, `-` or `.`), not a MIME type or a URL"
            ));
            continue;
        }
        let (cmd, mode) = match entry {
            schema::RawOpen::Argv(cmd) => (Some(cmd), None),
            schema::RawOpen::Detailed(table) => (table.cmd, table.mode),
        };
        let mode = match mode.as_deref() {
            None | Some("exec") => OpenMode::Exec,
            Some("detach") => OpenMode::Detach,
            Some(other) => {
                warnings.push(format!(
                    "{source}: ignoring `[open]` entry `{scheme}` — unknown mode `{other}` \
                     (expected `exec` or `detach`)"
                ));
                continue;
            }
        };
        // An absent `cmd` lands here rather than at the parse layer (see
        // [`schema::RawOpenTable::cmd`]), so the entry that names no program is dropped alone —
        // the whole layer used to go with it.
        let argv = cmd.map(schema::RawCmd::into_argv).unwrap_or_default();
        if argv.is_empty() || argv[0].is_empty() {
            warnings.push(format!(
                "{source}: ignoring `[open]` entry `{scheme}` — it names no program to open with"
            ));
            continue;
        }
        if argv.iter().any(|a| a.chars().any(char::is_control)) {
            warnings.push(format!(
                "{source}: ignoring `[open]` entry `{scheme}` — an argument carries a control \
                 character"
            ));
            continue;
        }
        out.insert(scheme, OpenHandler { argv, mode });
    }
    out
}

/// Validate a `[service]` table into resolved specs, dropping what cannot be honored with a warning
/// that names the service.
///
/// Dropping rather than failing keeps a malformed entry from taking the app down with it: an app
/// whose auxiliary process is missing usually still runs (degraded, and the warning says which one),
/// where a failed launch leaves nothing at all. That is the same trade `[open]` makes, for the same
/// reason.
pub(super) fn validate_service(
    warnings: &mut Vec<String>,
    source: &str,
    raw: BTreeMap<String, schema::RawService>,
) -> BTreeMap<String, ServiceSpec> {
    let mut out = BTreeMap::new();
    for (name, entry) in raw {
        // The name reaches a log file name and every diagnostic, so hold it to the same shape as a
        // bundle or group name rather than discovering a path separator in it later.
        if !is_valid_group_name(&name) {
            warnings.push(format!(
                "{source}: ignoring `[service]` entry `{name}` — a name is letters, digits, `.`, \
                 `_` or `-` (64 max)"
            ));
            continue;
        }
        let (cmd, enable, ready) = match entry {
            schema::RawService::Argv(cmd) => (Some(cmd), None, None),
            schema::RawService::Detailed(table) => (table.cmd, table.enable, table.ready),
        };
        // An absent `cmd` lands here rather than at the parse layer (see
        // [`schema::RawServiceTable::cmd`]), so the entry that names no program is dropped alone —
        // the whole layer used to go with it.
        let argv = cmd.map(schema::RawCmd::into_argv).unwrap_or_default();
        if argv.is_empty() || argv[0].is_empty() {
            warnings.push(format!(
                "{source}: ignoring `[service]` entry `{name}` — it names no program to run"
            ));
            continue;
        }
        if argv.iter().any(|a| a.chars().any(char::is_control)) {
            warnings.push(format!(
                "{source}: ignoring `[service]` entry `{name}` — an argument carries a control \
                 character"
            ));
            continue;
        }
        let enable = service_enable(warnings, source, &name, enable);
        let ready = service_ready(warnings, source, &name, ready);
        out.insert(
            name,
            ServiceSpec {
                argv,
                enable,
                ready,
            },
        );
    }
    out
}

/// The environment conditions that must all hold for one `[service]` entry to start. Empty starts
/// it unconditionally, which is both the default and where an unreadable condition lands.
///
/// The condition is dropped alone when it cannot be read, rather than taking the service with
/// it, on the same rule as the readiness gate: a qualifier sbx cannot understand must not
/// cost the process the profile is for. The direction of the drop is the safe one — the
/// service starts, which is what the profile asks for when nothing says otherwise.
///
/// The two ways a condition can be unreadable are the two ways `is`/`not` can be wrong: both
/// given (which of them was meant is not guessable) or neither (nothing is being compared).
///
/// A list is an `and`, so a member that cannot be read takes the WHOLE condition with it
/// rather than only itself: dropping one conjunct would silently *loosen* what the profile
/// asked for, and a service running under half a condition is worse than one running under
/// none, which at least matches what an absent `enable` means.
fn service_enable(
    warnings: &mut Vec<String>,
    source: &str,
    name: &str,
    enable: Option<schema::RawEnable>,
) -> Vec<EnvCondition> {
    match enable {
        None => Vec::new(),
        Some(spec) => {
            let raw = match spec {
                schema::RawEnable::One(cond) => vec![cond],
                schema::RawEnable::All(conds) => conds,
            };
            let reason = if raw.is_empty() {
                Some("it lists no condition".to_string())
            } else {
                raw.iter().find_map(|c| {
                    // An omitted `env` arrives as `None` rather than failing the parse of the whole
                    // layer (see [`schema::RawEnableCond::env`]); it reads the same as an empty one
                    // here, since neither names a variable to compare.
                    let Some(var) = c.env.as_deref().filter(|v| !v.is_empty()) else {
                        return Some("a condition names no variable".to_string());
                    };
                    match (&c.is, &c.not) {
                        (Some(_), Some(_)) => Some(format!(
                            "the condition on `{var}` sets both `is` and `not`, which cannot \
                             both be it"
                        )),
                        (None, None) => Some(format!(
                            "the condition on `{var}` sets neither `is` nor `not`, so it \
                             compares nothing"
                        )),
                        (Some(schema::RawValues::Any(v)), None)
                        | (None, Some(schema::RawValues::Any(v)))
                            if v.is_empty() =>
                        {
                            Some(format!(
                                "the condition on `{var}` lists no value, so it compares \
                                 nothing"
                            ))
                        }
                        _ => None,
                    }
                })
            };
            match reason {
                Some(reason) => {
                    warnings.push(format!(
                        "{source}: ignoring `enable` of `[service]` entry `{name}` — {reason}; \
                     the service starts unconditionally"
                    ));
                    Vec::new()
                }
                None => raw
                    .into_iter()
                    .map(|c| {
                        let (equals, values) = match (c.is, c.not) {
                            (Some(values), _) => (true, values.into_vec()),
                            (_, Some(values)) => (false, values.into_vec()),
                            // Refused above.
                            (None, None) => unreachable!(),
                        };
                        EnvCondition {
                            // Refused above: the scan drops the whole condition unless every
                            // member names a variable.
                            var: c.env.unwrap_or_default(),
                            equals,
                            values,
                        }
                    })
                    .collect(),
            }
        }
    }
}

/// The readiness gate of one `[service]` entry, or `None` to start the app without waiting.
///
/// Every way the gate can be unreadable — a port outside 1-65535, an unparseable timeout, a timeout
/// outside the accepted range — drops the gate with a warning rather than failing the config,
/// matching how [`service_enable`] treats an unreadable condition.
fn service_ready(
    warnings: &mut Vec<String>,
    source: &str,
    name: &str,
    ready: Option<schema::RawServiceReady>,
) -> Option<ServiceReady> {
    let gate = ready?;
    // The port is an `i64` at the parse layer (see [`schema::RawServiceReady::tcp`]), so every
    // integer TOML accepts arrives here and costs this gate alone rather than the whole config
    // layer. Zero is refused beside the out-of-range values, and for the same reason: nothing
    // listens on it, so the gate would wait for a connection that cannot arrive.
    let Some(tcp) = u16::try_from(gate.tcp).ok().filter(|port| *port != 0) else {
        warnings.push(format!(
            "{source}: ignoring `ready` of `[service]` entry `{name}` — {} is not a port a \
             service can listen on (1-65535)",
            gate.tcp
        ));
        return None;
    };
    let timeout = match gate.timeout.as_deref() {
        None => Some(READY_TIMEOUT_DEFAULT),
        Some(raw) => match parse_duration(raw) {
            Ok(d) => d,
            Err(reason) => {
                warnings.push(format!(
                    "{source}: `ready.timeout` of `[service]` entry `{name}` is invalid — \
                     {reason}; using the default"
                ));
                Some(READY_TIMEOUT_DEFAULT)
            }
        },
    };
    // `parse_duration` reads `0` as "no bound"; a readiness gate that never gives up would hang the
    // launch on a service that never binds, which is the one outcome the gate exists to avoid.
    match timeout {
        Some(timeout) => Some(ServiceReady { tcp, timeout }),
        None => {
            warnings.push(format!(
                "{source}: ignoring `ready` of `[service]` entry `{name}` — a timeout of 0 would \
                 wait forever on a service that never binds"
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A warning is a sentence someone reads, and its literal is written to be readable in both
    /// places. This one had been left unbroken and the formatter wrapped it where it stood, so the
    /// message carried its own source indentation: two ten-space runs, mid-sentence, in the middle
    /// of the one line a user sees when a rule list is quietly doing nothing.
    #[test]
    fn the_inert_network_fields_warning_carries_no_stray_whitespace() {
        let table: schema::NetworkTable =
            toml::from_str("mode = \"shared\"\nallow = [\"api.example.com\"]\n")
                .expect("a `[network]` table with a non-filtering mode");
        let mut warnings = Vec::new();
        validate_network(
            &mut warnings,
            "t",
            NetworkField::Table(table),
            &NetGroups::new(),
            &NetworkPolicy::default(),
        );
        assert_eq!(
            warnings.len(),
            1,
            "one warning naming the inert field: {warnings:?}"
        );
        assert!(
            !warnings[0].contains("  "),
            "the message is one sentence, not a wrapped source literal: {:?}",
            warnings[0]
        );
        // And still the whole message: the wrapping is what changed, never what it says.
        assert!(
            warnings[0].contains("ignoring `allow` under `[network]`")
                && warnings[0].contains("there is no egress proxy for these to address")
                && warnings[0].ends_with("to filter."),
            "{:?}",
            warnings[0]
        );
    }

    /// `capture_max_kb` bounds a captured *body*, so it is inert under `off` and `headers` exactly
    /// as it is with no `capture` at all. The guard keyed off the absence of `capture` while its
    /// message named the level, so two of the three ways to write the mistake passed in silence —
    /// including `capture = "headers"` beside a ceiling, which reads as bodies being kept.
    #[test]
    fn a_body_ceiling_is_named_under_every_capture_level_that_ignores_it() {
        let warnings_for = |text: &str| -> Vec<String> {
            let table: schema::NetworkTable = toml::from_str(text).expect("a table");
            let mut warnings = Vec::new();
            validate_network(
                &mut warnings,
                "t",
                NetworkField::Table(table),
                &NetGroups::new(),
                &NetworkPolicy::default(),
            );
            warnings
        };
        let base = "mode = \"deny\"\nallow = [\"api.example.com\"]\ncapture_max_kb = 256\n";
        for level in ["", "capture = \"off\"\n", "capture = \"headers\"\n"] {
            let warnings = warnings_for(&format!("{base}{level}"));
            assert!(
                warnings.iter().any(|w| w.contains("capture_max_kb")),
                "a ceiling beside `{level}` bounds nothing, so it is named: {warnings:?}"
            );
        }
        // Under `bodies` the ceiling is the setting doing the work, so nothing is said — or the
        // check above would pass by warning about every capture.
        let bodies = warnings_for(&format!("{base}capture = \"bodies\"\n"));
        assert!(bodies.is_empty(), "{bodies:?}");
    }

    /// A readiness gate names a port, and a port a service cannot listen on costs the gate alone.
    /// The value reaches this validator as an `i64` precisely so the range is answered here, where
    /// the service can be named, rather than at the parse layer where it failed the untagged
    /// `RawService` and took the whole config layer with it.
    #[test]
    fn a_ready_gate_on_an_impossible_port_costs_the_gate_and_not_the_service() {
        let raw: BTreeMap<String, schema::RawService> =
            toml::from_str("[gateway]\ncmd = [\"hermes\"]\nready = { tcp = 70000 }\n")
                .expect("a `[service]` table whose port is out of range");
        let mut warnings = Vec::new();
        let out = validate_service(&mut warnings, "t", raw);
        let gateway = out.get("gateway").expect("the service stands");
        assert!(gateway.ready.is_none(), "only the gate is dropped");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("70000") && warnings[0].contains("1-65535"),
            "the port is named with the range it is outside: {warnings:?}"
        );
    }
}
