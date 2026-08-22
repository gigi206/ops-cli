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
    match field {
        NetworkField::Posture(value) => match value.as_str() {
            "none" => Some(NetworkPolicy::Isolated),
            "shared" => Some(NetworkPolicy::Shared),
            // The filtered-egress modes in bare-string form (no carve-out lists): `deny` =
            // deny-by-default (only the built-in set reaches), `allow` = allow-by-default (a
            // denylist; the proxy stays active). Carve-out lists need the `[network]` table.
            "deny" => Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default(),
            )),
            "allow" => Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default()
                    .with_default(crate::allowlist::DefaultAction::Allow),
            )),
            // `ask` in bare-string form parks every unmatched request with no timeout (an
            // indefinite wait); a bound needs the `[network]` table's `ask_timeout`.
            "ask" => Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::default()
                    .with_default(crate::allowlist::DefaultAction::Ask),
            )),
            other => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown network policy `{other}` (expected \
                     \"none\", \"shared\", \"deny\", \"allow\", \"ask\", or an `[network]` table)"
                ));
                None
            }
        },
        NetworkField::Table(table) => {
            validate_network_table(warnings, source_label, table, groups, parent)
        }
    }
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
        Some("none") => return Some(NetworkPolicy::Isolated),
        Some("shared") => return Some(NetworkPolicy::Shared),
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
    let mut policy = crate::allowlist::EgressPolicy::new(allow, deny)
        .with_default(action)
        .with_mute(mute)
        .with_http2(http2);
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
        policy = policy
            .with_ask_timeout(timeout)
            .with_ask_notice(table.ask_notice.unwrap_or(true));
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
    if let Some(raw) = &table.capture {
        match crate::sandbox::control::CaptureLevel::parse(raw) {
            Some(level) => policy = policy.with_capture(level, table.capture_max_kb),
            None => warnings.push(format!(
                "{source_label}: ignoring unknown capture level `{raw}` (expected \"off\", \
                 \"headers\", or \"bodies\") — the traffic capture stays off"
            )),
        }
    } else if table.capture_max_kb.is_some() {
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
    if let NetworkPolicy::Allowlist(below) = parent {
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
    Some(NetworkPolicy::Allowlist(policy))
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
            schema::RawOpen::Argv(cmd) => (cmd, None),
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
        let argv = cmd.into_argv();
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
            schema::RawService::Argv(cmd) => (cmd, None, None),
            schema::RawService::Detailed(table) => (table.cmd, table.enable, table.ready),
        };
        let argv = cmd.into_argv();
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
                    if c.env.is_empty() {
                        Some("a condition names no variable".to_string())
                    } else {
                        match (&c.is, &c.not) {
                            (Some(_), Some(_)) => Some(format!(
                                "the condition on `{}` sets both `is` and `not`, which cannot \
                             both be it",
                                c.env
                            )),
                            (None, None) => Some(format!(
                                "the condition on `{}` sets neither `is` nor `not`, so it \
                             compares nothing",
                                c.env
                            )),
                            (Some(schema::RawValues::Any(v)), None)
                            | (None, Some(schema::RawValues::Any(v)))
                                if v.is_empty() =>
                            {
                                Some(format!(
                                    "the condition on `{}` lists no value, so it compares \
                                 nothing",
                                    c.env
                                ))
                            }
                            _ => None,
                        }
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
                            var: c.env,
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
/// Every way the gate can be unreadable — a port of 0, an unparseable timeout, a timeout outside
/// the accepted range — drops the gate with a warning rather than failing the config, matching how
/// [`service_enable`] treats an unreadable condition.
fn service_ready(
    warnings: &mut Vec<String>,
    source: &str,
    name: &str,
    ready: Option<schema::RawServiceReady>,
) -> Option<ServiceReady> {
    match ready {
        None => None,
        Some(gate) => {
            if gate.tcp == 0 {
                warnings.push(format!(
                    "{source}: ignoring `ready` of `[service]` entry `{name}` — port 0 is not \
                 a port a service can listen on"
                ));
                None
            } else {
                let timeout = match gate.timeout.as_deref() {
                    None => Some(READY_TIMEOUT_DEFAULT),
                    Some(raw) => match parse_duration(raw) {
                        Ok(d) => d,
                        Err(reason) => {
                            warnings.push(format!(
                                "{source}: `ready.timeout` of `[service]` entry `{name}` is \
                             invalid — {reason}; using the default"
                            ));
                            Some(READY_TIMEOUT_DEFAULT)
                        }
                    },
                };
                // `parse_duration` reads `0` as "no bound"; a readiness gate that never gives up
                // would hang the launch on a service that never binds, which is the one outcome
                // the gate exists to avoid.
                match timeout {
                    Some(timeout) => Some(ServiceReady {
                        tcp: gate.tcp,
                        timeout,
                    }),
                    None => {
                        warnings.push(format!(
                            "{source}: ignoring `ready` of `[service]` entry `{name}` — a \
                         timeout of 0 would wait forever on a service that never binds"
                        ));
                        None
                    }
                }
            }
        }
    }
}
