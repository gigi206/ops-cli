//! One-shot configuration overrides carried on the command line or in the environment.
//!
//! An override is the *final word* on a launch's configuration — it beats a trusted project
//! config **and** a named app's overlay — because it comes from the person running `sbx`, whose
//! authority over the process's argv and environment no lower-trust context (an in-cage agent, a
//! project directory) can reach. So an override is trusted *by invocation*, distinct from the
//! direnv-style content trust of a project config: it touches no trust marker.
//!
//! Two surfaces reach every field. A **blob** — `--config <toml|@file>` / `SBX_CONFIG` — carries
//! inline TOML shaped exactly like an `sbx.toml`, so it can set *any* field the schema has. A
//! **typed flag** — `--net`/`--gui`/`--nixpkgs`/`--bind`/`--forward`/`--limit`/`--package`/
//! `--seccomp`/`--device`/`--proc`/`--gpu`/`--audio`/`--dbus` (and their `--env` sibling), each with
//! an `SBX_*` environment equivalent — is an ergonomic shorthand for one field. The booleans
//! `--gpu`/`--audio`/`--dbus` are optional-value (bare = `true`, or `=true`/`=false`); the rest take
//! a required value.
//!
//! Because an override is trusted by invocation, its `--seccomp`/`--device` (and a blob's
//! `[seccomp]`/`[devices]`) relax the mandatory syscall denylist and grant a host device for the
//! one launch. The justification is **parity with the trusted config**: those two fields are
//! trusted-*only* in a config file (an untrusted project's is dropped), and the invoker strictly
//! outranks any config layer — so the override may declare exactly the relaxation/grant a trusted
//! config already can. (This is *not* the same axis as `--net`/`--bind`, which widen host reach:
//! `--seccomp` re-permits a syscall whose only containment was the filter, widening the kernel
//! attack surface reachable from in-cage code — so the ambient-env notice below matters more here.)
//!
//! Precedence, lowest to highest — four tiers:
//!
//! ```text
//! SBX_CONFIG (env blob) < SBX_* typed (env) < --config (cli blob) < --* typed (cli)
//! ```
//!
//! so any CLI input beats any environment one ("the CLI wins over the environment"), and within a
//! source the specific typed input beats the whole-schema blob.
//!
//! The merge across the four tiers is uniform: a **scalar** field (`nixpkgs`/`network`/`gui`) is
//! *replaced* by the highest tier that sets it; a **collection** field (`env`/`packages`/`binds`/
//! `limits`) is *unioned*, the higher tier winning per key/entry. So `--bind` adds to whatever the
//! blobs bound, and `--limit tasks_max=…` tunes one limit without dropping a `memory_max` a blob set.
//!
//! This module only *collects and merges* the inputs into one overlay; the authoritative application
//! onto a resolved configuration is [`super::Resolved::apply_override`] (and
//! [`super::Resolved::apply_override_channel`] for the nixpkgs channel, which must land before the
//! launch picks its lock). A set-but-invalid *value* (a `--gui bogus`, a `--net nonee`) is caught
//! there, fail-closed; this module only rejects a *structural* error (a `--limit` with no `=`, a
//! `--bind` with an empty path).
//!
//! Fail-closed: unlike [`super::load`], which is infallible (a bad config warns and is dropped), a
//! malformed override is an explicit request the user got wrong — [`collect`] returns `Err`, so the
//! launch aborts rather than silently dropping the field and running a different posture than asked.

use super::schema::{
    self, NetworkField, NetworkTable, ProcField, RawBind, RawBindTable, RawConfig, RawDevices,
    RawLimit, RawLimits, RawSeccomp,
};

/// The environment-variable prefix that sets one cage environment variable per key:
/// `SBX_ENV_FOO=bar` contributes `FOO=bar` to the cage environment.
const SBX_ENV_PREFIX: &str = "SBX_ENV_";
/// The environment-variable prefix that tunes one cgroup limit: `SBX_LIMIT_TASKS_MAX=8192`
/// contributes `tasks_max = 8192` (the suffix, lowercased, is the limit field).
const SBX_LIMIT_PREFIX: &str = "SBX_LIMIT_";
/// The environment-variable prefix that declares one package: `SBX_PACKAGE_hello=nix:hello`
/// contributes the `hello` package (the suffix is the package name, the value its backend locator).
const SBX_PACKAGE_PREFIX: &str = "SBX_PACKAGE_";
/// The whole-schema environment blob: inline TOML (or `@<file>`) shaped like an `sbx.toml`.
const SBX_CONFIG: &str = "SBX_CONFIG";

/// A collected, merged one-shot override plus the one-time notices to print before launch.
#[derive(Debug)]
pub(crate) struct Override {
    /// The merged overlay, shaped as a config file. Applied authoritatively last.
    pub(super) raw: RawConfig,
    /// Messages to surface **once**, at collection time — not per apply, which runs twice for
    /// `sbx app` (before and after the app overlay merges). Two kinds: the security-field-via-
    /// environment notices and the ignored-field warnings.
    notices: Vec<String>,
}

impl Override {
    /// An empty override — the no-op the launch paths that take no override flags pass.
    pub(crate) fn none() -> Self {
        Override {
            raw: RawConfig::default(),
            notices: Vec::new(),
        }
    }

    /// The one-time notices to print before launch (borrowed).
    pub(crate) fn notices(&self) -> &[String] {
        &self.notices
    }

    /// Whether nothing was overridden, so a caller can skip the apply entirely (a no-op otherwise).
    pub(crate) fn is_empty(&self) -> bool {
        self.raw == RawConfig::default() && self.notices.is_empty()
    }

    /// Build an override directly from a raw overlay — for the `apply_override` tests, which exercise
    /// the application onto a resolved config, not the collection/merge (covered here).
    #[cfg(test)]
    pub(super) fn for_test(raw: RawConfig) -> Self {
        Override {
            raw,
            notices: Vec::new(),
        }
    }
}

/// The command-line override inputs, already stripped from argv by the caller. Every field is a
/// repeatable list of raw flag values; a *scalar* flag (`--net`/`--gui`/`--nixpkgs`) takes the last
/// occurrence, a *collection* flag (`--bind`/`--limit`/`--package`/`--env`) takes them all.
#[derive(Debug, Default)]
pub(crate) struct CliOverrides {
    /// `--config <toml|@file>` — whole-schema blobs, merged in order (the uniform rule).
    pub(crate) config: Vec<String>,
    /// `--env KEY=VALUE` — one cage environment variable each.
    pub(crate) env: Vec<String>,
    /// `--net <posture|allow=…|deny=…>` — the network posture (last wins).
    pub(crate) net: Vec<String>,
    /// `--gui <none|wayland>` — the display posture (last wins).
    pub(crate) gui: Vec<String>,
    /// `--proc <off|observe|enforce|ask>` — the process/exec posture, a bare mode (last wins). The
    /// full `[proc]` table with `allow`/`deny` lists is set through a `--config` blob.
    pub(crate) proc: Vec<String>,
    /// `--nixpkgs <ref>` — the nixpkgs channel/revision (last wins).
    pub(crate) nixpkgs: Vec<String>,
    /// `--bind <path[:ro|:rw]>` — one host bind each.
    pub(crate) binds: Vec<String>,
    /// `--forward <port[,port…]>` — host loopback TCP ports forwarded into the cage (repeatable;
    /// each value may carry a comma-list). A collection — unioned across the tiers.
    pub(crate) forward: Vec<String>,
    /// `--limit <key>=<value>` — one cgroup limit each.
    pub(crate) limits: Vec<String>,
    /// `--package <name>=<backend:locator>` — one package each.
    pub(crate) packages: Vec<String>,
    /// `--seccomp <token[,token…]>` — relax the mandatory syscall denylist for this launch. Each
    /// value follows the `[seccomp] allow` grammar (a bare name, a `clone`/`ioctl` `:selector`, or a
    /// comma-list). A collection — unioned across the tiers.
    pub(crate) seccomp: Vec<String>,
    /// `--device <path>` — grant one host device node (a `/dev/…` path) into the cage. A collection.
    pub(crate) devices: Vec<String>,
    /// `--gpu[=true|false]` — the GPU posture (a boolean; bare `--gpu` means `true`). Last wins.
    pub(crate) gpu: Vec<String>,
    /// `--audio[=true|false]` — the audio posture (a boolean; bare `--audio` means `true`). Last wins.
    pub(crate) audio: Vec<String>,
    /// `--dbus[=true|false]` — the in-cage desktop portal (a boolean; bare `--dbus` means `true`).
    /// Last wins.
    pub(crate) dbus: Vec<String>,
}

/// The ambient (`SBX_*`) override inputs, scanned from the environment. Passed to [`collect_from`]
/// rather than read there, so the whole merge and its precedence are unit-testable without touching
/// the process environment. The typed fields mirror [`CliOverrides`]; the maps carry the per-key
/// forms (`SBX_ENV_<KEY>`, `SBX_LIMIT_<key>`, `SBX_PACKAGE_<name>`).
#[derive(Debug, Default)]
struct AmbientOverrides {
    /// `SBX_CONFIG` — the whole-schema blob.
    config: Option<String>,
    /// `SBX_ENV_<KEY>` — one cage environment variable each.
    env: Vec<(String, String)>,
    /// `SBX_NET` — the network posture.
    net: Option<String>,
    /// `SBX_GUI` — the display posture.
    gui: Option<String>,
    /// `SBX_PROC` — the process/exec posture (a bare mode).
    proc: Option<String>,
    /// `SBX_NIXPKGS` — the nixpkgs channel/revision.
    nixpkgs: Option<String>,
    /// `SBX_BIND` — one host bind (a list is a blob concern).
    binds: Vec<String>,
    /// `SBX_FORWARD` — host loopback forward ports, a comma-list (e.g. `1455,8080`).
    forward: Vec<String>,
    /// `SBX_LIMIT_<key>` — one cgroup limit each (key lowercased).
    limits: Vec<(String, String)>,
    /// `SBX_PACKAGE_<name>` — one package each.
    packages: Vec<(String, String)>,
    /// `SBX_SECCOMP` — a seccomp relaxation, a comma-list of allow tokens (e.g. `ptrace,unshare`).
    seccomp: Vec<String>,
    /// `SBX_DEVICE` — one host device path (a list is a blob concern, like `SBX_BIND`).
    devices: Vec<String>,
    /// `SBX_GPU` — the GPU posture (`true`/`false`).
    gpu: Option<String>,
    /// `SBX_AUDIO` — the audio posture (`true`/`false`).
    audio: Option<String>,
    /// `SBX_DBUS` — the in-cage desktop portal (`true`/`false`).
    dbus: Option<String>,
}

/// The flag names a typed fragment reports in its structural-error messages, so a `--bind` error
/// and an `SBX_BIND` error each name their own source. `gui`/`nixpkgs` are passthrough (their value
/// is validated downstream, never here), so they carry no label.
struct TypedLabels {
    net: &'static str,
    bind: &'static str,
    limit: &'static str,
    package: &'static str,
    forward: &'static str,
    gpu: &'static str,
    audio: &'static str,
    dbus: &'static str,
}

const CLI_LABELS: TypedLabels = TypedLabels {
    net: "--net",
    bind: "--bind",
    limit: "--limit",
    package: "--package",
    forward: "--forward",
    gpu: "--gpu",
    audio: "--audio",
    dbus: "--dbus",
};

const ENV_LABELS: TypedLabels = TypedLabels {
    net: "SBX_NET",
    bind: "SBX_BIND",
    limit: "SBX_LIMIT_*",
    package: "SBX_PACKAGE_*",
    forward: "SBX_FORWARD",
    gpu: "SBX_GPU",
    audio: "SBX_AUDIO",
    dbus: "SBX_DBUS",
};

/// Collect a one-shot override from the CLI values (already stripped from argv by the caller) and
/// the ambient `SBX_*` environment. Fail-closed: a malformed blob, an unreadable `@file`, or a
/// structurally-bad typed value (a `--limit` with no `=`, a `--bind` with an empty path) is an
/// `Err(message)`.
pub(crate) fn collect(cli: &CliOverrides) -> Result<Override, String> {
    collect_from(cli, scan_ambient())
}

/// Read the ambient `SBX_*` override variables from the environment. Exact names first, then the
/// per-key prefixes; the two never collide (`SBX_NET` is not an `SBX_ENV_*`).
fn scan_ambient() -> AmbientOverrides {
    let mut a = AmbientOverrides {
        config: env_nonempty(SBX_CONFIG),
        net: env_nonempty("SBX_NET"),
        gui: env_nonempty("SBX_GUI"),
        proc: env_nonempty("SBX_PROC"),
        nixpkgs: env_nonempty("SBX_NIXPKGS"),
        gpu: env_nonempty("SBX_GPU"),
        audio: env_nonempty("SBX_AUDIO"),
        dbus: env_nonempty("SBX_DBUS"),
        ..AmbientOverrides::default()
    };
    if let Some(v) = env_nonempty("SBX_BIND") {
        a.binds.push(v);
    }
    if let Some(v) = env_nonempty("SBX_FORWARD") {
        a.forward.push(v);
    }
    if let Some(v) = env_nonempty("SBX_SECCOMP") {
        a.seccomp.push(v);
    }
    if let Some(v) = env_nonempty("SBX_DEVICE") {
        a.devices.push(v);
    }
    for (k, v) in std::env::vars() {
        if let Some(name) = k.strip_prefix(SBX_ENV_PREFIX) {
            if !name.is_empty() {
                a.env.push((name.to_string(), v));
            }
        } else if let Some(key) = k.strip_prefix(SBX_LIMIT_PREFIX) {
            if !key.is_empty() {
                a.limits.push((key.to_lowercase(), v));
            }
        } else if let Some(name) = k.strip_prefix(SBX_PACKAGE_PREFIX) {
            if !name.is_empty() {
                a.packages.push((name.to_string(), v));
            }
        }
    }
    a
}

/// The value of an environment variable, or `None` if unset or empty.
fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

/// The pure core of [`collect`]: the ambient environment is passed in. Builds the four precedence
/// tiers (`SBX_CONFIG` blob, `SBX_*` typed, `--config` blob, `--*` typed), folds each into one
/// overlay per the uniform merge rule, and records the one-time notices.
fn collect_from(cli: &CliOverrides, ambient: AmbientOverrides) -> Result<Override, String> {
    // Tier 0 — the environment blob.
    let t0 = match &ambient.config {
        Some(s) => parse_blob(s).map_err(|e| format!("{SBX_CONFIG}: {e}"))?,
        None => RawConfig::default(),
    };
    // Tier 1 — the environment's typed fragments.
    let t1 = build_typed_fragment(
        ambient.net.as_deref(),
        ambient.gui.as_deref(),
        ambient.proc.as_deref(),
        ambient.nixpkgs.as_deref(),
        ambient.gpu.as_deref(),
        ambient.audio.as_deref(),
        ambient.dbus.as_deref(),
        &ambient.binds,
        &ambient.forward,
        &ambient.limits,
        &ambient.packages,
        &ambient.env,
        &ambient.seccomp,
        &ambient.devices,
        &ENV_LABELS,
    )?;
    // Tier 2 — the CLI blobs, merged in order (a later one winning per the uniform rule).
    let mut t2 = RawConfig::default();
    for (i, c) in cli.config.iter().enumerate() {
        let parsed = parse_blob(c).map_err(|e| format!("--config (#{}): {e}", i + 1))?;
        t2 = overlay_into(t2, parsed);
    }
    // Tier 3 — the CLI's typed fragments.
    let cli_limits = split_kv(&cli.limits, "--limit")?;
    let cli_packages = split_kv(&cli.packages, "--package")?;
    let cli_env = split_kv(&cli.env, "--env")?;
    let t3 = build_typed_fragment(
        cli.net.last().map(String::as_str),
        cli.gui.last().map(String::as_str),
        cli.proc.last().map(String::as_str),
        cli.nixpkgs.last().map(String::as_str),
        cli.gpu.last().map(String::as_str),
        cli.audio.last().map(String::as_str),
        cli.dbus.last().map(String::as_str),
        &cli.binds,
        &cli.forward,
        &cli_limits,
        &cli_packages,
        &cli_env,
        &cli.seccomp,
        &cli.devices,
        &CLI_LABELS,
    )?;

    // Fold each source into its side, then merge the sides. Keeping the two sides distinct lets the
    // notice logic tell an environment-sourced field from a CLI-sourced one.
    let env_side = overlay_into(t0, t1);
    let cli_side = overlay_into(t2, t3);

    let mut notices = Vec::new();
    push_ignored_field_notices(&env_side, &cli_side, &mut notices);
    push_env_source_notices(&env_side, &cli_side, &mut notices);

    let merged = overlay_into(env_side, cli_side);
    Ok(Override {
        raw: merged,
        notices,
    })
}

/// Note the fields an override carries that are not one-shot launch concepts: egress groups are a
/// global-config affordance, and an override shapes *the* launch rather than defining apps. They are
/// dropped (ignored downstream), so the notice is the only signal.
fn push_ignored_field_notices(
    env_side: &RawConfig,
    cli_side: &RawConfig,
    notices: &mut Vec<String>,
) {
    if !env_side.net.groups.is_empty() || !cli_side.net.groups.is_empty() {
        notices.push(
            "ignoring `[net.groups]` in the override — it is not a one-shot launch field"
                .to_string(),
        );
    }
    if !env_side.app.is_empty() || !cli_side.app.is_empty() {
        notices.push(
            "ignoring `[app.*]` in the override — it is not a one-shot launch field".to_string(),
        );
    }
}

/// Push a notice for each **security** field whose value the environment (either the `SBX_CONFIG`
/// blob or an `SBX_*` typed variable) contributed — so a stale ambient variable cannot silently
/// change a launch's posture without a word. `env` is a *free* field (folded without a notice).
///
/// A replaced (scalar) field is environment-sourced when the CLI did not set it but the environment
/// did; a unioned (collection) field is noted whenever the environment contributed any entry, since
/// its value then carries an ambient contribution even if the CLI added more.
fn push_env_source_notices(env_side: &RawConfig, cli_side: &RawConfig, notices: &mut Vec<String>) {
    let mut note = |field: &str| {
        notices.push(format!(
            "security field `{field}` set from the environment — an ambient SBX_* variable changes \
             every launch; set it on the command line for a true one-shot"
        ));
    };
    // Replaced scalars: noted when only the environment set them.
    for (field, env_has, cli_has) in [
        (
            "nixpkgs",
            env_side.nixpkgs.is_some(),
            cli_side.nixpkgs.is_some(),
        ),
        (
            "network",
            env_side.network.is_some(),
            cli_side.network.is_some(),
        ),
        ("gui", env_side.gui.is_some(), cli_side.gui.is_some()),
        ("proc", env_side.proc.is_some(), cli_side.proc.is_some()),
        ("gpu", env_side.gpu.is_some(), cli_side.gpu.is_some()),
        ("audio", env_side.audio.is_some(), cli_side.audio.is_some()),
        ("dbus", env_side.dbus.is_some(), cli_side.dbus.is_some()),
        (
            "secret",
            env_side.secret.is_some(),
            cli_side.secret.is_some(),
        ),
    ] {
        if env_has && !cli_has {
            note(field);
        }
    }
    // Unioned collections: noted whenever the environment contributed.
    for (field, env_has) in [
        ("binds", !env_side.binds.is_empty()),
        ("packages", !env_side.packages.is_empty()),
        ("limits", env_side.limits.is_some()),
        ("forward", env_side.forward.is_some()),
        ("seccomp", env_side.seccomp.is_some()),
        ("devices", env_side.devices.is_some()),
    ] {
        if env_has {
            note(field);
        }
    }
}

/// Merge `higher` onto `base` per the uniform rule: a scalar field is replaced when `higher` sets
/// it; a collection field is unioned, `higher` winning per key/entry. This is the one merge — used
/// for repeated `--config` blobs, for folding a typed fragment onto a blob, and for merging the two
/// precedence sides. `[net.groups]`/`[app.*]` ride along (ignored downstream but noticed).
fn overlay_into(mut base: RawConfig, higher: RawConfig) -> RawConfig {
    base.env.extend(higher.env);
    base.packages.extend(higher.packages);
    base.binds = union_binds(base.binds, higher.binds);
    base.limits = union_limits(base.limits, higher.limits);
    if higher.nixpkgs.is_some() {
        base.nixpkgs = higher.nixpkgs;
    }
    if higher.network.is_some() {
        base.network = higher.network;
    }
    if higher.gui.is_some() {
        base.gui = higher.gui;
    }
    if higher.proc.is_some() {
        base.proc = higher.proc;
    }
    if higher.gpu.is_some() {
        base.gpu = higher.gpu;
    }
    if higher.audio.is_some() {
        base.audio = higher.audio;
    }
    if higher.dbus.is_some() {
        base.dbus = higher.dbus;
    }
    if higher.secret.is_some() {
        base.secret = higher.secret;
    }
    base.forward = union_forward_opt(base.forward, higher.forward);
    base.seccomp = union_allow_opt(base.seccomp, higher.seccomp, |s| &mut s.allow);
    base.devices = union_allow_opt(base.devices, higher.devices, |d| &mut d.allow);
    base.net.groups.extend(higher.net.groups);
    base.app.extend(higher.app);
    base
}

/// Union two optional `{ allow: Vec<String> }` tables (`[seccomp]` / `[devices]`), a higher tier's
/// entries appended onto a lower's — the collection-union rule, so `--seccomp`/`--device` accumulate
/// across the tiers rather than clobbering a blob's list. `None` means "this tier set none". The
/// downstream `apply_*` dedups (devices) or is idempotent (seccomp), so a plain append is enough.
fn union_allow_opt<T>(
    base: Option<T>,
    higher: Option<T>,
    allow: impl Fn(&mut T) -> &mut Vec<String>,
) -> Option<T> {
    match (base, higher) {
        (b, None) => b,
        (None, h) => h,
        (Some(mut b), Some(mut h)) => {
            let extra = std::mem::take(allow(&mut h));
            allow(&mut b).extend(extra);
            Some(b)
        }
    }
}

/// The destination path a bind is keyed by (the same path it is bound at in the cage). A detailed
/// table missing its `path` is malformed — it has no key, so it only ever appends.
fn bind_path(b: &RawBind) -> Option<&str> {
    match b {
        RawBind::Path(p) => Some(p),
        RawBind::Detailed(t) => t.path.as_deref(),
    }
}

/// Union two bind lists, a higher-tier entry replacing a lower-tier one that binds the same path, so
/// `--bind /data:rw` overrides an `SBX_BIND=/data:ro`. Order is preserved; a keyless (malformed)
/// entry appends.
fn union_binds(mut base: Vec<RawBind>, higher: Vec<RawBind>) -> Vec<RawBind> {
    for h in higher {
        match bind_path(&h).map(str::to_string) {
            Some(p) => match base.iter_mut().find(|b| bind_path(b) == Some(p.as_str())) {
                Some(existing) => *existing = h,
                None => base.push(h),
            },
            None => base.push(h),
        }
    }
    base
}

/// Union two limit tables per field, a higher-tier field winning. So `--limit tasks_max=…` tunes one
/// limit over a blob's `memory_max` rather than replacing the whole table (dropping it).
fn union_limits(base: Option<RawLimits>, higher: Option<RawLimits>) -> Option<RawLimits> {
    match (base, higher) {
        (b, None) => b,
        (None, h) => h,
        (Some(mut b), Some(h)) => {
            if h.memory_high.is_some() {
                b.memory_high = h.memory_high;
            }
            if h.memory_max.is_some() {
                b.memory_max = h.memory_max;
            }
            if h.tasks_max.is_some() {
                b.tasks_max = h.tasks_max;
            }
            Some(b)
        }
    }
}

/// Union two optional forward port lists, deduped and sorted. `None` means "this tier set none"; a
/// higher tier's ports add to a lower's, never replace — the collection-union rule, so `--forward`
/// over `SBX_FORWARD` accumulates rather than clobbers.
fn union_forward_opt(base: Option<Vec<u16>>, higher: Option<Vec<u16>>) -> Option<Vec<u16>> {
    match (base, higher) {
        (b, None) => b,
        (None, h) => h,
        (Some(mut b), Some(h)) => {
            // Reuse the resolver's port-union (dedup + sort) so the two paths cannot drift.
            super::union_forward(&mut b, h);
            Some(b)
        }
    }
}

/// Parse one `--forward` value — a single port or a comma-list of ports — into `Vec<u16>`. A
/// structural error (an empty value, or a token that is not a port number) is fail-closed, since it
/// is an explicit request the user mistyped. A port of `0` parses here and is dropped downstream
/// by the resolver's validator (a value-range concern, not a structural one — the additive model).
fn parse_forward(spec: &str, label: &str) -> Result<Vec<u16>, String> {
    let ports: Vec<u16> = spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|t| {
            t.parse::<u16>()
                .map_err(|_| format!("{label}: `{t}` is not a valid port (expected 0–65535)"))
        })
        .collect::<Result<_, _>>()?;
    if ports.is_empty() {
        return Err(format!("{label}: no ports given"));
    }
    Ok(ports)
}

/// Build a `RawConfig` fragment from a source's typed inputs. A *structural* error (a bad `--net`
/// posture keyword, an empty `--bind` path, an unknown `--limit` key, an empty `--package` name) is
/// fail-closed; a set-but-invalid *value* passes through to the downstream validation.
#[allow(clippy::too_many_arguments)]
fn build_typed_fragment(
    net: Option<&str>,
    gui: Option<&str>,
    proc: Option<&str>,
    nixpkgs: Option<&str>,
    gpu: Option<&str>,
    audio: Option<&str>,
    dbus: Option<&str>,
    binds: &[String],
    forward: &[String],
    limits: &[(String, String)],
    packages: &[(String, String)],
    env: &[(String, String)],
    seccomp: &[String],
    devices: &[String],
    lbl: &TypedLabels,
) -> Result<RawConfig, String> {
    let mut raw = RawConfig::default();
    if let Some(v) = net {
        raw.network = Some(parse_net(v, lbl.net)?);
    }
    if let Some(v) = gui {
        raw.gui = Some(v.to_string());
    }
    // `--proc` sets only the mode (the bare-string form of the `proc` field); the mode value is
    // validated downstream (an unknown mode is fatal for an override, like `--gui`/`--net`), and the
    // full `[proc]` table with `allow`/`deny` lists is set through a `--config` blob.
    if let Some(v) = proc {
        raw.proc = Some(ProcField::Mode(v.to_string()));
    }
    if let Some(v) = nixpkgs {
        raw.nixpkgs = Some(v.to_string());
    }
    // `--gpu` is a boolean, so — unlike `gui`/`nixpkgs` whose value is validated downstream — the
    // only valid grammar is `true`/`false`, checked here (structural, fail-closed). A bare `--gpu`
    // is normalized to `"true"` by the CLI parser before it reaches this point.
    if let Some(v) = gpu {
        raw.gpu = Some(parse_bool(v, lbl.gpu)?);
    }
    // `--audio` is a boolean, exactly like `--gpu`: `true`/`false` only, checked here (a bare
    // `--audio` is normalized to `"true"` by the CLI parser before it reaches this point).
    if let Some(v) = audio {
        raw.audio = Some(parse_bool(v, lbl.audio)?);
    }
    // `--dbus` is a boolean, exactly like `--gpu`: `true`/`false` only, checked here (a bare `--dbus`
    // is normalized to `"true"` by the CLI parser). A stale `--dbus=incage` is rejected here (exit 2).
    if let Some(v) = dbus {
        raw.dbus = Some(parse_bool(v, lbl.dbus)?);
    }
    for spec in binds {
        raw.binds.push(parse_bind(spec, lbl.bind)?);
    }
    let mut ports: Vec<u16> = Vec::new();
    for spec in forward {
        ports.extend(parse_forward(spec, lbl.forward)?);
    }
    if !ports.is_empty() {
        raw.forward = Some(ports);
    }
    for (key, value) in limits {
        set_limit(&mut raw.limits, key, value, lbl.limit)?;
    }
    for (name, locator) in packages {
        if name.is_empty() {
            return Err(format!("{}: empty package name", lbl.package));
        }
        raw.packages.insert(name.clone(), locator.clone());
    }
    for (key, value) in env {
        raw.env.insert(key.clone(), value.clone());
    }
    // `--seccomp` / `--device` carry their entries verbatim into the `[seccomp]` / `[devices]`
    // `allow` lists — the exact config-file grammar, so `apply_seccomp`/`apply_devices` validate
    // them downstream (a bad token/path is warned and skipped, an additive collection like `binds`,
    // never a structural error here). A seccomp value is comma-splittable there; a device value is
    // one path (the field does not comma-split a device).
    if !seccomp.is_empty() {
        raw.seccomp = Some(RawSeccomp {
            allow: seccomp.to_vec(),
        });
    }
    if !devices.is_empty() {
        raw.devices = Some(RawDevices {
            allow: devices.to_vec(),
        });
    }
    Ok(raw)
}

/// Parse a boolean typed-flag value (`--gpu`/`--dbus`, `SBX_GPU`/`SBX_DBUS`). Only `true`/`false` are
/// valid; anything else is a structural error, fail-closed — an explicit request the user mistyped.
fn parse_bool(value: &str, label: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "{label}: expected `true` or `false`, got `{other}`"
        )),
    }
}

/// Parse a `--net` value into a `network` field. The postures `none`/`shared`/`ask` pass through
/// verbatim (validated downstream); `allow=h1,h2` becomes a default-deny allowlist and `deny=h1,h2`
/// a default-allow denylist — the common one-shot egress shapes. A bare `allow`/`deny` is refused as
/// ambiguous (it reads like the list forms but means the opposite, a wide-open posture); an unknown
/// keyword passes through and is caught by the downstream posture validation.
fn parse_net(value: &str, label: &str) -> Result<NetworkField, String> {
    if let Some(hosts) = value.strip_prefix("allow=") {
        return Ok(net_table(
            "deny",
            split_hosts(hosts, label, "allow")?,
            Vec::new(),
        ));
    }
    if let Some(hosts) = value.strip_prefix("deny=") {
        return Ok(net_table(
            "allow",
            Vec::new(),
            split_hosts(hosts, label, "deny")?,
        ));
    }
    if value == "allow" || value == "deny" {
        return Err(format!(
            "{label}: bare `{value}` is ambiguous — use `{label} allow=host,…` to restrict egress \
             to those hosts, or `--config` for a raw posture"
        ));
    }
    Ok(NetworkField::Posture(value.to_string()))
}

/// Split a comma-separated host list, trimming each and rejecting an empty result (a `--net allow=`
/// with no hosts is a structural error, not a silent all-deny).
fn split_hosts(hosts: &str, label: &str, kind: &str) -> Result<Vec<String>, String> {
    let list: Vec<String> = hosts
        .split(',')
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_string)
        .collect();
    if list.is_empty() {
        return Err(format!("{label}: `{kind}=` needs at least one host"));
    }
    Ok(list)
}

/// A `network` table with a mode and carve-out lists, the other fields left to inherit.
fn net_table(mode: &str, allow: Vec<String>, deny: Vec<String>) -> NetworkField {
    NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        mode: Some(mode.to_string()),
        allow,
        deny,
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
    })
}

/// Parse a `--bind` spec `path[:ro|:rw]` — the mode is the suffix after the **last** colon, and only
/// when it is exactly `ro` or `rw`, so a path that itself contains a colon (`/my:dir`) is not
/// mis-parsed. Read-only (the default) yields the bare-path form; read-write the detailed table. An
/// empty path is a structural error.
fn parse_bind(spec: &str, label: &str) -> Result<RawBind, String> {
    let (path, rw) = match spec.rsplit_once(':') {
        Some((p, "rw")) => (p, true),
        Some((p, "ro")) => (p, false),
        _ => (spec, false),
    };
    if path.is_empty() {
        return Err(format!("{label}: empty bind path in `{spec}`"));
    }
    Ok(if rw {
        RawBind::Detailed(RawBindTable {
            path: Some(path.to_string()),
            mode: Some("rw".to_string()),
        })
    } else {
        RawBind::Path(path.to_string())
    })
}

/// Set one cgroup limit on the fragment's `[limits]` table. The key must name a limit field; the
/// value parses to a bare number (`RawLimit::Number`) or a string form (`RawLimit::Text`) — exactly
/// the two TOML shapes — so the downstream systemd-grammar and bare-byte-floor checks apply
/// unchanged.
fn set_limit(
    limits: &mut Option<RawLimits>,
    key: &str,
    value: &str,
    label: &str,
) -> Result<(), String> {
    let table = limits.get_or_insert_with(RawLimits::default);
    let parsed = parse_raw_limit(value);
    match key {
        "memory_high" => table.memory_high = Some(parsed),
        "memory_max" => table.memory_max = Some(parsed),
        "tasks_max" => table.tasks_max = Some(parsed),
        other => {
            return Err(format!(
                "{label}: unknown limit `{other}` (memory_high | memory_max | tasks_max)"
            ))
        }
    }
    Ok(())
}

/// One limit value as declared: a bare number is a `Number` (a byte count for memory, a task count),
/// anything else a `Text` (`"80%"`, `"16G"`, `"infinity"`) validated downstream.
fn parse_raw_limit(value: &str) -> RawLimit {
    match value.parse::<u64>() {
        Ok(n) => RawLimit::Number(n),
        Err(_) => RawLimit::Text(value.to_string()),
    }
}

/// Parse one blob value: `@<path>` reads the file, anything else is inline TOML. The bytes are then
/// parsed as an `sbx.toml`-shaped config.
fn parse_blob(value: &str) -> Result<RawConfig, String> {
    let bytes = match value.strip_prefix('@') {
        Some(path) => {
            std::fs::read(path).map_err(|e| format!("cannot read override file `{path}`: {e}"))?
        }
        None => value.as_bytes().to_vec(),
    };
    schema::parse(&bytes)
}

/// Split `KEY=VALUE` items into pairs on the first `=`, so a value may itself contain `=`. An item
/// without `=` is a hard error — fail-closed, since a silently dropped `--env FOO` (or `--limit
/// tasks_max`) would launch differently than asked.
fn split_kv(items: &[String], label: &str) -> Result<Vec<(String, String)>, String> {
    items
        .iter()
        .map(|e| {
            e.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| format!("{label} `{e}`: expected KEY=VALUE"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `CliOverrides` from borrowed slices, for terse test call sites.
    #[derive(Default)]
    struct Cli<'a> {
        config: &'a [&'a str],
        env: &'a [&'a str],
        net: &'a [&'a str],
        gui: &'a [&'a str],
        proc: &'a [&'a str],
        nixpkgs: &'a [&'a str],
        binds: &'a [&'a str],
        forward: &'a [&'a str],
        limits: &'a [&'a str],
        packages: &'a [&'a str],
        seccomp: &'a [&'a str],
        devices: &'a [&'a str],
        gpu: &'a [&'a str],
        audio: &'a [&'a str],
        dbus: &'a [&'a str],
    }

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn collect_cli(cli: Cli) -> Result<Override, String> {
        let overrides = CliOverrides {
            config: owned(cli.config),
            env: owned(cli.env),
            net: owned(cli.net),
            gui: owned(cli.gui),
            proc: owned(cli.proc),
            nixpkgs: owned(cli.nixpkgs),
            binds: owned(cli.binds),
            forward: owned(cli.forward),
            limits: owned(cli.limits),
            packages: owned(cli.packages),
            seccomp: owned(cli.seccomp),
            devices: owned(cli.devices),
            gpu: owned(cli.gpu),
            audio: owned(cli.audio),
            dbus: owned(cli.dbus),
        };
        collect_from(&overrides, AmbientOverrides::default())
    }

    fn ambient(a: AmbientOverrides) -> Result<Override, String> {
        collect_from(&CliOverrides::default(), a)
    }

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn posture(name: &str) -> NetworkField {
        NetworkField::Posture(name.to_string())
    }

    #[test]
    fn an_empty_override_is_a_no_op() {
        let ov = collect_cli(Cli::default()).unwrap();
        assert!(ov.is_empty());
    }

    #[test]
    fn a_cli_config_blob_parses_every_field() {
        let ov = collect_cli(Cli {
            config: &["network = \"none\"\ngui = \"wayland\""],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("none")));
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
    }

    #[test]
    fn the_forward_flag_parses_a_comma_list_and_unions_across_tiers() {
        // A single `--forward` value may carry a comma-list; repeated flags accumulate; and the
        // env tier (`SBX_FORWARD`) unions with the CLI tier rather than being replaced.
        let ov = collect_from(
            &CliOverrides {
                forward: owned(&["1455", "8080,9090"]),
                ..Default::default()
            },
            AmbientOverrides {
                forward: vec!["3000".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.raw.forward, Some(vec![1455, 3000, 8080, 9090]));
        // The env contributed a security-relevant collection, so a source notice fires.
        assert!(ov
            .notices()
            .iter()
            .any(|n| n.contains("forward") && n.contains("environment")));
    }

    #[test]
    fn the_gpu_and_dbus_bool_flags_parse_bare_and_explicit() {
        // The CLI parser normalizes a bare `--gpu` to `"true"`; `--gpu=false` disables (so a profile's
        // `gpu = true` can be overridden off for one launch), and the last occurrence wins.
        let ov = collect_cli(Cli {
            gpu: &["true"],
            dbus: &["false"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.gpu, Some(true));
        assert_eq!(ov.raw.dbus, Some(false));

        let last_wins = collect_cli(Cli {
            gpu: &["true", "false"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(last_wins.raw.gpu, Some(false));
    }

    #[test]
    fn a_non_boolean_gpu_value_is_a_hard_error() {
        let err = collect_cli(Cli {
            gpu: &["maybe"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("--gpu") && err.contains("true"));
    }

    #[test]
    fn a_stale_dbus_incage_value_is_a_hard_error() {
        // `dbus` is now a bool; the former `--dbus=incage` string must fail LOUDLY (a usage error),
        // never silently drop to no-portal.
        let err = collect_cli(Cli {
            dbus: &["incage"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("--dbus") && err.contains("true"));
    }

    #[test]
    fn a_cli_gpu_flag_beats_an_ambient_sbx_gpu_and_the_env_source_notice_fires() {
        // The command line beats the environment (CLI `false` wins over `SBX_GPU=true`); and because
        // `SBX_DBUS` (a security field) is set only in the environment, a source notice fires for it.
        let ov = collect_from(
            &CliOverrides {
                gpu: owned(&["false"]),
                ..Default::default()
            },
            AmbientOverrides {
                gpu: Some("true".into()),
                dbus: Some("true".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.raw.gpu, Some(false));
        assert_eq!(ov.raw.dbus, Some(true));
        // `gpu` was also set on the CLI, so no notice for it; `dbus` came only from the environment.
        assert!(ov
            .notices()
            .iter()
            .any(|n| n.contains("dbus") && n.contains("environment")));
        assert!(!ov.notices().iter().any(|n| n.contains("`gpu`")));
    }

    #[test]
    fn a_non_numeric_forward_value_is_a_hard_error() {
        let err = collect_cli(Cli {
            forward: &["1455,notaport"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            err.contains("--forward") && err.contains("notaport"),
            "a bad port must be a structural error naming the flag: {err}"
        );
    }

    #[test]
    fn a_malformed_blob_is_a_hard_error_not_a_silent_drop() {
        let err = collect_cli(Cli {
            config: &["network = = nope"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.starts_with("--config (#1):"), "{err}");
        let err = ambient(AmbientOverrides {
            config: Some("not = = toml".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.starts_with("SBX_CONFIG:"), "{err}");
    }

    #[test]
    fn the_cli_beats_the_environment_per_field() {
        // SBX_CONFIG says shared, --config says none: the CLI wins, and because the winning value is
        // from the CLI, no security-via-env notice fires.
        let ov = collect_from(
            &CliOverrides {
                config: owned(&["network = \"none\""]),
                ..Default::default()
            },
            AmbientOverrides {
                config: Some("network = \"shared\"".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("none")));
        assert!(ov.notices().is_empty(), "{:?}", ov.notices());
    }

    #[test]
    fn a_security_field_only_in_the_environment_is_noticed() {
        let ov = ambient(AmbientOverrides {
            config: Some("network = \"none\"".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("none")));
        assert_eq!(ov.notices().len(), 1);
        assert!(
            ov.notices()[0].contains("security field `network`"),
            "{:?}",
            ov.notices()
        );
    }

    #[test]
    fn env_precedence_is_sbx_config_then_sbx_env_then_config_then_env() {
        // K set in all four sources: --env wins. Keys unique to a source survive untouched.
        let ov = collect_from(
            &CliOverrides {
                config: owned(&["[env]\nK = \"from-config\"\nONLY_CFG = \"c\""]),
                env: owned(&["K=from-cli-env"]),
                ..Default::default()
            },
            AmbientOverrides {
                config: Some("[env]\nK = \"from-sbx-config\"\nONLY_SBX = \"o\"".into()),
                env: pairs(&[("K", "from-sbx-env")]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            ov.raw.env.get("K").map(String::as_str),
            Some("from-cli-env")
        );
        assert_eq!(ov.raw.env.get("ONLY_SBX").map(String::as_str), Some("o"));
        assert_eq!(ov.raw.env.get("ONLY_CFG").map(String::as_str), Some("c"));
        assert!(ov.notices().is_empty(), "env is free — no notice");
    }

    #[test]
    fn sbx_env_per_key_variables_become_cage_env() {
        let ov = ambient(AmbientOverrides {
            env: pairs(&[("FOO", "bar"), ("BAZ", "qux")]),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(ov.raw.env.get("BAZ").map(String::as_str), Some("qux"));
    }

    #[test]
    fn a_bad_env_pair_is_a_hard_error() {
        let err = collect_cli(Cli {
            env: &["NOEQUALS"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("expected KEY=VALUE"), "{err}");
    }

    #[test]
    fn a_repeated_config_flag_merges_later_winning_scalars_and_unioning_collections() {
        let ov = collect_cli(Cli {
            config: &[
                "network = \"none\"\ngui = \"wayland\"\nbinds = [\"/a\"]",
                "network = \"shared\"\nbinds = [\"/b\"]",
            ],
            ..Default::default()
        })
        .unwrap();
        // the scalar network is replaced (later wins); gui survives (unset in the second)
        assert_eq!(ov.raw.network, Some(posture("shared")));
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
        // the collection binds unions across the two blobs
        assert_eq!(
            ov.raw.binds.len(),
            2,
            "binds should union: {:?}",
            ov.raw.binds
        );
    }

    #[test]
    fn every_launch_field_survives_the_merge_into_the_overlay() {
        // Regression guard: the fold must copy *every* launch field into the merged overlay — a
        // field dropped here (as `limits` once was, in the fold and in the repeated-blob merge)
        // silently defeats its validation and application downstream.
        let ov = collect_cli(Cli {
            config: &[r#"
                nixpkgs = "nixos-23.11"
                network = "none"
                gui = "wayland"
                forward = [1455]
                binds = ["/opt/data"]
                [env]
                E = "1"
                [packages]
                p = "nix:hello"
                [limits]
                tasks_max = 4096
                [secret."api.example.com"]
                from = "env://K"
                header = "X"
                type = "raw"
            "#],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.nixpkgs.as_deref(), Some("nixos-23.11"));
        assert!(ov.raw.network.is_some(), "network dropped in merge");
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
        assert_eq!(
            ov.raw.forward.as_deref(),
            Some(&[1455][..]),
            "forward dropped in merge"
        );
        assert!(!ov.raw.binds.is_empty(), "binds dropped in merge");
        assert_eq!(ov.raw.env.get("E").map(String::as_str), Some("1"));
        assert!(
            ov.raw.packages.contains_key("p"),
            "packages dropped in merge"
        );
        assert!(ov.raw.limits.is_some(), "limits dropped in merge");
        assert!(ov.raw.secret.is_some(), "secret dropped in merge");
    }

    #[test]
    fn a_repeated_limits_blob_unions_per_field() {
        // The repeated-blob merge must union `[limits]` per field, not replace it — `merge_raw` once
        // omitted `limits` entirely, so the second blob's table silently vanished.
        let ov = collect_cli(Cli {
            config: &[
                "[limits]\nmemory_max = \"80%\"",
                "[limits]\ntasks_max = 4096",
            ],
            ..Default::default()
        })
        .unwrap();
        let limits = ov.raw.limits.expect("limits present");
        assert!(
            limits.memory_max.is_some(),
            "memory_max from the first blob dropped"
        );
        assert!(
            limits.tasks_max.is_some(),
            "tasks_max from the second blob dropped"
        );
    }

    #[test]
    fn net_groups_and_apps_in_an_override_are_ignored_with_a_notice() {
        let ov = collect_cli(Cli {
            config: &["[net.groups]\nx = [\"a.example.com\"]\n[app.demo]\ncmd = \"demo\""],
            ..Default::default()
        })
        .unwrap();
        let text = ov.notices().join("\n");
        assert!(text.contains("[net.groups]"), "{text}");
        assert!(text.contains("[app.*]"), "{text}");
    }

    #[test]
    fn a_config_file_reference_reads_the_file() {
        let dir = crate::testutil::TmpDir::new();
        let file = dir.join("ov.toml");
        std::fs::write(&file, b"network = \"none\"\n").unwrap();
        let arg = format!("@{}", file.display());
        let ov = collect_cli(Cli {
            config: &[&arg],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("none")));
    }

    #[test]
    fn a_missing_config_file_is_a_hard_error() {
        let err = collect_cli(Cli {
            config: &["@/no/such/sbx-override.toml"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("cannot read override file"), "{err}");
    }

    // --- typed flags (increment 2) ---

    #[test]
    fn a_typed_net_posture_and_the_allow_deny_dsl_parse() {
        assert_eq!(
            collect_cli(Cli {
                net: &["none"],
                ..Default::default()
            })
            .unwrap()
            .raw
            .network,
            Some(posture("none"))
        );
        // allow=… is a default-deny allowlist
        let ov = collect_cli(Cli {
            net: &["allow=a.example.com,b.example.com"],
            ..Default::default()
        })
        .unwrap();
        match ov.raw.network {
            Some(NetworkField::Table(t)) => {
                assert_eq!(t.mode.as_deref(), Some("deny"));
                assert_eq!(t.allow, vec!["a.example.com", "b.example.com"]);
                assert!(t.deny.is_empty());
            }
            other => panic!("expected a table, got {other:?}"),
        }
        // deny=… is a default-allow denylist
        let ov = collect_cli(Cli {
            net: &["deny=x.example.com"],
            ..Default::default()
        })
        .unwrap();
        match ov.raw.network {
            Some(NetworkField::Table(t)) => {
                assert_eq!(t.mode.as_deref(), Some("allow"));
                assert_eq!(t.deny, vec!["x.example.com"]);
            }
            other => panic!("expected a table, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_net_allow_or_deny_is_refused_as_ambiguous() {
        let err = collect_cli(Cli {
            net: &["allow"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
        let err = collect_cli(Cli {
            net: &["deny"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("ambiguous"), "{err}");
        // an empty host list is structural too
        let err = collect_cli(Cli {
            net: &["allow="],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("at least one host"), "{err}");
    }

    #[test]
    fn typed_gui_and_nixpkgs_pass_through() {
        let ov = collect_cli(Cli {
            gui: &["wayland"],
            nixpkgs: &["nixos-23.11"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.gui.as_deref(), Some("wayland"));
        assert_eq!(ov.raw.nixpkgs.as_deref(), Some("nixos-23.11"));
    }

    #[test]
    fn a_typed_bind_parses_the_mode_off_the_last_colon() {
        // read-only default -> bare path
        let ov = collect_cli(Cli {
            binds: &["/data"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.binds, vec![RawBind::Path("/data".into())]);
        // :rw -> detailed table
        let ov = collect_cli(Cli {
            binds: &["/data:rw"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ov.raw.binds,
            vec![RawBind::Detailed(RawBindTable {
                path: Some("/data".into()),
                mode: Some("rw".into())
            })]
        );
        // :ro -> bare path (explicit read-only)
        let ov = collect_cli(Cli {
            binds: &["/data:ro"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.binds, vec![RawBind::Path("/data".into())]);
        // a colon in the path (not a mode) stays part of the path
        let ov = collect_cli(Cli {
            binds: &["/my:dir"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.binds, vec![RawBind::Path("/my:dir".into())]);
    }

    #[test]
    fn a_typed_bind_with_an_empty_path_is_a_hard_error() {
        let err = collect_cli(Cli {
            binds: &[":rw"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("empty bind path"), "{err}");
    }

    #[test]
    fn a_typed_limit_parses_numbers_and_strings_and_rejects_unknown_keys() {
        let ov = collect_cli(Cli {
            limits: &["tasks_max=8192", "memory_max=80%"],
            ..Default::default()
        })
        .unwrap();
        let limits = ov.raw.limits.expect("limits present");
        assert_eq!(limits.tasks_max, Some(RawLimit::Number(8192)));
        assert_eq!(limits.memory_max, Some(RawLimit::Text("80%".into())));
        // unknown key -> structural error
        let err = collect_cli(Cli {
            limits: &["cpu=1"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("unknown limit"), "{err}");
        // no '=' -> structural error
        let err = collect_cli(Cli {
            limits: &["tasks_max"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("expected KEY=VALUE"), "{err}");
    }

    #[test]
    fn a_typed_package_parses_name_and_locator() {
        let ov = collect_cli(Cli {
            packages: &["hello=nix:hello"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ov.raw.packages.get("hello").map(String::as_str),
            Some("nix:hello")
        );
        // no '=' -> structural error
        let err = collect_cli(Cli {
            packages: &["hello"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("expected KEY=VALUE"), "{err}");
        // empty name -> structural error
        let err = collect_cli(Cli {
            packages: &["=nix:hello"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("empty package name"), "{err}");
    }

    #[test]
    fn a_typed_flag_beats_a_blob_on_the_same_field() {
        // --net (cli typed) beats --config network (cli blob)
        let ov = collect_cli(Cli {
            config: &["network = \"shared\""],
            net: &["none"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("none")));
    }

    #[test]
    fn the_four_tiers_layer_env_typed_below_cli_blob_below_cli_typed() {
        // SBX_NET (env typed) is beaten by --config (cli blob), which is beaten by --net (cli typed).
        let ov = collect_from(
            &CliOverrides {
                config: owned(&["network = \"none\""]),
                net: owned(&["ask"]),
                ..Default::default()
            },
            AmbientOverrides {
                net: Some("shared".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("ask")));

        // Drop the cli typed: the cli blob wins over the env typed.
        let ov = collect_from(
            &CliOverrides {
                config: owned(&["network = \"none\""]),
                ..Default::default()
            },
            AmbientOverrides {
                net: Some("shared".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(ov.raw.network, Some(posture("none")));
    }

    #[test]
    fn typed_collections_union_across_the_env_and_cli_tiers() {
        // SBX_BIND + --bind -> both binds; SBX_LIMIT_* + --limit on different keys -> both limits.
        let ov = collect_from(
            &CliOverrides {
                binds: owned(&["/b"]),
                limits: owned(&["tasks_max=4096"]),
                ..Default::default()
            },
            AmbientOverrides {
                binds: owned(&["/a"]),
                limits: pairs(&[("memory_max", "80%")]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            ov.raw.binds.len(),
            2,
            "binds should union: {:?}",
            ov.raw.binds
        );
        let limits = ov.raw.limits.expect("limits present");
        assert!(limits.tasks_max.is_some() && limits.memory_max.is_some());
    }

    #[test]
    fn a_higher_tier_bind_replaces_a_lower_tier_bind_on_the_same_path() {
        // SBX_BIND=/data:ro then --bind /data:rw -> one entry, read-write (the CLI wins the path).
        let ov = collect_from(
            &CliOverrides {
                binds: owned(&["/data:rw"]),
                ..Default::default()
            },
            AmbientOverrides {
                binds: owned(&["/data:ro"]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            ov.raw.binds,
            vec![RawBind::Detailed(RawBindTable {
                path: Some("/data".into()),
                mode: Some("rw".into())
            })]
        );
    }

    #[test]
    fn an_ambient_typed_security_field_is_noticed() {
        // SBX_NET alone (a scalar the CLI did not set) is noticed.
        let ov = ambient(AmbientOverrides {
            net: Some("none".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(
            ov.notices().iter().any(|n| n.contains("`network`")),
            "{:?}",
            ov.notices()
        );
        // SBX_BIND alone (a collection the environment contributed to) is noticed.
        let ov = ambient(AmbientOverrides {
            binds: owned(&["/a"]),
            ..Default::default()
        })
        .unwrap();
        assert!(
            ov.notices().iter().any(|n| n.contains("`binds`")),
            "{:?}",
            ov.notices()
        );
    }

    #[test]
    fn an_ambient_typed_structural_error_is_a_hard_error() {
        let err = ambient(AmbientOverrides {
            limits: pairs(&[("bogus", "1")]),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("unknown limit"), "{err}");
    }

    // --- typed --seccomp / --device flags ---

    #[test]
    fn typed_seccomp_and_device_land_verbatim_in_the_allow_lists() {
        // A seccomp value may carry a comma-list (split downstream by apply_seccomp); a device value
        // is one path per flag. The collection carries the raw entries so the field grammar applies.
        let ov = collect_cli(Cli {
            seccomp: &["ptrace,unshare", "clone:newuser"],
            devices: &["/dev/kvm", "/dev/dri"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ov.raw.seccomp.as_ref().map(|s| s.allow.as_slice()),
            Some(&["ptrace,unshare".to_string(), "clone:newuser".to_string()][..])
        );
        assert_eq!(
            ov.raw.devices.as_ref().map(|d| d.allow.as_slice()),
            Some(&["/dev/kvm".to_string(), "/dev/dri".to_string()][..])
        );
    }

    #[test]
    fn seccomp_and_device_union_across_the_env_and_cli_tiers() {
        // SBX_SECCOMP + --seccomp accumulate; SBX_DEVICE + --device accumulate — the collection-union
        // rule, so the CLI adds to the environment's list rather than replacing it.
        let ov = collect_from(
            &CliOverrides {
                seccomp: owned(&["unshare"]),
                devices: owned(&["/dev/dri"]),
                ..Default::default()
            },
            AmbientOverrides {
                seccomp: owned(&["ptrace"]),
                devices: owned(&["/dev/kvm"]),
                ..Default::default()
            },
        )
        .unwrap();
        let allow = &ov.raw.seccomp.expect("seccomp present").allow;
        assert!(allow.contains(&"ptrace".to_string()) && allow.contains(&"unshare".to_string()));
        let devs = &ov.raw.devices.expect("devices present").allow;
        assert!(
            devs.contains(&"/dev/kvm".to_string()) && devs.contains(&"/dev/dri".to_string()),
            "{devs:?}"
        );
    }

    #[test]
    fn a_config_blob_seccomp_and_devices_survive_the_fold() {
        // Regression guard: overlay_into must copy the [seccomp]/[devices] tables (they were once
        // dropped in the fold, so a --config blob's relaxation silently vanished before apply).
        let ov = collect_cli(Cli {
            config: &["[seccomp]\nallow = [\"ptrace\"]\n[devices]\nallow = [\"/dev/kvm\"]"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ov.raw.seccomp.as_ref().map(|s| s.allow.as_slice()),
            Some(&["ptrace".to_string()][..])
        );
        assert_eq!(
            ov.raw.devices.as_ref().map(|d| d.allow.as_slice()),
            Some(&["/dev/kvm".to_string()][..])
        );
    }

    #[test]
    fn ambient_seccomp_and_device_are_noticed_as_security_fields() {
        // SBX_SECCOMP / SBX_DEVICE relax the cage, so a stale ambient variable must not change a
        // launch silently — each fires a security-via-environment notice.
        let ov = ambient(AmbientOverrides {
            seccomp: owned(&["ptrace"]),
            devices: owned(&["/dev/kvm"]),
            ..Default::default()
        })
        .unwrap();
        assert!(
            ov.notices().iter().any(|n| n.contains("`seccomp`")),
            "{:?}",
            ov.notices()
        );
        assert!(
            ov.notices().iter().any(|n| n.contains("`devices`")),
            "{:?}",
            ov.notices()
        );
    }

    #[test]
    fn a_cli_seccomp_or_device_fires_no_env_notice() {
        // On the command line these are explicit per-invocation — no stale-ambient risk, no notice.
        let ov = collect_cli(Cli {
            seccomp: &["ptrace"],
            devices: &["/dev/kvm"],
            ..Default::default()
        })
        .unwrap();
        assert!(ov.notices().is_empty(), "{:?}", ov.notices());
    }

    // --- typed --proc flag ---

    #[test]
    fn a_typed_proc_flag_sets_the_bare_mode_and_is_non_empty() {
        // `--proc enforce` sets the mode-only (bare-string) form of the `proc` field; the mode value
        // is validated downstream (fatal there if unknown), not here.
        let ov = collect_cli(Cli {
            proc: &["enforce"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.proc, Some(ProcField::Mode("enforce".into())));
        assert!(!ov.is_empty(), "a set proc override must be non-empty");

        // `--proc off` disables for one launch (an invoker turning off a trusted project's `enforce`,
        // the top-authority parity with `--gpu=false`) — it is a *set* override, not an unset one.
        let off = collect_cli(Cli {
            proc: &["off"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(off.raw.proc, Some(ProcField::Mode("off".into())));
        assert!(
            !off.is_empty(),
            "`--proc off` is a set override, not a no-op"
        );

        // Last occurrence wins (a scalar).
        let last = collect_cli(Cli {
            proc: &["observe", "enforce"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(last.raw.proc, Some(ProcField::Mode("enforce".into())));
    }

    #[test]
    fn a_typed_proc_flag_beats_a_blob_proc_table() {
        // `--proc` (scalar) replaces a `--config` blob's `[proc]` table on the same field.
        let ov = collect_cli(Cli {
            config: &["[proc]\nmode = \"ask\"\ndeny = [\"curl\"]"],
            proc: &["enforce"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.proc, Some(ProcField::Mode("enforce".into())));
    }

    #[test]
    fn an_ambient_sbx_proc_is_noticed_and_the_cli_beats_it() {
        // `SBX_PROC` alone (a security scalar the CLI did not set) fires a security-via-environment
        // notice; and the command line beats the environment.
        let ov = ambient(AmbientOverrides {
            proc: Some("observe".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.proc, Some(ProcField::Mode("observe".into())));
        assert!(
            ov.notices().iter().any(|n| n.contains("`proc`")),
            "{:?}",
            ov.notices()
        );

        let cli_wins = collect_from(
            &CliOverrides {
                proc: owned(&["enforce"]),
                ..Default::default()
            },
            AmbientOverrides {
                proc: Some("observe".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(cli_wins.raw.proc, Some(ProcField::Mode("enforce".into())));
        // set on the CLI, so no env-source notice for it.
        assert!(!cli_wins.notices().iter().any(|n| n.contains("`proc`")));
    }
}
