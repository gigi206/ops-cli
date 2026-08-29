//! One-shot configuration overrides carried on the command line or in the environment.
//!
//! An override is the *final word* on a launch's configuration — it beats a trusted project
//! config **and** a named app's overlay — because it comes from the person running `sbx`, whose
//! authority over the process's argv and environment no lower-trust context (an in-cage agent, a
//! project directory) can reach. So an override is trusted *by invocation*, distinct from the
//! direnv-style content trust of a project config: it touches no trust marker.
//!
//! Trusted by invocation is not the same as safe to read, and the `@<file>` form keeps the second:
//! it passes [`super::safety::read_safe_bytes`] like any other config file. Vouching for a path's
//! *content* says nothing about whether the thing at that path is a plain file the invoker owns, and
//! `SBX_CONFIG=@…` in particular can arrive from an ambient environment nobody re-read.
//!
//! Two surfaces reach every field. A **blob** — `--config <toml|@file>` / `SBX_CONFIG` — carries
//! inline TOML shaped exactly like an `sbx.toml`, so it can set *any* field the schema has. A
//! **typed flag** — `--net`/`--gui`/`--nixpkgs`/`--bind`/`--forward`/`--limit`/`--package`/
//! `--seccomp`/`--device`/`--proc`/`--notify`/`--gpu`/`--audio`/`--dbus` (and their `--env` sibling), each with
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
//! Fail-closed: unlike [`super::load()`], which is infallible (a bad config warns and is dropped),
//! a malformed override is an explicit request the user got wrong — [`collect`] returns `Err`, so
//! the launch aborts rather than silently dropping the field and running a different posture than
//! asked.

use super::schema::{
    self, NetworkField, NetworkTable, NotifyField, ProcField, RawBind, RawBindTable, RawConfig,
    RawDevices, RawFs, RawLimit, RawLimits, RawSeccomp, RawSshAgent,
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
    /// `--gui <none|offscreen|wayland>` — the display posture (last wins).
    pub(crate) gui: Vec<String>,
    /// `--proc <off|observe|enforce|ask>` — the process/exec posture, a bare mode (last wins). The
    /// full `[proc]` table with `allow`/`deny` lists is set through a `--config` blob.
    pub(crate) proc: Vec<String>,
    /// `--notify <off|once|always>` — how loudly a refusal is announced, a bare mode applied to
    /// every event (last wins). The per-event table and `repeat_after` are set through a `--config`
    /// blob.
    pub(crate) notify: Vec<String>,
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
    /// `SBX_NOTIFY` — how loudly a refusal is announced (a bare mode).
    notify: Option<String>,
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
        notify: env_nonempty("SBX_NOTIFY"),
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
    // `std::env::vars` panics when **any** variable in the environment — not merely one sbx reads —
    // carries a name or a value that is not valid Unicode, and this scan runs at the head of every
    // override-carrying command, so one Latin-1 value left by an unrelated tool aborted `sbx run`,
    // `sbx app` and `sbx config show` before anything else happened. `vars_os` is the total form:
    // an entry sbx cannot represent as text is skipped, which is right in both directions — a name
    // that is not UTF-8 cannot carry an `SBX_*` prefix, and a value that is not UTF-8 could not be
    // passed on as a cage variable, a limit, or a package locator anyway. The exact-name lookups
    // above are already total, through `std::env::var(..).ok()`.
    for (k, v) in std::env::vars_os() {
        let (Some(k), Some(v)) = (k.to_str(), v.to_str()) else {
            continue;
        };
        if let Some(name) = k.strip_prefix(SBX_ENV_PREFIX) {
            if !name.is_empty() {
                a.env.push((name.to_string(), v.to_string()));
            }
        } else if let Some(key) = k.strip_prefix(SBX_LIMIT_PREFIX) {
            if !key.is_empty() {
                a.limits.push((key.to_lowercase(), v.to_string()));
            }
        } else if let Some(name) = k.strip_prefix(SBX_PACKAGE_PREFIX)
            && !name.is_empty()
        {
            a.packages.push((name.to_string(), v.to_string()));
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
    // An unknown key is reported per blob, here, because it does not survive far enough to be
    // reported anywhere else: `overlay_into` carries the fields it understands and drops the
    // unknown-key bag with them. Reported rather than refused, for the reason a file's are —
    // that is what lets a blob written for a newer sbx run on an older one.
    let mut unknown = Vec::new();
    // Whether any blob declared egress groups, recorded per blob for the same reason: `network` is
    // a scalar field, so the blob that loses the merge takes its `groups` table out of sight with it.
    let mut blob_groups = false;

    // Tier 0 — the environment blob.
    let t0 = match &ambient.config {
        Some(s) => {
            let parsed = parse_blob(s).map_err(|e| format!("{SBX_CONFIG}: {e}"))?;
            super::warn_unknown_keys(&mut unknown, SBX_CONFIG, &parsed);
            blob_groups |= declares_net_groups(&parsed);
            parsed
        }
        None => RawConfig::default(),
    };
    // Tier 1 — the environment's typed fragments.
    let t1 = build_typed_fragment(
        ambient.net.as_deref(),
        ambient.gui.as_deref(),
        ambient.proc.as_deref(),
        ambient.notify.as_deref(),
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
        super::warn_unknown_keys(&mut unknown, &format!("--config (#{})", i + 1), &parsed);
        blob_groups |= declares_net_groups(&parsed);
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
        cli.notify.last().map(String::as_str),
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

    let mut notices = unknown;
    push_ignored_field_notices(&env_side, &cli_side, blob_groups, &mut notices);
    push_env_source_notices(&env_side, &cli_side, &mut notices);

    let mut merged = overlay_into(env_side, cli_side);
    // Drop the groups the notice above just accounted for, so the posture that reaches
    // `apply_override` carries only one-shot launch fields. Left in place they would be reported a
    // second time downstream, where every layer that may not define a group is reported.
    super::take_net_groups(&mut merged.network);
    Ok(Override {
        raw: merged,
        notices,
    })
}

/// Note the fields an override carries that are not one-shot launch concepts: egress groups are a
/// global-config affordance, and an override shapes *the* launch rather than defining apps. They are
/// dropped (ignored downstream), so the notice is the only signal.
///
/// `blob_groups` is decided per blob by the caller rather than read off the merged sides, for the
/// reason an unknown key is: `network` is a **scalar** field, so a later blob's posture replaces an
/// earlier one's table outright, and a `groups` declaration in the blob that lost would reach here
/// as an absence indistinguishable from never having been written.
fn push_ignored_field_notices(
    env_side: &RawConfig,
    cli_side: &RawConfig,
    blob_groups: bool,
    notices: &mut Vec<String>,
) {
    if blob_groups {
        notices.push(
            "ignoring `groups` under `[network]` in the override — it is not a one-shot launch field"
                .to_string(),
        );
    }
    if !env_side.app.is_empty() || !cli_side.app.is_empty() {
        notices.push(
            "ignoring `[app.*]` in the override — it is not a one-shot launch field".to_string(),
        );
    }
    if !env_side.bundle.is_empty() || !cli_side.bundle.is_empty() {
        notices.push(
            "ignoring `[bundle.*]` in the override — it is not a one-shot launch field (a bundle \
             is reached through an app's `use`, and an override declares no app)"
                .to_string(),
        );
    }
}

/// Whether an override blob declares egress groups — only the table form of `network` can carry
/// them, the bare-string posture having nowhere to put a sub-table.
fn declares_net_groups(raw: &RawConfig) -> bool {
    matches!(&raw.network, Some(schema::NetworkField::Table(t)) if !t.groups.is_empty())
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
    // `env_side` is destructured **exhaustively**, for the reason [`overlay_into`] gives for doing
    // the same: this is a hand-written list of fields with nothing above it checking the list is
    // complete, and it had silently dropped four — `allow_insecure_http`, `ssh_agent`, `[fs]` and
    // `[open]`, each of them a field an ambient variable can use to widen a launch, and none of
    // them said out loud. Naming every field makes the compiler refuse the next schema addition
    // until this function decides what becomes of it. A field deliberately not noted is bound to
    // `_` with its reason, never omitted.
    let RawConfig {
        allow_insecure_http,
        binds,
        packages,
        nixpkgs,
        network,
        proc,
        notify,
        gui,
        gpu,
        audio,
        dbus,
        forward,
        secret,
        limits,
        seccomp,
        devices,
        ssh_agent,
        fs,
        redact,
        open,
        service,
        // `env` is a *free* field: folded without a notice, as this function's own doc says.
        env: _,
        // Not a security field: what clock the cage reads changes no boundary.
        timezone: _,
        // Refused outright by `apply_override`, or reported per blob before this merge — an
        // override never carries them, so there is nothing here for an ambient value to have set.
        app: _,
        bundle: _,
        flakes: _,
        tarball: _,
        deb: _,
        appimage: _,
        binary: _,
        accepts_fresh_releases: _,
        task: _,
        plugin: _,
        broker: _,
        rest: _,
    } = env_side;
    // Replaced scalars: noted when only the environment set them.
    for (field, env_has, cli_has) in [
        ("nixpkgs", nixpkgs.is_some(), cli_side.nixpkgs.is_some()),
        ("network", network.is_some(), cli_side.network.is_some()),
        ("gui", gui.is_some(), cli_side.gui.is_some()),
        ("proc", proc.is_some(), cli_side.proc.is_some()),
        ("notify", notify.is_some(), cli_side.notify.is_some()),
        ("gpu", gpu.is_some(), cli_side.gpu.is_some()),
        ("audio", audio.is_some(), cli_side.audio.is_some()),
        ("dbus", dbus.is_some(), cli_side.dbus.is_some()),
        ("secret", secret.is_some(), cli_side.secret.is_some()),
        ("redact", redact.is_some(), cli_side.redact.is_some()),
        (
            "allow_insecure_http",
            allow_insecure_http.is_some(),
            cli_side.allow_insecure_http.is_some(),
        ),
    ] {
        if env_has && !cli_has {
            note(field);
        }
    }
    // Unioned collections: noted whenever the environment contributed.
    for (field, env_has) in [
        ("binds", !binds.is_empty()),
        ("packages", !packages.is_empty()),
        ("limits", limits.is_some()),
        ("forward", forward.is_some()),
        ("seccomp", seccomp.is_some()),
        ("devices", devices.is_some()),
        // `[fs]` sat in the scalar list above, where a field is only noted when the CLI left it
        // unset — but `overlay_into` folds it through `union_fs_opt`, so a CLI `[fs]` does not
        // replace an ambient one, it is *added to* it. An `SBX_CONFIG` mask therefore reached the
        // launch unannounced whenever the command line happened to carry a `[fs]` of its own.
        ("fs", fs.is_some()),
        ("ssh_agent", ssh_agent.is_some()),
        ("open", !open.is_empty()),
        ("service", !service.is_empty()),
    ] {
        if env_has {
            note(field);
        }
    }
}

/// Merge `higher` onto `base` per the uniform rule: a scalar field is replaced when `higher` sets
/// it; a collection field is unioned, `higher` winning per key/entry. This is the one merge — used
/// for repeated `--config` blobs, for folding a typed fragment onto a blob, and for merging the two
/// precedence sides. `[app.*]` rides along (ignored downstream but noticed).
fn overlay_into(mut base: RawConfig, higher: RawConfig) -> RawConfig {
    // `higher` is destructured **exhaustively**, and that is the point of writing it this way. This
    // fold is a hand-written list of fields with nothing above it checking the list is complete, and
    // it has now dropped a field in silence three times (`limits`, then `[fs]` twice over). Naming
    // every field makes the compiler refuse the next schema addition until this function says what
    // becomes of it — the one guard that cannot itself be forgotten, where a test only catches what
    // someone remembered to write. A field the override deliberately does not carry is bound to `_`
    // with its reason, never omitted.
    let RawConfig {
        allow_insecure_http,
        env,
        binds,
        packages,
        nixpkgs,
        network,
        proc,
        notify,
        gui,
        timezone,
        gpu,
        audio,
        dbus,
        forward,
        secret,
        app,
        limits,
        seccomp,
        devices,
        ssh_agent,
        fs,
        redact,
        bundle,
        open,
        service,
        // Carried no further on purpose: `apply_override` refuses each of these outright, so folding
        // them would only move the drop to a later line. An inline `flake.nix`, an auto-upgrade
        // resolver command, and a declared operation are all vetted where they are read and listed,
        // not assembled on a command line for one launch. `rest` is the unknown-key bag, reported
        // per blob in `collect_from` before this merge, since nothing downstream would see it.
        flakes: _,
        tarball: _,
        deb: _,
        appimage: _,
        binary: _,
        // Lifting a vendor's freshness delay is a standing decision about that vendor, weighed
        // once where the package is declared and read by whoever audits the profile. A one-shot
        // `--config` blob is the wrong place to assert it, for the same reason the inline
        // package tables above are dropped here.
        accepts_fresh_releases: _,
        task: _,
        plugin: _,
        // Not carried, like `plugin`: a broker's `socket` names a host resource to stand in front
        // of, which is declared where it can be read and reviewed rather than overlaid for a run.
        broker: _,
        rest: _,
    } = higher;

    base.env.extend(env);
    base.packages.extend(packages);
    // A collection keyed by scheme, so a later blob replaces an earlier blob's handler for the same
    // scheme and adds the rest — the behaviour `env` and `packages` already have on their key.
    base.open.extend(open);
    // Keyed by service name, on the same rule for the same reason.
    base.service.extend(service);
    base.binds = union_binds(base.binds, binds);
    base.limits = union_limits(base.limits, limits);
    if nixpkgs.is_some() {
        base.nixpkgs = nixpkgs;
    }
    if network.is_some() {
        base.network = network;
    }
    if gui.is_some() {
        base.gui = gui;
    }
    if timezone.is_some() {
        base.timezone = timezone;
    }
    if proc.is_some() {
        base.proc = proc;
    }
    if notify.is_some() {
        base.notify = notify;
    }
    if allow_insecure_http.is_some() {
        base.allow_insecure_http = allow_insecure_http;
    }
    if gpu.is_some() {
        base.gpu = gpu;
    }
    if audio.is_some() {
        base.audio = audio;
    }
    if dbus.is_some() {
        base.dbus = dbus;
    }
    if secret.is_some() {
        base.secret = secret;
    }
    // A scalar table: the higher blob's floor replaces the lower's outright. There is nothing to
    // union — two floors are not additive, and taking the stricter of the two would make the answer
    // depend on which blob was written first rather than on which one ranks higher.
    if redact.is_some() {
        base.redact = redact;
    }
    base.forward = union_forward_opt(base.forward, forward);
    base.fs = union_fs_opt(base.fs, fs);
    base.seccomp = union_allow_opt(base.seccomp, seccomp, |s| &mut s.allow);
    base.devices = union_allow_opt(base.devices, devices, |d| &mut d.allow);
    base.ssh_agent = union_ssh_agent_opt(base.ssh_agent, ssh_agent);
    base.app.extend(app);
    base.bundle.extend(bundle);
    base
}

/// Union two `[fs]` tables, a higher tier's entries appended onto a lower's. Every list only ever
/// *closes* something, so appending is the fail-closed direction and matches how the config layers
/// themselves fold: a repeated `--config` blob, and the two precedence sides, accumulate masks
/// instead of one silently replacing the other's. `apply_fs` validates and dedups downstream, so a
/// plain append is enough. Unknown keys ride along so the table's own report still sees them.
///
/// `scan_max_kb` is the one field that is not a list, and it folds by the rule its own layer merge
/// uses ([`crate::config::fspolicy`]): the **larger** window wins. That reads backwards until the
/// field is read as what it is — how many bytes of a file the content lens examines before letting
/// the open through — so a bigger number closes *more* files and a smaller one closes fewer, and
/// taking the minimum would let one tier widen what another had narrowed. `FsPolicy::union` was
/// corrected to `max` for exactly that reason; this fold, which runs *before* it and decides what
/// it is handed, kept the `min` and so let a stale ambient `SBX_CONFIG` ceiling beat the one an
/// invoker typed on the command line — against this module's own precedence rule.
///
/// The higher side is **destructured exhaustively** rather than read field by field. A field added
/// to [`RawFs`] and forgotten here is dropped in silence, and silence on this table means the thing
/// the invoker asked to close stays open. That has now happened three times (see the test below),
/// the third being `scan`, which the hand-written list of fields did not mention. Destructuring
/// makes the fourth a compile error instead of a launch that quietly protects nothing.
fn union_fs_opt(base: Option<RawFs>, higher: Option<RawFs>) -> Option<RawFs> {
    match (base, higher) {
        (b, None) => b,
        (None, h) => h,
        (Some(mut b), Some(h)) => {
            let RawFs {
                deny,
                readonly,
                scan,
                scan_max_kb,
                rest,
            } = h;
            b.deny.extend(deny);
            b.readonly.extend(readonly);
            b.scan.extend(scan);
            b.scan_max_kb = match (b.scan_max_kb, scan_max_kb) {
                (Some(a), Some(c)) => Some(a.max(c)),
                (None, other) | (other, None) => other,
            };
            b.rest.extend(rest);
            Some(b)
        }
    }
}

/// Union two optional allow-list-only tables (`[seccomp]` / `[devices]`), a higher tier's entries
/// appended onto a lower's — the collection-union rule, so `--seccomp`/`--device` accumulate across
/// the tiers rather than clobbering a blob's list. `None` means "this tier set none". The downstream
/// `apply_*` dedups (devices) or is idempotent (seccomp), so a plain append is enough.
///
/// It returns the *base* table with the higher tier's entries copied in, so every field of the
/// higher table other than `allow` is discarded. That is exact only where `allow` is the whole
/// table: `RawSeccomp` and `RawDevices` carry nothing else but the unknown-key bag, which
/// `warn_unknown_keys` has already reported per blob by the time this runs. A table with a field of
/// its own must not come through here — `[ssh_agent]` has [`union_ssh_agent_opt`], which
/// destructures it exhaustively so the next field added is a compile error rather than a silent
/// drop.
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

/// Union two `[ssh_agent]` tables: the higher tier's granted keys append onto the lower's, and
/// `confirm` ORs.
///
/// `confirm` deliberately does **not** follow tier precedence, which is why this table cannot be
/// folded as an allow-list-only one. Its own documentation states the rule — "the flag ORs across
/// layers — a layer that asks for confirmation cannot have it turned off by another" — and
/// [`super::Resolved::apply_override`] applies it as `|=`. Folding through the allow-only path
/// returned the *base* table, so a higher tier's `confirm = true` was dropped whenever a lower tier
/// also declared `[ssh_agent]`: two `--config` blobs, one granting a key and one asking for the
/// prompt, granted the key with no prompt at all. The key still has to have been granted by some
/// tier, so what was lost is the per-signature confirmation, not the grant.
///
/// The higher side is destructured exhaustively, for the reason [`union_fs_opt`] gives: a field
/// added to [`RawSshAgent`] and forgotten here would be dropped in silence, which is precisely how
/// `confirm` came to be dropped in the first place.
fn union_ssh_agent_opt(
    base: Option<RawSshAgent>,
    higher: Option<RawSshAgent>,
) -> Option<RawSshAgent> {
    match (base, higher) {
        (b, None) => b,
        (None, h) => h,
        (Some(mut b), Some(h)) => {
            let RawSshAgent {
                allow,
                confirm,
                rest,
            } = h;
            b.allow.extend(allow);
            b.confirm = match (b.confirm, confirm) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (lower, upper) => upper.or(lower),
            };
            b.rest.extend(rest);
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

/// Union two optional forward lists. `None` means "this tier set none"; a higher tier's entries
/// fold onto a lower's **keyed by cage port** — adding a cage port the lower tier did not forward,
/// and moving the host port of one it did. The keyed-collection rule, so `--forward` over
/// `SBX_FORWARD` refines rather than accumulating a second hole for the same in-cage service.
fn union_forward_opt(
    base: Option<Vec<schema::RawForward>>,
    higher: Option<Vec<schema::RawForward>>,
) -> Option<Vec<schema::RawForward>> {
    match (base, higher) {
        (b, None) => b,
        (None, h) => h,
        (Some(mut b), Some(h)) => {
            // The tiers hold raw entries — the cage port that keys them is only known after the
            // resolver parses each one, which happens downstream on the merged list. Concatenating
            // with `higher` last is exactly what that resolver reduces: `validate_forward` keeps
            // the last entry for a cage port, so a higher tier's remap wins by position. Doing the
            // keying here would mean parsing twice, in two places, with two chances to drift.
            b.extend(h);
            Some(b)
        }
    }
}

/// Parse one `--forward` value — a comma-list whose every token is a port (`1455`) or a `host:cage`
/// remap (`9200:9119`) — into raw schema entries. A structural error (an empty value, a token that
/// is not a port, a remap with more than one `:` or a non-port on either side) is fail-closed, since
/// it is an explicit request the user mistyped: unlike a config file, where a bad entry is warned
/// and skipped so one typo cannot void a whole layer, there is nothing else in a flag to save.
///
/// A port of `0` parses here and is dropped downstream by the resolver's validator (a value-range
/// concern, not a structural one — the additive model).
fn parse_forward(spec: &str, label: &str) -> Result<Vec<schema::RawForward>, String> {
    let entries: Vec<schema::RawForward> = spec
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|t| parse_forward_token(t, label))
        .collect::<Result<_, _>>()?;
    if entries.is_empty() {
        return Err(format!("{label}: no ports given"));
    }
    Ok(entries)
}

/// Parse one token of a `--forward` value. Both sides of a remap are checked here so the flag fails
/// at the point of the mistake, naming the token as typed.
fn parse_forward_token(token: &str, label: &str) -> Result<schema::RawForward, String> {
    let Some((host, cage)) = token.split_once(':') else {
        // Checked as a `u16` here even though the schema holds an `i64`: a flag fails at the point
        // of the mistake, naming the token as typed, while a *config* value is range-checked
        // downstream so that a bad port cannot take its whole layer with it.
        return token
            .parse::<u16>()
            .map(|p| schema::RawForward::Port(p.into()))
            .map_err(|_| format!("{label}: `{token}` is not a valid port (expected 0–65535)"));
    };
    let bad = |side: &str, which: &str| {
        format!(
            "{label}: `{token}` is not a valid forward — the {which} side `{side}` is not a port \
             (expected `<host>:<cage>`, e.g. `9200:9119`)"
        )
    };
    if cage.contains(':') {
        return Err(format!(
            "{label}: `{token}` is not a valid forward — more than one `:` (expected \
             `<host>:<cage>`, e.g. `9200:9119`)"
        ));
    }
    host.parse::<u16>().map_err(|_| bad(host, "host"))?;
    cage.parse::<u16>().map_err(|_| bad(cage, "cage"))?;
    Ok(schema::RawForward::Remap(token.to_string()))
}

/// Build a `RawConfig` fragment from a source's typed inputs. A *structural* error (a bad `--net`
/// posture keyword, an empty `--bind` path, an unknown `--limit` key, an empty `--package` name) is
/// fail-closed; a set-but-invalid *value* passes through to the downstream validation.
#[allow(clippy::too_many_arguments)]
fn build_typed_fragment(
    net: Option<&str>,
    gui: Option<&str>,
    proc: Option<&str>,
    notify: Option<&str>,
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
    // `--notify` sets only the mode (the bare-string form of the `notify` field), applied uniformly
    // to every event; the mode value is validated downstream (an unknown mode is fatal for an
    // override, like `--proc`), and the per-event table and `repeat_after` are set through a
    // `--config` blob.
    if let Some(v) = notify {
        raw.notify = Some(NotifyField::Mode(v.to_string()));
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
    let mut ports: Vec<schema::RawForward> = Vec::new();
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
            rest: Default::default(),
            allow: seccomp.to_vec(),
        });
    }
    if !devices.is_empty() {
        raw.devices = Some(RawDevices {
            rest: Default::default(),
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

/// Parse a `--net` value into a `network` field. A bare posture (`none`/`shared`/`ask`/`allow`/
/// `deny`) passes through verbatim — the same five words the config's bare-string `network = "…"`
/// form takes, validated downstream — while `allow=host1,host2` becomes a default-deny allowlist
/// and `deny=host1,host2` a default-allow denylist, the common one-shot egress shapes. An unknown
/// keyword passes through too and is caught by the downstream posture validation.
///
/// The two forms of the same word mean opposite things: bare `allow` is the allow-by-default
/// posture (an empty denylist, so everything reaches), whereas `allow=host1` restricts egress to
/// `host1`. That collision is the config's own — `mode = "allow"` versus `allow = […]` in a
/// `[network]` table reads exactly the same way — so the CLI keeps the config's vocabulary rather
/// than inventing a third spelling for a posture, and the help text carries the distinction.
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
    Ok(NetworkField::Posture(value.to_string()))
}

/// Split a comma-separated host list, trimming each and rejecting an empty result (a `--net allow=`
/// with no hosts is a structural error, not a silent all-deny).
///
/// The comma is the separator, which a `re:` pattern may legitimately contain (a `{n,m}` quantifier,
/// an alternation list) — and nothing here can tell a separator from a pattern's own comma, since
/// `re:a,b` is genuinely both readings. What *is* decidable is the damage: a split that leaves a
/// `re:` fragment which no longer compiles was a pattern cut in half. Rather than pass the halves on
/// as two unrelated malformed entries (`re:a{1` and `2}`, reported as a bad regex and a bad
/// hostname), the value is refused whole, pointing at the form that can carry it. A comma-free regex
/// is unaffected — `--net 'allow=re:.*'` is a perfectly good one-shot catch-all — and so is a list
/// mixing hosts with an intact pattern (`allow=github.com,re:^https://api\.`).
fn split_hosts(hosts: &str, label: &str, kind: &str) -> Result<Vec<String>, String> {
    if hosts.contains(',')
        && hosts
            .split(',')
            .map(str::trim)
            .any(|p| p.starts_with("re:") && crate::allowlist::classify(p).is_err())
    {
        return Err(format!(
            "{label}: a `re:` pattern containing a comma cannot go through `{kind}=` — the value is \
             split on commas, which cut `{hosts}` into fragments that are no longer a valid \
             pattern. Pass it as config instead: `--config '[network] {kind} = [\"re:…\"]'` (a \
             comma-free regex is fine here, e.g. `{kind}=re:.*`)"
        ));
    }
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
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
        capture: None,
        websocket_secret: None,
        capture_max_kb: None,
        // A typed `--net` fragment defines no vocabulary and carries no unknown keys: it is built
        // here from five known postures, not parsed from what someone wrote.
        groups: Default::default(),
        rest: Default::default(),
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
            ));
        }
    }
    Ok(())
}

/// One limit value as declared: a bare number is a `Number` (a byte count for memory, a task count),
/// anything else a `Text` (`"80%"`, `"16G"`, `"infinity"`) validated downstream.
fn parse_raw_limit(value: &str) -> RawLimit {
    match value.parse::<i64>() {
        Ok(n) => RawLimit::Number(n),
        Err(_) => RawLimit::Text(value.to_string()),
    }
}

/// Parse one blob value: `@<path>` reads the file, anything else is inline TOML. The bytes are then
/// parsed as an `sbx.toml`-shaped config.
///
/// The file form goes through [`super::safety::read_safe_bytes`], the gate every other config file
/// passes, because *trusted by invocation* and *safe to read* are different claims: naming a path is
/// the invoker vouching for its **content**, while owner, mode and file type say whether these bytes
/// are the ones that path promised. Reading it raw let a FIFO stall the launch at the open instead of
/// being refused, and accepted a world-writable or foreign-owned file. The refusal is the gate's own
/// wording, and it already names the path, so this prefix does not repeat it.
fn parse_blob(value: &str) -> Result<RawConfig, String> {
    let bytes = match value.strip_prefix('@') {
        Some(path) => super::safety::read_safe_bytes(std::path::Path::new(path))
            .map_err(|e| format!("cannot read override file: {e}"))?,
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
        notify: &'a [&'a str],
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
            notify: owned(cli.notify),
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

    /// A blob populating every field `overlay_into` carries. The five it deliberately drops
    /// (`flakes`/`tarball`/`deb`/`appimage`/`task`) are absent on purpose: including one would
    /// assert the opposite of the documented fail-closed behavior.
    const FULLY_POPULATED_BLOB: &str = r#"
        nixpkgs = "nixos-23.11"
        gui = "wayland"
        proc = "enforce"
        notify = "once"
        gpu = true
        audio = false
        dbus = true
        forward = [1455]
        binds = ["/opt/data"]
        [env]
        E = "1"
        [packages]
        p = "nix:hello"
        [limits]
        tasks_max = 4096
        [seccomp]
        allow = ["ptrace"]
        [devices]
        allow = ["/dev/kvm"]
        [ssh_agent]
        allow = ["deploy-key"]
        [fs]
        deny = [".env"]
        readonly = ["Cargo.lock"]
        [secret."api.example.com"]
        from = "env://K"
        header = "X"
        type = "raw"
        [network]
        mode = "none"
        [network.groups]
        infra = ["example.com"]
        [app.demo]
        network = "none"
        [bundle.tool]
        packages = { hello = "nix:hello" }
    "#;

    #[test]
    fn every_carried_field_survives_a_fold_onto_an_empty_base() {
        // The companion to the exhaustive destructuring in `overlay_into`. The compiler forces every
        // field to be *named* there; it cannot force one to be *carried*, and a field named and then
        // quietly ignored still compiles. So: fold a fully populated blob onto an empty base and
        // require the result back unchanged. A field the fold forgets to assign comes back at its
        // default and fails the comparison by name.
        let folded = overlay_into(
            RawConfig::default(),
            parse_blob(FULLY_POPULATED_BLOB).unwrap(),
        );
        assert_eq!(
            folded,
            parse_blob(FULLY_POPULATED_BLOB).unwrap(),
            "a field `overlay_into` names but does not carry is dropped in silence"
        );
    }

    #[test]
    fn a_populated_base_keeps_every_field_when_the_higher_side_is_empty() {
        // The mirror case, and the one that catches an assignment written the wrong way round: an
        // empty higher side must not blank a field the base holds. `--config` on its own tier folds
        // onto an empty typed fragment, so this is the every-launch path, not a corner.
        let base = parse_blob(FULLY_POPULATED_BLOB).unwrap();
        let folded = overlay_into(base, RawConfig::default());
        assert_eq!(
            folded,
            parse_blob(FULLY_POPULATED_BLOB).unwrap(),
            "an empty higher side must leave the base intact"
        );
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
        // env tier (`SBX_FORWARD`) unions with the CLI tier rather than being replaced. The order
        // is the tiers' own — env first, CLI after — because the entries are still raw here: the
        // cage port that keys them is only known once the resolver parses each one, and it keeps
        // the last entry per cage port, so a higher tier wins by sitting later in this list.
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
        assert_eq!(
            ov.raw.forward,
            Some(vec![
                schema::RawForward::Port(3000),
                schema::RawForward::Port(1455),
                schema::RawForward::Port(8080),
                schema::RawForward::Port(9090),
            ])
        );
        // The env contributed a security-relevant collection, so a source notice fires.
        assert!(
            ov.notices()
                .iter()
                .any(|n| n.contains("forward") && n.contains("environment"))
        );
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
        assert!(
            ov.notices()
                .iter()
                .any(|n| n.contains("dbus") && n.contains("environment"))
        );
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
    fn the_forward_flag_accepts_a_remap_and_rejects_every_malformed_one() {
        // The flag's contract differs from a config file's on purpose: a file is a collection where
        // one bad entry warns and is skipped so a typo cannot void a whole layer, but a flag has
        // nothing else to save — the caller typed exactly this and meant it, so it fails closed.
        let ov = collect_cli(Cli {
            forward: &["9200:9119,4096"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            ov.raw.forward,
            Some(vec![
                schema::RawForward::Remap("9200:9119".into()),
                schema::RawForward::Port(4096),
            ]),
            "a comma-list mixes remaps and bare ports"
        );

        for bad in ["9200:9119:8787", "nope:9119", "9200:nope", ":9119", "9200:"] {
            let err = collect_cli(Cli {
                forward: &[bad],
                ..Default::default()
            })
            .unwrap_err();
            assert!(
                err.contains("--forward") && err.contains(bad),
                "`{bad}` must be a structural error naming the flag and the token: {err}"
            );
        }
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
    fn a_blobs_unknown_key_is_named_against_the_blob_that_wrote_it() {
        // A blob is written in one shot on a command line, with no file to re-read, so a
        // misspelling is likelier here than in a config someone keeps — and it fails the same way,
        // by governing nothing. It has to be caught here: the merge below carries the fields it
        // understands and drops the unknown-key bag with them, so nothing downstream sees it.
        let ov = collect_cli(Cli {
            config: &["netowrk = \"none\""],
            ..Default::default()
        })
        .unwrap();
        let n = ov
            .notices()
            .iter()
            .find(|n| n.contains("`netowrk`"))
            .unwrap_or_else(|| panic!("{:?}", ov.notices()));
        assert!(n.contains("--config"), "named against its blob: {n}");
    }

    #[test]
    fn a_net_table_in_a_blob_is_an_unknown_section_like_any_other() {
        // There is one network namespace, `[network]`. A blob writing `[net]` gets the same
        // treatment as any unknown section — named, ignored, and given no hint pointing anywhere.
        let ov = collect_cli(Cli {
            config: &["[net]\nmode = \"deny\""],
            ..Default::default()
        })
        .unwrap();
        let n = ov
            .notices()
            .iter()
            .find(|n| n.contains("`net`"))
            .unwrap_or_else(|| panic!("the section must be named: {:?}", ov.notices()));
        assert!(!n.contains("network.groups"), "and no migration hint: {n}");
    }

    #[test]
    fn an_ambient_blobs_unknown_key_is_named_against_the_variable() {
        // The ambient blob is the one nobody is looking at while they type the command, so naming
        // the variable rather than the launch is what sends the reader to the right place.
        let ov = ambient(AmbientOverrides {
            config: Some("bindz = []".into()),
            ..Default::default()
        })
        .unwrap();
        let n = ov
            .notices()
            .iter()
            .find(|n| n.contains("`bindz`"))
            .unwrap_or_else(|| panic!("{:?}", ov.notices()));
        assert!(n.contains(SBX_CONFIG), "named against the variable: {n}");
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

    /// Every security field an ambient blob can carry has to be named, not just the ones someone
    /// remembered to list. These four were not: a stale `SBX_CONFIG` could turn off the refusal to
    /// speak cleartext, hand the cage the ssh-agent, rewrite the `[fs]` lens, or give it a handler
    /// to invoke on the host, and the launch said nothing about where any of it came from.
    #[test]
    fn every_security_field_an_ambient_blob_carries_is_named() {
        let ov = ambient(AmbientOverrides {
            config: Some(
                "allow_insecure_http = true\n\
                 [ssh_agent]\nallow = [\"deploy-key\"]\n\
                 [fs]\ndeny = [\".env\"]\n\
                 [open]\nhttps = { cmd = [\"xdg-open\"] }\n\
                 [service.api]\ncmd = [\"serve\"]\n"
                    .into(),
            ),
            ..Default::default()
        })
        .unwrap();
        let said = ov.notices().join("\n");
        for field in ["allow_insecure_http", "ssh_agent", "fs", "open", "service"] {
            assert!(
                said.contains(&format!("security field `{field}`")),
                "an ambient `{field}` must be named: {said}"
            );
        }
        // `env` stays free and the clock stays unremarkable — noticing those would be noise.
        let quiet = ambient(AmbientOverrides {
            config: Some("timezone = \"UTC\"\n[env]\nK = \"1\"\n".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(
            quiet.notices().is_empty(),
            "a free field is folded without a word: {:?}",
            quiet.notices()
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
            Some(&[schema::RawForward::Port(1455)][..]),
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
            config: &["[network.groups]\nx = [\"a.example.com\"]\n[app.demo]\ncmd = \"demo\""],
            ..Default::default()
        })
        .unwrap();
        let text = ov.notices().join("\n");
        assert!(text.contains("`groups` under `[network]`"), "{text}");
        assert!(text.contains("[app.*]"), "{text}");
        // Noticed *and* dropped: the posture handed to the launch carries no group table, so the
        // layer that may not define one is not asked about it a second time downstream.
        assert!(
            !declares_net_groups(&ov.raw),
            "the groups must not ride along"
        );
    }

    #[test]
    fn groups_in_a_blob_that_loses_the_merge_are_still_noticed() {
        // `network` is a scalar field: a later blob's posture replaces an earlier one's table
        // outright. Reading the notice off the merged result would then mistake a declaration that
        // was overwritten for one that was never written.
        let ov = collect_cli(Cli {
            config: &[
                "[network.groups]\nx = [\"a.example.com\"]",
                "network = \"none\"",
            ],
            ..Default::default()
        })
        .unwrap();
        assert!(
            ov.notices()
                .iter()
                .any(|n| n.contains("`groups` under `[network]`")),
            "{:?}",
            ov.notices()
        );
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
        // The gate names the path it failed on, so the prefix does not have to: assert the file is
        // still identified, since an override that aborts a launch must say which one.
        assert!(err.contains("/no/such/sbx-override.toml"), "{err}");
    }

    #[test]
    fn a_config_file_reference_passes_the_config_safety_gate() {
        use std::os::unix::fs::PermissionsExt as _;
        // An override is trusted by invocation, but the file it names still has to be one sbx would
        // load at all. Both blob surfaces funnel through `parse_blob`, and the environment one is
        // where it matters most: `SBX_CONFIG=@…` can arrive from an ambient environment nobody
        // re-read, so it is exercised here too rather than assumed from the shared call.
        let dir = crate::testutil::TmpDir::new();
        let file = dir.join("loose.toml");
        std::fs::write(&file, b"network = \"none\"\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let arg = format!("@{}", file.display());

        let err = collect_cli(Cli {
            config: &[&arg],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.starts_with("--config (#1):"), "{err}");
        assert!(
            err.contains("refusing to load config: world-writable"),
            "{err}"
        );

        let err = ambient(AmbientOverrides {
            config: Some(arg),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.starts_with("SBX_CONFIG:"), "{err}");
        assert!(
            err.contains("refusing to load config: world-writable"),
            "{err}"
        );
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
    fn group_references_reach_the_list_intact() {
        // `@<name>` is one of the entry forms the lists take, so it must arrive at the resolver
        // spelled as written: the split is on commas, and a reference carries none. The name is
        // resolved there, against the groups the global config declares — this side only has to
        // avoid mangling it. Several of them, mixed with a literal host, is the shape a launch line
        // takes when it opens a build's worth of destinations at once.
        let ov = collect_cli(Cli {
            net: &["allow=@ci-hosts, @mirror ,direct.example.com"],
            ..Default::default()
        })
        .unwrap();
        match ov.raw.network {
            Some(NetworkField::Table(t)) => {
                assert_eq!(t.mode.as_deref(), Some("deny"));
                assert_eq!(t.allow, vec!["@ci-hosts", "@mirror", "direct.example.com"]);
            }
            other => panic!("expected a table, got {other:?}"),
        }
        // The same on the other side: a denylist names groups too.
        let ov = collect_cli(Cli {
            net: &["deny=@telemetry,@ads"],
            ..Default::default()
        })
        .unwrap();
        match ov.raw.network {
            Some(NetworkField::Table(t)) => {
                assert_eq!(t.mode.as_deref(), Some("allow"));
                assert_eq!(t.deny, vec!["@telemetry", "@ads"]);
            }
            other => panic!("expected a table, got {other:?}"),
        }
    }

    #[test]
    fn a_comma_bearing_regex_is_refused_whole_rather_than_split_into_fragments() {
        // `re:a{1,2}` splits into `re:a{1` and `2}` — a bad regex and a bad hostname, two errors
        // that name neither the cause nor the cure. Refused as one value instead, pointing at
        // `--config`, the form that can carry a comma.
        let err = collect_cli(Cli {
            net: &["allow=re:a{1,2}"],
            ..Default::default()
        })
        .unwrap_err();
        assert!(
            err.contains("--config") && err.contains("comma"),
            "the refusal must name the cause and the cure: {err}"
        );

        // The guard keys on *damage*, not on the presence of a regex: a list mixing hosts with an
        // intact pattern still parses, and so does a comma-free catch-all.
        for ok in [
            "allow=github.com,re:^https://api\\.example\\.test",
            "allow=re:.*",
        ] {
            assert!(
                collect_cli(Cli {
                    net: &[ok],
                    ..Default::default()
                })
                .is_ok(),
                "`{ok}` is unambiguous and must still parse"
            );
        }
    }

    #[test]
    fn every_bare_config_posture_is_typeable_on_the_flag() {
        // The flag's vocabulary is the config's: the five words `network = "…"` takes are the five
        // the flag takes, each reaching the same downstream validation. `allow`/`deny` are the two
        // that also head a list form (`allow=host1`), and they mean the *opposite* of it — the bare
        // word is the posture, so `--net allow` opens by default where `--net allow=host1` restricts
        // egress to `host1`.
        for name in ["none", "shared", "ask", "allow", "deny"] {
            assert_eq!(
                collect_cli(Cli {
                    net: &[name],
                    ..Default::default()
                })
                .unwrap()
                .raw
                .network,
                Some(posture(name)),
                "`--net {name}` must reach the posture validation as itself"
            );
        }
        // The list form keeps its own meaning, and an empty list stays structural: `allow=` names
        // no host, which is a value the user mistyped, never a silent all-deny.
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
    fn a_config_blob_seccomp_devices_and_ssh_agent_survive_the_fold() {
        // Regression guard for a bug this fold has produced twice: `overlay_into` merges field by
        // field with nothing to check the list is complete, so a table it forgets is dropped in
        // *silence* — a --config blob's grant simply never reaches apply. Every `allow`-shaped
        // security table belongs here, and a new one must be added the day it is written.
        let ov = collect_cli(Cli {
            config: &["[seccomp]\nallow = [\"ptrace\"]\n\
                 [devices]\nallow = [\"/dev/kvm\"]\n\
                 [ssh_agent]\nallow = [\"deploy-key\"]"],
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
        assert_eq!(
            ov.raw.ssh_agent.as_ref().map(|s| s.allow.as_slice()),
            Some(&["deploy-key".to_string()][..])
        );
    }

    #[test]
    fn a_config_blob_fs_mask_survives_every_side_of_the_fold() {
        // Third occurrence of the bug the test above guards, and the one that got through it: `[fs]`
        // is not `allow`-shaped, so it was absent from `overlay_into` while `apply_override` read it
        // — a `--config` mask was dropped in silence, and silence on this table means the path the
        // invoker asked to close stays READABLE. One blob alone could not catch it (an empty base
        // takes the higher side wholesale); it takes a second blob, or the ambient side, to expose
        // which position is thrown away. Both are pinned here.
        let repeated = collect_cli(Cli {
            config: &[
                "[fs]\ndeny = [\".env\"]\nreadonly = [\"Cargo.lock\"]",
                "[fs]\ndeny = [\"prod.key\"]",
            ],
            ..Default::default()
        })
        .unwrap();
        let fs = repeated.raw.fs.as_ref().expect("fs present");
        assert!(
            fs.deny.contains(&".env".to_string()) && fs.deny.contains(&"prod.key".to_string()),
            "a repeated blob accumulates masks: {:?}",
            fs.deny
        );
        assert_eq!(fs.readonly, vec!["Cargo.lock".to_string()]);

        // The two precedence sides: `SBX_CONFIG` is the base and `--config` the higher one, which is
        // the exact asymmetry that let the ambient mask apply while the command line's vanished.
        let both = collect_from(
            &CliOverrides {
                config: owned(&["[fs]\ndeny = [\"cli.key\"]"]),
                ..Default::default()
            },
            AmbientOverrides {
                config: Some("[fs]\ndeny = [\"ambient.key\"]".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let fs = both.raw.fs.as_ref().expect("fs present");
        assert!(
            fs.deny.contains(&"cli.key".to_string())
                && fs.deny.contains(&"ambient.key".to_string()),
            "neither side may be dropped: {:?}",
            fs.deny
        );

        // `scan` is the field that reproduced this bug a third time: it closes a file by its
        // CONTENT, so a dropped pattern is a credential the cage keeps reading. Measured on the
        // shipped binary before the fix, with the same project either way: `[fs] deny` through
        // `--config` refused the file (rc=1) while `[fs] scan` through `--config` did not (rc=0),
        // and the same `scan` in a `.sbx.toml` did — the warnings fired on both planes, so the
        // table looked wired while the launch saw nothing.
        let scanned = collect_cli(Cli {
            config: &[
                "[fs]\nscan = [\"sk-[A-Za-z0-9]{20,}\"]\nscan_max_kb = 512",
                "[fs]\nscan = [\"AKIA[0-9A-Z]{16}\"]\nscan_max_kb = 64",
            ],
            ..Default::default()
        })
        .unwrap();
        let fs = scanned.raw.fs.as_ref().expect("fs present");
        assert!(
            fs.scan.contains(&"sk-[A-Za-z0-9]{20,}".to_string())
                && fs.scan.contains(&"AKIA[0-9A-Z]{16}".to_string()),
            "a repeated blob accumulates scan shapes: {:?}",
            fs.scan
        );
        // The larger window wins, the rule `FsPolicy::union` applies one layer down: `scan_max_kb`
        // is how far into a file the content lens reads before letting the open through, so the
        // bigger number closes *more* files. Taking the minimum here let a later blob — or a stale
        // ambient `SBX_CONFIG`, which this module ranks below the command line — shrink the window
        // an earlier tier had opened, and every credential past the smaller offset went through.
        assert_eq!(fs.scan_max_kb, Some(512));
    }

    /// The same union, read from the notice side. `[fs]` was listed among the *replaced* scalars,
    /// which note a field only when the command line left it unset — but the fold above unions the
    /// two sides, so a command line carrying any `[fs]` of its own suppressed the notice while the
    /// ambient mask went on applying. The rule is `forward`'s: a unioned field is named whenever
    /// the environment contributed to it.
    #[test]
    fn an_ambient_fs_mask_is_named_even_when_the_command_line_carries_one() {
        let both = collect_from(
            &CliOverrides {
                config: owned(&["[fs]\ndeny = [\"cli.key\"]"]),
                ..Default::default()
            },
            AmbientOverrides {
                config: Some("[fs]\ndeny = [\"ambient.key\"]".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        // The ambient mask is in force — it is not the CLI's that applies alone…
        let fs = both.raw.fs.as_ref().expect("fs present");
        assert!(
            fs.deny.contains(&"ambient.key".to_string()),
            "the ambient mask applies: {:?}",
            fs.deny
        );
        // …so it has to be named.
        assert!(
            both.notices()
                .iter()
                .any(|n| n.contains("security field `fs`")),
            "an ambient `[fs]` that reaches the launch must be named: {:?}",
            both.notices()
        );
        // And the notice still fires for an ambient `[fs]` with no command-line `[fs]` at all,
        // which is the case the scalar list did get right.
        let alone = ambient(AmbientOverrides {
            config: Some("[fs]\ndeny = [\"ambient.key\"]".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert!(
            alone
                .notices()
                .iter()
                .any(|n| n.contains("security field `fs`")),
            "{:?}",
            alone.notices()
        );
        // A `[fs]` the command line alone sets is not environment-sourced and stays unremarked, so
        // the notice cannot be satisfied by naming the field unconditionally.
        let cli_only = collect_from(
            &CliOverrides {
                config: owned(&["[fs]\ndeny = [\"cli.key\"]"]),
                ..Default::default()
            },
            AmbientOverrides::default(),
        )
        .unwrap();
        assert!(
            !cli_only
                .notices()
                .iter()
                .any(|n| n.contains("security field `fs`")),
            "{:?}",
            cli_only.notices()
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

    // --- typed --notify flag ---

    #[test]
    fn a_typed_notify_flag_sets_the_bare_mode_and_is_non_empty() {
        // `--notify once` sets the mode-only (bare-string) form of the `notify` field, which applies
        // uniformly to every event; the mode value is validated downstream, not here.
        let ov = collect_cli(Cli {
            notify: &["once"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.notify, Some(NotifyField::Mode("once".into())));
        assert!(!ov.is_empty(), "a set notify override must be non-empty");

        // `--notify off` silences one launch. It is a *set* override, not an unset one — otherwise a
        // baseline `always` would leak back in and the launch would talk anyway.
        let off = collect_cli(Cli {
            notify: &["off"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(off.raw.notify, Some(NotifyField::Mode("off".into())));
        assert!(
            !off.is_empty(),
            "`--notify off` is a set override, not a no-op"
        );

        // Last occurrence wins (a scalar).
        let last = collect_cli(Cli {
            notify: &["off", "always"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(last.raw.notify, Some(NotifyField::Mode("always".into())));
    }

    #[test]
    fn a_typed_notify_flag_beats_a_blob_notify_table() {
        // `--notify` (scalar) replaces a `--config` blob's `[notify]` table on the same field — so
        // the blob's `repeat_after` and per-event map go with it. Reach for the blob alone when
        // either is wanted.
        let ov = collect_cli(Cli {
            config: &["[notify]\nmode = \"once\"\nrepeat_after = \"5m\""],
            notify: &["always"],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.notify, Some(NotifyField::Mode("always".into())));
    }

    #[test]
    fn an_ambient_sbx_notify_is_noticed_and_the_cli_beats_it() {
        // `SBX_NOTIFY` alone fires the security-via-environment notice: a stale export that silences
        // refusals is exactly the kind of ambient setting worth naming out loud.
        let ov = ambient(AmbientOverrides {
            notify: Some("off".into()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(ov.raw.notify, Some(NotifyField::Mode("off".into())));
        assert!(
            ov.notices().iter().any(|n| n.contains("`notify`")),
            "{:?}",
            ov.notices()
        );

        let cli_wins = collect_from(
            &CliOverrides {
                notify: owned(&["always"]),
                ..Default::default()
            },
            AmbientOverrides {
                notify: Some("off".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            cli_wins.raw.notify,
            Some(NotifyField::Mode("always".into()))
        );
        // set on the CLI, so no env-source notice for it.
        assert!(!cli_wins.notices().iter().any(|n| n.contains("`notify`")));
    }

    /// `[ssh_agent] confirm` is not an allow list, and folding the table as if it were dropped it.
    ///
    /// `union_allow_opt` returns the *base* table with the higher tier's `allow` copied in, so every
    /// other field of the higher tier's table is discarded. For `[seccomp]` and `[devices]` there is
    /// no other field; `[ssh_agent]` carries `confirm`, whose whole contract is that it can be added
    /// and never removed. Two `--config` blobs — one granting a key, one asking for the
    /// per-signature prompt — therefore granted the key with no prompt at all, which is the
    /// fail-open direction on a flag that exists to be fail-closed.
    #[test]
    fn a_higher_tiers_ssh_agent_confirm_survives_a_lower_tier_that_declares_the_table_too() {
        let ov = collect_cli(Cli {
            config: &[
                "[ssh_agent]\nallow = [\"deploy-key\"]",
                "[ssh_agent]\nallow = [\"build-key\"]\nconfirm = true",
            ],
            ..Default::default()
        })
        .unwrap();
        let agent = ov.raw.ssh_agent.as_ref().expect("ssh_agent present");
        assert_eq!(
            agent.allow,
            vec!["deploy-key".to_string(), "build-key".to_string()],
            "both grants still accumulate across the blobs"
        );
        assert_eq!(
            agent.confirm,
            Some(true),
            "the prompt the second blob asked for must reach the launch"
        );

        // The other direction is the documented one and must not change: the flag ORs across the
        // tiers rather than following their precedence, so a lower tier that asked for the prompt
        // cannot have it turned off by a higher one — the most convenient place to try.
        let inverted = collect_from(
            &CliOverrides {
                config: owned(&["[ssh_agent]\nallow = [\"build-key\"]\nconfirm = false"]),
                ..Default::default()
            },
            AmbientOverrides {
                config: Some("[ssh_agent]\nallow = [\"deploy-key\"]\nconfirm = true".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            inverted.raw.ssh_agent.expect("ssh_agent present").confirm,
            Some(true),
            "confirmation is never turned off by another tier"
        );
    }

    /// The override plane's `[fs]` fold must widen the scan window, like the layer merge it names.
    ///
    /// `scan_max_kb` is how many bytes of a file the content lens reads before letting the open
    /// through, so the larger number closes more files — which is why `FsPolicy::union` was
    /// corrected from `min` to `max`. This fold runs first and decides what that union is handed,
    /// and it kept the `min`: an ambient `SBX_CONFIG` ceiling left in a shell by a wrapper beat the
    /// one the invoker typed on the command line, against this module's own precedence rule, and
    /// every credential past the smaller offset went to the cage unscanned.
    #[test]
    fn an_explicit_fs_scan_ceiling_is_not_shrunk_by_a_lower_tiers_one() {
        let ov = collect_from(
            &CliOverrides {
                config: owned(&["[fs]\nscan_max_kb = 512"]),
                ..Default::default()
            },
            AmbientOverrides {
                config: Some("[fs]\nscan = [\"AKIA[0-9A-Z]{16}\"]\nscan_max_kb = 1".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            ov.raw.fs.expect("fs present").scan_max_kb,
            Some(512),
            "the command line's window stands; the ambient one may only widen it"
        );
    }

    /// The ambient scan walks the whole environment, so it must tolerate the whole environment.
    ///
    /// `std::env::vars` panics when **any** variable — not one sbx reads — carries a name or a value
    /// that is not valid Unicode, and this scan runs at the head of every override-carrying command
    /// (`sbx run`, `sbx app`, `sbx config show`). One Latin-1 value left by an unrelated tool
    /// therefore aborted the process before the sandbox was built, with a panic naming neither the
    /// variable nor sbx's reason for reading it.
    #[test]
    fn a_non_utf8_variable_elsewhere_in_the_environment_does_not_abort_the_scan() {
        use std::os::unix::ffi::OsStringExt as _;
        let _lock = crate::testutil::env_lock();
        // `caf\xe9` — a Latin-1 value, which no `String` can hold.
        let _junk = crate::testutil::EnvVar::set(
            "SBX_TEST_LATIN1_VALUE",
            std::ffi::OsString::from_vec(vec![b'c', b'a', b'f', 0xE9]),
        );
        let _pkg = crate::testutil::EnvVar::set("SBX_PACKAGE_jq", "nix:jq");
        let _limit = crate::testutil::EnvVar::set("SBX_LIMIT_TASKS_MAX", "8192");

        let ambient = scan_ambient();
        assert!(
            ambient
                .packages
                .contains(&("jq".to_string(), "nix:jq".to_string())),
            "sbx's own variables are still read: {:?}",
            ambient.packages
        );
        assert!(
            ambient
                .limits
                .contains(&("tasks_max".to_string(), "8192".to_string())),
            "{:?}",
            ambient.limits
        );
    }
}
