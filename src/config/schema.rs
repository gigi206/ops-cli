//! The on-disk shape of an `ops` config file and its parse.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The fields a global `ops.toml` or a project `.ops.toml` may declare. Every
/// field is optional, and unknown fields are ignored, so a config written for a
/// newer ops still loads on an older one — the schema is additive, never a hard
/// parse wall a project could trip a command on.
///
/// Fields are split by the trust gate, not by this struct: `env` is a *free*
/// field (applied even from an untrusted project, minus a reserved-key denylist),
/// `binds` is a *security* field (honored only from a trusted source). The
/// distinction lives in the loader so the schema stays a plain data shape.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawConfig {
    /// Extra environment variables for the sandbox.
    #[serde(default)]
    pub(crate) env: BTreeMap<String, String>,
    /// Extra host paths to expose inside the sandbox — read-only by default, or read-write
    /// with the table form (see [`RawBind`]).
    #[serde(default)]
    pub(crate) binds: Vec<RawBind>,
    /// Tools to provision into the sandbox, as `name = "<backend>:<locator>"`. The name
    /// is a free label — the merge key across layers and the on-disk root name; the value
    /// carries a mandatory backend prefix (parsed downstream, not here): `nix:<attribute>`
    /// for a nixpkgs attribute provisioned host-side (e.g. `nix:nodejs_20`), `mise:<token>`
    /// for a mise backend equipped in-cage (e.g. `mise:aqua:openai/codex`), or `flake:<ref>`
    /// for a flake output built in-cage (e.g. `flake:github:owner/repo#attr`).
    /// A value with no recognized prefix is dropped with a warning — there is no bare form.
    #[serde(default)]
    pub(crate) packages: BTreeMap<String, String>,
    /// Override the nixpkgs reference the tools resolve against: a branch/channel
    /// (`nixos-23.11`) or a 40-hex revision under `NixOS/nixpkgs`. A security field
    /// — honored from the global config or a trusted project, ignored from an
    /// untrusted one (the source is a supply-chain-relevant choice).
    pub(crate) nixpkgs: Option<String>,
    /// The sandbox's network posture. Either a simple string — `"none"` (a fresh, empty
    /// network namespace), `"shared"` (the host network, the default when unset), `"deny"`
    /// (filtered egress, deny-by-default — only the built-in hosts reach), or `"allow"`
    /// (filtered egress, allow-by-default — a denylist, every public host reaches except the
    /// carve-outs), or `"ask"` (filtered egress, park-and-confirm — an undecided host blocks until
    /// you answer) — or a table that adds the `allow`/`deny` carve-out lists to a
    /// `deny`/`allow`/`ask` mode. A table may **omit** `mode` to inherit it from the parent config
    /// layer (an app takes the baseline's, a project takes the global's) while keeping its own
    /// rules — see [`NetworkTable::mode`]. A security field: honored from the global config or a
    /// trusted project, ignored from an untrusted one, since narrowing or widening the network is a
    /// confidentiality choice an untrusted project may not make.
    pub(crate) network: Option<NetworkField>,
    /// The sandbox's GUI posture: `"none"` (the default — no display access) or `"wayland"`
    /// (bind the host's Wayland compositor socket read-only so a graphical app can map a
    /// window). A security field — honored from the global config or a trusted project,
    /// ignored from an untrusted one: exposing a compositor socket is a confidentiality and
    /// integrity choice (clipboard access, and on some compositors screen capture or input
    /// injection) an untrusted project may not make. X11 is deliberately never offered — an
    /// X client can snoop and drive every other window, which Wayland's per-client isolation
    /// prevents on a well-behaved compositor.
    pub(crate) gui: Option<String>,
    /// Host loopback TCP ports to forward from the host into the cage — a list of port
    /// numbers (`forward = [1455]`). Each port is bound on the host's `127.0.0.1` and
    /// bridged, through a bound Unix socket, to the cage's own loopback at the same port,
    /// so a host process (a browser chasing an OAuth `localhost:<port>` callback, or a
    /// dev opening a cage-run dev server) can reach a service the agent started inside the
    /// empty-netns cage. A security field — honored from the global config or a trusted
    /// project, ignored from an untrusted one: opening a host port is a deliberate inbound
    /// hole, a choice an untrusted project may not make. A port already in use on the host
    /// fails the launch closed (the redirect URL is baked in for OAuth, so ops does not
    /// pick an ephemeral substitute). Loopback-only — never the host's external interfaces.
    pub(crate) forward: Option<Vec<u16>>,
    /// Credentials the egress proxy injects into matching outbound requests, declared
    /// as the `[secret]` section — a table keyed by destination host. A security field:
    /// honored from the global config or a trusted project, ignored from an untrusted one,
    /// and only effective under a network allowlist — the filtering proxy is what performs
    /// the injection, so the plaintext never enters the cage.
    pub(crate) secret: Option<RawSecretSection>,
    /// Named application launch profiles, declared as `[app.<name>]` tables. Each is an
    /// overlay over the sandbox baseline — a command to run plus the extra tools,
    /// environment, binds, network posture, and credentials that app needs. The overlay's
    /// fields are gated exactly like the baseline (the security ones honored only from a
    /// trusted source), then merged onto the baseline by `ops app <name>`.
    #[serde(default)]
    pub(crate) app: BTreeMap<String, RawApp>,
    /// Resource limits for the cage's cgroup scope (anti-DoS), overriding ops's built-in
    /// defaults. A security field — honored from the global config or a trusted project,
    /// ignored from an untrusted one: loosening a limit (a higher `tasks_max`, an unbounded
    /// memory ceiling) reduces the anti-DoS protection, a choice an untrusted project may not
    /// make. Each field is independent and falls back to the default when unset.
    pub(crate) limits: Option<RawLimits>,
    /// A trusted relaxation of the cage's mandatory seccomp syscall denylist, declared as the
    /// `[seccomp]` table. A security field — honored from the global config or a trusted project,
    /// ignored from an untrusted one: re-permitting a denied syscall reduces the kernel-attack-
    /// surface control, a choice an untrusted project may not make. Empty or absent leaves the full
    /// mandatory denylist.
    pub(crate) seccomp: Option<RawSeccomp>,
    /// A trusted grant of host device nodes into the cage, declared as the `[devices]` table. A
    /// security field — honored from the global config or a trusted project, ignored from an
    /// untrusted one: a real device node widens the kernel attack surface (a device-driver bug
    /// becomes reachable from the cage), a choice an untrusted project may not make. Empty or absent
    /// leaves the cage's minimal `/dev` (null/zero/urandom/tty…) with no host devices.
    pub(crate) devices: Option<RawDevices>,
    /// Network-scoped config that is not itself a posture — currently the reusable egress
    /// groups (`[net.groups]`). A group is a named list of egress entries that any `[network]`
    /// `allow`/`deny` list may reference with `@<name>`, so a set of hosts is declared once and
    /// shared across apps instead of being rewritten per profile. Groups are a security-relevant
    /// input (they expand to egress rules), so they are honored only from the global config
    /// (trusted by location); a project's `[net.groups]` is ignored.
    #[serde(default)]
    pub(crate) net: RawNet,
}

/// The `[net]` table: config under the `net` namespace that is not a per-launch posture. For now
/// it carries only `[net.groups]`. Kept a distinct struct (rather than folding `groups` onto
/// `RawConfig`) so the `net` namespace can grow without crowding the top level.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawNet {
    /// Named reusable egress groups, `[net.groups]` — each `name = [ "<entry>", … ]`, where an
    /// entry is any egress rule string the `allow`/`deny` lists accept (an IP, host, `*.domain`,
    /// exact URL, `re:` regex, or `tcp://` L4 target, with an optional `{VERB,…}` method prefix).
    /// A `[network]` list references a group by `@<name>`; the reference expands to these entries.
    #[serde(default)]
    pub(crate) groups: BTreeMap<String, Vec<String>>,
}

/// One `binds` entry: a bare path string (bound **read-only**, the default) or a table
/// `{ path = "...", mode = "rw" }` that marks the bind **read-write**. An untagged enum so
/// both forms coexist in one array — `binds = ["/ro/path", { path = "/rw/path", mode = "rw" }]`
/// — keeping the common read-only case a bare string, matching the string-or-table shape of
/// `cmd`/`network`. On serialize a read-only bind written as a bare string round-trips as
/// itself (the minimal, canonical form), a table form round-trips as a table.
///
/// `binds` is a security field either way (honored only from a trusted source): a read-only
/// bind exposes the path's contents, a read-write one additionally lets the cage write through
/// to the host path. An untrusted project gets no bind at all, so it can never obtain a
/// writable one.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawBind {
    /// A bare path: bound read-only.
    Path(String),
    /// A table: an explicit `path` plus an optional `mode` (`"ro"` default | `"rw"`).
    Detailed(RawBindTable),
}

/// The table form of a `binds` entry: `{ path = "...", mode = "ro" | "rw" }`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawBindTable {
    /// The host path to bind (absolute; validated downstream, like a bare-string bind). Optional
    /// at the parse layer so a table missing its `path` — a typo, or the tell-tale of a
    /// wrongly-authored entry — is skipped with a per-entry warning downstream rather than failing
    /// the untagged-enum parse and dropping the *whole* config layer (env, packages, apps and all).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) path: Option<String>,
    /// `"ro"` (the default) or `"rw"`. An unrecognized value is treated as read-only — the
    /// fail-closed direction for a security field — with a warning, downstream. Absent means
    /// read-only. Omitted on serialize when unset, so a plain read-only table stays minimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
}

/// The `[limits]` table: optional overrides for the cage's cgroup resource limits.
/// `memory_high` is the throttle threshold, `memory_max` the hard ceiling — each a systemd
/// memory value (a percentage like `"80%"`, a byte quantity like `"16G"`, or `"infinity"`);
/// `tasks_max` is the process/thread cap (a count like `8192`, or `"infinity"`). Each value's
/// syntax is validated downstream against exactly what systemd accepts, so a malformed one is
/// dropped with a warning rather than reaching `systemd-run` and failing the launch.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawLimits {
    pub(crate) memory_high: Option<RawLimit>,
    pub(crate) memory_max: Option<RawLimit>,
    pub(crate) tasks_max: Option<RawLimit>,
}

/// One resource-limit value as declared: a bare number — a byte count for memory, a task count
/// for tasks — or a string (`"80%"`, `"16G"`, `"infinity"`). An untagged enum so both TOML forms
/// parse: a natural `tasks_max = 8192` and a `memory_max = "80%"` both load, rather than a type
/// mismatch failing the whole config. A bare number is taken verbatim (bytes for memory, a count
/// for tasks); a percentage or a suffixed size must be quoted.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawLimit {
    /// A bare number: a byte count (memory) or a task count (tasks).
    Number(u64),
    /// A string form: a percentage (`"80%"`), a suffixed byte size (`"16G"`), or `"infinity"`.
    Text(String),
}

impl RawLimit {
    /// The value as the string token systemd's `-p KEY=VALUE` receives: a number renders as its
    /// decimal form, a string is taken verbatim (and validated downstream before it is used).
    pub(crate) fn as_token(&self) -> String {
        match self {
            RawLimit::Number(n) => n.to_string(),
            RawLimit::Text(s) => s.clone(),
        }
    }
}

/// The `[seccomp]` table: a trusted relaxation of the cage's mandatory syscall denylist. `allow`
/// lists syscalls (or argument-filtered sub-rules) to re-permit — a bare name lifts the whole
/// syscall (`ptrace`, `unshare`, `mount`), while `clone`/`ioctl` (the two argument-filtered
/// entries) also accept a `:selector` (`clone:newns`, `ioctl:tioclinux`) that lifts only that
/// sub-rule. Each string may itself be a comma-separated list (`"ptrace,unshare"`), split downstream.
/// A malformed or unknown entry is dropped with a warning (fail-closed); an entry that reopens a
/// real escape surface is accepted with a caution. Empty or absent leaves the full mandatory denylist.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawSeccomp {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allow: Vec<String>,
}

/// The `[devices]` table: a trusted grant of host device nodes into the cage. Each `allow` entry is
/// an absolute path under `/dev/` — a single device node (`/dev/kvm`, `/dev/net/tun`, `/dev/fuse`)
/// or a directory of them (`/dev/dri` for a GPU). The cage's default `/dev` is a minimal, hostless
/// tree (null/zero/urandom/tty…); an allowed path is bound over it with device access, so the tool
/// reaches the real host device. A malformed entry (not absolute, not under `/dev/`, or containing a
/// `..` component) is dropped with a warning (fail-closed); a device absent on the host is skipped at
/// launch, not fatal. Empty or absent leaves the minimal `/dev`.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawDevices {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allow: Vec<String>,
}

/// One `[app.<name>]` entry: the command to run plus an overlay over the sandbox
/// baseline. The overlay fields reuse the baseline shapes and gate identically — an
/// untrusted project's app may add `env`/`packages` and choose the command, but its
/// `binds`/`network`/`secret` are dropped, exactly as for the baseline.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawApp {
    /// The command to run, as an argv. A bare string is taken as a single-element argv
    /// (the program name, no arguments) — never split on whitespace, so a path with a
    /// space is not mis-parsed and there is no shell-quoting surface.
    pub(crate) cmd: Option<RawCmd>,
    /// Extra environment for this app, layered over the baseline (the app wins on a key
    /// collision). A free field, like the baseline `env`. Skipped when empty on serialize, so an
    /// exported profile carries no noise `[env]` table.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    /// Extra host paths to bind for this app — read-only by default, or read-write with the
    /// table form (see [`RawBind`]). A security field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) binds: Vec<RawBind>,
    /// Extra tools to provision for this app, `name = "<backend>:<locator>"` (the same
    /// backend-prefixed form as the baseline `packages`), overriding a baseline tool of the
    /// same name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) packages: BTreeMap<String, String>,
    /// The app's network posture, overriding the baseline's when set. A security field.
    pub(crate) network: Option<NetworkField>,
    /// The app's GUI posture, overriding the baseline's when set. A security field, like the
    /// baseline `gui`. An unset `Option` is omitted by TOML on export, so an app with no GUI
    /// need carries no `gui` line.
    pub(crate) gui: Option<String>,
    /// Host loopback ports forwarded into this app's cage (see `RawConfig.forward`). A
    /// security field, gated like the baseline `forward`: an app's ports **union** onto
    /// the baseline's, so an untrusted project can only add its own, never remove or
    /// override a trusted layer's set. An unset `Option` is omitted on export.
    pub(crate) forward: Option<Vec<u16>>,
    /// Credentials the egress proxy injects for this app. A security field, effective only
    /// under a network allowlist, like the baseline `[secret]` section.
    pub(crate) secret: Option<RawSecretSection>,
    /// The app's cgroup resource limits, overriding the baseline's per field. A security field,
    /// gated like the baseline `[limits]` (loosening them weakens the anti-DoS control), so an
    /// untrusted project's app `[limits]` is dropped whole. An unset `Option` is omitted on
    /// export, so an app that tunes nothing carries no `[limits]` table.
    pub(crate) limits: Option<RawLimits>,
    /// The app's seccomp denylist relaxation, unioned onto the baseline's. A security field, gated
    /// like the baseline `[seccomp]` (loosening the denylist weakens the kernel-attack-surface
    /// control), so an untrusted project's app `[seccomp]` is dropped. An unset `Option` is omitted
    /// on export, so an app that relaxes nothing carries no `[seccomp]` table.
    pub(crate) seccomp: Option<RawSeccomp>,
    /// The host device nodes this app grants into its cage, unioned onto the baseline's. A security
    /// field, gated like the baseline `[devices]` (a host device widens the kernel attack surface),
    /// so an untrusted project's app `[devices]` is dropped. An unset `Option` is omitted on export,
    /// so an app that needs no device carries no `[devices]` table.
    pub(crate) devices: Option<RawDevices>,
    /// Where this app's persistent `$HOME` (its config, login state, history) lives:
    /// `"global"` (the default) — one home per app, shared across every project, so the app
    /// keeps a single identity wherever it runs; or `"project"` — a home per (project, app),
    /// isolating what the agent writes in one project from another. An *integrity* field: an
    /// untrusted project may set the scope of its own app but may not move a trusted app from
    /// `"project"` to `"global"` (which would let it write into the shared home).
    pub(crate) home_scope: Option<String>,
}

/// The command form of an app's `cmd`: a full argv (`["claude", "--flag"]`) or a bare
/// program name (`"claude"`, taken as a one-element argv). An untagged enum so both TOML
/// shapes parse, matching the string-or-table forward-compatibility of `NetworkField`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawCmd {
    /// A bare program name — a single-element argv, never whitespace-split.
    Line(String),
    /// A full argv: the program followed by its arguments.
    Argv(Vec<String>),
}

impl RawCmd {
    /// The argv this command denotes: a bare name becomes a one-element argv, an array is
    /// taken verbatim.
    pub(crate) fn into_argv(self) -> Vec<String> {
        match self {
            RawCmd::Line(program) => vec![program],
            RawCmd::Argv(argv) => argv,
        }
    }
}

/// The `[secret]` section: a reserved `defaults` table plus one entry per destination host.
/// `secret` is a TOML *table* keyed by host (`[secret."api.github.com"]`), not an array — the
/// host is the section, so a credential's destination reads at a glance. The reserved `defaults`
/// key holds the resolver order and per-resolver bindings the terse `key` form expands through;
/// every other key is a concrete host whose value is one secret or, as an array of tables
/// (`[[secret."host"]]`), several (different headers to the same host). A host can therefore not
/// be named `defaults` — that key is reserved for the settings table.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawSecretSection {
    /// Resolver order and per-resolver bindings the terse `key` form expands through.
    pub(crate) defaults: Option<RawSecretDefaults>,
    /// One entry per destination host; the value is a single secret or an array of them. The
    /// reserved `defaults` key is consumed above, so this holds only host entries.
    #[serde(flatten)]
    pub(crate) hosts: BTreeMap<String, RawHostSecrets>,
}

/// The secret(s) declared for one host: a single table (`[secret."host"]`) or an array of
/// tables (`[[secret."host"]]`) for several credentials (different headers) to that host.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawHostSecrets {
    /// `[secret."host"]` — one secret.
    One(RawHostSecret),
    /// `[[secret."host"]]` — several secrets to the same host.
    Many(Vec<RawHostSecret>),
}

/// One credential bound to a host (the host is the section key, so there is no `to` field). The
/// source is either the terse `key` (expanded through `[secret.defaults]`) or an explicit `from`
/// resolver ref/chain — exactly one of the two. `header`/`type`/`prefix` shape what is set.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawHostSecret {
    /// The broker kind; optional, defaulting to the only kind today, `"http-header"`.
    pub(crate) kind: Option<String>,
    /// The terse source: a key name resolved through the default resolver order, optionally
    /// pinned with a trailing `@resolver[,resolver]`. Mutually exclusive with `from`.
    pub(crate) key: Option<String>,
    /// An explicit source: one `scheme://locator` ref (`from = "env://VAR"`) or a fallback chain
    /// tried in order (`from = ["env://VAR", "sops://f#k"]`). Mutually exclusive with `key`.
    pub(crate) from: Option<SecretFrom>,
    /// The header name to set, e.g. `Authorization`. Optional only if `[secret.defaults] header`
    /// supplies it; a secret that names neither is an explicit error (never a silent default).
    pub(crate) header: Option<String>,
    /// How to shape the value: `bearer`, `basic`, or `raw`. Optional only if `[secret.defaults]
    /// type` supplies it; a secret that names neither is an explicit error rather than a silent
    /// (and likely wrong) transform.
    #[serde(rename = "type")]
    pub(crate) value_type: Option<String>,
    /// An optional prefix overriding the type's default (`Bearer ` for bearer, empty for
    /// raw, `Basic ` for basic).
    pub(crate) prefix: Option<String>,
}

/// The defaults declared once under `[secret.defaults]`: the resolver order and per-resolver
/// bindings the terse `key` form expands through, plus a default `header`/`type` an entry may omit.
/// The `header`/`type` defaults apply to **every** entry — a verbose `from` entry omitting `header`
/// inherits it just as a terse `key` one does; only the resolver order/bindings are terse-only.
/// A per-entry value always overrides the default; an entry that names neither a `header`/`type`
/// here nor on itself is still an explicit error (no silent built-in default). The resolver order
/// is a security setting — it selects a secret's source — so this whole table is honored from the
/// global config or a trusted project, never an untrusted one.
#[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawSecretDefaults {
    /// The resolver names to try, in order, for a terse key — e.g. `["env", "sops"]`. The first
    /// that resolves at launch wins; a later one is a fallback. A per-secret `key@resolver`
    /// overrides this order for that secret.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) order: Vec<String>,
    /// The default header name for entries that omit `header` (e.g. `Authorization`). Note: the
    /// header is half the `(host, header)` dedup key, so several `[[secret."host"]]` entries that
    /// all fall back to this one default collapse to the last (with a warning).
    pub(crate) header: Option<String>,
    /// The default value type for entries that omit `type` (`bearer`/`basic`/`raw`).
    #[serde(rename = "type")]
    pub(crate) value_type: Option<String>,
    /// The `sops` binding: the encrypted file a terse sops key reads from.
    pub(crate) sops: Option<RawSopsDefaults>,
    /// The `env` binding: how to transform a terse key into a variable name.
    pub(crate) env: Option<RawEnvDefaults>,
    /// The `file` binding: the base directory a terse file key reads from.
    pub(crate) file: Option<RawFileDefaults>,
}

/// The `sops` resolver binding: a terse key `k` expands to `sops://<file>#k`.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawSopsDefaults {
    pub(crate) file: String,
}

/// The `env` resolver binding: a terse key `k` expands to `env://<case(k)>`.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawEnvDefaults {
    /// `"upper"`, `"lower"`, or `"asis"` (the default) — how to case the key before using it as
    /// a variable name.
    pub(crate) case: Option<String>,
}

/// The `file` resolver binding: a terse key `k` expands to `file://<dir>/k`.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawFileDefaults {
    pub(crate) dir: String,
}

/// The two shapes a secret's `from` accepts: a single resolver ref string, or a list of refs
/// tried in order. An untagged enum so both TOML forms parse — `from = "env://VAR"` and
/// `from = ["env://VAR", "file:///p"]` — keeping the single-source case a one-liner.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum SecretFrom {
    /// `from = "env://VAR"`.
    One(String),
    /// `from = ["env://VAR", "file:///p"]`.
    Many(Vec<String>),
}

/// The two shapes the `network` field accepts: a bare posture string, or a table for the
/// filtered-egress carve-out lists. An untagged enum so both TOML forms parse — `network = "none"`
/// and `[network] mode = "deny"` (or `"allow"`/`"ask"`) — keeping the simple case a one-liner.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum NetworkField {
    /// `network = "none"` | `"shared"` | `"deny"` | `"allow"` | `"ask"`.
    Posture(String),
    /// `[network] mode = "<mode>"` with optional `allow`/`deny` carve-out lists.
    Table(NetworkTable),
}

/// The table form of the `network` field: a mode plus the egress carve-out entries (IPs, domains,
/// `*.domain` wildcards, exact URLs — classified later). Under `deny` mode `allow` lists what may
/// reach; under `allow` mode `deny` lists what may not; under `ask` mode `allow` auto-passes and
/// `deny` auto-fails, everything else parks. `deny` always wins. `ask_timeout` (a duration like
/// `"90s"`/`"5m"`, or absent for an indefinite wait) bounds a parked `ask` request, and
/// `ask_notice = false` silences the inline stderr park alert (the request still parks).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct NetworkTable {
    /// The egress mode. Absent means "inherit the mode from the parent config layer" (an app takes
    /// the baseline's mode, a project takes the global's) while keeping this table's own
    /// `allow`/`deny` rules; only a filtering `deny`/`ask` is inherited — an `allow` denylist,
    /// `shared`/`none`, or no parent posture all fall back to the safe `deny`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    #[serde(default)]
    pub(crate) deny: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ask_timeout: Option<String>,
    /// Whether to print the `ask`-mode park notice to stderr when a request parks. On by default; a
    /// trusted layer may set `false` to silence the inline alert — the request still parks, answer it
    /// with `ops net pending`. Inert outside `ask` mode. Absent means "inherit" — a layer that does
    /// not mention it does not change the inherited value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ask_notice: Option<bool>,
    /// Whether the egress proxy records its per-host decision counters (`ops net stats`). On by
    /// default; a trusted layer may set `false` to turn the audit off (`true` re-enables it). Absent
    /// means "inherit" — a layer that does not mention it does not change the inherited value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stats: Option<bool>,
    /// The HTTP verbs an **app's** unscoped (`{...}`-less) allow rules default to — its read-by-default
    /// posture. Only meaningful on an `[app.<name>.network]` (or an imported profile's `[network]`):
    /// every Mode-B app defaults to `["GET","HEAD"]` so an agent reads but does not write unless a
    /// rule opts a host out with `{*}`/`{VERB}`; this field overrides that default for the app (e.g.
    /// `["GET","POST"]`, or `["*"]` for all verbs). Ignored on the baseline `[network]` — `ops run`/
    /// `ops shell` (Mode A) stay all-verbs. Absent means the built-in `["GET","HEAD"]` app default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) default_methods: Option<Vec<String>>,
}

/// Parse config bytes as TOML. The error is a human-readable string: the loader
/// turns it into a warning and ignores the layer rather than aborting a command,
/// so a malformed config never wedges the sandbox.
pub(crate) fn parse(bytes: &[u8]) -> Result<RawConfig, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| e.to_string())
}

/// Serialize an app as a top-level profile — the inverse of [`parse_app`], producing the portable
/// file `ops app export` writes. Empty `env`/`binds`/`packages` are skipped (the field attributes),
/// and an unset `Option` is omitted by TOML, so the output is the minimal faithful profile. The
/// error is a human-readable string. Proven a lossless round-trip with [`parse_app`] in the tests,
/// including the `#[serde(flatten)]` secret hosts and the untagged `cmd`/`network`/`from` enums.
pub(crate) fn serialize_app(app: &RawApp) -> Result<String, String> {
    toml::to_string(app).map_err(|e| e.to_string())
}

/// Parse bytes as a single app profile — a top-level [`RawApp`]. A profile file *is* one app
/// (its fields at the top level, no `[app.<name>]` wrapper), and its name comes from the file,
/// not the contents — so the file is name-agnostic and portable. The error is a human-readable
/// string, like [`parse`]. A file written in the inline `[app.<name>]` shape parses here as an
/// empty `RawApp` (the wrapper is an unknown top-level field, ignored); the import path catches
/// that by requiring a `cmd`, so the wrong shape is refused rather than silently mis-imported.
pub(crate) fn parse_app(bytes: &[u8]) -> Result<RawApp, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_and_binds() {
        let cfg = parse(
            br#"
            binds = ["/etc/ssl/custom", "/opt/data"]
            [env]
            FOO = "bar"
            BAZ = "qux"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(cfg.env.get("BAZ").map(String::as_str), Some("qux"));
        assert_eq!(
            cfg.binds,
            vec![
                RawBind::Path("/etc/ssl/custom".into()),
                RawBind::Path("/opt/data".into()),
            ]
        );
    }

    #[test]
    fn parses_a_mixed_ro_and_rw_bind_array() {
        // A bare string is a read-only bind (the default); a table with `mode = "rw"` marks a
        // read-write one. Both coexist in one array — the untagged enum tries `Path` first.
        let cfg = parse(
            br#"
            binds = [
                "/ro/path",
                { path = "/rw/path", mode = "rw" },
                { path = "/explicit/ro", mode = "ro" },
            ]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.binds,
            vec![
                RawBind::Path("/ro/path".into()),
                RawBind::Detailed(RawBindTable {
                    path: Some("/rw/path".into()),
                    mode: Some("rw".into()),
                }),
                RawBind::Detailed(RawBindTable {
                    path: Some("/explicit/ro".into()),
                    mode: Some("ro".into()),
                }),
            ]
        );
    }

    #[test]
    fn a_table_bind_missing_its_path_still_parses_the_rest_of_the_config() {
        // The tolerant-parse property: a table entry without `path` must NOT fail the untagged
        // enum and drop the whole layer — it parses to `path: None` (skipped, with a warning, at
        // resolve time) while every sibling field survives. Here the `env` table and the well-formed
        // sibling bind must both remain.
        let cfg = parse(
            br#"
            [env]
            FOO = "bar"
            [[binds]]
            mode = "rw"
            [[binds]]
            path = "/ok"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(
            cfg.binds,
            vec![
                RawBind::Detailed(RawBindTable {
                    path: None,
                    mode: Some("rw".into()),
                }),
                RawBind::Detailed(RawBindTable {
                    path: Some("/ok".into()),
                    mode: None,
                }),
            ]
        );
    }

    #[test]
    fn a_mixed_bind_array_round_trips_through_toml() {
        // The load-bearing spike: `serialize_app` must emit a heterogeneous string/table array
        // that `parse_app` reads back identically — `toml::to_string` of a `Vec<untagged-enum>`
        // where some elements are scalars and some are inline tables is the fragile corner.
        let app = parse_app(
            br#"
            cmd = "demo-app"
            binds = ["/ro/path", { path = "/rw/path", mode = "rw" }]
            "#,
        )
        .unwrap();
        assert_eq!(
            app.binds,
            vec![
                RawBind::Path("/ro/path".into()),
                RawBind::Detailed(RawBindTable {
                    path: Some("/rw/path".into()),
                    mode: Some("rw".into()),
                }),
            ]
        );
        let serialized = serialize_app(&app).unwrap();
        let reparsed = parse_app(serialized.as_bytes()).unwrap();
        assert_eq!(
            app, reparsed,
            "a mixed ro/rw bind array must round-trip:\n{serialized}"
        );
    }

    #[test]
    fn parses_packages_as_name_to_attribute() {
        let cfg = parse(b"[packages]\nnode = \"nodejs_20\"\npython = \"python311\"\n").unwrap();
        assert_eq!(
            cfg.packages.get("node").map(String::as_str),
            Some("nodejs_20")
        );
        assert_eq!(
            cfg.packages.get("python").map(String::as_str),
            Some("python311")
        );
    }

    #[test]
    fn parses_an_app_table_with_a_string_or_array_command() {
        let cfg = parse(
            br#"
            [app.demo-app]
            cmd = "demo-app"
            home_scope = "project"
            [app.demo-app.packages]
            demo-tool = "demo-tool"

            [app.build]
            cmd = ["make", "-j4"]
            "#,
        )
        .unwrap();
        // A bare string is a single-element argv; an array is taken verbatim.
        assert_eq!(
            cfg.app["demo-app"]
                .cmd
                .as_ref()
                .map(|c| c.clone().into_argv()),
            Some(vec!["demo-app".to_string()])
        );
        // the optional home scope parses as a bare string; an app without it leaves it unset
        assert_eq!(cfg.app["demo-app"].home_scope.as_deref(), Some("project"));
        assert_eq!(cfg.app["build"].home_scope, None);
        assert_eq!(
            cfg.app["demo-app"]
                .packages
                .get("demo-tool")
                .map(String::as_str),
            Some("demo-tool")
        );
        assert_eq!(
            cfg.app["build"].cmd.as_ref().map(|c| c.clone().into_argv()),
            Some(vec!["make".to_string(), "-j4".to_string()])
        );
    }

    #[test]
    fn parses_a_top_level_app_profile() {
        // A profile file is one app at the top level — its fields directly, no `[app.<name>]`
        // wrapper. The name lives in the filename, so the contents are name-agnostic.
        let app = parse_app(
            br#"
            cmd = "demo-app"
            home_scope = "global"
            [packages]
            demo-tool = "demo-tool"
            [network]
            mode = "deny"
            allow = ["api.example.com"]
            "#,
        )
        .unwrap();
        assert_eq!(
            app.cmd.map(|c| c.into_argv()),
            Some(vec!["demo-app".to_string()])
        );
        assert_eq!(app.home_scope.as_deref(), Some("global"));
        assert_eq!(
            app.packages.get("demo-tool").map(String::as_str),
            Some("demo-tool")
        );
        assert!(matches!(app.network, Some(NetworkField::Table(_))));
    }

    #[test]
    fn an_inline_wrapped_profile_parses_as_an_empty_app() {
        // A file mistakenly written in the inline `[app.<name>]` shape has no top-level `cmd`,
        // so it parses as an empty app — the tell-tale the import path refuses on.
        let app = parse_app(b"[app.demo-app]\ncmd = \"demo-app\"\n").unwrap();
        assert_eq!(app.cmd, None);
    }

    #[test]
    fn serializing_an_app_round_trips_through_toml() {
        // `serialize_app` is the inverse of `parse_app` — what `ops app export` writes must
        // re-import identically. Covers the fragile corners: `#[serde(flatten)]` secret hosts
        // (with a `defaults` table and an array-of-tables host) and the untagged `cmd`/`network`/
        // `from` enums.
        let src = br#"
            cmd = ["demo-app", "--resume"]
            home_scope = "global"
            gui = "wayland"
            binds = ["/opt/data"]
            [env]
            FOO = "bar"
            [packages]
            demo-tool = "mise:aqua:example/demo-tool"
            [network]
            mode = "deny"
            allow = ["api.example.com", "*.nixos.org"]
            deny = ["evil.example.com"]
            [limits]
            memory_max = "8G"
            tasks_max = 4096
            [secret.defaults]
            order = ["env", "sops"]
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            [[secret."api.npmjs.org"]]
            key = "npm_a"
            header = "X-A"
            type = "raw"
            [[secret."api.npmjs.org"]]
            key = "npm_b"
            header = "X-B"
            type = "raw"
            "#;
        let app = parse_app(src).unwrap();
        // The app's `[limits]` overlay parses with the same number-or-string forms as the baseline.
        let limits = app.limits.as_ref().expect("the [limits] overlay parses");
        assert_eq!(
            limits
                .memory_max
                .as_ref()
                .map(RawLimit::as_token)
                .as_deref(),
            Some("8G")
        );
        assert_eq!(
            limits.tasks_max.as_ref().map(RawLimit::as_token).as_deref(),
            Some("4096")
        );
        assert_eq!(limits.memory_high, None);
        let serialized = serialize_app(&app).unwrap();
        let reparsed = parse_app(serialized.as_bytes()).unwrap();
        assert_eq!(app, reparsed, "export must round-trip losslessly");
    }

    #[test]
    fn a_mode_less_network_table_round_trips_without_a_mode_line() {
        // `ops app export` of a profile that inherits its mode must not materialize a `mode` line —
        // that would pin the mode and break the inheritance the author chose.
        let app = parse_app(b"cmd = \"demo\"\n[network]\nallow = [\"api.foo.com\"]\n").unwrap();
        let out = serialize_app(&app).unwrap();
        assert!(
            !out.contains("mode"),
            "a mode-less table must not gain a `mode` line:\n{out}"
        );
        let reparsed = parse_app(out.as_bytes()).unwrap();
        assert_eq!(
            app, reparsed,
            "a mode-less network must round-trip losslessly"
        );
        assert!(matches!(
            reparsed.network,
            Some(NetworkField::Table(NetworkTable { mode: None, .. }))
        ));
    }

    #[test]
    fn serializing_skips_empty_collections_and_round_trips_a_bare_command() {
        // A minimal app serializes to a minimal profile — no noise `[env]`/`[packages]` tables or
        // `binds = []`, and an unset option is omitted entirely.
        let app = parse_app(b"cmd = \"demo-app\"\n").unwrap();
        let out = serialize_app(&app).unwrap();
        assert!(out.contains("cmd"), "{out}");
        assert!(!out.contains("[env]"), "empty env must be skipped:\n{out}");
        assert!(
            !out.contains("[packages]"),
            "empty packages must be skipped:\n{out}"
        );
        assert!(
            !out.contains("binds"),
            "empty binds must be skipped:\n{out}"
        );
        assert!(
            !out.contains("network"),
            "unset network must be omitted:\n{out}"
        );
        assert!(
            !out.contains("home_scope"),
            "unset home_scope must be omitted:\n{out}"
        );
        assert!(!out.contains("gui"), "unset gui must be omitted:\n{out}");
        assert!(
            !out.contains("limits"),
            "unset limits must be omitted:\n{out}"
        );
        // A bare-string command (`RawCmd::Line`) round-trips as itself — not silently promoted to a
        // one-element array — so an exported minimal profile re-imports identically.
        let reparsed = parse_app(out.as_bytes()).unwrap();
        assert_eq!(reparsed.cmd, Some(RawCmd::Line("demo-app".into())));
        assert_eq!(app, reparsed);
    }

    #[test]
    fn parses_the_gui_posture_string() {
        let cfg = parse(b"gui = \"wayland\"\n").unwrap();
        assert_eq!(cfg.gui.as_deref(), Some("wayland"));
        // unset means no declared posture — the loader treats that as the default (none).
        assert_eq!(parse(b"").unwrap().gui, None);
        // an app overlay carries its own gui posture
        let app = parse_app(b"cmd = \"x\"\ngui = \"wayland\"\n").unwrap();
        assert_eq!(app.gui.as_deref(), Some("wayland"));
    }

    #[test]
    fn parses_a_limits_table_in_number_and_string_forms() {
        let cfg = parse(
            br#"
            [limits]
            memory_high = "70%"
            memory_max  = "16G"
            tasks_max   = 8192
            "#,
        )
        .unwrap();
        let l = cfg.limits.as_ref().unwrap();
        // a string value is kept verbatim; a bare integer parses as a number and renders as its
        // decimal token (so `tasks_max = 8192` and `tasks_max = "8192"` agree downstream).
        assert_eq!(
            l.memory_high.as_ref().map(RawLimit::as_token).as_deref(),
            Some("70%")
        );
        assert_eq!(
            l.memory_max.as_ref().map(RawLimit::as_token).as_deref(),
            Some("16G")
        );
        assert_eq!(
            l.tasks_max.as_ref().map(RawLimit::as_token).as_deref(),
            Some("8192")
        );

        // an `infinity` string parses; an unset field stays None (falls back to the default).
        let cfg = parse(b"[limits]\ntasks_max = \"infinity\"\n").unwrap();
        let l = cfg.limits.as_ref().unwrap();
        assert_eq!(
            l.tasks_max.as_ref().map(RawLimit::as_token).as_deref(),
            Some("infinity")
        );
        assert_eq!(l.memory_max, None);

        // no table at all → None
        assert_eq!(parse(b"").unwrap().limits, None);
    }

    #[test]
    fn parses_the_nixpkgs_override_and_defaults_to_none() {
        let cfg = parse(b"nixpkgs = \"nixos-23.11\"\n").unwrap();
        assert_eq!(cfg.nixpkgs.as_deref(), Some("nixos-23.11"));
        assert_eq!(parse(b"").unwrap().nixpkgs, None);
    }

    #[test]
    fn parses_the_network_posture_string_form() {
        let cfg = parse(b"network = \"none\"\n").unwrap();
        assert_eq!(cfg.network, Some(NetworkField::Posture("none".into())));
        // unset means no declared posture — the loader treats that as the default
        // (shared) rather than an explicit choice.
        assert_eq!(parse(b"").unwrap().network, None);
    }

    #[test]
    fn parses_the_network_deny_table_form() {
        let cfg = parse(
            br#"
            [network]
            mode = "deny"
            allow = ["github.com", "*.nixos.org", "1.2.3.4", "https://example.com/x"]
            deny  = ["evil.nixos.org"]
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable {
                mode: Some("deny".into()),
                allow: vec![
                    "github.com".into(),
                    "*.nixos.org".into(),
                    "1.2.3.4".into(),
                    "https://example.com/x".into(),
                ],
                deny: vec!["evil.nixos.org".into()],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
            }))
        );
    }

    #[test]
    fn a_network_table_without_allow_or_deny_defaults_to_empty() {
        let cfg = parse(b"[network]\nmode = \"deny\"\n").unwrap();
        assert_eq!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable {
                mode: Some("deny".into()),
                allow: vec![],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
            }))
        );
    }

    #[test]
    fn a_network_table_may_omit_mode_to_inherit_it() {
        // A `[network]` table with rules but no `mode` parses to `mode: None` (the loader resolves
        // the effective mode by inheriting from the parent layer).
        let cfg = parse(b"[network]\nallow = [\"api.foo.com\"]\n").unwrap();
        assert_eq!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable {
                mode: None,
                allow: vec!["api.foo.com".into()],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
            }))
        );
    }

    #[test]
    fn a_bare_string_network_still_parses_as_a_posture_not_a_table() {
        // With `mode` optional, the untagged enum must still route a bare string to `Posture`, never
        // silently to an (empty, mode-less) `Table`.
        assert_eq!(
            parse(b"network = \"deny\"\n").unwrap().network,
            Some(NetworkField::Posture("deny".into()))
        );
    }

    #[test]
    fn a_network_table_with_an_unknown_field_is_ignored_not_a_parse_error() {
        // The schema is deliberately additive (unknown fields ignored) so a config using a *newer*
        // ops field still loads on an older ops. `[network]` must not break that: `NetworkField` is
        // an untagged enum, so a parse error there fails the WHOLE `RawConfig` → the loader drops the
        // entire layer → the network silently reverts to the open `shared` default (a fail-OPEN on a
        // security field). So an unknown `[network]` field is ignored, and the table still parses.
        // (A `mode` typo therefore lands here too — the table parses mode-less and *inherits*,
        // resolving to `deny`/`ask`, never `shared`: it fails safe.)
        let cfg = parse(b"[network]\nmode = \"deny\"\nfuturefield = 1\n").unwrap();
        assert!(matches!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable { ref mode, .. })) if mode.as_deref() == Some("deny")
        ));
    }

    /// Pull the single secret declared for `host` out of a parsed section, failing the test if
    /// the host is absent or declared as an array.
    #[cfg(test)]
    fn one_host<'a>(cfg: &'a RawConfig, host: &str) -> &'a RawHostSecret {
        match cfg
            .secret
            .as_ref()
            .and_then(|s| s.hosts.get(host))
            .unwrap_or_else(|| panic!("no secret for host `{host}`"))
        {
            RawHostSecrets::One(s) => s,
            RawHostSecrets::Many(_) => panic!("host `{host}` is an array, expected one"),
        }
    }

    #[test]
    fn parses_a_secret_section_keyed_by_host() {
        let cfg = parse(
            br#"
            [secret."api.github.com"]
            kind   = "http-header"
            from   = "env://GITHUB_TOKEN"
            header = "Authorization"
            type   = "bearer"

            [secret."registry.npmjs.org"]
            from   = "file:///run/secrets/npm"
            header = "Authorization"
            type   = "raw"
            prefix = "Bearer "
            "#,
        )
        .unwrap();
        let section = cfg.secret.as_ref().unwrap();
        // the reserved `defaults` key is absent here, and the two host keys are present
        assert!(section.defaults.is_none());
        assert_eq!(section.hosts.len(), 2);

        let gh = one_host(&cfg, "api.github.com");
        assert_eq!(gh.kind.as_deref(), Some("http-header"));
        // a single-string `from` parses to the `One` shape
        assert_eq!(gh.from, Some(SecretFrom::One("env://GITHUB_TOKEN".into())));
        assert_eq!(gh.header.as_deref(), Some("Authorization"));
        assert_eq!(gh.value_type.as_deref(), Some("bearer"));
        assert_eq!(gh.prefix, None);

        let npm = one_host(&cfg, "registry.npmjs.org");
        // kind is optional, defaulting downstream
        assert_eq!(npm.kind, None);
        assert_eq!(
            npm.from,
            Some(SecretFrom::One("file:///run/secrets/npm".into()))
        );
        assert_eq!(npm.prefix.as_deref(), Some("Bearer "));

        // unset means no declared secrets
        assert!(parse(b"").unwrap().secret.is_none());
    }

    #[test]
    fn parses_a_terse_key_and_a_defaults_table() {
        let cfg = parse(
            br#"
            [secret.defaults]
            order  = ["env", "sops"]
            header = "Authorization"
            type   = "bearer"
            [secret.defaults.sops]
            file = "secrets/prod.yaml"
            [secret.defaults.env]
            case = "upper"

            [secret."api.github.com"]
            key = "github_token"
            "#,
        )
        .unwrap();
        let defaults = cfg.secret.as_ref().unwrap().defaults.as_ref().unwrap();
        assert_eq!(defaults.order, vec!["env".to_string(), "sops".to_string()]);
        assert_eq!(defaults.sops.as_ref().unwrap().file, "secrets/prod.yaml");
        assert_eq!(
            defaults.env.as_ref().unwrap().case.as_deref(),
            Some("upper")
        );
        // the default header/type let a terse entry name only its key
        assert_eq!(defaults.header.as_deref(), Some("Authorization"));
        assert_eq!(defaults.value_type.as_deref(), Some("bearer"));
        // `defaults` is consumed by the named field, never leaking into the host map
        assert_eq!(cfg.secret.as_ref().unwrap().hosts.len(), 1);

        let gh = one_host(&cfg, "api.github.com");
        assert_eq!(gh.key.as_deref(), Some("github_token"));
        assert_eq!(gh.from, None);
        // the entry omits header/type — they come from the defaults
        assert_eq!(gh.header, None);
        assert_eq!(gh.value_type, None);
    }

    #[test]
    fn a_host_named_defaults_is_swallowed_by_the_reserved_table() {
        // `defaults` is the reserved settings key, so `[secret."defaults"]` (a host literally named
        // "defaults") is consumed as the defaults table, not a host entry. Its secret fields are
        // ignored, so no credential is injected for a host named "defaults" — fail-closed, never a
        // silent injection to the wrong place.
        let cfg = parse(
            br#"
            [secret."defaults"]
            key    = "x"
            header = "Authorization"
            type   = "bearer"
            "#,
        )
        .unwrap();
        let section = cfg.secret.as_ref().unwrap();
        assert!(
            section.defaults.is_some(),
            "the `defaults` key is the reserved settings table"
        );
        assert!(
            section.hosts.is_empty(),
            "no host entry is produced for a host named `defaults`"
        );
    }

    #[test]
    fn parses_several_secrets_for_one_host_as_an_array() {
        let cfg = parse(
            br#"
            [[secret."api.github.com"]]
            key    = "github_token"
            header = "Authorization"
            type   = "bearer"

            [[secret."api.github.com"]]
            key    = "github_ci"
            header = "X-Api-Key"
            type   = "raw"
            "#,
        )
        .unwrap();
        let many = match cfg.secret.as_ref().unwrap().hosts.get("api.github.com") {
            Some(RawHostSecrets::Many(v)) => v,
            other => panic!("expected an array of secrets, got {other:?}"),
        };
        assert_eq!(many.len(), 2);
        assert_eq!(many[0].header.as_deref(), Some("Authorization"));
        assert_eq!(many[1].header.as_deref(), Some("X-Api-Key"));
    }

    #[test]
    fn parses_a_secret_from_resolver_chain() {
        let cfg = parse(
            br#"
            [secret."api.github.com"]
            from   = ["env://GH_TOKEN", "file:///run/secrets/gh"]
            header = "Authorization"
            type   = "bearer"
            "#,
        )
        .unwrap();
        // a list `from` parses to the `Many` shape, in order
        assert_eq!(
            one_host(&cfg, "api.github.com").from,
            Some(SecretFrom::Many(vec![
                "env://GH_TOKEN".into(),
                "file:///run/secrets/gh".into(),
            ]))
        );
    }

    #[test]
    fn an_empty_config_is_all_defaults() {
        let cfg = parse(b"").unwrap();
        assert_eq!(cfg, RawConfig::default());
    }

    #[test]
    fn unknown_fields_are_ignored_for_forward_compatibility() {
        // a field a newer ops understands must not break an older one
        let cfg = parse(b"some_future_field = 42\n[env]\nA = \"1\"\n").unwrap();
        assert_eq!(cfg.env.get("A").map(String::as_str), Some("1"));
    }

    #[test]
    fn malformed_toml_is_a_readable_error() {
        let err = parse(b"this is = = not toml").unwrap_err();
        assert!(!err.is_empty());
    }
}
