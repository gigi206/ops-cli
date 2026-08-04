//! The on-disk shape of an `sbx` config file and its parse.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The fields a global `sbx.toml` or a project `.sbx.toml` may declare. Every
/// field is optional, and unknown fields are ignored, so a config written for a
/// newer sbx still loads on an older one — the schema is additive, never a hard
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
    /// for a mise backend equipped in-cage (e.g. `mise:aqua:example/demo-tool`), or `flake:<ref>`
    /// for a flake output built host-side into the shared store like `nix:` (e.g.
    /// `flake:github:owner/repo#attr`).
    /// A value with no recognized prefix is dropped with a warning — there is no bare form.
    #[serde(default)]
    pub(crate) packages: BTreeMap<String, String>,
    /// Inline nix flakes, declared as `[flakes.<name>]` tables. Each carries a full `flake.nix`
    /// written directly in the config (the `flake` field, a multiline string) plus an optional
    /// output `attr` (default `"default"`); sbx stages it, binds it read-only into the cage, and
    /// builds `path:<dir>#<attr>` **in-cage** — local content cannot be built host-side, unlike a
    /// remote `flake:` ref — folding it into the same tool set (the name is the merge key and the
    /// on-disk root name). A security field like
    /// `packages` — arbitrary nix build source, honored only from a trusted source. Distinct from
    /// `[packages]` so a bulky multiline flake reads clearly and never trips the TOML rule that
    /// forbids adding scalar keys to a table after one of its subtables is opened.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) flakes: BTreeMap<String, RawInlineFlake>,
    /// Auto-upgrade resolvers for `tarball:resolve` packages, declared as `[tarball.<name>]`
    /// tables. Each pairs with a `[packages]` entry `<name> = "tarball:resolve"` (the opt-in
    /// sentinel) and carries a `resolve` command that prints the newest release's download URL, so
    /// `sbx upgrade` can re-run it and roll the pin forward. A security field like `packages` — it
    /// runs an arbitrary (sandboxed) command host-side, so it is honored only from a trusted source.
    /// Declared as its own table (not folded into `[packages]`) so the command reads clearly and
    /// never trips the TOML rule that forbids adding scalar keys to a table after one of its
    /// subtables is opened.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) tarball: BTreeMap<String, RawResolve>,
    /// Auto-upgrade resolvers for `deb:resolve` packages, declared as `[deb.<name>]` tables — the
    /// exact `deb:` analogue of [`tarball`](Self::tarball). Each pairs with a `[packages]` entry
    /// `<name> = "deb:resolve"` and carries a `resolve` command that prints the newest release's
    /// `.deb` download URL, so `sbx upgrade` can re-run it and roll the pin forward. A security field
    /// (it runs an arbitrary sandboxed command host-side), honored only from a trusted source.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) deb: BTreeMap<String, RawResolve>,
    /// Auto-upgrade resolvers for `appimage:resolve` packages, declared as `[appimage.<name>]` tables
    /// — the exact `appimage:` analogue of [`tarball`](Self::tarball). Each pairs with a `[packages]`
    /// entry `<name> = "appimage:resolve"` and carries a `resolve` command that prints the newest
    /// release's `.AppImage` download URL, so `sbx upgrade` can re-run it and roll the pin forward. A
    /// security field (it runs an arbitrary sandboxed command host-side), honored only from a trusted
    /// source.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) appimage: BTreeMap<String, RawResolve>,
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
    /// The process/exec observation-and-enforcement posture. Either a bare mode string — `"off"`
    /// (the default), `"observe"` (capture spawns via a `/proc` poll, no blocking), `"enforce"`
    /// (block `deny` exec targets before the syscall runs, allow everything else — a denylist), or
    /// `"ask"` (block `deny`, allow `allow`, park an unmatched target for a live `sbx proc allow`/
    /// `deny`) — or a table adding the `allow`/`deny` exec-target lists. A security field: honored
    /// from the global config or a trusted project, ignored from an untrusted one — an untrusted
    /// project may neither forge nor loosen the enforcement of its own agent.
    pub(crate) proc: Option<ProcField>,
    /// Which refusals sbx announces to the person running it, and how often. Either a bare mode
    /// string — `"off"`, `"once"` (the first of each distinct problem), or `"always"` (the default:
    /// every occurrence, a repeat revising the notification already on screen) —
    /// or a table adding `events`, which narrows the set (a list) or sets a mode per event (a table).
    /// The event names are the config sections that govern each refusal: `network`, `proc`,
    /// `ssh_agent`, `task`, `trust`.
    ///
    /// A security field: honored from the global config or a trusted project, ignored from an
    /// untrusted one. A refusal notification is the one signal that a config's own restrictions are
    /// biting, so a `.sbx.toml` able to silence it could hide exactly what the boundary was built to
    /// surface — and would do so from the side the boundary exists to contain.
    pub(crate) notify: Option<NotifyField>,
    /// The sandbox's GUI posture: `"none"` (the default — no display access), `"offscreen"`
    /// (provision the fonts and — under a filtering egress posture — the NSS CA import a browser
    /// engine needs to render and to trust the proxy, without exposing any display), or
    /// `"wayland"` (all of that, plus bind the host's Wayland compositor socket read-only so a
    /// graphical app can map a window). A security field — honored from the global config or a
    /// trusted project, ignored from an untrusted one: exposing a compositor socket is a
    /// confidentiality and integrity choice (clipboard access, and on some compositors screen
    /// capture or input injection) an untrusted project may not make. `"offscreen"` grants no
    /// host access at all, but rides the same gate so the postures stay one ordered field.
    /// X11 is deliberately never offered — an X client can snoop and drive every other window,
    /// which Wayland's per-client isolation prevents on a well-behaved compositor.
    pub(crate) gui: Option<String>,
    /// Whether to open hardware-accelerated GPU rendering for the cage (`gpu = true`). sbx
    /// provisions mesa's DRI drivers into its own store and points the cage's libgbm/libEGL at
    /// them, grants the render node(s) under `/dev/dri`, and read-only-binds the minimal `/sys`
    /// DRM subtree the driver reads to enumerate the device. A security field — honored from the
    /// global config or a trusted project, ignored from an untrusted one: a render node and the
    /// `/sys` device tree widen the kernel attack surface (a GPU-driver bug becomes reachable
    /// from the cage), a choice an untrusted project may not make. Covers mesa-supported GPUs
    /// (Intel/AMD/nouveau); the NVIDIA proprietary stack is a separate, not-yet-built mechanism.
    /// Most useful together with `gui = "wayland"`.
    pub(crate) gpu: Option<bool>,
    /// Whether to open audio (microphone + playback) for the cage (`audio = true`). sbx provisions
    /// the PulseAudio client library into its own store and puts it on the app's loader path, and
    /// binds the host PulseAudio socket (`$XDG_RUNTIME_DIR/pulse/native`, which a PipeWire host
    /// exposes via `pipewire-pulse`) into the cage. A security field — honored from the global
    /// config or a trusted project, ignored from an untrusted one: the PulseAudio bus is not
    /// per-client isolated, so a connected client can capture the microphone and every `.monitor`
    /// source (record whatever is playing on the host), a capability an untrusted project may not
    /// grant itself. Most useful together with `gui = "wayland"`.
    pub(crate) audio: Option<bool>,
    /// Whether to give the cage a **private in-cage desktop portal** (`dbus = true`). sbx stands up
    /// a private D-Bus session bus inside the cage carrying its own `xdg-desktop-portal` with the GTK
    /// backend, so a Chromium/Electron app's file chooser renders **inside** the cage (seeing only
    /// the cage filesystem), the host light/dark theme is seeded at launch and followed live, and
    /// desktop notifications are relayed to the host. A security field — honored from the global
    /// config or a trusted project, ignored from an untrusted one: standing up an in-cage portal is a
    /// choice an untrusted project may not make. The private bus touches no host socket, so it is
    /// unaffected by the network posture. Requires `gui = "wayland"` (the GTK backend needs the
    /// compositor to render).
    pub(crate) dbus: Option<bool>,
    /// Host loopback TCP ports to forward from the host into the cage — a list of port
    /// numbers (`forward = [1455]`). Each port is bound on the host's `127.0.0.1` and
    /// bridged, through a bound Unix socket, to the cage's own loopback at the same port,
    /// so a host process (a browser chasing an OAuth `localhost:<port>` callback, or a
    /// dev opening a cage-run dev server) can reach a service the agent started inside the
    /// empty-netns cage. A security field — honored from the global config or a trusted
    /// project, ignored from an untrusted one: opening a host port is a deliberate inbound
    /// hole, a choice an untrusted project may not make. A port already in use on the host
    /// fails the launch closed (the redirect URL is baked in for OAuth, so sbx does not
    /// pick an ephemeral substitute). Loopback-only — never the host's external interfaces.
    pub(crate) forward: Option<Vec<u16>>,
    /// Credentials the egress proxy injects into matching outbound requests, declared
    /// as the `[secret]` section — a table keyed by destination host. A security field:
    /// honored from the global config or a trusted project, ignored from an untrusted one,
    /// and only effective under a network allowlist — the filtering proxy is what performs
    /// the injection, so the plaintext never enters the cage.
    pub(crate) secret: Option<RawSecretSection>,
    /// Declared operations, the `[task]` section: named fixed commands sbx runs in an ephemeral
    /// sibling cage with a credential the caller never holds. A security field — honored from the
    /// global config or a trusted project, ignored from an untrusted one: a task is a program sbx
    /// runs on a caller's behalf with a credential attached, which an untrusted project may neither
    /// declare nor loosen.
    pub(crate) task: Option<RawTaskSection>,
    /// Named application launch profiles, declared as `[app.<name>]` tables. Each is an
    /// overlay over the sandbox baseline — a command to run plus the extra tools,
    /// environment, binds, network posture, and credentials that app needs. The overlay's
    /// fields are gated exactly like the baseline (the security ones honored only from a
    /// trusted source), then merged onto the baseline by `sbx app <name>`.
    #[serde(default)]
    pub(crate) app: BTreeMap<String, RawApp>,
    /// Resource limits for the cage's cgroup scope (anti-DoS), overriding sbx's built-in
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
    /// A trusted grant of ssh-agent keys into the cage, declared as the `[ssh_agent]` table. A
    /// security field — honored from the global config or a trusted project, ignored from an
    /// untrusted one: a key the cage can sign with authenticates as the user everywhere that key is
    /// trusted, a choice an untrusted project may not make. Empty or absent leaves the cage with no
    /// agent at all.
    pub(crate) ssh_agent: Option<RawSshAgent>,
    /// Network-scoped config that is not itself a posture — currently the reusable egress
    /// groups (`[net.groups]`). A group is a named list of egress entries that any `[network]`
    /// `allow`/`deny` list may reference with `@<name>`, so a set of hosts is declared once and
    /// shared across apps instead of being rewritten per profile. Groups are a security-relevant
    /// input (they expand to egress rules), so they are honored only from the global config
    /// (trusted by location); a project's `[net.groups]` is ignored.
    #[serde(default)]
    pub(crate) net: RawNet,
    /// Reusable tool bundles, `[bundle.<name>]` — everything one tool needs to be *installed* and
    /// to *reach its own services*, declared once and folded into any app that names it in `use`.
    /// A bundle is the map-side companion of a `[net.groups]` group: a group factors out egress
    /// entries, which are list items a `@<name>` reference can expand into, while `packages`/`env`
    /// are maps with no slot for such a reference. Bundles are a security-relevant input (they add
    /// tools, environment, egress rules, and credentials), so they are honored only from the global
    /// config (trusted by location); a project's `[bundle]` is ignored.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) bundle: BTreeMap<String, RawBundle>,
    /// Every top-level key sbx does not know. Unknown keys stay **ignored** — that is what lets a
    /// config written for a newer sbx load on an older one — but a misspelled `memory_maxx` and a
    /// field from next year's release are indistinguishable in silence, and only one of them is
    /// harmless. Kept so the loader can say what it passed over. See [`RawIgnored`].
    #[serde(flatten)]
    pub(crate) rest: BTreeMap<String, RawIgnored>,
}

/// A `[bundle.<name>]` table: what one tool needs to be installed and to reach its own services.
///
/// The field set is the whole design. A bundle carries the tool (`packages` and the resolver
/// tables that pair with them), the configuration it reads (`env`), the egress it needs
/// (`allow`/`deny`/`mute`), and the credential it authenticates with (`secret`) — and **nothing
/// about the shape of the cage**. There is deliberately no `cmd` (an app's command is its own
/// identity, and inheriting one would be an integrity hijack), no `binds`/`forward`/`devices`/
/// `ssh_agent`/`seccomp`/`limits` (host exposure and kernel surface stay declared where they are
/// granted), and
/// none of the posture scalars (`network.mode`, `gui`, `gpu`, `audio`, `dbus`, `proc`,
/// `home_scope`) — a bundle that silently switched on a microphone because the tool it packages
/// can use one is exactly the surprise this shape rules out. So using a bundle can add a tool, its
/// environment, its egress and its credential; it can never widen what the cage exposes of the
/// host.
///
/// A bundle may not name another bundle: there is no `use` field here, so nesting — and with it
/// any cycle — is impossible by construction, the same way a `[net.groups]` entry may not be a
/// `@other` reference. Its `allow`/`deny`/`mute` entries *may* be `@group` references, because
/// those are reference sites like an app's own lists: the bundle is folded into the app before
/// classification, so the group expansion still runs exactly once.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawBundle {
    /// Tools this bundle provisions, `name = "<backend>:<locator>"` — the same backend-prefixed
    /// form as [`RawConfig::packages`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) packages: BTreeMap<String, String>,
    /// Environment this bundle's tool reads (its configuration, telemetry opt-outs, …).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    /// Egress entries the tool needs, unioned onto the app's `allow` list. Same grammar as
    /// [`NetworkTable::allow`], `@group` references included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allow: Vec<String>,
    /// Egress entries to refuse, unioned onto the app's `deny` list (deny always wins).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deny: Vec<String>,
    /// Refusals to keep out of the default egress log, unioned onto the app's `mute` list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) mute: Vec<String>,
    /// Credentials the egress proxy injects for this tool, host-side. Same shape and effect as an
    /// app's `[secret]` section — effective only under a network allowlist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) secret: Option<RawSecretSection>,
    /// Declared operations this bundle contributes, `[bundle.<name>.task.<task>]`. Folded into any
    /// app that names the bundle in `use`, like its packages and credentials — a tool that ships a
    /// brokered operation carries it with the rest of what it needs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) task: Option<RawTaskSection>,
    /// Inline nix flakes this bundle's packages refer to, `[bundle.<name>.flakes.<tool>]`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) flakes: BTreeMap<String, RawInlineFlake>,
    /// Auto-upgrade resolvers pairing with this bundle's `tarball:resolve` packages.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) tarball: BTreeMap<String, RawResolve>,
    /// Auto-upgrade resolvers pairing with this bundle's `deb:resolve` packages.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) deb: BTreeMap<String, RawResolve>,
    /// Auto-upgrade resolvers pairing with this bundle's `appimage:resolve` packages.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) appimage: BTreeMap<String, RawResolve>,
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
    /// Unknown keys in this table, kept so they can be reported. A misspelled limit is the sharpest
    /// case of the silence: the ceiling the author asked for is simply not in effect.
    #[serde(flatten)]
    pub(crate) rest: BTreeMap<String, RawIgnored>,
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
    /// Unknown keys in this table, kept so they can be reported.
    #[serde(flatten)]
    pub(crate) rest: BTreeMap<String, RawIgnored>,
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
    /// Unknown keys in this table, kept so they can be reported.
    #[serde(flatten)]
    pub(crate) rest: BTreeMap<String, RawIgnored>,
}

/// The `[ssh_agent]` table: which of the host agent's keys the cage may sign with. Each `allow`
/// entry names **one** key, by the `SHA256:…` fingerprint or by the comment `ssh-add -l` prints
/// beside it. There is no wildcard: a grant that could not be read off a listing would not be a
/// grant anyone could audit. sbx never binds the host agent's socket — it serves the cage a socket
/// of its own whose answers carry only the named keys, and whose message types are an allowlist, so
/// the cage can list and sign and nothing else (no add, no remove, no wipe). Empty or absent leaves
/// the cage with no agent.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawSshAgent {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allow: Vec<String>,
    /// Ask before **every** signature: sbx raises a prompt on the host desktop naming the key (and,
    /// when the client bound one, the server), and signs only if it is approved. Unlike `ssh-add -c`
    /// this asks for what the *cage* requests and nothing else, so ordinary use outside the sandbox
    /// is unaffected. Fail-closed in every direction: with no askpass helper on the host the cage
    /// gets no agent at all, and the flag ORs across layers — a layer that asks for confirmation
    /// cannot have it turned off by another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) confirm: Option<bool>,
    /// Unknown keys in this table, kept so they can be reported.
    #[serde(flatten)]
    pub(crate) rest: BTreeMap<String, RawIgnored>,
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
    /// Reusable tool bundles this app is built from, `use = ["<name>", …]` (see [`RawBundle`]).
    /// Each named bundle's packages, environment, egress entries and credentials are folded into
    /// this app before resolution, in the order written — a later bundle overrides an earlier one
    /// on the same key, and the app's own entries override every bundle. A *security* field: a
    /// bundle is declared in the global config, so honoring `use` from an untrusted project would
    /// let that project graft a trusted egress set or credential onto its own app; an untrusted
    /// layer's `use` is therefore dropped with a warning, like `network`. Grouped beside `cmd`
    /// because both say what the app *is*, ahead of the fields that shape it.
    ///
    /// When writing one by hand, `use` must sit at the top level, above the first `[table]`
    /// header: TOML reads a key after a header as belonging to that table, so a `use` written
    /// below (say) `[packages]` parses as `packages.use`, an unknown key, and is dropped in
    /// silence. Export never produces that shape — the serializer emits values ahead of tables.
    #[serde(default, rename = "use", skip_serializing_if = "Vec::is_empty")]
    pub(crate) uses: Vec<String>,
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
    /// Inline nix flakes for this app, declared as `[app.<name>.flakes.<tool>]` (or a top-level
    /// `[flakes.<tool>]` in an imported profile). Same shape and gating as the baseline `flakes`
    /// (see [`RawConfig::flakes`]); folded into the app's tool set beside its `packages`. Skipped
    /// when empty on serialize, so an app with no inline flake carries no `[flakes]` table.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) flakes: BTreeMap<String, RawInlineFlake>,
    /// Auto-upgrade resolvers for this app's `tarball:resolve` packages, declared as
    /// `[app.<name>.tarball.<tool>]` (or a top-level `[tarball.<tool>]` in an imported profile).
    /// Same shape and gating as the baseline `tarball` (see [`RawConfig::tarball`]); each pairs with
    /// a `<tool> = "tarball:resolve"` entry in the app's `packages`. Skipped when empty on serialize,
    /// so an app with no such package carries no `[tarball]` table.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) tarball: BTreeMap<String, RawResolve>,
    /// Auto-upgrade resolvers for this app's `deb:resolve` packages, declared as
    /// `[app.<name>.deb.<tool>]` (or a top-level `[deb.<tool>]` in an imported profile). Same shape
    /// and gating as the baseline `deb` (see [`RawConfig::deb`]); each pairs with a
    /// `<tool> = "deb:resolve"` entry in the app's `packages`. Skipped when empty on serialize.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) deb: BTreeMap<String, RawResolve>,
    /// Auto-upgrade resolvers for this app's `appimage:resolve` packages, declared as
    /// `[app.<name>.appimage.<tool>]` (or a top-level `[appimage.<tool>]` in an imported profile).
    /// Same shape and gating as the baseline `appimage` (see [`RawConfig::appimage`]); each pairs with
    /// an `<tool> = "appimage:resolve"` entry in the app's `packages`. Skipped when empty on serialize.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) appimage: BTreeMap<String, RawResolve>,
    /// The app's network posture, overriding the baseline's when set. A security field.
    pub(crate) network: Option<NetworkField>,
    /// The app's process/exec posture, overriding the baseline's when set. A security field.
    pub(crate) proc: Option<ProcField>,
    /// The app's refusal-notification policy, overriding the baseline's when set. A security field,
    /// like the baseline `notify`. Carried per app because how much an app's refusals are worth
    /// hearing is a property of the app: a browser profile refused by the egress policy on every
    /// third-party asset it loads is noise, while the same refusal from a coding agent is the signal.
    pub(crate) notify: Option<NotifyField>,
    /// The app's GUI posture, overriding the baseline's when set. A security field, like the
    /// baseline `gui`. An unset `Option` is omitted by TOML on export, so an app with no GUI
    /// need carries no `gui` line.
    pub(crate) gui: Option<String>,
    /// The app's GPU posture, overriding the baseline's when set (see `RawConfig.gpu`). A
    /// security field, like the baseline `gpu`. An unset `Option` is omitted on export, so an
    /// app with no GPU need carries no `gpu` line.
    pub(crate) gpu: Option<bool>,
    /// The app's audio posture, overriding the baseline's when set (see `RawConfig.audio`). A
    /// security field, like the baseline `audio`. An unset `Option` is omitted on export, so an
    /// app with no audio need carries no `audio` line.
    pub(crate) audio: Option<bool>,
    /// The app's D-Bus posture, overriding the baseline's when set (see `RawConfig.dbus`). A
    /// security field, like the baseline `dbus`. An unset `Option` is omitted on export, so an app
    /// with no D-Bus need carries no `dbus` line.
    pub(crate) dbus: Option<bool>,
    /// Host loopback ports forwarded into this app's cage (see `RawConfig.forward`). A
    /// security field, gated like the baseline `forward`: an app's ports **union** onto
    /// the baseline's, so an untrusted project can only add its own, never remove or
    /// override a trusted layer's set. An unset `Option` is omitted on export.
    pub(crate) forward: Option<Vec<u16>>,
    /// Credentials the egress proxy injects for this app. A security field, effective only
    /// under a network allowlist, like the baseline `[secret]` section.
    pub(crate) secret: Option<RawSecretSection>,
    /// The app's declared operations, `[app.<name>.task.<task>]`, unioned onto the baseline's (the
    /// app wins on a name collision). A security field, gated like the baseline `[task]` section.
    pub(crate) task: Option<RawTaskSection>,
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
    /// The ssh-agent keys this app's cage may sign with, unioned onto the baseline's. A security
    /// field, gated like the baseline `[ssh_agent]` (a key the cage can sign with authenticates as
    /// the user on every host that trusts it), so an untrusted project's app `[ssh_agent]` is
    /// dropped. This is what lets a deploy key be granted to *one* agent rather than to every cage
    /// the project launches. An unset `Option` is omitted on export, so an app that signs nothing
    /// carries no `[ssh_agent]` table.
    pub(crate) ssh_agent: Option<RawSshAgent>,
    /// Where this app's persistent `$HOME` (its config, login state, history) lives:
    /// `"global"` (the default) — one home per app, shared across every project, so the app
    /// keeps a single identity wherever it runs; or `"project"` — a home per (project, app),
    /// isolating what the agent writes in one project from another. An *integrity* field: an
    /// untrusted project may set the scope of its own app but may not move a trusted app from
    /// `"project"` to `"global"` (which would let it write into the shared home).
    pub(crate) home_scope: Option<String>,
}

/// The command form of an app's `cmd`: a full argv (`["demo-app", "--flag"]`) or a bare
/// program name (`"demo-app"`, taken as a one-element argv). An untagged enum so both TOML
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

/// An inline nix flake declared as a `[flakes.<name>]` table: the full `flake.nix` source plus
/// an optional output attribute. Unlike a `flake:<ref>` package (a reference to an external flake,
/// built host-side), the flake source lives directly in the config — sbx stages it to a directory,
/// binds it read-only into the cage, and builds `path:<dir>#<attr>` in-cage (local content cannot
/// be built host-side). The flake floats: it has no
/// persisted lock and no `sbx upgrade` path, so pin the inputs inside the `flake.nix` itself
/// (e.g. `nixpkgs.url = "github:NixOS/nixpkgs/<rev>"`) for a reproducible build.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawInlineFlake {
    /// The `flake.nix` source, verbatim. A multiline TOML string (`'''…'''`) is the natural form.
    pub(crate) flake: String,
    /// The flake output attribute to build, the `#<attr>` fragment — e.g. `default` (the sbx
    /// default when unset) or a dotted path like `packages.x86_64-linux.hello`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attr: Option<String>,
}

/// An auto-upgrade resolver declared as a `[tarball.<name>]` or `[deb.<name>]` table, paired with a
/// `[packages]` entry `<name> = "tarball:resolve"` / `"deb:resolve"`. It gives sbx a **command** that
/// discovers the newest release's download URL of a prebuilt app whose URL is version-stamped (no
/// stable `latest` alias): the command prints the concrete URL to stdout, and sbx runs it
/// **sandboxed** (in a hermetic bubblewrap cage with sbx's base tools — `curl`/`coreutils`/`grep`/
/// `sed`/`awk` — and the app's own `nix:` `[packages]` on `PATH`, so a command that needs e.g. `jq`
/// just declares it), then validates the printed URL (against the backend's shape — `.tar.gz` or
/// `.deb`) and pins it. `sbx upgrade` re-runs the command and rolls the app forward. Because the
/// command is arbitrary code, this is honored **only from a trusted source**; it never runs for an
/// untrusted layer.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawResolve {
    /// The resolver command as an argv (`["sh", "-c", "curl -s <api> | …"]`) — never
    /// whitespace-split, like `cmd`. It prints the newest release's download URL to stdout (and
    /// nothing else); sbx validates that URL before fetching or building it.
    pub(crate) resolve: Vec<String>,
}

/// The `[secret]` section: a reserved `defaults` table plus one entry per destination host.
/// `secret` is a TOML *table* keyed by host (`[secret."api.github.com"]`), not an array — the
/// host is the section, so a credential's destination reads at a glance. The reserved `defaults`
/// key holds the resolver order and per-resolver bindings the terse `key` form expands through;
/// every other key is a concrete host whose value is one secret or, as an array of tables
/// (`[[secret."host"]]`), several (different headers to the same host). A host can therefore not
/// be named `defaults` — that key is reserved for the settings table.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawHostSecret {
    /// A logical name for this credential, for the inventory `sbx secret list` prints. Optional,
    /// defaulting to the section key (the destination host) — several credentials to one host are
    /// what make it worth setting. It is a label, never a source: naming a secret does not select
    /// it, so a duplicate name is a warning, not a resolution rule.
    pub(crate) name: Option<String>,
    /// A one-line description of what this credential is for, printed beside the name. Free text,
    /// stripped of control characters and length-capped at validation.
    pub(crate) description: Option<String>,
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
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawSopsDefaults {
    pub(crate) file: String,
}

/// The `env` resolver binding: a terse key `k` expands to `env://<case(k)>`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawEnvDefaults {
    /// `"upper"`, `"lower"`, or `"asis"` (the default) — how to case the key before using it as
    /// a variable name.
    pub(crate) case: Option<String>,
}

/// The `file` resolver binding: a terse key `k` expands to `file://<dir>/k`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawFileDefaults {
    pub(crate) dir: String,
}

/// The `[task]` section: a reserved `defaults` table plus one entry per named task. Mirrors
/// [`RawSecretSection`]'s shape, and for the same reason — the per-section settings live in an
/// explicit `[task.defaults]` sub-table rather than as bare keys beside the entries, so a setting
/// can never be swallowed by whichever entry table happens to precede it in the file.
///
/// A task can therefore not be named `defaults`.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawTaskSection {
    /// Section-wide defaults an entry may override (`timeout`, `max_output`).
    pub(crate) defaults: Option<RawTaskDefaults>,
    /// One entry per task name. The reserved `defaults` key is consumed above.
    #[serde(flatten)]
    pub(crate) tasks: BTreeMap<String, RawTask>,
}

/// Section-wide task settings, declared once under `[task.defaults]`.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawTaskDefaults {
    /// The wall-clock ceiling for a task that sets none, as a duration (`"30s"`, `"2m"`).
    pub(crate) timeout: Option<String>,
    /// The captured-output ceiling for a task that sets none (`"64KiB"`).
    pub(crate) max_output: Option<String>,
    /// Whether a substituted credential is named with a per-invocation nonce (`${NAME@a91f3c}`)
    /// instead of the plain `${NAME}`. Off by default, because the plain form is what a reader
    /// expects; on, a placeholder in *this* output cannot have been forged by the command (it could
    /// not predict the nonce), and one copied from an earlier result is detectably stale.
    pub(crate) nonce: Option<bool>,
}

/// A `[task.<name>]` table: one **declared operation** — a fixed command sbx runs in an ephemeral
/// sibling cage with a credential the caller never holds, returning the exit status and whichever
/// of stdout/stderr the declaration permits.
///
/// The security property is that **sbx fixes the program**: `cmd` is an argv list (never a shell
/// string), its first element resolves host-side against a tree the cage cannot write, and the only
/// caller-supplied values are the declared `params`, each bounded by a pattern or an enum. A whole
/// section is a security field — honored from the global config or a trusted project, never from an
/// untrusted one, which may neither declare a task nor loosen one.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawTask {
    /// A one-line description of the operation, listed to the caller. This is the task's
    /// user-facing documentation: an agent picks a task by it.
    pub(crate) description: Option<String>,
    /// The command, as an argv list. Never a shell string — `;`, `&&` and friends carry no meaning
    /// in an `execve` argv, so what bounds the command is this list, the resolved program, and the
    /// `params` bounds, not a metacharacter filter. A `{param}` placeholder substitutes **inside**
    /// the element that contains it and never splits into extra elements.
    #[serde(default)]
    pub(crate) cmd: Vec<String>,
    /// The caller-supplied values `cmd` may interpolate, each declared with its bounds: the terse
    /// form is the pattern itself (`sql = "^SELECT .*$"`), the table form adds `enum` and
    /// `default`. A parameter with no `default` is required; an undeclared placeholder or a missing
    /// value is a hard error, never an empty substitution.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) params: BTreeMap<String, RawTaskParam>,
    /// The credentials the command reads from its environment, keyed by **variable name** — so the
    /// name a redacted value is reported under is the name the declaration already gives it. The
    /// value is a resolver ref (`sops://f#k`, `env://VAR`, `file:///p`, a plugin scheme) or a terse
    /// key expanded through `[secret.defaults]`; the table form adds `encode`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) secret: BTreeMap<String, RawTaskSecret>,
    /// Credentials injected **on the wire** by this task's own proxy instead of into its
    /// environment, keyed by destination host exactly like the top-level `[secret]` table. The
    /// strongest form available: the plaintext never enters the task cage at all, so the command
    /// runs knowing nothing. Requires the task to declare `network` reaching that host.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) inject: BTreeMap<String, RawHostSecrets>,
    /// Fixed environment for the command, from the declaration.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) env: BTreeMap<String, String>,
    /// The variable **names** a caller may set for one invocation. An allowlist of names, never a
    /// free map: an unlisted name is refused. It cannot reuse the `[env]` reserved-key denylist,
    /// which is untrusted-*config*-only (a trusted config harms only itself) — a caller reaching in
    /// over the control socket is a different actor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) env_allow: Vec<String>,
    /// Whether the caller receives stdout: `"show"` (the default) or `"hide"`. Substitution of
    /// secret values is unconditional and independent of this — `hide` withholds the stream, it is
    /// not what protects the credential.
    pub(crate) stdout: Option<String>,
    /// Whether the caller receives stderr: `"show"` (the default) or `"hide"`.
    pub(crate) stderr: Option<String>,
    /// This task's wall-clock ceiling, overriding `[task.defaults] timeout`.
    pub(crate) timeout: Option<String>,
    /// This task's captured-output ceiling, overriding `[task.defaults] max_output`.
    pub(crate) max_output: Option<String>,
    /// Whether this task gets a writable output directory that outlives the invocation.
    ///
    /// A task cage is otherwise entirely ephemeral — a tmpfs `$HOME`, a tmpfs `/tmp`, a read-only
    /// project — so a command that produces a file has nowhere to leave it. With this set, one
    /// directory is bound writable for the invocation, `{out}` substitutes to it, and the session's
    /// agent can read what was left there afterwards.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) output: bool,
    /// The programs this task's command may run, beside the command itself. Absent means no exec
    /// supervision at all; present — **including empty** — stands one up, and then only the command
    /// and what is listed here may `execve`. Each entry is resolved to the absolute in-cage path it
    /// will run as, so a name here names the program in the read-only store and not merely a
    /// filename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) spawn: Option<RawTaskSpawn>,
    /// What each of those programs may run in turn: `[task.<name>.exec.<program>] spawn = [...]`.
    ///
    /// `exec` is a namespace and not a program of its own, because a section named directly after
    /// the program would collide with the task's own fields — `[task.<name>.env]` is the task's
    /// environment, not the `env` binary, and `env`, `output`, `network` and `secret` are all
    /// programs a command plausibly runs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) exec: BTreeMap<String, RawTaskExecNode>,
    /// Present only so a task declaring them is **refused** rather than parsing into silence. Since
    /// unknown keys are ignored by design, a key shaped like a control has to exist here to be
    /// rejected at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) allow: Vec<String>,
    /// Refused for the same reason as `allow`, and present for the same reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) deny: Vec<String>,
    /// The egress this task's cage gets, as allowlist entries. Empty (the default) means an empty
    /// network namespace with no proxy at all. A task's rules are its own: they are served by a
    /// per-invocation proxy, never by the session's, so a task credential is unreachable from the
    /// agent's lane.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) network: Vec<String>,
    /// The `mise:` tools this task's command needs, installed host-side into the project's task
    /// pool and bound **read-only** into the task cage. Only the `mise:` prefix is accepted: every
    /// other backend already builds host-side into the shared store, which a task cage mounts
    /// read-only, so its binaries are on a task's path with nothing to declare here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) packages: Vec<String>,
    /// The bundle this entry came from, stamped when a bundle is folded into an app that names it
    /// in `use`. Never read from or written to a config file — the fold happens before validation,
    /// which is exactly why the bundle's name has to be carried rather than recovered afterwards.
    #[serde(skip)]
    pub(crate) from_bundle: Option<String>,
}

/// The shapes `spawn` accepts. A string is one program with nothing under it, a list is several,
/// and a table reads as "this program may run these" — a parent→child *graph*.
///
/// The graph form parses so that it can be **refused with its own reason** rather than as a type
/// error: what is enforced today is the flat set (a filter is inherited across `fork` and `exec`, so
/// a rule governs the whole cage at any depth, not one parent's children). Accepting the graph and
/// flattening it would be the worst of both — a declaration that reads as a per-parent restriction
/// and is none.
///
/// A graph has **two plausible spellings** and both have to reach that refusal. Whatever shape is
/// not accepted still has to *parse*, because an untagged variant that matches nothing is not a
/// refusal — it is a deserialization error, and a deserialization error is reported against the
/// file, so one mis-shaped key would take every other task and every other section down with it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawTaskSpawn {
    /// `spawn = "git"` — one program, nothing under it.
    One(String),
    /// `spawn = ["git", "less"]` — the enforced form.
    Flat(Vec<RawSpawnEntry>),
    /// `spawn = { git = ["git-remote-https"] }` — parsed to be refused, not applied.
    Nested(BTreeMap<String, RawTaskSpawn>),
}

/// One program's own node in a task's exec graph: what **it** may run.
///
/// A section rather than a list entry because a section body stays flat — a program that runs a
/// dozen others is a twelve-element list under one header, never twelve levels of indentation — and
/// because a section can gain a field later where a string cannot.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawTaskExecNode {
    /// What this program may run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) spawn: Option<RawTaskSpawn>,
    /// Everything else written in the section, kept so it can be **refused**. Unknown keys are
    /// ignored by design, so a deeper section (`[task.t.exec.git.ssh]`, which lands here as a table)
    /// and a misspelled key would both be silent — and a node that means less than it says is the
    /// one failure this whole field exists to avoid.
    #[serde(flatten)]
    pub(crate) rest: BTreeMap<String, RawIgnored>,
}

/// A value kept only for its key's sake: whatever was written under an unknown key is about to be
/// refused, so its content is never read. Accepting *any* shape is the point — a type that could
/// fail to deserialize would report against the whole file, taking every other declaration in it
/// down over a key that was already going to be rejected on its own.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawIgnored;

impl<'de> Deserialize<'de> for RawIgnored {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(d).map(|_| RawIgnored)
    }
}

/// Written back as an empty table, because a profile that holds one of these still has to be
/// writable: `sbx app export` serializes what was *parsed*, and TOML has no unit — a unit here
/// failed the whole export with "unsupported unit type", naming neither the app nor the key. An
/// empty table keeps the key visible, parses back to this same value, and is refused at load exactly
/// as it was before the round-trip.
impl Serialize for RawIgnored {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_map(std::iter::empty::<((), ())>())
    }
}

/// One element of a `spawn` list: a program name, or a table under it.
///
/// The table exists here for the same reason [`RawTaskSpawn::Nested`] does — so that
/// `spawn = ["git", { ssh = ["gpg"] }]` is a task that gets refused by name rather than a file that
/// fails to load.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawSpawnEntry {
    /// `"git"` — a program.
    Name(String),
    /// `{ ssh = ["gpg"] }` — parsed to be refused, not applied.
    Nested(BTreeMap<String, RawTaskSpawn>),
}

/// The two shapes a task parameter accepts: the terse pattern string, or a table adding `enum` and
/// `default`. An untagged enum so both TOML forms parse.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawTaskParam {
    /// `sql = "^SELECT [A-Za-z ]+$"` — the pattern the value must match, anchored by the author.
    Pattern(String),
    /// `sql = { match = "...", default = "...", enum = ["a", "b"] }`.
    Table(RawTaskParamTable),
}

/// The table form of a task parameter: at most one of `match`/`enum` bounds the value, and
/// `default` makes it optional.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawTaskParamTable {
    /// A regular expression the whole value must match.
    #[serde(rename = "match")]
    pub(crate) pattern: Option<String>,
    /// The exact set of accepted values.
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) choices: Vec<String>,
    /// The value used when the caller supplies none, which also makes the parameter optional.
    pub(crate) default: Option<String>,
}

/// The two shapes a task credential accepts: the terse resolver ref (or terse key), or a table
/// adding `encode` and a description. An untagged enum so both TOML forms parse.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum RawTaskSecret {
    /// `PGPASSWORD = "sops://secrets.enc.yaml#db.password"`.
    Ref(String),
    /// `PGPASSWORD = { from = "...", encode = "base64" }`.
    Table(RawTaskSecretTable),
}

/// The table form of a task credential.
#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RawTaskSecretTable {
    /// A terse key expanded through `[secret.defaults]`, optionally pinned `key@resolver`.
    pub(crate) key: Option<String>,
    /// An explicit resolver ref, or a fallback chain tried in order.
    pub(crate) from: Option<SecretFrom>,
    /// How the resolved value is rendered into the variable: `raw` (the default), `base64`, `url`,
    /// or `json-string`. Every encoding registers its rendered form for substitution, so a value
    /// cannot reach a text sink in a spelling the redactor does not know.
    pub(crate) encode: Option<String>,
    /// A one-line description of the credential, for the inventory.
    pub(crate) description: Option<String>,
}

/// The two shapes a secret's `from` accepts: a single resolver ref string, or a list of refs
/// tried in order. An untagged enum so both TOML forms parse — `from = "env://VAR"` and
/// `from = ["env://VAR", "file:///p"]` — keeping the single-source case a one-liner.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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
// The table variant is far larger than the bare-string one, and deliberately so: this is a
// deserialization shape, built once per config layer and consumed immediately into the resolved
// view. Boxing it would add an indirection to every field read to save a stack copy that happens a
// handful of times per launch.
#[allow(clippy::large_enum_variant)]
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
    /// Log-suppression entries (SELinux `dontaudit`): a **denied** request matching one is still
    /// refused and still counted in `sbx net stats`, but its refusal is kept out of the default
    /// `sbx net log` view (`sbx net log --all` shows it). Same entry grammar as `allow`/`deny`
    /// (hosts, `*.domain`, exact URLs, `re:`, ports, `{VERB}` prefixes, `@group` references). A
    /// pure logging filter — it never changes a verdict. Trusted/global-only like the rest of the
    /// table.
    #[serde(default)]
    pub(crate) mute: Vec<String>,
    /// Hosts the egress proxy man-in-the-middles as **HTTP/2** (ALPN `h2`, for gRPC) instead of the
    /// default HTTP/1.1. Each entry is an exact hostname or a `*.domain` subdomain wildcard, with an
    /// optional port (`grpc.example.com` for any port, `grpc.example.com:443` for that port only,
    /// `*.example.com` for the apex and every subdomain — the same spoof-safe rule as an `allow`
    /// `*.domain`). Selecting HTTP/2 is orthogonal to the verdict — a host must still be permitted by
    /// an `allow` rule, and every gRPC stream is inspected and verdict-checked (method + `:path` =
    /// `/pkg.Service/Method`) exactly like the HTTP/1.1 path. Transport selection happens at
    /// CONNECT/ALPN time (host:port only, no path), so there is no `re:`/`host/path` form here; and
    /// because the designation is ALPN-h2-only, a wildcard covering a host the client speaks HTTP/1.1
    /// to will fail that host's handshake — prefer exact hosts unless every subdomain is gRPC/h2.
    /// Trusted/global-only like the rest of the table; a malformed entry is dropped with a warning
    /// (fail-closed — that host keeps HTTP/1.1).
    #[serde(default)]
    pub(crate) http2: Vec<String>,
    /// DNS cache TTL in seconds for the egress proxy's host-side resolver. The proxy resolves an
    /// allowed host once and reuses the address for this long, so a long build that fetches from one
    /// host (e.g. `cache.nixos.org`) thousands of times resolves it once instead of per request —
    /// robust against a transient resolver hiccup. Absent means the default (60); `0` disables the
    /// cache (resolve every request). Trusted/global-only like the rest of the table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dns_cache_ttl: Option<u64>,
    /// How much of each permitted exchange the egress proxy retains for `sbx net logs
    /// --with-headers`/`--with-body`: `"off"` (the default), `"headers"` (the request and response
    /// heads), or `"bodies"` (those plus a bounded prefix of each body). Never a verdict — a
    /// captured request was already allowed, and capturing changes nothing about what is. What it
    /// changes is how much plaintext the launch holds in memory, which is why it is
    /// trusted/global-only like the rest of the table: an untrusted project cannot start capturing
    /// its own traffic. An unknown level is dropped with a warning and the capture stays off
    /// (fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capture: Option<String>,
    /// The per-body capture cap in KiB, meaningful only with `capture = "bodies"` (it is ignored,
    /// with a warning, otherwise). Absent means the default (8); the value is clamped to the
    /// ceiling (1024) rather than refused, since asking for more retains fewer exchanges rather
    /// than more bytes. The head side has its own independent bound, so a header flood cannot eat
    /// the body budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) capture_max_kb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ask_timeout: Option<String>,
    /// Whether to print the `ask`-mode park notice to stderr when a request parks. On by default; a
    /// trusted layer may set `false` to silence the inline alert — the request still parks, answer it
    /// with `sbx net pending`. Inert outside `ask` mode. Absent means "inherit" — a layer that does
    /// not mention it does not change the inherited value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ask_notice: Option<bool>,
    /// Whether the egress proxy records its per-host decision counters (`sbx net stats`). On by
    /// default; a trusted layer may set `false` to turn the audit off (`true` re-enables it). Absent
    /// means "inherit" — a layer that does not mention it does not change the inherited value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) stats: Option<bool>,
    /// The HTTP verbs an **app's** unscoped (`{...}`-less) allow rules default to — its read-by-default
    /// posture. Only meaningful on an `[app.<name>.network]` (or an imported profile's `[network]`):
    /// every Mode-B app defaults to `["GET","HEAD"]` so an agent reads but does not write unless a
    /// rule opts a host out with `{*}`/`{VERB}`; this field overrides that default for the app (e.g.
    /// `["GET","POST"]`, or `["*"]` for all verbs). Ignored on the baseline `[network]` — `sbx run`
    /// (Mode A) stays all-verbs. Absent means the built-in `["GET","HEAD"]` app default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) default_methods: Option<Vec<String>>,
}

/// The two shapes the `proc` field accepts: a bare mode string, or a table for the exec-target
/// lists. An untagged enum so both TOML forms parse — `proc = "observe"` and
/// `[proc] mode = "enforce"` with `allow`/`deny` — keeping the simple case a one-liner. The string
/// case must come first for serde untagged to prefer it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum ProcField {
    /// `proc = "off"` | `"observe"` | `"enforce"` | `"ask"`.
    Mode(String),
    /// `[proc] mode = "<mode>"` with optional `allow`/`deny` exec-target lists.
    Table(ProcTable),
}

/// The table form of the `proc` field: a mode plus the exec-target lists. Under `enforce` a `deny`
/// target is blocked and everything else runs (a denylist); under `ask` a `deny` target is blocked,
/// an `allow` target runs, and an unmatched target parks. `deny` always wins. Each entry is a
/// shell-style glob matching the exec path (a rule with `/`) or its basename (a rule without) —
/// `curl`, `ssh`, `/usr/bin/*`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ProcTable {
    /// The exec mode. Absent means "inherit the mode from the parent config layer" while keeping this
    /// table's own `allow`/`deny` rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    #[serde(default)]
    pub(crate) deny: Vec<String>,
}

/// The two shapes the `notify` field accepts: a bare mode string, or a table for the per-event
/// settings. An untagged enum so both TOML forms parse — `notify = "off"` and `[notify] mode = "once"`
/// with `events` — keeping the simple case a one-liner. The string case must come first for serde
/// untagged to prefer it.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum NotifyField {
    /// `notify = "off"` | `"once"` | `"always"`.
    Mode(String),
    /// `[notify] mode = "<mode>"` with an optional `events` list or table.
    Table(NotifyTable),
}

/// The table form of the `notify` field: a mode for every event, plus an optional per-event `events`
/// refinement.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct NotifyTable {
    /// The mode every event takes unless `events` says otherwise. Absent means "inherit from the
    /// parent config layer" while keeping this table's own per-event settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) events: Option<NotifyEvents>,
    /// How long one problem stays quiet after being announced, as a duration (`"5m"`, `"90s"`,
    /// `"2h"`). Only meaningful under `always`: it turns "every occurrence" into "at most once per
    /// period, per problem", which is what keeps an agent looping for an hour from putting the same
    /// notification back in front of you every few seconds. Absent (or `"0"`) means every occurrence
    /// is announced, and `once` ignores it — that mode never repeats at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) repeat_after: Option<String>,
}

/// The two shapes `events` accepts, an untagged enum so both TOML forms parse.
///
/// A list (`events = ["network", "proc"]`) is an **inclusion**: the named events take the table's
/// mode and every other event is silenced — the short way to say "only tell me about these". A table
/// (`[notify.events] network = "always"`) sets a mode per event and leaves the unnamed ones on the
/// table's mode, which is how one noisy lens is turned down without touching the rest.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub(crate) enum NotifyEvents {
    /// `events = ["network", "proc"]` — these only, at the table's mode.
    List(Vec<String>),
    /// `[notify.events] network = "always"` — a mode per named event.
    Map(BTreeMap<String, String>),
}

/// How deep [`locate_type_error`] will go looking for the key at fault. Three levels reach a
/// `[task.<name>].<field>` and an `[app.<name>].<field>`, which is as nested as this schema gets.
const LOCATE_DEPTH: usize = 3;

/// The most keys [`locate_type_error`] will test at one level. The search re-parses the document
/// once per candidate, so this bounds the work on a large config; a document wider than this simply
/// keeps the original message.
const LOCATE_MAX_KEYS: usize = 128;

/// Point at the key a *type* error came from, which the parser's own span does not.
///
/// `toml` reports a value nested inside a map against the map's **own** key: a `packages` written
/// as a table under `[task.deploy]` is blamed on `task`, whose header may be sections away from the
/// mistake — and since a failed parse drops the whole file, the reader is left with a caret on a
/// line that is perfectly correct. The document is syntactically valid (only a type is wrong), so
/// the offending key can be found by **elimination**: remove one candidate at a time and re-parse;
/// the one whose removal makes the document load is the culprit. Removal rather than isolation
/// because a sibling may be *required* — deserializing `{task.deploy.packages}` alone would fail on
/// the missing `cmd` and frame the wrong key.
///
/// Returns the dotted path and, when the document still carries its spans, the line it is written
/// on. Gives up quietly — a document with two errors is never fixed by removing one key, and a
/// guess is worse than the parser's own message.
fn locate_type_error<T: serde::de::DeserializeOwned>(
    text: &str,
) -> Option<(String, Option<usize>)> {
    let doc: toml_edit::DocumentMut = text.parse().ok()?;
    let mut path: Vec<String> = Vec::new();

    for _ in 0..LOCATE_DEPTH {
        let keys = keys_at(&doc, &path)?;
        if keys.len() > LOCATE_MAX_KEYS {
            return None;
        }
        let culprit = keys.into_iter().find(|key| {
            let mut trial = doc.clone();
            remove_at(&mut trial, &path, key) && toml::from_str::<T>(&trial.to_string()).is_ok()
        })?;
        path.push(culprit);
        // Descend only while the blamed value is itself a table: once it is a scalar or an array,
        // it *is* the mistake and there is nothing finer to name.
        if keys_at(&doc, &path).is_none() {
            break;
        }
    }

    Some((path.join("."), line_of(text, &path)))
}

/// The keys of the table at `path`, or `None` when the path does not lead to one.
fn keys_at(doc: &toml_edit::DocumentMut, path: &[String]) -> Option<Vec<String>> {
    let mut table = doc.as_table() as &dyn toml_edit::TableLike;
    for step in path {
        table = table.get(step)?.as_table_like()?;
    }
    Some(table.iter().map(|(k, _)| k.to_string()).collect())
}

/// Remove `key` from the table at `path`. False when the path or the key is not there.
fn remove_at(doc: &mut toml_edit::DocumentMut, path: &[String], key: &str) -> bool {
    let mut table = doc.as_table_mut() as &mut dyn toml_edit::TableLike;
    for step in path {
        match table
            .get_mut(step)
            .and_then(|item| item.as_table_like_mut())
        {
            Some(next) => table = next,
            None => return false,
        }
    }
    table.remove(key).is_some()
}

/// The 1-based line `path` is written on, read from a span-preserving parse of the same text.
fn line_of(text: &str, path: &[String]) -> Option<usize> {
    let doc = toml_edit::ImDocument::parse(text).ok()?;
    let mut item = doc.as_item();
    for step in path {
        item = item.as_table_like()?.get(step)?;
    }
    let start = item.span()?.start;
    Some(text.get(..start)?.matches('\n').count() + 1)
}

/// Append the located key to a parse error, when one can be found.
fn with_location<T: serde::de::DeserializeOwned>(text: &str, message: String) -> String {
    match locate_type_error::<T>(text) {
        Some((path, Some(line))) => {
            format!("{message}\n  --> the value at `{path}` (line {line}) is the one at fault")
        }
        Some((path, None)) => {
            format!("{message}\n  --> the value at `{path}` is the one at fault")
        }
        None => message,
    }
}

/// Parse config bytes as TOML. The error is a human-readable string: the loader
/// turns it into a warning and ignores the layer rather than aborting a command,
/// so a malformed config never wedges the sandbox.
pub(crate) fn parse(bytes: &[u8]) -> Result<RawConfig, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    toml::from_str(text).map_err(|e| with_location::<RawConfig>(text, e.to_string()))
}

/// Serialize an app as a top-level profile — the inverse of [`parse_app`], producing the portable
/// file `sbx app export` writes. Empty `env`/`binds`/`packages` are skipped (the field attributes),
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
    toml::from_str(text).map_err(|e| with_location::<RawApp>(text, e.to_string()))
}

#[cfg(test)]
mod locating {
    use super::*;

    /// The case this exists for, taken from a real mistake: a task's `packages` is a **list** of
    /// `mise:` entries, and writing it as a table makes the parser blame `task` — whose header can
    /// be sections away — while the whole file is dropped on it.
    #[test]
    fn a_type_error_inside_a_named_table_names_the_field_not_the_section() {
        let text = "\
[env]
A = \"b\"

[task.deploy]
cmd = [\"sshpass\", \"-e\", \"ssh\"]

[task.deploy.packages]
sshpass = \"nix:sshpass\"
";
        let err = parse(text.as_bytes()).unwrap_err();
        assert!(
            err.contains("`task.deploy.packages`"),
            "the field at fault must be named: {err}"
        );
        assert!(err.contains("line 7"), "and pointed at its own line: {err}");
        // The parser's own message survives; the location is added, never substituted.
        assert!(
            err.contains("invalid type: map, expected a sequence"),
            "{err}"
        );
    }

    /// A direct field already has a good span, and the located path must agree with it rather than
    /// wander off into a neighbour.
    #[test]
    fn a_top_level_field_locates_to_itself() {
        let err = parse(b"network = 42\n").unwrap_err();
        assert!(err.contains("`network`"), "{err}");
    }

    /// Two mistakes cannot be found by removing one key, so the search gives up and the reader
    /// keeps the parser's own message — a guess would be worse than none.
    #[test]
    fn two_errors_leave_the_original_message_alone() {
        let text = "network = 42\ngui = 7\n";
        let err = parse(text.as_bytes()).unwrap_err();
        assert!(!err.contains("is the one at fault"), "{err}");
    }

    /// A syntax error is not a type error: nothing is located, because the document cannot even be
    /// read as a tree to search.
    #[test]
    fn a_syntax_error_is_left_as_it_is() {
        let err = parse(b"[task.deploy\ncmd = 1\n").unwrap_err();
        assert!(!err.contains("is the one at fault"), "{err}");
    }

    /// The same treatment reaches an imported app profile, whose fields are the app's own.
    #[test]
    fn an_app_profile_locates_its_own_field() {
        let text = "cmd = [\"demo\"]\n\n[packages]\nx = 1\n";
        let err = parse_app(text.as_bytes()).unwrap_err();
        assert!(err.contains("`packages.x`"), "{err}");
    }
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
        // `serialize_app` is the inverse of `parse_app` — what `sbx app export` writes must
        // re-import identically. Covers the fragile corners: `#[serde(flatten)]` secret hosts
        // (with a `defaults` table and an array-of-tables host), the untagged `cmd`/`network`/
        // `from` enums, and the `use` array. The `use` placement assertion below pins a property
        // of the OUTPUT, not of the struct: an array is a *value*, and a value written under a
        // `[table]` header parses as a key of that table (so a hand-written `use` in the wrong
        // place is silently dropped) — this proves export never emits that shape. The serializer
        // hoists values ahead of tables on its own, so field order in `RawApp` does not control
        // it and moving `uses` there does not fail here; measured, not assumed.
        let src = br#"
            cmd = ["demo-app", "--resume"]
            use = ["demo-bundle", "shared-egress"]
            home_scope = "global"
            gui = "wayland"
            binds = ["/opt/data"]
            [env]
            FOO = "bar"
            [packages]
            demo-tool = "mise:aqua:example/demo-tool"
            demo-app = "tarball:manifest"
            [flakes.inline-tool]
            attr = "default"
            flake = '''
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: {
    packages.x86_64-linux.default = nixpkgs.legacyPackages.x86_64-linux.hello;
  };
}
'''
            [tarball.demo-app]
            resolve = ["sh", "-c", "curl -s https://api.example.com/releases | sed -n 1p"]
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
        // The inline flake parses with its multiline `'''…'''` source and explicit attribute.
        let flake = app
            .flakes
            .get("inline-tool")
            .expect("the [flakes] table parses");
        assert_eq!(flake.attr.as_deref(), Some("default"));
        assert!(flake.flake.contains("packages.x86_64-linux.default"));
        // The `[tarball.<name>]` auto-upgrade table parses (its `resolve` command argv).
        let tb = app
            .tarball
            .get("demo-app")
            .expect("the [tarball] table parses");
        assert_eq!(tb.resolve.first().map(String::as_str), Some("sh"));
        assert!(tb.resolve.iter().any(|a| a.contains("curl")));
        // The bundle references parse in declaration order (the order the fold applies them).
        assert_eq!(app.uses, vec!["demo-bundle", "shared-egress"]);
        let serialized = serialize_app(&app).unwrap();
        // …and are emitted ahead of every table header, so re-parsing finds them at the top level
        // rather than inside the last table opened. A table header is a `[` at the start of a
        // line — not the `[` that opens the `use` array itself.
        let line_of =
            |pred: &dyn Fn(&str) -> bool| serialized.lines().position(pred).unwrap_or(usize::MAX);
        let use_line = line_of(&|l: &str| l.trim_start().starts_with("use = "));
        let first_table = line_of(&|l: &str| l.starts_with('['));
        assert!(
            use_line < first_table,
            "`use` must serialize before the first table header, got:\n{serialized}"
        );
        let reparsed = parse_app(serialized.as_bytes()).unwrap();
        // A multiline flake source may re-emit escaped through `toml::to_string`; the round-trip is
        // on the parsed value, so this proves export→import preserves the flake byte-for-byte.
        assert_eq!(app, reparsed, "export must round-trip losslessly");
    }

    /// An exec node's unknown key is refused at load, but the profile holding it still has to be
    /// **writable**: `sbx app export` serializes what was parsed, before any validation. TOML has no
    /// unit, so a unit here failed the whole export with "unsupported unit type" — an error naming
    /// neither the app nor the key.
    #[test]
    fn an_unknown_key_in_an_exec_node_still_exports() {
        let app = parse_app(
            b"cmd = \"demo\"\n\
              [task.t]\ncmd = [\"tool\"]\nspawn = [\"git\"]\n\
              [task.t.exec.git]\nspawn = [\"ssh\"]\nbogus = { a = 1 }\n",
        )
        .unwrap();
        let out = serialize_app(&app).expect("a parsed profile must be writable");
        assert!(out.contains("bogus"), "the key stays visible, got:\n{out}");
        assert_eq!(
            parse_app(out.as_bytes()).unwrap(),
            app,
            "and what was written parses back to what was read"
        );
    }

    #[test]
    fn the_dbus_bool_round_trips_and_the_removed_string_form_is_rejected() {
        // `dbus` is a plain bool (`true` = the in-cage portal). `sbx app export` must round-trip it.
        let app = parse_app(b"cmd = \"demo\"\ndbus = true\n").unwrap();
        assert_eq!(app.dbus, Some(true));
        let out = serialize_app(&app).unwrap();
        assert!(
            out.contains("dbus = true"),
            "the bool posture must serialize as a bool, got:\n{out}"
        );
        assert_eq!(parse_app(out.as_bytes()).unwrap(), app);

        // The former `dbus = "incage"` string form is gone: a stale string must fail LOUDLY (the
        // whole profile is rejected), never silently drop to `dbus = false` (no portal). Re-import
        // the shipped profiles after this cutover.
        assert!(
            parse_app(b"cmd = \"demo\"\ndbus = \"incage\"\n").is_err(),
            "a stale `dbus = \\\"incage\\\"` must be rejected, not silently dropped to no-portal"
        );
    }

    #[test]
    fn a_mode_less_network_table_round_trips_without_a_mode_line() {
        // `sbx app export` of a profile that inherits its mode must not materialize a `mode` line —
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
                mute: vec![],
                http2: vec![],
                capture: None,
                capture_max_kb: None,
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
                dns_cache_ttl: None,
            }))
        );
    }

    #[test]
    fn a_network_table_without_allow_or_deny_defaults_to_empty() {
        let cfg = parse(b"[network]\nmode = \"deny\"\n").unwrap();
        assert_eq!(
            cfg.network,
            Some(NetworkField::Table(NetworkTable {
                mute: vec![],
                http2: vec![],
                capture: None,
                capture_max_kb: None,
                mode: Some("deny".into()),
                allow: vec![],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
                dns_cache_ttl: None,
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
                mute: vec![],
                http2: vec![],
                capture: None,
                capture_max_kb: None,
                mode: None,
                allow: vec!["api.foo.com".into()],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
                dns_cache_ttl: None,
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
        // sbx field still loads on an older sbx. `[network]` must not break that: `NetworkField` is
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
        // a field a newer sbx understands must not break an older one
        let cfg = parse(b"some_future_field = 42\n[env]\nA = \"1\"\n").unwrap();
        assert_eq!(cfg.env.get("A").map(String::as_str), Some("1"));
    }

    #[test]
    fn malformed_toml_is_a_readable_error() {
        let err = parse(b"this is = = not toml").unwrap_err();
        assert!(!err.is_empty());
    }
}
