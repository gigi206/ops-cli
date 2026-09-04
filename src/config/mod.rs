//! Project and global configuration: parse, layer the global and project files,
//! and gate the project's security-relevant fields by its trust.
//!
//! A config file is attacker-controlled the moment you `cd` into a cloned repo,
//! so reading one is itself a security operation. [`safety`] refuses any file that
//! is not a plain, owner-owned, non-world-writable regular file before its bytes
//! are ever acted on; the trust gate then decides whether the project's
//! security-relevant fields apply at all.
//!
//! The layering and gating ([`resolve`]) are pure — they turn already-read configs
//! and an already-decided trust verdict into the resolved set of environment and
//! binds — so the whole policy matrix is unit-testable without touching the
//! filesystem. [`load()`] is the thin I/O around it, and is the one place that ties
//! a project's bytes, its trust verdict, and its parse together so all three act
//! on the same inode.

mod apps;
pub(crate) mod fspolicy;
mod gate;
mod load;
pub(crate) mod manage;
pub(crate) mod overrides;
pub(crate) mod safety;
pub(crate) mod schema;
mod secrets;
pub(crate) mod tasks;
mod tools;
mod types;
mod validate;
pub(crate) mod view;

pub(crate) use types::*;

pub(crate) use apps::{AppHomeScope, ResolvedApp, is_valid_app_name};
pub(crate) use gate::{is_trust_drop, untrusted_reason};
pub(crate) use load::{
    Source, bundles, control_plane_pins, export_profile, is_valid_bundle_name, load, load_scoped,
    net_groups, profile_path, profiles_dir, read_bundle_fragment, read_net_groups_fragment,
    validate_profile,
};
pub(crate) use overrides::{CliOverrides, Override};
pub(crate) use schema::RawBundle;
/// The command form a bundle's install step is written in. Named here only where a test
/// constructs one; the renderer reaches it through [`schema::RawCmd::into_argv`].
#[cfg(test)]
pub(crate) use schema::RawCmd;
/// One `[<backend>.<name>]` table: the `resolve` command a roll re-runs, the extra library
/// attributes a build patches against, or both. Reached by name from the `bundle` renderer, which
/// reports the two halves apart because a table may carry either.
pub(crate) use schema::RawResolve;
// The locator grammar, reached from the fetching backends and the store as `crate::config::…`:
// every URL a backend derives is re-validated through the same predicate the declaration passed.
pub(crate) use tools::{
    is_bare_nix_attr, is_valid_appimage_url, is_valid_attr, is_valid_binary_url, is_valid_deb_url,
    is_valid_tarball_url,
};
// The per-app overlay engine, which the resolution engine drives once per resolution.
use apps::resolve_apps;
// The gate the resolution engine routes every security-relevant field through, and the two
// refusal sentences it does not phrase itself.
use gate::{Gate, dropped_binds_warning, refuse_untrusted};
// The declared-tool folds the resolution engine drives, one per layer it reads.
use tools::{
    apply_fresh_releases, apply_packages, apply_tools, upsert_package, warn_mise_nix_packages,
};
// The built-in app default a cross-cutting config unit test holds a resolved app layer against.
#[cfg(test)]
use apps::builtin_app_default_methods;
// Reached directly by the (cross-cutting) config unit tests, which exercise the declared-tool folds
// and the locator grammar a layer below the resolution engine that normally calls them.
#[cfg(test)]
use tools::{
    APPIMAGE_RESOLVE_SENTINEL, DEB_RESOLVE_SENTINEL, TARBALL_RESOLVE_SENTINEL, apply_flakes,
    apply_resolvers, is_valid_deb_apt_locator, is_valid_deb_github_locator, is_valid_mise_token,
    is_valid_package_name, parse_backend,
};
// Consumed by the resolution engine that stays in this file (and `global_path` by `manage`).
use load::{canonicalize_binds, global_path, read_global, sbx_control_plane_roots};
// The secret source/validation machinery the resolution engine folds into the resolved set.
use secrets::{
    SecretDefaults, apply_secret_section, count_host_secrets, upsert_secret, warn_resolver_bindings,
};
// The two leaf checks the task engine re-runs at invocation time: a caller's value against its
// declared bound, and the `{param}` placeholders in one argv element. They live with the validator
// so the check a task is accepted under and the check its invocation enforces cannot drift.
pub(crate) use tasks::check_value;
// Leaf secret validators the (cross-cutting) config unit tests exercise directly; the resolution
// engine reaches them only through `apply_secret_section`.
#[cfg(test)]
use secrets::{validate_header_shape, validate_host_secret, validate_secret_target};
use validate::{
    validate_device_path, validate_distro, validate_forward, validate_gui, validate_home_scope,
    validate_limits, validate_mise_engine, validate_network, validate_network_amending,
    validate_nixpkgs, validate_notify, validate_open, validate_proc, validate_redact_min_len,
    validate_service, validate_timezone,
};
// Exercised by a cross-cutting config unit test (profile merge + the shared `raw_app` builders).
#[cfg(test)]
use load::merge_profile_apps;

use crate::allowlist::{Layer, Methods, Rule, RuleKind, Slot};
use crate::plugins::PluginRegistry;
use crate::trust::{self, TrustState};
use fspolicy::FsPolicy;
use schema::{
    NetworkField, NetworkTable, RawApp, RawBind, RawConfig, RawHostSecret, RawHostSecrets,
    RawInlineFlake, RawSecretDefaults, RawTask, RawTaskDefaults, RawTaskParam, RawTaskSecret,
    RawTaskSection, SecretFrom,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// The global config file name, under `…/sbx/`.
const GLOBAL_CONFIG: &str = "sbx.toml";
/// The project config file name, in the project root.
pub(crate) const PROJECT_CONFIG: &str = ".sbx.toml";
/// The source label a one-shot override's warnings carry, so a dropped/malformed override field
/// reads as `override: …` rather than as coming from a config file.
const OVERRIDE_SOURCE: &str = "override";
/// The directory of imported app profiles, beside the global config (`…/sbx/apps/`). A profile
/// is a standalone TOML file (a top-level [`schema::RawApp`]) whose *filename* is the app name;
/// it is trusted by location, exactly like the global config, so its apps join the global app
/// layer. (Note: under the *config* root this `apps` directory holds profiles, while under the
/// *data* root an `apps` directory holds each app's persistent home — two distinct trees.)
const PROFILES_DIR: &str = "apps";

/// Environment keys an *untrusted or changed* project may not set. The point is
/// not to contain the agent — in Mode B it already runs arbitrary code inside the
/// cage, so a config-set `LD_PRELOAD` grants it nothing new. It is to stop an
/// untrusted project from silently reconfiguring the *execution environment* of
/// the user's own later (Mode A) sessions and the trusted tools they run in that
/// project. So the list mirrors what glibc itself strips under `AT_SECURE`, for
/// exactly this threat: the dynamic loader (`LD_*`), the libraries that iconv /
/// locale / the resolver load by path (`GCONV_PATH`, `LOCPATH`, `NLSPATH`,
/// `RESOLV_HOST_CONF`, `HOSTALIASES`), glibc's tunables (`GLIBC_TUNABLES`), and
/// the shell startup hooks (`BASH_ENV`, `ENV`, `IFS`); plus the structural
/// userland sbx owns (`HOME`, `PATH`) and the loader the sandbox routes foreign
/// binaries through (`NIX_LD`, `NIX_LD_LIBRARY_PATH` — the same `AT_SECURE` concern
/// as `LD_*`, since they steer what code a foreign binary loads). A trusted config
/// is exempt — vouching for it honors the whole schema, and overriding these harms
/// only its own sandbox.
///
/// The cage carries a nix the agent self-equips with, so the three variables that
/// inject nix configuration (`NIX_CONFIG` inline, `NIX_USER_CONF_FILES` and
/// `NIX_CONF_DIR` pointing at config files) join the list: an untrusted project
/// could otherwise aim the *user's* later Mode-A nix at an attacker's substituter
/// with `require-sigs` off, serving backdoored binaries. In-cage this is not an
/// escalation (the agent already runs arbitrary code), but the same Mode-A
/// protection applies, so it is closed for symmetry — completely, since a single
/// missed pointer leaves the hole open.
///
/// Under a network allowlist the cage's only egress is the sbx-managed filtering
/// proxy (Model B): the proxy-control variables (`http_proxy`/`https_proxy`/
/// `all_proxy`/`no_proxy`, either case) and the CA-bundle variables the cage trusts
/// sbx's per-session CA through ([`crate::sandbox::egress::CA_FILE_ENV_KEYS`]) are
/// reserved for the same reason. In-cage a redirected proxy or a swapped CA only
/// fails closed (empty netns, sbx-minted certs), but the same Mode-A protection as
/// `NIX_CONFIG` applies, and the keys sbx *sets* are exactly the keys it protects.
///
/// Also the barrier a broker plugin's `cage_env` passes, so the list of names that load code in
/// the cage is written once and both callers refuse exactly the same set.
///
/// Finally the whole `SBX_*` prefix, which is sbx's own control namespace rather than any one
/// variable: everything [`overrides`] reads from the ambient environment lives under it, and so do
/// the few names sbx sets into a cage. Reserved as a prefix because a per-name list has to be
/// extended for every control variable added later and one missed name is the whole hole.
pub(crate) fn is_reserved_env_key(key: &str) -> bool {
    key.starts_with("LD_")
        || is_proxy_env_key(key)
        // The CA-bundle keys are matched case-insensitively: env names are case-sensitive, but a
        // nonstandard tool reading a lowercase variant must not slip a swapped CA past the gate.
        || crate::sandbox::egress::CA_FILE_ENV_KEYS
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
        || matches!(
            key,
            "HOME"
                | "PATH"
                | "NIX_LD"
                | "NIX_LD_LIBRARY_PATH"
                | "NIX_CONFIG"
                | "NIX_USER_CONF_FILES"
                | "NIX_CONF_DIR"
                | "BASH_ENV"
                | "ENV"
                // Interactive-shell code-exec hooks: bash runs `PROMPT_COMMAND` before each prompt
                // and evaluates `$(...)` in `PS1`, so an untrusted `[env]` setting them would run
                // code in the user's later Mode-A interactive `sbx run`, exactly like `BASH_ENV`/`ENV`.
                | "PROMPT_COMMAND"
                | "PS1"
                | "IFS"
                | "GCONV_PATH"
                | "GLIBC_TUNABLES"
                | "LOCPATH"
                | "NLSPATH"
                | "RESOLV_HOST_CONF"
                | "HOSTALIASES"
                // GPU driver-load paths: mesa's libgbm/libEGL `dlopen` a `<driver>_dri.so` / gbm
                // backend from these, so — like `LD_*`/`NIX_LD` — an untrusted `[env]` could aim a
                // trusted GPU-enabled app's mesa at an attacker `.so` in the project tree and run
                // code in the app's cage. Data-redirection vars (`FONTCONFIG_FILE`) stay free; these
                // are code-load paths. sbx sets them for `gpu = true`; a trusted config still may.
                | "LIBGL_DRIVERS_PATH"
                | "GBM_BACKENDS_PATH"
                | "__EGL_VENDOR_LIBRARY_DIRS"
                // The same shape, one indirection further out: each of these names a *manifest*
                // (a small JSON) whose whole content is the path of a library to `dlopen`. Aiming
                // one at a project-shipped manifest is aiming the loader at a project-shipped
                // `.so`, so they belong in this group and not among the data paths. sbx sets them
                // for `gpu = true` where the host has an NVIDIA driver.
                | "__EGL_EXTERNAL_PLATFORM_CONFIG_DIRS"
                | "VK_DRIVER_FILES"
                | "VK_ADD_DRIVER_FILES"
                | "VK_ICD_FILENAMES"
                | "VK_LAYER_PATH"
                | "VK_ADD_LAYER_PATH"
                // Interpreter pre-load hooks, the same shape as `BASH_ENV`/`ENV` above: each names
                // a file the interpreter runs before the program, so an untrusted `[env]` setting
                // one runs code in the user's later `sbx run` without needing a prompt or a shell
                // startup at all. `config/tasks.rs` already refuses these for a task; the reason
                // it gives there — that the command is sbx's choice — holds here too.
                | "NODE_OPTIONS"
                | "PYTHONSTARTUP"
                | "PERL5OPT"
                | "RUBYOPT"
                // The two XDG base directories the in-cage portal resolves a URI scheme through.
                // `sandbox::openuri` freezes the OpenURI route by binding the generated desktop
                // entry and `mimeapps.list` read-only at the locations the XDG lookup prefers, and
                // that only outranks everything else while these stay unset: setting either points
                // the lookup at a directory the project ships, whose `.desktop` then answers a
                // sign-in click the *user* made. The cage's `--clearenv` and its three-name
                // passthrough already keep the host's values out; what they do not cover is an
                // untrusted `[env]`, which is this denylist's half of the same question.
                | "XDG_DATA_HOME"
                | "XDG_CONFIG_HOME"
        )
        // Exported shell functions, whole. bash runs `BASH_FUNC_<name>%%` definitions when it
        // starts, so this is `BASH_ENV`'s hole without the file: a prefix, because the name half
        // is the attacker's to choose and reserving one spelling at a time cannot keep up.
        || key.starts_with("BASH_FUNC_")
        // sbx's own namespace, whole. The rule above is that the keys sbx sets are the keys it
        // protects, and `SBX_*` is the larger half of that: sbx *reads* this prefix as its override
        // channel (`SBX_NET`, `SBX_BIND`, `SBX_SECCOMP`, `SBX_CONFIG`, `SBX_ENV_<name>`, …, see
        // [`overrides`]) and *sets* parts of it into the cage (`SBX_SANDBOX`,
        // `SBX_UPGRADE`, `SBX_TASK_CLI`). Reserving one name at a time would have to be redone
        // for every control variable added later, and a single missed one is the whole hole; the
        // prefix cannot fall behind. `SBX_UPGRADE` is the concrete case that motivated it: set, it
        // tells a bundle's install step to re-install rather than honor its own "already there"
        // guard, so an untrusted project could turn every launch into a re-download.
        //
        // A prefix, not a substring: `TRAE_SBX_UPDATE` and `HERMES_WEBUI_SBX_GATEWAY` are an app's
        // own variables and stay free.
        || key.starts_with("SBX_")
}

/// The proxy-control variables, matched case-insensitively (tools honor both
/// `http_proxy` and `HTTP_PROXY`). `no_proxy`/`all_proxy` and the WebSocket variants
/// (`ws_proxy`/`wss_proxy`, which sbx sets so a WS client routes through the proxy too)
/// are reserved alongside the HTTP ones, so an untrusted project can neither redirect the
/// cage's egress nor carve a hole around it.
fn is_proxy_env_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy" | "ws_proxy" | "wss_proxy"
    )
}

/// Where a broker's host resource lives: a Unix socket on this machine, or a TCP endpoint.
///
/// A TCP target is a **way out of the cage**, unlike a Unix socket, so it is admitted only where
/// the network allowlist already admits it. Without that there would be two different answers to
/// "where may this cage go", and the one a reader checks (`[network]`) would not be the one that
/// decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BrokerTarget {
    /// A Unix socket path on this machine.
    Unix(PathBuf),
    /// A TCP endpoint, subject to the egress allowlist.
    Tcp { host: String, port: u16 },
}

impl BrokerTarget {
    /// How the target is shown in a note, a warning, or `sbx config`.
    pub(crate) fn describe(&self) -> String {
        match self {
            BrokerTarget::Unix(path) => path.display().to_string(),
            BrokerTarget::Tcp { host, port } => format!("tcp://{host}:{port}"),
        }
    }
}

/// One broker plugin's binding: the host resource it stands in front of, and the policy it
/// brokers under.
///
/// The two halves come from different layers on purpose. `socket` is a fact about the machine and
/// is read from the global config alone; `allow` is a fact about the work and a trusted project
/// may set it. A project that could name the socket would be choosing which host resource a plugin
/// is put in front of, which is the one decision that must sit beside the plugin's installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrokerBinding {
    /// The installed broker plugin's name, which is the table's key.
    pub(crate) name: String,
    /// The host resource sbx connects to and holds the connection to.
    pub(crate) socket: BrokerTarget,
    /// The policy, passed to the plugin verbatim at the start of every connection.
    pub(crate) allow: Vec<String>,
    /// Where the credential this broker places comes from, when the global config named one and
    /// the plugin's manifest declares `uses_secret`. Resolved host-side at launch; the plugin is
    /// handed a marker, never the value.
    pub(crate) secret: Vec<SecretSource>,
    /// What this host supplies the broker plugin, from `[plugin.<name>]`, validated against the
    /// plugin's own manifest.
    ///
    /// Carried on the binding rather than set on the registry's plugin, because the registry is
    /// shared and read-only by the time a config is resolved: the launch takes the plugin by name
    /// and applies this to its own copy. Empty unless a table names it.
    pub(crate) host: crate::plugins::HostConfig,
    /// Which layer supplied the policy, for `sbx config`.
    pub(crate) origin: Provenance,
}

/// The resolved configuration the launcher applies: the layered environment and
/// the host binds, the declared tools, plus any warnings worth surfacing
/// (dropped fields, an unparseable or unsafe file). Nothing here is a hard error —
/// a missing or broken config yields empty defaults, never a failed launch.
#[derive(Clone)]
pub(crate) struct Resolved {
    /// Extra environment, in application order; a later entry overrides an earlier
    /// one at the same key.
    pub(crate) env: Vec<(String, String)>,
    /// Which layer each `env` key's winning value came from. Keyed by the env key (stable, so
    /// the lookup matches what `env` lists). A display affordance for `sbx config`; only the
    /// baseline resolution records it (an app overlay does not), and the launcher ignores it.
    pub(crate) env_layer: BTreeMap<String, Provenance>,
    /// Extra host paths to bind, each read-only or read-write.
    pub(crate) binds: Vec<Bind>,
    /// Which layer each effective bind came from, keyed by the *canonical* path `binds`
    /// lists (re-keyed after canonicalization in [`load()`], so the lookup matches the displayed
    /// path). A display affordance for `sbx config`, recorded only at the baseline.
    pub(crate) bind_layer: BTreeMap<PathBuf, Provenance>,
    /// Declared tools, in declaration order, each tagged with its source's trust.
    ///
    /// Admission (and the nix work it implies) is the launcher's, not decided here.
    pub(crate) packages: Vec<Package>,
    /// Packages whose vendor publishes faster than a freshness delay tolerates, named by a trusted
    /// layer so their equip and their roll accept a release with no cooling-off period. Package
    /// names, deduplicated, in declaration order; see [`schema::RawConfig::accepts_fresh_releases`]
    /// for what the delay is and why lifting it is a trade.
    pub(crate) accepts_fresh_releases: Vec<String>,
    /// Per-plugin settings for the installed resolver plugins, keyed by plugin name: where to get
    /// a program the manifest declares when `PATH` does not have it, and values for the variables
    /// it reads. Layered global-under-project and gated by trust, like `[packages]`.
    pub(crate) plugin: BTreeMap<String, crate::config::schema::RawPluginConfig>,
    /// What the cage opens a URI with, keyed by URI scheme. Layered global-under-project and gated
    /// by trust, like `[packages]` — a project that could declare one would decide what runs when a
    /// person clicks a sign-in link.
    pub(crate) open: BTreeMap<String, OpenHandler>,
    /// Auxiliary processes to start in the cage before its command, keyed by service name. Layered
    /// global-under-project and gated by trust, like `[packages]` — an entry runs a program of its
    /// choosing at every launch, which is the grant an untrusted project is refused for `cmd`.
    pub(crate) service: BTreeMap<String, ServiceSpec>,
    /// The install steps the launched app's bundles carry, in `use` order — empty for a project run.
    ///
    /// Held here, rather than read off the app and composed on the spot, so that the one function
    /// which stands up a cage composes the whole start-up in one place and in one order: install
    /// first, then services, then the command. Composed apart, the two wrappers nest, and which one
    /// ends up inside depends on the order the call sites happen to run in.
    pub(crate) provisions: Vec<BundleProvision>,
    /// The global config's `nixpkgs` override (trusted by location), or `None` for
    /// the default channel. Drives the base userland and is the default source for a
    /// project's tools.
    pub(crate) nixpkgs_global: Option<String>,
    /// The source the **mise engine** tracks, from the global `[mise] engine`. `None` follows
    /// [`Resolved::nixpkgs_global`], which is what happened before the field existed.
    ///
    /// The engine's revision was already pinned in a lock of its own (`store::channel`), so the
    /// engine and the base userland already rolled forward separately; this is the source half of
    /// that separation, and it is what lets the engine track something the base userland does not
    /// — a frozen nixpkgs, or a flake that is not nixpkgs at all.
    pub(crate) mise_engine: Option<String>,
    /// A trusted project's `nixpkgs` override, or `None`. Pins *this project's* tools
    /// to its own source; an untrusted or changed project's value is dropped (it is a
    /// supply-chain-relevant choice), so this is never set from one.
    pub(crate) nixpkgs_project: Option<String>,
    /// The project's mise file, when one is present beside a `.sbx.toml`. Its tools
    /// are resolved (trusted-only) by a later stage; here it records the file's
    /// presence and the gating verdict. Discovered in [`load()`] (it is I/O), so the
    /// pure [`resolve`] always leaves it `None`.
    pub(crate) mise: Option<MiseConfig>,
    /// The project's mise files that sbx declared inert — present, but with no `.sbx.toml` to
    /// anchor them, so nothing here is folded into the resolved configuration.
    ///
    /// Kept because saying a file is ignored does not make it so. The project tree is bound into
    /// the cage at its real path, and mise walks the working directory on every invocation, so
    /// the cage's own mise would find these files and act on them — resolving their tools, and
    /// reaching for the network to do it — while sbx reported them ignored. The launcher names
    /// them to mise (`MISE_IGNORED_CONFIG_PATHS`) so the verdict holds on both sides of the cage
    /// wall. Discovered in [`load()`] (it is I/O), so the pure [`resolve`] always leaves it empty.
    pub(crate) mise_ignored: Vec<std::path::PathBuf>,
    /// The resolved network posture: [`NetworkPolicy`]'s built-in default — the deny-by-default
    /// filtering allowlist, which reaches only the proxy's self-equip set — unless the global
    /// config or a trusted project declared one of its own (`none`, `shared`, or one of the
    /// filtering modes). An untrusted project's choice is dropped with a warning: it may neither
    /// narrow nor widen the network.
    pub(crate) network: NetworkPolicy,
    /// Which layer supplied the winning `network` posture (`Default` when neither config set it).
    /// A display affordance for `sbx config`; the launcher ignores it.
    pub(crate) network_origin: Provenance,
    /// The egress groups the global config declared, pre-classified, as the vocabulary a `@<name>`
    /// reference resolves against. Kept on the resolved config for one reason: a one-shot override
    /// is applied *after* layering, and it references groups too. The names come from the global
    /// config either way, so an override gains no reach by using one — it could always have written
    /// the same hosts out by hand — it gains the ability to say them by the name the config already
    /// uses, which is what keeps a launch line auditable against the policy it is bending.
    pub(crate) net_groups: NetGroups,
    /// Whether the egress proxy records its per-host decision counters (`sbx net stats`). On by
    /// default; a trusted layer's `[network] stats = false` turns the audit off. Gated like the
    /// rest of `[network]` — an untrusted project's table (and so its `stats`) is dropped, so it
    /// cannot disable the auditing of its own egress. Baseline-only: a `stats` key inside an
    /// `[app.<name>.network]` table is ignored (warned), and `sbx config show --app` does not surface
    /// the inherited value — the app inherits this baseline.
    pub(crate) egress_stats: bool,
    /// The resolved process/exec posture: the default (`off`) unless the global config or a trusted
    /// project set a mode. An untrusted project's choice is dropped with a warning — it may not forge
    /// or loosen the enforcement of its own agent.
    pub(crate) proc: crate::proc_policy::ProcPolicy,
    /// Which layer supplied the winning `proc` posture (`Default` when neither config set it).
    pub(crate) proc_origin: Provenance,
    /// The resolved refusal-notification policy: the default (`always` for every event) unless the
    /// global config or a trusted project set one. An untrusted project's choice is dropped with a
    /// warning — it may not silence the announcement of the refusals it provokes.
    pub(crate) notify: crate::notify::NotifyPolicy,
    /// Which layer supplied the winning `notify` policy (`Default` when neither config set it).
    pub(crate) notify_origin: Provenance,
    /// The resolved GUI posture: the default (`None`) unless the global config or a trusted
    /// project asked for `"wayland"`. An untrusted project's choice is dropped with a warning
    /// — it may not open a display.
    pub(crate) gui: GuiPolicy,
    /// Which layer supplied the winning `gui` posture (`Default` when neither config set it).
    pub(crate) gui_origin: Provenance,
    /// The distribution userland the cage runs on, when a layer named one. `None` — the ordinary
    /// case — leaves the cage on the hermetic nix userland the sandbox resolves from sbx's own
    /// store. A security field: an untrusted project's value is dropped with a warning, since the
    /// root filesystem supplies every program the cage runs.
    pub(crate) distro: Option<String>,
    /// How to authenticate to the registry serving [`Self::distro`], when the declaration named a
    /// credential. A reference to a secret, resolved host-side at the moment a registry asks for
    /// one, so no value is held here and none reaches the cage.
    pub(crate) distro_auth: Option<SecretSource>,
    /// Which layer supplied the winning `distro` locator (`Default` when neither config set it).
    pub(crate) distro_origin: Provenance,
    /// The IANA zone the cage's clock reads in, when a layer named one. `None` leaves the cage on
    /// the built-in default (`sandbox::binds::DEFAULT_ZONE`), which is a real zone and not
    /// an absence — the cage always carries the database and the `/etc/localtime` link. **Not a
    /// security field** (see [`schema::RawConfig::timezone`]): the value only tells the cage what
    /// to display, and `[env] TZ` is already free, so gating it would buy nothing. Syntactically
    /// validated here; the launcher checks the name against the provisioned database, since only it
    /// has one to check against. Baseline-only, like `egress_stats`: a zone belongs to the machine
    /// and the person, not to an app, so `[app.<name>]` carries no override.
    pub(crate) timezone: Option<String>,
    /// Which layer supplied the winning `timezone` (`Default` when no config named one).
    pub(crate) timezone_origin: Provenance,
    /// Whether hardware-accelerated GPU rendering is open (the default `false` unless the global
    /// config or a trusted project set `gpu = true`). A security field, gated like `gui` — an
    /// untrusted project may not open a render node and the `/sys` device tree.
    pub(crate) gpu: bool,
    /// Which layer supplied the winning `gpu` posture (`Default` when neither config set it).
    pub(crate) gpu_origin: Provenance,
    /// Whether a package source may be fetched over plaintext `http://` (the default `false`
    /// unless the global config, an app profile or a trusted project set `allow_insecure_http`).
    /// A security field — an untrusted project may not downgrade the transport its artefacts
    /// arrive over. Read by the six source validators in this module and by the two prebuilt
    /// re-validation sites, so one answer serves the declared locator and the resolved URL alike.
    pub(crate) allow_insecure_http: bool,
    /// Which layer supplied the winning `allow_insecure_http` (`Default` when none set it).
    pub(crate) allow_insecure_http_origin: Provenance,
    /// Whether audio (microphone + playback) is open (the default `false` unless the global config
    /// or a trusted project set `audio = true`). A security field, gated like `gui`/`gpu` — an
    /// untrusted project may not open the PulseAudio bus (which exposes the microphone and every
    /// system-audio `.monitor` source).
    pub(crate) audio: bool,
    /// Which layer supplied the winning `audio` posture (`Default` when neither config set it).
    pub(crate) audio_origin: Provenance,
    /// Whether the cage gets a private in-cage desktop portal (`dbus = true`; default `false` unless
    /// the global config or a trusted project set it). A security field, gated like `gui`/`gpu` — an
    /// untrusted project may not stand up an in-cage portal.
    pub(crate) dbus: bool,
    /// Which layer supplied the winning `dbus` posture (`Default` when neither config set it).
    pub(crate) dbus_origin: Provenance,
    /// Host loopback TCP ports forwarded into the cage (see [`RawConfig::forward`]). A security
    /// field, gated like `network`/`gui`; the merged set is the union of the global and a trusted
    /// project's ports (an untrusted project's ports are dropped, never added), so a trusted
    /// layer's ports survive an untrusted overlay. Empty when no layer declared any.
    pub(crate) forward: Vec<ForwardPort>,
    /// Which layer supplied the winning `forward` set. The union means a value here is the
    /// *highest-trust* layer that contributed any port (`Default` when none did). A display
    /// affordance for `sbx config`; the launcher ignores it.
    pub(crate) forward_origin: Provenance,
    /// The resolved cgroup resource limits (anti-DoS): the built-in defaults, with any field a
    /// trusted `[limits]` table (global or project) overrode. A security field, gated like
    /// `network`/`gui` — an untrusted project may not loosen a limit. Each of the three fields is
    /// layered independently (global under a trusted project), like `env`.
    pub(crate) limits: crate::sandbox::cgroup::Limits,
    /// The per-field provenance of `limits`: which layer set each of the three, or `Default` for a
    /// field no config overrode. A display affordance for `sbx config`.
    pub(crate) limits_origin: LimitsOrigin,
    /// The trusted relaxation of the cage's mandatory seccomp denylist (the built-in denylist plus
    /// any syscall a trusted `[seccomp] allow` re-permits). A security field, gated like
    /// `network`/`limits` — an untrusted project may not relax it. The default (empty) is the full
    /// mandatory denylist. The layering unions (a project adds to the global set), like `forward`.
    pub(crate) seccomp: crate::sandbox::seccomp::SeccompPolicy,
    /// Which layer supplied the seccomp relaxation — the highest-trust layer that lifted anything
    /// (`Default` when neither config did), like `forward_origin`. A display affordance for
    /// `sbx config`; the launcher ignores it.
    pub(crate) seccomp_origin: Provenance,
    /// Host device nodes granted into the cage from a trusted `[devices] allow` (each an absolute
    /// path under `/dev/`). A security field, gated like `network`/`seccomp` — an untrusted project
    /// may not expose a host device. The default (empty) leaves the cage's minimal, hostless `/dev`.
    /// The layering unions (a project adds to the global set), like `forward`; sorted and deduped.
    pub(crate) devices: Vec<PathBuf>,
    /// Which layer supplied the device grant — the highest-trust layer that granted anything
    /// (`Default` when neither config did), like `forward_origin`. A display affordance for
    /// `sbx config`; the launcher ignores it.
    pub(crate) devices_origin: Provenance,
    /// The project paths closed off inside the cage, from any layer's `[fs]`. The one security
    /// field that is **not** trust-gated: every entry only ever subtracts access from the cage, so
    /// an untrusted project closing its own files off is not a capability it could turn on the
    /// user. The layering unions (a project adds to the global set), like `devices` — which is also
    /// the fail-closed direction here, since a layer can only close more.
    pub(crate) fs: fspolicy::FsPolicy,
    /// Which layer supplied the mask set — the highest-trust layer that closed anything
    /// (`Default` when no config did), like `devices_origin`. A display affordance for
    /// `sbx config`; the launcher ignores it.
    pub(crate) fs_origin: Provenance,
    /// The ssh-agent keys a trusted `[ssh_agent] allow` grants the cage, each entry naming one key
    /// by its `SHA256:…` fingerprint or its comment. A security field, gated like
    /// `devices`/`seccomp` — a key the cage can sign with authenticates as the user wherever that
    /// key is trusted, so an untrusted project may not grant one. The default (empty) leaves the
    /// cage with no agent. The layering unions (a project adds to the global set), like `devices`.
    pub(crate) ssh_agent: Vec<String>,
    /// Which layer supplied the ssh-agent grant — the highest-trust layer that granted anything
    /// (`Default` when neither config did), like `devices_origin`. A display affordance for
    /// `sbx config`; the launcher ignores it.
    pub(crate) ssh_agent_origin: Provenance,
    /// The broker plugins to stand up for this cage, from `[broker.<name>]`, ordered by name.
    ///
    /// Empty is the common case and means no broker plugin runs.
    pub(crate) brokers: Vec<BrokerBinding>,
    /// Whether every signature must be confirmed on the host desktop before the broker forwards it
    /// (`[ssh_agent] confirm`). ORs across layers: a layer may ask for the prompt, none may remove
    /// it. With no askpass helper on the host the launch gives the cage no agent at all, rather than
    /// a grant whose promised confirmation never appears.
    pub(crate) ssh_agent_confirm: bool,
    /// The shortest credential, in bytes, this launch scans for — `[redact] min_len`, defaulting to
    /// [`crate::sandbox::redact::MIN_LEN_DEFAULT`]. One floor for both renderings of a needle set:
    /// the proxy's outbound refusal and inbound mask, and the `${name}` substitution over a task's
    /// output. A security field, gated like `network`/`limits` — raising it drops credentials out of
    /// the tripwires, so an untrusted project may not set it.
    pub(crate) redact_min_len: usize,
    /// Which layer supplied the winning `redact_min_len` (`Default` when neither config set it).
    /// A display affordance for `sbx config`; the launcher ignores it.
    pub(crate) redact_min_len_origin: Provenance,
    /// Credentials the egress proxy injects into matching requests (the plaintext never
    /// enters the cage). A security field, gated like `binds`; cleared with a warning
    /// unless the posture is an allowlist, since the filtering proxy is what injects them.
    pub(crate) secrets: Vec<HeaderSecret>,
    /// The baseline credentials *before* the posture clear — what an app overlay inherits. An app
    /// may open a filtering posture (`deny`/`allow`/`ask`) over a non-filtering baseline, in which
    /// case the proxy would inject these; [`Resolved::merge_app`] (and the `--app` view) re-derive
    /// the effective set from this, not from the posture-cleared `secrets`, so a baseline credential
    /// the baseline posture would clear is still inheritable. The baseline launch/display use
    /// `secrets`; only the per-app fold reads this.
    ///
    /// A one-shot override's `[secret]` section is applied to this set as well as to `secrets`
    /// ([`Resolved::apply_override`]): the `--app` view re-derives from here *after* an override
    /// has been folded in, so a set that stopped at the last config layer would describe an app as
    /// injecting nothing for a host the launch does inject for.
    pub(crate) declared_secrets: Vec<HeaderSecret>,
    /// Declared operations a caller may invoke — each a fixed command sbx runs in an ephemeral
    /// sibling cage with a credential the caller never holds. A security field, gated like
    /// `secrets`: an untrusted project may neither declare a task nor loosen one. Unlike `secrets`
    /// these are **not** cleared by the network posture — a task's egress is its own (served by a
    /// per-invocation proxy), so it neither needs nor inherits the session's posture.
    pub(crate) tasks: Vec<TaskSpec>,
    /// Named application launch profiles, each a gated overlay over this baseline. Keyed
    /// by name; `sbx app <name>` looks one up and folds it on with [`Resolved::merge_app`].
    ///
    /// `sbx run` ignores them.
    pub(crate) apps: BTreeMap<String, ResolvedApp>,
    /// Human-readable notes about what was dropped or ignored and why.
    pub(crate) warnings: Vec<String>,
}

/// One bundle's install step, as the fold hands it to a launch: the step itself and the bundle
/// that declared it.
///
/// The bundle's name travels with the command because everything a launch says about the step
/// names it — the note before it runs, the error when it fails — and "an install step failed" with
/// no author is a message a reader cannot act on. Same reason a folded [`RawTask`] carries
/// `from_bundle`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BundleProvision {
    /// The bundle that declared this step.
    pub(crate) bundle: String,
    /// The argv to run, exactly as the bundle wrote it.
    pub(crate) argv: Vec<String>,
}

impl Resolved {
    /// Fold an app's overlay onto this baseline with precedence **app > baseline**: the
    /// app's environment upserts over the baseline's, its packages override by name, its
    /// binds and credentials add, its network/GUI posture (when it set one) replaces the
    /// baseline's, and its cgroup limits override the baseline's per field. Every value was
    /// gated at resolve time, so this is a pure merge — no re-gating. The secret-vs-posture
    /// consistency is re-checked at the end, since the overlay can add secrets or change the
    /// posture.
    pub(crate) fn merge_app(&mut self, app: ResolvedApp) {
        for (key, val) in app.env {
            upsert(&mut self.env, key, val);
        }
        // Unioned, not overridden: the baseline and the app each speak for the packages they
        // declared, and a name only ever means "lift the delay", so there is nothing for one layer
        // to take back from the other.
        for name in app.accepts_fresh_releases {
            if !self.accepts_fresh_releases.contains(&name) {
                self.accepts_fresh_releases.push(name);
            }
        }
        for pkg in app.packages {
            upsert_package(
                &mut self.packages,
                pkg.name,
                pkg.backend,
                pkg.state,
                // The app's packages are already resolved, decoration included, so it travels with
                // the declaration instead of being re-read from a table this merge does not have.
                tools::Decoration {
                    libs: pkg.libs,
                    main: pkg.main,
                },
            );
        }
        // Merge by *path*: an app bind whose path the baseline already exposes overrides it in
        // place (so a dest is never mounted twice, and the app's mode wins), consistent with how
        // every other overlay field resolves — `env`/`packages`/`network`/`gui` all let the app
        // win. Both layers are trusted, so this is a precedence choice, not a security one: an app
        // may thus flip a baseline bind's mode (ro↔rw) or add a new path.
        // URI handlers fold by scheme, the app's replacing the baseline's — the same rule as `env`
        // and `packages`, so an app that opens its own deep links keeps whatever browser the
        // baseline set for the web schemes it does not mention.
        self.open.extend(app.open);
        // Services fold by name on the same rule, so an app can retune one its bundle declares (a
        // different port, a readiness gate the bundle left off) without forking the bundle.
        self.service.extend(app.service);
        // The app's install steps are taken whole rather than merged: a launch runs one app, and
        // the baseline has none of its own to fold under it.
        self.provisions = app.provisions;
        for bind in app.binds {
            if let Some(existing) = self.binds.iter_mut().find(|b| b.path == bind.path) {
                *existing = bind;
            } else {
                self.binds.push(bind);
            }
        }
        if let Some(network) = app.network {
            self.network = network;
        }
        // Apply the app's read-by-default verb posture to its *effective* allowlist — the app's own
        // (just merged) or, when the app set none, the inherited baseline. Only Mode-B `sbx app`
        // launches reach `merge_app`; `sbx run` (Mode A) never do, so they stay all-verbs.
        if let NetworkPolicy::Allowlist(policy) = &mut self.network {
            policy.apply_default_methods(&app.default_methods);
        }
        // The app's exec posture replaces the baseline's when it declared one (its own trusted
        // policy for its own agent); otherwise the baseline's stands.
        if let Some(proc) = app.proc {
            self.proc = proc;
        }
        // The app's notification policy replaces the baseline's when it declared one — how loud an
        // app's own refusals are is the app's property, not the project's.
        if let Some(notify) = app.notify {
            self.notify = notify;
        }
        if let Some(gui) = app.gui {
            self.gui = gui;
        }
        if let Some(allow) = app.allow_insecure_http {
            self.allow_insecure_http = allow;
        }
        if let Some(gpu) = app.gpu {
            self.gpu = gpu;
        }
        if let Some(audio) = app.audio {
            self.audio = audio;
        }
        if let Some(dbus) = app.dbus {
            self.dbus = dbus;
        }
        // The app's ports union onto the baseline's — an app adds ports, never removes or
        // overrides the trusted baseline set (the flagship "agent on untrusted code" property,
        // which holds because the untrusted contribution was dropped at resolve time).
        union_forward(&mut self.forward, app.forward);
        overlay_limits(&mut self.limits, app.limits);
        // The app's seccomp relaxation unions onto the baseline's — an app adds lifts, never
        // removes the trusted baseline's (the flagship "agent on untrusted code" property, which
        // holds because the untrusted contribution was dropped at resolve time).
        self.seccomp.union(&app.seccomp);
        // The app's device grant unions onto the baseline's — an app adds devices, never removes
        // the trusted baseline's (the same flagship property, holding for the same reason).
        union_devices(&mut self.devices, app.devices);
        // The app's `[fs]` masks union onto the baseline's — an app closes more of the project, and
        // can never reopen what the baseline closed. Ungated, so this holds whatever the project's
        // trust: the union direction, not the gate, is what makes it safe. That reading is exact
        // for the masks alone; `scan_max_kb` widens rather than closes, and an untrusted layer's is
        // already stripped where the app is resolved (`apps::resolve`), so nothing gated reaches
        // here.
        self.fs.union(app.fs);
        // The app's ssh-agent grant unions onto the baseline's, for the same reason and with the
        // same property: an app adds a key it needs, and cannot take away one the trusted baseline
        // granted. A key named by only one app is therefore granted to that app's cage alone — every
        // other launch of the project sees an agent without it.
        union_ssh_agent(&mut self.ssh_agent, app.ssh_agent);
        // …and its confirmation posture ORs on, for the same reason: an app may ask for the prompt,
        // and no app may take away one the baseline asked for.
        self.ssh_agent_confirm |= app.ssh_agent_confirm;
        // Drop the baseline secret-posture warning: it judged the *baseline* network, but the app's
        // posture re-decides injection just below — keeping it would let `sbx app <name>` both inject
        // a credential and print "ignoring N HTTP-header secret(s)". The re-check re-emits it only if
        // the *merged* posture still drops them.
        self.warnings
            .retain(|w| !w.contains("HTTP-header secret(s)"));
        self.warnings.extend(app.warnings);
        // Re-derive the effective credentials from the *declared* baseline (not the posture-cleared
        // `secrets`), so an app that opens a filtering posture inherits a baseline credential the
        // baseline posture would have cleared. App credentials fold through the same `(to, header)`
        // upsert a single layer uses, so an app credential shadows its baseline twin (like
        // env/packages) instead of injecting a second identical header line upstream.
        self.secrets = self.declared_secrets.clone();
        for secret in app.secrets {
            upsert_secret(&mut self.secrets, &mut self.warnings, "app overlay", secret);
        }
        enforce_secret_posture(&self.network, &mut self.secrets, &mut self.warnings);
        // The app's tasks fold onto the baseline's by name — an app task shadows a baseline one of
        // the same name (like env/packages/secrets) rather than offering two operations a caller
        // cannot tell apart. No posture check: a task's egress is its own, served by its own
        // per-invocation proxy, so the session's network posture neither enables nor clears it.
        for task in app.tasks {
            tasks::upsert_task(&mut self.tasks, &mut self.warnings, "app overlay", task);
        }
    }

    /// Apply a one-shot override's **nixpkgs channel**, if it set one, as the authoritative pin for
    /// this launch. Called from `prepare` *before* the lock target is chosen, because the channel
    /// decides which lock the whole launch (base userland and tools alike) resolves against — too
    /// late to set once [`crate::sandbox::effective_lock_target`] has read it.
    ///
    /// It reuses `nixpkgs_project` (the highest-precedence effective source), so an override wins
    /// over a trusted project's own pin. One display residual: the channel line then reads as a
    /// project-level source rather than "override" — the launched value is correct, only its label
    /// is coarse. The rest of the override is applied by [`Resolved::apply_override`], after any app
    /// overlay merges.
    ///
    /// A set-but-invalid channel is a **hard error** (`Err`): unlike a config layer, an override has
    /// no safe fallback — keeping the baseline would resolve a *different* source than the user's
    /// (mistyped) explicit one, a silent fail-open on a supply-chain field. The caller aborts the
    /// launch. `Ok(())` when the override set no channel or set a valid one.
    pub(crate) fn apply_override_channel(&mut self, ov: &Override) -> Result<(), String> {
        let Some(value) = ov.raw.nixpkgs.clone() else {
            return Ok(());
        };
        let mut notes = Vec::new();
        match validate_nixpkgs(&mut notes, OVERRIDE_SOURCE, value) {
            Some(valid) => {
                self.nixpkgs_project = Some(valid);
                Ok(())
            }
            None => Err(notes
                .into_iter()
                .next()
                .unwrap_or_else(|| format!("{OVERRIDE_SOURCE}: invalid `nixpkgs` value"))),
        }
    }

    /// Apply a one-shot override as the authoritative **final word** on this resolved configuration
    /// — after the project layer (for `sbx run`) or after a named app's overlay (for
    /// `sbx app`), so it beats both. Consumes the override. The nixpkgs channel is handled earlier
    /// by [`Resolved::apply_override_channel`] (the lock is already chosen by now), so it is skipped.
    ///
    /// Trusted **by invocation**: every field is honored, since the invoker owns the process argv
    /// and environment (no lower-trust context can reach them). This includes the two fields a config
    /// file gates trusted-only — `[seccomp]` (relax the syscall denylist), `[devices]` (grant a
    /// host device) and `[ssh_agent]` (grant a key the cage may sign with): the justification is
    /// **parity with the trusted config** — the invoker strictly
    /// outranks any config layer, so it may declare exactly the relaxation/grant a *trusted* config
    /// already can. (Not the `network`/`binds` axis: relaxing the denylist re-permits a syscall whose
    /// only containment was the filter, widening the in-cage kernel attack surface.) Each field it
    /// sets is stamped
    /// [`Provenance::Override`] for `sbx config show`; its binds are canonicalized and its secret
    /// posture re-checked exactly as the layered fields are, so this is a faithful final layer, not
    /// a raw assignment. `[network] groups`/`[app.*]` in an override are ignored (noticed at
    /// collection time), so they never reach here.
    ///
    /// A set-but-invalid **scalar security posture** (`network`/`gui`/`[limits]`) is a **hard error**
    /// (`Err`, the launch aborts): there is no safe fallback — silently keeping the baseline could
    /// leave a *wider* posture than the user's explicit (mistyped) intent, the exact fail-open this
    /// feature must not have. The additive fields
    /// (`env`/`binds`/`packages`/`seccomp`/`devices`/`ssh_agent`)
    /// instead fail *closed* by dropping a bad entry (a missing bind, an unbuilt tool, an unknown
    /// syscall token, a malformed device path, or an unmatchable key is *less*
    /// capability/relaxation, never a wider posture), so they warn and skip rather than abort. On a hard error nothing is applied (the
    /// scalars are validated up front, before any mutation), so a caller that surfaces the error can
    /// still show the untouched baseline.
    pub(crate) fn apply_override(&mut self, ov: Override) -> Result<(), Vec<String>> {
        let Override { raw, .. } = ov;
        let RawConfig {
            allow_insecure_http,
            env,
            binds,
            packages,
            network,
            gui,
            timezone,
            gpu,
            audio,
            dbus,
            limits,
            secret,
            forward,
            seccomp,
            devices,
            ssh_agent,
            fs,
            proc,
            notify,
            redact,
            open,
            service,
            // The channel is applied earlier (before the lock is chosen); groups/apps/bundles are
            // not launch-shaping and were noticed and dropped at collection time (a bundle is only
            // ever reached through an app's `use`, and an override declares no app). An override's
            // inline
            // `[flakes]`, `[tarball]`, `[deb]`, and `[appimage]` tables are dropped (fail-closed): a
            // one-shot `--config` blob is no place for a multiline `flake.nix` or an auto-upgrade
            // resolver command, so all are declared in a profile or project config. `[task]` joins
            // them for the same reason: a declared operation is a program plus a credential, vetted
            // where it is read and listed, not assembled on a command line for one launch.
            nixpkgs: _,
            // The distribution userland joins them, for the sharpest version of the same reason:
            // it names the root filesystem every program in the cage is executed from. That is
            // declared in a config that is reviewed and trusted, not assembled on a command line
            // for one launch.
            distro: _,
            // The engine that installs every `mise:` tool: global-only by construction,
            // so neither a project layer nor a one-shot override redirects it.
            mise: _,
            task: _,
            app: _,
            bundle: _,
            // `[plugin.*]` joins them, and for the sharpest version of the same reason: it can
            // trigger a build and set the environment of a binary that runs host-side on the
            // plaintext path. That is declared in a config someone reads, not assembled on a
            // command line for one launch.
            plugin: _,
            // `[broker.*]` joins them, for the same reason and one more: its `socket` names a host
            // resource sbx will connect to and hold, which is a standing fact about the machine —
            // not something a single launch gets to assert on a command line.
            broker: _,
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
            // Reported per blob when the override was collected, which is the only place it can
            // be: the merge that builds this overlay carries the fields it understands and drops
            // the bag with them, so by here there is nothing left to name.
            rest: _,
        } = raw;

        // Validate the scalar security postures FIRST, into locals — a set-but-invalid one is fatal,
        // and nothing must be mutated before that verdict. Validation warnings accumulate locally so
        // a *fatal* one is promoted into the returned error (printed before aborting) rather than
        // lost with the dropped config; on success they merge into `self.warnings`.
        let mut notes = Vec::new();
        let (scalars, fatal) = build_override_scalars(
            &self.network,
            &self.proc,
            &self.notify,
            &self.net_groups,
            network,
            gui,
            proc,
            notify,
            limits,
            redact,
            &mut notes,
        );
        if !fatal.is_empty() {
            return Err(override_fatal_error(fatal, notes));
        }
        let OverrideScalars {
            network: new_network,
            gui: new_gui,
            proc: new_proc,
            notify: new_notify,
            limits: new_limits,
            redact_min_len: new_redact_min_len,
        } = scalars;

        // No fatal — apply. Promote the (non-fatal) validation notes to the resolved warnings.
        self.warnings.extend(notes);

        // `env` — a free field; upsert over the resolved set, stamping the override provenance.
        apply_env(
            &mut self.env,
            Some((Provenance::Override, &mut self.env_layer)),
            &mut self.warnings,
            OVERRIDE_SOURCE,
            env,
            false,
        );

        // `[open]` — merged by scheme, the override's handler winning. Carried rather than refused
        // like `[flakes]`/`[plugin]`: an override is authoritative by invocation, the same tier
        // that already carries `binds`, and trying a handler for one launch before writing it into
        // a profile is how one is arrived at. It reaches nothing `binds` does not already reach.
        if !open.is_empty() {
            self.open
                .extend(validate_open(&mut self.warnings, OVERRIDE_SOURCE, open));
        }

        // `[service]` — merged by name, the override's entry winning, and carried for the same
        // reason as `[open]`: trying an auxiliary process for one launch, before writing it into a
        // profile, is how one is arrived at, and it runs in the cage like every other declared
        // command. It can only *add* or retune, never remove — turning a declared service off for
        // one launch is what its own `disable_env` and the existing `--env` are for.
        if !service.is_empty() {
            self.service.extend(validate_service(
                &mut self.warnings,
                OVERRIDE_SOURCE,
                service,
            ));
        }

        // `binds` — validate to absolute, canonicalize (as `load` does for the layered binds), then
        // merge by canonical path so the override's mode wins on a collision. The provenance is
        // recorded keyed by the *canonical* path, matching the displayed bind. Fail-closed: a
        // malformed/missing entry is warned and skipped (fewer binds, never a wider exposure).
        if !binds.is_empty() {
            let mut resolved_binds: Vec<Bind> = Vec::new();
            apply_binds(
                &mut resolved_binds,
                None,
                &mut self.warnings,
                OVERRIDE_SOURCE,
                binds,
            );
            let roots = sbx_control_plane_roots();
            // No project here: a `Resolved` does not carry the root it was resolved for, and an
            // override is applied to one that already exists. So a `--bind` inside the project
            // goes unremarked where the same line in a config file is named. The asymmetry is
            // deliberate rather than overlooked — an override is typed for one launch by someone
            // watching it, and a config line is what sits there unremarked for months. Threading
            // the root through is the fix if that ever stops being true.
            // No per-layer re-keying either: an override's provenance is the constant
            // `Provenance::Override`, recorded below against the canonical path directly.
            for bind in canonicalize_binds(resolved_binds, &roots, None, None, &mut self.warnings) {
                self.bind_layer
                    .insert(bind.path.clone(), Provenance::Override);
                if let Some(existing) = self.binds.iter_mut().find(|b| b.path == bind.path) {
                    *existing = bind;
                } else {
                    self.binds.push(bind);
                }
            }
        }

        // `allow_insecure_http` — applied BEFORE `packages`, not with the other scalar postures
        // below, and for the same reason it resolves ahead of `apply_tools` in `resolve`: it decides
        // how the package values on this very invocation are validated. Ordered with its siblings it
        // would reach `self` one statement too late, and `--config` naming both a plaintext locator
        // and the flag that admits it would see the locator refused. Trusted by invocation, like
        // every other override — the person typing the command line is the top authority.
        if let Some(value) = allow_insecure_http {
            self.allow_insecure_http = value;
            self.allow_insecure_http_origin = Provenance::Override;
        }

        // `packages` — trusted by invocation; upsert by name over the resolved set.
        if !packages.is_empty() {
            apply_packages(
                &mut self.packages,
                &mut self.warnings,
                OVERRIDE_SOURCE,
                packages,
                TrustState::Trusted,
                false,
                self.allow_insecure_http,
            );
        }

        // The scalar postures validated above.
        if let Some((policy, stats)) = new_network {
            if let Some(b) = stats {
                self.egress_stats = b;
            }
            self.network = policy;
            self.network_origin = Provenance::Override;
        }
        if let Some(policy) = new_gui {
            self.gui = policy;
            self.gui_origin = Provenance::Override;
        }
        // `timezone` — not a security posture, so a bad value is not fatal: it warns and leaves the
        // zone in effect, the fail-closed direction here (the cage keeps a zone it can resolve).
        // Applied for the same reason it exists as a field rather than as an `[env] TZ` line: the
        // clock and the `/etc/localtime` link have to move together, and only sbx can move both.
        // The validator's warning goes straight to `self.warnings`: the `notes` vector was already
        // drained into them above, and only a *fatal* verdict needed to reach the caller.
        if let Some(value) = timezone
            && let Some(zone) = validate_timezone(&mut self.warnings, OVERRIDE_SOURCE, value)
        {
            self.timezone = Some(zone);
            self.timezone_origin = Provenance::Override;
        }
        // `proc` — the exec posture, validated above (a bad mode is fatal, like `gui`/`network`). The
        // override is the final word, so it may raise, lower, or disable enforcement for this launch
        // regardless of the config/app layers — an invoker disabling a trusted app's `enforce` for one
        // run is by design (top authority, the same as `--gpu=false`).
        if let Some(policy) = new_proc {
            self.proc = policy;
            self.proc_origin = Provenance::Override;
        }
        // `notify` — how loudly this launch's refusals are announced, validated above (a bad mode is
        // fatal, like `proc`). Trusted by invocation and the final word: silencing a lens for one run
        // is the invoker's call, and they are the person the notification is for.
        if let Some(policy) = new_notify {
            self.notify = policy;
            self.notify_origin = Provenance::Override;
        }
        // `gpu` — a bool, so no value can be invalid (unlike `gui`/`network`); apply directly. The
        // override is trusted by invocation and the final word, so it may open or close GPU for this
        // launch regardless of the config layers.
        if let Some(value) = gpu {
            self.gpu = value;
            self.gpu_origin = Provenance::Override;
        }
        // `audio` — a bool, like `gpu`; apply directly. Trusted by invocation and the final word, so
        // it may open or close audio for this launch regardless of the config layers.
        if let Some(value) = audio {
            self.audio = value;
            self.audio_origin = Provenance::Override;
        }
        // `dbus` — a bool, like `gpu`/`audio`; apply directly. Trusted by invocation and the final
        // word, so it may stand up or drop the in-cage portal for this launch regardless of layers.
        if let Some(value) = dbus {
            self.dbus = value;
            self.dbus_origin = Provenance::Override;
        }
        if let Some(over) = new_limits {
            mark_limit_origins(&mut self.limits_origin, &over, Provenance::Override);
            overlay_limits(&mut self.limits, over);
        }
        // `[redact] min_len` — a scalar, validated above. Trusted by invocation and the final word,
        // so it may move the floor for this launch whatever the config layers set.
        if let Some(floor) = new_redact_min_len {
            self.redact_min_len = floor;
            self.redact_min_len_origin = Provenance::Override;
        }

        // `forward` — trusted by invocation; the ports add to the effective set (a collection, so a
        // bad port — only `0` is possible after parse — is warned and skipped, not fatal). The
        // override is the final word and additive: its ports union onto the resolved set, and the
        // origin stamps `Override` when it contributes any (it cannot remove a baseline's ports,
        // matching the additive model of `--bind`/`--package`).
        if let Some(raw) = forward {
            let validated = validate_forward(&mut self.warnings, OVERRIDE_SOURCE, &raw);
            if !validated.is_empty() {
                self.forward_origin = Provenance::Override;
            }
            union_forward(&mut self.forward, validated);
        }

        // `[seccomp]` / `[devices]` — trusted by invocation, so the override may relax the mandatory
        // syscall denylist and grant a host device for this launch. Both are additive collections
        // (union onto the resolved policy/set; a bad token/path is warned and skipped by
        // `apply_seccomp`/`apply_devices`, never fatal — the invoker can only *add* here). The origin
        // stamps `Override` when the override contributed any, for `sbx config show`.
        if seccomp.is_some() {
            let over = apply_seccomp(&mut self.warnings, OVERRIDE_SOURCE, seccomp);
            if !over.is_empty() {
                self.seccomp.union(&over);
                self.seccomp_origin = Provenance::Override;
            }
        }
        if devices.is_some() {
            let over = apply_devices(&mut self.warnings, OVERRIDE_SOURCE, devices);
            if !over.is_empty() {
                union_devices(&mut self.devices, over);
                self.devices_origin = Provenance::Override;
            }
        }
        // `[fs]` — additive like the two above, and the one field where "trusted by invocation"
        // carries no weight either way: an override can only close more of the project for this
        // launch, never reopen what a config layer closed.
        if fs.is_some() {
            let over = apply_fs(&mut self.warnings, OVERRIDE_SOURCE, fs);
            // `declares_nothing`, not `is_empty`: the latter asks whether there are mounts to lay
            // down, and a `scan`-only table lays down none — asking it here dropped the override
            // entirely, so `--config '[fs] scan = [...]'` protected nothing.
            if !over.declares_nothing() {
                self.fs.union(over);
                self.fs_origin = Provenance::Override;
            }
        }
        if ssh_agent.is_some() {
            let (over, confirm) = apply_ssh_agent(&mut self.warnings, OVERRIDE_SOURCE, ssh_agent);
            // Confirmation ORs in, like every other layer: an invoker may add the prompt, and the
            // one place it must not be possible to *remove* it is the most convenient one to try.
            self.ssh_agent_confirm |= confirm;
            if !over.is_empty() {
                union_ssh_agent(&mut self.ssh_agent, over);
                self.ssh_agent_origin = Provenance::Override;
            }
        }

        // `[secret]` — trusted by invocation; the credentials add to the effective set, resolved
        // through the override's own `[secret.defaults]`. The plaintext still never enters the cage
        // (the proxy injects it host-side). The secret↔posture invariant is re-checked against the
        // possibly-just-overridden posture below.
        if let Some(section) = secret {
            let defaults = section
                .defaults
                .as_ref()
                .map(SecretDefaults::from_raw)
                .unwrap_or_default();
            let plugins = match crate::store::Layout::from_env() {
                Some(layout) => PluginRegistry::load(&layout.plugins_dir(), &mut self.warnings),
                None => PluginRegistry::default(),
            };
            if let Some(raw_defaults) = &section.defaults {
                warn_resolver_bindings(&mut self.warnings, OVERRIDE_SOURCE, raw_defaults, &plugins);
            }
            // Both halves of the credential pair, because both are read after this: `secrets` is
            // what this launch injects, and `declared_secrets` is the pre-clear set an app overlay
            // — and the `--app` view, which runs after the override — re-derives its effective
            // credentials from. Applying to one of them left the view reporting an app that
            // injects nothing for a host the launch does inject for.
            //
            // The declared set takes the diagnostics: it is the one that holds every credential a
            // layer wrote, so its collision warnings are the complete ones, and repeating them for
            // the effective set would say the same thing twice.
            apply_secret_section(
                &mut self.declared_secrets,
                &mut self.warnings,
                OVERRIDE_SOURCE,
                section.hosts.clone(),
                &defaults,
                &plugins,
            );
            apply_secret_section(
                &mut self.secrets,
                &mut Vec::new(),
                OVERRIDE_SOURCE,
                section.hosts,
                &defaults,
                &plugins,
            );
        }
        enforce_secret_posture(&self.network, &mut self.secrets, &mut self.warnings);
        Ok(())
    }

    /// Validate a one-shot override's scalar security postures **without applying anything**, so a
    /// launch can reject a mistyped value *before* the expensive channel/userland resolution rather
    /// than after. Same verdict [`Resolved::apply_override`] would reach for those fields (the
    /// baseline is the mode-inheritance parent — and a mode-less table never *fails*, only resolves
    /// to a different valid policy, so validating against the baseline catches exactly the fatal
    /// values an app overlay would too). Borrows the override, so the scalar fields are cloned.
    pub(crate) fn validate_override(&self, ov: &Override) -> Result<(), Vec<String>> {
        let mut notes = Vec::new();
        let (_, fatal) = build_override_scalars(
            &self.network,
            &self.proc,
            &self.notify,
            &self.net_groups,
            ov.raw.network.clone(),
            ov.raw.gui.clone(),
            ov.raw.proc.clone(),
            ov.raw.notify.clone(),
            ov.raw.limits.clone(),
            ov.raw.redact.clone(),
            &mut notes,
        );
        if fatal.is_empty() {
            Ok(())
        } else {
            Err(override_fatal_error(fatal, notes))
        }
    }
}

/// The validated scalar security postures a one-shot override sets: each `Some` only when the
/// override declared it and it validated. Built once by [`build_override_scalars`] and consumed by
/// both the pre-launch check ([`Resolved::validate_override`], which discards it) and the real
/// application ([`Resolved::apply_override`], which assigns from it).
#[derive(Default)]
struct OverrideScalars {
    /// The resolved network policy plus the egress-stats toggle the `[network]` table carried.
    network: Option<(NetworkPolicy, Option<bool>)>,
    gui: Option<GuiPolicy>,
    /// The resolved process/exec posture (`Some` only when the override set `proc` and it validated).
    proc: Option<crate::proc_policy::ProcPolicy>,
    /// The resolved notification policy (`Some` only when the override set `notify` and it validated).
    notify: Option<crate::notify::NotifyPolicy>,
    limits: Option<crate::sandbox::cgroup::Limits>,
    /// The redaction floor (`Some` only when the override set `[redact] min_len` and it validated).
    redact_min_len: Option<usize>,
}

/// Validate an override's scalar security postures (`network`/`gui`/`[limits]`) against `baseline`
/// (the mode-inheritance parent). Returns the built policies and the list of *fatal* field names —
/// a set-but-invalid one, which has no safe fallback for an override. Non-fatal validator notes are
/// pushed to `notes`. Consuming (the fields move into the validators), so a borrowing caller clones.
#[allow(clippy::too_many_arguments)]
fn build_override_scalars(
    baseline: &NetworkPolicy,
    baseline_proc: &crate::proc_policy::ProcPolicy,
    baseline_notify: &crate::notify::NotifyPolicy,
    groups: &NetGroups,
    network: Option<NetworkField>,
    gui: Option<String>,
    proc: Option<schema::ProcField>,
    notify: Option<schema::NotifyField>,
    limits: Option<schema::RawLimits>,
    redact: Option<schema::RawRedact>,
    notes: &mut Vec<String>,
) -> (OverrideScalars, Vec<String>) {
    let mut fatal = Vec::new();
    let mut scalars = OverrideScalars::default();

    if let Some(field) = network {
        let stats = network_stats_of(&field);
        warn_if_baseline_sets_default_methods(notes, OVERRIDE_SOURCE, &field);
        // An override *references* the global config's groups and defines none of its own (its own
        // `groups` table is dropped where the override is collected). A mode-less table inherits
        // from `baseline`, and an `@ref` naming no group is dropped with a warning like anywhere
        // else — fail-closed in an `allow` list, which is where a one-shot reference belongs.
        match validate_network(notes, OVERRIDE_SOURCE, field, groups, baseline) {
            Some(policy) => scalars.network = Some((policy, stats)),
            None => fatal.push("network".to_string()),
        }
    }
    if let Some(value) = gui {
        match validate_gui(notes, OVERRIDE_SOURCE, value) {
            Some(policy) => scalars.gui = Some(policy),
            None => fatal.push("gui".to_string()),
        }
    }
    // `proc` — a mode-less `[proc]` table inherits `baseline_proc`'s mode (so a `--config` blob's
    // `[proc]\ndeny=[…]` keeps the effective mode); an *unknown* mode is fatal, exactly like `gui` —
    // keeping the baseline could leave *less* enforcement than the user's mistyped intent, a fail-open.
    if let Some(field) = proc {
        warn_unknown_proc_keys(notes, OVERRIDE_SOURCE, &field);
        match validate_proc(notes, OVERRIDE_SOURCE, field, baseline_proc) {
            Some(policy) => scalars.proc = Some(policy),
            None => fatal.push("proc".to_string()),
        }
    }
    // `notify` — a mode-less `[notify]` table inherits per event from `baseline_notify`; an *unknown*
    // mode is fatal, like `proc`. Keeping the baseline on a typo could leave a launch quieter than the
    // invoker's intent, which is the one direction this feature must never fail in.
    if let Some(field) = notify {
        warn_unknown_notify_keys(notes, OVERRIDE_SOURCE, &field);
        match validate_notify(notes, OVERRIDE_SOURCE, field, baseline_notify) {
            Some(policy) => scalars.notify = Some(policy),
            None => fatal.push("notify".to_string()),
        }
    }
    if let Some(raw_limits) = limits {
        // Which fields the override set — a set field that validates to `None` is invalid.
        let set = (
            raw_limits.memory_high.is_some(),
            raw_limits.memory_max.is_some(),
            raw_limits.tasks_max.is_some(),
        );
        let over = validate_limits(notes, OVERRIDE_SOURCE, Some(raw_limits));
        if set.0 && over.memory_high.is_none() {
            fatal.push("limits.memory_high".to_string());
        }
        if set.1 && over.memory_max.is_none() {
            fatal.push("limits.memory_max".to_string());
        }
        if set.2 && over.tasks_max.is_none() {
            fatal.push("limits.tasks_max".to_string());
        }
        scalars.limits = Some(over);
    }
    // `[redact] min_len` — a set-but-unusable value is fatal, like a limit: an override that meant
    // to move the floor and instead left the baseline's would watch this launch to a depth its
    // invoker did not choose.
    if let Some(value) = redact.and_then(|r| r.min_len) {
        match validate_redact_min_len(notes, OVERRIDE_SOURCE, value) {
            Some(floor) => scalars.redact_min_len = Some(floor),
            None => fatal.push("redact.min_len".to_string()),
        }
    }
    (scalars, fatal)
}

/// Assemble the hard-error message list for a one-shot override with invalid scalar values: a
/// summary naming the offending fields, then the specific validator notes (so the exact reason
/// survives the aborted launch, which discards `self.warnings`).
fn override_fatal_error(fatal: Vec<String>, notes: Vec<String>) -> Vec<String> {
    let fields = fatal
        .iter()
        .map(|f| format!("`{f}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut errs = vec![format!(
        "{OVERRIDE_SOURCE}: invalid value for {fields} — refusing to launch (a one-shot override \
         must be exact; it does not fall back to the baseline for a security field)"
    )];
    errs.extend(notes);
    errs
}

/// Answer the baseline credentials, split from [`apply_plugin_host_config`] so it can run **before**
/// the posture clear.
///
/// `resolve` snapshots `secrets` into `declared_secrets` at that point, and `merge_app` restores
/// that snapshot wholesale (`self.secrets = self.declared_secrets.clone()`) so an app opening a
/// filtering posture inherits a baseline credential the baseline posture had cleared. Answering the
/// whole table afterwards therefore answered a set the app path throws away: every inherited
/// baseline credential resolved through a plugin reached the launch with an empty `HostConfig`, so
/// the plugin ran with neither the configured environment nor its `nix:`-provisioned program —
/// under `sbx app run <name>` but not under `sbx run`, from one declaration.
///
/// The rest of the table (tasks, apps, brokers) is answered later because those are resolved after
/// the clear; `matched` is threaded through both halves so the "no secret uses a plugin by that
/// name" warning still sees the union.
fn apply_plugin_host_config_to_secrets(
    secrets: &mut [HeaderSecret],
    cfg: &BTreeMap<String, crate::config::schema::RawPluginConfig>,
    matched: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    if cfg.is_empty() {
        return;
    }
    apply_to_header_secrets(secrets, cfg, matched, warnings);
}

/// Attach the table to every plugin a wire credential reaches: the chain that resolves its value,
/// and the signer that forms one per request.
///
/// One function for all three sets of them — the baseline's, an app's, and a declared operation's
/// `[inject]` — because they were not. The signer half was written here for the baseline and
/// nowhere else, so an app's or a task's signed credential reached the launch with an empty
/// `HostConfig`: the plugin ran with neither the configured environment nor its `nix:`-provisioned
/// program, from a `[plugin.<name>]` table that was correct. The table was then reported as
/// matching no secret, which reads as a typo in a name that was in fact right.
fn apply_to_header_secrets(
    secrets: &mut [HeaderSecret],
    cfg: &BTreeMap<String, crate::config::schema::RawPluginConfig>,
    matched: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    for secret in secrets.iter_mut() {
        apply_to_sources(&mut secret.sources, cfg, matched, warnings);
        // A signer is a plugin this table configures too, and it is not one of the secret's
        // *sources*: it forms the value the sources resolved. Its manifest travels with the
        // declaration, so unlike a broker it is answered right here.
        if let Some(plugin) = secret.signer.as_mut()
            && let Some(raw) = cfg.get(&plugin.name)
        {
            matched.insert(plugin.name.clone());
            plugin.host = host_config_for(&plugin.name, &plugin.sandbox, raw, warnings);
        }
    }
}

/// Attach each `[plugin.<name>]` table to the plugin instances a task, an app or a broker
/// references, validating it against the manifest that instance carries.
///
/// The baseline credentials are answered by [`apply_plugin_host_config_to_secrets`] earlier, for
/// the reason stated there; these are the parts that are resolved only after the posture clear, and
/// `matched` is threaded in from that first half so the unmatched-table warning below sees both.
///
/// The manifest states what the plugin reads; the config supplies the values. So a variable the
/// manifest does not declare is **refused and dropped**, named — a config must not be able to put
/// an arbitrary variable into the environment of a third-party binary that runs host-side on the
/// plaintext path. Dropping rather than failing the launch keeps this additive-and-fail-closed
/// like every other config field: less is supplied, never more.
///
/// A table naming no installed plugin is reported too. It is almost always a typo, and staying
/// silent would leave the user waiting for settings that never applied.
fn apply_plugin_host_config(
    tasks: &mut [TaskSpec],
    apps: &mut BTreeMap<String, ResolvedApp>,
    brokers: &mut [BrokerBinding],
    plugins: &crate::plugins::PluginRegistry,
    cfg: &BTreeMap<String, crate::config::schema::RawPluginConfig>,
    matched: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    if cfg.is_empty() {
        return;
    }
    // A broker is configured by the same table and reached differently: it is not a secret's
    // source, so nothing here would ever see it. Its manifest lives in the registry, which is
    // read-only by now, so the answer is validated against that manifest and carried on the
    // binding for the launch to apply.
    for binding in brokers.iter_mut() {
        let (Some(raw), Some(plugin)) = (cfg.get(&binding.name), plugins.broker(&binding.name))
        else {
            continue;
        };
        matched.insert(binding.name.clone());
        binding.host = host_config_for(&binding.name, &plugin.sandbox, raw, warnings);
    }
    // A declared operation resolves its own credentials, through the same resolver chain, so a
    // plugin reached only from a `[task.<name>.secret]` needs the table just as much. Missing these
    // left such a plugin running with none of it *and* reported the table as matching no secret,
    // which reads as a typo in a name that was in fact correct.
    apply_to_tasks(tasks, cfg, matched, warnings);
    for app in apps.values_mut() {
        apply_to_header_secrets(&mut app.secrets, cfg, matched, warnings);
        apply_to_tasks(&mut app.tasks, cfg, matched, warnings);
    }
    for (name, table) in cfg {
        // Named, not refused at the parse layer: `deny_unknown_fields` here failed the whole
        // config file over one mistyped key, taking every declaration written beside it.
        for key in table.rest.keys() {
            warnings.push(format!(
                "`[plugin.{name}]`: ignoring unknown key `{key}` — the table supplies `env` and \
                 `programs`, and the plugin reads nothing else from it"
            ));
        }
        if !matched.contains(name) {
            warnings.push(format!(
                "`[plugin.{name}]`: no secret uses a plugin by that name — check the spelling \
                 against `sbx plugins list` (the table is otherwise inert)"
            ));
        }
    }
}

/// Attach the table to every plugin a declared operation reaches: the credentials its command reads
/// from its environment, and the ones its own proxy injects on the wire. Both resolve host-side
/// through the same chain, so both see the same host answer.
fn apply_to_tasks(
    tasks: &mut [TaskSpec],
    cfg: &BTreeMap<String, crate::config::schema::RawPluginConfig>,
    matched: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    for task in tasks.iter_mut() {
        for secret in task.secrets.iter_mut() {
            apply_to_sources(&mut secret.sources, cfg, matched, warnings);
        }
        apply_to_header_secrets(&mut task.injections, cfg, matched, warnings);
    }
}

/// Attach the table to every plugin instance in one source chain. Split out of
/// [`apply_plugin_host_config`] so the `matched` set can outlive each call without a closure
/// capturing it by reference across iterations.
fn apply_to_sources(
    sources: &mut [SecretSource],
    cfg: &BTreeMap<String, crate::config::schema::RawPluginConfig>,
    matched: &mut BTreeSet<String>,
    warnings: &mut Vec<String>,
) {
    for source in sources.iter_mut() {
        let SecretSource::Plugin { plugin, .. } = source else {
            continue;
        };
        let Some(raw) = cfg.get(&plugin.name) else {
            continue;
        };
        matched.insert(plugin.name.clone());
        plugin.host = host_config_for(&plugin.name, &plugin.sandbox, raw, warnings);
    }
}

/// One `[plugin.<name>]` table, validated against the manifest grant of the plugin it names.
///
/// The manifest states what the plugin reads; the config supplies the values. So a variable the
/// manifest does not declare is refused and dropped, named. One function for every plugin type,
/// because `[plugin.<name>]` means the same thing whatever the plugin does with it, and because a
/// second copy is how one type would come to accept what another refuses.
fn host_config_for(
    name: &str,
    grant: &crate::plugins::SandboxGrant,
    raw: &crate::config::schema::RawPluginConfig,
    warnings: &mut Vec<String>,
) -> crate::plugins::HostConfig {
    let mut env = Vec::new();
    for (key, value) in &raw.env {
        let declared = grant.allow_env.iter().any(|k| k == key)
            || grant.allow_env_paths.iter().any(|k| k == key);
        if declared {
            env.push((key.clone(), value.clone()));
        } else {
            warnings.push(format!(
                "`[plugin.{name}] env`: ignoring `{key}` — the plugin's manifest does not read it \
                 (it declares: {})",
                declared_vars_of(grant)
            ));
        }
    }
    let programs = validated_programs(name, &grant.programs, &raw.programs, warnings);
    crate::plugins::HostConfig { env, programs }
}

/// The `programs` entries of one `[plugin.<name>]` table, keeping those the manifest can actually
/// use and naming every one it drops.
///
/// Two rules, both fail-closed, and neither is a formality:
///
/// - the key must be a program the **manifest declares**. `programs` in a manifest is the list of
///   host tools that plugin runs, and a launch binds exactly those under one directory; naming
///   anything else here would ask sbx to build a package no plugin would ever invoke.
/// - the value must carry the `nix:` prefix. It is the only backend that can be built host-side,
///   project-independently, at the moment a plugin is installed: `mise:` is equipped *inside* a
///   cage and the prebuilt backends are pinned per project. Refusing the others by name is what
///   keeps this from reading as a general backend selector that happens to support one backend.
/// - the attribute must be one, by the same rule `[packages]` applies to the same `nix:<attr>`
///   syntax. It is not a new policy but the one this value already obeys one table over: what
///   follows `nix:` here is interpolated into the `--expr` of the unfree provisioning branch
///   ([`crate::store::provision_unfree`] and the command it builds), which is exactly what that
///   rule exists to keep clean.
///   The entry is dropped with its reason rather than failing the load, like the two rules above:
///   the program then reads as unprovisioned, and the launch says so fail-closed.
pub(crate) fn validated_programs(
    plugin_name: &str,
    manifest_programs: &[String],
    raw: &BTreeMap<String, String>,
    warnings: &mut Vec<String>,
) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(raw.len());
    for (program, locator) in raw {
        if !manifest_programs.iter().any(|p| p == program) {
            let declared = if manifest_programs.is_empty() {
                "none".to_string()
            } else {
                manifest_programs.join(", ")
            };
            warnings.push(format!(
                "`[plugin.{plugin_name}] programs`: ignoring `{program}` — the plugin's manifest \
                 does not run it (it declares: {declared})"
            ));
            continue;
        }
        let Some(attr) = locator.strip_prefix("nix:").filter(|a| !a.is_empty()) else {
            warnings.push(format!(
                "`[plugin.{plugin_name}] programs`: ignoring `{program} = \"{locator}\"` — only a \
                 `nix:<attribute>` value can be provisioned for a plugin"
            ));
            continue;
        };
        if !is_valid_attr(attr) {
            warnings.push(format!(
                "`[plugin.{plugin_name}] programs`: ignoring `{program} = \"{locator}\"` — \
                 `{attr}` is not a nix attribute"
            ));
            continue;
        }
        out.push((program.clone(), attr.to_string()));
    }
    out
}

/// The variables a plugin's manifest says it reads, for a diagnostic that names the alternatives
/// instead of only what was rejected. Takes the grant rather than a plugin, so the answer is the
/// same for every type that carries one.
fn declared_vars_of(grant: &crate::plugins::SandboxGrant) -> String {
    let mut all: Vec<&str> = grant
        .allow_env
        .iter()
        .chain(grant.allow_env_paths.iter())
        .map(String::as_str)
        .collect();
    all.sort_unstable();
    if all.is_empty() {
        "none".to_string()
    } else {
        all.join(", ")
    }
}

/// Layer the global config (trusted by location) under the project config, gating
/// the project's security-relevant fields by its trust verdict. Pure: the policy
/// matrix is decided here from already-read inputs.
///
/// Free fields (`env`) apply from any project, minus the reserved-key denylist for
/// an untrusted one. Security fields (`binds`) apply only from a trusted project;
/// an untrusted or since-changed project's binds are dropped with a warning.
fn resolve(
    mut global: RawConfig,
    mut project: Option<(RawConfig, TrustState)>,
    plugins: &PluginRegistry,
) -> Resolved {
    // Lift the app overlays out before the baseline fields are consumed below; they are
    // resolved and gated on their own at the end (each app a self-contained overlay).
    let global_apps = std::mem::take(&mut global.app);
    let project_apps = project
        .as_mut()
        .map(|(proj, state)| (std::mem::take(&mut proj.app), *state));

    let mut warnings = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut env_layer: BTreeMap<String, Provenance> = BTreeMap::new();
    let mut binds: Vec<Bind> = Vec::new();
    let mut bind_layer: BTreeMap<PathBuf, Provenance> = BTreeMap::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut accepts_fresh_releases: Vec<String> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();

    // Reusable egress groups are defined only in the global config (trusted by location) and
    // pre-classified once here; a `[network]` `allow`/`deny` list references one with `@<name>`.
    // A project's `[network.groups]` is a security-relevant input it may not supply, so it is
    // ignored. Both are *taken* out of the raw layer: the only `groups` table that may be read is
    // this one, so every table that still carries one when it reaches validation is declared at a
    // layer that cannot define groups, and is reported there.
    let net_groups = build_net_groups(&mut warnings, take_net_groups(&mut global.network));
    if let Some((proj, _)) = &mut project
        && !take_net_groups(&mut proj.network).is_empty()
    {
        warnings.push(format!(
            "{PROJECT_CONFIG}: ignoring `groups` under `[network]` — egress groups are defined in \
             the global config only; a project's `[network]` may reference them with `@<name>`"
        ));
    }

    // Say what was passed over before anything is applied, so a misspelled field is named next to
    // the values that did take effect rather than inferred from their absence.
    warn_unknown_keys(&mut warnings, GLOBAL_CONFIG, &global);
    // The global config is trusted by location, so it is honored in full: no
    // denylist, only key validation and the absolute-bind requirement.
    apply_env(
        &mut env,
        Some((Provenance::Global, &mut env_layer)),
        &mut warnings,
        GLOBAL_CONFIG,
        global.env,
        false,
    );
    apply_binds(
        &mut binds,
        Some((Provenance::Global, &mut bind_layer)),
        &mut warnings,
        GLOBAL_CONFIG,
        global.binds,
    );
    // Per-plugin settings, global layer: trusted by location, so taken in full.
    let mut plugin_cfg: BTreeMap<String, crate::config::schema::RawPluginConfig> =
        std::mem::take(&mut global.plugin);
    // URI handlers, global layer: trusted by location, so validated and taken.
    let mut open = validate_open(
        &mut warnings,
        GLOBAL_CONFIG,
        std::mem::take(&mut global.open),
    );
    // Auxiliary services, global layer: trusted by location, so validated and taken.
    let mut service = validate_service(
        &mut warnings,
        GLOBAL_CONFIG,
        std::mem::take(&mut global.service),
    );
    // Broker bindings, global layer: the only layer that may name a host resource.
    let mut broker_cfg: BTreeMap<String, crate::config::schema::RawBrokerConfig> =
        std::mem::take(&mut global.broker);
    let mut broker_origin: BTreeMap<String, Provenance> = broker_cfg
        .keys()
        .map(|name| (name.clone(), Provenance::Global))
        .collect();
    // `allow_insecure_http` resolves HERE, ahead of every `apply_tools`, and the ordering is the
    // substance rather than a detail. This flag decides how a package *value* is validated, so both
    // operands — the flag and the locator — have to be in hand before the first layer's tools are
    // parsed. The scalar postures further down resolve *after* the global layer's tools, which is
    // harmless for a value the cage merely displays and would be a silent hole here: a global
    // `[packages]` entry would be checked against a flag the project had not yet supplied, and the
    // layer that wrote `allow_insecure_http = true` would find it applied to its own packages and
    // not to the ones it inherited.
    //
    // A security field: taken from the global config (trusted by location) and from a *trusted*
    // project, refused with a warning from an untrusted or changed one — an untrusted layer must not
    // be able to downgrade the transport its own artefacts arrive over.
    let mut allow_insecure_http_origin = Provenance::Default;
    let mut allow_insecure_http = match global.allow_insecure_http {
        Some(value) => {
            allow_insecure_http_origin = Provenance::Global;
            value
        }
        None => false,
    };
    if let Some((proj, state)) = project.as_ref()
        && let Some(value) = proj.allow_insecure_http
    {
        if *state == TrustState::Trusted {
            allow_insecure_http = value;
            allow_insecure_http_origin = Provenance::Project;
        } else {
            refuse_untrusted(
                &mut warnings,
                PROJECT_CONFIG,
                "`allow_insecure_http`",
                *state,
            );
        }
    }
    apply_tools(
        &mut packages,
        &mut warnings,
        GLOBAL_CONFIG,
        global.packages,
        global.flakes,
        global.tarball,
        global.deb,
        global.appimage,
        global.binary,
        TrustState::Trusted,
        false,
        allow_insecure_http,
    );
    apply_fresh_releases(
        &mut accepts_fresh_releases,
        &mut warnings,
        GLOBAL_CONFIG,
        global.accepts_fresh_releases,
        TrustState::Trusted,
    );
    let nixpkgs_global = global
        .nixpkgs
        .and_then(|v| validate_nixpkgs(&mut warnings, GLOBAL_CONFIG, v));
    // The locator and the credential reference travel as one value through both layers: a
    // credential belongs to the image it was written for, so a project that replaces the image
    // replaces the credential with it rather than inheriting one meant for another registry.
    let mut distro_origin = Provenance::Default;
    let mut distro_decl = global
        .distro
        .and_then(|v| validate_distro(&mut warnings, GLOBAL_CONFIG, v));
    if distro_decl.is_some() {
        distro_origin = Provenance::Global;
    }
    // Global-only, like `[bundle]`: the engine installs every `mise:` tool in every cage, so a
    // project does not get to redirect it. The project layer's own `[mise]` is never read here.
    let mise_engine = global
        .mise
        .and_then(|m| m.engine)
        .and_then(|v| validate_mise_engine(&mut warnings, GLOBAL_CONFIG, v));
    // The network posture is trusted by location at the global layer; an invalid or
    // unset value falls back to the default (the deny-by-default allowlist). The origin is
    // recorded as `Global` only when the layer actually supplied a valid posture, so a `Default`
    // is never mistaken for one.
    let mut network_origin = Provenance::Default;
    // The egress-stats toggle rides the `[network]` table (the global layer is trusted by location);
    // extract it before the field moves into `validate_network`. Default on. Committed below, once
    // the table is known to be accepted: a rejected `[network]` leaves the posture at the built-in
    // default, and the toggle written beside it must not be the one half of it that still lands —
    // the same rule the project layer applies.
    let mut egress_stats = true;
    let global_stats = global.network.as_ref().and_then(network_stats_of);
    if let Some(field) = global.network.as_ref() {
        warn_if_baseline_sets_default_methods(&mut warnings, GLOBAL_CONFIG, field);
    }
    // The parent of the global layer is sbx's built-in default (the `deny` allowlist): a global
    // `[network]` table that omits `mode` has no lower posture to inherit, so it stays on `deny`.
    let mut network = match global.network.and_then(|v| {
        validate_network(
            &mut warnings,
            GLOBAL_CONFIG,
            v,
            &net_groups,
            &NetworkPolicy::default(),
        )
    }) {
        Some(policy) => {
            network_origin = Provenance::Global;
            policy
        }
        None => NetworkPolicy::default(),
    };
    if network_origin == Provenance::Global
        && let Some(b) = global_stats
    {
        egress_stats = b;
    }
    // The GUI posture is trusted by location at the global layer; an invalid or unset value
    // falls back to the default (no display).
    // The process/exec posture is trusted by location at the global layer. `parent` is the built-in
    // default (off) — the global layer has no lower config to inherit a table's omitted mode from.
    let mut proc_origin = Provenance::Default;
    let mut proc = match global.proc.and_then(|v| {
        warn_unknown_proc_keys(&mut warnings, GLOBAL_CONFIG, &v);
        validate_proc(
            &mut warnings,
            GLOBAL_CONFIG,
            v,
            &crate::proc_policy::ProcPolicy::off(),
        )
    }) {
        Some(policy) => {
            proc_origin = Provenance::Global;
            policy
        }
        None => crate::proc_policy::ProcPolicy::off(),
    };
    // The notification policy is trusted by location at the global layer. `parent` is the built-in
    // default (every event `always`) — the global layer has no lower config to inherit from.
    let mut notify_origin = Provenance::Default;
    let mut notify = match global.notify.and_then(|v| {
        warn_unknown_notify_keys(&mut warnings, GLOBAL_CONFIG, &v);
        validate_notify(&mut warnings, GLOBAL_CONFIG, v, &Default::default())
    }) {
        Some(policy) => {
            notify_origin = Provenance::Global;
            policy
        }
        None => crate::notify::NotifyPolicy::default(),
    };
    let mut gui_origin = Provenance::Default;
    let mut gui = match global
        .gui
        .and_then(|v| validate_gui(&mut warnings, GLOBAL_CONFIG, v))
    {
        Some(policy) => {
            gui_origin = Provenance::Global;
            policy
        }
        None => GuiPolicy::default(),
    };
    // The zone. Not a security field, so the layering is the plain scalar one — but the global
    // layer is where it usually belongs: a machine sits in one place, and every project on it
    // inherits that.
    let mut timezone_origin = Provenance::Default;
    let mut timezone = global
        .timezone
        .and_then(|v| validate_timezone(&mut warnings, GLOBAL_CONFIG, v))
        .inspect(|_| timezone_origin = Provenance::Global);
    // The GPU posture is trusted by location at the global layer; the origin records `Global`
    // whenever the layer set the flag at all (so `gpu = true` reads distinctly from the default).
    let mut gpu_origin = Provenance::Default;
    let mut gpu = match global.gpu {
        Some(value) => {
            gpu_origin = Provenance::Global;
            value
        }
        None => false,
    };
    // The audio posture is trusted by location at the global layer; the origin records `Global`
    // whenever the layer set the flag at all (so `audio = true` reads distinctly from the default).
    let mut audio_origin = Provenance::Default;
    let mut audio = match global.audio {
        Some(value) => {
            audio_origin = Provenance::Global;
            value
        }
        None => false,
    };
    // The D-Bus posture is trusted by location at the global layer; the origin records `Global`
    // whenever the layer set the flag at all (so `dbus = true` reads distinctly from the default).
    let mut dbus_origin = Provenance::Default;
    let mut dbus = match global.dbus {
        Some(value) => {
            dbus_origin = Provenance::Global;
            value
        }
        None => false,
    };
    // `forward` entries are trusted by location at the global layer; each invalid one is dropped
    // (warned) and the rest kept. The merged set is a union keyed by cage port (a project adds
    // forwards, and may move one to another host port, but never closes one), so the origin is
    // `Global` only when this layer contributed any entry.
    let mut forward_origin = Provenance::Default;
    let mut forward = global
        .forward
        .as_deref()
        .map(|r| validate_forward(&mut warnings, GLOBAL_CONFIG, r))
        .unwrap_or_default();
    if !forward.is_empty() {
        forward_origin = Provenance::Global;
    }
    // The redaction floor is trusted by location at the global layer; an unusable value is dropped
    // (warned) and the built-in floor kept.
    let mut redact_min_len = crate::sandbox::redact::MIN_LEN_DEFAULT;
    let mut redact_min_len_origin = Provenance::Default;
    if let Some(value) = global.redact.as_ref().and_then(|r| r.min_len)
        && let Some(floor) = validate_redact_min_len(&mut warnings, GLOBAL_CONFIG, value)
    {
        redact_min_len = floor;
        redact_min_len_origin = Provenance::Global;
    }
    // Resource limits are trusted by location at the global layer; each invalid field is dropped
    // (warned) and the built-in default kept. The origin is recorded per field that the layer set.
    let mut limits = validate_limits(&mut warnings, GLOBAL_CONFIG, global.limits);
    let mut limits_origin = LimitsOrigin::default();
    mark_limit_origins(&mut limits_origin, &limits, Provenance::Global);
    // The seccomp relaxation is trusted by location at the global layer; a bad `allow` entry is
    // dropped (warned) and the rest kept. A project's unions onto this, so the origin records
    // `Global` only when this layer actually lifted something.
    let mut seccomp = apply_seccomp(&mut warnings, GLOBAL_CONFIG, global.seccomp);
    let mut seccomp_origin = if seccomp.is_empty() {
        Provenance::Default
    } else {
        Provenance::Global
    };
    // The device grant is trusted by location at the global layer; a bad entry is dropped (warned)
    // and the rest kept. A project's unions onto this, so the origin records `Global` only when this
    // layer actually granted a device.
    let mut devices = apply_devices(&mut warnings, GLOBAL_CONFIG, global.devices);
    let mut devices_origin = if devices.is_empty() {
        Provenance::Default
    } else {
        Provenance::Global
    };
    // The `[fs]` masks from the global layer. Ungated (they only close paths), and layered like the
    // device grant: a project's set unions onto this, so a layer can close more and never less.
    let mut fs = apply_fs(&mut warnings, GLOBAL_CONFIG, global.fs);
    let mut fs_origin = if fs.declares_nothing() {
        Provenance::Default
    } else {
        Provenance::Global
    };
    // The ssh-agent grant is trusted by location at the global layer, and layers like the device
    // grant: a bad entry is dropped (warned), a project's unions onto this.
    let (mut ssh_agent, mut ssh_agent_confirm) =
        apply_ssh_agent(&mut warnings, GLOBAL_CONFIG, global.ssh_agent);
    let mut ssh_agent_origin = if ssh_agent.is_empty() {
        Provenance::Default
    } else {
        Provenance::Global
    };
    // Secrets are trusted by location at the global layer. The `[secret.defaults]` table is
    // captured for the global hosts and as the base a trusted project may extend.
    let mut secret_defaults = SecretDefaults::default();
    if let Some(section) = global.secret {
        if let Some(raw_defaults) = &section.defaults {
            secret_defaults = SecretDefaults::from_raw(raw_defaults);
            warn_resolver_bindings(&mut warnings, GLOBAL_CONFIG, raw_defaults, plugins);
        }
        apply_secret_section(
            &mut secrets,
            &mut warnings,
            GLOBAL_CONFIG,
            section.hosts,
            &secret_defaults,
            plugins,
        );
    }

    // Tasks are trusted by location at the global layer, like secrets. `[task.defaults]` is captured
    // as the base a trusted project may override field by field.
    let mut tasks: Vec<TaskSpec> = Vec::new();
    let mut task_defaults = tasks::TaskDefaults::default();
    if let Some(section) = global.task {
        // One value for the layer, so the ceilings it sets and the operations it declares can never
        // disagree about which config they came from.
        let layer = tasks::TaskLayer {
            source: GLOBAL_CONFIG,
            origin: TaskOrigin::Global,
        };
        if let Some(raw_defaults) = &section.defaults {
            task_defaults = task_defaults.merged_with(raw_defaults, &layer, &mut warnings);
        }
        warn_unknown_task_keys(&mut warnings, GLOBAL_CONFIG, &section);
        tasks::apply_task_section(
            &mut tasks,
            &mut warnings,
            &layer,
            section,
            &task_defaults,
            &secret_defaults,
            plugins,
        );
    }

    let mut nixpkgs_project = None;
    // The secret resolver defaults a PROJECT-LOCAL app resolves against: the global defaults, plus
    // a trusted project's own `[secret.defaults]` (captured below), so an app declared in the
    // project's `.sbx.toml` honors the project's resolver order/bindings. A GLOBAL app keeps the
    // global defaults, so a project can never steer how a globally-declared app's credentials
    // resolve. Stays global when there is no project or the project sets no `[secret.defaults]`.
    let mut project_secret_defaults = secret_defaults.clone();
    if let Some((proj, state)) = project {
        let trusted = state == TrustState::Trusted;
        let gate = Gate {
            trusted,
            state,
            source: PROJECT_CONFIG,
        };
        // Reported for an untrusted project too: an unknown key is a spelling question, not a
        // capability, so withholding the answer would only leave the author guessing.
        warn_unknown_keys(&mut warnings, PROJECT_CONFIG, &proj);
        // `env` is a free field — applied from any project, minus the reserved-key
        // denylist for an untrusted or changed one.
        apply_env(
            &mut env,
            Some((Provenance::Project, &mut env_layer)),
            &mut warnings,
            PROJECT_CONFIG,
            proj.env,
            !trusted,
        );
        // `binds` is a security field — honored only from a trusted project.
        if !proj.binds.is_empty() {
            if trusted {
                apply_binds(
                    &mut binds,
                    Some((Provenance::Project, &mut bind_layer)),
                    &mut warnings,
                    PROJECT_CONFIG,
                    proj.binds,
                );
            } else {
                warnings.push(dropped_binds_warning(state, proj.binds.len()));
            }
        }
        // `packages` are carried with the project's trust stamped on each — never
        // dropped here. Whether an untrusted project's tools are actually realised
        // is the launcher's call, the one place that can weigh it against the work
        // a tool would have to build.
        // `[plugin.*]` is a security field: it can trigger a build and set the environment of a
        // binary that runs host-side on the plaintext path. A trusted project layers its tables
        // over the global ones by plugin name; an untrusted one is dropped, named rather than
        // silently ignored so the difference between "not configured" and "not trusted" is
        // visible.
        // `[broker.*]` is a security field: it decides which host resource the cage may reach
        // through a plugin. A trusted project may set the **policy** for a broker the global
        // config already bound; it may not name a socket, and it may not introduce a broker the
        // global config never bound — either would let a project choose what is exposed.
        if !proj.broker.is_empty() {
            if trusted {
                for (name, table) in proj.broker.clone() {
                    if table.socket.is_some() {
                        warnings.push(format!(
                            "{PROJECT_CONFIG}: ignoring `[broker.{name}] socket` — which host \
                             resource a broker stands in front of is declared in the global \
                             config, beside the plugin's installation"
                        ));
                    }
                    // `secret` is global-only for a sharper version of the same reason, so it is
                    // named for the same reason: the two fields are dropped side by side, and
                    // saying so for one and not the other left a project author watching a
                    // credential they had declared never reach the wire, with nothing said.
                    if table.secret.is_some() {
                        warnings.push(format!(
                            "{PROJECT_CONFIG}: ignoring `[broker.{name}] secret` — the credential \
                             a broker places on the wire is declared in the global config, beside \
                             the plugin's installation"
                        ));
                    }
                    // Only the global tables reach `resolve_brokers`, which reports its own
                    // unknown keys; a project table is folded into the bound one field by field,
                    // so a key misspelled here would otherwise be seen by nothing.
                    for key in table.rest.keys() {
                        warnings.push(format!(
                            "{PROJECT_CONFIG}: ignoring unknown key `{key}` in `[broker.{name}]`"
                        ));
                    }
                    match broker_cfg.get_mut(&name) {
                        Some(bound) => {
                            // Only a project that actually wrote `allow` replaces the global
                            // policy. The two cases a bare list could not tell apart are opposite
                            // intentions — a table written for its `socket` alone (dropped just
                            // above) would otherwise clear the policy the global config declared,
                            // and `sbx config` would then attribute the empty list to the project.
                            // An explicit `allow = []` is still a project choice and still lands.
                            if let Some(allow) = table.allow {
                                bound.allow = Some(allow);
                                broker_origin.insert(name, Provenance::Project);
                            }
                        }
                        None => warnings.push(format!(
                            "{PROJECT_CONFIG}: ignoring `[broker.{name}]` — no `[broker.{name}] \
                             socket` in the global config, so nothing binds that broker to a host \
                             resource"
                        )),
                    }
                }
            } else {
                let mut names: Vec<&str> = proj.broker.keys().map(String::as_str).collect();
                names.sort_unstable();
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `[broker.*]` ({}) — it decides what a cage may \
                     reach through a broker plugin, so it is honored only from a trusted project \
                     (`sbx trust`)",
                    names.join(", ")
                ));
            }
        }
        // `[open]` is a security field — a trusted project may say what its links open with; an
        // untrusted one may not, or it would decide where a sign-in click lands.
        if !proj.open.is_empty() {
            if trusted {
                open.extend(validate_open(
                    &mut warnings,
                    PROJECT_CONFIG,
                    proj.open.clone(),
                ));
            } else {
                gate.refuse("`[open]` URI handlers", &mut warnings);
            }
        }
        // `[service]` is a security field for the plainest reason of all: an entry runs a program
        // at every launch. That is the grant an untrusted project is already refused for `cmd`.
        if !proj.service.is_empty() {
            if trusted {
                service.extend(validate_service(
                    &mut warnings,
                    PROJECT_CONFIG,
                    proj.service.clone(),
                ));
            } else {
                gate.refuse("`[service]` auxiliary processes", &mut warnings);
            }
        }
        if !proj.plugin.is_empty() {
            if trusted {
                plugin_cfg.extend(proj.plugin.clone());
            } else {
                let mut names: Vec<&str> = proj.plugin.keys().map(String::as_str).collect();
                names.sort_unstable();
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `[plugin.*]` ({}) — it can provision a \
                     program and set the environment of a host-side resolver, so it is \
                     honored only from a trusted project (`sbx trust`)",
                    names.join(", ")
                ));
            }
        }
        apply_tools(
            &mut packages,
            &mut warnings,
            PROJECT_CONFIG,
            proj.packages,
            proj.flakes,
            proj.tarball,
            proj.deb,
            proj.appimage,
            proj.binary,
            state,
            false,
            allow_insecure_http,
        );
        apply_fresh_releases(
            &mut accepts_fresh_releases,
            &mut warnings,
            PROJECT_CONFIG,
            proj.accepts_fresh_releases,
            state,
        );
        // `nixpkgs` is a security field — a trusted project may pin its tools'
        // source; an untrusted or changed one may not point the catalogue elsewhere.
        if let Some(value) = proj.nixpkgs {
            if trusted {
                nixpkgs_project = validate_nixpkgs(&mut warnings, PROJECT_CONFIG, value);
            } else {
                gate.refuse("`nixpkgs` override", &mut warnings);
            }
        }
        // `distro` is a security field — a trusted project may put the cage on its own
        // distribution userland; an untrusted or changed one may not choose the root filesystem
        // every program in the cage is executed from.
        if let Some(value) = proj.distro {
            // A userland is whole or absent, so the locator inherits nothing from the layer
            // below: a malformed value leaves the global one standing rather than stranding the
            // cage between two substrates.
            gate.take_validated(
                &mut distro_decl,
                &mut distro_origin,
                "`distro` userland",
                &mut warnings,
                |w, _| validate_distro(w, PROJECT_CONFIG, value).map(Some),
            );
        }
        // `network` is a security field — a trusted project may change the posture;
        // an untrusted or changed one may not narrow or widen the network.
        if let Some(value) = proj.network {
            // The stats toggle rides the same trusted `[network]` table, so it is read before the
            // field moves into `validate_network` — but committed only if that table is *accepted*.
            // Setting it inside the closure meant a rejected table (an unknown mode, a bad
            // allowlist) left the posture untouched and still turned the egress audit off: half of
            // a table that was refused whole. An untrusted project never reaches here.
            let stats = network_stats_of(&value);
            let mut accepted = false;
            gate.take_validated(
                &mut network,
                &mut network_origin,
                "`network` policy",
                &mut warnings,
                // `parent` is the posture as it stands after the global layer: a project
                // `[network]` table without a `mode` inherits it.
                |w, parent| {
                    warn_if_baseline_sets_default_methods(w, PROJECT_CONFIG, &value);
                    let policy = validate_network(w, PROJECT_CONFIG, value, &net_groups, parent);
                    accepted = policy.is_some();
                    policy
                },
            );
            if accepted && let Some(b) = stats {
                egress_stats = b;
            }
        }
        // `proc` is a security field — a trusted project may set its agent's exec posture; an
        // untrusted or changed one may not forge or loosen the enforcement of its own agent.
        if let Some(value) = proj.proc {
            // `parent` is the posture after the global layer: a `[proc]` table without a `mode`
            // inherits it.
            gate.take_validated(
                &mut proc,
                &mut proc_origin,
                "`proc` policy",
                &mut warnings,
                |w, parent| {
                    warn_unknown_proc_keys(w, PROJECT_CONFIG, &value);
                    validate_proc(w, PROJECT_CONFIG, value, parent)
                },
            );
        }
        // `notify` is a security field — a trusted project may tune how loudly its own refusals are
        // announced; an untrusted one may not, since silencing the notification is the cheapest way
        // to make a boundary look like it never bit.
        if let Some(value) = proj.notify {
            // A `[notify]` table without a `mode` inherits from `parent` per event, so refining
            // one lens leaves the others as the global layer set them.
            gate.take_validated(
                &mut notify,
                &mut notify_origin,
                "`notify` policy",
                &mut warnings,
                |w, parent| {
                    warn_unknown_notify_keys(w, PROJECT_CONFIG, &value);
                    validate_notify(w, PROJECT_CONFIG, value, parent)
                },
            );
        }
        // `gui` is a security field — a trusted project may open a display; an untrusted or
        // changed one may not (exposing a compositor socket is a confidentiality and integrity
        // choice an untrusted project must not make).
        if let Some(value) = proj.gui {
            // `gui` inherits nothing from the layer below — a posture is whole or absent.
            gate.take_validated(
                &mut gui,
                &mut gui_origin,
                "`gui` posture",
                &mut warnings,
                |w, _| validate_gui(w, PROJECT_CONFIG, value),
            );
        }
        // `timezone` is **not** a security field, so it applies whatever the project's verdict —
        // the same treatment `[env]` gets, and for the same reason: the value travels one way (it
        // tells the cage what to display, and reads nothing from the host), and a project can
        // already set `TZ` through `[env]`, which is free. Gating this one would only leave the
        // clock and the `/etc/localtime` link disagreeing.
        if let Some(value) = proj.timezone
            && let Some(zone) = validate_timezone(&mut warnings, PROJECT_CONFIG, value)
        {
            timezone = Some(zone);
            timezone_origin = Provenance::Project;
        }
        // `gpu` is a security field — a trusted project may open GPU rendering; an untrusted or
        // changed one may not (a render node and the `/sys` device tree widen the kernel attack
        // surface, a choice an untrusted project must not make).
        if let Some(value) = proj.gpu {
            gate.take(
                &mut gpu,
                &mut gpu_origin,
                "`gpu` posture",
                value,
                &mut warnings,
            );
        }
        // `audio` is a security field — a trusted project may open audio; an untrusted or changed one
        // may not (the PulseAudio bus exposes the microphone and every system-audio `.monitor`
        // source, a choice an untrusted project must not make).
        if let Some(value) = proj.audio {
            gate.take(
                &mut audio,
                &mut audio_origin,
                "`audio` posture",
                value,
                &mut warnings,
            );
        }
        // `dbus` is a security field — a trusted project may stand up the in-cage portal; an
        // untrusted or changed one may not (a session bus, near the keyring and the portals, is a
        // choice an untrusted project must not make).
        if let Some(value) = proj.dbus {
            gate.take(
                &mut dbus,
                &mut dbus_origin,
                "`dbus` posture",
                value,
                &mut warnings,
            );
        }
        // `forward` is a security field — a trusted project may add host loopback forward ports;
        // an untrusted or changed one may not (opening a host port is a deliberate inbound hole).
        // The ports union onto the global set: a project adds, never replaces (the flagship
        // property holds because the untrusted contribution is dropped here, before the union).
        if let Some(raw) = proj.forward {
            gate.union(
                &mut forward,
                &mut forward_origin,
                "`forward` ports",
                &mut warnings,
                |w| validate_forward(w, PROJECT_CONFIG, &raw),
                union_forward,
            );
        }
        // `[redact]` is a security field — a trusted project may move the floor its own credentials
        // are watched from; an untrusted or changed one may not, since raising it would drop those
        // credentials out of the tripwires that are watching *its* egress. A scalar: a trusted
        // project's value replaces the global one.
        if let Some(raw) = proj.redact {
            if trusted {
                if let Some(value) = raw.min_len
                    && let Some(floor) =
                        validate_redact_min_len(&mut warnings, PROJECT_CONFIG, value)
                {
                    redact_min_len = floor;
                    redact_min_len_origin = Provenance::Project;
                }
            } else {
                gate.refuse("`[redact]`", &mut warnings);
            }
        }
        // `[limits]` is a security field — a trusted project may tune the cgroup limits; an
        // untrusted or changed one may not (loosening them weakens the anti-DoS control). The
        // three fields layer independently: a project's set field overrides the global one, an
        // unset field keeps the global (or built-in) value — the `env` model, not a wholesale
        // replace, since each limit is a standalone scalar with its own default.
        if let Some(raw) = proj.limits {
            if trusted {
                let project_limits = validate_limits(&mut warnings, PROJECT_CONFIG, Some(raw));
                mark_limit_origins(&mut limits_origin, &project_limits, Provenance::Project);
                overlay_limits(&mut limits, project_limits);
            } else {
                gate.refuse("`[limits]`", &mut warnings);
            }
        }
        // `[seccomp]` is a security field — a trusted project may relax the denylist; an untrusted
        // or changed one may not (loosening the kernel-attack-surface control). The relaxation
        // unions onto the global set: a project adds lifts, never removes (the flagship property
        // holds because the untrusted contribution is dropped here, before the union).
        if let Some(raw) = proj.seccomp {
            if trusted {
                let project_seccomp = apply_seccomp(&mut warnings, PROJECT_CONFIG, Some(raw));
                if !project_seccomp.is_empty() {
                    seccomp_origin = Provenance::Project;
                }
                seccomp.union(&project_seccomp);
            } else {
                gate.refuse("`[seccomp]`", &mut warnings);
            }
        }
        // `[devices]` is a security field — a trusted project may grant a host device; an untrusted
        // or changed one may not (exposing a device widens the kernel attack surface). The grant
        // unions onto the global set: a project adds devices, never removes (the flagship property
        // holds because the untrusted contribution is dropped here, before the union).
        if let Some(raw) = proj.devices {
            gate.union(
                &mut devices,
                &mut devices_origin,
                "`[devices]`",
                &mut warnings,
                |w| apply_devices(w, PROJECT_CONFIG, Some(raw)),
                union_devices,
            );
        }
        // `[fs]` is the one table whose *masks* need no trust gate: they can only take access away
        // from the cage the project itself declares, so an untrusted project closing its own files
        // off gains nothing it could turn on the user — while dropping them would leave a file the
        // project asked to close wide open, which is the failure that actually matters. Unions onto
        // the global set, like `[devices]`.
        //
        // `scan_max_kb` is the exception, and the only
        // gated key in the table: it is not a mask but a ceiling on how many bytes of a file the
        // content lens *reads* before letting the open through, so lowering it closes fewer files.
        // An untrusted project setting `scan_max_kb = 1` therefore widens what its cage may read
        // past, which is the one direction the exemption above does not cover. Stripped and named
        // rather than left to lose a fold, so the author reads why the ceiling did not apply — and
        // stripped *before* `declares_nothing`, so a layer whose only key was this one contributes
        // nothing and does not move the provenance.
        if let Some(raw) = proj.fs {
            let mut project_fs = apply_fs(&mut warnings, PROJECT_CONFIG, Some(raw));
            if !gate.trusted && project_fs.scan_max_kb.take().is_some() {
                gate.refuse("`[fs] scan_max_kb`", &mut warnings);
            }
            if !project_fs.declares_nothing() {
                fs_origin = Provenance::Project;
            }
            fs.union(project_fs);
        }
        // `[ssh_agent]` is a security field — a trusted project may grant a key the cage can sign
        // with; an untrusted or changed one may not, because that signature authenticates as the
        // user on every host that trusts the key. Unions onto the global set, like `[devices]`.
        if let Some(raw) = proj.ssh_agent {
            gate.union(
                &mut ssh_agent,
                &mut ssh_agent_origin,
                "`[ssh_agent]`",
                &mut warnings,
                |w| {
                    // `confirm` rides the same table but is not part of the key set, so it is
                    // folded here, where it is produced, rather than smuggled through the union.
                    let (keys, confirm) = apply_ssh_agent(w, PROJECT_CONFIG, Some(raw));
                    ssh_agent_confirm |= confirm;
                    keys
                },
                union_ssh_agent,
            );
        }
        // The `[secret]` section is a security field — a trusted project may inject
        // credentials (and extend the resolver defaults); an untrusted or changed one may
        // not (it would aim the user's secrets at a host of its choosing). The whole
        // section — defaults included — is dropped, with one count warning.
        if let Some(section) = proj.secret {
            if trusted {
                let effective = match &section.defaults {
                    Some(raw_defaults) => {
                        warn_resolver_bindings(
                            &mut warnings,
                            PROJECT_CONFIG,
                            raw_defaults,
                            plugins,
                        );
                        secret_defaults.merged_with(raw_defaults)
                    }
                    None => secret_defaults.clone(),
                };
                // Carry these merged defaults to the project's own apps (below).
                project_secret_defaults = effective.clone();
                apply_secret_section(
                    &mut secrets,
                    &mut warnings,
                    PROJECT_CONFIG,
                    section.hosts,
                    &effective,
                    plugins,
                );
            } else {
                let n = count_host_secrets(&section.hosts);
                if n > 0 {
                    gate.refuse(&format!("{n} secret(s)"), &mut warnings);
                }
            }
        }
        // The `[task]` section is a security field, and the strongest one a project could reach for:
        // a task is a program sbx runs on a caller's behalf with a credential attached. A trusted
        // project may declare tasks (and tighten or loosen the section ceilings); an untrusted or
        // changed one may not — the whole section, defaults included, is dropped with one count
        // warning.
        if let Some(section) = proj.task {
            if trusted {
                let layer = tasks::TaskLayer {
                    source: PROJECT_CONFIG,
                    origin: TaskOrigin::Project,
                };
                if let Some(raw_defaults) = &section.defaults {
                    task_defaults = task_defaults.merged_with(raw_defaults, &layer, &mut warnings);
                }
                warn_unknown_task_keys(&mut warnings, PROJECT_CONFIG, &section);
                tasks::apply_task_section(
                    &mut tasks,
                    &mut warnings,
                    &layer,
                    section,
                    &task_defaults,
                    &project_secret_defaults,
                    plugins,
                );
            } else if !section.tasks.is_empty() {
                gate.refuse(&format!("{} task(s)", section.tasks.len()), &mut warnings);
            }
        }
    }

    // The baseline credentials are answered from `[plugin.*]` **before** the snapshot below, not
    // with the rest of the table further down. `merge_app` restores this snapshot wholesale, so an
    // answer applied after it is an answer the app path throws away — see
    // [`apply_plugin_host_config_to_secrets`]. `plugin_cfg` is final from the project layer
    // onwards, so nothing is missed by asking here.
    let mut plugin_matched: BTreeSet<String> = BTreeSet::new();
    apply_plugin_host_config_to_secrets(
        &mut secrets,
        &plugin_cfg,
        &mut plugin_matched,
        &mut warnings,
    );
    // Capture the declared baseline credentials before the posture clear: an app overlay that
    // opens a filtering posture inherits these (re-judged on its effective posture), even when the
    // baseline posture clears them from the baseline-effective `secrets`.
    let declared_secrets = secrets.clone();
    enforce_secret_posture(&network, &mut secrets, &mut warnings);
    warn_l4_l7_conflicts(&network, &mut warnings);

    let mut apps = resolve_apps(
        &mut warnings,
        global_apps,
        project_apps,
        &secret_defaults,
        &project_secret_defaults,
        &task_defaults,
        &net_groups,
        &network,
        &proc,
        &notify,
        allow_insecure_http,
        plugins,
    );

    // An *app* `[packages] mise:nix:<pkg>` re-introduces the per-project misalignment the mise split
    // otherwise fixes: a global app's Lane-1 pin lands the install record app-global while the `/nix`
    // store path is per-project. Warn per app, pointing at the aligned `nix:<pkg>` form. A *baseline*
    // `mise:nix:` (used by `sbx run`, whose home is already per-project) is aligned, so it is not
    // flagged. Trusted-only.
    for (app_name, app) in &apps {
        warn_mise_nix_packages(&format!("app `{app_name}` "), &app.packages, &mut warnings);
    }

    // Resolved before the `[plugin.*]` answer below, not inside the literal, because a broker is
    // one of the plugins that table configures: leaving it until after left every `[plugin.<name>]`
    // naming a broker unapplied *and* reported as matching nothing.
    let mut brokers = resolve_brokers(broker_cfg, &broker_origin, plugins, &mut warnings);

    // Answer each plugin the config configures, now that `[plugin.*]` has been layered and gated.
    // Done here rather than where a `SecretSource::Plugin` is parsed, because the answer must see
    // the FINAL table: a project layer that is read after the secrets would otherwise be missed.
    apply_plugin_host_config(
        &mut tasks,
        &mut apps,
        &mut brokers,
        plugins,
        &plugin_cfg,
        &mut plugin_matched,
        &mut warnings,
    );

    // Split the declaration now that both layers have had their say: the locator the launch binds,
    // and the credential reference resolved beside it. Parsed here rather than at validation because
    // a resolver plugin's scheme is only known once the registry has been read, which is the same
    // reason `[secret]` parses its own refs at this point.
    let (distro, distro_auth) = match distro_decl {
        Some((locator, Some(reff))) => match secrets::parse_secret_ref(&reff, plugins) {
            Ok(source) => (Some(locator), Some(source)),
            Err(why) => {
                // The image stands and the credential does not: a locator that resolves anonymously
                // still runs, and one that does not fails at the registry naming the image. Dropping
                // the image here would put the cage on a different userland than the config names,
                // which is the larger surprise of the two.
                warnings.push(format!("ignoring the `distro` credential: {why}"));
                (Some(locator), None)
            }
        },
        Some((locator, None)) => (Some(locator), None),
        None => (None, None),
    };

    // A declared distribution supplies its own `/etc/localtime`, and sbx stops emitting the link
    // that a `timezone` writes: the setting has no effect in such a cage. Named rather than left to
    // be discovered, on the rule the `[network]` layering follows — a setting sbx abandons is one it
    // says it abandoned, because the alternative is a user reading a config that describes a cage
    // they are not running.
    if distro.is_some() && timezone_origin != Provenance::Default {
        warnings.push(
            "`timezone` has no effect under `distro`: the image supplies its own `/etc/localtime`"
                .to_string(),
        );
    }

    Resolved {
        allow_insecure_http,
        allow_insecure_http_origin,
        env,
        env_layer,
        binds,
        bind_layer,
        packages,
        accepts_fresh_releases,
        plugin: plugin_cfg,
        open,
        service,
        // Filled by `merge_app` when a launch is an app's; a project run carries none.
        provisions: Vec::new(),
        nixpkgs_global,
        mise_engine,
        nixpkgs_project,
        distro,
        distro_auth,
        distro_origin,
        // A mise file is discovered by I/O in `load`; the pure layering never sees one.
        mise: None,
        mise_ignored: Vec::new(),
        network,
        network_origin,
        net_groups,
        egress_stats,
        redact_min_len,
        redact_min_len_origin,
        proc,
        proc_origin,
        notify,
        notify_origin,
        gui,
        gui_origin,
        timezone,
        timezone_origin,
        gpu,
        gpu_origin,
        audio,
        audio_origin,
        dbus,
        dbus_origin,
        forward,
        forward_origin,
        limits,
        limits_origin,
        seccomp,
        seccomp_origin,
        devices,
        devices_origin,
        fs,
        fs_origin,
        ssh_agent,
        ssh_agent_origin,
        ssh_agent_confirm,
        brokers,
        secrets,
        declared_secrets,
        tasks,
        apps,
        warnings,
    }
}

/// The egress-stats toggle a `network` field carries, or `None` if it does not mention it (the bare
/// string form never does; only the `[network]` table's `stats =` key). Pulled out so the resolver
/// can honor it from a trusted layer before the field is consumed by `validate_network`.
fn network_stats_of(field: &NetworkField) -> Option<bool> {
    match field {
        NetworkField::Table(t) => t.stats,
        NetworkField::Posture(_) => None,
    }
}

/// The `default_methods` override a `[network]` table carries, if any (peeked before the field moves
/// into `validate_network`). The string posture form never carries one.
fn network_default_methods_of(field: &NetworkField) -> Option<&Vec<String>> {
    match field {
        NetworkField::Table(t) => t.default_methods.as_ref(),
        NetworkField::Posture(_) => None,
    }
}

/// Report the unknown keys of a `[proc]` table, beside the mode that *did* take effect.
///
/// The keys are collected in a bag and named rather than refused by `deny_unknown_fields`, because
/// `proc` is an untagged-enum field ([`schema::ProcField`]): a key refused at the parse layer fails
/// the variant and drops the whole config layer — packages, apps and all — over one typo. Silence
/// was the worse half of that trade: a misspelled `deny` left `mode = "enforce"` enforcing an empty
/// list, which reads exactly like enforcement that decided to allow everything.
fn warn_unknown_proc_keys(warnings: &mut Vec<String>, source: &str, field: &schema::ProcField) {
    let schema::ProcField::Table(table) = field else {
        return;
    };
    for key in table.rest.keys() {
        warnings.push(format!(
            "{source}: ignoring unknown key `{key}` in `[proc]` — the table reads `mode`, `allow` \
             and `deny`, so nothing enforces what is written under `{key}`"
        ));
    }
}

/// Report the unknown keys of a `[notify]` table, for the reason [`warn_unknown_proc_keys`] gives:
/// `notify` is an untagged-enum field too, so its unknown keys are named rather than refused. A
/// misspelled `events` leaves the table's mode in force and the refinement written beside it
/// silently absent, which is how a lens comes to be believed quieter — or louder — than it is.
fn warn_unknown_notify_keys(warnings: &mut Vec<String>, source: &str, field: &schema::NotifyField) {
    let schema::NotifyField::Table(table) = field else {
        return;
    };
    for key in table.rest.keys() {
        warnings.push(format!(
            "{source}: ignoring unknown key `{key}` in `[notify]` — the table reads `mode`, \
             `events` and `repeat_after`, so nothing is announced differently for `{key}`"
        ));
    }
}

/// Warn when the **baseline** `[network]` carries a `default_methods`: it is an app-only posture
/// (Mode-B agents read by default), and `sbx run` (Mode A) deliberately stay all-verbs,
/// so a baseline value is parsed but ignored. Surfacing it keeps a user from believing they made
/// their interactive shell read-only when they did not.
fn warn_if_baseline_sets_default_methods(
    warnings: &mut Vec<String>,
    source: &str,
    field: &NetworkField,
) {
    if network_default_methods_of(field).is_some() {
        warnings.push(format!(
            "{source}: ignoring `default_methods` under the baseline `[network]` — it is an app-only \
             posture; `sbx run` stay all-verbs. Set it on an `[app.<name>.network]`"
        ));
    }
}

/// Overlay one set of limit overrides onto another, per field: a `Some` field in `over` replaces
/// the matching field in `base`; an unset (`None`) one leaves `base`'s value in place. The `env`
/// model — each limit is a standalone scalar with its own default — shared by every `[limits]`
/// layering: the baseline project-over-global merge, an app's project-over-global resolution, and
/// the app overlay onto the baseline.
fn overlay_limits(base: &mut crate::sandbox::cgroup::Limits, over: crate::sandbox::cgroup::Limits) {
    if over.memory_high.is_some() {
        base.memory_high = over.memory_high;
    }
    if over.memory_max.is_some() {
        base.memory_max = over.memory_max;
    }
    if over.tasks_max.is_some() {
        base.tasks_max = over.tasks_max;
    }
}

/// Whether `value` is shaped like an IANA zone name — the rule itself, written once because two
/// callers need it and must not drift: [`validate::validate_timezone`] applies it to a config value (and
/// warns), and the launcher applies it again to whatever it is about to join onto the zone
/// database's path (and fails closed). One or more `/`-separated segments of letters, digits, `_`,
/// `+` and `-`, each non-empty and none of them `.` or `..`, with no leading or trailing slash: that
/// admits every real zone name (`Europe/Paris`, `America/Argentina/Salta`, `Etc/GMT+3`, `UTC`) while
/// refusing the traversal (`../../etc/shadow`) and the absolute path (`/etc/shadow`) before either
/// can become a link target.
pub(crate) fn is_zone_name(value: &str) -> bool {
    !value.is_empty()
        && value.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'+' | b'-'))
        })
}

/// Resolve a `[seccomp] allow` table into a [`SeccompPolicy`](crate::sandbox::seccomp::SeccompPolicy): split each string on commas, trim,
/// and resolve each token against the mandatory denylist. A malformed or unknown entry is dropped
/// with a warning (fail-closed — an unrecognized token loosens nothing); an entry that reopens a
/// real escape surface is accepted but flagged with a caution. A collection field — drop-bad-entry,
/// keep-the-rest — like `forward`/`binds`, not an all-or-nothing scalar. Called only from a layer
/// already gated as trusted, so a bad entry warns for a relaxation that *is* being applied.
fn apply_seccomp(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawSeccomp>,
) -> crate::sandbox::seccomp::SeccompPolicy {
    let mut policy = crate::sandbox::seccomp::SeccompPolicy::default();
    let Some(raw) = raw else {
        return policy;
    };
    for entry in &raw.allow {
        for token in entry.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            match crate::sandbox::seccomp::resolve_allow(token) {
                Ok((allow, caution)) => {
                    policy.allow(allow);
                    if let Some(c) = caution {
                        warnings.push(format!(
                            "{source}: `[seccomp] allow` includes `{token}`, which reopens {}",
                            c.reopens()
                        ));
                    }
                }
                Err(reason) => warnings.push(format!(
                    "{source}: ignoring `[seccomp] allow` entry `{token}` ({reason})"
                )),
            }
        }
    }
    policy
}

/// Resolve one `[devices] allow` list into the host device paths to grant into the cage. Each entry
/// must be an **absolute path under `/dev/`** naming a device (or a directory of them). Validation is
/// purely lexical (no filesystem I/O, so [`resolve`] stays pure): a device absent on this host is
/// *not* an error here — it is skipped at launch by the `--dev-bind-try` mount, so a portable profile
/// that lists a device some hosts lack still launches everywhere. A malformed entry (not absolute,
/// outside `/dev/`, or containing `..`) is dropped with a warning (fail-closed — a bad path never
/// widens exposure). The result is sorted and deduped so two equivalent layers produce one canonical
/// set.
fn apply_devices(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawDevices>,
) -> Vec<PathBuf> {
    let mut devices: Vec<PathBuf> = Vec::new();
    let Some(raw) = raw else {
        return devices;
    };
    for entry in &raw.allow {
        let path = entry.trim();
        if path.is_empty() {
            continue;
        }
        match validate_device_path(path) {
            Ok(p) => devices.push(p),
            Err(reason) => warnings.push(format!(
                "{source}: ignoring `[devices] allow` entry `{path}` ({reason})"
            )),
        }
    }
    devices.sort();
    devices.dedup();
    devices
}

/// Read one layer's `[fs]` table into the resolved policy, dropping each entry the grammar refuses
/// with a warning that says why.
///
/// No trust gate anywhere near this: unlike every other table here, `[fs]` cannot grant. Each entry
/// takes something away from the cage it declares, so the worst an untrusted project can do with it
/// is close its own files — and a dropped entry fails closed by leaving the file *exposed*, which
/// is why the warning matters more here than the drop.
fn apply_fs(warnings: &mut Vec<String>, source: &str, raw: Option<schema::RawFs>) -> FsPolicy {
    let mut policy = FsPolicy::default();
    let Some(raw) = raw else {
        return policy;
    };
    for (field, entries, out) in [
        ("deny", &raw.deny, &mut policy.deny),
        ("readonly", &raw.readonly, &mut policy.readonly),
    ]
    .map(|(f, e, o)| (f, e.clone(), o))
    {
        for entry in entries {
            match fspolicy::validate_entry(&entry) {
                Ok(ok) if out.contains(&ok) => {}
                Ok(ok) => out.push(ok),
                Err(reason) => warnings.push(format!(
                    "{source}: ignoring `[fs] {field}` entry `{entry}` ({reason}) — that path stays \
                     open to the cage"
                )),
            }
        }
    }
    for entry in raw.scan {
        match crate::open_policy::validate_pattern(&entry) {
            Ok(()) if policy.scan.contains(&entry) => {}
            Ok(()) => policy.scan.push(entry),
            Err(reason) => warnings.push(format!(
                "{source}: ignoring `[fs] scan` pattern `{entry}` ({reason}) — no file is closed \
                 for carrying that shape"
            )),
        }
    }
    // Each pattern compiles on its own above; the *set* has its own ceiling, and only building it
    // answers whether this layer's list clears it. It is built here, per layer, because the launch
    // refuses outright when the scanner will not compile — and `[fs]` is the one table an untrusted
    // project may fill, so a cloned repo's `.sbx.toml` carrying a few thousand patterns could
    // otherwise abort every launch in its own directory instead of losing its own scan. Dropping
    // just this layer's entries is the same fail-closed drop every other bad `[fs]` entry gets, and
    // it leaves the shapes a trusted layer declared compiling as before. What is bounded here is
    // one layer's contribution: the launch compiles the union of the accepted layers, and a union
    // that does not fit is still refused there.
    //
    // The scan ceiling passed here is the built-in one: it bounds how many bytes a scan *reads* and
    // has no bearing on whether the set compiles, which is the only question asked.
    if let Err(reason) =
        crate::open_policy::OpenPolicy::compile(&policy.scan, crate::open_policy::MAX_SCAN_DEFAULT)
    {
        warnings.push(format!(
            "{source}: ignoring `[fs] scan` ({reason}) — no file is scanned for those shapes"
        ));
        policy.scan.clear();
    }
    // Zero would read nothing and call every file clean, which is worse than not scanning at all:
    // `config show` lists the shapes either way, so the protection would read as present. A
    // negative value is refused here rather than by the parser, for the reason the field's own doc
    // gives: at the parse layer it costs the whole config file.
    match raw.scan_max_kb {
        None => {}
        Some(0) => warnings.push(format!(
            "{source}: ignoring `[fs] scan_max_kb = 0` — a scan that reads nothing would pass every \
             file; leave it unset for the built-in ceiling"
        )),
        Some(kb) => match u64::try_from(kb) {
            Ok(kb) => policy.scan_max_kb = Some(kb),
            Err(_) => warnings.push(format!(
                "{source}: ignoring `[fs] scan_max_kb = {kb}` — a scan reads a length, so this is \
                 no ceiling at all; leave it unset for the built-in one"
            )),
        },
    }
    policy
}

/// Union `extra` forwards into `base`, keyed by **cage port**. The `forward` model — a layer adds
/// cage ports, never removes one — shared by the baseline project-over-global merge, the app
/// overlay onto the baseline, and the one-shot override onto the resolved set.
///
/// The cage port is the key because it is what a layer is actually naming: *this service inside the
/// cage should be reachable*. The host port is how that service is addressed from outside, and the
/// higher layer decides it — so an entry whose cage port `base` already forwards **replaces** its
/// host port rather than opening a second hole. That is the ordinary keyed-collection rule this
/// crate already applies to `env`, `packages`, `open` and `service`, and it is what makes a remap
/// resolve a host-port collision instead of adding to it: without it, `SBX_FORWARD=9200:9119` over
/// a profile's `forward = [9119]` would leave 9119 bound and the collision in place.
///
/// The invariant a layer cannot break is untouched: every cage port in `base` is still in the
/// result. A layer moves a forward; it never closes one.
fn union_forward(base: &mut Vec<ForwardPort>, extra: Vec<ForwardPort>) {
    for fwd in extra {
        match base.iter_mut().find(|f| f.cage == fwd.cage) {
            Some(prev) => *prev = fwd,
            None => base.push(fwd),
        }
    }
    sort_forward(base);
}

/// Report every key a layer wrote that sbx does not know.
///
/// Unknown keys stay **ignored**: that is what lets a config written for a newer sbx load on an
/// older one, and refusing them would turn the schema into a wall a project could trip a command
/// on. But silence cannot tell a misspelling from a field that does not exist yet, and only one of
/// those is harmless — a `memory_maxx` is a ceiling the author asked for and did not get, with
/// nothing anywhere to say so. So the key is named, the layer loads on regardless, and the reader
/// decides which it was.
///
/// Covers the top level and the tables where the silence costs the most: a limit that is not in
/// effect, and a grant that is not granted. A `[task.<name>]`/`[app.<name>]` entry's own fields are
/// reported by [`warn_unknown_task_keys`] and [`apps::warn_unknown_app_keys`] instead, each called
/// where the layer that supplied the entry — and the trust gate it passed — is known.
pub(super) fn warn_unknown_keys(warnings: &mut Vec<String>, source: &str, raw: &schema::RawConfig) {
    let mut report = |section: &str, keys: &BTreeMap<String, schema::RawIgnored>| {
        for key in keys.keys() {
            warnings.push(format!(
                "{source}: ignoring unknown key `{key}`{section} — sbx does not know this field \
                 (check the spelling; a newer sbx's fields are ignored here on purpose)"
            ));
        }
    };
    report("", &raw.rest);
    if let Some(limits) = &raw.limits {
        report(" under `[limits]`", &limits.rest);
    }
    if let Some(seccomp) = &raw.seccomp {
        report(" under `[seccomp]`", &seccomp.rest);
    }
    if let Some(devices) = &raw.devices {
        report(" under `[devices]`", &devices.rest);
    }
    if let Some(ssh_agent) = &raw.ssh_agent {
        report(" under `[ssh_agent]`", &ssh_agent.rest);
    }
    if let Some(redact) = &raw.redact {
        report(" under `[redact]`", &redact.rest);
    }
    if let Some(fs) = &raw.fs {
        report(" under `[fs]`", &fs.rest);
    }
    // `[network]` is reported where it is validated, not here: its table form is one variant of an
    // untagged enum, so the bare-string posture must stay a parse success, and the unknown keys are
    // named alongside the mode and the rules that did take effect.
}

/// Report the keys a `[task.<name>]` entry declared that sbx does not know, the task-scoped half of
/// [`warn_unknown_keys`].
///
/// A task is where an ignored key costs the most, because one of this table's fields is what
/// stands the exec supervisor up: `spawn` absent means no supervision at all, so `spwan = ["ssh"]`
/// reads as a command confined to two programs and is a command that may `execve` anything in the
/// cage. The same misspelling one level down, in a `[task.<name>.exec.<program>]` node, is already
/// refused by name — a node that means less than it says is the failure that field exists to
/// avoid, and it is no less a failure on the task itself.
///
/// The key is named and the task still loads, as everywhere else in this schema: refusing unknown
/// keys is what would stop a config written for a newer sbx from loading on an older one.
///
/// Called per layer rather than from [`warn_unknown_keys`], so a section an untrusted project never
/// gets to declare is not also reported key by key.
fn warn_unknown_task_keys(
    warnings: &mut Vec<String>,
    source: &str,
    section: &schema::RawTaskSection,
) {
    for (name, task) in &section.tasks {
        for key in task.rest.keys() {
            warnings.push(format!(
                "{source}: ignoring unknown key `{key}` under `[task.{name}]` — sbx does not know \
                 this field (check the spelling; a newer sbx's fields are ignored here on purpose)"
            ));
        }
    }
}

/// Validate a `[ssh_agent] allow` list into the entries the broker will match on, dropping a
/// malformed one with a warning and keeping the rest (the drop-bad-entry shape of `[devices]`).
///
/// An entry is matched against a key's fingerprint or its comment by **exact equality**, so the two
/// mistakes worth catching are the ones that would silently never match: a wildcard (there is none —
/// a grant names each key, so that it can be read off a listing and audited) and a truncated
/// `SHA256:` fingerprint (a base64 SHA-256 is always 43 characters once its padding is dropped, so a
/// shorter one is a copy-paste that lost its tail). Everything else is taken as a comment, which is
/// free-form by nature: `ssh-add -l` prints comments with spaces in them.
///
/// Returns the entries **and** whether this layer asked for per-signature confirmation, which the
/// caller ORs onto what it already has: a layer may turn confirmation on, never off.
fn apply_ssh_agent(
    warnings: &mut Vec<String>,
    source: &str,
    raw: Option<schema::RawSshAgent>,
) -> (Vec<String>, bool) {
    let mut keys: Vec<String> = Vec::new();
    let Some(raw) = raw else {
        return (keys, false);
    };
    let confirm = raw.confirm.unwrap_or(false);
    for entry in &raw.allow {
        let key = entry.trim();
        if key.is_empty() {
            continue;
        }
        let reason = if key == "*" {
            Some(
                "there is no wildcard — name each key by its `SHA256:…` fingerprint or its comment, as `ssh-add -l` prints them",
            )
        } else if let Some(digest) = key.strip_prefix("SHA256:") {
            let base64ish = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
            (digest.len() != 43 || !digest.chars().all(base64ish))
                .then_some("not a whole `SHA256:` fingerprint (43 base64 characters, unpadded)")
        } else {
            None
        };
        match reason {
            None => keys.push(key.to_string()),
            Some(reason) => warnings.push(format!(
                "{source}: ignoring `[ssh_agent] allow` entry `{key}` ({reason})"
            )),
        }
    }
    keys.sort();
    keys.dedup();
    (keys, confirm)
}

/// Union an ssh-agent grant onto the base set: a layer adds keys, never removes one, like
/// [`union_devices`].
fn union_ssh_agent(base: &mut Vec<String>, extra: Vec<String>) {
    for key in extra {
        if !base.contains(&key) {
            base.push(key);
        }
    }
    base.sort();
}

/// Union `extra` device paths into `base`, deduped and sorted — the same additive model as
/// [`union_forward`]: a layer (a trusted project overlay, an app) adds device grants, never removes
/// another layer's. A path already present is kept (idempotent); the result is sorted so two
/// equivalent layers produce one canonical set.
fn union_devices(base: &mut Vec<PathBuf>, extra: Vec<PathBuf>) {
    for dev in extra {
        if !base.contains(&dev) {
            base.push(dev);
        }
    }
    base.sort();
}

/// Parse one raw `forward` entry into a resolved [`ForwardPort`], or warn and return `None`.
///
/// A bare integer is the same-port form. A string is `"host:cage"`: exactly one colon, both sides
/// a port in `1..=65535`. Every rejection names the entry as written, because the value came from a
/// human and the useful message is the one that quotes them back.
fn parse_forward_entry(
    warnings: &mut Vec<String>,
    source: &str,
    entry: &schema::RawForward,
) -> Option<ForwardPort> {
    let spec = match entry {
        // Range-checked here rather than by the deserializer, for the reason `RawForward` states:
        // a value the schema layer refuses takes the whole config layer with it, so a port typed
        // with one digit too many would drop the env, the packages and the apps beside it.
        schema::RawForward::Port(p) if !(1..=65535).contains(p) => {
            warnings.push(format!(
                "{source}: ignoring `forward` port `{p}` — not a port in 1-65535"
            ));
            return None;
        }
        schema::RawForward::Port(p) => return Some(ForwardPort::same(*p as u16)),
        schema::RawForward::Remap(s) => s.trim(),
    };
    let mut warn = |why: &str| {
        warnings.push(format!(
            "{source}: ignoring `forward` entry `{spec}` — {why} (expected a port, or \
             `<host>:<cage>`)"
        ));
    };
    let Some((host, cage)) = spec.split_once(':') else {
        warn("no `:` separating the host port from the cage port");
        return None;
    };
    if cage.contains(':') {
        warn("more than one `:`");
        return None;
    }
    let parse_side = |side: &str| side.trim().parse::<u16>().ok().filter(|&p| p != 0);
    match (parse_side(host), parse_side(cage)) {
        (Some(host), Some(cage)) => Some(ForwardPort { host, cage }),
        (None, _) => {
            warn("the host side is not a port in 1-65535");
            None
        }
        (_, None) => {
            warn("the cage side is not a port in 1-65535");
            None
        }
    }
}

/// Order forward entries canonically, by cage port then host port, so two equivalent layers produce
/// one identical set. The cage port leads because it is the key.
fn sort_forward(forwards: &mut [ForwardPort]) {
    forwards.sort_unstable_by_key(|f| (f.cage, f.host));
}

/// Record `layer` as the provenance of each limit field that `limits` actually sets (a `Some`
/// value), leaving the others untouched. Called once per layer in declaration order — global, then
/// a trusted project overlay — so each field ends attributed to the last layer that set it, which
/// is exactly the layer whose value [`overlay_limits`] kept.
fn mark_limit_origins(
    origin: &mut LimitsOrigin,
    limits: &crate::sandbox::cgroup::Limits,
    layer: Provenance,
) {
    if limits.memory_high.is_some() {
        origin.memory_high = layer;
    }
    if limits.memory_max.is_some() {
        origin.memory_max = layer;
    }
    if limits.tasks_max.is_some() {
        origin.tasks_max = layer;
    }
}

/// The global config's resource limits, for `doctor` (host-level, with no project context). Reads
/// the global config — trusted by location — and validates its `[limits]`, discarding warnings:
/// `doctor` surfaces availability, while `sbx config` is the project-aware, warning-bearing view.
/// An absent or limit-free global config yields the built-in defaults (all-`None`).
pub(crate) fn global_limits() -> crate::sandbox::cgroup::Limits {
    let mut warnings = Vec::new();
    let global = read_global(&mut warnings);
    validate_limits(&mut warnings, GLOBAL_CONFIG, global.limits)
}

/// Clear injected credentials unless the posture is a filtering one. Injection is performed by
/// the filtering proxy, which exists only under a `deny`/`allow` (filtered-egress) posture; under
/// `shared` (no proxy) or `none` (no traffic) there is nowhere to inject, so the secrets are
/// cleared with a loud warning rather than left as a no-op the user mistakes for working injection.
/// (The plaintext is never read, so dropping is fail-safe.) Shared by the baseline resolution and
/// the per-app overlay, which can add secrets or change the posture.
fn enforce_secret_posture(
    network: &NetworkPolicy,
    secrets: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
) {
    if !secrets.is_empty() && !matches!(network, NetworkPolicy::Allowlist(_)) {
        warnings.push(format!(
            "ignoring {} HTTP-header secret(s): credential injection requires a filtering \
             network posture (`[network] mode = \"deny\"`, `\"allow\"`, or `\"ask\"`, the proxy that injects them)",
            secrets.len()
        ));
        secrets.clear();
    }
}

/// Warn when a host carries both a raw `tcp://` (L4) allow and an inspected (L7) rule on overlapping
/// ports: the splice is uninspected, so the L7 path/method/regex/redaction on that host:port is
/// silently ineffective. A config-quality hint (the layer partition is the actual control), so it
/// drops nothing — it points the user at keeping one layer per host:port. Checked on the **baseline**
/// policy (where rules are written); a per-app `[app.<name>.network]` override is not re-checked, to
/// avoid duplicating the baseline warning for the common inherit-the-network app.
fn warn_l4_l7_conflicts(network: &NetworkPolicy, warnings: &mut Vec<String>) {
    if let NetworkPolicy::Allowlist(policy) = network {
        for host in policy.l4_l7_conflicts() {
            warnings.push(format!(
                "host `{host}` has both a raw `tcp://` (L4) rule and an inspected (L7) rule on \
                 overlapping ports — the splice is uninspected, so the L7 rule does not apply to it \
                 (use one layer per host:port)"
            ));
        }
    }
}

/// Fold a layer's environment into `out`: drop a malformed key, drop a reserved
/// key when `deny_reserved` (an untrusted or changed project), and upsert the rest
/// so a later layer overrides an earlier one at the same key.
fn apply_env(
    out: &mut Vec<(String, String)>,
    mut origin: Option<(Provenance, &mut BTreeMap<String, Provenance>)>,
    warnings: &mut Vec<String>,
    source: &str,
    env: BTreeMap<String, String>,
    deny_reserved: bool,
) {
    for (key, val) in env {
        if !is_valid_env_key(&key) {
            warnings.push(format!("{source}: ignoring malformed env key `{key}`"));
            continue;
        }
        if deny_reserved && is_reserved_env_key(&key) {
            warnings.push(format!(
                "{source}: ignoring reserved env key `{key}` \
                 (an untrusted or changed project may not set it)"
            ));
            continue;
        }
        // Record the admitting layer at the upsert point — admission depends on the checks
        // above, so it cannot be reconstructed from outside. A later layer overwrites the key
        // here too, so the recorded layer always matches the value `out` ends up holding.
        if let Some((layer, map)) = origin.as_mut() {
            map.insert(key.clone(), *layer);
        }
        upsert(out, key, val);
    }
}

/// Interpret a bind table's optional `mode`: `None`/`"ro"` → read-only, `"rw"` → read-write. An
/// unrecognized value falls closed to read-only — the safe direction for a security field, never
/// a wider exposure than declared — returning a reason (with a case-variant hint) so the caller
/// can warn. The one place `"ro"`/`"rw"` are given meaning, shared by resolution and the display.
fn bind_mode(mode: Option<&str>) -> (bool, Option<String>) {
    match mode {
        None | Some("ro") => (false, None),
        Some("rw") => (true, None),
        Some(other) => {
            let hint = if other.eq_ignore_ascii_case("rw") || other.eq_ignore_ascii_case("ro") {
                format!(" (did you mean `\"{}\"`?)", other.to_ascii_lowercase())
            } else {
                String::new()
            };
            (
                false,
                Some(format!(
                    "has unknown mode `{other}`, binding read-only (use `\"ro\"` or `\"rw\"`){hint}"
                )),
            )
        }
    }
}

/// Fold a layer's binds into `out`, requiring each to be an absolute path. A
/// relative bind is dropped with a warning: the project is already mounted in
/// full, so an extra bind is by definition an out-of-project path, and resolving a
/// relative one against the working directory would be a surprise.
fn apply_binds(
    out: &mut Vec<Bind>,
    mut origin: Option<(Provenance, &mut BTreeMap<PathBuf, Provenance>)>,
    warnings: &mut Vec<String>,
    source: &str,
    binds: Vec<RawBind>,
) {
    // A leading `~`/`$HOME`/`$XDG_RUNTIME_DIR` is expanded from the environment of the user
    // launching sbx, so a portable config need not hard-code an absolute home path. Read once.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    for b in binds {
        let (raw_path, writable) = match b {
            RawBind::Path(p) => (p, false),
            RawBind::Detailed(t) => {
                // A table without a `path` is skipped with a warning — never dropped the whole
                // layer (the parse layer keeps `path` optional exactly so one such typo cannot).
                let Some(path) = t.path else {
                    warnings.push(format!("{source}: ignoring a bind table without a `path`"));
                    continue;
                };
                let (writable, reason) = bind_mode(t.mode.as_deref());
                if let Some(reason) = reason {
                    warnings.push(format!("{source}: bind `{path}` {reason}"));
                }
                (path, writable)
            }
        };
        let p = match expand_bind_path(&raw_path, home.as_deref(), runtime.as_deref()) {
            Ok(p) => p,
            Err(reason) => {
                warnings.push(format!("{source}: ignoring bind `{raw_path}`: {reason}"));
                continue;
            }
        };
        if p.is_absolute() {
            // Record the layer keyed by the expanded path; [`load`] re-keys it to the canonical
            // form when it canonicalizes, so the displayed path is the lookup key. The `Bind` and
            // the origin entry use the same `PathBuf` so a later `raw_layer.get(&bind.path)` hits.
            if let Some((layer, map)) = origin.as_mut() {
                map.insert(p.clone(), *layer);
            }
            out.push(Bind { path: p, writable });
        } else {
            warnings.push(format!("{source}: ignoring non-absolute bind `{raw_path}`"));
        }
    }
}

/// Parse a `tcp://host:port` endpoint. The port is required: a broker stands in front of one
/// service, and guessing a default would put it in front of something nobody named.
fn parse_tcp_endpoint(endpoint: &str) -> Result<BrokerTarget, String> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or("needs a port, e.g. `tcp://localhost:5432`")?;
    if host.is_empty() {
        return Err("needs a host".to_string());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("has `{port}` where a port number belongs"))?;
    if port == 0 {
        return Err("has port 0, which names no service".to_string());
    }
    Ok(BrokerTarget::Tcp {
        host: host.to_string(),
        port,
    })
}

/// Turn the layered `[broker.<name>]` tables into the bindings a launch acts on.
///
/// Fail-closed and named at every step: a table that binds no socket, one whose socket does not
/// expand or is not absolute, and one carrying an unknown key are each dropped with the reason.
/// Dropping is the safe direction here — a broker that does not start is a cage without that host
/// resource, while a broker started against the wrong path is one pointed somewhere nobody chose.
fn resolve_brokers(
    tables: BTreeMap<String, crate::config::schema::RawBrokerConfig>,
    origins: &BTreeMap<String, Provenance>,
    plugins: &crate::plugins::PluginRegistry,
    warnings: &mut Vec<String>,
) -> Vec<BrokerBinding> {
    // Read once, like the bind expander's: a portable config should not have to spell an absolute
    // runtime directory.
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let mut out = Vec::new();
    for (name, table) in tables {
        for key in table.rest.keys() {
            warnings.push(format!(
                "{GLOBAL_CONFIG}: ignoring unknown key `{key}` in `[broker.{name}]`"
            ));
        }
        // The name reaches a filesystem path: a launch binds `<data>/broker/<pid>/<name>.sock`, and
        // that is the one socket family under the data directory whose width a user chooses. The
        // data-directory cap reserves a fixed budget for every family, so a name past this length
        // would be approved here and then fail at `bind` with `sun_path` — a message about a socket
        // for a mistake that is about a name. Refused per entry, so a config that also carries
        // other brokers keeps them.
        if name.len() > crate::store::BROKER_NAME_MAX {
            warnings.push(format!(
                "`[broker.{name}]` has a name of {} characters, more than the {} a broker name may \
                 carry — its host socket would not fit the length the kernel allows. Shorten the \
                 name; the broker is not started",
                name.len(),
                crate::store::BROKER_NAME_MAX
            ));
            continue;
        }
        let Some(raw) = table.socket else {
            warnings.push(format!(
                "`[broker.{name}]` names no `socket`, so nothing says which host resource it \
                 brokers — the broker is not started"
            ));
            continue;
        };
        // `tcp://host:port` names an endpoint; anything else is a path on this machine.
        let socket = match raw.strip_prefix("tcp://") {
            Some(endpoint) => match parse_tcp_endpoint(endpoint) {
                Ok(target) => target,
                Err(why) => {
                    warnings.push(format!(
                        "`[broker.{name}] socket` is `{raw}`, which {why} — the broker is not \
                         started"
                    ));
                    continue;
                }
            },
            None => match expand_bind_path(&raw, home.as_deref(), runtime.as_deref()) {
                Ok(p) if p.is_absolute() => BrokerTarget::Unix(p),
                Ok(p) => {
                    warnings.push(format!(
                        "`[broker.{name}] socket` is `{}`, which is neither an absolute path nor \
                         a `tcp://host:port` endpoint — the broker is not started",
                        p.display()
                    ));
                    continue;
                }
                Err(why) => {
                    warnings.push(format!(
                        "`[broker.{name}] socket` cannot be resolved ({why}) — the broker is not \
                         started"
                    ));
                    continue;
                }
            },
        };
        // The secret's sources are parsed here, where a bad reference is still a configuration
        // error rather than something that surfaces at the first frame. A broker whose secret does
        // not parse is not started: it would otherwise put an unauthenticated connection in front
        // of the cage, which reads as the resource refusing it.
        let mut secret = Vec::new();
        let mut unresolved = false;
        if let Some(from) = &table.secret {
            // The same two shapes a `[secret] from` takes: one ref, or a fallback chain tried in
            // order.
            let refs: &[String] = match from {
                crate::config::schema::SecretFrom::One(one) => std::slice::from_ref(one),
                crate::config::schema::SecretFrom::Many(list) => list,
            };
            for reff in refs {
                match crate::config::secrets::parse_secret_ref(reff, plugins) {
                    Ok(source) => secret.push(source),
                    Err(why) => {
                        warnings.push(format!(
                            "`[broker.{name}] secret`: {why} — the broker is not started"
                        ));
                        unresolved = true;
                    }
                }
            }
        }
        if unresolved {
            continue;
        }
        out.push(BrokerBinding {
            origin: origins.get(&name).copied().unwrap_or(Provenance::Global),
            name,
            socket,
            allow: table.allow.unwrap_or_default(),
            secret,
            // Filled by `apply_plugin_host_config` once `[plugin.*]` is layered and gated; a
            // binding resolved with no such table keeps the empty answer.
            host: crate::plugins::HostConfig::default(),
        });
    }
    out
}

/// Expand a leading `~`, `$HOME`, or `$XDG_RUNTIME_DIR` in a `binds` source to an absolute host
/// path, using the environment of the user launching sbx (a config need not hard-code
/// `/home/<user>`). Only the head component — before the first `/` — is a variable; an
/// unrecognized `$VAR` at the head is rejected (fail closed: no arbitrary environment
/// interpolation into a mount source). A path with no recognized head is returned unchanged, and
/// the caller's absolute-path check still applies to the result.
///
/// The expandable-prefix set is deliberately identical to the resolver-plugin `allow_paths`
/// expander, so the user sees one variable vocabulary. It differs in one intentional way: a
/// literal `$` **past** the head is kept verbatim here, because a bind source is a real filesystem
/// path that may legitimately contain one (e.g. an exFAT/NTFS mount's `$RECYCLE.BIN`), whereas a
/// resolver allowlist can afford to reject any stray `$`. Do not merge the two behind one helper.
fn expand_bind_path(
    raw: &str,
    home: Option<&Path>,
    runtime: Option<&Path>,
) -> Result<PathBuf, String> {
    let (head, rest) = match raw.split_once('/') {
        Some((h, r)) => (h, Some(r)),
        None => (raw, None),
    };
    let base = match head {
        "~" | "$HOME" => home
            .ok_or_else(|| "needs `$HOME`, which is not set".to_string())?
            .to_path_buf(),
        "$XDG_RUNTIME_DIR" => runtime
            .ok_or_else(|| "needs `$XDG_RUNTIME_DIR`, which is not set".to_string())?
            .to_path_buf(),
        other if other.starts_with('$') => {
            return Err("uses an unsupported variable \
                        (only `~`, `$HOME`, `$XDG_RUNTIME_DIR` are expanded)"
                .to_string());
        }
        _ => return Ok(PathBuf::from(raw)),
    };
    Ok(match rest {
        Some(r) => base.join(r),
        None => base,
    })
}

/// The warning for an event name no lens answers to. Names the key *and* the vocabulary, because the
/// names are the config sections and a reader who guessed `egress` needs to be told it is `network`.
fn unknown_notify_event(source_label: &str, name: &str) -> String {
    let known: Vec<&str> = crate::notify::NotifyEvent::ALL
        .iter()
        .map(|e| e.as_str())
        .collect();
    format!(
        "{source_label}: ignoring unknown notify event `{name}` (expected one of: {})",
        known.join(", ")
    )
}

/// The default action a mode-less `[network]` table inherits from its parent config layer. Only a
/// filtering `Deny`/`Ask` is inherited; an `Allow` (allow-by-default denylist), `Shared`, or
/// `Isolated` parent falls back to the safe `Deny`, so a table that lists `allow` rules is never
/// silently turned into a wide-open denylist (which would make its own allow-list inert — the exact
/// `allow`-vs-`deny` footgun) or into the open host network.
fn mode_from_parent(parent: &NetworkPolicy) -> crate::allowlist::DefaultAction {
    use crate::allowlist::DefaultAction;
    match parent {
        NetworkPolicy::Allowlist(p) => match p.default_action() {
            DefaultAction::Ask => DefaultAction::Ask,
            DefaultAction::Deny | DefaultAction::Allow => DefaultAction::Deny,
        },
        NetworkPolicy::Shared | NetworkPolicy::Isolated => DefaultAction::Deny,
    }
}

/// Parse the `[network] http2` entries into the proxy's host matchers. Each is a `host` or
/// `host:port`; a malformed entry is dropped with a warning (fail-closed — that host keeps
/// HTTP/1.1). Unlike `allow`/`deny`, these are not egress rules and carry no `@group`/path/method
/// grammar — HTTP/2 is a transport choice, orthogonal to the verdict.
fn parse_http2_hosts(
    warnings: &mut Vec<String>,
    source_label: &str,
    entries: Vec<String>,
) -> Vec<crate::allowlist::Http2Host> {
    let mut hosts = Vec::with_capacity(entries.len());
    for entry in entries {
        match crate::allowlist::Http2Host::parse(&entry) {
            Some(h) => hosts.push(h),
            None => warnings.push(format!(
                "{source_label}: ignoring malformed `http2` entry `{entry}` \
                 (expected a host or host:port); that host keeps HTTP/1.1"
            )),
        }
    }
    hosts
}

/// Parse the `[network] shared_credential` groups into the host sets the credential store reads.
///
/// Each group names the hosts that are one service, and a credential the cage acquired on any of
/// them is then not refused on its way to the others. Hosts are canonicalized the way a request's
/// host is, so a group and the destination it must match are compared in one spelling.
///
/// Two shapes are dropped with a warning, both fail-closed — the tripwire keeps the per-host
/// exemption it had without the declaration. A group of fewer than two distinct hosts states
/// nothing a credential's own host does not already say. And a host in two groups leaves "the same
/// service" undecided: the sets would have to be merged to be usable, which is a wider grant than
/// either group asked for, so the second group is refused instead and named.
fn parse_shared_credential(
    warnings: &mut Vec<String>,
    source_label: &str,
    groups: Vec<Vec<String>>,
) -> Vec<Vec<String>> {
    let mut kept: Vec<Vec<String>> = Vec::new();
    for group in groups {
        let mut hosts: Vec<String> = Vec::new();
        for host in &group {
            let entry = host.trim();
            // A `*.domain` entry keeps its prefix and canonicalizes the domain, so the wildcard
            // survives to the match and the two sides still compare in one spelling.
            let canonical = match entry.strip_prefix("*.") {
                Some(domain) => {
                    let domain = crate::allowlist::canonical_host(domain);
                    if domain.is_empty() {
                        String::new()
                    } else {
                        format!("*.{domain}")
                    }
                }
                None => crate::allowlist::canonical_host(entry),
            };
            if !canonical.is_empty() && !hosts.contains(&canonical) {
                hosts.push(canonical);
            }
        }
        // One entry says something only when it is a wildcard: `*.example.com` widens the exemption
        // to a whole domain, while a single hostname repeats what the acquiring host already grants.
        let says_something = hosts.len() >= 2 || hosts.iter().any(|entry| entry.starts_with("*."));
        if !says_something {
            warnings.push(format!(
                "{source_label}: ignoring a `shared_credential` group naming one host and no \
                 wildcard ({}) — a credential is already exempt on the host it was acquired on, so \
                 such a group grants nothing",
                render_hosts(&group)
            ));
            continue;
        }
        // Overlap is asked with the same matcher the tripwire will use, so a wildcard that
        // swallows an earlier group's host counts as the collision it is: `*.example.com` and
        // `api.example.com` name one host between them however differently they spell it.
        let overlap = hosts.iter().find(|entry| {
            kept.iter().flatten().any(|earlier| {
                crate::allowlist::shared_credential_covers(entry, earlier)
                    || crate::allowlist::shared_credential_covers(earlier, entry)
            })
        });
        if let Some(shared) = overlap {
            warnings.push(format!(
                "{source_label}: ignoring a `shared_credential` group whose entry `{shared}` is \
                 already covered by an earlier group — a host belongs to one service here, and \
                 merging the two would widen the tripwire further than either group asks"
            ));
            continue;
        }
        kept.push(hosts);
    }
    kept
}

/// The hosts of a `shared_credential` group as written, for a warning that has to name which group
/// it is about. Quoted individually so an empty entry is visible rather than swallowed by the
/// separator.
fn render_hosts(group: &[String]) -> String {
    group
        .iter()
        .map(|h| format!("`{h}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse an `ask_timeout` duration string: a non-negative integer with an optional unit suffix
/// (`s` seconds [the default], `m` minutes, `h` hours), e.g. `"90s"`, `"5m"`, `"2h"`, or a bare
/// `"90"`. A zero-valued form (`"0"`, `"0m"`) means no timeout — an indefinite wait, the same as
/// omitting the field — so it returns `Ok(None)`; a positive value returns `Ok(Some(duration))`.
/// A malformed value is `Err(reason)` so the caller can warn and fall back to indefinite.
///
/// A value above [`DURATION_MAX_SECS`] is malformed too. Every duration parsed here becomes a
/// deadline somewhere — `Instant::now() + d` in the task runner, the readiness gate, the
/// connection pool — and that addition *panics* on overflow, so a config naming `18446744073709551615`
/// would abort the launcher rather than wait a long time. The ceiling is far beyond any duration
/// a person writes, so refusing it costs nothing and the callers' existing "warn and fall back"
/// path answers it.
fn parse_duration(raw: &str) -> Result<Option<std::time::Duration>, String> {
    let s = raw.trim();
    let malformed = || format!("`{raw}` is not a duration (try \"90s\", \"5m\", \"2h\")");
    let (digits, unit) = if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else {
        (s, 1)
    };
    let n: u64 = digits.trim().parse().map_err(|_| malformed())?;
    let secs = n
        .checked_mul(unit)
        .filter(|secs| *secs <= DURATION_MAX_SECS)
        .ok_or_else(|| {
            format!(
                "`{raw}` is too large — a duration may name at most {DURATION_MAX_SECS} seconds"
            )
        })?;
    Ok((secs > 0).then(|| std::time::Duration::from_secs(secs)))
}

/// The largest duration a config may name: one year. Not a policy about how long anything should
/// wait — every real value is orders of magnitude below it — but the bound that keeps a parsed
/// duration usable as a deadline (see [`parse_duration`]).
const DURATION_MAX_SECS: u64 = 365 * 24 * 3600;

/// Pre-classified reusable egress groups: each `[network.groups]` name mapped to the rules its
/// entries classify to. Built once from the global config (trusted by location) and consulted
/// when a `[network]` `allow`/`deny` list references a group with `@<name>`.
type NetGroups = BTreeMap<String, Vec<crate::allowlist::Rule>>;

/// The group an egress entry references, or `None` when the entry is a rule of its own. **Only a
/// leading `@` is a reference**: a `@` anywhere else (a URL path like `host/@user`, a `re:` pattern)
/// is a legitimate part of the entry and must classify as written.
///
/// One definition, three readers — the classifier that resolves the reference, and the two importers
/// that report an undeclared one before it is ever folded. Split, they would drift on exactly the
/// entries where the difference shows: an importer that missed a form would stay silent about a
/// reference the fold then drops.
pub(crate) fn group_ref(entry: &str) -> Option<&str> {
    entry.trim().strip_prefix('@')
}

/// Every group referenced across a set of egress entries, sorted and deduplicated — the importers'
/// view of what a fragment will need from `[network.groups]` before anything is resolved.
pub(crate) fn group_refs<'a>(entries: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut names: Vec<String> = entries
        .filter_map(|e| group_ref(e))
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Classify the entries of one egress list (`allow`, `deny`, or `mute`), expanding a leading
/// `@<name>` into the rules of that named group (from `[network.groups]`). A malformed entry is dropped
/// with a warning that names which list it was in, and it is classified *as* that list, so a
/// refusal that offers a way out (the bare `*` catch-all) offers the one this list's author wanted.
/// An unknown `@<name>` reference is dropped with a *loud* warning — a miss in a `deny` list
/// silently drops a carve-out (the host would no longer be blocked), the one case where a typo fails
/// open in intent, so an unresolved reference must never pass unnoticed. Only a leading `@` is a
/// reference: a `@` anywhere else (a URL path like `host/@user`, a `re:` pattern) is a legitimate
/// part of the entry and is classified as written.
fn classify_entries(
    warnings: &mut Vec<String>,
    source_label: &str,
    slot: Slot,
    entries: Vec<String>,
    groups: &NetGroups,
) -> Vec<crate::allowlist::Rule> {
    let list = slot.label();
    let mut rules = Vec::new();
    for entry in entries {
        if let Some(name) = group_ref(&entry) {
            match groups.get(name) {
                Some(group_rules) => rules.extend(group_rules.iter().cloned()),
                // Both ways in are named: a group most often arrives as a portable fragment
                // (`sbx net groups import`), and pointing only at hand-editing sends the reader to
                // write by hand what a verb already imports — the same defect as a message that
                // names a remedy the product does not offer, inverted.
                None => warnings.push(format!(
                    "{source_label}: {list} references undefined group `@{name}` — import it \
                     (`sbx net groups import <file>`) or define it under `[network.groups]` in the \
                     global config, or remove the reference (the entry is ignored, so nothing is \
                     {} for it)",
                    match slot {
                        Slot::Deny => "denied",
                        Slot::Mute => "muted",
                        _ => "allowed",
                    }
                )),
            }
            continue;
        }
        match crate::allowlist::classify_in(&entry, slot) {
            Ok(rule) => rules.push(rule),
            Err(e) => warnings.push(format!("{source_label}: ignoring {list} entry — {e}")),
        }
    }
    rules
}

/// Take the `groups` table out of a raw `network` field, leaving the posture behind. Returns the
/// groups when the layer wrote the table form and declared some, and an empty map otherwise (the
/// bare-string posture has nowhere to put them: TOML cannot extend a string with a sub-table).
///
/// Taking rather than reading is what keeps the "declared once, in the global config" rule
/// enforceable: the one caller allowed to define groups removes them here, so any `groups` still
/// attached to a table further down is, by construction, one that layer may not define — and
/// [`validate::validate_network_table`] reports it rather than expanding it.
fn take_net_groups(field: &mut Option<NetworkField>) -> BTreeMap<String, Vec<String>> {
    match field {
        Some(NetworkField::Table(table)) => std::mem::take(&mut table.groups),
        _ => BTreeMap::new(),
    }
}

/// Validate and pre-classify the global `[network.groups]` table into a [`NetGroups`] map. Each
/// group's name is charset-validated (an invalid name is skipped with a warning), and each entry
/// is classified like an `allow`/`deny` entry — a malformed one is dropped with a warning naming
/// the group. A nested reference (`@other` inside a group) is rejected: a group is a flat list of
/// egress entries in this version, so an unbounded or cyclic expansion is impossible by
/// construction. Building every defined group here (not only referenced ones) surfaces a typo in
/// an unused group early rather than only when some app first references it.
///
/// A group is built **before** anything references it, so which list it will land in is not known
/// here: entries classify as [`Slot::Allow`], the shape a group is written for (a reusable set of
/// destinations to open). The one visible consequence is the wording of a rejected `*` catch-all —
/// a group entry written as `*` is answered as if it sat in an `allow` list even when the group is
/// only ever referenced from a `deny`. The verdict is identical either way (the entry is dropped
/// with a warning naming the group); only the way out it suggests could point at the wrong posture.
fn build_net_groups(warnings: &mut Vec<String>, raw: BTreeMap<String, Vec<String>>) -> NetGroups {
    let mut groups = NetGroups::new();
    for (name, entries) in raw {
        if !is_valid_group_name(&name) {
            warnings.push(format!(
                "{GLOBAL_CONFIG}: ignoring net group `{name}`: a name must be 1–64 of [A-Za-z0-9._-]"
            ));
            continue;
        }
        let mut rules = Vec::new();
        for entry in entries {
            if entry.trim().starts_with('@') {
                warnings.push(format!(
                    "{GLOBAL_CONFIG}: net group `{name}`: ignoring nested reference `{}` — a group \
                     is a flat list of egress entries and may not reference another group",
                    entry.trim()
                ));
                continue;
            }
            match crate::allowlist::classify(&entry) {
                // Tag each rule with the group it came from, so a `@<name>` expansion carries its
                // origin into the resolved policy for `sbx net rules` to render (excluded from the
                // rule's equality, so this affects only display).
                Ok(mut rule) => {
                    rule.group = Some(name.clone());
                    rules.push(rule);
                }
                Err(e) => warnings.push(format!(
                    "{GLOBAL_CONFIG}: net group `{name}`: ignoring entry `{entry}` — {e}"
                )),
            }
        }
        groups.insert(name, rules);
    }
    groups
}

/// A URI scheme usable as an `[open]` key: RFC 3986's `scheme` production — an ASCII letter
/// followed by letters, digits, `+`, `-` or `.`.
///
/// Kept to exactly that set rather than a looser "no separators" rule because the scheme is written
/// into three generated artifacts at once — a `case` pattern in the router script, a `MimeType=`
/// entry, and a `mimeapps.list` key. Every character outside this production is significant in at
/// least one of them (`*` and `?` glob in the first, `;` terminates the second, `=` splits the
/// third), so restricting to the production is what keeps one validator sufficient for all three.
fn is_valid_uri_scheme(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && s.len() <= 64
}

/// Whether a `[network.groups]` name is a safe, referenceable identifier. A group name is not a path
/// component (unlike an app name), so `.`/`..` are harmless; it is charset- and length-bounded so
/// a reference `@<name>` is unambiguous and the name renders cleanly in warnings and `sbx net`.
/// Shared with the `sbx net allow/deny` write path so a persisted `@<name>` reference is validated
/// by the same rule the resolver uses to name a group.
pub(crate) fn is_valid_group_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A nixpkgs source: a branch/channel name (`nixos-23.11`) or a 40-hex revision
/// under `NixOS/nixpkgs`. Restricted to the characters those use so a declared value
/// can never widen into a different flake reference (a fork, a `git+https`/`path:`
/// URL) or smuggle shell-significant characters into a nix invocation — even from a
/// trusted config. Arbitrary flake references are a later, additive feature.
fn is_valid_nixpkgs_source(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// Whether `s` is a distribution userland locator.
///
/// The grammar itself lives in [`crate::sandbox::distro::reference`], which is also what takes the
/// locator apart when the image is fetched. One definition: a validator that read the string a
/// second time would drift from the parser, and the two disagreeing is how a value that passed
/// review reaches a registry as something else.
fn is_valid_distro_source(s: &str) -> bool {
    crate::sandbox::distro::reference::parse(s).is_some()
}

/// Whether `s` names a build of the mise engine: a nixpkgs source, or a **revision-pinned**
/// GitHub flake reference with an optional `#<attr>`.
///
/// Deliberately narrower than the `tools::is_valid_flake_ref` gate, and for a different reason
/// guards. This value selects the program that installs every other program in every cage, so the
/// shapes it admits are enumerated rather than filtered: `github:<owner>/<repo>/<40-hex>` and
/// nothing looser. A branch or tag in this position is refused — not because it could not be
/// fetched, but because a name can be moved under you, and the whole point of the engine's lock is
/// that its revision is fixed until someone changes it on purpose. `nixos-unstable` stays legal in
/// its own right: it is a *tracked channel*, resolved through the lock and rolled only by
/// `sbx upgrade mise`, which is a different thing from a reference that pretends to be pinned.
fn is_valid_mise_engine(s: &str) -> bool {
    if is_valid_nixpkgs_source(s) {
        return true;
    }
    let (reference, attr) = s.split_once('#').map_or((s, None), |(r, a)| (r, Some(a)));
    // An attribute, when written, is a plain nix identifier — no path, no quoting to interpret.
    if attr.is_some_and(|a| {
        a.is_empty()
            || !a
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    }) {
        return false;
    }
    let Some(rest) = reference.strip_prefix("github:") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    let [owner, repo, rev] = parts[..] else {
        return false;
    };
    let ident = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    };
    ident(owner) && ident(repo) && rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())
}

/// An env key usable with `--setenv`: non-empty, and free of `=` and control
/// characters (NUL, newline). A malformed key — reachable through a quoted TOML
/// key — is dropped rather than handed to the sandbox.
fn is_valid_env_key(key: &str) -> bool {
    !key.is_empty() && !key.contains('=') && !key.chars().any(char::is_control)
}

/// Set `key` to `val`, overriding an existing entry so a later layer wins over an
/// earlier one at the same key while preserving declaration order.
fn upsert(env: &mut Vec<(String, String)>, key: String, val: String) {
    match env.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = val,
        None => env.push((key, val)),
    }
}

/// What a layer pays for a field it got wrong.
///
/// Two rules meet here, and every test below holds one of them against a whole config file: a value
/// sbx cannot use costs **that value**, never the file it is written in (an untagged enum refusing a
/// key at the parse layer takes the packages, apps and credentials beside it down with it); and a
/// key sbx passes over is **named**, because a rule believed to be in force and governing nothing is
/// the failure the `[fs]`, `[proc]` and `[notify]` tables exist to avoid.
#[cfg(test)]
mod bad_fields_cost_a_field {
    use super::*;

    /// Parse a config the way the loader does, failing with the parser's own message — which is the
    /// assertion in half these tests: the file must still load.
    pub(super) fn cfg(text: &str) -> RawConfig {
        schema::parse(text.as_bytes())
            .unwrap_or_else(|e| panic!("this config must still parse — {e}\n---\n{text}"))
    }

    /// Resolve a global-only config.
    pub(super) fn global(text: &str) -> Resolved {
        resolve(cfg(text), None, &PluginRegistry::default())
    }

    /// Resolve a global config under a project one at the given trust.
    pub(super) fn layered(g: &str, p: &str, state: TrustState) -> Resolved {
        resolve(cfg(g), Some((cfg(p), state)), &PluginRegistry::default())
    }

    /// Whether any warning contains every one of `parts`.
    pub(super) fn warned(r: &Resolved, parts: &[&str]) -> bool {
        r.warnings
            .iter()
            .any(|w| parts.iter().all(|part| w.contains(part)))
    }

    #[test]
    fn a_negative_limit_costs_the_limit_and_not_the_file() {
        // `RawLimit`'s numeric variant is signed for this: as a `u64` it refused `-1` at the parse
        // layer, and since `RawLimit` is untagged that failure was the whole file's.
        let r = global("[env]\nFOO = \"bar\"\n\n[limits]\ntasks_max = -1\n");
        assert!(
            r.env.iter().any(|(k, v)| k == "FOO" && v == "bar"),
            "the rest of the layer survives a bad limit: {:?}",
            r.env
        );
        assert_eq!(r.limits.tasks_max, None, "the bad limit itself is dropped");
        assert!(
            warned(&r, &["limits.tasks_max", "-1"]),
            "the drop is named: {:?}",
            r.warnings
        );
        // The guard still admits a real count, or the check above would pass by refusing everything.
        let ok = global("[limits]\ntasks_max = 8192\n");
        assert_eq!(ok.limits.tasks_max.as_deref(), Some("8192"));
    }

    #[test]
    fn a_negative_scan_ceiling_costs_the_ceiling_and_not_the_file() {
        // Same trade as the limits above, on the field that decides how much of a file the content
        // lens reads: as a `u64` the parser refused `-1`, and the refusal was the whole file's.
        let r = global("[env]\nFOO = \"bar\"\n\n[fs]\nscan_max_kb = -1\n");
        assert!(
            r.env.iter().any(|(k, _)| k == "FOO"),
            "the rest of the layer survives: {:?}",
            r.warnings
        );
        assert_eq!(r.fs.scan_max_kb, None, "the bad ceiling is dropped");
        assert!(
            warned(&r, &["[fs] scan_max_kb = -1"]),
            "and named: {:?}",
            r.warnings
        );
        // A real ceiling still lands, so the check is not a blanket refusal.
        assert_eq!(global("[fs]\nscan_max_kb = 64\n").fs.scan_max_kb, Some(64));
    }

    #[test]
    fn a_service_or_handler_sbx_cannot_read_costs_the_entry_and_not_the_file() {
        // `RawOpen`/`RawService` are untagged, so an entry sbx cannot read matched no variant and
        // failed the parse of the whole document. Three spellings of that mistake, in one file: a
        // handler whose `cmd` line was forgotten, a readiness gate on a port that is not one, and a
        // start condition naming no variable. Each costs its own entry now, the way `forward =
        // [70000]` already did, and the `[env]` beside them survives to prove the layer did.
        let r = global(
            "[env]\nFOO = \"bar\"\n\n\
             [open.https]\nmode = \"detach\"\n\n\
             [service.gateway]\ncmd = [\"hermes\", \"gateway\"]\nready = { tcp = 70000 }\n\n\
             [service.chroma]\ncmd = [\"chroma\", \"run\"]\nenable = { is = \"1\" }\n",
        );
        assert!(
            r.env.iter().any(|(k, v)| k == "FOO" && v == "bar"),
            "the rest of the layer survives all three: {:?}",
            r.warnings
        );
        assert!(
            !r.open.contains_key("https"),
            "the handler that names no program is dropped"
        );
        assert!(
            warned(&r, &["`[open]` entry `https`", "names no program"]),
            "and named: {:?}",
            r.warnings
        );
        let gateway = r.service.get("gateway").expect("the service stands");
        assert!(
            gateway.ready.is_none(),
            "only the gate on an impossible port is dropped"
        );
        assert!(
            warned(&r, &["`[service]` entry `gateway`", "70000", "1-65535"]),
            "the port is named with the range it is outside: {:?}",
            r.warnings
        );
        let chroma = r.service.get("chroma").expect("this one stands too");
        assert!(
            chroma.enable.is_empty(),
            "a condition that compares nothing starts the service unconditionally"
        );
        assert!(
            warned(&r, &["`[service]` entry `chroma`", "names no variable"]),
            "and says so: {:?}",
            r.warnings
        );
        // The well-formed spellings still resolve, so none of the above passes by refusing
        // everything.
        let ok = global(
            "[open.https]\ncmd = [\"firefox\"]\nmode = \"detach\"\n\n\
             [service.gateway]\ncmd = [\"hermes\"]\nready = { tcp = 8100 }\n\
             enable = { env = \"GATEWAY\", not = \"0\" }\n",
        );
        assert_eq!(ok.open["https"].mode, OpenMode::Detach);
        assert_eq!(ok.service["gateway"].ready.map(|g| g.tcp), Some(8100));
        assert_eq!(ok.service["gateway"].enable.len(), 1);
        assert!(ok.warnings.is_empty(), "{:?}", ok.warnings);
    }

    #[test]
    fn a_misspelled_task_key_is_named_like_the_exec_node_one_level_down() {
        // `spawn` is the field that stands a task's exec supervisor up — absent means no
        // supervision at all — so a `spwan` parsing into silence left a command the author
        // believed confined to `git` plus `ssh` free to `execve` anything in the cage, with its
        // credential in the environment. The same misspelling inside
        // `[task.<name>.exec.<program>]` was already refused by name; the task's own table is now
        // walked too.
        let r = global("[task.deploy]\ncmd = [\"git\"]\nspwan = [\"ssh\"]\n");
        assert_eq!(r.tasks.len(), 1, "the task still loads: {:?}", r.warnings);
        assert!(
            r.tasks[0].spawn.is_none(),
            "and it really is unsupervised — which is why the key has to be named"
        );
        assert!(
            warned(&r, &["unknown key `spwan`", "[task.deploy]"]),
            "the key is named: {:?}",
            r.warnings
        );
        // Spelled right, the supervisor is declared and nothing is said, so the report cannot be
        // satisfied by complaining about every task.
        let ok = global("[task.deploy]\ncmd = [\"git\"]\nspawn = [\"ssh\"]\n");
        assert!(
            ok.tasks[0].spawn.is_some(),
            "the well-spelled field takes effect: {:?}",
            ok.warnings
        );
        assert!(
            !ok.warnings.iter().any(|w| w.contains("unknown key")),
            "{:?}",
            ok.warnings
        );
    }

    #[test]
    fn an_unknown_broker_or_plugin_key_is_named_and_the_file_still_loads() {
        // Both tables carried `deny_unknown_fields`, which fails the *document* — and which also
        // silenced the unknown-key report `resolve_brokers` has always tried to make.
        let r = global(
            "[env]\nFOO = \"bar\"\n\n[broker.gpg]\nsocket = \"/tmp/gpg.sock\"\nsokcet = \"/x\"\n\n\
             [plugin.age]\nprograms = { age = \"nix:age\" }\ntypo = 1\n",
        );
        assert!(
            r.env.iter().any(|(k, _)| k == "FOO"),
            "one mistyped key does not take the file down: {:?}",
            r.warnings
        );
        assert!(
            warned(&r, &["unknown key `sokcet`", "[broker.gpg]"]),
            "the broker's unknown key is named: {:?}",
            r.warnings
        );
        assert!(
            warned(&r, &["unknown key `typo`", "[plugin.age]"]),
            "the plugin's unknown key is named: {:?}",
            r.warnings
        );
        // And the keys these tables *do* read stay silent, so the report cannot be satisfied by
        // complaining about everything.
        let ok = global("[broker.gpg]\nsocket = \"/tmp/gpg.sock\"\nallow = [\"sign\"]\n");
        assert!(
            !ok.warnings.iter().any(|w| w.contains("unknown key")),
            "{:?}",
            ok.warnings
        );
        assert_eq!(ok.brokers.len(), 1, "the binding still stands");
        assert_eq!(ok.brokers[0].allow, vec!["sign".to_string()]);
    }

    #[test]
    fn a_project_broker_secret_is_named_like_its_sibling_socket() {
        // `socket` and `secret` are both global-only, and both are dropped from a project table.
        // Naming one and not the other left a project author watching a credential they had
        // declared never reach the wire, with nothing said.
        let r = layered(
            "[broker.gpg]\nsocket = \"/tmp/gpg.sock\"\nallow = [\"sign\"]\n",
            "[broker.gpg]\nallow = [\"list\"]\nsecret = \"env://TOKEN\"\nsokcet = \"/tmp/evil\"\n",
            TrustState::Trusted,
        );
        assert!(
            warned(&r, &[PROJECT_CONFIG, "[broker.gpg] secret"]),
            "the dropped credential is named: {:?}",
            r.warnings
        );
        assert!(
            warned(
                &r,
                &[PROJECT_CONFIG, "unknown key `sokcet`", "[broker.gpg]"]
            ),
            "a project table's unknown key is reported by the project loop, since only the global \
             tables reach `resolve_brokers`: {:?}",
            r.warnings
        );
        // The one field a trusted project *may* set still lands, and the socket it may not set is
        // still the global's.
        assert_eq!(r.brokers.len(), 1);
        assert_eq!(r.brokers[0].allow, vec!["list".to_string()]);
        assert_eq!(r.brokers[0].origin, Provenance::Project);
    }

    #[test]
    fn a_misspelled_proc_or_notify_key_is_named() {
        // The sharpest silence in the schema: `mode = "enforce"` enforcing an empty list, because
        // the rules were written under a key nothing reads.
        let r = global("[proc]\nmode = \"enforce\"\ndney = [\"curl\"]\n");
        assert_eq!(r.proc.mode, crate::proc_policy::ProcMode::Enforce);
        assert!(
            r.proc.deny.is_empty(),
            "the misspelled rules are not in force"
        );
        assert!(
            warned(&r, &["unknown key `dney`", "[proc]"]),
            "so the key is named: {:?}",
            r.warnings
        );

        let n = global("[notify]\nmode = \"always\"\nevnets = [\"network\"]\n");
        assert!(
            warned(&n, &["unknown key `evnets`", "[notify]"]),
            "{:?}",
            n.warnings
        );

        // Spelled right, both tables take effect and say nothing.
        let ok = global(
            "[proc]\nmode = \"enforce\"\ndeny = [\"curl\"]\n\n\
             [notify]\nmode = \"always\"\nevents = [\"network\"]\n",
        );
        assert_eq!(ok.proc.deny.len(), 1, "the rule is in force");
        assert!(
            !ok.warnings.iter().any(|w| w.contains("unknown key")),
            "{:?}",
            ok.warnings
        );
    }

    #[test]
    fn a_refused_network_table_does_not_take_its_stats_half_with_it() {
        // `stats` rides the `[network]` table, and was committed before the table was validated: a
        // table refused whole still turned the egress audit off, at either layer.
        let g = global("[network]\nmode = \"bogus\"\nstats = false\n");
        assert_eq!(
            g.network_origin,
            Provenance::Default,
            "the table is refused"
        );
        assert!(
            g.egress_stats,
            "a refused global `[network]` leaves the audit on: {:?}",
            g.warnings
        );

        let p = layered(
            "",
            "[network]\nmode = \"bogus\"\nstats = false\n",
            TrustState::Trusted,
        );
        assert_eq!(p.network_origin, Provenance::Default);
        assert!(
            p.egress_stats,
            "and so does a refused project `[network]`: {:?}",
            p.warnings
        );

        // An *accepted* table still turns it off from either layer, or the fix would just be a
        // toggle that no longer works.
        assert!(!global("[network]\nmode = \"deny\"\nstats = false\n").egress_stats);
        assert!(
            !layered(
                "",
                "[network]\nmode = \"deny\"\nstats = false\n",
                TrustState::Trusted
            )
            .egress_stats
        );
    }

    /// A `[fs] scan` list whose patterns each compile alone but whose combined scanner does not fit
    /// the set's size limit — the shape a hostile project uses, written small.
    fn scan_bomb() -> String {
        let patterns: Vec<String> = ('a'..='t')
            .map(|c| format!("\"(?:{c}{{500}}){{500}}\""))
            .collect();
        format!("[fs]\nscan = [{}]\n", patterns.join(", "))
    }

    #[test]
    fn an_over_budget_scan_set_costs_that_layer_its_scan_and_not_the_launch() {
        // `[fs]` is the one table an untrusted project may fill, and the launch *refuses* when the
        // scanner will not compile — so an over-budget list in a cloned repo's `.sbx.toml` could
        // abort every launch in its own directory. It is compiled here instead, and dropped like
        // every other bad `[fs]` entry.
        let r = layered(
            "[fs]\nscan = [\"AKIA[0-9A-Z]{16}\"]\n",
            &scan_bomb(),
            TrustState::Untrusted,
        );
        assert_eq!(
            r.fs.scan,
            vec!["AKIA[0-9A-Z]{16}".to_string()],
            "the trusted layer's lens is untouched and the project's is gone: {:?}",
            r.warnings
        );
        assert!(
            warned(&r, &[PROJECT_CONFIG, "`[fs] scan`"]),
            "the drop is named against the layer that caused it: {:?}",
            r.warnings
        );
        // An ordinary list of shapes still compiles and still scans, so the drop is not universal.
        let ok = global("[fs]\nscan = [\"AKIA[0-9A-Z]{16}\", \"-----BEGIN [A-Z ]*PRIVATE KEY\"]\n");
        assert_eq!(ok.fs.scan.len(), 2, "{:?}", ok.warnings);
        assert!(
            !ok.warnings.iter().any(|w| w.contains("[fs] scan")),
            "{:?}",
            ok.warnings
        );
    }
}

/// What a later layer replaces, and what it leaves standing.
///
/// A layer that says nothing about a field must leave that field — and the provenance `sbx config`
/// reports for it — exactly as it found them: "unset" and "set to nothing" are different
/// declarations, and a shape that cannot tell them apart makes the quieter one silently
/// destructive. The other half of the same rule is that a layer which *does* declare something
/// leaves every view of it in step, so what a launch does and what `sbx config` says it does cannot
/// drift apart.
#[cfg(test)]
mod a_layer_replaces_only_what_it_declares {
    // The fixtures next door parse and resolve a layered pair exactly as the loader does, so they
    // are reused here rather than written a second time.
    use super::bad_fields_cost_a_field::{cfg, global, layered};
    use super::*;

    /// The headers a credential set writes, in declaration order — the whole of what the two halves
    /// of the pair have to agree on.
    fn headers(set: &[HeaderSecret]) -> Vec<&str> {
        set.iter().map(|s| s.header.as_str()).collect()
    }

    #[test]
    fn a_project_broker_table_that_sets_no_policy_leaves_the_global_one_standing() {
        // The split this table exists for: the global config says which host resource is exposed, a
        // trusted project says only what may be done with it. So a project table written for its
        // `socket` — dropped, and named — declares nothing sbx reads, and as a bare list that was
        // indistinguishable from `allow = []`: the global policy was replaced by an empty one and
        // `sbx config` put the project's name against it.
        let r = layered(
            "[broker.gpg]\nsocket = \"/tmp/gpg.sock\"\nallow = [\"sign\"]\n",
            "[broker.gpg]\nsocket = \"/tmp/mine.sock\"\n",
            TrustState::Trusted,
        );
        assert_eq!(r.brokers.len(), 1);
        assert_eq!(
            r.brokers[0].allow,
            vec!["sign".to_string()],
            "the policy the global config declared still stands: {:?}",
            r.warnings
        );
        assert_eq!(
            r.brokers[0].origin,
            Provenance::Global,
            "and is still attributed to the layer that wrote it"
        );

        // An empty policy the project really did write is a project choice and still lands — the
        // two cases are told apart, not both refused.
        let cleared = layered(
            "[broker.gpg]\nsocket = \"/tmp/gpg.sock\"\nallow = [\"sign\"]\n",
            "[broker.gpg]\nallow = []\n",
            TrustState::Trusted,
        );
        assert!(
            cleared.brokers[0].allow.is_empty(),
            "{:?}",
            cleared.brokers[0].allow
        );
        assert_eq!(cleared.brokers[0].origin, Provenance::Project);
    }

    #[test]
    fn a_one_shot_credential_lands_in_both_halves_of_the_secret_pair() {
        // `secrets` is what this launch injects; `declared_secrets` is the pre-clear set an app
        // overlay — and the `--app` view, which runs after the override — re-derives an app's
        // effective credentials from. An override that reached only the first left `sbx config show
        // --app` reporting that the app injects nothing for a host the very same launch injects
        // for, which is the one thing that view exists to make visible.
        let mut r = global("network = \"deny\"\n");
        assert!(r.declared_secrets.is_empty(), "nothing is declared yet");
        let over = cfg("[secret.\"api.example.com\"]\n\
             from = \"env://DEMO_API_KEY\"\n\
             header = \"x-api-key\"\n\
             type = \"raw\"\n");
        r.apply_override(Override::for_test(over))
            .expect("the override applies");
        assert_eq!(
            headers(&r.secrets),
            vec!["x-api-key"],
            "the launch injects the override's credential: {:?}",
            r.warnings
        );
        assert_eq!(
            headers(&r.declared_secrets),
            headers(&r.secrets),
            "and the half the app view reads says the same"
        );
    }
}

#[cfg(test)]
mod tests;

/// The shipped catalogue under `examples/`, checked against the schema that accepts it — kept
/// apart from the engine's own suite because it shares none of its fixtures and calls no resolver.
#[cfg(test)]
mod catalogue_tests;
