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
//! filesystem. [`load`] is the thin I/O around it, and is the one place that ties
//! a project's bytes, its trust verdict, and its parse together so all three act
//! on the same inode.

pub(crate) mod manage;
pub(crate) mod safety;
mod schema;
pub(crate) mod view;

use crate::allowlist::{Rule, RuleKind};
use crate::plugins::PluginRegistry;
use crate::trust::{self, TrustState};
use schema::{
    NetworkField, NetworkTable, RawApp, RawConfig, RawHostSecret, RawHostSecrets,
    RawSecretDefaults, SecretFrom,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

/// The global config file name, under `…/ops/`.
const GLOBAL_CONFIG: &str = "ops.toml";
/// The project config file name, in the project root.
pub(crate) const PROJECT_CONFIG: &str = ".ops.toml";
/// The directory of imported app profiles, beside the global config (`…/ops/apps/`). A profile
/// is a standalone TOML file (a top-level [`schema::RawApp`]) whose *filename* is the app name;
/// it is trusted by location, exactly like the global config, so its apps join the global app
/// layer. (Note: under the *config* root this `apps` directory holds profiles, while under the
/// *data* root an `apps` directory holds each app's persistent home — two distinct trees.)
const PROFILES_DIR: &str = "apps";

/// The subcommand verbs of `ops app` (`ops app import`, `… export`, `… rm`, `… list`). They are
/// reserved so they can never also be an app name: otherwise `ops app import` would be ambiguous
/// between the subcommand and launching an app literally named `import`, and such an app could be
/// neither launched nor managed. Reserving them removes the ambiguity at the source — they are
/// rejected as app names wherever one is resolved.
pub(crate) const RESERVED_APP_VERBS: &[&str] = &["import", "export", "rm", "list"];

/// Whether `name` is a reserved `ops app` subcommand verb, and so may not be an app name.
pub(crate) fn is_reserved_app_verb(name: &str) -> bool {
    RESERVED_APP_VERBS.contains(&name)
}

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
/// userland ops owns (`HOME`, `PATH`) and the loader the sandbox routes foreign
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
/// Under a network allowlist the cage's only egress is the ops-managed filtering
/// proxy (Model B): the proxy-control variables (`http_proxy`/`https_proxy`/
/// `all_proxy`/`no_proxy`, either case) and the CA-bundle variables the cage trusts
/// ops's per-session CA through ([`crate::sandbox::egress::CA_FILE_ENV_KEYS`]) are
/// reserved for the same reason. In-cage a redirected proxy or a swapped CA only
/// fails closed (empty netns, ops-minted certs), but the same Mode-A protection as
/// `NIX_CONFIG` applies, and the keys ops *sets* are exactly the keys it protects.
fn is_reserved_env_key(key: &str) -> bool {
    key.starts_with("LD_")
        || is_proxy_env_key(key)
        || crate::sandbox::egress::CA_FILE_ENV_KEYS.contains(&key)
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
                | "IFS"
                | "GCONV_PATH"
                | "GLIBC_TUNABLES"
                | "LOCPATH"
                | "NLSPATH"
                | "RESOLV_HOST_CONF"
                | "HOSTALIASES"
        )
}

/// The proxy-control variables, matched case-insensitively (tools honor both
/// `http_proxy` and `HTTP_PROXY`). `no_proxy`/`all_proxy` are reserved alongside the
/// two ops sets, so an untrusted project can neither redirect the cage's egress nor
/// carve a hole around it.
fn is_proxy_env_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy"
    )
}

/// Which provider realises a declared package, parsed from the mandatory backend
/// prefix on the value: `nix:<attr>`, `mise:<token>`, or `flake:<ref>`. There is no
/// bare form — a value without a recognized prefix is dropped with a warning, so a
/// package's source is always explicit and never silently mis-routed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Backend {
    /// `nix:<attr>` — a nixpkgs attribute, provisioned host-side into ops's store
    /// (seeded, offline-reusable). nixpkgs is curated, so building it host-side is
    /// justified; realising it can run a build, so it is honored only from a trusted
    /// source.
    Nix(String),
    /// `mise:<token>` — a mise backend token (e.g. `aqua:openai/codex`, `opencode`,
    /// `npm:@scope/pkg`, or `nix:<pkg>` for nixhub), equipped in-cage globally via
    /// `mise use -g` (durable, on PATH, fetched at launch). The token after `mise:`
    /// is passed to mise verbatim — ops adds no per-backend logic of its own.
    Mise(String),
    /// `flake:<ref>` — an arbitrary nix flake reference (e.g.
    /// `github:owner/repo#attr`), built **in-cage** with `nix build --out-link` into
    /// the project's own writable store. A third-party flake is uncurated, so unlike
    /// `nix:` it is *not* built host-side: its eval + build are contained by the cage
    /// (the same posture as the in-cage `mise:nix:` self-equip). On PATH at launch and
    /// later launches via a persistent out-link under the home.
    Flake(String),
}

impl Backend {
    /// The backend-specific locator as declared: the nixpkgs attribute, the mise
    /// token, or the flake reference. Used for display and as the value the
    /// provisioner consumes.
    pub(crate) fn locator(&self) -> &str {
        match self {
            Backend::Nix(attr) => attr,
            Backend::Mise(token) => token,
            Backend::Flake(reference) => reference,
        }
    }

    /// A short label naming the provider, for `ops config` and warnings.
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Backend::Nix(_) => "nix",
            Backend::Mise(_) => "mise",
            Backend::Flake(_) => "flake",
        }
    }
}

/// A tool the configuration asks the sandbox to provide: a free `name` (the merge
/// key across layers and the on-disk root name) bound to a `backend` that names how
/// to realise it (a nixpkgs attribute host-side, or a mise token in-cage). Each
/// carries whether the layer that supplied its value is trusted, so the launcher can
/// decide — outside this pure layering — whether to provision it. Both backends are
/// security-relevant (each can fetch or build), so the decision is *deferred*, not
/// made here: this stage drops nothing for trust, it only records the verdict the
/// launcher will weigh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Package {
    /// The free label: merge key and on-disk root name.
    pub(crate) name: String,
    /// How to realise this package: a nixpkgs attribute (host-side) or a mise token
    /// (in-cage), parsed from the value's mandatory backend prefix.
    pub(crate) backend: Backend,
    /// The trust of the layer that supplied this value (global is always
    /// `Trusted`, by location; a project carries its own verdict). The full state
    /// is kept, not a bool, so a *changed* project is distinguished from a
    /// never-trusted one — they call for different action (re-approval vs first
    /// approval), and the build-vs-fetch relaxation still needs the distinction.
    pub(crate) state: TrustState,
}

/// A project's mise file as the resolved configuration sees it: the discovered
/// filename(s) for display, the trust verdict gating it, and the validated bytes
/// captured at load. The launcher maps a trusted mise `[env]` into the sandbox;
/// this records the file's presence, whether it would be honored, and the exact
/// content the verdict covers. `None` when the project declares no mise file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MiseConfig {
    /// The discovered filename(s), e.g. `.mise.toml` — for display only.
    pub(crate) name: String,
    /// The project's trust verdict — a mise file is honored only when `Trusted`.
    pub(crate) state: TrustState,
    /// The `(filename, bytes)` of each mise file, read once through the safety gate
    /// in [`load`] — the *exact* bytes the trust hash was computed over. The launcher
    /// materializes these for mise rather than letting it re-read from disk, so mise
    /// sees precisely the authorized, already-hashed content (closing the window
    /// between the trust check and the read). Empty when no mise file was safely
    /// readable — then `state` is `Untrusted` and nothing is honored.
    pub(crate) files: trust::MiseInputs,
}

/// The sandbox's resolved network posture. A security choice: honored from the
/// global config (trusted by location) or a trusted project, ignored from an
/// untrusted one. The default keeps the host network — there is no confidentiality
/// guarantee until the filtered-egress allowlist is enforced, so cutting the network
/// off entirely is the one posture that fully contains exfiltration today.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum NetworkPolicy {
    /// Keep the host network namespace (the default).
    #[default]
    Shared,
    /// A fresh, empty network namespace: the sandbox has no connectivity at all.
    Isolated,
    /// Filtered egress: the cage reaches only what the policy permits (an allow list with
    /// deny carve-outs), through a host-side proxy. Until that proxy is wired, the launcher
    /// treats this fail-closed (full isolation), never fail-open.
    Allowlist(crate::allowlist::EgressPolicy),
}

/// The sandbox's resolved GUI posture. A security choice, gated exactly like
/// [`NetworkPolicy`]: honored from the global config (trusted by location) or a trusted
/// project, ignored from an untrusted one. The default exposes no display — a graphical app
/// cannot reach the host's compositor. `Wayland` binds the compositor socket read-only so a
/// window can map; X11 is deliberately never offered (an X client could snoop and drive every
/// other window, which Wayland's per-client isolation prevents on a well-behaved compositor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum GuiPolicy {
    /// No display access (the default): a graphical app cannot reach a compositor.
    #[default]
    None,
    /// Bind the host's Wayland compositor socket read-only so a graphical app can map a window.
    Wayland,
}

/// A credential the egress proxy injects into matching outbound requests as an HTTP
/// header. The plaintext is deliberately **not** here — only how to obtain it host-side
/// at launch ([`SecretSource`]), where to inject it ([`Self::to`]), and how to shape it
/// ([`HeaderShape`]). Reading the source to a value happens later, host-side and
/// fail-closed, so this declaration carries no secret and is safe to log. A security
/// field: honored from the global config or a trusted project, dropped from an untrusted
/// one, and only effective under a network allowlist (the proxy that performs the
/// injection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderSecret {
    /// The resolver chain ops reads the plaintext from at launch — host-side, never inside the
    /// cage — tried in order, the first that resolves winning (a later one is a fallback).
    pub(crate) sources: Vec<SecretSource>,
    /// The concrete host (and optional path) the injection is scoped to: a request to
    /// anything else never receives the header. A `*.` wildcard or `re:` regex is
    /// rejected at validation, so a credential reaches exactly one known destination.
    pub(crate) to: Rule,
    /// The header name to set, e.g. `Authorization`.
    pub(crate) header: String,
    /// How the plaintext becomes the header value.
    pub(crate) shape: HeaderShape,
}

impl HeaderSecret {
    /// A human label for `ops config` — the resolver chain by locator (a variable name or file
    /// path), never a value. A single source reads as itself; a fallback chain is joined with
    /// `, then ` so the precedence is visible.
    pub(crate) fn describe_sources(&self) -> String {
        self.sources
            .iter()
            .map(SecretSource::describe)
            .collect::<Vec<_>>()
            .join(", then ")
    }
}

/// One resolver ref in a secret's source chain — where ops reads the plaintext, host-side at
/// launch. Only the locator is kept here, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretSource {
    /// A host environment variable, by name (not its value).
    Env(String),
    /// An absolute host file path, read host-side and never bound into the cage.
    File(PathBuf),
    /// A SOPS-encrypted file, decrypted host-side with the `sops` CLI. `file` is the encrypted
    /// path (relative ones resolve against the project root); `key` is an optional dotted path
    /// into the decrypted document (`db.password`), or the whole file when absent.
    Sops { file: PathBuf, key: Option<String> },
    /// A resolver plugin claims this ref's scheme. The launcher runs the plugin host-side under
    /// least privilege, passing `locator` (the part after `scheme://`) and reading the plaintext
    /// from its stdout. The validated manifest travels with the source so the launch runs exactly
    /// the plugin the config layer validated.
    Plugin {
        plugin: crate::plugins::ResolverPlugin,
        locator: String,
    },
}

impl SecretSource {
    /// A human label for `ops config` — the variable name, file path, or sops file/key, none of
    /// which is the secret itself.
    pub(crate) fn describe(&self) -> String {
        match self {
            SecretSource::Env(var) => format!("env {var}"),
            SecretSource::File(path) => format!("file {}", path.display()),
            SecretSource::Sops { file, key: Some(k) } => format!("sops {}#{k}", file.display()),
            SecretSource::Sops { file, key: None } => format!("sops {}", file.display()),
            SecretSource::Plugin { plugin, locator } => format!("{} {locator}", plugin.scheme),
        }
    }
}

/// How a header value is built from the plaintext: a `prefix` prepended to the secret,
/// the secret optionally base64-encoded first (HTTP Basic). `type = "bearer"` is
/// `prefix = "Bearer "`, `"raw"` is an empty prefix, `"basic"` is `prefix = "Basic "`
/// over base64; an explicit `prefix` overrides the type's default. The value never lives
/// here — [`Self::format`] takes the plaintext and returns the formed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderShape {
    prefix: String,
    base64: bool,
}

impl HeaderShape {
    /// Build the header value for `secret`: `prefix` then the secret, base64-encoded when
    /// `base64` (Basic auth, where the plaintext is a `user:pass` pair).
    pub(crate) fn format(&self, secret: &str) -> String {
        if self.base64 {
            format!("{}{}", self.prefix, base64_encode(secret.as_bytes()))
        } else {
            format!("{}{secret}", self.prefix)
        }
    }

    /// The secret-bearing byte strings that must never leave the cage verbatim in an outbound
    /// request — the needles of the egress leak tripwire. Always the raw plaintext (what
    /// `bearer`/`raw` carry on the wire after the static prefix), plus — when the shape
    /// base64-encodes it (Basic auth) — the base64 form, since that is what travels on the wire
    /// and is what a reflecting upstream echoes back. Built with the same `base64_encode`
    /// [`Self::format`] uses, so a needle matches the byte-for-byte wire form.
    pub(crate) fn needles(&self, secret: &str) -> Vec<Vec<u8>> {
        let mut out = vec![secret.as_bytes().to_vec()];
        if self.base64 {
            out.push(base64_encode(secret.as_bytes()).into_bytes());
        }
        out
    }

    /// Construct a shape directly — `prefix` prepended to the secret, base64-encoded first
    /// when `base64`. For tests that build an injection without parsing a `type`.
    #[cfg(test)]
    pub(crate) fn new(prefix: impl Into<String>, base64: bool) -> Self {
        Self {
            prefix: prefix.into(),
            base64,
        }
    }

    /// A short label for `ops config` — the *effective* type, reconstructed from the
    /// shape, so `raw` with a `"Bearer "` prefix reads as `bearer` (the value is identical);
    /// a non-standard prefix is shown so the effective form is never hidden.
    pub(crate) fn describe(&self) -> String {
        match (self.base64, self.prefix.as_str()) {
            (true, "Basic ") => "basic".to_string(),
            (true, p) => format!("basic, prefix {p:?}"),
            (false, "Bearer ") => "bearer".to_string(),
            (false, "") => "raw".to_string(),
            (false, p) => format!("raw, prefix {p:?}"),
        }
    }
}

/// Standard base64 (RFC 4648) with `=` padding, for HTTP Basic credentials. Hand-rolled
/// rather than pulling a dependency for one short, well-specified transform.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 0x3f] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// Where a resolved value came from — the provenance `ops config` surfaces so a value's origin
/// is never a mystery. `Default` is ops's built-in; `Global`/`Project` are the two config files.
/// A later layer overrides an earlier one at the same key, so for a value this is the *winning*
/// source. The launcher ignores it (provenance is a display affordance). Inheritance — an app
/// field taking the baseline's value — is a *display* concept derived at view time (the resolution
/// never inherits), so it lives only on the view-side [`view::ProvenanceView`](super::view), not
/// here.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum Provenance {
    /// ops's built-in default — no config layer set this value.
    #[default]
    Default,
    /// The global `ops.toml` (trusted by location).
    Global,
    /// The project `.ops.toml`.
    Project,
}

/// The per-field provenance of the cage's cgroup limits. Each of the three limits is a standalone
/// scalar with its own default, set independently by either config layer (the `env` model), so
/// each carries its own [`Provenance`].
#[derive(Clone, Copy, Default)]
pub(crate) struct LimitsOrigin {
    pub(crate) memory_high: Provenance,
    pub(crate) memory_max: Provenance,
    pub(crate) tasks_max: Provenance,
}

/// The resolved configuration the launcher applies: the layered environment and
/// the read-only host binds, the declared tools, plus any warnings worth surfacing
/// (dropped fields, an unparseable or unsafe file). Nothing here is a hard error —
/// a missing or broken config yields empty defaults, never a failed launch.
#[derive(Clone)]
pub(crate) struct Resolved {
    /// Extra environment, in application order; a later entry overrides an earlier
    /// one at the same key.
    pub(crate) env: Vec<(String, String)>,
    /// Which layer each `env` key's winning value came from. Keyed by the env key (stable, so
    /// the lookup matches what `env` lists). A display affordance for `ops config`; only the
    /// baseline resolution records it (an app overlay does not), and the launcher ignores it.
    pub(crate) env_layer: BTreeMap<String, Provenance>,
    /// Extra host paths to bind read-only.
    pub(crate) ro_binds: Vec<PathBuf>,
    /// Which layer each effective bind came from, keyed by the *canonical* path `ro_binds`
    /// lists (re-keyed after canonicalization in [`load`], so the lookup matches the displayed
    /// path). A display affordance for `ops config`, recorded only at the baseline.
    pub(crate) bind_layer: BTreeMap<PathBuf, Provenance>,
    /// Declared tools, in declaration order, each tagged with its source's trust.
    /// Admission (and the nix work it implies) is the launcher's, not decided here.
    pub(crate) packages: Vec<Package>,
    /// The global config's `nixpkgs` override (trusted by location), or `None` for
    /// the default channel. Drives the base userland and is the default source for a
    /// project's tools.
    pub(crate) nixpkgs_global: Option<String>,
    /// A trusted project's `nixpkgs` override, or `None`. Pins *this project's* tools
    /// to its own source; an untrusted or changed project's value is dropped (it is a
    /// supply-chain-relevant choice), so this is never set from one.
    pub(crate) nixpkgs_project: Option<String>,
    /// The project's mise file, when one is present beside a `.ops.toml`. Its tools
    /// are resolved (trusted-only) by a later stage; here it records the file's
    /// presence and the gating verdict. Discovered in [`load`] (it is I/O), so the
    /// pure [`resolve`] always leaves it `None`.
    pub(crate) mise: Option<MiseConfig>,
    /// The resolved network posture: the default (`Shared`) unless the global config
    /// or a trusted project asked for `"none"`. An untrusted project's choice is
    /// dropped with a warning — it may not narrow or widen the network.
    pub(crate) network: NetworkPolicy,
    /// Which layer supplied the winning `network` posture (`Default` when neither config set it).
    /// A display affordance for `ops config`; the launcher ignores it.
    pub(crate) network_origin: Provenance,
    /// Whether the egress proxy records its per-host decision counters (`ops net stats`). On by
    /// default; a trusted layer's `[network] stats = false` turns the audit off. Gated like the
    /// rest of `[network]` — an untrusted project's table (and so its `stats`) is dropped, so it
    /// cannot disable the auditing of its own egress. Baseline-only: a `stats` key inside an
    /// `[app.<name>.network]` table is ignored (warned), and `ops config show --app` does not surface
    /// the inherited value — the app inherits this baseline.
    pub(crate) egress_stats: bool,
    /// The resolved GUI posture: the default (`None`) unless the global config or a trusted
    /// project asked for `"wayland"`. An untrusted project's choice is dropped with a warning
    /// — it may not open a display.
    pub(crate) gui: GuiPolicy,
    /// Which layer supplied the winning `gui` posture (`Default` when neither config set it).
    pub(crate) gui_origin: Provenance,
    /// The resolved cgroup resource limits (anti-DoS): the built-in defaults, with any field a
    /// trusted `[limits]` table (global or project) overrode. A security field, gated like
    /// `network`/`gui` — an untrusted project may not loosen a limit. Each of the three fields is
    /// layered independently (global under a trusted project), like `env`.
    pub(crate) limits: crate::sandbox::cgroup::Limits,
    /// The per-field provenance of `limits`: which layer set each of the three, or `Default` for a
    /// field no config overrode. A display affordance for `ops config`.
    pub(crate) limits_origin: LimitsOrigin,
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
    pub(crate) declared_secrets: Vec<HeaderSecret>,
    /// Named application launch profiles, each a gated overlay over this baseline. Keyed
    /// by name; `ops app <name>` looks one up and folds it on with [`Resolved::merge_app`].
    /// `ops run`/`ops shell` ignore them.
    pub(crate) apps: BTreeMap<String, ResolvedApp>,
    /// Human-readable notes about what was dropped or ignored and why.
    pub(crate) warnings: Vec<String>,
}

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
/// location, or a project layer by its verdict). `ops app <name>` folds this onto the
/// baseline with [`Resolved::merge_app`].
#[derive(Clone)]
pub(crate) struct ResolvedApp {
    /// The argv to run. Empty when no layer declared a `cmd` — a launch error, never a
    /// silent default.
    pub(crate) cmd: Vec<String>,
    /// Where this app's persistent home is keyed (`Global` by default). Integrity-gated like
    /// `cmd`: an untrusted project may set its own app's scope but not flip a trusted app from
    /// `Project` to `Global`.
    pub(crate) home_scope: AppHomeScope,
    /// Extra environment, in application order; folded over the baseline's so the app wins.
    pub(crate) env: Vec<(String, String)>,
    /// Extra read-only host binds (absolute; canonicalized in [`load`], like the baseline).
    pub(crate) ro_binds: Vec<PathBuf>,
    /// Extra tools, each tagged with its source's trust; override a baseline tool by name.
    pub(crate) packages: Vec<Package>,
    /// The app's own network posture, set only when a trusted source declared one. `Some`
    /// overrides the baseline; `None` leaves the baseline posture in place.
    pub(crate) network: Option<NetworkPolicy>,
    /// The app's own GUI posture, set only when a trusted source declared one. `Some` overrides
    /// the baseline; `None` leaves the baseline posture in place.
    pub(crate) gui: Option<GuiPolicy>,
    /// The app's own cgroup limit overrides, set only from a trusted source (an untrusted
    /// project's app `[limits]` is dropped whole, like its `network`/`gui`). Each set field
    /// overrides the baseline at [`merge_app`]; an unset one keeps the baseline value. All-`None`
    /// means the app tunes nothing and inherits the baseline limits.
    pub(crate) limits: crate::sandbox::cgroup::Limits,
    /// Credentials to inject for this app (gated; the plaintext never enters the cage).
    pub(crate) secrets: Vec<HeaderSecret>,
    /// Per-field provenance of this app's *scalar* overlay fields, for the per-app `ops config`
    /// view — which app layer (`Global`/`Project`) set each. Read only when the app actually set
    /// the field; an unset scalar is shown as inherited from the baseline. `home_scope_origin` is
    /// `None` for the built-in default (`Global`), since the home scope is an app-only concept with
    /// no baseline to inherit. The launcher ignores all of these (a display affordance).
    pub(crate) cmd_origin: Provenance,
    pub(crate) network_origin: Provenance,
    pub(crate) gui_origin: Provenance,
    pub(crate) limits_origin: LimitsOrigin,
    pub(crate) home_scope_origin: Option<Provenance>,
    /// Notes about what this app's resolution dropped or ignored — surfaced when the app is
    /// launched, not on every `ops run`.
    pub(crate) warnings: Vec<String>,
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
        for pkg in app.packages {
            upsert_package(&mut self.packages, pkg.name, pkg.backend, pkg.state);
        }
        for bind in app.ro_binds {
            if !self.ro_binds.contains(&bind) {
                self.ro_binds.push(bind);
            }
        }
        if let Some(network) = app.network {
            self.network = network;
        }
        if let Some(gui) = app.gui {
            self.gui = gui;
        }
        overlay_limits(&mut self.limits, app.limits);
        // Drop the baseline secret-posture warning: it judged the *baseline* network, but the app's
        // posture re-decides injection just below — keeping it would let `ops app <name>` both inject
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
    let mut binds: Vec<PathBuf> = Vec::new();
    let mut bind_layer: BTreeMap<PathBuf, Provenance> = BTreeMap::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();

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
    apply_packages(
        &mut packages,
        &mut warnings,
        GLOBAL_CONFIG,
        global.packages,
        TrustState::Trusted,
        false,
    );
    let nixpkgs_global = global
        .nixpkgs
        .and_then(|v| validate_nixpkgs(&mut warnings, GLOBAL_CONFIG, v));
    // The network posture is trusted by location at the global layer; an invalid or
    // unset value falls back to the default (shared). The origin is recorded as `Global` only
    // when the layer actually supplied a valid posture, so a `Default` is never mistaken for one.
    let mut network_origin = Provenance::Default;
    // The egress-stats toggle rides the `[network]` table (the global layer is trusted by location);
    // extract it before the field moves into `validate_network`. Default on.
    let mut egress_stats = true;
    if let Some(b) = global.network.as_ref().and_then(network_stats_of) {
        egress_stats = b;
    }
    let mut network = match global
        .network
        .and_then(|v| validate_network(&mut warnings, GLOBAL_CONFIG, v))
    {
        Some(policy) => {
            network_origin = Provenance::Global;
            policy
        }
        None => NetworkPolicy::default(),
    };
    // The GUI posture is trusted by location at the global layer; an invalid or unset value
    // falls back to the default (no display).
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
    // Resource limits are trusted by location at the global layer; each invalid field is dropped
    // (warned) and the built-in default kept. The origin is recorded per field that the layer set.
    let mut limits = validate_limits(&mut warnings, GLOBAL_CONFIG, global.limits);
    let mut limits_origin = LimitsOrigin::default();
    mark_limit_origins(&mut limits_origin, &limits, Provenance::Global);
    // Secrets are trusted by location at the global layer. The `[secret.defaults]` table is
    // captured for the global hosts and as the base a trusted project may extend.
    let mut secret_defaults = SecretDefaults::default();
    if let Some(section) = global.secret {
        if let Some(raw_defaults) = &section.defaults {
            secret_defaults = SecretDefaults::from_raw(raw_defaults);
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

    let mut nixpkgs_project = None;
    if let Some((proj, state)) = project {
        let trusted = state == TrustState::Trusted;
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
        apply_packages(
            &mut packages,
            &mut warnings,
            PROJECT_CONFIG,
            proj.packages,
            state,
            false,
        );
        // `nixpkgs` is a security field — a trusted project may pin its tools'
        // source; an untrusted or changed one may not point the catalogue elsewhere.
        if let Some(value) = proj.nixpkgs {
            if trusted {
                nixpkgs_project = validate_nixpkgs(&mut warnings, PROJECT_CONFIG, value);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `nixpkgs` override ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `network` is a security field — a trusted project may change the posture;
        // an untrusted or changed one may not narrow or widen the network.
        if let Some(value) = proj.network {
            if trusted {
                // The stats toggle rides the same trusted `[network]` table — honor it before the
                // field moves into `validate_network`, so a trusted project may turn its own audit
                // off (or back on). An untrusted project never reaches here, so it cannot.
                if let Some(b) = network_stats_of(&value) {
                    egress_stats = b;
                }
                if let Some(policy) = validate_network(&mut warnings, PROJECT_CONFIG, value) {
                    network = policy;
                    network_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `network` policy ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `gui` is a security field — a trusted project may open a display; an untrusted or
        // changed one may not (exposing a compositor socket is a confidentiality and integrity
        // choice an untrusted project must not make).
        if let Some(value) = proj.gui {
            if trusted {
                if let Some(policy) = validate_gui(&mut warnings, PROJECT_CONFIG, value) {
                    gui = policy;
                    gui_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `gui` posture ({})",
                    untrusted_reason(state)
                ));
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
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `[limits]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // The `[secret]` section is a security field — a trusted project may inject
        // credentials (and extend the resolver defaults); an untrusted or changed one may
        // not (it would aim the user's secrets at a host of its choosing). The whole
        // section — defaults included — is dropped, with one count warning.
        if let Some(section) = proj.secret {
            if trusted {
                let effective = match &section.defaults {
                    Some(raw_defaults) => secret_defaults.merged_with(raw_defaults),
                    None => secret_defaults.clone(),
                };
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
                    warnings.push(format!(
                        "{PROJECT_CONFIG}: ignoring {n} secret(s) ({})",
                        untrusted_reason(state)
                    ));
                }
            }
        }
    }

    // Capture the declared baseline credentials before the posture clear: an app overlay that
    // opens a filtering posture inherits these (re-judged on its effective posture), even when the
    // baseline posture clears them from the baseline-effective `secrets`.
    let declared_secrets = secrets.clone();
    enforce_secret_posture(&network, &mut secrets, &mut warnings);

    let apps = resolve_apps(
        &mut warnings,
        global_apps,
        project_apps,
        &secret_defaults,
        plugins,
    );

    Resolved {
        env,
        env_layer,
        ro_binds: binds,
        bind_layer,
        packages,
        nixpkgs_global,
        nixpkgs_project,
        // A mise file is discovered by I/O in `load`; the pure layering never sees one.
        mise: None,
        network,
        network_origin,
        egress_stats,
        gui,
        gui_origin,
        limits,
        limits_origin,
        secrets,
        declared_secrets,
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

/// Validate a `[limits]` table into the resolved [`cgroup::Limits`](crate::sandbox::cgroup::Limits),
/// dropping any field whose value systemd would not accept (with a warning naming the field) so a
/// bad value can never reach `systemd-run` and brick a launch. A `None` table, or one whose every
/// field is unset or invalid, yields all-`None` — the built-in defaults. The per-field validators
/// mirror systemd's grammar exactly (verified against a live scope in the cgroup tests).
fn validate_limits(
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

/// Validate one memory limit (`memory_high`/`memory_max`): reject a value systemd would not
/// accept, and — the likely-typo guard — reject a *bare small byte count*, which is almost always
/// a percentage written without its `%` (`memory_max = 90` meaning 90 bytes, below the kernel
/// floor, which would brick the launch). Either rejection falls back to the field's default.
fn validate_memory_limit(
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
fn validate_tasks_limit(
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

/// The global config's resource limits, for `doctor` (host-level, with no project context). Reads
/// the global config — trusted by location — and validates its `[limits]`, discarding warnings:
/// `doctor` surfaces availability, while `ops config` is the project-aware, warning-bearing view.
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

/// Resolve every declared app into a gated overlay. The set of names is the union of the
/// global and project app tables; each app is layered global-under-project and gated by the
/// trust of the layer that supplied each field — identical to the baseline. An app whose name
/// is not a safe path component is dropped with a warning before it can ever key a directory.
fn resolve_apps(
    warnings: &mut Vec<String>,
    mut global_apps: BTreeMap<String, RawApp>,
    project_apps: Option<(BTreeMap<String, RawApp>, TrustState)>,
    secret_defaults: &SecretDefaults,
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
        if is_reserved_app_verb(&name) {
            warnings.push(format!(
                "ignoring app `{name}`: the name is a reserved `ops app` subcommand (rename it)"
            ));
            continue;
        }
        if !is_valid_app_name(&name) {
            warnings.push(format!(
                "ignoring app `{name}`: a name must be 1–64 of [A-Za-z0-9._-] and not `.`/`..` \
                 (it keys an on-disk home directory)"
            ));
            continue;
        }
        let global = global_apps.remove(&name);
        let project = project_apps.remove(&name).zip(project_state);
        let resolved = resolve_app(&name, global, project, secret_defaults, plugins);
        out.insert(name, resolved);
    }
    out
}

/// Whether an app name is safe to use as a single on-disk path component (it keys the app's
/// persistent home directory and, for an imported profile, its file). Restricted to a conservative
/// charset and length, and `.`/`..` are rejected outright so a name can never traverse out of a
/// directory. Reserved subcommand verbs are a *separate* check ([`is_reserved_app_verb`]) — a verb
/// like `rm` is otherwise a perfectly valid path component.
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
/// warnings, surfaced when the app is launched rather than on every `ops run`.
fn resolve_app(
    name: &str,
    global: Option<RawApp>,
    project: Option<(RawApp, TrustState)>,
    secret_defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> ResolvedApp {
    let mut warnings = Vec::new();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut ro_binds: Vec<PathBuf> = Vec::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();
    let mut network: Option<NetworkPolicy> = None;
    let mut gui: Option<GuiPolicy> = None;
    // The app's own cgroup limit overrides, accumulated like `network`/`gui`: the global layer
    // sets them by location, a trusted project overlays per field, an untrusted one is dropped.
    let mut limits = crate::sandbox::cgroup::Limits::default();
    let mut cmd: Vec<String> = Vec::new();
    // Whether the current `cmd` came from a trusted layer. An untrusted project may define its
    // *own* app's command, but may not override the command of an app a trusted layer defined
    // — else `ops app claude` against an untrusted repo would silently run the repo's command
    // under the trusted app's posture (an integrity-of-intent hijack).
    let mut cmd_trusted = false;
    // The persistent-home keying, defaulting to one global home per app. Integrity-gated by
    // `home_scope_trusted` for the same reason as `cmd`: an untrusted project may set the scope
    // of its own app, but must not flip a trusted app from `Project` to `Global` — that would
    // route the untrusted run into the home a trusted run shares.
    let mut home_scope = AppHomeScope::Global;
    let mut home_scope_trusted = false;
    // Per-field provenance of the scalar overlay fields, for the per-app `ops config` view: which
    // app layer set each, recorded at the same point the value is. A scalar the overlay never sets
    // stays `Default` here and the view shows it inherited from the baseline; `home_scope_origin`
    // stays `None` for the built-in default.
    let mut cmd_origin = Provenance::Default;
    let mut network_origin = Provenance::Default;
    let mut gui_origin = Provenance::Default;
    let mut limits_origin = LimitsOrigin::default();
    let mut home_scope_origin: Option<Provenance> = None;

    // The global layer — trusted by location, honored in full.
    if let Some(app) = global {
        let source = app_source(GLOBAL_CONFIG, name);
        apply_env(&mut env, None, &mut warnings, &source, app.env, false);
        apply_binds(&mut ro_binds, None, &mut warnings, &source, app.binds);
        apply_packages(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            TrustState::Trusted,
            false,
        );
        if let Some(field) = app.network {
            warn_if_app_sets_stats(&mut warnings, &source, &field);
            if let Some(policy) = validate_network(&mut warnings, &source, field) {
                network = Some(policy);
                network_origin = Provenance::Global;
            }
        }
        if let Some(value) = app.gui {
            if let Some(policy) = validate_gui(&mut warnings, &source, value) {
                gui = Some(policy);
                gui_origin = Provenance::Global;
            }
        }
        let global_limits = validate_limits(&mut warnings, &source, app.limits);
        mark_limit_origins(&mut limits_origin, &global_limits, Provenance::Global);
        overlay_limits(&mut limits, global_limits);
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
        if let Some(c) = app.cmd {
            cmd = c.into_argv();
            cmd_trusted = true;
            cmd_origin = Provenance::Global;
        }
        if let Some(raw) = app.home_scope {
            if let Some(scope) = validate_home_scope(&mut warnings, &source, &raw) {
                home_scope = scope;
                home_scope_trusted = true;
                home_scope_origin = Some(Provenance::Global);
            }
        }
    }

    // The project layer — gated by the project's verdict, overriding the global per field.
    if let Some((app, state)) = project {
        let trusted = state == TrustState::Trusted;
        let source = app_source(PROJECT_CONFIG, name);
        apply_env(&mut env, None, &mut warnings, &source, app.env, !trusted);
        if !app.binds.is_empty() {
            if trusted {
                apply_binds(&mut ro_binds, None, &mut warnings, &source, app.binds);
            } else {
                warnings.push(dropped_binds_warning(state, app.binds.len()));
            }
        }
        // An untrusted project may add its own app's packages but may not override a package a
        // trusted layer supplied (the `cmd`-integrity guard, applied to the tool).
        apply_packages(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            state,
            !trusted,
        );
        if let Some(field) = app.network {
            if trusted {
                warn_if_app_sets_stats(&mut warnings, &source, &field);
                if let Some(policy) = validate_network(&mut warnings, &source, field) {
                    network = Some(policy);
                    network_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `network` policy ({})",
                    untrusted_reason(state)
                ));
            }
        }
        // `gui` mirrors `network`: an untrusted project may not open a display, on its own app
        // or by overriding a trusted one (the flagship property — an agent runs *on* untrusted
        // code without that code being able to expose the user's compositor).
        if let Some(value) = app.gui {
            if trusted {
                if let Some(policy) = validate_gui(&mut warnings, &source, value) {
                    gui = Some(policy);
                    gui_origin = Provenance::Project;
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `gui` posture ({})",
                    untrusted_reason(state)
                ));
            }
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
                warnings.push(format!(
                    "{source}: ignoring `[limits]` ({})",
                    untrusted_reason(state)
                ));
            }
        }
        if let Some(section) = app.secret {
            if trusted {
                apply_app_secret(
                    &mut secrets,
                    &mut warnings,
                    &source,
                    section,
                    secret_defaults,
                    plugins,
                );
            } else {
                let n = count_host_secrets(&section.hosts);
                if n > 0 {
                    warnings.push(format!(
                        "{source}: ignoring {n} secret(s) ({})",
                        untrusted_reason(state)
                    ));
                }
            }
        }
        if let Some(c) = app.cmd {
            if trusted || !cmd_trusted {
                cmd = c.into_argv();
                cmd_origin = Provenance::Project;
            } else {
                warnings.push(format!(
                    "{source}: ignoring `cmd` override of a trusted app ({})",
                    untrusted_reason(state)
                ));
            }
        }
        if let Some(raw) = app.home_scope {
            // A trusted project may set any scope; an untrusted one may set its own app's scope
            // (nothing trusted to override) but not flip a trusted app — which could only widen
            // it to the shared `Global` home, the contamination vector.
            if trusted || !home_scope_trusted {
                if let Some(scope) = validate_home_scope(&mut warnings, &source, &raw) {
                    home_scope = scope;
                    home_scope_origin = Some(Provenance::Project);
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `home_scope` override of a trusted app ({})",
                    untrusted_reason(state)
                ));
            }
        }
    }

    ResolvedApp {
        cmd,
        home_scope,
        env,
        ro_binds,
        packages,
        network,
        gui,
        limits,
        secrets,
        cmd_origin,
        network_origin,
        gui_origin,
        limits_origin,
        home_scope_origin,
        warnings,
    }
}

/// Parse an app's `home_scope` string into [`AppHomeScope`]. An unrecognized value is dropped
/// with a warning and the caller keeps the prior (defaulting to `Global`) — fail-safe, never a
/// silent mis-scope.
fn validate_home_scope(
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
        Some(raw) => base_defaults.merged_with(raw),
        None => base_defaults.clone(),
    };
    apply_secret_section(out, warnings, source, section.hosts, &effective, plugins);
}

/// The warning source label for a field of `[app.<name>]` in a given config file — e.g.
/// `".ops.toml [app.claude]"` — so a dropped app field reads as clearly as a baseline one.
fn app_source(config: &str, name: &str) -> String {
    format!("{config} [app.{name}]")
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

/// Fold a layer's binds into `out`, requiring each to be an absolute path. A
/// relative bind is dropped with a warning: the project is already mounted in
/// full, so an extra bind is by definition an out-of-project path, and resolving a
/// relative one against the working directory would be a surprise.
fn apply_binds(
    out: &mut Vec<PathBuf>,
    mut origin: Option<(Provenance, &mut BTreeMap<PathBuf, Provenance>)>,
    warnings: &mut Vec<String>,
    source: &str,
    binds: Vec<String>,
) {
    for b in binds {
        let p = PathBuf::from(&b);
        if p.is_absolute() {
            // Record the layer keyed by the raw declared path; [`load`] re-keys it to the
            // canonical form when it canonicalizes, so the displayed path is the lookup key.
            if let Some((layer, map)) = origin.as_mut() {
                map.insert(p.clone(), *layer);
            }
            out.push(p);
        } else {
            warnings.push(format!("{source}: ignoring non-absolute bind `{b}`"));
        }
    }
}

/// Fold a layer's packages into `out`, validating the label and parsing the value's
/// mandatory backend prefix, stamping each with whether its source layer is trusted. A
/// later layer overrides an earlier one at the same name, so a project can pin a tool
/// the global set named. Nothing is dropped for trust here — that belongs to the
/// launcher; this is a pure merge. A malformed label, or a value with no `nix:`/`mise:`
/// prefix, *is* dropped (with a warning): it could never realise, and a label names an
/// on-disk path — fail-closed, never a silent mis-route.
fn apply_packages(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    packages: BTreeMap<String, String>,
    state: TrustState,
    protect_trusted: bool,
) {
    for (name, value) in packages {
        if !is_valid_package_name(&name) {
            warnings.push(format!(
                "{source}: ignoring malformed package name `{name}`"
            ));
            continue;
        }
        // When `protect_trusted` is set (an untrusted project layering over a trusted app),
        // a package a trusted layer already supplied may not be overridden — the integrity-of-
        // intent guard `cmd` has, applied to the tool: else an untrusted project could swap a
        // trusted app's `claude-code` for its own attribute and either run attacker code (closed
        // separately by `[packages]` being trusted-only) or simply deny the app its tool. A new
        // name may still be added.
        if protect_trusted
            && out
                .iter()
                .any(|p| p.name == name && p.state == TrustState::Trusted)
        {
            warnings.push(format!(
                "{source}: ignoring package `{name}` override of a trusted app ({})",
                untrusted_reason(state)
            ));
            continue;
        }
        let backend = match parse_backend(&value) {
            Ok(b) => b,
            Err(reason) => {
                warnings.push(format!("{source}: ignoring package `{name}`: {reason}"));
                continue;
            }
        };
        upsert_package(out, name, backend, state);
    }
}

/// Parse a `[packages]` value into its [`Backend`] from the mandatory prefix. `nix:<attr>`
/// routes to host-side nixpkgs provisioning, `mise:<token>` to the in-cage mise equip,
/// `flake:<ref>` to an in-cage `nix build` of an arbitrary flake; a value with no recognized
/// prefix is rejected (there is no bare form, so the backend is always explicit). The part
/// after `mise:` is the full mise token — including a `nix:`-prefixed nixhub token
/// (`mise:nix:<pkg>`), which is mise's concern, not a third nix code path here. `flake:` is
/// matched before `nix:` only by being a distinct prefix; the two never overlap.
fn parse_backend(value: &str) -> Result<Backend, String> {
    if let Some(attr) = value.strip_prefix("nix:") {
        if !is_valid_attr(attr) {
            return Err(format!("invalid nix attribute `{attr}`"));
        }
        Ok(Backend::Nix(attr.to_string()))
    } else if let Some(token) = value.strip_prefix("mise:") {
        if !is_valid_mise_token(token) {
            return Err(format!("invalid mise token `{token}`"));
        }
        Ok(Backend::Mise(token.to_string()))
    } else if let Some(reference) = value.strip_prefix("flake:") {
        if !is_valid_flake_ref(reference) {
            return Err(format!("invalid flake reference `{reference}`"));
        }
        Ok(Backend::Flake(reference.to_string()))
    } else {
        Err(format!(
            "`{value}` needs a backend prefix — use `nix:<attribute>`, `mise:<token>`, \
             or `flake:<ref>`"
        ))
    }
}

/// Set the package named `name` to `backend` with the supplying layer's trust,
/// overriding an existing entry so a later layer wins while preserving declaration
/// order.
fn upsert_package(out: &mut Vec<Package>, name: String, backend: Backend, state: TrustState) {
    match out.iter_mut().find(|p| p.name == name) {
        Some(slot) => {
            slot.backend = backend;
            slot.state = state;
        }
        None => out.push(Package {
            name,
            backend,
            state,
        }),
    }
}

/// The actionable reason a project's security-relevant value is held back, phrased
/// for the action it implies: a since-*changed* project points at re-approval, a
/// never-trusted one at first approval. Shared by the package launcher and
/// `ops config` so the two never phrase the same verdict differently.
pub(crate) fn untrusted_reason(state: TrustState) -> &'static str {
    match state {
        TrustState::Changed => "changed since it was trusted — re-run `ops trust`",
        _ => "untrusted — run `ops trust`",
    }
}

/// Validate a `nixpkgs` override source, returning it when well-formed and warning
/// when not. Dropping a malformed source keeps a bad value from reaching nix.
fn validate_nixpkgs(
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
fn validate_gui(
    warnings: &mut Vec<String>,
    source_label: &str,
    value: String,
) -> Option<GuiPolicy> {
    match value.as_str() {
        "none" => Some(GuiPolicy::None),
        "wayland" => Some(GuiPolicy::Wayland),
        other => {
            warnings.push(format!(
                "{source_label}: ignoring unknown gui posture `{other}` \
                 (expected \"none\" or \"wayland\")"
            ));
            None
        }
    }
}

/// Validate a `network` field — either a posture string or an allowlist table —
/// mapping it to a policy and warning on anything unrecognized. A typo must never
/// silently leave the network in the wrong posture; returning `None` keeps the prior
/// (default or global) posture rather than guessing.
fn validate_network(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: NetworkField,
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
        NetworkField::Table(table) => validate_network_table(warnings, source_label, table),
    }
}

/// Validate the table form of `network`: `none`/`shared` behave as the string form,
/// `allowlist` classifies each declared entry (a malformed one is dropped with a
/// warning, fail-closed — that host simply stays unreachable, never silently allowed).
fn validate_network_table(
    warnings: &mut Vec<String>,
    source_label: &str,
    table: NetworkTable,
) -> Option<NetworkPolicy> {
    match table.mode.as_str() {
        "none" => Some(NetworkPolicy::Isolated),
        "shared" => Some(NetworkPolicy::Shared),
        // `deny` is the canonical name for the classic deny-by-default allowlist; `allowlist`
        // is its permanently-kept backward-compatible alias. `allow` is the denylist: everything
        // public reaches except the `deny` carve-outs, proxy still active. `ask` parks an unmatched
        // request for a live decision (allow rules auto-pass, deny rules auto-fail).
        "deny" | "allowlist" | "allow" | "ask" => {
            use crate::allowlist::DefaultAction;
            let allow = classify_entries(warnings, source_label, "allow", table.allow);
            let deny = classify_entries(warnings, source_label, "deny", table.deny);
            let policy = crate::allowlist::EgressPolicy::new(allow, deny);
            let policy = match table.mode.as_str() {
                "allow" => policy.with_default(DefaultAction::Allow),
                "ask" => {
                    // A configured `ask_timeout` bounds the parked wait; a malformed value falls
                    // back to indefinite (warned), never a hard config failure.
                    let timeout = match &table.ask_timeout {
                        None => None,
                        Some(raw) => parse_ask_timeout(raw).unwrap_or_else(|reason| {
                            warnings.push(format!(
                                "{source_label}: ignoring invalid `ask_timeout` — {reason}; \
                                 parked requests will wait indefinitely"
                            ));
                            None
                        }),
                    };
                    policy
                        .with_default(DefaultAction::Ask)
                        .with_ask_timeout(timeout)
                        .with_ask_notice(table.ask_notice.unwrap_or(true))
                }
                _ => policy, // `deny` / the `allowlist` alias: deny-by-default
            };
            // An `ask_timeout` outside `ask` mode is moot — flag it rather than silently drop it.
            if table.mode != "ask" && table.ask_timeout.is_some() {
                warnings.push(format!(
                    "{source_label}: `ask_timeout` is only meaningful under `mode = \"ask\"` — ignored"
                ));
            }
            // Likewise an `ask_notice` outside `ask` mode is moot (parity with `ask_timeout`).
            if table.mode != "ask" && table.ask_notice.is_some() {
                warnings.push(format!(
                    "{source_label}: `ask_notice` is only meaningful under `mode = \"ask\"` — ignored"
                ));
            }
            Some(NetworkPolicy::Allowlist(policy))
        }
        other => {
            warnings.push(format!(
                "{source_label}: ignoring unknown network mode `{other}` (expected \"none\", \
                 \"shared\", \"deny\", \"allow\", \"ask\", or the \"allowlist\" alias)"
            ));
            None
        }
    }
}

/// Parse an `ask_timeout` duration string: a non-negative integer with an optional unit suffix
/// (`s` seconds [the default], `m` minutes, `h` hours), e.g. `"90s"`, `"5m"`, `"2h"`, or a bare
/// `"90"`. A zero-valued form (`"0"`, `"0m"`) means no timeout — an indefinite wait, the same as
/// omitting the field — so it returns `Ok(None)`; a positive value returns `Ok(Some(duration))`.
/// A malformed value is `Err(reason)` so the caller can warn and fall back to indefinite.
fn parse_ask_timeout(raw: &str) -> Result<Option<std::time::Duration>, String> {
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
        .ok_or_else(|| format!("`{raw}` is too large"))?;
    Ok((secs > 0).then(|| std::time::Duration::from_secs(secs)))
}

/// Classify the entries of one egress list (`allow` or `deny`), dropping a malformed
/// entry with a warning that names which list it was in. Dropping fails closed: a bad
/// `allow` entry leaves that host unreachable, and a bad `deny` entry leaves its carve-out
/// off — never the reverse.
fn classify_entries(
    warnings: &mut Vec<String>,
    source_label: &str,
    list: &str,
    entries: Vec<String>,
) -> Vec<crate::allowlist::Rule> {
    let mut rules = Vec::new();
    for entry in entries {
        match crate::allowlist::classify(&entry) {
            Ok(rule) => rules.push(rule),
            Err(e) => warnings.push(format!("{source_label}: ignoring {list} entry — {e}")),
        }
    }
    rules
}

/// Validate and fold a layer's `[secret]` host entries into `out`, expanding any terse `key`
/// through `defaults`. Each entry is fully validated (kind, source, target, header, type); a
/// malformed one is dropped with a warning naming the host — fail-closed, since a credential
/// injection is security-relevant. A later entry for the same (host, header) overrides an
/// earlier one (last-wins) with a warning, so a duplicate destination never silently emits two
/// header copies upstream.
fn apply_secret_section(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    hosts: BTreeMap<String, RawHostSecrets>,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) {
    for (host, entry) in hosts {
        let list = match entry {
            RawHostSecrets::One(s) => vec![s],
            RawHostSecrets::Many(v) => v,
        };
        for raw in list {
            match validate_host_secret(&host, raw, defaults, plugins) {
                Ok(secret) => upsert_secret(out, warnings, source, secret),
                Err(e) => warnings.push(format!("{source}: ignoring secret for `{host}` — {e}")),
            }
        }
    }
}

/// Total host secrets in a section — counting each element of a `[[secret."host"]]` array — for
/// the one-line warning when an untrusted project's whole section is dropped.
fn count_host_secrets(hosts: &BTreeMap<String, RawHostSecrets>) -> usize {
    hosts
        .values()
        .map(|h| match h {
            RawHostSecrets::One(_) => 1,
            RawHostSecrets::Many(v) => v.len(),
        })
        .sum()
}

/// Set the secret for its (target, header) pair, overriding an existing one (last-wins)
/// with a warning while preserving declaration order. Two secrets to the same host and
/// header would otherwise inject two copies of the header upstream.
fn upsert_secret(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    secret: HeaderSecret,
) {
    match out
        .iter_mut()
        .find(|s| s.to == secret.to && s.header.eq_ignore_ascii_case(&secret.header))
    {
        Some(slot) => {
            warnings.push(format!(
                "{source}: a later secret overrides an earlier one for `{}` -> {}",
                secret.header, secret.to
            ));
            *slot = secret;
        }
        None => out.push(secret),
    }
}

/// Validate one host entry into a [`HeaderSecret`], or report why it is malformed. `host` is the
/// section key (the injection target). Every check fails closed: an unknown kind, a missing or
/// both-set source, a non-concrete target, a bad header name, or a missing/unknown type each
/// drops the secret. `kind` is optional, defaulting to the only kind today.
fn validate_host_secret(
    host: &str,
    raw: RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<HeaderSecret, String> {
    let kind = raw.kind.as_deref().unwrap_or("http-header");
    if kind != "http-header" {
        return Err(format!(
            "unknown kind `{kind}` (the only secret kind today is \"http-header\")"
        ));
    }
    let sources = resolve_host_sources(&raw, defaults, plugins)?;
    let to = validate_secret_target(host)?;
    // `header` and `type` may come from the entry or fall back to `[secret.defaults]`; an entry
    // that names neither (on itself or in the defaults) is the same explicit error as before —
    // there is no silent built-in default.
    let header = raw
        .header
        .as_deref()
        .or(defaults.header.as_deref())
        .ok_or_else(|| {
            "set `header` (or a `[secret.defaults] header`) — the request header to set".to_string()
        })?;
    validate_header_name(header)?;
    let value_type = raw.value_type.as_deref().or(defaults.value_type.as_deref());
    let shape = validate_header_shape(value_type, raw.prefix.as_deref())?;
    Ok(HeaderSecret {
        sources,
        to,
        header: header.to_string(),
        shape,
    })
}

/// The resolver chain for a host secret: either the explicit `from` (a single `scheme://locator`
/// ref or a list tried in order) or the terse `key` expanded through `defaults` — exactly one of
/// the two. Both set, or neither, is rejected; an empty `from` list is rejected. The values are
/// not read here; that is host-side at launch.
fn resolve_host_sources(
    raw: &RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<Vec<SecretSource>, String> {
    match (raw.key.as_deref(), &raw.from) {
        (Some(_), Some(_)) => {
            Err("set `key` or `from`, not both — a secret has one source form".to_string())
        }
        (None, None) => Err(
            "set `key` or `from` — a secret needs a source (e.g. `key = \"github_token\"` \
                 or `from = \"env://VAR\"`)"
                .to_string(),
        ),
        (Some(key), None) => expand_key(key, defaults),
        (None, Some(from)) => {
            let refs: &[String] = match from {
                SecretFrom::One(one) => std::slice::from_ref(one),
                SecretFrom::Many(list) => {
                    if list.is_empty() {
                        return Err(
                            "`from` is an empty list — declare at least one resolver ref"
                                .to_string(),
                        );
                    }
                    list
                }
            };
            refs.iter().map(|r| parse_secret_ref(r, plugins)).collect()
        }
    }
}

/// The validated `[secret.defaults]` — the resolver order and per-resolver bindings a terse `key`
/// expands through, plus a default `header`/`type` an entry may omit. Built per config layer;
/// bindings and the header/type are validated lazily, when an entry actually uses them, so a
/// defaults table no entry references never blocks a launch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SecretDefaults {
    /// Resolver names to try, in order, for an unpinned key.
    order: Vec<String>,
    /// The sops file a terse sops key reads from (`sops://<file>#<key>`).
    sops_file: Option<String>,
    /// How to case a terse key before using it as a variable name (`upper`/`lower`/`asis`).
    env_case: Option<String>,
    /// The base directory a terse file key reads from (`file://<dir>/<key>`).
    file_dir: Option<String>,
    /// The default header name for an entry that omits `header`.
    header: Option<String>,
    /// The default value type for an entry that omits `type`.
    value_type: Option<String>,
}

impl SecretDefaults {
    /// The defaults declared in one `[secret.defaults]` table.
    fn from_raw(raw: &RawSecretDefaults) -> Self {
        Self {
            order: raw.order.clone(),
            sops_file: raw.sops.as_ref().map(|s| s.file.clone()),
            env_case: raw.env.as_ref().and_then(|e| e.case.clone()),
            file_dir: raw.file.as_ref().map(|f| f.dir.clone()),
            header: raw.header.clone(),
            value_type: raw.value_type.clone(),
        }
    }

    /// These defaults overridden field-by-field by a project's `[secret.defaults]`: an order, a
    /// binding, or a header/type the project sets wins; anything it omits inherits the global value.
    fn merged_with(&self, raw: &RawSecretDefaults) -> Self {
        Self {
            order: if raw.order.is_empty() {
                self.order.clone()
            } else {
                raw.order.clone()
            },
            sops_file: raw
                .sops
                .as_ref()
                .map(|s| s.file.clone())
                .or_else(|| self.sops_file.clone()),
            env_case: raw
                .env
                .as_ref()
                .and_then(|e| e.case.clone())
                .or_else(|| self.env_case.clone()),
            file_dir: raw
                .file
                .as_ref()
                .map(|f| f.dir.clone())
                .or_else(|| self.file_dir.clone()),
            header: raw.header.clone().or_else(|| self.header.clone()),
            value_type: raw.value_type.clone().or_else(|| self.value_type.clone()),
        }
    }
}

/// Expand a terse `key` spec into a resolver chain. The spec is `name[@resolver[,resolver…]]`:
/// without a `@` pin the default `order` is used; with one, exactly those resolvers in that
/// order, for this secret only. The `name` is validated as a conservative dotted key (so it can
/// never carry a path separator into the `file`/`sops` locator), each resolver builds a
/// `scheme://locator` ref, and the existing [`parse_secret_ref`] validates it — one validation
/// path for terse and explicit sources alike. A missing binding or an empty order fails closed.
fn expand_key(spec: &str, defaults: &SecretDefaults) -> Result<Vec<SecretSource>, String> {
    let (name, resolvers) = match spec.rsplit_once('@') {
        Some((name, pin)) => {
            let list: Vec<String> = pin.split(',').map(|r| r.trim().to_string()).collect();
            if list.iter().any(String::is_empty) {
                return Err(format!(
                    "the key `{spec}` has an empty resolver name after `@`"
                ));
            }
            (name, list)
        }
        None => (spec, defaults.order.clone()),
    };
    validate_terse_key(name)?;
    if resolvers.is_empty() {
        return Err(format!(
            "no resolver for key `{name}`: set `[secret.defaults] order` or pin it (e.g. \
             `{name}@env`)"
        ));
    }
    // A terse `key` only ever expands to a built-in resolver ref (`build_ref` emits `env://`,
    // `sops://`, or `file://`), so the registry is intentionally empty here: terse plugin
    // bindings (`key@<plugin>`) are a deliberate later addition, not silently in scope.
    let builtins_only = PluginRegistry::default();
    resolvers
        .iter()
        .map(|r| parse_secret_ref(&build_ref(r, name, defaults)?, &builtins_only))
        .collect()
}

/// Build a `scheme://locator` ref for one resolver from a terse `key`, applying that resolver's
/// binding: `env` cases the key into a variable name; `sops` joins the key onto the bound file
/// (`<file>#<key>`); `file` joins it onto the bound base directory (`<dir>/<key>`). A resolver
/// whose binding is unset, or an unknown resolver name, fails closed.
fn build_ref(resolver: &str, key: &str, defaults: &SecretDefaults) -> Result<String, String> {
    match resolver {
        "env" => {
            let name = match defaults.env_case.as_deref() {
                None | Some("asis") => key.to_string(),
                Some("upper") => key.to_ascii_uppercase(),
                Some("lower") => key.to_ascii_lowercase(),
                Some(other) => {
                    return Err(format!(
                        "unknown env `case` `{other}` (expected \"upper\", \"lower\", or \"asis\")"
                    ))
                }
            };
            Ok(format!("env://{name}"))
        }
        "sops" => {
            let file = defaults.sops_file.as_deref().ok_or_else(|| {
                format!("key `{key}` uses the sops resolver, but `[secret.defaults.sops] file` is unset")
            })?;
            if file.contains('#') {
                return Err(format!(
                    "the sops file `{file}` contains `#`, reserved by the `sops://<file>#<key>` form"
                ));
            }
            Ok(format!("sops://{file}#{key}"))
        }
        "file" => {
            let dir = defaults.file_dir.as_deref().ok_or_else(|| {
                format!(
                    "key `{key}` uses the file resolver, but `[secret.defaults.file] dir` is unset"
                )
            })?;
            if !std::path::Path::new(dir).is_absolute() {
                return Err(format!(
                    "the `[secret.defaults.file] dir` `{dir}` must be an absolute path"
                ));
            }
            let sep = if dir.ends_with('/') { "" } else { "/" };
            Ok(format!("file://{dir}{sep}{key}"))
        }
        other => Err(format!(
            "unknown resolver `{other}` for key `{key}` (built-in: env, file, sops)"
        )),
    }
}

/// Validate a terse `key`: dot-separated segments, each non-empty and made of letters, digits,
/// `_`, or `-`. Stricter than an env variable name on purpose — it forbids `/` and `..`, so a key
/// joined onto a `file`/`sops` locator can never carry a path separator or traverse out of the
/// bound directory.
fn validate_terse_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("a terse `key` is empty".to_string());
    }
    for seg in key.split('.') {
        if seg.is_empty() {
            return Err(format!("the key `{key}` has an empty segment"));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the key `{key}` has an invalid segment `{seg}` (allowed: letters, digits, _, -, \
                 separated by `.`)"
            ));
        }
    }
    Ok(())
}

/// Parse one `from` entry — a `scheme://locator` resolver ref — into a [`SecretSource`]. The
/// built-in schemes are `env`, `file`, and `sops`; any other scheme must be claimed by an
/// installed resolver plugin, else it is an error. A bare token with no `://` is an error too
/// (fail-closed: never a silent mis-read as a path or a variable).
fn parse_secret_ref(reff: &str, plugins: &PluginRegistry) -> Result<SecretSource, String> {
    let Some((scheme, locator)) = reff.split_once("://") else {
        return Err(format!(
            "a secret source needs a scheme, e.g. `env://VAR` or `file:///abs/path` (`{reff}`)"
        ));
    };
    match scheme {
        "env" => env_source(locator),
        "file" => file_source(locator),
        "sops" => sops_source(locator),
        other => match plugins.resolver(other) {
            Some(plugin) => {
                validate_plugin_locator(other, locator)?;
                Ok(SecretSource::Plugin {
                    plugin: plugin.clone(),
                    locator: locator.to_string(),
                })
            }
            None => Err(format!(
                "unknown secret resolver scheme `{other}://` (built-in: env, file, sops; \
                 or install a resolver plugin that claims it)"
            )),
        },
    }
}

/// Validate a plugin ref's locator before it becomes the plugin's `argv[1]`: non-empty and free
/// of control characters (a NUL would truncate the argument, a newline could confuse a
/// line-oriented resolver). The trust gate is the real control — an untrusted project's secrets
/// are dropped before this is reached — so this is belt-and-suspenders for the trusted path.
fn validate_plugin_locator(scheme: &str, locator: &str) -> Result<(), String> {
    if locator.is_empty() {
        return Err(format!("the `{scheme}://` ref has an empty locator"));
    }
    if locator.chars().any(char::is_control) {
        return Err(format!(
            "the `{scheme}://` ref locator contains a control character"
        ));
    }
    Ok(())
}

/// An `env` source from a variable name, validated as a usable shell variable name.
fn env_source(var: &str) -> Result<SecretSource, String> {
    if !is_valid_env_key(var) {
        return Err(format!("`{var}` is not a valid environment variable name"));
    }
    Ok(SecretSource::Env(var.to_string()))
}

/// A `sops` source from `<file>[#<dotted.key>]`. The `#` is split off the **end** (a sops key
/// cannot contain `#`, so a `#` in the file path is preserved); the key, when present, is
/// charset-validated so it can never malform the `["seg"]["seg"]` extract expression sops parses.
/// The file may be relative (resolved against the project root host-side) or absolute.
fn sops_source(locator: &str) -> Result<SecretSource, String> {
    let (file, key) = match locator.rsplit_once('#') {
        Some((f, k)) => (f, Some(k)),
        None => (locator, None),
    };
    if file.is_empty() {
        return Err("a sops source needs a file path `sops://<file>[#<key>]`".to_string());
    }
    if let Some(k) = key {
        validate_sops_key(k)?;
    }
    Ok(SecretSource::Sops {
        file: PathBuf::from(file),
        key: key.map(String::from),
    })
}

/// Validate a sops `--extract` key path: dot-separated segments, each non-empty and made of
/// letters, digits, `_`, or `-`. Rejects an empty key (a trailing `#`), an empty segment
/// (`a..b`, `.a`, `a.`), and any character that could break the bracketed extract expression.
fn validate_sops_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("the sops source has an empty key after `#`".to_string());
    }
    for seg in key.split('.') {
        if seg.is_empty() {
            return Err(format!("the sops key `{key}` has an empty path segment"));
        }
        if !seg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!(
                "the sops key `{key}` has an invalid segment `{seg}` (allowed: letters, digits, _, -)"
            ));
        }
    }
    Ok(())
}

/// A `file` source from an absolute host path (a relative path is rejected — it would resolve
/// against an unpredictable working directory).
fn file_source(file: &str) -> Result<SecretSource, String> {
    let path = PathBuf::from(file);
    if !path.is_absolute() {
        return Err(format!(
            "a file secret path must be an absolute path `{file}`"
        ));
    }
    Ok(SecretSource::File(path))
}

/// Classify a secret's `to` into a concrete-host rule. A credential goes to one known
/// destination, so only an exact host, IP, or `host[:port]/path` URL is allowed — a
/// `*.domain` wildcard or a `re:` regex is rejected, since either could match a host the
/// user never meant to hand the secret to.
fn validate_secret_target(to: &str) -> Result<Rule, String> {
    let rule = crate::allowlist::classify(to).map_err(|e| format!("invalid `to` target — {e}"))?;
    match rule.kind {
        RuleKind::Ip(..) | RuleKind::Host(..) | RuleKind::Url { .. } => Ok(rule),
        RuleKind::Subdomain(..) => Err(format!(
            "`to` must be a concrete host, not the `*.` wildcard `{to}` \
             (a credential is sent to one known host)"
        )),
        RuleKind::Regex { .. } => Err(format!(
            "`to` must be a concrete host, not the regex `{to}` \
             (a credential is sent to one known host)"
        )),
    }
}

/// A header name usable in a request head: a non-empty token free of control characters,
/// whitespace, and `:`, so it can never split the head or carry a second header.
fn validate_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the `header` name is empty".to_string());
    }
    if name
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == ':')
    {
        return Err(format!("invalid `header` name `{name}`"));
    }
    Ok(())
}

/// Build the [`HeaderShape`] from the required `type` and the optional `prefix`. The type
/// is required — there is no default, so an omitted type is an explicit error rather than a
/// silent (and likely wrong) transform. A given `prefix` may carry no control character,
/// since it becomes part of the header value.
fn validate_header_shape(
    value_type: Option<&str>,
    prefix: Option<&str>,
) -> Result<HeaderShape, String> {
    if let Some(p) = prefix {
        if p.chars().any(char::is_control) {
            return Err("the `prefix` contains a control character".to_string());
        }
    }
    let (default_prefix, base64) =
        match value_type {
            Some("bearer") => ("Bearer ", false),
            Some("raw") => ("", false),
            Some("basic") => ("Basic ", true),
            Some(other) => {
                return Err(format!(
                    "unknown `type` `{other}` (expected \"bearer\", \"basic\", or \"raw\")"
                ))
            }
            None => return Err(
                "missing `type` (one of \"bearer\", \"basic\", or \"raw\"; set it on the secret \
                 or as a `[secret.defaults] type`)"
                    .to_string(),
            ),
        };
    Ok(HeaderShape {
        prefix: prefix.unwrap_or(default_prefix).to_string(),
        base64,
    })
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

/// An env key usable with `--setenv`: non-empty, and free of `=` and control
/// characters (NUL, newline). A malformed key — reachable through a quoted TOML
/// key — is dropped rather than handed to the sandbox.
fn is_valid_env_key(key: &str) -> bool {
    !key.is_empty() && !key.contains('=') && !key.chars().any(char::is_control)
}

/// A package label usable as a single path component (it names a garbage-collection
/// root) and a stable merge key: non-empty, neither `.` nor `..`, and built only
/// from portable filename characters — so it can never carry a path separator,
/// escape its directory, or collide with a traversal element.
fn is_valid_package_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// A nixpkgs attribute path: a dotted chain of attribute names (e.g.
/// `python3Packages.requests`). Restricted to the characters a real attribute uses
/// so a declared value can never widen into a different flake reference or smuggle
/// shell- or flake-significant characters, even though it is passed to nix as a
/// single argument.
fn is_valid_attr(attr: &str) -> bool {
    !attr.is_empty()
        && attr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// A mise backend token (the part after `mise:`), e.g. `aqua:openai/codex`, `opencode`,
/// `npm:@anthropic-ai/claude-code`, or `aqua:openai/codex@0.141.0`. It rides the equip
/// wrapper positionally, so it cannot inject shell whatever it contains; the charset is
/// still restricted to what a real token uses (no whitespace or control characters) so a
/// malformed value is refused rather than handed to mise.
fn is_valid_mise_token(token: &str) -> bool {
    !token.is_empty()
        && token.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '@' | '.' | '_' | '-' | '+')
        })
}

/// A flake reference (the part after `flake:`), e.g. `github:owner/repo#attr`,
/// `github:owner/repo/rev#attr`, or `git+https://host/repo?ref=main#attr`. It rides the
/// in-cage build wrapper positionally, so it cannot inject shell whatever it contains; the
/// charset is still restricted to what a real flake ref uses — the URL-significant
/// characters (`:` `/` `#` `?` `=` `&` `~`) plus the identifier set — so a malformed or
/// shell/space-bearing value is refused rather than handed to nix. **Local sources are
/// rejected** so a package declaration can never point the in-cage build at a filesystem
/// path: not only the explicit local schemes (`path:`, and any `file:` or `+file:` scheme —
/// `file://`, `git+file:`, `tarball+file:`, …) but also a **bare path-flakeref** — nix treats a
/// ref starting with `/`, `.`, or `~` as a local path — and an ambiguous registry-indirect ref
/// (`nixpkgs`), by *requiring an explicit scheme* (a `:`). A real remote ref always carries one
/// (`github:`, `git+https:`, `gitlab:`, …).
fn is_valid_flake_ref(reference: &str) -> bool {
    if reference.is_empty()
        || reference.starts_with("path:")
        || reference.starts_with("file:")
        || reference.contains("+file:")
        || reference.starts_with('/')
        || reference.starts_with('.')
        || reference.starts_with('~')
        || !reference.contains(':')
    {
        return false;
    }
    reference.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                ':' | '/' | '#' | '?' | '=' | '&' | '~' | '@' | '.' | '_' | '-' | '+'
            )
    })
}

/// Set `key` to `val`, overriding an existing entry so a later layer wins over an
/// earlier one at the same key while preserving declaration order.
fn upsert(env: &mut Vec<(String, String)>, key: String, val: String) {
    match env.iter_mut().find(|(k, _)| *k == key) {
        Some(slot) => slot.1 = val,
        None => env.push((key, val)),
    }
}

/// The warning for security binds dropped from an untrusted project, made
/// actionable: a *changed* file points at re-approval, a never-trusted one at the
/// first approval.
fn dropped_binds_warning(state: TrustState, count: usize) -> String {
    match state {
        TrustState::Changed => format!(
            "{PROJECT_CONFIG} changed since it was trusted: dropping {count} bind(s) — \
             re-run `ops trust` to re-approve"
        ),
        _ => format!(
            "{PROJECT_CONFIG} is untrusted: dropping {count} bind(s) — \
             run `ops trust` to apply them"
        ),
    }
}

/// Which configuration layers feed a resolution. `All` is what a launch and the full `ops config
/// show` use; the restricted forms back the single-source `ops config show --global/--local/
/// --default` views, each showing what one layer contributes (over the built-in defaults) so the
/// provenance tags read as that layer's own additions. Plugins and bind canonicalization are
/// unaffected — only which config *files* are read changes.
#[derive(Clone, Copy)]
pub(crate) enum Source {
    /// Global config (and imported profiles) layered under the project — the default.
    All,
    /// The global config and imported profiles only; the project layer is ignored.
    Global,
    /// The project config only; the global config and imported profiles are ignored.
    Local,
    /// Neither config; the built-in defaults alone.
    Default,
}

impl Source {
    fn includes_global(self) -> bool {
        matches!(self, Source::All | Source::Global)
    }

    fn includes_project(self) -> bool {
        matches!(self, Source::All | Source::Local)
    }
}

/// Load and resolve the configuration for a project rooted at `cwd`. Infallible by
/// design: every failure mode (absent, unsafe, unparseable, no trust store)
/// degrades to a warning and a dropped layer, so a command is never blocked by a
/// bad config — least of all an attacker-controlled project one.
pub(crate) fn load(cwd: &Path) -> Resolved {
    load_scoped(cwd, Source::All)
}

/// Resolve the configuration for `cwd` restricted to `source`'s layers. `load_scoped(cwd,
/// Source::All)` is [`load`] — the launch and full-view path; the restricted forms read fewer
/// config files but are otherwise byte-identical (same plugins, mise gating, bind
/// canonicalization, and warning assembly), so a single-source view stays a faithful slice of
/// the same resolution rather than a parallel code path.
pub(crate) fn load_scoped(cwd: &Path, source: Source) -> Resolved {
    let mut warnings = Vec::new();
    // Imported app profiles live beside the global config and are trusted by location, so they
    // join the global app layer before resolution — `resolve_app`/`resolve_apps` then gate and
    // layer them exactly like an inline global app, with no special casing. They ride the global
    // layer, so a `--local` (project-only) view omits them just as it omits the global config.
    let global = if source.includes_global() {
        let mut global = read_global(&mut warnings);
        let profiles = read_profile_apps(&mut warnings);
        fold_profile_apps(&mut global, profiles, &mut warnings);
        global
    } else {
        RawConfig::default()
    };
    let project = if source.includes_project() {
        read_project(cwd, &mut warnings)
    } else {
        None
    };

    // Discover installed resolver plugins (trusted by location, under the data dir). With no
    // usable data directory there are simply no plugins; a malformed one warns and is dropped.
    let plugins = match crate::store::Layout::from_env() {
        Some(layout) => PluginRegistry::load(&layout.plugins_dir(), &mut warnings),
        None => PluginRegistry::default(),
    };

    // Capture the mise file, its verdict, and its validated bytes before `resolve`
    // consumes the project layer. A mise file is anchored on the `.ops.toml`: with no
    // usable project config there is nothing to gate it, so it is only flagged, not
    // honored. The bytes travel into `MiseConfig` so the launcher maps exactly the
    // content the verdict covered, without a second read.
    let project_state = project.as_ref().map(|(_, state, _)| *state);
    let mise_files = project
        .as_ref()
        .map(|(_, _, files)| files.clone())
        .unwrap_or_default();
    let mise = mise_status(cwd, project_state, mise_files, &mut warnings);

    let mut resolved = resolve(
        global,
        project.map(|(raw, state, _)| (raw, state)),
        &plugins,
    );
    resolved.mise = mise;

    // Canonicalize the (already absolute) bind sources, dropping any that cannot be
    // resolved — so `ro_binds` is the *effective* list, identical to what the
    // launch will bind, and `ops config` cannot advertise a bind the launch would
    // silently skip. Following symlinks here also pins each source against a swap.
    // The per-layer provenance is re-keyed from the raw declared path to the canonical
    // one as we go, so a lookup against the displayed (canonical) path resolves.
    let declared = std::mem::take(&mut resolved.ro_binds);
    let raw_layer = std::mem::take(&mut resolved.bind_layer);
    let mut canon_binds = Vec::with_capacity(declared.len());
    let mut canon_layer = BTreeMap::new();
    for p in declared {
        if let Some(canon) = canonicalize_one(&p, &mut resolved.warnings) {
            if let Some(layer) = raw_layer.get(&p) {
                canon_layer.insert(canon.clone(), *layer);
            }
            canon_binds.push(canon);
        }
    }
    resolved.ro_binds = canon_binds;
    resolved.bind_layer = canon_layer;

    // Each app's binds are canonicalized the same way, into that app's own warnings — so an
    // app overlay also advertises only the binds the launch would actually make.
    for app in resolved.apps.values_mut() {
        let declared = std::mem::take(&mut app.ro_binds);
        app.ro_binds = canonicalize_binds(declared, &mut app.warnings);
    }

    // I/O-level notes (unsafe/unparseable files) come first, then the gating notes.
    warnings.extend(std::mem::take(&mut resolved.warnings));
    resolved.warnings = warnings;
    resolved
}

/// Canonicalize one bind source, dropping it with a warning if it cannot be resolved (a
/// missing path or a broken symlink) — bwrap could not bind it anyway. Following symlinks
/// here also pins the source against a later swap.
fn canonicalize_one(p: &Path, warnings: &mut Vec<String>) -> Option<PathBuf> {
    match p.canonicalize() {
        Ok(canon) => Some(canon),
        Err(e) => {
            warnings.push(format!("ignoring bind {}: {e}", p.display()));
            None
        }
    }
}

/// Canonicalize each bind source, dropping with a warning any that cannot be resolved.
fn canonicalize_binds(binds: Vec<PathBuf>, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    binds
        .into_iter()
        .filter_map(|p| canonicalize_one(&p, warnings))
        .collect()
}

/// Read the global config (trusted by location, so no trust marker), defaulting to
/// empty when it is absent, unsafe, or unparseable.
fn read_global(warnings: &mut Vec<String>) -> RawConfig {
    let Some(path) = global_path() else {
        return RawConfig::default();
    };
    read_layer(&path, warnings).unwrap_or_default()
}

/// Read the project config and decide its trust on the *same bytes* it parses, so
/// the verdict and the applied content cannot belong to two different files. An
/// absent file is simply no project layer; an unsafe or unparseable one is dropped
/// with a warning. A config that cannot be trust-checked (no store) is treated as
/// untrusted — fail closed.
///
/// Returns the parsed config, its trust verdict, and the validated `(filename,
/// bytes)` of every sibling mise file — read here, once, through the safety gate.
/// Threading those bytes out (rather than re-reading them later) means the launcher
/// maps exactly the content the verdict covers, and the safety gate runs once.
fn read_project(
    cwd: &Path,
    warnings: &mut Vec<String>,
) -> Option<(RawConfig, TrustState, trust::MiseInputs)> {
    let path = cwd.join(PROJECT_CONFIG);
    let bytes = match safety::read_safe_bytes(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => {
            warnings.push(format!("ignoring {}: {e}", path.display()));
            return None;
        }
    };

    // Fold a sibling mise file into the verdict — trust covers both declarative
    // inputs. A present-but-unsafe mise file is unverifiable, so it forces the
    // project untrusted: its `.ops.toml` still parses (its free `env` applies under
    // untrusted rules), but its security fields drop. Verdict over the exact bytes
    // that will be parsed (closes the trust→parse window): hash these bytes —
    // framed with the mise bytes — and compare to the marker, never re-reading.
    let (state, mise_inputs) = match trust::mise_inputs_for(&path) {
        Err(e) => {
            warnings.push(format!("treating {} as untrusted: {e}", path.display()));
            (TrustState::Untrusted, Vec::new())
        }
        Ok(mise_inputs) => {
            let state = match trust::default_store_dir() {
                Some(store) => trust::verdict_for_hash(
                    &store,
                    &path,
                    &trust::content_hash(&bytes, &mise_inputs),
                ),
                None => {
                    warnings.push(format!(
                        "cannot locate the trust store; treating {} as untrusted",
                        path.display()
                    ));
                    TrustState::Untrusted
                }
            };
            (state, mise_inputs)
        }
    };

    match schema::parse(&bytes) {
        Ok(cfg) => Some((cfg, state, mise_inputs)),
        Err(e) => {
            warnings.push(format!("ignoring {}: {e}", path.display()));
            None
        }
    }
}

/// The project's mise file, the verdict gating it, and its validated bytes, for
/// `ops config` and the launcher's `[env]` mapping. `None` when the project declares
/// none. A mise file present without a usable `.ops.toml` to anchor it is not honored
/// — when there is no `.ops.toml` at all, the no-op is surfaced as a warning so it is
/// never silent; an unsafe or unparseable `.ops.toml` already warned on its own
/// account. `validated` carries the safety-gated `(filename, bytes)` read in
/// [`read_project`] (empty when none was safely readable).
fn mise_status(
    cwd: &Path,
    project_state: Option<TrustState>,
    validated: trust::MiseInputs,
    warnings: &mut Vec<String>,
) -> Option<MiseConfig> {
    let files = trust::mise_files_for(&cwd.join(PROJECT_CONFIG));
    if files.is_empty() {
        return None;
    }
    // List every discovered file — all of them are folded into trust and would be
    // read together, so showing only the first would understate the gated surface.
    let name = files
        .iter()
        .filter_map(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    match project_state {
        Some(state) => Some(MiseConfig {
            name,
            state,
            files: validated,
        }),
        None => {
            if !cwd.join(PROJECT_CONFIG).exists() {
                warnings.push(format!(
                    "mise file ({name}) ignored: mise is anchored on `{PROJECT_CONFIG}`, \
                     which is missing — add one (it may be empty) to enable it"
                ));
            }
            None
        }
    }
}

/// Read, safety-gate, and parse a config file with no trust marker (the global
/// layer). `None` when the file is absent, unsafe, or unparseable — each of the
/// latter two leaving a warning.
fn read_layer(path: &Path, warnings: &mut Vec<String>) -> Option<RawConfig> {
    match safety::read_safe_bytes(path) {
        Ok(bytes) => match schema::parse(&bytes) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                warnings.push(format!("ignoring {}: {e}", path.display()));
                None
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            warnings.push(format!("ignoring {}: {e}", path.display()));
            None
        }
    }
}

/// The global config path: `$XDG_CONFIG_HOME/ops/ops.toml` when that is absolute,
/// else `$HOME/.config/ops/ops.toml`. `None` when neither yields an absolute base
/// (the same fail-closed stance the trust store takes — never resolve against the
/// current directory).
fn global_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("ops").join(GLOBAL_CONFIG));
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute()
        .then(|| home.join(".config/ops").join(GLOBAL_CONFIG))
}

/// The imported-profiles directory (`…/ops/apps/`), a sibling of the global config. `None` when
/// no config base resolves, like [`global_path`]; `ops app import`/`rm`/`list` and [`load`] all
/// route through this one place so the location can never drift.
pub(crate) fn profiles_dir() -> Option<PathBuf> {
    global_path().and_then(|p| p.parent().map(|d| d.join(PROFILES_DIR)))
}

/// The posture an importable app profile would grant, in human-readable lines — shown so the
/// deliberate `ops app import` is informed (it is the consent act; an imported profile is then
/// honored even on an untrusted project, so what it grants must be visible).
#[derive(Debug)]
pub(crate) struct ProfilePreview {
    /// Display lines: the command, home scope, tools, binds, network, and each credential by
    /// destination + source *locator* (never a plaintext value — a profile carries only a locator).
    pub(crate) summary: Vec<String>,
}

/// Validate bytes as an importable app profile: they must parse as a top-level [`schema::RawApp`]
/// and declare a `cmd`. The `cmd` requirement is both a real rule (a profile with no command is
/// not launchable) and the guard against the wrong shape — a file wrapped in `[app.<name>]` parses
/// as an empty app, which this refuses with a hint rather than importing a silently-empty profile.
/// Returns the granted posture for display, or a human-readable reason to refuse. Reads nothing
/// from disk and resolves no secret — only the *shape* and *locators* are inspected.
pub(crate) fn validate_profile(bytes: &[u8]) -> Result<ProfilePreview, String> {
    let app = schema::parse_app(bytes)?;
    if app.cmd.is_none() {
        return Err(
            "a profile must declare a `cmd` (the command to run). A profile file holds the \
                    app's fields at the top level — if you wrapped it in an `[app.<name>]` table, \
                    remove the wrapper (the name comes from the file name)"
                .to_string(),
        );
    }
    Ok(ProfilePreview {
        summary: describe_app_posture(&app),
    })
}

/// Build the posture summary for a raw app profile: the command, the persistent-home scope, the
/// extra tools, the read-only binds, the network posture, and each injected credential by
/// destination and source *locator*. A profile never carries a plaintext secret — only a locator
/// (`env://VAR`, a `key`) — so this is safe to display and to share.
fn describe_app_posture(app: &RawApp) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(cmd) = &app.cmd {
        lines.push(format!("command: {}", cmd.clone().into_argv().join(" ")));
    }
    lines.push(format!(
        "home: {}",
        app.home_scope.as_deref().unwrap_or("global")
    ));
    if !app.packages.is_empty() {
        let names: Vec<&str> = app.packages.keys().map(String::as_str).collect();
        lines.push(format!("packages: {}", names.join(", ")));
    }
    if !app.binds.is_empty() {
        lines.push(format!("binds (read-only): {}", app.binds.join(", ")));
    }
    match &app.network {
        None => {}
        Some(NetworkField::Posture(p)) => lines.push(format!("network: {p}")),
        Some(NetworkField::Table(t)) => {
            let mut s = format!("network: {}", t.mode);
            if !t.allow.is_empty() {
                s.push_str(&format!(" — allow {}", t.allow.join(", ")));
            }
            if !t.deny.is_empty() {
                s.push_str(&format!(" — deny {}", t.deny.join(", ")));
            }
            lines.push(s);
        }
    }
    if let Some(gui) = &app.gui {
        lines.push(format!("gui: {gui}"));
    }
    if let Some(section) = &app.secret {
        let mut any = false;
        for (host, entry) in &section.hosts {
            let secrets: &[RawHostSecret] = match entry {
                RawHostSecrets::One(s) => std::slice::from_ref(s),
                RawHostSecrets::Many(v) => v.as_slice(),
            };
            for s in secrets {
                lines.push(format!("secret: {host} <- {}", describe_secret_source(s)));
                any = true;
            }
        }
        // A credential is injected only under a filtering posture (`deny`/`allow` — the proxy
        // performs the injection). If the profile declares secrets but not its own filtering
        // posture, say so — otherwise the summary reads as if they would be injected when,
        // standalone, they would not. Any of the filtering spellings counts (table or bare string).
        let filtered = match &app.network {
            Some(NetworkField::Table(t)) => {
                matches!(t.mode.as_str(), "allowlist" | "deny" | "allow" | "ask")
            }
            Some(NetworkField::Posture(p)) => matches!(p.as_str(), "deny" | "allow" | "ask"),
            None => false,
        };
        if any && !filtered {
            lines.push(
                "note: secrets are injected only under a filtering network posture (declare \
                 `[network] mode = \"deny\"`, `\"allow\"`, or `\"ask\"`)"
                    .to_string(),
            );
        }
    }
    lines
}

/// A one-line description of where a credential is read from: the terse `key`, or the explicit
/// `from` ref/chain. The locator only — never a value (a profile carries none).
fn describe_secret_source(s: &RawHostSecret) -> String {
    if let Some(key) = &s.key {
        return format!("key `{key}`");
    }
    match &s.from {
        Some(SecretFrom::One(r)) => format!("from {r}"),
        Some(SecretFrom::Many(rs)) => format!("from {}", rs.join(" | ")),
        None => "from (unspecified)".to_string(),
    }
}

/// Read every imported app profile from the profiles directory, keyed by filename stem.
/// Delegates to [`read_profile_apps_from`] with the resolved [`profiles_dir`]; the split keeps the
/// directory-reading logic unit-testable against an arbitrary directory, without depending on the
/// process environment.
fn read_profile_apps(warnings: &mut Vec<String>) -> BTreeMap<String, RawApp> {
    match profiles_dir() {
        Some(dir) => read_profile_apps_from(&dir, warnings),
        None => BTreeMap::new(),
    }
}

/// Read every `<name>.toml` profile under `dir`, keyed by its filename stem (the app name). Each
/// file is a standalone top-level [`schema::RawApp`], trusted by location. Infallible, like the
/// rest of [`load`]: an absent directory yields nothing; an unsafe, unparseable, or unsafely-named
/// file is dropped with a warning, never aborting the load. Entries are processed in sorted order
/// so warnings are deterministic.
fn read_profile_apps_from(dir: &Path, warnings: &mut Vec<String>) -> BTreeMap<String, RawApp> {
    let mut out = BTreeMap::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return out,
        Err(e) => {
            warnings.push(format!(
                "ignoring profiles directory {}: {e}",
                dir.display()
            ));
            return out;
        }
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        // Only `*.toml` files are profiles; anything else under the directory is ignored silently.
        if path.extension().and_then(|x| x.to_str()) != Some("toml") {
            continue;
        }
        let Some(name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            warnings.push(format!(
                "ignoring profile {}: its file name is not valid UTF-8",
                path.display()
            ));
            continue;
        };
        if is_reserved_app_verb(&name) || !is_valid_app_name(&name) {
            warnings.push(format!(
                "ignoring profile {}: `{name}` is not a usable app name",
                path.display()
            ));
            continue;
        }
        let bytes = match safety::read_safe_bytes(&path) {
            Ok(b) => b,
            Err(e) => {
                warnings.push(format!("ignoring profile {}: {e}", path.display()));
                continue;
            }
        };
        match schema::parse_app(&bytes) {
            Ok(app) => {
                out.insert(name, app);
            }
            Err(e) => warnings.push(format!("ignoring profile {}: {e}", path.display())),
        }
    }
    out
}

/// Fold imported profile apps into the global config's app map. They are trusted by location, so
/// they belong to the global layer. On a name collision an inline `[app.<name>]` in `ops.toml`
/// wins — the more explicit, hand-authored statement — and the profile is skipped with a loud
/// warning, never a silent merge of two definitions.
fn fold_profile_apps(
    global: &mut RawConfig,
    profiles: BTreeMap<String, RawApp>,
    warnings: &mut Vec<String>,
) {
    use std::collections::btree_map::Entry;
    for (name, app) in profiles {
        match global.app.entry(name) {
            Entry::Occupied(occupied) => {
                let name = occupied.key();
                warnings.push(format!(
                    "app `{name}`: an inline [app.{name}] in {GLOBAL_CONFIG} shadows the imported \
                     profile of the same name (remove one)"
                ));
            }
            Entry::Vacant(vacant) => {
                vacant.insert(app);
            }
        }
    }
}

/// Produce the portable profile bytes for `name`, for `ops app export`. An **imported profile**
/// (`<config>/ops/apps/<name>.toml`) is emitted **verbatim**, so the author's comments and
/// formatting survive a round-trip through the store; otherwise an app declared **inline** — in the
/// project `.ops.toml` (preferred, the local definition one would share) or the global `ops.toml` —
/// has its `RawApp` **serialized** to a minimal top-level profile. The app is exported **as
/// authored**, security fields and all, regardless of trust: import is the trust act, not export.
/// Returns the bytes to emit, or a human-readable reason none was found.
///
/// Note the precedence here is the **inverse** of [`fold_profile_apps`] at load: export prefers the
/// imported profile, whereas a launch prefers an inline `[app.<name>]`. They only diverge when one
/// name is *both* an imported profile and inline — a state the load-time collision warning already
/// pushes the user to resolve — so `ops app export <name>` may emit the profile while `ops app
/// <name>` would launch the inline definition. Keep at most one definition per name.
pub(crate) fn export_profile(cwd: &Path, name: &str) -> Result<Vec<u8>, String> {
    // 1. An imported profile: emit it verbatim (fidelity over re-serialization).
    if let Some(dir) = profiles_dir() {
        let path = dir.join(format!("{name}.toml"));
        if path.exists() {
            return safety::read_safe_bytes(&path).map_err(|e| e.to_string());
        }
    }
    // 2. An inline app: serialize its raw definition. The project layer is preferred over the
    //    global (the local definition is the one being packaged for sharing).
    let mut warnings = Vec::new();
    if let Some((mut project, _, _)) = read_project(cwd, &mut warnings) {
        if let Some(app) = project.app.remove(name) {
            return schema::serialize_app(&app).map(String::into_bytes);
        }
    }
    let mut global = read_global(&mut warnings);
    if let Some(app) = global.app.remove(name) {
        return schema::serialize_app(&app).map(String::into_bytes);
    }
    Err(format!(
        "no app `{name}` to export (not an imported profile, nor an inline [app.{name}] in \
         {PROJECT_CONFIG} or {GLOBAL_CONFIG})"
    ))
}

#[cfg(test)]
mod tests {
    use super::schema::{RawEnvDefaults, RawFileDefaults, RawSecretSection, RawSopsDefaults};
    use super::*;
    use crate::testutil::TmpDir;
    use std::collections::BTreeMap;

    fn raw(env: &[(&str, &str)], binds: &[&str]) -> RawConfig {
        RawConfig {
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            binds: binds.iter().map(|s| s.to_string()).collect(),
            packages: BTreeMap::new(),
            nixpkgs: None,
            network: None,
            gui: None,
            secret: None,
            app: BTreeMap::new(),
            limits: None,
        }
    }

    /// A `RawConfig` declaring only `packages` (as `name -> attr`).
    fn raw_packages(packages: &[(&str, &str)]) -> RawConfig {
        RawConfig {
            packages: packages
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            ..RawConfig::default()
        }
    }

    /// A `RawConfig` declaring only a `nixpkgs` override.
    fn raw_nixpkgs(source: &str) -> RawConfig {
        RawConfig {
            nixpkgs: Some(source.to_string()),
            ..RawConfig::default()
        }
    }

    /// A `RawConfig` declaring only a `network` posture (string form).
    fn raw_network(value: &str) -> RawConfig {
        RawConfig {
            network: Some(NetworkField::Posture(value.to_string())),
            ..RawConfig::default()
        }
    }

    /// A `RawConfig` declaring a `network` allowlist (table form) with allow and deny lists.
    fn raw_network_table(allow: &[&str], deny: &[&str]) -> RawConfig {
        RawConfig {
            network: Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".to_string(),
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: deny.iter().map(|s| s.to_string()).collect(),
                ask_timeout: None,
                ask_notice: None,
                stats: None,
            })),
            ..RawConfig::default()
        }
    }

    /// A `RawConfig` declaring only an allow list (no deny).
    fn raw_network_allow(allow: &[&str]) -> RawConfig {
        raw_network_table(allow, &[])
    }

    /// A `RawConfig` declaring only a `gui` posture.
    fn raw_gui(value: &str) -> RawConfig {
        RawConfig {
            gui: Some(value.to_string()),
            ..RawConfig::default()
        }
    }

    /// A `RawConfig` declaring a `[limits]` table from optional string tokens (each `None` leaves
    /// that field unset, falling back to the default).
    fn raw_limits(
        memory_high: Option<&str>,
        memory_max: Option<&str>,
        tasks_max: Option<&str>,
    ) -> RawConfig {
        let text = |o: Option<&str>| o.map(|s| schema::RawLimit::Text(s.to_string()));
        RawConfig {
            limits: Some(schema::RawLimits {
                memory_high: text(memory_high),
                memory_max: text(memory_max),
                tasks_max: text(tasks_max),
            }),
            ..RawConfig::default()
        }
    }

    /// A `RawApp` from its parts, for the app-layering tests.
    fn raw_app(
        cmd: &[&str],
        env: &[(&str, &str)],
        binds: &[&str],
        packages: &[(&str, &str)],
        network: Option<NetworkField>,
    ) -> RawApp {
        RawApp {
            cmd: if cmd.is_empty() {
                None
            } else {
                Some(schema::RawCmd::Argv(
                    cmd.iter().map(|s| s.to_string()).collect(),
                ))
            },
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            binds: binds.iter().map(|s| s.to_string()).collect(),
            packages: packages
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            network,
            gui: None,
            secret: None,
            limits: None,
            home_scope: None,
        }
    }

    /// A `RawConfig` declaring a single `[app.<name>]`.
    fn raw_with_app(name: &str, app: RawApp) -> RawConfig {
        RawConfig {
            app: std::iter::once((name.to_string(), app)).collect(),
            ..RawConfig::default()
        }
    }

    /// A `HeaderSecret` with an explicit `env://` source, for the overlay-merge tests (no
    /// dependence on the default resolver order).
    fn a_header_secret() -> HeaderSecret {
        let raw = RawHostSecret {
            kind: None,
            key: None,
            from: Some(SecretFrom::One("env://TOKEN".into())),
            header: Some("Authorization".into()),
            value_type: Some("bearer".into()),
            prefix: None,
        };
        validate(raw).unwrap()
    }

    #[test]
    fn an_app_layers_global_under_project_overriding_the_command_and_unioning_fields() {
        let global = raw_with_app(
            "demo-app",
            raw_app(
                &["demo-app"],
                &[("BASE", "g")],
                &[],
                &[("tool", "nix:ripgrep")],
                None,
            ),
        );
        let project = raw_with_app(
            "demo-app",
            raw_app(&["demo-app", "--resume"], &[("EXTRA", "p")], &[], &[], None),
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        let app = &r.apps["demo-app"];
        // The project's command wins; the global one is replaced, not appended.
        assert_eq!(
            app.cmd,
            vec!["demo-app".to_string(), "--resume".to_string()]
        );
        // Free env is unioned across both layers.
        assert!(app.env.iter().any(|(k, v)| k == "BASE" && v == "g"));
        assert!(app.env.iter().any(|(k, v)| k == "EXTRA" && v == "p"));
        // The global package is carried, trusted by location.
        assert!(app
            .packages
            .iter()
            .any(|p| p.name == "tool" && p.state == TrustState::Trusted));
    }

    #[test]
    fn an_untrusted_project_apps_security_fields_drop_but_env_packages_and_command_survive() {
        let project = raw_with_app(
            "probe",
            raw_app(
                &["id"],
                &[("OK", "v")],
                &["/etc/secret"],
                &[("pkg", "nix:ripgrep")],
                allowlist_net(&["x.com"]),
            ),
        );
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
        let app = &r.apps["probe"];
        // Security fields drop under an untrusted project.
        assert!(app.ro_binds.is_empty(), "binds must drop");
        assert!(app.network.is_none(), "network must drop");
        // Free fields and the command survive; the package is carried, stamped untrusted, for
        // the launcher to weigh.
        assert_eq!(app.cmd, vec!["id".to_string()]);
        assert!(app.env.iter().any(|(k, _)| k == "OK"));
        assert!(app
            .packages
            .iter()
            .any(|p| p.name == "pkg" && p.state == TrustState::Untrusted));
        // The drops are explained.
        assert!(app.warnings.iter().any(|w| w.contains("bind")));
        assert!(app.warnings.iter().any(|w| w.contains("network")));
    }

    #[test]
    fn an_untrusted_project_cannot_override_a_trusted_apps_command() {
        // The integrity-of-intent guard: `ops app claude` against an untrusted repo must run
        // the trusted app's command, never one the repo substituted.
        let global = raw_with_app("claude", raw_app(&["claude"], &[], &[], &[], None));
        let project = raw_with_app("claude", raw_app(&["evil"], &[], &[], &[], None));
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["claude"];
        assert_eq!(app.cmd, vec!["claude".to_string()]);
        assert!(app.warnings.iter().any(|w| w.contains("cmd")));

        // A trusted project, by contrast, may override the command.
        let global = raw_with_app("claude", raw_app(&["claude"], &[], &[], &[], None));
        let project = raw_with_app(
            "claude",
            raw_app(&["claude", "--resume"], &[], &[], &[], None),
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        assert_eq!(
            r.apps["claude"].cmd,
            vec!["claude".to_string(), "--resume".to_string()]
        );
    }

    #[test]
    fn an_untrusted_project_cannot_override_a_trusted_apps_package() {
        // The package half of the integrity-of-intent guard (mirror of `cmd`): `ops app claude`
        // against an untrusted repo must keep the trusted app's tool, never one the repo
        // substituted — else the repo could deny the app its tool, or aim it at an attacker's.
        let global = raw_with_app(
            "claude",
            raw_app(
                &["claude"],
                &[],
                &[],
                &[("claude-code", "mise:aqua:anthropics/claude-code")],
                None,
            ),
        );
        let project = raw_with_app(
            "claude",
            raw_app(
                &["claude"],
                &[],
                &[],
                &[("claude-code", "mise:aqua:attacker/x")],
                None,
            ),
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["claude"];
        let p = app
            .packages
            .iter()
            .find(|p| p.name == "claude-code")
            .expect("the app's package survives");
        // The trusted token survives, still trusted; the attacker's is refused with a warning.
        assert_eq!(
            p.backend,
            Backend::Mise("aqua:anthropics/claude-code".into())
        );
        assert_eq!(p.state, TrustState::Trusted);
        assert!(app
            .warnings
            .iter()
            .any(|w| w.contains("claude-code") && w.contains("override")));
        // Security teeth: the attacker's token is not merely lower-priority — it is absent, so it
        // can never reach `mise use -g`. Exactly one `claude-code`, and it is the trusted one.
        assert_eq!(
            app.packages
                .iter()
                .filter(|p| p.name == "claude-code")
                .count(),
            1
        );
        assert!(
            !app.packages
                .iter()
                .any(|p| p.backend == Backend::Mise("aqua:attacker/x".into())),
            "the attacker token must be absent, never carried"
        );

        // A trusted project, by contrast, may override the package by name.
        let global = raw_with_app(
            "claude",
            raw_app(
                &["claude"],
                &[],
                &[],
                &[("claude-code", "mise:aqua:anthropics/claude-code")],
                None,
            ),
        );
        let project = raw_with_app(
            "claude",
            raw_app(
                &["claude"],
                &[],
                &[],
                &[("claude-code", "nix:claude-code")],
                None,
            ),
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        let p = r.apps["claude"]
            .packages
            .iter()
            .find(|p| p.name == "claude-code")
            .unwrap();
        assert_eq!(p.backend, Backend::Nix("claude-code".into()));
    }

    #[test]
    fn network_modes_set_the_egress_default_action() {
        use crate::allowlist::DefaultAction;
        let mut w = Vec::new();
        let tbl = |mode: &str, allow: &[&str], deny: &[&str]| {
            NetworkField::Table(NetworkTable {
                mode: mode.into(),
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: deny.iter().map(|s| s.to_string()).collect(),
                ask_timeout: None,
                ask_notice: None,
                stats: None,
            })
        };

        // Bare-string `deny`/`allow` map to a filtered policy with the matching default action and
        // no carve-out lists.
        let deny =
            validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("deny".into())).unwrap();
        let allow =
            validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("allow".into())).unwrap();
        assert!(matches!(
            &deny,
            NetworkPolicy::Allowlist(p)
                if p.default_action() == DefaultAction::Deny && p.allow_rules().is_empty()
        ));
        assert!(matches!(
            &allow,
            NetworkPolicy::Allowlist(p) if p.default_action() == DefaultAction::Allow
        ));

        // Table form: `allow` mode carries the deny carve-outs and allow-by-default.
        let allow_tbl =
            validate_network(&mut w, GLOBAL_CONFIG, tbl("allow", &[], &["evil.com"])).unwrap();
        assert!(matches!(
            &allow_tbl,
            NetworkPolicy::Allowlist(p)
                if p.default_action() == DefaultAction::Allow && p.deny_rules().len() == 1
        ));

        // `allowlist` is the permanently-kept backward-compatible alias of `deny`.
        let alias = validate_network(
            &mut w,
            GLOBAL_CONFIG,
            tbl("allowlist", &["github.com"], &[]),
        )
        .unwrap();
        let canon =
            validate_network(&mut w, GLOBAL_CONFIG, tbl("deny", &["github.com"], &[])).unwrap();
        assert_eq!(
            alias, canon,
            "`allowlist` must resolve identically to `deny`"
        );

        assert!(w.is_empty(), "every valid mode warns nothing: {w:?}");

        // An unknown mode warns and yields nothing (fail-closed: the prior posture is kept).
        assert!(
            validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("yolo".into())).is_none()
        );
        assert!(
            w.len() == 1 && w[0].contains("yolo"),
            "unknown mode must warn: {w:?}"
        );
    }

    #[test]
    fn ask_mode_parses_and_carries_an_optional_timeout() {
        use crate::allowlist::DefaultAction;
        let ask_table = |timeout: Option<&str>| {
            NetworkField::Table(NetworkTable {
                mode: "ask".into(),
                allow: vec![],
                deny: vec![],
                ask_timeout: timeout.map(|s| s.to_string()),
                ask_notice: None,
                stats: None,
            })
        };
        let mut w = Vec::new();

        // Bare-string `ask` → ask-by-default with no timeout (an indefinite wait).
        let bare =
            validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("ask".into())).unwrap();
        assert!(matches!(&bare, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && p.ask_timeout().is_none()));

        // Table `ask` with a timeout → ask-by-default carrying the parsed duration.
        let timed = validate_network(&mut w, GLOBAL_CONFIG, ask_table(Some("90s"))).unwrap();
        assert!(matches!(&timed, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask
            && p.ask_timeout() == Some(std::time::Duration::from_secs(90))));
        assert!(w.is_empty(), "a valid ask config warns nothing: {w:?}");

        // A malformed timeout falls back to indefinite, warned — never a hard config failure.
        let fallback = validate_network(&mut w, GLOBAL_CONFIG, ask_table(Some("soon"))).unwrap();
        assert!(matches!(&fallback, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && p.ask_timeout().is_none()));
        assert!(
            w.iter().any(|m| m.contains("ask_timeout")),
            "a bad timeout must warn: {w:?}"
        );
        w.clear();

        // An `ask_timeout` under a non-ask mode is moot — warned and ignored.
        let moot = NetworkField::Table(NetworkTable {
            mode: "deny".into(),
            allow: vec![],
            deny: vec![],
            ask_timeout: Some("90s".into()),
            ask_notice: None,
            stats: None,
        });
        let _ = validate_network(&mut w, GLOBAL_CONFIG, moot).unwrap();
        assert!(
            w.iter().any(|m| m.contains("ask_timeout")),
            "a moot timeout must warn: {w:?}"
        );
    }

    #[test]
    fn ask_notice_defaults_on_and_can_be_silenced() {
        use crate::allowlist::DefaultAction;
        let ask = |notice: Option<bool>| {
            NetworkField::Table(NetworkTable {
                mode: "ask".into(),
                allow: vec![],
                deny: vec![],
                ask_timeout: None,
                ask_notice: notice,
                stats: None,
            })
        };
        let mut w = Vec::new();

        // Absent `ask_notice` → the park notice is shown (the default).
        let def = validate_network(&mut w, GLOBAL_CONFIG, ask(None)).unwrap();
        assert!(matches!(&def, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && p.ask_notice()));

        // `ask_notice = false` silences it.
        let off = validate_network(&mut w, GLOBAL_CONFIG, ask(Some(false))).unwrap();
        assert!(matches!(&off, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && !p.ask_notice()));

        // `ask_notice = true` is the explicit default — still shown, no warning.
        let on = validate_network(&mut w, GLOBAL_CONFIG, ask(Some(true))).unwrap();
        assert!(matches!(&on, NetworkPolicy::Allowlist(p) if p.ask_notice()));
        assert!(w.is_empty(), "valid ask_notice configs warn nothing: {w:?}");

        // An `ask_notice` under a non-ask mode is moot — warned and ignored.
        let moot = NetworkField::Table(NetworkTable {
            mode: "deny".into(),
            allow: vec![],
            deny: vec![],
            ask_timeout: None,
            ask_notice: Some(false),
            stats: None,
        });
        let _ = validate_network(&mut w, GLOBAL_CONFIG, moot).unwrap();
        assert!(
            w.iter().any(|m| m.contains("ask_notice")),
            "a moot ask_notice must warn: {w:?}"
        );
    }

    #[test]
    fn parse_ask_timeout_handles_units_and_rejects_garbage() {
        use std::time::Duration;
        assert_eq!(parse_ask_timeout("90s"), Ok(Some(Duration::from_secs(90))));
        assert_eq!(parse_ask_timeout("90"), Ok(Some(Duration::from_secs(90))));
        assert_eq!(parse_ask_timeout("5m"), Ok(Some(Duration::from_secs(300))));
        assert_eq!(parse_ask_timeout("2h"), Ok(Some(Duration::from_secs(7200))));
        // A zero of any unit means indefinite — the same as omitting the field.
        assert_eq!(parse_ask_timeout("0"), Ok(None));
        assert_eq!(parse_ask_timeout("0m"), Ok(None));
        // Malformed values are refused (the caller then warns and falls back to indefinite).
        assert!(parse_ask_timeout("soon").is_err());
        assert!(parse_ask_timeout("9x").is_err());
        assert!(parse_ask_timeout("").is_err());
    }

    #[test]
    fn a_global_apps_network_survives_an_untrusted_projects_override_attempt() {
        // A globally-declared app keeps its posture even when launched under an untrusted
        // project — the flagship use case: run an agent *on* untrusted code, safely.
        let global = raw_with_app(
            "demo-app",
            raw_app(
                &["demo-app"],
                &[],
                &[],
                &[],
                allowlist_net(&["api.example.com"]),
            ),
        );
        let mut widen = raw_app(&[], &[], &[], &[], None);
        widen.network = Some(NetworkField::Posture("shared".into()));
        let project = raw_with_app("demo-app", widen);
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["demo-app"];
        assert!(matches!(app.network, Some(NetworkPolicy::Allowlist(_))));
        assert!(app.warnings.iter().any(|w| w.contains("network")));
    }

    #[test]
    fn a_global_apps_gui_survives_an_untrusted_projects_override_attempt() {
        // The flagship property for the GUI hole: a globally-declared app keeps its display
        // posture even under an untrusted project, which can neither close it nor (in the reverse
        // case) open one — running an agent *on* untrusted code never lets that code touch the
        // compositor exposure.
        let global = raw_with_app(
            "desktop",
            RawApp {
                gui: Some("wayland".into()),
                ..raw_app(&["agent"], &[], &[], &[], None)
            },
        );
        // The untrusted project tries to flip the app to no display.
        let project = raw_with_app(
            "desktop",
            RawApp {
                gui: Some("none".into()),
                ..raw_app(&[], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["desktop"];
        assert_eq!(
            app.gui,
            Some(GuiPolicy::Wayland),
            "an untrusted project may not change a trusted app's GUI posture"
        );
        assert!(app.warnings.iter().any(|w| w.contains("gui")));

        // The reverse: an untrusted project cannot *open* a display on its own app either.
        let project = raw_with_app(
            "mine",
            RawApp {
                gui: Some("wayland".into()),
                ..raw_app(&["tool"], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
        let app = &r.apps["mine"];
        assert_eq!(app.gui, None, "an untrusted project may not open a display");
        assert!(app.warnings.iter().any(|w| w.contains("gui")));
    }

    /// Build a `RawLimits` from optional tokens, for the per-app overlay tests.
    fn app_raw_limits(
        memory_high: Option<&str>,
        memory_max: Option<&str>,
        tasks_max: Option<&str>,
    ) -> schema::RawLimits {
        let text = |o: Option<&str>| o.map(|s| schema::RawLimit::Text(s.to_string()));
        schema::RawLimits {
            memory_high: text(memory_high),
            memory_max: text(memory_max),
            tasks_max: text(tasks_max),
        }
    }

    #[test]
    fn a_trusted_project_app_overrides_limits_per_field() {
        // An app's `[limits]` overlay layers like its `network`/`gui`: a trusted project tunes a
        // field its global definition set, the others standing. The global app caps tasks and
        // memory; the trusted project lowers only the ceiling.
        let global = raw_with_app(
            "agent",
            RawApp {
                limits: Some(app_raw_limits(None, Some("16G"), Some("8192"))),
                ..raw_app(&["agent"], &[], &[], &[], None)
            },
        );
        let project = raw_with_app(
            "agent",
            RawApp {
                limits: Some(app_raw_limits(None, Some("8G"), None)),
                ..raw_app(&[], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        let app = &r.apps["agent"];
        assert_eq!(
            app.limits.memory_max.as_deref(),
            Some("8G"),
            "the trusted project overrides the ceiling"
        );
        assert_eq!(
            app.limits.tasks_max.as_deref(),
            Some("8192"),
            "the global task cap stands"
        );
        assert_eq!(
            app.limits.memory_high, None,
            "neither layer set the throttle"
        );
    }

    #[test]
    fn an_untrusted_projects_app_limits_are_dropped_and_a_global_apps_survive() {
        // The flagship property for the limits overlay: a globally-declared app keeps its tight
        // cap even under an untrusted project, which can neither loosen it nor set a limit on its
        // own app — running an agent *on* untrusted code never lets that code weaken the anti-DoS.
        let global = raw_with_app(
            "agent",
            RawApp {
                limits: Some(app_raw_limits(None, None, Some("4096"))),
                ..raw_app(&["agent"], &[], &[], &[], None)
            },
        );
        let project = raw_with_app(
            "agent",
            RawApp {
                limits: Some(app_raw_limits(None, None, Some("infinity"))),
                ..raw_app(&[], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["agent"];
        assert_eq!(
            app.limits.tasks_max.as_deref(),
            Some("4096"),
            "an untrusted project may not loosen a trusted app's task cap"
        );
        assert!(app.warnings.iter().any(|w| w.contains("[limits]")));

        // The reverse: an untrusted project cannot set a limit on its own app either.
        let project = raw_with_app(
            "mine",
            RawApp {
                limits: Some(app_raw_limits(None, None, Some("infinity"))),
                ..raw_app(&["tool"], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
        let app = &r.apps["mine"];
        assert_eq!(
            app.limits,
            crate::sandbox::cgroup::Limits::default(),
            "an untrusted project's own app limits are dropped"
        );
        assert!(app.warnings.iter().any(|w| w.contains("[limits]")));
    }

    #[test]
    fn an_apps_scalar_origins_record_which_app_layer_set_each_field() {
        // The data behind `config show --app`: each scalar the app overlay sets is attributed to
        // its app layer; an untouched scalar keeps the default origin, so the detail view shows it
        // inherited from the baseline.
        let global = raw_with_app(
            "demo",
            RawApp {
                limits: Some(app_raw_limits(None, None, Some("2048"))),
                ..raw_app(
                    &["demo-agent"],
                    &[],
                    &[],
                    &[],
                    Some(NetworkField::Posture("none".into())),
                )
            },
        );
        let resolved = resolve_no_plugins(global, None);
        let app = &resolved.apps["demo"];
        assert_eq!(
            app.cmd_origin,
            Provenance::Global,
            "the global app set the command"
        );
        assert_eq!(app.network_origin, Provenance::Global, "and the network");
        assert_eq!(
            app.limits_origin.tasks_max,
            Provenance::Global,
            "and the task cap"
        );
        // A scalar the app left alone keeps its default origin and sets no value of its own.
        assert_eq!(app.gui_origin, Provenance::Default);
        assert!(app.gui.is_none());
        assert_eq!(app.home_scope_origin, None);
        assert_eq!(app.limits_origin.memory_high, Provenance::Default);

        // A trusted project overriding a field is attributed to the project layer, while a field it
        // does not touch keeps the global app's attribution.
        let global = raw_with_app(
            "demo",
            raw_app(
                &["demo-agent"],
                &[],
                &[],
                &[],
                Some(NetworkField::Posture("none".into())),
            ),
        );
        let project = raw_with_app(
            "demo",
            raw_app(
                &[],
                &[],
                &[],
                &[],
                Some(NetworkField::Posture("shared".into())),
            ),
        );
        let resolved = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        let app = &resolved.apps["demo"];
        assert_eq!(
            app.network_origin,
            Provenance::Project,
            "the project overrode the network"
        );
        assert_eq!(
            app.cmd_origin,
            Provenance::Global,
            "the command stayed the global app's"
        );
    }

    #[test]
    fn an_app_home_scope_defaults_to_global_and_a_trusted_layer_may_set_project() {
        // Unset → the global default. A trusted layer (here the global config) may pin it.
        let plain = raw_with_app("demo-app", raw_app(&["demo-app"], &[], &[], &[], None));
        let r = resolve_no_plugins(plain, None);
        assert_eq!(r.apps["demo-app"].home_scope, AppHomeScope::Global);

        let scoped = raw_with_app(
            "review",
            RawApp {
                home_scope: Some("project".into()),
                ..raw_app(&["demo-app"], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(scoped, None);
        assert_eq!(r.apps["review"].home_scope, AppHomeScope::Project);
    }

    #[test]
    fn an_untrusted_project_cannot_widen_a_trusted_apps_home_scope_to_global() {
        // The integrity guard, mirroring `cmd`: a trusted app pinned to a per-project home must
        // not be flipped to the shared global home by an untrusted repo (the contamination
        // vector). The safe direction — narrowing to `project` — and an untrusted project's own
        // app are both allowed.
        let global = raw_with_app(
            "demo-app",
            RawApp {
                home_scope: Some("project".into()),
                ..raw_app(&["demo-app"], &[], &[], &[], None)
            },
        );
        let project = raw_with_app(
            "demo-app",
            RawApp {
                home_scope: Some("global".into()),
                ..raw_app(&[], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["demo-app"];
        assert_eq!(
            app.home_scope,
            AppHomeScope::Project,
            "the widening is refused"
        );
        assert!(app.warnings.iter().any(|w| w.contains("home_scope")));

        // An untrusted project's OWN app (nothing trusted to override) may set any scope.
        let project = raw_with_app(
            "mine",
            RawApp {
                home_scope: Some("global".into()),
                ..raw_app(&["tool"], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
        assert_eq!(r.apps["mine"].home_scope, AppHomeScope::Global);
    }

    #[test]
    fn global_limits_are_honored_by_location() {
        // The global config is trusted by location, so its whole `[limits]` table applies.
        let global = raw_limits(Some("70%"), Some("16G"), Some("8192"));
        let r = resolve_no_plugins(global, None);
        assert_eq!(r.limits.memory_high.as_deref(), Some("70%"));
        assert_eq!(r.limits.memory_max.as_deref(), Some("16G"));
        assert_eq!(r.limits.tasks_max.as_deref(), Some("8192"));
    }

    #[test]
    fn a_trusted_project_overrides_limits_per_field() {
        // Per-field layering (the `env` model, not wholesale): the project sets only the ceiling,
        // so it overrides `memory_max` while the global throttle and task cap stand.
        let global = raw_limits(Some("70%"), Some("16G"), Some("8192"));
        let project = raw_limits(None, Some("8G"), None);
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        assert_eq!(
            r.limits.memory_high.as_deref(),
            Some("70%"),
            "global throttle stands"
        );
        assert_eq!(
            r.limits.memory_max.as_deref(),
            Some("8G"),
            "project overrides the ceiling"
        );
        assert_eq!(
            r.limits.tasks_max.as_deref(),
            Some("8192"),
            "global task cap stands"
        );
    }

    #[test]
    fn an_untrusted_projects_limits_are_dropped_with_a_warning() {
        // Loosening the anti-DoS limits is a security choice — an untrusted project may not make
        // it. The whole `[limits]` table is dropped and the built-in defaults (all-None) stand.
        let project = raw_limits(Some("100%"), Some("infinity"), Some("infinity"));
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
        assert_eq!(r.limits, crate::sandbox::cgroup::Limits::default());
        assert!(r.warnings.iter().any(|w| w.contains("[limits]")));
    }

    #[test]
    fn a_value_set_to_its_default_still_records_its_layer_not_default() {
        // The discriminating provenance property — the whole reason the feature exists. A layer
        // that sets a value *to the built-in default* is still recorded as the origin, so
        // `ops config` distinguishes "shared because I chose it" from "shared because nothing set
        // it". `network = "shared"` and `gui = "none"` ARE the defaults, and `tasks_max = 16384` is
        // the documented default task cap — all three, set explicitly, must read as `Global`, never
        // `Default`. (If `validate_network` ever normalized "shared" to "unset", this would fail.)
        let global = RawConfig {
            network: Some(NetworkField::Posture("shared".into())),
            gui: Some("none".into()),
            limits: Some(schema::RawLimits {
                memory_high: None,
                memory_max: None,
                tasks_max: Some(schema::RawLimit::Number(16384)),
            }),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, None);
        assert_eq!(
            r.network,
            NetworkPolicy::Shared,
            "shared is honored as a posture"
        );
        assert_eq!(
            r.network_origin,
            Provenance::Global,
            "explicit shared is global-set"
        );
        assert_eq!(
            r.gui_origin,
            Provenance::Global,
            "explicit none is global-set"
        );
        assert_eq!(
            r.limits_origin.tasks_max,
            Provenance::Global,
            "an explicit default-valued task cap is still global-set"
        );
        // The contrast that gives the above its meaning: a field no layer set stays `Default`.
        assert_eq!(r.limits_origin.memory_high, Provenance::Default);

        // With nothing declared at all, every scalar origin reads `Default`.
        let bare = resolve_no_plugins(RawConfig::default(), None);
        assert_eq!(bare.network_origin, Provenance::Default);
        assert_eq!(bare.gui_origin, Provenance::Default);
        assert_eq!(bare.limits_origin.tasks_max, Provenance::Default);
    }

    #[test]
    fn a_trusted_project_records_its_layer_as_the_origin() {
        // The project path records origin too, per field: a trusted project sets the network and
        // the ceiling (attributed `Project`), while a global-set task cap stays `Global`.
        let global = raw_limits(None, None, Some("8192"));
        let project = RawConfig {
            network: Some(NetworkField::Posture("none".into())),
            limits: Some(schema::RawLimits {
                memory_high: None,
                memory_max: Some(schema::RawLimit::Text("8G".into())),
                tasks_max: None,
            }),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        assert_eq!(r.network_origin, Provenance::Project);
        assert_eq!(
            r.limits_origin.memory_max,
            Provenance::Project,
            "the project-set ceiling is attributed to the project"
        );
        assert_eq!(
            r.limits_origin.tasks_max,
            Provenance::Global,
            "the global-set task cap the project did not touch stays global"
        );
    }

    #[test]
    fn an_invalid_limits_value_is_dropped_and_the_field_keeps_its_default() {
        // A value systemd would reject (`2GB` — no `B` suffix) must never reach `systemd-run`, or
        // it would brick every launch. It is dropped (warned by field name) while the valid
        // siblings apply.
        let global = raw_limits(Some("80%"), Some("2GB"), Some("8192"));
        let r = resolve_no_plugins(global, None);
        assert_eq!(r.limits.memory_high.as_deref(), Some("80%"));
        assert_eq!(
            r.limits.memory_max, None,
            "the invalid ceiling falls back to the default"
        );
        assert_eq!(r.limits.tasks_max.as_deref(), Some("8192"));
        assert!(r.warnings.iter().any(|w| w.contains("limits.memory_max")));
    }

    #[test]
    fn a_bare_small_memory_number_is_refused_as_a_likely_percentage_typo() {
        // The `memory_max = 90` footgun: a bare integer is *bytes*, so `90` means 90 bytes — almost
        // certainly a percentage missing its `%`. It is dropped (with a "did you mean" hint) and
        // the field falls back to its default, rather than reaching systemd and bricking the launch.
        let global = RawConfig {
            limits: Some(schema::RawLimits {
                memory_max: Some(schema::RawLimit::Number(90)),
                ..Default::default()
            }),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, None);
        assert_eq!(r.limits.memory_max, None, "the bare byte count is refused");
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("did you mean") && w.contains("memory_max")));

        // A deliberate unit or percentage is honored — the guard only catches the bare small int.
        let global = raw_limits(None, Some("90%"), None);
        let r = resolve_no_plugins(global, None);
        assert_eq!(r.limits.memory_max.as_deref(), Some("90%"));
        let global = raw_limits(None, Some("16G"), None);
        let r = resolve_no_plugins(global, None);
        assert_eq!(r.limits.memory_max.as_deref(), Some("16G"));
    }

    #[test]
    fn an_unknown_home_scope_defaults_to_global_with_a_warning() {
        let global = raw_with_app(
            "demo-app",
            RawApp {
                home_scope: Some("frobnicate".into()),
                ..raw_app(&["demo-app"], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, None);
        let app = &r.apps["demo-app"];
        assert_eq!(app.home_scope, AppHomeScope::Global);
        assert!(app.warnings.iter().any(|w| w.contains("home_scope")));
    }

    #[test]
    fn an_app_with_an_unsafe_name_is_dropped_before_it_can_key_a_directory() {
        // An app name keys an on-disk home directory, so a traversal or odd-charset name must
        // never reach the launcher. It is dropped at resolve time with a baseline warning.
        for bad in ["../escape", "a/b", "..", ".", "with space", ""] {
            let global = raw_with_app(bad, raw_app(&["x"], &[], &[], &[], None));
            let r = resolve_no_plugins(global, None);
            assert!(
                !r.apps.contains_key(bad),
                "app `{bad}` must be dropped, not resolved"
            );
            assert!(
                r.warnings.iter().any(|w| w.contains("ignoring app")),
                "a dropped app `{bad}` must warn"
            );
        }
        // A conventional name survives.
        assert!(is_valid_app_name("demo-app"));
        assert!(is_valid_app_name("other-tool-2.dev_x"));
    }

    #[test]
    fn a_reserved_subcommand_verb_is_rejected_as_an_app_name() {
        // `import`/`export`/`rm`/`list` are `ops app` subcommands; an app of that name would be
        // unreachable and unmanageable, so it is dropped at resolve time (the charset check would
        // otherwise pass — `rm` is a valid path component, hence the separate reserved check).
        for verb in RESERVED_APP_VERBS {
            assert!(is_reserved_app_verb(verb));
            assert!(
                is_valid_app_name(verb),
                "`{verb}` is a valid path component"
            );
            let global = raw_with_app(verb, raw_app(&["x"], &[], &[], &[], None));
            let r = resolve_no_plugins(global, None);
            assert!(
                !r.apps.contains_key(*verb),
                "a reserved-verb app `{verb}` must be dropped"
            );
            assert!(
                r.warnings.iter().any(|w| w.contains("reserved")),
                "a dropped reserved-verb app `{verb}` must say so"
            );
        }
        assert!(!is_reserved_app_verb("demo-app"));
    }

    #[test]
    fn reading_profiles_keys_each_app_by_its_file_stem() {
        // A profile file is a top-level app; its filename (stem) is the app name.
        let dir = TmpDir::new();
        std::fs::write(
            dir.path().join("demo-app.toml"),
            b"cmd = \"demo-app\"\n[env]\nA = \"1\"\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("review.toml"), b"cmd = [\"review\"]\n").unwrap();
        // A non-.toml file is ignored; a profile whose stem is a reserved verb or an unsafe name
        // is dropped with a warning, never keyed.
        std::fs::write(dir.path().join("notes.txt"), b"ignore me\n").unwrap();
        std::fs::write(dir.path().join("import.toml"), b"cmd = \"x\"\n").unwrap();

        let mut warnings = Vec::new();
        let apps = read_profile_apps_from(dir.path(), &mut warnings);
        assert!(apps.contains_key("demo-app") && apps.contains_key("review"));
        assert!(
            !apps.contains_key("import"),
            "a reserved-verb profile is dropped"
        );
        assert!(
            !apps.contains_key("notes"),
            "a non-.toml file is not a profile"
        );
        assert!(
            warnings.iter().any(|w| w.contains("import.toml")),
            "a dropped reserved-verb profile must warn: {warnings:?}"
        );
    }

    #[test]
    fn an_absent_profiles_directory_is_simply_no_profiles() {
        let dir = TmpDir::new();
        let mut warnings = Vec::new();
        let apps = read_profile_apps_from(&dir.path().join("nope"), &mut warnings);
        assert!(apps.is_empty() && warnings.is_empty());
    }

    #[test]
    fn an_inline_app_shadows_a_profile_of_the_same_name() {
        // On a name collision the hand-authored inline app wins, loudly; the unique profile is
        // folded in.
        let mut global = raw_with_app("demo-app", raw_app(&["inline"], &[], &[], &[], None));
        let profiles: BTreeMap<String, RawApp> = [
            (
                "demo-app".to_string(),
                raw_app(&["profile"], &[], &[], &[], None),
            ),
            (
                "review".to_string(),
                raw_app(&["review"], &[], &[], &[], None),
            ),
        ]
        .into_iter()
        .collect();
        let mut warnings = Vec::new();
        fold_profile_apps(&mut global, profiles, &mut warnings);
        // The inline definition is untouched; the non-colliding profile is added.
        assert_eq!(
            global.app["demo-app"]
                .cmd
                .as_ref()
                .map(|c| c.clone().into_argv()),
            Some(vec!["inline".to_string()])
        );
        assert!(global.app.contains_key("review"));
        assert!(
            warnings.iter().any(|w| w.contains("shadows")),
            "a collision must warn: {warnings:?}"
        );
    }

    #[test]
    fn validating_a_profile_requires_a_command_and_summarizes_its_posture() {
        // A complete profile validates and its granted posture is summarized for display.
        let ok = validate_profile(
            br#"
            cmd = "demo-app"
            [network]
            mode = "allowlist"
            allow = ["api.example.com"]
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            "#,
        )
        .unwrap();
        let joined = ok.summary.join("\n");
        assert!(joined.contains("command: demo-app"), "{joined}");
        assert!(joined.contains("network: allowlist"), "{joined}");
        // The secret shows its destination and source locator — never a value (a profile has none).
        assert!(
            joined.contains("api.example.com") && joined.contains("env://DEMO_API_KEY"),
            "{joined}"
        );
        // `allowlist`/`deny`/`allow` are all filtering postures, so a secret declared under any of
        // them carries no "would not be injected" note. (The `allowlist` profile above already has
        // a secret and is filtering, so its summary must not warn.)
        assert!(
            !joined.contains("injected only under"),
            "a filtering-posture profile must not warn its secrets are uninjected:\n{joined}"
        );
        let deny = validate_profile(
            br#"
            cmd = "demo-app"
            network = "deny"
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            "#,
        )
        .unwrap();
        let deny_joined = deny.summary.join("\n");
        assert!(deny_joined.contains("network: deny"), "{deny_joined}");
        assert!(
            !deny_joined.contains("injected only under"),
            "a bare `deny` posture is filtering, so its secret must not warn:\n{deny_joined}"
        );

        // A non-filtering posture (`shared`) with a secret DOES carry the note — there is no proxy
        // to inject under, so the summary must say so rather than imply working injection.
        let shared = validate_profile(
            br#"
            cmd = "demo-app"
            network = "shared"
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            "#,
        )
        .unwrap();
        assert!(
            shared.summary.join("\n").contains("injected only under"),
            "a non-filtering posture must warn its secrets are uninjected:\n{}",
            shared.summary.join("\n")
        );

        // A profile with no command is refused — and so is a file wrapped in `[app.<name>]` (it
        // parses as an empty app, so it trips the same gate with a helpful hint).
        assert!(validate_profile(b"[env]\nA = \"1\"\n").is_err());
        let wrapped = validate_profile(b"[app.demo-app]\ncmd = \"demo-app\"\n").unwrap_err();
        assert!(wrapped.contains("cmd"), "{wrapped}");
    }

    #[test]
    fn merge_app_overlays_the_baseline_with_app_precedence() {
        let mut base = resolve_no_plugins(raw(&[("A", "base"), ("B", "base")], &[]), None);
        // Seed the baseline limits so the per-field overlay is observable: the app tightens only
        // the task cap, and must inherit the baseline's memory limits untouched.
        base.limits = crate::sandbox::cgroup::Limits {
            memory_high: Some("70%".into()),
            memory_max: Some("16G".into()),
            tasks_max: Some("8192".into()),
        };
        let app = ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: AppHomeScope::Global,
            env: vec![("A".into(), "app".into()), ("C".into(), "app".into())],
            ro_binds: vec![],
            packages: vec![],
            network: Some(NetworkPolicy::Isolated),
            gui: None,
            limits: crate::sandbox::cgroup::Limits {
                tasks_max: Some("4096".into()),
                ..Default::default()
            },
            secrets: vec![],
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            limits_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        };
        base.merge_app(app);
        // App env wins on a collision; baseline-only and app-only keys both survive.
        assert!(base.env.iter().any(|(k, v)| k == "A" && v == "app"));
        assert!(base.env.iter().any(|(k, v)| k == "B" && v == "base"));
        assert!(base.env.iter().any(|(k, v)| k == "C" && v == "app"));
        // The app's posture replaces the baseline's.
        assert!(matches!(base.network, NetworkPolicy::Isolated));
        // The app's limit override replaces the baseline per field; unset fields inherit it.
        assert_eq!(
            base.limits.tasks_max.as_deref(),
            Some("4096"),
            "app overrides the task cap"
        );
        assert_eq!(
            base.limits.memory_high.as_deref(),
            Some("70%"),
            "baseline throttle inherited"
        );
        assert_eq!(
            base.limits.memory_max.as_deref(),
            Some("16G"),
            "baseline ceiling inherited"
        );
    }

    #[test]
    fn merge_app_clears_secrets_when_the_effective_posture_is_not_an_allowlist() {
        let mut base = resolve_no_plugins(raw_network("shared"), None);
        let app = ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![],
            network: None, // inherits the baseline's shared posture
            gui: None,
            limits: Default::default(),
            secrets: vec![a_header_secret()],
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            limits_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        };
        base.merge_app(app);
        assert!(base.secrets.is_empty());
        assert!(base
            .warnings
            .iter()
            .any(|w| w.contains("credential injection requires")));
    }

    #[test]
    fn merge_app_keeps_secrets_under_an_allowlist_the_app_declares() {
        let mut base = resolve_no_plugins(raw_network("shared"), None);
        let app = ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![],
            network: Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::new(vec![], vec![]),
            )),
            gui: None,
            limits: Default::default(),
            secrets: vec![a_header_secret()],
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            limits_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        };
        base.merge_app(app);
        assert_eq!(base.secrets.len(), 1);
        assert!(matches!(base.network, NetworkPolicy::Allowlist(_)));
    }

    #[test]
    fn merge_app_dedups_a_secret_the_app_redeclares_for_the_same_host_and_header() {
        // A baseline credential and an app credential to the same host + header must collapse to
        // one (the app shadowing the baseline, like env/packages) — never two identical header
        // lines injected upstream.
        let mut base = resolve_no_plugins(raw_network("shared"), None);
        base.network =
            NetworkPolicy::Allowlist(crate::allowlist::EgressPolicy::new(vec![], vec![]));
        base.declared_secrets = vec![a_header_secret()];
        base.secrets = vec![a_header_secret()];
        let app = ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![],
            network: None,
            gui: None,
            limits: Default::default(),
            secrets: vec![a_header_secret()],
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            limits_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        };
        base.merge_app(app);
        assert_eq!(
            base.secrets.len(),
            1,
            "the app secret shadows its baseline twin, not duplicated"
        );
    }

    #[test]
    fn merge_app_inherits_a_baseline_secret_when_the_app_opens_a_filtering_posture() {
        // A baseline credential declared under a non-filtering baseline posture (the `shared`
        // default) is absent from the baseline-effective set, but an app that opens a filtering
        // posture must still inherit it — the proxy under the app's posture is what injects it.
        let mut base = resolve_no_plugins(raw_network("shared"), None);
        base.declared_secrets = vec![a_header_secret()];
        assert!(
            base.secrets.is_empty(),
            "the baseline-effective set is cleared under a shared posture"
        );
        let app = ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: AppHomeScope::Global,
            env: vec![],
            ro_binds: vec![],
            packages: vec![],
            network: Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::new(vec![], vec![]),
            )),
            gui: None,
            limits: Default::default(),
            secrets: vec![],
            cmd_origin: Default::default(),
            network_origin: Default::default(),
            gui_origin: Default::default(),
            limits_origin: Default::default(),
            home_scope_origin: None,
            warnings: vec![],
        };
        base.merge_app(app);
        assert_eq!(
            base.secrets.len(),
            1,
            "the app's filtering posture inherits the baseline credential"
        );
    }

    fn pkg<'a>(packages: &'a [Package], name: &str) -> Option<&'a Package> {
        packages.iter().find(|p| p.name == name)
    }

    fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn global_only_is_honored_in_full() {
        let r = resolve_no_plugins(raw(&[("FOO", "g")], &["/srv/data"]), None);
        assert_eq!(get(&r.env, "FOO"), Some("g"));
        assert_eq!(r.ro_binds, vec![PathBuf::from("/srv/data")]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_trusted_project_overrides_env_and_adds_binds() {
        let r = resolve_no_plugins(
            raw(&[("FOO", "global"), ("ONLYG", "g")], &["/srv/global"]),
            Some((
                raw(&[("FOO", "proj")], &["/srv/project"]),
                TrustState::Trusted,
            )),
        );
        // project wins on the shared key, global-only key survives
        assert_eq!(get(&r.env, "FOO"), Some("proj"));
        assert_eq!(get(&r.env, "ONLYG"), Some("g"));
        // binds are the union, global first
        assert_eq!(
            r.ro_binds,
            vec![PathBuf::from("/srv/global"), PathBuf::from("/srv/project")]
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_keeps_free_env_but_drops_binds() {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw(&[("PROJVAR", "v")], &["/etc/ssh"]),
                TrustState::Untrusted,
            )),
        );
        // the free env field still applies
        assert_eq!(get(&r.env, "PROJVAR"), Some("v"));
        // the security bind is dropped, with a first-approval hint
        assert!(r.ro_binds.is_empty());
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("untrusted"));
        assert!(r.warnings[0].contains("run `ops trust`"));
    }

    #[test]
    fn a_changed_project_drops_binds_with_a_reapproval_hint() {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((raw(&[], &["/etc/ssh"]), TrustState::Changed)),
        );
        assert!(r.ro_binds.is_empty());
        assert!(r.warnings[0].contains("changed since it was trusted"));
        assert!(r.warnings[0].contains("re-run `ops trust`"));
    }

    #[test]
    fn an_untrusted_project_cannot_set_reserved_env_keys() {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw(
                    &[
                        ("LD_PRELOAD", "/tmp/evil.so"),
                        ("PATH", "/tmp/bin"),
                        ("BASH_ENV", "/tmp/rc"),
                        ("SAFE", "ok"),
                    ],
                    &[],
                ),
                TrustState::Untrusted,
            )),
        );
        // the three reserved keys are refused, the ordinary one is kept
        assert_eq!(get(&r.env, "LD_PRELOAD"), None);
        assert_eq!(get(&r.env, "PATH"), None);
        assert_eq!(get(&r.env, "BASH_ENV"), None);
        assert_eq!(get(&r.env, "SAFE"), Some("ok"));
        assert_eq!(r.warnings.len(), 3, "one warning per refused key");
        assert!(r.warnings.iter().all(|w| w.contains("reserved env key")));
    }

    #[test]
    fn a_trusted_project_may_set_reserved_env_keys() {
        // vouching for a config honors the whole schema; overriding PATH/LD_PRELOAD
        // harms only its own sandbox (out of scope by design).
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw(
                    &[("LD_PRELOAD", "/opt/lib/shim.so"), ("PATH", "/opt/bin")],
                    &[],
                ),
                TrustState::Trusted,
            )),
        );
        assert_eq!(get(&r.env, "LD_PRELOAD"), Some("/opt/lib/shim.so"));
        assert_eq!(get(&r.env, "PATH"), Some("/opt/bin"));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn reserved_key_predicate_covers_the_ld_family_and_startup_hooks() {
        for k in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "HOME",
            "PATH",
            "NIX_LD",
            "NIX_LD_LIBRARY_PATH",
            "NIX_CONFIG",
            "NIX_USER_CONF_FILES",
            "NIX_CONF_DIR",
            "BASH_ENV",
            "ENV",
            "IFS",
            "GCONV_PATH",
            "GLIBC_TUNABLES",
            "NLSPATH",
            "HOSTALIASES",
            // proxy-control (either case) and the CA-bundle keys: under an allowlist
            // the cage's only egress is ops's filtering proxy, so an untrusted project
            // may not redirect it or swap the CA it trusts.
            "http_proxy",
            "HTTPS_PROXY",
            "no_proxy",
            "all_proxy",
            "NIX_SSL_CERT_FILE",
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "npm_config_cafile",
        ] {
            assert!(is_reserved_env_key(k), "{k} should be reserved");
        }
        // a nix variable that does not inject configuration stays allowed — the
        // denylist closes the config-injection vectors, not nix's whole namespace.
        // `proxychains`/`NIX_PATH` look proxy/nix-ish but are neither a proxy-control
        // nor a CA/config-injection key.
        for k in [
            "EDITOR",
            "RUST_LOG",
            "MY_TOKEN",
            "LDFLAGS",
            "NIX_PATH",
            "PROXY_HOST",
        ] {
            assert!(!is_reserved_env_key(k), "{k} should be allowed");
        }
    }

    #[test]
    fn a_non_absolute_bind_is_dropped() {
        // even a trusted project's relative bind is refused — extra binds are
        // out-of-project absolute paths by construction.
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((raw(&[], &["relative/dir", "/abs/ok"]), TrustState::Trusted)),
        );
        assert_eq!(r.ro_binds, vec![PathBuf::from("/abs/ok")]);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("non-absolute bind `relative/dir`"));
    }

    #[test]
    fn a_malformed_env_key_is_dropped() {
        // a quoted TOML key could carry `=`; it must never reach `--setenv`
        let r = resolve_no_plugins(raw(&[("A=B", "x"), ("OK", "y")], &[]), None);
        assert_eq!(get(&r.env, "OK"), Some("y"));
        assert!(r.env.iter().all(|(k, _)| k != "A=B"));
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("malformed env key"));
    }

    #[test]
    fn is_valid_env_key_rejects_empty_equals_and_control() {
        assert!(is_valid_env_key("FOO_BAR"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("A=B"));
        assert!(!is_valid_env_key("A\nB"));
        assert!(!is_valid_env_key("A\0B"));
    }

    #[test]
    fn global_packages_are_trusted_by_location() {
        let r = resolve_no_plugins(raw_packages(&[("node", "nix:nodejs_20")]), None);
        let node = pkg(&r.packages, "node").expect("global package present");
        assert_eq!(node.backend, Backend::Nix("nodejs_20".into()));
        assert_eq!(
            node.state,
            TrustState::Trusted,
            "a global package is trusted by location"
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_trusted_project_package_overrides_the_global_one_by_name() {
        let r = resolve_no_plugins(
            raw_packages(&[("node", "nix:nodejs_20"), ("onlyg", "nix:ripgrep")]),
            Some((
                raw_packages(&[("node", "nix:nodejs_22")]),
                TrustState::Trusted,
            )),
        );
        // the project pins the shared name; the global-only tool survives
        let node = pkg(&r.packages, "node").unwrap();
        assert_eq!(node.backend, Backend::Nix("nodejs_22".into()));
        assert_eq!(node.state, TrustState::Trusted);
        assert_eq!(
            pkg(&r.packages, "onlyg").unwrap().backend,
            Backend::Nix("ripgrep".into())
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_package_is_carried_but_flagged_untrusted() {
        // The launcher, not this stage, decides admission — so the package is kept,
        // stamped with its source's trust, with no drop and no warning here.
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw_packages(&[("node", "nix:nodejs_20")]),
                TrustState::Untrusted,
            )),
        );
        let node = pkg(&r.packages, "node").expect("untrusted package still carried");
        assert_eq!(node.backend, Backend::Nix("nodejs_20".into()));
        assert_eq!(node.state, TrustState::Untrusted);
        assert!(
            r.warnings.is_empty(),
            "admission warnings belong to the launcher, not the pure merge"
        );
    }

    #[test]
    fn a_changed_project_package_keeps_the_changed_state_distinct_from_untrusted() {
        // The Changed≠Untrusted distinction must survive onto the package: a changed
        // project points the user at re-approval, not first approval.
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw_packages(&[("node", "nix:nodejs_20")]),
                TrustState::Changed,
            )),
        );
        assert_eq!(pkg(&r.packages, "node").unwrap().state, TrustState::Changed);
        assert_eq!(
            untrusted_reason(TrustState::Changed),
            "changed since it was trusted — re-run `ops trust`"
        );
        assert_eq!(
            untrusted_reason(TrustState::Untrusted),
            "untrusted — run `ops trust`"
        );
    }

    #[test]
    fn a_malformed_or_unprefixed_package_is_dropped() {
        let r = resolve_no_plugins(
            raw_packages(&[
                ("../escape", "nix:hello"), // label escapes its directory
                ("ok", "nix:bad attr!"),    // attribute carries an illegal character
                ("bare", "nodejs_20"),      // no backend prefix — fail-closed, not a silent nix
                ("node", "nix:nodejs_20"),  // the well-formed one survives
            ]),
            None,
        );
        assert!(pkg(&r.packages, "../escape").is_none());
        assert!(pkg(&r.packages, "ok").is_none());
        assert!(
            pkg(&r.packages, "bare").is_none(),
            "a value with no nix:/mise: prefix is dropped, never treated as a bare nix attr"
        );
        assert_eq!(
            pkg(&r.packages, "node").unwrap().backend,
            Backend::Nix("nodejs_20".into())
        );
        assert_eq!(r.warnings.len(), 3, "one warning per dropped package");
        // the bare one names the fix, not a generic error
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("bare") && w.contains("backend prefix")));
    }

    #[test]
    fn a_mise_prefixed_package_parses_as_a_mise_backend() {
        // `mise:<token>` routes to the in-cage mise equip; the token is kept verbatim, including
        // a `nix:`-prefixed nixhub token (`mise:nix:...`), which is mise's concern.
        let r = resolve_no_plugins(
            raw_packages(&[
                ("demo-tool", "mise:aqua:example/demo-tool"),
                ("other-tool", "mise:other-tool"),
                ("nixhub", "mise:nix:jq"),
            ]),
            None,
        );
        assert_eq!(
            pkg(&r.packages, "demo-tool").unwrap().backend,
            Backend::Mise("aqua:example/demo-tool".into())
        );
        assert_eq!(
            pkg(&r.packages, "other-tool").unwrap().backend,
            Backend::Mise("other-tool".into())
        );
        assert_eq!(
            pkg(&r.packages, "nixhub").unwrap().backend,
            Backend::Mise("nix:jq".into())
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_flake_prefixed_package_parses_as_a_flake_backend_and_rejects_local_sources() {
        // `flake:<ref>` routes to the in-cage `nix build`; a remote ref is kept verbatim, while a
        // local source (`path:`/`git+file:`) is refused — a package must never point the build at
        // the host filesystem.
        let r = resolve_no_plugins(
            raw_packages(&[
                ("flake-tool", "flake:github:example/flake-tool#tui"),
                ("pinned", "flake:github:o/r/abc123#default"),
                ("local", "flake:path:/etc"), // local scheme: refused
                ("localgit", "flake:git+file:///etc"), // local git scheme: refused
                ("filescheme", "flake:file:///etc/x.tar.gz"), // file:// tarball: refused
                ("tarballfile", "flake:tarball+file:///etc/x.tar.gz"), // tarball+file: refused
                ("bare", "flake:/etc"),       // bare absolute path: refused
                ("dotted", "flake:./x"),      // bare relative path: refused
                ("tilde", "flake:~/x"),       // bare home path: refused
                ("indirect", "flake:nixpkgs"), // registry-indirect (no scheme): refused
                ("spacey", "flake:github:o/r#a b"), // whitespace: refused
            ]),
            None,
        );
        assert_eq!(
            pkg(&r.packages, "flake-tool").unwrap().backend,
            Backend::Flake("github:example/flake-tool#tui".into())
        );
        assert_eq!(
            pkg(&r.packages, "pinned").unwrap().backend,
            Backend::Flake("github:o/r/abc123#default".into())
        );
        for refused in [
            "local",
            "localgit",
            "filescheme",
            "tarballfile",
            "bare",
            "dotted",
            "tilde",
            "indirect",
            "spacey",
        ] {
            assert!(
                pkg(&r.packages, refused).is_none(),
                "{refused} should be refused"
            );
        }
        assert_eq!(r.warnings.len(), 9, "one warning per refused flake ref");
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("local") && w.contains("flake reference")));
    }

    #[test]
    fn package_name_and_attribute_validators() {
        for n in ["node", "python3", "rust-analyzer", "a.b", "_x"] {
            assert!(is_valid_package_name(n), "{n} should be a valid name");
        }
        for n in ["", ".", "..", "a/b", "a b", "a\0b"] {
            assert!(!is_valid_package_name(n), "{n} should be rejected");
        }
        for a in [
            "hello",
            "nodejs_20",
            "python3Packages.requests",
            "gcc-wrapper",
            "libstdc++",
        ] {
            assert!(is_valid_attr(a), "{a} should be a valid attribute");
        }
        for a in ["", "a b", "a#b", "a;b", "a$b", "a\"b"] {
            assert!(!is_valid_attr(a), "{a} should be rejected");
        }
    }

    #[test]
    fn a_global_nixpkgs_override_is_honored_a_trusted_project_overrides_it() {
        // global is trusted by location
        let r = resolve_no_plugins(raw_nixpkgs("nixos-23.11"), None);
        assert_eq!(r.nixpkgs_global.as_deref(), Some("nixos-23.11"));
        assert_eq!(r.nixpkgs_project, None);
        assert!(r.warnings.is_empty());

        // a trusted project sets its own (the launcher prefers it for the tools)
        let r = resolve_no_plugins(
            raw_nixpkgs("nixos-unstable"),
            Some((raw_nixpkgs("nixos-23.11"), TrustState::Trusted)),
        );
        assert_eq!(r.nixpkgs_global.as_deref(), Some("nixos-unstable"));
        assert_eq!(r.nixpkgs_project.as_deref(), Some("nixos-23.11"));
    }

    #[test]
    fn an_untrusted_project_nixpkgs_override_is_dropped_with_a_warning() {
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let r = resolve_no_plugins(
                RawConfig::default(),
                Some((raw_nixpkgs("nixos-23.11"), state)),
            );
            assert_eq!(
                r.nixpkgs_project, None,
                "an untrusted project may not repoint the catalogue"
            );
            assert_eq!(r.warnings.len(), 1);
            assert!(r.warnings[0].contains("nixpkgs"));
        }
    }

    #[test]
    fn a_malformed_nixpkgs_source_is_dropped() {
        // a full flake reference is not (yet) a valid source: it must not reach nix
        let r = resolve_no_plugins(raw_nixpkgs("github:evil/nixpkgs"), None);
        assert_eq!(r.nixpkgs_global, None);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("malformed nixpkgs source"));
    }

    #[test]
    fn the_default_network_posture_is_shared() {
        // No declared posture anywhere means the host network — the documented
        // default until the egress allowlist ships.
        assert_eq!(
            resolve_no_plugins(RawConfig::default(), None).network,
            NetworkPolicy::Shared
        );
    }

    #[test]
    fn a_global_network_posture_is_honored_a_trusted_project_overrides_it() {
        // global is trusted by location
        let r = resolve_no_plugins(raw_network("none"), None);
        assert_eq!(r.network, NetworkPolicy::Isolated);
        assert!(r.warnings.is_empty());

        // a trusted project sets its own, overriding the global posture
        let r = resolve_no_plugins(
            raw_network("none"),
            Some((raw_network("shared"), TrustState::Trusted)),
        );
        assert_eq!(r.network, NetworkPolicy::Shared);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_network_posture_is_dropped_with_a_warning() {
        // an untrusted project may not change the network — its choice is dropped and
        // the default (or the global posture) stands.
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let r = resolve_no_plugins(RawConfig::default(), Some((raw_network("none"), state)));
            assert_eq!(
                r.network,
                NetworkPolicy::Shared,
                "an untrusted project may not narrow the network"
            );
            assert_eq!(r.warnings.len(), 1);
            assert!(r.warnings[0].contains("network"));
        }
    }

    #[test]
    fn an_untrusted_project_cannot_widen_a_globally_isolated_network() {
        // The gate cuts both ways: with the global config isolating the network, an
        // untrusted project asking for `"shared"` cannot reopen it.
        let r = resolve_no_plugins(
            raw_network("none"),
            Some((raw_network("shared"), TrustState::Untrusted)),
        );
        assert_eq!(r.network, NetworkPolicy::Isolated);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("network"));
    }

    #[test]
    fn an_unknown_network_posture_is_dropped_with_a_warning() {
        // a typo must not silently leave the network in the wrong posture
        let r = resolve_no_plugins(raw_network("offline"), None);
        assert_eq!(r.network, NetworkPolicy::Shared);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("unknown network policy `offline`"));
    }

    #[test]
    fn the_default_gui_posture_is_none() {
        // No declared posture anywhere means no display — the cage exposes no compositor.
        assert_eq!(
            resolve_no_plugins(RawConfig::default(), None).gui,
            GuiPolicy::None
        );
    }

    #[test]
    fn a_global_gui_posture_is_honored_a_trusted_project_overrides_it() {
        // global is trusted by location
        let r = resolve_no_plugins(raw_gui("wayland"), None);
        assert_eq!(r.gui, GuiPolicy::Wayland);
        assert!(r.warnings.is_empty());

        // a trusted project sets its own, overriding the global posture
        let r = resolve_no_plugins(
            raw_gui("wayland"),
            Some((raw_gui("none"), TrustState::Trusted)),
        );
        assert_eq!(r.gui, GuiPolicy::None);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_gui_posture_is_dropped_with_a_warning() {
        // the flagship property at the baseline: an untrusted project may not open a display —
        // its `gui = "wayland"` is dropped and the default (no display) stands.
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let r = resolve_no_plugins(RawConfig::default(), Some((raw_gui("wayland"), state)));
            assert_eq!(
                r.gui,
                GuiPolicy::None,
                "an untrusted project may not open a display"
            );
            assert_eq!(r.warnings.len(), 1);
            assert!(r.warnings[0].contains("gui"));
        }
    }

    #[test]
    fn an_untrusted_project_cannot_close_a_globally_opened_gui() {
        // The gate cuts both ways: with the global config opening the display, an untrusted
        // project asking for `none` cannot touch it (it may not change a security field at all).
        let r = resolve_no_plugins(
            raw_gui("wayland"),
            Some((raw_gui("none"), TrustState::Untrusted)),
        );
        assert_eq!(r.gui, GuiPolicy::Wayland);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("gui"));
    }

    #[test]
    fn an_unknown_gui_posture_is_dropped_with_a_warning() {
        // a typo (or an X11 request, which is never offered) must not silently mis-set the posture
        let r = resolve_no_plugins(raw_gui("x11"), None);
        assert_eq!(r.gui, GuiPolicy::None);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("unknown gui posture `x11`"));
    }

    #[test]
    fn network_posture_validator() {
        let mut w = Vec::new();
        assert_eq!(
            validate_network(&mut w, "t", NetworkField::Posture("none".into())),
            Some(NetworkPolicy::Isolated)
        );
        assert_eq!(
            validate_network(&mut w, "t", NetworkField::Posture("shared".into())),
            Some(NetworkPolicy::Shared)
        );
        assert!(w.is_empty());
        assert_eq!(
            validate_network(&mut w, "t", NetworkField::Posture("bogus".into())),
            None
        );
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn a_trusted_project_allowlist_is_classified() {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw_network_allow(&["github.com", "*.nixos.org", "1.2.3.4", "ex.com/p"]),
                TrustState::Trusted,
            )),
        );
        match &r.network {
            NetworkPolicy::Allowlist(a) => {
                assert!(a.permits("github.com", 443, "/"));
                assert!(a.permits("cache.nixos.org", 443, "/nar/x"));
                assert!(a.permits("1.2.3.4", 80, "/"));
                assert!(a.permits("ex.com", 443, "/p"));
                assert!(
                    !a.permits("ex.com", 443, "/other"),
                    "URL rule is path-exact"
                );
                assert!(!a.permits("evil.com", 443, "/"));
            }
            other => panic!("expected an allowlist, got {other:?}"),
        }
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_allowlist_is_dropped_with_a_warning() {
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let r = resolve_no_plugins(
                RawConfig::default(),
                Some((raw_network_allow(&["github.com"]), state)),
            );
            assert_eq!(
                r.network,
                NetworkPolicy::Shared,
                "an untrusted project may not set an egress allowlist"
            );
            assert_eq!(r.warnings.len(), 1);
            assert!(r.warnings[0].contains("network"));
        }
    }

    #[test]
    fn a_trusted_project_deny_carves_out_of_allow() {
        // deny always wins: a broad allow with a deny carve-out blocks the carve-out.
        let r = resolve_no_plugins(
            raw_network_table(&["*.nixos.org"], &["evil.nixos.org"]),
            Some((RawConfig::default(), TrustState::Trusted)),
        );
        match &r.network {
            NetworkPolicy::Allowlist(a) => {
                assert!(a.permits("cache.nixos.org", 443, "/"));
                assert!(!a.permits("evil.nixos.org", 443, "/"), "deny wins");
            }
            other => panic!("expected an allowlist, got {other:?}"),
        }
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_malformed_entry_in_either_list_is_dropped_keeping_the_valid_ones() {
        // global is trusted by location; a bad entry fails closed (that host stays
        // unreachable / its carve-out absent), the valid ones are kept, each drop named.
        let r = resolve_no_plugins(
            raw_network_table(&["github.com", "bad host"], &["evil.com", "also bad"]),
            None,
        );
        match &r.network {
            NetworkPolicy::Allowlist(a) => {
                assert_eq!(
                    a.allow_rules().len(),
                    1,
                    "the malformed allow entry is dropped"
                );
                assert_eq!(
                    a.deny_rules().len(),
                    1,
                    "the malformed deny entry is dropped"
                );
                assert!(a.permits("github.com", 443, "/"));
                assert!(!a.permits("evil.com", 443, "/"), "the kept deny still wins");
            }
            other => panic!("expected an allowlist, got {other:?}"),
        }
        assert_eq!(r.warnings.len(), 2);
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("ignoring allow entry")));
        assert!(r.warnings.iter().any(|w| w.contains("ignoring deny entry")));
    }

    #[test]
    fn an_unknown_network_mode_is_dropped_with_a_warning() {
        let r = resolve_no_plugins(
            RawConfig {
                network: Some(NetworkField::Table(NetworkTable {
                    mode: "bogus".into(),
                    allow: vec![],
                    deny: vec![],
                    ask_timeout: None,
                    ask_notice: None,
                    stats: None,
                })),
                ..RawConfig::default()
            },
            None,
        );
        assert_eq!(r.network, NetworkPolicy::Shared);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("unknown network mode"));
    }

    #[test]
    fn nixpkgs_source_validator() {
        for s in [
            "nixos-unstable",
            "nixos-23.11",
            "release-23.11",
            "master",
            "staging-next",
            "9ae611a455b90cf061d8f332b977e387bda8e1ca",
        ] {
            assert!(is_valid_nixpkgs_source(s), "{s} should be valid");
        }
        for s in [
            "",
            "github:NixOS/nixpkgs",
            "git+https://x",
            "path:/etc",
            "a b",
            "a;b",
        ] {
            assert!(!is_valid_nixpkgs_source(s), "{s} should be rejected");
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn raw_secret(
        from_env: Option<&str>,
        from_file: Option<&str>,
        to: &str,
        header: &str,
        ty: Option<&str>,
        prefix: Option<&str>,
    ) -> (String, RawHostSecret) {
        // Map the convenience params onto a `from` ref so the many call sites stay terse. The
        // host is returned alongside the secret, since it is the section key in the new shape.
        let from = match (from_env, from_file) {
            (Some(v), None) => Some(SecretFrom::One(format!("env://{v}"))),
            (None, Some(p)) => Some(SecretFrom::One(format!("file://{p}"))),
            (None, None) => None,
            (Some(_), Some(_)) => panic!("test helper: set at most one of from_env / from_file"),
        };
        (
            to.into(),
            RawHostSecret {
                kind: Some("http-header".into()),
                key: None,
                from,
                header: Some(header.into()),
                value_type: ty.map(String::from),
                prefix: prefix.map(String::from),
            },
        )
    }

    /// Group `(host, secret)` pairs into a `[secret]` section, collapsing repeats of the same
    /// host into a `[[secret."host"]]` array (so the duplicate-target and multi-header cases are
    /// expressible).
    fn raw_secret_section(secrets: Vec<(String, RawHostSecret)>) -> RawSecretSection {
        let mut hosts: BTreeMap<String, RawHostSecrets> = BTreeMap::new();
        for (host, s) in secrets {
            match hosts.remove(&host) {
                None => {
                    hosts.insert(host, RawHostSecrets::One(s));
                }
                Some(RawHostSecrets::One(first)) => {
                    hosts.insert(host, RawHostSecrets::Many(vec![first, s]));
                }
                Some(RawHostSecrets::Many(mut v)) => {
                    v.push(s);
                    hosts.insert(host, RawHostSecrets::Many(v));
                }
            }
        }
        RawSecretSection {
            defaults: None,
            hosts,
        }
    }

    /// A `RawConfig` declaring a network allowlist (so secrets are not dropped by the
    /// allowlist dependency) plus the given secrets.
    fn raw_secrets(allow: &[&str], secrets: Vec<(String, RawHostSecret)>) -> RawConfig {
        RawConfig {
            network: Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".into(),
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
            })),
            secret: Some(raw_secret_section(secrets)),
            ..RawConfig::default()
        }
    }

    /// A `RawHostSecret` whose `from` is the given resolver-ref list, for the validation tests.
    fn raw_secret_from(from: Vec<&str>) -> RawHostSecret {
        RawHostSecret {
            kind: Some("http-header".into()),
            key: None,
            from: Some(SecretFrom::Many(
                from.into_iter().map(String::from).collect(),
            )),
            header: Some("Authorization".into()),
            value_type: Some("bearer".into()),
            prefix: None,
        }
    }

    /// Validate a host secret against empty defaults, for the source/parse tests. The host is a
    /// fixed concrete target so the tests focus on the source form.
    fn validate(secret: RawHostSecret) -> Result<HeaderSecret, String> {
        vhs("api.github.com", secret, &SecretDefaults::default())
    }

    /// [`validate_host_secret`] with no installed plugins — the default for the secret tests,
    /// which exercise the built-in resolvers. The plugin-scheme tests build a registry explicitly.
    fn vhs(
        host: &str,
        secret: RawHostSecret,
        defaults: &SecretDefaults,
    ) -> Result<HeaderSecret, String> {
        validate_host_secret(host, secret, defaults, &PluginRegistry::default())
    }

    /// [`resolve`] with no installed plugins — the default for the layering tests.
    fn resolve_no_plugins(global: RawConfig, project: Option<(RawConfig, TrustState)>) -> Resolved {
        super::resolve(global, project, &PluginRegistry::default())
    }

    #[test]
    fn the_egress_stats_toggle_defaults_on_and_is_gated_trusted_only() {
        // A `[network]` table carrying an explicit `stats` value.
        let net = |stats: Option<bool>| RawConfig {
            network: Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".into(),
                allow: vec!["github.com".into()],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats,
            })),
            ..RawConfig::default()
        };

        // Default: nothing set → recording is on.
        assert!(resolve_no_plugins(RawConfig::default(), None).egress_stats);
        // A bare-string posture carries no `stats` key → stays on.
        assert!(resolve_no_plugins(raw_network("allowlist"), None).egress_stats);
        // Global `stats = false` (trusted by location) → off.
        assert!(!resolve_no_plugins(net(Some(false)), None).egress_stats);
        // A TRUSTED project may turn its own audit off.
        assert!(
            !resolve_no_plugins(
                RawConfig::default(),
                Some((net(Some(false)), TrustState::Trusted))
            )
            .egress_stats
        );
        // An UNTRUSTED project's `stats = false` is dropped with its whole `[network]` table — it
        // cannot disable the auditing of its own egress.
        assert!(
            resolve_no_plugins(
                RawConfig::default(),
                Some((net(Some(false)), TrustState::Untrusted))
            )
            .egress_stats
        );
        // Layering: a trusted project's `stats = true` overrides a global `false`.
        assert!(
            resolve_no_plugins(
                net(Some(false)),
                Some((net(Some(true)), TrustState::Trusted))
            )
            .egress_stats
        );
    }

    #[test]
    fn an_apps_network_stats_toggle_is_warned_and_ignored() {
        // The egress-stats switch is baseline-only, so a `stats` key inside an `[app.<name>.network]`
        // table is parsed but has no effect — warned, never silently dropped (every shipped profile
        // declares its network as a table, so an author would otherwise believe it took).
        let app = raw_app(
            &["true"],
            &[],
            &[],
            &[],
            Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".into(),
                allow: vec!["api.example.com".into()],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: Some(false),
            })),
        );
        let r = resolve_no_plugins(raw_with_app("demo", app), None);
        assert!(
            r.egress_stats,
            "an app's stats toggle must not change the baseline (it is baseline-only)"
        );
        // The warning lives on the app (surfaced when `ops app demo` launches, via `merge_app`
        // folding it into the baseline warnings), not on the baseline read.
        let demo = r.apps.get("demo").expect("the app resolves");
        assert!(
            demo.warnings
                .iter()
                .any(|w| w.contains("stats") && w.contains("baseline-only")),
            "the ignored app stats toggle must be warned: {:?}",
            demo.warnings
        );
    }

    /// A terse `RawHostSecret` — `key` only, no explicit `from` — for the expansion tests.
    fn terse(key: &str) -> RawHostSecret {
        RawHostSecret {
            kind: None,
            key: Some(key.into()),
            from: None,
            header: Some("Authorization".into()),
            value_type: Some("bearer".into()),
            prefix: None,
        }
    }

    /// A terse `RawHostSecret` that also omits `header` and `type`, so they must come from
    /// `[secret.defaults]` — for the default-header/type tests.
    fn terse_bare(key: &str) -> RawHostSecret {
        RawHostSecret {
            kind: None,
            key: Some(key.into()),
            from: None,
            header: None,
            value_type: None,
            prefix: None,
        }
    }

    /// A raw `[secret.defaults]` table from its parts, for the expansion and layering tests.
    fn raw_defaults(
        order: &[&str],
        sops_file: Option<&str>,
        env_case: Option<&str>,
        file_dir: Option<&str>,
    ) -> RawSecretDefaults {
        RawSecretDefaults {
            order: order.iter().map(|s| s.to_string()).collect(),
            header: None,
            value_type: None,
            sops: sops_file.map(|f| RawSopsDefaults { file: f.into() }),
            env: env_case.map(|c| RawEnvDefaults {
                case: Some(c.into()),
            }),
            file: file_dir.map(|d| RawFileDefaults { dir: d.into() }),
        }
    }

    /// A trusted-shaped network allowlist for the given hosts.
    fn allowlist_net(allow: &[&str]) -> Option<NetworkField> {
        Some(NetworkField::Table(NetworkTable {
            mode: "allowlist".into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
        }))
    }

    /// A `[secret]` section with the given defaults and one terse host entry.
    fn terse_section(defaults: RawSecretDefaults, host: &str, key: &str) -> RawSecretSection {
        let mut hosts = BTreeMap::new();
        hosts.insert(host.to_string(), RawHostSecrets::One(terse(key)));
        RawSecretSection {
            defaults: Some(defaults),
            hosts,
        }
    }

    #[test]
    fn a_from_chain_parses_into_ordered_sources() {
        let s = validate(raw_secret_from(vec![
            "env://GH_TOKEN",
            "file:///run/secrets/gh",
        ]))
        .unwrap();
        assert_eq!(
            s.sources,
            vec![
                SecretSource::Env("GH_TOKEN".into()),
                SecretSource::File("/run/secrets/gh".into()),
            ]
        );
        // the chain is shown by locator (never a value), precedence visible
        assert_eq!(
            s.describe_sources(),
            "env GH_TOKEN, then file /run/secrets/gh"
        );
    }

    #[test]
    fn a_single_string_from_parses_to_one_source() {
        let mut raw = raw_secret_from(vec!["env://GH_TOKEN"]);
        raw.from = Some(SecretFrom::One("env://GH_TOKEN".into()));
        let s = validate(raw).unwrap();
        assert_eq!(s.sources, vec![SecretSource::Env("GH_TOKEN".into())]);
    }

    #[test]
    fn an_empty_from_list_is_rejected() {
        let err = validate(raw_secret_from(vec![])).unwrap_err();
        assert!(err.contains("empty list"), "{err}");
    }

    #[test]
    fn a_from_entry_without_a_scheme_is_rejected() {
        let err = validate(raw_secret_from(vec!["GH_TOKEN"])).unwrap_err();
        assert!(err.contains("needs a scheme"), "{err}");
    }

    #[test]
    fn an_unknown_resolver_scheme_is_rejected() {
        let err = validate(raw_secret_from(vec!["vault://secret/x#f"])).unwrap_err();
        assert!(
            err.contains("unknown secret resolver scheme") && err.contains("vault"),
            "{err}"
        );
    }

    #[test]
    fn a_secret_with_no_source_at_all_is_rejected() {
        let mut raw = raw_secret_from(vec!["env://X"]);
        raw.from = None;
        let err = validate(raw).unwrap_err();
        assert!(err.contains("needs a source"), "{err}");
    }

    #[test]
    fn a_sops_ref_parses_to_a_file_and_key() {
        let s = validate(raw_secret_from(vec![
            "sops://secrets/prod.yaml#db.password",
        ]))
        .unwrap();
        assert_eq!(
            s.sources,
            vec![SecretSource::Sops {
                file: "secrets/prod.yaml".into(),
                key: Some("db.password".into()),
            }]
        );
        assert_eq!(s.describe_sources(), "sops secrets/prod.yaml#db.password");
    }

    #[test]
    fn a_sops_ref_without_a_key_decrypts_the_whole_file() {
        let s = validate(raw_secret_from(vec!["sops:///abs/secrets.yaml"])).unwrap();
        assert_eq!(
            s.sources,
            vec![SecretSource::Sops {
                file: "/abs/secrets.yaml".into(),
                key: None,
            }]
        );
    }

    #[test]
    fn a_sops_key_with_an_invalid_segment_is_rejected() {
        let err = validate(raw_secret_from(vec!["sops://f.yaml#db.pa$$word"])).unwrap_err();
        assert!(err.contains("invalid segment"), "{err}");
    }

    #[test]
    fn a_sops_ref_with_a_trailing_hash_or_empty_segment_is_rejected() {
        let err = validate(raw_secret_from(vec!["sops://f.yaml#"])).unwrap_err();
        assert!(err.contains("empty key"), "{err}");
        let err = validate(raw_secret_from(vec!["sops://f.yaml#a..b"])).unwrap_err();
        assert!(err.contains("empty path segment"), "{err}");
    }

    // --- the terse `key` form + `[secret.defaults]` ------------------------------------------

    #[test]
    fn a_terse_key_expands_through_the_default_order() {
        // order [env, sops] with an env case + a sops file: the key becomes a fallback chain, env
        // first (upcased), then sops (joined onto the bound file). The chain reuses the existing
        // source types, so everything downstream is unchanged.
        let d = SecretDefaults::from_raw(&raw_defaults(
            &["env", "sops"],
            Some("prod.yaml"),
            Some("upper"),
            None,
        ));
        let s = vhs("api.github.com", terse("github_token"), &d).unwrap();
        assert_eq!(
            s.sources,
            vec![
                SecretSource::Env("GITHUB_TOKEN".into()),
                SecretSource::Sops {
                    file: "prod.yaml".into(),
                    key: Some("github_token".into()),
                },
            ]
        );
        assert_eq!(
            s.describe_sources(),
            "env GITHUB_TOKEN, then sops prod.yaml#github_token"
        );
    }

    #[test]
    fn a_pinned_resolver_overrides_the_order() {
        // `key@sops` ignores the default order and uses sops only
        let d = SecretDefaults::from_raw(&raw_defaults(&["env"], Some("prod.yaml"), None, None));
        let s = vhs("api.github.com", terse("tok@sops"), &d).unwrap();
        assert_eq!(
            s.sources,
            vec![SecretSource::Sops {
                file: "prod.yaml".into(),
                key: Some("tok".into()),
            }]
        );
    }

    #[test]
    fn a_pin_can_reorder_several_resolvers() {
        // `key@sops,env` is that order for this secret only, regardless of the default
        let d = SecretDefaults::from_raw(&raw_defaults(&["env"], Some("prod.yaml"), None, None));
        let s = vhs("api.github.com", terse("tok@sops,env"), &d).unwrap();
        assert_eq!(
            s.sources,
            vec![
                SecretSource::Sops {
                    file: "prod.yaml".into(),
                    key: Some("tok".into()),
                },
                SecretSource::Env("tok".into()),
            ]
        );
    }

    #[test]
    fn a_terse_file_key_joins_the_base_dir() {
        let d =
            SecretDefaults::from_raw(&raw_defaults(&["file"], None, None, Some("/run/secrets")));
        let s = vhs("h.test", terse("npm"), &d).unwrap();
        assert_eq!(
            s.sources,
            vec![SecretSource::File("/run/secrets/npm".into())]
        );
    }

    #[test]
    fn a_relative_file_dir_is_rejected_naming_the_binding() {
        // a relative `[secret.defaults.file] dir` fails closed with a message naming the binding,
        // not the joined path
        let d = SecretDefaults::from_raw(&raw_defaults(&["file"], None, None, Some("rel/secrets")));
        let err = vhs("h.test", terse("npm"), &d).unwrap_err();
        assert!(
            err.contains("[secret.defaults.file] dir") && err.contains("absolute"),
            "{err}"
        );
    }

    #[test]
    fn a_terse_key_using_an_unbound_resolver_is_rejected() {
        // sops is in the order but no `[secret.defaults.sops] file` is set — fail closed
        let d = SecretDefaults::from_raw(&raw_defaults(&["sops"], None, None, None));
        let err = vhs("h.test", terse("tok"), &d).unwrap_err();
        assert!(err.contains("sops") && err.contains("unset"), "{err}");
    }

    #[test]
    fn a_terse_key_with_no_order_and_no_pin_is_rejected() {
        // no default order and no `@resolver` — there is nothing to resolve through
        let err = vhs("h.test", terse("tok"), &SecretDefaults::default()).unwrap_err();
        assert!(err.contains("no resolver for key"), "{err}");
    }

    #[test]
    fn a_terse_key_with_a_path_separator_is_rejected() {
        // a terse key may not carry a `/` — it would traverse out of a file/sops base
        let d =
            SecretDefaults::from_raw(&raw_defaults(&["file"], None, None, Some("/run/secrets")));
        let err = vhs("h.test", terse("../../etc/shadow"), &d).unwrap_err();
        assert!(err.contains("segment"), "{err}");
    }

    #[test]
    fn an_unknown_env_case_is_rejected() {
        let d = SecretDefaults::from_raw(&raw_defaults(&["env"], None, Some("title"), None));
        let err = vhs("h.test", terse("tok"), &d).unwrap_err();
        assert!(err.contains("unknown env `case`"), "{err}");
    }

    #[test]
    fn key_and_from_together_is_rejected() {
        let mut s = terse("tok");
        s.from = Some(SecretFrom::One("env://TOK".into()));
        let err = validate(s).unwrap_err();
        assert!(err.contains("not both"), "{err}");
    }

    /// A test resolver plugin claiming `scheme`. The exec path and sandbox grant are
    /// placeholders — the config layer only records them, it never runs the plugin.
    fn plugin(scheme: &str) -> crate::plugins::ResolverPlugin {
        crate::plugins::ResolverPlugin {
            name: scheme.to_string(),
            scheme: scheme.to_string(),
            dir: PathBuf::from(format!("/data/plugins/{scheme}")),
            exec: PathBuf::from(format!("/data/plugins/{scheme}/resolve")),
            sandbox: crate::plugins::SandboxGrant::default(),
            version: None,
            description: None,
        }
    }

    /// [`validate_host_secret`] against a given registry, for the plugin-scheme tests.
    fn vhs_with(secret: RawHostSecret, plugins: &PluginRegistry) -> Result<HeaderSecret, String> {
        validate_host_secret(
            "api.github.com",
            secret,
            &SecretDefaults::default(),
            plugins,
        )
    }

    #[test]
    fn a_from_ref_resolves_through_a_registered_plugin() {
        let reg = PluginRegistry::with([plugin("pass")]);
        let s = vhs_with(raw_secret_from(vec!["pass://github/token"]), &reg).unwrap();
        match &s.sources[..] {
            [SecretSource::Plugin { plugin, locator }] => {
                assert_eq!(plugin.scheme, "pass");
                assert_eq!(locator, "github/token");
            }
            other => panic!("expected one plugin source, got {other:?}"),
        }
    }

    #[test]
    fn a_plugin_describes_without_the_value() {
        let reg = PluginRegistry::with([plugin("pass")]);
        let s = vhs_with(raw_secret_from(vec!["pass://github/token"]), &reg).unwrap();
        assert_eq!(s.describe_sources(), "pass github/token");
    }

    #[test]
    fn an_unregistered_plugin_scheme_is_rejected() {
        // no plugin claims `vault` → the scheme stays unknown and fails closed
        let err = vhs_with(
            raw_secret_from(vec!["vault://secret/x"]),
            &PluginRegistry::default(),
        )
        .unwrap_err();
        assert!(err.contains("vault://"), "{err}");
        assert!(err.contains("plugin"), "{err}");
    }

    #[test]
    fn a_plugin_can_follow_a_builtin_in_a_fallback_chain() {
        let reg = PluginRegistry::with([plugin("pass")]);
        let s = vhs_with(
            raw_secret_from(vec!["env://TOK", "pass://github/token"]),
            &reg,
        )
        .unwrap();
        assert!(matches!(s.sources[0], SecretSource::Env(_)));
        assert!(matches!(s.sources[1], SecretSource::Plugin { .. }));
    }

    #[test]
    fn a_plugin_locator_with_a_control_character_is_rejected() {
        let reg = PluginRegistry::with([plugin("pass")]);
        let err = vhs_with(raw_secret_from(vec!["pass://bad\nref"]), &reg).unwrap_err();
        assert!(err.contains("control character"), "{err}");
    }

    #[test]
    fn an_empty_plugin_locator_is_rejected() {
        let reg = PluginRegistry::with([plugin("pass")]);
        let err = vhs_with(raw_secret_from(vec!["pass://"]), &reg).unwrap_err();
        assert!(err.contains("empty locator"), "{err}");
    }

    #[test]
    fn a_terse_key_never_resolves_a_plugin_scheme() {
        // a terse `key` pinned to a plugin name is not a plugin binding — it is an unknown
        // resolver binding (terse plugin bindings are deliberately out of scope)
        let reg = PluginRegistry::with([plugin("pass")]);
        let err = validate_host_secret(
            "api.github.com",
            terse("tok@pass"),
            &SecretDefaults::default(),
            &reg,
        )
        .unwrap_err();
        assert!(err.contains("pass"), "{err}");
    }

    #[test]
    fn a_trusted_project_terse_secret_expands_through_global_defaults() {
        // the resolver defaults are global; a trusted project's terse `key` resolves through them
        let global = RawConfig {
            network: allowlist_net(&["api.github.com"]),
            secret: Some(RawSecretSection {
                defaults: Some(raw_defaults(
                    &["sops"],
                    Some("secrets/prod.yaml"),
                    None,
                    None,
                )),
                hosts: BTreeMap::new(),
            }),
            ..RawConfig::default()
        };
        let proj = RawConfig {
            secret: Some(terse_section(
                RawSecretDefaults::default(),
                "api.github.com",
                "gh_token",
            )),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
        assert_eq!(r.secrets.len(), 1);
        assert_eq!(
            r.secrets[0].sources,
            vec![SecretSource::Sops {
                file: "secrets/prod.yaml".into(),
                key: Some("gh_token".into()),
            }]
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    }

    #[test]
    fn a_trusted_project_overrides_a_global_default_binding() {
        // global points sops at prod; the project, with an empty order (inherited), overrides the
        // sops file to staging — the project's binding wins, the order is inherited
        let global = RawConfig {
            network: allowlist_net(&["api.github.com"]),
            secret: Some(RawSecretSection {
                defaults: Some(raw_defaults(&["sops"], Some("prod.yaml"), None, None)),
                hosts: BTreeMap::new(),
            }),
            ..RawConfig::default()
        };
        let proj = RawConfig {
            secret: Some(terse_section(
                raw_defaults(&[], Some("staging.yaml"), None, None),
                "api.github.com",
                "tok",
            )),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
        assert_eq!(
            r.secrets[0].sources,
            vec![SecretSource::Sops {
                file: "staging.yaml".into(),
                key: Some("tok".into()),
            }]
        );
    }

    #[test]
    fn an_untrusted_project_secret_section_steers_nothing() {
        // neither an explicit `sops://` source nor the terse `key` + `[secret.defaults]` is honored
        // from an untrusted project: the whole section — defaults included — is dropped, so it can
        // neither inject a credential nor redirect a secret's source.
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let mut hosts = BTreeMap::new();
            hosts.insert(
                "api.github.com".to_string(),
                RawHostSecrets::One(RawHostSecret {
                    kind: None,
                    key: None,
                    from: Some(SecretFrom::One("sops://prod.yaml#tok".into())),
                    header: Some("Authorization".into()),
                    value_type: Some("bearer".into()),
                    prefix: None,
                }),
            );
            hosts.insert(
                "api2.example.com".to_string(),
                RawHostSecrets::One(terse("demo_key")),
            );
            let proj = RawConfig {
                secret: Some(RawSecretSection {
                    defaults: Some(raw_defaults(
                        &["env", "sops"],
                        Some("prod.yaml"),
                        None,
                        None,
                    )),
                    hosts,
                }),
                ..RawConfig::default()
            };
            let global = RawConfig {
                network: allowlist_net(&["api.github.com", "api2.example.com"]),
                ..RawConfig::default()
            };
            let r = resolve_no_plugins(global, Some((proj, state)));
            assert!(
                r.secrets.is_empty(),
                "an untrusted project may not inject or redirect"
            );
            assert!(
                r.warnings
                    .iter()
                    .any(|w| w.contains("ignoring 2 secret(s)")),
                "{:?}",
                r.warnings
            );
        }
    }

    #[test]
    fn two_headers_to_one_host_both_survive() {
        // the array form (`[[secret."host"]]`) keeps several credentials for one host: a different
        // header is not a duplicate, so both are kept
        let r = resolve_no_plugins(
            raw_secrets(
                &["api.github.com"],
                vec![
                    raw_secret(
                        Some("A"),
                        None,
                        "api.github.com",
                        "Authorization",
                        Some("bearer"),
                        None,
                    ),
                    raw_secret(
                        Some("B"),
                        None,
                        "api.github.com",
                        "X-Api-Key",
                        Some("raw"),
                        None,
                    ),
                ],
            ),
            None,
        );
        assert_eq!(
            r.secrets.len(),
            2,
            "different headers to one host both survive"
        );
    }

    // --- default `header` / `type` in `[secret.defaults]` -------------------------------------

    /// `[secret.defaults]` with a default header + type, plus the given resolver order/sops file.
    fn defaults_with_shape(order: &[&str], sops_file: Option<&str>) -> RawSecretDefaults {
        let mut d = raw_defaults(order, sops_file, None, None);
        d.header = Some("Authorization".into());
        d.value_type = Some("bearer".into());
        d
    }

    #[test]
    fn a_terse_entry_inherits_the_default_header_and_type() {
        let d = SecretDefaults::from_raw(&defaults_with_shape(&["sops"], Some("prod.yaml")));
        let s = vhs("api.github.com", terse_bare("gh_token"), &d).unwrap();
        assert_eq!(s.header, "Authorization");
        assert_eq!(s.shape.format("abc"), "Bearer abc");
        assert_eq!(
            s.sources,
            vec![SecretSource::Sops {
                file: "prod.yaml".into(),
                key: Some("gh_token".into()),
            }]
        );
    }

    #[test]
    fn a_per_secret_header_and_type_override_the_defaults() {
        let d = SecretDefaults::from_raw(&defaults_with_shape(&["sops"], Some("prod.yaml")));
        let mut secret = terse_bare("k");
        secret.header = Some("X-Api-Key".into());
        secret.value_type = Some("raw".into());
        let s = vhs("h.test", secret, &d).unwrap();
        assert_eq!(
            s.header, "X-Api-Key",
            "the entry's header wins over the default"
        );
        assert_eq!(s.shape.format("abc"), "abc", "the entry's raw type wins");
    }

    #[test]
    fn neither_a_secret_nor_a_default_header_is_an_error() {
        // no `header` on the entry and none in the defaults — the same explicit error as before,
        // never a silent built-in default
        let d = SecretDefaults::from_raw(&raw_defaults(&["sops"], Some("p.yaml"), None, None));
        let err = vhs("h.test", terse_bare("k"), &d).unwrap_err();
        assert!(err.contains("set `header`"), "{err}");
    }

    #[test]
    fn neither_a_secret_nor_a_default_type_is_an_error() {
        // header is supplied by the defaults but type is set nowhere — still an explicit error
        let mut raw = raw_defaults(&["sops"], Some("p.yaml"), None, None);
        raw.header = Some("Authorization".into());
        let d = SecretDefaults::from_raw(&raw);
        let err = vhs("h.test", terse_bare("k"), &d).unwrap_err();
        assert!(err.contains("missing `type`"), "{err}");
    }

    #[test]
    fn a_default_header_collapses_array_entries_that_omit_it() {
        // the sharp edge: two `[[secret."host"]]` entries that both inherit the default header
        // collapse on `(host, header)` to the last one (with a warning) — fail-closed, never two
        // silent header copies upstream
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "api.github.com".to_string(),
            RawHostSecrets::Many(vec![terse_bare("a"), terse_bare("b")]),
        );
        let global = RawConfig {
            network: allowlist_net(&["api.github.com"]),
            secret: Some(RawSecretSection {
                defaults: Some(defaults_with_shape(&["sops"], Some("prod.yaml"))),
                hosts,
            }),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, None);
        assert_eq!(
            r.secrets.len(),
            1,
            "entries that both inherit the default header collapse to one"
        );
        assert!(r.warnings.iter().any(|w| w.contains("overrides")));
        assert_eq!(
            r.secrets[0].sources,
            vec![SecretSource::Sops {
                file: "prod.yaml".into(),
                key: Some("b".into()),
            }],
            "last wins"
        );
    }

    #[test]
    fn a_global_default_header_and_type_reach_a_project_through_merge() {
        // global sets the default header/type; a trusted project that declares its OWN
        // `[secret.defaults]` (so `merged_with` runs) but omits header/type inherits them, while a
        // per-entry header still wins after the merge — pins both merged_with header/type lines.
        let global = RawConfig {
            network: allowlist_net(&["a.test", "b.test"]),
            secret: Some(RawSecretSection {
                defaults: Some(defaults_with_shape(&["sops"], Some("prod.yaml"))),
                hosts: BTreeMap::new(),
            }),
            ..RawConfig::default()
        };
        let mut hosts = BTreeMap::new();
        // inherits the global default header *and* type through the merge
        hosts.insert("a.test".to_string(), RawHostSecrets::One(terse_bare("ka")));
        // overrides the header per-entry, after the merge
        let mut overriding = terse_bare("kb");
        overriding.header = Some("X-Api-Key".into());
        hosts.insert("b.test".to_string(), RawHostSecrets::One(overriding));
        let proj = RawConfig {
            // the project's own defaults set only the order, so header/type come from the global
            secret: Some(RawSecretSection {
                defaults: Some(raw_defaults(&["sops"], Some("prod.yaml"), None, None)),
                hosts,
            }),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
        assert_eq!(r.secrets.len(), 2);
        let a = r
            .secrets
            .iter()
            .find(|s| s.header == "Authorization")
            .expect("a.test inherits the global default header through the merge");
        assert_eq!(
            a.shape.format("x"),
            "Bearer x",
            "and the global default type"
        );
        assert!(
            r.secrets.iter().any(|s| s.header == "X-Api-Key"),
            "a per-entry header still wins after the merge"
        );
    }

    #[test]
    fn a_trusted_project_header_secret_is_honored() {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw_secrets(
                    &["api.github.com"],
                    vec![raw_secret(
                        Some("GH_TOKEN"),
                        None,
                        "api.github.com",
                        "Authorization",
                        Some("bearer"),
                        None,
                    )],
                ),
                TrustState::Trusted,
            )),
        );
        assert_eq!(r.secrets.len(), 1);
        let s = &r.secrets[0];
        assert_eq!(s.sources, vec![SecretSource::Env("GH_TOKEN".into())]);
        assert_eq!(s.header, "Authorization");
        assert_eq!(s.to, crate::allowlist::classify("api.github.com").unwrap());
        assert_eq!(s.shape.format("abc"), "Bearer abc");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_global_secret_is_honored_by_location() {
        let r = resolve_no_plugins(
            raw_secrets(
                &["api.github.com"],
                vec![raw_secret(
                    Some("GH_TOKEN"),
                    None,
                    "api.github.com",
                    "Authorization",
                    Some("bearer"),
                    None,
                )],
            ),
            None,
        );
        assert_eq!(r.secrets.len(), 1);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_secret_is_dropped_with_a_warning() {
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let r = resolve_no_plugins(
                RawConfig::default(),
                Some((
                    raw_secrets(
                        &["api.github.com"],
                        vec![raw_secret(
                            Some("GH"),
                            None,
                            "api.github.com",
                            "Authorization",
                            Some("bearer"),
                            None,
                        )],
                    ),
                    state,
                )),
            );
            assert!(
                r.secrets.is_empty(),
                "an untrusted project may not inject credentials"
            );
            assert!(r.warnings.iter().any(|w| w.contains("secret")));
        }
    }

    #[test]
    fn a_secret_without_an_allowlist_is_dropped_with_a_warning() {
        // a secret declared while the network stays shared (no filtering proxy) has
        // nowhere to inject; it is cleared with a warning, never a silent no-op.
        let r = resolve_no_plugins(
            RawConfig {
                secret: Some(raw_secret_section(vec![raw_secret(
                    Some("GH"),
                    None,
                    "api.github.com",
                    "Authorization",
                    Some("bearer"),
                    None,
                )])),
                ..RawConfig::default()
            },
            None,
        );
        assert!(r.secrets.is_empty());
        assert_eq!(r.network, NetworkPolicy::Shared);
        assert!(r
            .warnings
            .iter()
            .any(|w| w.contains("requires") && w.contains("filtering")));
    }

    #[test]
    fn a_wildcard_or_regex_secret_target_is_rejected() {
        for to in ["*.github.com", "re:^https://api\\.github\\.com/"] {
            let r = resolve_no_plugins(
                raw_secrets(
                    &["api.github.com"],
                    vec![raw_secret(
                        Some("GH"),
                        None,
                        to,
                        "Authorization",
                        Some("bearer"),
                        None,
                    )],
                ),
                None,
            );
            assert!(r.secrets.is_empty(), "{to} must be rejected as a target");
            assert!(r.warnings.iter().any(|w| w.contains("concrete host")));
        }
    }

    #[test]
    fn a_missing_or_unknown_secret_type_is_rejected() {
        let missing = resolve_no_plugins(
            raw_secrets(
                &["api.github.com"],
                vec![raw_secret(
                    Some("GH"),
                    None,
                    "api.github.com",
                    "Authorization",
                    None,
                    None,
                )],
            ),
            None,
        );
        assert!(missing.secrets.is_empty());
        assert!(missing
            .warnings
            .iter()
            .any(|w| w.contains("missing `type`")));

        let unknown = resolve_no_plugins(
            raw_secrets(
                &["api.github.com"],
                vec![raw_secret(
                    Some("GH"),
                    None,
                    "api.github.com",
                    "Authorization",
                    Some("digest"),
                    None,
                )],
            ),
            None,
        );
        assert!(unknown.secrets.is_empty());
        assert!(unknown
            .warnings
            .iter()
            .any(|w| w.contains("unknown `type`")));
    }

    #[test]
    fn a_secret_with_no_source_is_dropped_with_a_warning() {
        let r = resolve_no_plugins(
            raw_secrets(
                &["h.test"],
                vec![raw_secret(None, None, "h.test", "H", Some("raw"), None)],
            ),
            None,
        );
        assert!(r.secrets.is_empty());
        assert!(r.warnings.iter().any(|w| w.contains("needs a source")));
    }

    #[test]
    fn a_duplicate_target_header_secret_is_last_wins_with_a_warning() {
        let r = resolve_no_plugins(
            raw_secrets(
                &["h.test"],
                vec![
                    raw_secret(
                        Some("FIRST"),
                        None,
                        "h.test",
                        "Authorization",
                        Some("raw"),
                        None,
                    ),
                    // same host, same header (different case) — collapses to the later one
                    raw_secret(
                        Some("SECOND"),
                        None,
                        "h.test",
                        "authorization",
                        Some("raw"),
                        None,
                    ),
                ],
            ),
            None,
        );
        assert_eq!(
            r.secrets.len(),
            1,
            "a duplicate (host, header) collapses to one"
        );
        assert_eq!(
            r.secrets[0].sources,
            vec![SecretSource::Env("SECOND".into())],
            "last wins"
        );
        assert!(r.warnings.iter().any(|w| w.contains("overrides")));
    }

    #[test]
    fn a_non_absolute_from_file_is_rejected() {
        let r = resolve_no_plugins(
            raw_secrets(
                &["h.test"],
                vec![raw_secret(
                    None,
                    Some("relative/tok"),
                    "h.test",
                    "H",
                    Some("raw"),
                    None,
                )],
            ),
            None,
        );
        assert!(r.secrets.is_empty());
        assert!(r.warnings.iter().any(|w| w.contains("absolute path")));
    }

    #[test]
    fn an_unknown_secret_kind_and_a_bad_header_name_are_rejected() {
        let mut bad_kind = raw_secret(Some("X"), None, "h.test", "H", Some("raw"), None);
        bad_kind.1.kind = Some("ssh-agent".into());
        let r = resolve_no_plugins(raw_secrets(&["h.test"], vec![bad_kind]), None);
        assert!(r.secrets.is_empty());
        assert!(r.warnings.iter().any(|w| w.contains("unknown kind")));

        let r = resolve_no_plugins(
            raw_secrets(
                &["h.test"],
                vec![raw_secret(
                    Some("X"),
                    None,
                    "h.test",
                    "Bad: Header",
                    Some("raw"),
                    None,
                )],
            ),
            None,
        );
        assert!(r.secrets.is_empty());
        assert!(r.warnings.iter().any(|w| w.contains("`header`")));
    }

    #[test]
    fn header_shape_formats_each_type_and_prefix() {
        let shape = |ty, prefix| validate_header_shape(Some(ty), prefix).unwrap();
        assert_eq!(shape("bearer", None).format("tok"), "Bearer tok");
        assert_eq!(shape("raw", None).format("tok"), "tok");
        assert_eq!(shape("raw", Some("token ")).format("tok"), "token tok");
        assert_eq!(
            shape("bearer", Some("token ")).format("tok"),
            "token tok",
            "an explicit prefix overrides the type default"
        );
        // basic base64s a user:pass pair under the "Basic " prefix
        assert_eq!(
            shape("basic", None).format("user:pass"),
            "Basic dXNlcjpwYXNz"
        );
    }

    #[test]
    fn base64_encode_matches_rfc_4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), want, "base64({input:?})");
        }
    }
}
