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

pub(crate) mod safety;
mod schema;

use crate::allowlist::Rule;
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

/// A tool the configuration asks the sandbox to provide: a free `name` (the merge
/// key across layers and the on-disk root name) bound to a nixpkgs `attr` to
/// realise. Each carries whether the layer that supplied its value is trusted, so
/// the launcher can decide — outside this pure layering — whether to provision it.
/// Realising a tool is a security-relevant act (it can run a build), but the
/// decision is *deferred*, not made here: this stage drops nothing for trust, it
/// only records the verdict the launcher will weigh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Package {
    /// The free label: merge key and on-disk root name.
    pub(crate) name: String,
    /// The nixpkgs attribute to realise.
    pub(crate) attr: String,
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

/// The resolved configuration the launcher applies: the layered environment and
/// the read-only host binds, the declared tools, plus any warnings worth surfacing
/// (dropped fields, an unparseable or unsafe file). Nothing here is a hard error —
/// a missing or broken config yields empty defaults, never a failed launch.
pub(crate) struct Resolved {
    /// Extra environment, in application order; a later entry overrides an earlier
    /// one at the same key.
    pub(crate) env: Vec<(String, String)>,
    /// Extra host paths to bind read-only.
    pub(crate) ro_binds: Vec<PathBuf>,
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
    /// Credentials the egress proxy injects into matching requests (the plaintext never
    /// enters the cage). A security field, gated like `binds`; cleared with a warning
    /// unless the posture is an allowlist, since the filtering proxy is what injects them.
    pub(crate) secrets: Vec<HeaderSecret>,
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
    /// Credentials to inject for this app (gated; the plaintext never enters the cage).
    pub(crate) secrets: Vec<HeaderSecret>,
    /// Notes about what this app's resolution dropped or ignored — surfaced when the app is
    /// launched, not on every `ops run`.
    pub(crate) warnings: Vec<String>,
}

impl Resolved {
    /// Fold an app's overlay onto this baseline with precedence **app > baseline**: the
    /// app's environment upserts over the baseline's, its packages override by name, its
    /// binds and credentials add, and its network posture (when it set one) replaces the
    /// baseline's. Every value was gated at resolve time, so this is a pure merge — no
    /// re-gating. The secret-vs-posture consistency is re-checked at the end, since the
    /// overlay can add secrets or change the posture.
    pub(crate) fn merge_app(&mut self, app: ResolvedApp) {
        for (key, val) in app.env {
            upsert(&mut self.env, key, val);
        }
        for pkg in app.packages {
            upsert_package(&mut self.packages, pkg.name, pkg.attr, pkg.state);
        }
        for bind in app.ro_binds {
            if !self.ro_binds.contains(&bind) {
                self.ro_binds.push(bind);
            }
        }
        if let Some(network) = app.network {
            self.network = network;
        }
        self.secrets.extend(app.secrets);
        self.warnings.extend(app.warnings);
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
    let mut binds: Vec<PathBuf> = Vec::new();
    let mut packages: Vec<Package> = Vec::new();
    let mut secrets: Vec<HeaderSecret> = Vec::new();

    // The global config is trusted by location, so it is honored in full: no
    // denylist, only key validation and the absolute-bind requirement.
    apply_env(&mut env, &mut warnings, GLOBAL_CONFIG, global.env, false);
    apply_binds(&mut binds, &mut warnings, GLOBAL_CONFIG, global.binds);
    apply_packages(
        &mut packages,
        &mut warnings,
        GLOBAL_CONFIG,
        global.packages,
        TrustState::Trusted,
    );
    let nixpkgs_global = global
        .nixpkgs
        .and_then(|v| validate_nixpkgs(&mut warnings, GLOBAL_CONFIG, v));
    // The network posture is trusted by location at the global layer; an invalid or
    // unset value falls back to the default (shared).
    let mut network = global
        .network
        .and_then(|v| validate_network(&mut warnings, GLOBAL_CONFIG, v))
        .unwrap_or_default();
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
        apply_env(&mut env, &mut warnings, PROJECT_CONFIG, proj.env, !trusted);
        // `binds` is a security field — honored only from a trusted project.
        if !proj.binds.is_empty() {
            if trusted {
                apply_binds(&mut binds, &mut warnings, PROJECT_CONFIG, proj.binds);
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
                if let Some(policy) = validate_network(&mut warnings, PROJECT_CONFIG, value) {
                    network = policy;
                }
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring `network` policy ({})",
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
        ro_binds: binds,
        packages,
        nixpkgs_global,
        nixpkgs_project,
        // A mise file is discovered by I/O in `load`; the pure layering never sees one.
        mise: None,
        network,
        secrets,
        apps,
        warnings,
    }
}

/// Clear injected credentials unless the posture is an allowlist. Injection is performed by
/// the filtering proxy, which exists only under a network allowlist; under `shared` (no
/// proxy) or `none` (no traffic) there is nowhere to inject, so the secrets are cleared with
/// a loud warning rather than left as a no-op the user mistakes for working injection. (The
/// plaintext is never read, so dropping is fail-safe.) Shared by the baseline resolution and
/// the per-app overlay, which can add secrets or change the posture.
fn enforce_secret_posture(
    network: &NetworkPolicy,
    secrets: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
) {
    if !secrets.is_empty() && !matches!(network, NetworkPolicy::Allowlist(_)) {
        warnings.push(format!(
            "ignoring {} HTTP-header secret(s): credential injection requires \
             `[network] mode = \"allowlist\"` (the filtering proxy that injects them)",
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
/// persistent home directory). Restricted to a conservative charset and length, and `.`/`..`
/// are rejected outright so a name can never traverse out of the data directory.
fn is_valid_app_name(name: &str) -> bool {
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

    // The global layer — trusted by location, honored in full.
    if let Some(app) = global {
        let source = app_source(GLOBAL_CONFIG, name);
        apply_env(&mut env, &mut warnings, &source, app.env, false);
        apply_binds(&mut ro_binds, &mut warnings, &source, app.binds);
        apply_packages(
            &mut packages,
            &mut warnings,
            &source,
            app.packages,
            TrustState::Trusted,
        );
        if let Some(field) = app.network {
            network = validate_network(&mut warnings, &source, field);
        }
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
        }
        if let Some(raw) = app.home_scope {
            if let Some(scope) = validate_home_scope(&mut warnings, &source, &raw) {
                home_scope = scope;
                home_scope_trusted = true;
            }
        }
    }

    // The project layer — gated by the project's verdict, overriding the global per field.
    if let Some((app, state)) = project {
        let trusted = state == TrustState::Trusted;
        let source = app_source(PROJECT_CONFIG, name);
        apply_env(&mut env, &mut warnings, &source, app.env, !trusted);
        if !app.binds.is_empty() {
            if trusted {
                apply_binds(&mut ro_binds, &mut warnings, &source, app.binds);
            } else {
                warnings.push(dropped_binds_warning(state, app.binds.len()));
            }
        }
        apply_packages(&mut packages, &mut warnings, &source, app.packages, state);
        if let Some(field) = app.network {
            if trusted {
                if let Some(policy) = validate_network(&mut warnings, &source, field) {
                    network = Some(policy);
                }
            } else {
                warnings.push(format!(
                    "{source}: ignoring `network` policy ({})",
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
        secrets,
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
        upsert(out, key, val);
    }
}

/// Fold a layer's binds into `out`, requiring each to be an absolute path. A
/// relative bind is dropped with a warning: the project is already mounted in
/// full, so an extra bind is by definition an out-of-project path, and resolving a
/// relative one against the working directory would be a surprise.
fn apply_binds(
    out: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
    source: &str,
    binds: Vec<String>,
) {
    for b in binds {
        let p = PathBuf::from(&b);
        if p.is_absolute() {
            out.push(p);
        } else {
            warnings.push(format!("{source}: ignoring non-absolute bind `{b}`"));
        }
    }
}

/// Fold a layer's packages into `out`, validating the label and the attribute and
/// stamping each with whether its source layer is trusted. A later layer overrides
/// an earlier one at the same name, so a project can pin a tool the global set
/// named. Nothing is dropped for trust here — that belongs to the launcher; this is
/// a pure merge. A malformed label or attribute *is* dropped (with a warning): it
/// could never realise, and a label names an on-disk path.
fn apply_packages(
    out: &mut Vec<Package>,
    warnings: &mut Vec<String>,
    source: &str,
    packages: BTreeMap<String, String>,
    state: TrustState,
) {
    for (name, attr) in packages {
        if !is_valid_package_name(&name) {
            warnings.push(format!(
                "{source}: ignoring malformed package name `{name}`"
            ));
            continue;
        }
        if !is_valid_attr(&attr) {
            warnings.push(format!(
                "{source}: ignoring package `{name}` with invalid attribute `{attr}`"
            ));
            continue;
        }
        upsert_package(out, name, attr, state);
    }
}

/// Set the package named `name` to `attr` with the supplying layer's trust,
/// overriding an existing entry so a later layer wins while preserving declaration
/// order.
fn upsert_package(out: &mut Vec<Package>, name: String, attr: String, state: TrustState) {
    match out.iter_mut().find(|p| p.name == name) {
        Some(slot) => {
            slot.attr = attr;
            slot.state = state;
        }
        None => out.push(Package { name, attr, state }),
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
            other => {
                warnings.push(format!(
                    "{source_label}: ignoring unknown network policy `{other}` \
                     (expected \"none\", \"shared\", or an `[network]` allowlist table)"
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
        "allowlist" => {
            let allow = classify_entries(warnings, source_label, "allow", table.allow);
            let deny = classify_entries(warnings, source_label, "deny", table.deny);
            Some(NetworkPolicy::Allowlist(
                crate::allowlist::EgressPolicy::new(allow, deny),
            ))
        }
        other => {
            warnings.push(format!(
                "{source_label}: ignoring unknown network mode `{other}` \
                 (expected \"none\", \"shared\", or \"allowlist\")"
            ));
            None
        }
    }
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
    match rule {
        Rule::Ip(..) | Rule::Host(..) | Rule::Url { .. } => Ok(rule),
        Rule::Subdomain(..) => Err(format!(
            "`to` must be a concrete host, not the `*.` wildcard `{to}` \
             (a credential is sent to one known host)"
        )),
        Rule::Regex { .. } => Err(format!(
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

/// Load and resolve the configuration for a project rooted at `cwd`. Infallible by
/// design: every failure mode (absent, unsafe, unparseable, no trust store)
/// degrades to a warning and a dropped layer, so a command is never blocked by a
/// bad config — least of all an attacker-controlled project one.
pub(crate) fn load(cwd: &Path) -> Resolved {
    let mut warnings = Vec::new();
    let global = read_global(&mut warnings);
    let project = read_project(cwd, &mut warnings);

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
    let declared = std::mem::take(&mut resolved.ro_binds);
    resolved.ro_binds = canonicalize_binds(declared, &mut resolved.warnings);

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

/// Canonicalize each bind source, dropping with a warning any that cannot be
/// resolved (a missing path or a broken symlink) — bwrap could not bind it anyway.
fn canonicalize_binds(binds: Vec<PathBuf>, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    binds
        .into_iter()
        .filter_map(|p| match p.canonicalize() {
            Ok(canon) => Some(canon),
            Err(e) => {
                warnings.push(format!("ignoring bind {}: {e}", p.display()));
                None
            }
        })
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
                    "found a mise file ({name}) but no {PROJECT_CONFIG}: mise is anchored on \
                     {PROJECT_CONFIG} — add one (it may be empty) to enable it"
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

#[cfg(test)]
mod tests {
    use super::schema::{RawEnvDefaults, RawFileDefaults, RawSecretSection, RawSopsDefaults};
    use super::*;
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
            secret: None,
            app: BTreeMap::new(),
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
            })),
            ..RawConfig::default()
        }
    }

    /// A `RawConfig` declaring only an allow list (no deny).
    fn raw_network_allow(allow: &[&str]) -> RawConfig {
        raw_network_table(allow, &[])
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
            secret: None,
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
            "claude",
            raw_app(
                &["claude"],
                &[("BASE", "g")],
                &[],
                &[("tool", "ripgrep")],
                None,
            ),
        );
        let project = raw_with_app(
            "claude",
            raw_app(&["claude", "--resume"], &[("EXTRA", "p")], &[], &[], None),
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
        let app = &r.apps["claude"];
        // The project's command wins; the global one is replaced, not appended.
        assert_eq!(app.cmd, vec!["claude".to_string(), "--resume".to_string()]);
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
                &[("pkg", "ripgrep")],
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
    fn a_global_apps_network_survives_an_untrusted_projects_override_attempt() {
        // A globally-declared app keeps its posture even when launched under an untrusted
        // project — the flagship use case: run an agent *on* untrusted code, safely.
        let global = raw_with_app(
            "claude",
            raw_app(
                &["claude"],
                &[],
                &[],
                &[],
                allowlist_net(&["api.anthropic.com"]),
            ),
        );
        let mut widen = raw_app(&[], &[], &[], &[], None);
        widen.network = Some(NetworkField::Posture("shared".into()));
        let project = raw_with_app("claude", widen);
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["claude"];
        assert!(matches!(app.network, Some(NetworkPolicy::Allowlist(_))));
        assert!(app.warnings.iter().any(|w| w.contains("network")));
    }

    #[test]
    fn an_app_home_scope_defaults_to_global_and_a_trusted_layer_may_set_project() {
        // Unset → the global default. A trusted layer (here the global config) may pin it.
        let plain = raw_with_app("claude", raw_app(&["claude"], &[], &[], &[], None));
        let r = resolve_no_plugins(plain, None);
        assert_eq!(r.apps["claude"].home_scope, AppHomeScope::Global);

        let scoped = raw_with_app(
            "review",
            RawApp {
                home_scope: Some("project".into()),
                ..raw_app(&["claude"], &[], &[], &[], None)
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
            "claude",
            RawApp {
                home_scope: Some("project".into()),
                ..raw_app(&["claude"], &[], &[], &[], None)
            },
        );
        let project = raw_with_app(
            "claude",
            RawApp {
                home_scope: Some("global".into()),
                ..raw_app(&[], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
        let app = &r.apps["claude"];
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
    fn an_unknown_home_scope_defaults_to_global_with_a_warning() {
        let global = raw_with_app(
            "claude",
            RawApp {
                home_scope: Some("frobnicate".into()),
                ..raw_app(&["claude"], &[], &[], &[], None)
            },
        );
        let r = resolve_no_plugins(global, None);
        let app = &r.apps["claude"];
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
        assert!(is_valid_app_name("claude"));
        assert!(is_valid_app_name("opencode-2.dev_x"));
    }

    #[test]
    fn merge_app_overlays_the_baseline_with_app_precedence() {
        let mut base = resolve_no_plugins(raw(&[("A", "base"), ("B", "base")], &[]), None);
        let app = ResolvedApp {
            cmd: vec!["x".into()],
            home_scope: AppHomeScope::Global,
            env: vec![("A".into(), "app".into()), ("C".into(), "app".into())],
            ro_binds: vec![],
            packages: vec![],
            network: Some(NetworkPolicy::Isolated),
            secrets: vec![],
            warnings: vec![],
        };
        base.merge_app(app);
        // App env wins on a collision; baseline-only and app-only keys both survive.
        assert!(base.env.iter().any(|(k, v)| k == "A" && v == "app"));
        assert!(base.env.iter().any(|(k, v)| k == "B" && v == "base"));
        assert!(base.env.iter().any(|(k, v)| k == "C" && v == "app"));
        // The app's posture replaces the baseline's.
        assert!(matches!(base.network, NetworkPolicy::Isolated));
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
            secrets: vec![a_header_secret()],
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
            secrets: vec![a_header_secret()],
            warnings: vec![],
        };
        base.merge_app(app);
        assert_eq!(base.secrets.len(), 1);
        assert!(matches!(base.network, NetworkPolicy::Allowlist(_)));
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
        let r = resolve_no_plugins(raw_packages(&[("node", "nodejs_20")]), None);
        let node = pkg(&r.packages, "node").expect("global package present");
        assert_eq!(node.attr, "nodejs_20");
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
            raw_packages(&[("node", "nodejs_20"), ("onlyg", "ripgrep")]),
            Some((raw_packages(&[("node", "nodejs_22")]), TrustState::Trusted)),
        );
        // the project pins the shared name; the global-only tool survives
        let node = pkg(&r.packages, "node").unwrap();
        assert_eq!(node.attr, "nodejs_22");
        assert_eq!(node.state, TrustState::Trusted);
        assert_eq!(pkg(&r.packages, "onlyg").unwrap().attr, "ripgrep");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn an_untrusted_project_package_is_carried_but_flagged_untrusted() {
        // The launcher, not this stage, decides admission — so the package is kept,
        // stamped with its source's trust, with no drop and no warning here.
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw_packages(&[("node", "nodejs_20")]),
                TrustState::Untrusted,
            )),
        );
        let node = pkg(&r.packages, "node").expect("untrusted package still carried");
        assert_eq!(node.attr, "nodejs_20");
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
            Some((raw_packages(&[("node", "nodejs_20")]), TrustState::Changed)),
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
    fn a_malformed_package_name_or_attribute_is_dropped() {
        let r = resolve_no_plugins(
            raw_packages(&[
                ("../escape", "hello"), // label escapes its directory
                ("ok", "bad attr!"),    // attribute carries an illegal character
                ("node", "nodejs_20"),  // the well-formed one survives
            ]),
            None,
        );
        assert!(pkg(&r.packages, "../escape").is_none());
        assert!(pkg(&r.packages, "ok").is_none());
        assert_eq!(pkg(&r.packages, "node").unwrap().attr, "nodejs_20");
        assert_eq!(r.warnings.len(), 2, "one warning per dropped package");
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
                "api.openai.com".to_string(),
                RawHostSecrets::One(terse("openai_key")),
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
                network: allowlist_net(&["api.github.com", "api.openai.com"]),
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
            .any(|w| w.contains("requires") && w.contains("allowlist")));
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
