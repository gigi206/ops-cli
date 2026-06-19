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
use crate::trust::{self, TrustState};
use schema::{NetworkField, NetworkTable, RawConfig, RawSecret};
use std::collections::BTreeMap;
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
    /// Where ops reads the plaintext at launch — host-side, never inside the cage.
    pub(crate) source: SecretSource,
    /// The concrete host (and optional path) the injection is scoped to: a request to
    /// anything else never receives the header. A `*.` wildcard or `re:` regex is
    /// rejected at validation, so a credential reaches exactly one known destination.
    pub(crate) to: Rule,
    /// The header name to set, e.g. `Authorization`.
    pub(crate) header: String,
    /// How the plaintext becomes the header value.
    pub(crate) shape: HeaderShape,
}

/// Where ops reads a secret's plaintext, host-side at launch. Exactly one form per
/// secret. Only the locator is kept here — never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretSource {
    /// A host environment variable, by name (not its value).
    Env(String),
    /// An absolute host file path, read host-side and never bound into the cage.
    File(PathBuf),
}

impl SecretSource {
    /// A human label for `ops config` — the variable name or the file path, neither of
    /// which is the secret itself.
    pub(crate) fn describe(&self) -> String {
        match self {
            SecretSource::Env(var) => format!("env {var}"),
            SecretSource::File(path) => format!("file {}", path.display()),
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
    /// Human-readable notes about what was dropped or ignored and why.
    pub(crate) warnings: Vec<String>,
}

/// Layer the global config (trusted by location) under the project config, gating
/// the project's security-relevant fields by its trust verdict. Pure: the policy
/// matrix is decided here from already-read inputs.
///
/// Free fields (`env`) apply from any project, minus the reserved-key denylist for
/// an untrusted one. Security fields (`binds`) apply only from a trusted project;
/// an untrusted or since-changed project's binds are dropped with a warning.
fn resolve(global: RawConfig, project: Option<(RawConfig, TrustState)>) -> Resolved {
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
    // Secrets are trusted by location at the global layer.
    apply_secrets(&mut secrets, &mut warnings, GLOBAL_CONFIG, global.secret);

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
        // `[[secret]]` is a security field — a trusted project may inject credentials;
        // an untrusted or changed one may not (it would aim the user's secrets at a host
        // of its choosing). The whole list is dropped, with one count warning.
        if !proj.secret.is_empty() {
            if trusted {
                apply_secrets(&mut secrets, &mut warnings, PROJECT_CONFIG, proj.secret);
            } else {
                warnings.push(format!(
                    "{PROJECT_CONFIG}: ignoring {} secret(s) ({})",
                    proj.secret.len(),
                    untrusted_reason(state)
                ));
            }
        }
    }

    // Credential injection is performed by the filtering proxy, which exists only under a
    // network allowlist. Under `shared` (no proxy) or `none` (no traffic) there is nowhere
    // to inject, so the secrets are cleared rather than silently ignored — a loud warning,
    // never a no-op the user mistakes for working injection. (The plaintext is never read,
    // so dropping is fail-safe.)
    if !secrets.is_empty() && !matches!(network, NetworkPolicy::Allowlist(_)) {
        warnings.push(format!(
            "ignoring {} HTTP-header secret(s): credential injection requires \
             `[network] mode = \"allowlist\"` (the filtering proxy that injects them)",
            secrets.len()
        ));
        secrets.clear();
    }

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
        warnings,
    }
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

/// Validate and fold a layer's `[[secret]]` declarations into `out`. Each entry is fully
/// validated (kind, source, target, header, type); a malformed one is dropped with a
/// warning — fail-closed, since a credential injection is security-relevant. A later entry
/// for the same (target, header) overrides an earlier one (last-wins) with a warning, so a
/// duplicate destination never silently emits two header copies upstream.
fn apply_secrets(
    out: &mut Vec<HeaderSecret>,
    warnings: &mut Vec<String>,
    source: &str,
    secrets: Vec<RawSecret>,
) {
    for raw in secrets {
        match validate_secret(raw) {
            Ok(secret) => upsert_secret(out, warnings, source, secret),
            Err(e) => warnings.push(format!("{source}: ignoring secret — {e}")),
        }
    }
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

/// Validate one `[[secret]]` into a [`HeaderSecret`], or report why it is malformed. Every
/// check fails closed: an unknown kind, an ambiguous or missing source, a non-concrete
/// target, a bad header name, or a missing/unknown type each drops the secret.
fn validate_secret(raw: RawSecret) -> Result<HeaderSecret, String> {
    if raw.kind != "http-header" {
        return Err(format!(
            "unknown kind `{}` (the only secret kind today is \"http-header\")",
            raw.kind
        ));
    }
    let source = validate_secret_source(&raw)?;
    let to = validate_secret_target(&raw.to)?;
    validate_header_name(&raw.header)?;
    let shape = validate_header_shape(raw.value_type.as_deref(), raw.prefix.as_deref())?;
    Ok(HeaderSecret {
        source,
        to,
        header: raw.header,
        shape,
    })
}

/// The source for a secret: exactly one of `from_env` (a variable name) or `from_file`
/// (an absolute host path). Both-set or neither-set is rejected — an ambiguous source must
/// never silently pick one. The value is not read here; that is host-side at launch.
fn validate_secret_source(raw: &RawSecret) -> Result<SecretSource, String> {
    match (raw.from_env.as_deref(), raw.from_file.as_deref()) {
        (Some(_), Some(_)) => {
            Err("set exactly one of `from_env` or `from_file`, not both".to_string())
        }
        (None, None) => Err("set exactly one of `from_env` or `from_file`".to_string()),
        (Some(var), None) => {
            if !is_valid_env_key(var) {
                return Err(format!("`from_env` is not a valid variable name `{var}`"));
            }
            Ok(SecretSource::Env(var.to_string()))
        }
        (None, Some(file)) => {
            let path = PathBuf::from(file);
            if !path.is_absolute() {
                return Err(format!("`from_file` must be an absolute path `{file}`"));
            }
            Ok(SecretSource::File(path))
        }
    }
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
    let (default_prefix, base64) = match value_type {
        Some("bearer") => ("Bearer ", false),
        Some("raw") => ("", false),
        Some("basic") => ("Basic ", true),
        Some(other) => {
            return Err(format!(
                "unknown `type` `{other}` (expected \"bearer\", \"basic\", or \"raw\")"
            ))
        }
        None => return Err("missing `type` (one of \"bearer\", \"basic\", or \"raw\")".to_string()),
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

    let mut resolved = resolve(global, project.map(|(raw, state, _)| (raw, state)));
    resolved.mise = mise;

    // Canonicalize the (already absolute) bind sources, dropping any that cannot be
    // resolved — so `ro_binds` is the *effective* list, identical to what the
    // launch will bind, and `ops config` cannot advertise a bind the launch would
    // silently skip. Following symlinks here also pins each source against a swap.
    let declared = std::mem::take(&mut resolved.ro_binds);
    resolved.ro_binds = canonicalize_binds(declared, &mut resolved.warnings);

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
            secret: Vec::new(),
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

    fn pkg<'a>(packages: &'a [Package], name: &str) -> Option<&'a Package> {
        packages.iter().find(|p| p.name == name)
    }

    fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn global_only_is_honored_in_full() {
        let r = resolve(raw(&[("FOO", "g")], &["/srv/data"]), None);
        assert_eq!(get(&r.env, "FOO"), Some("g"));
        assert_eq!(r.ro_binds, vec![PathBuf::from("/srv/data")]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_trusted_project_overrides_env_and_adds_binds() {
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(
            RawConfig::default(),
            Some((raw(&[], &["/etc/ssh"]), TrustState::Changed)),
        );
        assert!(r.ro_binds.is_empty());
        assert!(r.warnings[0].contains("changed since it was trusted"));
        assert!(r.warnings[0].contains("re-run `ops trust`"));
    }

    #[test]
    fn an_untrusted_project_cannot_set_reserved_env_keys() {
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(raw(&[("A=B", "x"), ("OK", "y")], &[]), None);
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
        let r = resolve(raw_packages(&[("node", "nodejs_20")]), None);
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
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(raw_nixpkgs("nixos-23.11"), None);
        assert_eq!(r.nixpkgs_global.as_deref(), Some("nixos-23.11"));
        assert_eq!(r.nixpkgs_project, None);
        assert!(r.warnings.is_empty());

        // a trusted project sets its own (the launcher prefers it for the tools)
        let r = resolve(
            raw_nixpkgs("nixos-unstable"),
            Some((raw_nixpkgs("nixos-23.11"), TrustState::Trusted)),
        );
        assert_eq!(r.nixpkgs_global.as_deref(), Some("nixos-unstable"));
        assert_eq!(r.nixpkgs_project.as_deref(), Some("nixos-23.11"));
    }

    #[test]
    fn an_untrusted_project_nixpkgs_override_is_dropped_with_a_warning() {
        for state in [TrustState::Untrusted, TrustState::Changed] {
            let r = resolve(
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
        let r = resolve(raw_nixpkgs("github:evil/nixpkgs"), None);
        assert_eq!(r.nixpkgs_global, None);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("malformed nixpkgs source"));
    }

    #[test]
    fn the_default_network_posture_is_shared() {
        // No declared posture anywhere means the host network — the documented
        // default until the egress allowlist ships.
        assert_eq!(
            resolve(RawConfig::default(), None).network,
            NetworkPolicy::Shared
        );
    }

    #[test]
    fn a_global_network_posture_is_honored_a_trusted_project_overrides_it() {
        // global is trusted by location
        let r = resolve(raw_network("none"), None);
        assert_eq!(r.network, NetworkPolicy::Isolated);
        assert!(r.warnings.is_empty());

        // a trusted project sets its own, overriding the global posture
        let r = resolve(
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
            let r = resolve(RawConfig::default(), Some((raw_network("none"), state)));
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
        let r = resolve(
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
        let r = resolve(raw_network("offline"), None);
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
        let r = resolve(
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
            let r = resolve(
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
        let r = resolve(
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
        let r = resolve(
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
        let r = resolve(
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
    ) -> RawSecret {
        RawSecret {
            kind: "http-header".into(),
            from_env: from_env.map(String::from),
            from_file: from_file.map(String::from),
            to: to.into(),
            header: header.into(),
            value_type: ty.map(String::from),
            prefix: prefix.map(String::from),
        }
    }

    /// A `RawConfig` declaring a network allowlist (so secrets are not dropped by the
    /// allowlist dependency) plus the given secrets.
    fn raw_secrets(allow: &[&str], secrets: Vec<RawSecret>) -> RawConfig {
        RawConfig {
            network: Some(NetworkField::Table(NetworkTable {
                mode: "allowlist".into(),
                allow: allow.iter().map(|s| s.to_string()).collect(),
                deny: vec![],
            })),
            secret: secrets,
            ..RawConfig::default()
        }
    }

    #[test]
    fn a_trusted_project_header_secret_is_honored() {
        let r = resolve(
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
        assert_eq!(s.source, SecretSource::Env("GH_TOKEN".into()));
        assert_eq!(s.header, "Authorization");
        assert_eq!(s.to, crate::allowlist::classify("api.github.com").unwrap());
        assert_eq!(s.shape.format("abc"), "Bearer abc");
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn a_global_secret_is_honored_by_location() {
        let r = resolve(
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
            let r = resolve(
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
        let r = resolve(
            RawConfig {
                secret: vec![raw_secret(
                    Some("GH"),
                    None,
                    "api.github.com",
                    "Authorization",
                    Some("bearer"),
                    None,
                )],
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
            let r = resolve(
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
        let missing = resolve(
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

        let unknown = resolve(
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
    fn both_or_neither_secret_source_is_rejected() {
        let both = resolve(
            raw_secrets(
                &["h.test"],
                vec![raw_secret(
                    Some("A"),
                    Some("/f"),
                    "h.test",
                    "H",
                    Some("raw"),
                    None,
                )],
            ),
            None,
        );
        assert!(both.secrets.is_empty());
        assert!(both.warnings.iter().any(|w| w.contains("exactly one")));

        let neither = resolve(
            raw_secrets(
                &["h.test"],
                vec![raw_secret(None, None, "h.test", "H", Some("raw"), None)],
            ),
            None,
        );
        assert!(neither.secrets.is_empty());
        assert!(neither.warnings.iter().any(|w| w.contains("exactly one")));
    }

    #[test]
    fn a_duplicate_target_header_secret_is_last_wins_with_a_warning() {
        let r = resolve(
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
            r.secrets[0].source,
            SecretSource::Env("SECOND".into()),
            "last wins"
        );
        assert!(r.warnings.iter().any(|w| w.contains("overrides")));
    }

    #[test]
    fn a_non_absolute_from_file_is_rejected() {
        let r = resolve(
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
        bad_kind.kind = "ssh-agent".into();
        let r = resolve(raw_secrets(&["h.test"], vec![bad_kind]), None);
        assert!(r.secrets.is_empty());
        assert!(r.warnings.iter().any(|w| w.contains("unknown kind")));

        let r = resolve(
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
