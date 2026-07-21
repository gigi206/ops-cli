//! Secret-resolver plugin registry.
//!
//! A resolver plugin turns a secret *reference* (`scheme://locator`) into the secret's
//! plaintext, host-side. sbx discovers installed plugins under `<data>/plugins/<name>/`,
//! validates each manifest, and exposes the result as a scheme → plugin map the secret
//! validator consults: a `from = "scheme://…"` whose scheme a plugin claims resolves to a
//! [`ResolverPlugin`] the launcher later runs under least privilege.
//!
//! The registry is **trusted by location**, which rests on the data directory being
//! owner-only: a plugin is installed into `<data>/plugins/`, under a tree the runner keeps
//! `0700`, so a project (which writes only the project directory) cannot plant one. That
//! owner-only guarantee is what the *runner* must establish before it execs a resolver host-side
//! in the trusted computing base; loading a manifest here neither runs nor provisions anything.
//! A project's `.sbx.toml` may only *reference* a scheme; whether it may do so is the existing
//! secret trust gate (an untrusted project's whole `[secret]` section is dropped before any
//! scheme is looked up).
//!
//! Loading is **infallible and fail-closed**: a malformed manifest, an unsupported type, a
//! reserved or ill-formed scheme, or two plugins claiming one scheme drops the offending
//! plugin(s) with a warning — never a failed launch, and never a silently-honored bad plugin.

/// The remote signed-store subsystem lives alongside the registry: [`catalogue`] is the
/// offline Ed25519 trust core, and [`stores`] is the impure git-driven fetch/verify/cache
/// shell around it.
pub(crate) mod catalogue;
pub(crate) mod stores;

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The resolver schemes sbx implements itself; a plugin can never claim one of these (the
/// built-in always wins). Kept in sync with [`crate::config`]'s `parse_secret_ref`.
const BUILTIN_SCHEMES: &[&str] = &["env", "file", "sops"];

/// The resolver schemes sbx implements itself — for `sbx plugins`, so a user sees the full
/// namespace and why these can never be a plugin.
pub(crate) fn builtin_schemes() -> &'static [&'static str] {
    BUILTIN_SCHEMES
}

/// A validated resolver plugin: running `exec` with a `scheme://locator` ref as its single
/// argument prints the secret's plaintext to stdout. The launcher runs it sandboxed per
/// `sandbox`; this declaration carries no secret and is safe to log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolverPlugin {
    /// The plugin's name (its directory name), for diagnostics.
    pub(crate) name: String,
    /// The ref scheme this plugin claims — the namespace, unique across the registry.
    pub(crate) scheme: String,
    /// The plugin's own directory, bound read-only into the runner's cage so the executable
    /// (and any sibling helper it ships) is reachable at its real path. Held separately from
    /// `exec` because the manifest's `name` may differ from the directory name, so the directory
    /// cannot be reconstructed from `name`.
    pub(crate) dir: PathBuf,
    /// Absolute path to the executable: the plugin directory joined with the manifest's
    /// (directory-relative, traversal-free) `exec`.
    pub(crate) exec: PathBuf,
    /// The least-privilege grant the runner gives the plugin.
    pub(crate) sandbox: SandboxGrant,
    /// The manifest's declared version, if any. Display-only: sbx never compares or acts on it
    /// (version semantics belong to the plugin store's update mechanism).
    pub(crate) version: Option<String>,
    /// The manifest's one-line description, if any. Display-only.
    pub(crate) description: Option<String>,
}

impl ResolverPlugin {
    /// Whether the executable would be accepted by the runner at launch: a regular file owned by
    /// us and not writable by group or other. A plugin can pass [`PluginRegistry::load`] (the
    /// manifest is well-formed) yet fail this — so `sbx plugins` surfaces the gap, using the very
    /// check the runner enforces. Returns the refusal reason on failure.
    pub(crate) fn check_exec(&self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        // The reason carries no path: callers (`sbx plugins`, the runner) already name the plugin
        // or its executable, so prefixing it here would print the path twice.
        let meta = std::fs::metadata(&self.exec).map_err(|e| e.to_string())?;
        let euid = unsafe { libc::geteuid() };
        verdict_exec(meta.mode(), meta.uid(), euid)
    }
}

/// Pure ownership/mode decision for a plugin executable, shared by the runner (which refuses to
/// launch a failing one) and `sbx plugins` (which flags it). Refuses a non-regular file, one not
/// owned by us, or one writable by group or other — stricter than the config-file safety gate,
/// because this is code about to run in the trusted computing base. Split from the I/O so the
/// foreign-owner branch is unit-testable without a file owned by another uid.
pub(crate) fn verdict_exec(mode: u32, file_uid: u32, euid: u32) -> Result<(), String> {
    if mode & libc::S_IFMT != libc::S_IFREG {
        return Err("not a regular file".to_string());
    }
    if file_uid != euid {
        return Err(format!("owned by uid {file_uid}, expected {euid}"));
    }
    if mode & 0o022 != 0 {
        return Err("writable by group or other".to_string());
    }
    Ok(())
}

/// The host-side least-privilege grant a resolver runs under: the extra read-only paths it
/// needs, the host environment variables to pass through, and whether it may reach the
/// network. The runner supplies a structural environment (a minimal PATH, a read-only host
/// userland, `HOME`, and — under `network` — DNS/TLS files) on top of this; the grant
/// declares only the resolver-specific extra.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SandboxGrant {
    /// Extra host paths bound read-only, each absolute after expanding a leading `~`/`$HOME`
    /// or `$XDG_RUNTIME_DIR`.
    pub(crate) allow_paths: Vec<PathBuf>,
    /// Host environment variable names passed through into the otherwise-cleared environment.
    pub(crate) allow_env: Vec<String>,
    /// Whether the plugin may reach the network (`false` runs it in an empty network namespace).
    pub(crate) network: bool,
}

/// The installed resolver plugins, keyed by the scheme each claims.
#[derive(Debug, Default)]
pub(crate) struct PluginRegistry {
    resolvers: BTreeMap<String, ResolverPlugin>,
}

impl PluginRegistry {
    /// Discover and validate every plugin under `<plugins_dir>/<name>/plugin.toml`. A directory
    /// without a manifest is silently skipped (not every data subdirectory is a plugin); a
    /// manifest that fails validation drops that plugin with a warning. When two plugins claim
    /// the same scheme, **both** are dropped (the scheme is ambiguous — fail-closed, never an
    /// arbitrary winner). The path expansions read `HOME`/`XDG_RUNTIME_DIR` from the environment
    /// once, here.
    pub(crate) fn load(plugins_dir: &Path, warnings: &mut Vec<String>) -> Self {
        let exp = Expansion::from_env();
        Self::load_with(plugins_dir, &exp, warnings)
    }

    /// Core of [`load`](Self::load) with the environment expansion injected, so the path
    /// expansion is testable without touching the process environment.
    fn load_with(plugins_dir: &Path, exp: &Expansion, warnings: &mut Vec<String>) -> Self {
        let mut dirs: Vec<PathBuf> = match std::fs::read_dir(plugins_dir) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect(),
            // No plugins directory means no plugins — the common case, not an error.
            Err(_) => return Self::default(),
        };
        // A stable order makes a collision's "both dropped" outcome deterministic and the
        // warnings reproducible.
        dirs.sort();

        let mut resolvers: BTreeMap<String, ResolverPlugin> = BTreeMap::new();
        let mut conflicted: BTreeSet<String> = BTreeSet::new();
        for dir in dirs {
            let plugin = match load_one(&dir, exp) {
                Ok(Some(plugin)) => plugin,
                // Not a plugin directory (no manifest) — skip quietly.
                Ok(None) => continue,
                Err(e) => {
                    let name = dir.file_name().and_then(OsStr::to_str).unwrap_or("?");
                    warnings.push(format!("plugins: ignoring `{name}` — {e}"));
                    continue;
                }
            };
            let scheme = plugin.scheme.clone();
            if conflicted.contains(&scheme) {
                warnings.push(format!(
                    "plugins: ignoring `{}` — scheme `{scheme}` is claimed by more than one plugin",
                    plugin.name
                ));
                continue;
            }
            if let Some(prev) = resolvers.remove(&scheme) {
                conflicted.insert(scheme.clone());
                warnings.push(format!(
                    "plugins: scheme `{scheme}` is claimed by both `{}` and `{}` — both ignored \
                     (a scheme must be unique)",
                    prev.name, plugin.name
                ));
                continue;
            }
            resolvers.insert(scheme, plugin);
        }
        Self { resolvers }
    }

    /// The resolver claiming `scheme`, if any.
    pub(crate) fn resolver(&self, scheme: &str) -> Option<&ResolverPlugin> {
        self.resolvers.get(scheme)
    }

    /// The installed resolver plugins, ordered by scheme (the `BTreeMap` key) — for `sbx plugins`.
    pub(crate) fn resolvers(&self) -> impl Iterator<Item = &ResolverPlugin> {
        self.resolvers.values()
    }

    /// Whether any resolver plugin is installed.
    pub(crate) fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Build a registry directly from validated plugins, for tests that exercise the secret
    /// validator without staging manifests on disk.
    #[cfg(test)]
    pub(crate) fn with(plugins: impl IntoIterator<Item = ResolverPlugin>) -> Self {
        Self {
            resolvers: plugins.into_iter().map(|p| (p.scheme.clone(), p)).collect(),
        }
    }
}

/// The raw `plugin.toml` manifest, before validation. Every field is optional so a missing
/// one yields a precise "missing X" error rather than a generic parse failure.
#[derive(Debug, Deserialize)]
struct RawManifest {
    name: Option<String>,
    #[serde(rename = "type")]
    plugin_type: Option<String>,
    scheme: Option<String>,
    exec: Option<String>,
    version: Option<String>,
    description: Option<String>,
    #[serde(default)]
    sandbox: RawSandbox,
}

/// The raw `[sandbox]` table, before path expansion and key validation.
#[derive(Debug, Default, Deserialize)]
struct RawSandbox {
    #[serde(default)]
    allow_paths: Vec<String>,
    #[serde(default)]
    allow_env: Vec<String>,
    #[serde(default)]
    network: bool,
}

/// Load and validate one plugin directory. `Ok(None)` when the directory holds no
/// `plugin.toml` (skip it); `Ok(Some)` for a valid plugin; `Err` (with a reason) for a
/// present-but-invalid manifest, which the caller turns into a warning.
fn load_one(dir: &Path, exp: &Expansion) -> Result<Option<ResolverPlugin>, String> {
    let manifest_path = dir.join("plugin.toml");
    let bytes = match std::fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read plugin.toml: {e}")),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| "plugin.toml is not valid UTF-8")?;
    let raw: RawManifest = toml::from_str(text).map_err(|e| format!("invalid plugin.toml: {e}"))?;

    let dir_name = dir.file_name().and_then(OsStr::to_str).unwrap_or("?");
    let name = raw.name.unwrap_or_else(|| dir_name.to_string());

    match raw.plugin_type.as_deref() {
        Some("resolver") => {}
        Some(other) => {
            return Err(format!(
                "unsupported plugin type `{other}` (only \"resolver\" is supported)"
            ));
        }
        None => return Err("missing `type` (only \"resolver\" is supported)".to_string()),
    }

    let scheme = raw.scheme.ok_or("missing `scheme`")?;
    validate_scheme(&scheme)?;

    let exec = raw.exec.ok_or("missing `exec`")?;
    let exec = resolve_exec(dir, &exec)?;

    let mut allow_paths = Vec::with_capacity(raw.sandbox.allow_paths.len());
    for entry in &raw.sandbox.allow_paths {
        allow_paths.push(expand_allow_path(entry, exp)?);
    }
    for key in &raw.sandbox.allow_env {
        if !is_valid_env_key(key) {
            return Err(format!("`allow_env` has an invalid variable name `{key}`"));
        }
    }

    Ok(Some(ResolverPlugin {
        name,
        scheme,
        dir: dir.to_path_buf(),
        exec,
        sandbox: SandboxGrant {
            allow_paths,
            allow_env: raw.sandbox.allow_env,
            network: raw.sandbox.network,
        },
        version: raw.version,
        description: raw.description,
    }))
}

/// Validate a ref scheme: a lowercase URI scheme (`[a-z][a-z0-9+.-]*`) that is not one of the
/// built-in schemes sbx resolves itself. Lowercase-only keeps the comparison against a ref's
/// scheme unambiguous, and the built-in guard means a plugin can never shadow `env`/`file`/`sops`.
pub(crate) fn validate_scheme(scheme: &str) -> Result<(), String> {
    if scheme.is_empty() {
        return Err("`scheme` is empty".to_string());
    }
    let mut chars = scheme.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(format!(
            "scheme `{scheme}` must start with a lowercase letter"
        ));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
    {
        return Err(format!(
            "scheme `{scheme}` may only contain lowercase letters, digits, `+`, `-`, `.`"
        ));
    }
    if BUILTIN_SCHEMES.contains(&scheme) {
        return Err(format!(
            "scheme `{scheme}` is built in and cannot be claimed by a plugin"
        ));
    }
    Ok(())
}

/// Resolve the manifest's `exec` against the plugin directory, refusing an absolute path or any
/// `..`/`.` component so the executable can never point outside the plugin directory.
fn resolve_exec(dir: &Path, exec: &str) -> Result<PathBuf, String> {
    if exec.is_empty() {
        return Err("`exec` is empty".to_string());
    }
    let rel = Path::new(exec);
    if rel.is_absolute() {
        return Err(format!(
            "`exec` `{exec}` must be relative to the plugin directory"
        ));
    }
    use std::path::Component;
    for comp in rel.components() {
        match comp {
            Component::Normal(_) => {}
            _ => {
                return Err(format!(
                    "`exec` `{exec}` must be a plain path inside the plugin directory \
                     (no `..`, `.`, or absolute parts)"
                ));
            }
        }
    }
    Ok(dir.join(rel))
}

/// The home and runtime directories used to expand a leading `~`/`$HOME`/`$XDG_RUNTIME_DIR` in
/// an `allow_paths` entry.
#[derive(Debug, Default)]
struct Expansion {
    home: Option<PathBuf>,
    runtime: Option<PathBuf>,
}

impl Expansion {
    fn from_env() -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            runtime: std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        }
    }
}

/// Expand an `allow_paths` entry to an absolute host path. A leading `~` or `$HOME` expands to
/// the home directory and a leading `$XDG_RUNTIME_DIR` to the runtime directory (the gpg-agent
/// socket and similar runtime sockets live there); **any other `$` is rejected** — there is no
/// arbitrary environment interpolation into a bind path. A literal path must be absolute.
///
/// This shares its expandable-prefix set with the config layer's `binds` expander
/// (`config::expand_bind_path`) so the user sees one variable vocabulary, but the two differ
/// intentionally: this resolver allowlist rejects *any* stray `$`, whereas a `binds` source keeps
/// a literal `$` past the head (a real mount path may contain one). Keep them separate.
fn expand_allow_path(raw: &str, exp: &Expansion) -> Result<PathBuf, String> {
    if raw.is_empty() {
        return Err("an `allow_paths` entry is empty".to_string());
    }
    let (head, rest) = match raw.split_once('/') {
        Some((h, r)) => (h, Some(r)),
        None => (raw, None),
    };
    let base = match head {
        "~" | "$HOME" => exp.home.clone().ok_or_else(|| {
            format!("`allow_paths` entry `{raw}` needs `$HOME`, which is not set")
        })?,
        "$XDG_RUNTIME_DIR" => exp.runtime.clone().ok_or_else(|| {
            format!("`allow_paths` entry `{raw}` needs `$XDG_RUNTIME_DIR`, which is not set")
        })?,
        other => {
            if other.contains('$') || rest.is_some_and(|r| r.contains('$')) {
                return Err(format!(
                    "`allow_paths` entry `{raw}` uses an unsupported variable \
                     (only `~`, `$HOME`, `$XDG_RUNTIME_DIR` are expanded)"
                ));
            }
            let p = PathBuf::from(raw);
            if !p.is_absolute() {
                return Err(format!(
                    "`allow_paths` entry `{raw}` is not an absolute path"
                ));
            }
            return Ok(p);
        }
    };
    Ok(match rest {
        Some(r) => base.join(r),
        None => base,
    })
}

/// A POSIX-ish environment variable name: a non-empty run of letters, digits, and `_` not
/// starting with a digit. Mirrors the config layer's env-key check so `allow_env` entries are
/// held to the same bar — intentionally duplicated to keep the module self-contained; the two
/// are simple and stable, and a drift would only loosen `allow_env`, not the security boundary.
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// What a successful [`install`] placed — surfaced to the user so the report names the plugin's
/// own identity (its `name`, the token `sbx plugins rm` takes) and the scheme it now claims.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Installed {
    pub(crate) name: String,
    pub(crate) scheme: String,
}

/// Install a resolver plugin from a local source directory into `<data>/plugins/<name>/`, where it
/// becomes trusted by location. The whole tree is copied (regular files and subdirectories only —
/// a symlink or special file is refused), then the *staged copy* — the artifact that will actually
/// run — is re-validated exactly as the registry and runner would. Fail-closed at every step: a
/// malformed manifest, an executable that is not an owner-only regular file, an install name that
/// is not a safe directory component, an already-installed plugin of that name, or a scheme already
/// claimed by another installed plugin each refuse before anything is placed.
pub(crate) fn install(layout: &crate::store::Layout, source: &Path) -> Result<Installed, String> {
    install_inner(layout, source, None)
}

/// Install a resolver plugin fetched from a signed store, reconciling the catalogue's advertised
/// identity against the plugin's own manifest before placing it. The catalogue is the signed,
/// user-facing listing; the manifest is authoritative for the install. They must agree — the
/// plugin must install under the name the catalogue advertised (`expected_name`) and claim the
/// scheme it advertised (`expected_scheme`) — or the install is refused fail-closed, so a catalogue
/// that misrepresents what it pins can never install something other than what was listed. The
/// content itself was already pinned to the catalogue by the caller's
/// [`crate::plugins::catalogue::verify_entry`]; this adds the identity half of that reconciliation. The
/// store checkout's file modes (umask-dependent after a `git` fetch) are canonicalized during the
/// install, so the placed plugin's permissions are deterministic regardless of how it was fetched.
pub(crate) fn install_from_store(
    layout: &crate::store::Layout,
    source: &Path,
    expected_name: &str,
    expected_scheme: &str,
) -> Result<Installed, String> {
    install_inner(layout, source, Some((expected_name, expected_scheme)))
}

/// The shared body of [`install`] and [`install_from_store`]. `expect` is `Some((name, scheme))`
/// only for a store install, where the catalogue's advertised identity is reconciled against the
/// manifest before anything is placed; a local-directory or built-in install passes `None`.
fn install_inner(
    layout: &crate::store::Layout,
    source: &Path,
    expect: Option<(&str, &str)>,
) -> Result<Installed, String> {
    let exp = Expansion::from_env();

    // Validate the source up front (fail fast, before copying): a real plugin with a sound manifest
    // and a runnable executable. This also yields the name and scheme the install keys on.
    let probe = load_one(source, &exp)
        .map_err(|e| format!("{} is not a usable plugin: {e}", source.display()))?
        .ok_or_else(|| format!("{} is not a plugin (no plugin.toml)", source.display()))?;

    // Reconcile a store catalogue's advertised identity against the authoritative manifest before
    // anything else: a divergence means the listing does not describe what would be installed, so
    // refuse it by name rather than silently placing a different plugin (or one claiming a different
    // scheme than was browsed).
    if let Some((want_name, want_scheme)) = expect {
        if probe.name != want_name {
            return Err(format!(
                "the store lists this plugin as `{want_name}`, but its manifest declares \
                 `name = \"{}\"` — refusing the mismatch",
                probe.name
            ));
        }
        if probe.scheme != want_scheme {
            return Err(format!(
                "the store advertises scheme `{want_scheme}://`, but the plugin's manifest claims \
                 `{}://` — refusing the mismatch",
                probe.scheme
            ));
        }
    }

    // For a local source the executable is validated up front (fail fast). A store checkout's file
    // modes come from `git` plus the local umask — noise, since the catalogue pins only the content
    // and the executable bit (which `verify_entry` already checked) — so its executable is instead
    // canonicalized after the copy and validated on the staged copy below.
    if expect.is_none() {
        probe
            .check_exec()
            .map_err(|why| format!("the plugin's executable {} is {why}", probe.exec.display()))?;
    }

    let name = probe.name.clone();
    validate_install_name(&name).map_err(|e| {
        format!("{e}; set a `name = \"...\"` in plugin.toml to choose the install name")
    })?;

    // The trust-by-location root must be owner-only before anything is placed under it.
    ensure_owner_only(layout.data_dir())?;
    let plugins_dir = layout.plugins_dir();
    ensure_owner_only(&plugins_dir)?;

    let dest = plugins_dir.join(&name);
    if dest.exists() {
        return Err(format!(
            "a plugin named `{name}` is already installed — remove it first with \
             `sbx plugins rm {name}`"
        ));
    }

    // Refuse a scheme another installed plugin already claims: placing it would make the registry
    // drop *both* as ambiguous, so the install would "succeed" into a silently dead plugin. This
    // guards against a *cleanly resolving* prior claimant; a scheme already claimed by two or more
    // plugins resolves to nothing, so this lets a further claimant in — that scheme is already
    // broken and the user must `sbx plugins rm` the duplicates regardless (the next `list`/`info`
    // explains the conflict).
    let mut warnings = Vec::new();
    let installed = PluginRegistry::load_with(&plugins_dir, &exp, &mut warnings);
    if let Some(other) = installed.resolver(&probe.scheme) {
        if other.dir != dest {
            return Err(format!(
                "scheme `{}://` is already claimed by the installed plugin `{}` — remove it first \
                 with `sbx plugins rm {}`",
                probe.scheme, other.name, other.name
            ));
        }
    }

    // Stage into a temp sibling *outside* the plugins directory (so a concurrent `list` never scans
    // a half-built tree), re-validate what landed, then atomically place it.
    let stage =
        layout
            .data_dir()
            .join(format!(".plugin-stage-{}-{}", std::process::id(), unique()));
    let _ = std::fs::remove_dir_all(&stage);
    if let Err(e) = copy_tree(source, &stage) {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }
    // A store checkout inherits its file modes from the fetch's umask, while git records only the
    // executable bit (already pinned by the catalogue's content hash). Canonicalize the staged copy
    // so an installed store plugin's permissions are deterministic and owner-clean — an executable
    // file `0755`, the rest `0644` — rather than carrying a group/other-write bit the runner's
    // executable check would refuse. A local install keeps its source modes (the up-front check
    // already passed them).
    if expect.is_some() {
        if let Err(e) = canonicalize_modes(&stage) {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(e);
        }
    }
    // The staged copy is the real artifact: validate it, not just the source.
    let staged_ok = load_one(&stage, &exp)
        .map_err(|e| format!("the staged plugin failed validation: {e}"))
        .and_then(|opt| opt.ok_or_else(|| "the staged plugin lost its manifest".to_string()))
        .and_then(|p| {
            p.check_exec()
                .map_err(|why| format!("the staged executable is {why}"))
        });
    if let Err(e) = staged_ok {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
    }

    match std::fs::rename(&stage, &dest) {
        Ok(()) => Ok(Installed {
            name,
            scheme: probe.scheme,
        }),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&stage);
            // A non-empty dest (ENOTEMPTY) means a plugin of that name appeared between the check
            // and the rename — refuse rather than overwrite.
            if dest.exists() {
                Err(format!(
                    "a plugin named `{name}` appeared concurrently — remove it first with \
                     `sbx plugins rm {name}`"
                ))
            } else {
                Err(format!("could not place the plugin: {e}"))
            }
        }
    }
}

/// Remove an installed resolver plugin by name. The name is validated as a safe path component
/// first (so `..`/`/` can never escape the plugins directory), and the target must actually look
/// like a plugin (carry a `plugin.toml`) so a typo cannot delete an unrelated directory. The
/// directory is renamed aside atomically — leaving the registry at once — then removed.
pub(crate) fn remove(layout: &crate::store::Layout, name: &str) -> Result<(), String> {
    validate_install_name(name)?;
    let dest = layout.plugins_dir().join(name);
    let meta = match std::fs::symlink_metadata(&dest) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("no installed plugin named `{name}`"));
        }
        Err(e) => return Err(format!("cannot inspect `{name}`: {e}")),
    };
    if !meta.is_dir() {
        return Err(format!("`{name}` is not an installed plugin"));
    }
    if !dest.join("plugin.toml").is_file() {
        return Err(format!(
            "`{name}` carries no plugin.toml — refusing to remove (it is not a resolver plugin)"
        ));
    }
    let trash = layout
        .data_dir()
        .join(format!(".plugin-rm-{}-{}", std::process::id(), unique()));
    std::fs::rename(&dest, &trash).map_err(|e| format!("cannot remove `{name}`: {e}"))?;
    let _ = std::fs::remove_dir_all(&trash);
    Ok(())
}

/// Validate a plugin's on-disk identity: a single, safe directory component. It becomes a directory
/// name directly under the data dir, so it must contain no path separator or `.`/`..` traversal,
/// must not begin with a dot (which would collide with the `.plugin-*` staging namespace and hide
/// it from listings), and is held to a conservative name charset. The leading-dot and charset rules
/// together reject every traversal form (`.`, `..`, `a/b`).
pub(crate) fn validate_install_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the plugin name is empty".to_string());
    }
    if name.starts_with('.') {
        return Err(format!("plugin name `{name}` must not start with a dot"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "plugin name `{name}` may only contain letters, digits, `.`, `_`, `-`"
        ));
    }
    Ok(())
}

/// Recursively copy a plugin source tree into `dst` (which must not yet exist). Only directories
/// (created owner-only) and regular files (copied with their mode, preserving the executable bit)
/// are reproduced; a symlink, device, socket, or fifo is refused — a resolver plugin is a small
/// tree of real files, and copying a link by reference or following it into the host would defeat
/// the point of staging a self-contained, validated artifact.
fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    // Refuse a symlinked source root: `read_dir` would follow it and copy whatever it points at.
    // A plugin source is a real, self-contained directory (the recursive descent below only enters
    // entries already confirmed to be non-symlink directories, so this guards the root each caller
    // hands in).
    let src_meta = std::fs::symlink_metadata(src)
        .map_err(|e| format!("cannot stat {}: {e}", src.display()))?;
    if src_meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink (a plugin source must be a real directory)",
            src.display()
        ));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dst)
        .map_err(|e| format!("cannot create {}: {e}", dst.display()))?;
    let entries =
        std::fs::read_dir(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read an entry of {}: {e}", src.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", entry.path().display()))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&from, &to)?;
        } else if file_type.is_file() {
            std::fs::copy(&from, &to)
                .map_err(|e| format!("cannot copy {}: {e}", from.display()))?;
        } else {
            return Err(format!(
                "{} is not a regular file or directory (a plugin may not ship symlinks or \
                 special files)",
                from.display()
            ));
        }
    }
    Ok(())
}

/// Canonicalize a staged store plugin's file modes in place: a regular file becomes `0755` if it
/// carries any executable bit, `0644` otherwise. A store is fetched with `git`, whose checkout
/// applies the local umask and records only whether a file is executable — and that executable bit
/// is exactly what the catalogue's content hash pinned (and `verify_entry` checked). The remaining
/// mode bits are therefore umask noise; normalizing them makes an installed store plugin's
/// permissions deterministic and owner-clean, matching a built-in install, instead of inheriting
/// whatever umask the fetch ran under. Only directories and regular files are present (`copy_tree`
/// already refused symlinks and special files).
fn canonicalize_modes(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read an entry of {}: {e}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if file_type.is_dir() {
            canonicalize_modes(&path)?;
        } else if file_type.is_file() {
            let mode = std::fs::metadata(&path)
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
                .permissions()
                .mode();
            let canonical = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(canonical))
                .map_err(|e| format!("cannot set the mode of {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Create `dir` (and any missing parents) owner-only, tightening it if it already existed with
/// looser permissions — the same fail-closed bootstrap the store root uses, applied to the
/// trust-by-location plugins tree.
fn ensure_owner_only(dir: &Path) -> Result<(), String> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot secure {}: {e}", dir.display()))?;
    Ok(())
}

/// A per-call-unique suffix for a staging/trash temp directory, so two installs (or an install and
/// a removal) in one process never collide. A monotonic process-local counter — no clock or RNG.
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

// The default resolver-plugin store, embedded in the binary by `build.rs`: each entry is
// (plugin directory name, path relative to that directory, file bytes). The store ships inside
// the binary so a built-in install needs no fetch, network, or signature — trust is the binary.
include!(concat!(env!("OUT_DIR"), "/store_plugin_files.rs"));

/// One plugin in the built-in store, for `sbx plugins store list`. `name` is the token
/// `sbx plugins install` takes; a build-time check keeps it equal to the manifest `name`, so the
/// install (which keys on the manifest name) lands where `store list` says it will.
pub(crate) struct StoreEntry {
    pub(crate) name: String,
    pub(crate) scheme: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) description: Option<String>,
}

/// The distinct plugin names in the built-in store, sorted.
pub(crate) fn embedded_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = STORE_FILES.iter().map(|(name, _, _)| *name).collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The built-in store entries with their manifest metadata, for `sbx plugins store list`.
pub(crate) fn embedded_listing() -> Vec<StoreEntry> {
    embedded_names()
        .into_iter()
        .map(|name| {
            let raw = embedded_manifest(name);
            StoreEntry {
                name: name.to_string(),
                scheme: raw.as_ref().and_then(|r| r.scheme.clone()),
                version: raw.as_ref().and_then(|r| r.version.clone()),
                description: raw.as_ref().and_then(|r| r.description.clone()),
            }
        })
        .collect()
}

/// Parse the embedded `plugin.toml` of the built-in plugin `name`, if present and well-formed.
/// A built-in manifest is always valid (a build-time test enforces it), so a `None` here means an
/// unknown name; the lenient parse keeps `store list` from panicking on a hypothetical bad embed.
fn embedded_manifest(name: &str) -> Option<RawManifest> {
    let bytes = STORE_FILES
        .iter()
        .find(|(n, rel, _)| *n == name && *rel == "plugin.toml")
        .map(|(_, _, bytes)| *bytes)?;
    let text = std::str::from_utf8(bytes).ok()?;
    toml::from_str(text).ok()
}

/// Install a resolver plugin from the built-in store by name. The bundled files are extracted to a
/// private staging tree, the one executable the manifest names is made runnable (embedded bytes
/// carry no file mode), and the tree is handed to [`install`] — so a built-in install runs through
/// exactly the same validation, scheme-collision guard, and atomic placement as a local-directory
/// install. An unknown name is refused, fail-closed.
pub(crate) fn install_embedded(
    layout: &crate::store::Layout,
    name: &str,
) -> Result<Installed, String> {
    let files: Vec<(&str, &[u8])> = STORE_FILES
        .iter()
        .filter(|(n, _, _)| *n == name)
        .map(|(_, rel, bytes)| (*rel, *bytes))
        .collect();
    if files.is_empty() {
        return Err(format!(
            "no built-in plugin named `{name}` (see `sbx plugins store list`)"
        ));
    }

    ensure_owner_only(layout.data_dir())?;
    // The extraction tree is removed on drop — on the success path (after `install` has copied it
    // into place) and on any early return below.
    let extract = TempTree(layout.data_dir().join(format!(
        ".plugin-embed-{}-{}",
        std::process::id(),
        unique()
    )));
    let _ = std::fs::remove_dir_all(&extract.0);
    write_embedded_tree(&extract.0, &files)?;

    // The embedded bytes carry no mode, so the executable lands non-executable. Make exactly the
    // manifest's `exec` runnable before handing the tree to `install` (which re-validates it in
    // full) — the single step a built-in install adds over a local one, so a test asserts the bit
    // directly on the placed file. The manifest is parsed leniently here, only to locate the
    // executable and without expanding any `allow_paths`; `install`'s own `load_one` is the
    // authoritative validation.
    let raw = embedded_manifest(name)
        .ok_or_else(|| format!("built-in plugin `{name}` has a malformed manifest"))?;
    let exec_rel = raw
        .exec
        .ok_or_else(|| format!("built-in plugin `{name}` declares no `exec`"))?;
    set_executable(&resolve_exec(&extract.0, &exec_rel)?)?;

    install(layout, &extract.0)
}

/// Write an embedded plugin's files under `root` (created owner-only, as are any subdirectories).
fn write_embedded_tree(root: &Path, files: &[(&str, &[u8])]) -> Result<(), String> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;
    let owner_only = |dir: &Path| {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))
    };
    owner_only(root)?;
    for (rel, bytes) in files {
        let dest = root.join(rel);
        if let Some(parent) = dest.parent() {
            owner_only(parent)?;
        }
        std::fs::write(&dest, bytes)
            .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;
    }
    Ok(())
}

/// Make a file executable (and not group/other-writable): mode `0755`, the bit the runner requires
/// and an embedded byte blob lacks.
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("cannot make {} executable: {e}", path.display()))
}

/// An extraction directory removed when it goes out of scope, so a built-in install never leaks its
/// staging tree — on success (after the files are copied into place) or on any error path.
struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_plugin(root: &Path, name: &str, manifest: &str) {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.toml"), manifest).unwrap();
    }

    fn load(root: &Path) -> (PluginRegistry, Vec<String>) {
        let exp = Expansion {
            home: Some(PathBuf::from("/home/u")),
            runtime: Some(PathBuf::from("/run/user/1000")),
        };
        let mut warnings = Vec::new();
        let reg = PluginRegistry::load_with(root, &exp, &mut warnings);
        (reg, warnings)
    }

    #[test]
    fn loads_a_valid_resolver_and_expands_its_paths() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "pass",
            r#"
                name   = "pass"
                type   = "resolver"
                scheme = "pass"
                exec   = "resolve"
                [sandbox]
                allow_paths = ["~/.password-store", "$XDG_RUNTIME_DIR/gnupg", "/etc/passwd"]
                allow_env   = ["GNUPGHOME"]
                network     = false
            "#,
        );
        let (reg, warnings) = load(root.path());
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let p = reg.resolver("pass").expect("pass resolver");
        assert_eq!(p.name, "pass");
        assert_eq!(p.dir, root.path().join("pass"));
        assert_eq!(p.exec, root.path().join("pass/resolve"));
        assert_eq!(
            p.sandbox.allow_paths,
            vec![
                PathBuf::from("/home/u/.password-store"),
                PathBuf::from("/run/user/1000/gnupg"),
                PathBuf::from("/etc/passwd"),
            ]
        );
        assert_eq!(p.sandbox.allow_env, vec!["GNUPGHOME".to_string()]);
        assert!(!p.sandbox.network);
    }

    #[test]
    fn a_missing_manifest_is_skipped_not_an_error() {
        let root = crate::testutil::TmpDir::new();
        fs::create_dir_all(root.path().join("not-a-plugin")).unwrap();
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("not-a-plugin").is_none());
        assert!(
            warnings.is_empty(),
            "a bare directory must not warn: {warnings:?}"
        );
    }

    #[test]
    fn an_absent_plugins_dir_is_an_empty_registry() {
        let root = crate::testutil::TmpDir::new();
        let (reg, warnings) = load(&root.path().join("nope"));
        assert!(warnings.is_empty());
        assert!(reg.resolver("anything").is_none());
    }

    #[test]
    fn a_builtin_scheme_cannot_be_claimed() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "evil",
            "type = \"resolver\"\nscheme = \"env\"\nexec = \"resolve\"\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("env").is_none());
        assert!(
            warnings.iter().any(|w| w.contains("built in")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_non_resolver_type_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "broker",
            "type = \"broker\"\nscheme = \"x\"\nexec = \"resolve\"\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("x").is_none());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unsupported plugin type")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_colliding_scheme_drops_both_plugins() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "a-vault",
            "type = \"resolver\"\nscheme = \"vault\"\nexec = \"resolve\"\n",
        );
        write_plugin(
            root.path(),
            "b-vault",
            "type = \"resolver\"\nscheme = \"vault\"\nexec = \"resolve\"\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(
            reg.resolver("vault").is_none(),
            "an ambiguous scheme must resolve to nothing"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("both `a-vault` and `b-vault`")),
            "{warnings:?}"
        );
    }

    #[test]
    fn three_plugins_one_scheme_all_dropped() {
        let root = crate::testutil::TmpDir::new();
        for n in ["a", "b", "c"] {
            write_plugin(
                root.path(),
                n,
                "type = \"resolver\"\nscheme = \"dup\"\nexec = \"resolve\"\n",
            );
        }
        let (reg, _warnings) = load(root.path());
        assert!(reg.resolver("dup").is_none());
    }

    #[test]
    fn an_exec_escaping_the_dir_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "esc",
            "type = \"resolver\"\nscheme = \"esc\"\nexec = \"../../etc/evil\"\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("esc").is_none());
        assert!(warnings.iter().any(|w| w.contains("exec")), "{warnings:?}");
    }

    #[test]
    fn an_absolute_exec_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "abs",
            "type = \"resolver\"\nscheme = \"abs\"\nexec = \"/usr/bin/evil\"\n",
        );
        let (reg, _warnings) = load(root.path());
        assert!(reg.resolver("abs").is_none());
    }

    #[test]
    fn an_unsupported_path_variable_is_refused() {
        assert!(expand_allow_path("$SECRET_DIR/x", &Expansion::default()).is_err());
        assert!(expand_allow_path("/etc/$injected", &Expansion::default()).is_err());
    }

    #[test]
    fn a_relative_literal_path_is_refused() {
        assert!(expand_allow_path("relative/path", &Expansion::default()).is_err());
    }

    #[test]
    fn expansion_needs_the_variable_to_be_set() {
        // `$XDG_RUNTIME_DIR` unset → the entry that needs it is an error, not a silent drop.
        let exp = Expansion {
            home: Some(PathBuf::from("/home/u")),
            runtime: None,
        };
        assert!(expand_allow_path("$XDG_RUNTIME_DIR/gnupg", &exp).is_err());
        assert_eq!(
            expand_allow_path("~/.ssh", &exp).unwrap(),
            PathBuf::from("/home/u/.ssh")
        );
    }

    #[test]
    fn a_bare_home_or_runtime_token_expands() {
        let exp = Expansion {
            home: Some(PathBuf::from("/home/u")),
            runtime: Some(PathBuf::from("/run/user/1000")),
        };
        assert_eq!(
            expand_allow_path("$HOME", &exp).unwrap(),
            PathBuf::from("/home/u")
        );
        assert_eq!(
            expand_allow_path("$XDG_RUNTIME_DIR", &exp).unwrap(),
            PathBuf::from("/run/user/1000")
        );
    }

    #[test]
    fn a_malformed_manifest_warns_and_drops() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(root.path(), "bad", "this is not = valid toml [[[");
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("bad").is_none());
        assert!(
            warnings.iter().any(|w| w.contains("invalid plugin.toml")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_bad_allow_env_key_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "p",
            "type=\"resolver\"\nscheme=\"p\"\nexec=\"resolve\"\n[sandbox]\nallow_env=[\"BAD-KEY\"]\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("p").is_none());
        assert!(
            warnings.iter().any(|w| w.contains("allow_env")),
            "{warnings:?}"
        );
    }

    #[test]
    fn the_registry_surfaces_version_description_and_the_namespace() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "pass",
            "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n\
             version=\"0.1.0\"\ndescription=\"read from pass\"\n",
        );
        let (reg, _w) = load(root.path());
        assert!(!reg.is_empty());
        let p = reg.resolver("pass").unwrap();
        assert_eq!(p.version.as_deref(), Some("0.1.0"));
        assert_eq!(p.description.as_deref(), Some("read from pass"));
        // resolvers() iterates the installed set, ordered by scheme
        let schemes: Vec<&str> = reg.resolvers().map(|p| p.scheme.as_str()).collect();
        assert_eq!(schemes, vec!["pass"]);
        // the reserved namespace is what a plugin can never claim
        assert_eq!(builtin_schemes(), &["env", "file", "sops"]);
    }

    #[test]
    fn verdict_exec_accepts_an_owned_non_writable_regular_file() {
        let reg = libc::S_IFREG;
        assert!(verdict_exec(reg | 0o755, 1000, 1000).is_ok());
        assert!(verdict_exec(reg | 0o700, 1000, 1000).is_ok());
    }

    #[test]
    fn verdict_exec_refuses_foreign_owner_group_or_world_write_and_non_regular() {
        let reg = libc::S_IFREG;
        assert!(verdict_exec(reg | 0o755, 1234, 1000)
            .unwrap_err()
            .contains("owned by uid 1234"));
        // group-writable is refused here (stricter than the config gate)
        assert!(verdict_exec(reg | 0o775, 1000, 1000)
            .unwrap_err()
            .contains("group or other"));
        assert!(verdict_exec(reg | 0o777, 1000, 1000)
            .unwrap_err()
            .contains("group or other"));
        // a directory (no S_IFREG) is refused
        assert!(verdict_exec(libc::S_IFDIR | 0o755, 1000, 1000)
            .unwrap_err()
            .contains("not a regular file"));
    }

    #[test]
    fn check_exec_flags_a_group_writable_executable() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "p",
            "type=\"resolver\"\nscheme=\"p\"\nexec=\"resolve\"\n",
        );
        let exec = root.path().join("p/resolve");
        std::fs::write(&exec, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (reg, _w) = load(root.path());
        let p = reg.resolver("p").unwrap();
        assert!(
            p.check_exec().is_ok(),
            "an owner-only 0755 exec is runnable"
        );

        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(p.check_exec().unwrap_err().contains("group or other"));
    }

    /// Build a source plugin directory (a `plugin.toml` and an owner-owned `resolve` executable at
    /// `mode`) under `root`, returning its path — the kind of directory `sbx plugins install` takes.
    fn source_plugin(root: &Path, dirname: &str, manifest: &str, exec_mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = root.join(dirname);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.toml"), manifest).unwrap();
        let exec = dir.join("resolve");
        fs::write(&exec, "#!/bin/sh\necho secret\n").unwrap();
        fs::set_permissions(&exec, fs::Permissions::from_mode(exec_mode)).unwrap();
        dir
    }

    #[test]
    fn install_places_a_plugin_under_its_manifest_name_and_the_registry_finds_it() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // the source directory name differs from the manifest name on purpose
        let source = source_plugin(
            src_root.path(),
            "source-checkout",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\nversion=\"0.1.0\"\n",
            0o755,
        );

        let installed = install(&layout, &source).expect("install the plugin");
        assert_eq!(installed.name, "pass");
        assert_eq!(installed.scheme, "pass");

        // placed under the manifest name, not the source directory name, with its files intact
        let dest = layout.plugins_dir().join("pass");
        assert!(dest.join("plugin.toml").is_file());
        assert!(dest.join("resolve").is_file());
        // the executable bit must survive the copy — the load-bearing property of `copy_tree` for
        // an executable plugin. `check_exec` does not test it (it checks ownership / regular-file /
        // not-group-or-world-writable), so assert the mode directly: a future copy that lost the bit
        // (e.g. a read+write rewrite under a 0644 umask) would silently break every install.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dest.join("resolve"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o755,
            "copy_tree must preserve the executable bit"
        );

        // teeth: the live registry surfaces it under its scheme with zero warnings
        let (reg, warnings) = load(&layout.plugins_dir());
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let p = reg.resolver("pass").expect("the installed plugin resolves");
        assert!(
            p.check_exec().is_ok(),
            "the placed executable stays runnable"
        );
    }

    #[test]
    fn install_refuses_a_source_that_is_not_a_plugin() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let empty = src_root.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        let err = install(&layout, &empty).unwrap_err();
        assert!(err.contains("not a plugin"), "{err}");
    }

    #[test]
    fn install_refuses_an_invalid_manifest() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // a built-in scheme can never be claimed by a plugin
        let source = source_plugin(
            src_root.path(),
            "evil",
            "type=\"resolver\"\nscheme=\"env\"\nexec=\"resolve\"\n",
            0o755,
        );
        assert!(install(&layout, &source).is_err());
        assert!(!layout.plugins_dir().join("evil").exists());
    }

    #[test]
    fn install_refuses_a_group_writable_executable() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "pass",
            "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n",
            0o775,
        );
        let err = install(&layout, &source).unwrap_err();
        assert!(err.contains("group or other"), "{err}");
        assert!(
            !layout.plugins_dir().join("pass").exists(),
            "a non-runnable source must place nothing"
        );
    }

    #[test]
    fn install_refuses_a_symlink_in_the_tree() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "pass",
            "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n",
            0o755,
        );
        std::os::unix::fs::symlink("/etc/passwd", source.join("link")).unwrap();
        let err = install(&layout, &source).unwrap_err();
        assert!(err.contains("not a regular file or directory"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
        // the staging temp was cleaned up on the error path
        let leaked: Vec<_> = fs::read_dir(data.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".plugin-stage-")
            })
            .collect();
        assert!(leaked.is_empty(), "a staging temp leaked: {leaked:?}");
    }

    #[test]
    fn install_refuses_an_unsafe_install_name() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "weird",
            "name=\"../evil\"\ntype=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n",
            0o755,
        );
        let err = install(&layout, &source).unwrap_err();
        assert!(err.contains("must not start with a dot"), "{err}");
    }

    #[test]
    fn install_refuses_an_already_installed_name() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let a = source_plugin(
            src_root.path(),
            "a",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n",
            0o755,
        );
        install(&layout, &a).expect("first install");
        // a second source of the same name (a different scheme, so the dest-exists guard is what
        // fires, not the scheme-collision guard)
        let b = source_plugin(
            src_root.path(),
            "b",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"other\"\nexec=\"resolve\"\n",
            0o755,
        );
        let err = install(&layout, &b).unwrap_err();
        assert!(err.contains("already installed"), "{err}");
    }

    #[test]
    fn install_refuses_a_scheme_another_plugin_already_claims() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let a = source_plugin(
            src_root.path(),
            "a",
            "name=\"alpha\"\ntype=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
            0o755,
        );
        install(&layout, &a).expect("install alpha");
        // a different name, same scheme → reaches the collision guard (placing it would make the
        // registry drop both as ambiguous)
        let b = source_plugin(
            src_root.path(),
            "b",
            "name=\"beta\"\ntype=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
            0o755,
        );
        let err = install(&layout, &b).unwrap_err();
        assert!(
            err.contains("already claimed by the installed plugin `alpha`"),
            "{err}"
        );
        // teeth: the original still resolves cleanly and the rejected one was never placed
        let (reg, warnings) = load(&layout.plugins_dir());
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(
            reg.resolver("vault").map(|p| p.name.as_str()),
            Some("alpha")
        );
        assert!(!layout.plugins_dir().join("beta").exists());
    }

    #[test]
    fn install_from_store_installs_when_the_advertised_identity_matches() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // the manifest's scheme differs from its name on purpose, so the reconciliation threads
        // name and scheme separately and a swap cannot pass by accident
        let source = source_plugin(
            src_root.path(),
            "checkout",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"secret-store\"\nexec=\"resolve\"\n",
            0o755,
        );
        let installed =
            install_from_store(&layout, &source, "pass", "secret-store").expect("install");
        assert_eq!(installed.name, "pass");
        assert_eq!(installed.scheme, "secret-store");
        assert!(layout.plugins_dir().join("pass").exists());
    }

    #[test]
    fn install_from_store_refuses_a_name_the_catalogue_misadvertised() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "checkout",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"secret-store\"\nexec=\"resolve\"\n",
            0o755,
        );
        // the catalogue listed this as `other`, but the manifest declares `pass`
        let err = install_from_store(&layout, &source, "other", "secret-store").unwrap_err();
        assert!(err.contains("lists this plugin as `other`"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
        assert!(!layout.plugins_dir().join("other").exists());
    }

    #[test]
    fn install_from_store_refuses_a_scheme_the_catalogue_misadvertised() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "checkout",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"secret-store\"\nexec=\"resolve\"\n",
            0o755,
        );
        // the catalogue advertised `vault://`, but the plugin's manifest claims `secret-store://`
        let err = install_from_store(&layout, &source, "pass", "vault").unwrap_err();
        assert!(err.contains("advertises scheme `vault://`"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
    }

    #[test]
    fn remove_deletes_an_installed_plugin() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "pass",
            "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n",
            0o755,
        );
        install(&layout, &source).expect("install");
        assert!(layout.plugins_dir().join("pass").exists());

        remove(&layout, "pass").expect("remove");
        assert!(!layout.plugins_dir().join("pass").exists());
        let (reg, _w) = load(&layout.plugins_dir());
        assert!(reg.is_empty());
        // no removal temp left behind
        let leaked: Vec<_> = fs::read_dir(data.path())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".plugin-rm-"))
            .collect();
        assert!(leaked.is_empty(), "a removal temp leaked: {leaked:?}");
    }

    #[test]
    fn remove_refuses_an_unsafe_name() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        assert!(remove(&layout, "../etc").is_err());
        assert!(remove(&layout, ".hidden").is_err());
    }

    #[test]
    fn remove_errors_on_a_missing_plugin() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let err = remove(&layout, "ghost").unwrap_err();
        assert!(err.contains("no installed plugin named"), "{err}");
    }

    #[test]
    fn remove_refuses_a_directory_without_a_manifest() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // a stray, non-plugin directory under plugins/ must survive a `rm <typo>`
        let stray = layout.plugins_dir().join("stray");
        fs::create_dir_all(&stray).unwrap();
        fs::write(stray.join("note.txt"), "not a plugin").unwrap();
        let err = remove(&layout, "stray").unwrap_err();
        assert!(err.contains("no plugin.toml"), "{err}");
        assert!(stray.exists(), "a non-plugin directory must be left intact");
    }

    #[test]
    fn the_built_in_store_lists_the_bundled_plugins() {
        let names = embedded_names();
        assert!(names.contains(&"pass"), "the store ships `pass`: {names:?}");
        assert!(
            names.contains(&"vault"),
            "the store ships `vault`: {names:?}"
        );
        // the listing surfaces each plugin's scheme/version/description for `store list`
        let listing = embedded_listing();
        let pass = listing
            .iter()
            .find(|e| e.name == "pass")
            .expect("pass in the listing");
        assert_eq!(pass.scheme.as_deref(), Some("pass"));
        assert_eq!(pass.version.as_deref(), Some("0.1.0"));
        assert!(pass.description.is_some());
    }

    /// The load-bearing invariant: `install` keys on the manifest `name`, but `store list` and the
    /// user key on the directory name. They coincide for the shipped plugins; this fails the build
    /// the day a bundled plugin's directory and manifest name diverge — when `install <dir>` would
    /// silently land under the manifest name and `rm <dir>` would miss it.
    #[test]
    fn every_built_in_plugin_dir_name_equals_its_manifest_name() {
        for name in embedded_names() {
            let raw = embedded_manifest(name)
                .unwrap_or_else(|| panic!("built-in plugin `{name}` has no parseable manifest"));
            assert_eq!(
                raw.name.as_deref(),
                Some(name),
                "built-in plugin directory `{name}` must declare `name = \"{name}\"`"
            );
        }
    }

    /// Every bundled plugin must be *installable*, not merely parseable — extract it, run the same
    /// validation the registry applies, then make its `exec` runnable and run the very `check_exec`
    /// the install (and the runner) enforces. This is the regression net the built-in store
    /// advertises: a malformed manifest, a missing/renamed `exec`, or a non-runnable executable in a
    /// bundled plugin is a build-time bug that fails CI here, not the user's `sbx plugins install`.
    /// It covers `pass` too (the install-path integration test uses `vault` to dodge `$XDG_RUNTIME_DIR`).
    #[test]
    fn every_built_in_plugin_is_installable() {
        // A fixed expansion so a plugin referencing `$XDG_RUNTIME_DIR` (such as `pass`) validates
        // regardless of the test environment; `check_exec` does not expand paths.
        let exp = Expansion {
            home: Some(PathBuf::from("/home/u")),
            runtime: Some(PathBuf::from("/run/user/1000")),
        };
        for name in embedded_names() {
            let files: Vec<(&str, &[u8])> = STORE_FILES
                .iter()
                .filter(|(n, _, _)| *n == name)
                .map(|(_, rel, bytes)| (*rel, *bytes))
                .collect();
            let tmp = crate::testutil::TmpDir::new();
            let root = tmp.path().join(name);
            write_embedded_tree(&root, &files).unwrap();
            let plugin = load_one(&root, &exp)
                .unwrap_or_else(|e| panic!("built-in plugin `{name}` failed validation: {e}"))
                .unwrap_or_else(|| panic!("built-in plugin `{name}` has no manifest"));
            assert_eq!(plugin.name, name);
            // the step install adds, then the check install (and the runner) gates on: this fails on
            // a bundled plugin whose `exec` is missing or renamed (`set_executable` ENOENT) or not a
            // runnable owner-only regular file (`check_exec`).
            set_executable(&plugin.exec).unwrap();
            plugin
                .check_exec()
                .unwrap_or_else(|e| panic!("built-in plugin `{name}` is not installable: {e}"));
        }
    }

    #[test]
    fn install_embedded_places_a_built_in_plugin_and_makes_it_runnable() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // `vault` has no `allow_paths`, so the install validates with no environment dependency.
        let installed = install_embedded(&layout, "vault").expect("install the built-in vault");
        assert_eq!(installed.name, "vault");
        assert_eq!(installed.scheme, "vault");

        let dest = layout.plugins_dir().join("vault");
        assert!(dest.join("plugin.toml").is_file());
        // the executable bit was restored on extraction and survived the copy into place — the one
        // step a built-in install adds, asserted directly (the embedded bytes carried no mode).
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dest.join("resolve"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "the executable bit must be set");

        // the live registry surfaces it, runnable, with no warnings
        let mut warnings = Vec::new();
        let reg = PluginRegistry::load(&layout.plugins_dir(), &mut warnings);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let p = reg.resolver("vault").expect("the built-in plugin resolves");
        assert!(
            p.check_exec().is_ok(),
            "the placed executable stays runnable"
        );

        // no extraction temp was left behind
        assert!(!leaked_embed_temp(data.path()), "an extraction temp leaked");
    }

    #[test]
    fn install_embedded_refuses_an_unknown_name() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let err = install_embedded(&layout, "nope").unwrap_err();
        assert!(err.contains("no built-in plugin named `nope`"), "{err}");
    }

    #[test]
    fn install_embedded_cleans_up_when_the_install_fails() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        install_embedded(&layout, "vault").expect("first install");
        // a second install of the same name fails (already installed) — the extraction temp must
        // still be cleaned up on that failure path, not only on success.
        let err = install_embedded(&layout, "vault").unwrap_err();
        assert!(err.contains("already installed"), "{err}");
        assert!(
            !leaked_embed_temp(data.path()),
            "an extraction temp leaked on the failure path"
        );
    }

    /// Whether any `.plugin-embed-` extraction temp survives under the data directory.
    fn leaked_embed_temp(data: &Path) -> bool {
        fs::read_dir(data).unwrap().flatten().any(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".plugin-embed-")
        })
    }
}
