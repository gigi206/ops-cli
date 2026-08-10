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
//! A claimed-twice scheme resolves to *nothing* and every claimant is disabled until one remains;
//! installing is refused on both sides of that state, so the only way to reach it is to place a
//! plugin directory by hand, and the conflict is then reported (not merely warned about) by
//! `sbx plugins list` and `sbx plugins info <scheme>`.

/// The remote signed-store subsystem lives alongside the registry: [`catalogue`] is the
/// offline Ed25519 trust core, and [`stores`] is the impure git-driven fetch/verify/cache
/// shell around it. [`origin`] records where each installed plugin came from, which a manifest
/// (identical whatever the source) cannot say.
pub(crate) mod catalogue;
pub(crate) mod origin;
pub(crate) mod programs;
pub(crate) mod stores;

use serde::Deserialize;
use std::collections::BTreeMap;
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

/// Render names as `` `a`, `b`, `c` `` — the one shape every conflict message uses, so a listing
/// and a refusal never disagree about how they spell the plugins to remove.
pub(crate) fn quoted_list(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
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
    /// What the *host* supplies to this plugin, from a `[plugin.<name>]` table in the global or a
    /// trusted project config. Empty unless one is declared.
    ///
    /// Kept beside the manifest rather than folded into `sandbox`, because the two answer
    /// different questions and must stay legible apart: the grant is what the plugin **asked
    /// for** and was signed with; this is what this machine **answers**. `sbx plugins info`
    /// shows them as separate lines for the same reason.
    pub(crate) host: HostConfig,
}

/// The host's answer to what a plugin's manifest declares: values for the variables it reads, and
/// where to get the programs it runs when this machine does not already have them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct HostConfig {
    /// Values for variables the manifest declares in `allow_env`/`allow_env_paths`, validated
    /// against it: a variable the plugin does not read is refused, not passed. These take
    /// precedence over the same name in sbx's own environment — a config that names a value is
    /// more deliberate than whatever the invoking shell happened to export.
    pub(crate) env: Vec<(String, String)>,
    /// Nixpkgs attributes for programs the manifest declares, as `(program, attribute)`, validated
    /// against it: a program the plugin does not run is refused, and so is any prefix but `nix:`
    /// (the attribute is stored with the prefix removed).
    ///
    /// A *fallback*, consulted only where `PATH` has no answer. What is recorded here is the
    /// intent; the build happens at `sbx plugins install`, which is where a user expects one, and
    /// a launch only ever reads the resulting out-link.
    pub(crate) programs: Vec<(String, String)>,
}

impl ResolverPlugin {
    /// The plugin's on-disk identity: its directory name, which is the token `sbx plugins rm`
    /// takes and the key its origin record is filed under. It may differ from `name` (a
    /// hand-placed tree can declare any manifest `name`), so every message whose remedy is a
    /// command must use this, never `name`. Falls back to `name` only if the directory name is
    /// not UTF-8, which discovery would already have had to walk past.
    pub(crate) fn dir_name(&self) -> &str {
        self.dir
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or(&self.name)
    }

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

/// Whether a *source* executable may be copied in: a regular file we own and that no other user
/// can rewrite. Deliberately weaker than [`verdict_exec`], which governs the artifact about to run
/// — a checkout under `umask 002` is group-writable, and refusing that would make a plugin
/// uninstallable from its own repository, while the copy that is actually executed is placed
/// `0755` under an owner-only tree.
fn verdict_source(exec: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(exec).map_err(|e| {
        format!(
            "cannot read the plugin's executable {}: {e}",
            exec.display()
        )
    })?;
    let euid = unsafe { libc::geteuid() };
    if meta.mode() & libc::S_IFMT != libc::S_IFREG {
        return Err(format!(
            "the plugin's executable {} is not a regular file",
            exec.display()
        ));
    }
    if meta.uid() != euid {
        return Err(format!(
            "the plugin's executable {} is owned by uid {}, expected {euid}",
            exec.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o002 != 0 {
        return Err(format!(
            "the plugin's executable {} is writable by anyone — `chmod o-w {}` before installing",
            exec.display(),
            exec.display()
        ));
    }
    Ok(())
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

/// The host-side least-privilege grant a resolver runs under: the host programs it runs, the
/// extra read-only paths it needs, the host environment variables to pass through, and whether
/// it may reach the network. The runner supplies a structural environment (a minimal PATH, a
/// read-only host userland, `HOME`, and — under `network` — DNS/TLS files) on top of this; the
/// grant declares only the resolver-specific extra.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SandboxGrant {
    /// Host programs the plugin runs, by **name**. The runner locates each on sbx's own `PATH`
    /// and binds the resolved binary into the cage, on the cage's `PATH`, so the plugin calls it
    /// by name. This is what a manifest declares instead of guessing install locations in
    /// `allow_paths`: where a tool lives is a property of the machine, not of the plugin, and
    /// enumerating candidates is at once too wide (a nix profile's binaries are symlinks into
    /// the store, so the whole store had to be bound to reach one of them) and too narrow (no
    /// list covers every package manager).
    pub(crate) programs: Vec<String>,
    /// Extra host paths bound read-only, each absolute after expanding a leading `~`/`$HOME`
    /// or `$XDG_RUNTIME_DIR`. For the plugin's **data** — a token file, a database, a socket;
    /// a binary belongs in `programs`.
    pub(crate) allow_paths: Vec<PathBuf>,
    /// Host environment variable names passed through into the otherwise-cleared environment.
    pub(crate) allow_env: Vec<String>,
    /// Paths to hide **inside** a granted one, each covered by an empty tmpfs after the binds are
    /// applied.
    ///
    /// A grant is sometimes wide for a reason that has nothing to do with what the plugin needs:
    /// `~/.gnupg` has to be bound whole because the public material it holds has no single name
    /// (`pubring.kbx`, `pubring.gpg`, `public-keys.d/` under keyboxd, plus the `.conf` files), and
    /// binding it drags in `private-keys-v1.d` — which the resolver never needs to read, since the
    /// host agent does the decryption. Naming that subdirectory here removes it without narrowing
    /// the grant to a list of files that breaks on the next layout.
    ///
    /// What a mask buys is that the material cannot be *copied out*, not that it is beyond *use*:
    /// the same grant binds the agent socket, so decryption stays available for the length of the
    /// run. Copying is the capability worth removing, being the one that outlives it.
    ///
    /// A mask can only ever take away, so it needs no trust gate of its own: the widest thing a
    /// manifest can do with it is hide something from itself. Applied after every bind, since a
    /// tmpfs laid before one would simply be covered by it.
    ///
    /// Deliberately a **fixed path**, expanded like an `allow_paths` entry, so it cannot follow a
    /// location that [`Self::allow_env_paths`] supplies: that value may come from the environment
    /// *or* from the host's `[plugin.<name>]` table, and the two are known at different times. A
    /// protection that held for one source and not the other would be worse than one whose limit
    /// is stated, so a relocated home is bound whole and documented as unmasked.
    pub(crate) mask_paths: Vec<PathBuf>,
    /// Environment variables whose **value is a path to bind**, read-only, when they are set.
    ///
    /// A manifest can only name paths it knows in advance (`~/.password-store`, `~/.gnupg`), yet
    /// every tool it drives offers a variable to move that path (`PASSWORD_STORE_DIR`,
    /// `GNUPGHOME`, `VAULT_CACERT`). Passing the variable without binding what it names is worse
    /// than not passing it at all: the tool is told to look somewhere the cage does not have, so
    /// it fails where it would otherwise have worked. The only remedy left to a user was to edit
    /// the installed `plugin.toml`, which changes the tree digest — `sbx plugins list` then
    /// reports the plugin as MODIFIED, and the next reinstall drops the edit.
    ///
    /// Listing a name here **implies** the pass-through, so it must not also appear in
    /// `allow_env`: one name, one place, and no way for the two lists to disagree.
    ///
    /// The value is supplied at invocation, so it is checked then: it must be **absolute**, for
    /// the same reason `$SBX_DATA_DIR` refuses a relative override — a relative bind argument
    /// silently means something other than what it says. A variable that is unset, or that names
    /// a path which does not exist, binds nothing; the plugin then fails closed on its own, with
    /// its own message about what it could not find.
    pub(crate) allow_env_paths: Vec<String>,
    /// Whether the plugin may reach the network (`false` runs it in an empty network namespace).
    pub(crate) network: bool,
}

/// The installed resolver plugins, keyed by the scheme each claims, plus the schemes no plugin
/// gets to claim because more than one does.
#[derive(Debug, Default)]
pub(crate) struct PluginRegistry {
    resolvers: BTreeMap<String, ResolverPlugin>,
    /// Every ambiguous scheme → the directory names claiming it, in discovery order. A scheme
    /// listed here is claimed by no one: all of its claimants are disabled until exactly one
    /// remains. Recorded rather than merely warned about, so every surface can *show* the
    /// conflict and name the plugins to remove.
    conflicts: BTreeMap<String, Vec<String>>,
}

impl PluginRegistry {
    /// Discover and validate every plugin under `<plugins_dir>/<name>/plugin.toml`, reporting
    /// every reason a plugin was dropped — including scheme conflicts — as text in `warnings`.
    /// This is the form for a caller that only relays diagnostics (a launch, a config load); a
    /// caller that renders conflicts itself wants [`load_quiet`](Self::load_quiet).
    pub(crate) fn load(plugins_dir: &Path, warnings: &mut Vec<String>) -> Self {
        let registry = Self::load_quiet(plugins_dir, warnings);
        warnings.extend(registry.conflict_warnings());
        registry
    }

    /// Discovery without the conflict warnings: a directory without a manifest is silently skipped
    /// (not every data subdirectory is a plugin) and a manifest that fails validation still warns,
    /// but an ambiguous scheme is left to [`conflicts`](Self::conflicts) for the caller to render.
    pub(crate) fn load_quiet(plugins_dir: &Path, warnings: &mut Vec<String>) -> Self {
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
        let mut conflicts: BTreeMap<String, Vec<String>> = BTreeMap::new();
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
            // A scheme already known to be ambiguous stays ambiguous: record this claimant too, so
            // the conflict names every plugin that has to be dealt with, not just the first two.
            if let Some(claimants) = conflicts.get_mut(&scheme) {
                claimants.push(plugin.dir_name().to_string());
                continue;
            }
            // The second claimant unseats the first: the scheme becomes ambiguous and *neither*
            // resolves. The claimants are the directory names, because that is what `plugins rm`
            // takes — a conflict whose remedy names something else is a remedy that fails.
            if let Some(prev) = resolvers.remove(&scheme) {
                conflicts.insert(
                    scheme,
                    vec![prev.dir_name().to_string(), plugin.dir_name().to_string()],
                );
                continue;
            }
            resolvers.insert(scheme, plugin);
        }
        Self {
            resolvers,
            conflicts,
        }
    }

    /// The resolver claiming `scheme`, if any. A scheme claimed by more than one plugin has no
    /// resolver — ask [`conflict`](Self::conflict) to tell that apart from nothing claiming it.
    pub(crate) fn resolver(&self, scheme: &str) -> Option<&ResolverPlugin> {
        self.resolvers.get(scheme)
    }

    /// The directory names claiming `scheme` when more than one does — all of them disabled.
    pub(crate) fn conflict(&self, scheme: &str) -> Option<&[String]> {
        self.conflicts.get(scheme).map(Vec::as_slice)
    }

    /// Every ambiguous scheme with its claimants, ordered by scheme.
    pub(crate) fn conflicts(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.conflicts
            .iter()
            .map(|(scheme, claimants)| (scheme.as_str(), claimants.as_slice()))
    }

    /// One line per ambiguous scheme, for a caller that relays diagnostics as text.
    pub(crate) fn conflict_warnings(&self) -> Vec<String> {
        self.conflicts
            .iter()
            .map(|(scheme, claimants)| {
                format!(
                    "plugins: scheme `{scheme}` is claimed by more than one plugin ({}) — all are \
                     disabled until one remains (a scheme must be unique)",
                    quoted_list(claimants)
                )
            })
            .collect()
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
            conflicts: BTreeMap::new(),
        }
    }
}

/// The raw `plugin.toml` manifest, before validation. Every field is optional so a missing
/// one yields a precise "missing X" error rather than a generic parse failure.
///
/// Unknown fields are **refused**, here and in [`RawSandbox`]. A manifest is a security
/// declaration read by a machine, so a key nothing reads is never a harmless extra: a
/// misspelled `program` or `allow_path` would otherwise be accepted in silence and leave the
/// author believing they had granted (or withheld) something they had not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
struct RawSandbox {
    #[serde(default)]
    programs: Vec<String>,
    #[serde(default)]
    allow_paths: Vec<String>,
    #[serde(default)]
    allow_env: Vec<String>,
    #[serde(default)]
    allow_env_paths: Vec<String>,
    #[serde(default)]
    mask_paths: Vec<String>,
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

    for program in &raw.sandbox.programs {
        validate_program_name(program)?;
    }
    let mut allow_paths = Vec::with_capacity(raw.sandbox.allow_paths.len());
    for entry in &raw.sandbox.allow_paths {
        if let Some(p) = expand_allow_path(entry, exp)? {
            allow_paths.push(p);
        }
    }
    let mut mask_paths = Vec::with_capacity(raw.sandbox.mask_paths.len());
    for entry in &raw.sandbox.mask_paths {
        if let Some(p) = expand_allow_path(entry, exp)? {
            mask_paths.push(p);
        }
    }
    for key in &raw.sandbox.allow_env {
        if !is_valid_env_key(key) {
            return Err(format!("`allow_env` has an invalid variable name `{key}`"));
        }
    }
    for key in &raw.sandbox.allow_env_paths {
        if !is_valid_env_key(key) {
            return Err(format!(
                "`allow_env_paths` has an invalid variable name `{key}`"
            ));
        }
        // Naming it here already passes it through, so listing it twice is not a harmless
        // redundancy: it is two declarations of one grant that a later edit can make disagree.
        // Refused rather than deduplicated, so the manifest keeps saying exactly one thing.
        if raw.sandbox.allow_env.iter().any(|e| e == key) {
            return Err(format!(
                "`{key}` is in both `allow_env` and `allow_env_paths` — `allow_env_paths` \
                 already passes the variable through, so list it there only"
            ));
        }
    }

    Ok(Some(ResolverPlugin {
        name,
        scheme,
        dir: dir.to_path_buf(),
        exec,
        sandbox: SandboxGrant {
            programs: raw.sandbox.programs,
            allow_paths,
            mask_paths,
            allow_env: raw.sandbox.allow_env,
            allow_env_paths: raw.sandbox.allow_env_paths,
            network: raw.sandbox.network,
        },
        version: raw.version,
        description: raw.description,
        // Filled in by the config layer once `[plugin.<name>]` has been layered and gated: a
        // manifest is loaded from disk with no notion of what this host answers.
        host: HostConfig::default(),
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

/// Validate a `programs` entry: a bare executable **name**, never a path. It is used twice, and
/// both uses demand it: as the needle for a `PATH` lookup, and as the file name the resolved
/// binary is bound under inside the cage. A separator or a `.`/`..` component would let a
/// manifest name a binary outside the search (or a destination outside the programs directory),
/// and a leading dot would hide it from the cage's `PATH` lookup.
pub(crate) fn validate_program_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("a `programs` entry is empty".to_string());
    }
    if name.starts_with('.') {
        return Err(format!(
            "`programs` entry `{name}` must not start with a dot"
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    {
        return Err(format!(
            "`programs` entry `{name}` must be a bare program name \
             (letters, digits, `.`, `_`, `-`, `+`; no path)"
        ));
    }
    Ok(())
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
fn expand_allow_path(raw: &str, exp: &Expansion) -> Result<Option<PathBuf>, String> {
    if raw.is_empty() {
        return Err("an `allow_paths` entry is empty".to_string());
    }
    let (head, rest) = match raw.split_once('/') {
        Some((h, r)) => (h, Some(r)),
        None => (raw, None),
    };
    let base = match head {
        // An unset variable **drops the entry** rather than refusing the plugin, which is the
        // same answer the mount already gives: every grant path is a `--ro-bind-try`, so a path
        // that is not there is skipped. Refusing here made the two disagree, and disabled a whole
        // plugin over one optional path — `$XDG_RUNTIME_DIR` is unset under cron, a session-less
        // ssh or a container, and that is exactly where GnuPG puts its agent socket inside
        // `$GNUPGHOME` instead, a path the same manifest already binds. Dropping is also the
        // fail-closed direction: the cage gets less, never more.
        "~" | "$HOME" => match exp.home.clone() {
            Some(h) => h,
            None => {
                crate::diag::warn(&format!("plugins: not binding `{raw}` — $HOME is not set"));
                return Ok(None);
            }
        },
        "$XDG_RUNTIME_DIR" => match exp.runtime.clone() {
            Some(r) => r,
            None => {
                crate::diag::warn(&format!(
                    "plugins: not binding `{raw}` — $XDG_RUNTIME_DIR is not set"
                ));
                return Ok(None);
            }
        },
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
            return Ok(Some(p));
        }
    };
    Ok(Some(match rest {
        Some(r) => base.join(r),
        None => base,
    }))
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
    // The recorded path is the source's canonical location, so a listing names a stable directory
    // rather than whatever relative form the command line used. A path that does not canonicalize
    // (or is not UTF-8) still installs — the origin simply records less.
    let path = std::fs::canonicalize(source)
        .unwrap_or_else(|_| source.to_path_buf())
        .to_str()
        .map(str::to_string);
    // The digest is filled in by the install itself, once the tree is in place.
    install_inner(
        layout,
        source,
        None,
        origin::Origin::Local { path, sha256: None },
        Placement::Fresh,
    )
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
    origin: origin::Origin,
) -> Result<Installed, String> {
    install_inner(
        layout,
        source,
        Some((expected_name, expected_scheme)),
        origin,
        Placement::Fresh,
    )
}

/// Replace an installed plugin with a newer tree from the same signed store — the placement behind
/// `sbx plugins upgrade`. Identical to [`install_from_store`] in every check it runs; it differs
/// only in what an existing plugin of that name means. The old tree is moved aside and kept until
/// the new one is in place, and restored if the swap fails, so an upgrade that cannot complete
/// leaves the plugin the user already had — the hole that `rm` followed by a fresh install opens.
pub(crate) fn replace_from_store(
    layout: &crate::store::Layout,
    source: &Path,
    expected_name: &str,
    expected_scheme: &str,
    origin: origin::Origin,
) -> Result<Installed, String> {
    install_inner(
        layout,
        source,
        Some((expected_name, expected_scheme)),
        origin,
        Placement::Replace,
    )
}

/// The shared body of [`install`] and [`install_from_store`]. `expect` is `Some((name, scheme))`
/// only for a store install, where the catalogue's advertised identity is reconciled against the
/// manifest before anything is placed; a local-directory or built-in install passes `None`.
/// `origin` is where the plugin came from, recorded once it is in place — passed in rather than
/// inferred from `source`, since a built-in install stages into a temp tree whose path says
/// nothing about its provenance.
///
/// `placement` decides what an existing plugin of that name means: a refusal (the install verbs,
/// where silently overwriting would discard a plugin the user did not ask to lose) or a
/// replacement (the upgrade verb, which exists to do exactly that).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// Refuse if the name is taken.
    Fresh,
    /// Swap the new tree in over the old one, keeping the old one until the swap succeeds.
    Replace,
}

fn install_inner(
    layout: &crate::store::Layout,
    source: &Path,
    expect: Option<(&str, &str)>,
    origin: origin::Origin,
    placement: Placement,
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

    // A local source is checked up front (fail fast, before anything is copied), but against a
    // *source* rule rather than the runner's: a regular file we own and that is not
    // world-writable. The runner's rule — which also refuses group-write — is the right one for
    // the artifact about to be executed, and the staged copy is held to it below after its modes
    // are canonicalized. It is the wrong one for a source tree: a `git clone` under the common
    // `umask 002` is group-writable throughout, so applying it here would refuse a plugin checked
    // out of its own repository. What stays refused is the case that is actually dangerous —
    // an executable *anyone* on the machine can rewrite between reading it and installing it.
    if expect.is_none() {
        verdict_source(&probe.exec)?;
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
    if dest.exists() && placement == Placement::Fresh {
        let held = origin::read(layout, &name);
        // The same source again is a re-install — what a user reaches for when a store's listing
        // has moved past the version they hold — so it earns the two-step way forward rather than
        // a bare collision message. A *different* source is the two-stores-one-name case: name the
        // holder, because "already installed" alone leaves the user guessing which they have.
        return Err(if held.same_source_as(&origin) {
            format!(
                "a plugin named `{name}` is already installed from {} — to replace it, remove it \
                 first with `sbx plugins rm {name}`, then install it again",
                held.short()
            )
        } else {
            format!(
                "a plugin named `{name}` is already installed (from {}) — remove it first with \
                 `sbx plugins rm {name}`",
                held.short()
            )
        });
    }

    // Refuse a scheme another installed plugin already claims: placing it would make the registry
    // drop *both* as ambiguous, so the install would "succeed" into a silently dead plugin. Both
    // states are refused — a scheme claimed by one plugin, and a scheme already ambiguous — so an
    // install never adds a claimant to a namespace that is broken or about to be.
    let mut warnings = Vec::new();
    let installed = PluginRegistry::load_with(&plugins_dir, &exp, &mut warnings);
    if let Some(claimants) = installed.conflict(&probe.scheme) {
        return Err(format!(
            "scheme `{}://` is claimed by more than one installed plugin ({}) — they are all \
             disabled; remove all but one with `sbx plugins rm <name>` first",
            probe.scheme,
            quoted_list(claimants)
        ));
    }
    if let Some(other) = installed.resolver(&probe.scheme)
        && other.dir != dest
    {
        let holder = other.dir_name();
        return Err(format!(
            "scheme `{}://` is already claimed by the installed plugin `{}` (from {}) — \
                 remove it first with `sbx plugins rm {holder}`",
            probe.scheme,
            other.name,
            origin::read(layout, holder).short()
        ));
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
    // A source tree carries whatever modes produced it — a `git clone` or a checkout under the
    // caller's umask — while git records only the executable bit. Canonicalize the staged copy so
    // an installed plugin's permissions are deterministic and owner-clean (an executable file
    // `0755`, everything else `0644`), whatever the source looked like. The distinction that
    // matters is preserved, and the strict check below runs on the result.
    if let Err(e) = canonicalize_modes(&stage) {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(e);
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

    // A replacement moves the old tree aside first — `rename` cannot overwrite a non-empty
    // directory — and keeps it until the new one is in place. If the swap fails, the old plugin is
    // moved back: a failed upgrade must be a non-event, never the "removed, then failed to
    // install" hole that doing this with `rm` + install leaves.
    let displaced = if placement == Placement::Replace && dest.exists() {
        let aside =
            layout
                .data_dir()
                .join(format!(".plugin-old-{}-{}", std::process::id(), unique()));
        if let Err(e) = std::fs::rename(&dest, &aside) {
            let _ = std::fs::remove_dir_all(&stage);
            return Err(format!("could not set the installed plugin aside: {e}"));
        }
        Some(aside)
    } else {
        None
    };

    match std::fs::rename(&stage, &dest) {
        Ok(()) => {
            if let Some(aside) = &displaced {
                let _ = std::fs::remove_dir_all(aside);
            }
            // Record the provenance only once the plugin is in place: a record without a plugin
            // would be inherited by a later install of that name, so a wrong origin is worse than
            // no origin. A failure here does not fail the install — the plugin is installed and
            // usable; only the listing loses a detail — but it is never silent.
            //
            // The digest is of the tree *as placed*, not of the source: the staged copy had its
            // modes canonicalized, so only what was actually installed can later be compared
            // against it. A tree that cannot be hashed leaves no digest rather than a wrong one.
            let origin = origin.with_digest(
                catalogue::dir_digest(&dest)
                    .ok()
                    .map(|d| catalogue::to_hex(&d)),
            );
            if let Err(why) = origin::record(layout, &name, &origin) {
                crate::diag::warn(&format!(
                    "plugin `{name}` is installed, but its origin could not be recorded \
                     ({why}) — `sbx plugins list` will show it as unknown"
                ));
            }
            Ok(Installed {
                name,
                scheme: probe.scheme,
            })
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&stage);
            // Put the displaced plugin back before reporting: the caller asked for a newer tree,
            // not for the loss of the one they had.
            if let Some(aside) = &displaced {
                if let Err(why) = std::fs::rename(aside, &dest) {
                    return Err(format!(
                        "could not place the new plugin ({e}), and the installed one could not be \
                         restored ({why}) — it is at {}",
                        aside.display()
                    ));
                }
                return Err(format!(
                    "could not place the new plugin ({e}) — the installed one is untouched"
                ));
            }
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

/// Whether an installed plugin's tree still hashes to what was recorded when it was placed.
///
/// This is **drift detection, not a security control**, and the distinction is load-bearing: the
/// record lives in the same owner-only tree as the plugin, so anything able to rewrite the plugin
/// can rewrite the record too. What it catches is the accident — a plugin edited in place to debug
/// it and forgotten, a careless third-party process — which is exactly the case a silent registry
/// would leave a user guessing about. It is never consulted on the launch path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Integrity {
    /// The tree hashes to the digest recorded at install.
    Intact,
    /// It does not: the tree changed after it was placed.
    Modified,
    /// No digest is recorded — installed before sbx recorded one, or placed by hand. Distinct from
    /// `Intact`: nothing was checked, so nothing is attested.
    Unrecorded,
    /// The tree could not be hashed at all (a symlink appeared in it, a file became unreadable),
    /// which is itself a change worth naming rather than swallowing.
    Unreadable(String),
}

/// Compare an installed plugin's tree against the digest its origin record holds. `dir_name` is the
/// plugin's directory name — the token `rm` takes — not the manifest's `name`.
pub(crate) fn integrity(layout: &crate::store::Layout, dir_name: &str) -> Integrity {
    let Some(recorded) = origin::read(layout, dir_name).digest().map(str::to_string) else {
        return Integrity::Unrecorded;
    };
    match catalogue::dir_digest(&layout.plugins_dir().join(dir_name)) {
        Err(why) => Integrity::Unreadable(why),
        Ok(digest) if catalogue::to_hex(&digest) == recorded => Integrity::Intact,
        Ok(_) => Integrity::Modified,
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
    // The provenance record outlives the tree it describes (it is deliberately stored outside it),
    // so drop it here — otherwise a later install of that name would start with a stale origin
    // until it writes its own.
    origin::forget(layout, name);
    // The out-links for any program provisioned for this plugin are outside the tree for the same
    // reason, and outlive it the same way. An out-link left behind keeps a whole closure live in
    // the store, invisibly: nix's own root is indirect, so it stays valid exactly as long as the
    // link does, and nothing else would ever name the plugin it was built for.
    programs::forget(layout, name);
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
    fn a_mask_path_is_expanded_like_a_grant_path_and_kept_separate_from_it() {
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
                allow_paths = ["~/.gnupg"]
                mask_paths  = ["~/.gnupg/private-keys-v1.d"]
            "#,
        );
        let (reg, warnings) = load(root.path());
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        let p = reg.resolver("pass").expect("pass resolver");
        // The same `~` expansion as a grant path, so a manifest names one directory one way.
        assert_eq!(
            p.sandbox.mask_paths,
            vec![PathBuf::from("/home/u/.gnupg/private-keys-v1.d")]
        );
        // And it stays out of `allow_paths`: a mask must never read as one more thing granted.
        assert_eq!(p.sandbox.allow_paths, vec![PathBuf::from("/home/u/.gnupg")]);
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
    fn loads_declared_programs() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "vault",
            r#"
                type   = "resolver"
                scheme = "vault"
                exec   = "resolve"
                [sandbox]
                programs    = ["vault", "curl"]
                allow_paths = ["~/.vault-token"]
            "#,
        );
        let (reg, warnings) = load(root.path());
        assert!(warnings.is_empty(), "{warnings:?}");
        let p = reg.resolver("vault").expect("vault resolver");
        assert_eq!(p.sandbox.programs, vec!["vault".to_string(), "curl".into()]);
        // A binary belongs in `programs`; `allow_paths` keeps only the data.
        assert_eq!(
            p.sandbox.allow_paths,
            vec![PathBuf::from("/home/u/.vault-token")]
        );
    }

    #[test]
    fn loads_env_paths_a_user_can_redirect_a_grant_with() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "pass",
            r#"
                type   = "resolver"
                scheme = "pass"
                exec   = "resolve"
                [sandbox]
                allow_paths     = ["~/.password-store"]
                allow_env_paths = ["PASSWORD_STORE_DIR", "GNUPGHOME"]
            "#,
        );
        let (reg, warnings) = load(root.path());
        assert!(warnings.is_empty(), "{warnings:?}");
        let p = reg.resolver("pass").expect("pass resolver");
        assert_eq!(
            p.sandbox.allow_env_paths,
            vec!["PASSWORD_STORE_DIR".to_string(), "GNUPGHOME".to_string()]
        );
        // The manifest's own default survives alongside it: the variable moves the grant for the
        // user who sets one, and changes nothing for everyone else.
        assert_eq!(
            p.sandbox.allow_paths,
            vec![PathBuf::from("/home/u/.password-store")]
        );
    }

    #[test]
    fn a_variable_in_both_env_lists_is_refused() {
        // `allow_env_paths` already passes the variable through, so listing it twice is two
        // declarations of one grant that a later edit can make disagree.
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "p",
            "type = \"resolver\"\nscheme = \"p\"\nexec = \"resolve\"\n\
             [sandbox]\nallow_env = [\"GNUPGHOME\"]\nallow_env_paths = [\"GNUPGHOME\"]\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("p").is_none());
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("allow_env_paths") && w.contains("GNUPGHOME")),
            "the refusal names the field and the variable: {warnings:?}"
        );
    }

    #[test]
    fn an_invalid_env_path_variable_name_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write_plugin(
            root.path(),
            "p",
            "type = \"resolver\"\nscheme = \"p\"\nexec = \"resolve\"\n\
             [sandbox]\nallow_env_paths = [\"2BAD\"]\n",
        );
        let (reg, warnings) = load(root.path());
        assert!(reg.resolver("p").is_none());
        assert!(
            warnings.iter().any(|w| w.contains("allow_env_paths")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_program_that_is_a_path_is_refused() {
        // A path here would name a binary the `PATH` search never chose, and a `..` would land the
        // bind outside the cage's programs directory.
        for bad in ["/usr/bin/vault", "../vault", "sub/vault", ".hidden"] {
            let root = crate::testutil::TmpDir::new();
            write_plugin(
                root.path(),
                "p",
                &format!(
                    "type = \"resolver\"\nscheme = \"p\"\nexec = \"resolve\"\n\
                     [sandbox]\nprograms = [\"{bad}\"]\n"
                ),
            );
            let (reg, warnings) = load(root.path());
            assert!(reg.resolver("p").is_none(), "`{bad}` must be refused");
            assert!(
                warnings.iter().any(|w| w.contains("programs")),
                "the refusal names the field for `{bad}`: {warnings:?}"
            );
        }
    }

    #[test]
    fn an_unknown_manifest_field_is_refused_rather_than_ignored() {
        // A manifest is a security declaration: a key nothing reads must not pass in silence, or a
        // misspelled `program`/`allow_path` leaves the author believing they granted something.
        for manifest in [
            "type = \"resolver\"\nscheme = \"p\"\nexec = \"resolve\"\naliases = [\"q\"]\n",
            "type = \"resolver\"\nscheme = \"p\"\nexec = \"resolve\"\n[sandbox]\nprogram = [\"x\"]\n",
        ] {
            let root = crate::testutil::TmpDir::new();
            write_plugin(root.path(), "p", manifest);
            let (reg, warnings) = load(root.path());
            assert!(reg.resolver("p").is_none(), "{manifest}");
            assert!(
                warnings.iter().any(|w| w.contains("invalid plugin.toml")),
                "{warnings:?}"
            );
        }
    }

    #[test]
    fn a_colliding_scheme_drops_both_plugins_and_names_them_by_directory() {
        let root = crate::testutil::TmpDir::new();
        // The first calls itself something else in its manifest: the remedy is
        // `sbx plugins rm <directory>`, so that is what a conflict must name.
        write_plugin(
            root.path(),
            "a-vault",
            "name = \"vault-one\"\ntype = \"resolver\"\nscheme = \"vault\"\nexec = \"resolve\"\n",
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
        assert_eq!(
            reg.conflict("vault"),
            Some(&["a-vault".to_string(), "b-vault".to_string()][..])
        );
        assert!(
            warnings.is_empty(),
            "a conflict is state, not a per-plugin validation warning: {warnings:?}"
        );
        let text = reg.conflict_warnings();
        assert_eq!(text.len(), 1, "{text:?}");
        assert!(text[0].contains("`a-vault`, `b-vault`"), "{text:?}");
    }

    #[test]
    fn three_plugins_one_scheme_all_dropped_and_all_named() {
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
        // The third claimant is recorded too — a report listing only the first two would leave the
        // user removing one plugin and still holding a conflict.
        assert_eq!(
            reg.conflict("dup"),
            Some(&["a".to_string(), "b".to_string(), "c".to_string()][..])
        );
        let text = reg.conflict_warnings();
        assert_eq!(text.len(), 1, "one line per scheme, not per pair: {text:?}");
        assert!(text[0].contains("`a`, `b`, `c`"), "{text:?}");
    }

    #[test]
    fn the_text_form_of_load_relays_the_conflict() {
        // A caller that only relays diagnostics (a launch, a config load) must still hear about an
        // ambiguous scheme — it silently disables a plugin the project's config may depend on.
        let root = crate::testutil::TmpDir::new();
        for n in ["one", "two"] {
            write_plugin(
                root.path(),
                n,
                "type = \"resolver\"\nscheme = \"vault\"\nexec = \"resolve\"\n",
            );
        }
        let mut warnings = Vec::new();
        let reg = PluginRegistry::load(root.path(), &mut warnings);
        assert!(reg.resolver("vault").is_none());
        assert!(
            warnings.iter().any(
                |w| w.contains("claimed by more than one plugin") && w.contains("`one`, `two`")
            ),
            "{warnings:?}"
        );
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
    fn an_unset_variable_drops_its_entry_instead_of_refusing_the_plugin() {
        // An entry needing an unset variable is dropped, not fatal. Refusing disabled the whole
        // plugin over one optional path: `$XDG_RUNTIME_DIR` is unset under cron, a session-less
        // ssh or a container, and `pass://` then vanished from the registry entirely. Dropping
        // matches what the mount already does — every grant path is a `--ro-bind-try`, so an
        // absent one is skipped — and it only ever gives the cage *less*. The runner warns, so
        // the narrower grant is stated rather than silent.
        let exp = Expansion {
            home: Some(PathBuf::from("/home/u")),
            runtime: None,
        };
        assert_eq!(
            expand_allow_path("$XDG_RUNTIME_DIR/gnupg", &exp).unwrap(),
            None
        );
        assert_eq!(
            expand_allow_path("~/.ssh", &exp).unwrap(),
            Some(PathBuf::from("/home/u/.ssh"))
        );
        // A malformed entry is still an error: it can never be right on any host, while an unset
        // variable is a fact about this one.
        assert!(expand_allow_path("relative/path", &exp).is_err());
        assert!(expand_allow_path("$SECRET_DIR/x", &exp).is_err());
    }

    #[test]
    fn a_bare_home_or_runtime_token_expands() {
        let exp = Expansion {
            home: Some(PathBuf::from("/home/u")),
            runtime: Some(PathBuf::from("/run/user/1000")),
        };
        assert_eq!(
            expand_allow_path("$HOME", &exp).unwrap(),
            Some(PathBuf::from("/home/u"))
        );
        assert_eq!(
            expand_allow_path("$XDG_RUNTIME_DIR", &exp).unwrap(),
            Some(PathBuf::from("/run/user/1000"))
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
        assert!(
            verdict_exec(reg | 0o755, 1234, 1000)
                .unwrap_err()
                .contains("owned by uid 1234")
        );
        // group-writable is refused here (stricter than the config gate)
        assert!(
            verdict_exec(reg | 0o775, 1000, 1000)
                .unwrap_err()
                .contains("group or other")
        );
        assert!(
            verdict_exec(reg | 0o777, 1000, 1000)
                .unwrap_err()
                .contains("group or other")
        );
        // a directory (no S_IFREG) is refused
        assert!(
            verdict_exec(libc::S_IFDIR | 0o755, 1000, 1000)
                .unwrap_err()
                .contains("not a regular file")
        );
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
    /// The provenance a store install carries, for the tests that exercise the store path. The
    /// store subsystem builds the real one from the configured store and the catalogue entry.
    fn store_origin() -> origin::Origin {
        origin::Origin::Store {
            store: "mine".to_string(),
            url: Some("https://example.invalid/plugins.git".to_string()),
            sha256: Some("b".repeat(64)),
        }
    }

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
    fn install_refuses_a_world_writable_executable_but_places_a_group_writable_one_owner_only() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let manifest = "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n";

        // World-writable: anyone on the machine could swap the program between reading it and
        // installing it. Refused, and nothing is placed.
        let open = source_plugin(src_root.path(), "open", manifest, 0o777);
        let err = install(&layout, &open).unwrap_err();
        assert!(err.contains("writable by anyone"), "{err}");
        assert!(err.contains("chmod o-w"), "the fix is named: {err}");
        assert!(!layout.plugins_dir().join("open").exists());

        // Group-writable is what a checkout under the common `umask 002` looks like, so a plugin
        // must install from its own repository. What lands is owner-only regardless of the source.
        use std::os::unix::fs::PermissionsExt;
        let shared = source_plugin(src_root.path(), "shared", manifest, 0o775);
        install(&layout, &shared).expect("a group-writable source installs");
        // The manifest names no `name`, so it installs under its source directory name.
        let placed = layout.plugins_dir().join("shared/resolve");
        let mode = std::fs::metadata(&placed).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o755,
            "the placed executable is canonicalized, whatever the source mode was"
        );
        // ...and it passes the runner's own, stricter check — the one that governs execution.
        let mut warnings = Vec::new();
        let reg = PluginRegistry::load(&layout.plugins_dir(), &mut warnings);
        assert!(reg.resolver("pass").unwrap().check_exec().is_ok());
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
        // Both are local installs — the same source — so the refusal offers the way to replace it
        // rather than only naming the collision.
        assert!(err.contains("then install it again"), "{err}");
    }

    #[test]
    fn a_collision_with_a_different_source_names_the_holder() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // A store placed `vault`; a local directory then claims that name. The refusal has to say
        // who holds it, since the user has two plausible sources in mind.
        let from_store = source_plugin(
            src_root.path(),
            "checkout",
            "name=\"vault\"\ntype=\"resolver\"\nscheme=\"secret-store\"\nexec=\"resolve\"\n",
            0o755,
        );
        install_from_store(
            &layout,
            &from_store,
            "vault",
            "secret-store",
            store_origin(),
        )
        .expect("install from the store");
        let local = source_plugin(
            src_root.path(),
            "mine",
            "name=\"vault\"\ntype=\"resolver\"\nscheme=\"other\"\nexec=\"resolve\"\n",
            0o755,
        );
        let err = install(&layout, &local).unwrap_err();
        assert!(
            err.contains("already installed (from store 'mine')"),
            "{err}"
        );
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
    fn install_refuses_a_scheme_that_is_already_in_conflict() {
        // The only way into a conflict is a hand-placed tree, so stage one: two directories under
        // the plugins dir claiming one scheme. Neither resolves, so a guard that only asked "does
        // this scheme resolve?" would wave a third claimant in and deepen the breakage.
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        for n in ["one", "two"] {
            let src = source_plugin(
                src_root.path(),
                n,
                &format!("name=\"{n}\"\ntype=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n"),
                0o755,
            );
            copy_tree(&src, &layout.plugins_dir().join(n)).expect("hand-place");
        }
        let third = source_plugin(
            src_root.path(),
            "three",
            "name=\"three\"\ntype=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
            0o755,
        );
        let err = install(&layout, &third).unwrap_err();
        assert!(
            err.contains("claimed by more than one installed plugin (`one`, `two`)"),
            "{err}"
        );
        assert!(!layout.plugins_dir().join("three").exists());

        // And the way out works: with one claimant left, the scheme resolves again.
        remove(&layout, "two").expect("remove one claimant");
        let (reg, _warnings) = load(&layout.plugins_dir());
        assert_eq!(reg.resolver("vault").map(|p| p.name.as_str()), Some("one"));
        assert!(reg.conflict("vault").is_none());
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
            install_from_store(&layout, &source, "pass", "secret-store", store_origin())
                .expect("install");
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
        let err = install_from_store(&layout, &source, "other", "secret-store", store_origin())
            .unwrap_err();
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
        let err =
            install_from_store(&layout, &source, "pass", "vault", store_origin()).unwrap_err();
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
    fn each_install_path_records_where_the_plugin_came_from() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());

        // A local directory records its canonical path, so a listing names a stable location.
        let source = source_plugin(
            src_root.path(),
            "kp",
            "type=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n",
            0o755,
        );
        install(&layout, &source).expect("install");
        let placed = catalogue::to_hex(
            &catalogue::dir_digest(&layout.plugins_dir().join("kp")).expect("hash the placed tree"),
        );
        assert_eq!(
            origin::read(&layout, "kp"),
            origin::Origin::Local {
                path: Some(
                    std::fs::canonicalize(&source)
                        .unwrap()
                        .display()
                        .to_string()
                ),
                // The digest is of the tree as installed — the staged copy had its modes
                // canonicalized, so only that tree can later be compared against it.
                sha256: Some(placed),
            }
        );

        // A store install records the store, not the checkout it was copied from — and the digest
        // of what it placed, so both install paths are equally verifiable afterwards.
        let from_store = source_plugin(
            src_root.path(),
            "checkout",
            "name=\"pass\"\ntype=\"resolver\"\nscheme=\"secret-store\"\nexec=\"resolve\"\n",
            0o755,
        );
        install_from_store(&layout, &from_store, "pass", "secret-store", store_origin())
            .expect("install");
        let recorded = origin::read(&layout, "pass");
        assert!(recorded.is_store("mine"), "{recorded:?}");
        assert_eq!(
            recorded.digest(),
            Some(
                catalogue::to_hex(
                    &catalogue::dir_digest(&layout.plugins_dir().join("pass")).unwrap()
                )
                .as_str()
            )
        );
    }

    #[test]
    fn a_replacement_swaps_the_tree_and_re_records_its_digest() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let manifest = "name=\"kp\"\ntype=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n";
        let first = source_plugin(src_root.path(), "v1", manifest, 0o755);
        install_from_store(&layout, &first, "kp", "kp", store_origin()).expect("install");
        assert_eq!(integrity(&layout, "kp"), Integrity::Intact);

        // A second tree under the same name: a fresh install refuses it, a replacement is what the
        // upgrade verb needs.
        let second = source_plugin(src_root.path(), "v2", manifest, 0o755);
        fs::write(second.join("resolve"), "#!/bin/sh\necho newer\n").unwrap();
        let err = install_from_store(&layout, &second, "kp", "kp", store_origin()).unwrap_err();
        assert!(err.contains("already installed"), "{err}");
        replace_from_store(&layout, &second, "kp", "kp", store_origin()).expect("replace");

        // The placed tree is the new one, and the record follows it — otherwise the next `verify`
        // would call a correctly-upgraded plugin modified.
        let placed = fs::read_to_string(layout.plugins_dir().join("kp/resolve")).unwrap();
        assert!(placed.contains("newer"), "{placed}");
        assert_eq!(integrity(&layout, "kp"), Integrity::Intact);
        // Nothing is left behind in the data dir by the swap.
        let leaked: Vec<_> = fs::read_dir(data.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                n.starts_with(".plugin-old-") || n.starts_with(".plugin-stage-")
            })
            .collect();
        assert!(leaked.is_empty(), "a swap temp leaked: {leaked:?}");
    }

    #[test]
    fn a_refused_replacement_leaves_the_installed_plugin_in_place() {
        // The property the verb exists for: `rm` followed by an install deletes first, so a failure
        // after it leaves nothing. A replacement must be a non-event when it cannot complete.
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let good = source_plugin(
            src_root.path(),
            "v1",
            "name=\"kp\"\ntype=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n",
            0o755,
        );
        install_from_store(&layout, &good, "kp", "kp", store_origin()).expect("install");

        // A candidate whose manifest disagrees with the catalogue's advertised identity — the same
        // reconciliation an install runs, refused just as hard.
        let bad = source_plugin(
            src_root.path(),
            "v2",
            "name=\"impostor\"\ntype=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n",
            0o755,
        );
        let err = replace_from_store(&layout, &bad, "kp", "kp", store_origin()).unwrap_err();
        assert!(err.contains("refusing the mismatch"), "{err}");

        // Still installed, still the tree that was there, still matching its record.
        let (reg, _w) = load(&layout.plugins_dir());
        assert_eq!(reg.resolver("kp").map(|p| p.name.as_str()), Some("kp"));
        assert_eq!(integrity(&layout, "kp"), Integrity::Intact);
    }

    #[test]
    fn integrity_reports_intact_then_modified_then_intact_again() {
        let data = crate::testutil::TmpDir::new();
        let src_root = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let source = source_plugin(
            src_root.path(),
            "kp",
            "type=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n",
            0o755,
        );
        install(&layout, &source).expect("install");
        assert_eq!(integrity(&layout, "kp"), Integrity::Intact);

        // The manifest is the sharpest case: it carries the sandbox grant, so editing it in place
        // is a privilege change the registry would otherwise honor without a word.
        let manifest = layout.plugins_dir().join("kp/plugin.toml");
        fs::write(
            &manifest,
            "type=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n[sandbox]\nnetwork=true\n",
        )
        .unwrap();
        assert_eq!(integrity(&layout, "kp"), Integrity::Modified);

        // Reinstalling restores a known tree, and with it a matching record.
        remove(&layout, "kp").expect("remove");
        install(&layout, &source).expect("reinstall");
        assert_eq!(integrity(&layout, "kp"), Integrity::Intact);
    }

    #[test]
    fn integrity_separates_unrecorded_and_unhashable_from_modified() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // Hand-placed: no record, so nothing was ever attested. That is not the same answer as
        // "this changed", and it must not be reported as one.
        let dir = layout.plugins_dir().join("handmade");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            "type=\"resolver\"\nscheme=\"hm\"\nexec=\"resolve\"\n",
        )
        .unwrap();
        fs::write(dir.join("resolve"), "#!/bin/sh\n").unwrap();
        assert_eq!(integrity(&layout, "handmade"), Integrity::Unrecorded);

        // A tree that cannot be hashed at all is named as such, never silently passed: a symlink
        // appearing inside an installed plugin is itself a change.
        let src_root = crate::testutil::TmpDir::new();
        let source = source_plugin(
            src_root.path(),
            "kp",
            "type=\"resolver\"\nscheme=\"kp\"\nexec=\"resolve\"\n",
            0o755,
        );
        install(&layout, &source).expect("install");
        std::os::unix::fs::symlink("/etc/passwd", layout.plugins_dir().join("kp/leak")).unwrap();
        assert!(matches!(integrity(&layout, "kp"), Integrity::Unreadable(_)));
    }

    #[test]
    fn removing_a_plugin_drops_its_origin_record() {
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
        assert!(matches!(
            origin::read(&layout, "pass"),
            origin::Origin::Local { .. }
        ));
        remove(&layout, "pass").expect("remove");
        // The record lives outside the tree that was removed, so it has to be dropped explicitly —
        // otherwise a later local install of that name would inherit the stale provenance.
        assert_eq!(origin::read(&layout, "pass"), origin::Origin::Unknown);
    }

    #[test]
    fn the_origin_records_are_invisible_to_discovery() {
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
        // The records sit in a dot-prefixed directory *under* the plugins directory, which the
        // registry must skip silently — not warn about, and certainly not load.
        let (reg, warnings) = load(&layout.plugins_dir());
        assert_eq!(reg.resolvers().count(), 1);
        assert!(warnings.is_empty(), "{warnings:?}");
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
}
