//! The thin I/O layer around the pure [`super::resolve`]: read the global and project
//! config files (and imported profiles) from disk, canonicalize and control-plane-pin the
//! resolved binds, and expose the profile preview/export helpers. This is the one place
//! that ties a project's bytes, its trust verdict, and its parse together so all three act
//! on the same inode.

use super::*;

/// Which configuration layers feed a resolution. `All` is what a launch and the full `sbx config
/// show` use; the restricted forms back the single-source `sbx config show --global/--local/
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
        merge_profile_apps(&mut global, profiles, &mut warnings);
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
    // consumes the project layer. A mise file is anchored on the `.sbx.toml`: with no
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
    // resolved — so `binds` is the *effective* list, identical to what the
    // launch will bind, and `sbx config` cannot advertise a bind the launch would
    // silently skip. Following symlinks here also pins each source against a swap.
    // The bind's read-only/read-write mode carries through unchanged; the per-layer
    // provenance is re-keyed from the raw declared path to the canonical one as we go,
    // so a lookup against the displayed (canonical) path resolves.
    let sbx_roots = sbx_control_plane_roots();
    let declared = std::mem::take(&mut resolved.binds);
    let raw_layer = std::mem::take(&mut resolved.bind_layer);
    let mut canon_binds: Vec<Bind> = Vec::with_capacity(declared.len());
    let mut canon_layer = BTreeMap::new();
    for bind in declared {
        let Some(canon) = canonicalize_one(&bind.path, &mut resolved.warnings) else {
            continue;
        };
        // A read-write bind overlapping sbx's own control plane is either forced read-only (a bind
        // at or under a root — fail closed: writing there is host-side code execution or a forged
        // trust/config, beyond the accepted self-harm class) or kept read-write with its
        // control-plane paths pinned in place by the launcher (a bind that merely contains a root).
        let writable = control_plane_mode(
            canon.as_path(),
            bind.writable,
            &sbx_roots,
            &mut resolved.warnings,
        );
        if let Some(layer) = raw_layer.get(&bind.path) {
            canon_layer.insert(canon.clone(), *layer);
        }
        // Merge by canonical path: the last declaration of a path wins (project over global),
        // updated in place so a destination is never mounted twice — matching how `merge_app`
        // folds an app's binds, so `sbx config` shows exactly what the launch mounts.
        if let Some(existing) = canon_binds.iter_mut().find(|b| b.path == canon) {
            existing.writable = writable;
        } else {
            canon_binds.push(Bind {
                path: canon,
                writable,
            });
        }
    }
    // Nesting warnings once per effective bind (after dedup, so the reported mode is the one the
    // launch will use): a bind that nests with a structural mount will not behave as declared (a
    // descendant is shadowed, an ancestor over-exposes). Trusted-only field, so this warns
    // without dropping the bind.
    for bind in &canon_binds {
        if let Some(w) = crate::sandbox::structural_nesting_warning(&bind.path, bind.writable) {
            resolved.warnings.push(w);
        }
    }
    resolved.binds = canon_binds;
    resolved.bind_layer = canon_layer;

    // Each app's binds are canonicalized the same way, into that app's own warnings — so an
    // app overlay also advertises only the binds the launch would actually make.
    for app in resolved.apps.values_mut() {
        let declared = std::mem::take(&mut app.binds);
        app.binds = canonicalize_binds(declared, &sbx_roots, &mut app.warnings);
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

/// Canonicalize each bind source, dropping with a warning any that cannot be resolved; resolving a
/// read-write bind that overlaps an sbx control-plane root (forced read-only when it is at or under
/// one, kept read-write with its control-plane paths pinned when it merely contains one — see
/// [`control_plane_mode`]); de-duplicating by canonical path (last wins); and warning (without
/// dropping) any whose destination nests with a structural mount. The same treatment the baseline
/// binds get, so an app overlay advertises exactly what its launch would mount.
pub(super) fn canonicalize_binds(
    binds: Vec<Bind>,
    roots: &[PathBuf],
    warnings: &mut Vec<String>,
) -> Vec<Bind> {
    let mut out: Vec<Bind> = Vec::with_capacity(binds.len());
    for bind in binds {
        let Some(canon) = canonicalize_one(&bind.path, warnings) else {
            continue;
        };
        let writable = control_plane_mode(canon.as_path(), bind.writable, roots, warnings);
        if let Some(existing) = out.iter_mut().find(|b| b.path == canon) {
            existing.writable = writable;
        } else {
            out.push(Bind {
                path: canon,
                writable,
            });
        }
    }
    for bind in &out {
        if let Some(w) = crate::sandbox::structural_nesting_warning(&bind.path, bind.writable) {
            warnings.push(w);
        }
    }
    out
}

/// The sbx-owned control-plane roots a read-write config bind must never expose to the cage: the
/// data directory (its engine binaries are `execve`'d host-side; its plugin and store trees run
/// host-side too), the trust-marker store (a forged marker would approve another project's config),
/// and the global-config directory (trusted by location). Resolved from the environment like every
/// other sbx path; a component whose base does not resolve is simply omitted.
pub(super) fn sbx_control_plane_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(layout) = crate::store::Layout::from_env() {
        roots.push(layout.data_dir().to_path_buf());
    }
    if let Some(trusted) = trust::default_store_dir() {
        roots.push(trusted);
    }
    if let Some(dir) = global_path().and_then(|p| p.parent().map(Path::to_path_buf)) {
        roots.push(dir);
    }
    // Canonicalize best-effort: a config bind is compared canonicalized (symlinks resolved), so the
    // roots must be too, or a symlinked `$HOME` component would let a bind slip past the guard. A
    // root that does not exist yet keeps its raw form (nothing to resolve).
    roots
        .into_iter()
        .map(|r| r.canonicalize().unwrap_or(r))
        .collect()
}

/// Decide the read-write mode of a config bind `canon` that may overlap sbx's control plane, and
/// warn. Three cases, resolved in this order so the fail-closed one wins any ambiguity:
///
/// - The bind is **at or under** a control-plane root: the whole bind is control plane, there is
///   nothing to keep writable, so it is forced **read-only** with a warning naming the consequence.
///   Fail closed — a writable bind there is host-side code execution or a forged trust/config,
///   beyond the accepted (single-project, self-harm) class.
/// - The bind **strictly contains** one or more roots: it stays **read-write** — the launcher pins
///   each contained root's path in place ([`control_plane_pins`]), so the cage cannot substitute
///   what sbx runs or trusts on the host while the rest of the bound tree stays writable. An
///   informational note names the protected paths.
/// - The bind is unrelated to the control plane: its mode is returned unchanged.
///
/// The two overlaps are checked in the above order because the root set is disjoint (no root
/// contains another), so a bind cannot be both — but checking the read-only case first means any
/// future overlap defaults to the safe direction.
fn control_plane_mode(
    canon: &Path,
    writable: bool,
    roots: &[PathBuf],
    warnings: &mut Vec<String>,
) -> bool {
    if !writable {
        return false;
    }
    // At or under a root: the bind is entirely control plane → read-only.
    if let Some(root) = roots.iter().find(|r| canon.starts_with(r)) {
        warnings.push(format!(
            "bind `{}` is read-write over sbx's own control plane `{}` — binding it read-only \
             instead (a writable bind there could alter what sbx runs or trusts on the host)",
            canon.display(),
            root.display()
        ));
        return false;
    }
    // Strictly contains one or more roots: stays read-write; the launcher pins those roots' host
    // paths so the cage cannot rename a writable parent to substitute them.
    let contained: Vec<String> = roots
        .iter()
        .filter(|r| r.starts_with(canon) && r.as_path() != canon)
        .map(|r| r.display().to_string())
        .collect();
    if !contained.is_empty() {
        warnings.push(format!(
            "bind `{}` is read-write and contains sbx's own control plane ({}) — the tree stays \
             writable, but those paths are pinned read-only in place so the cage cannot alter what \
             sbx runs or trusts on the host",
            canon.display(),
            contained.join(", ")
        ));
    }
    true
}

/// The mountpoint-chain pins that protect sbx's control plane from path substitution when a
/// read-write bind strictly contains it. Without them a read-write ancestor bind lets in-cage code
/// rename a writable parent directory to move a control-plane root aside and recreate a forged one
/// at the same host path — which sbx would then read or `execve` on its next run. Each root is
/// pinned by making every path component below the containing bind a mountpoint (a mountpoint
/// cannot be renamed or removed — the kernel refuses with `EBUSY`): the intermediates read-write
/// (the rest of the tree stays writable), the root itself read-only (its host contents cannot be
/// written through).
///
/// Returns those mounts as host binds (source == destination), deduplicated and ordered
/// shallow-to-deep so a parent mountpoint is always established before its child — a child bound
/// first would be shadowed when the parent is later mounted over it, silently defeating the
/// protection. The caller binds them last (the final word on those paths) and creates each before
/// binding (a root the agent could otherwise create fresh). Iterates the same root set as
/// [`control_plane_mode`], so a root added there is pinned here automatically.
pub(crate) fn control_plane_pins(binds: &[Bind]) -> Vec<Bind> {
    control_plane_pins_for(binds, &sbx_control_plane_roots())
}

/// The pure core of [`control_plane_pins`], taking the roots explicitly so it is testable without
/// the environment.
fn control_plane_pins_for(binds: &[Bind], roots: &[PathBuf]) -> Vec<Bind> {
    let mut pins: Vec<Bind> = Vec::new();
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for bind in binds.iter().filter(|b| b.writable) {
        for root in roots
            .iter()
            .filter(|r| r.starts_with(&bind.path) && r.as_path() != bind.path)
        {
            // Each directory strictly between the containing bind and the root, shallow-to-deep: a
            // mountpoint (read-write) so it cannot be renamed to substitute the path below it.
            for ancestor in ancestors_between(&bind.path, root) {
                if seen.insert(ancestor.clone()) {
                    pins.push(Bind {
                        path: ancestor,
                        writable: true,
                    });
                }
            }
            // The root itself, read-only: a mountpoint (cannot be renamed/removed) whose host
            // contents also cannot be written through.
            if seen.insert(root.clone()) {
                pins.push(Bind {
                    path: root.clone(),
                    writable: false,
                });
            }
        }
    }
    pins
}

/// The directories strictly between `bind` (exclusive) and `root` (exclusive), shallow-to-deep.
/// `bind` must be an ancestor of `root`. Used to enumerate the intermediate mountpoints a pin needs.
fn ancestors_between(bind: &Path, root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = root
        .ancestors()
        .filter(|a| *a != root && *a != bind && a.starts_with(bind))
        .map(Path::to_path_buf)
        .collect();
    // `Path::ancestors` yields deep-to-shallow; pins need shallow-to-deep (parent before child).
    v.reverse();
    v
}

/// Read the global config (trusted by location, so no trust marker), defaulting to
/// empty when it is absent, unsafe, or unparseable.
pub(super) fn read_global(warnings: &mut Vec<String>) -> RawConfig {
    let Some(path) = global_path() else {
        return RawConfig::default();
    };
    read_layer(&path, warnings).unwrap_or_default()
}

/// The reusable egress groups declared in the global config (`[net.groups]`), as their raw authored
/// entries keyed by name, plus any load warnings. Global-only — matching the resolver, which honors
/// groups only from the global config — so this lists exactly the set a `@<name>` reference can
/// resolve to. A read-only, network-free view for `sbx net groups`; entries are returned verbatim
/// (unclassified), so the caller displays them as declared and may flag a malformed one on its own.
pub(crate) fn net_groups() -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    let mut warnings = Vec::new();
    let global = read_global(&mut warnings);
    (global.net.groups, warnings)
}

/// Read a portable `[net.groups]` fragment from `path` (the file `sbx net groups import` is given),
/// returning its groups. The file goes through the same safety gate as any config (owner-owned,
/// non-world-writable, a plain regular file). An error names why: unsafe/unreadable, not valid TOML,
/// or carrying no `[net.groups]` (the tell-tale of the wrong file). The entries are returned
/// verbatim — the caller validates the group names before writing them, and a malformed entry is
/// flagged at load like any other, so the import is deliberately not a second validation surface.
pub(crate) fn read_net_groups_fragment(
    path: &Path,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let bytes = safety::read_safe_bytes(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let raw = schema::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    if raw.net.groups.is_empty() {
        return Err(format!(
            "{} has no `[net.groups]` table to import (is it an export of `sbx net groups export`?)",
            path.display()
        ));
    }
    Ok(raw.net.groups)
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
    // project untrusted: its `.sbx.toml` still parses (its free `env` applies under
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
/// `sbx config` and the launcher's `[env]` mapping. `None` when the project declares
/// none. A mise file present without a usable `.sbx.toml` to anchor it is not honored
/// — when there is no `.sbx.toml` at all, the no-op is surfaced as a warning so it is
/// never silent; an unsafe or unparseable `.sbx.toml` already warned on its own
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

/// The global config path: `$XDG_CONFIG_HOME/sbx/sbx.toml` when that is absolute,
/// else `$HOME/.config/sbx/sbx.toml`. `None` when neither yields an absolute base
/// (the same fail-closed stance the trust store takes — never resolve against the
/// current directory).
pub(super) fn global_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("sbx").join(GLOBAL_CONFIG));
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    home.is_absolute()
        .then(|| home.join(".config/sbx").join(GLOBAL_CONFIG))
}

/// The imported-profiles directory (`…/sbx/apps/`), a sibling of the global config. `None` when
/// no config base resolves, like [`global_path`]; `sbx app import`/`rm`/`list` and [`load`] all
/// route through this one place so the location can never drift.
pub(crate) fn profiles_dir() -> Option<PathBuf> {
    global_path().and_then(|p| p.parent().map(|d| d.join(PROFILES_DIR)))
}

/// The profile file for app `name` (`…/sbx/apps/<name>.toml`), or `None` when no config base
/// resolves. The counterpart of [`profiles_dir`] for a single app — the target an app-scoped
/// global write (`sbx net allow -a <name> --save -g`, `sbx config … --app <name> -g`) reaches.
pub(crate) fn profile_path(name: &str) -> Option<PathBuf> {
    profiles_dir().map(|d| d.join(format!("{name}.toml")))
}

/// The posture an importable app profile would grant, in human-readable lines — shown so the
/// deliberate `sbx app import` is informed (it is the consent act; an imported profile is then
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

/// Render one raw bind for the import posture summary: its path, with a ` (rw)` marker when the
/// bind is read-write (the more-privileged, exceptional case worth flagging before import). An
/// unrecognized mode is shown verbatim (`(mode X?)`) so a typo is visible, and a table missing its
/// `path` reads as `(bind without a path)` so a malformed entry is not silently blank.
fn describe_raw_bind(bind: &RawBind) -> String {
    match bind {
        RawBind::Path(p) => p.clone(),
        RawBind::Detailed(t) => {
            let path = t.path.as_deref().unwrap_or("(bind without a path)");
            match t.mode.as_deref() {
                None | Some("ro") => path.to_string(),
                Some("rw") => format!("{path} (rw)"),
                Some(other) => format!("{path} (mode {other}?)"),
            }
        }
    }
}

/// Build the posture summary for a raw app profile: the command, the persistent-home scope, the
/// extra tools, the binds (each read-only or read-write, a `(rw)` marker flagging the latter), the
/// network posture, and each injected credential by destination and source *locator*. A profile
/// never carries a plaintext secret — only a locator (`env://VAR`, a `key`) — so this is safe to
/// display and to share.
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
        let descs: Vec<String> = app.binds.iter().map(describe_raw_bind).collect();
        lines.push(format!("binds: {}", descs.join(", ")));
    }
    match &app.network {
        None => {}
        Some(NetworkField::Posture(p)) => lines.push(format!("network: {p}")),
        Some(NetworkField::Table(t)) => {
            let mut s = format!(
                "network: {}",
                t.mode
                    .as_deref()
                    .unwrap_or("(mode inherited from the parent layer)")
            );
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
        // A credential is injected only under a filtering posture (`deny`/`allow`/`ask` — the proxy
        // performs the injection). If the profile declares secrets but not its own filtering
        // posture, say so — otherwise the summary reads as if they would be injected when,
        // standalone, they would not. Any filtering spelling counts (table or bare string); a
        // mode-less table inherits a filtering mode (`deny`/`ask`, or the `deny` fallback), so it
        // counts too.
        let filtered = match &app.network {
            Some(NetworkField::Table(t)) => {
                matches!(t.mode.as_deref(), None | Some("deny" | "allow" | "ask"))
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
        if !is_valid_app_name(&name) {
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

/// Make the imported profile apps the sole source of the global app layer. A global app lives only
/// as a profile file under `apps/<name>.toml` — an inline `[app.<name>]` in `sbx.toml` is forbidden
/// (it used to shadow an entire imported profile: `cmd`/`packages`/`binds`/`env` and the profile's
/// `[network]` all dropped, bricking the app). Any inline app present in the global config is
/// therefore dropped inert with a loud, per-app migration warning, and the profiles take its place
/// unconditionally — there is exactly one declaration site, so no collision is possible. `load`
/// stays infallible: a bad state reachable only by manual editing never wedges the sandbox.
pub(super) fn merge_profile_apps(
    global: &mut RawConfig,
    profiles: BTreeMap<String, RawApp>,
    warnings: &mut Vec<String>,
) {
    let apps_dir = profiles_dir()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| format!("<config>/{PROFILES_DIR}"));
    for name in global.app.keys() {
        // Two shapes of the forbidden state need different remedies. When a profile of the same name
        // already exists it is the one that runs, so the inline block is pure dead weight — say to
        // delete it. Otherwise the inline block carries the only definition, so point at `export` to
        // migrate it to a profile before it is dropped.
        let remedy = if profiles.contains_key(name) {
            format!(
                "the profile {PROFILES_DIR}/{name}.toml already provides it — delete the inline \
                 [app.{name}] from {GLOBAL_CONFIG}"
            )
        } else {
            format!(
                "migrate it with `sbx app export {name} --out {apps_dir}/{name}.toml`, then delete \
                 the inline [app.{name}] from {GLOBAL_CONFIG}"
            )
        };
        warnings.push(format!(
            "app `{name}`: an inline [app.{name}] in {GLOBAL_CONFIG} is forbidden — global apps \
             live as profile files under {PROFILES_DIR}/<name>.toml. The inline declaration is \
             ignored; {remedy}."
        ));
    }
    global.app.clear();
    for (name, app) in profiles {
        global.app.insert(name, app);
    }
}

/// Produce the portable profile bytes for `name`, for `sbx app export`. An **imported profile**
/// (`<config>/sbx/apps/<name>.toml`) is emitted **verbatim**, so the author's comments and
/// formatting survive a round-trip through the store; otherwise an app declared **inline** — in the
/// project `.sbx.toml` (preferred, the local definition one would share) or the global `sbx.toml` —
/// has its `RawApp` **serialized** to a minimal top-level profile. The app is exported **as
/// authored**, security fields and all, regardless of trust: import is the trust act, not export.
/// Returns the bytes to emit, or a human-readable reason none was found.
///
/// Note the precedence here is the **inverse** of [`merge_profile_apps`] at load: export prefers
/// the imported profile, whereas a launch drops an inline `[app.<name>]` in the global config
/// (forbidden — see [`merge_profile_apps`]). They only diverge when one name is *both* an imported
/// profile and an inline definition — a state the load-time migration warning already pushes the
/// user to resolve — so `sbx app export <name>` may emit the profile while `sbx app <name>` would
/// launch the profile (the inline is inert). Exporting the inline is itself the migration path off
/// the forbidden form. Keep at most one definition per name.
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
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn describe_raw_bind_marks_read_write_and_flags_malformed_entries() {
        // The import posture summary: a bare path and an explicit `"ro"` render plain; a
        // `"rw"` bind carries the `(rw)` marker (the more-privileged case worth flagging before an
        // import); an unrecognized mode and a table without a `path` are shown so they are visible.
        assert_eq!(describe_raw_bind(&RawBind::Path("/data".into())), "/data");
        assert_eq!(
            describe_raw_bind(&RawBind::Detailed(schema::RawBindTable {
                path: Some("/data".into()),
                mode: Some("ro".into()),
            })),
            "/data"
        );
        assert_eq!(
            describe_raw_bind(&RawBind::Detailed(schema::RawBindTable {
                path: Some("/data".into()),
                mode: Some("rw".into()),
            })),
            "/data (rw)"
        );
        assert_eq!(
            describe_raw_bind(&RawBind::Detailed(schema::RawBindTable {
                path: Some("/data".into()),
                mode: Some("write".into()),
            })),
            "/data (mode write?)"
        );
        assert_eq!(
            describe_raw_bind(&RawBind::Detailed(schema::RawBindTable {
                path: None,
                mode: Some("rw".into()),
            })),
            "(bind without a path) (rw)"
        );
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
        // A profile whose stem coincides with a `sbx app` subcommand verb is a usable app now that
        // launching goes through `sbx app run <name>` — it is keyed, not dropped.
        std::fs::write(dir.path().join("import.toml"), b"cmd = \"x\"\n").unwrap();
        // A non-.toml file is ignored; a profile whose stem is an unsafe name (here, a space) is
        // dropped with a warning, never keyed.
        std::fs::write(dir.path().join("notes.txt"), b"ignore me\n").unwrap();
        std::fs::write(dir.path().join("bad name.toml"), b"cmd = \"x\"\n").unwrap();

        let mut warnings = Vec::new();
        let apps = read_profile_apps_from(dir.path(), &mut warnings);
        assert!(apps.contains_key("demo-app") && apps.contains_key("review"));
        assert!(
            apps.contains_key("import"),
            "a profile named like a subcommand verb is a usable app (run via `sbx app run import`)"
        );
        assert!(
            !apps.contains_key("notes"),
            "a non-.toml file is not a profile"
        );
        assert!(
            !apps.contains_key("bad name"),
            "an unsafe-name profile is dropped"
        );
        assert!(
            warnings.iter().any(|w| w.contains("bad name.toml")),
            "a dropped unsafe-name profile must warn: {warnings:?}"
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
    fn control_plane_mode_forces_ro_at_or_under_a_root_and_keeps_rw_above_it() {
        // A writable bind AT or UNDER an sbx control-plane root is forced read-only (the whole bind
        // is control plane). A writable bind that merely CONTAINS a root stays read-write (the
        // launcher pins the root in place). An unrelated writable bind is left alone; a read-only
        // bind is never touched. Pure, over explicit roots (no environment).
        let roots = vec![PathBuf::from("/home/u/.config/sbx")];
        let mut warnings = Vec::new();

        // Exact match → forced read-only.
        assert!(!control_plane_mode(
            Path::new("/home/u/.config/sbx"),
            true,
            &roots,
            &mut warnings
        ));
        // A descendant of the root (aiming straight at a trust marker) → forced read-only.
        assert!(!control_plane_mode(
            Path::new("/home/u/.config/sbx/apps"),
            true,
            &roots,
            &mut warnings
        ));
        assert_eq!(warnings.len(), 2, "each read-only case warns: {warnings:?}");
        assert!(
            warnings.iter().all(|w| w.contains("read-only instead")),
            "the at-or-under case names the downgrade: {warnings:?}"
        );

        // An ancestor of the root (a broad `~/.config`, or a whole-home bind) → stays read-write,
        // with an informational note that its control-plane paths are pinned.
        let mut w2 = Vec::new();
        assert!(control_plane_mode(
            Path::new("/home/u/.config"),
            true,
            &roots,
            &mut w2
        ));
        assert_eq!(
            w2.len(),
            1,
            "the contains-a-root case notes the pinning: {w2:?}"
        );
        assert!(
            w2[0].contains("pinned read-only in place") && w2[0].contains("/home/u/.config/sbx"),
            "the note names the protected path: {w2:?}"
        );

        // A sibling that merely shares a textual prefix is not a conflict, and warns nothing.
        let mut w3 = Vec::new();
        assert!(control_plane_mode(
            Path::new("/home/u/.config/sbximposter"),
            true,
            &roots,
            &mut w3
        ));
        // A read-only bind is never touched and never warns, even at the root itself.
        assert!(!control_plane_mode(
            Path::new("/home/u/.config/sbx"),
            false,
            &roots,
            &mut w3
        ));
        assert!(w3.is_empty(), "no warning for the safe cases: {w3:?}");
    }

    #[test]
    fn control_plane_pins_freezes_each_contained_roots_path_chain() {
        // A whole-home read-write bind that contains three control-plane roots yields the mountpoint
        // chain that pins each: every intermediate directory read-write, each root read-only,
        // deduplicated (the shared `.local` appears once) and ordered shallow-to-deep so a parent is
        // always established before its child (a child bound first would be shadowed by the parent).
        let roots = vec![
            PathBuf::from("/home/u/.local/share/sbx"),
            PathBuf::from("/home/u/.local/state/sbx/trusted"),
            PathBuf::from("/home/u/.config/sbx"),
        ];
        let binds = vec![Bind {
            path: PathBuf::from("/home/u"),
            writable: true,
        }];
        let pins = control_plane_pins_for(&binds, &roots);

        // Every root is present read-only; every non-root pin is a read-write intermediate.
        for root in &roots {
            assert!(
                pins.iter().any(|p| &p.path == root && !p.writable),
                "root pinned read-only: {} in {pins:?}",
                root.display()
            );
        }
        assert!(
            pins.iter()
                .filter(|p| p.writable)
                .all(|p| !roots.contains(&p.path)),
            "read-write pins are intermediates, never a root: {pins:?}"
        );
        // The shared ancestor `.local` is pinned exactly once (dedup across the two roots under it).
        assert_eq!(
            pins.iter()
                .filter(|p| p.path == Path::new("/home/u/.local"))
                .count(),
            1,
            "the shared intermediate is deduplicated: {pins:?}"
        );
        // Parent-before-child: each pin's index is greater than every strict ancestor pin's index.
        for (i, p) in pins.iter().enumerate() {
            for (j, q) in pins.iter().enumerate() {
                if p.path.starts_with(&q.path) && p.path != q.path {
                    assert!(
                        j < i,
                        "ancestor {} must precede {}: {pins:?}",
                        q.path.display(),
                        p.path.display()
                    );
                }
            }
        }
    }

    #[test]
    fn control_plane_pins_only_covers_roots_a_bind_strictly_contains() {
        let roots = vec![
            PathBuf::from("/home/u/.local/share/sbx"),
            PathBuf::from("/home/u/.config/sbx"),
        ];

        // A partial-ancestor bind covers only the root it contains, and its chain starts below the
        // bind boundary (never re-pinning the bind itself).
        let partial = vec![Bind {
            path: PathBuf::from("/home/u/.local"),
            writable: true,
        }];
        let pins = control_plane_pins_for(&partial, &roots);
        assert!(
            pins.iter()
                .any(|p| p.path == Path::new("/home/u/.local/share/sbx") && !p.writable),
            "the contained root is pinned: {pins:?}"
        );
        assert!(
            pins.iter()
                .all(|p| p.path != Path::new("/home/u/.config/sbx")),
            "an uncontained root is not pinned: {pins:?}"
        );
        assert!(
            pins.iter().all(|p| p.path != Path::new("/home/u/.local")),
            "the bind boundary itself is never a pin: {pins:?}"
        );

        // A descendant/exact bind (at or under a root) yields no pins — that bind is forced
        // read-only by `control_plane_mode`, so it is not writable here anyway.
        let under = vec![Bind {
            path: PathBuf::from("/home/u/.config/sbx/apps"),
            writable: true,
        }];
        assert!(
            control_plane_pins_for(&under, &roots).is_empty(),
            "a bind under a root pins nothing"
        );

        // A read-only ancestor bind pins nothing (only a read-write bind needs the protection).
        let ro = vec![Bind {
            path: PathBuf::from("/home/u"),
            writable: false,
        }];
        assert!(
            control_plane_pins_for(&ro, &roots).is_empty(),
            "a read-only bind pins nothing"
        );
    }
}
