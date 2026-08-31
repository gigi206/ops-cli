//! Where a project's runtime state lives on the host, and the identity it is keyed by.
//!
//! A different question from "what does the cage see": nothing here names an in-cage destination,
//! and nothing here produces a mount. It is nevertheless the part of [`super`] the rest of the crate
//! depends on most — the per-project id keys the runtime tree that the store, the pin locks and
//! housekeeping all address, so a module with no interest in binds still reaches through this one.
//!
//! The home and the synthetic `/etc` are always allocated as siblings, which is what the parent's
//! integrity note rests on: the identity files must sit outside every read-write bind.

use std::io;
use std::path::{Path, PathBuf};

/// Host-side paths backing one project's sandbox. The writable home and the
/// read-only synthetic `/etc` are deliberately *siblings*: nothing read-write
/// contains the identity files (see the module integrity note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectRuntime {
    /// The sandbox `$HOME` on the host, bound read-write.
    pub(crate) home_src: PathBuf,
    /// Directory holding the synthetic `passwd`/`group`, bound read-only.
    pub(crate) etc_dir: PathBuf,
    /// For a **global app** only: the host path of the per-project mise data pool, bound writable
    /// as mise's primary [`super::MISE_PROJECT_INCAGE`] so a `nix:` self-equip's install aligns
    /// with the per-project `/nix` store. `None` for `sbx run` and a per-project app, whose home —
    /// and thus mise's data dir — is already per-project, so they keep the single-pool wiring.
    pub(crate) mise_project_src: Option<PathBuf>,
}

/// Which persistent runtime a launch uses — the writable `$HOME` and its sibling synthetic
/// `/etc`. `sbx run` use the project's shared default; an app gets a dedicated,
/// persistent home so its config, login state, and history never bleed into the project shell
/// or another app. An app's home is either shared across projects (`GlobalApp`, one identity
/// everywhere) or keyed per-project (`ProjectApp`, isolated per project).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Runtime<'a> {
    /// The project's default shared home — `sbx run`.
    ProjectDefault,
    /// `sbx app <name>` with one home per app, shared across every project.
    GlobalApp(&'a str),
    /// `sbx app <name>` with a home per (project, app).
    ProjectApp(&'a str),
}

/// Host-side runtime paths for `project` under sbx's data directory, for the given
/// [`Runtime`]. The home and the synthetic `/etc` are always siblings so the latter sits
/// outside every read-write bind (module integrity note). An app name is a validated single
/// path component (the config app-name check), so joining it cannot traverse out of the data
/// directory.
pub(super) fn project_runtime(data_dir: &Path, project: &Path, runtime: Runtime) -> ProjectRuntime {
    let project_base = || data_dir.join("projects").join(project_id(project));
    let (base, mise_project_src) = match runtime {
        Runtime::ProjectDefault => (project_base(), None),
        // A global app's home is project-independent — keyed only by the app name, so the same
        // identity is reused in every project. Its mise data pool, however, is keyed per (project,
        // app) — `projects/<id>/apps/<name>/mise`, the same base a per-project app roots its home
        // under, plus `/mise` — so a `nix:` self-equip's install record aligns with the per-project
        // `/nix` store and never points at another project's store. App-keyed (not project-keyed),
        // so a tool the agent self-equips in app A stays private to app A, preserving per-app
        // isolation for mise install records exactly as before the split.
        Runtime::GlobalApp(name) => (
            data_dir.join("apps").join(name),
            Some(project_base().join("apps").join(name).join("mise")),
        ),
        // A per-project app's home nests under the project, isolating its state per project — its
        // mise data dir is therefore already per-project-aligned, so it keeps the single-pool wiring.
        Runtime::ProjectApp(name) => (project_base().join("apps").join(name), None),
    };
    ProjectRuntime {
        home_src: base.join("home"),
        etc_dir: base.join("etc"),
        mise_project_src,
    }
}

/// The host path of the cage's persistent `$HOME` for this launch — the exact directory
/// [`super::build_spec`] binds writable as the home (derived identically: canonicalise the cwd, then
/// [`project_runtime`]). Lets a host-side helper place a file the cage reads through the home bind
/// (the live-theme keyfile the in-cage portal watches).
pub(crate) fn home_src(data_dir: &Path, cwd: &Path, runtime: Runtime) -> io::Result<PathBuf> {
    let project = canonicalize_project(cwd)?;
    Ok(project_runtime(data_dir, &project, runtime).home_src)
}

/// A collision-resistant directory name for a canonical project path, stable within a given binary
/// build. Housekeeping hashes a running session's recorded canonical path with this to match it
/// against a runtime tree's id, so it can skip a tree a live session still holds. The hash is
/// `DefaultHasher`, whose output std does not guarantee equal across toolchain/std versions, so a
/// future build could re-key a project's trees (GC/re-seed heals the orphaned ones); switch to a
/// specified hash here if cross-build stability is ever required.
pub(crate) fn project_id(project: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    project.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// The stable per-project identity sbx keys runtime state on. The writable home,
/// the synthetic identity, and a project's garbage-collection roots all derive from
/// it, so housekeeping can reclaim a project's tools alongside the rest of its
/// runtime. Canonicalises first, so a relative or symlinked `cwd` maps to the same
/// identity as the real path (the same pin [`canonicalize_project`] applies to the
/// bind source).
pub(crate) fn project_runtime_id(cwd: &Path) -> io::Result<String> {
    Ok(project_identity(cwd)?.0)
}

/// The per-project identity together with the canonical project path it derives from. The id keys
/// the project's runtime tree (home, store, gcroots); the canonical path is what a launch records
/// in a durable marker so housekeeping can later recognise — and reclaim — that tree once the
/// project directory is gone (the id alone is a one-way hash). Canonicalises once, so id and path
/// agree and both match the bind source's pinned location.
pub(crate) fn project_identity(cwd: &Path) -> io::Result<(String, PathBuf)> {
    let canonical = canonicalize_project(cwd)?;
    let id = project_id(&canonical);
    Ok((id, canonical))
}

/// Resolve `path` to a real, existing directory, following symlinks in the host
/// namespace. Canonicalising up front *narrows* the bind-source TOCTOU window:
/// the source is pinned to its real location, so a later project-controlled
/// symlink swap no longer trivially redirects the bind. It is not an absolute
/// guarantee — a parent component swapped between this call and the actual bind
/// still races — but the broader confinement of arbitrary, config-declared bind
/// paths is enforced where those binds are introduced.
pub(super) fn canonicalize_project(path: &Path) -> io::Result<PathBuf> {
    let canon = path.canonicalize()?;
    if !canon.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("project path is not a directory: {}", canon.display()),
        ));
    }
    Ok(canon)
}
