//! In-project store garbage collection.
//!
//! A project's own writable store (`<data>/projects/<id>/store`) grows as the agent
//! self-equips: every `flake:` build, every in-cage `mise`/`nix` install lands a closure
//! there. Most of it stays referenced — the base userland and the project's declared tools
//! are gc-rooted at seed time (see [`super::projectstore`]), mise installs root themselves,
//! and each `flake:` build registers a host-resolvable root keyed by package name that a roll
//! re-points — but a flake revision rolled forward, and a flake package removed outright, leave
//! the previous build unreferenced. This reclaims those.
//!
//! Two steps. First [`prune_flake_roots`] drops the `ops-flake-<name>` roots of removed packages
//! (a roll's overwrite self-cleans, but a removal cannot reach itself). Then a plain `nix-store
//! --gc` against the project store sweeps: every live build carries a root whose target is a
//! `/nix/store/<hash>` path, which the relocated store resolves host-side, so the sweep keeps the
//! live set and collects the rest — no per-home enumeration. The default is a dry run: it reports
//! what would be freed with `--print-dead`, summed by `--query --size`, and only changes anything
//! when the caller asks.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// What a gc pass reclaimed (or would reclaim, in a dry run).
pub(crate) struct GcReport {
    /// Store paths the sweep collected, or would collect in a dry run.
    pub(crate) paths: usize,
    /// Bytes the collected paths occupied.
    pub(crate) bytes: u64,
}

/// Remove the host-resolvable `ops-flake-<name>` gc roots whose package is no longer declared.
///
/// A `flake:` build registers a root keyed by package name, overwritten each launch — so a roll
/// (same name, new build) self-cleans, but a *removed* package's root lingers, pointing at a build
/// nothing wants. This drops those roots so the following sweep reclaims their builds. `current` is
/// the set of currently-declared flake package names across the project's runtimes; any
/// `ops-flake-<name>` root whose `<name>` is not in it is stale. Read-only unless `prune` (a dry
/// run lists what it would remove without touching anything). Returns the stale roots.
pub(crate) fn prune_flake_roots(
    store_dir: &Path,
    current: &BTreeSet<String>,
    prune: bool,
) -> Vec<PathBuf> {
    let dir = super::projectstore::gcroots_dir(store_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name
            .to_str()
            .and_then(|n| n.strip_prefix("ops-flake-"))
        else {
            continue;
        };
        if current.contains(name) {
            continue;
        }
        let path = entry.path();
        if prune {
            if std::fs::remove_file(&path).is_ok() {
                stale.push(path);
            }
        } else {
            stale.push(path);
        }
    }
    stale
}

/// Garbage-collect `store_dir`'s store: compute the dead paths and their size, and delete them
/// when `prune`. The dead set is found with `--gc --print-dead` (the mark phase without the
/// sweep), so a dry run measures exactly what a prune would remove. Daemonless (`NIX_REMOTE`
/// empty), like every other store operation.
pub(crate) fn collect(nix_store: &Path, store_dir: &Path, prune: bool) -> io::Result<GcReport> {
    let dead = print_dead(nix_store, store_dir)?;
    let bytes = total_size(nix_store, store_dir, &dead)?;
    if prune && !dead.is_empty() {
        sweep(nix_store, store_dir)?;
    }
    Ok(GcReport {
        paths: dead.len(),
        bytes,
    })
}

/// The store paths `nix-store --gc` would collect, without deleting them. Only lines that are
/// store paths are kept; nix prints its progress ("finding roots…") on stderr.
fn print_dead(nix_store: &Path, store_dir: &Path) -> io::Result<Vec<String>> {
    let out = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(store_dir)
        .arg("--gc")
        .arg("--print-dead")
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix-store --gc --print-dead failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("/nix/store/"))
        .map(str::to_owned)
        .collect())
}

/// The summed size (bytes) of `paths` in `store_dir`'s store. Empty input is zero without
/// invoking nix. `--query --size` prints one size per path; any unparsable line is ignored so a
/// single odd line never derails the total.
fn total_size(nix_store: &Path, store_dir: &Path, paths: &[String]) -> io::Result<u64> {
    if paths.is_empty() {
        return Ok(0);
    }
    // Query in bounded batches: passing every dead path as one argv overflows the kernel's argv
    // limit (E2BIG) on a large store, which would abort the whole GC (including `--prune`). Store
    // paths are ~100 bytes each, so a few thousand per call stays well under any ARG_MAX.
    const BATCH: usize = 2048;
    let mut total = 0u64;
    for chunk in paths.chunks(BATCH) {
        let out = Command::new(nix_store)
            .env("NIX_REMOTE", "")
            .arg("--store")
            .arg(store_dir)
            .arg("--query")
            .arg("--size")
            .args(chunk)
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "nix-store --query --size failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        total += String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.trim().parse::<u64>().ok())
            .sum::<u64>();
    }
    Ok(total)
}

/// Delete every dead path in `store_dir`'s store.
fn sweep(nix_store: &Path, store_dir: &Path) -> io::Result<()> {
    let status = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(store_dir)
        .arg("--gc")
        .stdout(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("nix-store --gc failed"));
    }
    Ok(())
}

/// Render `bytes` as a short human figure (e.g. `412.0 MiB`), for the gc report.
pub(crate) fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

/// The outcome of a cross-project reap over the runtime trees under `<data>/projects/`.
pub(crate) struct ReapReport {
    /// Trees whose project directory is gone (its parent still present, no live session holds it):
    /// reclaimed when pruning, otherwise listed.
    pub(crate) dead: Vec<DeadTree>,
    /// Trees with no marker — their project path predates marker-recording and is unknown, so
    /// deadness cannot be verified: listed for a manual decision, reclaimed only when the caller
    /// opts in with `--unidentified` (the entries actually removed land in `reaped_unidentified`).
    pub(crate) unidentified: Vec<UnidentifiedTree>,
    /// Markerless trees reclaimed under the `--unidentified` opt-in. Empty unless the caller passed
    /// `prune_unidentified` *and* `prune`; the trees in this list have already been removed.
    pub(crate) reaped_unidentified: Vec<UnidentifiedTree>,
}

/// A reclaimable dead project tree: the recorded project path that is gone, and the tree's size.
pub(crate) struct DeadTree {
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
}

/// A tree whose project path is unknown (no marker): its on-disk location and size.
pub(crate) struct UnidentifiedTree {
    pub(crate) dir: PathBuf,
    pub(crate) bytes: u64,
}

/// Reclaim — or, in a dry run, report — the runtime trees under `projects_dir` whose project is
/// gone. A tree is reclaimed only when every safety condition holds: it carries a `project` marker
/// (so its project path is known), that path no longer exists, **its parent directory still does**
/// (a cheap guard against reaping when a whole enclosing structure is gone — see [`project_is_gone`]
/// for what that does and does not catch, notably that it is not a reliable unmount check), and no
/// live session holds it (`live_ids`, the ids of running sessions).
///
/// A tree with no usable marker is **never** reclaimed on deadness, because its path is unknown and
/// deadness cannot be verified. It is reclaimed only under the explicit `prune_unidentified` opt-in
/// — a fail-closed escape hatch (`ops gc --all --unidentified --prune`) that reaps markerless trees
/// *without* a deadness proof, after the live-session guard has already excluded any tree a running
/// session holds. The caller owns that risk: a markerless tree belonging to a project still in use
/// (a pre-marker launch, or a marker write that failed) would be lost, so the flag is never the
/// default. Destructive only when `prune`; a dry run computes the same sets and changes nothing.
pub(crate) fn reap_dead_projects(
    projects_dir: &Path,
    live_ids: &BTreeSet<String>,
    prune: bool,
    prune_unidentified: bool,
) -> ReapReport {
    let mut dead = Vec::new();
    let mut unidentified = Vec::new();
    let mut reaped_unidentified = Vec::new();
    let entries = match std::fs::read_dir(projects_dir) {
        Ok(e) => e,
        // No projects tree yet — nothing to reap.
        Err(_) => {
            return ReapReport {
                dead,
                unidentified,
                reaped_unidentified,
            }
        }
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        // A live session still using this tree: never touch it, whatever its marker says — this
        // guard also protects the `--unidentified` path below, which reaps without a deadness proof.
        if let Some(id) = dir.file_name().and_then(|n| n.to_str()) {
            if live_ids.contains(id) {
                continue;
            }
        }
        match read_marker(&dir) {
            // Identified, and the project is gone with its parent still present — reclaimable.
            Some(path) if project_is_gone(&path) => {
                let bytes = tree_size(&dir);
                if prune {
                    let _ = force_remove_dir_all(&dir);
                }
                dead.push(DeadTree { path, bytes });
            }
            // Identified and still live (or only its mount is absent) — keep.
            Some(_) => {}
            // No usable marker. Default: report for a manual decision. With the `--unidentified`
            // opt-in, reclaim the tree too (no deadness proof — the caller accepts that risk).
            None => {
                let bytes = tree_size(&dir);
                if prune_unidentified && prune {
                    let _ = force_remove_dir_all(&dir);
                    reaped_unidentified.push(UnidentifiedTree { bytes, dir });
                } else {
                    unidentified.push(UnidentifiedTree { bytes, dir });
                }
            }
        }
    }
    ReapReport {
        dead,
        unidentified,
        reaped_unidentified,
    }
}

/// The canonical project path recorded in `<dir>/project`, if the marker is present and holds an
/// absolute path. An absent, unreadable, empty, or non-absolute marker yields `None` — the tree is
/// then treated as unidentified, never reaped on a path that cannot be trusted.
fn read_marker(dir: &Path) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = std::fs::read(dir.join(super::projectstore::PROJECT_MARKER)).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(&bytes));
    path.is_absolute().then_some(path)
}

/// The outcome of [`reap_one`] — a targeted reap of a single named project tree. The caller names
/// the id, so unlike [`reap_dead_projects`] no deadness proof is required: the user *is* the
/// proof. The live-session guard still holds (`Live`), and a missing id is reported (`NotFound`)
/// so a typo never silently succeeds.
#[derive(Debug)]
pub(crate) enum ReapOneOutcome {
    /// No tree directory exists for that id.
    NotFound,
    /// A running session holds the tree — never touch it.
    Live,
    /// The tree was identified and (when `prune`) removed. `bytes` is its measured size.
    Tree { dir: PathBuf, bytes: u64 },
}

/// Whether `id` is safe to use as a project-tree directory name — a single, ordinary path
/// component with no separator, no `.`/`..`, and no absolute form. This is the anti-traversal
/// guard for `ops gc --id`: the id is joined onto `projects/` and fed to a recursive delete, so a
/// value like `/etc` (which `Path::join` treats as absolute and *replaces* the base with) or
/// `../x` (which escapes the tree) must never reach the `join`. A real id is a 16-hex hash, but the
/// check does not hard-code that — any legitimate directory name under `projects/` is one normal
/// component; anything that is not is refused.
pub(crate) fn is_safe_tree_id(id: &str) -> bool {
    use std::path::Component;
    let mut comps = Path::new(id).components();
    matches!(comps.next(), Some(Component::Normal(c)) if c == std::ffi::OsStr::new(id))
        && comps.next().is_none()
}

/// Reap — or, in a dry run, measure — one named project tree. The caller supplies the id, so this
/// needs no marker and no deadness check: it works on markerless trees too, and on trees a marker
/// would call idle (the user named it, overriding the "keep" default). The only guard is the
/// live-session one — a tree a running session holds is refused, the same guard [`reap_dead_projects`]
/// applies. Destructive only when `prune`.
pub(crate) fn reap_one(
    projects_dir: &Path,
    id: &str,
    live_ids: &BTreeSet<String>,
    prune: bool,
) -> ReapOneOutcome {
    // The id names a directory *under* `projects_dir` and reaches `force_remove_dir_all` — so it
    // must be a single, ordinary path component. Reject anything with a separator, a `..`, or an
    // absolute form before the `join`: `projects_dir.join("/etc")` would *replace* the base and
    // `join("../x")` would escape it, turning a mistyped id into a recursive delete outside the
    // tree. Defense at the sink (the CLI validates too, with a clearer message).
    if !is_safe_tree_id(id) {
        return ReapOneOutcome::NotFound;
    }
    let dir = projects_dir.join(id);
    if !dir.is_dir() {
        return ReapOneOutcome::NotFound;
    }
    if live_ids.contains(id) {
        return ReapOneOutcome::Live;
    }
    let bytes = tree_size(&dir);
    if prune {
        let _ = force_remove_dir_all(&dir);
    }
    ReapOneOutcome::Tree { dir, bytes }
}

/// The state of one project tree, for `ops path`'s per-project annotation. The non-destructive,
/// finer-grained counterpart of [`reap_dead_projects`] (which folds `Live` and `Idle` into "keep"):
/// `Live` (a running session holds it), `Idle` (no session, the marker points at a project
/// directory that still exists), `Dead` (the marker points at a gone path — reclaimable by `ops gc
/// --all`), or `Markerless` (no marker — a pre-marker orphan, identity unknown).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TreeState {
    Live,
    Idle,
    Dead,
    Markerless,
}

impl TreeState {
    /// The short tag rendered beside a project's path by `ops path`.
    pub(crate) fn label(self) -> &'static str {
        match self {
            TreeState::Live => "live",
            TreeState::Idle => "idle",
            TreeState::Dead => "dead",
            TreeState::Markerless => "markerless",
        }
    }
}

/// A project tree's classification plus the last time it was touched, for `ops path`'s per-project
/// annotation. `last_used` is the marker file's mtime when present (the last launch, since the
/// marker is rewritten each seed), else the tree directory's mtime — the best available proxy for
/// "when was this last used". `UNIX_EPOCH` is the fallback when even the dir's mtime is unreadable.
/// `project_path` is the canonical project path the marker records, when there is a marker — the
/// answer to "which project does this id belong to?" For a markerless tree it is `None` (unknown).
#[derive(Clone, Debug)]
pub(crate) struct TreeClassification {
    pub(crate) state: TreeState,
    pub(crate) last_used: std::time::SystemTime,
    pub(crate) project_path: Option<PathBuf>,
}

/// Classify one project tree non-destructively — the read-only counterpart of the reap decision.
/// `live_ids` is the set of project ids a running session holds (the same set [`reap_dead_projects`]
/// uses to guard a live tree), so a tree in use now reads `Live` rather than its marker-based state.
/// The marker is always read (when present) for `project_path`, so a `Live` tree still reports which
/// project it belongs to — the marker was written at the launch that is now live.
pub(crate) fn classify_tree(dir: &Path, live_ids: &BTreeSet<String>) -> TreeClassification {
    let id = dir.file_name().and_then(|n| n.to_str());
    let is_live = id.is_some_and(|id| live_ids.contains(id));
    let marker = dir.join(super::projectstore::PROJECT_MARKER);
    let last_used = mtime_of(&marker)
        .or_else(|| mtime_of(dir))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let project_path = read_marker(dir);
    let state = if is_live {
        TreeState::Live
    } else {
        match &project_path {
            Some(path) if project_is_gone(path) => TreeState::Dead,
            Some(_) => TreeState::Idle,
            None => TreeState::Markerless,
        }
    };
    TreeClassification {
        state,
        last_used,
        project_path,
    }
}

/// A file's mtime, if it exists and the metadata reads. `symlink_metadata` so a symlinked marker
/// reports the link's time, not its target's — a marker is a regular file in practice, so this
/// only matters as defense-in-depth.
fn mtime_of(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::symlink_metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
}

/// Whether a recorded project `path` is gone in the way that makes its tree a reclamation
/// candidate: the path itself is absent, but its parent directory still exists. The parent check is
/// a cheap guard that keeps a tree when even the project's *parent* directory has also vanished — a
/// sign a whole enclosing structure (a workspace or an entire mount tree) was removed, not just one
/// project. It does **not** reliably detect an unmounted filesystem: a mountpoint directory usually
/// persists when its filesystem is detached, so a project beneath it has an absent path but a
/// present parent, and would be treated as gone. The dry-run default — the user sees the path listed
/// before `--prune` — is the real backstop for that case.
fn project_is_gone(path: &Path) -> bool {
    if path.exists() {
        return false;
    }
    match path.parent() {
        Some(parent) => parent.is_dir(),
        // The filesystem root has no parent — never treat it as a deleted project.
        None => false,
    }
}

/// Remove a directory tree, forcing each directory writable first. The nix store leaves its path
/// directories read-only (`0555`), so a plain `remove_dir_all` cannot unlink their entries; this
/// chmods each directory owner-writable before descending. Symlinks are unlinked, never followed —
/// `file_type` reads the entry's own type without dereferencing.
fn force_remove_dir_all(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            force_remove_dir_all(&entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    std::fs::remove_dir(path)
}

/// The on-disk size of a tree, summing each file's allocated blocks (the `du` semantic, which
/// accounts for sparse files). Symlinks are not followed. Best-effort: an unreadable entry is
/// skipped rather than failing the report. Reflinked content shared with another project counts
/// per file, so the figure is an upper bound on what a prune actually frees.
fn tree_size(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return total;
    };
    for entry in entries.flatten() {
        match entry.file_type() {
            Ok(t) if t.is_dir() => total += tree_size(&entry.path()),
            Ok(_) => {
                if let Ok(m) = entry.path().symlink_metadata() {
                    total += m.blocks() * 512;
                }
            }
            Err(_) => {}
        }
    }
    total
}

/// Prune — or, in a dry run, list — the stale gc roots of the **shared** store, returning the root
/// directories dropped. The shared store keeps one closure per channel revision and per project, so
/// it is rooted under `<data>/gcroots/`: `base/<rev>/` and `gui/<rev>/` (both keyed by the base
/// channel revision), `mise/<rev>/` (the engine revision), and `projects/<id>/` (a project's
/// declared `[packages]` and `nix:` tools). A rev directory not in its live set, and a project
/// directory whose runtime tree under `projects_dir` is gone, are stale: dropping the root lets the
/// following `nix-store --gc` collect the closure it held. Destructive only when `prune`. The live
/// sets must be computed *before* this runs (and after any dead-tree reap, so a reaped project's
/// pin no longer counts) — see [`crate::store::live_base_revisions`] / [`live_mise_revisions`].
pub(crate) fn prune_shared_gcroots(
    gcroots_dir: &Path,
    projects_dir: &Path,
    live_base: &BTreeSet<String>,
    live_mise: &BTreeSet<String>,
    prune: bool,
) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    // base and the GUI font set are both keyed by the base channel revision.
    prune_rev_dirs(&gcroots_dir.join("base"), live_base, prune, &mut removed);
    prune_rev_dirs(&gcroots_dir.join("gui"), live_base, prune, &mut removed);
    prune_rev_dirs(&gcroots_dir.join("mise"), live_mise, prune, &mut removed);

    // Per-project roots: stale once the project's runtime tree is gone (the dead-tree reaper removes
    // the tree but not these shared-store roots, so they are reclaimed here).
    if let Ok(entries) = std::fs::read_dir(gcroots_dir.join("projects")) {
        for entry in entries.flatten() {
            if projects_dir.join(entry.file_name()).exists() {
                continue; // the project still exists — keep its tools rooted
            }
            if prune {
                let _ = force_remove_dir_all(&entry.path());
            }
            removed.push(entry.path());
        }
    }
    removed
}

/// Drop each revision-keyed root directory under `dir` whose revision is not in `live`. A root
/// directory's name is the revision; one outside the live set roots a channel revision nothing
/// references any more.
fn prune_rev_dirs(dir: &Path, live: &BTreeSet<String>, prune: bool, removed: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(rev) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if live.contains(&rev) {
            continue;
        }
        if prune {
            let _ = force_remove_dir_all(&entry.path());
        }
        removed.push(entry.path());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn prune_flake_roots_drops_only_removed_packages() {
        let store = TmpDir::new();
        let gcroots = store.path().join("nix/var/nix/gcroots");
        std::fs::create_dir_all(&gcroots).unwrap();
        // two flake roots, plus a base/tool root and nix's own auto dir that must be untouched
        for name in ["ops-flake-hello", "ops-flake-gone", "abcd-coreutils"] {
            std::os::unix::fs::symlink("/nix/store/x", gcroots.join(name)).unwrap();
        }
        std::fs::create_dir(gcroots.join("auto")).unwrap();

        let current = BTreeSet::from(["hello".to_string()]);

        // a dry run lists the stale root without removing it
        let listed = prune_flake_roots(store.path(), &current, false);
        assert_eq!(listed.len(), 1);
        assert!(gcroots.join("ops-flake-gone").symlink_metadata().is_ok());

        // a prune removes exactly the removed package's root
        let removed = prune_flake_roots(store.path(), &current, true);
        assert_eq!(removed.len(), 1);
        assert!(gcroots.join("ops-flake-gone").symlink_metadata().is_err());
        // the current flake root, the base root, and nix's auto dir are all left alone
        assert!(gcroots.join("ops-flake-hello").symlink_metadata().is_ok());
        assert!(gcroots.join("abcd-coreutils").symlink_metadata().is_ok());
        assert!(gcroots.join("auto").is_dir());
    }

    #[test]
    fn human_bytes_scales_units() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    /// Create a runtime tree `projects/<id>/` with a read-only nix-style store subdir (so a prune
    /// exercises the writable-forcing removal) and, optionally, a `project` marker pointing at
    /// `marker`.
    fn make_tree(projects: &Path, id: &str, marker: Option<&Path>) {
        use std::os::unix::fs::PermissionsExt;
        let dir = projects.join(id);
        let store_path = dir.join("store/nix/store/abcd");
        std::fs::create_dir_all(&store_path).unwrap();
        std::fs::write(store_path.join("f"), b"data").unwrap();
        // the nix store leaves path directories read-only; the reaper must still remove them
        std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o555)).unwrap();
        if let Some(path) = marker {
            use std::os::unix::ffi::OsStrExt;
            std::fs::write(
                dir.join(super::super::projectstore::PROJECT_MARKER),
                path.as_os_str().as_bytes(),
            )
            .unwrap();
        }
    }

    #[test]
    fn reap_dead_projects_reclaims_only_a_gone_project_with_a_present_parent() {
        let base = TmpDir::new();
        let projects = base.path().join("projects");

        // a LIVE project — its marker points at an existing directory
        let live_proj = base.path().join("live-proj");
        std::fs::create_dir_all(&live_proj).unwrap();
        make_tree(&projects, "1111111111111111", Some(&live_proj));

        // a DEAD project — path absent, but its parent (a workspace) still exists
        let workspace = base.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let dead_path = workspace.join("gone-proj"); // never created
        make_tree(&projects, "2222222222222222", Some(&dead_path));

        // a project whose ENCLOSING tree is gone — path absent AND its parent absent too, so the
        // parent-exists guard keeps it (this is the case the guard actually catches — not a
        // persistent-mountpoint unmount, which it does not)
        let enclosing_gone = base.path().join("removed/workspace/proj"); // no component exists
        make_tree(&projects, "3333333333333333", Some(&enclosing_gone));

        // a BUSY dead project — path gone, parent present, but a live session holds the id
        let busy_path = workspace.join("busy-proj");
        make_tree(&projects, "4444444444444444", Some(&busy_path));

        // an UNIDENTIFIED tree — no marker at all
        make_tree(&projects, "5555555555555555", None);

        let live = BTreeSet::from(["4444444444444444".to_string()]);

        // dry run: the one dead tree and the one unidentified tree are reported, nothing removed
        let report = reap_dead_projects(&projects, &live, false, false);
        assert_eq!(report.dead.len(), 1, "exactly one tree is reclaimable");
        assert_eq!(report.dead[0].path, dead_path);
        assert_eq!(
            report.unidentified.len(),
            1,
            "the markerless tree is listed"
        );
        assert!(
            report.reaped_unidentified.is_empty(),
            "no opt-in, no reaping"
        );
        assert!(report.dead[0].bytes > 0, "the dead tree's size is measured");
        assert!(
            projects.join("2222222222222222").is_dir(),
            "a dry run removed a tree"
        );

        // prune: only the dead, present-parent, not-busy, identified tree is removed
        let report = reap_dead_projects(&projects, &live, true, false);
        assert_eq!(report.dead.len(), 1);
        assert!(
            !projects.join("2222222222222222").exists(),
            "the dead tree (read-only store dirs and all) was not reclaimed"
        );
        assert!(
            projects.join("1111111111111111").is_dir(),
            "a live project was reclaimed"
        );
        assert!(
            projects.join("3333333333333333").is_dir(),
            "a tree whose parent is also absent was reclaimed — the parent-exists guard failed"
        );
        assert!(
            projects.join("4444444444444444").is_dir(),
            "a busy project (held by a live session) was reclaimed"
        );
        assert!(
            projects.join("5555555555555555").is_dir(),
            "an unidentified (markerless) tree was reclaimed"
        );
    }

    /// `reap_one` targets a single named tree. The caller names the id, so no deadness proof and
    /// no marker are needed — it reaps markerless and idle trees alike. The only guard is the
    /// live-session one; a missing id is reported so a typo never silently succeeds.
    #[test]
    fn reap_one_targets_a_named_tree_with_only_the_live_guard() {
        let base = TmpDir::new();
        let projects = base.path().join("projects");
        std::fs::create_dir_all(&projects).unwrap();

        // a markerless tree (no marker) — reaped because the user named it, not because it is dead
        make_tree(&projects, "aaaaaaaaaaaaaaaa", None);
        // an idle tree (marker points at an existing project) — also reaped when named
        let real = base.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        make_tree(&projects, "bbbbbbbbbbbbbbbb", Some(&real));
        // a tree a live session holds — refused
        make_tree(&projects, "cccccccccccccccc", None);
        let live = BTreeSet::from(["cccccccccccccccc".to_string()]);

        // a missing id is reported, never silently succeeding.
        match reap_one(&projects, "deadbeefdeadbeef", &live, true) {
            ReapOneOutcome::NotFound => {}
            other => panic!("a missing id must be NotFound, got {other:?}"),
        }

        // a live id is refused.
        match reap_one(&projects, "cccccccccccccccc", &live, true) {
            ReapOneOutcome::Live => {}
            other => panic!("a live tree must be refused, got {other:?}"),
        }
        assert!(
            projects.join("cccccccccccccccc").is_dir(),
            "a live tree was reaped despite the guard"
        );

        // dry run on a markerless tree: reported as a Tree, not removed.
        let out = reap_one(&projects, "aaaaaaaaaaaaaaaa", &live, false);
        let ReapOneOutcome::Tree { dir, bytes } = out else {
            panic!("markerless tree must be a Tree outcome, got {out:?}")
        };
        assert!(dir.ends_with("aaaaaaaaaaaaaaaa"));
        assert!(bytes > 0, "the tree's size is measured");
        assert!(
            projects.join("aaaaaaaaaaaaaaaa").is_dir(),
            "a dry run removed a named tree"
        );

        // prune on an idle tree (marker points at an existing project): reaped anyway, because the
        // user named it — `reap_one` does not apply the deadness check `reap_dead_projects` does.
        let out = reap_one(&projects, "bbbbbbbbbbbbbbbb", &live, true);
        assert!(matches!(out, ReapOneOutcome::Tree { .. }));
        assert!(
            !projects.join("bbbbbbbbbbbbbbbb").exists(),
            "an idle named tree was not reaped"
        );
        // the live tree is still there.
        assert!(projects.join("cccccccccccccccc").is_dir());
    }

    /// `is_safe_tree_id` accepts a single ordinary component (a real id) and refuses every path-ish
    /// form — the anti-traversal guard for `ops gc --id`.
    #[test]
    fn is_safe_tree_id_rejects_traversal_and_absolute_ids() {
        // Real ids (16-hex) and any single component are fine.
        assert!(is_safe_tree_id("0123456789abcdef"));
        assert!(is_safe_tree_id("markerlessid"));
        // Traversal, absolute, separators, and the dot forms are all refused.
        for bad in [
            "",
            ".",
            "..",
            "/etc",
            "../etc",
            "../../home",
            "a/b",
            "foo/../bar",
            "sub/",
            "/",
        ] {
            assert!(!is_safe_tree_id(bad), "must refuse `{bad}`");
        }
    }

    /// `reap_one` refuses a traversal/absolute id at the sink — it never joins it onto `projects/`
    /// nor deletes anything, even with `prune`. Teeth: a real directory that a naive `join` of the
    /// id would have reached is left untouched.
    #[test]
    fn reap_one_refuses_a_traversal_id_without_deleting() {
        let base = TmpDir::new();
        let projects = base.path().join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        // A sibling of `projects/` that `projects.join("../victim")` would resolve to.
        let victim = base.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        let live = BTreeSet::new();

        match reap_one(&projects, "../victim", &live, true) {
            ReapOneOutcome::NotFound => {}
            other => panic!("a traversal id must be NotFound, got {other:?}"),
        }
        assert!(victim.is_dir(), "the traversal target must be untouched");

        // An absolute id would `join`-replace the base; it too is refused, nothing removed.
        match reap_one(&projects, "/", &live, true) {
            ReapOneOutcome::NotFound => {}
            other => panic!("an absolute id must be NotFound, got {other:?}"),
        }
        assert!(victim.is_dir(), "still untouched after an absolute id");
    }

    /// `--unidentified` reaps markerless trees without a deadness proof — but the live-session guard
    /// still holds (a markerless tree a running session uses is never touched), and a dry run with
    /// the opt-in reports them without removing them.
    #[test]
    fn reap_dead_projects_unidentified_opt_in_reaps_markerless_trees() {
        let base = TmpDir::new();
        let projects = base.path().join("projects");
        std::fs::create_dir_all(&projects).unwrap();

        // a markerless tree nothing holds — ripe for the opt-in reap
        make_tree(&projects, "aaaaaaaaaaaaaaaa", None);
        // a markerless tree a LIVE session still holds — the guard must protect it even under the
        // opt-in, since `--unidentified` reaps without a deadness proof, not without a liveness one
        make_tree(&projects, "bbbbbbbbbbbbbbbb", None);
        let live = BTreeSet::from(["bbbbbbbbbbbbbbbb".to_string()]);

        // dry run with the opt-in: both reported as candidates, neither removed
        let report = reap_dead_projects(&projects, &live, false, true);
        assert_eq!(
            report.unidentified.len(),
            1,
            "only the unheld markerless tree is a candidate; the live one is guarded away"
        );
        assert!(
            report.reaped_unidentified.is_empty(),
            "dry run reaped nothing"
        );
        assert!(
            projects.join("aaaaaaaaaaaaaaaa").is_dir(),
            "a dry run removed a markerless tree"
        );
        assert!(
            projects.join("bbbbbbbbbbbbbbbb").is_dir(),
            "the live markerless tree disappeared in a dry run"
        );

        // prune with the opt-in: the unheld markerless tree is reaped, the live one is kept
        let report = reap_dead_projects(&projects, &live, true, true);
        assert_eq!(
            report.reaped_unidentified.len(),
            1,
            "the unheld markerless tree was reaped"
        );
        assert!(
            report.reaped_unidentified[0]
                .dir
                .ends_with("aaaaaaaaaaaaaaaa"),
            "the reaped tree is the unheld one"
        );
        assert!(
            report.unidentified.is_empty(),
            "no markerless tree left unreported"
        );
        assert!(
            !projects.join("aaaaaaaaaaaaaaaa").exists(),
            "the unheld markerless tree was not removed"
        );
        assert!(
            projects.join("bbbbbbbbbbbbbbbb").is_dir(),
            "the live markerless tree was reaped despite the guard"
        );
    }

    #[test]
    fn force_remove_dir_all_clears_read_only_dirs_and_unlinks_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let base = TmpDir::new();
        let tree = base.path().join("tree");
        let store = tree.join("store/nix/store/xxxx");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("file"), b"x").unwrap();
        // a symlink to a real file outside the tree must be unlinked, never followed
        std::os::unix::fs::symlink("/etc/hostname", tree.join("link")).unwrap();
        // nix-style read-only directory
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o555)).unwrap();

        force_remove_dir_all(&tree).unwrap();
        assert!(!tree.exists(), "the read-only tree was not removed");
        assert!(
            Path::new("/etc/hostname").exists(),
            "a symlink target was followed and deleted"
        );
    }

    #[test]
    fn prune_shared_gcroots_drops_stale_revs_and_dead_projects_only() {
        let base = TmpDir::new();
        let gcroots = base.path().join("gcroots");
        let projects = base.path().join("projects");

        let mk = |dir: &Path| {
            std::fs::create_dir_all(dir).unwrap();
            std::os::unix::fs::symlink("/nix/store/x", dir.join("root")).unwrap();
        };
        // base + gui are both keyed by the base channel rev: "live" current, "stale" rolled away
        mk(&gcroots.join("base/live"));
        mk(&gcroots.join("base/stale"));
        mk(&gcroots.join("gui/live"));
        mk(&gcroots.join("gui/stale"));
        // mise keyed by the engine rev
        mk(&gcroots.join("mise/eng"));
        mk(&gcroots.join("mise/oldeng"));
        // per-project roots: p1 still has a runtime tree, p2 was reaped
        mk(&gcroots.join("projects/p1/tool"));
        mk(&gcroots.join("projects/p2/tool"));
        std::fs::create_dir_all(projects.join("p1")).unwrap();

        let live_base = BTreeSet::from(["live".to_string()]);
        let live_mise = BTreeSet::from(["eng".to_string()]);

        // a dry run lists the stale set (base/stale, gui/stale, mise/oldeng, projects/p2) and
        // removes nothing
        let listed = prune_shared_gcroots(&gcroots, &projects, &live_base, &live_mise, false);
        assert_eq!(listed.len(), 4, "stale set: {listed:?}");
        assert!(
            gcroots.join("base/stale").is_dir(),
            "a dry run removed a root"
        );

        // a prune removes exactly those, keeping every live revision and the live project
        let removed = prune_shared_gcroots(&gcroots, &projects, &live_base, &live_mise, true);
        assert_eq!(removed.len(), 4);
        assert!(!gcroots.join("base/stale").exists() && gcroots.join("base/live").is_dir());
        assert!(!gcroots.join("gui/stale").exists() && gcroots.join("gui/live").is_dir());
        assert!(!gcroots.join("mise/oldeng").exists() && gcroots.join("mise/eng").is_dir());
        assert!(!gcroots.join("projects/p2").exists() && gcroots.join("projects/p1").is_dir());
    }
}
