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
    let out = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(store_dir)
        .arg("--query")
        .arg("--size")
        .args(paths)
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix-store --query --size failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<u64>().ok())
        .sum())
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
    /// deadness cannot be verified: listed for a manual decision, never reclaimed automatically.
    pub(crate) unidentified: Vec<UnidentifiedTree>,
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
/// live session holds it (`live_ids`, the ids of running sessions). A tree with no usable marker is
/// never reclaimed — its path is unknown, so deadness
/// cannot be verified — only reported. Destructive only when `prune`; a dry run computes the same
/// set and changes nothing.
pub(crate) fn reap_dead_projects(
    projects_dir: &Path,
    live_ids: &BTreeSet<String>,
    prune: bool,
) -> ReapReport {
    let mut dead = Vec::new();
    let mut unidentified = Vec::new();
    let entries = match std::fs::read_dir(projects_dir) {
        Ok(e) => e,
        // No projects tree yet — nothing to reap.
        Err(_) => return ReapReport { dead, unidentified },
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        // A live session still using this tree: never touch it, whatever its marker says.
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
            // No usable marker — the project path is unknown, so list only.
            None => unidentified.push(UnidentifiedTree {
                bytes: tree_size(&dir),
                dir,
            }),
        }
    }
    ReapReport { dead, unidentified }
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
        let report = reap_dead_projects(&projects, &live, false);
        assert_eq!(report.dead.len(), 1, "exactly one tree is reclaimable");
        assert_eq!(report.dead[0].path, dead_path);
        assert_eq!(
            report.unidentified.len(),
            1,
            "the markerless tree is listed"
        );
        assert!(report.dead[0].bytes > 0, "the dead tree's size is measured");
        assert!(
            projects.join("2222222222222222").is_dir(),
            "a dry run removed a tree"
        );

        // prune: only the dead, present-parent, not-busy, identified tree is removed
        let report = reap_dead_projects(&projects, &live, true);
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
}
