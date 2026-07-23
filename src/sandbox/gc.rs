//! In-project store garbage collection.
//!
//! A project's own writable store (`<data>/projects/<id>/store`) grows as the agent
//! self-equips: every host-provisioned `nix:`/`flake:` build seeded here, every in-cage
//! `mise`/inline-flake install lands a closure there. Most of it stays referenced — the base
//! userland and the project's declared tools are gc-rooted at seed time (see
//! [`super::projectstore`]), mise installs root themselves — but a build superseded by a roll, and
//! a package removed outright, leave the previous closure unreferenced. This reclaims those.
//!
//! The stale roots come in two shapes, pruned before the sweep. An inline `[flakes.<name>]` flake
//! builds in-cage and registers a name-keyed `sbx-flake-<name>` root in the project store, which
//! [`prune_flake_roots`] drops once its name leaves the config (an edit self-cleans; a removal
//! cannot reach itself). A host-provisioned package (`nix:`, a remote `flake:`, the prebuilt trio)
//! carries a data-dir out-link that [`prune_project_package_roots`] drops on removal, while
//! [`prune_superseded_roots`] reconciles the per-project seed roots a roll supersedes. Then a plain
//! `nix-store --gc` against the project store sweeps: every live build carries a root whose target is
//! a `/nix/store/<hash>` path, which the relocated store resolves host-side, so the sweep keeps the
//! live set and collects the rest — no per-home enumeration. The default is a dry run: it reports
//! what would be freed with `--print-dead`, summed by `--query --size`, and only changes anything
//! when the caller asks.

use std::collections::BTreeSet;
use std::ffi::OsString;
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

/// Remove the in-cage `sbx-flake-<name>` gc roots whose inline flake is no longer declared.
///
/// Only an inline `[flakes.<name>]` flake builds in-cage and registers this name-keyed root,
/// overwritten each launch — so an edit (same name, new build) self-cleans, but a *removed* inline
/// flake's root lingers, pointing at a build nothing wants. This drops those roots so the following
/// sweep reclaims their builds. A remote `flake:` package is provisioned host-side and never writes
/// here — its data-dir out-link is pruned by [`prune_project_package_roots`] instead. `current` is
/// the set of currently-declared inline-flake names across the project's runtimes; any
/// `sbx-flake-<name>` root whose `<name>` is not in it is stale. Read-only unless `prune` (a dry run
/// lists what it would remove without touching anything). Returns the stale roots.
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
            .and_then(|n| n.strip_prefix("sbx-flake-"))
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

/// Remove — or, in a dry run, list — the **data-dir** `<data>/gcroots/projects/<id>/<name>`
/// out-links of host-provisioned packages that are no longer declared. `packages::provision` (and
/// the `deb:`/`appimage:`/`tarball:` build paths) write one out-link per declared package there —
/// bare `<name>` for `nix:`, `deb-`/`appimage-`/`tarball-<name>` for a prebuilt — and never remove
/// one for a package the config drops, so a *removed* package leaks: [`project_keep_roots`] then
/// still reads its (possibly dangling) out-link into the keep-set, and [`prune_superseded_roots`]
/// keeps the per-project store copy it holds forever. This is the analogue of [`prune_flake_roots`]
/// for that directory. `current` is the gcroot names of every currently-declared such package across
/// the project's runtimes (see [`super::packages::project_gcroot_names`]); an out-link matching none
/// is stale, and dropping it lets the same gc pass reclaim its per-project copy.
///
/// **Multi-output.** `nix build --out-link <name>` links *every* output of a derivation, so one
/// `nix:` package roots `<name>` **and** siblings like `<name>-man`/`<name>-dev`. A sibling shares
/// the `<name>-` prefix, so it is kept whenever its base package is declared — otherwise a live
/// package's man/dev output would be deleted on every gc. A pruned prebuilt root's sibling `.expr`
/// stamp (a plain file [`super::store::provision_expr`] writes beside it) is removed with it; the
/// stamp of a *kept* root is a non-symlink and is never touched. Destructive only when `prune`.
pub(crate) fn prune_project_package_roots(
    data_gcroots: &Path,
    id: &str,
    current: &BTreeSet<String>,
    prune: bool,
) -> Vec<PathBuf> {
    let dir = data_gcroots.join("projects").join(id);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        // Only the out-link symlinks are package roots; the `.expr` stamp beside a prebuilt root is a
        // plain file, handled with its root below and otherwise left to a kept root.
        if !entry.file_type().is_ok_and(|t| t.is_symlink()) {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        // Keep the out-link of a currently-declared package, and any multi-output sibling `<name>-…`.
        if current.iter().any(|n| {
            name == n
                || name
                    .strip_prefix(n.as_str())
                    .is_some_and(|r| r.starts_with('-'))
        }) {
            continue;
        }
        let path = entry.path();
        if prune {
            if std::fs::remove_file(&path).is_ok() {
                // Drop the sibling `.expr` stamp of a pruned prebuilt root so a re-add rebuilds clean
                // rather than short-circuiting on a stamp whose out-link is gone. A `nix:` root has no
                // such stamp, so this is a harmless no-op there.
                let mut stamp = path.clone().into_os_string();
                stamp.push(".expr");
                let _ = std::fs::remove_file(PathBuf::from(stamp));
                removed.push(path);
            }
        } else {
            removed.push(path);
        }
    }
    removed
}

/// The store-path basenames every *current* out-link of a project still points at — the keep-set a
/// per-project store gc reconciles its accumulated seed roots against. `data_gcroots` is
/// `<data>/gcroots`; the six root families that can seed a per-project store are all covered so the
/// keep-set is complete by construction: the project's own `projects/<id>/*` (its provisioned
/// `nix:`/`deb:` tools and the GUI app builds an `sbx app` run from here left), the base userland and
/// the gui/gpu/audio holes for the project's channel revision `base_rev` (`{base,gui,gpu,audio}/<base_rev>/*`),
/// and the in-cage mise engine for each live engine revision (`mise/<mise_rev>/*` — mise is rooted on
/// its *own* revision, not the base one, so omitting it would drop the current mise). Each out-link
/// points at a `…/nix/store/<hash-name>` build; its basename is the key, matching a seed root's own
/// file name. A broken or absent out-link simply contributes nothing.
pub(crate) fn project_keep_roots(
    data_gcroots: &Path,
    id: &str,
    base_rev: &str,
    mise_revs: &BTreeSet<String>,
) -> BTreeSet<OsString> {
    let mut keep = BTreeSet::new();
    let mut add_targets = |dir: PathBuf| {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                if let Some(base) = target.file_name() {
                    keep.insert(base.to_os_string());
                }
            }
        }
    };
    add_targets(data_gcroots.join("projects").join(id));
    for family in ["base", "gui", "gpu", "audio"] {
        add_targets(data_gcroots.join(family).join(base_rev));
    }
    for rev in mise_revs {
        add_targets(data_gcroots.join("mise").join(rev));
    }
    keep
}

/// Prune — or, in a dry run, list — the per-project store's accumulated **seed** gc roots for
/// superseded builds, returning the roots dropped. [`super::projectstore::gcroot_roots`] is
/// add-only: every seeded or provisioned path gets a permanent `gcroots/<hash-name>` root and a
/// newer build's root never displaces the older one, so each version a project ever provisioned
/// stays rooted and a plain `nix-store --gc` reports zero dead however many are superseded (its mark
/// phase honours every root). This reconciles those direct roots against `keep` — the store-path
/// basenames a current out-link still references (see [`project_keep_roots`]). A root whose file name
/// (which *is* the store-path basename it roots) is not in `keep` roots a build nothing current points
/// at; dropping it lets the following [`collect`] reclaim that build. nix recomputes reachability
/// during the sweep, so a shared dependency still reachable from a kept build survives even though its
/// own direct root was dropped. nix's own `auto/` indirect-root directory and the `sbx-flake-*` roots
/// [`prune_flake_roots`] owns are never touched. Destructive only when `prune`.
///
/// Deriving the keep-set at gc time — from the *union* of every out-link family a project ever
/// accumulated — is deliberate: a single launch's seed sees only its own subset (a base-only `sbx run`
/// would omit every app build), so this must never move to seed time.
pub(crate) fn prune_superseded_roots(
    store_dir: &Path,
    keep: &BTreeSet<OsString>,
    prune: bool,
) -> Vec<PathBuf> {
    let dir = super::projectstore::gcroots_dir(store_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        // nix's own indirect-root directory, and the flake roots `prune_flake_roots` owns, are
        // off-limits — this pass reconciles only the seed roots.
        if name == "auto" || name.to_str().is_some_and(|n| n.starts_with("sbx-flake-")) {
            continue;
        }
        // A seed root's file name is the store-path basename it roots; keep it while a current
        // out-link still points at that build.
        if keep.contains(&name) {
            continue;
        }
        // A seed root is a symlink; never remove a stray directory or regular file that landed here.
        if !entry.file_type().is_ok_and(|t| t.is_symlink()) {
            continue;
        }
        let path = entry.path();
        if prune {
            if std::fs::remove_file(&path).is_ok() {
                removed.push(path);
            }
        } else {
            removed.push(path);
        }
    }
    removed
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
/// invoking nix.
///
/// `--query --size` prints one size per path in argv order and aborts at the *first* path it
/// rejects as invalid — an interrupted build leaves residue in the store dir (a `<store-path>.lock`
/// build lock, a `.chroot` build root) that `--gc --print-dead` reports yet which is not a
/// registered store object, so it trips this. One such entry must not derail the whole collection,
/// so a failing batch is not fatal: the sizes printed before the abort are summed, the single
/// rejected path is skipped, and sizing resumes after it. The figure is only a report — `sweep`
/// still deletes every dead entry regardless.
fn total_size(nix_store: &Path, store_dir: &Path, paths: &[String]) -> io::Result<u64> {
    // Query in bounded windows: passing every dead path as one argv overflows the kernel's argv
    // limit (E2BIG) on a large store, which would abort the whole GC (including `--prune`). Store
    // paths are ~100 bytes each, so a few thousand per call stays well under any ARG_MAX.
    const BATCH: usize = 2048;
    let mut total = 0u64;
    let mut i = 0;
    while i < paths.len() {
        let end = (i + BATCH).min(paths.len());
        let out = Command::new(nix_store)
            .env("NIX_REMOTE", "")
            .arg("--store")
            .arg(store_dir)
            .arg("--query")
            .arg("--size")
            .args(&paths[i..end])
            .output()?;
        let (bytes, consumed) = parse_size_batch(&String::from_utf8_lossy(&out.stdout));
        total += bytes;
        if out.status.success() {
            i = end;
        } else {
            // nix sized the `consumed` leading paths, then rejected the next one. Skip that path
            // (its size is unknowable and it is residue, not a real store object) and resume; the
            // step is always at least one, so the loop terminates.
            i += consumed + 1;
        }
    }
    Ok(total)
}

/// Fold one `--query --size` batch: sum the byte sizes it printed and count how many paths nix
/// processed. `--query --size` prints one integer per path in argv order and stops at the first
/// invalid path, so the line count is exactly the number of leading paths consumed — which locates
/// the rejected path (the next one) when the batch failed. A non-integer line still counts as a
/// consumed path but contributes no bytes, so a stray line never skews the resume offset.
fn parse_size_batch(stdout: &str) -> (u64, usize) {
    let mut bytes = 0u64;
    let mut consumed = 0usize;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        consumed += 1;
        if let Ok(size) = trimmed.parse::<u64>() {
            bytes += size;
        }
    }
    (bytes, consumed)
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
    /// opts in with `--markerless` (the entries actually removed land in `reaped_unidentified`).
    pub(crate) unidentified: Vec<UnidentifiedTree>,
    /// Markerless trees reclaimed under the `--markerless` opt-in. Empty unless the caller passed
    /// `prune_unidentified`; the trees in this list have already been removed.
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
/// — a fail-closed escape hatch (`sbx projects rm --markerless --yes`) that reaps markerless trees
/// *without* a deadness proof, after the live-session guard has already excluded any tree a running
/// session holds. The caller owns that risk: a markerless tree belonging to a project still in use
/// (a pre-marker launch, or a marker write that failed) would be lost, so the flag is never the
/// default.
///
/// The two switches are **independent**: `prune` reaps the dead (marker-identified, gone) trees and
/// `prune_unidentified` reaps the markerless ones, so a caller can sweep either category alone or
/// both. With neither set the call is a pure dry run — it computes the same sets and changes nothing.
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
            // No usable marker. Default: report for a manual decision. With the `--markerless`
            // opt-in (`prune_unidentified`, independent of the dead reap), reclaim the tree too (no
            // deadness proof — the caller accepts that risk).
            None => {
                let bytes = tree_size(&dir);
                if prune_unidentified {
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
/// guard for `sbx gc --id`: the id is joined onto `projects/` and fed to a recursive delete, so a
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

/// One home directory a purge removed, and the bytes it freed.
pub(crate) struct PurgedHome {
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
}

/// The outcome of purging an app's isolated home directories: what was removed, and what could not
/// be. Best-effort by design — one directory that fails to remove never stops the others.
pub(crate) struct AppPurgeReport {
    /// Homes removed, each with the bytes it freed.
    pub(crate) removed: Vec<PurgedHome>,
    /// Homes that existed but could not be removed (path and the reason), reported not swallowed.
    pub(crate) failed: Vec<(PathBuf, io::Error)>,
}

impl AppPurgeReport {
    /// No home was found at all (nothing removed, nothing failed) — the caller uses this to tell a
    /// genuine no-op (a typo, an app that left no runtime state) from a successful purge.
    pub(crate) fn found_nothing(&self) -> bool {
        self.removed.is_empty() && self.failed.is_empty()
    }

    /// Total bytes reclaimed across the removed homes.
    pub(crate) fn freed(&self) -> u64 {
        self.removed.iter().map(|h| h.bytes).sum()
    }
}

/// Remove app `name`'s isolated runtime directories — the global home `<data>/apps/<name>/` (shared
/// across projects) and each per-project directory `<data>/projects/<id>/apps/<name>/`. The whole
/// `apps/<name>/` subtree is removed at each site, so it reclaims everything an app keeps there: a
/// per-project (`home_scope = "project"`) app's home, and — for a **global** app — its per-project
/// mise pool (`mise/`, the `nix:`-via-mise self-equips kept `/nix`-aligned per project beside the
/// shared store), which sits under the same `apps/<name>/` dir and so goes with it. These hold the
/// app's mise data (the tools its `mise:` backends installed), its config, and its login/session
/// state — all app-exclusive, so removing them frees that state immediately. The shared per-project
/// nix store, which backs *every* app in a project, is deliberately **not** touched here; `sbx gc`
/// owns its reclamation (a purged app's `nix:`/`flake:` closures — the pool's included — become
/// collectable once their in-pool out-links are removed with the pool).
///
/// `name` reaches [`force_remove_dir_all`], so the same single-ordinary-component guard the reap
/// sink applies ([`is_safe_tree_id`]) is re-applied here before any `join`: a separator, a `..`, or
/// an absolute form would turn the join into a delete outside the data directory. The CLI validates
/// the name too (with a clearer message); this is defense at the sink. Best-effort per directory.
pub(crate) fn purge_app_homes(data_dir: &Path, name: &str) -> AppPurgeReport {
    let mut removed = Vec::new();
    let mut failed = Vec::new();
    // Defense at the sink: `name` is about to be joined onto a path that reaches a recursive delete.
    if !is_safe_tree_id(name) {
        return AppPurgeReport { removed, failed };
    }
    // The global home, then each per-project home under an existing project tree.
    let mut candidates = vec![data_dir.join("apps").join(name)];
    if let Ok(entries) = std::fs::read_dir(data_dir.join("projects")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                candidates.push(entry.path().join("apps").join(name));
            }
        }
    }
    for dir in candidates {
        if !dir.is_dir() {
            continue;
        }
        let bytes = tree_size(&dir);
        match force_remove_dir_all(&dir) {
            Ok(()) => removed.push(PurgedHome { path: dir, bytes }),
            Err(e) => failed.push((dir, e)),
        }
    }
    AppPurgeReport { removed, failed }
}

/// One app that has isolated runtime state on disk — its home(s) under the data directory. The
/// read-only counterpart of [`purge_app_homes`], for the `sbx app list` view: it lets a user see
/// which apps have installed tools/login state (even ones with no imported profile) before deciding
/// what to purge. An app may have a global home (shared across projects), per-project homes, or both.
///
/// A per-project tree carries a **home** only for a `home_scope = "project"` app. A
/// `home_scope = "global"` app keeps its single home under `<data>/apps/<name>/` yet still gets a
/// per-project **mise pool** (`<data>/projects/<id>/apps/<name>/mise`, its install pool kept aligned
/// with that project's `/nix` store). The two are counted separately, so a bare pool is never
/// reported as a second isolated home; both are sized into [`project_bytes`], the disk a purge
/// reclaims.
///
/// A pool that holds **no tool** is not counted at all: every launch creates the pool dir (the
/// writable bind needs an existing source), so an app that has merely *run* in a project carries an
/// empty pool there, and reporting it would say the app has per-project state it does not. Only a
/// pool the agent actually self-equipped into is state worth listing. Its size still counts (it is
/// a handful of directory blocks, and a purge does remove it).
///
/// [`project_bytes`]: InstalledApp::project_bytes
pub(crate) struct InstalledApp {
    pub(crate) name: String,
    /// Size of the global home `<data>/apps/<name>/`, or `None` when there is none.
    pub(crate) global_bytes: Option<u64>,
    /// Number of per-project trees carrying a real home `<data>/projects/<id>/apps/<name>/home`.
    pub(crate) project_homes: usize,
    /// Number of per-project trees carrying a mise pool with at least one installed tool, and no
    /// home of their own. An empty pool — the dir every launch creates — is not counted.
    pub(crate) project_pools: usize,
    /// Total size across every per-project tree: homes, tool-bearing pools, and empty pools alike.
    pub(crate) project_bytes: u64,
}

impl InstalledApp {
    /// Total disk a full `sbx app rm <name> --purge` would free (global + every per-project tree).
    pub(crate) fn total_bytes(&self) -> u64 {
        self.global_bytes.unwrap_or(0) + self.project_bytes
    }
}

/// Whether a mise pool dir holds at least one installed tool — the test that separates a pool worth
/// reporting from the empty one every launch creates. The pool *is* mise's data dir, so its tools
/// live directly under `<pool>/installs/` (unlike a home, whose mise data sits under
/// `.local/share/mise`). A pool with no `installs/`, or an empty one, carries only the plugin symlink
/// and the migration markers a launch writes — nothing the user installed.
fn pool_holds_a_tool(pool: &Path) -> bool {
    std::fs::read_dir(pool.join("installs")).is_ok_and(|mut e| e.next().is_some())
}

/// Enumerate the apps with isolated state on disk, grouped and sized by name. Scans the global homes
/// under `<data>/apps/` and the per-project trees under `<data>/projects/<id>/apps/`, sizing each
/// with [`tree_size`] and classifying a per-project tree as a home when it carries a `home/` dir
/// (the same test [`app_home_dirs`] applies), else as a mise pool — counted only when the pool holds
/// an installed tool ([`pool_holds_a_tool`]). Sorted by name. Read-only; a missing tree is simply no
/// state. Sizing is a recursive stat, so a very large mise data dir makes this proportionally slower
/// — acceptable for an interactive management listing, where the size is the point (it drives the
/// purge decision).
///
/// [`app_home_dirs`]: super::inspect::app_home_dirs
pub(crate) fn installed_app_homes(data_dir: &Path) -> Vec<InstalledApp> {
    use std::collections::BTreeMap;
    // name -> (global_bytes, project_homes, project_pools, project_bytes)
    let mut apps: BTreeMap<String, (Option<u64>, usize, usize, u64)> = BTreeMap::new();

    // Global homes: <data>/apps/<name>/
    if let Ok(entries) = std::fs::read_dir(data_dir.join("apps")) {
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                let bytes = tree_size(&entry.path());
                apps.entry(name.to_string()).or_default().0 = Some(bytes);
            }
        }
    }

    // Per-project trees: <data>/projects/<id>/apps/<name>/ — a home only when it carries `home/`,
    // otherwise the global app's mise pool for that project.
    if let Ok(projects) = std::fs::read_dir(data_dir.join("projects")) {
        for project in projects.flatten() {
            if !project.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(project.path().join("apps")) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                if let Some(name) = entry.file_name().to_str() {
                    let path = entry.path();
                    let bytes = tree_size(&path);
                    let e = apps.entry(name.to_string()).or_default();
                    if path.join("home").is_dir() {
                        e.1 += 1;
                    } else if pool_holds_a_tool(&path.join("mise")) {
                        e.2 += 1;
                    }
                    e.3 += bytes;
                }
            }
        }
    }

    apps.into_iter()
        .map(
            |(name, (global_bytes, project_homes, project_pools, project_bytes))| InstalledApp {
                name,
                global_bytes,
                project_homes,
                project_pools,
                project_bytes,
            },
        )
        .collect()
}

/// One mise tool `sbx app prune` would remove (or removed) from an app home — a tool the app's
/// config does not declare (a leftover from a former profile, or one pulled in by hand).
pub(crate) struct PrunedTool {
    /// The tool's real backend token (`pipx:demo-agent`), for the report.
    pub(crate) token: String,
    /// On-disk size of the install that was (or would be) freed.
    pub(crate) bytes: u64,
}

/// Remove the mise tools an app's home carries that its config does **not** declare — `sbx app
/// prune`. `declared` is the app's declared `mise:` tokens; any installed tool not matching one is
/// undeclared and pruned: its install dir under `<home>/.local/share/mise/installs/` is deleted, and
/// (so it does not re-equip at the next launch) its entry is dropped from the home's
/// `<home>/.config/mise/config.toml` `[tools]`. With `apply = false` nothing is removed — the return
/// is the preview of what would go. Read-only when previewing; a targeted cleanup when applying.
pub(crate) fn prune_app_tools(home: &Path, declared: &[&str], apply: bool) -> Vec<PrunedTool> {
    let installs = home.join(".local/share/mise/installs");
    let mut pruned = Vec::new();
    let mut removed_any = false;
    for tool in super::inspect::mise_installed(home) {
        if declared.iter().any(|d| tool.is(d)) {
            continue; // declared — keep it.
        }
        let dir = installs.join(&tool.name);
        let bytes = tree_size(&dir);
        if apply {
            removed_any |= force_remove_dir_all(&dir).is_ok();
        }
        pruned.push(PrunedTool {
            token: tool.label().to_string(),
            bytes,
        });
    }
    // Drop the pruned tools from the home's mise config so a later launch does not re-equip them.
    if apply && removed_any {
        prune_mise_config(&home.join(".config/mise/config.toml"), declared);
    }
    pruned
}

/// Remove from a mise `config.toml`'s `[tools]` table every entry whose token the app does not
/// declare, leaving the declared ones (and any other section) untouched. A no-op if the file is
/// absent/unparsable or nothing changes. The file is machine-generated by `mise use`, so a
/// reserialize loses no meaningful formatting.
fn prune_mise_config(path: &Path, declared: &[&str]) {
    let Ok(body) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(mut doc) = body.parse::<toml::Table>() else {
        return;
    };
    let Some(toml::Value::Table(tools)) = doc.get_mut("tools") else {
        return;
    };
    let before = tools.len();
    tools.retain(|key, _| {
        declared
            .iter()
            .any(|d| *d == key || super::inspect::mise_munge(d) == super::inspect::mise_munge(key))
    });
    if tools.len() != before {
        if let Ok(out) = toml::to_string(&doc) {
            let _ = std::fs::write(path, out);
        }
    }
}

/// The state of one project tree, for `sbx path`'s per-project annotation. The non-destructive,
/// finer-grained counterpart of [`reap_dead_projects`] (which folds `Live` and `Idle` into "keep"):
/// `Live` (a running session holds it), `Idle` (no session, the marker points at a project
/// directory that still exists), `Dead` (the marker points at a gone path — reclaimable by `sbx gc
/// --all`), or `Markerless` (no marker — a pre-marker orphan, identity unknown).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum TreeState {
    Live,
    Idle,
    Dead,
    Markerless,
}

impl TreeState {
    /// The short tag rendered beside a project's path by `sbx path`.
    pub(crate) fn label(self) -> &'static str {
        match self {
            TreeState::Live => "live",
            TreeState::Idle => "idle",
            TreeState::Dead => "dead",
            TreeState::Markerless => "markerless",
        }
    }
}

/// A project tree's classification plus the last time it was touched, for `sbx path`'s per-project
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
pub(crate) fn force_remove_dir_all(path: &Path) -> io::Result<()> {
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
pub(crate) fn tree_size(path: &Path) -> u64 {
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
/// it is rooted under `<data>/gcroots/`: `base/<rev>/`, `gui/<rev>/`, `gpu/<rev>/`, and
/// `audio/<rev>/` (all four keyed by the base channel revision — a hole's userspace is provisioned
/// against the same channel as the base), `mise/<rev>/` (the engine revision), and `projects/<id>/` (a project's
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
    // base and the gui/gpu/audio hole userspaces are all keyed by the base channel revision: a
    // hole's closure (fonts, mesa, the audio libraries) is built against the same channel as the
    // base, so a base revision leaving the live set strands every hole built for it too. The family
    // list is the one `project_keep_roots` uses, so the two cannot drift.
    for family in ["base", "gui", "gpu", "audio"] {
        prune_rev_dirs(&gcroots_dir.join(family), live_base, prune, &mut removed);
    }
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

/// The per-launch runtime directories under the data dir, each with the filename prefixes whose
/// entries are keyed by the **launcher pid**.
///
/// These hold a launch's live plumbing — the egress MITM CA and its proxy/control sockets, the
/// inbound forwarder's socket dir, the in-cage portal's runtime dir, the process-observation
/// sockets — all of which a clean exit unlinks through an RAII guard. A `Drop` does not run on a
/// signal, and a cage normally ends on one (Ctrl-C, `sbx session stop`'s SIGTERM→SIGKILL, a
/// detached launch killed later), so the guard covers the minority case and the rest accumulate.
/// [`sweep_runtime_dirs`] is the backstop: the same doctrine the session registry already applies
/// to its records — treat what is on disk as a hint, validate it by liveness, self-heal.
///
/// An empty prefix matches a bare-pid name (the portal's `<pid>/` directory). `<data>/egress`'s
/// `stats-<pid>-<ticks>` is deliberately **absent**: it outlives its session by design, as the data
/// `sbx net stats` aggregates (`sbx net stats --reset` is its purge).
///
/// `dbus` is a legacy directory — the filtered host-bus proxy it belonged to was replaced by the
/// private in-cage portal, so nothing writes there any more; sweeping it reclaims the residue an
/// older version left behind, after which the directory simply stays empty.
const RUNTIME_DIRS: &[(&str, &[&str])] = &[
    ("egress", &["ca-", "proxy-", "control-"]),
    ("forward", &["fwd-"]),
    ("portal", &[""]),
    ("proc", &["control-", "notif-"]),
    ("dbus", &["proxy-"]),
];

/// The launcher pid a runtime entry is keyed by, given the `prefixes` of its directory — or `None`
/// when the name is not one this sweep recognises, which keeps it.
///
/// A name matches when it carries one of the prefixes and what follows, up to the first `.` (the
/// `.sock`/`.pem` extension), parses as a pid. Everything else — an unprefixed name, a
/// `stats-<pid>-<ticks>` (whose tail is not a bare number), a flush intermediate — yields `None`
/// and is left alone: the sweep only ever removes what it positively identified.
fn runtime_entry_pid(name: &str, prefixes: &[&str]) -> Option<u32> {
    prefixes.iter().find_map(|prefix| {
        let rest = name.strip_prefix(prefix)?;
        let stem = rest.split('.').next()?;
        stem.parse().ok()
    })
}

/// Sweep — or, in a dry run, list — the entries of the per-launch runtime directories
/// ([`RUNTIME_DIRS`]) whose launcher pid is gone. Returns what was (or would be) removed.
///
/// Liveness is by bare pid, the only key these names carry: a pid still taken keeps its entry, so
/// a *reused* pid merely delays a stale entry to a later pass. The error that would matter — a
/// live launch losing its socket — cannot happen, because a live launcher's pid always reads as
/// live. An absent or unreadable directory is skipped, and each removal is best-effort: this is
/// housekeeping, never a reason to fail the caller.
pub(crate) fn sweep_runtime_dirs(data_dir: &Path, prune: bool) -> Vec<PathBuf> {
    sweep_runtime_dirs_with(data_dir, prune, &crate::session::pid_is_live)
}

/// [`sweep_runtime_dirs`] with the liveness predicate injected, so the sweep is testable without
/// spawning processes.
fn sweep_runtime_dirs_with(
    data_dir: &Path,
    prune: bool,
    is_live: &dyn Fn(u32) -> bool,
) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    for (dir_name, prefixes) in RUNTIME_DIRS {
        let dir = data_dir.join(dir_name);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(pid) = runtime_entry_pid(name, prefixes) else {
                continue;
            };
            if is_live(pid) {
                continue;
            }
            let path = entry.path();
            if prune {
                // A directory entry (the portal's runtime dir, the forwarder's socket dir) needs the
                // recursive removal; a socket or the CA file is a plain unlink. Try the file form
                // first — the common case — and fall back rather than stat'ing every entry.
                if std::fs::remove_file(&path).is_err() {
                    let _ = force_remove_dir_all(&path);
                }
            }
            removed.push(path);
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn runtime_entry_pid_reads_only_the_names_it_owns() {
        // the egress trio, each keyed by the launcher pid before its extension
        let egress = &["ca-", "proxy-", "control-"][..];
        assert_eq!(runtime_entry_pid("ca-1234.pem", egress), Some(1234));
        assert_eq!(runtime_entry_pid("proxy-1234.sock", egress), Some(1234));
        assert_eq!(runtime_entry_pid("control-99.sock", egress), Some(99));

        // The stats files share the directory but NOT the sweep: they outlive their session as
        // `sbx net stats`' data. Neither the file nor a flush intermediate may ever be identified.
        assert_eq!(runtime_entry_pid("stats-1234-99887766", egress), None);
        assert_eq!(runtime_entry_pid("stats-1234-99887766.tmp.0", egress), None);

        // The other directories' shapes.
        assert_eq!(runtime_entry_pid("fwd-77", &["fwd-"]), Some(77));
        assert_eq!(
            runtime_entry_pid("notif-77.sock", &["control-", "notif-"]),
            Some(77)
        );
        // A bare-pid directory name (the portal's) matches the empty prefix.
        assert_eq!(runtime_entry_pid("4242", &[""]), Some(4242));

        // Anything not positively identified is left alone — the sweep never guesses.
        assert_eq!(runtime_entry_pid("ca-notapid.pem", egress), None);
        assert_eq!(runtime_entry_pid("README", egress), None);
        assert_eq!(runtime_entry_pid("ca-.pem", egress), None);
        assert_eq!(runtime_entry_pid("notes.txt", &[""]), None);
    }

    #[test]
    fn sweep_runtime_dirs_removes_only_the_entries_of_dead_launches() {
        let data = TmpDir::new();
        let root = data.path();
        let egress = root.join("egress");
        let forward = root.join("forward");
        let portal = root.join("portal");
        std::fs::create_dir_all(&egress).unwrap();
        std::fs::create_dir_all(&forward).unwrap();
        std::fs::create_dir_all(&portal).unwrap();

        // pid 1 is live, pid 2 is gone.
        for name in ["ca-1.pem", "proxy-1.sock", "ca-2.pem", "control-2.sock"] {
            std::fs::write(egress.join(name), b"x").unwrap();
        }
        // The stats of BOTH launches, and an unrecognised file, must survive either way.
        std::fs::write(egress.join("stats-1-111"), b"x").unwrap();
        std::fs::write(egress.join("stats-2-222"), b"x").unwrap();
        std::fs::write(egress.join("keepme"), b"x").unwrap();
        // Directory-shaped entries: the forwarder's socket dir and the portal's runtime dir.
        std::fs::create_dir_all(forward.join("fwd-2").join("nested")).unwrap();
        std::fs::create_dir(portal.join("1")).unwrap();
        std::fs::create_dir(portal.join("2")).unwrap();

        let live = |pid: u32| pid == 1;

        // A dry run identifies the dead entries and changes nothing.
        let listed = sweep_runtime_dirs_with(root, false, &live);
        assert_eq!(
            listed.len(),
            4,
            "ca-2, control-2, fwd-2, portal/2: {listed:?}"
        );
        assert!(
            egress.join("ca-2.pem").exists(),
            "a dry run removes nothing"
        );
        assert!(forward.join("fwd-2").exists());

        // The sweep removes exactly those four — files and directories alike.
        let removed = sweep_runtime_dirs_with(root, true, &live);
        assert_eq!(removed.len(), 4);
        assert!(!egress.join("ca-2.pem").exists());
        assert!(!egress.join("control-2.sock").exists());
        assert!(
            !forward.join("fwd-2").exists(),
            "a directory entry is removed recursively"
        );
        assert!(!portal.join("2").exists());

        // The live launch keeps its plumbing, and the stats of the DEAD launch survive too.
        assert!(
            egress.join("ca-1.pem").exists(),
            "a live launch is never touched"
        );
        assert!(egress.join("proxy-1.sock").exists());
        assert!(portal.join("1").exists());
        assert!(egress.join("stats-1-111").exists());
        assert!(
            egress.join("stats-2-222").exists(),
            "a dead launch's stats outlive it — they are `sbx net stats`' data"
        );
        assert!(
            egress.join("keepme").exists(),
            "an unrecognised name is left alone"
        );

        // Idempotent: a second sweep finds nothing left.
        assert!(sweep_runtime_dirs_with(root, true, &live).is_empty());
    }

    #[test]
    fn sweep_runtime_dirs_tolerates_absent_directories() {
        let data = TmpDir::new();
        // None of the runtime directories exist yet (a fresh data dir) — the sweep is a no-op, not
        // an error, so it can run unconditionally at the head of every launch.
        assert!(sweep_runtime_dirs_with(data.path(), true, &|_| false).is_empty());
    }

    #[test]
    fn prune_flake_roots_drops_only_removed_packages() {
        let store = TmpDir::new();
        let gcroots = store.path().join("nix/var/nix/gcroots");
        std::fs::create_dir_all(&gcroots).unwrap();
        // two flake roots, plus a base/tool root and nix's own auto dir that must be untouched
        for name in ["sbx-flake-hello", "sbx-flake-gone", "abcd-coreutils"] {
            std::os::unix::fs::symlink("/nix/store/x", gcroots.join(name)).unwrap();
        }
        std::fs::create_dir(gcroots.join("auto")).unwrap();

        let current = BTreeSet::from(["hello".to_string()]);

        // a dry run lists the stale root without removing it
        let listed = prune_flake_roots(store.path(), &current, false);
        assert_eq!(listed.len(), 1);
        assert!(gcroots.join("sbx-flake-gone").symlink_metadata().is_ok());

        // a prune removes exactly the removed package's root
        let removed = prune_flake_roots(store.path(), &current, true);
        assert_eq!(removed.len(), 1);
        assert!(gcroots.join("sbx-flake-gone").symlink_metadata().is_err());
        // the current flake root, the base root, and nix's auto dir are all left alone
        assert!(gcroots.join("sbx-flake-hello").symlink_metadata().is_ok());
        assert!(gcroots.join("abcd-coreutils").symlink_metadata().is_ok());
        assert!(gcroots.join("auto").is_dir());
    }

    #[test]
    fn prune_project_package_roots_keeps_declared_and_multi_output_siblings() {
        let data = TmpDir::new();
        let gcroots = data.path().join("gcroots");
        let id = "proj1";
        let proj = gcroots.join("projects").join(id);
        std::fs::create_dir_all(&proj).unwrap();

        // A bare-`nix:` root and its multi-output sibling (`nix build --out-link gzip` links `gzip`
        // AND `gzip-man`); a declared prebuilt root with its `.expr` stamp; and a removed prebuilt
        // root, also with a stamp. Plus a stray non-symlink that must never be touched.
        let link = |name: &str| {
            std::os::unix::fs::symlink(format!("/nix/store/h-{name}"), proj.join(name)).unwrap();
        };
        for name in ["gzip", "gzip-man", "deb-cursor", "tarball-gone"] {
            link(name);
        }
        std::fs::write(proj.join("deb-cursor.expr"), b"stampA").unwrap();
        std::fs::write(proj.join("tarball-gone.expr"), b"stampB").unwrap();
        std::fs::write(proj.join("README"), b"note").unwrap();

        // gzip (and its -man sibling) and deb-cursor stay declared; tarball-gone is removed.
        let current = BTreeSet::from(["gzip".to_string(), "deb-cursor".to_string()]);

        // A dry run lists exactly the removed root, removing nothing (not even its stamp).
        let listed = prune_project_package_roots(&gcroots, id, &current, false);
        assert_eq!(listed.len(), 1);
        assert!(listed[0].ends_with("tarball-gone"));
        assert!(proj.join("tarball-gone").symlink_metadata().is_ok());
        assert!(proj.join("tarball-gone.expr").exists());

        // A prune drops only the removed root, and its `.expr` stamp with it.
        let removed = prune_project_package_roots(&gcroots, id, &current, true);
        assert_eq!(removed.len(), 1);
        assert!(proj.join("tarball-gone").symlink_metadata().is_err());
        assert!(!proj.join("tarball-gone.expr").exists());

        // The declared roots, the multi-output sibling, the kept root's stamp, and the stray plain
        // file all survive.
        assert!(proj.join("gzip").symlink_metadata().is_ok());
        assert!(proj.join("gzip-man").symlink_metadata().is_ok());
        assert!(proj.join("deb-cursor").symlink_metadata().is_ok());
        assert!(proj.join("deb-cursor.expr").exists());
        assert!(proj.join("README").exists());

        // An absent project directory is a clean no-op, never an error.
        assert!(prune_project_package_roots(&gcroots, "nope", &current, true).is_empty());
    }

    #[test]
    fn prune_superseded_roots_drops_only_roots_no_current_out_link_keeps() {
        let store = TmpDir::new();
        let gcroots = store.path().join("nix/var/nix/gcroots");
        std::fs::create_dir_all(&gcroots).unwrap();
        // Seed roots: two current (a keep out-link points at them) and two superseded (nothing does).
        for name in [
            "aaa-glibc-2.42-67",
            "bbb-mise-2026.7.5",
            "ccc-mise-2026.6.0", // an older engine — superseded
            "ddd-chromium-old",  // a rolled-away app build — superseded
        ] {
            std::os::unix::fs::symlink(format!("/nix/store/{name}"), gcroots.join(name)).unwrap();
        }
        // Off-limits: nix's own indirect-root dir and a flake root owned by `prune_flake_roots`.
        std::fs::create_dir(gcroots.join("auto")).unwrap();
        std::os::unix::fs::symlink("/nix/store/x", gcroots.join("sbx-flake-hello")).unwrap();

        let keep = BTreeSet::from([
            OsString::from("aaa-glibc-2.42-67"),
            OsString::from("bbb-mise-2026.7.5"),
        ]);

        // A dry run lists the superseded roots without removing anything.
        let listed = prune_superseded_roots(store.path(), &keep, false);
        assert_eq!(listed.len(), 2);
        assert!(gcroots.join("ccc-mise-2026.6.0").symlink_metadata().is_ok());

        // A prune drops exactly the two superseded roots.
        let removed = prune_superseded_roots(store.path(), &keep, true);
        assert_eq!(removed.len(), 2);
        assert!(gcroots
            .join("ccc-mise-2026.6.0")
            .symlink_metadata()
            .is_err());
        assert!(gcroots.join("ddd-chromium-old").symlink_metadata().is_err());
        // The current builds, the flake root, and nix's auto dir are untouched.
        assert!(gcroots.join("aaa-glibc-2.42-67").symlink_metadata().is_ok());
        assert!(gcroots.join("bbb-mise-2026.7.5").symlink_metadata().is_ok());
        assert!(gcroots.join("sbx-flake-hello").symlink_metadata().is_ok());
        assert!(gcroots.join("auto").is_dir());
    }

    #[test]
    fn project_keep_roots_unions_every_out_link_family_including_mise_on_its_own_rev() {
        let data = TmpDir::new();
        let gcroots = data.path().join("gcroots");
        let (id, base_rev, mise_rev) = ("proj1", "baserev", "miserev");

        // One out-link per family, each pointing at a distinct `/nix/store/<hash>-<name>` build. The
        // out-link *file name* (name-keyed) differs from the target basename — the keep-set keys on
        // the target's basename, which is what a seed root's own file name is.
        let link = |dir: std::path::PathBuf, link_name: &str, target_base: &str| {
            std::fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink(format!("/nix/store/{target_base}"), dir.join(link_name))
                .unwrap();
        };
        link(
            gcroots.join("projects").join(id),
            "deb-app",
            "h1-app-desktop",
        );
        link(
            gcroots.join("base").join(base_rev),
            "glibc",
            "h2-glibc-2.42",
        );
        link(
            gcroots.join("gui").join(base_rev),
            "fonts",
            "h3-dejavu-fonts",
        );
        link(gcroots.join("gpu").join(base_rev), "mesa", "h4-mesa-26.1");
        link(gcroots.join("audio").join(base_rev), "pa", "h5-portaudio");
        // mise is rooted on the *engine* revision, distinct from the base one.
        link(
            gcroots.join("mise").join(mise_rev),
            "mise",
            "h6-mise-2026.7.5",
        );
        // A revision NOT in the keep set (a stale base rev) must not contribute — its build is exactly
        // what a prune should reclaim.
        link(
            gcroots.join("base").join("oldrev"),
            "glibc",
            "old-glibc-2.41",
        );

        let mise_revs = BTreeSet::from([mise_rev.to_string()]);
        let keep = project_keep_roots(&gcroots, id, base_rev, &mise_revs);

        for base in [
            "h1-app-desktop",
            "h2-glibc-2.42",
            "h3-dejavu-fonts",
            "h4-mesa-26.1",
            "h5-portaudio",
            "h6-mise-2026.7.5",
        ] {
            assert!(keep.contains(&OsString::from(base)), "missing {base}");
        }
        // The stale-rev build is excluded, so a later prune can reclaim it.
        assert!(!keep.contains(&OsString::from("old-glibc-2.41")));
        assert_eq!(keep.len(), 6);
    }

    #[test]
    fn parse_size_batch_sums_valid_and_locates_the_reject() {
        // a fully-valid batch: every size summed, every path counted
        assert_eq!(parse_size_batch("10\n20\n30\n"), (60, 3));
        // nix aborted after one valid path (the leftover-lock case): the one size is summed and one
        // path counted, so `total_size` skips the path right after it and resumes
        assert_eq!(parse_size_batch("2208\n"), (2208, 1));
        // an abort on the very first path prints nothing: zero summed, zero consumed → skip index 0
        assert_eq!(parse_size_batch(""), (0, 0));
        // a blank line is ignored entirely; a non-integer line still marks a consumed path but adds
        // no bytes, keeping the skip offset aligned with nix's argv position
        assert_eq!(parse_size_batch("5\n\n7\n"), (12, 2));
        assert_eq!(parse_size_batch("5\ngarbage\n7\n"), (12, 3));
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
    /// form — the anti-traversal guard for `sbx gc --id`.
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

    /// The per-project mise pool a global app self-equips into lives at
    /// `projects/<id>/apps/<name>/mise`, under the project tree `reap_one` (and so `sbx projects rm`)
    /// removes wholesale. Pin that it is reclaimed with the tree — a future move of the pool out from
    /// under `projects/<id>/` would leak it past a project removal, and fail here.
    #[test]
    fn reap_one_reclaims_a_projects_per_project_mise_pool() {
        let base = TmpDir::new();
        let projects = base.path().join("projects");
        std::fs::create_dir_all(&projects).unwrap();

        make_tree(&projects, "aaaaaaaaaaaaaaaa", None);
        // a global app's per-project mise pool nested in the tree
        let pool = projects.join("aaaaaaaaaaaaaaaa/apps/ag/mise/installs/nix-jq/1.0");
        std::fs::create_dir_all(&pool).unwrap();
        std::fs::write(pool.join("f"), b"x").unwrap();

        let live = BTreeSet::new();
        let out = reap_one(&projects, "aaaaaaaaaaaaaaaa", &live, true);
        assert!(matches!(out, ReapOneOutcome::Tree { .. }));
        assert!(!projects.join("aaaaaaaaaaaaaaaa").exists());
        // teeth: the mise pool went with the tree
        assert!(!projects.join("aaaaaaaaaaaaaaaa/apps/ag/mise").exists());
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

        // dry run (neither switch): both reported as candidates, neither removed
        let report = reap_dead_projects(&projects, &live, false, false);
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

        // the markerless opt-in reaps the unheld markerless tree with the dead-prune OFF — the two
        // switches are independent — and the live one is still kept
        let report = reap_dead_projects(&projects, &live, false, true);
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
        // base + the gui/gpu/audio hole userspaces are all keyed by the base channel rev: "live"
        // current, "stale" rolled away. gpu/audio must be pruned exactly like base/gui — a rolled
        // channel strands the mesa/libpulse closures built for the old revision.
        for family in ["base", "gui", "gpu", "audio"] {
            mk(&gcroots.join(family).join("live"));
            mk(&gcroots.join(family).join("stale"));
        }
        // mise keyed by the engine rev
        mk(&gcroots.join("mise/eng"));
        mk(&gcroots.join("mise/oldeng"));
        // per-project roots: p1 still has a runtime tree, p2 was reaped
        mk(&gcroots.join("projects/p1/tool"));
        mk(&gcroots.join("projects/p2/tool"));
        std::fs::create_dir_all(projects.join("p1")).unwrap();

        let live_base = BTreeSet::from(["live".to_string()]);
        let live_mise = BTreeSet::from(["eng".to_string()]);

        // a dry run lists the stale set (base/gui/gpu/audio stale, mise/oldeng, projects/p2) and
        // removes nothing
        let listed = prune_shared_gcroots(&gcroots, &projects, &live_base, &live_mise, false);
        assert_eq!(listed.len(), 6, "stale set: {listed:?}");
        assert!(
            gcroots.join("base/stale").is_dir(),
            "a dry run removed a root"
        );

        // a prune removes exactly those, keeping every live revision and the live project
        let removed = prune_shared_gcroots(&gcroots, &projects, &live_base, &live_mise, true);
        assert_eq!(removed.len(), 6);
        for family in ["base", "gui", "gpu", "audio"] {
            assert!(
                !gcroots.join(family).join("stale").exists()
                    && gcroots.join(family).join("live").is_dir(),
                "{family}: stale rev must be dropped and live kept"
            );
        }
        assert!(!gcroots.join("mise/oldeng").exists() && gcroots.join("mise/eng").is_dir());
        assert!(!gcroots.join("projects/p2").exists() && gcroots.join("projects/p1").is_dir());
    }

    /// Create an app home directory with one small file, so it is a non-empty tree with a size.
    fn mk_home(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("state"), b"x").unwrap();
    }

    #[test]
    fn purge_app_homes_removes_the_global_and_per_project_homes_only() {
        let data = TmpDir::new();
        let d = data.path();
        // the target app: a global home and a per-project home
        mk_home(&d.join("apps/demo-app/home"));
        mk_home(&d.join("apps/demo-app/etc"));
        mk_home(&d.join("projects/p1/apps/demo-app/home"));
        // a different app, and unrelated project state, must all survive
        mk_home(&d.join("apps/demo-tool/home"));
        mk_home(&d.join("projects/p1/apps/other/home"));
        mk_home(&d.join("projects/p1/store/nix"));

        let report = purge_app_homes(d, "demo-app");

        // both of demo-app's homes removed, nothing failed
        assert_eq!(
            report.removed.len(),
            2,
            "removed: {:?}",
            report.removed.iter().map(|h| &h.path).collect::<Vec<_>>()
        );
        assert!(report.failed.is_empty());
        assert!(report.freed() > 0);
        assert!(!d.join("apps/demo-app").exists());
        assert!(!d.join("projects/p1/apps/demo-app").exists());
        // everything else is untouched
        assert!(d.join("apps/demo-tool/home").is_dir());
        assert!(d.join("projects/p1/apps/other/home").is_dir());
        assert!(d.join("projects/p1/store/nix").is_dir());
    }

    /// A global app (`home_scope = "global"`) keeps one app-global home *and*, in each project it has
    /// self-equipped in, a per-project mise pool at `projects/<id>/apps/<name>/mise` — a sibling of an
    /// absent per-project home, holding the `nix:`-via-mise installs kept `/nix`-aligned. The pool
    /// nests under the `apps/<name>/` dir a purge removes wholesale, so it must be reclaimed with the
    /// home. This pins it: moving the pool out from under `apps/<name>/` would leak it past a purge and
    /// fail here.
    #[test]
    fn purge_app_homes_reclaims_a_global_apps_per_project_mise_pool() {
        let data = TmpDir::new();
        let d = data.path();
        // the app-global home (shared across projects)
        mk_home(&d.join("apps/ag/home"));
        // two per-project pools — mise data only, no per-project home (the global-app layout)
        mk_home(&d.join("projects/p1/apps/ag/mise/installs/nix-jq/1.0"));
        mk_home(&d.join("projects/p2/apps/ag/mise/installs/nix-jq/1.0"));
        // unrelated state that must survive
        mk_home(&d.join("projects/p1/store/nix"));
        mk_home(&d.join("projects/p1/apps/other/home"));

        let report = purge_app_homes(d, "ag");

        // the app-global home plus both per-project pools were reclaimed
        assert_eq!(
            report.removed.len(),
            3,
            "removed: {:?}",
            report.removed.iter().map(|h| &h.path).collect::<Vec<_>>()
        );
        assert!(report.failed.is_empty());
        assert!(!d.join("apps/ag").exists());
        // teeth: each per-project pool went with its `apps/<name>/` dir
        assert!(!d.join("projects/p1/apps/ag/mise").exists());
        assert!(!d.join("projects/p2/apps/ag/mise").exists());
        // the shared store and a sibling app are untouched
        assert!(d.join("projects/p1/store/nix").is_dir());
        assert!(d.join("projects/p1/apps/other/home").is_dir());
    }

    #[test]
    fn purge_app_homes_reports_nothing_for_an_unknown_app() {
        let data = TmpDir::new();
        mk_home(&data.path().join("apps/demo-app/home"));
        let report = purge_app_homes(data.path(), "ghost");
        assert!(report.found_nothing());
        assert!(data.path().join("apps/demo-app").is_dir()); // the real app is untouched
    }

    #[test]
    fn purge_app_homes_refuses_a_traversing_name_at_the_sink() {
        let data = TmpDir::new();
        // a sibling of apps/ that a traversal would try to reach
        mk_home(&data.path().join("victim"));
        // names that are not a single ordinary component must be refused before any join
        for name in ["../victim", "a/b", "/etc", ".", ".."] {
            let report = purge_app_homes(data.path(), name);
            assert!(report.found_nothing(), "removed something for {name:?}");
        }
        assert!(data.path().join("victim").is_dir());
    }

    #[test]
    fn installed_app_homes_groups_global_and_per_project() {
        let data = TmpDir::new();
        let d = data.path();
        // demo-app: a global home + two per-project homes
        mk_home(&d.join("apps/demo-app/home"));
        mk_home(&d.join("projects/p1/apps/demo-app/home"));
        mk_home(&d.join("projects/p2/apps/demo-app/home"));
        // demo-tool: a global home only
        mk_home(&d.join("apps/demo-tool/home"));
        // scratch: a single per-project home, no global one
        mk_home(&d.join("projects/p1/apps/scratch/home"));

        let apps = installed_app_homes(d);
        let names: Vec<&str> = apps.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["demo-app", "demo-tool", "scratch"]); // sorted

        let demo_app = &apps[0];
        assert!(demo_app.global_bytes.is_some());
        assert_eq!(demo_app.project_homes, 2);
        assert_eq!(demo_app.project_pools, 0);
        assert!(demo_app.total_bytes() > 0);

        let demo_tool = &apps[1];
        assert!(demo_tool.global_bytes.is_some());
        assert_eq!(demo_tool.project_homes, 0);

        let scratch = &apps[2];
        assert!(scratch.global_bytes.is_none());
        assert_eq!(scratch.project_homes, 1);
    }

    /// A `home_scope = "global"` app's per-project tree holds only its mise pool, no `home/` — the
    /// launch-time layout. A pool the agent self-equipped into is state on disk (sized, and purged
    /// with the app) but not a second isolated home, so it must be counted as a pool: counting it as
    /// a home told the user an app had a per-project home it never had.
    #[test]
    fn installed_app_homes_counts_a_bare_mise_pool_as_a_pool_not_a_home() {
        let data = TmpDir::new();
        let d = data.path();
        // the global-app layout: one global home, and a per-project tree carrying only `mise/`
        mk_home(&d.join("apps/demo-app/home"));
        mk_home(&d.join("projects/p1/apps/demo-app/mise/installs/demo-tool"));
        // a per-project tree that carries both is still a home (the home is what names it)
        mk_home(&d.join("projects/p2/apps/demo-app/home"));
        mk_home(&d.join("projects/p2/apps/demo-app/mise"));

        let apps = installed_app_homes(d);
        assert_eq!(apps.len(), 1);
        let demo_app = &apps[0];
        assert_eq!(demo_app.project_homes, 1);
        assert_eq!(demo_app.project_pools, 1);
        // both per-project trees are sized: a purge reclaims the pool too
        assert!(demo_app.project_bytes > 0);
    }

    /// Every launch creates the per-project pool dir (the writable bind needs an existing source),
    /// so an app that has merely *run* in a project carries an empty pool there. Counting it would
    /// report per-project state the app does not have — it holds no installed tool, only the plugin
    /// symlink and migration markers a launch writes.
    #[test]
    fn installed_app_homes_ignores_an_empty_mise_pool() {
        let data = TmpDir::new();
        let d = data.path();
        mk_home(&d.join("apps/demo-app/home"));
        // the launch-created layout: a pool with the plugin registration but no installed tool
        mk_home(&d.join("projects/p1/apps/demo-app/mise/plugins"));
        // and one where mise created `installs/` without ever populating it
        mk_home(&d.join("projects/p2/apps/demo-app/mise"));
        std::fs::create_dir_all(d.join("projects/p2/apps/demo-app/mise/installs")).unwrap();

        let apps = installed_app_homes(d);
        assert_eq!(apps.len(), 1);
        let demo_app = &apps[0];
        assert_eq!(demo_app.project_homes, 0);
        assert_eq!(demo_app.project_pools, 0);
        // still sized: `sbx app rm --purge` removes those dirs, so the total must not lie
        assert!(demo_app.project_bytes > 0);
    }

    #[test]
    fn installed_app_homes_is_empty_without_a_data_tree() {
        let data = TmpDir::new();
        assert!(installed_app_homes(data.path()).is_empty());
    }
}
