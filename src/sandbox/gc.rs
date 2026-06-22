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
}
