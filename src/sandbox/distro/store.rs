//! Where a provisioned root filesystem lives, and the lock that pins which one.
//!
//! Three questions, answered in this order because each depends on the last:
//!
//! * **which image** — the locator from the config, and the digest a tag currently resolves to;
//! * **is it already here** — the tree is keyed by that digest, so the answer is a `stat`;
//! * **if not, unpack it** — fetch each layer and apply it, into a directory that only becomes the
//!   tree once every layer has landed.
//!
//! ## The digest is the pin, and the lock is what remembers it
//!
//! A tag moves. Resolving one costs a request to the registry, and a launch that did it every time
//! would both need the network and silently follow the tag wherever it went. So the resolution is
//! recorded in a lock beside the project's other state, and a launch that finds one does no
//! resolution at all: the digest names the tree, the tree is already unpacked, and nothing is
//! fetched. Moving to a new image is then an act ([`crate::cli::upgrade`]), never a side effect of
//! launching.
//!
//! A locator that already names a digest needs no resolution and locks to itself, so the lock's
//! shape is the same either way and the roll that refreshes it has one path rather than two.
//!
//! ## What the unpacked tree is, and is not
//!
//! It is the image's layers applied in order, plus the empty directories and files sbx's own mounts
//! need as mountpoints (see [`crate::sandbox::binds`] for why a read-only root cannot be given a
//! mountpoint at launch). It is never a place a cage writes: the launch binds it read-only, which
//! is what lets one copy serve every project on that digest.

use super::reference::{self, ImageRef, Reference};
use super::{layers, registry};
use crate::store::Layout;
use std::io;
use std::path::{Path, PathBuf};

/// The file recording a distribution locator and the digest it resolved to. Named beside the
/// channel lock (`nixpkgs.lock`) and in the same two-line format, so the two read alike and a
/// project's pinned state is one directory rather than two mechanisms.
pub(crate) const DISTRO_LOCK: &str = "distro.lock";

/// The directory holding one image's unpacked tree, keyed by its digest.
///
/// `sha256:<hex>` becomes `sha256-<hex>`: a colon is a legal path byte on Linux, but this directory
/// is named in messages, in `PATH`-like lists and on command lines, and a component that needs
/// quoting in half of them is a component that will eventually be split in one of them.
fn image_dir(layout: &Layout, digest: &str) -> PathBuf {
    layout.distro_dir().join(digest.replacen(':', "-", 1))
}

/// The directory of holder markers beside a tree: one empty file per project that has launched on
/// it. See [`provision`] for why they exist and [`crate::sandbox::gc::sweep_distro_trees`] for what reads them.
pub(crate) const ROOTS_DIR: &str = "roots";

/// Provision the root filesystem `locator` names, and return the directory to bind at `/`.
///
/// `lock_path` is where this launch's pin is recorded — the project's own lock under a project
/// declaration, the shared one otherwise. It is written on every call, not only when it changes, so
/// that a tree provisioned before the lock existed still ends up pinned.
///
/// `holder` is the runtime id of the project this launch is for, recorded as an empty file under
/// [`ROOTS_DIR`]. It is a garbage-collection root, in the sense nix uses the word: a lock says which
/// tree the *next* launch wants, and that is not the same question as which tree a *running* cage is
/// executing from. The two diverge for as long as a session outlives a roll, and removing a tree
/// under a live cage is not a degraded launch but a broken one, measured: the cage keeps its mount
/// and loses every file through it, so its own shell disappears mid-command.
///
/// Written on every launch and removed by nothing, which is what makes it self-healing: a marker is
/// read against the set of live sessions, so one left by a cage that crashed holds nothing, and
/// [`crate::sandbox::gc::sweep_distro_trees`] removes it when it sweeps.
pub(crate) fn provision(
    layout: &Layout,
    locator: &str,
    lock_path: &Path,
    holder: &str,
) -> io::Result<PathBuf> {
    let image = reference::parse(locator).ok_or_else(|| {
        io::Error::other(format!(
            "`{locator}` is not a usable image locator (expected `oci:<registry>/<repository>:<tag>` or `…@sha256:<digest>`)"
        ))
    })?;

    let digest = match &image.reference {
        // A digest names the image itself, so there is nothing to resolve and nothing a registry
        // could answer differently.
        Reference::Digest(digest) => digest.clone(),
        Reference::Tag(_) => match locked_digest(lock_path, locator) {
            Some(digest) => digest,
            None => registry::resolve(&image)?.digest,
        },
    };

    let dir = image_dir(layout, &digest);
    let rootfs = dir.join("rootfs");
    if !rootfs.is_dir() {
        unpack_into(&image.pinned(&digest), &digest, &dir)?;
    }
    // Checked on every launch rather than once at unpack: the list of paths a distribution has to
    // supply is sbx's, so a tree unpacked by an earlier version is held to the current one.
    check_supplied(&rootfs, locator)?;
    let roots = dir.join(ROOTS_DIR);
    std::fs::create_dir_all(&roots)?;
    std::fs::File::create(roots.join(holder))?;
    crate::store::write_lock(lock_path, locator, &digest)?;
    Ok(rootfs)
}

/// What a roll of the distribution lock did: the image it names, the digest it now records, and
/// what it recorded before.
///
/// `previous` is read across sources, not scoped to this locator, because the question it answers is
/// "was there a tree here that this roll supersedes?" — and a lock recording another image answers
/// yes. Changing the declared image repoints the cage root exactly as rolling a tag forward does,
/// which is the same distinction [`crate::store::LockTarget::previously_locked`] draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rolled {
    pub(crate) locator: String,
    pub(crate) digest: String,
    pub(crate) previous: Option<String>,
}

/// Re-resolve `locator` and rewrite its lock, whatever the lock already said.
///
/// The one difference from [`provision`] is that the lock is not consulted: a roll exists precisely
/// to ask the registry again, so a tag that has moved is followed and one that has not reports no
/// change. A locator that names a digest resolves to itself, which is not a special case here but
/// the same answer the grammar already gives — a digest is the image.
///
/// Nothing is fetched or unpacked. The new digest names a tree the next launch provisions, on the
/// rule every channel here follows: a roll rewrites a lock, and the build happens when something is
/// actually run.
pub(crate) fn refresh(locator: &str, lock_path: &Path) -> io::Result<Rolled> {
    let image = reference::parse(locator)
        .ok_or_else(|| io::Error::other(format!("`{locator}` is not a usable image locator")))?;
    let previous = crate::store::read_lock_lines(lock_path)
        .and_then(|(_, digest)| digest)
        .and_then(|d| reference::valid_digest(&d).map(str::to_string));
    let digest = match &image.reference {
        Reference::Digest(digest) => digest.clone(),
        Reference::Tag(_) => registry::resolve(&image)?.digest,
    };
    crate::store::write_lock(lock_path, locator, &digest)?;
    Ok(Rolled {
        locator: locator.to_string(),
        digest,
        previous,
    })
}

/// The digest this lock records for `locator`, or `None` when it records another image or none.
///
/// Scoped to the locator so a lock left by a different image never resurfaces as this one's pin —
/// the same rule [`crate::store::LockTarget::locked_revision`] applies to a channel. Held to the
/// digest grammar here rather than trusted, because a lock is a file on disk and this value goes on
/// to name a directory.
fn locked_digest(lock_path: &Path, locator: &str) -> Option<String> {
    let (source, digest) = crate::store::read_lock_lines(lock_path)?;
    (source == locator)
        .then_some(digest)
        .flatten()
        .and_then(|d| reference::valid_digest(&d).map(str::to_string))
}

/// Fetch every layer of `image` and apply it, then move the result into place.
///
/// The tree is assembled under a sibling name and renamed at the end, so the directory a launch
/// binds at `/` exists only once every layer has landed: an interrupted unpack leaves a partial
/// directory that no launch will ever name, rather than a root filesystem missing half its files.
/// The name carries this process's pid so two launches provisioning the same image at once each
/// assemble their own, and the loser of the rename finds the winner's tree already there.
fn unpack_into(image: &ImageRef, digest: &str, dir: &Path) -> io::Result<()> {
    let parent = dir
        .parent()
        .ok_or_else(|| io::Error::other(format!("`{}` has no parent directory", dir.display())))?;
    std::fs::create_dir_all(parent)?;
    let partial = parent.join(format!(
        "{}.partial.{}",
        dir.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&partial);

    let outcome = (|| -> io::Result<()> {
        let blobs = partial.join("blobs");
        std::fs::create_dir_all(&blobs)?;
        let manifest = registry::resolve(image)?;
        let rootfs = partial.join("rootfs");
        for layer in &manifest.layers {
            let blob = registry::fetch_layer(image, layer, &blobs)?;
            layers::apply(&blob, &layer.media_type, &rootfs)?;
            // Freed as soon as it is applied: the layers of one image can outweigh the tree they
            // produce, and keeping them all would double the cost of every provision for a set of
            // files nothing reads again.
            let _ = std::fs::remove_file(&blob);
        }
        std::fs::remove_dir_all(&blobs)?;
        crate::sandbox::binds::create_distro_mountpoints(&rootfs)
    })();

    if outcome.is_err() {
        let _ = std::fs::remove_dir_all(&partial);
        return outcome;
    }
    match std::fs::rename(&partial, dir) {
        Ok(()) => Ok(()),
        // Another launch provisioned the same digest first. Its tree is this one's tree — the
        // digest says so — so the loser drops what it built rather than overwriting a directory a
        // running cage may already be reading.
        Err(_) if dir.join("rootfs").is_dir() => {
            let _ = std::fs::remove_dir_all(&partial);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&partial);
            Err(io::Error::other(format!(
                "cannot place the unpacked root filesystem for {digest}: {e}"
            )))
        }
    }
}

/// Refuse a tree that does not carry what a distribution has to supply.
///
/// The paths in [`crate::sandbox::binds::DISTRO_SUPPLIED`] are the ones sbx stops emitting once an
/// image is in force, and every one of them is a symlink or the ELF interpreter — neither of which
/// can be created at launch, because bubblewrap makes them at a destination whose parent is the
/// image's own read-only tree (`Can't make symlink at …: Read-only file system`). So an image
/// missing one leaves a cage without it, and the failure would surface much later as an exec error
/// naming a path nobody declared. Refusing here names the image and every path it lacks.
fn check_supplied(rootfs: &Path, locator: &str) -> io::Result<()> {
    let missing: Vec<&str> = crate::sandbox::binds::DISTRO_SUPPLIED
        .iter()
        .copied()
        .filter(|p| {
            let path = rootfs.join(p.trim_start_matches('/'));
            path.symlink_metadata().is_err()
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "the image `{locator}` does not carry {}, which a distribution userland has to supply \
         (sbx cannot add them: they sit under the image's own read-only tree)",
        missing.join(", ")
    )))
}

#[cfg(test)]
mod tests;
