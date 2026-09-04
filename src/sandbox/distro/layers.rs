//! Applying an image's layers into a root filesystem, in order.
//!
//! A layer is a tar of the changes it makes, so applying an image is unpacking each one over the
//! last. Two things make that more than a loop around an extractor.
//!
//! ## Whiteouts
//!
//! A layer cannot carry an absence, so a deletion is spelled as a file: `.wh.<name>` beside where
//! `<name>` would be means the entry is gone from here down, and `.wh..wh..opq` in a directory
//! means everything the lower layers put in that directory is gone. Neither marker is itself
//! written out. An applier that ignored them would produce a tree carrying files the image
//! deleted, which is the kind of failure that is silent until something reads one.
//!
//! ## Where a member is allowed to land
//!
//! Every destination is decided here, never by the archive. Three ways an archive tries to leave
//! its directory, and all three are refused rather than sanitised, because a member that wanted out
//! is not a member whose corrected path is worth writing:
//!
//! * an **absolute** path, which would land at the host's root;
//! * a `..` **component**, which climbs;
//! * a **symlink in the path**, which is the one that survives a naive check: layer one ships
//!   `etc -> /`, layer two ships `etc/passwd`, and an extractor that resolves the second path
//!   through the first writes to the host's `/etc/passwd`. So no component of a member's parent
//!   may be a symlink, checked against what is already on disk rather than against the archive.
//!
//! Unprivileged, so ownership is not restored and a device node or fifo is skipped rather than
//! failing the unpack: the cage runs as one uid and mounts the tree read-only, so an image's uid
//! table and its `/dev` entries describe a world it does not get.
//!
//! ## Two deliberate departures from the archive's modes
//!
//! The owner's read and write bits are **added** to every member, search as well on a directory,
//! and `setuid`/`setgid` are **removed**.
//!
//! Adding write is what lets a later layer replace a member of a read-only directory, and it is
//! what lets the tree be deleted again: a store that cannot be reclaimed without a recursive
//! `chmod` first is a store that leaks. It costs nothing where it shows, since the cage mounts the
//! tree read-only and every process in it runs as the one uid that already owns these files.
//!
//! Read comes along with it, which is worth saying out loud because it is visible: a member the
//! image published as `0o000` is readable in the cage. Nothing is reachable through that which the
//! same uid could not already read by unpacking the layer itself, and the alternative is a tree
//! whose own assembler cannot re-read what it wrote.
//!
//! Removing `setuid` is defence in depth rather than a fix: the cage is same-uid behind
//! `no_new_privs`, so a set-user-ID bit on a file this user already owns grants nothing. It is
//! dropped anyway, because a bit that grants nothing today is not a bit worth carrying into
//! whatever the cage looks like later.

use super::gzip::GzipReader;
use std::fs;
use std::io::{self, BufReader};
use std::path::{Component, Path, PathBuf};

/// The prefix a deletion marker carries, and the exact name of the opaque-directory marker.
const WHITEOUT: &str = ".wh.";
const OPAQUE: &str = ".wh..wh..opq";

/// Apply `blob` over `root`, creating `root` if it is not there yet.
///
/// `media_type` decides the framing: the gzip layer types are inflated, an uncompressed one is read
/// as a tar, and anything else is refused by name rather than guessed at. `zstd` layers are the
/// refusal that will be met in practice, and naming it is the point: an image pushed that way is
/// not unpacked wrongly, it is not unpacked at all.
pub(super) fn apply(blob: &Path, media_type: &str, root: &Path) -> io::Result<()> {
    fs::create_dir_all(root)?;
    let file = BufReader::new(fs::File::open(blob)?);
    if media_type.ends_with("+zstd") {
        return Err(io::Error::other(format!(
            "layer media type `{media_type}` is not supported (only tar and tar+gzip layers are)"
        )));
    }
    if media_type.ends_with("+gzip") || media_type.ends_with(".tar.gzip") || media_type.is_empty() {
        // An empty media type is the ambiguous case a hand-written manifest can produce; gzip is
        // the overwhelmingly common framing, and a tar that is not one fails at its header rather
        // than being written as garbage.
        let mut archive = tar::Archive::new(GzipReader::new(file)?);
        return unpack(&mut archive, root);
    }
    let mut archive = tar::Archive::new(file);
    unpack(&mut archive, root)
}

/// Walk one layer's members, applying each.
fn unpack<R: io::Read>(archive: &mut tar::Archive<R>, root: &Path) -> io::Result<()> {
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            // A member whose final component is not UTF-8 cannot be compared against the whiteout
            // markers, and a name that cannot be read is a name that cannot be checked.
            return Err(io::Error::other(format!(
                "layer member has an unreadable name: {}",
                path.display()
            )));
        };

        if name == OPAQUE {
            let dir = safe_path(root, path.parent().unwrap_or(Path::new("")))?;
            clear_directory(&dir)?;
            continue;
        }
        if let Some(target) = name.strip_prefix(WHITEOUT) {
            let parent = path.parent().unwrap_or(Path::new(""));
            let dest = safe_path(root, &parent.join(target))?;
            remove(&dest)?;
            continue;
        }

        let dest = safe_path(root, &path)?;
        write_member(&mut entry, &dest, root)?;
    }
    Ok(())
}

/// Resolve `rel` under `root`, refusing every shape that would leave it.
///
/// The symlink check looks at what is **on disk**, because that is what an `open` would follow: a
/// link planted by an earlier layer is exactly the case a check against the archive's own paths
/// misses.
fn safe_path(root: &Path, rel: &Path) -> io::Result<PathBuf> {
    let mut out = root.to_path_buf();
    // Which component is the last one, counted rather than compared against a rebuilt path: a
    // member spelled `./bin` has the same destination as `bin`, and a comparison would find the two
    // unequal and refuse the first for a symlink the second is allowed to replace.
    let last = rel
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    let mut seen = 0;
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                seen += 1;
                out.push(part);
                // The parent chain is checked as it is built, so a link is caught before anything
                // is created beyond it. The final component is exempt because a layer replacing a
                // link writes *at* it and not *through* it, which is why every branch of
                // `write_member` unlinks what is there before creating anything.
                if seen < last
                    && out
                        .symlink_metadata()
                        .is_ok_and(|m| m.file_type().is_symlink())
                {
                    return Err(io::Error::other(format!(
                        "layer member `{}` would be written through the symlink `{}`",
                        rel.display(),
                        out.display()
                    )));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::other(format!(
                    "refusing layer member `{}`: it leaves the image root",
                    rel.display()
                )));
            }
        }
    }
    if out == *root {
        return Err(io::Error::other("a layer member names the root itself"));
    }
    Ok(out)
}

/// Remove whatever is at `path`, if anything. A whiteout for something no lower layer created is
/// not an error: layers are written against an assumed base, not against this one.
fn remove(path: &Path) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(_) => Ok(()),
    }
}

/// Empty a directory without removing it: what an opaque marker means.
fn clear_directory(dir: &Path) -> io::Result<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries {
        remove(&entry?.path())?;
    }
    Ok(())
}

/// Write one member at `dest`.
fn write_member<R: io::Read>(
    entry: &mut tar::Entry<'_, R>,
    dest: &Path,
    root: &Path,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let kind = entry.header().entry_type();
    // `setuid`/`setgid`/sticky are masked off here rather than at each call below, so no path
    // through this function can carry one through by omission.
    let mode = entry.header().mode().unwrap_or(0o644) & 0o777;

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }

    if kind.is_dir() {
        // `symlink_metadata`, never `is_dir`, which follows: the exemption for a final component
        // that is a link means `dest` may be one an earlier layer planted, and a link to a
        // directory answers `is_dir` with a yes about somewhere else entirely. Taking that yes
        // would skip the removal below and leave `set_permissions` to chmod that somewhere else.
        let present = dest.symlink_metadata().ok();
        if !present.is_some_and(|m| m.is_dir()) {
            // A later layer may replace a file, or a link, with a directory of the same name.
            remove(dest)?;
            fs::create_dir_all(dest)?;
        }
        // Owner write and search, so a later layer can add to this directory and `sbx gc` can
        // remove it.
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(mode | 0o700));
        return Ok(());
    }

    if kind.is_symlink() {
        let target = entry
            .link_name()?
            .ok_or_else(|| io::Error::other("a symlink member names no target"))?;
        remove(dest)?;
        // The *target* is not checked: a symlink is data until something follows it, and inside a
        // read-only cage root a link pointing out of the tree resolves against the cage's own root,
        // not the host's. What must not happen is writing *through* one, which `safe_path` refuses.
        std::os::unix::fs::symlink(target, dest)?;
        return Ok(());
    }

    if kind.is_hard_link() {
        let link = entry
            .link_name()?
            .ok_or_else(|| io::Error::other("a hard link member names no target"))?;
        let target = safe_path(root, &link)?;
        remove(dest)?;
        // A hard link to something no layer created cannot be made; copying is not equivalent and
        // guessing is worse, so the image is refused rather than silently changed.
        fs::hard_link(&target, dest).map_err(|e| {
            io::Error::other(format!(
                "hard link {} -> {}: {e}",
                dest.display(),
                target.display()
            ))
        })?;
        return Ok(());
    }

    if kind.is_file() {
        remove(dest)?;
        let mut file = fs::File::create(dest)?;
        io::copy(entry, &mut file)?;
        // The owner keeps read and write access whatever the archive says: the tree is assembled
        // by this user, a later layer has to be able to replace a member of it, and reclaiming the
        // store must not need a recursive `chmod` first.
        let _ = fs::set_permissions(dest, fs::Permissions::from_mode(mode | 0o600));
        return Ok(());
    }

    // A device node, fifo or socket: unprivileged creation would fail, and the cage mounts its own
    // `/dev` over whatever the image carries. Skipping is not a loss of anything the cage would use.
    Ok(())
}

#[cfg(test)]
mod tests;
