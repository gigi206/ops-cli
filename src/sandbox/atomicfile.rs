//! Installing a file so no reader ever sees half of it.
//!
//! Write a temp sibling, then rename it over the target. The rename is the atomic step: a concurrent
//! cage that binds the file read-only sees either the complete old content or the complete new one,
//! and because the rename installs a fresh inode, a cage already bound to the prior inode keeps its
//! own view rather than observing a later launch's overwrite.
//!
//! A leaf on purpose. Every file sbx stages this way answers the same three questions — where the
//! temp goes, what happens to it on failure, and whether an unchanged file is rewritten — and the
//! answers were once given eight times over, at which point they had already diverged. The callers
//! are the cage's synthetic identity and egress contract ([`super::binds`]), the per-project pin
//! locks ([`super::flake`], [`super::nixhub`], [`super::prebuilt`]), the staged audio shim
//! ([`super::audio`]) and the desktop mark ([`super::notify_sink`]).

use std::io;
use std::path::Path;

/// Write `bytes` to `path` atomically: a unique temp sibling (named by pid, so concurrent launches
/// do not collide on it) written then renamed over `path`.
///
/// The temp is a **hidden** sibling, and that is not cosmetic: the router directory bound at
/// `/opt/sbx/open` leads the cage's `PATH`, so a temp named after the file it replaces would put a
/// second resolvable name in front of the project's tools for as long as the write lasts. (Named
/// rather than linked: [`super::binds`] holds that path in a private constant, so a link from here
/// would resolve to nothing.)
///
/// The owner-only parent is created if it is missing, and **on either failure — the write (ENOSPC)
/// or the rename — the temp is removed**, so a failed write leaves nothing behind.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic_mode(path, bytes, None)
}

/// [`write_atomic`], with `mode` applied to the temp file **before** the rename.
///
/// The mode belongs on the temp name, not on the published one. A caller that writes atomically and
/// *then* calls `set_permissions` has already put the file at its final path with whatever mode the
/// write gave it, and only afterwards makes it what it has to be — so between the two there is a
/// file that is there and is not right. For the cage's `xdg-open` router that meant a router
/// visible at the head of the cage's `PATH` without its executable bit: a launch of the same home
/// racing that window resolves it and cannot run it. Setting the mode before the rename closes the
/// window by construction, because the rename is the only thing that appears at the final path and
/// it appears finished.
pub(crate) fn write_atomic_mode(path: &Path, bytes: &[u8], mode: Option<u32>) -> io::Result<()> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    let staged = || -> io::Result<()> {
        std::fs::write(&tmp, bytes)?;
        if let Some(mode) = mode {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    };
    staged().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// A number no other staging in this process will use, for the temp name a content-keyed
/// materialization renames from.
///
/// The pid alone is not enough: one launch stages several trees (an inline flake, a fontconfig
/// file, the mise plugin), and two of them entering their staging at once would otherwise pick the
/// same temp path and have one `rename` pull the ground from under the other. Across processes the
/// pid separates them; within one, this does.
///
/// One definition rather than three byte-identical copies, which is what
/// [`super::flake_inline`], [`super::fonts`] and [`super::miseplugin`] each carried.
pub(crate) fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// [`write_atomic`], skipped when the file already holds exactly `bytes` — which is the ordinary
/// case for content that changes only across sbx releases (the staged audio shim, the desktop
/// mark). Answers whether the file was written.
pub(crate) fn write_atomic_if_changed(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    if std::fs::read(path).is_ok_and(|on_disk| on_disk == bytes) {
        return Ok(false);
    }
    write_atomic(path, bytes)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    /// The published file carries its mode, and a caller that needs one no longer has to set it
    /// after the rename.
    #[test]
    fn write_atomic_mode_publishes_the_file_with_the_mode_it_was_given() {
        let dir = TmpDir::new();
        let exe = dir.join("router");
        write_atomic_mode(&exe, b"#!/bin/sh\n", Some(0o755)).unwrap();
        assert_eq!(
            std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
            0o755
        );

        // And the plain form still writes without opinion about the mode.
        let plain = dir.join("plain");
        write_atomic(&plain, b"x").unwrap();
        assert_eq!(std::fs::read(&plain).unwrap(), b"x");
    }

    /// No caller in `binds` publishes a file and *then* makes it what it has to be.
    ///
    /// The cage's `xdg-open` router was written atomically and chmod-ed afterwards, so between the
    /// two there was a router at the head of the cage's `PATH` without its executable bit — a
    /// launch of the same home racing that window resolves it and cannot run it. The window closes
    /// by construction when the mode rides the temp file, and this counts the shape that reopened
    /// it rather than trusting the one call site to stay converted.
    #[test]
    fn binds_publishes_no_file_it_has_to_chmod_afterwards() {
        let source = include_str!("binds.rs");
        assert_eq!(
            source.matches("set_permissions").count(),
            0,
            "a mode belongs on the temp file `write_atomic_mode` renames, not on the published one"
        );
    }
}
