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
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
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
