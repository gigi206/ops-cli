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
//! ([`super::audio`]), the desktop mark ([`super::notify_sink`]), the snapshot an overwrite keeps
//! ([`crate::cli::keep_replaced_file`]), the profile an import writes ([`crate::cli::app`]) and the
//! pointer to a storage volume ([`crate::storage::write_pointer`]). The last three arrived by
//! deletion rather than by design: each had its own copy of this staging, and each named its temp
//! from the pid alone.

use std::io;
use std::path::Path;

/// Write `bytes` to `path` atomically: a temp sibling written, then renamed over `path`.
///
/// The temp's name carries the target's own name, the pid **and** [`unique()`]. The first two
/// separate stagings of different files and of different processes; the third separates two
/// stagings of the *same* file inside one process, and that is not the cosmetic case. Two writers
/// sharing a temp do not merely lose one update: the second truncates the inode the first is still
/// writing into, so the rename publishes one writer's head followed by the other's tail — a file
/// that is present, is the right name, and is not the TOML it promises to be. With the temps
/// separate, the loser of the race is a whole body that a later rename replaces.
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
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp.{}.{}", std::process::id(), unique()));
    let staged = || -> io::Result<()> {
        // Written and flushed to the device before the rename, rather than through `fs::write`.
        // The rename orders itself against the data only if the data is already durable: without
        // this, a machine that loses power just after the rename can come back with the new name
        // pointing at an inode whose blocks were never written — a file that is present, is the
        // right size, and holds zeros. `write_atomic` publishes the pointer to a storage volume and
        // the pin locks a launch resolves against, so an empty-but-present one is the shape that
        // costs most.
        //
        // The mode rides the `open` as well as following it. `create` alone would leave the temp at
        // the umask's mode for the whole write, and a caller asking for `0600` is asking that the
        // bytes never exist more readable than that -- a profile carrying `[secret]` locators is
        // staged in a directory that is not always owner-only. The `set_permissions` after it is
        // not redundant: `open` masks its mode with the umask, so a `0755` router under a strict
        // umask still has to be made what it must be, and doing it before the rename keeps the
        // published path finished from its first instant.
        //
        // The open is `create_new` and `O_NOFOLLOW`. The temp name is this process's to make, so
        // whatever else may be sitting there is not this write's business to open: a symlink left at
        // the name would otherwise be followed, and the bytes would land wherever it points, with
        // `mode` set on that file instead. Planting one takes a process of the same uid, which is
        // inside sbx's trust domain and outside this function's assumptions — and the two flags cost
        // nothing to hold, because a temp name is disposable: the write reports the collision, and
        // the next attempt takes the next sequence number.
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW);
        let file = match mode {
            Some(mode) => opts.mode(mode).open(&tmp)?,
            None => opts.open(&tmp)?,
        };
        {
            use io::Write as _;
            let mut file = &file;
            file.write_all(bytes)?;
            file.flush()?;
        }
        if let Some(mode) = mode {
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        file.sync_all()
    };
    staged().inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    sync_dir(dir);
    Ok(())
}

/// Flush a directory's own entries to the device, after a `rename` published one of them.
///
/// The directory entry is a second piece of metadata beside the file's contents: the rename is
/// atomic against a concurrent reader either way, but only this makes it survive a crash.
///
/// Best-effort, and deliberately so at every call site: a filesystem that will not open its own
/// directory has already published the file, and failing the write here would report a failure that
/// did not happen.
///
/// Shared rather than written twice — [`crate::config::manage::write_text`] publishes config the
/// same way, through a temp of its own whose creation it cannot delegate, and the durability half
/// of the two is the same half.
pub(crate) fn sync_dir(dir: &Path) {
    if let Ok(dir) = std::fs::File::open(dir) {
        let _ = dir.sync_all();
    }
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

    /// A symlink sitting at the temp's name is not followed, and the write says so instead.
    ///
    /// The staging opened its temp with `create`, which follows a link and truncates whatever is on
    /// the other end — so a file outside the directory would be written with the bytes, and given
    /// `mode` on top. Planting the link takes a process of the same uid, which sbx already treats as
    /// inside its trust domain; the point is that this function no longer *assumes* it, at the cost
    /// of two open flags.
    ///
    /// The names are planted over a span because the sequence number is the process's, shared with
    /// whatever else stages a file while this runs. A span that the run walks past would fail the
    /// test loudly rather than pass it on a name nobody used, which is the reason for the second
    /// assertion.
    #[test]
    fn a_symlink_left_at_the_temps_name_is_refused_rather_than_written_through() {
        let dir = TmpDir::new();
        let target = dir.join("elsewhere");
        std::fs::write(&target, b"untouched").unwrap();

        let staged = dir.join("pointer.toml");
        let next = unique() + 1;
        let planted: Vec<std::path::PathBuf> = (next..next + 64)
            .map(|n| {
                let tmp = dir
                    .path()
                    .join(format!(".pointer.toml.tmp.{}.{n}", std::process::id()));
                std::os::unix::fs::symlink(&target, &tmp).unwrap();
                tmp
            })
            .collect();

        let e = write_atomic_mode(&staged, b"volume = \"/dev/sdb1\"\n", Some(0o600))
            .expect_err("a name this write did not create is not a name it may open");
        assert_eq!(
            e.kind(),
            io::ErrorKind::AlreadyExists,
            "the refusal must be the collision itself: {e}"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"untouched",
            "the link's target must not have been written through"
        );
        assert!(
            !staged.exists(),
            "and nothing was published at the destination either"
        );
        // Calibration: the name the write reached is one of the planted ones, so the assertions
        // above were answered by the guard rather than by a name nobody tried.
        assert!(
            planted.iter().any(|p| !p.exists()),
            "the write never reached a planted name — the span no longer covers the sequence"
        );
    }

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

    /// The temp is never, at any instant, more readable than the mode the caller asked for.
    ///
    /// A mode applied after the `open` leaves the bytes at the umask's mode for the whole write and
    /// flush. The window is not theoretical for what goes through here: an app profile carries
    /// `[secret]` locators, and it is staged beside its destination, which is not always an
    /// owner-only directory. So the mode rides the `open`, and this watches the directory during a
    /// write large enough to last while it looks.
    #[test]
    fn a_staged_file_is_never_readable_beyond_the_mode_it_was_asked_for() {
        use std::os::unix::fs::PermissionsExt as _;
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("stage");
        std::fs::create_dir_all(&dir).unwrap();
        // A permissive umask, so a temp created without a mode of its own is visibly wider than
        // what was asked for rather than accidentally equal to it.
        let previous = unsafe { libc::umask(0o022) };

        let target = dir.join("profile.toml");
        let body = vec![b'x'; 8 * 1024 * 1024];
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u32>::new()));
        let watching = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let (w, d, s) = (watching.clone(), dir.clone(), seen.clone());
        let watcher = std::thread::spawn(move || {
            while w.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(entries) = std::fs::read_dir(&d) {
                    for e in entries.flatten() {
                        if e.file_name().to_string_lossy().contains(".tmp.")
                            && let Ok(m) = e.metadata()
                        {
                            s.lock().unwrap().push(m.permissions().mode() & 0o777);
                        }
                    }
                }
            }
        });
        write_atomic_mode(&target, &body, Some(0o600)).unwrap();
        watching.store(false, std::sync::atomic::Ordering::Relaxed);
        watcher.join().unwrap();
        unsafe { libc::umask(previous) };

        let mut modes = seen.lock().unwrap().clone();
        modes.sort_unstable();
        modes.dedup();
        assert!(
            !modes.is_empty(),
            "the watcher never saw the temp, so it asserts nothing about it"
        );
        assert!(
            modes.iter().all(|m| *m & 0o077 == 0),
            "the temp existed readable beyond its owner: {:?}",
            modes.iter().map(|m| format!("{m:o}")).collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// Two stagings running at once publish two whole files, never one file made of both.
    ///
    /// The failure this holds off is not the lost update — one of two writers to the same name
    /// always loses — but the torn publish: with a shared temp, the second writer truncates the
    /// inode the first is still filling, and the rename installs a head from one body and a tail
    /// from the other. So the assertion is on the *content*: whichever body wins, the file holds
    /// that one entire and nothing of the other. Bodies large enough that a write is not one
    /// syscall, because a torn file needs the two writes to interleave.
    #[test]
    fn two_concurrent_stagings_publish_a_whole_body_and_never_a_mixture() {
        let base = crate::testutil::TmpDir::new();
        let dir = base.path().join("stage");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("contended");
        let a = vec![b'a'; 512 * 1024];
        let b = vec![b'b'; 512 * 1024];

        for round in 0..16 {
            std::thread::scope(|s| {
                let one = s.spawn(|| write_atomic(&target, &a));
                let two = s.spawn(|| write_atomic(&target, &b));
                // Both report success: a writer whose temp another one renamed away fails its own
                // rename with ENOENT, which is the same defect seen from the other end.
                for (which, r) in [("a", one.join()), ("b", two.join())] {
                    let r = r.expect("staging thread");
                    assert!(r.is_ok(), "round {round}, writer {which}: {r:?}");
                }
            });
            let published = std::fs::read(&target).unwrap();
            assert!(
                published == a || published == b,
                "the published file is neither whole body: {} bytes, {} of them 'a'",
                published.len(),
                published.iter().filter(|&&c| c == b'a').count()
            );
            // And the staging leaves nothing behind under either name.
            let leftovers: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(".tmp."))
                .collect();
            assert!(leftovers.is_empty(), "temps left behind: {leftovers:?}");
        }
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
