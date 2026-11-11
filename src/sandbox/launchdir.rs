//! A launch's own runtime directory, bound read-write into its cage.
//!
//! The port forwarder ([`super::forward`]) gives its launch a host directory under the data
//! directory, keyed by the launcher pid, and binds it into the cage read-write so that sockets made
//! on one side are reached from the other. Two things follow from that shape, for any directory
//! that has it.
//!
//! The name carries the pid alone, so two launches of one process would name one directory:
//! [`LiveDir`] refuses the second while the first holds it. And the directory a launch is handed
//! may be a dead predecessor's, left by a process whose pid this one now has and whose cage could
//! write anything into it: [`fresh_dir`] hands it back empty and `0700`.

use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// The launch directories a launch of this process holds, so a second launch running at the same
/// time is refused its directory rather than emptying it under the first.
static LIVE_DIRS: std::sync::Mutex<std::collections::BTreeSet<PathBuf>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// One launch's hold on its directory in [`LIVE_DIRS`], released on drop.
pub(crate) struct LiveDir(PathBuf);

impl LiveDir {
    /// Hold `dir`, or refuse when a launch of this process already does.
    ///
    /// The name carries the pid alone, so two launches of one process name one directory, and the
    /// second's [`fresh_dir`] would empty the first's sockets. sbx launches one cage at a time per
    /// process — `sbx upgrade` drops each launch's guard before the next — so this is the shape a
    /// future caller could reach rather than one that runs today.
    pub(crate) fn take(dir: &Path) -> io::Result<Self> {
        let mut live = LIVE_DIRS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !live.insert(dir.to_path_buf()) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "another launch of this process holds {}; one launch at a time per process \
                     uses it",
                    dir.display()
                ),
            ));
        }
        Ok(LiveDir(dir.to_path_buf()))
    }
}

impl Drop for LiveDir {
    fn drop(&mut self) {
        LIVE_DIRS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// Make `dir`, one launch's directory, empty and `0700`, whatever was at that name.
///
/// The directory is bound into the cage read-write, so the cage can widen its mode, and leave a
/// socket, a fifo or a directory at any name in it. Keyed by pid, it is the directory a later
/// process inherits when its pid is that of a `SIGKILL`ed predecessor whose teardown never ran.
/// Reused as found, it would keep the mode that cage left (`DirBuilder::mode` applies only to a
/// directory it creates), and a leftover at a socket's name would make the in-cage listener that
/// binds it fail.
///
/// A directory already at the name is a dead predecessor's — a live launch of this process holds
/// it in [`LIVE_DIRS`] first — so it is removed, without following any link inside it, and made
/// again. One a killed process left behind is also reaped by `sbx gc`, which reads the pid off its
/// name and removes the entries of launches no longer running.
pub(crate) fn fresh_dir(dir: &Path) -> io::Result<()> {
    let make = || std::fs::DirBuilder::new().mode(0o700).create(dir);
    match make() {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            std::fs::remove_dir_all(dir)?;
            make()
        }
        made => made,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// A launch directory already at its name is a dead predecessor's, and the launch gets it back
    /// empty and `0700` whatever the predecessor's cage left: a widened mode, a stale socket, a
    /// directory at a socket's name, a link out of it. The link's target is left alone.
    #[test]
    fn a_directory_left_by_a_dead_predecessor_is_made_again_empty_and_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = TmpDir::new();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("kept"), b"").unwrap();
        let dir = tmp.path().join("fwd-1");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("p-9119.sock"), b"").unwrap();
        std::fs::create_dir(dir.join("p-9120.sock")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("p-9121.sock")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        fresh_dir(&dir).expect("make the directory again");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(
            outside.join("kept").exists(),
            "a link inside is not followed"
        );
    }
}
