//! Test-only helpers shared across the module unit tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique temp directory that removes itself on drop, so tests leave nothing
/// behind (cleanup runs on panic-unwind too, not just on success).
pub(crate) struct TmpDir(PathBuf);

impl TmpDir {
    pub(crate) fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Throwaway dirs live on the repo's disk, not the system tmpfs. A test that
        // provisions a nix store copies the entire nixpkgs source tree — a very large
        // file count — into it, and several such tests running concurrently would
        // exhaust a tmpfs's fixed inode budget (`ENOSPC`, even with bytes to spare),
        // while disk has inodes in abundance. This also matches production, where the
        // store lives on disk under the data directory, never on a tmpfs. `target/`
        // keeps it out of the way and reclaimable by `cargo clean`.
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("target/test-tmp");
        d.push(format!("ops-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories — a provisioned nix store
/// makes its directories `0555`, so a plain `remove_dir_all` cannot delete their
/// contents. Add write to each directory on the way down, then remove. Best
/// effort: cleanup never fails a test.
pub(crate) fn force_remove(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}
