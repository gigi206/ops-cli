//! The fixture directory every integration suite creates its trees under.
//!
//! One definition rather than twenty. Each suite used to carry its own `struct TmpDir` — the same
//! four-line type, differing only in the prefix it stamped on a directory name — and the copies had
//! already drifted into eight shapes, only one of which capped the tag. A rule about where fixtures
//! live is worth nothing if it has to be re-stated per suite to hold.
//!
//! The root itself comes from [`fixture_root`], included here rather than linked because an
//! integration test is its own crate and cannot see into the binary. A suite that needs the root for
//! something other than a `TmpDir` includes that same text itself; the two definitions are the same
//! bytes, which is the property that matters.

// The fixtures' root, one definition shared with the unit tests.
include!("../../src/testroot.rs");

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// How much of a fixture's tag survives into its directory name. With the prefix, a pid and the
/// counter, this keeps a fixture directory at 25 bytes or so — inside the budget an `…/sbx` data
/// dir has under a checkout at a normal depth.
const TAG_MAX: usize = 10;

/// A fixture directory, removed when it drops.
pub struct TmpDir(PathBuf);

impl TmpDir {
    /// Create one, labelled `tag`.
    ///
    /// A short prefix on purpose: a launch's egress proxy binds a Unix socket under this data dir
    /// (`…/<dir>/sbx/egress/proxy-<pid>.sock`), and `sun_path` caps the whole path at 108 bytes. A
    /// longer prefix plus a 7-digit pid (counted twice — here and in the socket name) tips a deep
    /// checkout over the limit, so keep this terse.
    ///
    /// The tag is a fixture label, not an identity — the counter alone makes the name unique — so it
    /// is capped here rather than trusted. A test that picks a descriptive tag would otherwise push
    /// its own data dir past the budget and fail with sbx's "path too long" refusal, which reads as
    /// a product bug rather than as a fixture that named itself.
    pub fn new(tag: &str) -> Self {
        Self::build(None, tag)
    }

    /// Create one under a suite-wide `prefix`, labelled `tag`.
    ///
    /// For the suites whose tests each name their own fixture: the prefix says which suite left a
    /// directory behind, which the tag alone would not, and it is the suite's identity rather than
    /// the test's so it is not subject to [`TAG_MAX`].
    pub fn prefixed(prefix: &str, tag: &str) -> Self {
        Self::build(Some(prefix), tag)
    }

    fn build(prefix: Option<&str>, tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        let tag: String = tag.chars().take(TAG_MAX).collect();
        let pid = std::process::id();
        d.push(match prefix {
            Some(p) => format!("{p}-{tag}-{pid}-{n}"),
            None => format!("{tag}-{pid}-{n}"),
        });
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }

    /// The directory itself.
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A path under it.
    pub fn join(&self, rel: impl AsRef<Path>) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories — a provisioned nix store makes its
/// directories `0555`, so a plain `remove_dir_all` cannot delete their contents. Add write to each
/// directory on the way down, then remove. Best effort: cleanup never fails a test.
///
/// One definition rather than eleven. The copies were identical to the byte, and the suites that
/// did *not* carry one dropped their fixtures with `remove_dir_all` — which is exactly the call
/// that walks into a store's `0555` directories and leaves most of the tree on disk.
pub fn force_remove(path: &Path) {
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
