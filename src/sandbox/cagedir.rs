//! Making a directory inside a tree the **cage** can write, with symlinks refused.
//!
//! Several host-side steps place files under a directory that is bind-mounted read-write into the
//! sandbox: the per-project nix store's skeleton, the mise plugin registration, the live-theme
//! keyfile. The cage runs same-uid and those directories are `0700` owned by that uid, so
//! everything *below* the bind's mount point is an entry untrusted in-cage code may replace with a
//! symlink and leave behind for the next launch to walk into.
//!
//! `create_dir_all` cannot see that: it stats through a link, finds a directory, and reports the
//! parents as made. What follows then lands wherever the cage pointed — a seed copying the base
//! closure, a `remove_dir_all` clearing a slot, a keyfile write. Each of those was found as its own
//! defect before this module existed, which is why the rule lives in one place now rather than in
//! each of them.
//!
//! What is **not** here is the mount point itself. A bind's target is the one component the cage
//! cannot exchange (from inside, it *is* the mount), so it is the anchor every walk starts from and
//! the caller's job to name correctly.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Make `root`'s descendant `rel` (slash-separated), one component at a time, refusing any that
/// already exists and is **not a real directory**. Returns the path of the leaf.
///
/// `root` is the trusted anchor — a bind's mount point, or a directory the cage never sees — and is
/// created with `create_dir_all` like any ordinary path. Every component below it is
/// `symlink_metadata`'d before it is used, and a non-directory is a hard error rather than
/// something repaired in place: a tree that is not what sbx left is a finding the user should see,
/// and silently re-creating it would destroy the evidence along with whatever the cage had staged.
///
/// This closes the shape, not its last instant. A cage that is live *while* a launch walks here
/// could still swap a component between the check and the use; closing that needs descriptor-based
/// I/O carried through every caller, several of which hand paths to `nix`. What it removes is the
/// case that needs no race at all: a symlink left behind for the next launch to find.
pub(crate) fn ensure_under(root: &Path, rel: &str, mode: u32) -> io::Result<PathBuf> {
    DirBuilder::new().recursive(true).mode(mode).create(root)?;
    let mut at = root.to_path_buf();
    for component in rel.split('/').filter(|c| !c.is_empty()) {
        at.push(component);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) => return Err(not_a_directory(&at, &meta)),
            // Absent a moment ago. Creating it can still lose a race — two launches of the same
            // project register their mise plugin at once, which is the "second terminal" case
            // `miseplugin` is tested for — so `AlreadyExists` is re-read rather than propagated,
            // exactly as `create_dir_all` tolerates it. What the winner left still has to be a real
            // directory: the check is not skipped for having lost.
            Err(_) => match DirBuilder::new().mode(mode).create(&at) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    match fs::symlink_metadata(&at) {
                        Ok(meta) if meta.is_dir() => {}
                        Ok(meta) => return Err(not_a_directory(&at, &meta)),
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            },
        }
    }
    Ok(at)
}

/// The refusal [`ensure_under`] returns for a component that exists and is not a directory, naming
/// what was found and what to do about it.
fn not_a_directory(at: &Path, meta: &fs::Metadata) -> io::Error {
    let kind = if meta.file_type().is_symlink() {
        "a symlink"
    } else {
        "not a directory"
    };
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "`{}` is {kind} — this tree is writable by the cage, so this is what in-cage code \
             leaves behind to redirect the next launch. Reclaim it (`sbx gc`) or remove that entry \
             by hand",
            at.display()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// The case that needs no race: a link left behind for the next launch to walk into. Every
    /// component below the anchor is checked, because one missing check is the whole hole.
    #[test]
    fn a_symlink_at_any_component_is_refused_and_never_written_through() {
        for rel in ["a", "a/b", "a/b/c"] {
            let tmp = TmpDir::new();
            let root = tmp.join("root");
            let elsewhere = tmp.join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            let planted = root.join(rel);
            std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &planted).unwrap();

            let err = ensure_under(&root, "a/b/c", 0o700)
                .err()
                .unwrap_or_else(|| panic!("a symlink at {rel} must be refused"));
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{rel}");
            assert!(err.to_string().contains("is a symlink"), "{err}");
            assert_eq!(
                std::fs::read_dir(&elsewhere).unwrap().count(),
                0,
                "{rel}: the walk went through the link"
            );
            assert_eq!(
                std::fs::read_link(&planted).unwrap(),
                elsewhere,
                "{rel}: the planted link must be reported, not replaced"
            );
        }
    }

    /// Two launches of the same project walk the same chain at once — the "second terminal" case
    /// `miseplugin::register` is tested for. A component absent a moment ago can be created by the
    /// other thread in between, so `AlreadyExists` has to be re-read rather than propagated, the
    /// way `create_dir_all` tolerates it. This caught a real regression when the walk first
    /// replaced `create_dir_all`.
    #[test]
    fn concurrent_walks_of_one_chain_all_succeed() {
        let tmp = TmpDir::new();
        let root = tmp.join("root");
        std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| ensure_under(&root, "a/b/c", 0o700)))
                .collect();
            for h in handles {
                let made = h.join().expect("no panic").expect("no error");
                assert_eq!(made, root.join("a/b/c"));
            }
        });
    }

    /// A file where a directory belongs is refused too, and says so differently — it is a mistake
    /// rather than an attack, and the message is what tells them apart.
    #[test]
    fn a_plain_file_in_the_way_is_refused_as_itself() {
        let tmp = TmpDir::new();
        let root = tmp.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a"), b"").unwrap();
        let err = ensure_under(&root, "a/b", 0o700).expect_err("a file is not a directory");
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    /// And the ordinary path is made, owner-only and idempotently — a guard that refused everything
    /// would satisfy the tests above while breaking every launch.
    #[test]
    fn a_missing_chain_is_created_owner_only_and_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new();
        let root = tmp.join("root");

        let made = ensure_under(&root, "a/b/c", 0o700).unwrap();
        assert_eq!(made, root.join("a/b/c"));
        for dir in [root.clone(), root.join("a"), root.join("a/b"), made.clone()] {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is not owner-only", dir.display());
        }
        assert_eq!(ensure_under(&root, "a/b/c", 0o700).unwrap(), made);
        // An empty `rel` is the anchor itself, which is a legitimate ask.
        assert_eq!(ensure_under(&root, "", 0o700).unwrap(), root);
    }
}
