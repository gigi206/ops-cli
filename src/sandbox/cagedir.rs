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

use std::fs::DirBuilder;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// Make `root`'s descendant `rel` (slash-separated), one component at a time, refusing any that
/// already exists and is **not a real directory**. Returns the path of the leaf.
///
/// `root` is the trusted anchor — a bind's mount point, or a directory the cage never sees — and is
/// created with `create_dir_all` like any ordinary path. Every component below it is opened
/// `O_NOFOLLOW | O_DIRECTORY` **from the descriptor of the one above it**, and a non-directory is a
/// hard error rather than something repaired in place: a tree that is not what sbx left is a finding
/// the user should see, and silently re-creating it would destroy the evidence along with whatever
/// the cage had staged.
///
/// The walk descends by descriptor rather than by re-resolving the path at each step, and that is
/// what makes the check and the use the same act: a component validated here is the one the next
/// component is opened from, so exchanging it afterwards reaches nothing this walk went on to use.
/// Re-resolving from the path — which is what this did — left a window between a component's check
/// and the resolution that walked through it, and the cage owns every directory below the anchor.
///
/// What remains open is the **path this returns**. A caller holds a name, not a descriptor, and the
/// cage may exchange a component before the caller uses it; closing that needs descriptor-based I/O
/// carried through every caller, several of which hand paths to `nix`. So the window this removes is
/// the one inside the walk, and the case that needs no race at all — a symlink left behind for the
/// next launch to find — is removed with it.
pub(crate) fn ensure_under(root: &Path, rel: &str, mode: u32) -> io::Result<PathBuf> {
    use std::os::fd::AsRawFd;

    DirBuilder::new().recursive(true).mode(mode).create(root)?;
    let mut at = root.to_path_buf();
    let mut dir = open_dir(libc::AT_FDCWD, &cstr(root.as_os_str().as_encoded_bytes())?)?;

    for component in rel.split('/').filter(|c| !c.is_empty()) {
        at.push(component);
        let name = cstr(component.as_bytes())?;
        let opened = match open_dir(dir.as_raw_fd(), &name) {
            Ok(fd) => Some(fd),
            // Absent a moment ago. Creating it can still lose a race — two launches of the same
            // project register their mise plugin at once, which is the "second terminal" case
            // `miseplugin` is tested for — so `AlreadyExists` is re-read rather than propagated,
            // exactly as `create_dir_all` tolerates it. What the winner left still has to be a real
            // directory, and the re-open below is the check: it is not skipped for having lost.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // SAFETY: `name` is a live NUL-terminated component for the duration of the call,
                // and `dir` is an open directory descriptor this function owns. `split('/')` on a
                // `&str` cannot yield an interior NUL, which `cstr` refuses in any case.
                let made = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
                if made < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                }
                None
            }
            Err(e) => return Err(describe(&at, dir.as_raw_fd(), &name, e)),
        };
        dir = match opened {
            Some(fd) => fd,
            None => {
                let parent = dir.as_raw_fd();
                open_dir(parent, &name).map_err(|e| describe(&at, parent, &name, e))?
            }
        };
    }
    Ok(at)
}

/// Open `name` under `at` as a directory that is itself no symlink: `O_PATH` because nothing is read
/// through it, `O_NOFOLLOW` so a component the cage replaced with a link is refused rather than
/// walked, and `O_DIRECTORY` so anything else that is not a directory is refused too.
fn open_dir(at: libc::c_int, name: &std::ffi::CString) -> io::Result<OwnedFd> {
    // SAFETY: `name` is a live NUL-terminated path for the duration of the call, and `at` is either
    // `AT_FDCWD` or a directory descriptor owned by the caller and still open.
    let fd = unsafe {
        libc::openat(
            at,
            name.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh owned descriptor; `OwnedFd` takes sole ownership and closes it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A component's path as a NUL-terminated string, refusing the interior NUL a path cannot carry.
fn cstr(bytes: &[u8]) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "a path component holds a NUL byte",
        )
    })
}

/// Turn the open's errno into the refusal a reader can act on.
///
/// `O_NOFOLLOW | O_DIRECTORY` answers a symlink and a plain file with the same `ENOTDIR`, and the
/// difference is the whole of what the user needs to know — so the kind is read back with an
/// `lstat`, which is a second look at a name this walk is refusing either way. Any other errno is
/// what it is.
fn describe(at: &Path, dir: libc::c_int, name: &std::ffi::CString, e: io::Error) -> io::Error {
    if e.raw_os_error() != Some(libc::ENOTDIR) && e.raw_os_error() != Some(libc::ELOOP) {
        return e;
    }
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is a live NUL-terminated component, `dir` is an open directory descriptor the
    // caller still owns, and `st` is written only on success, which the return value reports.
    let asked = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if asked < 0 {
        return e;
    }
    // SAFETY: `fstatat` returned success, so `st` is initialised.
    let mode = unsafe { st.assume_init() }.st_mode;
    not_a_directory(at, mode & libc::S_IFMT == libc::S_IFLNK)
}

/// The refusal [`ensure_under`] returns for a component that exists and is not a directory, naming
/// what was found and what to do about it.
fn not_a_directory(at: &Path, is_symlink: bool) -> io::Error {
    let kind = if is_symlink {
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

    /// A component exchanged between two walks is refused on the second, and nothing is written
    /// through it.
    ///
    /// The case the module exists for, and the one that needs no race at all: in-cage code replaces
    /// a directory in the middle of a tree it holds read-write with a link to somewhere it owns, and
    /// the next launch walks the same chain. What the descriptor walk adds on top of this is the
    /// window *inside* one walk, between a component's check and the resolution that walks through
    /// it. That window is closed by construction rather than by this test: racing it against the
    /// previous implementation does not reach it, so there is no red to calibrate against and the
    /// property is asserted where it can be — the elsewhere stays untouched.
    #[test]
    fn a_component_exchanged_between_two_walks_is_refused_on_the_second() {
        let base = crate::testutil::TmpDir::new();
        let root = base.path().join("root");
        let elsewhere = base.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("witness"), b"untouched").unwrap();

        let leaf = ensure_under(&root, "a/b/c", 0o700).expect("the first walk builds the chain");
        assert!(leaf.is_dir(), "the first walk leaves a real tree");

        std::fs::remove_dir_all(root.join("a")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("a")).unwrap();

        let e = ensure_under(&root, "a/b/c", 0o700)
            .expect_err("a component that is now a link must be refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        assert!(
            e.to_string().contains("symlink"),
            "the refusal names what it found: {e}"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere).unwrap().count(),
            1,
            "nothing was created through the link"
        );
        assert_eq!(
            std::fs::read(elsewhere.join("witness")).unwrap(),
            b"untouched"
        );
    }

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
