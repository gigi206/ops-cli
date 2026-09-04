//! Locating executables on `PATH`.
//!
//! The prerequisite checks share one first-match-wins search: the same routine
//! that finds the sandbox engine also finds the nix binary that drives the
//! store. Only an **absolute** `PATH` entry is searched, whichever routine asks
//! — see [`candidates`] for what a relative one would otherwise resolve to.

use std::path::{Path, PathBuf};

/// Search `$PATH` for an executable file with the given name, returning the first match.
pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    find_in_dirs(name, std::env::split_paths(&path))
}

/// Pure core of [`find_on_path`]: the first directory whose `name` entry is
/// executable. Split out so it can be tested without mutating the process
/// `PATH`.
pub(crate) fn find_in_dirs(name: &str, dirs: impl Iterator<Item = PathBuf>) -> Option<PathBuf> {
    candidates(name, dirs).find(|cand| is_executable(cand))
}

/// Every executable named `name` on `$PATH`, in search order. Where [`find_on_path`]
/// stops at the first match, this yields all of them so a caller that applies its own
/// trust check can skip an untrusted early match and continue to a later trusted one —
/// a world-writable `nix`/`bwrap` in an early `PATH` directory then does not shadow the
/// legitimate engine further down.
pub(crate) fn find_all_on_path(name: &str) -> Vec<PathBuf> {
    let Some(path) = std::env::var_os("PATH") else {
        return Vec::new();
    };
    find_all_in_dirs(name, std::env::split_paths(&path))
}

/// Pure core of [`find_all_on_path`]: every directory whose `name` entry is executable,
/// in iteration order. Split out so it can be tested without mutating the process `PATH`.
pub(crate) fn find_all_in_dirs(name: &str, dirs: impl Iterator<Item = PathBuf>) -> Vec<PathBuf> {
    candidates(name, dirs)
        .filter(|cand| is_executable(cand))
        .collect()
}

/// What `name` may be, one candidate per **absolute** `PATH` entry. A relative entry yields none.
///
/// POSIX gives an empty `PATH` element the meaning "the current directory", and a shell honours it.
/// Nothing here is a shell. These lookups choose a binary to *execute* — the sandbox engine, the
/// nix that drives the store, the host tool a plugin's cage is built around — while the process's
/// working directory is the project tree, which sbx treats as untrusted by construction. Without
/// this filter an empty element (a stray `PATH="$PATH:"` in a shell profile is enough) makes
/// `dir.join(name)` relative, and the search resolves it against that tree: a file a repository
/// ships is then eligible to be the engine, or to be the `curl` a resolver runs beside a
/// credential. Nothing downstream refuses it — the ownership check is satisfied by a file in your
/// own checkout, since you own it and it need not be world-writable.
///
/// Every non-absolute entry is dropped, not the empty one alone: `.`, `bin`, and `../tools` name
/// the same class of thing and would resolve the same way. A `PATH` entry that means anything to
/// sbx is one that means the same thing from any directory.
fn candidates<'a>(
    name: &'a str,
    dirs: impl Iterator<Item = PathBuf> + 'a,
) -> impl Iterator<Item = PathBuf> + 'a {
    dirs.filter(|dir| dir.is_absolute())
        .map(move |dir| dir.join(name))
}

fn is_executable(p: &Path) -> bool {
    // A regular file this process can actually execute. `access(X_OK)` asks the kernel, weighing our
    // uid/gid against the file's owner/group/other bits together — unlike a raw `mode & 0o111 != 0`
    // test, which would accept a file whose only exec bit is for a user we are not, so an
    // unexecutable early `PATH` match would shadow a working later one.
    let is_file = std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false);
    is_file && access_x_ok(p)
}

/// Whether the current process may execute `p` (`access(2)` with `X_OK`).
fn access_x_ok(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path; `access` only reads and returns a status.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    fn write_exec(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn is_executable_reads_mode_bits() {
        let dir = TmpDir::new();
        let exe = dir.join("runme");
        write_exec(&exe);
        assert!(is_executable(&exe));

        let plain = dir.join("data");
        std::fs::write(&plain, b"x").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!is_executable(&plain));

        assert!(!is_executable(&dir.join("missing")));
    }

    #[test]
    fn find_in_dirs_picks_first_executable_match() {
        let a = TmpDir::new();
        let b = TmpDir::new();
        let tool = b.join("tool");
        write_exec(&tool);

        let dirs = [a.path().to_path_buf(), b.path().to_path_buf()];
        // present only in `b`, and executable
        let found = find_in_dirs("tool", dirs.iter().cloned());
        assert_eq!(found.as_deref(), Some(tool.as_path()));

        // absent everywhere
        assert!(find_in_dirs("absent", dirs.into_iter()).is_none());
    }

    #[test]
    fn find_all_in_dirs_yields_every_match_in_order() {
        let a = TmpDir::new();
        let b = TmpDir::new();
        // The same name is executable in both directories.
        write_exec(&a.join("tool"));
        write_exec(&b.join("tool"));

        let dirs = [a.path().to_path_buf(), b.path().to_path_buf()];
        let found = find_all_in_dirs("tool", dirs.iter().cloned());
        assert_eq!(
            found,
            vec![a.join("tool"), b.join("tool")],
            "both matches, in PATH order"
        );

        // A name present in neither yields an empty list, not a panic.
        assert!(find_all_in_dirs("absent", dirs.into_iter()).is_empty());
    }

    #[test]
    fn a_relative_path_entry_yields_no_candidate() {
        // The empty entry is the one that occurs in the wild: `PATH="$PATH:"` in a shell profile
        // gives it, a shell reads it as the current directory, and this search would then have
        // offered whatever the project tree ships under that name — as the sandbox engine, or as
        // the program a plugin runs beside a credential. Asserted on the candidate list rather
        // than on a lookup, because the property is that such a path is never *formed*: nothing
        // downstream would reject it, since a file in your own checkout is owned by you and need
        // not be world-writable.
        let dirs = [
            PathBuf::new(),
            PathBuf::from("."),
            PathBuf::from("bin"),
            PathBuf::from("../tools"),
            PathBuf::from("/usr/bin"),
        ];
        let formed: Vec<PathBuf> = candidates("bw", dirs.into_iter()).collect();
        assert_eq!(
            formed,
            vec![PathBuf::from("/usr/bin/bw")],
            "only the absolute entry may name a candidate"
        );
        assert!(
            formed.iter().all(|p| p.is_absolute()),
            "no candidate resolves against the working directory"
        );
    }

    #[test]
    fn a_relative_entry_does_not_shadow_an_absolute_one() {
        // The same rule through the public lookups: an empty entry ahead of a real directory
        // neither matches nor displaces the match behind it.
        let dir = TmpDir::new();
        write_exec(&dir.join("tool"));
        let dirs = || [PathBuf::new(), dir.path().to_path_buf()].into_iter();

        assert_eq!(
            find_in_dirs("tool", dirs()).as_deref(),
            Some(dir.join("tool").as_path())
        );
        assert_eq!(find_all_in_dirs("tool", dirs()), vec![dir.join("tool")]);
    }
}
