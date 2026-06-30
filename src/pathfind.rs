//! Locating executables on `PATH`.
//!
//! The prerequisite checks share one first-match-wins search: the same routine
//! that finds the sandbox engine also finds the nix binary that drives the
//! store.

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
    dirs.map(|dir| dir.join(name))
        .find(|cand| is_executable(cand))
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
    dirs.map(|dir| dir.join(name))
        .filter(|cand| is_executable(cand))
        .collect()
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
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
}
