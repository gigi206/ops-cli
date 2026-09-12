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

    /// No production launch names its program by a bare literal, because such a name never reaches
    /// this module.
    ///
    /// The rule here is universal: only an absolute `PATH` entry may name a program. It is written
    /// once, in [`candidates`], and a `Command::new("tool")` never arrives there — a program
    /// holding no `/` is looked up by `execvp(3)` against the **inherited** `PATH`, where POSIX
    /// gives an empty element the meaning "the current directory". A launch's current directory is
    /// the project tree, which sbx treats as untrusted by construction, so a repository shipping a
    /// `sops` of its own would be the one handed its own encrypted file to decrypt.
    ///
    /// What this reads is the literal written at the call. A program held in a variable cannot be
    /// judged from the text, and neither can one a helper takes as an argument: the `sops` site was
    /// spelled `Path::new("sops")` two calls away and is pinned by its own test instead. So this
    /// closes the spelling that five sites used, not the class — which is why the lookup is a
    /// function every caller can reach rather than a rule kept in a comment.
    #[test]
    fn no_production_launch_names_its_program_by_a_bare_literal() {
        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let declared_test_only = crate::testutil::test_only_sources();
        let mut offenders: Vec<String> = Vec::new();
        for file in crate::testutil::crate_sources() {
            if crate::testutil::is_test_only_source(&file) || declared_test_only.contains(&file) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let production = crate::testutil::production_half(&text);
            for (at, needle) in production.match_indices("Command::new(\"") {
                let Some(name) = production[at + needle.len()..].split('"').next() else {
                    continue;
                };
                if name.contains('/') {
                    continue;
                }
                let line = production[..at].matches('\n').count() + 1;
                let relative = file.display().to_string().replacen(&root, "", 1);
                offenders.push(format!("{relative}:{line} runs `{name}`"));
            }
        }
        assert!(
            offenders.is_empty(),
            "these leave the program to `execvp` and the inherited `PATH`:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// Every production `PATH` search that skips the trust check is named here, with its reason.
    ///
    /// [`find_on_path`] answers "what would `execvp` run"; [`crate::store::find_trusted_on_path`]
    /// adds the owner and mode verdict the engine tiers apply, skipping an untrusted match for a
    /// later sound one. Host tools take the second. The few sites that do not each have a reason
    /// that is not "nobody looked", so a new one fails here until it is named rather than joining
    /// them by default. The inventory is checked both ways: a stale entry fails too, because a
    /// list that keeps naming a site it no longer describes stops being read.
    #[test]
    fn every_production_path_search_that_skips_the_trust_check_is_accounted_for() {
        const ACCOUNTED: &[(&str, &str)] = &[
            (
                "src/cli/config/edit.rs",
                "`sh` is the interpreter every `$EDITOR` invocation already runs through, so an \
                 untrusted one is a condition of the machine rather than of this verb",
            ),
            (
                "src/sandbox/cgroup.rs",
                "the `doctor` note tells `no systemd-run at all` from `one found but refused`, \
                 which is a distinction only the unweighed search can still make",
            ),
        ];
        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let declared_test_only = crate::testutil::test_only_sources();
        let mut found: Vec<String> = Vec::new();
        for file in crate::testutil::crate_sources() {
            if crate::testutil::is_test_only_source(&file) || declared_test_only.contains(&file) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            if !crate::testutil::production_half(&text).contains("pathfind::find_on_path(") {
                continue;
            }
            found.push(file.display().to_string().replacen(&root, "", 1));
        }
        let unaccounted: Vec<&String> = found
            .iter()
            .filter(|f| !ACCOUNTED.iter().any(|(named, _)| *named == f.as_str()))
            .collect();
        assert!(
            unaccounted.is_empty(),
            "these search `PATH` without weighing the match, and none says why:\n  {:?}",
            unaccounted
        );
        let stale: Vec<&str> = ACCOUNTED
            .iter()
            .map(|(named, _)| *named)
            .filter(|named| !found.iter().any(|f| f == named))
            .collect();
        assert!(
            stale.is_empty(),
            "no longer search `PATH` bare:\n  {stale:?}"
        );
    }
}
