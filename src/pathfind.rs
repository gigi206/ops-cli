//! Locating executables on `PATH`.
//!
//! The prerequisite checks share one first-match-wins search: the same routine
//! that finds the sandbox engine also finds the nix binary that drives the
//! store. Only an **absolute** `PATH` entry outside the project is searched,
//! whichever routine asks — see [`candidates`] for what a relative one would
//! otherwise resolve to, and what one in the project would let the cage plant.

use std::path::{Path, PathBuf};

/// Search `$PATH` for an executable file with the given name, returning the first match.
pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let tree = untrusted_tree();
    say_left_out(name, std::env::split_paths(&path), tree.as_deref());
    find_in_dirs(name, std::env::split_paths(&path), tree.as_deref())
}

/// Pure core of [`find_on_path`]: the first directory whose `name` entry is
/// executable, none in `untrusted`. Split out so it can be tested without mutating
/// the process `PATH` or its working directory.
pub(crate) fn find_in_dirs(
    name: &str,
    dirs: impl Iterator<Item = PathBuf>,
    untrusted: Option<&Path>,
) -> Option<PathBuf> {
    candidates(name, dirs, untrusted).find(|cand| is_executable(cand))
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
    let tree = untrusted_tree();
    say_left_out(name, std::env::split_paths(&path), tree.as_deref());
    find_all_in_dirs(name, std::env::split_paths(&path), tree.as_deref())
}

/// Pure core of [`find_all_on_path`]: every directory whose `name` entry is executable,
/// in iteration order, none in `untrusted`. Split out so it can be tested without
/// mutating the process `PATH` or its working directory.
pub(crate) fn find_all_in_dirs(
    name: &str,
    dirs: impl Iterator<Item = PathBuf>,
    untrusted: Option<&Path>,
) -> Vec<PathBuf> {
    candidates(name, dirs, untrusted)
        .filter(|cand| is_executable(cand))
        .collect()
}

/// The tree the cage writes as the project, canonical: the working directory every verb runs in.
/// `None` when that is `/`, a project the cage writes whole, where leaving out what lies under it
/// would leave out every program and protect nothing, or when it cannot be read.
pub(crate) fn untrusted_tree() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?.canonicalize().ok()?;
    cwd.parent().is_some().then_some(cwd)
}

/// Whether `p` lies in `tree`, read through every link on the way to it: a `PATH` entry that is a
/// link into the project is the project.
pub(crate) fn lies_in(tree: &Path, p: &Path) -> bool {
    crate::trust::canonicalize_existing_prefix(p).starts_with(tree)
}

/// Say, once per program, each executable `name` the search leaves out because it lies in
/// `untrusted`: without a word, a program found only there would read as not installed.
fn say_left_out(name: &str, dirs: impl Iterator<Item = PathBuf>, untrusted: Option<&Path>) {
    use std::sync::{Mutex, OnceLock};
    static SAID: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    let Some(tree) = untrusted else { return };
    for found in candidates(name, dirs, None).filter(|c| is_executable(c)) {
        if !lies_in(tree, found.parent().unwrap_or(&found)) {
            continue;
        }
        let mut said = crate::sandbox::locks::locked(SAID.get_or_init(Mutex::default));
        if !said.contains(&found) {
            crate::diag::warn(&format!(
                "`{}` on your PATH is not used: it lies in the project, which the cage writes, so \
                 a session could have put it there. Install `{name}` outside the project",
                crate::sandbox::sanitize(&found.display().to_string())
            ));
            said.push(found);
        }
    }
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
///
/// An absolute entry in `untrusted`, the project, is dropped for the same reason: the cage writes
/// the project, so a `<project>/.venv/bin` an activated environment or a `direnv` put in front of
/// `/usr/bin` holds whatever a session left there, and the ownership check is satisfied by what it
/// holds. Read through links, so an entry linking into the project counts as the project. A
/// read-write bind is written by the cage too and is not weighed here: `PATH` lookups do not know
/// the binds.
///
/// And `name` must be a bare file name. One holding a `/` is not a `PATH` lookup at all —
/// `dir.join("/bin/sh")` is `/bin/sh` whatever `dir` is, and `dir.join("../x")` leaves it — so it
/// would be answered by a file the `PATH` never named. Such a name, an empty one, `.` and `..`
/// yield no candidate.
fn candidates<'a>(
    name: &'a str,
    dirs: impl Iterator<Item = PathBuf> + 'a,
    untrusted: Option<&'a Path>,
) -> impl Iterator<Item = PathBuf> + 'a {
    let bare = !name.is_empty() && !name.contains('/') && name != "." && name != "..";
    dirs.filter(move |dir| {
        bare && dir.is_absolute() && !untrusted.is_some_and(|tree| lies_in(tree, dir))
    })
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
    access_ok(p, libc::X_OK)
}

/// Whether the current process may use `p` as `mode` says (`access(2)`: `R_OK`, `W_OK`, `X_OK`).
///
/// The kernel's answer rather than a reading of the mode bits: it weighs this uid and its groups
/// against owner, group and other together, applies ACLs, and refuses a write on a read-only mount,
/// none of which a `mode & 0o222` test sees.
pub(crate) fn access_ok(p: &Path, mode: libc::c_int) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path; `access` only reads and returns a status.
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    /// The scenario measured on the engine and the askpass lookups: a `<project>/.venv/bin` an
    /// activated environment put in front of the system directory holds a planted program, and the
    /// search takes the system one. An entry that is a link into the project is the project too.
    #[test]
    fn a_path_entry_in_the_project_is_not_searched() {
        let tmp = TmpDir::new();
        let root = tmp.path().canonicalize().unwrap();
        let project = root.join("proj");
        let venv = project.join(".venv/bin");
        let system = root.join("usr/bin");
        let linked = root.join("linked-bin");
        std::fs::create_dir_all(&venv).unwrap();
        std::fs::create_dir_all(&system).unwrap();
        std::os::unix::fs::symlink(&venv, &linked).unwrap();
        for name in ["bwrap", "nix", "ssh-askpass"] {
            for dir in [&venv, &system] {
                let tool = dir.join(name);
                std::fs::write(&tool, b"#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            for first in [&venv, &linked] {
                let dirs = || [first.clone(), system.clone()].into_iter();
                assert_eq!(
                    find_in_dirs(name, dirs(), Some(&project)),
                    Some(system.join(name)),
                    "{name} through {}",
                    first.display()
                );
                assert_eq!(
                    find_all_in_dirs(name, dirs(), Some(&project)),
                    vec![system.join(name)]
                );
                assert_eq!(
                    find_in_dirs(name, dirs(), None),
                    Some(first.join(name)),
                    "outside any project the first entry still wins"
                );
            }
        }
    }

    fn write_exec(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_name_that_is_not_a_bare_file_name_yields_no_candidate() {
        let dir = TmpDir::new();
        let bin = dir.join("bin");
        std::fs::create_dir(&bin).unwrap();
        write_exec(&dir.join("outside"));
        let dirs = || std::iter::once(bin.clone());
        let absolute = dir.join("outside");
        for name in [absolute.to_str().unwrap(), "../outside", "", ".", ".."] {
            assert_eq!(find_in_dirs(name, dirs(), None), None, "{name:?} was found");
            assert!(
                find_all_in_dirs(name, dirs(), None).is_empty(),
                "{name:?} was found"
            );
        }
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
        let found = find_in_dirs("tool", dirs.iter().cloned(), None);
        assert_eq!(found.as_deref(), Some(tool.as_path()));

        // absent everywhere
        assert!(find_in_dirs("absent", dirs.into_iter(), None).is_none());
    }

    #[test]
    fn find_all_in_dirs_yields_every_match_in_order() {
        let a = TmpDir::new();
        let b = TmpDir::new();
        // The same name is executable in both directories.
        write_exec(&a.join("tool"));
        write_exec(&b.join("tool"));

        let dirs = [a.path().to_path_buf(), b.path().to_path_buf()];
        let found = find_all_in_dirs("tool", dirs.iter().cloned(), None);
        assert_eq!(
            found,
            vec![a.join("tool"), b.join("tool")],
            "both matches, in PATH order"
        );

        // A name present in neither yields an empty list, not a panic.
        assert!(find_all_in_dirs("absent", dirs.into_iter(), None).is_empty());
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
        let formed: Vec<PathBuf> = candidates("bw", dirs.into_iter(), None).collect();
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
            find_in_dirs("tool", dirs(), None).as_deref(),
            Some(dir.join("tool").as_path())
        );
        assert_eq!(
            find_all_in_dirs("tool", dirs(), None),
            vec![dir.join("tool")]
        );
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

    /// Whether `line` names [`find_on_path`] as a whole identifier, not as part of a longer one.
    fn names_find_on_path(line: &str) -> bool {
        const NAME: &str = "find_on_path";
        let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
        line.match_indices(NAME).any(|(at, _)| {
            !line[..at].ends_with(ident) && !line[at + NAME.len()..].starts_with(ident)
        })
    }

    #[test]
    fn the_inventory_sees_a_search_however_it_is_spelled() {
        for spelled in [
            "let x = crate::pathfind::find_on_path(\"tool\");",
            "use crate::pathfind::find_on_path;",
            "let x = find_on_path(name);",
            "names.iter().filter_map(|n| pathfind::find_on_path(n))",
            ".map(crate::pathfind::find_on_path)",
        ] {
            assert!(names_find_on_path(spelled), "missed: {spelled}");
        }
        for other in [
            "crate::store::find_trusted_on_path(\"nix\")",
            "crate::pathfind::find_all_on_path(name)",
            "fn my_find_on_path_helper()",
        ] {
            assert!(!names_find_on_path(other), "flagged: {other}");
        }
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
            if file.ends_with("src/pathfind.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            // The name as a token on a code line, however it is reached: qualified, imported and
            // called bare, or passed as a value. Comment lines are skipped, since a doc that names
            // the function searches nothing.
            let searches = crate::testutil::production_half(&text)
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(names_find_on_path);
            if !searches {
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
