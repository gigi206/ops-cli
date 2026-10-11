//! Tests that the two runs claiming to exercise the cage name every suite that needs one.
//!
//! `cargo test` counts a test that returns early as **passed**, so a suite whose prerequisites are
//! absent reports green over work it never did. Two runs exist to answer that — `mise run test-cage`
//! locally and the `Cage` workflow on a runner given the prerequisites — and both name their suites
//! in a written-out list rather than globbing the directory. That choice is deliberate and stated in
//! both files: a new suite should be a deliberate addition, not a silent inclusion.
//!
//! What the choice does not do by itself is notice an **omission**. The lists are hand-kept in two
//! places, and a comment asking that they be held in step does not stop a suite added after them
//! from being left out of both, silently.
//!
//! So the list stays written out, and this is what makes forgetting it impossible. The addition is
//! still deliberate; only the silence is gone.

use crate::testutil::{files_under, read_listed};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The repository root, so a test reads the same files a reader would open.
fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The suites that carry a host-capability skip: the population both runs mean to name.
///
/// A host-capability skip, and not an off-host one — the distinction is the whole rule. The first
/// says *this host* lacks userns, bwrap, nix or systemd, exactly what these runs provide, so a
/// suite carrying one belongs in them. The second says something outside the host is unavailable (a
/// cache, a registry, the network), which no runner setting makes dependable and which therefore
/// says nothing about whether the cage was exercised.
///
/// The host kind is written two ways and both are read here. `skip_incapable!` is the macro itself;
/// `probe_or_skip!` is the gate the integration suites write around it, which runs a launch that
/// does nothing and reports that launch's own refusal through `skip_incapable!` when it fails. A
/// launch that failed on a download goes to `skip_unreachable!` instead, but every other refusal
/// is still the host's. A suite that adopted the gate did not stop needing a cage, and a scan
/// reading only the inner spelling would drop four suites and then report the omission against the
/// runs rather than against itself.
///
/// **The distinction selects nothing different in the current tree.** Every suite that carries an
/// off-host skip (`skip_unreachable!`, `need_reachable!`) carries host-capability skips besides, so
/// relaxing this predicate to any skip at all selects the same suites and a mutation doing so
/// survives. The rule is still the right one — it is the one both runs state — and it starts to
/// bite once a suite carries only the off-host kind. Until then this test cannot tell the two
/// apart, and a reader should not assume it can.
fn suites_carrying_a_cage_skip() -> BTreeSet<String> {
    let dir = root().join("tests");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("the integration test directory is readable") {
        let path: PathBuf = entry.expect("a readable directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("an integration suite is readable");
        if (text.contains("skip_incapable!") || text.contains("probe_or_skip!"))
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            out.insert(stem.to_string());
        }
    }
    assert!(
        out.len() > 5,
        "the scan found only {} suite(s) carrying a cage skip, so it has stopped matching the \
         source's shape and this test would pass vacuously",
        out.len()
    );
    out
}

/// The suites a run spells out, read from its single `for suite in … ; do` line.
///
/// Both files write that loop the same way, so one reader serves both. A file that stops carrying
/// the line fails here rather than returning an empty set that would agree with nothing.
fn named_suites(relative: &str) -> BTreeSet<String> {
    let path = root().join(relative);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{relative} is readable: {e}"));
    let mut found: Option<BTreeSet<String>> = None;
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("for suite in ") else {
            continue;
        };
        // The names end at the `;` before `do`, or with the line when the loop is written without one.
        let names = rest.split_once(';').map_or(rest, |(names, _)| names);
        let set: BTreeSet<String> = names.split_whitespace().map(str::to_string).collect();
        assert!(
            found.is_none(),
            "{relative} carries more than one `for suite in` line, so this reader cannot tell \
             which one runs the suites"
        );
        found = Some(set);
    }
    found.unwrap_or_else(|| {
        panic!("{relative} carries no `for suite in … ; do` line — the reader has gone stale")
    })
}

/// Every fully qualified test path a CI file names, as the file that names it and the path.
///
/// Read from `.github/` and `mise.toml` together because a filter and the prose describing it have
/// drifted apart before, and a reader looking for one finds the other.
fn test_paths_named_by_ci() -> Vec<(String, String)> {
    let mut files = files_under(&root().join(".github"), &["yml", "yaml"]);
    files.push(root().join("mise.toml"));

    let mut found = Vec::new();
    for file in files {
        let Some(text) = read_listed(&file) else {
            continue;
        };
        let name = file
            .strip_prefix(root())
            .unwrap_or(&file)
            .to_string_lossy()
            .into_owned();
        for token in text.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':')) {
            if token.contains("::tests::") {
                found.push((name.clone(), token.to_string()));
            }
        }
    }
    found
}

/// A CI filter that names a test which does not exist silences nothing, and says so to no one.
///
/// `cargo test -- --skip <path>` treats a path matching no test as satisfied, so a filter keeps
/// reading as though it still excludes something while the run it guards has quietly changed. That
/// is not hypothetical here: the systemd dollar test was renamed in 358bd4b, five places were
/// realigned in c0136ad, and the composite build action kept the old name because it had been
/// written days earlier and nobody was looking at it. The filter had stopped excluding anything,
/// and the only reason nothing broke is that the test also refuses itself on a host without a user
/// session, which is a second mechanism doing the first one's job by accident.
///
/// **The limit.** This reads fully qualified paths, which is what a live filter is written as. A
/// bare function name in prose is not matched, because an unqualified identifier cannot be told
/// from any other snake_case word without guessing, and a guard that guesses reports drift where
/// there is none.
///
/// The **module** half is checked too, not only the leaf. A filter names a path, and `--skip` reads
/// the whole of it: a test that keeps its name and moves to another module leaves the filter
/// excluding nothing, which is the same silence this guard exists for. The module a source file
/// declares is derived from its path under `src/` — the crate is a binary, so that path *is* the
/// module path — and a `tests` segment is dropped from both sides before the comparison, from the
/// filter because a test module's own nesting is not visible from the file tree, and from the
/// declared path because a module written as `<name>/tests.rs` spells that segment in the tree.
#[test]
fn every_test_a_ci_file_names_exists() {
    // Every test a source declares, with the module its file spells. `mod.rs` names the directory
    // it sits in; any other file names itself.
    let mut declared: Vec<(String, String)> = Vec::new();
    for (path, text) in walk_sources_with_paths() {
        let module = module_path_of(&path);
        declared.extend(
            declared_tests(&text)
                .into_iter()
                .map(|name| (module.clone(), name.to_string())),
        );
    }

    let mut missing = Vec::new();
    for (file, path) in test_paths_named_by_ci() {
        let leaf = path.rsplit("::").next().unwrap_or_default();
        // The filter's module half: everything before the leaf, with `tests` segments dropped.
        let named: Vec<&str> = path
            .split("::")
            .take(path.split("::").count().saturating_sub(1))
            .filter(|seg| *seg != "tests")
            .collect();
        let hit = declared.iter().any(|(module, name)| {
            name == leaf && {
                let have: Vec<&str> = module
                    .split("::")
                    .filter(|s| !s.is_empty() && *s != "tests")
                    .collect();
                // The filter may name the module from any depth (`cgroup::tests::x` and
                // `sandbox::cgroup::tests::x` both reach it), so a suffix match is the question.
                named.is_empty() || have.ends_with(&named[..])
            }
        });
        if !hit {
            let where_it_is: Vec<String> = declared
                .iter()
                .filter(|(_, name)| name == leaf)
                .map(|(module, name)| match module.ends_with("tests") {
                    true => format!("{module}::{name}"),
                    false => format!("{module}::tests::{name}"),
                })
                .collect();
            missing.push(match where_it_is.as_slice() {
                [] => format!("  {file} names `{path}`, and no test is called `{leaf}`"),
                found => format!(
                    "  {file} names `{path}`, but that test is at {}",
                    found.join(", ")
                ),
            });
        }
    }
    assert!(
        missing.is_empty(),
        "a CI file filters on a test that does not exist, so the filter excludes nothing:\n{}",
        missing.join("\n")
    );
}

/// The names of the tests `text` declares: each `fn` a `#[test]` line stands over, past the other
/// attributes, comments and blank lines between them. A filter that names a function no attribute
/// makes a test excludes nothing, so a helper of that name answers nothing here, and neither does
/// `fn ` met in a comment or in a string on one line. A `proptest!` block writes its `#[test]` the
/// same way. The scan reads lines, not tokens: a string spanning lines, one reading `#[test]` and a
/// later one `fn x(`, would declare `x`.
fn declared_tests(text: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut marked = false;
    for line in text.lines() {
        let code = line.trim();
        if code == "#[test]" {
            marked = true;
        } else if code.is_empty() || code.starts_with("#[") || code.starts_with("//") {
            continue;
        } else {
            if marked && let Some(name) = declared_fn(code) {
                names.push(name);
            }
            marked = false;
        }
    }
    names
}

/// The name of the function `code`, one line of source, declares, past its visibility and its
/// qualifiers; `None` when the line declares none.
fn declared_fn(code: &str) -> Option<&str> {
    // A restricted visibility first, whole: `pub(in crate::x)` holds a space of its own.
    let mut rest = match code.strip_prefix("pub(") {
        Some(scope) => scope.split_once(')')?.1.trim_start(),
        None => code,
    };
    loop {
        rest = match rest.split_once(' ') {
            Some((word, after))
                if word.starts_with("pub")
                    || ["const", "async", "unsafe", "extern", "\"C\""].contains(&word) =>
            {
                after
            }
            _ => break,
        };
    }
    let rest = rest.strip_prefix("fn ")?;
    let end = rest.find(['(', '<'])?;
    Some(&rest[..end])
}

/// Only a function a `#[test]` line stands over is a test the filters can name, whatever lies
/// between the two, and `fn ` in a comment or a string declares nothing.
#[test]
fn only_a_function_a_test_attribute_stands_over_is_a_test() {
    // One line of source per line of text, so that this module's own scan reads no test in it.
    let text = [
        "/// Calls `fn ghost()`.",
        "fn helper() {}",
        "const S: &str = \"fn quoted() {}\";",
        "#[test]",
        "fn plain() {}",
        "",
        "#[test]",
        "#[ignore = \"run by hand\"]",
        "/// A measurement.",
        "pub(crate) async fn qualified<T>() {}",
        "    #[test]",
        "    fn in_a_block(a in 0u8..) {}",
        "#[test]",
        "pub(in crate::sandbox) unsafe fn scoped() {}",
        "// fn other(",
    ]
    .join("\n");
    assert_eq!(
        declared_tests(&text),
        ["plain", "qualified", "in_a_block", "scoped"]
    );
}

/// The module path a source file spells, as a filter would write it: its path under `src/` with
/// the extension dropped, `mod.rs` naming the directory it sits in, and separators as `::`. A file
/// under `tests/` is its own integration crate and has no module path, so it answers empty and any
/// filter naming it matches on the leaf alone.
fn module_path_of(path: &Path) -> String {
    let Ok(rel) = path.strip_prefix(root().join("src")) else {
        return String::new();
    };
    let mut parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    match parts.pop() {
        Some(last) => {
            let stem = last.trim_end_matches(".rs");
            if stem != "mod" && stem != "main" {
                parts.push(stem.to_string());
            }
        }
        None => return String::new(),
    }
    parts.join("::")
}

/// Every `.rs` file under `src/` and `tests/`, with its path.
fn walk_sources_with_paths() -> Vec<(PathBuf, String)> {
    ["src", "tests"]
        .iter()
        .flat_map(|dir| files_under(&root().join(dir), &["rs"]))
        .filter_map(|path| Some((path.clone(), read_listed(&path)?)))
        .collect()
}

/// A directory or a file these guards cannot read fails them by its name, rather than leaving them
/// to pass on the part of the tree they read.
#[test]
fn what_the_walk_cannot_read_fails_it_by_name() {
    use std::os::unix::fs::PermissionsExt;
    // Root reads either regardless of its mode.
    // SAFETY: `geteuid` takes no argument and only reads this process's effective uid.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tmp = crate::testutil::TmpDir::new();
    let shut = tmp.join("shut");
    std::fs::create_dir(&shut).unwrap();
    let sealed = tmp.join("sealed.rs");
    std::fs::write(&sealed, "").unwrap();
    for path in [&shut, &sealed] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let message = |outcome: std::thread::Result<()>| -> String {
        let payload = outcome.expect_err("an unreadable entry must fail the walk");
        payload
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default()
    };
    let dir = tmp.path().to_path_buf();
    let walked = std::panic::catch_unwind(|| drop(files_under(&dir, &["rs"])));
    let read = std::panic::catch_unwind(|| drop(read_listed(&sealed)));
    // Given back before anything is asserted, so a failing run leaves a fixture it can remove.
    for path in [&shut, &sealed] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let (walked, read) = (message(walked), message(read));
    assert!(
        walked.contains(&format!("`{}` cannot be read", shut.display())),
        "{walked}"
    );
    assert!(
        read.contains(&format!("`{}` cannot be read", sealed.display())),
        "{read}"
    );
    assert_eq!(
        read_listed(&tmp.join("gone.rs")),
        None,
        "a file gone since it was listed is no failure"
    );
}

/// A link back up the tree is not followed: the walk lists each file once and ends.
#[test]
fn the_walk_does_not_follow_a_link_back_up_the_tree() {
    let tmp = crate::testutil::TmpDir::new();
    std::fs::write(tmp.join("f.rs"), "").unwrap();
    for name in ["up", "again"] {
        std::os::unix::fs::symlink(".", tmp.join(name)).unwrap();
    }
    let dir = tmp.path().to_path_buf();
    let found = crate::testutil::returns_within(
        std::time::Duration::from_secs(15),
        "a walk of a tree with two links back up it",
        move || files_under(&dir, &["rs"]),
    );
    assert_eq!(found, [tmp.join("f.rs")]);
}

#[test]
fn both_cage_runs_name_every_suite_that_carries_a_cage_skip() {
    // Both lists are pinned to the same set in both directions, which is also what makes them
    // equal to each other: a separate "the two runs agree" test was written here and removed, having
    // no state in which it could fail while this one passed. A test that cannot go red on its own is
    // not a second guarantee, it is a second thing to read.
    let expected = suites_carrying_a_cage_skip();
    for run in [".github/workflows/cage.yml", "mise.toml"] {
        let named = named_suites(run);
        let missing: Vec<_> = expected.difference(&named).cloned().collect();
        let extra: Vec<_> = named.difference(&expected).cloned().collect();
        assert!(
            missing.is_empty(),
            "{run} does not name {missing:?}, which carry a host-capability skip and so are \
             exactly the suites a hosted runner passes without running. Add them to its list."
        );
        assert!(
            extra.is_empty(),
            "{run} names {extra:?}, which carry no `skip_incapable!` and no `probe_or_skip!`. \
             Either the suite lost its skip and the name should go, or the skip was spelled \
             `skip_unreachable!`, which no runner setting can satisfy."
        );
    }
}
