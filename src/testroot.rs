// The one definition of where a test's fixtures are created, shared by the unit tests and the
// integration tests.
//
// The root is OUTSIDE the workspace by default, and that is the property rather than an accident: a
// language server watching the repository spends one inotify watch per directory, one run of the
// cage suites leaves hundreds of thousands of them, and the machine's `max_user_watches` is what
// runs out. What breaks then is not the language server: systemd loses the cgroup watches a
// transient scope needs to learn its cage emptied, so the scope is never collected. The root stays
// on disk rather than on a tmpfs, whose fixed inode budget a provisioned nix store exhausts, and
// falls back inside the workspace only when neither variable names a home to use.
//
// `SBX_TEST_TMPDIR` moves it. What a killed run leaves behind is reclaimed by `sweep_in`, which
// every test binary runs once on its way to the root: a `TmpDir` removes itself on drop, including
// on a panic-unwind, but a run that is killed outright never reaches either, and the cage suites
// leave a provisioned nix store per fixture. `mise run clean-fixtures` applies the same rule from
// a shell, for the case where no test is going to run and the disk is wanted back now. Neither goes
// near a plain `rm -rf`: it walks into a store's `0555` directories and leaves most of the tree
// behind, which is why both add write on the way down.
//
// This file is **included**, not linked: the integration tests are separate crates and cannot see
// into the binary, so `src/testutil.rs` and each suite under `tests/` `include!` this text, the same
// way both halves take `src/testskip.rs`. One definition, many compilations. A copy per suite drifts
// the moment the root has to move, and a root that means two different places is worse than one
// nobody can change.

/// The directory under which every fixture tree is created.
///
/// Keep the per-fixture tag a caller appends to this short: a launch's egress proxy binds a Unix
/// socket under the data dir, and `sun_path` caps the whole path at 108 bytes, most of which this
/// tree already spends.
fn fixture_root() -> std::path::PathBuf {
    let root = fixture_root_path();
    // Once per module that includes this text, which is up to three times in a suite that also
    // pulls in the shared `common` module: the sweep is idempotent and costs one `read_dir` each,
    // so the repetition is left rather than coordinated across modules that cannot see each other.
    //
    // Reached from here because a test binary has no entry point of its own to hang it on, and
    // every fixture goes through this function. It runs before the caller creates its own
    // directory, so the run doing the sweeping never offers itself up to it.
    static SWEPT: std::sync::Once = std::sync::Once::new();
    SWEPT.call_once(|| sweep_in(&root, std::path::Path::new("/proc")));
    root
}

/// The root itself, with no sweep — what [`fixture_root`] resolves and what the sweep is handed.
fn fixture_root_path() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return std::path::PathBuf::from(dir);
    }
    let mut d = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    d.push("sbx/test-tmp");
    d
}

/// The pid a fixture directory's name encodes, or `None` when `name` is not a fixture's.
///
/// Both spellings end the same way — `<tag>-<pid>-<n>` and `sbx-test-<pid>-<n>` — and a tag may
/// itself carry dashes and digits, so the shape is read from the end: the last two segments must
/// both be numbers, and the pid is the one before the counter. That is what keeps the sweep off
/// `isolated-config` and off anything else a developer parked under the root.
fn fixture_owner_pid(name: &str) -> Option<u32> {
    let (rest, counter) = name.rsplit_once('-')?;
    counter.parse::<u32>().ok()?;
    rest.rsplit_once('-')?.1.parse().ok()
}

/// Remove the fixture trees left by runs that are gone, under `root`, deciding liveness from
/// `proc_root`.
///
/// A pid reads live when its `/proc` entry is there, and a live pid keeps its fixture. Every way
/// that answer can be wrong keeps a tree that could have gone: an entry that belongs to another
/// user, or to a process that has reused the pid, still reads live. That is the direction this has
/// to fail in, since the alternative is deleting the fixtures of a run in progress — and there is
/// always one, because a suite's own binaries run alongside each other.
///
/// There is deliberately no age fallback for the reused-pid case. It defers a reclaim rather than
/// losing one: this runs afresh at the start of every test binary, so the tree goes as soon as any
/// run starts after the process that borrowed the pid has exited. An age threshold would buy
/// nothing and would put a long run's fixtures at risk.
///
/// Silent, like the scope sweep: a test binary's output belongs to its tests.
fn sweep_in(root: &std::path::Path, proc_root: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(fixture_owner_pid)
        else {
            continue;
        };
        if proc_root.join(pid.to_string()).exists() {
            continue;
        }
        force_remove(&entry.path());
    }
}

/// Remove a tree that may contain read-only directories — a provisioned nix store makes its
/// directories `0555`, so a plain `remove_dir_all` cannot delete their contents. Add write to each
/// directory on the way down, then remove. Best effort: cleanup never fails a test.
fn force_remove(path: &std::path::Path) {
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
