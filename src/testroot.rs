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
    fixture_root_from(|key| std::env::var_os(key))
}

/// [`fixture_root_path`] with the environment handed in, so the reading of each variable can be
/// pinned without setting one under the tests that are creating fixtures from it.
///
/// An empty variable reads as unset, the way the `${VAR:-…}` of `mise run clean-fixtures` reads
/// it, and a relative `XDG_CACHE_HOME` is ignored, as the XDG base-directory specification says.
/// Either one taken as written would put the root, and the sweep, somewhere that depends on the
/// directory a test binary happens to start in.
fn fixture_root_from(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> std::path::PathBuf {
    let set = |key: &str| var(key).filter(|value| !value.is_empty());
    if let Some(dir) = set("SBX_TEST_TMPDIR") {
        return std::path::PathBuf::from(dir);
    }
    let mut d = set("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .or_else(|| set("HOME").map(|h| std::path::PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    d.push("sbx/test-tmp");
    d
}

/// The pid a fixture directory's name encodes, or `None` when `name` is not a fixture's.
///
/// Both spellings end the same way — `<tag>-<pid>-<n>` and `sbx-test-<pid>-<n>` — and a tag may
/// itself carry dashes and digits, so the shape is read from the end: the last two segments must
/// both be numbers, and the pid is the one before the counter. That is what keeps the sweep off
/// `isolated-config`, and off any name that does not end in two numbers. A directory parked under
/// the root whose name does — `backup-2024-06` — reads as a fixture of pid 2024 and goes once no
/// such process runs: the root belongs to the suites, and is no place to keep anything.
fn fixture_owner_pid(name: &str) -> Option<u32> {
    let (rest, counter) = name.rsplit_once('-')?;
    counter.parse::<u32>().ok()?;
    rest.rsplit_once('-')?.1.parse().ok()
}

/// Remove the fixture trees left by runs that are gone, under `root`, deciding liveness from
/// `proc_root`.
///
/// A pid reads live unless its `/proc` entry is definitely absent, and a live pid keeps its
/// fixture. Every way that answer can be wrong keeps a tree that could have gone: an entry that
/// belongs to another user, to a process that has reused the pid, or whose lookup fails with
/// anything but `ENOENT`, still reads live — and a `proc_root` that is no `/proc`, because
/// it has no `self`, decides nothing and takes nothing. That is the direction this has to fail in,
/// since the alternative is deleting the fixtures of a run in progress — and there is always one,
/// because a suite's own binaries run alongside each other.
///
/// There is deliberately no age fallback for the reused-pid case. It defers a reclaim rather than
/// losing one: this runs afresh at the start of every test binary, so the tree goes as soon as any
/// run starts after the process that borrowed the pid has exited. An age threshold would buy
/// nothing and would put a long run's fixtures at risk.
///
/// Silent, like the scope sweep: a test binary's output belongs to its tests.
fn sweep_in(root: &std::path::Path, proc_root: &std::path::Path) {
    if std::fs::symlink_metadata(proc_root.join("self")).is_err() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(fixture_owner_pid) else {
            continue;
        };
        if !run_is_gone(proc_root, pid) {
            continue;
        }
        force_remove(&entry.path());
    }
}

/// Whether `pid` has no entry under `proc_root` — definitely none, not merely none that reads.
///
/// `exists` answers false on any error, so an entry this process may not look at would read as a
/// run that is gone. Only `ENOENT` says so here.
fn run_is_gone(proc_root: &std::path::Path, pid: u32) -> bool {
    matches!(
        std::fs::symlink_metadata(proc_root.join(pid.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound
    )
}

/// How many directory levels [`force_remove`] descends. Far past any tree a fixture holds, and
/// short enough that the recursion cannot run a test thread out of stack whatever lies below.
const REMOVE_DEPTH: u32 = 256;

/// Remove a tree that may contain read-only directories — a provisioned nix store makes its
/// directories `0555`, so a plain `remove_dir_all` cannot delete their contents. Add write to each
/// directory on the way down, then remove. Best effort: cleanup never fails a test.
///
/// A symlink is unlinked, never followed, including one swapped in for a directory while the walk
/// is under way: each entry is opened `O_PATH | O_NOFOLLOW | O_DIRECTORY`, and what does not open
/// that way is unlinked as a file. A directory is made writable and listed through
/// `/proc/self/fd/<n>`, which names the inode the handle holds rather than a path a link could be
/// planted on, and its entries are reached through that same name. Below [`REMOVE_DEPTH`] levels
/// the tree is left in place.
fn force_remove(path: &std::path::Path) {
    force_remove_within(path, REMOVE_DEPTH);
}

/// Create the fixture directory `d` empty, taking out whatever a leftover of the same name holds.
///
/// A fixture is named after the pid of the run that made it, and the sweep spares every live
/// pid's fixtures, this run's included. A run killed without its cleanup leaves its directories
/// behind, and a later run handed the same pid would otherwise adopt one with whatever it still
/// holds. A directory found under this run's own name is such a leftover — every live one of that
/// name is this run's — and is removed before the fixture is made afresh.
///
/// Allowed to go unused: a suite that includes this text for the root alone makes no fixture of
/// its own.
#[allow(dead_code)]
fn create_afresh(d: &std::path::Path) {
    if let Err(e) = std::fs::create_dir(d) {
        assert_eq!(
            e.kind(),
            std::io::ErrorKind::AlreadyExists,
            "the fixture {}: {e}",
            d.display()
        );
        force_remove(d);
        std::fs::create_dir(d).unwrap_or_else(|e| panic!("the fixture {}: {e}", d.display()));
    }
}

/// [`force_remove`], descending at most `depth` more levels.
fn force_remove_within(path: &std::path::Path, depth: u32) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt;
    // Through `libc::open` rather than `OpenOptions::custom_flags`, which masks `O_PATH` away under
    // musl (it folds the flag into `O_ACCMODE`), the target the binary ships as.
    let fd = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_or(-1, |c| {
        // SAFETY: `c` is a live NUL-terminated path for the duration of the call.
        unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        }
    });
    if fd < 0 {
        let _ = std::fs::remove_file(path);
        return;
    }
    // SAFETY: `fd` was just returned by open(2), and nothing else holds it.
    let dir = unsafe { OwnedFd::from_raw_fd(fd) };
    if let Some(depth) = depth.checked_sub(1) {
        let held = std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        // Through the descriptor's own entry, which acts on the inode it holds: `fchmod` refuses
        // an `O_PATH` handle, and the handle is `O_PATH` so a `0000` directory still opens.
        let _ = std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(&held) {
            for entry in entries.flatten() {
                force_remove_within(&held.join(entry.file_name()), depth);
            }
        }
    }
    let _ = std::fs::remove_dir(path);
}
