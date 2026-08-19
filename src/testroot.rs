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
// `SBX_TEST_TMPDIR` moves it. Reclaim what a killed run left with
// `chmod -R u+w "$dir" && rm -rf "$dir"`: a bare `rm -rf` walks into a store's `0555` directories
// and leaves most of the tree behind.
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
