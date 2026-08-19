//! Test-only helpers shared across the module unit tests.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Held for the whole body of any test that pins an environment variable.
///
/// The environment is one slot shared by every thread of the test binary, and the tests run
/// in parallel: `setenv` may reallocate `environ` while another thread is inside `getenv`.
/// One lock for the whole binary — not one per module — is what makes that impossible, and
/// what makes the `unsafe` in [`EnvVar`] sound.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Take [`ENV_LOCK`]. A test that panicked while holding it poisons the mutex, but the
/// poison flag says nothing about the environment: [`EnvVar`] restores every variable on
/// the way out of that panic, so the next test takes the lock over a clean environment.
pub(crate) fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// One environment variable pinned for the length of a test and put back exactly as it was
/// on the way out — including when the way out is a panic. A variable left set would decide
/// what every later test in the binary reads, and a test that restores only on success
/// leaves it set precisely when something went wrong.
///
/// The caller holds [`env_lock`] for a scope that outlives the guard.
pub(crate) struct EnvVar {
    key: &'static str,
    prior: Option<OsString>,
}

impl EnvVar {
    /// Pin `key` to `value` until the guard is dropped.
    pub(crate) fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let guard = Self {
            key,
            prior: std::env::var_os(key),
        };
        // SAFETY: the caller holds `ENV_LOCK` for a scope that outlives this guard, so no
        // other thread of this binary reads or writes the environment meanwhile.
        unsafe { std::env::set_var(key, value) };
        guard
    }

    /// Pin `key` to *unset* until the guard is dropped — what a test asserting the absent
    /// case needs, since the variable may be set in the environment the run inherited.
    pub(crate) fn unset(key: &'static str) -> Self {
        let guard = Self {
            key,
            prior: std::env::var_os(key),
        };
        // SAFETY: as in `set`.
        unsafe { std::env::remove_var(key) };
        guard
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        // SAFETY: as in `set` — the lock is held until after this guard is dropped.
        unsafe {
            match self.prior.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Where throwaway fixtures are rooted, overridable with `SBX_TEST_TMPDIR` — the same variable the
/// twenty integration suites already read, so one setting moves every fixture in the repository
/// rather than the ones that happened to be written last.
///
/// Deliberately not the system tmpfs. A test that provisions a nix store copies the entire nixpkgs
/// source tree into it, a very large file count, and several such tests running concurrently would
/// exhaust a tmpfs's fixed inode budget (`ENOSPC`, even with bytes to spare) while disk has inodes
/// in abundance. It also matches production, where the store lives on disk under the data
/// directory, never on a tmpfs.
///
/// The default keeps it under `target/`, out of the way and reclaimable by `cargo clean`. That
/// default has a cost worth knowing before choosing it: the tree is inside the workspace, one
/// suite leaves hundreds of thousands of directories there, and a language server that watches the
/// workspace spends one inotify watch per directory until the machine's `max_user_watches` is
/// gone — which then breaks systemd's own cgroup watches, so a cage scope never learns it emptied.
/// No analyzer setting avoids this: `files.exclude` bounds what is *analysed*, not what is
/// *watched*, whether it arrives from a workspace file or from the client. Pointing this variable
/// outside the workspace is what actually avoids it, and `mise run test` does so.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

/// A unique temp directory that removes itself on drop, so tests leave nothing
/// behind (cleanup runs on panic-unwind too, not just on success).
pub(crate) struct TmpDir(PathBuf);

impl TmpDir {
    pub(crate) fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("sbx-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories — a provisioned nix store
/// makes its directories `0555`, so a plain `remove_dir_all` cannot delete their
/// contents. Add write to each directory on the way down, then remove. Best
/// effort: cleanup never fails a test.
pub(crate) fn force_remove(path: &Path) {
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

/// A sorted `(relative path, size)` fingerprint of a tree — sensitive to any
/// addition, removal, or size change, enough to assert a store never moved.
pub(crate) fn fingerprint(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = path.symlink_metadata() else {
                continue;
            };
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if meta.is_dir() {
                out.push((rel, 0));
                stack.push(path);
            } else {
                out.push((rel, meta.len()));
            }
        }
    }
    out.sort();
    out
}

/// A baseline [`crate::config::Resolved`] carrying nothing but the packages and apps a test cares
/// about, every other field at its quietest value. Config resolution has a wide struct and a test
/// that spells all of it out says nothing about what it is testing; this keeps each test's fixture
/// to the two lines that matter. Reach for it whenever a test needs a config to hand to production
/// code rather than a config to assert about.
pub(crate) fn resolved(
    packages: Vec<crate::config::Package>,
    apps: Vec<(&str, crate::config::ResolvedApp)>,
) -> crate::config::Resolved {
    crate::config::Resolved {
        timezone: None,
        timezone_origin: crate::config::Provenance::Default,
        open: Default::default(),
        service: Default::default(),
        provisions: Default::default(),
        plugin: Default::default(),
        net_groups: Default::default(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
        notify: Default::default(),
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        env: vec![],
        env_layer: Default::default(),
        binds: vec![],
        bind_layer: Default::default(),
        packages,
        nixpkgs_global: None,
        nixpkgs_project: None,
        mise: None,
        network: crate::config::NetworkPolicy::Shared,
        network_origin: Default::default(),
        egress_stats: true,
        redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
        redact_min_len_origin: Default::default(),
        gui: crate::config::GuiPolicy::default(),
        gui_origin: Default::default(),
        proc: Default::default(),
        proc_origin: Default::default(),
        gpu: false,
        audio: false,
        dbus: false,
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
        forward_origin: Default::default(),
        limits: Default::default(),
        limits_origin: Default::default(),
        secrets: vec![],
        tasks: vec![],
        seccomp: Default::default(),
        seccomp_origin: Default::default(),
        devices: Vec::new(),
        devices_origin: Default::default(),
        ssh_agent: vec![],
        brokers: Vec::new(),
        ssh_agent_origin: Default::default(),
        declared_secrets: vec![],
        apps: apps.into_iter().map(|(n, a)| (n.to_string(), a)).collect(),
        warnings: vec![],
    }
}

/// An app overlay declaring only `packages`, for a test that asserts how the baseline and an app's
/// own layer combine. `cmd` is a placeholder -- the overlay is never launched.
pub(crate) fn app_with(packages: Vec<crate::config::Package>) -> crate::config::ResolvedApp {
    crate::config::ResolvedApp {
        provisions: Vec::new(),
        open: Default::default(),
        service: Default::default(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        cmd: vec!["x".into()],
        home_scope: crate::config::AppHomeScope::Global,
        env: vec![],
        binds: vec![],
        packages,
        network: None,
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        forward: vec![],
        secrets: vec![],
        tasks: vec![],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward_origin: Default::default(),
        limits_origin: Default::default(),
        seccomp: Default::default(),
        seccomp_origin: Default::default(),
        devices: Vec::new(),
        devices_origin: Default::default(),
        proc: None,
        proc_origin: Default::default(),
        home_scope_origin: None,
        warnings: vec![],
    }
}

#[cfg(test)]
mod skip_macro_tests {
    use super::{EnvVar, TmpDir, env_lock};

    /// The three promises of the skip macros, asserted together because they are one contract: a
    /// skip is **recorded** so a run can report it, a host skip **fails** where the host was
    /// declared capable, and a remote skip never does — no setting on this machine makes a binary
    /// cache reachable, so enforcing it would only teach people to unset the flag.
    #[test]
    fn a_skip_is_recorded_and_only_a_host_skip_is_enforced() {
        let _lock = env_lock();
        let tmp = TmpDir::new();
        let log = tmp.join("skips");
        let _log_var = EnvVar::set("SBX_SKIP_LOG", &log);
        let read = || std::fs::read_to_string(&log).unwrap_or_default();

        // Unset: both skip quietly, and both leave a line behind.
        let _off = EnvVar::unset("SBX_REQUIRE_CAPABLE");
        skip_incapable!("skipping a: need {}", "bwrap");
        skip_unreachable!("skipping b: the cache is unreachable");
        assert_eq!(
            read(),
            "skipping a: need bwrap\nskipping b: the cache is unreachable\n"
        );

        // `0` is how a caller says "no", and it must not read as "set".
        let _zero = EnvVar::set("SBX_REQUIRE_CAPABLE", "0");
        skip_incapable!("skipping c");
        assert!(
            read().ends_with("skipping c\n"),
            "a skip under `=0` was not recorded"
        );

        // Set: the host was supposed to manage, so a host skip is a failure — and the panic names
        // the reason, which is the whole point of failing rather than returning.
        let _on = EnvVar::set("SBX_REQUIRE_CAPABLE", "1");
        let err = std::panic::catch_unwind(|| skip_incapable!("skipping d: need nix")).unwrap_err();
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap_or_default();
        assert!(
            msg.contains("skipping d: need nix"),
            "the panic did not name the reason: {msg}"
        );

        // A remote is not a host capability: still recorded, still not a failure.
        skip_unreachable!("skipping e: the registry is down");
        assert!(read().ends_with("skipping e: the registry is down\n"));
    }
}

/// `nix-instantiate`, when this host can run it: the resolved `nix` has a sibling by that name.
/// `None` is the caller's cue to `skip_incapable!`, so a run that skipped the check says so
/// instead of reporting a guard that did nothing.
pub(crate) fn nix_instantiate() -> Option<PathBuf> {
    let instantiate = crate::store::resolve_nix(None)?.with_file_name("nix-instantiate");
    instantiate.exists().then_some(instantiate)
}

/// Ask nix whether `expr` is an expression at all, and fail with nix's own error beside the text
/// when it is not. `emitter` names what produced it.
///
/// Every expression sbx hands to nix is built by substituting into a template, and what the tests
/// around those templates assert is `contains` on the pieces -- which a missing `;`, an unbalanced
/// indented-string delimiter, or an interpolation opened and not closed all leave in place. This is
/// the question none of them asks, and the emitters share it, so it is defined once here.
///
/// `--parse` is the right depth: it answers "is this an expression?" without fetching the pinned
/// nixpkgs or building anything, so it needs no network and costs milliseconds.
pub(crate) fn assert_nix_parses(instantiate: &Path, emitter: &str, expr: &str) {
    let out = std::process::Command::new(instantiate)
        .args(["--parse", "-E", expr])
        .output()
        .expect("nix-instantiate runs");
    assert!(
        out.status.success(),
        "`{emitter}` emits an expression nix rejects:\n{}\n--- expression ---\n{expr}",
        String::from_utf8_lossy(&out.stderr),
    );
}

/// A skip must promise only what it can keep: an off-host condition is counted, never enforced.
///
/// The enforceable macro is the one `SBX_REQUIRE_CAPABLE` turns into a failure, and `mise run
/// test-cage` sets exactly that over the suites meant to prove the cage ran. A site that spells an
/// **off-host** reason with it hands that lever a condition no host setting can make dependable: a
/// network hiccup then reads as "this host cannot sandbox", which is the single distinction the
/// task exists to make.
///
/// The exception is real and stays mechanical: a reason may name an off-host condition when it also
/// names the host capability, because several sites fail for either and say so ("host cannot
/// sandbox (no userns/bwrap, or the base cache is unreachable)"). Those are enforceable on their
/// host half, so they keep the enforceable macro.
#[test]
fn an_off_host_skip_is_never_written_with_the_enforceable_macro() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Built at runtime, so this file does not match its own needle.
    let needle = format!("skip_{}!(", "incapable");
    const OFF_HOST: [&str; 3] = ["is unreachable", "download fault", "flake upstream"];
    const HOST: &str = "cannot sandbox";
    let mut offenders = Vec::new();
    let mut scanned = 0;
    let mut stack = vec![root.join("src"), root.join("tests")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("read a source directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read a source file");
            let mut from = 0;
            while let Some(at) = text[from..].find(&needle) {
                let call = from + at + needle.len();
                from = call;
                // The reason is the first string literal of the call, which rustfmt may have put on
                // the next line. Read it raw: an escaped quote inside it would end it early, and a
                // reason that quotes a command's own error is exactly where that happens.
                let Some(open) = text[call..].find('"') else {
                    continue;
                };
                let start = call + open + 1;
                let mut end = start;
                let bytes = text.as_bytes();
                while end < bytes.len() && (bytes[end] != b'"' || bytes[end - 1] == b'\\') {
                    end += 1;
                }
                let reason = &text[start..end.min(text.len())];
                scanned += 1;
                if OFF_HOST.iter().any(|o| reason.contains(o)) && !reason.contains(HOST) {
                    let rel = path.strip_prefix(root).unwrap_or(&path).display();
                    let line = text[..start].lines().count();
                    offenders.push(format!("{rel}:{line}: {reason}"));
                }
            }
        }
    }
    // The sweep is worth nothing if it found nothing to read, which a moved macro or a renamed
    // directory would produce in silence.
    assert!(
        scanned > 50,
        "the sweep read only {scanned} enforceable skips: it is looking in the wrong place"
    );
    assert!(
        offenders.is_empty(),
        "these skips name a condition outside the host, so they must not be enforceable \
         (use the counted macro instead):\n{}",
        offenders.join("\n")
    );
}

/// No test may give up in silence: a skip has to go through the macros, never through a bare
/// print.
///
/// A hand-written `eprintln!` plus `return` is what the harness counts as a pass and what it then
/// swallows, so a suite can report green for work it never did. The macros make that skip a
/// recorded event and, for a host capability, an enforceable one. This sweep is what keeps the
/// next one from being written by hand again.
///
/// What it cannot catch, and the limit is real: a test that returns early with **no message at
/// all** is invisible to any grep. This guards the shape that exists, not the shape nobody has
/// written yet.
#[test]
fn no_test_gives_up_through_a_bare_print() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Built at runtime, so this file does not match its own needle.
    let needles: Vec<String> = ["eprintln!", "println!"]
        .iter()
        .map(|m| format!("{m}(\"skipping"))
        .collect();
    let mut offenders = Vec::new();
    let mut macro_uses = 0;
    let mut files = 0;
    let mut stack = vec![root.join("src"), root.join("tests")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("read a source directory")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read a source file");
            files += 1;
            macro_uses += text.matches("skip_incapable!(").count();
            macro_uses += text.matches("skip_unreachable!(").count();
            for (n, line) in text.lines().enumerate() {
                if needles.iter().any(|needle| line.contains(needle.as_str())) {
                    let rel = path.strip_prefix(root).unwrap_or(&path).display();
                    offenders.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these tests skip through a bare print, so the harness counts them passed and hides the \
         message: {offenders:?} — use `skip_incapable!` (the host lacks something) or \
         `skip_unreachable!` (a remote does), from `src/testskip.rs`"
    );
    // The preconditions, asserted rather than assumed: a sweep that read nothing, or a tree that
    // stopped skipping altogether, would pass while guarding nothing.
    assert!(files > 100, "the sweep read only {files} source files");
    assert!(
        macro_uses > 100,
        "only {macro_uses} skip macro uses — has the sweep gone stale?"
    );
}
