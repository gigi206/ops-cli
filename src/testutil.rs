//! Test-only helpers shared across the module unit tests.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Held for the whole body of any test that pins an environment variable.
///
/// The environment is one slot shared by every thread of the test binary, and the tests run
/// in parallel: `setenv` may reallocate `environ` while another thread is inside `getenv`.
///
/// One lock for the whole binary — not one per module — is what makes that impossible, and
/// what makes the `unsafe` in [`EnvVar`] sound.
static ENV_LOCK: Mutex<()> = Mutex::new(());

std::thread_local! {
    /// How many [`EnvLock`]s this thread holds: what lets [`EnvVar`] check its caller holds one.
    static ENV_LOCKS_HELD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// [`ENV_LOCK`] held by this thread, as [`env_lock`] hands it out.
pub(crate) struct EnvLock {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for EnvLock {
    fn drop(&mut self) {
        ENV_LOCKS_HELD.with(|held| held.set(held.get() - 1));
    }
}

/// Take [`ENV_LOCK`]. A test that panicked while holding it poisons the mutex, but the
/// poison flag says nothing about the environment: [`EnvVar`] restores every variable on
/// the way out of that panic, so the next test takes the lock over a clean environment.
pub(crate) fn env_lock() -> EnvLock {
    let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    ENV_LOCKS_HELD.with(|held| held.set(held.get() + 1));
    EnvLock { _guard: guard }
}

/// Refuse to touch the environment from a thread that does not hold [`ENV_LOCK`]: the
/// `unsafe` in [`EnvVar`] is sound only under it, and a test that forgot it races every other.
fn assert_env_locked(key: &str) {
    assert!(
        ENV_LOCKS_HELD.with(std::cell::Cell::get) > 0,
        "`{key}` pinned without `env_lock()` held on this thread"
    );
}

/// One environment variable pinned for the length of a test and put back exactly as it was
/// on the way out — including when the way out is a panic. A variable left set would decide
/// what every later test in the binary reads, and a test that restores only on success
/// leaves it set precisely when something went wrong.
///
/// The caller holds [`env_lock`] for a scope that outlives the guard, on the thread that makes it;
/// one made without is refused.
pub(crate) struct EnvVar {
    key: &'static str,
    prior: Option<OsString>,
}

impl EnvVar {
    /// Pin `key` to `value` until the guard is dropped.
    pub(crate) fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        assert_env_locked(key);
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
        assert_env_locked(key);
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

// The fixtures' root, one definition shared with the integration suites.
include!("testroot.rs");

// A fixture path as a `file://` URL, one definition shared with the integration suites.
include!("testurl.rs");

/// A unique temp directory that removes itself on drop, so tests leave nothing
/// behind (cleanup runs on panic-unwind too, not just on success).
pub(crate) struct TmpDir(PathBuf);

impl TmpDir {
    /// A directory no other fixture has, created empty.
    ///
    /// Created exclusively, since the name alone does not make it unique: a run that ended
    /// without its cleanup leaves its directories behind, and a later run handed the same pid
    /// would otherwise adopt one with whatever it still holds. A directory found under this
    /// run's own name is such a leftover — every live one of this name is this run's — and is
    /// removed before the fixture is made afresh.
    pub(crate) fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = fixture_root();
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|e| panic!("the fixtures' root {}: {e}", root.display()));
        let d = root.join(format!("sbx-test-{}-{n}", std::process::id()));
        create_afresh(&d);
        TmpDir(d)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// `name` inside the fixture. A name that is absolute, or climbs out with `..`, would land
    /// outside it, where nothing removes what the test writes, so it is refused.
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        assert!(
            Path::new(name)
                .components()
                .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
            "`{name}` is not a path inside the fixture"
        );
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Run `attempt` until it stops failing with `ETXTBSY`, then hand back what it produced.
///
/// Writing an executable and then running it is racy in a multi-threaded process, and a test binary
/// is one: while the write descriptor is open, whatever another thread forks in that instant
/// inherits it, and the kernel refuses to exec a file some process holds open for writing. The
/// descriptor is close-on-exec, so the window shuts by itself the moment that other child execs,
/// which is why waiting is the whole fix. Nothing a session does has this shape, so the retry
/// belongs to the tests rather than to what they exercise.
///
/// The `sops` tests in [`crate::sandbox::egress`] and the store clone's in `plugins::stores` wait
/// the same race out on their own, because the call they retry returns the spawn failure as a
/// message rather than an `io::Error` of its own. Those are not routed through here.
fn past_etxtbsy<T>(what: &str, attempt: impl FnMut() -> std::io::Result<T>) -> T {
    result_past_etxtbsy(what, attempt).unwrap_or_else(|e| panic!("{what}: {e}"))
}

/// Run `attempt` until it stops failing with `ETXTBSY`, and hand back what it then returned, a
/// failure included: for a test whose subject is how a program's failure is reported.
pub(crate) fn result_past_etxtbsy<T>(
    what: &str,
    mut attempt: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    for _ in 0..100 {
        match attempt() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
    panic!("{what}: the file stayed held open for writing by another thread");
}

/// Write `body` as an executable `/bin/sh` script at `path`, a stand-in for a program sbx runs.
/// Run it past the `ETXTBSY` [`past_etxtbsy`] describes.
pub(crate) fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("the stand-in is writable");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in is executable");
}

/// `path` as one word of a `/bin/sh` script, whatever the fixture root it sits under is called.
pub(crate) fn sh_word(path: &Path) -> String {
    crate::sandbox::shell_quote(path.to_str().expect("utf-8 fixture path"))
}

/// How long a descriptor a test closed may still be held by a neighbouring test's forked child.
///
/// The test binary runs its cases as threads of one process, and a fork copies every descriptor the
/// process holds, close-on-exec or not, into a child that keeps them until it calls `exec` or
/// exits. Every test that forks in that process execs or exits at once; those whose child lingers,
/// `pty`'s, run alone, in a process of their own.
pub(crate) const FORK_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

/// Ask `settled` until it answers yes or [`FORK_WINDOW`] has passed: for a test that closed a
/// descriptor and asks whether every copy of it is gone. A copy a neighbour's fork holds goes
/// within the window; one the code under test left open is still there when it ends, and the
/// test's own assertion, made after this returns, fails on it.
pub(crate) fn once_forks_let_go(mut settled: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + FORK_WINDOW;
    while !settled() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// A program's standard error that tries each thing a relayed diagnostic can do to the line it is
/// shown on: break it, return over it, drive the terminal with an escape and a title-setting
/// sequence, and reorder it with a right-to-left override.
pub(crate) const HOSTILE_STDERR: &[u8] =
    b"error:\n\t\xe2\x80\xa6 while fetching \x1b[2J\x1b]0;x\x07 it\r\n\n\
      error: \xe2\x80\xaegnp.x the cause\n";

/// [`HOSTILE_STDERR`] as [`crate::sandbox::resolver::one_line`] shows it: one line, and whole.
pub(crate) const HOSTILE_STDERR_SHOWN: &str =
    "error: \u{2026} while fetching [2J ]0;x it error: gnp.x the cause";

/// The body of a stand-in that writes `stderr` and exits 1. Every byte goes through `printf` as an
/// octal escape, and nothing but shell builtins runs, so no quoting and no narrowed `PATH` can
/// change what it writes.
pub(crate) fn failing_with(stderr: &[u8]) -> String {
    let octal: String = stderr.iter().map(|b| format!("\\{b:03o}")).collect();
    format!("printf '{octal}' >&2\nexit 1")
}

/// Spawn `cmd`, waiting out the `ETXTBSY` [`past_etxtbsy`] describes.
pub(crate) fn spawn_past_etxtbsy(cmd: &mut std::process::Command) -> std::process::Child {
    past_etxtbsy("spawn", || cmd.spawn())
}

/// Run `cmd` to completion and collect its output, waiting out the same `ETXTBSY`.
pub(crate) fn output_past_etxtbsy(cmd: &mut std::process::Command) -> std::process::Output {
    past_etxtbsy("run", || cmd.output())
}

/// Create a FIFO at `path`, with no writer: a reader that opens it without `O_NONBLOCK` waits for
/// one for good.
pub(crate) fn make_fifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("a path without NUL");
    // SAFETY: `mkfifo` only creates a FIFO at the given NUL-terminated path.
    assert_eq!(
        unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
        0,
        "mkfifo {}",
        path.display()
    );
}

/// Run `f` on a thread of its own and hand back what it returned, failing the test when that takes
/// longer than `limit`. A read that blocks then shows as a red test naming `what`, not as a run
/// that never ends; the blocked thread is left behind and goes with the test process.
pub(crate) fn returns_within<T: Send + 'static>(
    limit: std::time::Duration,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit)
        .unwrap_or_else(|_| panic!("{what} did not return within {limit:?}"))
}

/// How long a process [`run_within`] runs has to end before it is killed and the test that ran it
/// fails.
const END_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);

/// The variable that tells a test it is run alone ([`alone`]), and carries what it was handed.
const RUN_ALONE_WITH: &str = "SBX_TEST_RUN_ALONE_WITH";

/// The line a test run alone writes last when its body returned, which nothing else writes.
const ENDED_WELL: &str = "sbx-alone: ended well";

/// The test binary, set to run the ignored test `entry` alone, in a process of its own, and to hand
/// it `with` ([`when_run_alone`]). `entry` is the test's path, its module as `module_path!` spells
/// it; the test is an ignored one that does nothing unless run this way.
pub(crate) fn alone(entry: &str, with: impl AsRef<OsStr>) -> std::process::Command {
    // libtest names a test by its path in the crate, without the crate's own name.
    let (_, name) = entry.split_once("::").expect("a path in the crate");
    let mut command = std::process::Command::new(std::env::current_exe().expect("the test binary"));
    command
        .args([
            name,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RUN_ALONE_WITH, with);
    command
}

/// How a process [`run_within`] ran ended, and what it wrote.
pub(crate) struct Ran {
    pub(crate) status: std::process::ExitStatus,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Ran {
    /// Whether the test's body returned and its process ended there ([`when_run_alone`]): not by a
    /// failure or a signal, and not through the harness, as a test that was not run alone does.
    pub(crate) fn ended_well(&self) -> bool {
        self.status.success() && self.stdout.lines().any(|line| line == ENDED_WELL)
    }
}

/// Run the test `entry` alone ([`alone`]), handed a directory of its own, and say how it ended.
///
/// A process, rather than a thread of the test process, for a test that does to its process what
/// the rest of the test process must not see: a seccomp filter above all, which each of sbx's
/// helpers installs on a process of its own ([`crate::sandbox::seccomp`]). A filter that refuses a
/// call the rest of the process needs stops more than the thread it is on: without `futex`, a lock
/// that thread releases while another waits on it is never handed over, and a wait of the C
/// library's own that is refused ends the whole process, every other test with it and none of them
/// named. A filter also holds for as long as its thread does, and a choice the standard library
/// makes once per process, made first under it, would be the wrong one for every test after.
///
/// And a process started afresh, the test binary run again for that one test, rather than a copy
/// of this one by `fork`: a copy of a threaded process holds every lock another thread held at the
/// fork. The C library resets its allocator's there, but the standard library does not reset the
/// one it takes to record a thread it starts, and a thread started in the copy waits on it for good
/// whenever another test was starting a thread at that instant.
///
/// The directory is removed once the test has ended; how long it has, and how what it wrote is
/// read, [`run_within`] says.
pub(crate) fn run_alone(entry: &str) -> Ran {
    let dir = TmpDir::new();
    run_within(
        alone(entry, dir.path()).stdin(std::process::Stdio::null()),
        entry,
    )
}

/// Run `command`, its output and errors piped, and say how it ended; `what` names it in a failure.
///
/// A process that has not ended within [`END_WITHIN`] is killed, and the test that ran it fails
/// rather than waits: a fault a process has a handler for, and cannot take the handler off under a
/// helper's filters, is raised again forever, and a thread of the harness a filter left unwoken
/// waits for good. What it wrote is read once it has ended, and not to the end of the stream: a
/// process another test forks meanwhile holds a copy of every descriptor this one has open, the
/// pipes' among them, and a stream some other process holds does not end with the process. What
/// the processes run here write is far smaller than a pipe's buffer, so it is all there.
pub(crate) fn run_within(command: &mut std::process::Command, what: &str) -> Ran {
    use std::process::Stdio;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{what} does not start: {e}"));
    let pidfd = crate::session::open_pidfd(child.id()).expect("a pidfd for the process run");
    let ended = crate::session::wait_for_exit(pidfd, END_WITHIN);
    crate::session::close_fd(pidfd);
    if !ended {
        child.kill().expect("the process run is killed");
    }
    let status = child.wait().expect("the process run is reaped");
    let stdout = queued(child.stdout.take().expect("its output"));
    let stderr = queued(child.stderr.take().expect("its errors"));
    assert!(
        ended,
        "{what} did not end within {END_WITHIN:?}: {stdout}{stderr}"
    );
    Ran {
        status,
        stdout,
        stderr,
    }
}

/// What is already queued on `pipe`, read without waiting for more.
///
/// A descriptor left blocking would make the read wait for the end of a stream another process
/// may hold, so a failure to switch it is a failed test rather than a read that never returns.
pub(crate) fn queued(mut pipe: impl std::io::Read + std::os::fd::AsRawFd) -> String {
    let fd = pipe.as_raw_fd();
    // SAFETY: plain integer arguments on a descriptor this process holds.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(
        flags >= 0,
        "the pipe's flags: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: as above.
    let set = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert_eq!(
        set,
        0,
        "the pipe made non-blocking: {}",
        std::io::Error::last_os_error()
    );
    let mut bytes = Vec::new();
    match pipe.read_to_end(&mut bytes) {
        Err(e) if e.kind() != std::io::ErrorKind::WouldBlock => panic!("a pipe that fails: {e}"),
        _ => String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// When this process is a test run alone ([`alone`]): run `body`, handed what the test was handed,
/// and end the process there, never handing back to the harness, whose thread waiting for the
/// test's end a filter `body` installed may leave unwoken. The process ends with 0, having written
/// [`ENDED_WELL`], when `body` returned; with 2 when it failed, or the line could not be written;
/// with 3 when it panicked. It is marked as one that leaves no core behind, should it end by a
/// signal. Anywhere else, nothing.
pub(crate) fn when_run_alone(body: impl FnOnce(&OsStr) -> std::io::Result<()>) {
    let Some(with) = std::env::var_os(RUN_ALONE_WITH) else {
        return;
    };
    // SAFETY: plain integer arguments, a flag of the calling process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        eprintln!(
            "sbx-alone: not marked as leaving no core: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: as below.
        unsafe { libc::_exit(2) };
    }
    let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&with)));
    let code = match ran.map(|ran| ran.and_then(|()| written(&format!("\n{ENDED_WELL}\n")))) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => 2,
        Err(_) => 3,
    };
    // SAFETY: `_exit` ends the process without running anything more of it.
    unsafe { libc::_exit(code) };
}

/// Write `text` on the standard output by `write` on the descriptor itself, which every helper's
/// filters allow, with no lock or buffer of the standard library's in between.
pub(crate) fn written(text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::fd::FromRawFd as _;
    // SAFETY: the standard output is open for the whole process, and is left open.
    let mut out =
        std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(libc::STDOUT_FILENO) });
    out.write_all(text.as_bytes())
}

/// A reader handing out `bytes` in pieces, as a socket or a slow filesystem may: never more in one
/// read than the next of `sizes`, taken in turn, and a read interrupted where `interrupts` says,
/// never twice in a row. A read returns nothing only once every byte is out.
pub(crate) struct Trickle<'a> {
    bytes: &'a [u8],
    sizes: Vec<usize>,
    interrupts: Vec<bool>,
    reads: usize,
    interrupted: bool,
}

impl<'a> Trickle<'a> {
    /// `sizes` and `interrupts` are read in turn, round and round, so neither may be empty; and a
    /// size of 0 would end the stream early, a read that returns nothing being its end.
    pub(crate) fn new(bytes: &'a [u8], sizes: Vec<usize>, interrupts: Vec<bool>) -> Self {
        assert!(
            !sizes.is_empty() && !sizes.contains(&0),
            "sizes {sizes:?}: none, or one that ends the stream"
        );
        assert!(!interrupts.is_empty(), "no interrupts to read in turn");
        Trickle {
            bytes,
            sizes,
            interrupts,
            reads: 0,
            interrupted: false,
        }
    }
}

impl std::io::Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let turn = self.reads;
        self.reads += 1;
        if !self.interrupted && self.interrupts[turn % self.interrupts.len()] {
            self.interrupted = true;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        self.interrupted = false;
        let n = self.sizes[turn % self.sizes.len()]
            .min(buf.len())
            .min(self.bytes.len());
        let (out, rest) = self.bytes.split_at(n);
        buf[..n].copy_from_slice(out);
        self.bytes = rest;
        Ok(n)
    }
}

/// Every `.rs` source under `dir`, sorted, subdirectories included. The walk descends because a
/// module that outgrew one file keeps its root in `<name>.rs` and everything else in a `<name>/`
/// beside it: a flat listing would read the root, skip the children, and report the silence as a
/// pass. A directory that cannot be listed fails the test for the same reason.
fn rs_sources_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("listing {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("listing {}: {e}", dir.display()))
                .path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// Whether `text` contains a **call** to `needle` — a function name with its opening parenthesis —
/// rather than a mention of it inside a longer identifier.
///
/// The distinction is what separates a call to `write` from one to `memfd_write`, and it is what a
/// source-scanning guard needs: a needle matched anywhere inside a longer identifier would put
/// files in a population that never call the thing at all, and a guard whose population is wrong
/// reports on the wrong files. The parenthesis is the needle's own, so it is required of it: a
/// bare `write` would also match `write_all(`.
pub(crate) fn calls_function(text: &str, needle: &str) -> bool {
    assert!(
        needle.ends_with('('),
        "`{needle}` is a name without its opening parenthesis"
    );
    text.match_indices(needle).any(|(i, _)| {
        i == 0
            || !matches!(text.as_bytes()[i - 1],
                    b'_' | b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
    })
}

/// Whether `path` holds nothing but tests.
///
/// A module that outgrew one file keeps its test half in a `tests.rs` — or a `<topic>_tests.rs` —
/// beside it, declared `#[cfg(test)] mod tests;` from the parent. Unlike an in-file `mod tests`,
/// such a file carries no `#[cfg(test)]` of its own to cut at, so a guard reading production code
/// would take the whole thing; and what a guard looks for is exactly what a test quotes, asserts
/// about, or names in a failure message. The naming is the crate's convention, and it is the only
/// signal available from the path alone.
pub(crate) fn is_test_only_source(path: &Path) -> bool {
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|stem| stem == "tests" || stem.ends_with("_tests"))
}

/// A module declared under `#[cfg(test)]`, as [`gated_modules`] finds it.
struct GatedModule<'a> {
    /// The line the attribute is on.
    attribute: usize,
    /// The line the `mod` is on.
    item: usize,
    name: &'a str,
    /// Whether its body follows inline (`mod x { … }`) rather than in a file of its own
    /// (`mod x;`).
    inline: bool,
}

/// Every module of `lines` that a `#[cfg(test)]` gates, as rustfmt lays the declaration out: the
/// attribute alone on its line, any further attributes on lines of their own, then the `mod` under
/// whatever visibility it has.
///
/// Whole lines rather than every place the text spells the attribute, so a mention in a string or
/// a comment declares nothing.
fn gated_modules<'a>(lines: &[&'a str]) -> Vec<GatedModule<'a>> {
    let mut out = Vec::new();
    for (attribute, line) in lines.iter().enumerate() {
        if line.trim() != "#[cfg(test)]" {
            continue;
        }
        let Some(item) = (attribute + 1..lines.len()).find(|&i| !lines[i].trim().starts_with("#["))
        else {
            continue;
        };
        let decl = lines[item].trim();
        let decl = match decl.strip_prefix("pub(") {
            Some(rest) => rest.split_once(')').map_or(decl, |(_, rest)| rest),
            None => decl.strip_prefix("pub ").unwrap_or(decl),
        };
        let Some(rest) = decl.trim_start().strip_prefix("mod ") else {
            continue;
        };
        let rest = rest.trim_start();
        let name_len = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, after) = rest.split_at(name_len);
        let inline = match after.trim() {
            ";" => false,
            "{" => true,
            _ => continue,
        };
        if !name.is_empty() {
            out.push(GatedModule {
                attribute,
                item,
                name,
                inline,
            });
        }
    }
    out
}

/// Every source the crate compiles **only under `cfg(test)`**, because the module that declares it
/// says so.
///
/// [`is_test_only_source`] answers from the path alone, which covers the `tests.rs` convention and
/// nothing beyond it. A file its parent declares as `#[cfg(test)] mod <name>;` carries no marker of
/// its own and is named like production code — `catalogue_freshness.rs`, `bench.rs` — so a guard
/// reading it as production reports a site no shipped binary contains, and the author who reads the
/// failure has nothing to fix. The declaration is the only place that fact is written, so it is
/// where this reads it, whatever attributes or visibility stand between the two.
pub(crate) fn test_only_sources() -> std::collections::BTreeSet<PathBuf> {
    let mut out = std::collections::BTreeSet::new();
    for file in crate_sources() {
        let text = std::fs::read_to_string(&file)
            .unwrap_or_else(|e| panic!("reading {}: {e}", file.display()));
        // The directory this file's own modules live in: beside it for a `mod.rs` or the crate
        // root, in a subdirectory named after it otherwise.
        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let Some(parent) = file.parent() else {
            continue;
        };
        let dir = if stem == "mod" || stem == "main" || stem == "lib" {
            parent.to_path_buf()
        } else {
            parent.join(stem)
        };
        let lines: Vec<&str> = text.lines().collect();
        // A `mod x { … }` written inline carries its own `#[cfg(test)]` into the file this walk
        // already reads; only the `mod x;` form names a second file.
        for module in gated_modules(&lines).iter().filter(|m| !m.inline) {
            for candidate in [
                dir.join(format!("{}.rs", module.name)),
                dir.join(module.name).join("mod.rs"),
            ] {
                if candidate.is_file() {
                    out.insert(candidate);
                }
            }
        }
    }
    out
}

/// The production half of a source file: the text with every test module written inline in it
/// taken out, from its `#[cfg(test)]` to the line of the brace that closes it.
///
/// Taken out where they stand rather than cut at, because neither end of a file is reliably the
/// boundary: production code may follow a test module, a `#[cfg(test)]` on a single item may stand
/// above production code, and a test module may gate an item of its own, which a cut at the last
/// attribute would take for the boundary and so read the whole module as production. Every other
/// gated item — a `use`, a helper `fn` — is short and stays in, so a guard errs toward reading too
/// much rather than missing a site. A guard's own needles, spelled in its test module, are out of
/// the population it measures.
pub(crate) fn production_half(text: &str) -> Cow<'_, str> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let starts: Vec<usize> = lines
        .iter()
        .scan(0, |at, line| {
            let start = *at;
            *at += line.len();
            Some(start)
        })
        .collect();
    let mut cuts = Vec::new();
    for module in gated_modules(&lines).iter().filter(|m| m.inline) {
        // A module inside one already taken out goes with it.
        if cuts.last().is_some_and(|&(_, end)| module.attribute <= end) {
            continue;
        }
        let open = starts[module.item] + lines[module.item].rfind('{').unwrap_or(0);
        let close = closing_brace(text.as_bytes(), open)
            .map_or(lines.len(), |at| starts.partition_point(|&s| s <= at) - 1);
        cuts.push((module.attribute, close));
    }
    if cuts.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    for (start, end) in cuts {
        out.extend(lines[from..start].iter().copied());
        from = end + 1;
    }
    if from < lines.len() {
        out.extend(lines[from..].iter().copied());
    }
    Cow::Owned(out)
}

/// Where the brace that `text[open]` opens is closed, counting only the braces that are code: a
/// brace inside a string, a raw string, a character literal or a comment — a fixture's JSON, a
/// shell function a test runs — opens nothing.
fn closing_brace(text: &[u8], open: usize) -> Option<usize> {
    let ident = |b: u8| b == b'_' || b.is_ascii_alphanumeric();
    let mut depth = 0usize;
    let mut i = open;
    while i < text.len() {
        let next = text.get(i + 1).copied();
        match text[i] {
            b'/' if next == Some(b'/') => {
                i = text[i..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(text.len(), |n| i + n);
            }
            b'/' if next == Some(b'*') => {
                // Block comments nest.
                let mut nested = 0usize;
                while i < text.len() {
                    if text[i..].starts_with(b"/*") {
                        nested += 1;
                        i += 2;
                    } else if text[i..].starts_with(b"*/") {
                        nested -= 1;
                        i += 2;
                        if nested == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            b'"' => {
                i += 1;
                while i < text.len() && text[i] != b'"' {
                    i += if text[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'r' if matches!(next, Some(b'"' | b'#'))
                && (i == 0
                    || !ident(text[i - 1])
                    || (text[i - 1] == b'b' && (i < 2 || !ident(text[i - 2])))) =>
            {
                let hashes = text[i + 1..].iter().take_while(|&&b| b == b'#').count();
                // `r#name` is a raw identifier, not a string.
                if text.get(i + 1 + hashes) == Some(&b'"') {
                    let mut end = vec![b'"'];
                    end.extend(std::iter::repeat_n(b'#', hashes));
                    let body = i + 2 + hashes;
                    i = text[body..]
                        .windows(end.len())
                        .position(|w| w == end.as_slice())
                        .map_or(text.len(), |n| body + n + end.len() - 1);
                }
            }
            b'\'' => {
                // A character literal, or a lifetime, which has no closing quote.
                let width = match next {
                    Some(b'\\') => text[i + 3..]
                        .iter()
                        .position(|&b| b == b'\'')
                        .map(|n| n + 3),
                    Some(b) => {
                        let len = match b {
                            0xf0.. => 4,
                            0xe0.. => 3,
                            0xc0.. => 2,
                            _ => 1,
                        };
                        (text.get(i + 1 + len) == Some(&b'\'')).then_some(len + 1)
                    }
                    None => None,
                };
                i += width.unwrap_or(0);
            }
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Every `.rs` source under `src/cli`, sorted, subdirectories included.
///
/// Two guards read the dispatcher sources — the routed-subcommand check in [`crate::cli`] and the
/// alias check in [`crate::help`] — and both must see the same corpus.
pub(crate) fn cli_sources() -> Vec<PathBuf> {
    rs_sources_under(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli"))
}

/// Every `.rs` source in the crate, sorted, subdirectories included.
///
/// The corpus for guards whose subject is not one module's code but a claim any file may make — a
/// command named in a diagnostic, a comment, or a doc — where restricting the sweep to the module
/// that happens to hold today's instance would let tomorrow's land anywhere else unguarded.
pub(crate) fn crate_sources() -> Vec<PathBuf> {
    rs_sources_under(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
}

/// A sorted `(relative path, size)` fingerprint of a tree — sensitive to any
/// addition, removal, or size change, enough to assert a store never moved.
///
/// A symlink is recorded as itself, by the length of what it points at, and not followed: what
/// it points at may lie outside the tree, or be the tree again. Anything that cannot be read fails
/// the test, since a fingerprint that skipped it would match its own earlier blind spot.
pub(crate) fn fingerprint(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("listing {}: {e}", dir.display()));
        for entry in entries {
            let path = entry
                .unwrap_or_else(|e| panic!("listing {}: {e}", dir.display()))
                .path();
            let meta = path
                .symlink_metadata()
                .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
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
        apps_share_install_pools: false,
        apps_share_install_pools_origin: Default::default(),
        distro_run: Vec::new(),
        accepts_fresh_releases: Default::default(),
        timezone: None,
        timezone_origin: crate::config::Provenance::Default,
        distro: None,
        distro_auth: None,
        distro_origin: crate::config::Provenance::Default,
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
        ssh_agent_confirm_origin: Default::default(),
        env: vec![],
        env_layer: Default::default(),
        binds: vec![],
        bind_layer: Default::default(),
        packages,
        nixpkgs_global: None,
        mise_engine: None,
        nixpkgs_project: None,
        mise: None,
        mise_ignored: Vec::new(),
        network: crate::config::NetworkPolicy::Shared,
        network_origin: Default::default(),
        egress_stats: true,
        egress_stats_origin: Default::default(),
        redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
        redact_min_len_origin: Default::default(),
        observe_record: false,
        observe_record_origin: Default::default(),
        gui: crate::config::GuiPolicy::default(),
        gui_origin: Default::default(),
        proc: Default::default(),
        proc_origin: Default::default(),
        gpu: false,
        allow_insecure_http: false,
        audio: false,
        dbus: false,
        gpu_origin: Default::default(),
        allow_insecure_http_origin: Default::default(),
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
        refusals: Vec::new(),
    }
}

/// The baseline config with only the two `nixpkgs` pins set — the global channel and the project's.
///
/// The pair decides which revision a launch resolves against, and the tests that vary it are spread
/// across the launch tree (the lock target, the package groups, the equip tokens). Written once here
/// so those three do not each carry their own copy of the same two-line fixture.
pub(crate) fn resolved_channels(
    global: Option<&str>,
    project: Option<&str>,
) -> crate::config::Resolved {
    let mut cfg = resolved(vec![], vec![]);
    cfg.nixpkgs_global = global.map(String::from);
    cfg.nixpkgs_project = project.map(String::from);
    cfg
}

/// An app overlay declaring only `packages`, for a test that asserts how the baseline and an app's
/// own layer combine. `cmd` is a placeholder -- the overlay is never launched.
pub(crate) fn app_with(packages: Vec<crate::config::Package>) -> crate::config::ResolvedApp {
    crate::config::ResolvedApp {
        contract: None,
        accepts_fresh_releases: Default::default(),
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
        allow_insecure_http: None,
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
        allow_insecure_http_origin: Default::default(),
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
        refusals: Vec::new(),
    }
}

/// What the fixture root promises: it names one place, and it reclaims what a killed run left
/// there. The sweep is the half that can do damage, so its tests state liveness rather than
/// borrow it — except the one that has to ask the real `/proc`.
#[cfg(test)]
mod fixture_root_tests {
    use super::TmpDir;
    use std::path::{Path, PathBuf};

    /// Write a fixture directory under `root`, with the read-only inner directory a provisioned
    /// nix store leaves behind — the thing a plain `remove_dir_all` cannot get past.
    fn fixture_like(root: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = root.join(name);
        let store = dir.join("sbx/store/nix/store/abc-tool");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("payload"), b"x").unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o555)).unwrap();
        dir
    }

    /// A `/proc` holding exactly the pids named, so liveness is stated rather than borrowed from
    /// whatever this host happens to be running.
    fn fake_proc(root: &Path, live: &[u32]) -> PathBuf {
        let proc = root.join("proc");
        for pid in live {
            std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
        }
        std::fs::create_dir_all(proc.join("self")).unwrap();
        proc
    }

    #[test]
    fn a_fixture_name_yields_its_owner_pid_and_nothing_else_does() {
        // Both spellings, and a tag carrying its own dashes and digits.
        assert_eq!(
            super::fixture_owner_pid("sbx-test-3738169-0"),
            Some(3738169)
        );
        assert_eq!(
            super::fixture_owner_pid("r-ingr-datb-3725338-10"),
            Some(3725338)
        );
        assert_eq!(super::fixture_owner_pid("p-670023-17"), Some(670023));
        // The shared directories under the same root, which the sweep must never reach.
        assert_eq!(super::fixture_owner_pid("isolated-config"), None);
        assert_eq!(super::fixture_owner_pid("fs-isolated-config"), None);
        assert_eq!(super::fixture_owner_pid("proc-isolated-config"), None);
        // A name with only one number, or none, is not a fixture's.
        assert_eq!(super::fixture_owner_pid("scratch-12"), None);
        assert_eq!(super::fixture_owner_pid("notes"), None);
    }

    #[test]
    fn the_sweep_takes_the_trees_of_dead_runs_and_leaves_every_other_entry() {
        let tmp = TmpDir::new();
        let root = tmp.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let dead = fixture_like(&root, "r-gpu-data-4711-3");
        let live = fixture_like(&root, "r-gpu-data-4712-3");
        let shared = root.join("isolated-config");
        std::fs::create_dir_all(&shared).unwrap();
        let proc = fake_proc(tmp.path(), &[4712]);

        super::sweep_in(&root, &proc);

        // The read-only store inside is what a plain `remove_dir_all` would have choked on.
        assert!(!dead.exists(), "a dead run's fixture was left behind");
        assert!(live.exists(), "a live run's fixture was taken");
        assert!(shared.exists(), "the shared config directory was taken");
    }

    #[test]
    fn the_sweep_reads_this_very_process_as_live() {
        // The one error that would cost a running suite its fixtures, asserted against the real
        // `/proc` rather than a written one: a fixture named after a live pid has to survive.
        let tmp = TmpDir::new();
        let root = tmp.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let mine = fixture_like(&root, &format!("r-mine-{}-0", std::process::id()));

        super::sweep_in(&root, Path::new("/proc"));

        assert!(
            mine.exists(),
            "the sweep took the fixture of the running process"
        );
    }

    #[test]
    fn a_proc_root_with_no_self_takes_nothing() {
        // No `/proc` mounted reads every pid as gone; the sweep decides nothing from that.
        let tmp = TmpDir::new();
        let root = tmp.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let dead = fixture_like(&root, "r-gpu-data-4711-3");
        let proc = tmp.join("not-proc");
        std::fs::create_dir_all(&proc).unwrap();

        super::sweep_in(&root, &proc);

        assert!(dead.exists(), "a fixture was taken on no evidence");
    }

    #[test]
    fn a_pid_entry_that_cannot_be_read_reads_live() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new();
        let proc = fake_proc(tmp.path(), &[]);
        assert!(
            super::run_is_gone(&proc, 4711),
            "an absent entry reads as gone"
        );
        // A directory this process may not search answers `EACCES`, never `ENOENT`. Root searches
        // it regardless.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        std::fs::set_permissions(&proc, std::fs::Permissions::from_mode(0o000)).unwrap();
        let gone = super::run_is_gone(&proc, 4711);
        std::fs::set_permissions(&proc, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            !gone,
            "an entry that could not be read was taken for a dead run"
        );
    }

    #[test]
    fn the_removal_unlinks_a_symlink_and_leaves_what_it_names() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new();
        let outside = tmp.join("outside");
        let kept = outside.join("ro");
        std::fs::create_dir_all(&kept).unwrap();
        std::fs::write(kept.join("payload"), b"x").unwrap();
        std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o555)).unwrap();
        let tree = tmp.join("tree");
        std::fs::create_dir_all(tree.join("inner/sealed")).unwrap();
        std::fs::write(tree.join("inner/sealed/file"), b"x").unwrap();
        std::fs::set_permissions(
            tree.join("inner/sealed"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("inner/link")).unwrap();

        super::force_remove(&tree);

        assert!(!tree.exists(), "the tree was left");
        assert!(
            kept.join("payload").exists(),
            "the removal followed the link"
        );
        let mode = std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777;
        std::fs::set_permissions(&kept, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            mode, 0o555,
            "the removal changed the mode of what the link names"
        );
    }

    #[test]
    fn the_removal_stops_at_its_depth() {
        let tmp = TmpDir::new();
        let tree = tmp.join("tree");
        std::fs::create_dir_all(tree.join("a/b")).unwrap();
        std::fs::write(tree.join("a/top"), b"x").unwrap();

        super::force_remove_within(&tree, 1);

        assert!(
            tree.join("a/b").exists(),
            "the removal went below its depth"
        );
        super::force_remove(&tree);
        assert!(!tree.exists(), "a shallow tree was left");
    }

    #[test]
    fn an_empty_or_relative_variable_does_not_place_the_root() {
        use std::ffi::OsString;
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let home = Path::new("/home/u/.cache/sbx/test-tmp");
        assert_eq!(
            super::fixture_root_from(env(&[("SBX_TEST_TMPDIR", "/t"), ("HOME", "/home/u")])),
            Path::new("/t")
        );
        assert_eq!(
            super::fixture_root_from(env(&[("SBX_TEST_TMPDIR", ""), ("HOME", "/home/u")])),
            home
        );
        assert_eq!(
            super::fixture_root_from(env(&[("XDG_CACHE_HOME", "cache"), ("HOME", "/home/u")])),
            home
        );
        assert_eq!(
            super::fixture_root_from(env(&[("XDG_CACHE_HOME", ""), ("HOME", "/home/u")])),
            home
        );
        assert_eq!(
            super::fixture_root_from(env(&[("XDG_CACHE_HOME", "/c"), ("HOME", "/home/u")])),
            Path::new("/c/sbx/test-tmp")
        );
    }

    #[test]
    fn the_sweep_says_nothing_about_a_root_that_is_not_there() {
        // A first run on a clean machine has no root yet, and the sweep runs before anything
        // creates one.
        super::sweep_in(Path::new("/nonexistent/sbx-test-root"), Path::new("/proc"));
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
/// There is no exception for a reason that names both. The sites that once said "host cannot
/// sandbox (no userns/bwrap, or the base cache is unreachable)" could not tell which half had
/// failed, so they now go through `probe_or_skip!`, which can.
///
/// The integration suites' two gate macros are not exceptions but the property made structural: a
/// site written with `probe_or_skip!` cannot name an off-host reason, because the macro writes the
/// reason itself around the caller's label and sends a launch that failed on a download to the
/// counted macro, and a site written with `need_reachable!` reaches only the counted macro. What
/// this sweep still reads is every skip written out by hand.
#[test]
fn an_off_host_skip_is_never_written_with_the_enforceable_macro() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Built at runtime, so this file does not match its own needle.
    let needle = format!("skip_{}!(", "incapable");
    const OFF_HOST: [&str; 3] = ["is unreachable", "download fault", "flake upstream"];
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
                if OFF_HOST.iter().any(|o| reason.contains(o)) {
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
/// A hand-written print plus `return` (`eprintln!`, or sbx's own `errln!` and `outln!`, which are
/// `eprint!` and `print!` under test) is what the harness counts as a pass and what it then
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
    let needles: Vec<String> = ["eprintln!", "println!", "errln!", "outln!"]
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

/// Every fixture tree is rooted outside the workspace, and stays there.
///
/// The root moved out for a reason that is invisible from inside a test: a language server watching
/// the repository spends one inotify watch per directory, one run of the cage suites leaves hundreds
/// of thousands of them, and what runs out of `max_user_watches` first is systemd — which then loses
/// the cgroup watches a transient scope needs to learn its cage emptied, so the scope is never
/// collected. Nothing in a suite fails when its fixtures land in the workspace instead; the cost
/// arrives later, somewhere else, as scopes that will not die.
///
/// That is the shape this sweep exists for. The hole was closed once by moving twenty-one roots to
/// one definition, and closing it took editing a single file — so re-opening it takes editing a
/// single file too. Since then the twenty-one `TmpDir` declarations behind those roots have
/// themselves collapsed to two, one per half of the suite, so what this sweep now guards is that no
/// third one appears with a root of its own.
///
/// Two shapes are refused. A file that declares its own `TmpDir` without reaching [`fixture_root`]
/// has a root of its own, wherever it points today; and a line of code naming the in-workspace tree
/// outright has one whether or not it declares a type. Prose may still name it — a comment
/// explaining where fixtures used to live is not a fixture.
///
/// A third refusal points the other way, at this test rather than at the tree: an exception that no
/// longer excuses anything fails too. The list is empty today because the last entry on it was
/// measured rather than assumed — the reason it carried had gone stale, and the suite it named
/// takes the shared root with every one of its tests still green.
#[test]
fn every_fixture_root_is_the_shared_one() {
    // Empty, and meant to stay so. A suite that must root its fixtures in the workspace is named
    // here rather than exempted by a pattern, so an entry is a decision someone writes down — and
    // the sweep below refuses an entry that no longer excuses anything, because a rule about a file
    // that has since been fixed is one the next reader trusts.
    const ROOTED_IN_THE_WORKSPACE: &[&str] = &[];

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Assembled at runtime, so this file does not match its own needle.
    let in_workspace = format!("target/{}", "test-tmp");
    let (mut own_root, mut hardcoded, mut declaring, mut reaching, mut files) =
        (Vec::new(), Vec::new(), 0, 0, 0);
    let mut used_exception = std::collections::BTreeSet::new();

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
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let excused = ROOTED_IN_THE_WORKSPACE.contains(&rel.as_str());

            // Counted apart: a file that *reaches* a fixture tree names `TmpDir`, whether it
            // declares the type or uses the shared one. The precondition below rests on that count
            // rather than on the number of declarations, which is now two by design.
            if text.contains("TmpDir") {
                reaching += 1;
            }
            if text.contains("struct TmpDir") {
                declaring += 1;
                if !text.contains("fixture_root()") {
                    if excused {
                        used_exception.insert(rel.clone());
                    } else {
                        own_root.push(rel.clone());
                    }
                }
            }
            for (n, line) in text.lines().enumerate() {
                // Prose may name the old location; code may not.
                if line.trim_start().starts_with("//") || !line.contains(&in_workspace) {
                    continue;
                }
                if excused {
                    used_exception.insert(rel.clone());
                } else {
                    hardcoded.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }

    assert!(
        own_root.is_empty(),
        "these suites declare a fixture directory without reaching `fixture_root()`, so their trees \
         land wherever that declaration points — and a tree inside the workspace is watched by \
         whatever language server is open on it: {own_root:?} — `include!(\"../src/testroot.rs\")` \
         and build the root from `fixture_root()`"
    );
    assert!(
        hardcoded.is_empty(),
        "these lines build a fixture path inside the workspace by name, which no `SBX_TEST_TMPDIR` \
         can move: {hardcoded:?} — root them at `fixture_root()` instead"
    );
    // An exception that no longer excuses anything is worse than none: it reads as a rule about a
    // file that has since been fixed, and the next reader trusts it.
    let stale: Vec<&str> = ROOTED_IN_THE_WORKSPACE
        .iter()
        .copied()
        .filter(|named| !used_exception.contains(*named))
        .collect();
    assert!(
        stale.is_empty(),
        "these files are excused from rooting their fixtures outside the workspace but no longer \
         need it: {stale:?} — drop them from the list"
    );
    // The preconditions, asserted rather than assumed: a sweep that read nothing, or one that
    // stopped recognising how a fixture directory is declared, would pass while guarding nothing.
    assert!(files > 100, "the sweep read only {files} source files");
    // Two declarers by design — `testutil` for the unit tests, `tests/common/fixture.rs` for the
    // integration ones — so counting declarations would now assert almost nothing. What has to stay
    // large is the number of files that reach a fixture tree at all: that is the population this
    // rule governs, and a sweep that stopped recognising them would pass while guarding nothing.
    assert!(
        declaring >= 2,
        "only {declaring} files declare a fixture directory — has the sweep gone stale?"
    );
    assert!(
        reaching >= 80,
        "only {reaching} files reach a fixture tree — has the sweep gone stale?"
    );
}

/// A path whose first component is `..`, joined onto another, reaches outside it.
///
/// Everywhere this codebase takes such a name from a caller it refuses it: `reap_one` answers
/// `NotFound` for `../victim` rather than delete a sibling of `projects/`, and a `[cage] timezone`
/// of `../escaped` falls back to the default rather than become a link target. The one place the
/// shape survived was the *writing* side of a test, where nothing refuses anything — and a test
/// that writes through `..` writes outside its own fixture.
///
/// What that leaves behind is not swept by [`TmpDir`]'s drop, which removes only the directory it
/// made. It carries no pid, so nothing reclaiming a killed run's trees can tell it from a live
/// one's. And every process running the suite writes that one absolute path at the same moment.
///
/// The rule is narrow, and worth stating as exactly what it is: **no line of code joins or pushes a
/// literal whose first component is `..`**, and a file named `...toml`, which begins with the same
/// two dots and leaves nothing, is not one. A traversal assembled any other way — through
/// [`Path::parent`], a `format!`, or a `PathBuf` built up piece by piece — walks past this sweep
/// untouched. Prose may still name the shape; a comment describing a traversal is not one.
#[test]
fn nothing_joins_a_path_that_traverses_out_of_the_one_it_is_joined_to() {
    // Assembled at runtime, so this file does not match its own needles.
    // `..` as the literal's first component: followed by a separator or by the literal's end.
    let needles: Vec<String> = [".join(\"", ".push(\""]
        .iter()
        .flat_map(|call| ["/", "\""].map(|end| format!("{call}{}{end}", "..")))
        .collect();
    let offends = |line: &str| {
        !line.trim_start().starts_with("//") && needles.iter().any(|n| line.contains(n.as_str()))
    };

    // The predicate answers both ways before it is trusted on the tree: one that recognised nothing,
    // and one that flagged the prose as well, both report an empty list from a clean sweep.
    let joined = format!(
        "std::fs::write(db.path().join(\"{}/escaped\"), b\"x\").unwrap();",
        ".."
    );
    let pushed = format!("let mut d = base.clone(); d.push(\"{}\");", "..");
    let prose = format!(
        "// a sibling of the base that `p.join(\"{}/victim\")` would reach",
        ".."
    );
    assert!(
        offends(&joined),
        "the sweep no longer sees the shape it exists for"
    );
    assert!(
        offends(&pushed),
        "the sweep sees only one of the two spellings"
    );
    assert!(!offends(&prose), "prose naming the shape is not the shape");
    let dotted_name = format!("let f = dir.join(\"{}.toml\");", "..");
    assert!(
        !offends(&dotted_name),
        "a file name that begins with two dots is not a traversal"
    );

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let (mut traversing, mut files) = (Vec::new(), 0);
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
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for (n, line) in text.lines().enumerate() {
                if offends(line) {
                    traversing.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }

    assert!(
        traversing.is_empty(),
        "these lines build a path that begins by leaving the directory it is joined to: \
         {traversing:?} — in a test that means writing outside its own fixture, into a tree every \
         other process running the suite shares and no cleanup owns. Give the traversal a target \
         the fixture holds, the way `gc.rs` gives `../victim` a sibling of its own `projects/`"
    );
    // The precondition, asserted rather than assumed: a sweep that read nothing passes silently.
    assert!(files > 100, "the sweep read only {files} source files");
}

/// The shell task that reclaims fixtures says where its rule is written.
///
/// `mise run clean-fixtures` applies the same test as [`sweep_in`] — a fixture's name ends in
/// `<pid>-<counter>`, and a live pid keeps its tree — from a shell, because the automatic sweep
/// only runs when a test binary asks for the root and the disk is sometimes wanted back without
/// starting one. Two spellings of one rule is a drift risk, and what makes it survivable is that
/// the shell copy names the definition it mirrors: a reader who changes the naming has a thread to
/// pull. This refuses the task that stops naming it.
#[test]
fn the_fixture_cleanup_task_names_the_rule_it_mirrors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(root.join("mise.toml")).expect("read mise.toml");
    let (_, task) = text
        .split_once("[tasks.clean-fixtures]")
        .expect("mise.toml no longer carries a `clean-fixtures` task");
    let task = task.split("\n[tasks.").next().expect("the task has an end");
    for needle in ["sweep_in", "src/testroot.rs"] {
        assert!(
            task.contains(needle),
            "the `clean-fixtures` task no longer names `{needle}`, so nothing ties its rule to the \
             one the test harness applies"
        );
    }
}

/// The cage suites are named in two places, and the two have to agree.
///
/// `mise run test-cage` and the `Cage` workflow both run the suites that carry a capability skip,
/// and both write the list out rather than globbing it, so that a new suite carrying a skip is a
/// deliberate addition instead of a silent omission. That decision costs a second copy, and a
/// second copy of a version or a list is how the two drift: the same shape, one level down, once
/// let a published binary be linked by a toolchain three major versions from the one this
/// repository resolved, with nothing failing to say so.
///
/// So the copy is allowed and the drift is not. What this refuses is the two lists differing, in
/// either direction: a suite the task runs and the workflow does not is coverage that only exists
/// on someone's machine, and one the workflow runs and the task does not is a failure nobody can
/// reproduce locally.
#[test]
fn the_cage_suites_are_the_same_list_in_the_task_and_the_workflow() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Assembled at runtime, so this file does not match its own needle.
    let needle = format!("for {} in ", "suite");

    let listed = |rel: &str| -> Vec<String> {
        let text =
            std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let line = text
            .lines()
            .find(|l| l.contains(&needle))
            .unwrap_or_else(|| panic!("{rel} no longer names the suites with `{needle}`"));
        let (_, rest) = line.split_once(&needle).expect("the needle is in the line");
        let names = rest.split(';').next().unwrap_or("");
        names
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    let task = listed("mise.toml");
    let workflow = listed(".github/workflows/cage.yml");

    assert_eq!(
        task, workflow,
        "`mise run test-cage` and the `Cage` workflow run different suites — the one missing from \
         either side is coverage that exists in only one place"
    );
    // The precondition, asserted rather than assumed: two empty lists are equal, and a sweep that
    // stopped recognising the shape would report agreement it never checked.
    assert!(
        task.len() >= 10,
        "only {} suites were read — has the list moved?",
        task.len()
    );
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn a_variable_is_pinned_only_under_the_lock() {
        const KEY: &str = "SBX_TEST_PINNED_UNDER_THE_LOCK";
        let unlocked = std::thread::spawn(|| {
            std::panic::catch_unwind(|| EnvVar::set(KEY, "x")).is_err()
                && std::panic::catch_unwind(|| EnvVar::unset(KEY)).is_err()
        });
        assert!(
            unlocked.join().unwrap(),
            "a variable was pinned without the lock"
        );
        let _lock = env_lock();
        let _pinned = EnvVar::set(KEY, "x");
        assert_eq!(std::env::var(KEY).as_deref(), Ok("x"));
    }

    #[test]
    fn a_leftover_under_the_fixtures_name_is_emptied_before_it_is_used() {
        let base = TmpDir::new();
        let d = base.join("sbx-test-1-0");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/stale"), b"from a dead run").unwrap();
        create_afresh(&d);
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            0,
            "the leftover kept its contents"
        );
    }

    #[test]
    fn a_name_that_leaves_the_fixture_is_refused() {
        let base = TmpDir::new();
        assert_eq!(base.join("a/./b"), base.path().join("a/./b"));
        for name in ["../escape", "a/../../escape", "/etc/passwd"] {
            let refused =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| base.join(name)));
            assert!(refused.is_err(), "`{name}` was joined");
        }
    }

    #[test]
    fn a_needle_without_its_parenthesis_is_refused() {
        assert!(calls_function("x = memfd::write(fd)", "memfd::write("));
        assert!(!calls_function("x = my_write(fd)", "write("));
        let refused = std::panic::catch_unwind(|| calls_function("write_all(b)", "write"));
        assert!(refused.is_err(), "a bare name was taken as a needle");
    }

    #[test]
    fn a_trickle_refuses_a_size_that_would_end_the_stream_early() {
        use std::io::Read as _;
        let mut out = Vec::new();
        Trickle::new(b"abcdef", vec![2, 1], vec![true, false])
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"abcdef");
        for (sizes, interrupts) in [
            (vec![1, 0], vec![false]),
            (vec![], vec![false]),
            (vec![1], vec![]),
        ] {
            let refused = std::panic::catch_unwind(|| Trickle::new(b"ab", sizes, interrupts));
            assert!(refused.is_err(), "an unreadable rotation was taken");
        }
    }

    #[test]
    fn a_tree_that_cannot_be_listed_fails_the_fingerprint() {
        let base = TmpDir::new();
        std::fs::write(base.join("f"), b"four").unwrap();
        assert_eq!(fingerprint(base.path()), vec![(PathBuf::from("f"), 4)]);
        let missing = base.join("missing");
        assert!(std::panic::catch_unwind(|| fingerprint(&missing)).is_err());
    }

    /// The three shapes a cut at the last `#[cfg(test)]` reads wrong: a mention of the attribute in
    /// text, production code after the test module, and a test module that gates an item of its
    /// own.
    #[test]
    fn the_production_half_takes_out_test_modules_where_they_stand() {
        let quoted = "fn a() {}\nconst S: &str = \"#[cfg(test)]\";\nfn b() {}\n";
        assert_eq!(production_half(quoted), quoted);
        assert!(matches!(production_half(quoted), Cow::Borrowed(_)));

        let after = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn b() {}\n";
        assert_eq!(production_half(after), "fn a() {}\nfn b() {}\n");

        let nested = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n    #[cfg(test)]\n    \
                      fn u() {}\n    #[cfg(test)]\n    mod inner {\n    }\n}\n";
        assert_eq!(production_half(nested), "fn a() {}\n");

        let gated_items = "#[cfg(test)]\nuse x::y;\nfn a() {}\n#[cfg(test)]\n#[allow(dead_code)]\n\
                           pub(super) mod t {\n    fn t() {}\n}\n";
        assert_eq!(
            production_half(gated_items),
            "#[cfg(test)]\nuse x::y;\nfn a() {}\n"
        );
    }

    /// A brace inside a string, a character, or a comment opens nothing: a test module holding one
    /// still ends at its own closing brace, and the production code after it is kept.
    #[test]
    fn the_production_half_counts_only_the_braces_that_are_code() {
        let tail = "fn after() {}\n";
        let text = [
            "fn before() {}\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    const SHELL: &str = r#\"\n",
            "run() {\n",
            "}\n",
            "\"#;\n",
            "    const QUOTE: &str = \"\\\"}\";\n",
            "    const BRACE: char = '}';\n",
            "    const PAIR: [char; 2] = ['\\'','}'];\n",
            "    // }\n",
            "    /* /* */ } */\n",
            "    fn held<'a>(r#type: &'a str) -> &'a str { r#type }\n",
            "    const QUOTED: &str = r#\"a \"}\" b\"#;\n",
            "    const BYTES: &[u8] = br#\"a \"}\" b\"#;\n",
            "    fn raw(r#fn: u8) {}\n",
            "}\n",
            tail,
        ]
        .concat();
        assert_eq!(production_half(&text), ["fn before() {}\n", tail].concat());
    }

    /// `src/main.rs` declares `testskip` with `#[macro_use]` between the gate and the `mod`.
    #[test]
    fn a_test_only_module_is_found_past_attributes_and_visibility() {
        let lines = [
            "#[cfg(test)]",
            "#[macro_use]",
            "mod skip;",
            "#[cfg(test)]",
            "pub(in crate::x) mod helpers;",
            "#[cfg(test)]",
            "mod inline {",
            "}",
            "// #[cfg(test)] mod quoted;",
        ];
        let found: Vec<(&str, bool)> = gated_modules(&lines)
            .iter()
            .map(|m| (m.name, m.inline))
            .collect();
        assert_eq!(
            found,
            [("skip", false), ("helpers", false), ("inline", true)]
        );
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert!(test_only_sources().contains(&root.join("src/testskip.rs")));
    }
}
