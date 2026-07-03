//! The on-disk session registry (no daemon).
//!
//! Each running sandbox writes a small record under `<data>/sessions/`; `ops ls`
//! reads them back. Without a daemon nothing guarantees a record is removed when
//! its sandbox dies, so a record is a **liveness-validated hint**, never trusted
//! to be cleaned up: [`Registry::list`] re-checks every record and prunes the
//! dead ones. A clean exit removes its own record eagerly through [`RecordGuard`]
//! (a best-effort fast path), but correctness rests entirely on the liveness
//! check, which is also what makes a crash or `SIGKILL` self-healing.
//!
//! Liveness uses the `(pid, start_ticks)` pair, not the pid alone: a bare pid is
//! ambiguous because the kernel reuses pids. The process start time (clock ticks
//! since boot, from `/proc/<pid>/stat`) pins one *incarnation* of a pid, so a
//! reused pid no longer masquerades as a live session. The start time survives
//! `execve`, so registering just before `ops run` execs into bubblewrap is safe:
//! the record keeps matching the same pid after it becomes the sandbox.
//!
//! The recorded project path is the **canonical** project root (the same path the
//! sandbox binds and the same one the per-project runtime id is derived from), so
//! the registry and the on-disk runtime never disagree about a project's identity.
//!
//! Security: the registry lives at `<data>/sessions`, outside every sandbox bind
//! (a sandbox only ever sees its own `<data>/projects/<id>/home`, never `<data>`
//! itself), so a sandboxed — possibly untrusted — process can neither read nor
//! tamper with it. It adds no new attack surface inside the cage.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What kind of sandbox a record describes. Both are tracked: `ops run` is the
/// autonomous-agent path (the sandboxes the registry most needs to surface) and
/// `ops shell` the interactive one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Run,
    Shell,
}

impl Kind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Run => "run",
            Kind::Shell => "shell",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "run" => Some(Kind::Run),
            "shell" => Some(Kind::Shell),
            _ => None,
        }
    }
}

/// Which persistent home a session runs in — the bit `ops attach` needs to reproduce the same
/// environment. A plain `ops run`/`ops shell` uses the project's default home (`Project`); an
/// `ops app` uses its own isolated home, keyed by the app name and its scope (`GlobalApp` shared
/// across projects, `ProjectApp` per project). Owned (unlike the borrowing launch-side `Runtime`),
/// so a record outlives the launch that wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionRuntime {
    Project,
    GlobalApp(String),
    ProjectApp(String),
}

impl SessionRuntime {
    /// Serialise to a single token: `project`, `global-app:<name>`, or `project-app:<name>`. An
    /// app name is a validated single component (`[A-Za-z0-9._-]`), so it carries no `:` or newline
    /// to confuse the framing.
    fn serialize(&self) -> String {
        match self {
            SessionRuntime::Project => "project".to_string(),
            SessionRuntime::GlobalApp(name) => format!("global-app:{name}"),
            SessionRuntime::ProjectApp(name) => format!("project-app:{name}"),
        }
    }

    /// Parse the token form. An unrecognised or absent value is the project default — back-compat
    /// with records written before this field, and fail-safe: an unknown runtime attaches as a
    /// plain project shell rather than as an app it cannot identify.
    fn parse(value: &str) -> Self {
        if let Some(name) = value.strip_prefix("global-app:") {
            SessionRuntime::GlobalApp(name.to_string())
        } else if let Some(name) = value.strip_prefix("project-app:") {
            SessionRuntime::ProjectApp(name.to_string())
        } else {
            SessionRuntime::Project
        }
    }
}

/// What [`Session::stop`] did to a session's process.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StopOutcome {
    /// Nothing was signalled: the process had already exited, or its pid had been
    /// reused by a different incarnation (so signalling it would hit the wrong process).
    AlreadyGone,
    /// SIGTERM was enough — the process exited within the grace window.
    Terminated,
    /// The process outlived the grace window and was forced down with SIGKILL.
    Killed,
}

/// One registered sandbox. The `(pid, start_ticks)` pair identifies the live
/// process; `project` is the canonical project root (display and identity); `runtime` is the home
/// it runs in, so `ops attach` can reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Session {
    pub(crate) project: PathBuf,
    pub(crate) pid: u32,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat` field 22).
    /// Pins the pid to one incarnation, defeating pid reuse.
    pub(crate) start_ticks: u64,
    pub(crate) kind: Kind,
    pub(crate) runtime: SessionRuntime,
}

impl Session {
    /// Describe the *current* process as a session for `project`. Reads this
    /// process's own start time so the record can later be matched against it.
    pub(crate) fn current(
        project: PathBuf,
        kind: Kind,
        runtime: SessionRuntime,
    ) -> io::Result<Self> {
        let pid = std::process::id();
        let start_ticks = read_start_ticks(pid)
            .ok_or_else(|| io::Error::other("cannot read this process's start time"))?;
        Ok(Self {
            project,
            pid,
            start_ticks,
            kind,
            runtime,
        })
    }

    /// The record's stable file name: unique per process *incarnation*, so two
    /// sessions — even ones that happen to reuse a pid — never collide.
    fn file_name(&self) -> String {
        format!("{}-{}", self.pid, self.start_ticks)
    }

    /// A short label for display: the kind (`run`/`shell`) for a project session, or `app:<name>`
    /// for an app — so a listing or a stop message tells agents apart from plain shells.
    pub(crate) fn label(&self) -> String {
        match &self.runtime {
            SessionRuntime::Project => self.kind.as_str().to_string(),
            SessionRuntime::GlobalApp(name) | SessionRuntime::ProjectApp(name) => {
                format!("app:{name}")
            }
        }
    }

    /// The app this session runs as (`ops app <name>`), or `None` for a plain project shell/run — so
    /// a listing or an action can be scoped to one app's session(s).
    pub(crate) fn app(&self) -> Option<&str> {
        match &self.runtime {
            SessionRuntime::Project => None,
            SessionRuntime::GlobalApp(name) | SessionRuntime::ProjectApp(name) => Some(name),
        }
    }

    /// Stop this session's process: SIGTERM, then SIGKILL if it has not exited within `grace`.
    ///
    /// Signalling goes through a **pidfd**, not a bare pid, for two reasons that matter here. A
    /// pidfd pins one exact process: the pid is read once after opening to confirm it is the
    /// incarnation we recorded (the same `(pid, start_ticks)` guard the registry uses), and from
    /// then on the kernel cannot reuse that pid behind our back, so a stop can never signal an
    /// unrelated process. And a pidfd becomes *readable* when its process terminates, so waiting
    /// on it reports the exit cleanly — including the brief zombie window a plain liveness read
    /// would still see as alive.
    ///
    /// The cage is torn down by killing not only the recorded process but its whole descendant
    /// subtree. Killing the recorded pid alone is *not* reliable: on the allowlist path it is a
    /// supervisor whose death is meant to cascade to bubblewrap through `--die-with-parent`, but
    /// when the cage runs inside a transient systemd resource-limit scope that parent-death cascade
    /// is racy and can leave the agent running. So the stop snapshots the subtree first and SIGKILLs
    /// any survivor directly — killing bubblewrap (pid 1 of the cage's pid namespace) makes the
    /// kernel reap everything left inside it. The exec path (recorded pid == bubblewrap) is covered
    /// by the same sweep.
    pub(crate) fn stop(&self, grace: Duration) -> StopOutcome {
        let Some(pidfd) = open_pidfd(self.pid) else {
            return StopOutcome::AlreadyGone;
        };
        // Confirm the pinned process is the one we recorded: the pid could have been reused
        // between listing and the open. Once confirmed, the held fd keeps it pinned.
        if read_start_ticks(self.pid) != Some(self.start_ticks) {
            close_fd(pidfd);
            return StopOutcome::AlreadyGone;
        }
        // Snapshot the cage subtree now, while the parent links still hold — once the recorded
        // process dies its children reparent to init and the links are lost.
        let cage = descendants(self.pid);
        let outcome = stop_pinned(pidfd, &cage, grace);
        close_fd(pidfd);
        outcome
    }
}

/// Open a pidfd for `pid`, or `None` if the process is already gone.
fn open_pidfd(pid: u32) -> Option<libc::c_int> {
    // SAFETY: `pidfd_open` only reads `pid`; it returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    (fd >= 0).then_some(fd as libc::c_int)
}

fn close_fd(fd: libc::c_int) {
    // SAFETY: closing a fd we opened.
    unsafe { libc::close(fd) };
}

/// Send `signal` to the process a pidfd pins. Returns whether the kernel accepted it (a failure
/// means the process has already exited).
fn send_signal(pidfd: libc::c_int, signal: libc::c_int) -> bool {
    // SAFETY: `pidfd_send_signal` with a null `siginfo` sends `signal` as if by `kill`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    rc == 0
}

/// Wait up to `timeout` for the pinned process to terminate. A pidfd is readable once its process
/// exits, so a positive poll means it is gone; returns `true` in that case.
fn wait_for_exit(pidfd: libc::c_int, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    // SAFETY: polling one fd we own.
    unsafe { libc::poll(&mut pfd, 1, ms) > 0 }
}

/// SIGTERM the pinned process and the cage subtree, then SIGKILL whatever outlives `grace`. A
/// `grace` of zero escalates immediately (SIGTERM, then SIGKILL with no wait). The cage members are
/// always SIGKILLed at the end — even when the recorded process exited cleanly — so a stop is
/// deterministic regardless of how the agent, bubblewrap, or the resource-limit scope behaved.
fn stop_pinned(pidfd: libc::c_int, cage: &[(u32, u64)], grace: Duration) -> StopOutcome {
    if !send_signal(pidfd, libc::SIGTERM) {
        // The recorded process exited between the open and now; still sweep any cage leftovers.
        kill_cage(cage);
        return StopOutcome::AlreadyGone;
    }
    // Signalling the cage's own processes (not just the recorded parent) lets a well-behaved agent
    // shut down — and on the supervised path that cascades a clean supervisor exit — instead of
    // relying on a parent-death signal that may not arrive.
    for &(pid, start) in cage {
        signal_if_match(pid, start, libc::SIGTERM);
    }
    let exited = wait_for_exit(pidfd, grace);
    if !exited {
        // SIGKILL cannot be caught, so this is bounded; a SIGKILL on an already-exited process is
        // harmless, so a late voluntary exit only confirms it is gone.
        let _ = send_signal(pidfd, libc::SIGKILL);
    }
    // Force down any surviving cage member, so the agent never outlives the stop.
    kill_cage(cage);
    if exited {
        StopOutcome::Terminated
    } else {
        wait_for_exit(pidfd, Duration::from_secs(5));
        StopOutcome::Killed
    }
}

/// SIGKILL every still-present member of a cage subtree (reuse-guarded by start time), tearing the
/// namespace down: killing bubblewrap (pid 1 of the cage's pid namespace) makes the kernel reap
/// everything left inside it.
fn kill_cage(cage: &[(u32, u64)]) {
    for &(pid, start) in cage {
        signal_if_match(pid, start, libc::SIGKILL);
    }
}

/// Send `signal` to `pid` only if it is still the incarnation `start_ticks` recorded — the same
/// reuse guard the registry applies, so a cage member whose pid the kernel has since recycled is
/// never signalled by mistake. (A vanishingly small window remains between the start-time read and
/// the `kill`; the recorded process itself is signalled through a race-free pidfd instead.)
fn signal_if_match(pid: u32, start_ticks: u64, signal: libc::c_int) {
    if read_start_ticks(pid) == Some(start_ticks) {
        // SAFETY: `kill(pid, signal)`; a failure (e.g. the process just exited) is ignored.
        unsafe { libc::kill(pid as libc::pid_t, signal) };
    }
}

/// The transitive descendants of `root` (excluding `root` itself), each paired with its start time,
/// as a snapshot of `/proc` at this instant. Built from one pass over `/proc`: a `parent -> children`
/// map, then a walk down from `root`. The start times let a later kill skip a pid the kernel has
/// since reused.
fn descendants(root: u32) -> Vec<(u32, u64)> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut start_of: HashMap<u32, u64> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let (Some(ppid), Some(start)) = (parse_ppid(&stat), parse_start_ticks(&stat)) else {
                continue;
            };
            children.entry(ppid).or_default().push(pid);
            start_of.insert(pid, start);
        }
    }
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(parent) = stack.pop() {
        let Some(kids) = children.get(&parent) else {
            continue;
        };
        for &kid in kids {
            if let Some(&start) = start_of.get(&kid) {
                out.push((kid, start));
                stack.push(kid);
            }
        }
    }
    out
}

/// Extract field 4 (parent pid) from the contents of `/proc/<pid>/stat`. Like
/// [`parse_start_ticks`], it reads the clean tail after the final `)`: there field 3 (state) is the
/// first token and field 4 (ppid) the second.
fn parse_ppid(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

/// The session registry rooted at `<data>/sessions`. Holds no I/O itself; each
/// method touches the filesystem on demand.
pub(crate) struct Registry {
    dir: PathBuf,
}

impl Registry {
    /// The registry under ops's data directory.
    pub(crate) fn at(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join("sessions"),
        }
    }

    /// Write `session`'s record atomically and return its path. The directory is
    /// created owner-only if absent (and tightened if it existed looser). The
    /// write is a temp-file-then-rename so a concurrent [`list`](Self::list)
    /// never observes a half-written record.
    pub(crate) fn register(&self, session: &Session) -> io::Result<PathBuf> {
        use std::fs::{DirBuilder, Permissions};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)?;
        std::fs::set_permissions(&self.dir, Permissions::from_mode(0o700))?;

        let name = session.file_name();
        let final_path = self.dir.join(&name);
        // A dotted temp name: `list` skips dotfiles, so an in-flight registration
        // is never parsed or pruned by a concurrent lister.
        let tmp_path = self.dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp_path, serialize(session))?;
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(final_path)
    }

    /// The live sessions, sorted for stable display — the live half of
    /// [`housekeep`](Self::housekeep), which also prunes the dead records as a side effect.
    pub(crate) fn list(&self) -> io::Result<Vec<Session>> {
        self.housekeep().map(|(live, _)| live)
    }

    /// Re-validate every record against its running process: return the live sessions (sorted for
    /// stable display) and the count of dead or unparseable records reaped. Pruning happens only
    /// here, so the directory is bounded by how often this runs: `ops shell` self-cleans on exit via
    /// [`RecordGuard`], an `ops run` record (no post-exec hook) lingers until the next `ops ls` or
    /// `ops gc` reaps it. `ops gc` calls this directly to report the prune; `ops ls` and the gc
    /// reaper take the live half through [`list`](Self::list).
    pub(crate) fn housekeep(&self) -> io::Result<(Vec<Session>, usize)> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            // No sessions directory yet means no sessions — not an error.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(e),
        };

        let mut live = Vec::new();
        let mut pruned = 0;
        for entry in entries {
            // A single unreadable directory entry must not abort the whole listing: the caller's
            // live-session guard (used by `ops gc` to skip a project with a running session) would
            // then see zero live sessions and could collect an in-use one. Skip the bad entry so
            // every other live record still appears — a far smaller exposure than losing them all.
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            // Skip dotfiles (in-flight temp records) and anything not a plain file.
            let is_dotfile = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('.'));
            if is_dotfile || !path.is_file() {
                continue;
            }
            match parse_record(&path) {
                Some(session) if is_alive(&session) => live.push(session),
                // Dead or corrupt: reclaim it.
                _ => {
                    if std::fs::remove_file(&path).is_ok() {
                        pruned += 1;
                    }
                }
            }
        }

        live.sort_by(|a, b| a.project.cmp(&b.project).then(a.pid.cmp(&b.pid)));
        Ok((live, pruned))
    }

    /// Remove a specific session's record (best-effort), so a session just stopped disappears from
    /// `ops ls` at once rather than lingering until liveness pruning catches it — which it would
    /// not do immediately anyway while the killed process is still a zombie reading as alive. A
    /// missing record is fine; liveness pruning remains the real cleanup.
    pub(crate) fn reap(&self, session: &Session) {
        let _ = std::fs::remove_file(self.dir.join(session.file_name()));
    }
}

/// Removes a session record when dropped — the eager, best-effort cleanup for a
/// supervised session (`ops shell`). It covers normal/error/panic exits; a
/// `SIGKILL` skips it, which is exactly why [`Registry::list`] does not rely on
/// it and prunes by liveness instead.
pub(crate) struct RecordGuard {
    path: PathBuf,
}

impl RecordGuard {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for RecordGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Serialise a record as newline-separated `key=value` lines. The project path is
/// hex-encoded from its raw bytes, so a non-UTF-8 or newline-bearing path round
/// trips exactly; the other fields are ASCII.
fn serialize(s: &Session) -> String {
    format!(
        "kind={}\npid={}\nstart={}\nruntime={}\nproject={}\n",
        s.kind.as_str(),
        s.pid,
        s.start_ticks,
        s.runtime.serialize(),
        to_hex(s.project.as_os_str().as_bytes()),
    )
}

/// Parse a record file back into a [`Session`], or `None` if any field is missing
/// or malformed (so a corrupt record is treated as prunable, never trusted).
fn parse_record(path: &Path) -> Option<Session> {
    let content = std::fs::read_to_string(path).ok()?;
    let (mut kind, mut pid, mut start, mut project) = (None, None, None, None);
    // Absent in records written before the field; defaults to the project home (back-compat).
    let mut runtime = SessionRuntime::Project;
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        match key {
            "kind" => kind = Kind::from_str(value),
            "pid" => pid = value.parse::<u32>().ok(),
            "start" => start = value.parse::<u64>().ok(),
            "runtime" => runtime = SessionRuntime::parse(value),
            "project" => project = from_hex(value).map(|b| PathBuf::from(OsString::from_vec(b))),
            _ => {}
        }
    }
    Some(Session {
        project: project?,
        pid: pid?,
        start_ticks: start?,
        kind: kind?,
        runtime,
    })
}

/// Whether `session`'s process is still the same one we registered.
///
/// `kill(pid, 0)` is only a cheap pre-filter: `ESRCH` means the pid is gone and
/// `EPERM` means it now belongs to another user (a reused pid) — both dead. A
/// success means *a* process holds the pid, which is not enough, so the decisive
/// test is always the start-time match: only the original incarnation has it.
///
/// One harmless transient: a just-exited `ops run` not yet reaped by its parent is
/// a zombie whose `/proc/<pid>/stat` still carries the original start time, so it
/// reads as alive for that brief window. Treating the zombie state as dead would
/// remove it, but the window is short and self-clears on the next listing.
fn is_alive(session: &Session) -> bool {
    let rc = unsafe { libc::kill(session.pid as libc::pid_t, 0) };
    if rc != 0 {
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) | Some(libc::EPERM) => return false,
            // An unexpected errno is inconclusive; fall through to the decisive check.
            _ => {}
        }
    }
    read_start_ticks(session.pid) == Some(session.start_ticks)
}

/// The start time (clock ticks since boot) of `pid`, or `None` if it is gone.
fn read_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_ticks(&stat)
}

/// This process's own start-time ticks, pairing with its pid to identify this incarnation across
/// pid reuse. `None` if `/proc/self/stat` is unreadable. Used to name per-session files uniquely so
/// a later process that happens to reuse the pid cannot clobber a prior session's persisted file.
pub(crate) fn current_start_ticks() -> Option<u64> {
    read_start_ticks(std::process::id())
}

/// Extract field 22 (start time) from the contents of `/proc/<pid>/stat`.
///
/// Field 2 (`comm`) is wrapped in parentheses and may itself contain spaces and
/// parentheses, so splitting the whole line on whitespace is wrong. Everything
/// after the *final* `)` is clean, space-separated fields starting at field 3, so
/// start time (field 22) is the 20th token there.
fn parse_start_ticks(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Lower-case hex encoding of raw bytes.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode lower-case hex back to bytes, or `None` on any non-hex input.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    fn session_at(project: &str, pid: u32, start: u64, kind: Kind) -> Session {
        Session {
            project: PathBuf::from(project),
            pid,
            start_ticks: start,
            kind,
            runtime: SessionRuntime::Project,
        }
    }

    /// Spawn a quiet child process and build a [`Session`] that points at it, with its real start
    /// time — so `stop` exercises the genuine pidfd signalling path against a live process.
    fn spawn_session(cmd: &str, args: &[&str]) -> (std::process::Child, Session) {
        let child = std::process::Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn test child");
        let pid = child.id();
        let start_ticks = read_start_ticks(pid).expect("read the child's start time");
        let session = Session {
            project: PathBuf::from("/test"),
            pid,
            start_ticks,
            kind: Kind::Run,
            runtime: SessionRuntime::Project,
        };
        (child, session)
    }

    /// Block until `pid`'s `comm` becomes `want`, so a test can wait for a shell to finish
    /// `exec`ing into the program it launches (e.g. for an ignored-signal disposition to be in
    /// place) before acting on it — making the test deterministic rather than racing startup.
    fn wait_for_comm(pid: u32, want: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                if comm.trim() == want {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("process {pid} never became `{want}`");
    }

    #[test]
    fn record_round_trips_through_serialization() {
        // a path with a space, a newline and a non-UTF-8 byte must survive intact
        let raw = OsString::from_vec(vec![b'/', b'a', b' ', b'\n', 0xff, b'/', b'p']);
        let s = Session {
            project: PathBuf::from(raw),
            pid: 4321,
            start_ticks: 99887766,
            kind: Kind::Shell,
            // an app runtime must round-trip too, so attach can reproduce the app's home
            runtime: SessionRuntime::GlobalApp("demo-tool".to_string()),
        };
        let dir = TmpDir::new();
        let path = dir.join("rec");
        std::fs::write(&path, serialize(&s)).unwrap();
        assert_eq!(parse_record(&path), Some(s));
    }

    #[test]
    fn a_record_without_a_runtime_line_defaults_to_the_project_home() {
        // Back-compat: a record written before the `runtime` field must parse as a project shell,
        // never panic — and a project-app runtime must round-trip the other branch.
        let dir = TmpDir::new();
        let legacy = dir.join("legacy");
        std::fs::write(&legacy, "kind=run\npid=7\nstart=42\nproject=2f70\n").unwrap();
        assert_eq!(
            parse_record(&legacy).unwrap().runtime,
            SessionRuntime::Project
        );

        let pa = Session {
            project: PathBuf::from("/w/p"),
            pid: 9,
            start_ticks: 3,
            kind: Kind::Run,
            runtime: SessionRuntime::ProjectApp("agent".to_string()),
        };
        let path = dir.join("pa");
        std::fs::write(&path, serialize(&pa)).unwrap();
        assert_eq!(parse_record(&path), Some(pa));
    }

    #[test]
    fn parse_start_ticks_handles_a_comm_with_spaces_and_parens() {
        // comm is "(weird ) name)" — spaces and a stray ')' inside it. The fields
        // after the final ')' are field 3 onward; each token n stands in for field
        // n, and field 22 (the start time) carries the sentinel value.
        let mut fields: Vec<String> = Vec::new();
        for n in 3..=32 {
            fields.push(if n == 22 { "555".into() } else { n.to_string() });
        }
        let stat = format!("1234 (weird ) name) {}", fields.join(" "));
        assert_eq!(parse_start_ticks(&stat), Some(555));
    }

    #[test]
    fn register_then_list_returns_the_live_current_process() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        let me = Session::current(
            PathBuf::from("/work/proj"),
            Kind::Run,
            SessionRuntime::Project,
        )
        .unwrap();

        reg.register(&me).unwrap();
        let listed = reg.list().unwrap();
        assert_eq!(listed, vec![me]);
    }

    #[test]
    fn list_prunes_a_pid_reused_with_a_different_start_time() {
        // The reuse guard: a record carrying *our* pid but the wrong start time
        // describes a different incarnation and must be pruned — proving liveness
        // is more than `kill(pid, 0)` (which would call our own pid alive).
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());

        let mut me = Session::current(
            PathBuf::from("/work/live"),
            Kind::Shell,
            SessionRuntime::Project,
        )
        .unwrap();
        reg.register(&me).unwrap();

        // same pid, deliberately wrong start time
        me.start_ticks = me.start_ticks.wrapping_add(1);
        me.project = PathBuf::from("/work/stale");
        reg.register(&me).unwrap();

        let listed = reg.list().unwrap();
        assert_eq!(listed.len(), 1, "only the matching incarnation is live");
        assert_eq!(listed[0].project, PathBuf::from("/work/live"));
        // the stale record file is gone
        assert!(!dir.path().join(me.file_name()).exists());
    }

    #[test]
    fn list_prunes_a_dead_pid() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        // A pid that cannot exist (above the kernel's pid ceiling): no /proc entry,
        // kill -> ESRCH.
        let dead = session_at("/work/gone", u32::MAX, 1, Kind::Run);
        reg.register(&dead).unwrap();

        assert!(reg.list().unwrap().is_empty());
        assert!(!dir.path().join(dead.file_name()).exists());
    }

    #[test]
    fn label_distinguishes_apps_from_plain_sessions() {
        assert_eq!(session_at("/p", 1, 1, Kind::Run).label(), "run");
        let mut s = session_at("/p", 1, 1, Kind::Shell);
        assert_eq!(s.label(), "shell");
        s.runtime = SessionRuntime::GlobalApp("demo-app".into());
        assert_eq!(s.label(), "app:demo-app");
        s.runtime = SessionRuntime::ProjectApp("agent".into());
        assert_eq!(s.label(), "app:agent");
    }

    #[test]
    fn stop_a_dead_pid_reports_already_gone() {
        // A pid above the kernel's ceiling cannot exist: pidfd_open fails, so there is nothing to
        // signal.
        let s = session_at("/test", u32::MAX, 1, Kind::Run);
        assert_eq!(s.stop(Duration::from_secs(5)), StopOutcome::AlreadyGone);
    }

    #[test]
    fn stop_does_not_signal_a_reused_pid() {
        // A record carrying *our own* live pid but the wrong start time describes a different
        // incarnation. `stop` must refuse to signal it — returning AlreadyGone — rather than
        // SIGTERM the running test process under that pid. This is the reuse guard that makes
        // signalling safe; without it this test would terminate the whole run.
        let mut s = session_at("/test", std::process::id(), 0, Kind::Run);
        s.start_ticks = read_start_ticks(std::process::id())
            .unwrap()
            .wrapping_add(1);
        assert_eq!(s.stop(Duration::from_secs(5)), StopOutcome::AlreadyGone);

        // Sanity: with the correct start time the same pid reads as our live incarnation — proving
        // the AlreadyGone above came from the start-time mismatch, not from the pid being absent.
        s.start_ticks = read_start_ticks(std::process::id()).unwrap();
        assert!(is_alive(&s));
    }

    #[test]
    fn stop_terminates_a_live_process_with_sigterm() {
        let (mut child, s) = spawn_session("sleep", &["30"]);
        assert!(is_alive(&s));
        assert_eq!(s.stop(Duration::from_secs(5)), StopOutcome::Terminated);
        // Reap the zombie so the start-time check below sees the pid truly gone (a not-yet-reaped
        // zombie still carries the recorded start time and would read as alive).
        let _ = child.wait();
        assert!(!is_alive(&s));
    }

    #[test]
    fn stop_kills_a_process_that_ignores_sigterm() {
        // `trap "" TERM` makes the shell ignore SIGTERM; `exec sleep` keeps that ignore (an ignored
        // disposition survives execve), so the single recorded process cannot be terminated by
        // SIGTERM and must be forced down with SIGKILL once the short grace window elapses.
        let (mut child, s) = spawn_session("sh", &["-c", "trap '' TERM; exec sleep 30"]);
        // Wait until the shell has exec'd into `sleep`: the `trap` runs before the `exec` in the
        // script, so once `comm` is `sleep` the SIGTERM-ignore is guaranteed in place. Without this
        // the stop could race the shell's startup and SIGTERM it before the trap is set.
        wait_for_comm(s.pid, "sleep");
        assert_eq!(s.stop(Duration::from_millis(300)), StopOutcome::Killed);
        let _ = child.wait();
        assert!(!is_alive(&s));
    }

    #[test]
    fn stop_tears_down_the_whole_descendant_tree() {
        // Stopping a process must take its descendants with it — the property a supervised cage
        // relies on (parent supervisor, bubblewrap + agent as descendants) that a parent-death
        // cascade does not deliver reliably. A shell that forks a child `sleep` and waits stands in
        // for that tree without needing a sandbox.
        let (mut child, s) = spawn_session("sh", &["-c", "sleep 300 & wait"]);

        // Wait for the child `sleep` to appear under the shell.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut kids = Vec::new();
        while std::time::Instant::now() < deadline {
            kids = descendants(s.pid);
            if !kids.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(kids.len(), 1, "the shell should have one child sleep");
        let (kid_pid, kid_start) = kids[0];

        assert_eq!(s.stop(Duration::from_secs(5)), StopOutcome::Terminated);
        let _ = child.wait();
        assert!(!is_alive(&s), "the recorded process is gone");

        // The child must be gone too — not orphaned. It is SIGKILLed and reaped by init; poll past
        // the brief zombie window in which its start time still reads as the original.
        let gone_by = std::time::Instant::now() + Duration::from_secs(5);
        let child_gone = loop {
            if read_start_ticks(kid_pid) != Some(kid_start) {
                break true;
            }
            if std::time::Instant::now() >= gone_by {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(child_gone, "stopping the parent orphaned its child");
    }

    #[test]
    fn reap_removes_a_specific_record() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        let s =
            Session::current(PathBuf::from("/w/p"), Kind::Run, SessionRuntime::Project).unwrap();
        let path = reg.register(&s).unwrap();
        assert!(path.exists());
        reg.reap(&s);
        assert!(!path.exists());
    }

    #[test]
    fn register_creates_an_owner_only_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        reg.register(
            &Session::current(PathBuf::from("/work/p"), Kind::Run, SessionRuntime::Project)
                .unwrap(),
        )
        .unwrap();

        let mode = std::fs::metadata(dir.path().join("sessions"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn record_guard_removes_the_record_on_drop() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        let path = reg
            .register(
                &Session::current(
                    PathBuf::from("/work/p"),
                    Kind::Shell,
                    SessionRuntime::Project,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(path.exists());

        let guard = RecordGuard::new(path.clone());
        drop(guard);
        assert!(!path.exists(), "the guard must unlink the record on drop");
    }

    #[test]
    fn list_skips_an_in_flight_temp_record() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        // seed the directory
        reg.register(
            &Session::current(PathBuf::from("/work/p"), Kind::Run, SessionRuntime::Project)
                .unwrap(),
        )
        .unwrap();
        // a dotted temp file (as register writes mid-flight) must be ignored, not
        // parsed or pruned
        let tmp = dir.path().join("sessions").join(".999-1.tmp");
        std::fs::write(&tmp, b"garbage").unwrap();

        let _ = reg.list().unwrap();
        assert!(
            tmp.exists(),
            "an in-flight temp record must be left untouched"
        );
    }

    #[test]
    fn hex_round_trips_arbitrary_bytes() {
        let bytes = [0x00u8, 0x0f, 0xff, 0x42, 0xa0];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("abc"), None); // odd length
    }
}
