//! The on-disk session registry (no daemon).
//!
//! Each running sandbox writes a small record under `<data>/sessions/`; `sbx session ls`
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
//! `execve`, so registering just before `sbx run` execs into bubblewrap is safe:
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

/// What kind of sandbox a record describes. Both are tracked: a command launch (`sbx run
/// <cmd>`) is the autonomous-agent path (the sandboxes the registry most needs to surface)
/// and a shell (`sbx run` with no command) the interactive one.
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

/// Which persistent home a session runs in — the bit `sbx session attach` needs to reproduce the same
/// environment. A plain `sbx run` uses the project's default home (`Project`); an
/// `sbx app` uses its own isolated home, keyed by the app name and its scope (`GlobalApp` shared
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
    /// Nothing was signalled and the session may well still be running: opening a handle on its
    /// process failed for a reason other than that process being absent. Carries the `errno`, so
    /// the report can name it — and so a caller knows it must neither claim a stop nor drop the
    /// session's record.
    NotSignalled(i32),
}

/// One registered sandbox. The `(pid, start_ticks)` pair identifies the live
/// process; `project` is the canonical project root (display and identity); `runtime` is the home
/// it runs in, so `sbx session attach` can reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Session {
    pub(crate) project: PathBuf,
    pub(crate) pid: u32,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat` field 22).
    ///
    /// Pins the pid to one incarnation, defeating pid reuse.
    pub(crate) start_ticks: u64,
    pub(crate) kind: Kind,
    pub(crate) runtime: SessionRuntime,
    /// Whether the session runs as a background daemon (`--detach`) rather than in the
    /// launching terminal. It is the bit that decides where the session's output went: a
    /// detached session's stdout/stderr is redirected to a log file, so it is the only kind
    /// `sbx session logs` can read; a foreground one writes to the terminal that started it.
    pub(crate) detached: bool,
}

impl Session {
    /// Describe the *current* process as a session for `project`. Reads this
    /// process's own start time so the record can later be matched against it.
    ///
    /// Foreground by default: the detached launch marks its own record with
    /// [`Session::detached`], so a caller that forgets cannot claim a log that does not exist.
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
            detached: false,
        })
    }

    /// Mark this record as a detached (background daemon) session.
    pub(crate) fn detached(mut self) -> Self {
        self.detached = true;
        self
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

    /// The app this session runs as (`sbx app <name>`), or `None` for a plain project shell/run — so
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
        // Only `ESRCH` says the process is gone. Every other refusal means this stop could not get
        // a handle on a process that may still be running, and reporting "already gone" there
        // would be both a false statement and a lost session: the caller drops the record on every
        // outcome but this one, so a live cage would stop being listable — or nameable to a second
        // attempt. This is the rule [`pid_is_live`] already states for `kill(2)` (an unexpected
        // errno is inconclusive, never "dead"), applied to the one liveness answer in this module
        // that read every failure as absence.
        let pidfd = match open_pidfd(self.pid) {
            Ok(fd) => fd,
            Err(libc::ESRCH) => return StopOutcome::AlreadyGone,
            Err(errno) => return StopOutcome::NotSignalled(errno),
        };
        // Confirm the pinned process is the one we recorded: the pid could have been reused
        // between listing and the open. Once confirmed, the held fd keeps it pinned.
        //
        // A start time that cannot be read counts as gone here, and only here: the pidfd is proof
        // the process existed a moment ago, so `/proc/<pid>/stat` being absent now means it exited
        // and was reaped — not that this stop failed to look. The residual is an entry that exists
        // but cannot be opened (descriptors exhausted between the two calls); it stays folded into
        // "gone" because the open a line above just succeeded, and telling it apart would need an
        // outcome of its own for a window one syscall wide.
        if read_start_ticks(self.pid) != Some(self.start_ticks) {
            close_fd(pidfd);
            return StopOutcome::AlreadyGone;
        }
        // Snapshot the cage members now, while the recorded process is still pinned. Two sources,
        // unioned: the ppid subtree of the recorded process, and — the reliable one — the members of
        // the cage's transient systemd scope, read from its cgroup. The subtree alone is racy: the
        // resource-limit scope can reparent the cage out of the launcher's subtree (onto the systemd
        // user manager), so `descendants` may miss it and leave the agent running after the launcher
        // is signalled. The scope's cgroup lists exactly the cage's processes regardless of parentage.
        let cage = union_cage_members(descendants(self.pid), scope_members(self.pid));
        let outcome = stop_pinned(pidfd, &cage, grace);
        close_fd(pidfd);
        outcome
    }
}

/// Merge the two cage-member sources — the launcher's ppid subtree and the scope cgroup — into one
/// list, dropping a pid that appears in both. The scope members are the load-bearing half: when the
/// resource-limit scope has reparented the cage off the launcher, the ppid subtree is empty or
/// partial and only the scope cgroup still names the cage, so a teardown that dropped them would
/// leave the agent running.
fn union_cage_members(mut subtree: Vec<(u32, u64)>, scope: Vec<(u32, u64)>) -> Vec<(u32, u64)> {
    for member in scope {
        if !subtree.iter().any(|&(p, _)| p == member.0) {
            subtree.push(member);
        }
    }
    subtree
}

/// The members of the cage's transient resource-limit scope, as `(pid, start_ticks)`.
///
/// The launch wraps the cage in a systemd user scope whose unit name embeds the launcher's pid —
/// `sbx-<slug>-<pid>.scope`, the same pid the session record pins — and the scope's cgroup lists
/// exactly the cage's processes. Reading it gives a teardown a reliable member set even when the
/// ppid subtree does not (a scope can reparent the cage off the launcher). Empty when no scope was
/// created (the best-effort degraded launch on a host without a usable systemd user manager), in
/// which case the ppid subtree is the only source and covers that case.
fn scope_members(pid: u32) -> Vec<(u32, u64)> {
    let Some(procs) = scope_cgroup_procs(pid) else {
        return Vec::new();
    };
    procs
        .split_whitespace()
        .filter_map(|s| s.parse::<u32>().ok())
        .filter_map(|p| read_start_ticks(p).map(|start| (p, start)))
        .collect()
}

/// Whether a cgroup directory name is the cage scope for `pid` — `sbx-<slug>-<pid>.scope`. The
/// `-<pid>` segment is dash-delimited, so a longer pid ending in the same digits (or a slug ending
/// in digits) cannot match by accident; the name is parsed by the module that builds it, so this
/// property and the sweep's both rest on one reading of the format.
fn is_cage_scope(name: &str, pid: u32) -> bool {
    crate::sandbox::cgroup::scope_launcher_pid(name) == Some(pid)
}

/// Find the cage scope's `cgroup.procs` contents. `None` if no such scope exists (a launch degraded
/// to no scope) or the cgroup is unreadable.
fn scope_cgroup_procs(pid: u32) -> Option<String> {
    let dir = crate::sandbox::cgroup::cage_scope_dirs()
        .into_iter()
        .find(|d| {
            d.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| is_cage_scope(n, pid))
        })?;
    std::fs::read_to_string(dir.join("cgroup.procs")).ok()
}

/// Open a pidfd for `pid`, or the `errno` the kernel refused with.
///
/// Shared with the resolver runner, which arms a deadline on a plugin process the same way a stop
/// pins a session's: these three calls are the one place the syscalls are spelled, so a second
/// caller cannot end up pinning a process by a rule of its own.
///
/// The errno is carried out instead of being folded into "gone", because only `ESRCH` means the
/// process has exited. `pidfd_open` also refuses a pid no process can hold (`EINVAL`), reports the
/// syscall as unavailable (`ENOSYS`, on a kernel older than 5.3 or under a filter that hides it),
/// and fails when *this* process is out of descriptors or memory (`EMFILE`, `ENFILE`, `ENOMEM`) —
/// none of which say anything about whether the target is alive.
pub(crate) fn open_pidfd(pid: u32) -> Result<libc::c_int, i32> {
    // SAFETY: `pidfd_open` only reads `pid`; it returns a new fd, or -1 with `errno` set.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd >= 0 {
        return Ok(fd as libc::c_int);
    }
    // `last_os_error` reads the `errno` the failed syscall just set and always carries one; the
    // fallback exists only to keep the signature total.
    Err(io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO))
}

pub(crate) fn close_fd(fd: libc::c_int) {
    // SAFETY: closing a fd we opened.
    unsafe { libc::close(fd) };
}

/// Send `signal` to the process a pidfd pins. Returns whether the kernel accepted it (a failure
/// means the process has already exited).
///
/// Unlike the *open*, this failure is not read errno by errno, deliberately: the fd already pins
/// one live-or-zombie process, so the refusals [`open_pidfd`] must tell apart — no such syscall,
/// a pid no process can hold, no descriptor left — cannot arise once it has succeeded, and what
/// remains is the target being reaped between the open and the signal. A caller that ever holds a
/// pidfd it did not open itself, or signals across a user boundary (`EPERM`), leaves that ground
/// and would have to discriminate here too.
pub(crate) fn send_signal(pidfd: libc::c_int, signal: libc::c_int) -> bool {
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
///
/// `EINTR` resumes against the original deadline rather than being reported as "still running".
/// `poll` is interrupted by any signal the waiting process handles — a `SIGWINCH` from a resized
/// terminal is enough — and the caller ([`stop_pinned`]) reads a `false` as the grace having run
/// out, so a single stray signal would cut the shutdown window short and `SIGKILL` an agent that
/// was still cleaning up. Every other failure still returns `false`: the descriptor is ours and
/// the process is pinned, so nothing else is recoverable by waiting longer.
pub(crate) fn wait_for_exit(pidfd: libc::c_int, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let deadline = std::time::Instant::now() + timeout;
    let mut remaining = timeout;
    loop {
        let ms = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: polling one fd we own.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc > 0 {
            return true;
        }
        if rc == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
        // Interrupted: what is left of the original window, or nothing if it elapsed meanwhile.
        remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
    }
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
/// never signalled by mistake.
///
/// The pidfd is opened **first**, and that ordering is the guard rather than an optimisation. A
/// bare `kill` behind a start-time check leaves a window: between reading `/proc/<pid>/stat` and the
/// call, the process can exit and the kernel hand its number to something else, which is then
/// signalled in its place. Holding a pidfd keeps the number reserved for as long as it is open, so
/// the start time read after it describes the process the signal will reach — the same pinning the
/// recorded process already had, extended to the cage members it was not covering.
///
/// A pidfd that cannot be opened means nothing is signalled: without it the identity cannot be held
/// still, and this is a sweep of things that are already meant to be dying, not a step a launch
/// depends on.
fn signal_if_match(pid: u32, start_ticks: u64, signal: libc::c_int) {
    let Ok(pidfd) = open_pidfd(pid) else {
        return;
    };
    if read_start_ticks(pid) == Some(start_ticks) {
        let _ = send_signal(pidfd, signal);
    }
    close_fd(pidfd);
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
    walk_descendants(&children, &start_of, root)
}

/// The graph half of [`descendants`]: walk `root`'s subtree of a `parent -> children` map, pairing
/// each pid with its start time. Split out because the `/proc` half cannot be exercised in a test —
/// a cycle in the parent graph is not something a test can arrange on a live kernel — and the walk
/// is where the termination guarantee lives.
fn walk_descendants(
    children: &HashMap<u32, Vec<u32>>,
    start_of: &HashMap<u32, u64>,
    root: u32,
) -> Vec<(u32, u64)> {
    let mut out = Vec::new();
    // The visited set both sibling walkers carry (`observe::descendants_of` and
    // `sandbox::observe_feed::descendant_pids`), for the reason they state: `/proc` is read pid by
    // pid without a consistent snapshot, so a process that exits and whose pid is reused mid-walk
    // can produce a parent edge pointing back into the part already walked. Following that edge
    // walks the same subtree again, and a full cycle never terminates — in `sbx session stop`, a
    // hang with signals still to deliver. The root is seeded so a back-edge onto it is refused too.
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(root);
    let mut stack = vec![root];
    while let Some(parent) = stack.pop() {
        let Some(kids) = children.get(&parent) else {
            continue;
        };
        for &kid in kids {
            if let Some(&start) = start_of.get(&kid)
                && seen.insert(kid)
            {
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
    /// The registry under sbx's data directory.
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

    /// The same answer, without touching the directory: for a caller that is *asking*, not tidying.
    ///
    /// The two are separated because most callers only ever wanted the question. `sbx net pending`
    /// cross-references a pid against the registry; `sbx session logs --follow` asks whether the
    /// session it is following is still there, four times a second for the whole of an agent's run.
    /// Going through [`list`](Self::list) made each of those a full reclamation pass — a readdir, a
    /// parse, a `kill` and a `/proc` read per record, and an unlink for every record that had died —
    /// which is not what the caller asked for and not what `FOLLOW_POLL` was costed against. It also
    /// quietly took the work `sbx gc` reports, so the count gc prints was whatever a concurrent
    /// reader had left it.
    ///
    /// Reclaiming stays with the verbs that mean it: `sbx session ls`, `sbx session stop`, `sbx gc`.
    pub(crate) fn live(&self) -> io::Result<Vec<Session>> {
        self.scan(false).map(|(live, _)| live)
    }

    /// Re-validate every record against its running process: return the live sessions (sorted for
    /// stable display) and the count of dead or unparseable records reaped. Pruning happens only
    /// here, so the directory is bounded by how often this runs: an interactive `sbx run` self-cleans on exit via
    /// [`RecordGuard`], an `sbx run` record (no post-exec hook) lingers until the next `sbx session ls` or
    /// `sbx gc` reaps it. `sbx gc` calls this directly to report the prune; `sbx session ls` and the gc
    /// reaper take the live half through [`list`](Self::list).
    pub(crate) fn housekeep(&self) -> io::Result<(Vec<Session>, usize)> {
        self.scan(true)
    }

    /// One walk over the records, with `prune` deciding whether a dead or unparseable one is
    /// removed or merely left out of the answer. Written once so the two readings can never
    /// disagree on what "live" means — which is the whole reason a caller that only asks is allowed
    /// to skip the tidying.
    fn scan(&self, prune: bool) -> io::Result<(Vec<Session>, usize)> {
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
            // live-session guard (used by `sbx gc` to skip a project with a running session) would
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
                // Dead or corrupt: reclaim it, if reclaiming is what this walk is for.
                _ => {
                    if prune && std::fs::remove_file(&path).is_ok() {
                        pruned += 1;
                    }
                }
            }
        }

        live.sort_by(|a, b| a.project.cmp(&b.project).then(a.pid.cmp(&b.pid)));
        Ok((live, pruned))
    }

    /// Remove a specific session's record (best-effort), so a session just stopped disappears from
    /// `sbx session ls` at once rather than lingering until liveness pruning catches it — which it would
    /// not do immediately anyway while the killed process is still a zombie reading as alive. A
    /// missing record is fine; liveness pruning remains the real cleanup.
    pub(crate) fn reap(&self, session: &Session) {
        let _ = std::fs::remove_file(self.dir.join(session.file_name()));
    }
}

/// Removes a session record when dropped — the eager, best-effort cleanup for a
/// supervised session (an interactive `sbx run`). It covers normal/error/panic exits; a
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
        "kind={}\npid={}\nstart={}\nruntime={}\ndetached={}\nproject={}\n",
        s.kind.as_str(),
        s.pid,
        s.start_ticks,
        s.runtime.serialize(),
        u8::from(s.detached),
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
    // Likewise absent in older records, and likewise fail-safe: an unmarked record reads as a
    // foreground session, so a listing never promises a log file that was never written.
    let mut detached = false;
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
            "detached" => detached = value == "1",
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
        detached,
    })
}

/// Whether `session`'s process is still the same one we registered.
///
/// [`pid_is_live`] is only a cheap pre-filter: a live pid means *a* process holds it, which is not
/// enough, so the decisive test is always the start-time match — only the original incarnation
/// has it.
///
/// One harmless transient: a just-exited `sbx run` not yet reaped by its parent is
/// a zombie whose `/proc/<pid>/stat` still carries the original start time, so it
/// reads as alive for that brief window. Treating the zombie state as dead would
/// remove it, but the window is short and self-clears on the next listing.
fn is_alive(session: &Session) -> bool {
    pid_is_live(session.pid) && read_start_ticks(session.pid) == Some(session.start_ticks)
}

/// Whether *some* process currently holds `pid` — the cheap pre-filter half of [`is_alive`],
/// exposed for the callers that have only a pid to go on.
///
/// `ESRCH` means the pid is gone and `EPERM` means it now belongs to another user (so the
/// original is gone either way); both read as dead. An unexpected errno is inconclusive and reads
/// as live, which is the conservative direction for a caller that deletes what reads as dead.
///
/// This answers *"is the pid taken"*, not *"is it the same process"* — a reused pid reads as live.
/// A caller that recorded a start time must pair this with that match ([`is_alive`] does); one
/// keyed by a bare pid cannot, and merely keeps a stale entry a while longer.
pub(crate) fn pid_is_live(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc != 0
        && let Some(libc::ESRCH) | Some(libc::EPERM) = io::Error::last_os_error().raw_os_error()
    {
        return false;
    }
    true
}

/// The start time (clock ticks since boot) of `pid`, or `None` if it is gone.
pub(crate) fn read_start_ticks(pid: u32) -> Option<u64> {
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

    #[test]
    fn union_cage_members_keeps_scope_members_when_the_ppid_subtree_misses_them() {
        // The exact regression the fix guards: the resource-limit scope reparented the cage off the
        // launcher, so the ppid subtree is empty — the scope cgroup's members are the only ones that
        // reach the teardown sweep. A revert to descendants-only would return `[]` and fail here.
        assert_eq!(
            union_cage_members(vec![], vec![(10, 1), (11, 2)]),
            vec![(10, 1), (11, 2)]
        );
        // Both sources name the same process: no duplicate (a double SIGKILL is harmless, but the
        // dedup keeps the sweep list honest).
        assert_eq!(
            union_cage_members(vec![(10, 1)], vec![(10, 1)]),
            vec![(10, 1)]
        );
        // Disjoint sources are combined.
        assert_eq!(
            union_cage_members(vec![(10, 1)], vec![(11, 2)]),
            vec![(10, 1), (11, 2)]
        );
        // No scope (degraded launch, no systemd): the ppid subtree is used unchanged.
        assert_eq!(union_cage_members(vec![(10, 1)], vec![]), vec![(10, 1)]);
    }

    #[test]
    fn is_cage_scope_matches_the_pid_at_a_dash_boundary() {
        // The exact cage scope for pid 42.
        assert!(is_cage_scope("sbx-probe-42.scope", 42));
        // A slug that itself contains digits/dashes still matches on the pid segment.
        assert!(is_cage_scope("sbx-my-app-2-42.scope", 42));
        // A longer pid ending in the same digits must NOT match (no dash boundary).
        assert!(!is_cage_scope("sbx-probe-342.scope", 42));
        // A shorter pid that is a suffix of the real one must NOT match.
        assert!(!is_cage_scope("sbx-probe-342.scope", 2));
        // Not a cage scope / not a scope / wrong pid.
        assert!(!is_cage_scope("user-1000.slice", 42));
        assert!(!is_cage_scope("sbx-probe-42.service", 42));
        assert!(!is_cage_scope("other-probe-42.scope", 42));
        assert!(!is_cage_scope("sbx-probe-99.scope", 42));
    }

    /// A pid no process can hold: above `PID_MAX_LIMIT`, the ceiling `/proc/sys/kernel/pid_max`
    /// itself cannot exceed (4 194 304 on 64-bit, 32 768 on 32-bit). Both halves of the liveness
    /// check answer "absent" for it, and `pidfd_open` answers `ESRCH`.
    ///
    /// `u32::MAX` does not serve: it casts to `pid_t` as -1, which `kill` reads as *every* process
    /// the caller may signal — so the pid reads as **live** — and which `pidfd_open` refuses with
    /// `EINVAL`, the errno that now means "could not look", not "gone".
    const PID_ABOVE_CEILING: u32 = 1 << 30;

    fn session_at(project: &str, pid: u32, start: u64, kind: Kind) -> Session {
        Session {
            project: PathBuf::from(project),
            pid,
            start_ticks: start,
            kind,
            runtime: SessionRuntime::Project,
            detached: false,
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
            detached: false,
        };
        (child, session)
    }

    /// Block until `pid`'s `comm` becomes `want`, so a test can wait for a shell to finish
    /// `exec`ing into the program it launches (e.g. for an ignored-signal disposition to be in
    /// place) before acting on it — making the test deterministic rather than racing startup.
    fn wait_for_comm(pid: u32, want: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                && comm.trim() == want
            {
                return;
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
            // set, so the round-trip covers the non-default direction: a detached record that
            // parsed back as foreground would make `sbx session ls` hide the one session whose
            // output `sbx session logs` can actually read.
            detached: true,
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
            detached: false,
        };
        let path = dir.join("pa");
        std::fs::write(&path, serialize(&pa)).unwrap();
        assert_eq!(parse_record(&path), Some(pa));
    }

    #[test]
    fn a_record_without_a_detached_line_reads_as_a_foreground_session() {
        // Back-compat and fail-safe in one: a record written before the `detached` field must
        // parse, and must read as *foreground* — the direction that promises no log file. The
        // opposite default would make `sbx session ls` mark every pre-existing session detached
        // and point `sbx session logs` at a file that was never written.
        let dir = TmpDir::new();
        let legacy = dir.join("legacy");
        std::fs::write(
            &legacy,
            "kind=run\npid=7\nstart=42\nruntime=project\nproject=2f70\n",
        )
        .unwrap();
        assert!(!parse_record(&legacy).unwrap().detached);

        // An unparseable value is not "detached" either: only the exact `1` sets it.
        let odd = dir.join("odd");
        std::fs::write(
            &odd,
            "kind=run\npid=7\nstart=42\ndetached=yes\nproject=2f70\n",
        )
        .unwrap();
        assert!(!parse_record(&odd).unwrap().detached);
    }

    #[test]
    fn detached_marks_the_record_and_current_defaults_to_foreground() {
        // The builder is the only way a record becomes detached, so a launch path that forgets to
        // call it registers a foreground session rather than claiming a log it never opened.
        let me = Session::current(PathBuf::from("/w/p"), Kind::Run, SessionRuntime::Project)
            .expect("read this process's session identity");
        assert!(!me.detached, "current() must default to foreground");
        assert!(me.detached().detached, "detached() must set the flag");
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
        let stale = reg.register(&me).unwrap();

        let listed = reg.list().unwrap();
        assert_eq!(listed.len(), 1, "only the matching incarnation is live");
        assert_eq!(listed[0].project, PathBuf::from("/work/live"));
        // the stale record file is gone — asked of the path `register` returned, since a path
        // rebuilt from the record's name misses the `sessions/` directory it actually lives in and
        // would read as absent however the walk behaves.
        assert!(!stale.exists());
    }

    #[test]
    fn list_prunes_a_dead_pid() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        // A pid that cannot exist (above the kernel's pid ceiling): no /proc entry,
        // kill -> ESRCH.
        let dead = session_at("/work/gone", PID_ABOVE_CEILING, 1, Kind::Run);
        let record = reg.register(&dead).unwrap();

        assert!(reg.list().unwrap().is_empty());
        assert!(!record.exists(), "the dead record is reclaimed");
    }

    /// Asking is not tidying: a read that only wants to know leaves the directory as it found it.
    ///
    /// The distinction is load-bearing in two places. `sbx session logs --follow` asks this
    /// question four times a second for as long as an agent runs, and a reclamation pass on every
    /// poll is not what that interval was costed against. And `sbx gc` reports how many records it
    /// reclaimed, which is only true of gc if a reader has not silently done it first.
    #[test]
    fn a_read_that_only_asks_leaves_the_dead_record_for_a_verb_that_reclaims() {
        let dir = TmpDir::new();
        let reg = Registry::at(dir.path());
        let dead = session_at("/work/gone", PID_ABOVE_CEILING, 1, Kind::Run);
        // The path comes from `register` rather than being rebuilt here: the registry keeps its
        // records in a `sessions/` subdirectory, so a rebuilt path names a file that never existed
        // and an assertion on its absence holds whatever the code does.
        let record = reg.register(&dead).unwrap();

        assert!(
            reg.live().unwrap().is_empty(),
            "a dead record is not a live session under either reading"
        );
        assert!(record.exists(), "...but asking must not be what removes it");

        let (live, pruned) = reg.housekeep().unwrap();
        assert!(live.is_empty());
        assert_eq!(
            pruned, 1,
            "the verb that reclaims still gets the work to do"
        );
        assert!(!record.exists());
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
        // A pid above the kernel's ceiling cannot exist, so `pidfd_open` answers `ESRCH` — the one
        // errno that means the process is gone, and now the only one this outcome is reached by.
        let s = session_at("/test", PID_ABOVE_CEILING, 1, Kind::Run);
        assert_eq!(s.stop(Duration::from_secs(5)), StopOutcome::AlreadyGone);
    }

    #[test]
    fn stop_reports_a_pid_it_cannot_open_rather_than_calling_it_gone() {
        // Pid 0 is not a pid a process can hold, and `pidfd_open` refuses it with `EINVAL` — a
        // refusal that says nothing about any process being alive. The stop must carry that out
        // rather than report the session as already exited: its caller drops the record on
        // `AlreadyGone`, so answering "gone" to *any* failed open turns a live cage into one no
        // listing shows and no second `stop` can name. `EMFILE` under descriptor exhaustion is the
        // same refusal on a genuinely running session; pid 0 is how a test reaches it without
        // having to exhaust anything.
        let s = session_at("/test", 0, 1, Kind::Run);
        assert_eq!(
            s.stop(Duration::from_secs(5)),
            StopOutcome::NotSignalled(libc::EINVAL)
        );
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

    /// A cage member is signalled only when its start time is the one recorded.
    ///
    /// This is the guard `stop` applies to the session's own process through a pidfd, tested on the
    /// path that sweeps the rest of the cage. What the pidfd adds cannot be seen from here: it keeps
    /// the kernel from handing the number to something else between the check and the signal, which
    /// is a window, not an outcome. What is observable is the rule itself, and a mutation that
    /// dropped it would be seen here rather than at the next pid the kernel recycles.
    #[test]
    fn a_cage_member_is_signalled_only_under_the_start_time_recorded() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep");
        let pid = child.id();
        let start = read_start_ticks(pid).expect("the child's start time");

        signal_if_match(pid, start.wrapping_add(1), libc::SIGKILL);
        // Waited for, and read through `try_wait` rather than through the start time: a process
        // killed but not yet reaped is a zombie whose `/proc/<pid>/stat` still carries the very
        // start time recorded, so reading that would have called a killed child alive. Measured —
        // the first version of this test passed with the guard removed.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            child.try_wait().expect("the child can be polled").is_none(),
            "a wrong start time must signal nothing"
        );

        signal_if_match(pid, start, libc::SIGKILL);
        let status = child.wait().expect("the child is reaped");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "the recorded incarnation is signalled"
        );
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

    /// `/proc` is read pid by pid with no consistent snapshot, so the parent graph the walk is
    /// handed can carry an edge back into a subtree already visited — a pid the kernel reused
    /// between two reads. Following it walks that subtree again, and a full cycle never terminates:
    /// `sbx session stop` hangs with signals still to deliver, which is the one moment a user
    /// cannot wait. The two sibling walkers in this codebase both carry a visited set for exactly
    /// this; this one did not.
    #[test]
    fn a_cycle_in_the_parent_graph_does_not_make_the_walk_spin() {
        // 1 -> 2 -> 3 -> 2: the back-edge closes a loop below the root.
        let children: HashMap<u32, Vec<u32>> =
            HashMap::from([(1, vec![2]), (2, vec![3]), (3, vec![2])]);
        let start_of: HashMap<u32, u64> = HashMap::from([(2, 20), (3, 30)]);

        let mut out = walk_descendants(&children, &start_of, 1);
        out.sort_unstable();
        assert_eq!(
            out,
            vec![(2, 20), (3, 30)],
            "each descendant is reported once, and the walk returns"
        );

        // A back-edge onto the root itself is refused too, so the root is never reported as its own
        // descendant.
        let onto_root: HashMap<u32, Vec<u32>> = HashMap::from([(1, vec![2]), (2, vec![1])]);
        let starts: HashMap<u32, u64> = HashMap::from([(1, 10), (2, 20)]);
        assert_eq!(walk_descendants(&onto_root, &starts, 1), vec![(2, 20)]);
    }

    #[test]
    fn stop_tears_down_the_whole_descendant_tree() {
        // Stopping a process must take its descendants with it — the property a supervised cage
        // relies on (parent supervisor, bubblewrap + agent as descendants) that a parent-death
        // cascade does not deliver reliably. A shell that forks a child `sleep` and waits stands in
        // for that tree without needing a sandbox.
        let (mut child, s) = spawn_session("sh", &["-c", "sleep 300 & wait"]);

        // The wait stops on the condition the assertion below reads — one descendant, not at least
        // one. A shell that is still assembling its child tree can show a count the assertion would
        // reject, and stopping at the weaker condition would hand it exactly that; stopping at the
        // stronger one leaves the deadline to absorb any transient state, so a count that is wrong
        // for longer than the deadline is still the failure it should be.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut kids = Vec::new();
        while std::time::Instant::now() < deadline {
            kids = descendants(s.pid);
            if kids.len() == 1 {
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

    /// A signal arriving while the grace period runs must not be read as the grace having
    /// expired. The child outlives the interrupts, so a `wait_for_exit` that surrendered on the
    /// first `EINTR` returns `false` here well before the child is gone — and on the caller's side
    /// ([`stop_pinned`]) that `false` is what escalates a still-cleaning-up agent to `SIGKILL`.
    #[test]
    fn a_signal_during_the_wait_does_not_end_it_early() {
        // A handler that does nothing: the point is only that the signal is delivered rather than
        // killing the test process, and that it interrupts the `poll` below.
        extern "C" fn noop(_: libc::c_int) {}
        // SAFETY: installing a no-op handler for a signal this test alone sends, and sends only to
        // the thread it names below.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = noop as *const () as usize;
            // No `SA_RESTART`: an automatically restarted `poll` would never surface the `EINTR`
            // this test is about.
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        }

        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .unwrap();
        let pidfd = open_pidfd(child.id()).unwrap();

        // SAFETY: `pthread_self` on the waiting thread, handed to a signaller thread so the
        // interrupts land on the `poll` and not on some unrelated harness thread.
        let waiter = unsafe { libc::pthread_self() };
        let signaller = std::thread::spawn(move || {
            for _ in 0..5 {
                std::thread::sleep(Duration::from_millis(20));
                // SAFETY: signalling a live thread of this process with an installed handler.
                unsafe { libc::pthread_kill(waiter, libc::SIGUSR1) };
            }
        });

        let exited = wait_for_exit(pidfd, Duration::from_secs(10));
        signaller.join().unwrap();
        close_fd(pidfd);
        let _ = child.wait();
        assert!(
            exited,
            "the wait must resume across signals and observe the child's exit"
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
