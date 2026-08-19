//! In-supervisor observation — the host-side half of process and filesystem observation.
//!
//! When observation is on, the launch is forced onto a supervised path (a parent that outlives the
//! cage), and observation runs from there. The **exec lens** (this module's [`ExecObserver`]) polls the
//! cage's process set from `/proc` on a short interval, diffs successive snapshots, and for each
//! newly-seen process pushes an event into the exec ring — read out-of-band by `sbx proc logs` — and,
//! on the foreground non-tty path, also echoes a `[sbx:exec] <cmd>` line to stderr inline with the run.
//! The **filesystem lens** ([`super::fs_watch`]) watches the project tree with inotify and pushes each
//! write into the fs ring, read by `sbx fs logs`.
//!
//! The exec lens roots on the supervisor's own pid (`std::process::id()`): the cage's processes are its
//! descendants in host pid-space (the same vantage point [`crate::observe`] and `sbx proc ls` use),
//! so a `/proc` walk from that root sees the whole tree. No privilege, no cage cooperation.
//!
//! [`Observation`] assembles both lenses — each with its own ring, control socket + serve thread, and
//! observer — and unlinks the sockets on drop; it is the observe analogue of the egress guard, and the
//! same substrate the later seccomp user-notification enforcement will reuse. The two lenses degrade
//! **independently**: a failure to stand one up warns and leaves the other running.
//!
//! Honest limit: the exec poll only sees a process that outlives a tick, so very short-lived commands
//! are missed. Precise, per-`execve` capture (and the blocking that rides on it) is the seccomp
//! user-notification path, a later increment; these feeds are the cheap, unprivileged first cut.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use super::fs_control::{self, FS_RING_CAP, FsRing, fs_control_dir, fs_control_socket};
use super::fs_watch::FsWatcher;
use super::proc_control::{self, EXEC_RING_CAP, ExecRing, proc_control_dir, proc_control_socket};
use crate::observe::{self, ProcInfo};

/// How often the observer polls `/proc` for new cage processes. Short enough to catch most of what an
/// agent spawns, long enough that the walk's cost is negligible; a command shorter than this between
/// ticks is missed (the polling limit, closed by the seccomp user-notification path).
pub(crate) const OBSERVE_POLL_INTERVAL: Duration = Duration::from_millis(300);

/// The launch plumbing (bubblewrap, and systemd-run on the scoped path) between the supervisor and
/// the agent's command; not "the agent spawning something", so it is filtered out of the feed.
fn is_plumbing(comm: &str) -> bool {
    matches!(comm, "bwrap" | "systemd-run" | "socat")
}

/// The descendant pids of `root` (excluding `root`) from a flat process table. Pure and
/// cycle-safe, so the diff logic is unit-tested without touching `/proc`.
fn descendant_pids(table: &BTreeMap<u32, ProcInfo>, root: u32) -> Vec<u32> {
    let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (&pid, info) in table {
        if pid != info.ppid {
            kids.entry(info.ppid).or_default().push(pid);
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    seen.insert(root); // never re-add the root itself via a back-edge in a malformed graph
    let mut stack = vec![root];
    while let Some(p) = stack.pop() {
        if let Some(cs) = kids.get(&p) {
            for &c in cs {
                if seen.insert(c) {
                    out.push(c);
                    stack.push(c);
                }
            }
        }
    }
    out
}

/// The command shown for a process: its argv joined, or `[comm]` when the argv is empty (a kernel
/// thread or an unreadable cmdline). Sanitised before it leaves here — the value feeds both the
/// line-based control wire and the stderr feed, so control characters (an argv carrying a newline)
/// are replaced with a space, and the result is length-capped, so a hostile argv can neither inject a
/// forged event line nor bloat the ring.
fn command_of(info: &ProcInfo) -> String {
    let raw = if info.args.is_empty() {
        format!("[{}]", info.comm)
    } else {
        info.args.join(" ")
    };
    sanitize(&raw)
}

/// Replace ASCII/Unicode control characters with a space and cap the length (on a char boundary), so
/// the value is safe on the line-based control wire, the stderr feed, and any terminal reading
/// either. A Linux filename may carry a newline exactly as a hostile argv can.
///
/// # What now depends on this, and why it must not be narrowed
///
/// It began as the exec lens's own and is now the crate's one answer to a value the cage chooses.
/// Six sinks reach it, and on each one it is the only filter between a name the cage picked and a
/// line somebody reads:
///
/// - [`command_of`], for the exec feed's inline stderr echo;
/// - [`super::fs_watch`], for a project-relative path;
/// - [`super::proc_control::ExecRing::push_verdict`], the door every exec event enters by —
///   including the seccomp supervisor's, whose target path is read out of the calling process's own
///   memory and whose caller is a `/proc/<pid>/exe` link;
/// - [`super::notify_sink`], where the stderr fallback composes one line per announcement, the lines
///   a detached session leaves in the log `sbx logs` reads;
/// - [`super::egress_stats`], for a destination host in a tab-delimited row;
/// - and `crate::observe`, outside this module through the [`super::sanitize`] re-export, for the
///   `sbx proc ls` tree.
///
/// Each of those was, at some point, a place a caged process could write a line of its own. Narrowing
/// what this replaces, or moving it somewhere a caller stops finding it, reopens all of them at once
/// and nothing will fail to say so — a forged line is well-formed by construction.
pub(crate) fn sanitize(s: &str) -> String {
    const MAX: usize = 512;
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.chars().count() <= MAX {
        cleaned
    } else {
        let mut out: String = cleaned.chars().take(MAX - 1).collect();
        out.push('…');
        out
    }
}

/// A running exec-activity observer. The thread pushes each newly-seen cage process into the shared
/// exec ring and — when `inline` — also echoes it to stderr. It stops and is joined on drop (mirroring
/// the relay guards), so it never outlives the supervised wait.
pub(crate) struct ExecObserver {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ExecObserver {
    /// Start observing the cage rooted at `root` (the supervisor's own pid), pushing each new process
    /// into `ring`. With `inline`, each event is also written to stderr (the foreground non-tty feed);
    /// an interactive or detached session leaves it `false` and reads the ring out-of-band instead.
    pub(crate) fn start(root: u32, interval: Duration, ring: Arc<ExecRing>, inline: bool) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let color = inline && std::io::IsTerminal::is_terminal(&std::io::stderr());
        let handle =
            std::thread::spawn(move || run_loop(root, interval, &flag, color, &ring, inline));
        ExecObserver {
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for ExecObserver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// The poll loop: each tick, snapshot the cage's descendants, record any newly-seen non-plumbing
/// process (into the ring, and to stderr when `inline`), then sleep in short slices so a stop is
/// honoured promptly.
fn run_loop(
    root: u32,
    interval: Duration,
    stop: &AtomicBool,
    color: bool,
    ring: &ExecRing,
    inline: bool,
) {
    let pal = crate::style::Palette::for_stream(color);
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    while !stop.load(Ordering::Relaxed) {
        let table = observe::read_proc_table();
        for pid in descendant_pids(&table, root) {
            if seen.insert(pid)
                && let Some(info) = table.get(&pid)
                && !is_plumbing(&info.comm)
            {
                let cmd = command_of(info);
                ring.push(pid, &cmd);
                if inline {
                    // One `\n`-terminated line per event. Inline runs only on the non-tty
                    // foreground path (an interactive terminal reads `sbx proc logs`/`live`
                    // instead), so no raw-mode `\r` framing is needed — plain newlines are
                    // correct here.
                    // Verbatim, never through the span painter: `cmd` is the agent's own
                    // argv, and a backtick pair inside it is command text, not markup.
                    eprintln!("{}[sbx:exec]{} {}", pal.dim, pal.reset, cmd);
                }
            }
        }
        sleep_interruptible(interval, stop);
    }
}

/// An assembled observation session: both lenses (exec and filesystem), each with its ring, control
/// socket + serve thread, and observer, wired together and held for a supervised cage's lifetime.
/// Enabled when observation is on (any launch path where a parent sbx survives the cage), it unlinks
/// the sockets on drop and stops the observers — the observe analogue of the egress guard.
pub(crate) struct Observation {
    /// Stops and joins the exec poll thread on drop, or `None` when the exec lens is off — either it
    /// was not requested, or the launch is *enforcing* (`[proc] mode = enforce|ask`), in which case the
    /// seccomp user-notification supervisor is the exec source and owns the proc control socket, so the
    /// poll observer must not also bind it. Held (not read) for the drop effect.
    _observer: Option<ExecObserver>,
    /// The bound exec control socket to unlink on drop, or `None` when it could not be bound (degraded
    /// to the inline feed only).
    exec_socket: Option<PathBuf>,
    /// Stops and joins the inotify thread on drop, or `None` when the filesystem lens could not start
    /// (degraded to the exec lens only); held (not read) for the drop effect.
    _fs_watcher: Option<FsWatcher>,
    /// The bound filesystem control socket to unlink on drop, or `None` when the lens is off / it could
    /// not be bound.
    fs_socket: Option<PathBuf>,
}

impl Observation {
    /// Enable observation for the current supervisor: stand up the exec lens (an exec ring served on a
    /// `<data>/proc/` socket, plus a `/proc` poll rooted on this process's own pid) and the filesystem
    /// lens (an fs ring served on a `<data>/fs/` socket, plus an inotify watch of `project`). `inline`
    /// echoes each *exec* event to stderr (the foreground non-tty feed); the out-of-band rings + sockets
    /// are populated regardless, so `sbx proc logs`/`sbx fs logs` can watch any observed session —
    /// including a detached one, which has no terminal for an inline feed at all. The filesystem feed is
    /// never inline (it is far too chatty for a run's stderr).
    ///
    /// Best-effort and lens-independent: observation is not a security boundary here (that is the later
    /// seccomp user-notification path), so a failure to stand up one lens warns and leaves the other
    /// running — the launch never fails for it.
    pub(crate) fn start(
        data_dir: &Path,
        project: &Path,
        exec_poll: bool,
        fs: bool,
        inline: bool,
    ) -> Self {
        let pid = std::process::id();

        // Exec lens (the cheap `/proc` poll). Skipped when the launch is enforcing — the seccomp
        // user-notification supervisor is the exec source then, and owns the proc control socket.
        let (observer, exec_socket) = if exec_poll {
            let exec_ring = Arc::new(ExecRing::new(EXEC_RING_CAP));
            let exec_socket = bind_control(data_dir, pid, &exec_ring);
            let observer = ExecObserver::start(pid, OBSERVE_POLL_INTERVAL, exec_ring, inline);
            (Some(observer), exec_socket)
        } else {
            (None, None)
        };

        // Filesystem lens (independent: a failure here leaves exec observation running).
        let (fs_watcher, fs_socket) = if fs {
            start_fs(data_dir, pid, project)
        } else {
            (None, None)
        };

        Observation {
            _observer: observer,
            exec_socket,
            _fs_watcher: fs_watcher,
            fs_socket,
        }
    }
}

impl Drop for Observation {
    fn drop(&mut self) {
        // Unlink both sockets so `sbx proc logs`/`sbx fs logs` see the session end. The `_observer` and
        // `_fs_watcher` fields' own Drops stop and join their threads. Each serve thread is left blocked
        // on `accept` and is reaped when the supervisor exits — the egress control thread has the same
        // lifetime. A `SIGKILL` skips this drop, so the pre-bind stale-socket removal in `bind_control`/
        // `bind_fs_control` is what rescues an orphaned socket at the next launch that reuses the pid.
        for socket in [&self.exec_socket, &self.fs_socket].into_iter().flatten() {
            let _ = std::fs::remove_file(socket);
        }
    }
}

/// Stand up the filesystem lens (best-effort, independent of the exec lens): create the fs ring, watch
/// the project tree with inotify, and bind + serve the fs control socket. A failure to create the
/// inotify instance warns and yields `None` (the exec lens is untouched); a watcher that starts but
/// whose socket cannot be bound is still held (harmless) so its own Drop tears it down cleanly.
fn start_fs(data_dir: &Path, pid: u32, project: &Path) -> (Option<FsWatcher>, Option<PathBuf>) {
    let ring = Arc::new(FsRing::new(FS_RING_CAP));
    let watcher = match FsWatcher::start(project, ring.clone()) {
        Ok(w) => w,
        Err(e) => {
            crate::diag::warn(&format!(
                "could not start filesystem observation ({e}) — `sbx fs logs` will not see this session"
            ));
            return (None, None);
        }
    };
    let socket = bind_fs_control(data_dir, pid, &ring);
    (Some(watcher), socket)
}

/// Stand up one observation lens's control socket: create its owner-only directory under the data
/// dir, then bind and serve the socket on a detached thread. Returns the socket path when bound (so
/// the guard can unlink it), or `None` when it could not be.
///
/// Either failure is warned and never fatal: the observation itself is already running, and a lens
/// with no reader is a far smaller loss than a launch that refused to start. `lens` names the
/// observation in prose and `reader` names the command that would have read it, so the warning says
/// which of the two feeds went quiet — with both stood up, an unqualified one would not.
fn bind_lens(
    dir: PathBuf,
    socket: PathBuf,
    lens: &str,
    reader: &str,
    serve: impl FnOnce(UnixListener) -> std::io::Result<()> + Send + 'static,
) -> Option<PathBuf> {
    if let Err(e) = super::lens::ensure_control_dir(&dir) {
        crate::diag::warn(&format!(
            "could not create the {lens} directory ({e}) — `{reader}` will not see this session"
        ));
        return None;
    }
    if let Err(e) = super::lens::bind_and_serve(&socket, serve) {
        crate::diag::warn(&format!(
            "could not bind the {lens} socket ({e}) — `{reader}` will not see this session"
        ));
        return None;
    }
    Some(socket)
}

/// Stand up the exec lens's control socket, so `sbx proc logs` can read the ring the observer pushes
/// to.
fn bind_control(data_dir: &Path, pid: u32, ring: &Arc<ExecRing>) -> Option<PathBuf> {
    let serve_ring = ring.clone();
    bind_lens(
        proc_control_dir(data_dir),
        proc_control_socket(data_dir, pid),
        "process-observation",
        "sbx proc logs",
        move |l| proc_control::serve(l, serve_ring),
    )
}

/// Stand up the filesystem lens's control socket, so `sbx fs logs` can read the ring the watcher
/// pushes to.
fn bind_fs_control(data_dir: &Path, pid: u32, ring: &Arc<FsRing>) -> Option<PathBuf> {
    let serve_ring = ring.clone();
    bind_lens(
        fs_control_dir(data_dir),
        fs_control_socket(data_dir, pid),
        "filesystem-observation",
        "sbx fs logs",
        move |l| fs_control::serve(l, serve_ring),
    )
}

/// Sleep up to `interval`, waking early (in ~50 ms slices) if a stop is requested, so `drop` joins
/// promptly instead of blocking for a whole tick.
fn sleep_interruptible(interval: Duration, stop: &AtomicBool) {
    let slice = Duration::from_millis(50);
    let mut left = interval;
    while left > Duration::ZERO && !stop.load(Ordering::Relaxed) {
        let nap = left.min(slice);
        std::thread::sleep(nap);
        left = left.saturating_sub(nap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(ppid: u32, comm: &str, args: &[&str]) -> ProcInfo {
        ProcInfo {
            ppid,
            comm: comm.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn descendant_pids_collects_the_whole_subtree_excluding_root() {
        // 100 -> 200 -> {300, 301 -> 400}; 999 unrelated.
        let table: BTreeMap<u32, ProcInfo> = [
            (100, info(1, "bwrap", &["bwrap"])),
            (200, info(100, "node", &["node", "agent"])),
            (300, info(200, "rg", &["rg", "x"])),
            (301, info(200, "sh", &["sh"])),
            (400, info(301, "git", &["git", "log"])),
            (999, info(1, "other", &["other"])),
        ]
        .into_iter()
        .collect();
        let mut d = descendant_pids(&table, 100);
        d.sort();
        assert_eq!(d, vec![200, 300, 301, 400]);
        // 999 is not under 100.
        assert!(!d.contains(&999));
    }

    #[test]
    fn descendant_pids_is_cycle_safe() {
        // A malformed parent graph must terminate, not loop.
        let table: BTreeMap<u32, ProcInfo> = [(5, info(6, "a", &["a"])), (6, info(5, "b", &["b"]))]
            .into_iter()
            .collect();
        let d = descendant_pids(&table, 5);
        assert_eq!(d, vec![6]); // 6 once; the back-edge to 5 does not re-add it
    }

    #[test]
    fn plumbing_is_filtered_but_agent_processes_are_not() {
        assert!(is_plumbing("bwrap"));
        assert!(is_plumbing("systemd-run"));
        assert!(is_plumbing("socat"));
        assert!(!is_plumbing("node"));
        assert!(!is_plumbing("rg"));
    }

    #[test]
    fn command_of_uses_argv_and_falls_back_to_comm() {
        assert_eq!(
            command_of(&info(1, "rg", &["rg", "--json", "x"])),
            "rg --json x"
        );
        assert_eq!(command_of(&info(1, "kworker", &[])), "[kworker]");
    }

    #[test]
    fn command_of_strips_control_characters_so_an_argv_cannot_forge_a_line() {
        // An argv arg carrying a newline (and a CR/tab) must not survive into the value: it feeds a
        // line-based wire and stderr, where a raw `\n` could inject a second, forged event line.
        let out = command_of(&info(1, "sh", &["sh", "-c", "a\nevil cmd=x\tb\rc"]));
        assert!(!out.contains('\n') && !out.contains('\r') && !out.contains('\t'));
        assert_eq!(out, "sh -c a evil cmd=x b c");
    }

    #[test]
    fn sanitize_caps_a_pathological_length() {
        let long = "x".repeat(5000);
        let out = sanitize(&long);
        assert_eq!(out.chars().count(), 512);
        assert!(out.ends_with('…'));
    }
}
