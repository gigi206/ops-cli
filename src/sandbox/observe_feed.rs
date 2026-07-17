//! In-supervisor exec-activity observer — the host-side half of process observation.
//!
//! When observation is on, the launch is forced onto a supervised path (a parent that outlives the
//! cage), and this module runs a background thread there. It polls the cage's process set from `/proc`
//! on a short interval, diffs successive snapshots, and for each newly-seen process pushes an event
//! into the exec ring — read out-of-band by `sbx proc logs` over a per-session control socket — and,
//! on the foreground non-tty path, also echoes a `[sbx:exec] <cmd>` line to stderr inline with the run.
//!
//! It roots on the supervisor's own pid (`std::process::id()`): the cage's processes are its
//! descendants in host pid-space (the same vantage point [`crate::observe`] and `sbx proc ls` use),
//! so a `/proc` walk from that root sees the whole tree. No privilege, no cage cooperation.
//!
//! [`ProcObs`] assembles the three pieces — the ring, its control socket + serve thread, and the poll
//! observer — and unlinks the socket on drop; it is the process/exec analogue of the egress guard, and
//! the same substrate the later seccomp user-notification enforcement will reuse.
//!
//! Honest limit: polling only sees a process that outlives a tick, so very short-lived commands are
//! missed. Precise, per-`execve` capture (and the blocking that rides on it) is the seccomp
//! user-notification path, a later increment; this feed is the cheap, unprivileged first cut.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use super::proc_control::{self, proc_control_dir, proc_control_socket, ExecRing, EXEC_RING_CAP};
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
/// the value is safe on the line-based control wire and the stderr feed.
fn sanitize(s: &str) -> String {
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
            if seen.insert(pid) {
                if let Some(info) = table.get(&pid) {
                    if !is_plumbing(&info.comm) {
                        let cmd = command_of(info);
                        ring.push(pid, &cmd);
                        if inline {
                            // One `\n`-terminated line per event. Inline runs only on the non-tty
                            // foreground path (an interactive terminal reads `sbx proc logs`/`live`
                            // instead), so no raw-mode `\r` framing is needed — plain newlines are
                            // correct here.
                            eprintln!("{}[sbx:exec]{} {}", pal.dim, pal.reset, cmd);
                        }
                    }
                }
            }
        }
        sleep_interruptible(interval, stop);
    }
}

/// An assembled process observer: the exec ring, its control socket + serve thread, and the poll
/// observer, wired together and held for a supervised cage's lifetime. Enabled when observation is on
/// (any launch path where a parent sbx survives the cage), it unlinks the socket on drop and stops the
/// observer — the process/exec analogue of the egress guard.
pub(crate) struct ProcObs {
    /// Stops and joins the poll thread on drop; held (not read) for that effect.
    _observer: ExecObserver,
    /// The bound control socket to unlink on drop, or `None` when it could not be bound (degraded to
    /// the inline feed only).
    socket: Option<PathBuf>,
}

impl ProcObs {
    /// Enable observation for the current supervisor: create the exec ring, bind the per-session
    /// control socket under `<data>/proc/`, serve it, and start the poll observer rooted on this
    /// process's own pid. `inline` echoes each event to stderr (the foreground non-tty feed); the
    /// out-of-band ring + socket are populated regardless, so `sbx proc logs` can watch any observed
    /// session — including a detached one, which has no terminal for an inline feed at all.
    ///
    /// Best-effort: observation is not a security boundary here (that is the later seccomp
    /// user-notification path), so a failure to bind the socket warns and degrades to the inline feed
    /// only — the launch never fails for it.
    pub(crate) fn start(data_dir: &Path, inline: bool) -> Self {
        let pid = std::process::id();
        let ring = Arc::new(ExecRing::new(EXEC_RING_CAP));
        let socket = bind_control(data_dir, pid, &ring);
        let observer = ExecObserver::start(pid, OBSERVE_POLL_INTERVAL, ring, inline);
        ProcObs {
            _observer: observer,
            socket,
        }
    }
}

impl Drop for ProcObs {
    fn drop(&mut self) {
        // Unlink the socket so `sbx proc logs` sees the session end. The `_observer` field's own Drop
        // stops and joins the poll thread after this. The serve thread is left blocked on `accept`
        // and is reaped when the supervisor exits — the egress control thread has the same lifetime.
        // A `SIGKILL` skips this drop, so the pre-bind stale-socket removal in `bind_control` is what
        // rescues an orphaned socket at the next launch that reuses the pid.
        if let Some(socket) = &self.socket {
            let _ = std::fs::remove_file(socket);
        }
    }
}

/// Bind the per-session control socket and serve the ring on it. Returns the socket path when bound
/// (so the guard can unlink it), or `None` (warned) when it could not be — the inline feed still runs.
/// Mirrors the egress control socket's setup: the `<data>/proc/` dir is created owner-only, a stale
/// socket left by a crashed predecessor that reused the pid is cleared first (a `SIGKILL` skips the
/// guard's unlink), then the listener is bound and served on a detached thread.
fn bind_control(data_dir: &Path, pid: u32, ring: &Arc<ExecRing>) -> Option<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = proc_control_dir(data_dir);
    if let Err(e) = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
    {
        crate::diag::warn(&format!(
            "could not create the process-observation directory ({e}) — `sbx proc logs` will not \
             see this session"
        ));
        return None;
    }
    let socket = proc_control_socket(data_dir, pid);
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            crate::diag::warn(&format!(
                "could not bind the process-observation socket ({e}) — `sbx proc logs` will not see \
                 this session"
            ));
            return None;
        }
    };
    let serve_ring = ring.clone();
    std::thread::spawn(move || {
        let _ = proc_control::serve(listener, serve_ring);
    });
    Some(socket)
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
