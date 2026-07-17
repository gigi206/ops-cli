//! In-supervisor exec-activity feed — the host-side half of `sbx run --observe`.
//!
//! When observation is on, the launch is forced onto the supervised path (a parent that outlives
//! the cage), and this module runs a background thread there. It polls the cage's process set from
//! `/proc` on a short interval, diffs successive snapshots, and streams a `[sbx:exec] <cmd>` line to
//! stderr for each newly-seen process — so you watch what the agent runs, inline with the run.
//!
//! It roots on the supervisor's own pid (`std::process::id()`): the cage's processes are its
//! descendants in host pid-space (the same vantage point [`crate::observe`] and `sbx proc ls` use),
//! so a `/proc` walk from that root sees the whole tree. No privilege, no cage cooperation.
//!
//! Honest limit: polling only sees a process that outlives a tick, so very short-lived commands are
//! missed. Precise, per-`execve` capture (and the blocking that rides on it) is the seccomp
//! user-notification path, a later increment; this feed is the cheap, unprivileged first cut.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::observe::{self, ProcInfo};

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
/// thread or an unreadable cmdline).
fn command_of(info: &ProcInfo) -> String {
    if info.args.is_empty() {
        format!("[{}]", info.comm)
    } else {
        info.args.join(" ")
    }
}

/// A running exec-activity observer. The thread stops and is joined on drop (mirroring the relay
/// guards), so it never outlives the supervised wait.
pub(crate) struct ExecObserver {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ExecObserver {
    /// Start observing the cage rooted at `root` (the supervisor's own pid), emitting to stderr.
    pub(crate) fn start(root: u32, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let color = std::io::IsTerminal::is_terminal(&std::io::stderr());
        let handle = std::thread::spawn(move || run_loop(root, interval, &flag, color));
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

/// The poll loop: each tick, snapshot the cage's descendants, emit any newly-seen non-plumbing
/// process, then sleep in short slices so a stop is honoured promptly.
fn run_loop(root: u32, interval: Duration, stop: &AtomicBool, color: bool) {
    let pal = crate::style::Palette::for_stream(color);
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    while !stop.load(Ordering::Relaxed) {
        let table = observe::read_proc_table();
        for pid in descendant_pids(&table, root) {
            if seen.insert(pid) {
                if let Some(info) = table.get(&pid) {
                    if !is_plumbing(&info.comm) {
                        // One `\n`-terminated line per event. This feed only runs on the non-tty
                        // foreground path (an interactive terminal is redirected to `sbx proc live`),
                        // so no raw-mode `\r` framing is needed — plain newlines are correct here.
                        eprintln!("{}[sbx:exec]{} {}", pal.dim, pal.reset, command_of(info));
                    }
                }
            }
        }
        sleep_interruptible(interval, stop);
    }
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
}
