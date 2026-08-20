//! In-cage observability — read-only, host-side, unprivileged.
//!
//! Given a running session's recorded pid, snapshot the cage's **process tree**
//! from `/proc` — the `sbx proc ls` view. It needs no privilege and no
//! cooperation from the cage: the launcher process (or bubblewrap itself on the
//! exec path) is the root, and every cage process is one of its descendants in
//! host pid-space, so a plain `/proc` walk from that root sees the whole tree.
//!
//! This is the first lens of the observability stack; the exec/filesystem event
//! feeds build on the same host-side vantage point. The tree builder and the
//! renderers are pure over an injected process table, so they are unit-tested
//! without touching `/proc`; only [`read_proc_table`] does I/O.

use std::collections::{BTreeMap, BTreeSet};

/// One process in a cage's tree: host-side pid, `comm`, argv, and its children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcNode {
    pub(crate) pid: u32,
    pub(crate) comm: String,
    pub(crate) args: Vec<String>,
    pub(crate) children: Vec<ProcNode>,
}

/// A flat process-table row: the parent pid, `comm`, and argv. Kept separate
/// from [`ProcNode`] so the tree builder is a pure function of an injectable
/// table — the same shape [`read_proc_table`] produces from `/proc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcInfo {
    pub(crate) ppid: u32,
    pub(crate) comm: String,
    pub(crate) args: Vec<String>,
}

/// Build the tree rooted at `root` from a flat table. Pure. Children are ordered
/// by pid for a stable render; a `visited` set makes a malformed parent graph
/// (a self-parent or a cycle from a `/proc` read race) terminate rather than
/// recurse forever. Returns `None` if `root` is not in the table (it exited).
pub(crate) fn build_tree(table: &BTreeMap<u32, ProcInfo>, root: u32) -> Option<ProcNode> {
    let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (&pid, info) in table {
        if pid != info.ppid {
            kids.entry(info.ppid).or_default().push(pid);
        }
    }
    let mut visited = BTreeSet::new();
    node(root, table, &kids, &mut visited)
}

fn node(
    pid: u32,
    table: &BTreeMap<u32, ProcInfo>,
    kids: &BTreeMap<u32, Vec<u32>>,
    visited: &mut BTreeSet<u32>,
) -> Option<ProcNode> {
    let info = table.get(&pid)?;
    if !visited.insert(pid) {
        return None; // already placed — break any cycle
    }
    let mut children = Vec::new();
    if let Some(cs) = kids.get(&pid) {
        for &c in cs {
            if let Some(n) = node(c, table, kids, visited) {
                children.push(n);
            }
        }
    }
    Some(ProcNode {
        pid,
        comm: info.comm.clone(),
        args: info.args.clone(),
        children,
    })
}

/// Read `/proc` into a flat process table (host pid-space). Best-effort: an
/// entry that races away mid-read is simply skipped.
pub(crate) fn read_proc_table() -> BTreeMap<u32, ProcInfo> {
    let mut table = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return table;
    };
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
        let Some(ppid) = parse_ppid(&stat) else {
            continue;
        };
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let args = read_cmdline(pid);
        table.insert(pid, ProcInfo { ppid, comm, args });
    }
    table
}

/// The process tree of the cage rooted at `root_pid`, read live from `/proc`.
pub(crate) fn tree(root_pid: u32) -> Option<ProcNode> {
    build_tree(&read_proc_table(), root_pid)
}

/// Extract field 4 (parent pid) from `/proc/<pid>/stat`. Field 2 (`comm`) is
/// parenthesised and may contain spaces and `)`, so the clean fields start after
/// the final `)`: there field 3 (state) is first and field 4 (ppid) second.
fn parse_ppid(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

/// The argv of `pid` from `/proc/<pid>/cmdline` (NUL-separated), trailing empty
/// field dropped. Empty for a kernel thread or a process whose cmdline is
/// unreadable — the renderer falls back to `comm` there.
fn read_cmdline(pid: u32) -> Vec<String> {
    let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return Vec::new();
    };
    raw.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// Render the tree as an indented human view (does not include a header line —
/// the caller prints the session context). Root at the shallowest indent.
pub(crate) fn render_human(root: &ProcNode) -> String {
    let mut out = String::new();
    render_node(root, 0, &mut out);
    out
}

/// One line per process, `pid` then command, indented by depth.
///
/// The command is sanitised before it is placed on a line, because none of it is ours: `argv` is
/// whatever the process set, and `comm` is 16 bytes `prctl(PR_SET_NAME)` accepts without inspecting
/// them. A newline in either would put a second line in this view under a pid and an indent the
/// process chose, and an escape would drive the terminal reading it. The same treatment the exec and
/// filesystem feeds give their own free-form field, through the same definition; `to_json` needs
/// none, since the serialiser escapes what it emits.
fn render_node(n: &ProcNode, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth + 1);
    let cmd = if n.args.is_empty() {
        format!("[{}]", n.comm)
    } else {
        n.args.join(" ")
    };
    let cmd = crate::sandbox::sanitize(&cmd);
    out.push_str(&format!("{indent}{}  {}\n", n.pid, truncate(&cmd, 120)));
    for c in &n.children {
        render_node(c, depth + 1, out);
    }
}

/// Serialise the tree for `--json` consumers.
pub(crate) fn to_json(n: &ProcNode) -> serde_json::Value {
    serde_json::json!({
        "pid": n.pid,
        "comm": n.comm,
        "args": n.args,
        "children": n.children.iter().map(to_json).collect::<Vec<_>>(),
    })
}

/// Truncate to `max` chars with a trailing ellipsis (char-boundary safe).
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn info(ppid: u32, comm: &str, args: &[&str]) -> ProcInfo {
        ProcInfo {
            ppid,
            comm: comm.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn table(rows: &[(u32, ProcInfo)]) -> BTreeMap<u32, ProcInfo> {
        rows.iter().cloned().collect()
    }

    #[test]
    fn build_tree_nests_children_under_their_parent() {
        // 100 (bwrap) -> 200 (agent) -> {300 (rg), 301 (git)}; 999 is unrelated.
        let t = table(&[
            (100, info(1, "bwrap", &["bwrap", "--unshare-all"])),
            (200, info(100, "node", &["node", "/store/agent"])),
            (300, info(200, "rg", &["rg", "TODO"])),
            (301, info(200, "git", &["git", "commit"])),
            (999, info(1, "other", &["other"])),
        ]);
        let root = build_tree(&t, 100).expect("root present");
        assert_eq!(root.pid, 100);
        assert_eq!(root.children.len(), 1);
        let agent = &root.children[0];
        assert_eq!(agent.pid, 200);
        // children sorted by pid
        let kids: Vec<u32> = agent.children.iter().map(|c| c.pid).collect();
        assert_eq!(kids, vec![300, 301]);
        // 999 is not under 100
        assert!(!render_human(&root).contains("other"));
    }

    #[test]
    fn build_tree_returns_none_for_an_absent_root() {
        let t = table(&[(1, info(0, "init", &["init"]))]);
        assert_eq!(build_tree(&t, 4242), None);
    }

    #[test]
    fn build_tree_terminates_on_a_cycle() {
        // A malformed graph from a /proc read race: 5 is its own ancestor.
        let t = table(&[(5, info(6, "a", &["a"])), (6, info(5, "b", &["b"]))]);
        let root = build_tree(&t, 5).expect("root present");
        // 6 appears once as a child; the back-edge to 5 is broken by `visited`.
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].pid, 6);
        assert!(root.children[0].children.is_empty());
    }

    #[test]
    fn render_uses_argv_and_falls_back_to_comm_in_brackets() {
        let t = table(&[
            (10, info(1, "sh", &["sh", "-c", "sleep 1"])),
            (11, info(10, "kthread", &[])), // empty argv -> [comm]
        ]);
        let out = render_human(&build_tree(&t, 10).unwrap());
        assert!(out.contains("10  sh -c sleep 1"), "argv joined: {out}");
        assert!(out.contains("11  [kthread]"), "comm fallback: {out}");
        // child is indented deeper than its parent
        let root_line = out.lines().find(|l| l.contains("10  sh")).unwrap();
        let kid_line = out.lines().find(|l| l.contains("11  [kthread]")).unwrap();
        let lead = |l: &str| l.len() - l.trim_start().len();
        assert!(lead(kid_line) > lead(root_line));
    }

    /// A process names itself in this view, so the view holds it to one line. `argv` is whatever it
    /// passed to `execve` and `comm` is whatever it handed `prctl(PR_SET_NAME)`, neither inspected by
    /// the kernel: a newline in either would otherwise add a line here, under a pid and an indent of
    /// the process's choosing, and an escape would reach the terminal reading it.
    #[test]
    fn a_process_cannot_add_a_line_to_the_tree_by_naming_itself() {
        let t = table(&[
            (
                10,
                info(1, "sh", &["sh", "-c", "x\n      4242  /bin/su root"]),
            ),
            // The same through `comm`, on the argv-less path that falls back to it.
            (11, info(10, "a\n      4243  /bin/su root", &[])),
        ]);
        let out = render_human(&build_tree(&t, 10).unwrap());
        assert_eq!(
            out.lines().count(),
            2,
            "one line per process, two processes: {out:?}"
        );
        for forged in ["4242", "4243"] {
            assert!(
                !out.lines().any(|l| l.trim_start().starts_with(forged)),
                "a process put itself in the tree under a pid it chose: {out:?}"
            );
        }
        // An escape sequence does not reach the terminal either.
        let t = table(&[(20, info(1, "sh", &["sh", "\u{1b}[2J"]))]);
        let out = render_human(&build_tree(&t, 20).unwrap());
        assert!(!out.contains('\u{1b}'), "an escape survived: {out:?}");
    }

    #[test]
    fn to_json_carries_pid_args_and_nested_children() {
        let t = table(&[
            (1, info(0, "root", &["root"])),
            (2, info(1, "kid", &["kid", "arg"])),
        ]);
        let j = to_json(&build_tree(&t, 1).unwrap());
        assert_eq!(j["pid"], 1);
        assert_eq!(j["children"][0]["pid"], 2);
        assert_eq!(j["children"][0]["args"][1], "arg");
    }

    #[test]
    fn truncate_is_char_boundary_safe() {
        assert_eq!(truncate("héllo", 100), "héllo");
        let t = truncate("héllo wörld", 4);
        assert_eq!(t.chars().count(), 4);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn tree_reads_a_real_process_subtree_from_proc() {
        // Spawn a shell that forks a child `sleep` and waits — a real 2-level tree
        // in host /proc — then assert `tree()` roots at the shell and captures the
        // child. Mirrors the registry's descendant test.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & wait"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn test shell");
        let root_pid = child.id();

        // The wait asks the question the assertion asks: not "does the shell have a child" but
        // "is that child `sleep`". The two are not the same moment — a forked child carries its
        // parent's argv until it execs — so a loop that stops at the weaker condition can hand
        // the assertion a child still showing the shell's own command line. Stopping only on the
        // stronger one makes any such transient state something the deadline absorbs rather than
        // something the assertion reads.
        let execed = |n: &ProcNode| {
            n.children
                .first()
                .and_then(|c| c.args.first())
                .is_some_and(|a| a.contains("sleep"))
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        let found = loop {
            if let Some(node) = tree(root_pid)
                && execed(&node)
            {
                break Some(node);
            }
            if Instant::now() >= deadline {
                break tree(root_pid);
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let node = found.expect("the shell must be in /proc");
        assert_eq!(node.pid, root_pid);
        assert_eq!(node.children.len(), 1, "the shell should have one child");
        assert!(
            node.children[0]
                .args
                .first()
                .is_some_and(|a| a.contains("sleep")),
            "child is the sleep: {:?}",
            node.children[0].args
        );

        // Clean up.
        unsafe {
            libc::kill(root_pid as libc::pid_t, libc::SIGKILL);
        }
        let _ = child.wait();
    }
}
