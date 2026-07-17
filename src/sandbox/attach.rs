//! Real `sbx session attach`: join a *running* cage's namespaces and either open an interactive
//! shell or run one command inside it — the agent's live processes, its real `/tmp`, its network —
//! the way `docker exec` / `docker exec -it` works, not a fresh cage that only shares the home on
//! disk. A command from a terminal takes the pty path ([`TtyMode::Pty`], job control); a command
//! with no terminal takes the inherited-stdio path ([`TtyMode::Inherit`], clean piped bytes).
//!
//! ## A second namespace-entry path, kept honest
//!
//! Every normal launch describes the cage in exactly one place
//! ([`super::spec::SandboxSpec`] → [`super::argv::to_argv`]) and bubblewrap builds it.
//! `attach` cannot: it must enter namespaces bubblewrap already created, which no
//! `SandboxSpec` can express. So it is a deliberate *second* path — and the risk it
//! must not introduce is a joined process **less** confined than the agent, because none of the
//! cage's confinement is inherited across [`setns`](libc::setns):
//!
//! - **seccomp** is per-thread, not per-namespace, so a joined process starts with the
//!   whole syscall surface open. [`enter_and_exec`] re-installs the mandatory denylist
//!   ([`super::seccomp`]) before exec, on **both** the pty and inherited-stdio paths. It always
//!   installs the *baseline* policy, never a project's `[seccomp] allow` relaxation, so the joined
//!   shell or command is confined **at least** as tightly as the agent.
//! - **no_new_privs + capabilities** are likewise re-applied: `PR_SET_NO_NEW_PRIVS`, the
//!   ambient set cleared, the bounding set dropped. With an empty permitted set and
//!   `no_new_privs`, no bounded capability can ever become effective, so a full bounding
//!   set (which `setns` leaves in place) is inert and grants nothing the agent lacks.
//!
//! Two residuals, both named and accepted:
//! - **cgroup resource limits are not shared.** `setns(CLONE_NEWCGROUP)` joins the cgroup
//!   *namespace* (the `/proc/self/cgroup` view) but not the cage's cgroup *membership*, so the
//!   attached process runs in `sbx session attach`'s own scope, outside the cage's `MemoryMax`/`TasksMax`.
//!   This is deliberate — an interactive inspection shell should not share the agent's OOM
//!   ceiling — and it is not a confinement hole (a runaway there is bounded by the host, and the
//!   security controls above are all re-applied).
//! - **the shell or command binary comes from the agent's own mount namespace** (writable in Mode B),
//!   so an agent that has tampered with its `/bin/bash` runs that — inherent to any `exec`-into-a-
//!   container. Entering an agent's environment to inspect it is the whole point; the confinement
//!   above bounds what the entered process can do, and the operation is host-initiated by the
//!   trusted user — the caged agent cannot trigger it.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A handle to a running cage: a **pidfd** for one of its live processes. A pidfd plus a
/// single [`setns`](libc::setns) with a *combined* namespace mask is the only way an
/// unprivileged process can join a user namespace **and** the namespaces it owns: the
/// kernel enters them atomically, in the one internal order that works. A sequence of
/// per-namespace `setns` calls cannot — joining the user namespace first drops the very
/// capability the mnt/net/… joins require, and joining them first is refused for lack of
/// that capability, so *either* order of separate calls fails. Held across the `fork`;
/// close-on-exec (`pidfd_open` sets it), so the final `execve` closes it.
pub(super) struct CageHandle {
    pidfd: OwnedFd,
    /// The `CLONE_NEW*` flags to join: only the namespaces the cage does *not* share with us.
    mask: libc::c_int,
}

/// How the entered command connects to a terminal. A bare `sbx session attach` (interactive
/// shell) and a command run from a terminal take [`Pty`](TtyMode::Pty) — the shell owns the pty
/// slave as its controlling terminal, so job control and resize work. A command run with no
/// terminal on stdin (a pipe or a script) takes [`Inherit`](TtyMode::Inherit) — it keeps sbx's own
/// stdin/stdout/stderr, so bytes pass through clean (no pty `\n`→`\r\n` translation) for scripting.
#[derive(Clone, Copy)]
pub(super) enum TtyMode {
    /// Take this pty slave fd as the controlling terminal via `login_tty`.
    Pty(libc::c_int),
    /// Inherit sbx's own stdin/stdout/stderr descriptors unchanged.
    Inherit,
}

/// The seven namespace types, paired with their `setns` flag. Order is not significant — the
/// combined `setns(pidfd, mask)` joins them atomically in the kernel's own internal order.
const NAMESPACES: [(&str, libc::c_int); 7] = [
    ("user", libc::CLONE_NEWUSER),
    ("mnt", libc::CLONE_NEWNS),
    ("pid", libc::CLONE_NEWPID),
    ("net", libc::CLONE_NEWNET),
    ("ipc", libc::CLONE_NEWIPC),
    ("uts", libc::CLONE_NEWUTS),
    ("cgroup", libc::CLONE_NEWCGROUP),
];

/// Open a pidfd for the cage process `pid` and compute the namespace mask to join. Same uid, so
/// `pidfd_open` is permitted; the pidfd pins that exact process, so a pid reused between discovery
/// and the join can never be entered by mistake.
pub(super) fn open_cage_handle(pid: u32) -> io::Result<CageHandle> {
    // SAFETY: `pidfd_open` with flags 0 returns a fresh owned descriptor or -1/errno.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh owned descriptor from `pidfd_open`, wrapped exactly once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    let mask = namespaces_to_join(pid);
    Ok(CageHandle { pidfd, mask })
}

/// The `CLONE_NEW*` mask of namespaces to join: for each type, its flag **only if** the cage's
/// namespace differs from ours. A namespace the cage *shares* with us — most importantly the host
/// network namespace under `network = "shared"` — is omitted: we are already in it, and the combined
/// `setns` (which enters the user namespace in the same call) is refused if it also names a
/// namespace we already share (proven: joining a shared network namespace that way returns EPERM).
fn namespaces_to_join(pid: u32) -> libc::c_int {
    let readings = NAMESPACES.map(|(ns, flag)| {
        let ours = std::fs::read_link(format!("/proc/self/ns/{ns}")).ok();
        let theirs = std::fs::read_link(format!("/proc/{pid}/ns/{ns}")).ok();
        (
            flag,
            ours.map(|p| p.into_os_string()),
            theirs.map(|p| p.into_os_string()),
        )
    });
    join_mask(&readings)
}

/// Pure core of [`namespaces_to_join`]: OR in a flag unless the cage's namespace link equals ours.
/// When either link is unreadable, include the flag (attempt the join rather than silently skip it).
fn join_mask(
    readings: &[(
        libc::c_int,
        Option<std::ffi::OsString>,
        Option<std::ffi::OsString>,
    )],
) -> libc::c_int {
    let mut mask = 0;
    for (flag, ours, theirs) in readings {
        match (ours, theirs) {
            (Some(a), Some(b)) if a == b => {} // shared — we are already in it
            _ => mask |= flag,
        }
    }
    mask
}

/// Read the cage environment from the payload's `/proc/<pid>/environ` (NUL-separated
/// `KEY=VALUE`). This is the exact environment bubblewrap set for the agent — its
/// PATH, proxy, and CA settings — and, by the never-in-the-cage secrets invariant, it
/// carries no plaintext credential. Best-effort: an empty read yields an empty env.
pub(super) fn read_environ(pid: u32) -> Vec<u8> {
    std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default()
}

/// Build the attached shell's environment from the agent's `environ`: keep every entry
/// verbatim except `TERM`, which is set to the attaching terminal's so rendering and
/// resize match the real terminal (the agent's recorded `TERM` may be stale). Pure, so
/// the split/override logic is unit-testable.
pub(super) fn build_env(environ: &[u8], term: Option<&str>) -> Vec<CString> {
    let mut out: Vec<CString> = environ
        .split(|&b| b == 0)
        .filter(|e| !e.is_empty() && !e.starts_with(b"TERM="))
        .filter_map(|e| CString::new(e).ok())
        .collect();
    let term = term.unwrap_or("xterm-256color");
    if let Ok(entry) = CString::new(format!("TERM={term}")) {
        out.push(entry);
    }
    out
}

/// Locate a live process *inside* the cage of session `session_pid`. The recorded pid
/// is the cage's host-side anchor — bubblewrap on the exec path, the sbx supervisor on
/// the egress path — and the cage processes are always its descendants (verified on
/// both paths). Among the descendants, one in a *child* user namespace is inside the
/// cage; the payload (not bubblewrap itself) is preferred so its `environ` is the cage
/// environment. Returns `None` if the cage has no live in-namespace process (it just
/// exited, or the host lacks user namespaces).
pub(super) fn find_cage_pid(session_pid: u32) -> Option<u32> {
    let host = userns_link(std::process::id())?;
    let parents = parent_map();
    let candidates: Vec<(u32, Option<String>, Option<String>)> = descendants(session_pid, &parents)
        .into_iter()
        .map(|p| (p, userns_link(p), comm(p)))
        .collect();
    choose_cage_pid(&candidates, &host)
}

/// Pick the cage process from `(pid, userns_link, comm)` candidates: skip any in the
/// host user namespace (`host_userns`), prefer the first non-`bwrap` process in a child
/// user namespace (the payload, whose `environ` is the cage's), and fall back to a
/// child-namespace `bwrap` if that is all there is. Pure.
fn choose_cage_pid(
    candidates: &[(u32, Option<String>, Option<String>)],
    host_userns: &str,
) -> Option<u32> {
    let mut fallback = None;
    for (pid, userns, comm) in candidates {
        let Some(userns) = userns else { continue };
        if userns == host_userns {
            continue;
        }
        if comm.as_deref() != Some("bwrap") {
            return Some(*pid);
        }
        fallback.get_or_insert(*pid);
    }
    fallback
}

/// The `user:[<inode>]` link string of `/proc/<pid>/ns/user`, used to tell a cage's
/// child user namespace apart from the host's. `None` if the process is gone.
fn userns_link(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/ns/user"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// The process command name from `/proc/<pid>/comm` (trimmed of its trailing newline).
fn comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
}

/// Every live pid → its parent pid, read from `/proc/<pid>/stat`. The parent is the
/// field after the `(comm)` group, so parsing starts past the last `)` — robust to a
/// `comm` containing spaces or parentheses.
fn parent_map() -> BTreeMap<u32, u32> {
    let mut map = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(ppid) = read_ppid(pid) {
            map.insert(pid, ppid);
        }
    }
    map
}

/// Parse the parent pid from a process's `/proc/<pid>/stat`.
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    // Fields after `)`: state, ppid, … — ppid is the second whitespace token.
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

/// Every descendant pid of `root` (excluding `root`), by breadth-first walk over the
/// parent map. Pure over its input, so the tree walk is unit-testable.
fn descendants(root: u32, parents: &BTreeMap<u32, u32>) -> Vec<u32> {
    let mut children: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for (&pid, &ppid) in parents {
        children.entry(ppid).or_default().push(pid);
    }
    let mut out = Vec::new();
    let mut queue: Vec<u32> = children.get(&root).cloned().unwrap_or_default();
    while let Some(pid) = queue.pop() {
        out.push(pid);
        if let Some(kids) = children.get(&pid) {
            queue.extend(kids);
        }
    }
    out
}

/// Enter the cage's namespaces and `exec` the confined shell. Called between `fork` and
/// `exec` in the pty supervisor's child; **never returns** (execs the shell in a
/// grandchild, then `_exit`s with its status, or `_exit`s on any failure).
///
/// # Safety
///
/// Async-signal-safe: after the `fork` inside, only raw syscalls and the prebuilt
/// `filters`/`argv`/`envp` are touched — no allocation, no locks. `tty` selects the
/// controlling-terminal setup ([`TtyMode`]); `argv`/`envp` are NUL-terminated C string
/// arrays that outlive the call.
pub(super) unsafe fn enter_and_exec(
    cage: &CageHandle,
    filters: &[Vec<u8>],
    tty: TtyMode,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    // One atomic join of every cage namespace we do not already share — *including* the
    // user namespace — through the pidfd. The kernel orders the user-namespace entry
    // internally so the capability to enter the mnt/net/… namespaces it owns is held at
    // the right instant, which a sequence of per-namespace `setns` calls cannot reproduce.
    let mask = cage.mask;
    let pidfd = cage.pidfd.as_raw_fd();
    if libc::setns(pidfd, mask) != 0 {
        // The combined join is atomic, so a cage without a cgroup namespace (or one that
        // refuses that single join) would fail the whole call; retry without it — the
        // cgroup namespace only changes a cosmetic `/proc/self/cgroup` view.
        if libc::setns(pidfd, mask & !libc::CLONE_NEWCGROUP) != 0 {
            libc::_exit(126);
        }
    }
    // Fork so the shell runs *in* the cage's pid namespace (a `setns` into a pid
    // namespace only moves the caller's future children into it).
    let child = libc::fork();
    if child < 0 {
        libc::_exit(126);
    }
    if child == 0 {
        confine_and_exec(filters, tty, argv, envp);
    }
    // Parent of the shell: reap it and mirror its exit status up to the pty supervisor.
    let mut status: libc::c_int = 0;
    loop {
        if libc::waitpid(child, &mut status, 0) >= 0 {
            break;
        }
        if *libc::__errno_location() != libc::EINTR {
            libc::_exit(126);
        }
    }
    if libc::WIFEXITED(status) {
        libc::_exit(libc::WEXITSTATUS(status));
    }
    if libc::WIFSIGNALED(status) {
        libc::_exit(128 + libc::WTERMSIG(status));
    }
    libc::_exit(126);
}

/// The grandchild: set up the terminal per [`TtyMode`], re-apply the cage's confinement,
/// and exec the command. Never returns.
///
/// # Safety
///
/// Async-signal-safe (raw syscalls only). Must run in the process that will `exec` the
/// command — i.e. after the pid-namespace fork in [`enter_and_exec`].
unsafe fn confine_and_exec(
    filters: &[Vec<u8>],
    tty: TtyMode,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    match tty {
        // setsid + make the pty slave our controlling terminal + dup it onto stdio — the
        // same `login_tty` the an interactive `sbx run` supervisor uses, so job control works inside.
        TtyMode::Pty(slave) => {
            if libc::login_tty(slave) != 0 {
                libc::_exit(127);
            }
        }
        // A non-interactive command: keep sbx's own stdin/stdout/stderr so bytes pass
        // through unmodified (no controlling terminal, no pty line translation).
        TtyMode::Inherit => {}
    }
    // Re-apply the cage confinement — NONE of it survived `setns`. `no_new_privs`
    // before seccomp: an unprivileged filter install requires it.
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        libc::_exit(125);
    }
    // Drop the capability bounding + ambient sets. Defense in depth: already inert
    // under `no_new_privs` with an empty permitted set, but this matches the cage
    // exactly. Best-effort (a bounding-set drop can lack CAP_SETPCAP after `setns`);
    // the inert-under-no_new_privs argument holds regardless.
    let mut cap: libc::c_int = 0;
    while cap <= 63 {
        libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
        cap += 1;
    }
    libc::prctl(
        libc::PR_CAP_AMBIENT,
        libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
        0,
        0,
        0,
    );
    // The seccomp denylist — the load-bearing re-application: this refuses the
    // mount/namespace/ptrace family the confined agent cannot call.
    if !super::seccomp::install_filters(filters) {
        libc::_exit(125);
    }
    libc::execve(*argv, argv, envp);
    // Only reached if execve failed (e.g. the cage's /bin/bash is gone).
    libc::_exit(127);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choose_prefers_the_payload_over_bwrap_and_skips_the_host_namespace() {
        let host = "user:[4026531837]".to_string();
        let child = "user:[4026533809]".to_string();
        // Order: an outer bwrap in the host ns, the inner bwrap in the child ns, then
        // the payload in the child ns. The payload must win despite bwrap coming first.
        let candidates = vec![
            (100, Some(host.clone()), Some("bwrap".to_string())),
            (101, Some(child.clone()), Some("bwrap".to_string())),
            (102, Some(child.clone()), Some("sleep".to_string())),
            (103, Some(child.clone()), Some("socat".to_string())),
        ];
        assert_eq!(choose_cage_pid(&candidates, &host), Some(102));
    }

    #[test]
    fn choose_falls_back_to_bwrap_when_it_is_the_only_in_cage_process() {
        let host = "user:[4026531837]".to_string();
        let child = "user:[4026533809]".to_string();
        let candidates = vec![
            (100, Some(host.clone()), Some("bwrap".to_string())),
            (101, Some(child.clone()), Some("bwrap".to_string())),
        ];
        assert_eq!(choose_cage_pid(&candidates, &host), Some(101));
    }

    #[test]
    fn choose_returns_none_when_every_candidate_is_in_the_host_namespace() {
        // No process left a child user namespace: the cage is gone, so there is
        // nothing to attach to.
        let host = "user:[4026531837]".to_string();
        let candidates = vec![
            (100, Some(host.clone()), Some("bwrap".to_string())),
            (200, Some(host.clone()), Some("sbx".to_string())),
            (300, None, None),
        ];
        assert_eq!(choose_cage_pid(&candidates, &host), None);
    }

    #[test]
    fn descendants_collects_the_whole_subtree_not_just_direct_children() {
        // 1 → 2 → {3, 4}; 4 → 5; plus an unrelated 9 → 8. From root 2 we must reach
        // 3, 4, 5 and never 8/9.
        let parents: BTreeMap<u32, u32> = [(2, 1), (3, 2), (4, 2), (5, 4), (8, 9)]
            .into_iter()
            .collect();
        let mut got = descendants(2, &parents);
        got.sort_unstable();
        assert_eq!(got, vec![3, 4, 5]);
    }

    #[test]
    fn build_env_overrides_term_and_keeps_every_other_entry() {
        let environ = b"PATH=/nix/bin\x00HOME=/home/sandbox\x00TERM=dumb\x00\x00";
        let env = build_env(environ, Some("xterm-256color"));
        let strings: Vec<&str> = env.iter().map(|c| c.to_str().unwrap()).collect();
        // The agent's PATH/HOME survive verbatim; the stale TERM is replaced (once), not
        // duplicated; the trailing empty entries are dropped.
        assert!(strings.contains(&"PATH=/nix/bin"));
        assert!(strings.contains(&"HOME=/home/sandbox"));
        assert!(strings.contains(&"TERM=xterm-256color"));
        assert!(!strings.contains(&"TERM=dumb"));
        assert_eq!(strings.iter().filter(|e| e.starts_with("TERM=")).count(), 1);
    }

    #[test]
    fn join_mask_skips_a_shared_namespace_and_joins_every_distinct_one() {
        use std::ffi::OsString;
        let os = |s: &str| Some(OsString::from(s));
        // The `network = "shared"` shape: the cage's net namespace equals ours, everything else is
        // distinct. The shared net must be omitted (joining it in the combined call is refused),
        // and an unreadable link is included (attempt the join rather than silently skip it).
        let readings = [
            (libc::CLONE_NEWUSER, os("user:[1]"), os("user:[9]")),
            (libc::CLONE_NEWNET, os("net:[5]"), os("net:[5]")),
            (libc::CLONE_NEWPID, os("pid:[1]"), os("pid:[9]")),
            (libc::CLONE_NEWCGROUP, None, os("cgroup:[9]")),
        ];
        let mask = join_mask(&readings);
        assert_ne!(mask & libc::CLONE_NEWUSER, 0);
        assert_ne!(mask & libc::CLONE_NEWPID, 0);
        assert_ne!(mask & libc::CLONE_NEWCGROUP, 0);
        assert_eq!(
            mask & libc::CLONE_NEWNET,
            0,
            "a namespace shared with the host must not be joined"
        );
    }

    #[test]
    fn build_env_defaults_term_when_the_attaching_terminal_has_none() {
        let env = build_env(b"HOME=/home/sandbox\x00", None);
        let strings: Vec<&str> = env.iter().map(|c| c.to_str().unwrap()).collect();
        assert!(strings.contains(&"TERM=xterm-256color"));
    }
}
