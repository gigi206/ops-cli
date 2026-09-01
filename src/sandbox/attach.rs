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
//! - **no_new_privs + capabilities** are likewise re-applied, and the capability drops are
//!   load-bearing rather than decorative. `setns(CLONE_NEWUSER)` does not leave the joining
//!   process's credentials alone: the kernel grants it a *full* permitted, effective and bounding
//!   set inside the namespace it has just entered, so for a moment the joining process is the most
//!   capable process in the cage. `no_new_privs` does not take that back — it bounds a
//!   file-capability `execve` by intersecting the permitted set the file would grant with the
//!   caller's own, which is a no-op when the caller's own set is already full. What keeps the
//!   entered shell no more capable than the agent is therefore the *emptying* of the sets:
//!   [`confine_and_exec`] drops the whole bounding set (the `X` in the kernel's `pP' = X & fP`,
//!   and so the only thing standing between a file-capability binary inside the cage and a
//!   privileged `execve`), clears the ambient set, and then empties permitted, effective and
//!   inheritable with `capset`. Each of the three is checked, and a failure `_exit`s rather than
//!   exec'ing a shell more capable than the agent. `no_new_privs` is still set first, because an
//!   unprivileged seccomp install requires it. The intermediate process that performed the
//!   `setns` empties its own sets the same way as soon as it has forked, so no process outlives
//!   the join still holding what the join granted.
//!
//! Three residuals, all named and accepted:
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
//! - **the environment the shell starts from is the agent's too.** It is read out of a live in-cage
//!   process ([`read_environ`]), which that process owns: `PATH`, the proxy variables and the CA
//!   path are whatever the agent left there, not whatever bubblewrap originally set. It is passed
//!   through unfiltered on purpose — those variables are what let the entered shell resolve
//!   anything inside the cage, and stripping them would buy no confinement, because the binary they
//!   point at is the agent's either way (bullet above). What bounds the entered process is the
//!   seccomp and capability re-application, never the environment it inherits.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

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
/// `pidfd_open` is permitted; the pidfd pins that exact process, so a pid reused **after** it is
/// opened can never be entered by mistake.
///
/// After it is opened, and that is the whole of what a pidfd promises. [`find_cage_pid`] chose this
/// pid a moment earlier, and the doc here used to say the pin covered that moment too — it does not:
/// a pid recycled between the choice and the open is pinned as confidently as the right one. So the
/// discriminating predicate is asked again on the pinned pid, and it is the one that separates this
/// session's cage from everything else on the host: does that process's mount namespace carry the
/// project. A pid recycled into an unrelated process fails it, and a `sbx session attach` that would
/// otherwise have entered whatever now holds the number is refused instead.
///
/// The window it does not close is the one strictly between the choice and this re-check, which
/// needs the recycled process to satisfy the predicate as well — that is, to be another process in
/// this same session's cage, which is not a wrong place to attach. Closing it outright would mean
/// verifying identity *through* the descriptor rather than through `/proc/<pid>`, which the kernel
/// gives no way to do for the question being asked here.
pub(super) fn open_cage_handle(pid: u32, project: &Path) -> io::Result<CageHandle> {
    // SAFETY: `pidfd_open` with flags 0 returns a fresh owned descriptor or -1/errno.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh owned descriptor from `pidfd_open`, wrapped exactly once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
    if !in_session_cage(pid, project) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "the process chosen for this session is no longer in the session's cage",
        ));
    }
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

/// Read the cage environment from a live in-cage process's `/proc/<pid>/environ`
/// (NUL-separated `KEY=VALUE`) — ordinarily what bubblewrap set for the agent, its
/// PATH, proxy and CA settings. Ordinarily, not necessarily: the process it is read
/// from is one the agent owns, so the agent decides what it says — it can exec a child
/// with any environment it likes, or rewrite its own `environ` region in place. That is
/// the third residual this module names above, and it is bounded the same way: the
/// entered process is confined regardless of what it is told, and by the
/// never-in-the-cage secrets invariant no plaintext credential is there to leak. The
/// read itself is best-effort: an empty one yields an empty env.
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

/// One descendant of the session pid, with everything [`choose_cage_pid`] judges it on.
struct Candidate {
    pid: u32,
    /// The `user:[<inode>]` link of `/proc/<pid>/ns/user`; `None` once the process is gone.
    userns: Option<String>,
    /// `/proc/<pid>/comm`; `None` once the process is gone.
    comm: Option<String>,
    /// Whether this process is in the session's *own* cage rather than a sibling plugin fence —
    /// see [`in_session_cage`].
    in_session_cage: bool,
}

/// Locate a live process *inside* the cage of session `session_pid`, whose project root is
/// `project`. The recorded pid is the cage's host-side anchor — bubblewrap on the exec path, the
/// sbx supervisor on the egress path — and the cage processes are always its descendants (verified
/// on both paths). Among the descendants, one in a *child* user namespace that carries the
/// session's project is inside the cage; the payload (not bubblewrap itself) is preferred so its
/// `environ` is the cage environment. Returns `None` if the cage has no live in-namespace process
/// (it just exited, or the host lacks user namespaces).
pub(super) fn find_cage_pid(session_pid: u32, project: &Path) -> Option<u32> {
    let host = userns_link(std::process::id())?;
    let parents = parent_map();
    let candidates: Vec<Candidate> = descendants(session_pid, &parents)
        .into_iter()
        .map(|pid| Candidate {
            pid,
            userns: userns_link(pid),
            comm: comm(pid),
            in_session_cage: in_session_cage(pid, project),
        })
        .collect();
    choose_cage_pid(&candidates, &host)
}

/// Whether `pid`'s mount namespace carries `project` — the mark that tells the session's own cage
/// apart from a sibling plugin fence.
///
/// "Any descendant in a child user namespace" is not the cage. The recorded pid is the sbx
/// supervisor, and the supervisor is also the parent of every broker and signer plugin fence: each
/// of those is its own `bwrap` with its own user namespace, and a broker fence is spawned *on the
/// caged agent's request*, whenever it opens a broker connection. [`descendants`] walks the
/// highest-numbered direct child's subtree first, so a fence spawned after the payload is normally
/// reached ahead of it — which would hand the operator a shell in the credential-brokering cage the
/// design exists to keep separate, while the agent it meant to inspect stayed invisible, at a
/// moment the agent picks.
///
/// What separates them is what they mount. Every payload cage binds its project at the project's
/// own absolute path (a structural mount of `binds::build_spec`, and the same path the session
/// record stores), while a plugin fence's mounts are fixed by `resolver::cage_spec` — the host
/// `/usr`, `/proc`, `/dev`, a `/tmp` tmpfs, the plugin's own directory and its manifest's grant
/// paths — and carry no workspace. The probe goes through `/proc/<pid>/root`, so the rest of the
/// path is resolved inside that process's own mount namespace.
///
/// In-cage code cannot forge or drop the mark: creating a mount namespace needs `unshare`, adding a
/// mount needs `mount`, and removing this one needs `umount2` — the cage's seccomp denylist refuses
/// all three. The one residual is an operator-installed plugin whose manifest grants a path
/// containing the project; its fence would then also carry the mark, which is a plugin the operator
/// chose to trust with the workspace.
fn in_session_cage(pid: u32, project: &Path) -> bool {
    let mut probe = PathBuf::from(format!("/proc/{pid}/root"));
    // Component-wise: `project` is absolute, and pushing an absolute path would replace the
    // `/proc/<pid>/root` prefix instead of extending it.
    probe.extend(
        project
            .components()
            .filter(|c| matches!(c, Component::Normal(_))),
    );
    std::fs::metadata(probe).is_ok_and(|m| m.is_dir())
}

/// Pick the cage process from the candidates: skip any in the host user namespace (`host_userns`)
/// and any that is not in this session's own cage ([`in_session_cage`]), prefer the first
/// non-`bwrap` process left (the payload, whose `environ` is the cage's), and fall back to a
/// child-namespace `bwrap` if that is all there is. Pure.
fn choose_cage_pid(candidates: &[Candidate], host_userns: &str) -> Option<u32> {
    let mut fallback = None;
    for candidate in candidates {
        let Some(userns) = &candidate.userns else {
            continue;
        };
        if userns == host_userns || !candidate.in_session_cage {
            continue;
        }
        if candidate.comm.as_deref() != Some("bwrap") {
            return Some(candidate.pid);
        }
        fallback.get_or_insert(candidate.pid);
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
    unsafe {
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
        // The shell's parent stays inside the cage's mount/net/ipc/uts namespaces, holding
        // everything the `setns` granted, for as long as the attach lasts — so empty its
        // capability sets too. It has to happen *after* the fork: emptying the effective set
        // before it would take CAP_SETPCAP away from the child, whose own bounding-set drop needs
        // it. The child is killed rather than left behind if the drop fails, because a supervisor
        // that exits would orphan a live shell inside the cage.
        if !drop_all_capabilities() {
            libc::kill(child, libc::SIGKILL);
            libc::_exit(125);
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
    unsafe {
        match tty {
            // setsid + make the pty slave our controlling terminal + dup it onto stdio — the
            // same `login_tty` the an interactive `sbx run` supervisor uses, so job control works inside.
            TtyMode::Pty(slave) => {
                if libc::login_tty(slave) != 0 {
                    libc::_exit(127);
                }
            }
            // A non-interactive command: keep sbx's own stdin/stdout/stderr so bytes pass through
            // unmodified (no pty line translation). The stdio is inherited; the **session** is not.
            //
            // A controlling terminal is a property of the session and survives `fork`, so without
            // this the joined process kept `sbx session attach`'s own ctty. `--dev /dev` gives the
            // cage `/dev/tty`, the 5:0 device that resolves to the opener's controlling terminal
            // whatever the mount namespace, so in-cage code could open it, read the user's
            // keystrokes, write to it and drive its termios — and keep it after sbx exited. Nothing
            // in the seccomp filter closes that: it refuses `TIOCSTI`, which is a different attack
            // on the same device.
            //
            // Every other launch path leaves the session for this reason (`argv.rs` emits
            // `--new-session`), and its one documented exception is the private pty above, where
            // `login_tty` does the `setsid` itself. Fatal on failure, like the confinement steps
            // below: entering without leaving the session is entering unconfined in this respect.
            TtyMode::Inherit => {
                if libc::setsid() < 0 {
                    libc::_exit(126);
                }
            }
        }
        // Re-apply the cage confinement — NONE of it survived `setns`. `no_new_privs`
        // before seccomp: an unprivileged filter install requires it.
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            libc::_exit(125);
        }
        // Empty every capability set. The `setns` into the cage's user namespace granted this
        // process a full permitted, effective and bounding set there, and `no_new_privs` does not
        // undo that (module header), so these drops — not the `prctl` above — are what makes the
        // exec'd command no more privileged than the agent. Order is forced: the bounding set is
        // `X` in the kernel's `pP' = X & fP`, so it must go before the permitted set that carries
        // the CAP_SETPCAP the drop itself requires.
        //
        // Every failure is fatal. A capability number this kernel does not define answers `EINVAL`
        // and is simply past the end of the set; anything else is a failure to confine, and
        // confining is the precondition of entering at all.
        let mut cap: libc::c_int = 0;
        while cap <= 63 {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) != 0
                && *libc::__errno_location() != libc::EINVAL
            {
                libc::_exit(125);
            }
            cap += 1;
        }
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        ) != 0
        {
            libc::_exit(125);
        }
        if !drop_all_capabilities() {
            libc::_exit(125);
        }
        // The seccomp denylist — the other re-application the confinement rests on: this refuses
        // the mount/namespace/ptrace family the confined agent cannot call.
        if !super::seccomp::install_filters(filters) {
            libc::_exit(125);
        }
        libc::execve(*argv, argv, envp);
        // Only reached if execve failed (e.g. the cage's /bin/bash is gone).
        libc::_exit(127);
    }
}

/// Empty the calling thread's permitted, effective and inheritable capability sets, reporting
/// whether the kernel accepted the call.
///
/// Both processes on the attach path call it, and not for symmetry with the cage: entering a user
/// namespace makes a process fully capable *in that namespace*, so the join itself is what grants
/// the privilege being taken away here. Lowering one's own sets never requires a capability, so the
/// only way this fails is an ABI the kernel does not recognise — which is why each caller treats a
/// failure as a reason to refuse the attach rather than as a best-effort miss.
///
/// # Safety
///
/// Async-signal-safe: one `capset` syscall over two stack buffers, no allocation and no locks, so
/// it may be called between `fork` and `exec`.
unsafe fn drop_all_capabilities() -> bool {
    /// `_LINUX_CAPABILITY_VERSION_3`: the 64-capability ABI, which splits each set across two
    /// 32-bit words. Version 1 covers only the first 32 and the kernel answers `EINVAL` for it on
    /// a modern header, so the version word is not a formality.
    const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    // `struct __user_cap_header_struct { __u32 version; int pid; }` — pid 0 meaning this thread —
    // followed by two `struct __user_cap_data_struct { __u32 effective, permitted, inheritable; }`,
    // the low half of each set first. Written as plain words because Rust only ever fills them in:
    // every field is read by the kernel, none by this crate.
    let mut header: [u32; 2] = [CAPABILITY_VERSION_3, 0];
    let data: [u32; 6] = [0; 6];
    // SAFETY: both buffers are live for the call and sized exactly as the version-3 ABI above
    // requires. The header is passed mutably because a kernel that rejects the version writes the
    // one it prefers back into that word before answering `EINVAL`.
    unsafe { libc::syscall(libc::SYS_capset, header.as_mut_ptr(), data.as_ptr()) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a candidate; `in_session_cage` says whether it carries the session's project mount.
    fn candidate(pid: u32, userns: Option<&str>, comm: Option<&str>, mine: bool) -> Candidate {
        Candidate {
            pid,
            userns: userns.map(str::to_string),
            comm: comm.map(str::to_string),
            in_session_cage: mine,
        }
    }

    #[test]
    fn choose_prefers_the_payload_over_bwrap_and_skips_the_host_namespace() {
        let host = "user:[4026531837]";
        let child = "user:[4026533809]";
        // Order: an outer bwrap in the host ns, the inner bwrap in the child ns, then
        // the payload in the child ns. The payload must win despite bwrap coming first.
        let candidates = vec![
            candidate(100, Some(host), Some("bwrap"), true),
            candidate(101, Some(child), Some("bwrap"), true),
            candidate(102, Some(child), Some("sleep"), true),
            candidate(103, Some(child), Some("socat"), true),
        ];
        assert_eq!(choose_cage_pid(&candidates, host), Some(102));
    }

    #[test]
    fn choose_falls_back_to_bwrap_when_it_is_the_only_in_cage_process() {
        let host = "user:[4026531837]";
        let child = "user:[4026533809]";
        let candidates = vec![
            candidate(100, Some(host), Some("bwrap"), true),
            candidate(101, Some(child), Some("bwrap"), true),
        ];
        assert_eq!(choose_cage_pid(&candidates, host), Some(101));
    }

    #[test]
    fn choose_returns_none_when_every_candidate_is_in_the_host_namespace() {
        // No process left a child user namespace: the cage is gone, so there is
        // nothing to attach to.
        let host = "user:[4026531837]";
        let candidates = vec![
            candidate(100, Some(host), Some("bwrap"), true),
            candidate(200, Some(host), Some("sbx"), true),
            candidate(300, None, None, false),
        ];
        assert_eq!(choose_cage_pid(&candidates, host), None);
    }

    /// A plugin fence is never mistaken for the agent's cage.
    ///
    /// The session pid is the sbx supervisor, so a broker or signer fence — its own `bwrap`, its
    /// own user namespace — is a sibling subtree of the payload's, not a stranger. A broker fence
    /// is spawned when the caged agent opens a broker connection, and [`descendants`] walks the
    /// highest-numbered direct child's subtree first, so the agent can arrange for a fence to be
    /// the first candidate at the moment an operator attaches. "In a child user namespace and not
    /// `bwrap`" accepts it; only the session's own project mount tells the two apart, and it has to
    /// beat *both* the payload preference and the `bwrap` fallback.
    #[test]
    fn a_plugin_fence_is_never_chosen_over_the_agents_own_cage() {
        let host = "user:[4026531837]";
        let fence = "user:[4026534000]";
        let cage = "user:[4026533809]";
        // The fence subtree comes first, exactly as the highest-pid-first walk yields it.
        let candidates = vec![
            candidate(200, Some(fence), Some("bwrap"), false),
            candidate(201, Some(fence), Some("sbx-broker-ssh"), false),
            candidate(101, Some(cage), Some("bwrap"), true),
            candidate(102, Some(cage), Some("claude"), true),
        ];
        assert_eq!(
            choose_cage_pid(&candidates, host),
            Some(102),
            "the agent's payload must win over a fence's plugin process that comes first"
        );

        // And with the payload already gone, the fallback is the cage's own bwrap — never the
        // fence's, which would hand the operator a shell in the credential-brokering cage.
        let candidates = vec![
            candidate(200, Some(fence), Some("bwrap"), false),
            candidate(201, Some(fence), Some("sbx-broker-ssh"), false),
            candidate(101, Some(cage), Some("bwrap"), true),
        ];
        assert_eq!(choose_cage_pid(&candidates, host), Some(101));

        // With nothing but the fence left there is no cage to enter, and saying so is the only
        // safe answer: attaching into a fence is worse than reporting that the session is gone.
        let candidates = vec![
            candidate(200, Some(fence), Some("bwrap"), false),
            candidate(201, Some(fence), Some("sbx-broker-ssh"), false),
        ];
        assert_eq!(choose_cage_pid(&candidates, host), None);
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

    /// The `capset` that empties the entered process is hand-rolled against the kernel ABI, so a
    /// wrong version word or a mis-sized data buffer would be answered with `EINVAL` — and the
    /// process would keep every capability the user-namespace join granted it. Proven in a forked
    /// child that runs only async-signal-safe calls, so the suite's own credentials are untouched
    /// whatever privilege it happens to run with.
    #[test]
    fn the_capset_that_empties_a_joined_process_is_accepted_by_the_kernel() {
        // SAFETY: the child calls `capset` and `_exit` only — both async-signal-safe — so the
        // fork is safe from a threaded harness.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe { libc::_exit(i32::from(!drop_all_capabilities())) };
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status),
            "the probe child did not exit normally"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "the kernel refused the capability drop the attach path depends on"
        );
    }

    /// Both arms of `confine_and_exec` must leave `sbx session attach`'s session. The pty arm does
    /// it through `login_tty`; the inherited-stdio arm has to say so itself, and used to be empty.
    /// A controlling terminal survives `fork`, and `--dev /dev` puts `/dev/tty` in the cage, so a
    /// process that kept the ctty can read the user's keystrokes from it — an exposure seccomp does
    /// not close, since it refuses `TIOCSTI` and this needs no ioctl at all.
    ///
    /// Pinned against the source because the defect is an arm that does *nothing*: there is no
    /// call to observe from a test, only the absence of one, and an empty arm reads as deliberate.
    #[test]
    fn both_tty_arms_leave_the_launching_session() {
        // The production half only: this test quotes the shapes it looks for.
        let source = include_str!("attach.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");
        assert!(
            source.contains("if libc::setsid() < 0 {"),
            "the inherited-stdio arm must leave the session; the pty arm's `login_tty` does it \
             for that one"
        );
        assert!(
            source.contains("libc::login_tty(slave)"),
            "and the pty arm still takes its own controlling terminal"
        );
    }

    /// Every capability drop on the attach path is checked, and both processes that hold what the
    /// join granted perform one. A discarded return here fails nothing else in the suite: the
    /// drops succeed on every host that runs it, and the exposure — a file-capability binary in
    /// the cage gaining privilege across the entered shell's `execve` — appears only on a host
    /// where one of them does not. So the shape is pinned against the source.

    #[test]
    fn the_capability_drops_the_join_makes_necessary_are_checked_not_attempted() {
        // The production half only: this test quotes the shapes it looks for, and would otherwise
        // find its own assertions.
        let source = include_str!("attach.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a production half");
        assert!(
            source.contains("if libc::prctl(libc::PR_CAPBSET_DROP"),
            "the bounding-set drop bounds `X` in `pP' = X & fP`: its return decides whether the \
             entered shell may still gain file capabilities, so it cannot be discarded"
        );
        assert_eq!(
            source.matches("if !drop_all_capabilities()").count(),
            2,
            "both the exec'd command and the process supervising it must empty the sets \
             `setns(CLONE_NEWUSER)` granted them"
        );
    }
}
