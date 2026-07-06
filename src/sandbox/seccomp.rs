//! The mandatory seccomp-bpf denylist — kernel-attack-surface reduction layered
//! on top of the namespace cage.
//!
//! bubblewrap drops capabilities and isolates every namespace, but the agent can
//! still *reach* the whole syscall surface. This module narrows it: a
//! **default-allow** filter that refuses a denylist of syscalls which have no
//! legitimate in-cage use and a history of kernel privilege-escalation. It is the
//! consensus shape of serious unprivileged agent sandboxes (Flatpak, greywall,
//! Codex, Anthropic), and it is **unconditional** — the launcher loads it on every
//! cage, the same way [`super::argv`] emits the namespace hardening.
//!
//! ## Two filters, two actions
//!
//! seccompiler compiles one action per filter, and the denylist needs two:
//!
//! - **EPERM** for the surface-reduction set (ptrace, the module/kexec/keyring
//!   families, `bpf`, `perf_event_open`, `io_uring`, `userfaultfd`, …) **and** the
//!   mount/namespace family (`unshare`/`setns`/`mount`/`umount2`/`pivot_root`/
//!   `chroot`, plus `clone` filtered on its `CLONE_NEWUSER`/`CLONE_NEWNS` flags).
//! - **ENOSYS** for `clone3` and the *new* mount API (`fsopen`/`fsmount`/… and
//!   `open_tree`/`move_mount`). ENOSYS — not EPERM — because these are the
//!   *bypass* routes for the EPERM set (a namespace via `clone3`, a mount via
//!   `fsmount`), and ENOSYS lets glibc and tools fall back gracefully
//!   (`clone3`→`clone`, the new mount API→`mount`). Returning EPERM here would
//!   break process creation, since glibc only falls back to `clone` on ENOSYS.
//!
//! The two denylists are disjoint and both filters run on every syscall; since a
//! non-matching filter yields *allow* and an `errno` action outranks *allow*, each
//! denied syscall gets exactly its own filter's action.
//!
//! ## The mount/namespace family and in-cage nix
//!
//! Blocking the mount/ns family removes the userns→mount→overlayfs/pivot_root
//! kernel paths — the most common Linux container-escape class — from the cage.
//! But nix's *build* sandbox creates those same namespaces, so an in-cage
//! `nix build` would hit the filter. The cage is the security boundary, not nix's
//! inner sandbox, so the launcher resolves this by forcing nix's `sandbox = false`
//! (in [`super::binds`]'s structural `NIX_CONFIG`): in-cage builds run without
//! their redundant inner sandbox and never touch the blocked syscalls. The agent
//! already runs arbitrary code in the cage, so this is no escalation.
//!
//! Carve-outs kept *allowed* on purpose: `AF_UNIX` sockets (the egress forwarder's
//! bridge), `socketpair`, and `recvfrom` (toolchain subprocess plumbing).

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("ops's seccomp denylist is implemented only for x86_64 and aarch64");

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// `clone`/`unshare` flag for a new user namespace.
const CLONE_NEWUSER: u64 = 0x1000_0000;
/// `clone`/`unshare` flag for a new mount namespace.
const CLONE_NEWNS: u64 = 0x0002_0000;
/// `ioctl` request that injects bytes into a terminal's input queue.
const TIOCSTI: u64 = 0x5412;
/// `ioctl` request that drives the Linux console (selection, also injection-capable).
const TIOCLINUX: u64 = 0x541C;

type Rules = BTreeMap<i64, Vec<SeccompRule>>;

/// Match `clone`/`unshare` calls that request the given namespace flag in arg0.
fn arg0_has_flag(flag: u64) -> SeccompRule {
    SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(flag),
        flag,
    )
    .expect("a constant condition is valid")])
    .expect("a single-condition rule is valid")
}

/// Match an `ioctl` whose request (arg1) equals `request`.
fn arg1_is(request: u64) -> SeccompRule {
    SeccompRule::new(vec![SeccompCondition::new(
        1,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::Eq,
        request,
    )
    .expect("a constant condition is valid")])
    .expect("a single-condition rule is valid")
}

/// The syscalls denied outright with EPERM — no namespace/mount semantics, so an
/// unconditional refusal is safe.
fn eperm_unconditional() -> Vec<i64> {
    let mut v = vec![
        // process inspection/patching of siblings
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // kernel module loading
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        // kexec / reboot
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        libc::SYS_reboot,
        // introspection / perf / async-IO that hides syscalls from a filter
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_userfaultfd,
        // kernel keyring
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        // misc privileged
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_syslog,
        libc::SYS_sethostname,
        libc::SYS_setdomainname,
        libc::SYS_personality,
        // mount / namespace family (the container-escape surface)
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
    ];
    // I/O-port access exists only on x86.
    #[cfg(target_arch = "x86_64")]
    v.extend_from_slice(&[libc::SYS_ioperm, libc::SYS_iopl]);
    v
}

/// The EPERM filter's rules: the unconditional set, plus `clone` filtered on its
/// namespace flags and `ioctl` filtered on the terminal-injection requests.
fn eperm_rules() -> Rules {
    let mut m = Rules::new();
    for nr in eperm_unconditional() {
        m.insert(nr, vec![]); // empty rule vec = match unconditionally
    }
    // clone is also ordinary fork/thread creation; deny only when it asks for a
    // new user or mount namespace.
    m.insert(
        libc::SYS_clone,
        vec![arg0_has_flag(CLONE_NEWUSER), arg0_has_flag(CLONE_NEWNS)],
    );
    // ioctl is ubiquitous; deny only the terminal-injection requests.
    m.insert(libc::SYS_ioctl, vec![arg1_is(TIOCSTI), arg1_is(TIOCLINUX)]);
    m
}

/// The ENOSYS filter's rules: `clone3` and the new mount API, so a caller falls
/// back to the (filtered) old syscalls instead of bypassing the EPERM denylist.
fn enosys_rules() -> Rules {
    let mut m = Rules::new();
    for nr in [
        libc::SYS_clone3,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_mount_setattr,
    ] {
        m.insert(nr, vec![]);
    }
    m
}

/// Compile a rule set with the given match action into raw cBPF bytes.
fn compile(rules: Rules, match_action: SeccompAction) -> Vec<u8> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, match_action, TARGET_ARCH)
        .expect("a statically-defined filter is always valid");
    let program: BpfProgram = filter.try_into().expect("the filter compiles to cBPF");
    serialize(&program)
}

/// Serialize a compiled program to the raw `struct sock_filter` array bytes
/// (native-endian) that `bwrap --add-seccomp-fd` reads.
fn serialize(program: &BpfProgram) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for insn in program {
        bytes.extend_from_slice(&insn.code.to_ne_bytes());
        bytes.push(insn.jt);
        bytes.push(insn.jf);
        bytes.extend_from_slice(&insn.k.to_ne_bytes());
    }
    bytes
}

/// The two compiled filters in load order: the EPERM denylist, then the ENOSYS
/// denylist. Pure.
fn programs() -> [Vec<u8>; 2] {
    [
        compile(eperm_rules(), SeccompAction::Errno(libc::EPERM as u32)),
        compile(enosys_rules(), SeccompAction::Errno(libc::ENOSYS as u32)),
    ]
}

/// Write each compiled filter into an anonymous in-memory file, ready to hand to
/// `bwrap --add-seccomp-fd`. The descriptors are deliberately **not**
/// close-on-exec so bwrap inherits them across the launch; the caller must keep
/// the returned files alive until bwrap has read them. (No `memfd` seal is applied
/// or needed — the file is written, rewound, and read once by bwrap.)
pub(crate) fn memfds() -> io::Result<Vec<File>> {
    programs().into_iter().map(write_to_memfd).collect()
}

fn write_to_memfd(bytes: Vec<u8>) -> io::Result<File> {
    // SAFETY: the name is a valid NUL-terminated C string and `flags = 0` yields a
    // descriptor without O_CLOEXEC, so it survives the exec into bwrap.
    let fd = unsafe { libc::memfd_create(c"ops-seccomp".as_ptr(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: memfd_create returned an owned descriptor we wrap exactly once.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// The bwrap flags that load `memfds` as additional seccomp filters, to be placed
/// before the rest of the argv. Each is applied on top of the others.
pub(crate) fn argv_prefix(memfds: &[File]) -> Vec<OsString> {
    let mut a = Vec::with_capacity(memfds.len() * 2);
    for f in memfds {
        a.push(OsString::from("--add-seccomp-fd"));
        a.push(OsString::from(f.as_raw_fd().to_string()));
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn the_two_denylists_are_disjoint() {
        let eperm = eperm_rules();
        let enosys = enosys_rules();
        for nr in enosys.keys() {
            assert!(
                !eperm.contains_key(nr),
                "syscall {nr} is in both filters; their actions would compete"
            );
        }
    }

    #[test]
    fn the_eperm_set_covers_the_surface_and_the_mount_ns_family() {
        let m = eperm_rules();
        for nr in [
            libc::SYS_ptrace,
            libc::SYS_bpf,
            libc::SYS_io_uring_setup,
            libc::SYS_userfaultfd,
            libc::SYS_keyctl,
            libc::SYS_perf_event_open,
            // mount/ns family
            libc::SYS_unshare,
            libc::SYS_mount,
            // `umount2` is load-bearing beyond LPE surface reduction: the control-plane pins rely
            // on in-cage code being unable to tear a pinned mountpoint down (a launch-side
            // interdependency), so its removal here must fail a test.
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_setns,
        ] {
            assert!(m.contains_key(&nr), "EPERM set is missing syscall {nr}");
        }
        // clone and ioctl are present but conditionally (non-empty rule vecs).
        assert_eq!(m.get(&libc::SYS_clone).map(Vec::len), Some(2));
        assert_eq!(m.get(&libc::SYS_ioctl).map(Vec::len), Some(2));
    }

    #[test]
    fn the_enosys_set_is_clone3_and_the_new_mount_api() {
        let m = enosys_rules();
        for nr in [
            libc::SYS_clone3,
            libc::SYS_fsopen,
            libc::SYS_fsmount,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_mount_setattr,
        ] {
            assert!(m.contains_key(&nr), "ENOSYS set is missing syscall {nr}");
        }
    }

    #[test]
    fn the_egress_and_toolchain_carve_outs_stay_allowed() {
        let eperm = eperm_rules();
        let enosys = enosys_rules();
        // The egress forwarder (socat TCP-LISTEN→UNIX-CONNECT) needs socket/socketpair/recvfrom.
        // The inbound forwarder (socat UNIX-LISTEN→TCP-CONNECT) additionally needs the server
        // socket primitives — bind/listen/accept/connect/sendto — which were never denied, but
        // pinning them here guards against a future denylist that would silently break inbound.
        for nr in [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_recvfrom,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_connect,
            libc::SYS_sendto,
        ] {
            assert!(!eperm.contains_key(&nr), "carve-out {nr} must stay allowed");
            assert!(
                !enosys.contains_key(&nr),
                "carve-out {nr} must stay allowed"
            );
        }
    }

    #[test]
    fn both_filters_compile_to_non_empty_programs() {
        let [eperm, enosys] = programs();
        assert!(!eperm.is_empty() && eperm.len() % 8 == 0);
        assert!(!enosys.is_empty() && enosys.len() % 8 == 0);
    }

    #[test]
    fn the_eperm_filter_actually_blocks_a_denied_syscall() {
        // The set-membership tests prove WHICH syscalls are listed; this proves the compiled filter
        // ENFORCES — a regression that flipped the match action to Allow or broke the codegen would
        // pass those yet fail here, without needing bwrap (so it runs in `cargo test --bins`). The
        // filter is built in the parent and installed in a forked child that runs ONLY
        // async-signal-safe calls (prctl + syscall + _exit), so there is no fork-in-threaded hazard
        // and no test-harness recursion.
        let prog = compile(eperm_rules(), SeccompAction::Errno(libc::EPERM as u32));
        // SAFETY: the child touches only async-signal-safe libc calls before `_exit`; `prog` is
        // read-only memory shared copy-on-write from the parent (the child allocates nothing).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let fprog = libc::sock_fprog {
                    len: (prog.len() / 8) as libc::c_ushort,
                    filter: prog.as_ptr() as *mut libc::sock_filter,
                };
                if libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &fprog as *const libc::sock_fprog as libc::c_ulong,
                ) != 0
                {
                    // could not install the filter (e.g. a kernel without CONFIG_SECCOMP): skip.
                    libc::_exit(2);
                }
                // a denied syscall must return EPERM (neither succeed nor kill the process)
                let denied = libc::syscall(libc::SYS_keyctl, 0, 0, 0, 0, 0);
                let blocked = denied == -1 && *libc::__errno_location() == libc::EPERM;
                // an allowed syscall must still work
                let allowed_ok = libc::getpid() > 0;
                libc::_exit(if blocked && allowed_ok { 0 } else { 1 });
            }
        }
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFEXITED(status),
            "the probe child did not exit normally"
        );
        match libc::WEXITSTATUS(status) {
            0 => {} // enforced: the denied syscall was refused with EPERM, the allowed one ran
            2 => eprintln!(
                "skipping seccomp enforcement: filter not installable (no CONFIG_SECCOMP?)"
            ),
            code => panic!("the EPERM filter did not enforce the denylist (probe exit {code})"),
        }
    }

    #[test]
    fn each_memfd_holds_its_compiled_filter() {
        let files = memfds().expect("memfds");
        let expected = programs();
        assert_eq!(files.len(), 2);
        for (mut f, want) in files.into_iter().zip(expected) {
            let mut got = Vec::new();
            f.read_to_end(&mut got).expect("read memfd");
            assert_eq!(got, want, "memfd content must equal the compiled filter");
        }
    }

    #[test]
    fn argv_prefix_emits_one_add_flag_per_filter() {
        let files = memfds().expect("memfds");
        let argv = argv_prefix(&files);
        assert_eq!(argv.len(), 4);
        assert_eq!(argv[0], "--add-seccomp-fd");
        assert_eq!(argv[2], "--add-seccomp-fd");
        // the fd numbers are the live descriptors
        assert_eq!(argv[1], files[0].as_raw_fd().to_string().as_str());
        assert_eq!(argv[3], files[1].as_raw_fd().to_string().as_str());
    }

    /// `bwrap` plus a capability-bearing user namespace, or `None` to skip.
    fn sandbox_prereq() -> Option<std::path::PathBuf> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        matches!(crate::probe_userns(), crate::Userns::Ok).then_some(bwrap)
    }

    /// End-to-end teeth: load the real compiled filters into a real cage and
    /// confirm the kernel enforces them — a denied core syscall returns EPERM, a
    /// bypass route (`clone3`) returns ENOSYS, and the `AF_UNIX` carve-out works.
    /// x86_64-only because it triggers syscalls by raw number.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_real_cage_enforces_the_denylist() {
        use super::super::spec::{Mount, NetPolicy, SandboxSpec};
        use std::path::PathBuf;
        use std::process::Command;

        let Some(bwrap) = sandbox_prereq() else {
            eprintln!("skipping seccomp cage test: no bwrap or no capability-bearing userns");
            return;
        };
        if !PathBuf::from("/usr/bin/python3").exists() {
            eprintln!("skipping seccomp cage test: no /usr/bin/python3 for the probe");
            return;
        }

        // x86_64 syscall numbers: keyctl=250, clone3=435, unshare=272, clone=56,
        // ioctl=16. `clone(CLONE_NEWUSER|SIGCHLD)` and `ioctl(TIOCSTI)` exercise the
        // *argument-filtered* rules (a different BPF codegen than the unconditional
        // entries); a regression in either reopens the mount/namespace escape surface the
        // denylist closes.
        // The EPERM action fires before the syscall runs, so the clone probe spawns
        // no child. `fork()` (clone without namespace flags) must still succeed.
        let probe = "import ctypes,os,socket\n\
             l=ctypes.CDLL(None,use_errno=True)\n\
             def e(nr,*a):\n \
              ctypes.set_errno(0); l.syscall(nr,*[ctypes.c_long(x) for x in a]); return ctypes.get_errno()\n\
             print('keyctl',e(250,0,-3,0))\n\
             print('clone3',e(435,0,0))\n\
             print('unshare',e(272,0x10000000))\n\
             print('clone_newuser',e(56,0x10000000|17,0,0,0,0))\n\
             print('ioctl_tiocsti',e(16,0,0x5412,0))\n\
             pid=os.fork()\n\
             if pid==0: os._exit(0)\n\
             os.waitpid(pid,0); print('fork','ok')\n\
             s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); print('afunix','ok'); s.close()\n";

        let mounts = vec![
            Mount::RoBind {
                src: PathBuf::from("/usr"),
                dest: PathBuf::from("/usr"),
            },
            Mount::Symlink {
                target: PathBuf::from("usr/lib"),
                dest: PathBuf::from("/lib"),
            },
            Mount::Symlink {
                target: PathBuf::from("usr/lib64"),
                dest: PathBuf::from("/lib64"),
            },
            Mount::Symlink {
                target: PathBuf::from("usr/bin"),
                dest: PathBuf::from("/bin"),
            },
            Mount::Proc {
                dest: PathBuf::from("/proc"),
            },
            Mount::Dev {
                dest: PathBuf::from("/dev"),
            },
            Mount::Tmpfs {
                dest: PathBuf::from("/tmp"),
            },
        ];
        let spec = SandboxSpec::new(
            PathBuf::from("/tmp"),
            mounts,
            vec![("PATH".to_string(), "/usr/bin:/bin".to_string())],
            NetPolicy::Shared,
            vec![
                OsString::from("/usr/bin/python3"),
                OsString::from("-c"),
                OsString::from(probe),
            ],
        )
        .expect("probe spec");

        let memfds = memfds().expect("memfds");
        let mut argv = argv_prefix(&memfds);
        argv.extend(super::super::argv::to_argv(&spec));
        let out = Command::new(&bwrap)
            .args(argv)
            .output()
            .expect("launch bwrap");
        // memfds stay alive until here.
        drop(memfds);

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "probe did not run; stdout=\n{stdout}\nstderr=\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(stdout.contains("keyctl 1"), "keyctl not EPERM: {stdout}");
        assert!(stdout.contains("clone3 38"), "clone3 not ENOSYS: {stdout}");
        assert!(stdout.contains("unshare 1"), "unshare not EPERM: {stdout}");
        assert!(
            stdout.contains("clone_newuser 1"),
            "clone(CLONE_NEWUSER) not EPERM — the userns escape path is open: {stdout}"
        );
        assert!(
            stdout.contains("ioctl_tiocsti 1"),
            "ioctl(TIOCSTI) not EPERM — terminal injection is open: {stdout}"
        );
        assert!(
            stdout.contains("fork ok"),
            "fork (clone without namespace flags) was wrongly denied: {stdout}"
        );
        assert!(
            stdout.contains("afunix ok"),
            "AF_UNIX carve-out broke: {stdout}"
        );
    }
}
