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
//!
//! ## Relaxing the denylist — `[seccomp] allow`
//!
//! The denylist is mandatory by default, but a **trusted** config (global or a trusted
//! project) can re-permit a specific denied syscall so a tool that genuinely needs it — a
//! debugger (`ptrace`), a profiler (`perf_event_open`), a runtime using `userfaultfd`, or
//! nested-container tooling (`unshare`/`mount`) — can run in the cage. The grammar is
//! **uniform**: a bare syscall name (`ptrace`, `unshare`, `mount`) lifts the whole syscall,
//! while `clone`/`ioctl` — the two *argument-filtered* entries — additionally accept a
//! `:selector` (`clone:newns`, `ioctl:tioclinux`) that lifts only one sub-rule and leaves the
//! rest denied. An empty or absent `allow` list reproduces the mandatory baseline exactly.
//! Loosening is trusted-only (an untrusted project's `[seccomp]` is dropped), and each token
//! that reopens a real escape surface (`clone`→userns, `ioctl`→terminal injection,
//! `umount2`→a mount teardown that can defeat a control-plane pin) is surfaced with a
//! [`Caution`] the resolver turns into a warning.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("sbx's seccomp denylist is implemented only for x86_64 and aarch64");

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
    SeccompRule::new(vec![
        SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(flag),
            flag,
        )
        .expect("a constant condition is valid"),
    ])
    .expect("a single-condition rule is valid")
}

/// Match an `ioctl` whose request (arg1) equals `request`.
///
/// Compared as a **`Dword`**, and that is the whole of this guard. `ioctl` is
/// `SYSCALL_DEFINE3(ioctl, unsigned int fd, unsigned int cmd, unsigned long arg)`: the kernel takes
/// `cmd` as a 32-bit `unsigned int` and drops whatever rode in the top half of the register. A
/// filter comparing the register's full 64 bits therefore answers a different question from the one
/// the kernel goes on to act on, and `ioctl(fd, 0x1_0000_5412, …)` walks past a `Qword` equality
/// against `0x5412` into a kernel that reads it as `TIOCSTI` and injects into the terminal — the
/// exact escape [`TIOCSTI`] is on this list to close. Every high bit is a fresh spelling, so there
/// is no enumerating them: the comparison has to be the width the kernel uses.
///
/// The masked flag rules beside this one ([`arg0_has_flag`]) are not exposed the same way — a
/// `MaskedEq` looks only at the bits in its mask, so setting others changes nothing — and `clone`
/// does take a 64-bit `flags`, which is why they stay `Qword`.
fn arg1_is(request: u64) -> SeccompRule {
    SeccompRule::new(vec![
        SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, request)
            .expect("a constant condition is valid"),
    ])
    .expect("a single-condition rule is valid")
}

/// The syscalls denied outright with EPERM (no namespace/mount semantics, so an unconditional
/// refusal is safe), as `(name, number)` pairs. This is the **single source** for both the
/// compiled filter and the `[seccomp] allow` name lookup, so the set a trusted config can
/// re-permit can never drift from the set the filter denies. Names are the canonical Linux
/// syscall names — the exact tokens `[seccomp] allow` accepts.
fn eperm_unconditional_named() -> Vec<(&'static str, i64)> {
    let mut v = vec![
        // process inspection/patching of siblings
        ("ptrace", libc::SYS_ptrace),
        ("process_vm_readv", libc::SYS_process_vm_readv),
        ("process_vm_writev", libc::SYS_process_vm_writev),
        // kernel module loading
        ("init_module", libc::SYS_init_module),
        ("finit_module", libc::SYS_finit_module),
        ("delete_module", libc::SYS_delete_module),
        // kexec / reboot
        ("kexec_load", libc::SYS_kexec_load),
        ("kexec_file_load", libc::SYS_kexec_file_load),
        ("reboot", libc::SYS_reboot),
        // introspection / perf / async-IO that hides syscalls from a filter
        ("bpf", libc::SYS_bpf),
        ("perf_event_open", libc::SYS_perf_event_open),
        ("io_uring_setup", libc::SYS_io_uring_setup),
        ("io_uring_enter", libc::SYS_io_uring_enter),
        ("io_uring_register", libc::SYS_io_uring_register),
        ("userfaultfd", libc::SYS_userfaultfd),
        // kernel keyring
        ("keyctl", libc::SYS_keyctl),
        ("add_key", libc::SYS_add_key),
        ("request_key", libc::SYS_request_key),
        // misc privileged
        ("swapon", libc::SYS_swapon),
        ("swapoff", libc::SYS_swapoff),
        ("acct", libc::SYS_acct),
        ("syslog", libc::SYS_syslog),
        ("sethostname", libc::SYS_sethostname),
        ("setdomainname", libc::SYS_setdomainname),
        ("personality", libc::SYS_personality),
        // mount / namespace family (the container-escape surface)
        ("unshare", libc::SYS_unshare),
        ("setns", libc::SYS_setns),
        ("mount", libc::SYS_mount),
        ("umount2", libc::SYS_umount2),
        ("pivot_root", libc::SYS_pivot_root),
        ("chroot", libc::SYS_chroot),
    ];
    // I/O-port access exists only on x86.
    #[cfg(target_arch = "x86_64")]
    v.extend_from_slice(&[("ioperm", libc::SYS_ioperm), ("iopl", libc::SYS_iopl)]);
    v
}

/// The ENOSYS-denied syscalls as `(name, number)` pairs: `clone3` and the new mount API, so a
/// caller falls back to the (filtered) old syscalls instead of bypassing the EPERM denylist.
///
/// Like [`eperm_unconditional_named`], this is the single source for both the filter and the
/// allow-token lookup.
fn enosys_named() -> Vec<(&'static str, i64)> {
    vec![
        ("clone3", libc::SYS_clone3),
        ("open_tree", libc::SYS_open_tree),
        ("move_mount", libc::SYS_move_mount),
        ("fsopen", libc::SYS_fsopen),
        ("fsconfig", libc::SYS_fsconfig),
        ("fsmount", libc::SYS_fsmount),
        ("fspick", libc::SYS_fspick),
        ("mount_setattr", libc::SYS_mount_setattr),
    ]
}

/// The number of a denied syscall by name — searching both the EPERM and ENOSYS unconditional
/// sets (not `clone`/`ioctl`, which are argument-filtered and handled by name in [`resolve_allow`]).
/// `None` for a name sbx does not deny, so an `allow` entry for it is refused (loosening nothing).
fn denied_number(name: &str) -> Option<i64> {
    eperm_unconditional_named()
        .into_iter()
        .chain(enosys_named())
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| nr)
}

/// The canonical name of a denied syscall by number, for rendering a policy back to tokens
/// (`sbx config`). `clone`/`ioctl` are recognized explicitly; every other number is looked up in
/// the two named sets. `None` for a number that is not denied (never happens for a policy built by
/// [`resolve_allow`], whose whole-syscall lifts are all drawn from these sets).
fn denied_name(nr: i64) -> Option<&'static str> {
    if nr == libc::SYS_clone {
        return Some("clone");
    }
    if nr == libc::SYS_ioctl {
        return Some("ioctl");
    }
    eperm_unconditional_named()
        .into_iter()
        .chain(enosys_named())
        .find(|(_, n)| *n == nr)
        .map(|(n, _)| n)
}

/// The EPERM filter's rules for a given relaxation policy: the unconditional set (minus any
/// syscall the policy lifts wholesale), plus `clone` filtered on the namespace flags the policy has
/// not lifted and `ioctl` filtered on the terminal-injection requests the policy has not lifted. A
/// default (empty) policy reproduces the full mandatory denylist.
fn eperm_rules(policy: &SeccompPolicy) -> Rules {
    let mut m = Rules::new();
    for (_, nr) in eperm_unconditional_named() {
        if !policy.whole.contains(&nr) {
            m.insert(nr, vec![]); // empty rule vec = match unconditionally
        }
    }
    // clone is also ordinary fork/thread creation; deny only when it asks for a new user or mount
    // namespace — and only for a flag the policy has not lifted. If the whole syscall is lifted, or
    // every namespace flag is, clone is left entirely allowed (no entry).
    if !policy.whole.contains(&libc::SYS_clone) {
        let clone_rules: Vec<SeccompRule> = [CLONE_NEWUSER, CLONE_NEWNS]
            .into_iter()
            .filter(|f| !policy.clone_flags.contains(f))
            .map(arg0_has_flag)
            .collect();
        if !clone_rules.is_empty() {
            m.insert(libc::SYS_clone, clone_rules);
        }
    }
    // ioctl is ubiquitous; deny only the terminal-injection requests the policy has not lifted.
    if !policy.whole.contains(&libc::SYS_ioctl) {
        let ioctl_rules: Vec<SeccompRule> = [TIOCSTI, TIOCLINUX]
            .into_iter()
            .filter(|r| !policy.ioctl_reqs.contains(r))
            .map(arg1_is)
            .collect();
        if !ioctl_rules.is_empty() {
            m.insert(libc::SYS_ioctl, ioctl_rules);
        }
    }
    m
}

/// The ENOSYS filter's rules for a given relaxation policy: `clone3` and the new mount API, minus
/// any the policy lifts wholesale. A default (empty) policy reproduces the full set.
fn enosys_rules(policy: &SeccompPolicy) -> Rules {
    let mut m = Rules::new();
    for (_, nr) in enosys_named() {
        if !policy.whole.contains(&nr) {
            m.insert(nr, vec![]);
        }
    }
    m
}

/// The bit an x32 system call carries in its number (`__X32_SYSCALL_BIT`).
///
/// x32 is a third ABI on x86_64: 32-bit pointers, 64-bit registers. What matters here is how it
/// presents itself to a filter. It reports `AUDIT_ARCH_X86_64`, so the architecture check the
/// compiled filter opens with **passes**, and it carries this bit in the call number, so every rule
/// below compares against a number it can never equal. A denylist whose default action is `Allow`
/// then allows the whole of it.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Refuse anything arriving through the x32 ABI, ahead of the compiled rules.
///
/// Three instructions, prepended rather than woven in: cBPF jumps are relative to the following
/// instruction, so a block placed entirely in front leaves every offset the compiler emitted
/// untouched. It loads the call number, and returns `ENOSYS` for any number carrying
/// [`X32_SYSCALL_BIT`] — the same answer this module already gives for a call it will not let
/// through but does not want to make fatal.
///
/// It is unconditional on purpose, and it cannot be demonstrated on a host whose kernel is built
/// without `CONFIG_X86_X32_ABI` — which is most of them, and is exactly why it is written from the
/// ABI's specification rather than from a reproduction. A guard that only defends the hosts a
/// developer happened to have is not a guard.
#[cfg(target_arch = "x86_64")]
fn refuse_x32(program: &mut BpfProgram) {
    const LD_W_ABS: u16 = 0x20;
    const JMP_JGE_K: u16 = 0x35;
    const RET_K: u16 = 0x06;
    const RET_ERRNO: u32 = 0x0005_0000;
    program.splice(
        0..0,
        [
            // A <- seccomp_data.nr
            sock_filter {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            // if A >= __X32_SYSCALL_BIT: fall through to the refusal; else skip it
            sock_filter {
                code: JMP_JGE_K,
                jt: 0,
                jf: 1,
                k: X32_SYSCALL_BIT,
            },
            sock_filter {
                code: RET_K,
                jt: 0,
                jf: 0,
                k: RET_ERRNO | (libc::ENOSYS as u32),
            },
        ],
    );
}

/// No such ABI here: aarch64 has one system-call convention, and the architecture check the
/// compiled filter opens with is the whole of the answer.
#[cfg(not(target_arch = "x86_64"))]
fn refuse_x32(_program: &mut BpfProgram) {}

/// Compile a rule set with the given match action into raw cBPF bytes.
fn compile(rules: Rules, match_action: SeccompAction) -> Vec<u8> {
    let filter = SeccompFilter::new(rules, SeccompAction::Allow, match_action, TARGET_ARCH)
        .expect("a statically-defined filter is always valid");
    let mut program: BpfProgram = filter.try_into().expect("the filter compiles to cBPF");
    // Every program, not one of them: each is installed on its own and each defaults to `Allow`, so
    // a bypass left open in any of them is a bypass.
    refuse_x32(&mut program);
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

/// The compiled filters in load order for a given relaxation policy: the EPERM denylist, then the
/// ENOSYS denylist. Pure. A filter whose rule set the policy has fully emptied is **omitted**, an
/// empty denylist being a no-op — so the result has two entries for the default (mandatory) policy
/// and fewer only if a trusted config lifts an entire filter's worth of syscalls.
///
/// **Never none, though.** A denylist is not all a compiled filter carries: each one opens with the
/// x32 refusal [`refuse_x32`] prepends and the architecture check seccompiler emits ahead of the
/// rules, and *that* pair is not a denylist entry a config can lift — it is what keeps a foreign
/// ABI from presenting call numbers this cage's supervision was never written against. A policy
/// that lifts every denied syscall would, with no filter left to carry it, hand the cage an
/// `int 0x80` `execve` that the proc-shim's notification filter — native numbers, no `arch` load —
/// never matches, so the exec would run unsupervised. So a policy that empties both rule sets still
/// gets one filter: no rules, and the guard alone.
///
/// An empty rule set compiles: seccompiler's `validate` rejects only identical match and mismatch
/// actions, and its code generator short-circuits an empty rule map to the architecture check plus
/// the default action.
fn programs(policy: &SeccompPolicy) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(2);
    let eperm = eperm_rules(policy);
    if !eperm.is_empty() {
        out.push(compile(eperm, SeccompAction::Errno(libc::EPERM as u32)));
    }
    let enosys = enosys_rules(policy);
    if !enosys.is_empty() {
        out.push(compile(enosys, SeccompAction::Errno(libc::ENOSYS as u32)));
    }
    if out.is_empty() {
        out.push(compile(
            Rules::new(),
            SeccompAction::Errno(libc::ENOSYS as u32),
        ));
    }
    out
}

/// Write each compiled filter into an anonymous in-memory file, ready to hand to
/// `bwrap --add-seccomp-fd`. The descriptors are deliberately **not**
/// close-on-exec so bwrap inherits them across the launch; the caller must keep
/// the returned files alive until bwrap has read them. (No `memfd` seal is applied
/// or needed — the file is written, rewound, and read once by bwrap.)
pub(crate) fn memfds(policy: &SeccompPolicy) -> io::Result<Vec<File>> {
    programs(policy).into_iter().map(write_to_memfd).collect()
}

fn write_to_memfd(bytes: Vec<u8>) -> io::Result<File> {
    super::memfd::write(c"sbx-seccomp", &bytes)
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

/// The compiled denylist filters (serialized cBPF) for `policy`, in load order — the
/// same bytes [`memfds`] hands to bwrap, exposed for direct in-process installation
/// by [`install_filters`]. `sbx session attach` needs this because, entering an existing
/// cage's namespaces, there is no bwrap to load the filters for it.
pub(crate) fn filter_bytes(policy: &SeccompPolicy) -> Vec<Vec<u8>> {
    programs(policy)
}

/// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, …)` — the classic filter install
/// (`SECCOMP_MODE_STRICT` is 1, `SECCOMP_MODE_FILTER` is 2).
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

/// Install each compiled filter on the *calling thread* via `prctl`, stacking them
/// exactly as bwrap's two `--add-seccomp-fd` do (a non-matching filter yields
/// *allow*, an `errno` action outranks it). Returns `false` on the first failure.
///
/// Async-signal-safe: called between `fork` and `exec` (in `sbx session attach`'s cage-entry
/// child), it only reads the prebuilt bytes and builds a `sock_fprog` on the stack —
/// no allocation. The caller MUST have set `PR_SET_NO_NEW_PRIVS` first, or an
/// unprivileged install is refused with `EACCES`.
pub(crate) fn install_filters(filters: &[Vec<u8>]) -> bool {
    for bytes in filters {
        // Each cBPF instruction serializes to 8 bytes (see `serialize`).
        let prog = libc::sock_fprog {
            len: (bytes.len() / 8) as libc::c_ushort,
            filter: bytes.as_ptr() as *mut libc::sock_filter,
        };
        // SAFETY: `prog` is a valid `sock_fprog` for the duration of the call, and
        // `PR_SET_SECCOMP` with `SECCOMP_MODE_FILTER` reads it to install the filter
        // on the current thread. No memory is retained past the call.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            )
        };
        if rc != 0 {
            return false;
        }
    }
    true
}

/// A resolved relaxation of the mandatory denylist: which denied syscalls (or argument-filtered
/// sub-rules) a trusted `[seccomp] allow` re-permits. The **default is empty** — the full
/// mandatory denylist, byte-identical to a cage with no `[seccomp]` config. Only a trusted config
/// (global or a trusted project) contributes to it; the layering is a **union** (a security field
/// that only ever subtracts from the denied set, like `forward` only ever adds ports).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SeccompPolicy {
    /// Denied syscalls (by number) lifted wholesale — a bare token like `ptrace`, or a bare
    /// `clone`/`ioctl` (which drops all of that syscall's argument-filtered rules).
    whole: BTreeSet<i64>,
    /// `clone` namespace flags lifted individually (a `clone:newns` token), effective only while
    /// `clone` is not lifted wholesale.
    clone_flags: BTreeSet<u64>,
    /// `ioctl` requests lifted individually (an `ioctl:tiocsti` token), effective only while
    /// `ioctl` is not lifted wholesale.
    ioctl_reqs: BTreeSet<u64>,
}

/// What one resolved `[seccomp] allow` token lifts, against the denylist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Allow {
    /// Lift a whole denied syscall (a bare name, including a bare `clone`/`ioctl`).
    Whole(i64),
    /// Lift one `clone` namespace flag (`clone:newns`/`clone:newuser`).
    CloneFlag(u64),
    /// Lift one `ioctl` request (`ioctl:tiocsti`/`ioctl:tioclinux`).
    IoctlReq(u64),
}

/// The escape surface a token reopens — surfaced by the resolver as a graduated warning so a
/// trusted operator sees exactly what they are opening. Tokens that only reduce defense-in-depth
/// (e.g. `ptrace`, `perf_event_open`) carry no caution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Caution {
    /// Reopens unprivileged user-namespace creation (bare `clone`, `clone:newuser`, `clone3`).
    Userns,
    /// Reopens injecting input into the controlling terminal (bare `ioctl`, `ioctl:tiocsti`,
    /// `ioctl:tioclinux`).
    TerminalInjection,
    /// Reopens tearing down a mount, which can defeat a control-plane pin sbx relies on (`umount2`).
    ControlPlane,
}

impl Caution {
    /// A short phrase naming what the token reopens, for the resolver's warning.
    pub(crate) fn reopens(self) -> &'static str {
        match self {
            Caution::Userns => "unprivileged user-namespace creation",
            Caution::TerminalInjection => "terminal input injection",
            Caution::ControlPlane => {
                "tearing down a mount (can defeat a control-plane pin when sbx's control plane is \
                 bound read-write, and every `[fs]` mask, which is a mount over a project path)"
            }
        }
    }
}

/// Resolve one `[seccomp] allow` token against the denylist. A bare syscall name lifts the whole
/// syscall; `clone`/`ioctl` additionally accept a `:selector` (`clone:newns`, `ioctl:tioclinux`)
/// that lifts only that sub-rule. Returns the lift plus any [`Caution`] the caller should surface.
/// `Err` names why the token is unusable (unknown syscall, bad or superfluous selector) so the
/// caller drops it with a warning — an unrecognized token must loosen nothing (fail-closed). The
/// token is trimmed here; comma-splitting a single string into several tokens is the caller's job.
pub(crate) fn resolve_allow(token: &str) -> Result<(Allow, Option<Caution>), String> {
    let token = token.trim();
    if token.is_empty() {
        return Err("empty entry".to_string());
    }
    if let Some((name, selector)) = token.split_once(':') {
        return match name {
            "clone" => match selector {
                "newuser" => Ok((Allow::CloneFlag(CLONE_NEWUSER), Some(Caution::Userns))),
                "newns" => Ok((Allow::CloneFlag(CLONE_NEWNS), None)),
                other => Err(format!(
                    "unknown clone flag `{other}` (expected `newuser` or `newns`)"
                )),
            },
            "ioctl" => match selector {
                "tiocsti" => Ok((Allow::IoctlReq(TIOCSTI), Some(Caution::TerminalInjection))),
                "tioclinux" => Ok((Allow::IoctlReq(TIOCLINUX), Some(Caution::TerminalInjection))),
                other => Err(format!(
                    "unknown ioctl request `{other}` (expected `tiocsti` or `tioclinux`)"
                )),
            },
            other => Err(format!(
                "`{other}` takes no `:selector` (only `clone` and `ioctl` are argument-filtered)"
            )),
        };
    }
    match token {
        // The two argument-filtered syscalls, lifted wholesale (every flag/request). The caution
        // names what the coarse form reopens; the `:selector` form above is the narrow alternative.
        "clone" => Ok((Allow::Whole(libc::SYS_clone), Some(Caution::Userns))),
        "ioctl" => Ok((
            Allow::Whole(libc::SYS_ioctl),
            Some(Caution::TerminalInjection),
        )),
        name => match denied_number(name) {
            Some(nr) => {
                let caution = match name {
                    "umount2" => Some(Caution::ControlPlane),
                    // clone3 cannot be argument-filtered (its flags live behind a struct pointer a
                    // cBPF cannot read), so lifting it reopens unfiltered namespace creation.
                    "clone3" => Some(Caution::Userns),
                    // `unshare(CLONE_NEWUSER)` creates a user namespace exactly as `clone` does,
                    // and there is no `:selector` form to narrow it to the harmless flags — so the
                    // bare token is the wholesale lift. It carried no caution while its two
                    // siblings did, which left the one spelling of this grant that says nothing.
                    "unshare" => Some(Caution::Userns),
                    _ => None,
                };
                Ok((Allow::Whole(nr), caution))
            }
            None => Err(format!("`{name}` is not in sbx's seccomp denylist")),
        },
    }
}

impl SeccompPolicy {
    /// Record one resolved allowance.
    pub(crate) fn allow(&mut self, a: Allow) {
        match a {
            Allow::Whole(nr) => {
                self.whole.insert(nr);
            }
            Allow::CloneFlag(f) => {
                self.clone_flags.insert(f);
            }
            Allow::IoctlReq(r) => {
                self.ioctl_reqs.insert(r);
            }
        }
    }

    /// Whether this policy relaxes nothing — the mandatory baseline. When true, [`programs`]
    /// yields exactly the two mandatory filters, identical to a cage with no `[seccomp]` config.
    pub(crate) fn is_empty(&self) -> bool {
        self.whole.is_empty() && self.clone_flags.is_empty() && self.ioctl_reqs.is_empty()
    }

    /// Union another policy's allowances into this one — the merge used for both the
    /// project-over-global baseline and an app overlay onto the baseline. Additive by nature
    /// (a lifted syscall stays lifted), so a trusted layer's relaxation survives an overlay.
    pub(crate) fn union(&mut self, other: &SeccompPolicy) {
        self.whole.extend(&other.whole);
        self.clone_flags.extend(&other.clone_flags);
        self.ioctl_reqs.extend(&other.ioctl_reqs);
    }

    /// The canonical, sorted token strings this policy allows — for `sbx config` display. Derived
    /// from the same name tables the parse used, so what is shown can never drift from what the
    /// cage enforces. A `clone`/`ioctl` lifted wholesale renders as the bare name; a lifted flag or
    /// request renders in its `:selector` form.
    pub(crate) fn tokens(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for nr in &self.whole {
            out.push(denied_name(*nr).unwrap_or("unknown").to_string());
        }
        for f in &self.clone_flags {
            if *f == CLONE_NEWUSER {
                out.push("clone:newuser".to_string());
            } else if *f == CLONE_NEWNS {
                out.push("clone:newns".to_string());
            }
        }
        for r in &self.ioctl_reqs {
            if *r == TIOCSTI {
                out.push("ioctl:tiocsti".to_string());
            } else if *r == TIOCLINUX {
                out.push("ioctl:tioclinux".to_string());
            }
        }
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One instruction, decoded from the serialized `struct sock_filter` bwrap reads.
    fn insn(bytes: &[u8], at: usize) -> (u16, u8, u8, u32) {
        let w = &bytes[at * 8..at * 8 + 8];
        (
            u16::from_ne_bytes([w[0], w[1]]),
            w[2],
            w[3],
            u32::from_ne_bytes([w[4], w[5], w[6], w[7]]),
        )
    }

    /// Where the architecture check sits in an emitted program: behind the three instructions
    /// [`refuse_x32`] prepends on x86_64, and first on an architecture that has no second ABI.
    #[cfg(target_arch = "x86_64")]
    const ARCH_CHECK_AT: usize = 3;
    #[cfg(not(target_arch = "x86_64"))]
    const ARCH_CHECK_AT: usize = 0;

    /// Every compiled filter opens by refusing the x32 ABI, and the architecture check it was
    /// already opening with still follows.
    ///
    /// Decoded from what [`programs`] actually emits — the bytes bwrap is handed — rather than by
    /// calling the guard and checking the guard. A filter that forgot to apply it would pass the
    /// second and fail this.
    ///
    /// It has to be read out of the instructions rather than exercised, because the ABI it defends
    /// against does not exist on a kernel built without `CONFIG_X86_X32_ABI` — most of them, this
    /// machine included. The constants are spelled out so they can be compared by eye against
    /// `seccomp(2)` instead of trusted through a name.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn every_filter_refuses_the_x32_abi_before_it_looks_at_anything_else() {
        let compiled = programs(&SeccompPolicy::default());
        assert_eq!(compiled.len(), 2, "the default policy emits both filters");
        for program in &compiled {
            // A <- seccomp_data.nr (a word at offset 0)
            assert_eq!(insn(program, 0), (0x20, 0, 0, 0));
            // if A >= 0x40000000 fall through to the return (jt = 0), else skip it (jf = 1)
            assert_eq!(insn(program, 1), (0x35, 0, 1, 0x4000_0000));
            // return ENOSYS: SECCOMP_RET_ERRNO (0x00050000) with the errno in the low bits
            assert_eq!(insn(program, 2), (0x06, 0, 0, 0x0005_0000 | 38));
            assert_eq!(libc::ENOSYS, 38, "the errno the line above spells out");

            // ...and the compiler's own prologue is intact behind it: load the architecture, and
            // kill anything that is not the one this filter was built for.
            assert_eq!(insn(program, ARCH_CHECK_AT), (0x20, 0, 0, 4));
            assert_eq!(insn(program, ARCH_CHECK_AT + 1).0, 0x15);
            assert_eq!(insn(program, ARCH_CHECK_AT + 1).3, 0xc000_003e);
            assert_eq!(
                insn(program, ARCH_CHECK_AT + 2),
                (0x06, 0, 0, 0x8000_0000),
                "an architecture this filter does not know is killed, not allowed"
            );
        }
    }

    use std::io::Read;

    #[test]
    fn the_two_denylists_are_disjoint() {
        let eperm = eperm_rules(&SeccompPolicy::default());
        let enosys = enosys_rules(&SeccompPolicy::default());
        for nr in enosys.keys() {
            assert!(
                !eperm.contains_key(nr),
                "syscall {nr} is in both filters; their actions would compete"
            );
        }
    }

    #[test]
    fn the_eperm_set_covers_the_surface_and_the_mount_ns_family() {
        let m = eperm_rules(&SeccompPolicy::default());
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
        let m = enosys_rules(&SeccompPolicy::default());
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
        let eperm = eperm_rules(&SeccompPolicy::default());
        let enosys = enosys_rules(&SeccompPolicy::default());
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

    /// A `[seccomp] allow` that names every denied syscall empties both rule sets — and a filter
    /// carries more than its rules. The architecture check and the x32 refusal are not denylist
    /// entries a config can lift: they are what stops a second ABI from presenting call numbers
    /// this cage's supervision was never written against, and with no filter emitted at all an
    /// `int 0x80` `execve` would reach the proc-shim's notification filter, which compares native
    /// numbers and never matches it — an exec neither denied nor announced.
    ///
    /// The lift is built from the same name tables the filter denies from, so it cannot fall
    /// behind a syscall added to the denylist later; that both rule sets really are empty is
    /// asserted first, or the rest of this test would be about a policy that lifts nothing.
    #[test]
    fn a_policy_that_lifts_every_denied_syscall_still_carries_the_abi_guard() {
        let mut policy = SeccompPolicy::default();
        for (name, _) in eperm_unconditional_named()
            .into_iter()
            .chain(enosys_named())
        {
            let (allow, _) = resolve_allow(name).expect("a name the denylist itself spells");
            policy.allow(allow);
        }
        for name in ["clone", "ioctl"] {
            let (allow, _) = resolve_allow(name).expect("the argument-filtered pair, wholesale");
            policy.allow(allow);
        }
        assert!(
            eperm_rules(&policy).is_empty() && enosys_rules(&policy).is_empty(),
            "the lift must be total, or this test measures nothing"
        );

        let compiled = programs(&policy);
        assert_eq!(
            compiled.len(),
            1,
            "a fully lifted policy still ships the guard, and only the guard"
        );
        let program = &compiled[0];
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(insn(program, 0), (0x20, 0, 0, 0));
            assert_eq!(insn(program, 1), (0x35, 0, 1, 0x4000_0000));
            assert_eq!(insn(program, 2), (0x06, 0, 0, 0x0005_0000 | 38));
        }
        assert_eq!(insn(program, ARCH_CHECK_AT), (0x20, 0, 0, 4));
        assert_eq!(insn(program, ARCH_CHECK_AT + 1).0, 0x15);
        assert_eq!(
            insn(program, ARCH_CHECK_AT + 2),
            (0x06, 0, 0, 0x8000_0000),
            "a foreign ABI is killed here too, not allowed through an empty denylist"
        );
    }

    #[test]
    fn both_filters_compile_to_non_empty_programs() {
        let progs = programs(&SeccompPolicy::default());
        assert_eq!(
            progs.len(),
            2,
            "the default policy yields both mandatory filters"
        );
        for prog in &progs {
            assert!(!prog.is_empty() && prog.len() % 8 == 0);
        }
    }

    #[test]
    fn resolve_allow_parses_bare_names_selectors_and_rejects_unknowns() {
        // A bare unconditional name lifts the whole syscall, no caution.
        assert!(
            matches!(resolve_allow("ptrace"), Ok((Allow::Whole(nr), None)) if nr == libc::SYS_ptrace)
        );
        // A bare argument-filtered name lifts the whole syscall, with its caution.
        assert!(
            matches!(resolve_allow("clone"), Ok((Allow::Whole(nr), Some(Caution::Userns))) if nr == libc::SYS_clone)
        );
        assert!(matches!(
            resolve_allow("ioctl"),
            Ok((Allow::Whole(_), Some(Caution::TerminalInjection)))
        ));
        // The two syscalls with a specific, non-default caution.
        assert!(matches!(
            resolve_allow("umount2"),
            Ok((Allow::Whole(_), Some(Caution::ControlPlane)))
        ));
        assert!(matches!(
            resolve_allow("clone3"),
            Ok((Allow::Whole(_), Some(Caution::Userns)))
        ));
        // `unshare(CLONE_NEWUSER)` creates a user namespace as surely as `clone` does, and takes no
        // `:selector` to narrow it — so the bare token is the wholesale lift and must say so. It
        // was the one spelling of this grant that resolved silently.
        assert!(matches!(
            resolve_allow("unshare"),
            Ok((Allow::Whole(_), Some(Caution::Userns)))
        ));
        // Selectors lift only the named sub-rule; `newns` reopens nothing worth a caution,
        // `newuser` and the ioctl requests do.
        assert!(
            matches!(resolve_allow("clone:newns"), Ok((Allow::CloneFlag(f), None)) if f == CLONE_NEWNS)
        );
        assert!(matches!(
            resolve_allow("clone:newuser"),
            Ok((Allow::CloneFlag(_), Some(Caution::Userns)))
        ));
        assert!(
            matches!(resolve_allow("ioctl:tioclinux"), Ok((Allow::IoctlReq(r), Some(Caution::TerminalInjection))) if r == TIOCLINUX)
        );
        // Each token is trimmed (the caller splits a string on commas, this trims the pieces).
        assert!(resolve_allow("  ptrace  ").is_ok());
        // Unknown syscall, unknown selector, a `:selector` on a non-filtered syscall, and empty
        // all fail — a token that resolves nothing must loosen nothing.
        assert!(resolve_allow("read").is_err());
        assert!(resolve_allow("clone:newnet").is_err());
        assert!(resolve_allow("ptrace:foo").is_err());
        assert!(resolve_allow("").is_err());
    }

    #[test]
    fn a_default_policy_denies_the_whole_list_and_a_lift_is_surgical() {
        let default = SeccompPolicy::default();
        assert!(default.is_empty());
        assert!(eperm_rules(&default).contains_key(&libc::SYS_ptrace));

        // Lifting a whole syscall removes exactly it, nothing else.
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("ptrace").unwrap().0);
        let rules = eperm_rules(&p);
        assert!(
            !rules.contains_key(&libc::SYS_ptrace),
            "ptrace should be lifted"
        );
        assert!(
            rules.contains_key(&libc::SYS_keyctl),
            "an unrelated denial must stay"
        );

        // A clone flag lifts only that flag: the clone entry keeps the OTHER flag's rule (one rule
        // left, not two) — the fine grammar's whole point.
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("clone:newns").unwrap().0);
        assert_eq!(
            eperm_rules(&p).get(&libc::SYS_clone).map(Vec::len),
            Some(1),
            "clone:newns must leave clone(CLONE_NEWUSER) denied"
        );

        // Lifting BOTH clone flags drops the clone entry entirely (equivalent to bare `clone`).
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("clone:newns").unwrap().0);
        p.allow(resolve_allow("clone:newuser").unwrap().0);
        assert!(!eperm_rules(&p).contains_key(&libc::SYS_clone));

        // A BARE `clone`/`ioctl` lifts the WHOLE syscall through the `whole` branch — distinct from
        // lifting every sub-rule above (that path builds an empty rule vec; this one short-circuits
        // on `whole.contains`). Both drop the entry, but a bare token must exercise its own branch,
        // and must NOT disturb the *other* arg-filtered syscall's rules.
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("clone").unwrap().0);
        let rules = eperm_rules(&p);
        assert!(
            !rules.contains_key(&libc::SYS_clone),
            "bare `clone` must drop the whole clone entry"
        );
        assert_eq!(
            rules.get(&libc::SYS_ioctl).map(Vec::len),
            Some(2),
            "lifting `clone` must leave ioctl's two rules intact"
        );
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("ioctl").unwrap().0);
        let rules = eperm_rules(&p);
        assert!(
            !rules.contains_key(&libc::SYS_ioctl),
            "bare `ioctl` must drop the whole ioctl entry"
        );
        assert_eq!(
            rules.get(&libc::SYS_clone).map(Vec::len),
            Some(2),
            "lifting `ioctl` must leave clone's two rules intact"
        );

        // An ENOSYS lift removes it from the ENOSYS filter.
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("clone3").unwrap().0);
        assert!(!enosys_rules(&p).contains_key(&libc::SYS_clone3));
    }

    #[test]
    fn tokens_round_trip_the_policy_for_display() {
        let mut p = SeccompPolicy::default();
        for t in [
            "ptrace",
            "unshare",
            "clone:newns",
            "ioctl:tioclinux",
            "clone3",
        ] {
            p.allow(resolve_allow(t).unwrap().0);
        }
        assert_eq!(
            p.tokens(),
            vec![
                "clone3",
                "clone:newns",
                "ioctl:tioclinux",
                "ptrace",
                "unshare"
            ]
        );
        // A wholesale clone/ioctl renders as the bare name.
        let mut p = SeccompPolicy::default();
        p.allow(resolve_allow("clone").unwrap().0);
        p.allow(resolve_allow("ioctl").unwrap().0);
        assert_eq!(p.tokens(), vec!["clone", "ioctl"]);
    }

    #[test]
    fn union_is_additive() {
        let mut base = SeccompPolicy::default();
        base.allow(resolve_allow("ptrace").unwrap().0);
        let mut over = SeccompPolicy::default();
        over.allow(resolve_allow("clone:newns").unwrap().0);
        base.union(&over);
        assert_eq!(base.tokens(), vec!["clone:newns", "ptrace"]);
    }

    #[test]
    fn the_eperm_filter_actually_blocks_a_denied_syscall() {
        // The set-membership tests prove WHICH syscalls are listed; this proves the compiled filter
        // ENFORCES — a regression that flipped the match action to Allow or broke the codegen would
        // pass those yet fail here, without needing bwrap (so it runs in `cargo test --bins`). The
        // filter is built in the parent and installed in a forked child that runs ONLY
        // async-signal-safe calls (prctl + syscall + _exit), so there is no fork-in-threaded hazard
        // and no test-harness recursion.
        let prog = compile(
            eperm_rules(&SeccompPolicy::default()),
            SeccompAction::Errno(libc::EPERM as u32),
        );
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
            2 => skip_incapable!(
                "skipping seccomp enforcement: filter not installable (no CONFIG_SECCOMP?)"
            ),
            code => panic!("the EPERM filter did not enforce the denylist (probe exit {code})"),
        }
    }

    #[test]
    fn each_memfd_holds_its_compiled_filter() {
        let files = memfds(&SeccompPolicy::default()).expect("memfds");
        let expected = programs(&SeccompPolicy::default());
        assert_eq!(files.len(), 2);
        for (mut f, want) in files.into_iter().zip(expected) {
            let mut got = Vec::new();
            f.read_to_end(&mut got).expect("read memfd");
            assert_eq!(got, want, "memfd content must equal the compiled filter");
        }
    }

    #[test]
    fn argv_prefix_emits_one_add_flag_per_filter() {
        let files = memfds(&SeccompPolicy::default()).expect("memfds");
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

    /// The mount set + a `/usr/bin/python3 -c <probe>` spec for the real-cage seccomp tests: host
    /// `/usr` bound read-only so python runs, plus `/proc`/`/dev`/tmpfs on shared net. x86_64-only
    /// (the probes trigger raw syscalls by number).
    #[cfg(target_arch = "x86_64")]
    fn probe_spec(probe: &str) -> super::super::spec::SandboxSpec {
        use super::super::spec::{Mount, NetPolicy, SandboxSpec};
        use std::path::PathBuf;
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
        SandboxSpec::new(
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
        .expect("probe spec")
    }

    /// Run `probe` under `policy`'s compiled filters in a real cage, returning its stdout — or
    /// `None` to skip (no bwrap / no capability-bearing userns / no python3). A non-zero bwrap exit
    /// is a test failure (the probe must actually run), not a skip.
    #[cfg(target_arch = "x86_64")]
    fn run_probe(policy: &SeccompPolicy, probe: &str) -> Option<String> {
        use std::path::PathBuf;
        use std::process::Command;
        let bwrap = sandbox_prereq()?;
        if !PathBuf::from("/usr/bin/python3").exists() {
            skip_incapable!("skipping seccomp cage test: no /usr/bin/python3 for the probe");
            return None;
        }
        let spec = probe_spec(probe);
        let memfds = memfds(policy).expect("memfds");
        let mut argv = argv_prefix(&memfds);
        let (spec_argv, env) = super::super::argv::compose(&spec).expect("compose");
        argv.extend(spec_argv);
        let out = Command::new(&bwrap)
            .args(argv)
            .output()
            .expect("launch bwrap");
        // Both kinds of anonymous file stay alive until bwrap has read the inherited descriptors:
        // the compiled filters, and the cage's environment.
        drop((memfds, env));
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "probe did not run; stdout=\n{stdout}\nstderr=\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Some(stdout)
    }

    /// The `ioctl` request comparison must be the width the kernel uses, not the width of the
    /// register — and this proves it against the running kernel rather than against the emitted BPF.
    ///
    /// `ioctl` takes `cmd` as an `unsigned int`, so the top half of the register is dropped before
    /// the kernel acts on it. A `Qword` equality against `0x5412` therefore let
    /// `ioctl(fd, 0x1_0000_5412, …)` past the filter into a kernel that read it as `TIOCSTI` and
    /// injected into the terminal: EPERM for the plain spelling, ENOTTY (the tty layer answering, so
    /// the call had *arrived*) for the high-bit one. Every high bit is another spelling, so this is
    /// asserted on more than one of them.
    ///
    /// Installed in a forked child because a filter cannot be taken off a live process, and directly
    /// rather than through a cage so it runs on any host — no bwrap, no user namespaces.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_denied_ioctl_request_stays_denied_with_the_high_half_set() {
        // Answered through the exit status: EPERM is 1, and any other errno means the syscall
        // reached the kernel. 0 says every spelling was refused.
        const REFUSED_ALL: i32 = 0;
        let requests = [
            TIOCSTI,
            TIOCSTI | 0x1_0000_0000,
            TIOCSTI | 0xffff_ffff_0000_0000,
            TIOCLINUX | 0x1_0000_0000,
        ];
        // SAFETY: the child does no allocation between `fork` and `_exit` beyond the filter bytes it
        // was handed before forking, and the parent only waits for it.
        let filters = filter_bytes(&SeccompPolicy::default());
        let status = unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(90);
                }
                if !install_filters(&filters) {
                    libc::_exit(91);
                }
                for (i, req) in requests.iter().enumerate() {
                    *libc::__errno_location() = 0;
                    libc::syscall(libc::SYS_ioctl, 0i64, *req as i64, 0i64);
                    if *libc::__errno_location() != libc::EPERM {
                        libc::_exit(i as i32 + 1);
                    }
                }
                libc::_exit(REFUSED_ALL);
            }
            let mut status = 0;
            libc::waitpid(pid, &mut status, 0);
            libc::WEXITSTATUS(status)
        };
        assert_ne!(status, 90, "the child could not set no_new_privs");
        assert_ne!(status, 91, "the child could not install the denylist");
        assert_eq!(
            status,
            REFUSED_ALL,
            "ioctl request {:#x} was not refused with EPERM — it reached the kernel, which reads \
             `cmd` as 32 bits and would act on it as TIOCSTI/TIOCLINUX",
            requests[(status as usize).saturating_sub(1).min(requests.len() - 1)]
        );
    }

    /// End-to-end teeth: load the DEFAULT (mandatory) filters into a real cage and confirm the
    /// kernel enforces them — a denied core syscall returns EPERM, a bypass route (`clone3`) returns
    /// ENOSYS, the arg-filtered `clone(CLONE_NEWUSER)`/`ioctl(TIOCSTI)` are refused, and `fork` plus
    /// the `AF_UNIX` carve-out still work. x86_64-only (raw syscall numbers).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_real_cage_enforces_the_denylist() {
        // keyctl=250, clone3=435, unshare=272, clone=56, ioctl=16. `clone(CLONE_NEWUSER|SIGCHLD)`
        // and `ioctl(TIOCSTI)` exercise the *argument-filtered* rules; the EPERM action fires
        // before the syscall runs, so the clone probe spawns no child, and `fork()` (clone without
        // namespace flags) must still succeed.
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

        let Some(stdout) = run_probe(&SeccompPolicy::default(), probe) else {
            return;
        };
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

    /// The guard-only filter is a program the kernel accepts, not just bytes that decode.
    ///
    /// A fully lifted policy emits one filter with no rules — three instructions of x32 refusal,
    /// three of architecture check, one `ALLOW` — and nothing short of a real launch proves bwrap
    /// loads it and the kernel takes it. The lift is read back through `clone3`: denied it answers
    /// `ENOSYS` (the filter's own action), lifted it reaches the kernel and answers `EFAULT` for
    /// the zero-sized argument struct the probe passes. That distinction is the kernel's own —
    /// `clone3` rejects a size below its first version before it ever reads the pointer — so it
    /// cannot be produced by a filter that quietly refused to load.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_fully_lifted_policy_loads_in_a_real_cage() {
        let probe = "import ctypes\n\
             l=ctypes.CDLL(None,use_errno=True)\n\
             def e(nr,*a):\n \
              ctypes.set_errno(0); l.syscall(nr,*[ctypes.c_long(x) for x in a]); return ctypes.get_errno()\n\
             print('clone3',e(435,0,0))\n";

        let mut policy = SeccompPolicy::default();
        for (name, _) in eperm_unconditional_named()
            .into_iter()
            .chain(enosys_named())
        {
            policy.allow(resolve_allow(name).unwrap().0);
        }
        for name in ["clone", "ioctl"] {
            policy.allow(resolve_allow(name).unwrap().0);
        }
        assert_eq!(programs(&policy).len(), 1, "one filter, the guard alone");

        let Some(stdout) = run_probe(&policy, probe) else {
            return;
        };
        assert!(
            stdout.contains("clone3 22"),
            "a lifted clone3 must reach the kernel and be refused on its zero-sized argument \
             (EINVAL), not answer the filter's own ENOSYS: {stdout}"
        );
    }

    /// End-to-end teeth for a **bare** `allow` token (`xxx` — the whole-syscall form): a trusted
    /// `allow = ["ptrace"]` lifts the entire syscall, so in a real kernel `ptrace(PTRACE_TRACEME)`
    /// returns 0 (it is EPERM while denied), while an unrelated denial (`keyctl`) stays EPERM — the
    /// lift is surgical. x86_64-only (raw syscall numbers).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_bare_seccomp_allow_lifts_a_whole_syscall_in_a_real_cage() {
        // ptrace=101 (PTRACE_TRACEME=0 → returns 0 on success), keyctl=250. `syscall` returns the
        // raw result; the probe prints the errno so the assertion tells a lift from a block.
        let probe = "import ctypes\n\
             l=ctypes.CDLL(None,use_errno=True)\n\
             def r(nr,*a):\n \
              ctypes.set_errno(0); rv=l.syscall(nr,*[ctypes.c_long(x) for x in a]); return (rv,ctypes.get_errno())\n\
             rv,er=r(101,0,0,0,0); print('ptrace_traceme',rv,er)\n\
             _,er=r(250,0,-3,0); print('keyctl',er)\n";

        let mut policy = SeccompPolicy::default();
        policy.allow(resolve_allow("ptrace").unwrap().0);
        let Some(stdout) = run_probe(&policy, probe) else {
            return;
        };
        // ptrace lifted wholesale → PTRACE_TRACEME succeeds (return 0, errno 0).
        assert!(
            stdout.contains("ptrace_traceme 0 0"),
            "ptrace not lifted (expected TRACEME to succeed): {stdout}"
        );
        // An unrelated denial stays: the lift is surgical, not a blanket relaxation.
        assert!(
            stdout.contains("keyctl 1"),
            "keyctl wrongly lifted — a bare `ptrace` must not touch it: {stdout}"
        );
    }

    /// End-to-end teeth for a **selector** `allow` token (`xxx:yyy` — the fine grammar): a trusted
    /// `allow = ["ioctl:tioclinux"]` lifts *only* that request, so in a real kernel
    /// `ioctl(TIOCLINUX)` reaches the kernel (errno **not** EPERM — EFAULT/ENOTTY) while
    /// `ioctl(TIOCSTI)` — the *other* request of the *same* syscall, not lifted — stays EPERM. This
    /// is the crux: the selector lifts one sub-rule, not the whole syscall. x86_64-only.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_seccomp_selector_lifts_only_the_named_sub_rule_in_a_real_cage() {
        // ioctl=16, TIOCLINUX=0x541C, TIOCSTI=0x5412. The probe prints each errno (0 on success).
        let probe = "import ctypes\n\
             l=ctypes.CDLL(None,use_errno=True)\n\
             def r(nr,*a):\n \
              ctypes.set_errno(0); l.syscall(nr,*[ctypes.c_long(x) for x in a]); return ctypes.get_errno()\n\
             print('ioctl_tioclinux',r(16,0,0x541C,0))\n\
             print('ioctl_tiocsti',r(16,0,0x5412,0))\n";

        let mut policy = SeccompPolicy::default();
        policy.allow(resolve_allow("ioctl:tioclinux").unwrap().0);
        let Some(stdout) = run_probe(&policy, probe) else {
            return;
        };
        // ioctl:tioclinux lifted → the request reaches the kernel, so its errno is NOT EPERM.
        assert!(
            stdout.contains("ioctl_tioclinux ") && !stdout.contains("ioctl_tioclinux 1"),
            "ioctl(TIOCLINUX) still blocked by seccomp — the selector did not lift it: {stdout}"
        );
        // ioctl:tiocsti NOT lifted → the OTHER request of the same syscall stays EPERM.
        assert!(
            stdout.contains("ioctl_tiocsti 1"),
            "ioctl(TIOCSTI) not EPERM — the selector lifted more than the named request: {stdout}"
        );
    }
}
