//! Reading a parked target: its memory, under the open-then-validate ordering the module header
//! proves, and its syscall arguments, decoded per syscall number.
//!
//! Pure ABI knowledge — where each of the five notified calls keeps its dirfd, path pointer,
//! flags, mode and resolve word — with no opinion about what any of it means. A sixth notified
//! syscall is a change to this file and to nothing else.

use super::notify::notif_id_valid;

/// Open a target's memory, and confirm afterwards that it is still the target's.
///
/// The order is the point, and it is what `seccomp_unotify(2)` prescribes: open first, then re-check
/// the notification id. A pid is only free to be reused once its process is gone, and a notification
/// id stays valid only while its target is parked in the syscall — so an id still valid *after* the
/// open proves the target never left, which proves the number was never free, which proves this
/// descriptor is the target's memory and not a stranger's.
///
/// Checking before the open cannot give that: the two are separate steps, and a target killed in
/// between can have its number reissued under the read. Nothing catastrophic followed (the kernel
/// refuses every answer to a gone target's id, so a verdict formed on a stranger's memory reaches no
/// process) — but a refusal line naming another process's path is still a wrong record, and reading
/// an unrelated process's memory at all is worth not doing.
///
/// `notif` is `None` for a caller with no notification in hand — the unit tests, which read this
/// process's own memory.
pub(super) fn open_target_mem(
    pid: u32,
    notif: Option<(libc::c_int, u64)>,
) -> Option<std::fs::File> {
    let file = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    if let Some((notif_fd, id)) = notif
        && !notif_id_valid(notif_fd, id)
    {
        return None;
    }
    Some(file)
}

/// Read one `u64` from a target's memory. `openat2` passes its flags behind a pointer rather than in
/// a register, and that word has to be read the same careful way the path is.
pub(super) fn read_u64(pid: u32, addr: u64, notif: Option<(libc::c_int, u64)>) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = open_target_mem(pid, notif)?;
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf).ok()?;
    Some(u64::from_ne_bytes(buf))
}

/// The smallest `struct open_how` the kernel will accept from an `openat2` caller.
///
/// `openat2(dirfd, path, how, size)` refuses a `size` below this outright — `EINVAL`, before the
/// path is looked at — because the struct's first version is already three words long and there is
/// no shorter one to read. The three readers below therefore treat a short `size` as a call they
/// cannot establish anything about, rather than reading the words that *are* there: what they would
/// establish belongs to a syscall that never runs.
///
/// This is the ABI's own number and not a guess at it. `size_of::<libc::open_how>()` agrees today
/// and is asserted to, but the constant is the contract: a later kernel that grows the struct grows
/// the type with it, while the minimum the kernel accepts stays where it is.
pub(super) const OPEN_HOW_VER0: u64 = 24;

/// The flags a notified open was called with, by syscall number.
///
/// The three forms do not agree on where they keep them, exactly as they disagree on the path (see
/// [`open_args`]): `open(path, flags, …)` and `openat(dirfd, path, flags, …)` pass a register, while
/// `openat2(dirfd, path, how, size)` passes a pointer to a `struct open_how` whose first field is the
/// flag word. Reading the wrong register would serve a descriptor opened for something other than
/// what the cage asked for, so the mapping is explicit and unit-tested rather than inferred.
///
/// `None` means the flags could not be established, and a caller that cannot establish them must not
/// serve the open from a descriptor.
pub(super) fn open_flags(
    pid: u32,
    nr: libc::c_int,
    args: &[u64; 6],
    notif: Option<(libc::c_int, u64)>,
) -> Option<u64> {
    // `open` exists on x86_64 and not on aarch64, where the kernel offers only `openat`, so
    // naming it unconditionally does not compile there. The same guard [`open_args`] carries.
    #[cfg(target_arch = "x86_64")]
    if nr as libc::c_long == libc::SYS_open {
        return Some(args[1]);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(args[2]);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. Only the first word is
        // wanted, but a call whose `size` is short of the whole struct is one the kernel refuses
        // ([`OPEN_HOW_VER0`]) — so there are no flags to establish, whatever sits at that address.
        if args[3] < OPEN_HOW_VER0 {
            return None;
        }
        return read_u64(pid, args[2], notif);
    }
    None
}

/// The mode a creating open asks its file to land with, read from wherever its own ABI puts it.
///
/// The mirror of [`open_flags`], and needed for the same reason: a file made on the cage's behalf
/// has to arrive with the permissions the cage asked for rather than with a guess.
pub(super) fn open_mode(
    pid: u32,
    nr: libc::c_int,
    args: &[u64; 6],
    notif: Option<(libc::c_int, u64)>,
) -> Option<u64> {
    // `open` exists on x86_64 and not on aarch64, where the kernel offers only `openat`, so
    // naming it unconditionally does not compile there. The same guard [`open_args`] carries.
    #[cfg(target_arch = "x86_64")]
    if nr as libc::c_long == libc::SYS_open {
        return Some(args[2]);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(args[3]);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. The mode is the second
        // word — and, as for the flags, a `size` short of the whole struct describes a call the
        // kernel refuses before it reads any of it ([`OPEN_HOW_VER0`]).
        if args[3] < OPEN_HOW_VER0 {
            return None;
        }
        return read_u64(pid, args[2].wrapping_add(8), notif);
    }
    None
}

/// The `resolve` word of an `openat2`, which names path-walk restrictions the caller wants the
/// kernel to enforce (`RESOLVE_NO_SYMLINKS`, `RESOLVE_BENEATH`, `RESOLVE_IN_ROOT`,
/// `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV`). `Some(0)` for the two older forms, which have no
/// such word and therefore ask for no restriction.
///
/// The third word of `struct open_how`, and read for the same reason its siblings are: a caller
/// that asked for a stricter walk than the supervisor performed must not be handed the result of
/// the looser one.
///
/// `None` means it could not be established, which — like an unreadable flag word — is a call that
/// must not be served from a descriptor.
pub(super) fn open_resolve(
    pid: u32,
    nr: libc::c_int,
    args: &[u64; 6],
    notif: Option<(libc::c_int, u64)>,
) -> Option<u64> {
    // Split rather than joined by `||`, because only one half exists on every architecture: see
    // [`open_flags`]. Both mean the same thing here -- neither call carries a `resolve` word, so
    // the walk the supervisor performed is the walk the caller asked for.
    #[cfg(target_arch = "x86_64")]
    if nr as libc::c_long == libc::SYS_open {
        return Some(0);
    }
    if nr as libc::c_long == libc::SYS_openat {
        return Some(0);
    }
    if nr as libc::c_long == libc::SYS_openat2 {
        // `struct open_how { __u64 flags; __u64 mode; __u64 resolve; }`. A `size` short of the
        // third word was read here as a call asking for no restriction, on the reasoning that the
        // kernel reads a missing tail as zero. It does not: `copy_struct_from_user` zero-fills a
        // struct the *caller* is older than, but `openat2` refuses anything shorter than the first
        // version outright ([`OPEN_HOW_VER0`]). Answering `Some(0)` therefore served a descriptor
        // for a syscall that was never going to run, from a `resolve` word nobody had established.
        if args[3] < OPEN_HOW_VER0 {
            return None;
        }
        return read_u64(pid, args[2].wrapping_add(16), notif);
    }
    None
}

/// Read a NUL-terminated path from a parked target's memory at `addr`, as the bytes it is. The
/// notified *thread* is blocked in the `execve`, so the pointer is valid to read — but only that
/// thread is stopped: a sibling in the cage can rewrite the buffer between this read and the
/// `CONTINUE`, which is why allowing a named path is TOCTOU-racy while refusing one is not (module
/// header). Nothing here closes that window. Returns `None` on any read failure.
pub(super) fn read_path_bytes(
    pid: u32,
    addr: u64,
    notif: Option<(libc::c_int, u64)>,
) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = open_target_mem(pid, notif)?;
    // Seek and read a bounded window; a path is at most PATH_MAX.
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(addr)).ok()?;
    let mut buf = [0u8; 4096];
    let n = file.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(buf[..end].to_vec())
}

/// The same read, as a name this supervisor can carry — or `None` where it cannot.
///
/// `from_utf8` and not `from_utf8_lossy`, for the reason [`super::caller_chain`] gives about the program
/// that issued the call: a Linux path is bytes and every byte the encoding cannot carry becomes the
/// same replacement character, so what came back was a **different name** from the one the cage
/// wrote. That name was then matched against the policy, and — under the open lens — resolved,
/// scanned, served and created: measured, an `open` of a file whose name carries one non-UTF-8 byte
/// had the supervisor walk to a path that does not exist, and a *creating* one of the same shape
/// would have made a file under the substituted name and handed the cage its descriptor. A name
/// that cannot be carried is not a name, and joins the reads that did not work.
///
/// Carrying the bytes end to end would be better still — such a path would then be scanned like any
/// other rather than refused — but it is the whole resolution chain (`open_target_path`,
/// `caller_proc_path`, `splice_first_link`, `serve_creation`) plus the `String` keys
/// [`crate::proc_policy::ProcPolicy`] matches on, and this is the half that stops a wrong file
/// being acted on.
pub(super) fn read_exec_path(
    pid: u32,
    addr: u64,
    notif: Option<(libc::c_int, u64)>,
) -> Option<String> {
    String::from_utf8(read_path_bytes(pid, addr, notif)?).ok()
}

/// Where a notified open keeps its directory descriptor and its path pointer, by syscall number.
///
/// The three forms do not agree on argument order: `open(path, …)` has no descriptor at all and is
/// implicitly relative to the working directory, while `openat(dirfd, path, …)` and
/// `openat2(dirfd, path, …)` lead with one. Reading the path from the wrong register would scan an
/// unrelated address, so the mapping is explicit and unit-tested rather than inferred at the call
/// site.
///
/// `None` for any other syscall: the same receive loop also carries `execve`, which is decided
/// elsewhere.
pub(super) fn open_args(nr: libc::c_int, args: &[u64; 6]) -> Option<(libc::c_int, u64)> {
    #[cfg(target_arch = "x86_64")]
    if nr as libc::c_long == libc::SYS_open {
        return Some((libc::AT_FDCWD, args[0]));
    }
    if nr as libc::c_long == libc::SYS_openat || nr as libc::c_long == libc::SYS_openat2 {
        return Some((args[0] as libc::c_int, args[1]));
    }
    None
}

/// Where a notified exec keeps its directory descriptor and its path pointer, by syscall number —
/// the exec half of the mapping [`open_args`] states for the open family, and for the same reason.
///
/// The shim notifies on **both** exec forms (`proc-shim`'s filter names `execve` and `execveat`),
/// and they do not agree on argument order: `execve(path, argv, envp)` leads with the path, while
/// `execveat(dirfd, path, argv, envp, flags)` leads with a descriptor. Reading the path from the
/// wrong register does not merely scan an unrelated address here — it makes the target unnameable,
/// and an unnameable target is decided by [`crate::proc_policy::ProcPolicy::unmatched`], which
/// under the shipped `enforce` denylist is `Allow`. Every `execveat` therefore used to walk past a
/// `deny` rule that named it. The mapping is explicit and unit-tested rather than inferred at the
/// call site.
///
/// `None` for any other syscall: the receive loop answers such a notification fail-closed rather
/// than judging it as an exec against a register that means something else.
pub(super) fn exec_args(nr: libc::c_int, args: &[u64; 6]) -> Option<(libc::c_int, u64)> {
    if nr as libc::c_long == libc::SYS_execve {
        return Some((libc::AT_FDCWD, args[0]));
    }
    if nr as libc::c_long == libc::SYS_execveat {
        return Some((args[0] as libc::c_int, args[1]));
    }
    None
}
