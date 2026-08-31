//! The content lens: decide one notified open by the bytes behind it.
//!
//! Name the path, reach the inode the cage's own walk would reach, vouch for it against the
//! cage's mounts, scan it against the compiled `OpenPolicy`, and say what to report. The impure
//! counterpart of [`crate::open_policy`], which holds the matching itself.
//!
//! Everything here is per launch. The scan cache and the remembered mount sets hang off
//! [`OpenLens`], so two sessions never share a verdict formed against another's patterns.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::cagepath::{caller_proc_path, open_target_path, proc_self_behind_a_link};
use super::notify::{notif_of, respond_continue, respond_errno};
use super::open_serve::{Creation, serve_creation, serve_open};
use super::report::Undecidable;
use super::target::read_path_bytes;

/// What the supervisor could make of the path a notified open named.
///
/// The two failures are answered differently, which is why they are told apart. See [`open_name`].
pub(super) enum OpenName {
    /// A name this supervisor can carry, and so can resolve, scan and serve.
    Named(String),
    /// Nothing was read at all, so there is nothing to decide about. The lens allows these: it
    /// takes away what it can prove, and a cage whose undecidable opens all failed would not run.
    Unreadable,
    /// The path was read but is not a name this supervisor can carry (see
    /// [`super::target::read_exec_path`]), so it is refused rather than allowed — the one place the
    /// lens departs from "unreadable means allowed", because unlike a read that did not work this
    /// one is the cage's own choosing: a `rename` to a name with one non-UTF-8 byte costs it
    /// nothing and needs no read of the content, so allowing these would be a documented way around
    /// the scan rather than a hole in the supervisor's reach. Refusing is also what the cage
    /// already met — the substituted name resolved to nothing and the open was answered `ENOENT` —
    /// with the errno now saying which side refused it.
    Unusable,
}

/// The path an open asked for.
///
/// The read is where an unnameable open is counted, because it is the only step that knows it
/// happened: the decision downstream allows it, and this lens records the refusals it decided rather
/// than the decisions it could not take, so nothing afterwards would remember. Counted only where a
/// lens is armed — with none there was nothing to decide and nothing was given up, and a number on
/// those cages would be a number on a lens they never asked for.
pub(super) fn open_name(
    lens_armed: bool,
    undecidable: &Undecidable,
    pid: u32,
    path_addr: u64,
    notif: Option<(libc::c_int, u64)>,
) -> OpenName {
    match read_path_bytes(pid, path_addr, notif) {
        Some(bytes) if !bytes.is_empty() => match String::from_utf8(bytes) {
            Ok(named) => return OpenName::Named(named),
            Err(_) => {
                // Once: a cage that keeps naming them would otherwise fill the session's output
                // with the same line, and it is the same line every time.
                if !UNNAMEABLE_OPEN_SAID.swap(true, Ordering::Relaxed) {
                    crate::diag::warn(
                        "an open named a path that is not valid UTF-8, and the content lens \
                         resolves, scans and serves by name — so it was refused rather than \
                         decided under a name with the bytes replaced, which would be a different \
                         file",
                    );
                }
                return OpenName::Unusable;
            }
        },
        // An empty pathname names no file; it is answered like a read that produced nothing.
        Some(_) | None => {}
    }
    if lens_armed && undecidable.open.fetch_add(1, Ordering::Relaxed) == 0 {
        crate::diag::warn(
            "could not read the path an open asked for, so the content lens examined nothing and \
             the open was allowed. That read needs this supervisor to be the caller's ancestor; \
             where that does not hold, the lens examines nothing at all",
        );
    }
    OpenName::Unreadable
}

/// Set once an open has been refused for naming a path this supervisor cannot carry, so a cage that
/// keeps doing it pays one line for the session rather than one per open.
static UNNAMEABLE_OPEN_SAID: AtomicBool = AtomicBool::new(false);

/// Decide one notified open and answer it, from the syscall's own arguments.
///
/// The open half of the receive path, lifted out of [`super::handle_notif`] whole: it reads the
/// name, decides it against `lens`, and answers the notification — an errno for a refusal, the
/// supervisor's own descriptor for an allow, a `CONTINUE` for a call that cannot be served that
/// way. It is given the two pieces of the supervisor's state it uses rather than the whole of it,
/// which is what keeps the content lens from reaching back into the exec gate beside it.
pub(super) fn handle_open(
    notif_fd: libc::c_int,
    req: &libc::seccomp_notif,
    dirfd: libc::c_int,
    path_addr: u64,
    lens: Option<&OpenLens>,
    undecidable: &Undecidable,
) {
    let named = match open_name(
        lens.is_some(),
        undecidable,
        req.pid,
        path_addr,
        notif_of(notif_fd, req.id),
    ) {
        OpenName::Named(named) => named,
        // Nothing read: the empty name falls through to the allowing arm below, which is what
        // the lens does with an open it could not examine.
        OpenName::Unreadable => String::new(),
        // Read, and not a name this supervisor can act on. Answered here rather than allowed —
        // see [`OpenName::Unusable`].
        OpenName::Unusable => {
            respond_errno(notif_fd, req.id, libc::EACCES);
            return;
        }
    };
    // Twice at most, and the second pass only when the first found nothing there and the open
    // asked for the name to be created. Creating it is what makes the second pass meaningful:
    // the file exists by then, so the ordinary decision has something to examine.
    for pass in 0..2 {
        let outcome = match lens {
            // An unreadable path is allowed, like an unreadable exec target: the lens takes away
            // what it can prove, and a cage whose undecidable opens all failed would not run.
            Some(lens) if !named.is_empty() => open_is_refused(lens, req.pid, dirfd, &named),
            _ => OpenOutcome::ALLOWED,
        };
        if let Some(report) = &outcome.report {
            if report.partial {
                crate::diag::warn(&format!(
                    "`{}` is longer than the {} bytes the content scan reads, so it is open to the \
                 cage on the strength of its start alone — anything past that was not examined",
                    report.path,
                    policy_scan_ceiling(lens)
                ));
            } else {
                // Named rather than merely counted: a refusal a person cannot attribute to a pattern
                // is one they will turn the lens off to escape.
                let shapes = report.shapes.join("`, `");
                crate::diag::warn(&format!(
                    "closed `{}` to the cage: its content matches `{shapes}`",
                    report.path
                ));
            }
        }
        if outcome.refused {
            respond_errno(notif_fd, req.id, libc::EACCES);
        } else if let Some(errno) = outcome.errno {
            // A name that is not there is the answer to a plain open and not to a creating one, and
            // the probe that looked for it creates nothing. Rather than report the absence the
            // probe met, make what the open asked for.
            if pass == 0
                && errno == libc::ENOENT
                && let Some(lens) = lens
            {
                match serve_creation(notif_fd, req, lens, dirfd, &named) {
                    Creation::Served => return,
                    // The name is there after all — it appeared while this was being decided, so it
                    // carries content nothing has examined and belongs to the ordinary decision.
                    Creation::Exists => continue,
                    // Made and then unmade: nothing was handed over and the name is as the open
                    // found it, so the real syscall runs and creates it for itself. `CONTINUE`
                    // rather than the ordinary decision, which would answer `EEXIST` for the
                    // file this supervisor had just made and removed.
                    Creation::Unmade => {
                        respond_continue(notif_fd, req.id);
                        return;
                    }
                    Creation::Declined => {}
                }
            }
            respond_errno(notif_fd, req.id, errno);
        } else if !serve_open(notif_fd, req, dirfd, &named, outcome.probe) {
            // Nothing sound to serve it from, so the open runs the way it always did — and with it
            // the re-resolution a sibling thread can redirect. The cases that land here are named
            // where each is decided: a target whose type would make a reopen block, flags that
            // cannot be carried onto a descriptor, and a kernel without `ADDFD`.
            respond_continue(notif_fd, req.id);
        }
        return;
    }
}

/// One file's identity for the scan cache: the same bytes under a different name are the same
/// answer, and a rewrite changes at least one of these fields.
///
/// `mtime` alone would miss a write that lands inside the same timestamp granularity, so size and
/// inode ride along. This is a cache key, not a boundary: a rewrite that preserved all four would
/// serve a stale verdict, which is the same window a scan-at-open filesystem has and is why the lens
/// is a backstop rather than a proof.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub(super) struct FileId {
    pub(super) dev: u64,
    pub(super) ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl FileId {
    pub(super) fn of(meta: &std::fs::Metadata) -> FileId {
        use std::os::unix::fs::MetadataExt;
        FileId {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
        }
    }
}

/// How many distinct files the scan cache remembers within one launch.
///
/// A build reopens the same headers and sources over and over, which is what the cache exists for.
/// The ceiling bounds the supervisor's own memory; past it the map is cleared rather than evicted
/// one by one, because the cost of a miss is one bounded scan and the cost of tracking recency on
/// every open is paid whether or not it ever helps.
const SCAN_CACHE_MAX: usize = 8192;

/// The per-launch memory of what the content scan already decided.
#[derive(Default)]
struct ScanCache {
    seen: Mutex<BTreeMap<FileId, bool>>,
}

impl ScanCache {
    /// The remembered verdict for `id`, if this launch already scanned that exact content.
    fn get(&self, id: &FileId) -> Option<bool> {
        self.seen.lock().ok()?.get(id).copied()
    }

    /// Remember `refused` for `id`.
    fn put(&self, id: FileId, refused: bool) {
        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        if seen.len() >= SCAN_CACHE_MAX {
            seen.clear();
        }
        seen.insert(id, refused);
    }
}

/// How many mount namespaces a launch remembers the mount set of.
///
/// One is the common case: the cage's own. A cage that puts a descendant in a mount namespace of its
/// own adds one per namespace, and the ceiling bounds the supervisor's memory rather than naming a
/// limit anyone should meet.
const CAGE_MOUNTS_MAX: usize = 64;

/// The mounts a cage can see, remembered per mount namespace.
///
/// The set answers one question: did the supervisor's own path walk stay on the mounts the *cage*
/// has? A walk that left them reached its object through this process's root rather than the cage's,
/// and what it found cannot be handed over on the cage's behalf.
///
/// Keyed by the namespace rather than by the pid, because a cage may put a descendant in a mount
/// namespace of its own and that descendant's opens have to be judged against the mounts *it* sees.
///
/// Never refreshed. A set older than a mount the cage made since only sends that open down the
/// slower path, which resolves inside the cage's root and reaches the same answer — so staleness
/// costs time, never correctness, and a refresh on every miss would let a cage spend the
/// supervisor's time by opening paths that miss on purpose.
#[derive(Default)]
pub(super) struct CageMounts {
    seen: Mutex<BTreeMap<u64, BTreeSet<u64>>>,
}

impl CageMounts {
    /// The inode of `pid`'s mount namespace, which is what `/proc/<pid>/ns/mnt` names.
    pub(super) fn namespace_of(pid: u32) -> Option<u64> {
        let link = std::fs::read_link(format!("/proc/{pid}/ns/mnt")).ok()?;
        link.to_str()?
            .strip_prefix("mnt:[")?
            .strip_suffix(']')?
            .parse()
            .ok()
    }

    /// The mount ids `pid` can see, as its own `mountinfo` numbers them.
    fn read(pid: u32) -> Option<BTreeSet<u64>> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;
        let ids: BTreeSet<u64> = text
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter_map(|id| id.parse().ok())
            .collect();
        (!ids.is_empty()).then_some(ids)
    }

    /// Whether `id` names one of the mounts `pid` can see.
    ///
    /// `false` when the question cannot be answered at all — an unreadable `mountinfo`, a target
    /// already reaped — because an unknown mount must not be taken for a known one. The caller pays
    /// for that with a second resolution, which is the safe direction.
    pub(super) fn holds(&self, pid: u32, id: u64) -> bool {
        let Some(ns) = Self::namespace_of(pid) else {
            return false;
        };
        if let Ok(seen) = self.seen.lock()
            && let Some(ids) = seen.get(&ns)
        {
            return ids.contains(&id);
        }
        let Some(fresh) = Self::read(pid) else {
            return false;
        };
        let holds = fresh.contains(&id);
        if let Ok(mut seen) = self.seen.lock() {
            if seen.len() >= CAGE_MOUNTS_MAX {
                seen.clear();
            }
            seen.insert(ns, fresh);
        }
        holds
    }
}

/// The bit that asks `statx` for the mount number, and the one it sets when it answered.
const STATX_MNT_ID: libc::c_uint = 0x1000;

/// The kernel's `struct statx`, of which this module reads two fields.
///
/// Declared here rather than taken from `libc`, which carries the type for some targets and not for
/// the static one this ships as. The layout is the kernel's ABI, fixed by it: a field read at the
/// wrong offset would come back as whatever sits there, plausibly and in silence, so the size and
/// the offsets of the two fields read here are asserted rather than assumed.
#[repr(C)]
pub(super) struct Statx {
    pub(super) mask: u32,
    blksize: u32,
    attributes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    mode: u16,
    spare0: u16,
    ino: u64,
    size: u64,
    blocks: u64,
    attributes_mask: u64,
    /// Four `statx_timestamp`, sixteen bytes each, none of which this call asks for.
    times: [u64; 8],
    rdev_major: u32,
    rdev_minor: u32,
    dev_major: u32,
    dev_minor: u32,
    pub(super) mnt_id: u64,
    /// The remainder of the 256 bytes the kernel is free to write into.
    tail: [u64; 13],
}

/// The mount the object behind `fd` sits on, numbered the way `mountinfo` numbers mounts.
///
/// `None` is a refusal to answer rather than an answer: a kernel that does not carry the field
/// leaves the caller to resolve inside the cage's root instead of taking an unknown mount for one
/// the cage has.
pub(super) fn mount_id(fd: libc::c_int) -> Option<u64> {
    let mut buf: Statx = unsafe { std::mem::zeroed() };
    // SAFETY: buf is a live, correctly-sized statx buffer, and the empty path with `AT_EMPTY_PATH`
    // asks about the descriptor itself — the one question an `O_PATH` probe can answer.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_statx,
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_MNT_ID,
            std::ptr::addr_of_mut!(buf),
        )
    };
    (rc == 0 && buf.mask & STATX_MNT_ID != 0).then_some(buf.mnt_id)
}

/// Set once the kernel has refused `openat2`, so a host without it pays one failed syscall for the
/// whole session rather than one per open that has to be resolved again.
static OPENAT2_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

/// Reach `absolute` from **inside the cage's root**, the way the cage's own kernel would.
///
/// `RESOLVE_IN_ROOT` is what makes this faithful. A symlink whose target begins with `/` restarts
/// the resolution at the root of whoever is resolving, and a walk this process makes is resolved
/// against *its* root — so the target is taken relative to the cage's root instead. That is the
/// whole difference between reaching the cage's `/etc/hostname` and reaching ours, and it also means
/// the walk from here cannot leave the cage whatever it meets.
///
/// `absolute` is the path the supervisor's own walk ended on, which for the case that brings a
/// caller here — a symlink target beginning with `/` — is the path the cage's kernel resolves too.
/// The limit that leaves: an object the cage reaches under a *different* path than this process does
/// is not found, and the open is refused rather than served. That case needs both an absolute
/// symlink and a bind whose two sides sit at different paths; it fails closed, and the alternative
/// would be serving an object from a walk the cage did not make.
///
/// Returns the errno the cage's own open would have met, so the caller has an answer either way.
pub(super) fn probe_in_cage_root(pid: u32, absolute: &Path) -> Result<libc::c_int, libc::c_int> {
    if OPENAT2_UNAVAILABLE.load(Ordering::Relaxed) {
        return Err(libc::ENOSYS);
    }
    // `/proc/<pid>/fd/<n>` is rendered by the kernel against *this* process's root, so a target it
    // cannot name from there comes back marked rather than absolute — and a path that is not
    // absolute is not one this walk can start from.
    let Some(rest) = absolute.to_str().and_then(|p| p.strip_prefix('/')) else {
        return Err(libc::ENOENT);
    };
    // An empty remainder names the root itself, which `openat2` spells `.`.
    let rest = if rest.is_empty() { "." } else { rest };
    let (Ok(cstart), Ok(crest)) = (
        std::ffi::CString::new(format!("/proc/{pid}/root")),
        std::ffi::CString::new(rest),
    ) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: cstart is a live NUL-terminated path for the duration of the call.
    let start = unsafe { libc::open(cstart.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if start < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOENT));
    }
    // Zeroed and then filled: the struct is non-exhaustive, and a zero in a field this call does
    // not use is what the kernel reads as "unset" anyway.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT;
    // SAFETY: start is this call's live descriptor, crest a live NUL-terminated path, and how a
    // live correctly-sized `open_how` for the kernel to read.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            start,
            crest.as_ptr(),
            std::ptr::addr_of!(how),
            std::mem::size_of::<libc::open_how>(),
        )
    };
    let err = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOENT);
    // SAFETY: start is this call's owned descriptor, closed exactly once.
    unsafe { libc::close(start) };
    if fd >= 0 {
        return Ok(fd as libc::c_int);
    }
    if err == libc::ENOSYS && !OPENAT2_UNAVAILABLE.swap(true, Ordering::Relaxed) {
        // Said at all, because it is the difference between a guard that holds and one that only
        // looks like it does, and nothing else in a launch mentions it. Said once, from whichever
        // thread learns it first: a parked open answers from its own.
        //
        // This is not covered by a test: reproducing it needs a kernel that lacks the operation.
        crate::diag::warn(
            "this kernel does not offer `openat2` (it landed in 5.6), which is what lets the \
             supervisor resolve a path the way the cage would; under `[fs] scan` an open whose walk \
             leaves the cage's own mounts is refused rather than answered from a resolution this \
             process's root steered",
        );
    }
    Err(err)
}

/// The probe, once it is known to describe what the **cage's** own walk would have reached.
///
/// The supervisor resolves through `/proc/<pid>/root`, which puts the walk on the cage's mounts —
/// but only until it meets a symlink whose target begins with `/`. Such a target restarts the
/// resolution at the resolving process's root, and that is this one's: `/dev/stdout` is a link to
/// `/proc/self/fd/1`, where `self` names the supervisor. Measured, a cage that opens it receives the
/// supervisor's own descriptor, and a link the cage plants itself reaches the host's copy of any
/// file it names.
///
/// So the walk is checked rather than trusted. Either the probe landed on a mount the cage can see,
/// and the walk stayed inside; or it did not, and the path it landed on is reached again from inside
/// the cage's root, which is the resolution the cage's own kernel performs for such a target. The
/// second form is exact for a bind of the same file — the cage reaches that inode under that name —
/// so a secret named through an absolute link is still scanned and still refused, and a store path
/// named through one is still served.
pub(super) fn vouched_probe(
    lens: &OpenLens,
    pid: u32,
    probe: std::fs::File,
    own: bool,
) -> Result<std::fs::File, libc::c_int> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    if let Some(id) = mount_id(probe.as_raw_fd())
        && lens.mounts.holds(pid, id)
    {
        return Ok(probe);
    }
    let Ok(landed) = std::fs::read_link(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return Err(libc::ENOENT);
    };
    // A pipe, a socket or an anonymous inode sits on no mount any `mountinfo` lists, and the kernel
    // names it `pipe:[…]` rather than with a path — so no mount can ever vouch for one. Reached
    // through the caller's **own** `/proc` entry it needs none: what `/proc/self/fd` holds is what
    // the caller already holds, and handing a copy back grants nothing. Reached any other way it is
    // refused below, which is what keeps `/dev/stdout` from arriving as this process's descriptor.
    if own && landed.to_str().is_some_and(|named| !named.starts_with('/')) {
        return Ok(probe);
    }
    let fd = probe_in_cage_root(pid, &landed)?;
    // SAFETY: fd is a fresh owned descriptor; the File takes sole ownership and closes it.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// The scan ceiling of the lens in force, for a message that has to say how far it looked.
fn policy_scan_ceiling(open: Option<&OpenLens>) -> usize {
    open.map(|l| l.policy.max_scan()).unwrap_or(0)
}

/// The content lens a launch runs with: the compiled patterns, and what this launch already decided.
///
/// Held together because neither is useful alone — and because the cache is per launch, so two
/// sessions never share a verdict formed against another's patterns.
pub(super) struct OpenLens {
    policy: crate::open_policy::OpenPolicy,
    cache: ScanCache,
    /// The project root, on the host, outside which nothing is scanned.
    ///
    /// The lens exists for the credentials that sit in the tree an agent works in. Everything else a
    /// cage opens — the read-only store, `/usr/lib`, `/proc` — is content the user did not write and
    /// cannot leave a secret in, and it is also where the volume is: a build's opens are mostly
    /// there. Bounding the scan by the project is what keeps the cost proportional to the risk.
    ///
    /// The bound is applied to the path the **kernel resolved**, never to the one the cage wrote, so
    /// a symlink pointing out of the tree cannot smuggle a scan-worthy file past it — nor one
    /// pointing in be scanned twice under two names.
    root: PathBuf,
    /// The mounts each cage namespace can see, which is what tells a walk that stayed inside from
    /// one that left through an absolute symlink.
    mounts: CageMounts,
}

impl OpenLens {
    pub(super) fn new(policy: crate::open_policy::OpenPolicy, root: PathBuf) -> OpenLens {
        OpenLens {
            policy,
            cache: ScanCache::default(),
            root,
            mounts: CageMounts::default(),
        }
    }
}

/// Take the `O_PATH` probe for `target` and confirm it describes what the cage's own walk reaches.
///
/// Opened `O_PATH`, which never blocks whatever sits at the path. Opening for reading straight away
/// would hang on a FIFO with no writer — and this is the one thread every other open in the cage is
/// queued behind, so that hang would be the whole cage's.
///
/// Deliberately **without** `O_NOFOLLOW`: the kernel is about to follow the cage's symlinks, and a
/// scan that stopped at the link would be walked around with one `ln -s`.
///
/// The errno on failure is the one the cage's own open would have met. `O_PATH` is the most
/// permissive open there is, succeeding even without read permission, so a probe that fails
/// describes a path the cage was going to fail on too — which is what lets the answer be given
/// without a second walk, and closes the last way a `CONTINUE` could be reached by naming something
/// absent while the answer is formed and putting the secret behind it afterwards.
fn probe_and_vouch(
    lens: &OpenLens,
    pid: u32,
    target: &Path,
    own: bool,
) -> Result<std::fs::File, libc::c_int> {
    use std::os::unix::io::FromRawFd;
    let Ok(cpath) = std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) else {
        return Err(libc::EINVAL);
    };
    // SAFETY: cpath is a live NUL-terminated path for the duration of the call.
    let probe = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if probe < 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOENT));
    }
    // SAFETY: probe is a fresh owned descriptor; the File takes sole ownership and closes it.
    let probe = unsafe { std::fs::File::from_raw_fd(probe) };
    // Before a byte is read from it or it is handed over: is this what the *cage's* walk would have
    // reached? Asked before the type test below, because a device and a FIFO are served from the
    // probe without ever being scanned — and `/dev/stdout` is exactly such a device.
    vouched_probe(lens, pid, probe, own)
}

/// Decide one notified open: does the file it names carry a configured shape?
///
/// Returns `true` when the open must be refused. The supervisor reads the bytes **outside** the
/// cage, so the answer is formed before the cage holds a descriptor — and because the refusal is an
/// errno rather than an approval, it is not exposed to the re-pointing race that makes an *allow*
/// racy (module header).
///
/// Anything the supervisor cannot read — a path it cannot resolve, a directory, a device, a file it
/// has no permission on — is **allowed**. The lens closes what it can prove carries a secret; it is
/// not an allowlist, and a launch whose every unreadable open failed would not survive its first
/// `/proc` read.
pub(super) fn open_is_refused(
    lens: &OpenLens,
    pid: u32,
    dirfd: libc::c_int,
    path: &str,
) -> OpenOutcome {
    let (policy, cache) = (&lens.policy, &lens.cache);
    use std::io::Read;
    // A path that names the caller's own `/proc` entry is one whose object the caller already holds,
    // which is what lets an anonymous inode behind it be accepted where no mount could vouch for it.
    let own = caller_proc_path(pid, path).is_some();
    let probe = match probe_and_vouch(lens, pid, &open_target_path(pid, dirfd, path), own) {
        Ok(probe) => probe,
        // Nothing was reached, or what was reached is not what the cage's walk would have found.
        // Before answering with that, one more question: does the path arrive at the caller's own
        // `/proc` entry through a link? `/dev/stdout` is `/proc/self/fd/1`, and its neighbours are
        // the same shape — names that say nothing about `self`, so the rewriting that handles the
        // spelled-out form cannot see them, while the kernel following them resolves `self` against
        // this process. Asked only here, so an open that resolved normally pays nothing for it.
        Err(e) => {
            let Some(reached) = proc_self_behind_a_link(pid, dirfd, path) else {
                return OpenOutcome::failed(e);
            };
            match probe_and_vouch(lens, pid, &open_target_path(pid, dirfd, &reached), true) {
                Ok(probe) => probe,
                // The first answer, not the second: the link was a guess at what the path meant, and
                // a guess that led nowhere says nothing about the open.
                Err(_) => return OpenOutcome::failed(e),
            }
        }
    };
    use std::os::unix::io::AsRawFd;
    // What the kernel actually resolved, which is what the project bound is applied to.
    let Ok(resolved) = std::fs::read_link(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return OpenOutcome::ALLOWED;
    };
    let Ok(meta) = probe.metadata() else {
        return OpenOutcome::ALLOWED;
    };
    // A FIFO, a socket or a device carries no content this policy is written about, so none of them
    // is scanned. The descriptor still rides out: what serves such an open is decided in
    // `serve_open`, which knows the caller's flags and therefore knows whether reopening one could
    // block. Answering `CONTINUE` here instead would leave the widest door of all, since the cage
    // picks what it names first and a `mkfifo` in its own project costs it nothing.
    if !meta.is_file() && !meta.is_dir() {
        return OpenOutcome::allowed_from(probe);
    }
    // The type is settled before the project bound, because a file outside the tree is served from a
    // descriptor too. Nothing outside is *scanned* — that is what the bound is for — but a
    // `CONTINUE` there would re-resolve a path the cage can point back *into* the tree after the
    // fact, which would leave the whole lens walkable by naming `/etc/hostname` first.
    if !meta.is_file() || !resolved.starts_with(&lens.root) {
        return OpenOutcome::allowed_from(probe);
    }
    let id = FileId::of(&meta);
    if let Some(remembered) = cache.get(&id) {
        // Already decided this launch: the same answer without reopening, reading or naming — which
        // is the whole point of the cache, and why it is consulted before the read is set up. A
        // repeat refusal is silent on purpose: a build reopening one denied file would otherwise
        // fill the diagnostics with the same line.
        return OpenOutcome {
            refused: remembered,
            report: None,
            probe: (!remembered).then_some(probe),
            errno: None,
        };
    }
    // Re-opened for reading through the descriptor already resolved, so the bytes scanned belong to
    // the file just inspected rather than to whatever the path names a moment later.
    let Ok(mut file) = std::fs::File::open(format!("/proc/self/fd/{}", probe.as_raw_fd())) else {
        return OpenOutcome::ALLOWED;
    };
    // Bounded in *size*, not in time. `S_ISREG` is true of a file on a FUSE mount, an NFS path or
    // any other backing store that can stall, and this read is on the one thread every other open in
    // the cage is queued behind — the same failure shape the `O_PATH` probe closes for a FIFO, left
    // open here because bounding it needs a reader that can be abandoned rather than a ceiling.
    let mut buf = Vec::with_capacity(policy.max_scan().min(meta.len() as usize + 1));
    if file
        .by_ref()
        .take(policy.max_scan() as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return OpenOutcome::ALLOWED;
    }
    let verdict = policy.verdict(&buf);
    cache.put(id, verdict.matched);
    if !verdict.matched {
        // The dangerous truncation is *this* one. A file that matched is refused whatever was left
        // unread, but a file that came back clean only because the scan stopped is a false negative,
        // and staying silent about it would present a prefix as a whole-file result.
        return OpenOutcome {
            refused: false,
            report: verdict.scanned.is_partial().then(|| OpenReport {
                path: crate::sandbox::sanitize(path),
                shapes: Vec::new(),
                partial: true,
            }),
            probe: Some(probe),
            errno: None,
        };
    }
    // Naming the shapes costs a second walk, paid only here — on content already refused, once per
    // file per launch.
    let shapes: Vec<String> = policy
        .matched_names(&buf)
        .into_iter()
        .map(str::to_string)
        .collect();
    // A refusal needs no descriptor: it is answered with an errno, and the syscall never runs.
    OpenOutcome {
        refused: true,
        report: Some(OpenReport {
            path: crate::sandbox::sanitize(path),
            shapes,
            partial: false,
        }),
        probe: None,
        errno: None,
    }
}

/// What one notified open resolved to, and whether it is worth telling anyone.
pub(super) struct OpenOutcome {
    pub(super) refused: bool,
    /// Present only the first time this launch scanned the file, so one reopened in a loop is
    /// reported once.
    pub(super) report: Option<OpenReport>,
    /// The supervisor's own `O_PATH` descriptor for the inode it examined, when the open can be
    /// served from one.
    ///
    /// This is what closes the allow race. The verdict was formed against *this* inode; handing the
    /// cage a descriptor derived from it means the path it wrote is never resolved a second time,
    /// so there is no moment at which a sibling thread's rewrite could redirect the open. Absent
    /// when there is nothing to serve from: a refusal, which is answered with an errno of its own,
    /// or a probe that could not be taken at all.
    probe: Option<std::fs::File>,
    /// The errno the supervisor's own probe met, when it met one.
    ///
    /// Carried rather than discarded because it *is* the answer: a path the probe could not open is
    /// a path the cage could not have opened either, so replying with it settles the open without
    /// the kernel walking that path a second time.
    pub(super) errno: Option<libc::c_int>,
}

impl OpenOutcome {
    const ALLOWED: OpenOutcome = OpenOutcome {
        refused: false,
        report: None,
        probe: None,
        errno: None,
    };

    /// A refusal carrying the errno the cage is told.
    ///
    /// The rule is applied here rather than by the caller, because the caller is where it was
    /// missed: an errno that describes *this* process — out of descriptors, out of memory — is
    /// replaced by the supervisor's own `EACCES`. The refusal itself stands either way; a path that
    /// could not be examined is not one to serve, and answering `CONTINUE` instead would let a cage
    /// walk past the scan by putting the supervisor under descriptor pressure. What is corrected is
    /// only what the cage is told about *why*, which it would otherwise read as its own failure.
    pub(super) fn failed(errno: libc::c_int) -> OpenOutcome {
        OpenOutcome {
            refused: false,
            report: None,
            probe: None,
            errno: Some(if errno_describes_the_file(errno) {
                errno
            } else {
                libc::EACCES
            }),
        }
    }

    /// Allowed, and servable from the descriptor the supervisor already holds.
    fn allowed_from(probe: std::fs::File) -> OpenOutcome {
        OpenOutcome {
            refused: false,
            report: None,
            probe: Some(probe),
            errno: None,
        }
    }
}

/// What one file's first scan is worth saying: either the shapes that closed it, or that the answer
/// covers only a prefix.
pub(super) struct OpenReport {
    /// The name the cage asked for, **sanitised** on the way in — for the reason
    /// [`super::pending::PendingExec::park`] states about the registry beside it, and it was this
    /// producer's turn to be written apart. This string is read out of the cage's own memory, a
    /// Linux path may carry a newline or an escape sequence, and both report sites put it on a
    /// `diag::warn` line that reaches the operator's terminal and the session log `sbx logs` reads.
    /// A cage could otherwise paint whole lines of its own there — a refusal that never happened,
    /// or an escape run that hides the one that did. Sanitising is idempotent and the verdict was
    /// reached on the raw path above, so nothing but the rendering changes.
    pub(super) path: String,
    /// The patterns that matched. Empty when the report is about coverage rather than a refusal.
    shapes: Vec<String>,
    /// Whether the scan stopped before the end of the file, leaving the rest unexamined.
    partial: bool,
}

/// Whether an `errno` from an open describes the **file** or this **process**.
///
/// The distinction decides what may be reported to the cage. An errno about the file is one the cage
/// would have met itself, reopening the same inode on the same mounts under the same identity, so it
/// is the answer. An errno about the opener — this process out of descriptors, the machine out of
/// memory — says nothing about the cage: reporting it fails an open that had every right to succeed,
/// and tells the caller its own descriptors ran out when they did not.
///
/// One definition, because the two places that ask are written apart and only one of them used to
/// ask. The reopen that *serves* an open carried this list; the `O_PATH` probe that *examines* the
/// path did not, and passed whatever it got straight back — so a supervisor under descriptor
/// pressure answered `EMFILE` to a cage that had every descriptor it needed. A rule stated in one
/// site's comment is a rule the other site misses.
pub(super) fn errno_describes_the_file(e: libc::c_int) -> bool {
    matches!(
        e,
        libc::EROFS
            | libc::EACCES
            | libc::EPERM
            | libc::ENXIO
            | libc::ELOOP
            | libc::ENOTDIR
            | libc::EISDIR
            | libc::ENOENT
            | libc::ETXTBSY
    )
}
