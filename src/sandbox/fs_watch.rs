//! In-supervisor filesystem-write observer — the host-side half of filesystem observation.
//!
//! When observation is on, the launch is forced onto a supervised path (a parent that outlives the
//! cage), and this module watches the cage's **project tree** from there with inotify. The project is
//! bound into the cage read-write at its own host path, so a write the agent makes lands on the same
//! host inode the supervisor watches — the change is visible across the mount-namespace boundary with
//! no privilege and no cage cooperation. Each observed change is pushed into the fs ring, read
//! out-of-band by `sbx fs logs` over a per-session control socket.
//!
//! Scope and blind spots (documented, not silent):
//! - Only the **project tree** is watched. The per-project store (`/nix`) and the app home are
//!   host-backed too but are excluded as provisioning/state noise; `/tmp` is a cage-private tmpfs, so
//!   it is structurally invisible to the host and cannot be watched at all.
//! - Build/VCS/vendor trees (`.git`, `node_modules`, `target`, `.venv` — see [`IGNORED_COMPONENTS`])
//!   are filtered out: the filesystem analogue of the exec feed's process-plumbing filter, and what
//!   keeps a real project's synchronous initial walk fast.
//! - inotify reports a completed **write-and-close** (`IN_CLOSE_WRITE`), not each in-progress write, so
//!   a file still being written is shown only once it is closed.
//! - inotify is not recursive: a watch is added per directory, and for a directory created after start
//!   the watch is added on its `IN_CREATE`. A file created in that directory *before* the watch lands
//!   is caught by rescanning the new directory's contents (emitting synthetic creates); a race a plain
//!   `IN_CREATE`-then-`add_watch` would miss. A watch-descriptor exhaustion or a kernel queue overflow
//!   is surfaced with a one-time warning rather than hidden, and so is a directory that cannot be
//!   watched at all (inotify needs read access, which the directory's owner can take away).
//! - The filtered trees are an **exploitable blind spot**, not just noise: since the cage runs an
//!   untrusted agent, anything it writes under `./.git`, `./node_modules`, `./target`, or `./.venv`
//!   is not reported at all. This is a deliberate cost/coverage trade for v1 (those trees would flood
//!   the feed and slow the launch); a configurable ignore-set is the follow-on. It is not a boundary —
//!   the cage is — only an observation gap.
//! - A **directory renamed after start** keeps its pre-rename path in the watch map (move-cookie
//!   pairing is deferred), so a subsequent write under it reports the *old* path prefix until that
//!   directory is next re-walked. The event still fires; only its reported path can be stale.
//! - The watch is on the **project tree on disk**, not on the cage: it reports every writer to that
//!   tree, so if two sessions run on one project each also sees the other's writes. For the intended
//!   single-agent case this is exactly "what the agent wrote".

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use super::fs_control::{FsKind, FsRing};

/// Directory names whose churn is pure noise for "what did the agent write" and whose trees are large
/// enough to matter — the filesystem analogue of the exec feed's process-plumbing filter
/// (`bwrap`/`systemd-run`/`socat`). A directory with one of these names is neither watched nor
/// reported, which serves two ends at once: it keeps the feed to the source writes a user cares about,
/// and — because the initial watch install is synchronous and recursive — it keeps a real project's
/// launch fast by not walking a build/vendor tree with tens of thousands of directories.
///
/// - `.git` — a single `git commit`/`checkout` writes hundreds of internal objects/refs/locks, and
///   the exec feed already shows the `git` command itself.
/// - `node_modules`, `target`, `.venv` — dependency and build-output trees: huge, machine-managed, and
///   not the agent's authored work.
///
/// The trade is a real blind spot, named honestly: the agent is untrusted, so anything it writes under
/// one of these trees is not observed. That is acceptable for a cheap observe lens (the cage, not this
/// feed, is the boundary), and a surgical, configurable ignore set is the natural follow-on; this fixed
/// set covers the common heavy cases.
///
/// Reachable crate-wide so `docs_coverage` can assert the guide names every entry: a tree that stops
/// being watched without its page saying so turns a written blind spot back into a silent one.
pub(crate) const IGNORED_COMPONENTS: &[&str] = &[".git", "node_modules", "target", ".venv"];

/// The inotify event mask installed on every watched directory. `IN_ONLYDIR` makes an accidental
/// `add_watch` on a non-directory fail closed; `IN_EXCL_UNLINK` drops events for an already-unlinked
/// open file (noise). The reported changes are a completed write (`IN_CLOSE_WRITE`), a create/move-in
/// (`IN_CREATE`/`IN_MOVED_TO`), a delete (`IN_DELETE`), and a move-out (`IN_MOVED_FROM`); the `*_SELF`
/// masks let the watcher drop a directory that was itself removed.
///
/// There is no `IN_DONT_FOLLOW`: a watch is installed through `/proc/self/fd/<n>` ([`add_watch`]),
/// a link the kernel has to follow to reach the directory the descriptor holds. What keeps the watch
/// set inside the project is that descriptor, opened without following a link on any component
/// ([`Watcher::add_tree`]); the flag only ever covered the final one.
const WATCH_MASK: u32 = libc::IN_CLOSE_WRITE
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_DELETE_SELF
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR
    | libc::IN_EXCL_UNLINK;

/// A running filesystem-write observer. The thread drains inotify events and pushes each observed
/// change into the shared fs ring. It stops and is joined on drop (mirroring the exec observer), so it
/// never outlives the supervised wait.
pub(crate) struct FsWatcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl FsWatcher {
    /// Start watching the project tree rooted at `root`, pushing each observed change into `ring`.
    ///
    /// The inotify instance and the **initial** recursive set of watches are installed **synchronously**
    /// here, before the caller launches the cage: inotify only reports events under an already-installed
    /// watch, so a watch added later (from the background thread) would miss a write the cage makes in
    /// the gap. Only the event loop runs in the spawned thread. Fails (so the caller can degrade the fs
    /// lens without disturbing exec observation) when the inotify instance cannot be created, or when
    /// the root cannot be resolved: an observer with no root to watch would record nothing while
    /// reading as one that ran.
    ///
    /// The root is canonicalised here rather than assumed canonical: every directory below it is
    /// reached without following a link (see [`Watcher::add_tree`]), the root included, so a caller
    /// handing in a path whose last component is a link would otherwise get an observer that watches
    /// nothing at all. Reported paths are unaffected — each is stripped of this same prefix.
    pub(crate) fn start(root: &Path, ring: Arc<FsRing>) -> io::Result<FsWatcher> {
        // SAFETY: `inotify_init1` with valid flags returns a new fd or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor the call returned, owned here and closed once, on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut watcher = Watcher {
            fd,
            root: root.canonicalize()?,
            wd_paths: HashMap::new(),
            ring,
            warned: Warned::new(),
        };
        // Initial walk: add watches only, emit no events (the pre-existing project is not "written by
        // the agent"). A new directory *after* start rescans-and-emits to catch the create race.
        watcher.walk_root(false);

        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handle = std::thread::spawn(move || watcher.event_loop(&flag));
        Ok(FsWatcher {
            stop,
            handle: Some(handle),
        })
    }
}

impl Drop for FsWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// One-time warning latches: a hit watch-descriptor limit (a subtree left unwatched) and a kernel
/// event-queue overflow (events dropped before the watcher drained them). Each is surfaced exactly
/// once, so a persistent condition does not spam the terminal or the detached session log — but is
/// never hidden (silent truncation would read as "recorded everything").
struct Warned {
    limit: AtomicBool,
    overflow: AtomicBool,
    unwatched: AtomicBool,
}

impl Warned {
    fn new() -> Self {
        Warned {
            limit: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
            unwatched: AtomicBool::new(false),
        }
    }

    fn warn_limit_once(&self) {
        if !self.limit.swap(true, Ordering::Relaxed) {
            crate::diag::warn(
                "filesystem watch limit reached — part of the project tree is not being watched, so \
                 `sbx fs logs` may miss writes there (raise `fs.inotify.max_user_watches` to watch a \
                 larger tree)",
            );
        }
    }

    /// A directory left unwatched, or unlisted, for a reason other than the two the walk passes over
    /// in silence (see [`Watcher::add_tree`]): typically one whose owner took away the read access
    /// inotify needs, which the agent can do to a directory of its own and then write under it.
    fn warn_unwatched_once(&self, rel: &Path, e: &io::Error) {
        if !self.unwatched.swap(true, Ordering::Relaxed) {
            crate::diag::warn(&format!(
                "a directory of the project tree could not be watched (`{}`: {e}) — `sbx fs logs` \
                 misses writes under it, and under any other directory this warning is not repeated \
                 for",
                crate::diag::visible(&rel.to_string_lossy())
            ));
        }
    }

    fn warn_overflow_once(&self) {
        if !self.overflow.swap(true, Ordering::Relaxed) {
            crate::diag::warn(
                "filesystem event queue overflowed — some writes were not recorded by `sbx fs logs` \
                 (the agent wrote faster than the observer could drain)",
            );
        }
    }
}

/// Whether a single path component names an ignored directory (e.g. `.git`).
fn is_ignored_name(name: &OsStr) -> bool {
    IGNORED_COMPONENTS.iter().any(|i| name == OsStr::new(i))
}

/// Whether a project-relative path lies under (or is) an ignored directory, so it is neither watched
/// nor reported.
fn is_ignored_path(rel: &Path) -> bool {
    rel.components().any(|c| match c {
        Component::Normal(n) => is_ignored_name(n),
        _ => false,
    })
}

/// The path through which the kernel reaches the very file `fd` holds, whatever is now at the path
/// it was opened by.
fn through(fd: BorrowedFd<'_>) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Install a watch on the directory `dir` holds, returning its watch descriptor.
///
/// It takes a descriptor rather than a path because `inotify_add_watch` takes only a path, which the
/// kernel resolves again at the call: a path checked a moment earlier can by then lead elsewhere
/// through any of its components. The descriptor's own `/proc/self/fd` link leads to the directory
/// it was opened on, and nowhere else.
fn add_watch(inotify: BorrowedFd<'_>, dir: BorrowedFd<'_>) -> io::Result<i32> {
    let c = CString::new(through(dir).into_os_string().into_vec())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `inotify` is a live inotify instance and `c` a valid NUL-terminated path.
    let wd = unsafe { libc::inotify_add_watch(inotify.as_raw_fd(), c.as_ptr(), WATCH_MASK) };
    if wd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(wd)
    }
}

/// The inotify watch set for one project tree: the fd, the root every event is reported relative to,
/// the watch-descriptor map the kernel's ids resolve through, the ring events land in, and the
/// one-time warning latches.
///
/// The five travel together through every step of a watch — adding a subtree, resolving one event,
/// walking a read buffer, running the loop — because they are one thing. Naming it is what retires
/// the `#[allow(clippy::too_many_arguments)]` the event handler used to need, and all five already
/// moved into the watch thread together.
struct Watcher {
    fd: OwnedFd,
    root: PathBuf,
    wd_paths: HashMap<i32, PathBuf>,
    ring: Arc<FsRing>,
    warned: Warned,
}

impl Watcher {
    /// Walk the root itself, at start-up. Separate from [`Watcher::add_tree`] because
    /// `self.add_tree(&self.root, ..)` would borrow `self` two ways; this clones the root once.
    fn walk_root(&mut self, emit: bool) {
        let start = self.root.clone();
        self.add_tree(&start, emit);
    }

    /// Add watches over the subtree rooted at `start`, recording each in `wd_paths`. Iterative (an explicit
    /// stack, so a deep tree cannot overflow the thread stack). With `emit`, a synthetic `create` event is
    /// pushed for every entry found — used when a directory appears *after* start, so a file created in it
    /// before its watch was installed is still reported (the inotify create race); the initial walk passes
    /// `false` so the pre-existing project is not replayed as writes. On a watch-descriptor exhaustion the
    /// walk stops and warns once; the directories already watched keep working.
    ///
    /// A symlink is never traversed. Each directory is held by a descriptor opened one component at a
    /// time from the root with every link refused ([`super::cagedir::hold_beneath`]), and the watch
    /// and the listing both go through that descriptor. The cage owns the project tree, so between
    /// the event that named a directory and this walk it can turn the directory, or any directory
    /// above it, into a link to anywhere on the host; the path would then be resolved through it,
    /// pulling the watch set out of the project, spending the host-wide
    /// `fs.inotify.max_user_watches` budget on the cage's behalf, and reporting host paths under a
    /// project-relative name. A directory the walk refuses is skipped without being enumerated.
    ///
    /// Two failures are passed over in silence: a directory that is gone (`NotFound`, the ordinary
    /// race with a removal) and one that is a link or not a directory (`InvalidData`, the refusal
    /// the walk returns for either), whose appearance the parent's watch has already reported and
    /// below which there is nothing of the project. Anything else leaves a part of the tree
    /// unobserved, and is warned about once.
    fn add_tree(&mut self, start: &Path, emit: bool) {
        let mut stack = vec![start.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rel) = dir.strip_prefix(&self.root) else {
                continue;
            };
            let silent = |e: &io::Error| {
                matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::InvalidData
                )
            };
            let held = match super::cagedir::hold_beneath(&self.root, rel) {
                Ok(held) => held,
                Err(e) if silent(&e) => continue,
                Err(e) => {
                    self.warned.warn_unwatched_once(rel, &e);
                    continue;
                }
            };
            match add_watch(self.fd.as_fd(), held.as_fd()) {
                Ok(wd) => {
                    self.wd_paths.insert(wd, dir.clone());
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                    self.warned.warn_limit_once();
                    return;
                }
                Err(e) if silent(&e) => continue,
                Err(e) => {
                    self.warned.warn_unwatched_once(rel, &e);
                    continue;
                }
            }
            // Listed through the descriptor too, which stays open for the loop: an entry whose type
            // `d_type` leaves unknown is looked at under that same path.
            let entries = match std::fs::read_dir(through(held.as_fd())) {
                Ok(entries) => entries,
                Err(e) if silent(&e) => continue,
                Err(e) => {
                    self.warned.warn_unwatched_once(rel, &e);
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        self.warned.warn_unwatched_once(rel, &e);
                        break;
                    }
                };
                let name = entry.file_name();
                if is_ignored_name(&name) {
                    continue;
                }
                let path = dir.join(&name);
                // `file_type` does not traverse a symlink, so a symlink to a directory is not recursed
                // into — the watch set stays within the real project tree.
                let is_dir = match entry.file_type() {
                    Ok(t) => t.is_dir(),
                    Err(e) => {
                        if !silent(&e) {
                            self.warned.warn_unwatched_once(&rel.join(&name), &e);
                        }
                        false
                    }
                };
                if emit && let Ok(rel) = path.strip_prefix(&self.root) {
                    push_rel(&self.ring, rel, FsKind::Create);
                }
                if is_dir {
                    stack.push(path);
                }
            }
        }
    }

    /// Handle one inotify event: update the watch map, add watches for a new directory (and rescan it for
    /// the create race), and push a reportable change into the ring. `wd_paths` maps a watch descriptor to
    /// the directory it watches, so the event's `name` (a leaf within that directory) resolves to a full
    /// path.
    fn handle_event(&mut self, wd: i32, mask: u32, name: &OsStr) {
        if mask & libc::IN_Q_OVERFLOW != 0 {
            self.warned.warn_overflow_once();
            return;
        }
        // The kernel removed this watch (its directory was deleted, moved, or unmounted): forget it.
        if mask & libc::IN_IGNORED != 0 {
            self.wd_paths.remove(&wd);
            return;
        }
        // A self-event on the watched directory: the parent directory's own `IN_DELETE`/`IN_MOVED_FROM`
        // already reports the removal, so nothing extra is emitted here.
        if mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0 {
            return;
        }
        let Some(dir) = self.wd_paths.get(&wd).cloned() else {
            return;
        };
        if name.is_empty() {
            return;
        }
        let full = dir.join(name);
        let Ok(rel) = full.strip_prefix(&self.root) else {
            return;
        };
        if is_ignored_path(rel) {
            return;
        }
        match classify(mask) {
            Class::New { is_dir: true } => {
                push_rel(&self.ring, rel, FsKind::Create);
                // A new directory: watch it, and rescan it so a file created between its birth and the
                // watch is still reported.
                self.add_tree(&full, true);
            }
            Class::New { is_dir: false } => push_rel(&self.ring, rel, FsKind::Create),
            Class::Write => push_rel(&self.ring, rel, FsKind::Write),
            Class::Remove => push_rel(&self.ring, rel, FsKind::Remove),
            Class::Rename => push_rel(&self.ring, rel, FsKind::Rename),
            Class::Ignore => {}
        }
    }

    /// Parse one read buffer of packed inotify events and handle each. The header is copied out with an
    /// unaligned read, so the buffer's alignment is irrelevant.
    fn parse_buffer(&mut self, buf: &[u8]) {
        let mut off = 0;
        while off + EVENT_HEADER <= buf.len() {
            // SAFETY: `off + EVENT_HEADER <= buf.len()`, and `read_unaligned` copies the header out
            // regardless of the buffer's alignment.
            let ev: libc::inotify_event = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(off) as *const libc::inotify_event)
            };
            let len = ev.len as usize;
            let name_off = off + EVENT_HEADER;
            if name_off + len > buf.len() {
                break; // truncated tail — should not happen with a correctly sized read
            }
            let name = OsStr::from_bytes(nul_trimmed(&buf[name_off..name_off + len]));
            self.handle_event(ev.wd, ev.mask, name);
            off = name_off + len;
        }
    }

    /// The background event loop: poll the inotify fd (with a short timeout so a stop is honoured
    /// promptly), drain and handle every pending event, and repeat until stopped. The fd closes with
    /// the watcher (which removes all watches), on a panic as on a return.
    ///
    /// A failure that ends the loop is warned about: the session goes on, and `sbx fs logs` would
    /// otherwise read as a record of everything written after it.
    fn event_loop(&mut self, stop: &AtomicBool) {
        let mut buf = vec![0u8; 16 * 1024];
        let stopped = 'watch: loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd, waited up to 250 ms so the stop flag is re-checked promptly.
            let r = unsafe { libc::poll(&mut pfd, 1, 250) };
            match after_poll(r, io::Error::last_os_error(), pfd.revents) {
                Polled::Again => continue,
                Polled::Stop(cause) => break cause,
                Polled::Drain => {}
            }
            // Drain every buffered event before polling again.
            loop {
                // SAFETY: read into our owned buffer; the fd is non-blocking, so an empty queue returns
                // EAGAIN and ends the drain.
                let n = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                match after_read(n, io::Error::last_os_error()) {
                    Read::Events(n) => self.parse_buffer(&buf[..n]),
                    Read::Again => {}
                    Read::Drained => break,
                    Read::Stop(cause) => break 'watch cause,
                }
            }
        };
        crate::diag::warn(&format!(
            "filesystem observation stopped ({stopped}) — `sbx fs logs` records no write made after \
             this"
        ));
    }
}

/// What the event loop does after a `poll`.
#[derive(Debug, PartialEq, Eq)]
enum Polled {
    /// Nothing to read, a timeout, or a signal: check the stop flag and poll again.
    Again,
    /// Events are waiting.
    Drain,
    /// The descriptor cannot be polled any more; the cause, for the warning.
    Stop(String),
}

/// Decide on a `poll` that returned `r`, with `err` the errno it left and `revents` what it reported
/// for the inotify descriptor. Pure, so each branch is tested without an instance.
fn after_poll(r: libc::c_int, err: io::Error, revents: libc::c_short) -> Polled {
    if r < 0 {
        return match err.kind() {
            io::ErrorKind::Interrupted => Polled::Again,
            _ => Polled::Stop(format!("polling the inotify descriptor failed: {err}")),
        };
    }
    if r == 0 {
        return Polled::Again;
    }
    if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Polled::Stop(format!(
            "the inotify descriptor became unusable (poll events {revents:#x})"
        ));
    }
    if revents & libc::POLLIN == 0 {
        return Polled::Again;
    }
    Polled::Drain
}

/// What the drain does after a `read`.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// That many bytes of events to handle.
    Events(usize),
    /// Interrupted by a signal: read again.
    Again,
    /// The queue is empty: poll again.
    Drained,
    /// The descriptor cannot be read any more; the cause, for the warning.
    Stop(String),
}

/// Decide on a `read` that returned `n`, with `err` the errno it left. inotify hands back whole
/// events or fails, so a zero-length read is a failure too. Pure, as [`after_poll`] is.
fn after_read(n: isize, err: io::Error) -> Read {
    match usize::try_from(n) {
        Ok(0) => Read::Stop("reading the inotify descriptor returned nothing".to_string()),
        Ok(n) => Read::Events(n),
        Err(_) => match err.kind() {
            io::ErrorKind::WouldBlock => Read::Drained,
            io::ErrorKind::Interrupted => Read::Again,
            _ => Read::Stop(format!("reading the inotify descriptor failed: {err}")),
        },
    }
}

/// How an inotify event mask classifies for reporting. Kept pure (a function of the mask alone) so it
/// is unit-tested without an inotify instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A path appeared (`IN_CREATE`/`IN_MOVED_TO`); `is_dir` decides whether it also needs a new watch.
    New {
        is_dir: bool,
    },
    Write,
    Remove,
    Rename,
    /// Nothing to report (an unrecognised mask).
    Ignore,
}

/// Classify a path-event mask. The queue-overflow, watch-removed, and directory-self masks are handled
/// by the caller (they carry side effects, not a reportable path), so this covers only the four
/// reportable changes.
fn classify(mask: u32) -> Class {
    let is_dir = mask & libc::IN_ISDIR != 0;
    if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
        Class::New { is_dir }
    } else if mask & libc::IN_CLOSE_WRITE != 0 {
        Class::Write
    } else if mask & libc::IN_DELETE != 0 {
        Class::Remove
    } else if mask & libc::IN_MOVED_FROM != 0 {
        Class::Rename
    } else {
        Class::Ignore
    }
}

/// Push one project-relative change into the ring, sanitised of control characters and length-capped
/// (a Linux filename may carry a newline, which would otherwise inject a second line on the control
/// wire — the same protection the exec feed applies to a command).
fn push_rel(ring: &FsRing, rel: &Path, kind: FsKind) {
    let s = super::observe_feed::sanitize(&rel.to_string_lossy());
    ring.push(kind, &s);
}

/// The size of the fixed inotify event header; the variable-length name follows it in the read buffer.
const EVENT_HEADER: usize = std::mem::size_of::<libc::inotify_event>();

/// The name bytes up to the first NUL: inotify NUL-pads the name field to align the next event.
fn nul_trimmed(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(i) => &bytes[..i],
        None => bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::super::fs_control::FsEvent;
    use super::*;
    use crate::testutil::TmpDir;
    use std::time::{Duration, Instant};

    #[test]
    fn classify_maps_each_reportable_mask() {
        assert_eq!(classify(libc::IN_CLOSE_WRITE), Class::Write);
        assert_eq!(classify(libc::IN_DELETE), Class::Remove);
        assert_eq!(classify(libc::IN_MOVED_FROM), Class::Rename);
        assert_eq!(classify(libc::IN_CREATE), Class::New { is_dir: false });
        assert_eq!(
            classify(libc::IN_CREATE | libc::IN_ISDIR),
            Class::New { is_dir: true }
        );
        assert_eq!(
            classify(libc::IN_MOVED_TO | libc::IN_ISDIR),
            Class::New { is_dir: true }
        );
        // An unrecognised mask reports nothing.
        assert_eq!(classify(libc::IN_ACCESS), Class::Ignore);
    }

    #[test]
    fn ignored_paths_are_recognised_at_any_depth() {
        assert!(is_ignored_name(OsStr::new(".git")));
        assert!(is_ignored_name(OsStr::new("node_modules")));
        assert!(is_ignored_name(OsStr::new("target")));
        assert!(is_ignored_name(OsStr::new(".venv")));
        assert!(!is_ignored_name(OsStr::new("src")));
        assert!(is_ignored_path(Path::new(".git/objects/ab/cd")));
        assert!(is_ignored_path(Path::new("sub/.git/HEAD")));
        assert!(is_ignored_path(Path::new("target/debug/build")));
        assert!(is_ignored_path(Path::new("app/node_modules/x/index.js")));
        assert!(!is_ignored_path(Path::new("src/main.rs")));
        // A file whose *name* merely contains an ignored word is not filtered — only a path component.
        assert!(!is_ignored_path(Path::new("src/target_list.rs")));
    }

    #[test]
    fn nul_trimmed_stops_at_the_first_nul() {
        assert_eq!(nul_trimmed(b"foo\0\0\0"), b"foo");
        assert_eq!(nul_trimmed(b"bar"), b"bar");
        assert_eq!(nul_trimmed(b"\0"), b"");
    }

    /// Poll the ring until it holds an event matching `pred`, or the deadline passes.
    fn wait_for(ring: &FsRing, deadline: Duration, pred: impl Fn(&FsEvent) -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if ring.snapshot(None).events.iter().any(&pred) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn a_write_in_the_watched_tree_reaches_the_ring() {
        let dir = TmpDir::new();
        let root = dir.path().canonicalize().unwrap();
        let ring = Arc::new(FsRing::new(100));
        let _watcher = FsWatcher::start(&root, ring.clone()).unwrap();

        // A write-and-close of a new file: reported as create (the file appeared) and/or write.
        std::fs::write(root.join("marker.txt"), b"hello").unwrap();
        assert!(
            wait_for(&ring, Duration::from_secs(3), |e| e.path == "marker.txt"),
            "the write to marker.txt was observed"
        );
    }

    #[test]
    fn a_git_write_is_filtered_but_a_nested_source_write_is_not() {
        let dir = TmpDir::new();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        let ring = Arc::new(FsRing::new(100));
        let _watcher = FsWatcher::start(&root, ring.clone()).unwrap();

        std::fs::write(root.join(".git").join("index"), b"x").unwrap();
        std::fs::write(root.join("src").join("lib.rs"), b"y").unwrap();

        // The source write is seen; the `.git` write never is.
        assert!(
            wait_for(&ring, Duration::from_secs(3), |e| e.path == "src/lib.rs"),
            "the source write was observed"
        );
        assert!(
            !ring
                .snapshot(None)
                .events
                .iter()
                .any(|e| e.path.starts_with(".git")),
            "no `.git` event is ever recorded"
        );
    }

    #[test]
    fn a_write_in_a_directory_created_after_start_is_observed() {
        // The recursion path: a directory born after start gets a watch (and a rescan), so a write
        // inside it is reported even though the directory did not exist when the initial walk ran.
        let dir = TmpDir::new();
        let root = dir.path().canonicalize().unwrap();
        let ring = Arc::new(FsRing::new(100));
        let _watcher = FsWatcher::start(&root, ring.clone()).unwrap();

        std::fs::create_dir(root.join("late")).unwrap();
        std::fs::write(root.join("late").join("f.txt"), b"z").unwrap();
        assert!(
            wait_for(&ring, Duration::from_secs(3), |e| e.path == "late/f.txt"),
            "a write under a directory created after start was observed"
        );
    }

    /// A watcher over `root` with no watch installed yet, for a test to drive `add_tree` by hand.
    fn bare_watcher(root: &Path, ring: &Arc<FsRing>) -> Watcher {
        // SAFETY: `inotify_init1` with valid flags returns a new fd or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        assert!(fd >= 0, "an inotify instance could be created");
        Watcher {
            // SAFETY: the descriptor just returned, owned here and closed once, on drop.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            root: root.to_path_buf(),
            wd_paths: HashMap::new(),
            ring: ring.clone(),
            warned: Warned::new(),
        }
    }

    /// The escape this pins: the watcher reaches a directory by its path up to a poll period after
    /// the kernel reported it, so the cage can swap that directory, or one above it, for a link in
    /// between. Neither the watch nor the listing may then follow the link: nothing is recorded,
    /// and nothing behind it is reported as a project-relative change.
    #[test]
    fn a_link_anywhere_on_a_directorys_path_is_neither_watched_nor_walked_through() {
        let project = TmpDir::new();
        let root = project.path().canonicalize().unwrap();
        let elsewhere = TmpDir::new();
        let outside = elsewhere.path().canonicalize().unwrap();
        std::fs::create_dir_all(outside.join("b").join("host-only")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("a")).unwrap();

        // The final component is the link, then a component above the directory named is.
        for start in [root.join("a"), root.join("a").join("b")] {
            let ring = Arc::new(FsRing::new(100));
            let mut watcher = bare_watcher(&root, &ring);
            watcher.add_tree(&start, true);
            assert!(
                watcher.wd_paths.is_empty(),
                "{}: no watch is recorded for a path that leaves the project tree",
                start.display()
            );
            assert!(
                ring.snapshot(None).events.is_empty(),
                "{}: nothing behind the link is reported",
                start.display()
            );
            assert!(
                !watcher.warned.unwatched.load(Ordering::Relaxed),
                "a link is passed over in silence: the parent's watch reported it"
            );
        }
    }

    /// A directory that appears after start is rescanned, and what was already in it is reported
    /// under its project-relative path.
    #[test]
    fn a_rescanned_directory_reports_what_it_already_held() {
        let project = TmpDir::new();
        let root = project.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("late").join("deeper")).unwrap();
        std::fs::write(root.join("late").join("f.txt"), b"z").unwrap();
        let ring = Arc::new(FsRing::new(100));
        let mut watcher = bare_watcher(&root, &ring);
        watcher.add_tree(&root.join("late"), true);

        let mut seen: Vec<String> = ring
            .snapshot(None)
            .events
            .iter()
            .map(|e| e.path.clone())
            .collect();
        seen.sort();
        assert_eq!(seen, ["late/deeper", "late/f.txt"]);
        let mut watched: Vec<&PathBuf> = watcher.wd_paths.values().collect();
        watched.sort();
        assert_eq!(
            watched,
            [&root.join("late"), &root.join("late").join("deeper")]
        );
    }

    /// inotify needs read access to a directory, which its owner can take away and still write in
    /// it: such a directory cannot be watched, and that is said rather than passed over.
    #[test]
    fn a_directory_that_cannot_be_watched_is_warned_about() {
        use std::os::unix::fs::PermissionsExt as _;
        // SAFETY: `geteuid` reads this process's credentials and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            skip_incapable!("running as root, which reads a directory whatever its mode");
            return;
        }
        let project = TmpDir::new();
        let root = project.path().canonicalize().unwrap();
        let locked = root.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o333)).unwrap();
        let ring = Arc::new(FsRing::new(100));
        let mut watcher = bare_watcher(&root, &ring);
        watcher.walk_root(false);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(watcher.wd_paths.values().any(|p| *p == root));
        assert!(!watcher.wd_paths.values().any(|p| *p == locked));
        assert!(
            watcher.warned.unwatched.load(Ordering::Relaxed),
            "the directory left unwatched is warned about"
        );
    }

    /// An observer with no root to watch is refused rather than started watching nothing.
    #[test]
    fn a_root_that_cannot_be_resolved_is_refused() {
        let project = TmpDir::new();
        let ring = Arc::new(FsRing::new(100));
        assert!(FsWatcher::start(&project.path().join("absent"), ring).is_err());
    }

    #[test]
    fn a_signal_retries_and_any_other_failure_stops_the_loop() {
        let errno = io::Error::from_raw_os_error;
        let quiet = || errno(0);
        assert_eq!(after_poll(-1, errno(libc::EINTR), 0), Polled::Again);
        assert!(matches!(
            after_poll(-1, errno(libc::ENOMEM), 0),
            Polled::Stop(_)
        ));
        assert_eq!(after_poll(0, quiet(), 0), Polled::Again);
        for bad in [libc::POLLERR, libc::POLLHUP, libc::POLLNVAL] {
            assert!(matches!(
                after_poll(1, quiet(), bad | libc::POLLIN),
                Polled::Stop(_)
            ));
        }
        assert_eq!(after_poll(1, quiet(), libc::POLLIN), Polled::Drain);
        assert_eq!(after_poll(1, quiet(), libc::POLLPRI), Polled::Again);

        assert_eq!(after_read(32, quiet()), Read::Events(32));
        assert_eq!(after_read(-1, errno(libc::EAGAIN)), Read::Drained);
        assert_eq!(after_read(-1, errno(libc::EINTR)), Read::Again);
        assert!(matches!(after_read(-1, errno(libc::EBADF)), Read::Stop(_)));
        assert!(matches!(after_read(0, quiet()), Read::Stop(_)));
    }
}
