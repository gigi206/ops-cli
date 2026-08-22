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
//!   is surfaced with a one-time warning rather than hidden.
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
use std::os::unix::ffi::OsStrExt;
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
    /// lens without disturbing exec observation) only when the inotify instance itself cannot be created.
    pub(crate) fn start(root: &Path, ring: Arc<FsRing>) -> io::Result<FsWatcher> {
        // SAFETY: `inotify_init1` with valid flags returns a new fd or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut watcher = Watcher {
            fd,
            root: root.to_path_buf(),
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
}

impl Warned {
    fn new() -> Self {
        Warned {
            limit: AtomicBool::new(false),
            overflow: AtomicBool::new(false),
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

/// Install a watch on a directory, returning its watch descriptor. A path carrying an interior NUL
/// (impossible for a real path) fails closed.
fn add_watch(fd: libc::c_int, dir: &Path) -> io::Result<i32> {
    let c = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `fd` is our inotify instance and `c` a valid NUL-terminated path.
    let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), WATCH_MASK) };
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
    fd: libc::c_int,
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
    /// `false` so the pre-existing project is not replayed as writes. Symlinks are not followed (an entry's
    /// type is read without traversing it), so the watch set cannot loop or escape the project tree. On a
    /// watch-descriptor exhaustion the walk stops and warns once; the directories already watched keep
    /// working.
    fn add_tree(&mut self, start: &Path, emit: bool) {
        let mut stack = vec![start.to_path_buf()];
        while let Some(dir) = stack.pop() {
            match add_watch(self.fd, &dir) {
                Ok(wd) => {
                    self.wd_paths.insert(wd, dir.clone());
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                    self.warned.warn_limit_once();
                    return;
                }
                // The directory vanished between discovery and the watch, or is otherwise unwatchable:
                // skip it, keep watching the rest.
                Err(_) => continue,
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                if is_ignored_name(&name) {
                    continue;
                }
                let path = entry.path();
                // `file_type` does not traverse a symlink, so a symlink to a directory is not recursed
                // into — the watch set stays within the real project tree.
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
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
    /// promptly), drain and handle every pending event, and repeat until stopped. Closes the fd on exit
    /// (which removes all watches).
    fn event_loop(&mut self, stop: &AtomicBool) {
        let mut buf = vec![0u8; 16 * 1024];
        while !stop.load(Ordering::Relaxed) {
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd, waited up to 250 ms so the stop flag is re-checked promptly.
            let r = unsafe { libc::poll(&mut pfd, 1, 250) };
            if r <= 0 {
                continue; // timeout or EINTR — loop back and re-check the stop flag
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                break; // the inotify fd is unusable — end the loop
            }
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            // Drain every buffered event before polling again.
            loop {
                // SAFETY: read into our owned buffer; the fd is non-blocking, so an empty queue returns
                // EAGAIN (n < 0) and ends the drain.
                let n = unsafe {
                    libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n <= 0 {
                    break;
                }
                self.parse_buffer(&buf[..n as usize]);
            }
        }
        // SAFETY: closing our own inotify fd; removes every watch with it.
        unsafe { libc::close(self.fd) };
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
}
