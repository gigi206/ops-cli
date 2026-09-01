//! Per-host egress decision counters: how often each destination an agent reached was allowed,
//! denied by a rule, or stopped by a security guard. The proxy ([`super::proxy`]) records one
//! outcome per request into an [`EgressStats`]; a host-side `sbx net stats` aggregates the
//! per-session files back into a project view.
//!
//! Design notes:
//! - **One outcome per request.** A request is counted exactly once — `allow` when it egressed,
//!   `deny` when a rule (or an `ask` decision) refused it, `blocked` when a security guard fired
//!   (SSRF, an outbound-secret tripwire, a domain-fronting host mismatch). Protocol/transport
//!   failures (a malformed request, a DNS or upstream error) are not a policy verdict and are not
//!   counted, so the numbers mean "what the policy did", not "what the network did".
//! - **Flush per decision, not on exit.** A long-running agent session most often ends by being
//!   killed (`sbx session stop` sends SIGTERM→SIGKILL), and a Rust `Drop` does not run on a signal — so a
//!   flush-on-drop would silently persist nothing for exactly the sessions worth auditing. Each
//!   recorded decision rewrites the session file atomically, so the file is current as of the last
//!   completed request regardless of how the session dies.
//! - **Bounded in destinations.** That per-decision rewrite is only affordable because the file is
//!   small, and it is only small because the number of rows is capped ([`MAX_HOSTS`]). The key is
//!   the destination the caller in the cage chose, reached before any policy decision permits
//!   anything, so uncapped it is the caller who decides how much the host rewrites per request.
//!   Destinations past the cap are folded into one counter rather than dropped ([`Tally::overflow`]),
//!   so the totals stay true.
//! - **One file per session, aggregated at read.** Files are keyed by this process *incarnation*
//!   (`stats-<pid>-<start-ticks>`), so two sessions of the same project never contend on a write and
//!   a later process reusing the pid cannot clobber a prior session's still-wanted file; `sbx net
//!   stats` sums every session file whose embedded `project=` header matches the project the user
//!   stands in. The project key
//!   is the canonical path [`super::binds::project_identity`] derives, the same on the write and
//!   read sides, so a launch's record and a later read cannot drift apart.
//! - **Finished sessions are folded together.** One file per session is right while a session runs
//!   and wrong once it has ended: nothing ever reads a *single* session's counters — every consumer
//!   sums them — so keeping one file per session forever is an unbounded directory holding data
//!   that is only ever added up. [`compact`] folds the finished ones into a single file per
//!   project+app, which loses nothing and bounds the count. A running session's file is never
//!   touched, since it is still being written.

use crate::sandbox::locks::locked;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Which bucket a recorded request falls into — one per request (see the module note).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatKind {
    /// The request egressed (the policy permitted it and it was forwarded).
    Allow,
    /// A rule — or a live `ask` decision / timeout — refused it.
    Deny,
    /// A security guard stopped it: SSRF (a private/metadata address), an outbound-secret leak, or
    /// a domain-fronting host mismatch.
    Blocked,
}

/// The three counters for one destination host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub(crate) allow: u64,
    pub(crate) deny: u64,
    pub(crate) blocked: u64,
}

impl Counts {
    /// The total across the three buckets — the natural sort key for the listing (busiest first).
    pub(crate) fn total(&self) -> u64 {
        self.allow + self.deny + self.blocked
    }

    fn bump(&mut self, kind: StatKind) {
        match kind {
            StatKind::Allow => self.allow += 1,
            StatKind::Deny => self.deny += 1,
            StatKind::Blocked => self.blocked += 1,
        }
    }

    fn add(&mut self, other: &Counts) {
        self.allow += other.allow;
        self.deny += other.deny;
        self.blocked += other.blocked;
    }
}

/// The most destinations one set of counters keeps a row for.
///
/// The key is the destination host, which the caller in the cage chooses and which reaches this
/// counter **before** any policy decision permits anything — a refused request is counted, and a
/// refused `http://` request is one plaintext line on a socket with no TLS, no DNS and no upstream
/// behind it. Uncapped, that is an in-cage caller setting the pace at which the host allocates and
/// rewrites a file, outside the cage's own memory ceiling; every other accumulation this proxy
/// exposes to a caller is bounded the same way (the leaf cache, the capture and log rings, the
/// notification queue, the splice and connection counts, the held-body budget, the pool).
///
/// Far above any real workload, which reaches a handful of hosts: this is the pathological case's
/// bound, not a budget anyone should meet. What lands past it is folded rather than dropped, so the
/// totals stay true — see [`Tally::overflow`].
const MAX_HOSTS: usize = 256;

/// How often at most the session file is rewritten while requests keep arriving.
///
/// The file is rewritten whole on every decision, which is what keeps it current no matter how a
/// session dies. At an ordinary request rate that is a few writes a second and the interval never
/// binds. Under a flood it is the difference between the caller in the cage choosing how fast the
/// host writes to storage and the host choosing: a refused request costs the caller one line on a
/// socket and was costing the host a rewrite of every row it had ever recorded, measured at roughly
/// four kilobytes for every sixty bytes asked.
///
/// Short enough that a person reading `sbx net stats` beside a running session sees live numbers,
/// which is the property being traded against — see [`start_flusher`] for the other half of keeping
/// it.
const FLUSH_INTERVAL: Duration = Duration::from_millis(200);

/// A set of egress counters: a row per destination, plus everything folded past [`MAX_HOSTS`].
///
/// The two travel together everywhere counters do — recorded, serialized, parsed, summed across
/// sessions, folded into a rollup — which is why they are one type rather than two values a caller
/// has to remember to carry in pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    /// One row per destination, up to [`MAX_HOSTS`] of them.
    pub(crate) hosts: BTreeMap<String, Counts>,
    /// Requests whose destination got no row of its own. Their counts are kept, so what
    /// `sbx net stats` adds up is still every request the proxy decided; *which* hosts they were is
    /// deliberately not remembered, since remembering is what the cap exists to stop.
    pub(crate) overflow: Counts,
}

/// The line prefixes the session-file format reserves for its own lines: the two identity headers
/// and the folded-counter line. [`parse`] recognises a line by these, so a destination whose name
/// begins with one would write a row that reads back as that line instead of as a counter row —
/// see [`Tally::bump`], which is where a name that could spell one is refused a row.
const RESERVED_PREFIXES: [&str; 3] = ["project=", "app=", "overflow="];

impl Tally {
    /// Count one request for `host`, giving it a row while there is room and folding it into
    /// [`Self::overflow`] once there is not. A host that already has a row always keeps counting
    /// into it, so the cap never turns a busy destination into an anonymous one part-way through.
    ///
    /// The name is sanitised on the way in, so what the row is keyed by and what the file carries are
    /// the same string. A row is `host\tallow\tdeny\tblocked` on one line, and a host bearing a tab
    /// or a newline would write extra fields or an extra row — read back as counters for a
    /// destination nothing ever reached. Today the wire cannot deliver one: a request line is split
    /// on whitespace before its target is read, and an HTTP/2 `:authority` is re-checked against the
    /// CONNECT host it must equal. That is an invariant held three parsers away from here, by code
    /// with its own reasons to change; the format's own rule belongs to the format.
    ///
    /// The delimiters are not the format's only structure: a line is also claimed by its **prefix**
    /// ([`RESERVED_PREFIXES`]), and those survive sanitising because `=` is not a control character.
    /// A destination the cage names `project=…` is real — a CONNECT authority is not validated as a
    /// hostname, and a host-mismatch is counted against the name the client asked for — so it is
    /// refused a row of its own and folded like a destination past the cap: its requests are still
    /// counted, and nothing it can spell reaches the file as a line the reader would take for the
    /// session's identity.
    fn bump(&mut self, host: &str, kind: StatKind) {
        let host = super::observe_feed::sanitize(host);
        let has_room = self.hosts.contains_key(&host) || self.hosts.len() < MAX_HOSTS;
        if has_room && !RESERVED_PREFIXES.iter().any(|p| host.starts_with(*p)) {
            self.hosts.entry(host).or_default().bump(kind);
        } else {
            self.overflow.bump(kind);
        }
    }

    /// Add another tally into this one, host by host — summing across sessions, and folding session
    /// files into a rollup. A host beyond the cap folds here too, so merging many sessions that each
    /// stayed under it cannot walk past it.
    pub(crate) fn merge(&mut self, other: &Tally) {
        for (host, c) in &other.hosts {
            if self.hosts.contains_key(host) || self.hosts.len() < MAX_HOSTS {
                self.hosts.entry(host.clone()).or_default().add(c);
            } else {
                self.overflow.add(c);
            }
        }
        self.overflow.add(&other.overflow);
    }

    /// Whether nothing has been recorded at all — the "nothing recorded yet" case, which the
    /// overflow has to be part of or a tally holding only folded counts would read as empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.overflow.total() == 0
    }
}

/// One session's live counters plus the metadata that lets a reader attribute them to a project.
/// Shared (via `Arc`) across the proxy's per-connection threads; each [`record`](EgressStats::record)
/// updates the in-memory map and rewrites the session file atomically.
pub(crate) struct EgressStats {
    /// The session file this flushes to (`<data>/egress/stats-<pid>-<start-ticks>`).
    path: PathBuf,
    /// The canonical project path (the `project=` header), for read-side attribution.
    project: String,
    /// The app name when this is an `sbx app <name>` launch (the `app=` header), else `None`.
    app: Option<String>,
    /// A monotonic counter giving each flush a unique temp filename, so concurrent flushes from
    /// different connection threads never collide on the temp before the atomic rename.
    tmp_seq: AtomicU64,
    /// When this set of counters was created, the origin [`Self::next_flush_ms`] is measured from.
    started: Instant,
    /// Milliseconds since [`Self::started`] at which the next write is allowed. Read and written
    /// only under `inner`, which is what serialises it.
    next_flush_ms: AtomicU64,
    /// Whether a decision has been recorded that no write has yet persisted — what
    /// [`start_flusher`] looks at, so the tail of a burst is not left in memory once the traffic
    /// that produced it stops.
    pending: AtomicBool,
    /// Whether the session file can be written at all — see [`identity_is_recordable`]. Settled once,
    /// at construction, from the two header values; `false` keeps the counters in memory and writes
    /// nothing.
    recordable: bool,
    inner: Mutex<Tally>,
}

/// Whether a session file can carry this identity.
///
/// The two header lines are `project=<path>` and `app=<name>`, each read back as everything after
/// the `=` to the end of the line. A line break in either does two things, neither of them loud: the
/// value comes back truncated, so the session's counters answer to a project nobody will ask about;
/// and what follows the break is read as a further line, so a directory named to spell one hands
/// `sbx net stats` a `project=` of its choosing and takes another project's totals. A trailing `\r`
/// is quieter still — `lines()` drops it, and the identity simply stops matching the one the reader
/// derives from the same directory.
///
/// Sanitising is not open to this field the way it is to a host row: these are **matching keys**,
/// compared for equality against an identity `sbx net stats` derives independently from a cwd, so a
/// value that changed shape here would either stop matching or, worse, start matching a second
/// project that normalised to the same string. A name the format cannot carry therefore records no
/// stats at all — the same outcome a project that cannot be canonicalised already gets, and for the
/// same reason: counters are worth having, never worth a wrong answer.
fn identity_is_recordable(project: &str, app: Option<&str>) -> bool {
    let carries_break = |s: &str| s.contains('\n') || s.contains('\r');
    !carries_break(project) && !app.is_some_and(carries_break)
}

impl EgressStats {
    pub(crate) fn new(path: PathBuf, project: String, app: Option<String>) -> Self {
        EgressStats {
            recordable: identity_is_recordable(&project, app.as_deref()),
            path,
            project,
            app,
            tmp_seq: AtomicU64::new(0),
            started: Instant::now(),
            // Zero, so the first decision of a session writes its file at once rather than after an
            // interval in which `sbx net stats` would have nothing to read.
            next_flush_ms: AtomicU64::new(0),
            pending: AtomicBool::new(false),
            inner: Mutex::new(Tally::default()),
        }
    }

    /// Record one request's outcome for `host` and flush the session file. The flush is best-effort:
    /// a write error must never break egress, so it is dropped (the next decision rewrites the file
    /// anyway). The snapshot is taken under the lock and written outside it, so a burst of
    /// concurrent decisions does not serialise on file I/O; the counters are monotonic, so a lost
    /// flush race is at most an off-by-a-few that the next decision corrects.
    pub(crate) fn record(&self, host: &str, kind: StatKind) {
        let snapshot = {
            let mut tally = locked(&self.inner);
            tally.bump(host, kind);
            if !self.due_to_write() {
                self.pending.store(true, Ordering::Relaxed);
                return;
            }
            // Cleared before the snapshot is taken and under the same lock, so a decision recorded
            // after this one cannot have its flag cleared by this write.
            self.pending.store(false, Ordering::Relaxed);
            tally.clone()
        };
        let _ = self.flush(&snapshot);
    }

    /// Whether enough time has passed since the last write to take another. Called only under
    /// `inner`, which is what makes the read-then-write of the deadline sound.
    fn due_to_write(&self) -> bool {
        let now = self.started.elapsed().as_millis() as u64;
        if now < self.next_flush_ms.load(Ordering::Relaxed) {
            return false;
        }
        self.next_flush_ms
            .store(now + FLUSH_INTERVAL.as_millis() as u64, Ordering::Relaxed);
        true
    }

    /// Write out whatever the interval left behind, if anything. The trailing half of the debounce:
    /// without it the decisions of the last interval before a session goes quiet would sit in memory
    /// for as long as the silence lasts, and a reader would be told a number that stops short of
    /// what the proxy decided.
    fn flush_pending(&self) {
        let snapshot = {
            let tally = locked(&self.inner);
            if !self.pending.swap(false, Ordering::Relaxed) {
                return;
            }
            tally.clone()
        };
        let _ = self.flush(&snapshot);
    }

    /// Write the current counters out, a final tidy for a graceful exit (the per-decision flush
    /// already keeps the file current; this just guarantees the last state is on disk).
    pub(crate) fn flush_final(&self) {
        let snapshot = {
            let tally = locked(&self.inner);
            self.pending.store(false, Ordering::Relaxed);
            tally.clone()
        };
        let _ = self.flush(&snapshot);
    }

    /// The current in-memory counters — lets a test assert which bucket a recorded request landed in
    /// without round-tripping through the file.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> BTreeMap<String, Counts> {
        locked(&self.inner).hosts.clone()
    }

    /// Serialise a snapshot to the session file atomically (temp + rename), so a reader never sees a
    /// torn file and a crash mid-write leaves the prior good file in place.
    fn flush(&self, tally: &Tally) -> io::Result<()> {
        // Nothing is written for an identity the file cannot carry: the counters stay in memory for
        // the session and are simply not persisted (see [`identity_is_recordable`]).
        if !self.recordable {
            return Ok(());
        }
        let body = serialize(&self.project, self.app.as_deref(), tally);
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        write_stats_file(&self.path, &seq.to_string(), &body)
    }
}

/// One session file read back: its project/app metadata and per-host counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionStats {
    pub(crate) project: String,
    pub(crate) app: Option<String>,
    pub(crate) tally: Tally,
}

/// The session-file body: `project=`/`app=` metadata lines, then one `host\tallow\tdeny\tblocked`
/// row per destination (host first; a host carries no tab, so the four fields are unambiguous).
///
/// Both halves of that are held upstream rather than here, each where the value enters: a host is
/// sanitised — and kept clear of the format's own line prefixes — by [`Tally::bump`], and an
/// identity the header cannot carry writes no file at all ([`identity_is_recordable`]). This
/// function is therefore total over what reaches it.
fn serialize(project: &str, app: Option<&str>, tally: &Tally) -> String {
    let mut out = String::new();
    out.push_str(&format!("project={project}\n"));
    if let Some(app) = app {
        out.push_str(&format!("app={app}\n"));
    }
    for (host, c) in &tally.hosts {
        out.push_str(&format!("{host}\t{}\t{}\t{}\n", c.allow, c.deny, c.blocked));
    }
    // Written only when something was actually folded, so a file from a session that stayed under
    // the cap — every real one — is byte-for-byte what it was before the cap existed.
    let o = &tally.overflow;
    if o.total() > 0 {
        out.push_str(&format!(
            "overflow={}\t{}\t{}\n",
            o.allow, o.deny, o.blocked
        ));
    }
    out
}

/// Parse a session file's contents, or `None` if it carries no `project=` header (an unrelated or
/// truncated file). A malformed counter row is skipped, not fatal — a partially-written file still
/// yields the rows it can (self-healing).
///
/// **The identity is the first line that states it.** [`serialize`] writes both headers before any
/// row, so the first is always the real one; taking a later `project=`/`app=` line instead would let
/// anything further down the file rename the session — and what is further down is destination
/// names, which the caller in the cage chooses. Losing the whole session's counters to an
/// unqueryable identity is durable audit evasion, since this file is the only persistent record of
/// what the proxy decided. [`Tally::bump`] closes the same hole from the write side; this closes it
/// for every file, including one written before that rule existed.
fn parse(contents: &str) -> Option<SessionStats> {
    let mut project = None;
    let mut app = None;
    let mut tally = Tally::default();
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("project=") {
            if project.is_none() {
                project = Some(rest.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("app=") {
            if app.is_none() {
                app = Some(rest.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("overflow=") {
            // Read on the same terms as a counter row: three numbers, and a malformed one skipped
            // rather than fatal. Recognized by prefix like the two headers above; a destination that
            // could be mistaken for one never reaches this file with a row of its own, so a line
            // here is either the fold or damage, and damage is skipped.
            let mut f = rest.split('\t');
            let (Some(a), Some(d), Some(b), None) = (f.next(), f.next(), f.next(), f.next()) else {
                continue;
            };
            let (Ok(allow), Ok(deny), Ok(blocked)) = (a.parse(), d.parse(), b.parse()) else {
                continue;
            };
            tally.overflow.add(&Counts {
                allow,
                deny,
                blocked,
            });
        } else {
            let mut f = line.split('\t');
            let (Some(host), Some(a), Some(d), Some(b)) = (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let (Ok(allow), Ok(deny), Ok(blocked)) = (a.parse(), d.parse(), b.parse()) else {
                continue;
            };
            tally.hosts.insert(
                host.to_string(),
                Counts {
                    allow,
                    deny,
                    blocked,
                },
            );
        }
    }
    project.map(|project| SessionStats {
        project,
        app,
        tally,
    })
}

/// Start the trailing write for `stats`: a thread that persists whatever [`FLUSH_INTERVAL`] held
/// back, once the traffic that produced it stops.
///
/// It is what keeps the interval a rate limit rather than a change to what the file means. Without
/// it, a burst that ends inside an interval leaves its last decisions in memory, and a person
/// reading `sbx net stats` beside a session that has gone quiet is told a number that stops short of
/// what the proxy decided — for as long as the quiet lasts.
///
/// The thread holds a [`Weak`](std::sync::Weak), so it ends on its own once the launch lets go of
/// its counters. There is no stop flag, and so none to forget to set on a path that exits early.
pub(crate) fn start_flusher(stats: &Arc<EgressStats>) {
    let weak = Arc::downgrade(stats);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(FLUSH_INTERVAL);
            // The upgraded handle is dropped at the end of this arm, so holding it never keeps the
            // counters (and with them this thread) alive past the launch.
            match weak.upgrade() {
                Some(stats) => stats.flush_pending(),
                None => break,
            }
        }
    });
}

/// The prefix of a folded file: the summed counters of sessions that have ended, one per
/// project+app. It reads back as an ordinary session file — every consumer parses the body, never
/// the name — so folding changes what is on disk and nothing else.
const ROLLUP_PREFIX: &str = "stats-rollup.";

/// Whether the session that owns this file has ended, and so whether its counters may be folded.
///
/// A rollup is always foldable — folding again just re-sums it, which is how repeated passes stay at
/// one file rather than accumulating one per pass. A session file carries `<pid>-<ticks>`, so the
/// check is the exact incarnation pair rather than a bare pid: a reused pid must not make a dead
/// session's file look live and pin it forever.
///
/// Anything else — a name this does not recognise — is reported as still live, which keeps it. The
/// safe direction: a file kept costs nothing but space, while folding a file still being written
/// would lose the counters flushed after the read.
fn is_finished(name: &str) -> bool {
    if name.starts_with(ROLLUP_PREFIX) {
        return true;
    }
    let Some(rest) = name.strip_prefix("stats-") else {
        return false;
    };
    let Some((pid, ticks)) = rest.split_once('-') else {
        return false;
    };
    match (pid.parse::<u32>(), ticks.parse::<u64>()) {
        (Ok(pid), Ok(ticks)) => crate::session::read_start_ticks(pid) != Some(ticks),
        _ => false,
    }
}

/// The file a project+app's folded counters live in. Named from a hash of the pair because a
/// project key is a filesystem path — it carries separators, and it is unbounded in length.
fn rollup_name(project: &str, app: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(project.as_bytes());
    hasher.update([0u8]);
    hasher.update(app.unwrap_or("").as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{ROLLUP_PREFIX}{hex}")
}

/// The finished files of one project+app, each paired with the counters it holds.
///
/// A file at a time rather than one running sum, because the fold has to be able to name the
/// counters of an individual source: one that outlives its unlink is still on disk and still counted
/// by [`aggregate`], so it has to be left out of the rollup — and taking it back out of a sum is not
/// possible, since [`Tally::merge`] folds a host past [`MAX_HOSTS`] into [`Tally::overflow`] and no
/// subtraction undoes that.
type Group = Vec<(PathBuf, Tally)>;

/// The lock file whose `flock` serialises [`compact`] across processes.
///
/// A file **beside** the session files rather than one of them, and named outside their prefix: every
/// reader of this directory — [`session_files`], [`reset`], [`compact`] itself, and `sbx gc`'s
/// runtime sweep — selects on `stats-`, so nothing here ever reads, folds or removes it.
const COMPACT_LOCK: &str = ".compact.lock";

/// Take the fold lock without blocking, or `None` when another process holds it (or the directory
/// cannot carry the file). The handle is held only for its `Drop`: closing the fd releases the
/// `flock`.
///
/// Non-blocking on purpose. This runs on **every** launch, so waiting would put an unbounded stall
/// on the launch path for pure housekeeping; a process that cannot take the lock has nothing to do,
/// because the process holding it is doing exactly this work.
fn lock_compact(egress_dir: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(egress_dir.join(COMPACT_LOCK))
        .ok()?;
    // SAFETY: `flock` on a valid owned fd. `LOCK_NB` returns `EWOULDBLOCK` instead of blocking when
    // another open file description holds the lock. The fd lives in the returned handle, so the lock
    // is held until the caller drops it.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return None;
    }
    Some(file)
}

/// Fold the counters of every finished session into one file per project+app, and return the files
/// that were (or, in a dry run, would be) folded away.
///
/// This is housekeeping with no observable effect: nothing reads a single session's counters, so a
/// folded directory answers `sbx net stats` exactly as the unfolded one did. What it buys is a
/// bound — a session per file, kept forever, is a directory that only grows.
///
/// That equivalence holds only while one fold runs at a time. The body is a read-merge-write-unlink
/// over a directory every launch shares (`build()` folds on each one), and two concurrent folds
/// corrupt the rollup in either direction: one can read a session file, watch the other fold and
/// unlink it, then write a rollup that counts it twice; or it can miss a file the other has already
/// folded away and overwrite the rollup with a total that never held it. Both are written into the
/// rollup permanently and can only be cleared by `sbx net stats --reset`, which discards everything.
/// So the whole body runs under an exclusive [`lock_compact`], and a process that finds it held
/// simply does not fold.
///
/// Best-effort throughout. A file that cannot be read or parsed is left where it is, and a group
/// whose rollup cannot be written keeps its sources: the counters are worth more than the tidiness.
/// The rollup is written *before* its sources are unlinked for that same reason — a pass that stops
/// in between leaves the counters in two places rather than none. What that ordering costs is a
/// source that survives its own unlink: it still answers for its counters, which the rollup has just
/// absorbed, so `sbx net stats` would count them twice and every later pass would fold the same file
/// in again. So the rollup is rewritten from what actually went away, leaving the survivor's
/// counters where the survivor still holds them.
pub(crate) fn compact(egress_dir: &Path, prune: bool) -> Vec<PathBuf> {
    compact_with(egress_dir, prune, &|path| std::fs::remove_file(path))
}

/// [`compact`] with the unlink injected, so the fold's behaviour around a source it cannot remove is
/// testable without a filesystem that refuses removals.
fn compact_with(
    egress_dir: &Path,
    prune: bool,
    remove: &dyn Fn(&Path) -> io::Result<()>,
) -> Vec<PathBuf> {
    // Held for the whole function: the dry run takes it too, or it would report files a fold running
    // beside it is in the middle of removing.
    let Some(_lock) = lock_compact(egress_dir) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(egress_dir) else {
        return Vec::new();
    };
    // The files this pass may touch, by name alone — none of them read yet.
    let finished: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("stats-") && !name.contains(".tmp.") && is_finished(&name) {
                Some((name, entry.path()))
            } else {
                None
            }
        })
        .collect();
    // A fold with no session file left to fold is a no-op, and learning that costs names alone. A
    // rollup passes the filter above — it starts with `stats-`, and `is_finished` is true for it
    // unconditionally — so without this pre-pass every launch reads and parses every rollup in the
    // directory only to find each group already exactly its own file.
    if !finished
        .iter()
        .any(|(name, _)| !name.starts_with(ROLLUP_PREFIX))
    {
        return Vec::new();
    }
    // Group the finished files by the project+app they belong to, carrying their parsed counters.
    let mut groups: BTreeMap<(String, Option<String>), Group> = BTreeMap::new();
    for (_, path) in finished {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(session) = parse(&contents) else {
            continue;
        };
        groups
            .entry((session.project, session.app))
            .or_default()
            .push((path, session.tally));
    }

    let mut folded = Vec::new();
    for ((project, app), sources) in groups {
        let target = egress_dir.join(rollup_name(&project, app.as_deref()));
        // A group that is already exactly its own rollup has nothing to fold; re-writing it every
        // pass would be churn for no change.
        if sources.len() == 1 && sources[0].0 == target {
            continue;
        }
        if !prune {
            folded.extend(
                sources
                    .into_iter()
                    .map(|(path, _)| path)
                    .filter(|path| *path != target),
            );
            continue;
        }
        let mut total = Tally::default();
        for (_, tally) in &sources {
            total.merge(tally);
        }
        if write_rollup(&target, &project, app.as_deref(), &total).is_err() {
            continue; // keep the sources: losing counters is worse than keeping files
        }
        // The rollup now carries every source, so any source still on disk is counted twice. Build
        // what the rollup may keep from the removals that actually happened: its own prior counters,
        // plus those of the files this pass took away.
        let mut kept = Tally::default();
        let mut survivors = false;
        for (path, tally) in sources {
            if path == target {
                kept.merge(&tally);
                continue;
            }
            // A file another process removed first counts as gone: `sbx net stats --reset` races
            // this fold, and a source that is no longer on disk answers for nothing, so its counters
            // belong in the rollup exactly like a source this pass unlinked itself.
            let gone = match remove(&path) {
                Ok(()) => true,
                Err(err) => err.kind() == io::ErrorKind::NotFound,
            };
            if gone {
                kept.merge(&tally);
                folded.push(path);
            } else {
                survivors = true;
            }
        }
        if survivors {
            // Best-effort like every other write here. Should this one fail, the rollup keeps the
            // survivor's counters until a later pass rewrites it, and the overcount stays bounded at
            // that one copy: every pass puts the rollup back to what it actually took away.
            let _ = write_rollup(&target, &project, app.as_deref(), &kept);
        }
    }
    folded.sort();
    folded
}

/// Write a folded file atomically (temp + rename), so a reader never sees it half-written and an
/// interrupted fold leaves the sources still standing.
fn write_rollup(target: &Path, project: &str, app: Option<&str>, tally: &Tally) -> io::Result<()> {
    let body = serialize(project, app, tally);
    write_stats_file(target, &std::process::id().to_string(), &body)
}

/// Write one counters file atomically: an owner-only temp sibling named `<target>.tmp.<suffix>`,
/// then a rename over `target`, so a reader never sees a torn file and a crash mid-write leaves the
/// previous good one in place. On ANY failure — open, write (e.g. ENOSPC), or rename — the temp is
/// removed, so a failed write never leaks an orphan.
///
/// The `.tmp.` in that name is load-bearing: [`compact`], [`session_files`] and [`reset`] all skip
/// the intermediates by it, so a writer that spelled its temp differently would have its orphans
/// read back as session files. What the suffix carries is only what tells two writers apart — a
/// per-instance sequence number for the session flush, the pid for the fold.
fn write_stats_file(target: &Path, tmp_suffix: &str, body: &str) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = target.with_extension(format!("tmp.{tmp_suffix}"));
    // Owner-only: the counters live under the 0700 egress dir, but tighten the file too.
    let write = || -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body.as_bytes())
    };
    let result = write().and_then(|()| std::fs::rename(&tmp, target));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// The session-stat files under an egress directory (`stats-*`, excluding the `.tmp.*` flush
/// intermediates), each parsed. A file that cannot be read or has no header is skipped.
fn session_files(egress_dir: &Path) -> Vec<SessionStats> {
    let Ok(entries) = std::fs::read_dir(egress_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            // `stats-<pid>` only — never a `stats-<pid>.tmp.<n>` flush intermediate.
            if !name.starts_with("stats-") || name.contains(".tmp.") {
                return None;
            }
            let contents = std::fs::read_to_string(e.path()).ok()?;
            parse(&contents)
        })
        .collect()
}

/// Aggregate every session file for `project` (and `app`, when given) into one host→counts map,
/// summing across sessions. An absent directory or no matching file is an empty map (a clean
/// "nothing recorded yet").
pub(crate) fn aggregate(egress_dir: &Path, project: &str, app: Option<&str>) -> Tally {
    let mut total = Tally::default();
    for session in session_files(egress_dir) {
        if session.project != project {
            continue;
        }
        if let Some(want) = app
            && session.app.as_deref() != Some(want)
        {
            continue;
        }
        total.merge(&session.tally);
    }
    total
}

/// Delete every session file matching `project` (and `app`, when given), returning how many were
/// removed — `sbx net stats --reset`. Best-effort per file: a removal error is skipped, so a
/// partially-removable set still clears what it can.
///
/// This clears the persisted counters of *ended* sessions. A still-**live** session keeps its
/// counters in memory and rewrites its file on the next decision, so its lifetime totals reappear —
/// `--reset` does not zero a running agent's counters (that would need a control message to the live
/// proxy; not implemented). Reset after the sessions you want cleared have exited.
pub(crate) fn reset(egress_dir: &Path, project: &str, app: Option<&str>) -> usize {
    let Ok(entries) = std::fs::read_dir(egress_dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("stats-") || name.contains(".tmp.") {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Some(session) = parse(&contents) else {
            continue;
        };
        if session.project != project {
            continue;
        }
        if let Some(want) = app
            && session.app.as_deref() != Some(want)
        {
            continue;
        }
        if std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    /// Write a stats file as a session would, for a pid+incarnation of the caller's choosing.
    fn session_file(dir: &Path, pid: u32, ticks: u64, project: &str, host: &str, allow: u64) {
        let counts = [(
            host.to_string(),
            Counts {
                allow,
                deny: 0,
                blocked: 0,
            },
        )]
        .into_iter()
        .collect();
        let tally = Tally {
            hosts: counts,
            ..Tally::default()
        };
        std::fs::write(
            dir.join(format!("stats-{pid}-{ticks}")),
            serialize(project, None, &tally),
        )
        .unwrap();
    }

    /// The names of the stats files under an egress directory, sorted. Filtered to the `stats-`
    /// prefix every reader of this directory selects on, so the fold's own lock file — a sibling of
    /// the data, never read as data — is not counted as one.
    fn stats_names(egress: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(egress)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("stats-"))
            .collect();
        names.sort();
        names
    }

    /// Folding is invisible: the aggregate a caller reads is the same before and after, and what
    /// changes is only how many files hold it.
    #[test]
    fn folding_finished_sessions_preserves_every_counter() {
        let dir = TmpDir::new();
        let egress = dir.path();
        // Three sessions of one project, all ended (pid 1 exists but not with these start times).
        session_file(egress, 1, 11, "/p", "api.example.com", 3);
        session_file(egress, 1, 12, "/p", "api.example.com", 4);
        session_file(egress, 1, 13, "/p", "cdn.example.com", 5);
        let before = aggregate(egress, "/p", None);

        let folded = compact(egress, true);

        assert_eq!(
            folded.len(),
            3,
            "every finished file is folded away: {folded:?}"
        );
        assert_eq!(
            aggregate(egress, "/p", None),
            before,
            "folding must not change a single counter"
        );
        let remaining = stats_names(egress);
        assert_eq!(
            remaining.len(),
            1,
            "one project must end up with one file, not one per session: {remaining:?}"
        );
        assert!(remaining[0].starts_with(ROLLUP_PREFIX), "{remaining:?}");
    }

    /// A session still running is still writing its file, so folding it would drop whatever it
    /// flushes next. It is left exactly where it is.
    #[test]
    fn a_running_sessions_file_is_never_folded() {
        let dir = TmpDir::new();
        let egress = dir.path();
        let me = std::process::id();
        let ticks = crate::session::read_start_ticks(me).expect("our own start time");
        session_file(egress, me, ticks, "/p", "api.example.com", 1);
        session_file(egress, 1, 11, "/p", "api.example.com", 2);

        let folded = compact(egress, true);

        assert_eq!(folded.len(), 1, "only the finished session may be folded");
        assert!(
            egress.join(format!("stats-{me}-{ticks}")).exists(),
            "the live session's file must be untouched"
        );
        assert_eq!(
            aggregate(egress, "/p", None).hosts["api.example.com"].allow,
            3,
            "the live file and the fold are both still counted"
        );
    }

    /// Folding repeatedly converges: a second pass over an already-folded directory has nothing to
    /// do, so the file count stays at one rather than growing a rollup per pass.
    #[test]
    fn folding_twice_leaves_one_file_and_no_churn() {
        let dir = TmpDir::new();
        let egress = dir.path();
        session_file(egress, 1, 11, "/p", "api.example.com", 3);
        session_file(egress, 1, 12, "/p", "api.example.com", 4);
        compact(egress, true);

        assert!(
            compact(egress, true).is_empty(),
            "a folded directory has nothing left to fold"
        );
        assert_eq!(stats_names(egress).len(), 1);
        assert_eq!(
            aggregate(egress, "/p", None).hosts["api.example.com"].allow,
            7
        );
    }

    /// A source the fold cannot unlink is still on disk, and every consumer sums the files it finds
    /// — so a rollup that already absorbed it counts it twice, and each later pass would fold the
    /// same file in again, growing the rollup without bound. The rollup keeps only what actually
    /// went away.
    #[test]
    fn a_source_that_outlives_its_unlink_is_not_counted_twice() {
        let dir = TmpDir::new();
        let egress = dir.path();
        session_file(egress, 1, 11, "/p", "api.example.com", 3);
        session_file(egress, 1, 12, "/p", "api.example.com", 4);
        let before = aggregate(egress, "/p", None);
        let stuck = egress.join("stats-1-12");
        // One source refuses to go, as an unlink denied by the directory's permissions does. The
        // rest of the group folds as always.
        let refuse = |path: &Path| -> io::Result<()> {
            if path == stuck {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            std::fs::remove_file(path)
        };

        let folded = compact_with(egress, true, &refuse);

        assert_eq!(
            folded,
            [egress.join("stats-1-11")],
            "only the source that went away may be reported folded"
        );
        assert!(
            stuck.exists(),
            "the refused source must be left where it is"
        );
        assert_eq!(
            aggregate(egress, "/p", None),
            before,
            "folding must not change a single counter"
        );

        // And the next pass does not add it a second time: what the rollup holds is still only the
        // sources that left.
        assert!(
            compact_with(egress, true, &refuse).is_empty(),
            "a source that cannot be removed is never reported folded"
        );
        assert_eq!(aggregate(egress, "/p", None), before);
    }

    /// `sbx net stats --reset` removes session files without taking the fold lock, so a source can
    /// be gone by the time the fold unlinks it. It is gone either way: it answers for nothing on
    /// disk, so its counters stay in the rollup rather than being dropped as a survivor's.
    #[test]
    fn a_source_removed_underneath_the_fold_keeps_its_counters() {
        let dir = TmpDir::new();
        let egress = dir.path();
        session_file(egress, 1, 11, "/p", "api.example.com", 3);
        session_file(egress, 1, 12, "/p", "api.example.com", 4);
        let before = aggregate(egress, "/p", None);
        // Removed by somebody else first: the unlink reports the file already gone.
        let raced = |path: &Path| -> io::Result<()> {
            std::fs::remove_file(path)?;
            Err(io::Error::from(io::ErrorKind::NotFound))
        };

        let folded = compact_with(egress, true, &raced);

        assert_eq!(folded.len(), 2, "both sources are gone: {folded:?}");
        assert_eq!(
            aggregate(egress, "/p", None),
            before,
            "counters of a file that vanished mid-fold must land in the rollup"
        );
    }

    /// The fold is a read-merge-write-unlink over a directory every launch shares, and `build()`
    /// runs it on each one — two terminals starting a session at the same time is the ordinary case.
    /// Unserialised, one process reads a session file, the other folds and unlinks it, and the first
    /// then writes a rollup counting it twice (or, the other way round, one that never held it).
    /// Either lands in the rollup permanently and survives every later fold.
    ///
    /// So the fold takes an exclusive lock and, finding it held, does nothing at all: the holder is
    /// already doing exactly this work. `flock` is per open file description, so a second open in
    /// this same process contends exactly as another process would — which is what lets the test
    /// stand a concurrent fold up without one.
    #[test]
    fn a_fold_already_running_elsewhere_makes_this_one_stand_down() {
        let dir = TmpDir::new();
        let egress = dir.path();
        session_file(egress, 1, 11, "/p", "api.example.com", 3);

        let held = lock_compact(egress).expect("the fold lock");
        assert!(
            compact(egress, true).is_empty(),
            "a fold that cannot take the lock must report folding nothing"
        );
        assert_eq!(
            stats_names(egress),
            ["stats-1-11"],
            "and must leave every source where the holder expects it"
        );
        assert_eq!(
            aggregate(egress, "/p", None).hosts["api.example.com"].allow,
            3,
            "the counters are read exactly once, whoever folds"
        );

        drop(held);
        assert_eq!(
            compact(egress, true).len(),
            1,
            "once the lock is free the fold proceeds as always"
        );
        assert_eq!(
            aggregate(egress, "/p", None).hosts["api.example.com"].allow,
            3,
            "and folding still changes no counter"
        );
    }

    /// A destination name cannot write a row of its own: the file is tab-and-newline delimited, so a
    /// host bearing either would otherwise be read back as extra fields, or as counters for a
    /// destination nothing ever reached.
    #[test]
    fn a_hostile_destination_name_cannot_forge_a_row() {
        let dir = TmpDir::new();
        let path = dir.path().join("stats-1");
        let stats = EgressStats::new(path.clone(), "/p".into(), None);

        // Both delimiters at once: the tab would add fields to this row, the newline a row after it.
        stats.record("a.test\t9\t9\t9\nb.test\t7\t7\t7", StatKind::Deny);
        stats.record("ok.test", StatKind::Allow);
        stats.flush_final();

        let parsed = parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            parsed.tally.hosts.len(),
            2,
            "one row per destination recorded, no forged third: {:?}",
            parsed.tally.hosts
        );
        assert!(
            !parsed.tally.hosts.contains_key("b.test"),
            "a name carrying a newline invented a destination: {:?}",
            parsed.tally.hosts
        );
        assert_eq!(parsed.tally.hosts["ok.test"].allow, 1);
        // The counters the hostile name carried are its own row's, and they are the ones recorded —
        // one deny — rather than the nines it wrote into its name.
        let (name, counts) = parsed
            .tally
            .hosts
            .iter()
            .find(|(h, _)| h.starts_with("a.test"))
            .expect("the destination still has a row of its own");
        assert_eq!((counts.deny, counts.allow), (1, 0), "row {name}");
    }

    /// A line of this file is claimed by its **prefix** as well as by its delimiters, and `=` is not
    /// a control character, so sanitising leaves a destination free to spell one. The cage can
    /// reach the counter with such a name — a CONNECT authority is never validated as a hostname,
    /// and a host-mismatch is counted against the name the client asked for — and a row that reads
    /// back as `project=` renames the whole session to something no `sbx net stats`, no `--reset`
    /// and no fold will ever match again. That is durable audit evasion: this file is the only
    /// persistent record of what the proxy decided (`sbx net log` is an in-memory ring).
    ///
    /// Both halves are pinned, because each holds on its own: the row never reaches the file, and a
    /// file that carries one anyway still reads back with the identity its first line stated.
    #[test]
    fn a_destination_named_like_a_header_cannot_rename_the_session() {
        let dir = TmpDir::new();
        let egress = dir.path();
        let path = egress.join("stats-1-11");
        let stats = EgressStats::new(path.clone(), "/home/u/proj".into(), None);
        stats.record("api.example.com", StatKind::Allow);
        stats.record("project=/tmp/x", StatKind::Blocked);
        stats.record("app=other", StatKind::Blocked);
        stats.flush_final();

        let parsed = parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            parsed.project, "/home/u/proj",
            "the session still answers to the project it ran in"
        );
        assert_eq!(parsed.app, None, "and to no app it never belonged to");
        assert_eq!(
            parsed.tally.hosts.len(),
            1,
            "a name that could spell a header line gets no row: {:?}",
            parsed.tally.hosts
        );
        // Folded rather than dropped, like a destination past the cap: what `sbx net stats` adds up
        // is still every request the proxy decided.
        assert_eq!(parsed.tally.overflow.blocked, 2);
        assert_eq!(
            aggregate(egress, "/home/u/proj", None).hosts["api.example.com"].allow,
            1,
            "the session must stay visible to the project that owns it"
        );

        // The read side holds alone, for a file written before that rule existed — or by hand.
        let forged = "project=/home/u/proj\napi.example.com\t1\t0\t0\nproject=/tmp/x\t0\t0\t1\n";
        assert_eq!(parse(forged).unwrap().project, "/home/u/proj");
    }

    /// A project path a session file cannot carry records nothing, rather than a header a reader
    /// would attribute to somebody else. Both halves matter: the forged identity must not appear,
    /// and the real one must not be silently written under a truncated name either.
    #[test]
    fn a_project_path_the_header_cannot_carry_records_no_file() {
        let dir = TmpDir::new();
        let egress = dir.path();
        // A directory named to spell a second header line. Legal on Linux, and the whole attack.
        let hostile = "/home/u/proj\nproject=/home/u/victim";
        let stats = EgressStats::new(egress.join("stats-1"), hostile.into(), None);
        stats.record("api.example.com", StatKind::Allow);
        stats.flush_final();

        assert!(
            !egress.join("stats-1").exists(),
            "a file was written for an identity that cannot be read back"
        );
        assert!(
            aggregate(egress, "/home/u/victim", None).is_empty(),
            "another project was handed this session's counters"
        );
        assert!(
            aggregate(egress, hostile, None).is_empty(),
            "the counters were kept under a name no reader can match"
        );
        // The counting itself is untouched — only the writing is withheld.
        assert_eq!(stats.snapshot()["api.example.com"].allow, 1);

        // The same session under an ordinary path writes its file as always: the rule refuses what
        // the format cannot carry, not paths that merely look unusual.
        let ok = EgressStats::new(egress.join("stats-2"), "/home/u/my proj (2)".into(), None);
        ok.record("api.example.com", StatKind::Allow);
        ok.flush_final();
        assert_eq!(
            aggregate(egress, "/home/u/my proj (2)", None).hosts["api.example.com"].allow,
            1
        );
    }

    /// A dry run reports what it would fold and touches nothing — the same contract the rest of gc
    /// keeps, and the reason a `sbx gc` without `--prune` is safe to run anywhere.
    #[test]
    fn a_dry_run_folds_nothing() {
        let dir = TmpDir::new();
        let egress = dir.path();
        session_file(egress, 1, 11, "/p", "api.example.com", 3);
        session_file(egress, 1, 12, "/p", "api.example.com", 4);

        assert_eq!(compact(egress, false).len(), 2);
        assert_eq!(
            stats_names(egress),
            ["stats-1-11", "stats-1-12"],
            "a dry run must leave every counter file exactly as it found it"
        );
    }

    /// Two projects do not pool their counters, however the files are folded.
    #[test]
    fn projects_are_folded_apart() {
        let dir = TmpDir::new();
        let egress = dir.path();
        session_file(egress, 1, 11, "/a", "api.example.com", 3);
        session_file(egress, 1, 12, "/b", "api.example.com", 4);

        compact(egress, true);

        assert_eq!(
            aggregate(egress, "/a", None).hosts["api.example.com"].allow,
            3
        );
        assert_eq!(
            aggregate(egress, "/b", None).hosts["api.example.com"].allow,
            4
        );
        assert_eq!(stats_names(egress).len(), 2);
    }

    #[test]
    fn recorded_decisions_round_trip_through_the_session_file() {
        let dir = TmpDir::new();
        let path = dir.path().join("stats-1");
        let stats = EgressStats::new(path.clone(), "/home/u/proj".into(), None);

        stats.record("cache.nixos.org", StatKind::Allow);
        stats.record("cache.nixos.org", StatKind::Allow);
        stats.record("evil.test", StatKind::Deny);
        stats.record("evil.test", StatKind::Blocked);
        // The tail of a burst is written by the trailing write or, as here, by the session's own
        // final one — see `a_burst_is_rate_limited_but_never_lost` for the timing this stands on.
        stats.flush_final();

        // Read the file straight back through the parser.
        let parsed = parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.project, "/home/u/proj");
        assert_eq!(parsed.app, None);
        assert_eq!(
            parsed.tally.hosts["cache.nixos.org"],
            Counts {
                allow: 2,
                deny: 0,
                blocked: 0
            }
        );
        assert_eq!(
            parsed.tally.hosts["evil.test"],
            Counts {
                allow: 0,
                deny: 1,
                blocked: 1
            }
        );
        // No temp intermediate is left behind after the atomic rename.
        assert!(!dir.path().join("stats-1.tmp.0").exists());
    }

    #[test]
    fn serialize_parse_round_trips_with_an_app_header() {
        let mut counts = BTreeMap::new();
        counts.insert(
            "a.test".to_string(),
            Counts {
                allow: 5,
                deny: 1,
                blocked: 0,
            },
        );
        let body = serialize(
            "/p",
            Some("demo"),
            &Tally {
                hosts: counts,
                ..Tally::default()
            },
        );
        let parsed = parse(&body).unwrap();
        assert_eq!(parsed.project, "/p");
        assert_eq!(parsed.app.as_deref(), Some("demo"));
        assert_eq!(
            parsed.tally.hosts["a.test"],
            Counts {
                allow: 5,
                deny: 1,
                blocked: 0
            }
        );
    }

    #[test]
    fn parse_rejects_a_headerless_file_and_skips_malformed_rows() {
        // No `project=` line → not a stats file.
        assert!(parse("a.test\t1\t0\t0\n").is_none());
        // A header plus one good row and one malformed row → the good row survives.
        let parsed = parse("project=/p\ngood.test\t3\t0\t0\nbad row\tx\ty\n").unwrap();
        assert_eq!(parsed.tally.hosts.len(), 1);
        assert_eq!(parsed.tally.hosts["good.test"].allow, 3);
    }

    #[test]
    fn aggregate_sums_matching_sessions_and_filters_by_project_and_app() {
        let dir = TmpDir::new();
        // Two sessions of the same project (one an app), one of a different project.
        EgressStats::new(dir.path().join("stats-1"), "/p".into(), None).record_n(
            "h.test",
            StatKind::Allow,
            2,
        );
        EgressStats::new(dir.path().join("stats-2"), "/p".into(), Some("demo".into())).record_n(
            "h.test",
            StatKind::Allow,
            3,
        );
        EgressStats::new(dir.path().join("stats-3"), "/other".into(), None).record_n(
            "h.test",
            StatKind::Allow,
            9,
        );

        // Project-wide: both /p sessions sum (2+3), the /other one is excluded.
        let all = aggregate(dir.path(), "/p", None);
        assert_eq!(all.hosts["h.test"].allow, 5);
        // App-scoped: only the `demo` session.
        let app = aggregate(dir.path(), "/p", Some("demo"));
        assert_eq!(app.hosts["h.test"].allow, 3);
        // An unrelated project: empty.
        assert!(aggregate(dir.path(), "/nope", None).is_empty());
    }

    /// The first decision of a session is written at once, a burst behind it is rate-limited rather
    /// than written per decision, and none of it is lost.
    ///
    /// The interval exists because the file is rewritten whole and the destination is the caller's
    /// to choose: uncapped, an in-cage caller decides how fast the host writes to storage, measured
    /// at roughly four kilobytes of writes for a sixty-byte refused request. What it must not become
    /// is a change to what the file *means*, which is what the trailing write settles.
    #[test]
    fn a_burst_is_rate_limited_but_never_lost() {
        let dir = TmpDir::new();
        let path = dir.path().join("stats-1");
        let stats = EgressStats::new(path.clone(), "/p".into(), None);
        let on_disk = || {
            parse(&std::fs::read_to_string(&path).unwrap())
                .unwrap()
                .tally
                .hosts["a.test"]
                .allow
        };

        stats.record("a.test", StatKind::Allow);
        assert_eq!(
            on_disk(),
            1,
            "the first decision of a session is on disk immediately, so a reader beside a launch \
             that has just started is not told there is nothing"
        );

        for _ in 0..999 {
            stats.record("a.test", StatKind::Allow);
        }
        assert!(
            on_disk() < 1000,
            "the burst behind it did not rewrite the file once per decision"
        );

        stats.flush_pending();
        assert_eq!(
            on_disk(),
            1000,
            "and the trailing write persists every one of them"
        );
        // Nothing further is pending, so a quiet session does not keep rewriting the same file.
        std::fs::remove_file(&path).unwrap();
        stats.flush_pending();
        assert!(
            !path.exists(),
            "a trailing write with nothing to say writes nothing"
        );
    }

    /// Past the cap a destination gets no row, and its requests are still counted.
    ///
    /// The cap exists because the key is chosen by the caller in the cage and reached before any
    /// policy decision permits anything — see [`MAX_HOSTS`]. Dropping the counts instead would make
    /// the one number this file exists to produce quietly wrong, so they fold.
    ///
    /// The expected values are literals rather than expressions over [`MAX_HOSTS`]: moving the cap
    /// should make a reader come here and agree to the new numbers, not slide past a test that
    /// re-derives whatever the constant now says.
    #[test]
    fn a_destination_past_the_cap_is_folded_rather_than_dropped() {
        let mut tally = Tally::default();
        for i in 0..300 {
            tally.bump(&format!("h{i}.test"), StatKind::Deny);
        }
        assert_eq!(tally.hosts.len(), 256, "the cap is where rows stop");
        assert_eq!(
            tally.overflow,
            Counts {
                allow: 0,
                deny: 44,
                blocked: 0
            },
            "the 44 destinations past it are counted without being named"
        );
        assert_eq!(
            tally.hosts.values().map(Counts::total).sum::<u64>() + tally.overflow.total(),
            300,
            "every request is still counted exactly once"
        );

        // A destination that already has a row keeps counting into it, so the cap never turns a busy
        // one anonymous part-way through.
        tally.bump("h0.test", StatKind::Deny);
        assert_eq!(tally.hosts["h0.test"].deny, 2);
        assert_eq!(tally.overflow.deny, 44, "and does not fold on the way");
    }

    /// Merging obeys the same cap, so summing many sessions that each stayed under it cannot walk
    /// past it — the read side is where a project's sessions actually add up.
    #[test]
    fn merging_sessions_folds_past_the_cap_too() {
        let session = |from: usize| {
            let mut t = Tally::default();
            for i in from..from + 200 {
                t.bump(&format!("h{i}.test"), StatKind::Allow);
            }
            t
        };
        let mut total = Tally::default();
        total.merge(&session(0));
        total.merge(&session(1000));
        assert_eq!(total.hosts.len(), 256);
        assert_eq!(total.overflow.allow, 144, "400 recorded, 256 named");
        assert_eq!(
            total.hosts.values().map(Counts::total).sum::<u64>() + total.overflow.total(),
            400
        );
    }

    /// The fold survives the file: it is written, read back, and summed like any other counter.
    /// And a session that never met the cap writes exactly the file it always did — no new line, so
    /// nothing about an ordinary session's bytes changes.
    #[test]
    fn the_folded_counts_round_trip_and_only_appear_when_something_folded() {
        let plain = Tally {
            hosts: [(
                "a.test".to_string(),
                Counts {
                    allow: 5,
                    deny: 1,
                    blocked: 0,
                },
            )]
            .into_iter()
            .collect(),
            ..Tally::default()
        };
        let body = serialize("/p", None, &plain);
        assert_eq!(body, "project=/p\na.test\t5\t1\t0\n");
        assert_eq!(parse(&body).unwrap().tally, plain);

        let folded = Tally {
            overflow: Counts {
                allow: 0,
                deny: 44,
                blocked: 2,
            },
            ..plain.clone()
        };
        let body = serialize("/p", None, &folded);
        assert_eq!(body, "project=/p\na.test\t5\t1\t0\noverflow=0\t44\t2\n");
        assert_eq!(parse(&body).unwrap().tally, folded);

        // A malformed fold line is skipped like a malformed counter row, not fatal.
        let parsed = parse("project=/p\na.test\t5\t1\t0\noverflow=nope\n").unwrap();
        assert_eq!(parsed.tally, plain);
    }

    /// A tally holding only folded counts is not empty. It reads as empty on the host map alone,
    /// which is the shape that would tell a reader "nothing recorded yet" about a session that
    /// refused a hundred thousand requests.
    #[test]
    fn a_tally_holding_only_folded_counts_is_not_empty() {
        let mut only_folded = Tally::default();
        only_folded.overflow.bump(StatKind::Deny);
        assert!(!only_folded.is_empty());
        assert!(Tally::default().is_empty());
    }

    #[test]
    fn reset_removes_only_the_matching_sessions() {
        let dir = TmpDir::new();
        EgressStats::new(dir.path().join("stats-1"), "/p".into(), None).record_n(
            "h.test",
            StatKind::Allow,
            1,
        );
        EgressStats::new(dir.path().join("stats-2"), "/other".into(), None).record_n(
            "h.test",
            StatKind::Allow,
            1,
        );

        assert_eq!(reset(dir.path(), "/p", None), 1);
        assert!(!dir.path().join("stats-1").exists());
        assert!(
            dir.path().join("stats-2").exists(),
            "another project's file is untouched"
        );
        assert!(aggregate(dir.path(), "/p", None).is_empty());
    }

    impl EgressStats {
        /// Record the same outcome `n` times (a test convenience).
        fn record_n(&self, host: &str, kind: StatKind, n: u64) {
            for _ in 0..n {
                self.record(host, kind);
            }
            // As a session's own teardown does: writes are rate-limited, so a burst reaches disk
            // once something asks for it rather than after every decision.
            self.flush_final();
        }
    }
}
