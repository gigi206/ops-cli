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

impl Tally {
    /// Count one request for `host`, giving it a row while there is room and folding it into
    /// [`Self::overflow`] once there is not. A host that already has a row always keeps counting
    /// into it, so the cap never turns a busy destination into an anonymous one part-way through.
    fn bump(&mut self, host: &str, kind: StatKind) {
        if self.hosts.contains_key(host) || self.hosts.len() < MAX_HOSTS {
            self.hosts.entry(host.to_string()).or_default().bump(kind);
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
    inner: Mutex<Tally>,
}

impl EgressStats {
    pub(crate) fn new(path: PathBuf, project: String, app: Option<String>) -> Self {
        EgressStats {
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
            let mut tally = self.inner.lock().unwrap();
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
            let tally = self.inner.lock().unwrap();
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
            let tally = self.inner.lock().unwrap();
            self.pending.store(false, Ordering::Relaxed);
            tally.clone()
        };
        let _ = self.flush(&snapshot);
    }

    /// The current in-memory counters — lets a test assert which bucket a recorded request landed in
    /// without round-tripping through the file.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> BTreeMap<String, Counts> {
        self.inner.lock().unwrap().hosts.clone()
    }

    /// Serialise a snapshot to the session file atomically (temp + rename), so a reader never sees a
    /// torn file and a crash mid-write leaves the prior good file in place.
    fn flush(&self, tally: &Tally) -> io::Result<()> {
        let body = serialize(&self.project, self.app.as_deref(), tally);
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp = self.path.with_extension(format!("tmp.{seq}"));
        // Owner-only: the counters live under the 0700 egress dir, but tighten the file too.
        let write = || -> io::Result<()> {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(body.as_bytes())
        };
        // On ANY failure — open, write (e.g. ENOSPC), or rename — remove the temp, so a failed flush
        // never leaks a `.tmp.<seq>` orphan that the aggregate read and `reset` both skip by name.
        let result = write().and_then(|()| std::fs::rename(&tmp, &self.path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
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
fn parse(contents: &str) -> Option<SessionStats> {
    let mut project = None;
    let mut app = None;
    let mut tally = Tally::default();
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("project=") {
            project = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("app=") {
            app = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("overflow=") {
            // Read on the same terms as a counter row: three numbers, and a malformed one skipped
            // rather than fatal. Recognized by prefix like the two headers above, and carrying the
            // same theoretical ambiguity they do (a destination literally named `overflow=…`), which
            // costs that destination its row and nothing else.
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

/// The finished files of one project+app, and the counters they add up to.
type Group = (Vec<PathBuf>, Tally);

/// Fold the counters of every finished session into one file per project+app, and return the files
/// that were (or, in a dry run, would be) folded away.
///
/// This is housekeeping with no observable effect: nothing reads a single session's counters, so a
/// folded directory answers `sbx net stats` exactly as the unfolded one did. What it buys is a
/// bound — a session per file, kept forever, is a directory that only grows.
///
/// Best-effort throughout. A file that cannot be read or parsed is left where it is, and a group
/// whose rollup cannot be written keeps its sources: the counters are worth more than the tidiness.
pub(crate) fn compact(egress_dir: &Path, prune: bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(egress_dir) else {
        return Vec::new();
    };
    // Group the finished files by the project+app they belong to, carrying their parsed counters.
    let mut groups: BTreeMap<(String, Option<String>), Group> = BTreeMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if !name.starts_with("stats-") || name.contains(".tmp.") || !is_finished(&name) {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Some(session) = parse(&contents) else {
            continue;
        };
        let slot = groups
            .entry((session.project, session.app))
            .or_insert_with(|| (Vec::new(), Tally::default()));
        slot.0.push(entry.path());
        slot.1.merge(&session.tally);
    }

    let mut folded = Vec::new();
    for ((project, app), (sources, tally)) in groups {
        let target = egress_dir.join(rollup_name(&project, app.as_deref()));
        // A group that is already exactly its own rollup has nothing to fold; re-writing it every
        // pass would be churn for no change.
        if sources.len() == 1 && sources[0] == target {
            continue;
        }
        let gone: Vec<PathBuf> = sources.iter().filter(|p| **p != target).cloned().collect();
        if !prune {
            folded.extend(gone);
            continue;
        }
        if write_rollup(&target, &project, app.as_deref(), &tally).is_err() {
            continue; // keep the sources: losing counters is worse than keeping files
        }
        for path in gone {
            if std::fs::remove_file(&path).is_ok() {
                folded.push(path);
            }
        }
    }
    folded.sort();
    folded
}

/// Write a folded file atomically (temp + rename), so a reader never sees it half-written and an
/// interrupted fold leaves the sources still standing.
fn write_rollup(target: &Path, project: &str, app: Option<&str>, tally: &Tally) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let body = serialize(project, app, tally);
    let tmp = target.with_extension(format!("tmp.{}", std::process::id()));
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
        let remaining: Vec<String> = std::fs::read_dir(egress)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
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
        assert_eq!(std::fs::read_dir(egress).unwrap().count(), 1);
        assert_eq!(
            aggregate(egress, "/p", None).hosts["api.example.com"].allow,
            7
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
            std::fs::read_dir(egress).unwrap().count(),
            2,
            "a dry run must leave the directory exactly as it found it"
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
        assert_eq!(std::fs::read_dir(egress).unwrap().count(), 2);
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
