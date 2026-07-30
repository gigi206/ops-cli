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
//!   recorded decision rewrites the (tiny — one line per distinct host) session file atomically, so
//!   the file is current as of the last completed request regardless of how the session dies.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

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
    inner: Mutex<BTreeMap<String, Counts>>,
}

impl EgressStats {
    pub(crate) fn new(path: PathBuf, project: String, app: Option<String>) -> Self {
        EgressStats {
            path,
            project,
            app,
            tmp_seq: AtomicU64::new(0),
            inner: Mutex::new(BTreeMap::new()),
        }
    }

    /// Record one request's outcome for `host` and flush the session file. The flush is best-effort:
    /// a write error must never break egress, so it is dropped (the next decision rewrites the file
    /// anyway). The snapshot is taken under the lock and written outside it, so a burst of
    /// concurrent decisions does not serialise on file I/O; the counters are monotonic, so a lost
    /// flush race is at most an off-by-a-few that the next decision corrects.
    pub(crate) fn record(&self, host: &str, kind: StatKind) {
        let snapshot = {
            let mut map = self.inner.lock().unwrap();
            map.entry(host.to_string()).or_default().bump(kind);
            map.clone()
        };
        let _ = self.flush(&snapshot);
    }

    /// Write the current counters out, a final tidy for a graceful exit (the per-decision flush
    /// already keeps the file current; this just guarantees the last state is on disk).
    pub(crate) fn flush_final(&self) {
        let snapshot = self.inner.lock().unwrap().clone();
        let _ = self.flush(&snapshot);
    }

    /// The current in-memory counters — lets a test assert which bucket a recorded request landed in
    /// without round-tripping through the file.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> BTreeMap<String, Counts> {
        self.inner.lock().unwrap().clone()
    }

    /// Serialise a snapshot to the session file atomically (temp + rename), so a reader never sees a
    /// torn file and a crash mid-write leaves the prior good file in place.
    fn flush(&self, counts: &BTreeMap<String, Counts>) -> io::Result<()> {
        let body = serialize(&self.project, self.app.as_deref(), counts);
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
    pub(crate) counts: BTreeMap<String, Counts>,
}

/// The session-file body: `project=`/`app=` metadata lines, then one `host\tallow\tdeny\tblocked`
/// row per destination (host first; a host carries no tab, so the four fields are unambiguous).
fn serialize(project: &str, app: Option<&str>, counts: &BTreeMap<String, Counts>) -> String {
    let mut out = String::new();
    out.push_str(&format!("project={project}\n"));
    if let Some(app) = app {
        out.push_str(&format!("app={app}\n"));
    }
    for (host, c) in counts {
        out.push_str(&format!("{host}\t{}\t{}\t{}\n", c.allow, c.deny, c.blocked));
    }
    out
}

/// Parse a session file's contents, or `None` if it carries no `project=` header (an unrelated or
/// truncated file). A malformed counter row is skipped, not fatal — a partially-written file still
/// yields the rows it can (self-healing).
fn parse(contents: &str) -> Option<SessionStats> {
    let mut project = None;
    let mut app = None;
    let mut counts = BTreeMap::new();
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("project=") {
            project = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("app=") {
            app = Some(rest.to_string());
        } else {
            let mut f = line.split('\t');
            let (Some(host), Some(a), Some(d), Some(b)) = (f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let (Ok(allow), Ok(deny), Ok(blocked)) = (a.parse(), d.parse(), b.parse()) else {
                continue;
            };
            counts.insert(
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
        counts,
    })
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
type Group = (Vec<PathBuf>, BTreeMap<String, Counts>);

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
            .or_insert_with(|| (Vec::new(), BTreeMap::new()));
        slot.0.push(entry.path());
        for (host, c) in session.counts {
            let e = slot.1.entry(host).or_default();
            e.allow += c.allow;
            e.deny += c.deny;
            e.blocked += c.blocked;
        }
    }

    let mut folded = Vec::new();
    for ((project, app), (sources, counts)) in groups {
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
        if write_rollup(&target, &project, app.as_deref(), &counts).is_err() {
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
fn write_rollup(
    target: &Path,
    project: &str,
    app: Option<&str>,
    counts: &BTreeMap<String, Counts>,
) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let body = serialize(project, app, counts);
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
pub(crate) fn aggregate(
    egress_dir: &Path,
    project: &str,
    app: Option<&str>,
) -> BTreeMap<String, Counts> {
    let mut total: BTreeMap<String, Counts> = BTreeMap::new();
    for session in session_files(egress_dir) {
        if session.project != project {
            continue;
        }
        if let Some(want) = app {
            if session.app.as_deref() != Some(want) {
                continue;
            }
        }
        for (host, c) in session.counts {
            let e = total.entry(host).or_default();
            e.allow += c.allow;
            e.deny += c.deny;
            e.blocked += c.blocked;
        }
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
        if let Some(want) = app {
            if session.app.as_deref() != Some(want) {
                continue;
            }
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
        std::fs::write(
            dir.join(format!("stats-{pid}-{ticks}")),
            serialize(project, None, &counts),
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
            aggregate(egress, "/p", None)["api.example.com"].allow,
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
        assert_eq!(aggregate(egress, "/p", None)["api.example.com"].allow, 7);
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

        assert_eq!(aggregate(egress, "/a", None)["api.example.com"].allow, 3);
        assert_eq!(aggregate(egress, "/b", None)["api.example.com"].allow, 4);
        assert_eq!(std::fs::read_dir(egress).unwrap().count(), 2);
    }

    #[test]
    fn record_flushes_each_decision_to_the_session_file() {
        let dir = TmpDir::new();
        let path = dir.path().join("stats-1");
        let stats = EgressStats::new(path.clone(), "/home/u/proj".into(), None);

        stats.record("cache.nixos.org", StatKind::Allow);
        stats.record("cache.nixos.org", StatKind::Allow);
        stats.record("evil.test", StatKind::Deny);
        stats.record("evil.test", StatKind::Blocked);

        // The file is current after each decision (not only on a final flush) — read it straight
        // back through the parser.
        let parsed = parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.project, "/home/u/proj");
        assert_eq!(parsed.app, None);
        assert_eq!(
            parsed.counts["cache.nixos.org"],
            Counts {
                allow: 2,
                deny: 0,
                blocked: 0
            }
        );
        assert_eq!(
            parsed.counts["evil.test"],
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
        let body = serialize("/p", Some("demo"), &counts);
        let parsed = parse(&body).unwrap();
        assert_eq!(parsed.project, "/p");
        assert_eq!(parsed.app.as_deref(), Some("demo"));
        assert_eq!(
            parsed.counts["a.test"],
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
        assert_eq!(parsed.counts.len(), 1);
        assert_eq!(parsed.counts["good.test"].allow, 3);
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
        assert_eq!(all["h.test"].allow, 5);
        // App-scoped: only the `demo` session.
        let app = aggregate(dir.path(), "/p", Some("demo"));
        assert_eq!(app["h.test"].allow, 3);
        // An unrelated project: empty.
        assert!(aggregate(dir.path(), "/nope", None).is_empty());
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
        }
    }
}
