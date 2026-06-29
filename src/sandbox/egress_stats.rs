//! Per-host egress decision counters: how often each destination an agent reached was allowed,
//! denied by a rule, or stopped by a security guard. The proxy ([`super::proxy`]) records one
//! outcome per request into an [`EgressStats`]; a host-side `ops net stats` aggregates the
//! per-session files back into a project view.
//!
//! Design notes:
//! - **One outcome per request.** A request is counted exactly once — `allow` when it egressed,
//!   `deny` when a rule (or an `ask` decision) refused it, `blocked` when a security guard fired
//!   (SSRF, an outbound-secret tripwire, a domain-fronting host mismatch). Protocol/transport
//!   failures (a malformed request, a DNS or upstream error) are not a policy verdict and are not
//!   counted, so the numbers mean "what the policy did", not "what the network did".
//! - **Flush per decision, not on exit.** A long-running agent session most often ends by being
//!   killed (`ops stop` sends SIGTERM→SIGKILL), and a Rust `Drop` does not run on a signal — so a
//!   flush-on-drop would silently persist nothing for exactly the sessions worth auditing. Each
//!   recorded decision rewrites the (tiny — one line per distinct host) session file atomically, so
//!   the file is current as of the last completed request regardless of how the session dies.
//! - **One file per session, aggregated at read.** Files are keyed by pid (`stats-<pid>`), so two
//!   sessions of the same project never contend on a write; `ops net stats` sums every session
//!   file whose embedded `project=` header matches the project the user stands in. The project key
//!   is the canonical path [`super::binds::project_identity`] derives, the same on the write and
//!   read sides, so a launch's record and a later read cannot drift apart.

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
    /// The session file this flushes to (`<data>/egress/stats-<pid>`).
    path: PathBuf,
    /// The canonical project path (the `project=` header), for read-side attribution.
    project: String,
    /// The app name when this is an `ops app <name>` launch (the `app=` header), else `None`.
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
/// removed — `ops net stats --reset`. Best-effort per file: a removal error is skipped, so a
/// partially-removable set still clears what it can.
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
