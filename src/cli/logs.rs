//! The `sbx <lens> logs` views, and the merged `sbx logs` that reads them all at once.
//!
//! Two things live here. [`run`] is the per-lens view, once for the three observation lenses: the
//! files a session writes (`sbx fs logs`), the processes it execs (`sbx proc logs`), and what its
//! ssh-agent broker decided (`sbx ssh-agent logs`). [`run_merged`] is `sbx logs`, which reads those
//! three plus every feed with no verb of its own — the egress decisions, what a broker plugin ruled
//! on, what a signer plugin formed, and the task invocations — and interleaves them in time.
//!
//! They share this module for the output discipline described below, and because the merged view is
//! the same read loop with one cursor per feed instead of one in total.
//!
//! All three read a bounded ring host-side over a per-session control socket — see
//! [`crate::sandbox::lens`] for the substrate under them — and all three present it the same way: a
//! tail of the retained window, then optionally a `--follow` that polls past a cursor until the
//! session ends. What differs is the words and the two functions that reach the socket, and that is
//! what [`LogView`] carries.
//!
//! A session that has **ended** has no socket, and is read from the record its lenses left under the
//! data dir when the launch asked for one ([`crate::sandbox::lens::Recorder`]). Which of the two
//! answers is decided by whether the session is running, never by a flag: while it runs its ring
//! holds what its record does and what has not reached the disk yet. The one thing a finished
//! session needs that a live one does not is a way to be *named* — it is gone from `sbx session ls`,
//! and a foreground `sbx run` never printed its pid — so a view with nothing live lists this
//! project's records instead of reporting that there is nothing.
//!
//! The output discipline is the reason this is worth having in one place rather than three. Rust
//! ignores `SIGPIPE`, so a bare `println!` into a closed downstream pipe (`… | head`) panics; every
//! write here goes through a locked, error-checked stdout and a failed write ends the view cleanly
//! at exit 0. Getting that wrong in one of three copies would be invisible until someone piped it.

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::sandbox::lens::Snapshot;
use crate::{diag, help, layout_or_fail, live_sessions, style};

/// How often a `--follow` view asks the session for what is new. Short enough to read as live,
/// long enough that watching a busy agent is not itself a load.
const FOLLOW_INTERVAL: Duration = Duration::from_millis(400);

/// What tells one lens's `logs` view from another. Everything not here — the flags, the session
/// resolution, the header, the follow loop, the broken-pipe handling — is the same view three times
/// over and lives in [`run`].
pub(crate) struct LogView<E: 'static> {
    /// How the command names itself in its own argument errors (`fs logs`).
    pub(crate) verb: &'static str,
    /// The help page printed on a usage error.
    pub(crate) page: &'static [&'static str],
    /// What the session resolver calls this command, in `no live session '<id>'` and in the listing
    /// it prints when several are live. Deliberately not derived from [`verb`](LogView::verb): the
    /// three spell it differently today, and it is user-visible text.
    pub(crate) session_verb: &'static str,
    /// The feed's name in the header line (`file-write feed`).
    pub(crate) feed: &'static str,
    /// Where this lens's socket for a session pid lives.
    pub(crate) socket: fn(&Path, u32) -> PathBuf,
    /// This lens's own directory under the data dir: the socket's parent, and where the session
    /// records ([`crate::sandbox::lens::Recorder`]) sit beside it.
    pub(crate) dir: fn(&Path) -> PathBuf,
    /// Read the retained window, or everything past a cursor.
    pub(crate) read: fn(&Path, Option<u64>) -> std::io::Result<Snapshot<E>>,
    /// What to say when a **live** session's socket does not answer. This is the message that has to
    /// teach: a lens that was never stood up and a lens with nothing to report both come back
    /// empty-handed, and only this text tells them apart — so each lens says why *it* in particular
    /// might not be there. A finished session never reaches this: it was resolved by finding its
    /// record, so there is one to read.
    pub(crate) absent: fn(u32) -> String,
    /// Write one event: a JSON object per line (so a `--follow` stream is valid NDJSON), or this
    /// lens's human row. Returns the write result so the caller ends cleanly on a closed pipe.
    pub(crate) write_event:
        fn(&mut dyn Write, u32, &E, bool, &style::Palette) -> std::io::Result<()>,
}

/// Where one view's events come from, once a target has been resolved.
///
/// The two are not variants of a preference: a live session's ring is the only place its newest
/// events exist, and a finished session's record is the only place any of them still do. Which one
/// answers is decided by whether the session is running, never by a flag.
enum Source {
    /// A running session, read over its control socket.
    Live { pid: u32, header: String },
    /// A session that has ended, read from the file its lens left behind. `ticks` is the
    /// incarnation the pid resolved to, which is how a second lens opens the same session's file
    /// rather than its own newest; `reused` marks a pid that named more than one session, so the
    /// view can say a choice was made.
    Record {
        pid: u32,
        path: PathBuf,
        ticks: u64,
        reused: bool,
    },
}

/// `sbx <lens> logs [<id>] [-f|--follow] [--json]`. `<id>` is the PID `sbx session ls` shows, or one
/// a session left a record under; with no id this project's sole live session is used, otherwise its
/// live ones are listed so one can be named, and with none of them live its records are.
pub(crate) fn run<E: crate::sandbox::lens::Event>(
    args: &[OsString],
    view: &LogView<E>,
) -> ExitCode {
    let mut json = false;
    let mut follow = false;
    let mut id: Option<&str> = None;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some("-f") | Some("--follow") => follow = true,
            Some(s) if !s.starts_with('-') => {
                if id.is_some() {
                    diag::error(&format!("sbx: {}: at most one session id", view.verb));
                    return ExitCode::from(2);
                }
                id = Some(s);
            }
            other => {
                diag::error(&format!(
                    "sbx: {}: unexpected argument {:?}",
                    view.verb,
                    other.unwrap_or_default()
                ));
                eprint!("{}", help::page_usage(view.page).unwrap_or_default());
                return ExitCode::from(2);
            }
        }
    }

    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let data_dir = layout.data_dir();
    let dir = (view.dir)(data_dir);
    // The project this reader stands in, derived exactly as a launch derived the `project=` header
    // it wrote — one derivation, so a record and a reader never drift apart.
    let project = match crate::config_cwd() {
        Ok(cwd) => match crate::sandbox::project_identity(&cwd) {
            Ok((_, canon)) => canon.display().to_string(),
            Err(e) => {
                diag::error(&format!("sbx: cannot resolve the project directory: {e}"));
                return ExitCode::FAILURE;
            }
        },
        Err(code) => return code,
    };
    let sessions = match live_sessions(data_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let source = match resolve_source(
        view.verb,
        view.session_verb,
        &sessions,
        id,
        std::slice::from_ref(&dir),
        &project,
    ) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());

    match source {
        Source::Live { pid, header } => live_view(view, data_dir, pid, &header, follow, json, &pal),
        Source::Record {
            pid, path, reused, ..
        } => record_view(view, pid, &path, reused, follow, json, &pal),
    }
}

/// Which session this invocation is about, and where its events are.
///
/// A live session is preferred over a record of the same pid: while a session runs its ring holds
/// what its record does *and* what has not been written yet, so reading the file would answer with
/// a lag nobody asked for.
///
/// With no id and nothing live, the answer is not an error but a **list**: a finished session is not
/// in `sbx session ls` any more, and a foreground `sbx run` never printed its pid, so a user with a
/// record to read has no way to name it. Listing what is there is the only thing that makes the
/// record reachable at all.
///
/// "Nothing live" means nothing live **of this project**. A reader standing in one project is not
/// asking about another one's session, and answering with it costs more than a surprising header:
/// it takes the listing above out of reach, because on a machine where any other project has a
/// session running the empty case is never reached and a finished session here can never be named.
///
/// A pid given explicitly is answered whatever project it belongs to, which is the one place the
/// two halves differ: `sbx session ls` lists every live session on the machine with its project
/// beside it, so that pid is one the user was shown and chose. A record is in no such listing — it
/// is only ever reached through this project's own — so a pid naming another project's record
/// stays absent, as [`crate::sandbox::lens::records_for_project`] has it.
fn resolve_source(
    verb: &str,
    session_verb: &str,
    sessions: &[crate::session::Session],
    id: Option<&str>,
    dirs: &[PathBuf],
    project: &str,
) -> Result<Source, ExitCode> {
    if let Some(id) = id {
        if let Some(live) = sessions.iter().find(|s| s.pid.to_string() == id) {
            return Ok(Source::Live {
                pid: live.pid,
                header: format!(
                    "session {} [{}] {}",
                    live.pid,
                    live.label(),
                    live.project.display()
                ),
            });
        }
        // Not live. A pid that named a record of *this* project is answered from it; one that named
        // a record of another project is not there at all, which is the same answer as a pid that
        // named nothing (see `records_for_project`).
        if let Ok(pid) = id.parse::<u32>()
            && let Some((path, ticks, reused)) = first_record(dirs, project, pid)
        {
            return Ok(Source::Record {
                pid,
                path,
                ticks,
                reused,
            });
        }
        diag::error(&format!(
            "sbx: {verb}: no live session '{id}' and no record of one — run `sbx session ls` for \
             the live ones, or `sbx {verb}` for this project's records."
        ));
        return Err(ExitCode::from(2));
    }
    let mine: Vec<&crate::session::Session> = sessions
        .iter()
        .filter(|s| s.project.as_path() == Path::new(project))
        .collect();
    match mine.as_slice() {
        [one] => Ok(Source::Live {
            pid: one.pid,
            header: format!(
                "session {} [{}] {}",
                one.pid,
                one.label(),
                one.project.display()
            ),
        }),
        [] => Err(list_records(verb, dirs, project)),
        many => {
            eprintln!(
                "sbx: {session_verb}: {} live sessions — name one by its PID:",
                many.len()
            );
            for s in many {
                eprintln!("       {}  [{}]  {}", s.pid, s.label(), s.project.display());
            }
            Err(ExitCode::from(2))
        }
    }
}

/// The empty case: nothing is running, so say what *was*. Returns the exit code the caller ends on,
/// which is `2` either way — the invocation named no session and produced no events — but the two
/// texts differ in the only thing that matters, whether there is anything to ask for.
fn list_records(verb: &str, dirs: &[PathBuf], project: &str) -> ExitCode {
    let records = crate::sandbox::lens::records_across(dirs, project);
    eprint!("{}", records_listing(verb, &records));
    ExitCode::from(2)
}

/// The session `pid` names, and the file the first of `dirs` holds for it — the single-lens view
/// then reads that file, which is the only one it shows. For the merged view the directories are
/// every lens's, so a session that recorded only a broker is found by its broker record; the merged
/// reader opens each feed under the incarnation resolved here, never one each lens picks for itself.
fn first_record(dirs: &[PathBuf], project: &str, pid: u32) -> Option<(PathBuf, u64, bool)> {
    let (ticks, reused) = crate::sandbox::lens::session_of_pid(dirs, project, pid)?;
    let path = dirs
        .iter()
        .find_map(|dir| crate::sandbox::lens::record_of_session(dir, project, pid, ticks))?;
    Some((path, ticks, reused))
}

/// The text [`list_records`] prints, built apart from the printing so it can be asserted.
///
/// A finished session is gone from `sbx session ls` and a foreground `sbx run` never printed its
/// pid, so this listing is the only thing that makes a record nameable. When there is none, the
/// text says **this project** rather than borrowing the machine-wide "no active sandbox sessions"
/// the live-only views use: the scope here is the project, so another one's session can be running
/// and listed by `sbx session ls` while this reader has nothing, and the shared sentence would read
/// as a contradiction of a listing the user just saw. The second line answers the question the
/// first raises, which is why there is no record to fall back on.
fn records_listing(verb: &str, records: &[crate::sandbox::lens::RecordEntry]) -> String {
    use std::fmt::Write as _;
    if records.is_empty() {
        return format!(
            "sbx: {verb}: no live session in this project, and no record of a finished one.\n       \
             a launch keeps one when its config sets `[observe] record`.\n"
        );
    }
    let mut out = format!(
        "sbx: {verb}: no live session in this project — {} finished session(s) recorded here:\n",
        records.len()
    );
    for r in records {
        let when =
            r.at.duration_since(std::time::UNIX_EPOCH)
                .map(|d| crate::paths::civil_date(std::time::UNIX_EPOCH + d))
                .unwrap_or_else(|_| "?".to_string());
        let _ = writeln!(out, "       {}  {}", r.pid, when);
    }
    let _ = writeln!(out, "     read one with `sbx {verb} <id>`.");
    out
}

/// A running session: the retained ring, then optionally a poll past a cursor until it ends. This is
/// the view as it always was.
fn live_view<E>(
    view: &LogView<E>,
    data_dir: &Path,
    pid: u32,
    header: &str,
    follow: bool,
    json: bool,
    pal: &style::Palette,
) -> ExitCode {
    let socket = (view.socket)(data_dir, pid);

    // The first read is a tail of the whole retained window. A connect failure means this lens was
    // never stood up for this session — there is no ring to read, which is a different thing from
    // an empty one, and the lens says which in its own words.
    let first = match (view.read)(&socket, None) {
        Ok(s) => s,
        Err(_) => {
            diag::error(&(view.absent)(pid));
            return ExitCode::from(2);
        }
    };

    // Write the header and the tail batch through a locked, error-checked stdout: a closed
    // downstream pipe (`… | head`) ends the view cleanly (exit 0) rather than panicking on the
    // broken pipe.
    {
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if !json {
                let (h, r) = (pal.head, pal.reset);
                writeln!(out, "{h}{} — {header}{r}", view.feed)?;
            }
            for e in &first.events {
                (view.write_event)(&mut out, pid, e, json, pal)?;
            }
            out.flush()
        })();
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
    }

    if !follow {
        return ExitCode::SUCCESS;
    }

    // Follow: poll past the cursor until the session ends. Whoever stood the lens up unlinks its
    // socket on drop, so a connect failure *after* the first successful read is the clean
    // end-of-session signal (a local UDS connect does not fail transiently); Ctrl+C stops it before
    // then, and a closed downstream pipe ends it cleanly too.
    let mut cursor = first.head;
    loop {
        std::thread::sleep(FOLLOW_INTERVAL);
        let snap = match (view.read)(&socket, Some(cursor)) {
            Ok(s) => s,
            Err(_) => {
                if !json {
                    let mut out = std::io::stdout().lock();
                    let (dim, r) = (pal.dim, pal.reset);
                    let _ = writeln!(out, "  {dim}(session {pid} ended){r}");
                }
                return ExitCode::SUCCESS;
            }
        };
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if snap.dropped > 0 && !json {
                let (dim, r) = (pal.dim, pal.reset);
                writeln!(
                    out,
                    "  {dim}({} earlier event(s) evicted from the ring before this poll){r}",
                    snap.dropped
                )?;
            }
            for e in &snap.events {
                (view.write_event)(&mut out, pid, e, json, pal)?;
            }
            out.flush()
        })();
        drop(out);
        if wrote.is_err() {
            // A closed downstream pipe (`… | head`) ends the follow cleanly.
            return ExitCode::SUCCESS;
        }
        cursor = snap.head;
    }
}

/// A finished session: its record, read once.
///
/// `--follow` is accepted and says why it did nothing rather than being refused. A file whose writer
/// is gone will never grow, so polling it would be a spinner over a fixed answer; refusing the flag
/// outright would break the ordinary habit of leaving `-f` on a command one re-runs.
///
/// A `truncated=` record is announced the way an eviction gap is on the live path: the events shown
/// are true, and what is missing is stated rather than left to be inferred from a tail that stops.
fn record_view<E: crate::sandbox::lens::Event>(
    view: &LogView<E>,
    pid: u32,
    path: &Path,
    reused: bool,
    follow: bool,
    json: bool,
    pal: &style::Palette,
) -> ExitCode {
    let record = match crate::sandbox::lens::read_record::<E>(path) {
        Ok(r) => r,
        Err(e) => {
            diag::error(&format!(
                "sbx: {}: cannot read the session record {}: {e}",
                view.verb,
                path.display()
            ));
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::stdout().lock();
    let wrote = (|| -> std::io::Result<()> {
        if !json {
            let (h, dim, r) = (pal.head, pal.dim, pal.reset);
            writeln!(
                out,
                "{h}{} — session {pid} (ended) {}{r}",
                view.feed, record.project
            )?;
            if reused {
                writeln!(
                    out,
                    "  {dim}(more than one session recorded under pid {pid}; showing the most \
                     recent){r}"
                )?;
            }
            if record.truncated {
                writeln!(
                    out,
                    "  {dim}(this session outran the record's size cap; its last events are \
                     missing){r}"
                )?;
            }
            if follow {
                writeln!(
                    out,
                    "  {dim}(nothing is writing this record any more, so there is nothing to \
                     follow){r}"
                )?;
            }
        }
        for e in &record.events {
            (view.write_event)(&mut out, pid, e, json, pal)?;
        }
        out.flush()
    })();
    if wrote.is_err() {
        // A closed downstream pipe (`… | head`) ends the view cleanly.
        return ExitCode::SUCCESS;
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------------------------
// The merged view: `sbx logs`
// ---------------------------------------------------------------------------------------------

/// One event of one session, flattened out of whichever feed saw it.
///
/// The feeds record different things and none of them is reshaped here: what they share is
/// already the same shape — a stamp, a short fixed token, and one field of free text — because each
/// was built to put its verbatim field last on the wire. This is that shape named, so every feed can
/// be sorted into one column of time.
struct Row {
    /// When the event **happened**, in epoch milliseconds. The merge key, and the reason every feed
    /// was brought to one unit first: sorting a second-resolution stamp against millisecond ones
    /// misplaces rows silently. For a task invocation this is when it *began*, not when its entry
    /// was written — an invocation is recorded at its end, and filing it there would put a slow one
    /// after everything that ran while it was still going.
    at_epoch_ms: u128,
    /// Which feed saw it, as the column prints it.
    feed: &'static str,
    /// The feed's own short verdict/kind token, unchanged: `deny`, `exec`, `write`, `sign`, `exit=0`.
    token: String,
    /// The feed's verbatim field: a host, a command, a path, a key comment, an operation name.
    subject: String,
}

/// Read one feed past a cursor: its new rows, the head to come back with, and how many events it
/// evicted before this read could see them.
///
/// The head is `None` when this feed cannot be followed — it answered, and its rows are good, but it
/// handed back no cursor to come back with. Reading that as zero would re-ask for everything on
/// every poll and print the same rows again; declining to follow shows them once and stops polling
/// it, which is the honest reading of a source that cannot tell us what is new. It is not the feed
/// ending, and the view says so: see [`FollowEnd`].
type FeedRead = fn(&Path, Option<u64>) -> std::io::Result<(Vec<Row>, Option<u64>, u64)>;

/// How a feed answers for a session that has ended: where its records live, and how to turn one into
/// merged rows plus whether it was cut short by the size cap.
type RecordRead = (
    fn(&Path) -> PathBuf,
    fn(&Path) -> std::io::Result<(Vec<Row>, bool)>,
);

/// One feed of the merged view, and where it stands.
struct Feed {
    name: &'static str,
    socket: PathBuf,
    /// Why this feed might not be there — the sentence that separates "nothing happened" from
    /// "nothing was ever watching", which is the single most misleading thing a merged view can get
    /// wrong. Each feed keeps its own wording, because the remedy differs.
    absent: &'static str,
    read: FeedRead,
    /// Why this feed has nothing for a session that has **ended** — a different sentence from
    /// [`absent`](Feed::absent), which explains a live session with no such lens. A feed that keeps
    /// no record says so here, so its silence is never read as a quiet session.
    no_record: &'static str,
    /// Where this feed's directory is, and how to read a record out of it. Every feed has one; the
    /// `Option` is what a feed added later, before it records anything, would use.
    record: Option<RecordRead>,
    /// The cursor to read past, or `None` once this feed is gone: either it was never stood up, or
    /// it ended while the others ran on. A gone feed is never polled again.
    cursor: Option<u64>,
}

/// One feed's session record read into merged rows: the same mapping its socket read makes, over
/// the file instead of the ring. Also hands back whether the record was cut short, which the view
/// states rather than letting a reader infer it from a tail that stops.
fn record_rows<E: crate::sandbox::lens::Event>(
    path: &Path,
    map: fn(E) -> Row,
) -> std::io::Result<(Vec<Row>, bool)> {
    let record = crate::sandbox::lens::read_record::<E>(path)?;
    Ok((
        record.events.into_iter().map(map).collect(),
        record.truncated,
    ))
}

/// One `fs` event as a merged row. Named rather than inlined because the socket read and the
/// record read make the same mapping, and a view where the two diverged would show one session two
/// ways depending on whether it was still running.
fn fs_row(e: crate::sandbox::fs_control::FsEvent) -> Row {
    Row {
        at_epoch_ms: e.at_epoch_ms,
        feed: "fs",
        token: e.kind.token().to_string(),
        subject: e.path,
    }
}

/// A running session's `fs` feed (the files it wrote), read over its control socket.
fn read_fs_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::fs_control::read_fs_log(socket, after)?;
    let rows = snap.events.into_iter().map(fs_row).collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

/// The same feed for a session that has ended, read from the record it left behind.
fn record_fs_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    record_rows(path, fs_row)
}

/// One `proc` event as a merged row. Named rather than inlined because the socket read and the
/// record read make the same mapping, and a view where the two diverged would show one session two
/// ways depending on whether it was still running.
fn proc_row(e: crate::sandbox::proc_control::ExecEvent) -> Row {
    Row {
        at_epoch_ms: e.at_epoch_ms,
        feed: "proc",
        token: e.verdict,
        subject: e.command,
    }
}

/// A running session's `proc` feed (the processes it execd), read over its control socket.
fn read_proc_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::proc_control::read_exec_log(socket, after)?;
    let rows = snap.events.into_iter().map(proc_row).collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

/// The same feed for a session that has ended, read from the record it left behind.
fn record_proc_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    record_rows(path, proc_row)
}

/// One `ssh` event as a merged row. Named rather than inlined because the socket read and the
/// record read make the same mapping, and a view where the two diverged would show one session two
/// ways depending on whether it was still running.
fn ssh_row(e: crate::sandbox::sshagent_control::AgentEvent) -> Row {
    Row {
        at_epoch_ms: e.at_epoch_ms,
        feed: "ssh",
        token: e.kind.token().to_string(),
        subject: e.detail,
    }
}

/// A running session's `ssh` feed (what its ssh-agent broker decided), read over its control socket.
fn read_ssh_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::sshagent_control::read_agent_log(socket, after)?;
    let rows = snap.events.into_iter().map(ssh_row).collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

/// The same feed for a session that has ended, read from the record it left behind.
fn record_ssh_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    record_rows(path, ssh_row)
}

/// One `broker` event as a merged row. Named rather than inlined because the socket read and the
/// record read make the same mapping, and a view where the two diverged would show one session two
/// ways depending on whether it was still running.
fn broker_row(e: crate::sandbox::broker_control::BrokerEvent) -> Row {
    Row {
        at_epoch_ms: e.at_epoch_ms,
        feed: "broker",
        token: e.kind.token().to_string(),
        subject: e.detail,
    }
}

/// A running session's `broker` feed (what a broker plugin ruled on), read over its control socket.
fn read_broker_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::broker_control::read_broker_log(socket, after)?;
    let rows = snap.events.into_iter().map(broker_row).collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

/// The same feed for a session that has ended, read from the record it left behind.
fn record_broker_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    record_rows(path, broker_row)
}

/// One `signer` event as a merged row. Named rather than inlined because the socket read and the
/// record read make the same mapping, and a view where the two diverged would show one session two
/// ways depending on whether it was still running.
fn signer_row(e: crate::sandbox::signer_control::SignerEvent) -> Row {
    Row {
        at_epoch_ms: e.at_epoch_ms,
        feed: "signer",
        token: e.kind.token().to_string(),
        subject: e.detail,
    }
}

/// A running session's `signer` feed (what a signer plugin formed), read over its control socket.
fn read_signer_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::signer_control::read_signer_log(socket, after)?;
    let rows = snap.events.into_iter().map(signer_row).collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

/// The same feed for a session that has ended, read from the record it left behind.
fn record_signer_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    record_rows(path, signer_row)
}

/// One egress decision as a merged row. Named rather than inlined for the reason the lens feeds'
/// twins are: the socket read and the record read make the same mapping, and a view where the two
/// diverged would show one session two ways depending on whether it was still running.
fn net_row(e: crate::sandbox::control::LogEvent) -> Row {
    let mut subject = format!("{}:{}", e.host, e.port);
    if let (Some(method), Some(path)) = (&e.method, &e.path) {
        subject.push_str(&format!("  {method} {path}"));
    }
    // The reason is a stable category token, never a rule's text or a secret's name — and it is the
    // whole value of a refusal line: `deny` alone does not say what to change. The verdicts whose
    // reason only spells the verdict again are the type's own rule, so this view and `sbx net logs`
    // cannot drift into rendering one event two ways.
    if !e.verdict.reason_restates_verdict() {
        subject.push_str(&format!("  ({})", e.reason));
    }
    Row {
        at_epoch_ms: e.at_epoch_ms,
        feed: "net",
        token: e.verdict.as_str().to_string(),
        subject,
    }
}

/// A finished session's egress decisions, read from the record the proxy left behind. Muted refusals
/// are absent by construction: `mute` is `dontaudit`, so they are counted and never written.
fn record_net_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    let record = crate::sandbox::control::read_record(path)?;
    Ok((
        record.events.into_iter().map(net_row).collect(),
        record.truncated,
    ))
}

fn read_net_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    // Muted refusals and captured traffic stay out: this view is the shape of a session's activity,
    // and `sbx net logs --all --with-body` is where one request is opened up. Asking for neither
    // keeps the read cheap and the column honest about what the default egress view shows.
    let snap = crate::sandbox::control::read_log(socket, after, None, false, false)?;
    let rows = snap.events.into_iter().map(net_row).collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

/// One task invocation as a merged row, shared by the socket read and the record read.
fn task_row(e: crate::sandbox::task_control::LogEntry) -> Row {
    Row {
        at_epoch_ms: e.started_epoch_ms,
        feed: "task",
        token: match e.refused.is_some() {
            true => "refused".to_string(),
            false => format!("exit={}", e.exit),
        },
        subject: match e.refused {
            Some(reason) => format!("{}  ({reason})", e.task),
            None => e.task,
        },
    }
}

/// A finished session's task invocations, read from the record the plane left behind.
fn record_task_rows(path: &Path) -> std::io::Result<(Vec<Row>, bool)> {
    let record = crate::sandbox::task_control::read_record(path)?;
    Ok((
        record.events.into_iter().map(task_row).collect(),
        record.truncated,
    ))
}

fn read_task_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let (entries, head, dropped) = crate::sandbox::task_control::read_entries(socket, after)?;
    let rows: Vec<Row> = entries.into_iter().map(task_row).collect();
    // A plane that predates the append cursor answers with no `head=`, and rows all the same. Zero
    // with nothing to show is simply an empty log and follows fine; zero *with* rows is that older
    // plane, which has no way to say what is new — so it is read once and not followed.
    let head = match head == 0 && !rows.is_empty() {
        true => None,
        false => Some(head),
    };
    Ok((rows, head, dropped))
}

/// The feed names `--feed` selects from, in the order [`feeds_for`] builds them.
///
/// Named separately because completion needs the vocabulary without a session to read: a feed
/// carries a socket path, which takes a data directory and a pid that a shell completing a flag
/// has neither of. `feeds_and_names_agree` pins the two together, so a feed added to one cannot
/// become a value the CLI accepts and the completion never offers.
pub(crate) const FEED_NAMES: &[&str] = &["proc", "signer", "net", "fs", "ssh", "broker", "task"];

/// Every feed of one session, in the order their columns read best when two events share a
/// millisecond: what the agent reached for, then what was decided about it.
///
/// That is why `signer` precedes `net`, which reads oddly until the order the proxy works in is
/// spelled out: a request's credential is formed *before* its allow is recorded, on all three
/// planes, and a refusal to form one is recorded before the `blocked` it causes. Two events of the
/// same request can share a millisecond, and the pair must not read as the effect preceding its
/// cause.
fn feeds_for(data_dir: &Path, pid: u32) -> Vec<Feed> {
    vec![
        Feed {
            name: "proc",
            socket: crate::sandbox::proc_control::proc_control_socket(data_dir, pid),
            absent: "not observed — relaunch with `--observe` to record what it execs",
            read: read_proc_rows,
            no_record: "no record — the exec lens did not run (`--observe`, or a `[proc] mode`), or the launch had no `[observe] record`",
            record: Some((
                crate::sandbox::proc_control::proc_control_dir,
                record_proc_rows,
            )),
            cursor: Some(0),
        },
        Feed {
            name: "signer",
            socket: crate::sandbox::signer_control::signer_control_socket(data_dir, pid),
            absent: "no signer plugin — no credential in this config declares `sign`",
            read: read_signer_rows,
            no_record: "no record — no credential in that config declared `sign`, or the launch had no `[observe] record`",
            record: Some((
                crate::sandbox::signer_control::signer_control_dir,
                record_signer_rows,
            )),
            cursor: Some(0),
        },
        Feed {
            name: "net",
            socket: crate::sandbox::control::control_socket(data_dir, pid),
            absent: "no filtering egress posture — `[network] mode` decides nothing to record",
            read: read_net_rows,
            no_record: "no record — that config had no filtering `[network] mode`, or the launch \
                        had no `[observe] record`",
            record: Some((crate::sandbox::control::control_dir, record_net_rows)),
            cursor: Some(0),
        },
        Feed {
            name: "fs",
            socket: crate::sandbox::fs_control::fs_control_socket(data_dir, pid),
            absent: "not observed — relaunch with `--observe` to record what it writes",
            read: read_fs_rows,
            no_record: "no record — the file lens did not run (`--observe`), or the launch had no `[observe] record`",
            record: Some((crate::sandbox::fs_control::fs_control_dir, record_fs_rows)),
            cursor: Some(0),
        },
        Feed {
            name: "ssh",
            socket: crate::sandbox::sshagent_control::agent_control_socket(data_dir, pid),
            absent: "no ssh-agent broker — this config has no `[ssh_agent] allow`",
            read: read_ssh_rows,
            no_record: "no record — that config granted no key (`[ssh_agent] allow`), or the launch had no `[observe] record`",
            record: Some((
                crate::sandbox::sshagent_control::agent_control_dir,
                record_ssh_rows,
            )),
            cursor: Some(0),
        },
        Feed {
            name: "broker",
            socket: crate::sandbox::broker_control::broker_control_socket(data_dir, pid),
            absent: "no broker plugin — this config has no `[broker.<name>]`",
            read: read_broker_rows,
            no_record: "no record — that config declared no `[broker.<name>]`, or the launch had no `[observe] record`",
            record: Some((
                crate::sandbox::broker_control::broker_control_dir,
                record_broker_rows,
            )),
            cursor: Some(0),
        },
        Feed {
            name: "task",
            socket: crate::sandbox::task_control::log_socket(data_dir, pid),
            absent: "no declared operations — this config has no `[task]`",
            read: read_task_rows,
            no_record: "no record — that config declared no `[task]`, or the launch had no \
                        `[observe] record`",
            record: Some((crate::sandbox::task_control::tasks_dir, record_task_rows)),
            cursor: Some(0),
        },
    ]
}

/// Width of the token column: the widest token any feed emits (`blocked`, `observe`, `exit=-1`),
/// so the verbatim subjects line up whatever mix of feeds a session has.
const TOKEN_WIDTH: usize = 8;

/// Write one merged row: a JSON object per line (so a `--follow` stream is valid NDJSON), or the
/// human row. Returns the write result so the caller ends cleanly on a closed pipe.
fn write_row(
    out: &mut dyn Write,
    session_pid: u32,
    row: &Row,
    json: bool,
    pal: &style::Palette,
) -> std::io::Result<()> {
    if json {
        let obj = serde_json::json!({
            "session_pid": session_pid,
            "at_epoch_ms": row.at_epoch_ms as u64,
            "feed": row.feed,
            "token": row.token,
            "subject": row.subject,
        });
        writeln!(out, "{obj}")
    } else {
        let (dim, r) = (pal.dim, pal.reset);
        let time = crate::format_log_time(row.at_epoch_ms);
        // The verdict tokens the decision feeds share, coloured the same way each of them colours
        // its own: a refusal must read as one at a glance in a column mixing every source.
        let hue = match row.token.as_str() {
            "allow" => pal.ok,
            "deny" | "blocked" | "error" | "refuse" | "refused" => pal.err,
            "ask" => pal.warn,
            _ => pal.dim,
        };
        writeln!(
            out,
            "  {dim}{time}{r}  {dim}{:<4}{r}  {hue}{:<TOKEN_WIDTH$}{r}  {}",
            row.feed, row.token, row.subject
        )
    }
}

/// The refusal for a merged view in which every feed that was read turned out to be absent.
///
/// `--feed` narrows the list *before* the read, so with a filter in play the unfiltered sentence
/// would state a property of the whole session on the strength of a subset of it — telling an
/// operator that a session records nothing while the very next `sbx logs` prints its egress rows.
/// The filtered wording names what was consulted and claims nothing about the rest.
fn nothing_recorded_message(pid: u32, filtered: bool, consulted: &[&str]) -> String {
    if filtered {
        return format!(
            "sbx: logs: session {pid} is not recording {}.",
            consulted.join(", ")
        );
    }
    format!("sbx: logs: session {pid} is recording nothing.")
}

/// `sbx logs [<id>] [--feed <a,b,…>] [-n <N>] [-f|--follow] [--json]`: one session's feeds,
/// interleaved in time.
///
/// This reads; it stands nothing up. Every feed it shows is one a launch already decided to run, and
/// a feed that is not running is *named* rather than passed over — an empty column and an absent one
/// look identical, and telling them apart is most of what this view is for.
pub(crate) fn run_merged(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut follow = false;
    let mut id: Option<&str> = None;
    let mut limit: Option<usize> = None;
    let mut only: Option<Vec<String>> = None;
    let mut rest = args.iter();
    while let Some(a) = rest.next() {
        match a.to_str() {
            Some("--json") => json = true,
            Some("-f") | Some("--follow") => follow = true,
            Some("-n") | Some("--lines") => match rest.next().and_then(|v| v.to_str()) {
                Some(v) => match v.parse() {
                    Ok(n) => limit = Some(n),
                    Err(_) => {
                        diag::error(&format!("sbx: logs: -n takes a count, not {v:?}"));
                        return ExitCode::from(2);
                    }
                },
                None => {
                    diag::error("sbx: logs: -n takes a count");
                    return ExitCode::from(2);
                }
            },
            Some("--feed") => match rest.next().and_then(|v| v.to_str()) {
                Some(v) => only = Some(v.split(',').map(|s| s.trim().to_string()).collect()),
                None => {
                    diag::error("sbx: logs: --feed takes a comma-separated list of feed names");
                    return ExitCode::from(2);
                }
            },
            Some(s) if !s.starts_with('-') => {
                if id.is_some() {
                    diag::error("sbx: logs: at most one session id");
                    return ExitCode::from(2);
                }
                id = Some(s);
            }
            other => {
                diag::error(&format!(
                    "sbx: logs: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!("{}", help::page_usage(&["logs"]).unwrap_or_default());
                return ExitCode::from(2);
            }
        }
    }

    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let data_dir = layout.data_dir();
    let project = match crate::config_cwd() {
        Ok(cwd) => match crate::sandbox::project_identity(&cwd) {
            Ok((_, canon)) => canon.display().to_string(),
            Err(e) => {
                diag::error(&format!("sbx: cannot resolve the project directory: {e}"));
                return ExitCode::FAILURE;
            }
        },
        Err(code) => return code,
    };
    let sessions = match live_sessions(data_dir) {
        Ok(s) => s,
        Err(code) => return code,
    };
    // Resolved through the same door one lens's view uses, so `sbx logs` and `sbx proc logs` accept
    // exactly the same ids. Every lens's directory is consulted, not just one: no single lens is the
    // one every session records — a launch with a broker and no `--observe` writes a broker record
    // and no exec record — so resolving on one directory would make such a session unnameable.
    let dirs: Vec<PathBuf> = feeds_for(data_dir, 0)
        .iter()
        .filter_map(|f| f.record.map(|(dir, _)| dir(data_dir)))
        .collect();
    let (pid, live, header, reused, ticks) =
        match resolve_source("logs", "logs", &sessions, id, &dirs, &project) {
            Ok(Source::Live { pid, header }) => (pid, true, header, false, None),
            Ok(Source::Record {
                pid, reused, ticks, ..
            }) => (
                pid,
                false,
                format!("session {pid} (ended) {project}"),
                reused,
                Some(ticks),
            ),
            Err(code) => return code,
        };

    let mut feeds = feeds_for(data_dir, pid);
    if let Some(names) = &only {
        // A name nobody answers to is a typo, and silently showing fewer feeds than asked for is the
        // one failure this view cannot afford — the reader would read absence as quiet.
        let known: Vec<&str> = feeds.iter().map(|f| f.name).collect();
        if let Some(bad) = names.iter().find(|n| !known.contains(&n.as_str())) {
            diag::error(&format!("sbx: logs: no feed named `{bad}`"));
            diag::hint(&format!("       the feeds are: {}.", known.join(", ")));
            return ExitCode::from(2);
        }
        feeds.retain(|f| names.contains(&f.name.to_string()));
    }

    // The first read is the whole retained window of every feed. A connect failure here means that
    // feed was never stood up for this session, which each feed says in its own words below.
    let mut rows = Vec::new();
    let mut absent: Vec<(&str, &str)> = Vec::new();
    // Feeds that answered but handed back no cursor: shown once, then not polled again.
    let mut unfollowable: Vec<&str> = Vec::new();
    // Records that were cut short: named once, beside the feeds that are missing entirely.
    let mut truncated: Vec<&str> = Vec::new();
    for feed in &mut feeds {
        // A running session is read from its ring, which holds what its record does and what has
        // not reached the disk yet; a finished one only exists as a file.
        let read = if live {
            (feed.read)(&feed.socket, None).map(|(batch, head, _)| (batch, head))
        } else {
            match &feed.record {
                // Every feed opens the *same* session: the incarnation was resolved once over all
                // the directories, so a pid the kernel has reused cannot hand one lens's file from
                // one session and another lens's from the next.
                Some((dir, read_record)) => {
                    match ticks.and_then(|t| {
                        crate::sandbox::lens::record_of_session(&dir(data_dir), &project, pid, t)
                    }) {
                        Some(path) => read_record(&path).map(|(batch, cut)| {
                            if cut {
                                truncated.push(feed.name);
                            }
                            // No cursor: a record nobody is writing has nothing to poll for.
                            (batch, None)
                        }),
                        None => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
                    }
                }
                None => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            }
        };
        match read {
            Ok((batch, head)) => {
                rows.extend(batch);
                feed.cursor = head;
                if head.is_none() && live {
                    unfollowable.push(feed.name);
                }
            }
            Err(_) => {
                absent.push((feed.name, if live { feed.absent } else { feed.no_record }));
                feed.cursor = None;
            }
        }
    }
    // "Recording nothing" is about feeds that did not **answer**, not about feeds that answered
    // without a cursor. A cursor is what `--follow` polls with; an older session's plane hands back
    // none and still returns its whole retained window, which the loop above has already collected.
    // Reading the missing cursor as a missing feed threw those rows away and told the reader the
    // session was recording nothing while holding its record in hand.
    if absent.len() == feeds.len() {
        let consulted: Vec<&str> = absent.iter().map(|(name, _)| *name).collect();
        diag::error(&nothing_recorded_message(pid, only.is_some(), &consulted));
        for (name, why) in &absent {
            diag::hint(&format!("       {name}: {why}"));
        }
        if only.is_some() {
            diag::hint(
                "       `--feed` narrowed the read to those; this session's other feeds were not \
                 consulted.",
            );
        }
        return ExitCode::from(2);
    }

    // Stable, so two events sharing a millisecond keep the order `feeds_for` puts them in — what the
    // agent reached for before what was decided about it.
    rows.sort_by_key(|r| r.at_epoch_ms);
    if let Some(n) = limit {
        let from = rows.len().saturating_sub(n);
        rows.drain(..from);
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    {
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if !json {
                let (h, d, r) = (pal.head, pal.dim, pal.reset);
                let answered: Vec<&str> = feeds
                    .iter()
                    .filter(|f| !absent.iter().any(|(name, _)| *name == f.name))
                    .map(|f| f.name)
                    .collect();
                writeln!(out, "{h}feeds — {header}{r}")?;
                if reused {
                    writeln!(
                        out,
                        "  {d}(more than one session recorded under pid {pid}; showing the most \
                         recent){r}"
                    )?;
                }
                writeln!(
                    out,
                    "  {d}{}: {}{r}",
                    if live { "recording" } else { "recorded" },
                    answered.join(", ")
                )?;
                for (name, why) in &absent {
                    writeln!(out, "  {d}{name}: {why}{r}")?;
                }
                // A record that outran its cap shows true events and stops early; saying which feed
                // was cut is the only thing that separates that from a session that went quiet.
                for name in &truncated {
                    writeln!(
                        out,
                        "  {d}{name}: this session outran the record's size cap; its last events \
                         are missing{r}"
                    )?;
                }
                // Said out loud rather than left to look like a quiet feed: this one answered, and
                // what it showed is the whole of what it has to say here.
                for name in &unfollowable {
                    writeln!(
                        out,
                        "  {d}{name}: shown once, not followed — this session's plane predates the \
                         cursor `--follow` needs (it was launched by an earlier sbx){r}"
                    )?;
                }
            }
            for row in &rows {
                write_row(&mut out, pid, row, json, &pal)?;
            }
            out.flush()
        })();
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
    }

    if !follow {
        return ExitCode::SUCCESS;
    }

    // A finished session was read from files nobody is writing, so there is nothing to poll and
    // nothing *ended* while this view ran. Said in the record's own words rather than falling into
    // the loop below, whose `(session … ended)` is about a socket that closed under a live read.
    if !live {
        if !json {
            let mut out = std::io::stdout().lock();
            let (dim, r) = (pal.dim, pal.reset);
            let _ = writeln!(
                out,
                "  {dim}(nothing is writing these records any more, so there is nothing to \
                 follow){r}"
            );
        }
        return ExitCode::SUCCESS;
    }

    // Nothing left to poll before the first sleep: every feed either did not answer or answered
    // without a cursor, and what was printed above is the whole of their record. Saying the session
    // ended here would report a live session as finished, so the follow declines instead.
    if let Some(end) = follow_end(&feeds, !unfollowable.is_empty()) {
        if !json {
            let mut out = std::io::stdout().lock();
            let (dim, r) = (pal.dim, pal.reset);
            let _ = writeln!(out, "  {dim}({}){r}", end.note(pid));
        }
        return ExitCode::SUCCESS;
    }

    // Follow: poll every live feed past its own cursor, sort each round together, and stop when the
    // last one ends. The feeds are independent by construction — each owns its ring and its socket —
    // so one ending is not the session ending, and dropping it while the others run on is the whole
    // reason a cursor can go `None` here rather than the loop returning.
    //
    // The round's rows are written **before** its end is acted on. A feed can lose its cursor on a
    // *successful* read that handed back rows, so returning first discarded the batch just
    // collected and closed the view with a verdict about a session whose record it was holding.
    loop {
        std::thread::sleep(FOLLOW_INTERVAL);
        let round = follow_round(&mut feeds);
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if round.evicted > 0 && !json {
                let (dim, r) = (pal.dim, pal.reset);
                let evicted = round.evicted;
                writeln!(
                    out,
                    "  {dim}({evicted} earlier event(s) evicted from a ring before this poll){r}"
                )?;
            }
            for row in &round.rows {
                write_row(&mut out, pid, row, json, &pal)?;
            }
            out.flush()
        })();
        drop(out);
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
        if let Some(end) = round.end {
            if !json {
                let mut out = std::io::stdout().lock();
                let (dim, r) = (pal.dim, pal.reset);
                let _ = writeln!(out, "  {dim}({}){r}", end.note(pid));
            }
            return ExitCode::SUCCESS;
        }
    }
}

/// Why a merged `--follow` stops: there is a difference between the feeds *ending* and their never
/// having been followable, and only one of them says anything about the session.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum FollowEnd {
    /// Every feed stopped answering — its socket was unlinked when whoever stood it up went away,
    /// which is the session ending.
    SessionEnded,
    /// A feed answered and handed back no cursor: its plane predates the append cursor `--follow`
    /// polls with, so it is read once and not followed. The session may still be running.
    NothingFollowable,
}

impl FollowEnd {
    /// The parenthetical the view closes with.
    fn note(self, pid: u32) -> String {
        match self {
            FollowEnd::SessionEnded => format!("session {pid} ended"),
            FollowEnd::NothingFollowable => {
                format!("nothing further to follow for session {pid}")
            }
        }
    }
}

/// Whether every feed has stopped carrying a cursor, and what that means — `None` while at least
/// one is still followable.
///
/// `lost_cursor` says whether any feed dropped out on a **successful** read. One that answered and
/// handed back no cursor was never followable, which is a statement about that plane rather than
/// about the session, so it must not close the view by declaring the session over.
fn follow_end(feeds: &[Feed], lost_cursor: bool) -> Option<FollowEnd> {
    if feeds.iter().any(|f| f.cursor.is_some()) {
        return None;
    }
    Some(match lost_cursor {
        true => FollowEnd::NothingFollowable,
        false => FollowEnd::SessionEnded,
    })
}

/// What one round of the merged follow produced.
struct FollowRound {
    /// The rows every polled feed handed back, merged and sorted on their own timestamps. They are
    /// carried out of the round rather than written inside it, so a round that also ends the follow
    /// cannot end it without them.
    rows: Vec<Row>,
    /// Events a ring evicted before this poll could see them, summed across the feeds.
    evicted: u64,
    /// Set when no feed is left to poll, with the reason.
    end: Option<FollowEnd>,
}

/// Poll every feed that still carries a cursor, past that cursor.
///
/// A feed drops out in two ways and they are not the same answer: a connect failure is that feed
/// ending (whoever stood it up unlinks its socket on drop, and a local UDS connect does not fail
/// transiently), while a successful read that hands back no cursor is a feed that cannot say what
/// is new and so is read once and not followed. When the last cursor goes, only the first of those
/// is the session ending.
fn follow_round(feeds: &mut [Feed]) -> FollowRound {
    let mut rows = Vec::new();
    let mut evicted = 0;
    let mut lost_cursor = false;
    for feed in feeds.iter_mut() {
        let Some(cursor) = feed.cursor else { continue };
        match (feed.read)(&feed.socket, Some(cursor)) {
            Ok((batch, head, dropped)) => {
                rows.extend(batch);
                evicted += dropped;
                lost_cursor |= head.is_none();
                feed.cursor = head;
            }
            Err(_) => feed.cursor = None,
        }
    }
    rows.sort_by_key(|r| r.at_epoch_ms);
    let end = follow_end(feeds, lost_cursor);
    FollowRound { rows, evicted, end }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vocabulary completion offers and the feeds this command actually reads are one list.
    /// Held together here because they cannot be one expression: a feed carries a socket path,
    /// and completion has no session to derive one from. A feed added to `feeds_for` and
    /// not to `FEED_NAMES` would be accepted by the CLI and offered by nothing.
    #[test]
    fn feeds_and_names_agree() {
        let built: Vec<&str> = feeds_for(Path::new("/nonexistent"), 1)
            .iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(built, FEED_NAMES);
    }

    /// `--feed` narrows the read before it happens, so the refusal that follows it may only speak
    /// for what it consulted. A session with a filtering `[network] mode` and no `--observe` is
    /// recording its egress and not its file writes: `sbx logs <pid> --feed fs` told the operator
    /// the session was recording nothing, one command before `sbx logs <pid>` printed its egress
    /// rows.
    #[test]
    fn a_filtered_read_that_found_nothing_does_not_speak_for_the_whole_session() {
        // Unfiltered, the sentence is about the session, and it is true: every feed was consulted.
        assert_eq!(
            nothing_recorded_message(4242, false, &["proc", "fs"]),
            "sbx: logs: session 4242 is recording nothing."
        );

        let filtered = nothing_recorded_message(4242, true, &["fs"]);
        assert!(
            !filtered.contains("recording nothing"),
            "a partial reading must not deliver a whole-session verdict: {filtered}"
        );
        assert!(
            filtered.contains("fs") && filtered.contains("4242"),
            "the refusal names what was consulted: {filtered}"
        );
    }

    /// A feed read that succeeds and hands back no cursor is a plane that cannot say what is new,
    /// not a feed that ended — and its rows are as good as any other's. The follow loop tested the
    /// cursors and returned before writing the batch, so the last such read had its rows discarded
    /// and closed the view with "(session ended)" for a session that was still running.
    #[test]
    fn a_round_that_ends_the_follow_still_carries_the_rows_it_just_read() {
        fn answers_without_a_cursor(
            _socket: &Path,
            _after: Option<u64>,
        ) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
            Ok((
                vec![Row {
                    at_epoch_ms: 7,
                    feed: "task",
                    token: "exit=0".to_string(),
                    subject: "sync".to_string(),
                }],
                None,
                0,
            ))
        }

        let mut feeds = vec![Feed {
            name: "task",
            socket: PathBuf::from("/nonexistent"),
            absent: "no declared operations",
            read: answers_without_a_cursor,
            no_record: "no session record",
            record: None,
            cursor: Some(0),
        }];
        let round = follow_round(&mut feeds);
        assert_eq!(round.rows.len(), 1, "the rows this round read are carried");
        assert_eq!(round.rows[0].subject, "sync");
        assert_eq!(
            round.end,
            Some(FollowEnd::NothingFollowable),
            "a plane that cannot be followed is not the session ending"
        );
        assert_eq!(
            round.end.unwrap().note(4242),
            "nothing further to follow for session 4242"
        );

        // A feed that stops answering at all *is* the session ending, and keeps that wording.
        fn refuses(
            _socket: &Path,
            _after: Option<u64>,
        ) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
        }
        let mut feeds = vec![Feed {
            name: "net",
            socket: PathBuf::from("/nonexistent"),
            absent: "no filtering egress posture",
            read: refuses,
            no_record: "no session record",
            record: None,
            cursor: Some(0),
        }];
        let round = follow_round(&mut feeds);
        assert!(round.rows.is_empty());
        assert_eq!(round.end, Some(FollowEnd::SessionEnded));
        assert_eq!(round.end.unwrap().note(4242), "session 4242 ended");

        // While one feed still carries a cursor the follow does not end, whatever the others did.
        fn answers_with_a_cursor(
            _socket: &Path,
            _after: Option<u64>,
        ) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
            Ok((Vec::new(), Some(3), 0))
        }
        let mut feeds = vec![
            Feed {
                name: "task",
                socket: PathBuf::from("/nonexistent"),
                absent: "no declared operations",
                read: answers_without_a_cursor,
                no_record: "no session record",
                record: None,
                cursor: Some(0),
            },
            Feed {
                name: "net",
                socket: PathBuf::from("/nonexistent"),
                absent: "no filtering egress posture",
                read: answers_with_a_cursor,
                no_record: "no session record",
                record: None,
                cursor: Some(0),
            },
        ];
        let round = follow_round(&mut feeds);
        assert_eq!(round.rows.len(), 1);
        assert_eq!(round.end, None);
    }
    /// A finished session is gone from `sbx session ls`, and a foreground `sbx run` never printed
    /// its pid, so this listing is the only way a record can be named. It has to carry the id and
    /// the day, and say what to type next.
    #[test]
    fn the_empty_case_lists_what_can_still_be_read() {
        let records = vec![
            crate::sandbox::lens::RecordEntry {
                pid: 148820,
                ticks: 1,
                path: PathBuf::from("/d/proc/record-148820-1.log"),
                at: std::time::UNIX_EPOCH + Duration::from_secs(1_757_376_000),
            },
            crate::sandbox::lens::RecordEntry {
                pid: 147311,
                ticks: 1,
                path: PathBuf::from("/d/proc/record-147311-1.log"),
                at: std::time::UNIX_EPOCH + Duration::from_secs(1_757_289_600),
            },
        ];
        let out = records_listing("proc logs", &records);
        assert!(out.contains("2 finished session(s)"), "{out}");
        assert!(out.contains("148820"), "{out}");
        assert!(out.contains("147311"), "{out}");
        assert!(out.contains("`sbx proc logs <id>`"), "{out}");
        // The suggestion is what the user types, so it is built from the verb and never from the
        // session-resolver's word for the command: `logs` and `ssh-agent logs` both carry `logs`
        // already, and a second one would print `sbx logs logs`.
        assert!(!out.contains("logs logs"), "{out}");
        assert!(!records_listing("logs", &records).contains("logs logs"));
        assert!(
            !records_listing("ssh-agent logs", &records).contains("logs logs"),
            "{}",
            records_listing("ssh-agent logs", &records)
        );
    }

    /// With no record either, the text names **this project**. The machine-wide sentence the
    /// live-only views use would contradict a `sbx session ls` the user may have just run: another
    /// project's session can be live while this reader has nothing at all.
    #[test]
    fn the_empty_case_names_the_project_it_is_empty_for() {
        let out = records_listing("proc logs", &[]);
        assert!(
            out.contains("proc logs: no live session in this project"),
            "{out}"
        );
        assert!(
            !out.contains("no active sandbox sessions"),
            "the machine-wide wording would deny a session `sbx session ls` still lists: {out}"
        );
        assert!(
            out.contains("`[observe] record`"),
            "and it says why there is no record to fall back on: {out}"
        );
    }

    /// With no id the scope is this project. A neighbouring project's live session is not the
    /// answer, and letting it be one costs more than a surprising header: it takes the record
    /// listing out of reach, because on a machine where any other project has a session running the
    /// empty case that makes a finished session nameable is never reached.
    #[test]
    fn with_no_id_a_neighbouring_projects_live_session_is_not_the_answer() {
        let here = PathBuf::from("/tmp/demo-app");
        let elsewhere = PathBuf::from("/tmp/other-app");
        let session = |project: &Path| crate::session::Session {
            project: project.to_path_buf(),
            pid: 4242,
            start_ticks: 7,
            kind: crate::session::Kind::Run,
            runtime: crate::session::SessionRuntime::Project,
            detached: false,
        };
        let project = here.display().to_string();

        // Standing in this project, its own live session answers.
        let mine = [session(&here)];
        assert!(matches!(
            resolve_source("logs", "logs", &mine, None, &[], &project),
            Ok(Source::Live { pid: 4242, .. })
        ));

        // A neighbour's does not: with no record here either, the answer is the empty listing.
        let theirs = [session(&elsewhere)];
        assert!(
            resolve_source("logs", "logs", &theirs, None, &[], &project).is_err(),
            "another project's session must not stand in for this project's"
        );

        // A pid given explicitly is answered whatever project it belongs to: `sbx session ls`
        // lists every live session on the machine with its project beside it, so that is a pid the
        // user was shown and chose.
        assert!(matches!(
            resolve_source("logs", "logs", &theirs, Some("4242"), &[], &project),
            Ok(Source::Live { pid: 4242, .. })
        ));
    }
}
