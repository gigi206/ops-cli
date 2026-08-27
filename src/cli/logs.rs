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
use crate::{diag, help, resolve_session_target, session, store, style};

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
    /// Read the retained window, or everything past a cursor.
    pub(crate) read: fn(&Path, Option<u64>) -> std::io::Result<Snapshot<E>>,
    /// What to say when the socket is absent. This is the message that has to teach: a lens that was
    /// never stood up and a lens with nothing to report both come back empty-handed, and only this
    /// text tells them apart — so each lens says why *it* in particular might not be there.
    pub(crate) absent: fn(u32) -> String,
    /// Write one event: a JSON object per line (so a `--follow` stream is valid NDJSON), or this
    /// lens's human row. Returns the write result so the caller ends cleanly on a closed pipe.
    pub(crate) write_event:
        fn(&mut dyn Write, u32, &E, bool, &style::Palette) -> std::io::Result<()>,
}

/// `sbx <lens> logs [<id>] [-f|--follow] [--json]`. `<id>` is the PID `sbx session ls` shows; with
/// no id the sole live session is used, otherwise the live ones are listed so one can be named.
pub(crate) fn run<E>(args: &[OsString], view: &LogView<E>) -> ExitCode {
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

    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let sessions = match session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the session registry: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let target = match resolve_session_target(&sessions, id, view.session_verb) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let socket = (view.socket)(layout.data_dir(), target.pid);

    // The first read is a tail of the whole retained window. A connect failure means this lens was
    // never stood up for this session — there is no ring to read, which is a different thing from
    // an empty one, and the lens says which in its own words.
    let first = match (view.read)(&socket, None) {
        Ok(s) => s,
        Err(_) => {
            diag::error(&(view.absent)(target.pid));
            return ExitCode::from(2);
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());

    // Write the header and the tail batch through a locked, error-checked stdout: a closed
    // downstream pipe (`… | head`) ends the view cleanly (exit 0) rather than panicking on the
    // broken pipe.
    {
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if !json {
                let (h, r) = (pal.head, pal.reset);
                writeln!(
                    out,
                    "{h}{} — session {} [{}] {}{r}",
                    view.feed,
                    target.pid,
                    target.label(),
                    target.project.display()
                )?;
            }
            for e in &first.events {
                (view.write_event)(&mut out, target.pid, e, json, &pal)?;
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
                    let _ = writeln!(out, "  {dim}(session {} ended){r}", target.pid);
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
                (view.write_event)(&mut out, target.pid, e, json, &pal)?;
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
/// every poll and print the same rows again; declining to follow shows them once and says the feed
/// ended, which is the honest reading of a source that cannot tell us what is new.
type FeedRead = fn(&Path, Option<u64>) -> std::io::Result<(Vec<Row>, Option<u64>, u64)>;

/// One feed of the merged view, and where it stands.
struct Feed {
    name: &'static str,
    socket: PathBuf,
    /// Why this feed might not be there — the sentence that separates "nothing happened" from
    /// "nothing was ever watching", which is the single most misleading thing a merged view can get
    /// wrong. Each feed keeps its own wording, because the remedy differs.
    absent: &'static str,
    read: FeedRead,
    /// The cursor to read past, or `None` once this feed is gone: either it was never stood up, or
    /// it ended while the others ran on. A gone feed is never polled again.
    cursor: Option<u64>,
}

fn read_fs_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::fs_control::read_fs_log(socket, after)?;
    let rows = snap
        .events
        .into_iter()
        .map(|e| Row {
            at_epoch_ms: e.at_epoch_ms,
            feed: "fs",
            token: e.kind.token().to_string(),
            subject: e.path,
        })
        .collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

fn read_proc_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::proc_control::read_exec_log(socket, after)?;
    let rows = snap
        .events
        .into_iter()
        .map(|e| Row {
            at_epoch_ms: e.at_epoch_ms,
            feed: "proc",
            token: e.verdict,
            subject: e.command,
        })
        .collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

fn read_ssh_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::sshagent_control::read_agent_log(socket, after)?;
    let rows = snap
        .events
        .into_iter()
        .map(|e| Row {
            at_epoch_ms: e.at_epoch_ms,
            feed: "ssh",
            token: e.kind.token().to_string(),
            subject: e.detail,
        })
        .collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

fn read_broker_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::broker_control::read_broker_log(socket, after)?;
    let rows = snap
        .events
        .into_iter()
        .map(|e| Row {
            at_epoch_ms: e.at_epoch_ms,
            feed: "broker",
            token: e.kind.token().to_string(),
            subject: e.detail,
        })
        .collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

fn read_signer_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let snap = crate::sandbox::signer_control::read_signer_log(socket, after)?;
    let rows = snap
        .events
        .into_iter()
        .map(|e| Row {
            at_epoch_ms: e.at_epoch_ms,
            feed: "signer",
            token: e.kind.token().to_string(),
            subject: e.detail,
        })
        .collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

fn read_net_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    // Muted refusals and captured traffic stay out: this view is the shape of a session's activity,
    // and `sbx net logs --all --with-body` is where one request is opened up. Asking for neither
    // keeps the read cheap and the column honest about what the default egress view shows.
    let snap = crate::sandbox::control::read_log(socket, after, None, false, false)?;
    let rows = snap
        .events
        .into_iter()
        .map(|e| {
            let mut subject = format!("{}:{}", e.host, e.port);
            if let (Some(method), Some(path)) = (&e.method, &e.path) {
                subject.push_str(&format!("  {method} {path}"));
            }
            // The reason is a stable category token, never a rule's text or a secret's name — and it
            // is the whole value of a refusal line: `deny` alone does not say what to change.
            if e.verdict != crate::sandbox::control::LogVerdict::Allow {
                subject.push_str(&format!("  ({})", e.reason));
            }
            Row {
                at_epoch_ms: e.at_epoch_ms,
                feed: "net",
                token: e.verdict.as_str().to_string(),
                subject,
            }
        })
        .collect();
    Ok((rows, Some(snap.head), snap.dropped))
}

fn read_task_rows(
    socket: &Path,
    after: Option<u64>,
) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
    let (entries, head, dropped) = crate::sandbox::task_control::read_entries(socket, after)?;
    let rows: Vec<Row> = entries
        .into_iter()
        .map(|e| Row {
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
        })
        .collect();
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
            cursor: Some(0),
        },
        Feed {
            name: "signer",
            socket: crate::sandbox::signer_control::signer_control_socket(data_dir, pid),
            absent: "no signer plugin — no credential in this config declares `sign`",
            read: read_signer_rows,
            cursor: Some(0),
        },
        Feed {
            name: "net",
            socket: crate::sandbox::control::control_socket(data_dir, pid),
            absent: "no filtering egress posture — `[network] mode` decides nothing to record",
            read: read_net_rows,
            cursor: Some(0),
        },
        Feed {
            name: "fs",
            socket: crate::sandbox::fs_control::fs_control_socket(data_dir, pid),
            absent: "not observed — relaunch with `--observe` to record what it writes",
            read: read_fs_rows,
            cursor: Some(0),
        },
        Feed {
            name: "ssh",
            socket: crate::sandbox::sshagent_control::agent_control_socket(data_dir, pid),
            absent: "no ssh-agent broker — this config has no `[ssh_agent] allow`",
            read: read_ssh_rows,
            cursor: Some(0),
        },
        Feed {
            name: "broker",
            socket: crate::sandbox::broker_control::broker_control_socket(data_dir, pid),
            absent: "no broker plugin — this config has no `[broker.<name>]`",
            read: read_broker_rows,
            cursor: Some(0),
        },
        Feed {
            name: "task",
            socket: crate::sandbox::task_control::log_socket(data_dir, pid),
            absent: "no declared operations — this config has no `[task]`",
            read: read_task_rows,
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

    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let sessions = match session::Registry::at(layout.data_dir()).list() {
        Ok(s) => s,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the session registry: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let target = match resolve_session_target(&sessions, id, "logs") {
        Ok(t) => t,
        Err(code) => return code,
    };

    let mut feeds = feeds_for(layout.data_dir(), target.pid);
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
    for feed in &mut feeds {
        match (feed.read)(&feed.socket, None) {
            Ok((batch, head, _)) => {
                rows.extend(batch);
                feed.cursor = head;
                if head.is_none() {
                    unfollowable.push(feed.name);
                }
            }
            Err(_) => {
                absent.push((feed.name, feed.absent));
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
        diag::error(&format!(
            "sbx: logs: session {} is recording nothing.",
            target.pid
        ));
        for (name, why) in &absent {
            diag::hint(&format!("       {name}: {why}"));
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
                let live: Vec<&str> = feeds
                    .iter()
                    .filter(|f| f.cursor.is_some())
                    .map(|f| f.name)
                    .collect();
                writeln!(
                    out,
                    "{h}feeds — session {} [{}] {}{r}",
                    target.pid,
                    target.label(),
                    target.project.display()
                )?;
                writeln!(out, "  {d}recording: {}{r}", live.join(", "))?;
                for (name, why) in &absent {
                    writeln!(out, "  {d}{name}: {why}{r}")?;
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
                write_row(&mut out, target.pid, row, json, &pal)?;
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

    // Follow: poll every live feed past its own cursor, sort each round together, and stop when the
    // last one ends. The feeds are independent by construction — each owns its ring and its socket —
    // so one ending is not the session ending, and dropping it while the others run on is the whole
    // reason a cursor can go `None` here rather than the loop returning.
    loop {
        std::thread::sleep(FOLLOW_INTERVAL);
        let round = poll_round(&mut feeds);
        let mut batch = round.rows;
        batch.sort_by_key(|r| r.at_epoch_ms);
        let mut out = std::io::stdout().lock();
        let wrote = (|| -> std::io::Result<()> {
            if round.evicted > 0 && !json {
                let (dim, r) = (pal.dim, pal.reset);
                writeln!(
                    out,
                    "  {dim}({} earlier event(s) evicted from a ring before this poll){r}",
                    round.evicted
                )?;
            }
            for row in &batch {
                write_row(&mut out, target.pid, row, json, &pal)?;
            }
            out.flush()
        })();
        drop(out);
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
        // Only now: the round that ends the session can carry rows, and returning on the verdict
        // before the batch was written dropped them and told the reader the session had ended while
        // its last events were in hand.
        if round.all_ended {
            if !json {
                let mut out = std::io::stdout().lock();
                let (dim, r) = (pal.dim, pal.reset);
                let _ = writeln!(out, "  {dim}(session {} ended){r}", target.pid);
            }
            return ExitCode::SUCCESS;
        }
    }
}

/// What one `--follow` poll of every live feed collected.
struct Round {
    /// The events the feeds handed back, in the order the feeds were polled.
    rows: Vec<Row>,
    /// How many events a ring evicted before this read could reach them.
    evicted: u64,
    /// Every feed has ended, so this is the last round. Reported rather than acted on here,
    /// because it is true of rounds that carry rows: a feed can hand back its final events and
    /// drop its cursor in the same read (`read_task_rows` answers with rows and no head for a
    /// plane that predates the append cursor), and those rows are the reader's before the view
    /// says the session ended.
    all_ended: bool,
}

/// Poll every live feed once, past its own cursor.
///
/// A feed whose cursor is `None` is gone and is not polled again. Whoever stood a feed up unlinks
/// its socket on drop, so a connect failure after a successful read is that feed ending, not a
/// transient (a local UDS connect does not fail transiently).
fn poll_round(feeds: &mut [Feed]) -> Round {
    let mut rows = Vec::new();
    let mut evicted = 0;
    for feed in feeds.iter_mut() {
        let Some(cursor) = feed.cursor else { continue };
        match (feed.read)(&feed.socket, Some(cursor)) {
            Ok((batch, head, dropped)) => {
                rows.extend(batch);
                evicted += dropped;
                feed.cursor = head;
            }
            Err(_) => feed.cursor = None,
        }
    }
    Round {
        rows,
        evicted,
        all_ended: feeds.iter().all(|f| f.cursor.is_none()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A feed's last read can carry rows and end the feed at once, so the round reports the end
    /// instead of returning on it.
    ///
    /// `read_task_rows` answers with rows and no head for a plane that predates the append cursor,
    /// so the poll assigns `cursor = None` for a feed that just handed back events. The follow loop
    /// tested "have all feeds ended?" before it wrote the batch, so those events were dropped and
    /// the reader was told "(session ended)" while the session was still running and its last
    /// invocation had already been read.
    #[test]
    fn a_final_round_still_carries_the_rows_it_read() {
        fn last_rows(
            _socket: &Path,
            _after: Option<u64>,
        ) -> std::io::Result<(Vec<Row>, Option<u64>, u64)> {
            Ok((
                vec![Row {
                    at_epoch_ms: 7,
                    feed: "task",
                    token: "exit=0".to_string(),
                    subject: "build".to_string(),
                }],
                None,
                0,
            ))
        }
        let mut feeds = vec![Feed {
            name: "task",
            socket: PathBuf::from("/nonexistent"),
            absent: "no declared operations",
            read: last_rows,
            cursor: Some(0),
        }];
        let round = poll_round(&mut feeds);
        assert!(round.all_ended, "a feed with no cursor left is a feed gone");
        assert_eq!(
            round.rows.len(),
            1,
            "the rows read in the ending round are the reader's, not the loop's to discard"
        );
    }

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
}
