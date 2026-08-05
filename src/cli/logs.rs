//! The `sbx <lens> logs` view, once for the three observation lenses: the files a session writes
//! (`sbx fs logs`), the processes it execs (`sbx proc logs`), and what its ssh-agent broker decided
//! (`sbx ssh-agent logs`).
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
    /// What the session resolver calls this command, in "no live session '<id>'" and in the listing
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
