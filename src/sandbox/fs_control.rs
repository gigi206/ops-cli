//! The filesystem-observation control plane: a bounded, in-RAM ring of the write events the supervisor
//! observes in the cage's project tree, plus the per-session Unix socket a host-side `sbx fs logs`
//! reaches to read them.
//!
//! This is the filesystem analogue of the exec control plane in [`super::proc_control`], and the same
//! second lens over one observed session: `--observe` stands both up, and each is read independently
//! (`sbx proc logs` for the processes the agent spawns, `sbx fs logs` for the files it writes). It owns
//! its own ring and its own socket at `<data>/fs/control-<pid>.sock` rather than sharing the exec one,
//! so a failure of one lens never takes the other down.
//!
//! Security mirrors the exec control socket exactly. The socket is bound under the `0700` data dir and
//! is **never** bound into the cage: in Mode B the in-cage agent is the adversary, so it must not reach
//! the socket that records what it writes. The ring is never written to disk and never crosses into the
//! cage; it is the supervisor's owner-only RAM for the session's lifetime and dies with it.
//!
//! The wire protocol is line-based and minimal (one command per connection): `LOG` returns the retained
//! events (a `dropped=` line when a `--follow` cursor fell behind the ring, a `head=` cursor, then one
//! `event …` line each) then `ok`; `LOG after=<seq>` returns only events past that cursor. A path
//! carries spaces (and a Linux filename may even carry a newline), so it is emitted **last** on an event
//! line and taken verbatim by the reader; the watcher sanitises it of control characters, so it can
//! never inject a second line.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The default number of recent filesystem events a session retains for the live feed.
pub(crate) const FS_RING_CAP: usize = 1000;

/// The largest control command / reply line accepted — bounded so a confused or hostile peer cannot
/// make the reader buffer unboundedly. A command is short (`LOG after=<seq>`); a reply carries the
/// event's path, which can be long, so the bound is generous but still finite. The peer is the
/// owner-only, host-side control client.
const LINE_MAX: u64 = 8 * 1024;

/// The kind of filesystem change observed. A closed enum with a fixed one-word wire token, so it is a
/// safe field before the verbatim `path=` on an event line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FsKind {
    /// A file was written and closed (`IN_CLOSE_WRITE`) — the primary "the agent wrote this" signal.
    Write,
    /// A file or directory was created (`IN_CREATE`), or one moved into the tree (`IN_MOVED_TO`).
    Create,
    /// A file or directory was deleted (`IN_DELETE`).
    Remove,
    /// A path was moved out of the tree (`IN_MOVED_FROM`).
    Rename,
}

impl FsKind {
    /// The one-word wire token — also what the human and `--json` views print.
    pub(crate) fn token(self) -> &'static str {
        match self {
            FsKind::Write => "write",
            FsKind::Create => "create",
            FsKind::Remove => "remove",
            FsKind::Rename => "rename",
        }
    }

    fn from_token(s: &str) -> Option<Self> {
        match s {
            "write" => Some(FsKind::Write),
            "create" => Some(FsKind::Create),
            "remove" => Some(FsKind::Remove),
            "rename" => Some(FsKind::Rename),
            _ => None,
        }
    }
}

/// One observed filesystem event: a path in the cage's project tree that changed, as the supervisor's
/// inotify watch saw it. `path` is project-relative and already sanitised of control characters and
/// length-capped by the watcher — so it is safe to carry on the line-based wire and to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FsEvent {
    pub(crate) seq: u64,
    /// Wall-clock capture time in epoch milliseconds — a clean stamp for `--json`; the human view
    /// renders it as a local `hh:mm:ss` time.
    pub(crate) at_epoch_ms: u128,
    pub(crate) kind: FsKind,
    pub(crate) path: String,
}

impl super::lens::Event for FsEvent {
    fn seq(&self) -> u64 {
        self.seq
    }
}

/// The result of a `LOG` query over this lens. See [`super::lens::Snapshot`].
pub(crate) type FsSnapshot = super::lens::Snapshot<FsEvent>;

/// A bounded ring of recent filesystem events. Shared (via `Arc`) between the watcher thread (which
/// [`push`](FsRing::push)es) and the control serve thread (which [`snapshot`](FsRing::snapshot)s for
/// `sbx fs logs`). The sequencing and eviction are [`super::lens::Ring`]'s; what this adds is the
/// shape of a write event.
pub(crate) struct FsRing(super::lens::Ring<FsEvent>);

impl FsRing {
    pub(crate) fn new(cap: usize) -> Self {
        FsRing(super::lens::Ring::new(cap))
    }

    /// Append one observed change. `path` must already be sanitised of control characters and
    /// length-capped by the caller. Returns the assigned sequence number.
    pub(crate) fn push(&self, kind: FsKind, path: &str) -> u64 {
        self.0.push_with(|seq, at_epoch_ms| FsEvent {
            seq,
            at_epoch_ms,
            kind,
            path: path.to_string(),
        })
    }

    pub(crate) fn snapshot(&self, after: Option<u64>) -> FsSnapshot {
        self.0.snapshot(after)
    }
}

/// Serve the control socket: one short-lived thread per connection, each handling exactly one command.
/// A per-connection error is that connection's problem, never the server's. The ring is shared in (the
/// same one the watcher pushes to).
pub(crate) fn serve(listener: UnixListener, ring: Arc<FsRing>) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        let ring = ring.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &ring);
        });
    }
    Ok(())
}

/// Handle one control connection: read a single command line, dispatch it, write the response, and
/// close. The socket is owner-only and host-side, so the peer is trusted; the bound read and the
/// timeout are belt-and-braces against a stuck or malformed caller.
fn handle(stream: UnixStream, ring: &FsRing) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new((&stream).take(LINE_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim(), ring);
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

/// Map a control command to its response. `LOG` returns the retained events (a `dropped=` line when a
/// `--follow` cursor fell behind the ring, a `head=` cursor, then one `event …` line each) then `ok`;
/// `LOG after=<seq>` returns only events past that cursor. `path` is emitted last on an event line so a
/// path's spaces cannot be mistaken for a field separator (the reader takes the whole remainder).
fn dispatch(cmd: &str, ring: &FsRing) -> String {
    let mut parts = cmd.split_whitespace();
    match parts.next() {
        Some("LOG") => {
            let mut after = None;
            for token in parts {
                if let Some(v) = token.strip_prefix("after=") {
                    after = v.parse().ok();
                }
            }
            let snap = ring.snapshot(after);
            let mut out = String::new();
            if snap.dropped > 0 {
                out.push_str(&format!("dropped={}\n", snap.dropped));
            }
            out.push_str(&format!("head={}\n", snap.head));
            for ev in &snap.events {
                out.push_str(&format_event_line(ev));
            }
            out.push_str("ok\n");
            out
        }
        _ => "err bad-request\n".to_string(),
    }
}

/// Format one event as a control-wire line. The fixed fields are `key=value` tokens; `path` is emitted
/// **last** and taken verbatim by the reader (the path carries spaces). The watcher has stripped
/// control characters from the path, so it cannot inject a second line.
fn format_event_line(ev: &FsEvent) -> String {
    format!(
        "event seq={} at={} kind={} path={}\n",
        ev.seq,
        ev.at_epoch_ms,
        ev.kind.token(),
        ev.path
    )
}

// ── Client side (the `sbx fs logs` process) ───────────────────────────────────────────────────

/// The filesystem-observation control directory under the data dir, where the per-session sockets
/// live.
pub(crate) fn fs_control_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("fs")
}

/// The control socket path for a session pid.
pub(crate) fn fs_control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    fs_control_dir(data_dir).join(format!("control-{pid}.sock"))
}

/// Query one session's control socket for its filesystem events (`LOG`, or `LOG after=<seq>` for a
/// follow read past a cursor). A session whose socket is absent (not observed, or a dead/stale launch)
/// fails the connect, which the caller distinguishes from an empty log.
pub(crate) fn read_fs_log(socket: &Path, after: Option<u64>) -> io::Result<FsSnapshot> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut cmd = String::from("LOG");
    if let Some(seq) = after {
        cmd.push_str(&format!(" after={seq}"));
    }
    cmd.push('\n');
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut events = Vec::new();
    let mut dropped = 0;
    let mut head = 0;
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(v) = line.strip_prefix("dropped=") {
            dropped = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("head=") {
            head = v.parse().unwrap_or(0);
        } else if let Some(ev) = parse_event_line(&line) {
            events.push(ev);
        }
    }
    Ok(FsSnapshot {
        events,
        dropped,
        head,
    })
}

/// Parse one `event seq=… at=… kind=… path=…` line back into an event, or `None` if malformed. Every
/// field but `path` is a simple `key=value` token; `path` is the verbatim remainder after the first
/// `path=` (it carries spaces, and the fixed fields precede it, so the first `path=` is always the
/// field marker even if the path itself contains `path=`).
fn parse_event_line(line: &str) -> Option<FsEvent> {
    let rest = line.strip_prefix("event ")?;
    let (head, path) = match rest.split_once("path=") {
        Some((h, p)) => (h, p.to_string()),
        None => return None,
    };
    let (mut seq, mut at, mut kind) = (None, None, None);
    for token in head.split_whitespace() {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "kind" => kind = FsKind::from_token(value),
            _ => {}
        }
    }
    Some(FsEvent {
        seq: seq?,
        at_epoch_ms: at?,
        kind: kind?,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring's own sequencing and eviction are [`super::super::lens`]'s and tested there. What is
    /// this lens's to get right is the mapping: the arguments `push` takes must land on the fields
    /// the wire and the CLI read back.
    #[test]
    fn push_maps_its_arguments_onto_the_event() {
        let ring = FsRing::new(10);
        assert_eq!(ring.push(FsKind::Write, "src/main.rs"), 1);
        assert_eq!(ring.push(FsKind::Create, "src/new.rs"), 2);
        let snap = ring.snapshot(None);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[0].kind, FsKind::Write);
        assert_eq!(snap.events[0].path, "src/main.rs");
        assert_eq!(snap.events[1].kind, FsKind::Create);
        assert_eq!(snap.events[1].path, "src/new.rs");
    }

    #[test]
    fn an_event_line_round_trips_including_a_path_with_spaces_and_an_equals() {
        // The path carries spaces and its own `path=`/`=`; it must survive the verbatim-last framing.
        let ev = FsEvent {
            seq: 7,
            at_epoch_ms: 1_700_000_000_123,
            kind: FsKind::Rename,
            path: "a dir/with path=weird =name.txt".to_string(),
        };
        let line = format_event_line(&ev);
        let line = line.trim_end();
        assert_eq!(parse_event_line(line), Some(ev));
    }

    #[test]
    fn every_kind_round_trips_through_its_token() {
        for kind in [
            FsKind::Write,
            FsKind::Create,
            FsKind::Remove,
            FsKind::Rename,
        ] {
            assert_eq!(FsKind::from_token(kind.token()), Some(kind));
        }
        assert_eq!(FsKind::from_token("bogus"), None);
    }

    #[test]
    fn parse_rejects_a_line_without_a_path_field_or_the_prefix() {
        assert_eq!(parse_event_line("event seq=1 at=2 kind=write"), None);
        assert_eq!(parse_event_line("noise seq=1 at=2 kind=write path=x"), None);
        // An unknown kind token fails the parse rather than being silently coerced.
        assert_eq!(parse_event_line("event seq=1 at=2 kind=bogus path=x"), None);
    }

    #[test]
    fn serve_answers_a_log_query_over_a_real_socket() {
        use crate::testutil::TmpDir;
        let dir = TmpDir::new();
        let socket = dir.join("fs.sock");
        let ring = Arc::new(FsRing::new(10));
        ring.push(FsKind::Create, "src/new.rs");
        ring.push(FsKind::Write, "src/main.rs");
        let listener = UnixListener::bind(&socket).unwrap();
        let serve_ring = ring.clone();
        std::thread::spawn(move || {
            let _ = serve(listener, serve_ring);
        });

        // A tail read sees both events; a follow read past seq 1 sees only the second.
        let all = read_fs_log(&socket, None).unwrap();
        assert_eq!(all.events.len(), 2);
        assert_eq!(all.head, 2);
        assert_eq!(all.events[1].path, "src/main.rs");
        assert_eq!(all.events[1].kind, FsKind::Write);

        let tail = read_fs_log(&socket, Some(1)).unwrap();
        assert_eq!(tail.events.iter().map(|e| e.seq).collect::<Vec<_>>(), [2]);
    }
}
