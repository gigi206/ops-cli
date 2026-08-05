//! The substrate every observation lens stands on: a bounded, in-RAM ring of stamped events, read
//! out-of-band over a per-session Unix socket.
//!
//! Three lenses are built from it — the files the cage writes ([`super::fs_control`]), the processes
//! it execs ([`super::proc_control`]), and the decisions its ssh-agent broker made
//! ([`super::sshagent_control`]). They stay deliberately independent of one another at runtime: each
//! owns its own ring and its own socket, so a failure to stand one up never takes another down. What
//! they share is *shape*, and the shape lives here.
//!
//! The two socket primitives at the bottom reach a little wider than the three rings do:
//! [`ensure_control_dir`] and [`bind_and_serve`] are also what stand up the exec supervisor's
//! notification socket and the ssh-agent broker's, neither of which is a reader's. They are the
//! mechanics of a per-session socket under the data dir, not of a lens, and each caller keeps its
//! own view of what a failure to bind one costs.
//!
//! The egress control plane ([`super::control`]) is not one of them, and folding it in here would be
//! the wrong trade: its ring keeps a separate muted ring, a second monotonic cursor for retroactive
//! amendments, captured traffic and secret sightings. That is a superset, and the three lenses that
//! never need any of it would carry the weight.
//!
//! Security is the same for all three, and it is the reason the ring is RAM and the socket is not in
//! the cage. The socket is bound under the `0700` data dir and is **never** bound into the cage: in
//! Mode B the in-cage agent is the adversary, so it must not reach the record of what it did. A ring
//! is never written to disk and never crosses the boundary; it is the supervisor's owner-only memory
//! for the session's lifetime, and it dies with it.
//!
//! The wire is line-based and minimal, one command per connection: `LOG` returns the retained events
//! (a `dropped=` line when a `--follow` cursor fell behind the ring, a `head=` cursor, then one
//! `event …` line each) then `ok`; `LOG after=<seq>` returns only events past that cursor. Every
//! lens has one field that carries arbitrary text — a path, a command line, a key comment — and it
//! is always emitted **last** and taken verbatim, so the spaces and `=` inside it can never be read
//! as a field separator. Each lens sanitises that field of control characters before it ever reaches
//! the ring, which is what stops one event from writing a second one.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The largest control command / reply line accepted — bounded so a confused or hostile peer cannot
/// make the reader buffer unboundedly. A command is short (`LOG after=<seq>`); a reply carries a
/// lens's verbatim last field, which can be long, so the bound is generous but still finite. The
/// peer is the owner-only, host-side control client.
const LINE_MAX: u64 = 8 * 1024;

/// How long a control read or write waits before giving up. The peer is trusted, so this is
/// belt-and-braces against one that is stuck rather than hostile.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// One event a lens records, and how it crosses the wire. The ring stamps the sequence number, so an
/// event only has to hand it back: that is what a `--follow` cursor is compared against, and what an
/// eviction gap is measured in.
///
/// A lens's wire line is its own — the fields differ, and so does which one is the verbatim last —
/// so the two halves live with the lens. What is shared is that they are a matched pair:
/// [`format_line`](Event::format_line) is read back by [`parse_line`](Event::parse_line), and each
/// lens pins that with a round-trip test over a value carrying spaces and an `=` of its own.
pub(crate) trait Event: Clone {
    fn seq(&self) -> u64;

    /// This event as one control-wire line, newline-terminated.
    fn format_line(&self) -> String;

    /// One wire line back into an event, or `None` if it is not a well-formed one for this lens.
    fn parse_line(line: &str) -> Option<Self>
    where
        Self: Sized;
}

/// The result of a `LOG` query: the events past the caller's cursor, how many fell off the ring
/// before that cursor (surfaced, not silently dropped — a bursty agent between `--follow` polls),
/// and the newest sequence number (the cursor to pass next time, even when `events` is empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot<E> {
    pub(crate) events: Vec<E>,
    pub(crate) dropped: u64,
    pub(crate) head: u64,
}

/// A bounded ring of recent events, newest appended, oldest evicted past `cap`. Shared (via `Arc`)
/// between whatever produces the events — a watcher thread, a supervisor, a broker's per-connection
/// threads — and the control serve thread that [`snapshot`](Ring::snapshot)s them for a reader.
/// Sequence numbers start at 1 and never repeat within a session, so a `--follow` cursor of 0 means
/// "from the beginning" and can never collide with a real event.
pub(crate) struct Ring<E> {
    inner: Mutex<Inner<E>>,
    cap: usize,
}

struct Inner<E> {
    next_seq: u64,
    events: VecDeque<E>,
}

impl<E: Event> Ring<E> {
    pub(crate) fn new(cap: usize) -> Self {
        Ring {
            inner: Mutex::new(Inner {
                next_seq: 1,
                events: VecDeque::new(),
            }),
            cap: cap.max(1),
        }
    }

    /// Append one event, assigning the next sequence number and evicting the oldest if the ring is
    /// full. `make` builds the event from the two things the ring stamps: its sequence number and
    /// the wall-clock capture time in epoch milliseconds. Returns the assigned sequence number.
    ///
    /// `make` runs **while the ring is locked**, so it must do nothing but build the event. Anything
    /// that reaches outside — announcing a refusal on the desktop, say — belongs to the caller
    /// around this call, never inside it: a lens whose notification blocked would hold the lock the
    /// reader needs to answer `sbx … logs`.
    pub(crate) fn push_with(&self, make: impl FnOnce(u64, u128) -> E) -> u64 {
        // Stamped before the lock, so a contended ring times events by when they happened rather
        // than by when they got their turn.
        let at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let mut g = self.inner.lock().unwrap();
        let seq = g.next_seq;
        g.next_seq += 1;
        g.events.push_back(make(seq, at_epoch_ms));
        while g.events.len() > self.cap {
            g.events.pop_front();
        }
        seq
    }

    /// The events past `after`, plus the eviction gap and the newest sequence. `after = None` is a
    /// tail read (the whole retained window; never reports a gap — a first read has nothing to
    /// miss); `after = Some(cursor)` is a follow read (events with `seq > cursor`, reporting how
    /// many between the cursor and the retained window were evicted unseen).
    pub(crate) fn snapshot(&self, after: Option<u64>) -> Snapshot<E> {
        let g = self.inner.lock().unwrap();
        let head = g.next_seq - 1;
        let cursor = after.unwrap_or(0);
        let events: Vec<E> = g
            .events
            .iter()
            .filter(|e| e.seq() > cursor)
            .cloned()
            .collect();
        let dropped = match (after, g.events.front()) {
            (Some(a), Some(oldest)) if oldest.seq() > a + 1 => oldest.seq() - a - 1,
            _ => 0,
        };
        Snapshot {
            events,
            dropped,
            head,
        }
    }
}

// ── The wire ──────────────────────────────────────────────────────────────────────────────────

/// Walk one `event …` line's fixed `key=value` tokens and hand back the verbatim remainder after
/// `marker`, or `None` when the line is not an event line of this shape. `field` is called once per
/// fixed token, in order; a token that carries no `=` fails the whole line rather than being skipped,
/// so a malformed head is never half-read into a plausible event.
///
/// `marker` is found by its **first** occurrence, never its last. Every fixed field precedes it, so
/// the first match is always the field marker — and a value that happens to contain the marker again
/// stays whole inside the field it landed in, instead of being cut at its own text. Reaching for
/// `rsplit_once` here would look more correct for a last field and would quietly change what a path
/// or a caller carrying the marker parses to.
pub(crate) fn read_event_line<'a>(
    line: &'a str,
    marker: &str,
    mut field: impl FnMut(&str, &str),
) -> Option<&'a str> {
    let rest = line.strip_prefix("event ")?;
    let (head, tail) = rest.split_once(marker)?;
    for token in head.split_whitespace() {
        let (key, value) = token.split_once('=')?;
        field(key, value);
    }
    Some(tail)
}

/// Answer the one command every lens shares: `LOG`, optionally `after=<seq>`. Anything else is a bad
/// request — a lens with verbs of its own (the `ask` decisions on the exec lens) matches those first
/// and falls through to here.
pub(crate) fn dispatch_log<E: Event>(cmd: &str, ring: &Ring<E>) -> String {
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
                out.push_str(&ev.format_line());
            }
            out.push_str("ok\n");
            out
        }
        _ => "err bad-request\n".to_string(),
    }
}

// ── The server (the supervisor holding the ring) ──────────────────────────────────────────────

/// Serve a lens's control socket: one short-lived thread per connection, each handling exactly one
/// command through `dispatch`. A per-connection error is that connection's problem, never the
/// server's — a reader that hangs up mid-reply must not stop the next one being answered.
pub(crate) fn serve<F>(listener: UnixListener, dispatch: F) -> io::Result<()>
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let dispatch = Arc::new(dispatch);
    for stream in listener.incoming() {
        let stream = stream?;
        let dispatch = dispatch.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, dispatch.as_ref());
        });
    }
    Ok(())
}

/// Handle one control connection: read a single command line, dispatch it, write the response, and
/// close. The socket is owner-only and host-side, so the peer is trusted; the bounded read and the
/// timeouts are belt-and-braces against a stuck or malformed caller.
fn handle(stream: UnixStream, dispatch: &dyn Fn(&str) -> String) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new((&stream).take(LINE_MAX));
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let response = dispatch(line.trim());
    (&stream).write_all(response.as_bytes())?;
    (&stream).flush()
}

// ── The client (the `sbx … logs` process) ─────────────────────────────────────────────────────

/// The per-session control socket inside a lens's own directory. One spelling of the name, because
/// three lenses write it and the egress client reads a pid back out of it.
pub(crate) fn control_socket(dir: &Path, pid: u32) -> PathBuf {
    dir.join(format!("control-{pid}.sock"))
}

/// Create a lens's control directory under the data dir, owner-only. The `0700` is the point rather
/// than a habit: the sockets inside are how a session's record is read, and in Mode B the cage must
/// not reach them.
///
/// Callers differ on what a failure means and each decides for itself — a lens stood up beside a
/// running broker degrades to no reader, while one that owns its whole directory has nowhere to put
/// anything and says so.
pub(crate) fn ensure_control_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Bind one lens's per-session control socket and serve it on a detached thread.
///
/// A stale socket left by a crashed predecessor that reused this pid is cleared first: whatever
/// guard normally unlinks it is skipped by a `SIGKILL`, so without this the next launch to land on
/// that pid would fail to bind on residue rather than on anything real.
///
/// The thread is detached and never joined. It sits blocked in `accept` for the session's life and
/// is reaped when the supervisor exits — the egress control thread has the same lifetime. What ends
/// a reader's follow cleanly is the caller unlinking the socket, not this thread stopping.
pub(crate) fn bind_and_serve(
    socket: &Path,
    serve: impl FnOnce(UnixListener) -> io::Result<()> + Send + 'static,
) -> io::Result<()> {
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    std::thread::spawn(move || {
        let _ = serve(listener);
    });
    Ok(())
}

/// Read one session's lens over its control socket (`LOG`, or `LOG after=<seq>` for a follow read
/// past a cursor). A session whose socket is absent — the lens was never stood up, or the launch is
/// dead — fails the connect, which the caller distinguishes from an empty feed.
///
/// A line the reader does not recognise is skipped rather than failing the read, so a session
/// serving a field this reader has never heard of is still readable.
pub(crate) fn read_log<E: Event>(socket: &Path, after: Option<u64>) -> io::Result<Snapshot<E>> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
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
        } else if let Some(ev) = E::parse_line(&line) {
            events.push(ev);
        }
    }
    Ok(Snapshot {
        events,
        dropped,
        head,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The least an event can be: a sequence number and nothing else. The ring's contract is about
    /// sequencing and eviction, so a lens's own fields would only be noise here — each lens tests
    /// that its `push` maps its arguments onto its own event.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestEvent {
        seq: u64,
        at_epoch_ms: u128,
        /// Stands in for whatever arbitrary text a real lens carries last — a path, a command line,
        /// a key comment.
        tail: String,
    }

    impl Event for TestEvent {
        fn seq(&self) -> u64 {
            self.seq
        }

        fn format_line(&self) -> String {
            format!(
                "event seq={} at={} tail={}\n",
                self.seq, self.at_epoch_ms, self.tail
            )
        }

        fn parse_line(line: &str) -> Option<Self> {
            let (mut seq, mut at) = (None, None);
            let tail = read_event_line(line, "tail=", |key, value| match key {
                "seq" => seq = value.parse().ok(),
                "at" => at = value.parse().ok(),
                _ => {}
            })?;
            Some(TestEvent {
                seq: seq?,
                at_epoch_ms: at?,
                tail: tail.to_string(),
            })
        }
    }

    fn push(ring: &Ring<TestEvent>) -> u64 {
        ring.push_with(|seq, at_epoch_ms| TestEvent {
            seq,
            at_epoch_ms,
            tail: String::new(),
        })
    }

    #[test]
    fn push_assigns_monotonic_seqs_and_stamps_a_capture_time() {
        let ring = Ring::new(10);
        assert_eq!(push(&ring), 1);
        assert_eq!(push(&ring), 2);
        let snap = ring.snapshot(None);
        assert_eq!(snap.head, 2);
        assert_eq!(snap.dropped, 0);
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        // The stamp is the ring's, not the caller's — an event carries a real wall-clock time.
        assert!(snap.events[0].at_epoch_ms > 0);
    }

    #[test]
    fn snapshot_after_returns_only_newer_events() {
        let ring = Ring::new(10);
        for _ in 0..5 {
            push(&ring);
        }
        let snap = ring.snapshot(Some(3));
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [4, 5]
        );
        assert_eq!(snap.head, 5);
        assert_eq!(snap.dropped, 0);
    }

    #[test]
    fn a_follow_cursor_behind_the_evicted_window_reports_the_gap() {
        // cap 3: after pushing 6, the ring holds seq 4..=6; a follow reader at cursor 1 missed 2 and 3.
        let ring = Ring::new(3);
        for _ in 0..6 {
            push(&ring);
        }
        let snap = ring.snapshot(Some(1));
        assert_eq!(
            snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [4, 5, 6]
        );
        assert_eq!(
            snap.dropped, 2,
            "seq 2 and 3 fell off before the cursor caught up"
        );
        assert_eq!(snap.head, 6);

        // A tail read over the same evicted ring never claims a gap: a first read has nothing to
        // have missed, however much fell off before it.
        let tail = ring.snapshot(None);
        assert_eq!(tail.dropped, 0);
        assert_eq!(tail.events.len(), 3);
    }

    /// A ring with no room would evict the event it was just handed, so `snapshot` could never
    /// return anything and every reader would see an empty feed. One is the floor.
    #[test]
    fn a_zero_cap_ring_still_retains_one_event() {
        let ring = Ring::new(0);
        push(&ring);
        assert_eq!(ring.snapshot(None).events.len(), 1);
    }

    /// The verbatim last field is why the wire is framed the way it is: it carries text nobody
    /// controls the shape of. It must survive spaces, an `=` of its own, and even its own marker.
    #[test]
    fn the_last_field_is_taken_verbatim_from_its_first_marker() {
        let (mut seq, mut at) = (None, None);
        let tail = read_event_line(
            "event seq=7 at=42 tail=a dir/with tail=weird =name.txt",
            "tail=",
            |key, value| match key {
                "seq" => seq = value.parse::<u64>().ok(),
                "at" => at = value.parse::<u64>().ok(),
                _ => {}
            },
        )
        .expect("a well-formed event line");
        assert_eq!((seq, at), (Some(7), Some(42)));
        assert_eq!(
            tail, "a dir/with tail=weird =name.txt",
            "cut at the FIRST marker, so the field keeps its own copy of it"
        );
    }

    #[test]
    fn a_line_that_is_not_an_event_of_this_shape_is_refused() {
        let ignore = |_: &str, _: &str| {};
        // Not an event line at all.
        assert_eq!(read_event_line("noise seq=1 tail=x", "tail=", ignore), None);
        // No such field on it.
        assert_eq!(read_event_line("event seq=1 at=2", "tail=", ignore), None);
        // A fixed token carrying no `=` fails the whole line rather than being skipped, so a
        // malformed head is never half-read into a plausible event.
        assert_eq!(
            read_event_line("event bogus seq=1 tail=x", "tail=", ignore),
            None
        );
    }

    #[test]
    fn dispatch_answers_log_with_the_framing_a_reader_expects() {
        let ring = Ring::new(3);
        for _ in 0..5 {
            push(&ring);
        }

        // A tail read: the cursor, then one line per retained event, then `ok`. No gap is claimed.
        let reply = dispatch_log("LOG", &ring);
        assert!(reply.starts_with("head=5\n"), "{reply}");
        assert!(reply.ends_with("ok\n"), "{reply}");
        assert_eq!(reply.lines().filter(|l| l.starts_with("event ")).count(), 3);

        // A follow read past an evicted cursor leads with the gap it is admitting to: the window
        // starts at seq 3, so a reader last told about seq 1 missed exactly seq 2.
        let reply = dispatch_log("LOG after=1", &ring);
        assert!(reply.starts_with("dropped=1\nhead=5\n"), "{reply}");

        assert_eq!(dispatch_log("NOPE", &ring), "err bad-request\n");
    }

    /// The whole point of the socket is that another process reads it. A live pass over a real Unix
    /// socket, since the serve/read pair is where a protocol mistake would hide.
    #[test]
    fn a_client_reads_a_lens_over_a_real_socket() {
        let dir = crate::testutil::TmpDir::new();
        let socket = dir.join("lens.sock");
        let ring = Arc::new(Ring::new(10));
        ring.push_with(|seq, at_epoch_ms| TestEvent {
            seq,
            at_epoch_ms,
            tail: "first one".to_string(),
        });
        let listener = UnixListener::bind(&socket).expect("bind");
        let served = ring.clone();
        std::thread::spawn(move || {
            let _ = serve(listener, move |cmd| dispatch_log(cmd, &served));
        });

        let snap: Snapshot<TestEvent> = read_log(&socket, None).expect("the log reads back");
        assert_eq!(snap.head, 1);
        assert_eq!(snap.events[0].tail, "first one");

        // A later event is picked up past the cursor — the `--follow` path.
        ring.push_with(|seq, at_epoch_ms| TestEvent {
            seq,
            at_epoch_ms,
            tail: "second".to_string(),
        });
        let snap: Snapshot<TestEvent> =
            read_log(&socket, Some(snap.head)).expect("the follow read");
        assert_eq!(snap.events.iter().map(|e| e.seq).collect::<Vec<_>>(), [2]);
        assert_eq!(snap.events[0].tail, "second");
    }
}
