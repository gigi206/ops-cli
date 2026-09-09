//! The substrate every observation lens stands on: a bounded, in-RAM ring of stamped events, read
//! out-of-band over a per-session Unix socket.
//!
//! Five lenses are built from it — the files the cage writes ([`super::fs_control`]), the processes
//! it execs ([`super::proc_control`]), the decisions its ssh-agent broker made
//! ([`super::sshagent_control`]), what a broker plugin ruled on ([`super::broker_control`]), and what
//! a signer plugin formed for its requests ([`super::signer_control`]). They stay deliberately
//! independent of one another at runtime: each owns its own ring and its own socket, so a failure to
//! stand one up never takes another down. What they share is *shape*, and the shape lives here.
//!
//! The two socket primitives at the bottom reach a little wider than the three rings do:
//! [`ensure_control_dir`] and [`bind_and_serve`] are also what stand up the exec supervisor's
//! notification socket and the ssh-agent broker's, neither of which is a reader's. They are the
//! mechanics of a per-session socket under the data dir, not of a lens, and each caller keeps its
//! own view of what a failure to bind one costs.
//!
//! The egress control plane ([`super::control`]) is not one of them, and folding it in here would be
//! the wrong trade: its ring keeps a separate muted ring, a second monotonic cursor for retroactive
//! amendments, captured traffic and secret sightings. That is a superset, and the lenses that never
//! need any of it would carry the weight.
//!
//! Security is the same for all five, and it is the reason the socket is not in the cage. The socket
//! is bound under the `0700` data dir and is **never** bound into the cage: in Mode B the in-cage
//! agent is the adversary, so it must not reach the record of what it did. The property that carries
//! that is **unreachable from the cage**, not "never on disk": a ring is the supervisor's owner-only
//! memory for the session's lifetime, and a launch that asked for one also writes an owner-only
//! [`Recorder`] file beside the socket, under the same directory and the same rule. What crosses the
//! boundary is nothing, in either direction.
//!
//! The wire is line-based and minimal, one command per connection: `LOG` returns the retained events
//! (a `dropped=` line when a `--follow` cursor fell behind the ring, a `head=` cursor, then one
//! `event …` line each) then `ok`; `LOG after=<seq>` returns only events past that cursor. Every
//! lens has one field that carries arbitrary text — a path, a command line, a key comment — and it
//! is always emitted **last** and taken verbatim, so the spaces and `=` inside it can never be read
//! as a field separator. Each lens sanitises that field of control characters before it ever reaches
//! the ring, which is what stops one event from writing a second one.

/// The longest free-text detail an event carries. Long enough for a key comment or a command
/// line, short enough that one event cannot fill a reader's screen.
pub(crate) const DETAIL_MAX: usize = 200;

/// Strip a detail of anything that could forge a second wire line or a terminal escape, and cap
/// its length.
///
/// Every lens has one field of free text, and none of them can vouch for it: a key comment comes
/// from the user's own agent, a path from the cage, a broker plugin's label from third-party code.
/// The record of a credential channel is exactly the wrong place to trust that and be wrong, and
/// an event line whose `detail` could contain a newline would let one entry write another. The
/// same treatment serves a detail on its way to a *terminal*, which is why this lives here rather
/// than inside any one lens.
pub(crate) fn sanitize_detail(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.chars().count() > DETAIL_MAX {
        out = out.chars().take(DETAIL_MAX - 1).collect::<String>() + "…";
    }
    out
}

use crate::sandbox::locks::locked;
use std::collections::{BTreeMap, VecDeque};
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
    /// Where every pushed event is also written, when the launch asked for a record. `None` is the
    /// default and the shape every lens had before: memory for the session's lifetime, and nothing
    /// after it. See [`Recorder`].
    record: Option<Recorder>,
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
            record: None,
        }
    }

    /// Attach the session record every push is also written to, or leave the ring memory-only when
    /// the launch asked for none. A builder rather than a second constructor, the same shape the
    /// ssh-agent lens's notifier already uses, so every existing `new(cap)` stays as it is.
    pub(crate) fn with_record(mut self, record: Option<Recorder>) -> Self {
        self.record = record;
        self
    }

    /// Append one event, assigning the next sequence number and evicting the oldest if the ring is
    /// full. `make` builds the event from the two things the ring stamps: its sequence number and
    /// the wall-clock capture time in epoch milliseconds. Returns the assigned sequence number.
    ///
    /// `make` runs **while the ring is locked**, so it must do nothing but build the event. Anything
    /// that reaches outside — announcing a refusal on the desktop, say — belongs to the caller
    /// around this call, never inside it: a lens whose notification blocked would hold the lock the
    /// reader needs to answer `sbx … logs`. The session record obeys the same rule from the other
    /// side: the event is cloned out under the lock and written after it is released, so the file
    /// this push may be waiting on is never a file a reader is waiting behind.
    ///
    /// This is the single door every lens's event goes through, which is why the record is attached
    /// here rather than to each lens. Two of them have producers written apart — the exec lens's
    /// observer and its enforcer — and a duty stated once per producer is the kind the second one
    /// misses.
    pub(crate) fn push_with(&self, make: impl FnOnce(u64, u128) -> E) -> u64 {
        // Stamped before the lock, so a contended ring times events by when they happened rather
        // than by when they got their turn.
        let at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let (seq, recorded) = {
            let mut g = locked(&self.inner);
            let seq = g.next_seq;
            g.next_seq += 1;
            let event = make(seq, at_epoch_ms);
            // Cloned only when there is a record to write, and formatted below rather than here:
            // the lock this holds is the one `sbx … logs` waits on, and a `write(2)` under it would
            // put a reader behind the disk.
            let recorded = self.record.as_ref().map(|_| event.clone());
            g.events.push_back(event);
            while g.events.len() > self.cap {
                g.events.pop_front();
            }
            (seq, recorded)
        };
        if let (Some(record), Some(event)) = (&self.record, recorded) {
            record.record(&event.format_line());
        }
        seq
    }

    /// The events past `after`, plus the eviction gap and the newest sequence. `after = None` is a
    /// tail read (the whole retained window; never reports a gap — a first read has nothing to
    /// miss); `after = Some(cursor)` is a follow read (events with `seq > cursor`, reporting how
    /// many between the cursor and the retained window were evicted unseen).
    pub(crate) fn snapshot(&self, after: Option<u64>) -> Snapshot<E> {
        let g = locked(&self.inner);
        let head = g.next_seq - 1;
        let cursor = after.unwrap_or(0);
        let events: Vec<E> = g
            .events
            .iter()
            .filter(|e| e.seq() > cursor)
            .cloned()
            .collect();
        // Saturating for the same reason the task feed's twin is: `a` is parsed straight off the
        // wire with no ceiling, and `a + 1` at `u64::MAX` panics in debug and wraps in release into
        // a `dropped=` count that was never true.
        let dropped = match (after, g.events.front()) {
            (Some(a), Some(oldest)) if oldest.seq() > a.saturating_add(1) => oldest.seq() - a - 1,
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
        let stream = match stream {
            Ok(s) => s,
            // Not `?`: that ended the loop, and this runs on a detached thread, so returning closed
            // the listening fd and took every lens's control socket down with it for the rest of the
            // launch — `sbx proc logs`, `sbx fs logs` and their siblings all failing for a session
            // still running fine. The rule the doc above states ("a per-connection error is that
            // connection's problem, never the server's") is the one this broke.
            Err(e) => {
                super::conncap::accept_backoff("lens control", &e);
                continue;
            }
        };
        let dispatch = dispatch.clone();
        super::conncap::spawn_conn("lens control", move || {
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

// ── The record (what outlives the session) ────────────────────────────────────────────────────

/// The line prefixes a record file reserves for its own lines: the two identity headers a reader
/// attributes the file by, and the note a capped record ends with. No event line can collide with
/// one, because every [`Event::format_line`] opens with `event `.
pub(crate) const RECORD_RESERVED: [&str; 3] = ["project=", "app=", "truncated="];

/// The most one session's record may grow to before it stops accepting lines.
///
/// A ring is bounded by construction; a file is not, and the party that decides how many events a
/// session produces is the cage. Without a ceiling, an agent that churns short-lived processes
/// writes until the owner's disk is full — the same shape as the request-body cap on the proxy, and
/// the reason [`super::egress_stats`] bounds its destination count. Past the cap the record ends
/// with a `truncated=` line rather than silently stopping, so a reader is told the tail is missing.
pub(crate) const RECORD_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// How many finished sessions' records one lens directory keeps.
///
/// The per-file cap bounds a session; nothing bounds the number of sessions, and a record is
/// deliberately **not** swept when its session ends — that is the whole point of it. So the ceiling
/// has to be a count, applied when a new record is opened: the oldest finished records past this
/// many are removed. A running session's record is never a candidate, whatever its age.
pub(crate) const RECORD_KEEP: usize = 32;

/// One session's record file inside a lens's own directory, keyed by the session incarnation rather
/// than the pid alone. Same reason the session registry and the egress counters use the pair: a
/// later process landing on a reused pid would otherwise append into its predecessor's record and
/// the two sessions would read as one.
pub(crate) fn record_path(dir: &Path, pid: u32, start_ticks: u64) -> PathBuf {
    dir.join(format!("record-{pid}-{start_ticks}.log"))
}

/// The launcher pid a `record-<pid>-<ticks>.log` names, or `None` for any other name.
///
/// Deliberately its own parser rather than [`super::gc::sweep_runtime_dirs`]'s: that one answers
/// "may this be deleted when its session is gone", and a record's answer to that is always no. This
/// one answers "whose record is this", which is asked only to keep a *live* session's file out of a
/// prune that is otherwise ordered by age.
fn record_entry_pid(name: &str) -> Option<u32> {
    let rest = name.strip_prefix("record-")?;
    let (pid, _) = rest.split_once('-')?;
    pid.parse().ok()
}

/// Remove the oldest finished sessions' records past [`RECORD_KEEP`], newest kept.
///
/// Best-effort throughout: a directory that cannot be listed, a modification time the filesystem
/// will not report, a file that will not unlink — none of them is worth failing a launch over, and
/// each simply leaves a record in place. The one thing that is not best-effort is skipping a live
/// session: a record still being appended to must never be a candidate, whatever its age.
fn prune_records(dir: &Path, keep: usize, is_live: &dyn Fn(u32) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut finished: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let pid = record_entry_pid(name.to_str()?)?;
            if is_live(pid) {
                return None;
            }
            let at = e.metadata().ok()?.modified().ok()?;
            Some((at, e.path()))
        })
        .collect();
    if finished.len() <= keep {
        return;
    }
    // Oldest first, so the tail of the sort is what is kept.
    finished.sort_by_key(|entry| entry.0);
    for (_, path) in finished.iter().take(finished.len() - keep) {
        let _ = std::fs::remove_file(path);
    }
}

/// A lens's session record: the same lines the control wire carries, appended to an owner-only file
/// under the data dir, redacted on the way out.
///
/// This is the one thing a ring is not. A ring is bounded and dies with the session, which is right
/// for a live view and wrong for an audit: the question "what did that agent run last Tuesday" has
/// no answer once the supervisor exits. A record answers it, and the properties that make the ring
/// safe have to be carried over rather than assumed:
///
/// - **Out of the cage's reach.** The file is `0600` inside the lens's `0700` control directory,
///   which is never bound into the cage. That, not "never written down", is the property the
///   recorded party must not be able to defeat.
/// - **Redacted at the write.** Only [`super::signer_control`] redacts before its ring; the process
///   lens records the cage's own argv, which is where a credential passed on a command line lands.
///   In RAM that died with the session. On disk it would not, so the substitution happens here, for
///   every lens at once. It is against the needles known **at that moment**: a credential the launch
///   learns later cannot reach back into a line already written, which is why recording is opt-in
///   rather than the default meaning of `observe`.
/// - **Bounded.** See [`RECORD_MAX_BYTES`].
///
/// Recording is best-effort by construction: a lens that cannot open its record still stands up and
/// still serves its live reader, because a missing audit file is worth less than a missing lens.
pub(crate) struct Recorder {
    /// `None` once the record is closed — capped, or failed on a write. A closed record is never
    /// reopened: the next line would sit past a `truncated=` note and read as if nothing was lost.
    inner: Mutex<Option<OpenRecord>>,
    /// The launch's credential set, read fresh on every line. It is filled as the launch resolves
    /// secrets, so a handle taken at construction is empty and correct.
    needles: crate::sandbox::notify_sink::Needles,
}

/// The open half of a [`Recorder`]: the file and how many bytes have gone into it.
struct OpenRecord {
    file: std::fs::File,
    written: u64,
}

impl Recorder {
    /// Create a session's record, or `None` when there is nothing safe to write: an identity the
    /// header lines cannot carry ([`super::egress_stats::identity_is_recordable`]), or a file that
    /// will not open. Both are the same outcome as recording being off.
    pub(crate) fn create(
        path: &Path,
        project: &str,
        app: Option<&str>,
        needles: crate::sandbox::notify_sink::Needles,
    ) -> Option<Recorder> {
        use std::os::unix::fs::OpenOptionsExt;
        if !super::egress_stats::identity_is_recordable(project, app) {
            return None;
        }
        // Before the new file, not after: the ceiling is on what the directory holds, and opening
        // first would let a launch that fails on the write leave the directory one over.
        if let Some(dir) = path.parent() {
            prune_records(dir, RECORD_KEEP, &crate::session::pid_is_live);
        }
        let mut header = format!("project={project}\n");
        if let Some(app) = app {
            header.push_str(&format!("app={app}\n"));
        }
        // Truncating rather than appending: the path names one session incarnation, so anything
        // already there is residue from a pid the kernel reused, and appending would splice two
        // sessions' events under one header.
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .ok()?;
        file.write_all(header.as_bytes()).ok()?;
        Some(Recorder {
            inner: Mutex::new(Some(OpenRecord {
                file,
                written: header.len() as u64,
            })),
            needles,
        })
    }

    /// Append one wire line, redacted and bounded. Errors are the record's own to absorb: a lens
    /// that failed to write its audit line has still recorded the event in the ring its reader is
    /// watching, and there is no caller for whom failing the push would be the better outcome.
    ///
    /// The redaction happens **before** the file lock is taken, so a slow credential set is never
    /// held against another lens thread pushing into the same record.
    pub(crate) fn record(&self, line: &str) {
        let line = {
            let needles = crate::sandbox::locks::read_locked(&self.needles);
            crate::sandbox::redact::redact_string(
                line,
                &needles,
                &crate::sandbox::redact::Placeholder::Plain,
            )
            .0
        };
        // A line that could be read back as one of this file's own is not written at all. Nothing
        // produces one today — every `format_line` opens with `event ` — which is exactly why the
        // rule belongs here rather than in each lens: it stays true for the sixth lens too.
        if RECORD_RESERVED.iter().any(|p| line.starts_with(p)) {
            return;
        }
        let mut g = locked(&self.inner);
        let Some(open) = g.as_mut() else {
            return;
        };
        if open.written + line.len() as u64 > RECORD_MAX_BYTES {
            let _ = open.file.write_all(b"truncated=1\n");
            *g = None;
            return;
        }
        if open.file.write_all(line.as_bytes()).is_err() {
            *g = None;
            return;
        }
        open.written += line.len() as u64;
    }
}

/// One session's record read back: who it belongs to, whether its tail is missing, and the events.
///
/// Held whole in memory, which is bounded by construction: [`RECORD_MAX_BYTES`] caps the file the
/// writer produced, so the largest thing this can be is that cap plus what parsing it costs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record<E> {
    /// The `project=` header: the canonical path [`super::binds::project_identity`] derives, which
    /// is what a reader standing in a project compares against.
    pub(crate) project: String,
    /// The `app=` header, for an `sbx app <name>` launch.
    pub(crate) app: Option<String>,
    /// Whether the record ends on a `truncated=` line, meaning the session outran the cap and the
    /// tail is missing. Surfaced by the reader the way an eviction gap is, never swallowed.
    pub(crate) truncated: bool,
    pub(crate) events: Vec<E>,
}

/// Read one record file back into its events.
///
/// **The identity is the first line that states it**, the same rule
/// [`super::egress_stats`]'s reader follows and for the same reason: the writer emits both headers
/// before any event, so the first is always the real one, and honouring a later `project=` would let
/// something further down the file rename the session. What is further down is the cage's own
/// command lines. The writer already refuses to emit a line that could pass for a header
/// ([`RECORD_RESERVED`]); this closes the same hole from the read side, for a file written by any
/// version.
///
/// A line that is not a well-formed event of this lens is skipped rather than fatal: a record whose
/// last line was half-written when the machine went down still yields everything before it.
pub(crate) fn read_record<E: Event>(path: &Path) -> io::Result<Record<E>> {
    let contents = std::fs::read_to_string(path)?;
    let mut record = Record {
        project: String::new(),
        app: None,
        truncated: false,
        events: Vec::new(),
    };
    let mut named = false;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("project=") {
            if !named {
                record.project = rest.to_string();
                named = true;
            }
        } else if let Some(rest) = line.strip_prefix("app=") {
            if record.app.is_none() {
                record.app = Some(rest.to_string());
            }
        } else if line.starts_with("truncated=") {
            record.truncated = true;
        } else if let Some(event) = E::parse_line(line) {
            record.events.push(event);
        }
    }
    Ok(record)
}

/// The `project=` header alone, without parsing the events under it.
///
/// A view that lists a project's records reads one header per file, and a file may be up to
/// [`RECORD_MAX_BYTES`]. Reading them whole to compare one line would make listing cost whatever
/// the sessions spent. The scan stops at the first line that is not a header, which the writer
/// guarantees is the first event.
pub(crate) fn record_project(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    for line in BufReader::new(file).lines() {
        let line = line.ok()?;
        if let Some(rest) = line.strip_prefix("project=") {
            return Some(rest.to_string());
        }
        if !RECORD_RESERVED.iter().any(|p| line.starts_with(p)) {
            return None;
        }
    }
    None
}

/// One record file in a lens's directory, as the reader finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordEntry {
    /// The launcher pid the file is named for: what a reader passes as the session id.
    pub(crate) pid: u32,
    pub(crate) path: PathBuf,
    /// The file's modification time, which is when the session last recorded anything.
    pub(crate) at: std::time::SystemTime,
}

/// Every record in `dir`, newest first. Empty for a directory that is not there, which is what a
/// lens that never recorded anything leaves behind.
pub(crate) fn records_in(dir: &Path) -> Vec<RecordEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<RecordEntry> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let pid = record_entry_pid(name.to_str()?)?;
            Some(RecordEntry {
                pid,
                path: e.path(),
                at: e.metadata().ok()?.modified().ok()?,
            })
        })
        .collect();
    out.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.path.cmp(&b.path)));
    out
}

/// The records in `dir` that belong to `project`, newest first.
///
/// The data directory is one per user, not one per project, so a lens's directory holds every
/// project's records. A record of another project is simply **not there** for this reader: not
/// counted, not named, not hinted at. Same uid, so nothing here is a boundary — it is that a view
/// of "this project's sessions" that leaked a neighbouring project's paths would be answering a
/// question nobody asked.
pub(crate) fn records_for_project(dir: &Path, project: &str) -> Vec<RecordEntry> {
    records_in(dir)
        .into_iter()
        .filter(|e| record_project(&e.path).as_deref() == Some(project))
        .collect()
}

/// This project's records across several lenses' directories, newest first, one entry per session.
///
/// The merged view needs this because no single lens is the one every session records: a launch with
/// a broker and no `--observe` writes a broker record and no exec record, and resolving on either
/// directory alone would make such a session unnameable. A pid is listed once, at the time of its
/// newest record among the directories.
pub(crate) fn records_across(dirs: &[PathBuf], project: &str) -> Vec<RecordEntry> {
    let mut best: BTreeMap<u32, RecordEntry> = BTreeMap::new();
    for dir in dirs {
        for entry in records_for_project(dir, project) {
            best.entry(entry.pid)
                .and_modify(|kept| {
                    if entry.at > kept.at {
                        *kept = entry.clone();
                    }
                })
                .or_insert(entry);
        }
    }
    let mut out: Vec<RecordEntry> = best.into_values().collect();
    out.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.pid.cmp(&b.pid)));
    out
}

/// The record `pid` names in `dir`, and whether more than one file carried that pid.
///
/// A record is keyed by the session incarnation, but a reader only ever has the pid: it is what
/// `sbx session ls` showed and what a detached launch printed. So the pid may name more than one
/// file, once the kernel has wrapped its counter round onto it. The newest is the answer — the
/// session a user just watched end is the one they are asking about — and the second return value
/// is what lets the view *say* that a choice was made, rather than presenting one of several as the
/// only one.
///
/// The alternative, one file per pid with in-file session headers, is what `sbx session logs` does
/// for the detached log. It is the right shape there, where the writer is `>>` on a path a caller
/// named; it is the wrong one here, where the writer knows its own incarnation and a reader that
/// wants a whole session should not have to scan for its boundaries.
pub(crate) fn record_of_pid(dir: &Path, project: &str, pid: u32) -> Option<(PathBuf, bool)> {
    let matching: Vec<RecordEntry> = records_for_project(dir, project)
        .into_iter()
        .filter(|e| e.pid == pid)
        .collect();
    let newest = matching.first()?;
    Some((newest.path.clone(), matching.len() > 1))
}

/// What a launch resolves once so every lens opens its record the same way.
///
/// One value rather than five arguments, for the reason [`super::notify_sink::NotifyWiring`] is one
/// value: the parts are only correct together. The needle set must be the launch's own `Arc` — a
/// fresh one stays empty for the session and every line goes down unredacted — and the project key
/// must be the canonical identity a reader derives independently from a cwd, or the record is
/// written under a name nothing will ever ask for.
#[derive(Clone)]
pub(crate) struct RecordWiring {
    /// The launcher pid, and the incarnation it is: together they name one session, which is what
    /// keeps a pid the kernel reuses from writing into its predecessor's record.
    pid: u32,
    start_ticks: u64,
    /// The canonical project path, from [`super::binds::project_identity`] — the same derivation the
    /// egress counters key on, so a record and a reader cannot drift apart.
    project: String,
    /// The app name for an `sbx app <name>` launch, else `None`.
    app: Option<String>,
    needles: crate::sandbox::notify_sink::Needles,
}

/// Omits the needle set, which is the credential values themselves — the same reason
/// [`super::notify_sink::NotifyWiring`]'s does.
impl std::fmt::Debug for RecordWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordWiring")
            .field("pid", &self.pid)
            .field("start_ticks", &self.start_ticks)
            .field("project", &self.project)
            .field("app", &self.app)
            .field("needles", &"<redacted>")
            .finish()
    }
}

impl RecordWiring {
    /// The wiring for this supervisor's session. `needles` is cloned from the launch's set by `Arc`,
    /// never built here.
    pub(crate) fn new(
        project: String,
        app: Option<String>,
        needles: crate::sandbox::notify_sink::Needles,
    ) -> Self {
        let pid = std::process::id();
        RecordWiring {
            pid,
            // Zero for a kernel that will not report the incarnation: the name stays unique among
            // live sessions (one pid, one session) and only loses its guard against pid reuse.
            start_ticks: crate::session::read_start_ticks(pid).unwrap_or(0),
            project,
            app,
            needles,
        }
    }

    /// Open this session's record in `dir`, a lens's own control directory. `None` when there is
    /// nothing to write into — the directory would not go owner-only, or the file would not open.
    pub(crate) fn open(&self, dir: &Path) -> Option<Recorder> {
        ensure_control_dir(dir).ok()?;
        Recorder::create(
            &record_path(dir, self.pid, self.start_ticks),
            &self.project,
            self.app.as_deref(),
            self.needles.clone(),
        )
    }
}

/// [`RecordWiring::open`] for the shape every lens holds: recording off is `None`, and so is
/// recording on that could not open a file. One call at each of the six ring constructions.
pub(crate) fn open_record(wiring: Option<&RecordWiring>, dir: &Path) -> Option<Recorder> {
    wiring.and_then(|w| w.open(dir))
}

// ── The client (the `sbx … logs` process) ─────────────────────────────────────────────────────

/// The per-session control socket inside a lens's own directory. One spelling of the name, because
/// every lens writes it and the egress client reads a pid back out of it.
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
///
/// The mode is applied twice on purpose, which is what makes the `0700` a guarantee rather than an
/// intention. `DirBuilder::create` carries its mode only to a directory it actually creates: under
/// `recursive` it succeeds and changes nothing when one is already there, so a directory left
/// looser by an earlier version, a restored backup or a hand-created path would keep that mode and
/// every socket below it would be reachable by another user on the machine. The second call
/// tightens what the first found. Same bootstrap, and same reason, as
/// [`crate::plugins::ensure_owner_only`] — that one states it for the trusted-by-location trees,
/// this one for the lens sockets.
pub(crate) fn ensure_control_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
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

    /// A ring a panic has poisoned still reads AND still records.
    ///
    /// Both halves, because they fail differently and only one of them is visible. A read that
    /// panics takes down `sbx … logs` where the user is looking; a *write* that panics takes down
    /// whichever thread was recording, and the events it would have kept are simply never there —
    /// so the ring goes quiet at exactly the moment something went wrong on it. `make` runs under
    /// the lock, which is how a panic gets in here at all.
    #[test]
    fn a_ring_a_panic_poisoned_still_reads_and_still_records() {
        let ring = std::sync::Arc::new(Ring::<TestEvent>::new(8));
        ring.push_with(|seq, at_epoch_ms| TestEvent {
            seq,
            at_epoch_ms,
            tail: "before".into(),
        });

        let poisoner = std::sync::Arc::clone(&ring);
        let panicked = std::thread::spawn(move || {
            poisoner.push_with(|_seq, _at| -> TestEvent { panic!("the recorder gives up") });
        })
        .join();
        assert!(
            panicked.is_err(),
            "the fixture must actually poison the ring"
        );

        assert_eq!(
            ring.snapshot(None)
                .events
                .iter()
                .map(|e| e.tail.as_str())
                .collect::<Vec<_>>(),
            ["before"],
            "what the ring held before the panic is what it was worth keeping"
        );
        ring.push_with(|seq, at_epoch_ms| TestEvent {
            seq,
            at_epoch_ms,
            tail: "after".into(),
        });
        assert_eq!(
            ring.snapshot(None)
                .events
                .iter()
                .map(|e| e.tail.as_str())
                .collect::<Vec<_>>(),
            ["before", "after"],
            "and it goes on recording, rather than losing every event from here on"
        );
    }

    /// A control directory that already exists with a looser mode is **tightened**, not left as it
    /// was found.
    ///
    /// The mode the builder carries applies only to a directory it creates, so before the second
    /// call this passed over anything already on disk — and what sits in these directories is the
    /// socket a session's record is read through, the ssh-agent channel among them. The looser mode
    /// here is one a directory could plausibly carry from an earlier version or a restored backup.
    #[test]
    fn an_existing_control_dir_with_a_looser_mode_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = crate::testutil::TmpDir::new();
        let dir = tmp.path().join("lens");
        std::fs::create_dir(&dir).expect("plant the directory");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("loosen it the way an earlier version would have left it");

        ensure_control_dir(&dir).expect("the directory is already there, so this only tightens");

        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "a pre-existing control directory keeps its looser mode unless the call tightens it"
        );
    }

    /// The ordinary path still holds: a directory this call creates is owner-only from the start.
    #[test]
    fn a_created_control_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = crate::testutil::TmpDir::new();
        let dir = tmp.path().join("nested").join("lens");

        ensure_control_dir(&dir).expect("create it");

        let mode = std::fs::metadata(&dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    // ── The record ────────────────────────────────────────────────────────────────────────────

    fn needles(pairs: &[(&str, &str)]) -> crate::sandbox::notify_sink::Needles {
        std::sync::Arc::new(std::sync::RwLock::new(
            pairs
                .iter()
                .map(|(name, value)| {
                    crate::sandbox::proxy::SecretNeedle::named(*name, value.as_bytes().to_vec())
                })
                .collect(),
        ))
    }

    fn push_tail(ring: &Ring<TestEvent>, tail: &str) -> u64 {
        ring.push_with(|seq, at_epoch_ms| TestEvent {
            seq,
            at_epoch_ms,
            tail: tail.to_string(),
        })
    }

    /// The file a reader will look at: the identity it is attributed by, then one line per event in
    /// the order they were pushed — the same lines the control wire carries.
    #[test]
    fn a_record_is_the_identity_then_one_wire_line_per_event() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = Recorder::create(&path, "/home/u/proj", Some("demo"), needles(&[])).unwrap();
        let ring = Ring::<TestEvent>::new(10).with_record(Some(record));
        push_tail(&ring, "first");
        push_tail(&ring, "second");

        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "project=/home/u/proj");
        assert_eq!(lines[1], "app=demo");
        assert!(lines[2].starts_with("event seq=1 "), "{}", lines[2]);
        assert!(lines[2].ends_with("tail=first"), "{}", lines[2]);
        assert!(lines[3].ends_with("tail=second"), "{}", lines[3]);
        // What the ring still holds and what the file holds are the same events, which is the
        // property that lets one reader answer from either.
        assert_eq!(ring.snapshot(None).events.len(), 2);
    }

    /// The reason recording is opt-in rather than implied by `observe`. The process lens records the
    /// cage's own argv, so a credential passed on a command line reaches this writer in the clear;
    /// in RAM it died with the session, and on disk it must not survive as itself.
    #[test]
    fn a_recorded_line_is_redacted_against_the_launch_needles() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = Recorder::create(
            &path,
            "/p",
            None,
            needles(&[("API_TOKEN", "sk-abcdefghijklmnop")]),
        )
        .unwrap();
        let ring = Ring::<TestEvent>::new(10).with_record(Some(record));
        push_tail(
            &ring,
            "curl -H authorization:sk-abcdefghijklmnop https://api",
        );

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(
            !body.contains("sk-abcdefghijklmnop"),
            "the credential reached the disk verbatim: {body}"
        );
        assert!(body.contains("${API_TOKEN}"), "{body}");
        // The ring itself is untouched: it is memory the cage cannot reach, and a reader watching a
        // live session is the launch's own owner.
        assert_eq!(
            ring.snapshot(None).events[0].tail,
            "curl -H authorization:sk-abcdefghijklmnop https://api"
        );
    }

    /// The cage decides how many events a session produces, so the file needs a ceiling. Past it the
    /// record says the tail is missing rather than simply stopping, which would read as a session
    /// that went quiet.
    #[test]
    fn a_record_past_its_cap_says_so_and_writes_no_more() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = Recorder::create(&path, "/p", None, needles(&[])).unwrap();
        // Push lines until the cap is crossed. Each carries a long tail so the count stays small.
        let long = "x".repeat(DETAIL_MAX);
        let ring = Ring::<TestEvent>::new(4).with_record(Some(record));
        for _ in 0..(RECORD_MAX_BYTES as usize / DETAIL_MAX) + 2 {
            push_tail(&ring, &long);
        }

        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.ends_with("truncated=1\n"), "no truncation note");
        assert!((body.len() as u64) <= RECORD_MAX_BYTES + 32);
        let before = body.len();
        push_tail(&ring, "after the cap");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            before,
            "a closed record must not accept another line"
        );
    }

    /// The identity lines are matching keys, compared against what a reader derives on its own. A
    /// value the format cannot carry writes no record at all rather than one under a forged name —
    /// the same answer [`super::super::egress_stats`] gives for its counters, from the same rule.
    #[test]
    fn an_identity_the_header_cannot_carry_writes_no_record() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        assert!(
            Recorder::create(&path, "/p\nproject=/other", None, needles(&[])).is_none(),
            "a project name spelling a second header line must be refused"
        );
        assert!(
            !path.exists(),
            "nothing may be written for a refused identity"
        );
    }

    /// A record is deliberately not swept when its session ends, so the ceiling on the directory has
    /// to be applied when a new one is opened. A running session's record is never a candidate,
    /// whatever its age.
    #[test]
    fn opening_a_record_drops_the_oldest_finished_ones() {
        let dir = crate::testutil::TmpDir::new();
        // Three finished sessions and one still running, oldest first.
        for (i, name) in ["record-10-1.log", "record-11-1.log", "record-12-1.log"]
            .iter()
            .enumerate()
        {
            std::fs::write(dir.path().join(name), "project=/p\n").unwrap();
            let at =
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(100 + i as u64);
            filetime_set(&dir.path().join(name), at);
        }
        let live = dir.path().join("record-99-1.log");
        std::fs::write(&live, "project=/p\n").unwrap();
        filetime_set(&live, std::time::SystemTime::UNIX_EPOCH);

        prune_records(dir.path(), 1, &|pid| pid == 99);

        assert!(!dir.path().join("record-10-1.log").exists(), "oldest kept");
        assert!(
            !dir.path().join("record-11-1.log").exists(),
            "second oldest kept"
        );
        assert!(
            dir.path().join("record-12-1.log").exists(),
            "newest dropped"
        );
        assert!(
            live.exists(),
            "a live session's record must survive the prune whatever its age"
        );
    }

    /// The one line the writer must never produce: an event that could be read back as this file's
    /// own metadata. Nothing formats one today, which is why the rule lives at the single door every
    /// lens's line goes through rather than in each lens.
    #[test]
    fn a_line_that_could_pass_for_a_header_is_not_written() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = Recorder::create(&path, "/p", None, needles(&[])).unwrap();
        for reserved in RECORD_RESERVED {
            record.record(&format!("{reserved}/forged\n"));
        }
        record.record("event seq=1 at=0 tail=real\n");

        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            body, "project=/p\nevent seq=1 at=0 tail=real\n",
            "only the writer's own header may carry a reserved prefix"
        );
    }

    /// The reader's half of the round trip: what [`Recorder`] wrote is what [`read_record`] hands
    /// back, headers and all.
    #[test]
    fn a_record_reads_back_as_the_events_that_were_pushed() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        let record = Recorder::create(&path, "/home/u/proj", Some("demo"), needles(&[])).unwrap();
        let ring = Ring::<TestEvent>::new(10).with_record(Some(record));
        push_tail(&ring, "first one");
        push_tail(&ring, "second one");

        let back = read_record::<TestEvent>(&path).unwrap();
        assert_eq!(back.project, "/home/u/proj");
        assert_eq!(back.app.as_deref(), Some("demo"));
        assert!(!back.truncated);
        let tails: Vec<&str> = back.events.iter().map(|e| e.tail.as_str()).collect();
        assert_eq!(tails, ["first one", "second one"]);
        assert_eq!(back.events[0].seq, 1);
    }

    /// The identity is the **first** line that states it. The writer refuses to emit a line that
    /// could pass for a header, so this is the read side of the same rule: a record written before
    /// that refusal existed, or damaged, must not be renamable by its own contents.
    #[test]
    fn a_later_project_line_cannot_rename_a_record() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        std::fs::write(
            &path,
            "project=/real\nevent seq=1 at=1 tail=x\nproject=/forged\nevent seq=2 at=2 tail=y\n",
        )
        .unwrap();

        let back = read_record::<TestEvent>(&path).unwrap();
        assert_eq!(back.project, "/real", "a later header renamed the session");
        assert_eq!(back.events.len(), 2, "the events after it are still read");
    }

    /// A truncated record is a record: the events before the cap are true, and the reader is told
    /// the tail is gone rather than left to infer it from a feed that stops.
    #[test]
    fn a_truncated_record_reads_its_events_and_says_it_was_cut() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        std::fs::write(&path, "project=/p\nevent seq=1 at=1 tail=x\ntruncated=1\n").unwrap();

        let back = read_record::<TestEvent>(&path).unwrap();
        assert_eq!(back.events.len(), 1);
        assert!(back.truncated);
    }

    /// A half-written last line costs that line, never the file: a machine that went down mid-append
    /// still leaves everything it had already recorded.
    #[test]
    fn a_damaged_line_costs_that_line_and_nothing_else() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        std::fs::write(
            &path,
            "project=/p\nevent seq=1 at=1 tail=x\nevent seq=2 at=no\nevent seq=3 at=3 tail=z\n",
        )
        .unwrap();

        let back = read_record::<TestEvent>(&path).unwrap();
        let seqs: Vec<u64> = back.events.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, [1, 3]);
    }

    /// The data directory holds every project's records. A view of "this project's sessions" that
    /// listed a neighbouring project's would be answering a question nobody asked, so a record of
    /// another project is simply not there.
    #[test]
    fn a_record_of_another_project_is_not_listed_or_resolved() {
        let dir = crate::testutil::TmpDir::new();
        std::fs::write(dir.path().join("record-10-1.log"), "project=/mine\n").unwrap();
        std::fs::write(dir.path().join("record-11-1.log"), "project=/theirs\n").unwrap();

        let mine = records_for_project(dir.path(), "/mine");
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].pid, 10);
        assert!(record_of_pid(dir.path(), "/mine", 11).is_none());
        assert!(record_of_pid(dir.path(), "/mine", 10).is_some());
    }

    /// A pid the kernel wrapped round onto names two records. The newest is the answer — the session
    /// a user just watched end is the one they are asking about — and the second value is what lets
    /// the view say a choice was made instead of presenting one of two as the only one.
    #[test]
    fn a_reused_pid_resolves_to_the_newest_record_and_says_so() {
        let dir = crate::testutil::TmpDir::new();
        let old = dir.path().join("record-42-100.log");
        let new = dir.path().join("record-42-200.log");
        std::fs::write(&old, "project=/p\n").unwrap();
        std::fs::write(&new, "project=/p\n").unwrap();
        filetime_set(
            &old,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(100),
        );
        filetime_set(
            &new,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(200),
        );

        let (path, reused) = record_of_pid(dir.path(), "/p", 42).unwrap();
        assert_eq!(path, new);
        assert!(reused, "two records under one pid must be announced");

        let (path, reused) = record_of_pid(dir.path(), "/p", 42).unwrap();
        assert_eq!(path, new);
        assert!(reused);
        std::fs::remove_file(&old).unwrap();
        let (_, reused) = record_of_pid(dir.path(), "/p", 42).unwrap();
        assert!(!reused, "one record is not a choice");
    }

    /// Listing reads one header per file, never the events under it: a directory of full records
    /// must cost the same to list as a directory of empty ones.
    #[test]
    fn the_project_header_is_read_without_the_events() {
        let dir = crate::testutil::TmpDir::new();
        let path = dir.path().join("record-1-2.log");
        std::fs::write(&path, "project=/p\napp=demo\nevent seq=1 at=1 tail=x\n").unwrap();
        assert_eq!(record_project(&path).as_deref(), Some("/p"));

        // A file whose first line is not a header of this format names no project, so it is not one
        // of ours and is never listed as one.
        let alien = dir.path().join("record-2-2.log");
        std::fs::write(&alien, "something else\nproject=/p\n").unwrap();
        assert_eq!(record_project(&alien), None);
    }

    /// No single lens is the one every session records: a launch with a broker and no `--observe`
    /// writes a broker record and no exec record. A merged view that resolved on one directory would
    /// make that session unnameable, so the listing is the union — one entry per session, at the
    /// time of its newest record.
    #[test]
    fn records_across_lenses_list_a_session_that_only_one_of_them_saw() {
        let root = crate::testutil::TmpDir::new();
        let proc = root.path().join("proc");
        let broker = root.path().join("broker");
        std::fs::create_dir_all(&proc).unwrap();
        std::fs::create_dir_all(&broker).unwrap();
        // Session 10 recorded on both lenses; session 11 only on the broker.
        for (dir, name, at) in [
            (&proc, "record-10-1.log", 100),
            (&broker, "record-10-1.log", 200),
            (&broker, "record-11-1.log", 150),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, "project=/p\n").unwrap();
            filetime_set(
                &path,
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(at),
            );
        }

        let all = records_across(&[proc.clone(), broker.clone()], "/p");
        let pids: Vec<u32> = all.iter().map(|e| e.pid).collect();
        assert_eq!(pids, [10, 11], "newest first, one entry per session");
        assert_eq!(
            all[0].at,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(200),
            "a session is dated by its newest record among the lenses"
        );

        // Resolving on the exec directory alone would lose the broker-only session entirely.
        assert_eq!(records_for_project(&proc, "/p").len(), 1);
        assert!(record_of_pid(&proc, "/p", 11).is_none());
        assert!(record_of_pid(&broker, "/p", 11).is_some());
    }

    /// Set one file's modification time, so the prune's ordering is asserted on a known order rather
    /// than on how fast the test's own writes happen to run.
    fn filetime_set(path: &Path, at: std::time::SystemTime) {
        let secs = at
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as libc::time_t;
        let times = [
            libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
        ];
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid path and a two-element `timeval` array, as `utimes(2)` requires.
        assert_eq!(unsafe { libc::utimes(c.as_ptr(), times.as_ptr()) }, 0);
    }
}
