//! The task control plane: the per-session socket a caller **inside** the cage reaches to list and
//! invoke declared operations, plus a second, host-only socket carrying the invocation log and the
//! live control of what is running.
//!
//! # Two sockets, on purpose
//!
//! Every other control plane in sbx (egress, `proc`, `fs`) is **never** bound into the cage, because
//! the in-cage agent is the adversary and must not answer its own asks. This one has to cross — an
//! agent that cannot reach it cannot invoke a task at all. So the surface that crosses is kept as
//! small as it can be (`LIST`, `SECRETS`, `RUN`), and everything else lives on a second socket that
//! stays host-only. What a session recorded is for the human, and the recorded party does not get to
//! read (or trim) it; what a session is *running* is for the human too, because an invocation id is
//! per session and a cage reaching those verbs could watch and end an invocation the human started.
//! Same-uid leaves no way to tell the two callers apart, so the socket does it.
//!
//! # The residual to be honest about
//!
//! Same-uid gives no per-process identity, so the crossing socket's authority is the **cage's**, not
//! the agent's: any process in the cage — including a subprocess of whatever the agent spawned — can
//! invoke a task. That is why what bounds a task is its fixed program and its bounded parameters,
//! not who is calling.
//!
//! # Wire protocol
//!
//! Line-based with **length-prefixed payloads**, one command per connection. A parameter value is
//! arbitrary text (SQL with newlines, a JSON body), so it is never squeezed onto a line:
//!
//! ```text
//! → LIST                          ← task <name>\tparams=a,b\tdeclared-in=<where>\t<desc>… `ok`
//! → SECRETS                       ← secret <name>\t<where>\t<description>… then `ok`
//! → RUN <name>                    ← id <n>, exit <code>, redacted <n>, truncated <0|1>,
//!   param <key> <len>\n<bytes>       timed-out <0|1>, stopped <0|1>, elapsed-ms <n>,
//!   env <key> <len>\n<bytes>         [nonce <hex>], [refused-exec <path>…],
//!   run                              [output <bytes> <path>], stdout <len>\n<bytes>,
//!                                    stderr <len>\n<bytes>, then `ok`
//!                                  — or `id <n>` then `err <reason>`, which ends the answer. An
//!                                    `id` there means the request was admitted and the refusal is
//!                                    in the log under that number; no `id` means it never was.
//! ```
//!
//! And on the host-only socket:
//!
//! ```text
//! → LOG [after=<cursor>]          ← [dropped=<n>], head=<cursor>, event seq=<id> cur=<cursor> ……
//!                                    then `ok`. `after`/`head` are **append order**, never an
//!                                    invocation id — see `TaskLog::since` for why the two must not
//!                                    be confused. A reply with no `head=` is a plane that predates
//!                                    the cursor and must not be followed.
//! → STATUS                        ← running <id>\ttask=<name>\telapsed_ms=<n>…  then `ok`
//! → STOP <id>                     ← stopped <id> | stopping <id> | finished <id>, then `ok`
//! → DETACH <name>                 ← id <n>, then `ok` — or `err <reason>`
//!   param/env payloads, then run
//! → RESULT <id>                   ← the same shape a `RUN` answers with, or `err <reason>`
//! → INFO <id-or-name>             ← field <key>\t<value>… then `ok`, or `err <reason>` — a live
//!                                    invocation's state and declaration, a finished one's log
//!                                    entry and the declaration it ran under, or an operation's
//!                                    declaration alone
//! ```
//!
//! `DETACH` and `RESULT` are on **this** socket rather than the crossing one, and that placement is
//! the access control. A detached invocation is one nobody is waiting for, so it can only be watched,
//! stopped and collected through the host-only verbs — putting the start of it within reach of a cage
//! would let a caller create invocations it cannot then see or end, and let it hold several at once,
//! which having to wait is what prevents today. It is also why `RUN` is not merely given a flag: the
//! crossing socket has no way to tell a host caller from an in-cage one.
//!
//! Any refusal is a single `err <message>` line. A message never echoes a caller's value back: a
//! value can carry the very secret a caller is probing for.

use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::task::{TaskEngine, TaskOutcome};
use crate::sandbox::locks::locked;

/// Where the crossing socket is bound **inside** the cage. Under `/tmp`, beside the egress socket,
/// colliding with no structural mount. Bound as the socket *file* (never its directory), so a caller
/// can connect through it but cannot unlink it and put its own listener in its place.
pub(crate) const CAGE_TASK_UDS: &str = "/tmp/sbx-task.sock";

/// The environment variable that tells an in-cage tool the task plane is available, and where. The
/// discovery handle, like `SBX_EGRESS_CONTRACT` for the egress contract.
pub(crate) const TASK_SOCKET_ENV: &str = "SBX_TASK_SOCKET";

/// Where the task client is bound read-only inside the cage. Under `/opt/sbx`, beside the egress
/// contract and the mise plugin.
///
/// What sits there is **not** the sbx binary: it is a generated script that can express the three
/// declared-operation verbs and nothing else (see [`super::task_shim`]). The path keeps sbx's name
/// so an invocation reads the same inside the cage as on the host, but the surface behind it is
/// three commands, and the policy stays host-side across the socket.
pub(crate) const TASK_SHIM_INCAGE: &str = "/opt/sbx/bin/sbx";

/// How many invocations a session retains in its log ring.
const LOG_CAPACITY: usize = 512;

/// How many detached results a session holds for collection.
///
/// Smaller than the log ring on purpose: a log entry is a line, while a result carries both streams,
/// each already bounded by the task's `max_output`. Comfortably above the number that can be produced
/// between two collections, since only [`super::task::MAX_DETACHED`] can run at once.
const RESULT_CAPACITY: usize = 32;

/// The default ceiling on invocations per session — a task is a brokered operation, not a loop
/// primitive, and an exit-status oracle over a credential gets cheaper the more calls it can make.
/// Reaching it refuses further invocations rather than degrading anything silently.
const DEFAULT_CALL_QUOTA: u64 = 500;

/// The most one payload may carry: bounded well above any legitimate parameter and far below
/// anything that would matter.
const MAX_PAYLOAD_BYTES: usize = 1 << 20;

/// A ceiling on live connections, applied to both of the plane's sockets.
///
/// Each connection is served on its own thread, and one serving a `RUN` holds that thread for as
/// long as the task's timeout allows: without a ceiling, a caller opening connections in a loop
/// spawns host threads until the process cannot make another. It was the only accept loop in the
/// binary without one, of four.
///
/// The same number the broker applies, and for the same situation: a socket bound host-side,
/// reachable from the cage, with a host resource on the other end. What crosses it is a handful of
/// calls from an agent, so the ceiling is far above use and far below exhaustion.
///
/// A refusal here is **not** recorded in the invocation log, and that is deliberate: the log is a
/// 512-entry ring, so a flood of refused connections would evict the invocation history the ring
/// exists for, which is the very thing a caller unable to connect would want to read.
const MAX_CONCURRENT_CONNS: usize = 32;

/// How long the crossing socket waits for a connection to say what it wants.
///
/// A connection is accepted, given a host thread and one of [`MAX_CONCURRENT_CONNS`] slots before
/// the cage has said a word, and this socket set no read deadline at all: 32 connections that
/// connect and then stay silent held every slot of the plane for the rest of the session, refusing
/// every later caller with nothing recorded anywhere — [`MAX_CONCURRENT_CONNS`] itself says a
/// refused connection is deliberately not logged. Both brokers whose sockets cross into the cage
/// bound their first message for exactly this (`sshagent`'s `CAGE_FIRST_MESSAGE`, `broker`'s
/// `CAGE_FIRST_FRAME`); this was the plane that did not.
///
/// It bounds the whole request rather than only its first line. `RUN` is followed by its payloads,
/// so a budget lifted at the command line would move the wait one line down and no further. It ends
/// at the `run` terminator because nothing is read after it: what follows is the invocation, which
/// legitimately holds this connection for as long as the task's own timeout allows.
///
/// Thirty seconds, the number both brokers chose and for their reason: a client connected because
/// it had something to send, so a pause before it sends is slack rather than need.
const CAGE_FIRST_REQUEST: std::time::Duration = std::time::Duration::from_secs(30);

/// The most one request may make sbx hold, keys and values together, before anything about it has
/// been validated. Held literally: [`read_payloads`] refuses a payload that is not valid UTF-8
/// rather than expanding it, so what a field is charged is what a field costs.
///
/// The per-payload ceiling alone does not bound a request: a caller sending a thousand empty
/// payloads costs nothing per payload and a map entry each time. So what is bounded is the whole
/// request — each field's own request line, framing included, plus its payload — which bounds the
/// count as a consequence rather than by a second number. The line rather than the key, because a
/// key is only what grows while a caller supplies one, and a field naming nothing is still a field.
///
/// Eight payloads at the ceiling. A choice rather than a derivation, and the trigger for revisiting
/// it is a task legitimately refused for it: a task declaring eight megabytes of parameters is not
/// one this bound is in the way of.
const MAX_REQUEST_BYTES: usize = 8 * MAX_PAYLOAD_BYTES;

/// Read one request line, or `None` when the peer closed cleanly.
///
/// The reading is [`super::broker::read_bounded_line`], the same one the broker and signer
/// protocols use, because the property is the same one: sbx buffers a line before it can bound
/// anything inside it, so a peer that never writes a newline is a peer taking host memory. It
/// matters more here than there. The plugin protocols talk to a process sbx started; this socket is
/// bound host-side and mounted into the cage, and the thread reading it belongs to the sbx process,
/// **outside** the cgroup bounding the cage's own memory.
///
/// A clean close is `None` rather than an error: on this protocol a peer that has said everything
/// hangs up, and that is not a fault.
///
/// Generic over the reader rather than taking the socket's `BufReader` itself, so a caller can put
/// a [`super::deadline::Deadlined`] budget in front of it. [`serve_cage`] does, over the whole of a
/// request: a socket's receive timeout bounds one `read`, and this protocol reads a request in as
/// many pieces as its sender chooses to send it in.
fn read_request_line(reader: &mut impl io::BufRead) -> io::Result<Option<String>> {
    match super::broker::read_bounded_line(reader, MAX_PAYLOAD_BYTES as u64) {
        Ok(line) => Ok(Some(line)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

/// One recorded invocation. The command is **not** recorded — it is fixed by the declaration, so the
/// task name identifies it — and no parameter value is recorded either: a value can carry a secret,
/// and the point of the log is who ran what, when, and what it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEntry {
    /// The **invocation's id** — the same number `sbx task status` shows while it runs and
    /// `sbx task stop` takes, not a counter of its own. Drawn when the invocation was admitted, so
    /// two overlapping invocations appear here in the order they *finished* and their ids can
    /// therefore read out of order. `0` marks an entry no invocation stands behind: a request
    /// refused before it was admitted at all.
    pub(crate) seq: u64,
    /// Where this entry sits in **append order**, stamped by [`TaskLog::push`]. This — not
    /// [`seq`](LogEntry::seq) — is what a `--follow` cursor compares against, and the two must not be
    /// confused: an id is drawn when an invocation is *admitted* and its entry lands when it
    /// *finishes*, so a long invocation admitted before a short one is recorded after it. A cursor
    /// over ids would step past the short one and never show the long one. A cursor over append
    /// order cannot, because it is assigned at the moment of the append.
    pub(crate) cursor: u64,
    /// Wall-clock time in epoch **milliseconds** when the invocation finished. Milliseconds, and
    /// named like the other feeds' stamp ([`crate::sandbox::fs_control::FsEvent::at_epoch_ms`] and
    /// its peers), because these records are read side by side with them: one unit and one name
    /// across the feeds is what keeps a merged, time-ordered view from quietly misplacing a row.
    pub(crate) at_epoch_ms: u128,
    /// Wall-clock epoch milliseconds when the invocation *began* — [`at_epoch_ms`](LogEntry::at_epoch_ms)
    /// less its duration, settled by [`TaskLog::push`]. Recorded rather than derived by each reader
    /// because it is what orders this record against the other feeds: an entry is written when an
    /// invocation ends, so sorting on the finish would file a slow invocation after everything that
    /// ran during it. Equal to the finish for a refusal, which never ran.
    pub(crate) started_epoch_ms: u128,
    pub(crate) task: String,
    pub(crate) exit: i32,
    /// Substitutions across **both** streams, including one the declaration withheld from the
    /// caller. This log never crosses into a cage, so it is the one place the question "did the
    /// credential reach the output" can be answered whether or not the caller was shown the output
    /// — and answering it is the point of keeping the log host-side.
    pub(crate) redacted: usize,
    pub(crate) truncated: bool,
    pub(crate) timed_out: bool,
    /// Whether `sbx task stop` ended it — recorded separately from `timed_out` because they are
    /// different events with the same effect.
    pub(crate) stopped: bool,
    pub(crate) elapsed_ms: u64,
    /// A refusal reason, when the invocation never ran.
    pub(crate) refused: Option<String>,
    /// Whether it ran detached. Recorded because it is what makes the entry answerable later: a
    /// detached result is held for collection and can fall out of that ring, and "it was dropped to
    /// make room" is a different answer from "no such invocation" — this field is what tells them
    /// apart once the result itself is gone.
    pub(crate) detached: bool,
}

impl LogEntry {
    /// One `event …` line, for the log socket. Fixed fields first; the optional refusal reason is
    /// **last** and taken verbatim by the reader, since it is the only free-text field of the two
    /// that end up on this line. The other is the task name, which the cage chooses and which sits
    /// among the head's `key=value` tokens — [`head_field`] is what keeps it inside one of them.
    fn to_line(&self) -> String {
        let mut line = format!(
            "event seq={} cur={} at={} started={} exit={} redacted={} truncated={} timed_out={} \
             stopped={} detached={} elapsed_ms={} task={}",
            self.seq,
            self.cursor,
            self.at_epoch_ms,
            self.started_epoch_ms,
            self.exit,
            self.redacted,
            u8::from(self.truncated),
            u8::from(self.timed_out),
            u8::from(self.stopped),
            u8::from(self.detached),
            self.elapsed_ms,
            // The one head field the cage names. `sanitize` bounds it and strips its control
            // characters; `head_field` is what keeps it inside its own token, since the characters
            // that break a head parse — a space, an `=` — are not control characters and sanitising
            // a newline *produces* one of them.
            head_field(&sanitize(&self.task)),
        );
        if let Some(reason) = &self.refused {
            line.push_str(&format!(" refused={}", sanitize(reason)));
        }
        line
    }

    /// Read one `event …` line back, or `None` for anything else (the `ok`, a `head=`, a line from a
    /// plane that predates a field).
    ///
    /// Placed beside [`to_line`](LogEntry::to_line) deliberately, the way each observation lens keeps
    /// its own pair together: the two halves share one format, and a change to the writer that the
    /// reader does not follow does not fail loudly — it drops entries, or files them at the wrong
    /// time, in the record whose whole job is to miss nothing. A round-trip test pins them.
    ///
    /// The refusal reason is split off **first**, exactly as the writer appends it last: it is the
    /// one free-text field, so everything after ` refused=` is its value, spaces and `=` included.
    pub(crate) fn from_line(line: &str) -> Option<LogEntry> {
        let event = line.strip_prefix("event ")?;
        let (head, refused) = match event.split_once(" refused=") {
            Some((head, reason)) => (head, Some(reason.to_string())),
            None => (event, None),
        };
        let mut fields: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for (key, value) in head.split_whitespace().filter_map(|f| f.split_once('=')) {
            // The **first** occurrence of a key wins, where `collect()` kept the last. The writer
            // emits each key once and in a fixed order, so a repeat can only be a value that
            // escaped its own field — and preferring the later one is preferring the forgery.
            // [`head_field`] keeps such a value off the wire in the first place; this is the
            // reader's own half of it, so a plane older than that encoder is still read honestly.
            fields.entry(key).or_insert(value);
        }
        // Generic over the field's own type: these are four different integers (a `u128` stamp, a
        // `u64` id, an `i32` exit, a `usize` count) and each must parse as what it is.
        fn num<T: std::str::FromStr>(
            fields: &std::collections::BTreeMap<&str, &str>,
            key: &str,
        ) -> Option<T> {
            fields.get(key)?.parse().ok()
        }
        let flag = |key: &str| fields.get(key).copied() == Some("1");
        let at_epoch_ms = epoch_ms(num(&fields, "at")?);
        Some(LogEntry {
            seq: num(&fields, "seq")?,
            // Zero for a plane that predates the append cursor. The entry is still worth showing —
            // it has a stamp, so it can be placed — and it is the *reader* that must then decline to
            // follow, since a cursor of zero asks such a plane for everything, every poll.
            cursor: num(&fields, "cur").unwrap_or(0),
            at_epoch_ms,
            // A plane that predates the start stamp sends no `started=`; falling back to the finish
            // is the honest reading — it is where such an entry has always been placed — and it
            // keeps one missing field from dropping the whole entry.
            started_epoch_ms: num(&fields, "started").map(epoch_ms).unwrap_or(at_epoch_ms),
            task: fields.get("task").copied().unwrap_or_default().to_string(),
            exit: num(&fields, "exit")?,
            redacted: num(&fields, "redacted").unwrap_or(0),
            truncated: flag("truncated"),
            timed_out: flag("timed_out"),
            stopped: flag("stopped"),
            elapsed_ms: num(&fields, "elapsed_ms").unwrap_or(0),
            refused,
            detached: flag("detached"),
        })
    }
}

/// Read a wire stamp as epoch milliseconds, accepting the seconds an older plane sends.
///
/// The `at=` field carried Unix **seconds** before the feeds were brought to one unit. Both halves of
/// this wire ship in the same binary, so they normally agree — but a session outlives the binary that
/// launched it, and rebuilding sbx while one is running leaves a new reader asking an old plane.
/// Without this it would render a 2026 stamp as a day in 1970: not a crash, just a wrong answer, in
/// the field a merged view sorts on.
///
/// The boundary is unambiguous and stays so: epoch milliseconds passed 10^12 in 2001, and epoch
/// seconds do not reach it until the year 33658.
pub(crate) fn epoch_ms(value: u128) -> u128 {
    const MILLIS_SINCE_2001: u128 = 1_000_000_000_000;
    match value < MILLIS_SINCE_2001 {
        true => value * 1000,
        false => value,
    }
}

/// Flatten a value into one safe log field.
///
/// [`super::sanitize`] itself — the crate's one answer to a value the cage chooses. It maps control
/// characters (a newline that would forge a second event line, an escape that would drive a
/// terminal) to spaces **and bounds the result**, and it is the bound this module used to be missing
/// by having a copy that only did the first half.
///
/// The task name arrives as the tail of a `RUN <name>` request line, which `read_bounded_line`
/// limits only to [`MAX_PAYLOAD_BYTES`] — a mebibyte. A name matching nothing becomes
/// `TaskError::Unknown(name)`, whose `Display` embeds it again, and `serve_run` stores both the name
/// and that reason in a `LogEntry`. So one refused request pinned about 2 MiB of caller-chosen host
/// memory, and [`LOG_CAPACITY`] bounds the ring at 512 *entries* rather than bytes: a cage could
/// hold roughly a gibibyte in the supervisor by asking for tasks that do not exist, in a log it
/// cannot read and nothing else evicts.
///
/// Applied where an entry is **built** as well as where one is rendered. Sanitising only on the way
/// out, which is what `to_line` did, leaves the raw bytes sitting in the ring — which is the thing
/// being bounded.
fn sanitize(text: &str) -> String {
    super::sanitize(text)
}

/// Make a value safe to occupy one whitespace-split `key=value` token of an `event …` line's
/// **head**.
///
/// [`sanitize`] is not that, and cannot be: it maps every control character to a **space**, which
/// is the separator the head is split on, and it leaves `=` alone. `task=` is the last head field
/// and the task name is whatever the cage put after `RUN `, so a name spelling
/// ` exit=0 stopped=0` rewrote the very fields of the row recording that the invocation was
/// refused — [`LogEntry::from_line`] parses the head with `split_whitespace()` then
/// `split_once('=')` — and a name spelling ` refused=…` took the free-text tail as well, since the
/// reader splits at the *first* ` refused=` it finds. The row is the human's record of what the
/// cage asked for, and the cage does not get to write the rest of it.
///
/// The same two characters [`super::proc_control`]'s `head_token` replaces, for the same reason and
/// at the same price: a legitimate name carrying a space renders with an underscore, which is a
/// name this head could not have carried either way.
fn head_field(text: &str) -> String {
    text.chars()
        .map(|c| match c.is_whitespace() || c == '=' {
            true => '_',
            false => c,
        })
        .collect()
}

/// The session's bounded, in-RAM invocation log. Never written to disk and never readable from the
/// cage — it is the supervisor's own record for the session's lifetime, and it dies with it.
///
/// # The lock recovers from a poisoning, and its critical sections are what make that sound
///
/// Every method here takes the lock through [`crate::sandbox::locks::locked`], which hands back what
/// the lock was guarding rather than propagating a previous holder's panic. This is the recovering
/// class that module names: an entry that is not appended is gone, a record that silently loses
/// entries is the one failure this ring exists to prevent, and `sbx task status` reading through a
/// second panic would destroy the record instead of reporting it.
///
/// Recovering is sound only because no critical section here can leave the data half-written, and
/// none of them can unwind at all. Enumerated, because that is the only way to know it: stamping a
/// time (`duration_since` is matched, `saturating_sub` cannot overflow), counting, pushing and
/// popping a `VecDeque`, and cloning entries out of it. No indexing, no slicing, no arithmetic that
/// can overflow, no `unwrap` on anything fallible, and nothing that calls out. So a poisoned guard
/// holds a `VecDeque` that is valid, at worst without the entry that was being appended.
///
/// What would break it: moving fallible or panicking work **inside** a guard — a helper called with
/// the lock held, a slice index, an `unwrap`. Keep the work outside and hold the lock only for the
/// container operation, which is what every method here does. Taking the lock any other way — an
/// `unwrap`, an `expect`, a degrade to `.ok()` — would re-decide here a question
/// [`crate::sandbox::locks`] decides once for the whole program.
#[derive(Default)]
pub(crate) struct TaskLog {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    entries: std::collections::VecDeque<LogEntry>,
    /// How many entries have ever been appended — the source of every entry's
    /// [`cursor`](LogEntry::cursor), and therefore the head a reader is handed to come back with.
    /// Counted rather than read off the last entry so that an eviction cannot walk it backwards.
    appended: u64,
}

impl TaskLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record one invocation, evicting the oldest when the ring is full.
    ///
    /// The entry arrives carrying its own id — the invocation's, drawn when it was admitted. The log
    /// stamps the times and the append order, the fields it is the authority on: an invocation that
    /// ran under a credential does not get to say when it finished, nor where it sits in the record
    /// of what finished before it.
    ///
    /// `started_epoch_ms` is settled here too, once, rather than left for each reader to work out
    /// from the finish and the duration. It is the stamp a time-ordered view sorts on — an
    /// invocation belongs where it *began*, not where it happened to end, or a slow one reads as
    /// having been provoked by whatever ran while it was still going.
    fn push(&self, mut entry: LogEntry) {
        let mut inner = locked(&self.inner);
        entry.at_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        entry.started_epoch_ms = entry
            .at_epoch_ms
            .saturating_sub(u128::from(entry.elapsed_ms));
        inner.appended += 1;
        entry.cursor = inner.appended;
        if inner.entries.len() == LOG_CAPACITY {
            // No lifetime eviction counter is kept: what a reader is told is the gap between its
            // own cursor and the window it is handed, which `since` computes from the oldest entry
            // still held. A running total answers a question nobody asks here.
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);
    }

    /// The retained entries past `after`, how many fell out of the ring, and the head to come back
    /// with.
    ///
    /// `after` is a cursor over **append order**, not over invocation ids. The distinction is the
    /// whole correctness of following this log: an id is drawn when its invocation is *admitted*
    /// while its entry lands when it *finishes*, so a long invocation admitted before a short one is
    /// recorded after it — and a cursor over ids, already moved past the short one's higher id,
    /// would never yield the long one. Append order is assigned at the append itself and so cannot
    /// run backwards.
    fn since(&self, after: u64) -> (Vec<LogEntry>, u64, u64) {
        let inner = locked(&self.inner);
        // What fell out of the ring **between this reader's cursor and the window it is being
        // handed** — the same question every other feed answers, and the one its reader asks: a
        // `--follow` tick prints "earlier event(s) evicted from a ring before this poll". The
        // lifetime counter answered a different question, so once anything had ever been evicted
        // every later poll reported the same total again, for the rest of the session, over polls
        // that had lost nothing. Append order is contiguous, so the gap is arithmetic on the oldest
        // entry still held.
        // `saturating_add`, because `after` is whatever the caller put on the wire — and on this
        // socket the caller is the cage. `after + 1` at `u64::MAX` panics in a debug build and wraps
        // in a release one (nothing sets `overflow-checks`), and the wrap lands here as a fabricated
        // eviction count rather than as a failure. Saturating gives the true answer for that cursor
        // too: nothing can be newer than `u64::MAX`, so nothing was missed.
        let evicted = match inner.entries.front() {
            Some(oldest) if oldest.cursor > after.saturating_add(1) => oldest.cursor - after - 1,
            _ => 0,
        };
        (
            inner
                .entries
                .iter()
                .filter(|e| e.cursor > after)
                .cloned()
                .collect(),
            evicted,
            inner.appended,
        )
    }

    /// Whether an invocation with this id has already been recorded — what tells "you are too late"
    /// from "there is no such invocation" when a stop names one that is not running.
    fn recorded(&self, id: u64) -> bool {
        self.entry(id).is_some()
    }

    /// What the ring kept about one invocation.
    fn entry(&self, id: u64) -> Option<LogEntry> {
        let inner = locked(&self.inner);
        inner.entries.iter().find(|e| e.seq == id).cloned()
    }
}

/// What a detached invocation left behind: what it produced, or why it never produced anything. Both
/// are held, because an invocation can still fail *after* it was admitted — a credential that will not
/// resolve, a proxy that will not start — and the caller that would have been told is already gone.
type Held = Result<TaskOutcome, String>;

/// The finished detached invocations a session is holding for collection.
///
/// In RAM and never on disk, for the same reason as [`TaskLog`]: this holds a command's own output,
/// which is exactly the class of data the log ring is careful not to leave behind. It dies with the
/// session, which is also the longest a detached invocation can live — the plane runs in the session's
/// process, so nothing is ever waiting for a result whose session is gone.
///
/// Its lock recovers from a poisoning for the same reason and by the same enumeration: the two
/// critical sections below hold it for a `VecDeque` push, pop and scan, and nothing else, so
/// [`crate::sandbox::locks::locked`] can hand back a record a panic touched. See [`TaskLog`] for the
/// enumeration in full and for what would break it.
#[derive(Default)]
pub(crate) struct TaskResults {
    inner: Mutex<std::collections::VecDeque<(u64, Held)>>,
}

impl TaskResults {
    /// Hold one finished invocation's result, evicting the oldest when the ring is full.
    fn store(&self, id: u64, held: Held) {
        let mut results = locked(&self.inner);
        if results.len() == RESULT_CAPACITY {
            results.pop_front();
        }
        results.push_back((id, held));
    }

    /// What is held for `id`. A read, not a take: collecting a result must not be the thing that
    /// destroys it, or a caller whose terminal scrolled would have no second look.
    fn get(&self, id: u64) -> Option<Held> {
        let results = locked(&self.inner);
        results
            .iter()
            .find(|(held_id, _)| *held_id == id)
            .map(|(_, held)| held.clone())
    }
}

/// The cage-visible programs the generated client is written against. They are the cage's own store
/// paths, not the host's — the client runs inside, where the store is mounted at `/nix`.
pub(crate) struct ClientPrograms<'a> {
    pub(crate) bash: &'a Path,
    pub(crate) socat: &'a Path,
    pub(crate) head: &'a Path,
}

/// A live task plane: the two listeners' threads and the paths they own. Dropping it removes the
/// socket files and the generated client, so a session leaves nothing behind for the next one to
/// trip over.
pub(crate) struct TaskPlane {
    /// The crossing socket's host path — what the launcher binds into the cage.
    pub(crate) cage_socket: PathBuf,
    /// The host-only log socket's path.
    log_socket: PathBuf,
    /// The generated in-cage client's host path — bound read-only at [`TASK_SHIM_INCAGE`].
    shim: PathBuf,
    dir: PathBuf,
}

impl Drop for TaskPlane {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cage_socket);
        let _ = std::fs::remove_file(&self.log_socket);
        let _ = std::fs::remove_file(&self.shim);
        let _ = std::fs::remove_file(self.dir.join(INCARNATION));
        // Last: the directory only goes when what it held is gone.
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Records which incarnation of the directory's pid owns it: the launcher's start time in clock
/// ticks, the same discriminator the session registry uses against pid reuse.
const INCARNATION: &str = "incarnation";

/// The directory a session's task sockets live in, under the `0700` data dir.
pub(crate) fn task_dir(data_dir: &Path, pid: u32) -> PathBuf {
    data_dir.join("tasks").join(pid.to_string())
}

/// The generated in-cage client's host path for a session pid. Derivable before the plane starts,
/// so the launcher can bind it in the same pass that binds the socket.
pub(crate) fn shim_path(data_dir: &Path, pid: u32) -> PathBuf {
    task_dir(data_dir, pid).join("task-client")
}

/// The host-only socket for a session pid: its invocation log, what it is running, and the stop.
/// Never bound into a cage — that is what keeps those three host-side.
pub(crate) fn log_socket(data_dir: &Path, pid: u32) -> PathBuf {
    task_dir(data_dir, pid).join("log.sock")
}

/// Stand up the task plane for one session: bind both sockets and serve each on its own thread.
///
/// The engine is shared (`Arc`) with the serve threads; each invocation runs on the connection's
/// thread, so a long task blocks only its own caller.
pub(crate) fn start(
    data_dir: &Path,
    pid: u32,
    engine: TaskEngine,
    client: &ClientPrograms<'_>,
) -> io::Result<TaskPlane> {
    // Sweep first, for its effect rather than its answer: every launch removes the directories of
    // sessions that are gone, so the listing stays honest on a machine where nobody runs
    // `sbx task list` between crashes.
    let _ = session_pids(data_dir);

    let dir = task_dir(data_dir, pid);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    // Stamp which incarnation of this pid owns the directory, before anything else is put in it.
    // Nothing guarantees a plane gets to clean up after itself — a `SIGKILL`ed session never runs
    // its `Drop` — so what makes the directory listing trustworthy is not tidy shutdown but this
    // stamp, which [`session_pids`] re-checks and which no reused pid can satisfy.
    if let Some(ticks) = crate::session::read_start_ticks(pid) {
        std::fs::write(dir.join(INCARNATION), ticks.to_string())?;
    }

    let cage_socket = dir.join("control.sock");
    let log_path = log_socket(data_dir, pid);
    let shim = shim_path(data_dir, pid);
    // A leftover from a crashed session would make the bind fail; the directory is per-pid and
    // owner-only, so removing a stale socket here is safe.
    let _ = std::fs::remove_file(&cage_socket);
    let _ = std::fs::remove_file(&log_path);

    // The in-cage client, written before the launch so bwrap finds it present. It is generated
    // rather than shipped, so it always matches the session it was written for and there is no
    // build in which it is missing.
    super::task_shim::write(&shim, client.bash, client.socat, client.head, CAGE_TASK_UDS)?;

    let engine = Arc::new(engine);
    let log = Arc::new(TaskLog::new());
    let results = Arc::new(TaskResults::default());
    let quota = Arc::new(AtomicU64::new(DEFAULT_CALL_QUOTA));

    let cage_listener = UnixListener::bind(&cage_socket)?;
    let log_listener = UnixListener::bind(&log_path)?;

    {
        let engine = Arc::clone(&engine);
        let log = Arc::clone(&log);
        let quota = Arc::clone(&quota);
        let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);
        std::thread::spawn(move || {
            for stream in cage_listener.incoming() {
                let stream = match stream {
                    Ok(s) => s,
                    // `.flatten()` dropped the error and went straight round again, which kept the
                    // plane serving but spun this thread flat out while the condition held.
                    Err(e) => {
                        super::conncap::accept_backoff("task control (cage)", &e);
                        continue;
                    }
                };
                // Dropping the stream closes it: a caller past the ceiling is refused rather than
                // queued, so nothing waits on a thread that will not come.
                let Some(slot) = cap.take() else { continue };
                let engine = Arc::clone(&engine);
                let log = Arc::clone(&log);
                let quota = Arc::clone(&quota);
                // One thread per connection: an invocation runs for as long as its task's timeout,
                // and a second caller must not queue behind it.
                super::conncap::spawn_conn("task control (cage)", move || {
                    let _slot = slot;
                    let _ = serve_cage(stream, &engine, &log, &quota, CAGE_FIRST_REQUEST);
                });
            }
        });
    }
    {
        let engine = Arc::clone(&engine);
        let log = Arc::clone(&log);
        let results = Arc::clone(&results);
        let quota = Arc::clone(&quota);
        let cap = super::conncap::ConnCap::new(MAX_CONCURRENT_CONNS);
        std::thread::spawn(move || {
            for stream in log_listener.incoming() {
                let stream = match stream {
                    Ok(s) => s,
                    // The same as the crossing socket above, and worth saying twice: this is the
                    // listener `sbx task status` and `sbx task stop` are answered on.
                    Err(e) => {
                        super::conncap::accept_backoff("task control (logs)", &e);
                        continue;
                    }
                };
                // Its own ceiling rather than a share of the crossing socket's: a cage filling the
                // one must not be able to lock the user out of the other, which is where `sbx task
                // status` and `sbx task stop` are answered.
                let Some(slot) = cap.take() else { continue };
                let engine = Arc::clone(&engine);
                let log = Arc::clone(&log);
                let results = Arc::clone(&results);
                let quota = Arc::clone(&quota);
                // Its own thread for the same reason the crossing socket's connections get one: a
                // `STOP` waits for the invocation to end, and a `STATUS` behind it must not queue
                // behind that wait.
                super::conncap::spawn_conn("task control (logs)", move || {
                    let _slot = slot;
                    let _ = serve_host(stream, &engine, &log, &results, &quota);
                });
            }
        });
    }

    Ok(TaskPlane {
        cage_socket,
        log_socket: log_path,
        shim,
        dir,
    })
}

/// Serve one connection on the crossing socket, with the whole request read under
/// `first_request`.
///
/// Both halves of that bound are needed and neither replaces the other, exactly as the plugin
/// broker spells out: the socket timeout so a peer that says nothing at all does not block in
/// `read` for good, the wall-clock budget so a peer trickling a byte per timeout does not extend
/// the wait a request's length at a time. A read deadline is per-syscall; a request is read in
/// pieces.
///
/// The write timeout is set with them and left in place. A cage that connects, sends `LIST` and
/// then never reads stalls the reply once the socket buffer fills, which holds the same thread and
/// the same slot the read deadline was added to protect.
///
/// The budget is a parameter rather than [`CAGE_FIRST_REQUEST`] read directly, the way the
/// ssh-agent broker takes its own: a test can then prove a silent connection is given up on without
/// waiting out the real thirty seconds.
fn serve_cage(
    stream: UnixStream,
    engine: &TaskEngine,
    log: &TaskLog,
    quota: &AtomicU64,
    first_request: std::time::Duration,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    // Set on `writer`, which reaches the same socket: `try_clone` dups the descriptor, and a
    // receive timeout belongs to the socket rather than to either descriptor naming it.
    writer.set_read_timeout(Some(first_request))?;
    writer.set_write_timeout(Some(first_request))?;
    let mut reader =
        super::deadline::Deadlined::new(&mut reader, std::time::Instant::now() + first_request);
    let Some(command) = read_request_line(&mut reader)? else {
        return Ok(());
    };
    let command = command.trim_end();

    if command == "LIST" {
        for task in engine.tasks() {
            let params: Vec<&str> = task.params.iter().map(|p| p.name.as_str()).collect();
            // A task whose declared tools are not in the pool will fail at exec. Say so here, where
            // a caller is choosing what to invoke, rather than let it discover a "not found" later:
            // the pool is filled best-effort, so this is the field that carries that consequence.
            let missing = engine.missing_packages(task);
            let missing = if missing.is_empty() {
                String::new()
            } else {
                format!("\tmissing-tools={}", missing.join(","))
            };
            // Where this operation's artifacts will be, when it declares `output`. Listed rather
            // than only reported afterwards: the path is one per task, so a caller can know it
            // before invoking anything — which is the whole reason it is not per invocation.
            let output = match task.output {
                false => String::new(),
                true => format!("\toutput={}/{}", super::task::TASK_OUT_AGENT, task.name),
            };
            writeln!(
                writer,
                "task {}\tparams={}\tstdout={}\tstderr={}\ttimeout={}s{}{}\tdeclared-in={}\t{}",
                task.name,
                params.join(","),
                task.stdout.as_str(),
                task.stderr.as_str(),
                task.timeout.as_secs(),
                missing,
                output,
                // Which config the `[task.<name>]` block is in. A session can be offered
                // operations by the project, by its app, and by each bundle the app names, and the
                // name alone does not say which — so a caller wondering which file to open is told.
                // It claims the block's location and nothing more: a ceiling the block does not set
                // is inherited, and `sbx task show` is where that is spelled out.
                sanitize(&task.origin.label()),
                sanitize(task.description.as_deref().unwrap_or("")),
            )?;
        }
        return writeln!(writer, "ok");
    }
    if command == "SECRETS" {
        // Names and descriptions only — never a value, and never a source locator: what a caller
        // needs is which credentials an operation carries, not where they come from.
        for task in engine.tasks() {
            for secret in &task.secrets {
                writeln!(
                    writer,
                    "secret {}\ttask={}\tencode={}\t{}",
                    secret.var,
                    task.name,
                    secret.encode.as_str(),
                    sanitize(secret.description.as_deref().unwrap_or("")),
                )?;
            }
            for injection in &task.injections {
                writeln!(
                    writer,
                    "secret {}\ttask={}\twire-injected for {}",
                    injection.name, task.name, injection.to,
                )?;
            }
        }
        return writeln!(writer, "ok");
    }
    if let Some(name) = command.strip_prefix("RUN ") {
        return serve_run(&mut reader, &mut writer, name.trim(), engine, log, quota);
    }
    writeln!(writer, "err unknown command")
}

/// A request's caller-supplied parameters and environment.
type Payloads = (BTreeMap<String, String>, BTreeMap<String, String>);

/// Read the length-prefixed `param`/`env` payloads up to the `run` terminator.
///
/// Every refusal here is a fixed string rather than one built from what was read: a malformed request
/// is malformed in the framing, and echoing the bytes back would put a caller's value — which can be
/// the very secret it is probing for — into an error message.
fn read_payloads(reader: &mut impl io::BufRead) -> io::Result<Result<Payloads, &'static str>> {
    let mut params = BTreeMap::new();
    let mut env = BTreeMap::new();
    // What this request has cost so far, keys and values together. Counted here because it is the
    // only place that sees every entry: a per-payload ceiling bounds one field, and a caller sends
    // as many as it likes.
    let mut held = 0usize;
    loop {
        let Some(line) = read_request_line(reader)? else {
            return Ok(Err("truncated request"));
        };
        let line = line.trim_end();
        if line == "run" {
            break;
        }
        let Some((kind, rest)) = line.split_once(' ') else {
            return Ok(Err("malformed request line"));
        };
        let Some((key, len)) = rest.rsplit_once(' ') else {
            return Ok(Err("malformed request line"));
        };
        let Ok(len) = len.parse::<usize>() else {
            return Ok(Err("malformed payload length"));
        };
        // A caller must not be able to make sbx allocate arbitrarily. Both checks stand before the
        // allocation, not after it: one bounds this field, the other bounds the request it belongs
        // to, and a field admitted by the first would still be an unbounded total without the
        // second.
        if len > MAX_PAYLOAD_BYTES {
            return Ok(Err("payload too large"));
        }
        // The **line** is charged, not the key alone. A key is what grows only while a caller
        // supplies one: `param  0` names nothing and declares nothing, so it cost zero and could be
        // repeated without end — the count this ceiling is supposed to bound as a consequence was
        // not bounded at all. Charging the framing gives every field a floor, whatever it carries.
        held = held.saturating_add(line.len()).saturating_add(len);
        if held > MAX_REQUEST_BYTES {
            return Ok(Err("request too large"));
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        // The newline closing the payload. Bounded like every other line: a caller that writes a
        // payload and then never ends its line is the same unbounded read as one that never ends
        // its first, and this one is easy to miss because nothing is done with what it returns.
        let _ = read_request_line(reader);
        // Refused rather than repaired. `String::from_utf8_lossy` replaces each invalid byte with a
        // three-byte U+FFFD, so a payload charged `len` above was retained as up to three times that
        // and the ceiling admitted three times what it says it admits — on a thread that belongs to
        // sbx, outside the cgroup bounding the cage's own memory. Refusing keeps the charge exact by
        // construction, and it is also the honest answer: a bound is checked against the value that
        // arrived, and a rewritten copy is not that value. Every legitimate sender writes a `String`,
        // so nothing but a probe reaches this.
        let Ok(value) = String::from_utf8(buf) else {
            return Ok(Err("payload is not valid UTF-8"));
        };
        match kind {
            "param" => params.insert(key.to_string(), value),
            "env" => env.insert(key.to_string(), value),
            _ => return Ok(Err("unknown request field")),
        };
    }
    Ok(Ok((params, env)))
}

/// Take a slot from the session's call quota and draw the invocation's id.
///
/// The quota is decremented before anything runs, so a refusal is recorded once and a concurrent pair
/// of callers cannot both slip past the last slot. `None` means the quota is exhausted and the caller
/// has already been answered.
fn admit_quota(
    writer: &mut UnixStream,
    name: &str,
    log: &TaskLog,
    quota: &AtomicU64,
) -> io::Result<Option<u64>> {
    if quota
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
            (left > 0).then(|| left - 1)
        })
        .is_err()
    {
        let reason = "this session's task quota is exhausted".to_string();
        // Id `0`: nothing was admitted, so there is no invocation for an id to name. It is also what
        // keeps the id inside the width the socket paths were sized against — the quota is the bound
        // on how many are ever drawn.
        log.push(refusal(0, name, &reason));
        writeln!(writer, "err {reason}")?;
        return Ok(None);
    }
    // Admitted: from here the invocation has an identity, and it is the *same* number wherever it
    // appears — in the host-side names it stands up, in the row `sbx task status` shows while it
    // runs, in the id `sbx task stop` takes, and in the line it leaves in this log. Drawn here
    // rather than inside the engine so a refusal the engine returns is recorded under it too.
    Ok(Some(super::task::next_invocation()))
}

/// The log entry one finished invocation leaves.
fn finished(id: u64, name: &str, outcome: &TaskOutcome, detached: bool) -> LogEntry {
    LogEntry {
        seq: id,
        // Both stamped by `TaskLog::push`, which is their authority; zero until it runs.
        cursor: 0,
        at_epoch_ms: 0,
        started_epoch_ms: 0,
        task: sanitize(name),
        exit: outcome.exit,
        redacted: outcome.redacted + outcome.redacted_withheld,
        truncated: outcome.truncated,
        timed_out: outcome.timed_out,
        stopped: outcome.stopped,
        elapsed_ms: outcome.elapsed_ms,
        refused: None,
        detached,
    }
}

/// Read a `RUN`'s parameter/environment payloads, invoke the task, and write the result.
fn serve_run(
    reader: &mut impl io::BufRead,
    writer: &mut UnixStream,
    name: &str,
    engine: &TaskEngine,
    log: &TaskLog,
    quota: &AtomicU64,
) -> io::Result<()> {
    let (params, env) = match read_payloads(reader)? {
        Ok(payloads) => payloads,
        Err(reason) => return writeln!(writer, "err {reason}"),
    };
    let Some(id) = admit_quota(writer, name, log, quota)? else {
        return Ok(());
    };

    match engine.run(name, &params, &env, id) {
        Ok(outcome) => {
            log.push(finished(id, name, &outcome, false));
            write_outcome(writer, id, &outcome)
        }
        Err(e) => {
            let reason = e.to_string();
            log.push(refusal(id, name, &reason));
            // The id first, then the refusal: this request was admitted, so it *has* an invocation,
            // and the log records the refusal under that number. Without it a caller could not find
            // its own refusal in `sbx task logs`. It precedes `err` because that line ends the
            // answer — a reader stops there.
            writeln!(writer, "id {id}")?;
            writeln!(writer, "err {}", sanitize(&reason))
        }
    }
}

/// Read a `DETACH`'s payloads, admit the invocation, hand it to a thread, and answer with its id.
///
/// The split between what happens here and what happens in the thread is the whole design: everything
/// a caller could act on is decided **before** it is told the invocation was admitted, because after
/// that it is no longer listening. What runs in the thread is the command itself and the things that
/// can only fail once it is under way — a credential that will not resolve, a proxy that will not
/// start — and those are held for `RESULT` rather than reported to a caller that has gone.
fn serve_detach(
    reader: &mut impl io::BufRead,
    writer: &mut UnixStream,
    name: &str,
    engine: &Arc<TaskEngine>,
    log: &Arc<TaskLog>,
    results: &Arc<TaskResults>,
    quota: &AtomicU64,
) -> io::Result<()> {
    let (params, env) = match read_payloads(reader)? {
        Ok(payloads) => payloads,
        Err(reason) => return writeln!(writer, "err {reason}"),
    };
    let Some(id) = admit_quota(writer, name, log, quota)? else {
        return Ok(());
    };
    let admitted = match engine.admit(name, &params, &env, id, true) {
        Ok(admitted) => admitted,
        Err(e) => {
            let reason = e.to_string();
            log.push(refusal(id, name, &reason));
            writeln!(writer, "id {id}")?;
            return writeln!(writer, "err {}", sanitize(&reason));
        }
    };

    // The admission moves into the thread with everything it holds — the output directory's claim,
    // and the registry entry that makes the invocation visible to `status` and stoppable by `stop` —
    // so both are released when the command ends rather than when this connection closes.
    //
    // The registry entry is taken out of the admission first, and held here until the result is
    // stored. Left inside, it would be released the moment the run returns, two statements before
    // the result exists: an invocation in that window reads as neither running nor holding a
    // result, and `RESULT <id>` answers "no invocation" or "its result is no longer held", which
    // are both false and both terminal to a caller that asks once. Held, the worst answer in the
    // window is "still running".
    let mut admitted = admitted;
    let live = admitted.hold_registration();
    {
        let engine = Arc::clone(engine);
        let log = Arc::clone(log);
        let results = Arc::clone(results);
        let name = name.to_string();
        std::thread::spawn(move || {
            // Bound first so it drops last: locals are released in reverse order of declaration,
            // which puts this after the store below.
            let _live = live;
            match engine.run_admitted(&name, admitted) {
                Ok(outcome) => {
                    log.push(finished(id, &name, &outcome, true));
                    results.store(id, Ok(outcome));
                }
                Err(e) => {
                    let reason = e.to_string();
                    let mut entry = refusal(id, &name, &reason);
                    entry.detached = true;
                    log.push(entry);
                    results.store(id, Err(reason));
                }
            }
        });
    }
    writeln!(writer, "id {id}")?;
    writeln!(writer, "ok")
}

/// Answer `RESULT <id>` — the held result, or which of the four other things is true instead.
fn serve_result(
    writer: &mut UnixStream,
    engine: &TaskEngine,
    log: &TaskLog,
    results: &TaskResults,
    id: u64,
) -> io::Result<()> {
    match results.get(id) {
        Some(Ok(outcome)) => return write_outcome(writer, id, &outcome),
        Some(Err(reason)) => {
            // The same shape a refused `RUN` answers with, so one parser reads both: an invocation
            // that failed after admission is still an invocation that has an id and no result.
            writeln!(writer, "id {id}")?;
            return writeln!(writer, "err {}", sanitize(&reason));
        }
        None => {}
    }
    let reason = if engine.running().iter().any(|row| row.id == id) {
        format!("invocation {id} is still running")
    } else {
        match log.entry(id) {
            Some(entry) if entry.detached => format!(
                "invocation {id} has finished, but its result is no longer held — a session keeps \
                 the last {RESULT_CAPACITY}, and newer ones have replaced it"
            ),
            Some(_) => format!(
                "invocation {id} did not run detached, so its result went to the caller that waited \
                 for it"
            ),
            None => format!("no invocation {id}"),
        }
    };
    writeln!(writer, "err {reason}")
}

/// The fields for a target that is not running: an invocation the log remembers, or an operation
/// named directly. Both end in the same place — the declaration — because an invocation *is* its
/// declaration plus what one run of it did.
fn finished_fields(
    engine: &TaskEngine,
    log: &TaskLog,
    target: &str,
) -> Option<Vec<(String, String)>> {
    if let Ok(id) = target.parse::<u64>() {
        let entry = log.entry(id)?;
        let mut out = vec![
            ("id".to_string(), id.to_string()),
            ("operation".to_string(), entry.task.clone()),
            (
                "state".to_string(),
                match (&entry.refused, entry.stopped, entry.timed_out) {
                    (Some(_), _, _) => "refused".to_string(),
                    (_, true, _) => "stopped".to_string(),
                    (_, _, true) => "timed out".to_string(),
                    _ => "finished".to_string(),
                },
            ),
            ("finished_at".to_string(), entry.at_epoch_ms.to_string()),
            ("elapsed_ms".to_string(), entry.elapsed_ms.to_string()),
        ];
        // Beside the state rather than folded into it: detaching is orthogonal to how an invocation
        // ended, and a detached one can equally have finished, been stopped, or timed out. Shown only
        // when true, like the other fields that appear when they have something to say — and shown at
        // all because it is what says where the result went, which is the next thing a reader asks.
        if entry.detached {
            out.push(("detached".to_string(), "yes".to_string()));
        }
        if entry.refused.is_none() {
            out.push(("exit".to_string(), entry.exit.to_string()));
        }
        if let Some(reason) = &entry.refused {
            out.push(("refused".to_string(), reason.clone()));
        }
        if entry.redacted > 0 {
            out.push(("redacted".to_string(), entry.redacted.to_string()));
        }
        out.extend(engine.describe_task(&entry.task).unwrap_or_default());
        return Some(out);
    }
    let mut out = vec![("operation".to_string(), target.to_string())];
    out.extend(engine.describe_task(target)?);
    Some(out)
}

/// A log entry for an invocation that never ran.
fn refusal(id: u64, task: &str, reason: &str) -> LogEntry {
    LogEntry {
        seq: id,
        // Both stamped by `TaskLog::push`, which is their authority; zero until it runs.
        cursor: 0,
        at_epoch_ms: 0,
        started_epoch_ms: 0,
        task: sanitize(task),
        exit: -1,
        redacted: 0,
        truncated: false,
        timed_out: false,
        stopped: false,
        elapsed_ms: 0,
        refused: Some(sanitize(reason)),
        detached: false,
    }
}

/// Write one outcome in the response shape. A withheld stream is `-1`, distinct from an empty one
/// (`0`), so a caller can tell "the declaration hides this" from "the command printed nothing".
fn write_outcome(writer: &mut UnixStream, id: u64, outcome: &TaskOutcome) -> io::Result<()> {
    // The invocation's id, so a result can be matched against the line it leaves in the session's
    // log — one number, whichever verb you are looking at.
    writeln!(writer, "id {id}")?;
    writeln!(writer, "exit {}", outcome.exit)?;
    writeln!(writer, "redacted {}", outcome.redacted)?;
    writeln!(writer, "truncated {}", u8::from(outcome.truncated))?;
    writeln!(writer, "timed-out {}", u8::from(outcome.timed_out))?;
    writeln!(writer, "stopped {}", u8::from(outcome.stopped))?;
    writeln!(writer, "elapsed-ms {}", outcome.elapsed_ms)?;
    // The invocation's substitution nonce, when the section enabled it — out of band, which is the
    // whole point: a `${NAME@nonce}` in the *text* is only unforgeable because the nonce arrives
    // here, where the command that produced the text could not have seen it.
    if let Some(nonce) = &outcome.nonce {
        writeln!(writer, "nonce {nonce}")?;
    }
    // What `spawn` refused. One line per `execve`, because which program was refused is the whole
    // content of the report — a count would say "something you declared is missing" and leave the
    // caller to guess which. Two paths, caller first: what may run depends on who is running it, so
    // the target alone can send a reader to add an entry that is already there. Neither carries a
    // space (both are exec paths the cage resolved), so the line-based framing holds; the caller is
    // `-` when the policy decided by target alone, keeping the field count fixed.
    for refusal in &outcome.refused {
        let caller = match refusal.caller.is_empty() {
            true => "-",
            false => &refusal.caller,
        };
        writeln!(writer, "refused-exec {caller} {}", refusal.target)?;
    }
    // Where the invocation left its artifacts, as the caller's own cage sees the path, with the size
    // so "it produced something" is visible without going to look.
    if let Some((path, bytes)) = &outcome.output {
        writeln!(writer, "output {bytes} {path}")?;
    }
    for (label, stream) in [("stdout", &outcome.stdout), ("stderr", &outcome.stderr)] {
        match stream {
            Some(text) => {
                writeln!(writer, "{label} {}", text.len())?;
                writer.write_all(text.as_bytes())?;
                writeln!(writer)?;
            }
            None => writeln!(writer, "{label} -1")?,
        }
    }
    writeln!(writer, "ok")
}

/// Serve one connection on the session's host-only socket: `STATUS`, `DETACH <name>`,
/// `RESULT <id>`, `INFO <id-or-name>`, `STOP <id>`, or `LOG` (optionally `after=<seq>`).
///
/// All six are here rather than on the crossing socket, and that placement *is* the access control:
/// this socket is never bound into a cage, so the in-cage client cannot express these verbs however
/// it is called. The reasons differ by verb and each matters. `LOG`: the recorded party does not get
/// to read the record. `STATUS`/`STOP`/`INFO`: ids are per session, so an in-cage caller reaching
/// them could see and end an invocation *another* caller started — the human at the terminal — and
/// nothing in the cage distinguishes the two, since a task plane has no per-caller identity.
///
/// `DETACH`/`RESULT`: a detached invocation is one nobody is waiting for, so putting its start
/// within reach of a cage would let a caller create invocations it cannot then see or end, and hold
/// several at once — which having to wait is what prevents.
fn serve_host(
    stream: UnixStream,
    engine: &Arc<TaskEngine>,
    log: &Arc<TaskLog>,
    results: &Arc<TaskResults>,
    quota: &AtomicU64,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let Some(command) = read_request_line(&mut reader)? else {
        return Ok(());
    };
    let command = command.trim_end();

    if command == "STATUS" {
        for row in engine.running() {
            writeln!(
                writer,
                "running {}\ttask={}\telapsed_ms={}\tpid={}\tstopping={}\tdetached={}",
                row.id,
                sanitize(&row.task),
                row.elapsed_ms,
                row.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                u8::from(row.stopping),
                u8::from(row.detached),
            )?;
        }
        return writeln!(writer, "ok");
    }

    if let Some(name) = command.strip_prefix("DETACH ") {
        return serve_detach(
            &mut reader,
            &mut writer,
            name.trim(),
            engine,
            log,
            results,
            quota,
        );
    }

    if let Some(rest) = command.strip_prefix("RESULT ") {
        let Ok(id) = rest.trim().parse::<u64>() else {
            return writeln!(writer, "err a result names an invocation id");
        };
        return serve_result(&mut writer, engine, log, results, id);
    }

    if let Some(rest) = command.strip_prefix("INFO ") {
        let target = rest.trim();
        // A live invocation answers with its state *and* its declaration; one that is over answers
        // with what the log kept plus the declaration it ran under, because "what was that" is the
        // same question a minute later.
        let fields = match target
            .parse::<u64>()
            .ok()
            .and_then(|id| engine.describe(id))
        {
            Some(fields) => Some(fields),
            None => finished_fields(engine, log, target),
        };
        let Some(fields) = fields else {
            return writeln!(writer, "err nothing here is called `{}`", sanitize(target));
        };
        for (key, value) in fields {
            writeln!(writer, "field {key}\t{}", sanitize(&value))?;
        }
        return writeln!(writer, "ok");
    }

    if let Some(rest) = command.strip_prefix("STOP ") {
        let Ok(id) = rest.trim().parse::<u64>() else {
            return writeln!(writer, "err a stop names an invocation id");
        };
        let line = match engine.stop(id) {
            super::task::StopOutcome::Stopped => format!("stopped {id}"),
            super::task::StopOutcome::Stopping => format!("stopping {id}"),
            // Not running now — but the log says whether it ever was, and "you are too late" and
            // "there is no such invocation" are different things to be told.
            super::task::StopOutcome::NotRunning if log.recorded(id) => format!("finished {id}"),
            super::task::StopOutcome::NotRunning => {
                return writeln!(writer, "err no invocation {id}");
            }
        };
        writeln!(writer, "{line}")?;
        return writeln!(writer, "ok");
    }

    let after = match command.strip_prefix("LOG") {
        None => return writeln!(writer, "err unknown command"),
        Some(rest) => rest
            .trim()
            .strip_prefix("after=")
            .and_then(|n| n.trim().parse::<u64>().ok())
            .unwrap_or(0),
    };
    let (entries, dropped, head) = log.since(after);
    if dropped > 0 {
        writeln!(writer, "dropped={dropped}")?;
    }
    // The head goes out before the events, the way the observation lenses send theirs: a reader that
    // stops mid-stream still has a cursor it can come back with, and one that sees no `head=` at all
    // is talking to a plane that predates this and must not try to follow.
    writeln!(writer, "head={head}")?;
    for entry in &entries {
        writeln!(writer, "{}", entry.to_line())?;
    }
    writeln!(writer, "ok")
}

/// Ask a session's host-only socket one thing and read the whole answer.
fn ask_host(socket: &Path, command: &str) -> io::Result<Vec<String>> {
    let mut stream = UnixStream::connect(socket)?;
    writeln!(stream, "{command}")?;
    stream.flush()?;
    let mut text = String::new();
    BufReader::new(stream).read_to_string(&mut text)?;
    Ok(text.lines().map(str::to_string).collect())
}

/// The raw `LOG` reply, line by line — for the tests that assert on the **wire format itself**.
///
/// Not a reader for anything else. Every consumer of the log goes through [`read_entries`], which
/// parses with [`LogEntry::from_line`], the function [`LogEntry::to_line`] is round-tripped
/// against. A second hand-rolled reader is the drift that round-trip cannot catch: it does not fail
/// loudly, it drops entries or files them wrongly, in the record whose whole job is to miss nothing.
#[cfg(test)]
pub(crate) fn read_log(socket: &Path) -> io::Result<Vec<String>> {
    ask_host(socket, "LOG")
}

/// One read of the invocation log as parsed entries: what is past `after`, the head to come back
/// with, and how many fell out of the ring — in that order, which is not the order
/// [`TaskLog::since`] returns its three in. The two are read by different callers and the tuple a
/// reader binds is this one.
///
/// `after` is **append order**, never an invocation id (see [`TaskLog::since`]), and a caller only
/// ever gets one from a previous read — so a plane too old to send `head=` yields head `0` and is
/// simply never followed, rather than followed wrongly.
pub(crate) fn read_entries(
    socket: &Path,
    after: Option<u64>,
) -> io::Result<(Vec<LogEntry>, u64, u64)> {
    let command = match after {
        Some(cursor) => format!("LOG after={cursor}"),
        None => "LOG".to_string(),
    };
    let lines = ask_host(socket, &command)?;
    let mut entries = Vec::new();
    let mut dropped = 0;
    let mut head = 0;
    for line in &lines {
        if let Some(n) = line.strip_prefix("dropped=") {
            dropped = n.trim().parse().unwrap_or(0);
        } else if let Some(n) = line.strip_prefix("head=") {
            head = n.trim().parse().unwrap_or(0);
        } else if let Some(entry) = LogEntry::from_line(line) {
            entries.push(entry);
        }
    }
    Ok((entries, head, dropped))
}

/// One invocation running right now, as the host-side verb prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusRow {
    pub(crate) id: u64,
    pub(crate) fields: Vec<String>,
}

/// What a session is running right now.
pub(crate) fn read_status(socket: &Path) -> io::Result<Vec<StatusRow>> {
    Ok(ask_host(socket, "STATUS")?
        .iter()
        .filter_map(|line| {
            let rest = line.strip_prefix("running ")?;
            let mut fields = rest.split('\t').map(str::to_string);
            let id = fields.next()?.parse().ok()?;
            Some(StatusRow {
                id,
                fields: fields.collect(),
            })
        })
        .collect())
}

/// Everything one invocation (or one operation) has to say about itself, in reading order.
pub(crate) fn read_info(socket: &Path, target: &str) -> io::Result<Vec<(String, String)>> {
    let lines = ask_host(socket, &format!("INFO {target}"))?;
    if let Some(reason) = lines.iter().find_map(|l| l.strip_prefix("err ")) {
        return Err(io::Error::other(reason.to_string()));
    }
    Ok(lines
        .iter()
        .filter_map(|l| l.strip_prefix("field "))
        .filter_map(|rest| rest.split_once('\t'))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

/// What a stop achieved, as the plane reports it. The plane is the authority on this: it is the side
/// that waited to see whether the invocation actually ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StopReply {
    Stopped,
    Stopping,
    Finished,
    Refused(String),
}

/// Stop one invocation by id, host-side.
pub(crate) fn stop_invocation(socket: &Path, id: u64) -> io::Result<StopReply> {
    let lines = ask_host(socket, &format!("STOP {id}"))?;
    for line in &lines {
        if let Some(reason) = line.strip_prefix("err ") {
            return Ok(StopReply::Refused(reason.to_string()));
        }
        if line.starts_with("stopped ") {
            return Ok(StopReply::Stopped);
        }
        if line.starts_with("stopping ") {
            return Ok(StopReply::Stopping);
        }
        if line.starts_with("finished ") {
            return Ok(StopReply::Finished);
        }
    }
    // A connection that closed before saying anything is a plane that went away mid-answer; that is
    // not a stop, and reporting one would be inventing a result.
    Err(io::Error::other(
        "the task plane gave no answer to the stop",
    ))
}

/// The pids of the sessions currently offering declared operations, sorted — and, as a side effect,
/// the removal of the directories that no longer belong to one.
///
/// A directory is not evidence of a session. Nothing removes it when a session is killed rather than
/// closed, so an unvalidated listing accumulates: after a few crashed launches, naming a session
/// becomes a choice between pids that are all dead, and the caller has no way to tell which. This is
/// the same reason the session registry validates rather than trusts, and the fix is the same shape
/// — check, and prune what fails, so a crash heals itself at the next read.
///
/// The check is the `(pid, start_ticks)` pair, never the pid alone, because the kernel reuses pids
/// and a reused one would otherwise resurrect a dead session's directory.
pub(crate) fn session_pids(data_dir: &Path) -> Vec<u32> {
    let root = data_dir.join("tasks");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = Vec::new();
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let dir = root.join(pid.to_string());
        if plane_is_live(&dir, pid) {
            pids.push(pid);
        } else {
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    pids.sort_unstable();
    pids
}

/// Whether `dir` belongs to a session that is still running.
///
/// With a stamp, the answer is exact: the pid must still be the incarnation that wrote it. Without
/// one, the directory is either older than the stamp or is being created right now by a plane that
/// has not written it yet — so the weaker test applies, and a live pid is left alone. Erring toward
/// keeping is the safe direction: a directory kept one read too long is a stale row, while one
/// removed too early takes a running session's sockets with it.
fn plane_is_live(dir: &Path, pid: u32) -> bool {
    let running = crate::session::read_start_ticks(pid);
    match std::fs::read_to_string(dir.join(INCARNATION))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
    {
        Some(stamped) => running == Some(stamped),
        None => running.is_some(),
    }
}

/// The in-cage (or host-side) client: one connection, one command.
pub(crate) mod client {
    use super::*;

    /// One task as the plane describes it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct TaskRow {
        pub(crate) name: String,
        pub(crate) fields: Vec<String>,
    }

    /// Ask the plane for its task inventory.
    pub(crate) fn list(socket: &Path) -> io::Result<Vec<TaskRow>> {
        let lines = exchange(socket, "LIST", &[])?;
        Ok(lines
            .iter()
            .filter_map(|l| l.strip_prefix("task "))
            .map(|rest| {
                let mut parts = rest.split('\t');
                TaskRow {
                    name: parts.next().unwrap_or_default().to_string(),
                    fields: parts.map(str::to_string).collect(),
                }
            })
            .collect())
    }

    /// Ask the plane for the credential inventory — names and descriptions, never values.
    pub(crate) fn secrets(socket: &Path) -> io::Result<Vec<String>> {
        let lines = exchange(socket, "SECRETS", &[])?;
        Ok(lines
            .iter()
            .filter_map(|l| l.strip_prefix("secret ").map(str::to_string))
            .collect())
    }

    /// Invoke a task and parse the structured result.
    pub(crate) fn run(
        socket: &Path,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
    ) -> io::Result<RunResult> {
        invoke(socket, "RUN", name, params, env)
    }

    /// Start a task without waiting for it: the answer carries the invocation's id and nothing else.
    ///
    /// A different socket from [`run`] — the session's host-only one — which is what keeps a cage from
    /// starting an invocation it could then neither watch nor stop.
    pub(crate) fn run_detached(
        socket: &Path,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
    ) -> io::Result<RunResult> {
        invoke(socket, "DETACH", name, params, env)
    }

    /// Send one invocation request and parse the answer. `RUN` and `DETACH` differ in the verb, in
    /// the socket they are sent to, and in how much of the answer is filled in — not in their framing.
    fn invoke(
        socket: &Path,
        verb: &str,
        name: &str,
        params: &BTreeMap<String, String>,
        env: &BTreeMap<String, String>,
    ) -> io::Result<RunResult> {
        let mut stream = UnixStream::connect(socket)?;
        writeln!(stream, "{verb} {name}")?;
        for (kind, map) in [("param", params), ("env", env)] {
            for (key, value) in map {
                writeln!(stream, "{kind} {key} {}", value.len())?;
                stream.write_all(value.as_bytes())?;
                writeln!(stream)?;
            }
        }
        writeln!(stream, "run")?;
        stream.flush()?;
        let mut raw = Vec::new();
        BufReader::new(stream).read_to_end(&mut raw)?;
        parse_run(&raw)
    }

    /// Collect what a detached invocation produced, in the same shape [`run`] returns.
    pub(crate) fn result(socket: &Path, id: u64) -> io::Result<RunResult> {
        let mut stream = UnixStream::connect(socket)?;
        writeln!(stream, "RESULT {id}")?;
        stream.flush()?;
        let mut raw = Vec::new();
        BufReader::new(stream).read_to_end(&mut raw)?;
        parse_run(&raw)
    }

    /// A parsed invocation result.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub(crate) struct RunResult {
        /// The invocation's id — the number its line in `sbx task logs` carries, and the one
        /// `sbx task stop` would have taken while it ran.
        pub(crate) id: u64,
        pub(crate) exit: i32,
        pub(crate) stdout: Option<String>,
        pub(crate) stderr: Option<String>,
        pub(crate) redacted: usize,
        pub(crate) truncated: bool,
        pub(crate) timed_out: bool,
        /// Whether `sbx task stop` ended it.
        pub(crate) stopped: bool,
        pub(crate) elapsed_ms: u64,
        /// This invocation's substitution nonce, when the section enabled it — the out-of-band half
        /// of an unforgeable `${NAME@nonce}` placeholder.
        pub(crate) nonce: Option<String>,
        /// The refusal message when the plane answered `err …`.
        pub(crate) error: Option<String>,
        /// The `execve`s `spawn` refused during the invocation, each as the program that reached and
        /// the program it reached for. Carried because the refusal is invisible in the result
        /// otherwise — the refused program decides whether to mention it.
        pub(crate) refused: Vec<crate::sandbox::proc_enforce::Refusal>,
        /// Where the invocation left its artifacts, and how many bytes.
        pub(crate) output: Option<(String, u64)>,
    }

    /// Parse a `RUN` response. The length-prefixed streams are read by byte count, so a payload
    /// containing the protocol's own keywords cannot be mistaken for a header line.
    pub(crate) fn parse_run(raw: &[u8]) -> io::Result<RunResult> {
        let mut out = RunResult::default();
        let mut rest = raw;
        while !rest.is_empty() {
            let (line, tail) = split_line(rest);
            rest = tail;
            let line = String::from_utf8_lossy(line).into_owned();
            if let Some(msg) = line.strip_prefix("err ") {
                out.error = Some(msg.to_string());
                return Ok(out);
            }
            let Some((key, value)) = line.split_once(' ') else {
                continue;
            };
            match key {
                "id" => out.id = value.parse().unwrap_or(0),
                "exit" => out.exit = value.parse().unwrap_or(-1),
                "redacted" => out.redacted = value.parse().unwrap_or(0),
                "truncated" => out.truncated = value == "1",
                "timed-out" => out.timed_out = value == "1",
                "stopped" => out.stopped = value == "1",
                "elapsed-ms" => out.elapsed_ms = value.parse().unwrap_or(0),
                "nonce" => out.nonce = Some(value.to_string()),
                "refused-exec" => {
                    let (caller, target) = value.split_once(' ').unwrap_or(("-", value));
                    out.refused.push(crate::sandbox::proc_enforce::Refusal {
                        caller: match caller {
                            "-" => String::new(),
                            named => named.to_string(),
                        },
                        target: target.to_string(),
                    });
                }
                "output" => {
                    if let Some((bytes, path)) = value.split_once(' ') {
                        out.output = Some((path.to_string(), bytes.parse().unwrap_or(0)));
                    }
                }
                "stdout" | "stderr" => {
                    let len: i64 = value.parse().unwrap_or(-1);
                    if len < 0 {
                        continue; // the declaration hides this stream
                    }
                    let len = len as usize;
                    // A declared length longer than what arrived is an error, not a shorter
                    // stream. The whole answer is already in hand (`read_to_end`), so this is a
                    // plane that died mid-write or miscounted, and the two are indistinguishable
                    // from here. Taking what there is would hand the caller a partial output that
                    // reads exactly like a complete one — the ambiguity the length prefix and the
                    // `truncated` flag exist to keep apart, and the same short payload the server
                    // side of this protocol refuses outright (`read_exact` in `read_payloads`).
                    if len > rest.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "the task plane declared {len} bytes of {key} and sent {}",
                                rest.len()
                            ),
                        ));
                    }
                    let text = String::from_utf8_lossy(&rest[..len]).into_owned();
                    rest = &rest[len..];
                    if rest.first() == Some(&b'\n') {
                        rest = &rest[1..];
                    }
                    if key == "stdout" {
                        out.stdout = Some(text);
                    } else {
                        out.stderr = Some(text);
                    }
                }
                _ => {}
            }
        }
        Ok(out)
    }

    /// Split off one `\n`-terminated line, returning it without the newline.
    fn split_line(buf: &[u8]) -> (&[u8], &[u8]) {
        match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (&buf[..i], &buf[i + 1..]),
            None => (buf, &[][..]),
        }
    }

    /// Send a payload-free command and return its response lines (without the trailing `ok`).
    fn exchange(socket: &Path, command: &str, payload: &[String]) -> io::Result<Vec<String>> {
        let mut stream = UnixStream::connect(socket)?;
        writeln!(stream, "{command}")?;
        for line in payload {
            writeln!(stream, "{line}")?;
        }
        stream.flush()?;
        let mut text = String::new();
        BufReader::new(stream).read_to_string(&mut text)?;
        if let Some(err) = text.lines().find_map(|l| l.strip_prefix("err ")) {
            return Err(io::Error::other(err.to_string()));
        }
        Ok(text
            .lines()
            .filter(|l| *l != "ok")
            .map(str::to_string)
            .collect())
    }
}

#[cfg(test)]
mod tests;
