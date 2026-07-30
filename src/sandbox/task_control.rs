//! The task control plane: the per-session socket a caller **inside** the cage reaches to list and
//! invoke declared operations, plus a second, host-only socket carrying the invocation log.
//!
//! # Two sockets, on purpose
//!
//! Every other control plane in sbx (egress, `proc`, `fs`) is **never** bound into the cage, because
//! the in-cage agent is the adversary and must not answer its own asks. This one has to cross — an
//! agent that cannot reach it cannot invoke a task at all. So the surface that crosses is kept as
//! small as it can be (`LIST`, `SECRETS`, `RUN`), and the **log** lives on a separate socket that
//! stays host-only: what a session recorded is for the human, and the recorded party does not get to
//! read (or trim) it.
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
//! → LIST                          ← task <name>\tparams=a,b\t<description>… then `ok`
//! → SECRETS                       ← secret <name>\t<where>\t<description>… then `ok`
//! → RUN <name>                    ← exit <code>, redacted <n>, truncated <0|1>,
//!   param <key> <len>\n<bytes>       timed-out <0|1>, elapsed-ms <n>, [nonce <hex>],
//!   env <key> <len>\n<bytes>         stdout <len>\n<bytes>, stderr <len>\n<bytes>, then `ok`
//!   run
//! ```
//!
//! Any refusal is a single `err <message>` line. A message never echoes a caller's value back: a
//! value can carry the very secret a caller is probing for.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::task::{TaskEngine, TaskOutcome};

/// Where the crossing socket is bound **inside** the cage. Under `/tmp`, beside the egress socket,
/// colliding with no structural mount. Bound as the socket *file* (never its directory), so a caller
/// can connect through it but cannot unlink it and put its own listener in its place.
pub(crate) const CAGE_TASK_UDS: &str = "/tmp/sbx-task.sock";

/// The environment variable that tells an in-cage tool the task plane is available, and where. The
/// discovery handle, like `SBX_EGRESS_CONTRACT` for the egress contract.
pub(crate) const TASK_SOCKET_ENV: &str = "SBX_TASK_SOCKET";

/// Where sbx's own binary is bound read-only inside the cage, as the task client. Under `/opt/sbx`,
/// beside the egress contract and the mise plugin.
///
/// It is the same binary, not a separate shim, so the client and the server can never drift — but
/// nothing else about it becomes reachable: the cage never sees sbx's data directory or its config,
/// so every other subcommand has nothing to work on. The task client's authority is the socket, and
/// the policy stays host-side behind it.
pub(crate) const TASK_SHIM_INCAGE: &str = "/opt/sbx/bin/sbx";

/// How many invocations a session retains in its log ring.
const LOG_CAPACITY: usize = 512;

/// The default ceiling on invocations per session — a task is a brokered operation, not a loop
/// primitive, and an exit-status oracle over a credential gets cheaper the more calls it can make.
/// Reaching it refuses further invocations rather than degrading anything silently.
const DEFAULT_CALL_QUOTA: u64 = 500;

/// One recorded invocation. The command is **not** recorded — it is fixed by the declaration, so the
/// task name identifies it — and no parameter value is recorded either: a value can carry a secret,
/// and the point of the log is who ran what, when, and what it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEntry {
    pub(crate) seq: u64,
    /// Unix seconds when the invocation finished.
    pub(crate) at: u64,
    pub(crate) task: String,
    pub(crate) exit: i32,
    pub(crate) redacted: usize,
    pub(crate) truncated: bool,
    pub(crate) timed_out: bool,
    pub(crate) elapsed_ms: u64,
    /// A refusal reason, when the invocation never ran.
    pub(crate) refused: Option<String>,
}

impl LogEntry {
    /// One `event …` line, for the log socket. Fixed fields first; the optional refusal reason is
    /// **last** and taken verbatim by the reader, since it is the only free-text field.
    fn to_line(&self) -> String {
        let mut line = format!(
            "event seq={} at={} exit={} redacted={} truncated={} timed_out={} elapsed_ms={} task={}",
            self.seq,
            self.at,
            self.exit,
            self.redacted,
            u8::from(self.truncated),
            u8::from(self.timed_out),
            self.elapsed_ms,
            sanitize(&self.task),
        );
        if let Some(reason) = &self.refused {
            line.push_str(&format!(" refused={}", sanitize(reason)));
        }
        line
    }
}

/// Flatten a value into one safe log field: control characters (a newline that would forge a second
/// event line, an escape that would drive a terminal) become spaces.
fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The session's bounded, in-RAM invocation log. Never written to disk and never readable from the
/// cage — it is the supervisor's own record for the session's lifetime, and it dies with it.
#[derive(Default)]
pub(crate) struct TaskLog {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next_seq: u64,
    entries: std::collections::VecDeque<LogEntry>,
    dropped: u64,
}

impl TaskLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record one invocation, evicting the oldest when the ring is full.
    fn push(&self, mut entry: LogEntry) {
        let mut inner = self.inner.lock().expect("task log");
        inner.next_seq += 1;
        entry.seq = inner.next_seq;
        entry.at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if inner.entries.len() == LOG_CAPACITY {
            inner.entries.pop_front();
            inner.dropped += 1;
        }
        inner.entries.push_back(entry);
    }

    /// The retained entries past `after`, plus how many fell out of the ring.
    fn since(&self, after: u64) -> (Vec<LogEntry>, u64) {
        let inner = self.inner.lock().expect("task log");
        (
            inner
                .entries
                .iter()
                .filter(|e| e.seq > after)
                .cloned()
                .collect(),
            inner.dropped,
        )
    }
}

/// A live task plane: the two listeners' threads and the paths they own. Dropping it removes the
/// socket files, so a session leaves nothing behind for the next one to trip over.
pub(crate) struct TaskPlane {
    /// The crossing socket's host path — what the launcher binds into the cage.
    pub(crate) cage_socket: PathBuf,
    /// The host-only log socket's path.
    log_socket: PathBuf,
    dir: PathBuf,
}

impl Drop for TaskPlane {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cage_socket);
        let _ = std::fs::remove_file(&self.log_socket);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// The directory a session's task sockets live in, under the `0700` data dir.
pub(crate) fn task_dir(data_dir: &Path, pid: u32) -> PathBuf {
    data_dir.join("tasks").join(pid.to_string())
}

/// The host-only log socket for a session pid.
pub(crate) fn log_socket(data_dir: &Path, pid: u32) -> PathBuf {
    task_dir(data_dir, pid).join("log.sock")
}

/// Stand up the task plane for one session: bind both sockets and serve each on its own thread.
///
/// The engine is shared (`Arc`) with the serve threads; each invocation runs on the connection's
/// thread, so a long task blocks only its own caller.
pub(crate) fn start(data_dir: &Path, pid: u32, engine: TaskEngine) -> io::Result<TaskPlane> {
    let dir = task_dir(data_dir, pid);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;

    let cage_socket = dir.join("control.sock");
    let log_path = log_socket(data_dir, pid);
    // A leftover from a crashed session would make the bind fail; the directory is per-pid and
    // owner-only, so removing a stale socket here is safe.
    let _ = std::fs::remove_file(&cage_socket);
    let _ = std::fs::remove_file(&log_path);

    let engine = Arc::new(engine);
    let log = Arc::new(TaskLog::new());
    let quota = Arc::new(AtomicU64::new(DEFAULT_CALL_QUOTA));

    let cage_listener = UnixListener::bind(&cage_socket)?;
    let log_listener = UnixListener::bind(&log_path)?;

    {
        let engine = Arc::clone(&engine);
        let log = Arc::clone(&log);
        let quota = Arc::clone(&quota);
        std::thread::spawn(move || {
            for stream in cage_listener.incoming().flatten() {
                let engine = Arc::clone(&engine);
                let log = Arc::clone(&log);
                let quota = Arc::clone(&quota);
                // One thread per connection: an invocation runs for as long as its task's timeout,
                // and a second caller must not queue behind it.
                std::thread::spawn(move || {
                    let _ = serve_cage(stream, &engine, &log, &quota);
                });
            }
        });
    }
    {
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for stream in log_listener.incoming().flatten() {
                let _ = serve_log(stream, &log);
            }
        });
    }

    Ok(TaskPlane {
        cage_socket,
        log_socket: log_path,
        dir,
    })
}

/// Serve one connection on the crossing socket.
fn serve_cage(
    stream: UnixStream,
    engine: &TaskEngine,
    log: &TaskLog,
    quota: &AtomicU64,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut command = String::new();
    if reader.read_line(&mut command)? == 0 {
        return Ok(());
    }
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
            writeln!(
                writer,
                "task {}\tparams={}\tstdout={}\tstderr={}\ttimeout={}s{}\t{}",
                task.name,
                params.join(","),
                task.stdout.as_str(),
                task.stderr.as_str(),
                task.timeout.as_secs(),
                missing,
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

/// Read a `RUN`'s parameter/environment payloads, invoke the task, and write the result.
fn serve_run(
    reader: &mut BufReader<UnixStream>,
    writer: &mut UnixStream,
    name: &str,
    engine: &TaskEngine,
    log: &TaskLog,
    quota: &AtomicU64,
) -> io::Result<()> {
    let mut params = BTreeMap::new();
    let mut env = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return writeln!(writer, "err truncated request");
        }
        let line = line.trim_end();
        if line == "run" {
            break;
        }
        let Some((kind, rest)) = line.split_once(' ') else {
            return writeln!(writer, "err malformed request line");
        };
        let Some((key, len)) = rest.rsplit_once(' ') else {
            return writeln!(writer, "err malformed request line");
        };
        let Ok(len) = len.parse::<usize>() else {
            return writeln!(writer, "err malformed payload length");
        };
        // A caller must not be able to make sbx allocate arbitrarily: one payload is bounded well
        // above any legitimate parameter and far below anything that would matter.
        if len > 1 << 20 {
            return writeln!(writer, "err payload too large");
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        let mut newline = String::new();
        let _ = reader.read_line(&mut newline);
        let value = String::from_utf8_lossy(&buf).into_owned();
        match kind {
            "param" => params.insert(key.to_string(), value),
            "env" => env.insert(key.to_string(), value),
            _ => return writeln!(writer, "err unknown request field"),
        };
    }

    // The quota is decremented before the run, so a refusal is recorded once and a concurrent pair
    // of callers cannot both slip past the last slot.
    if quota
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
            (left > 0).then(|| left - 1)
        })
        .is_err()
    {
        let reason = "this session's task quota is exhausted".to_string();
        log.push(refusal(name, &reason));
        return writeln!(writer, "err {reason}");
    }

    match engine.run(name, &params, &env) {
        Ok(outcome) => {
            log.push(LogEntry {
                seq: 0,
                at: 0,
                task: name.to_string(),
                exit: outcome.exit,
                redacted: outcome.redacted,
                truncated: outcome.truncated,
                timed_out: outcome.timed_out,
                elapsed_ms: outcome.elapsed_ms,
                refused: None,
            });
            write_outcome(writer, &outcome)
        }
        Err(e) => {
            let reason = e.to_string();
            log.push(refusal(name, &reason));
            writeln!(writer, "err {}", sanitize(&reason))
        }
    }
}

/// A log entry for an invocation that never ran.
fn refusal(task: &str, reason: &str) -> LogEntry {
    LogEntry {
        seq: 0,
        at: 0,
        task: task.to_string(),
        exit: -1,
        redacted: 0,
        truncated: false,
        timed_out: false,
        elapsed_ms: 0,
        refused: Some(reason.to_string()),
    }
}

/// Write one outcome in the response shape. A withheld stream is `-1`, distinct from an empty one
/// (`0`), so a caller can tell "the declaration hides this" from "the command printed nothing".
fn write_outcome(writer: &mut UnixStream, outcome: &TaskOutcome) -> io::Result<()> {
    writeln!(writer, "exit {}", outcome.exit)?;
    writeln!(writer, "redacted {}", outcome.redacted)?;
    writeln!(writer, "truncated {}", u8::from(outcome.truncated))?;
    writeln!(writer, "timed-out {}", u8::from(outcome.timed_out))?;
    writeln!(writer, "elapsed-ms {}", outcome.elapsed_ms)?;
    // The invocation's substitution nonce, when the section enabled it — out of band, which is the
    // whole point: a `${NAME@nonce}` in the *text* is only unforgeable because the nonce arrives
    // here, where the command that produced the text could not have seen it.
    if let Some(nonce) = &outcome.nonce {
        writeln!(writer, "nonce {nonce}")?;
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

/// Serve one connection on the host-only log socket: `LOG` or `LOG after=<seq>`.
fn serve_log(stream: UnixStream, log: &TaskLog) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut command = String::new();
    if reader.read_line(&mut command)? == 0 {
        return Ok(());
    }
    let command = command.trim_end();
    let after = match command.strip_prefix("LOG") {
        None => return writeln!(writer, "err unknown command"),
        Some(rest) => rest
            .trim()
            .strip_prefix("after=")
            .and_then(|n| n.trim().parse::<u64>().ok())
            .unwrap_or(0),
    };
    let (entries, dropped) = log.since(after);
    if dropped > 0 {
        writeln!(writer, "dropped={dropped}")?;
    }
    for entry in &entries {
        writeln!(writer, "{}", entry.to_line())?;
    }
    writeln!(writer, "ok")
}

/// Read one session's invocation log, host-side. The counterpart of [`serve_log`]; it only reads.
pub(crate) fn read_log(socket: &Path) -> io::Result<Vec<String>> {
    let mut stream = UnixStream::connect(socket)?;
    writeln!(stream, "LOG")?;
    stream.flush()?;
    let mut text = String::new();
    BufReader::new(stream).read_to_string(&mut text)?;
    Ok(text.lines().map(str::to_string).collect())
}

/// The session pids that have a task log socket present, sorted. A superset of the live sessions: a
/// stale socket from a crashed launch is listed, but connecting to it simply fails and the caller
/// skips it — the same discovery model as the other control planes.
pub(crate) fn session_pids(data_dir: &Path) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(data_dir.join("tasks")) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids
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
        let mut stream = UnixStream::connect(socket)?;
        writeln!(stream, "RUN {name}")?;
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

    /// A parsed invocation result.
    #[derive(Debug, Clone, PartialEq, Eq, Default)]
    pub(crate) struct RunResult {
        pub(crate) exit: i32,
        pub(crate) stdout: Option<String>,
        pub(crate) stderr: Option<String>,
        pub(crate) redacted: usize,
        pub(crate) truncated: bool,
        pub(crate) timed_out: bool,
        pub(crate) elapsed_ms: u64,
        /// This invocation's substitution nonce, when the section enabled it — the out-of-band half
        /// of an unforgeable `${NAME@nonce}` placeholder.
        pub(crate) nonce: Option<String>,
        /// The refusal message when the plane answered `err …`.
        pub(crate) error: Option<String>,
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
                "exit" => out.exit = value.parse().unwrap_or(-1),
                "redacted" => out.redacted = value.parse().unwrap_or(0),
                "truncated" => out.truncated = value == "1",
                "timed-out" => out.timed_out = value == "1",
                "elapsed-ms" => out.elapsed_ms = value.parse().unwrap_or(0),
                "nonce" => out.nonce = Some(value.to_string()),
                "stdout" | "stderr" => {
                    let len: i64 = value.parse().unwrap_or(-1);
                    if len < 0 {
                        continue; // the declaration hides this stream
                    }
                    let len = (len as usize).min(rest.len());
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
mod tests {
    use super::*;

    fn entry(task: &str, exit: i32) -> LogEntry {
        LogEntry {
            seq: 0,
            at: 0,
            task: task.to_string(),
            exit,
            redacted: 2,
            truncated: false,
            timed_out: false,
            elapsed_ms: 12,
            refused: None,
        }
    }

    // The log is the trustworthy record: sbx assigns the sequence and the timestamp, and the
    // substitution count is host-side — none of it is anything a caller can forge.
    #[test]
    fn the_log_assigns_sequence_numbers_and_retains_in_order() {
        let log = TaskLog::new();
        log.push(entry("db-query", 0));
        log.push(entry("db-query", 1));
        let (entries, dropped) = log.since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[1].seq, 2);
        assert_eq!(dropped, 0);
        assert!(entries[0].at > 0, "the timestamp is stamped host-side");

        let (tail, _) = log.since(1);
        assert_eq!(tail.len(), 1, "a cursor returns only what is past it");
        assert_eq!(tail[0].seq, 2);
    }

    // A refusal is recorded too — a caller probing a task it may not run is exactly what a human
    // reading the log wants to see.
    #[test]
    fn a_refusal_is_recorded_with_its_reason() {
        let log = TaskLog::new();
        log.push(refusal("db-query", "parameter `sql` does not match"));
        let (entries, _) = log.since(0);
        let line = entries[0].to_line();
        assert!(line.contains("task=db-query"), "{line}");
        assert!(line.contains("refused=parameter"), "{line}");
    }

    // A task name or a refusal reason carrying a newline must not be able to forge a second event
    // line in the log a human reads.
    #[test]
    fn a_control_character_cannot_forge_a_second_log_line() {
        let log = TaskLog::new();
        log.push(refusal("db-query", "bad\nevent seq=99 exit=0 task=forged"));
        let (entries, _) = log.since(0);
        let line = entries[0].to_line();
        assert_eq!(line.lines().count(), 1, "one entry is one line: {line}");
        assert!(!line.contains("\nevent"), "{line}");
    }

    #[test]
    fn the_ring_evicts_the_oldest_and_reports_the_drop() {
        let log = TaskLog::new();
        for _ in 0..LOG_CAPACITY + 3 {
            log.push(entry("t", 0));
        }
        let (entries, dropped) = log.since(0);
        assert_eq!(entries.len(), LOG_CAPACITY);
        assert_eq!(dropped, 3);
    }

    // The response parser reads each stream by byte count, so a payload that happens to contain the
    // protocol's own keywords is returned verbatim instead of being re-parsed as headers.
    #[test]
    fn the_run_parser_takes_streams_by_length_not_by_keyword() {
        let payload = "exit 42\nok\nstderr 7\n";
        let raw = format!(
            "exit 0\nredacted 1\ntruncated 0\ntimed-out 0\nelapsed-ms 5\nstdout {}\n{}\nstderr -1\nok\n",
            payload.len(),
            payload
        );
        let parsed = client::parse_run(raw.as_bytes()).unwrap();
        assert_eq!(parsed.exit, 0);
        assert_eq!(parsed.redacted, 1);
        assert_eq!(parsed.stdout.as_deref(), Some(payload));
        assert_eq!(
            parsed.stderr, None,
            "a hidden stream is absent, not empty — the two must stay distinguishable"
        );
        assert!(parsed.error.is_none());
    }

    // The nonce must survive the socket: a `${NAME@nonce}` in the text is unforgeable only because
    // the nonce arrives out of band. Computing it and dropping it here would remove the property.
    #[test]
    fn the_nonce_crosses_the_wire_out_of_band() {
        let raw =
            "exit 0\nredacted 1\nnonce a91f3c\nstdout 22\ntok=${DEMO@a91f3c} ok\nstderr -1\nok\n";
        let parsed = client::parse_run(raw.as_bytes()).unwrap();
        assert_eq!(parsed.nonce.as_deref(), Some("a91f3c"));
        assert!(parsed.stdout.unwrap().contains("${DEMO@a91f3c}"));

        // Without the flag there is no nonce line, and none is invented.
        let plain = client::parse_run(b"exit 0\nredacted 0\nstdout -1\nstderr -1\nok\n").unwrap();
        assert_eq!(plain.nonce, None);
    }

    #[test]
    fn the_run_parser_surfaces_a_refusal() {
        let parsed = client::parse_run(b"err parameter `sql` is required\n").unwrap();
        assert_eq!(parsed.error.as_deref(), Some("parameter `sql` is required"));
    }

    // An empty stream and a withheld one are different answers, and the wire keeps them apart.
    #[test]
    fn an_empty_stream_is_not_a_withheld_one() {
        let raw = "exit 0\nstdout 0\n\nstderr -1\nok\n";
        let parsed = client::parse_run(raw.as_bytes()).unwrap();
        assert_eq!(parsed.stdout.as_deref(), Some(""));
        assert_eq!(parsed.stderr, None);
    }
}
