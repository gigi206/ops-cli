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
//! → LIST                          ← task <name>\tparams=a,b\t<description>… then `ok`
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
//! → LOG [after=<seq>]             ← [dropped=<n>], event seq=<id> …… then `ok`
//! → STATUS                        ← running <id>\ttask=<name>\telapsed_ms=<n>…  then `ok`
//! → STOP <id>                     ← stopped <id> | stopping <id> | finished <id>, then `ok`
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

/// The default ceiling on invocations per session — a task is a brokered operation, not a loop
/// primitive, and an exit-status oracle over a credential gets cheaper the more calls it can make.
/// Reaching it refuses further invocations rather than degrading anything silently.
const DEFAULT_CALL_QUOTA: u64 = 500;

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
    /// Unix seconds when the invocation finished.
    pub(crate) at: u64,
    pub(crate) task: String,
    pub(crate) exit: i32,
    pub(crate) redacted: usize,
    pub(crate) truncated: bool,
    pub(crate) timed_out: bool,
    /// Whether `sbx task stop` ended it — recorded separately from `timed_out` because they are
    /// different events with the same effect.
    pub(crate) stopped: bool,
    pub(crate) elapsed_ms: u64,
    /// A refusal reason, when the invocation never ran.
    pub(crate) refused: Option<String>,
}

impl LogEntry {
    /// One `event …` line, for the log socket. Fixed fields first; the optional refusal reason is
    /// **last** and taken verbatim by the reader, since it is the only free-text field.
    fn to_line(&self) -> String {
        let mut line = format!(
            "event seq={} at={} exit={} redacted={} truncated={} timed_out={} stopped={} \
             elapsed_ms={} task={}",
            self.seq,
            self.at,
            self.exit,
            self.redacted,
            u8::from(self.truncated),
            u8::from(self.timed_out),
            u8::from(self.stopped),
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
    entries: std::collections::VecDeque<LogEntry>,
    dropped: u64,
}

impl TaskLog {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Record one invocation, evicting the oldest when the ring is full.
    ///
    /// The entry arrives carrying its own id — the invocation's, drawn when it was admitted. The log
    /// stamps only the time, which is the one field it is the authority on: an invocation that ran
    /// under a credential does not get to say when it finished.
    fn push(&self, mut entry: LogEntry) {
        let mut inner = self.inner.lock().expect("task log");
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
    ///
    /// `after` is a cursor over invocation ids, and an id is drawn when its invocation is *admitted*
    /// while its entry lands when it *finishes* — so a long invocation admitted before a short one
    /// can be recorded after it, and a reader that has already moved its cursor past the short one
    /// will not see it. Which is why nothing follows this log: `read_log` asks for all of it.
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

    /// Whether an invocation with this id has already been recorded — what tells "you are too late"
    /// from "there is no such invocation" when a stop names one that is not running.
    fn recorded(&self, id: u64) -> bool {
        self.entry(id).is_some()
    }

    /// What the ring kept about one invocation.
    fn entry(&self, id: u64) -> Option<LogEntry> {
        let inner = self.inner.lock().expect("task log");
        inner.entries.iter().find(|e| e.seq == id).cloned()
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
        let engine = Arc::clone(&engine);
        let log = Arc::clone(&log);
        std::thread::spawn(move || {
            for stream in log_listener.incoming().flatten() {
                let engine = Arc::clone(&engine);
                let log = Arc::clone(&log);
                // Its own thread for the same reason the crossing socket's connections get one: a
                // `STOP` waits for the invocation to end, and a `STATUS` behind it must not queue
                // behind that wait.
                std::thread::spawn(move || {
                    let _ = serve_host(stream, &engine, &log);
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
            // Where this operation's artifacts will be, when it declares `output`. Listed rather
            // than only reported afterwards: the path is one per task, so a caller can know it
            // before invoking anything — which is the whole reason it is not per invocation.
            let output = match task.output {
                false => String::new(),
                true => format!("\toutput={}/{}", super::task::TASK_OUT_AGENT, task.name),
            };
            writeln!(
                writer,
                "task {}\tparams={}\tstdout={}\tstderr={}\ttimeout={}s{}{}\t{}",
                task.name,
                params.join(","),
                task.stdout.as_str(),
                task.stderr.as_str(),
                task.timeout.as_secs(),
                missing,
                output,
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
        // Id `0`: nothing was admitted, so there is no invocation for an id to name. It is also what
        // keeps the id inside the width the socket paths were sized against — the quota is the bound
        // on how many are ever drawn.
        log.push(refusal(0, name, &reason));
        return writeln!(writer, "err {reason}");
    }

    // Admitted: from here the invocation has an identity, and it is the *same* number wherever it
    // appears — in the host-side names it stands up, in the row `sbx task status` shows while it
    // runs, in the id `sbx task stop` takes, and in the line it leaves in this log. Drawn here
    // rather than inside the engine so a refusal the engine returns is recorded under it too.
    let id = super::task::next_invocation();

    match engine.run(name, &params, &env, id) {
        Ok(outcome) => {
            log.push(LogEntry {
                seq: id,
                at: 0,
                task: name.to_string(),
                exit: outcome.exit,
                redacted: outcome.redacted,
                truncated: outcome.truncated,
                timed_out: outcome.timed_out,
                stopped: outcome.stopped,
                elapsed_ms: outcome.elapsed_ms,
                refused: None,
            });
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
            ("finished_at".to_string(), entry.at.to_string()),
            ("elapsed_ms".to_string(), entry.elapsed_ms.to_string()),
        ];
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
        at: 0,
        task: task.to_string(),
        exit: -1,
        redacted: 0,
        truncated: false,
        timed_out: false,
        stopped: false,
        elapsed_ms: 0,
        refused: Some(reason.to_string()),
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
    // What `spawn` refused. One line per target, because which program was refused is the whole
    // content of the report — a count would say "something you declared is missing" and leave the
    // caller to guess which. The path carries no space (it is an exec target the cage resolved), so
    // the line-based framing holds.
    for target in &outcome.refused {
        writeln!(writer, "refused-exec {target}")?;
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

/// Serve one connection on the session's host-only socket: `LOG` (optionally `after=<seq>`),
/// `STATUS`, or `STOP <id>`.
///
/// All three are here rather than on the crossing socket, and that placement *is* the access
/// control: this socket is never bound into a cage, so the in-cage client cannot express these verbs
/// however it is called. The reasons differ by verb and both matter. `LOG`: the recorded party does
/// not get to read the record. `STATUS`/`STOP`: ids are per session, so an in-cage caller reaching
/// them could see and end an invocation *another* caller started — the human at the terminal — and
/// nothing in the cage distinguishes the two, since a task plane has no per-caller identity.
fn serve_host(stream: UnixStream, engine: &TaskEngine, log: &TaskLog) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut command = String::new();
    if reader.read_line(&mut command)? == 0 {
        return Ok(());
    }
    let command = command.trim_end();

    if command == "STATUS" {
        for row in engine.running() {
            writeln!(
                writer,
                "running {}\ttask={}\telapsed_ms={}\tpid={}\tstopping={}",
                row.id,
                sanitize(&row.task),
                row.elapsed_ms,
                row.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                u8::from(row.stopping),
            )?;
        }
        return writeln!(writer, "ok");
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
                return writeln!(writer, "err no invocation {id}")
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
    let (entries, dropped) = log.since(after);
    if dropped > 0 {
        writeln!(writer, "dropped={dropped}")?;
    }
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

/// Read one session's invocation log, host-side. The counterpart of [`serve_host`]; it only reads.
pub(crate) fn read_log(socket: &Path) -> io::Result<Vec<String>> {
    ask_host(socket, "LOG")
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
        /// The exec targets `spawn` refused during the invocation. Carried because the refusal is
        /// invisible in the result otherwise — the refused program decides whether to mention it.
        pub(crate) refused: Vec<String>,
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
                "refused-exec" => out.refused.push(value.to_string()),
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
    use crate::config::{OutputDisposition, ParamBound, TaskParam, TaskSpec};
    use crate::testutil::TmpDir;
    use std::process::Command;
    use std::time::Duration;

    /// A value with the two properties a line-oriented client would get wrong: an embedded newline
    /// (which would forge a protocol line if it were not length-framed) and a multi-byte character
    /// (which a client counting characters instead of bytes would under-announce).
    const AWKWARD: &str = "SELECT 1\nFROM caf\u{e9}";

    fn probe_task() -> TaskSpec {
        TaskSpec {
            name: "probe".into(),
            description: Some("a declared operation for the wire".into()),
            cmd: vec!["/nonexistent/program".into(), "{sql}".into()],
            // A closed choice makes the server the oracle: it accepts the invocation only if the
            // exact bytes arrived, so "the value crossed intact" is something the plane decides
            // rather than something the test asserts about itself.
            params: vec![TaskParam {
                name: "sql".into(),
                bound: ParamBound::Choices(vec![AWKWARD.to_string()]),
                default: None,
            }],
            secrets: vec![],
            injections: vec![],
            env: BTreeMap::new(),
            env_allow: vec![],
            stdout: OutputDisposition::Show,
            stderr: OutputDisposition::Show,
            timeout: Duration::from_secs(30),
            max_output: 4096,
            network: vec![],
            nonce: false,
            packages: vec![],
            spawn: None,
            output: false,
        }
    }

    /// A live plane serving `tasks`, plus a client script pointed at it.
    ///
    /// The server is the production one — [`start`] and [`serve_cage`], not a stand-in — and the
    /// client is written by the production generator. Only the programs differ: the shipped client
    /// names the cage's shell and `socat`, and here it names the host's, because that is what a test
    /// process can execute. That the launcher passes the cage's own is a separate, static fact.
    fn plane_and_client(tasks: Vec<TaskSpec>) -> Option<(TmpDir, TaskPlane, PathBuf)> {
        let bash = crate::pathfind::find_on_path("bash")?;
        let socat = crate::pathfind::find_on_path("socat")?;
        let head = crate::pathfind::find_on_path("head")?;
        let data = TmpDir::new();
        let engine = super::super::task::TaskEngine::inventory_only(tasks);
        let programs = ClientPrograms {
            bash: &bash,
            socat: &socat,
            head: &head,
        };
        let plane = start(data.path(), std::process::id(), engine, &programs).expect("start");
        let script = data.path().join("client");
        super::super::task_shim::write(
            &script,
            &bash,
            &socat,
            &head,
            plane.cage_socket.to_str().expect("a utf-8 socket path"),
        )
        .expect("write the client");
        Some((data, plane, script))
    }

    /// A directory left by a session that is gone is neither listed nor left behind.
    ///
    /// Nothing removes it at the time: a `SIGKILL`ed launcher never runs its `Drop`, and stopping a
    /// session sweeps its process tree, not its files. So the listing has to be the thing that
    /// heals — otherwise naming a session degrades, after a few crashes, into choosing among pids
    /// that are all dead.
    #[test]
    fn a_dead_sessions_directory_is_neither_listed_nor_left_behind() {
        let data = TmpDir::new();
        let live = std::process::id();

        // A directory stamped with an incarnation that is not this process's: whatever pid wrote it,
        // that incarnation is gone. Pid 1 is certain to exist and equally certain not to have this
        // start time, so the pair fails while the bare pid would have passed.
        let dead = task_dir(data.path(), 1);
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::write(dead.join("incarnation"), "1").unwrap();
        std::fs::write(dead.join("control.sock"), "not really a socket").unwrap();

        let mine = task_dir(data.path(), live);
        std::fs::create_dir_all(&mine).unwrap();
        let ticks = crate::session::read_start_ticks(live).expect("our own start time");
        std::fs::write(mine.join("incarnation"), ticks.to_string()).unwrap();

        assert_eq!(
            session_pids(data.path()),
            vec![live],
            "only a session that is still running may be offered to a caller"
        );
        assert!(
            !dead.exists(),
            "the dead session's directory must be removed, not merely skipped — otherwise it \
             accumulates until the listing is useless"
        );
        assert!(mine.exists(), "the live session's directory must survive");
    }

    /// A directory with no stamp yet is the one being created right now, so it is left alone while
    /// its pid runs. Removing it would take a starting session's sockets with it.
    #[test]
    fn an_unstamped_directory_survives_while_its_process_runs() {
        let data = TmpDir::new();
        let live = std::process::id();
        let dir = task_dir(data.path(), live);
        std::fs::create_dir_all(&dir).unwrap();

        assert_eq!(session_pids(data.path()), vec![live]);
        assert!(dir.exists(), "a plane mid-creation must not be swept away");
    }

    /// Starting a plane stamps the directory, which is what makes the check above possible at all.
    #[test]
    fn a_started_plane_records_which_incarnation_owns_its_directory() {
        let Some((data, _plane, _script)) = plane_and_client(vec![probe_task()]) else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let stamp = task_dir(data.path(), std::process::id()).join("incarnation");
        let recorded: u64 = std::fs::read_to_string(&stamp)
            .expect("the plane must stamp its directory")
            .trim()
            .parse()
            .expect("the stamp is the start time in ticks");
        assert_eq!(
            Some(recorded),
            crate::session::read_start_ticks(std::process::id()),
            "the stamp must name this incarnation, not merely this pid"
        );
    }

    /// A plane whose invocations take `seconds` to answer, plus the client that talks to it.
    ///
    /// The launcher is a script standing in for bubblewrap: it ignores the cage argv, waits, and
    /// prints. That is the only way to exercise what a real operation does to the wire — take time.
    fn slow_plane_and_client(seconds: &str) -> Option<(TmpDir, TaskPlane, PathBuf)> {
        plane_with_launcher(&format!("sleep {seconds}\nprintf 'the-answer\\n'\n"))
    }

    /// A plane whose cage is `body` — a script standing in for bubblewrap — plus the client script.
    fn plane_with_launcher(body: &str) -> Option<(TmpDir, TaskPlane, PathBuf)> {
        use std::os::unix::fs::PermissionsExt;
        let bash = crate::pathfind::find_on_path("bash")?;
        let socat = crate::pathfind::find_on_path("socat")?;
        let head = crate::pathfind::find_on_path("head")?;
        let data = TmpDir::new();

        let launcher = data.path().join("slow-launcher");
        std::fs::write(&launcher, format!("#!{}\n{body}", bash.display()))
            .expect("write the launcher");
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
            .expect("make the launcher executable");

        let engine = super::super::task::TaskEngine::inventory_only(vec![probe_task()])
            .with_launcher(launcher);
        let programs = ClientPrograms {
            bash: &bash,
            socat: &socat,
            head: &head,
        };
        let plane = start(data.path(), std::process::id(), engine, &programs).expect("start");
        let script = data.path().join("client");
        super::super::task_shim::write(
            &script,
            &bash,
            &socat,
            &head,
            plane.cage_socket.to_str().expect("a utf-8 socket path"),
        )
        .expect("write the client");
        Some((data, plane, script))
    }

    /// An operation that takes longer than an instant still answers the in-cage caller.
    ///
    /// The transport under the client is `socat`, which by default gives the far end half a second
    /// after this side stops writing and then tears the connection down — so an operation that runs
    /// for two seconds returned a truncated answer, while the very same call succeeded host-side.
    /// A declared operation is a command being run; taking time is its normal case, not its edge.
    #[test]
    fn an_operation_that_takes_seconds_still_answers_the_cage() {
        let Some((_data, _plane, script)) = slow_plane_and_client("2") else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let out = run_client(
            &script,
            &["task", "run", "probe", "-p", &format!("sql={AWKWARD}")],
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains("the-answer"),
            "the operation's output must survive the wait: stdout={stdout} stderr={stderr}"
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "the operation's own exit code must come back: stderr={stderr}"
        );
    }

    /// A running invocation is visible, stoppable by the id it is visible under, and the result says
    /// it was **stopped** rather than timed out.
    ///
    /// The whole feature is here: `status` and `stop` are the same number as the log's, the stop
    /// reaches a command that is genuinely mid-run, and the answer stays distinguishable from the
    /// timeout it shares a lever with. `timed_out` staying false is the load-bearing assertion — both
    /// paths kill the same cage the same way, and only the field tells a person which happened.
    ///
    /// The launcher `exec`s its sleep so that the killed process is the one holding the pipes, the
    /// way bubblewrap is in a real cage (it is the pid-namespace init, so nothing survives it).
    #[test]
    fn a_running_invocation_is_stopped_by_the_id_status_shows() {
        let Some((data, plane, _script)) = plane_with_launcher("exec sleep 20\n") else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let host = plane.log_socket.clone();
        let cage = plane.cage_socket.clone();
        let caller = std::thread::spawn(move || {
            client::run(
                &cage,
                "probe",
                &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
                &BTreeMap::new(),
            )
        });

        // The id cannot be predicted — the counter is per process and these tests share one — so it
        // is read the way a person reads it.
        let mut id = None;
        for _ in 0..200 {
            if let Some(row) = read_status(&host).expect("status").first() {
                id = Some(row.id);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let id = id.expect("the running invocation must be visible while it runs");

        let reply = stop_invocation(&host, id).expect("stop");
        assert_eq!(
            reply,
            StopReply::Stopped,
            "the plane waits to see the invocation end before it reports one"
        );

        let result = caller.join().expect("the caller thread").expect("a result");
        assert!(result.stopped, "the result must say it was stopped");
        assert!(
            !result.timed_out,
            "a stop is not a timeout: {}ms",
            result.elapsed_ms
        );
        assert_eq!(result.id, id, "one id, whichever verb reports it");
        assert!(
            result.elapsed_ms < 15_000,
            "the stop must land well before the 30s timeout, not read as one: {}ms",
            result.elapsed_ms
        );

        assert!(
            read_status(&host).expect("status").is_empty(),
            "a stopped invocation is no longer running"
        );
        let line = read_log(&host)
            .expect("log")
            .into_iter()
            .find(|l| l.starts_with("event "))
            .expect("the invocation is recorded");
        assert!(
            line.contains(&format!("seq={id} ")),
            "the log carries the same id status showed: {line}"
        );
        assert!(line.contains("stopped=1"), "{line}");
        assert!(line.contains("timed_out=0"), "{line}");
        drop(data);
    }

    /// `info` answers about a live invocation, and the answer carries the command with this
    /// invocation's parameters substituted in — but **no environment value**, which is the whole
    /// point of a task carrying a credential the caller never holds.
    #[test]
    fn info_shows_what_an_invocation_runs_and_never_what_it_carries() {
        let Some((_data, plane, _script)) = plane_with_launcher("exec sleep 20\n") else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let host = plane.log_socket.clone();
        let cage = plane.cage_socket.clone();
        let caller = std::thread::spawn(move || {
            client::run(
                &cage,
                "probe",
                &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
                &BTreeMap::new(),
            )
        });

        let mut id = None;
        for _ in 0..200 {
            if let Some(row) = read_status(&host).expect("status").first() {
                id = Some(row.id);
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let id = id.expect("the invocation must be visible while it runs");

        let fields = read_info(&host, &id.to_string()).expect("info");
        let field = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(field("id"), id.to_string());
        assert_eq!(field("operation"), "probe");
        assert_eq!(field("state"), "running");
        assert!(
            field("command").contains("caf"),
            "the command carries this invocation's parameter: {:?}",
            field("command")
        );
        assert_eq!(field("timeout_s"), "30", "the declaration travels with it");
        assert!(
            !fields.iter().any(|(k, _)| k == "environment" || k == "env"),
            "an environment value has no field to arrive in: {fields:?}"
        );
        // One line per field, always: a value with a newline in it (this parameter has one) must not
        // be able to forge a second field.
        assert!(
            !field("command").contains('\n'),
            "a field is one line: {:?}",
            field("command")
        );

        assert_eq!(
            stop_invocation(&host, id).expect("stop"),
            StopReply::Stopped
        );
        let _ = caller.join().expect("the caller thread");

        // And it still answers once the invocation is over — the log's half, plus the declaration.
        let after = read_info(&host, &id.to_string()).expect("info after");
        let state = after
            .iter()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.as_str())
            .unwrap_or_default();
        assert_eq!(state, "stopped", "{after:?}");
        assert!(
            after.iter().any(|(k, _)| k == "timeout_s"),
            "the declaration is what an invocation still is once it is over: {after:?}"
        );

        assert!(
            read_info(&host, "no-such-thing").is_err(),
            "a name nothing answers to is an error, not an empty record"
        );
    }

    /// A stop that names an invocation the session never had is refused, and one that names a
    /// finished invocation is told it is too late — two different things to be told.
    #[test]
    fn a_stop_tells_a_finished_invocation_from_an_unknown_one() {
        let Some((_data, plane, _script)) = plane_and_client(vec![probe_task()]) else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let host = plane.log_socket.clone();
        assert!(
            matches!(
                stop_invocation(&host, 4242).expect("stop"),
                StopReply::Refused(_)
            ),
            "an id this session never issued is not something to report as stopped"
        );

        // One real invocation, run to completion: the launcher does not exist, so it fails at once
        // and is recorded either way.
        let _ = client::run(
            &plane.cage_socket,
            "probe",
            &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
            &BTreeMap::new(),
        );
        let recorded: Vec<u64> = read_log(&host)
            .expect("log")
            .iter()
            .filter_map(|l| {
                l.strip_prefix("event seq=")?
                    .split(' ')
                    .next()?
                    .parse()
                    .ok()
            })
            .collect();
        let id = *recorded.first().expect("the invocation is recorded");
        assert_eq!(
            stop_invocation(&host, id).expect("stop"),
            StopReply::Finished,
            "an id the log knows is a finished invocation, not an unknown one"
        );
    }

    /// Execute the client the way a caller does — the file itself, through its shebang.
    ///
    /// The retry is a multithreaded-test artifact, not a property of the client: these tests write
    /// scripts and spawn processes concurrently in one process, so a spawn can inherit another
    /// thread's still-open write descriptor and make the exec fail with `ETXTBSY`. Nothing in a
    /// session does that — sbx writes the client, then bwrap binds it.
    fn run_client(script: &Path, args: &[&str]) -> std::process::Output {
        for _ in 0..100 {
            match Command::new(script).args(args).output() {
                Ok(out) => return out,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("run the client: {e}"),
            }
        }
        panic!("the client stayed busy: another thread held a write descriptor throughout");
    }

    // The listing verbs, end to end: the generated client's request is parsed by the real plane and
    // the real answer is rendered back. A change to either side's wording breaks this rather than
    // reaching a cage.
    #[test]
    fn the_client_lists_what_the_plane_serves() {
        let Some((_data, _plane, script)) = plane_and_client(vec![probe_task()]) else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let out = run_client(&script, &["task", "list"]);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{out:?}");
        assert!(text.starts_with("probe  "), "{text}");
        assert!(text.contains("params=sql"), "{text}");
        assert!(text.contains("timeout=30s"), "{text}");
        assert!(
            text.contains("a declared operation for the wire"),
            "the description must survive the tab columns: {text}"
        );
    }

    // The empty inventory has its own wording, and it must come from the client rather than from an
    // empty screen a caller would read as a failure.
    #[test]
    fn the_client_names_an_empty_inventory() {
        let Some((_data, _plane, script)) = plane_and_client(vec![]) else {
            return;
        };
        let out = run_client(&script, &["task", "secrets"]);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("no credentials are carried"),
            "{out:?}"
        );
    }

    // The load-bearing one. A parameter carrying a newline and a multi-byte character reaches the
    // plane byte-identical — proven by the plane itself, which admits the invocation only against
    // its declared choice. A desynchronised stream would instead come back as a protocol complaint.
    #[test]
    fn an_awkward_parameter_crosses_the_wire_byte_identical() {
        let Some((_data, _plane, script)) = plane_and_client(vec![probe_task()]) else {
            return;
        };
        let out = run_client(
            &script,
            &["task", "run", "probe", "-p", &format!("sql={AWKWARD}")],
        );
        let err = String::from_utf8_lossy(&out.stderr);
        for protocol_complaint in ["malformed", "unknown request field", "truncated request"] {
            assert!(
                !err.contains(protocol_complaint),
                "the request desynchronised: {err}"
            );
        }
        assert!(
            !err.contains("does not match") && !err.contains("is not one of"),
            "the plane judged the value unequal to the one that was sent: {err}"
        );
        // The plane admitted the value against its declared choice and went on to launch the
        // command, which is as far as an engine with no cage can get. That failure comes back as an
        // ordinary outcome — so this also pins the return path: the captured stderr crossed as a
        // length-framed stream and reached the caller's own descriptor.
        assert!(
            err.contains("/nonexistent/bwrap"),
            "the command's stderr must reach the caller verbatim: {err}"
        );
        assert_ne!(
            out.status.code(),
            Some(125),
            "the invocation ran, so this is the command's status and not a refusal: {err}"
        );
    }

    // A value the declaration does not admit is refused by the plane, not by the client — the same
    // bytes crossing, the opposite verdict. Together with the test above this pins that the oracle
    // is the plane's and that the client is not quietly filtering.
    #[test]
    fn a_value_outside_its_bound_is_refused_by_the_plane() {
        let Some((_data, _plane, script)) = plane_and_client(vec![probe_task()]) else {
            return;
        };
        let out = run_client(&script, &["task", "run", "probe", "-p", "sql=DROP TABLE t"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(125), "{err}");
        assert!(err.contains("sbx: task run:"), "{err}");
    }

    // A caller must be able to know where an operation's artifacts land *before* invoking it —
    // that is the reason the directory is one per task rather than one per invocation, and the
    // listing is where a caller is choosing what to invoke.
    #[test]
    fn the_listing_says_where_an_operation_writes() {
        let mut producing = probe_task();
        producing.name = "dump".into();
        producing.output = true;
        let Some((_data, _plane, script)) = plane_and_client(vec![producing, probe_task()]) else {
            eprintln!("skipping: bash, socat or head is not on PATH");
            return;
        };
        let out = run_client(&script, &["task", "list"]);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            text.contains("output=/opt/sbx/task-out/dump"),
            "the producing task must carry its path: {text}"
        );
        assert_eq!(
            text.matches("output=").count(),
            1,
            "and a task that declares none must carry no such field: {text}"
        );
    }

    // The response half, against the real writer: bytes produced by `write_outcome` are what the
    // client parses. Streams go to their own descriptors, the exit code is the command's, and a
    // payload containing the protocol's own keywords is copied rather than re-read as headers.
    #[test]
    fn the_client_parses_what_write_outcome_produces() {
        let Some(bash) = crate::pathfind::find_on_path("bash") else {
            return;
        };
        let (Some(socat), Some(head)) = (
            crate::pathfind::find_on_path("socat"),
            crate::pathfind::find_on_path("head"),
        ) else {
            return;
        };
        let dir = TmpDir::new();
        let socket = dir.path().join("replay.sock");
        let listener = UnixListener::bind(&socket).expect("bind");

        let outcome = super::super::task::TaskOutcome {
            exit: 3,
            stdout: Some("exit 42\nok\nstderr 7\n".to_string()),
            stderr: Some("caf\u{e9} warning\n".to_string()),
            truncated: true,
            redacted: 2,
            timed_out: false,
            stopped: false,
            elapsed_ms: 12,
            nonce: Some("a91f3c".to_string()),
            refused: Vec::new(),
            output: None,
        };
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                // Drain the request up to its terminator, so the client's write side never blocks.
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    if line.trim_end() == "run" {
                        break;
                    }
                    line.clear();
                }
                let mut writer = stream;
                let _ = write_outcome(&mut writer, 7, &outcome);
            }
        });

        let script = dir.path().join("client");
        super::super::task_shim::write(
            &script,
            &bash,
            &socat,
            &head,
            socket.to_str().expect("a utf-8 socket path"),
        )
        .expect("write the client");
        let out = run_client(&script, &["task", "run", "probe"]);

        assert_eq!(out.status.code(), Some(3), "the command's own exit code");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "exit 42\nok\nstderr 7\n",
            "a payload carrying the protocol's keywords is copied, never re-parsed"
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("caf\u{e9} warning"), "{err}");
        assert!(err.contains("was truncated"), "{err}");
        assert!(err.contains("2 credential value(s)"), "{err}");
        assert!(
            err.contains("nonce is a91f3c"),
            "the nonce arrives out of band and must be reported: {err}"
        );
    }

    // A refusal leaves no trace in the result: the refused program decides for itself whether to say
    // anything, and many say nothing — so an empty output and a success code would be all a caller
    // saw. The report has to cross the wire and reach the caller, naming what was refused, or
    // declaring `spawn` turns a missing entry into an unexplainable command.
    #[test]
    fn a_refused_exec_is_reported_to_the_caller_by_name() {
        let Some(bash) = crate::pathfind::find_on_path("bash") else {
            return;
        };
        let (Some(socat), Some(head)) = (
            crate::pathfind::find_on_path("socat"),
            crate::pathfind::find_on_path("head"),
        ) else {
            return;
        };
        let dir = TmpDir::new();
        let socket = dir.path().join("replay.sock");
        let listener = UnixListener::bind(&socket).expect("bind");

        let outcome = super::super::task::TaskOutcome {
            exit: 0,
            // What a refused `psql \!` actually looks like: nothing printed, a success code.
            stdout: Some(String::new()),
            stderr: Some(String::new()),
            truncated: false,
            redacted: 0,
            timed_out: false,
            stopped: false,
            elapsed_ms: 4,
            nonce: None,
            refused: vec![
                "/nix/store/demo/bin/sh".to_string(),
                "/nix/store/demo/bin/base64".to_string(),
            ],
            output: None,
        };
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    if line.trim_end() == "run" {
                        break;
                    }
                    line.clear();
                }
                let mut writer = stream;
                let _ = write_outcome(&mut writer, 7, &outcome);
            }
        });

        let script = dir.path().join("client");
        super::super::task_shim::write(
            &script,
            &bash,
            &socat,
            &head,
            socket.to_str().expect("a utf-8 socket path"),
        )
        .expect("write the client");
        let out = run_client(&script, &["task", "run", "probe"]);

        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("not allowed to run"),
            "the refusal must be said at all: {err}"
        );
        assert!(
            err.contains("/nix/store/demo/bin/sh") && err.contains("/nix/store/demo/bin/base64"),
            "and must name every target, since which one is the whole content: {err}"
        );
        assert!(
            err.contains("`spawn`"),
            "and point at the declaration that decides it: {err}"
        );
    }

    // A stream the declaration hides carries no payload at all — not an empty one. The client must
    // keep the two apart, or it would consume a framing newline that was never written and read the
    // next header as payload.
    #[test]
    fn a_hidden_stream_and_an_empty_one_stay_distinguishable() {
        let Some(bash) = crate::pathfind::find_on_path("bash") else {
            return;
        };
        let (Some(socat), Some(head)) = (
            crate::pathfind::find_on_path("socat"),
            crate::pathfind::find_on_path("head"),
        ) else {
            return;
        };
        let dir = TmpDir::new();
        let socket = dir.path().join("replay.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let outcome = super::super::task::TaskOutcome {
            exit: 0,
            // Shown but empty, beside a hidden one: the pair that a mis-framed reader confuses.
            stdout: Some(String::new()),
            stderr: None,
            truncated: false,
            redacted: 0,
            timed_out: false,
            stopped: false,
            elapsed_ms: 1,
            nonce: None,
            refused: Vec::new(),
            output: None,
        };
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    if line.trim_end() == "run" {
                        break;
                    }
                    line.clear();
                }
                let mut writer = stream;
                let _ = write_outcome(&mut writer, 7, &outcome);
            }
        });
        let script = dir.path().join("client");
        super::super::task_shim::write(&script, &bash, &socat, &head, socket.to_str().unwrap())
            .expect("write the client");
        let out = run_client(&script, &["task", "run", "probe"]);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(out.stdout.is_empty(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).is_empty(),
            "a hidden stream must produce nothing at all: {out:?}"
        );
    }

    // The reason the split exists: nothing but the task plane is expressible from inside.
    #[test]
    fn the_client_refuses_every_word_but_task() {
        let Some((_data, _plane, script)) = plane_and_client(vec![probe_task()]) else {
            return;
        };
        for verb in ["config", "app", "secret", "run", "gc", "trust", "doctor"] {
            let out = run_client(&script, &[verb]);
            assert_eq!(out.status.code(), Some(2), "`{verb}` must be refused");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("only the task plane is exposed"),
                "`{verb}`: {out:?}"
            );
        }
        // And the log stays host-only: the recorded party does not get to read the record.
        let out = run_client(&script, &["task", "logs"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("not readable from inside the cage"));
        // So do the live verbs, for the second reason: an invocation id is per session, so reaching
        // them from here would be reaching another caller's invocation.
        for verb in ["status", "stop"] {
            let out = run_client(&script, &["task", verb]);
            assert_eq!(out.status.code(), Some(2), "`task {verb}` must be refused");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("host-side only"),
                "`task {verb}`: {out:?}"
            );
        }
    }

    // What the launcher binds is the client the plane wrote, pointed at the socket the cage sees.
    #[test]
    fn the_plane_writes_a_client_aimed_at_the_cage_socket() {
        let Some(bash) = crate::pathfind::find_on_path("bash") else {
            return;
        };
        let data = TmpDir::new();
        let programs = ClientPrograms {
            bash: &bash,
            socat: Path::new("/store/socat/bin/socat"),
            head: Path::new("/store/coreutils/bin/head"),
        };
        let plane = start(
            data.path(),
            std::process::id(),
            super::super::task::TaskEngine::inventory_only(vec![]),
            &programs,
        )
        .expect("start");
        let path = shim_path(data.path(), std::process::id());
        let script = std::fs::read_to_string(&path).expect("the client was written");
        assert!(
            script.contains(&format!("sock='{CAGE_TASK_UDS}'")),
            "the client must name the socket as the CAGE sees it: {script}"
        );
        drop(plane);
        assert!(
            !path.exists(),
            "the client must not outlive the session that wrote it"
        );
    }

    fn entry(id: u64, task: &str, exit: i32) -> LogEntry {
        LogEntry {
            seq: id,
            at: 0,
            task: task.to_string(),
            exit,
            redacted: 2,
            truncated: false,
            timed_out: false,
            stopped: false,
            elapsed_ms: 12,
            refused: None,
        }
    }

    // The log is the trustworthy record: the timestamp is stamped host-side and the substitution
    // count is host-side — none of it is anything a caller can forge. The id is the *invocation's*,
    // carried in rather than counted here, so one number names an invocation everywhere.
    #[test]
    fn the_log_keeps_the_invocations_own_id_and_stamps_the_time() {
        let log = TaskLog::new();
        log.push(entry(4, "db-query", 0));
        log.push(entry(5, "db-query", 1));
        let (entries, dropped) = log.since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].seq, 4,
            "the entry keeps the id the invocation was admitted under"
        );
        assert_eq!(entries[1].seq, 5);
        assert_eq!(dropped, 0);
        assert!(entries[0].at > 0, "the timestamp is stamped host-side");

        let (tail, _) = log.since(4);
        assert_eq!(tail.len(), 1, "a cursor returns only what is past it");
        assert_eq!(tail[0].seq, 5);
    }

    // A refusal is recorded too — a caller probing a task it may not run is exactly what a human
    // reading the log wants to see.
    #[test]
    fn a_refusal_is_recorded_with_its_reason() {
        let log = TaskLog::new();
        log.push(refusal(1, "db-query", "parameter `sql` does not match"));
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
        log.push(refusal(
            1,
            "db-query",
            "bad\nevent seq=99 exit=0 task=forged",
        ));
        let (entries, _) = log.since(0);
        let line = entries[0].to_line();
        assert_eq!(line.lines().count(), 1, "one entry is one line: {line}");
        assert!(!line.contains("\nevent"), "{line}");
    }

    #[test]
    fn the_ring_evicts_the_oldest_and_reports_the_drop() {
        let log = TaskLog::new();
        for _ in 0..LOG_CAPACITY + 3 {
            log.push(entry(1, "t", 0));
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

    /// A refusal the plane *admitted* carries its invocation id, which is the number the log records
    /// it under — so a caller can find its own refusal there. A refusal before admission carries
    /// none, and inventing one would name an invocation that never existed.
    #[test]
    fn an_admitted_refusal_carries_the_id_it_is_logged_under() {
        let admitted = client::parse_run(b"id 4\nerr parameter `sql` is required\n").unwrap();
        assert_eq!(admitted.id, 4);
        assert_eq!(
            admitted.error.as_deref(),
            Some("parameter `sql` is required")
        );

        let refused = client::parse_run(b"err this session's task quota is exhausted\n").unwrap();
        assert_eq!(refused.id, 0);
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
