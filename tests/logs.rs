//! Integration tests for the `sbx <lens> logs` views — the filesystem, process and ssh-agent
//! observation lenses, driven through the real binary against a stand-in control socket.
//!
//! The three views share one implementation and differ only in a description: which socket to open,
//! which reader to call, what to head the feed with, and how to render a row. Every one of those is
//! a value that would compile just as happily wired to the wrong lens, and nothing inside the
//! process can tell — so this suite goes the whole way round instead. It fabricates a session
//! record, binds each lens's socket where that lens says its socket lives, serves the line protocol
//! by hand, and reads the command's actual stdout back.
//!
//! Serving the wire by hand is the point rather than a shortcut: it is a second, independent
//! spelling of the protocol. A change to the framing that updated both halves inside the crate
//! would still fail here.
//!
//! No sandbox, no privilege, no network — a `sleep` stands in for the session's process, since all
//! the resolver wants is a pid that is alive.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`. Deliberately not `/tmp`, whose tmpfs inode cap is shared machine-wide.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("l-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Read a process's start-time ticks (`/proc/<pid>/stat` field 22) for the fabricated record.
fn read_start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read stat");
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    after.split_whitespace().nth(19).unwrap().parse().unwrap()
}

/// Write the session record the `logs` views resolve, pointing at a live `pid`. The on-disk format
/// is stable, and fabricating it isolates the view under test from the registration machinery.
fn write_session_record(data: &Path, pid: u32, project: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let start = read_start_ticks(pid);
    let dir = data.join("sbx").join("sessions");
    std::fs::create_dir_all(&dir).unwrap();
    let hex: String = project
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let rec = format!("kind=run\npid={pid}\nstart={start}\nruntime=project\nproject={hex}\n");
    std::fs::write(dir.join(format!("{pid}-{start}")), rec).unwrap();
}

/// The commands a stand-in socket was asked, in order — how a test sees the cursor the view walked.
type Asked = Arc<Mutex<Vec<String>>>;

/// Frame `events` the way a session frames a `LOG` reply: the `head=` cursor, one `event …` line
/// each, then `ok`.
fn frame(events: &[&str]) -> String {
    let mut reply = format!("head={}\n", events.len());
    for e in events {
        reply.push_str(e);
        reply.push('\n');
    }
    reply.push_str("ok\n");
    reply
}

/// Bind `<data>/sbx/<lens>/control-<pid>.sock` — where that lens says its socket lives, which is
/// half of what these tests are checking.
fn bind_lens_socket(data: &Path, lens: &str, pid: u32) -> (PathBuf, UnixListener) {
    let dir = data.join("sbx").join(lens);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).expect("bind the stand-in control socket");
    (socket, listener)
}

/// Answer every read with the same window, for as long as anything asks. A view that is not
/// following still reads more than once across a test (the human pass and the `--json` pass are two
/// runs of the command), and the protocol is one command per connection.
fn serve_lens(data: &Path, lens: &str, pid: u32, events: &[&str]) {
    let (_, listener) = bind_lens_socket(data, lens, pid);
    let reply = frame(events);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            let _ = (&stream).write_all(reply.as_bytes());
            let _ = (&stream).flush();
        }
    });
}

/// Answer `replies` one per connection — which is one per read — and then stop.
///
/// When the script runs out the socket is unlinked and the listener dropped, which is exactly how a
/// session ends: its guard unlinks on drop and the next connect simply fails. That is what a
/// `--follow` view reads as end-of-session.
///
/// Returns the commands the view sent, so a test can assert the cursor it carried forward.
fn serve_script(data: &Path, lens: &str, pid: u32, replies: Vec<String>) -> Asked {
    let (socket, listener) = bind_lens_socket(data, lens, pid);
    let asked: Asked = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&asked);
    std::thread::spawn(move || {
        for reply in replies {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            seen.lock().unwrap().push(line.trim_end().to_string());
            let _ = (&stream).write_all(reply.as_bytes());
            let _ = (&stream).flush();
        }
        let _ = std::fs::remove_file(&socket);
        drop(listener);
    });
    asked
}

/// A live pid to hang a session record on, and the guard that reaps it.
struct Standin(std::process::Child);

impl Standin {
    fn new() -> Self {
        Standin(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the stand-in process"),
        )
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Standin {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run one lens's `logs` view against a session whose socket is being served, and return stdout.
fn read_feed(data: &Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("run the logs view");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The filesystem lens: its own socket directory, its own header, and a row of `kind` then path.
#[test]
fn the_filesystem_lens_reads_its_own_socket_and_renders_its_own_rows() {
    let (data, project) = (TmpDir::new(), TmpDir::new());
    let child = Standin::new();
    write_session_record(data.path(), child.pid(), project.path());
    serve_lens(
        data.path(),
        "fs",
        child.pid(),
        &[
            "event seq=1 at=1700000000123 kind=write path=src/main.rs",
            "event seq=2 at=1700000000456 kind=remove path=a dir/with a space.txt",
        ],
    );
    let pid = child.pid().to_string();

    let human = read_feed(data.path(), &["fs", "logs", &pid]);
    assert!(
        human.contains(&format!("file-write feed — session {pid}")),
        "the header names this lens's feed: {human}"
    );
    assert!(human.contains("write   src/main.rs"), "{human}");
    assert!(
        human.contains("remove  a dir/with a space.txt"),
        "a path's spaces survive the wire's verbatim-last field: {human}"
    );

    let json = read_feed(data.path(), &["fs", "logs", &pid, "--json"]);
    assert_eq!(json.lines().count(), 2, "one object per event: {json}");
    assert!(json.contains(r#""kind":"write""#), "{json}");
    assert!(json.contains(r#""path":"src/main.rs""#), "{json}");
    assert!(
        json.contains(&format!(r#""session_pid":{pid}"#)),
        "each row carries the session it came from: {json}"
    );
    assert!(
        !json.contains("file-write feed"),
        "the header is suppressed under --json so the stream is valid NDJSON: {json}"
    );
}

/// The process lens: a different socket directory, a different header, and a row that leads with
/// the enforcement verdict.
#[test]
fn the_process_lens_reads_its_own_socket_and_renders_its_own_rows() {
    let (data, project) = (TmpDir::new(), TmpDir::new());
    let child = Standin::new();
    write_session_record(data.path(), child.pid(), project.path());
    serve_lens(
        data.path(),
        "proc",
        child.pid(),
        &[
            "event seq=1 at=1700000000123 pid=4242 verdict=observe cmd=rg --json needle",
            "event seq=2 at=1700000000456 pid=4243 verdict=deny by=/bin/bash cmd=/usr/bin/curl",
        ],
    );
    let pid = child.pid().to_string();

    let human = read_feed(data.path(), &["proc", "logs", &pid]);
    assert!(
        human.contains(&format!("process feed — session {pid}")),
        "{human}"
    );
    assert!(human.contains("observe 4242  rg --json needle"), "{human}");
    assert!(human.contains("deny    4243  /usr/bin/curl"), "{human}");

    let json = read_feed(data.path(), &["proc", "logs", &pid, "--json"]);
    assert!(json.contains(r#""command":"rg --json needle""#), "{json}");
    assert!(json.contains(r#""verdict":"deny""#), "{json}");
    assert!(json.contains(r#""pid":4243"#), "{json}");
}

/// The ssh-agent lens: a third socket directory, a third header, and a row of `kind` then detail.
#[test]
fn the_ssh_agent_lens_reads_its_own_socket_and_renders_its_own_rows() {
    let (data, project) = (TmpDir::new(), TmpDir::new());
    let child = Standin::new();
    write_session_record(data.path(), child.pid(), project.path());
    serve_lens(
        data.path(),
        "ssh-agent",
        child.pid(),
        &[
            "event seq=1 at=1700000000123 kind=sign detail=deploy@example",
            "event seq=2 at=1700000000456 kind=refuse detail=a key the grant does not name",
        ],
    );
    let pid = child.pid().to_string();

    let human = read_feed(data.path(), &["ssh-agent", "logs", &pid]);
    assert!(
        human.contains(&format!("ssh-agent feed — session {pid}")),
        "{human}"
    );
    assert!(human.contains("sign     deploy@example"), "{human}");
    assert!(
        human.contains("refuse   a key the grant does not name"),
        "{human}"
    );

    let json = read_feed(data.path(), &["ssh-agent", "logs", &pid, "--json"]);
    assert!(json.contains(r#""kind":"refuse""#), "{json}");
    assert!(
        json.contains(r#""detail":"a key the grant does not name""#),
        "{json}"
    );
}

/// `--follow` is the half of the view a single read never exercises, and the half where a mistake
/// is silent: the cursor it carries forward, the gap it admits to when the ring moved on without it,
/// and how it decides the session is over. All three are asserted from the outside — the cursor by
/// what the socket was actually asked.
#[test]
fn a_follow_walks_its_cursor_reports_the_gap_and_stops_when_the_session_ends() {
    let (data, project) = (TmpDir::new(), TmpDir::new());
    let child = Standin::new();
    write_session_record(data.path(), child.pid(), project.path());
    let asked = serve_script(
        data.path(),
        "fs",
        child.pid(),
        vec![
            // The opening tail: one event, cursor now at 1.
            frame(&["event seq=1 at=1700000000123 kind=write path=first.rs"]),
            // The ring moved on while the view was between polls: three events fell off unseen,
            // and the one it does get is seq 5, so the cursor must jump to 5 and not to 2.
            "dropped=3\nhead=5\nevent seq=5 at=1700000000456 kind=create path=later.rs\nok\n"
                .to_string(),
            // Nothing new. The cursor must be unchanged, not rewound.
            "head=5\nok\n".to_string(),
        ],
    );
    let pid = child.pid().to_string();

    let feed = read_feed(data.path(), &["fs", "logs", &pid, "--follow"]);
    assert!(feed.contains("write   first.rs"), "{feed}");
    assert!(
        feed.contains("(3 earlier event(s) evicted from the ring before this poll)"),
        "a gap is surfaced, never silently swallowed: {feed}"
    );
    assert!(feed.contains("create  later.rs"), "{feed}");
    assert!(
        feed.contains(&format!("(session {pid} ended)")),
        "an absent socket after a good first read is the end of the session, not an error: {feed}"
    );

    assert_eq!(
        *asked.lock().unwrap(),
        ["LOG", "LOG after=1", "LOG after=5"],
        "each poll resumes from the head the last one reported"
    );
}

/// The three views take the same flags and refuse the same things in their own name. A view that
/// borrowed a sibling's name here would be reporting the wrong command to the user.
#[test]
fn each_view_refuses_a_bad_argument_in_its_own_name() {
    let data = TmpDir::new();
    for (args, verb) in [
        (["fs", "logs", "--nope"], "fs logs"),
        (["proc", "logs", "--nope"], "proc logs"),
        (["ssh-agent", "logs", "--nope"], "ssh-agent logs"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(args)
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("run the logs view");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {err}");
        assert!(
            err.contains(&format!("sbx: {verb}: unexpected argument")),
            "{args:?} should name itself `{verb}`: {err}"
        );
    }

    // Two ids is the other shared refusal, and it too must be named by the right command.
    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["ssh-agent", "logs", "1", "2"])
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("run the logs view");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(
        err.contains("sbx: ssh-agent logs: at most one session id"),
        "{err}"
    );
}

/// Bind `<data>/sbx/tasks/<pid>/log.sock` — the task plane's host-only socket, which does not follow
/// the `control-<pid>.sock` shape the four lenses share.
fn serve_task(data: &Path, pid: u32, events: &[&str]) {
    let dir = data.join("sbx").join("tasks").join(pid.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let listener = UnixListener::bind(dir.join("log.sock")).expect("bind the task log socket");
    let reply = frame(events);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let mut line = String::new();
            if BufReader::new(&stream).read_line(&mut line).is_err() {
                continue;
            }
            let _ = (&stream).write_all(reply.as_bytes());
            let _ = (&stream).flush();
        }
    });
}

/// The merged view is the only one that can be wrong about *order*, and the only one that can lie by
/// omission. Both are checked here, over four feeds served at once and a fifth left unbound.
///
/// The stamps are chosen so that every feed contributes exactly one row and the correct order is not
/// the order the feeds are read in — a view that concatenated its feeds, or sorted by anything but
/// the event's own time, produces a different sequence.
///
/// The task row is the load-bearing one. Its invocation *began* at .200 and its record was written
/// when it *ended* at .500: filed at the finish it would sort last, after the write it preceded.
#[test]
fn the_merged_view_orders_every_feed_by_when_it_happened() {
    let dir = TmpDir::new();
    let data = dir.path();
    let standin = Standin::new();
    let pid = standin.pid();
    write_session_record(data, pid, Path::new("/tmp/demo-app"));

    serve_lens(
        data,
        "proc",
        pid,
        &[
            "event seq=1 at=1700000000100 pid=4242 verdict=observe cmd=curl -s https://api.example.com",
        ],
    );
    serve_task(
        data,
        pid,
        &[
            "event seq=1 cur=1 at=1700000000500 started=1700000000200 exit=0 redacted=0 \
           truncated=0 timed_out=0 stopped=0 detached=0 elapsed_ms=300 task=db-query",
        ],
    );
    serve_lens(
        data,
        "egress",
        pid,
        &[
            "event seq=1 at=1700000000300 port=443 verdict=deny proto=https reason=no-rule \
           host=api.example.com",
        ],
    );
    serve_lens(
        data,
        "fs",
        pid,
        &["event seq=1 at=1700000000400 kind=write path=./retry.sh"],
    );
    // ssh-agent is deliberately not bound: an absent feed must be named, not passed over.

    let out = read_feed(data, &["logs", &pid.to_string()]);

    let lenses: Vec<&str> = out
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter(|w| ["proc", "task", "net", "fs", "ssh"].contains(w))
        .collect();
    assert_eq!(
        lenses,
        ["proc", "task", "net", "fs"],
        "every feed sorted by when its event happened, not by feed: {out}"
    );

    assert!(
        out.contains("curl -s https://api.example.com"),
        "each feed's verbatim field survives: {out}"
    );
    assert!(
        out.contains("api.example.com:443") && out.contains("(no-rule)"),
        "a refusal carries the category that says what to change: {out}"
    );
    assert!(out.contains("./retry.sh"), "{out}");
    assert!(out.contains("db-query"), "{out}");

    assert!(
        out.contains("recording: proc, net, fs, task"),
        "the live feeds are named: {out}"
    );
    assert!(
        out.contains("ssh: no ssh-agent broker"),
        "and so is the one that is not, with the reason: {out}"
    );
}

/// `--feed` narrows, and a name no feed answers to is refused rather than silently dropped: a view
/// that showed fewer feeds than asked for would read as a quiet session.
#[test]
fn the_merged_view_narrows_by_feed_and_refuses_a_name_no_feed_answers_to() {
    let dir = TmpDir::new();
    let data = dir.path();
    let standin = Standin::new();
    let pid = standin.pid();
    write_session_record(data, pid, Path::new("/tmp/demo-app"));
    serve_lens(
        data,
        "fs",
        pid,
        &["event seq=1 at=1700000000400 kind=write path=./kept.rs"],
    );
    serve_lens(
        data,
        "proc",
        pid,
        &["event seq=1 at=1700000000100 pid=4242 verdict=observe cmd=dropped-command"],
    );

    let out = read_feed(data, &["logs", &pid.to_string(), "--feed", "fs"]);
    assert!(out.contains("./kept.rs"), "{out}");
    assert!(
        !out.contains("dropped-command"),
        "a feed left out of --feed is not read: {out}"
    );

    let bad = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["logs", &pid.to_string(), "--feed", "netwrok"])
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("run the merged view");
    assert_eq!(bad.status.code(), Some(2), "a typo is an error");
    let err = String::from_utf8_lossy(&bad.stderr);
    assert!(err.contains("no feed named `netwrok`"), "{err}");
    assert!(
        err.contains("proc, net, fs, ssh, task"),
        "and the error lists what there is: {err}"
    );
}

/// A session recording nothing at all is said so, not shown as an empty view — which would read as
/// an agent that did nothing rather than one nobody was watching.
#[test]
fn the_merged_view_refuses_a_session_that_records_nothing() {
    let dir = TmpDir::new();
    let data = dir.path();
    let standin = Standin::new();
    let pid = standin.pid();
    write_session_record(data, pid, Path::new("/tmp/demo-app"));

    let out = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["logs", &pid.to_string()])
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("run the merged view");
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("is recording nothing"), "{err}");
    assert!(
        err.contains("--observe") && err.contains("[ssh_agent] allow"),
        "each feed says why it in particular is not there: {err}"
    );
}
