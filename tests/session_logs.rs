//! `sbx session logs` end to end, one case per output shape the command can take.
//!
//! The reading was rewritten to answer from a bounded window at the end of the file instead of
//! holding all of it, which turned one path into five: a window, a window with a line limit, a
//! whole-file copy, a copy of one session from its own header, and the branch that explains a log
//! that is not there. The unit tests cover the readers those shapes are built from; nothing covered
//! the shapes. This does, against a log written by hand, with the expected bytes written out rather
//! than recomputed by the same logic under test.
//!
//! The split the assertions rely on is the command's own: the body goes to stdout so a redirect
//! gives exactly what the agent wrote, and the context line goes to stderr.

#[macro_use]
mod common;

use common::fixture::TmpDir;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

/// A data directory with the log directory made: a fixture under the suites' own root, created
/// afresh and removed when it drops ([`TmpDir`]), never a name in the shared temporary directory
/// that another user could have made first.
struct Data(TmpDir);

impl Data {
    fn new(tag: &str) -> Data {
        let dir = TmpDir::prefixed("slogs", tag);
        std::fs::create_dir(dir.join("logs")).expect("make the log directory");
        Data(dir)
    }

    fn log(&self, pid: u32) -> PathBuf {
        self.0.join("logs").join(format!("{pid}.log"))
    }
}

/// `sbx <args>` over `data`, read within a bound: a reading that never ends — a follow that did not
/// see its session had exited — fails the test naming its arguments rather than holding the suite
/// until the job times out.
fn sbx_in(data: &Path, args: &[&str]) -> Output {
    common::procs::output_within(
        Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(args)
            .env("SBX_DATA_DIR", data),
        std::time::Duration::from_secs(60),
    )
    .unwrap_or_else(|| panic!("`sbx {}` did not end within 60 s", args.join(" ")))
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Where `got` first parts from `want`, byte for byte, or `None` when the two are the same. A long
/// body is compared whole this way rather than by its ends and its line count, which let a change
/// inside it through, and the failure names an offset instead of printing megabytes.
fn first_difference(got: &[u8], want: &[u8]) -> Option<usize> {
    (got != want).then(|| {
        got.iter()
            .zip(want)
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(want.len()))
    })
}

/// Two sessions in one log, the way a reused pid leaves them.
const HEAD_OLD: &str = "=== sbx session 4242 started=1699999000 ===\n";
const HEAD_NEW: &str = "=== sbx session 4242 started=1700000100 ===\n";
const OLD_BODY: &str = "old-1\nold-2\n";
const NEW_BODY: &str = "new-1\nnew-2\nnew-3\n";
/// The note a reading of that log prints: the state, and the day `HEAD_NEW` names. The date is
/// rendered in UTC, so it does not move with the zone the test runs in.
const NOTE: &str = "sbx: note: session 4242 — exited, started 2023-11-14";

fn two_sessions(data: &Data) -> String {
    let whole = format!("{HEAD_OLD}{OLD_BODY}{HEAD_NEW}{NEW_BODY}");
    std::fs::write(data.log(4242), &whole).expect("write the log");
    whole
}

#[test]
fn each_reading_prints_exactly_what_it_names() {
    let data = Data::new("shapes");
    let whole = two_sessions(&data);

    // The default: the last session's body, and nothing of the one whose pid it reused.
    let o = sbx_in(data.0.path(), &["session", "logs", "4242"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), NEW_BODY, "the default reading is the last session");
    assert!(
        err(&o).lines().any(|l| l == NOTE),
        "the note must name the state and the last session's date: {}",
        err(&o)
    );

    // A line limit counts inside that session, under the same note.
    let o = sbx_in(data.0.path(), &["session", "logs", "4242", "-n", "2"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), "new-2\nnew-3\n");
    assert!(err(&o).lines().any(|l| l == NOTE), "{}", err(&o));

    // `--all` is every byte in the file, headers included.
    let o = sbx_in(data.0.path(), &["session", "logs", "4242", "--all"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), whole, "--all copies the file");
    assert!(err(&o).contains("all sessions"));

    // `--all` with a limit counts back across the header into the session above.
    let o = sbx_in(
        data.0.path(),
        &["session", "logs", "4242", "--all", "-n", "4"],
    );
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!("{HEAD_NEW}{NEW_BODY}"),
        "four lines back from the end reaches the header above them"
    );

    // Following a session that has exited says so instead of waiting on a file nothing will append
    // to — and still prints the body first.
    let o = sbx_in(data.0.path(), &["session", "logs", "4242", "-f"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), NEW_BODY);
    assert!(
        err(&o).contains("nothing further will be written"),
        "{}",
        err(&o)
    );

    // A log that is not there is explained rather than reported as empty, and an id the registry
    // does not hold is a name that names nothing.
    let o = sbx_in(data.0.path(), &["session", "logs", "9999"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_eq!(
        err(&o),
        format!(
            "sbx: no log for session 9999 ({}).\n       `sbx session ls` lists the live sessions and \
             whether each one is detached.\n",
            data.log(9999).display()
        ),
        "the refusal names the log it looked for and where the live sessions are listed"
    );
    assert!(out(&o).is_empty());
}

/// A log that is not there, for an id the registry cannot be asked about: whether the id names a
/// session is not known, so the answer is the 1 of a failure about it rather than the 2 of a name
/// that names nothing. No hint points at `sbx session ls`, which reads the same registry.
#[test]
fn a_missing_log_under_an_unreadable_registry_is_a_failure_not_a_usage_error() {
    let data = Data::new("missing");
    std::fs::write(data.0.join("sessions"), b"not a directory").expect("write the registry");
    let o = sbx_in(data.0.path(), &["session", "logs", "9999"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("no log for session 9999")
            && err(&o).contains("cannot read the session registry")
            && !err(&o).contains("session ls"),
        "{}",
        err(&o)
    );
    assert!(out(&o).is_empty());
}

/// A registry that cannot be read leaves unknown whether the session still runs. The reading still
/// prints the body, and its note says the state is unknown instead of "exited"; a follow is refused
/// at exit 1 once the body is printed, rather than ended at 0 as if the session had exited. Each
/// form names the registry once.
///
/// A `sessions` entry that is a plain file is the unreadable registry: reading it as a directory
/// fails with an error that is not `NotFound`, the one failure the registry reads as no sessions.
#[test]
fn an_unreadable_registry_leaves_the_state_unknown_and_refuses_a_follow() {
    let data = Data::new("unreadable");
    two_sessions(&data);
    std::fs::write(data.0.join("sessions"), b"not a directory").expect("write the registry");

    let o = sbx_in(data.0.path(), &["session", "logs", "4242"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(out(&o), NEW_BODY);
    assert!(
        err(&o).contains("state unknown") && !err(&o).contains("exited"),
        "{}",
        err(&o)
    );

    let o = sbx_in(data.0.path(), &["session", "logs", "4242", "-f"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert_eq!(out(&o), NEW_BODY, "the body comes before the refusal");
    assert!(
        err(&o).contains("its log is not followed") && !err(&o).contains("nothing further"),
        "{}",
        err(&o)
    );

    for args in [
        &["session", "logs", "4242"][..],
        &["session", "logs", "4242", "-f"],
    ] {
        let o = sbx_in(data.0.path(), args);
        assert_eq!(
            err(&o).matches("cannot read the session registry").count(),
            1,
            "{args:?}: {}",
            err(&o)
        );
    }
}

/// The same shapes with a session past the read window: the answers must not change, and the note
/// must still name when the session started.
///
/// This is the case the window was built for and the one it broke first. A session larger than a
/// read chunk puts its header out of reach of a window sized by a line limit, and the date fell to
/// `?` — for exactly the long-running agent the verb exists to read.
#[test]
fn a_session_past_the_window_reads_the_same_and_still_names_its_date() {
    let data = Data::new("big");
    let mut whole = String::from(HEAD_OLD);
    whole.push_str(OLD_BODY);
    whole.push_str(HEAD_NEW);
    // Comfortably past the 64 KiB read chunk.
    let mut session = String::new();
    for i in 0..20_000 {
        session.push_str(&format!("chatty line {i}\n"));
    }
    whole.push_str(&session);
    // Past one read chunk and inside the window: the first window, sized by the line limit, then
    // holds the two lines and not the header, which is the shape under test. A smaller fixture
    // reaches the header in that window and passes without testing anything. The two sizes are
    // `LOG_CHUNK` and `TAIL_WINDOW_MAX` in `src/cli/session.rs`, out of an integration test's reach.
    assert!(
        whole.len() > 64 * 1024 && whole.len() < 8 * 1024 * 1024,
        "the fixture must sit past one 64 KiB read chunk and inside the 8 MiB window: {} bytes",
        whole.len()
    );
    std::fs::write(data.log(4242), &whole).expect("write the log");

    let o = sbx_in(data.0.path(), &["session", "logs", "4242", "-n", "2"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), "chatty line 19998\nchatty line 19999\n");
    assert!(
        !err(&o).contains("started ?"),
        "the note must still name the date for a session bigger than the window: {}",
        err(&o)
    );

    // And the unlimited reading of that same session is that session, byte for byte: every line in
    // order, no header, and nothing of the session whose pid it reused.
    let o = sbx_in(data.0.path(), &["session", "logs", "4242"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(
        first_difference(&o.stdout, session.as_bytes()),
        None,
        "the reading must be the whole session and nothing else ({} bytes read, {} written)",
        o.stdout.len(),
        session.len()
    );
}

/// The one shape a window can never answer: a session longer than the window itself.
///
/// Here the command stops trying to hold the answer and streams it from the session's own header,
/// found by a forward pass. Nothing else reaches that arm — a session merely larger than a *read
/// chunk* still fits the window, which is why this fixture is deliberately past the window's own
/// ceiling rather than past the chunk's.
#[test]
fn a_session_longer_than_the_window_is_streamed_from_its_own_header() {
    let data = Data::new("huge");
    let mut whole = String::from(HEAD_OLD);
    whole.push_str(OLD_BODY);
    whole.push_str(HEAD_NEW);
    // Past `TAIL_WINDOW_MAX` (8 MiB), so the window gives up on finding the header.
    let mut session = String::new();
    for i in 0..600_000 {
        session.push_str(&format!("a chatty line number {i}\n"));
    }
    whole.push_str(&session);
    assert!(
        whole.len() > 9 * 1024 * 1024,
        "the fixture must clear the ceiling"
    );
    std::fs::write(data.log(4242), &whole).expect("write the log");

    let o = sbx_in(data.0.path(), &["session", "logs", "4242"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(
        first_difference(&o.stdout, session.as_bytes()),
        None,
        "the stream must be the whole session, starting where it does and nothing above its \
         header ({} bytes read, {} written)",
        o.stdout.len(),
        session.len()
    );
    assert!(
        !err(&o).contains("started ?"),
        "the same forward pass names the date: {}",
        err(&o)
    );
}

/// The log holds the caged agent's own stdout, so every field of a header line is a value the agent
/// can choose. `started` is a bare `u64` and the note renders it as a date; `SystemTime`'s seconds
/// are an `i64` on Linux, so a stamp at or above 2^63 used to abort the command before a byte of the
/// body was printed. That made `sbx session logs` — the one way to find out what a background agent
/// did — permanently unusable for that session, the log being append-only.
///
/// The body must still be printed and the unreadable stamp must degrade to the `?` a missing header
/// already renders.
#[test]
fn a_header_stamp_the_agent_chose_cannot_stop_the_log_being_read() {
    let data = Data::new("stamp");
    // 9.3e18 > i64::MAX (9.223e18), and still inside u64.
    let head = "=== sbx session 4242 started=9300000000000000000 ===\n";
    std::fs::write(data.log(4242), format!("{head}{NEW_BODY}")).expect("write the log");

    let o = sbx_in(data.0.path(), &["session", "logs", "4242"]);
    assert!(
        o.status.success(),
        "an out-of-range stamp must not fail the command: {}",
        err(&o)
    );
    assert_eq!(out(&o), NEW_BODY, "the body is still what was asked for");
    assert!(
        err(&o).contains("started ?"),
        "an unreadable stamp reads as `?`, like a missing header: {}",
        err(&o)
    );
    assert!(
        !err(&o).contains("panicked"),
        "and nothing panicked: {}",
        err(&o)
    );
}

/// Start `sbx <args>` over `data` with standard output on `stdout`, a destination [`sbx_in`] cannot
/// take since it pipes both streams itself, and standard error into the file `said`, which a test
/// can read while the reading runs.
fn spawn_onto(data: &Path, args: &[&str], stdout: Stdio, said: &Path) -> Child {
    let said =
        std::fs::File::create(said).unwrap_or_else(|e| panic!("create {}: {e}", said.display()));
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .env("SBX_DATA_DIR", data)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(said)
        .spawn()
        .unwrap_or_else(|e| panic!("spawn `sbx {}`: {e}", args.join(" ")))
}

/// `child`'s exit status once it ends, or a failure naming `args` when it is still running 60 s on:
/// a reading that goes on writing into an output that refuses it would otherwise hold the suite.
fn reaped(mut child: Child, args: &[&str]) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut status = None;
    let ended = common::procs::wait_until(deadline, || {
        status = child.try_wait().expect("wait for sbx");
        status.is_some()
    });
    if !ended {
        let _ = child.kill();
        let _ = child.wait();
        panic!("`sbx {}` still runs 60 s on", args.join(" "));
    }
    status.expect("an ended child has a status")
}

/// A reading whose output cannot be written fails, said once, and one whose reader has gone does
/// not, for each way the log reaches standard output: a copy of the file (`--all`), the window a
/// plain reading prints, and a follow's drains. A full disk under `> file` leaves an incomplete log
/// there, which a script reading the exit code has to learn; a reader gone, `… | head`, is the end
/// of a pipeline the shell reports as fine. Every shape is run and the ones that fail are listed
/// together, so each is held to its own write.
///
/// The follow's log holds only the header, so the reading before the follow writes nothing, and the
/// line appended once the note is out reaches standard output through the follow alone: the note is
/// said after the reading has fixed where the follow resumes. The session is this test's process,
/// registered as running, so the follow does not end on an exited session before it writes.
#[test]
fn a_reading_it_cannot_write_fails_once_and_a_reader_gone_does_not() {
    let Ok(full) = std::fs::OpenOptions::new().write(true).open("/dev/full") else {
        skip_incapable!(
            "skipping a_reading_it_cannot_write_fails_once_and_a_reader_gone_does_not: no /dev/full here"
        );
        return;
    };
    // `write_session_record` takes the `XDG_DATA_HOME` the data directory sits in.
    let root = TmpDir::prefixed("slogs", "unwritten");
    let data = root.join("sbx");
    std::fs::create_dir_all(data.join("logs")).expect("make the log directory");
    let pid = std::process::id();
    common::write_session_record(root.path(), pid, "project", Path::new("/p"));
    let log = data.join("logs").join(format!("{pid}.log"));
    let header = format!("=== sbx session {pid} started=1700000100 ===\n");
    let said = root.join("stderr");
    let id = pid.to_string();

    let mut failed = Vec::new();
    for (shape, args) in [
        ("a copy of the file", vec!["session", "logs", &id, "--all"]),
        ("the window", vec!["session", "logs", &id]),
        ("a follow", vec!["session", "logs", &id, "-f"]),
    ] {
        let follow = args.contains(&"-f");
        for (onto, stdout, code, told) in [
            (
                "a full disk",
                Stdio::from(full.try_clone().expect("reopen /dev/full")),
                1,
                1,
            ),
            ("a closed pipe", common::procs::closed_pipe(), 0, 0),
        ] {
            let body = if follow { "" } else { NEW_BODY };
            std::fs::write(&log, format!("{header}{body}")).expect("write the log");
            let mut child = spawn_onto(&data, &args, stdout, &said);
            if follow {
                let deadline = Instant::now() + Duration::from_secs(60);
                let noted = common::procs::wait_until(deadline, || {
                    std::fs::read_to_string(&said).is_ok_and(|s| {
                        s.split_inclusive('\n')
                            .any(|l| l.starts_with("sbx: note: session") && l.ends_with('\n'))
                    })
                });
                let note = std::fs::read_to_string(&said).unwrap_or_default();
                if !noted || !note.contains(&format!("session {pid} — running")) {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{shape} onto {onto} is not the follow of a running session: {note}");
                }
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&log)
                    .and_then(|mut f| f.write_all(b"after the note\n"))
                    .expect("append to the log");
            }
            let status = reaped(child, &args);
            let stderr = std::fs::read_to_string(&said).expect("read stderr");
            let says = stderr.matches("cannot write to standard output").count();
            if status.code() != Some(code) || says != told {
                failed.push(format!(
                    "{shape} onto {onto}: exit {status}, said {says} time(s), want exit {code} \
                     said {told}:\n{stderr}"
                ));
            }
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}
