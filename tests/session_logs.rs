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

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A data directory that cleans itself up, with the log directory made.
struct Data(PathBuf);

impl Data {
    fn new(tag: &str) -> Data {
        let base = std::env::temp_dir().join(format!(
            "sbx-session-logs-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("logs")).expect("make the log directory");
        Data(base)
    }

    fn log(&self, pid: u32) -> PathBuf {
        self.0.join("logs").join(format!("{pid}.log"))
    }
}

impl Drop for Data {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sbx_in(data: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(args)
        .env("SBX_DATA_DIR", data)
        .output()
        .expect("spawn sbx")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Two sessions in one log, the way a reused pid leaves them.
const HEAD_OLD: &str = "=== sbx session 4242 started=1699999000 ===\n";
const HEAD_NEW: &str = "=== sbx session 4242 started=1700000100 ===\n";
const OLD_BODY: &str = "old-1\nold-2\n";
const NEW_BODY: &str = "new-1\nnew-2\nnew-3\n";

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
    let o = sbx_in(&data.0, &["session", "logs", "4242"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), NEW_BODY, "the default reading is the last session");
    assert!(
        err(&o).contains("exited") && !err(&o).contains("started ?"),
        "the note must name the state and the date: {}",
        err(&o)
    );

    // A line limit counts inside that session.
    let o = sbx_in(&data.0, &["session", "logs", "4242", "-n", "2"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), "new-2\nnew-3\n");

    // `--all` is every byte in the file, headers included.
    let o = sbx_in(&data.0, &["session", "logs", "4242", "--all"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), whole, "--all copies the file");
    assert!(err(&o).contains("all sessions"));

    // `--all` with a limit counts back across the header into the session above.
    let o = sbx_in(&data.0, &["session", "logs", "4242", "--all", "-n", "4"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(
        out(&o),
        format!("{HEAD_NEW}{NEW_BODY}"),
        "four lines back from the end reaches the header above them"
    );

    // Following a session that has exited says so instead of waiting on a file nothing will append
    // to — and still prints the body first.
    let o = sbx_in(&data.0, &["session", "logs", "4242", "-f"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), NEW_BODY);
    assert!(
        err(&o).contains("nothing further will be written"),
        "{}",
        err(&o)
    );

    // A log that is not there is explained rather than reported as empty.
    let o = sbx_in(&data.0, &["session", "logs", "9999"]);
    assert!(!o.status.success());
    assert!(err(&o).contains("no log for session 9999"), "{}", err(&o));
    assert!(out(&o).is_empty());
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
    for i in 0..20_000 {
        whole.push_str(&format!("chatty line {i}\n"));
    }
    std::fs::write(data.log(4242), &whole).expect("write the log");

    let o = sbx_in(&data.0, &["session", "logs", "4242", "-n", "2"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), "chatty line 19998\nchatty line 19999\n");
    assert!(
        !err(&o).contains("started ?"),
        "the note must still name the date for a session bigger than the window: {}",
        err(&o)
    );

    // And the unlimited reading of that same session is complete: every line, no header.
    let o = sbx_in(&data.0, &["session", "logs", "4242"]);
    assert!(o.status.success(), "{}", err(&o));
    let body = out(&o);
    assert!(
        body.starts_with("chatty line 0\n") && body.ends_with("chatty line 19999\n"),
        "the whole session, from its first line to its last"
    );
    assert!(
        !body.contains("=== sbx session") && !body.contains("old-1"),
        "and nothing of the session whose pid it reused"
    );
    assert_eq!(body.lines().count(), 20_000);
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
    let lines = 600_000;
    for i in 0..lines {
        whole.push_str(&format!("a chatty line number {i}\n"));
    }
    assert!(
        whole.len() > 9 * 1024 * 1024,
        "the fixture must clear the ceiling"
    );
    std::fs::write(data.log(4242), &whole).expect("write the log");

    let o = sbx_in(&data.0, &["session", "logs", "4242"]);
    assert!(o.status.success(), "{}", err(&o));
    let body = out(&o);
    assert_eq!(body.lines().count(), lines, "every line of the session");
    assert!(body.starts_with("a chatty line number 0\n"));
    assert!(body.ends_with(&format!("a chatty line number {}\n", lines - 1)));
    assert!(
        !body.contains("=== sbx session") && !body.contains("old-1"),
        "and nothing above its header: the stream starts where the session does"
    );
    assert!(
        !err(&o).contains("started ?"),
        "the same forward pass names the date: {}",
        err(&o)
    );
}
