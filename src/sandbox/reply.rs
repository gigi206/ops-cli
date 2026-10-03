//! The rule every host-side reader of a control socket follows for a verb that only reads: an
//! answer counts once its closing `ok` has arrived, and an answer that ends before it is an error.
//!
//! Each server ends a read verb's answer with `ok`, or answers a verb it cannot serve with a single
//! `err …` line. An answer that stops short of both was cut: the server's write deadline passed,
//! its connection thread failed, or the supervisor exited mid-answer. Taken at face value, a cut
//! answer is a complete one that happens to be short: a listing that looks empty, or a log whose
//! `head=` cursor runs past the last event read, so the next `--follow` poll starts beyond the
//! events that never arrived and nothing says so.
//!
//! A peer the server refuses outright, past its connection ceiling or at its peer check, is closed
//! before its command is read, and that does not read as a short answer: the kernel resets a
//! connection closed with unread bytes in it, so the reader's next read fails with
//! `ECONNRESET`, or its write fails with `EPIPE` when the close came first. [`unanswered`] counts
//! both, a cut and a reader that ran out of time as the one fact a reader needs: the session was
//! reached and its answer did not arrive in full.
//!
//! The verbs that act (an answer to a parked request, a remembered rule, a stop) are not read
//! through this. By the time their answer is cut the action may already have landed, and each of
//! those readers says what it makes of a missing reply.

use std::io::{self, BufRead};

/// Whether a read verb's error says the session was reached and its answer did not arrive in full.
///
/// An answer cut before its `ok` ([`answer`]'s `UnexpectedEof`), a peer closed before its command was
/// read (`ConnectionReset` on the read, `BrokenPipe` on the write; see the module documentation),
/// and a session that did not answer within the reader's timeout. A connect that fails is the other
/// case: no socket, or one nobody serves any more, which is a plane never stood up or a session
/// gone, and each reader keeps its own words for that.
pub(crate) fn unanswered(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::TimedOut
    )
}

/// The lines of one answer, up to and without its closing `ok`.
///
/// An `err …` line that ends the stream is the server's own answer and ends the iteration cleanly,
/// so each reader keeps whatever meaning it gave that line. Any other end of the stream yields one
/// [`io::ErrorKind::UnexpectedEof`] error, which a caller tells apart from a connect failure: the
/// session is there, and its answer did not arrive whole.
pub(crate) fn answer<R: BufRead>(reader: R) -> Answer<R> {
    Answer {
        lines: reader.lines(),
        ends_on_err: false,
        done: false,
    }
}

/// The iterator [`answer`] returns.
pub(crate) struct Answer<R> {
    lines: io::Lines<R>,
    /// Whether the last line read was an `err …` one, which may end an answer without `ok`.
    ends_on_err: bool,
    done: bool,
}

impl<R: BufRead> Iterator for Answer<R> {
    type Item = io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.lines.next() {
            Some(Ok(line)) if line == "ok" => {
                self.done = true;
                None
            }
            Some(Ok(line)) => {
                self.ends_on_err = line.starts_with("err ");
                Some(Ok(line))
            }
            Some(Err(e)) => {
                self.done = true;
                Some(Err(e))
            }
            None => {
                self.done = true;
                (!self.ends_on_err).then(|| {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "the session's answer ended before its `ok`",
                    ))
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(wire: &str) -> Vec<Result<String, io::ErrorKind>> {
        answer(wire.as_bytes())
            .map(|line| line.map_err(|e| e.kind()))
            .collect()
    }

    #[test]
    fn an_answer_counts_up_to_its_ok() {
        assert_eq!(
            read("head=2\nevent seq=2\nok\n"),
            vec![Ok("head=2".to_string()), Ok("event seq=2".to_string())]
        );
        assert_eq!(
            read("ok\n"),
            Vec::new(),
            "an empty answer is still a whole one"
        );
    }

    #[test]
    fn an_answer_cut_before_its_ok_ends_in_an_error() {
        assert_eq!(
            read("head=2\nevent seq=1\n"),
            vec![
                Ok("head=2".to_string()),
                Ok("event seq=1".to_string()),
                Err(io::ErrorKind::UnexpectedEof),
            ],
            "the lines that arrived are handed over, and the cut is said after them"
        );
        assert_eq!(
            read(""),
            vec![Err(io::ErrorKind::UnexpectedEof)],
            "a connection closed unanswered, as a refused peer's is, is not an empty answer"
        );
        assert_eq!(
            read("err bad-request\nhead=2\n"),
            vec![
                Ok("err bad-request".to_string()),
                Ok("head=2".to_string()),
                Err(io::ErrorKind::UnexpectedEof),
            ],
            "only an `err` line that ends the stream ends the answer"
        );
    }

    /// A connect that fails is not an answer that did not arrive: there is no socket, or a socket
    /// file nobody serves any more, which is what a session that died leaves behind.
    #[test]
    fn a_failed_connect_is_not_an_unanswered_read() {
        let dir = crate::testutil::TmpDir::new();
        let missing = std::os::unix::net::UnixStream::connect(dir.join("none.sock"))
            .expect_err("nothing is there");
        assert!(!unanswered(&missing), "{missing}");
        let stale = dir.join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&stale).expect("bind"));
        let gone = std::os::unix::net::UnixStream::connect(&stale).expect_err("nobody serves it");
        assert_eq!(gone.kind(), io::ErrorKind::ConnectionRefused, "{gone}");
        assert!(!unanswered(&gone));
    }

    #[test]
    fn a_server_error_line_is_a_whole_answer() {
        assert_eq!(
            read("err bad-request\n"),
            vec![Ok("err bad-request".to_string())]
        );
    }

    /// Bind `socket`, take one connection, read its command line and answer it with `wire`, then
    /// close: a server whose answer is exactly those bytes.
    fn answer_once(socket: &std::path::Path, wire: &'static [u8]) -> std::thread::JoinHandle<()> {
        use std::io::Write;
        let listener = std::os::unix::net::UnixListener::bind(socket).expect("bind");
        std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut command = String::new();
                let _ = io::BufReader::new(&conn).read_line(&mut command);
                let _ = conn.write_all(wire);
            }
        })
    }

    /// Bind `socket`, take one connection and close it without reading a byte of it: what the peer
    /// check and the connection ceiling do with a peer they refuse.
    fn refuse_once(socket: &std::path::Path) -> std::thread::JoinHandle<()> {
        let listener = std::os::unix::net::UnixListener::bind(socket).expect("bind");
        std::thread::spawn(move || drop(listener.accept()))
    }

    /// Every reader of a read verb goes through [`answer`], so each refuses an answer cut after a
    /// line, one closed after its command was read, and one closed before it was, takes the same
    /// bytes followed by `ok`, and keeps whatever it made of a server's `err` line. A reader that
    /// parses the wire itself again passes the cut answers off as whole ones and turns this red, and
    /// so does an [`unanswered`] that knows only the cut: the refused peer meets a reset or a broken
    /// pipe, never an end of stream.
    #[test]
    fn every_read_verb_reader_refuses_a_cut_answer() {
        use crate::sandbox::{control, fs_control, proc_control, task_control};
        type Reader = fn(&std::path::Path) -> io::Result<()>;
        let readers: [(&str, Reader); 11] = [
            ("lens LOG", |s| {
                proc_control::read_exec_log(s, None).map(drop)
            }),
            ("fs lens LOG", |s| {
                fs_control::read_fs_log(s, Some(1)).map(drop)
            }),
            ("proc LIST", |s| proc_control::read_pending(s).map(drop)),
            ("proc RULES", |s| {
                proc_control::read_overlay_rules(s).map(drop)
            }),
            ("egress LOG", |s| {
                control::read_log(s, None, None, false, false, None).map(drop)
            }),
            ("egress FLOWS", |s| control::read_flows(s).map(drop)),
            ("task LOG", |s| {
                task_control::read_entries(s, None).map(drop)
            }),
            ("task STATUS", |s| task_control::read_status(s).map(drop)),
            ("task INFO", |s| {
                task_control::read_info(s, "sync").map(drop)
            }),
            ("task LIST", |s| task_control::client::list(s).map(drop)),
            ("task SECRETS", |s| {
                task_control::client::secrets(s).map(drop)
            }),
        ];
        // What each shape must give: `Some(true)` a whole answer, `Some(false)` a cut one, `None`
        // the reader's own outcome for an `err` line, which only has to be something other than a
        // cut (`sbx proc rules` against an observing session reads one).
        let dir = crate::testutil::TmpDir::new();
        for (name, reader) in readers {
            for (shape, wire, whole) in [
                ("whole", &b"head=3\nok\n"[..], Some(true)),
                ("an err line", &b"err bad-request\n"[..], None),
                ("cut after a line", &b"head=3\n"[..], Some(false)),
                ("closed unanswered", &b""[..], Some(false)),
            ] {
                let socket = dir.join("answer.sock");
                let _ = std::fs::remove_file(&socket);
                let server = answer_once(&socket, wire);
                let read = reader(&socket);
                server.join().expect("the server thread");
                let cut = read.as_ref().err().is_some_and(unanswered);
                match whole {
                    Some(true) => assert!(read.is_ok(), "{name}, {shape}: {read:?}"),
                    Some(false) => assert!(cut, "{name}, {shape}: {read:?}"),
                    None => assert!(!cut, "{name}, {shape}: {read:?}"),
                }
            }
            let socket = dir.join("answer.sock");
            let _ = std::fs::remove_file(&socket);
            let server = refuse_once(&socket);
            let read = reader(&socket);
            server.join().expect("the server thread");
            assert!(
                read.as_ref().err().is_some_and(unanswered),
                "{name}, refused before its command was read: {read:?}"
            );
        }

        // The two readers addressed by session rather than by socket: `RULES` fails like the others,
        // and the `LIST` sweep leaves a session out rather than listing part of its answer as all.
        let data_dir = dir.join("data");
        std::fs::create_dir_all(control::control_dir(&data_dir)).expect("egress dir");
        let socket = control::control_socket(&data_dir, 4242);
        for (wire, whole) in [
            (&b"ok\n"[..], true),
            (&b"err bad-request\n"[..], true),
            (&b""[..], false),
        ] {
            let _ = std::fs::remove_file(&socket);
            let server = answer_once(&socket, wire);
            let read = control::query_manual(&data_dir, 4242).map(drop);
            server.join().expect("the server thread");
            assert_eq!(read.is_ok(), whole, "egress RULES: {read:?}");

            let _ = std::fs::remove_file(&socket);
            let server = answer_once(&socket, wire);
            let listed = control::list_all_within(&data_dir, std::time::Duration::from_secs(5));
            server.join().expect("the server thread");
            assert_eq!(listed.len(), usize::from(whole), "egress LIST");
        }
    }
}
