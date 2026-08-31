use super::*;

/// A detached session's trust-drop note is redacted against the launch's credential set, and
/// that set lives behind an `RwLock` whose only other reader is the notifier's delivery thread.
/// A panic there poisons the lock, and this reader used to take it with `read().ok()` — which
/// mapped "poisoned" onto `None`, the branch that writes the warning **unredacted**, into a log
/// file that outlives the session. The one event most likely to leave a half-populated needle
/// set behind would have been the event that stopped redacting against it, so recover the set
/// instead: what a panicking holder had already put there still names real credentials.
#[test]
fn a_poisoned_needle_set_still_redacts_the_trust_drop_note() {
    use crate::sandbox::proxy::SecretNeedle;
    use std::sync::{Arc, RwLock};

    let secret = "hunter2-actual-token";
    let warning = format!("project: dropped `network.allow` (token {secret}) — run `sbx trust`");
    let needles: crate::sandbox::notify_sink::Needles =
        Arc::new(RwLock::new(vec![SecretNeedle::named(
            "TOKEN",
            secret.as_bytes().to_vec(),
        )]));

    // Poison it exactly as a panic on the delivery thread would.
    let poisoner = Arc::clone(&needles);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.write().unwrap();
        panic!("delivery thread died holding the needle set");
    })
    .join();
    assert!(
        needles.read().is_err(),
        "the lock is poisoned for this reader"
    );

    let notes = trust_drop_notes(std::slice::from_ref(&warning), Some(&needles));
    assert_eq!(notes.len(), 1, "the trust drop is still recorded");
    assert!(
        !notes[0].contains(secret),
        "a poisoned lock must not fall back to writing the secret verbatim: {}",
        notes[0]
    );
    // Redacted, not discarded — the reader still learns which field was dropped and how to
    // get it back, or the note would be worthless.
    assert!(notes[0].contains("`network.allow`") && notes[0].contains("`sbx trust`"));

    // And with no wiring at all there is nothing to redact against, so the note goes out as
    // the terminal already had it — this guard must not be satisfiable by blanking everything.
    assert_eq!(
        trust_drop_notes(std::slice::from_ref(&warning), None),
        vec![warning.clone()]
    );
    // A warning that is not a trust drop is not noted here at all.
    assert!(
        trust_drop_notes(&["project: some other warning".to_string()], Some(&needles)).is_empty()
    );
}

#[test]
fn detach_log_path_is_keyed_by_pid_under_logs() {
    // The daemon, the reporting parent and `sbx session logs` must agree on the log location;
    // all three derive it from the session pid, so this is the single source of that name.
    let path = detach_log_path(Path::new("/var/lib/sbx"), 4242);
    assert_eq!(path, PathBuf::from("/var/lib/sbx/logs/4242.log"));
}

#[test]
fn the_header_open_detach_log_writes_is_the_one_the_parser_reads() {
    // The writer/parser seam. Both halves live in this file precisely so a change to one is
    // caught here: a header the parser no longer recognises does not fail loudly, it makes
    // `sbx session logs` silently replay a *previous* session's output as the current one's.
    // So this drives the real writer and parses what actually landed on disk.
    let dir = crate::testutil::TmpDir::new();
    let path = dir.join("logs").join("nested.log");
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let file = open_detach_log(&path).expect("open the session log");
    drop(file);

    let bytes = std::fs::read(&path).expect("read the session log back");
    let first = bytes.split(|&b| b == b'\n').next().expect("a first line");
    let header = parse_session_header(first).expect("the written header must parse");
    assert_eq!(
        header.pid,
        std::process::id(),
        "the header must name the session whose output follows it"
    );
    assert!(
        header.started >= before,
        "started={} must be the wall clock at open (>= {before})",
        header.started
    );

    // Appending a second session's header is what a reused pid does; both must parse, so the
    // reader can tell the two apart rather than running them together.
    let file = open_detach_log(&path).expect("reopen the session log");
    drop(file);
    let bytes = std::fs::read(&path).expect("read back after the second open");
    let headers = bytes
        .split(|&b| b == b'\n')
        .filter_map(parse_session_header)
        .count();
    assert_eq!(headers, 2, "each open must mark its own session");
}

#[test]
fn a_detached_log_notes_the_trust_drops_and_nothing_else() {
    // The record that outlives the launching terminal a detached session is about to lose.
    // Three properties hold it up, and each fails silently if it breaks: only a trust drop is
    // noted, the warning survives verbatim (a reader has to be able to act on it), and a note
    // can never be read as a session boundary — which would hide every line before it.
    let dir = crate::testutil::TmpDir::new();
    let path = dir.join("logs").join("notes.log");
    let file = open_detach_log(&path).expect("open the session log");
    note_trust_drops(
        &file,
        &[
            ".sbx.toml: ignoring `gpu` posture (untrusted — run `sbx trust`)".to_string(),
            ".sbx.toml: ignoring malformed nixpkgs source `nope`".to_string(),
        ],
        None,
    );
    drop(file);

    let text = std::fs::read_to_string(&path).expect("read the session log back");
    assert!(
        text.contains(
            "=== sbx trust-drop: .sbx.toml: ignoring `gpu` posture \
             (untrusted — run `sbx trust`) ==="
        ),
        "the dropped security field must survive the terminal that announced it: {text}"
    );
    assert!(
        !text.contains("malformed nixpkgs"),
        "a warning that is not a trust drop is not this record's business: {text}"
    );

    let notes: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("=== sbx trust-drop: "))
        .collect();
    assert_eq!(notes.len(), 1, "one note per dropped field: {text}");
    for note in notes {
        assert!(
            parse_session_header(note.as_bytes()).is_none(),
            "a note must not read as a session boundary: {note}"
        );
    }

    // A pid the kernel reuses appends a second session to this same file, and each note must
    // land on its own session's side of the boundary. A reader shows only what follows the
    // last header, so a note written before it would be attributed to the session that ended.
    let file = open_detach_log(&path).expect("reopen the session log");
    note_trust_drops(
        &file,
        &[".sbx.toml: ignoring `forward` ports (untrusted — run `sbx trust`)".to_string()],
        None,
    );
    drop(file);

    let text = std::fs::read_to_string(&path).expect("read back after the second open");
    let shape: Vec<&str> = text
        .lines()
        .map(|l| {
            if parse_session_header(l.as_bytes()).is_some() {
                "header"
            } else if l.starts_with("=== sbx trust-drop: ") {
                "note"
            } else {
                "other"
            }
        })
        .collect();
    assert_eq!(
        shape,
        ["header", "note", "header", "note"],
        "each note must follow its own session's header: {text}"
    );
}

#[test]
fn a_session_header_needs_every_field_to_parse() {
    // A line an agent prints that merely resembles a header must not be taken for one, or its
    // output would be read as a session boundary and hide everything before it.
    assert!(parse_session_header(b"=== sbx session 12 started=99 ===").is_some());
    for lookalike in [
        &b"=== sbx session 12 started=later ==="[..],
        &b"=== sbx session twelve started=99 ==="[..],
        &b"=== sbx session 12 ==="[..],
        &b"=== sbx session 12 started=99"[..],
        &b"plain agent output"[..],
    ] {
        assert!(
            parse_session_header(lookalike).is_none(),
            "must not parse: {}",
            String::from_utf8_lossy(lookalike)
        );
    }
}
