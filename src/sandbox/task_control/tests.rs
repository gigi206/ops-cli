use super::*;
// Production reads every line through `read_request_line`, which brings its own; a test client
// speaks the protocol from the other side and reads replies straight off the socket.
use crate::config::{OutputDisposition, ParamBound, TaskParam, TaskSpec};
use crate::testutil::TmpDir;
use std::io::BufRead;
use std::process::Command;
use std::time::Duration;

// --- what a caller can make the host hold ---

/// Drive `read_payloads` from the other end of a socketpair, the way the cage drives it.
///
/// The writer runs on its own thread because the point of these tests is a request larger than
/// the socket buffer: writing it from the reading thread would block against itself.
fn read_payloads_of(request: Vec<u8>) -> io::Result<Result<Payloads, &'static str>> {
    let (ours, theirs) = UnixStream::pair().expect("socketpair");
    let writer = std::thread::spawn(move || {
        let mut theirs = theirs;
        // Ignored: a refusal closes the socket while this is still writing, which is the
        // outcome under test rather than a failure of it.
        let _ = theirs.write_all(&request);
    });
    let out = read_payloads(&mut BufReader::new(ours));
    let _ = writer.join();
    out
}

/// A request line that never ends is refused instead of being buffered.
///
/// The plane's threads belong to the sbx process, and the socket the cage speaks on is bound
/// host-side: what is read here is outside the cgroup that bounds the cage's own memory, so an
/// unterminated line is host memory the cage could take.
///
/// The peer holds its end **open**, and that is what makes this test measure the ceiling. A
/// flood that ends in EOF is refused for having no final newline whatever the ceiling is, so a
/// test written that way passes with the bound removed: measured, and it did. Here an unbounded
/// read has nothing to return and the answer never comes, which the timeout turns into a
/// failure rather than a hang. The flood is finite for the same reason it is written at all.
#[test]
fn a_request_line_that_never_ends_is_refused_rather_than_buffered() {
    let (ours, theirs) = UnixStream::pair().expect("socketpair");
    let mut peer = theirs.try_clone().expect("clone");
    let flood = std::thread::spawn(move || {
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..(4 * MAX_PAYLOAD_BYTES / chunk.len()) {
            // The refusal closes the reading end, and this stops rather than failing the test:
            // being unable to finish the flood is the outcome under test.
            if peer.write_all(&chunk).is_err() {
                break;
            }
        }
    });

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_payloads(&mut BufReader::new(ours)).map_err(|e| e.kind()));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("a read that followed the flood instead of stopping at the ceiling");
    assert_eq!(outcome, Err(io::ErrorKind::InvalidData));

    drop(theirs);
    let _ = flood.join();
}

/// What a field is charged must be what a field costs.
///
/// `String::from_utf8_lossy` replaces every invalid byte with a three-byte U+FFFD, so a payload
/// declared and charged `len` was retained as up to `3 * len`: [`MAX_REQUEST_BYTES`] — the one
/// bound between the cage and a thread whose memory is sbx's, outside the cgroup bounding the
/// cage's — admitted three times what its own doc says it admits, across all
/// [`MAX_CONCURRENT_CONNS`] connections at once and with nothing recorded anywhere. Refusing the
/// payload keeps the charge exact by construction; the second half pins that this is a refusal
/// of bytes that are not text and not of text that is merely multi-byte.
#[test]
fn a_payload_that_is_not_utf8_is_refused_rather_than_expanded_past_the_ceiling() {
    let mut request = Vec::new();
    request.extend_from_slice(b"param k 4\n");
    request.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    request.extend_from_slice(b"\nrun\n");
    assert_eq!(
        read_payloads_of(request).expect("the read itself succeeds"),
        Err("payload is not valid UTF-8")
    );

    // Multi-byte text is not what this refuses, and what is stored is exactly what was charged.
    let value = "SELECT 1\nFROM café".as_bytes();
    let mut request = Vec::new();
    request.extend_from_slice(format!("param sql {}\n", value.len()).as_bytes());
    request.extend_from_slice(value);
    request.extend_from_slice(b"\nrun\n");
    let (params, _) = read_payloads_of(request)
        .expect("the read itself succeeds")
        .expect("valid UTF-8 is admitted");
    assert_eq!(
        params.get("sql").map(String::len),
        Some(value.len()),
        "the stored value must weigh what the ceiling was told it weighs"
    );
    assert_eq!(
        params.get("sql").map(String::as_str),
        Some("SELECT 1\nFROM café")
    );
}

/// One payload under the ceiling is admitted; the request they add up to is bounded too.
///
/// The per-payload ceiling is not that bound: this request is made of fields each of which is
/// legitimate. Nothing about it is refused until the total is.
#[test]
fn payloads_that_are_each_admissible_are_refused_by_what_they_add_up_to() {
    let mut request = Vec::new();
    let value = vec![b'v'; MAX_PAYLOAD_BYTES];
    for i in 0..(MAX_REQUEST_BYTES / MAX_PAYLOAD_BYTES) + 1 {
        request.extend_from_slice(format!("param k{i} {MAX_PAYLOAD_BYTES}\n").as_bytes());
        request.extend_from_slice(&value);
        request.push(b'\n');
    }
    request.extend_from_slice(b"run\n");
    assert_eq!(
        read_payloads_of(request).expect("the read itself succeeds"),
        Err("request too large")
    );
}

/// The log is bounded at 512 *entries*, not bytes, so what one entry may hold is the other half
/// of that bound. The task name is the tail of a `RUN <name>` line, capped only at a mebibyte,
/// and a name matching nothing is stored twice over — once as the entry's task, once inside the
/// `no such task \u{60}{name}\u{60}` reason. A cage asking repeatedly for tasks that do not exist
/// could therefore pin roughly a gibibyte of supervisor memory in a log it cannot even read.
///
/// Sanitising at render time did not bound it: the raw bytes were already in the ring.
#[test]
fn one_log_entry_cannot_hold_a_megabyte_the_cage_chose() {
    let huge = "x".repeat(MAX_PAYLOAD_BYTES);
    let entry = refusal(1, &huge, &format!("no such task `{huge}`"));

    assert!(
        entry.task.len() <= 4 * 512,
        "the stored task name is unbounded: {} bytes",
        entry.task.len()
    );
    let refused = entry
        .refused
        .as_deref()
        .expect("a refusal carries its reason");
    assert!(
        refused.len() <= 4 * 512,
        "the stored reason is unbounded: {} bytes",
        refused.len()
    );
    // Truncated rather than dropped, so the record still says what was asked for.
    assert!(entry.task.starts_with("xxx"), "{}", entry.task);
    assert!(refused.starts_with("no such task"), "{refused}");

    // A name of ordinary length is untouched, or the cap would be rewriting real records.
    let ordinary = refusal(2, "build", "no such task `build`");
    assert_eq!(ordinary.task, "build");
    assert_eq!(ordinary.refused.as_deref(), Some("no such task `build`"));
}

/// A caller sending nothing but keys is bounded too, and by the same rule.
///
/// An empty payload costs no value bytes and a map entry every time, so a ceiling counting
/// only values would not see this at all. The keys are what grows, which is why the bound
/// counts them.
#[test]
fn a_flood_of_empty_payloads_is_bounded_by_the_keys_it_is_made_of() {
    let mut request = Vec::new();
    let key = "k".repeat(1024);
    for i in 0..(MAX_REQUEST_BYTES / 1024) + 1 {
        request.extend_from_slice(format!("param {key}{i} 0\n\n").as_bytes());
    }
    request.extend_from_slice(b"run\n");
    assert_eq!(
        read_payloads_of(request).expect("the read itself succeeds"),
        Err("request too large")
    );
}

/// The field that names nothing is bounded too, and it is the one the rule missed.
///
/// `param  0` declares no key and no payload, so a ceiling counting keys and values saw a cost
/// of zero and let it repeat without end: the count this bound is supposed to bound as a
/// consequence was not bounded at all, and one cage connection could hold a host thread reading
/// eight bytes at a time for as long as it liked. Every field is charged its own framing now,
/// so a field that carries nothing still costs something.
#[test]
fn a_flood_of_fields_that_name_nothing_is_bounded_too() {
    let mut request = Vec::new();
    // `param  0`: an empty key, a zero-length payload, and its closing newline. What it is
    // charged is its request line, eight bytes, so that is what the count has to exceed.
    let field = b"param  0\n\n";
    let charged = b"param  0".len();
    for _ in 0..(MAX_REQUEST_BYTES / charged) + 1 {
        request.extend_from_slice(field);
    }
    request.extend_from_slice(b"run\n");
    assert_eq!(
        read_payloads_of(request).expect("the read itself succeeds"),
        Err("request too large")
    );
}

/// The negative control: an ordinary request is not caught by any of it.
#[test]
fn an_ordinary_request_passes_every_bound() {
    let mut request = Vec::new();
    request.extend_from_slice(b"param sql 8\nSELECT 1\n");
    request.extend_from_slice(b"env TZ 3\nUTC\n");
    request.extend_from_slice(b"run\n");
    let (params, env) = read_payloads_of(request)
        .expect("the read succeeds")
        .expect("an ordinary request is admitted");
    assert_eq!(params.get("sql").map(String::as_str), Some("SELECT 1"));
    assert_eq!(env.get("TZ").map(String::as_str), Some("UTC"));
}

/// One probe of the crossing socket: `Some(reply)` when the plane served it, `None` when it
/// refused the connection.
///
/// A refusal is **not** an empty read, and measuring it as one is what a first version of this
/// did. The plane closes a refused connection while the request is still unread in its receive
/// queue, and a Unix socket closed that way resets: the caller sees `ECONNRESET`, not an
/// end-of-file. Emptiness alone would also match a connection that was served but slow to
/// answer, which is a loaded machine rather than a ceiling, so the two are told apart by how
/// the read ended.
fn probe_plane(socket: &Path) -> Option<Vec<u8>> {
    let Ok(mut probe) = UnixStream::connect(socket) else {
        return None;
    };
    if probe.write_all(b"LIST\n").is_err() {
        return None;
    }
    let _ = probe.set_read_timeout(Some(Duration::from_secs(2)));
    let mut reply = Vec::new();
    match probe.read_to_end(&mut reply) {
        // Closed without a word, either way round: reset while the request sat unread, or a
        // clean end-of-file if it had been read first.
        Ok(_) if reply.is_empty() => None,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) =>
        {
            None
        }
        // Anything else, including a read that timed out with nothing: served, however slowly.
        _ => Some(reply),
    }
}

/// A connection past the ceiling is refused instead of pinning another host thread.
///
/// Each connection is served on its own thread of the sbx process, and a `RUN` holds its thread
/// for as long as the task's timeout allows. This was the only accept loop in the binary
/// without a ceiling, of four, so a caller opening connections in a loop spawned host threads
/// until the process could not make another.
///
/// The held connections say nothing: each is accepted and then blocks reading its first line,
/// which is how a slot is held for as long as the test keeps its end open.
#[test]
fn a_connection_past_the_ceiling_is_refused_rather_than_served() {
    let Some((_data, plane, _script)) = plane_and_client(vec![probe_task()]) else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let mut held = Vec::new();
    for _ in 0..MAX_CONCURRENT_CONNS {
        held.push(UnixStream::connect(&plane.cage_socket).expect("connect"));
    }

    // The accept loop is a thread of its own, so the ceiling is reached shortly after the last
    // connect returns rather than at it.
    let refused = (0..200).any(|_| {
        if probe_plane(&plane.cage_socket).is_none() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
        false
    });
    assert!(refused, "the ceiling never refused a connection");

    // The negative control, on the same socket: a slot given back is a caller served.
    held.pop();
    let served = (0..200).any(|_| {
        if probe_plane(&plane.cage_socket).is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
        false
    });
    assert!(served, "a returned slot must serve the next caller");
}

/// Stand the production [`serve_cage`] up over a socketpair with a short first-request budget,
/// and hand back the caller's end plus a channel carrying what the server returned.
///
/// [`plane_and_client`] would do this through a real listener, but the budget is what is under
/// test here and the listener passes the real thirty seconds. Same server function either way.
fn cage_conn(budget: Duration) -> (UnixStream, std::sync::mpsc::Receiver<io::Result<()>>) {
    let (server, client) = UnixStream::pair().expect("socketpair");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let engine = super::super::task::TaskEngine::inventory_only(vec![probe_task()]);
        let log = TaskLog::new();
        let quota = AtomicU64::new(DEFAULT_CALL_QUOTA);
        let _ = tx.send(serve_cage(server, &engine, &log, &quota, budget));
    });
    (client, rx)
}

/// A connection that says nothing is given up on instead of holding its thread and its slot.
///
/// This socket is bound host-side and mounted into the cage, and it had no read deadline at
/// all: every other cage-facing socket in the binary bounds its first message, and this one
/// accepted a connection, took one of [`MAX_CONCURRENT_CONNS`] slots and a host thread, and
/// then blocked in `read` for as long as the peer cared to stay quiet. Thirty-two of those and
/// the plane the agent invokes tasks through answers nobody for the rest of the session —
/// silently, since a connection refused by the ceiling is deliberately not logged.
///
/// The caller's end stays **open** and simply says nothing, which is what makes this measure
/// the deadline: a peer that closed would be given up on at end-of-file whatever the deadline
/// was, so a test written that way passes with the deadline removed.
#[test]
fn a_connection_that_says_nothing_is_given_up_on_rather_than_holding_its_slot() {
    let budget = Duration::from_millis(200);
    let (held, rx) = cage_conn(budget);
    let out = rx.recv_timeout(Duration::from_secs(5));
    assert!(
        out.is_ok(),
        "a connection that said nothing kept its thread and its slot past the deadline"
    );
    assert!(
        out.expect("the server returned").is_err(),
        "a peer that ran out its deadline is a fault, not a clean hangup"
    );
    drop(held);

    // The negative control, on the same budget: a caller that speaks is served in full. Without
    // it this test would pass just as well against a plane that dropped every connection.
    let (mut client, rx) = cage_conn(budget);
    client.write_all(b"LIST\n").expect("write LIST");
    let mut reply = String::new();
    BufReader::new(client.try_clone().expect("clone"))
        .read_to_string(&mut reply)
        .expect("read the reply");
    assert!(
        reply.starts_with("task probe\t"),
        "the declared operation must still be listed: {reply:?}"
    );
    assert!(
        reply.ends_with("ok\n"),
        "and the answer completed: {reply:?}"
    );
    assert!(
        rx.recv_timeout(Duration::from_secs(5))
            .expect("the server returned")
            .is_ok(),
        "serving a caller that spoke is not a fault"
    );
}

/// A request trickled a byte at a time cannot outlast the budget by renewing the socket timeout.
///
/// The two halves are not the same bound, which is the whole of [`super::deadline`]: a receive
/// timeout bounds one `read`, and a peer that produces a byte just inside it starts a fresh one
/// every time. So the socket timeout alone would hold this thread for as long as the peer keeps
/// dribbling — here six seconds, and a real one would not stop.
///
/// The peer never writes a newline, so nothing about the request is ever complete; the only
/// thing that can end this is the wall-clock budget over the whole request.
#[test]
fn a_request_trickled_a_byte_at_a_time_cannot_outlast_the_budget() {
    let budget = Duration::from_millis(300);
    let (client, rx) = cage_conn(budget);
    std::thread::spawn(move || {
        let mut peer = client;
        for _ in 0..60 {
            // The write fails once the server has given up and closed, which is the outcome
            // under test rather than a failure of it.
            if peer.write_all(b"L").is_err() {
                return;
            }
            // A third of the budget: each byte lands well inside the socket's own timeout, so
            // that timeout is renewed and never fires.
            std::thread::sleep(budget / 3);
        }
    });
    let out = rx.recv_timeout(Duration::from_secs(2));
    assert!(
        out.is_ok(),
        "a trickled request outlasted its budget by renewing the socket timeout"
    );
    assert!(
        out.expect("the server returned").is_err(),
        "a request that never arrived is a fault, not a clean hangup"
    );
}

/// A value with the two properties a line-oriented client would get wrong: an embedded newline
/// (which would forge a protocol line if it were not length-framed) and a multi-byte character
/// (which a client counting characters instead of bytes would under-announce).
const AWKWARD: &str = "SELECT 1\nFROM caf\u{e9}";

fn probe_task() -> TaskSpec {
    TaskSpec {
        unmask: Vec::new(),
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
        exec: Default::default(),
        output: false,
        origin: crate::config::TaskOrigin::Project,
        timeout_from: crate::config::Ceiling::Declared,
        max_output_from: crate::config::Ceiling::Declared,
    }
}

/// A live plane serving `tasks`, plus a client script pointed at it.
///
/// The server is the production one — [`start`] and [`serve_cage`], not a stand-in — and the
/// client is written by the production generator. Only the programs differ: the shipped client
/// names the cage's shell and `socat`, and here it names the host's, because that is what a test
/// process can execute. That the launcher passes the cage's own is a separate, static fact.
fn plane_and_client(tasks: Vec<TaskSpec>) -> Option<(TmpDir, TaskPlane, PathBuf)> {
    plane_and_client_inner(tasks, None)
}

/// [`plane_and_client`] whose engine launches `launcher` instead of `/nonexistent/bwrap`.
///
/// The script is written into the plane's own `TmpDir`, so it lives exactly as long as the
/// fixture and needs no cleanup of its own.
fn plane_and_client_with_launcher(
    tasks: Vec<TaskSpec>,
    launcher: &str,
) -> Option<(TmpDir, TaskPlane, PathBuf)> {
    plane_and_client_inner(tasks, Some(launcher))
}

fn plane_and_client_inner(
    tasks: Vec<TaskSpec>,
    launcher: Option<&str>,
) -> Option<(TmpDir, TaskPlane, PathBuf)> {
    let bash = crate::pathfind::find_on_path("bash")?;
    let socat = crate::pathfind::find_on_path("socat")?;
    let head = crate::pathfind::find_on_path("head")?;
    let data = TmpDir::new();
    let engine = match launcher {
        None => super::super::task::TaskEngine::inventory_only(tasks),
        Some(body) => {
            use std::os::unix::fs::PermissionsExt as _;
            let path = data.path().join("launcher");
            std::fs::write(&path, format!("#!{}\n{body}\n", bash.display()))
                .expect("write the launcher");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("make the launcher executable");
            super::super::task::TaskEngine::inventory_with_launcher(tasks, path)
        }
    };
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
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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
    std::fs::write(&launcher, format!("#!{}\n{body}", bash.display())).expect("write the launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make the launcher executable");

    let engine =
        super::super::task::TaskEngine::inventory_only(vec![probe_task()]).with_launcher(launcher);
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

/// A plane whose single operation declares an output directory, over a real project tree.
///
/// The tree has to be real: the directory's path is derived from the project's canonical
/// location, so an engine pointed at a path that does not exist cannot claim one at all.
fn plane_with_output(body: &str) -> Option<(TmpDir, TmpDir, TaskPlane)> {
    use std::os::unix::fs::PermissionsExt;
    let bash = crate::pathfind::find_on_path("bash")?;
    let socat = crate::pathfind::find_on_path("socat")?;
    let head = crate::pathfind::find_on_path("head")?;
    let data = TmpDir::new();
    let project = TmpDir::new();

    let launcher = data.path().join("launcher");
    std::fs::write(&launcher, format!("#!{}\n{body}", bash.display())).expect("the launcher");
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .expect("make the launcher executable");

    let mut task = probe_task();
    task.output = true;
    let engine = super::super::task::TaskEngine::inventory_only(vec![task])
        .with_launcher(launcher)
        .with_tree(data.path(), project.path().to_path_buf());
    let programs = ClientPrograms {
        bash: &bash,
        socat: &socat,
        head: &head,
    };
    let plane = start(data.path(), std::process::id(), engine, &programs).expect("start");
    Some((data, project, plane))
}

/// A second detached invocation of an operation that writes is refused **synchronously**, while
/// the first is still holding the directory.
///
/// This is the case the admission split exists for. A task's output directory is one per *task*,
/// so two invocations at once would interleave in it — and a detached caller stops listening the
/// moment it has an id, so discovering that inside the thread would mean handing back an id for
/// an invocation that died on a refusal nobody ever saw. The assertion that carries it is the
/// **absent id**: refused before admission, not after.
#[test]
fn a_second_detached_writer_is_refused_before_it_is_given_an_id() {
    let Some((_data, _project, plane)) = plane_with_output("sleep 3\nprintf 'wrote\\n'\n") else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    let params = BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]);

    let first = client::run_detached(&host, "probe", &params, &BTreeMap::new()).expect("start");
    assert_eq!(first.error, None, "the first writer must be admitted");

    let second = client::run_detached(&host, "probe", &params, &BTreeMap::new()).expect("start");
    let reason = second
        .error
        .expect("a second concurrent writer must be refused");
    assert!(
        reason.contains("still writing to its output directory"),
        "the refusal must name what is in the way: {reason}"
    );
    assert_eq!(
        read_status(&host)
            .expect("status")
            .iter()
            .filter(|row| row.id != first.id)
            .count(),
        0,
        "a refused invocation must not be running"
    );

    // And once the first has finished, the directory is free again — the claim is released by
    // the thread that took it, not by the connection that asked for it.
    let done = eventually(|| {
        let answer = client::result(&host, first.id).expect("result");
        answer.error.is_none().then_some(answer)
    })
    .expect("the first writer must finish");
    assert!(
        done.output.is_some(),
        "an operation that declares an output directory must report it"
    );
    let third = client::run_detached(&host, "probe", &params, &BTreeMap::new()).expect("start");
    assert_eq!(
        third.error, None,
        "the directory must be free once the invocation holding it has ended"
    );
    let _ = stop_invocation(&host, third.id);
}

/// An operation that takes longer than an instant still answers the in-cage caller.
///
/// The transport under the client is `socat`, which by default gives the far end half a second
/// after this side stops writing and then tears the connection down — so an operation that runs
/// for two seconds returned a truncated answer, while the very same call succeeded host-side.
///
/// A declared operation is a command being run; taking time is its normal case, not its edge.
#[test]
fn an_operation_that_takes_seconds_still_answers_the_cage() {
    let Some((_data, _plane, script)) = slow_plane_and_client("2") else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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

/// Poll `f` until it answers, or give up. The invocation ids these tests work with cannot be
/// predicted — the counter is per process and the tests share one — so they are read the way a
/// person reads them, and a command that takes time is waited for rather than assumed done.
fn eventually<T>(mut f: impl FnMut() -> Option<T>) -> Option<T> {
    for _ in 0..400 {
        if let Some(value) = f() {
            return Some(value);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    None
}

/// The whole of `--detach`: the caller is answered with an id while the command is still running,
/// the invocation is visible as detached in the meantime, and its output is there to collect
/// afterwards.
///
/// The load-bearing assertion is the middle one. A `run_detached` that merely returned early
/// would pass the first and the third even if it had run the command inline and thrown the answer
/// away; seeing the invocation *live* under its own id is what says the command is genuinely
/// elsewhere and still reachable by `status` and `stop`.
#[test]
fn a_detached_invocation_is_answered_at_once_and_collected_afterwards() {
    let Some((_data, plane, _script)) = plane_with_launcher("sleep 2\nprintf 'the-answer\\n'\n")
    else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    let started = client::run_detached(
        &host,
        "probe",
        &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
        &BTreeMap::new(),
    )
    .expect("the detached start");

    assert_eq!(
        started.error, None,
        "the invocation must have been admitted"
    );
    assert_ne!(started.id, 0, "an admitted invocation has an id");
    assert_eq!(
        started.stdout, None,
        "a detached start carries no streams — nothing has run yet"
    );

    let row = read_status(&host)
        .expect("status")
        .into_iter()
        .find(|row| row.id == started.id)
        .expect("the detached invocation must be running while its caller is free");
    assert!(
        row.fields.iter().any(|f| f == "detached=1"),
        "status must say nobody is waiting for it: {:?}",
        row.fields
    );

    let result = eventually(|| {
        let answer = client::result(&host, started.id).expect("result");
        answer.error.is_none().then_some(answer)
    })
    .expect("the detached invocation must finish and hold its result");
    assert_eq!(
        result.stdout.as_deref(),
        Some("the-answer\n"),
        "collecting must give the command's own output"
    );
    assert_eq!(result.exit, 0, "and its own exit code");
    assert_eq!(result.id, started.id, "one id, whichever verb reports it");
}

/// An invocation that is finishing is never reported as one that never existed.
///
/// The run releases its registry entry and stores its result at two different moments, and the
/// reader consults both. Caught in between, `RESULT <id>` falls through to branches that say
/// "no invocation" or "its result is no longer held" — a caller that asks once believes either.
/// So the only answer this loop tolerates before the result is that the invocation is still
/// running, which is the answer a caller retries on.
///
/// It polls without sleeping and runs the shortest command there is, because the window it is
/// looking for is two statements wide, and it repeats the whole invocation because landing in
/// those two statements is a matter of chance. One attempt catches the defect often enough to
/// prove it exists and rarely enough to be no guard at all; the repetition is what turns that
/// into a test. It cannot fail the other way: while the registration is held, "still running"
/// is a true answer, so a correct tree has nothing here to trip on.
#[test]
fn a_finishing_invocation_is_never_reported_as_one_that_never_ran() {
    let Some((_data, plane, _script)) = plane_with_launcher("printf 'done\n'\n") else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    for _ in 0..10 {
        let started = client::run_detached(
            &host,
            "probe",
            &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
            &BTreeMap::new(),
        )
        .expect("the detached start");
        assert_eq!(
            started.error, None,
            "the invocation must have been admitted"
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let answer = client::result(&host, started.id).expect("an answer");
            let Some(why) = answer.error.as_deref() else {
                break;
            };
            assert!(
                why.contains("is still running"),
                "an invocation between its last statement and its stored result is still \
                 running, and nothing else is true of it — answered instead: {why:?}"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "the invocation never produced a result"
            );
        }
    }
}

/// Reading a result does not consume it: a caller whose terminal scrolled gets a second look.
#[test]
fn a_collected_result_stays_collectable() {
    let Some((_data, plane, _script)) = plane_with_launcher("printf 'twice\\n'\n") else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    let started = client::run_detached(
        &host,
        "probe",
        &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
        &BTreeMap::new(),
    )
    .expect("the detached start");
    let first = eventually(|| {
        let answer = client::result(&host, started.id).expect("result");
        answer.error.is_none().then_some(answer)
    })
    .expect("a result");
    let second = client::result(&host, started.id).expect("result");
    assert_eq!(
        first.stdout, second.stdout,
        "a second collection must give the same result, not an empty one"
    );
}

/// A refusal a caller could act on happens **before** it is told the invocation was admitted.
///
/// This is the reason the engine's admission is split from its run. A detached caller stops
/// listening the moment it has an id, so an id handed back for an invocation that then dies on a
/// bad parameter would be a caller told "it is running" about something that never ran.
#[test]
fn a_detached_invocation_is_refused_before_it_is_given_an_id() {
    let Some((_data, plane, _script)) = plane_and_client(vec![probe_task()]) else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    let started = client::run_detached(
        &host,
        "probe",
        &BTreeMap::from([("sql".to_string(), "not the declared value".to_string())]),
        &BTreeMap::new(),
    )
    .expect("the detached start");
    assert!(
        started.error.is_some(),
        "a value outside its declared bound must be refused synchronously"
    );
    assert!(
        read_status(&host).expect("status").is_empty(),
        "nothing may be running after a refusal"
    );
}

/// Detaching is not something a cage can ask for. The verb lives on the host-only socket, and the
/// crossing socket does not know it — which is the access control itself, not a check that could
/// be forgotten: a cage that could start an invocation it cannot see or stop would be creating
/// invocations nobody owns, several at once.
#[test]
fn the_crossing_socket_does_not_know_how_to_detach() {
    let Some((_data, plane, _script)) = plane_and_client(vec![probe_task()]) else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let refused = client::run_detached(
        // The socket a cage reaches, rather than the host-only one the verb belongs to.
        &plane.cage_socket,
        "probe",
        &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
        &BTreeMap::new(),
    )
    .expect("an answer");
    assert_eq!(
        refused.error.as_deref(),
        Some("unknown command"),
        "the crossing socket must not serve DETACH"
    );
    assert_eq!(refused.id, 0, "and must not have admitted anything");
}

/// Past the concurrency cap, a further detached invocation is refused rather than queued.
///
/// The session's call quota does not cover this: it bounds how many invocations are ever started,
/// not how many run together, and detaching is what removes the caller's own wait as a limit.
#[test]
fn detached_invocations_are_capped_while_they_are_live() {
    let Some((_data, plane, _script)) = plane_with_launcher("exec sleep 20\n") else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    let start_one = || {
        client::run_detached(
            &host,
            "probe",
            &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
            &BTreeMap::new(),
        )
        .expect("a detached start")
    };
    let mut ids = Vec::new();
    for _ in 0..super::super::task::MAX_DETACHED {
        let started = start_one();
        assert_eq!(started.error, None, "up to the cap, each one is admitted");
        ids.push(started.id);
    }
    let over = start_one();
    let reason = over.error.expect("past the cap, an invocation is refused");
    assert!(
        reason.contains("detached invocations are already running"),
        "the refusal must say what the limit is about: {reason}"
    );

    for id in ids {
        let _ = stop_invocation(&host, id);
    }
}

/// The four things a session can say about an invocation's result are kept apart, because they
/// call for different things: wait, look elsewhere, or stop looking.
#[test]
fn a_result_tells_running_from_foreground_from_unknown() {
    let Some((_data, plane, _script)) = plane_with_launcher("exec sleep 20\n") else {
        skip_incapable!("skipping: bash, socat or head is not on PATH");
        return;
    };
    let host = plane.log_socket.clone();
    let cage = plane.cage_socket.clone();

    let unknown = client::result(&host, 999_999).expect("an answer");
    assert_eq!(
        unknown.error.as_deref(),
        Some("no invocation 999999"),
        "an id this session never drew is not a dropped result"
    );

    let running = client::run_detached(
        &host,
        "probe",
        &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
        &BTreeMap::new(),
    )
    .expect("the detached start");
    let answer = client::result(&host, running.id).expect("an answer");
    assert_eq!(
        answer.error.as_deref(),
        Some(&*format!("invocation {} is still running", running.id)),
        "a result that has not happened yet is not a missing one"
    );
    let _ = stop_invocation(&host, running.id);

    // A foreground invocation's result went to the caller that waited for it, and was never kept
    // here — which is a different thing to be told than "there is no such invocation".
    let attached = std::thread::spawn(move || {
        client::run(
            &cage,
            "probe",
            &BTreeMap::from([("sql".to_string(), AWKWARD.to_string())]),
            &BTreeMap::new(),
        )
    });
    let id = eventually(|| {
        read_status(&host)
            .expect("status")
            .iter()
            .find(|row| row.fields.iter().any(|f| f == "detached=0"))
            .map(|row| row.id)
    })
    .expect("the foreground invocation must be visible while it runs");
    let _ = stop_invocation(&host, id);
    let _ = attached.join().expect("the caller thread");

    let answer = client::result(&host, id).expect("an answer");
    assert_eq!(
        answer.error.as_deref(),
        Some(&*format!(
            "invocation {id} did not run detached, so its result went to the caller that waited \
             for it"
        )),
        "a foreground invocation is named as such rather than reported missing"
    );
}

/// The result ring is bounded, and what falls out of it is answerable as *dropped* rather than as
/// *never existed* — the log entry is what survives to say so.
#[test]
fn the_result_ring_evicts_its_oldest() {
    let results = TaskResults::default();
    for id in 1..=(RESULT_CAPACITY as u64 + 1) {
        results.store(id, Err(format!("result {id}")));
    }
    assert!(
        results.get(1).is_none(),
        "the oldest must be gone once the ring is full"
    );
    assert!(
        results.get(2).is_some(),
        "and the one after it must still be held"
    );
    assert!(
        results.get(RESULT_CAPACITY as u64 + 1).is_some(),
        "as must the newest"
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
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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
    // A launcher that exists and writes a marker of its own, because the subject below is what
    // the command wrote and not how a failed exec is worded. See
    // [`super::super::task::TaskEngine::inventory_with_launcher`]: with `/nonexistent/bwrap` the
    // wording is the host's -- `systemd-run` names the program under a scope, a bare
    // `Command::spawn` names nothing without one -- so the assertion measured the user manager.
    let Some((_data, _plane, script)) =
        plane_and_client_with_launcher(vec![probe_task()], "echo '<<STDERR-MARKER>>' >&2; exit 7")
    else {
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
        err.contains("<<STDERR-MARKER>>"),
        "the command's stderr must reach the caller verbatim: {err}"
    );
    // The command's own status, not a refusal (125) and not a launch failure: it crossed the
    // wire beside its stderr. Pinning the exact code is what the previous `assert_ne!` could
    // not do, having no command that chose one.
    assert_eq!(
        out.status.code(),
        Some(7),
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
        skip_incapable!("skipping: bash, socat or head is not on PATH");
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
        redacted_withheld: 0,
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
        redacted_withheld: 0,
        timed_out: false,
        stopped: false,
        elapsed_ms: 4,
        nonce: None,
        refused: vec![
            crate::sandbox::proc_enforce::Refusal {
                caller: "/nix/store/demo/bin/psql".to_string(),
                target: "/nix/store/demo/bin/sh".to_string(),
            },
            crate::sandbox::proc_enforce::Refusal {
                caller: String::new(),
                target: "/nix/store/demo/bin/base64".to_string(),
            },
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
        err.contains("/nix/store/demo/bin/psql  ->  /nix/store/demo/bin/sh"),
        "with the caller beside it — the target alone would send a reader to add an entry that \
         is already there: {err}"
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
        redacted_withheld: 0,
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
        cursor: 0,
        at_epoch_ms: 0,
        started_epoch_ms: 0,
        task: task.to_string(),
        exit,
        redacted: 2,
        truncated: false,
        timed_out: false,
        stopped: false,
        elapsed_ms: 12,
        refused: None,
        detached: false,
    }
}

// The log is the trustworthy record: the timestamp is stamped host-side and the substitution
// count is host-side — none of it is anything a caller can forge. The id is the *invocation's*,
// carried in rather than counted here, so one number names an invocation everywhere.
/// A cursor at `u64::MAX` is answered, not panicked on.
///
/// `after` is whatever the caller wrote on the wire, and on the cage-facing socket the caller is
/// the adversary. The eviction gap was `oldest.cursor > after + 1`, which at `u64::MAX` panics in
/// a debug build — while the ring's lock is held, so it would poison the log for the rest of the
/// session — and wraps in a release one into an eviction count that was never true. The `TaskLog`
/// doc gives "no arithmetic that can overflow" as a reason the lock cannot be poisoned, so this
/// was the one line falsifying its own guarantee.
#[test]
fn a_cursor_at_the_end_of_the_number_line_is_answered_not_panicked_on() {
    let log = TaskLog::new();
    log.push(entry(4, "db-query", 0));
    let (entries, dropped, _head) = log.since(u64::MAX);
    assert!(
        entries.is_empty(),
        "nothing can be newer than the largest cursor there is"
    );
    assert_eq!(
        dropped, 0,
        "and nothing was missed reaching it — a wrapped subtraction reported otherwise"
    );
}

#[test]
fn the_log_keeps_the_invocations_own_id_and_stamps_the_time() {
    let log = TaskLog::new();
    log.push(entry(4, "db-query", 0));
    log.push(entry(5, "db-query", 1));
    let (entries, dropped, head) = log.since(0);
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0].seq, 4,
        "the entry keeps the id the invocation was admitted under"
    );
    assert_eq!(entries[1].seq, 5);
    assert_eq!(dropped, 0);
    assert!(
        entries[0].at_epoch_ms > 1_600_000_000_000,
        "the timestamp is stamped host-side, in epoch milliseconds"
    );
    assert_eq!(
        head, 2,
        "the head counts the appends, whatever the ids were"
    );

    let (tail, _, _) = log.since(1);
    assert_eq!(tail.len(), 1, "a cursor returns only what is past it");
    assert_eq!(tail[0].seq, 5);
}

// The trap the append-order cursor exists to avoid, and the reason a cursor over ids was never
// followable: an id is drawn when an invocation is *admitted*, its entry lands when it
// *finishes*. So a long invocation admitted first can be recorded after a short one admitted
// later, and a reader whose cursor had already passed the short one's higher id would never be
// shown the long one at all. Silent loss, in the record whose job is to miss nothing.
#[test]
fn the_log_cursor_follows_append_order_not_invocation_ids() {
    let log = TaskLog::new();
    // Admitted second (id 5), finished first.
    log.push(entry(5, "quick", 0));
    let (first, _, head) = log.since(0);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].seq, 5);
    assert_eq!(head, 1);

    // Admitted first (id 4), finished second — the lower id lands later.
    log.push(entry(4, "slow", 0));
    let (next, _, head) = log.since(head);
    assert_eq!(
        next.len(),
        1,
        "an append past the cursor must be yielded even though its id is lower"
    );
    assert_eq!(next[0].seq, 4);
    assert_eq!(head, 2);

    let (nothing, _, _) = log.since(head);
    assert!(
        nothing.is_empty(),
        "a cursor at the head yields nothing until something else is appended"
    );
}

// The writer and the reader are one format, and a drift between them does not fail loudly: it
// drops entries or files them at the wrong time. So this drives the real writer and parses what
// it actually emitted — over a value carrying the two things that break a naive split, a space
// and an `=`.
#[test]
fn an_entry_survives_the_round_trip_through_its_own_wire_line() {
    let mut written = entry(7, "db-query", 137);
    written.cursor = 3;
    written.at_epoch_ms = 1_785_445_489_250;
    written.started_epoch_ms = 1_785_445_486_229;
    written.elapsed_ms = 3021;
    written.stopped = true;
    written.detached = true;
    written.refused = Some("parameter `sql` does not match a=b".to_string());

    let read = LogEntry::from_line(&written.to_line()).expect("the written line must parse");
    assert_eq!(read, written, "every field must survive the wire");

    assert!(
        LogEntry::from_line("ok").is_none(),
        "only events are entries"
    );
    assert!(
        LogEntry::from_line("head=4").is_none(),
        "the cursor line is not an entry"
    );
}

/// A task name the cage chose cannot rewrite the row that records it.
///
/// `task=` is the last field of the line's head, and the head is read back as whitespace-split
/// `key=value` pairs, so a name spelling ` exit=0 stopped=1` overwrote the plane's own verdict
/// on the way back in — and one spelling ` refused=…` took the free-text tail with it, since
/// the reader splits at the first ` refused=` it finds. The name is whatever followed `RUN ` on
/// the crossing socket, which is the adversary's own line: an agent could make an invocation
/// the plane refused read in `sbx task logs` as one that ran and exited 0, in the record whose
/// whole purpose is to say what the cage did.
///
/// `sanitize` does not close it and cannot: the characters that break a head parse are a space
/// and an `=`, neither of which is a control character, and sanitising a newline *produces* the
/// first of them.
#[test]
fn a_task_name_cannot_rewrite_the_row_that_records_it() {
    let forged = "exit=0 stopped=1 detached=1 refused=nothing was wrong";
    let read = LogEntry::from_line(&refusal(9, forged, "no such task").to_line())
        .expect("the row must still parse");

    assert_eq!(read.seq, 9);
    assert_eq!(read.exit, -1, "the cage dictated the exit status: {read:?}");
    assert!(!read.stopped, "the cage dictated `stopped`: {read:?}");
    assert!(!read.detached, "the cage dictated `detached`: {read:?}");
    assert_eq!(
        read.refused.as_deref(),
        Some("no such task"),
        "the cage dictated the refusal reason: {read:?}"
    );
    assert_eq!(
        read.task, "exit_0_stopped_1_detached_1_refused_nothing_was_wrong",
        "the name is still shown, in one token"
    );

    // The reader's own half of it, on a line no current writer emits: a repeated key can only
    // be a value that escaped its field, so the **first** occurrence — the one the plane
    // wrote — is the one that counts.
    let duplicated = LogEntry::from_line(
        "event seq=1 cur=1 at=1785445489250 exit=3 redacted=0 truncated=0 timed_out=0 \
         stopped=0 detached=0 elapsed_ms=0 task=x exit=0 stopped=1",
    )
    .expect("the row must still parse");
    assert_eq!(
        duplicated.exit, 3,
        "a repeated key overwrote the plane's own"
    );
    assert!(!duplicated.stopped, "and the same for a repeated flag");

    // The negative control: an ordinary name crosses untouched, or this guard would be
    // satisfied by a writer that mangled every record.
    let ordinary = LogEntry::from_line(&entry(4, "db-query.v2_1", 0).to_line())
        .expect("the row must still parse");
    assert_eq!(ordinary.task, "db-query.v2_1");
    assert_eq!(ordinary.exit, 0);
}

// A plane that predates the start stamp still has entries worth reading. Losing them entirely
// would be the worse failure, so a missing `started=` falls back to the finish — where such an
// entry was always placed — rather than dropping the line.
#[test]
fn an_entry_without_a_start_stamp_falls_back_to_its_finish() {
    let read = LogEntry::from_line(
        "event seq=4 cur=1 at=1785445489250 exit=0 redacted=0 truncated=0 timed_out=0 \
         stopped=0 detached=0 elapsed_ms=3021 task=slow",
    )
    .expect("an entry missing only the start stamp still parses");
    assert_eq!(read.started_epoch_ms, 1_785_445_489_250);
    assert_eq!(read.at_epoch_ms, read.started_epoch_ms);
}

// A session outlives the binary that launched it, so rebuilding sbx mid-session leaves a new
// reader asking a plane that still stamps in seconds. Rendered as milliseconds that is a day in
// 1970 — no crash, just a wrong answer in the field a merged view sorts on.
#[test]
fn a_stamp_in_seconds_from_an_older_plane_is_read_as_the_same_moment() {
    // No `cur=` and no `started=` either: an entry from before any of this. It still reads,
    // because it still has everything needed to be *placed* — dropping it would lose the record
    // rather than protect it. Only following such a plane is declined, by its reader.
    let read = LogEntry::from_line(
        "event seq=4 at=1785445489 exit=0 redacted=0 truncated=0 timed_out=0 stopped=0 \
         detached=0 elapsed_ms=0 task=slow",
    )
    .expect("an older plane's entry is still worth reading");
    assert_eq!(
        read.at_epoch_ms, 1_785_445_489_000,
        "its seconds stamp names the same moment in milliseconds"
    );
    assert_eq!(read.started_epoch_ms, read.at_epoch_ms);
    assert_eq!(read.cursor, 0, "and it carries no append cursor");

    assert_eq!(
        epoch_ms(1_785_445_489_250),
        1_785_445_489_250,
        "a stamp already in milliseconds is left alone"
    );
}

// Why an entry carries two stamps. It is written when an invocation *ends*, so a view that
// ordered on the finish would file a slow invocation after everything that ran while it was
// still going — reading as though it came last when it came first. The start is what a
// time-ordered view sorts on, and these two must therefore disagree for a slow invocation.
#[test]
fn an_invocation_is_stamped_where_it_began_not_only_where_it_ended() {
    let log = TaskLog::new();
    let mut slow = entry(1, "slow", 0);
    slow.elapsed_ms = 5_000;
    let mut instant = entry(2, "instant", 0);
    instant.elapsed_ms = 0;
    log.push(slow);
    log.push(instant);

    let (entries, _, _) = log.since(0);
    let (slow, instant) = (&entries[0], &entries[1]);
    assert!(
        slow.started_epoch_ms < instant.started_epoch_ms,
        "the slow invocation began first: {} vs {}",
        slow.started_epoch_ms,
        instant.started_epoch_ms
    );
    assert!(
        slow.at_epoch_ms <= instant.at_epoch_ms,
        "while ending no later — which is exactly why one stamp cannot serve for both"
    );
    assert_eq!(
        instant.started_epoch_ms, instant.at_epoch_ms,
        "something that took no time began when it ended"
    );
}

// The caller and the log answer different questions, so they carry different numbers: the
// caller is told what was substituted in what it received, and the log — which never crosses
// into a cage — is told whether the credential reached the output at all.
#[test]
fn the_log_counts_a_withheld_streams_substitutions_and_the_caller_does_not() {
    let outcome = super::super::task::TaskOutcome {
        exit: 0,
        stdout: None, // withheld
        stderr: Some(String::new()),
        truncated: false,
        redacted: 1,          // what the caller received
        redacted_withheld: 3, // what it did not
        timed_out: false,
        stopped: false,
        elapsed_ms: 4,
        nonce: None,
        refused: vec![],
        output: None,
    };
    let entry = finished(7, "print-both", &outcome, false);
    assert_eq!(
        entry.redacted, 4,
        "the log holds the total, so a withheld stream is not a blind spot"
    );
    assert!(
        entry.to_line().contains("redacted=4"),
        "{}",
        entry.to_line()
    );
}

// A refusal is recorded too — a caller probing a task it may not run is exactly what a human
// reading the log wants to see.
#[test]
fn a_refusal_is_recorded_with_its_reason() {
    let log = TaskLog::new();
    log.push(refusal(1, "db-query", "parameter `sql` does not match"));
    let (entries, _, _) = log.since(0);
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
    let (entries, _, _) = log.since(0);
    let line = entries[0].to_line();
    assert_eq!(line.lines().count(), 1, "one entry is one line: {line}");
    assert!(!line.contains("\nevent"), "{line}");
}

/// What a reader is told is the gap between **its own cursor** and the window it is handed, on
/// the terms every other feed answers on: a `--follow` tick prints "earlier event(s) evicted
/// from a ring before this poll". A lifetime total answers a different question, and answering
/// it here made every poll after the first eviction report the same number again, for the rest
/// of the session, over polls that had lost nothing.
#[test]
fn the_ring_evicts_the_oldest_and_reports_the_gap_the_reader_missed() {
    let log = TaskLog::new();
    for _ in 0..LOG_CAPACITY + 3 {
        log.push(entry(1, "t", 0));
    }
    // From the beginning: the three that fell out before the retained window.
    let (entries, dropped, head) = log.since(0);
    assert_eq!(entries.len(), LOG_CAPACITY);
    assert_eq!(dropped, 3);

    // A reader already at the head has missed nothing, however much the ring has evicted over
    // its life. This is the poll that used to keep reporting the total.
    let (nothing, dropped, _) = log.since(head);
    assert!(nothing.is_empty());
    assert_eq!(dropped, 0, "a caught-up reader has lost nothing");

    // Two more evictions past that cursor are two, not five.
    for _ in 0..2 {
        log.push(entry(1, "t", 0));
    }
    let (_, dropped, _) = log.since(head - LOG_CAPACITY as u64);
    assert_eq!(
        dropped, 2,
        "the gap is measured from the reader's own cursor"
    );
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
/// A declared payload longer than what arrived is an error, on the same terms the server side
/// of this protocol already holds a short payload to (`read_exact` in `read_payloads`).
///
/// The whole answer is read to EOF before it is parsed, so a short one is a plane that died
/// mid-write or miscounted. Taking what there is would hand back a partial command output that
/// reads exactly like a complete one, which is what the length prefix and the `truncated` flag
/// exist to keep apart.
///
/// Teeth: clamping the length to what remains returns `Ok` with two of the five bytes, and the
/// caller cannot tell that from a command that printed two.
#[test]
fn a_declared_output_longer_than_the_answer_is_an_error() {
    let short = client::parse_run(b"exit 0\nstdout 5\nab\n").unwrap_err();
    assert_eq!(short.kind(), std::io::ErrorKind::InvalidData);
    assert!(
        short
            .to_string()
            .contains("declared 5 bytes of stdout and sent"),
        "the refusal names both counts: {short}"
    );
    // Exactly as many bytes as declared is the ordinary case and still parses.
    let exact = client::parse_run(b"exit 0\nstdout 2\nab\nstderr -1\nok\n").unwrap();
    assert_eq!(exact.stdout.as_deref(), Some("ab"));
}

#[test]
fn the_nonce_crosses_the_wire_out_of_band() {
    let raw = "exit 0\nredacted 1\nnonce a91f3c\nstdout 22\ntok=${DEMO@a91f3c} ok\nstderr -1\nok\n";
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
