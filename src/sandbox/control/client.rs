//! Host-side control-plane client: the `sbx net …` process reads the per-session control
//! sockets under the data dir — listing parked requests, streaming the log/flow rings, and
//! injecting live allow/deny/mute decisions. The counterpart of the in-cage server in
//! [`super`]; it only *reads* the sockets and shares the wire types, never the server state.

use super::*;

/// The egress control directory under the data dir, where the per-session control sockets live.
pub(crate) fn control_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("egress")
}

/// The control socket path for a session pid.
pub(crate) fn control_socket(data_dir: &Path, pid: u32) -> PathBuf {
    control_dir(data_dir).join(format!("control-{pid}.sock"))
}

/// One reachable session's pending requests, for `sbx net pending`.
pub(crate) struct SessionPending {
    pub(crate) pid: u32,
    pub(crate) rows: Vec<PendingRow>,
}

/// Format a pending id the user types and the notice prints: `<pid>.<seq>`.
pub(crate) fn format_id(pid: u32, seq: u64) -> String {
    format!("{pid}.{seq}")
}

/// Parse a `<pid>.<seq>` id back into its parts, or `None` if it is not that shape.
pub(crate) fn parse_id(id: &str) -> Option<(u32, u64)> {
    let (pid, seq) = id.split_once('.')?;
    Some((pid.parse().ok()?, seq.parse().ok()?))
}

/// Discover every reachable ask-mode session's pending requests: glob the control sockets, parse
/// each filename's pid, and query it. A socket whose session is gone (connect refused, or a stale
/// file from a crashed launch) is skipped — so a dead session never blocks the listing. Sessions
/// are returned ordered by pid for stable output.
pub(crate) fn list_all(data_dir: &Path) -> Vec<SessionPending> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(rows) = query(&control_socket(data_dir, pid)) {
            sessions.push(SessionPending { pid, rows });
        }
    }
    sessions
}

/// The pids of every session that has a control socket present, sorted for stable output. A superset
/// of the still-live sessions: a stale socket from a crashed launch is included, but a connect to it
/// (a `query` or a [`drain_session`]) simply fails and the caller skips it. This is the authoritative
/// pid source (the socket glob), distinct from the session registry — a launch may have a control
/// socket before, or without, a registry record.
pub(crate) fn session_pids(data_dir: &Path) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir(control_dir(data_dir)) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|e| pid_from_socket(&e.file_name().to_string_lossy()))
        .collect();
    pids.sort_unstable();
    pids
}

/// Extract the pid from a `control-<pid>.sock` filename.
fn pid_from_socket(name: &str) -> Option<u32> {
    name.strip_prefix("control-")?
        .strip_suffix(".sock")?
        .parse()
        .ok()
}

/// Query one session's control socket for its pending rows (`LIST`).
fn query(socket: &Path) -> io::Result<Vec<PendingRow>> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(b"LIST\n")?;
    (&stream).flush()?;
    let mut rows = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(row) = parse_pending_line(&line) {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Parse one `pending seq=… port=… waiting=… host=… path=…` line into a row, or `None` if it is
/// not a well-formed pending line. Each token is split on its first `=`, so a `path` carrying a
/// query string's `=` round-trips (it is the last field).
fn parse_pending_line(line: &str) -> Option<PendingRow> {
    let mut seq = None;
    let mut port = None;
    let mut waiting = None;
    let mut host = None;
    let mut path = None;
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "pending" {
        return None;
    }
    for token in tokens {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "port" => port = value.parse().ok(),
            "waiting" => waiting = value.parse().ok(),
            "host" => host = Some(value.to_string()),
            "path" => path = Some(value.to_string()),
            _ => {}
        }
    }
    Some(PendingRow {
        seq: seq?,
        host: host?,
        port: port?,
        path: path?,
        waiting_secs: waiting?,
    })
}

// The client half of the event log — the reader the `sbx net logs` command connects through.

/// One reachable session's recent egress events, for `sbx net logs`.
pub(crate) struct SessionLog {
    pub(crate) pid: u32,
    pub(crate) snapshot: LogSnapshot,
}

/// Query one session's control socket for its recent egress events (`LOG`, or `LOG after=<seq>` for a
/// follow read past a cursor). A session whose socket is gone (a dead/stale launch) fails the connect
/// and the caller skips it.
pub(crate) fn read_log(
    socket: &Path,
    after: Option<u64>,
    after_amend: Option<u64>,
    include_muted: bool,
    with_capture: bool,
) -> io::Result<LogSnapshot> {
    let stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut cmd = String::from("LOG");
    if let Some(seq) = after {
        cmd.push_str(&format!(" after={seq}"));
    }
    // Only sent for a `--with-status` follow; an older session ignores the token (no re-emission).
    if let Some(a) = after_amend {
        cmd.push_str(&format!(" amended={a}"));
    }
    // `--all` — ask the session to fold its muted (`dontaudit`) ring in; an older session ignores
    // the token (it has no muted ring) and returns its normal view.
    if include_muted {
        cmd.push_str(" all");
    }
    // `--with-headers`/`--with-body` — ask for the captured traffic. A session that captures nothing
    // simply sends no `cap` lines, so the request is always safe to make.
    if with_capture {
        cmd.push_str(" capture");
    }
    cmd.push('\n');
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut events = Vec::new();
    let mut captures: Vec<Capture> = Vec::new();
    let mut dropped = 0;
    let mut head = 0;
    let mut amend_head = 0;
    let mut capture_evicted = 0;
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(v) = line.strip_prefix("dropped=") {
            dropped = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("head=") {
            head = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("amended=") {
            amend_head = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("capture-evicted=") {
            capture_evicted = v.parse().unwrap_or(0);
        } else if let Some(ev) = parse_event_line(&line) {
            events.push(ev);
        } else if let Some((seq, sighting)) = parse_sighting_line(&line) {
            // A sighting follows its own event on the wire, so the event it belongs to is already in
            // hand. One that arrives without it (an evicted event, a truncated reply) is dropped
            // rather than invented into a bare record with no host or time to show it against.
            if let Some(ev) = events.iter_mut().find(|e| e.seq == seq) {
                ev.secrets_seen.push(sighting);
            }
        } else if let Some((seq, part, bytes)) = parse_capture_line(&line) {
            // Parts of one exchange arrive as consecutive lines; fold them into a single capture.
            let entry = match captures.iter_mut().find(|c| c.seq == seq) {
                Some(c) => c,
                None => {
                    captures.push(Capture::new(seq));
                    captures.last_mut().expect("just pushed")
                }
            };
            *entry.part_mut(part) = bytes;
        }
    }
    Ok(LogSnapshot {
        events,
        dropped,
        head,
        amend_head,
        captures,
        capture_evicted,
    })
}

/// Parse one `cap seq=<n> part=<p> trunc=<0|1> b64=<…>` line into the part it carries. Anything
/// malformed — a missing field, an unknown part, bytes that do not decode — yields `None`, so a
/// capture is dropped rather than rendered as garbage.
fn parse_capture_line(line: &str) -> Option<(u64, CapturePart, CaptureBytes)> {
    let rest = line.strip_prefix("cap ")?;
    let (mut seq, mut part, mut truncated, mut bytes) = (None, None, false, None);
    for token in rest.split(' ') {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse::<u64>().ok(),
            "part" => part = CapturePart::parse(value),
            "trunc" => truncated = value == "1",
            "b64" => bytes = base64_decode(value),
            _ => {}
        }
    }
    Some((
        seq?,
        part?,
        CaptureBytes {
            bytes: bytes?,
            truncated,
        },
    ))
}

/// Discover every reachable session's recent egress events: glob the control sockets, parse each
/// filename's pid, and query it (with an optional per-nothing tail read — a shared cursor makes no
/// sense across sessions, whose sequence spaces are independent). A dead/stale socket is skipped.
/// Sessions are returned ordered by pid for stable output.
pub(crate) fn log_all(data_dir: &Path, include_muted: bool, with_capture: bool) -> Vec<SessionLog> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(snapshot) = read_log(
            &control_socket(data_dir, pid),
            None,
            None,
            include_muted,
            with_capture,
        ) {
            sessions.push(SessionLog { pid, snapshot });
        }
    }
    sessions
}

/// One reachable session's currently-open flows, for `sbx net live`.
pub(crate) struct SessionFlows {
    pub(crate) pid: u32,
    pub(crate) flows: Vec<FlowSnapshot>,
}

/// Query one session's control socket for the tunnels open right now (`FLOWS`). A session whose
/// socket is gone (a dead/stale launch) fails the connect and the caller skips it.
pub(crate) fn read_flows(socket: &Path) -> io::Result<Vec<FlowSnapshot>> {
    let stream = UnixStream::connect(socket)?;
    // A short timeout: `sbx net live` polls every session sequentially on a ~1s redraw, so a single
    // stuck session must not freeze the whole frame for long (a dead one is skipped on the connect).
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    (&stream).write_all(b"FLOWS\n")?;
    (&stream).flush()?;
    let mut flows = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        if let Some(f) = parse_flow_line(&line) {
            flows.push(f);
        }
    }
    Ok(flows)
}

/// Discover every reachable session's open flows: glob the control sockets, parse each filename's
/// pid, and query it. A dead/stale socket is skipped. Sessions are returned ordered by pid for stable
/// output. An old session that predates the `FLOWS` verb replies `err bad-request`, which parses to no
/// flow lines — so it simply contributes an empty list rather than failing the whole listing.
pub(crate) fn flows_all(data_dir: &Path) -> Vec<SessionFlows> {
    let mut sessions = Vec::new();
    for pid in session_pids(data_dir) {
        if let Ok(flows) = read_flows(&control_socket(data_dir, pid)) {
            sessions.push(SessionFlows { pid, flows });
        }
    }
    sessions
}

/// Parse one `flow proto=… port=… start=… up=… down=… host=…` line into a snapshot, or `None` if it
/// is malformed. Each token is split on its first `=`; `host` is last (it carries no space or `=`).
pub(super) fn parse_flow_line(line: &str) -> Option<FlowSnapshot> {
    let mut proto = Proto::Other;
    let mut port = None;
    let mut start = None;
    let mut up = 0u64;
    let mut down = 0u64;
    let mut host = None;
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "flow" {
        return None;
    }
    for token in tokens {
        let (key, value) = token.split_once('=')?;
        match key {
            "proto" => proto = Proto::parse(value),
            "port" => port = value.parse().ok(),
            "start" => start = value.parse().ok(),
            "up" => up = value.parse().unwrap_or(0),
            "down" => down = value.parse().unwrap_or(0),
            "host" => host = Some(value.to_string()),
            _ => {}
        }
    }
    Some(FlowSnapshot {
        host: host?,
        port: port?,
        proto,
        start_epoch_ms: start?,
        up,
        down,
    })
}

/// Parse one `event seq=… at=… port=… verdict=… reason=… [method=…] host=… [path=…]` line into an
/// event, or `None` if it is malformed. Each token is split on its first `=`, so a `path` carrying a
/// query string's `=` round-trips (it is the last field).
/// Parse one `seen seq=… way=… name=…` line into the event sequence it belongs to and the sighting,
/// or `None` if it is malformed.
///
/// `name` is read as the **rest of the line**, not as a whitespace token: it is a configuration key,
/// which may carry a space where a host or a request target cannot.
fn parse_sighting_line(line: &str) -> Option<(u64, SecretSighting)> {
    let rest = line.strip_prefix("seen ")?;
    let (fields, name) = rest.split_once(" name=")?;
    let mut seq = None;
    let mut way = None;
    for token in fields.split_whitespace() {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "way" => way = SecretWay::parse(value),
            _ => {}
        }
    }
    Some((
        seq?,
        SecretSighting {
            name: name.to_string(),
            way: way?,
        },
    ))
}

fn parse_event_line(line: &str) -> Option<LogEvent> {
    let mut seq = None;
    let mut at = None;
    let mut port = None;
    let mut verdict = None;
    let mut reason = None;
    let mut method = None;
    let mut host = None;
    let mut path = None;
    let mut status = None;
    let mut muted = false;
    let mut proto = Proto::Other;
    let mut http_ver = HttpVer::Unknown;
    let mut rpc = RpcKind::None;
    let mut tokens = line.split_whitespace();
    if tokens.next()? != "event" {
        return None;
    }
    for token in tokens {
        let (key, value) = token.split_once('=')?;
        match key {
            "seq" => seq = value.parse().ok(),
            "at" => at = value.parse().ok(),
            "port" => port = value.parse().ok(),
            "verdict" => verdict = LogVerdict::parse(value),
            "proto" => proto = Proto::parse(value),
            "ver" => http_ver = HttpVer::parse(value),
            "l7" => rpc = RpcKind::parse(value),
            "reason" => reason = Some(value.to_string()),
            "method" => method = Some(value.to_string()),
            "host" => host = Some(value.to_string()),
            "path" => path = Some(value.to_string()),
            "status" => status = value.parse().ok(),
            "muted" => muted = value == "1",
            _ => {}
        }
    }
    Some(LogEvent {
        seq: seq?,
        at_epoch_ms: at?,
        host: host?,
        port: port?,
        method,
        path,
        verdict: verdict?,
        reason: reason?,
        proto,
        http_ver,
        rpc,
        muted,
        status,
        // Amend bookkeeping is server-side; a parsed (client-side) event never carries it.
        amend_seq: None,
        awaiting_capture: false,
        secrets_seen: Vec::new(),
    })
}

/// The outcome of answering a request over the control socket.
pub(crate) enum AnswerOutcome {
    /// The request was answered: the host it was for (for a `--save`) and how many parked requests to
    /// that destination the answer woke (identical retries collapse to one decision).
    Answered { host: String, count: usize },
    /// No such request is parked (already answered, timed out, or a wrong id).
    NotFound,
}

/// Parse a control `ALLOW`/`DENY` reply line into an outcome. `ok host=<h> count=<n>` is an answer;
/// `count` is **optional** (defaults to 1) so a freshly-built client degrades cleanly against an
/// older server that omits it — a long-lived session serves the wire protocol of the binary that
/// launched it, so new-client ↔ older-server skew is real before a release. Anything else (`err …`)
/// is [`AnswerOutcome::NotFound`].
fn parse_answer_reply(line: &str) -> AnswerOutcome {
    if let Some(rest) = line.strip_prefix("ok ") {
        let mut host = None;
        let mut count = 1usize;
        for token in rest.split_whitespace() {
            if let Some(h) = token.strip_prefix("host=") {
                host = Some(h.to_string());
            } else if let Some(c) = token.strip_prefix("count=") {
                count = c.parse().unwrap_or(1);
            }
        }
        if let Some(host) = host {
            return AnswerOutcome::Answered { host, count };
        }
    }
    AnswerOutcome::NotFound
}

/// Answer the parked request `<pid>.<seq>`: connect to that session's control socket and send the
/// verdict. With `remember`, a trailing `session` token also records the decision as a live manual
/// rule (so the same request is not re-asked this session). A missing socket / dead session surfaces
/// as a connect error; a live session that has no such request returns [`AnswerOutcome::NotFound`].
pub(crate) fn answer_request(
    data_dir: &Path,
    pid: u32,
    seq: u64,
    verdict: Verdict,
    remember: bool,
) -> io::Result<AnswerOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    let cmd = if remember {
        format!("{verb} {seq} session\n")
    } else {
        format!("{verb} {seq}\n")
    };
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut response = String::new();
    let n = BufReader::new((&stream).take(REPLY_MAX)).read_line(&mut response)?;
    // If the reply filled the bound with no terminating newline it was truncated — refuse to parse a
    // partial host (which `--save` would persist as a wrong rule) and report it as not answered.
    if n as u64 >= REPLY_MAX && !response.ends_with('\n') {
        return Ok(AnswerOutcome::NotFound);
    }
    Ok(parse_answer_reply(response.trim()))
}

/// The outcome of a bulk drain (`ALLOW *`/`DENY *`) of one session.
pub(crate) enum DrainOutcome {
    /// The session drained: the hosts it answered, oldest first. An empty vec means the session was
    /// healthy but had nothing parked.
    Drained(Vec<String>),
    /// The session's control server did not understand the bulk-drain command (it replied `err …`) —
    /// it was launched by an `sbx` predating `--all`. Its requests are still parked; only relaunching
    /// the agent with the current binary lets `--all` reach them. (Answering by id is *not* a fallback:
    /// destination-grouping is server-side, so an old server's `ALLOW <seq>` wakes one connection of
    /// the group, leaving the retries parked.)
    Unsupported,
}

/// Drain *every* parked request in one session (`ALLOW *`/`DENY *`): connect, send the bulk verdict,
/// and collect the hosts it answered (oldest first). With `remember`, the trailing `session` token
/// also records each as a live manual rule. An empty queue is `Drained(vec![])`; a control server too
/// old to know `ALLOW *` (it replies `err …`) is `Unsupported` — distinct from a clean empty drain,
/// so the caller can tell "nothing parked" from "this session predates --all". A connect error (the
/// session is gone, or a stale socket) propagates so the caller skips that session.
pub(crate) fn drain_session(
    data_dir: &Path,
    pid: u32,
    verdict: Verdict,
    remember: bool,
) -> io::Result<DrainOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    let cmd = if remember {
        format!("{verb} * session\n")
    } else {
        format!("{verb} *\n")
    };
    (&stream).write_all(cmd.as_bytes())?;
    (&stream).flush()?;
    let mut hosts = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            return Ok(DrainOutcome::Drained(hosts));
        }
        if let Some(host) = line.strip_prefix("answered host=") {
            hosts.push(host.to_string());
        } else if line.starts_with("err ") {
            // A current server never answers a bulk drain with `err` — so any `err` line is an older
            // server that does not understand `ALLOW *`/`DENY *`.
            return Ok(DrainOutcome::Unsupported);
        }
    }
    // EOF without a terminating `ok` (defensive — a current server always closes with `ok`): report
    // what we collected rather than inventing an error.
    Ok(DrainOutcome::Drained(hosts))
}

/// The kind of a manual (`--session`) rule reported by a live session: a verdict rule (allow/deny)
/// or a mute (`dontaudit`) log-suppression rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManualKind {
    Allow,
    Deny,
    Mute,
}

/// One manual rule reported by a live session: its kind and its display text.
pub(crate) struct ManualRuleRow {
    pub(crate) kind: ManualKind,
    pub(crate) rule: String,
}

/// The outcome of loading a proactive `--session` rule into one session's overlay.
pub(crate) enum InjectOutcome {
    /// The rule was loaded into the live overlay — the proxy folds it into its effective policy, so
    /// it decides the matching request from now on.
    Loaded,
    /// The server refused it (a rule it could not classify, or a control server too old to know
    /// `REMEMBER`) — reported so the caller does not present it as loaded.
    Refused,
}

/// Load a proactive egress `rule` into one session's live manual overlay (`REMEMBER ALLOW|DENY
/// <rule>`) — the `sbx net allow|deny <rule> --session` path. A connect error (the session is gone,
/// or a stale socket) propagates so the caller skips that session.
pub(crate) fn inject_rule(
    data_dir: &Path,
    pid: u32,
    verdict: Verdict,
    rule: &str,
) -> io::Result<InjectOutcome> {
    let verb = match verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Deny => "DENY",
    };
    send_remember(data_dir, pid, verb, rule)
}

/// Load a proactive **mute** (`dontaudit`) `rule` into one session's live overlay — the
/// `sbx net mute <rule> --session` path. A denied request matching it has its log line suppressed
/// for this session; the verdict and the `sbx net stats` count are untouched. Same wire shape as
/// [`inject_rule`], with the `MUTE` verb.
pub(crate) fn inject_mute(data_dir: &Path, pid: u32, rule: &str) -> io::Result<InjectOutcome> {
    send_remember(data_dir, pid, "MUTE", rule)
}

/// Send one `REMEMBER <verb> <rule>` to a session's control socket and read its one-line reply.
/// Shared by [`inject_rule`] (ALLOW/DENY) and [`inject_mute`] (MUTE) so the connection handling and
/// the reply parsing cannot drift.
fn send_remember(data_dir: &Path, pid: u32, verb: &str, rule: &str) -> io::Result<InjectOutcome> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(format!("REMEMBER {verb} {rule}\n").as_bytes())?;
    (&stream).flush()?;
    let mut response = String::new();
    BufReader::new((&stream).take(REPLY_MAX)).read_line(&mut response)?;
    Ok(match response.trim() {
        "ok" => InjectOutcome::Loaded,
        _ => InjectOutcome::Refused,
    })
}

/// Query a session's live manual rules (`RULES`) — the runtime rules added by `--session` answers.
/// A connect error (the session is gone) propagates so the caller can skip it.
pub(crate) fn query_manual(data_dir: &Path, pid: u32) -> io::Result<Vec<ManualRuleRow>> {
    let stream = UnixStream::connect(control_socket(data_dir, pid))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    (&stream).write_all(b"RULES\n")?;
    (&stream).flush()?;
    let mut rules = Vec::new();
    for line in BufReader::new(&stream).lines() {
        let line = line?;
        if line == "ok" {
            break;
        }
        // The rule text is everything after the kind prefix — taken as the whole remainder, so a
        // rule carrying whitespace (a `re:` regex loaded with `--session`) round-trips intact.
        if let Some(rule) = line.strip_prefix("manual allow ") {
            rules.push(ManualRuleRow {
                kind: ManualKind::Allow,
                rule: rule.to_string(),
            });
        } else if let Some(rule) = line.strip_prefix("manual deny ") {
            rules.push(ManualRuleRow {
                kind: ManualKind::Deny,
                rule: rule.to_string(),
            });
        } else if let Some(rule) = line.strip_prefix("manual mute ") {
            rules.push(ManualRuleRow {
                kind: ManualKind::Mute,
                rule: rule.to_string(),
            });
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_answer_reply_reads_count_and_tolerates_its_absence() {
        match parse_answer_reply("ok host=api.test count=9") {
            AnswerOutcome::Answered { host, count } => {
                assert_eq!(host, "api.test");
                assert_eq!(count, 9);
            }
            AnswerOutcome::NotFound => panic!("a well-formed ok must answer"),
        }
        // An older server omits `count` → defaults to 1 (new-client ↔ older-server version skew).
        match parse_answer_reply("ok host=api.test") {
            AnswerOutcome::Answered { host, count } => {
                assert_eq!(host, "api.test");
                assert_eq!(count, 1);
            }
            AnswerOutcome::NotFound => panic!("a countless ok must still answer"),
        }
        assert!(matches!(
            parse_answer_reply("err not-found"),
            AnswerOutcome::NotFound
        ));
    }

    #[test]
    fn capture_lines_round_trip_through_the_wire_including_binary_and_padding() {
        let mut cap = Capture::new(9);
        cap.req_head = CaptureBytes {
            bytes: b"POST /v1?a=b HTTP/1.1\r\nhost: api.test\r\n".to_vec(),
            truncated: false,
        };
        cap.injected = CaptureBytes {
            bytes: b"authorization".to_vec(),
            truncated: false,
        };
        // A body of every byte value: the encoding must survive NULs, newlines, and `=` alike.
        cap.res_body = CaptureBytes {
            bytes: (0..=255u8).collect(),
            truncated: true,
        };
        let wire = super::super::format_capture_lines(&cap);

        let mut back = Capture::new(9);
        let mut lines = 0;
        for line in wire.lines() {
            let (seq, part, bytes) =
                parse_capture_line(line).expect("every emitted line must parse back");
            assert_eq!(seq, 9);
            *back.part_mut(part) = bytes;
            lines += 1;
        }
        assert_eq!(lines, 3, "one line per non-empty part");
        assert_eq!(back, cap, "the whole capture round-trips byte for byte");
    }

    #[test]
    fn a_malformed_capture_line_is_dropped_rather_than_rendered_as_garbage() {
        assert!(parse_capture_line("cap seq=1 part=req-head trunc=0 b64=!!!!").is_none());
        assert!(parse_capture_line("cap part=req-head trunc=0 b64=aGk=").is_none());
        assert!(parse_capture_line("cap seq=1 part=nope trunc=0 b64=aGk=").is_none());
        assert!(parse_capture_line("event seq=1 host=a.test").is_none());
    }

    #[test]
    fn format_and_parse_flow_line_round_trip() {
        let f = FlowSnapshot {
            host: "example.test".into(),
            port: 443,
            proto: Proto::Tcp,
            start_epoch_ms: 1_700_000_000_000,
            up: 4096,
            down: 8192,
        };
        let line = format_flow_line(&f);
        let back = parse_flow_line(line.trim()).expect("a well-formed flow line parses");
        assert_eq!(back, f);
    }

    #[test]
    fn parse_pending_line_round_trips_a_query_path() {
        let row = parse_pending_line(
            "pending seq=3 port=443 waiting=12 host=api.example.com path=/v1?a=b&c=d",
        )
        .unwrap();
        assert_eq!(row.seq, 3);
        assert_eq!(row.port, 443);
        assert_eq!(row.waiting_secs, 12);
        assert_eq!(row.host, "api.example.com");
        // the query string's `=` is preserved (path is the last field, split on the first `=`)
        assert_eq!(row.path, "/v1?a=b&c=d");
    }

    #[test]
    fn pid_from_socket_parses_the_filename() {
        assert_eq!(pid_from_socket("control-4321.sock"), Some(4321));
        assert_eq!(pid_from_socket("proxy-4321.sock"), None);
        assert_eq!(pid_from_socket("control-.sock"), None);
    }

    #[test]
    fn event_line_round_trips_through_the_wire() {
        // A full L7 event whose path carries a query string's `=` (the field that must stay last).
        let ev = LogEvent {
            seq: 7,
            at_epoch_ms: 1_700_000_000_123,
            host: "api.test".into(),
            port: 8443,
            method: Some("POST".into()),
            path: Some("/v1/x?a=1&b=2".into()),
            verdict: LogVerdict::Allow,
            proto: Proto::Https,
            // Non-default version + RPC framing so the `ver=`/`l7=` tokens are exercised end to end.
            http_ver: HttpVer::H2,
            rpc: RpcKind::Grpc,
            reason: "allowed".into(),
            muted: false,
            // A captured upstream status round-trips on the wire alongside the query path.
            status: Some(200),
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        };
        let line = format_event_line(&ev);
        let parsed = parse_event_line(line.trim()).expect("a well-formed line parses");
        assert_eq!(
            parsed, ev,
            "the event round-trips including the status and query path"
        );

        // An early-CONNECT / L4 event has no method/path — those tokens are omitted and parse None.
        let bare = LogEvent {
            seq: 8,
            at_epoch_ms: 1_700_000_000_456,
            host: "raw.test".into(),
            port: 22,
            method: None,
            path: None,
            verdict: LogVerdict::Allow,
            proto: Proto::Https,
            // A raw/early event carries no HTTP version or RPC framing — both stay default and their
            // tokens are omitted from the line.
            http_ver: HttpVer::Unknown,
            rpc: RpcKind::None,
            reason: "allowed".into(),
            muted: false,
            status: None,
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        };
        let parsed = parse_event_line(format_event_line(&bare).trim()).unwrap();
        assert_eq!(
            parsed, bare,
            "a status-less L4 event omits the token and parses None"
        );

        // Every verdict token round-trips — in particular `error` (allowed-but-failed), the one the
        // proxy tests only ever assert in memory, so a typo in its wire token would otherwise surface
        // only when the CLI reads a live event over the socket.
        for verdict in [
            LogVerdict::Allow,
            LogVerdict::Deny,
            LogVerdict::Blocked,
            LogVerdict::Error,
        ] {
            let ev = LogEvent {
                seq: 9,
                at_epoch_ms: 1_700_000_000_789,
                host: "h.test".into(),
                port: 443,
                method: Some("GET".into()),
                path: Some("/p".into()),
                verdict,
                reason: "dns-failure".into(),
                proto: Proto::Https,
                // HTTP/1.1 here exercises the `ver=h1` token alongside every verdict.
                http_ver: HttpVer::H1,
                rpc: RpcKind::None,
                // A muted deny exercises the `muted=1` token on the wire (mute only ever applies to
                // a deny), so its round-trip is covered here alongside every verdict token.
                muted: verdict == LogVerdict::Deny,
                status: None,
                amend_seq: None,
                awaiting_capture: false,
                secrets_seen: Vec::new(),
            };
            let parsed = parse_event_line(format_event_line(&ev).trim()).unwrap();
            assert_eq!(
                parsed.verdict, verdict,
                "verdict {verdict:?} must round-trip"
            );
            assert_eq!(parsed, ev);
        }
    }

    #[test]
    fn a_line_without_ver_or_l7_parses_to_unknown_and_none() {
        // Backward compatibility: a persisted line predating these two axes (no `ver=`/`l7=`) must
        // still parse, defaulting them rather than failing the whole line.
        let old = "event seq=1 at=1700000000000 port=443 verdict=allow proto=https \
               reason=allowed host=h.test path=/p";
        let parsed = parse_event_line(old).expect("an older line still parses");
        assert_eq!(parsed.http_ver, HttpVer::Unknown);
        assert_eq!(parsed.rpc, RpcKind::None);
        assert_eq!(parsed.proto, Proto::Https);
    }

    /// A sighting round-trips over the control wire, INCLUDING a credential name carrying a space.
    /// The name comes from a configuration key, so unlike a host or a request target it is not
    /// whitespace-free — which is why it is written last and read as the rest of the line. A
    /// whitespace-token parser would truncate it and name the wrong credential.
    #[test]
    fn a_sighting_round_trips_with_a_spaced_credential_name() {
        let mut ev = LogEvent {
            seq: 9,
            at_epoch_ms: 1_000_000,
            host: "chat.example.com".into(),
            port: 443,
            method: Some("GET".into()),
            path: Some("/socket".into()),
            verdict: LogVerdict::Allow,
            reason: "allowed".into(),
            proto: Proto::Https,
            http_ver: HttpVer::Unknown,
            rpc: RpcKind::None,
            muted: false,
            status: Some(101),
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        };
        ev.secrets_seen.push(SecretSighting {
            name: "my api token".into(),
            way: SecretWay::Back,
        });
        ev.secrets_seen.push(SecretSighting {
            name: "other".into(),
            way: SecretWay::Out,
        });
        let wire = format_sighting_lines(&ev);
        let parsed: Vec<(u64, SecretSighting)> =
            wire.lines().filter_map(parse_sighting_line).collect();
        assert_eq!(parsed.len(), 2, "both sightings cross the wire: {wire:?}");
        assert_eq!(parsed[0].0, 9, "each line names the event it belongs to");
        assert_eq!(parsed[0].1.name, "my api token", "the space survives");
        assert_eq!(parsed[0].1.way, SecretWay::Back);
        assert_eq!(parsed[1].1.name, "other");
        assert_eq!(parsed[1].1.way, SecretWay::Out);
    }

    /// An event with no sighting writes no line at all, so the ordinary case costs the wire nothing
    /// and an older reader sees exactly what it saw before.
    #[test]
    fn an_event_with_no_sighting_writes_no_line() {
        let ev = LogEvent {
            seq: 1,
            at_epoch_ms: 0,
            host: "api.example.com".into(),
            port: 443,
            method: None,
            path: None,
            verdict: LogVerdict::Allow,
            reason: "allowed".into(),
            proto: Proto::Https,
            http_ver: HttpVer::Unknown,
            rpc: RpcKind::None,
            muted: false,
            status: None,
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        };
        assert!(format_sighting_lines(&ev).is_empty());
    }
}
