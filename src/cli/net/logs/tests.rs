use super::*;

fn log_event(
    seq: u64,
    host: &str,
    method: Option<&str>,
    path: Option<&str>,
    verdict: sandbox::control::LogVerdict,
    reason: &str,
) -> sandbox::control::LogEvent {
    sandbox::control::LogEvent {
        seq,
        at_epoch_ms: 1_000_000,
        host: host.into(),
        port: 443,
        method: method.map(str::to_string),
        path: path.map(str::to_string),
        verdict,
        reason: reason.into(),
        proto: sandbox::control::Proto::Https,
        http_ver: sandbox::control::HttpVer::Unknown,
        rpc: sandbox::control::RpcKind::None,
        // These fixtures stand in for events decoded from the control wire, which carries no plane.
        plane: sandbox::control::Plane::Unknown,
        muted: false,
        status: None,
        amend_seq: None,
        awaiting_capture: false,
        secrets_seen: Vec::new(),
    }
}

/// A secret seen crossing a tunnel is shown on a PLAIN `sbx net logs`, with no flag asked for,
/// and it says plainly that nothing was stopped.
///
/// Teeth on both halves. It is not behind `--with-headers`/`--with-body`, because a capture is a
/// debugging convenience a reader opts into while a credential leaving the cage is a fact about
/// the session. And the wording states the outcome: unlike the two HTTP tripwires, this one
/// neither refused nor masked anything, so a line that only said "secret detected" would leave a
/// reader believing they were protected when they were not.
#[test]
fn a_secret_seen_crossing_a_tunnel_shows_without_asking_and_says_it_was_not_stopped() {
    let pal = style::Palette::plain();
    let mut ev = log_event(
        1,
        "chat.test",
        Some("GET"),
        Some("/socket"),
        sandbox::control::LogVerdict::Allow,
        "allowed",
    );
    ev.secrets_seen.push(sandbox::control::SecretSighting {
        name: "demo-token".into(),
        way: sandbox::control::SecretWay::Out,
    });
    let sessions = vec![sandbox::control::SessionLog {
        pid: 42,
        snapshot: sandbox::control::LogSnapshot {
            events: vec![ev.clone()],
            dropped: 0,
            head: 1,
            amend_head: 0,
            captures: Vec::new(),
            capture_evicted: 0,
        },
    }];
    let out = render_logs(&sessions, &[], &LogView::default(), &pal, false);
    assert!(
        out.contains("demo-token"),
        "the credential is named on the default view: {out}"
    );
    assert!(
        out.contains("NOT blocked or masked"),
        "the line must not let a reader think the leak was stopped: {out}"
    );
    assert!(
        out.contains("cage → upstream"),
        "the direction is part of the fact: {out}"
    );

    // An event with no sighting adds nothing, so ordinary output is unchanged.
    let quiet = log_event(
        2,
        "api.test",
        Some("GET"),
        Some("/x"),
        sandbox::control::LogVerdict::Allow,
        "allowed",
    );
    let plain = render_logs(
        &[sandbox::control::SessionLog {
            pid: 42,
            snapshot: sandbox::control::LogSnapshot {
                events: vec![quiet],
                dropped: 0,
                head: 1,
                amend_head: 0,
                captures: Vec::new(),
                capture_evicted: 0,
            },
        }],
        &[],
        &LogView::default(),
        &pal,
        false,
    );
    assert!(!plain.contains("secret `"), "{plain}");
}

/// A capture fixture: a POST exchange with both heads, both bodies, and one injected header.
fn log_capture(seq: u64) -> sandbox::control::Capture {
    let part = |b: &[u8], truncated: bool| sandbox::control::CaptureBytes {
        bytes: b.to_vec(),
        truncated,
    };
    let mut cap = sandbox::control::Capture::new(seq);
    cap.req_head = part(
        b"POST /v1/messages HTTP/1.1\r\nhost: api.test\r\ncontent-type: application/json\r\n",
        false,
    );
    cap.injected = part(b"authorization", false);
    cap.req_body = part(br#"{"prompt":"hi"}"#, false);
    cap.res_head = part(
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n",
        false,
    );
    cap.res_body = part(br#"{"reply":"pong"}"#, true);
    cap
}

#[test]
fn asking_for_traffic_from_a_session_that_does_not_capture_says_so() {
    let pal = style::Palette::plain();
    let sessions = vec![sandbox::control::SessionLog {
        pid: 42,
        snapshot: sandbox::control::LogSnapshot {
            events: vec![log_event(
                1,
                "api.test",
                Some("GET"),
                Some("/"),
                sandbox::control::LogVerdict::Allow,
                "allowed",
            )],
            dropped: 0,
            head: 1,
            amend_head: 0,
            captures: Vec::new(),
            capture_evicted: 0,
        },
    }];
    let view = LogView {
        with_headers: true,
        with_body: true,
        ..LogView::default()
    };
    let out = render_logs(&sessions, &[], &view, &pal, false);
    assert!(
        out.contains("no captured traffic here"),
        "an empty capture must be explained, not read as an empty exchange: {out}"
    );
    // Both causes are named: a session that does not capture, and one whose exchanges simply
    // carried nothing to keep. Claiming only the first would be wrong for a capturing session
    // whose every request was refused.
    assert!(
        out.contains("not capturing") && out.contains("nothing it did carried any"),
        "the note must not assert a cause it cannot know: {out}"
    );
    // Without the flags the note never appears.
    let plain = render_logs(&sessions, &[], &LogView::default(), &pal, false);
    assert!(!plain.contains("captured traffic"), "{plain}");
}

#[test]
fn render_capture_shows_each_direction_and_marks_the_truncation() {
    let pal = style::Palette::plain();
    let view = LogView {
        with_headers: true,
        with_body: true,
        ..LogView::default()
    };
    let out = render_capture(&log_capture(1), &view, &pal);
    assert!(
        out.contains("> POST /v1/messages HTTP/1.1"),
        "the request head is shown with the outbound marker: {out}"
    );
    assert!(
        out.contains("> authorization: <injected by sbx>"),
        "an injected header is named, never valued: {out}"
    );
    assert!(out.contains(r#"> {"prompt":"hi"}"#), "{out}");
    assert!(out.contains("< HTTP/1.1 200 OK"), "{out}");
    assert!(out.contains(r#"< {"reply":"pong"}"#), "{out}");
    assert!(
        out.contains("truncated, more followed"),
        "a cut body says so rather than reading as complete: {out}"
    );
}

/// A WebSocket's transcript renders with the same direction markers as an HTTP exchange, and
/// answers to the same flag as a body: the frames ARE the payload, so `--with-headers` alone
/// shows the handshake and withholds them.
#[test]
fn a_websocket_transcript_renders_per_direction_and_only_under_with_body() {
    let pal = style::Palette::plain();
    let part = |b: &[u8]| sandbox::control::CaptureBytes {
        bytes: b.to_vec(),
        truncated: false,
    };
    let mut cap = sandbox::control::Capture::new(1);
    cap.req_head = part(b"GET /chat HTTP/1.1\r\nhost: api.test\r\n");
    cap.res_head = part(b"HTTP/1.1 101 Switching Protocols\r\n");
    cap.ws_up = part(br#"{"from":"cage"}"#);
    cap.ws_down = part(br#"{"from":"server"}"#);

    let full = render_capture(
        &cap,
        &LogView {
            with_headers: true,
            with_body: true,
            ..LogView::default()
        },
        &pal,
    );
    assert!(
        full.contains(r#"> {"from":"cage"}"#),
        "the cage's frames carry the outbound marker: {full}"
    );
    assert!(
        full.contains(r#"< {"from":"server"}"#),
        "the upstream's carry the inbound one: {full}"
    );

    let heads_only = render_capture(
        &cap,
        &LogView {
            with_headers: true,
            ..LogView::default()
        },
        &pal,
    );
    assert!(
        heads_only.contains("101 Switching Protocols"),
        "the handshake still shows: {heads_only}"
    );
    assert!(
        !heads_only.contains("from"),
        "but the transcript is payload, so it waits for --with-body: {heads_only}"
    );
}

#[test]
fn with_headers_alone_shows_the_heads_and_withholds_both_bodies() {
    let pal = style::Palette::plain();
    let view = LogView {
        with_headers: true,
        ..LogView::default()
    };
    let out = render_capture(&log_capture(1), &view, &pal);
    assert!(out.contains("> POST /v1/messages HTTP/1.1"));
    assert!(out.contains("< HTTP/1.1 200 OK"));
    assert!(
        !out.contains("prompt") && !out.contains("reply"),
        "no payload without --with-body: {out}"
    );
}

#[test]
fn with_body_implies_with_headers_and_both_ask_the_session_for_the_capture() {
    let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();
    let v = parse_log_args(&osv(&["--with-body"])).unwrap();
    assert!(
        v.with_body && v.with_headers,
        "a body needs its head to read"
    );
    assert!(v.wants_capture());
    let h = parse_log_args(&osv(&["--with-headers"])).unwrap();
    assert!(h.wants_capture() && !h.with_body);
    assert!(
        !parse_log_args(&osv(&[])).unwrap().wants_capture(),
        "an ordinary listing never asks for traffic"
    );
}

#[test]
fn a_binary_body_is_summarized_rather_than_printed_as_noise() {
    // A gzip magic header plus NUL bytes — not text, and printing it would corrupt a terminal.
    let binary = [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe];
    let lines = render_bytes(&binary);
    assert_eq!(lines, vec!["<10 byte(s) of binary data>"]);
    // Real text still renders as text, with the head's trailing blank line dropped.
    assert_eq!(
        render_bytes(b"HTTP/1.1 200 OK\r\nx: 1\r\n\r\n"),
        vec!["HTTP/1.1 200 OK", "x: 1"]
    );
}

#[test]
fn capture_json_encodes_bodies_base64_so_binary_survives_the_round_trip() {
    let view = LogView {
        with_headers: true,
        with_body: true,
        ..LogView::default()
    };
    let j = capture_json(&log_capture(1), &view);
    assert_eq!(
        j["injected"],
        serde_json::json!(["authorization"]),
        "injected headers are names only"
    );
    let b64 = j["res_body"]["b64"].as_str().unwrap();
    assert_eq!(
        sandbox::control::base64_decode(b64).unwrap(),
        br#"{"reply":"pong"}"#.to_vec(),
        "the body decodes back byte for byte"
    );
    assert_eq!(j["res_body"]["truncated"], serde_json::json!(true));
    // Without --with-body the bodies are absent from JSON too, matching the human view.
    let heads_only = LogView {
        with_headers: true,
        ..LogView::default()
    };
    let j = capture_json(&log_capture(1), &heads_only);
    assert!(j.get("res_body").is_none() && j.get("req_body").is_none());
}

#[test]
fn parse_log_args_reads_every_flag_and_rejects_bad_input() {
    use sandbox::control::LogVerdict;
    let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

    let v = parse_log_args(&osv(&[
        "--app",
        "demo-app",
        "--host",
        "api.test",
        "--verdict",
        "error",
        "-n",
        "5",
        "--with-query",
        "--json",
    ]))
    .unwrap();
    assert_eq!(v.app.as_deref(), Some("demo-app"));
    assert_eq!(v.host.as_deref(), Some("api.test"));
    assert_eq!(v.verdict, Some(LogVerdict::Error));
    assert_eq!(v.limit, Some(5));
    assert!(v.with_query && v.json);
    assert!(!v.follow, "follow is off unless asked");
    assert!(!v.with_status, "status is off unless asked");
    assert!(
        parse_log_args(&osv(&["--with-status"]))
            .unwrap()
            .with_status,
        "--with-status turns the status column on"
    );

    // `--follow`/`-f` with an explicit interval; the default interval is 1s.
    let f = parse_log_args(&osv(&["--follow", "--interval", "3"])).unwrap();
    assert!(f.follow && f.interval_secs == 3);
    assert!(parse_log_args(&osv(&["-f"])).unwrap().follow);
    assert_eq!(parse_log_args(&osv(&["-f"])).unwrap().interval_secs, 1);
    // A zero or non-numeric interval is refused (a zero would busy-poll).
    assert!(parse_log_args(&osv(&["-i", "0"])).is_err());
    assert!(
        parse_log_args(&osv(&["-i", "soon"]))
            .unwrap_err()
            .contains("soon")
    );
    assert!(parse_log_args(&osv(&["-i"])).is_err());

    // Every verdict token parses through the flag (in particular `error`, the log-only one).
    for (tok, want) in [
        ("allow", LogVerdict::Allow),
        ("deny", LogVerdict::Deny),
        ("blocked", LogVerdict::Blocked),
        ("error", LogVerdict::Error),
    ] {
        assert_eq!(
            parse_log_args(&osv(&["--verdict", tok])).unwrap().verdict,
            Some(want)
        );
    }

    // Rejects: an unknown verdict (naming it), a non-numeric count, a missing value, a bad flag.
    assert!(
        parse_log_args(&osv(&["--verdict", "nope"]))
            .unwrap_err()
            .contains("nope")
    );
    assert!(
        parse_log_args(&osv(&["-n", "lots"]))
            .unwrap_err()
            .contains("lots")
    );
    assert!(parse_log_args(&osv(&["--host"])).is_err());
    assert!(parse_log_args(&osv(&["--verdict"])).is_err());
    assert!(parse_log_args(&osv(&["-n"])).is_err());
    assert!(parse_log_args(&osv(&["--nonsense"])).is_err());
}

#[test]
fn filtered_log_events_applies_host_verdict_and_limit() {
    use sandbox::control::LogVerdict::*;
    let events = vec![
        log_event(1, "a.test", Some("GET"), Some("/1"), Allow, "allowed"),
        log_event(2, "b.test", Some("GET"), Some("/2"), Deny, "denied-default"),
        log_event(
            3,
            "a.test",
            Some("POST"),
            Some("/3"),
            Blocked,
            "ssrf-blocked",
        ),
        log_event(4, "a.test", Some("GET"), Some("/4"), Error, "dns-failure"),
    ];
    let view = |host: Option<&str>, verdict, limit| LogView {
        host: host.map(str::to_string),
        verdict,
        limit,
        ..LogView::default()
    };

    // Host filter keeps only exact matches.
    let by_host = filtered_log_events(&events, &view(Some("a.test"), None, None));
    assert_eq!(by_host.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 3, 4]);
    // Verdict filter, including the log-only `error`.
    let errs = filtered_log_events(&events, &view(None, Some(Error), None));
    assert_eq!(errs.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
    // `-n` keeps the most recent N (the ring is oldest-first).
    let last2 = filtered_log_events(&events, &view(None, None, Some(2)));
    assert_eq!(last2.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4]);
    // Filters compose: host a.test, then the last 1.
    let combo = filtered_log_events(&events, &view(Some("a.test"), None, Some(1)));
    assert_eq!(combo.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
}

#[test]
fn display_log_path_drops_the_query_unless_asked() {
    assert_eq!(display_log_path("/v1/x?token=abc", false), "/v1/x");
    assert_eq!(display_log_path("/v1/x?token=abc", true), "/v1/x?token=abc");
    assert_eq!(display_log_path("/v1/x", false), "/v1/x");
}

#[test]
fn status_shows_only_under_with_status_in_both_render_and_json() {
    use sandbox::control::LogVerdict::*;
    let p = style::Palette::plain();

    // A completed L7 allow carrying a 200, and an L4/error event carrying none.
    let mut ok = log_event(1, "api.test", Some("GET"), Some("/p"), Allow, "allowed");
    ok.status = Some(200);
    let raw = log_event(2, "db.test", None, None, Allow, "allowed"); // status stays None

    let on = LogView {
        with_status: true,
        ..LogView::default()
    };
    let off = LogView::default();

    // Human render: the code appears only under `--with-status`; a status-less event shows `-`.
    assert!(!render_log_line(&ok, 4242, &off, &p).contains("200"));
    let line = render_log_line(&ok, 4242, &on, &p);
    assert!(
        line.contains("200"),
        "the code shows under --with-status: {line}"
    );
    // The session id leads the line (before the time).
    assert!(
        line.trim_start().starts_with("4242"),
        "the line leads with the session id: {line}"
    );
    let bare = render_log_line(&raw, 4242, &on, &p);
    assert!(
        bare.trim_end().ends_with('-'),
        "a status-less event shows `-` under --with-status: {bare}"
    );

    // JSON: the `status` key is present only under `--with-status` (a number, or null).
    let j_off = log_event_json(&ok, 7, None, None, &off, None);
    assert!(j_off.get("status").is_none(), "no status key by default");
    let j_on = log_event_json(&ok, 7, None, None, &on, None);
    assert_eq!(j_on["status"], serde_json::json!(200));
    let j_raw = log_event_json(&raw, 7, None, None, &on, None);
    assert_eq!(
        j_raw["status"],
        serde_json::Value::Null,
        "null when none captured"
    );
}

#[test]
fn the_proto_column_names_the_transport_in_render_and_json() {
    use sandbox::control::LogVerdict::*;
    use sandbox::control::Proto;
    let p = style::Palette::plain();
    let view = LogView::default();

    // Each transport surfaces its own token in the human line AND the JSON `proto` field — the
    // port alone would not tell them apart (a `tcp://` splice can ride 443).
    let mut https = log_event(
        1,
        "example.com",
        Some("WS"),
        Some("/sub"),
        Deny,
        "denied-method",
    );
    https.proto = Proto::Https;
    let mut http = log_event(
        2,
        "clients2.google.com",
        Some("GET"),
        Some("/t"),
        Deny,
        "denied-default",
    );
    http.proto = Proto::Http;
    let mut tcp = log_event(3, "db.internal", None, None, Allow, "allowed");
    tcp.proto = Proto::Tcp;

    for (ev, tok) in [(&https, "https"), (&http, "http"), (&tcp, "tcp")] {
        let line = render_log_line(ev, 42, &view, &p);
        assert!(
            line.contains(tok),
            "the {tok} transport shows in the line: {line}"
        );
        assert_eq!(
            log_event_json(ev, 7, None, None, &view, None)["proto"],
            serde_json::json!(tok),
            "the JSON proto field names the {tok} transport"
        );
    }

    // A request refused before its transport was known renders and serializes as `-`.
    let mut other = log_event(4, "", None, None, Blocked, "bad-request");
    other.proto = Proto::Other;
    assert_eq!(
        log_event_json(&other, 7, None, None, &view, None)["proto"],
        serde_json::json!("-")
    );
}

#[test]
fn the_proto_column_suffixes_the_http_version_and_tags_rpc_framing() {
    use sandbox::control::LogVerdict::Allow;
    use sandbox::control::{HttpVer, Proto, RpcKind};
    let p = style::Palette::plain();
    let view = LogView::default();

    // An inspected HTTP/2 gRPC forward reads `https/h2` — transport AND version, so the "it was
    // TLS" signal is never lost to a bare `h2` — with a `grpc` tag; both surface in the JSON too.
    let mut h2 = log_event(
        1,
        "repo42.example.net",
        Some("POST"),
        Some("/pkg.Service/Method"),
        Allow,
        "allowed",
    );
    h2.proto = Proto::Https;
    h2.http_ver = HttpVer::H2;
    h2.rpc = RpcKind::Grpc;
    let line = render_log_line(&h2, 42, &view, &p);
    assert!(
        line.contains("https/h2"),
        "version suffix in the line: {line}"
    );
    assert!(line.contains("grpc"), "rpc tag in the line: {line}");
    let j = log_event_json(&h2, 7, None, None, &view, None);
    assert_eq!(j["http_version"], serde_json::json!("h2"));
    assert_eq!(j["rpc"], serde_json::json!("grpc"));

    // An HTTP/1.1 Connect-streaming forward reads `https/h1` + `connect`.
    let mut h1 = log_event(2, "api.test", Some("POST"), Some("/p"), Allow, "allowed");
    h1.proto = Proto::Https;
    h1.http_ver = HttpVer::H1;
    h1.rpc = RpcKind::Connect;
    let line = render_log_line(&h1, 42, &view, &p);
    assert!(line.contains("https/h1"), "h1 suffix: {line}");
    assert!(line.contains("connect"), "connect tag: {line}");

    // A version-less / plain event keeps the bare proto, carries no rpc tag, and its two JSON
    // fields are null — the backward-compatible default (a raw `tcp://` splice here).
    let mut plain = log_event(3, "db.internal", None, None, Allow, "allowed");
    plain.proto = Proto::Tcp; // http_ver = Unknown, rpc = None (log_event's defaults)
    let line = render_log_line(&plain, 42, &view, &p);
    assert!(line.contains("tcp"), "bare proto: {line}");
    assert!(
        !line.contains("/h1") && !line.contains("/h2"),
        "no version suffix when unknown: {line}"
    );
    let j = log_event_json(&plain, 7, None, None, &view, None);
    assert_eq!(j["http_version"], serde_json::Value::Null);
    assert_eq!(j["rpc"], serde_json::Value::Null);
}

#[test]
fn a_websocket_event_is_flagged_ws_even_without_with_status() {
    use sandbox::control::LogVerdict::Allow;
    let p = style::Palette::plain();
    // A WebSocket carries a 101 (set only by the upgrade relay); a normal request never does.
    let mut ws = log_event(1, "chat.test", Some("GET"), Some("/rt"), Allow, "allowed");
    ws.status = Some(101);
    let normal = {
        let mut e = log_event(2, "api.test", Some("GET"), Some("/p"), Allow, "allowed");
        e.status = Some(200);
        e
    };
    let off = LogView::default();
    // The `ws` marker shows even without `--with-status`, and only for a 101.
    assert!(
        render_log_line(&ws, 7, &off, &p).contains("ws"),
        "a 101 event is flagged ws in the default view"
    );
    assert!(
        !render_log_line(&normal, 7, &off, &p).contains(" ws"),
        "a normal request is not flagged ws"
    );
    // Under --with-status the explicit 101 code is still shown alongside the ws marker.
    let on = LogView {
        with_status: true,
        ..LogView::default()
    };
    let line = render_log_line(&ws, 7, &on, &p);
    assert!(
        line.contains("ws") && line.contains("101"),
        "with --with-status a WebSocket shows both `ws` and `101`: {line}"
    );
}

#[test]
fn render_logs_groups_events_by_session_with_verdict_and_reason() {
    use sandbox::control::{LogVerdict::*, SessionLog};
    let p = style::Palette::plain();

    // Empty → a live-only note; under `--app`, it names the app.
    assert!(render_logs(&[], &[], &LogView::default(), &p, true).contains("nothing to show"));
    let scoped = render_logs(
        &[],
        &[],
        &LogView {
            app: Some("demo-app".into()),
            ..LogView::default()
        },
        &p,
        true,
    );
    assert!(scoped.contains("for app `demo-app`"), "{scoped}");

    let sessions = [SessionLog {
        pid: 4242,
        snapshot: sandbox::control::LogSnapshot {
            events: vec![
                log_event(
                    1,
                    "api.test",
                    Some("POST"),
                    Some("/v1/m?k=sec"),
                    Allow,
                    "allowed",
                ),
                log_event(
                    2,
                    "evil.test",
                    Some("GET"),
                    Some("/x"),
                    Deny,
                    "denied-default",
                ),
                log_event(
                    3,
                    "api.test",
                    Some("GET"),
                    Some("/dl"),
                    Error,
                    "dns-failure",
                ),
            ],
            dropped: 0,
            head: 3,
            amend_head: 0,
            captures: Vec::new(),
            capture_evicted: 0,
        },
    }];
    let context = vec![(
        4242u32,
        std::path::PathBuf::from("/home/u/proj"),
        "app:demo-app".to_string(),
    )];

    let out = render_logs(&sessions, &context, &LogView::default(), &p, true);
    // The session header from the registry context.
    assert!(
        out.contains("session 4242 [app:demo-app] /home/u/proj"),
        "{out}"
    );
    // Each event line leads with the session id (before the time) — proven by the id and the host
    // landing on one line, not just the header.
    assert!(
        out.lines()
            .any(|l| l.contains("4242") && l.contains("api.test:443") && l.contains("POST /v1/m")),
        "the event line leads with the session id: {out}"
    );
    // …and carries the event's wall-clock time as local HH:MM:SS (the events' 1_000_000 ms stamp).
    assert!(
        out.contains(&format_log_time(1_000_000)),
        "the line shows the local time: {out}"
    );
    assert!(
        !out.contains("k=sec"),
        "the query must be dropped by default: {out}"
    );
    assert!(
        !out.contains("(allowed)"),
        "an allow line omits the redundant reason: {out}"
    );
    // A deny line shows the reason category.
    assert!(
        out.contains("evil.test:443") && out.contains("(denied-default)"),
        "{out}"
    );
    // An error line (allowed-but-failed) shows its reason too.
    assert!(out.contains("(dns-failure)"), "{out}");
    // The live-only footer.
    assert!(out.contains("nothing is kept after it exits"), "{out}");

    // `--with-query` keeps the (already-redacted) query.
    let wq = render_logs(
        &sessions,
        &context,
        &LogView {
            with_query: true,
            ..LogView::default()
        },
        &p,
        true,
    );
    assert!(
        wq.contains("/v1/m?k=sec"),
        "--with-query keeps the query: {wq}"
    );
}

#[test]
fn render_logs_surfaces_ring_eviction_rather_than_truncating_silently() {
    use sandbox::control::{LogVerdict::*, SessionLog};
    let p = style::Palette::plain();

    // A session whose ring already evicted its oldest events: the retained window starts at
    // seq 4001, so 4000 older events fell off. `snapshot_evicted` reports the gap…
    let snapshot = sandbox::control::LogSnapshot {
        events: vec![
            log_event(4001, "api.test", Some("GET"), Some("/a"), Allow, "allowed"),
            log_event(
                4002,
                "api.test",
                Some("GET"),
                Some("/b"),
                Deny,
                "denied-default",
            ),
        ],
        dropped: 0,
        head: 4002,
        amend_head: 0,
        captures: Vec::new(),
        capture_evicted: 0,
    };
    assert_eq!(snapshot_evicted(&snapshot), 4000);
    // …a fresh ring (seqs from 1) reports none.
    let fresh = sandbox::control::LogSnapshot {
        events: vec![log_event(
            1,
            "api.test",
            Some("GET"),
            Some("/a"),
            Allow,
            "allowed",
        )],
        dropped: 0,
        head: 1,
        amend_head: 0,
        captures: Vec::new(),
        capture_evicted: 0,
    };
    assert_eq!(snapshot_evicted(&fresh), 0);

    // The render says so, rather than silently showing the last 1000 as if they were all.
    let sessions = [SessionLog { pid: 7, snapshot }];
    let out = render_logs(&sessions, &[], &LogView::default(), &p, true);
    assert!(
        out.contains("4000 earlier event(s) evicted from the ring"),
        "the ring overflow must be surfaced, not truncated silently:\n{out}"
    );
}

#[test]
fn a_muted_event_is_neither_shown_nor_counted_as_an_eviction() {
    use sandbox::control::{LogVerdict::*, SessionLog};
    let p = style::Palette::plain();

    // The finding: muted (`dontaudit`) refusals live in a ring of their own but draw their
    // sequence numbers from the same counter, so the default view's numbering has a hole at each
    // one — and `snapshot_evicted` read the oldest retained `seq - 1` as "this many events fell
    // off". A session with one `mute` rule was told it had lost events it still held. The reader
    // now asks for both rings merged (contiguous again) and suppresses the muted lines here.
    let mut muted = log_event(1, "telemetry.test", None, None, Deny, "denied-default");
    muted.muted = true;
    let snapshot = sandbox::control::LogSnapshot {
        events: vec![
            muted,
            log_event(2, "api.test", Some("GET"), Some("/a"), Allow, "allowed"),
            log_event(3, "api.test", Some("GET"), Some("/b"), Allow, "allowed"),
        ],
        dropped: 0,
        head: 3,
        amend_head: 0,
        captures: Vec::new(),
        capture_evicted: 0,
    };
    assert_eq!(
        snapshot_evicted(&snapshot),
        0,
        "nothing was evicted — seq 1 is the muted event, still retained"
    );
    let sessions = [SessionLog { pid: 7, snapshot }];
    let out = render_logs(&sessions, &[], &LogView::default(), &p, true);
    assert!(
        !out.contains("telemetry.test"),
        "a muted refusal stays out of the default view:\n{out}"
    );
    assert!(
        !out.contains("evicted from the ring"),
        "no eviction happened, so none may be reported:\n{out}"
    );
    // The suppression is the `--all` gate, not a blanket drop: what `--all` asks for still
    // arrives, and both real events show either way.
    assert!(
        out.contains("/a") && out.contains("/b"),
        "the unmuted events are shown:\n{out}"
    );
    let all = render_logs(
        &sessions,
        &[],
        &LogView {
            all: true,
            ..LogView::default()
        },
        &p,
        true,
    );
    assert!(
        all.contains("telemetry.test"),
        "`--all` shows the muted refusal:\n{all}"
    );
}

#[test]
fn the_log_reader_asks_each_session_for_its_muted_ring_so_a_hole_is_not_an_eviction() {
    use crate::testutil::{EnvVar, TmpDir, env_lock};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    // The sibling test above builds the merged snapshot by hand, so it says nothing about the
    // half of the fix that has to hold for the arithmetic to work: that the *reader* asks for
    // both rings whatever the view shows. This stand-in session answers like a real one — a
    // plain `LOG` omits the muted refusal, leaving a hole where seq 1 was, and `LOG all` folds
    // it back in — so a reader that asks for the default view is told an event was evicted that
    // the session still holds.
    let _lock = env_lock();
    let data = TmpDir::new();
    let _data_var = EnvVar::set("SBX_DATA_DIR", data.path());

    let pid = 424_243u32;
    let egress = data.path().join("egress");
    std::fs::create_dir_all(&egress).expect("create the control directory");
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).expect("bind the stand-in control socket");

    let session = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept the log read");
        let mut cmd = String::new();
        BufReader::new(&stream)
            .read_line(&mut cmd)
            .expect("read the command");
        let mut out = String::from("head=3\namended=0\n");
        // Only `LOG all` gets the muted ring — the split the session keeps between the two.
        if cmd.split_whitespace().any(|t| t == "all") {
            out.push_str(
                "event seq=1 at=1000000 port=443 verdict=deny proto=https \
                 reason=denied-default muted=1 host=telemetry.test\n",
            );
        }
        out.push_str(
            "event seq=2 at=1000000 port=443 verdict=allow proto=https reason=allowed \
             method=GET host=api.test path=/a\n\
             event seq=3 at=1000000 port=443 verdict=allow proto=https reason=allowed \
             method=GET host=api.test path=/b\n\
             ok\n",
        );
        (&stream)
            .write_all(out.as_bytes())
            .expect("write the log reply");
        cmd.trim_end().to_string()
    });

    let (sessions, context) = collect_logs(data.path(), None, false);
    let asked = session.join().expect("the stand-in session thread");
    assert_eq!(sessions.len(), 1, "the stand-in session must be reachable");
    assert_eq!(
        snapshot_evicted(&sessions[0].snapshot),
        0,
        "nothing was evicted — seq 1 is the muted refusal, still held (the reader asked \
         `{asked}`)"
    );

    // And the fold is invisible to the reader: the muted refusal is still suppressed, the two
    // real events still shown, and no eviction line invented from the hole it left.
    let out = render_logs(
        &sessions,
        &context,
        &LogView::default(),
        &style::Palette::plain(),
        true,
    );
    assert!(
        !out.contains("evicted from the ring"),
        "no eviction happened, so none may be reported:\n{out}"
    );
    assert!(
        !out.contains("telemetry.test"),
        "a muted refusal stays out of the default view:\n{out}"
    );
    assert!(
        out.contains("/a") && out.contains("/b"),
        "the unmuted events are shown:\n{out}"
    );
}
