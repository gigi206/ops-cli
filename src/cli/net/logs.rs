//! `sbx net logs` — the egress decisions a session recorded, and the traffic captured with them.
//!
//! The view model every function here branches on ([`LogView`]), the argument parser, the reader
//! and its filters, the one-shot render, the `--follow` stream, the per-event line, the
//! captured-traffic block and both JSON emitters. Events and captures are one file because they
//! interleave inside [`render_logs`] and [`net_logs_follow`] rather than layering.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{diag, help, sandbox, style};
use crate::{
    egress_dir_or_fail, format_log_time, interval_seconds, pending_session_context,
    session_pids_for_app,
};

use super::{write_session_header, write_session_header_line};

/// The parsed `sbx net logs` display options.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LogView {
    json: bool,
    app: Option<String>,
    host: Option<String>,
    verdict: Option<sandbox::control::LogVerdict>,
    limit: Option<usize>,
    with_query: bool,
    /// `--with-status`: show the captured upstream HTTP status (200/404/…) — for completed L7
    /// requests only; blank/absent for an L4 splice, a refusal, or an error.
    with_status: bool,
    /// `--follow`: after the initial listing, keep polling and append new events (a `tail -f`).
    follow: bool,
    /// The `--follow` poll interval in seconds (`-i`), default 1. Ignored without `--follow`.
    interval_secs: u64,
    /// `--all`: also show refusals a `mute` (`dontaudit`) rule suppressed from the default view —
    /// tagged `muted`. They live in a separate ring and are still counted in `sbx net stats`; the
    /// default view omits them.
    all: bool,
    /// `--with-headers`: show each exchange's request and response heads, when the session captured
    /// them (`[network] capture`).
    with_headers: bool,
    /// `--with-body`: show the captured bodies too — implies `--with-headers`, since a body without
    /// its head names nothing.
    with_body: bool,
}

impl LogView {
    /// Whether this view needs the captured traffic — the single predicate the reader and the
    /// renderer branch on, so the two can never disagree about whether to ask for it.
    fn wants_capture(&self) -> bool {
        self.with_headers || self.with_body
    }
}

/// Parse `sbx net logs [-a|--app <name>] [--host <h>] [--verdict allow|deny|blocked|error]
/// [-n <N>] [--with-query] [--with-status] [--follow] [-i|--interval <secs>] [--json]`. Pure (no
/// I/O), so every reject path is unit-testable — a missing value, an unknown verdict, a non-numeric
/// count or interval, a zero interval, or an unknown flag is an error.
fn parse_log_args(args: &[OsString]) -> Result<LogView, String> {
    let mut v = LogView {
        interval_secs: 1,
        ..LogView::default()
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--json") => v.json = true,
            Some("--all") => v.all = true,
            Some("--with-query") => v.with_query = true,
            Some("--with-status") => v.with_status = true,
            Some("--with-headers") => v.with_headers = true,
            // A body is unreadable without the head that names it, so `--with-body` turns both on.
            Some("--with-body") => {
                v.with_body = true;
                v.with_headers = true;
            }
            Some("--follow") | Some("-f") => v.follow = true,
            Some("-i") | Some("--interval") => v.interval_secs = interval_seconds(it.next())?,
            Some("-a") | Some("--app") => {
                let name = it.next().ok_or("`--app` needs an app name")?;
                v.app = Some(name.to_string_lossy().into_owned());
            }
            Some("--host") => {
                let h = it.next().ok_or("`--host` needs a hostname")?;
                v.host = Some(h.to_string_lossy().into_owned());
            }
            Some("--verdict") => {
                let val = it
                    .next()
                    .ok_or("`--verdict` needs one of allow|deny|blocked|error")?;
                let parsed = val
                    .to_str()
                    .and_then(sandbox::control::LogVerdict::parse)
                    .ok_or_else(|| {
                        format!(
                            "invalid verdict `{}` — expected allow|deny|blocked|error",
                            val.to_string_lossy()
                        )
                    })?;
                v.verdict = Some(parsed);
            }
            Some("-n") => {
                let val = it.next().ok_or("`-n` needs a count")?;
                let n: usize = val.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid count `{}` — expected a whole number",
                        val.to_string_lossy()
                    )
                })?;
                v.limit = Some(n);
            }
            _ => {
                return Err(format!("usage: {}", help::synopsis_of(&["net", "logs"])));
            }
        }
    }
    Ok(v)
}

/// Query the live control sockets for each session's recent egress events, scoped to one app's
/// session(s) when `app` is set, and pair them with their registry context. The read-only gather
/// step behind `sbx net logs` — the log's analogue of `pending::collect_pending`, private to that
/// sibling and so named rather than linked. No launch / nix / network.
///
/// The muted (`dontaudit`) ring is always folded in, whatever the view shows: a session keeps its
/// muted refusals in a *separate* ring that shares one sequence counter with the main one, so the
/// default view's sequence numbers have a hole at every muted event — and [`snapshot_evicted`] reads
/// the retained window's first sequence number as the count of what fell off. Asking for the merged
/// view is what makes that sequence contiguous again. What the reader sees is decided in
/// [`filtered_log_events`], which drops the muted events unless `--all` asked for them.
fn collect_logs(
    data_dir: &Path,
    app: Option<&str>,
    with_capture: bool,
) -> (
    Vec<sandbox::control::SessionLog>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut sessions = sandbox::control::log_all(data_dir, true, with_capture);
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        sessions.retain(|s| pids.contains(&s.pid));
    }
    let context = pending_session_context(data_dir);
    (sessions, context)
}

/// Whether one event passes the ongoing `--host`/`--verdict` filters (the `-n` limit is separate —
/// it caps the initial listing, not the followed stream). Shared by the one-shot listing and the
/// `--follow` stream so a filter behaves identically in both.
fn event_passes_filters(e: &sandbox::control::LogEvent, view: &LogView) -> bool {
    view.host.as_deref().is_none_or(|h| e.host == h) && view.verdict.is_none_or(|v| e.verdict == v)
}

/// The events of one session that pass the `--host`/`--verdict` filters, then the `-n` limit (the
/// most recent N, since the ring is oldest-first). Borrowed, so the render/JSON share one filter.
///
/// This is also where a muted (`dontaudit`) refusal is suppressed. [`collect_logs`] asks every
/// session for its muted ring as well — the eviction count is only derivable from the two merged —
/// so the gate that keeps those events out of the default view lives here, on the one path the
/// listing and the `--follow` seed both render through.
fn filtered_log_events<'a>(
    events: &'a [sandbox::control::LogEvent],
    view: &LogView,
) -> Vec<&'a sandbox::control::LogEvent> {
    let mut out: Vec<&sandbox::control::LogEvent> = events
        .iter()
        .filter(|e| (view.all || !e.muted) && event_passes_filters(e, view))
        .collect();
    if let Some(n) = view.limit
        && out.len() > n
    {
        out = out.split_off(out.len() - n);
    }
    out
}

/// The path as displayed: the query string is dropped by default (a token can ride in a query, and
/// the terminal scrollback is itself "at rest"), kept only under `--with-query` — where it is
/// already secret-redacted, since the proxy masks configured needles before the event enters the ring.
fn display_log_path(path: &str, with_query: bool) -> &str {
    if with_query {
        path
    } else {
        path.split('?').next().unwrap_or(path)
    }
}

/// How many of a session's oldest events fell off the ring before the retained window. Sequence
/// numbers start at 1, so the oldest retained event's `seq - 1` is the evicted count — surfaced (not
/// silently truncated) even for the one-shot listing, distinct from any `-n`/`--host`/`--verdict` the
/// user applied. Computed from the **unfiltered** snapshot.
///
/// That arithmetic only holds while the window is contiguous, which is why [`collect_logs`] always
/// asks for the muted ring: muted refusals are numbered from the same counter but kept in a ring of
/// their own, so on the default view every muted event left a hole that read here as an event
/// evicted. A session with a single `mute` rule and a chatty muted host was told it had lost
/// hundreds of events it still had. Counted over the merged rings the number is what it claims to
/// be: how many events the session recorded before the oldest one it still holds.
fn snapshot_evicted(snapshot: &sandbox::control::LogSnapshot) -> u64 {
    snapshot.events.first().map(|e| e.seq - 1).unwrap_or(0)
}

/// `sbx net logs [-a|--app <name>] [--host <h>] [--verdict …] [-n <N>] [--with-query] [--json]`:
/// the live egress event log — a chronological, per-session record of every egress decision the
/// proxy made, read from the same control sockets `sbx net pending` uses. Live-only: it shows a
/// running session's egress, and nothing remains once the session exits. No launch / nix / network.
pub(super) fn net_logs(args: &[OsString]) -> ExitCode {
    let view = match parse_log_args(args) {
        Ok(v) => v,
        Err(e) => {
            diag::error(&format!("sbx: net logs: {e}"));
            return ExitCode::from(2);
        }
    };
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    if view.follow {
        return net_logs_follow(&data_dir, &view, &pal);
    }

    let (sessions, context) = collect_logs(&data_dir, view.app.as_deref(), view.wants_capture());

    if view.json {
        let ctx_of = |pid: u32| context.iter().find(|(p, _, _)| *p == pid);
        let rows: Vec<_> = sessions
            .iter()
            .flat_map(|s| {
                let ctx = ctx_of(s.pid);
                let project = ctx.map(|(_, p, _)| p.display().to_string());
                let label = ctx.map(|(_, _, l)| l.clone());
                // Capture `view` by reference (it is used again below), the owned project/label by move.
                let view = &view;
                filtered_log_events(&s.snapshot.events, view)
                    .into_iter()
                    .map(move |e| {
                        let cap = capture_of(&s.snapshot, e.seq, view);
                        log_event_json(e, s.pid, project.as_deref(), label.as_deref(), view, cap)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        // Per-session ring-eviction counts (only where >0) — the overflow surfaced, not silent.
        let evicted: Vec<_> = sessions
            .iter()
            .filter_map(|s| {
                let n = snapshot_evicted(&s.snapshot);
                (n > 0).then(|| serde_json::json!({ "pid": s.pid, "count": n }))
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({ "logs": rows, "evicted": evicted })
        );
        return ExitCode::SUCCESS;
    }

    print!("{}", render_logs(&sessions, &context, &view, &pal, true));
    ExitCode::SUCCESS
}

/// `sbx net logs --follow`: after seeding with the current listing, poll each reachable session on
/// the interval and **append** the events past a per-session seq cursor — a `tail -f` for egress. A
/// ring overflow between polls (`dropped` > 0) is announced, never dropped silently. A session that
/// ends (its control socket vanishes) is noted once; a new one is picked up. Runs until interrupted
/// (Ctrl-C); the append shape is pipe-friendly (unlike `pending watch`'s in-place redraw), so it
/// needs no terminal. The `--follow` NDJSON stream (`--json`) emits one event object per line.
fn net_logs_follow(data_dir: &Path, view: &LogView, pal: &style::Palette) -> ExitCode {
    use std::collections::HashMap;
    use std::fmt::Write as _;

    let interval = std::time::Duration::from_secs(view.interval_secs.max(1));
    // A per-session cursor: the last seq already shown, plus the amendment cursor (for retroactive
    // status). Seeded from the initial listing so the follow only ever appends genuinely new events.
    let mut cursor: HashMap<u32, (u64, u64)> = HashMap::new();
    let (dim, r) = (pal.dim, pal.reset);
    let ctx_of = |ctx: &[(u32, PathBuf, String)], pid: u32| {
        ctx.iter()
            .find(|(p, _, _)| *p == pid)
            .map(|(_, proj, label)| (proj.display().to_string(), label.clone()))
    };

    // Seed: the current listing (human render, or NDJSON of the retained events), respecting `-n`.
    // Only actual events are written — the one-shot's "nothing to show" line is skipped, so a follow
    // that pipes to `head` on an idle session emits no spurious line then spins.
    let (sessions, context) = collect_logs(data_dir, view.app.as_deref(), view.wants_capture());
    let has_events = sessions
        .iter()
        .any(|s| !filtered_log_events(&s.snapshot.events, view).is_empty());
    let mut seed = String::new();
    if view.json {
        for s in &sessions {
            let c = ctx_of(&context, s.pid);
            for e in filtered_log_events(&s.snapshot.events, view) {
                let obj = log_event_json(
                    e,
                    s.pid,
                    c.as_ref().map(|(p, _)| p.as_str()),
                    c.as_ref().map(|(_, l)| l.as_str()),
                    view,
                    capture_of(&s.snapshot, e.seq, view),
                );
                let _ = writeln!(seed, "{obj}");
            }
        }
    } else if has_events {
        // No footer in the seed — events append below it, so the live-only note would land mid-stream.
        seed = render_logs(&sessions, &context, view, pal, false);
    }
    for s in &sessions {
        cursor.insert(s.pid, (s.snapshot.head, s.snapshot.amend_head));
    }
    // A closed downstream pipe (`… | head`) ends the follow cleanly — Rust ignores SIGPIPE, so a
    // write to a gone reader returns an error we must act on rather than spin forever.
    if flush_stream(&seed).is_err() {
        return ExitCode::SUCCESS;
    }
    diag::error("sbx: following egress (Ctrl-C to quit)");

    let mut last_pid: Option<u32> = None; // the session whose header was last printed (human view)
    loop {
        std::thread::sleep(interval);
        let context = pending_session_context(data_dir);
        let mut pids = sandbox::control::session_pids(data_dir);
        if let Some(name) = view.app.as_deref() {
            let allowed = session_pids_for_app(data_dir, name);
            pids.retain(|p| allowed.contains(p));
        }

        // Build this tick's output into a buffer, then write it once — so a broken pipe is detected on
        // the single write and ends the follow, and the ordering of every line is deterministic.
        let mut tick = String::new();

        // A session that had a cursor but no longer has a socket has ended — note it once and forget.
        let live: std::collections::HashSet<u32> = pids.iter().copied().collect();
        let ended: Vec<u32> = cursor
            .keys()
            .copied()
            .filter(|p| !live.contains(p))
            .collect();
        for pid in ended {
            cursor.remove(&pid);
            if !view.json {
                let _ = writeln!(tick, "  {dim}session {pid} ended{r}");
                if last_pid == Some(pid) {
                    last_pid = None;
                }
            }
        }

        for pid in pids {
            let entry = cursor.get(&pid).copied();
            let after = entry.map(|(seq, _)| seq);
            // Request retroactive re-emission only when something amended is actually shown — a
            // status under `--with-status`, or the traffic under `--with-headers`/`--with-body`.
            // Otherwise the completion is invisible and re-showing the line would be pure
            // duplication. Both arrive as ONE amendment per exchange, so an event is re-shown once.
            let after_amend = if view.with_status || view.wants_capture() {
                entry.map(|(_, amend)| amend)
            } else {
                None
            };
            let Ok(snap) = sandbox::control::read_log(
                &sandbox::control::control_socket(data_dir, pid),
                after,
                after_amend,
                view.all,
                view.wants_capture(),
            ) else {
                continue; // a session that vanished mid-read is handled next tick
            };
            // A gap between polls (the ring overflowed) — surfaced, never silent.
            if snap.dropped > 0 {
                if view.json {
                    let _ = writeln!(
                        tick,
                        "{}",
                        serde_json::json!({ "pid": pid, "dropped": snap.dropped })
                    );
                } else {
                    let _ = writeln!(
                        tick,
                        "  {dim}[{pid}] {} event(s) dropped — the ring overflowed between polls{r}",
                        snap.dropped
                    );
                }
            }
            let new: Vec<&sandbox::control::LogEvent> = snap
                .events
                .iter()
                .filter(|e| event_passes_filters(e, view))
                .collect();
            if !new.is_empty() {
                let c = ctx_of(&context, pid);
                for e in new {
                    if view.json {
                        let obj = log_event_json(
                            e,
                            pid,
                            c.as_ref().map(|(p, _)| p.as_str()),
                            c.as_ref().map(|(_, l)| l.as_str()),
                            view,
                            capture_of(&snap, e.seq, view),
                        );
                        let _ = writeln!(tick, "{obj}");
                    } else {
                        // A session header only when the stream switches sessions, so a single-session
                        // follow does not repeat it every event.
                        if last_pid != Some(pid) {
                            write_session_header_line(
                                &mut tick,
                                pid,
                                c.as_ref()
                                    .map(|(proj, label)| (label.as_str(), proj.as_str())),
                                pal,
                            );
                            last_pid = Some(pid);
                        }
                        let _ = writeln!(tick, "{}", render_log_line(e, pid, view, pal));
                        tick.push_str(&render_sightings(e, pal));
                        if let Some(cap) = capture_of(&snap, e.seq, view) {
                            tick.push_str(&render_capture(cap, view, pal));
                        }
                    }
                }
            }
            cursor.insert(pid, (snap.head, snap.amend_head));
        }
        if flush_stream(&tick).is_err() {
            return ExitCode::SUCCESS; // downstream pipe closed
        }
    }
}

/// Write `s` to stdout and flush, returning the I/O result — a broken pipe (a closed `… | head`
/// downstream) surfaces here rather than being swallowed, so a `--follow` loop can stop instead of
/// spinning forever (Rust ignores SIGPIPE). An empty string is a successful no-op.
fn flush_stream(s: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    if s.is_empty() {
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())?;
    out.flush()
}

/// The ANSI span for a verdict: green for `allow`, red for a refusal (`deny`/`blocked`), yellow for
/// `error` (allowed but failed) — so a scan of the log reads at a glance.
fn verdict_color(verdict: sandbox::control::LogVerdict, pal: &style::Palette) -> &str {
    use sandbox::control::LogVerdict::*;
    match verdict {
        Allow => pal.ok,
        Deny | Blocked => pal.err,
        Error => pal.warn,
    }
}

/// The ANSI span for an upstream HTTP status class: green for 2xx, red for 4xx/5xx, yellow for the
/// rest (1xx/3xx) — so a failing response stands out under `--with-status`.
fn status_color(code: u16, pal: &style::Palette) -> &str {
    match code {
        200..=299 => pal.ok,
        400..=599 => pal.err,
        _ => pal.warn,
    }
}

/// Render the live egress log — a pure presenter (its colored layout is asserted in a test): a
/// header, then per session a context line and one line per event
/// (`time · host:port · method path · verdict · reason`), oldest first. The `reason` is dropped for a
/// plain `allow` (it would just repeat "allowed"). An empty result explains the log is live-only.
/// `footer` appends the live-only note — on for the one-shot listing, off for the `--follow` seed
/// (where events append below it, so the note would land mid-stream).
fn render_logs(
    sessions: &[sandbox::control::SessionLog],
    context: &[(u32, PathBuf, String)],
    view: &LogView,
    pal: &style::Palette,
    footer: bool,
) -> String {
    use std::fmt::Write as _;
    let (h, dim, r) = (pal.head, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions
        .iter()
        .map(|s| filtered_log_events(&s.snapshot.events, view).len())
        .sum();
    if total == 0 {
        let scope = view
            .app
            .as_deref()
            .map(|a| format!(" for app `{a}`"))
            .unwrap_or_default();
        let _ = writeln!(
            o,
            "{h}egress log:{r} {dim}(nothing to show{scope} — the log is live while a filtering \
             posture (allowlist/ask) runs, and is not kept after a session exits){r}"
        );
        return o;
    }
    let _ = writeln!(o, "{h}egress log:{r}");
    for session in sessions {
        let events = filtered_log_events(&session.snapshot.events, view);
        if events.is_empty() {
            continue;
        }
        write_session_header(&mut o, session.pid, context, pal);
        // The ring is bounded; if it evicted older events, say so rather than truncate silently.
        let evicted = snapshot_evicted(&session.snapshot);
        if evicted > 0 {
            let _ = writeln!(
                o,
                "    {dim}({evicted} earlier event(s) evicted from the ring){r}"
            );
        }
        // The capture ring is bounded on its own (a byte budget), so an exchange can be listed with
        // its traffic already evicted — say so rather than let a missing body read as "none sent".
        if view.wants_capture() && session.snapshot.capture_evicted > 0 {
            let _ = writeln!(
                o,
                "    {dim}({} earlier capture(s) evicted — the capture budget is bounded){r}",
                session.snapshot.capture_evicted
            );
        }
        for e in events {
            let _ = writeln!(o, "{}", render_log_line(e, session.pid, view, pal));
            o.push_str(&render_sightings(e, pal));
            if let Some(cap) = capture_of(&session.snapshot, e.seq, view) {
                o.push_str(&render_capture(cap, view, pal));
            }
        }
        // Asked for traffic and this session has none at all: say why rather than print the same
        // listing as without the flag, which reads as "nothing was sent". Both causes are named,
        // because the reader cannot tell them apart from here: a session that does not capture, and
        // a capturing session none of whose exchanges had traffic to keep (every one refused, or a
        // `tcp://` splice, which never has a head to read).
        if view.wants_capture() && session.snapshot.captures.is_empty() {
            let _ = writeln!(
                o,
                "    {dim}(no captured traffic here — either this session is not capturing (set \
                 `[network] capture = \"bodies\"`, or launch with \
                 `--config '[network] capture = \"bodies\"'`), or nothing it did carried any: a \
                 refused request and a `tcp://` splice never do){r}"
            );
        }
    }
    if footer {
        let _ = writeln!(
            o,
            "  {dim}live view — this session's egress; nothing is kept after it exits{r}"
        );
    }
    o
}

/// One event's display line (indented, no trailing newline): `session-id · time · host:port ·
/// method path · verdict · reason`. The `pid` is the session id (the one `sbx session ls`/`attach`/`stop`
/// use), led so a line is self-contained when scanned or piped. The `reason` is dropped for a plain
/// `allow` (it would just repeat "allowed"); a blank host (a malformed handshake) shows `-`. Shared
/// by the one-shot render and the `--follow` stream so a line looks identical in both.
fn render_log_line(
    e: &sandbox::control::LogEvent,
    pid: u32,
    view: &LogView,
    pal: &style::Palette,
) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let hostport = if e.host.is_empty() {
        "-".to_string()
    } else {
        format!("{}:{}", e.host, e.port)
    };
    let time = format_log_time(e.at_epoch_ms);
    let method = e
        .method
        .as_deref()
        .map(|m| format!("{m} "))
        .unwrap_or_default();
    let path = e
        .path
        .as_deref()
        .map(|p| display_log_path(p, view.with_query))
        .unwrap_or("");
    // The transport the request used (`https`/`http`/`tcp`, or `-` when refused before it was
    // known) — shown because the port alone does not name it (a `tcp://` splice can ride 443) —
    // suffixed with the HTTP version for an inspected request (`https/h1` vs `https/h2`), so the
    // transport-security axis is preserved while the h1-vs-h2 axis is added beside it.
    let proto = format!("{}{}", e.proto.as_str(), e.http_ver.suffix());
    // The RPC framing recognized from the request `Content-Type` (`grpc`/`grpc-web`/`connect`), shown
    // as a compact tag; empty for a plain request (Connect *unary* is byte-identical to plain protobuf
    // and is deliberately not tagged).
    let rpc = if e.rpc == sandbox::control::RpcKind::None {
        String::new()
    } else {
        format!("  {n}{}{r}", e.rpc.as_str())
    };
    let vc = verdict_color(e.verdict, pal);
    let reason = if e.verdict == sandbox::control::LogVerdict::Allow {
        String::new()
    } else {
        format!("  {dim}({}){r}", e.reason)
    };
    // A WebSocket shows a `101` status (set only by the upgrade relay; the normal path never records
    // a 1xx), so flag it explicitly — a long-lived bidirectional tunnel reads differently from a
    // one-shot request, and the marker shows even without `--with-status`.
    let ws = if e.status == Some(101) {
        format!("  {n}ws{r}")
    } else {
        String::new()
    };
    // A refusal shown only because of `--all` — flag it so a suppressed (`mute`/`dontaudit`) line is
    // never mistaken for one the default view would have shown.
    let muted = if e.muted {
        format!("  {dim}muted{r}")
    } else {
        String::new()
    };
    // The upstream status, only under `--with-status`: the code (colored by class) for a completed
    // L7 request, or `-` where none was captured (an L4 splice, a refusal, or a not-yet-returned
    // response) so the column is legible rather than mysteriously blank.
    let status = if view.with_status {
        match e.status {
            Some(code) => format!("  {}{code}{r}", status_color(code, pal)),
            None => format!("  {dim}-{r}"),
        }
    } else {
        String::new()
    };
    format!(
        "    {dim}{pid}{r}  {dim}{time}{r}  {dim}{proto}{r}  {n}{hostport}{r}  {method}{path}{rpc}  {vc}{}{r}{reason}{ws}{muted}{status}",
        e.verdict.as_str()
    )
}

/// Render the configured secrets seen crossing an exchange's WebSocket tunnel, one line each, or
/// nothing when none were.
///
/// Shown on every view, not behind `--with-headers`/`--with-body`: a capture is a debugging
/// convenience the reader opts into, while a credential crossing a tunnel is a fact about the
/// session that has to reach a plain `sbx net logs`. It reads as a warning rather than as traffic,
/// because unlike the two HTTP tripwires nothing was refused or masked — the bytes crossed, and this
/// says so. Only the credential's NAME is printed; its value never leaves the host.
fn render_sightings(e: &sandbox::control::LogEvent, pal: &style::Palette) -> String {
    let (warn, r) = (pal.warn, pal.reset);
    let mut out = String::new();
    for seen in &e.secrets_seen {
        let way = match seen.way {
            sandbox::control::SecretWay::Out => "cage → upstream",
            sandbox::control::SecretWay::Back => "upstream → cage",
        };
        out.push_str(&format!(
            "      {warn}! secret `{}` crossed this websocket ({way}); it was NOT blocked or \
             masked{r}\n",
            seen.name
        ));
    }
    out
}

/// The capture belonging to event `seq` in `snapshot`, or `None` when the view did not ask for one
/// or the session retained none for that exchange.
fn capture_of<'a>(
    snapshot: &'a sandbox::control::LogSnapshot,
    seq: u64,
    view: &LogView,
) -> Option<&'a sandbox::control::Capture> {
    view.wants_capture()
        .then(|| snapshot.captures.iter().find(|c| c.seq == seq))
        .flatten()
}

/// Render one exchange's captured traffic as an indented block under its event line: `>` lines for
/// what the cage sent, `<` lines for what came back — the direction convention `curl -v` uses.
///
/// Bodies appear only under `--with-body`; a part that was cut is marked, never trimmed in silence.
/// The marker names the fact rather than a cause: a part is cut when it reached its cap, and also
/// when the exchange was filed while more was still arriving (an HTTP/2 request body whose pump is
/// still running). Every configured secret was masked out of these bytes by the session that
/// captured them.
fn render_capture(cap: &sandbox::control::Capture, view: &LogView, pal: &style::Palette) -> String {
    use sandbox::control::CapturePart;
    use std::fmt::Write as _;
    let (dim, n, r) = (pal.dim, pal.name, pal.reset);
    let mut o = String::new();
    for (part, bytes) in cap.parts() {
        // A WebSocket's frames are payload like a body, so they answer to the same flag: `--with-headers`
        // alone shows the handshake, and the transcript needs `--with-body`.
        let body = matches!(
            part,
            CapturePart::ReqBody | CapturePart::ResBody | CapturePart::WsUp | CapturePart::WsDown
        );
        if body && !view.with_body {
            continue;
        }
        let arrow = match part {
            CapturePart::ReqHead
            | CapturePart::Injected
            | CapturePart::ReqBody
            | CapturePart::WsUp => ">",
            CapturePart::ResHead | CapturePart::ResBody | CapturePart::WsDown => "<",
        };
        if part == CapturePart::Injected {
            // The names of the credentials sbx added for the upstream. Their values are never
            // captured, so name them rather than let the head read as the whole of what was sent.
            for name in String::from_utf8_lossy(&bytes.bytes).lines() {
                let _ = writeln!(
                    o,
                    "      {dim}{arrow}{r} {n}{name}{r}{dim}: <injected by sbx>{r}"
                );
            }
            continue;
        }
        for line in render_bytes(&bytes.bytes) {
            let _ = writeln!(o, "      {dim}{arrow}{r} {line}");
        }
        if bytes.truncated {
            let _ = writeln!(
                o,
                "      {dim}{arrow} … truncated, more followed ({} byte(s) shown){r}",
                bytes.bytes.len()
            );
        }
    }
    o
}

/// The lines to print for one captured part: its text, split on newlines with control characters
/// escaped, or a single summary line when the bytes are not text at all (a compressed or binary
/// body, which would otherwise print as noise). Trailing blank lines are dropped — an HTTP head's
/// terminator would render as one.
fn render_bytes(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    if !is_mostly_text(bytes) {
        return vec![format!("<{} byte(s) of binary data>", bytes.len())];
    }
    let text = String::from_utf8_lossy(bytes);
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|l| {
            l.chars()
                .map(|c| match c {
                    '\r' => String::new(),
                    '\t' => "    ".to_string(),
                    c if c.is_control() => format!("\\x{:02x}", c as u32),
                    c => c.to_string(),
                })
                .collect()
        })
        .collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines
}

/// Whether `bytes` read as text worth printing: valid UTF-8 (up to a trailing partial character,
/// which a capped capture will often end on) with no NUL and few control bytes. A gzip or protobuf
/// body fails this and is summarized instead.
fn is_mostly_text(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|b| !b.is_ascii_control() || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    // A body is text if nearly all of it is; the slack covers UTF-8 continuation bytes, which are
    // non-ASCII rather than control and so already count as printable.
    printable * 10 >= bytes.len() * 9
}

/// One event as a JSON object (for `--json` and the `--follow` NDJSON stream). Epoch-ms is a number
/// (it fits u64); the path honors `--with-query`. The `status` field is included only under
/// `--with-status` (a number for a completed L7 request, else null) — parity with `--with-query`.
/// Shared so the two JSON paths cannot diverge.
fn log_event_json(
    e: &sandbox::control::LogEvent,
    pid: u32,
    project: Option<&str>,
    label: Option<&str>,
    view: &LogView,
    capture: Option<&sandbox::control::Capture>,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "pid": pid,
        "project": project,
        "label": label,
        "at_epoch_ms": e.at_epoch_ms as u64,
        "host": e.host,
        "port": e.port,
        "method": e.method,
        "path": e.path.as_deref().map(|p| display_log_path(p, view.with_query)),
        "verdict": e.verdict.as_str(),
        "proto": e.proto.as_str(),
        // The HTTP version of an inspected request (`h1`/`h2`), or null for a refusal / raw splice.
        "http_version": (e.http_ver != sandbox::control::HttpVer::Unknown).then(|| e.http_ver.as_wire()),
        // The RPC framing from the `Content-Type` (`grpc`/`grpc-web`/`connect`), or null.
        "rpc": (e.rpc != sandbox::control::RpcKind::None).then(|| e.rpc.as_str()),
        "reason": e.reason,
        "muted": e.muted,
        // Configured secrets seen crossing this exchange's websocket tunnel, by NAME and direction
        // (`out` = cage to upstream, `back` = upstream to cage). Empty for everything else. Present
        // unconditionally, like `muted`: it is a fact about the session, not a view option.
        "secrets_seen": e.secrets_seen.iter().map(|s| serde_json::json!({
            "name": s.name,
            "way": s.way.as_str(),
        })).collect::<Vec<_>>(),
    });
    if view.with_status {
        obj["status"] = e
            .status
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null);
    }
    if view.wants_capture() {
        // The captured traffic, present only when the session retained some for this exchange.
        // Each part carries its bytes **base64-encoded**: a body is arbitrary binary (and may be
        // compressed), so encoding it is the only lossless choice — a lossy-UTF8 string field would
        // silently corrupt what the consumer is inspecting.
        obj["capture"] = match capture {
            Some(cap) => capture_json(cap, view),
            None => serde_json::Value::Null,
        };
    }
    obj
}

/// One capture as a JSON object: one field per non-empty part, each `{"b64": …, "truncated": bool}`,
/// plus `injected` as a plain list of header names (never values). Bodies and a WebSocket's frames
/// are included only under `--with-body`, matching the human view.
fn capture_json(cap: &sandbox::control::Capture, view: &LogView) -> serde_json::Value {
    use sandbox::control::CapturePart;
    let mut obj = serde_json::Map::new();
    for (part, bytes) in cap.parts() {
        let body = matches!(
            part,
            CapturePart::ReqBody | CapturePart::ResBody | CapturePart::WsUp | CapturePart::WsDown
        );
        if body && !view.with_body {
            continue;
        }
        if part == CapturePart::Injected {
            let names: Vec<&str> = std::str::from_utf8(&bytes.bytes)
                .unwrap_or_default()
                .lines()
                .collect();
            obj.insert("injected".into(), serde_json::json!(names));
            continue;
        }
        obj.insert(
            part.as_str().replace('-', "_"),
            serde_json::json!({
                "b64": sandbox::control::base64_encode(&bytes.bytes),
                "truncated": bytes.truncated,
            }),
        );
    }
    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod tests;
