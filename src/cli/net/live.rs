//! `sbx net live` — the egress tunnels that are open right now.
//!
//! Argument parsing, the flow gather, the age formatter, the frame presenter and the NDJSON
//! snapshot emitter. Deliberately distinct from the log view: this one shows connections still
//! open, where `logs` reports decisions already taken.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::{diag, help, sandbox, style};
use crate::{egress_dir_or_fail, interval_seconds, pending_session_context, session_pids_for_app};

use super::{write_session_header, write_unanswered};

/// Parsed `sbx net live` options: the redraw interval, an optional app filter, and JSON output.
#[derive(Debug)]
struct LiveArgs {
    interval: Duration,
    app: Option<String>,
    json: bool,
}

/// Parse `live [-i|--interval <secs>] [-a|--app <name>] [--json]`. Pure (no I/O), so every reject path
/// is unit-testable without a terminal. The refresh defaults to 1 second — a live view wants a
/// snappier tick than the pending watch. A missing/zero/non-numeric interval or an unknown flag errors.
fn parse_live_args(args: &[OsString]) -> Result<LiveArgs, String> {
    let mut interval_secs: u64 = 1;
    let mut app: Option<String> = None;
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("-i") | Some("--interval") => interval_secs = interval_seconds(it.next())?,
            Some("-a") | Some("--app") => {
                app = Some(crate::cli::option_text(it.next(), "--app", "an app name")?.to_string());
            }
            Some("--json") => json = true,
            _ => return Err(format!("usage: {}", help::synopsis_of(&["net", "live"]))),
        }
    }
    Ok(LiveArgs {
        interval: Duration::from_secs(interval_secs),
        app,
        json,
    })
}

/// Query the live control sockets for the tunnels open right now, scoped to one app's session(s) when
/// `app` is set, and pair them with their registry context (`(pid, project, label)`). The shared
/// gather behind each `net live` tick. No launch / nix / network.
///
/// A session that was reached and did not answer in full comes back in [`Swept::unread`], scoped
/// the same way, and each tick names it in its frame.
///
/// [`Swept::unread`]: sandbox::control::Swept::unread
fn collect_flows(
    data_dir: &Path,
    app: Option<&str>,
) -> (
    sandbox::control::Swept<sandbox::control::SessionFlows>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut swept = sandbox::control::flows_all(data_dir);
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        swept.read.retain(|s| pids.contains(&s.pid));
        swept.unread.retain(|(pid, _)| pids.contains(pid));
    }
    let context = pending_session_context(data_dir);
    (swept, context)
}

/// Render a flow's age compactly: `12s`, `3m04s`, `2h05m`.
fn format_flow_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Render the open-flow listing — a pure presenter (its layout is asserted in a test): the tunnels
/// open right now grouped under a per-session header (registry label + project), each a
/// `host:port  proto  age  ↑up ↓down` line. An empty listing says so and names what populates it.
/// `now_ms` is passed in (not read from the clock) so the age column is deterministic under test.
///
/// A session in `unread` was reached and did not answer in full. It is named at the foot of the
/// frame, and while one is, the frame never says no tunnel is open: that would read as a session
/// with nothing open.
fn render_live(
    sessions: &[sandbox::control::SessionFlows],
    unread: &[(u32, std::io::Error)],
    context: &[(u32, PathBuf, String)],
    app: Option<&str>,
    now_ms: u128,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions.iter().map(|s| s.flows.len()).sum();
    if total == 0 && unread.is_empty() {
        match app {
            Some(name) => {
                let _ = writeln!(
                    o,
                    "{h}open egress flows:{r} {}",
                    style::dim_prose(
                        &format!(
                            "(none for app `{name}` — its session(s) have no tunnel open right now)"
                        ),
                        pal
                    )
                );
            }
            None => {
                let _ = writeln!(
                    o,
                    "{h}open egress flows:{r} {dim}(none — no egress tunnel is open right now){r}"
                );
            }
        }
        return o;
    }
    let _ = writeln!(o, "{h}open egress flows:{r}");
    for session in sessions {
        if session.flows.is_empty() {
            continue;
        }
        // A per-session header from the registry, so with several agents the user can tell which one
        // each flow belongs to.
        write_session_header(&mut o, session.pid, context, pal);
        for f in &session.flows {
            // Age from the passed-in clock; saturate against any skew between the proxy and this reader
            // (a flow's start is never really in the future).
            let age = format_flow_age((now_ms.saturating_sub(f.start_epoch_ms) / 1000) as u64);
            let _ = writeln!(
                o,
                "    {n}{}:{}{r}  {}  {dim}{}{r}  {dim}↑{} ↓{}{r}",
                f.host,
                f.port,
                f.proto.as_str(),
                age,
                sandbox::human_bytes(f.up),
                sandbox::human_bytes(f.down),
            );
        }
    }
    write_unanswered(
        &mut o,
        unread,
        context,
        "its open flows are not in this frame",
        pal,
    );
    o
}

/// Emit one `sbx net live --json` snapshot object (the whole state this tick, NDJSON — one object per
/// line, not one per flow: a live view is a state, not an event stream). Each flow carries its session
/// context, destination, transport, age, and byte totals.
///
/// `unanswered` is always present, and lists each session that was reached this tick and did not
/// answer in full, with why, so an empty `flows` beside it is not read as nothing open there.
fn flush_live_json(
    out: &mut impl std::io::Write,
    sessions: &[sandbox::control::SessionFlows],
    unread: &[(u32, std::io::Error)],
    context: &[(u32, PathBuf, String)],
    now_ms: u128,
) -> std::io::Result<()> {
    let flows: Vec<_> = sessions
        .iter()
        .flat_map(|s| {
            let ctx = context.iter().find(|(p, _, _)| *p == s.pid);
            let project = ctx.map(|(_, p, _)| p.display().to_string());
            let label = ctx.map(|(_, _, l)| l.clone());
            s.flows.iter().map(move |f| {
                serde_json::json!({
                    "pid": s.pid,
                    "project": project,
                    "label": label,
                    "host": f.host,
                    "port": f.port,
                    "proto": f.proto.as_str(),
                    "age_ms": now_ms.saturating_sub(f.start_epoch_ms) as u64,
                    "up": f.up,
                    "down": f.down,
                })
            })
        })
        .collect();
    let unanswered: Vec<_> = unread
        .iter()
        .map(|(pid, e)| serde_json::json!({ "pid": pid, "error": e.to_string() }))
        .collect();
    let obj = serde_json::json!({ "flows": flows, "unanswered": unanswered });
    writeln!(out, "{obj}")?;
    out.flush()
}

/// `sbx net live [-i|--interval <secs>] [-a|--app <name>] [--json]`: show the egress tunnels open
/// right now — one line per flow (destination, transport, age, bytes each way) — redrawn in place on
/// an interval (default 1s) until interrupted. A `top`-style live view of the same control sockets
/// `sbx net logs` reads, but of *open connections* rather than *decided requests*. Because the proxy
/// closes each inspected L7 request after one response, short API calls flash by in under a second; the
/// durable rows are raw `tcp://` tunnels (SSH/DB), WebSockets, and large L7 transfers in progress.
/// Requires a terminal (the frame redraws in place); `--json` emits one snapshot object per tick and
/// works in a pipe. No launch / nix / network — it just polls the live control sockets.
pub(super) fn net_live(args: &[OsString]) -> ExitCode {
    use std::io::Write as _;
    let parsed = match parse_live_args(args) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    let is_tty = std::io::stdout().is_terminal();
    if !parsed.json && !is_tty {
        diag::error(
            "sbx: `net live` needs a terminal — use `--json` to script it (one snapshot per tick)",
        );
        return ExitCode::from(2);
    }
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let pal = style::Palette::for_stream(is_tty);
    let (dim, r) = (pal.dim, pal.reset);
    let secs = parsed.interval.as_secs();
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let (swept, context) = collect_flows(&data_dir, parsed.app.as_deref());
        // Build this tick's frame, then write it once — a broken downstream pipe (`… | head`) is
        // detected on the single write and ends the view cleanly (Rust ignores SIGPIPE).
        let mut out = std::io::stdout().lock();
        let wrote = if parsed.json {
            // One snapshot object per tick (NDJSON) — a live state, not a per-flow event stream.
            flush_live_json(&mut out, &swept.read, &swept.unread, &context, now_ms)
        } else {
            // `top`-style in-place redraw: home the cursor, paint the frame, then clear to end of
            // screen (keeps scrollback intact and erases a shorter frame's trailing lines).
            let body = render_live(
                &swept.read,
                &swept.unread,
                &context,
                parsed.app.as_deref(),
                now_ms,
                &pal,
            );
            write!(
                out,
                "\x1b[H{dim}live egress · refresh {secs}s · Ctrl-C to quit{r}\n{body}\x1b[J"
            )
            .and_then(|_| out.flush())
        };
        drop(out);
        if wrote.is_err() {
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(parsed.interval);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_live_args_defaults_and_overrides() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // No flags → the 1s default, no app scope, human output.
        let d = parse_live_args(&[]).expect("bare live parses");
        assert_eq!(d.interval, Duration::from_secs(1));
        assert!(d.app.is_none());
        assert!(!d.json);

        // Every flag, both spellings.
        let a = parse_live_args(&osv(&["-i", "3", "-a", "demo-app", "--json"])).unwrap();
        assert_eq!(a.interval, Duration::from_secs(3));
        assert_eq!(a.app.as_deref(), Some("demo-app"));
        assert!(a.json);
        let b = parse_live_args(&osv(&["--interval", "5", "--app", "demo-tool"])).unwrap();
        assert_eq!(b.interval, Duration::from_secs(5));
        assert_eq!(b.app.as_deref(), Some("demo-tool"));
        assert!(!b.json);
    }

    #[test]
    fn parse_live_args_rejects_bad_input() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(
            parse_live_args(&osv(&["-i", "0"])).is_err(),
            "zero interval busy-loops"
        );
        assert!(
            parse_live_args(&osv(&["-i", "soon"]))
                .unwrap_err()
                .contains("soon")
        );
        assert!(
            parse_live_args(&osv(&["-i"])).is_err(),
            "missing interval value"
        );
        assert!(parse_live_args(&osv(&["-a"])).is_err(), "missing app value");
        assert!(parse_live_args(&osv(&["--nope"])).is_err(), "unknown flag");
    }

    #[test]
    fn format_flow_age_is_compact() {
        assert_eq!(format_flow_age(5), "5s");
        assert_eq!(format_flow_age(59), "59s");
        assert_eq!(format_flow_age(64), "1m04s");
        assert_eq!(format_flow_age(3661), "1h01m");
    }

    #[test]
    fn render_live_groups_open_flows_by_session() {
        let pal = style::Palette::plain();
        let now_ms = 10_000u128;
        let sessions = vec![sandbox::control::SessionFlows {
            pid: 4242,
            flows: vec![
                sandbox::control::FlowSnapshot {
                    host: "api.test".into(),
                    port: 443,
                    proto: sandbox::control::Proto::Https,
                    start_epoch_ms: 7_000,
                    up: 1024,
                    down: 4096,
                },
                sandbox::control::FlowSnapshot {
                    host: "db.test".into(),
                    port: 5432,
                    proto: sandbox::control::Proto::Tcp,
                    start_epoch_ms: 4_000,
                    up: 500,
                    down: 500,
                },
            ],
        }];
        let ctx = vec![(
            4242u32,
            PathBuf::from("/home/u/proj"),
            "app:demo-app".to_string(),
        )];
        let out = render_live(&sessions, &[], &ctx, None, now_ms, &pal);
        assert!(out.contains("open egress flows:"), "header: {out}");
        assert!(
            out.contains("session 4242 [app:demo-app] /home/u/proj"),
            "session header: {out}"
        );
        assert!(out.contains("api.test:443"), "flow host:port shown: {out}");
        assert!(
            out.contains("https") && out.contains("tcp"),
            "protos shown: {out}"
        );
        assert!(out.contains("3s"), "age = (10000-7000)/1000 = 3s: {out}");
        assert!(
            out.contains('↑') && out.contains('↓'),
            "byte columns shown: {out}"
        );

        // An empty listing names what populates it, and an app filter names the app.
        let empty = render_live(&[], &[], &[], None, now_ms, &pal);
        assert!(empty.contains("no egress tunnel is open"), "empty: {empty}");
        let empty_app = render_live(&[], &[], &[], Some("demo-app"), now_ms, &pal);
        assert!(
            empty_app.contains("app `demo-app`"),
            "app-scoped empty: {empty_app}"
        );
    }

    /// A session reached that did not answer in full is named in the frame, under its own header,
    /// beside the sessions that did answer, and while one is, the frame does not say no tunnel is
    /// open. Left out, it read exactly like a session with nothing open.
    #[test]
    fn a_session_that_did_not_answer_is_named_in_the_frame() {
        let pal = style::Palette::plain();
        let unread = || {
            vec![(
                5151u32,
                std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            )]
        };
        let ctx = vec![(
            5151u32,
            PathBuf::from("/home/u/other"),
            "app:demo-tool".to_string(),
        )];

        for app in [None, Some("demo-tool")] {
            let alone = render_live(&[], &unread(), &ctx, app, 10_000, &pal);
            assert!(
                alone.contains("session 5151 [app:demo-tool] /home/u/other"),
                "{app:?}: under its own header: {alone}"
            );
            assert!(
                alone.contains("did not answer in full")
                    && alone.contains("its open flows are not in this frame"),
                "{app:?}: named, with what is missing: {alone}"
            );
            assert!(!alone.contains("none"), "{app:?}: no empty claim: {alone}");
        }

        let answered = vec![sandbox::control::SessionFlows {
            pid: 4242,
            flows: vec![sandbox::control::FlowSnapshot {
                host: "api.test".into(),
                port: 443,
                proto: sandbox::control::Proto::Https,
                start_epoch_ms: 7_000,
                up: 1,
                down: 1,
            }],
        }];
        let both = render_live(&answered, &unread(), &ctx, None, 10_000, &pal);
        assert!(both.contains("api.test:443"), "the answer is shown: {both}");
        assert!(
            both.contains("session 5151") && both.contains("did not answer in full"),
            "and the silent session is named beside it: {both}"
        );
    }

    /// Every `--json` snapshot carries `unanswered`, empty when every session answered, so a
    /// consumer reads an empty `flows` beside a session that did not answer for what it is.
    #[test]
    fn a_json_snapshot_names_the_sessions_that_did_not_answer() {
        let snapshot = |unread: &[(u32, std::io::Error)]| {
            let mut out = Vec::new();
            flush_live_json(&mut out, &[], unread, &[], 0).expect("write the snapshot");
            serde_json::from_slice::<serde_json::Value>(&out).expect("one JSON object")
        };
        let quiet = snapshot(&[]);
        assert_eq!(quiet["unanswered"], serde_json::json!([]), "{quiet}");
        let named = snapshot(&[(
            5151,
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        )]);
        assert_eq!(named["unanswered"][0]["pid"], 5151, "{named}");
        assert!(
            named["unanswered"][0]["error"]
                .as_str()
                .is_some_and(|e| !e.is_empty()),
            "why it did not answer: {named}"
        );
        assert_eq!(named["flows"], serde_json::json!([]), "{named}");
    }
}
