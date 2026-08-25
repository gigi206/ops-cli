//! `sbx net` — inspect and manage the per-project egress allowlist and the live
//! network control plane.
//!
//! Handlers for `net rules/groups/allow/deny/mute/unmute/pending/stats/logs/live`,
//! their argument parsers and view models, and the whole egress-observability
//! rendering layer (pending prompts, live flows, the log stream, rule/group tables,
//! and drain/stats summaries). Cross-cutting domain and plumbing helpers — session
//! record readers (`session_pids_*`, `pending_session_context`), the shared egress
//! writers (`persist_egress_rule`, `egress_write_target`), the rule-write admission and its
//! local-save trust gate (`open_rule_write`/`precheck_local_save`), and formatting shared with other
//! families (`format_log_time`, `net_mode_word`, `short_rev`) — stay at the crate root
//! and are reached from here via `crate::`.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::{
    RuleWrite, egress_data_dir, egress_write_target, fold_app_overlay, format_log_time,
    interval_seconds, net_mode_word, open_rule_write, pending_session_context, persist_egress_rule,
    precheck_local_save, session_app_of, session_pids_for_app, session_pids_for_project,
    split_one_rule, split_scope, split_session_flags,
};
use crate::{allowlist, config, diag, help, sandbox, style, trust};

/// `sbx net <subcommand>`: the interactive-egress namespace. `rules` lists the effective egress
/// rules (optionally for one app), `allow`/`deny` persist a rule to a config file, `pending`
/// drives the live `ask`-posture control plane, and `stats` reports the per-host allow/deny/blocked
/// decision counters a launch recorded. Distinct from `sbx test net <url>` (the URL matcher): `net`
/// is the listing/management surface.
pub(crate) fn net_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("rules") => net_rules(&args[1..]),
        Some("groups") => net_groups(&args[1..]),
        // Each rule list is added to and taken back out with one vocabulary, so undoing a rule never
        // means dropping to the schema key it was written under. The removal verbs are config-only:
        // an `--session` overlay rule cannot be un-loaded (the control plane injects, it does not
        // retract), so it dies with the session instead.
        Some("allow") => net_add_rule(config::manage::EgressList::Allow, &args[1..]),
        Some("unallow") => net_remove_rule(config::manage::EgressList::Allow, &args[1..]),
        Some("deny") => net_add_rule(config::manage::EgressList::Deny, &args[1..]),
        Some("undeny") => net_remove_rule(config::manage::EgressList::Deny, &args[1..]),
        // `mute` adds a `dontaudit` log-suppression rule; `unmute` removes one. Both are
        // config-level (the same scopes as allow/deny) — a live `--session` mute is not yet wired.
        Some("mute") => net_add_rule(config::manage::EgressList::Mute, &args[1..]),
        Some("unmute") => net_remove_rule(config::manage::EgressList::Mute, &args[1..]),
        Some("pending") => net_pending(&args[1..]),
        Some("stats") => net_stats(&args[1..]),
        // `log` is an accepted alias for `logs` so a typo does not error.
        Some("logs") | Some("log") => net_logs(&args[1..]),
        // `live` is the real-time view of the tunnels *currently open*, distinct from the decided
        // requests `logs` records.
        Some("live") => net_live(&args[1..]),
        // Unknown or no subcommand: name the mistake (if any), then print the full page — its
        // Subcommands list reveals rules/allow/deny/pending/… instead of a bare one-line synopsis,
        // the way `sbx config` and bare `sbx` guide.
        other => {
            if let Some(tok) = other {
                diag::error(&format!("sbx: net: unknown subcommand {tok:?}"));
            }
            eprint!("{}", help::page_usage(&["net"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `sbx net pending` family — the live control plane for the `ask` egress posture (see
/// [`sandbox::control`]). With no verb it lists the requests parked across every reachable ask-mode
/// session; `allow <id>`/`deny <id>` answer one (`<id>` = `<pid>.<seq>` from the listing or the
/// launch's notice), optionally persisting a matching rule with `--save` + a scope. The control
/// sockets live under `<data>/egress`, never inside any cage.
fn net_pending(args: &[OsString]) -> ExitCode {
    use sandbox::control::Verdict;
    match args.first().and_then(|a| a.to_str()) {
        Some("allow") => net_pending_answer(Verdict::Allow, &args[1..]),
        Some("deny") => net_pending_answer(Verdict::Deny, &args[1..]),
        Some("watch") => net_pending_watch(&args[1..]),
        // No verb (or `--json`): list the pending requests.
        _ => net_pending_list(args),
    }
}

/// Query the live control sockets for the parked requests, scoped to one app's session(s) when
/// `app` is set, and pair them with their registry context (`(pid, project, label)`). The shared
/// gather step behind both the one-shot listing and the `watch` loop. No launch / nix / network.
fn collect_pending(
    data_dir: &Path,
    app: Option<&str>,
) -> (
    Vec<sandbox::control::SessionPending>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut sessions = sandbox::control::list_all(data_dir);
    // `--app <name>` scopes the listing to that app's session(s) (the registry maps pid → app).
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        sessions.retain(|s| pids.contains(&s.pid));
    }
    let context = pending_session_context(data_dir);
    (sessions, context)
}

/// The rule string that matches the destination just answered, port included. A host-level rule
/// carries a **port set**, and a bare host is the HTTPS default — port 443 and nothing else — so
/// saving the bare host for a request answered on 8443 writes a rule that can never match the
/// request it was saved for. The shaping is the one `netlearn` gives its rule candidates: 443 is the
/// bare host (the shortest rule that means the same thing), 80 is the cleartext scheme (a `:80` on
/// an implicitly-TLS host would name the right port at the wrong layer), and any other port is
/// pinned explicitly.
///
/// `None` — the parked row could not be read back before the answer landed — keeps the bare host:
/// the previous behaviour, and still right for the port almost every ask is on.
fn egress_rule_for(host: &str, port: Option<u16>) -> String {
    match port {
        None | Some(443) => host.to_string(),
        Some(80) => format!("http://{host}"),
        // An IPv6 literal is bracketed only when it carries a port — bare otherwise — so the
        // brackets go on here rather than in the caller.
        Some(p) if host.contains(':') && !host.starts_with('[') => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
    }
}

/// The port one parked request is waiting on, or `None` when it is no longer parked (already
/// answered, or timed out) or its session cannot be reached. Read from the same `LIST` the listing
/// uses, so it sees exactly what `sbx net pending` would show.
fn pending_port(data_dir: &Path, pid: u32, seq: u64) -> Option<u16> {
    sandbox::control::list_all(data_dir)
        .into_iter()
        .find(|s| s.pid == pid)?
        .rows
        .into_iter()
        .find(|r| r.seq == seq)
        .map(|r| r.port)
}

/// `sbx net pending [-a|--app <name>] [--json]`: list every reachable ask-mode session's parked
/// requests, grouped by session (with its agent/project context); identical retries of one URL
/// collapse to a single destination carrying the `<pid>.<seq>` id to answer it (and, in `--json`, a
/// `count`). `--app <name>` limits the listing to that app's session(s). No launch / nix / network —
/// it just queries the live control sockets. An empty result is a clean success (nothing is waiting).
fn net_pending_list(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut app: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("--json") => json = true,
            Some("--app") | Some("-a") => match it.next() {
                Some(name) => app = Some(name.to_string_lossy().into_owned()),
                None => {
                    diag::error("sbx: `--app` needs an app name");
                    return ExitCode::from(2);
                }
            },
            _ => {
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "pending"])
                ));
                return ExitCode::from(2);
            }
        }
    }
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let (sessions, context) = collect_pending(&data_dir, app.as_deref());
    let ctx_of = |pid: u32| context.iter().find(|(p, _, _)| *p == pid);

    if json {
        // Grouped like the human listing — one object per destination, not per connection — because
        // `allow <id>` now answers the whole destination: exposing every individually-addressable seq
        // would mislead a consumer into per-seq answering (the first answers the group, the rest are
        // NotFound). `count` carries how many connections collapsed; `id` is the representative.
        let rows: Vec<_> = sessions
            .iter()
            .flat_map(|s| {
                let ctx = ctx_of(s.pid);
                let project = ctx.map(|(_, p, _)| p.display().to_string());
                let label = ctx.map(|(_, _, l)| l.clone());
                group_pending(&s.rows)
                    .into_iter()
                    .map(move |g| {
                        serde_json::json!({
                            "id": sandbox::control::format_id(s.pid, g.seq),
                            "pid": s.pid,
                            "project": project,
                            "label": label,
                            "host": g.host,
                            "port": g.port,
                            "path": g.path,
                            "count": g.count,
                            "waiting_secs": g.waiting_secs,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        println!("{}", serde_json::json!({ "pending": rows }));
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_pending(&sessions, &context, app.as_deref(), &pal)
    );
    ExitCode::SUCCESS
}

/// The parsed `sbx net pending watch` flags: how often to refresh, and an optional app scope.
#[derive(Debug)]
struct WatchArgs {
    interval: Duration,
    app: Option<String>,
}

/// Parse `watch [-i|--interval <secs>] [-a|--app <name>]`. Pure (no I/O), so every reject path is
/// unit-testable without a terminal or entering the loop: a missing value, a non-numeric or zero
/// interval, or an unknown flag is an error. The refresh defaults to 2 seconds.
fn parse_watch_args(args: &[OsString]) -> Result<WatchArgs, String> {
    let mut interval_secs: u64 = 2;
    let mut app: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.to_str() {
            Some("-i") | Some("--interval") => interval_secs = interval_seconds(it.next())?,
            Some("-a") | Some("--app") => {
                let name = it.next().ok_or("`--app` needs an app name")?;
                app = Some(name.to_string_lossy().into_owned());
            }
            _ => {
                return Err(format!(
                    "usage: {}",
                    help::synopsis_of(&["net", "pending", "watch"])
                ));
            }
        }
    }
    Ok(WatchArgs {
        interval: Duration::from_secs(interval_secs),
        app,
    })
}

/// `sbx net pending watch [-i|--interval <secs>] [-a|--app <name>]`: redraw the parked-request
/// listing in place on an interval (default 2s) until interrupted. A `top`-style poll of the same
/// live control sockets `sbx net pending` queries — no launch, nix, or network, and nothing is held
/// open between ticks. Requires a terminal (the frame is redrawn in place); the one-shot listing
/// (optionally `--json`) is the path for a pipe or a script.
fn net_pending_watch(args: &[OsString]) -> ExitCode {
    use std::io::Write as _;
    let parsed = match parse_watch_args(args) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    let is_tty = std::io::stdout().is_terminal();
    if !is_tty {
        diag::error(
            "sbx: `watch` needs a terminal — use `sbx net pending` for a one-shot listing, \
             or `--json` to script it",
        );
        return ExitCode::from(2);
    }
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(is_tty);
    let (dim, r) = (pal.dim, pal.reset);
    let secs = parsed.interval.as_secs();
    loop {
        let (sessions, context) = collect_pending(&data_dir, parsed.app.as_deref());
        let body = render_pending(&sessions, &context, parsed.app.as_deref(), &pal);
        // `top`-style in-place redraw: home the cursor, paint the frame, then clear from the cursor to
        // the end of the screen. This keeps the terminal scrollback intact (unlike `\x1b[3J`) and
        // erases any trailing lines a shorter frame leaves behind, with no full-screen blank flicker.
        // Interrupting mid-watch just leaves the last frame on screen — no cleanup is owed.
        let mut out = std::io::stdout().lock();
        let _ = write!(
            out,
            "\x1b[H{dim}watching · refresh {secs}s · Ctrl-C to quit{r}\n{body}\x1b[J"
        );
        let _ = out.flush();
        std::thread::sleep(parsed.interval);
    }
}

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
                let name = it.next().ok_or("`--app` needs an app name")?;
                app = Some(name.to_string_lossy().into_owned());
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
fn collect_flows(
    data_dir: &Path,
    app: Option<&str>,
) -> (
    Vec<sandbox::control::SessionFlows>,
    Vec<(u32, PathBuf, String)>,
) {
    let mut sessions = sandbox::control::flows_all(data_dir);
    if let Some(name) = app {
        let pids = session_pids_for_app(data_dir, name);
        sessions.retain(|s| pids.contains(&s.pid));
    }
    let context = pending_session_context(data_dir);
    (sessions, context)
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
fn render_live(
    sessions: &[sandbox::control::SessionFlows],
    context: &[(u32, PathBuf, String)],
    app: Option<&str>,
    now_ms: u128,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions.iter().map(|s| s.flows.len()).sum();
    if total == 0 {
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
    o
}

/// Emit one `sbx net live --json` snapshot object (the whole state this tick, NDJSON — one object per
/// line, not one per flow: a live view is a state, not an event stream). Each flow carries its session
/// context, destination, transport, age, and byte totals.
fn flush_live_json(
    out: &mut impl std::io::Write,
    sessions: &[sandbox::control::SessionFlows],
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
    let obj = serde_json::json!({ "flows": flows });
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
fn net_live(args: &[OsString]) -> ExitCode {
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
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(is_tty);
    let (dim, r) = (pal.dim, pal.reset);
    let secs = parsed.interval.as_secs();
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let (sessions, context) = collect_flows(&data_dir, parsed.app.as_deref());
        // Build this tick's frame, then write it once — a broken downstream pipe (`… | head`) is
        // detected on the single write and ends the view cleanly (Rust ignores SIGPIPE).
        let mut out = std::io::stdout().lock();
        let wrote = if parsed.json {
            // One snapshot object per tick (NDJSON) — a live state, not a per-flow event stream.
            flush_live_json(&mut out, &sessions, &context, now_ms)
        } else {
            // `top`-style in-place redraw: home the cursor, paint the frame, then clear to end of
            // screen (keeps scrollback intact and erases a shorter frame's trailing lines).
            let body = render_live(&sessions, &context, parsed.app.as_deref(), now_ms, &pal);
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

/// One collapsed group of identical pending requests (same `host:port/path`): the representative id
/// (the lowest seq — the id to answer, which wakes the whole group), how many were collapsed, and the
/// longest wait (the oldest still parked).
struct PendingGroup<'a> {
    seq: u64,
    host: &'a str,
    port: u16,
    path: &'a str,
    count: usize,
    waiting_secs: u64,
}

/// Collapse a session's parked requests by destination, preserving first-seen (lowest-seq) order. A
/// tool that retries one URL re-parks it many times; those are a single decision, so the listing
/// shows one line per destination rather than one per connection.
fn group_pending(rows: &[sandbox::control::PendingRow]) -> Vec<PendingGroup<'_>> {
    let mut groups: Vec<PendingGroup> = Vec::new();
    for row in rows {
        match groups
            .iter_mut()
            .find(|g| g.host == row.host && g.port == row.port && g.path == row.path)
        {
            Some(g) => {
                g.count += 1;
                g.seq = g.seq.min(row.seq);
                g.waiting_secs = g.waiting_secs.max(row.waiting_secs);
            }
            None => groups.push(PendingGroup {
                seq: row.seq,
                host: &row.host,
                port: row.port,
                path: &row.path,
                count: 1,
                waiting_secs: row.waiting_secs,
            }),
        }
    }
    groups
}

/// Render the pending-request listing — a pure presenter (its colored layout is asserted in a test):
/// the parked requests grouped under a per-session header (the registry label + project, so several
/// sessions are told apart), each destination a `<pid>.<seq>` id, target, and wait time. Identical
/// retries of one URL collapse to a single `×N` line. An empty listing says so and points at how
/// requests arrive (an `ask`-posture launch); under an `--app` filter it names the app, so an empty
/// result is not mistaken for "nothing parked anywhere" when other apps do have requests.
fn render_pending(
    sessions: &[sandbox::control::SessionPending],
    context: &[(u32, PathBuf, String)],
    app: Option<&str>,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = sessions.iter().map(|s| s.rows.len()).sum();
    if total == 0 {
        match app {
            Some(name) => {
                let _ = writeln!(
                    o,
                    "{h}pending egress requests:{r} {}",
                    style::dim_prose(
                        &format!(
                            "(none for app `{name}` — nothing parked in its `ask`-mode session(s))"
                        ),
                        pal
                    )
                );
            }
            None => {
                let _ = writeln!(
                    o,
                    "{h}pending egress requests:{r} {}",
                    style::dim_prose(
                        "(none — a request parks here only under `[network] mode = \"ask\"`)",
                        pal
                    )
                );
            }
        }
        return o;
    }
    let _ = writeln!(o, "{h}pending egress requests:{r}");
    for session in sessions {
        // A per-session header from the registry, so with several agents the user can tell which one
        // each request belongs to (the literal reason the control plane is multi-session).
        write_session_header(&mut o, session.pid, context, pal);
        // Collapse identical destinations: a tool that retries one URL re-parks it many times, and
        // they are a single decision. `×N` is itself a signal — an agent hammering one endpoint.
        for group in group_pending(&session.rows) {
            let id = sandbox::control::format_id(session.pid, group.seq);
            let times = if group.count > 1 {
                format!("×{}, ", group.count)
            } else {
                String::new()
            };
            let _ = writeln!(
                o,
                "    {n}{id}{r}  {}:{}{}  {dim}({times}waiting {}s){r}",
                group.host, group.port, group.path, group.waiting_secs
            );
        }
    }
    let _ = writeln!(
        o,
        "  {dim}answer: sbx net pending allow <id> [--save --local|--global|--app <name>]{r}"
    );
    let _ = writeln!(
        o,
        "  {dim}        sbx net pending allow|deny --all  (drain every parked request at once){r}"
    );
    o
}

/// Answer every parked request in each session `keep` accepts, and report what happened.
///
/// Returns the hosts answered per session (in `session_pids` order, sessions with nothing parked
/// omitted) and the pids of sessions running an sbx too old to understand the command — those keep
/// their requests parked, so they are named rather than folded into a misleading "nothing parked".
/// A dead or stale socket is a session that went away and is skipped.
///
/// `keep` is evaluated **before** the drain, never after: this writes, and answering a parked
/// request cannot be undone, so a session the caller meant to skip must not be drained first and
/// filtered afterwards. Written once for that reason — `sbx net pending allow/deny` and the
/// drain-and-save path differ only in which scopes they compose into `keep`.
fn drain_sessions(
    data_dir: &Path,
    verdict: sandbox::control::Verdict,
    session: bool,
    keep: impl Fn(u32) -> bool,
) -> (Vec<(u32, Vec<String>)>, Vec<u32>) {
    let mut answered: Vec<(u32, Vec<String>)> = Vec::new();
    let mut unsupported: Vec<u32> = Vec::new();
    for pid in sandbox::control::session_pids(data_dir) {
        if !keep(pid) {
            continue;
        }
        match sandbox::control::drain_session(data_dir, pid, verdict, session) {
            Ok(sandbox::control::DrainOutcome::Drained(hosts)) if !hosts.is_empty() => {
                answered.push((pid, hosts))
            }
            Ok(sandbox::control::DrainOutcome::Drained(_)) => {}
            Ok(sandbox::control::DrainOutcome::Unsupported) => unsupported.push(pid),
            Err(_) => {}
        }
    }
    (answered, unsupported)
}

/// One session's header line: `session <pid> [<agent>] <project>`, or `session <pid>
/// (unregistered)` when the registry does not know it.
///
/// Every `sbx net` listing that spans sessions prints this line, and it must read the same in all
/// of them — it is what tells the user which agent a flow, a parked request or a grant belongs to,
/// which is the literal reason the control plane is multi-session. Written once so the six listings
/// cannot come to disagree about the shape of the identifier they share.
fn write_session_header_line(
    o: &mut String,
    pid: u32,
    ctx: Option<(&str, &str)>,
    pal: &style::Palette,
) {
    use std::fmt::Write as _;
    let (dim, r) = (pal.dim, pal.reset);
    match ctx {
        Some((label, project)) => {
            let _ = writeln!(o, "  {dim}session {pid} [{label}] {project}{r}");
        }
        None => {
            let _ = writeln!(o, "  {dim}session {pid} (unregistered){r}");
        }
    }
}

/// [`write_session_header_line`] for a caller holding the registry snapshot rather than an
/// already-resolved entry: the pid is looked up in `context`, and an absent one reads as
/// unregistered.
fn write_session_header(
    o: &mut String,
    pid: u32,
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) {
    let found = context.iter().find(|(p, _, _)| *p == pid);
    let project = found.map(|(_, project, _)| project.display().to_string());
    write_session_header_line(
        o,
        pid,
        match (&found, &project) {
            (Some((_, _, label)), Some(project)) => Some((label.as_str(), project.as_str())),
            _ => None,
        },
        pal,
    );
}

/// `sbx net pending allow|deny <id> [--save --local|--global|--app <name>]`: answer one parked
/// request live. The unblock is the primary action; `--save` additionally persists a matching rule
/// (the request's host) through the shared writer so the same host is pre-decided next launch — a
/// secondary step whose failure is a warning, never undoing the answer. `<id>` is `<pid>.<seq>`.
fn net_pending_answer(verdict: sandbox::control::Verdict, args: &[OsString]) -> ExitCode {
    use config::manage::EgressList;
    let verb = match verdict {
        sandbox::control::Verdict::Allow => "allow",
        sandbox::control::Verdict::Deny => "deny",
    };
    // `--all`, `--save` and `--session` are extracted before `split_scope`, which rejects any flag
    // it does not know. The id is the lone positional; the scope flags (--local/--global/--app) ride
    // `split_scope` and apply only with `--save`. `--session` remembers the decision for the live
    // session (no config write); the two combine.
    let all = args.iter().any(|a| a.to_str() == Some("--all"));
    let save = args.iter().any(|a| a.to_str() == Some("--save"));
    let session = args.iter().any(|a| a.to_str() == Some("--session"));
    let rest: Vec<OsString> = args
        .iter()
        .filter(|a| {
            !matches!(
                a.to_str(),
                Some("--save") | Some("--session") | Some("--all")
            )
        })
        .cloned()
        .collect();

    // `--all` drains every parked request across every reachable session (or, with `--app <name>`,
    // that one app's session(s)). With `--save` it also persists a rule per answered host; the drain
    // is then scoped to match the save target — `--local` (the default) writes the *current project's*
    // config and so restricts the drain to that project, which is what makes a bulk local save
    // unambiguous (it can never answer one project's requests into another's config). Without `--save`,
    // a scope flag is meaningless (there is no file to write), so it is refused.
    if all {
        let parsed = match split_scope(&rest) {
            Ok(p) => p,
            Err(e) => {
                diag::error(&format!("sbx: {e}"));
                return ExitCode::from(2);
            }
        };
        if !parsed.positionals.is_empty() {
            diag::error(
                "sbx: `--all` answers every parked request and takes no id \
                 (use `--app <name>` to limit it to one app; `--session` to remember)",
            );
            return ExitCode::from(2);
        }
        if save {
            return net_pending_drain_and_save(
                verdict,
                session,
                &parsed.scope,
                parsed.app.as_deref(),
            );
        }
        if parsed.scope_explicit {
            diag::error(
                "sbx: `--all` without `--save` takes no scope (--local/--global/-c) — add `--save` \
                 to persist a rule per host, or use `--app <name>` to limit the drain to one app",
            );
            return ExitCode::from(2);
        }
        return net_pending_answer_all(verdict, session, parsed.app.as_deref());
    }
    let parsed = match split_scope(&rest) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::from(2);
        }
    };
    let id = match parsed.positionals.as_slice() {
        [id] => id.as_str(),
        _ => {
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["net", "pending", verb])
            ));
            return ExitCode::from(2);
        }
    };
    let Some((pid, seq)) = sandbox::control::parse_id(id) else {
        diag::error(&format!(
            "sbx: invalid pending id '{id}' (expected <pid>.<seq>, e.g. 12345.1)"
        ));
        return ExitCode::from(2);
    };
    // A *config* scope (--global / -c) without `--save` is meaningless — there is no rule to write, so
    // flag it rather than silently ignore it. `--local` is the `split_scope` default, so a bare oneshot
    // does not trip it. `--app` is deliberately *not* here: it doubles as a session scope, so it is
    // honored without `--save` too (a natural carry-over from `sbx net pending -a <app>`) and validated
    // against the id below.
    if !save && !matches!(parsed.scope, config::manage::Scope::Local) {
        diag::error(
            "sbx: --global/-c only applies with --save (it names where to persist the rule)",
        );
        return ExitCode::from(2);
    }

    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // `--app <name>` on the by-id path asserts the id belongs to that app. The id already names the
    // exact session, so this is a consistency check, not a filter: if the registry knows this session
    // as a *different* app, the assertion is wrong → flag it (and, with `--save`, the save would land
    // in the wrong app's config). An unregistered session or a plain shell (no known app) is given the
    // benefit of the doubt — the id is authoritative.
    if let Some(name) = parsed.app.as_deref()
        && let Some(actual) = session_app_of(&data_dir, pid)
        && actual != name
    {
        diag::error(&format!(
            "sbx: {id} is a session of app `{actual}`, not `{name}`"
        ));
        return ExitCode::from(2);
    }
    // With `--save`, the port has to be read **before** the answer: the parked row carries it and is
    // gone from the queue the moment the answer lands, while the reply names only the host. A rule
    // saved without it means port 443 alone — see [`egress_rule_for`].
    let port = save.then(|| pending_port(&data_dir, pid, seq)).flatten();
    let (host, count) = match sandbox::control::answer_request(
        &data_dir, pid, seq, verdict, session,
    ) {
        Ok(sandbox::control::AnswerOutcome::Answered { host, count }) => (host, count),
        Ok(sandbox::control::AnswerOutcome::NotFound) => {
            diag::error(&format!(
                "sbx: no pending request '{id}' (it may have been answered already or timed out)"
            ));
            return ExitCode::from(2);
        }
        Err(_) => {
            diag::error(&format!(
                "sbx: no live session for '{id}' (the launch may have ended, or its socket is \
                 stale)"
            ));
            return ExitCode::from(2);
        }
    };
    // `<id>` names one parked request, but identical retries of the same URL collapse to one decision
    // — so the answer may have woken several. `×N` mirrors the grouped listing.
    let times = if count > 1 {
        format!(" (×{count})")
    } else {
        String::new()
    };
    if session {
        println!("{verb}ed {host}{times} for {id} (remembered for this session)");
    } else {
        println!("{verb}ed {host}{times} for {id}");
    }

    // `--save` persists a matching rule (the host) so the same destination is pre-decided next
    // launch: an allow becomes an allow rule, a deny a deny rule. The live answer already stuck, so
    // a save failure is a warning, never a hard failure that would imply the answer was undone.
    if save {
        let list = match verdict {
            sandbox::control::Verdict::Allow => EgressList::Allow,
            sandbox::control::Verdict::Deny => EgressList::Deny,
        };
        // Resolve a `--local` save against the *answered session's* project (from the registry), not
        // the cwd — the rule belongs in the project the agent runs in, which may not be where the
        // user is standing. Fall back to the cwd if the session is not in the registry.
        let base = pending_session_context(&data_dir)
            .into_iter()
            .find(|(p, _, _)| *p == pid)
            .map(|(_, project, _)| project)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let rule = egress_rule_for(&host, port);
        match persist_egress_rule(list, &rule, &parsed.scope, parsed.app.as_deref(), &base) {
            Ok(message) => println!(
                "{}",
                style::prose(
                    &message,
                    &style::Palette::for_stream(std::io::stdout().is_terminal())
                )
            ),
            Err((_, message)) => {
                diag::warn(&format!("answered, but could not save the rule: {message}"));
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// `sbx net pending allow|deny --all [-a|--app <name>] [--session]`: drain every parked request
/// across every reachable ask-mode session in one shot — or, with `--app <name>`, only that app's
/// session(s). A point-in-time bulk answer — a request that parks *after* the drain still waits. It
/// reports per session what it answered, so a cross-agent grant (one keystroke can open egress for
/// several agents at once) is visible rather than a silent aggregate count. `--session` remembers
/// each answered host for its session. A session that vanished between the socket glob and the drain
/// is skipped (best-effort, mirroring the listing).
fn net_pending_answer_all(
    verdict: sandbox::control::Verdict,
    session: bool,
    app: Option<&str>,
) -> ExitCode {
    let past = match verdict {
        sandbox::control::Verdict::Allow => "allowed",
        sandbox::control::Verdict::Deny => "denied",
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let context = pending_session_context(&data_dir);
    // `--app <name>` scopes the drain to that app's session pids (from the registry); an unregistered
    // session has no known app, so it is excluded under a filter.
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));
    let (answered, unsupported) = drain_sessions(&data_dir, verdict, session, |pid| {
        app_pids.as_ref().is_none_or(|pids| pids.contains(&pid))
    });
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_drain(past, session, app, &answered, &unsupported, &context, &pal)
    );
    ExitCode::SUCCESS
}

/// Collapse a session's answered-host list — one entry per parked request, so a host repeats once per
/// request — into first-seen order paired with an occurrence count. A burst of retries (or several
/// paths) to one destination then reads as a single `host ×N` line instead of N identical lines. The
/// fold is host-granular: the drain wire format carries only `answered host=`, so distinct paths and
/// plain retries to the same host both add to the one count.
fn collapse_hosts(hosts: &[String]) -> Vec<(&str, usize)> {
    let mut order: Vec<(&str, usize)> = Vec::new();
    for host in hosts {
        match order.iter_mut().find(|(h, _)| *h == host.as_str()) {
            Some(entry) => entry.1 += 1,
            None => order.push((host.as_str(), 1)),
        }
    }
    order
}

/// Render a bulk `--all` drain: a per-session breakdown of the hosts it answered (so the user sees
/// exactly what was granted/refused, across which agents), then a total. An empty drain says nothing
/// was parked (naming the `--app` filter when one narrowed the scope, so an empty result is not
/// mistaken for "nothing anywhere"). A pure presenter — its palette comes from the caller (plain on a
/// captured stream).
fn render_drain(
    past: &str,
    session: bool,
    app: Option<&str>,
    answered: &[(u32, Vec<String>)],
    unsupported: &[u32],
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let total: usize = answered.iter().map(|(_, hosts)| hosts.len()).sum();
    if total == 0 {
        // Nothing answered. Distinguish "every session is healthy but empty" from "the only sessions
        // present were launched by an older sbx that does not understand `--all`" — the latter would
        // otherwise read as "nothing parked" while requests are in fact still blocked.
        if unsupported.is_empty() {
            match app {
                Some(name) => {
                    let _ = writeln!(
                        o,
                        "{}",
                        style::dim_prose(
                            &format!(
                                "no pending requests for app `{name}` (nothing parked in its \
                                 ask-mode session(s))"
                            ),
                            pal
                        )
                    );
                }
                None => {
                    let _ = writeln!(
                        o,
                        "{dim}no pending requests (nothing parked across any ask-mode session){r}"
                    );
                }
            }
        }
        write_unsupported_note(&mut o, unsupported, pal);
        return o;
    }
    let _ = writeln!(o, "{h}{past} {total} parked request(s):{r}");
    for (pid, hosts) in answered {
        // A per-session header from the registry, so with several agents the user can tell which one
        // each grant belongs to — the cross-agent reach made visible, not silent.
        write_session_header(&mut o, *pid, context, pal);
        // One parked request emits one host, so a burst of retries (or several paths) to one
        // destination would print that host once per request. Fold the repeats into `host ×N`.
        for (host, count) in collapse_hosts(hosts) {
            if count > 1 {
                let _ = writeln!(o, "    {n}{host}{r} {dim}×{count}{r}");
            } else {
                let _ = writeln!(o, "    {n}{host}{r}");
            }
        }
    }
    if session {
        let _ = writeln!(o, "  {dim}(remembered for each session — not re-asked){r}");
    }
    write_unsupported_note(&mut o, unsupported, pal);
    o
}

/// Append the older-session warning to a drain report: name the sessions whose control server is too
/// old to understand `--all`, and point at the only fix (relaunch the agent). Answering their requests
/// by id is deliberately *not* offered — destination grouping is server-side, so an old server's
/// `ALLOW <seq>` wakes one connection of a retried group and leaves the rest blocked.
fn write_unsupported_note(o: &mut String, unsupported: &[u32], pal: &style::Palette) {
    use std::fmt::Write as _;
    if unsupported.is_empty() {
        return;
    }
    let (warn, r) = (pal.warn, pal.reset);
    let pids = unsupported
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        o,
        "{}",
        style::paint_spans(
            &format!(
                "{warn}session(s) {pids} were launched by an older sbx without `--all` support — \
                 their parked requests stay blocked.{r}"
            ),
            pal.code,
            pal.warn,
            pal
        )
    );
    let _ = writeln!(
        o,
        "  {}",
        style::dim_prose(
            "relaunch the agent with the current sbx to drain them in bulk.",
            pal
        )
    );
}

/// `sbx net stats [--app <name>] [--reset] [--json]`: report the per-host egress decision counters a
/// project's launches recorded — how often each destination was allowed, denied by a rule, or
/// stopped by a security guard (SSRF, an outbound-secret tripwire, a domain-fronting mismatch).
/// Read-only and host-side: it aggregates the session files under `<data>/egress`, with no launch,
/// nix, or network. `--reset` clears this project's recorded files instead.
fn net_stats(args: &[OsString]) -> ExitCode {
    let mut app: Option<String> = None;
    let mut reset = false;
    let mut json = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--reset") => reset = true,
            Some("--app") | Some("-a") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: net stats: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(v.to_string());
            }
            _ => {
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "stats"])
                ));
                return ExitCode::from(2);
            }
        }
    }
    // `--reset` reports how many files it cleared; pairing it with `--json` is meaningless — flag it
    // rather than silently pick one.
    if reset && json {
        diag::error("sbx: net stats: `--reset` does not combine with `--json`");
        return ExitCode::from(2);
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // The canonical project identity is exactly what `egress::start` writes into each session file's
    // `project=` header, so a read here matches what a launch recorded — no canonicalization drift.
    let project = match sandbox::project_identity(&cwd) {
        Ok((_, canon)) => canon.display().to_string(),
        Err(e) => {
            diag::error(&format!("sbx: cannot resolve the project directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let egress_dir = match egress_data_dir() {
        Ok(d) => d.join("egress"),
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };

    if reset {
        let n = sandbox::egress_stats::reset(&egress_dir, &project, app.as_deref());
        let scope = app
            .as_ref()
            .map(|a| format!(" for app {a}"))
            .unwrap_or_default();
        println!("reset {n} egress stat file(s){scope}");
        return ExitCode::SUCCESS;
    }

    let tally = sandbox::egress_stats::aggregate(&egress_dir, &project, app.as_deref());
    if json {
        let rows: Vec<_> = tally
            .hosts
            .iter()
            .map(|(host, c)| {
                serde_json::json!({
                    "host": host,
                    "allow": c.allow,
                    "deny": c.deny,
                    "blocked": c.blocked,
                })
            })
            .collect();
        // Present only when something was folded, so a reader that never meets the cap sees the
        // shape it always saw. Its counts are in no row above, so a consumer summing the rows must
        // add this to get the total the proxy decided.
        let overflow = (tally.overflow.total() > 0).then(|| {
            serde_json::json!({
                "allow": tally.overflow.allow,
                "deny": tally.overflow.deny,
                "blocked": tally.overflow.blocked,
            })
        });
        println!(
            "{}",
            serde_json::json!({
                "project": project,
                "app": app,
                "stats": rows,
                "overflow": overflow,
            })
        );
        return ExitCode::SUCCESS;
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_stats(&project, app.as_deref(), &tally, &pal));
    ExitCode::SUCCESS
}

/// Render the per-host egress stats table — a pure presenter (its colored layout is asserted in a
/// test): a project/app header, then one row per destination with its allow/deny/blocked counts,
/// busiest first (ties broken by host for stable output). An empty result says nothing has been
/// recorded yet and when recording happens.
fn render_stats(
    project: &str,
    app: Option<&str>,
    tally: &sandbox::egress_stats::Tally,
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let mut o = String::new();
    let scope = app.map(|a| format!(" · app {a}")).unwrap_or_default();
    let _ = writeln!(o, "{h}egress stats{r} {dim}({project}{scope}){r}");
    if tally.is_empty() {
        let _ = writeln!(
            o,
            "  {dim}nothing recorded yet \
             (stats accrue while a filtering posture — allowlist/ask — runs){r}"
        );
        return o;
    }
    // Busiest host first; ties by host name so the order is stable run to run.
    let mut rows: Vec<(&String, &sandbox::egress_stats::Counts)> = tally.hosts.iter().collect();
    rows.sort_by(|(ha, a), (hb, b)| b.total().cmp(&a.total()).then(ha.cmp(hb)));
    let host_w = rows
        .iter()
        .map(|(host, _)| host.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let _ = writeln!(
        o,
        "  {dim}{:<host_w$}  {:>6}  {:>6}  {:>7}{r}",
        "HOST", "ALLOW", "DENY", "BLOCKED"
    );
    for (host, c) in rows {
        let _ = writeln!(
            o,
            "  {n}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}",
            host, c.allow, c.deny, c.blocked
        );
    }
    // The destinations past the per-session cap, as one row. Shown only when something was folded,
    // and named rather than left out: a total that silently omitted them would be the one number
    // here nobody could reconcile.
    let folded = &tally.overflow;
    if folded.total() > 0 {
        let _ = writeln!(
            o,
            "  {dim}{:<host_w$}{r}  {:>6}  {:>6}  {:>7}",
            "(other hosts)", folded.allow, folded.deny, folded.blocked
        );
    }
    o
}

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
            Some("-i") | Some("--interval") => {
                let val = it.next().ok_or("`--interval` needs a value in seconds")?;
                let secs: u64 = val.to_str().and_then(|s| s.parse().ok()).ok_or_else(|| {
                    format!(
                        "invalid interval `{}` — expected a whole number of seconds",
                        val.to_string_lossy()
                    )
                })?;
                if secs == 0 {
                    return Err("interval must be at least 1 second".into());
                }
                v.interval_secs = secs;
            }
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
/// step behind `sbx net logs` — the log's analogue of [`collect_pending`]. No launch / nix / network.
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
fn net_logs(args: &[OsString]) -> ExitCode {
    let view = match parse_log_args(args) {
        Ok(v) => v,
        Err(e) => {
            diag::error(&format!("sbx: net logs: {e}"));
            return ExitCode::from(2);
        }
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
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

/// `sbx net rules [--source config|builtin|session] [--filter <substr>] [--json]`: list the effective
/// egress rules, each tagged by source, optionally filtered. Reflects the trust gate (an untrusted
/// project's rules are dropped), and does no launch / nix / network — the read-only posture of
/// `sbx config show` and `sbx test net`.
fn net_rules(args: &[OsString]) -> ExitCode {
    use config::view::RuleSourceView;
    let mut source: Option<RuleSourceView> = None;
    let mut filter: Option<String> = None;
    let mut app: Option<String> = None;
    let mut json = false;
    let mut expand = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--expand") | Some("-e") => expand = true,
            Some("--app") | Some("-a") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: net rules: `--app` needs an app name");
                    return ExitCode::from(2);
                };
                app = Some(v.to_string());
            }
            Some("--source") | Some("-s") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: `--source` needs a value (config, builtin, session)");
                    return ExitCode::from(2);
                };
                source = Some(match v {
                    "config" => RuleSourceView::Config,
                    "builtin" => RuleSourceView::Builtin,
                    // `session` is the live `--session`-answered overlay; `manual` is kept as an
                    // accepted alias for the same source.
                    "session" | "manual" => RuleSourceView::Manual,
                    other => {
                        diag::error(&format!(
                            "sbx: unknown rule source '{other}' (known: config, builtin, session)"
                        ));
                        return ExitCode::from(2);
                    }
                });
            }
            Some("--filter") | Some("-f") => {
                let Some(v) = it.next().and_then(|a| a.to_str()) else {
                    diag::error("sbx: `--filter` needs a substring");
                    return ExitCode::from(2);
                };
                filter = Some(v.to_lowercase());
            }
            _ => {
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "rules"])
                ));
                return ExitCode::from(2);
            }
        }
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // `--source session` is live runtime state, not config: query the running sessions for the rules
    // loaded into their live overlay, rather than reading the static config policy. Scoped to this
    // project by default, or — with `-a <app>` — to that app's session(s), mirroring how
    // `sbx net allow --session -a <app>` scopes the load (`--app` here filters *which sessions* to
    // query, it does not fold a config overlay the way it does for the config/builtin sources).
    if source == Some(RuleSourceView::Manual) {
        return net_rules_manual(&cwd, app.as_deref(), filter.as_deref(), json);
    }

    let mut resolved = config::load(&cwd);
    for w in &resolved.warnings {
        diag::warn(w);
    }
    // Fold a named app's overlay so the rules listed are the *effective* set `sbx app <name>` would
    // launch with (its own posture, allow/deny, credentials), not the bare baseline — the same path
    // `sbx test net --app` uses, so the two read the same policy.
    if let Some(name) = &app
        && let Err(e) = fold_app_overlay(&mut resolved, name)
    {
        diag::error(&format!("sbx: net rules: {e}"));
        return ExitCode::from(2);
    }

    // A `--filter` is a search for a host, so it forces expansion: otherwise the substring would run
    // against a collapsed `@<group>` row and a host *inside* a group would be reported absent though
    // it is allowed — a filter must never hide a matching rule. (`sbx test net <url>` is the
    // authoritative "does this resolve" check regardless.)
    let expand = expand || filter.is_some();

    // The effective posture decides the mode word and whether there are rules at all. The built-in
    // built-in set is unioned by the proxy, which runs only under a filtering posture, so it is
    // absent (with every other rule) under `shared`/`none`.
    let (mode, all_rules) = match &resolved.network {
        config::NetworkPolicy::Shared => ("shared", Vec::new()),
        config::NetworkPolicy::Isolated => ("none", Vec::new()),
        config::NetworkPolicy::Allowlist(policy) => (
            net_mode_word(policy.default_action().into()),
            config::view::net_rules_view(policy, expand),
        ),
    };

    // Apply the source and substring filters (the substring is matched case-insensitively against
    // the rule text). `total` is the unfiltered count, so an empty result reads as "nothing matched
    // your filter" rather than "no rules at all".
    let total = all_rules.len();
    let shown: Vec<&config::view::NetRuleView> = all_rules
        .iter()
        .filter(|r| source.is_none_or(|s| r.source == s))
        .filter(|r| {
            filter
                .as_ref()
                .is_none_or(|f| r.rule.to_lowercase().contains(f))
        })
        .collect();

    if json {
        let value = serde_json::json!({
            "mode": mode,
            "rules": shown.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    // Name the posture in view: the baseline, or one app's effective overlay (matching the label
    // `sbx test net --app` prints, so the two commands read the same).
    let scope = app
        .as_ref()
        .map(|n| format!(" (app {n})"))
        .unwrap_or_default();
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_net_rules(mode, &scope, &shown, total, &pal));
    ExitCode::SUCCESS
}

/// `sbx net groups` — the reusable-egress-group surface. `export`/`import` move groups between
/// configs (they are reserved subcommand verbs, so a group named `export`/`import` is listable and
/// referenceable as `@export` but not resolvable by bare name — use the listing); anything else is
/// the list/resolve reader ([`net_groups_list`]).
fn net_groups(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("export") => net_groups_export(&args[1..]),
        Some("import") => net_groups_import(&args[1..]),
        _ => net_groups_list(args),
    }
}

/// `sbx net groups [<name>…] [--json]`: list the reusable egress groups declared in the global
/// config (`[network.groups]`), or resolve named ones to their entries. Groups are global-only (the
/// resolver honors them only from the global config), so there is no scope flag — this always reads
/// the global config. Read-only, network-free. With no name it lists each group and its entry count;
/// with names it prints each named group's authored entries, flagging a malformed or nested one.
fn net_groups_list(args: &[OsString]) -> ExitCode {
    let mut json = false;
    let mut names: Vec<String> = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some("--json") => json = true,
            Some(s) if s.starts_with('-') => {
                diag::error(&format!("sbx: net groups: unknown flag `{s}`"));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "groups"])
                ));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                diag::error("sbx: net groups: a group name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let (groups, warnings) = config::net_groups();
    for w in &warnings {
        diag::warn(w);
    }

    // A named group that does not exist is an explicit error (never a blank success). Report every
    // missing name at once, and point at what *is* defined.
    if !names.is_empty() {
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !groups.contains_key(*n))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            diag::error(&format!(
                "sbx: net groups: no such group: {}",
                missing.join(", ")
            ));
            if groups.is_empty() {
                diag::error(
                    "sbx: no egress groups are defined — declare them under [network.groups] in the \
                     global config",
                );
            } else {
                let avail: Vec<&str> = groups.keys().map(String::as_str).collect();
                diag::error(&format!("sbx: defined groups: {}", avail.join(", ")));
            }
            return ExitCode::from(2);
        }
    }

    if json {
        // name → [ { entry, invalid } ], all groups (sorted) or the named subset (given order).
        let selected: Vec<(&String, &Vec<String>)> = if names.is_empty() {
            groups.iter().collect()
        } else {
            names
                .iter()
                .filter_map(|n| groups.get_key_value(n))
                .collect()
        };
        let obj: Vec<_> = selected
            .iter()
            .map(|(name, entries)| {
                let rows: Vec<_> = entries
                    .iter()
                    .map(|e| serde_json::json!({ "entry": e, "invalid": net_group_entry_issue(e) }))
                    .collect();
                serde_json::json!({ "name": name, "entries": rows })
            })
            .collect();
        println!("{}", serde_json::json!({ "groups": obj }));
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_net_groups(&groups, &names, &pal));
    ExitCode::SUCCESS
}

/// `sbx net groups export [<name>…] [--out <file>]`: write the reusable egress groups as a portable
/// `[network.groups]` TOML fragment — every group, or the named subset — to stdout (the default,
/// composable and clobber-safe: `sbx net groups export > groups.toml`) or to `--out <file>`. The
/// inverse of `import`. Read-only on the config; no launch, no nix.
fn net_groups_export(args: &[OsString]) -> ExitCode {
    let mut out: Option<PathBuf> = None;
    let mut names: Vec<String> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") | Some("-o") => {
                let Some(v) = it.next() else {
                    diag::error("sbx: net groups export: `--out` needs a file path");
                    return ExitCode::from(2);
                };
                out = Some(PathBuf::from(v));
            }
            Some(s) if s.starts_with('-') => {
                diag::error(&format!("sbx: net groups export: unknown flag `{s}`"));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["net", "groups", "export"])
                ));
                return ExitCode::from(2);
            }
            Some(s) => names.push(s.to_string()),
            None => {
                diag::error("sbx: net groups export: a group name must be valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }

    let (groups, warnings) = config::net_groups();
    for w in &warnings {
        diag::warn(w);
    }

    // Select all groups (sorted) or the named subset. An unknown name is an explicit error.
    let selected: std::collections::BTreeMap<String, Vec<String>> = if names.is_empty() {
        groups.clone()
    } else {
        let missing: Vec<&str> = names
            .iter()
            .filter(|n| !groups.contains_key(*n))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            diag::error(&format!(
                "sbx: net groups export: no such group: {}",
                missing.join(", ")
            ));
            return ExitCode::from(2);
        }
        names
            .iter()
            .filter_map(|n| groups.get_key_value(n).map(|(k, v)| (k.clone(), v.clone())))
            .collect()
    };
    if selected.is_empty() {
        diag::error(
            "sbx: net groups export: no egress groups to export (none are defined under \
             [network.groups] in the global config)",
        );
        return ExitCode::from(2);
    }

    let fragment = config::manage::export_net_groups(&selected);
    match &out {
        None => {
            print!("{fragment}");
            ExitCode::SUCCESS
        }
        Some(path) => match std::fs::write(path, &fragment) {
            Ok(()) => {
                let n = selected.len();
                let s = if n == 1 { "" } else { "s" };
                println!("exported {n} egress group{s} to {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                diag::error(&format!(
                    "sbx: net groups export: cannot write {}: {e}",
                    path.display()
                ));
                ExitCode::FAILURE
            }
        },
    }
}

/// Keep every egress group a forced import is about to replace, and say what the incoming fragment
/// no longer declares. Returns one warning per replaced group, for the caller to surface once the
/// write succeeded.
///
/// A group is a key inside the shared global config, not a file of its own, so what stands in for a
/// per-file copy is the fragment `sbx net groups export` already emits: the replaced group is
/// written back out in the same portable form, as `<name>.group.replaced` beside the config, so
/// re-declaring it is `sbx net groups import` on that file. The name is read as configuration by
/// nothing (the loader reads `sbx.toml` and `apps/*.toml`).
///
/// Only a group whose entries actually CHANGE is kept: re-importing an identical fragment leaves no
/// copy and reports nothing. An error here fails the import closed, before the write, so a group is
/// never overwritten with no way back. The bundle importer does the same thing for the same reason
/// — see `cli::bundle::keep_replaced_bundles`.
fn keep_replaced_groups(
    config_path: &std::path::Path,
    incoming: &std::collections::BTreeMap<String, Vec<String>>,
    force: bool,
) -> Result<Vec<String>, String> {
    if !force {
        return Ok(Vec::new());
    }
    let Some(dir) = config_path.parent() else {
        return Ok(Vec::new());
    };
    let (declared, _) = config::net_groups();
    let mut notes = Vec::new();
    for (name, new) in incoming {
        let Some(old) = declared.get(name) else {
            continue; // added, not replaced
        };
        let one = |entries: &Vec<String>| {
            config::manage::export_net_groups(&std::collections::BTreeMap::from([(
                name.clone(),
                entries.clone(),
            )]))
        };
        let (before, after) = (one(old), one(new));
        if before == after {
            continue;
        }
        let kept = dir.join(format!("{name}.group.replaced"));
        crate::cli::keep_replaced_file(&kept, before.as_bytes()).map_err(|e| {
            format!(
                "cannot keep the group being replaced at {}: {e}",
                kept.display()
            )
        })?;
        notes.push(render_replaced_group(
            name,
            &crate::cli::settings_dropped_by(&before, &after),
            &kept,
        ));
    }
    Ok(notes)
}

/// The overwrite warning for one egress group: the entries its replacement no longer declares, and
/// where the previous fragment is. A few are named in full (the point is to recognize one's own
/// edit); beyond that the count stands in, because the kept fragment holds the rest.
fn render_replaced_group(name: &str, dropped: &[String], kept: &std::path::Path) -> String {
    const NAMED: usize = 3;
    let kept = kept.display();
    if dropped.is_empty() {
        return format!(
            "replaced egress group `{name}`, which differed only in layout — the previous fragment \
             is kept at {kept}"
        );
    }
    let named = dropped
        .iter()
        .take(NAMED)
        .map(|l| format!("`{l}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let rest = dropped.len().saturating_sub(NAMED);
    let more = if rest > 0 {
        format!(" (and {rest} more)")
    } else {
        String::new()
    };
    format!(
        "replaced egress group `{name}`, which declared {} the new one does not: {named}{more} — \
         the previous fragment is kept at {kept}, so a per-machine entry can be read back and \
         re-imported",
        if dropped.len() == 1 {
            "1 line".to_string()
        } else {
            format!("{} lines", dropped.len())
        },
    )
}

/// `sbx net groups import <file> [--force]`: merge a portable `[network.groups]` fragment into the
/// global config, preserving every existing group and comment (`toml_edit`). Groups are global-only,
/// so the target is always the global config; the deliberate command is the consent (an agent in the
/// cage cannot run it), and the global config is trusted by location, so there is no prompt. A name
/// that already exists is refused unless `--force` overwrites it. The imported groups are inert until
/// referenced by a `[network]` `allow`/`deny` with `@<name>`.
fn net_groups_import(args: &[OsString]) -> ExitCode {
    let (file, force) =
        match crate::cli::one_file(args, &["net", "groups", "import"], &["-f", "--force"]) {
            Ok(parsed) => parsed,
            Err(code) => return code,
        };

    let groups = match config::read_net_groups_fragment(&file) {
        Ok(g) => g,
        Err(e) => {
            diag::error(&format!("sbx: net groups import: {e}"));
            return ExitCode::from(2);
        }
    };
    // Validate every name before writing (a name keys a referenceable identifier and, if invalid,
    // would be dropped at load) — fail closed, naming the offender.
    if let Some(bad) = groups.keys().find(|n| !config::is_valid_group_name(n)) {
        diag::error(&format!(
            "sbx: net groups import: invalid group name `{bad}` (1–64 of [A-Za-z0-9._-]); nothing imported"
        ));
        return ExitCode::from(2);
    }

    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let path = match config::manage::scope_path(&config::manage::Scope::Global, &cwd) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: net groups import: {e}"));
            return ExitCode::from(1);
        }
    };
    // `--force` replaces groups that are already declared, and one may carry an entry added by hand
    // on this machine — an egress group is policy, so a silent drop widens or narrows what an app
    // may reach. Keep each replaced group beside the config BEFORE the write, and report what the
    // incoming fragment no longer declares.
    let replaced = match keep_replaced_groups(&path, &groups, force) {
        Ok(kept) => kept,
        Err(e) => {
            diag::error(&format!(
                "sbx: net groups import: {e} — nothing was overwritten"
            ));
            return ExitCode::FAILURE;
        }
    };
    match config::manage::import_net_groups(&path, &groups, force) {
        Ok(outcome) => {
            for note in &replaced {
                diag::warn(note);
            }
            let mut parts = Vec::new();
            if !outcome.added.is_empty() {
                parts.push(format!("added {}", outcome.added.join(", ")));
            }
            if !outcome.overwritten.is_empty() {
                parts.push(format!("overwrote {}", outcome.overwritten.join(", ")));
            }
            let summary = if parts.is_empty() {
                "nothing to do".to_string()
            } else {
                parts.join("; ")
            };
            println!(
                "imported {} egress group(s) into {} — {summary}",
                groups.len(),
                path.display()
            );
            // Import is the one moment the user consciously brings in someone else's data, so flag any
            // entry that will not resolve (a malformed or nested one) right here — the same inspect-time
            // check `sbx net groups <name>` applies — rather than let it surface only at the next launch.
            let dead: Vec<String> = groups
                .iter()
                .filter(|(_, entries)| entries.iter().any(|e| net_group_entry_issue(e).is_some()))
                .map(|(name, _)| name.clone())
                .collect();
            if !dead.is_empty() {
                diag::warn(&format!(
                    "some entries will not resolve in: {} — inspect with `sbx net groups <name>`",
                    dead.join(", ")
                ));
            }
            ExitCode::SUCCESS
        }
        Err(config::manage::ManageError::GroupCollision(names)) => {
            diag::error(&format!(
                "sbx: net groups import: {} already defined: {} — re-run with --force to overwrite, \
                 or rename in the fragment (nothing was written)",
                if names.len() == 1 { "group" } else { "groups" },
                names.join(", ")
            ));
            ExitCode::from(2)
        }
        Err(e) => {
            diag::error(&format!("sbx: net groups import: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Why a group entry is not a usable rule, or `None` if it is fine. Mirrors what `build_net_groups`
/// does at resolve time: a leading `@` is a nested reference (a group is flat, so it is ignored);
/// anything else is classified, and a classification error is the reason. Used to flag an entry in
/// the `sbx net groups <name>` listing so a typo in a group is visible where the group is inspected.
fn net_group_entry_issue(entry: &str) -> Option<String> {
    if entry.trim().starts_with('@') {
        return Some("nested group reference — ignored (a group is a flat list of entries)".into());
    }
    allowlist::classify(entry).err()
}

/// Render `sbx net groups` — a pure presenter (its layout is asserted in a test). With no names it
/// lists each group and its entry count; with names it prints each named group's entries (as a
/// `@name` block), appending a note to any entry that would be ignored or is malformed.
fn render_net_groups(
    groups: &std::collections::BTreeMap<String, Vec<String>>,
    names: &[String],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    let plural = |count: usize| if count == 1 { "entry" } else { "entries" };
    let mut o = String::new();

    if names.is_empty() {
        let _ = writeln!(o, "{h}egress groups{r} {dim}({}){r}", groups.len());
        if groups.is_empty() {
            let _ = writeln!(
                o,
                "  {dim}none defined — declare them under [network.groups] in the global config{r}"
            );
            return o;
        }
        let name_w = groups.keys().map(String::len).max().unwrap_or(0);
        for (name, entries) in groups {
            let _ = writeln!(
                o,
                "  {n}{name:<name_w$}{r}  {dim}({} {}){r}",
                entries.len(),
                plural(entries.len())
            );
        }
        let _ = writeln!(
            o,
            "  {}",
            style::dim_prose("resolve one with `sbx net groups <name>`", pal)
        );
        return o;
    }

    for name in names {
        let Some(entries) = groups.get(name) else {
            continue; // an unknown name was already reported by the caller
        };
        let _ = writeln!(
            o,
            "{h}@{name}{r} {dim}({} {}){r}",
            entries.len(),
            plural(entries.len())
        );
        if entries.is_empty() {
            let _ = writeln!(o, "  {dim}(empty){r}");
        }
        for e in entries {
            match net_group_entry_issue(e) {
                None => {
                    let _ = writeln!(o, "  {e}");
                }
                Some(issue) => {
                    let _ = writeln!(o, "  {e}  {dim}({issue}){r}");
                }
            }
        }
    }
    o
}

/// `sbx net rules --source session`: the live overlay rules this project's running sessions carry —
/// loaded with `sbx net allow|deny --session` or remembered from a `sbx net pending … --session`
/// answer. These live in the sessions' memory (not config) and are gone when the sessions end. The
/// proxy folds them into its effective policy, so they apply in any filtering posture, not only
/// `ask`. Cross-references the registry to find the sessions for this project (by the
/// canonical project root the registry keys on), queries each one's control socket, and lists the
/// merged, deduped rules. No config read, no launch, no nix.
fn net_rules_manual(cwd: &Path, app: Option<&str>, filter: Option<&str>, json: bool) -> ExitCode {
    use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Which sessions to query: `-a <app>` selects that app's session(s) (from the registry, across
    // projects — an app's live rules are the same wherever it runs); otherwise this project's
    // sessions, keyed by the canonical project root (the registry stores canonical paths; fall back
    // to the cwd as-is if it cannot be canonicalized).
    let (pids, scope): (Vec<u32>, String) = match app {
        Some(name) => (
            session_pids_for_app(&data_dir, name).into_iter().collect(),
            format!(" (app: {name})"),
        ),
        None => {
            let project = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
            (
                pending_session_context(&data_dir)
                    .into_iter()
                    .filter(|(_, proj, _)| *proj == project)
                    .map(|(pid, _, _)| pid)
                    .collect(),
                String::new(),
            )
        }
    };

    // Merge + dedup the manual rules across this project's sessions.
    let mut rules: Vec<NetRuleView> = Vec::new();
    for pid in pids {
        let Ok(rows) = sandbox::control::query_manual(&data_dir, pid) else {
            continue; // the session ended between the registry read and the query
        };
        for row in rows {
            // A live rule crosses the control socket as text, so its reach is re-derived here
            // through the same classifier that admitted it. An unclassifiable row cannot be in the
            // overlay (the loader validates first), so the fallback is unreachable in practice and
            // errs toward the unlabelled, never toward a false "opens every host".
            let catch_all = crate::allowlist::classify(&row.rule)
                .map(|r| r.opens_every_host())
                .unwrap_or(false);
            let view = NetRuleView {
                kind: match row.kind {
                    sandbox::control::ManualKind::Allow => NetRuleKind::Allow,
                    sandbox::control::ManualKind::Deny => NetRuleKind::Deny,
                    sandbox::control::ManualKind::Mute => NetRuleKind::Mute,
                },
                source: RuleSourceView::Manual,
                rule: row.rule,
                group: None,
                catch_all,
            };
            if !rules
                .iter()
                .any(|r| r.kind == view.kind && r.rule == view.rule)
            {
                rules.push(view);
            }
        }
    }

    let total = rules.len();
    let shown: Vec<&NetRuleView> = rules
        .iter()
        .filter(|r| filter.is_none_or(|f| r.rule.to_lowercase().contains(f)))
        .collect();

    if json {
        let value = serde_json::json!({
            "mode": "session",
            "rules": shown.iter().map(|r| (*r).clone()).collect::<Vec<_>>(),
        });
        println!("{value}");
        return ExitCode::SUCCESS;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_net_rules("session", &scope, &shown, total, &pal)
    );
    ExitCode::SUCCESS
}

/// Render the egress rule listing — a pure presenter (so its colored layout is asserted in a test):
/// a header naming the effective mode, then one line per shown rule (`allow`/`deny` keyword, the
/// rule as a cyan identifier matching `sbx config`, the source dim). `shared`/`none` carry no rules
/// and say so; an empty result distinguishes "no rules declared" from "nothing matched the filter".
fn render_net_rules(
    mode: &str,
    scope: &str,
    shown: &[&config::view::NetRuleView],
    total: usize,
    pal: &style::Palette,
) -> String {
    use config::view::{NetRuleKind, RuleSourceView};
    use std::fmt::Write as _;
    let (h, n, ok, err, dim, r) = (pal.head, pal.name, pal.ok, pal.err, pal.dim, pal.reset);
    let mut o = String::new();

    match mode {
        "shared" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} shared {dim}— no egress rules (host network, no proxy){r}"
            );
            return o;
        }
        "none" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} none {dim}— no egress rules (no network){r}"
            );
            return o;
        }
        // A filtering posture: name it and frame what the rules mean.
        "allow" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} allow {dim}— denylist: every public host reaches except the deny rules{r}"
            );
        }
        "ask" => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} ask {}",
                style::dim_prose(
                    "— an unmatched host parks for a live `sbx net pending` decision; \
                     allow rules auto-pass, deny rules auto-fail",
                    pal
                )
            );
        }
        // The live session-rule listing (`--source session`): runtime rules from `--session`
        // answers, not config — framed as such so they are not mistaken for the static policy.
        "session" => {
            // `scope` is ` (app: <name>)` when `-a` narrowed the query, else empty (this project).
            let where_ = if scope.is_empty() {
                "this project's running sessions".to_string()
            } else {
                format!("that app's running sessions{scope}")
            };
            let _ = writeln!(
                o,
                "{h}session egress rules{r} {}",
                style::dim_prose(
                    &format!(
                        "— live, loaded with `sbx net allow|deny --session` \
                         (or a `sbx net pending … --session` answer) into {where_} (gone when they end)"
                    ),
                    pal
                )
            );
        }
        _ => {
            let _ = writeln!(
                o,
                "{h}network{scope}:{r} deny {dim}— allowlist: only the listed and built-in hosts reach{r}"
            );
        }
    }

    if shown.is_empty() {
        let note = if total == 0 {
            "(no rules declared)"
        } else {
            "(no rules match the filter)"
        };
        let _ = writeln!(o, "  {dim}{note}{r}");
        return o;
    }

    for rule in shown {
        let source = match rule.source {
            RuleSourceView::Config => "config",
            RuleSourceView::Builtin => "builtin",
            RuleSourceView::Manual => "session",
        };
        // A group-expanded rule notes its origin `@<group>` beside the source — but only in the
        // expanded view: a collapsed row's text is already `@<group>`, so the annotation would just
        // repeat it.
        let tag = match &rule.group {
            Some(g) if rule.rule != format!("@{g}") => format!("{source}, @{g}"),
            _ => source.to_string(),
        };
        // A catch-all regex is the one rule whose text does not show its reach — `re:.*`, a bare
        // `re:`, `re:^https://` all read as "a pattern" and mean "every host". The grammar refuses a
        // bare `*` so that a policy reads as what it does; saying so here keeps that promise for the
        // spelling it does accept. Verdict-neutral: the rule is listed exactly as declared.
        let tag = if rule.catch_all {
            format!("{tag}, matches every host")
        } else {
            tag
        };
        match rule.kind {
            NetRuleKind::Allow => {
                let _ = writeln!(o, "  {ok}allow{r} {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
            NetRuleKind::Deny => {
                let _ = writeln!(o, "  {err}deny{r}  {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
            // A `mute` (`dontaudit`) rule suppresses the log line of a request that is *denied*
            // anyway — dim, so it never reads as a third verdict beside allow/deny.
            NetRuleKind::Mute => {
                let _ = writeln!(o, "  {dim}mute{r}  {n}{}{r}  {dim}({tag}){r}", rule.rule);
            }
        }
    }
    o
}

/// `sbx net allow|deny <rule> [--local|--global|-c <file>] [--app <name>]`: persist an egress rule
/// to a config file. The rule is validated up front (fail-closed), then `manage::add_egress_rule`
/// places it per the posture matrix. A write to the project `.sbx.toml` is trust-gated: it must be
/// absent or already trusted (else refuse — never bless an unreviewed file by appending), and is
/// re-trusted after the write so the rule takes effect. The global config is trusted by location
/// (no gate). `--app <name>` targets the app's own `[app.<name>.network]`.
fn net_add_rule(list: config::manage::EgressList, args: &[OsString]) -> ExitCode {
    use config::manage;
    // The list is also the rule's classification slot: a refused `*` catch-all then names the escape
    // hatch this verb's author was reaching for, rather than one shared pointer that fits only
    // `allow` (and tells a `deny` author to open the network — the exact opposite of the intent).
    let slot = match list {
        manage::EgressList::Allow => allowlist::Slot::Allow,
        manage::EgressList::Deny => allowlist::Slot::Deny,
        manage::EgressList::Mute => allowlist::Slot::Mute,
    };
    let verb = slot.label();

    let (session, all, rest) = split_session_flags(args);
    let (parsed, rule) = match split_one_rule("net", verb, &rest) {
        Ok(v) => v,
        Err(code) => return code,
    };
    // Validate the rule before touching any file or session (fail-closed). A `@<name>` group reference
    // is an alias for a `[network.groups]` group, expanded at load time — not itself a classifiable rule —
    // so it is validated as a group name rather than through `classify` (which would reject the `@`).
    // An undefined reference is not a write-time error (the group may be defined later); it warns
    // loudly on the next load. Any other entry is classified: a `*` catch-all, a scheme, or an
    // uncompilable regex is refused, the same classification the config resolver applies.
    let is_group = rule.trim().starts_with('@');
    if is_group {
        let group = rule.trim().strip_prefix('@').unwrap_or_default();
        if !config::is_valid_group_name(group) {
            diag::error(&format!(
                "sbx: invalid group reference {rule:?}: a group name must be 1–64 of [A-Za-z0-9._-]"
            ));
            return ExitCode::from(2);
        }
    } else if let Err(e) = allowlist::classify_in(&rule, slot) {
        diag::error(&format!("sbx: invalid rule {rule:?}: {e}"));
        return ExitCode::from(2);
    }

    if session {
        // `--session` writes no config file, so the file-scope flags do not apply — point at the
        // session-scope flags instead of silently ignoring a `--global` the user expected to matter.
        if parsed.scope_explicit {
            diag::error(
                "sbx: --session loads a live rule and writes no file, so --local/--global/-c do not \
                 apply — use -a <app> or --all to scope the session(s)",
            );
            return ExitCode::from(2);
        }
        // A `@group` is expanded from the config at launch; the live overlay has no group vocabulary,
        // so it cannot carry one. Point at the two ways to use a group.
        if is_group {
            diag::error(
                "sbx: --session cannot load a @group (a group is expanded from the config at launch) \
                 — pass the concrete rules, or add the group to the config without --session",
            );
            return ExitCode::from(2);
        }
        let cwd = match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                diag::error(&format!("sbx: cannot read the current directory: {e}"));
                return ExitCode::FAILURE;
            }
        };
        return net_inject_session(list, &rule, all, parsed.app.as_deref(), &cwd);
    }

    // `--all` is a session-scope widener, meaningless for a config write (which targets one file).
    if all {
        diag::error(
            "sbx: --all only applies with --session (it widens a live rule to every session); a config \
             write targets one file — drop --all",
        );
        return ExitCode::from(2);
    }

    // `sbx net allow|deny` resolves a `--local` scope against the cwd, as one expects of a command
    // run in a project.
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match persist_egress_rule(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) {
        Ok(message) => {
            println!(
                "{}",
                style::prose(
                    &message,
                    &style::Palette::for_stream(std::io::stdout().is_terminal())
                )
            );
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            diag::error(&format!("sbx: {message}"));
            ExitCode::from(code)
        }
    }
}

/// `sbx net unallow|undeny|unmute <rule> [--local|--global|-c <file>] [-a <app>]`: remove one egress
/// rule from a config file — the inverse of `sbx net allow|deny|mute`, so a rule is undone with the
/// vocabulary it was written in. Idempotent (removing a rule that is not there is a reported no-op,
/// not an error); a project `.sbx.toml` write is trust-gated and re-trusted exactly like the add
/// path. There is no `--session` form on any of the three: the live overlay only takes rules
/// (`inject_rule` has no retraction), so an overlay rule dies with the session rather than being
/// un-loaded, and a session-scope flag is refused rather than silently ignored.
///
/// The posture is deliberately left alone. `sbx net allow` sets one because a rule without it
/// decides nothing; taking the rule back out cannot leave that inert state behind, so removing the
/// last `allow` leaves the closed posture in place — an empty allowlist under `deny`, which is
/// stricter than what was there before, never looser.
fn net_remove_rule(list: config::manage::EgressList, args: &[OsString]) -> ExitCode {
    let (verb, _) = removal_words(list);
    if args
        .iter()
        .any(|a| matches!(a.to_str(), Some("--session") | Some("--all")))
    {
        diag::error(&format!(
            "sbx: net {verb}: --session/--all do not apply — this removes a rule from a config file"
        ));
        return ExitCode::from(2);
    }
    let (parsed, rule) = match split_one_rule("net", verb, args) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match persist_egress_removal(list, &rule, &parsed.scope, parsed.app.as_deref(), &cwd) {
        Ok(message) => {
            println!(
                "{}",
                style::prose(
                    &message,
                    &style::Palette::for_stream(std::io::stdout().is_terminal())
                )
            );
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            diag::error(&format!("sbx: {message}"));
            ExitCode::from(code)
        }
    }
}

/// `sbx net allow|deny <rule> --session [-a <app>] [--all]`: load a rule into the **live overlay** of
/// the running session(s) instead of a config file — the proactive sibling of `sbx net pending
/// allow|deny <id> --session`, which remembers a decision for a request that already parked. It writes
/// no file (so it never re-trusts a project the way a config write does) and the rule dies with the
/// session. Scope: by default the **current project's** sessions; `-a <app>` narrows to that app's;
/// `--all` widens to every reachable session. Only an `ask`-posture session consults the overlay, so a
/// filtering-posture session reports the load as skipped (`err not-ask`) rather than a silent no-op.
fn net_inject_session(
    list: config::manage::EgressList,
    rule: &str,
    all: bool,
    app: Option<&str>,
    cwd: &Path,
) -> ExitCode {
    use config::manage::EgressList;
    // `allow`/`deny` load a verdict rule; `mute` loads a log-suppression rule (a different overlay
    // and control verb), so the injection call is dispatched per-list in the loop below.
    let verb = match list {
        EgressList::Allow => "allow",
        EgressList::Deny => "deny",
        EgressList::Mute => "mute",
    };
    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Two composing pid filters: the project (unless `--all` widens machine-wide) and the app (`-a`).
    // A session must pass every active filter to receive the rule.
    let project_pids = if all {
        None
    } else {
        let canonical = match sandbox::project_identity(cwd) {
            Ok((_, c)) => c,
            Err(e) => {
                diag::error(&format!(
                    "sbx: cannot resolve the current project directory: {e}"
                ));
                return ExitCode::FAILURE;
            }
        };
        Some(session_pids_for_project(&data_dir, &canonical))
    };
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));

    let context = pending_session_context(&data_dir);
    let mut loaded: Vec<u32> = Vec::new();
    let mut refused: Vec<u32> = Vec::new();
    for pid in sandbox::control::session_pids(&data_dir) {
        if app_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        if project_pids.as_ref().is_some_and(|p| !p.contains(&pid)) {
            continue;
        }
        // A mute loads through the dedicated mute overlay (`REMEMBER MUTE`); allow/deny load a
        // verdict rule (`REMEMBER ALLOW|DENY`).
        let injected = match list {
            EgressList::Mute => sandbox::control::inject_mute(&data_dir, pid, rule),
            EgressList::Allow => sandbox::control::inject_rule(
                &data_dir,
                pid,
                sandbox::control::Verdict::Allow,
                rule,
            ),
            EgressList::Deny => {
                sandbox::control::inject_rule(&data_dir, pid, sandbox::control::Verdict::Deny, rule)
            }
        };
        match injected {
            Ok(sandbox::control::InjectOutcome::Loaded) => loaded.push(pid),
            Ok(sandbox::control::InjectOutcome::Refused) => refused.push(pid),
            // A dead/stale socket (the session went away) — skip it.
            Err(_) => {}
        }
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!(
        "{}",
        render_inject(verb, rule, all, app, &loaded, &refused, &context, &pal)
    );
    ExitCode::SUCCESS
}

/// Render a `--session` rule load: which live sessions took the rule (with their agent/project
/// context, so a cross-agent reach is visible) and which an older server refused. When no session in
/// scope took it, it says so and points at the config write as the persistent alternative. A pure
/// presenter — its palette comes from the caller.
#[allow(clippy::too_many_arguments)]
fn render_inject(
    verb: &str,
    rule: &str,
    all: bool,
    app: Option<&str>,
    loaded: &[u32],
    refused: &[u32],
    context: &[(u32, PathBuf, String)],
    pal: &style::Palette,
) -> String {
    use std::fmt::Write as _;
    let (h, dim, warn, r) = (pal.head, pal.dim, pal.warn, pal.reset);
    let mut o = String::new();
    if !loaded.is_empty() {
        let _ = writeln!(
            o,
            "{}",
            style::paint_spans(
                &format!(
                    "{h}loaded {verb} rule `{rule}` into {} live session(s):{r}",
                    loaded.len()
                ),
                pal.name,
                pal.head,
                pal
            )
        );
        for pid in loaded {
            write_session_header(&mut o, *pid, context, pal);
        }
        // The rule is live-only, never written to config — so plain `sbx net rules` (the config
        // policy) will not show it. Point at where it *is* visible.
        let _ = writeln!(
            o,
            "  {}",
            style::dim_prose(
                "see it with `sbx net rules --source session` (it is not in the config)",
                pal
            )
        );
    }
    if !refused.is_empty() {
        let pids = refused
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            o,
            "{warn}session(s) {pids} refused the rule (an older sbx without --session rule \
             support).{r}"
        );
    }
    // Nothing took the rule: no session with egress filtering is running in scope. Point at the
    // persistent path (which pre-decides the host for the next launch), carrying the `--app <name>`
    // scope when one was given so the hint is copy-pasteable.
    if loaded.is_empty() {
        if refused.is_empty() {
            let scope = match (app, all) {
                (Some(a), _) => format!("app `{a}`"),
                (None, true) => "any session".to_string(),
                (None, false) => "this project".to_string(),
            };
            let _ = writeln!(
                o,
                "{dim}no reachable session with egress filtering for {scope} — nothing to load the \
                 rule into.{r}"
            );
        }
        let app_flag = app.map(|a| format!(" --app {a}")).unwrap_or_default();
        let _ = writeln!(
            o,
            "  {dim}to pre-decide it for the next launch, persist it: sbx net {verb} \
             {rule}{app_flag}{r}"
        );
    }
    o
}

/// `sbx net pending allow|deny --all --save [-l|-g|-a <app>]`: drain parked requests *and* persist a
/// rule per answered host, so the same destinations are pre-decided next launch. The drain is scoped
/// to match the save target: a `--local` save (the default) writes the **current project's** config,
/// so it drains only that project's sessions — never machine-wide — which is what makes a bulk local
/// save unambiguous (one project's requests can never land in another's config). `--global` writes the
/// one global file and so may drain across projects; `-a <app>` narrows by app and composes with the
/// project scope. The drain is irreversible, so a `--local` save pre-flights the trust gate first.
fn net_pending_drain_and_save(
    verdict: sandbox::control::Verdict,
    session: bool,
    scope: &config::manage::Scope,
    app: Option<&str>,
) -> ExitCode {
    use config::manage::{EgressList, Scope};
    let (list, verb, past) = match verdict {
        sandbox::control::Verdict::Allow => (EgressList::Allow, "allow", "allowed"),
        sandbox::control::Verdict::Deny => (EgressList::Deny, "deny", "denied"),
    };
    if matches!(scope, Scope::File(_)) {
        diag::error("sbx: `--all --save` takes --local or --global, not `-c <file>`");
        return ExitCode::from(2);
    }
    let local = matches!(scope, Scope::Local);

    let data_dir = match egress_data_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // For a `--local` save, resolve the current project up front — its canonical root scopes the drain
    // AND is the save base — and pre-flight the trust gate before the irreversible drain.
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let project_canonical = if local {
        if let Err((code, msg)) = precheck_local_save(&cwd) {
            diag::error(&format!("sbx: {msg}"));
            return ExitCode::from(code);
        }
        match sandbox::project_identity(&cwd) {
            Ok((_, canonical)) => Some(canonical),
            Err(e) => {
                diag::error(&format!(
                    "sbx: cannot resolve the current project directory: {e}"
                ));
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // Two composing pid filters: the project (a `--local` save) and the app (`-a`). A session must
    // pass every active filter to be drained.
    let app_pids = app.map(|name| session_pids_for_app(&data_dir, name));
    let project_pids = project_canonical
        .as_deref()
        .map(|canon| session_pids_for_project(&data_dir, canon));

    let context = pending_session_context(&data_dir);
    // Both filters must pass: `--app` and `--local` compose rather than override, so a session is
    // drained only when every active scope accepts it.
    let (answered, unsupported) = drain_sessions(&data_dir, verdict, session, |pid| {
        app_pids.as_ref().is_none_or(|p| p.contains(&pid))
            && project_pids.as_ref().is_none_or(|p| p.contains(&pid))
    });
    // The flat host list the rule-writing below turns into rules, derived from what was answered
    // rather than accumulated a second time, so the two can never disagree about order.
    let hosts: Vec<String> = answered
        .iter()
        .flat_map(|(_, h)| h.iter().cloned())
        .collect();

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let total: usize = answered.iter().map(|(_, h)| h.len()).sum();
    if total == 0 {
        let mut out = String::new();
        if unsupported.is_empty() {
            let scope_note = if local {
                "for this project".to_string()
            } else if let Some(name) = app {
                format!("for app `{name}`")
            } else {
                "across any ask-mode session".to_string()
            };
            out.push_str(&style::dim_prose(
                &format!("no pending requests {scope_note} — nothing to answer or save"),
                &pal,
            ));
            out.push('\n');
        }
        write_unsupported_note(&mut out, &unsupported, &pal);
        print!("{out}");
        return ExitCode::SUCCESS;
    }

    // Persist a rule per *unique* answered host, preserving first-seen order. The base of a
    // `--local` write is the cwd — every drained session is in this project. The live answers
    // already stuck, so a save failure is a warning, not a rollback.
    //
    // The rule is the bare host, and that is a real limitation of the bulk path: the drain reply
    // names hosts only, so unlike the by-id answer (which reads the parked row's port first — see
    // [`egress_rule_for`]) it cannot tell which port each host was answered on, and a bare host is
    // the HTTPS port set alone. The success line below says so rather than leaving a rule that does
    // not match to be discovered on the next launch.
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<String> = hosts
        .into_iter()
        .filter(|h| seen.insert(h.clone()))
        .collect();
    let mut saved = 0usize;
    let mut save_error = None;
    for host in &unique {
        match persist_egress_rule(list, host, scope, app, &cwd) {
            Ok(_) => saved += 1,
            Err((_, msg)) => {
                save_error = Some(msg);
                break;
            }
        }
    }

    print!(
        "{}",
        render_drain(past, session, app, &answered, &unsupported, &context, &pal)
    );
    // Name the real write target — the same resolution the per-host save just used — so a global
    // app's save is reported as its profile file, not "the global config under app" (the profile is
    // where the rule actually landed). The target already carries the app, so there is no separate
    // " under app" suffix. Resolving cannot fail on this success path: every host was just persisted
    // to this same target; the fallback covers only the theoretical no-config-dir case.
    let target = egress_write_target(scope, app, &cwd)
        .map(|(_, _, t)| t)
        .unwrap_or_else(|_| {
            if local {
                "the project config".to_string()
            } else {
                "the global config".to_string()
            }
        });
    match save_error {
        None => {
            println!(
                "  saved {saved} {verb} rule(s) to {target}{}",
                if local { " (re-trusted)" } else { "" }
            );
            println!(
                "{}  each rule names its host alone, which covers port 443 — a destination \
                 answered on another port needs `sbx net {verb} <host>:<port>` as well{}",
                pal.dim, pal.reset
            );
            if local {
                println!(
                    "{}  scoped to this project — other projects' sessions are untouched \
                     (use --global to widen){}",
                    pal.dim, pal.reset
                );
            }
            ExitCode::SUCCESS
        }
        Some(msg) => {
            diag::warn(&format!(
                "answered {total} request(s) and saved {saved} of {} rule(s), then stopped: {msg}",
                unique.len()
            ));
            ExitCode::FAILURE
        }
    }
}

/// The removal verb and the rule noun for one egress list: `sbx net unallow` takes an `allow` rule
/// back out, `undeny` a `deny`, `unmute` a `mute`. One spelling for all of it, so the usage errors,
/// the help lookup and the confirmation sentence cannot drift from the verb the user actually typed.
///
/// Its `[proc]` twin is `cli::proc::removal_words`, deliberately a separate function: the two match
/// over unrelated enums, and a trait to share five lines would cost more than it saves.
fn removal_words(list: config::manage::EgressList) -> (&'static str, &'static str) {
    match list {
        config::manage::EgressList::Allow => ("unallow", "allow"),
        config::manage::EgressList::Deny => ("undeny", "deny"),
        config::manage::EgressList::Mute => ("unmute", "mute"),
    }
}

/// Remove an egress `rule` from the scoped config file — the removal sibling of
/// [`persist_egress_rule`], behind `sbx net unallow|undeny|unmute`. A rule that is not present is a
/// reported no-op (no write, no re-trust). Same scope vocabulary, trust-gate, and error codes as the
/// add path: a `-c <file>` scope or an untrusted project config is code `2`; a trust-store/write/
/// re-trust failure is code `1`.
fn persist_egress_removal(
    list: config::manage::EgressList,
    rule: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    base: &Path,
) -> Result<String, (u8, String)> {
    use config::manage::{self, RemoveOutcome};
    let (verb, noun) = removal_words(list);
    // A project `.sbx.toml` edit is trust-gated and re-trusted, exactly like the add path — removing
    // a rule still rewrites the file, so it must not silently bless an untrusted one. The missing-
    // store sentence is shorter here than on the add path, and stays so: it is user-visible.
    let RuleWrite {
        path,
        app_key,
        target,
        store,
    } = open_rule_write(
        "net",
        verb,
        "cannot determine the trust store (set XDG_STATE_HOME or HOME)",
        scope,
        app,
        base,
    )?;
    let gated = store.is_some();

    let outcome =
        manage::remove_egress_rule(&path, app_key, list, rule).map_err(|e| (2, e.to_string()))?;

    match outcome {
        RemoveOutcome::NotPresent => Ok(format!("{noun} {rule} was not in {target} — no change")),
        RemoveOutcome::Removed => {
            // Re-trust only after an actual change (the file bytes changed). Fail-safe ordering: a
            // crash between the write and the trust leaves a correct-but-untrusted file the next
            // launch drops — never a security hole.
            if let Some(store) = &store {
                trust::trust(store, &path).map_err(|e| {
                    (
                        1,
                        format!(
                            "removed the rule but could not re-trust {e} — run `sbx trust {}`",
                            config::PROJECT_CONFIG
                        ),
                    )
                })?;
            }
            let mut msg = format!("removed {noun} {rule} from {target}");
            if gated {
                msg.push_str(&format!("\nre-trusted {}", config::PROJECT_CONFIG));
            }
            Ok(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The overwrite warning: a few dropped entries named in full, the rest counted, and always
    /// the path the previous fragment went to — a group lives in a shared file, so that path is the
    /// only way back.
    #[test]
    fn the_group_overwrite_warning_names_a_few_losses_and_counts_the_rest() {
        let kept = std::path::Path::new("/config/sbx/ci.group.replaced");
        let one = render_replaced_group("ci", &["\"{GET} https://x\",".to_string()], kept);
        assert!(one.contains("`ci`") && one.contains("1 line"), "{one}");
        assert!(one.contains("ci.group.replaced"), "{one}");
        let many: Vec<String> = (0..5).map(|i| format!("\"e{i}\",")).collect();
        let lots = render_replaced_group("ci", &many, kept);
        assert!(
            lots.contains("5 lines") && lots.contains("(and 2 more)"),
            "{lots}"
        );
        // A group that differs only in layout still names where the previous fragment went.
        let none = render_replaced_group("ci", &[], kept);
        assert!(
            none.contains("only in layout") && none.contains(".replaced"),
            "{none}"
        );
    }

    #[test]
    fn net_rules_render_tags_each_rule_by_source_and_kind() {
        use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
        let p = style::Palette::plain();
        let mk = |kind, source, rule: &str| NetRuleView {
            kind,
            source,
            rule: rule.into(),
            group: None,
            catch_all: false,
        };
        let rules = [
            mk(NetRuleKind::Allow, RuleSourceView::Config, "github.com"),
            mk(NetRuleKind::Deny, RuleSourceView::Config, "evil.com"),
            mk(
                NetRuleKind::Allow,
                RuleSourceView::Builtin,
                "cache.nixos.org",
            ),
            // A live `--session`-answered rule is tagged `session`, not `manual`.
            mk(NetRuleKind::Deny, RuleSourceView::Manual, "adhoc.test"),
        ];
        let refs: Vec<&NetRuleView> = rules.iter().collect();

        // deny mode: header frames it as an allowlist; each rule carries its kind + source.
        let out = render_net_rules("deny", "", &refs, refs.len(), &p);
        assert!(out.contains("network: deny"), "{out}");
        assert!(out.contains("allow github.com  (config)"), "{out}");
        assert!(out.contains("deny  evil.com  (config)"), "{out}");
        assert!(out.contains("allow cache.nixos.org  (builtin)"), "{out}");
        assert!(out.contains("deny  adhoc.test  (session)"), "{out}");

        // Colored: `allow` carries the green span, `deny` the red one.
        let c = render_net_rules("deny", "", &refs, refs.len(), &style::Palette::colored());
        assert!(c.contains("\x1b[32mallow\x1b[0m"), "allow is green: {c:?}");
        assert!(c.contains("\x1b[1;31mdeny\x1b[0m"), "deny is red: {c:?}");

        // allow mode frames it as a denylist.
        assert!(render_net_rules("allow", "", &refs, refs.len(), &p).contains("network: allow"));

        // A `--app` scope labels the header exactly as `sbx test net --app` does, on every posture.
        assert!(
            render_net_rules("deny", " (app demo)", &refs, refs.len(), &p)
                .contains("network (app demo): deny"),
            "the app scope must label the header"
        );
        assert!(
            render_net_rules("shared", " (app demo)", &[], 0, &p).contains("network (app demo):"),
            "the app scope must label a non-filtering posture too"
        );

        // shared/none carry no rules, with an explanatory one-liner (no rule list).
        assert!(render_net_rules("shared", "", &[], 0, &p).contains("no egress rules"));
        assert!(render_net_rules("none", "", &[], 0, &p).contains("no egress rules"));

        // An empty result distinguishes "nothing declared" from "the filter matched nothing".
        assert!(render_net_rules("deny", "", &[], 0, &p).contains("no rules declared"));
        assert!(render_net_rules("deny", "", &[], 3, &p).contains("no rules match the filter"));
    }

    #[test]
    fn render_net_rules_annotates_only_an_expanded_group_rule() {
        use config::view::{NetRuleKind, NetRuleView, RuleSourceView};
        let p = style::Palette::plain();

        // A collapsed group row — the rule text is already `@mcp`, so the origin note would just
        // repeat it and is omitted.
        let collapsed = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "@mcp".into(),
            group: Some("mcp".into()),
            catch_all: false,
        };
        let out = render_net_rules("deny", "", &[&collapsed], 1, &p);
        assert!(out.contains("allow @mcp  (config)"), "{out}");
        assert!(
            !out.contains("@mcp, @mcp"),
            "no redundant annotation:\n{out}"
        );

        // A catch-all regex — listed exactly as declared (the tag never changes a verdict), with
        // its reach spelled out beside the source, since `re:.*` does not read as "every host".
        let wide = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "re:.*".into(),
            group: None,
            catch_all: true,
        };
        let out = render_net_rules("deny", "", &[&wide], 1, &p);
        assert!(
            out.contains("allow re:.*  (config, matches every host)"),
            "a catch-all must carry its reach in the listing:\n{out}"
        );

        // An expanded group row — the rule is the host, so the source tag notes its `@mcp` origin.
        let expanded = NetRuleView {
            kind: NetRuleKind::Allow,
            source: RuleSourceView::Config,
            rule: "{*} https://a.example.com".into(),
            group: Some("mcp".into()),
            catch_all: false,
        };
        let out = render_net_rules("deny", "", &[&expanded], 1, &p);
        assert!(
            out.contains("(config, @mcp)"),
            "an expanded group rule must note its origin:\n{out}"
        );
    }

    #[test]
    fn net_group_entry_issue_flags_malformed_and_nested_entries() {
        // A well-formed entry of any kind is fine.
        assert!(net_group_entry_issue("github.com:443").is_none());
        assert!(net_group_entry_issue("{*} api.example.com:443").is_none());
        assert!(net_group_entry_issue("re:^https://x/").is_none());
        // A nested reference is ignored (a group is flat) — reported so a typo is visible.
        let nested = net_group_entry_issue("@other").expect("a nested ref is flagged");
        assert!(nested.contains("nested group reference"), "{nested}");
        // A malformed entry carries the classifier's reason.
        assert!(net_group_entry_issue("https://*").is_some());
    }

    #[test]
    fn render_net_groups_lists_and_resolves() {
        use std::collections::BTreeMap;
        let p = style::Palette::plain();
        let groups: BTreeMap<String, Vec<String>> = [
            ("mcp".to_string(), vec!["{*} a.example.com:443".to_string()]),
            (
                "telemetry".to_string(),
                vec!["*.datadoghq.com:*".to_string(), "*.sentry.io:*".to_string()],
            ),
        ]
        .into_iter()
        .collect();

        // List mode (no names): a count header and one line per group with its entry count.
        let list = render_net_groups(&groups, &[], &p);
        assert!(list.contains("egress groups (2)"), "{list}");
        assert!(list.contains("mcp") && list.contains("(1 entry)"), "{list}");
        assert!(
            list.contains("telemetry") && list.contains("(2 entries)"),
            "{list}"
        );

        // Resolve mode (a name): a `@name` block listing the authored entries verbatim.
        let resolved = render_net_groups(&groups, &["mcp".to_string()], &p);
        assert!(resolved.contains("@mcp (1 entry)"), "{resolved}");
        assert!(resolved.contains("{*} a.example.com:443"), "{resolved}");
        // Only the named group is shown, not the whole set.
        assert!(!resolved.contains("telemetry"), "{resolved}");

        // Empty set: an explicit "none defined" line, not a blank output.
        assert!(render_net_groups(&BTreeMap::new(), &[], &p).contains("none defined"));
    }

    #[test]
    fn render_pending_groups_requests_under_a_session_header() {
        use sandbox::control::{PendingRow, SessionPending};
        let p = style::Palette::plain();

        // Empty → the "none" line with the how-it-arrives hint.
        assert!(render_pending(&[], &[], None, &p).contains("none"));
        // An empty listing under an `--app` filter names the app (not "nothing anywhere").
        let scoped = render_pending(&[], &[], Some("demo-app"), &p);
        assert!(
            scoped.contains("none for app `demo-app`"),
            "the empty filtered listing must name the app:\n{scoped}"
        );

        let row = |seq, host: &str, path: &str, waiting| PendingRow {
            seq,
            host: host.into(),
            port: 443,
            path: path.into(),
            waiting_secs: waiting,
        };
        let sessions = [
            SessionPending {
                pid: 12345,
                rows: vec![
                    row(1, "api.example.com", "/v1/x", 12),
                    // A retry of the SAME destination: it must collapse onto the lowest-seq line as
                    // `×2` with the *largest* wait, not show as its own row.
                    row(4, "api.example.com", "/v1/x", 5),
                ],
            },
            SessionPending {
                pid: 67890,
                rows: vec![row(1, "files.example.org", "/dl", 3)],
            },
        ];
        // Only the first session is in the registry context, so the two render differently.
        let context = vec![(
            12345u32,
            std::path::PathBuf::from("/home/u/proj"),
            "app:demo".to_string(),
        )];

        let out = render_pending(&sessions, &context, None, &p);
        // The collapsed destination: the lowest-seq id, the target, `×2`, and the largest wait.
        assert!(
            out.contains("12345.1")
                && out.contains("api.example.com:443/v1/x")
                && out.contains("×2, waiting 12s"),
            "{out}"
        );
        // The retry collapsed — its higher seq is not a line of its own.
        assert!(!out.contains("12345.4"), "{out}");
        // A lone request carries no `×N` prefix.
        assert!(
            out.contains("67890.1")
                && out.contains("files.example.org:443/dl")
                && out.contains("(waiting 3s)"),
            "{out}"
        );
        // The registered session shows its label + project; the other is flagged — so two sessions
        // are told apart (the literal multi-session ask).
        assert!(
            out.contains("session 12345 [app:demo] /home/u/proj"),
            "{out}"
        );
        assert!(out.contains("session 67890 (unregistered)"), "{out}");
        assert!(out.contains("sbx net pending allow <id>"), "{out}");
        // The footer also advertises the bulk drain.
        assert!(out.contains("sbx net pending allow|deny --all"), "{out}");
    }

    #[test]
    fn parse_watch_args_defaults_and_overrides() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // No flags → the 2s default, no app scope.
        let d = parse_watch_args(&[]).expect("bare watch parses");
        assert_eq!(d.interval, Duration::from_secs(2));
        assert!(d.app.is_none());

        // `-i` / `--interval` set the refresh; `-a` / `--app` set the scope; both spellings work.
        let a = parse_watch_args(&osv(&["-i", "5", "-a", "demo-app"])).unwrap();
        assert_eq!(a.interval, Duration::from_secs(5));
        assert_eq!(a.app.as_deref(), Some("demo-app"));
        let b = parse_watch_args(&osv(&["--interval", "10", "--app", "demo-tool"])).unwrap();
        assert_eq!(b.interval, Duration::from_secs(10));
        assert_eq!(b.app.as_deref(), Some("demo-tool"));
    }

    #[test]
    fn parse_watch_args_rejects_bad_input() {
        let osv = |xs: &[&str]| xs.iter().map(OsString::from).collect::<Vec<_>>();

        // A zero interval would busy-loop — refused, not silently clamped.
        assert!(parse_watch_args(&osv(&["-i", "0"])).is_err());
        // A non-numeric interval is an error naming the offending value.
        assert!(
            parse_watch_args(&osv(&["-i", "soon"]))
                .unwrap_err()
                .contains("soon")
        );
        // A flag missing its value is an error, not a panic.
        assert!(parse_watch_args(&osv(&["-i"])).is_err());
        assert!(parse_watch_args(&osv(&["--app"])).is_err());
        // An unknown flag (e.g. the contradictory `--json`) is refused with a usage hint.
        assert!(parse_watch_args(&osv(&["--json"])).is_err());
        assert!(parse_watch_args(&osv(&["bogus"])).is_err());
    }

    // ── sbx net live ───────────────────────────────────────────────────────────────────────────

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
        let out = render_live(&sessions, &ctx, None, now_ms, &pal);
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
        let empty = render_live(&[], &[], None, now_ms, &pal);
        assert!(empty.contains("no egress tunnel is open"), "empty: {empty}");
        let empty_app = render_live(&[], &[], Some("demo-app"), now_ms, &pal);
        assert!(
            empty_app.contains("app `demo-app`"),
            "app-scoped empty: {empty_app}"
        );
    }

    // ── sbx net logs ───────────────────────────────────────────────────────────────────────────

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
            out.lines().any(|l| l.contains("4242")
                && l.contains("api.test:443")
                && l.contains("POST /v1/m")),
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
    fn a_saved_rule_carries_the_port_the_request_was_answered_on() {
        // The finding: `--save` persisted the bare host the answer reply named, and a bare host is
        // the HTTPS port set — {443} — so answering a request on 8443 wrote a rule that could not
        // match the request it was saved for, and the next launch parked it again.
        assert_eq!(
            egress_rule_for("api.test", Some(8443)),
            "api.test:8443",
            "a non-default port must be pinned or the rule matches 443 instead"
        );
        // …and the guard still permits the short form where it means the same thing: 443 is the
        // bare host's own port set, and 80 is the cleartext scheme (`:80` on an implicitly-TLS host
        // would name the right port at the wrong layer).
        assert_eq!(egress_rule_for("api.test", Some(443)), "api.test");
        assert_eq!(egress_rule_for("api.test", None), "api.test");
        assert_eq!(egress_rule_for("api.test", Some(80)), "http://api.test");
        // An IPv6 literal is bracketed only when it carries a port.
        assert_eq!(egress_rule_for("::1", Some(8080)), "[::1]:8080");
        assert_eq!(egress_rule_for("::1", Some(443)), "::1");
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
    fn render_drain_reports_each_session_and_a_total() {
        let p = style::Palette::plain();

        // Empty drain → the "nothing parked" line, no total.
        assert!(
            render_drain("allowed", false, None, &[], &[], &[], &p).contains("no pending requests")
        );
        // An empty drain under an `--app` filter names the app (not "nothing anywhere").
        let scoped = render_drain("allowed", false, Some("demo-app"), &[], &[], &[], &p);
        assert!(
            scoped.contains("for app `demo-app`"),
            "the empty filtered drain must name the app:\n{scoped}"
        );

        // An empty drain whose only sessions are too old to understand `--all` does NOT say "nothing
        // parked" — it names the older sessions and points at relaunching.
        let old = render_drain("allowed", false, None, &[], &[99999u32], &[], &p);
        assert!(
            !old.contains("no pending requests")
                && old.contains("99999")
                && old.contains("older sbx")
                && old.contains("relaunch the agent"),
            "an unsupported-only drain must name the older session and the fix, not claim emptiness:\n{old}"
        );

        let answered = vec![
            (
                12345u32,
                vec!["api.example.com".to_string(), "cdn.example.com".to_string()],
            ),
            (67890u32, vec!["files.example.org".to_string()]),
        ];
        // Only the first session is registered, so the two headers render differently.
        let context = vec![(
            12345u32,
            std::path::PathBuf::from("/home/u/proj"),
            "app:demo".to_string(),
        )];

        let out = render_drain("allowed", true, None, &answered, &[], &context, &p);
        // The total counts every answered host across every session.
        assert!(out.contains("allowed 3 parked request(s)"), "{out}");
        // Each session is named (the cross-agent grant made visible), and each host listed.
        assert!(
            out.contains("session 12345 [app:demo] /home/u/proj"),
            "{out}"
        );
        assert!(
            out.contains("api.example.com") && out.contains("cdn.example.com"),
            "{out}"
        );
        assert!(out.contains("session 67890 (unregistered)"), "{out}");
        assert!(out.contains("files.example.org"), "{out}");
        // `--session` adds the remembered-for-each note.
        assert!(out.contains("remembered for each session"), "{out}");

        // Without `--session`, no remembered note; "denied" past tense for a deny drain.
        let out = render_drain("denied", false, None, &answered, &[], &context, &p);
        assert!(out.contains("denied 3 parked request(s)"), "{out}");
        assert!(!out.contains("remembered for each session"), "{out}");

        // Duplication collapse (the regression): a session that retried one destination many times
        // must list that host ONCE with a ×count, not once per request.
        let mut hosts = vec!["ziglang.org".to_string(); 20];
        hosts.push("downloads.example.com".to_string());
        let bursty = vec![(285706u32, hosts)];
        let out = render_drain("allowed", false, None, &bursty, &[], &[], &p);
        // Teeth: on the un-folded code this count is 20, so the assert fails without the fix.
        assert_eq!(
            out.matches("ziglang.org").count(),
            1,
            "a repeated host must be listed once, not once per request:\n{out}"
        );
        assert!(
            out.contains("×20"),
            "the collapsed host must carry its occurrence count:\n{out}"
        );
        // The header still counts every request (21), and the singleton host gets no ×1 noise.
        assert!(out.contains("allowed 21 parked request(s)"), "{out}");
        assert!(
            out.contains("downloads.example.com") && !out.contains("×1"),
            "a single-request host must not get a ×1 suffix:\n{out}"
        );
    }

    #[test]
    fn collapse_hosts_folds_repeats_in_first_seen_order_and_preserves_the_total() {
        let hosts = vec![
            "a.test".to_string(),
            "b.test".to_string(),
            "a.test".to_string(),
            "a.test".to_string(),
        ];
        let folded = collapse_hosts(&hosts);
        // First-seen order, each host once, with its count.
        assert_eq!(folded, vec![("a.test", 3), ("b.test", 1)]);
        // The counts sum back to the request total — the invariant the drain header relies on.
        assert_eq!(folded.iter().map(|(_, n)| n).sum::<usize>(), hosts.len());
    }

    #[test]
    fn render_stats_tabulates_hosts_busiest_first() {
        use sandbox::egress_stats::Counts;
        let p = style::Palette::plain();

        // Empty → the project header plus the "nothing recorded yet" line.
        let empty = sandbox::egress_stats::Tally::default();
        let out = render_stats("/home/u/proj", None, &empty, &p);
        assert!(
            out.contains("/home/u/proj") && out.contains("nothing recorded yet"),
            "{out}"
        );

        let mut counts = std::collections::BTreeMap::new();
        counts.insert(
            "quiet.test".to_string(),
            Counts {
                allow: 1,
                deny: 0,
                blocked: 0,
            },
        );
        counts.insert(
            "busy.test".to_string(),
            Counts {
                allow: 40,
                deny: 2,
                blocked: 1,
            },
        );
        let tally = sandbox::egress_stats::Tally {
            hosts: counts,
            ..Default::default()
        };
        let out = render_stats("/home/u/proj", Some("demo"), &tally, &p);
        assert!(
            !out.contains("(other hosts)"),
            "no fold row when nothing was folded: {out}"
        );
        // The app scope is shown in the header, and the columns are present.
        assert!(out.contains("app demo"), "{out}");
        assert!(
            out.contains("HOST")
                && out.contains("ALLOW")
                && out.contains("DENY")
                && out.contains("BLOCKED"),
            "{out}"
        );
        // Busiest host first: busy.test (total 43) precedes quiet.test (total 1).
        let busy = out.find("busy.test").unwrap();
        let quiet = out.find("quiet.test").unwrap();
        assert!(busy < quiet, "busiest host must sort first:\n{out}");
    }

    /// The destinations past the per-session cap get one row of their own, named rather than left
    /// out: a listing whose numbers did not add up to what the proxy decided would be the one figure
    /// here nobody could reconcile.
    #[test]
    fn render_stats_shows_the_folded_destinations_as_their_own_row() {
        use sandbox::egress_stats::{Counts, Tally};
        let p = style::Palette::plain();
        let tally = Tally {
            hosts: [(
                "busy.test".to_string(),
                Counts {
                    allow: 40,
                    deny: 0,
                    blocked: 0,
                },
            )]
            .into_iter()
            .collect(),
            overflow: Counts {
                allow: 0,
                deny: 44,
                blocked: 2,
            },
        };
        let out = render_stats("/home/u/proj", None, &tally, &p);
        let folded = out
            .lines()
            .find(|l| l.contains("(other hosts)"))
            .unwrap_or_else(|| panic!("no fold row:\n{out}"));
        assert!(folded.contains("44") && folded.contains("2"), "{folded:?}");

        // ...and a tally holding *only* folded counts is a listing, not "nothing recorded yet".
        let only_folded = Tally {
            overflow: Counts {
                allow: 0,
                deny: 7,
                blocked: 0,
            },
            ..Default::default()
        };
        let out = render_stats("/home/u/proj", None, &only_folded, &p);
        assert!(!out.contains("nothing recorded yet"), "{out}");
        assert!(out.contains("(other hosts)"), "{out}");
    }
}
