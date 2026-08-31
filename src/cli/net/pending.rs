//! `sbx net pending` — the live control plane for the `ask` egress posture.
//!
//! Listing the requests parked across every reachable session, watching that listing refresh,
//! answering one request by id, draining a whole session at once, and persisting the matching
//! rules when the answer asks for them. Everything that writes an irreversible answer into a live
//! session is here, next to the presenters that report what was answered.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use crate::{config, diag, help, sandbox, style};
use crate::{
    config_cwd, egress_dir_or_fail, egress_write_target, in_scope, interval_seconds,
    pending_session_context, persist_egress_rule, precheck_local_save, session_app_of,
    session_pids_for_app, session_pids_for_project, split_scope,
};

use super::write_session_header;

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
pub(super) fn net_pending_list(args: &[OsString]) -> ExitCode {
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
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
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
pub(super) fn net_pending_watch(args: &[OsString]) -> ExitCode {
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
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
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

/// Render the pending-request listing — a pure presenter (its colored layout is asserted in a
/// test): the parked requests grouped under a per-session header (the registry label + project, so
/// several sessions are told apart; a session with nothing parked contributes no header), each
/// destination a `<pid>.<seq>` id, target, and wait time. Identical retries of one URL collapse to
/// a single `×N` line. An empty listing says so and points at how requests arrive (an `ask`-posture
/// launch); under an `--app` filter it names the app, so an empty result is not mistaken for
/// "nothing parked anywhere" when other apps do have requests.
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
        // Every reachable control socket answers `LIST`, including a session with nothing parked
        // (the control plane runs under every filtering posture, not only `ask`). A header claims
        // the requests below belong to that session, so one with no rows contributes no line at
        // all — the same skip the live-flow and log listings make.
        if session.rows.is_empty() {
            continue;
        }
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

/// `sbx net pending allow|deny <id> [--save --local|--global|--app <name>]`: answer one parked
/// request live. The unblock is the primary action; `--save` additionally persists a matching rule
/// (the request's host) through the shared writer so the same host is pre-decided next launch — a
/// secondary step whose failure is a warning, never undoing the answer. `<id>` is `<pid>.<seq>`.
pub(super) fn net_pending_answer(
    verdict: sandbox::control::Verdict,
    args: &[OsString],
) -> ExitCode {
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

    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
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
    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
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

/// The scope clause an empty `--all --save` drain reports: which sessions were eligible to be
/// drained in the first place.
///
/// The project scope of a `--local` save and the `-a <app>` filter **compose** in the drain
/// predicate rather than override one another, so both belong in the sentence. Naming only the
/// project would state that this project has nothing parked when an app filter was the sole reason
/// nothing was answered — and the operator, reading a true-sounding sentence, stops looking at a
/// queue that is not empty.
fn drain_scope_note(local: bool, app: Option<&str>) -> String {
    match (local, app) {
        (true, Some(name)) => format!("for app `{name}` in this project"),
        (true, None) => "for this project".to_string(),
        (false, Some(name)) => format!("for app `{name}`"),
        (false, None) => "across any ask-mode session".to_string(),
    }
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

    let data_dir = match egress_dir_or_fail() {
        Ok(d) => d,
        Err(code) => return code,
    };

    // For a `--local` save, resolve the current project up front — its canonical root scopes the drain
    // AND is the save base — and pre-flight the trust gate before the irreversible drain.
    let cwd = match config_cwd() {
        Ok(c) => c,
        Err(code) => return code,
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
        in_scope(pid, &project_pids, &app_pids)
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
            let scope_note = drain_scope_note(local, app);
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
#[cfg(test)]
mod tests {
    use super::*;

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

    /// A reachable session with nothing parked contributes no line at all. The session header means
    /// "the requests below belong to this agent", so a bare one under `pending egress requests:`
    /// claims a queue the session does not have. Every reachable control socket answers the listing
    /// query — the control plane runs under every filtering posture, not only `ask` — so an idle
    /// session beside a busy one is the ordinary multi-session case, not a corner.
    #[test]
    fn render_pending_leaves_out_a_session_that_has_nothing_parked() {
        use sandbox::control::{PendingRow, SessionPending};
        let p = style::Palette::plain();

        let sessions = [
            // Reachable, registered, and empty: it answered the query with no rows.
            SessionPending {
                pid: 4242,
                rows: Vec::new(),
            },
            SessionPending {
                pid: 4243,
                rows: vec![PendingRow {
                    seq: 1,
                    host: "api.example.com".into(),
                    port: 443,
                    path: "/v1/x".into(),
                    waiting_secs: 12,
                }],
            },
        ];
        let context = vec![
            (
                4242u32,
                std::path::PathBuf::from("/home/u/other-proj"),
                "app:builder".to_string(),
            ),
            (
                4243u32,
                std::path::PathBuf::from("/home/u/proj"),
                "app:agent".to_string(),
            ),
        ];

        let out = render_pending(&sessions, &context, None, &p);
        assert!(
            !out.contains("session 4242"),
            "a session with nothing parked must not get a header:\n{out}"
        );
        // The session that does hold a request still reads exactly as before.
        assert!(
            out.contains("session 4243 [app:agent] /home/u/proj")
                && out.contains("4243.1")
                && out.contains("api.example.com:443/v1/x"),
            "{out}"
        );
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
    fn a_by_id_save_persists_the_port_the_stand_in_session_parked_the_request_on() {
        use crate::testutil::{EnvVar, TmpDir, env_lock};
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;

        // The defect is at the `--save` call site, not in the mapping above: the answer reply names
        // the host and nothing else, so the port has to be read off the parked row (`LIST`) *before*
        // the answer clears it from the queue. This drives the whole verb — `net pending allow <id>
        // --save --global` — against a stand-in session parking one request on 8443, and asserts on
        // the rule the global config ends up carrying.
        let _lock = env_lock();
        let data = TmpDir::new();
        let config_home = TmpDir::new();
        let _data_var = EnvVar::set("SBX_DATA_DIR", data.path());
        let _config_var = EnvVar::set("XDG_CONFIG_HOME", config_home.path());

        let pid = 424_242u32; // no live session: the socket is the whole session, as far as sbx sees
        let egress = data.path().join("egress");
        std::fs::create_dir_all(&egress).expect("create the control directory");
        let socket = egress.join(format!("control-{pid}.sock"));
        let listener = UnixListener::bind(&socket).expect("bind the stand-in control socket");

        // The stand-in serves one command per connection and returns once the answer lands, so it
        // ends whether or not the reader asked for the listing first.
        let session = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.expect("accept a control connection");
                let mut cmd = String::new();
                BufReader::new(&stream)
                    .read_line(&mut cmd)
                    .expect("read the command");
                let cmd = cmd.trim_end().to_string();
                if cmd == "LIST" {
                    (&stream)
                        .write_all(
                            b"pending seq=1 port=8443 waiting=3 host=api.test path=/v1/x\nok\n",
                        )
                        .expect("write the pending row");
                    continue;
                }
                let reply: &[u8] = if cmd.starts_with("ALLOW ") {
                    b"ok host=api.test count=1\n"
                } else {
                    b"err bad-request\n"
                };
                (&stream).write_all(reply).expect("write the reply");
                return cmd;
            }
            String::new()
        });

        let _code = net_pending_answer(
            sandbox::control::Verdict::Allow,
            &[
                OsString::from(format!("{pid}.1")),
                OsString::from("--save"),
                OsString::from("--global"),
            ],
        );
        // Unblock a stand-in still waiting on `accept` (the answer never reached it), so a failure
        // reports itself instead of hanging the suite.
        if let Ok(poke) = std::os::unix::net::UnixStream::connect(&socket) {
            let _ = (&poke).write_all(b"QUIT\n");
        }
        let answered = session.join().expect("the stand-in session thread");
        assert_eq!(answered, "ALLOW 1", "the request must have been answered");

        let global = std::fs::read_to_string(config_home.path().join("sbx").join("sbx.toml"))
            .expect("`--save --global` must have written the global config");
        assert!(
            global.contains("\"api.test:8443\""),
            "the saved rule must carry the port the request was answered on, or it cannot match \
             that request next launch:\n{global}"
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

    /// The empty `--all --save` drain must name every filter that could have emptied it. `--local`
    /// is the *default* scope, so a lone `-a <app>` composes with it rather than replacing it: a
    /// note that named only the project would state this project has nothing parked while another
    /// app in the same project holds parked requests, and an operator reading a true-sounding
    /// sentence stops looking.
    #[test]
    fn the_empty_drain_note_names_the_app_filter_beside_the_default_project_scope() {
        // The default scope plus `-a`: both filters were active, so both are named.
        let both = drain_scope_note(true, Some("agent"));
        assert!(
            both.contains("agent") && both.contains("this project"),
            "both active filters must be named: {both:?}"
        );
        // The three single-scope spellings still say exactly what they scoped to.
        assert_eq!(drain_scope_note(true, None), "for this project");
        assert_eq!(drain_scope_note(false, Some("agent")), "for app `agent`");
        let any = drain_scope_note(false, None);
        assert_eq!(any, "across any ask-mode session");
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
}
