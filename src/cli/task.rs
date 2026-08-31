//! `sbx task <subcommand>`: the declared-operation surface — list what a session offers, invoke one,
//! and read the host-side invocation log.
//!
//! This is the **host** side of that surface. The verbs read the same inside a cage, but nothing
//! here runs there: what a cage holds is a generated client that speaks the same wire and can
//! express nothing else (see [`crate::sandbox::task_shim`]). Two callers, one plane, and only one of
//! them gets a binary.
//!
//! On the host the verbs resolve a live session and talk to its socket, so a human can try an
//! operation exactly as the agent would see it — the value of that is that a task is testable
//! without an agent. `logs` is host-only by construction: the invocation log lives on a socket the
//! cage never sees, because the recorded party does not get to read the record.
//!
//! No policy lives here. The client sends a name, bounded values, and allowed variable names; every
//! decision — the program, the bounds, the credential, the ceilings — is the host-side engine's.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::sandbox::task_control::{TASK_SOCKET_ENV, client};
use std::io::IsTerminal;

use crate::style::{Align, print_table};
use crate::{diag, help, layout_or_fail, print_json, sandbox, store, style};

/// The exit code `sbx task run` returns when the plane **refused** an invocation — an unknown
/// operation, a value outside its declared bound, an unlisted variable, an exhausted quota. Distinct
/// from any code the wrapped command could plausibly return, so a script can tell "nothing ran" from
/// "it ran and failed"; 125 is the convention `env` and `docker` use for the same distinction.
const REFUSED_EXIT: u8 = 125;

/// `sbx task <subcommand>`: `list`, `secrets`, `run`, `status`, `show`, `stop`, or `logs`.
pub(crate) fn task_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("task", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => task_list(&args[1..]),
        Some("secrets") => task_secrets(&args[1..]),
        Some("run") => task_run(&args[1..]),
        Some("result") => task_result(&args[1..]),
        Some("status") => task_status(&args[1..]),
        Some("show") => task_show(&args[1..]),
        Some("stop") => task_stop(&args[1..]),
        Some("logs") | Some("log") => task_logs(&args[1..]),
        None => {
            eprint!("{}", help::page_usage(&["task"]).unwrap_or_default());
            ExitCode::from(2)
        }
        Some(other) => {
            diag::error(&format!("sbx: task: unknown subcommand `{other}`"));
            diag::hint("       run `sbx help task` for usage.");
            ExitCode::from(2)
        }
    }
}

/// Which session a verb is talking to, and the socket to reach it on.
///
/// The session is carried alongside the socket because a listing has to say **whose** operations it
/// is showing: a plane belongs to one project, and a reader with two sessions open cannot tell which
/// answered from the rows alone.
struct Plane {
    socket: PathBuf,
    /// Where the operation *inventory* is served — the crossing socket. The same socket for the
    /// verbs that already talk to it, and the sibling of the log socket for the host-only ones,
    /// which need it to tell a misspelled operation from an empty answer.
    inventory: PathBuf,
    /// The host-only socket, when there is one — absent in a cage, which cannot reach it. It is what
    /// lets the inventory say which operations are running right now.
    host: Option<PathBuf>,
    /// The session's pid and project, when one was resolved. Absent in a cage, where there is no
    /// session to resolve — the socket is the one the environment names, and it is the only one.
    session: Option<(u32, PathBuf)>,
}

impl Plane {
    /// Print which session answered, above the listing it answered with.
    fn announce(&self) {
        let Some((pid, project)) = &self.session else {
            return;
        };
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        println!(
            "{}session {pid} — {}{}",
            pal.dim,
            project.display(),
            pal.reset
        );
    }

    /// This plane's session id as a table cell.
    fn cell(&self) -> String {
        self.session
            .as_ref()
            .map(|(pid, _)| pid.to_string())
            .unwrap_or_else(|| NONE.to_string())
    }

    /// This plane's session as a line under a refusal: the id to hand `--session`, and the project
    /// that tells one session from another. The same shape [`resolve_task_session`] lists.
    fn describe(&self) -> String {
        match &self.session {
            Some((pid, project)) => format!("{pid}  {}", project.display()),
            None => NONE.to_string(),
        }
    }
}

/// Which of a session's two sockets a verb speaks to.
#[derive(Clone, Copy, PartialEq)]
enum Side {
    /// The crossing socket: the inventory and the invocations. Reachable from a cage.
    Cage,
    /// The host-only socket: the log, what is running, and the stop.
    Host,
}

/// Every plane a **listing** should read: the one named, or all of them.
///
/// A read-only listing across sessions is strictly better than the refusal it replaces. Ambiguity is
/// only dangerous where it decides *what runs* — `run` and `stop` still make the caller name one,
/// because guessing there would run a real command with a real credential, or end someone else's
/// invocation. Reading answers no such question, and a reader with two sessions open was being told
/// to go and pick one before being shown anything at all.
fn planes_for(id: Option<&str>, verb: &str, side: Side) -> Result<Vec<Plane>, ExitCode> {
    refuse_host_side_in_a_cage(verb, side)?;
    if let Some(one) = env_plane(id, verb)? {
        return Ok(vec![one]);
    }
    let layout = layout_or_fail()?;
    if let Some(id) = id {
        return Ok(vec![one_plane(&layout, resolve_named(id, verb)?, side)]);
    }
    let pids = sandbox::task_control::session_pids(layout.data_dir());
    if pids.is_empty() {
        return Err(no_sessions(verb));
    }
    Ok(pids
        .into_iter()
        .map(|pid| one_plane(&layout, pid, side))
        .collect())
}

/// The plane the environment names, when this sbx is talking to one rather than owning it.
fn env_plane(id: Option<&str>, verb: &str) -> Result<Option<Plane>, ExitCode> {
    let Some(path) = std::env::var_os(TASK_SOCKET_ENV) else {
        return Ok(None);
    };
    // A cage reaches exactly one plane — its own — so `--session` names something that cannot be
    // selected from here. Refused rather than dropped: a flag a caller believes it set must never
    // silently become nothing, least of all one that chooses which credentials an operation runs
    // with.
    if id.is_some() {
        diag::error(&format!(
            "sbx: task {verb}: `--session` cannot be used here — a cage reaches one plane, its own"
        ));
        return Err(ExitCode::from(2));
    }
    let socket = PathBuf::from(path);
    Ok(Some(Plane {
        inventory: socket.clone(),
        socket,
        host: None,
        session: None,
    }))
}

fn one_plane(layout: &store::Layout, pid: u32, side: Side) -> Plane {
    let inventory = sandbox::task_control::task_dir(layout.data_dir(), pid).join("control.sock");
    let host = sandbox::task_control::log_socket(layout.data_dir(), pid);
    Plane {
        socket: match side {
            Side::Cage => inventory.clone(),
            Side::Host => host.clone(),
        },
        inventory,
        host: Some(host),
        session: Some((pid, session_project(layout.data_dir(), pid))),
    }
}

fn resolve_named(id: &str, verb: &str) -> Result<u32, ExitCode> {
    id.parse::<u32>().map_err(|_| {
        diag::error(&format!("sbx: task {verb}: `{id}` is not a session id"));
        diag::hint("       `sbx session ls` lists them; the id is the session's PID.");
        ExitCode::from(2)
    })
}

fn no_sessions(verb: &str) -> ExitCode {
    diag::error(&format!(
        "sbx: task {verb}: no session is offering declared operations"
    ));
    diag::hint("       a session offers them when its config declares `[task.<name>]`.");
    ExitCode::FAILURE
}

/// Refuse a host-side verb inside a cage, where there is no host plane to speak it to.
///
/// The socket the cage advertises is the crossing one, which offers the inventory and the
/// invocations and nothing else: the log, what is running, and the stop are deliberately elsewhere
/// (`task_control::serve_host` states why). Without this, [`env_plane`] handed those verbs the
/// crossing socket anyway — `side` is not a thing it looks at — and the caller got `err unknown
/// command` for a verb that is not missing but withheld. The listing verbs went that way while the
/// acting ones were refused here, from one rule written twice.
///
/// It is the message that changes, not the boundary: the host socket is never bound into a cage, so
/// nothing in there could reach these verbs however it asked.
fn refuse_host_side_in_a_cage(verb: &str, side: Side) -> Result<(), ExitCode> {
    if side == Side::Host && std::env::var_os(TASK_SOCKET_ENV).is_some() {
        diag::error(&format!(
            "sbx: task {verb}: this is host-side only — a cage may invoke operations, not watch or \
             collect them"
        ));
        return Err(ExitCode::from(2));
    }
    Ok(())
}

/// The one plane a verb that **acts** must be given: exactly one, named when several exist.
///
/// `$SBX_TASK_SOCKET` short-circuits the search, which is how a specific plane can be addressed
/// without resolving a session. It is also the discovery handle the cage advertises, so a tool that
/// wants to find the plane looks in one place whichever side it is on.
fn plane_for(id: Option<&str>, verb: &str, side: Side) -> Result<Plane, ExitCode> {
    refuse_host_side_in_a_cage(verb, side)?;
    if let Some(one) = env_plane(id, verb)? {
        return Ok(one);
    }
    let layout = layout_or_fail()?;
    let pid = resolve_task_session(layout.data_dir(), id, verb)?;
    Ok(one_plane(&layout, pid, side))
}

/// The project a session runs in, from the session registry. A plane whose registry record is gone
/// still answers, so a missing project is a blank rather than a failure.
fn session_project(data_dir: &std::path::Path, pid: u32) -> PathBuf {
    crate::session::Registry::at(data_dir)
        .list()
        .unwrap_or_default()
        .into_iter()
        .find(|s| s.pid == pid)
        .map(|s| s.project)
        .unwrap_or_default()
}

/// Resolve which session's task plane to address: the id the user named, or the sole one that has a
/// plane. Ambiguity is an error rather than a guess — invoking an operation against the wrong
/// session would run a real command with a real credential.
fn resolve_task_session(
    data_dir: &std::path::Path,
    id: Option<&str>,
    verb: &str,
) -> Result<u32, ExitCode> {
    if let Some(id) = id {
        return resolve_named(id, verb);
    }
    let pids = sandbox::task_control::session_pids(data_dir);
    match pids.as_slice() {
        [] => Err(no_sessions(verb)),
        [one] => Ok(*one),
        many => {
            diag::error(&format!(
                "sbx: task {verb}: {} sessions are offering operations — name one with `--session`",
                many.len()
            ));
            for pid in many {
                diag::hint(&format!(
                    "       {pid}  {}",
                    session_project(data_dir, *pid).display()
                ));
            }
            Err(ExitCode::from(2))
        }
    }
}

/// The value shown for a field an operation does not have. A dash rather than a blank, so an empty
/// cell is visibly "none" instead of something the renderer dropped.
const NONE: &str = "-";

/// Split one wire row into its `key=value` fields and its trailing free text. The description is
/// always last and may itself contain `=`, so it is taken by position, not by parsing.
fn split_fields(fields: &[String]) -> (BTreeMap<&str, &str>, String) {
    match fields.split_last() {
        Some((tail, head)) => (key_values(head), tail.to_string()),
        None => (BTreeMap::new(), String::new()),
    }
}

/// The `key=value` fields of one wire row, by key. A field without `=` is not one.
fn key_values(fields: &[String]) -> BTreeMap<&str, &str> {
    fields.iter().filter_map(|f| f.split_once('=')).collect()
}

/// `sbx task list [<operation>] [--session <id>]`: the operations on offer, with their parameters
/// and ceilings — across every session that offers any, unless one is named.
///
/// Only the columns that carry something are printed. Every operation shows its stream dispositions
/// and none of them declares an output directory in the common case, so fixed columns would spend
/// most of the width on `show  show` — the noise that makes a listing unreadable is the part that is
/// the same on every line.
fn task_list(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "list") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let planes = match planes_for(listing.session.as_deref(), "list", Side::Cage) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let all = match gather(&planes, "list", |p| client::list(&p.socket)) {
        Ok(rows) => rows,
        Err(code) => return code,
    };
    for plane in &planes {
        plane.announce();
    }
    if all.is_empty() {
        println!("no declared operations");
        return ExitCode::SUCCESS;
    }
    let rows: Vec<(String, client::TaskRow)> = match &listing.operation {
        None => all,
        Some(name) => {
            let kept: Vec<_> = all
                .iter()
                .filter(|(_, r)| &r.name == name)
                .cloned()
                .collect();
            if kept.is_empty() {
                let known: Vec<String> = all.iter().map(|(_, r)| r.name.clone()).collect();
                return no_match("list", name, &known);
            }
            kept
        }
    };

    let sessions: Vec<String> = rows.iter().map(|(s, _)| s.clone()).collect();
    let inventory: Vec<client::TaskRow> = rows.into_iter().map(|(_, r)| r).collect();
    let mut table = list_table(&inventory, &running_now(&planes), &sessions);
    with_session_column(
        spans_sessions(&planes),
        &mut table.headers,
        &mut table.align,
        &mut table.rows,
        &sessions,
    );
    print_table(&table.headers, &table.align, &table.rows);

    // The two columns whose meaning does not fit in a cell, said once under the table rather than
    // repeated on every line.
    if table.output {
        diag::note(&format!(
            "an operation marked OUTPUT writes into {}/<operation>",
            sandbox::task::TASK_OUT_AGENT
        ));
    }
    if table.missing {
        diag::warn(
            "an operation with MISSING TOOLS will fail at exec — the tool pool does not hold them",
        );
    }
    ExitCode::SUCCESS
}

/// The inventory laid out in columns, with the two facts the table can only gesture at.
struct ListTable {
    headers: Vec<&'static str>,
    align: Vec<Align>,
    rows: Vec<Vec<String>>,
    /// Whether any operation declares an output directory, or is missing a declared tool.
    output: bool,
    missing: bool,
}

/// How many invocations of each `(session, operation)` are running right now.
///
/// The inventory is a listing of what is *declared*, but `ls` is the word this product uses for what
/// is **live** (`sbx session ls`), so a reader typing it is often asking the other question. Answering
/// both costs one read of the host socket and a column that only appears when something is running.
/// A cage cannot reach that socket — it has no `host` — so there the listing stays what it always
/// was.
fn running_now(planes: &[Plane]) -> BTreeMap<(String, String), usize> {
    let mut counts = BTreeMap::new();
    for plane in planes {
        let Some(host) = &plane.host else { continue };
        let Ok(rows) = sandbox::task_control::read_status(host) else {
            continue;
        };
        for row in rows {
            if let Some(task) = key_values(&row.fields).get("task") {
                *counts
                    .entry((plane.cell(), (*task).to_string()))
                    .or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Lay the inventory out, keeping only the columns that carry something.
fn list_table(
    rows: &[client::TaskRow],
    running: &BTreeMap<(String, String), usize>,
    sessions: &[String],
) -> ListTable {
    let parsed: Vec<(&str, BTreeMap<&str, &str>, String)> = rows
        .iter()
        .map(|row| {
            let (fields, description) = split_fields(&row.fields);
            (row.name.as_str(), fields, description)
        })
        .collect();
    let any = |key: &str, test: &dyn Fn(&str) -> bool| {
        parsed
            .iter()
            .any(|(_, f, _)| f.get(key).is_some_and(|v| test(v)))
    };
    // A stream disposition is worth a column only when one of them is not the default: two columns
    // reading `show  show` on every line are exactly the noise that makes a listing unreadable.
    let streams = any("stdout", &|v| v != "show") || any("stderr", &|v| v != "show");
    let output = any("output", &|_| true);
    let missing = any("missing-tools", &|_| true);
    let described = parsed.iter().any(|(_, _, d)| !d.is_empty());
    // Where each operation is declared, by the same rule: worth a column when the rows disagree, and
    // noise when a project's whole set comes from one file. The two never overlap — rows disagree
    // exactly when more than one source contributed, which is exactly when `sbx session ls` (which
    // names the app and the project, but no bundle) cannot answer it. `sbx task show <name>` says it
    // either way.
    let origins: Vec<&str> = parsed
        .iter()
        .map(|(_, f, _)| f.get("declared-in").copied().unwrap_or_default())
        .collect();
    let mixed_origins = origins.windows(2).any(|w| w[0] != w[1]);

    // How many invocations of each row are live, in the order the rows are in. Zero everywhere means
    // no column: the listing is back to what is declared, which is all there is to say.
    let live: Vec<usize> = parsed
        .iter()
        .enumerate()
        .map(|(i, (name, _, _))| {
            let session = sessions.get(i).cloned().unwrap_or_default();
            running
                .get(&(session, (*name).to_string()))
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let any_live = live.iter().any(|n| *n > 0);

    let mut headers = vec!["NAME", "PARAMS", "TIMEOUT"];
    let mut align = vec![Align::Left, Align::Left, Align::Right];
    if any_live {
        headers.push("RUNNING");
        align.push(Align::Right);
    }
    for (wanted, label) in [
        (mixed_origins, "DECLARED IN"),
        (streams, "STDOUT"),
        (streams, "STDERR"),
        (output, "OUTPUT"),
        (missing, "MISSING TOOLS"),
        (described, "DESCRIPTION"),
    ] {
        if wanted {
            headers.push(label);
            align.push(Align::Left);
        }
    }

    let rows = parsed
        .iter()
        .enumerate()
        .map(|(i, (name, f, description))| {
            let cell = |key: &str| match f.get(key).copied() {
                None | Some("") => NONE.to_string(),
                Some(v) => v.to_string(),
            };
            let mut row = vec![(*name).to_string(), cell("params"), cell("timeout")];
            if any_live {
                row.push(match live[i] {
                    0 => NONE.to_string(),
                    n => n.to_string(),
                });
            }
            if mixed_origins {
                row.push(cell("declared-in"));
            }
            if streams {
                row.push(cell("stdout"));
                row.push(cell("stderr"));
            }
            if output {
                // The path is one per operation and derivable from its name, so the cell says
                // *whether*, and the note under the table says where.
                row.push(
                    if f.contains_key("output") {
                        "yes"
                    } else {
                        NONE
                    }
                    .to_string(),
                );
            }
            if missing {
                row.push(cell("missing-tools"));
            }
            if described {
                row.push(description.clone());
            }
            row
        })
        .collect();
    ListTable {
        headers,
        align,
        rows,
        output,
        missing,
    }
}

/// `sbx task secrets [<operation>] [--session <id>]`: the credentials the operations carry — names
/// and descriptions only.
fn task_secrets(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "secrets") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let planes = match planes_for(listing.session.as_deref(), "secrets", Side::Cage) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let all = match gather(&planes, "secrets", |p| client::secrets(&p.socket)) {
        Ok(rows) => rows,
        Err(code) => return code,
    };
    for plane in &planes {
        plane.announce();
    }
    let rows: Vec<(String, String)> = match &listing.operation {
        None => all,
        Some(name) => all
            .iter()
            .filter(|(_, r)| r.split('\t').any(|f| f == format!("task={name}")))
            .cloned()
            .collect(),
    };
    if rows.is_empty() {
        return match &listing.operation {
            Some(name) => empty_or_unknown(
                &planes,
                "secrets",
                name,
                &format!("`{name}` carries no credentials"),
            ),
            None => {
                println!("no credentials are carried by the declared operations");
                ExitCode::SUCCESS
            }
        };
    }
    let sessions: Vec<String> = rows.iter().map(|(s, _)| s.clone()).collect();
    let rows: Vec<String> = rows.into_iter().map(|(_, r)| r).collect();
    // Two shapes cross the wire — a variable the operation's environment carries, and a value
    // injected into a request the operation never sees — and DELIVERY is where they differ. That is
    // the field a reader is actually after: whether the command holds the credential at all.
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            let mut fields = row.split('\t');
            let name = fields.next().unwrap_or_default().to_string();
            let rest: Vec<&str> = fields.collect();
            let (map, tail) = {
                let mut map = BTreeMap::new();
                let mut tail = String::new();
                for field in &rest {
                    match field.split_once('=') {
                        Some((k, v)) => {
                            map.insert(k, v);
                        }
                        None => tail = (*field).to_string(),
                    }
                }
                (map, tail)
            };
            let (delivery, description) = match tail.strip_prefix("wire-injected for ") {
                Some(to) => (format!("wire -> {to}"), String::new()),
                None => (
                    format!("env ({})", map.get("encode").copied().unwrap_or("raw")),
                    tail,
                ),
            };
            vec![
                name,
                map.get("task").copied().unwrap_or(NONE).to_string(),
                delivery,
                description,
            ]
        })
        .collect();
    let mut table = table;
    let mut headers = vec!["NAME", "OPERATION", "DELIVERY", "DESCRIPTION"];
    let mut align = vec![Align::Left; 4];
    with_session_column(
        spans_sessions(&planes),
        &mut headers,
        &mut align,
        &mut table,
        &sessions,
    );
    print_table(&headers, &align, &table);
    ExitCode::SUCCESS
}

/// `sbx task run <name> [--param k=v]… [--env K=V]… [--session <id>] [--json]`: invoke one operation.
///
/// The exit code is the command's own, so a task composes in a script exactly like the program it
/// wraps; a *refusal* (an unknown task, a value outside its bound) is [`REFUSED_EXIT`], which the
/// wrapped command could not plausibly return, so a caller can tell it from the command having run
/// and failed.
fn task_run(args: &[OsString]) -> ExitCode {
    let mut name: Option<String> = None;
    let mut id: Option<String> = None;
    let mut params = BTreeMap::new();
    let mut env = BTreeMap::new();
    let mut json = false;
    let mut detach = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--param") | Some("-p") => match pair(args.get(i + 1), "--param") {
                Ok((k, v)) => {
                    params.insert(k, v);
                    i += 2;
                }
                Err(code) => return code,
            },
            Some("--env") | Some("-e") => match pair(args.get(i + 1), "--env") {
                Ok((k, v)) => {
                    env.insert(k, v);
                    i += 2;
                }
                Err(code) => return code,
            },
            Some("--json") => {
                json = true;
                i += 1;
            }
            Some("--detach") => {
                detach = true;
                i += 1;
            }
            Some("--session") => match args.get(i + 1).and_then(|a| a.to_str()) {
                Some(v) => {
                    id = Some(v.to_string());
                    i += 2;
                }
                None => {
                    diag::error("sbx: task run: `--session` needs a session id");
                    return ExitCode::from(2);
                }
            },
            Some(s) if !s.starts_with('-') && name.is_none() => {
                name = Some(s.to_string());
                i += 1;
            }
            other => {
                diag::error(&format!(
                    "sbx: task run: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!("{}", help::page_usage(&["task", "run"]).unwrap_or_default());
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        diag::error("sbx: task run: name the operation to run");
        eprint!("{}", help::page_usage(&["task", "run"]).unwrap_or_default());
        return ExitCode::from(2);
    };
    if detach {
        return run_detached(id.as_deref(), &name, &params, &env, json);
    }
    let plane = match plane_for(id.as_deref(), "run", Side::Cage) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // No announcement here, unlike the listings: `run` returns the command's own streams, and a line
    // of sbx's own above them would end up in whatever the caller piped this into.
    let result = match client::run(&plane.socket, &name, &params, &env) {
        Ok(r) => r,
        Err(e) => return unreachable_plane(&e),
    };
    render_result("run", &name, &result, json)
}

/// `sbx task run --detach`: start an operation and return its invocation id without waiting.
///
/// Host-only, and on the session's host-only socket rather than the crossing one. A detached
/// invocation can only be watched with `status`, ended with `stop` and collected with `result` — all
/// three host-only — so a cage that could start one could create invocations it can neither see nor
/// end. It would also be able to hold several at once, which having to wait for each is what prevents.
fn run_detached(
    session: Option<&str>,
    name: &str,
    params: &BTreeMap<String, String>,
    env: &BTreeMap<String, String>,
    json: bool,
) -> ExitCode {
    if std::env::var_os(TASK_SOCKET_ENV).is_some() {
        diag::error(
            "sbx: task run: `--detach` is host-side only — a detached invocation is watched, \
             stopped and collected from the host",
        );
        return ExitCode::from(2);
    }
    let plane = match plane_for(session, "run", Side::Host) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let result = match client::run_detached(&plane.socket, name, params, env) {
        Ok(r) => r,
        Err(e) => return unreachable_plane(&e),
    };
    if json {
        let view = DetachView {
            task: name,
            id: (result.id != 0).then_some(result.id),
            detached: result.error.is_none(),
            error: result.error.as_deref(),
        };
        if let Err(code) = print_json("task run", &view) {
            return code;
        }
        return match result.error {
            Some(_) => ExitCode::from(REFUSED_EXIT),
            None => ExitCode::SUCCESS,
        };
    }
    if let Some(error) = &result.error {
        diag::error(&format!("sbx: task run: {error}"));
        return ExitCode::from(REFUSED_EXIT);
    }
    // The id alone on stdout, so `id=$(sbx task run --detach <name>)` is the whole of it. Everything
    // else a person needs goes to stderr, where it cannot end up in that variable.
    println!("{}", result.id);
    diag::note(&format!(
        "invocation {} is running detached — `sbx task status` watches it, `sbx task result {}` \
         collects what it produced",
        result.id, result.id
    ));
    ExitCode::SUCCESS
}

/// `sbx task result <invocation>`: what a detached invocation produced.
///
/// Deliberately the same rendering as a foreground `run`, down to the exit code, so that detaching
/// changes *when* a result arrives and nothing about what it is.
fn task_result(args: &[OsString]) -> ExitCode {
    let mut target: Option<String> = None;
    let mut session: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--json") => {
                json = true;
                i += 1;
            }
            Some("--session") => match args.get(i + 1).and_then(|a| a.to_str()) {
                Some(v) => {
                    session = Some(v.to_string());
                    i += 2;
                }
                None => {
                    diag::error("sbx: task result: `--session` needs a session id");
                    return ExitCode::from(2);
                }
            },
            Some(s) if !s.starts_with('-') && target.is_none() => {
                target = Some(s.to_string());
                i += 1;
            }
            other => {
                diag::error(&format!(
                    "sbx: task result: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!(
                    "{}",
                    help::page_usage(&["task", "result"]).unwrap_or_default()
                );
                return ExitCode::from(2);
            }
        }
    }
    let Some(target) = target else {
        diag::error("sbx: task result: name the invocation to collect");
        eprint!(
            "{}",
            help::page_usage(&["task", "result"]).unwrap_or_default()
        );
        return ExitCode::from(2);
    };
    // An invocation, never an operation. The listings take either because narrowing by name is
    // useful there; a result belongs to one run, and an operation name would name several.
    let Ok(id) = target.parse::<u64>() else {
        diag::error(&format!(
            "sbx: task result: `{target}` is not an invocation id"
        ));
        diag::hint("       it is the number `sbx task run --detach` returned.");
        return ExitCode::from(2);
    };
    let plane = match plane_for(session.as_deref(), "result", Side::Host) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let result = match client::result(&plane.socket, id) {
        Ok(r) => r,
        Err(e) => return unreachable_plane(&e),
    };
    // Which operation this was is asked of the session rather than of the caller, who named an
    // invocation and has no reason to also remember what it ran. A session that no longer knows
    // leaves the field as the id, which is still true.
    let name = sandbox::task_control::read_info(&plane.socket, &target)
        .ok()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key == "operation")
                .map(|(_, value)| value.clone())
        })
        .unwrap_or_else(|| target.clone());
    render_result("result", &name, &result, json)
}

/// Print one invocation's result — as prose on the real streams, or as one JSON document.
///
/// `verb` names the subcommand a refusal is reported under: the same answer reaches this from `run`
/// (the plane declined to run anything) and from `result` (there is nothing here to give you), and a
/// message prefixed with the wrong one sends a reader to the wrong page.
fn render_result(verb: &str, name: &str, result: &client::RunResult, json: bool) -> ExitCode {
    if json {
        return run_as_json(name, result);
    }
    if let Some(error) = &result.error {
        diag::error(&format!("sbx: task {verb}: {error}"));
        // Not 2: that is a plausible exit code for the wrapped command itself, and a caller must be
        // able to tell "sbx refused to run it" from "it ran and exited 2". 125 is the convention
        // `env`/`docker` use for exactly this — the runner refused, nothing was executed.
        return ExitCode::from(REFUSED_EXIT);
    }
    // Streams go to their own channels, so a caller can pipe stdout while still seeing stderr.
    if let Some(out) = &result.stdout {
        print!("{out}");
    }
    if let Some(err) = &result.stderr {
        eprint!("{err}");
    }
    if result.timed_out {
        diag::warn(&format!(
            "the operation was killed at its timeout after {}ms",
            result.elapsed_ms
        ));
    }
    // Said for the same reason as the timeout: what came back is a partial result, and the exit
    // code alone would read as the command having failed on its own.
    if result.stopped {
        diag::warn(&format!(
            "invocation {} was stopped after {}ms",
            result.id, result.elapsed_ms
        ));
    }
    if result.truncated {
        diag::warn("the output reached the operation's `max_output` and was truncated");
    }
    if let Some((path, bytes)) = &result.output {
        diag::note(&format!("the operation wrote {bytes} byte(s) to {path}"));
    }
    // What `spawn` refused. Reported for the same reason as truncation: the refusal leaves no trace
    // in the result — the program that was refused decides whether to mention it, and many do not,
    // so an empty output would otherwise read as a command that simply found nothing.
    if !result.refused.is_empty() {
        diag::warn("the operation was not allowed to run:");
        // Caller first, then what it reached for. Under a policy where what may run depends on who
        // is running it, the target alone misleads: a program can be declared and still refused —
        // to whoever reached for it — and a reader told only the target goes to add an entry that
        // is already there.
        for refusal in &result.refused {
            match refusal.caller.is_empty() {
                true => eprintln!("  {}", refusal.target),
                false => eprintln!("  {}  →  {}", refusal.caller, refusal.target),
            }
        }
        diag::note(
            "this operation declares `spawn`; list the target there when the caller is the command \
             itself, and under `[task.<name>.exec.<caller>]` otherwise.",
        );
    }
    if result.redacted > 0 {
        let named = match &result.nonce {
            // With the nonce on, report it: a `${NAME@nonce}` in the text is only unforgeable
            // because the nonce arrives out of band, here.
            Some(nonce) => format!(" (this invocation's nonce is {nonce})"),
            None => String::new(),
        };
        diag::warn(&format!(
            "{} credential value(s) were substituted out of the output{named}",
            result.redacted
        ));
    }
    // The command's own exit code, clamped into the byte a process can return.
    ExitCode::from(result.exit.clamp(0, 255) as u8)
}

/// One invocation as a machine reads it: everything the prose path says in warnings, as fields.
///
/// The streams live **inside** the document rather than on the real ones. A caller that asked for
/// JSON asked for one parseable thing on stdout, and a command that writes to stdout would otherwise
/// interleave with it — so under `--json` stdout carries the document and nothing else.
#[derive(serde::Serialize)]
struct RunView<'a> {
    /// The operation invoked, as the caller named it.
    task: &'a str,
    /// This invocation's id — what `sbx task show`/`stop`/`logs` take. `null` when the plane refused
    /// before admitting the request (an exhausted quota), where no invocation exists to name.
    id: Option<u64>,
    /// The command's own exit status, or `null` when nothing ran (`error` says why).
    exit: Option<i32>,
    /// The captured streams, **after** credential substitution. `null` is a stream the declaration
    /// withholds (`stdout = "hide"`), which is not the same as an empty one.
    stdout: Option<&'a str>,
    stderr: Option<&'a str>,
    /// The command was killed at the operation's `timeout`.
    timed_out: bool,
    /// A person ended it with `sbx task stop`. Distinct from `timed_out`: same lever, different
    /// event.
    stopped: bool,
    /// A stream reached `max_output` and what follows it is missing.
    truncated: bool,
    elapsed_ms: u64,
    /// How many credential values were substituted out of the output.
    redacted: usize,
    /// This invocation's substitution nonce, when the operation enabled it — the out-of-band half of
    /// an unforgeable `${NAME@nonce}` placeholder.
    nonce: Option<&'a str>,
    /// What `spawn` refused, each as the program that reached and the one it reached for. Empty
    /// unless the operation confines exec.
    refused: Vec<RunRefusalView<'a>>,
    /// Where the invocation left its artifacts, when the operation declares `output`.
    output: Option<RunOutputView<'a>>,
    /// Why the plane refused, or `null`. Non-null means nothing was executed.
    error: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct RunOutputView<'a> {
    path: &'a str,
    bytes: u64,
}

/// A detached start, as a machine reads it. Its own document rather than a [`RunView`] with most
/// fields empty: nothing has run yet, so an `exit` of `0` and an `elapsed_ms` of `0` would be
/// answers to questions that have not been asked. What exists at this point is the id.
#[derive(serde::Serialize)]
struct DetachView<'a> {
    task: &'a str,
    /// The invocation to collect with `sbx task result`. `null` when the plane refused before
    /// admitting the request, where no invocation exists to name.
    id: Option<u64>,
    /// True once the invocation is running; false alongside an `error`, where nothing started.
    detached: bool,
    /// Why the plane refused, or `null`.
    error: Option<&'a str>,
}

/// One refused `execve`. Two fields rather than one rendered string, because a reader that parses
/// this is deciding which node to add the target to, and that is `caller`'s answer.
#[derive(serde::Serialize)]
struct RunRefusalView<'a> {
    /// The program that issued it, or `null` where the policy decided by target alone.
    caller: Option<&'a str>,
    target: &'a str,
}

/// The document's model. Pure, so what the fields mean is pinned by a test rather than by a live
/// invocation: every value is already substituted and redacted host-side by the time it arrives here,
/// which is what makes encoding it safe — a credential containing a quote would survive escaping,
/// and the needles that find it match raw bytes.
fn run_view<'a>(name: &'a str, result: &'a client::RunResult) -> RunView<'a> {
    RunView {
        task: name,
        // Drawn after admission, so a zero is the plane declining before any invocation existed.
        id: (result.id != 0).then_some(result.id),
        exit: result.error.is_none().then_some(result.exit),
        stdout: result.stdout.as_deref(),
        stderr: result.stderr.as_deref(),
        timed_out: result.timed_out,
        stopped: result.stopped,
        truncated: result.truncated,
        elapsed_ms: result.elapsed_ms,
        redacted: result.redacted,
        nonce: result.nonce.as_deref(),
        refused: result
            .refused
            .iter()
            .map(|r| RunRefusalView {
                caller: (!r.caller.is_empty()).then_some(r.caller.as_str()),
                target: &r.target,
            })
            .collect(),
        output: result.output.as_ref().map(|(path, bytes)| RunOutputView {
            path,
            bytes: *bytes,
        }),
        error: result.error.as_deref(),
    }
}

/// Print one invocation as a JSON document and return the same exit code the prose path would.
///
/// A refusal is a document too — a caller that parses stdout must not have to fall back to reading
/// prose off stderr to learn that nothing ran.
fn run_as_json(name: &str, result: &client::RunResult) -> ExitCode {
    let view = run_view(name, result);
    if let Err(code) = print_json("task run", &view) {
        return code;
    }
    match result.error {
        Some(_) => ExitCode::from(REFUSED_EXIT),
        None => ExitCode::from(result.exit.clamp(0, 255) as u8),
    }
}

/// `sbx task status [<invocation>|<operation>] [--session <id>]`: the invocations running right now,
/// across every session offering operations unless one is named.
fn task_status(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "status") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let planes = match planes_for(listing.session.as_deref(), "status", Side::Host) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let all = match gather(&planes, "status", |p| {
        sandbox::task_control::read_status(&p.socket)
    }) {
        Ok(rows) => rows,
        Err(code) => return code,
    };
    for plane in &planes {
        plane.announce();
    }
    let rows: Vec<(String, sandbox::task_control::StatusRow)> = match &listing.operation {
        None => all,
        // An id or a name, the same way `stop` takes either — the id is what a stopped invocation's
        // report names, and asking after it is the first thing a reader does with it.
        Some(target) => match target.parse::<u64>() {
            Ok(id) => all.into_iter().filter(|(_, r)| r.id == id).collect(),
            Err(_) => all
                .into_iter()
                .filter(|(_, r)| key_values(&r.fields).get("task") == Some(&target.as_str()))
                .collect(),
        },
    };
    if rows.is_empty() {
        let Some(target) = &listing.operation else {
            println!("no operation is running");
            return ExitCode::SUCCESS;
        };
        // An id names an invocation, which either runs or is over — there is no inventory to check
        // it against, and where it went is a question the log answers.
        if target.parse::<u64>().is_ok() {
            println!("invocation {target} is not running");
            diag::hint("       `sbx task logs` holds it if it has already finished.");
            return ExitCode::SUCCESS;
        }
        return empty_or_unknown(
            &planes,
            "status",
            target,
            &format!("`{target}` is not running"),
        );
    }
    let sessions: Vec<String> = rows.iter().map(|(s, _)| s.clone()).collect();
    let mut table: Vec<Vec<String>> = rows
        .iter()
        .map(|(_, row)| {
            let f = key_values(&row.fields);
            vec![
                row.id.to_string(),
                f.get("task").copied().unwrap_or(NONE).to_string(),
                f.get("elapsed_ms")
                    .and_then(|v| v.parse().ok())
                    .map(format_elapsed)
                    .unwrap_or_else(|| NONE.to_string()),
                f.get("pid").copied().unwrap_or(NONE).to_string(),
                // Detached is part of the state rather than a column of its own: a reader looking at
                // a live invocation wants one answer to "what is this doing", and an invocation is
                // either being waited for or not. `stopping` still wins — it is the more urgent fact.
                match (f.get("stopping"), f.get("detached")) {
                    (Some(&"1"), _) => "stopping".to_string(),
                    (_, Some(&"1")) => "detached".to_string(),
                    _ => "running".to_string(),
                },
            ]
        })
        .collect();
    let mut headers = vec!["ID", "OPERATION", "ELAPSED", "PID", "STATE"];
    let mut align = vec![
        Align::Right,
        Align::Left,
        Align::Right,
        Align::Right,
        Align::Left,
    ];
    with_session_column(
        spans_sessions(&planes),
        &mut headers,
        &mut align,
        &mut table,
        &sessions,
    );
    print_table(&headers, &align, &table);
    ExitCode::SUCCESS
}

/// The running invocations of one operation, or all of them when no name narrows it.
fn filter_by_operation(
    rows: &[sandbox::task_control::StatusRow],
    operation: Option<&str>,
) -> Vec<sandbox::task_control::StatusRow> {
    match operation {
        None => rows.to_vec(),
        Some(name) => rows
            .iter()
            .filter(|r| key_values(&r.fields).get("task") == Some(&name))
            .cloned()
            .collect(),
    }
}

/// Whether a target that several planes answered is one this side must not choose between.
///
/// An invocation id comes from a per-process counter ([`sandbox::task::next_invocation`]), so every
/// session numbers its invocations from 1 and the same number names a different run in each:
/// rendering whichever plane answered first would show a reader another session's invocation under
/// the id they asked about, complete with its operation, exit code and elapsed time. An operation
/// *name* means the same thing wherever it is declared, so there the first answer stands and the
/// rest are named — the read-across-sessions this verb exists to give.
fn ambiguous_across_sessions(target: &str, answers: usize) -> bool {
    answers > 1 && target.parse::<u64>().is_ok()
}

/// `sbx task show <invocation>|<operation> [--session <id>]`: everything about one of them.
///
/// The listings answer "what is there" in one line each; this answers "what is *that*" in full — the
/// command with its parameters substituted in, the ceilings it runs under, what it may reach, and
/// which credentials it carries. Host-only, on the same socket as `status` and `stop`.
///
/// An id that resolves in more than one session is refused the way the acting verbs refuse an
/// ambiguous session, naming them and asking for `--session`: ids are drawn per session, so the
/// alternative is answering about a run the reader did not ask about.
///
/// **Never an environment value.** A task's credentials are resolved for one invocation and held
/// nowhere this can reach, so their absence here is structural rather than a filter that could be
/// forgotten; what is shown is their names, which is what a substituted value is reported as anyway.
fn task_show(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "show") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let Some(target) = listing.operation else {
        diag::error("sbx: task show: name an invocation id or an operation");
        eprint!(
            "{}",
            help::page_usage(&["task", "show"]).unwrap_or_default()
        );
        return ExitCode::from(2);
    };
    let planes = match planes_for(listing.session.as_deref(), "show", Side::Host) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // Every plane that knows the target is asked before any of them is rendered: whether the first
    // answer may stand depends on how many others there are, and for an id it may not.
    let mut answers: Vec<(&Plane, Vec<(String, String)>)> = Vec::new();
    for plane in &planes {
        if let Ok(fields) = sandbox::task_control::read_info(&plane.socket, &target) {
            answers.push((plane, fields));
        }
    }
    if ambiguous_across_sessions(&target, answers.len()) {
        diag::error(&format!(
            "sbx: task show: invocation `{target}` exists in {} sessions — name one with \
             `--session`",
            answers.len()
        ));
        for (plane, _) in &answers {
            diag::hint(&format!("       {}", plane.describe()));
        }
        return ExitCode::from(2);
    }
    let Some((plane, fields)) = answers.first() else {
        diag::error(&format!(
            "sbx: task show: nothing here is called `{target}`"
        ));
        diag::hint(
            "       `sbx task status` lists what is running, `sbx task ls` what is declared.",
        );
        return ExitCode::FAILURE;
    };
    // Only an operation name reaches here with more than one answer, so the note below is about a
    // name declared in several sessions — an id that collided was refused above.
    let also: Vec<String> = answers.iter().skip(1).map(|(p, _)| p.cell()).collect();
    plane.announce();
    // Where a value came from, when it is not from the operation's own block. Not a row of its own:
    // it says where the row it names got its value, which belongs beside that value rather than
    // under it as a field a reader has to pair up by eye.
    let provenance: BTreeMap<&str, &str> = fields
        .iter()
        .filter_map(|(key, value)| Some((key.strip_suffix("_from")?, value.as_str())))
        .collect();
    // The plane sends data and this side renders it, the same split the log has: an epoch crosses
    // the wire, a time of day reaches the reader — and a field whose label names its unit loses the
    // unit once the value carries it.
    let shown: Vec<(String, String, Option<&str>)> = fields
        .iter()
        .filter(|(key, _)| !key.ends_with("_from"))
        .map(|(key, value)| {
            let (label, text) = match (key.as_str(), value.parse::<u128>()) {
                ("finished_at", Ok(v)) => (
                    "finished".into(),
                    crate::format_log_time(sandbox::task_control::epoch_ms(v)),
                ),
                ("elapsed_ms", Ok(ms)) => ("elapsed".into(), format_elapsed(ms as u64)),
                ("timeout_s", Ok(s)) => ("timeout".into(), format_elapsed(s as u64 * 1000)),
                _ => (key.clone(), value.clone()),
            };
            // Looked up under the key the *plane* sent, not the label: the rename above is this
            // side's presentation and the pairing is the plane's.
            (label, text, provenance.get(key.as_str()).copied())
        })
        .collect();
    let width = shown.iter().map(|(k, _, _)| k.len()).max().unwrap_or(0);
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    for (key, value, from) in &shown {
        match from {
            Some(from) => println!(
                "{}{key:<width$}{}  {value}  {}({from}){}",
                pal.head, pal.reset, pal.dim, pal.reset
            ),
            None => println!("{}{key:<width$}{}  {value}", pal.head, pal.reset),
        }
    }
    if !also.is_empty() {
        diag::note(&format!(
            "`{target}` is also declared in session(s) {} — name one with `--session`",
            also.join(", ")
        ));
    }
    ExitCode::SUCCESS
}

/// A duration a person reads at a glance, at the scale an invocation actually takes: milliseconds
/// under a second, then seconds, then minutes. `format_age` is for sessions, which live in hours.
fn format_elapsed(ms: u64) -> String {
    match ms {
        ms if ms < 1_000 => format!("{ms}ms"),
        ms if ms < 60_000 => format!("{}.{}s", ms / 1_000, (ms % 1_000) / 100),
        ms => format!("{}m{:02}s", ms / 60_000, (ms % 60_000) / 1_000),
    }
}

/// `sbx task stop <invocation|operation> [--session <id>]`: end one running invocation.
///
/// Named either way, because both are things a person has in front of them: the id `sbx task status`
/// shows, or the operation's own name when only one invocation of it is running. A number is read as
/// an id first — an operation named `42` would be reachable through `status` — and a name matching
/// several running invocations is an error listing them rather than a guess at which to end.
fn task_stop(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "stop") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let Some(target) = listing.operation else {
        diag::error("sbx: task stop: name the invocation to stop, as `sbx task status` shows it");
        eprint!(
            "{}",
            help::page_usage(&["task", "stop"]).unwrap_or_default()
        );
        return ExitCode::from(2);
    };
    let plane = match plane_for(listing.session.as_deref(), "stop", Side::Host) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let socket = plane.socket;
    let id = match target.parse::<u64>() {
        Ok(id) => id,
        Err(_) => {
            let running = match sandbox::task_control::read_status(&socket) {
                Ok(rows) => rows,
                Err(e) => return unreachable_plane(&e),
            };
            let matching = filter_by_operation(&running, Some(&target));
            match matching.as_slice() {
                [] => {
                    diag::error(&format!("sbx: task stop: `{target}` is not running"));
                    diag::hint("       `sbx task status` lists what is.");
                    return ExitCode::FAILURE;
                }
                [one] => one.id,
                many => {
                    diag::error(&format!(
                        "sbx: task stop: {} invocations of `{target}` are running — name one by id",
                        many.len()
                    ));
                    diag::hint(&format!(
                        "       ids: {}",
                        many.iter()
                            .map(|r| r.id.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    return ExitCode::from(2);
                }
            }
        }
    };
    match sandbox::task_control::stop_invocation(&socket, id) {
        Ok(sandbox::task_control::StopReply::Stopped) => {
            println!("stopped invocation {id}");
            ExitCode::SUCCESS
        }
        // Accepted but not yet done, and said as exactly that: everything under way before the
        // command spawned — a credential resolving, a proxy standing up — completes first.
        Ok(sandbox::task_control::StopReply::Stopping) => {
            diag::warn(&format!(
                "invocation {id} was asked to stop and is still finishing"
            ));
            diag::hint("       `sbx task status` shows it until it ends.");
            ExitCode::FAILURE
        }
        Ok(sandbox::task_control::StopReply::Finished) => {
            diag::note(&format!("invocation {id} had already finished"));
            ExitCode::SUCCESS
        }
        Ok(sandbox::task_control::StopReply::Refused(reason)) => {
            diag::error(&format!("sbx: task stop: {reason}"));
            diag::hint("       `sbx task status` lists what is running.");
            ExitCode::FAILURE
        }
        Err(e) => unreachable_plane(&e),
    }
}

/// `sbx task logs [<operation>] [--session <id>]`: the session's invocation log — host-only, by
/// design.
fn task_logs(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "logs") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let planes = match planes_for(listing.session.as_deref(), "logs", Side::Host) {
        Ok(p) => p,
        Err(code) => return code,
    };
    // Read through the typed reader the writer is pinned against, never by re-parsing the wire:
    // `LogEntry::to_line`/`from_line` are round-tripped by a test, and a second hand-rolled reader
    // is exactly the drift that test cannot catch — it would drop entries, or file them wrongly, in
    // the record whose whole job is to miss nothing.
    let dropped: std::cell::RefCell<Vec<(String, u64)>> = std::cell::RefCell::new(Vec::new());
    let entries = match gather(&planes, "logs", |p| {
        let (entries, _head, fell_out) = sandbox::task_control::read_entries(&p.socket, None)?;
        if fell_out > 0 {
            dropped.borrow_mut().push((p.cell(), fell_out));
        }
        Ok(entries)
    }) {
        Ok(entries) => entries,
        Err(code) => return code,
    };
    for plane in &planes {
        plane.announce();
    }
    for (session, fell_out) in dropped.borrow().iter() {
        diag::warn(&format!(
            "{fell_out} older invocation(s) fell out of session {session}'s log ring"
        ));
    }
    let mut rows = Vec::new();
    let mut sessions = Vec::new();
    for (session, entry) in &entries {
        // An id or an operation name, the same way `status` and `stop` take either — the id in a
        // result is what a reader has in front of them, and the log is where a finished invocation
        // went. Narrowing here rather than in the log keeps the wire one shape and the filter one
        // place; asking the entry rather than its rendered cells is what lets the filter say `seq
        // 0 matches nothing` directly, since no invocation stands behind such an entry.
        let keeps = match listing.operation.as_deref() {
            None => true,
            Some(target) => match target.parse::<u64>() {
                Ok(id) => entry.seq != 0 && entry.seq == id,
                Err(_) => entry.task == target,
            },
        };
        if keeps {
            rows.push(log_row(entry));
            sessions.push(session.clone());
        }
    }
    if rows.is_empty() {
        let Some(target) = &listing.operation else {
            println!("no invocations recorded");
            return ExitCode::SUCCESS;
        };
        if target.parse::<u64>().is_ok() {
            println!("no invocation {target} recorded");
            return ExitCode::SUCCESS;
        }
        return empty_or_unknown(
            &planes,
            "logs",
            target,
            &format!("no invocation of `{target}` recorded"),
        );
    }
    let mut headers = vec!["ID", "TIME", "OPERATION", "EXIT", "TOOK", "NOTE"];
    let mut align = vec![
        Align::Right,
        Align::Left,
        Align::Left,
        Align::Right,
        Align::Right,
        Align::Left,
    ];
    with_session_column(
        spans_sessions(&planes),
        &mut headers,
        &mut align,
        &mut rows,
        &sessions,
    );
    print_table(&headers, &align, &rows);
    ExitCode::SUCCESS
}

/// One recorded invocation as a table row.
///
/// Takes the typed entry, not the wire line: the refusal reason is free text and always last on the
/// wire, and reading it back by hand is what let a reason containing a space be parsed as more
/// fields. [`sandbox::task_control::LogEntry::from_line`] owns that rule for every reader.
fn log_row(e: &sandbox::task_control::LogEntry) -> Vec<String> {
    // What is worth saying about an invocation beyond its exit code — a refusal first, since then
    // nothing ran and the other fields describe nothing.
    let note = match &e.refused {
        Some(reason) => format!("refused: {reason}"),
        None => {
            let mut notes = Vec::new();
            // First, because it says who was there to see the rest: nobody waited for this one, so
            // whatever it printed went to the result ring rather than to a terminal.
            if e.detached {
                notes.push("detached".to_string());
            }
            if e.stopped {
                notes.push("stopped".to_string());
            }
            if e.timed_out {
                notes.push("timed out".to_string());
            }
            if e.truncated {
                notes.push("output truncated".to_string());
            }
            if e.redacted > 0 {
                notes.push(format!("{} credential value(s) substituted", e.redacted));
            }
            notes.join(", ")
        }
    };
    vec![
        match e.seq {
            // The one entry no invocation stands behind: refused before it was ever admitted.
            0 => NONE.to_string(),
            seq => seq.to_string(),
        },
        crate::format_log_time(sandbox::task_control::epoch_ms(e.at_epoch_ms)),
        e.task.clone(),
        match e.refused.is_some() {
            // A refusal's `-1` is a sentinel, not an exit code; the note already says what happened.
            true => NONE.to_string(),
            false => e.exit.to_string(),
        },
        format_elapsed(e.elapsed_ms),
        note,
    ]
}

/// What every listing verb takes: which operation to narrow to, and which session to ask.
///
/// The positional is the **operation**, uniformly across the surface — it is the thing these verbs
/// are about, and `--session` names the session everywhere including `run` and `stop`. A session id
/// sitting in the positional slot was the one place the surface disagreed with itself, and it read
/// as an operation name to everyone who tried it.
struct Listing {
    operation: Option<String>,
    session: Option<String>,
}

fn listing_args(args: &[OsString], verb: &str) -> Result<Listing, ExitCode> {
    let mut listing = Listing {
        operation: None,
        session: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--session") => match args.get(i + 1).and_then(|a| a.to_str()) {
                Some(v) => {
                    listing.session = Some(v.to_string());
                    i += 2;
                }
                None => {
                    diag::error(&format!("sbx: task {verb}: `--session` needs a session id"));
                    return Err(ExitCode::from(2));
                }
            },
            Some(s) if !s.starts_with('-') && listing.operation.is_none() => {
                listing.operation = Some(s.to_string());
                i += 1;
            }
            other => {
                diag::error(&format!(
                    "sbx: task {verb}: unexpected argument {:?}",
                    other.unwrap_or_default()
                ));
                eprint!("{}", help::page_usage(&["task", verb]).unwrap_or_default());
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(listing)
}

/// Report a filter that matched nothing, naming what *is* there — the answer to "did I misspell it
/// or is it not running?" is the list, and a bare "no match" leaves the reader to go and ask.
fn no_match(verb: &str, operation: &str, known: &[String]) -> ExitCode {
    diag::error(&format!(
        "sbx: task {verb}: no operation `{operation}` here"
    ));
    if !known.is_empty() {
        diag::hint(&format!("       this session offers: {}", known.join(", ")));
    }
    ExitCode::FAILURE
}

/// Read one listing from every plane, keeping each answer beside the plane that gave it.
///
/// A plane that has gone since it was listed is reported and skipped rather than taken as an empty
/// answer: a session ending between the listing and the read is ordinary, and silently showing one
/// session's rows as if they were all of them would be a lie about what is out there.
fn gather<T>(
    planes: &[Plane],
    verb: &str,
    read: impl Fn(&Plane) -> std::io::Result<Vec<T>>,
) -> Result<Vec<(String, T)>, ExitCode> {
    let mut rows = Vec::new();
    let mut reached = 0usize;
    let mut last: Option<std::io::Error> = None;
    for plane in planes {
        match read(plane) {
            Ok(found) => {
                reached += 1;
                rows.extend(found.into_iter().map(|row| (plane.cell(), row)));
            }
            Err(e) => {
                if planes.len() > 1 {
                    diag::warn(&format!(
                        "session {} did not answer ({e}) — its operations are not listed",
                        plane.cell()
                    ));
                }
                last = Some(e);
            }
        }
    }
    match (reached, last) {
        // Nothing answered at all: that is the plane being unreachable, not an empty listing.
        (0, Some(e)) => {
            let _ = verb;
            Err(unreachable_plane(&e))
        }
        _ => Ok(rows),
    }
}

/// Whether a listing spans more than one session — the one condition under which the rows need to
/// say which session each came from.
fn spans_sessions(planes: &[Plane]) -> bool {
    planes.len() > 1
}

/// Put the session column in front of a table when the listing spans several.
fn with_session_column(
    multi: bool,
    headers: &mut Vec<&'static str>,
    align: &mut Vec<Align>,
    rows: &mut [Vec<String>],
    sessions: &[String],
) {
    if !multi {
        return;
    }
    headers.insert(0, "SESSION");
    align.insert(0, Align::Right);
    for (row, session) in rows.iter_mut().zip(sessions) {
        row.insert(0, session.clone());
    }
}

/// An empty answer to a narrowed listing, told apart from a misspelled name.
///
/// The two look identical from the filter alone — nothing matched either way — and they are opposite
/// things: one is a real result, the other is a typo that would otherwise read as one. The inventory
/// is what separates them, so it is asked for **only** on the empty path, where the answer changes
/// what to say.
fn empty_or_unknown(planes: &[Plane], verb: &str, operation: &str, empty: &str) -> ExitCode {
    let mut known: Vec<String> = planes
        .iter()
        .filter_map(|p| client::list(&p.inventory).ok())
        .flatten()
        .map(|r| r.name)
        .collect();
    known.sort();
    known.dedup();
    if !known.is_empty() && !known.iter().any(|n| n == operation) {
        return no_match(verb, operation, &known);
    }
    println!("{empty}");
    ExitCode::SUCCESS
}

/// Split a `KEY=VALUE` argument. A missing `=` is an error rather than an empty value: a parameter a
/// caller believes it set must never silently become nothing.
fn pair(arg: Option<&OsString>, flag: &str) -> Result<(String, String), ExitCode> {
    let Some(raw) = arg.and_then(|a| a.to_str()) else {
        diag::error(&format!("sbx: task run: `{flag}` needs KEY=VALUE"));
        return Err(ExitCode::from(2));
    };
    match raw.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => {
            diag::error(&format!("sbx: task run: `{flag} {raw}` is not KEY=VALUE"));
            Err(ExitCode::from(2))
        }
    }
}

/// Report a plane that could not be reached. The common causes are a session that has ended and a
/// config that declares no operation, so say both rather than only the errno.
fn unreachable_plane(e: &std::io::Error) -> ExitCode {
    diag::error(&format!("sbx: task: cannot reach the task plane: {e}"));
    diag::hint("       the session may have ended, or its config declares no `[task.<name>]`.");
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, fields: &[&str]) -> client::TaskRow {
        client::TaskRow {
            name: name.to_string(),
            fields: fields.iter().map(|f| (*f).to_string()).collect(),
        }
    }

    /// A cage reaches one plane, the crossing one, and it offers the inventory and the invocations
    /// and nothing else. The acting verbs said so; the listing verbs went through a path that does
    /// not look at `side` at all, so they were handed the crossing socket and the caller got
    /// `err unknown command` for a verb that is not missing but withheld. Same rule, one function.
    #[test]
    fn a_host_side_verb_inside_a_cage_says_which_side_it_belongs_to() {
        use crate::testutil::{EnvVar, env_lock};
        let _lock = env_lock();
        let _sock = EnvVar::set(TASK_SOCKET_ENV, "/run/sbx-task/control.sock");

        // The listing verbs, which took the crossing socket and asked it for a host verb.
        for verb in ["logs", "status", "show"] {
            assert!(
                planes_for(None, verb, Side::Host).is_err(),
                "`sbx task {verb}` must be refused in a cage, not sent to the wrong socket"
            );
        }
        // The acting verbs, which were already refused.
        for verb in ["stop", "result"] {
            assert!(plane_for(None, verb, Side::Host).is_err());
        }
        // The crossing side is what a cage may reach, and both entry points still give it.
        assert!(plane_for(None, "run", Side::Cage).is_ok());
        assert!(planes_for(None, "ls", Side::Cage).is_ok());
    }

    /// A column every row answers the same way is not information. The default case — nothing
    /// hidden, no output directory, every tool present — must print three columns, not seven.
    #[test]
    fn the_listing_drops_the_columns_that_say_the_same_thing_on_every_line() {
        let table = list_table(
            &[
                row(
                    "quick",
                    &["params=", "stdout=show", "stderr=show", "timeout=30s", ""],
                ),
                row(
                    "slow",
                    &[
                        "params=n",
                        "stdout=show",
                        "stderr=show",
                        "timeout=120s",
                        "counts slowly",
                    ],
                ),
            ],
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(
            table.headers,
            vec!["NAME", "PARAMS", "TIMEOUT", "DESCRIPTION"]
        );
        assert!(!table.output && !table.missing);
        assert_eq!(
            table.rows[0],
            vec!["quick", "-", "30s", ""],
            "an operation with no parameters says so rather than leaving a hole"
        );
    }

    /// And they come back the moment one row differs — a hidden stream, an output directory or a
    /// missing tool is exactly what a reader must not have to go and ask about.
    #[test]
    fn a_listing_shows_what_one_operation_alone_makes_worth_showing() {
        let table = list_table(
            &[
                row(
                    "quiet",
                    &["params=", "stdout=hide", "stderr=show", "timeout=30s", ""],
                ),
                row(
                    "dump",
                    &[
                        "params=",
                        "stdout=show",
                        "stderr=show",
                        "timeout=30s",
                        "output=/opt/sbx/task-out/dump",
                        "missing-tools=pg_dump",
                        "",
                    ],
                ),
            ],
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(
            table.headers,
            vec![
                "NAME",
                "PARAMS",
                "TIMEOUT",
                "STDOUT",
                "STDERR",
                "OUTPUT",
                "MISSING TOOLS"
            ],
            "one hidden stream is enough to make the disposition worth a column"
        );
        assert!(
            table.output && table.missing,
            "and both notes are called for"
        );
        assert_eq!(
            table.rows[0],
            vec!["quiet", "-", "30s", "hide", "show", "-", "-"]
        );
        assert_eq!(
            table.rows[1],
            vec!["dump", "-", "30s", "show", "show", "yes", "pg_dump"]
        );
    }

    /// A recorded invocation reads as a row, and its refusal reason — free text, with spaces, always
    /// last — is not mistaken for more fields.
    #[test]
    fn a_log_line_becomes_a_row_and_its_reason_survives_its_spaces() {
        // The wire strings stay here and are read by the one reader the writer is pinned against,
        // so this keeps testing the format end to end rather than a second parser's idea of it.
        let entry = |line: &str| sandbox::task_control::LogEntry::from_line(line);
        let ran = log_row(
            &entry(
                "event seq=4 cur=1 at=1785445489000 exit=137 redacted=2 truncated=0 timed_out=0 \
                 stopped=1 elapsed_ms=3021 task=slow-count",
            )
            .expect("an event parses"),
        );
        assert_eq!(ran[0], "4");
        // `at=` is epoch milliseconds, as every feed's stamp is. Read as seconds it would land tens
        // of thousands of years out, so pinning that it renders a time of day at all is what keeps
        // the two sides of this wire on one unit.
        assert_eq!(ran[1].len(), 8, "a local HH:MM:SS: {}", ran[1]);
        assert_eq!(ran[1].matches(':').count(), 2, "{}", ran[1]);
        assert_eq!(ran[2], "slow-count");
        assert_eq!(ran[3], "137");
        assert_eq!(ran[4], "3.0s");
        assert_eq!(
            ran[5], "stopped, 2 credential value(s) substituted",
            "the notes are what the columns cannot say"
        );

        let refused = log_row(
            &entry(
                "event seq=0 cur=2 at=1785445489000 exit=-1 redacted=0 timed_out=0 truncated=0 \
                 stopped=0 elapsed_ms=0 task=db-query refused=parameter `sql` does not match its \
                 declared pattern",
            )
            .expect("a refusal parses too"),
        );
        assert_eq!(ran.len(), refused.len(), "one shape for every row");
        assert_eq!(refused[0], NONE, "nothing was admitted, so no id names it");
        assert_eq!(refused[3], NONE, "and -1 is a sentinel, not an exit code");
        assert_eq!(
            refused[5], "refused: parameter `sql` does not match its declared pattern",
            "the reason keeps its spaces"
        );

        assert!(entry("ok").is_none(), "only events are entries");
    }

    /// `ls` is the word this product uses for what is live (`sbx session ls`), so the inventory says
    /// what is running when anything is — and stays the plain inventory when nothing is.
    #[test]
    fn the_inventory_says_what_is_running_only_when_something_is() {
        let rows = [
            row("quick", &["params=", "timeout=30s", ""]),
            row("slow", &["params=", "timeout=120s", ""]),
        ];
        let sessions = ["4081336".to_string(), "4081336".to_string()];

        let idle = list_table(&rows, &BTreeMap::new(), &sessions);
        assert_eq!(idle.headers, vec!["NAME", "PARAMS", "TIMEOUT"]);

        let live = BTreeMap::from([(("4081336".to_string(), "slow".to_string()), 2)]);
        let busy = list_table(&rows, &live, &sessions);
        assert_eq!(busy.headers, vec!["NAME", "PARAMS", "TIMEOUT", "RUNNING"]);
        assert_eq!(busy.rows[0], vec!["quick", "-", "30s", "-"]);
        assert_eq!(
            busy.rows[1],
            vec!["slow", "-", "120s", "2"],
            "the count, not a flag: two invocations of one operation is a thing to know"
        );

        // The count is per *session*: the same operation name in another session is another row.
        let elsewhere = ["999".to_string(), "999".to_string()];
        let other = list_table(&rows, &live, &elsewhere);
        assert_eq!(
            other.headers,
            vec!["NAME", "PARAMS", "TIMEOUT"],
            "another session's invocation must not mark this session's operation as running"
        );
    }

    /// An invocation's duration is read at the scale it happens on.
    #[test]
    fn an_elapsed_time_reads_at_the_scale_it_happened() {
        assert_eq!(format_elapsed(0), "0ms");
        assert_eq!(format_elapsed(312), "312ms");
        assert_eq!(format_elapsed(5_002), "5.0s");
        assert_eq!(format_elapsed(59_999), "59.9s");
        assert_eq!(format_elapsed(70_000), "1m10s");
        assert_eq!(format_elapsed(3_600_000), "60m00s");
    }

    /// The description is the last field and may itself contain `=`, so it is taken by position.
    #[test]
    fn a_description_carrying_an_equals_sign_is_not_read_as_a_field() {
        let wire = [
            "params=sql".to_string(),
            "timeout=30s".to_string(),
            "run with LANG=C".to_string(),
        ];
        let (fields, description) = split_fields(&wire);
        assert_eq!(fields.get("params"), Some(&"sql"));
        assert_eq!(fields.len(), 2, "the trailing text is not a field");
        assert_eq!(description, "run with LANG=C");
    }

    /// Where each operation is declared earns a column when the rows disagree, and only then — one
    /// project whose whole set comes from one file gets the same table it always had, and
    /// `sbx task show <name>` says it either way.
    #[test]
    fn the_listing_names_where_an_operation_is_declared_only_when_the_rows_disagree() {
        let same = list_table(
            &[
                row("a", &["params=", "timeout=30s", "declared-in=project", ""]),
                row("b", &["params=", "timeout=30s", "declared-in=project", ""]),
            ],
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(
            same.headers,
            vec!["NAME", "PARAMS", "TIMEOUT"],
            "one origin on every line says nothing a reader did not already know"
        );

        let mixed = list_table(
            &[
                row("a", &["params=", "timeout=30s", "declared-in=project", ""]),
                row(
                    "b",
                    &["params=", "timeout=30s", "declared-in=bundle:psql", ""],
                ),
                row(
                    "c",
                    &["params=", "timeout=30s", "declared-in=app:agent", ""],
                ),
            ],
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(
            mixed.headers,
            vec!["NAME", "PARAMS", "TIMEOUT", "DECLARED IN"]
        );
        assert_eq!(mixed.rows[0], vec!["a", "-", "30s", "project"]);
        assert_eq!(mixed.rows[1], vec!["b", "-", "30s", "bundle:psql"]);
        assert_eq!(mixed.rows[2], vec!["c", "-", "30s", "app:agent"]);
    }

    /// A ran invocation as a document: the streams inside it, and everything the prose path would
    /// have said on stderr as a field beside them.
    #[test]
    fn a_json_result_carries_the_streams_and_every_prose_warning_as_a_field() {
        let result = client::RunResult {
            id: 7,
            exit: 3,
            stdout: Some("id\n1\n".to_string()),
            stderr: Some(String::new()),
            redacted: 2,
            truncated: true,
            timed_out: true,
            stopped: false,
            elapsed_ms: 412,
            nonce: Some("a91f3c".to_string()),
            error: None,
            refused: vec![crate::sandbox::proc_enforce::Refusal {
                caller: "/nix/store/x/bin/bash".to_string(),
                target: "/nix/store/x/bin/curl".to_string(),
            }],
            output: Some(("/opt/sbx/task-out/dump".to_string(), 4096)),
        };
        let doc: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&run_view("dump", &result)).expect("encode"),
        )
        .expect("decode");
        assert_eq!(doc["task"], "dump");
        assert_eq!(doc["id"], 7);
        assert_eq!(doc["exit"], 3);
        assert_eq!(doc["stdout"], "id\n1\n");
        assert_eq!(doc["elapsed_ms"], 412);
        assert_eq!(doc["redacted"], 2);
        assert_eq!(doc["nonce"], "a91f3c");
        assert_eq!(doc["timed_out"], true);
        assert_eq!(doc["truncated"], true);
        assert_eq!(doc["stopped"], false);
        // Two fields, not one rendered line: a reader parsing this is deciding which node the
        // target belongs under, and that is what `caller` answers.
        assert_eq!(doc["refused"][0]["target"], "/nix/store/x/bin/curl");
        assert_eq!(doc["refused"][0]["caller"], "/nix/store/x/bin/bash");
        assert_eq!(doc["output"]["path"], "/opt/sbx/task-out/dump");
        assert_eq!(doc["output"]["bytes"], 4096);
        assert!(doc["error"].is_null());
    }

    /// A detached start is its own document, carrying what exists at that point and nothing more.
    ///
    /// The absent fields are the assertion. Reusing the result document would have printed `"exit":
    /// 0` and `"elapsed_ms": 0` for a command that has not run — answers to questions nobody asked,
    /// and the first one reads as success.
    #[test]
    fn a_detached_start_reports_its_id_and_claims_no_result() {
        let doc: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&DetachView {
                task: "nightly-dump",
                id: Some(7),
                detached: true,
                error: None,
            })
            .expect("encode"),
        )
        .expect("decode");
        assert_eq!(doc["task"], "nightly-dump");
        assert_eq!(doc["id"], 7);
        assert_eq!(doc["detached"], true);
        assert!(doc["error"].is_null());
        assert!(
            doc.get("exit").is_none() && doc.get("stdout").is_none(),
            "nothing has run, so there is no exit code and no output to report: {doc}"
        );
    }

    /// A refusal is a document too, and it says plainly that nothing started — `detached` is false
    /// beside the reason, so a reader that only checks that field is not misled.
    #[test]
    fn a_refused_detach_says_nothing_started() {
        let doc: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&DetachView {
                task: "nightly-dump",
                id: None,
                detached: false,
                error: Some("this session's task quota is exhausted"),
            })
            .expect("encode"),
        )
        .expect("decode");
        assert!(doc["id"].is_null());
        assert_eq!(doc["detached"], false);
        assert_eq!(doc["error"], "this session's task quota is exhausted");
    }

    /// A withheld stream is `null` and a stream that ran and printed nothing is `""` — the whole
    /// reason the field is nullable rather than always a string.
    #[test]
    fn a_withheld_stream_is_null_and_an_empty_one_is_a_string() {
        let result = client::RunResult {
            stdout: None,
            stderr: Some(String::new()),
            ..Default::default()
        };
        let doc = serde_json::to_value(run_view("quiet", &result)).expect("encode");
        assert!(doc["stdout"].is_null(), "hidden is not the same as empty");
        assert_eq!(doc["stderr"], "");
    }

    /// A refusal is a document too: `error` says why, `exit` is null because nothing ran, and the
    /// pre-admission id (a zero on the wire) is null because no invocation stands behind it.
    #[test]
    fn a_refusal_is_a_document_with_a_null_exit_and_no_invocation() {
        let result = client::RunResult {
            id: 0,
            error: Some("the session's invocation quota is exhausted".to_string()),
            ..Default::default()
        };
        let doc = serde_json::to_value(run_view("dump", &result)).expect("encode");
        assert_eq!(doc["error"], "the session's invocation quota is exhausted");
        assert!(
            doc["exit"].is_null(),
            "nothing ran, so there is no exit code"
        );
        assert!(doc["id"].is_null());

        // An id drawn *after* admission is a real invocation, and survives a refusal that names it.
        let admitted = client::RunResult {
            id: 4,
            error: Some("`sql` does not satisfy its declared bound".to_string()),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(run_view("q", &admitted)).expect("encode")["id"],
            4
        );
    }

    /// An invocation id is per session, so `task show <id>` must not answer from whichever plane
    /// replied first.
    ///
    /// Ids are drawn from a per-process counter and every session starts at 1, so the same number
    /// names a different run in each. Taking the first answer — the lowest pid, since the planes
    /// come sorted — showed the reader another project's operation, exit code and elapsed time
    /// under the id they had asked about. An operation *name* carries no such collision: it means
    /// the same thing wherever it is declared, and reading across sessions is what this verb is
    /// for, so only the id is refused.
    #[test]
    fn an_invocation_id_that_several_sessions_answer_is_refused_rather_than_guessed() {
        assert!(ambiguous_across_sessions("7", 2));
        // One answer is not a choice, and no answer is the miss.
        assert!(!ambiguous_across_sessions("7", 1));
        assert!(!ambiguous_across_sessions("7", 0));
        // A name declared in several sessions still reads across them, the others named in a note.
        assert!(!ambiguous_across_sessions("nightly-dump", 2));
        // A numeric token is an id first, everywhere this surface reads one (`task stop` says so
        // too), so an operation that looks like a number is held to the id's rule.
        assert!(ambiguous_across_sessions("42", 3));
    }
}
