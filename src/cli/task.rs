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

use crate::sandbox::task_control::{client, TASK_SOCKET_ENV};
use std::io::IsTerminal;

use crate::{diag, help, sandbox, store, style};

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

fn layout_or_fail() -> Result<store::Layout, ExitCode> {
    store::Layout::from_env().ok_or_else(|| {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        ExitCode::FAILURE
    })
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

/// The one plane a verb that **acts** must be given: exactly one, named when several exist.
///
/// `$SBX_TASK_SOCKET` short-circuits the search, which is how a specific plane can be addressed
/// without resolving a session. It is also the discovery handle the cage advertises, so a tool that
/// wants to find the plane looks in one place whichever side it is on.
fn plane_for(id: Option<&str>, verb: &str, side: Side) -> Result<Plane, ExitCode> {
    if side == Side::Host && std::env::var_os(TASK_SOCKET_ENV).is_some() {
        diag::error(&format!(
            "sbx: task {verb}: this is host-side only — a cage may invoke operations, not watch them"
        ));
        return Err(ExitCode::from(2));
    }
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

/// Print an aligned table: `headers` over `rows`, columns as wide as their widest cell.
///
/// The last column is never padded (it is the free-text one and padding it would trail spaces to the
/// end of every line), and the first is colored — the same shape `sbx session ls` prints, because a
/// listing that reads differently from verb to verb is one the reader has to re-learn each time.
///
/// The header is padded *before* it is colored so the escape sequences never count toward a column's
/// width and the alignment is identical with and without color.
fn print_table(headers: &[&str], align: &[Align], rows: &[Vec<String>]) {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (lines, first) = render_table(headers, align, rows);
    for (i, line) in lines.iter().enumerate() {
        // The header in the header color, and each row's first cell in the name color — the same
        // reading order `sbx session ls` gives, where the eye lands on the identifier. The span is
        // the *rendered* first column, padding included, so a right-aligned id is colored where it
        // sits rather than where its digits would start.
        //
        // `first` counts **characters**, which is what the padding is measured in; the byte index is
        // then looked up rather than assumed equal to it. An operation name with an accent in it
        // would otherwise split the line mid-character — which does not merely misplace the color,
        // it panics.
        let split = line
            .char_indices()
            .nth(first)
            .map_or(line.len(), |(i, _)| i);
        let (head, rest) = line.split_at(split);
        match i {
            0 => println!("{}{line}{}", pal.head, pal.reset),
            _ => println!("{}{head}{}{rest}", pal.name, pal.reset),
        }
    }
}

/// The table's lines, header first, and the width of the first column — the layout with none of the
/// printing, so the alignment is something a test can read rather than something a person eyeballs.
fn render_table(headers: &[&str], align: &[Align], rows: &[Vec<String>]) -> (Vec<String>, usize) {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .filter_map(|r| r.get(i).map(|c| c.chars().count()))
                .chain([h.chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let last = headers.len().saturating_sub(1);
    let line = |cells: &dyn Fn(usize) -> String| -> String {
        (0..headers.len())
            .map(|i| {
                let cell = cells(i);
                match (i == last, align.get(i)) {
                    // The last column is never padded: it is the free-text one, and padding it
                    // would trail spaces to the end of every line.
                    (true, _) => cell,
                    (_, Some(Align::Right)) => format!("{cell:>w$}", w = widths[i]),
                    _ => format!("{cell:<w$}", w = widths[i]),
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut out = vec![line(&|i| headers[i].to_string()).trim_end().to_string()];
    for row in rows {
        out.push(
            line(&|i| row.get(i).cloned().unwrap_or_default())
                .trim_end()
                .to_string(),
        );
    }
    (out, widths.first().copied().unwrap_or(0))
}

/// Which way a column's cells sit against their width.
#[derive(Clone, Copy)]
enum Align {
    Left,
    Right,
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

/// `sbx task run <name> [--param k=v]… [--env K=V]… [--session <id>]`: invoke one operation.
///
/// The exit code is the command's own, so a task composes in a script exactly like the program it
/// wraps; a *refusal* (an unknown task, a value outside its bound) is exit 2, distinguishable from
/// the command having run and failed.
fn task_run(args: &[OsString]) -> ExitCode {
    let mut name: Option<String> = None;
    let mut id: Option<String> = None;
    let mut params = BTreeMap::new();
    let mut env = BTreeMap::new();
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
    if let Some(error) = &result.error {
        diag::error(&format!("sbx: task run: {error}"));
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
        for target in &result.refused {
            eprintln!("  {target}");
        }
        diag::note("this operation declares `spawn`; a program it needs must be listed there.");
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

/// The session's **host-only** socket — the log, what is running, and the stop.
///
/// Refuses outright when the environment says this sbx is talking to a plane rather than owning one:
/// these verbs are host-side by construction (the socket is never bound into a cage), and the
/// explicit refusal is what makes that a message instead of a connection error.
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
                match f.get("stopping") {
                    Some(&"1") => "stopping".to_string(),
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

/// `sbx task show <invocation>|<operation> [--session <id>]`: everything about one of them.
///
/// The listings answer "what is there" in one line each; this answers "what is *that*" in full — the
/// command with its parameters substituted in, the ceilings it runs under, what it may reach, and
/// which credentials it carries. Host-only, on the same socket as `status` and `stop`.
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
    // Across sessions, the first that knows the target answers. An invocation id belongs to exactly
    // one session; an operation name can be declared in several, and then `--session` is how a
    // reader says which — so the others are named rather than silently passed over.
    let mut found: Option<(&Plane, Vec<(String, String)>)> = None;
    let mut also = Vec::new();
    for plane in &planes {
        match sandbox::task_control::read_info(&plane.socket, &target) {
            Ok(fields) if found.is_none() => found = Some((plane, fields)),
            Ok(_) => also.push(plane.cell()),
            Err(_) => {}
        }
    }
    let Some((plane, fields)) = found else {
        diag::error(&format!(
            "sbx: task show: nothing here is called `{target}`"
        ));
        diag::hint(
            "       `sbx task status` lists what is running, `sbx task ls` what is declared.",
        );
        return ExitCode::FAILURE;
    };
    plane.announce();
    // The plane sends data and this side renders it, the same split the log has: an epoch crosses
    // the wire, a time of day reaches the reader — and a field whose label names its unit loses the
    // unit once the value carries it.
    let shown: Vec<(String, String)> = fields
        .iter()
        .map(|(key, value)| match (key.as_str(), value.parse::<u128>()) {
            ("finished_at", Ok(secs)) => ("finished".into(), crate::format_log_time(secs * 1000)),
            ("elapsed_ms", Ok(ms)) => ("elapsed".into(), format_elapsed(ms as u64)),
            ("timeout_s", Ok(s)) => ("timeout".into(), format_elapsed(s as u64 * 1000)),
            _ => (key.clone(), value.clone()),
        })
        .collect();
    let width = shown.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    for (key, value) in &shown {
        println!("{}{key:<width$}{}  {value}", pal.head, pal.reset);
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
    let lines = match gather(&planes, "logs", |p| {
        sandbox::task_control::read_log(&p.socket)
    }) {
        Ok(lines) => lines,
        Err(code) => return code,
    };
    for plane in &planes {
        plane.announce();
    }
    let mut rows = Vec::new();
    let mut sessions = Vec::new();
    for (session, line) in &lines {
        if let Some(dropped) = line.strip_prefix("dropped=") {
            diag::warn(&format!(
                "{dropped} older invocation(s) fell out of session {session}'s log ring"
            ));
            continue;
        }
        // An id or an operation name, the same way `status` and `stop` take either — the id in a
        // result is what a reader has in front of them, and the log is where a finished invocation
        // went. The id is the first cell and the operation the third; narrowing here rather than in
        // the log keeps the wire one shape and the filter one place.
        let Some(row) = log_row(line) else { continue };
        let keeps = match listing.operation.as_deref() {
            None => true,
            Some(target) => match target.parse::<u64>().is_ok() {
                true => row.first().map(String::as_str) == Some(target),
                false => row.get(2).map(String::as_str) == Some(target),
            },
        };
        if keeps {
            rows.push(row);
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

/// One recorded invocation as a table row, or `None` for a line that is not an event.
///
/// The refusal reason is free text and always last, so it is split off *before* the fixed fields are
/// read — a reason containing a space (most of them do) would otherwise be parsed as more fields.
fn log_row(line: &str) -> Option<Vec<String>> {
    let event = line.strip_prefix("event ")?;
    let (head, refused) = match event.split_once(" refused=") {
        Some((head, reason)) => (head, Some(reason)),
        None => (event, None),
    };
    let fields: BTreeMap<&str, &str> = head
        .split_whitespace()
        .filter_map(|f| f.split_once('='))
        .collect();
    let get = |key: &str| fields.get(key).copied().unwrap_or_default();
    let flag = |key: &str| get(key) == "1";

    // What is worth saying about an invocation beyond its exit code — a refusal first, since then
    // nothing ran and the other fields describe nothing.
    let note = match refused {
        Some(reason) => format!("refused: {reason}"),
        None => {
            let mut notes = Vec::new();
            if flag("stopped") {
                notes.push("stopped".to_string());
            }
            if flag("timed_out") {
                notes.push("timed out".to_string());
            }
            if flag("truncated") {
                notes.push("output truncated".to_string());
            }
            match get("redacted").parse::<usize>() {
                Ok(n) if n > 0 => notes.push(format!("{n} credential value(s) substituted")),
                _ => {}
            }
            notes.join(", ")
        }
    };
    Some(vec![
        match get("seq") {
            // The one entry no invocation stands behind: refused before it was ever admitted.
            "0" => NONE.to_string(),
            seq => seq.to_string(),
        },
        get("at")
            .parse::<u128>()
            .map(|secs| crate::format_log_time(secs * 1000))
            .unwrap_or_else(|_| NONE.to_string()),
        get("task").to_string(),
        match refused.is_some() {
            // A refusal's `-1` is a sentinel, not an exit code; the note already says what happened.
            true => NONE.to_string(),
            false => get("exit").to_string(),
        },
        get("elapsed_ms")
            .parse()
            .map(format_elapsed)
            .unwrap_or_else(|_| NONE.to_string()),
        note,
    ])
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

    /// The columns are as wide as their widest cell, and the last one is not padded — a listing
    /// whose columns shift with the data is the one a reader gives up on.
    #[test]
    fn a_table_aligns_on_its_widest_cell_and_leaves_no_trailing_space() {
        let (lines, first) = render_table(
            &["NAME", "N", "NOTE"],
            &[Align::Left, Align::Right, Align::Left],
            &[
                vec!["a".into(), "1000".into(), "one".into()],
                vec!["longer-name".into(), "7".into(), String::new()],
            ],
        );
        assert_eq!(
            lines,
            vec![
                "NAME            N  NOTE",
                "a            1000  one",
                "longer-name     7",
            ],
            "each column takes the width of its widest cell, right-aligned where asked"
        );
        assert_eq!(
            first,
            "longer-name".len(),
            "the first column's rendered width"
        );
        for line in &lines {
            assert_eq!(line.trim_end(), line, "no line may trail spaces: {line:?}");
        }
    }

    /// Widths are counted in characters and the color span is sliced in bytes, so a first cell that
    /// is not ASCII must not be able to split the line mid-character — that is a panic, not a
    /// cosmetic slip. An operation name is config text, so it can hold anything.
    #[test]
    fn a_non_ascii_first_cell_neither_misaligns_nor_splits_a_character() {
        let rows = vec![
            vec!["opération".into(), "1".into()],
            vec!["ab".into(), "2".into()],
        ];
        let (lines, first) = render_table(&["NAME", "N"], &[Align::Left, Align::Left], &rows);
        assert_eq!(
            first,
            "opération".chars().count(),
            "widths count characters"
        );
        assert_eq!(lines, vec!["NAME       N", "opération  1", "ab         2"]);
        for line in &lines {
            // What `print_table` does with the width — it must land on a character boundary.
            let split = line
                .char_indices()
                .nth(first)
                .map_or(line.len(), |(i, _)| i);
            assert!(
                line.is_char_boundary(split),
                "the color span must not split a character: {line:?}"
            );
        }
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
        let ran = log_row(
            "event seq=4 at=1785445489 exit=137 redacted=2 truncated=0 timed_out=0 stopped=1 \
             elapsed_ms=3021 task=slow-count",
        )
        .expect("an event is a row");
        assert_eq!(ran[0], "4");
        assert_eq!(ran[2], "slow-count");
        assert_eq!(ran[3], "137");
        assert_eq!(ran[4], "3.0s");
        assert_eq!(
            ran[5], "stopped, 2 credential value(s) substituted",
            "the notes are what the columns cannot say"
        );

        let refused = log_row(
            "event seq=0 at=1785445489 exit=-1 redacted=0 truncated=0 timed_out=0 stopped=0 \
             elapsed_ms=0 task=db-query refused=parameter `sql` does not match its declared pattern",
        )
        .expect("a refusal is a row too");
        assert_eq!(ran.len(), refused.len(), "one shape for every row");
        assert_eq!(refused[0], NONE, "nothing was admitted, so no id names it");
        assert_eq!(refused[3], NONE, "and -1 is a sentinel, not an exit code");
        assert_eq!(
            refused[5], "refused: parameter `sql` does not match its declared pattern",
            "the reason keeps its spaces"
        );

        assert!(log_row("ok").is_none(), "only events are rows");
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
}
