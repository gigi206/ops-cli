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

/// `sbx task <subcommand>`: `list`, `secrets`, `run`, `status`, `stop`, or `logs`.
pub(crate) fn task_cmd(args: Vec<OsString>) -> ExitCode {
    if let Some(code) = help::maybe_help("task", &args) {
        return code;
    }
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => task_list(&args[1..]),
        Some("secrets") => task_secrets(&args[1..]),
        Some("run") => task_run(&args[1..]),
        Some("status") => task_status(&args[1..]),
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
}

/// The task plane to talk to: a live session's, or the one the environment names outright.
///
/// `$SBX_TASK_SOCKET` short-circuits the search, which is how a specific plane can be addressed
/// without resolving a session. It is also the discovery handle the cage advertises, so a tool that
/// wants to find the plane looks in one place whichever side it is on.
fn plane_for(id: Option<&str>, verb: &str) -> Result<Plane, ExitCode> {
    if let Some(path) = std::env::var_os(TASK_SOCKET_ENV) {
        return Ok(Plane {
            socket: PathBuf::from(path),
            session: None,
        });
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return Err(ExitCode::FAILURE);
    };
    let pid = resolve_task_session(layout.data_dir(), id, verb)?;
    Ok(Plane {
        socket: sandbox::task_control::task_dir(layout.data_dir(), pid).join("control.sock"),
        session: Some((pid, session_project(layout.data_dir(), pid))),
    })
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
        return id.parse::<u32>().map_err(|_| {
            diag::error(&format!("sbx: task {verb}: `{id}` is not a session id"));
            diag::hint("       `sbx session ls` lists them; the id is the session's PID.");
            ExitCode::from(2)
        });
    }
    let pids = sandbox::task_control::session_pids(data_dir);
    match pids.as_slice() {
        [] => {
            diag::error(&format!(
                "sbx: task {verb}: no session is offering declared operations"
            ));
            diag::hint("       a session offers them when its config declares `[task.<name>]`.");
            Err(ExitCode::FAILURE)
        }
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
        let (head, rest) = line.split_at(first.min(line.len()));
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

/// `sbx task list [<id>]`: the operations this session offers, with their parameters and ceilings.
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
    let plane = match plane_for(listing.session.as_deref(), "list") {
        Ok(p) => p,
        Err(code) => return code,
    };
    let all = match client::list(&plane.socket) {
        Ok(rows) => rows,
        Err(e) => return unreachable_plane(&e),
    };
    plane.announce();
    if all.is_empty() {
        println!("no declared operations");
        return ExitCode::SUCCESS;
    }
    let rows: Vec<client::TaskRow> = match &listing.operation {
        None => all,
        Some(name) => {
            let kept: Vec<_> = all.iter().filter(|r| &r.name == name).cloned().collect();
            if kept.is_empty() {
                let known: Vec<String> = all.iter().map(|r| r.name.clone()).collect();
                return no_match("list", name, &known);
            }
            kept
        }
    };

    let table = list_table(&rows);
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

/// Lay the inventory out, keeping only the columns that carry something.
fn list_table(rows: &[client::TaskRow]) -> ListTable {
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

    let mut headers = vec!["NAME", "PARAMS", "TIMEOUT"];
    let mut align = vec![Align::Left, Align::Left, Align::Right];
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
        .map(|(name, f, description)| {
            let cell = |key: &str| match f.get(key).copied() {
                None | Some("") => NONE.to_string(),
                Some(v) => v.to_string(),
            };
            let mut row = vec![(*name).to_string(), cell("params"), cell("timeout")];
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
    let plane = match plane_for(listing.session.as_deref(), "secrets") {
        Ok(p) => p,
        Err(code) => return code,
    };
    let all = match client::secrets(&plane.socket) {
        Ok(rows) => rows,
        Err(e) => return unreachable_plane(&e),
    };
    plane.announce();
    let rows: Vec<String> = match &listing.operation {
        None => all,
        Some(name) => all
            .iter()
            .filter(|r| r.split('\t').any(|f| f == format!("task={name}")))
            .cloned()
            .collect(),
    };
    if rows.is_empty() {
        match &listing.operation {
            Some(name) => println!("`{name}` carries no credentials"),
            None => println!("no credentials are carried by the declared operations"),
        }
        return ExitCode::SUCCESS;
    }
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
    print_table(
        &["NAME", "OPERATION", "DELIVERY", "DESCRIPTION"],
        &[Align::Left; 4],
        &table,
    );
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
    let plane = match plane_for(id.as_deref(), "run") {
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
fn host_plane(id: Option<&str>, verb: &str) -> Result<Plane, ExitCode> {
    if std::env::var_os(TASK_SOCKET_ENV).is_some() {
        diag::error(&format!(
            "sbx: task {verb}: this is host-side only — a cage may invoke operations, not watch them"
        ));
        return Err(ExitCode::from(2));
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return Err(ExitCode::FAILURE);
    };
    let pid = resolve_task_session(layout.data_dir(), id, verb)?;
    Ok(Plane {
        socket: sandbox::task_control::log_socket(layout.data_dir(), pid),
        session: Some((pid, session_project(layout.data_dir(), pid))),
    })
}

/// `sbx task status [<operation>] [--session <id>]`: the invocations running right now.
fn task_status(args: &[OsString]) -> ExitCode {
    let listing = match listing_args(args, "status") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let plane = match host_plane(listing.session.as_deref(), "status") {
        Ok(p) => p,
        Err(code) => return code,
    };
    let rows = match sandbox::task_control::read_status(&plane.socket) {
        Ok(rows) => rows,
        Err(e) => return unreachable_plane(&e),
    };
    plane.announce();
    let rows = filter_by_operation(&rows, listing.operation.as_deref());
    if rows.is_empty() {
        match &listing.operation {
            Some(name) => println!("`{name}` is not running"),
            None => println!("no operation is running"),
        }
        return ExitCode::SUCCESS;
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
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
    print_table(
        &["ID", "OPERATION", "ELAPSED", "PID", "STATE"],
        &[
            Align::Right,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Left,
        ],
        &table,
    );
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
    let plane = match host_plane(listing.session.as_deref(), "stop") {
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
    let plane = match host_plane(listing.session.as_deref(), "logs") {
        Ok(p) => p,
        Err(code) => return code,
    };
    let lines = match sandbox::task_control::read_log(&plane.socket) {
        Ok(lines) => lines,
        Err(e) => return unreachable_plane(&e),
    };
    plane.announce();
    let mut rows = Vec::new();
    for line in &lines {
        if let Some(dropped) = line.strip_prefix("dropped=") {
            diag::warn(&format!(
                "{dropped} older invocation(s) fell out of the session's log ring"
            ));
            continue;
        }
        // The operation is the third cell; narrowing here rather than in the log keeps the wire one
        // shape and the filter one place.
        match (log_row(line), listing.operation.as_deref()) {
            (Some(row), Some(name)) if row.get(2).map(String::as_str) != Some(name) => {}
            (Some(row), _) => rows.push(row),
            (None, _) => {}
        }
    }
    if rows.is_empty() {
        match &listing.operation {
            Some(name) => println!("no invocation of `{name}` recorded"),
            None => println!("no invocations recorded"),
        }
        return ExitCode::SUCCESS;
    }
    print_table(
        &["ID", "TIME", "OPERATION", "EXIT", "TOOK", "NOTE"],
        &[
            Align::Right,
            Align::Left,
            Align::Left,
            Align::Right,
            Align::Right,
            Align::Left,
        ],
        &rows,
    );
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

    /// A column every row answers the same way is not information. The default case — nothing
    /// hidden, no output directory, every tool present — must print three columns, not seven.
    #[test]
    fn the_listing_drops_the_columns_that_say_the_same_thing_on_every_line() {
        let table = list_table(&[
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
        ]);
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
        let table = list_table(&[
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
        ]);
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
