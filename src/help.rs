//! `sbx --help` / `sbx help <command> [subcommand...]` — the usage surface.
//!
//! One table of [`Page`]s is the single source of truth: every top-level command
//! *and* every subcommand has a page carrying its argument grammar (`synopsis`),
//! one-line summary, option list, and prose. The top-level listing, each page, and
//! the handlers' own argument-error paths (which print [`synopsis`]) all render from
//! it, so help text and error text cannot drift.
//!
//! Help is dispatched centrally: [`maybe_help`] resolves the deepest command path a
//! `--help`/`-h` flag asks about, so `sbx plugins store add --help` shows that exact
//! page. The top-level command list and each subcommand listing are both sorted
//! alphabetically.
//!
//! A command a dispatcher accepts under more than one spelling has one page, under its
//! canonical name; [`ALIASES`] maps the other spellings onto it, so `sbx plugins ls --help`
//! resolves the same page `sbx plugins list --help` does. Alternate spellings are resolved
//! but never *offered*: they stay out of the listings and out of completion.
//!
//! Option descriptions duplicate knowledge that also lives in each handler's argument
//! parser — a deliberate, documented maintenance seam (options change rarely, and the
//! table and the parsers all live next to each other in `main.rs`). The guard test
//! enforces the one invariant the structure is exposed to: every dispatched command
//! and verb resolves to a page.
//!
//! The table lives in [`pages`], as one flat const — that single definition site is what makes it
//! the source of truth — and the painting in [`mod@render`]. This file owns the page type, the
//! alias table, the queries the rest of the crate asks over the table, and the entry points that
//! decide *which* page a request names and which stream's palette it is rendered for.

mod pages;
mod render;

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::style::Palette;

use pages::PAGES;
use render::{render, top_level};

/// One option or operand line: the flag/operand token and its one-line description.
type Opt = (&'static str, &'static str);

/// A help page for a command path. A length-1 path is a top-level command; a longer
/// path is a subcommand (e.g. `["plugins", "store", "add"]`). `details` is prose only —
/// it never repeats the synopsis or the option/subcommand lists the page renders above it.
struct Page {
    path: &'static [&'static str],
    synopsis: &'static str,
    summary: &'static str,
    options: &'static [Opt],
    details: &'static str,
}

/// Option rows a page renders **folded under a heading** instead of one per line, keyed by command
/// path.
///
/// It exists for a page whose option list is mostly one repeated shape. `sbx upgrade` is the case:
/// seven of its ten rows are a channel name, each a way to narrow the roll to one backend, and
/// listing them at the same level as the default made the command read as a choice to make when the
/// answer is almost always `sbx upgrade` with no argument at all. Folding them says which rows are
/// the decision and which are the narrowing, without taking a capability away.
///
/// It governs the RENDERING only. The rows stay in [`Page::options`], which is what
/// [`options_of`] answers and what completion walks — so a folded target still completes, and the
/// help/completion parity guards still see one page with ten rows. A member named here that the
/// page does not carry is simply not folded; the table cannot invent a row.
const OPTION_GROUPS: &[(&[&str], &str, &[&str])] = &[(
    &["upgrade"],
    "narrow to one channel",
    &[
        "nix", "mise", "flake", "deb", "appimage", "tarball", "binary",
    ],
)];

/// The heading and members folded on this page, or `None` when it folds nothing.
fn option_group(path: &[&str]) -> Option<(&'static str, &'static [&'static str])> {
    OPTION_GROUPS
        .iter()
        .find(|(p, _, _)| *p == path)
        .map(|(_, heading, members)| (*heading, *members))
}

/// Every alternate spelling a dispatcher accepts: the command path it is read under, the
/// spelling itself, and the canonical name it stands for. Aliases stay out of [`PAGES`] —
/// a page per spelling would double every subcommand listing, every completion candidate
/// and every guard-test iteration — so the table below is what turns a typed alias into
/// the path help, completion and the option lists are keyed by.
///
/// Only subcommand spellings belong here. A flag alias (`--optimise`/`--optimize`) or an
/// option-value alias (`--source session`/`manual`) names no command path, so it is
/// documented on the page that accepts it and nothing resolves it.
const ALIASES: &[(&[&str], &str, &str)] = &[
    (&[], "log", "logs"),
    (&[], "project", "projects"),
    (&[], "secrets", "secret"),
    (&[], "sessions", "session"),
    (&[], "tasks", "task"),
    (&["app"], "ls", "list"),
    (&["fs"], "log", "logs"),
    (&["net"], "log", "logs"),
    (&["plugins"], "ls", "list"),
    (&["plugins", "store"], "ls", "list"),
    (&["proc"], "list", "ls"),
    (&["proc"], "log", "logs"),
    (&["projects"], "ls", "list"),
    (&["projects"], "remove", "rm"),
    (&["secret"], "ls", "list"),
    (&["session"], "list", "ls"),
    (&["session"], "log", "logs"),
    (&["ssh-agent"], "log", "logs"),
    (&["task"], "log", "logs"),
    (&["task"], "ls", "list"),
];

/// The canonical name `tok` stands for under `parent`, or `tok` unchanged when it is not an
/// alias there. `parent` is itself a canonical path, so a caller that descends a command
/// tree must canonicalize each level before looking up the next: `sbx sessions list` reaches
/// `["session", "ls"]` only because `sessions` was folded to `session` first.
pub fn canonical<'a>(parent: &[&str], tok: &'a str) -> &'a str {
    ALIASES
        .iter()
        .find(|(p, alias, _)| *p == parent && *alias == tok)
        .map_or(tok, |(_, _, name)| *name)
}

/// Find the page for an exact command path.
fn find(path: &[&str]) -> Option<&'static Page> {
    PAGES.iter().find(|p| p.path == path)
}

/// The pages exactly one level below `path`, sorted alphabetically by their last token —
/// the subcommand listing under a command's page.
fn children(path: &[&str]) -> Vec<&'static Page> {
    let mut kids: Vec<&Page> = PAGES
        .iter()
        .filter(|p| p.path.len() == path.len() + 1 && p.path.starts_with(path))
        .collect();
    kids.sort_by_key(|p| *p.path.last().unwrap());
    kids
}

/// The argument grammar for a command path, e.g. `synopsis_of(&["app","import"])`. Handlers
/// print this on an argument error so the grammar lives in exactly one place. An unknown
/// path (only an internal caller can pass one) yields a generic fallback.
pub fn synopsis_of(path: &[&str]) -> &'static str {
    find(path).map_or("sbx <command>", |p| p.synopsis)
}

/// The argument grammar for a top-level command, e.g. `synopsis("run")`.
pub fn synopsis(name: &str) -> &'static str {
    synopsis_of(&[name])
}

/// Whether `name` is a dispatched top-level command, under its own name or an accepted
/// alias. Used to keep the help-flag interception from swallowing an unknown command (which
/// has its own diagnosis).
pub fn is_command(name: &str) -> bool {
    find(&[canonical(&[], name)]).is_some()
}

/// Whether a full command path is a known command or subcommand, e.g.
/// `is_command_path(&["plugins", "store", "add"])`. The empty path is the command root.
pub fn is_command_path(path: &[&str]) -> bool {
    path.is_empty() || find(path).is_some()
}

/// The names one level below `path`, each with its one-line summary, alphabetically. The
/// empty path yields the top-level commands, so one call covers every depth. Shell
/// completion renders these as the candidates for the next word.
pub fn subcommands_of(path: &[&str]) -> Vec<(&'static str, &'static str)> {
    children(path)
        .into_iter()
        .map(|p| (*p.path.last().unwrap(), p.summary))
        .collect()
}

/// Every command path the table declares, in declaration order. Exists for the guard tests,
/// which assert their properties over the whole surface rather than over a sample of it.
#[cfg(test)]
pub fn all_paths() -> Vec<&'static [&'static str]> {
    PAGES.iter().map(|p| p.path).collect()
}

/// The raw option rows a command path documents, as written in the page. The tokens are
/// human-formatted grammar (`-a, --app <name>`, `--gpu[=true|false]`, a bare `<file>`
/// operand), not completable flags — a caller that needs flag names normalizes them itself.
pub fn options_of(path: &[&str]) -> &'static [Opt] {
    find(path).map_or(&[], |p| p.options)
}

/// Print one command path's page to stdout. A path that is not a known page is a usage
/// error pointing back at the top-level help.
pub fn show(path: &[&str]) -> ExitCode {
    match find(path) {
        Some(page) => {
            let pal = Palette::for_stream(std::io::stdout().is_terminal());
            print!("{}", render(page, &pal));
            ExitCode::SUCCESS
        }
        None => {
            crate::diag::error(&format!(
                "sbx: no help for `sbx {}` — run `sbx --help` for the list of commands.",
                path.join(" ")
            ));
            ExitCode::from(2)
        }
    }
}

/// The deepest command path a help request is about: the command, then each following
/// non-flag token that extends it to a known subcommand. `sbx plugins store add --help`
/// resolves to `["plugins","store","add"]`; `sbx session stop --all --help` to `["session","stop"]`.
/// Every token is read through [`canonical`], so an alias lands on the page of the name it
/// stands for (`sbx plugins ls --help` on `plugins list`) instead of falling back to the
/// parent's page.
fn resolve_path<'a>(cmd: &'a str, rest: &'a [OsString]) -> Vec<&'a str> {
    let mut path = vec![canonical(&[], cmd)];
    for arg in rest {
        let Some(tok) = arg.to_str() else { break };
        if tok.starts_with('-') {
            break;
        }
        let mut candidate = path.clone();
        candidate.push(canonical(&path, tok));
        if find(&candidate).is_some() {
            path = candidate;
        } else {
            break;
        }
    }
    path
}

/// If the arguments carry a `--help`/`-h` flag, show the page for the deepest command path
/// they name and return its exit code; otherwise `None`, so the command runs normally. The
/// caller restricts this to known commands (an unknown command keeps its own diagnosis) and
/// excludes `run`/`mise`, which handle a leading help flag themselves.
///
/// A `--` ends sbx's own options: anything after it belongs to a launched command (e.g.
/// `sbx app run <name> -- --help` passes `--help` through to that command), so the help scan stops
/// at the first `--` — the same rule the `run` arm applies to its command.
pub fn maybe_help(cmd: &str, rest: &[OsString]) -> Option<ExitCode> {
    let asks_help = rest
        .iter()
        .take_while(|a| a.to_str() != Some("--"))
        .any(|a| matches!(a.to_str(), Some("--help" | "-h")));
    asks_help.then(|| show(&resolve_path(cmd, rest)))
}

/// `sbx help [command [subcommand...]]` / `sbx --help` / `sbx -h`: the top-level list, or
/// the page for the full command path given after the verb. Each token is folded to the
/// canonical name it stands for, against the path resolved so far; a token that names no
/// command is kept as typed, so an unknown path is reported in the words the user used.
pub fn dispatch(args: Vec<OsString>) -> ExitCode {
    let mut path: Vec<&str> = Vec::new();
    for tok in args
        .iter()
        .map_while(|a| a.to_str())
        .take_while(|t| !t.starts_with('-'))
    {
        let name = canonical(&path, tok);
        path.push(name);
    }
    if path.is_empty() {
        let pal = Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", top_level(&pal));
        ExitCode::SUCCESS
    } else {
        show(&path)
    }
}

/// Render the top-level list to a string for the no-command usage error (the caller writes
/// it to stderr and exits non-zero). Color is decided for stderr.
pub fn top_level_usage() -> String {
    top_level(&Palette::for_stream(std::io::stderr().is_terminal()))
}

/// Render a command's page to a string for a no-subcommand usage error — the caller writes it to
/// stderr and exits non-zero, the way bare `sbx` writes [`top_level_usage`]. The page lists the
/// command's subcommands, so `sbx config` reveals `show`/`get`/… instead of silently acting. An
/// unknown path (only an internal caller can pass one) yields `None`. Color is decided for stderr.
pub fn page_usage(path: &[&str]) -> Option<String> {
    find(path).map(|page| render(page, &Palette::for_stream(std::io::stderr().is_terminal())))
}

#[cfg(test)]
mod tests;
