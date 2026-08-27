//! `sbx completion <shell>` — the shell completion surface, and the hidden `__complete`
//! verb the scripts it emits call back into.
//!
//! The emitted script carries no copy of the command tree: it collects the words typed so
//! far and asks the binary which candidates fit. Every command name and flag is derived
//! from the help table, so completion cannot drift from the documented surface, and
//! supporting one more shell is one more adapter rather than a second transcription of
//! ninety command paths.
//!
//! The `__complete` protocol: `sbx __complete -- <word>...`, where the words are everything
//! typed after `sbx`, up to and including the (possibly empty) word under the cursor. It
//! writes one `name<TAB>description` line per candidate to stdout, and nothing at all to
//! stderr — a script runs it on every completion request, so a stray diagnostic would land
//! in the middle of the user's prompt.
//!
//! Where the table says a word is a *value* — the `<id>` of `session logs`, the `<name>`
//! of `app run`, the `<posture>` of `--net` — the oracle completes the value itself. A
//! value sbx can enumerate from this machine's registries is read fresh on every request
//! (session pids, stores, plugins and catalogue plugins, app profiles, project trees, the
//! `[task.<name>]` sections and keys of the config files in front of it), a value whose
//! cells the CLI itself knows completes as those cells (bash | zsh, a net posture, an
//! upgrade target). Only a value sbx cannot enumerate — a filesystem path, a command to
//! run — is left to the shell's own file completion, requested with the reserved [`FILES`]
//! line the scripts recognise. Everything after a `--` belongs to the launched command
//! and is left to the shell, so `sbx run -- ls <TAB>` never shows sbx's verbs.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::plugins::stores;
use crate::sandbox::proc_control;
use crate::{config, diag, help, plugins, session};

/// The shells a script can be emitted for, and the script for each.
const SHELLS: &[(&str, &str)] = &[("bash", BASH), ("zsh", ZSH)];

/// How much of a description reaches the completion menu. A help page wraps a long line;
/// a completion menu gives each candidate one line, where the same line crowds out the
/// list.
const DESC_WIDTH: usize = 64;

/// The one line that is an instruction rather than a value: the word under the cursor is a
/// path sbx cannot enumerate. The scripts see it and answer with the shell's own file
/// completion for that word.
const FILES: &str = "__sbx_files__";

pub(crate) fn completion_cmd(args: Vec<OsString>) -> ExitCode {
    let Some(shell) = args.first() else {
        eprint!("{}", help::page_usage(&["completion"]).unwrap_or_default());
        return ExitCode::from(2);
    };
    if let Err(code) = super::reject_extra(&["completion"], &args[1..]) {
        return code;
    }
    let found = shell
        .to_str()
        .and_then(|name| SHELLS.iter().find(|(n, _)| *n == name));
    let Some((_, script)) = found else {
        diag::error(&format!(
            "sbx: completion: unsupported shell '{}'",
            shell.to_string_lossy()
        ));
        diag::hint(&format!(
            "       supported shells: {}.",
            SHELLS
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return ExitCode::from(2);
    };
    print!("{script}");
    ExitCode::SUCCESS
}

/// The hidden completion oracle. Never invoked by a user directly.
pub(crate) fn complete_cmd(args: Vec<OsString>) -> ExitCode {
    // The separator is always sent. Requiring it keeps the protocol explicit instead of
    // guessing at the shape of an invocation that does not match the emitted scripts.
    let rest = match args.split_first() {
        Some((sep, rest)) if sep.to_str() == Some("--") => rest,
        _ => {
            diag::error("sbx: usage: sbx __complete -- <word>...");
            return ExitCode::from(2);
        }
    };
    // A word that is not valid UTF-8 cannot name a command or a flag; carrying it through
    // lossily lets it take part in prefix matching and match nothing, which is the truth.
    let words: Vec<String> = rest
        .iter()
        .map(|w| w.to_string_lossy().into_owned())
        .collect();

    let mut out = String::new();
    for (name, desc) in candidates(&words) {
        // The one gate every candidate passes, whatever produced it — see [`insertable`].
        if !insertable(&name) {
            continue;
        }
        out.push_str(&name);
        out.push('\t');
        out.push_str(&describe(&desc));
        out.push('\n');
    }
    print!("{out}");
    ExitCode::SUCCESS
}

/// Whether a candidate is a word the shell can insert onto the command line **as typed**.
///
/// The emitted scripts insert a candidate verbatim — bash does `COMPREPLY+=("$cand")`, and bash
/// applies no quoting of its own to a `COMPREPLY` entry unless `compopt -o filenames` is set, which
/// the script does only for the [`FILES`] branch. `no_page_offers_a_malformed_candidate` states the
/// resulting requirement ("A value candidate is a single word the shell can insert as typed") and
/// checks it across every help page — but a page is not the only source. `rule_values` reads egress
/// and proc rules straight out of the config files a removal would edit, and one of those is the
/// **project** file, which may have been authored by whoever wrote the repository the user cloned.
///
/// A rule is not a bare word by construction: `re:<regex>` admits `(`, `)`, `|`, and `$`. So a
/// project could put `re:$(…)` on the user's command line, where nothing evaluates it until they
/// press Enter — and then the shell expands it. That is a short step from a Tab to a shell
/// substitution the user never typed.
///
/// Enforced here rather than at each producer, because this is the single point every candidate
/// crosses on its way to a shell, and because the invariant was already written down; what was
/// missing was somewhere to hold it. A candidate that fails is dropped rather than quoted: three
/// shell dialects would need three quotings, and a rule that cannot be offered as a word is one the
/// user can still type in full.
fn insertable(name: &str) -> bool {
    name == FILES
        || (!name.is_empty()
            && !name.contains(char::is_whitespace)
            && !name
                .bytes()
                .any(|b| b < 0x20 || b == 0x7f || br#""'`$\|&;<>()!#"#.contains(&b)))
}

/// The candidates for the word under the cursor, sorted, already filtered by the prefix
/// typed so far.
///
/// A name is either a command of the table or a value of the grammar, never both — the
/// position decides. Flags answer a `-`-prefixed word (and `--flag=` asks the flag's own
/// value); a value answers any other word on a value slot; the subcommand names answer
/// everything else.
fn candidates(words: &[String]) -> Vec<(String, String)> {
    let cur = words.last().map(String::as_str).unwrap_or("");
    let before: &[String] = words.split_last().map_or(&[], |(_, b)| b);

    // Past a bare `--` the words belong to a launched command, not to sbx. Offering sbx's
    // own names there would be wrong, and answering nothing would leave the line dead:
    // the word is handed to the shell, which completes it as it would any other command's.
    if before.iter().any(|w| w == "--") {
        return vec![(FILES.to_string(), String::new())];
    }

    // The deepest known command path the words name. A leading `help` is transparent, so
    // `sbx help plugins store` offers the same subcommands as `sbx plugins store`. A word
    // that is an accepted alias descends through the name it stands for, so `sbx plugins
    // ls` offers what `sbx plugins list` offers; only canonical names are ever *offered*,
    // since a menu holding both spellings of one verb would read as two verbs.
    let mut path: Vec<&str> = Vec::new();
    let mut via_help = false;
    let mut tail_at = 0usize;
    for (idx, word) in before.iter().enumerate() {
        if word.starts_with('-') {
            continue;
        }
        if path.is_empty() && !via_help && word == "help" {
            via_help = true;
            continue;
        }
        let mut deeper = path.clone();
        deeper.push(help::canonical(&path, word));
        if help::is_command_path(&deeper) {
            path = deeper;
            tail_at = idx + 1;
        } else {
            // A positional value (an app name, a session id, a path, a command):
            // whatever follows belongs to that value's grammar, not to a deeper
            // subcommand.
            break;
        }
    }

    if cur.starts_with('-') {
        // `--net=deny` means the word under the cursor is the value of `--net`, asked in
        // line. Any other `-`-prefixed word is the flag itself.
        if let Some((flag, want)) = cur.split_once('=') {
            let Some(kind) = flag_value_kind(flag, &path) else {
                return Vec::new();
            };
            return value_candidates(&kind, want);
        }
        let mut flags = flag_menu(&path);
        flags.retain(|(name, _)| name.starts_with(cur));
        flags.sort_by(|a, b| a.0.cmp(&b.0));
        flags
    } else if let Some(kind) = cursor_value_kind(&path, &before[tail_at..]) {
        // The page's own verbs share the menu with the value: `sbx bundle <TAB>`
        // offers export|import alongside the bundle names, `sbx projects <TAB>` its
        // commands alongside the tree ids. The prefix filters both halves.
        let mut merged = value_candidates(&kind, cur);
        for (name, summary) in help::subcommands_of(&path) {
            if name.starts_with(cur) && !merged.iter().any(|(n, _)| n == name) {
                merged.push((name.to_string(), summary.to_string()));
            }
        }
        merged
    } else {
        let mut names: Vec<(String, String)> = help::subcommands_of(&path)
            .into_iter()
            .map(|(name, summary)| (name.to_string(), summary.to_string()))
            .collect();
        if path.is_empty() && !via_help {
            // `help` is a real verb with no page of its own, so the table cannot supply
            // it. Offered once: `sbx help help` has no page either, so proposing it again
            // under itself would complete a command that does not exist.
            names.push(("help".to_string(), "show usage for a command".to_string()));
        }
        // Bare on a command path (`sbx run <TAB>`, `sbx net logs <TAB>`), the menu is
        // the command's own options; past a typed value it belongs to the launched
        // command, so nothing of sbx's is offered there.
        if tail_at == before.len() {
            names.extend(flag_menu(&path));
        }
        names.retain(|(name, _)| name.starts_with(cur));
        names.sort_by(|a, b| a.0.cmp(&b.0));
        names
    }
}

/// The option names a command path accepts, deduplicated and blessed with the `--help`
/// every command answers.
fn flag_menu(path: &[&str]) -> Vec<(String, String)> {
    let mut flags: Vec<(String, String)> = Vec::new();
    for (row, desc) in help::options_of(path) {
        for name in flag_names(row) {
            if !flags.iter().any(|(f, _)| f == name) {
                flags.push((name.to_string(), (*desc).to_string()));
            }
        }
    }
    if !flags.iter().any(|(f, _)| f == "--help") {
        flags.push((
            "--help".to_string(),
            "show usage for this command".to_string(),
        ));
    }
    flags
}

// -----------------------------------------------------------------------------------
// Values.
// -----------------------------------------------------------------------------------

/// The kind of value a position takes. Its candidates come either from the machine's own
/// registries — the same reads the commands above use — or from cells sbx itself knows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueKind {
    /// A live sandbox session, by its pid.
    Sessions,
    /// An installed store's own plugins, the configured store names.
    Stores,
    /// An installed resolver plugin.
    Plugins,
    /// The plugins of a store named earlier on the same line.
    Catalogue(String),
    /// An application: an imported profile or an installed app home.
    Apps,
    Projects,
    /// A live `[task.<name>]` declaration.
    Tasks,
    /// A key of the runtime's own config files.
    ConfigKeys,
    /// A parked-request id (`<session-pid>.<seq>`) of a live observe session.
    PendingIds,
    /// A rule already written to a config file, for the verb that takes one back out.
    Rules {
        which: RuleList,
        /// The app the line names, whose overlay the removal would edit.
        app: Option<String>,
    },
    /// A fixed set of words the grammar spells out.
    Literal(Vec<String>),
    /// A path the shell completes for itself (see [`FILES`]).
    Files,
}

/// Which list of a config file a removal verb takes its rule out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleList {
    Egress(config::manage::EgressList),
    Proc(config::manage::ProcList),
}

/// The list a removal verb takes a rule out of, if this page is one.
///
/// Only the removal verbs. An `allow`/`deny`/`mute` takes a rule that is *not* there yet, so
/// completing it from the rules already written would offer exactly the words that cannot be
/// meant — and a removal is the mirror case, where the only valid argument is one of them.
fn removal_list(path: &[&str]) -> Option<RuleList> {
    use config::manage::{EgressList, ProcList};
    Some(match path {
        ["net", "unallow"] => RuleList::Egress(EgressList::Allow),
        ["net", "undeny"] => RuleList::Egress(EgressList::Deny),
        ["net", "unmute"] => RuleList::Egress(EgressList::Mute),
        ["proc", "unallow"] => RuleList::Proc(ProcList::Allow),
        ["proc", "undeny"] => RuleList::Proc(ProcList::Deny),
        _ => return None,
    })
}

/// The rules a removal could take out, read from the files it would edit.
fn rule_values(which: RuleList, app: Option<&str>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (path, key) in rule_files(app) {
        let found = match which {
            RuleList::Egress(list) => config::manage::egress_rules_in(&path, key, list),
            RuleList::Proc(list) => config::manage::proc_rules_in(&path, key, list),
        };
        out.extend(found.into_iter().map(|rule| (rule, String::new())));
    }
    out
}

/// The config files a rule removal would edit, each with the in-file app key to read under,
/// resolved the way the write path resolves its target: a named app is the project file's
/// `[app.<name>]` overlay plus its own global profile, and the baseline is the project and
/// global files themselves.
fn rule_files(app: Option<&str>) -> Vec<(PathBuf, Option<&str>)> {
    let mut out: Vec<(PathBuf, Option<&str>)> = Vec::new();
    if let Some(path) = project_config_file() {
        out.push((path, app));
    }
    let global = match app {
        Some(name) => config::profile_path(name),
        None => global_config_file(),
    };
    if let Some(path) = global {
        out.push((path, None));
    }
    out
}

/// The candidates of a value position, filtered by the prefix typed so far.
fn value_candidates(kind: &ValueKind, prefix: &str) -> Vec<(String, String)> {
    use ValueKind::*;
    let mut out: Vec<(String, String)> = match kind {
        Literal(words) => words.iter().map(|w| (w.clone(), String::new())).collect(),
        // Read from the config files rather than a registry, so no data directory is needed.
        Rules { which, app } => rule_values(*which, app.as_deref()),
        // The oracle cannot decide a path; the shell owns file completion for it. The
        // prefix filtering is then the script's job, so the marker is unconditional.
        Files => return vec![(FILES.to_string(), String::new())],
        _ => registry_values(kind),
    };
    out.retain(|(name, _)| name.starts_with(prefix));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// The registries behind a value position. A registry that cannot be read — no data
/// directory, a missing file, a closed control plane — is simply empty; the oracle never
/// prints anything but candidates.
fn registry_values(kind: &ValueKind) -> Vec<(String, String)> {
    use ValueKind::*;
    // Resolved **without mounting**: this runs on a keystroke, and the ordinary resolution follows
    // a volume pointer by mounting the volume — so completing an argument attached a loop device
    // and mounted a filesystem. See [`crate::store::Layout::from_env_without_mounting`].
    let Some(layout) = crate::store::Layout::from_env_without_mounting() else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = Vec::new();
    match kind {
        Sessions => {
            // The same listing the verbs use, liveness and all; the pid is the value.
            if let Ok(sessions) = session::Registry::at(layout.data_dir()).list() {
                for s in sessions {
                    out.push((s.pid.to_string(), String::new()));
                }
            }
        }
        Stores => {
            for name in stores::list(&layout) {
                out.push((name, String::new()));
            }
        }
        Plugins => {
            let mut warnings = Vec::new();
            let registry =
                plugins::PluginRegistry::load_quiet(&layout.plugins_dir(), &mut warnings);
            // Every kind, because the verbs that take this value take a plugin whatever it
            // does — and a broker and a signer claim no scheme, so the name completion
            // withholds is the only token that reaches them.
            for name in registry
                .resolvers()
                .map(|p| &p.name)
                .chain(registry.brokers().map(|p| &p.name))
                .chain(registry.signers().map(|p| &p.name))
            {
                out.push((name.clone(), String::new()));
            }
            out.sort();
        }
        Catalogue(store) => {
            if let Ok(cat) = stores::cached_catalogue(&layout, store) {
                for (name, entry) in cat.plugins {
                    out.push((name, format!("v{}", entry.version)));
                }
            }
        }
        Apps => {
            // The imported profiles and the installed app homes, unioned: what `sbx app
            // run` accepts.
            let mut names: Vec<String> = Vec::new();
            if let Some(dir) = config::profiles_dir()
                && let Ok(entries) = std::fs::read_dir(dir)
            {
                for e in entries
                    .flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                {
                    if let Some(base) = e.strip_suffix(".toml") {
                        names.push(base.to_string());
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(layout.data_dir().join("apps")) {
                for e in entries
                    .flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                {
                    if !e.starts_with('.') {
                        names.push(e);
                    }
                }
            }
            names.sort();
            names.dedup();
            for name in names {
                out.push((name, "app".to_string()));
            }
        }
        Projects => {
            if let Ok(entries) = std::fs::read_dir(layout.data_dir().join("projects")) {
                for e in entries
                    .flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                {
                    if !e.starts_with('.') {
                        out.push((e, "project".to_string()));
                    }
                }
            }
        }
        Tasks | ConfigKeys => {
            // The section names of the config files in front of the oracle.
            for (key, is_task) in config_tokens() {
                if is_task {
                    if let Some(name) = key.strip_prefix("task.") {
                        out.push((name.to_string(), "task".to_string()));
                    }
                } else if matches!(kind, ConfigKeys) {
                    out.push((key, String::new()));
                }
            }
        }
        PendingIds => {
            // A parked request's id is `<session-pid>.<n>`, held by each live session's
            // own control plane; ask it as `sbx proc pending` does — but on a glance
            // budget, since this runs on a keystroke and every live session is asked. A
            // session slow to answer drops out of the menu rather than stalling the prompt.
            if let Ok(sessions) = session::Registry::at(layout.data_dir()).list() {
                for s in sessions {
                    let socket = proc_control::proc_control_socket(layout.data_dir(), s.pid);
                    if let Ok(parked) =
                        proc_control::read_pending_within(&socket, proc_control::GLANCE_TIMEOUT)
                    {
                        for p in parked {
                            out.push((format!("{}.{}", s.pid, p.id), p.path));
                        }
                    }
                }
            }
        }
        // These name no registry — `value_candidates` answers them without coming here.
        // Answering nothing rather than panicking is what keeps the promise above: a panic
        // would write to stderr, in the middle of the user's prompt.
        Files | Literal(_) | Rules { .. } => {}
    }
    out
}

/// The section headers of the project's and the global config files, as written —
/// `[network]`, `[env]`, `[app.foo]`, `[task.deploy]`. Best-effort line reading: no
/// parse, no resolution, never a block on a config.
fn config_tokens() -> Vec<(String, bool)> {
    let mut tokens: Vec<(String, bool)> = Vec::new();
    for path in config_files() {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let inner = inner.trim();
                if !inner.is_empty() {
                    tokens.push((inner.to_string(), inner.starts_with("task.")));
                }
            }
        }
    }
    tokens
}

/// The two config files value completion reads: the project file under the current
/// directory and the global one next to the imported profiles.
fn config_files() -> Vec<PathBuf> {
    [project_config_file(), global_config_file()]
        .into_iter()
        .flatten()
        .collect()
}

/// The project config file under the current directory.
fn project_config_file() -> Option<PathBuf> {
    std::env::current_dir()
        .ok()
        .map(|cwd| cwd.join(config::PROJECT_CONFIG))
}

/// The global config file, which sits next to the imported profiles: `<config>/sbx/sbx.toml`.
fn global_config_file() -> Option<PathBuf> {
    config::profiles_dir()
        .and_then(|d| d.parent().map(|p| p.to_path_buf()))
        .map(|dir| dir.join("sbx.toml"))
}

// -----------------------------------------------------------------------------------
// The operand grammar of a page's value positions.
// -----------------------------------------------------------------------------------

/// One position of a page's operand grammar, read off its option rows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Operand {
    /// Words the grammar itself names — `bash` | `zsh` on the completion page, the
    /// `tarball` of upgrade. A literal lead on a row that names a value span first.
    Literal(Vec<String>),
    /// A metavariable (`<id>`, `<name>…`, `[name]`) whose value vocabulary the page
    /// decides.
    Value(String),
}

/// The union of the literal words a page's grammar is made of, when nothing but
/// literals remains under the cursor — the completion page (bash|zsh), the upgrade
/// targets. `None` when the grammar names none.
fn all_literal_words(slots: &[Operand]) -> Option<Vec<String>> {
    let words: Vec<String> = slots
        .iter()
        .filter_map(|s| match s {
            Operand::Literal(words) => Some(words),
            Operand::Value(_) => None,
        })
        .flatten()
        .cloned()
        .collect();
    if words.is_empty() { None } else { Some(words) }
}

/// The operand slots of a page. A flag row (and the `--` row) is skipped; a bare operand
/// row contributes its metavariables — `<id>`, `[name]`, a `<name>…` repeat; a row of
/// nothing but prose contributes nothing; a page with metavariables but also literal
/// rows (`allow <id> | deny <id>`) leads its value span with those words. A page whose
/// rows are all literal words (`bash`, `zsh`) is a single literal slot.
fn operand_slots(path: &[&str]) -> Vec<Operand> {
    let mut slots: Vec<Operand> = Vec::new();
    let mut pure: Vec<String> = Vec::new();
    let mut saw_value_row = false;
    for (row, _) in help::options_of(path) {
        let toks: Vec<&str> = row.split_whitespace().collect();
        // Flag rows and the separator row belong to the flag grammar.
        if toks.contains(&"--") || toks.iter().any(|t| t.starts_with('-') && *t != "--") {
            continue;
        }
        let mut row_values: Vec<String> = Vec::new();
        let mut row_literals: Vec<String> = Vec::new();
        for tok in toks {
            if tok == "|" || tok == "(none)" || tok.starts_with('(') || tok.starts_with("->") {
                continue;
            }
            if let Some(name) = metavar_of(tok).or_else(|| optional_of(tok)) {
                row_values.push(name);
            } else if is_literal(tok) {
                row_literals.push(tok.to_string());
            }
        }
        if row_values.is_empty() {
            // A prose row reads as nothing; a page of nothing but `tarball`-style rows
            // becomes one literal slot.
            if !saw_value_row && !row_literals.is_empty() {
                pure.extend(row_literals);
            }
            continue;
        }
        saw_value_row = true;
        if !row_literals.is_empty() && slots.is_empty() {
            slots.push(Operand::Literal(row_literals));
        }
        for name in row_values {
            slots.push(Operand::Value(name));
        }
    }
    if !saw_value_row && !pure.is_empty() {
        return vec![Operand::Literal(pure)];
    }
    slots
}

/// The name of a `<…>` metavariable. A repeat marker (`<name>…`) changes nothing, and the
/// grammar a metavariable carries is not part of its name: an alternation names its first
/// cell (`<toml|@file>` is `toml`) and a bracketed suffix is dropped, so `<path[:ro|:rw]>`
/// and `<port[,port…]>` are `path` and `port` rather than `path[:ro` and `port[,port…]`.
fn metavar_of(tok: &str) -> Option<String> {
    if !tok.starts_with('<') {
        return None;
    }
    let end = tok.find('>')?;
    let name = &tok[1..end];
    let name = name.split(['|', '[']).next().unwrap_or(name).trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// The body of a `[value]` optional operand.
fn optional_of(tok: &str) -> Option<String> {
    if !tok.starts_with('[') || !tok.ends_with(']') {
        return None;
    }
    let inner = &tok[1..tok.len() - 1];
    metavar_of(inner).or_else(|| {
        if inner.is_empty() {
            None
        } else {
            Some(inner.to_string())
        }
    })
}

/// Whether a word of an operand row is a candidate literal rather than prose. A row that
/// says `a runtime to provision` must not read as the literals `runtime`/`provision`.
fn is_literal(tok: &str) -> bool {
    const NOISE: &[&str] = &[
        "a", "an", "the", "to", "of", "or", "and", "in", "on", "for", "with", "from", "at", "by",
        "be", "is", "are", "it", "as", "per", "via", "which", "one", "its", "their", "when", "see",
        "e.g.", "e.g", "i.e.", "(the",
    ];
    !NOISE.contains(&tok)
        && !tok.starts_with('(')
        && tok
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

/// Which value vocabulary a metavariable's name is, in the context of its page. The
/// pages where the name means a different registry are settled here too.
fn kind_of_metavar(name: &str, path: &[&str]) -> Option<ValueKind> {
    // A removal verb's `<rule>`: the app is filled in by the caller, which sees the line.
    if name == "rule"
        && let Some(which) = removal_list(path)
    {
        return Some(ValueKind::Rules { which, app: None });
    }
    // Page-context overrides: the same metavariable means a different registry page
    // by page.
    if path.first() == Some(&"plugins") && name == "name" {
        // `<name>` means two registries under this verb, and neither is the app it means
        // everywhere else: a configured store on the `store` pages, an installed plugin on
        // `plugins rm|upgrade|verify`. Keyed on the page rather than on the verb, because the
        // set of pages on each side grows.
        return Some(match path.get(1) {
            Some(&"store") => ValueKind::Stores,
            _ => ValueKind::Plugins,
        });
    }
    if path.first() == Some(&"projects") && (name == "id" || name == "project") {
        // `projects show|rm <id>`: a project tree, not a session.
        return Some(ValueKind::Projects);
    }
    let base = match name {
        "id" | "pid" | "session" => ValueKind::Sessions,
        "name" | "app" | "profile" | "sketch" => ValueKind::Apps,
        "store" => ValueKind::Stores,
        "plugin" | "scheme" => ValueKind::Plugins,
        "invocation" | "operation" | "task" => ValueKind::Tasks,
        "key" => ValueKind::ConfigKeys,
        // A URL is deliberately absent: it is no more a path than a rule is, and handing
        // the word to the shell would answer a `<url>` slot with the working directory.
        "path" | "file" | "dir" | "image" | "out" | "src" => ValueKind::Files,
        _ => return None,
    };
    // On the pending pages the `<id>` answers a parked request, not a session.
    if matches!(base, ValueKind::Sessions) && is_pending_page(path) {
        return Some(ValueKind::PendingIds);
    }
    Some(base)
}

/// The request-plane pages, whose `<pid>`/`<id>` is a parked-request id.
fn is_pending_page(path: &[&str]) -> bool {
    path == ["proc", "pending"]
        || path == ["net", "pending", "allow"]
        || path == ["net", "pending", "deny"]
}

// -----------------------------------------------------------------------------------
// Where the value slot sits: the cursor's value kind.
// -----------------------------------------------------------------------------------

/// What the word after a flag is, when that flag takes its value as the next word rather
/// than fused to its name. Either way that word belongs to the flag and not to the operand
/// grammar: counted as an operand it would shift every slot after it, and the page would
/// read as already past its own `<id>` the moment a flag was typed first.
enum PendingWord {
    /// Some flag's value, which the operand count must skip.
    Value,
    /// The `--app` name, which also scopes what a value position reads.
    AppName,
}

/// The value kind of the word under the cursor: the flag value the typed flags want, or
/// the operand slot the positional arguments have reached. `None` means the position
/// takes no completable value — the cursor sits on a flag or a command name.
fn cursor_value_kind(path: &[&str], before: &[String]) -> Option<ValueKind> {
    let slots = operand_slots(path);
    let mut pos: usize = 0;
    let mut pending_flag: Option<ValueKind> = None;
    let mut first_positional: Option<String> = None;
    let mut literal_consumed = false;
    let mut app: Option<String> = None;
    let mut pending_word: Option<PendingWord> = None;
    for word in before {
        let word = word.as_str();
        // Whatever the last flag's value was, this word consumed it.
        pending_flag = None;
        if let Some(pending) = pending_word.take() {
            if matches!(pending, PendingWord::AppName) {
                app = Some(word.to_string());
            }
            continue;
        }
        if word.starts_with('-') && word != "--" {
            let (name, inline) = match word.split_once('=') {
                Some((flag, value)) => (flag, Some(value)),
                None => (word, None),
            };
            let names_app = matches!(name, "--app" | "-a");
            match inline {
                Some(value) if names_app => app = Some(value.to_string()),
                Some(_) => {}
                None if flag_takes_value(name, path) => {
                    pending_flag = flag_value_kind(name, path);
                    pending_word = Some(if names_app {
                        PendingWord::AppName
                    } else {
                        PendingWord::Value
                    });
                }
                None => {}
            }
            continue;
        }
        // A word of a literal slot filling it (`allow`, `tarball`, `list`) occupies
        // that slot rather than counting as a positional.
        if let Some(Operand::Literal(words)) = slots.get(pos)
            && words.iter().any(|w| w == word)
        {
            literal_consumed = true;
            pos += 1;
            continue;
        }
        // A value word of the grammar occupies one value slot; the first one is also
        // remembered when the page's second value depends on it.
        if first_positional.is_none() {
            first_positional = Some(word.to_string());
        }
        pos += 1;
    }
    if let Some(kind) = pending_flag {
        return Some(kind);
    }
    while let Some(Operand::Literal(_)) = slots.get(pos) {
        pos += 1;
    }
    let Some(Operand::Value(name)) = slots.get(pos) else {
        // The page's whole remaining grammar is literal — the completion page
        // (bash|zsh), the upgrade targets: the word under the cursor is one of them.
        // A literal the user just typed filled the page; nothing is left to offer.
        if literal_consumed {
            return None;
        }
        return all_literal_words(&slots).map(ValueKind::Literal);
    };
    let kind = kind_of_metavar(name, path);
    // A removal reads the rules of the scope it would edit, which the line's `--app` names.
    if let Some(ValueKind::Rules { which, .. }) = kind {
        return Some(ValueKind::Rules { which, app });
    }
    // `plugins store install <store> <plugin>`: the second operand is a plugin of the
    // store just named, asked of that store's signed catalogue.
    if matches!(kind, Some(ValueKind::Plugins))
        && path.len() >= 2
        && path[0] == "plugins"
        && path[1] == "store"
        && let Some(store) = first_positional
    {
        return Some(ValueKind::Catalogue(store));
    }
    kind
}

// -----------------------------------------------------------------------------------
// The value of a flag.
// -----------------------------------------------------------------------------------

/// The value kind a documented flag takes — its `<value>` metavariable or its inline
/// `[=cell|cell]` list — or `None` when the flag takes no value. Postures the table
/// spells symbolically get their real cell list here, mirroring the parser.
fn flag_value_kind(flag: &str, path: &[&str]) -> Option<ValueKind> {
    let path = grammar_page(path, flag);
    if let Some(cells) = flag_literals(path, flag) {
        return Some(ValueKind::Literal(cells));
    }
    for (row, _) in help::options_of(path) {
        let some_tail = flag_tail(row, flag);
        let tail = match some_tail {
            Some(t) => t,
            None => continue,
        };
        // A fused `[=true|false]` list is a literal.
        if let Some(inner) = tail.strip_prefix('[') {
            let inner = inner.strip_suffix(']').unwrap_or(inner);
            let inner = inner.strip_prefix('=').unwrap_or(inner);
            if inner.contains('|') {
                let cells: Vec<String> = inner
                    .split('|')
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
                    .collect();
                return Some(ValueKind::Literal(cells));
            }
            continue;
        }
        if let Some(name) = metavar_of(tail) {
            if name == "toml" || name == "hex" {
                // `--config <toml|@file>`: the file half is a path the shell completes.
                return Some(ValueKind::Files);
            }
            if let Some(cells) = alternation_cells(tail) {
                return Some(ValueKind::Literal(cells));
            }
            if let Some(kind) = flag_metavar_kind(&name) {
                return Some(kind);
            }
        }
    }
    None
}

/// The cells of a metavariable that spells its own alternation — `<none|offscreen|wayland>`,
/// `<off|once|always>` — so a posture the table already enumerates needs no second list here.
///
/// Only when every cell is a bare word. `<toml|@file>` and `<url|tcp://host:port>` name two
/// *shapes* rather than a closed set, and `<path[:ro|:rw]>` puts its alternation inside the
/// grammar of a single value; neither is a menu.
fn alternation_cells(tail: &str) -> Option<Vec<String>> {
    let body = tail.strip_prefix('<')?.strip_suffix('>')?;
    if !body.contains('|') {
        return None;
    }
    let cells: Vec<String> = body.split('|').map(str::to_string).collect();
    cells
        .iter()
        .all(|c| {
            !c.is_empty()
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        })
        .then_some(cells)
}

/// Whether a documented flag takes the **following word** as its value, completable or not. The
/// question [`flag_value_kind`] answers is narrower — *which* value — and a flag whose value sbx
/// cannot complete still consumes the word after it.
///
/// A fused optional value is not one: `--gpu[=true|false]` is read only inline (`take_flag_bool`
/// removes the token and nothing else), so `sbx run --gpu <command>` leaves the command in place
/// and the completion must leave the operand slot in place too. Offering the cells there answered
/// the command position with `true`, which sbx would then have launched.
fn flag_takes_value(flag: &str, path: &[&str]) -> bool {
    let path = grammar_page(path, flag);
    help::options_of(path).iter().any(|(row, _)| {
        flag_tail(row, flag).is_some_and(|tail| !row.contains(&format!("{flag}{tail}")))
    })
}

/// The page whose option rows carry `flag`'s value grammar: its own, except where a page documents
/// a shared flag without repeating that grammar.
///
/// `sbx app run` is the one such page. It takes the whole one-shot override set `sbx run` takes —
/// one parser, `take_override_flag`, serves both — but lists them for the reader in a single row
/// (`--env / --net / … / --dbus`) that points at `sbx help run` for the prose and carries no
/// metavariable. Read literally, none of those flags took a value here, so the word after `--net`
/// was counted as an operand and consumed the page's only slot, `<name>`: the app registry went
/// quiet on the one page where it is the whole point.
fn grammar_page<'a>(path: &'a [&'a str], flag: &str) -> &'a [&'a str] {
    if path == ["app", "run"]
        && !help::options_of(path)
            .iter()
            .any(|(row, _)| flag_tail(row, flag).is_some())
    {
        return &["run"];
    }
    path
}

/// The value cell of a flag metavar — the shared vocabulary `--app <name>`,
/// `--session <id>`, `--proxy <url>`. `None` for an enumerable or an uppercase-bound
/// (`KEY=VALUE`, `<N>`) value.
fn flag_metavar_kind(name: &str) -> Option<ValueKind> {
    if name.chars().any(|c| c.is_uppercase()) || name.contains('=') {
        return None;
    }
    match name {
        "path" | "locator" | "location" | "image" | "file" | "key-file" | "dir" | "dir:"
        | "src" => Some(ValueKind::Files),
        "session" | "id" | "pid" => Some(ValueKind::Sessions),
        "app" | "profile" | "name" | "sketch" => Some(ValueKind::Apps),
        "store" => Some(ValueKind::Stores),
        "plugin" => Some(ValueKind::Plugins),
        "operation" | "task" => Some(ValueKind::Tasks),
        "key" => Some(ValueKind::ConfigKeys),
        _ => None,
    }
}

/// The literal cells of the few flags whose posture the docs write symbolically. The
/// same cells the parser reads, minus the reference row overrun in the table itself.
fn flag_literals(path: &[&str], flag: &str) -> Option<Vec<String>> {
    let cells: &[&str] = match (path, flag) {
        (["run"], "--net") => &["none", "shared", "ask", "allow", "deny", "allow=", "deny="],
        (["net", "logs"], "--verdict") => &["allow", "deny", "blocked", "error"],
        // `logs --feed` takes a comma-joined subset of a closed set. The names come from the feed
        // table itself rather than a second copy of it, so a feed added there is offered here.
        // What is completed is one name: a shell splits on whitespace, so the value after a comma
        // is inside a single word and is the caller's to type.
        (["logs"], "--feed") => super::logs::FEED_NAMES,
        _ => return None,
    };
    Some(cells.iter().map(|c| (*c).to_string()).collect())
}

/// The value grammar tail of a flag in one option row: fused to the name
/// (`--gpu[=true|false]`) or a following value token — a `<value>` metavariable (`--app <name>`)
/// or a bound one written in capitals (`--env KEY=VALUE`). An option row may pair a short and a
/// long spelling; the one that matches decides.
fn flag_tail<'a>(row: &'a str, flag: &str) -> Option<&'a str> {
    let toks: Vec<&str> = row.split_whitespace().collect();
    for (i, tok) in toks.iter().enumerate() {
        // A row separates its spellings with the punctuation a reader expects, so the
        // token carrying `-a` is written `-a,`. Matching the bare name is what lets the
        // short spelling reach the same value as the long one.
        let Some(rest) = tok.trim_end_matches([',', '/']).strip_prefix(flag) else {
            continue;
        };
        if !rest.is_empty() && !rest.starts_with('[') {
            continue;
        }
        if rest.is_empty() {
            // The value follows the name, past any further spelling of it: the `<name>`
            // of `-a, --app <name>` is two tokens on from `-a`.
            for next in &toks[i + 1..] {
                if next.starts_with('-') {
                    continue;
                }
                return (next.starts_with('<') || next.starts_with('[') || is_bound_metavar(next))
                    .then_some(*next);
            }
            return None;
        }
        // The value is fused to the name: `--gpu[=true|false]`.
        return Some(rest);
    }
    None
}

/// A value written in capitals rather than in angle brackets: the `KEY=VALUE` of `--env` and of
/// `--param`. It is a metavariable a reader recognizes on sight, and the flag before it takes the
/// following word exactly as a `<value>` one does — so the completion must skip that word too,
/// instead of counting it as the page's next operand.
fn is_bound_metavar(tok: &str) -> bool {
    tok.chars().any(|c| c.is_ascii_uppercase())
        && tok
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '=' || c == '_')
}

// -----------------------------------------------------------------------------------
// Flags.
// -----------------------------------------------------------------------------------

/// The completable flag names in one documented option row. A row is written for a reader,
/// not for a parser: it may pair a short and a long spelling (`-a, --app`), offer two
/// opposed flags (`-g, --global / -l, --local`), carry an optional value
/// (`--gpu[=true|false]`), or name no flag at all (a bare `<file>` operand, the `--`
/// separator). Each alternative is split out and stripped of its value grammar; a row that
/// names no flag yields nothing.
fn flag_names(row: &str) -> Vec<&str> {
    row.split([',', '/'])
        .map(|part| {
            let part = part.trim();
            let end = part.find(&[' ', '[', '=', '<'][..]).unwrap_or(part.len());
            &part[..end]
        })
        .filter(|token| token.starts_with('-') && *token != "--")
        .collect()
}

/// One candidate's description, fit for a single tab-delimited line: the inline-code
/// backticks of the help prose dropped, whitespace collapsed, and the result cut to one
/// line on a word boundary.
fn describe(desc: &str) -> String {
    let flat = desc
        .replace('`', "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if flat.len() <= DESC_WIDTH {
        return flat;
    }
    let mut end = DESC_WIDTH;
    while !flat.is_char_boundary(end) {
        end -= 1;
    }
    let head = match flat[..end].rsplit_once(' ') {
        Some((h, _)) => h,
        None => &flat[..end],
    };
    format!("{}…", head.trim_end_matches([',', ';', ':']))
}

/// The bash script. `-o default` is deliberately gone: asking bash for the filesystem
/// beside sbx's own answers would drown one in the other. Files appear only where the
/// [`FILES`] marker asks for them.
const BASH: &str = r#"# bash completion for sbx. Generated by `sbx completion bash`.
#
# The command tree lives in the binary, not here: this function forwards the words typed
# so far and renders what comes back, so it cannot go stale as sbx grows verbs.
_sbx_complete() {
    local cand
    local -a typed
    COMPREPLY=()
    typed=("${COMP_WORDS[@]:1:COMP_CWORD-1}")
    # Append the word under the cursor explicitly: it is empty when the cursor sits after
    # a space, and that empty trailing word is what asks sbx for the unfiltered list.
    typed+=("${COMP_WORDS[COMP_CWORD]-}")
    while IFS=$'\t' read -r cand _; do
        if [[ $cand == "__sbx_files__" ]]; then
            # sbx refuses to guess at a path: this word is the shell's to complete.
            # `mapfile` reads one name per line, so a name holding a space stays a single
            # candidate (word splitting would offer each half as its own); `-o filenames`
            # is what has bash quote it and mark a directory as one.
            compopt -o filenames 2>/dev/null
            mapfile -t COMPREPLY < <(compgen -f -- "${COMP_WORDS[COMP_CWORD]-}")
            return 0
        fi
        [ -n "$cand" ] && COMPREPLY+=("$cand")
    done < <(sbx __complete -- "${typed[@]}" 2>/dev/null)
}
complete -F _sbx_complete sbx
"#;

/// The zsh script. `_describe` renders the descriptions sbx returns; `_files` is called
/// only where sbx itself asks for a path. A colon inside a candidate is escaped before
/// `_describe` sees it, since that is the character it splits value from description on —
/// `the_zsh_script_escapes_a_colon_inside_a_candidate` holds that property.
const ZSH: &str = r#"#compdef sbx
# zsh completion for sbx. Generated by `sbx completion zsh`.
#
# The command tree lives in the binary, not here: this function forwards the words typed
# so far and renders what comes back, which cannot go stale as sbx grows verbs.
_sbx() {
    local cand desc
    local -a typed cands
    # Everything after the program name, up to the word under the cursor. `(@)` inside
    # the quotes keeps that word when it is empty, which is what asks for the unfiltered
    # list.
    typed=("${(@)words[2,CURRENT]}")
    while IFS=$'\t' read -r cand desc; do
        if [[ $cand == "__sbx_files__" ]]; then
            # sbx refuses to guess: the path under the cursor is the shell's to complete.
            _files
            return 0
        fi
        if [[ -z $cand ]]; then
            continue
        fi
        # `_describe` reads each element as `value:description` and splits on the FIRST
        # unescaped colon, so a candidate carrying one of its own (an egress rule
        # `api.example.com:443`, a proc rule `re:token`) was cut in two: the menu offered
        # `api.example.com` as the word to insert and `443` as its description, and Tab
        # completed a rule nobody typed. The value half is escaped here; the description
        # is everything after the separator and needs none.
        if [[ -n $desc ]]; then
            cands+=("${cand//:/\\:}:${desc}")
        else
            cands+=("${cand//:/\\:}")
        fi
    done < <(sbx __complete -- "${typed[@]}" 2>/dev/null)
    if (( ${#cands} )); then
        _describe -t sbx-candidates 'sbx' cands
    fi
}

# Sourced directly (`source <(sbx completion zsh)`), the function has to be registered;
# autoloaded from $fpath, running the file *is* the first completion call.
if [[ $funcstack[1] == _sbx ]]; then
    _sbx "$@"
else
    compdef _sbx sbx
fi
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{EnvVar, TmpDir, env_lock};

    /// The word list a shell sends: the words typed, then the cursor word.
    fn words(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn names(xs: &[&str]) -> Vec<String> {
        candidates(&words(xs)).into_iter().map(|(n, _)| n).collect()
    }

    /// The word list for `sbx <path...> <cursor>`, the shape a shell sends while the
    /// user is partway through the word after a command path.
    fn at(path: &[&str], cursor: &str) -> Vec<String> {
        path.iter()
            .map(|s| s.to_string())
            .chain(std::iter::once(cursor.to_string()))
            .collect()
    }

    fn names_at(path: &[&str], cursor: &str) -> Vec<String> {
        candidates(&at(path, cursor))
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    /// [`names_at`] with words typed between the command path and the cursor.
    fn names_at_with(path: &[&str], typed: &[&str], cursor: &str) -> Vec<String> {
        let words: Vec<String> = path
            .iter()
            .chain(typed)
            .map(|s| s.to_string())
            .chain(std::iter::once(cursor.to_string()))
            .collect();
        candidates(&words).into_iter().map(|(n, _)| n).collect()
    }

    #[test]
    fn flag_names_reads_every_row_shape_the_table_uses() {
        // A short/long pair, the shape most option rows use.
        assert_eq!(flag_names("-a, --app <name>"), ["-a", "--app"]);
        // Two opposed flags in one row, each with both spellings.
        assert_eq!(
            flag_names("-g, --global / -l, --local"),
            ["-g", "--global", "-l", "--local"]
        );
        // An optional value, an inline value, and a value with its own bracket grammar.
        assert_eq!(flag_names("--gpu[=true|false]"), ["--gpu"]);
        assert_eq!(flag_names("--limit <key>=<value>"), ["--limit"]);
        assert_eq!(flag_names("--bind <path[:ro|:rw]>"), ["--bind"]);
        assert_eq!(flag_names("-e, --env KEY=VALUE"), ["-e", "--env"]);
        assert_eq!(
            flag_names("--optimise, --optimize"),
            ["--optimise", "--optimize"]
        );
        // Rows that name no flag: an operand, a literal value, the separator, prose.
        assert!(flag_names("<file>").is_empty());
        assert!(flag_names("[name]").is_empty());
        assert!(flag_names("tarball").is_empty());
        assert!(flag_names("(no flag)").is_empty());
        assert!(flag_names("--").is_empty());
        assert!(flag_names("-- command [args...]").is_empty());
    }

    #[test]
    fn the_run_page_yields_only_real_flags() {
        // The worst case in the table: optional-value booleans, inline values, and a
        // bare `--` row all live on this page. Nothing may reach a menu carrying grammar.
        let flags = names(&["run", "-"]);
        assert!(flags.contains(&"--detach".to_string()));
        assert!(flags.contains(&"--net".to_string()));
        assert!(flags.contains(&"--gpu".to_string()));
        assert!(flags.contains(&"--config".to_string()));
        assert!(flags.contains(&"--limit".to_string()));
        for flag in &flags {
            assert!(
                flag.starts_with('-') && *flag != "--",
                "not a completable flag: {flag:?}"
            );
            assert!(
                !flag.contains([' ', '[', '<', '=', ',']),
                "grammar leaked into a candidate: {flag:?}"
            );
        }
    }

    #[test]
    fn a_bare_word_completes_commands_at_every_depth() {
        // The empty cursor word a shell sends after `sbx `.
        let top = names(&[""]);
        assert!(top.contains(&"run".to_string()));
        assert!(top.contains(&"completion".to_string()));
        assert!(top.contains(&"help".to_string()));
        // A prefix filters, and the answer stays sorted.
        assert_eq!(names(&["comp"]), ["completion"]);
        // Depth two and three resolve through the table.
        assert!(names(&["app", ""]).contains(&"import".to_string()));
        assert_eq!(names(&["plugins", "store", "publ"]), ["publish"]);
        // A leaf command with an operand starts its value, not a deeper subcommand.
        assert_eq!(names(&["completion", ""]), ["bash", "zsh"]);
        // A leaf command with no subcommands completes its own options instead.
        assert!(names(&["doctor", ""]).iter().all(|n| n.starts_with('-')));
    }

    #[test]
    fn help_is_transparent_and_offered() {
        assert!(names(&["help", ""]).contains(&"plugins".to_string()));
        assert_eq!(names(&["help", "plugins", "store", "rek"]), ["rekey"]);
        // A prefix immediately after `help` filters that list rather than falling
        // through: the skip fires on the first non-flag word.
        assert_eq!(names(&["help", "comp"]), ["completion"]);
    }

    #[test]
    fn an_alias_completes_what_the_name_it_stands_for_completes() {
        assert_eq!(names(&["session", "logs", "--al"]), ["--all"]);
        assert_eq!(names(&["session", "log", "--al"]), ["--all"]);
        assert_eq!(names(&["sessions", "log", "--al"]), ["--all"]);
        assert!(names(&["task", "ls", "-"]).contains(&"--session".to_string()));
        assert_eq!(
            names(&["plugins", "ls", "-"]),
            names(&["plugins", "list", "-"])
        );
        // Only canonical names are offered.
        let plugins = names(&["plugins", ""]);
        assert!(plugins.contains(&"list".to_string()));
        assert!(!plugins.contains(&"ls".to_string()));
    }

    #[test]
    fn a_positional_value_does_not_deepen_the_path() {
        // `demo-app` would be an app name, not a subcommand; the path stops there rather
        // than matching some deeper page, and flags still come from `app run`.
        assert!(names(&["app", "run", "demo-app", ""]).is_empty());
        assert!(names(&["app", "run", "demo-app", "-"]).contains(&"--help".to_string()));
        // A cursor *on* the value position asks for the value instead: whatever this
        // machine's registries hold, the answer is the value vocabulary, never a verb.
        let out = names(&["app", "run", "demo"]);
        let verbs: Vec<&str> = help::subcommands_of(&["app", "run"])
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(
            out.iter().all(|n| !verbs.contains(&n.as_str())),
            "a value position offered a command: {out:?}"
        );
    }

    #[test]
    fn past_a_double_dash_the_line_belongs_to_the_shell() {
        // Everything after `--` runs literally, so none of sbx's own names may appear —
        // and the answer is the marker rather than an empty list, which would leave
        // `sbx run -- ls <TAB>` completing nothing at all instead of the launched
        // command's own files.
        assert_eq!(names(&["run", "--", ""]), [FILES]);
        assert_eq!(names(&["run", "--", "ls", ""]), [FILES]);
        // A `-`-prefixed word past the separator is the launched command's flag, not
        // sbx's: the shell owns that word too.
        assert_eq!(names(&["run", "--", "ls", "-"]), [FILES]);
        // Before the separator, the flags of `run` are still the answer.
        assert!(names(&["run", "--det"]).contains(&"--detach".to_string()));
    }

    #[test]
    fn help_is_completable_on_every_command() {
        // `--help` is documented on almost no page and works everywhere, so it is added.
        assert!(names(&["doctor", "--"]).contains(&"--help".to_string()));
        assert!(names(&["plugins", "store", "add", "--h"]).contains(&"--help".to_string()));
    }

    #[test]
    fn descriptions_survive_as_one_clean_line() {
        let d = describe("run `sbx help run`\n   for the\tdetails");
        assert_eq!(d, "run sbx help run for the details");
        let long = describe(
            "one-shot config override: inline TOML (or @file) shaped like an sbx.toml, \
             setting any field; repeatable, later wins",
        );
        assert!(long.chars().count() <= DESC_WIDTH + 1, "{long:?}");
        assert!(long.ends_with('…'));
        assert!(!long.contains("  "));

        // Every description the table can produce stays on one line, whatever its shape.
        for (_, desc) in candidates(&words(&["run", "-"])) {
            let out = describe(&desc);
            assert!(!out.contains(['\n', '\t']), "{out:?}");
        }
    }

    #[test]
    fn a_multibyte_description_is_cut_on_a_character_boundary() {
        let d = describe(&"é".repeat(DESC_WIDTH));
        assert!(d.ends_with('…'));
    }

    // ---- value completion -------------------------------------------------------

    #[test]
    fn literal_operands_complete_from_the_page_itself() {
        // `completion` takes a shell; `upgrade` a closed set of targets.
        assert!(names_at(&["completion"], "b").contains(&"bash".to_string()));
        assert!(names_at(&["completion"], "").contains(&"zsh".to_string()));
        // Every target the parser accepts, offered by the completion. The two come from
        // independent sources — the parser reads `TARGETS`, the completion reads the help page's
        // operand list — so walking one and asserting the other is a parity check, not a test
        // computing its own expectation. A hand-kept literal here is what would silently miss a
        // target added to both the parser and the page but forgotten in this list.
        let targets = names_at(&["upgrade"], "");
        for want in super::super::upgrade::TARGETS {
            assert!(
                targets.contains(&want.to_string()),
                "upgrade does not offer {want:?}: {targets:?}"
            );
        }
    }

    #[test]
    fn flag_values_complete_the_cells_of_the_value() {
        // `--net <posture>`: the cells of the posture, with the list shorthands.
        let cells = names_at(&["run", "--net"], "");
        for want in ["none", "shared", "ask", "allow", "deny", "allow=", "deny="] {
            assert!(
                cells.contains(&want.to_string()),
                "run --net does not offer {want:?}: {cells:?}"
            );
        }
        // `--verdict <allow|deny|blocked|error>` on `net logs`.
        let verdict = names_at(&["net", "logs", "--verdict"], "");
        assert!(verdict.contains(&"blocked".to_string()));
        // An inline `[=…]` list: `--gpu[=true|false]`. The cells answer the *fused* spelling,
        // which is the only one that carries a value — see
        // `an_optional_value_boolean_does_not_consume_the_word_after_it` for the other half.
        assert_eq!(names_at(&["run"], "--gpu="), ["false", "true"]);

        // A flag that takes a file hands the word to the shell — including one whose
        // metavariable carries its own grammar, `--bind <path[:ro|:rw]>`.
        assert_eq!(names_at(&["run", "--config"], ""), [FILES]);
        assert_eq!(names_at(&["run", "--bind"], ""), [FILES]);
        assert_eq!(
            names_at(&["plugins", "store", "publish", "--key"], ""),
            [FILES]
        );
        // A metavariable that spells its own alternation is its own cell list, so a
        // posture the table already enumerates needs no second copy in the code.
        assert_eq!(
            names_at(&["run", "--gui"], ""),
            ["none", "offscreen", "wayland"]
        );
        assert_eq!(
            names_at(&["run", "--notify"], ""),
            ["always", "off", "once"]
        );
        // ... but a two-shape alternation is not a menu: `<toml|@file>` is a path.
        assert_eq!(names_at(&["run", "--config"], ""), [FILES]);
    }

    #[test]
    fn a_flag_value_does_not_take_an_operand_slot() {
        // `-n 20` is the value of `--lines`, not the `<id>` of `session logs`. Counting it
        // as one shifts every slot after it, and the page then reads as already past its
        // operand: the menu goes quiet exactly when a flag was typed first.
        let words = |xs: &[&str]| -> Vec<String> { xs.iter().map(|s| s.to_string()).collect() };
        let path = &["session", "logs"];
        assert_eq!(cursor_value_kind(path, &[]), Some(ValueKind::Sessions));
        assert_eq!(
            cursor_value_kind(path, &words(&["-n", "20"])),
            Some(ValueKind::Sessions),
            "a short flag's value took the operand slot"
        );
        assert_eq!(
            cursor_value_kind(path, &words(&["--lines", "20"])),
            Some(ValueKind::Sessions)
        );
        // A flag that takes no value leaves the slot alone either way.
        assert_eq!(
            cursor_value_kind(path, &words(&["--all"])),
            Some(ValueKind::Sessions)
        );
        // On the flag's own value word, that value is what is being completed.
        assert_eq!(
            cursor_value_kind(&["test", "net"], &words(&["-a"])),
            Some(ValueKind::Apps),
            "the short spelling of a valued flag must reach the same value as the long one"
        );
        // The same for `upgrade`, whose `--app` narrows an in-cage roll: a page that declares the
        // flag in the shared `-a, --app <name>` spelling gets the app-name value for free, so this
        // is what would catch a row written in some other shape.
        for spelling in [vec!["--app"], vec!["provision", "-a"]] {
            assert_eq!(
                cursor_value_kind(&["upgrade"], &words(&spelling)),
                Some(ValueKind::Apps),
                "upgrade --app must complete app names ({spelling:?})"
            );
        }
    }

    /// An optional-value boolean is read only inline, so the word after it is not its value.
    ///
    /// `take_flag_bool` removes the flag token and nothing else, so `sbx run --gpu <command>`
    /// leaves the command in place. Modelling the flag as consuming the next word offered
    /// `false`/`true` in the command position, and accepting one produced `sbx run --gpu true` —
    /// which launches `/bin/true` instead of the program the user was about to name.
    #[test]
    fn an_optional_value_boolean_does_not_consume_the_word_after_it() {
        let words = |xs: &[&str]| -> Vec<String> { xs.iter().map(|s| s.to_string()).collect() };
        for flag in ["--gpu", "--audio", "--dbus"] {
            assert!(
                !flag_takes_value(flag, &["run"]),
                "{flag} is fused-value only, so it consumes no following word"
            );
            // The position after it is the command position, exactly as after any other switch.
            assert_eq!(
                cursor_value_kind(&["run"], &words(&[flag])),
                cursor_value_kind(&["run"], &words(&["--detach"])),
                "`sbx run {flag} <TAB>` must offer what any switch leaves: the command"
            );
            // On `app run` the same flags sit before the name, which stays the slot on offer.
            assert_eq!(
                cursor_value_kind(&["app", "run"], &words(&[flag])),
                Some(ValueKind::Apps),
                "{flag} swallowed the app name"
            );
        }
        // The fused spelling still carries its cells: `--gpu=<TAB>` is the value position.
        assert_eq!(names_at(&["run"], "--gpu="), ["false", "true"]);
    }

    /// The shared one-shot overrides of `app run` take their value grammar from the `run` page.
    ///
    /// One parser (`take_override_flag`) serves both pages, and the grammar is written out on
    /// `run`; `app run` collapses the set into a single reader-facing row
    /// (`--env / --net / … / --dbus`) that points at `sbx help run` and carries no metavariable.
    /// Read literally, `--net deny` was two operands rather than a flag and its value, so `deny`
    /// consumed the page's only slot — `<name>` — and no app was offered on the one page whose
    /// whole point is the app registry.
    #[test]
    fn the_shared_overrides_of_app_run_take_their_grammar_from_the_run_page() {
        let words = |xs: &[&str]| -> Vec<String> { xs.iter().map(|s| s.to_string()).collect() };
        for typed in [
            vec!["--net", "deny"],
            vec!["--env", "FOO=1"],
            vec!["--bind", "/x"],
            vec!["--limit", "tasks_max=4"],
            vec!["--package", "a=nix:b"],
            vec!["--nixpkgs", "nixos-23.11"],
            vec!["--gui", "none"],
            vec!["--seccomp", "ptrace"],
        ] {
            assert_eq!(
                cursor_value_kind(&["app", "run"], &words(&typed)),
                Some(ValueKind::Apps),
                "{typed:?} took the app-name slot"
            );
        }
        // And the value position itself reads the cells `run` reads, rather than nothing.
        assert_eq!(
            cursor_value_kind(&["app", "run"], &words(&["--net"])),
            cursor_value_kind(&["run"], &words(&["--net"])),
        );
    }

    #[test]
    fn a_removal_verb_completes_the_rules_already_written() {
        let _lock = env_lock();
        let tmp = TmpDir::new();
        std::fs::create_dir_all(tmp.join("sbx").join("apps")).unwrap();
        std::fs::write(
            tmp.join("sbx").join("sbx.toml"),
            "[network]\nmode = \"allow\"\nallow = [\"api.example.com\"]\ndeny = [\"evil.example.com\"]\n\
             [proc]\nmode = \"ask\"\nallow = [\"/usr/bin/git\"]\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("sbx").join("apps").join("demo-app.toml"),
            "cmd = [\"true\"]\n[network]\nmode = \"allow\"\nallow = [\"only.the.app\"]\n",
        )
        .unwrap();
        let _config_home = EnvVar::set("XDG_CONFIG_HOME", tmp.path());

        // The rule a removal could take out is the only argument it accepts, so that is
        // what the position offers — and each verb offers only its own list.
        assert!(names_at(&["net", "unallow"], "").contains(&"api.example.com".to_string()));
        assert!(names_at(&["net", "undeny"], "").contains(&"evil.example.com".to_string()));
        assert!(names_at(&["proc", "unallow"], "").contains(&"/usr/bin/git".to_string()));
        assert!(
            !names_at(&["net", "unallow"], "").contains(&"evil.example.com".to_string()),
            "`unallow` must not offer a rule from the deny list"
        );
        // `--app` moves the scope to that app's own profile, which is the file the removal
        // would edit.
        let scoped = names_at_with(&["net", "unallow"], &["--app", "demo-app"], "");
        assert!(scoped.contains(&"only.the.app".to_string()), "{scoped:?}");
        assert!(
            !scoped.contains(&"api.example.com".to_string()),
            "an app-scoped removal must not offer the baseline's rules: {scoped:?}"
        );
        // The add verb takes a rule that is *not* there yet, so it offers none of them.
        assert!(!names_at(&["net", "allow"], "").contains(&"api.example.com".to_string()));
    }

    #[test]
    fn a_session_slot_reads_the_live_registry() {
        // `SBX_DATA_DIR` is what the rest of the binary reads to find the real data
        // directory, so pinning it to a fixture takes the lock the whole binary shares.
        let _lock = env_lock();
        let tmp = TmpDir::new();
        let registry = crate::session::Registry::at(tmp.path());
        let session = crate::session::Session::current(
            PathBuf::from("/tmp"),
            crate::session::Kind::Shell,
            crate::session::SessionRuntime::Project,
        )
        .expect("the test process itself is a live session");
        registry.register(&session).expect("a registered session");
        let pid = session.pid.to_string();
        let _data_dir = EnvVar::set("SBX_DATA_DIR", tmp.path());

        // `session logs <TAB>` completes the registered pid.
        assert!(names_at(&["session", "logs"], "").contains(&pid));
        assert!(names_at(&["session", "stop"], "").contains(&pid));
        // A prefix filters: `session stop <first digits>` narrows the same pid.
        assert!(names_at(&["session", "stop"], &pid[..pid.len().saturating_sub(1)]).contains(&pid));
    }

    #[test]
    fn a_store_with_a_catalogue_completes_its_archive() {
        let _lock = env_lock();
        let tmp = TmpDir::new();
        let data = tmp.join("data");
        let checkout = data.join("stores").join("hub").join("checkout");
        std::fs::create_dir_all(&checkout).expect("the store checkout dir");
        std::fs::write(
            checkout.join("catalogue.toml"),
            "[plugin.foo]\nscheme = \"x\"\nversion = \"1.2\"\n\
             description = \"test plugin\"\npath = \"plugin/foo\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
        )
        .expect("a catalogue fixture");
        let _data_dir = EnvVar::set("SBX_DATA_DIR", &data);

        // The configured stores are the configured value set: `<data>/stores/hub`.
        let names: Vec<String> = registry_values(&ValueKind::Stores)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(names.contains(&"hub".to_string()), "stores: {names:?}");

        // ... and the store's catalogue plugins answer after its name, with versions.
        let cat: Vec<String> = registry_values(&ValueKind::Catalogue("hub".to_string()))
            .into_iter()
            .map(|(n, d)| format!("{n}={d}"))
            .collect();
        assert!(cat.contains(&"foo=v1.2".to_string()), "catalogue: {cat:?}");
    }

    #[test]
    fn a_config_file_offers_its_tables_and_tasks() {
        let _lock = env_lock();
        let tmp = TmpDir::new();
        std::fs::create_dir_all(tmp.join("sbx")).unwrap();
        std::fs::write(
            tmp.join("sbx").join("sbx.toml"),
            "[defaults]\nfoo = 1\n[task.deploy]\nrun = \"true\"\n",
        )
        .unwrap();
        // The global file and the profile dir live under `$XDG_CONFIG_HOME/sbx`; the data
        // directory is pinned too, since a task slot resolves the layout before reading it.
        let _config_home = EnvVar::set("XDG_CONFIG_HOME", tmp.path());
        let _data_dir = EnvVar::set("SBX_DATA_DIR", tmp.join("data"));

        let tokens = config_tokens();
        let keys: Vec<&str> = tokens.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"defaults"), "{keys:?}");
        assert!(keys.contains(&"task.deploy"), "{keys:?}");

        let tasks: Vec<String> = registry_values(&ValueKind::Tasks)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert!(tasks.contains(&"deploy".to_string()), "tasks: {tasks:?}");
    }

    // ---- exhaustive sweeps over the whole table ----------------------------------

    // These tests pin the properties above over *every* command path there is, so a page
    // added tomorrow is covered the moment it lands.

    #[test]
    fn every_command_path_in_the_table_completes() {
        let mut checked = 0;
        for path in help::all_paths() {
            let (name, parent) = path.split_last().expect("a page path is never empty");
            let name = *name;

            // The parent must be a page (or the root). A subcommand whose parent has no
            // page is unreachable by completion *and* by `sbx help`, since both derive a
            // listing from the same path prefix.
            assert!(
                help::is_command_path(parent),
                "{path:?}: its parent {parent:?} has no page, so this name can never be offered"
            );

            // The three states a word passes through as it is typed: nothing, one
            // character, the whole name, each offering it.
            for cursor in ["", &name[..1], name] {
                let offered = names_at(parent, cursor);
                assert!(
                    offered.contains(&name.to_string()),
                    "{path:?}: not offered for the cursor word {cursor:?} (got {offered:?})"
                );
            }

            // And through the same transparent `help` prefix.
            let via_help: Vec<&str> = std::iter::once("help")
                .chain(parent.iter().copied())
                .collect();
            assert!(
                names_at(&via_help, "").contains(&name.to_string()),
                "{path:?}: not offered under `sbx help {}`",
                parent.join(" ")
            );
            checked += 1;
        }
        // A sweep that silently swept nothing would pass; assert it saw the surface.
        assert!(checked > 80, "only {checked} command paths swept");
    }

    #[test]
    fn every_documented_flag_completes_on_the_page_that_documents_it() {
        let mut checked = 0;
        for path in help::all_paths() {
            let offered = names_at(path, "-");
            for (row, _) in help::options_of(path) {
                for flag in flag_names(row) {
                    assert!(
                        offered.contains(&flag.to_string()),
                        "sbx {}: documents {flag:?} but does not complete it (offers {offered:?})",
                        path.join(" ")
                    );
                    assert!(
                        names_at(path, &flag[..2].to_string()[..]).contains(&flag.to_string()),
                        "sbx {}: {flag:?} is not offered for the prefix {:?}",
                        path.join(" "),
                        &flag[..2]
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 100, "only {checked} documented flags swept");
    }

    /// The invariant `no_page_offers_a_malformed_candidate` states is checked there against every
    /// help *page*. A page is not the only source: `rule_values` reads egress and proc rules out of
    /// the config files a removal would edit, and one of those is the project file — which may have
    /// been authored by whoever wrote the repository the user cloned. A rule is not a bare word by
    /// construction (`re:<regex>` admits `(`, `)`, `|`, `$`), and the emitted bash inserts a
    /// candidate into `COMPREPLY` with no quoting of its own.
    ///
    /// So the invariant needed somewhere to hold, not only somewhere to be asserted.
    #[test]
    fn a_candidate_the_shell_would_expand_is_never_offered() {
        for bad in [
            "re:$(id)",
            "re:`id`",
            "re:a|b",
            "re:(a)",
            "host.test;reboot",
            "a b",
            "quote\"d",
            "amp&",
            "redirect>x",
            "bang!",
            "hash#",
            "",
        ] {
            assert!(
                !insertable(bad),
                "{bad:?} would be inserted onto the user's command line as typed"
            );
        }
        // The shapes a rule legitimately takes still pass, or the gate would silence the feature
        // for exactly the rules people write. Glob and brace characters run nothing — an unmatched
        // glob is left as typed — so they stay.
        for good in [
            "github.com",
            "*.example.com",
            "tcp://db.internal:5432",
            "tcp://[::1]:22",
            "http://example.com:8080/path",
            "{GET,HEAD}example.com",
            "example.com/v1/*",
            "1234",
            "1234.7",
            "--json",
            FILES,
        ] {
            assert!(insertable(good), "{good:?} must still be offered");
        }
    }

    #[test]
    fn no_page_offers_a_malformed_candidate() {
        for path in help::all_paths() {
            // A flag candidate is a bare flag: never a metavariable, an alternation, or
            // the `--` separator.
            for flag in names_at(path, "-") {
                assert!(
                    flag.starts_with('-') && flag != "--",
                    "sbx {}: {flag:?} is not a flag",
                    path.join(" ")
                );
                assert!(
                    !flag.contains([' ', '[', ']', '<', '>', '=', ',', '/', '|', '(', ')']),
                    "sbx {}: grammar leaked into the candidate {flag:?}",
                    path.join(" ")
                );
            }
            // A candidate of a value position is a bare word (the marker the shell
            // turns into a path is the only exception); a `-`-word is an option of
            // the path itself, offered at the bare cursor.
            for name in names_at(path, "") {
                if name == FILES {
                    continue;
                }
                if name.starts_with('-') {
                    assert!(
                        name != "--" && !name.contains('='),
                        "sbx {}: {name:?} is not an option",
                        path.join(" ")
                    );
                    continue;
                }
                // A value candidate is a single word the shell can insert as typed: a
                // registry name, a pid, a `<pid>.<seq>` id, a cell of the grammar. Never
                // a metavariable, an alternation, or a fragment of prose.
                assert!(
                    !name.is_empty()
                        && !name.contains(char::is_whitespace)
                        && !name.contains(['<', '>', '[', ']', '|', '(', ')', ',', '`', '=']),
                    "sbx {}: {name:?} is not a bare candidate",
                    path.join(" ")
                );
            }
        }
    }

    /// The metavariables sbx deliberately does not complete, because the set each names is
    /// not one this machine holds. Everything else the grammar names must map to a value
    /// vocabulary; see [`every_value_position_is_completed_or_declared_unenumerable`].
    ///
    /// Declared by name, not by position: the same name means the same kind of value
    /// wherever it appears. A name that means something enumerable on one page and not on
    /// another is settled in `kind_of_metavar`, which sees the page, and never reaches here.
    const NOT_ENUMERABLE: &[&str] = &[
        // A number: a count, a duration, a size, a port.
        "N", "n", "secs", "port",
        // Free text the user is composing, not choosing: a value being set, a search
        // substring, a host pattern.
        "value", "substr", "h",
        // A rule being *written*. Its removal twin completes from what is already there
        // (`kind_of_metavar` answers `<rule>` on `net unallow` and friends); an add takes
        // precisely the rule that is not in the list yet.
        "rule",
        // A list entry being added to, or removed from, an arbitrary `config` key. The
        // removal half is enumerable in principle, from the list at the key named first.
        "entry", // A locator, not a local name: a URL to fetch, a flake ref to resolve.
        "url", "git-url", "ref",
        // An HTTP method. The proxy's rule grammar takes any verb rather than a closed
        // set, so there is no list to offer.
        "verb",
        // A seccomp relaxation token (`ptrace`, `clone:newuser`), whose vocabulary belongs
        // to the filter builder rather than to the CLI grammar.
        "token",
    ];

    #[test]
    fn every_value_position_is_completed_or_declared_unenumerable() {
        // The sweeps above pin the *commands* and the *options* of every page. This is the
        // third surface: a metavariable that is neither mapped to a value vocabulary nor
        // declared unenumerable is a silent hole — the position offers nothing, and nothing
        // in the tree says whether that was meant. A page added tomorrow lands here.
        let mut holes: Vec<String> = Vec::new();
        for path in help::all_paths() {
            let named = |what: &str| format!("sbx {}: {what}", path.join(" "));
            for slot in operand_slots(path) {
                let Operand::Value(name) = slot else { continue };
                if kind_of_metavar(&name, path).is_some() || NOT_ENUMERABLE.contains(&&*name) {
                    continue;
                }
                holes.push(named(&format!("the operand <{name}>")));
            }
            for (row, _) in help::options_of(path) {
                for flag in flag_names(row) {
                    let Some(tail) = flag_tail(row, flag) else {
                        continue;
                    };
                    if flag_value_kind(flag, path).is_some() {
                        continue;
                    }
                    // A value with no metavariable to declare (a fused cell list) is
                    // answered above; what is left is a named one that is not.
                    let Some(name) = metavar_of(tail) else {
                        continue;
                    };
                    if NOT_ENUMERABLE.contains(&&*name) {
                        continue;
                    }
                    holes.push(named(&format!("{flag} <{name}>")));
                }
            }
        }
        holes.sort();
        holes.dedup();
        assert!(
            holes.is_empty(),
            "these value positions complete nothing and say nothing about it — map the \
             metavariable in `kind_of_metavar`/`flag_metavar_kind`, or add it to \
             `NOT_ENUMERABLE` with the reason:\n{}",
            holes.join("\n")
        );
    }

    #[test]
    fn every_candidate_renders_as_one_clean_line() {
        // The protocol is line-and-tab delimited, so a description with either would
        // split a candidate in two or graft onto the wrong name.
        for path in help::all_paths() {
            for cursor in ["", "-"] {
                for (name, desc) in candidates(&at(path, cursor)) {
                    if name == FILES {
                        continue;
                    }
                    let rendered = describe(&desc);
                    assert!(
                        !rendered.contains(['\t', '\n']),
                        "sbx {}: {name:?} has a multi-line description: {rendered:?}",
                        path.join(" ")
                    );
                    assert!(
                        !rendered.contains('`'),
                        "sbx {}: {name:?} kept its inline-code backticks: {rendered:?}",
                        path.join(" ")
                    );
                    assert!(
                        rendered.chars().count() <= DESC_WIDTH + 1,
                        "sbx {}: {name:?} has an over-long description: {rendered:?}",
                        path.join(" ")
                    );
                }
            }
        }
    }

    #[test]
    fn help_is_offered_once_and_never_under_itself() {
        // `sbx help help` has no page, so offering it again would name a command that
        // does not exist. The transparency fires exactly once.
        assert!(names(&[""]).contains(&"help".to_string()));
        assert!(!names(&["help", ""]).contains(&"help".to_string()));
        assert!(!names(&["help", "he"]).contains(&"help".to_string()));
    }

    /// A candidate may carry a colon of its own — [`insertable`] admits one deliberately, and both
    /// `rule_values` sources produce them: an egress rule is `host:port`, a proc rule can be
    /// `re:…`. `_describe` reads each element as `value:description` and splits on the first
    /// unescaped colon, so such a candidate was cut in half: the menu inserted the truncated word
    /// and rendered the rest as its description, which for `api.example.com:443` completed a
    /// *different rule* than the one offered.
    ///
    /// Pinned on the emitted text rather than driven through a real zsh, which the drives in
    /// `tests/completion.rs` do only where zsh is installed: what a generated script must contain
    /// is a property of this constant.
    #[test]
    fn the_zsh_script_escapes_a_colon_inside_a_candidate() {
        assert!(
            !ZSH.contains(r#"cands+=("${cand}:"#),
            "the value half must not reach `_describe` raw — a candidate's own colon would split it"
        );
        assert!(
            !ZSH.contains(r#"cands+=("$cand")"#),
            "the description-less push splits on the same colon and needs the same escape"
        );
        assert_eq!(
            ZSH.matches(r#"${cand//:/\\:}"#).count(),
            2,
            "both pushes escape the value half"
        );
        // The description is the remainder after the separator, so it is left alone — and it is
        // colon-free anyway only by accident, never by rule.
        assert!(ZSH.contains(r#"cands+=("${cand//:/\\:}:${desc}")"#));
        // And a candidate really can carry one, or this would be guarding nothing.
        assert!(insertable("api.example.com:443"));
        assert!(insertable("re:token"));
    }

    #[test]
    fn every_emitted_script_names_the_completion_entry_point() {
        // A script that forgets to call `__complete` would complete nothing, silently. The
        // whole invocation is pinned, separator included: the oracle refuses a call that
        // does not carry it, so a script that dropped it would fail on every request.
        for (shell, script) in SHELLS {
            assert!(
                script.contains("sbx __complete --"),
                "{shell}: the script must call the completion oracle"
            );
            // And it has to recognise the one answer that is an instruction rather than a
            // candidate, or a path would complete as the literal marker.
            assert!(
                script.contains(FILES),
                "{shell}: the script must recognise the {FILES} marker"
            );
        }
    }
}
