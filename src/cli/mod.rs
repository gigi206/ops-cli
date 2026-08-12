//! The command-line surface: argument parsing, dispatch, and per-command handlers, one module
//! per command family. `main` parses argv and routes here; each family owns its argument
//! parsing, orchestration, and output rendering.

pub(crate) mod app;
pub(crate) mod bundle;
pub(crate) mod completion;
pub(crate) mod config;
pub(crate) mod confirm;
pub(crate) mod doctor;
pub(crate) mod fs;
pub(crate) mod gc;
pub(crate) mod logs;
pub(crate) mod net;
pub(crate) mod plugins;
pub(crate) mod proc;
pub(crate) mod projects;
pub(crate) mod search;
pub(crate) mod secret;
pub(crate) mod session;
pub(crate) mod sshagent;
pub(crate) mod storage;
pub(crate) mod store;
pub(crate) mod task;
pub(crate) mod test;
pub(crate) mod trust;
pub(crate) mod upgrade;

use crate::diag;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

/// Refuse an argument a verb does not take, rather than ignoring it. Silently dropping one is worse
/// than not supporting it: `sbx plugins store ls --installed` would print the whole listing, which
/// reads as a filtered result and quietly answers a different question than the one asked — and a
/// mistyped flag would look like it worked. Names the offending token and prints the verb's own
/// usage. Shared by every family, so the behavior is one rule rather than a per-verb habit.
pub(crate) fn reject_extra(path: &[&str], extra: &[OsString]) -> Result<(), ExitCode> {
    let Some(tok) = extra.first() else {
        return Ok(());
    };
    diag::error(&format!(
        "sbx: {} takes no {}",
        path.join(" "),
        match tok.to_str() {
            Some(t) if t.starts_with('-') => format!("option '{t}'"),
            Some(t) => format!("argument '{t}'"),
            None => "such argument".to_string(),
        }
    ));
    eprintln!("sbx: usage: {}", crate::help::synopsis_of(path));
    Err(ExitCode::from(2))
}

/// What parsing a `<verb> <name> [switch]` command line yielded: show the verb's page, run with the
/// name and the switch's state, or report a usage error. `Error` carries the message already
/// formatted, and a hint only where the verb offers one, so the caller reports without deciding
/// anything.
#[derive(Debug, PartialEq)]
pub(crate) enum OneName<'a> {
    Help,
    Run {
        name: &'a str,
        switch: bool,
    },
    Error {
        message: String,
        hint: Option<String>,
    },
}

/// Parse the grammar shared by the verbs that inspect or act on a single named thing
/// (`sbx app show`, `sbx app prune`, `sbx projects show`): one required name, one optional boolean
/// switch under any of its spellings, and the usual help flags. Pure — it reads no config and
/// prints nothing — so the grammar is unit-tested, which a loop returning an `ExitCode` around
/// `println!` is not.
///
/// A second positional is an error rather than being swallowed: `sbx app show one two` silently
/// inspecting `one` would answer a different question than the one asked, and a mistyped name would
/// look like it worked. The same reasoning as [`reject_extra`], applied to a verb that does take one
/// argument. An argument that is not valid UTF-8 cannot be a name sbx knows, so it is refused by the
/// same rule instead of being lossily converted.
///
/// Only an unknown flag carries a hint: it is the one mistake whose fix is to read the verb's
/// options, whereas an extra argument, a bad encoding and a missing name each say what to do in the
/// message itself.
pub(crate) fn parse_one_name<'a>(
    args: &'a [OsString],
    path: &[&str],
    switches: &[&str],
    missing: &str,
) -> OneName<'a> {
    let verb = path.join(" ");
    let mut name: Option<&str> = None;
    let mut switch = false;
    for a in args {
        match a.to_str() {
            Some(s) if switches.contains(&s) => switch = true,
            Some("--help") | Some("-h") => return OneName::Help,
            Some(flag) if flag.starts_with('-') => {
                return OneName::Error {
                    message: format!("sbx: {verb}: unknown flag `{flag}`"),
                    hint: Some(format!("       run `sbx help {verb}` for usage.")),
                };
            }
            Some(other) if name.is_none() => name = Some(other),
            Some(extra) => {
                return OneName::Error {
                    message: format!("sbx: {verb}: unexpected extra argument `{extra}`"),
                    hint: None,
                };
            }
            None => {
                return OneName::Error {
                    message: format!("sbx: {verb}: argument is not valid UTF-8"),
                    hint: None,
                };
            }
        }
    }
    match name {
        Some(name) => OneName::Run { name, switch },
        // The synopsis rather than a hint: the name is positional, so seeing where it goes is the
        // answer.
        None => OneName::Error {
            message: format!(
                "sbx: {verb}: {missing} — usage: {}",
                crate::help::synopsis_of(path)
            ),
            hint: None,
        },
    }
}

/// [`parse_one_name`] plus the reporting each call site would otherwise repeat: the verb's page for
/// a help flag, the usage error with its hint otherwise, and the name and switch when the line
/// parses. `Err` carries the code the handler must return, which for a help flag is a success.
/// Kept apart from the parsing so the grammar is tested on its values rather than through captured
/// output.
pub(crate) fn one_name<'a>(
    args: &'a [OsString],
    path: &[&str],
    switches: &[&str],
    missing: &str,
) -> Result<(&'a str, bool), ExitCode> {
    match parse_one_name(args, path, switches, missing) {
        OneName::Run { name, switch } => Ok((name, switch)),
        OneName::Help => Err(crate::help::show(path)),
        OneName::Error { message, hint } => {
            diag::error(&message);
            if let Some(hint) = hint {
                diag::hint(&hint);
            }
            Err(ExitCode::from(2))
        }
    }
}

/// What parsing a `<verb> <file> [switch]` command line yielded: the path with the switch's state,
/// or the refusal as the lines to print in order. An unknown flag prints the synopsis under itself
/// because the fix is to read the verb's options; the other two refusals say enough on their own.
#[derive(Debug, PartialEq)]
pub(crate) enum OneFile {
    Run { file: PathBuf, switch: bool },
    Error(Vec<String>),
}

/// Parse the grammar the fragment-importing verbs share (`sbx bundle import`,
/// `sbx net groups import`): exactly one file, one optional boolean switch under any of its
/// spellings. Pure, so the grammar is unit-tested without writing to anyone's config.
///
/// The file is taken as raw bytes rather than through `to_str`, so a path that is not valid UTF-8
/// still names the file the user meant; that is the opposite of [`parse_one_name`], where the
/// argument has to match something sbx knows by name. A second file is refused rather than
/// overwriting the first, since importing the wrong fragment writes to the global config.
pub(crate) fn parse_one_file(args: &[OsString], path: &[&str], switches: &[&str]) -> OneFile {
    let verb = path.join(" ");
    let usage = format!("sbx: usage: {}", crate::help::synopsis_of(path));
    let mut switch = false;
    let mut file: Option<PathBuf> = None;
    for arg in args {
        match arg.to_str() {
            Some(s) if switches.contains(&s) => switch = true,
            Some(flag) if flag.starts_with('-') => {
                return OneFile::Error(vec![format!("sbx: {verb}: unknown flag `{flag}`"), usage]);
            }
            _ => {
                if file.is_some() {
                    return OneFile::Error(vec![format!("sbx: {verb}: expected exactly one file")]);
                }
                file = Some(PathBuf::from(arg));
            }
        }
    }
    match file {
        Some(file) => OneFile::Run { file, switch },
        None => OneFile::Error(vec![usage]),
    }
}

/// [`parse_one_file`] plus the reporting, the way [`one_name`] pairs with [`parse_one_name`].
pub(crate) fn one_file(
    args: &[OsString],
    path: &[&str],
    switches: &[&str],
) -> Result<(PathBuf, bool), ExitCode> {
    match parse_one_file(args, path, switches) {
        OneFile::Run { file, switch } => Ok((file, switch)),
        OneFile::Error(lines) => {
            for line in lines {
                diag::error(&line);
            }
            Err(ExitCode::from(2))
        }
    }
}

/// Fold a name repeated in one multi-name removal (`sbx app rm`, `sbx plugins rm`) down to a single
/// removal, keeping the order the user typed. Without this the second pass over a name finds
/// nothing left to remove and reports a phantom failure over work that in fact succeeded.
pub(crate) fn dedupe_names(names: &mut Vec<&str>) {
    let mut seen = std::collections::HashSet::new();
    names.retain(|name| seen.insert(*name));
}

/// Route a resolved command name to its handler. `main` has already peeled off the help paths
/// (`sbx --help`, `sbx <cmd> --help`) and the no-command usage error, so every name that reaches
/// here is a concrete command plus its remaining arguments; each family owns its parsing from this
/// point. The shared leading-flag helpers (`flag_name`/`take_override_flag`/`build_override`) and
/// the standalone `path` verb live at the crate root, reached via `crate::`.
pub(crate) fn dispatch(name: &str, rest: Vec<OsString>) -> ExitCode {
    // A one-time, terminal-only suggestion to adopt a storage volume, on the first interactive
    // launch of an eligible host. Silent and immediate in every other case — a non-launch verb, a
    // non-terminal (so an agent, a pipe or CI never meets it), an override already set, a host
    // already using a volume, one already offered, or an ineligible host.
    storage::maybe_propose_on_launch(name, &rest);
    match name {
        // Internal: the network-namespace holder. Runs host-side (never in the cage), pre-creates
        // the cage's network namespace with a black-hole `dummy0` interface so an in-cage browser
        // reports itself online, then execs the real `bwrap …` command. Never invoked by a user
        // directly. `rest` is `[bwrap, bwrap-args…]`; it never returns.
        "__netns-holder" => crate::sandbox::run_holder(&rest),
        // Internal: the oracle the emitted completion scripts call on every completion
        // request. Answers with the candidates for the words typed so far and nothing
        // else — never invoked by a user directly, so it carries no page of its own.
        "__complete" => completion::complete_cmd(rest),
        "completion" => completion::completion_cmd(rest),
        "doctor" => match reject_extra(&["doctor"], &rest) {
            Err(code) => code,
            Ok(()) => doctor::doctor(),
        },
        "session" | "sessions" => session::session_cmd(rest),
        "trust" => trust::trust_cmd(rest),
        "untrust" => trust::untrust_cmd(rest),
        "config" => config::config_cmd(rest),
        "upgrade" => upgrade::upgrade_cmd(rest),
        "gc" => gc::run(rest),
        "projects" | "project" => projects::projects_cmd(rest),
        "storage" => storage::storage_cmd(rest),
        "store" => store::store_cmd(rest),
        "path" => crate::path_cmd(&rest),
        "run" => {
            let mut cmd: Vec<OsString> = rest;
            // Leading sbx flags before the command: `--detach` to run in the background, a one-shot
            // override (the whole-schema `--config <toml|@file>` and the typed `--env`/`--net`/
            // `--gui`/`--nixpkgs`/`--bind`/`--limit`/`--package`, each repeatable), `--help`/`-h` for
            // this command's page, and an optional `--` separating sbx's arguments from the
            // command's. The `--` is consumed before scanning the command, so `sbx run -- --detach`
            // (or `-- --help`) runs the literal argument.
            let mut detach = false;
            let mut observe = false;
            let mut cli = crate::config::CliOverrides::default();
            while let Some(raw) = cmd.first().and_then(|a| a.to_str()) {
                match crate::flag_name(raw) {
                    "--detach" => {
                        detach = true;
                        cmd.remove(0);
                    }
                    "--observe" => {
                        observe = true;
                        cmd.remove(0);
                    }
                    "--help" | "-h" => return crate::help::show(&["run"]),
                    "--" => {
                        cmd.remove(0);
                        break;
                    }
                    // A one-shot override flag, or the start of the command.
                    _ => match crate::take_override_flag(&mut cmd, &mut cli, "run") {
                        Some(Ok(())) => {}
                        Some(Err(c)) => return c,
                        None => break,
                    },
                }
            }
            let ov = match crate::build_override(cli) {
                Ok(ov) => ov,
                Err(c) => return c,
            };
            crate::sandbox::run(cmd, detach, observe, ov)
        }
        "mise" => {
            // A passthrough, so a help flag is only sbx's when it leads: `sbx mise --help`
            // shows sbx's page, while `sbx mise help` (and any later `--help`) reaches the
            // in-cage mise's own help.
            if matches!(rest.first().and_then(|a| a.to_str()), Some("--help" | "-h")) {
                return crate::help::show(&["mise"]);
            }
            crate::sandbox::run_mise(rest)
        }
        "app" => app::app_cmd(rest),
        "search" => search::run(rest),
        "test" => test::test_cmd(rest),
        "bundle" => bundle::bundle_cmd(&rest),
        "net" => net::net_cmd(rest),
        "ssh-agent" => sshagent::ssh_agent_cmd(rest),
        "proc" => proc::proc_cmd(rest),
        "fs" => fs::fs_cmd(rest),
        "logs" | "log" => match crate::help::maybe_help("logs", &rest) {
            Some(code) => code,
            None => logs::run_merged(&rest),
        },
        "task" | "tasks" => task::task_cmd(rest),
        "secret" | "secrets" => secret::secret_cmd(rest),
        "plugins" => plugins::plugins_cmd(rest),
        other => {
            diag::error(&format!("sbx: unknown command '{other}'"));
            diag::hint("Run `sbx --help` for the list of commands.");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OneFile, OneName, dedupe_names, one_name, parse_one_file, parse_one_name};
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn dedupe_names_keeps_the_first_of_each_in_order() {
        let mut names = vec!["demo-tool", "demo-app", "demo-tool", "demo-app", "demo-svc"];
        dedupe_names(&mut names);
        assert_eq!(names, vec!["demo-tool", "demo-app", "demo-svc"]);
    }

    fn os(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    /// `sbx app show`'s grammar, which every assertion below spells out literally rather than
    /// rebuilding it from `path` the way the function does.
    fn show(args: &[OsString]) -> OneName<'_> {
        parse_one_name(args, &["app", "show"], &["--json"], "name an app")
    }

    #[test]
    fn a_name_parses_with_the_switch_on_either_side_of_it() {
        assert_eq!(
            show(&os(&["demo-app"])),
            OneName::Run {
                name: "demo-app",
                switch: false
            }
        );
        for line in [["demo-app", "--json"], ["--json", "demo-app"]] {
            assert_eq!(
                show(&os(&line)),
                OneName::Run {
                    name: "demo-app",
                    switch: true
                },
                "{line:?}"
            );
        }
        // The switch repeated is not a second positional.
        assert_eq!(
            show(&os(&["--json", "demo-app", "--json"])),
            OneName::Run {
                name: "demo-app",
                switch: true
            }
        );
    }

    #[test]
    fn each_spelling_of_a_switch_turns_it_on() {
        for spelling in ["-y", "--yes"] {
            assert_eq!(
                parse_one_name(
                    &os(&["demo-app", spelling]),
                    &["app", "prune"],
                    &["-y", "--yes"],
                    "name an app",
                ),
                OneName::Run {
                    name: "demo-app",
                    switch: true
                },
                "{spelling}"
            );
        }
    }

    #[test]
    fn a_help_flag_wins_over_everything_else_on_the_line() {
        for line in [
            vec!["--help"],
            vec!["-h"],
            vec!["demo-app", "--help"],
            vec!["--json", "-h"],
        ] {
            assert_eq!(show(&os(&line)), OneName::Help, "{line:?}");
        }
        // Only over the arguments it reaches: the line is scanned left to right and returns at the
        // first refusal, so a help flag behind an already-refused argument does not rescue it.
        assert!(matches!(
            show(&os(&["a", "b", "--help"])),
            OneName::Error { .. }
        ));
    }

    #[test]
    fn an_unknown_flag_is_named_and_points_at_the_verbs_page() {
        let OneName::Error { message, hint } = show(&os(&["--bogus"])) else {
            panic!("an unknown flag must not parse");
        };
        assert_eq!(message, "sbx: app show: unknown flag `--bogus`");
        assert_eq!(
            hint.as_deref(),
            Some("       run `sbx help app show` for usage.")
        );
        // A flag typed after the name is still a flag, not the extra argument.
        let OneName::Error { message, .. } = show(&os(&["demo-app", "--bogus"])) else {
            panic!("an unknown flag after the name must not parse");
        };
        assert_eq!(message, "sbx: app show: unknown flag `--bogus`");
    }

    #[test]
    fn a_second_name_is_refused_rather_than_swallowed() {
        let OneName::Error { message, hint } = show(&os(&["demo-app", "other-app"])) else {
            panic!("two names must not parse");
        };
        assert_eq!(
            message,
            "sbx: app show: unexpected extra argument `other-app`"
        );
        assert_eq!(hint, None);
    }

    #[test]
    fn a_name_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStringExt;
        let args = vec![OsString::from_vec(vec![0x64, 0xff, 0x6d])];
        let OneName::Error { message, hint } = show(&args) else {
            panic!("a non-UTF-8 name must not parse");
        };
        assert_eq!(message, "sbx: app show: argument is not valid UTF-8");
        assert_eq!(hint, None);
    }

    #[test]
    fn a_missing_name_answers_with_the_verbs_synopsis() {
        for line in [vec![], vec!["--json"]] {
            let OneName::Error { message, hint } = show(&os(&line)) else {
                panic!("a line with no name must not parse: {line:?}");
            };
            assert_eq!(
                message,
                "sbx: app show: name an app — usage: sbx app show <name> [--json]"
            );
            assert_eq!(hint, None);
        }
    }

    /// The pair a caller destructures, which is the one thing a command-line comparison cannot
    /// check: a verb that acts on its switch (`sbx app prune`) previews when it is off and applies
    /// when it is on, so a switch read as anything but the second element would act on a line that
    /// asked for a preview.
    #[test]
    fn the_reported_pair_is_the_name_then_the_switch() {
        for (line, want) in [
            (vec!["demo-app"], ("demo-app", false)),
            (vec!["demo-app", "-y"], ("demo-app", true)),
            (vec!["demo-app", "--yes"], ("demo-app", true)),
        ] {
            let args = os(&line);
            assert_eq!(
                one_name(&args, &["app", "prune"], &["-y", "--yes"], "name an app").ok(),
                Some(want),
                "{line:?}"
            );
        }
    }

    /// `sbx bundle import`'s grammar, spelled out literally the same way.
    fn import(args: &[OsString]) -> OneFile {
        parse_one_file(args, &["bundle", "import"], &["-f", "--force"])
    }

    #[test]
    fn a_file_parses_with_either_spelling_of_the_switch() {
        assert_eq!(
            import(&os(&["frag.toml"])),
            OneFile::Run {
                file: PathBuf::from("frag.toml"),
                switch: false
            }
        );
        for line in [
            vec!["frag.toml", "-f"],
            vec!["frag.toml", "--force"],
            vec!["--force", "frag.toml"],
        ] {
            assert_eq!(
                import(&os(&line)),
                OneFile::Run {
                    file: PathBuf::from("frag.toml"),
                    switch: true
                },
                "{line:?}"
            );
        }
    }

    /// The deliberate difference from [`parse_one_name`]: a path is bytes, so one that is not valid
    /// UTF-8 still names the file the user meant instead of being refused.
    #[test]
    fn a_file_whose_name_is_not_utf8_is_still_the_file() {
        use std::os::unix::ffi::OsStringExt;
        let raw = OsString::from_vec(vec![0x66, 0xff, 0x2e, 0x74, 0x6f, 0x6d, 0x6c]);
        assert_eq!(
            parse_one_file(
                std::slice::from_ref(&raw),
                &["bundle", "import"],
                &["-f", "--force"]
            ),
            OneFile::Run {
                file: PathBuf::from(&raw),
                switch: false
            }
        );
    }

    #[test]
    fn refusing_a_file_says_what_to_do_next() {
        assert_eq!(
            import(&os(&["--bogus"])),
            OneFile::Error(vec![
                "sbx: bundle import: unknown flag `--bogus`".to_string(),
                "sbx: usage: sbx bundle import <file> [-f|--force]".to_string(),
            ])
        );
        // A second file is refused rather than overwriting the first, which would import the wrong
        // fragment into the global config.
        assert_eq!(
            import(&os(&["one.toml", "two.toml"])),
            OneFile::Error(vec![
                "sbx: bundle import: expected exactly one file".to_string()
            ])
        );
        for line in [vec![], vec!["-f"]] {
            assert_eq!(
                import(&os(&line)),
                OneFile::Error(vec![
                    "sbx: usage: sbx bundle import <file> [-f|--force]".to_string()
                ]),
                "{line:?}"
            );
        }
    }

    /// The second verb sharing the grammar, asserted whole for the same reason as the one below.
    #[test]
    fn the_file_refusals_name_the_verb_that_was_run() {
        let path = ["net", "groups", "import"];
        assert_eq!(
            parse_one_file(&os(&["--bogus"]), &path, &["-f", "--force"]),
            OneFile::Error(vec![
                "sbx: net groups import: unknown flag `--bogus`".to_string(),
                "sbx: usage: sbx net groups import <file> [-f|--force]".to_string(),
            ])
        );
        assert_eq!(
            parse_one_file(&os(&["a", "b"]), &path, &["-f", "--force"]),
            OneFile::Error(vec![
                "sbx: net groups import: expected exactly one file".to_string()
            ])
        );
    }

    /// The messages interpolate the verb and its own wording, so a second `path` is asserted whole:
    /// a helper that hardcoded `app show` would pass every test above and still mislabel this one.
    #[test]
    fn the_messages_name_the_verb_that_was_run() {
        let path = ["projects", "show"];
        let missing = "name a tree id";
        let OneName::Error { message, hint } =
            parse_one_name(&os(&["--bogus"]), &path, &["--json"], missing)
        else {
            panic!("an unknown flag must not parse");
        };
        assert_eq!(message, "sbx: projects show: unknown flag `--bogus`");
        assert_eq!(
            hint.as_deref(),
            Some("       run `sbx help projects show` for usage.")
        );

        let OneName::Error { message, .. } = parse_one_name(&os(&[]), &path, &["--json"], missing)
        else {
            panic!("a line with no id must not parse");
        };
        assert_eq!(
            message,
            "sbx: projects show: name a tree id — usage: sbx projects show <id> [--json]"
        );
    }
}
