//! `sbx completion <shell>` — the shell completion surface, and the hidden `__complete`
//! verb the scripts it emits call back into.
//!
//! The emitted script carries no copy of the command tree: it collects the words typed so
//! far and asks the binary which candidates fit. Every candidate is derived from the help
//! table, so completion cannot drift from the documented surface, and supporting one more
//! shell is one more adapter rather than a second transcription of ninety command paths.
//!
//! The `__complete` protocol: `sbx __complete -- <word>...`, where the words are everything
//! typed after `sbx`, up to and including the (possibly empty) word under the cursor. It
//! writes one `name<TAB>description` line per candidate to stdout, and nothing at all to
//! stderr — a script runs it on every completion request, so a stray diagnostic would land
//! in the middle of the user's prompt.

use std::ffi::OsString;
use std::process::ExitCode;

use crate::{diag, help};

/// The shells a script can be emitted for, and the script for each.
const SHELLS: &[(&str, &str)] = &[("bash", BASH), ("zsh", ZSH)];

/// How much of a description reaches the completion menu. A help page wraps a long line;
/// a completion menu gives each candidate one row, where the same line crowds out the list.
const DESC_WIDTH: usize = 64;

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
        out.push_str(&name);
        out.push('\t');
        out.push_str(&describe(desc));
        out.push('\n');
    }
    print!("{out}");
    ExitCode::SUCCESS
}

/// The candidates for the word under the cursor, alphabetically, already filtered by the
/// prefix typed so far.
fn candidates(words: &[String]) -> Vec<(String, &'static str)> {
    let cur = words.last().map(String::as_str).unwrap_or("");
    let before: &[String] = words.split_last().map_or(&[], |(_, b)| b);

    // Past a bare `--` the words belong to a launched command, not to sbx. Offering sbx's
    // own names there would be wrong, and an empty answer lets the shell complete files.
    if before.iter().any(|w| w == "--") {
        return Vec::new();
    }

    // The deepest known command path the words name. A leading `help` is transparent, so
    // `sbx help plugins store` offers the same subcommands as `sbx plugins store`.
    let mut path: Vec<&str> = Vec::new();
    let mut via_help = false;
    for word in before {
        if word.starts_with('-') {
            continue;
        }
        if path.is_empty() && !via_help && word == "help" {
            via_help = true;
            continue;
        }
        let mut deeper = path.clone();
        deeper.push(word);
        if help::is_command_path(&deeper) {
            path = deeper;
        } else {
            // A positional value (an app name, a session id, a command to run): whatever
            // follows belongs to that value's grammar, not to a deeper subcommand.
            break;
        }
    }

    let mut out: Vec<(String, &'static str)> = if cur.starts_with('-') {
        let mut flags: Vec<(String, &'static str)> = Vec::new();
        for (row, desc) in help::options_of(&path) {
            for name in flag_names(row) {
                if !flags.iter().any(|(f, _)| f == name) {
                    flags.push((name.to_string(), *desc));
                }
            }
        }
        // Accepted on every command path, and documented on almost no page of its own.
        if !flags.iter().any(|(f, _)| f == "--help") {
            flags.push(("--help".to_string(), "show usage for this command"));
        }
        flags
    } else {
        let mut names: Vec<(String, &'static str)> = help::subcommands_of(&path)
            .into_iter()
            .map(|(name, summary)| (name.to_string(), summary))
            .collect();
        if path.is_empty() && !via_help {
            // A real verb with no page of its own, so the table cannot supply it. Offered
            // once: `sbx help help` has no page, so proposing it again under itself would
            // complete a command that does not exist.
            names.push(("help".to_string(), "show usage for a command"));
        }
        names
    };

    out.retain(|(name, _)| name.starts_with(cur));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The completable flag names in one documented option row. A row is written for a reader,
/// not for a parser: it may pair a short and a long spelling (`-a, --app <name>`), offer two
/// opposed flags (`-g, --global / -l, --local`), carry an optional value (`--gpu[=true|false]`),
/// or name no flag at all (a bare `<file>` operand, a literal value such as `tarball`, the
/// `--` separator). Each alternative is split out and stripped of its value grammar; a row
/// that names no flag yields nothing.
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
/// backticks of the help prose dropped, whitespace collapsed (the table wraps its longer
/// descriptions across source lines), and the result cut to one menu row.
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
    // Cut on the last word boundary that fits, so the tail is never half a word.
    let head = match flat[..end].rsplit_once(' ') {
        Some((h, _)) => h,
        None => &flat[..end],
    };
    format!("{}…", head.trim_end_matches([',', ';', ':']))
}

/// The bash script. `-o bashdefault -o default` makes the shell complete filenames whenever
/// sbx answers with nothing, which is how a value operand (a path, an app name) still
/// completes usefully.
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
        [ -n "$cand" ] && COMPREPLY+=("$cand")
    done < <(sbx __complete -- "${typed[@]}" 2>/dev/null)
}
complete -o bashdefault -o default -F _sbx_complete sbx
"#;

/// The zsh script. `_describe` renders the descriptions sbx returns alongside each
/// candidate; `_files` is the fallback when sbx answers with nothing, matching bash's.
const ZSH: &str = r#"#compdef sbx
# zsh completion for sbx. Generated by `sbx completion zsh`.
#
# The command tree lives in the binary, not here: this function forwards the words typed
# so far and renders what comes back, so it cannot go stale as sbx grows verbs.
_sbx() {
    local cand desc
    local -a typed cands
    # Everything after the program name, up to the word under the cursor. `(@)` inside
    # quotes keeps that word when it is empty, which is what asks for the unfiltered list.
    typed=("${(@)words[2,CURRENT]}")
    while IFS=$'\t' read -r cand desc; do
        [[ -z $cand ]] && continue
        if [[ -n $desc ]]; then
            cands+=("${cand}:${desc}")
        else
            cands+=("$cand")
        fi
    done < <(sbx __complete -- "${typed[@]}" 2>/dev/null)
    if (( ${#cands} )); then
        _describe -t sbx-candidates 'sbx' cands
    else
        _files
    fi
}

# Sourced directly (`source <(sbx completion zsh)`), the function has to be registered.
# Autoloaded from $fpath, running the file *is* the first completion call, so serve it.
if [[ $funcstack[1] == _sbx ]]; then
    _sbx "$@"
else
    compdef _sbx sbx
fi
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the word list a shell would send: the words typed, then the cursor word.
    fn words(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    fn names(xs: &[&str]) -> Vec<String> {
        candidates(&words(xs)).into_iter().map(|(n, _)| n).collect()
    }

    /// The word list for `sbx <path...> <cursor>`, the shape a shell sends while the user is
    /// partway through the word after a command path.
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
        // Rows that name no flag: an operand, a literal value, the separator, a prose note.
        assert!(flag_names("<file>").is_empty());
        assert!(flag_names("[name]").is_empty());
        assert!(flag_names("tarball").is_empty());
        assert!(flag_names("(no flag)").is_empty());
        assert!(flag_names("--").is_empty());
        assert!(flag_names("-- command [args...]").is_empty());
    }

    #[test]
    fn the_run_page_yields_only_real_flags() {
        // The worst case in the table: optional-value booleans, inline values, and a bare
        // `--` row all live on this page. Nothing may reach a menu carrying its grammar.
        let flags = names(&["run", "-"]);
        assert!(flags.contains(&"--detach".to_string()));
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
        // Top level, from the empty cursor word a shell sends after `sbx `.
        let top = names(&[""]);
        assert!(top.contains(&"run".to_string()));
        assert!(top.contains(&"completion".to_string()));
        assert!(top.contains(&"help".to_string()));
        // A prefix filters, and the answer stays sorted.
        assert_eq!(names(&["comp"]), ["completion"]);
        // Depth two and three resolve through the table.
        assert!(names(&["app", ""]).contains(&"import".to_string()));
        assert_eq!(names(&["plugins", "store", "publ"]), ["publish"]);
        // A leaf command has no subcommands: the shell falls back to file completion.
        assert!(names(&["doctor", ""]).is_empty());
    }

    #[test]
    fn help_is_transparent_and_offered() {
        // `sbx help <TAB>` offers the same top-level list, and goes as deep as the table.
        assert!(names(&["help", ""]).contains(&"plugins".to_string()));
        assert_eq!(names(&["help", "plugins", "store", "rek"]), ["rekey"]);
        // A prefix immediately after `help` filters that list rather than falling through:
        // the skip fires on the first non-flag word, so nothing is consumed as a path token.
        assert_eq!(names(&["help", "comp"]), ["completion"]);
    }

    #[test]
    fn a_positional_value_does_not_deepen_the_path() {
        // `demo-app` is an app name, not a subcommand; the path stops there rather than
        // matching some deeper page, and flags still come from `app run`.
        assert!(names(&["app", "run", "demo-app", ""]).is_empty());
        assert!(names(&["app", "run", "demo-app", "-"]).contains(&"--help".to_string()));
    }

    #[test]
    fn nothing_is_offered_past_a_double_dash() {
        // Everything after `--` runs literally, so sbx's own names must not appear.
        assert!(names(&["run", "--", ""]).is_empty());
        assert!(names(&["run", "--", "-"]).is_empty());
        // Before the separator, the flags of `run` are still the answer.
        assert!(names(&["run", "--det"]).contains(&"--detach".to_string()));
    }

    #[test]
    fn help_is_completable_on_every_command() {
        // `--help` works everywhere but is documented on almost no page, so it is added.
        assert!(names(&["doctor", "--"]).contains(&"--help".to_string()));
        assert!(names(&["plugins", "store", "add", "--h"]).contains(&"--help".to_string()));
    }

    #[test]
    fn descriptions_survive_as_one_clean_line() {
        // Backticks are dropped, the table's source wrapping is collapsed, and a long
        // description is cut on a word boundary rather than mid-word.
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
            let out = describe(desc);
            assert!(!out.contains(['\n', '\t']), "{out:?}");
        }
    }

    #[test]
    fn a_multibyte_description_is_cut_on_a_character_boundary() {
        // The cut index is a byte offset; walking it back to a boundary is what keeps a
        // description carrying non-ASCII from panicking.
        let d = describe(&"é".repeat(DESC_WIDTH));
        assert!(d.ends_with('…'));
    }

    // ---- exhaustive sweeps over the whole table ------------------------------------
    //
    // The tests above pin specific shapes that once went wrong, or that would go wrong
    // silently. These four assert the same properties over *every* command path there is,
    // so a page added tomorrow is covered the moment it lands rather than when someone
    // remembers to extend a sample.

    #[test]
    fn every_command_path_in_the_table_completes() {
        let mut checked = 0;
        for path in help::all_paths() {
            let (name, parent) = path.split_last().expect("a page path is never empty");
            let name = *name;

            // The parent must be a page (or the root). A subcommand whose parent has no page
            // is unreachable by completion *and* by `sbx help`, since both derive a listing
            // from the path prefix.
            assert!(
                help::is_command_path(parent),
                "{path:?}: its parent {parent:?} has no page, so this name can never be offered"
            );

            // The three states a word passes through as it is typed: nothing yet, a first
            // character, the whole name. Each must offer it.
            for cursor in ["", &name[..1], name] {
                let offered = names_at(parent, cursor);
                assert!(
                    offered.contains(&name.to_string()),
                    "{path:?}: not offered for the cursor word {cursor:?} (got {offered:?})"
                );
            }

            // And the same through the transparent `help` prefix.
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
        // A sweep that silently swept nothing would pass; assert it saw the real surface.
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
                    // A flag also has to survive being typed out character by character.
                    assert!(
                        names_at(path, &flag[..2]).contains(&flag.to_string()),
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

    #[test]
    fn no_page_offers_a_malformed_candidate() {
        for path in help::all_paths() {
            // A flag candidate is a bare flag: never a metavariable, an alternation, or the
            // `--` separator that ends sbx's own options.
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
            // A subcommand candidate is a single bare word.
            for name in names_at(path, "") {
                assert!(
                    !name.is_empty() && !name.starts_with('-'),
                    "sbx {}: {name:?} is not a subcommand name",
                    path.join(" ")
                );
                assert!(
                    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                    "sbx {}: {name:?} is not a bare word",
                    path.join(" ")
                );
            }
        }
    }

    #[test]
    fn every_candidate_on_every_page_renders_as_one_clean_line() {
        // The protocol is line-and-tab delimited, so a description carrying either would
        // split one candidate into two, or graft a description onto the wrong name.
        for path in help::all_paths() {
            for cursor in ["", "-"] {
                for (name, desc) in candidates(&at(path, cursor)) {
                    let rendered = describe(desc);
                    assert!(
                        !rendered.contains(['\n', '\t']),
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
        // `sbx help help` has no page, so completing it would name a command that does not
        // exist. The transparency has to fire exactly once.
        assert!(names(&[""]).contains(&"help".to_string()));
        assert!(!names(&["help", ""]).contains(&"help".to_string()));
        assert!(!names(&["help", "he"]).contains(&"help".to_string()));
    }

    #[test]
    fn every_emitted_script_names_the_completion_entry_point() {
        // A script that forgets to call `__complete` would complete nothing, silently.
        for (shell, script) in SHELLS {
            assert!(
                script.contains("sbx __complete --"),
                "{shell}: the script must call the completion oracle"
            );
            assert!(!script.is_empty());
        }
    }
}
