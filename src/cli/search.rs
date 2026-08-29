//! `sbx search <query>`: nixhub-backed tool discovery — host-side, read-only, no trust gate.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::{diag, help, sandbox, store, style};

/// Parse `sbx search`'s arguments: exactly one query word.
///
/// This verb declares no options at all — its page lists none — so a `-`-prefixed token can only be
/// a mistake, and it is refused rather than skipped. Dropped in silence it answered a different
/// question than the one asked, at exit 0: `sbx search --json ripgrep` printed the human report a
/// script then failed to parse, and `sbx search --limit 5 ripgrep` searched for `5`. It is the rule
/// every sibling reader already applies.
///
/// Further *words* are still ignored, which is a different decision and a deliberate one: nixhub
/// matches a single token, so a multi-word search has nothing to carry — quote a phrase to pass it
/// as one argument. An argument that is not valid UTF-8 cannot be a query nixhub answers to, so it
/// is refused by name rather than dropped.
///
/// `Err` carries the lines to print, in order, so the grammar is unit-tested without capturing
/// output.
fn parse_search_args(args: &[OsString]) -> Result<&str, Vec<String>> {
    let usage = || format!("sbx: usage: {}", help::synopsis("search"));
    let mut query: Option<&str> = None;
    for arg in args {
        match arg.to_str() {
            Some(flag) if flag.starts_with('-') => {
                return Err(vec![format!("sbx: search: unknown flag `{flag}`"), usage()]);
            }
            Some(word) if query.is_none() => query = Some(word),
            Some(_) => {}
            None => {
                return Err(vec!["sbx: search: argument is not valid UTF-8".to_string()]);
            }
        }
    }
    query.ok_or_else(|| vec![usage()])
}

pub(crate) fn run(args: Vec<OsString>) -> ExitCode {
    let query = match parse_search_args(&args) {
        Ok(query) => query,
        Err(lines) => {
            for line in lines {
                diag::error(&line);
            }
            return ExitCode::from(2);
        }
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let Some(nix) = store::resolve_nix(Some(&layout)) else {
        diag::error(
            "sbx: nix not found — `sbx search` needs it to query nixhub. See `sbx doctor`.",
        );
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    match sandbox::search(&nix, &layout, query, &sandbox::current_system(), &pal) {
        Ok(report) => {
            print!("{report}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx search: {e}"));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_search_args;
    use std::ffi::OsString;

    /// A flag this verb does not take is refused, not dropped. `search` declares no options, so
    /// every flag reaching it is a typo — and a dropped one answers a different question than the
    /// one asked with a zero exit and output that looks right: `sbx search --json ripgrep` returned
    /// the human report to a caller waiting for JSON, and `sbx search --limit 5 ripgrep` searched
    /// for `5`.
    #[test]
    fn a_flag_this_verb_does_not_take_is_refused_rather_than_dropped() {
        let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };

        assert_eq!(parse_search_args(&v(&["ripgrep"])), Ok("ripgrep"));
        // Further words are still ignored — nixhub matches one token, and that is documented.
        assert_eq!(parse_search_args(&v(&["ripgrep", "fast"])), Ok("ripgrep"));

        for bad in [v(&["--json", "ripgrep"]), v(&["ripgrep", "--json"])] {
            let err = parse_search_args(&bad).expect_err("an unknown flag is a usage error");
            assert!(err[0].contains("--json"), "{err:?}");
            assert!(
                err.iter().any(|l| l.contains("sbx search")),
                "the refusal shows the verb's own grammar: {err:?}"
            );
        }
        // `--limit 5 ripgrep` used to search for `5`: the flag is what is wrong, and it is named.
        let err = parse_search_args(&v(&["--limit", "5", "ripgrep"])).expect_err("refused");
        assert!(err[0].contains("--limit"), "{err:?}");

        // No query at all is still the usage error it was.
        assert!(parse_search_args(&v(&[])).is_err());
    }
}
