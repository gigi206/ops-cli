//! `sbx search <query>`: nixhub-backed tool discovery — host-side, read-only, no trust gate.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::process::ExitCode;

use crate::{diag, help, sandbox, store, style};

pub(crate) fn run(args: Vec<OsString>) -> ExitCode {
    // The query is the first non-flag argument; any further words are ignored (nixhub
    // matches a single token, so a multi-word search is pointless — quote a phrase to
    // pass it as one argument if ever needed).
    let query = args
        .iter()
        .filter_map(|a| a.to_str())
        .find(|a| !a.starts_with('-'));
    let Some(query) = query else {
        diag::error(&format!("sbx: usage: {}", help::synopsis("search")));
        return ExitCode::from(2);
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
