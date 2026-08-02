//! `sbx trust [--show] [path]` and `sbx untrust [path]`: the trust gate's recording side — vouch
//! for a project config's current contents (content-hashed, direnv model) or revoke that trust.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{diag, help, style, trust};

/// The config path an `sbx trust`/`untrust` invocation targets: the given path,
/// or the project `.sbx.toml` in the current directory by default.
fn config_path_arg(arg: Option<OsString>) -> std::path::PathBuf {
    arg.map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(".sbx.toml"))
}

/// Resolve the trust store directory or report why it cannot be located. The
/// absolute-path requirement is a security control (a relative base could let a
/// cloned repo pre-approve itself), so an unresolved store is a hard failure.
fn trust_store_dir() -> Result<std::path::PathBuf, ExitCode> {
    trust::default_store_dir().ok_or_else(|| {
        crate::diag::error(
            "sbx: cannot locate the trust store — set HOME or XDG_STATE_HOME to an absolute path.",
        );
        ExitCode::FAILURE
    })
}

/// `sbx trust [path]` vouches for a project config's current contents;
/// `sbx trust --show [path]` reports its trust state without changing it. `--show` is honored in
/// any position, and an unknown flag or a second path is a usage error — recording trust is the
/// most security-sensitive write in the tool, so a mistyped `--show` must never fall through to it.
pub(crate) fn trust_cmd(args: Vec<OsString>) -> ExitCode {
    let (show, path) = match parse_trust_args(args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            crate::diag::error(&format!("sbx: {msg} — usage: sbx trust [--show] [path]"));
            return ExitCode::from(2);
        }
    };
    let path = config_path_arg(path);
    if show {
        show_trust(path)
    } else {
        record_trust(path)
    }
}

/// Parse `sbx trust`'s arguments into `(show, path)`. `--show` is honored in any position and an
/// unknown flag or a second path is an error — recording trust is the tool's most security-sensitive
/// write, so a mistyped or trailing `--show` must never fall through to it. A pure helper (tested).
fn parse_trust_args(args: Vec<OsString>) -> Result<(bool, Option<OsString>), String> {
    let mut show = false;
    let mut path: Option<OsString> = None;
    for arg in args {
        match arg.to_str() {
            Some("--show") => show = true,
            Some(tok) if tok.starts_with('-') => return Err(format!("unknown flag {tok}")),
            _ => {
                if path.is_some() {
                    return Err("trust takes a single path".to_string());
                }
                path = Some(arg);
            }
        }
    }
    Ok((show, path))
}

/// Record trust for a config's current contents, so its security-relevant fields
/// are honored until the file changes again.
fn record_trust(path: std::path::PathBuf) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    match trust::trust(&store_dir, &path) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_trust_recorded(&path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot trust {}: {e}", path.display()));
            ExitCode::FAILURE
        }
    }
}

/// The confirmation line for a recorded trust — the resulting `trusted` state word in green,
/// matching how `sbx trust --show` renders that state. A pure presenter (its colored layout is
/// asserted in a test); every span is empty under a non-terminal.
fn render_trust_recorded(path: &Path, pal: &style::Palette) -> String {
    format!("sbx: {}trusted{} {}", pal.ok, pal.reset, path.display())
}

/// Report a config's current trust state. A query never changes anything, so it
/// succeeds whatever the state — the verdict is the message, not the exit code.
fn show_trust(path: std::path::PathBuf) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let state = trust::state(&store_dir, &path);
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("{}", render_trust_verdict(&path, state, &pal));
    ExitCode::SUCCESS
}

/// Render a trust verdict — a pure presenter (so its colored layout is asserted in a test). The
/// state word carries the conventional hue: `trusted` green, `untrusted` yellow (the default
/// state, security fields simply not applied — a caution, not an error), and `changed` red (it
/// was trusted and has since drifted, so re-approval is needed). Only the state word is colored;
/// the re-approval hint stays plain. Every span is empty under a non-terminal.
fn render_trust_verdict(path: &Path, state: trust::TrustState, pal: &style::Palette) -> String {
    let (ok, warn, err, r) = (pal.ok, pal.warn, pal.err, pal.reset);
    let verdict = match state {
        trust::TrustState::Trusted => format!("{ok}trusted{r}"),
        trust::TrustState::Untrusted => format!("{warn}untrusted{r}"),
        trust::TrustState::Changed => {
            format!("{err}changed{r} since it was trusted — re-run `sbx trust` to re-approve")
        }
    };
    format!("sbx: {} is {verdict}", path.display())
}

/// `sbx untrust [path]`: revoke a project config's trust, so its security-relevant
/// fields stop applying until it is trusted again.
pub(crate) fn untrust_cmd(args: Vec<OsString>) -> ExitCode {
    // `untrust` takes at most one path and defines no flag, so a leading `-` is a typo rather than
    // a relative path. Read as a path it would revoke nothing and *report success*, which is the
    // one answer a revocation must never give when it did not happen.
    if let Some(bad) = args
        .first()
        .filter(|a| a.to_string_lossy().starts_with('-'))
    {
        diag::error(&format!(
            "sbx: untrust takes no option '{}'",
            bad.to_string_lossy()
        ));
        eprintln!("sbx: usage: {}", help::synopsis_of(&["untrust"]));
        return ExitCode::from(2);
    }
    if let Err(code) = crate::cli::reject_extra(&["untrust"], args.get(1..).unwrap_or_default()) {
        return code;
    }
    let path = config_path_arg(args.into_iter().next());
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let result = match trust::untrust(&store_dir, &path) {
        Ok(existed) => existed,
        Err(e) => {
            crate::diag::error(&format!(
                "sbx: cannot revoke trust for {}: {e}",
                path.display()
            ));
            return ExitCode::FAILURE;
        }
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("{}", render_untrust_result(&path, result, &pal));
    ExitCode::SUCCESS
}

/// The confirmation line for `sbx untrust`. When a marker existed it is revoked — the result is
/// the untrusted default, so `revoked` takes the caution hue that `--show` gives that state; when
/// none existed it is a benign no-op, with the note dimmed. A pure presenter, asserted in a test.
fn render_untrust_result(path: &Path, existed: bool, pal: &style::Palette) -> String {
    if existed {
        format!(
            "sbx: {}revoked{} trust for {}",
            pal.warn,
            pal.reset,
            path.display()
        )
    } else {
        format!(
            "sbx: {} was not trusted; {}nothing to revoke{}",
            path.display(),
            pal.dim,
            pal.reset
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    #[test]
    fn trust_verdict_is_plain_text_when_uncolored() {
        let p = style::Palette::plain();
        let path = Path::new("/p/.sbx.toml");
        assert_eq!(
            render_trust_verdict(path, trust::TrustState::Trusted, &p),
            "sbx: /p/.sbx.toml is trusted"
        );
        assert_eq!(
            render_trust_verdict(path, trust::TrustState::Untrusted, &p),
            "sbx: /p/.sbx.toml is untrusted"
        );
        assert_eq!(
            render_trust_verdict(path, trust::TrustState::Changed, &p),
            "sbx: /p/.sbx.toml is changed since it was trusted — re-run `sbx trust` to re-approve"
        );
    }

    #[test]
    fn parse_trust_args_honors_show_in_any_position_and_rejects_stray_tokens() {
        let os = |s: &str| OsString::from(s);
        // `--show` after the path must SHOW, not record trust — the security-sensitive default.
        let (show, path) = parse_trust_args(vec![os("./repo/.sbx.toml"), os("--show")]).unwrap();
        assert!(show, "trailing --show must be honored");
        assert_eq!(
            path.as_deref(),
            Some(std::ffi::OsStr::new("./repo/.sbx.toml"))
        );
        // `--show` first, path after.
        let (show, path) = parse_trust_args(vec![os("--show"), os("p.toml")]).unwrap();
        assert!(show);
        assert_eq!(path.as_deref(), Some(std::ffi::OsStr::new("p.toml")));
        // No args: record the default path.
        assert_eq!(parse_trust_args(vec![]).unwrap(), (false, None));
        // An unknown flag or a second path is rejected (so a typo cannot fall through to a record).
        assert!(parse_trust_args(vec![os("--shwo")]).is_err());
        assert!(parse_trust_args(vec![os("a.toml"), os("b.toml")]).is_err());
    }

    #[test]
    fn trust_verdict_maps_each_state_to_its_hue_and_resets() {
        // The ON path: each state word takes its own span (green/yellow/red) and resets — a
        // swapped hue (the failure plain output cannot see) is caught here.
        let p = style::Palette::colored();
        let path = Path::new("/p/.sbx.toml");
        let cases = [
            (trust::TrustState::Trusted, p.ok, "trusted"),
            (trust::TrustState::Untrusted, p.warn, "untrusted"),
            (trust::TrustState::Changed, p.err, "changed"),
        ];
        for (state, span, word) in cases {
            let out = render_trust_verdict(path, state, &p);
            assert!(
                out.contains(&format!("{span}{word}{}", p.reset)),
                "{word} must be wrapped in its own span and reset:\n{out}"
            );
        }
    }

    #[test]
    fn trust_confirmations_are_plain_text_when_uncolored() {
        let p = style::Palette::plain();
        let path = Path::new("/p/.sbx.toml");
        assert_eq!(render_trust_recorded(path, &p), "sbx: trusted /p/.sbx.toml");
        assert_eq!(
            render_untrust_result(path, true, &p),
            "sbx: revoked trust for /p/.sbx.toml"
        );
        assert_eq!(
            render_untrust_result(path, false, &p),
            "sbx: /p/.sbx.toml was not trusted; nothing to revoke"
        );
    }

    #[test]
    fn trust_confirmations_carry_the_resulting_state_hue() {
        // The ON path: `trusted` green (matching the verdict), `revoked` yellow (the result is the
        // untrusted default), and the no-op note dimmed — each closed with a reset.
        let p = style::Palette::colored();
        let path = Path::new("/p/.sbx.toml");
        assert!(
            render_trust_recorded(path, &p).contains(&format!("{}trusted{}", p.ok, p.reset)),
            "a recorded trust must show `trusted` in green"
        );
        assert!(
            render_untrust_result(path, true, &p)
                .contains(&format!("{}revoked{}", p.warn, p.reset)),
            "a revocation must show `revoked` in the caution hue"
        );
        assert!(
            render_untrust_result(path, false, &p)
                .contains(&format!("{}nothing to revoke{}", p.dim, p.reset)),
            "a no-op revocation must dim the note"
        );
    }
}
