//! `sbx trust [--show] [--yes] [path]` and `sbx untrust [path]`: the trust gate's recording side —
//! vouch for a project config's current contents (content-hashed, direnv model) or revoke that
//! trust.
//!
//! Recording shows what it records. The project tree is writable from the cage, so the contents
//! a user is asked to approve may not be the ones they wrote: `sbx trust` prints how they differ
//! from what was last approved — or all of them, when nothing was — and asks before granting.

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

/// `sbx trust [--yes] [path]` vouches for a project config's current contents, after showing them;
/// `sbx trust --show [path]` reports its trust state without changing it. `--show` is honored in
/// any position, and an unknown flag or a second path is a usage error — recording trust is the
/// most security-sensitive write in the tool, so a mistyped `--show` must never fall through to it.
pub(crate) fn trust_cmd(args: Vec<OsString>) -> ExitCode {
    let TrustArgs { show, yes, path } = match parse_trust_args(args) {
        Ok(parsed) => parsed,
        Err(msg) => {
            crate::diag::error(&format!(
                "sbx: {msg} — usage: {}",
                help::synopsis_of(&["trust"])
            ));
            return ExitCode::from(2);
        }
    };
    let path = config_path_arg(path);
    // The global config and the app profiles under `apps/` are trusted **by location**: no reader
    // ever looks for a marker on either, so recording one writes a file nothing consults and says
    // a gate was closed that does not exist. The editing verbs answer this way already; the verb
    // whose whole subject is trust did not, and `--show` then reported a verdict — "trusted", and
    // "changed since it was trusted" after the next edit — about a gate the loader never opens.
    if trusted_by_location(&path) {
        diag::note(&format!(
            "{} is trusted by location; `sbx trust` is not needed",
            path.display()
        ));
        return ExitCode::SUCCESS;
    }
    if show {
        show_trust(&path)
    } else {
        record_trust(&path, yes)
    }
}

/// Whether this path is one the loader trusts for being where it is: the global config, or a
/// profile under the imported-app directory. Compared on the canonical parent, like the trust store
/// keys, so a path reached through a symlinked home answers the same.
fn trusted_by_location(path: &Path) -> bool {
    // The parent goes through `trust::canonicalize_existing_prefix`, which names the current
    // directory explicitly: the parent of a bare `claude.toml` is the empty path, which
    // `canonicalize` refuses, so a name given from inside the config or `apps/` directory would
    // otherwise stay relative and match neither location.
    let canon = |p: &Path| {
        p.parent()
            .map(|d| trust::canonicalize_existing_prefix(d).join(p.file_name().unwrap_or_default()))
    };
    let this = canon(path);
    if this.is_none() {
        return false;
    }
    if let Some(global) = crate::config::global_config_path()
        && canon(&global) == this
    {
        return true;
    }
    match (crate::config::profiles_dir(), path.parent()) {
        (Some(dir), Some(parent)) => dir
            .canonicalize()
            .is_ok_and(|dir| dir == trust::canonicalize_existing_prefix(parent)),
        _ => false,
    }
}

/// `sbx trust`'s parsed arguments.
#[derive(Debug, PartialEq, Eq)]
struct TrustArgs {
    /// `--show`: report the state, change nothing.
    show: bool,
    /// `--yes`: record without asking — the answer a script gives, since it has no terminal.
    yes: bool,
    /// The config to act on; the project `.sbx.toml` of the current directory when absent.
    path: Option<OsString>,
}

/// Parse `sbx trust`'s arguments. `--show` and `--yes` are honored in any position and an unknown
/// flag or a second path is an error — recording trust is the tool's most security-sensitive
/// write, so a mistyped or trailing `--show` must never fall through to it. A pure helper (tested).
fn parse_trust_args(args: Vec<OsString>) -> Result<TrustArgs, String> {
    let mut parsed = TrustArgs {
        show: false,
        yes: false,
        path: None,
    };
    for arg in args {
        match arg.to_str() {
            Some("--show") => parsed.show = true,
            Some("--yes") => parsed.yes = true,
            Some(tok) if tok.starts_with('-') => return Err(format!("unknown flag {tok}")),
            _ => {
                if parsed.path.is_some() {
                    return Err("trust takes a single path".to_string());
                }
                parsed.path = Some(arg);
            }
        }
    }
    Ok(parsed)
}

/// Record trust for a config's current contents, so its security-relevant fields are honored
/// until the file changes again.
///
/// The contents are read once, shown, and those very bytes are what gets hashed
/// ([`trust::trust_written`]): the tree is writable from the cage, so a second read after the
/// question would attest to whatever was written while the user was reading. A config that already
/// matches its marker grants nothing new and is re-recorded without a question.
fn record_trust(path: &Path, yes: bool) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let read = crate::config::safety::read_safe_bytes(path)
        .and_then(|sbx| Ok((sbx, trust::mise_inputs_for(path)?)));
    let (sbx_bytes, mise) = match read {
        Ok(read) => read,
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot trust {e}"));
            return ExitCode::FAILURE;
        }
    };
    let current = trust::content_hash(&sbx_bytes, &mise);
    if trust::verdict_for_hash(&store_dir, path, &current) != trust::TrustState::Trusted {
        let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
        let before = trust::approved(&store_dir, path);
        let now = contents_of(path, &sbx_bytes, &mise);
        let was = before
            .as_ref()
            .map(|(sbx, mise)| contents_of(path, sbx, mise));
        eprint!("{}", render_trust_review(path, was.as_deref(), &now, &epal));
        if !yes && !crate::cli::confirm::ask("trust these contents?", "these contents are intended")
        {
            diag::error(&format!("sbx: not trusting {}", path.display()));
            return ExitCode::FAILURE;
        }
    }
    match trust::trust_written(&store_dir, path, &sbx_bytes, &mise) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_trust_recorded(path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            crate::diag::error(&format!("sbx: cannot trust {e}"));
            ExitCode::FAILURE
        }
    }
}

/// One file of what a trust covers: the name it is shown under, and its text.
type Shown = (String, String);

/// The files a trust covers, named for display: the config as it was given, then each mise file
/// by its path relative to the project. Bytes that are not UTF-8 are shown lossily — the review is
/// for a reader, and the hash is over the bytes whatever is displayed.
fn contents_of(path: &Path, sbx: &[u8], mise: &trust::MiseInputs) -> Vec<Shown> {
    let mut out = vec![(
        path.display().to_string(),
        String::from_utf8_lossy(sbx).into_owned(),
    )];
    for (name, bytes) in mise {
        out.push((name.clone(), String::from_utf8_lossy(bytes).into_owned()));
    }
    out
}

/// The review printed before a trust is recorded: per file, what changed since the approved
/// contents — or, when none are recorded, every line, since all of it is being granted. A file
/// that appeared shows as all added, one that went away as all removed, and an unchanged file is
/// not shown. A pure presenter (its layout is asserted in a test).
fn render_trust_review(
    path: &Path,
    approved: Option<&[Shown]>,
    now: &[Shown],
    pal: &style::Palette,
) -> String {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let mut out = match approved {
        Some(_) => format!(
            "sbx: {n}{}{r} changed since it was trusted; trusting it grants:\n",
            path.display()
        ),
        None => format!(
            "sbx: {n}{}{r} {dim}(no approved contents on record){r}; trusting it grants:\n",
            path.display()
        ),
    };
    let find = |set: &[Shown], name: &str| {
        set.iter()
            .find(|(k, _)| k == name)
            .map(|(_, text)| text.clone())
    };
    let mut names: Vec<&str> = now.iter().map(|(k, _)| k.as_str()).collect();
    for (k, _) in approved.unwrap_or_default() {
        if !names.contains(&k.as_str()) {
            names.push(k);
        }
    }
    for name in names {
        let old = approved.and_then(|set| find(set, name)).unwrap_or_default();
        let new = find(now, name).unwrap_or_default();
        if approved.is_some() && old == new {
            continue;
        }
        out.push_str(&format!("{n}--- {name}{r}\n"));
        out.push_str(&render_line_diff(&old, &new, pal));
    }
    out
}

/// A line diff of `old` against `new`: removed lines under `-`, added ones under `+`, each run of
/// changes introduced by the line numbers it starts at, unchanged lines left out. A pure presenter.
///
/// The common head and tail are set aside first, and the middle is matched by longest common
/// subsequence. A middle too large for that table is shown as removed in full and added in full:
/// more than the change, never less, which is the direction a review may err in.
fn render_line_diff(old: &str, new: &str, pal: &style::Palette) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);
    let ops = diff_ops(am, bm);
    let (mut out, mut i, mut j, mut in_run) = (String::new(), 0, 0, false);
    for op in ops {
        if op == Op::Same {
            (i, j, in_run) = (i + 1, j + 1, false);
            continue;
        }
        if !in_run {
            out.push_str(&format!(
                "{}@@ -{} +{} @@{}\n",
                pal.dim,
                head + i + 1,
                head + j + 1,
                pal.reset
            ));
            in_run = true;
        }
        if op == Op::Del {
            out.push_str(&format!("{}-{}{}\n", pal.err, am[i], pal.reset));
            i += 1;
        } else {
            out.push_str(&format!("{}+{}{}\n", pal.ok, bm[j], pal.reset));
            j += 1;
        }
    }
    out
}

/// One step of a line diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Same,
    Del,
    Add,
}

/// The largest LCS table [`diff_ops`] builds, in cells; past it the middle is replaced whole.
const MAX_DIFF_CELLS: usize = 4_000_000;

/// The edit script from `a` to `b`, by longest common subsequence. Every line of `a` is consumed
/// by a `Same` or a `Del`, every line of `b` by a `Same` or an `Add`, in order.
fn diff_ops(a: &[&str], b: &[&str]) -> Vec<Op> {
    let (n, m) = (a.len(), b.len());
    if n.saturating_mul(m) > MAX_DIFF_CELLS {
        return std::iter::repeat_n(Op::Del, n)
            .chain(std::iter::repeat_n(Op::Add, m))
            .collect();
    }
    // `lcs[i][j]`: the longest common subsequence of `a[i..]` and `b[j..]`.
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut ops) = (0, 0, Vec::with_capacity(n + m));
    while i < n || j < m {
        if i < n && j < m && a[i] == b[j] {
            ops.push(Op::Same);
            (i, j) = (i + 1, j + 1);
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            ops.push(Op::Add);
            j += 1;
        } else {
            ops.push(Op::Del);
            i += 1;
        }
    }
    ops
}

/// The confirmation line for a recorded trust — the resulting `trusted` state word in green,
/// matching how `sbx trust --show` renders that state. A pure presenter (its colored layout is
/// asserted in a test); every span is empty under a non-terminal.
fn render_trust_recorded(path: &Path, pal: &style::Palette) -> String {
    format!("sbx: {}trusted{} {}", pal.ok, pal.reset, path.display())
}

/// Report a config's current trust state. A query never changes anything, so it
/// succeeds whatever the state — the verdict is the message, not the exit code.
fn show_trust(path: &Path) -> ExitCode {
    let store_dir = match trust_store_dir() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let state = trust::state(&store_dir, path);
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!("{}", render_trust_verdict(path, state, &pal));
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
    // The same pair as `trust`: a file trusted by location has no marker to revoke, and answering
    // "was not trusted" about it would describe a gate that does not exist.
    if trusted_by_location(&path) {
        diag::note(&format!(
            "{} is trusted by location; there is no marker to revoke",
            path.display()
        ));
        return ExitCode::SUCCESS;
    }
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
        let parsed = parse_trust_args(vec![os("./repo/.sbx.toml"), os("--show")]).unwrap();
        assert!(parsed.show, "trailing --show must be honored");
        assert_eq!(parsed.path, Some(os("./repo/.sbx.toml")));
        // `--show` first, path after.
        let parsed = parse_trust_args(vec![os("--show"), os("p.toml")]).unwrap();
        assert!(parsed.show);
        assert_eq!(parsed.path, Some(os("p.toml")));
        // `--yes` in either position, and not mistaken for `--show`.
        let parsed = parse_trust_args(vec![os("p.toml"), os("--yes")]).unwrap();
        assert_eq!(
            parsed,
            TrustArgs {
                show: false,
                yes: true,
                path: Some(os("p.toml"))
            }
        );
        // No args: record the default path, asking first.
        assert_eq!(
            parse_trust_args(vec![]).unwrap(),
            TrustArgs {
                show: false,
                yes: false,
                path: None
            }
        );
        // An unknown flag or a second path is rejected (so a typo cannot fall through to a record).
        assert!(parse_trust_args(vec![os("--shwo")]).is_err());
        assert!(parse_trust_args(vec![os("--y")]).is_err());
        assert!(parse_trust_args(vec![os("a.toml"), os("b.toml")]).is_err());
    }

    fn shown(set: &[(&str, &str)]) -> Vec<Shown> {
        set.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_review_shows_what_changed_since_the_approval_and_nothing_else() {
        // The scenario the review exists for: the cage appends a bind to a trusted config, and the
        // user is asked to re-approve. The added path is what they must see.
        let p = style::Palette::plain();
        let was = shown(&[
            (".sbx.toml", "network = \"filter\"\nenv = { A = \"1\" }\n"),
            ("mise.toml", "[tools]\nnode = \"22\"\n"),
        ]);
        let now = shown(&[
            (
                ".sbx.toml",
                "network = \"filter\"\nbinds = [\"/home/u/.ssh\"]\nenv = { A = \"1\" }\n",
            ),
            ("mise.toml", "[tools]\nnode = \"22\"\n"),
        ]);
        assert_eq!(
            render_trust_review(Path::new(".sbx.toml"), Some(&was), &now, &p),
            "sbx: .sbx.toml changed since it was trusted; trusting it grants:\n\
             --- .sbx.toml\n\
             @@ -2 +2 @@\n\
             +binds = [\"/home/u/.ssh\"]\n"
        );
    }

    #[test]
    fn the_review_shows_every_line_when_nothing_was_approved_and_a_file_that_appeared() {
        let p = style::Palette::plain();
        let now = shown(&[(".sbx.toml", "binds = [\"/a\"]\n")]);
        assert_eq!(
            render_trust_review(Path::new(".sbx.toml"), None, &now, &p),
            "sbx: .sbx.toml (no approved contents on record); trusting it grants:\n\
             --- .sbx.toml\n\
             @@ -1 +1 @@\n\
             +binds = [\"/a\"]\n"
        );
        // A mise file created since the approval shows whole; one removed shows as removed.
        let was = shown(&[(".sbx.toml", "x = 1\n"), (".tool-versions", "node 20\n")]);
        let now = shown(&[(".sbx.toml", "x = 1\n"), ("mise.toml", "[tools]\n")]);
        let out = render_trust_review(Path::new(".sbx.toml"), Some(&was), &now, &p);
        assert!(
            out.contains("--- mise.toml\n@@ -1 +1 @@\n+[tools]\n"),
            "{out}"
        );
        assert!(
            out.contains("--- .tool-versions\n@@ -1 +1 @@\n-node 20\n"),
            "{out}"
        );
        assert!(
            !out.contains("--- .sbx.toml"),
            "an unchanged file is not shown:\n{out}"
        );
    }

    #[test]
    fn the_line_diff_replays_into_the_new_text() {
        // Whatever the script, applying it to the old lines must give the new ones — including the
        // fallback past the table limit, which replaces the middle whole.
        let cases = [
            ("a\nb\nc\n", "a\nx\nc\n"),
            ("", "a\nb\n"),
            ("a\nb\n", ""),
            ("a\nb\nc\nd\n", "b\nd\ne\n"),
            ("same\n", "same\n"),
        ];
        for (old, new) in cases {
            let (a, b): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
            let (mut i, mut j, mut out) = (0, 0, Vec::new());
            for op in diff_ops(&a, &b) {
                match op {
                    Op::Same => {
                        assert_eq!(a[i], b[j]);
                        out.push(a[i]);
                        (i, j) = (i + 1, j + 1);
                    }
                    Op::Del => i += 1,
                    Op::Add => {
                        out.push(b[j]);
                        j += 1;
                    }
                }
            }
            assert_eq!(
                (i, j, out),
                (a.len(), b.len(), b.clone()),
                "{old:?} -> {new:?}"
            );
        }
        let big: Vec<String> = (0..3000).map(|n| n.to_string()).collect();
        let big: Vec<&str> = big.iter().map(String::as_str).collect();
        let ops = diff_ops(&big, &big[1..]);
        assert_eq!(
            ops.iter().filter(|o| **o == Op::Del).count(),
            3000,
            "past the limit"
        );
        assert_eq!(ops.iter().filter(|o| **o == Op::Add).count(), 2999);
    }

    #[test]
    fn the_review_colors_removals_and_additions() {
        let p = style::Palette::colored();
        let out = render_line_diff("a\n", "b\n", &p);
        assert!(out.contains(&format!("{}-a{}", p.err, p.reset)), "{out:?}");
        assert!(out.contains(&format!("{}+b{}", p.ok, p.reset)), "{out:?}");
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
