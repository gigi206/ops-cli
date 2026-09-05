//! Styled stderr diagnostics — the single chokepoint for the `sbx: warning:` / `sbx: note:`
//! family. Each call decides its palette from stderr, so a captured stream is plain text; the
//! prefix carries the severity hue (yellow `warning:`, bold `note:`) and any `` `identifier` ``
//! span in the message is lifted to the identifier hue (cyan). A plain stream is byte-for-byte the
//! bare message with its backticks intact, so existing captured-output assertions are unaffected.

use crate::style::Palette;
use std::io::IsTerminal;

/// Print `sbx: warning: <msg>` to stderr — the prefix in the caution hue, the message's
/// `` `identifiers` `` in the identifier hue, when stderr is a terminal. The message must be the
/// bare text (no `sbx: warning:` prefix — this adds it), so a slip cannot double the prefix.
pub(crate) fn warn(msg: &str) {
    eprintln!(
        "{}",
        warning_line(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// Print a warning whose text a **config file chose** part of, with that part filtered.
///
/// [`warn`]'s text is sbx's own from end to end, so it needs no filter. A configuration warning is
/// not: it names the key or value it is complaining about, and for an untrusted project's
/// `.sbx.toml` that name is the project's to spell — including control bytes and escape sequences,
/// which reach the launching terminal exactly when sbx is telling the user what it refused. That is
/// the one moment the user is reading, so it is the one worth forging: an escape run can erase the
/// trust warnings printed above it.
///
/// The same reasoning already produced `mise_token_display` for the `[tools]` table, with a
/// regression test beside it (`sandbox::launch::equip`, not linked here: it is `pub(super)` in a
/// private module, so no path to it resolves from this one). This is that rule for every other
/// table, so a new warning producer does not have to rediscover it.
pub(crate) fn warn_config(msg: &str) {
    warn(&crate::sandbox::sanitize(msg));
}

/// Print `sbx: note: <msg>` to stderr — an advisory. The prefix is bold (not the caution hue): a
/// note explains a silent no-op (e.g. why a security field did not apply), so it must stay visible
/// without reading as a problem. Same `` `identifier` `` highlighting as [`warn`].
pub(crate) fn note(msg: &str) {
    eprintln!(
        "{}",
        note_line(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// Print a bare stderr line — a continuation of a preceding [`warn`]/[`note`], a `run `sbx help
/// …` for usage.` pointer, a status note — with its `` `identifiers` `` highlighted like the
/// family, so a multi-line diagnostic does not mix the family's cyan with literal backticks. No
/// prefix is added; the caller owns any indent (it is part of `line`), preserved verbatim in
/// plain mode.
pub(crate) fn hint(line: &str) {
    eprintln!(
        "{}",
        highlight(line, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// Print a bare stderr error line (a usage error, a refusal) with its `` `identifiers` ``
/// highlighted. The message carries its own `sbx: …` prefix verbatim — unlike [`warn`]/[`note`],
/// nothing is added — so converting a plain `eprintln!` here changes no byte of a captured
/// stream, only lifts the spans when stderr is a terminal.
pub(crate) fn error(msg: &str) {
    eprintln!(
        "{}",
        highlight(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// The `sbx: warning: <msg>` line. Pure, so the prefix and highlighting are unit-testable without
/// capturing stderr.
fn warning_line(msg: &str, pal: &Palette) -> String {
    format!(
        "sbx: {}warning:{} {}",
        pal.warn,
        pal.reset,
        highlight(msg, pal)
    )
}

/// The `sbx: note: <msg>` line. Pure (see [`warning_line`]).
fn note_line(msg: &str, pal: &Palette) -> String {
    format!(
        "sbx: {}note:{} {}",
        pal.head,
        pal.reset,
        highlight(msg, pal)
    )
}

/// Lift each `` `…` `` span in `msg` to the identifier hue — the diagnostic family's view over
/// the shared span scanner ([`crate::style::paint_spans`]). A plain palette returns the message
/// verbatim — backticks kept — so a captured stream is byte-identical and every existing substring
/// assertion (including ones that match a backtick-delimited token) still holds.
fn highlight(msg: &str, pal: &Palette) -> String {
    crate::style::paint_spans(msg, pal.name, "", pal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every warning a config produced reaches the terminal through [`warn_config`], which filters
    /// it, and never through the unfiltered [`warn`].
    ///
    /// The text of such a warning names the key or value it is complaining about, and that name is
    /// the config's to spell. The global config and an imported app profile are trusted **by
    /// location**, so nothing gates what they may put in one; a project `.sbx.toml` reaches the same
    /// tables once it is trusted. Control bytes in the name reach the launching terminal at the
    /// exact moment sbx is reporting what it refused, so an escape run can erase the trust warnings
    /// printed just above it.
    ///
    /// Counted rather than trusted to stay converted, because the failure is silent: a new warning
    /// producer with a plain `warn` looks exactly like a correct one. The loop variable is the tell
    /// — a `warn` whose argument is a bare `warning` or `w` is printing somebody else's string.
    ///
    /// **The population is the whole crate.** The rule belongs to the function it is about rather
    /// than to any one module that happens to hold today's instances: the launch tree and the CLI
    /// verbs print the same `resolved.warnings` from the same loader, and a guard scoped to one of
    /// them passes on the other's silence.
    ///
    /// **What this does not cover, stated because the count reads stronger than it is:** the
    /// *inline* form, `warn(&format!("… {key} …"))`, where a config-chosen value arrives through
    /// interpolation and never becomes a loop variable. No mechanical rule separates those from the
    /// sites that interpolate only sbx's own values — the format string has to be read. A new one is
    /// therefore not caught here; [`warn_config`]'s own doc is where that rule is written for a
    /// reader adding a warning.
    #[test]
    fn no_config_warning_reaches_the_terminal_unfiltered() {
        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let mut offenders: Vec<String> = Vec::new();
        for file in crate::testutil::crate_sources() {
            if crate::testutil::is_test_only_source(&file) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let production = crate::testutil::production_half(&text);
            for needle in ["warn(warning)", "warn(w)"] {
                let n = production.matches(needle).count();
                if n > 0 {
                    let relative = file.display().to_string().replacen(&root, "", 1);
                    offenders.push(format!("{relative}: {n}× `{needle}`"));
                }
            }
        }
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "a config-chosen warning is printed through the unfiltered `warn`; use \
             `diag::warn_config`, the rule `mise_token_display` already applies to `[tools]`: \
             {offenders:?}"
        );
    }

    #[test]
    fn plain_lines_are_verbatim_including_backticks() {
        // The plain path must be byte-identical to the bare prefix + message, backticks intact —
        // the invariant the captured-output assertions (some matching a `token`) depend on.
        let p = Palette::plain();
        assert_eq!(
            warning_line("found a mise file (`mise.toml`) but no `.sbx.toml`", &p),
            "sbx: warning: found a mise file (`mise.toml`) but no `.sbx.toml`"
        );
        assert_eq!(
            note_line("`network` is a security field", &p),
            "sbx: note: `network` is a security field"
        );
        assert_eq!(highlight("a `b` c", &p), "a `b` c");
    }

    #[test]
    fn colored_lines_color_the_prefix_and_lift_identifiers() {
        let p = Palette::colored();

        let w = warning_line("the `key` field", &p);
        assert!(w.contains(&format!("{}warning:{}", p.warn, p.reset)));
        assert!(w.contains(&format!("{}key{}", p.name, p.reset)));
        // The backticks are dropped in color — the hue replaces the markup.
        assert!(!w.contains('`'));

        let n = note_line("`network` is a security field", &p);
        assert!(n.contains(&format!("{}note:{}", p.head, p.reset)));
        assert!(n.contains(&format!("{}network{}", p.name, p.reset)));
    }

    #[test]
    fn an_error_line_is_the_bare_message_with_identifiers_lifted() {
        // `error` adds no prefix — the plain path is byte-identical to the message (a converted
        // `eprintln!` changes nothing captured), and color only lifts the spans.
        let plain = Palette::plain();
        assert_eq!(
            highlight("sbx: store: unknown argument `--bogus`", &plain),
            "sbx: store: unknown argument `--bogus`"
        );
        let p = Palette::colored();
        let out = highlight("sbx: store: unknown argument `--bogus`", &p);
        assert!(out.starts_with("sbx: store: unknown argument "));
        assert!(out.contains(&format!("{}--bogus{}", p.name, p.reset)));
        assert!(!out.contains('`'));
    }

    #[test]
    fn a_trailing_unmatched_backtick_keeps_the_tail() {
        // After a real span, a lone backtick with no partner is not a span: the colored path must
        // emit it and the rest verbatim rather than dropping the tail.
        let p = Palette::colored();
        let out = highlight("a `real` span then a lone ` tick", &p);
        assert!(out.contains(&format!("{}real{}", p.name, p.reset)));
        assert!(out.contains("` tick"));
    }

    #[test]
    fn a_hint_line_keeps_its_indent_and_lifts_identifiers() {
        // A continuation line (the `hint` body) keeps its caller-owned indent and gets the family's
        // identifier hue, so a multi-line diagnostic is uniform rather than mixing cyan with literal
        // backticks.
        let plain = Palette::plain();
        assert_eq!(
            highlight("       run `sbx trust /p`", &plain),
            "       run `sbx trust /p`"
        );
        let p = Palette::colored();
        let out = highlight("       run `sbx trust /p`", &p);
        assert!(out.starts_with("       run "));
        assert!(out.contains(&format!("{}sbx trust /p{}", p.name, p.reset)));
    }
}
