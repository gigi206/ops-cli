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
