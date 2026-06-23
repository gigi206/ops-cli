//! Styled stderr diagnostics — the single chokepoint for the `ops: warning:` / `ops: note:`
//! family. Each call decides its palette from stderr, so a captured stream is plain text; the
//! prefix carries the severity hue (yellow `warning:`, bold `note:`) and any `` `identifier` ``
//! span in the message is lifted to the identifier hue (cyan). A plain stream is byte-for-byte the
//! bare message with its backticks intact, so existing captured-output assertions are unaffected.

use crate::style::Palette;
use std::io::IsTerminal;

/// Print `ops: warning: <msg>` to stderr — the prefix in the caution hue, the message's
/// `` `identifiers` `` in the identifier hue, when stderr is a terminal. The message must be the
/// bare text (no `ops: warning:` prefix — this adds it), so a slip cannot double the prefix.
pub(crate) fn warn(msg: &str) {
    eprintln!(
        "{}",
        warning_line(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// Print `ops: note: <msg>` to stderr — an advisory. The prefix is bold (not the caution hue): a
/// note explains a silent no-op (e.g. why a security field did not apply), so it must stay visible
/// without reading as a problem. Same `` `identifier` `` highlighting as [`warn`].
pub(crate) fn note(msg: &str) {
    eprintln!(
        "{}",
        note_line(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// The `ops: warning: <msg>` line. Pure, so the prefix and highlighting are unit-testable without
/// capturing stderr.
fn warning_line(msg: &str, pal: &Palette) -> String {
    format!(
        "ops: {}warning:{} {}",
        pal.warn,
        pal.reset,
        highlight(msg, pal)
    )
}

/// The `ops: note: <msg>` line. Pure (see [`warning_line`]).
fn note_line(msg: &str, pal: &Palette) -> String {
    format!(
        "ops: {}note:{} {}",
        pal.head,
        pal.reset,
        highlight(msg, pal)
    )
}

/// Lift each `` `…` `` span in `msg` to the identifier hue. A plain palette returns the message
/// verbatim — backticks kept — so a captured stream is byte-identical and every existing substring
/// assertion (including ones that match a backtick-delimited token) still holds. A colored palette
/// emits the span's content in the identifier hue with the backticks dropped, so the color replaces
/// the markup. An unmatched backtick is emitted verbatim and ends the scan.
fn highlight(msg: &str, pal: &Palette) -> String {
    // The plain fast-path is the load-bearing guarantee: the message is returned unchanged, so a
    // non-terminal is byte-for-byte the bare text. (Backtick is ASCII, so every slice below lands
    // on a char boundary regardless of the bytes between the ticks.)
    if pal.name.is_empty() {
        return msg.to_owned();
    }
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(start) = rest.find('`') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('`') {
            Some(end) => {
                out.push_str(pal.name);
                out.push_str(&after[..end]);
                out.push_str(pal.reset);
                rest = &after[end + 1..];
            }
            None => {
                // An unmatched backtick: not a span — emit the remainder as-is and stop.
                out.push_str(&rest[start..]);
                return out;
            }
        }
    }
    out.push_str(rest);
    out
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
            warning_line("found a mise file (`mise.toml`) but no `.ops.toml`", &p),
            "ops: warning: found a mise file (`mise.toml`) but no `.ops.toml`"
        );
        assert_eq!(
            note_line("`network` is a security field", &p),
            "ops: note: `network` is a security field"
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
    fn a_trailing_unmatched_backtick_keeps_the_tail() {
        // After a real span, a lone backtick with no partner is not a span: the colored path must
        // emit it and the rest verbatim rather than dropping the tail.
        let p = Palette::colored();
        let out = highlight("a `real` span then a lone ` tick", &p);
        assert!(out.contains(&format!("{}real{}", p.name, p.reset)));
        assert!(out.contains("` tick"));
    }
}
