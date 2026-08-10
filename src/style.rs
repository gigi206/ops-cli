//! Shared ANSI styling for terminal output. One [`Palette`] decides whether a stream is
//! painted (it is a terminal, `NO_COLOR` is unset, `TERM` is not `dumb`) or left plain (a
//! pipe, a captured test). Every span is empty when color is off, so the render code stays
//! unconditional and a non-terminal is byte-for-byte plain text.

/// ANSI styling for one output stream. Empty strings when color is off, so the render code is
/// unconditional and a non-terminal (a pipe, a captured test) is plain text.
pub(crate) struct Palette {
    /// Command and subcommand names, configuration keys, identifiers, rules.
    pub(crate) name: &'static str,
    /// Option and operand flags.
    pub(crate) flag: &'static str,
    /// Placeholder metavariables in a usage synopsis (`<name>`, `<file>`).
    pub(crate) arg: &'static str,
    /// Inline code spans in prose — the backtick-quoted tokens of help text
    /// (`--flag`, `sbx help run`, `.sbx.toml`). The backticks themselves are
    /// dropped when this style is active; kept verbatim when color is off.
    pub(crate) code: &'static str,
    /// Section headers (`Usage:`, `Options:`, `env:`, …).
    pub(crate) head: &'static str,
    /// A success status (`[ ok ]`, `ALLOWED`).
    pub(crate) ok: &'static str,
    /// A warning status (`[warn]`).
    pub(crate) warn: &'static str,
    /// A failure status (`[FAIL]`, `DENIED`, a not-runnable note).
    pub(crate) err: &'static str,
    /// De-emphasized prose — secondary detail lines, never an identifier.
    pub(crate) dim: &'static str,
    pub(crate) reset: &'static str,
}

impl Palette {
    /// The active ANSI styling — names in bold cyan, flags in bold green, usage placeholders and
    /// headers in bold, inline code in cyan, and the conventional status hues (green ok, yellow
    /// warn, red fail) with dim secondary text.
    pub(crate) fn colored() -> Self {
        Palette {
            name: "\x1b[1;36m",
            flag: "\x1b[1;32m",
            arg: "\x1b[1m",
            code: "\x1b[36m",
            head: "\x1b[1m",
            ok: "\x1b[32m",
            warn: "\x1b[33m",
            err: "\x1b[1;31m",
            dim: "\x1b[2m",
            reset: "\x1b[0m",
        }
    }

    /// No styling — every span is empty, so the render code is unconditional and the output is
    /// plain text (a pipe, a captured test, `NO_COLOR`, a `dumb` terminal).
    pub(crate) fn plain() -> Self {
        Palette {
            name: "",
            flag: "",
            arg: "",
            code: "",
            head: "",
            ok: "",
            warn: "",
            err: "",
            dim: "",
            reset: "",
        }
    }

    /// Decide color for a stream — the conventional auto-detection: colored only when the stream
    /// is a terminal, `NO_COLOR` is unset, and the terminal is not `dumb`. The caller passes the
    /// stream's `is_terminal()` so the same logic serves stdout and stderr.
    pub(crate) fn for_stream(is_tty: bool) -> Self {
        let on = is_tty
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var_os("TERM").is_none_or(|t| t != "dumb");
        if on { Self::colored() } else { Self::plain() }
    }

    /// Whether this palette paints nothing — the discriminant every span painter keys on, so a
    /// plain stream keeps its backtick markup verbatim instead of having it silently dropped.
    pub(crate) fn is_plain(&self) -> bool {
        self.reset.is_empty()
    }
}

/// Lift each `` `…` `` span in `text` to `hue` — the one backtick-span scanner every painter
/// shares. A plain palette returns the text verbatim (backticks kept), so a piped/captured stream
/// is byte-for-byte the bare markup and existing substring assertions hold. A colored palette
/// drops the backticks and wraps the span's content in `hue`; after the span's reset it re-emits
/// `resume` (the enclosing style — e.g. [`Palette::dim`] — or empty), so a span inside a styled
/// wrapper does not cancel the wrapper for the rest of the line. An unmatched backtick is emitted
/// verbatim and ends the scan, so malformed input can only under-style.
pub(crate) fn paint_spans(text: &str, hue: &str, resume: &str, pal: &Palette) -> String {
    // The plain fast-path is the load-bearing guarantee: the text is returned unchanged, so a
    // non-terminal is byte-for-byte the bare markup. (Backtick is ASCII, so every slice below
    // lands on a char boundary regardless of the bytes between the ticks.)
    if pal.is_plain() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('`') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('`') {
            Some(end) => {
                out.push_str(hue);
                out.push_str(&after[..end]);
                out.push_str(pal.reset);
                out.push_str(resume);
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

/// Prose for stdout reports with its `` `…` `` spans lifted to the code hue (the same hue help
/// text gives inline code). Plain palette: verbatim, backticks kept.
pub(crate) fn prose(text: &str, pal: &Palette) -> String {
    paint_spans(text, pal.code, "", pal)
}

/// A dimmed prose line — the recurring `{dim}…{reset}` hint shape — with each `` `…` `` span
/// lifted *out* of the dim into the code hue and the dim resumed after it, so the hint stays
/// de-emphasized while its commands read as code. Plain palette: the bare text, no wrapper.
pub(crate) fn dim_prose(text: &str, pal: &Palette) -> String {
    format!(
        "{}{}{}",
        pal.dim,
        paint_spans(text, pal.code, pal.dim, pal),
        pal.reset
    )
}

#[cfg(test)]
mod tests {
    use super::Palette;

    #[test]
    fn plain_spans_are_all_empty_so_captured_output_is_byte_for_byte_plain() {
        let p = Palette::plain();
        for span in [
            p.name, p.flag, p.arg, p.code, p.head, p.ok, p.warn, p.err, p.dim, p.reset,
        ] {
            assert!(span.is_empty(), "a plain span must be empty");
        }
    }

    #[test]
    fn colored_spans_are_all_non_empty_escapes_with_a_reset() {
        let p = Palette::colored();
        for span in [
            p.name, p.flag, p.arg, p.code, p.head, p.ok, p.warn, p.err, p.dim,
        ] {
            assert!(
                span.starts_with('\x1b'),
                "a colored span must be an ANSI escape"
            );
        }
        assert_eq!(p.reset, "\x1b[0m", "reset must clear styling");
    }

    #[test]
    fn a_non_terminal_is_never_colored() {
        // The load-bearing invariant: a captured (non-terminal) stream is plain, so every
        // `.output()` test asserts byte-identical plain text regardless of the host's $TERM.
        let p = Palette::for_stream(false);
        assert!(p.name.is_empty() && p.reset.is_empty());
    }

    #[test]
    fn plain_spans_keep_their_backticks_verbatim() {
        // The painters' plain path must be byte-identical to the input — backticks kept — so a
        // captured stream still shows the markup the substring assertions pin.
        let p = Palette::plain();
        assert_eq!(super::paint_spans("a `b` c", p.name, "", &p), "a `b` c");
        assert_eq!(super::prose("run `sbx gc`", &p), "run `sbx gc`");
        assert_eq!(super::dim_prose("see `sbx help`", &p), "see `sbx help`");
    }

    #[test]
    fn colored_spans_drop_the_backticks_and_take_the_hue() {
        let p = Palette::colored();
        let out = super::paint_spans("run `sbx gc` now", p.name, "", &p);
        assert!(out.contains(&format!("{}sbx gc{}", p.name, p.reset)));
        assert!(!out.contains('`'), "color replaces the markup");
    }

    #[test]
    fn a_span_inside_a_wrapper_resumes_the_enclosing_style() {
        // The `{dim}…{reset}` hint shape: the span's reset must not cancel the dim for the rest
        // of the line — `resume` re-opens it.
        let p = Palette::colored();
        let out = super::dim_prose("see `sbx gc` for details", &p);
        assert!(out.starts_with(p.dim));
        assert!(out.contains(&format!("{}sbx gc{}{}", p.code, p.reset, p.dim)));
        assert!(out.ends_with(&format!("for details{}", p.reset)));
        assert!(!out.contains('`'));
    }

    #[test]
    fn an_unmatched_backtick_is_kept_verbatim() {
        let p = Palette::colored();
        let out = super::paint_spans("a `real` span then a lone ` tick", p.name, "", &p);
        assert!(out.contains(&format!("{}real{}", p.name, p.reset)));
        assert!(out.contains("` tick"));
    }
}
