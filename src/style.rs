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
        if on {
            Self::colored()
        } else {
            Self::plain()
        }
    }
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
}
