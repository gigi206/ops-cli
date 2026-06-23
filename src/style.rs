//! Shared ANSI styling for terminal output. One [`Palette`] decides whether a stream is
//! painted (it is a terminal, `NO_COLOR` is unset, `TERM` is not `dumb`) or left plain (a
//! pipe, a captured test). Every span is empty when color is off, so the render code stays
//! unconditional and a non-terminal is byte-for-byte plain text.

/// ANSI styling for one output stream. Empty strings when color is off, so the render code is
/// unconditional and a non-terminal (a pipe, a captured test) is plain text.
pub(crate) struct Palette {
    /// Command and subcommand names, configuration keys, identifiers.
    pub(crate) name: &'static str,
    /// Option and operand flags.
    pub(crate) flag: &'static str,
    /// Section headers (`Usage:`, `Options:`, `env:`, …).
    pub(crate) head: &'static str,
    pub(crate) reset: &'static str,
}

impl Palette {
    /// The active ANSI styling — names in bold cyan, flags in bold green, headers in bold.
    pub(crate) fn colored() -> Self {
        Palette {
            name: "\x1b[1;36m",
            flag: "\x1b[1;32m",
            head: "\x1b[1m",
            reset: "\x1b[0m",
        }
    }

    /// No styling — every span is empty, so the render code is unconditional and the output is
    /// plain text (a pipe, a captured test, `NO_COLOR`, a `dumb` terminal).
    pub(crate) fn plain() -> Self {
        Palette {
            name: "",
            flag: "",
            head: "",
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
