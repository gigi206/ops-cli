//! Shared ANSI styling for terminal output. One [`Palette`] decides whether a stream is
//! painted (it is a terminal, `NO_COLOR` is unset, `TERM` is not `dumb`) or left plain (a
//! pipe, a captured test). Every span is empty when color is off, so the render code stays
//! unconditional and a non-terminal is byte-for-byte plain text.

use std::io::IsTerminal;

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

/// Print an aligned table: `headers` over `rows`, columns as wide as their widest cell.
///
/// The last column is never padded (it is the free-text one and padding it would trail spaces to the
/// end of every line), and the first is colored — the same shape `sbx session ls` prints, because a
/// listing that reads differently from verb to verb is one the reader has to re-learn each time.
///
/// The header is padded *before* it is colored so the escape sequences never count toward a column's
/// width and the alignment is identical with and without color.
pub(crate) fn print_table(headers: &[&str], align: &[Align], rows: &[Vec<String>]) {
    let pal = Palette::for_stream(std::io::stdout().is_terminal());
    let (lines, first) = render_table(headers, align, rows);
    for (i, line) in lines.iter().enumerate() {
        // The header in the header color, and each row's first cell in the name color — the same
        // reading order `sbx session ls` gives, where the eye lands on the identifier. The span is
        // the *rendered* first column, padding included, so a right-aligned id is colored where it
        // sits rather than where its digits would start.
        //
        // `first` counts **characters**, which is what the padding is measured in; the byte index is
        // then looked up rather than assumed equal to it. An operation name with an accent in it
        // would otherwise split the line mid-character — which does not merely misplace the color,
        // it panics.
        let split = line
            .char_indices()
            .nth(first)
            .map_or(line.len(), |(i, _)| i);
        let (head, rest) = line.split_at(split);
        match i {
            0 => println!("{}{line}{}", pal.head, pal.reset),
            _ => println!("{}{head}{}{rest}", pal.name, pal.reset),
        }
    }
}

/// The table's lines, header first, and the width of the first column — the layout with none of the
/// printing, so the alignment is something a test can read rather than something a person eyeballs.
pub(crate) fn render_table(
    headers: &[&str],
    align: &[Align],
    rows: &[Vec<String>],
) -> (Vec<String>, usize) {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            rows.iter()
                .filter_map(|r| r.get(i).map(|c| c.chars().count()))
                .chain([h.chars().count()])
                .max()
                .unwrap_or(0)
        })
        .collect();
    let last = headers.len().saturating_sub(1);
    let line = |cells: &dyn Fn(usize) -> String| -> String {
        (0..headers.len())
            .map(|i| {
                let cell = cells(i);
                match (i == last, align.get(i)) {
                    // The last column is never padded: it is the free-text one, and padding it
                    // would trail spaces to the end of every line.
                    (true, _) => cell,
                    (_, Some(Align::Right)) => format!("{cell:>w$}", w = widths[i]),
                    _ => format!("{cell:<w$}", w = widths[i]),
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut out = vec![line(&|i| headers[i].to_string()).trim_end().to_string()];
    for row in rows {
        out.push(
            line(&|i| row.get(i).cloned().unwrap_or_default())
                .trim_end()
                .to_string(),
        );
    }
    (out, widths.first().copied().unwrap_or(0))
}

/// Which way a column's cells sit against their width.
#[derive(Clone, Copy)]
pub(crate) enum Align {
    Left,
    Right,
}

#[cfg(test)]
mod tests {
    use super::{Align, Palette, render_table};

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
    /// `sbx session ls`'s six-column shape, rendered here rather than by a per-verb width
    /// calculation. It had its own, which measured a cell in bytes and so mis-padded a non-ASCII
    /// app label; this pins the layout the shared renderer gives it, non-ASCII cell included.
    #[test]
    fn a_session_listing_aligns_on_a_non_ascii_name_like_every_other_listing() {
        let rows = vec![
            vec![
                "sbx-café".to_string(),
                "app:café".to_string(),
                "detached".to_string(),
                "42".to_string(),
                "3m".to_string(),
                "/home/u/p".to_string(),
            ],
            vec![
                "sbx-x".to_string(),
                "shell".to_string(),
                "attached".to_string(),
                "7".to_string(),
                "10s".to_string(),
                "/home/u/q".to_string(),
            ],
        ];
        let (lines, first) = render_table(
            &["NAME", "KIND", "MODE", "PID", "AGE", "PROJECT"],
            &[
                Align::Left,
                Align::Left,
                Align::Left,
                Align::Right,
                Align::Right,
                Align::Left,
            ],
            &rows,
        );
        // `sbx-café` is 8 characters and 9 bytes: the width is the character count, so the
        // columns after NAME line up in both rows.
        assert_eq!(first, 8);
        // NAME is 8 wide plus the two-space gutter, so every line's KIND column starts at
        // character 10 — the header's included, and the accented row's with it.
        let kind_at = |l: &str| {
            let i = l.char_indices().nth(10).map(|(i, _)| i).unwrap();
            l[i..].split("  ").next().unwrap().to_string()
        };
        assert_eq!(kind_at(&lines[0]), "KIND");
        assert_eq!(kind_at(&lines[1]), "app:café");
        assert_eq!(kind_at(&lines[2]), "shell");
        // No line trails whitespace, in either row.
        assert!(lines.iter().all(|l| l == l.trim_end()));
    }

    /// The columns are as wide as their widest cell, and the last one is not padded — a listing
    /// whose columns shift with the data is the one a reader gives up on.
    #[test]
    fn a_table_aligns_on_its_widest_cell_and_leaves_no_trailing_space() {
        let (lines, first) = render_table(
            &["NAME", "N", "NOTE"],
            &[Align::Left, Align::Right, Align::Left],
            &[
                vec!["a".into(), "1000".into(), "one".into()],
                vec!["longer-name".into(), "7".into(), String::new()],
            ],
        );
        assert_eq!(
            lines,
            vec![
                "NAME            N  NOTE",
                "a            1000  one",
                "longer-name     7",
            ],
            "each column takes the width of its widest cell, right-aligned where asked"
        );
        assert_eq!(
            first,
            "longer-name".len(),
            "the first column's rendered width"
        );
        for line in &lines {
            assert_eq!(line.trim_end(), line, "no line may trail spaces: {line:?}");
        }
    }

    /// Widths are counted in characters and the color span is sliced in bytes, so a first cell that
    /// is not ASCII must not be able to split the line mid-character — that is a panic, not a
    /// cosmetic slip. An operation name is config text, so it can hold anything.
    #[test]
    fn a_non_ascii_first_cell_neither_misaligns_nor_splits_a_character() {
        let rows = vec![
            vec!["opération".into(), "1".into()],
            vec!["ab".into(), "2".into()],
        ];
        let (lines, first) = render_table(&["NAME", "N"], &[Align::Left, Align::Left], &rows);
        assert_eq!(
            first,
            "opération".chars().count(),
            "widths count characters"
        );
        assert_eq!(lines, vec!["NAME       N", "opération  1", "ab         2"]);
        for line in &lines {
            // What `print_table` does with the width — it must land on a character boundary.
            let split = line
                .char_indices()
                .nth(first)
                .map_or(line.len(), |(i, _)| i);
            assert!(
                line.is_char_boundary(split),
                "the color span must not split a character: {line:?}"
            );
        }
    }
}
