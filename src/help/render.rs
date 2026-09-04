//! Turning a page into the text a terminal shows: the palette-aware painters, the top-level
//! command list, and the per-page layout.
//!
//! Kept apart from the queries and the entry points because it decides only *how* a page reads —
//! never which page, and never which stream's palette applies. Every function here is total on
//! malformed input: an unterminated `<` or backtick is emitted verbatim rather than left as a
//! dangling style span, so a bad table entry can only under-style, never corrupt the output.

use super::pages::PAGES;
use super::{Page, children};
use crate::style::Palette;

/// One aligned `  flag    description` line, the flag painted in `color`.
fn item(out: &mut String, color: &str, reset: &str, key: &str, width: usize, desc: &str) {
    if desc.is_empty() {
        out.push_str(&format!("  {color}{key}{reset}\n"));
    } else {
        out.push_str(&format!("  {color}{key:<width$}{reset}  {desc}\n"));
    }
}

/// Paint the `<metavar>` placeholders in a usage synopsis, leaving the literal command words,
/// flags, and `[...]`/`|` punctuation untouched. Each `<...>` span (its angle brackets included)
/// is wrapped in the palette's placeholder style; with color off every span is empty, so the
/// string is returned byte-for-byte. An unterminated `<` is emitted verbatim (never a dangling
/// open span), so malformed input can only under-style, never corrupt the output.
pub(super) fn paint_synopsis(syn: &str, pal: &Palette) -> String {
    let mut out = String::with_capacity(syn.len());
    let mut rest = syn;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        match rest[start..].find('>') {
            Some(end) => {
                out.push_str(pal.arg);
                out.push_str(&rest[start..start + end + 1]); // the whole `<…>`
                out.push_str(pal.reset);
                rest = &rest[start + end + 1..];
            }
            None => {
                out.push_str(&rest[start..]); // no closing `>`: emit the remainder as-is
                return out;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Paint the backtick-quoted inline-code spans in prose (summaries, option descriptions, the
/// `details` body, the reminder lines). Each `` `…` `` span has its backticks dropped and its
/// content wrapped in the palette's code style. With color off the style span is empty, so the
/// backticks are *kept* and the string is returned byte-for-byte — the delimiters stay useful in
/// piped/plain output, and the non-terminal-is-plain invariant holds. An unterminated backtick is
/// emitted verbatim (never a dangling open span), so malformed input can only under-style.
pub(super) fn paint_inline_code(text: &str, pal: &Palette) -> String {
    crate::style::paint_spans(text, pal.code, "", pal)
}

/// Render the top-level command list — the body of `sbx --help` and the no-command usage.
///
/// Top-level commands are sorted alphabetically, like each subcommand listing.
pub(super) fn top_level(pal: &Palette) -> String {
    let mut out = String::from("sbx — a sandbox launcher (bubblewrap + daemonless nix)\n\n");
    out.push_str(&format!(
        "{}Usage:{}\n  {}\n\n",
        pal.head,
        pal.reset,
        paint_synopsis("sbx <command> [arguments]", pal)
    ));
    out.push_str(&format!("{}Commands:{}\n", pal.head, pal.reset));
    let mut tops: Vec<&Page> = PAGES.iter().filter(|p| p.path.len() == 1).collect();
    tops.sort_by_key(|p| p.path[0]);
    let width = tops.iter().map(|p| p.path[0].len()).max().unwrap_or(0);
    for p in tops {
        item(
            &mut out,
            pal.name,
            pal.reset,
            p.path[0],
            width,
            &paint_inline_code(p.summary, pal),
        );
    }
    out.push_str(&paint_inline_code(
        "\nRun `sbx help <command>` (or `sbx <command> --help`) for usage and details.\n",
        pal,
    ));
    out
}

/// The folded option rows under their heading, indented one level below the ungrouped list.
fn emit_group(
    out: &mut String,
    folded: Option<(&'static str, &'static [&'static str])>,
    names: &[&str],
    pal: &Palette,
) {
    let Some((heading, _)) = folded else { return };
    if names.is_empty() {
        return;
    }
    out.push_str(&format!(
        "\n  {}{heading}:{}\n    {}\n\n",
        pal.head,
        pal.reset,
        names.join(", ")
    ));
}

/// Render one page: header, usage, options, subcommands (alphabetical), then prose.
pub(super) fn render(page: &Page, pal: &Palette) -> String {
    let joined = page.path.join(" ");
    let mut out = format!(
        "{}sbx {}{} — {}\n\n",
        pal.name,
        joined,
        pal.reset,
        paint_inline_code(page.summary, pal)
    );
    out.push_str(&format!(
        "{}Usage:{}\n  {}\n",
        pal.head,
        pal.reset,
        paint_synopsis(page.synopsis, pal)
    ));

    if !page.options.is_empty() {
        // A page may fold part of its list under a heading — see `super::OPTION_GROUPS` for why.
        // The folded rows keep their place in `page.options` (completion reads that table), so this
        // only decides where each one is PRINTED: everything else in order, then the group.
        let folded = super::option_group(page.path);
        let is_folded = |flag: &str| folded.is_some_and(|(_, members)| members.contains(&flag));
        out.push_str(&format!("\n{}Options:{}\n", pal.head, pal.reset));
        let width = page
            .options
            .iter()
            .filter(|(f, _)| !is_folded(f))
            .map(|(f, _)| f.len())
            .max()
            .unwrap_or(0);
        // Printed from `page.options` rather than from the group's own list, so the rendered set is
        // the page's set: a member the page dropped disappears here too, instead of being announced
        // as a target that no longer exists.
        let folded_names: Vec<&str> = page
            .options
            .iter()
            .map(|(f, _)| *f)
            .filter(|f| is_folded(f))
            .collect();
        let mut group_emitted = folded_names.is_empty();
        for (flag, desc) in page.options.iter().filter(|(f, _)| !is_folded(f)) {
            // The group sits between the operands and the flags, because that is what it is made
            // of: every folded row on such a page is an operand, and printing it after `--project`
            // would put a way to name the target below the flags that modify one.
            if !group_emitted && flag.starts_with('-') {
                emit_group(&mut out, folded, &folded_names, pal);
                group_emitted = true;
            }
            item(
                &mut out,
                pal.flag,
                pal.reset,
                flag,
                width,
                &paint_inline_code(desc, pal),
            );
        }
        if !group_emitted {
            emit_group(&mut out, folded, &folded_names, pal);
        }
    }

    let kids = children(page.path);
    if !kids.is_empty() {
        out.push_str(&format!("\n{}Subcommands:{}\n", pal.head, pal.reset));
        let width = kids
            .iter()
            .map(|k| k.path.last().unwrap().len())
            .max()
            .unwrap_or(0);
        for k in &kids {
            item(
                &mut out,
                pal.name,
                pal.reset,
                k.path.last().unwrap(),
                width,
                &paint_inline_code(k.summary, pal),
            );
        }
        out.push_str(&paint_inline_code(
            &format!("\nRun `sbx help {joined} <subcommand>` for a subcommand's options.\n"),
            pal,
        ));
    }

    if !page.details.is_empty() {
        out.push_str(&format!("\n{}\n", paint_inline_code(page.details, pal)));
    }
    out
}
