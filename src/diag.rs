//! Styled stderr diagnostics — the single chokepoint for the `sbx: warning:` / `sbx: note:`
//! family. Each call decides its palette from stderr, so a captured stream is plain text; the
//! prefix carries the severity hue (yellow `warning:`, bold `note:`) and any `` `identifier` ``
//! span in the message is lifted to the identifier hue (cyan). A plain stream is sbx's own text
//! byte for byte, backticks intact, so existing captured-output assertions are unaffected.
//!
//! Every message is written the way [`visible_lines`] writes it before any hue is added: a control
//! character or a character that reorders a line comes out as an escape (`\x1b`, `\u{202e}`),
//! while a line break and a tab are kept. A message quotes values sbx did not write (a path the
//! cage chose, a program's stderr, a project's file name), and this is the one place they all
//! reach the terminal, so a value is escaped whatever route it took. The hues sbx adds are the only
//! escape sequences a diagnostic carries. What stays: a line break inside a value still starts a
//! line, which can read as sbx's own, and only [`warn_config`] folds that away.

use crate::style::Palette;
use std::io::IsTerminal;

/// Text sbx did not choose, as a terminal is to show it: a line of a file under review in the
/// project, a name the cage gave to something sbx reports, or the traffic a session captured.
///
/// A character that would move the cursor, erase a line, recolour the text or reorder it is written
/// as an escape (`\x1b`, `\x0d`, `\u{202e}`): the reader sees that it is there instead of what it
/// would do to the lines around it. A tab only moves forward, and is kept. Nothing is cut, unlike
/// [`crate::sandbox::sanitize`], so a message that names a path still ends with what to do about
/// it. Only what is printed is escaped; the text is compared and acted on as it is.
pub(crate) fn visible(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\t' => out.push(c),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c if reorders(c) => out.push_str(&format!("\\u{{{:04x}}}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

/// A message as a terminal is to show it: each line written the way [`visible`] writes it, the
/// line breaks kept. Text whose only control characters are line breaks and tabs, and that holds no
/// character that reorders a line, comes back byte for byte, and escaping twice changes nothing.
///
/// For a message that spans lines on purpose, such as a parser's drawing the line at fault under a
/// caret, whose line is the file's own text: a file sbx did not write can put an escape sequence or
/// a right-to-left override in it. A carriage return is not a line break here, so one before a
/// newline is shown rather than dropped. A one-line message goes through [`visible`] whole
/// instead, so that a newline carried by a value it quotes cannot start a line.
pub(crate) fn visible_lines(text: &str) -> String {
    text.split('\n').map(visible).collect::<Vec<_>>().join("\n")
}

/// Whether `c` changes the order a terminal lays out the characters around it: the directional
/// marks, embeddings, overrides and isolates. None of them is a control character to
/// [`char::is_control`], which reads the `Cc` category alone, so a filter that keeps a line to what
/// it says tests this beside it.
pub(crate) fn reorders(c: char) -> bool {
    matches!(
        c,
        '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// Text sbx did not choose, folded to one line that reads as written: each control character (a
/// newline that would forge a line of its own, an escape that would drive the terminal) and each
/// character that [`reorders`] a line becomes a space, and runs of whitespace collapse.
///
/// Never rejects, and nothing is cut: how much of the line to keep is the caller's to decide.
pub(crate) fn one_line(text: &str) -> String {
    let cleaned: String = text
        .chars()
        .map(|c| {
            if c.is_control() || reorders(c) {
                ' '
            } else {
                c
            }
        })
        .collect();
    let mut out = String::with_capacity(cleaned.len());
    for word in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// Write to stderr what `err!` and `errln!` formatted, dropping a write that fails.
///
/// stderr is where sbx says that something failed, so a write to it that fails has no channel left
/// to be reported on, and the verb's answer is its exit code, which a diagnostic that could not be
/// shown does not change: `sbx app show nope 2>/dev/full` still exits 2. That holds for every cause
/// alike, a reader that has gone or a full disk, because none of them leaves a channel to say it on.
/// The panic `eprintln!` raises instead replaced the verb's answer with 101. A question put to the
/// user is the exception, and goes through [`prompt`].
#[cfg(not(test))]
pub(crate) fn emit(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let _ = std::io::stderr().write_fmt(args);
}

/// Put `question` to the user on stderr, flushed, and say whether it was written.
///
/// Unlike [`emit`], a failure here is not dropped: an answer read after a question nobody saw is
/// no answer to it, so a caller that gets `false` takes it as a no. The text is written as given.
pub(crate) fn prompt(question: &str) -> bool {
    use std::io::Write as _;
    let mut err = std::io::stderr().lock();
    err.write_all(question.as_bytes())
        .and_then(|()| err.flush())
        .is_ok()
}

/// Print `sbx: warning: <msg>` to stderr — the prefix in the caution hue, the message's
/// `` `identifiers` `` in the identifier hue, when stderr is a terminal. The message must be the
/// bare text (no `sbx: warning:` prefix — this adds it), so a slip cannot double the prefix.
pub(crate) fn warn(msg: &str) {
    errln!(
        "{}",
        warning_line(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// Print a warning whose text a **config file chose** part of, with that part filtered.
///
/// [`warn`] escapes what would drive the terminal but keeps line breaks, since sbx writes some of
/// its own. A configuration warning names the key or value it is complaining about, and for an
/// untrusted project's `.sbx.toml` that name is the project's to spell, including control bytes,
/// escape sequences and line breaks, which reach the launching terminal exactly when sbx is telling
/// the user what it refused. That is the one moment the user is reading, so it is the one worth
/// forging: a line break can start a line that reads as sbx's own. This folds the warning to one
/// bounded line first.
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
    errln!(
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
    errln!(
        "{}",
        highlight(line, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// Print a bare stderr error line (a usage error, a refusal) with its `` `identifiers` ``
/// highlighted. The message carries its own `sbx: …` prefix verbatim (unlike [`warn`]/[`note`],
/// nothing is added), so converting a bare `errln!` here changes no byte of sbx's own text in
/// a captured stream, only lifts the spans when stderr is a terminal.
pub(crate) fn error(msg: &str) {
    errln!(
        "{}",
        highlight(msg, &Palette::for_stream(std::io::stderr().is_terminal()))
    );
}

/// The hue a whole diagnostic line is written in, for the few lines that are more than a message:
/// a verdict that stops sbx, a failure worth catching the eye, a change sbx made, an aside.
#[derive(Clone, Copy)]
pub(crate) enum Hue {
    Ok,
    Warn,
    Err,
    Dim,
}

impl Hue {
    fn of(self, pal: &Palette) -> &'static str {
        match self {
            Hue::Ok => pal.ok,
            Hue::Warn => pal.warn,
            Hue::Err => pal.err,
            Hue::Dim => pal.dim,
        }
    }
}

/// [`error`], the whole line in `hue`. The message is escaped as every diagnostic is, so the hue
/// is the only escape sequence the line carries: a caller never colours the text it passes.
pub(crate) fn error_in(hue: Hue, msg: &str) {
    errln!(
        "{}",
        hued_line(
            msg,
            hue,
            &Palette::for_stream(std::io::stderr().is_terminal())
        )
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

/// The [`error_in`] line: the escaped message in `hue`, its spans lifted and the hue resumed after
/// each. Pure (see [`warning_line`]).
fn hued_line(msg: &str, hue: Hue, pal: &Palette) -> String {
    let hue = hue.of(pal);
    format!(
        "{hue}{}{}",
        crate::style::paint_spans(&visible_lines(msg), pal.name, hue, pal),
        pal.reset
    )
}

/// Write `msg` the way [`visible_lines`] does, then lift each `` `…` `` span to the identifier hue:
/// the diagnostic family's view over the shared span scanner ([`crate::style::paint_spans`]). The
/// escaping comes first, so the hue is added to text that can no longer carry one of its own. A
/// plain palette returns sbx's own text verbatim, backticks kept, so a captured stream is
/// byte-identical and every existing substring assertion (including ones that match a
/// backtick-delimited token) still holds.
fn highlight(msg: &str, pal: &Palette) -> String {
    crate::style::paint_spans(&visible_lines(msg), pal.name, "", pal)
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
        // `errln!` changes nothing captured), and color only lifts the spans.
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

    /// The directional formatting characters are the ones a control-character test lets through,
    /// which is why [`reorders`] exists beside it; [`visible`] writes each of them out. A letter of
    /// a right-to-left script is not one: it is text, and it stays.
    #[test]
    fn a_character_that_reorders_a_line_is_one_no_control_test_catches() {
        let formatting = ['\u{200e}', '\u{200f}']
            .into_iter()
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}');
        for c in formatting {
            assert!(reorders(c) && !c.is_control(), "{c:?}");
            assert_eq!(
                visible(&c.to_string()),
                format!("\\u{{{:04x}}}", u32::from(c))
            );
        }
        for c in ['\u{05d0}', '\u{0627}', '\u{200d}', 'a'] {
            assert!(!reorders(c), "{c:?}");
            assert_eq!(visible(&c.to_string()), c.to_string());
        }
    }

    /// Every line the family prints is the message as [`visible_lines`] writes it: an escape
    /// sequence, a carriage return or a character that reorders a line comes out written, while
    /// the line breaks and tabs sbx puts in a message are kept. The only escape sequences in a
    /// coloured line are the palette's own.
    #[test]
    fn every_diagnostic_line_writes_what_would_drive_the_terminal() {
        let msg = "a\u{1b}[2J b\r c\u{202e}d\u{2066}\n\te `x`\u{7}";
        let shown = visible_lines(msg);
        assert_eq!(shown, "a\\x1b[2J b\\x0d c\\u{202e}d\\u{2066}\n\te `x`\\x07");
        // A carriage return before a line break is shown, not dropped, and a final break is kept.
        assert_eq!(visible_lines("a\r\nb\n"), "a\\x0d\nb\n");
        let plain = Palette::plain();
        assert_eq!(highlight(msg, &plain), shown);
        assert_eq!(warning_line(msg, &plain), format!("sbx: warning: {shown}"));
        assert_eq!(note_line(msg, &plain), format!("sbx: note: {shown}"));
        assert_eq!(hued_line(msg, Hue::Err, &plain), shown);

        let p = Palette::colored();
        for line in [
            highlight(msg, &p),
            warning_line(msg, &p),
            note_line(msg, &p),
            hued_line(msg, Hue::Warn, &p),
        ] {
            let mut rest = line.clone();
            for code in [p.name, p.warn, p.head, p.reset] {
                rest = rest.replace(code, "");
            }
            assert!(
                !rest.contains('\u{1b}') && !rest.contains('\r') && !rest.contains('\u{202e}'),
                "an escape sequence other than the palette's reached the line: {line:?}"
            );
            assert!(
                line.contains(&format!("{}x{}", p.name, p.reset)),
                "{line:?}"
            );
            assert!(line.contains("\n\te "), "{line:?}");
        }
    }

    /// sbx's own text is untouched, so a captured stream reads as before; and a message a producer
    /// already escaped comes through the family unchanged rather than escaped twice.
    #[test]
    fn clean_or_already_escaped_text_is_left_as_it_is() {
        let own =
            "sbx: cannot trust `/p/.sbx.toml`: it is world-writable\n       run `sbx trust /p`\t.";
        assert_eq!(visible_lines(own), own);
        assert_eq!(highlight(own, &Palette::plain()), own);
        for hostile in ["a\u{1b}]0;t\u{7}b", "x\ny\r\nz\u{202e}", "\u{200f}"] {
            let once = visible_lines(hostile);
            assert_eq!(visible_lines(&once), once);
            assert_eq!(visible_lines(&visible(hostile)), visible(hostile));
        }
    }

    /// A whole line in a hue keeps that hue around the spans it lifts, so an identifier inside it
    /// does not end the colour for the rest of the line.
    #[test]
    fn a_hued_line_resumes_its_hue_after_each_span() {
        let p = Palette::colored();
        let line = hued_line("sbx: now using `/v` for data", Hue::Ok, &p);
        assert!(line.starts_with(p.ok), "{line:?}");
        assert!(line.ends_with(p.reset), "{line:?}");
        assert!(
            line.contains(&format!("{}/v{}{}", p.name, p.reset, p.ok)),
            "{line:?}"
        );
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
