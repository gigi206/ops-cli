//! Named substitution of secret values out of a **text sink** — a task's stdout/stderr, an error
//! message sbx composes, a log line.
//!
//! This is the second of two renderings over one needle set. The proxy substitutes **in place and
//! length-preserving** (it fills with `*`) because a changed byte count would break
//! `Content-Length`, HTTP/2 frames, and mid-stream relaying. A text sink has no such constraint —
//! the output is buffered whole before it is returned — so here a value is replaced by its
//! **name**: `${gh_token}`. That reads as what it is, tells the reader what was withheld, and
//! doubles as a placeholder a later call can reuse.
//!
//! What it is not: a boundary. Any transformation the producing command applies (hash, encrypt,
//! truncate) passes through untouched. Its real value is the dominant accident — a credential
//! echoed into an error message. The count it returns is the trustworthy signal: `${name}` in the
//! text proves nothing (the producer can print that literal itself), while the count is computed
//! host-side by the substituter.

use crate::sandbox::proxy::SecretNeedle;

/// A value shorter than this many bytes is never substituted. Two independent reasons, both
/// pointing the same way: on the wire such a needle matches benign traffic and would refuse
/// legitimate egress (a self-inflicted denial), and on a text sink it would pepper the output with
/// placeholders and *leak the value* through their positions and frequency. Below the threshold the
/// credential is still used — only the substitution is skipped, and loudly.
pub(crate) const REDACT_MIN_LEN: usize = 8;

/// How a substituted value is named in the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Placeholder {
    /// `${name}` — readable, and what a reader expects. The default.
    Plain,
    /// `${name@<nonce>}` — the nonce is drawn fresh per invocation and reported out-of-band, so a
    /// placeholder in *this* output cannot have been forged by the producer (it could not predict
    /// the nonce) and one copied from an earlier result is detectably stale.
    ///
    /// Escaping the producer's own `${…}` was considered and rejected: it is imitable (the producer
    /// can print the escaped form too, and a reader that de-escapes restores the ambiguity) and it
    /// corrupts legitimate payloads, which are full of `${…}` (shell, CI YAML, templates).
    Nonced(String),
}

impl Placeholder {
    /// The text that replaces one occurrence of a needle named `name`.
    fn render(&self, name: &str) -> String {
        match self {
            Placeholder::Plain => format!("${{{name}}}"),
            Placeholder::Nonced(nonce) => format!("${{{name}@{nonce}}}"),
        }
    }
}

/// Replace every occurrence of every needle in `buf` with its name, returning the new bytes and how
/// many substitutions were made.
///
/// Operates on **bytes**, never on a lossily-decoded string: a command's output is arbitrary bytes,
/// and decoding first could split a value across a replacement character and hide it from the scan.
///
/// Needles are applied **longest first**, so a value that contains another (a plaintext and an
/// encoding of it that share a prefix, two credentials where one is a substring of the other) is
/// named after the longest match rather than being broken up by a shorter one. A needle below
/// [`REDACT_MIN_LEN`] is skipped — see the constant.
pub(crate) fn redact_named(
    buf: &[u8],
    needles: &[SecretNeedle],
    placeholder: &Placeholder,
) -> (Vec<u8>, usize) {
    // Longest first, and skip what is too short to substitute safely. Sorting indices keeps the
    // caller's needle set untouched.
    let mut order: Vec<&SecretNeedle> = needles
        .iter()
        .filter(|n| n.as_bytes().len() >= REDACT_MIN_LEN)
        .collect();
    order.sort_by_key(|n| std::cmp::Reverse(n.as_bytes().len()));

    let mut out = buf.to_vec();
    let mut count = 0;
    for needle in order {
        let bytes = needle.as_bytes();
        let replacement = placeholder.render(needle.name()).into_bytes();
        let mut next = Vec::with_capacity(out.len());
        let mut i = 0;
        while i < out.len() {
            if i + bytes.len() <= out.len() && &out[i..i + bytes.len()] == bytes {
                next.extend_from_slice(&replacement);
                i += bytes.len();
                count += 1;
            } else {
                next.push(out[i]);
                i += 1;
            }
        }
        out = next;
    }
    (out, count)
}

/// Substitute over a `String`, for the sinks that are already text (a log line, an error message
/// sbx composes). The result is lossy-decoded, which is safe *after* the byte-level scan.
pub(crate) fn redact_string(
    text: &str,
    needles: &[SecretNeedle],
    placeholder: &Placeholder,
) -> (String, usize) {
    let (bytes, count) = redact_named(text.as_bytes(), needles, placeholder);
    (String::from_utf8_lossy(&bytes).into_owned(), count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn needle(name: &str, value: &str) -> SecretNeedle {
        SecretNeedle::named(name, value.as_bytes().to_vec())
    }

    // The headline behaviour: a value becomes its own name, every occurrence, and the count is what
    // the host-side log reports.
    #[test]
    fn every_occurrence_becomes_the_name_and_is_counted() {
        let needles = vec![needle("gh_token", "ghp-abcdefgh")];
        let (out, count) = redact_named(
            b"first ghp-abcdefgh then ghp-abcdefgh done",
            &needles,
            &Placeholder::Plain,
        );
        assert_eq!(out, b"first ${gh_token} then ${gh_token} done");
        assert_eq!(count, 2);
    }

    // A registered encoding variant of the same secret carries the same name, so the reader sees one
    // credential regardless of the spelling that reached the sink.
    #[test]
    fn an_encoding_variant_renders_under_the_same_name() {
        let needles = vec![
            needle("api_key", "plaintext-value"),
            needle("api_key", "cGxhaW50ZXh0LXZhbHVl"), // its base64 form
        ];
        let (out, count) = redact_named(
            b"raw=plaintext-value b64=cGxhaW50ZXh0LXZhbHVl",
            &needles,
            &Placeholder::Plain,
        );
        assert_eq!(out, b"raw=${api_key} b64=${api_key}");
        assert_eq!(count, 2);
    }

    // Longest-first matters: when one needle contains another, the containing value must be named
    // as a whole instead of being cut apart by the shorter one.
    #[test]
    fn a_longer_needle_wins_over_a_contained_shorter_one() {
        let needles = vec![
            needle("short", "abcdefgh"),
            needle("long", "abcdefgh-with-more"),
        ];
        let (out, _) = redact_named(b"v=abcdefgh-with-more", &needles, &Placeholder::Plain);
        assert_eq!(
            out, b"v=${long}",
            "the longest match names the value; the shorter needle must not fragment it"
        );
    }

    // Below the threshold nothing is substituted: such a value would match benign text and its
    // placeholders would leak the value through their positions.
    #[test]
    fn a_needle_below_the_minimum_length_is_not_substituted() {
        let needles = vec![needle("tiny", "abc")];
        let (out, count) = redact_named(b"abc appears in abcdef", &needles, &Placeholder::Plain);
        assert_eq!(out, b"abc appears in abcdef", "the output is untouched");
        assert_eq!(count, 0);
    }

    // The nonce form is what makes a placeholder unforgeable for *this* output: the producer cannot
    // predict the nonce, so a `${name@nonce}` it printed itself would carry the wrong one.
    #[test]
    fn the_nonced_placeholder_carries_the_invocation_nonce() {
        let needles = vec![needle("gh_token", "ghp-abcdefgh")];
        let (out, count) = redact_named(
            b"tok=ghp-abcdefgh",
            &needles,
            &Placeholder::Nonced("a91f3c".to_string()),
        );
        assert_eq!(out, b"tok=${gh_token@a91f3c}");
        assert_eq!(count, 1);
    }

    // Arbitrary command output is not necessarily UTF-8. The scan is byte-level, so a value sitting
    // next to invalid bytes is still found — decoding first could have hidden it.
    #[test]
    fn a_value_beside_invalid_utf8_is_still_substituted() {
        let needles = vec![needle("gh_token", "ghp-abcdefgh")];
        let mut buf = vec![0xff, 0xfe];
        buf.extend_from_slice(b"ghp-abcdefgh");
        buf.push(0x80);
        let (out, count) = redact_named(&buf, &needles, &Placeholder::Plain);
        assert_eq!(count, 1);
        let mut want = vec![0xff, 0xfe];
        want.extend_from_slice(b"${gh_token}");
        want.push(0x80);
        assert_eq!(out, want);
    }

    // The string front-end is the same substitution for the sinks that are already text.
    #[test]
    fn the_string_form_substitutes_and_counts_the_same() {
        let needles = vec![needle("db_pass", "hunter2-hunter2")];
        let (out, count) = redact_string(
            "psql: error: password=hunter2-hunter2 rejected",
            &needles,
            &Placeholder::Plain,
        );
        assert_eq!(out, "psql: error: password=${db_pass} rejected");
        assert_eq!(count, 1);
    }
}
