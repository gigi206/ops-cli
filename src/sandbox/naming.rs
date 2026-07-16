//! A cage's human-readable name, derived once and shown consistently on every face
//! it surfaces through: the systemd scope (`systemctl --user`, `ps`, `systemd-cgls`),
//! the in-cage hostname (a shell prompt, `hostname`, `uname -n`), and the session
//! listing (`ops session ls`, `ops net … --session`). All three read the same slug so a cage
//! reads the same everywhere, instead of the opaque `run-p<pid>-i<pid>.scope` systemd
//! picks and the fixed `sandbox` hostname every cage otherwise shares.
//!
//! The slug comes from the launch's own identity — the app name for `ops app <name>`,
//! else the project's directory name — never from anything an untrusted project can
//! set, so naming grants no new influence over the host.

use std::path::Path;

/// The longest slug kept before the composed forms add their prefix/suffix. A hostname
/// label is capped at 63 bytes and `ops-` takes four, so 50 leaves comfortable room while
/// staying readable; the scope unit name has a far larger ceiling, so this bounds both.
const MAX_SLUG: usize = 50;

/// Fold a common accented Latin letter to its base ASCII letter (lowercase), so an accented
/// project directory yields a legible slug (`café-app` → `cafe-app`) rather than dropping the
/// accent to a separator. Covers the Latin-1 Supplement and common Latin Extended-A letters;
/// anything outside that (other scripts) is left for the caller to treat as a separator. This
/// is deliberately a slug transliteration, not linguistically exact (`ß` → `s`, `þ` → `t`).
fn ascii_fold(ch: char) -> Option<char> {
    Some(match ch {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => 'a',
        'ç' | 'ć' | 'ĉ' | 'ċ' | 'č' => 'c',
        'ð' | 'ď' | 'đ' => 'd',
        'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => 'e',
        'ĝ' | 'ğ' | 'ġ' | 'ģ' => 'g',
        'ì' | 'í' | 'î' | 'ï' | 'ī' | 'ĭ' | 'į' | 'ı' => 'i',
        'ĺ' | 'ļ' | 'ľ' | 'ł' => 'l',
        'ñ' | 'ń' | 'ņ' | 'ň' => 'n',
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ŏ' | 'ő' => 'o',
        'ŕ' | 'ŗ' | 'ř' => 'r',
        'ß' | 'ś' | 'ŝ' | 'ş' | 'š' => 's',
        'ţ' | 'ť' | 'ŧ' | 'þ' => 't',
        'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => 'u',
        'ý' | 'ÿ' => 'y',
        'ź' | 'ż' | 'ž' => 'z',
        _ => return None,
    })
}

/// Reduce an arbitrary label to the character set shared by a systemd unit name and a
/// DNS hostname label: lowercase ASCII alphanumerics and `-`. A common accented Latin letter
/// is transliterated to its base (`café` → `cafe`); every other non-alphanumeric byte becomes
/// a separator, runs of separators collapse, leading/trailing separators are trimmed, and the
/// result is bounded — so a project directory with accents, spaces, dots, or other-script
/// characters still yields a clean, valid, bounded token. An input that reduces to nothing
/// (e.g. `/`, a name of only punctuation, or an all-CJK name) falls back to `cage`.
pub(crate) fn sanitize_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_SLUG));
    let mut last_was_sep = true; // true so a leading separator is dropped
    for ch in input.chars() {
        // Unicode-aware lowercase first, so an uppercase accent (`É`) folds like its lowercase
        // form (`é`); `next()` takes the base where a lowercasing expands to several chars.
        let lower = ch.to_lowercase().next().unwrap_or(ch);
        let mapped = if lower.is_ascii_alphanumeric() {
            lower
        } else {
            ascii_fold(lower).unwrap_or('-')
        };
        if mapped == '-' {
            if last_was_sep {
                continue; // collapse runs and skip a leading separator
            }
            last_was_sep = true;
        } else {
            last_was_sep = false;
        }
        out.push(mapped);
        if out.len() >= MAX_SLUG {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        return "cage".to_string();
    }
    out
}

/// The bare slug for a cage: the app name for an `ops app <name>` launch, otherwise the
/// project directory's own name. Sanitized to the safe, bounded token every face reuses.
pub(crate) fn cage_slug(app: Option<&str>, project: &Path) -> String {
    let source = app
        .map(str::to_string)
        .or_else(|| {
            project
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    sanitize_label(&source)
}

/// The in-cage hostname for a slug: `ops-<slug>`, so `$HOSTNAME`, `uname -n`, and a
/// `\h`-based shell prompt name the cage and distinguish it per project/app — while still
/// never revealing the *host's* own hostname (the fresh UTS namespace's whole point).
pub(crate) fn cage_hostname(slug: &str) -> String {
    format!("ops-{slug}")
}

/// The full display name for a cage — `ops-<slug>` — straight from its app/project identity.
/// The one function a session listing (`ops session ls`, `ops net … --session`) renders from, so the
/// name it shows is *identical* to the cage's hostname and systemd scope (they share this
/// slug), and cannot drift from them.
pub(crate) fn cage_name(app: Option<&str>, project: &Path) -> String {
    cage_hostname(&cage_slug(app, project))
}

/// The transient systemd scope's unit name for a slug: `ops-<slug>-<pid>.scope`. The pid
/// is the launcher's, present only to keep the name unique among concurrently live scopes
/// (two cages of one project share a slug); systemd requires a live unit name be unique
/// and `--collect` frees it on exit, so a finished cage never blocks the next.
pub(crate) fn scope_unit(slug: &str, pid: u32) -> String {
    format!("ops-{slug}-{pid}.scope")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sanitize_lowercases_and_replaces_unsafe_bytes() {
        assert_eq!(sanitize_label("Ops-CLI"), "ops-cli");
        assert_eq!(sanitize_label("my project.v2"), "my-project-v2");
        assert_eq!(sanitize_label("a__b  c"), "a-b-c");
    }

    #[test]
    fn sanitize_trims_and_collapses_separators() {
        assert_eq!(sanitize_label("--edge--"), "edge");
        assert_eq!(sanitize_label("a---b"), "a-b");
    }

    #[test]
    fn sanitize_transliterates_accented_latin() {
        // A French project name keeps its letters instead of dropping accents to separators.
        assert_eq!(sanitize_label("café déjà"), "cafe-deja");
        assert_eq!(sanitize_label("mon-projet-éàü"), "mon-projet-eau");
        // Uppercase accents fold like their lowercase form.
        assert_eq!(sanitize_label("Zürich-App"), "zurich-app");
        assert_eq!(sanitize_label("ÉTÉ"), "ete");
        // Other Latin scripts and the German ß transliterate too.
        assert_eq!(sanitize_label("Łódź"), "lodz");
        assert_eq!(sanitize_label("straße"), "strase");
        // A name in another script has nothing to fold, so it still falls back.
        assert_eq!(sanitize_label("プロジェクト"), "cage");
    }

    #[test]
    fn sanitize_falls_back_when_nothing_survives() {
        assert_eq!(sanitize_label(""), "cage");
        assert_eq!(sanitize_label("///"), "cage");
        assert_eq!(sanitize_label("."), "cage");
    }

    #[test]
    fn sanitize_bounds_length_without_a_trailing_separator() {
        let long = "x".repeat(80);
        let s = sanitize_label(&long);
        assert_eq!(s.len(), MAX_SLUG);
        // A slug truncated right after a separator must not keep the dangling '-'.
        let sep_at_boundary = format!("{}-tail", "a".repeat(MAX_SLUG - 1));
        let s2 = sanitize_label(&sep_at_boundary);
        assert!(
            !s2.ends_with('-'),
            "no dangling separator after truncation: {s2}"
        );
        assert!(s2.len() <= MAX_SLUG);
    }

    #[test]
    fn cage_slug_prefers_the_app_then_the_project_basename() {
        let project = PathBuf::from("/home/gigi/Documents/ops-cli");
        assert_eq!(cage_slug(Some("claude-code"), &project), "claude-code");
        assert_eq!(cage_slug(None, &project), "ops-cli");
        // A rootless / unnamed project path falls back rather than yielding an empty slug.
        assert_eq!(cage_slug(None, Path::new("/")), "cage");
    }

    #[test]
    fn a_cage_hostname_carries_the_ops_prefix() {
        assert_eq!(cage_hostname("ops-cli"), "ops-ops-cli");
        assert_eq!(cage_hostname("claude-code"), "ops-claude-code");
    }

    #[test]
    fn a_scope_unit_carries_the_ops_prefix_and_pid() {
        assert_eq!(
            scope_unit("claude-code", 4089496),
            "ops-claude-code-4089496.scope"
        );
        assert_eq!(scope_unit("ops-cli", 62727), "ops-ops-cli-62727.scope");
    }
}
