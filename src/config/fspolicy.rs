//! The `[fs]` policy: which parts of the project tree a cage may not read or may not write.
//!
//! This module owns the *grammar* — what a mask entry may look like — and nothing else. Turning an
//! entry into the paths it actually covers needs the project on disk, so it belongs to the launch
//! (see [`crate::sandbox::fsmask`]); keeping the two apart is what lets the grammar be checked
//! without touching the filesystem, here and in the task loader, from one definition.
//!
//! The grammar is narrow on purpose. Every glob costs a directory read at launch, and a recursive
//! one costs a walk of the whole project: measured on a real repository, an unanchored `**` took
//! seconds while an anchored pattern took milliseconds. So exactly one rule bounds the cost — a
//! wildcard may appear only in an entry's **last** component — and it also makes every entry
//! anchored by construction, since every component above the last is a literal name.

use serde::Serialize;

/// The resolved `[fs]` policy: the project paths a cage may not read, and those it may not write.
///
/// Entries are kept as *patterns*, not paths: the launch expands them against the project it is
/// about to mount, so a pattern that matches nothing today and something tomorrow needs no
/// re-resolution. A trailing `/` is preserved — it is how an entry says "this is a directory".
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FsPolicy {
    /// Patterns the cage may not read. The path's *name* stays visible in a listing.
    pub(crate) deny: Vec<String>,
    /// Patterns the cage may read but not write.
    pub(crate) readonly: Vec<String>,
}

impl FsPolicy {
    /// Whether this policy closes nothing at all, in which case a launch skips the whole mechanism.
    pub(crate) fn is_empty(&self) -> bool {
        self.deny.is_empty() && self.readonly.is_empty()
    }

    /// Union `extra` onto this policy, deduped and order-preserving.
    ///
    /// The merge direction is the field's whole safety story: a layer *adds* masks and can never
    /// remove one, so a project (or an app) folded onto the global config can only close more of
    /// the tree than the layer below it did.
    pub(crate) fn union(&mut self, extra: FsPolicy) {
        for entry in extra.deny {
            if !self.deny.contains(&entry) {
                self.deny.push(entry);
            }
        }
        for entry in extra.readonly {
            if !self.readonly.contains(&entry) {
                self.readonly.push(entry);
            }
        }
    }
}

/// Validate one mask entry lexically and return it normalised, or the reason it was refused.
///
/// Pure: the path need not exist (a portable profile may name a file only some checkouts carry —
/// an entry matching nothing is a launch-time warning, not a parse error). What is judged is the
/// entry's *spelling*:
///
/// - **relative to the project root** — an absolute path is refused. The cage's exposure of the
///   host outside the project is `binds`, a trusted field with its own gate; letting `[fs]`, which
///   is honored from any source, name a path outside the project would make it a second way to
///   reach one.
/// - **no `..` component** — it would leave the project, and the containment check downstream would
///   have to undo the traversal rather than never see it.
/// - **no `**`** — it means a recursive walk, and the walk is the cost this grammar exists to bound.
/// - **a wildcard only in the last component** — so matching reads exactly one directory, and every
///   component above it is a literal name.
pub(crate) fn validate_entry(entry: &str) -> Result<String, String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err("is empty".to_string());
    }
    if trimmed.starts_with('/') {
        return Err(
            "must be relative to the project root (host paths outside the project are \
                    exposed by `binds`, not closed by `[fs]`)"
                .to_string(),
        );
    }
    if trimmed.contains("**") {
        return Err(
            "must not use `**` — a recursive match walks the whole project; name the \
                    directory instead, which closes it for good"
                .to_string(),
        );
    }
    // Strip a leading `./` and a trailing `/`, keeping the latter's meaning in a flag: the
    // components are then judged on names alone.
    let body = trimmed.strip_prefix("./").unwrap_or(trimmed);
    let dir_only = body.ends_with('/');
    let body = body.trim_end_matches('/');
    if body.is_empty() {
        return Err("names the project root itself, which would close the whole tree".to_string());
    }
    let parts: Vec<&str> = body.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() || *part == "." {
            return Err("has an empty path component".to_string());
        }
        if *part == ".." {
            return Err("must not contain a `..` component".to_string());
        }
        let last = i + 1 == parts.len();
        if !last && has_wildcard(part) {
            return Err(format!(
                "may only use a wildcard in its last component (`{part}` is not the last), so \
                 matching it reads one directory rather than walking the project"
            ));
        }
    }
    let mut out = parts.join("/");
    if dir_only {
        out.push('/');
    }
    Ok(out)
}

/// Whether a path component carries a glob metacharacter, and so needs a directory read to match.
pub(crate) fn has_wildcard(part: &str) -> bool {
    part.contains(['*', '?', '['])
}

/// Match one path component against one pattern component, with `*` (any run, including empty),
/// `?` (exactly one character) and `[...]` (one of a set, `!`- or `^`-negated, with `a-z` ranges).
///
/// Written out rather than pulled from a crate because it is the same shell-glob shape `[proc]`
/// already matches exec targets with, and one dependency for two dozen lines of matching is not a
/// trade this crate makes. Bytes, not chars: a filename is bytes on Linux, and a `?` that consumed
/// a multi-byte character would match a different set than the shell's.
pub(crate) fn matches_component(pattern: &str, name: &str) -> bool {
    glob_match(pattern.as_bytes(), name.as_bytes())
}

/// The matcher behind [`matches_component`], recursing on `*` with the standard backtrack.
///
/// No wildcard consumes a `/`. The callers only ever pass single components, so today that changes
/// no verdict — it is here because the function's name is a promise, and a later caller that hands
/// it a whole path must not silently get a pattern matching across directories.
fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some(b'*') => {
            // The empty match first, then one more consumed byte each time, stopping at a `/`.
            let stop = name.iter().position(|&c| c == b'/').unwrap_or(name.len());
            (0..=stop).any(|skip| glob_match(&pattern[1..], &name[skip..]))
        }
        Some(b'?') => {
            matches!(name.first(), Some(&c) if c != b'/') && glob_match(&pattern[1..], &name[1..])
        }
        Some(b'[') => match (name.first(), class_end(pattern)) {
            (Some(&c), Some(end)) if c != b'/' => {
                class_matches(&pattern[1..end], c) && glob_match(&pattern[end + 1..], &name[1..])
            }
            // An unterminated `[` is a literal `[`, as a shell treats it.
            _ => name.first() == Some(&b'[') && glob_match(&pattern[1..], &name[1..]),
        },
        Some(&c) => name.first() == Some(&c) && glob_match(&pattern[1..], &name[1..]),
    }
}

/// The index of the `]` closing a character class opened at index 0, or `None` when it is
/// unterminated. A `]` immediately after the opening bracket (or after its negation) is a literal
/// member, which is the shell's rule.
fn class_end(pattern: &[u8]) -> Option<usize> {
    let mut i = 1;
    if matches!(pattern.get(i), Some(b'!') | Some(b'^')) {
        i += 1;
    }
    if pattern.get(i) == Some(&b']') {
        i += 1;
    }
    while i < pattern.len() {
        if pattern[i] == b']' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Whether `c` is in the class body (what sits between the brackets).
fn class_matches(body: &[u8], c: u8) -> bool {
    let (negated, body) = match body.first() {
        Some(b'!') | Some(b'^') => (true, &body[1..]),
        _ => (false, body),
    };
    let mut hit = false;
    let mut i = 0;
    while i < body.len() {
        // A `-` between two members is a range; one at either end is a literal `-`.
        if i + 2 < body.len() && body[i + 1] == b'-' {
            if body[i] <= c && c <= body[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if body[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    hit != negated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_entry_normalises_to_itself() {
        assert_eq!(
            validate_entry("config/prod.key").unwrap(),
            "config/prod.key"
        );
        assert_eq!(validate_entry("  .env  ").unwrap(), ".env");
        assert_eq!(validate_entry("./certs/x.pem").unwrap(), "certs/x.pem");
    }

    #[test]
    fn a_trailing_slash_is_kept_as_the_directory_intent() {
        assert_eq!(validate_entry("secrets/").unwrap(), "secrets/");
        assert_eq!(validate_entry("secrets//").unwrap(), "secrets/");
        assert_eq!(validate_entry("secrets").unwrap(), "secrets");
    }

    #[test]
    fn a_wildcard_is_allowed_only_in_the_last_component() {
        assert_eq!(validate_entry("certs/*.pem").unwrap(), "certs/*.pem");
        assert_eq!(validate_entry("*.pem").unwrap(), "*.pem");
        assert_eq!(validate_entry("certs/*/").unwrap(), "certs/*/");
        let refused = validate_entry("*/prod.key").unwrap_err();
        assert!(refused.contains("last component"), "{refused}");
        let refused = validate_entry("a/b*/c").unwrap_err();
        assert!(refused.contains("last component"), "{refused}");
    }

    #[test]
    fn the_refused_shapes_each_say_why() {
        // The recursive glob: the cost this grammar exists to bound.
        assert!(validate_entry("**/*.pem").unwrap_err().contains("`**`"));
        assert!(validate_entry("a/**/b").unwrap_err().contains("`**`"));
        // Outside the project.
        assert!(validate_entry("/etc/shadow")
            .unwrap_err()
            .contains("relative to the project root"));
        // Traversal.
        assert!(validate_entry("../secrets")
            .unwrap_err()
            .contains("`..` component"));
        assert!(validate_entry("a/../b")
            .unwrap_err()
            .contains("`..` component"));
        // The degenerate ones.
        assert!(validate_entry("").unwrap_err().contains("empty"));
        assert!(validate_entry("   ").unwrap_err().contains("empty"));
        assert!(validate_entry("/").unwrap_err().contains("relative"));
        assert!(validate_entry("./").unwrap_err().contains("project root"));
        assert!(validate_entry("a//b").unwrap_err().contains("empty path"));
    }

    #[test]
    fn the_component_matcher_covers_the_shell_shapes() {
        assert!(matches_component("*.pem", "server.pem"));
        assert!(matches_component("*.pem", ".pem"));
        assert!(!matches_component("*.pem", "server.key"));
        // No wildcard crosses a separator. Matching is per-component today, so this is what keeps
        // a later caller from getting a pattern that reaches across directories by accident.
        assert!(!matches_component("*.pem", "sub/server.pem"));
        assert!(!matches_component("a?c", "a/c"));
        assert!(!matches_component("a[/]c", "a/c"));
        assert!(matches_component("id_?sa", "id_rsa"));
        assert!(!matches_component("id_?sa", "id_sa"));
        assert!(matches_component("key[0-9]", "key7"));
        assert!(!matches_component("key[0-9]", "keyx"));
        assert!(matches_component("key[!0-9]", "keyx"));
        assert!(matches_component("prod.key", "prod.key"));
        assert!(!matches_component("prod.key", "prod.keys"));
        // An unterminated class is a literal bracket, as a shell has it.
        assert!(matches_component("a[bc", "a[bc"));
    }

    #[test]
    fn a_union_adds_and_never_removes() {
        let mut base = FsPolicy {
            deny: vec!["a".into()],
            readonly: vec!["r".into()],
        };
        base.union(FsPolicy {
            deny: vec!["a".into(), "b".into()],
            readonly: vec!["r2".into()],
        });
        assert_eq!(base.deny, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(base.readonly, vec!["r".to_string(), "r2".to_string()]);
        assert!(!base.is_empty());
        assert!(FsPolicy::default().is_empty());
    }
}
