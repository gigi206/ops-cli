//! `distro:` userlands — a prebuilt distribution root filesystem the cage runs on.
//!
//! A cage without one runs on the hermetic userland [`super::fhs`] resolves from sbx's own store.
//! Declaring an image replaces that userland with a distribution's own, which is what a project
//! building against a release's compiler, headers and ABI needs.
//!
//! Scope, and the reason for it: sbx **consumes** a published image and never builds one. It
//! resolves the locator to a digest, fetches the layers the digest names, applies them, and mounts
//! the result read-only. That is the same shape as the prebuilt `[packages]` backends, and it is
//! what makes every distribution work without a line of code that knows one: nothing here parses a
//! package name, runs a package manager, or maps a name from one distribution to another.

pub(crate) mod build;
mod gzip;
mod http;
pub(crate) mod layers;
pub(crate) mod reference;
pub(crate) mod registry;
pub(crate) mod store;
pub(crate) mod unpack;

/// Resolve the credential a `[distro] auth` reference names, host-side.
///
/// `None` when no credential was declared, which is every public image and so almost every
/// configuration. The value is `<username>:<password>` as the registry's token service expects it;
/// nothing here inspects it, and it is handed to [`registry::Credential`] at the boundary.
///
/// Host-side, before the cage exists, and never bound into it: a credential the cage could read is
/// a credential every program in the cage has. That is the same rule `[secret]` follows, and this
/// runs through the same resolver, so a source that works for one works for the other.
///
/// **No brokers.** A launch starts its brokers well after the userland it is going to run on has to
/// exist, so a resolver plugin that itself reaches one has nothing to reach here. Passing the empty
/// set rather than pretending otherwise means such a plugin fails with its own message instead of
/// resolving to something unexpected.
pub(crate) fn credential(
    cfg: &crate::config::Resolved,
    project_root: &std::path::Path,
    bwrap: &std::path::Path,
) -> std::io::Result<Option<String>> {
    let Some(source) = cfg.distro_auth.as_ref() else {
        return Ok(None);
    };
    crate::sandbox::egress::resolve_chain(
        std::slice::from_ref(source),
        "the distribution registry",
        project_root,
        bwrap,
        &[],
    )
    .map(Some)
}

/// The line that reports a failure to provision or roll an image, as a terminal is to show it.
///
/// The error names what a registry and an image chose: a layer member's name, a media type, a
/// registry's challenge, its token endpoint's answer. Those bytes reach the terminal at the moment
/// sbx reports why a launch did not start or a roll did not happen, so the line goes through
/// [`crate::diag::visible`], and an escape sequence in them is written out rather than obeyed.
///
/// `doing` is sbx's own text around the locator a configuration chose, and the whole line is
/// escaped: none of it carries a line break of sbx's own.
pub(crate) fn failure(doing: &str, e: &std::io::Error) -> String {
    crate::diag::visible(&format!("sbx: cannot {doing}: {e}"))
}

#[cfg(test)]
mod tests {
    /// What a registry or an image chose is shown written out, never obeyed: an escape sequence in
    /// a member's name, a carriage return in a challenge, a character that reorders text. sbx's
    /// own words and the backticks the diagnostics colour are kept.
    #[test]
    fn a_failure_shows_what_the_registry_or_the_image_chose_as_an_escape() {
        let e = std::io::Error::other(
            "refusing layer member `../\u{1b}[2Jx`: it leaves the image root \
             (Bearer a\rb \u{202e}c)",
        );
        let shown = super::failure("provision the `oci:x` root filesystem", &e);
        assert!(
            !shown.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{shown:?}"
        );
        for escaped in ["\\x1b[2Jx", "a\\x0db", "\\u{202e}c"] {
            assert!(shown.contains(escaped), "`{escaped}` in {shown}");
        }
        assert!(
            shown.starts_with("sbx: cannot provision the `oci:x` root filesystem: refusing layer"),
            "{shown}"
        );
    }

    /// Every production file that provisions or rolls an image prints the failure through
    /// [`super::failure`].
    ///
    /// Read from the sources because the failure is an omission: a caller that formats the error
    /// itself compiles, reports the same words, and differs only on a terminal handed an escape
    /// sequence. The population is every file calling either entry point, so a new caller is held
    /// to the rule without being named here, and it is checked not to be empty.
    #[test]
    fn every_image_failure_is_printed_through_the_escaping_line() {
        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let test_only = crate::testutil::test_only_sources();
        let mut callers = Vec::new();
        let mut offenders = Vec::new();
        for file in crate::testutil::crate_sources() {
            if crate::testutil::is_test_only_source(&file) || test_only.contains(&file) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let production = crate::testutil::production_half(&text);
            let entry = ["distro::store::provision(", "distro::store::refresh("]
                .iter()
                .any(|needle| crate::testutil::calls_function(production, needle));
            if !entry {
                continue;
            }
            let relative = file.display().to_string().replacen(&root, "", 1);
            if !crate::testutil::calls_function(production, "distro::failure(") {
                offenders.push(relative.clone());
            }
            callers.push(relative);
        }
        assert!(
            callers.len() >= 2,
            "the launch and the roll call the image store: {callers:?}"
        );
        assert!(
            offenders.is_empty(),
            "an image failure is printed without `distro::failure`: {offenders:?}"
        );
    }
}
