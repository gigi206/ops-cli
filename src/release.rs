//! The release this binary was published as, when it was published at all.
//!
//! A publishing workflow stamps three values into the build: the tag the binary is published under
//! (`latest`, `nightly`, `v1.2.3`), the commit it was built from, and the repository that publishes
//! it. `sbx --version` names the first two, and `sbx upgrade self` follows the release the three of
//! them designate. A build that carries none was built from source. It has no release to follow, and
//! its version number does not say which build it is, since every build carries the crate's.
//!
//! The values are checked when the crate is compiled, not when they are read. They are spliced into
//! the addresses `upgrade self` fetches from, so a malformed stamp fails the build that carries it
//! instead of reaching a user as a URL.

/// A published build's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Release {
    /// The tag the binary is published under.
    pub(crate) tag: &'static str,
    /// The full hash of the commit it was built from.
    pub(crate) commit: &'static str,
    /// The repository that publishes it, as `owner/name`.
    pub(crate) repo: &'static str,
}

/// What a release follows when it upgrades.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    /// A tag its workflow moves onto every new build (`latest`, `nightly`): following it means
    /// fetching the same tag again.
    Rolling(&'static str),
    /// A tag that is a version names one publication that never changes, so its successor is the
    /// newest stable release.
    Stable,
}

impl Release {
    /// The channel this release follows: a tag that reads as a version is a fixed publication, any
    /// other is a rolling one.
    pub(crate) fn channel(&self) -> Channel {
        // A tag ranks against itself exactly when it is plainly a version; `latest` and `nightly`
        // do not rank at all.
        if crate::version::version_order(self.tag, self.tag).is_some() {
            Channel::Stable
        } else {
            Channel::Rolling(self.tag)
        }
    }
}

/// This binary's identity, `None` for a build from source.
pub(crate) const PUBLISHED: Option<Release> = stamp(
    option_env!("SBX_RELEASE_TAG"),
    option_env!("SBX_RELEASE_COMMIT"),
    option_env!("SBX_RELEASE_REPO"),
);

/// The identity three stamped values make, failing the compilation on a stamp that is partial or
/// malformed. Evaluated in a constant, so its panics are build errors.
const fn stamp(
    tag: Option<&'static str>,
    commit: Option<&'static str>,
    repo: Option<&'static str>,
) -> Option<Release> {
    let stamped = tag.is_some() as u8 + commit.is_some() as u8 + repo.is_some() as u8;
    assert!(
        stamped == 0 || stamped == 3,
        "SBX_RELEASE_TAG, SBX_RELEASE_COMMIT and SBX_RELEASE_REPO are stamped together or not at \
         all"
    );
    let (Some(tag), Some(commit), Some(repo)) = (tag, commit, repo) else {
        return None;
    };
    assert!(is_tag(tag), "SBX_RELEASE_TAG is not a release tag");
    assert!(
        is_hex(commit, 40) || is_hex(commit, 64),
        "SBX_RELEASE_COMMIT is not a full commit hash"
    );
    assert!(is_repo(repo), "SBX_RELEASE_REPO is not owner/name");
    Some(Release { tag, commit, repo })
}

/// The line `sbx --version` prints: the crate's version, then the release's tag and commit when
/// the build was published.
pub(crate) fn version_line() -> String {
    let version = env!("CARGO_PKG_VERSION");
    match PUBLISHED {
        Some(release) => format!(
            "sbx {version} ({}, {})",
            release.tag,
            crate::short_rev(release.commit)
        ),
        None => format!("sbx {version}"),
    }
}

/// A byte a tag or a repository name may carry, the set GitHub allows in both.
const fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'
}

/// Whether `s` is one URL path segment of name bytes that starts with a letter or a digit, so it
/// can name neither a parent directory (`..`) nor an option.
const fn is_segment(s: &[u8]) -> bool {
    if s.is_empty() || !s[0].is_ascii_alphanumeric() {
        return false;
    }
    let mut i = 0;
    while i < s.len() {
        if !is_name_byte(s[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `s` can be a release tag: one segment of name bytes, the shape `install.sh` holds a tag
/// to before splicing it into a URL.
pub(crate) const fn is_tag(s: &str) -> bool {
    is_segment(s.as_bytes())
}

/// Whether `s` is `owner/name`, each half a segment of name bytes.
pub(crate) const fn is_repo(s: &str) -> bool {
    let bytes = s.as_bytes();
    let mut slash = 0;
    while slash < bytes.len() && bytes[slash] != b'/' {
        slash += 1;
    }
    if slash == bytes.len() {
        return false;
    }
    let (owner, name) = bytes.split_at(slash);
    is_segment(owner) && is_segment(name.split_at(1).1)
}

/// Whether `s` is exactly `len` lowercase hex digits: a commit hash, or a SHA-256 as `sha256sum`
/// writes it.
pub(crate) const fn is_hex(s: &str, len: usize) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != len {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        if !matches!(bytes[i], b'0'..=b'9' | b'a'..=b'f') {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0a9ad1c73748cfa9b09d1994ece8a2aaa4ed8fe5";

    #[test]
    fn a_stamp_is_all_three_values_or_none() {
        assert_eq!(stamp(None, None, None), None);
        assert_eq!(
            stamp(Some("latest"), Some(COMMIT), Some("gigi206/ops-cli")),
            Some(Release {
                tag: "latest",
                commit: COMMIT,
                repo: "gigi206/ops-cli",
            })
        );
        for partial in [
            (Some("latest"), None, None),
            (None, Some(COMMIT), Some("gigi206/ops-cli")),
            (Some("latest"), Some(COMMIT), None),
        ] {
            let caught = std::panic::catch_unwind(|| stamp(partial.0, partial.1, partial.2));
            assert!(caught.is_err(), "a partial stamp was accepted: {partial:?}");
        }
    }

    #[test]
    fn a_malformed_value_is_refused_before_it_can_reach_a_url() {
        assert!(is_tag("latest") && is_tag("v1.9.0") && is_tag("v2.0.0-rc1"));
        for tag in ["", "..", ".hidden", "-x", "latest/x", "a b", "v1?x"] {
            assert!(!is_tag(tag), "accepted the tag {tag:?}");
        }
        assert!(is_repo("gigi206/ops-cli"));
        for repo in [
            "ops-cli",
            "gigi206/",
            "/ops-cli",
            "gigi206/ops-cli/x",
            "gigi 206/x",
            "a/..",
        ] {
            assert!(!is_repo(repo), "accepted the repository {repo:?}");
        }
        assert!(is_hex(COMMIT, 40));
        for commit in [
            "0a9ad1c7",
            "0A9AD1C73748CFA9B09D1994ECE8A2AAA4ED8FE5",
            "g".repeat(40).as_str(),
        ] {
            assert!(!is_hex(commit, 40), "accepted the commit {commit:?}");
        }
        // And the stamp holds every value to them, not only the predicates.
        let caught = std::panic::catch_unwind(|| stamp(Some(".."), Some(COMMIT), Some("a/b")));
        assert!(caught.is_err(), "a stamp with a malformed tag was accepted");
    }

    #[test]
    fn a_version_tag_follows_the_stable_releases_and_any_other_rolls() {
        let release = |tag| Release {
            tag,
            commit: COMMIT,
            repo: "gigi206/ops-cli",
        };
        assert_eq!(release("v1.9.0").channel(), Channel::Stable);
        assert_eq!(release("v2.0.0-rc1").channel(), Channel::Stable);
        assert_eq!(release("latest").channel(), Channel::Rolling("latest"));
        assert_eq!(release("nightly").channel(), Channel::Rolling("nightly"));
    }

    #[test]
    fn the_version_line_names_the_release_only_when_there_is_one() {
        let line = version_line();
        let version = env!("CARGO_PKG_VERSION");
        match PUBLISHED {
            Some(release) => assert_eq!(
                line,
                format!("sbx {version} ({}, {})", release.tag, &release.commit[..7])
            ),
            None => assert_eq!(line, format!("sbx {version}")),
        }
    }
}
