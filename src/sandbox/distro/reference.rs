//! Parsing an `oci:` locator into the three things a registry request needs.
//!
//! One definition of the grammar, for the reason every split rule in this codebase eventually
//! earns: the config validates a locator before it is stored and the provisioner takes it apart
//! before it is fetched, and two hand-written readings of the same string drift. So the parser is
//! the definition, and the config's own validator is "the parser accepted it".
//!
//! The grammar is enumerated rather than filtered, because this value names the root filesystem
//! every program in the cage is executed from:
//!
//! * the registry is written out, since a reference with no host resolves against whatever default
//!   the client that reads it happens to carry;
//! * a reference is mandatory, since an image named with no tag and no digest floats;
//! * a tag and a digest together are refused: the digest alone pins, and honoring both would mean
//!   choosing which one wins when they disagree.

use std::fmt;

/// What selects an image inside a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reference {
    /// A name the registry may move under you, resolved to a digest and then locked.
    Tag(String),
    /// `sha256:<64 lowercase hex>`: the image itself, which no registry can move.
    Digest(String),
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reference::Tag(tag) => write!(f, ":{tag}"),
            Reference::Digest(digest) => write!(f, "@{digest}"),
        }
    }
}

/// A parsed `oci:` locator: where to ask, what to ask for, and which image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageRef {
    /// The registry host, port included when one was written (`docker.io`, `localhost:5000`).
    pub(crate) registry: String,
    /// The repository path under it (`library/debian`), with no leading or trailing slash.
    pub(crate) repository: String,
    /// The tag or digest that selects the image.
    pub(crate) reference: Reference,
}

impl ImageRef {
    /// The registry's API host. `docker.io` is the one name that does not address its own API:
    /// Docker Hub publishes under `docker.io` and serves under `registry-1.docker.io`, and a
    /// request to the former answers with a redirect a fetcher would have to follow to a host it
    /// never checked. Naming the substitution here keeps it one line instead of one condition per
    /// request.
    pub(crate) fn api_host(&self) -> &str {
        match self.registry.as_str() {
            "docker.io" | "index.docker.io" => "registry-1.docker.io",
            other => other,
        }
    }

    /// The locator this reference came from, rebuilt. Used where a message or a lock has to name
    /// the image as it was written rather than as it was taken apart.
    pub(crate) fn locator(&self) -> String {
        format!(
            "oci:{}/{}{}",
            self.registry, self.repository, self.reference
        )
    }

    /// The same image, pinned to `digest` instead of whatever selected it.
    pub(crate) fn pinned(&self, digest: &str) -> ImageRef {
        ImageRef {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            reference: Reference::Digest(digest.to_string()),
        }
    }
}

/// Parse an `oci:` locator, or `None` for anything the grammar above refuses.
pub(crate) fn parse(locator: &str) -> Option<ImageRef> {
    let rest = locator.strip_prefix("oci:")?;
    // The registry is the first `/`-segment, so a `:` is a reference separator only past the last
    // `/`; an earlier one is the registry's port.
    let slash = rest.rfind('/')?;
    let (name, reference) = match rest.split_once('@') {
        Some((name, digest)) => (name, Reference::Digest(valid_digest(digest)?.to_string())),
        None => {
            let offset = rest[slash..].find(':')?;
            let at = slash + offset;
            (
                &rest[..at],
                Reference::Tag(valid_tag(&rest[at + 1..])?.to_string()),
            )
        }
    };
    let (registry, repository) = name.split_once('/')?;
    if !valid_registry(registry) || !valid_repository(repository) {
        return None;
    }
    Some(ImageRef {
        registry: registry.to_string(),
        repository: repository.to_string(),
        reference,
    })
}

/// A registry host: something that looks like one (a dot, or `localhost`), with an optional
/// numeric port. Required to look like a host so a locator cannot be a bare repository the
/// registry client would complete on its own.
fn valid_registry(registry: &str) -> bool {
    let (host, port) = registry
        .split_once(':')
        .map_or((registry, None), |(h, p)| (h, Some(p)));
    if host != "localhost" && !host.contains('.') {
        return false;
    }
    if !host.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return false;
    }
    !port.is_some_and(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
}

/// A repository path: one or more lowercase segments. No empty segment, and no `.` or `..`, which
/// would let a locator climb out of the repository it appears to name once it becomes a URL.
fn valid_repository(repository: &str) -> bool {
    let mut segments = 0;
    for segment in repository.split('/') {
        segments += 1;
        let ok = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if !ok {
            return false;
        }
    }
    segments > 0
}

/// An image tag, in the shape a registry accepts and nothing looser.
fn valid_tag(tag: &str) -> Option<&str> {
    let ok = !tag.is_empty()
        && tag.len() <= 128
        && tag
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some(tag)
}

/// A content digest: the one algorithm every registry serves, and a fixed-width lowercase hex
/// body. Anything else is refused here rather than passed on to a fetch, and the fixed width is
/// what lets the fetcher compare it against what it computed without normalising either side.
pub(crate) fn valid_digest(digest: &str) -> Option<&str> {
    let hex = digest.strip_prefix("sha256:")?;
    let ok = hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    ok.then_some(digest)
}

#[cfg(test)]
mod tests;
