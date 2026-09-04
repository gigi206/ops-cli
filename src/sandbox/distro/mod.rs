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

mod gzip;
mod http;
mod layers;
pub(crate) mod reference;
pub(crate) mod registry;
pub(crate) mod store;

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
