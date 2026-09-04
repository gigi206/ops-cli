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
