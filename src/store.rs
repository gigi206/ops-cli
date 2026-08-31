//! The user-owned, daemonless nix store.
//!
//! sbx provisions a project's tools into a store it owns under its own data
//! directory, never the host's `/nix`. The shared store is a single flat tree —
//! deduplicated across projects, written only while sbx itself provisions into it
//! on the host side; a sandbox then consumes a per-project copy seeded from it,
//! bound read-write so an agent can self-equip, while the shared tree stays
//! read-only. This module computes the
//! on-disk layout, bootstraps it, and builds the daemonless nix invocation that
//! drives it.
//!
//! Four questions, one per child, and they are asked in that order because their
//! dependencies run only one way — [`mod@layout`] is the leaf the other three read, and
//! [`mod@engine`] is read by [`mod@provisioning`]:
//!
//! * [`mod@layout`] — *where the data lives*: the pure path derivation rooted at the data
//!   directory, the guards that refuse a directory sbx could not bind its sockets under,
//!   and the skeleton it creates on first use.
//! * [`mod@engine`] — *which host binaries sbx execs*: `nix` and its multi-call siblings,
//!   `bwrap`, `git`, the embedded exec shim, and the trust verdict each is admitted under.
//!   Nothing here concerns the store's content.
//! * [`mod@channel`] — *which nixpkgs revision is in force*: the source → lock → pinned-revision
//!   state machine, one lock file per scope, and the reachability witness that says whether a
//!   pinned revision is one nixpkgs history actually contains. It never resolves a binary:
//!   every entry point takes `nix: &Path` from its caller.
//! * [`mod@provisioning`] — *turning a pinned reference into a built path*: the daemonless nix
//!   invocation, the four provision entry points, the expression-stamp short-circuit and the
//!   selection of the output that carries what the caller asked for.
//!
//! The re-exports below are the module's surface: the rest of the crate names
//! `crate::store::<item>` and never a child directly.

mod channel;
mod engine;
mod layout;
mod provisioning;

pub(crate) use channel::{
    LockTarget, Origin, Upgrade, is_pinned_revision, live_base_revisions, live_mise_revisions,
    read_global_lock, resolve_engine_ref, revision_of, witness_revision,
};
#[cfg(test)]
pub(crate) use engine::embedded_proc_shim;
pub(crate) use engine::{
    ensure_proc_shim, host_exec_verdict, resolve_bwrap, resolve_git, resolve_nix, resolve_nix_store,
};
pub(crate) use layout::{BROKER_NAME_MAX, Layout, data_dir_overridden, ensure, physical_path};
pub(crate) use provisioning::{
    nix_command, provision, provision_expr, provision_flake, provision_unfree, root_channel_source,
};
