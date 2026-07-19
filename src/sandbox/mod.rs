//! The sandbox core: a declarative [`spec::SandboxSpec`] and the pure function
//! that turns it into a bubblewrap argv.
//!
//! Security keystone. The Spec is the single description of everything the
//! sandbox exposes; [`argv::to_argv`] adds no exposure of its own and is a pure
//! function of the Spec. So whatever reaches bubblewrap was declared in one
//! place — a security review has a single surface to audit.

mod appimage;
mod argv;
mod attach;
mod audio;
mod binds;
mod catrust;
pub(crate) mod cgroup;
mod contract;
pub(crate) mod control;
mod deb;
pub(crate) mod egress;
pub(crate) mod egress_stats;
mod fhs;
mod flake;
mod flake_inline;
mod fonts;
mod forward;
pub(crate) mod fs_control;
mod fs_watch;
mod gc;
mod gpu;
mod guidata;
pub(crate) mod inspect;
mod launch;
mod mise;
mod miseplugin;
mod naming;
pub(crate) mod netlearn;
mod netns;
mod nixhub;
mod notify_relay;
mod observe_feed;
mod packages;
mod portal;
mod prebuilt;
pub(crate) mod proc_control;
pub(crate) mod proc_enforce;
mod projectstore;
mod proxy;
mod resolver;
mod search;
pub(crate) mod seccomp;
mod smoke;
mod spec;
mod tarball;
mod theme_relay;

pub(crate) use appimage::{
    pinned_hashes as appimage_pinned_hashes, upgrade as upgrade_appimage,
    withheld as withheld_appimage_packages, AppImageUpgrade,
};
pub(crate) use binds::{project_id, project_identity, structural_nesting_warning};
pub(crate) use cgroup::{probe as resource_limits, LimitReport};
pub(crate) use deb::{
    pinned_hashes as deb_pinned_hashes, upgrade as upgrade_deb, withheld as withheld_deb_packages,
    DebUpgrade,
};
pub(crate) use flake::{
    pinned_revs as flake_pinned_revs, upgrade as upgrade_flake,
    withheld as withheld_flake_packages, FlakeUpgrade,
};
pub(crate) use gc::{
    classify_tree, human_bytes, installed_app_homes, prune_app_tools, purge_app_homes, tree_size,
    InstalledApp,
};
pub(crate) use launch::{
    app, attach, effective_lock_target, gc, projects_list, projects_rm, projects_show,
    rm_apply as projects_rm_apply, run, run_mise, stop, superseded_reclaimable_hint,
    upgrade_mise_packages,
};
pub(crate) use naming::cage_name;
pub(crate) use netlearn::{Granularity, Synthesis};
pub(crate) use netns::run_holder;
pub(crate) use nixhub::{current_system, parse_nix_tools, upgrade_tools, ToolUpgrade};
#[cfg(test)]
pub(crate) use projectstore::PROJECT_MARKER;
pub(crate) use proxy::{builtin_allow_rules, union_with_builtin};
pub(crate) use search::run as search;
pub(crate) use smoke::run as smoke;
pub(crate) use tarball::{
    pinned_hashes as tarball_pinned_hashes, upgrade_project as upgrade_tarball,
    withheld as withheld_tarball_packages, TarballUpgrade,
};
