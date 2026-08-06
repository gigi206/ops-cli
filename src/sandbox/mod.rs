//! The sandbox core: a declarative [`spec::SandboxSpec`] and the pure function
//! that turns it into a bubblewrap argv.
//!
//! Security keystone. The Spec is the single description of everything the
//! sandbox exposes; [`argv::to_argv`] adds no exposure of its own and is a pure
//! function of the Spec. So whatever reaches bubblewrap was declared in one
//! place — a security review has a single surface to audit.

// Launch core: the SandboxSpec -> bwrap-argv -> cage pipeline, plus the terminal.
mod argv;
mod binds;
mod fhs;
mod launch;
mod memfd;
mod naming;
mod pty;
mod smoke;
mod spec;

// Declared operations: a fixed command run in an ephemeral sibling cage with a brokered credential,
// plus the control plane a caller reaches to invoke one and the host-only invocation log.
pub(crate) mod task;
pub(crate) mod task_control;
pub(crate) mod task_shim;
pub(crate) mod taskpool;

// Provisioning & packaging: the nix/mise engines, the package backends, the store.
mod appimage;
mod deb;
mod flake;
mod flake_inline;
mod mise;
mod miseplugin;
mod nixhub;
mod packages;
mod prebuilt;
mod projectstore;
mod resolve;
/// The resolver-plugin runner. Public to the crate for one function only: `sbx plugins info`
/// shows where a declared program resolves, and must use the very lookup a launch would.
pub(crate) mod resolver;
mod search;
mod tarball;

// Network egress (Model B): empty netns -> in-cage forwarder -> host MITM proxy.
mod contract;
pub(crate) mod control;
pub(crate) mod egress;
pub(crate) mod egress_stats;
mod forward;
pub(crate) mod netlearn;
mod netns;
mod proxy;
pub(crate) mod redact;

// The observation-lens substrate: the bounded event ring and the per-session control socket the
// filesystem, process and ssh-agent lenses below are each built from.
pub(crate) mod lens;

// Credential brokers: the cage gets the capability, never the secret behind it.
pub(crate) mod sshagent;
pub(crate) mod sshagent_control;

// In-cage enforcement: seccomp denylist, cgroup limits, exec policy.
pub(crate) mod cgroup;
pub(crate) mod proc_control;
pub(crate) mod proc_enforce;
pub(crate) mod seccomp;

// Filesystem observability.
pub(crate) mod fs_control;
mod fs_watch;
mod fsmask;

// Desktop / GUI holes: Wayland, GPU, audio, the D-Bus portal, theme/notifications.
mod audio;
mod catrust;
mod fonts;
mod gpu;
mod guidata;
mod notify_relay;
mod notify_sink;
mod portal;
mod theme_relay;

// Session lifecycle & introspection.
mod attach;
mod gc;
pub(crate) mod inspect;
mod observe_feed;

pub(crate) use appimage::{
    pinned_hashes as appimage_pinned_hashes, upgrade_project as upgrade_appimage,
    withheld as withheld_appimage_packages, AppImageUpgrade,
};
pub(crate) use binds::{project_id, project_identity, structural_nesting_warning};
pub(crate) use cgroup::{probe as resource_limits, LimitReport};
pub(crate) use deb::{
    pinned_hashes as deb_pinned_hashes, upgrade_project as upgrade_deb,
    withheld as withheld_deb_packages, DebUpgrade,
};
pub(crate) use flake::{
    pinned_revs as flake_pinned_revs, upgrade as upgrade_flake,
    withheld as withheld_flake_packages, FlakeUpgrade,
};
pub(crate) use gc::{
    classify_tree, human_bytes, installed_app_homes, prune_app_tools, purge_app_homes, tree_size,
    tree_usage, InstalledApp,
};
pub(crate) use launch::{
    app, attach, detach_log_path, effective_lock_target, gc, parse_session_header, projects_list,
    projects_rm, projects_show, rm_apply as projects_rm_apply, run, run_mise, stop,
    superseded_reclaimable_hint, upgrade_mise_packages, SessionHeader,
};
pub(crate) use naming::cage_name;
pub(crate) use netlearn::{Granularity, Synthesis};
pub(crate) use netns::run_holder;
pub(crate) use nixhub::{current_system, parse_nix_tools, upgrade_tools, ToolUpgrade};
/// The one outcome type the three prebuilt backends share. `DebUpgrade` and its siblings are
/// aliases of it, so a caller matching on outcomes names the variants through this — a `use` path
/// resolves through modules, and an alias is not one.
pub(crate) use prebuilt::Upgrade as PrebuiltUpgrade;
#[cfg(test)]
pub(crate) use projectstore::PROJECT_MARKER;
pub(crate) use projectstore::{reflink_verdict, supports_reflink};
pub(crate) use proxy::{
    builtin_allow_rules, ip_refusal, names_exact_host, union_with_builtin, AddrRefusal,
};
pub(crate) use search::run as search;
pub(crate) use smoke::run as smoke;
pub(crate) use tarball::{
    pinned_hashes as tarball_pinned_hashes, upgrade_project as upgrade_tarball,
    withheld as withheld_tarball_packages, TarballUpgrade,
};
