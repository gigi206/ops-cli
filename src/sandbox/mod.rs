//! The sandbox core: a declarative [`spec::SandboxSpec`] and the pure function
//! that turns it into a bubblewrap argv.
//!
//! Security keystone. The Spec is the single description of everything the
//! sandbox exposes; [`argv::to_argv`] adds no exposure of its own and is a pure
//! function of the Spec. So whatever reaches bubblewrap was declared in one
//! place — a security review has a single surface to audit.

mod argv;
mod binds;
mod cgroup;
pub(crate) mod egress;
mod fhs;
mod flake;
mod fonts;
mod launch;
mod mise;
mod miseplugin;
mod nixhub;
mod packages;
mod projectstore;
mod proxy;
mod resolver;
mod search;
mod seccomp;
mod smoke;
mod spec;

pub(crate) use cgroup::{probe as resource_limits, LimitReport};
pub(crate) use flake::{
    upgrade as upgrade_flake, withheld as withheld_flake_packages, FlakeUpgrade,
};
pub(crate) use launch::{app, effective_lock_target, run, run_mise, shell, upgrade_mise_packages};
pub(crate) use nixhub::{current_system, parse_nix_tools, upgrade_tools, ToolUpgrade};
pub(crate) use proxy::nix_cache_hosts;
pub(crate) use search::run as search;
pub(crate) use smoke::run as smoke;
