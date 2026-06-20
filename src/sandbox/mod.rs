//! The sandbox core: a declarative [`spec::SandboxSpec`] and the pure function
//! that turns it into a bubblewrap argv.
//!
//! Security keystone. The Spec is the single description of everything the
//! sandbox exposes; [`argv::to_argv`] adds no exposure of its own and is a pure
//! function of the Spec. So whatever reaches bubblewrap was declared in one
//! place — a security review has a single surface to audit.

mod argv;
mod binds;
pub(crate) mod egress;
mod fhs;
mod launch;
mod mise;
mod miseplugin;
mod nixhub;
mod packages;
mod projectstore;
mod proxy;
mod resolver;
mod smoke;
mod spec;

pub(crate) use launch::{effective_lock_target, run, run_mise, shell};
pub(crate) use nixhub::parse_nix_tools;
pub(crate) use proxy::nix_cache_hosts;
pub(crate) use smoke::run as smoke;
