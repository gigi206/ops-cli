//! Provisioning a program a resolver plugin needs, when the host does not already have one.
//!
//! A manifest names the *tools* its resolver runs and sbx finds each on its own `PATH`, which is
//! what makes a published plugin portable across package managers. This module is the answer for
//! the machine where one of those tools is simply not installed: a `[plugin.<name>] programs` entry
//! names a nixpkgs attribute, sbx builds it into its own store, and a launch binds that instead.
//!
//! **`PATH` always wins.** This is a fallback, never a redirection: a user who has the tool gets
//! the tool they have, and nothing here can point a plugin at a different binary.
//!
//! ## Why the build happens at install time
//!
//! A plugin's program is **project-independent**: the plugin is installed once and any project's
//! secret may route through it. Provisioning it during a launch would therefore run a project-scoped
//! path to produce a project-independent artifact, and re-ask the question on every launch of every
//! project; provisioning it lazily inside the resolver would stall the first secret of a launch on a
//! nix build. `sbx plugins install` is where a user adds a plugin deliberately and where a build is
//! expected, so that is where it happens. A launch only ever *reads* the out-link, which costs one
//! `readlink`.
//!
//! The consequence is that configuring `programs` **after** installing needs a reinstall, not a new
//! launch — and not a bare re-run of the install either, which is refused over a name already
//! taken. The sequence is `sbx plugins rm <name>` and then installing the plugin again, which is
//! what the fail-closed error a launch raises for a missing program names, and what the
//! `sbx plugins info` line for a configured-but-unbuilt program names too.
//!
//! ## The store the paths come from
//!
//! A provisioned path is *logical* (`/nix/store/<hash>-<name>`) and its content lives at the
//! *physical* path under sbx's own store root. The two must not be confused: the logical path is
//! what a wrapper script's interpreter line names, and the physical path is where the bytes are.
//! [`crate::sandbox::resolver`] binds `src = physical, dest = logical` for exactly this reason, and
//! the closure of such a path can only be queried with `--store` (the host's nix database does not
//! know it).

use crate::store::{self, Layout};
use std::path::{Path, PathBuf};

/// The output that must contain a provisioned program, matching what `[packages]` selects.
const BIN: &str = "bin";

/// Where a plugin's provisioned programs are rooted against garbage collection.
///
/// Its own family beside `base`/`mise`/`gui`/`projects`, keyed by plugin directory name, because a
/// plugin's program belongs to the plugin and not to any project: filing it under a project would
/// tie its lifetime to a tree that can be removed while the plugin stays installed.
pub(crate) fn gcroot_dir(layout: &Layout, plugin: &str) -> PathBuf {
    layout
        .data_dir()
        .join("gcroots")
        .join("plugins")
        .join(plugin)
}

/// The *logical* path of a program previously provisioned for `plugin`, or `None`.
///
/// Reads the out-link and appends the program's `bin/` entry, then confirms the file is really
/// there by checking the **physical** path, since that is where the content lives. A dangling or
/// emptied out-link therefore reads as "not provisioned" rather than yielding a path that would
/// fail later at `execve`.
pub(crate) fn provisioned(layout: &Layout, plugin: &str, program: &str) -> Option<PathBuf> {
    let link = gcroot_dir(layout, plugin).join(program);
    let root = std::fs::read_link(&link).ok()?;
    let logical = root.join(BIN).join(program);
    store::physical_path(layout, &logical)
        .is_file()
        .then_some(logical)
}

/// Build every program `cfg` names for `plugin` that the host does not already provide, returning
/// what was built so the caller can report it.
///
/// `PATH` is consulted first for each one: a tool the user already has is left alone, and its
/// configured attribute is reported as unused rather than built into a second copy nobody will run.
///
/// A build failure is returned, never swallowed. The entry exists because the plugin cannot work
/// without that program, so a silent skip would only move the failure to the first secret.
pub(crate) fn provision(
    layout: &Layout,
    nix: &Path,
    nixpkgs: &str,
    plugin: &str,
    cfg: &[(String, String)],
) -> Result<Vec<Provisioned>, String> {
    let mut out = Vec::with_capacity(cfg.len());
    for (program, attr) in cfg {
        if let Some(path) = crate::sandbox::resolver::locate_program(program) {
            out.push(Provisioned::OnPath { path });
            continue;
        }
        let gcroot = gcroot_dir(layout, plugin).join(program);
        let logical =
            store::provision_unfree(nix, layout, &gcroot, nixpkgs, attr, BIN).map_err(|e| {
                format!("cannot provision `{program}` (nix:{attr}) for `{plugin}`: {e}")
            })?;
        let bin = logical.join(BIN).join(program);
        if !store::physical_path(layout, &bin).is_file() {
            // The attribute built, but its `bin/` holds no file by that name — a wrong attribute
            // for the tool, which is worth saying now rather than as a bare `execvp` failure at the
            // first secret.
            return Err(format!(
                "`nix:{attr}` built for `{plugin}`, but it provides no `{BIN}/{program}` — check \
                 the attribute against `sbx search {program}`"
            ));
        }
        out.push(Provisioned::Built {
            program: program.clone(),
            path: bin,
        });
    }
    Ok(out)
}

/// What became of one configured program.
pub(crate) enum Provisioned {
    /// The host already had it, so nothing was built and the configured attribute is inert.
    OnPath { path: PathBuf },
    /// It was built into sbx's store; the path is *logical*.
    Built { program: String, path: PathBuf },
}

/// Remove a plugin's provisioned out-links, so the store paths they held stop being live.
///
/// Called when a plugin is removed. An out-link that outlives what justified it keeps a closure
/// alive forever and is invisible in every listing: the same shape as a project gcroot left behind
/// by a removed tree. Best-effort, since a plugin must still be removable when its data directory
/// is in an odd state.
pub(crate) fn forget(layout: &Layout, plugin: &str) {
    let _ = std::fs::remove_dir_all(gcroot_dir(layout, plugin));
}
