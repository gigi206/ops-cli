//! Read-only introspection of what an app home or project tree has **realized on disk** — the
//! backing data for `sbx app show` / `sbx projects show`. This is the counterpart to the config
//! layer: config says what is *declared*, this reads what is *actually present* (the mise installs,
//! the per-tree package locks), so a user can see declared-vs-installed. Pure host-side filesystem
//! reads — no sandbox, no nix, no network.

use std::path::{Path, PathBuf};

/// A mise tool present under a home's `installs/` dir, by its on-disk (munged) directory name and
/// the version directories realized for it.
pub(crate) struct InstalledTool {
    /// The directory name mise gives the tool under `installs/` — the *munged* form of its declared
    /// token (see [`mise_munge`]), e.g. `aqua-example-demo-tool`. Sanitised on the way in, because
    /// the cage writes this directory itself (see [`mise_installed_in`]).
    ///
    /// For display and for matching only. Sanitising is not reversible — a name carrying a byte the
    /// filter drops or replaces no longer names the directory it came from — so anything that has
    /// to reach the filesystem uses [`InstalledTool::dir_name`] instead.
    pub(crate) name: String,
    /// The directory name exactly as it is on disk, for the one use the sanitised form cannot
    /// serve: naming the path again. `sbx app prune` joins this to delete an undeclared tool, and a
    /// tool whose real name is not sanitise-stable would otherwise be looked for at a path that
    /// does not exist — never removed, and (before the report was corrected) named as pruned
    /// anyway. Never rendered: a terminal only ever sees `name` or `token`.
    pub(crate) dir_name: std::ffi::OsString,
    /// The real backend token mise recorded for this tool (`pipx:demo-agent`, `aqua:example/demo-tool`,
    /// …), read from its `.mise.backend.toml`. `None` when that metadata is absent. Preferred over
    /// the munged directory name for display *and* for an exact match against a declared token, and
    /// sanitised for the same reason the name is.
    pub(crate) token: Option<String>,
    /// The version subdirectories realized for the tool, sanitised like the name. Includes mise's
    /// `latest` alias directory alongside the concrete version it points at; [`concrete_versions`]
    /// filters the alias out.
    pub(crate) versions: Vec<String>,
}

impl InstalledTool {
    /// The tool's real backend token when known, else its munged directory name — for display.
    pub(crate) fn label(&self) -> &str {
        self.token.as_deref().unwrap_or(&self.name)
    }

    /// Whether this installed tool is the one a declared mise `locator` refers to. Prefers an exact
    /// match on the recorded backend token; falls back to comparing the munged directory name when
    /// the token metadata is absent.
    pub(crate) fn is(&self, locator: &str) -> bool {
        self.token.as_deref() == Some(locator) || self.name == mise_munge(locator)
    }
}

/// Map a declared mise locator to the directory name mise gives it under `installs/`: `:` and `/`
/// become `-` and `@` is dropped, so `aqua:example/demo-tool` → `aqua-example-demo-tool`,
/// `npm:@example/other-tool` → `npm-example-other-tool`, and a bare registry token like `bare-tool`
/// is unchanged. Best-effort — it mirrors mise's observed naming so a declared package can be paired
/// with its realized install; a miss only drops the pairing, never asserts a wrong state, because
/// the installed list is read straight from disk regardless of this mapping.
pub(crate) fn mise_munge(locator: &str) -> String {
    locator
        .chars()
        .filter(|c| *c != '@')
        .map(|c| if c == ':' || c == '/' { '-' } else { c })
        .collect()
}

/// The concrete version(s) of an installed tool for display: the version directories minus mise's
/// `latest` alias, unless `latest` is the only entry (then it is kept, so a tool pinned to `latest`
/// with no resolved concrete dir still shows something honest rather than nothing).
pub(crate) fn concrete_versions(tool: &InstalledTool) -> Vec<String> {
    let concrete: Vec<String> = tool
        .versions
        .iter()
        .filter(|v| v.as_str() != "latest")
        .cloned()
        .collect();
    if concrete.is_empty() {
        tool.versions.clone()
    } else {
        concrete
    }
}

/// The mise tools realized under a home — reads `<home>/.local/share/mise/installs/<tool>/<ver>/`.
/// A thin wrapper over [`mise_installed_in`] for the home layout (mise's data dir is `.local/share/mise`
/// under the home); a global app's per-project pool reads its `installs/` directly instead.
pub(crate) fn mise_installed(home: &Path) -> Vec<InstalledTool> {
    mise_installed_in(&home.join(".local/share/mise/installs"))
}

/// The mise tools realized directly under a mise `installs/` dir — `<installs>/<tool>/<ver>/`,
/// skipping mise's own `.mise-installs.toml` metadata file (filtered out by the directory check) and
/// any non-directory entry. Sorted by name; empty when the dir carries no mise data. Read-only. Used
/// for a home's mise dir (via [`mise_installed`]) and for a global app's per-project pool, whose
/// `installs/` sits directly under the pool dir (the pool *is* mise's data dir).
///
/// Every name it returns is run through [`crate::sandbox::sanitize`] first. The `installs/` tree is
/// inside the cage's own writable home, so a hostile payload chooses these directory names — and
/// `sbx app show` prints them to a terminal. Filtering at this entry point (rather than in the
/// renderer) is what keeps a later renderer, `--json` included, from getting the raw form.
pub(crate) fn mise_installed_in(installs: &Path) -> Vec<InstalledTool> {
    let mut tools = Vec::new();
    let Ok(entries) = std::fs::read_dir(installs) else {
        return tools;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        // These names come off the cage's own writable home: the payload can `mkdir` whatever it
        // likes under `installs/`, so a directory name is attacker-chosen text, not mise's. Sanitise
        // it here, at the one place it enters the model, rather than at each renderer — the human
        // table and `--json` and anything added later then all get the filtered form, and a name
        // carrying `\r` or an ANSI escape cannot forge a line of `sbx app show`.
        let dir_name = entry.file_name();
        let name = crate::sandbox::sanitize(&dir_name.to_string_lossy());
        let token = backend_token(&entry.path());
        let mut versions: Vec<String> = match std::fs::read_dir(entry.path()) {
            Ok(vs) => vs
                .flatten()
                .filter(|v| v.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|v| crate::sandbox::sanitize(&v.file_name().to_string_lossy()))
                .collect(),
            Err(_) => Vec::new(),
        };
        versions.sort();
        tools.push(InstalledTool {
            name,
            dir_name,
            token,
            versions,
        });
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

/// The real backend token mise recorded for the tool installed at `tool_dir` — the `short` (or
/// `full`) key of its `.mise.backend.toml` (`short = "pipx:demo-agent"`). This recovers the
/// provider the munged directory name hides. Parsed line-wise (the file is a tiny flat table), so no
/// TOML dependency. `None` when the metadata is absent or unparsable.
fn backend_token(tool_dir: &Path) -> Option<String> {
    let body = read_cage_metadata(&tool_dir.join(".mise.backend.toml"))?;
    let value = |key: &str| {
        body.lines().find_map(|line| {
            let rest = line.trim().strip_prefix(key)?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            let quoted = rest.strip_prefix('"')?.strip_suffix('"')?;
            // The file sits in the cage's writable home, so its value is payload-chosen; it is
            // displayed in place of the directory name, so it gets the same filter (see
            // [`mise_installed_in`]).
            (!quoted.is_empty()).then(|| crate::sandbox::sanitize(quoted))
        })
    };
    value("short").or_else(|| value("full"))
}

/// How much of a cage-written metadata file is read. A `.mise.backend.toml` is a flat table of two
/// or three short lines, so a few KiB is orders of magnitude more than one ever needs — and a
/// ceiling is required, because the size is the payload's to choose.
const CAGE_METADATA_CAP: u64 = 8 * 1024;

/// Read a small metadata file that lives inside the cage's writable home.
///
/// The payload owns every component of these paths, so the **open** is as much its choice as the
/// content is, and it is the half a content filter does not cover. `read_to_string` on such a path
/// follows a symlink the payload planted and blocks in `open(2)` on a FIFO it created: a `/dev/zero`
/// link is read until the host is out of memory (NUL bytes are valid UTF-8, so nothing stops the
/// buffer growing), and a reader-less FIFO wedges the caller — which for `sbx gc --prune`, a
/// scripted `sbx app show`, or `taskpool::bins_for` on the launch path means a host command that
/// never returns and nobody there to interrupt it. A symlink is also a read primitive in its own
/// right: it aims the reader at any file the invoking user can read, and what that file says is then
/// displayed as the tool's backend.
///
/// So: `O_NOFOLLOW` refuses a symlink at the final component outright, `O_NONBLOCK` keeps a FIFO's
/// open from blocking, the file type is checked on the **descriptor** — a check on the path would
/// answer about whatever was there at that instant, and the payload can swap the entry before the
/// open — and the read stops at [`CAGE_METADATA_CAP`]. `None` for anything that is not a readable
/// regular file, which reads the same as absent metadata.
///
/// Every future reader of a path under the cage's writable home belongs on this function rather
/// than on `std::fs::read_to_string`.
fn read_cage_metadata(path: &Path) -> Option<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut body = String::new();
    file.take(CAGE_METADATA_CAP)
        .read_to_string(&mut body)
        .ok()?;
    Some(body)
}

/// One isolated home an app has on disk. An app's mise-installed tools are per-home, so `sbx app
/// show` reads every home (a `home_scope = "global"` app has one; a `"project"` app has one per
/// project it launched in).
pub(crate) struct AppHome {
    /// The home directory itself (`.../home`), the parent of the mise data dir.
    pub(crate) dir: PathBuf,
    /// The global home `<data>/apps/<name>/home` (shared across projects), versus a per-project home.
    pub(crate) global: bool,
    /// The project tree id for a per-project home; `None` for the global one.
    pub(crate) project_id: Option<String>,
}

/// The isolated home directories app `name` has on disk: the global home `<data>/apps/<name>/home`
/// and each per-project home `<data>/projects/<id>/apps/<name>/home`. Only existing directories are
/// returned, global first then per-project sorted by id. Read-only; a missing tree is simply no
/// homes.
pub(crate) fn app_home_dirs(data_dir: &Path, name: &str) -> Vec<AppHome> {
    let mut homes = Vec::new();
    let global = data_dir.join("apps").join(name).join("home");
    if global.is_dir() {
        homes.push(AppHome {
            dir: global,
            global: true,
            project_id: None,
        });
    }
    if let Ok(projects) = std::fs::read_dir(data_dir.join("projects")) {
        let mut per_project: Vec<AppHome> = projects
            .flatten()
            .filter_map(|p| {
                if !p.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    return None;
                }
                let id = p.file_name().to_string_lossy().into_owned();
                let dir = p.path().join("apps").join(name).join("home");
                dir.is_dir().then_some(AppHome {
                    dir,
                    global: false,
                    project_id: Some(id),
                })
            })
            .collect();
        per_project.sort_by(|a, b| a.project_id.cmp(&b.project_id));
        homes.extend(per_project);
    }
    homes
}

/// A global app's per-project mise pool on disk — `<data>/projects/<id>/apps/<name>/mise`, where a
/// global app's `nix:`-via-mise self-equips and project `.mise.toml` tools install, kept aligned with
/// each project's `/nix` store. The pool dir *is* mise's data dir, so its tools live directly under
/// `<dir>/installs/` (unlike a home, whose mise data is under `.local/share/mise`). Only a
/// `home_scope = "global"` app has these — a per-project app roots its mise data under its per-project
/// home instead, and so has none.
pub(crate) struct AppMisePool {
    /// The project tree id the pool belongs to.
    pub(crate) project_id: String,
    /// The pool directory `<data>/projects/<id>/apps/<name>/mise` — mise's data dir, `installs/` under it.
    pub(crate) dir: PathBuf,
}

/// The per-project mise pools app `name` has on disk — one per project tree carrying a
/// `projects/<id>/apps/<name>/mise` dir (a global app that self-equipped in that project). Sorted by
/// project id. Read-only; a project without the dir contributes nothing.
pub(crate) fn app_per_project_mise_pools(data_dir: &Path, name: &str) -> Vec<AppMisePool> {
    let mut pools = Vec::new();
    let Ok(projects) = std::fs::read_dir(data_dir.join("projects")) else {
        return pools;
    };
    for p in projects.flatten() {
        if !p.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let dir = p.path().join("apps").join(name).join("mise");
        if dir.is_dir() {
            pools.push(AppMisePool {
                project_id: p.file_name().to_string_lossy().into_owned(),
                dir,
            });
        }
    }
    pools.sort_by(|a, b| a.project_id.cmp(&b.project_id));
    pools
}

/// Which project trees pin `locator` in `lockfile` — the realized-where signal for a `deb:`,
/// `appimage:`, or `flake:` package, whose build output lives in the **per-project** store (not the
/// app home). Scans every `<data>/projects/<id>/<lockfile>` for a line whose first tab-column is
/// `locator`, returning `(tree_id, short_pin)` per hit (the second column — a content hash or flake
/// revision — shortened). `lockfile` is `deb-packages.lock` / `appimage-packages.lock` /
/// `flake-packages.lock`, which share the `key\tpin[\t…]` line format keyed by the declared locator.
/// Sorted by tree id. Read-only.
pub(crate) fn prebuilt_pin_trees(
    data_dir: &Path,
    lockfile: &str,
    locator: &str,
) -> Vec<(String, String)> {
    let mut hits = Vec::new();
    let Ok(projects) = std::fs::read_dir(data_dir.join("projects")) else {
        return hits;
    };
    for project in projects.flatten() {
        if !project.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let id = project.file_name().to_string_lossy().into_owned();
        if let Some(short) = prebuilt_pin_in(&project.path(), lockfile, locator) {
            hits.push((id, short));
        }
    }
    hits.sort();
    hits
}

/// The pin `locator` has in one project tree's `lockfile`, or `None` if the tree does not pin it.
/// Reads `<tree_dir>/<lockfile>` for a line whose first tab-column is `locator` and returns the
/// second column (hash or flake revision) shortened for display. Read-only.
pub(crate) fn prebuilt_pin_in(tree_dir: &Path, lockfile: &str, locator: &str) -> Option<String> {
    let body = std::fs::read_to_string(tree_dir.join(lockfile)).ok()?;
    for line in body.lines() {
        let mut cols = line.split('\t');
        if cols.next() == Some(locator) {
            let pin = cols.next().unwrap_or("");
            return Some(
                pin.strip_prefix("sha256-")
                    .unwrap_or(pin)
                    .chars()
                    .take(8)
                    .collect(),
            );
        }
    }
    None
}

/// The lock filename a prebuilt backend records its pins in, derived from [`super::prebuilt::Kind`]
/// so this view and the write side cannot name different files. `None` for a backend that is not a
/// per-tree prebuilt: their build output lands in the **per-project
/// store**, so a per-tree lock (and the store gcroot) is their realized signal. `flake:` builds into
/// the cage **home** instead (see [`flake_built`]); mise is per-home; nix has no lock of this shape.
pub(crate) fn prebuilt_lockfile(backend: &crate::config::Backend) -> Option<String> {
    use super::prebuilt::lock_file;
    use crate::config::Backend;
    // Exhaustive, with no catch-all arm: every backend that implements
    // [`super::prebuilt::Kind`] writes a lock this view has to be able to name, and a `_` arm
    // answers `None` for a new one without anything failing to compile. `binary:` was that case —
    // it has had a `Kind` and a `binary-packages.lock` all along, and reached the caller's
    // per-project fallback instead of its own pin.
    match backend {
        Backend::Deb(_) | Backend::DebResolve { .. } => Some(lock_file(&super::deb::Deb)),
        Backend::AppImage(_) | Backend::AppImageResolve { .. } => {
            Some(lock_file(&super::appimage::AppImage))
        }
        Backend::Tarball(_) | Backend::TarballResolve { .. } => {
            Some(lock_file(&super::tarball::Tarball))
        }
        Backend::Binary(_) | Backend::BinaryResolve { .. } => {
            Some(lock_file(&super::binary::Binary))
        }
        // Not per-tree prebuilts: their build output lands in the per-project store, `flake:`
        // inline builds into the cage home, mise is per-home, and nix has no lock of this shape.
        Backend::Nix(_) | Backend::Mise(_) | Backend::Flake(_) | Backend::FlakeInline { .. } => {
            None
        }
    }
}

/// The key a prebuilt package's pin is stored under in its per-tree lock: the declared locator for a
/// direct form (its URL / `github:` / `apt:` locator), or `resolve:<name>` for a `*:resolve` package
/// — whose pin is keyed by name, not by the one-line `resolve` sentinel [`Backend::locator`](crate::config::Backend::locator) returns.
/// So a built `deb:resolve` / `appimage:resolve` / `tarball:resolve` / `binary:resolve` package is
/// found in its lock, not reported as un-built.
///
/// Through [`super::prebuilt::resolve_key`], which is what the write side spells the key with, so
/// the two cannot drift. Exhaustive for the same reason
/// [`prebuilt_lockfile`] is: a `*:resolve` variant left out of the list does not fail to compile, it
/// silently looks its pin up under the `resolve` sentinel and finds nothing — which is what
/// `binary:resolve` did.
pub(crate) fn prebuilt_pin_key(backend: &crate::config::Backend, name: &str) -> String {
    use crate::config::Backend;
    match backend {
        Backend::TarballResolve { .. }
        | Backend::DebResolve { .. }
        | Backend::AppImageResolve { .. }
        | Backend::BinaryResolve { .. } => super::prebuilt::resolve_key(name),
        direct @ (Backend::Nix(_)
        | Backend::Mise(_)
        | Backend::Flake(_)
        | Backend::FlakeInline { .. }
        | Backend::Deb(_)
        | Backend::AppImage(_)
        | Backend::Tarball(_)
        | Backend::Binary(_)) => direct.locator().to_string(),
    }
}

/// The out-link directory a home built before the `ops`→`sbx` rename still carries. A launch now
/// writes the out-link to [`binds::FLAKE_ROOTS_REL`](super::binds::FLAKE_ROOTS_REL) (`.local/state/sbx/flake`), but a home last built
/// under the old name keeps it here until its next relaunch rebuilds into the current dir — so the
/// read side checks both, current first, to report such a home accurately through the transition.
const FLAKE_ROOTS_REL_LEGACY: &str = ".local/state/ops/flake";

/// Whether an inline `[flakes.<name>]` package named `name` (its free label) has a warm build
/// out-link in `home` — `<home>/<FLAKE_ROOTS_REL>/<name>` (the stable PATH entry) or
/// `<name>-<hash>` (one build, keyed by the flake source's content hash), where the
/// out-link's target store path lives in the per-project store the launch bound at `/nix`. The
/// out-link *symlink* is the realized signal a launch leaves in the home (a *floating* flake has an
/// out-link but no lock entry at all, which a lock scan would miss). The current relative path is
/// [`binds::FLAKE_ROOTS_REL`](super::binds::FLAKE_ROOTS_REL) — the same constant the launch writes to, so the read side cannot drift
/// from the write side — with the pre-rename [`FLAKE_ROOTS_REL_LEGACY`] as a fallback for a home built
/// before the rename. Returns the out-link target's store-path label (e.g. `demo-agent-0.18.2`, the
/// basename minus the store hash) for display, or `None` when no out-link exists. Read-only.
pub(crate) fn flake_built(home: &Path, name: &str) -> Option<String> {
    [super::binds::FLAKE_ROOTS_REL, FLAKE_ROOTS_REL_LEGACY]
        .into_iter()
        .find_map(|rel| flake_built_in(&home.join(rel), name))
}

/// The realized label of a `flake:` package's out-link within one out-link directory `dir`, or `None`
/// when `dir` has no matching out-link. Factored out so [`flake_built`] can try the current and legacy
/// directories in turn.
///
/// The label is run through [`crate::sandbox::sanitize`] for the same reason every name in
/// [`mise_installed_in`] is: the out-link directory sits in the cage's own writable home and the
/// link is written by the in-cage `nix build`, so its target — and therefore this label — is text
/// the payload chooses. A symlink target may hold anything but `/` and NUL, so it can carry the
/// escape sequences that let one line of `sbx app show` erase the lines above it and assert a
/// package is built, trusted, or at a version it is not.
fn flake_built_in(dir: &Path, name: &str) -> Option<String> {
    let prefix = format!("{name}-");
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let fname = entry.file_name().to_string_lossy().into_owned();
        if fname != name && !fname.starts_with(&prefix) {
            continue;
        }
        // The out-link target's basename, minus the store hash, is a friendly `<pname>-<version>`.
        let detail = std::fs::read_link(entry.path())
            .ok()
            .and_then(|t| t.file_name().map(|f| f.to_string_lossy().into_owned()))
            .and_then(|base| base.split_once('-').map(|(_, rest)| rest.to_string()))
            .map(|detail| crate::sandbox::sanitize(&detail))
            .unwrap_or_else(|| "built".to_string());
        return Some(detail);
    }
    None
}

/// The nix store roots a project tree has realized — the out-link names under
/// `<data>/gcroots/projects/<id>/`. This is the project's **shared** store content: the roots accrue
/// from the project baseline *and* every app launched in it (they share one per-project store). A
/// `deb-<name>` / `appimage-<name>` name is a prebuilt build output; every other name is a `nix:`
/// package (or a hole provision). Sorted.
///
/// A root is a **leaf** out-link, so a sub-*directory* is not one:
/// [`nixhub::provision`](crate::sandbox::nixhub::provision) roots the tree's `nix:` mise tools one
/// level down, in the `nix-tools/` directory it keeps apart from the native `[packages]` roots so the
/// two tool sources cannot collide on a shared name — and that directory entry was read as a root of
/// its own, so `sbx projects show` listed a `nix:` package literally named `nix-tools` that no project
/// declares. The `.expr` derivation-source stamp beside a prebuilt root is a plain file and is skipped
/// by name, as before.
///
/// Read-only; an absent gcroot dir is simply no roots.
pub(crate) fn gcroot_names(data_dir: &Path, tree_id: &str) -> Vec<String> {
    let dir = data_dir.join("gcroots").join("projects").join(tree_id);
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| !e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".expr"))
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

/// Which project trees have realized the `nix:` package named `name` — its per-tree "installed"
/// signal, the analogue of [`prebuilt_pin_trees`] for the prebuilt backends. A `nix:` package builds
/// host-side into the shared store and is seeded into each project's own store, gcrooted per tree at
/// `<data>/gcroots/projects/<id>/<name>` (the launch keys the gcroot on the package's declared name).
/// Scans every tree for that gcroot and returns the matching tree ids, sorted. Read-only; an absent
/// gcroots dir is simply no trees.
pub(crate) fn nix_built_trees(data_dir: &Path, name: &str) -> Vec<String> {
    let Ok(trees) = std::fs::read_dir(data_dir.join("gcroots").join("projects")) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = trees
        .flatten()
        .filter_map(|t| {
            if !t.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                return None;
            }
            let id = t.file_name().to_string_lossy().into_owned();
            gcroot_names(data_dir, &id)
                .iter()
                .any(|n| n == name)
                .then_some(id)
        })
        .collect();
    ids.sort();
    ids
}

/// The `nix:` mise tools a project tree has resolved — `<tree_dir>/tools.lock`, mapping each
/// package to the concrete version nixhub locked it to. The lock's line format is
/// `pkg\tversion\tsystem\tcommit\tattr\tresolved-version`, so the package is column 0 and the
/// resolved version column 5. Read-only; an absent lock is empty.
pub(crate) fn nix_tools_locked(tree_dir: &Path) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(body) = std::fs::read_to_string(tree_dir.join("tools.lock")) else {
        return out;
    };
    for line in body.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 6 && !cols[0].is_empty() {
            out.insert(cols[0].to_string(), cols[5].to_string());
        }
    }
    out
}

/// The nixpkgs channel/revision a project tree resolves against: its own `<tree_dir>/nixpkgs.lock`
/// when it carries a pin (`per_project = true`), else the global `<data>/nixpkgs.lock`. Returns
/// `(source, short_rev, per_project)`. A lock is `<source>\n<rev>` (or a legacy bare `<rev>` on the
/// default channel). `None` when neither lock exists. Read-only.
pub(crate) fn nixpkgs_pin(tree_dir: &Path, data_dir: &Path) -> Option<(String, String, bool)> {
    let read = |p: &Path| -> Option<(String, String)> {
        let body = std::fs::read_to_string(p).ok()?;
        let mut lines = body.lines();
        let first = lines.next()?.trim().to_string();
        match lines.next() {
            Some(second) => Some((first, second.trim().to_string())),
            None => Some(("nixos-unstable".to_string(), first)),
        }
    };
    let short = |rev: String| rev.chars().take(8).collect::<String>();
    if let Some((source, rev)) = read(&tree_dir.join("nixpkgs.lock")) {
        return Some((source, short(rev), true));
    }
    read(&data_dir.join("nixpkgs.lock")).map(|(source, rev)| (source, short(rev), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn munge_mirrors_mises_backend_naming() {
        assert_eq!(
            mise_munge("aqua:example/demo-tool"),
            "aqua-example-demo-tool"
        );
        assert_eq!(
            mise_munge("npm:@example/other-tool"),
            "npm-example-other-tool"
        );
        assert_eq!(
            mise_munge("aqua:example/pinned-tool"),
            "aqua-example-pinned-tool"
        );
        // A bare registry token is unchanged.
        assert_eq!(mise_munge("bare-tool"), "bare-tool");
    }

    #[test]
    fn concrete_versions_drops_the_latest_alias_but_keeps_it_when_alone() {
        let with_concrete = InstalledTool {
            name: "t".into(),
            dir_name: "t".into(),
            token: None,
            versions: vec!["latest".into(), "2.1.209".into()],
        };
        assert_eq!(concrete_versions(&with_concrete), vec!["2.1.209"]);
        let alias_only = InstalledTool {
            name: "t".into(),
            dir_name: "t".into(),
            token: None,
            versions: vec!["latest".into()],
        };
        assert_eq!(concrete_versions(&alias_only), vec!["latest"]);
    }

    #[test]
    fn mise_installed_reads_tools_and_versions_skipping_metadata() {
        let dir = crate::testutil::TmpDir::new();
        let tmp = dir.path();
        let installs = tmp.join(".local/share/mise/installs");
        std::fs::create_dir_all(installs.join("aqua-example-demo-tool/2.1.209")).unwrap();
        std::fs::create_dir_all(installs.join("aqua-example-demo-tool/latest")).unwrap();
        std::fs::create_dir_all(installs.join("bare-tool/1.17.9")).unwrap();
        // mise's own metadata file must be ignored (it is a file, not a tool dir).
        std::fs::write(installs.join(".mise-installs.toml"), b"x").unwrap();
        // The backend metadata recovers the real token behind the munged directory name.
        std::fs::write(
            installs.join("aqua-example-demo-tool/.mise.backend.toml"),
            "short = \"aqua:example/demo-tool\"\nfull = \"aqua:example/demo-tool\"\n",
        )
        .unwrap();

        let tools = mise_installed(tmp);
        assert_eq!(tools.len(), 2, "two tools, metadata skipped");
        assert_eq!(tools[0].name, "aqua-example-demo-tool");
        assert_eq!(tools[0].token.as_deref(), Some("aqua:example/demo-tool"));
        assert_eq!(tools[0].label(), "aqua:example/demo-tool");
        assert!(tools[0].is("aqua:example/demo-tool"), "exact token match");
        assert_eq!(tools[0].versions, vec!["2.1.209", "latest"]);
        assert_eq!(concrete_versions(&tools[0]), vec!["2.1.209"]);
        // No metadata → token None, label falls back to the munged dir, match via munge still works.
        assert_eq!(tools[1].name, "bare-tool");
        assert_eq!(tools[1].token, None);
        assert_eq!(tools[1].label(), "bare-tool");
        assert!(tools[1].is("bare-tool"));
    }

    #[test]
    fn mise_installed_filters_control_characters_the_cage_chose() {
        // `installs/` is inside the cage's own writable home, so a hostile payload picks these
        // directory names and the `.mise.backend.toml` value beside them. Every one of the three
        // reaches a terminal through `sbx app show`, so a `\r` or an ANSI escape in any of them
        // would let the payload forge a line of the host's own output.
        let dir = crate::testutil::TmpDir::new();
        let tmp = dir.path();
        let installs = tmp.join(".local/share/mise/installs");
        let tool = "evil\u{1b}[2Ktool";
        std::fs::create_dir_all(installs.join(tool).join("1.0\rfake")).unwrap();
        std::fs::write(
            installs.join(tool).join(".mise.backend.toml"),
            "short = \"npm:evil\u{1b}[31mpkg\"\n",
        )
        .unwrap();

        let tools = mise_installed(tmp);
        assert_eq!(tools.len(), 1);
        assert_eq!(
            tools[0].name, "evil [2Ktool",
            "the directory name must arrive with its control bytes replaced"
        );
        assert_eq!(
            tools[0].versions,
            vec!["1.0 fake".to_string()],
            "a version directory name is payload-chosen too"
        );
        assert_eq!(
            tools[0].token.as_deref(),
            Some("npm:evil [31mpkg"),
            "the backend token is read out of a cage-writable file"
        );
        assert_eq!(tools[0].label(), "npm:evil [31mpkg");
        // The filter must not eat ordinary names: a plain install still reads back verbatim.
        std::fs::create_dir_all(installs.join("bare-tool/1.17.9")).unwrap();
        let tools = mise_installed(tmp);
        let bare = tools.iter().find(|t| t.name == "bare-tool").expect("kept");
        assert_eq!(bare.versions, vec!["1.17.9".to_string()]);
        assert!(
            bare.is("bare-tool"),
            "pairing with a declared token survives"
        );
    }

    /// The cage's metadata file is opened defensively, not just filtered afterwards.
    ///
    /// `<home>/.local/share/mise/installs/<tool>/.mise.backend.toml` is a path the payload owns
    /// end to end, and `mise_installed_in` is reached by `sbx app show`, `sbx projects show`,
    /// `sbx gc --prune` and `taskpool::bins_for` on the launch path — three of which nobody is
    /// sitting in front of to interrupt. Sanitising the parsed value defends the *content*; this
    /// pins the *open*, which is the half that decides whether the host command returns at all.
    #[test]
    fn a_cage_chosen_backend_file_is_read_only_when_it_is_a_bounded_regular_file() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = crate::testutil::TmpDir::new();
        let tmp = dir.path();
        let installs = tmp.join(".local/share/mise/installs");

        // A symlink is a read primitive: it aims the reader at any file the invoking user can
        // read, and `sbx app show` then displays what that file said as the tool's backend.
        let bait = tmp.join("elsewhere.toml");
        std::fs::write(&bait, "short = \"npm:read-from-elsewhere\"\n").unwrap();
        std::fs::create_dir_all(installs.join("node")).unwrap();
        std::os::unix::fs::symlink(&bait, installs.join("node/.mise.backend.toml")).unwrap();

        // A FIFO is the variant that never returns: `open(2)` on one with no writer blocks, and an
        // unattended `sbx gc --prune` then hangs with no diagnostic. Reaching the assertion below
        // at all is what this half of the test proves.
        std::fs::create_dir_all(installs.join("python")).unwrap();
        let fifo = installs.join("python/.mise.backend.toml");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `mkfifo` only creates a FIFO at the given path and touches nothing else.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        // A regular file whose real value sits past the ceiling: the payload cannot make the host
        // read (and hold) a file of its own choosing in size.
        std::fs::create_dir_all(installs.join("ruby")).unwrap();
        let padded = format!(
            "pad = \"{}\"\nshort = \"npm:past-the-ceiling\"\n",
            "A".repeat(2 * CAGE_METADATA_CAP as usize)
        );
        std::fs::write(installs.join("ruby/.mise.backend.toml"), padded).unwrap();

        // The honest case, so the guard is not simply refusing everything.
        std::fs::create_dir_all(installs.join("bare-tool")).unwrap();
        std::fs::write(
            installs.join("bare-tool/.mise.backend.toml"),
            "short = \"npm:bare-tool\"\n",
        )
        .unwrap();

        let tools = mise_installed(tmp);
        let token = |name: &str| {
            tools
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("{name} is listed"))
                .token
                .clone()
        };
        assert_eq!(token("node"), None, "a symlinked metadata file is not read");
        assert_eq!(
            token("python"),
            None,
            "a FIFO is neither read nor waited on"
        );
        assert_eq!(
            token("ruby"),
            None,
            "the read stops at the ceiling, so a value buried past it never arrives"
        );
        assert_eq!(
            token("bare-tool").as_deref(),
            Some("npm:bare-tool"),
            "an ordinary metadata file still reads back"
        );
    }

    #[test]
    fn mise_installed_is_empty_without_a_mise_dir() {
        let dir = crate::testutil::TmpDir::new();
        assert!(mise_installed(dir.path()).is_empty());
    }

    #[test]
    fn app_per_project_mise_pools_reads_a_global_apps_pools_directly() {
        // A global app's per-project pool is `projects/<id>/apps/<name>/mise` — the pool dir *is*
        // mise's data dir, so its tools live directly under `<pool>/installs/` (not `.local/share/mise`,
        // the home layout `mise_installed` assumes). Pin that the enumeration finds only projects with a
        // pool and that `mise_installed_in` reads the pool's `installs/` at the right depth.
        let scratch = crate::testutil::TmpDir::new();
        let data = scratch.path();
        // two projects each with a per-project pool holding one self-equipped tool
        for id in ["p1", "p2"] {
            let installs = data.join(format!("projects/{id}/apps/ag/mise/installs"));
            std::fs::create_dir_all(installs.join("nix-jq/1.8.1")).unwrap();
            std::fs::write(
                installs.join("nix-jq/.mise.backend.toml"),
                "short = \"nix:jq\"\n",
            )
            .unwrap();
        }
        // a project where this app has only a home (a per-project app, or no self-equip) — no pool
        std::fs::create_dir_all(data.join("projects/p3/apps/ag/home")).unwrap();

        let pools = app_per_project_mise_pools(data, "ag");
        assert_eq!(
            pools
                .iter()
                .map(|p| p.project_id.as_str())
                .collect::<Vec<_>>(),
            ["p1", "p2"],
            "only projects with a mise pool, sorted by id (p3 has a home, no pool)"
        );
        // the pool's tools read directly from `<pool>/installs`, not `.local/share/mise`
        let tools = mise_installed_in(&pools[0].dir.join("installs"));
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].label(), "nix:jq");
        assert_eq!(concrete_versions(&tools[0]), vec!["1.8.1"]);
    }

    #[test]
    fn prebuilt_pin_trees_finds_the_locator_across_trees() {
        let scratch = crate::testutil::TmpDir::new();
        let data = scratch.path();
        let mk = |id: &str, body: &str| {
            let dir = data.join("projects").join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("deb-packages.lock"), body).unwrap();
        };
        // Two trees pin the URL, one pins something else.
        mk(
            "aaaaaaaaaaaaaaaa",
            "https://example.com/app.deb\tsha256-DEADBEEFcafef00d\n",
        );
        mk(
            "bbbbbbbbbbbbbbbb",
            "https://example.com/app.deb\tsha256-DEADBEEFcafef00d\n",
        );
        mk(
            "cccccccccccccccc",
            "https://other.example/x.deb\tsha256-00\n",
        );

        let hits = prebuilt_pin_trees(data, "deb-packages.lock", "https://example.com/app.deb");
        assert_eq!(hits.len(), 2, "two trees pin it: {hits:?}");
        assert_eq!(hits[0], ("aaaaaaaaaaaaaaaa".into(), "DEADBEEF".into()));
        assert_eq!(hits[1].0, "bbbbbbbbbbbbbbbb");
        // The single-tree lookup the fan-out is built on.
        let one = data.join("projects/aaaaaaaaaaaaaaaa");
        assert_eq!(
            prebuilt_pin_in(&one, "deb-packages.lock", "https://example.com/app.deb"),
            Some("DEADBEEF".to_string())
        );
        assert_eq!(
            prebuilt_pin_in(&one, "deb-packages.lock", "https://nope"),
            None
        );
    }

    #[test]
    fn prebuilt_pin_key_is_the_locator_for_a_direct_form_and_resolve_name_for_a_resolver() {
        use crate::config::Backend;
        // A direct prebuilt looks its pin up by its declared locator (URL / github: / apt:).
        assert_eq!(
            prebuilt_pin_key(&Backend::Deb("https://e/a.deb".into()), "app"),
            "https://e/a.deb"
        );
        assert_eq!(
            prebuilt_pin_key(&Backend::AppImage("github:o/r".into()), "app"),
            "github:o/r"
        );
        // A `*:resolve` package's pin is keyed `resolve:<name>` (not the `resolve` sentinel locator),
        // so a built one is found in its lock instead of reported as un-built.
        for backend in [
            Backend::DebResolve { command: vec![] },
            Backend::AppImageResolve { command: vec![] },
            Backend::TarballResolve { command: vec![] },
            Backend::BinaryResolve { command: vec![] },
        ] {
            assert_eq!(prebuilt_pin_key(&backend, "cursor"), "resolve:cursor");
        }
    }

    /// Every backend that writes a per-tree lock can be named by the read side.
    ///
    /// The write side derives the filename from [`super::super::prebuilt::Kind`]; this view has to
    /// answer with the same name for each one, or a package that is pinned reads as un-built. The
    /// list carries `binary:` because it has a `Kind` of its own, and it was the one the catch-all
    /// arm answered `None` for.
    #[test]
    fn every_per_tree_prebuilt_backend_is_named_by_the_read_side() {
        use crate::config::Backend;
        for (backend, expected) in [
            (Backend::Deb("https://e/a.deb".into()), "deb-packages.lock"),
            (
                Backend::AppImage("github:o/r".into()),
                "appimage-packages.lock",
            ),
            (
                Backend::Tarball("https://e/a.tar.gz".into()),
                "tarball-packages.lock",
            ),
            (
                Backend::Binary("https://e/tool".into()),
                "binary-packages.lock",
            ),
            (
                Backend::BinaryResolve { command: vec![] },
                "binary-packages.lock",
            ),
        ] {
            assert_eq!(
                prebuilt_lockfile(&backend).as_deref(),
                Some(expected),
                "{backend:?} writes {expected} but the read side does not name it"
            );
        }
    }

    /// A backend that is not a per-tree prebuilt still answers `None` — the realized signal for
    /// these lives in the per-project store or the cage home, not in a lock.
    #[test]
    fn a_backend_with_no_per_tree_lock_is_still_none() {
        use crate::config::Backend;
        for backend in [
            Backend::Nix("hello".into()),
            Backend::Mise("node".into()),
            Backend::Flake("github:o/r#a".into()),
            Backend::FlakeInline {
                content: String::new(),
                attr: String::new(),
            },
        ] {
            assert_eq!(prebuilt_lockfile(&backend), None, "{backend:?}");
        }
    }

    #[test]
    fn gcroot_names_lists_the_out_links_not_the_nix_tools_directory() {
        let scratch = crate::testutil::TmpDir::new();
        let data = scratch.path();
        let dir = data.join("gcroots/projects/abc123");
        std::fs::create_dir_all(&dir).unwrap();
        // The real directory layout: an out-link symlink per realized package, a plain `.expr`
        // derivation-source stamp beside a prebuilt one, and the `nix-tools/` sub-directory the
        // `nix:` mise tools are rooted under.
        for f in ["chromium", "deb-demo-app", "node"] {
            std::os::unix::fs::symlink(format!("/nix/store/hash-{f}"), dir.join(f)).unwrap();
        }
        std::fs::write(dir.join("deb-demo-app.expr"), b"x").unwrap();
        let nix_tools = dir.join("nix-tools");
        std::fs::create_dir_all(&nix_tools).unwrap();
        std::os::unix::fs::symlink("/nix/store/hash-jq", nix_tools.join("jq")).unwrap();

        let names = gcroot_names(data, "abc123");
        assert_eq!(
            names,
            vec!["chromium", "deb-demo-app", "node"],
            "the out-links, and only those: no `.expr` stamp and no `nix-tools` directory"
        );
        // The `nix:` tool rooted inside `nix-tools/` is not a project package root either — it must
        // not be pulled up a level and reported as one.
        assert!(!names.iter().any(|n| n == "jq"));
        assert!(gcroot_names(data, "absent").is_empty());
    }

    #[test]
    fn nix_tools_locked_reads_pkg_and_resolved_version() {
        let scratch = crate::testutil::TmpDir::new();
        let tree = scratch.path();
        std::fs::write(
            tree.join("tools.lock"),
            "jq\tlatest\tx86_64-linux\taaaa\tjq\t1.7.1\nrg\t14\tx86_64-linux\tbbbb\tripgrep\t14.1.0\n",
        )
        .unwrap();
        let locked = nix_tools_locked(tree);
        assert_eq!(locked.get("jq"), Some(&"1.7.1".to_string()));
        assert_eq!(locked.get("rg"), Some(&"14.1.0".to_string()));
    }

    #[test]
    fn flake_built_finds_a_warm_out_link_floating_or_pinned() {
        let scratch = crate::testutil::TmpDir::new();
        let home = scratch.path();
        // The read path is the same constant the launch writes to — pinning it here means a rename of
        // the out-link directory cannot silently make `flake_built` miss a warm build (the `ops`→`sbx`
        // drift this constant closed).
        let flake = home.join(crate::sandbox::binds::FLAKE_ROOTS_REL);
        std::fs::create_dir_all(&flake).unwrap();
        // A floating out-link keyed by name, pointing at a store path.
        std::os::unix::fs::symlink(
            "/nix/store/9d2v9068xl6f926gl4hbkyfixh8ar0yw-demo-agent-0.18.2",
            flake.join("demo-app"),
        )
        .unwrap();
        assert_eq!(
            flake_built(home, "demo-app"),
            Some("demo-agent-0.18.2".to_string()),
            "the store-path label, hash stripped"
        );
        // A per-build out-link is keyed `<name>-<hash>`; still matched by the name.
        assert!(flake_built(home, "other").is_none());
        std::os::unix::fs::symlink(
            "/nix/store/abcd1234abcd1234abcd1234abcd1234abcd1234-other-1.0",
            flake.join("other-deadbeef"),
        )
        .unwrap();
        assert!(flake_built(home, "other").is_some());
    }

    /// The out-link label is a value the cage chose, so it is filtered like every other one.
    ///
    /// `<home>/.local/state/sbx/flake/` is inside the cage's writable home and the link is written
    /// by the in-cage `nix build`, so the payload picks its target. A symlink target may hold any
    /// byte but `/` and NUL, and the label is the part of the target's basename after the first
    /// dash — so an unfiltered one carries escape sequences straight into `sbx app show`, the exact
    /// command an operator runs to check declared-versus-built state, where an erase sequence
    /// rewrites the rows above it. This is the same filter `mise_installed_in` applies two hundred
    /// lines up, on the same threat.
    #[test]
    fn flake_built_filters_the_out_link_label_the_cage_chose() {
        let scratch = crate::testutil::TmpDir::new();
        let home = scratch.path();
        let flake = home.join(crate::sandbox::binds::FLAKE_ROOTS_REL);
        std::fs::create_dir_all(&flake).unwrap();
        std::os::unix::fs::symlink(
            "/nix/store/aaaa-x-1.0\u{1b}[2K\rdemo-app  built 2.0  (trusted)",
            flake.join("demo-app"),
        )
        .unwrap();
        let label = flake_built(home, "demo-app").expect("the out-link is found");
        assert!(
            !label.contains('\u{1b}') && !label.contains('\r'),
            "a control character reached `sbx app show`: {label:?}"
        );
        // Filtered, not dropped: the honest part of the label still reads back.
        assert!(label.starts_with("x-1.0 "), "unexpected label: {label:?}");
    }

    #[test]
    fn flake_built_falls_back_to_the_pre_rename_out_link_dir() {
        let scratch = crate::testutil::TmpDir::new();
        let home = scratch.path();
        // A home built before the ops→sbx rename carries the out-link only at the legacy path; it must
        // still be reported so the fix does not regress an existing home to `not installed`.
        let legacy = home.join(FLAKE_ROOTS_REL_LEGACY);
        std::fs::create_dir_all(&legacy).unwrap();
        std::os::unix::fs::symlink(
            "/nix/store/9d2v9068xl6f926gl4hbkyfixh8ar0yw-demo-desktop-0.17.0",
            legacy.join("demo-desktop"),
        )
        .unwrap();
        assert_eq!(
            flake_built(home, "demo-desktop"),
            Some("demo-desktop-0.17.0".to_string()),
            "a pre-rename home's out-link must still be found via the legacy fallback"
        );
    }

    #[test]
    fn nix_built_trees_finds_the_package_gcroot_across_trees() {
        let scratch = crate::testutil::TmpDir::new();
        let data = scratch.path();
        // Two trees gcrooted `chromium`; a third gcrooted only something else.
        for id in ["t1", "t3"] {
            let g = data.join("gcroots/projects").join(id);
            std::fs::create_dir_all(&g).unwrap();
            std::os::unix::fs::symlink("/nix/store/hash-chromium", g.join("chromium")).unwrap();
            // A derivation-source sibling is a plain file, not an out-link, and must not count as a
            // build.
            std::fs::write(g.join("chromium.expr"), "").unwrap();
        }
        let t2 = data.join("gcroots/projects/t2");
        std::fs::create_dir_all(&t2).unwrap();
        std::os::unix::fs::symlink("/nix/store/hash-jq", t2.join("jq")).unwrap();

        assert_eq!(
            nix_built_trees(data, "chromium"),
            vec!["t1".to_string(), "t3".to_string()],
            "the trees that gcrooted the package, sorted"
        );
        assert_eq!(nix_built_trees(data, "jq"), vec!["t2".to_string()]);
        // A package no tree built, and an absent gcroots dir, are both empty.
        assert!(nix_built_trees(data, "ripgrep").is_empty());
        assert!(nix_built_trees(&data.join("nope"), "chromium").is_empty());
    }

    #[test]
    fn nixpkgs_pin_prefers_the_per_project_lock_then_falls_back_to_global() {
        let scratch = crate::testutil::TmpDir::new();
        let data = scratch.path();
        let tree = data.join("projects/t1");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            data.join("nixpkgs.lock"),
            "nixos-unstable\n1234567890abcdef\n",
        )
        .unwrap();

        // No per-project lock → the global one, per_project = false.
        let (source, rev, per) = nixpkgs_pin(&tree, data).unwrap();
        assert_eq!(
            (source.as_str(), rev.as_str(), per),
            ("nixos-unstable", "12345678", false)
        );

        // A per-project pin wins and is flagged.
        std::fs::write(tree.join("nixpkgs.lock"), "nixos-23.11\nfedcba0987654321\n").unwrap();
        let (source, rev, per) = nixpkgs_pin(&tree, data).unwrap();
        assert_eq!(
            (source.as_str(), rev.as_str(), per),
            ("nixos-23.11", "fedcba09", true)
        );
    }
}
