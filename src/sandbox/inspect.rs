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
    /// token (see [`mise_munge`]), e.g. `aqua-example-demo-tool`.
    pub(crate) name: String,
    /// The real backend token mise recorded for this tool (`pipx:demo-agent`, `aqua:example/demo-tool`,
    /// …), read from its `.mise.backend.toml`. `None` when that metadata is absent. Preferred over
    /// the munged directory name for display *and* for an exact match against a declared token.
    pub(crate) token: Option<String>,
    /// The version subdirectories realized for the tool. Includes mise's `latest` alias directory
    /// alongside the concrete version it points at; [`concrete_versions`] filters the alias out.
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

/// The mise tools realized under `home` — reads `<home>/.local/share/mise/installs/<tool>/<ver>/`,
/// skipping mise's own `.mise-installs.toml` metadata file (filtered out by the directory check) and
/// any non-directory entry. Sorted by name; empty when the home carries no mise data. Read-only.
pub(crate) fn mise_installed(home: &Path) -> Vec<InstalledTool> {
    let installs = home.join(".local/share/mise/installs");
    let mut tools = Vec::new();
    let Ok(entries) = std::fs::read_dir(&installs) else {
        return tools;
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let token = backend_token(&entry.path());
        let mut versions: Vec<String> = match std::fs::read_dir(entry.path()) {
            Ok(vs) => vs
                .flatten()
                .filter(|v| v.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .map(|v| v.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        versions.sort();
        tools.push(InstalledTool {
            name,
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
    let body = std::fs::read_to_string(tool_dir.join(".mise.backend.toml")).ok()?;
    let value = |key: &str| {
        body.lines().find_map(|line| {
            let rest = line.trim().strip_prefix(key)?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            let quoted = rest.strip_prefix('"')?.strip_suffix('"')?;
            (!quoted.is_empty()).then(|| quoted.to_string())
        })
    };
    value("short").or_else(|| value("full"))
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

/// The lock filename a prebuilt backend records its pins in, or `None` for a backend that is not a
/// per-tree prebuilt. Only `deb:`/`appimage:` qualify: their build output lands in the **per-project
/// store**, so a per-tree lock (and the store gcroot) is their realized signal. `flake:` builds into
/// the cage **home** instead (see [`flake_built`]); mise is per-home; nix has no lock of this shape.
pub(crate) fn prebuilt_lockfile(backend: &crate::config::Backend) -> Option<&'static str> {
    use crate::config::Backend;
    match backend {
        Backend::Deb(_) => Some("deb-packages.lock"),
        Backend::AppImage(_) => Some("appimage-packages.lock"),
        Backend::Tarball(_) | Backend::TarballResolve { .. } => Some("tarball-packages.lock"),
        _ => None,
    }
}

/// The out-link directory a home built before the `ops`→`sbx` rename still carries. A launch now
/// writes the out-link to [`binds::FLAKE_ROOTS_REL`] (`.local/state/sbx/flake`), but a home last built
/// under the old name keeps it here until its next relaunch rebuilds into the current dir — so the
/// read side checks both, current first, to report such a home accurately through the transition.
const FLAKE_ROOTS_REL_LEGACY: &str = ".local/state/ops/flake";

/// Whether a `flake:` package named `name` (its free label) has a warm build out-link in `home` —
/// `<home>/<FLAKE_ROOTS_REL>/<name>` (a floating build) or `<name>-<rev>` (a pinned one), where the
/// out-link's target store path lives in the per-project store the launch bound at `/nix`. The
/// out-link *symlink* is the realized signal a launch leaves in the home (a *floating* flake has an
/// out-link but no lock entry at all, which a lock scan would miss). The current relative path is
/// [`binds::FLAKE_ROOTS_REL`] — the same constant the launch writes to, so the read side cannot drift
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
            .unwrap_or_else(|| "built".to_string());
        return Some(detail);
    }
    None
}

/// The nix store roots a project tree has realized — the gcroot names under
/// `<data>/gcroots/projects/<id>/`, skipping the `.expr` derivation-source siblings. This is the
/// project's **shared** store content: the roots accrue from the project baseline *and* every app
/// launched in it (they share one per-project store). A `deb-<name>` / `appimage-<name>` name is a
/// prebuilt build output; every other name is a `nix:` package (or a hole provision). Sorted.
/// Read-only; an absent gcroot dir is simply no roots.
pub(crate) fn gcroot_names(data_dir: &Path, tree_id: &str) -> Vec<String> {
    let dir = data_dir.join("gcroots").join("projects").join(tree_id);
    let mut names: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
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
            token: None,
            versions: vec!["latest".into(), "2.1.209".into()],
        };
        assert_eq!(concrete_versions(&with_concrete), vec!["2.1.209"]);
        let alias_only = InstalledTool {
            name: "t".into(),
            token: None,
            versions: vec!["latest".into()],
        };
        assert_eq!(concrete_versions(&alias_only), vec!["latest"]);
    }

    #[test]
    fn mise_installed_reads_tools_and_versions_skipping_metadata() {
        let tmp = std::env::temp_dir().join(format!("sbx-inspect-{}", std::process::id()));
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

        let tools = mise_installed(&tmp);
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

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn mise_installed_is_empty_without_a_mise_dir() {
        let tmp = std::env::temp_dir().join(format!("sbx-inspect-empty-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(mise_installed(&tmp).is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn prebuilt_pin_trees_finds_the_locator_across_trees() {
        let data = std::env::temp_dir().join(format!("sbx-inspect-pins-{}", std::process::id()));
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

        let hits = prebuilt_pin_trees(&data, "deb-packages.lock", "https://example.com/app.deb");
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

        std::fs::remove_dir_all(&data).ok();
    }

    #[test]
    fn gcroot_names_lists_roots_skipping_expr_siblings() {
        let data = std::env::temp_dir().join(format!("sbx-inspect-gc-{}", std::process::id()));
        let dir = data.join("gcroots/projects/abc123");
        std::fs::create_dir_all(&dir).unwrap();
        for f in ["chromium", "deb-demo-app", "deb-demo-app.expr", "node"] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        let names = gcroot_names(&data, "abc123");
        assert_eq!(
            names,
            vec!["chromium", "deb-demo-app", "node"],
            "expr skipped"
        );
        assert!(gcroot_names(&data, "absent").is_empty());
        std::fs::remove_dir_all(&data).ok();
    }

    #[test]
    fn nix_tools_locked_reads_pkg_and_resolved_version() {
        let tree = std::env::temp_dir().join(format!("sbx-inspect-tl-{}", std::process::id()));
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            tree.join("tools.lock"),
            "jq\tlatest\tx86_64-linux\taaaa\tjq\t1.7.1\nrg\t14\tx86_64-linux\tbbbb\tripgrep\t14.1.0\n",
        )
        .unwrap();
        let locked = nix_tools_locked(&tree);
        assert_eq!(locked.get("jq"), Some(&"1.7.1".to_string()));
        assert_eq!(locked.get("rg"), Some(&"14.1.0".to_string()));
        std::fs::remove_dir_all(&tree).ok();
    }

    #[test]
    fn flake_built_finds_a_warm_out_link_floating_or_pinned() {
        let home = std::env::temp_dir().join(format!("sbx-inspect-flk-{}", std::process::id()));
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
            flake_built(&home, "demo-app"),
            Some("demo-agent-0.18.2".to_string()),
            "the store-path label, hash stripped"
        );
        // A pinned out-link is keyed `<name>-<rev>`; still matched by the name.
        assert!(flake_built(&home, "other").is_none());
        std::os::unix::fs::symlink(
            "/nix/store/abcd1234abcd1234abcd1234abcd1234abcd1234-other-1.0",
            flake.join("other-deadbeef"),
        )
        .unwrap();
        assert!(flake_built(&home, "other").is_some());
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn flake_built_falls_back_to_the_pre_rename_out_link_dir() {
        let home =
            std::env::temp_dir().join(format!("sbx-inspect-flk-legacy-{}", std::process::id()));
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
            flake_built(&home, "demo-desktop"),
            Some("demo-desktop-0.17.0".to_string()),
            "a pre-rename home's out-link must still be found via the legacy fallback"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn nix_built_trees_finds_the_package_gcroot_across_trees() {
        let data = std::env::temp_dir().join(format!("sbx-inspect-nbt-{}", std::process::id()));
        // Two trees gcrooted `chromium`; a third gcrooted only something else.
        for id in ["t1", "t3"] {
            let g = data.join("gcroots/projects").join(id);
            std::fs::create_dir_all(&g).unwrap();
            std::fs::write(g.join("chromium"), "").unwrap();
            // A derivation-source sibling must not count as a build (gcroot_names filters `.expr`).
            std::fs::write(g.join("chromium.expr"), "").unwrap();
        }
        let t2 = data.join("gcroots/projects/t2");
        std::fs::create_dir_all(&t2).unwrap();
        std::fs::write(t2.join("jq"), "").unwrap();

        assert_eq!(
            nix_built_trees(&data, "chromium"),
            vec!["t1".to_string(), "t3".to_string()],
            "the trees that gcrooted the package, sorted"
        );
        assert_eq!(nix_built_trees(&data, "jq"), vec!["t2".to_string()]);
        // A package no tree built, and an absent gcroots dir, are both empty.
        assert!(nix_built_trees(&data, "ripgrep").is_empty());
        assert!(nix_built_trees(&data.join("nope"), "chromium").is_empty());
        std::fs::remove_dir_all(&data).ok();
    }

    #[test]
    fn nixpkgs_pin_prefers_the_per_project_lock_then_falls_back_to_global() {
        let data = std::env::temp_dir().join(format!("sbx-inspect-np-{}", std::process::id()));
        let tree = data.join("projects/t1");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(
            data.join("nixpkgs.lock"),
            "nixos-unstable\n1234567890abcdef\n",
        )
        .unwrap();

        // No per-project lock → the global one, per_project = false.
        let (source, rev, per) = nixpkgs_pin(&tree, &data).unwrap();
        assert_eq!(
            (source.as_str(), rev.as_str(), per),
            ("nixos-unstable", "12345678", false)
        );

        // A per-project pin wins and is flagged.
        std::fs::write(tree.join("nixpkgs.lock"), "nixos-23.11\nfedcba0987654321\n").unwrap();
        let (source, rev, per) = nixpkgs_pin(&tree, &data).unwrap();
        assert_eq!(
            (source.as_str(), rev.as_str(), per),
            ("nixos-23.11", "fedcba09", true)
        );

        std::fs::remove_dir_all(&data).ok();
    }
}
