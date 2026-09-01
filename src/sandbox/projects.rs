//! The `sbx projects` verb: the per-project runtime trees under `<data>/projects/`, listed, shown
//! and removed.
//!
//! Pure host-side filesystem work — no sandbox, no nix engine, no cage. A project's tree is the
//! durable state a launch leaves behind (its store roots, its mise installs, its gcroots), so this
//! module reads and reaps that tree without ever building one; the mechanics of *deciding* what is
//! safe to reap live in [`mod@super::gc`] and are called from here, and the read-only views come from
//! [`super::inspect`].
//!
//! Kept apart from [`super::launch`] for that reason: the launch pipeline turns a config into a
//! bwrap invocation and supervises it, and shares no state with this — no `Prepared`, no
//! `SandboxSpec`, no guard. The two only meet where `sbx gc` sweeps the trees this verb also
//! removes, which it does by calling in here.

use std::path::Path;
use std::process::ExitCode;

/// Reap — or, in a dry run, list — the runtime trees under `<data>/projects/` whose project
/// directory is gone, plus surface any markerless legacy trees. A tree is reclaimed only when it
/// carries a `project` marker, that path is absent while its parent directory still exists (a cheap
/// guard, not a reliable unmount check — the dry-run default is the backstop there), and no live
/// session holds it. Markerless trees (their project path unknown) are listed for a manual decision
/// by default; `markerless` opts into reaping them without a deadness proof (the `--markerless`
/// escape hatch). Pure host-side filesystem work — no sandbox, no nix. This drives the bulk
/// `sbx projects rm --dead` / `--markerless` sweeps.
///
/// The two selectors arrive as the caller's **intent** and `apply` decides whether it happens, so
/// the report can tell "you asked for this and it is a preview" from "you did not ask". Folding
/// each selector into its own already-applied flag at the call site lost that: a preview of
/// `--markerless` was indistinguishable from a plain listing, so it pointed the reader at a manual
/// removal instead of at the apply form, while the branch written for it could not be reached at
/// all — with the flag set, the trees are reaped and the list it reads is empty.
fn reap_dead_trees(
    layout: &crate::store::Layout,
    live_ids: &std::collections::BTreeSet<String>,
    dead: bool,
    markerless: bool,
    apply: bool,
    pal: &crate::style::Palette,
) {
    let (prune, prune_unidentified) = (apply && dead, apply && markerless);
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let projects_dir = layout.data_dir().join("projects");
    let report = super::gc::reap_dead_projects(&projects_dir, live_ids, prune, prune_unidentified);
    if report.dead.is_empty()
        && report.unidentified.is_empty()
        && report.reaped_unidentified.is_empty()
        && report.failed.is_empty()
    {
        println!("{h}sbx projects rm:{r} {dim}no dead project trees to reclaim.{r}");
        return;
    }

    let mut freed = 0u64;
    for tree in &report.dead {
        freed += tree.bytes;
        // Done (green) when actually reclaimed; a dry-run "reclaimable" is dim (nothing changed).
        let verb = if prune {
            format!("{ok}reclaimed{r}")
        } else {
            format!("{dim}reclaimable{r}")
        };
        println!(
            "  {verb}: {n}{}{r} ({})",
            tree.path.display(),
            super::gc::human_bytes(tree.bytes)
        );
    }
    if !report.dead.is_empty() {
        if prune {
            println!(
                "{h}sbx projects rm:{r} reclaimed {} dead project tree(s), freed up to {}.",
                report.dead.len(),
                super::gc::human_bytes(freed)
            );
        } else {
            println!(
                "{}",
                crate::style::prose(
                    &format!(
                        "{h}sbx projects rm:{r} {} dead project tree(s) reclaimable (up to {}) — \
                         run `sbx projects rm --dead --yes` to reclaim.",
                        report.dead.len(),
                        super::gc::human_bytes(freed)
                    ),
                    pal
                )
            );
        }
    }

    // Markerless trees reaped under the `--markerless` opt-in. Their deadness was NOT verified
    // (the marker is absent, so the project path is unknown) — the caller accepted that risk. They
    // are gone now, so report them as reclaimed rather than as candidates.
    let mut ufreed = 0u64;
    for tree in &report.reaped_unidentified {
        ufreed += tree.bytes;
        println!(
            "  {ok}reclaimed{r} {warn}(no marker, deadness unverified){r}: {n}{}{r} ({})",
            tree.dir.display(),
            super::gc::human_bytes(tree.bytes)
        );
    }
    if !report.reaped_unidentified.is_empty() {
        println!(
            "{h}sbx projects rm --markerless:{r} reclaimed {} markerless tree(s), freed up to {}.",
            report.reaped_unidentified.len(),
            super::gc::human_bytes(ufreed)
        );
    }

    // Markerless trees not reaped (no opt-in, or a dry run): surfaced for a manual decision. The
    // hint adapts to whether the user is using the `--markerless` hatch — a dry run of it points
    // at the apply form, the default still points at a by-hand removal (the fail-closed stance).
    for tree in &report.unidentified {
        let hint = if markerless {
            "run `sbx projects rm --markerless --yes` to reclaim (no deadness proof)"
        } else {
            "remove by hand if unwanted"
        };
        println!(
            "  {warn}unidentified{r} (no marker, project path unknown): {n}{}{r} ({}) — {hint}",
            tree.dir.display(),
            super::gc::human_bytes(tree.bytes)
        );
    }

    // A tree the recursive delete could not get past. Named rather than folded into the reclaimed
    // count, and its bytes deliberately excluded from `freed`: a removal can fail part-way, so what
    // is left is neither the whole tree nor nothing, and a figure either way would be wrong.
    for (dir, error) in &report.failed {
        crate::diag::error(&format!(
            "sbx projects rm: could not remove {}: {error}. What is left is neither the whole \
             tree nor nothing — inspect it before retrying.",
            dir.display()
        ));
    }
}

/// One per-project runtime tree, classified and sized, for `sbx projects [list]`.
#[derive(serde::Serialize)]
struct ProjectTreeView {
    /// The tree's directory name under `<data>/projects/` — the id `sbx projects rm` takes.
    id: String,
    /// `live` (a running session holds it), `idle` (its project still exists), `dead` (the project
    /// directory is gone), or `markerless` (a legacy tree pre-dating marker recording).
    state: &'static str,
    /// On-disk size in bytes (an upper bound — reflinked content shared with another tree counts
    /// per file).
    bytes: u64,
    /// The `bytes` figure rendered human-readably (the text listing shows this).
    size: String,
    /// `YYYY-MM-DD` of the last launch (the marker's mtime), else the tree directory's mtime.
    last_used: String,
    /// The canonical project path the tree belongs to, when it carries a marker.
    project: Option<String>,
    /// Whether this tree is the current working directory's project (marked `*` in the listing).
    current: bool,
}

/// Gather the per-project runtime trees under `<data>/projects/`, classified and sized, sorted by
/// id — the shared core of `sbx projects [list]` (text or JSON). Live ids come from the session
/// registry (the same self-healing housekeep `sbx session ls` runs), so a tree in use reads `live`. Pure
/// host-side filesystem work — no sandbox, no nix.
fn collect_project_trees(layout: &crate::store::Layout) -> Vec<ProjectTreeView> {
    let live_ids = super::launch::session_housekeeping(layout);
    let current = crate::current_project_id();
    let projects_dir = layout.data_dir().join("projects");
    let mut rows: Vec<ProjectTreeView> = match std::fs::read_dir(&projects_dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .map(|e| {
                let dir = e.path();
                let id = e.file_name().to_string_lossy().into_owned();
                let class = super::gc::classify_tree(&dir, &live_ids);
                let bytes = super::gc::tree_size(&dir);
                ProjectTreeView {
                    current: current.as_deref() == Some(id.as_str()),
                    id,
                    state: class.state.label(),
                    bytes,
                    size: super::gc::human_bytes(bytes),
                    last_used: crate::paths::civil_date(class.last_used),
                    project: class.project_path.map(|p| p.display().to_string()),
                }
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

/// The realized nix store roots of a project tree, grouped by backend, for `sbx projects show`.
#[derive(serde::Serialize, Default)]
struct StoreRootsView {
    /// `nix:` packages and hole provisions — the gcroot names that are not a prebuilt build output.
    nix: Vec<String>,
    /// `deb:` build outputs (the `deb-` gcroots, prefix stripped).
    deb: Vec<String>,
    /// `appimage:` build outputs (the `appimage-` gcroots, prefix stripped).
    appimage: Vec<String>,
    /// `tarball:` build outputs (the `tarball-` gcroots, prefix stripped).
    tarball: Vec<String>,
    /// `binary:` build outputs (the `binary-` gcroots, prefix stripped).
    binary: Vec<String>,
}

/// A mise tool realized in the project's own home, for `sbx projects show`.
#[derive(serde::Serialize)]
struct ProjToolView {
    /// The on-disk (munged) tool directory name.
    name: String,
    versions: Vec<String>,
}

/// A declared item the project has not realized yet — `sbx projects show`'s "declared but not built"
/// section — distinguishing an untrusted `withheld` item (a launch would not provision it) from a
/// trusted one simply not built yet (an offline first launch equips it).
#[derive(serde::Serialize)]
struct UnbuiltView {
    /// `nix`/`deb`/`appimage`/`flake`/`mise` for a `[packages]` backend, or `nix tool`/`mise tool`
    /// for a mise `[tools]` entry.
    kind: String,
    locator: String,
    withheld: bool,
}

/// The nixpkgs channel/revision a project resolves against, for `sbx projects show`.
#[derive(serde::Serialize)]
struct NixpkgsView {
    source: String,
    rev: String,
    /// `true` when the tree carries its own pin, `false` when it tracks the global channel.
    per_project: bool,
}

/// The `sbx projects show` model — serialized directly for `--json`.
#[derive(serde::Serialize)]
struct ProjectShowView {
    id: String,
    state: &'static str,
    /// The canonical project path the tree belongs to, when it carries a marker.
    project: Option<String>,
    last_used: String,
    total_bytes: u64,
    store_bytes: u64,
    home_bytes: u64,
    other_bytes: u64,
    nixpkgs: Option<NixpkgsView>,
    store_roots: StoreRootsView,
    mise_tools: Vec<ProjToolView>,
    unbuilt: Vec<UnbuiltView>,
    /// Whether the project directory still exists, so its declared config could be read (a dead tree
    /// shows realized state only — there is nothing left to compare against).
    config_available: bool,
}

/// Show one project runtime tree's realized-on-disk detail — `sbx projects show <id>`. Reports the
/// tree's state and size (broken down store/home/other), the nixpkgs pin it resolves against, the
/// store roots realized in its (shared) store grouped by backend, the mise tools in its own home,
/// and — when the project directory still exists — the project's declared packages/tools that are
/// **not** built yet (an untrusted one flagged `withheld`). Read-only: no sandbox, no nix, no
/// network. The counterpart of `sbx app show` for a project rather than an app.
pub(crate) fn projects_show(id: &str, json: bool, pal: &crate::style::Palette) -> ExitCode {
    use crate::config::Backend;

    let layout = match crate::layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    // The same guard `sbx projects rm` applies before its own `join`, and for the same reason a
    // read verb still needs it: `Path::join` replaces the base with an absolute argument and walks
    // out of it for a `../`, so `sbx projects show /etc` sized and read `/etc` and reported it as a
    // runtime tree. Nothing is written here, which is why this is a guard against answering about
    // the wrong directory rather than against destroying one — but the two verbs take the same
    // argument and should not disagree about what it may be.
    if !super::gc::is_safe_tree_id(id) {
        crate::diag::error(&format!(
            "sbx projects show: invalid project id `{id}` — expected a single tree name \
             (an id `sbx projects` lists), not a path."
        ));
        return ExitCode::from(2);
    }
    let data = layout.data_dir();
    let dir = data.join("projects").join(id);
    if !dir.is_dir() {
        crate::diag::error(&format!(
            "sbx projects show: no runtime tree `{id}` — run `sbx projects list` to see them."
        ));
        return ExitCode::FAILURE;
    }

    let live_ids = super::launch::session_housekeeping(&layout);
    let class = super::gc::classify_tree(&dir, &live_ids);

    // One walk for all three figures: `store` and `home` are inside the tree, so sizing them
    // separately visited every one of their inodes twice.
    let (total, parts) = super::gc::tree_usage_parts(&dir, &[dir.join("store"), dir.join("home")]);
    let (total_bytes, store_bytes, home_bytes) = (total.bytes, parts[0].bytes, parts[1].bytes);
    let other_bytes = total_bytes
        .saturating_sub(store_bytes)
        .saturating_sub(home_bytes);

    // Realized signals, read once from the tree.
    let gcroots = super::inspect::gcroot_names(data, id);
    let gcroot_set: std::collections::BTreeSet<&str> = gcroots.iter().map(String::as_str).collect();
    let tools_locked = super::inspect::nix_tools_locked(&dir);
    let home_tools = super::inspect::mise_installed(&dir.join("home"));
    let nixpkgs =
        super::inspect::nixpkgs_pin(&dir, data).map(|(source, rev, per_project)| NixpkgsView {
            source,
            rev,
            per_project,
        });

    // Group the store roots: a prefixed gcroot is a prebuilt build output of that backend;
    // everything else is a `nix:` package (or a hole provision realized into the shared store).
    //
    // Every prefix the realized-signal match below looks for is listed here. Two of them were not,
    // so a `tarball:` or `binary:` package's gcroot fell through to the `nix` bucket and `sbx
    // projects show` reported it as a `nix:` package the project does not declare.
    let mut store_roots = StoreRootsView::default();
    for name in &gcroots {
        let prefixed = [
            ("deb-", &mut store_roots.deb),
            ("appimage-", &mut store_roots.appimage),
            ("tarball-", &mut store_roots.tarball),
            ("binary-", &mut store_roots.binary),
        ]
        .into_iter()
        .find_map(|(prefix, into)| name.strip_prefix(prefix).map(|rest| (rest, into)));
        match prefixed {
            Some((rest, into)) => into.push(rest.to_string()),
            None => store_roots.nix.push(name.clone()),
        }
    }

    let mise_tools: Vec<ProjToolView> = home_tools
        .iter()
        .map(|t| ProjToolView {
            name: t.label().to_string(),
            versions: super::inspect::concrete_versions(t),
        })
        .collect();

    // "Declared but not built": the project's own declared packages + mise tools that no realized
    // signal accounts for. Only computable when the project directory still exists (a dead tree has
    // no config to read). Untrusted declarations read `withheld` — a launch would not provision them.
    let project = class.project_path.as_ref().map(|p| p.display().to_string());
    let config_available = class
        .project_path
        .as_deref()
        .map(Path::is_dir)
        .unwrap_or(false);
    let mut unbuilt = Vec::new();
    if let Some(ppath) = class.project_path.as_deref().filter(|p| p.is_dir()) {
        let resolved = crate::config::load(ppath);
        for pkg in &resolved.packages {
            let realized = match &pkg.backend {
                Backend::Mise(token) => home_tools.iter().any(|t| t.is(token)),
                Backend::Nix(_) => gcroot_set.contains(pkg.name.as_str()),
                Backend::Deb(_) | Backend::DebResolve { .. } => {
                    gcroot_set.contains(format!("deb-{}", pkg.name).as_str())
                }
                Backend::AppImage(_) | Backend::AppImageResolve { .. } => {
                    gcroot_set.contains(format!("appimage-{}", pkg.name).as_str())
                }
                Backend::Tarball(_) | Backend::TarballResolve { .. } => {
                    gcroot_set.contains(format!("tarball-{}", pkg.name).as_str())
                }
                Backend::Binary(_) | Backend::BinaryResolve { .. } => {
                    gcroot_set.contains(format!("binary-{}", pkg.name).as_str())
                }
                // A remote `flake:` builds host-side under a bare-`<name>` data-dir gcroot, like
                // `nix:`; an inline `[flakes.<name>]` builds in-cage and lands a warm out-link in the
                // project home, so the home out-link is its realized signal.
                Backend::Flake(_) => gcroot_set.contains(pkg.name.as_str()),
                Backend::FlakeInline { .. } => {
                    super::inspect::flake_built(&dir.join("home"), &pkg.name).is_some()
                }
            };
            if !realized {
                unbuilt.push(UnbuiltView {
                    kind: pkg.backend.label().to_string(),
                    locator: format!("{} = {}", pkg.name, pkg.backend.locator()),
                    withheld: pkg.state != crate::trust::TrustState::Trusted,
                });
            }
        }
        // Declared mise `[tools]`: a `nix:` tool is host-provisioned (trusted-only), recorded in
        // tools.lock; any other backend is auto-equipped in-cage into the project home. A withheld
        // `nix:` tool is one the (untrusted) mise config would not have provisioned.
        if let Some(mise) = resolved.mise.as_ref() {
            let mise_trusted = mise.state == crate::trust::TrustState::Trusted;
            let declared = super::nixhub::parse_nix_tools(&mise.files);
            for tool in &declared.nix {
                if !tools_locked.contains_key(&tool.pkg) {
                    unbuilt.push(UnbuiltView {
                        kind: "nix tool".to_string(),
                        locator: format!("nix:{} = {}", tool.pkg, tool.version),
                        withheld: !mise_trusted,
                    });
                }
            }
            for tool in &declared.non_nix {
                if !home_tools.iter().any(|t| t.is(&tool.token)) {
                    unbuilt.push(UnbuiltView {
                        kind: "mise tool".to_string(),
                        locator: format!("{} = {}", tool.token, tool.version),
                        withheld: false,
                    });
                }
            }
        }
    }

    let view = ProjectShowView {
        id: id.to_string(),
        state: class.state.label(),
        project,
        last_used: crate::paths::civil_date(class.last_used),
        total_bytes,
        store_bytes,
        home_bytes,
        other_bytes,
        nixpkgs,
        store_roots,
        mise_tools,
        unbuilt,
        config_available,
    };

    if json {
        if let Err(code) = crate::print_json("projects show", &view) {
            return code;
        }
        return ExitCode::SUCCESS;
    }
    print!("{}", render_project_show(&view, pal));
    ExitCode::SUCCESS
}

/// Render the `sbx projects show` model — a pure presenter (every color span is empty under a
/// non-terminal, so captured output is the plain text the tests pin).
fn render_project_show(v: &ProjectShowView, pal: &crate::style::Palette) -> String {
    use std::fmt::Write;
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let mut s = String::new();
    let _ = writeln!(s, "{h}project{r} {n}{}{r}  {}", v.id, v.state);
    match &v.project {
        Some(p) => {
            let _ = writeln!(s, "  path:     {p}");
        }
        None => {
            let _ = writeln!(s, "  path:     {dim}(no marker — project path unknown){r}");
        }
    }
    let _ = writeln!(s, "  last:     {dim}{}{r}", v.last_used);
    let _ = writeln!(
        s,
        "  disk:     {}  {dim}(store {} · home {} · other {}){r}",
        super::gc::human_bytes(v.total_bytes),
        super::gc::human_bytes(v.store_bytes),
        super::gc::human_bytes(v.home_bytes),
        super::gc::human_bytes(v.other_bytes),
    );
    match &v.nixpkgs {
        Some(np) => {
            let scope = if np.per_project {
                "per-project pin"
            } else {
                "global channel"
            };
            let _ = writeln!(
                s,
                "  nixpkgs:  {} @ {}  {dim}({scope}){r}",
                np.source, np.rev
            );
        }
        None => {
            let _ = writeln!(s, "  nixpkgs:  {dim}(no lock recorded){r}");
        }
    }
    // Store roots realized in the (shared) per-project store.
    let roots_empty = v.store_roots.nix.is_empty()
        && v.store_roots.deb.is_empty()
        && v.store_roots.appimage.is_empty()
        && v.store_roots.tarball.is_empty()
        && v.store_roots.binary.is_empty();
    if roots_empty {
        let _ = writeln!(s, "  store roots: {dim}none{r}");
    } else {
        let _ = writeln!(
            s,
            "  store roots {dim}(built in this project's store, shared by its apps):{r}"
        );
        let mut row = |label: &str, items: &[String]| {
            if !items.is_empty() {
                let _ = writeln!(s, "    {label:<9} {n}{}{r}", items.join(", "));
            }
        };
        row("nix", &v.store_roots.nix);
        row("deb", &v.store_roots.deb);
        row("appimage", &v.store_roots.appimage);
        row("tarball", &v.store_roots.tarball);
        row("binary", &v.store_roots.binary);
    }
    // mise tools in the project's own home.
    if !v.mise_tools.is_empty() {
        let _ = writeln!(s, "  mise tools {dim}(project home):{r}");
        for t in &v.mise_tools {
            let versions = t.versions.join(", ");
            let suffix = if versions.is_empty() {
                String::new()
            } else {
                format!("  {dim}{versions}{r}")
            };
            let _ = writeln!(s, "    {n}{}{r}{suffix}", t.name);
        }
    }
    // Declared-but-not-built (the useful direction of declared-vs-installed).
    if !v.config_available {
        let _ = writeln!(
            s,
            "  {dim}(project directory is gone — showing realized state only){r}"
        );
    } else if v.unbuilt.is_empty() {
        let _ = writeln!(
            s,
            "  declared: {ok}all declared packages/tools are built{r}"
        );
    } else {
        let _ = writeln!(s, "  declared but not built:");
        for u in &v.unbuilt {
            let (tag, hue) = if u.withheld {
                ("withheld (untrusted — run `sbx trust`)", warn)
            } else {
                ("not built yet", dim)
            };
            let _ = writeln!(s, "    {n}{}{r} {}  {hue}{tag}{r}", u.kind, u.locator);
        }
    }
    s
}

/// List the per-project runtime trees — `sbx projects` / `sbx projects list`. A read-only overview
/// (richer than `sbx path`'s projects section: it adds each tree's on-disk size), in aligned text
/// or `--json`.
pub(crate) fn projects_list(json: bool, pal: &crate::style::Palette) -> ExitCode {
    let layout = match crate::layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let rows = collect_project_trees(&layout);

    if json {
        if let Err(code) = crate::print_json("projects", &rows) {
            return code;
        }
        return ExitCode::SUCCESS;
    }

    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    if rows.is_empty() {
        println!("{h}sbx projects{r} {dim}— no per-project runtime trees.{r}");
        return ExitCode::SUCCESS;
    }
    let total: u64 = rows.iter().map(|row| row.bytes).sum();
    println!(
        "{h}sbx projects{r} {dim}({} tree(s), {}){r}",
        rows.len(),
        super::gc::human_bytes(total)
    );
    let state_w = rows.iter().map(|row| row.state.len()).max().unwrap_or(0);
    let size_w = rows.iter().map(|row| row.size.len()).max().unwrap_or(0);
    for row in &rows {
        let state = format!("{:<state_w$}", row.state);
        let size = format!("{:>size_w$}", row.size);
        let mark = if row.current {
            format!("  {n}*{r}")
        } else {
            String::new()
        };
        let path = row.project.as_deref().unwrap_or("(no marker)");
        println!(
            "  {n}{id}{r}  {state}  {size}  {dim}{last}{r}  {path}{mark}",
            id = row.id,
            last = row.last_used,
        );
    }
    println!(
        "{}",
        crate::style::dim_prose(
            "remove one with `sbx projects rm <id>`; sweep dead trees with `sbx projects rm --dead --yes`.",
            pal
        )
    );
    ExitCode::SUCCESS
}

/// Decide whether `sbx projects rm` applies the removal or only previews it. A *targeted* removal
/// (ids named, no bulk selector) applies immediately — naming the id is the intent, like `rm`; a
/// *bulk* selector (`--dead`/`--markerless`) previews by default and requires `--yes`. `--dry-run`
/// forces a preview, `--yes` forces apply; the two together are contradictory (`None`).
pub(crate) fn rm_apply(targeted: bool, bulk: bool, dry_run: bool, yes: bool) -> Option<bool> {
    if dry_run && yes {
        return None;
    }
    if dry_run {
        return Some(false);
    }
    if yes {
        return Some(true);
    }
    Some(targeted && !bulk)
}

/// Whether `sbx projects rm <id>` must refuse `id` because it is the tree of the current working
/// directory — deleting the store and home you are standing in — unless `--force` overrides it.
/// `current` is [`crate::current_project_id`]; `None` (cwd unresolvable) never guards.
fn rm_refuses_current(id: &str, current: Option<&str>, force: bool) -> bool {
    !force && current == Some(id)
}

/// Remove named project trees and/or sweep the dead/markerless ones — `sbx projects rm`. Each named
/// id is reaped through the shared [`super::gc::reap_one`] (no deadness proof — naming the id is the
/// proof), the bulk selectors through [`reap_dead_trees`]; a live-held tree is always refused, and
/// the current project is refused without `--force`. `apply` gates the actual deletion (a preview
/// otherwise). With `--gc`, the shared-store collection runs after a real removal to reclaim the
/// now-orphaned closures. Pure host-side filesystem work (bar the optional `--gc`) — no sandbox.
#[allow(clippy::too_many_arguments)]
pub(crate) fn projects_rm(
    ids: &[String],
    dead: bool,
    markerless: bool,
    apply: bool,
    do_gc: bool,
    force: bool,
    pal: &crate::style::Palette,
) -> ExitCode {
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let layout = match crate::layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let live_ids = super::launch::session_housekeeping(&layout);
    let current = crate::current_project_id();
    let projects_dir = layout.data_dir().join("projects");
    let mut had_error = false;

    for id in ids {
        if !super::gc::is_safe_tree_id(id) {
            crate::diag::error(&format!(
                "sbx projects rm: invalid project id `{id}` — expected a single tree name \
                 (an id `sbx projects` lists), not a path."
            ));
            had_error = true;
            continue;
        }
        // Guard the tree you are standing in: an idle current project is not `Live`, so naming its
        // exact id would delete the store and home of this very directory. `--force` is the opt-in.
        if rm_refuses_current(id, current.as_deref(), force) {
            crate::diag::error(&format!(
                "sbx projects rm: {n}{id}{r} is the current project — refusing without {n}--force{r}."
            ));
            had_error = true;
            continue;
        }
        match super::gc::reap_one(&projects_dir, id, &live_ids, apply) {
            super::gc::ReapOneOutcome::NotFound => {
                crate::diag::error(&format!(
                    "sbx projects rm: no project tree for id `{id}` under {}.",
                    projects_dir.display()
                ));
                had_error = true;
            }
            super::gc::ReapOneOutcome::Live => {
                crate::diag::error(&format!(
                    "sbx projects rm: project tree {n}{id}{r} is held by a live session — \
                     stop it first with `sbx session stop` (`sbx session ls` names the pid), \
                     then `sbx projects rm {id}`."
                ));
                had_error = true;
            }
            super::gc::ReapOneOutcome::Tree { dir, bytes } => {
                let verb = if apply {
                    format!("{ok}removed{r}")
                } else {
                    format!("{dim}removable{r}")
                };
                println!(
                    "  {verb}: {n}{}{r} ({})",
                    dir.display(),
                    super::gc::human_bytes(bytes)
                );
                if !apply {
                    println!(
                        "{}",
                        crate::style::prose(
                            &format!(
                                "{h}sbx projects rm:{r} {n}{id}{r} removable ({}) — \
                                 run `sbx projects rm {id}` (without `--dry-run`) to remove.",
                                super::gc::human_bytes(bytes)
                            ),
                            pal
                        )
                    );
                }
            }
            // A recursive delete fails on a tree holding a mount point or a subdirectory another
            // uid owns, and it can fail part-way. Reporting it as removed would state a figure the
            // disk does not agree with, and would hide the one tree that keeps failing by naming
            // it reclaimed on every run.
            super::gc::ReapOneOutcome::Failed { dir, error } => {
                crate::diag::error(&format!(
                    "sbx projects rm: could not remove {n}{}{r}: {error}. \
                     What is left is neither the whole tree nor nothing — inspect it before \
                     retrying.",
                    dir.display()
                ));
                had_error = true;
            }
        }
    }

    if dead || markerless {
        reap_dead_trees(&layout, &live_ids, dead, markerless, apply, pal);
    }

    if do_gc {
        if apply {
            super::launch::shared_store_gc(&layout, true, false, pal);
        } else {
            crate::diag::error(&format!(
                "sbx projects rm: {dim}--gc runs the shared-store collection only when the removal \
                 is applied (add --yes, or drop --dry-run).{r}"
            ));
        }
    }

    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod projects_rm_tests {
    use super::{rm_apply, rm_refuses_current};

    #[test]
    fn a_named_id_applies_immediately_but_a_bulk_selector_previews() {
        // Pure targeted: apply now.
        assert_eq!(rm_apply(true, false, false, false), Some(true));
        // Bulk selector present: preview by default (needs --yes).
        assert_eq!(rm_apply(false, true, false, false), Some(false));
        assert_eq!(rm_apply(true, true, false, false), Some(false));
    }

    #[test]
    fn dry_run_and_yes_override_the_default_and_conflict_together() {
        assert_eq!(rm_apply(true, false, true, false), Some(false)); // --dry-run wins over targeted
        assert_eq!(rm_apply(false, true, false, true), Some(true)); // --yes applies a bulk sweep
        assert_eq!(rm_apply(true, false, true, true), None); // contradictory
    }

    #[test]
    fn the_current_project_tree_is_refused_unless_forced() {
        // The id matches the cwd's tree: refuse without --force, allow with it.
        assert!(rm_refuses_current("abc", Some("abc"), false));
        assert!(!rm_refuses_current("abc", Some("abc"), true));
        // A different tree, or an unresolvable cwd, never guards.
        assert!(!rm_refuses_current("abc", Some("def"), false));
        assert!(!rm_refuses_current("abc", None, false));
    }
}
