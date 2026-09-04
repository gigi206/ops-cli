//! The `sbx gc` verb: what a reclaim run decides, in what order, and what it reports.
//!
//! The policy layer, not the mechanics. [`mod@crate::sandbox::gc`] holds the store-level work —
//! collecting a nix store, pruning gcroots, sweeping runtime directories, sizing a tree — and this
//! module decides which of it runs, against which project, and whether the run is a dry one.
//! Hence `reclaim` rather than a second `gc`.
//!
//! Order is a property here rather than a convenience: the current project's sweep re-materialises
//! what it re-roots, so a shared collection taken before it measures a state the same command goes
//! on to invalidate. A reclaim also refuses rather than races — a live session's roots are held,
//! never swept out from under it.

use super::*;

/// `sbx gc [--all] [--prune]`: reclaim sbx's store space.
///
/// By default it sweeps the **current** project's store (see [`sweep_current`]). With `--all` it
/// also, across all projects: reaps whole runtime trees whose project directory is gone (see
/// `reap_dead_trees` in [`mod@crate::sandbox::projects`]), then garbage-collects the **shared** store — the
/// channel revisions left
/// behind by `sbx upgrade` and the tools of reaped projects (see [`shared_store_gc`]). A dry run
/// by default; `--prune` is the destructive form.
///
/// **The current-project sweep runs first, and the shared collection last.** The sweep provisions
/// this project's declared tools to re-root them, and that provisioning re-materializes the pinned
/// channel's flake source in the shared store. Collecting the shared store *before* the sweep
/// therefore measured a state the same command went on to invalidate: the sweep put back the source
/// the collection had just taken, so the run left an orphan behind and the next `sbx gc --all`
/// reported the very same reclaimable bytes — it took two passes to converge. Sweeping first means
/// the shared collection sees the final state.
///
/// The cross-project passes stay independent of the sandbox/nix prerequisites the sweep needs, so
/// they run **whatever the sweep did** — `sbx gc --all` still reclaims from a directory that is not
/// a project, or on a host that has lost its sandbox capability.
pub(crate) fn gc(prune: bool, all: bool, optimise: bool, pal: &crate::style::Palette) -> ExitCode {
    let swept = sweep_current(prune, optimise, pal);

    if all {
        match crate::store::Layout::from_env() {
            Some(layout) => {
                // Prune stale session records, then collect the shared store. Reaping whole
                // per-project runtime *trees* is `sbx projects rm`; `--all` here is purely the
                // nix-store side — the shared store's orphaned closures across every project.
                let live = session_housekeeping(&layout);
                runtime_housekeeping(&layout, &live, prune, pal);
                shared_store_gc(&layout, prune, optimise, pal);
            }
            None => crate::diag::error(
                "sbx gc: cannot locate sbx's data directory; skipping the shared-store housekeeping.",
            ),
        }
    }

    match swept {
        Ok(()) => ExitCode::SUCCESS,
        // Under `--all` the shared-store collection ran regardless, so a current-project sweep that
        // could not run (the host cannot sandbox, nix is unavailable) — or that hit an error — must
        // not fail the whole command. Its own message is already printed above; only the exit code
        // is flattened.
        Err(_) if all => {
            crate::diag::error(
                "sbx gc: the current project's store was not swept (see above); the shared-store collection ran.",
            );
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Prune dead session records and report it (the dedicated housekeeping pass the registry deferred:
/// an `sbx run` record with no post-exec hook lingered until the next `sbx session ls`). Returns the ids of
/// projects with a *live* session — hashing each recorded canonical path — so the dead-tree reap
/// can skip a tree a session still holds without scanning the registry a second time.
pub(in crate::sandbox) fn session_housekeeping(
    layout: &crate::store::Layout,
) -> std::collections::BTreeSet<String> {
    match crate::session::Registry::at(layout.data_dir()).housekeep() {
        Ok((live, pruned)) => {
            if pruned > 0 {
                // On **stderr**, like every other diagnostic. It used to be a `println!`, and this
                // function runs first in `sbx projects`, `sbx projects show` and `sbx projects rm`
                // — including their `--json` forms, where one pruned record put a line of prose
                // ahead of the document and left `sbx projects --json | jq` with a parse error on a
                // run that had done nothing wrong. The notice is about sbx's own bookkeeping, not
                // the answer to the question asked, so it belongs where the other bookkeeping goes.
                crate::diag::note(&format!(
                    "pruned {pruned} stale session record(s); {} live.",
                    live.len()
                ));
            }
            // Hash the stored path directly rather than re-canonicalise: a live session's recorded
            // path is already canonical, so its hash matches the id its tree is keyed by.
            live.iter().map(|s| binds::project_id(&s.project)).collect()
        }
        Err(e) => {
            crate::diag::error(&format!(
                "sbx gc: cannot read the session registry ({e}); skipping session housekeeping."
            ));
            std::collections::BTreeSet::new()
        }
    }
}

/// Reclaim — or, in a dry run, count — the per-launch runtime files left behind by launches that
/// are gone: the egress MITM CA and its sockets, the inbound forwarder's and in-cage portal's
/// runtime directories, the process-observation sockets. Every launch already sweeps these, so this
/// is for the data directory of someone who has stopped launching; it is pure host-side filesystem
/// work (no sandbox, no nix), and stays silent when there is nothing to reclaim.
fn runtime_housekeeping(
    layout: &crate::store::Layout,
    live_projects: &std::collections::BTreeSet<String>,
    prune: bool,
    pal: &crate::style::Palette,
) {
    let (h, n, r) = (pal.head, pal.name, pal.reset);
    // Reported apart from the sweep below because it is a different event: these counters are added
    // into the file that replaces them, not discarded. `sbx net stats` answers the same afterwards.
    let folded = crate::sandbox::gc::fold_egress_counters(layout.data_dir(), prune);
    if !folded.is_empty() {
        let verb = if prune { "folded" } else { "would be folded" };
        println!(
            "{h}sbx gc:{r} egress counters — {n}{}{r} finished session file(s) {verb} into one per \
             project; nothing is discarded (`sbx net stats --reset` is what discards).",
            folded.len()
        );
    }
    // The unpacked distribution root filesystems, reported before the runtime files because they
    // are the larger number by orders of magnitude: an image tree is a distribution, and a run that
    // freed one has freed more than every other pass here put together.
    let trees = crate::sandbox::gc::sweep_distro_trees(layout.data_dir(), live_projects, prune);
    if !trees.is_empty() {
        let bytes: u64 = trees.iter().map(|(_, b)| b).sum();
        let verb = if prune { "removed" } else { "would be removed" };
        println!(
            "{h}sbx gc:{r} distribution images — {n}{}{r} unpacked tree(s) {verb}, {n}{}{r} freed.",
            trees.len(),
            crate::sandbox::human_bytes(bytes)
        );
    }

    let stale = crate::sandbox::gc::sweep_runtime_dirs(layout.data_dir(), prune);
    if stale.is_empty() {
        return;
    }
    if prune {
        println!(
            "{h}sbx gc:{r} runtime files — removed {n}{}{r} left by launches that are gone.",
            stale.len()
        );
    } else {
        println!(
            "{h}sbx gc:{r} runtime files — {n}{}{r} left by launches that are gone would be removed.",
            stale.len()
        );
    }
}

/// Garbage-collect the **shared** store: drop the gc roots of channel revisions no longer locked
/// and of reaped projects, then `nix-store --gc` the shared store. Runs *after* the dead-tree reap,
/// so a reaped project's pin no longer keeps its channel revision alive. Held under the exclusive
/// shared-store lock for the whole prune + collection, so a concurrent seed's reflink copy (which
/// holds the same lock shared) can never race the deletion. Best-effort: a missing `nix-store`, or
/// an unlockable store, skips with a note rather than failing the command — like the reap, it is
/// independent of the current-project sweep.
///
/// Concurrency scope, precisely: the lock closes the one corruption window — the seeder's direct
/// copy versus this collector deleting mid-copy. It does **not** cover a launch *provisioning* a
/// brand-new revision (the `nix build --out-link` and the lock write happen outside it), so a
/// launch first-resolving a fresh revision concurrent with a `--prune` can have that revision's
/// just-created gc root pruned (it was not in the live-set snapshot) and its closure collected,
/// after which the launch's seed cache-misses or fails. That is **recoverable** — a re-run
/// re-provisions, and nix's own gc lock still stops the build itself from racing the collector, so
/// it is never corruption. Widening the sbx lock to cover provisioning would make this collector
/// wait behind minutes-long builds, so the narrow lock plus this named residual is the deliberate
/// trade.
pub(in crate::sandbox) fn shared_store_gc(
    layout: &crate::store::Layout,
    prune: bool,
    optimise: bool,
    pal: &crate::style::Palette,
) {
    let (h, r) = (pal.head, pal.reset);
    let Some(nix_store) = crate::store::resolve_nix_store(Some(layout)) else {
        eprintln!("sbx gc: nix-store not found; skipping the shared-store gc.");
        return;
    };

    // Exclusive across the whole prune + `nix-store --gc`: it waits for in-flight seeds to release
    // their shared hold, and blocks new seeds until the collection finishes.
    let _lock = match crate::sandbox::projectstore::lock_exclusive(layout) {
        Ok(guard) => guard,
        Err(e) => {
            crate::diag::error(&format!(
                "sbx gc: cannot lock the shared store ({e}); skipping the shared-store gc."
            ));
            return;
        }
    };

    // Read the live revisions *after* acquiring the lock, so the snapshot reflects every lock
    // written before the exclusive acquire settled (no read-then-lock gap).
    let live_base = crate::store::live_base_revisions(layout);
    let live_mise = crate::store::live_mise_revisions(layout);

    let stale = crate::sandbox::gc::prune_shared_gcroots(
        &layout.data_dir().join("gcroots"),
        &layout.data_dir().join("projects"),
        &live_base,
        &live_mise,
        prune,
    );

    let report = match crate::sandbox::gc::collect(&nix_store, &layout.store_dir(), prune) {
        Ok(r) => r,
        Err(e) => {
            crate::diag::error(&format!("sbx gc: shared-store gc failed: {e}"));
            return;
        }
    };

    if prune {
        println!(
            "{h}sbx gc:{r} shared store — dropped {} stale gc root(s), collected {} store path(s), freed {}.",
            stale.len(),
            report.paths,
            crate::sandbox::gc::human_bytes(report.bytes)
        );
    } else {
        // On a dry run the stale roots are not dropped, so their closures are still rooted and not
        // yet counted as collectable; the count of stale roots is the signal, and `--prune` frees
        // their closures on top of the orphans reported here (a lower bound).
        println!(
            "{}",
            crate::style::prose(
                &format!(
                    "{h}sbx gc:{r} shared store — {} stale gc root(s) would be dropped; \
                     {} orphaned path(s) reclaimable now ({}). Run `sbx gc --all --prune` to \
                     drop the roots and reclaim their closures.",
                    stale.len(),
                    report.paths,
                    crate::sandbox::gc::human_bytes(report.bytes)
                ),
                pal
            )
        );
    }

    // After the collection, so nothing about to be deleted is deduplicated first. Still under the
    // exclusive lock, which is what keeps a concurrent seed from reading a file mid-relink.
    if optimise {
        report_optimise(&nix_store, &layout.store_dir(), "shared store", pal);
    }
}

/// Deduplicate one store and report the gain, naming which store it was. Best-effort: a failure is
/// reported and does not fail the surrounding collection, since nothing was reclaimed either way.
fn report_optimise(
    nix_store: &std::path::Path,
    store_dir: &std::path::Path,
    label: &str,
    pal: &crate::style::Palette,
) {
    let (h, r, ok) = (pal.head, pal.reset, pal.ok);
    match crate::sandbox::gc::optimise(nix_store, store_dir) {
        Ok(report) if report.inodes_freed == 0 && report.bytes_freed == 0 => {
            println!("{h}sbx gc:{r} {label} — already deduplicated, nothing to reclaim.");
        }
        Ok(report) => println!(
            "{h}sbx gc:{r} {label} — {ok}deduplicated{r}: freed {} across {} inode(s).",
            crate::sandbox::gc::human_bytes(report.bytes_freed),
            report.inodes_freed,
        ),
        Err(e) => crate::diag::error(&format!("sbx gc: {label} — deduplication failed: {e}")),
    }
}

/// The in-store `sbx-flake-<name>` gcroot names of every **declared** inline `[flakes.<name>]`,
/// which is the keep-set `sbx gc` reconciles those roots against.
///
/// Declared, **not** trusted — the same rule [`packages::project_gcroot_names`] states for the
/// data-dir out-links, and for the same reason. This was read through
/// [`packages::flake_inline_packages`], which filters to `TrustState::Trusted` because it decides
/// what is actually built and bound; that made a lapse in project trust indistinguishable from a
/// removal. One edit to `sbx.toml` turns every inline flake `Changed`, and the next `sbx gc
/// --prune` would then drop the roots of flakes the config still declares and collect their
/// builds. Trust decides what runs; only a package no longer declared at all is a removal.
///
/// [`packages::project_gcroot_names`]: crate::sandbox::packages::project_gcroot_names
/// [`packages::flake_inline_packages`]: crate::sandbox::packages::flake_inline_packages
fn inline_flake_gcroot_names(packages: &[crate::config::Package]) -> Vec<String> {
    packages
        .iter()
        .filter(|p| matches!(p.backend, crate::config::Backend::FlakeInline { .. }))
        .map(|p| p.name.clone())
        .collect()
}

/// Why `sbx gc` must not collect this project's store right now, or `None` when it may.
///
/// Collecting a store a running cage reads and writes could drop a path it still needs, so the
/// registry is consulted first. The unreadable case is the point of this function: the check used
/// to be `if let Ok(sessions) = …`, which turned "I cannot tell you what is running" into "nothing
/// is running" and let the sweep proceed unguarded against a live cage. Not being able to read the
/// registry is not evidence that it is empty, so it refuses — matching `Registry::scan`, which
/// already skips individual unreadable records rather than reporting an empty list for the same
/// reason. A missing `sessions/` directory is not an error there (it lists empty), so this cannot
/// refuse on a cold data directory.
fn gc_live_session_refusal(
    listed: std::io::Result<Vec<crate::session::Session>>,
    project: &Path,
) -> Option<String> {
    match listed {
        Ok(sessions) if sessions.iter().any(|s| s.project == project) => Some(
            "sbx gc: a sandbox is running in this project — stop it first (see `sbx session ls`)."
                .to_string(),
        ),
        Err(e) => Some(format!(
            "sbx gc: cannot read the session registry ({e}) — refusing to collect, because a live \
             sandbox holding this project cannot be ruled out."
        )),
        Ok(_) => None,
    }
}

/// Reclaim the current project's own writable store.
///
/// The agent self-equips into a per-project store — `flake:` builds, in-cage installs — and over
/// time a flake revision rolled forward by `sbx upgrade flake` (or a package removed outright)
/// leaves the previous build behind. This reclaims it. Everything the project still needs is
/// gc-rooted by a **host-resolvable** root (one whose target is a `/nix/store/<hash>` path, which
/// the relocated store reads both in-cage and host-side): the seeded base and `nix:` tools are
/// rooted at seed time, mise installs root themselves the same way, and each `flake:` build
/// registers a root keyed by package name that a roll re-points — so the current build survives and
/// the rolled-away one, now unrooted, is collected. A removed package's lingering root (which a
/// roll's overwrite cannot reach) is dropped first, by name, against the set the current config
/// still declares across every runtime. A plain host-side `nix-store --gc` then does the rest with
/// no per-home enumeration: the rooting lives in the store, keyed by build, not in any home — which
/// is why a `flake:` package in an app's own `$HOME` needs no special handling.
///
/// A dry run by default — it reports what would be freed and changes nothing; `--prune` sweeps the
/// dead paths. It refuses while a live sandbox holds the project (its store is in use). Like a
/// launch it provisions the current tools and re-seeds first, which re-establishes the base/tool
/// roots on a store seeded before rooting existed, so a sweep can never delete the unrooted base.
/// Returns `Err(code)` when it cannot run (not a project, no sandbox capability, a nix failure),
/// which the caller treats as fatal — except under `--all`, where the reap has already run.
///
/// Limitation (a follow-up): a build the agent roots only by an in-cage path — a raw `nix build
/// --out-link <non-store-path>` it runs itself, outside the supported self-equip paths (`sbx mise`,
/// `nix profile`, declared `flake:` packages) — is not seen host-side and would be collected. The
/// supported self-equip paths all root by store path, so they survive.
fn sweep_current(prune: bool, optimise: bool, pal: &crate::style::Palette) -> Result<(), ExitCode> {
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);

    // A project that was never launched has no store to reclaim — and finding that out must not
    // cost anything, so the check runs **before** `prepare()`. Preparing provisions the base
    // userland, so on a cold data directory it downloads an entire toolchain only to then report
    // that there is nothing to reclaim. Its two inputs are exactly the ones `prepare` derives (the
    // process's directory and the data-directory layout), so the identity is the same either way;
    // where either is unavailable the check is skipped and `prepare` below reports that failure in
    // its own words rather than this path second-guessing it. This is also what makes `sbx gc
    // --all` safe to run from any directory: a non-project cwd is skipped, never provisioned.
    let early = std::env::current_dir()
        .ok()
        .zip(Layout::from_env())
        .and_then(|(cwd, layout)| Some((layout, binds::project_identity(&cwd).ok()?)));
    if let Some((layout, (id, project))) = &early
        && !crate::sandbox::projectstore::store_exists(layout, id)
    {
        println!(
            "{h}sbx gc{r} — {n}{}{r}: {dim}no per-project store yet, nothing to reclaim.{r}",
            project.display()
        );
        return Ok(());
    }

    let prep = prepare()?;

    let (id, project) = match binds::project_identity(&prep.cwd) {
        Ok(v) => v,
        Err(e) => {
            crate::diag::error(&format!(
                "sbx gc: cannot resolve the project directory: {e}"
            ));
            return Err(ExitCode::FAILURE);
        }
    };

    // Refuse if a live sandbox holds this project: collecting a store a running cage reads and
    // writes could drop a path it still needs. The registry list prunes dead records as it goes.
    if let Some(refusal) = gc_live_session_refusal(
        crate::session::Registry::at(prep.layout.data_dir()).list(),
        &project,
    ) {
        crate::diag::error(&refusal);
        return Err(ExitCode::FAILURE);
    }

    // Surface what the trust gate dropped or withheld, exactly as a launch would.
    for warning in &prep.cfg.warnings {
        crate::diag::warn_config(warning);
    }

    // Provision the project's declared tools and seed its store: the seed gc-roots the base and
    // every `nix:` tool, so the sweep keeps them and collects only orphans — and this re-roots a
    // store seeded before rooting existed. The `flake:` builds carry their own roots from launch.
    let store = equip_for_gc(&prep)?;
    let store_dir = store.store_dir().to_path_buf();

    // Drop the in-cage `sbx-flake-<name>` roots of removed inline `[flakes.<name>]` flakes. Only an
    // inline flake builds in-cage and registers this root (a remote `flake:` is provisioned host-side
    // and carries a data-dir out-link, pruned by `prune_project_package_roots` below); the root is
    // name-keyed and overwritten each launch, so an edit self-cleans, but a removal leaves it pointing
    // at an unwanted build — this prunes those so the sweep reclaims them. The current set spans every
    // runtime — the baseline and each app's merged packages — so an inline flake declared only in an
    // app keeps its root.
    let mut flake_names: std::collections::BTreeSet<String> =
        inline_flake_gcroot_names(&prep.cfg.packages)
            .into_iter()
            .collect();
    // The host-provisioned data-dir out-links a removed package leaks: `<data>/gcroots/projects/<id>/
    // <name>` (bare `<name>` for `nix:`, `deb-`/`appimage-`/`tarball-<name>` for a prebuilt) is
    // add-only, so a package no longer declared keeps its out-link — which reads into the keep-set
    // below and holds its per-project store copy forever. Collect the currently-declared set across
    // the same runtimes as the flake names (declared, not trusted: a still-declared package whose
    // trust has merely lapsed must keep its heavy build — see `packages::project_gcroot_names`).
    let mut package_names: std::collections::BTreeSet<String> =
        crate::sandbox::packages::project_gcroot_names(&prep.cfg.packages)
            .into_iter()
            .collect();
    for app in prep.cfg.apps.values() {
        let mut merged = prep.cfg.clone();
        merged.merge_app(app.clone());
        flake_names.extend(inline_flake_gcroot_names(&merged.packages));
        package_names.extend(crate::sandbox::packages::project_gcroot_names(
            &merged.packages,
        ));
    }
    let data_gcroots = prep.layout.data_dir().join("gcroots");
    // Drop the removed packages' roots — flake (inside the project store) and host-provisioned (in the
    // data dir) — *before* the keep-set is read below, so a dropped data-dir out-link no longer holds
    // its per-project seed copy and this same pass reclaims it.
    let pruned = crate::sandbox::gc::prune_flake_roots(&store_dir, &flake_names, prune).len()
        + crate::sandbox::gc::prune_project_package_roots(
            &data_gcroots,
            &id,
            &package_names,
            prune,
        )
        .len();

    // Reconcile the seed roots too. `gcroot_roots` is add-only, so a superseded build — an old base
    // revision, a rebuilt tool, an app version rolled forward — keeps a permanent direct root and
    // `nix-store --gc` never collects it: the store otherwise accumulates every version ever
    // provisioned. Drop the seed roots whose build no current out-link references so the sweep
    // reclaims them. The keep-set is the union of every out-link family, which only gc (never a
    // single launch's seed) sees.
    // Read off the reference this launch actually resolved, not a second derivation of it: `prep`
    // already holds it, and re-deciding the channel here would have to know which app this is — a
    // fact the sweep has no reason to carry, and would get wrong the day it went stale.
    let base_rev = crate::store::revision_of(&prep.nixpkgs);
    let mise_revs = crate::store::live_mise_revisions(&prep.layout);
    // Prune only when the base *and* mise out-links for the current revisions are present: those two
    // families root the irreducible userland (mise on its own revision, not the base one), so without
    // them the keep-set could omit a current core build and the sweep would delete it. A missing
    // family means we cannot safely tell superseded from sole-current, so skip — a re-provision on
    // the next launch is cheap, a wrongful wipe is not. This out-link check is the whole guard: the
    // revision itself is always known here (the launch resolved it above), so there is no
    // "unknown revision" case to fall through, and pretending there is would hide which condition
    // actually protects the sweep.
    let superseded = if data_gcroots.join("base").join(base_rev).is_dir()
        && mise_revs
            .iter()
            .any(|m| data_gcroots.join("mise").join(m).is_dir())
    {
        // `id` is `project_identity(cwd).0` — the very value `project_runtime_id` returns and the
        // provisioning path keys `<data>/gcroots/projects/<id>/` on — so the projects family of the
        // keep-set cannot drift from where a project's app builds are actually rooted.
        // Every live base revision, not this project's alone: an app installed here may sit on a
        // revision of its own, and a keep-set built from one would let the sweep take that app's
        // base out from under it.
        let base_revs = crate::store::live_base_revisions(&prep.layout);
        let keep =
            crate::sandbox::gc::project_keep_roots(&data_gcroots, &id, &base_revs, &mise_revs);
        crate::sandbox::gc::prune_superseded_roots(&store_dir, &keep, prune).len()
    } else {
        0
    };

    println!("{h}sbx gc{r} — {n}{}{r}", project.display());
    let report = match crate::sandbox::gc::collect(&prep.nix_store, &store_dir, prune) {
        Ok(r) => r,
        Err(e) => {
            crate::diag::error(&format!("sbx gc: {e}"));
            return Err(ExitCode::FAILURE);
        }
    };
    if prune {
        // The dropped roots' builds were unrooted before the sweep, so they are already counted in
        // `report.paths`; name how many roots this pass dropped — removed-package flakes plus
        // superseded seed builds — to explain where the collection came from.
        println!(
            "  {}collected{} {} store path(s) ({} from removed package(s), {} superseded build(s)), freed {}.",
            pal.ok,
            r,
            report.paths,
            pruned,
            superseded,
            crate::sandbox::gc::human_bytes(report.bytes)
        );
    } else {
        // A dry run cannot size the roots it would drop (their builds are still held, so not yet in
        // the dead set), so report their counts separately from the currently-dead total.
        println!(
            "  {}",
            crate::style::dim_prose(
                &format!(
                    "{} store path(s) collectable now, {} would be freed — run `sbx gc --prune` to reclaim.",
                    report.paths,
                    crate::sandbox::gc::human_bytes(report.bytes)
                ),
                pal
            )
        );
        if pruned > 0 || superseded > 0 {
            println!(
                "  {dim}and {pruned} removed-package build(s) + {superseded} superseded build(s) would also be reclaimed.{r}"
            );
        }
    }

    // After the collection, so nothing about to be deleted is deduplicated first. This is the store
    // where deduplication pays: a seeded per-project store arrives as fresh inodes by construction.
    //
    // Unlike the shared store's pass this takes no exclusive lock — a per-project store has none.
    // What guards it is the live-session refusal above: the sweep already declines to touch a store
    // a running cage holds, and this rides that same check, with the same window between it and the
    // work that `--prune` already has here.
    if optimise {
        report_optimise(&prep.nix_store, &store_dir, "this project's store", pal);
    }
    Ok(())
}

/// After an `sbx upgrade` roll, surface — cheaply and best-effort — how many superseded builds the
/// current project's store already holds, pointing at `sbx gc --prune` to reclaim them. A roll is
/// what eventually supersedes a build, so upgrade is the natural moment to remind. Pure filesystem
/// reads: it reuses the gc keep-set derivation over the existing store without provisioning or
/// invoking nix, so it adds no weight to upgrade. Silent when there is no store, when the keep-set
/// guard (the base and mise out-links for the current revisions) cannot be met, or when nothing is
/// superseded — the same guard [`sweep_current`] prunes under, so the count never over-reports (a
/// just-rolled revision whose build is still deferred to the next launch fails the guard, so the
/// hint waits until the superseded state is real).
///
/// `app` is the roll's `--app` selector, so the revision this measures is the one that roll
/// actually moved: an app with its own lock is on its own revision, and reading the project's here
/// would count against a base the app is not on.
pub(crate) fn superseded_reclaimable_hint(
    layout: &Layout,
    cwd: &Path,
    cfg: &crate::config::Resolved,
    app: Option<&str>,
    pal: &crate::style::Palette,
) {
    let Ok(id) = binds::project_runtime_id(cwd) else {
        return;
    };
    if !crate::sandbox::projectstore::store_exists(layout, &id) {
        return;
    }
    let Some(rev) = effective_lock_target(cwd, layout, cfg, app)
        .ok()
        .and_then(|t| t.locked_revision())
    else {
        return;
    };
    let data_gcroots = layout.data_dir().join("gcroots");
    let mise_revs = crate::store::live_mise_revisions(layout);
    if !data_gcroots.join("base").join(&rev).is_dir()
        || !mise_revs
            .iter()
            .any(|m| data_gcroots.join("mise").join(m).is_dir())
    {
        return;
    }
    let store_dir = crate::sandbox::projectstore::store_dir_for(layout, &id);
    // The whole live set, for the reason the pruning path above states.
    let base_revs = crate::store::live_base_revisions(layout);
    let keep = crate::sandbox::gc::project_keep_roots(&data_gcroots, &id, &base_revs, &mise_revs);
    let n = crate::sandbox::gc::prune_superseded_roots(&store_dir, &keep, false).len();
    if n > 0 {
        println!(
            "  {}",
            crate::style::dim_prose(
                &format!(
                    "{n} superseded build(s) in this project's store are reclaimable — run `sbx gc --prune`."
                ),
                pal
            )
        );
    }
}

/// Provision the project's declared tools and seed its store, returning the store. Mirrors
/// the provisioning a launch does — native `[packages]`, `nix:` tools, and (under the GUI
/// hole) fonts — so the seed gc-roots the same set a launch would, but stops at the seed: gc
/// needs the rooted store, not a runnable cage.
///
/// It inherits a launch's strictness — a withheld (untrusted) tool only warns, but an admitted
/// tool that cannot be realised is fatal — so gc shares a launch's provisioning (and its
/// network need). For protecting the base only the base roots matter, and those come from
/// `prep.userland` without provisioning; re-provisioning the rest keeps gc's rooted set in
/// lockstep with a launch's at the cost of that coupling — an accepted trade for a single
/// source of the project's root set.
fn equip_for_gc(prep: &Prepared) -> Result<crate::sandbox::projectstore::ProjectStore, ExitCode> {
    let mut packages = crate::sandbox::packages::provision(
        &prep.nix,
        &prep.layout,
        &prep.cwd,
        &prep.nixpkgs,
        &prep.cfg.packages,
    )
    .map_err(|e| {
        crate::diag::error(&format!("sbx gc: {e}"));
        ExitCode::FAILURE
    })?;
    for warning in &packages.warnings {
        crate::diag::warn_config(warning);
    }

    // The prebuilt backends are host-side like `nix:`, so their roots must be part of the gc seed
    // too — otherwise the per-project store copy would be collected and re-provisioned every launch.
    // When warm (pinned + built) this is a fast no-op; it mirrors the launch path's provisioning.
    let ctx = prebuilt_ctx(prep);
    for kind in crate::sandbox::prebuilt::DIRECT_ORDER {
        for (name, url) in kind.packages(&prep.cfg.packages) {
            let decor = crate::sandbox::prebuilt::decor_of(&prep.cfg.packages, &name);
            match crate::sandbox::prebuilt::provision(kind, &ctx, &name, &url, &decor) {
                Ok((_, root)) => packages.roots.push(root),
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx gc: cannot provision {} package `{name}` ({url}): {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    // A `<backend>:resolve` package: build from its EXISTING pin only — gc must never run the resolve
    // command or touch the network. An unpinned package (never launched) has nothing built to keep,
    // so it is skipped rather than resolved.
    for kind in crate::sandbox::prebuilt::RESOLVE_ORDER {
        for (name, _command) in kind.resolve_packages(&prep.cfg.packages) {
            let decor = crate::sandbox::prebuilt::decor_of(&prep.cfg.packages, &name);
            match crate::sandbox::prebuilt::provision_resolve_pinned(kind, &ctx, &name, &decor) {
                Ok(Some((_, root))) => packages.roots.push(root),
                Ok(None) => {}
                Err(e) => {
                    crate::diag::error(&format!(
                        "sbx gc: cannot build the pinned {} resolver package `{name}`: {e}",
                        kind.name()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }

    let tools = mise_tools(prep)?;
    for warning in &tools.warnings {
        crate::diag::warn_config(warning);
    }

    let font_layer = if prep.cfg.gui.renders() {
        crate::sandbox::fonts::provision(&prep.nix, &prep.layout, &prep.nixpkgs).ok()
    } else {
        None
    };
    let mut gui_roots: Vec<PathBuf> = font_layer
        .as_ref()
        .map_or_else(Vec::new, |l| l.roots.clone());

    // mesa driver roots under `gpu = true`, so gc keeps the built output rather than collecting and
    // re-provisioning it each launch — mirroring the launch path's GPU provisioning and the fonts.
    // GLVND comes with it where this host has an NVIDIA bridge: it is provisioned on the same
    // condition, so it has to be retained on the same condition or gc would collect what the next
    // launch rebuilds.
    if prep.cfg.gpu
        && let Ok(layer) = crate::sandbox::gpu::provision(
            &prep.nix,
            &prep.layout,
            &prep.nixpkgs,
            crate::sandbox::gpu::nvidia_bridge().as_ref(),
        )
    {
        gui_roots.push(layer.root);
        gui_roots.extend(layer.glvnd);
    }

    // audio userspace roots under `audio = true`, same reason: gc keeps the client libraries and
    // ALSA shim rather than collecting and re-provisioning them each launch.
    if prep.cfg.audio
        && let Ok(layer) = crate::sandbox::audio::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.extend(layer.roots);
    }

    // GUI data root (GSettings schemas + GTK themes) under `gui = "wayland"`, same reason: gc keeps
    // the provisioned output.
    if matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland)
        && let Ok(layer) =
            crate::sandbox::guidata::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.push(layer.root);
    }

    // In-cage portal roots under `gui = "wayland"` + `dbus = true`: gc keeps the portal closure.
    if prep.cfg.dbus
        && matches!(prep.cfg.gui, crate::config::GuiPolicy::Wayland)
        && let Ok(p) = crate::sandbox::portal::provision(&prep.nix, &prep.layout, &prep.nixpkgs)
    {
        gui_roots.extend(p.roots);
    }

    seed_project_store(prep, &packages.roots, &tools.roots, &gui_roots).map_err(|e| {
        crate::diag::error(&format!("sbx gc: cannot prepare the project's store: {e}"));
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests;
