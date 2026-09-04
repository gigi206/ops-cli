//! The two `sbx upgrade` sub-rolls that need a cage — `upgrade_mise_packages` and
//! `upgrade_provision_steps` — with the groups they roll over, the task-pool roll beside them, and
//! the aligned report all three print.
//!
//! Batch drivers over the launch machinery rather than a launch: each one prepares a cage per
//! group, runs a single captured command in it, and reports what moved. Nothing here is on the
//! path an interactive `sbx run` takes.
//!
//! A group is the unit because a roll is only meaningful per home: the baseline packages and each
//! app's own pool install into different trees, and rolling them together would move a version in
//! a cage that never asked for it.

use super::build::build;
use super::cage::{echo_cage_output, run_captured};
use super::equip::mise_upgrade_cmd;
use super::startup::provision_only_cmd;
use super::*;

/// Which persistent home a `mise:` package group is equipped in, owning its app name so a
/// group can outlive the config it was derived from. Mirrors [`binds::Runtime`], which borrows
/// the name; [`GroupHome::runtime`] rebuilds the borrowing form at launch.
enum GroupHome {
    /// The project's default shell home — where `sbx run` equip baseline tools.
    ProjectDefault,
    /// An app's home shared across projects (`home_scope = "global"`).
    GlobalApp(String),
    /// An app's per-project home (`home_scope = "project"`).
    ProjectApp(String),
}

impl GroupHome {
    fn runtime(&self) -> binds::Runtime<'_> {
        match self {
            GroupHome::ProjectDefault => binds::Runtime::ProjectDefault,
            GroupHome::GlobalApp(name) => binds::Runtime::GlobalApp(name),
            GroupHome::ProjectApp(name) => binds::Runtime::ProjectApp(name),
        }
    }

    fn label(&self) -> String {
        match self {
            GroupHome::ProjectDefault => "project".to_string(),
            GroupHome::GlobalApp(name) | GroupHome::ProjectApp(name) => format!("app: {name}"),
        }
    }

    /// The bare display name for the report column and the recap list — the app name, or `project`
    /// for the baseline. Unlike [`GroupHome::label`] it carries no `app:` prefix, so a run of them
    /// aligns cleanly.
    fn name(&self) -> String {
        match self {
            GroupHome::ProjectDefault => "project".to_string(),
            GroupHome::GlobalApp(name) | GroupHome::ProjectApp(name) => name.clone(),
        }
    }
}

/// One in-cage `mise:` roll: the home that equips these tokens, the merged config to launch it
/// with, and the tokens to advance.
struct MiseGroup {
    home: GroupHome,
    cfg: crate::config::Resolved,
    tokens: Vec<String>,
}

/// The `mise:` `[packages]` groups to roll forward — generic over every declared group: the
/// project baseline (equipped in its default home by `sbx run`) and each app
/// (equipped in its own home, keyed by `home_scope`), each with its merged trusted `mise:`
/// token set. A group with no trusted `mise:` token — and an app with no command — is omitted,
/// so a project or app without any produces no cage, and no app is special-cased. Trusted-only
/// by construction, since [`crate::sandbox::packages::mise_packages`] keeps only trusted tokens. Pure
/// over the resolved config (it clones to merge each app), so the grouping is unit-tested
/// without launching a cage.
fn mise_package_groups(cfg: &crate::config::Resolved, only: Option<&str>) -> Vec<MiseGroup> {
    let mut groups = Vec::new();

    // The project baseline, equipped in the default shell home. Dropped under `--app`: the
    // baseline is not an app, so keeping it would make the selector roll project-wide work.
    let baseline = crate::sandbox::packages::mise_packages(&cfg.packages);
    if !baseline.is_empty() && only.is_none() {
        groups.push(MiseGroup {
            home: GroupHome::ProjectDefault,
            cfg: cfg.clone(),
            tokens: baseline,
        });
    }

    // Each app, in its own home. Merging folds the baseline packages in (an app's cage equips
    // both layers), so the token set is exactly the one the app's launch equips.
    for (name, app) in &cfg.apps {
        if only.is_some_and(|want| want != name) {
            continue;
        }
        if app.cmd.is_empty() {
            continue; // an unlaunchable app never equips anything
        }
        let home = match app.home_scope {
            crate::config::AppHomeScope::Global => GroupHome::GlobalApp(name.clone()),
            crate::config::AppHomeScope::Project => GroupHome::ProjectApp(name.clone()),
        };
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        let tokens = crate::sandbox::packages::mise_packages(&merged.packages);
        if tokens.is_empty() {
            continue;
        }
        groups.push(MiseGroup {
            home,
            cfg: merged,
            tokens,
        });
    }
    groups
}

/// How many declared `mise:` packages are withheld for being untrusted — across the project
/// baseline and each app's own overlay. Only a count: the per-package withholding reason is
/// already warned on the launch path, so `sbx upgrade` just needs to not read as "none declared".
fn withheld_mise_packages(cfg: &crate::config::Resolved, only: Option<&str>) -> usize {
    let untrusted_mise = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Mise(_))
                    && p.state != crate::trust::TrustState::Trusted
            })
            .count()
    };
    // Under `--app`, count what that app's cage would have equipped and nothing else — both its own
    // packages and the baseline it folds in. Reporting the project's total there would attribute
    // another app's withheld package to this roll.
    let baseline = untrusted_mise(&cfg.packages);
    match only {
        Some(name) => match cfg.apps.get(name) {
            Some(app) => baseline + untrusted_mise(&app.packages),
            None => 0,
        },
        None => {
            baseline
                + cfg
                    .apps
                    .values()
                    .map(|app| untrusted_mise(&app.packages))
                    .sum::<usize>()
        }
    }
}

/// Roll the project's and its apps' `mise:` `[packages]` forward, in-cage. A `mise:` package is
/// equipped by `mise use -g --pin <token>` at launch and is frozen there at the installed version —
/// frozen *because* of the pin, which writes the resolved version into the cage's config so a later
/// launch has nothing left to resolve. A floating request would not have held: the tool on the PATH
/// is a mise shim that re-resolves it on every exec. So advancing the version means running
/// `mise upgrade --bump <token>` in the same cage — the equip environment,
/// so the fetch rides the app's egress allowlist. Generic over [`mise_package_groups`]: the
/// project baseline (its default home) and each app (its own home), no app special-cased.
///
/// Trusted-only by construction. Returns whether every group rolled cleanly; a group that fails
/// makes this `false` but never aborts the others.
///
/// Unlike the host-side lock rewrites (`nix:`, the engine, `nix:` tools), the roll needs the
/// sandbox — but only when there is something to roll: the groups are computed from the
/// already-resolved `cfg` first, so a project with no `mise:` package costs nothing here and
/// `sbx upgrade nix`/`all` keeps its cheap, sandbox-free common path. With work to do, a host
/// that cannot sandbox warns and rolls nothing rather than failing (best-effort, like the
/// cgroup limits).
pub(crate) fn upgrade_mise_packages(
    cwd: &Path,
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
    only: Option<&str>,
) -> bool {
    let (h, warn, dim, r, ok_c) = (pal.head, pal.warn, pal.dim, pal.reset, pal.ok);
    println!("{h}sbx upgrade — mise packages{r}");
    let groups = mise_package_groups(cfg, only);
    // Surface withheld (untrusted) `mise:` packages so an untrusted project does not silently
    // read as "nothing declared" — parity with the `nix:` tools path, which warns the same.
    let withheld = withheld_mise_packages(cfg, only);
    if withheld > 0 {
        println!(
            "{}",
            crate::style::prose(
                &format!(
                    "  {warn}{withheld} mise: package(s) withheld (untrusted){r} — not rolled; run `sbx trust`."
                ),
                pal
            )
        );
    }
    // The declared operations' own tool pool rolls here too: it is filled by `mise use -g`, which
    // records a spec the launch then short-circuits on, so without this pass a pool tool would be
    // frozen at whatever the first fill resolved.
    let pool_tokens: Vec<String> = cfg
        .tasks
        .iter()
        .flat_map(|t| t.packages.iter().cloned())
        .fold(Vec::new(), |mut acc, t| {
            if !acc.contains(&t) {
                acc.push(t);
            }
            acc
        });

    if groups.is_empty() && pool_tokens.is_empty() {
        if withheld == 0 {
            println!("  {dim}no mise: packages to roll.{r}");
        }
        return true;
    }

    // Only now, with something to roll, take on the sandbox prerequisites — against `cwd`, the
    // project being upgraded, so `--project` builds the roll cage in that project's store and home
    // rather
    // than wherever the command was invoked.
    let mut prep = match prepare_in(cwd.to_path_buf(), &crate::config::Override::none(), only) {
        Ok(p) => p,
        Err(_) => {
            // prepare_in already printed the pointed reason (missing bwrap/userns/nix).
            crate::diag::warn("mise packages: skipped — no usable sandbox; see `sbx doctor`");
            return true;
        }
    };

    // One cage per app: the lines `build` prints about how it assembled each one — the equipping
    // line, the standing broker's note — repeat for every app and bury the roll result. Silenced
    // here, where the report names each app anyway.
    prep.in_batch = true;
    // A roll fetches packages; the credentials an app declares are for the traffic it makes when it
    // actually runs. One that cannot be resolved now denies its own destination for this cage
    // instead of failing the upgrade — the roll never sends it, and an app whose token endpoint is
    // briefly unavailable is still an app whose tools can move forward.
    prep.unresolved_secret = crate::sandbox::egress::Unresolved::DenyDestination;

    // Every group name is known up front, so the result lines are dot-leader aligned to one column
    // even though each prints live (as its cage finishes) to keep progress visible over a long
    // multi-app roll. A closing recap then names exactly which apps advanced.
    let width = groups
        .iter()
        .map(|g| g.home.name().chars().count())
        .max()
        .unwrap_or(0);

    let mut ok = true;
    let mut rolled: Vec<String> = Vec::new();
    // Groups whose roll moved a tool somewhere the versions do not call forward. Kept apart from
    // `rolled` rather than counted with it: the recap's job is to answer "what changed?", and a
    // tool walked back to an earlier release line is the one answer a user has to act on.
    let mut not_forward: Vec<String> = Vec::new();
    let (mut up_to_date, mut skipped, mut failed) = (0usize, 0usize, 0usize);

    for group in groups {
        let MiseGroup { home, cfg, tokens } = group;
        let name = home.name();
        // `network = "none"` cannot fetch — the launch skips the equip there — so skip the roll
        // too (the tool stays at its persisted version). Not a failure: it is the declared posture.
        if matches!(cfg.network, crate::config::NetworkPolicy::Isolated) {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{dim}network \"none\" — skipped{r}"),
                    pal
                )
            );
            skipped += 1;
            continue;
        }

        // Launch a cage in this group's home with its merged config so `build` sees the right
        // network/packages/home. The baseline warnings were already surfaced by `upgrade_cmd`,
        // so clear them to avoid one repeat per cage. The command is `mise upgrade <tokens>`; the
        // launch's own `mise use -g` equip wrap runs first (a warm no-op once installed, or a
        // fresh equip if the app was never launched), then the upgrade rolls the version.
        let runtime = home.runtime();
        let mut cfg = cfg;
        cfg.warnings.clear();
        prep.cfg = cfg;

        let cmd = mise_upgrade_cmd(
            runtime,
            &prep.userland.mise_bin,
            &prep.userland.shell_bin,
            &tokens,
        );

        let (spec, guard) = match build(&prep, runtime, cmd) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "{}",
                    roll_line(&name, width, &format!("{warn}failed to launch{r}"), pal)
                );
                failed += 1;
                ok = false;
                continue;
            }
        };
        // Fork-and-wait (never exec-replace) so the next group can run; the guard, if any, is
        // held across the wait so the proxy/forwarder serves the fetch, then dropped as the group
        // ends (unlinks the sockets and CA). The cage's output is captured (not streamed): on a
        // clean roll only mise's own version-transition summary is surfaced; the install/progress
        // noise is shown only when the roll fails, so its cause is visible.
        let (code, out) = run_captured(&prep.bwrap, &spec, &prep.cfg.limits);
        drop(guard);
        if code == 0 {
            match mise_transitions(&out).as_slice() {
                [] if mise_up_to_date(&out) => {
                    println!(
                        "{}",
                        roll_line(&name, width, &format!("{dim}up to date{r}"), pal)
                    );
                    up_to_date += 1;
                }
                [] => {
                    println!(
                        "{}",
                        roll_line(&name, width, &format!("{ok_c}upgraded{r}"), pal)
                    );
                    rolled.push(name);
                }
                [only] => {
                    // The token is redundant with the name column, so show just the version delta.
                    let delta = only.split_once(' ').map_or(only.as_str(), |(_, v)| v);
                    match transition_regression(only) {
                        Some(reg) => {
                            println!(
                                "{}",
                                roll_line(
                                    &name,
                                    width,
                                    &format!("{warn}{delta} — {}{r}", reg.describe()),
                                    pal
                                )
                            );
                            not_forward.push(name);
                        }
                        None => {
                            println!(
                                "{}",
                                roll_line(&name, width, &format!("{ok_c}{delta}{r}"), pal)
                            );
                            rolled.push(name);
                        }
                    }
                }
                many => {
                    // A group that rolled several tokens: a count on the aligned line, then each
                    // full `<token> <old> → <new>` transition indented below it. One token that did
                    // not move forward names itself on its own line and decides the group's colour,
                    // so a single walked-back tool cannot hide inside a count of its siblings.
                    let back = many
                        .iter()
                        .filter(|t| transition_regression(t).is_some())
                        .count();
                    let status = if back > 0 {
                        format!("{warn}{} tools rolled, {back} not forward{r}", many.len())
                    } else {
                        format!("{ok_c}{} tools rolled{r}", many.len())
                    };
                    println!("{}", roll_line(&name, width, &status, pal));
                    for t in many {
                        match transition_regression(t) {
                            Some(reg) => println!("       {warn}{t} — {}{r}", reg.describe()),
                            None => println!("       {ok_c}{t}{r}"),
                        }
                    }
                    if back > 0 {
                        not_forward.push(name);
                    } else {
                        rolled.push(name);
                    }
                }
            }
        } else {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{warn}mise upgrade exited {code}{r}"),
                    pal
                )
            );
            crate::diag::warn(&format!("`{}`: mise upgrade exited {code}", home.label()));
            echo_cage_output(&out);
            failed += 1;
            ok = false;
        }
    }

    // The task tool pool, rolled host-side rather than in a cage (that is where it is filled). Its
    // own line, because it belongs to the declared operations, not to any app.
    if !pool_tokens.is_empty() {
        // Counted into the same tallies the apps use, so the closing recap can never read
        // "nothing to roll" one line under a pool that rolled.
        match roll_task_pool(cwd, &mut prep, cfg) {
            Ok(true) => {
                println!(
                    "{}",
                    roll_line("task pool", width.max(9), &format!("{ok_c}rolled{r}"), pal)
                );
                rolled.push("task pool".to_string());
            }
            Ok(false) => {
                println!(
                    "{}",
                    roll_line(
                        "task pool",
                        width.max(9),
                        &format!("{dim}nothing to roll{r}"),
                        pal
                    )
                );
                up_to_date += 1;
            }
            Err(e) => {
                println!(
                    "{}",
                    roll_line("task pool", width.max(9), &format!("{warn}{e}{r}"), pal)
                );
                failed += 1;
                ok = false;
            }
        }
    }

    // Close with the one line that answers "what changed?": each rolled app — and the task tool
    // pool, when it rolled — by name, plus a tally of the rest, coloured by outcome (a failure
    // paints it a warning, a clean no-op dims).
    let recap = mise_roll_recap(&rolled, &not_forward, up_to_date, skipped, failed);
    let hue = if failed > 0 || !not_forward.is_empty() {
        warn
    } else if rolled.is_empty() {
        dim
    } else {
        ok_c
    };
    println!("  {hue}{recap}{r}");
    ok
}

/// One in-cage provision roll: the app whose bundles carry install steps, the merged config to
/// launch it with, and the steps to re-run.
struct ProvisionGroup {
    home: GroupHome,
    cfg: crate::config::Resolved,
    steps: Vec<crate::config::BundleProvision>,
}

/// The apps whose `use`d bundles carry an install step. Only apps: a `provision` is a bundle's
/// field, and a bundle only ever folds into an app, so there is no project-baseline group here —
/// the shape [`mise_package_groups`] needs. An app with no command is omitted (it can never
/// launch, so nothing installs for it), and the fold has already dropped the steps of an untrusted
/// layer, so this is trusted-only by construction. Pure over the resolved config, so the grouping
/// is unit-tested without launching a cage.
fn provision_groups(cfg: &crate::config::Resolved, only: Option<&str>) -> Vec<ProvisionGroup> {
    let mut groups = Vec::new();
    for (name, app) in &cfg.apps {
        if only.is_some_and(|want| want != name) {
            continue;
        }
        if app.cmd.is_empty() || app.provisions.is_empty() {
            continue;
        }
        let home = match app.home_scope {
            crate::config::AppHomeScope::Global => GroupHome::GlobalApp(name.clone()),
            crate::config::AppHomeScope::Project => GroupHome::ProjectApp(name.clone()),
        };
        let steps = app.provisions.clone();
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        groups.push(ProvisionGroup {
            home,
            cfg: merged,
            steps,
        });
    }
    groups
}

/// Run each app's bundle install steps — the roll for an agent that rides no `[packages]` backend.
///
/// A `nix:`/`mise:`/`deb:` package advances by re-resolving a lock; an agent its bundle *installs*
/// (a clone and a build, a vendor script) has no lock to rewrite, so what advances it is running
/// that install again. Which leaves one question, and `force` is it: who decides whether this run
/// installs anything.
///
/// **`force = false`** hands that decision to each step's own guard, and is what `sbx upgrade all`
/// asks for. A guard that compares the upstream release to what is installed then re-installs
/// exactly when something moved, and costs a few bytes of channel read when nothing did — so the
/// command that means "bring everything up to date" brings these up to date too, instead of naming
/// them and walking past. A guard that can only ask whether the agent is installed at all reports
/// nothing to do, which is all it can honestly say.
///
/// **`force = true`** raises `SBX_UPGRADE=1` in the cage, which every shipped guard is written to
/// yield to, and is what the `provision` verb and `sbx app upgrade` ask for. That is the only thing
/// that advances an agent whose guard *cannot* tell — a checkout of a branch, with no version to
/// compare — and the way to re-install over a guard that is simply wrong.
///
/// The cage is the app's own (its home, packages, egress, environment), so what the roll installs
/// is exactly what the next launch finds. The app's command never runs: the install is the point,
/// and launching the agent would make a version roll a launch. Returns whether every group ran
/// cleanly; a group that fails makes this `false` but never aborts the others.
pub(crate) fn upgrade_provision_steps(
    cwd: &Path,
    cfg: &crate::config::Resolved,
    pal: &crate::style::Palette,
    only: Option<&str>,
    force: bool,
) -> bool {
    let (h, warn, dim, r, ok_c) = (pal.head, pal.warn, pal.dim, pal.reset, pal.ok);
    println!("{h}sbx upgrade — bundle install steps{r}");
    let groups = provision_groups(cfg, only);
    if groups.is_empty() {
        println!("  {dim}no bundle install steps to re-run.{r}");
        return true;
    }

    // Only now, with work to do, take on the sandbox prerequisites — against `cwd`, so `--project`
    // retargets these cages the way it retargets every other roll.
    let mut prep = match prepare_in(cwd.to_path_buf(), &crate::config::Override::none(), only) {
        Ok(p) => p,
        Err(_) => {
            // prepare_in already printed the pointed reason (missing bwrap/userns/nix).
            crate::diag::warn("install steps: skipped — no usable sandbox; see `sbx doctor`");
            return true;
        }
    };
    prep.in_batch = true;
    // A roll fetches packages; the credentials an app declares are for the traffic it makes when it
    // actually runs. One that cannot be resolved now denies its own destination for this cage
    // instead of failing the upgrade — the roll never sends it, and an app whose token endpoint is
    // briefly unavailable is still an app whose tools can move forward.
    prep.unresolved_secret = crate::sandbox::egress::Unresolved::DenyDestination;

    let width = groups
        .iter()
        .map(|g| g.home.name().chars().count())
        .max()
        .unwrap_or(0);
    let mut ok = true;
    let (mut ran, mut skipped, mut failed) = (Vec::new(), 0usize, 0usize);

    for group in groups {
        let ProvisionGroup { home, cfg, steps } = group;
        let name = home.name();
        // An isolated cage cannot fetch, and every install step fetches something. Skipping is the
        // declared posture, not a failure — the same call `upgrade_mise_packages` makes.
        if matches!(cfg.network, crate::config::NetworkPolicy::Isolated) {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{dim}network \"none\" — skipped{r}"),
                    pal
                )
            );
            skipped += 1;
            continue;
        }

        let runtime = home.runtime();
        let mut cfg = cfg;
        cfg.warnings.clear();
        // The signal the steps' guards read, and only under `force`: without it each guard answers
        // for itself, which is the whole difference between "bring what moved up to date" and
        // "re-install regardless". It rides the app's `[env]` layer, so it reaches the cage the way
        // every other declared variable does — never on the bwrap argv.
        if force {
            cfg.env.push(("SBX_UPGRADE".to_string(), "1".to_string()));
        }
        prep.cfg = cfg;

        let (spec, guard) = match build(&prep, runtime, provision_only_cmd(&steps)) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "{}",
                    roll_line(&name, width, &format!("{warn}failed to launch{r}"), pal)
                );
                failed += 1;
                ok = false;
                continue;
            }
        };
        // Fork-and-wait so the next group runs; the guard holds the proxy/forwarder across the
        // fetch. The output is always shown on failure. On a clean run it is shown only when the
        // guards decided (`!force`), because there it is the only thing that says which way they
        // decided; under `force` the line above already says what happened, and an install is
        // verbose enough that repeating it would bury a fifty-app report.
        let (code, out) = run_captured(&prep.bwrap, &spec, &prep.cfg.limits);
        drop(guard);
        if code == 0 {
            let bundles = step_bundles(&steps);
            // What is KNOWN is the exit status, and the line says no more than that. Under `force`
            // the re-install was asked for, so naming it is fair; without it the guard decided, and
            // sbx cannot see which way — the version a guard compares lives in the vendor's channel
            // and in the vendor's own manifest, which is exactly why the guard is in the step.
            //
            // So the step's own output is what tells the user, and here it is SHOWN rather than
            // dropped: a step that acted says so (`… the release channel moved (a -> b)`), and one
            // that stood down says nothing. That is the step's account, not sbx's inference, which
            // is the only honest form this line can take.
            let verdict = if force {
                format!("{ok_c}re-installed ({bundles}){r}")
            } else {
                format!("{ok_c}install step ran ({bundles}){r}")
            };
            println!("{}", roll_line(&name, width, &verdict, pal));
            if !force {
                echo_cage_output(&out);
            }
            ran.push(name);
        } else {
            println!(
                "{}",
                roll_line(
                    &name,
                    width,
                    &format!("{warn}install step exited {code}{r}"),
                    pal
                )
            );
            crate::diag::warn(&format!("`{}`: install step exited {code}", home.label()));
            echo_cage_output(&out);
            failed += 1;
            ok = false;
        }
    }

    let recap = provision_roll_recap(&ran, skipped, failed, force);
    let hue = if failed > 0 {
        warn
    } else if ran.is_empty() {
        dim
    } else {
        ok_c
    };
    println!("  {hue}{recap}{r}");
    ok
}

/// The bundles a group's steps came from, named in order and each named once — an app may `use`
/// several bundles that install, and the roll line is where a reader learns which ran.
fn step_bundles(steps: &[crate::config::BundleProvision]) -> String {
    let mut names: Vec<&str> = Vec::new();
    for step in steps {
        if !names.contains(&step.bundle.as_str()) {
            names.push(&step.bundle);
        }
    }
    names.join(", ")
}

/// The closing line of a provision roll: which apps re-installed, and a tally of the rest.
fn provision_roll_recap(ran: &[String], skipped: usize, failed: usize, force: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    let (none, some) = if force {
        ("nothing re-installed", "re-installed")
    } else {
        ("no install step ran", "install steps ran")
    };
    if ran.is_empty() {
        parts.push(none.to_string());
    } else {
        parts.push(format!("{some}: {}", ran.join(", ")));
    }
    if skipped > 0 {
        parts.push(format!("{skipped} skipped"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    parts.join(" · ")
}

/// Roll the declared operations' tool pool forward. Returns whether anything was rolled, or the
/// reason it could not run.
///
/// The pool is filled and rolled **host-side**, so unlike an app's `mise:` packages this needs no
/// launch — only a spec to derive the task cage's skeleton from, which is what a pool tool runs
/// against. The spec is built for a command that never executes: `build` is the one place that
/// assembles the cage, and reproducing it here would be a second implementation of the thing whose
/// whole point is to be the same.
fn roll_task_pool(
    cwd: &Path,
    prep: &mut Prepared,
    cfg: &crate::config::Resolved,
) -> Result<bool, String> {
    let id = crate::sandbox::binds::project_runtime_id(cwd)
        .map_err(|e| format!("no project tree ({e})"))?;
    // The per-app loop above leaves `prep.cfg` on whichever app it rolled last. The pool belongs to
    // the project's declared operations, not to any app, so restore the baseline before deriving a
    // cage from it.
    prep.cfg = cfg.clone();
    let (spec, guard) = build(
        prep,
        binds::Runtime::ProjectDefault,
        vec![OsString::from("/bin/true")],
    )
    .map_err(|_| "cannot assemble a cage".to_string())?;
    let engine = crate::sandbox::task::TaskEngine::from_cage(
        &prep.bwrap,
        &spec,
        &prep.layout,
        cwd,
        cwd,
        cfg.tasks.clone(),
        cfg.limits.clone(),
        spec.cage_slug(),
        Some(prep.userland.ca_bundle_src.as_path()),
        crate::sandbox::task::CageForwarder {
            socat: prep.userland.socat_bin.clone(),
            shell: prep.userland.shell_bin.clone(),
        },
        cfg.redact_min_len,
    )
    .with_pool(
        crate::sandbox::taskpool::pool_dir(prep.layout.data_dir(), &id),
        prep.userland.mise_bin.clone(),
    );
    let outcome = engine.upgrade_pool().map_err(|e| e.to_string());
    // Dropped only now: the guard holds the launch's runtime files, and the roll runs against the
    // spec derived from them.
    drop(guard);
    match outcome? {
        None => Ok(false),
        Some(run) if run.ok => Ok(true),
        Some(run) => Err(pool_upgrade_failure(&run)),
    }
}

/// The roll report's status line for a pool upgrade that failed.
///
/// The tail quoted is [`crate::sandbox::taskpool::InstallRun::diagnostics`], not the stderr tail
/// alone: mise wraps backends that report a resolution failure on stdout while mise's own stderr
/// carries only progress that trims away to nothing, and this line is the operator's summary of
/// which it was. It lands on the roll report's aligned status column, beside sbx's own lines, so it
/// is sanitised like every other value the cage chose (see [`crate::sandbox::sanitize`]).
fn pool_upgrade_failure(run: &crate::sandbox::taskpool::InstallRun) -> String {
    format!(
        "mise upgrade failed: {}",
        crate::sandbox::sanitize(
            String::from_utf8_lossy(run.diagnostics())
                .trim()
                .lines()
                .last()
                .unwrap_or("no output")
        )
    )
}

/// The version-transition lines mise prints for a successful roll — `<token> <from> → <to>`, one per
/// upgraded tool — extracted from captured (non-TTY) output. The ` → ` (U+2192, space-padded) marker
/// is unique to these lines; mise's install/download progress and the `mise use -g` equip preamble
/// carry no arrow. Empty when nothing rolled (see [`mise_up_to_date`]). Pure — unit-tested against
/// real mise output.
///
/// Each surviving line goes through [`crate::sandbox::sanitize`] here rather than at the two places
/// that print one, because every one of these lines is a value the cage chose: the token half is
/// whatever the config asked mise to install, and the version half is whatever the backend
/// answered — for the registry, `aqua:` and `npm:` backends, a remote package server's string. The
/// roll report interleaves them with sbx's own trust and failure lines on the launching terminal,
/// so an escape sequence in one erases what sbx said above it.
pub(super) fn mise_transitions(captured: &str) -> Vec<String> {
    captured
        .lines()
        .map(str::trim)
        .filter(|l| l.contains(" → "))
        .map(crate::sandbox::sanitize)
        .collect()
}

/// Whether one `<token> <old> → <new>` transition moved a tool somewhere the two versions do not
/// call forward, and which of the shapes in [`crate::version::Regression`] it was.
///
/// The versions are read off the arrow rather than off a field count: mise writes the token first,
/// and a token carries its backend's own syntax (`aqua:anthropics/claude-code`), so the old version
/// is the last field before the arrow and the new one is everything after it. A line the arrow does
/// not split is not a transition at all, and a pair that says nothing conclusive is not a
/// regression — [`crate::version::regression`] decides which pairs qualify.
fn transition_regression(line: &str) -> Option<crate::version::Regression> {
    let (before, new) = line.split_once(" → ")?;
    let old = before.rsplit(' ').next()?;
    crate::version::regression(old.trim(), new.trim())
}

/// Whether mise reported nothing to do. mise prints `All tools are up to date` (to stderr) when a
/// roll finds every tool already current. Pure — unit-tested against real mise output.
fn mise_up_to_date(captured: &str) -> bool {
    captured.contains("up to date")
}

/// One dot-leader-aligned result line for the `mise:` roll report: the group `name`, a run of dots
/// filling toward `width`, then the caller's already-styled `status`. Pure formatting — the dots
/// carry `width - name` + a 3-dot minimum so even the widest name keeps a small gap.
fn roll_line(name: &str, width: usize, status: &str, pal: &crate::style::Palette) -> String {
    let dots = ".".repeat(width.saturating_sub(name.chars().count()) + 3);
    format!(
        "  {}{name}{} {}{dots}{} {status}",
        pal.name, pal.reset, pal.dim, pal.reset
    )
}

/// The one line that closes the `mise:` roll report and answers "which apps changed?": the rolled
/// groups by name, then a parenthesised tally of the rest. Plain text (the caller colours it by
/// outcome); pure, so it is unit-tested. With nothing rolled and nothing wrong it collapses to a
/// single reassuring line rather than "0 apps rolled".
fn mise_roll_recap(
    rolled: &[String],
    not_forward: &[String],
    up_to_date: usize,
    skipped: usize,
    failed: usize,
) -> String {
    let mut tail = Vec::new();
    if up_to_date > 0 {
        tail.push(format!("{up_to_date} up to date"));
    }
    // Named, not just counted, and inside the tally rather than beside the rolled list: these are
    // the groups a user has to look at, and a bare number would send them back to the lines above
    // to find out which.
    if !not_forward.is_empty() {
        tail.push(format!(
            "{} not forward: {}",
            not_forward.len(),
            not_forward.join(", ")
        ));
    }
    if skipped > 0 {
        tail.push(format!("{skipped} skipped"));
    }
    if failed > 0 {
        tail.push(format!("{failed} failed"));
    }
    let tally = if tail.is_empty() {
        String::new()
    } else {
        format!(" ({})", tail.join(", "))
    };

    if rolled.is_empty() {
        if !tail.is_empty() && skipped == 0 && failed == 0 && not_forward.is_empty() {
            format!("all {up_to_date} up to date.")
        } else if tail.is_empty() {
            "nothing to roll.".to_string()
        } else {
            format!("nothing rolled{tally}.")
        }
    } else {
        // No noun: the names are an app's most of the time, but the declared operations' tool pool
        // rolls under this same recap and is not an app. Counting them without naming a kind keeps
        // the line accurate for both rather than mislabelling one.
        format!("{} rolled: {}{tally}.", rolled.len(), rolled.join(", "))
    }
}

#[cfg(test)]
mod tests;
