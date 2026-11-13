//! The roll of the project's own mise tools: the non-`nix:` tools of the project's mise file, which
//! a launch installs when they are missing and never moves.
//!
//! Every cage launched from the project equips them in the pool of its own home, so the roll walks
//! the same homes: the project's (`sbx run`) and each app's. An app that reads the pool `sbx run`
//! fills is left out, since the project's roll is what moves the copy it runs, and rolling its own
//! would fetch under an egress that usually refuses the tools' hosts.

use super::*;
use crate::config::Resolved;

/// One home whose copy of the project's tools the roll advances, with the merged configuration its
/// cage is launched with and the tokens it equips.
pub(super) struct ProjectToolsGroup {
    pub(super) home: GroupHome,
    pub(super) cfg: Resolved,
    pub(super) tokens: Vec<String>,
}

/// What the roll does with the project's tools, home by home.
pub(super) struct ProjectToolsPlan {
    /// The homes whose own copy is rolled, the project's first.
    pub(super) groups: Vec<ProjectToolsGroup>,
    /// The global apps left to follow the project's pool, by name.
    pub(super) following: Vec<String>,
}

/// The homes the roll advances the project's tools in, and the apps that follow the project's
/// pool instead. Pure over the resolved configuration, so the selection is tested without a cage.
///
/// The project's own home is rolled unless `only` names an app, for the reason
/// [`mise_package_groups`] drops the baseline there. An app is rolled in its own home when it is
/// launchable and `only` selects it, except a global app that reads the project's pool, which is
/// `cfg.apps_read_project_pool` on a bubblewrap that can mount the pool (`shares_pool`): that app
/// runs the copy the project's roll moves. An app's tokens are read from its merged configuration,
/// since its `[env]` may name tools in `MISE_DISABLE_TOOLS` the project's does not.
pub(super) fn project_tools_plan(
    cfg: &Resolved,
    only: Option<&str>,
    shares_pool: bool,
) -> ProjectToolsPlan {
    let mut plan = ProjectToolsPlan {
        groups: Vec::new(),
        following: Vec::new(),
    };
    if only.is_none() {
        let tokens = super::super::equip::auto_equip_tokens(cfg);
        if !tokens.is_empty() {
            plan.groups.push(ProjectToolsGroup {
                home: GroupHome::ProjectDefault,
                cfg: cfg.clone(),
                tokens,
            });
        }
    }
    for (name, app) in &cfg.apps {
        if only.is_some_and(|want| want != name) || app.cmd.is_empty() || !app.refusals.is_empty() {
            continue;
        }
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        let tokens = super::super::equip::auto_equip_tokens(&merged);
        if tokens.is_empty() {
            continue;
        }
        let home = match app.home_scope {
            crate::config::AppHomeScope::Global => {
                if cfg.apps_read_project_pool && shares_pool {
                    plan.following.push(name.clone());
                    continue;
                }
                GroupHome::GlobalApp(name.clone())
            }
            crate::config::AppHomeScope::Project => GroupHome::ProjectApp(name.clone()),
        };
        plan.groups.push(ProjectToolsGroup {
            home,
            cfg: merged,
            tokens,
        });
    }
    plan
}

/// Whether `sbx upgrade --app <name>` has project tools to roll in that app's own home: the app
/// equips some, and does not follow the project's pool. Read from the configuration alone, so an
/// app granted the pool counts as following it whatever this host's bubblewrap can mount; the roll
/// itself still rolls such an app's own copy where the pool cannot be mounted.
pub(crate) fn app_rolls_project_tools(cfg: &Resolved, name: &str) -> bool {
    cfg.mise
        .as_ref()
        .is_some_and(|m| m.state == crate::trust::TrustState::Trusted)
        && !project_tools_plan(cfg, Some(name), true).groups.is_empty()
}

/// The command a project-tools roll runs in one home's cage: `mise upgrade -- <tokens>`, in the
/// project, so mise reads the project's mise file the tokens come from.
///
/// mise upgrades only the tools a configuration it reads declares, and it reads the project's file
/// only when it is told to trust it: without `MISE_TRUSTED_CONFIG_PATHS` it reports every tool up
/// to date and moves nothing. A launch sets that variable for its own equip; a roll cage does not
/// equip, so the script sets it. `mise upgrade` also installs a declared tool the home does not
/// hold yet.
///
/// A global app's state is shared by every project it is launched from while its pool for this
/// project is not, and both are mounted at the same paths in each cage. The old version an upgrade
/// schedules for deletion is recorded by that path in the shared state, so a later mise in another
/// project would delete that project's copy. `MISE_UPGRADE_AUTO_PRUNE=0` keeps the roll from
/// scheduling any deletion there; the other homes keep their state and their pool together and keep
/// mise's default.
///
/// The tokens ride `"$@"` after a `--`, and the two interpolated values, the mise path and the
/// project directory, go through `shell_quote`, so a token from the project's file reaches mise
/// as a tool and never as shell or as an option.
pub(super) fn project_tools_upgrade_cmd(
    runtime: binds::Runtime,
    mise: &Path,
    bash: &Path,
    project: &Path,
    tokens: &[String],
    mode: RollMode,
) -> Vec<OsString> {
    use super::super::startup::shell_quote;
    let prune = match runtime {
        binds::Runtime::GlobalApp(_) => "export MISE_UPGRADE_AUTO_PRUNE=0; ",
        _ => "",
    };
    let dry = match mode {
        RollMode::Apply => "",
        RollMode::DryRun => " --dry-run",
    };
    let script = format!(
        "export MISE_TRUSTED_CONFIG_PATHS={}; {prune}{} upgrade{dry} -- \"$@\"",
        shell_quote(&project.to_string_lossy()),
        shell_quote(&mise.to_string_lossy()),
    );
    let mut cmd = vec![
        bash.as_os_str().to_os_string(),
        OsString::from("-c"),
        OsString::from(script),
        // `$0` — a label; the tokens are `$1..$n`.
        OsString::from("sbx-project-tools-upgrade"),
    ];
    cmd.extend(tokens.iter().map(OsString::from));
    cmd
}

/// What one home's roll did, read from its captured output: the moves mise named, an empty list
/// with `current` when it had nothing to do, or the lines a dry run says it would install.
pub(super) fn project_tools_moves(captured: &str, mode: RollMode) -> (Vec<String>, bool) {
    match mode {
        RollMode::Apply => {
            let moves = mise_transitions(captured);
            let current = moves.is_empty() && mise_up_to_date(captured);
            (moves, current)
        }
        RollMode::DryRun => {
            let moves: Vec<String> = captured
                .lines()
                .map(str::trim)
                .filter_map(|line| line.strip_prefix("Would install "))
                .map(crate::sandbox::sanitize)
                .collect();
            let current = moves.is_empty();
            (moves, current)
        }
    }
}

/// Roll the project's own mise tools forward, home by home (see the module). Returns whether every
/// home rolled cleanly; a home that fails makes this `false` but never aborts the others.
///
/// Trusted-only, like the project's `nix:` tools: the roll runs mise on the project's file, which
/// an untrusted project's cages are told to leave inert, so an untrusted project is named and left
/// alone. Under `network = "none"` a home is skipped, as its launch skips the equip.
pub(crate) fn upgrade_project_tools(
    cwd: &Path,
    cfg: &Resolved,
    pal: &crate::style::Palette,
    only: Option<&str>,
    mode: RollMode,
) -> bool {
    let (h, warn, dim, r, ok_c) = (pal.head, pal.warn, pal.dim, pal.reset, pal.ok);
    outln!("{h}{}{r}", mode.heading("project mise tools"));
    let Some(mise) = &cfg.mise else {
        outln!("  {dim}no mise file in this project.{r}");
        return true;
    };
    if mise.state != crate::trust::TrustState::Trusted {
        outln!(
            "  {warn}mise file `{}` withheld (untrusted){r} — its tools are not rolled; run `sbx trust`.",
            crate::sandbox::sanitize(&mise.name)
        );
        return true;
    }
    // Whether this host's bubblewrap can mount the project's pool at all: an app that reads it on
    // paper reads nothing without that, and is rolled in its own home like any other.
    let shares_pool = crate::store::Layout::from_env()
        .and_then(|layout| crate::store::try_resolve_bwrap(Some(&layout)).ok())
        .is_some_and(|choice| super::super::cage::bwrap_binds_descriptors(&choice.path));
    let plan = project_tools_plan(cfg, only, shares_pool);
    if plan.groups.is_empty() && plan.following.is_empty() {
        outln!("  {dim}no non-nix tools to roll.{r}");
        return true;
    }
    if mode.applies() && !super::super::host_can_sandbox() {
        crate::diag::warn("project mise tools: skipped — no usable sandbox; see `sbx doctor`");
        return true;
    }
    let width = plan
        .groups
        .iter()
        .map(|g| g.home.name())
        .chain(plan.following.first().cloned())
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0);
    let mut ok = true;
    for group in plan.groups {
        let ProjectToolsGroup { home, cfg, tokens } = group;
        let name = home.name();
        let say = |status: String| outln!("{}", roll_line(&name, width, &status, pal));
        if matches!(cfg.network, crate::config::NetworkPolicy::Isolated) {
            say(format!("{dim}network \"none\" — skipped{r}"));
            continue;
        }
        // A dry run writes nothing, and building a cage can: it seeds the project's store on a
        // first launch and pins a lock that names no revision yet. Such a home is not asked, and the
        // reason is said, as the `mise:` packages' dry run does.
        if !mode.applies()
            && let Some(layout) = crate::store::Layout::from_env()
        {
            if super::super::would_seed_project_store(&layout, cwd) {
                say(format!(
                    "{dim}not checked — this project has no store yet, and a launch here would \
                     seed one{r}"
                ));
                continue;
            }
            if let Some(what) = first_pin_of_a_launch(&layout, cwd, &cfg, home.app()) {
                say(format!(
                    "{dim}not checked — a launch here would first pin {what}{r}"
                ));
                continue;
            }
        }
        let mut prep = match prepare_roll_cage(cwd, home.app()) {
            Ok(p) => p,
            Err(_) => {
                say(format!("{warn}failed to prepare{r}"));
                ok = false;
                continue;
            }
        };
        let mut cfg = cfg;
        cfg.warnings.clear();
        // A dry run asks one question of mise, so what runs before a launch's command (the
        // bundles' install steps, the app's services, the equip lanes) has no place in its cage,
        // nor do the packages the host would build for a command that never runs. A real roll
        // keeps the cage its launch gets: a tool it installs may need one of those packages (a
        // `cargo:` tool builds with the toolchain a `[packages]` entry provides).
        if !mode.applies() {
            cfg.provisions.clear();
            cfg.service.clear();
            cfg.packages
                .retain(|p| matches!(p.backend, crate::config::Backend::Mise(_)));
            prep.equips = false;
        }
        prep.cfg = cfg;
        let runtime = home.runtime();
        let cmd = project_tools_upgrade_cmd(
            runtime,
            &prep.userland.mise_bin,
            &prep.userland.shell_bin,
            &prep.cwd,
            &tokens,
            mode,
        );
        let (spec, guard, _, _store_lock) = match build(&prep, runtime, cmd) {
            Ok(v) => v,
            Err(_) => {
                say(format!("{warn}failed to launch{r}"));
                ok = false;
                continue;
            }
        };
        let (code, out) = run_captured(&prep.bwrap, &spec, &prep.cfg.limits);
        drop(guard);
        if code != 0 {
            say(format!("{warn}mise upgrade exited {code}{r}"));
            crate::diag::warn(&format!("`{}`: mise upgrade exited {code}", home.label()));
            echo_cage_output(&out);
            ok = false;
            continue;
        }
        let (moves, current) = project_tools_moves(&out, mode);
        match moves.as_slice() {
            [] if current => say(format!("{dim}up to date{r}")),
            [] => say(format!("{ok_c}upgraded{r}")),
            [one] => say(format!("{ok_c}{}{one}{r}", mode.says("", "would install "))),
            many => {
                say(format!(
                    "{ok_c}{} tools {}{r}",
                    many.len(),
                    mode.says("rolled", "would roll")
                ));
                for line in many {
                    outln!("       {ok_c}{line}{r}");
                }
            }
        }
    }
    // One line for every app that follows the project's pool: in a project whose apps all read it,
    // a line each would bury the homes that were actually rolled.
    match plan.following.as_slice() {
        [] => {}
        [one] => outln!(
            "{}",
            roll_line(
                one,
                width,
                &format!("{dim}follows the project's pool{r}"),
                pal
            )
        ),
        many => outln!(
            "  {dim}{} apps follow the project's pool, rolled with it{r}",
            many.len()
        ),
    }
    ok
}

#[cfg(test)]
mod tests;
