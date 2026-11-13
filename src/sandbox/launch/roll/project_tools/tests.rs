use super::*;
use crate::config::AppHomeScope;

/// A trusted project whose mise file declares one tool the roll handles and one `nix:` tool it
/// leaves to the `nix:` roll, with four apps: a global one, a project-scoped one, one with no
/// command and one whose own `[env]` disables the tool.
fn fixture(reads_project_pool: bool) -> Resolved {
    let mut cfg = crate::testutil::resolved_channels(None, None);
    cfg.mise = Some(crate::config::MiseConfig {
        name: "mise.toml".into(),
        state: crate::trust::TrustState::Trusted,
        files: vec![(
            "mise.toml".into(),
            b"[tools]\n\"nix:jq\" = \"latest\"\n\"core:demo-runtime\" = \"2\"\n".to_vec(),
        )],
    });
    cfg.apps_read_project_pool = reads_project_pool;
    let app = |scope: AppHomeScope, cmd: &[&str], env: &[(&str, &str)]| {
        let mut app = crate::testutil::app_with(Vec::new());
        app.home_scope = scope;
        app.cmd = cmd.iter().map(|s| s.to_string()).collect();
        app.env = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        app
    };
    cfg.apps
        .insert("global-app".into(), app(AppHomeScope::Global, &["x"], &[]));
    cfg.apps
        .insert("scoped-app".into(), app(AppHomeScope::Project, &["x"], &[]));
    cfg.apps
        .insert("no-cmd".into(), app(AppHomeScope::Global, &[], &[]));
    cfg.apps.insert(
        "disabling".into(),
        app(
            AppHomeScope::Global,
            &["x"],
            &[("MISE_DISABLE_TOOLS", "demo-runtime")],
        ),
    );
    cfg
}

fn names(plan: &ProjectToolsPlan) -> (Vec<String>, Vec<String>) {
    (
        plan.groups.iter().map(|g| g.home.label()).collect(),
        plan.following.clone(),
    )
}

/// The roll walks the project's home and each launchable app's, with the tokens each one equips; a
/// global app that reads the project's pool follows it instead, and only where this host's
/// bubblewrap can mount the pool.
#[test]
fn the_project_tools_roll_walks_each_home_that_keeps_its_own_copy() {
    let project = "project".to_string();
    let global = "app: global-app".to_string();
    let scoped = "app: scoped-app".to_string();

    // Not granted: every launchable app with a token keeps its own copy.
    let plan = project_tools_plan(&fixture(false), None, true);
    assert_eq!(
        names(&plan),
        (
            vec![project.clone(), global.clone(), scoped.clone()],
            vec![]
        )
    );
    assert_eq!(
        plan.groups[0].tokens,
        ["core:demo-runtime@2"],
        "no `nix:` tool"
    );

    // Granted: the global app follows the project's pool; a project-scoped app cannot read it.
    let plan = project_tools_plan(&fixture(true), None, true);
    assert_eq!(
        names(&plan),
        (
            vec![project.clone(), scoped.clone()],
            vec!["global-app".to_string()]
        )
    );

    // Granted on a bubblewrap that cannot mount the pool: the app reads nothing, so it is rolled.
    let plan = project_tools_plan(&fixture(true), None, false);
    assert_eq!(
        names(&plan),
        (
            vec![project.clone(), global.clone(), scoped.clone()],
            vec![]
        )
    );

    // `--app` narrows to that app's home and leaves the project's alone.
    let plan = project_tools_plan(&fixture(false), Some("global-app"), true);
    assert_eq!(names(&plan), (vec![global], vec![]));
    let plan = project_tools_plan(&fixture(true), Some("global-app"), true);
    assert_eq!(names(&plan), (vec![], vec!["global-app".to_string()]));
}

/// A stand-in `mise` that appends its argv and the two variables the roll sets to
/// `$SBX_TEST_RECORD`, one line per call.
fn recording_mise(path: &Path) {
    std::fs::write(
        path,
        "#!/bin/sh\necho \"trusted=${MISE_TRUSTED_CONFIG_PATHS-unset} \
         prune=${MISE_UPGRADE_AUTO_PRUNE-unset} mise $*\" >> \"$SBX_TEST_RECORD\"\n",
    )
    .unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

/// The roll's command trusts the project's mise file, which mise otherwise ignores and then reports
/// every tool up to date; passes the tokens after a `--`; asks a dry run with `--dry-run`; and keeps
/// mise from scheduling a deletion in a global app's pool, whose state other projects share.
#[test]
fn the_project_tools_roll_trusts_the_file_and_schedules_no_deletion_in_a_global_app() {
    let bash = PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping project tools roll run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    recording_mise(&dir.path().join("mise"));
    let tokens = vec!["--help".to_string(), "core:demo-runtime@2".to_string()];
    for (runtime, mode, called) in [
        (
            binds::Runtime::ProjectDefault,
            RollMode::Apply,
            "trusted=/demo/project prune=unset mise -C /demo/project upgrade -- --help core:demo-runtime@2",
        ),
        (
            binds::Runtime::GlobalApp("demo-app"),
            RollMode::Apply,
            "trusted=/demo/project prune=0 mise -C /demo/project upgrade -- --help core:demo-runtime@2",
        ),
        (
            binds::Runtime::ProjectApp("demo-app"),
            RollMode::DryRun,
            "trusted=/demo/project prune=unset mise -C /demo/project upgrade --dry-run -- --help core:demo-runtime@2",
        ),
    ] {
        let record = dir.path().join("record");
        let _ = std::fs::remove_file(&record);
        let argv = project_tools_upgrade_cmd(
            runtime,
            Path::new("./mise"),
            &bash,
            Path::new("/demo/project"),
            &tokens,
            mode,
        );
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(dir.path())
            .env("SBX_TEST_RECORD", &record)
            .env_remove("MISE_UPGRADE_AUTO_PRUNE")
            .output()
            .expect("run the generated roll script");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&record).expect("the stand-in recorded its call"),
            format!("{called}\n")
        );
    }
}

/// The roll report reads what mise prints, in the shapes it prints them: an applied move as a
/// `<token> <from> → <to>` line, nothing to do as `All tools are up to date`, and a dry run's moves
/// as `Would install` lines beside the deletions it would schedule.
#[test]
fn the_project_tools_report_reads_mise_s_own_lines() {
    let applied = "mise by @jdx – installing 1 tool\n\nUpgraded 1 tool:\n  aqua:example/demo-tool 1.0.0 → 1.1.0\n";
    assert_eq!(
        project_tools_moves(applied, RollMode::Apply),
        (
            vec!["aqua:example/demo-tool 1.0.0 → 1.1.0".to_string()],
            false
        )
    );
    let current = "mise ████ 1/1 · resolved 1 tool in 0ms\nmise All tools are up to date\n";
    assert_eq!(
        project_tools_moves(current, RollMode::Apply),
        (vec![], true)
    );
    let dry = "Would schedule aqua:example/demo-tool@1.0.0 for pruning after 24h\n\
               Would install aqua:example/demo-tool@1.1.0\n";
    assert_eq!(
        project_tools_moves(dry, RollMode::DryRun),
        (vec!["aqua:example/demo-tool@1.1.0".to_string()], false)
    );
    assert_eq!(project_tools_moves("", RollMode::DryRun), (vec![], true));
}

/// A home counts as having equipped the project's tools when the pool the project's lane installs
/// into holds an `installs` directory: the home's own mise data for the project's shell and a
/// project-scoped app, a global app's per-project pool for a global app. A home with none is never
/// rolled, so a roll does not install the project's toolchain into an app never launched there.
#[test]
fn a_home_is_rolled_only_once_it_equipped_the_project_tools() {
    let data = crate::testutil::TmpDir::new();
    let project = crate::testutil::TmpDir::new();
    let id = binds::project_id(&project.path().canonicalize().unwrap());
    let base = data.path().join("projects").join(&id);
    let global = binds::Runtime::GlobalApp("demo-app");
    for runtime in [binds::Runtime::ProjectDefault, global] {
        assert!(
            !equipped(data.path(), project.path(), runtime),
            "nothing equipped yet"
        );
    }
    std::fs::create_dir_all(base.join("home/.local/share/mise/installs")).unwrap();
    assert!(equipped(
        data.path(),
        project.path(),
        binds::Runtime::ProjectDefault
    ));
    assert!(
        !equipped(data.path(), project.path(), global),
        "the project's pool is not the app's own"
    );
    std::fs::create_dir_all(base.join("apps/demo-app/mise/installs")).unwrap();
    assert!(equipped(data.path(), project.path(), global));
}
