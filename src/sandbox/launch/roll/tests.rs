use super::*;

#[test]
fn mise_transitions_extracts_the_version_rolls_from_captured_output() {
    // The exact shape a captured (non-TTY) `mise upgrade` produces: the `X → Y` summary goes to
    // stdout under an "Upgraded N tool:" header, the install/uninstall progress to stderr — this
    // fixture concatenates both, as `run_captured` does. Only the transition line is surfaced.
    let captured = "\
\nUpgraded 1 tool:\n  shfmt 3.7.0 → 3.13.1\n\
mise shfmt@3.13.1    [1/2] install\n\
mise shfmt@3.13.1  ✓ installed\n\
mise uninstall shfmt@3.7.0 ✓ done\n";
    assert_eq!(mise_transitions(captured), vec!["shfmt 3.7.0 → 3.13.1"]);

    // A group that rolls several tokens surfaces one transition line each; the full-token form
    // (as an `aqua:`/`pipx:` roll prints) is kept verbatim.
    let multi = "\
Upgraded 2 tools:\n  aqua:example/demo-tool 0.144.4 → 0.144.5\n  pipx:demo-agent 2.20.0 → 2.21.0\n";
    assert_eq!(
        mise_transitions(multi),
        vec![
            "aqua:example/demo-tool 0.144.4 → 0.144.5",
            "pipx:demo-agent 2.20.0 → 2.21.0"
        ]
    );

    // No roll (the progress/equip preamble carries no ` → `) → nothing surfaced, so the caller
    // falls through to the up-to-date / generic branch.
    let none =
        "mise ~/.config/mise/config.toml tools: npm:demo-tool@3.0.40\nadded 3 packages in 617ms\n";
    assert!(mise_transitions(none).is_empty());
}

#[test]
fn mise_up_to_date_detects_the_no_op_roll() {
    // mise prints this to stderr when a roll finds every tool already current.
    assert!(mise_up_to_date("mise All tools are up to date\n"));
    assert!(!mise_up_to_date(
        "Upgraded 1 tool:\n  shfmt 3.7.0 → 3.13.1\n"
    ));
}

#[test]
fn mise_roll_recap_names_what_rolled_and_tallies_the_rest() {
    // The headline case: two advanced out of many — the recap names them and tallies the
    // untouched majority, so "what is concerned?" reads at a glance. No noun on the count: the
    // names are usually apps, but the task tool pool rolls under this same recap and is not one.
    assert_eq!(
        mise_roll_recap(&["demo-app".into(), "other-app".into()], &[], 15, 0, 0),
        "2 rolled: demo-app, other-app (15 up to date)."
    );
    // Nothing advanced, everything current — collapse to one reassuring line, not "0 rolled".
    assert_eq!(mise_roll_recap(&[], &[], 17, 0, 0), "all 17 up to date.");
    // A mixed tally (skips + failures) still surfaces.
    assert_eq!(
        mise_roll_recap(&["demo-app".into()], &[], 0, 1, 2),
        "1 rolled: demo-app (1 skipped, 2 failed)."
    );
    // Nothing rolled but not a clean no-op — say what got in the way.
    assert_eq!(
        mise_roll_recap(&[], &[], 10, 2, 1),
        "nothing rolled (10 up to date, 2 skipped, 1 failed)."
    );
    // Degenerate empty run (no groups reached the loop).
    assert_eq!(mise_roll_recap(&[], &[], 0, 0, 0), "nothing to roll.");
}

#[test]
fn mise_roll_recap_names_the_groups_that_did_not_move_forward() {
    // The headline case this distinction exists for: most apps advanced, one walked back. It is
    // named inside the tally rather than counted with the rolled, so "what do I have to look at?"
    // is answered without re-reading the lines above.
    assert_eq!(
        mise_roll_recap(&["demo-app".into()], &["kilo-app".into()], 15, 0, 0),
        "1 rolled: demo-app (15 up to date, 1 not forward: kilo-app)."
    );
    // Nothing advanced and one walked back: the run is not the clean sweep the all-up-to-date
    // collapse would claim.
    assert_eq!(
        mise_roll_recap(&[], &["kilo-app".into()], 17, 0, 0),
        "nothing rolled (17 up to date, 1 not forward: kilo-app)."
    );
}

#[test]
fn transition_regression_reads_the_versions_off_the_arrow() {
    use crate::version::Regression;
    // The token carries its backend's own syntax, so the old version is the last field before the
    // arrow — not the second field of the line.
    assert_eq!(
        transition_regression("aqua:anthropics/claude-code 2.1.220 → 2.1.251"),
        None
    );
    // A tag that names another release line is what a bare " → " filter cannot see.
    assert_eq!(
        transition_regression("kilo 7.4.17 → jetbrains/v7.1.2"),
        Some(Regression::ChangedLine)
    );
    assert_eq!(
        transition_regression("demo 7.4.17 → 7.1.2"),
        Some(Regression::Backward)
    );
    // A line the arrow does not split is not a transition.
    assert_eq!(transition_regression("added 3 packages in 617ms"), None);
}

fn mise_pkg(name: &str, token: &str, trusted: bool) -> crate::config::Package {
    crate::config::Package {
        name: name.into(),
        backend: crate::config::Backend::Mise(token.into()),
        state: if trusted {
            crate::trust::TrustState::Trusted
        } else {
            crate::trust::TrustState::Untrusted
        },
        libs: Vec::new(),
        main: String::new(),
    }
}

fn nix_pkg(name: &str, attr: &str) -> crate::config::Package {
    crate::config::Package {
        name: name.into(),
        backend: crate::config::Backend::Nix(attr.into()),
        state: crate::trust::TrustState::Trusted,
        libs: Vec::new(),
        main: String::new(),
    }
}

fn app_overlay(
    cmd: &[&str],
    scope: crate::config::AppHomeScope,
    packages: Vec<crate::config::Package>,
) -> crate::config::ResolvedApp {
    crate::config::ResolvedApp {
        accepts_fresh_releases: Default::default(),
        provisions: Vec::new(),
        open: Default::default(),
        service: Default::default(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        cmd: cmd.iter().map(|s| s.to_string()).collect(),
        home_scope: scope,
        env: vec![],
        binds: vec![],
        packages,
        network: None,
        gui: None,
        gpu: None,
        allow_insecure_http: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        forward: vec![],
        secrets: vec![],
        tasks: vec![],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        allow_insecure_http_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward_origin: Default::default(),
        limits_origin: Default::default(),
        seccomp: Default::default(),
        seccomp_origin: Default::default(),
        devices: Vec::new(),
        devices_origin: Default::default(),
        proc: None,
        proc_origin: Default::default(),
        home_scope_origin: None,
        warnings: vec![],
    }
}

/// The roll's unit of work: only apps, only those whose bundles install, each in the home its
/// launch would use. A `provision` is a bundle's field and a bundle only folds into an app, so
/// unlike the `mise:` roll there is no project-baseline group to find here.
#[test]
fn provision_groups_takes_only_the_apps_whose_bundles_install() {
    use crate::config::{AppHomeScope, BundleProvision};
    let step = |bundle: &str| BundleProvision {
        bundle: bundle.into(),
        argv: vec!["bash".into(), "-c".into(), "install".into()],
    };
    let mut cfg = crate::testutil::resolved_channels(None, None);
    let mut apps = std::collections::BTreeMap::new();

    let mut installs = app_overlay(&["alpha"], AppHomeScope::Global, vec![]);
    installs.provisions = vec![step("alpha-bundle")];
    apps.insert("alpha".to_string(), installs);

    // Rides a backend: nothing to re-run.
    apps.insert(
        "beta".to_string(),
        app_overlay(&["beta"], AppHomeScope::Project, vec![]),
    );

    // Declares a step but has no command: never launchable, so nothing installs for it.
    let mut unlaunchable = app_overlay(&[], AppHomeScope::Global, vec![]);
    unlaunchable.provisions = vec![step("ghost")];
    apps.insert("gamma".to_string(), unlaunchable);

    // Two bundles that install, in `use` order, in a per-project home.
    let mut two = app_overlay(&["delta"], AppHomeScope::Project, vec![]);
    two.provisions = vec![step("first"), step("second")];
    apps.insert("delta".to_string(), two);
    cfg.apps = apps;

    let groups = provision_groups(&cfg, None);
    assert_eq!(groups.len(), 2, "only alpha and delta install");
    assert!(matches!(&groups[0].home, GroupHome::GlobalApp(n) if n == "alpha"));
    assert_eq!(groups[0].steps.len(), 1);
    assert!(matches!(&groups[1].home, GroupHome::ProjectApp(n) if n == "delta"));
    assert_eq!(
        groups[1].steps.len(),
        2,
        "both bundles' steps, in use order"
    );
    assert_eq!(step_bundles(&groups[1].steps), "first, second");
    // A bundle named twice contributes one name to the line, not two.
    assert_eq!(step_bundles(&[step("dup"), step("dup")]), "dup");

    // `--app <name>` narrows the roll to that app's cage and takes nothing else with it.
    let only = provision_groups(&cfg, Some("delta"));
    assert_eq!(only.len(), 1, "the selector takes one app, not two");
    assert!(matches!(&only[0].home, GroupHome::ProjectApp(n) if n == "delta"));
    assert_eq!(only[0].steps.len(), 2, "that app keeps all of its steps");
    // A name the selector matches but that has nothing to roll still yields no group here; the
    // CLI is what refuses it by name, so this stays a plain filter.
    assert!(provision_groups(&cfg, Some("beta")).is_empty());
    assert!(provision_groups(&cfg, Some("nope")).is_empty());
}

/// The roll runs the install and stops there: chaining the app's command onto it would make a
/// version roll a launch. The steps are quoted for the same reason the launch quotes them.
#[test]
fn an_install_roll_runs_the_steps_alone_and_never_the_app() {
    use crate::config::BundleProvision;
    let steps = vec![
        BundleProvision {
            bundle: "alpha".into(),
            argv: vec!["bash".into(), "-c".into(), "first $HOME".into()],
        },
        BundleProvision {
            bundle: "beta".into(),
            argv: vec!["installer".into(), "it's here".into()],
        },
    ];
    let cmd = provision_only_cmd(&steps);
    assert_eq!(cmd[0], OsString::from("bash"));
    assert_eq!(cmd[1], OsString::from("-c"));
    let script = cmd[2].to_string_lossy().to_string();
    assert!(
        !script.contains("exec"),
        "the app's command must not be chained on: {script}"
    );
    assert!(
        script.contains("'first $HOME'") && script.contains(r#"'it'\''s here'"#),
        "each argument stays data, not shell syntax: {script}"
    );
    assert_eq!(
        script.matches("&&").count(),
        1,
        "two steps, one `&&` — a failed step stops the chain: {script}"
    );
    assert_eq!(cmd.len(), 4, "a label for $0 and nothing positional");
}

#[test]
fn the_install_roll_recap_names_what_ran_and_tallies_the_rest() {
    let apps = ["trae".to_string(), "odysseus".to_string()];
    assert_eq!(
        provision_roll_recap(&apps, 0, 0, true),
        "re-installed: trae, odysseus"
    );
    assert_eq!(
        provision_roll_recap(&[], 2, 1, true),
        "nothing re-installed · 2 skipped · 1 failed"
    );
    // Without `force` the same run claims less, because it knows less: the guards decided, and an
    // exit status does not say which way. Saying "re-installed" here would be the report asserting
    // what only the step can see.
    assert_eq!(
        provision_roll_recap(&apps, 0, 0, false),
        "install steps ran: trae, odysseus"
    );
    assert_eq!(
        provision_roll_recap(&[], 2, 1, false),
        "no install step ran · 2 skipped · 1 failed"
    );
}

#[test]
fn mise_package_groups_covers_the_baseline_and_each_app_generically() {
    use crate::config::AppHomeScope;
    let mut cfg = crate::testutil::resolved_channels(None, None);
    cfg.packages = vec![
        mise_pkg("other-tool", "other-tool", true),
        nix_pkg("jq", "jq"), // a nix package is not a mise token
        mise_pkg("evil", "aqua:attacker/x", false), // untrusted: dropped
    ];
    let mut apps = std::collections::BTreeMap::new();
    // An app with its own mise: package, in a shared (global) home.
    apps.insert(
        "alpha".to_string(),
        app_overlay(
            &["alpha"],
            AppHomeScope::Global,
            vec![mise_pkg("foo", "aqua:foo", true)],
        ),
    );
    // An app with only a nix: package — no mise: group.
    apps.insert(
        "beta".to_string(),
        app_overlay(
            &["beta"],
            AppHomeScope::Project,
            vec![nix_pkg("rg", "ripgrep")],
        ),
    );
    // An app with a mise: package but no command — never launchable, so skipped.
    apps.insert(
        "gamma".to_string(),
        app_overlay(
            &[],
            AppHomeScope::Global,
            vec![mise_pkg("g", "aqua:g", true)],
        ),
    );
    cfg.apps = apps;

    let groups = mise_package_groups(&cfg, None);
    // Three groups: the project baseline plus each launchable app — beta inherits the
    // baseline `mise:` tool (an app's cage equips both layers), so even a nix-only app gets
    // a group. gamma has no command, so it is skipped.
    assert_eq!(groups.len(), 3);

    // The baseline group rolls only the trusted mise token, in the default home.
    let base = &groups[0];
    assert!(matches!(base.home, GroupHome::ProjectDefault));
    assert_eq!(base.tokens, vec!["other-tool".to_string()]);

    // alpha rolls in its own (global) home; its tokens are the merged set (baseline + app).
    let alpha = groups
        .iter()
        .find(|g| matches!(&g.home, GroupHome::GlobalApp(n) if n == "alpha"))
        .expect("alpha has a global-home group");
    assert!(alpha.tokens.contains(&"other-tool".to_string()));
    assert!(alpha.tokens.contains(&"aqua:foo".to_string()));

    // beta rolls in its own per-project home, inheriting only the baseline mise tool.
    let beta = groups
        .iter()
        .find(|g| matches!(&g.home, GroupHome::ProjectApp(n) if n == "beta"))
        .expect("beta inherits the baseline mise tool in its per-project home");
    assert_eq!(beta.tokens, vec!["other-tool".to_string()]);

    // The command-less app produced no group.
    assert!(!groups.iter().any(|g| g.home.label().contains("gamma")));

    // `--app <name>` narrows to that app's cage AND drops the project baseline, which is not
    // an app: keeping it would make a per-app flag roll project-wide work. The app's own group
    // still carries the merged token set, since its cage equips both layers.
    let only = mise_package_groups(&cfg, Some("alpha"));
    assert_eq!(only.len(), 1, "one app, and no baseline group beside it");
    assert!(matches!(&only[0].home, GroupHome::GlobalApp(n) if n == "alpha"));
    assert!(only[0].tokens.contains(&"other-tool".to_string()));
    assert!(only[0].tokens.contains(&"aqua:foo".to_string()));
    assert!(mise_package_groups(&cfg, Some("gamma")).is_empty());
    assert!(mise_package_groups(&cfg, Some("nope")).is_empty());

    // The withheld count follows the selector: a roll narrowed to one app must not report a
    // package withheld from a different one, or the line contradicts what the roll just did.
    // The fixture's untrusted `mise:` package is the project baseline's, which every app's
    // cage folds in — so it counts for an app, and once, not once per app.
    assert_eq!(withheld_mise_packages(&cfg, None), 1);
    assert_eq!(withheld_mise_packages(&cfg, Some("alpha")), 1);
    assert_eq!(
        withheld_mise_packages(&cfg, Some("nope")),
        0,
        "a name no app carries withholds nothing"
    );
}

/// The roll report's pool line must quote whichever stream carried the diagnostic.
///
/// mise wraps backends (`npm`, `pipx`) that report a resolution failure on stdout while mise's own
/// stderr carries only progress that trims away to nothing. Reading the stderr tail alone turned
/// that failure into `no output` on the one line an operator reads to tell a registry outage from a
/// typo'd token.
#[test]
fn the_pool_roll_failure_quotes_the_stream_that_carried_the_diagnostic() {
    let backend_spoke_on_stdout = crate::sandbox::taskpool::InstallRun {
        ok: false,
        stderr: b"  \n \n".to_vec(),
        stdout: b"npm error 404 Not Found - GET https://registry.example/no-such".to_vec(),
    };
    assert_eq!(
        pool_upgrade_failure(&backend_spoke_on_stdout),
        "mise upgrade failed: npm error 404 Not Found - GET https://registry.example/no-such"
    );

    // mise's own stderr wins whenever it has something to say, and only its last line is quoted.
    let mise_spoke = crate::sandbox::taskpool::InstallRun {
        ok: false,
        stderr: b"mise downloading\nmise ERROR failed to resolve tool\n".to_vec(),
        stdout: b"progress".to_vec(),
    };
    assert_eq!(
        pool_upgrade_failure(&mise_spoke),
        "mise upgrade failed: mise ERROR failed to resolve tool"
    );

    // Neither stream said anything, which is the only case the placeholder describes.
    let silent = crate::sandbox::taskpool::InstallRun {
        ok: false,
        stderr: Vec::new(),
        stdout: Vec::new(),
    };
    assert_eq!(
        pool_upgrade_failure(&silent),
        "mise upgrade failed: no output"
    );
}
