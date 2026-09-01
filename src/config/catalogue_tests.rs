//! Conformance tests for the **shipped catalogue** under `examples/`: the app profiles, the
//! bundles table and the install steps sbx ships, checked against the schema that accepts them.
//!
//! Kept apart from [`super::tests`], which exercises the resolution engine. These read files from
//! `examples/` and assert on their contents; they never construct a [`super::TrustState`] or a
//! resolved config, and never call `resolve()`. A contributor adding a shipped profile has no
//! reason to open the engine's suite, and one changing the engine has no reason to page through
//! these.

use super::schema;
use crate::testutil::TmpDir;

#[test]
fn no_shipped_profile_carries_a_key_sbx_does_not_know() {
    // The catalogue is the population the new app-scoped unknown-key report is loudest on: 71
    // profiles, each parsed on import, each warning surfacing at launch. A key that is real on the
    // baseline and inert here would have been invisible before; now it would be a line on every
    // launch of that app, so the catalogue has to be clean for the message to mean anything.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/app");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/app/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let raw = schema::parse_app(&std::fs::read(&path).expect("read the profile")).unwrap();
        assert!(
            raw.rest.is_empty(),
            "{}: unknown key(s) {:?}",
            path.display(),
            raw.rest.keys().collect::<Vec<_>>()
        );
        checked += 1;
    }
    // The bundles beside them, on the same rule: a bundle carries no `cmd` and no posture, so one
    // written there would be dropped in silence, and the shipped set is where that would be
    // loudest.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/bundle");
    let mut bundles = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/bundle/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle"))
            .expect("the bundle parses");
        for (name, bundle) in &raw.bundle {
            assert!(
                bundle.rest.is_empty(),
                "{} (`{name}`): unknown key(s) {:?}",
                path.display(),
                bundle.rest.keys().collect::<Vec<_>>()
            );
            bundles += 1;
        }
    }
    // The guard asserts its own precondition: a `read_dir` that found nothing would pass in silence.
    assert!(checked >= 60, "only {checked} profiles were read");
    assert!(bundles >= 60, "only {bundles} bundles were read");
}

/// Every shipped profile whose `cmd` is a shell script forwards `"$@"`.
///
/// `sbx app run <name> -- <args>` is in the verb's own synopsis, and sbx honours it by appending
/// the trailing arguments to the declared `cmd`. A profile that wraps its command in `<shell> -c`
/// and never expands `"$@"` therefore accepts those arguments and drops them, exit code 0 — the
/// promise is kept by the launcher and broken by the profile, which is the half no launcher-side
/// fix can reach.
///
/// The shape is re-derived here rather than borrowed from `sandbox::launch`: a net that shares its
/// rule with the code it guards agrees with that code when the rule itself is what drifted. A plain
/// argv needs nothing — sbx appends to it and the program reads its own arguments.
#[test]
fn every_shipped_shell_profile_forwards_its_trailing_arguments() {
    const SHELLS: [&str; 4] = ["bash", "sh", "zsh", "dash"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("examples/app");
    let (mut shell_profiles, mut plain) = (0, 0);
    for entry in std::fs::read_dir(&dir).expect("examples/app/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse_app(&std::fs::read(&path).expect("read the profile")).unwrap();
        let argv = match raw.cmd {
            Some(cmd) => cmd.into_argv(),
            None => continue,
        };
        // The script is whatever follows a `-…c` flag that follows a shell. Anything else is a
        // program, and its arguments are its own.
        let script = argv.windows(2).position(|w| {
            let is_shell = std::path::Path::new(&w[0])
                .file_name()
                .is_some_and(|s| SHELLS.iter().any(|k| s == *k));
            let is_c_flag = w[1].strip_prefix('-').is_some_and(|rest| {
                rest.ends_with('c') && rest.bytes().all(|b| b.is_ascii_lowercase())
            });
            is_shell && is_c_flag
        });
        let Some(i) = script.and_then(|i| argv.get(i + 2)) else {
            plain += 1;
            continue;
        };
        shell_profiles += 1;
        assert!(
            i.contains("\"$@\""),
            "`examples/app/{name}.toml` wraps its command in a shell but never expands `\"$@\"`, so \
             `sbx app run {name} -- <args>` accepts arguments and silently drops them. Add `\"$@\"` \
             to the final `exec`, or drop the shell if the command is a plain argv."
        );
    }
    // The precondition, asserted rather than assumed: a catalogue that stopped using shell commands
    // would pass this test vacuously, and it would then be guarding nothing.
    assert!(
        shell_profiles >= 15,
        "expected the shipped catalogue to still carry shell-wrapped profiles to guard, found \
         {shell_profiles} (plain argv: {plain})"
    );
}

#[test]
fn a_runtime_staged_out_of_the_store_is_restaged_once_it_stops_running() {
    // `aionui` is the one shipped profile whose wrapper copies a tree OUT of the nix store into the
    // app's persistent home, because the app rewrites files inside it and the store is read-only.
    // The copy keeps the store paths of the revision it came from — `bin/node`'s ELF interpreter,
    // the shebangs of the npm and corepack shims beside it — so a launch that resolves against a
    // newer revision, plus a `gc --prune` of the old one, leaves a tree that is still present, still
    // executable and still writable, and that cannot run. A guard keyed on the tree's presence skips
    // it forever, and the app reports only that its installation is incomplete.
    //
    // This runs the SHIPPED script, unmodified, against a stand-in app root: the profile's own
    // `command -v aionui` lookup and its own `$HOME` are what place the two trees.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let profile = root.join("examples/app/aionui.toml");
    let raw = schema::parse_app(&std::fs::read(&profile).expect("read the profile")).unwrap();
    let argv = raw.cmd.expect("aionui ships a command").into_argv();
    let script = argv.last().expect("the wrapper script").clone();
    assert!(
        script.contains("managed-resources/node"),
        "`examples/app/aionui.toml` no longer stages the bundled Node runtime; this guard now \
         asserts nothing and must be retargeted or removed"
    );

    let tmp = TmpDir::new();
    let (app, home) = (tmp.path().join("approot"), tmp.path().join("home"));
    let src =
        app.join("opt/AionUi/resources/bundled-aioncore/linux-x64/managed-resources/node/v24/bin");
    let dest = home.join(".config/AionUi/aionui/runtime/node/v24");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(app.join("bin")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // The launcher the script derives the app root from, and the runtime it stages. Both are given
    // the store's own modes: read-only, executable, which is the state the staging exists to escape.
    let write_exec = |path: &std::path::Path, body: &str, mode: u32| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    write_exec(&app.join("bin/aionui"), "#!/bin/sh\nexit 0\n", 0o555);
    write_exec(&src.join("node"), "#!/bin/sh\necho v24.0.0\n", 0o555);

    let launch = || {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", app.join("bin").display()),
            )
            .output()
            .expect("run the shipped wrapper");
        assert!(out.status.success(), "the wrapper failed: {out:?}");
    };
    let node = dest.join("bin/node");
    let runs = || {
        std::process::Command::new(&node)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    };

    // 1. Nothing staged yet: the runtime lands, writable, and runs.
    launch();
    assert!(runs(), "the first launch did not stage a runnable runtime");
    assert!(
        !node.metadata().unwrap().permissions().readonly(),
        "staged read-only"
    );

    // 2. A relaunch leaves it alone — the marker survives, so nothing was re-copied. Restaging is not
    //    free: it discards whatever the app installed into the tree.
    let marker = dest.join(".installed-by-the-app");
    std::fs::write(&marker, "x").unwrap();
    launch();
    assert!(
        marker.exists(),
        "a healthy runtime was restaged, discarding the app's own install"
    );

    // 3. The revision it was copied from is reclaimed: the file is there, executable and writable,
    //    and its interpreter is not. Presence says fine; running says otherwise.
    write_exec(
        &node,
        "#!/nix/store/0000000000000000-reclaimed/bin/sh\n",
        0o755,
    );
    assert!(!runs(), "the broken-runtime state was not reproduced");
    launch();
    assert!(
        runs(),
        "a runtime whose interpreter was reclaimed was left in place"
    );
    assert!(!marker.exists(), "the tree was not replaced");

    // 4. A stage that never got its write bits: the repair must be able to remove what it replaces,
    //    which `rm -rf` cannot do inside directories it may not write. Reached here through the
    //    guard's exec test, so the removal is exercised whatever the uid.
    let lock_the_stage = || {
        for p in [dest.join("bin"), dest.clone()] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
    };
    write_exec(
        &node,
        "#!/nix/store/0000000000000000-reclaimed/bin/sh\n",
        0o555,
    );
    lock_the_stage();
    launch();
    assert!(runs(), "a read-only stage was not repaired");
    assert!(
        !node.metadata().unwrap().permissions().readonly(),
        "still read-only"
    );

    // 5. The write bits on their own: a stage that RUNS but cannot be written to must restage all
    //    the same, because AionCore rewrites files inside the copy and exec never sees the mode.
    //    That is the guard's `-w` test, and it is the one thing here root cannot observe — `[ -w ]`
    //    asks whether *this* process could write, and for root the answer is yes whatever the mode.
    if unsafe { libc::geteuid() } == 0 {
        skip_incapable!(
            "skipping the aionui stage guard's write-bit test: running as root, where `[ -w ]` is \
             true whatever the mode, so a read-only stage is indistinguishable from a healthy one"
        );
        return;
    }
    write_exec(&node, "#!/bin/sh\necho v24.0.0\n", 0o555);
    lock_the_stage();
    launch();
    assert!(
        !node.metadata().unwrap().permissions().readonly(),
        "a stage that runs but cannot be written to was left in place"
    );
}

#[test]
fn a_launch_that_installs_from_its_own_command_survives_an_absent_override_and_a_reclaimed_shim() {
    // `open-design` is the shipped profile that installs from its own `cmd` instead of a bundle's
    // step, so everything a launch repairs is written in that script and nothing else selects it.
    // Two of its properties are pinned here by RUNNING the shipped script, unmodified:
    //
    //   1. The refresh override is read with a default. The script runs under `set -u`, and the
    //      variable that arms the refresh is set by nothing but the `--env` of the launch that asks
    //      for it, so an undefended read aborts an ordinary launch before its first line of work.
    //   2. Corepack's shims are symlinks into the store, so reclaiming the revision that wrote them
    //      leaves them dangling. Corepack resolves a `yarn` shim before it compares targets, which
    //      fails on a dangling one and takes the whole `enable` down; the shim survives that
    //      failure, so the next launch fails identically. The script must hand Corepack a directory
    //      holding no dangling shim.
    //
    // `git`, `corepack` and `pnpm` are stood in for, because the launch otherwise clones from the
    // network and walks a workspace. The Corepack stand-in REPORTS what it was handed rather than
    // reproducing the upstream failure, so the assertion is on the state the script produces.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let profile = root.join("examples/app/open-design.toml");
    let raw = schema::parse_app(&std::fs::read(&profile).expect("read the profile")).unwrap();
    let argv = raw.cmd.expect("open-design ships a command").into_argv();
    let script = argv.last().expect("the wrapper script").clone();
    assert!(
        script.contains("corepack enable"),
        "`examples/app/open-design.toml` no longer installs Corepack's shims; this guard now \
         asserts nothing and must be retargeted or removed"
    );

    let tmp = TmpDir::new();
    let (home, bin) = (tmp.path().join("home"), tmp.path().join("bin"));
    let shims = home.join(".local/bin");
    // The checkout the script would otherwise clone. Its `.git` is what makes the clone branch skip.
    std::fs::create_dir_all(home.join(".local/share/open-design/.git")).unwrap();
    std::fs::create_dir_all(&shims).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let stub = |name: &str, body: &str| {
        use std::os::unix::fs::PermissionsExt;
        let path = bin.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    stub(
        "git",
        "#!/bin/sh\ncase \"$1 $2\" in \"rev-parse HEAD\") echo 1111111111111111111111111111111111111111 ;; esac\nexit 0\n",
    );
    stub("pnpm", "#!/bin/sh\nexit 0\n");
    stub(
        "corepack",
        "#!/bin/sh\n: > \"$HOME/corepack-saw\"\nfor e in \"$3\"/*; do\n    if [ -L \"$e\" ] && [ ! -e \"$e\" ]; then basename \"$e\" >> \"$HOME/corepack-saw\"; fi\ndone\nexit 0\n",
    );

    // A shim left by a launch whose Corepack has since been reclaimed: a symlink that resolves
    // nowhere, which is the state `sbx gc --prune` produces and the one Corepack cannot repair.
    for name in ["pnpm", "pnpx", "yarn", "yarnpkg"] {
        std::os::unix::fs::symlink(
            format!("/nix/store/0000000000000000-reclaimed/corepack/dist/{name}.js"),
            shims.join(name),
        )
        .unwrap();
    }
    assert!(
        !shims.join("yarn").exists() && shims.join("yarn").is_symlink(),
        "the dangling-shim state was not reproduced"
    );

    let launch = || {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            // The override is what a refresh launch sets and an ordinary one does not.
            .env_remove("OPEN_DESIGN_SBX_UPDATE")
            .output()
            .expect("run the shipped wrapper");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "an ordinary launch failed: {err}");
        let saw = std::fs::read_to_string(home.join("corepack-saw"))
            .expect("the wrapper did not reach Corepack at all");
        assert!(
            saw.is_empty(),
            "Corepack was handed shims that resolve nowhere: {saw}"
        );
        err
    };

    // Reclaimed: the launch repairs, and says so. A repair the user cannot see is one they cannot
    // tell from their PATH changing under them for no reason.
    let spoke = launch();
    assert!(
        spoke.contains("reclaimed"),
        "the repair was silent: {spoke}"
    );
    assert!(
        spoke.contains("yarn"),
        "the repair did not name what it dropped: {spoke}"
    );

    // Healthy: the same launch says nothing, which is what makes the sentence above a report of an
    // event rather than a line printed on every launch.
    for name in ["pnpm", "pnpx", "yarn", "yarnpkg"] {
        std::os::unix::fs::symlink(bin.join("pnpm"), shims.join(name)).unwrap();
    }
    assert!(
        shims.join("yarn").exists(),
        "the healthy state was not set up"
    );
    let quiet = launch();
    assert!(
        !quiet.contains("reclaimed"),
        "a launch with nothing to repair still announced one: {quiet}"
    );
}

#[test]
fn every_shipped_bundle_matches_the_agent_profile_it_was_derived_from() {
    // The shipped bundles under `examples/bundle/` are the single source of truth for what each
    // agent needs: the namesake profile under `examples/app/` no longer restates any of it — it
    // names the bundle with `use = ["<name>"]` and declares nothing the bundle provides. Two
    // artifacts describing one tool is the drift risk this whole feature exists to remove — so it
    // is pinned here, and it is pinnable *because* both are authored in this repo for the same
    // agent. (The general form — inferring the same obligation between two unrelated profiles — is
    // NOT sound: a front-end legitimately exposes a smaller surface than the agent it embeds. Here
    // the obligation is declared by construction, which is the whole difference.)
    //
    // The old containment direction (bundle ⊆ profile) is gone: after the thin-profile sweep the
    // profile declares none of the bundle's packages, env or egress, so containment would compare
    // against empty lists and prove nothing. Three invariants replace it, still pinnable against
    // the real artifacts:
    //   1. The namesake profile names THIS bundle — `use = ["<name>"]`, nothing else.
    //   2. No duplication: the profile carries no package, env key or egress rule the bundle
    //      provides. (It may carry things the bundle does not — hermes keeps the in-cage
    //      chromium/agent-browser for its web variants, openfox a wider npm rule — but a second
    //      copy of the same requirement is exactly the drift this feature removes.)
    //   3. Every `@group` reference — from a bundle or its namesake profile — resolves to a
    //      shipped fragment under `examples/net-groups/`, so a header's REQUIRES block (and an
    //      app's allow list) can never point at a fragment that does not exist.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let groups_dir = root.join("examples/net-groups");
    let mut shipped_groups = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&groups_dir).expect("examples/net-groups/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // Parsed with sbx's own parser, so a fragment this test accepts is one `sbx net groups
        // import` accepts.
        schema::parse(&std::fs::read(&path).expect("read the group fragment")).unwrap();
        shipped_groups.insert(path.file_stem().unwrap().to_str().unwrap().to_string());
    }

    let dir = root.join("examples/bundle");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/bundle/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();

        // Parsed with sbx's own parser, so a fragment this test accepts is one `sbx bundle import`
        // accepts — and a field written in the wrong TOML place (an `allow` under `[…packages]`,
        // which parses as an unknown key and vanishes) fails the checks below rather than passing
        // unnoticed.
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let bundle = raw.bundle.get(&name).unwrap_or_else(|| {
            panic!("{name}.toml must declare `[bundle.{name}]` (keyed by its file stem)")
        });

        let profile_path = root.join(format!("examples/app/{name}.toml"));
        let profile = schema::parse_app(
            &std::fs::read(&profile_path)
                .unwrap_or_else(|e| panic!("bundle `{name}` has no namesake agent profile: {e}")),
        )
        .unwrap();

        // Invariant 1: the namesake profile is thin and names this bundle, and only it.
        assert_eq!(
            profile.uses,
            vec![name.clone()],
            "bundle `{name}` must be named by `use = [\"{name}\"]` in `examples/app/{name}.toml` — \
             the namesake profile is thin and names its bundle"
        );

        // Invariant 2: nothing the bundle provides is restated in the profile.
        for key in profile.packages.keys() {
            assert!(
                !bundle.packages.contains_key(key),
                "`examples/app/{name}.toml` declares the package {key}, which the `{name}` bundle \
                 already provisions — one of the two moved"
            );
        }
        for key in profile.env.keys() {
            assert!(
                !bundle.env.contains_key(key),
                "`examples/app/{name}.toml` sets the env var {key}, which the `{name}` bundle \
                 already sets — one of the two moved"
            );
        }
        if let Some(schema::NetworkField::Table(t)) = &profile.network {
            for (label, from, into) in [
                ("allow", &t.allow, &bundle.allow),
                ("deny", &t.deny, &bundle.deny),
                ("mute", &t.mute, &bundle.mute),
            ] {
                for rule in from {
                    if rule.starts_with('@') {
                        // A shared-group reference belongs to the profile (the bundle may carry
                        // group references of its own); it must still resolve — invariant 3.
                        continue;
                    }
                    assert!(
                        !into.contains(rule),
                        "`examples/app/{name}.toml` carries the {label} rule {rule:?}, which the \
                         `{name}` bundle already provides — one of the two moved"
                    );
                }
            }
        }

        // Invariant 3: every @group reference resolves to a shipped fragment.
        for (label, list) in [
            ("allow", &bundle.allow),
            ("deny", &bundle.deny),
            ("mute", &bundle.mute),
        ] {
            for rule in list {
                if let Some(group) = rule.strip_prefix('@') {
                    assert!(
                        shipped_groups.contains(group),
                        "bundle `{name}` references @{group} in its {label} list, but \
                         `examples/net-groups/{group}.toml` does not exist — the header's REQUIRES \
                         block would import nothing"
                    );
                }
            }
        }
        if let Some(schema::NetworkField::Table(t)) = &profile.network {
            for (label, list) in [("allow", &t.allow), ("deny", &t.deny), ("mute", &t.mute)] {
                for rule in list {
                    if let Some(group) = rule.strip_prefix('@') {
                        assert!(
                            shipped_groups.contains(group),
                            "`examples/app/{name}.toml` references @{group} in its {label} list, \
                             but `examples/net-groups/{group}.toml` does not exist"
                        );
                    }
                }
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 36,
        "expected the shipped agent bundles to be checked, saw {checked}"
    );
}

#[test]
fn every_shipped_exemption_names_a_mise_package_its_own_layer_declares() {
    // `accepts_fresh_releases` names packages, and a name that matches nothing is ignored by
    // design: the list is unioned across a project, an app and its bundles, so a name routinely
    // sits beside a package another layer contributes. That tolerance is right at runtime and
    // useless here, because it makes a TYPO indistinguishable from a correct declaration: the
    // launch proceeds, no warning is printed, and the package it was meant to exempt resolves to no
    // version — the very failure the line was added to remove.
    //
    // So for what this repository ships, the stricter rule holds: a shipped layer names only its
    // own packages, and only `mise:` ones, since no freshness delay governs a `nix:` attribute or a
    // content-hashed prebuilt and exempting one would be a line that cannot do anything.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for dir in ["examples/bundle", "examples/app"] {
        for entry in std::fs::read_dir(root.join(dir))
            .expect("the examples directory is readable")
            .flatten()
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let raw = schema::parse(&std::fs::read(&path).expect("read the profile")).unwrap();
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            // A bundle file carries its declarations under `[bundle.<name>]`; an app profile
            // carries them at the root. Both are checked against the packages of the same layer.
            let layers: Vec<(Vec<String>, std::collections::BTreeMap<String, String>)> =
                match raw.bundle.get(&name) {
                    Some(bundle) => vec![(
                        bundle.accepts_fresh_releases.clone(),
                        bundle.packages.clone(),
                    )],
                    None => vec![(raw.accepts_fresh_releases.clone(), raw.packages.clone())],
                };
            for (named, packages) in layers {
                for pkg_name in named {
                    let declared = packages.get(&pkg_name).unwrap_or_else(|| {
                        panic!(
                            "`{}` names `{pkg_name}` in `accepts_fresh_releases`, but declares no \
                             package by that name — the line would be silently inert",
                            path.display()
                        )
                    });
                    assert!(
                        declared.starts_with("mise:"),
                        "`{}` exempts `{pkg_name}`, which is `{declared}` — no freshness delay \
                         governs that backend, so the line cannot do anything",
                        path.display()
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(
        checked >= 2,
        "expected the shipped exemptions to be checked, saw {checked}"
    );
}

#[test]
fn every_shipped_install_step_yields_to_the_upgrade_signal() {
    // `sbx upgrade provision` re-runs a bundle's install step in the app's cage with
    // `SBX_UPGRADE=1` set. The step's own "already installed" guard is what keeps an ordinary
    // launch from re-installing every time, so a step that never reads that variable takes the
    // guard's short path and does nothing — while the roll, which only sees exit status 0, prints
    // `re-installed`. The channel would be inert for that app and say the opposite, which is
    // exactly what this guard exists to prevent for the steps this repository ships.
    //
    // The variable is looked for in the step's own argv rather than in the file text, and the
    // script's whole-line shell comments are dropped before the search. Both filters are load
    // bearing and were each proven by mutation: every bundle carrying a step explains the channel
    // in a TOML comment above it *and* in a shell comment inside it, so a search over either the
    // file or the raw script passes on a script whose guard no longer reads the variable. A
    // trailing comment on a line of code is not stripped — it would take a shell parser to tell
    // one from a `#` inside a string, and a guard that reads the variable on the same line is not
    // the regression this is watching for.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let Some(provision) = raw
            .bundle
            .get(&name)
            .and_then(|bundle| bundle.provision.clone())
        else {
            continue;
        };
        let script: String = provision
            .into_argv()
            .join(" ")
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            script.contains("SBX_UPGRADE"),
            "`examples/bundle/{name}.toml` carries a `provision` whose script never reads \
             SBX_UPGRADE — `sbx upgrade provision` would run it, its own guard would skip the \
             install, and the roll would still report it as re-installed"
        );
        checked += 1;
    }
    assert!(
        checked >= 8,
        "expected the shipped install steps to be checked, saw {checked}"
    );
}

#[test]
fn every_shipped_freshness_exemption_is_named_in_the_bundles_table() {
    // The sibling of the install-step guard above, and for the same reason it exists: the third
    // column is what a reader consults before folding a bundle in, and an `accepts_fresh_releases`
    // belongs there for the sharpest version of that reason. It relaxes a supply-chain protection —
    // the bundle's tool will be installed from a build its vendor published moments ago — which is
    // exactly the kind of thing a reader must not have to open the file to discover.
    //
    // Written as its own guard rather than folded into that one: the two watch different fields,
    // and a single test failing for either would name the wrong fact half the time.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs-site/docs/guide/configuration/bundles.md"))
        .expect("the bundles page exists");
    let mut missing = Vec::new();
    let mut carriers = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        // Read with sbx's own parser, like the step above: a name written under a sub-table folds
        // into it and never reaches the launch, and grepping the file would not tell.
        if raw
            .bundle
            .get(&name)
            .is_none_or(|bundle| bundle.accepts_fresh_releases.is_empty())
        {
            continue;
        }
        carriers += 1;
        let row = page
            .lines()
            .find(|line| line.starts_with(&format!("| `{name}` |")));
        if !row.is_some_and(|line| line.contains("freshness exemption")) {
            missing.push(name);
        }
    }
    assert!(
        carriers > 0,
        "no shipped bundle names a freshness exemption, so this guard now asserts nothing"
    );
    assert!(
        missing.is_empty(),
        "these bundles lift the freshness delay for one of their packages and the bundles table \
         does not say so in their row: {missing:?}"
    );
}

#[test]
fn every_shipped_install_step_is_named_in_the_bundles_table() {
    // The bundles table's third column is what a reader consults to know what folding a bundle in
    // will bring, and a `provision` is the one entry there that *runs a command in their cage* —
    // the item least safe to leave unsaid. Nothing failed when a bundle gained one, so the column
    // drifted: when this guard was written ten bundles carried a step and five rows named it.
    //
    // A row is required rather than a bare mention. The words "install step" appear in the page's
    // own prose describing the field, so a search over the whole page would pass on a table that
    // lists none of them. And the step is read with sbx's parser rather than grepped: one named
    // only in a comment is not one a launch runs, and one written under a sub-table would vanish
    // the way a misplaced `allow` does.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs-site/docs/guide/configuration/bundles.md"))
        .expect("the bundles page exists");
    let mut missing = Vec::new();
    let mut carriers = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        if raw
            .bundle
            .get(&name)
            .and_then(|bundle| bundle.provision.as_ref())
            .is_none()
        {
            continue;
        }
        carriers += 1;
        let row = page
            .lines()
            .find(|line| line.starts_with(&format!("| `{name}` |")));
        if !row.is_some_and(|line| line.contains("install step")) {
            missing.push(name);
        }
    }
    assert!(
        carriers > 0,
        "no shipped bundle carries an install step, so this guard now asserts nothing"
    );
    missing.sort();
    assert!(
        missing.is_empty(),
        "these bundles carry an install step the bundles table does not name in their row: \
         {missing:?}"
    );
}

#[test]
fn every_shipped_bundle_declares_the_packages_its_row_names() {
    // The bundles table's FIRST column is what a reader consults to know what folding a bundle in
    // will install, and nothing held it to the files: the two guards above watch the third column
    // only, so a row could name a backend its bundle does not use and ship that way. Both errors
    // this closes were of that kind, and neither is visible from the page alone: a row counting one
    // `nix:` package for the one bundle that declares none, and a row naming `mise:` for a package
    // whose bundle explains at length that mise cannot serve it at all.
    //
    // The cell's form is the table's own, read off the rows that were already right: the number of
    // packages, then their distinct backend prefixes in sorted order, so two `nix:` packages read
    // `2 (`nix:`)`. A bundle with no `[packages]` reads `none`, the word the fourth column already
    // uses for its own empty case, which is what makes it the table's convention rather than one
    // invented here.
    //
    // Packages are read with sbx's parser rather than grepped, for the reason the sibling guards
    // give: a map written under the wrong sub-table folds into it and never reaches a launch, so
    // the row has to describe what a launch installs, not what the file appears to say.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs-site/docs/guide/configuration/bundles.md"))
        .expect("the bundles page exists");
    let mut wrong = Vec::new();
    let mut checked = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let packages = raw
            .bundle
            .get(&name)
            .map(|bundle| bundle.packages.clone())
            .unwrap_or_default();
        let want = if packages.is_empty() {
            "none".to_string()
        } else {
            // A value carries its backend as the part before the first colon (`mise:aqua:…`,
            // `flake:github:…`). One without a colon is not a form sbx accepts, so it is quoted
            // whole rather than truncated: the mismatch then names the value the row must explain.
            let backends: std::collections::BTreeSet<String> = packages
                .values()
                .map(|value| match value.split_once(':') {
                    Some((backend, _)) => format!("`{backend}:`"),
                    None => format!("`{value}`"),
                })
                .collect();
            let backends: Vec<String> = backends.into_iter().collect();
            format!("{} ({})", packages.len(), backends.join(", "))
        };
        checked += 1;
        let Some(row) = page
            .lines()
            .find(|line| line.starts_with(&format!("| `{name}` |")))
        else {
            wrong.push(format!("`{name}`: no row in the bundles table at all"));
            continue;
        };
        let got = row.split('|').nth(2).map(str::trim).unwrap_or_default();
        if got != want {
            wrong.push(format!(
                "`{name}`: the row says `{got}`, the bundle declares `{want}`"
            ));
        }
    }
    assert!(
        checked >= 36,
        "expected the shipped bundles to be checked, saw {checked}"
    );
    wrong.sort();
    assert!(
        wrong.is_empty(),
        "the bundles table's packages column does not say what these bundles install: {wrong:#?}"
    );
}

#[test]
fn every_shipped_resolver_table_is_named_in_the_bundles_table() {
    // The third column's last unwatched item. A `[tarball.<name>]`, `[deb.<name>]`,
    // `[appimage.<name>]` or `[binary.<name>]` table is what makes a prebuilt package rollable:
    // `sbx upgrade` re-runs its `resolve` command to find the current download URL, so whether a
    // bundle carries one decides whether folding it in leaves the reader with a pin they must bump
    // by hand. That is a property of the same kind as the install step beside it, and it drifted
    // the same way: the guard that recomputes the packages column found `grok` naming `mise:` for
    // a `binary:resolve` package, and the row had lost the resolver along with the backend.
    //
    // The rule is an equivalence, not a presence check, which is where it goes further than its
    // two siblings: a row that claims a resolver the bundle does not declare misleads exactly as
    // much as one that omits the table, and promises a roll that will never happen.
    //
    // `[flakes.<name>]` is deliberately not here. It is an inline source a package refers to, not
    // an auto-upgrade resolver, so the column's own word for these tables does not describe it.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs-site/docs/guide/configuration/bundles.md"))
        .expect("the bundles page exists");
    let mut wrong = Vec::new();
    let mut carriers = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let Some(bundle) = raw.bundle.get(&name) else {
            continue;
        };
        // Read as tables rather than as `<name> = "<backend>:resolve"` package values: the sentinel
        // and the table are two halves of one declaration, and it is the table that carries the
        // command a roll runs.
        let tables = [
            ("tarball", !bundle.tarball.is_empty()),
            ("deb", !bundle.deb.is_empty()),
            ("appimage", !bundle.appimage.is_empty()),
            ("binary", !bundle.binary.is_empty()),
        ];
        let carries = page
            .lines()
            .find(|line| line.starts_with(&format!("| `{name}` |")))
            .and_then(|line| line.split('|').nth(3))
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        for (backend, declared) in tables {
            if declared {
                carriers += 1;
            }
            // The article in front varies with the backend it introduces (`a `deb:``, `an
            // `appimage:``), so the phrase is matched from the backend on.
            let named = carries.contains(&format!("`{backend}:` resolver"));
            if declared && !named {
                wrong.push(format!(
                    "`{name}` declares a `[{backend}.<name>]` resolver its row does not name: \
                     {carries:?}"
                ));
            } else if named && !declared {
                wrong.push(format!(
                    "`{name}`'s row promises a `{backend}:` resolver the bundle does not declare, \
                     so nothing rolls it: {carries:?}"
                ));
            }
        }
    }
    assert!(
        carriers > 0,
        "no shipped bundle carries a resolver table, so this guard now asserts nothing"
    );
    wrong.sort();
    assert!(
        wrong.is_empty(),
        "the bundles table does not say which bundles carry an auto-upgrade resolver: {wrong:#?}"
    );
}

#[test]
fn every_shipped_bundle_carries_the_counts_its_row_states() {
    // The two numeric items of the same column, and the last of it nothing read. They are what a
    // reader weighs before folding a bundle in: how much egress it will add to the app's allowlist,
    // and how many variables it will set in the launch. Hand-maintained counts drift the way every
    // other cell here did, and a count is the worst of them to check by eye, since a row that is
    // merely out of date looks exactly like one that is right.
    //
    // The egress figure is the three lists a bundle contributes to the consuming app's `[network]`
    // table, `allow` + `mute` + `deny`, because that is the number the reader is deciding about: all
    // three land in that app, and a bundle that muted twenty hosts has added twenty entries to it
    // whatever the verb. The variables are its `[bundle.<name>.env]` map.
    //
    // Both directions again, and both wordings: a clause whose number no longer matches the file,
    // and a clause standing where the bundle declares nothing at all. The singular forms are the
    // table's own (`1 egress entry`, `1 env var`), so a row cannot satisfy this by pluralising a
    // single entry.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs-site/docs/guide/configuration/bundles.md"))
        .expect("the bundles page exists");
    let mut wrong = Vec::new();
    let mut checked = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let Some(bundle) = raw.bundle.get(&name) else {
            continue;
        };
        let egress = bundle.allow.len() + bundle.mute.len() + bundle.deny.len();
        let vars = bundle.env.len();
        let carries = page
            .lines()
            .find(|line| line.starts_with(&format!("| `{name}` |")))
            .and_then(|line| line.split('|').nth(3))
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        // The cell is a comma-separated list of clauses, each naming one thing the bundle carries.
        let clauses: Vec<&str> = carries
            .split(", ")
            .map(str::trim)
            .filter(|clause| !clause.is_empty())
            .collect();
        let stated = [
            (
                "egress entr",
                egress,
                match egress {
                    1 => "1 egress entry".to_string(),
                    n => format!("{n} egress entries"),
                },
            ),
            (
                "env var",
                vars,
                match vars {
                    1 => "1 env var".to_string(),
                    n => format!("{n} env vars"),
                },
            ),
        ];
        for (marker, count, want) in stated {
            let said: Vec<&str> = clauses
                .iter()
                .copied()
                .filter(|clause| clause.contains(marker))
                .collect();
            let holds = if count == 0 {
                said.is_empty()
            } else {
                said.len() == 1 && said[0] == want
            };
            if !holds {
                let declares = match count {
                    0 => "nothing of the kind".to_string(),
                    _ => format!("`{want}`"),
                };
                wrong.push(format!(
                    "`{name}`: the row states {said:?} where the bundle declares {declares}"
                ));
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 36,
        "expected the shipped bundles to be checked, saw {checked}"
    );
    wrong.sort();
    assert!(
        wrong.is_empty(),
        "the bundles table counts these bundles wrong: {wrong:#?}"
    );
}

/// The shipped `provision` of `<bundle>`, as the script a shell would run.
fn shipped_install_step(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/bundle")
        .join(format!("{name}.toml"));
    let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
    let argv = raw
        .bundle
        .get(name)
        .and_then(|bundle| bundle.provision.clone())
        .unwrap_or_else(|| panic!("`examples/bundle/{name}.toml` ships a provision step"))
        .into_argv();
    argv.last()
        .expect("the step's script is its last element")
        .clone()
}

#[test]
fn the_hermes_desktop_install_step_writes_its_marker_and_yields_to_a_roll() {
    // Runs the SHIPPED step, unmodified, against a stand-in home — the two guards above read the
    // step's text, and text is not behaviour. What has to hold is a pair: an ordinary launch writes
    // the marker once and then leaves it alone, and `sbx upgrade provision` (which is `SBX_UPGRADE`
    // in the cage, nothing more) writes it again. A step that only ever wrote would pass the first
    // half; one that only ever skipped would pass the second.
    let script = shipped_install_step("hermes-desktop");
    let tmp = TmpDir::new();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let marker = home.join(".hermes/.install_method");

    let run = |upgrade: bool| {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .env("SBX_UPGRADE", if upgrade { "1" } else { "" })
            .output()
            .expect("run the shipped step");
        assert!(out.status.success(), "the step failed: {out:?}");
    };

    // 1. A first launch declares the install method.
    run(false);
    assert_eq!(
        std::fs::read_to_string(&marker).expect("the marker was written"),
        "nixos\n"
    );

    // 2. An ordinary relaunch leaves what it finds. Asserted by tampering rather than by a
    //    timestamp: a write of the same bytes is indistinguishable from a skip otherwise.
    std::fs::write(&marker, "pip\n").unwrap();
    run(false);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "pip\n",
        "an ordinary launch overwrote a marker it should have left alone"
    );

    // 3. A roll writes it again, which is what keeps `re-installed` from being a lie.
    run(true);
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "nixos\n",
        "the roll left the marker as it found it, so the channel is inert for this app"
    );
}

#[test]
fn the_kiro_install_step_states_the_preference_once_and_then_says_what_it_did() {
    // Runs the SHIPPED step against a stand-in home with a stand-in `kiro-cli` that records being
    // called. This step is the one shipped `provision` that must NOT re-do its work on a roll — it
    // states a user preference, and re-imposing one the user has since changed would undo their
    // edit. So what is asserted is the pair the text cannot show: the writer is invoked exactly
    // when the preference is unset, and on a roll that finds it set the step SAYS so instead of
    // going quiet, which is the honesty `sbx upgrade provision` reports on.
    let script = shipped_install_step("kiro");
    let tmp = TmpDir::new();
    let (home, bin) = (tmp.path().join("home"), tmp.path().join("bin"));
    std::fs::create_dir_all(home.join(".kiro/settings")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let called = tmp.path().join("called");

    let stub = |ok: bool| {
        use std::os::unix::fs::PermissionsExt;
        let path = bin.join("kiro-cli");
        let code = i32::from(!ok);
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexit {code}\n",
                called.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let run = |upgrade: bool| {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("SBX_UPGRADE", if upgrade { "1" } else { "" })
            .output()
            .expect("run the shipped step");
        assert!(out.status.success(), "the step failed: {out:?}");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let invocations = || std::fs::read_to_string(&called).unwrap_or_default();

    // 1. Nothing stated yet: the CLI's own settings writer is invoked, with the preference.
    stub(true);
    let quiet = run(false);
    assert!(
        invocations().contains("settings telemetry.enabled false"),
        "the step did not state the preference through the CLI's own writer: {:?}",
        invocations()
    );
    assert_eq!(
        quiet, "",
        "a first launch that succeeded should say nothing"
    );

    // 2. The preference is now stated. A roll must not restate it — and must not go quiet either.
    std::fs::write(
        home.join(".kiro/settings/cli.json"),
        "{\"telemetry.enabled\": true}\n",
    )
    .unwrap();
    let before = invocations();
    let said = run(true);
    assert_eq!(
        invocations(),
        before,
        "the roll called the settings writer again, overriding a preference the user may have set"
    );
    assert!(
        said.contains("leaving it as it is"),
        "the roll skipped silently, so `re-installed` would be a lie: {said:?}"
    );

    // 3. A writer that fails is reported rather than swallowed — the same silence, other branch.
    std::fs::remove_file(home.join(".kiro/settings/cli.json")).unwrap();
    stub(false);
    let complained = run(false);
    assert!(
        complained.contains("could not state"),
        "a failed write said nothing: {complained:?}"
    );
}

#[test]
fn every_shipped_profile_resolves_the_egress_groups_it_references() {
    // Invariant 3 of the bundle test above reaches a profile only through its namesake bundle, so
    // the profiles that have none — the desktop and web builds, and the agents packaged by a
    // bootstrap or a source checkout — were never checked. They reference groups too, and a
    // reference to a fragment that does not ship is fail-closed: the launch loses the whole lane,
    // and the header's `sbx net groups import` line points at a file that is not there.
    //
    // This walks `examples/app/` directly, so a profile is covered whether or not a bundle exists
    // for it.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut shipped_groups = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(root.join("examples/net-groups"))
        .expect("examples/net-groups/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            shipped_groups.insert(path.file_stem().unwrap().to_str().unwrap().to_string());
        }
    }

    let mut checked = 0;
    for entry in std::fs::read_dir(root.join("examples/app"))
        .expect("examples/app/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let profile = schema::parse_app(&std::fs::read(&path).expect("read the profile")).unwrap();
        if let Some(schema::NetworkField::Table(t)) = &profile.network {
            for (label, list) in [("allow", &t.allow), ("deny", &t.deny), ("mute", &t.mute)] {
                for rule in list {
                    if let Some(group) = rule.strip_prefix('@') {
                        assert!(
                            shipped_groups.contains(group),
                            "`examples/app/{name}.toml` references @{group} in its {label} list, \
                             but `examples/net-groups/{group}.toml` does not exist — the lane it \
                             names would resolve to nothing"
                        );
                    }
                }
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 60,
        "expected the shipped profiles to be checked, saw {checked}"
    );
}
