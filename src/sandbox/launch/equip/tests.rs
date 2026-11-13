use super::*;

#[test]
fn auto_equip_tokens_formats_non_nix_tools_and_ignores_trust() {
    // no mise file → nothing to equip
    assert!(auto_equip_tokens(&crate::testutil::resolved_channels(None, None)).is_empty());

    // a mise file mixing a `nix:` tool (host-provisioned), a backend-prefixed tool, and a
    // plain registry tool: only the non-`nix:` ones become `token@version` install specs.
    // The state is Untrusted on purpose — auto-equip is the open self-equip path, so it is
    // independent of the project's trust verdict (the egress allowlist is the control).
    let mut cfg = crate::testutil::resolved_channels(None, None);
    cfg.mise = Some(crate::config::MiseConfig {
        name: "mise.toml".into(),
        state: crate::trust::TrustState::Untrusted,
        files: vec![(
            "mise.toml".into(),
            b"[tools]\n\"nix:jq\" = \"latest\"\n\"aqua:BurntSushi/ripgrep\" = \"latest\"\nnode = \"20\"\n"
                .to_vec(),
        )],
    });
    assert_eq!(
        auto_equip_tokens(&cfg),
        vec![
            "aqua:BurntSushi/ripgrep@latest".to_string(),
            "node@20".to_string(),
        ]
    );
}

/// A tool handed to `mise install` by name is installed whatever `MISE_DISABLE_TOOLS` says, so the
/// equip leaves out the tools that variable names, the last value set winning, with or without the
/// `core:` prefix mise gives its built-in tools.
#[test]
fn auto_equip_leaves_out_the_tools_mise_disable_tools_names() {
    let mut cfg = crate::testutil::resolved_channels(None, None);
    cfg.mise = Some(crate::config::MiseConfig {
        name: "mise.toml".into(),
        state: crate::trust::TrustState::Trusted,
        files: vec![(
            "mise.toml".into(),
            b"[tools]\nrust = \"1.99.1\"\n\"core:zig\" = \"0.15.2\"\nnode = \"26\"\n".to_vec(),
        )],
    });
    cfg.env = vec![
        ("MISE_DISABLE_TOOLS".into(), "node".into()),
        ("MISE_DISABLE_TOOLS".into(), " rust , zig ".into()),
    ];
    assert_eq!(auto_equip_tokens(&cfg), vec!["node@26".to_string()]);

    cfg.env.clear();
    assert_eq!(
        auto_equip_tokens(&cfg).len(),
        3,
        "an unset variable disables nothing"
    );
}

/// `wrap_mise_equip` already proves a hostile `.mise.toml` token cannot inject *shell*. The
/// other end of the same token is the launching terminal, which reads escapes: the two launch
/// messages that name these tools printed them verbatim, so a `[tools]` key of
/// `"x\u{1b}[2K\rsbx: trusted"` — a quoted TOML key is an arbitrary string — could erase the
/// trust warnings sbx had just printed above it and write a reassuring line of its own. The
/// terminal is where sbx says what it dropped and why; a repo must not be able to edit that.
#[test]
fn a_hostile_mise_token_cannot_rewrite_the_launching_terminal() {
    let tokens = [
        "node@22".to_string(),
        "x\u{1b}[2K\rsbx: project trusted\n@1.0".to_string(),
    ];
    let shown = mise_token_display(tokens.iter());

    assert!(
        !shown.contains('\u{1b}') && !shown.contains('\r') && !shown.contains('\n'),
        "no escape, carriage return or newline may reach the terminal: {shown:?}"
    );
    assert!(
        !shown.chars().any(char::is_control),
        "and nothing else the terminal acts on either: {shown:?}"
    );
    // The forged text itself is left visible rather than dropped — the reader should see the
    // token the project actually declared, only stripped of the bytes that move the cursor.
    assert!(shown.contains("sbx: project trusted"));

    // And an ordinary declaration is untouched, or this guard would be satisfied by mangling
    // every token: the message has to stay readable for the tools people really declare.
    assert!(shown.starts_with("node@22, "));
    assert_eq!(
        mise_token_display(["aqua:BurntSushi/ripgrep@latest".to_string()].iter()),
        "aqua:BurntSushi/ripgrep@latest"
    );
}

/// A mise path that would need quoting reaches the script as **one** word.
///
/// The interpolated values are sbx's own, so today none of them carries a space or a quote — which
/// is exactly why the property has to be asserted against a value that does. Unquoted, the path
/// below reaches bash as three words and the equip runs something else entirely.
#[test]
fn an_interpolated_mise_path_is_one_word_whatever_it_contains() {
    let mise = PathBuf::from("/nix/store/a b/it's/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let cmd = vec![OsString::from("demo-app")];

    let argv = wrap_mise_equip(
        &mise,
        &bash,
        EquipVerb::InstallMissing {
            suggest_project_pool: false,
        },
        &tokens,
        None,
        false,
        cmd,
    );
    let script = argv[2].to_string_lossy();

    assert!(
        script.contains(r"'/nix/store/a b/it'\''s/mise' install"),
        "the path must reach bash as one word, quotes and all: {script}"
    );
}

#[test]
fn wrap_autoequip_passes_tokens_and_command_positionally() {
    // The install tokens and the real command both ride `"$@"`, so a token from an
    // untrusted project config can never inject shell: only the absolute mise path and
    // the integer count ever reach the script string.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec![
        "aqua:BurntSushi/ripgrep@latest".to_string(),
        // a hostile token must stay a single positional arg, never reach the script
        "node@20; rm -rf /".to_string(),
    ];
    let cmd = vec![OsString::from("demo-app"), OsString::from("--print")];

    let argv = wrap_mise_equip(
        &mise,
        &bash,
        EquipVerb::InstallMissing {
            suggest_project_pool: false,
        },
        &tokens,
        None,
        false,
        cmd,
    );

    assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
    assert_eq!(argv[1], OsString::from("-c"));
    let script = argv[2].to_string_lossy();
    // mise by absolute path; the slice/shift use the count, not the tokens; the command
    // is exec'd (so it stays the cage's main process) after the tokens are shifted off.
    assert!(
        script.contains("for t in \"${@:1:2}\"; do '/nix/store/mise/bin/mise' where -- \"$t\"")
    );
    assert!(script.contains("'/nix/store/mise/bin/mise' install -- \"${missing[@]}\""));
    // The project's lane equips the project's own mise file, so it runs where that file is.
    assert!(!script.contains(MISE_OUTSIDE_PROJECT), "{script}");
    assert!(script.contains("shift 2;"));
    assert!(script.trim_end().ends_with("exec \"$@\""));
    assert!(
        !script.contains("rm -rf"),
        "a hostile token must never be interpolated into the script: {script}"
    );
    // label, then the tokens, then the command — all positional
    assert_eq!(argv[3], OsString::from("sbx-mise-equip"));
    assert_eq!(argv[4], OsString::from("aqua:BurntSushi/ripgrep@latest"));
    assert_eq!(argv[5], OsString::from("node@20; rm -rf /"));
    assert_eq!(argv[6], OsString::from("demo-app"));
    assert_eq!(argv[7], OsString::from("--print"));
}

/// The project's lane installs only what no installed version satisfies, and a launch with nothing
/// missing runs no install at all.
///
/// mise resolves a token handed to `install` by name against the newest upstream release, so
/// handing it every token reinstalls `tool@2` at each launch once a newer 2.x is out, though a
/// 2.x is installed in the pool the cage reads, and under an app's egress that fetch is refused
/// at every launch for a tool the cage already has. Run with a stand-in mise whose `where` resolves
/// only the tokens `$SBX_TEST_PRESENT` names, so the test sees which tokens reach `install`. Each
/// form ends with a `mise reshim`, the step that puts a tool resolved from a shared pool on the
/// cage's `PATH` when nothing is installed.
#[test]
fn the_project_lane_installs_only_the_tokens_mise_where_does_not_resolve() {
    let bash = PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping equip-script run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    let mise = dir.path().join("mise");
    // `where -- <token>`: resolved when the token is listed, an error past the one exit code mise
    // uses for a token it cannot resolve when the token says so, and unresolved otherwise.
    std::fs::write(
        &mise,
        "#!/bin/sh\necho \"mise $*\" >> \"$SBX_TEST_RECORD\"\n\
         if [ \"$1\" = where ]; then\n\
         case \" $SBX_TEST_PRESENT \" in *\" $3 \"*) exit 0;; esac\n\
         case \"$3\" in *broken*) exit 7;; esac\n\
         exit 1\nfi\n",
    )
    .unwrap();
    std::fs::set_permissions(&mise, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let tokens = vec![
        "core:demo-runtime@2".to_string(),
        "aqua:example/demo-tool@latest".to_string(),
        "npm:broken-lookup@1.0".to_string(),
    ];
    let wheres = "mise where -- core:demo-runtime@2\n\
                  mise where -- aqua:example/demo-tool@latest\n\
                  mise where -- npm:broken-lookup@1.0\n";
    for (present, install) in [
        // Every token resolves: no install runs, so nothing is fetched.
        (
            "core:demo-runtime@2 aqua:example/demo-tool@latest npm:broken-lookup@1.0",
            None,
        ),
        // Some resolve: only the rest are installed, in declaration order, after a `--`.
        (
            "aqua:example/demo-tool@latest",
            Some("mise install -- core:demo-runtime@2 npm:broken-lookup@1.0\n"),
        ),
        // None resolves, one of them through an error rather than a miss: all are installed.
        (
            "",
            Some(
                "mise install -- core:demo-runtime@2 aqua:example/demo-tool@latest \
                 npm:broken-lookup@1.0\n",
            ),
        ),
    ] {
        let record = dir.path().join("record");
        let _ = std::fs::remove_file(&record);
        let argv = wrap_mise_equip(
            Path::new("./mise"),
            &bash,
            EquipVerb::InstallMissing {
                suggest_project_pool: false,
            },
            &tokens,
            None,
            false,
            vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("echo cmd >> \"$SBX_TEST_RECORD\""),
            ],
        );
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(dir.path())
            .env("SBX_TEST_RECORD", &record)
            .env("SBX_TEST_PRESENT", present)
            .output()
            .expect("run the generated equip script");
        assert!(
            out.status.success(),
            "the equip script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let calls = std::fs::read_to_string(&record).expect("the stand-ins recorded their calls");
        assert_eq!(
            calls,
            format!("{wheres}{}mise reshim\ncmd\n", install.unwrap_or("")),
            "present: {present:?}"
        );
    }
}

/// A global app that does not read the project's pool is told, when an install of the project's
/// tools fails, which grant would let it run the copy `sbx run` installs; the line is printed only
/// on a failure, and only for the launch that asked for it.
#[test]
fn a_failed_project_install_names_the_project_pool_grant_when_asked() {
    let bash = PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping equip-script run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    let mise = dir.path().join("mise");
    // `where` resolves nothing, so every token is missing; `install` exits with the code asked for.
    std::fs::write(
        &mise,
        "#!/bin/sh\ncase \"$1\" in where) exit 1;; install) exit \"$SBX_TEST_INSTALL_RC\";; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&mise, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    for (suggest, install_rc, printed) in
        [(true, "1", true), (true, "0", false), (false, "1", false)]
    {
        let argv = wrap_mise_equip(
            Path::new("./mise"),
            &bash,
            EquipVerb::InstallMissing {
                suggest_project_pool: suggest,
            },
            &["core:demo-runtime@2".to_string()],
            None,
            false,
            vec![OsString::from("/bin/true")],
        );
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(dir.path())
            .env("SBX_TEST_INSTALL_RC", install_rc)
            .output()
            .expect("run the generated equip script");
        assert!(
            out.status.success(),
            "the command still runs after a failed install"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            stderr.contains(PROJECT_POOL_HINT),
            printed,
            "suggest {suggest}, install exit {install_rc}: {stderr}"
        );
    }
}

#[test]
fn wrap_mise_equip_uses_the_global_verb_for_app_packages() {
    // The app's `[packages] mise:` tools are equipped globally (`mise use -g`), so the verb
    // is interpolated literally (an sbx-chosen constant, never config) while the token stays
    // positional — proving the same no-shell-injection shape for the global lane.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let cmd = vec![OsString::from("demo-app")];

    let argv = wrap_mise_equip(
        &mise,
        &bash,
        EquipVerb::PinGlobally,
        &tokens,
        None,
        true,
        cmd,
    );

    let script = argv[2].to_string_lossy();
    assert!(script.contains("'/nix/store/mise/bin/mise' -C / use -g --pin -- \"${@:1:1}\""));
    assert!(script.contains("shift 1;"));
    // no data-dir override: the equip runs under the ambient primary
    assert!(!script.contains("MISE_DATA_DIR="));
    // the token is a positional arg, never in the script
    assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
    assert_eq!(argv[5], OsString::from("demo-app"));
}

/// The launch freezes a `mise:` package at its installed version and the roll is what moves it.
/// Both halves are needed and each breaks the other's guarantee when removed, so they are
/// asserted together rather than one per test.
#[test]
fn a_mise_package_is_pinned_at_equip_and_only_a_bump_roll_moves_it() {
    // Equip: the resolved version is written into the cage's config. Without this the config
    // keeps the floating request, the tool's mise shim re-resolves it on every exec, and the
    // app stops launching as soon as upstream publishes a version the pool does not hold.
    assert!(
        MISE_EQUIP_VERB.contains("--pin"),
        "the equip must pin, or a launch re-resolves: {MISE_EQUIP_VERB}"
    );
    assert!(
        MISE_EQUIP_VERB.starts_with("use -g"),
        "the app lane equips globally: {MISE_EQUIP_VERB}"
    );

    // Roll: an exact pin is a range a plain `mise upgrade` treats as already satisfied, so
    // without `--bump` the shipped roll would report every tool up to date and move nothing.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];

    for rt in [
        binds::Runtime::ProjectDefault,
        binds::Runtime::GlobalApp("demo-app"),
    ] {
        let cmd = mise_upgrade_cmd(rt, &mise, &bash, &tokens);
        let script = cmd[2].to_string_lossy();
        assert!(
            script.contains("'/nix/store/mise/bin/mise' -C / upgrade --bump -- \"$@\""),
            "a pinned tool only advances with --bump: {script}"
        );
    }
}

/// What the launch says it is about to do is what it does.
///
/// The announcement carried a hand-written copy of the verb, so it kept saying `mise use -g`
/// after the equip started pinning: a reader who reproduced the printed command by hand got a
/// floating install and no hint that the two had parted. Reading both from one constant is the
/// fix; this holds it there.
#[test]
fn the_equip_line_names_the_invocation_it_runs() {
    let line = equip_announcement(&[
        "aqua:example/demo-tool".to_string(),
        "npm:demo-cli".to_string(),
    ]);

    assert!(
        line.contains(&format!("mise {MISE_EQUIP_VERB}:")),
        "the printed verb must be the one the equip uses: {line}"
    );
    // The tools are named too, and separately: this line is how a user learns which package a
    // slow launch is fetching.
    assert!(
        line.contains("aqua:example/demo-tool, npm:demo-cli"),
        "{line}"
    );
}

/// The equip line writes its tokens as text, whatever they hold: a token carrying an escape, a
/// carriage return or a newline reaches the terminal stripped of them, as the project's own tools
/// do, and its visible text is kept.
#[test]
fn the_equip_line_writes_its_tokens_as_text() {
    let line = equip_announcement(&["x\u{1b}[2K\rsbx: project trusted\n@1.0".to_string()]);
    assert!(
        !line.chars().any(char::is_control),
        "nothing the terminal acts on may reach it: {line:?}"
    );
    assert!(line.contains("sbx: project trusted"), "{line:?}");
}

#[test]
fn wrap_mise_equip_pins_the_app_global_data_dir_for_the_global_lane() {
    // For a global app, Lane-1 `mise use -g` is pinned to the app-global home pool so the app
    // tool installs there (shared across projects, read by `sbx app show`/`gc`) while the
    // ambient primary stays the per-project pool. The pin applies to the equip step only — the
    // exec'd command keeps the ambient value — and the value is single-quoted (injection-safe,
    // an sbx-owned fixed path).
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let cmd = vec![OsString::from("demo-app")];
    let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

    let argv = wrap_mise_equip(
        &mise,
        &bash,
        EquipVerb::PinGlobally,
        &tokens,
        Some(&data_dir),
        true,
        cmd,
    );

    let script = argv[2].to_string_lossy();
    // the equip's MISE_DATA_DIR is pinned to the app-global home, quoted, before mise
    assert!(
        script.contains(&format!(
            "MISE_DATA_DIR='{data_dir}' '/nix/store/mise/bin/mise' -C / use -g"
        )),
        "the global lane must pin the app-global data dir: {script}"
    );
    // the pin is only on the equip command, not the exec'd command
    assert!(script.trim_end().ends_with("exec \"$@\""));
    // the token still rides positionally
    assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
}

/// A stand-in `mise` (and a stand-in command) that appends the `MISE_DATA_DIR` it was invoked
/// with to `$SBX_TEST_RECORD`, so a run of the generated script reports the value each half
/// actually saw rather than the value the script text appears to set.
fn recording_stub(path: &std::path::Path, tag: &str) {
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf '{tag}=%s\\n' \"${{MISE_DATA_DIR-unset}}\" >> \"$SBX_TEST_RECORD\"\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

#[test]
fn running_the_equip_script_gives_mise_the_pinned_dir_and_the_command_the_ambient_one() {
    // The pin is a string in a generated bash script, and a test that only reads that string
    // cannot tell an assignment that reaches mise from one that does not — nor that the pin stops
    // at the equip step, which is the whole reason it is written as a prefix rather than an export.
    // So run the script, with a stand-in mise and a stand-in command that each report the
    // `MISE_DATA_DIR` they were given.
    let bash = std::path::PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping equip-script run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    let mise = dir.path().join("mise");
    let cmd = dir.path().join("app");
    recording_stub(&mise, "mise");
    recording_stub(&cmd, "cmd");

    let ambient = "/opt/sbx/mise-project";
    let pinned = crate::sandbox::binds::mise_app_global_data_dir();
    let tokens = vec!["aqua:example/demo-tool".to_string()];

    // Lane 1 for a global app: pinned. Lane 2 (and every other runtime): no pin.
    for (pin, expected_mise) in [(Some(pinned.as_str()), pinned.as_str()), (None, ambient)] {
        let record = dir.path().join("record");
        let _ = std::fs::remove_file(&record);
        // `mise` is named from the fixture the script runs in, the way a launch names a store path:
        // the fixture root never enters the script.
        let argv = wrap_mise_equip(
            Path::new("./mise"),
            &bash,
            EquipVerb::PinGlobally,
            &tokens,
            pin,
            true,
            vec![cmd.clone().into_os_string()],
        );
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(dir.path())
            .env("SBX_TEST_RECORD", &record)
            .env("MISE_DATA_DIR", ambient)
            .output()
            .expect("run the generated equip script");
        assert!(
            out.status.success(),
            "the equip script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let seen = std::fs::read_to_string(&record).expect("the stubs recorded their env");
        assert!(
            seen.contains(&format!("mise={expected_mise}\n")),
            "mise did not run under {expected_mise}: {seen}"
        );
        // The pin never reaches the exec'd command, which keeps the cage's ambient primary: an
        // agent's own `mise use` after launch must still land where the ambient value says.
        assert!(
            seen.contains(&format!("cmd={ambient}\n")),
            "the exec'd command did not keep the ambient primary: {seen}"
        );
    }
}

/// A stand-in `mise` that appends its whole argv, one line per call, to `$SBX_TEST_RECORD`.
fn argv_recording_stub(path: &std::path::Path) {
    std::fs::write(
        path,
        "#!/bin/sh\necho \"mise $*\" >> \"$SBX_TEST_RECORD\"\n",
    )
    .unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

#[test]
fn running_the_equip_script_reinstalls_a_pipx_tool_whose_python_is_gone() {
    // A pipx virtualenv links `bin/python` to the store path of the interpreter it was built on,
    // and mise keeps counting it as installed after that path leaves the cage. Run the script
    // against a real tree, so the test sees which installs the checks pick and not only the text.
    let bash = std::path::PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping equip-script run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    let mise = dir.path().join("mise");
    argv_recording_stub(&mise);
    let pool = dir.path().join("pool");
    let installs = pool.join("installs");
    let venv = |tool: &str, version: &str, python: &std::path::Path| {
        let bin = installs.join(tool).join(version).join("env").join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(python, bin.join("python")).unwrap();
    };
    let gone =
        std::path::Path::new("/nix/store/00000000000000000000000000000000-python3/bin/python");
    let present = dir.path().join("python");
    std::fs::write(&present, "").unwrap();
    // Broken: its interpreter is gone. mise's alias link to it must not trigger a second repair.
    venv("pipx-broken-tool", "1.2.0", gone);
    std::os::unix::fs::symlink("./1.2.0", installs.join("pipx-broken-tool").join("latest"))
        .unwrap();
    // Broken too, but under names the cage chose: an escape sequence mise would print on the
    // launching terminal, and a `ref:` spec mise would build from. Neither is repaired.
    venv("pipx-broken-tool", "1.0\u{1b}[2K", gone);
    venv("pipx-broken-tool", "ref:main", gone);
    // Healthy: its interpreter is present.
    venv("pipx-healthy-tool", "3.0", &present);
    // Not a pipx token, even though its install looks like a broken virtualenv.
    venv("aqua-example-demo-tool", "0.1", gone);
    // `pipx:absent-tool` has no install at all.
    let tokens = vec![
        "pipx:broken-tool".to_string(),
        "pipx:healthy-tool@3.0".to_string(),
        "pipx:absent-tool".to_string(),
        "aqua:example/demo-tool".to_string(),
    ];

    // `mise` and the pinned pool are named from the fixture the script runs in, as a launch names a
    // store path and a constant: the fixture root never enters the script.
    for pin in [Some("pool"), None] {
        let record = dir.path().join("record");
        let _ = std::fs::remove_file(&record);
        let argv = wrap_mise_equip(
            Path::new("./mise"),
            &bash,
            EquipVerb::PinGlobally,
            &tokens,
            pin,
            true,
            vec![OsString::from("true")],
        );
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(dir.path())
            .env("SBX_TEST_RECORD", &record)
            .env("MISE_DATA_DIR", &pool)
            .output()
            .expect("run the generated equip script");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "the equip script failed: {stderr}");
        let calls = std::fs::read_to_string(&record).expect("the stub recorded its calls");
        assert_eq!(
            calls,
            "mise -C / install --force pipx:broken-tool@1.2.0\n\
             mise -C / use -g --pin -- pipx:broken-tool pipx:healthy-tool@3.0 pipx:absent-tool \
             aqua:example/demo-tool\n",
            "exactly the broken pipx install is repaired, then the equip runs (pin {pin:?})"
        );
        assert!(
            stderr.contains("sbx: pipx:broken-tool: the Python its environment was built on"),
            "the repair is announced: {stderr}"
        );
    }
}

/// mise names a tool's directory by its own rule, which splits and lowercases a token's capitals:
/// a `pipx:` token written with them is installed under a name the token does not spell. Its broken
/// install is found and repaired all the same.
#[test]
fn running_the_equip_script_repairs_a_pipx_tool_whose_directory_mise_named_from_capitals() {
    let bash = std::path::PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping equip-script run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    argv_recording_stub(&dir.path().join("mise"));
    let pool = dir.path().join("pool");
    // The second keeps its capitals, as a directory named before mise lowercased them would.
    for install in ["pipx-broken-caps/2.0", "pipx-Kept-Caps/1.0"] {
        let bin = pool.join("installs").join(install).join("env/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::os::unix::fs::symlink(
            "/nix/store/00000000000000000000000000000000-python3/bin/python",
            bin.join("python"),
        )
        .unwrap();
    }
    let record = dir.path().join("record");
    let argv = wrap_mise_equip(
        Path::new("./mise"),
        &bash,
        EquipVerb::PinGlobally,
        &["pipx:Broken-Caps".to_string(), "pipx:Kept-Caps".to_string()],
        None,
        true,
        vec![OsString::from("true")],
    );
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(dir.path())
        .env("SBX_TEST_RECORD", &record)
        .env("MISE_DATA_DIR", &pool)
        .output()
        .expect("run the generated equip script");
    assert!(
        out.status.success(),
        "the equip script failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&record).expect("the stub recorded its calls"),
        "mise -C / install --force pipx:Broken-Caps@2.0\n\
         mise -C / install --force pipx:Kept-Caps@1.0\n\
         mise -C / use -g --pin -- pipx:Broken-Caps pipx:Kept-Caps\n"
    );
}

/// Every script that hands mise a token ends mise's options before it, so a token is read as a
/// tool and never as an option. The project's lane takes its tokens from the project's own
/// `.mise.toml`, which no declaration check has seen, and a word starting with `-` there would
/// otherwise reach mise as a flag: `use -g --pin --help` prints the help and installs nothing.
///
/// Run, rather than read off the script text, with a stand-in mise that records its argv.
#[test]
fn every_mise_script_ends_the_options_before_its_tokens() {
    let bash = PathBuf::from("/bin/bash");
    if !bash.is_file() {
        skip_incapable!("skipping mise-script run: no /bin/bash on this host");
        return;
    }
    let dir = crate::testutil::TmpDir::new();
    argv_recording_stub(&dir.path().join("mise"));
    let tokens = vec!["--help".to_string()];
    let then = || vec![OsString::from("/bin/true")];
    // `mise` is named from the fixture the script runs in, as the other runs here name it.
    let mise = Path::new("./mise");
    for (what, argv, called) in [
        (
            "the project's lane",
            wrap_mise_equip(
                mise,
                &bash,
                EquipVerb::InstallMissing {
                    suggest_project_pool: false,
                },
                &tokens,
                None,
                false,
                then(),
            ),
            "mise where -- --help",
        ),
        (
            "the app's lane",
            wrap_mise_equip(
                mise,
                &bash,
                EquipVerb::PinGlobally,
                &tokens,
                None,
                true,
                then(),
            ),
            "mise -C / use -g --pin -- --help",
        ),
        (
            "the roll",
            mise_upgrade_cmd(binds::Runtime::ProjectDefault, mise, &bash, &tokens),
            "mise -C / upgrade --bump -- --help",
        ),
        (
            "the roll's question",
            mise_state_cmd(binds::Runtime::ProjectDefault, mise, &bash, &tokens),
            "mise -C / outdated --bump --json -- --help",
        ),
    ] {
        let record = dir.path().join("record");
        let _ = std::fs::remove_file(&record);
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(dir.path())
            .env("SBX_TEST_RECORD", &record)
            .output()
            .expect("run the generated script");
        assert!(
            out.status.success(),
            "{what}: the script failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let seen = std::fs::read_to_string(&record).expect("the stand-in recorded its argv");
        assert!(
            seen.lines().any(|line| line == called),
            "{what}: mise was not called as `{called}`: {seen}"
        );
    }
}

#[test]
fn mise_upgrade_cmd_pins_the_app_global_pool_only_for_a_global_app() {
    // `sbx upgrade mise` rolls `[packages] mise:` tools, which for a global app live in the
    // app-global home pool. The cage's ambient primary for a global app is the per-project pool
    // (the split), which does not hold them, so the roll must be pinned to the app-global pool —
    // else `mise upgrade` finds nothing and silently rolls nothing (a shipped-command regression).
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec![
        "aqua:example/demo-tool".to_string(),
        "x'; rm -rf ~; echo '".to_string(),
    ];
    let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

    // A global app is pinned to the app-global pool; `sbx run` and a per-project app have a single
    // pool, the ambient primary, and are not.
    for (rt, pinned) in [
        (binds::Runtime::GlobalApp("cc"), true),
        (binds::Runtime::ProjectApp("cc"), false),
        (binds::Runtime::ProjectDefault, false),
    ] {
        let cmd = mise_upgrade_cmd(rt, &mise, &bash, &tokens);
        assert_eq!(cmd[0], OsString::from("/nix/store/bash/bin/bash"));
        let script = cmd[2].to_string_lossy();
        assert!(
            script.starts_with("set -e; "),
            "a failing upgrade fails the cage before its report: {script}"
        );
        assert_eq!(
            script.contains(&format!("export MISE_DATA_DIR='{data_dir}'; ")),
            pinned,
            "only a global app's installs live in the app-global pool: {script}"
        );
        // The pool's listing follows the upgrade, so the roll can tell a current tool from one the
        // equip never installed.
        let upgrade = script.find("upgrade --bump -- \"$@\"").expect("the roll");
        let report = script.find(MISE_STATE_MARKER).expect("the report");
        assert!(upgrade < report, "{script}");
        // And one precedes it, so a move mise does not name can still be read off the two.
        let before = script.find(MISE_BEFORE_MARKER).expect("the listing before");
        assert!(before < upgrade, "{script}");
        assert!(script.contains("'/nix/store/mise/bin/mise' -C / ls --global --json"));
        // The tokens are data: positional, never in the script.
        assert!(!script.contains("rm -rf"));
        assert_eq!(
            cmd[4..],
            tokens.iter().map(OsString::from).collect::<Vec<_>>()[..]
        );
    }
}

#[test]
fn wrap_flake_equip_passes_quads_and_command_positionally() {
    // Each (ref, target, good, key) rides `"$@"`, so a value from an untrusted-but-trusted-app
    // config can never inject shell: only the absolute nix path, the out-link parent, and the
    // integer quad count reach the script string. The per-quad build, the good-out-link
    // promotion, the fallback branch, the `<target>.failed` marker, and the host-resolvable gc
    // root (keyed by package name, the `$key` positional, never interpolated) are all present.
    let nix = PathBuf::from("/nix/store/nix/bin/nix");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let dir = PathBuf::from("/home/sandbox/.local/state/sbx/flake");
    let quads = vec![
        (
            "github:example/flake-tool#tui".to_string(),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool-rev"),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool"),
            "flake-tool".to_string(),
        ),
        // a hostile ref must stay a single positional arg, never reach the script
        (
            "github:evil/x#bin; rm -rf /".to_string(),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil-rev"),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil"),
            "evil".to_string(),
        ),
    ];
    let cmd = vec![OsString::from("flake-tool"), OsString::from("-z")];
    let env_bin = PathBuf::from("/nix/store/coreutils/bin/env");

    let argv = wrap_flake_equip(&nix, &bash, &env_bin, &dir, &quads, cmd);

    assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
    assert_eq!(argv[1], OsString::from("-c"));
    let script = argv[2].to_string_lossy();
    // nix by absolute path; the quad count drives the loop, not the refs; the command is exec'd
    // after the quads are shifted.
    assert!(script.contains("n=2"));
    assert!(script.contains(
        "'/nix/store/nix/bin/nix' build \"$ref\" --no-write-lock-file --out-link \"$target\""
    ));
    assert!(
        script
            .contains("'/nix/store/coreutils/bin/mkdir' -p '/home/sandbox/.local/state/sbx/flake'")
    );
    // the fallback machinery: the per-revision failed-marker, the promotion of the good
    // out-link on success, and the loud notice when a pinned build fails.
    assert!(script.contains("'/nix/store/coreutils/bin/touch' \"$target.failed\""));
    assert!(script.contains("'/nix/store/coreutils/bin/ln' -sfn \"$sp\" \"$good\""));
    assert!(script.contains("falling back to the last good build"));
    assert!(script.contains("there is no prior build to fall back to"));
    // the gc root is keyed by the `$key` positional (the package name), targeting the used
    // build's store path resolved by `readlink -f` — host-resolvable, overwritten each launch
    assert!(script.contains(
        "'/nix/store/coreutils/bin/ln' -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\""
    ));
    // Every helper is an absolute store path, never a bare name: this preamble is the cage's
    // first process, before the `[proc]` shim filters anything, and the cage writes its own PATH.
    for bare in ["mkdir ", "touch ", "rm ", "readlink ", "ln "] {
        assert!(
            !script.contains(bare),
            "{bare} is run by name, which the cage's PATH decides: {script}"
        );
    }
    assert!(script.contains("shift 4"));
    assert!(script.trim_end().ends_with("exec \"$@\""));
    assert!(
        !script.contains("rm -rf"),
        "a hostile ref must never be interpolated into the script: {script}"
    );
    // label, then interleaved (ref, target, good, key) quads, then the command — all positional
    assert_eq!(argv[3], OsString::from("sbx-flake-equip"));
    assert_eq!(argv[4], OsString::from("github:example/flake-tool#tui"));
    assert_eq!(
        argv[5],
        OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool-rev")
    );
    assert_eq!(
        argv[6],
        OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool")
    );
    assert_eq!(argv[7], OsString::from("flake-tool"));
    assert_eq!(argv[8], OsString::from("github:evil/x#bin; rm -rf /"));
    assert_eq!(
        argv[9],
        OsString::from("/home/sandbox/.local/state/sbx/flake/evil-rev")
    );
    assert_eq!(
        argv[10],
        OsString::from("/home/sandbox/.local/state/sbx/flake/evil")
    );
    assert_eq!(argv[11], OsString::from("evil"));
    assert_eq!(argv[12], OsString::from("flake-tool"));
    assert_eq!(argv[13], OsString::from("-z"));
}

/// Every path the wrap interpolates reaches the shell as one word, whatever it holds: the out-link
/// parent, `nix` and the coreutils it runs are read back as written even when their names carry a
/// quote, a double quote or a blank.
///
/// The paths are relative to the fixture, which the script runs from: a launch passes store paths
/// and a constant, and the names below are the whole of what is under test, whatever the fixture
/// root is called.
#[test]
fn wrap_flake_equip_quotes_every_path_it_interpolates() {
    let tmp = crate::testutil::TmpDir::new();
    let (tools, flake) = ("co'reutils \"bin\"", "it's \"flake\"");
    std::fs::create_dir_all(tmp.join(tools)).unwrap();
    let host = host_env_bin();
    for name in ["env", "mkdir", "touch", "rm", "readlink", "ln"] {
        std::os::unix::fs::symlink(host.with_file_name(name), tmp.join(tools).join(name)).unwrap();
    }
    let argv = wrap_flake_equip(
        Path::new("ni'x"),
        &PathBuf::from("bash"),
        &Path::new(tools).join("env"),
        Path::new(flake),
        &[],
        vec![OsString::from("true")],
    );

    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(tmp.path())
        .output()
        .expect("run the flake-equip script");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        tmp.join(flake).is_dir(),
        "the out-link parent is made at the path it was given"
    );
}

/// The host's coreutils `env`, whose siblings the wrap invokes by absolute path.
///
/// The tests below really run the emitted script, so the helper paths baked into it have to name
/// programs this host has; on a launch they are the cage's store copies, pinned read-only.
#[cfg(test)]
fn host_env_bin() -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    // The whole set has to come from one directory, the way the cage's does: a PATH entry may
    // carry an `env` of its own (a shell snippet from a toolchain installer, say) without the
    // helpers beside it.
    let runnable = |path: &Path| {
        std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set"))
        .map(|dir| dir.join("env"))
        .find(|env_bin| {
            ["env", "mkdir", "touch", "rm", "readlink", "ln"]
                .iter()
                .all(|name| runnable(&env_bin.with_file_name(name)))
        })
        .expect("a coreutils bin directory on PATH")
}

/// Write `body` to `path` as an executable file (a stub used to drive the flake-equip script).
#[cfg(test)]
fn write_exec(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

#[test]
fn wrap_flake_equip_falls_back_to_the_last_good_build_when_a_pinned_build_fails() {
    // The headline of the fallback feature, run for real: when the content-keyed build
    // fails, the launch must run the last good build instead of breaking — and must not
    // re-attempt the doomed build on the next launch (the `<target>.failed` marker).
    let tmp = crate::testutil::TmpDir::new();
    let flake = tmp.path().join("flake");
    std::fs::create_dir_all(&flake).unwrap();

    // A `nix` that always fails the build, recording each call so we can prove the marker
    // stops the second attempt.
    let calls = tmp.path().join("nixcalls");
    let fake_nix = tmp.path().join("nix");
    write_exec(
        &fake_nix,
        &format!(
            "#!/bin/sh\necho call >> {}\nexit 1\n",
            crate::testutil::sh_word(&calls)
        ),
    );

    // A pre-existing good build (the previous version) the fallback resolves to.
    let good_store = tmp.path().join("goodstore");
    std::fs::create_dir_all(good_store.join("bin")).unwrap();
    let good = flake.join("tool");
    std::os::unix::fs::symlink(&good_store, &good).unwrap();
    let target = flake.join("tool-deadbeef"); // content-keyed, does not exist

    let quads = vec![(
        "github:o/tool#default".to_string(),
        target.clone(),
        good.clone(),
        "tool".to_string(),
    )];
    // The command the wrap execs once equip is done — reaching it proves we did NOT exit 1.
    let cmd = vec![OsString::from("echo"), OsString::from("FELL-BACK")];
    // `nix` and the out-link parent are named from the fixture the script runs in, the way a
    // launch names them from store paths and a constant: the fixture root never enters the script.
    let argv = wrap_flake_equip(
        Path::new("./nix"),
        &PathBuf::from("bash"),
        &host_env_bin(),
        Path::new("flake"),
        &quads,
        cmd,
    );

    let run = || {
        std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(tmp.path())
            .output()
            .expect("run the flake-equip script")
    };

    // First launch: build fails → fall back to the good build, exec the command, mark the failure.
    let out1 = run();
    assert!(out1.status.success(), "must fall back, not exit 1");
    assert!(
        String::from_utf8_lossy(&out1.stdout).contains("FELL-BACK"),
        "the command must run off the good build after a failed pinned build"
    );
    assert!(
        String::from_utf8_lossy(&out1.stderr).contains("falling back to the last good build"),
        "the fallback must be announced loudly on stderr"
    );
    assert!(
        flake.join("tool-deadbeef.failed").exists(),
        "a failed pinned build must be marked so it is not re-attempted every launch"
    );
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap().lines().count(),
        1,
        "the failing build is attempted exactly once"
    );

    // Second launch: the marker short-circuits the doomed rebuild — still falls back, no new call.
    let out2 = run();
    assert!(out2.status.success());
    assert!(String::from_utf8_lossy(&out2.stdout).contains("FELL-BACK"));
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap().lines().count(),
        1,
        "the marker must stop a second attempt at the same failing revision"
    );
}

#[test]
fn wrap_flake_equip_hard_fails_when_a_build_fails_and_no_good_build_exists() {
    // With no prior good build to fall back to, a failed build is a hard error (exit 1) — the
    // app cannot run, and that must surface, not be masked.
    let tmp = crate::testutil::TmpDir::new();
    let flake = tmp.path().join("flake");
    std::fs::create_dir_all(&flake).unwrap();
    let fake_nix = tmp.path().join("nix");
    write_exec(&fake_nix, "#!/bin/sh\nexit 1\n");

    let good = flake.join("tool"); // does NOT exist
    let target = flake.join("tool-deadbeef");
    let quads = vec![(
        "github:o/tool#default".to_string(),
        target,
        good,
        "tool".to_string(),
    )];
    let cmd = vec![OsString::from("echo"), OsString::from("SHOULD-NOT-RUN")];
    // Named from the fixture the script runs in, as the fallback test above says.
    let argv = wrap_flake_equip(
        Path::new("./nix"),
        &PathBuf::from("bash"),
        &host_env_bin(),
        Path::new("flake"),
        &quads,
        cmd,
    );

    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(tmp.path())
        .output()
        .expect("run the flake-equip script");
    assert!(!out.status.success(), "no good build → must hard-fail");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("SHOULD-NOT-RUN"),
        "the command must not run when there is nothing to fall back to"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no prior build to fall back to"));
}

#[test]
fn mise_state_cmd_asks_both_questions_in_the_pool_the_roll_advances() {
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec![
        "aqua:example/demo-tool".to_string(),
        "x'; rm -rf ~; echo '".to_string(),
    ];
    let data_dir = crate::sandbox::binds::mise_app_global_data_dir();
    for (rt, pinned) in [
        (binds::Runtime::GlobalApp("cc"), true),
        (binds::Runtime::ProjectApp("cc"), false),
        (binds::Runtime::ProjectDefault, false),
    ] {
        let cmd = mise_state_cmd(rt, &mise, &bash, &tokens);
        assert_eq!(cmd[0], OsString::from("/nix/store/bash/bin/bash"));
        assert_eq!(cmd[1], OsString::from("-c"));
        let script = cmd[2].to_string_lossy();
        assert!(
            script.starts_with("set -e; "),
            "a failing mise fails the cage: {script}"
        );
        assert_eq!(
            script.contains(&format!("export MISE_DATA_DIR='{data_dir}'; ")),
            pinned,
            "only a global app's installs live in the app-global pool: {script}"
        );
        assert!(script.contains(MISE_STATE_MARKER));
        assert!(script.contains("'/nix/store/mise/bin/mise' -C / ls --global --json"));
        // The roll's own flag, so the target `outdated` names is the one the roll would write.
        assert!(
            script.contains("'/nix/store/mise/bin/mise' -C / outdated --bump --json -- \"$@\"")
        );
        // The tokens are data: positional, never in the script.
        assert!(!script.contains("rm -rf"));
        assert_eq!(
            cmd[4..],
            tokens.iter().map(OsString::from).collect::<Vec<_>>()[..]
        );
    }
}
