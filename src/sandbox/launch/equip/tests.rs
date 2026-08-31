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

    let argv = wrap_mise_equip(&mise, &bash, "install", &tokens, None, cmd);

    assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
    assert_eq!(argv[1], OsString::from("-c"));
    let script = argv[2].to_string_lossy();
    // mise by absolute path; the slice/shift use the count, not the tokens; the command
    // is exec'd (so it stays the cage's main process) after the tokens are shifted off.
    assert!(script.contains("/nix/store/mise/bin/mise install \"${@:1:2}\""));
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

#[test]
fn wrap_mise_equip_uses_the_global_verb_for_app_packages() {
    // The app's `[packages] mise:` tools are equipped globally (`mise use -g`), so the verb
    // is interpolated literally (an sbx-chosen constant, never config) while the token stays
    // positional — proving the same no-shell-injection shape for the global lane.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let cmd = vec![OsString::from("demo-app")];

    let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, None, cmd);

    let script = argv[2].to_string_lossy();
    assert!(script.contains("/nix/store/mise/bin/mise use -g \"${@:1:1}\""));
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

    let plain = mise_upgrade_cmd(binds::Runtime::ProjectDefault, &mise, &bash, &tokens);
    assert_eq!(plain[1], OsString::from("upgrade"));
    assert_eq!(
        plain[2],
        OsString::from("--bump"),
        "a pinned tool only advances with --bump"
    );
    assert_eq!(plain[3], OsString::from("aqua:example/demo-tool"));

    // The same on the global-app lane, where the roll runs through a shell to pin the pool.
    let global = mise_upgrade_cmd(binds::Runtime::GlobalApp("demo-app"), &mise, &bash, &tokens);
    assert!(
        global[2]
            .to_string_lossy()
            .contains("upgrade --bump \"$@\""),
        "the global lane bumps too: {}",
        global[2].to_string_lossy()
    );
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

    let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, Some(&data_dir), cmd);

    let script = argv[2].to_string_lossy();
    // the equip's MISE_DATA_DIR is pinned to the app-global home, single-quoted, before mise
    assert!(
        script.contains(&format!(
            "MISE_DATA_DIR='{data_dir}' /nix/store/mise/bin/mise use -g"
        )),
        "the global lane must pin the app-global data dir: {script}"
    );
    // the pin is only on the equip command, not the exec'd command
    assert!(script.trim_end().ends_with("exec \"$@\""));
    // the token still rides positionally
    assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
}

#[test]
fn mise_upgrade_cmd_pins_the_app_global_pool_only_for_a_global_app() {
    // `sbx upgrade mise` rolls `[packages] mise:` tools, which for a global app live in the
    // app-global home pool. The cage's ambient primary for a global app is the per-project pool
    // (the split), which does not hold them, so the roll must be pinned to the app-global pool —
    // else `mise upgrade` finds nothing and silently rolls nothing (a shipped-command regression).
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

    // global app: pinned to the app-global pool via a bash MISE_DATA_DIR prefix
    let g = mise_upgrade_cmd(binds::Runtime::GlobalApp("cc"), &mise, &bash, &tokens);
    assert_eq!(g[0], OsString::from("/nix/store/bash/bin/bash"));
    let script = g[2].to_string_lossy();
    assert!(
        script.contains(&format!(
            "MISE_DATA_DIR='{data_dir}' exec /nix/store/mise/bin/mise upgrade"
        )),
        "the global-app roll must pin the app-global data dir: {script}"
    );
    assert_eq!(g[4], OsString::from("aqua:example/demo-tool")); // token positional

    // sbx run / a per-project app: single pool (the ambient primary), plain unwrapped command
    for rt in [
        binds::Runtime::ProjectDefault,
        binds::Runtime::ProjectApp("cc"),
    ] {
        let c = mise_upgrade_cmd(rt, &mise, &bash, &tokens);
        assert_eq!(c[0], OsString::from("/nix/store/mise/bin/mise"));
        assert_eq!(c[1], OsString::from("upgrade"));
        // `--bump` sits between the verb and the tokens on this lane too: the launch pins the
        // config at the installed version, and a pinned range is one a plain roll would call
        // already satisfied.
        assert_eq!(c[2], OsString::from("--bump"));
        assert_eq!(c[3], OsString::from("aqua:example/demo-tool"));
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

    let argv = wrap_flake_equip(&nix, &bash, &dir, &quads, cmd);

    assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
    assert_eq!(argv[1], OsString::from("-c"));
    let script = argv[2].to_string_lossy();
    // nix by absolute path; the quad count drives the loop, not the refs; the command is exec'd
    // after the quads are shifted.
    assert!(script.contains("n=2"));
    assert!(script.contains(
        "'/nix/store/nix/bin/nix' build \"$ref\" --no-write-lock-file --out-link \"$target\""
    ));
    assert!(script.contains("mkdir -p '/home/sandbox/.local/state/sbx/flake'"));
    // the fallback machinery: the per-revision failed-marker, the promotion of the good
    // out-link on success, and the loud notice when a pinned build fails.
    assert!(script.contains("touch \"$target.failed\""));
    assert!(script.contains("ln -sfn \"$sp\" \"$good\""));
    assert!(script.contains("falling back to the last good build"));
    assert!(script.contains("there is no prior build to fall back to"));
    // the gc root is keyed by the `$key` positional (the package name), targeting the used
    // build's store path resolved by `readlink -f` — host-resolvable, overwritten each launch
    assert!(script.contains("ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\""));
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
        &format!("#!/bin/sh\necho call >> '{}'\nexit 1\n", calls.display()),
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
    let argv = wrap_flake_equip(&fake_nix, &PathBuf::from("bash"), &flake, &quads, cmd);

    let run = || {
        std::process::Command::new(&argv[0])
            .args(&argv[1..])
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
    let argv = wrap_flake_equip(&fake_nix, &PathBuf::from("bash"), &flake, &quads, cmd);

    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .expect("run the flake-equip script");
    assert!(!out.status.success(), "no good build → must hard-fail");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("SHOULD-NOT-RUN"),
        "the command must not run when there is nothing to fall back to"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no prior build to fall back to"));
}
