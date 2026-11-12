//! Integration guard for the auto-gated terminal color: a captured (non-terminal) stream must be
//! byte-for-byte plain text. Every human-facing renderer decides its palette with
//! `Palette::for_stream(<stream>.is_terminal())`, asked of the stream it writes to, so a pipe is
//! always plain — which is also why every other integration test can assert exact substrings. This file is the end-to-end proof
//! that the commands actually take that path (not an accidental `colored()`), across the surface
//! the color pass touched. It exercises only the cheap, side-effect-free commands (no sandbox, no
//! nix, no network) so it runs everywhere and fast.

#[macro_use]
mod common;
use common::fixture::TmpDir;
use common::pty::Pty;

use std::path::Path;
use std::process::Command;

/// `sbx <args>` with a throwaway home (data, state, config all redirected) and a clean cwd.
///
/// `NO_COLOR` and `TERM`, which the palette reads besides the stream itself, are removed so the
/// result does not depend on the host's environment leaking in. So is `SBX_DATA_DIR`, which
/// outranks `XDG_DATA_HOME`: inherited, it would hand these verbs the host's own data directory,
/// its plugins and its sessions, and `session stop --all` would stop every session running there.
fn command(args: &[&str], home: &Path, cwd: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("SBX_DATA_DIR")
        .env_remove("NO_COLOR")
        .env_remove("TERM");
    cmd
}

/// Run [`command`] to completion with both streams captured: pipes, so color must be off on each.
fn run(args: &[&str], home: &Path, cwd: &Path) -> std::process::Output {
    command(args, home, cwd).output().expect("spawn sbx")
}

/// Assert a captured invocation carries no ANSI escape on either stream.
fn assert_no_ansi(out: &std::process::Output, label: &str) {
    assert!(
        !out.stdout.contains(&0x1b),
        "`{label}` emitted an ANSI escape on a captured stream:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !out.stderr.contains(&0x1b),
        "`{label}` emitted an ANSI escape on captured stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn captured_output_carries_no_ansi_escapes() {
    let home = TmpDir::new("color");
    let cwd = TmpDir::new("color");
    // A real project config so `trust`/`untrust` take their confirmation path (recording then
    // revoking a marker), not an early read error — the colored confirmation lines must still be
    // plain when captured.
    std::fs::write(cwd.path().join(".sbx.toml"), "env = { A = \"1\" }\n").unwrap();
    // Each is a renderer the color pass touched; all are cheap and host-agnostic. `doctor` is
    // included even though it probes the host — its output is captured, so it too must be plain.
    // `trust` precedes `untrust` so the revoke finds the marker it recorded (the `existed` path).
    //
    // Each comes with the exit it gives here, and must have printed something: a verb that stopped
    // before its renderer, or ended with nothing written, would otherwise pass as plain. `doctor`
    // answers for the host, so its exit is not pinned. The trust store records a project by a path
    // that is text: under a fixture root outside UTF-8, `trust` refuses the project (exit 1), and
    // its refusal is the line held to plain there.
    let trusted = if cwd.path().to_str().is_some() { 0 } else { 1 };
    let invocations: &[(&[&str], Option<i32>)] = &[
        (&["config", "show"], Some(0)),
        // The resolution overview (no scope flag) colors its layer labels and present/absent
        // markers — captured here with a present project config and an absent global, so it must
        // be plain.
        (&["config", "path"], Some(0)),
        // Bare `config` prints its page to stderr (a no-subcommand usage error) — captured, so it
        // too must be plain.
        (&["config"], Some(2)),
        (&["session", "ls"], Some(0)),
        (&["app", "list"], Some(0)),
        (&["plugins", "list"], Some(0)),
        (&["plugins", "store", "list"], Some(0)),
        (&["test", "net", "https://example.com/x"], Some(0)),
        (&["net", "rules"], Some(0)),
        (&["net", "rules", "--source", "session"], Some(0)),
        (&["net", "pending"], Some(0)),
        // The bulk-drain presenter (`--all`) — a no-op with no live session, but it must still build
        // its "no pending requests" line from the captured-stream palette.
        (&["net", "pending", "allow", "--all"], Some(0)),
        // The egress-stats table (empty here) — its header + "nothing recorded" line must be plain.
        (&["net", "stats"], Some(0)),
        (&["trust", "--show"], Some(0)),
        (&["trust", "--yes", ".sbx.toml"], Some(trusted)),
        (&["untrust", ".sbx.toml"], Some(0)),
        (&["doctor"], None),
    ];
    for (args, code) in invocations {
        let out = run(args, home.path(), cwd.path());
        let label = format!("sbx {}", args.join(" "));
        if let Some(code) = code {
            assert_eq!(
                out.status.code(),
                Some(*code),
                "`{label}`:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        assert!(
            !out.stdout.is_empty() || !out.stderr.is_empty(),
            "`{label}` printed nothing"
        );
        assert_no_ansi(&out, &label);
    }
}

#[test]
fn transactional_confirmations_are_plain_when_captured() {
    // The read commands above are stateless; the *transactional* confirmations (import, install,
    // …) only take their colored path after a side effect, so the flat loop cannot reach them.
    // Drive each cheap, host-agnostic one end to end (no nix, no network) so a miswired caller —
    // one that prints raw ANSI — cannot slip past with the presenter unit tests alone. Both streams
    // are pipes here, so a line that takes its palette from the other stream is plain as well:
    // `a_line_takes_its_palette_from_the_stream_it_is_written_to` is where that one shows.
    let home = TmpDir::new("color");
    let cwd = TmpDir::new("color");
    // A minimal importable profile: a top-level app with a command.
    std::fs::write(cwd.path().join("probe.toml"), "cmd = \"true\"\n").unwrap();

    // app: import → export (to a file, so the confirmation is the stderr line) → rm.
    let imported = run(&["app", "import", "./probe.toml"], home.path(), cwd.path());
    assert!(
        imported.status.success(),
        "import must succeed:\n{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    assert_no_ansi(&imported, "app import");

    // The fixture paths go to the verb as the OS strings they are: the fixture root comes from the
    // environment and may hold bytes outside UTF-8, which a `&str` could not carry.
    let out_file = cwd.path().join("exported.toml");
    let exported = command(
        &["app", "export", "probe", "--out"],
        home.path(),
        cwd.path(),
    )
    .arg(&out_file)
    .output()
    .expect("spawn sbx");
    assert!(
        exported.status.success(),
        "export must succeed:\n{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_no_ansi(&exported, "app export --out");

    let removed = run(&["app", "rm", "probe"], home.path(), cwd.path());
    assert!(removed.status.success(), "app rm must succeed");
    assert_no_ansi(&removed, "app rm");

    // plugins: install a plugin directory (no network), then remove it. The directory is built
    // here rather than taken from the repository, so this stays a color assertion and cannot be
    // broken again by a plugin moving out of the tree.
    let plugin_dir = cwd.path().join("demo-resolver");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    std::fs::write(
        plugin_dir.join("plugin.toml"),
        "name = \"demo-resolver\"\ntype = \"resolver\"\nscheme = \"demo-resolver\"\n\
         exec = \"resolve\"\nversion = \"0.1.0\"\ndescription = \"a test resolver\"\n",
    )
    .unwrap();
    let exec = plugin_dir.join("resolve");
    std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let pinstall = command(&["plugins", "install"], home.path(), cwd.path())
        .arg(&plugin_dir)
        .output()
        .expect("spawn sbx");
    assert!(
        pinstall.status.success(),
        "plugin install must succeed:\n{}",
        String::from_utf8_lossy(&pinstall.stderr)
    );
    assert_no_ansi(&pinstall, "plugins install demo-resolver");

    let prm = run(&["plugins", "rm", "demo-resolver"], home.path(), cwd.path());
    assert!(prm.status.success(), "plugin rm must succeed");
    assert_no_ansi(&prm, "plugins rm demo-resolver");

    // plugins store update with nothing configured: the dimmed "no stores" message. Exit status
    // depends on whether git is on PATH (host-dependent), so the invariant is pinned on whichever
    // of its two answers came back.
    let update = run(&["plugins", "store", "update"], home.path(), cwd.path());
    let answered = String::from_utf8_lossy(&update.stdout).contains("no remote stores")
        || String::from_utf8_lossy(&update.stderr).contains("git is not on PATH");
    assert!(
        answered,
        "plugins store update gave neither answer:\n{}",
        String::from_utf8_lossy(&update.stderr)
    );
    assert_no_ansi(&update, "plugins store update");

    // config writes: set (creates the local .sbx.toml), then unset (removes the key). Both print a
    // confirmation on stdout; no nix, no network.
    let set = run(
        &["config", "set", "env.FOO", "bar"],
        home.path(),
        cwd.path(),
    );
    assert!(
        set.status.success(),
        "config set must succeed:\n{}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert_no_ansi(&set, "config set");

    let unset = run(&["config", "unset", "env.FOO"], home.path(), cwd.path());
    assert!(unset.status.success(), "config unset must succeed");
    assert_no_ansi(&unset, "config unset");

    // session verbs: `stop --all` on an empty registry hits the dimmed "no active sessions" stdout
    // line with no live session, no nix, no network — exactly as cheap as the cases above, and the
    // one session-verb confirmation reachable end to end (the stop-outcome and attach lines need a
    // live cage, so they stay presenter-unit-tested). This proves `stop` built its palette from the
    // captured stream rather than hardcoding `colored()`.
    let stop_all = run(&["session", "stop", "--all"], home.path(), cwd.path());
    assert!(
        stop_all.status.success(),
        "stop --all on an empty registry must exit 0:\n{}",
        String::from_utf8_lossy(&stop_all.stderr)
    );
    assert_no_ansi(&stop_all, "stop --all");
}

/// A line takes its palette from the stream it is written to. With one stream on a terminal and the
/// other captured, the captured one stays plain: the confirmation `app export --out` writes on
/// stderr while stdout is a terminal, and the one `config set` writes on stdout while stderr is.
///
/// With both streams captured, as in the tests above, a line painted for the other stream's
/// terminal is plain too, and nothing there can tell the two apart.
#[test]
fn a_line_takes_its_palette_from_the_stream_it_is_written_to() {
    let home = TmpDir::new("color");
    let cwd = TmpDir::new("color");
    std::fs::write(cwd.path().join("probe.toml"), "cmd = \"true\"\n").unwrap();
    let imported = run(&["app", "import", "./probe.toml"], home.path(), cwd.path());
    assert!(
        imported.status.success(),
        "import must succeed:\n{}",
        String::from_utf8_lossy(&imported.stderr)
    );

    let terminal = Pty::open(None);
    let exported = command(
        &["app", "export", "probe", "--out"],
        home.path(),
        cwd.path(),
    )
    .arg(cwd.path().join("exported.toml"))
    .stdout(terminal.stdio())
    .output()
    .expect("spawn sbx");
    let said = String::from_utf8_lossy(&exported.stderr);
    assert!(exported.status.success(), "export must succeed:\n{said}");
    assert!(
        said.contains("exported"),
        "the export confirms on stderr:\n{said}"
    );
    assert!(
        !exported.stderr.contains(&0x1b),
        "the stderr line was painted for the terminal on stdout:\n{said}"
    );

    let terminal = Pty::open(None);
    let set = command(
        &["config", "set", "env.FOO", "bar"],
        home.path(),
        cwd.path(),
    )
    .stderr(terminal.stdio())
    .output()
    .expect("spawn sbx");
    let said = String::from_utf8_lossy(&set.stdout);
    assert!(
        set.status.success(),
        "config set must succeed:\n{}",
        String::from_utf8_lossy(&set.stderr)
    );
    assert!(
        said.contains("env.FOO"),
        "config set confirms on stdout:\n{said}"
    );
    assert!(
        !set.stdout.contains(&0x1b),
        "the stdout line was painted for the terminal on stderr:\n{said}"
    );
}

#[test]
fn app_targeted_net_test_is_plain_when_captured() {
    // `sbx test net --app <name>` renders spans the flat read-only loop never reaches: the app
    // scope label, the built-in-built-in tag, and the credential-injection note. A miswired
    // renderer (raw `colored()` instead of the captured-stream palette) would leak ANSI here only.
    let home = TmpDir::new("color");
    let cwd = TmpDir::new("color");
    // A global app lives as a profile file (trusted by location; an inline `[app.<name>]` in the
    // global config is forbidden): a top-level `RawApp` with its own allowlist and injected credential.
    let apps_dir = home.path().join("sbx").join("apps");
    std::fs::create_dir_all(&apps_dir).unwrap();
    std::fs::write(
        apps_dir.join("demo.toml"),
        "cmd = \"true\"\n\
         \n\
         [network]\n\
         mode = \"deny\"\n\
         allow = [\"api.demo.test\"]\n\
         \n\
         [secret.\"api.demo.test\"]\n\
         from = \"env://DEMO_API_KEY\"\n\
         header = \"x-api-key\"\n\
         type = \"raw\"\n",
    )
    .unwrap();

    // The injection-note + app-scope path (an allowed app host).
    let injected = run(
        &["test", "net", "--app", "demo", "https://api.demo.test/v1"],
        home.path(),
        cwd.path(),
    );
    assert!(
        injected.status.success(),
        "test net --app must succeed:\n{}",
        String::from_utf8_lossy(&injected.stderr)
    );
    assert_no_ansi(&injected, "test net --app (injection note)");

    // The built-in-built-in tag path (a cache host allowed only by the built-in union).
    let builtin = run(
        &["test", "net", "--app", "demo", "https://cache.nixos.org/x"],
        home.path(),
        cwd.path(),
    );
    assert!(builtin.status.success());
    assert_no_ansi(&builtin, "test net --app (built-in tag)");

    // `sbx net rules --app demo` colors the app-scoped header and the per-rule source tags — a
    // captured run must still be plain.
    let rules = run(&["net", "rules", "--app", "demo"], home.path(), cwd.path());
    assert!(rules.status.success());
    assert_no_ansi(&rules, "net rules --app");
}

#[test]
fn a_captured_warning_is_plain_with_exactly_one_prefix() {
    // The `sbx: warning:` / `sbx: note:` family routes through the diag chokepoint. Drive a real
    // warning (an orphan mise file with no `.sbx.toml`, the anchoring warning) and assert the
    // captured stream is plain AND carries exactly one `warning:` prefix. The count is the guard a
    // plain `.contains("warning:")` cannot give: the mechanical conversion stripped the literal
    // `sbx: warning:` from ~30 sites, and a missed strip would double the prefix while every
    // substring assertion still passed.
    let home = TmpDir::new("color");
    let cwd = TmpDir::new("color");
    std::fs::write(cwd.path().join("mise.toml"), "[tools]\nnode = \"20\"\n").unwrap();

    let out = run(&["config", "show"], home.path(), cwd.path());
    assert!(
        out.status.success(),
        "config show on an orphan mise must not hard-fail:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_no_ansi(&out, "config show (orphan-mise warning)");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("warning:") && stderr.contains("mise file"),
        "the orphan-mise anchoring warning must fire on stderr:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("warning:").count(),
        1,
        "exactly one `warning:` prefix — a double prefix means a site kept its literal:\n{stderr}"
    );
}
