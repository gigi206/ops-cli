//! Integration guard for the auto-gated terminal color: a captured (non-terminal) stream must be
//! byte-for-byte plain text. Every human-facing renderer decides its palette with
//! `Palette::for_stream(stdout().is_terminal())`, so a pipe is always plain — which is also why
//! every other integration test can assert exact substrings. This file is the end-to-end proof
//! that the commands actually take that path (not an accidental `colored()`), across the surface
//! the color pass touched. It exercises only the cheap, side-effect-free commands (no sandbox, no
//! nix, no network) so it runs everywhere and fast.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// A unique temp dir removed on drop, so a command's data-dir reads land in a throwaway location
/// instead of the real `$HOME`.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-color-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `ops <args>` with a throwaway home (data, state, config all redirected) and a clean cwd,
/// capturing stdout (a pipe — so color must be off). `NO_COLOR`/`TERM` are also neutralised so the
/// result does not depend on the host's environment leaking in.
fn run(args: &[&str], home: &Path, cwd: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ops"))
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home)
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env_remove("NO_COLOR")
        .env_remove("TERM")
        .output()
        .expect("spawn ops")
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
    let home = TmpDir::new();
    let cwd = TmpDir::new();
    // A real project config so `trust`/`untrust` take their confirmation path (recording then
    // revoking a marker), not an early read error — the colored confirmation lines must still be
    // plain when captured.
    std::fs::write(cwd.path().join(".ops.toml"), "env = { A = \"1\" }\n").unwrap();
    // Each is a renderer the color pass touched; all are cheap and host-agnostic. `doctor` is
    // included even though it probes the host — its output is captured, so it too must be plain.
    // `trust` precedes `untrust` so the revoke finds the marker it recorded (the `existed` path).
    let invocations: &[&[&str]] = &[
        &["config", "show"],
        // The resolution overview (no scope flag) colors its layer labels and present/absent
        // markers — captured here with a present project config and an absent global, so it must
        // be plain.
        &["config", "path"],
        // Bare `config` prints its page to stderr (a no-subcommand usage error) — captured, so it
        // too must be plain.
        &["config"],
        &["ls"],
        &["app", "list"],
        &["plugins", "list"],
        &["plugins", "store", "list"],
        &["test", "net", "https://example.com/x"],
        &["net", "rules"],
        &["net", "rules", "--source", "manual"],
        &["net", "pending"],
        // The bulk-drain presenter (`--all`) — a no-op with no live session, but it must still build
        // its "no pending requests" line from the captured-stream palette.
        &["net", "pending", "allow", "--all"],
        // The egress-stats table (empty here) — its header + "nothing recorded" line must be plain.
        &["net", "stats"],
        &["trust", "--show"],
        &["trust", ".ops.toml"],
        &["untrust", ".ops.toml"],
        &["doctor"],
    ];
    for args in invocations {
        let out = run(args, home.path(), cwd.path());
        assert!(
            !out.stdout.contains(&0x1b),
            "`ops {}` emitted an ANSI escape on a captured stream:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            !out.stderr.contains(&0x1b),
            "`ops {}` emitted an ANSI escape on captured stderr:\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn transactional_confirmations_are_plain_when_captured() {
    // The read commands above are stateless; the *transactional* confirmations (import, install,
    // …) only take their colored path after a side effect, so the flat loop cannot reach them.
    // Drive each cheap, host-agnostic one end to end (no nix, no network) so a miswired caller —
    // one that prints raw ANSI, or derives a stderr line's palette from the wrong stream — cannot
    // slip past with the presenter unit tests alone.
    let home = TmpDir::new();
    let cwd = TmpDir::new();
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

    let out_file = cwd.path().join("exported.toml");
    let exported = run(
        &[
            "app",
            "export",
            "probe",
            "--out",
            out_file.to_str().unwrap(),
        ],
        home.path(),
        cwd.path(),
    );
    assert!(
        exported.status.success(),
        "export must succeed:\n{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert_no_ansi(&exported, "app export --out");

    let removed = run(&["app", "rm", "probe"], home.path(), cwd.path());
    assert!(removed.status.success(), "app rm must succeed");
    assert_no_ansi(&removed, "app rm");

    // plugins: install a built-in by name (compiled in, no network), then remove it.
    let pinstall = run(&["plugins", "install", "vault"], home.path(), cwd.path());
    assert!(
        pinstall.status.success(),
        "plugin install must succeed:\n{}",
        String::from_utf8_lossy(&pinstall.stderr)
    );
    assert_no_ansi(&pinstall, "plugins install vault");

    let prm = run(&["plugins", "rm", "vault"], home.path(), cwd.path());
    assert!(prm.status.success(), "plugin rm must succeed");
    assert_no_ansi(&prm, "plugins rm vault");

    // plugins store update with nothing configured: the dimmed "no stores" message. Exit status
    // depends on whether git is on PATH (host-dependent), so only the no-ANSI invariant is pinned.
    let update = run(&["plugins", "store", "update"], home.path(), cwd.path());
    assert_no_ansi(&update, "plugins store update");

    // config writes: set (creates the local .ops.toml), then unset (removes the key). Both print a
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
    let stop_all = run(&["stop", "--all"], home.path(), cwd.path());
    assert!(
        stop_all.status.success(),
        "stop --all on an empty registry must exit 0:\n{}",
        String::from_utf8_lossy(&stop_all.stderr)
    );
    assert_no_ansi(&stop_all, "stop --all");
}

#[test]
fn app_targeted_net_test_is_plain_when_captured() {
    // `ops test net --app <name>` renders spans the flat read-only loop never reaches: the app
    // scope label, the built-in-built-in tag, and the credential-injection note. A miswired
    // renderer (raw `colored()` instead of the captured-stream palette) would leak ANSI here only.
    let home = TmpDir::new();
    let cwd = TmpDir::new();
    // A global app lives as a profile file (trusted by location; an inline `[app.<name>]` in the
    // global config is forbidden): a top-level `RawApp` with its own allowlist and injected credential.
    let apps_dir = home.path().join("ops").join("apps");
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

    // `ops net rules --app demo` colors the app-scoped header and the per-rule source tags — a
    // captured run must still be plain.
    let rules = run(&["net", "rules", "--app", "demo"], home.path(), cwd.path());
    assert!(rules.status.success());
    assert_no_ansi(&rules, "net rules --app");
}

#[test]
fn a_captured_warning_is_plain_with_exactly_one_prefix() {
    // The `ops: warning:` / `ops: note:` family routes through the diag chokepoint. Drive a real
    // warning (an orphan mise file with no `.ops.toml`, the anchoring warning) and assert the
    // captured stream is plain AND carries exactly one `warning:` prefix. The count is the guard a
    // plain `.contains("warning:")` cannot give: the mechanical conversion stripped the literal
    // `ops: warning:` from ~30 sites, and a missed strip would double the prefix while every
    // substring assertion still passed.
    let home = TmpDir::new();
    let cwd = TmpDir::new();
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
