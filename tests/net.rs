//! Integration tests for `ops net` — the egress-policy listing/management surface — exercising
//! the built binary end to end against redirected config/state/data dirs and a temp project as
//! the working directory. Read-only and host-side: no launch, no nix, no network.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("ops-net-it-{}-{n}", std::process::id()));
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

/// One project under test: the working dir plus the redirected config-home (global config),
/// state-home (trust store) and data-home (per-project runtime).
struct Fixture {
    proj: TmpDir,
    config_home: TmpDir,
    state_home: TmpDir,
    data_home: TmpDir,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            proj: TmpDir::new(),
            config_home: TmpDir::new(),
            state_home: TmpDir::new(),
            data_home: TmpDir::new(),
        }
    }

    fn write_global(&self, body: &str) {
        let dir = self.config_home.path().join("ops");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ops.toml"), body).unwrap();
    }

    fn write_project(&self, body: &str) {
        std::fs::write(self.proj.path().join(".ops.toml"), body).unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ops"))
            .args(args)
            .current_dir(self.proj.path())
            .env("XDG_CONFIG_HOME", self.config_home.path())
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_DATA_HOME", self.data_home.path())
            .output()
            .expect("spawn ops")
    }
}

#[test]
fn net_rules_lists_config_and_builtin_rules_tagged_by_source() {
    let fx = Fixture::new();
    fx.write_project(
        "[network]\nmode = \"deny\"\nallow = [\"github.com\", \"*.nixos.org\"]\ndeny = [\"evil.nixos.org\"]\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["net", "rules"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // the mode header, the config allow/deny rules each tagged, and the built-in nix-cache set
    assert!(stdout.contains("network: deny"), "{stdout}");
    assert!(stdout.contains("allow github.com  (config)"), "{stdout}");
    assert!(stdout.contains("allow *.nixos.org  (config)"), "{stdout}");
    assert!(
        stdout.contains("deny  evil.nixos.org  (config)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("allow cache.nixos.org  (builtin)"),
        "the built-in nix-cache set must be listed and tagged:\n{stdout}"
    );

    // `--source builtin` shows only the built-in set; the config rules are gone.
    let out = fx.run(&["net", "rules", "--source", "builtin"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("(builtin)") && !stdout.contains("github.com  (config)"),
        "--source builtin must filter to the built-in set:\n{stdout}"
    );

    // `--source config` shows only the config rules; the built-in set is gone.
    let out = fx.run(&["net", "rules", "-s", "config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("github.com  (config)") && !stdout.contains("(builtin)"),
        "--source config must filter to the config rules:\n{stdout}"
    );

    // `--filter` substring-matches the rule text (case-insensitive).
    let out = fx.run(&["net", "rules", "--filter", "EVIL"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("evil.nixos.org") && !stdout.contains("github.com"),
        "--filter must substring-match case-insensitively:\n{stdout}"
    );

    // a filter that matches nothing reports it (not silent empty output).
    let out = fx.run(&["net", "rules", "--filter", "zzz-no-match"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("no rules match the filter"));
}

#[test]
fn net_rules_json_emits_the_mode_and_tagged_rules() {
    let fx = Fixture::new();
    fx.write_project("[network]\nmode = \"deny\"\nallow = [\"github.com\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["net", "rules", "--source", "config", "--json"]);
    assert!(out.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("net rules --json emits valid JSON");
    assert_eq!(json["mode"], "deny");
    assert_eq!(json["rules"][0]["rule"], "github.com");
    assert_eq!(json["rules"][0]["kind"], "Allow");
    assert_eq!(json["rules"][0]["source"], "Config");
}

#[test]
fn net_rules_under_a_non_filtering_posture_has_no_rules() {
    let fx = Fixture::new();
    fx.write_project("network = \"shared\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["net", "rules"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // No rules at all — not even the built-in set, which the proxy unions only under a filtering
    // posture (it does not run under `shared`).
    assert!(
        stdout.contains("network: shared")
            && stdout.contains("no egress rules")
            && !stdout.contains("(builtin)"),
        "shared must list no rules, including no built-in set:\n{stdout}"
    );

    fx.write_project("network = \"none\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["net", "rules"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("network: none") && stdout.contains("no egress rules"),
        "none must list no rules:\n{stdout}"
    );
}

#[test]
fn net_rules_reflects_the_trust_gate() {
    // The gate teeth: a GLOBAL filtering posture (trusted by location) stands, while an UNTRUSTED
    // project's attempt to add its own rule is dropped — so the listing shows the global rule and
    // the built-in set, but never the untrusted project's rule.
    let fx = Fixture::new();
    fx.write_global("[network]\nmode = \"deny\"\nallow = [\"global.example\"]\n");
    fx.write_project("[network]\nmode = \"deny\"\nallow = [\"project.example\"]\n");
    // deliberately NOT trusting the project.

    let out = fx.run(&["net", "rules"]);
    assert!(
        out.status.success(),
        "an untrusted project must not hard-fail"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("allow global.example  (config)"),
        "the global (trusted-by-location) rule must stand:\n{stdout}"
    );
    assert!(
        !stdout.contains("project.example"),
        "an untrusted project's rule must never appear:\n{stdout}"
    );
    assert!(
        stderr.contains("network") && stderr.contains("untrusted"),
        "the dropped project posture must be explained:\n{stderr}"
    );
}

#[test]
fn net_rejects_an_unknown_subcommand_and_source() {
    let fx = Fixture::new();
    // an unknown `net` subcommand
    let out = fx.run(&["net", "bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("rules"));

    // an unknown rule source (`config`/`builtin`/`manual` are the known ones)
    fx.write_project("network = \"deny\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["net", "rules", "--source", "bogus"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("config, builtin, manual"),
        "an unknown source must name the known ones"
    );
}

#[test]
fn net_rules_source_manual_is_accepted_and_empty_without_live_sessions() {
    let fx = Fixture::new();
    // `--source manual` is a live query, valid even with no config and no running sessions: it
    // succeeds with an empty listing under the manual header (not the unknown-source error).
    let out = fx.run(&["net", "rules", "--source", "manual"]);
    assert!(out.status.success(), "manual is a valid source");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("manual egress rules"), "{stdout}");
    assert!(stdout.contains("no rules declared"), "{stdout}");

    // `--json` is a clean empty list tagged `manual`.
    let json = fx.run(&["net", "rules", "--source", "manual", "--json"]);
    assert!(json.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["mode"], "manual");
    assert_eq!(v["rules"].as_array().map(|a| a.len()), Some(0));
}

#[test]
fn net_pending_session_flag_without_a_live_session_is_refused() {
    let fx = Fixture::new();
    // `--session` (like a bare answer) needs a live session; absent one it is a pointed refusal, not
    // a crash. Combined `--session --save` parses too (both extracted before the scope parser).
    let out = fx.run(&[
        "net",
        "pending",
        "allow",
        "4294967295.1",
        "--session",
        "--save",
        "-l",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no live session"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn net_allow_bootstraps_a_local_allowlist_retrusts_and_rules_shows_it() {
    let fx = Fixture::new();
    // A fresh project (no .ops.toml): `allow` bootstraps a deny-by-default allowlist and re-trusts.
    let out = fx.run(&["net", "allow", "github.com"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mode `deny`")
            && stdout.contains("github.com")
            && stdout.contains("re-trusted"),
        "bootstrap must report the created posture and the re-trust:\n{stdout}"
    );
    // The round-trip: the project is now trusted, so the rule is honored and `ops net rules` lists
    // it as a config rule (a re-trust failure would have left it untrusted and dropped).
    let rules = fx.run(&["net", "rules"]);
    assert!(
        String::from_utf8_lossy(&rules.stdout).contains("allow github.com  (config)"),
        "the persisted, re-trusted rule must appear in `ops net rules`:\n{}",
        String::from_utf8_lossy(&rules.stdout)
    );

    // A second add of the same rule is an idempotent no-op.
    let again = fx.run(&["net", "allow", "github.com"]);
    assert!(String::from_utf8_lossy(&again.stdout).contains("already present"));
}

#[test]
fn net_deny_on_a_fresh_project_is_refused_with_guidance() {
    let fx = Fixture::new();
    let out = fx.run(&["net", "deny", "evil.com"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("posture") && stderr.contains("ops config set network"),
        "a deny on a fresh project must refuse and point at setting a posture:\n{stderr}"
    );
}

#[test]
fn net_allow_refuses_an_untrusted_existing_project() {
    let fx = Fixture::new();
    // A pre-existing, never-trusted project config: appending must not silently bless it.
    fx.write_project("[network]\nmode = \"deny\"\nallow = [\"a.com\"]\n");
    let out = fx.run(&["net", "allow", "b.com"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not trusted")
            && String::from_utf8_lossy(&out.stderr).contains("ops trust"),
        "an untrusted existing config must be refused, pointing at `ops trust`:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The file is untouched (b.com was never written).
    let body = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        !body.contains("b.com"),
        "a refused write must not touch the file:\n{body}"
    );
}

#[test]
fn net_allow_global_writes_the_global_config_without_a_trust_gate() {
    let fx = Fixture::new();
    // `--global` is trusted by location: no re-trust line, and it works from an untrusted project.
    let out = fx.run(&["net", "allow", "cdn.example.com", "--global"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("global config") && !stdout.contains("re-trusted"),
        "{stdout}"
    );
    let global = fx.config_home.path().join("ops").join("ops.toml");
    let body = std::fs::read_to_string(&global).unwrap();
    assert!(
        body.contains("[network]") && body.contains("cdn.example.com"),
        "{body}"
    );
}

#[test]
fn net_allow_app_writes_the_apps_network_table_and_retrusts() {
    let fx = Fixture::new();
    let out = fx.run(&["net", "allow", "api.anthropic.com", "--app", "claude"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("re-trusted"),
        "a local --app write must re-trust the project config"
    );
    // A second --app add must SUCCEED (it hits the Trusted branch) — proving the first add's
    // re-trust took. Had it not, the project would be Untrusted and this would re-refuse. This is
    // the one path that is three gates at once: app + local + trust.
    let second = fx.run(&["net", "deny", "telemetry.example.com", "--app", "claude"]);
    assert!(
        second.status.success(),
        "a second --app add must not re-refuse (the first re-trusted): {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let body = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        body.contains("[app.claude.network]")
            && body.contains("api.anthropic.com")
            && body.contains("telemetry.example.com"),
        "both rules must land in the app's own network table:\n{body}"
    );
}

#[test]
fn net_allow_rejects_an_explicit_file_scope() {
    let fx = Fixture::new();
    // `-c <file>` is neither the trusted-by-location global nor the trust-gated project path, so a
    // write to it would be silently dropped at launch — refuse it outright.
    let out = fx.run(&["net", "allow", "github.com", "-c", ".ops.toml"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--local"),
        "the refusal must point at the supported scopes:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn net_allow_rejects_an_invalid_rule_before_writing() {
    let fx = Fixture::new();
    // A `*` catch-all is refused by classification (the fail-closed validation), no file written.
    let out = fx.run(&["net", "allow", "*"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("invalid rule"));
    assert!(
        !fx.proj.path().join(".ops.toml").exists(),
        "an invalid rule must not create the config"
    );
}

// ── increment 4: the `ask` posture + the live pending control plane ────────────────────────────

#[test]
fn ask_mode_renders_across_config_rules_and_the_tester() {
    let fx = Fixture::new();
    // A trusted `ask` posture with a timeout and one auto-allow / one auto-deny carve-out.
    fx.write_project(
        "[network]\nmode = \"ask\"\nask_timeout = \"90s\"\nallow = [\"github.com\"]\ndeny = [\"evil.com\"]\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // `ops config show` names the ask posture and surfaces the configured timeout.
    let show = fx.run(&["config", "show"]);
    let s = String::from_utf8_lossy(&show.stdout);
    assert!(s.contains("network: ask"), "config show:\n{s}");
    assert!(s.contains("ask timeout: 90s"), "config show:\n{s}");

    // `ops net rules` frames the ask posture and still tags the carve-out rules.
    let rules = fx.run(&["net", "rules"]);
    let r = String::from_utf8_lossy(&rules.stdout);
    assert!(r.contains("network: ask"), "net rules:\n{r}");
    assert!(r.contains("allow github.com  (config)"), "net rules:\n{r}");
    assert!(r.contains("deny  evil.com  (config)"), "net rules:\n{r}");

    // `ops test net` reports an unmatched host as "would ask" (no static verdict).
    let test = fx.run(&["test", "net", "https://unlisted.example.com/x"]);
    let t = String::from_utf8_lossy(&test.stdout);
    assert!(t.contains("WOULD ASK"), "test net:\n{t}");
    // A carve-out host still resolves statically: the allow rule auto-passes.
    let allowed = fx.run(&["test", "net", "https://github.com/x"]);
    assert!(
        String::from_utf8_lossy(&allowed.stdout).contains("ALLOWED"),
        "an ask-mode allow rule must still pass: {:?}",
        String::from_utf8_lossy(&allowed.stdout)
    );
}

#[test]
fn net_pending_lists_nothing_when_no_session_is_parked() {
    let fx = Fixture::new();
    let out = fx.run(&["net", "pending"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("none"),
        "an empty queue says so: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // `--json` is a clean empty list — the contract a front-end relies on.
    let json = fx.run(&["net", "pending", "--json"]);
    assert!(json.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("net pending --json is valid JSON");
    assert_eq!(v["pending"].as_array().map(|a| a.len()), Some(0));
}

#[test]
fn net_pending_answer_rejects_a_malformed_id() {
    let fx = Fixture::new();
    let out = fx.run(&["net", "pending", "allow", "not-an-id"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("invalid pending id"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn net_pending_answer_an_absent_session_is_refused() {
    let fx = Fixture::new();
    // A well-formed id whose session does not exist (no control socket) → a pointed refusal, exit 2.
    let out = fx.run(&["net", "pending", "allow", "4294967295.1"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no live session"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn net_pending_answer_rejects_a_scope_without_save() {
    let fx = Fixture::new();
    // A scope flag (here --global) is meaningless without --save — flagged, not silently ignored.
    let out = fx.run(&["net", "pending", "allow", "123.1", "--global"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("only applies with --save"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}
