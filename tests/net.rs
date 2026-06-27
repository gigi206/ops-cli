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

#[test]
fn net_pending_all_drains_nothing_when_no_session_is_parked() {
    let fx = Fixture::new();
    // With no live session, `--all` is a clean no-op (exit 0), not an error — it answered nothing.
    let out = fx.run(&["net", "pending", "allow", "--all"]);
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no pending requests"),
        "{:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // `deny --all` is symmetric.
    let out = fx.run(&["net", "pending", "deny", "--all"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("no pending requests"));
}

#[test]
fn net_pending_all_rejects_save_and_a_stray_id_or_scope() {
    let fx = Fixture::new();

    // `--save` is deliberately not supported with `--all` (a per-host, per-project fan-out) — it is
    // refused explicitly, pointing at saving by id, rather than silently ignored.
    let out = fx.run(&["net", "pending", "allow", "--all", "--save"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not combine with `--all`"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A stray positional id alongside `--all` is a usage error (the two address different things).
    let out = fx.run(&["net", "pending", "deny", "--all", "123.1"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("takes no id or scope"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A scope flag alongside `--all` (no save) is likewise refused.
    let out = fx.run(&["net", "pending", "allow", "--all", "--global"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("takes no id or scope"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn net_pending_all_drains_a_live_session_through_the_socket() {
    // The headline non-empty drain, proven end to end through the real binary — no cage needed, since
    // the control plane is just a bound Unix socket + a server thread (the same seam the in-process
    // round-trip test stands up). This closes the one path the unit tests cover only with synthetic
    // data: the CLI's glob → drain → per-session render orchestration.
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    // The control socket lives at <data>/egress/control-<pid>.sock, and <data> is $XDG_DATA_HOME/ops
    // (the dir `fx.run` redirects). Binding it at the right place is itself the proof the path wiring
    // is correct — a wrong path yields an empty drain ("no pending requests") and the assert fails.
    let egress = fx.data_home.path().join("ops").join("egress");
    std::fs::create_dir_all(&egress).unwrap();
    let pid = 33333u32; // not in the session registry → the `(unregistered)` header path
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();

    // A one-shot fake session: accept one connection, assert it is the bulk drain, answer two hosts.
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        assert!(
            cmd.starts_with("ALLOW *"),
            "the CLI must send a bulk drain, got: {cmd:?}"
        );
        (&stream)
            .write_all(b"answered host=a.test\nanswered host=b.test\nok\n")
            .unwrap();
    });

    let out = fx.run(&["net", "pending", "allow", "--all"]);
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The total over every session, both answered hosts, and the per-session breakdown (so the
    // cross-agent reach is visible, not a silent count).
    assert!(
        stdout.contains("allowed 2 parked request(s)"),
        "the drain total must be reported:\n{stdout}"
    );
    assert!(
        stdout.contains("a.test") && stdout.contains("b.test"),
        "every answered host must be listed:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("session {pid}")),
        "the answering session must be named:\n{stdout}"
    );
}

// ── `ops test net` enrichments: app targeting, launch fidelity, scheme-optional ─────────────────

#[test]
fn test_net_targets_an_app_effective_policy() {
    let fx = Fixture::new();
    // A global config (trusted by location, so no `ops trust` needed): a baseline allowlist that
    // does NOT list the app's host, plus an app whose own overlay allows it and injects a key.
    fx.write_global(
        "[network]\n\
         mode = \"deny\"\n\
         allow = [\"github.com\"]\n\
         \n\
         [app.demo]\n\
         cmd = \"true\"\n\
         \n\
         [app.demo.network]\n\
         mode = \"deny\"\n\
         allow = [\"api.demo.test\"]\n\
         \n\
         [app.demo.secret.\"api.demo.test\"]\n\
         from = \"env://DEMO_API_KEY\"\n\
         header = \"x-api-key\"\n\
         type = \"raw\"\n",
    );

    // Baseline: the app's host is not in the baseline allowlist → DENIED.
    let base = fx.run(&["test", "net", "https://api.demo.test/v1"]);
    assert!(base.status.success());
    let b = String::from_utf8_lossy(&base.stdout);
    assert!(
        b.contains("DENIED"),
        "baseline must deny the app host:\n{b}"
    );

    // Same host under the app: ALLOWED by the app's own rule, with the injection noted by header
    // and source (never the value).
    let app = fx.run(&["test", "net", "--app", "demo", "https://api.demo.test/v1"]);
    assert!(app.status.success());
    let a = String::from_utf8_lossy(&app.stdout);
    assert!(
        a.contains("network (app demo):"),
        "the header must name the app scope:\n{a}"
    );
    assert!(
        a.contains("ALLOWED") && a.contains("api.demo.test"),
        "the app's own allow rule must pass:\n{a}"
    );
    assert!(
        a.contains("a credential would be injected")
            && a.contains("x-api-key")
            && a.contains("env DEMO_API_KEY"),
        "the injection note must name the header and source, never the value:\n{a}"
    );
    assert!(
        !a.contains("DEMO_API_KEY=") && !a.contains("placeholder"),
        "no plaintext or value may appear:\n{a}"
    );

    // A bare host (no scheme) is completed to https and decides the same way.
    let bare = fx.run(&["test", "net", "--app", "demo", "api.demo.test"]);
    assert!(bare.status.success());
    let r = String::from_utf8_lossy(&bare.stdout);
    assert!(
        r.contains("ALLOWED") && r.contains("https://api.demo.test"),
        "a bare host must be completed to https and allowed:\n{r}"
    );

    // An unknown app is a pointed, exit-2 error that lists what exists.
    let bad = fx.run(&["test", "net", "--app", "nope", "https://api.demo.test/v1"]);
    assert_eq!(bad.status.code(), Some(2));
    let e = String::from_utf8_lossy(&bad.stderr);
    assert!(
        e.contains("no app named") && e.contains("demo"),
        "the error must name the missing app and list the declared one:\n{e}"
    );
}

#[test]
fn net_rules_targets_an_app_effective_policy() {
    let fx = Fixture::new();
    // A global config (trusted by location): a baseline allowlist listing one host, plus an app
    // whose OWN network overlay lists a different host and a path-scoped deny. `--app` must list the
    // app's effective rules (its overlay replaces the baseline posture), not the baseline's.
    fx.write_global(
        "[network]\n\
         mode = \"deny\"\n\
         allow = [\"github.com\"]\n\
         \n\
         [app.demo]\n\
         cmd = \"true\"\n\
         \n\
         [app.demo.network]\n\
         mode = \"deny\"\n\
         allow = [\"api.demo.test\"]\n\
         deny = [\"api.demo.test/secret\"]\n",
    );

    // Bare `net rules`: the baseline only — github.com, and NOT the app's host. This is the teeth:
    // it proves the `--app` listing below took the overlay, not coincidentally echoed the baseline.
    let base = fx.run(&["net", "rules"]);
    assert!(base.status.success());
    let b = String::from_utf8_lossy(&base.stdout);
    assert!(
        b.contains("allow github.com  (config)") && !b.contains("api.demo.test"),
        "the baseline listing must be the baseline, not the app:\n{b}"
    );

    // `--app demo`: the app's effective policy. The header names the scope; its own allow/deny
    // appear; the baseline's github.com is GONE (the app's network replaces it); the built-in
    // nix-cache set is still unioned (app-invariant).
    let app = fx.run(&["net", "rules", "--app", "demo"]);
    assert!(app.status.success());
    let a = String::from_utf8_lossy(&app.stdout);
    assert!(
        a.contains("network (app demo): deny"),
        "the header must name the app scope:\n{a}"
    );
    assert!(a.contains("allow api.demo.test  (config)"), "{a}");
    assert!(a.contains("deny  api.demo.test/secret  (config)"), "{a}");
    assert!(
        !a.contains("github.com  (config)"),
        "the app's network overlay replaces the baseline's, so github.com must be gone:\n{a}"
    );
    assert!(
        a.contains("allow cache.nixos.org  (builtin)"),
        "the built-in nix-cache set is app-invariant and still listed:\n{a}"
    );

    // `--source config` + `--app`: the app's config rules only, no built-in set.
    let cfg = fx.run(&["net", "rules", "--app", "demo", "--source", "config"]);
    let c = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        c.contains("api.demo.test") && !c.contains("(builtin)"),
        "--source config must filter to the app's own rules:\n{c}"
    );

    // `--json` + `--app`: the effective rules as JSON (the {mode, rules} contract is unchanged).
    let json = fx.run(&["net", "rules", "--app", "demo", "--json"]);
    let v: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("net rules --app --json emits valid JSON");
    assert_eq!(v["mode"], "deny");
    assert!(
        v["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["rule"] == "api.demo.test"),
        "the app's rule must be in the JSON:\n{v}"
    );

    // An unknown app is a pointed, exit-2 error listing what exists.
    let bad = fx.run(&["net", "rules", "--app", "nope"]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("no app named"),
        "an unknown app must error"
    );

    // `--app` does not combine with `--source manual` (manual is live runtime, not config).
    let clash = fx.run(&["net", "rules", "--app", "demo", "--source", "manual"]);
    assert_eq!(clash.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&clash.stderr).contains("does not combine"),
        "--app + --source manual must be refused"
    );
}

#[test]
fn test_net_reflects_the_built_in_nix_cache_set_both_directions() {
    let fx = Fixture::new();
    // A trusted project allowlist that lists one host which is ALSO a built-in nix-cache host.
    fx.write_project("[network]\nmode = \"deny\"\nallow = [\"github.com\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // A nix-cache host the user did NOT list: allowed only by the built-in union, and tagged so.
    let cache = fx.run(&["test", "net", "https://cache.nixos.org/nix-cache-info"]);
    assert!(cache.status.success());
    let c = String::from_utf8_lossy(&cache.stdout);
    assert!(
        c.contains("ALLOWED") && c.contains("built-in nix-cache"),
        "a cache host must pass via the built-in set and be tagged:\n{c}"
    );

    // A host the user explicitly listed: allowed by the user's own rule — no built-in tag, even
    // though github.com is also in the built-in set (the user rule is what decides).
    let user = fx.run(&["test", "net", "https://github.com/x"]);
    assert!(user.status.success());
    let u = String::from_utf8_lossy(&user.stdout);
    assert!(
        u.contains("ALLOWED") && !u.contains("(built-in nix-cache)"),
        "a user-listed host must not be tagged built-in:\n{u}"
    );
}
