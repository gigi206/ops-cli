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

    /// Write an imported app profile `apps/<name>.toml` (a top-level `RawApp`) beside the global
    /// config. Global apps live only as profile files — an inline `[app.<name>]` in `ops.toml` is
    /// forbidden — so any test that needs a global app routes through here.
    fn write_profile(&self, name: &str, body: &str) {
        let dir = self.config_home.path().join("ops").join("apps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), body).unwrap();
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
    // the mode header, the config allow/deny rules each tagged, and the built-in self-equip set
    assert!(stdout.contains("network: deny"), "{stdout}");
    // each L7 host rule renders the implicit `https://`, so the layer is visible at a glance
    assert!(
        stdout.contains("allow https://github.com  (config)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("allow https://*.nixos.org  (config)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("deny  https://evil.nixos.org  (config)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("allow {GET,HEAD} https://cache.nixos.org  (builtin)"),
        "the built-in self-equip set must be listed and tagged (read-only hosts scoped):\n{stdout}"
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
    assert_eq!(json["rules"][0]["rule"], "https://github.com");
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
        stdout.contains("allow https://global.example  (config)"),
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
        String::from_utf8_lossy(&rules.stdout).contains("allow https://github.com  (config)"),
        "the persisted, re-trusted rule must appear in `ops net rules`:\n{}",
        String::from_utf8_lossy(&rules.stdout)
    );

    // A second add of the same rule is an idempotent no-op.
    let again = fx.run(&["net", "allow", "github.com"]);
    assert!(String::from_utf8_lossy(&again.stdout).contains("already present"));
}

#[test]
fn net_allow_persists_a_tcp_rule_that_reloads_as_a_splice() {
    let fx = Fixture::new();
    // `net allow tcp://…` is a security-rule write: it must validate, persist, re-trust, and reload
    // as a raw-splice rule. Bootstrap a fresh project with the tcp:// rule.
    let out = fx.run(&["net", "allow", "tcp://ssh.example.com:22"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The round-trip: it persists with its scheme and reloads as a config rule (the layer visible).
    let rules = fx.run(&["net", "rules"]);
    assert!(
        String::from_utf8_lossy(&rules.stdout).contains("allow tcp://ssh.example.com:22  (config)"),
        "the persisted tcp:// rule must reload and show its scheme:\n{}",
        String::from_utf8_lossy(&rules.stdout)
    );

    // And it decides a raw splice — the reloaded rule drives `l4_decision`, not just display.
    let hit = fx.run(&["test", "net", "tcp://ssh.example.com:22"]);
    assert!(
        String::from_utf8_lossy(&hit.stdout).contains("SPLICED"),
        "the persisted tcp:// rule must splice its host:port:\n{}",
        String::from_utf8_lossy(&hit.stdout)
    );
}

#[test]
fn net_allow_rejects_a_portless_tcp_rule() {
    // A raw splice must name the port it opens — a port-less `tcp://` rule is refused at the CLI
    // (exit 2), with a message pointing at the fix. (A bare L7 host, by contrast, defaults to 443.)
    let fx = Fixture::new();
    let out = fx.run(&["net", "allow", "tcp://ssh.example.com"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "a port-less tcp:// rule must be rejected"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("explicit `:port`"),
        "the error must point at the missing port:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // `tcp://host:*` (every port) is accepted — the explicit way to open all ports and protocols.
    assert!(fx
        .run(&["net", "allow", "tcp://ssh.example.com:*"])
        .status
        .success());
}

#[test]
fn a_host_with_both_a_tcp_and_an_l7_rule_warns() {
    let fx = Fixture::new();
    // The same host:port carries a raw tcp:// allow AND an inspected (L7) path deny — the splice is
    // uninspected, so the L7 deny silently does not apply. The config load must warn about it.
    fx.write_project(
        "[network]\nmode = \"allowlist\"\nallow = [\"tcp://api.example.com:443\"]\ndeny = [\"api.example.com/secret\"]\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["net", "rules"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("api.example.com")
            && stderr.contains("tcp://")
            && stderr.contains("splice is uninspected"),
        "a host with both an L4 and an L7 rule must warn that the splice bypasses inspection:\n{stderr}"
    );

    // A host reached by only one layer does not warn (no false positive).
    fx.write_project(
        "[network]\nmode = \"allowlist\"\nallow = [\"tcp://ssh.example.com:22\", \"api.example.com\"]\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let clean = fx.run(&["net", "rules"]);
    assert!(
        !String::from_utf8_lossy(&clean.stderr).contains("splice is uninspected"),
        "disjoint single-layer hosts must not warn:\n{}",
        String::from_utf8_lossy(&clean.stderr)
    );
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
fn net_allow_accepts_a_group_reference_and_persists_it_verbatim() {
    let fx = Fixture::new();
    // A `@<group>` reference is an alias for a `[net.groups]` group (expanded at load time), not a
    // classifiable host rule, so the write path validates it as a group *name* rather than through
    // `classify` (which rejects the `@`) and persists it verbatim — a group can be added the same
    // way a host is.
    let out = fx.run(&["net", "allow", "@mcp", "--global"]);
    assert!(
        out.status.success(),
        "a group reference must be accepted: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let global = fx.config_home.path().join("ops").join("ops.toml");
    let body = std::fs::read_to_string(&global).unwrap();
    assert!(
        body.contains("\"@mcp\""),
        "the reference lands verbatim in the allow list:\n{body}"
    );
    // An invalid group name is refused (fail-closed), like a malformed host rule — nothing is
    // written that a later load could not resolve to a legal reference.
    let bad = fx.run(&["net", "allow", "@bad name", "--global"]);
    assert!(
        !bad.status.success(),
        "an invalid group name must be refused"
    );
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("group name"),
        "the error names the group-name rule: {}",
        String::from_utf8_lossy(&bad.stderr)
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
    // NOTE: this still wholesale-replaces the app's effective network until the Inc 2 deep-merge
    // lands — a project `[app.<name>.network]` with a mode replaces the profile's posture. Inc 2
    // makes a mode-less overlay amend it instead.
}

#[test]
fn net_allow_app_save_global_writes_to_profile_and_preserves_profile_fields() {
    let fx = Fixture::new();
    // A full claude-code-style profile: cmd, packages, binds, env, and an `[network] mode="ask"`
    // allowlist of 7 hosts. An app-scoped `--save -g` must AMEND the profile's allow array in place
    // — preserving mode/cmd/packages/binds/env — and must NOT write a shadowing `[app.claude-code…]`
    // into the global ops.toml (the brick bug).
    fx.write_global("[network]\nmode = \"shared\"\n");
    fx.write_profile(
        "claude-code",
        "cmd = \"claude\"\n\
         \n\
         [packages]\nclaude-code = \"mise:aqua:anthropics/claude-code\"\n\
         \n\
         [env]\nHOME = \"/home/gigi\"\nDISABLE_TELEMETRY = \"1\"\n\
         \n\
         [[binds]]\npath = \"/home/gigi/.claude\"\nmode = \"rw\"\n\
         \n\
         [network]\nmode = \"ask\"\nallow = [\n\
         \t\"{*} api.anthropic.com:443\",\n\
         \t\"{*} platform.claude.com:443\",\n\
         \t\"{*} console.anthropic.com:443\",\n\
         \t\"{*} mcp-proxy.anthropic.com:443\",\n\
         \t\"claude.ai:443\",\n\
         \t\"{GET,HEAD} downloads.claude.ai:443\",\n\
         \t\"{GET,HEAD} storage.googleapis.com:443/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/*\",\n\
         ]\n",
    );

    let out = fx.run(&["net", "allow", "new.host.com", "--app", "claude-code", "-g"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The rule landed in the PROFILE's `[network].allow`, mode="ask" preserved, and every other
    // profile field (cmd/packages/env/binds) is untouched.
    let profile = std::fs::read_to_string(
        fx.config_home
            .path()
            .join("ops")
            .join("apps")
            .join("claude-code.toml"),
    )
    .unwrap();
    assert!(
        profile.contains("new.host.com") && profile.contains("mode = \"ask\""),
        "the new host must append to the profile's allowlist with the mode preserved:\n{profile}"
    );
    assert!(
        profile.contains("cmd = \"claude\"")
            && profile.contains("mise:aqua:anthropics/claude-code")
            && profile.contains("DISABLE_TELEMETRY")
            && profile.contains("/home/gigi/.claude"),
        "the profile's cmd/packages/env/binds must be preserved:\n{profile}"
    );

    // The global ops.toml must NOT carry a shadowing `[app.claude-code…]` stub.
    let global =
        std::fs::read_to_string(fx.config_home.path().join("ops").join("ops.toml")).unwrap();
    assert!(
        !global.contains("[app.claude-code"),
        "no inline app stub must be written to the global config:\n{global}"
    );

    // The effective policy reflects the amended allowlist: 8 hosts, mode ask.
    let rules = fx.run(&["net", "rules", "--app", "claude-code"]);
    assert!(rules.status.success());
    let r = String::from_utf8_lossy(&rules.stdout);
    assert!(
        r.contains("network (app claude-code): ask"),
        "the app's mode stays ask:\n{r}"
    );
    assert!(
        r.contains("new.host.com") && r.contains("api.anthropic.com"),
        "both the new host and a profile host must be in the effective rules:\n{r}"
    );
}

#[test]
fn net_allow_app_save_global_creates_profile_when_absent() {
    let fx = Fixture::new();
    fx.write_global("[network]\nmode = \"shared\"\n");
    // No profile exists for `newapp`. An app-scoped `--save -g` creates a minimal profile carrying
    // a deny-by-default allowlist with the host (the Absent bootstrap).
    let out = fx.run(&["net", "allow", "host.com", "--app", "newapp", "-g"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let profile = std::fs::read_to_string(
        fx.config_home
            .path()
            .join("ops")
            .join("apps")
            .join("newapp.toml"),
    )
    .unwrap();
    assert!(
        profile.contains("[network]")
            && profile.contains("mode = \"deny\"")
            && profile.contains("host.com"),
        "a fresh profile is created with a deny allowlist carrying the host:\n{profile}"
    );
    let rules = fx.run(&["net", "rules", "--app", "newapp"]);
    assert!(rules.status.success());
    assert!(
        String::from_utf8_lossy(&rules.stdout).contains("host.com"),
        "the new app's rule is visible"
    );
}

#[test]
fn inline_app_in_global_ops_toml_is_dropped_with_migration_guidance() {
    let fx = Fixture::new();
    // Simulate the pre-fix bad state: a hand-written `[app.foo]` in the global config. It must be
    // dropped inert (never shadow a profile of the same name) with a per-app migration warning, and
    // `ops net rules --app foo` must report no such app rather than launch a half-stub.
    fx.write_global(
        "[app.foo]\ncmd = \"true\"\n\
         [app.foo.network]\nmode = \"deny\"\nallow = [\"api.foo.test\"]\n",
    );
    let rules = fx.run(&["net", "rules"]);
    let stderr = String::from_utf8_lossy(&rules.stderr);
    assert!(
        stderr.contains("app `foo`") && stderr.contains("ops app export foo"),
        "the dropped inline must warn with migration guidance:\n{stderr}"
    );
    let bad = fx.run(&["net", "rules", "--app", "foo"]);
    assert_eq!(
        bad.status.code(),
        Some(2),
        "the inline app is inert — it is not a resolvable app"
    );
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("no app named"),
        "the inline app must not be launchable:\n{}",
        String::from_utf8_lossy(&bad.stderr)
    );
}

#[test]
fn net_allow_app_save_local_still_writes_project_ops_toml() {
    let fx = Fixture::new();
    fx.write_global("[network]\nmode = \"shared\"\n");
    fx.write_profile(
        "claude",
        "cmd = \"claude\"\n[network]\nmode = \"ask\"\nallow = [\"api.anthropic.com\"]\n",
    );
    // `--save -l -a <app>` targets the project `.ops.toml [app.<app>.network]` (a project overlay is
    // still allowed). Inc 1 leaves this path wholesale-replacing the profile's network at resolve
    // time — the Inc 2 deep-merge fixes that. Here we only pin that the write lands in the project.
    let out = fx.run(&["net", "allow", "h.com", "--app", "claude", "-l"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        body.contains("[app.claude.network]") && body.contains("h.com"),
        "the project overlay must land in .ops.toml:\n{body}"
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
    assert!(
        r.contains("allow https://github.com  (config)"),
        "net rules:\n{r}"
    );
    assert!(
        r.contains("deny  https://evil.com  (config)"),
        "net rules:\n{r}"
    );

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
fn net_pending_all_rejects_a_stray_id_a_scope_without_save_and_a_file_scope() {
    let fx = Fixture::new();

    // A stray positional id alongside `--all` is a usage error (the two address different things).
    let out = fx.run(&["net", "pending", "deny", "--all", "123.1"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("takes no id"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A scope flag WITHOUT `--save` is meaningless (there is no file to write) — refused, pointing at
    // `--save` (to persist) or `--app` (to narrow the drain).
    let out = fx.run(&["net", "pending", "allow", "--all", "--global"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("without `--save` takes no scope"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `--all --save` does NOT take a `-c <file>` scope (the vocabulary is --local/--global).
    let out = fx.run(&[
        "net",
        "pending",
        "allow",
        "--all",
        "--save",
        "-c",
        "/tmp/x.toml",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--local or --global"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn net_pending_all_save_local_refuses_an_untrusted_project_before_draining() {
    let fx = Fixture::new();
    // An untrusted project config in the cwd: a `--local` bulk save must refuse UP FRONT — before the
    // irreversible drain — rather than answer everything then fail to save with nothing persisted.
    fx.write_project("[network]\nmode = \"ask\"\nallow = [\"x.test\"]\n");
    let before = std::fs::read(fx.proj.path().join(".ops.toml")).unwrap();

    let out = fx.run(&["net", "pending", "allow", "--all", "--save", "--local"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not trusted"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The untrusted config is byte-for-byte untouched — not silently blessed by the refused save.
    assert_eq!(
        std::fs::read(fx.proj.path().join(".ops.toml")).unwrap(),
        before,
        "the untrusted config must not be modified"
    );
}

#[test]
fn net_pending_all_save_global_drains_and_persists_each_host() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let egress = fx.data_home.path().join("ops").join("egress");
    std::fs::create_dir_all(&egress).unwrap();
    let pid = 55555u32; // a fake session: --global drains every socket, no registry/project filter
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();

    // The fake session answers the bulk drain with one host.
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        assert!(
            cmd.starts_with("ALLOW *"),
            "expected a bulk drain, got {cmd:?}"
        );
        (&stream)
            .write_all(b"answered host=blocked.example\nok\n")
            .unwrap();
    });

    let out = fx.run(&["net", "pending", "allow", "--all", "--save", "--global"]);
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("blocked.example")
            && stdout.contains("saved 1 allow rule(s) to the global config"),
        "the drain and the save must both be reported:\n{stdout}"
    );

    // The global config now carries the allow rule for the drained host (the durable half).
    let global =
        std::fs::read_to_string(fx.config_home.path().join("ops").join("ops.toml")).unwrap();
    assert!(
        global.contains("blocked.example"),
        "the rule must be persisted to the global config:\n{global}"
    );
}

#[test]
fn net_pending_all_save_global_app_writes_the_profile_and_names_it_not_the_global_config() {
    // The user's exact command: `net pending allow --all --save -g --app <name>`. The drained host
    // must land in the app's PROFILE file (`apps/<name>.toml`), amending its `[network].allow` with
    // `mode = "ask"` and every other field preserved — NOT a shadowing `[app.<name>.network]` stub in
    // the global ops.toml (the brick bug) — and the summary must NAME the profile, never "the global
    // config under app <name>" (the stale line that lied about where the rule went).
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    // A global baseline exists (so the "no inline stub" assertion is meaningful), plus the app's real
    // profile: a cmd and an ask-mode allowlist the drain must preserve.
    fx.write_global("[network]\nmode = \"shared\"\n");
    fx.write_profile(
        "claude-code",
        "cmd = \"claude\"\n\
         \n\
         [network]\n\
         mode = \"ask\"\n\
         allow = [\"api.anthropic.com:443\"]\n",
    );

    // Register THIS process as a live GlobalApp session of `claude-code` so the `--app` filter finds
    // it (liveness pruning keeps it — the process is alive and its start_ticks match). The record
    // format is session.rs's serializer: `runtime=global-app:<name>`, filename `<pid>-<start_ticks>`.
    let data = fx.data_home.path().join("ops");
    let egress = data.join("egress");
    let sessions = data.join("sessions");
    std::fs::create_dir_all(&egress).unwrap();
    std::fs::create_dir_all(&sessions).unwrap();
    let pid = std::process::id();
    let start_ticks: u64 = {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after = &stat[stat.rfind(')').unwrap() + 1..];
        after.split_whitespace().nth(19).unwrap().parse().unwrap()
    };
    let project_hex: String = fx
        .proj
        .path()
        .canonicalize()
        .unwrap()
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        sessions.join(format!("{pid}-{start_ticks}")),
        format!(
            "kind=run\npid={pid}\nstart={start_ticks}\nruntime=global-app:claude-code\n\
             project={project_hex}\n"
        ),
    )
    .unwrap();

    // The fake session answers the bulk drain with one host to be saved into the profile.
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        assert!(
            cmd.starts_with("ALLOW *"),
            "expected a bulk drain, got {cmd:?}"
        );
        (&stream)
            .write_all(b"answered host=mcp.context7.com\nok\n")
            .unwrap();
    });

    let out = fx.run(&[
        "net",
        "pending",
        "allow",
        "--all",
        "--save",
        "--global",
        "--app",
        "claude-code",
    ]);
    server.join().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The summary names the PROFILE, and never claims the global config (the old lie).
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mcp.context7.com")
            && stdout.contains("saved 1 allow rule(s) to the app profile `claude-code`"),
        "the drain must report the profile as the target:\n{stdout}"
    );
    assert!(
        !stdout.contains("to the global config"),
        "the summary must not claim the rule went to the global config:\n{stdout}"
    );

    // The rule appended to the profile's allowlist, with mode ask and cmd preserved.
    let profile = std::fs::read_to_string(
        fx.config_home
            .path()
            .join("ops")
            .join("apps")
            .join("claude-code.toml"),
    )
    .unwrap();
    assert!(
        profile.contains("mcp.context7.com")
            && profile.contains("mode = \"ask\"")
            && profile.contains("cmd = \"claude\""),
        "the host must append to the profile's allowlist, preserving mode and cmd:\n{profile}"
    );

    // No shadowing inline app stub was written to the global ops.toml.
    let global =
        std::fs::read_to_string(fx.config_home.path().join("ops").join("ops.toml")).unwrap();
    assert!(
        !global.contains("[app.claude-code"),
        "no inline app stub must be written to the global config:\n{global}"
    );
}

#[test]
fn net_pending_all_save_local_drains_this_project_and_writes_its_config() {
    // The headline, proven end to end: `--all --save --local` drains only THIS project's session and
    // persists the host to THIS project's `.ops.toml`. The project filter needs a *live* registered
    // session, so register THIS test process (alive → survives liveness pruning) as a project session
    // of fx.proj, and bind its control socket; the child `fx.run` then drains it via the project
    // filter. The one coupling is the registry record format (session.rs's serializer): fields
    // `kind=/pid=/start=/runtime=project/project=<canonical>`, filename `<pid>-<start_ticks>`,
    // start_ticks = `/proc/self/stat` field 22.
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let data = fx.data_home.path().join("ops");
    let egress = data.join("egress");
    let sessions = data.join("sessions");
    std::fs::create_dir_all(&egress).unwrap();
    std::fs::create_dir_all(&sessions).unwrap();

    let pid = std::process::id();
    let start_ticks: u64 = {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        // Everything after the last ')' starts at field 3 (state); starttime is field 22 → index 19.
        let after = &stat[stat.rfind(')').unwrap() + 1..];
        after.split_whitespace().nth(19).unwrap().parse().unwrap()
    };
    // The project path is hex-encoded in the record (so a non-UTF-8/newline path round-trips).
    use std::os::unix::ffi::OsStrExt;
    let project = fx.proj.path().canonicalize().unwrap();
    let project_hex: String = project
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        sessions.join(format!("{pid}-{start_ticks}")),
        format!(
            "kind=run\npid={pid}\nstart={start_ticks}\nruntime=project\nproject={project_hex}\n"
        ),
    )
    .unwrap();

    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        assert!(
            cmd.starts_with("ALLOW *"),
            "expected a bulk drain, got {cmd:?}"
        );
        (&stream)
            .write_all(b"answered host=blocked.example\nok\n")
            .unwrap();
    });

    // No initial `.ops.toml` → the precheck passes (absent is fine) and the local save bootstraps it.
    let out = fx.run(&["net", "pending", "allow", "--all", "--save", "--local"]);
    server.join().unwrap();
    let _ = std::fs::remove_file(&socket);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("blocked.example") && stdout.contains("scoped to this project"),
        "the local drain must report the host and the project scope:\n{stdout}"
    );

    // THIS project's config was created (and trusted) with the allow rule — the durable local half,
    // proving drain-filtered-to-project + persist-local composed correctly.
    let cfg = std::fs::read_to_string(fx.proj.path().join(".ops.toml"))
        .expect("the project config must be created");
    assert!(
        cfg.contains("blocked.example"),
        "the rule must be persisted to THIS project's config:\n{cfg}"
    );
}

#[test]
fn net_pending_all_accepts_an_app_filter_and_lists_accept_it_too() {
    let fx = Fixture::new();

    // The user's exact shape — `-a <app> --all --session` — is now ACCEPTED (it used to error with
    // "takes no id or scope"). With no live session for that app it is a clean no-op that names the
    // app, so an empty result is not mistaken for "nothing parked anywhere".
    let out = fx.run(&[
        "net",
        "pending",
        "allow",
        "-a",
        "claude-code",
        "--all",
        "--session",
    ]);
    assert!(
        out.status.success(),
        "an app-scoped --all must be accepted:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("for app `claude-code`"),
        "the empty drain must name the app:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // `-a <app>` is also accepted on the listing (it used to be silently ignored). No session → the
    // clean empty line, which names the app (not "nothing anywhere"), exit 0.
    let out = fx.run(&["net", "pending", "-a", "claude-code"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("none for app `claude-code`"),
        "{:?}",
        String::from_utf8_lossy(&out.stdout)
    );

    // A bare `--app` with no name is a usage error, and an unknown flag is now rejected rather than
    // silently ignored (the bug that hid `-a` in the first place).
    assert_eq!(fx.run(&["net", "pending", "--app"]).status.code(), Some(2));
    assert_eq!(
        fx.run(&["net", "pending", "--bogus"]).status.code(),
        Some(2)
    );
}

#[test]
fn net_stats_aggregates_a_projects_sessions_and_filters_by_app() {
    // Hand-author session stat files keyed by this project's canonical path (the header
    // `egress::start` writes), then prove `ops net stats` sums them for the project, scopes to an
    // app, carries the counts in `--json`, and `--reset` clears only this project's files.
    let fx = Fixture::new();
    let egress = fx.data_home.path().join("ops").join("egress");
    std::fs::create_dir_all(&egress).unwrap();
    let proj = fx.proj.path().canonicalize().unwrap();
    let proj = proj.display().to_string();

    // Two sessions of this project (one tagged `app=demo`), one of an unrelated project.
    std::fs::write(
        egress.join("stats-1"),
        format!("project={proj}\ncache.nixos.org\t10\t0\t0\nevil.test\t0\t3\t1\n"),
    )
    .unwrap();
    std::fs::write(
        egress.join("stats-2"),
        format!("project={proj}\napp=demo\ncache.nixos.org\t5\t0\t0\n"),
    )
    .unwrap();
    std::fs::write(
        egress.join("stats-3"),
        "project=/somewhere/else\nother.test\t99\t0\t0\n",
    )
    .unwrap();

    // Project-wide table: the two sessions sum, the other project is excluded.
    let out = fx.run(&["net", "stats"]);
    assert!(
        out.status.success(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("ALLOW") && s.contains("DENY") && s.contains("BLOCKED"),
        "{s}"
    );
    assert!(
        s.contains("cache.nixos.org") && s.contains("evil.test"),
        "{s}"
    );
    assert!(
        !s.contains("other.test"),
        "another project's hosts must not appear:\n{s}"
    );

    // `--json` carries exact counts: cache.nixos.org allow = 10 + 5 = 15.
    let out = fx.run(&["net", "stats", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let cache = v["stats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["host"] == "cache.nixos.org")
        .expect("cache.nixos.org row");
    assert_eq!(cache["allow"], 15);
    let evil = v["stats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["host"] == "evil.test")
        .expect("evil.test row");
    assert_eq!(evil["deny"], 3);
    assert_eq!(evil["blocked"], 1);

    // `--app demo`: only the tagged session (allow 5), the untagged session's evil.test is gone.
    let out = fx.run(&["net", "stats", "--app", "demo", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rows = v["stats"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "only the app session's host: {rows:?}");
    assert_eq!(rows[0]["host"], "cache.nixos.org");
    assert_eq!(rows[0]["allow"], 5);

    // `--reset` clears this project's two files; the unrelated project's file is untouched.
    let out = fx.run(&["net", "stats", "--reset"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("reset 2"),
        "{:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!egress.join("stats-1").exists() && !egress.join("stats-2").exists());
    assert!(
        egress.join("stats-3").exists(),
        "another project's file must survive --reset"
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

#[test]
fn net_pending_all_app_scoped_drains_a_registered_app_session() {
    // The app-scoped live drain — the path that was untested (the existing app-filter test covered
    // only the empty case). Register THIS process as a `global-app:claude-code` session, bind its
    // control socket, then drive `-a claude-code --all --session` and assert it actually answers.
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let data = fx.data_home.path().join("ops");
    let egress = data.join("egress");
    let sessions = data.join("sessions");
    std::fs::create_dir_all(&egress).unwrap();
    std::fs::create_dir_all(&sessions).unwrap();

    let pid = std::process::id();
    let start_ticks: u64 = {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after = &stat[stat.rfind(')').unwrap() + 1..];
        after.split_whitespace().nth(19).unwrap().parse().unwrap()
    };
    let project = fx.proj.path().canonicalize().unwrap();
    let project_hex: String = project
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // The crux: an APP session (`global-app:claude-code`), so `session.app() == Some("claude-code")`.
    std::fs::write(
        sessions.join(format!("{pid}-{start_ticks}")),
        format!(
            "kind=run\npid={pid}\nstart={start_ticks}\nruntime=global-app:claude-code\nproject={project_hex}\n"
        ),
    )
    .unwrap();

    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        assert!(
            cmd.starts_with("ALLOW *"),
            "expected a bulk drain, got {cmd:?}"
        );
        (&stream)
            .write_all(b"answered host=claude.ai\nok\n")
            .unwrap();
    });

    let out = fx.run(&[
        "net",
        "pending",
        "allow",
        "-a",
        "claude-code",
        "--all",
        "--session",
    ]);
    let _ = std::fs::remove_file(&socket);
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("claude.ai") && !stdout.contains("no pending requests"),
        "the app-scoped drain must answer the parked host, got:\n{stdout}"
    );
}

#[test]
fn net_pending_all_names_an_older_session_instead_of_claiming_empty() {
    // A control server speaking the OLD protocol (one predating `--all`) replies `err bad-request`
    // to a bulk drain. The CLI must NOT swallow it as "no pending requests" (the misleading field
    // symptom) — it names the older session and points at the only real fix, relaunching the agent.
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let egress = fx.data_home.path().join("ops").join("egress");
    std::fs::create_dir_all(&egress).unwrap();
    let pid = 44444u32;
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        // An old server does not understand `ALLOW *`.
        (&stream).write_all(b"err bad-request\n").unwrap();
    });
    let out = fx.run(&["net", "pending", "allow", "--all"]);
    let _ = std::fs::remove_file(&socket);
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("no pending requests")
            && stdout.contains("44444")
            && stdout.contains("older ops")
            && stdout.contains("relaunch the agent"),
        "the drain must surface the older session, not claim emptiness:\n{stdout}"
    );
}

#[test]
fn net_pending_all_save_names_an_older_session_and_saves_nothing() {
    // The `--save` drain site must surface an older session too — and, since nothing was answered,
    // persist nothing (no false "saved a rule" against a session it could not actually drain).
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let egress = fx.data_home.path().join("ops").join("egress");
    std::fs::create_dir_all(&egress).unwrap();
    let pid = 45454u32;
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        (&stream).write_all(b"err bad-request\n").unwrap();
    });
    // `--global` avoids the project filter so the unsupported session is reached.
    let out = fx.run(&["net", "pending", "allow", "--all", "--save", "--global"]);
    let _ = std::fs::remove_file(&socket);
    server.join().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("older ops") && stdout.contains("relaunch the agent"),
        "the --save drain must name the older session:\n{stdout}"
    );
    assert!(
        !stdout.contains("saved"),
        "nothing was answered, so nothing must be reported saved:\n{stdout}"
    );
    // The global config must not have been written (no rule to persist).
    assert!(
        !fx.config_home.path().join("ops").join("ops.toml").exists(),
        "an unsupported-only drain must not write any config"
    );
}

#[test]
fn net_pending_by_id_accepts_an_app_scope_and_rejects_a_mismatch() {
    // `-a <app>` on the by-id path is a session scope (the natural carry-over from
    // `ops net pending -a <app>`), honored without `--save`: it answers the id when the registry
    // confirms that session is that app, and refuses when the id belongs to a *different* app.
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let data = fx.data_home.path().join("ops");
    let egress = data.join("egress");
    let sessions = data.join("sessions");
    std::fs::create_dir_all(&egress).unwrap();
    std::fs::create_dir_all(&sessions).unwrap();

    let pid = std::process::id();
    let start_ticks: u64 = {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let after = &stat[stat.rfind(')').unwrap() + 1..];
        after.split_whitespace().nth(19).unwrap().parse().unwrap()
    };
    let project = fx.proj.path().canonicalize().unwrap();
    let project_hex: String = project
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        sessions.join(format!("{pid}-{start_ticks}")),
        format!(
            "kind=run\npid={pid}\nstart={start_ticks}\nruntime=global-app:claude-code\nproject={project_hex}\n"
        ),
    )
    .unwrap();

    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();
    // Only the matching-app case reaches the socket (the mismatch is refused before any answer).
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut cmd = String::new();
        BufReader::new(&stream).read_line(&mut cmd).unwrap();
        assert!(cmd.starts_with(&format!("ALLOW {pid_seq}", pid_seq = 1)));
        (&stream).write_all(b"ok host=claude.ai count=1\n").unwrap();
    });

    // Matching app → answered (the rejection that prompted this fix is gone).
    let ok = fx.run(&[
        "net",
        "pending",
        "allow",
        "-a",
        "claude-code",
        &format!("{pid}.1"),
        "--session",
    ]);
    server.join().unwrap();
    assert!(
        ok.status.success() && String::from_utf8_lossy(&ok.stdout).contains("claude.ai"),
        "an app-scoped by-id answer must work:\nout={}\nerr={}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );

    // A different app → refused before contacting the session, naming the actual app.
    let bad = fx.run(&[
        "net",
        "pending",
        "allow",
        "-a",
        "some-other-app",
        &format!("{pid}.1"),
    ]);
    let _ = std::fs::remove_file(&socket);
    assert_eq!(bad.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("is a session of app `claude-code`"),
        "the mismatch must name the actual app:\n{}",
        String::from_utf8_lossy(&bad.stderr)
    );
}

#[test]
fn net_pending_list_collapses_identical_retries_in_text_and_json() {
    // A tool that retries one URL re-parks it many times; the listing must show one line per
    // destination (with a count), not one per connection — proven through the real binary against a
    // fake control socket that replies with duplicate LIST rows. The same grouping holds in `--json`
    // (so a consumer is not handed individually-addressable seqs that `allow` no longer answers one
    // at a time).
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let fx = Fixture::new();
    let egress = fx.data_home.path().join("ops").join("egress");
    std::fs::create_dir_all(&egress).unwrap();
    let pid = 44444u32; // not registered → the `(unregistered)` header path; irrelevant to grouping
    let socket = egress.join(format!("control-{pid}.sock"));
    let listener = UnixListener::bind(&socket).unwrap();

    // Two LISTs are served (one per `ops net pending` invocation below): three parked rows each — two
    // identical retries of one URL (seqs 1 and 4) plus a different destination (seq 2).
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            let mut cmd = String::new();
            BufReader::new(&stream).read_line(&mut cmd).unwrap();
            assert!(cmd.starts_with("LIST"), "expected a LIST, got {cmd:?}");
            (&stream)
                .write_all(
                    b"pending seq=1 port=443 waiting=80 host=dl.test path=/latest\n\
                      pending seq=4 port=443 waiting=20 host=dl.test path=/latest\n\
                      pending seq=2 port=443 waiting=50 host=logs.test path=/api\n\
                      ok\n",
                )
                .unwrap();
        }
    });

    // Text: the two dl.test retries collapse to one `×2` line at the lowest seq (44444.1) with the
    // largest wait (80s); the different destination keeps its own line; the higher seq is gone.
    let text = fx.run(&["net", "pending"]);
    let t = String::from_utf8_lossy(&text.stdout);
    assert!(
        t.contains("44444.1") && t.contains("dl.test:443/latest") && t.contains("×2, waiting 80s"),
        "identical retries must collapse to one ×2 line:\n{t}"
    );
    assert!(
        !t.contains("44444.4"),
        "the retry must not be a line of its own:\n{t}"
    );
    assert!(t.contains("logs.test:443/api"), "{t}");

    // JSON: grouped the same way — one object per destination, dl.test carrying count=2.
    let json = fx.run(&["net", "pending", "--json"]);
    server.join().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let arr = v["pending"].as_array().unwrap();
    assert_eq!(arr.len(), 2, "two destinations, not three connections: {v}");
    let dl = arr.iter().find(|r| r["host"] == "dl.test").unwrap();
    assert_eq!(dl["count"], 2, "{v}");
    assert_eq!(dl["id"], "44444.1", "{v}");
    assert_eq!(dl["waiting_secs"], 80, "{v}");
}

// ── `ops test net` enrichments: app targeting, launch fidelity, scheme-optional ─────────────────

#[test]
fn test_net_targets_an_app_effective_policy() {
    let fx = Fixture::new();
    // A global config (trusted by location, so no `ops trust` needed): a baseline allowlist that
    // does NOT list the app's host. The app itself lives as an imported profile `apps/demo.toml`
    // (a global app is a profile file, never an inline `[app.demo]` in `ops.toml`), whose own
    // overlay allows the host and injects a key.
    fx.write_global("[network]\nmode = \"deny\"\nallow = [\"github.com\"]\n");
    fx.write_profile(
        "demo",
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
    // A global config (trusted by location): a baseline allowlist listing one host. The app lives
    // as an imported profile `apps/demo.toml` (a global app is a profile file), whose OWN network
    // overlay lists a different host and a path-scoped deny. `--app` must list the app's effective
    // rules (its overlay replaces the baseline posture), not the baseline's.
    fx.write_global("[network]\nmode = \"deny\"\nallow = [\"github.com\"]\n");
    fx.write_profile(
        "demo",
        "cmd = \"true\"\n\
         \n\
         [network]\n\
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
        b.contains("allow https://github.com  (config)") && !b.contains("api.demo.test"),
        "the baseline listing must be the baseline, not the app:\n{b}"
    );

    // `--app demo`: the app's effective policy. The header names the scope; its own allow/deny
    // appear; the baseline's github.com is GONE (the app's network replaces it); the built-in
    // built-in set is still unioned (app-invariant).
    let app = fx.run(&["net", "rules", "--app", "demo"]);
    assert!(app.status.success());
    let a = String::from_utf8_lossy(&app.stdout);
    assert!(
        a.contains("network (app demo): deny"),
        "the header must name the app scope:\n{a}"
    );
    // the app's unscoped allow host is read-by-default ({GET,HEAD}); the deny is left broad.
    assert!(
        a.contains("allow {GET,HEAD} https://api.demo.test  (config)"),
        "{a}"
    );
    assert!(
        a.contains("deny  https://api.demo.test/secret  (config)"),
        "{a}"
    );
    assert!(
        !a.contains("github.com  (config)"),
        "the app's network overlay replaces the baseline's, so github.com must be gone:\n{a}"
    );
    assert!(
        a.contains("allow {GET,HEAD} https://cache.nixos.org  (builtin)"),
        "the built-in self-equip set is app-invariant and still listed:\n{a}"
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
            .any(|r| r["rule"] == "{GET,HEAD} https://api.demo.test"),
        "the app's rule must be in the JSON (read-by-default):\n{v}"
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
fn test_net_reflects_the_built_in_set_both_directions() {
    let fx = Fixture::new();
    // A trusted project allowlist that lists one host which is ALSO a built-in self-equip host.
    fx.write_project("[network]\nmode = \"deny\"\nallow = [\"github.com\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // A built-in host the user did NOT list: allowed only by the built-in union, and tagged so.
    let cache = fx.run(&["test", "net", "https://cache.nixos.org/nix-cache-info"]);
    assert!(cache.status.success());
    let c = String::from_utf8_lossy(&cache.stdout);
    assert!(
        c.contains("ALLOWED") && c.contains("(built-in)"),
        "a cache host must pass via the built-in set and be tagged:\n{c}"
    );

    // A host the user explicitly listed: allowed by the user's own rule — no built-in tag, even
    // though github.com is also in the built-in set (the user rule is what decides).
    let user = fx.run(&["test", "net", "https://github.com/x"]);
    assert!(user.status.success());
    let u = String::from_utf8_lossy(&user.stdout);
    assert!(
        u.contains("ALLOWED") && !u.contains("(built-in)"),
        "a user-listed host must not be tagged built-in:\n{u}"
    );
}

#[test]
fn test_net_method_scopes_a_rule_to_its_verbs() {
    let fx = Fixture::new();
    // a GET/HEAD-only allow for the host
    fx.write_project("[network]\nmode = \"allowlist\"\nallow = [\"{GET,HEAD} api.test:443\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // the prefix is shown in the rule listing, with the implicit scheme (443 is the default → bare)
    let rules = fx.run(&["net", "rules", "--source", "config"]);
    assert!(
        String::from_utf8_lossy(&rules.stdout).contains("{GET,HEAD} https://api.test"),
        "the method prefix and scheme must be listed"
    );

    // GET (and the default verb) reach; POST does not
    let get = fx.run(&["test", "net", "--method", "GET", "https://api.test/x"]);
    assert!(
        String::from_utf8_lossy(&get.stdout).contains("ALLOWED"),
        "GET must be allowed by a GET/HEAD rule"
    );
    let dflt = fx.run(&["test", "net", "https://api.test/x"]);
    assert!(
        String::from_utf8_lossy(&dflt.stdout).contains("ALLOWED"),
        "the default verb (GET) must be allowed"
    );
    let post = fx.run(&["test", "net", "-X", "POST", "https://api.test/x"]);
    assert!(
        String::from_utf8_lossy(&post.stdout).contains("DENIED"),
        "POST must be denied by a GET/HEAD-only rule"
    );
}

#[test]
fn test_net_reports_a_tcp_rule_as_a_raw_splice() {
    let fx = Fixture::new();
    // a tcp:// (raw L4) allow for a specific host:port
    fx.write_project("[network]\nmode = \"allowlist\"\nallow = [\"tcp://ssh.example.com:22\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // the rule listing shows the `tcp://` scheme, so the layer (the proto) is visible
    let rules = fx.run(&["net", "rules", "--source", "config"]);
    assert!(
        String::from_utf8_lossy(&rules.stdout).contains("tcp://ssh.example.com:22"),
        "the tcp:// scheme must be shown in the rule listing:\n{}",
        String::from_utf8_lossy(&rules.stdout)
    );

    // the exact host:port is SPLICED (raw L4)
    let hit = fx.run(&["test", "net", "tcp://ssh.example.com:22"]);
    let h = String::from_utf8_lossy(&hit.stdout);
    assert!(
        h.contains("SPLICED"),
        "the tcp:// rule must splice its host:port:\n{h}"
    );

    // a different port on the same host is NOT spliced (it would take the inspected L7 path)
    let other_port = fx.run(&["test", "net", "tcp://ssh.example.com:2222"]);
    assert!(
        String::from_utf8_lossy(&other_port.stdout).contains("NOT SPLICED"),
        "a port the tcp:// rule does not cover must not splice"
    );

    // a different host is not spliced
    let other_host = fx.run(&["test", "net", "tcp://other.example.com:22"]);
    assert!(
        String::from_utf8_lossy(&other_host.stdout).contains("NOT SPLICED"),
        "an unlisted host must not splice"
    );
}

#[test]
fn test_net_reports_a_deny_suppressed_splice() {
    // deny wins even over a `tcp://` allow: a host-level deny suppresses the raw splice, and the
    // tester says *why* (a covered host that does not splice must not read as "no rule covers it").
    let fx = Fixture::new();
    fx.write_project(
        "[network]\nmode = \"allowlist\"\n\
         allow = [\"tcp://evil.com:443\"]\ndeny = [\"re:^https://evil\\\\.com\"]\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["test", "net", "tcp://evil.com:443"]);
    let o = String::from_utf8_lossy(&out.stdout);
    assert!(
        o.contains("NOT SPLICED") && o.contains("deny rule suppressed"),
        "a deny must suppress the splice and the tester must explain it:\n{o}"
    );
}

#[test]
fn an_app_is_read_by_default_while_the_baseline_shell_stays_open() {
    // The Mode-A vs Mode-B contrast: a trusted baseline allowlist is all-verbs for `ops run`/`ops
    // shell` (Mode A), but an app (Mode B) that inherits that same allowlist is read-by-default
    // ({GET,HEAD}) — so a POST the bare `ops test net` allows is denied under `--app`.
    let fx = Fixture::new();
    fx.write_project(
        "[network]\nmode = \"allowlist\"\nallow = [\"shared.test\"]\n\
         [app.agent]\ncmd = \"true\"\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // Baseline (no --app): all verbs — a POST is allowed.
    let base_post = fx.run(&["test", "net", "-X", "POST", "https://shared.test/x"]);
    assert!(
        String::from_utf8_lossy(&base_post.stdout).contains("ALLOWED"),
        "the baseline shell is all-verbs (Mode A open):\n{}",
        String::from_utf8_lossy(&base_post.stdout)
    );

    // The app inherits the same allowlist but is read-by-default: GET passes, POST is denied.
    let app_get = fx.run(&[
        "test",
        "net",
        "--app",
        "agent",
        "-X",
        "GET",
        "https://shared.test/x",
    ]);
    assert!(
        String::from_utf8_lossy(&app_get.stdout).contains("ALLOWED"),
        "GET under the app passes"
    );
    let app_post = fx.run(&[
        "test",
        "net",
        "--app",
        "agent",
        "-X",
        "POST",
        "https://shared.test/x",
    ]);
    assert!(
        String::from_utf8_lossy(&app_post.stdout).contains("DENIED"),
        "POST under the app is denied — the agent is read-by-default:\n{}",
        String::from_utf8_lossy(&app_post.stdout)
    );
}

#[test]
fn an_app_declares_a_write_host_with_a_star_prefix() {
    // An app's own allowlist: an unscoped host inherits the {GET,HEAD} default; a `{*}` host opts
    // back out to every verb (the way a profile declares its API/write hosts).
    let fx = Fixture::new();
    fx.write_project(
        "[app.agent]\ncmd = \"true\"\n\
         [app.agent.network]\nmode = \"allowlist\"\nallow = [\"read.test\", \"{*} write.test\"]\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // `net rules --app` shows the unscoped host narrowed and the {*} host kept.
    let rules = fx.run(&["net", "rules", "--app", "agent"]);
    let r = String::from_utf8_lossy(&rules.stdout);
    assert!(
        r.contains("allow {GET,HEAD} https://read.test"),
        "an unscoped host is read-by-default:\n{r}"
    );
    assert!(
        r.contains("allow {*} https://write.test"),
        "a {{*}} host keeps every verb:\n{r}"
    );

    // The verdicts follow: POST denied on the read host, allowed on the write host.
    let read_post = fx.run(&[
        "test",
        "net",
        "--app",
        "agent",
        "-X",
        "POST",
        "https://read.test/x",
    ]);
    assert!(
        String::from_utf8_lossy(&read_post.stdout).contains("DENIED"),
        "POST to the read-by-default host is denied"
    );
    let write_post = fx.run(&[
        "test",
        "net",
        "--app",
        "agent",
        "-X",
        "POST",
        "https://write.test/x",
    ]);
    assert!(
        String::from_utf8_lossy(&write_post.stdout).contains("ALLOWED"),
        "POST to the {{*}} write host is allowed"
    );
}
