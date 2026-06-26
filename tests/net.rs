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

    // an unknown rule source
    fx.write_project("network = \"deny\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["net", "rules", "--source", "manual"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("config, builtin"),
        "an unknown source must name the known ones (manual lands later)"
    );
}
