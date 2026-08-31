//! Integration tests for `sbx path`: the built binary lists every on-disk
//! location sbx uses, grouped by XDG base, marks which exist, and enumerates the
//! per-project / per-app / per-profile entries actually on disk. Read-only: no
//! trust gate, no network — so the assertions exercise the layout against
//! redirected XDG data/config/state dirs and a temp project as the cwd.

#[macro_use]
mod common;
use common::fixture::TmpDir;

use std::process::Command;

struct Fixture {
    proj: TmpDir,
    config_home: TmpDir,
    state_home: TmpDir,
    data_home: TmpDir,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            proj: TmpDir::new("path"),
            config_home: TmpDir::new("path"),
            state_home: TmpDir::new("path"),
            data_home: TmpDir::new("path"),
        }
    }

    fn sbx(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
        cmd.args(args)
            .current_dir(self.proj.path())
            .env("XDG_CONFIG_HOME", self.config_home.path())
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_DATA_HOME", self.data_home.path())
            .env("LC_ALL", "C.UTF-8")
            .env_remove("LANG");
        cmd
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        self.sbx(args).output().expect("spawn sbx")
    }
}

#[test]
fn path_lists_the_three_bases_with_present_absent_markers() {
    let fx = Fixture::new();
    // The common first-run state: the data root exists (sbx creates it lazily on
    // a launch, but here nothing has run yet) only if we make it; the overview
    // must still succeed and mark each entry honestly either way.
    let out = fx.run(&["path"]);
    assert!(out.status.success(), "sbx path must exit 0");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("sbx on-disk locations"), "header:\n{s}");
    // All three bases are listed, each with its XDG-contract hint.
    assert!(
        s.contains("data:") && s.contains("config:") && s.contains("state:"),
        "bases:\n{s}"
    );
    assert!(s.contains("$XDG_DATA_HOME/sbx"), "data env hint:\n{s}");
    assert!(s.contains("$XDG_CONFIG_HOME/sbx"), "config env hint:\n{s}");
    assert!(s.contains("$XDG_STATE_HOME/sbx"), "state env hint:\n{s}");
    // Every known entry appears, and each carries a present/absent tag — never
    // a bare path with no state.
    for entry in [
        "store/",
        "engine/",
        "plugins/",
        "stores/",
        "sessions/",
        "egress/",
        "mise/",
        "gcroots/",
        "projects/",
        "apps/",
        "sbx.toml",
        "trusted/",
    ] {
        assert!(s.contains(entry), "entry {entry} listed:\n{s}");
    }
    assert!(
        s.contains("(present)") || s.contains("(absent)"),
        "state tags:\n{s}"
    );
    // The cross-reference to the config-files overview is shown.
    assert!(s.contains("sbx config path"), "cross-ref:\n{s}");
}

#[test]
fn path_enumerates_per_project_per_app_and_per_profile_entries() {
    let fx = Fixture::new();
    // A project runtime tree, a global app home (data), and an imported profile
    // (config) — the three enumeration axes.
    std::fs::create_dir_all(fx.data_home.path().join("sbx/projects/abcdef")).unwrap();
    std::fs::create_dir_all(fx.data_home.path().join("sbx/apps/myagent")).unwrap();
    let cfg_apps = fx.config_home.path().join("sbx/apps");
    std::fs::create_dir_all(&cfg_apps).unwrap();
    std::fs::write(cfg_apps.join("codex.toml"), "").unwrap();
    // A non-.toml file in the profiles dir is ignored by the Profiles filter.
    std::fs::write(cfg_apps.join("README.txt"), "").unwrap();

    let out = fx.run(&["path"]);
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    // Each enumerated child appears indented under its parent.
    assert!(s.contains("    abcdef"), "project id enumerated:\n{s}");
    // A markerless project (no `project` file) is annotated with its state, and the line carries a
    // YYYY-MM-DD date, the "is this stale?" signal a cleanup decision rests on.
    assert!(
        s.contains("(markerless)"),
        "markerless state shown for a project:\n{s}"
    );
    assert!(
        s.contains("20"),
        "a date is rendered beside the state:\n{s}"
    );
    assert!(
        s.contains("    myagent"),
        "global app home enumerated:\n{s}"
    );
    assert!(
        s.contains("    codex"),
        "profile enumerated (suffix stripped):\n{s}"
    );
    // The non-profile file is not shown as a profile.
    assert!(!s.contains("    README"), "non-.toml excluded:\n{s}");
    // A project child's full path is shown beside its name.
    assert!(
        s.contains(
            fx.data_home
                .path()
                .join("sbx/projects/abcdef")
                .to_str()
                .unwrap()
        ),
        "project child path:\n{s}"
    );
    assert!(
        s.contains(
            fx.config_home
                .path()
                .join("sbx/apps/codex.toml")
                .to_str()
                .unwrap()
        ),
        "profile child keeps .toml in path:\n{s}"
    );
}

#[test]
fn path_json_is_a_valid_document_carrying_the_layout() {
    let fx = Fixture::new();
    std::fs::create_dir_all(fx.data_home.path().join("sbx/projects/abcdef")).unwrap();
    std::fs::create_dir_all(fx.data_home.path().join("sbx/apps/myagent")).unwrap();
    let cfg_apps = fx.config_home.path().join("sbx/apps");
    std::fs::create_dir_all(&cfg_apps).unwrap();
    std::fs::write(cfg_apps.join("codex.toml"), "").unwrap();

    let out = fx.run(&["path", "--json"]);
    assert!(out.status.success(), "sbx path --json must exit 0");
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("path --json must emit valid JSON");

    let bases = doc["bases"].as_array().expect("bases array");
    assert_eq!(bases.len(), 3, "three bases");
    assert_eq!(bases[0]["label"], "data");
    assert_eq!(bases[1]["label"], "config");
    assert_eq!(bases[2]["label"], "state");

    // The data root is reflected, and a present project is enumerated as a child.
    let data = &bases[0];
    assert_eq!(
        data["root"],
        fx.data_home.path().join("sbx").to_str().unwrap()
    );
    let projects = data["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["label"] == "projects/")
        .unwrap();
    let kids = projects["children"].as_array().expect("projects children");
    assert!(
        kids.iter().any(|c| c["name"] == "abcdef"),
        "project child: {kids:?}"
    );
    let apps = data["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["label"] == "apps/")
        .unwrap();
    assert!(
        apps["children"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "myagent"),
        "app child: {:?}",
        apps["children"]
    );

    // A profile child's path keeps the .toml suffix; the name drops it.
    let config = &bases[1];
    let profiles = config["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["label"] == "apps/")
        .unwrap();
    let pkids = profiles["children"].as_array().expect("profile children");
    let codex = pkids.iter().find(|c| c["name"] == "codex").unwrap();
    assert!(
        codex["path"].as_str().unwrap().ends_with("/codex.toml"),
        "profile path keeps suffix: {:?}",
        codex["path"]
    );
}

#[test]
fn path_rejects_an_unknown_flag() {
    let fx = Fixture::new();
    let out = fx.run(&["path", "--bogus"]);
    assert!(!out.status.success(), "unknown flag must not succeed");
    let s = String::from_utf8_lossy(&out.stderr);
    assert!(s.contains("unknown argument"), "stderr:\n{s}");
}
