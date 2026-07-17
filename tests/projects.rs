//! Integration tests for `sbx projects`: the built binary lists and removes the per-project
//! runtime trees under `<data>/projects/<id>`. Pure host-side filesystem work — no sandbox, no
//! nix, no network — so the tests run everywhere against redirected XDG dirs and fabricated trees
//! (a directory with a `project` marker whose recorded path is present = `idle`, absent = `dead`,
//! or no marker = `markerless`). They never touch the shared store, so `--gc` is exercised only in
//! its no-op branch here; its real shared-store collection is proven end-to-end in `run.rs`.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A unique temp dir removed on drop, on the repo disk (not tmpfs).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("target/test-tmp");
        d.push(format!("sbx-projects-{}-{n}", std::process::id()));
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

    fn sbx(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args(args)
            .current_dir(self.proj.path())
            .env("XDG_CONFIG_HOME", self.config_home.path())
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_DATA_HOME", self.data_home.path())
            .env("LC_ALL", "C.UTF-8")
            .env_remove("LANG")
            .output()
            .expect("spawn sbx")
    }

    fn projects_dir(&self) -> PathBuf {
        self.data_home.path().join("sbx/projects")
    }

    /// Fabricate a project runtime tree with some on-disk content (so it has a size). `marker` is
    /// the absolute path recorded in the `project` file — `Some(existing)` reads back `idle`,
    /// `Some(absent-under-present-parent)` reads back `dead`; `None` writes no marker (`markerless`).
    fn make_tree(&self, id: &str, marker: Option<&Path>) -> PathBuf {
        let dir = self.projects_dir().join(id);
        std::fs::create_dir_all(dir.join("store/nix")).unwrap();
        std::fs::write(dir.join("store/nix/blob"), vec![b'x'; 4096]).unwrap();
        if let Some(p) = marker {
            assert!(p.is_absolute(), "a marker path must be absolute");
            std::fs::write(dir.join("project"), p.as_os_str().as_bytes()).unwrap();
        }
        dir
    }

    /// Fabricate a store gcroot `<data>/sbx/gcroots/projects/<tree_id>/<name>` — the realized-package
    /// signal `sbx projects show` reads.
    fn make_gcroot(&self, tree_id: &str, name: &str) {
        let dir = self
            .data_home
            .path()
            .join("sbx/gcroots/projects")
            .join(tree_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), b"x").unwrap();
    }

    /// Fabricate a warm flake out-link in a tree's own home — `<tree>/home/.local/state/ops/flake/
    /// <name>` — the realized signal for a `flake:` package (which builds into the home, not the store).
    fn build_flake(&self, tree_id: &str, name: &str, store_leaf: &str) {
        let dir = self
            .projects_dir()
            .join(tree_id)
            .join("home/.local/state/ops/flake");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(format!("/nix/store/{store_leaf}"), dir.join(name)).unwrap();
    }
}

fn text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

#[test]
fn list_classifies_and_sizes_each_tree() {
    let fx = Fixture::new();
    fx.make_tree("aaaaaaaaaaaaaaaa", Some(fx.proj.path())); // idle: marker path exists
    fx.make_tree("bbbbbbbbbbbbbbbb", Some(&fx.proj.path().join("gone"))); // dead: parent present
    fx.make_tree("cccccccccccccccc", None); // markerless

    let out = fx.sbx(&["projects", "list"]);
    assert!(
        out.status.success(),
        "sbx projects list failed: {}",
        text(&out)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    for id in ["aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb", "cccccccccccccccc"] {
        assert!(s.contains(id), "listing is missing tree {id}:\n{s}");
    }
    assert!(s.contains("idle"), "missing the idle state:\n{s}");
    assert!(s.contains("dead"), "missing the dead state:\n{s}");
    assert!(
        s.contains("markerless"),
        "missing the markerless state:\n{s}"
    );
    // The size column: 4 KiB of content per tree renders a KiB figure, not 0.
    assert!(
        s.contains("KiB"),
        "the size column should show a KiB figure:\n{s}"
    );
}

#[test]
fn show_reports_store_roots_and_declared_but_not_built() {
    let fx = Fixture::new();
    let proj = fx.proj.path().canonicalize().unwrap();
    // A tree that belongs to the project directory (idle), with one realized nix package.
    let tree = "1111111111111111";
    fx.make_tree(tree, Some(&proj));
    fx.make_gcroot(tree, "built"); // the `built` package's gcroot
                                   // The project declares two nix packages: one is realized (`built`), one is not (`absent`).
    std::fs::write(
        proj.join(".sbx.toml"),
        "[packages]\nbuilt = \"nix:hello\"\nabsent = \"nix:missing\"\n",
    )
    .unwrap();
    // Trust the config so its packages resolve as trusted (declared, not withheld).
    let out = fx.sbx(&["trust"]);
    assert!(out.status.success(), "trust failed: {}", text(&out));

    let out = fx.sbx(&["projects", "show", tree]);
    assert!(out.status.success(), "projects show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    // The realized package shows as a store root; the size breakdown is present.
    assert!(
        s.contains("store roots") && s.contains("built"),
        "the realized package should be a store root:\n{s}"
    );
    assert!(
        s.contains("store ") && s.contains("home "),
        "size breakdown:\n{s}"
    );
    // The unrealized declared package shows as `not built yet` (trusted, so not `withheld`).
    assert!(
        s.contains("declared but not built:") && s.contains("absent"),
        "the unrealized package should be listed:\n{s}"
    );
    assert!(
        s.contains("not built yet") && !s.contains("withheld"),
        "a trusted unbuilt package reads `not built yet`, not `withheld`:\n{s}"
    );

    // --json carries the same distinction.
    let out = fx.sbx(&["projects", "show", tree, "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert!(v["store_roots"]["nix"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "built"));
    let unbuilt = v["unbuilt"].as_array().expect("unbuilt array");
    assert_eq!(unbuilt.len(), 1, "one unbuilt package: {v}");
    assert!(unbuilt[0]["locator"].as_str().unwrap().contains("absent"));
    assert_eq!(unbuilt[0]["withheld"], false);
}

#[test]
fn show_counts_a_flake_built_into_the_home_as_realized() {
    let fx = Fixture::new();
    let proj = fx.proj.path().canonicalize().unwrap();
    let tree = "4444444444444444";
    fx.make_tree(tree, Some(&proj));
    // The project declares a flake; it is built into the tree's home (floating — no lock).
    std::fs::write(
        proj.join(".sbx.toml"),
        "[packages]\nagent = \"flake:github:foo/bar#default\"\n",
    )
    .unwrap();
    fx.build_flake(
        tree,
        "agent",
        "abcd1234abcd1234abcd1234abcd1234abcd1234-bar-1.0",
    );
    let out = fx.sbx(&["trust"]);
    assert!(out.status.success(), "trust failed: {}", text(&out));

    let out = fx.sbx(&["projects", "show", tree, "--json"]);
    assert!(out.status.success(), "projects show failed: {}", text(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    // The flake is realized (warm out-link), so it is NOT in the "declared but not built" set.
    assert!(
        v["unbuilt"].as_array().unwrap().is_empty(),
        "a flake built into the home must not read as unbuilt: {v}"
    );
}

#[test]
fn show_marks_an_untrusted_declaration_withheld() {
    let fx = Fixture::new();
    let proj = fx.proj.path().canonicalize().unwrap();
    let tree = "2222222222222222";
    fx.make_tree(tree, Some(&proj));
    // Declared, but the config is never trusted.
    std::fs::write(
        proj.join(".sbx.toml"),
        "[packages]\nabsent = \"nix:missing\"\n",
    )
    .unwrap();

    let out = fx.sbx(&["projects", "show", tree]);
    assert!(out.status.success(), "projects show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("absent") && s.contains("withheld"),
        "an untrusted declaration should read `withheld`:\n{s}"
    );
}

#[test]
fn show_of_a_dead_tree_reports_realized_state_only() {
    let fx = Fixture::new();
    // A marker pointing at a project directory that no longer exists.
    let tree = "3333333333333333";
    fx.make_tree(tree, Some(&fx.proj.path().join("gone")));
    fx.make_gcroot(tree, "somepkg");

    let out = fx.sbx(&["projects", "show", tree]);
    assert!(out.status.success(), "projects show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    // Realized state (the gcroot) is shown…
    assert!(s.contains("somepkg"), "realized root should show:\n{s}");
    // …but with no config to compare against, there is no declared section — just the note.
    assert!(
        s.contains("project directory is gone") && !s.contains("declared but not built"),
        "a dead tree shows realized state only:\n{s}"
    );

    let out = fx.sbx(&["projects", "show", tree, "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["config_available"], false);
    assert!(v["unbuilt"].as_array().unwrap().is_empty());
}

#[test]
fn show_of_an_unknown_tree_fails() {
    let fx = Fixture::new();
    let out = fx.sbx(&["projects", "show", "deadbeefdeadbeef"]);
    assert_eq!(out.status.code(), Some(1), "unknown tree should fail 1");
    assert!(
        text(&out).contains("no runtime tree"),
        "missing not-found message:\n{}",
        text(&out)
    );
}

#[test]
fn show_without_an_id_is_a_usage_error() {
    let fx = Fixture::new();
    let out = fx.sbx(&["projects", "show"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "bare `projects show` should exit 2"
    );
    assert!(
        text(&out).contains("sbx projects show <id>"),
        "should print the synopsis:\n{}",
        text(&out)
    );
}

#[test]
fn bare_projects_prints_the_page_and_does_not_list() {
    let fx = Fixture::new();
    fx.make_tree("aaaaaaaaaaaaaaaa", Some(fx.proj.path()));

    // Bare `sbx projects` (no subcommand) prints the help page and exits 2 — it does NOT list, so
    // it never runs the sweep, mirroring bare `sbx app`/`sbx session`.
    let out = fx.sbx(&["projects"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "bare `sbx projects` should exit 2: {}",
        text(&out)
    );
    let s = text(&out);
    assert!(
        s.contains("sbx projects list"),
        "the page should show the `list` synopsis:\n{s}"
    );
    assert!(
        !s.contains("aaaaaaaaaaaaaaaa"),
        "bare `sbx projects` must not list any tree:\n{s}"
    );

    // A leading flag with no subcommand (e.g. `--json`) also prints the page rather than listing.
    let out = fx.sbx(&["projects", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "`sbx projects --json` (no subcommand) should exit 2: {}",
        text(&out)
    );
}

#[test]
fn list_json_is_an_array_carrying_state_and_size() {
    let fx = Fixture::new();
    fx.make_tree("deadfeeddeadfeed", Some(&fx.proj.path().join("gone")));

    let out = fx.sbx(&["projects", "list", "--json"]);
    assert!(
        out.status.success(),
        "sbx projects --json failed: {}",
        text(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let rows = v.as_array().expect("a JSON array");
    let row = rows
        .iter()
        .find(|r| r["id"] == "deadfeeddeadfeed")
        .expect("the fabricated tree in the JSON");
    assert_eq!(row["state"], "dead");
    assert!(
        row["bytes"].as_u64().unwrap() > 0,
        "bytes should be non-zero: {row}"
    );
    assert!(
        row["size"].is_string(),
        "a human-readable size string: {row}"
    );
    assert_eq!(row["current"], false);
}

#[test]
fn list_is_empty_when_there_are_no_trees() {
    let fx = Fixture::new();
    let out = fx.sbx(&["projects", "list"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no per-project runtime trees"),
        "an empty listing should say so:\n{}",
        text(&out)
    );
}

#[test]
fn rm_a_named_tree_removes_it_immediately() {
    let fx = Fixture::new();
    let dir = fx.make_tree("1234567890abcdef", Some(&fx.proj.path().join("gone")));

    let out = fx.sbx(&["projects", "rm", "1234567890abcdef"]);
    assert!(out.status.success(), "rm failed: {}", text(&out));
    assert!(!dir.exists(), "the tree should be gone:\n{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("removed"),
        "should report the removal:\n{}",
        text(&out)
    );
}

#[test]
fn rm_dry_run_previews_without_removing() {
    let fx = Fixture::new();
    let dir = fx.make_tree("1234567890abcdef", Some(&fx.proj.path().join("gone")));

    let out = fx.sbx(&["projects", "rm", "1234567890abcdef", "--dry-run"]);
    assert!(out.status.success(), "dry-run rm failed: {}", text(&out));
    assert!(
        dir.exists(),
        "a dry run must not remove the tree:\n{}",
        text(&out)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("removable"),
        "should report it as removable:\n{}",
        text(&out)
    );
}

#[test]
fn rm_dead_previews_by_default_and_reaps_with_yes() {
    let fx = Fixture::new();
    let dead = fx.make_tree("deaddeaddeaddead", Some(&fx.proj.path().join("gone")));
    let idle = fx.make_tree("keepkeepkeepkeep", Some(fx.proj.path())); // idle: must survive

    // Default is a preview — nothing removed.
    let preview = fx.sbx(&["projects", "rm", "--dead"]);
    assert!(preview.status.success());
    assert!(
        dead.exists(),
        "a --dead preview must not remove:\n{}",
        text(&preview)
    );

    // --yes applies, reaping only the dead tree.
    let apply = fx.sbx(&["projects", "rm", "--dead", "--yes"]);
    assert!(
        apply.status.success(),
        "--dead --yes failed: {}",
        text(&apply)
    );
    assert!(
        !dead.exists(),
        "the dead tree should be reaped:\n{}",
        text(&apply)
    );
    assert!(
        idle.exists(),
        "the idle tree must survive a --dead sweep:\n{}",
        text(&apply)
    );
}

#[test]
fn rm_markerless_needs_yes_and_leaves_marked_trees() {
    let fx = Fixture::new();
    let markerless = fx.make_tree("nomarkernomarker", None);
    let idle = fx.make_tree("keepkeepkeepkeep", Some(fx.proj.path()));

    let out = fx.sbx(&["projects", "rm", "--markerless", "--yes"]);
    assert!(
        out.status.success(),
        "--markerless --yes failed: {}",
        text(&out)
    );
    assert!(
        !markerless.exists(),
        "the markerless tree should be reaped:\n{}",
        text(&out)
    );
    assert!(
        idle.exists(),
        "a marked tree must survive a --markerless sweep:\n{}",
        text(&out)
    );
}

#[test]
fn rm_with_no_target_is_a_usage_error() {
    let fx = Fixture::new();
    let out = fx.sbx(&["projects", "rm"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "no target should be a usage error"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("name a project id"),
        "should explain what to pass:\n{}",
        text(&out)
    );
}

#[test]
fn rm_dry_run_and_yes_together_are_contradictory() {
    let fx = Fixture::new();
    fx.make_tree("1234567890abcdef", Some(&fx.proj.path().join("gone")));
    let out = fx.sbx(&["projects", "rm", "1234567890abcdef", "--dry-run", "--yes"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "contradictory flags should be a usage error"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("contradictory"),
        "should name the contradiction:\n{}",
        text(&out)
    );
}

#[test]
fn rm_an_unknown_id_fails_without_touching_other_trees() {
    let fx = Fixture::new();
    let keep = fx.make_tree("keepkeepkeepkeep", Some(fx.proj.path()));
    let out = fx.sbx(&["projects", "rm", "0000000000000000"]);
    assert_eq!(out.status.code(), Some(1), "an unknown id is a failure");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no project tree for id"),
        "should report the missing id:\n{}",
        text(&out)
    );
    assert!(
        keep.exists(),
        "an unrelated tree must be untouched:\n{}",
        text(&out)
    );
}

#[test]
fn rm_rejects_a_path_shaped_id() {
    let fx = Fixture::new();
    // A traversal id must be refused before any join reaches a recursive delete.
    let out = fx.sbx(&["projects", "rm", "../escape"]);
    assert_eq!(out.status.code(), Some(1), "a path-shaped id is refused");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("invalid project id"),
        "should name the invalid id:\n{}",
        text(&out)
    );
}

#[test]
fn gc_is_inert_on_a_dry_run() {
    let fx = Fixture::new();
    let dir = fx.make_tree("1234567890abcdef", Some(&fx.proj.path().join("gone")));
    // --gc with a preview must not run the shared-store collection; it says so and removes nothing.
    let out = fx.sbx(&["projects", "rm", "1234567890abcdef", "--dry-run", "--gc"]);
    assert!(out.status.success(), "dry-run --gc failed: {}", text(&out));
    assert!(dir.exists(), "a dry run must not remove:\n{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("--gc runs the shared-store collection only when"),
        "should explain --gc is deferred on a preview:\n{}",
        text(&out)
    );
}
