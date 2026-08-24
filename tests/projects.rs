//! Integration tests for `sbx projects`: the built binary lists and removes the per-project
//! runtime trees under `<data>/projects/<id>`. Host-side filesystem work — no sandbox and no
//! network — against redirected XDG dirs and fabricated trees (a directory with a `project` marker
//! whose recorded path is present = `idle`, absent = `dead`, or no marker = `markerless`). They
//! never touch the shared store, so `--gc` is exercised only in its no-op branch here; its real
//! shared-store collection is proven end-to-end in `run.rs`.
//!
//! One test does read the *order* of `sbx gc --all`'s two passes, and the second of those passes
//! needs `nix-store` to run at all. It skips where the tool is absent rather than reading the
//! collection's own "skipping" line as a missing report.
//!
//! The same host-side-only harness also covers `sbx gc`'s sweep of the per-launch **runtime files**
//! (fabricated under a redirected data dir and keyed by a reaped pid), including the dry run's
//! must-touch-nothing contract.

#[macro_use]
mod common;

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

// The fixtures' root, one definition shared with the unit tests.
include!("../src/testroot.rs");

/// A unique temp dir removed on drop, on the repo disk (not tmpfs).
struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
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
}

fn text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// The registry's self-healing pass runs first in every `sbx projects` verb, and it announced its
/// pruning on **stdout**. One stale record — a session whose process is gone, which is the ordinary
/// state of a data directory after a crash or a reboot — put a line of prose ahead of the JSON
/// document, so `sbx projects --json | jq` failed on a run that had done nothing wrong. The notice
/// belongs on stderr with every other diagnostic.
#[test]
fn a_pruned_session_record_does_not_land_in_the_json_document() {
    let fx = Fixture::new();
    fx.make_tree("aaaaaaaaaaaaaaaa", Some(fx.proj.path()));
    // A record for a pid that cannot be live: pid 0 is the scheduler, never a session.
    let sessions = fx.data_home.path().join("sbx/sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::write(
        sessions.join("0-1"),
        format!(
            "kind=run\npid=0\nstart=1\nruntime=project\ndetached=false\nproject={}\n",
            fx.proj.path().display()
        ),
    )
    .unwrap();

    let out = fx.sbx(&["projects", "list", "--json"]);
    assert!(
        out.status.success(),
        "sbx projects --json failed: {}",
        text(&out)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be one JSON document ({e}):\n{stdout}"));
    // The notice itself is not lost, only moved.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("stale session record"),
        "the pruning must still be reported, on stderr:\n{stderr}"
    );
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
    assert!(
        v["store_roots"]["nix"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "built")
    );
    let unbuilt = v["unbuilt"].as_array().expect("unbuilt array");
    assert_eq!(unbuilt.len(), 1, "one unbuilt package: {v}");
    assert!(unbuilt[0]["locator"].as_str().unwrap().contains("absent"));
    assert_eq!(unbuilt[0]["withheld"], false);

    // A gcroot's prefix says which backend built it, and every prefix the realized-signal check
    // looks for has to be one this grouping strips. `tarball-` and `binary-` were not, so those
    // roots fell into the `nix` bucket and were reported as `nix:` packages the project does not
    // declare.
    fx.make_gcroot(tree, "tarball-rolled");
    fx.make_gcroot(tree, "binary-shipped");
    let out = fx.sbx(&["projects", "show", tree, "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let bucket = |kind: &str| -> Vec<String> {
        v["store_roots"][kind]
            .as_array()
            .unwrap_or_else(|| panic!("no `{kind}` bucket: {v}"))
            .iter()
            .map(|x| x.as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert_eq!(bucket("tarball"), vec!["rolled".to_string()]);
    assert_eq!(bucket("binary"), vec!["shipped".to_string()]);
    let nix = bucket("nix");
    assert!(
        !nix.iter()
            .any(|n| n.contains("rolled") || n.contains("shipped")),
        "a prebuilt output must not read as a `nix:` package: {nix:?}"
    );
}

#[test]
fn show_counts_a_remote_flake_built_into_the_store_as_realized() {
    let fx = Fixture::new();
    let proj = fx.proj.path().canonicalize().unwrap();
    let tree = "4444444444444444";
    fx.make_tree(tree, Some(&proj));
    // The project declares a remote flake; it builds host-side into the per-project store, gcrooted
    // by its declared name (like `nix:`), so the per-tree gcroot is its realized signal.
    std::fs::write(
        proj.join(".sbx.toml"),
        "[packages]\nagent = \"flake:github:foo/bar#default\"\n",
    )
    .unwrap();
    fx.make_gcroot(tree, "agent");
    let out = fx.sbx(&["trust"]);
    assert!(out.status.success(), "trust failed: {}", text(&out));

    let out = fx.sbx(&["projects", "show", tree, "--json"]);
    assert!(out.status.success(), "projects show failed: {}", text(&out));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    // The flake is realized (its per-project store gcroot), so it is NOT in the "declared but not
    // built" set.
    assert!(
        v["unbuilt"].as_array().unwrap().is_empty(),
        "a flake built into the per-project store must not read as unbuilt: {v}"
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

/// The preview of `--markerless` points at the apply form; a listing nobody asked `--markerless`
/// for points at a manual removal, which is the fail-closed stance.
///
/// Both selectors were folded into their own already-applied flag at the call site, so the report
/// could not tell "you asked for this and it is a preview" from "you did not ask": a preview said
/// "remove by hand", and the branch written for it could not be reached at all, since with the flag
/// set the trees are reaped and the list it reads is empty.
#[test]
fn a_markerless_preview_points_at_the_apply_form() {
    let fx = Fixture::new();
    let markerless = fx.make_tree("nomarkernomarker", None);

    let preview = fx.sbx(&["projects", "rm", "--markerless"]);
    assert!(
        preview.status.success(),
        "preview failed: {}",
        text(&preview)
    );
    assert!(
        markerless.exists(),
        "a preview reclaims nothing:\n{}",
        text(&preview)
    );
    let said = text(&preview);
    assert!(
        said.contains("--markerless --yes"),
        "the preview of the opt-in must point at its apply form:\n{said}"
    );

    // The default listing, where nobody asked for the hatch, still points at a by-hand removal.
    let plain = fx.sbx(&["projects", "rm", "--dead"]);
    let said = text(&plain);
    assert!(
        said.contains("remove by hand"),
        "an unasked-for markerless tree keeps the fail-closed hint:\n{said}"
    );
    assert!(
        !said.contains("--markerless --yes"),
        "and is not pointed at an opt-in it did not ask for:\n{said}"
    );
}

/// `Path::join` replaces the base with an absolute argument and walks out of it for a `../`, so an
/// id taken from the caller has to be one ordinary component before it is joined. `rm` checked;
/// `show` did not, so `sbx projects show /etc` sized and read that directory and reported it as a
/// runtime tree.
#[test]
fn show_refuses_an_id_that_is_a_path() {
    let fx = Fixture::new();
    fx.make_tree("aaaaaaaaaaaaaaaa", Some(fx.proj.path()));
    for bad in ["/etc", "../..", "a/b", "."] {
        let out = fx.sbx(&["projects", "show", bad]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{bad}` must be refused as an id, not joined: {}",
            text(&out)
        );
        assert!(
            text(&out).contains("invalid project id"),
            "and named as what it is: {}",
            text(&out)
        );
    }
    // A real id still works.
    let ok = fx.sbx(&["projects", "show", "aaaaaaaaaaaaaaaa"]);
    assert!(ok.status.success(), "{}", text(&ok));
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

/// The pid of a process that has run and been reaped — dead by construction, so a liveness check
/// classifies anything keyed by it as a leftover.
fn reaped_pid() -> u32 {
    let mut child = Command::new("/bin/true").spawn().expect("spawn /bin/true");
    let pid = child.id();
    let _ = child.wait();
    pid
}

/// The per-launch runtime files of a dead launch are swept by `sbx gc --all --prune` — and, the
/// property that regressed once, left **untouched** by the dry run that merely reports them.
///
/// A unit test cannot catch that regression: the sweep function itself was correct, and the bug was
/// *where it was called from* (a launch-path helper `sbx gc` also runs, so a dry run deleted what it
/// claimed was merely reclaimable). Only driving the real binary pins it.
#[test]
fn gc_sweeps_dead_launch_runtime_files_but_never_on_a_dry_run() {
    let fx = Fixture::new();
    let pid = reaped_pid();
    let sbx_data = fx.data_home.path().join("sbx");
    let egress = sbx_data.join("egress");
    let portal = sbx_data.join("portal").join(pid.to_string());
    std::fs::create_dir_all(&egress).unwrap();
    std::fs::create_dir_all(&portal).unwrap();

    // What a launch leaves when it ends on a signal: the MITM CA and its two sockets, plus the
    // portal's runtime directory. The stats file shares the directory but must survive both passes —
    // it outlives its session as the data `sbx net stats` aggregates.
    let ca = egress.join(format!("ca-{pid}.pem"));
    let proxy = egress.join(format!("proxy-{pid}.sock"));
    let control = egress.join(format!("control-{pid}.sock"));
    let stats = egress.join(format!("stats-{pid}-12345"));
    for f in [&ca, &proxy, &control, &stats] {
        std::fs::write(f, b"x").unwrap();
    }

    // The dry run identifies them and changes nothing.
    let out = fx.sbx(&["gc", "--all"]);
    assert!(
        text(&out).contains("runtime files"),
        "a dry run should report the leftovers:\n{}",
        text(&out)
    );
    for f in [&ca, &proxy, &control, &stats, &portal] {
        assert!(
            f.exists(),
            "a dry run must remove nothing, but {} is gone:\n{}",
            f.display(),
            text(&out)
        );
    }

    // The prune removes exactly the four identified entries — file and directory alike.
    let out = fx.sbx(&["gc", "--all", "--prune"]);
    for f in [&ca, &proxy, &control, &portal] {
        assert!(
            !f.exists(),
            "the prune should have removed {}:\n{}",
            f.display(),
            text(&out)
        );
    }
    assert!(
        stats.exists(),
        "the session's stats outlive it — `sbx net stats` reads them:\n{}",
        text(&out)
    );
}

/// `sbx gc --all` sweeps the **current project first** and collects the **shared store last**.
///
/// The order is load-bearing, not cosmetic. The sweep provisions this project's declared tools in
/// order to re-root them, and that provisioning re-materializes the pinned channel's flake source
/// — a ~300 MiB tree no gc root holds — in the shared store. Collecting the shared store first
/// therefore measured a state the same command went on to invalidate: the sweep put back the source
/// the collection had just taken, so every run left an orphan behind and the next `sbx gc --all`
/// reported the very same reclaimable bytes. It took two passes to converge.
///
/// Pinned on the two passes' own output, since nothing else observes which ran first. Only
/// **stdout** is read: `text()` concatenates stderr after stdout, which would not be chronological,
/// while both of these lines are `println!`s on the one stream.
#[test]
fn the_current_project_sweep_runs_before_the_shared_collection() {
    let fx = Fixture::new();
    let out = fx.sbx(&["gc", "--all"]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    // The sweep's own line, not the shared pass's: both are prefixed `sbx gc`, so key on the
    // sweep-only wording. The cwd is a bare fixture directory, so the sweep finds no store here.
    let Some(sweep) = stdout.find("no per-project store yet") else {
        // The sweep could not run at all (no nix, no sandbox capability): there is no order left to
        // observe. Skip rather than fail — but the shared pass must still have run, which is the
        // robustness half of the same property.
        assert!(
            stdout.contains("shared store") || text(&out).contains("cannot locate"),
            "with the sweep unable to run, the shared pass must still run:\n{}",
            text(&out)
        );
        return;
    };
    let Some(shared) = stdout.find("shared store") else {
        // The mirror of the branch above, for the other pass. The collection needs `nix-store` to
        // read the store database at all and says so when it is absent; with only one of the two
        // passes able to run there is again no order to observe. The run reports this itself, so
        // the skip is keyed on its words rather than on the test probing the host separately.
        if text(&out).contains("nix-store not found") {
            skip_incapable!(
                "skipping the gc pass-ordering check: nix-store is not installed, so the \
                 shared-store collection cannot run"
            );
            return;
        }
        panic!(
            "the shared-store collection should report itself:\n{}",
            text(&out)
        );
    };
    assert!(
        sweep < shared,
        "the sweep must run before the shared collection, else it re-materializes what the \
         collection just took:\n{}",
        text(&out)
    );
}

/// `sbx gc` does not provision in order to discover it has nothing to reclaim.
///
/// The sweep needs a provisioned, re-rooted store to report truthfully — but only when there *is* a
/// store. For a project never launched there is nothing to reclaim, and the check that says so used
/// to run after the preparation that provisions the base userland: on a cold data directory, `sbx
/// gc` downloaded an entire toolchain and then printed "nothing to reclaim".
///
/// Keyed on the base userland's gcroot directory, which provisioning creates and nothing else does.
#[test]
fn gc_provisions_nothing_for_a_project_that_has_no_store() {
    let fx = Fixture::new();
    let out = fx.sbx(&["gc", "--all"]);
    assert!(
        text(&out).contains("no per-project store yet"),
        "a project with no store should report exactly that:\n{}",
        text(&out)
    );
    // Having nothing to reclaim is not an error. Pinned because the check now returns before the
    // preparation runs, so this no longer inherits the exit code of a host that cannot sandbox.
    assert!(
        out.status.success(),
        "nothing to reclaim should exit 0:\n{}",
        text(&out)
    );
    let base_roots = fx.data_home.path().join("sbx/gcroots/base");
    assert!(
        !base_roots.exists(),
        "gc provisioned the base userland ({}) only to report there was nothing to reclaim:\n{}",
        base_roots.display(),
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
