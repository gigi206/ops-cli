//! Integration tests for the host-side `sbx app` verbs: what they report about an app, and what
//! they remove.
//!
//! `show` reports one app's realized-on-disk detail — its profile source, home size, and each
//! declared package annotated with whether it is actually installed (a `mise:` tool from the app
//! home, a `deb:` build from a project tree's pins, a `nix:` package from the project trees that
//! gcrooted it). `rm --purge` takes the installed homes away again, and must take exactly those:
//! not a second app's, and not the shared per-project store, which belongs to `sbx gc`.
//!
//! None of it launches a cage, so none of it needs a capable host: every fixture is fabricated
//! files under a redirected data dir. Which is what makes the reports and the removals assertable
//! here at all — an e2e that had to provision first could only skip on most machines.

#[macro_use]
mod common;
use common::project::Project;

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

impl Project {
    /// Fabricate a global app home with a mise tool installed at `<munged>/<version>/`.
    fn install_mise_tool(&self, app: &str, munged: &str, version: &str) {
        let ver = self.data_home.path().join(format!(
            "sbx/apps/{app}/home/.local/share/mise/installs/{munged}/{version}"
        ));
        std::fs::create_dir_all(&ver).unwrap();
        // Some bytes so the home has a non-zero size.
        std::fs::write(ver.join("bin"), vec![b'x'; 2048]).unwrap();
    }

    /// The global app home's mise installs dir.
    fn installs_dir(&self, app: &str) -> PathBuf {
        self.data_home
            .path()
            .join(format!("sbx/apps/{app}/home/.local/share/mise/installs"))
    }

    /// Record a tool's real backend token in its `.mise.backend.toml` (what mise writes).
    fn set_tool_token(&self, app: &str, munged: &str, token: &str) {
        let dir = self.installs_dir(app).join(munged);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".mise.backend.toml"),
            format!("short = \"{token}\"\nfull = \"{token}\"\n"),
        )
        .unwrap();
    }

    /// The global app home itself, the directory a cage runs with as `$HOME`.
    fn app_home(&self, app: &str) -> PathBuf {
        self.data_home.path().join(format!("sbx/apps/{app}/home"))
    }

    /// Fabricate a cache entry of a known size under the global app home's `.cache`.
    fn write_cache_entry(&self, app: &str, name: &str, bytes: usize) {
        let dir = self.app_home(app).join(".cache").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob"), vec![b'x'; bytes]).unwrap();
    }

    /// Fabricate a global app's per-project mise pool with a tool installed at `version`. The pool
    /// dir *is* mise's data dir, so `installs/` sits directly under it.
    fn install_pool_tool(&self, app: &str, tree: &str, munged: &str, version: &str) {
        let ver = self.data_home.path().join(format!(
            "sbx/projects/{tree}/apps/{app}/mise/installs/{munged}/{version}"
        ));
        std::fs::create_dir_all(&ver).unwrap();
        std::fs::write(ver.join("bin"), vec![b'x'; 2048]).unwrap();
    }

    /// Write the app home's mise `config.toml` (the `mise use` record).
    fn write_home_mise_config(&self, app: &str, body: &str) {
        let dir = self
            .data_home
            .path()
            .join(format!("sbx/apps/{app}/home/.config/mise"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), body).unwrap();
    }

    /// Fabricate a project tree whose `deb-packages.lock` pins `url`.
    fn pin_deb(&self, tree_id: &str, url: &str, hash: &str) {
        let dir = self.data_home.path().join("sbx/projects").join(tree_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deb-packages.lock"), format!("{url}\t{hash}\n")).unwrap();
    }

    /// Fabricate a warm flake out-link in a global app home — `home/.local/state/sbx/flake/<name>`
    /// pointing at a store path — the realized signal for a `flake:` package (the out-link symlink the
    /// launch leaves in the home; its target store path lives in the per-project store). The path
    /// mirrors the launch's write path (`binds::FLAKE_ROOTS_REL`).
    fn build_flake(&self, app: &str, name: &str, store_leaf: &str) {
        let dir = self
            .data_home
            .path()
            .join(format!("sbx/apps/{app}/home/.local/state/sbx/flake"));
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(format!("/nix/store/{store_leaf}"), dir.join(name)).unwrap();
    }

    /// Write one file of a portable catalogue laid out the way this repository ships its examples:
    /// `app/`, `bundle/` and `net-groups/` as siblings under one root. The import suggestions are
    /// derived from exactly that shape, so a fixture that flattened it would not exercise them.
    fn catalogue(&self, kind: &str, name: &str, body: &str) -> PathBuf {
        let dir = self.proj.path().join("catalogue").join(kind);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, body).unwrap();
        path
    }

    /// Fabricate a `nix:` package gcroot in a project tree — `gcroots/projects/<tree_id>/<name>`, the
    /// per-tree realized signal for a host-provisioned `nix:` package. The gcroot is keyed on the
    /// package's **declared name** (the `[packages]` key), not its nixpkgs attribute.
    fn build_nix(&self, tree_id: &str, name: &str) {
        let dir = self
            .data_home
            .path()
            .join("sbx/gcroots/projects")
            .join(tree_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), "").unwrap();
    }
}

fn text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

const DEB_URL: &str = "https://example.com/demo-app.deb";

/// A profile mixing all three "installed" cases: a `mise:` tool (app-home-scoped), a `deb:` build
/// (per-project, pinned), and a `nix:` package (per-project).
fn demo_profile() -> String {
    format!(
        "cmd = \"demo\"\n\n\
         [packages]\n\
         tool = \"mise:aqua:demo/tool\"\n\
         gui = \"deb:{DEB_URL}\"\n\
         core = \"nix:hello\"\n"
    )
}

#[test]
fn show_reports_declared_vs_installed_across_backends() {
    let fx = Project::new("app");
    fx.write_profile("demo-app", &demo_profile());
    // mise:aqua:demo/tool munges to aqua-demo-tool on disk.
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    fx.pin_deb("aaaaaaaaaaaaaaaa", DEB_URL, "sha256-DEADBEEFcafef00d");
    // The `nix:hello` package is keyed on its declared name `core`; gcroot it in the one tree.
    fx.build_nix("aaaaaaaaaaaaaaaa", "core");

    let out = fx.run(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);

    // The profile source is shown.
    assert!(s.contains("demo-app.toml"), "profile path missing:\n{s}");
    // The mise tool is installed at its concrete version (matched through the munge).
    assert!(
        s.contains("mise:aqua:demo/tool") && s.contains("installed 1.2.3"),
        "mise install status missing:\n{s}"
    );
    // The deb build is pinned in the one project tree, with its short hash.
    assert!(
        s.contains("pinned in 1 tree (DEADBEEF)"),
        "deb pin status missing:\n{s}"
    );
    // The nix package reports the concrete tree it is built in — the per-tree realized signal, not a
    // vague "per-project" deferral.
    assert!(
        s.contains("nix:hello") && s.contains("built in 1 tree"),
        "nix per-tree status missing:\n{s}"
    );
    // The size breakdown is present, and it is the home's own composition rather than a total: a
    // location line, then at least one entry carrying its share of the home.
    assert!(
        s.contains("disk:") && s.contains("global \u{b7} "),
        "size breakdown missing:\n{s}"
    );
    assert!(
        s.lines()
            .any(|l| l.trim_start().starts_with('.') && l.trim_end().ends_with('%')),
        "the home's composition is missing its entries:\n{s}"
    );
}

#[test]
fn show_json_carries_each_packages_installed_state() {
    let fx = Project::new("app");
    fx.write_profile("demo-app", &demo_profile());
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    fx.pin_deb("bbbbbbbbbbbbbbbb", DEB_URL, "sha256-00112233abcdef");
    fx.build_nix("bbbbbbbbbbbbbbbb", "core");

    let out = fx.run(&["app", "show", "demo-app", "--json"]);
    assert!(
        out.status.success(),
        "sbx app show --json failed: {}",
        text(&out)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");

    assert_eq!(v["name"], "demo-app");
    let pkgs = v["packages"].as_array().expect("packages array");
    let by_backend = |backend: &str| {
        pkgs.iter()
            .find(|p| p["backend"] == backend)
            .unwrap_or_else(|| panic!("no {backend} package in {v}"))
    };
    assert_eq!(by_backend("mise")["installed"]["state"], "installed");
    assert!(
        by_backend("mise")["installed"]["detail"]
            .as_str()
            .unwrap()
            .contains("1.2.3")
    );
    assert_eq!(by_backend("deb")["installed"]["state"], "installed");
    assert_eq!(by_backend("nix")["installed"]["state"], "installed");
    assert!(
        by_backend("nix")["installed"]["detail"]
            .as_str()
            .unwrap()
            .contains("built in 1 tree")
    );
    // The one installed tool is declared, so nothing is orphaned.
    assert!(
        v["orphans"].as_array().expect("orphans array").is_empty(),
        "a declared installed tool must not be an orphan: {v}"
    );
}

#[test]
fn show_detects_a_remote_flake_built_into_the_per_project_store() {
    let fx = Project::new("app");
    // A profile whose only package is a remote flake. A remote `flake:` builds host-side into the
    // per-project store, gcrooted by its declared name (like `nix:`), not the cage home — so its
    // realized signal is the per-tree gcroot, which `sbx app show` reads via `nix_built_trees`.
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[packages]\nagent = \"flake:github:foo/bar#default\"\n",
    );
    fx.build_nix("aaaaaaaaaaaaaaaa", "agent");

    let out = fx.run(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("flake:github:foo/bar#default") && s.contains("built in 1 tree"),
        "a store-built remote flake should read `built in <n> tree(s)`:\n{s}"
    );
    assert!(
        !s.contains("not installed"),
        "the flake must not read `not installed`:\n{s}"
    );

    let out = fx.run(&["app", "show", "demo-app", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let flake = v["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["backend"] == "flake")
        .expect("the flake package");
    assert_eq!(flake["installed"]["state"], "installed");
    assert!(
        flake["installed"]["detail"]
            .as_str()
            .unwrap()
            .contains("tree")
    );
}

#[test]
fn show_detects_an_inline_flake_built_into_the_home() {
    let fx = Project::new("app");
    // An inline `[flakes.<name>]` flake builds in-cage into a home out-link exactly like a `flake:`
    // package (keyed `<name>-<hash>`), so its realized signal is that warm out-link — not the vague
    // "per-project" the catch-all would otherwise report.
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[flakes.agent]\nattr = \"default\"\nflake = \"{ outputs = { self }: {}; }\"\n",
    );
    // The launch names an inline flake's out-link `<name>-<hash>`; `flake_built` matches it by the
    // declared name's prefix, so a hash-suffixed link stands in for a real build.
    fx.build_flake(
        "demo-app",
        "agent-0f1e2d3c",
        "abcd1234abcd1234abcd1234abcd1234abcd1234-agent-2.0",
    );

    let out = fx.run(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("built agent-2.0"),
        "an inline flake's warm out-link should read `built <pname-version>`, not per-project:\n{s}"
    );

    let out = fx.run(&["app", "show", "demo-app", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let flake = v["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["backend"] == "flake")
        .expect("the inline flake package");
    // `installed`, not `per-project` — the decisive check that FlakeInline is read via its out-link.
    assert_eq!(flake["installed"]["state"], "installed");
    assert!(
        flake["installed"]["detail"]
            .as_str()
            .unwrap()
            .contains("agent-2.0")
    );
}

#[test]
fn show_lists_installed_tools_no_declaration_accounts_for() {
    let fx = Project::new("app");
    fx.write_profile("demo-app", &demo_profile());
    // The declared tool is installed…
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    // …and a second tool sits in the home that the profile does not declare (a leftover or a
    // dependency mise pulled in), with its real backend token recorded.
    fx.install_mise_tool("demo-app", "npm-extra-thing", "9.9.9");
    fx.set_tool_token("demo-app", "npm-extra-thing", "npm:extra-thing");

    let out = fx.run(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("installed (undeclared):"),
        "the undeclared section should appear:\n{s}"
    );
    // Shown with the `mise:` backend prefix and its real provider token, like the packages section.
    assert!(
        s.contains("mise:npm:extra-thing") && s.contains("9.9.9"),
        "the undeclared tool should read `mise:<token>` with its version:\n{s}"
    );
    // The declared tool stays in the packages section, not repeated as undeclared.
    let undeclared = s.split("installed (undeclared):").nth(1).unwrap_or("");
    assert!(
        !undeclared.contains("aqua:demo/tool"),
        "a declared tool must not appear as undeclared:\n{s}"
    );

    // --json carries the orphan by the same `mise:`-prefixed name.
    let out = fx.run(&["app", "show", "demo-app", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let orphans = v["orphans"].as_array().expect("orphans array");
    assert_eq!(orphans.len(), 1, "one orphan: {v}");
    assert_eq!(orphans[0]["name"], "mise:npm:extra-thing");
}

#[test]
fn show_marks_a_declared_but_unbuilt_package_not_installed() {
    let fx = Project::new("app");
    fx.write_profile("demo-app", &demo_profile());
    // No mise install, no deb pin: the launchable-but-unrealized state.

    let out = fx.run(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("mise:aqua:demo/tool") && s.contains("not installed"),
        "an unbuilt mise tool should read `not installed`:\n{s}"
    );
    // A `nix:` package no tree has gcrooted reads `not installed` too — not a false "built
    // per-project" for a build that never happened.
    let nix_line = s
        .lines()
        .find(|l| l.contains("nix:hello"))
        .unwrap_or_else(|| panic!("no nix:hello line:\n{s}"));
    assert!(
        nix_line.contains("not installed"),
        "an unbuilt nix package should read `not installed`, got: {nix_line}"
    );
    assert!(
        s.contains("not launched yet"),
        "an app with no home should report it:\n{s}"
    );
}

#[test]
fn show_of_an_unknown_app_fails_and_lists_the_declared_ones() {
    let fx = Project::new("app");
    fx.write_profile("demo-app", &demo_profile());

    let out = fx.run(&["app", "show", "nope"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unknown app should fail: {}",
        text(&out)
    );
    let s = text(&out);
    assert!(
        s.contains("no app named"),
        "missing not-found message:\n{s}"
    );
    assert!(
        s.contains("demo-app"),
        "should list the declared apps:\n{s}"
    );
}

/// A profile with no `cmd` is told where a command goes — in the file the profile is actually in.
///
/// `sbx app import` refuses a `cmd`-less profile, but a launch reads the profile *directory*, not
/// the import record, so a file dropped there by hand reaches this refusal. Its remedy therefore has
/// to fit a profile's own shape: the fields sit at the top level, and asking for an `[app.<name>]`
/// table would ask for the very wrapper `validate_profile` tells the author to remove. The check is
/// on the file being named, which is what a reader opens.
#[test]
fn a_profile_with_no_command_is_told_where_the_command_goes() {
    let fx = Project::new("app");
    fx.write_profile("ghost", "[network]\nmode = \"deny\"\n");

    let out = fx.run(&["app", "run", "ghost"]);
    let s = text(&out);
    assert!(
        s.contains("declares no command"),
        "a profile with no cmd must be refused, not launched:\n{s}"
    );
    assert!(
        s.contains("apps/ghost.toml"),
        "the refusal must name the file that carries the profile:\n{s}"
    );
}

/// A demo-app fixture with one declared mise tool installed and one undeclared leftover, plus a home
/// mise config listing both — the shape `sbx app prune` acts on.
fn fixture_with_a_leftover() -> Project {
    let fx = Project::new("app");
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[packages]\nkeep = \"mise:aqua:demo/keep\"\n",
    );
    // The declared tool (aqua:demo/keep munges to aqua-demo-keep) and an undeclared leftover.
    fx.install_mise_tool("demo-app", "aqua-demo-keep", "1.0.0");
    fx.set_tool_token("demo-app", "aqua-demo-keep", "aqua:demo/keep");
    fx.install_mise_tool("demo-app", "pipx-orphan", "0.9.0");
    fx.set_tool_token("demo-app", "pipx-orphan", "pipx:orphan");
    fx.write_home_mise_config(
        "demo-app",
        "[tools]\n\"aqua:demo/keep\" = \"latest\"\n\"pipx:orphan\" = \"latest\"\n",
    );
    fx
}

#[test]
fn prune_previews_the_undeclared_tool_by_provider_and_removes_nothing() {
    let fx = fixture_with_a_leftover();
    let out = fx.run(&["app", "prune", "demo-app"]);
    assert!(out.status.success(), "prune preview failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    // The undeclared tool is named by its real provider token, not the munged dir.
    assert!(
        s.contains("pipx:orphan") && s.contains("would prune"),
        "preview should list the undeclared tool: {s}"
    );
    assert!(
        !s.contains("aqua:demo/keep"),
        "the declared tool must not be pruned: {s}"
    );
    // Nothing was removed by the preview.
    assert!(
        fx.installs_dir("demo-app").join("pipx-orphan").is_dir(),
        "preview must not delete the install"
    );
}

/// A prune deletes trees out of the very home a running session of this app is using: its `PATH`
/// entries and interpreters live in `installs/`, so a build in flight loses its tool mid-command.
/// The applying form is refused while such a session exists; the preview stays safe and stays
/// available.
///
/// Register a live session of `app` in the fixture's registry: a record for *this* process, which
/// is alive, so it survives the liveness pruning the registry does on every read.
fn register_live_session(fx: &Project, app: &str) {
    let sessions = fx.data_home.path().join("sbx/sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let pid = std::process::id();
    let start = start_ticks(pid).expect("this process's start time");
    // The record's `project` is hex-encoded raw bytes, as the registry writes it.
    let project: String = fx
        .proj
        .path()
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::fs::write(
        sessions.join(format!("{pid}-{start}")),
        format!(
            "kind=run\npid={pid}\nstart={start}\nruntime=global-app:{app}\ndetached=false\n\
             project={project}\n"
        ),
    )
    .unwrap();
}

#[test]
fn reset_yes_refuses_while_a_session_of_that_app_is_live() {
    // The most destructive form of the verb answers to the same guard as the narrowest one, and
    // the preview stays available under it because it deletes nothing.
    let fx = fixture_with_a_leftover();
    register_live_session(&fx, "demo-app");

    let out = fx.run(&["app", "prune", "demo-app", "--reset", "--yes"]);
    assert!(
        !out.status.success(),
        "a reset under a live session must refuse: {}",
        text(&out)
    );
    assert!(
        text(&out).contains("live session"),
        "and say why: {}",
        text(&out)
    );
    assert!(
        fx.installs_dir("demo-app").join("pipx-orphan").is_dir(),
        "nothing may be deleted under the running agent"
    );

    let preview = fx.run(&["app", "prune", "demo-app", "--reset"]);
    assert!(
        preview.status.success(),
        "the preview deletes nothing, so a live session has nothing to refuse: {}",
        text(&preview)
    );
}

#[test]
fn reset_empties_every_home_and_pool_and_keeps_the_profile() {
    let fx = Project::new("app");
    let sbx_dir = fx.data_home.path().join("sbx");
    let profile = sbx_dir.join("apps/demo/profile.toml");
    touch_under(&profile);
    touch_under(&sbx_dir.join("apps/demo/home/.config/creds"));
    touch_under(&sbx_dir.join("apps/demo/home/.rustup/toolchain/bin/rustc"));
    // The per-project mise pool a global app self-equips into: part of "everything", or the app
    // comes back equipped in one project and bare in the next.
    touch_under(&sbx_dir.join("projects/testproj/apps/demo/mise/installs/node/22/bin/node"));
    // Another app, which the reset must not reach.
    touch_under(&sbx_dir.join("apps/other/home/.config/creds"));

    let out = fx.run(&["app", "prune", "demo", "--reset", "--yes"]);
    assert!(out.status.success(), "reset failed: {}", text(&out));

    let home = sbx_dir.join("apps/demo/home");
    assert!(home.is_dir(), "the home itself must survive its reset");
    assert_eq!(
        std::fs::read_dir(&home).unwrap().count(),
        0,
        "the home still holds something: {}",
        text(&out)
    );
    assert!(
        !sbx_dir
            .join("projects/testproj/apps/demo/mise/installs/node")
            .exists(),
        "the per-project mise pool survived the reset: {}",
        text(&out)
    );
    assert!(
        profile.exists(),
        "a reset keeps the declaration — removing it is `app rm --purge`"
    );
    assert!(
        sbx_dir.join("apps/other/home/.config/creds").exists(),
        "the reset reached another app"
    );
}

#[test]
fn prune_yes_refuses_while_a_session_of_that_app_is_live() {
    let fx = fixture_with_a_leftover();
    register_live_session(&fx, "demo-app");

    let out = fx.run(&["app", "prune", "demo-app", "--yes"]);
    assert!(
        !out.status.success(),
        "a prune under a live session must refuse: {}",
        text(&out)
    );
    assert!(
        text(&out).contains("live session"),
        "and say why: {}",
        text(&out)
    );
    assert!(
        fx.installs_dir("demo-app").join("pipx-orphan").is_dir(),
        "nothing may be deleted under the running agent"
    );

    // The preview is unaffected: it deletes nothing, so there is nothing to refuse.
    let preview = fx.run(&["app", "prune", "demo-app"]);
    assert!(
        preview.status.success()
            && String::from_utf8_lossy(&preview.stdout).contains("would prune"),
        "the preview must still work: {}",
        text(&preview)
    );
}

#[test]
fn prune_yes_refuses_when_the_session_registry_cannot_be_read() {
    let fx = fixture_with_a_leftover();
    // A plain file where the registry's directory belongs, so `read_dir` answers `ENOTDIR`. That is
    // neither of the two states the scan already absorbs: a missing directory means no sessions,
    // and a single unreadable record is skipped so one bad entry cannot blank the answer. What is
    // left is the guard being unable to know, and the applying form has to refuse rather than read
    // it as an all-clear — the alternative deletes a running agent's interpreters.
    let sessions = fx.data_home.path().join("sbx/sessions");
    std::fs::create_dir_all(sessions.parent().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&sessions);
    std::fs::write(&sessions, b"not a directory").unwrap();

    let out = fx.run(&["app", "prune", "demo-app", "--yes"]);
    assert!(
        !out.status.success(),
        "an unreadable registry must refuse the apply: {}",
        text(&out)
    );
    assert!(
        text(&out).contains("cannot read the session registry"),
        "and say what it could not know: {}",
        text(&out)
    );
    assert!(
        fx.installs_dir("demo-app").join("pipx-orphan").is_dir(),
        "nothing may be deleted while liveness is unknown"
    );

    // `--all` refuses too. Its live-app semantics is skip-and-name, and naming requires knowing
    // which app is live: an unreadable registry cannot answer that for any of them, so sweeping
    // every app is the one reading that would delete the most under a running agent.
    let all = fx.run(&["app", "prune", "--all", "--yes"]);
    assert!(
        !all.status.success(),
        "the sweep must refuse on the same unreadable registry: {}",
        text(&all)
    );

    // The preview is unaffected: it deletes nothing, so it never asks the registry.
    let preview = fx.run(&["app", "prune", "demo-app"]);
    assert!(
        preview.status.success()
            && String::from_utf8_lossy(&preview.stdout).contains("would prune"),
        "the preview must still work: {}",
        text(&preview)
    );
}

/// This process's start time in clock ticks, as the session registry records it — read from
/// `/proc/<pid>/stat`'s 22nd field, past the parenthesised comm which may itself contain spaces.
fn start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[test]
fn prune_yes_removes_the_undeclared_tool_and_its_config_entry_only() {
    let fx = fixture_with_a_leftover();
    let out = fx.run(&["app", "prune", "demo-app", "--yes"]);
    assert!(out.status.success(), "prune --yes failed: {}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("pruned 1"),
        "should report the removal: {}",
        text(&out)
    );
    // The undeclared install is gone; the declared one stays.
    assert!(
        !fx.installs_dir("demo-app").join("pipx-orphan").exists(),
        "the undeclared install should be removed"
    );
    assert!(
        fx.installs_dir("demo-app").join("aqua-demo-keep").is_dir(),
        "the declared install must be kept"
    );
    // The config `[tools]` dropped the undeclared token, kept the declared one.
    let config = std::fs::read_to_string(
        fx.data_home
            .path()
            .join("sbx/apps/demo-app/home/.config/mise/config.toml"),
    )
    .unwrap();
    assert!(
        !config.contains("pipx:orphan"),
        "the undeclared token should be dropped from config:\n{config}"
    );
    assert!(
        config.contains("aqua:demo/keep"),
        "the declared token must remain in config:\n{config}"
    );
}

#[test]
fn prune_reports_nothing_when_all_installed_tools_are_declared() {
    let fx = Project::new("app");
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[packages]\nkeep = \"mise:aqua:demo/keep\"\n",
    );
    fx.install_mise_tool("demo-app", "aqua-demo-keep", "1.0.0");
    fx.set_tool_token("demo-app", "aqua-demo-keep", "aqua:demo/keep");

    let out = fx.run(&["app", "prune", "demo-app"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no undeclared mise tools"),
        "should report nothing to prune: {}",
        text(&out)
    );
}

/// Without `--caches` the cache directory is not in scope at all: the flag is what widens the verb,
/// and a prune that emptied caches by default would delete on a command line that asked for tools.
#[test]
fn prune_leaves_the_caches_alone_unless_asked_for_them() {
    let fx = fixture_with_a_leftover();
    fx.write_cache_entry("demo-app", "mise", 4096);

    let out = fx.run(&["app", "prune", "demo-app", "--yes"]);
    assert!(out.status.success(), "prune --yes failed: {}", text(&out));
    assert!(
        fx.app_home("demo-app").join(".cache/mise/blob").exists(),
        "a prune without --caches must not touch the cache: {}",
        text(&out)
    );
}

/// `--caches` names each cache entry with its size and, previewing, removes none of them. The entry
/// is named rather than summed into a total, so what has to refill is legible before the removal.
#[test]
fn prune_caches_previews_each_entry_and_removes_nothing() {
    let fx = fixture_with_a_leftover();
    fx.write_cache_entry("demo-app", "mise", 4096);
    fx.write_cache_entry("demo-app", "uv", 2048);

    let out = fx.run(&["app", "prune", "demo-app", "--caches"]);
    assert!(out.status.success(), "preview failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains(".cache/mise") && s.contains(".cache/uv"),
        "the preview must name each cache entry: {s}"
    );
    assert!(
        s.contains("2 cache(s)"),
        "the preview must count the caches: {s}"
    );
    assert!(
        fx.app_home("demo-app").join(".cache/mise/blob").exists(),
        "a preview must remove nothing"
    );
}

/// Applied, the caches go and the app stays signed in: login and session state lives under
/// `.config` and `.local/share`, which is what makes emptying `.cache` cost a refetch and nothing
/// else. A declared tool is not a cache and stays installed.
#[test]
fn prune_caches_yes_empties_the_cache_and_keeps_login_state() {
    let fx = fixture_with_a_leftover();
    fx.write_cache_entry("demo-app", "mise", 4096);
    let home = fx.app_home("demo-app");
    std::fs::create_dir_all(home.join(".local/share/demo-app")).unwrap();
    std::fs::write(home.join(".local/share/demo-app/session"), b"signed-in").unwrap();

    let out = fx.run(&["app", "prune", "demo-app", "--caches", "--yes"]);
    assert!(out.status.success(), "prune failed: {}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cache(s)"),
        "the applied line must account for the caches: {}",
        text(&out)
    );
    assert!(
        !home.join(".cache/mise").exists(),
        "the cache entry must be gone"
    );
    assert!(
        home.join(".local/share/demo-app/session").exists(),
        "login state must survive a cache prune"
    );
    assert!(
        fx.installs_dir("demo-app").join("aqua-demo-keep").is_dir(),
        "a declared tool is not a cache and stays installed"
    );
}

/// `--all` stands instead of a name and covers every app that has an installed home, so the sweep
/// reaches an app the command line never mentions. Each line is attributed, since a report over
/// several apps that does not name them cannot be acted on.
#[test]
fn prune_all_sweeps_every_app_that_has_a_home() {
    let fx = fixture_with_a_leftover();
    fx.write_cache_entry("demo-app", "mise", 4096);
    fx.write_cache_entry("other-app", "npm", 2048);

    let out = fx.run(&["app", "prune", "--all", "--caches"]);
    assert!(out.status.success(), "sweep failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("demo-app") && s.contains("other-app"),
        "each app's lines must be attributed to it: {s}"
    );
    assert!(
        s.contains("and 2 cache(s)"),
        "the sweep totals both apps' caches in one line: {s}"
    );
}

/// A sweep must not stop at the first app it may not touch: an app whose session is live is skipped
/// and named, the rest are still pruned, and the run exits non-zero so a script sees that the sweep
/// was not complete. Refusing outright, as the named form does, would let one running agent stand
/// between the user and every other app's caches.
#[test]
fn prune_all_skips_a_live_app_names_it_and_still_sweeps_the_rest() {
    let fx = fixture_with_a_leftover();
    fx.write_cache_entry("demo-app", "mise", 4096);
    fx.write_cache_entry("other-app", "npm", 2048);
    register_live_session(&fx, "demo-app");

    let out = fx.run(&["app", "prune", "--all", "--caches", "--yes"]);

    assert_eq!(
        out.status.code(),
        Some(1),
        "an incomplete sweep must exit non-zero: {}",
        text(&out)
    );
    assert!(
        text(&out).contains("demo-app") && text(&out).contains("live session"),
        "the skipped app must be named, with the reason: {}",
        text(&out)
    );
    assert!(
        fx.app_home("demo-app").join(".cache/mise/blob").exists(),
        "the live app's cache must be left alone"
    );
    assert!(
        !fx.app_home("other-app").join(".cache/npm").exists(),
        "every other app is still swept: {}",
        text(&out)
    );
}

/// Every verb that prints a size prints one counted from `st_blocks`, which is the data held and
/// not the space a removal returns. A figure read without that is a plan against a number that will
/// not materialise, so each surface that shows one has to carry the caveat: this pins the two that
/// report an app's footprint, alongside the prune total and the `sbx projects` footer.
#[test]
fn the_size_reporting_verbs_say_the_figure_is_data_not_reclaimed_space() {
    let fx = fixture_with_a_leftover();
    fx.write_cache_entry("demo-app", "mise", 4096);

    for args in [
        vec!["app", "list"],
        vec!["app", "show", "demo-app"],
        vec!["app", "prune", "demo-app", "--caches"],
    ] {
        let out = fx.run(&args);
        assert!(out.status.success(), "{args:?} failed: {}", text(&out));
        let s = String::from_utf8_lossy(&out.stdout);
        assert!(
            s.contains("sbx storage status"),
            "{args:?} prints sizes without saying what they mean:\n{s}"
        );
    }

    // Not in the JSON: a consumer reads `bytes` and compares them, and a sentence in a document is
    // something it would have to skip rather than something it can act on.
    let json = fx.run(&["app", "list", "--json"]);
    assert!(json.status.success(), "{}", text(&json));
    assert!(
        !String::from_utf8_lossy(&json.stdout).contains("storage status"),
        "the caveat is prose for a reader, not a field for a script"
    );
}

/// A global app's install pool is per project, so a version it equipped there stays behind when the
/// app's own activation record moves on: the tool is still declared and still current, and an older
/// copy of it sits in a pool nothing reaches. `--stale` is the only thing that reaches it, since
/// plain `prune` asks whether the *tool* is declared and this one is.
#[test]
fn prune_stale_drops_a_pool_version_no_activation_asks_for() {
    let fx = fixture_with_a_leftover();
    // The app's record names 2.0.0; its pool in a project still holds 1.0.0 from an earlier launch.
    fx.write_home_mise_config("demo-app", "[tools]\n\"aqua:demo/keep\" = \"2.0.0\"\n");
    fx.install_pool_tool("demo-app", "testproj", "aqua-demo-keep", "1.0.0");
    let pool = fx
        .data_home
        .path()
        .join("sbx/projects/testproj/apps/demo-app/mise/installs/aqua-demo-keep/1.0.0");
    // The tree has to name a project that exists, or the pool is skipped: what that project's mise
    // file asks for is part of the answer, and it cannot be read once the directory is gone.
    let marker = fx.data_home.path().join("sbx/projects/testproj/project");
    std::fs::write(&marker, fx.proj.path().as_os_str().as_bytes()).unwrap();

    let preview = fx.run(&["app", "prune", "demo-app", "--stale"]);
    assert!(preview.status.success(), "{}", text(&preview));
    let s = String::from_utf8_lossy(&preview.stdout);
    assert!(
        s.contains("1.0.0") && s.contains("stale version"),
        "the preview must name the version and why:\n{s}"
    );
    assert!(pool.exists(), "a preview removes nothing");

    let applied = fx.run(&["app", "prune", "demo-app", "--stale", "--yes"]);
    assert!(applied.status.success(), "{}", text(&applied));
    assert!(
        !pool.exists(),
        "the applied run removes it: {}",
        text(&applied)
    );
    assert!(
        fx.installs_dir("demo-app").join("aqua-demo-keep").is_dir(),
        "the app's own current install is untouched"
    );
}

/// Without `--stale` the pool version is not in scope: the flag is what widens the verb, and a
/// `prune` that dropped versions by default would delete on a line that asked about tools.
#[test]
fn prune_leaves_a_stale_pool_version_alone_unless_asked() {
    let fx = fixture_with_a_leftover();
    fx.write_home_mise_config("demo-app", "[tools]\n\"aqua:demo/keep\" = \"2.0.0\"\n");
    fx.install_pool_tool("demo-app", "testproj", "aqua-demo-keep", "1.0.0");
    let marker = fx.data_home.path().join("sbx/projects/testproj/project");
    std::fs::write(&marker, fx.proj.path().as_os_str().as_bytes()).unwrap();

    let out = fx.run(&["app", "prune", "demo-app", "--yes"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        fx.data_home
            .path()
            .join("sbx/projects/testproj/apps/demo-app/mise/installs/aqua-demo-keep/1.0.0")
            .exists(),
        "a prune without --stale must not touch a pool version: {}",
        text(&out)
    );
}

/// The two selectors are alternatives, and a line carrying both leaves it unsaid which governs —
/// so it is refused rather than resolved by a precedence nobody can see on the command line.
#[test]
fn prune_refuses_a_name_and_all_together() {
    let fx = fixture_with_a_leftover();
    let out = fx.run(&["app", "prune", "demo-app", "--all"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("not both"),
        "the refusal must say why: {}",
        text(&out)
    );
}

/// A profile is not self-contained: it names a bundle, and it may reference an egress group. Both
/// resolve against the global config, and an undeclared one is silent in the way that matters — an
/// absent tool, or dropped egress rules. These four exercise what the import says about it.
#[test]
fn import_names_the_bundle_file_that_sits_beside_the_profile() {
    let fx = Project::new("app");
    let bundle = fx.catalogue("bundle", "demo-tool", "[packages]\ntool = \"nix:hello\"\n");
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.run(&["app", "import", profile.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    // The command as the reader must type it, with the file — not a `<file>` placeholder they then
    // have to go find. Assert the whole command, so a path that lost its directory still fails.
    assert!(
        t.contains(&format!("sbx bundle import {}", bundle.display())),
        "the remedy should name the sibling bundle file:\n{t}"
    );
}

#[test]
fn import_keeps_the_placeholder_when_no_file_backs_the_reference() {
    let fx = Project::new("app");
    // A file IS at the path the layout implies — it is just not a bundle. This is the case the
    // content gate exists for: the guess is plausible, and the import it would suggest fails. A
    // bundle carries no `cmd`, so an app profile filed under `bundle/` is refused.
    fx.catalogue(
        "bundle",
        "demo-tool",
        "cmd = \"demo\"\n[packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.run(&["app", "import", profile.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    assert!(
        t.contains("sbx bundle import <file>"),
        "an unbacked guess must fall back to the placeholder:\n{t}"
    );
    assert!(
        !t.contains("bundle/demo-tool.toml"),
        "the file that does not declare it must not be named:\n{t}"
    );
}

#[test]
fn import_reports_an_egress_group_the_profile_references_and_nothing_defines() {
    let fx = Project::new("app");
    let group = fx.catalogue(
        "net-groups",
        "demo-lane",
        "entries = [\"api.example.com\"]\n",
    );
    let profile = fx.catalogue(
        "app",
        "demo-app",
        "cmd = \"demo\"\n[network]\nmode = \"deny\"\nallow = [\"@demo-lane\"]\n",
    );

    let out = fx.run(&["app", "import", profile.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    assert!(
        t.contains("@demo-lane")
            && t.contains(&format!("sbx net groups import {}", group.display())),
        "an undefined group must be named with the file that defines it:\n{t}"
    );

    // Control: once the group is defined, the same import says nothing about it. Without this the
    // test above would pass on a warning printed unconditionally.
    assert!(
        fx.run(&["net", "groups", "import", group.to_str().unwrap()])
            .status
            .success()
    );
    let again = fx.run(&["app", "import", "--force", profile.to_str().unwrap()]);
    let t = text(&again);
    // Discriminate on the remedy, not on the group's name: the granted posture legitimately prints
    // `allow @demo-lane` on every import, so asserting the name is absent would assert nothing.
    assert!(
        !t.contains("sbx net groups import"),
        "a defined group must not be reported as missing:\n{t}"
    );
}

/// A `--force` import keeps the bytes it is about to drop, and refuses the whole import when it
/// cannot. That held for a copy it could not *write* and not for one it could not *read*: the
/// unreadable case fell into the arm meaning "there is nothing to keep", so the file was
/// overwritten with no copy and nothing said — which is the one outcome the copy exists to prevent.
#[test]
fn a_forced_import_refuses_when_the_profile_it_would_replace_cannot_be_read() {
    let fx = Project::new("app");
    let dest = fx.profile_path("demo-app");
    std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
    // Present and unreadable, for every uid: a read of a directory is `EISDIR`, where a mode of
    // `0o000` is simply ignored for root and would make this test a no-op there.
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("marker"), b"still here").unwrap();

    // Named so the import targets the very profile staged above (the stem is the app name).
    let source = fx.proj.path().join("demo-app.toml");
    std::fs::write(&source, "cmd = \"new\"\n").unwrap();

    let out = fx.run(&["app", "import", "--force", source.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a profile that cannot be read must refuse the import: {}",
        text(&out)
    );
    assert!(
        text(&out).contains("nothing was overwritten"),
        "and say what was left alone: {}",
        text(&out)
    );
    assert!(
        dest.join("marker").exists(),
        "what was there must be exactly as it was"
    );
}

#[test]
fn bundle_import_reports_the_groups_the_bundle_itself_references() {
    let fx = Project::new("app");
    // The majority case in the shipped catalogue: the group is referenced by the BUNDLE, which an
    // app profile cannot see into — `validate_profile` resolves nothing from disk. If this import
    // stays silent, the reference surfaces only as an app quietly reaching less than it names.
    let group = fx.catalogue(
        "net-groups",
        "demo-lane",
        "entries = [\"api.example.com\"]\n",
    );
    let bundle = fx.catalogue(
        "bundle",
        "demo-tool",
        "allow = [\"@demo-lane\"]\n[packages]\ntool = \"nix:hello\"\n",
    );

    let out = fx.run(&["bundle", "import", bundle.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    assert!(
        t.contains("@demo-lane")
            && t.contains(&format!("sbx net groups import {}", group.display())),
        "the bundle's own group reference must be reported at its import:\n{t}"
    );
}

/// `--with-deps` is the opt-in half of the same finding: instead of naming what is missing, the
/// import follows the reference and merges it. It writes into the file the user maintains by hand,
/// which is why it is a flag and not the default.
#[test]
fn with_deps_imports_the_bundle_and_the_group_it_reaches_through_it() {
    let fx = Project::new("app");
    fx.catalogue(
        "net-groups",
        "demo-lane",
        "entries = [\"api.example.com\"]\n",
    );
    fx.catalogue(
        "bundle",
        "demo-tool",
        "allow = [\"@demo-lane\"]\n[packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.run(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    let bundle = std::fs::read_to_string(fx.bundle_path("demo-tool")).unwrap_or_default();
    assert!(
        bundle.contains("nix:hello"),
        "the bundle the profile names should be filed under bundles/:\n{bundle}"
    );
    // The group is reached THROUGH the bundle — nothing in the profile's own bytes names it. A plan
    // built from the profile alone would write the bundle and leave its reference dead, which is the
    // majority case in the shipped catalogue.
    //
    // Assert the group's ENTRY, not its name: `demo-lane` also appears as the bundle's own `allow`
    // reference, and now as a file name besides, so a test that looked for the name would pass with
    // the group's own file never written.
    let group = std::fs::read_to_string(fx.group_path("demo-lane")).unwrap_or_default();
    assert!(
        group.contains("api.example.com"),
        "the group the bundle references should be defined too, not just referenced:\n{group}"
    );
    // The grant belongs to the bytes, not to the verb: this is the one import where the reader did
    // not name the bundle themselves, so a silent credential or egress rule would be least expected.
    assert!(
        t.contains("egress rule(s)"),
        "the grant must still be announced:\n{t}"
    );

    // Nothing is left to ask for afterwards — the warnings and the writes agree on what "missing"
    // means, which they cannot if each side keeps its own filter.
    let again = fx.run(&[
        "app",
        "import",
        "--force",
        "--with-deps",
        profile.to_str().unwrap(),
    ]);
    let t = text(&again);
    assert!(
        !t.contains("sbx bundle import") && !t.contains("sbx net groups import"),
        "a second import has nothing left to report:\n{t}"
    );

    // Renaming the app does not rename what it references: the plan follows `use` and the source
    // path, never the name the profile is being filed under. Two names in play, only one of which
    // the references answer to.
    let fx = Project::new("app");
    fx.catalogue("bundle", "demo-tool", "[packages]\ntool = \"nix:hello\"\n");
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");
    let out = fx.run(&[
        "app",
        "import",
        profile.to_str().unwrap(),
        "--as",
        "renamed",
        "--with-deps",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(fx.profile_path("renamed").exists(), "{}", text(&out));
    assert!(
        fx.bundle_path("demo-tool").exists(),
        "the bundle the profile names still lands under its own name:\n{}",
        fx.global_config()
    );
}

#[test]
fn with_deps_writes_nothing_at_all_when_a_reference_has_no_file() {
    let fx = Project::new("app");
    // A file IS at the implied path; it is not a bundle (it carries a `cmd`). The reference cannot
    // be followed, and following the rest would leave the app short of exactly what it names.
    fx.catalogue(
        "bundle",
        "demo-tool",
        "cmd = \"demo\"\n[packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.run(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unfollowable reference must refuse:\n{}",
        text(&out)
    );
    // The assertion that separates all-or-nothing from a half-implementation: the refusal lands
    // before the profile does, so the user is left exactly where they were.
    assert!(
        !fx.profile_path("demo-app").exists(),
        "the profile must not have been written:\n{}",
        text(&out)
    );
    assert!(
        fx.global_config().is_empty() && !fx.bundle_path("demo-tool").exists(),
        "nor may anything have reached the global config or the bundles directory"
    );
}

#[test]
fn with_deps_refuses_a_name_that_would_be_dropped_at_load() {
    let fx = Project::new("app");
    // Nothing upstream refuses this: a profile's `use` is not validated against the name charset,
    // and the fragment declares what it declares. Merged as-is, the bundle would be dropped when the
    // config is read and the app would launch short of the tool it names, with nothing said — the
    // silent shortfall this whole path exists to remove.
    fx.catalogue("bundle", "bad name!", "[packages]\ntool = \"nix:hello\"\n");
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"bad name!\"]\n");

    let out = fx.run(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unusable name must refuse:\n{}",
        text(&out)
    );
    assert!(
        text(&out).contains("invalid bundle name"),
        "and must name why:\n{}",
        text(&out)
    );
    assert!(
        !fx.profile_path("demo-app").exists(),
        "the refusal lands before the profile does"
    );

    // The same rule on the other name source, which is a separate check over a separate loop: a
    // group name comes from an `@<name>` entry, not from `use`. Deleting one guard leaves the other
    // one's tests green, so both are pinned here.
    let fx = Project::new("app");
    fx.catalogue(
        "net-groups",
        "bad name!",
        "entries = [\"api.example.com\"]\n",
    );
    let profile = fx.catalogue(
        "app",
        "demo-app",
        "cmd = \"demo\"\n[network]\nmode = \"deny\"\nallow = [\"@bad name!\"]\n",
    );
    let out = fx.run(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unusable group name must refuse too:\n{}",
        text(&out)
    );
    assert!(
        text(&out).contains("invalid group name"),
        "and must name why:\n{}",
        text(&out)
    );
    assert!(
        !fx.profile_path("demo-app").exists(),
        "the refusal lands before the profile does"
    );
}

#[test]
fn with_deps_merges_only_the_referenced_name_from_a_fragment() {
    let fx = Project::new("app");
    // Two bundles sit in the catalogue; only the one the profile names may land. A catalogue is not
    // a manifest of what the reader asked for, and writing the rest widens the import past the
    // reference, the very thing that made this opt-in.
    fx.catalogue("bundle", "demo-tool", "[packages]\ntool = \"nix:hello\"\n");
    fx.catalogue(
        "bundle",
        "demo-spare",
        "[packages]\nspare = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.run(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        fx.bundle_path("demo-tool").exists(),
        "the referenced bundle should land:\n{}",
        text(&out)
    );
    assert!(
        !fx.bundle_path("demo-spare").exists(),
        "the rest of the catalogue must not:\n{}",
        text(&out)
    );
}

#[test]
fn show_without_a_name_is_a_usage_error() {
    let fx = Project::new("app");
    let out = fx.run(&["app", "show"]);
    assert_eq!(out.status.code(), Some(2), "bare `app show` should exit 2");
    assert!(
        text(&out).contains("sbx app show <name>"),
        "should print the synopsis:\n{}",
        text(&out)
    );
}

// --- `sbx app rm --purge`: the host-side removal of an app's installed homes.
//
// These moved here from `tests/run.rs`, which is the launch suite: they neither launch nor need
// a capable host, they stand up fabricated app homes on disk and ask what the management verb
// does with them. On the way they picked up the shared harness, so they now run from an empty
// project directory rather than from wherever cargo was invoked.

/// Materialize a non-empty file at `path`, creating parents. A helper for the app-purge e2es, which
/// stand up fake app homes on disk (the purge is host-side filesystem work — no sandbox needed).
fn touch_under(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"x").unwrap();
}

#[test]
fn sbx_app_rm_purge_removes_the_installed_homes_and_lists_them() {
    let fx = Project::new("app");
    let sbx_dir = fx.data_home.path().join("sbx");
    // The target app 'claude': a global home (with a sibling etc) and one per-project home.
    touch_under(&sbx_dir.join("apps/claude/home/state"));
    touch_under(&sbx_dir.join("apps/claude/etc/passwd"));
    touch_under(&sbx_dir.join("projects/testproj/apps/claude/home/state"));
    // A different app and unrelated project state that must all survive the purge.
    touch_under(&sbx_dir.join("apps/codex/home/state"));
    touch_under(&sbx_dir.join("projects/testproj/store/nix/keepme"));

    // `sbx app list` shows one row per app with its installed home, so a user can see what there is
    // to purge. The unified table carries the `HOME` column header and a row for each installed app.
    let listed = fx.run(&["app", "list"]);
    assert!(listed.status.success(), "app list failed: {listed:?}");
    let list_out = String::from_utf8_lossy(&listed.stdout);
    assert!(
        list_out.contains("HOME") && list_out.contains("claude") && list_out.contains("codex"),
        "app list did not report the installed homes:\n{list_out}"
    );

    // Purge 'claude': profile absent (fine), both homes removed, everything else intact.
    let purged = fx.run(&["app", "rm", "claude", "--purge"]);
    assert!(purged.status.success(), "purge failed: {purged:?}");
    let purge_out = String::from_utf8_lossy(&purged.stdout);
    assert!(
        purge_out.contains("purged"),
        "no purge summary:\n{purge_out}"
    );
    assert!(
        !sbx_dir.join("apps/claude").exists(),
        "global home survived"
    );
    assert!(
        !sbx_dir.join("projects/testproj/apps/claude").exists(),
        "per-project home survived"
    );
    assert!(
        sbx_dir.join("apps/codex/home/state").exists(),
        "codex was collateral"
    );
    assert!(
        sbx_dir.join("projects/testproj/store/nix/keepme").exists(),
        "the shared per-project store was touched — purge must leave it to `sbx gc`"
    );

    // A second purge finds nothing and says so (a typo/no-op must not report success).
    let again = fx.run(&["app", "rm", "claude", "--purge"]);
    assert!(!again.status.success(), "a no-op purge reported success");
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("nothing to purge"),
        "no-op purge did not explain itself: {again:?}"
    );
}

#[test]
fn sbx_app_rm_purges_several_apps_in_one_call() {
    let fx = Project::new("app");
    let sbx_dir = fx.data_home.path().join("sbx");
    // Two target apps, one with a global home and one with a per-project home, plus a third that
    // is not named and must survive.
    touch_under(&sbx_dir.join("apps/agent-one/home/state"));
    touch_under(&sbx_dir.join("projects/testproj/apps/agent-two/home/state"));
    touch_under(&sbx_dir.join("apps/agent-three/home/state"));

    // Three names with an absent one in the middle: each app is purged on its own, so the failing
    // name is reported without stopping the one after it, and the call exits non-zero.
    let out = fx.run(&[
        "app",
        "rm",
        "agent-one",
        "absent-app",
        "agent-two",
        "--purge",
    ]);
    assert!(
        !out.status.success(),
        "an app with nothing to purge must colour the exit code: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("nothing to purge for 'absent-app'"),
        "the failing name is not the one reported: {out:?}"
    );
    assert!(
        !sbx_dir.join("apps/agent-one").exists(),
        "the app named before the failing one was not purged"
    );
    assert!(
        !sbx_dir.join("projects/testproj/apps/agent-two").exists(),
        "the failing name stopped the batch — the name after it was skipped"
    );
    assert!(
        sbx_dir.join("apps/agent-three/home/state").exists(),
        "an app that was not named was collateral"
    );
    // Each purged app reports its own summary…
    assert_eq!(
        stdout.matches("purged app").count(),
        2,
        "one summary line per purged app expected:\n{stdout}"
    );
    // …while the closing store note is batch-level: the store it points at is shared by every app
    // in the project, so one call prints it once however many apps it purged.
    assert_eq!(
        stdout.matches("nix:/flake: tool closures").count(),
        1,
        "the shared-store note must be printed once per call:\n{stdout}"
    );
}

#[test]
fn sbx_app_rm_counts_a_repeated_name_once() {
    let fx = Project::new("app");
    let sbx_dir = fx.data_home.path().join("sbx");
    touch_under(&sbx_dir.join("apps/agent-one/home/state"));

    // The same app named twice is one removal: a second pass would find nothing left and report a
    // phantom "nothing to purge" over work that in fact succeeded.
    let out = fx.run(&["app", "rm", "agent-one", "agent-one", "--purge"]);
    assert!(
        out.status.success(),
        "a repeated name reported a failure: {out:?}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("nothing to purge"),
        "the repeat was purged twice: {out:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout)
            .matches("purged app")
            .count(),
        1,
        "the repeat produced a second summary line: {out:?}"
    );
    assert!(
        !sbx_dir.join("apps/agent-one").exists(),
        "the home survived the purge"
    );
}

#[test]
fn sbx_app_rm_gc_is_skipped_when_the_call_purged_nothing() {
    // Nothing on disk for any name: the sweep has no reclamation to make, so it must not run —
    // which is also what keeps this test free of nix and of a capable host.
    let fx = Project::new("app");
    let out = fx.run(&["app", "rm", "absent-app", "--purge", "--gc"]);
    assert!(
        !out.status.success(),
        "a call that purged nothing must not report success: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("swept this project's store"),
        "the sweep ran for a call that purged nothing:\n{stdout}"
    );
    assert!(
        !stdout.contains("nix:/flake: tool closures"),
        "a store note was printed with no purge to point it at:\n{stdout}"
    );
}

#[test]
fn sbx_app_rm_gc_requires_purge() {
    // `--gc` sweeps the store a purged home referenced, so it is meaningless without `--purge`.
    // This errors before any work, so it needs no capable host and no data setup.
    let fx = Project::new("app");
    let out = fx.run(&["app", "rm", "agent", "--gc"]);
    assert!(
        !out.status.success(),
        "`--gc` without `--purge` should be a usage error"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "usage error should exit 2: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("requires `--purge`"),
        "the error should explain the --gc/--purge relationship: {out:?}"
    );
}

#[test]
fn sbx_app_rm_purge_refuses_while_a_session_is_live() {
    let fx = Project::new("app");
    let sbx_dir = fx.data_home.path().join("sbx");
    touch_under(&sbx_dir.join("apps/agent/home/state"));

    // A real live process to anchor a session record: the guard is decided by a start-time match
    // against /proc, so a fabricated record must name a genuinely-running pid.
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    let start_ticks = common::start_ticks(pid);

    // A session record tagging that live pid as `sbx app agent` (runtime `global-app:agent`); the
    // record format is the module's `key=value` text, project hex-encoded (`/x` = 2f78).
    let sessions = sbx_dir.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::write(
        sessions.join(format!("{pid}-{start_ticks}")),
        format!(
            "kind=run\npid={pid}\nstart={start_ticks}\nruntime=global-app:agent\nproject=2f78\n"
        ),
    )
    .unwrap();

    let out = fx.run(&["app", "rm", "agent", "--purge"]);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !out.status.success(),
        "purge did not refuse a live app: {out:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("running session"),
        "refusal did not name the live session: {err}"
    );
    // Nothing was removed — the home is still there for a retry after the session stops.
    assert!(
        sbx_dir.join("apps/agent/home/state").exists(),
        "purge removed the home despite the live session"
    );
}

/// `sbx app export --out` wrote with a straight `fs::write`, while the two other exporters that
/// compose a config file (`bundle export --out`, `net groups export --out`) go through the writer
/// that lands a temporary beside the destination and renames. A straight write truncates first, so
/// an interrupted export leaves a fragment at a path whose whole purpose is to be imported back;
/// and it follows a symlink at the destination, so `--out` into a directory the cage can write
/// turns into a write through somebody else's name.
#[test]
fn app_export_does_not_write_through_a_symlink_at_its_destination() {
    let fx = Project::new("app");
    fx.write_profile("demo-app", &demo_profile());

    let victim = fx.proj.path().join("victim.toml");
    std::fs::write(&victim, b"original\n").unwrap();
    let out_path = fx.proj.path().join("export.toml");
    std::os::unix::fs::symlink(&victim, &out_path).unwrap();

    let out = fx.run(&[
        "app",
        "export",
        "demo-app",
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert!(
        std::fs::read_to_string(&victim).unwrap() == "original\n",
        "the link's target was written through: {}",
        text(&out)
    );

    // Witness: an ordinary destination still receives the profile, and it reads back as one.
    let plain = fx.proj.path().join("plain.toml");
    let out = fx.run(&[
        "app",
        "export",
        "demo-app",
        "--out",
        plain.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "sbx app export failed: {}",
        text(&out)
    );
    let written = std::fs::read_to_string(&plain).unwrap();
    assert!(written.contains("cmd = \"demo\""), "{written}");
}
