//! Integration tests for `sbx app show`: the built binary reports one app's realized-on-disk detail
//! — its profile source, home size, and each declared package annotated with whether it is actually
//! installed (a `mise:` tool from the app home, a `deb:` build from a project tree's pins, a `nix:`
//! package from the project trees that gcrooted it). Read-only: no sandbox, no nix, no network, so a
//! lightweight fixture of fabricated files is enough.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// Deliberately **not** `std::env::temp_dir()`, which resolves to `/tmp` when `TMPDIR` is unset.
/// These fixtures are small, but the repo's tree is the safe default: a fixture that ends up
/// holding a provisioned nix store is inode-heavy enough to exhaust a tmpfs's machine-wide inode
/// budget, which then surfaces as "no space left on device" in *unrelated* work while the disk is
/// nearly empty. Disk has inodes to spare, and it is reclaimed by removing that tree.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    // Outside the workspace by default, and that is the point rather than an accident: a language
    // server watching the repository spends one inotify watch per directory, one run of this suite
    // leaves hundreds of thousands of them, and the machine's `max_user_watches` is what runs out.
    // Still on disk rather than a tmpfs, whose fixed inode budget a provisioned nix store exhausts.
    // Falls back inside the workspace only when neither variable names a home to use.
    let mut d = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"));
    d.push("sbx/test-tmp");
    d
}

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = fixture_root();
        d.push(format!("app-{}-{n}", std::process::id()));
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

    /// Write an imported profile `<config>/sbx/apps/<name>.toml` (trusted by location).
    fn write_profile(&self, name: &str, body: &str) {
        let dir = self.config_home.path().join("sbx/apps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), body).unwrap();
    }

    /// Where `sbx app import` places a profile.
    fn profile_path(&self, name: &str) -> PathBuf {
        self.config_home
            .path()
            .join(format!("sbx/apps/{name}.toml"))
    }

    /// The global config bundles and groups are merged into, or empty when nothing wrote it.
    fn global_config(&self) -> String {
        std::fs::read_to_string(self.config_home.path().join("sbx/sbx.toml")).unwrap_or_default()
    }

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
    let fx = Fixture::new();
    fx.write_profile("demo-app", &demo_profile());
    // mise:aqua:demo/tool munges to aqua-demo-tool on disk.
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    fx.pin_deb("aaaaaaaaaaaaaaaa", DEB_URL, "sha256-DEADBEEFcafef00d");
    // The `nix:hello` package is keyed on its declared name `core`; gcroot it in the one tree.
    fx.build_nix("aaaaaaaaaaaaaaaa", "core");

    let out = fx.sbx(&["app", "show", "demo-app"]);
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
    // The size breakdown is present.
    assert!(
        s.contains("disk:") && s.contains("tools"),
        "size breakdown missing:\n{s}"
    );
}

#[test]
fn show_json_carries_each_packages_installed_state() {
    let fx = Fixture::new();
    fx.write_profile("demo-app", &demo_profile());
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    fx.pin_deb("bbbbbbbbbbbbbbbb", DEB_URL, "sha256-00112233abcdef");
    fx.build_nix("bbbbbbbbbbbbbbbb", "core");

    let out = fx.sbx(&["app", "show", "demo-app", "--json"]);
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
    let fx = Fixture::new();
    // A profile whose only package is a remote flake. A remote `flake:` builds host-side into the
    // per-project store, gcrooted by its declared name (like `nix:`), not the cage home — so its
    // realized signal is the per-tree gcroot, which `sbx app show` reads via `nix_built_trees`.
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[packages]\nagent = \"flake:github:foo/bar#default\"\n",
    );
    fx.build_nix("aaaaaaaaaaaaaaaa", "agent");

    let out = fx.sbx(&["app", "show", "demo-app"]);
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

    let out = fx.sbx(&["app", "show", "demo-app", "--json"]);
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
    let fx = Fixture::new();
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

    let out = fx.sbx(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("built agent-2.0"),
        "an inline flake's warm out-link should read `built <pname-version>`, not per-project:\n{s}"
    );

    let out = fx.sbx(&["app", "show", "demo-app", "--json"]);
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
    let fx = Fixture::new();
    fx.write_profile("demo-app", &demo_profile());
    // The declared tool is installed…
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    // …and a second tool sits in the home that the profile does not declare (a leftover or a
    // dependency mise pulled in), with its real backend token recorded.
    fx.install_mise_tool("demo-app", "npm-extra-thing", "9.9.9");
    fx.set_tool_token("demo-app", "npm-extra-thing", "npm:extra-thing");

    let out = fx.sbx(&["app", "show", "demo-app"]);
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
    let out = fx.sbx(&["app", "show", "demo-app", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let orphans = v["orphans"].as_array().expect("orphans array");
    assert_eq!(orphans.len(), 1, "one orphan: {v}");
    assert_eq!(orphans[0]["name"], "mise:npm:extra-thing");
}

#[test]
fn show_marks_a_declared_but_unbuilt_package_not_installed() {
    let fx = Fixture::new();
    fx.write_profile("demo-app", &demo_profile());
    // No mise install, no deb pin: the launchable-but-unrealized state.

    let out = fx.sbx(&["app", "show", "demo-app"]);
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
    let fx = Fixture::new();
    fx.write_profile("demo-app", &demo_profile());

    let out = fx.sbx(&["app", "show", "nope"]);
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
    let fx = Fixture::new();
    fx.write_profile("ghost", "[network]\nmode = \"deny\"\n");

    let out = fx.sbx(&["app", "run", "ghost"]);
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
fn fixture_with_a_leftover() -> Fixture {
    let fx = Fixture::new();
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
    let out = fx.sbx(&["app", "prune", "demo-app"]);
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

#[test]
fn prune_yes_removes_the_undeclared_tool_and_its_config_entry_only() {
    let fx = fixture_with_a_leftover();
    let out = fx.sbx(&["app", "prune", "demo-app", "--yes"]);
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
    let fx = Fixture::new();
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[packages]\nkeep = \"mise:aqua:demo/keep\"\n",
    );
    fx.install_mise_tool("demo-app", "aqua-demo-keep", "1.0.0");
    fx.set_tool_token("demo-app", "aqua-demo-keep", "aqua:demo/keep");

    let out = fx.sbx(&["app", "prune", "demo-app"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("no undeclared mise tools"),
        "should report nothing to prune: {}",
        text(&out)
    );
}

/// A profile is not self-contained: it names a bundle, and it may reference an egress group. Both
/// resolve against the global config, and an undeclared one is silent in the way that matters — an
/// absent tool, or dropped egress rules. These four exercise what the import says about it.
#[test]
fn import_names_the_bundle_file_that_sits_beside_the_profile() {
    let fx = Fixture::new();
    let bundle = fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.demo-tool.packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap()]);
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
    let fx = Fixture::new();
    // A file IS at the path the layout implies — it just declares a different bundle. This is the
    // case the content gate exists for: the guess is plausible and running it would change nothing.
    fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.other-tool.packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap()]);
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
    let fx = Fixture::new();
    let group = fx.catalogue(
        "net-groups",
        "demo-lane",
        "[network.groups]\ndemo-lane = [\"api.example.com\"]\n",
    );
    let profile = fx.catalogue(
        "app",
        "demo-app",
        "cmd = \"demo\"\n[network]\nmode = \"deny\"\nallow = [\"@demo-lane\"]\n",
    );

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap()]);
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
        fx.sbx(&["net", "groups", "import", group.to_str().unwrap()])
            .status
            .success()
    );
    let again = fx.sbx(&["app", "import", "--force", profile.to_str().unwrap()]);
    let t = text(&again);
    // Discriminate on the remedy, not on the group's name: the granted posture legitimately prints
    // `allow @demo-lane` on every import, so asserting the name is absent would assert nothing.
    assert!(
        !t.contains("sbx net groups import"),
        "a defined group must not be reported as missing:\n{t}"
    );
}

#[test]
fn bundle_import_reports_the_groups_the_bundle_itself_references() {
    let fx = Fixture::new();
    // The majority case in the shipped catalogue: the group is referenced by the BUNDLE, which an
    // app profile cannot see into — `validate_profile` resolves nothing from disk. If this import
    // stays silent, the reference surfaces only as an app quietly reaching less than it names.
    let group = fx.catalogue(
        "net-groups",
        "demo-lane",
        "[network.groups]\ndemo-lane = [\"api.example.com\"]\n",
    );
    let bundle = fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.demo-tool]\nallow = [\"@demo-lane\"]\n[bundle.demo-tool.packages]\ntool = \"nix:hello\"\n",
    );

    let out = fx.sbx(&["bundle", "import", bundle.to_str().unwrap()]);
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
    let fx = Fixture::new();
    fx.catalogue(
        "net-groups",
        "demo-lane",
        "[network.groups]\ndemo-lane = [\"api.example.com\"]\n",
    );
    fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.demo-tool]\nallow = [\"@demo-lane\"]\n[bundle.demo-tool.packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert!(out.status.success(), "{}", text(&out));
    let t = text(&out);
    let cfg = fx.global_config();
    assert!(
        cfg.contains("[bundle.demo-tool]"),
        "the bundle the profile names should be merged:\n{cfg}"
    );
    // The group is reached THROUGH the bundle — nothing in the profile's own bytes names it. A plan
    // built from the profile alone would write the bundle and leave its reference dead, which is the
    // majority case in the shipped catalogue.
    //
    // Assert the group's ENTRY, not its name: `demo-lane` also appears as the bundle's own `allow`
    // reference, so a test that looked for the name would pass with the group table never written —
    // it would assert that the bundle landed, twice.
    assert!(
        cfg.contains("api.example.com"),
        "the group the bundle references should be defined too, not just referenced:\n{cfg}"
    );
    // The grant belongs to the bytes, not to the verb: this is the one import where the reader did
    // not name the bundle themselves, so a silent credential or egress rule would be least expected.
    assert!(
        t.contains("egress rule(s)"),
        "the grant must still be announced:\n{t}"
    );

    // Nothing is left to ask for afterwards — the warnings and the writes agree on what "missing"
    // means, which they cannot if each side keeps its own filter.
    let again = fx.sbx(&[
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
    let fx = Fixture::new();
    fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.demo-tool.packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");
    let out = fx.sbx(&[
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
        fx.global_config().contains("[bundle.demo-tool]"),
        "the bundle the profile names still lands under its own name:\n{}",
        fx.global_config()
    );
}

#[test]
fn with_deps_writes_nothing_at_all_when_a_reference_has_no_file() {
    let fx = Fixture::new();
    // A file IS at the implied path; it declares a different bundle. The reference cannot be
    // followed, and following the rest would leave the app short of exactly what it names.
    fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.other-tool.packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
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
        fx.global_config().is_empty(),
        "nor may anything have reached the global config"
    );
}

#[test]
fn with_deps_refuses_a_name_that_would_be_dropped_at_load() {
    let fx = Fixture::new();
    // Nothing upstream refuses this: a profile's `use` is not validated against the name charset,
    // and the fragment declares what it declares. Merged as-is, the bundle would be dropped when the
    // config is read and the app would launch short of the tool it names, with nothing said — the
    // silent shortfall this whole path exists to remove.
    fx.catalogue(
        "bundle",
        "bad name!",
        "[bundle.\"bad name!\".packages]\ntool = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"bad name!\"]\n");

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
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
    let fx = Fixture::new();
    fx.catalogue(
        "net-groups",
        "bad name!",
        "[network.groups]\n\"bad name!\" = [\"api.example.com\"]\n",
    );
    let profile = fx.catalogue(
        "app",
        "demo-app",
        "cmd = \"demo\"\n[network]\nmode = \"deny\"\nallow = [\"@bad name!\"]\n",
    );
    let out = fx.sbx(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
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
    let fx = Fixture::new();
    // One file, two bundles. Only the one the profile names may land: a catalogue fragment is not a
    // manifest of what the reader asked for, and writing the rest widens the import past the
    // reference — the very thing that made this opt-in.
    fx.catalogue(
        "bundle",
        "demo-tool",
        "[bundle.demo-tool.packages]\ntool = \"nix:hello\"\n\
         [bundle.demo-spare.packages]\nspare = \"nix:hello\"\n",
    );
    let profile = fx.catalogue("app", "demo-app", "cmd = \"demo\"\nuse = [\"demo-tool\"]\n");

    let out = fx.sbx(&["app", "import", profile.to_str().unwrap(), "--with-deps"]);
    assert!(out.status.success(), "{}", text(&out));
    let cfg = fx.global_config();
    assert!(
        cfg.contains("demo-tool"),
        "the referenced bundle should land:\n{cfg}"
    );
    assert!(
        !cfg.contains("demo-spare"),
        "the rest of the fragment must not:\n{cfg}"
    );
}

#[test]
fn show_without_a_name_is_a_usage_error() {
    let fx = Fixture::new();
    let out = fx.sbx(&["app", "show"]);
    assert_eq!(out.status.code(), Some(2), "bare `app show` should exit 2");
    assert!(
        text(&out).contains("sbx app show <name>"),
        "should print the synopsis:\n{}",
        text(&out)
    );
}
