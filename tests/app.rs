//! Integration tests for `sbx app show`: the built binary reports one app's realized-on-disk detail
//! — its profile source, home size, and each declared package annotated with whether it is actually
//! installed (a `mise:` tool from the app home, a `deb:` build from a project tree's pins, a `nix:`
//! package built per-project). Read-only: no sandbox, no nix, no network, so a lightweight fixture of
//! fabricated files is enough.

use std::path::{Path, PathBuf};
use std::process::Command;

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut d = std::env::temp_dir();
        d.push(format!("sbx-appshow-{}-{n}", std::process::id()));
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

    /// Fabricate a global app home with a mise tool installed at `<munged>/<version>/`.
    fn install_mise_tool(&self, app: &str, munged: &str, version: &str) {
        let ver = self.data_home.path().join(format!(
            "sbx/apps/{app}/home/.local/share/mise/installs/{munged}/{version}"
        ));
        std::fs::create_dir_all(&ver).unwrap();
        // Some bytes so the home has a non-zero size.
        std::fs::write(ver.join("bin"), vec![b'x'; 2048]).unwrap();
    }

    /// Fabricate a project tree whose `deb-packages.lock` pins `url`.
    fn pin_deb(&self, tree_id: &str, url: &str, hash: &str) {
        let dir = self.data_home.path().join("sbx/projects").join(tree_id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deb-packages.lock"), format!("{url}\t{hash}\n")).unwrap();
    }

    /// Fabricate a warm flake out-link in a global app home — `home/.local/state/ops/flake/<name>`
    /// pointing at a store path — the realized signal for a `flake:` package (which builds into the
    /// home, not the per-project store).
    fn build_flake(&self, app: &str, name: &str, store_leaf: &str) {
        let dir = self
            .data_home
            .path()
            .join(format!("sbx/apps/{app}/home/.local/state/ops/flake"));
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(format!("/nix/store/{store_leaf}"), dir.join(name)).unwrap();
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
    // The nix package is reported as built per-project.
    assert!(
        s.contains("nix:hello") && s.contains("built per-project"),
        "nix per-project status missing:\n{s}"
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
    assert!(by_backend("mise")["installed"]["detail"]
        .as_str()
        .unwrap()
        .contains("1.2.3"));
    assert_eq!(by_backend("deb")["installed"]["state"], "installed");
    assert_eq!(by_backend("nix")["installed"]["state"], "per_project");
    // The one installed tool is declared, so nothing is orphaned.
    assert!(
        v["orphans"].as_array().expect("orphans array").is_empty(),
        "a declared installed tool must not be an orphan: {v}"
    );
}

#[test]
fn show_detects_a_flake_built_into_the_home_even_when_floating() {
    let fx = Fixture::new();
    // A profile whose only package is a flake — built into the home, not the per-project store, and
    // floating (no lock), which a lock scan would miss.
    fx.write_profile(
        "demo-app",
        "cmd = \"demo\"\n\n[packages]\nagent = \"flake:github:foo/bar#default\"\n",
    );
    fx.build_flake(
        "demo-app",
        "agent",
        "abcd1234abcd1234abcd1234abcd1234abcd1234-bar-1.0",
    );

    let out = fx.sbx(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("flake:github:foo/bar#default") && s.contains("built bar-1.0"),
        "a warm flake out-link should read `built <pname-version>`:\n{s}"
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
    assert!(flake["installed"]["detail"]
        .as_str()
        .unwrap()
        .contains("bar-1.0"));
}

#[test]
fn show_lists_installed_tools_no_declaration_accounts_for() {
    let fx = Fixture::new();
    fx.write_profile("demo-app", &demo_profile());
    // The declared tool is installed…
    fx.install_mise_tool("demo-app", "aqua-demo-tool", "1.2.3");
    // …and a second tool sits in the home that the profile does not declare (a leftover or a
    // dependency mise pulled in).
    fx.install_mise_tool("demo-app", "npm-extra-thing", "9.9.9");

    let out = fx.sbx(&["app", "show", "demo-app"]);
    assert!(out.status.success(), "sbx app show failed: {}", text(&out));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("installed (undeclared):"),
        "the undeclared section should appear:\n{s}"
    );
    assert!(
        s.contains("npm-extra-thing") && s.contains("9.9.9"),
        "the undeclared tool + version should be listed:\n{s}"
    );
    // The declared tool stays in the packages section, not repeated as undeclared.
    let undeclared = s.split("installed (undeclared):").nth(1).unwrap_or("");
    assert!(
        !undeclared.contains("aqua-demo-tool"),
        "a declared tool must not appear as undeclared:\n{s}"
    );

    // --json carries the orphan.
    let out = fx.sbx(&["app", "show", "demo-app", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let orphans = v["orphans"].as_array().expect("orphans array");
    assert_eq!(orphans.len(), 1, "one orphan: {v}");
    assert_eq!(orphans[0]["name"], "npm-extra-thing");
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
    // With no home yet, the disk line says so rather than showing a size.
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
