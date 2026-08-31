//! One project under test, and the redirected homes a verb reads around it.
//!
//! Five suites (`app`, `config`, `net`, `path`, `projects`) each drove the host-side verbs the same
//! way: a temporary working directory, the three XDG bases pointed away from the developer's own,
//! and an `sbx` spawned with all four applied. Each carried its own `struct Fixture` for it, and
//! the five had already drifted — one forgot to pin the locale, one built a `Command` where the
//! next built an `Output`, and only one could run a verb from outside the project.
//!
//! The redirection is the point, not a convenience: a suite that misses one of the three bases
//! reads the developer's real global config, trust store or app homes, and then passes or fails on
//! what is installed on that machine.
//!
//! Only the part every suite shares lives here. A suite's own staging — a fabricated project tree,
//! a plugin directory, a mise install — is its own business, and it adds those as further methods
//! on this type: the module is compiled into each test binary rather than linked, so `Project` is
//! a local type there and an inherent `impl` is the natural place for them.

use super::fixture::TmpDir;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

/// A project directory plus the three XDG bases a launch resolves against.
pub struct Project {
    /// The working directory: `.sbx.toml`, `.mise.toml`, and whatever else a test stages.
    pub proj: TmpDir,
    /// `XDG_CONFIG_HOME` — the global `sbx.toml` and the imported app profiles under `sbx/apps/`.
    pub config_home: TmpDir,
    /// `XDG_STATE_HOME` — the trust store.
    pub state_home: TmpDir,
    /// `XDG_DATA_HOME` — per-project runtime trees, app homes, plugins, sessions, gcroots.
    pub data_home: TmpDir,
    /// Created on first call to [`Project::scratch`], since most suites never ask for one.
    scratch: OnceLock<TmpDir>,
}

impl Project {
    /// Four fresh directories, each labelled `tag` so a leftover names the suite that left it.
    pub fn new(tag: &str) -> Self {
        Project {
            proj: TmpDir::new(tag),
            config_home: TmpDir::new(tag),
            state_home: TmpDir::new(tag),
            data_home: TmpDir::new(tag),
            scratch: OnceLock::new(),
        }
    }

    /// An `sbx` invocation from `dir`, with the three homes redirected.
    ///
    /// The locale is pinned rather than inherited. The cage honors the host's locale, so a
    /// provisioned tool's output is translated on a developer machine that is not set to English,
    /// and an assertion on that output then fails for a reason that has nothing to do with sbx.
    /// `C.UTF-8` keeps messages English while staying UTF-8-clean.
    pub fn cmd_in(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
        cmd.args(args)
            .current_dir(dir)
            .env("XDG_CONFIG_HOME", self.config_home.path())
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_DATA_HOME", self.data_home.path())
            .env("LC_ALL", "C.UTF-8")
            .env_remove("LANG");
        cmd
    }

    /// An `sbx` invocation from the project directory.
    pub fn cmd(&self, args: &[&str]) -> Command {
        self.cmd_in(self.proj.path(), args)
    }

    /// Run `sbx <args>` from `dir` to completion.
    ///
    /// The project config lives in `proj`, so running from anywhere else is running with no project
    /// config at all — which is what a user does whenever they launch a global app from outside a
    /// project, and the only way to ask what changes when just the working directory does.
    pub fn run_in(&self, dir: &Path, args: &[&str]) -> Output {
        self.cmd_in(dir, args).output().expect("spawn sbx")
    }

    /// Run `sbx <args>` from the project directory to completion.
    pub fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("spawn sbx")
    }

    /// A directory outside the project, for the trees a test binds or installs *from*.
    ///
    /// Outside on purpose: an install that is meant to copy its source in has to be given a source
    /// the destination does not already contain, or the test proves nothing.
    pub fn scratch(&self) -> &Path {
        self.scratch.get_or_init(|| TmpDir::new("scratch")).path()
    }

    /// Write the global `<config>/sbx/sbx.toml`.
    pub fn write_global(&self, body: &str) {
        let dir = self.config_home.path().join("sbx");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sbx.toml"), body).unwrap();
    }

    /// Read the global config back, or the empty string when nothing has written it — the shape a
    /// test wants when asking what a management verb merged into it.
    pub fn global_config(&self) -> String {
        std::fs::read_to_string(self.config_home.path().join("sbx/sbx.toml")).unwrap_or_default()
    }

    /// Write the project's `.sbx.toml`.
    pub fn write_project(&self, body: &str) {
        std::fs::write(self.proj.path().join(".sbx.toml"), body).unwrap();
    }

    /// Write an imported app profile at [`Project::profile_path`] — the artifact `sbx app import`
    /// produces, trusted by its location beside the global config. A global app exists only as a
    /// profile file; an inline `[app.<name>]` in `sbx.toml` is refused, so every test that needs
    /// one routes through here.
    pub fn write_profile(&self, name: &str, body: &str) {
        let path = self.profile_path(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// Where `sbx app import` places the profile for `name`.
    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.config_home
            .path()
            .join(format!("sbx/apps/{name}.toml"))
    }
}
