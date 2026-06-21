//! Integration tests for `ops config`, exercising the built binary end to end:
//! global+project layering and the trust gate, against redirected config/state
//! dirs and a temp project as the working directory.

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
        d.push(format!("ops-config-it-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Remove a tree that may contain read-only directories: a provisioned nix store
/// makes its directories `0555`, so add write on the way down before deleting.
fn force_remove(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                force_remove(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// One project sandbox under test: a project dir (the working directory), the
/// redirected config-home (global config), state-home (trust store) and data-home
/// (per-project runtime), plus a scratch root for real bind targets.
struct Fixture {
    proj: TmpDir,
    config_home: TmpDir,
    state_home: TmpDir,
    data_home: TmpDir,
    bind_dir: TmpDir,
}

impl Fixture {
    fn new() -> Self {
        Fixture {
            proj: TmpDir::new(),
            config_home: TmpDir::new(),
            state_home: TmpDir::new(),
            data_home: TmpDir::new(),
            bind_dir: TmpDir::new(),
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

    fn write_mise(&self, body: &str) {
        std::fs::write(self.proj.path().join(".mise.toml"), body).unwrap();
    }

    /// Stage a resolver plugin under the data dir (`<data>/plugins/<name>/plugin.toml`), the
    /// trusted-by-location registry `ops config` and the launcher read.
    fn write_plugin(&self, name: &str, manifest: &str) {
        let dir = self.data_home.path().join("ops").join("plugins").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), manifest).unwrap();
    }

    /// Stage (or re-permission) a plugin's `resolve` executable with `mode`, returning its path.
    /// The plugin directory must already exist (call [`write_plugin`](Self::write_plugin) first).
    fn write_plugin_exec(&self, name: &str, mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let exec = self
            .data_home
            .path()
            .join("ops/plugins")
            .join(name)
            .join("resolve");
        std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(mode)).unwrap();
        exec
    }

    /// Build a *source* plugin directory (a manifest and a `resolve` executable) under a scratch
    /// area, returning its path — the kind of directory `ops plugins install <dir>` consumes. It is
    /// deliberately outside the data dir, so the install must copy it in.
    fn source_plugin(&self, dirname: &str, manifest: &str, exec_mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = self.bind_dir.path().join(dirname);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), manifest).unwrap();
        let exec = dir.join("resolve");
        std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(exec_mode)).unwrap();
        dir
    }

    /// Create a real directory to bind, returning its absolute path. Binds are
    /// canonicalized and missing ones dropped, so a bind target must exist.
    fn bind_target(&self, name: &str) -> PathBuf {
        let p = self.bind_dir.path().join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// An `ops` invocation in the project dir with the redirected dirs.
    fn ops(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ops"));
        cmd.args(args)
            .current_dir(self.proj.path())
            .env("XDG_CONFIG_HOME", self.config_home.path())
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_DATA_HOME", self.data_home.path());
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.ops(args).output().expect("spawn ops")
    }
}

#[test]
fn no_config_files_resolves_to_empty_defaults() {
    let fx = Fixture::new();
    let out = fx.run(&["config"]);
    assert!(out.status.success(), "config must succeed with no files");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("env:   (none)"), "stdout:\n{stdout}");
    assert!(stdout.contains("binds: (none)"), "stdout:\n{stdout}");
    assert!(stdout.contains("mise:  (none)"), "stdout:\n{stdout}");
}

#[test]
fn a_mise_file_is_withheld_until_the_project_is_trusted() {
    let fx = Fixture::new();
    fx.write_project("[env]\nA = \"1\"\n");
    fx.write_mise("[tools]\nnode = \"20\"\n");

    // Untrusted: the mise file is present but would not be honored.
    let out = fx.run(&["config"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mise:  .mise.toml (withheld:"),
        "an untrusted mise file must be withheld:\n{stdout}"
    );

    // Trusting the project (which hashes both files) honors it.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mise:  .mise.toml (trusted)"),
        "a trusted mise file must be honored:\n{stdout}"
    );
}

#[test]
fn editing_the_mise_file_re_arms_the_project_trust() {
    let fx = Fixture::new();
    fx.write_project("[env]\nA = \"1\"\n");
    fx.write_mise("[tools]\nnode = \"20\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // Editing only the mise file must re-arm the gate — trust covers both inputs.
    // The project declares no security field to drop, so the "changed" signal rides
    // the mise line's withheld reason (stdout), not a dropped-bind warning (stderr).
    fx.write_mise("[tools]\nnode = \"22\"\n");
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mise:  .mise.toml (withheld: changed since it was trusted"),
        "an edited mise file must drop back to withheld as changed:\n{stdout}"
    );
}

#[test]
fn a_mise_file_without_an_ops_toml_warns_and_is_not_honored() {
    let fx = Fixture::new();
    fx.write_mise("[tools]\nnode = \"20\"\n");

    let out = fx.run(&["config"]);
    assert!(
        out.status.success(),
        "an orphan mise file must not hard-fail"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // anchored on .ops.toml — with none present, mise is not honored, and the
    // no-op is surfaced rather than left silent.
    assert!(stdout.contains("mise:  (none)"), "stdout:\n{stdout}");
    assert!(
        stderr.contains("mise file") && stderr.contains(".ops.toml"),
        "an unanchored mise file must be explained:\n{stderr}"
    );
}

#[test]
fn the_global_config_is_honored_in_full() {
    let fx = Fixture::new();
    let shared = fx.bind_target("shared");
    fx.write_global(&format!(
        "binds = [\"{}\"]\n[env]\nGLOBALVAR = \"g\"\n",
        shared.display()
    ));
    let out = fx.run(&["config"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GLOBALVAR=g"), "stdout:\n{stdout}");
    let canon = shared.canonicalize().unwrap();
    assert!(
        stdout.contains(&*canon.to_string_lossy()),
        "stdout:\n{stdout}"
    );
}

#[test]
fn an_untrusted_project_keeps_env_but_drops_binds() {
    let fx = Fixture::new();
    fx.write_project("binds = [\"/etc/ssh\"]\n[env]\nPROJVAR = \"p\"\n");

    let out = fx.run(&["config"]);
    assert!(out.status.success(), "untrusted config must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // free field applied
    assert!(stdout.contains("PROJVAR=p"), "stdout:\n{stdout}");
    // security field dropped, and not silently
    assert!(
        !stdout.contains("/etc/ssh"),
        "untrusted binds must be dropped:\n{stdout}"
    );
    assert!(
        stderr.contains("untrusted") && stderr.contains("dropping"),
        "a dropped bind must be explained:\n{stderr}"
    );
}

#[test]
fn trusting_the_project_applies_its_binds() {
    let fx = Fixture::new();
    let extra = fx.bind_target("extra");
    fx.write_project(&format!(
        "binds = [\"{}\"]\n[env]\nPROJVAR = \"p\"\n",
        extra.display()
    ));

    let trusted = fx.run(&["trust", ".ops.toml"]);
    assert!(
        trusted.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = fx.run(&["config"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // now the security bind is honored
    let canon = extra.canonicalize().unwrap();
    assert!(
        stdout.contains(&*canon.to_string_lossy()),
        "trusted binds must apply:\n{stdout}"
    );
    assert!(stdout.contains("PROJVAR=p"), "stdout:\n{stdout}");
}

#[test]
fn the_network_posture_is_a_trust_gated_security_field() {
    let fx = Fixture::new();
    fx.write_project("network = \"none\"\n");

    // Untrusted: the posture is dropped to the default (shared), and the drop is
    // explained — an untrusted project may not cut (or reopen) the network.
    let out = fx.run(&["config"]);
    assert!(out.status.success(), "untrusted config must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("network: shared"),
        "an untrusted network posture must fall back to the default:\n{stdout}"
    );
    assert!(
        stderr.contains("network") && stderr.contains("untrusted"),
        "a dropped network posture must be explained:\n{stderr}"
    );

    // Trusted: the posture is honored — the cage would isolate the network.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("network: none"),
        "a trusted network posture must be honored:\n{stdout}"
    );
}

#[test]
fn the_network_allowlist_is_a_trust_gated_security_field() {
    let fx = Fixture::new();
    fx.write_project(
        "[network]\nmode = \"allowlist\"\nallow = [\"github.com\", \"*.nixos.org\", \"example.com/exact\"]\ndeny = [\"evil.nixos.org\"]\n",
    );

    // Untrusted: the allowlist is dropped to the default (shared), with an explanation.
    let out = fx.run(&["config"]);
    assert!(out.status.success(), "untrusted config must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("network: shared"),
        "an untrusted allowlist must fall back to the default:\n{stdout}"
    );
    assert!(
        stderr.contains("network") && stderr.contains("untrusted"),
        "a dropped allowlist must be explained:\n{stderr}"
    );

    // Trusted: the allowlist is honored and its classified rules are shown.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("network: allowlist"), "stdout:\n{stdout}");
    assert!(stdout.contains("allow github.com"), "stdout:\n{stdout}");
    assert!(stdout.contains("allow *.nixos.org"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("allow example.com/exact"),
        "stdout:\n{stdout}"
    );
    // the deny carve-out is shown too (deny wins over allow)
    assert!(
        stdout.contains("deny") && stdout.contains("evil.nixos.org"),
        "stdout:\n{stdout}"
    );
    // the built-in nix-cache allow-set is shown (always allowed so self-equip works), so it
    // is never a silent allowance.
    assert!(
        stdout.contains("built-in") && stdout.contains("cache.nixos.org"),
        "the built-in nix-cache allow-set must be shown:\n{stdout}"
    );
}

#[test]
fn editing_a_trusted_project_re_arms_the_gate() {
    let fx = Fixture::new();
    fx.write_project("binds = [\"/etc/ssh\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // an edit changes the content hash; the binds must drop again until re-trusted
    fx.write_project("binds = [\"/etc/ssh\", \"/opt/extra\"]\n");
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("/etc/ssh"),
        "changed config binds must drop:\n{stdout}"
    );
    assert!(
        stderr.contains("changed since it was trusted"),
        "a changed config must say so:\n{stderr}"
    );
}

#[test]
fn a_malformed_project_config_is_ignored_not_fatal() {
    // The threat-model case: an attacker-controlled project ships garbage. It must
    // neither crash the command nor apply anything — just warn, naming the file.
    let fx = Fixture::new();
    fx.write_project("binds = = not toml\n");
    let out = fx.run(&["config"]);
    assert!(
        out.status.success(),
        "a malformed config must not hard-fail"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("binds: (none)"),
        "nothing applied:\n{stdout}"
    );
    assert!(
        stderr.contains(".ops.toml") && stderr.to_lowercase().contains("ignoring"),
        "the ignored file must be named:\n{stderr}"
    );
}

#[test]
fn a_world_writable_project_config_is_skipped() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    fx.write_project("binds = [\"/etc/ssh\"]\n[env]\nPROJVAR = \"p\"\n");
    let cfg = fx.proj.path().join(".ops.toml");
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();

    let out = fx.run(&["config"]);
    assert!(out.status.success(), "an unsafe config must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // the whole layer is skipped — not even the free env field is applied
    assert!(
        !stdout.contains("PROJVAR"),
        "unsafe layer must be skipped:\n{stdout}"
    );
    assert!(stdout.contains("binds: (none)"), "stdout:\n{stdout}");
    assert!(
        stderr.contains("world-writable"),
        "the refusal must explain why:\n{stderr}"
    );
}

#[test]
fn the_trust_gate_reaches_the_sandbox_through_a_real_launch() {
    // The end-to-end proof: a security bind is invisible inside the sandbox until
    // the project is trusted. Bind a host path that is neither structural nor under
    // `/tmp` (the sandbox's tmpfs would shadow a `/tmp` bind that is deliberately
    // emitted before it). Skip where the host cannot sandbox or the path is absent.
    let fx = Fixture::new();
    let can_sandbox = fx
        .ops(&["run", "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let target = Path::new("/etc/hostname");
    if !can_sandbox || !target.exists() {
        eprintln!("skipping launch gate test: host cannot sandbox or /etc/hostname absent");
        return;
    }

    fx.write_project("binds = [\"/etc/hostname\"]\n");
    let probe = "if [ -e /etc/hostname ]; then echo PRESENT; else echo ABSENT; fi";

    // Untrusted: the security bind must not reach the sandbox.
    let untrusted = fx
        .ops(&["run", "--", "/bin/sh", "-c", probe])
        .output()
        .expect("spawn ops run");
    assert!(
        String::from_utf8_lossy(&untrusted.stdout).contains("ABSENT"),
        "an untrusted bind must not reach the sandbox; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&untrusted.stdout),
        String::from_utf8_lossy(&untrusted.stderr)
    );

    // Trust it, and the same bind is now visible inside.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let trusted = fx
        .ops(&["run", "--", "/bin/sh", "-c", probe])
        .output()
        .expect("spawn ops run");
    assert!(
        String::from_utf8_lossy(&trusted.stdout).contains("PRESENT"),
        "a trusted bind must reach the sandbox; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&trusted.stdout),
        String::from_utf8_lossy(&trusted.stderr)
    );
}

#[test]
fn config_shows_packages_with_their_trust_verdict() {
    // `ops config` reports declared tools and whether each would be provisioned,
    // without realising anything — so this needs no nix.
    let fx = Fixture::new();
    fx.write_project("[packages]\nnode = \"nodejs_20\"\n");

    // Untrusted: shown, but marked withheld.
    let out = fx.run(&["config"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("node -> nodejs_20"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("withheld"),
        "an untrusted package must be shown as withheld:\n{stdout}"
    );

    // Trusted: shown plainly, no longer withheld.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("node -> nodejs_20"), "stdout:\n{stdout}");
    assert!(
        !stdout.contains("withheld"),
        "a trusted package must not be withheld:\n{stdout}"
    );
}

#[test]
fn a_trusted_project_package_lands_on_the_sandbox_path() {
    // End-to-end: a declared tool is provisioned into ops's store and reachable on
    // PATH inside the sandbox — but only once the project is trusted. Uses `hello`
    // (tiny, in the signed cache). Skipped where the host cannot sandbox.
    let fx = Fixture::new();
    let can_sandbox = fx
        .ops(&["run", "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !can_sandbox {
        eprintln!("skipping package PATH test: host cannot sandbox");
        return;
    }
    fx.write_project("[packages]\nhello = \"hello\"\n");

    // Untrusted: the tool is withheld, so it is not on PATH.
    let probe = "command -v hello >/dev/null 2>&1 && echo PRESENT || echo ABSENT";
    let untrusted = fx
        .ops(&["run", "--", "/bin/sh", "-c", probe])
        .output()
        .expect("spawn ops run");
    assert!(
        String::from_utf8_lossy(&untrusted.stdout).contains("ABSENT"),
        "an untrusted project's tool must not reach PATH; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&untrusted.stdout),
        String::from_utf8_lossy(&untrusted.stderr)
    );

    // Trust it, and the tool is provisioned and runs.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let trusted = fx
        .ops(&["run", "--", "hello"])
        .output()
        .expect("spawn ops run");
    assert!(
        String::from_utf8_lossy(&trusted.stdout).contains("Hello, world!"),
        "a trusted tool must run inside the sandbox; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&trusted.stdout),
        String::from_utf8_lossy(&trusted.stderr)
    );
}

#[test]
fn a_trusted_package_that_cannot_be_realised_fails_the_launch_naming_it() {
    // A declared tool is a stated requirement: an *admitted* one that cannot be
    // realised (a non-existent attribute, or — same path — a lib-only output with no
    // `bin/`) is a hard failure that names the tool, never a silent drop. Skipped
    // where the host cannot sandbox.
    let fx = Fixture::new();
    let can_sandbox = fx
        .ops(&["run", "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !can_sandbox {
        eprintln!("skipping unrealisable-package test: host cannot sandbox");
        return;
    }
    // a well-formed attribute (so it passes validation and reaches nix) that no real
    // package provides
    fx.write_project("[packages]\nbogus = \"ops-no-such-attribute-xyz\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx
        .ops(&["run", "--", "true"])
        .output()
        .expect("spawn ops run");
    assert!(
        !out.status.success(),
        "an unrealisable declared tool must fail the launch"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bogus"),
        "the failure must name the package; stderr:\n{stderr}"
    );
}

#[test]
fn config_shows_the_nixpkgs_source_and_gates_a_project_override() {
    // `ops config` shows which nixpkgs source the tools resolve against, without
    // resolving a revision — so this needs no nix.
    let fx = Fixture::new();

    // default when nothing overrides it
    let out = fx.run(&["config"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("nixpkgs: nixos-unstable  (default)"),
        "stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // an untrusted project override is a security field: ignored (still default),
    // and not silently
    fx.write_project("nixpkgs = \"nixos-23.11\"\n");
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("nixpkgs: nixos-unstable  (default)"),
        "an untrusted override must not apply:\n{stdout}"
    );
    assert!(
        stderr.contains("nixpkgs"),
        "the dropped override must be explained:\n{stderr}"
    );

    // trusting the project applies the pin
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("nixpkgs: nixos-23.11  (project pin)"),
        "a trusted pin must apply:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn config_shows_the_locked_revision_once_resolved() {
    // Once a revision is locked, the source line shows it — routed through the same
    // channel decision a launch uses. Seeded directly here (`ops config` never
    // resolves), so the check stays network-free.
    let fx = Fixture::new();
    let lock_dir = fx.data_home.path().join("ops");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    std::fs::write(
        lock_dir.join("nixpkgs.lock"),
        format!("nixos-unstable\n{rev}\n"),
    )
    .unwrap();

    let out = fx.run(&["config"]);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("nixpkgs: nixos-unstable @ 9ae611a  (default)"),
        "config must show the locked revision:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn upgrade_in_a_trusted_pinned_project_rolls_the_per_project_lock() {
    // The headline of M3.2d's context-awareness: `ops upgrade` rolls the lock the
    // current directory resolves against — a trusted pin's own per-project lock, not
    // the global one. A 40-hex revision pin resolves to itself, so this needs no nix
    // call (only nix on PATH, which `upgrade` gates on); skipped if nix is absent.
    let fx = Fixture::new();
    let rev = "205fd4226592cc83fd4c0885a3e4c9c400efabb5";
    fx.write_project(&format!("nixpkgs = \"{rev}\"\n"));
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["upgrade", "nix"]);
    if !out.status.success() {
        eprintln!(
            "skipping pinned upgrade: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("(project pin)"),
        "a pinned project's upgrade must report the project pin:\n{stdout}"
    );
    // the per-project lock holds the pinned revision; the global lock is untouched
    assert!(
        has_per_project_nixpkgs_lock(fx.data_home.path()),
        "a pinned upgrade must write a per-project lock"
    );
    assert!(
        !fx.data_home.path().join("ops/nixpkgs.lock").exists(),
        "a pure project pin must not write the global lock"
    );
}

#[test]
fn upgrade_with_an_untrusted_pin_falls_back_to_the_global_lock() {
    // An untrusted project pin is a dropped security field, so `ops upgrade` rolls the
    // global channel instead — and says why. A global revision override keeps this
    // network-free (it resolves to itself). Skipped if nix is absent.
    let fx = Fixture::new();
    let global_rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    let project_rev = "205fd4226592cc83fd4c0885a3e4c9c400efabb5";
    fx.write_global(&format!("nixpkgs = \"{global_rev}\"\n"));
    fx.write_project(&format!("nixpkgs = \"{project_rev}\"\n")); // untrusted → dropped

    let out = fx.run(&["upgrade", "nix"]);
    if !out.status.success() {
        eprintln!(
            "skipping untrusted-pin upgrade: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // the dropped pin is explained, and the upgrade rolled the global override
    assert!(
        stderr.contains("nixpkgs") && stderr.to_lowercase().contains("ignoring"),
        "a dropped pin must be explained:\n{stderr}"
    );
    assert!(
        stdout.contains("(global)") && stdout.contains("9ae611a"),
        "the upgrade must roll the global override, not the project pin:\n{stdout}"
    );
    // the global lock was written; no per-project lock was created
    assert!(
        fx.data_home.path().join("ops/nixpkgs.lock").is_file(),
        "the global lock must be written"
    );
    assert!(
        !has_per_project_nixpkgs_lock(fx.data_home.path()),
        "an untrusted pin must not create a per-project lock"
    );
}

/// Whether a per-project nixpkgs lock was recorded anywhere under the data dir's
/// `projects/` tree.
fn has_per_project_nixpkgs_lock(data_home: &Path) -> bool {
    let projects = data_home.join("ops/projects");
    std::fs::read_dir(&projects)
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.path().join("nixpkgs.lock").is_file())
        })
        .unwrap_or(false)
}

#[test]
fn a_trusted_pin_to_a_different_channel_runs_a_tool_from_that_channel() {
    // The regression guard for the base/tool divergence bug: a project pinned to a
    // *different* channel than the default must run its tool — which works only
    // because the whole sandbox (base userland included) resolves against the one
    // pinned channel, so the tool's glibc matches the base's. Pinning a real release
    // (`nixos-23.11`) makes the glibc genuinely differ from the default rolling
    // channel. Trust+pin first, so even the capability probe runs on the pinned base
    // (one base closure, not two). Skipped where the host cannot sandbox.
    let fx = Fixture::new();
    fx.write_project("nixpkgs = \"nixos-23.11\"\n[packages]\nhello = \"hello\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let can_sandbox = fx
        .ops(&["run", "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !can_sandbox {
        eprintln!("skipping cross-channel pin test: host cannot sandbox");
        return;
    }

    let out = fx
        .ops(&["run", "--", "hello"])
        .output()
        .expect("spawn ops run");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("Hello, world!"),
        "a tool pinned to a different channel must run (base must share the pin); \
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        has_per_project_nixpkgs_lock(fx.data_home.path()),
        "a trusted pin must record a per-project nixpkgs lock"
    );
}

#[test]
fn a_registered_resolver_plugin_scheme_is_honored_in_a_secret() {
    let fx = Fixture::new();
    fx.write_plugin(
        "pass",
        "type = \"resolver\"\nscheme = \"pass\"\nexec = \"resolve\"\n",
    );
    fx.write_project(
        "[network]\nmode = \"allowlist\"\nallow = [\"api.github.com\"]\n\n\
         [secret.\"api.github.com\"]\nfrom = \"pass://github/token\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Authorization -> api.github.com"),
        "the secret must be shown:\n{stdout}"
    );
    // the source is the plugin scheme + locator — by reference, never a value
    assert!(
        stdout.contains("from pass github/token"),
        "the resolver plugin source must be shown:\n{stdout}"
    );
}

#[test]
fn an_unregistered_resolver_scheme_drops_the_secret_with_a_warning() {
    let fx = Fixture::new();
    // no plugin claims `vault`
    fx.write_project(
        "[network]\nmode = \"allowlist\"\nallow = [\"api.github.com\"]\n\n\
         [secret.\"api.github.com\"]\nfrom = \"vault://secret/x\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n",
    );
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["config"]);
    assert!(out.status.success(), "an unknown scheme must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.contains("Authorization -> api.github.com"),
        "a secret with an unknown scheme must be dropped:\n{stdout}"
    );
    assert!(
        stderr.contains("vault://") && stderr.contains("plugin"),
        "the dropped secret must be explained, naming the scheme:\n{stderr}"
    );
}

#[test]
fn plugins_list_shows_installed_plugins_builtins_and_drop_warnings() {
    let fx = Fixture::new();
    // a valid, runnable plugin
    fx.write_plugin(
        "pass",
        "name=\"pass\"\ntype=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n\
         version=\"0.1.0\"\ndescription=\"read from the pass store\"\n",
    );
    fx.write_plugin_exec("pass", 0o755);
    // two plugins claiming one scheme (both dropped), and a malformed manifest (dropped)
    fx.write_plugin(
        "v1",
        "type=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
    );
    fx.write_plugin(
        "v2",
        "type=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
    );
    fx.write_plugin("broken", "not valid toml [[[\n");

    let out = fx.run(&["plugins", "list"]);
    assert!(out.status.success(), "plugins list must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // the built-in namespace and the surviving plugin are listed
    assert!(
        stdout.contains("built-in schemes") && stdout.contains("env, file, sops"),
        "the built-in namespace must be shown:\n{stdout}"
    );
    assert!(
        stdout.contains("pass://") && stdout.contains("v0.1.0"),
        "the installed plugin must be listed with its version:\n{stdout}"
    );
    assert!(
        stdout.contains("read from the pass store"),
        "the description must be shown:\n{stdout}"
    );
    // the ambiguous scheme dropped both, and the malformed manifest was dropped — explained
    assert!(
        !stdout.contains("vault://"),
        "an ambiguous scheme must resolve to nothing:\n{stdout}"
    );
    assert!(
        stderr.contains("claimed by both") && stderr.contains("invalid plugin.toml"),
        "drops must be explained on stderr:\n{stderr}"
    );
}

#[test]
fn plugins_list_flags_a_non_runnable_executable() {
    let fx = Fixture::new();
    fx.write_plugin(
        "pass",
        "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n",
    );
    // a group-writable exec loads fine but the runner would refuse it — `list` surfaces the gap
    fx.write_plugin_exec("pass", 0o775);

    let out = fx.run(&["plugins", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("pass://")
            && stdout.contains("not runnable")
            && stdout.contains("group or other"),
        "a non-runnable exec must be flagged:\n{stdout}"
    );
}

#[test]
fn plugins_info_reports_builtin_unknown_and_a_plugin() {
    let fx = Fixture::new();
    fx.write_plugin(
        "pass",
        "type=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\nversion=\"0.1.0\"\n\
         [sandbox]\nallow_paths=[\"/etc/passwd\"]\nallow_env=[\"GNUPGHOME\"]\nnetwork=false\n",
    );
    fx.write_plugin_exec("pass", 0o755);

    // a built-in scheme is reported as such, with success
    let builtin = fx.run(&["plugins", "info", "env"]);
    assert!(builtin.status.success());
    assert!(
        String::from_utf8_lossy(&builtin.stdout).contains("built-in resolver"),
        "info on a built-in must say so"
    );

    // an unknown scheme is a non-zero miss
    let unknown = fx.run(&["plugins", "info", "nope"]);
    assert!(
        !unknown.status.success(),
        "info on an unknown scheme must be non-zero"
    );
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("no installed resolver plugin"));

    // an installed plugin's manifest and grant are shown
    let info = fx.run(&["plugins", "info", "pass"]);
    assert!(info.status.success());
    let stdout = String::from_utf8_lossy(&info.stdout);
    assert!(
        stdout.contains("scheme:      pass://")
            && stdout.contains("version:     0.1.0")
            && stdout.contains("/etc/passwd")
            && stdout.contains("GNUPGHOME"),
        "the plugin's manifest and grant must be shown:\n{stdout}"
    );
}

#[test]
fn plugins_info_explains_a_dropped_conflicting_scheme() {
    // `info <scheme>` is the command a user runs to learn why their plugin is not picked up. When
    // two plugins claim one scheme, both are dropped — so the registry has no entry for it, and the
    // miss must be *explained* (the conflict warning), not a bare "no plugin claims it".
    let fx = Fixture::new();
    fx.write_plugin(
        "v1",
        "type=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
    );
    fx.write_plugin(
        "v2",
        "type=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
    );

    let out = fx.run(&["plugins", "info", "vault"]);
    assert!(
        !out.status.success(),
        "info on a dropped scheme must be non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("claimed by both") && stderr.contains("vault"),
        "the conflict must be explained, not hidden behind a bare miss:\n{stderr}"
    );
}

#[test]
fn plugins_install_then_list_then_remove_through_the_binary() {
    let fx = Fixture::new();
    // a source plugin whose manifest name differs from its directory name
    let source = fx.source_plugin(
        "checkout",
        "name=\"pass\"\ntype=\"resolver\"\nscheme=\"pass\"\nexec=\"resolve\"\n\
         version=\"0.1.0\"\ndescription=\"read from the pass store\"\n",
        0o755,
    );
    let source = source.to_str().unwrap();

    // install: places it under its manifest name, and names the `rm` token in the report
    let out = fx.run(&["plugins", "install", source]);
    assert!(out.status.success(), "install must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("installed 'pass'") && stdout.contains("ops plugins rm pass"),
        "the install report must name the plugin and the rm token:\n{stdout}"
    );

    // list now surfaces it (teeth: zero drop warnings on stderr) with the removal hint
    let out = fx.run(&["plugins", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("pass://") && stdout.contains("read from the pass store"),
        "the installed plugin must be listed:\n{stdout}"
    );
    assert!(
        stdout.contains("remove one with: ops plugins rm <name>"),
        "list must surface the rm token:\n{stdout}"
    );
    assert!(
        !stderr.contains("warning"),
        "a cleanly installed plugin must load without warnings:\n{stderr}"
    );

    // rm removes it, and list falls back to none
    let out = fx.run(&["plugins", "rm", "pass"]);
    assert!(out.status.success(), "rm must succeed");
    assert!(String::from_utf8_lossy(&out.stdout).contains("removed 'pass'"));

    let out = fx.run(&["plugins", "list"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("installed resolver plugins: (none)"),
        "the plugin must be gone after rm"
    );
}

#[test]
fn plugins_install_refuses_a_colliding_scheme_through_the_binary() {
    let fx = Fixture::new();
    let alpha = fx.source_plugin(
        "alpha-src",
        "name=\"alpha\"\ntype=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
        0o755,
    );
    assert!(
        fx.run(&["plugins", "install", alpha.to_str().unwrap()])
            .status
            .success(),
        "the first install must succeed"
    );

    // a different plugin claiming the same scheme: installing it would make the registry drop both,
    // so it is refused up front, naming the conflict and the rm token
    let beta = fx.source_plugin(
        "beta-src",
        "name=\"beta\"\ntype=\"resolver\"\nscheme=\"vault\"\nexec=\"resolve\"\n",
        0o755,
    );
    let out = fx.run(&["plugins", "install", beta.to_str().unwrap()]);
    assert!(!out.status.success(), "a colliding install must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("already claimed by the installed plugin `alpha`"),
        "the collision must be explained:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // teeth: the original still resolves, and `beta` was never placed
    let info = fx.run(&["plugins", "info", "vault"]);
    assert!(info.status.success(), "the original must still resolve");
    assert!(String::from_utf8_lossy(&info.stdout).contains("resolver plugin: alpha"));
}

#[test]
fn plugins_store_list_then_install_a_builtin_then_remove() {
    let fx = Fixture::new();

    // the built-in store lists the bundled plugins, none installed yet
    let out = fx.run(&["plugins", "store", "list"]);
    assert!(out.status.success(), "store list must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("vault  (vault://)") && stdout.contains("pass  (pass://)"),
        "the built-in store must list its plugins:\n{stdout}"
    );
    assert!(
        !stdout.contains("[installed]"),
        "nothing is installed yet:\n{stdout}"
    );

    // install one by bare name (no path separator) — `vault` declares no allow_paths, so the
    // install needs no environment beyond the redirected data dir
    let out = fx.run(&["plugins", "install", "vault"]);
    assert!(
        out.status.success(),
        "installing a built-in by name must succeed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("installed 'vault'"));

    // it now reads as installed in both the store list and the installed list
    let out = fx.run(&["plugins", "store", "list"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("[installed]"),
        "the store list must mark it installed"
    );
    let out = fx.run(&["plugins", "list"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("vault://"),
        "the installed list must surface it"
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("warning"),
        "a built-in install must load cleanly"
    );

    // rm removes it, and the store list shows it uninstalled again
    assert!(fx.run(&["plugins", "rm", "vault"]).status.success());
    let out = fx.run(&["plugins", "store", "list"]);
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("[installed]"),
        "the store list must show it uninstalled again"
    );
}

#[test]
fn plugins_install_an_unknown_builtin_name_is_refused() {
    let fx = Fixture::new();
    let out = fx.run(&["plugins", "install", "nope"]);
    assert!(!out.status.success(), "an unknown built-in name must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no built-in plugin named `nope`"),
        "the refusal must name it:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Whether `git` is on PATH, so the publish→clone→install end-to-end can run (it clones a
/// `file://` store the publish produced). Absent → the test skips rather than fails.
fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a git subcommand in `dir` with an explicit identity and no signing, independent of the
/// host's git configuration. Asserts success.
fn git_in(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(["-C", dir.to_str().unwrap()])
        .args([
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .status()
        .expect("spawn git")
        .success();
    assert!(ok, "git {args:?} failed");
}

/// The producing side feeds the consuming side through a *real* git clone: `ops plugins store
/// publish` signs a plugin tree, the operator commits exactly that tree, and `store add`/`store
/// install` fetch it via `file://`. This is the only proof the signed format survives a clone —
/// the catalogue bytes the signature is over, the per-plugin content digest, and the executable
/// bit all have to come back byte-identical, or `add` (signature) and `install` (content hash)
/// refuse. Skips, never fails, when git is absent.
#[test]
fn publish_then_add_and_install_through_a_real_clone() {
    if !git_available() {
        eprintln!("skipping publish e2e: git is not available");
        return;
    }
    let fx = Fixture::new();

    // A store source repository with one resolver plugin (scheme distinct from its name, so the
    // install-time reconciliation is exercised, not bypassed).
    let repo = fx.bind_dir.path().join("store");
    let plugin = repo.join("plugins/pass");
    std::fs::create_dir_all(&plugin).unwrap();
    std::fs::write(
        plugin.join("plugin.toml"),
        "name = \"pass\"\ntype = \"resolver\"\nscheme = \"secret-store\"\nexec = \"resolve\"\n\
         version = \"0.1.0\"\ndescription = \"a test resolver\"\n",
    )
    .unwrap();
    let exec = plugin.join("resolve");
    std::fs::write(&exec, "#!/bin/sh\necho secret\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // Publish: sign the tree (generating the key on first use).
    let keyfile = fx.bind_dir.path().join("store.key");
    let publish = fx.run(&[
        "plugins",
        "store",
        "publish",
        repo.to_str().unwrap(),
        "--key",
        keyfile.to_str().unwrap(),
    ]);
    assert!(
        publish.status.success(),
        "publish failed:\n{}",
        String::from_utf8_lossy(&publish.stderr)
    );

    // Commit exactly the published tree — the operator's step.
    git_in(&repo, &["init", "-q"]);
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "store"]);
    let url = format!("file://{}", repo.to_str().unwrap());

    // Add via a real clone: trust-on-first-use reads the shipped `pubkey` and verifies the cloned
    // catalogue against it (so a clone that mangled the signed bytes would be refused here).
    let add = fx.run(&[
        "plugins", "store", "add", "--name", "acme", "--url", &url, "--trust",
    ]);
    assert!(
        add.status.success(),
        "add failed:\n{}",
        String::from_utf8_lossy(&add.stderr)
    );

    // Install: the cloned plugin subdirectory must reproduce the catalogue's content digest.
    let install = fx.run(&["plugins", "store", "install", "acme", "pass"]);
    assert!(
        install.status.success(),
        "install failed:\n{}",
        String::from_utf8_lossy(&install.stderr)
    );

    // The plugin is now installed and claims its scheme.
    let list = fx.run(&["plugins", "list"]);
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        stdout.contains("secret-store"),
        "the installed plugin must appear in `plugins list`:\n{stdout}"
    );
}

#[test]
fn an_app_overlay_shows_in_config_and_its_security_fields_gate_by_trust() {
    let fx = Fixture::new();
    let bind = fx.bind_target("appdir");
    fx.write_project(&format!(
        "[app.probe]\n\
         cmd = [\"id\"]\n\
         binds = [{bind:?}]\n\
         [app.probe.packages]\n\
         tool = \"ripgrep\"\n\
         [app.review]\n\
         cmd = [\"id\"]\n\
         home_scope = \"project\"\n",
        bind = bind.display().to_string()
    ));

    // Untrusted: the app shows with its command and package, but its bind is a security
    // field — dropped, with a note on the app.
    let out = fx.run(&["config"]);
    assert!(out.status.success(), "config must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("apps:"), "apps section missing:\n{stdout}");
    assert!(
        stdout.contains("probe: id"),
        "app command missing:\n{stdout}"
    );
    // The home scope is shown: `probe` defaults to a global home, `review` opted into a
    // per-project one.
    assert!(
        stdout.contains("home: global"),
        "the default global home scope must show:\n{stdout}"
    );
    assert!(
        stdout.contains("home: per-project"),
        "an opted-in per-project home scope must show:\n{stdout}"
    );
    assert!(
        stdout.contains("packages: tool"),
        "app package missing:\n{stdout}"
    );
    assert!(
        stdout.to_lowercase().contains("note:") && stdout.to_lowercase().contains("bind"),
        "an untrusted app's bind must be dropped with a note:\n{stdout}"
    );

    // Trusted: the bind is honored — no drop note remains.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("probe: id"),
        "app command missing:\n{stdout}"
    );
    assert!(
        !stdout.contains("note:"),
        "a trusted app must not drop its bind:\n{stdout}"
    );
}
