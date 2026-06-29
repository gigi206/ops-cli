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

    /// Drop an imported app profile under the profiles directory
    /// (`<config>/ops/apps/<name>.toml`) — the artifact `ops app import` produces, trusted by
    /// location beside the global config.
    fn write_profile(&self, name: &str, body: &str) {
        let dir = self.config_home.path().join("ops").join("apps");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), body).unwrap();
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
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success(), "config must succeed with no files");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("env:   (none)"), "stdout:\n{stdout}");
    assert!(stdout.contains("binds: (none)"), "stdout:\n{stdout}");
    assert!(stdout.contains("mise:  (none)"), "stdout:\n{stdout}");
}

#[test]
fn config_json_is_a_valid_document_carrying_the_resolved_model() {
    // The machine-readable surface a script or a future management front-end consumes: the same
    // resolved model the human render shows, as one parseable JSON document on stdout.
    let fx = Fixture::new();
    fx.write_project("[env]\nFOO = \"bar\"\n\n[packages]\njq = \"nix:jq\"\n");

    let out = fx.run(&["config", "show", "--json"]);
    assert!(
        out.status.success(),
        "`ops config show --json` should exit 0"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("config --json must emit valid JSON");

    assert_eq!(doc["env"][0]["key"], "FOO");
    assert_eq!(doc["env"][0]["value"], "bar");
    assert_eq!(doc["packages"][0]["name"], "jq");
    assert_eq!(doc["packages"][0]["backend"], "nix");
    // An untrusted project withholds its package — the JSON carries the same verdict the human
    // render shows (the field is the model, not a re-derivation).
    assert_eq!(doc["packages"][0]["trusted"], false);
    assert_eq!(doc["network"], "Shared");
}

#[test]
fn config_show_rejects_an_unknown_argument() {
    let fx = Fixture::new();
    let out = fx.run(&["config", "show", "--bogus"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown argument is a usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unexpected argument"), "stderr:\n{stderr}");
    assert!(
        stderr.contains("ops config show"),
        "should print the usage synopsis:\n{stderr}"
    );
}

#[test]
fn bare_config_reveals_its_subcommands() {
    // `ops config` with no subcommand must not silently render the resolved view (which would
    // hide that `show`/`get`/set/… exist) — it prints the config page, listing the subcommands,
    // to stderr and exits non-zero, the way bare `ops` does.
    let fx = Fixture::new();
    let out = fx.run(&["config"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "bare `ops config` is a no-subcommand usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Subcommands:") && stderr.contains("show") && stderr.contains("get"),
        "bare config must list its subcommands:\n{stderr}"
    );
    // The resolved view never lands on stdout for a bare invocation — that is `ops config show`.
    assert!(
        out.stdout.is_empty(),
        "bare config must not print the resolved view to stdout"
    );
}

#[test]
fn config_a_misplaced_flag_points_at_show() {
    // A flag with no subcommand (the old `ops config --json` muscle memory) is a usage error that
    // names the right form, rather than being silently accepted.
    let fx = Fixture::new();
    let out = fx.run(&["config", "--json"]);
    assert_eq!(out.status.code(), Some(2), "a bare flag is a usage error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ops config show --json"),
        "a misplaced flag must point at `ops config show`:\n{stderr}"
    );
}

#[test]
fn a_mise_file_is_withheld_until_the_project_is_trusted() {
    let fx = Fixture::new();
    fx.write_project("[env]\nA = \"1\"\n");
    fx.write_mise("[tools]\nnode = \"20\"\n");

    // Untrusted: the mise file is present but would not be honored.
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mise:  .mise.toml (withheld:"),
        "an untrusted mise file must be withheld:\n{stdout}"
    );

    // Trusting the project (which hashes both files) honors it.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
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

    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GLOBALVAR=g"), "stdout:\n{stdout}");
    let canon = shared.canonicalize().unwrap();
    assert!(
        stdout.contains(&*canon.to_string_lossy()),
        "stdout:\n{stdout}"
    );
    // Both free fields are tagged with their source layer (the global config).
    assert!(
        stdout.contains("GLOBALVAR=g  (global)"),
        "env provenance:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("{}  (global)", canon.to_string_lossy())),
        "bind provenance:\n{stdout}"
    );
}

#[test]
fn env_provenance_names_the_winning_layer_on_a_same_key_override() {
    // When both layers set the same key, the project applies last and wins — the provenance
    // tag must name the *winning* layer, not the one that declared it first.
    let fx = Fixture::new();
    fx.write_global("[env]\nFOO = \"g\"\n");
    fx.write_project("[env]\nFOO = \"p\"\n");

    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("FOO=p  (project)"),
        "the project's value must win and the tag must say project:\n{stdout}"
    );
    assert!(
        !stdout.contains("FOO=g"),
        "the overridden global value must not be shown:\n{stdout}"
    );
}

#[test]
fn an_untrusted_project_keeps_env_but_drops_binds() {
    let fx = Fixture::new();
    fx.write_project("binds = [\"/etc/ssh\"]\n[env]\nPROJVAR = \"p\"\n");

    let out = fx.run(&["config", "show"]);
    assert!(out.status.success(), "untrusted config must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // free field applied, tagged with its source layer (the project config)
    assert!(stdout.contains("PROJVAR=p"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("PROJVAR=p  (project)"),
        "env provenance:\n{stdout}"
    );
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

    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // now the security bind is honored
    let canon = extra.canonicalize().unwrap();
    assert!(
        stdout.contains(&*canon.to_string_lossy()),
        "trusted binds must apply:\n{stdout}"
    );
    assert!(stdout.contains("PROJVAR=p"), "stdout:\n{stdout}");
    // a trusted project's free fields are tagged as the project layer's
    assert!(
        stdout.contains(&format!("{}  (project)", canon.to_string_lossy())),
        "bind provenance:\n{stdout}"
    );
    assert!(
        stdout.contains("PROJVAR=p  (project)"),
        "env provenance:\n{stdout}"
    );
}

#[test]
fn the_network_posture_is_a_trust_gated_security_field() {
    let fx = Fixture::new();
    fx.write_project("network = \"none\"\n");

    // Untrusted: the posture is dropped to the default (shared), and the drop is
    // explained — an untrusted project may not cut (or reopen) the network.
    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `mode = "allowlist"` is the backward-compatible alias of `deny`, so it renders as `deny`.
    assert!(stdout.contains("network: deny"), "stdout:\n{stdout}");
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
    // the built-in allow-set is shown (always allowed so self-equip works), so it
    // is never a silent allowance.
    assert!(
        stdout.contains("built-in") && stdout.contains("cache.nixos.org"),
        "the built-in allow-set must be shown:\n{stdout}"
    );
    // stats default on under a filtering posture.
    assert!(
        stdout.contains("stats: recording"),
        "the egress-stats toggle defaults on:\n{stdout}"
    );
}

#[test]
fn the_egress_stats_toggle_is_shown_and_trust_gated() {
    // A trusted project that turns its audit off reads `stats: off`.
    let fx = Fixture::new();
    fx.write_project("[network]\nmode = \"allowlist\"\nallow = [\"github.com\"]\nstats = false\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("stats: off"),
        "a trusted `stats = false` must read off:\n{stdout}"
    );

    // The gate: an untrusted project's `stats = false` is dropped with its whole `[network]` table,
    // so the global filtering posture's recording stays on — a project cannot disable the auditing
    // of its own egress.
    let fx = Fixture::new();
    fx.write_global("[network]\nmode = \"allowlist\"\nallow = [\"github.com\"]\n");
    fx.write_project("[network]\nmode = \"allowlist\"\nallow = [\"github.com\"]\nstats = false\n");
    // deliberately NOT trusting the project
    let out = fx.run(&["config", "show"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("stats: recording"),
        "an untrusted `stats = false` must not disable recording:\n{stdout}"
    );
}

#[test]
fn the_allow_mode_is_a_denylist_default_allow_with_deny_carve_outs() {
    let fx = Fixture::new();
    // Allow-by-default (a denylist) with one deny carve-out, in the table form.
    fx.write_project("[network]\nmode = \"allow\"\ndeny = [\"evil.example/secret\"]\n");

    // Security boundary: an UNTRUSTED project must not be able to *open* egress with allow mode —
    // it falls back to the default (shared) with an explanation. Opening egress is exactly the
    // capability an untrusted project may not gain; `allow` is a filtering posture but still a
    // trust-gated security field, gated identically to `none`/`shared`/`deny`/`allowlist`.
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success(), "untrusted config must not hard-fail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("network: shared") && !stdout.contains("network: allow"),
        "an untrusted `allow` mode must fall back to shared, not open egress:\n{stdout}"
    );
    assert!(
        stderr.contains("network") && stderr.contains("untrusted"),
        "a dropped allow-mode posture must be explained:\n{stderr}"
    );

    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // `config show` names the mode and frames it as a denylist, not an allowlist.
    let out = fx.run(&["config", "show"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("network: allow"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("every public host is reachable except"),
        "allow mode must read as a denylist:\n{stdout}"
    );
    assert!(
        stdout.contains("deny") && stdout.contains("evil.example/secret"),
        "the deny carve-out must be shown:\n{stdout}"
    );

    // `ops test net`: an unlisted host is ALLOWED (the new default-allow behavior)...
    let out = fx.run(&["test", "net", "https://anything.example/page"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ALLOWED") && stdout.contains("allow-by-default"),
        "an unlisted host must be allowed under allow mode:\n{stdout}"
    );
    // ...while the deny carve-out is still DENIED (deny wins, even under allow-by-default).
    let out = fx.run(&["test", "net", "https://evil.example/secret"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DENIED") && stdout.contains("evil.example/secret"),
        "the deny carve-out must still win under allow mode:\n{stdout}"
    );
}

#[test]
fn editing_a_trusted_project_re_arms_the_gate() {
    let fx = Fixture::new();
    fx.write_project("binds = [\"/etc/ssh\"]\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // an edit changes the content hash; the binds must drop again until re-trusted
    fx.write_project("binds = [\"/etc/ssh\", \"/opt/extra\"]\n");
    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
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

    let out = fx.run(&["config", "show"]);
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
    fx.write_project("[packages]\nnode = \"nix:nodejs_20\"\n");

    // Untrusted: shown, but marked withheld.
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("node -> nix:nodejs_20"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("withheld"),
        "an untrusted package must be shown as withheld:\n{stdout}"
    );

    // Trusted: shown plainly, no longer withheld.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config", "show"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("node -> nix:nodejs_20"),
        "stdout:\n{stdout}"
    );
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
    fx.write_project("[packages]\nhello = \"nix:hello\"\n");

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
    fx.write_project("[packages]\nbogus = \"nix:ops-no-such-attribute-xyz\"\n");
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
    let out = fx.run(&["config", "show"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("nixpkgs: nixos-unstable  (default)"),
        "stdout:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // an untrusted project override is a security field: ignored (still default),
    // and not silently
    fx.write_project("nixpkgs = \"nixos-23.11\"\n");
    let out = fx.run(&["config", "show"]);
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
    let out = fx.run(&["config", "show"]);
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

    let out = fx.run(&["config", "show"]);
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
    fx.write_project("nixpkgs = \"nixos-23.11\"\n[packages]\nhello = \"nix:hello\"\n");
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

    let out = fx.run(&["config", "show"]);
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

    let out = fx.run(&["config", "show"]);
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
         tool = \"nix:ripgrep\"\n\
         [app.review]\n\
         cmd = [\"id\"]\n\
         home_scope = \"project\"\n",
        bind = bind.display().to_string()
    ));

    // Untrusted: the app shows with its command, but its security fields read as the launch would
    // treat them — the bind is dropped with a note, and the package shows `(withheld)` (an
    // untrusted layer's `[packages]` is withheld at launch, so the view must not show it as plain).
    let out = fx.run(&["config", "show"]);
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
        stdout.contains("packages: tool (withheld)"),
        "an untrusted app package must read as withheld (it is withheld at launch):\n{stdout}"
    );
    assert!(
        stdout.to_lowercase().contains("note:") && stdout.to_lowercase().contains("bind"),
        "an untrusted app's bind must be dropped with a note:\n{stdout}"
    );

    // Trusted: the bind is honored — no drop note remains — and the package is admitted, so it
    // shows plainly, no longer marked `(withheld)`.
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());
    let out = fx.run(&["config", "show"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("probe: id"),
        "app command missing:\n{stdout}"
    );
    assert!(
        !stdout.contains("note:"),
        "a trusted app must not drop its bind:\n{stdout}"
    );
    assert!(
        stdout.contains("packages: tool") && !stdout.contains("(withheld)"),
        "a trusted app package must show plainly, not withheld:\n{stdout}"
    );

    // `--details` expands the compact list to the full per-package line, surfacing the backend the
    // baseline `packages` section shows — the same line, just indented under the app.
    let out = fx.run(&["config", "show", "--details"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tool -> nix:ripgrep"),
        "--details must expand an app package to its full backend line:\n{stdout}"
    );
}

#[test]
fn an_imported_profile_is_a_trusted_by_location_app() {
    let fx = Fixture::new();
    // A profile dropped beside the global config is honored in full — its security `network`
    // field included — even with no project trust, exactly like a global `[app.<name>]`.
    fx.write_profile(
        "demo-app",
        "cmd = \"demo-app\"\n[network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n",
    );
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("demo-app: demo-app"),
        "the imported profile must resolve as an app:\n{stdout}"
    );
    assert!(
        stdout.contains("network: deny"),
        "a profile's security field must be honored (trusted by location):\n{stdout}"
    );
}

#[test]
fn an_app_allowlist_shows_counts_by_default_and_rules_under_details() {
    let fx = Fixture::new();
    // A profile (trusted by location) whose allowlist lives in the app overlay — the common case,
    // since the baseline stays `shared`. The compact view shows the rule counts; `--details`
    // expands the individual rules plus the always-allowed built-in set (which the
    // baseline `network` section never prints here, because the baseline is not an allowlist).
    fx.write_profile(
        "demo-app",
        "cmd = \"demo-app\"\n[network]\nmode = \"allowlist\"\n\
         allow = [\"api.example.com\", \"github.com\"]\ndeny = [\"github.com/secret\"]\n",
    );

    // Default: the compact one-line count, both numbers present.
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("network: deny (2 allow, 1 deny)"),
        "the default must show compact rule counts:\n{stdout}"
    );
    assert!(
        !stdout.contains("allow api.example.com"),
        "the default must not expand the rules:\n{stdout}"
    );

    // --details: the rules themselves, the deny carve-out, and the built-in set.
    let out = fx.run(&["config", "show", "--details"]);
    assert!(out.status.success(), "config show --details must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("allow api.example.com") && stdout.contains("allow github.com"),
        "--details must list the allow rules:\n{stdout}"
    );
    assert!(
        stdout.contains("deny") && stdout.contains("github.com/secret"),
        "--details must list the deny rule:\n{stdout}"
    );
    assert!(
        stdout.contains("built-in") && stdout.contains("cache.nixos.org"),
        "--details must surface the always-allowed built-in set:\n{stdout}"
    );
}

#[test]
fn config_show_app_shows_the_effective_config_with_inheritance() {
    let fx = Fixture::new();
    // A baseline `[limits]` (global, trusted by location) the app inherits, plus a profile (also
    // trusted by location) that sets its own command, network, and one limit. `config show --app`
    // then tells the inheritance story end-to-end: the fields the app set read `app:global`, the
    // ones it left alone read `inherited` and show the baseline's effective value.
    fx.write_global("[limits]\nmemory_high = \"70%\"\n");
    fx.write_profile(
        "demo",
        "cmd = \"demo-agent\"\n[network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n\
         [limits]\ntasks_max = 2048\n[env]\nDEMO_TOKEN = \"placeholder\"\n",
    );

    let out = fx.run(&["config", "show", "--app", "demo"]);
    assert!(out.status.success(), "config show --app must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The app set these — attributed to the app's global declaration.
    assert!(
        stdout.contains("cmd:     demo-agent  (app:global)"),
        "the command the app set must read app:global:\n{stdout}"
    );
    assert!(
        stdout.contains("network: deny  (app:global)"),
        "the network the app set must read app:global:\n{stdout}"
    );
    assert!(
        stdout.contains("TasksMax=2048 (app:global)"),
        "the task cap the app set must read app:global:\n{stdout}"
    );
    // The app left these alone — inherited from the baseline (the throttle the baseline set; the
    // GUI default). This is the headline the per-app view exists for.
    assert!(
        stdout.contains("gui:     none  (inherited)"),
        "the untouched gui must read inherited:\n{stdout}"
    );
    assert!(
        stdout.contains("MemoryHigh=70% (inherited)"),
        "the throttle the app left to the baseline must read inherited at the baseline's value:\n{stdout}"
    );
    assert!(
        stdout.contains("env:     1 own"),
        "the overlay's own env count must show:\n{stdout}"
    );

    // An unknown app fails and names the declared ones.
    let out = fx.run(&["config", "show", "--app", "nope"]);
    assert!(!out.status.success(), "an unknown app must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no app named") && stderr.contains("demo"),
        "the error must name the unknown app and list the declared ones:\n{stderr}"
    );

    // `--json` emits the machine-readable model, carrying the per-field provenance.
    let out = fx.run(&["config", "show", "--app", "demo", "--json"]);
    assert!(
        out.status.success(),
        "config show --app --json must succeed"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--app --json must emit valid JSON");
    assert_eq!(doc["name"], "demo");
    assert_eq!(
        doc["cmd_origin"], "Global",
        "the JSON carries the command's provenance"
    );
    assert_eq!(doc["gui_origin"], "Inherited", "and the inherited GUI's");
}

#[test]
fn config_show_app_with_a_narrowed_network_drops_the_inherited_secret() {
    let fx = Fixture::new();
    // A baseline credential (global, trusted by location) under a network allowlist, and two apps:
    // `wide` inherits the allowlist (so the launch injects the secret), `narrow` cuts the network
    // to none (so the launch injects nothing). The per-app view must match the launch — it must not
    // report a credential `ops app narrow` would silently drop.
    fx.write_global(
        "[network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n\
         [secret.\"api.example.com\"]\nfrom = \"env://DEMO_TOKEN\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n\
         [app.wide]\ncmd = \"agent\"\n\
         [app.narrow]\ncmd = \"agent\"\nnetwork = \"none\"\n",
    );

    // `wide` keeps the network, so it inherits the baseline credential.
    let out = fx.run(&["config", "show", "--app", "wide"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("inherits 1 baseline"),
        "an app under the allowlist inherits the baseline credential:\n{stdout}"
    );

    // `narrow` cuts the network — the launch injects nothing, so the view reports zero credentials
    // (own and inherited) and carries the same drop note the launch would emit.
    let out = fx.run(&["config", "show", "--app", "narrow"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0 own  · inherits 0 baseline"),
        "a narrowed network drops the inherited credential in the view:\n{stdout}"
    );
    assert!(
        stdout.contains("ignoring 1 HTTP-header secret(s)"),
        "the view must carry the launch's drop note:\n{stdout}"
    );

    // The JSON model agrees: no credential survives.
    let out = fx.run(&["config", "show", "--app", "narrow", "--json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["secrets"].as_array().unwrap().len(), 0);
    assert_eq!(doc["secrets_inherited"], 0);
}

#[test]
fn config_show_compact_app_section_is_secret_posture_aware() {
    let fx = Fixture::new();
    // The compact `apps:` roster in the full `config show` must agree with the launch (and the
    // `--app` detail view): an app declaring its own credential injects it only under an allowlist.
    // `wired` keeps an allowlist (injects); `solo` declares the same credential but cuts the network
    // to none (the launch injects nothing), so the roster must not claim an injection for it.
    fx.write_global(
        "[app.wired]\ncmd = \"agent\"\n[app.wired.network]\nmode = \"allowlist\"\n\
         allow = [\"api.example.com\"]\n[app.wired.secret.\"api.example.com\"]\n\
         from = \"env://DEMO_TOKEN\"\nheader = \"Authorization\"\ntype = \"bearer\"\n\
         [app.solo]\ncmd = \"agent\"\nnetwork = \"none\"\n\
         [app.solo.secret.\"api.example.com\"]\nfrom = \"env://DEMO_TOKEN\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n",
    );

    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The allowlist app injects: its compact roster shows the credential count.
    assert!(
        stdout.contains("secrets: 1 injected host-side"),
        "the allowlist app must show its injected credential:\n{stdout}"
    );
    // Exactly one app shows an injected-secrets line — `solo` (network none) must not, since the
    // launch injects nothing for it (the line is omitted, like an app with no credential).
    assert_eq!(
        stdout.matches("injected host-side").count(),
        1,
        "a narrowed-network app must not claim an injection in the compact roster:\n{stdout}"
    );
}

#[test]
fn config_show_single_source_views_restrict_to_one_layer() {
    let fx = Fixture::new();
    // A free env var and a security field in the global config; a different free env var in the
    // project. Each single-source view shows what *that* layer contributes (over the defaults), so
    // its provenance tags read as that layer's own additions.
    fx.write_global("[env]\nGLOBAL_VAR = \"g\"\n[network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n");
    fx.write_project("[env]\nPROJECT_VAR = \"p\"\n");

    // --global: the global's var (tagged global) and its network; the project's var is absent.
    let out = fx.run(&["config", "show", "--global"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("GLOBAL_VAR=g  (global)") && stdout.contains("network: deny  (global)"),
        "--global shows the global layer's contributions:\n{stdout}"
    );
    assert!(
        !stdout.contains("PROJECT_VAR"),
        "--global omits the project layer:\n{stdout}"
    );

    // --local: the project's var (tagged project); the network is the default (the project did not
    // set one), and the global's var is absent.
    let out = fx.run(&["config", "show", "--local"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PROJECT_VAR=p  (project)")
            && stdout.contains("network: shared")
            && stdout.contains("(default)"),
        "--local shows the project's contributions over the defaults:\n{stdout}"
    );
    assert!(
        !stdout.contains("GLOBAL_VAR"),
        "--local omits the global layer:\n{stdout}"
    );

    // --default: neither var; the built-in default network.
    let out = fx.run(&["config", "show", "--default"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("GLOBAL_VAR") && !stdout.contains("PROJECT_VAR"),
        "--default shows neither config layer:\n{stdout}"
    );
    assert!(
        stdout.contains("network: shared") && stdout.contains("(default)"),
        "--default shows the built-in default network:\n{stdout}"
    );
}

#[test]
fn config_show_rejects_conflicting_source_and_app_flags() {
    let fx = Fixture::new();
    // Two different source flags is a user error, not last-wins.
    let out = fx.run(&["config", "show", "--global", "--local"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "conflicting sources are a usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("conflicts"), "stderr:\n{stderr}");

    // A per-app view is inherently over the full baseline, so a single-source flag is rejected.
    let out = fx.run(&["config", "show", "--app", "demo", "--global"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "--app + a source flag is a usage error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not combine"), "stderr:\n{stderr}");
}

#[test]
fn config_app_flag_addresses_the_app_table_for_get_set_unset() {
    let fx = Fixture::new();
    // `set --app` writes under the app's table — sugar for the dotted key `app.<name>.<key>`.
    let out = fx.run(&["config", "set", "--app", "demo", "cmd", "mytool"]);
    assert!(out.status.success(), "set --app must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("app.demo.cmd"),
        "the write must name the app-scoped key:\n{stdout}"
    );
    let body = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        body.contains("[app.demo]") && body.contains("cmd = \"mytool\""),
        "the file must carry the app table:\n{body}"
    );

    // `get --app` reads it back.
    let out = fx.run(&["config", "get", "--app", "demo", "cmd"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "mytool");

    // `unset --app` removes it.
    let out = fx.run(&["config", "unset", "--app", "demo", "cmd"]);
    assert!(out.status.success());
    let body = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        !body.contains("cmd = \"mytool\""),
        "unset --app must remove the key:\n{body}"
    );
}

#[test]
fn config_app_flag_validates_the_name_and_does_not_apply_to_path_or_edit() {
    let fx = Fixture::new();
    // A name with a `.` cannot be one TOML table segment under the naive key splitter — the error
    // points at `ops config edit`.
    let out = fx.run(&["config", "set", "--app", "my.app", "cmd", "x"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ops config edit"), "stderr:\n{stderr}");

    // A name no app could carry is rejected outright.
    let out = fx.run(&["config", "set", "--app", "bad name", "cmd", "x"]);
    assert_eq!(out.status.code(), Some(2));

    // `path` and `edit` take no key, so `--app` does not apply.
    let out = fx.run(&["config", "path", "--app", "demo"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not apply"),
        "path must reject --app"
    );
    let out = fx.run(&["config", "edit", "--app", "demo"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not apply"),
        "edit must reject --app"
    );
}

#[test]
fn config_short_flags_alias_their_long_forms() {
    let fx = Fixture::new();
    fx.write_global("[env]\nGLOBAL_VAR = \"g\"\n");
    fx.write_project("[env]\nPROJECT_VAR = \"p\"\n");

    // `-g` on `show` is `--global`: the global var, not the project's.
    let out = fx.run(&["config", "show", "-g"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("GLOBAL_VAR=g  (global)") && !stdout.contains("PROJECT_VAR"),
        "-g must alias --global:\n{stdout}"
    );

    // `-l` on `show` is `--local`: the project's var, not the global's.
    let out = fx.run(&["config", "show", "-l"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PROJECT_VAR=p  (project)") && !stdout.contains("GLOBAL_VAR"),
        "-l must alias --local:\n{stdout}"
    );

    // `-d` on `show` is `--default`: neither layer's var.
    let out = fx.run(&["config", "show", "-d"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("GLOBAL_VAR") && !stdout.contains("PROJECT_VAR"),
        "-d must alias --default:\n{stdout}"
    );

    // `-a` on the write verbs is `--app`: `set -a` writes under the app's table, `-g` targets the
    // global file.
    let out = fx.run(&["config", "set", "-a", "demo", "-g", "cmd", "mytool"]);
    assert!(out.status.success(), "set -a -g must succeed");
    let global = fx.config_home.path().join("ops").join("ops.toml");
    let body = std::fs::read_to_string(&global).unwrap();
    assert!(
        body.contains("[app.demo]") && body.contains("cmd = \"mytool\""),
        "-a writes the app table into the -g (global) file:\n{body}"
    );

    // `get -a -g` reads it back from the same global file.
    let out = fx.run(&["config", "get", "-a", "demo", "-g", "cmd"]);
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "mytool");

    // `-a` on `show` is `--app`: the per-app effective view (a distinct parser from the write verbs)
    // — the global app just written is visible.
    let out = fx.run(&["config", "show", "-a", "demo"]);
    assert!(out.status.success(), "show -a must succeed");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("mytool"),
        "show -a must render the app's effective cmd"
    );
}

#[test]
fn an_app_secret_shows_a_count_by_default_and_its_destination_under_details() {
    let fx = Fixture::new();
    // A profile whose credential lives in the app overlay — the common case, since the shipped
    // profiles inject host-side from the overlay while the baseline carries no secret. The compact
    // view shows a count; `--details` expands each by destination and source. The value never
    // appears (ops reads it host-side at launch, and never resolves it here) — only the header,
    // host, shape, and the source *locator* (the variable name, `env DEMO_API_KEY`).
    fx.write_profile(
        "demo-app",
        "cmd = \"demo-app\"\n[network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n\
         [secret.\"api.example.com\"]\nfrom = \"env://DEMO_API_KEY\"\n\
         header = \"x-api-key\"\ntype = \"raw\"\n",
    );

    // Default: the compact count, no destination expanded.
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("secrets: 1 injected host-side"),
        "the default must show a compact secret count:\n{stdout}"
    );
    assert!(
        !stdout.contains("x-api-key -> api.example.com"),
        "the default must not expand the credential:\n{stdout}"
    );

    // --details: the credential by destination, header, shape, and source *locator* — the variable
    // name, a pointer, never a resolved value (ops config does not read the secret's source).
    let out = fx.run(&["config", "show", "--details"]);
    assert!(out.status.success(), "config show --details must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("x-api-key -> api.example.com") && stdout.contains("from env DEMO_API_KEY"),
        "--details must show the credential by destination and source locator:\n{stdout}"
    );
}

#[test]
fn an_app_env_and_binds_show_counts_by_default_and_expand_under_details() {
    let fx = Fixture::new();
    // A baseline (global) env, to prove the app section shows the overlay's *own* additions, not
    // the baseline-merged set: BASE_ONLY is baseline-only and must not be duplicated into the app
    // block; SHARED collides on a key and the app shows its own value, not the baseline's.
    fx.write_global("[env]\nBASE_ONLY = \"base\"\nSHARED = \"base\"\n");

    // A real directory the profile binds read-only (a bind target must exist — binds are
    // canonicalized and a missing one is dropped).
    let bind = fx.bind_target("workspace");
    let canonical = std::fs::canonicalize(&bind).unwrap();
    // A profile (trusted by location) adding two env entries and one read-only bind in its overlay.
    // The top-level keys (`cmd`, `binds`) precede the `[env]` table, or TOML would fold `binds`
    // into `[env]` (an array where a string is expected → a parse error, a silently dropped app).
    fx.write_profile(
        "demo-app",
        &format!(
            "cmd = \"demo-app\"\nbinds = [\"{}\"]\n[env]\nSHARED = \"app\"\nAPP_ONLY = \"app\"\n",
            bind.display()
        ),
    );

    // Default: compact counts. The env count is the overlay's two entries, not the merged three —
    // proof the view shows the overlay delta. No values or paths expanded.
    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("env: 2 set"),
        "the app must show its overlay's env count (2, not the merged 3):\n{stdout}"
    );
    assert!(
        stdout.contains("binds: 1"),
        "the app must show its bind count:\n{stdout}"
    );
    assert!(
        !stdout.contains("APP_ONLY=app") && !stdout.contains(&canonical.display().to_string()),
        "the default must not expand env values or bind paths:\n{stdout}"
    );

    // --details: the overlay's own env entries and the bind path. BASE_ONLY is a baseline-only key
    // — it appears exactly once (in the top-level env section), never duplicated into the app
    // block, which a merged (not overlay-only) projection would betray.
    let out = fx.run(&["config", "show", "--details"]);
    assert!(out.status.success(), "config show --details must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("SHARED=app") && stdout.contains("APP_ONLY=app"),
        "--details must show the app overlay's own env entries:\n{stdout}"
    );
    assert!(
        stdout.matches("BASE_ONLY").count() == 1,
        "a baseline-only key must not be duplicated into the app block (overlay-only):\n{stdout}"
    );
    assert!(
        stdout.contains(&canonical.display().to_string()),
        "--details must show the app's bind path:\n{stdout}"
    );
}

#[test]
fn an_imported_profile_keeps_its_command_and_posture_under_an_untrusted_project() {
    let fx = Fixture::new();
    // The flagship case: an imported profile (trusted by location) runs *on* untrusted code without
    // the repo hijacking it. The profile sets the command and a network allowlist.
    fx.write_profile(
        "claude",
        "cmd = \"claude\"\n[network]\nmode = \"allowlist\"\nallow = [\"api.anthropic.com\"]\n",
    );
    // An untrusted project tries to override the very same app's command and widen its network.
    fx.write_project("[app.claude]\ncmd = [\"evil\"]\nnetwork = \"shared\"\n");

    let out = fx.run(&["config", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The profile's command stands; the untrusted override is refused.
    assert!(
        stdout.contains("claude: claude"),
        "the profile command must stand:\n{stdout}"
    );
    assert!(
        !stdout.contains("claude: evil"),
        "the untrusted command must not win:\n{stdout}"
    );
    // The profile's network posture stands (the untrusted `shared` is dropped), and the refusals
    // are explained on the app.
    assert!(
        stdout.contains("network: deny"),
        "the profile network must stand:\n{stdout}"
    );
    assert!(
        stdout.contains("note:") && stdout.to_lowercase().contains("cmd"),
        "the refused command override must be noted:\n{stdout}"
    );
}

#[test]
fn ops_app_import_places_validates_renames_and_removes_a_profile() {
    let fx = Fixture::new();
    // A portable profile authored as a standalone file (the app's fields at the top level).
    std::fs::write(
        fx.proj.path().join("demo-app.toml"),
        "cmd = \"demo-app\"\n\
         [network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n\
         [secret.\"api.example.com\"]\nfrom = \"env://DEMO_API_KEY\"\n\
         header = \"x-api-key\"\ntype = \"raw\"\n",
    )
    .unwrap();

    // Import names it by the file stem, validates it, prints the granted posture, and places it.
    let imp = fx.run(&["app", "import", "demo-app.toml"]);
    assert!(
        imp.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );
    let out = String::from_utf8_lossy(&imp.stdout);
    assert!(out.contains("imported app profile 'demo-app'"), "{out}");
    assert!(out.contains("granted posture"), "{out}");
    assert!(out.contains("command: demo-app"), "{out}");
    // The secret is shown by destination + source locator, never a value.
    assert!(
        out.contains("api.example.com") && out.contains("env://DEMO_API_KEY"),
        "{out}"
    );

    // It now resolves as a trusted-by-location app.
    let cfg = String::from_utf8_lossy(&fx.run(&["config", "show"]).stdout).to_string();
    assert!(cfg.contains("demo-app: demo-app"), "{cfg}");

    // A second import without --force refuses to clobber.
    let again = fx.run(&["app", "import", "demo-app.toml"]);
    assert!(
        !again.status.success(),
        "a second import must refuse without --force"
    );
    assert!(String::from_utf8_lossy(&again.stderr).contains("--force"));

    // `--as` re-keys to a different name (the contents are name-agnostic), and `list` shows both.
    let renamed = fx.run(&["app", "import", "demo-app.toml", "--as", "agent"]);
    assert!(renamed.status.success());
    let listed = String::from_utf8_lossy(&fx.run(&["app", "list"]).stdout).to_string();
    assert!(
        listed.contains("agent") && listed.contains("demo-app"),
        "{listed}"
    );

    // Remove an imported profile; the other remains.
    let rm = fx.run(&["app", "rm", "demo-app"]);
    assert!(
        rm.status.success(),
        "rm failed: {}",
        String::from_utf8_lossy(&rm.stderr)
    );
    let after = String::from_utf8_lossy(&fx.run(&["config", "show"]).stdout).to_string();
    assert!(
        !after.contains("demo-app: demo-app"),
        "removed app lingers:\n{after}"
    );
    assert!(
        after.contains("agent: demo-app"),
        "the other app must remain:\n{after}"
    );
}

#[test]
fn ops_app_import_refuses_a_wrapped_profile_and_a_reserved_name() {
    let fx = Fixture::new();
    // A file mistakenly wrapped in `[app.<name>]` has no top-level cmd → refused with a hint.
    std::fs::write(
        fx.proj.path().join("wrapped.toml"),
        "[app.demo-app]\ncmd = \"demo-app\"\n",
    )
    .unwrap();
    let wrapped = fx.run(&["app", "import", "wrapped.toml"]);
    assert!(
        !wrapped.status.success(),
        "a wrapped profile must be refused"
    );
    assert!(String::from_utf8_lossy(&wrapped.stderr).contains("cmd"));

    // A reserved subcommand verb cannot be an app name.
    std::fs::write(fx.proj.path().join("ok.toml"), "cmd = \"x\"\n").unwrap();
    let reserved = fx.run(&["app", "import", "ok.toml", "--as", "rm"]);
    assert!(
        !reserved.status.success(),
        "a reserved name must be refused"
    );
    assert!(String::from_utf8_lossy(&reserved.stderr).contains("reserved"));
}

#[test]
fn ops_app_export_emits_a_profile_verbatim_an_inline_app_serialized_and_round_trips() {
    let fx = Fixture::new();

    // (a) An imported profile exports verbatim — comments and formatting survive.
    let profile_body = "# my demo-app profile\n\
                        cmd = \"demo-app\"\n\
                        [network]\nmode = \"allowlist\"\nallow = [\"api.example.com\"]\n";
    fx.write_profile("demo-app", profile_body);
    let exp = fx.run(&["app", "export", "demo-app"]);
    assert!(
        exp.status.success(),
        "export failed: {}",
        String::from_utf8_lossy(&exp.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&exp.stdout),
        profile_body,
        "an imported profile must export verbatim"
    );

    // (b) An inline (untrusted) project app serializes to a minimal profile and re-imports
    //     identically — the export -> import portability loop, exercising `--out` too.
    fx.write_project(
        "[app.review]\ncmd = [\"review\", \"--all\"]\n[app.review.env]\nMODE = \"ci\"\n",
    );
    let exported = fx.proj.path().join("review.toml");
    let exp2 = fx.run(&[
        "app",
        "export",
        "review",
        "--out",
        exported.to_str().unwrap(),
    ]);
    assert!(
        exp2.status.success(),
        "inline export failed: {}",
        String::from_utf8_lossy(&exp2.stderr)
    );
    let serialized = std::fs::read_to_string(&exported).unwrap();
    assert!(
        serialized.contains("cmd = [\"review\", \"--all\"]") && serialized.contains("MODE"),
        "the serialized profile is missing fields:\n{serialized}"
    );
    assert!(
        !serialized.contains("[packages]"),
        "empty fields must be skipped:\n{serialized}"
    );
    // Re-import the exported file: it resolves as an app, closing the loop.
    let imp = fx.run(&["app", "import", exported.to_str().unwrap()]);
    assert!(
        imp.status.success(),
        "re-import of the exported profile failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );
    assert!(
        String::from_utf8_lossy(&fx.run(&["app", "list"]).stdout).contains("review"),
        "the re-imported profile must list"
    );

    // (c) An unknown app is a clean error.
    let missing = fx.run(&["app", "export", "nope"]);
    assert!(!missing.status.success(), "an unknown export must fail");
    assert!(String::from_utf8_lossy(&missing.stderr).contains("no app"));
}

#[test]
fn the_shipped_profiles_import_and_resolve() {
    // Every profile under the repo's `profiles/` directory must import cleanly (parse, have a
    // command, a usable name) and resolve as a launchable app — so a shipped profile is never
    // subtly broken, and the import path is re-exercised on real artifacts.
    let fx = Fixture::new();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles");
    let mut imported = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("profiles/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let imp = fx.run(&["app", "import", path.to_str().unwrap()]);
        assert!(
            imp.status.success(),
            "shipped profile `{name}` failed to import: {}",
            String::from_utf8_lossy(&imp.stderr)
        );
        imported.push(name);
    }
    assert!(
        !imported.is_empty(),
        "expected at least one shipped profile in {}",
        dir.display()
    );
    // Each imported profile now resolves as an app (`ops config` lists it by name).
    let cfg = String::from_utf8_lossy(&fx.run(&["config", "show"]).stdout).to_string();
    for name in &imported {
        assert!(
            cfg.contains(&format!("{name}:")),
            "shipped profile `{name}` did not resolve as an app:\n{cfg}"
        );
    }
}

#[test]
fn ops_app_rm_of_an_absent_profile_points_at_ops_toml() {
    let fx = Fixture::new();
    let out = fx.run(&["app", "rm", "nope"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ops.toml"));
}

#[test]
fn config_get_set_unset_round_trip() {
    let fx = Fixture::new();
    // set creates the file; get reads it back; unset removes it; get then exits 1.
    assert!(fx
        .run(&["config", "set", "env.FOO", "bar"])
        .status
        .success());
    let got = fx.run(&["config", "get", "env.FOO"]);
    assert!(got.status.success());
    assert_eq!(String::from_utf8_lossy(&got.stdout).trim(), "bar");

    assert!(fx.run(&["config", "unset", "env.FOO"]).status.success());
    let missing = fx.run(&["config", "get", "env.FOO"]);
    assert_eq!(
        missing.status.code(),
        Some(1),
        "an unset key exits 1 (distinct from a usage error)"
    );
}

#[test]
fn config_set_preserves_comments_and_warns_when_it_re_arms_trust() {
    let fx = Fixture::new();
    fx.write_project("# a comment to keep\nnixpkgs = \"nixos-23.11\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    let out = fx.run(&["config", "set", "nixpkgs", "nixos-24.05"]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("re-armed the trust gate"),
        "a write to a trusted file must warn:\n{stderr}"
    );
    assert!(stderr.contains("ops trust"), "and point at re-trusting");

    let after = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        after.contains("# a comment to keep"),
        "comment kept:\n{after}"
    );
    assert!(
        after.contains("nixpkgs = \"nixos-24.05\""),
        "value set:\n{after}"
    );
}

#[test]
fn config_set_with_trust_applies_a_security_field_at_once() {
    let fx = Fixture::new();
    // Setting a security field then trusting in one step: the resolved view honors it.
    let out = fx.run(&["config", "set", "network", "none", "--trust"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("trusted"),
        "--trust should report the file is now trusted"
    );

    let view = fx.run(&["config", "show"]);
    assert!(
        String::from_utf8_lossy(&view.stdout).contains("network: none"),
        "the trusted security field must apply:\n{}",
        String::from_utf8_lossy(&view.stdout)
    );
}

#[test]
fn config_set_a_security_field_on_an_untrusted_project_is_noted_and_withheld() {
    let fx = Fixture::new();
    let out = fx.run(&["config", "set", "network", "none"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("security field"),
        "an untrusted security write should note it needs trust"
    );
    // And the launch would not honor it: the resolved view still shows the default.
    let view = fx.run(&["config", "show"]);
    assert!(
        String::from_utf8_lossy(&view.stdout).contains("network: shared"),
        "an untrusted network choice is withheld"
    );
}

#[test]
fn config_path_reports_the_target_file_per_scope() {
    let fx = Fixture::new();
    // An explicit scope prints a single bare path — the scripting contract.
    let local = fx.run(&["config", "path", "--local"]);
    assert!(local.status.success());
    assert!(String::from_utf8_lossy(&local.stdout)
        .trim()
        .ends_with(".ops.toml"));

    let global = fx.run(&["config", "path", "--global"]);
    assert!(global.status.success());
    let g = String::from_utf8_lossy(&global.stdout);
    assert!(
        g.contains("ops.toml") && !g.contains(".ops.toml"),
        "global path:\n{g}"
    );
}

#[test]
fn config_path_lists_the_resolution_order_by_default() {
    let fx = Fixture::new();

    // No files exist yet (the common first-run state): the overview still succeeds and lists both
    // layers as absent, rather than printing one bare path that does not exist.
    let out = fx.run(&["config", "path"]);
    assert!(out.status.success(), "the overview must exit 0");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("resolution order"), "header missing:\n{s}");
    assert!(
        s.contains("global") && s.contains("project"),
        "layers:\n{s}"
    );
    assert_eq!(s.matches("(absent)").count(), 2, "both absent:\n{s}");
    assert!(!s.contains("(present)"), "nothing present yet:\n{s}");

    // The project line must carry exactly the path `--local` targets — the overview is derived from
    // the same primitive, so they can never disagree.
    let local = fx.run(&["config", "path", "--local"]);
    let local_path = String::from_utf8_lossy(&local.stdout).trim().to_string();
    assert!(s.contains(&local_path), "project line vs --local:\n{s}");

    // Once both files exist, each layer reads present.
    fx.write_global("env.A = \"1\"\n");
    fx.write_project("env.B = \"2\"\n");
    let out = fx.run(&["config", "path"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(s.matches("(present)").count(), 2, "both present:\n{s}");
    assert!(!s.contains("(absent)"), "none absent now:\n{s}");
}

#[test]
fn config_set_global_creates_a_missing_config_dir() {
    // A fresh fixture has no <config>/ops/ directory yet: the first `set --global` must create it,
    // not fail to write.
    let fx = Fixture::new();
    let out = fx.run(&["config", "set", "env.G", "1", "--global"]);
    assert!(
        out.status.success(),
        "set --global on a fresh config dir:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let got = fx.run(&["config", "get", "env.G", "--global"]);
    assert!(got.status.success());
    assert_eq!(String::from_utf8_lossy(&got.stdout).trim(), "1");
}

#[test]
fn config_set_into_a_non_scalar_field_is_refused() {
    let fx = Fixture::new();
    fx.write_project("binds = [\"/tmp\"]\n");
    let out = fx.run(&["config", "set", "binds", "/var"]);
    assert!(
        !out.status.success(),
        "setting an array as a scalar must fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("edit"),
        "the error should point at `ops config edit`"
    );
}

#[test]
fn config_edit_runs_the_editor_and_warns_when_it_re_arms_trust() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::new();
    fx.write_project("nixpkgs = \"nixos-23.11\"\n");
    assert!(fx.run(&["trust", ".ops.toml"]).status.success());

    // A non-interactive "editor": a script that appends a line to its file argument, standing in
    // for a real $EDITOR so the test stays headless.
    let editor = fx.bind_dir.path().join("fake-editor.sh");
    std::fs::write(
        &editor,
        "#!/bin/sh\nprintf '\\n[env]\\nEDITED = \"yes\"\\n' >> \"$1\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = fx
        .ops(&["config", "edit"])
        .env("EDITOR", &editor)
        .env_remove("VISUAL")
        .output()
        .expect("spawn ops");
    assert!(out.status.success(), "edit should exit 0");

    let after = std::fs::read_to_string(fx.proj.path().join(".ops.toml")).unwrap();
    assert!(
        after.contains("EDITED = \"yes\""),
        "the editor ran:\n{after}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("re-armed the trust gate"),
        "changing a trusted file must warn:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
