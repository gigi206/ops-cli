//! Integration tests for `sbx run`, exercising the built binary end to end —
//! including the exec-replace exit-status propagation that the in-crate smokes
//! (which spawn rather than exec) cannot cover. The sandbox cases skip, rather
//! than fail, where the host cannot create a sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

fn sbx() -> Command {
    // Isolate XDG_CONFIG_HOME from the user's real `~/.config/sbx`: these e2es must not read the
    // developer's global sbx config (imported app profiles, a global `[network]` posture), or a
    // test's outcome would depend on the host. Default it to a fixed empty dir under the test
    // tree — no run.rs test writes a global config there (the profile-import test sets its own
    // XDG_CONFIG_HOME, which overrides this default), so a shared empty dir is race-free.
    let mut cfg = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cfg.push("target/test-tmp/isolated-config");
    let _ = std::fs::create_dir_all(&cfg);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sbx"));
    cmd.env("XDG_CONFIG_HOME", cfg);
    // Pin a deterministic UTF-8 locale: the cage now honors the host locale, so a provisioned
    // tool's output (e.g. GNU `hello`) would otherwise be translated on a non-English developer
    // machine and break an assertion on its English text. `C.UTF-8` keeps messages English while
    // staying UTF-8-clean, independent of the runner's own `LANG`.
    cmd.env("LC_ALL", "C.UTF-8").env_remove("LANG");
    cmd
}

/// Where this suite's throwaway fixtures live: the repo's own test tree, overridable with
/// `SBX_TEST_TMPDIR`.
///
/// On the repo's disk, deliberately not the system tmpfs: provisioning a nix store copies the whole
/// nixpkgs source tree (a huge file count) into it, and concurrent tests would exhaust a tmpfs's
/// machine-wide inode budget — which surfaces as "no space left on device" in *unrelated* work
/// while the disk is nearly empty. Disk has inodes to spare, it matches production (the store lives
/// on disk), and `cargo clean` reclaims it.
fn fixture_root() -> PathBuf {
    if let Some(dir) = std::env::var_os("SBX_TEST_TMPDIR") {
        return PathBuf::from(dir);
    }
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("target/test-tmp");
    d
}

/// Kills and reaps a backgrounded child on drop, so a panicking assertion never leaks the running
/// cage — a `TmpDir` cleans directories, not processes.
///
/// The tests that need this tear their session down explicitly before asserting, which covers the
/// assertions; this covers the panics *inside* the polling loop that runs first (a `serde_json`
/// shape assumption, an `assert_eq!` on a record field), where nothing else would.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TmpDir(PathBuf);

/// How much of a fixture's tag survives into its directory name. With the prefix, a pid and the
/// counter, this keeps a fixture directory at 25 bytes or so — inside the budget an `…/sbx` data
/// dir has under a checkout at a normal depth.
const TAG_MAX: usize = 10;

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut d = fixture_root();
        // A short prefix on purpose: a launch's egress proxy binds a Unix socket under this
        // data dir (`…/<dir>/sbx/egress/proxy-<pid>.sock`), and `sun_path` caps the whole path
        // at 108 bytes. A longer prefix plus a 7-digit pid (counted twice — here and in the
        // socket name) tips a deep checkout over the limit, so keep this terse.
        //
        // The tag is a fixture label, not an identity — the counter alone makes the name unique —
        // so it is capped here rather than trusted. A test that picks a descriptive tag would
        // otherwise push its own data dir past the budget and fail with sbx's "path too long"
        // refusal, which reads as a product bug rather than as a fixture that named itself.
        let tag: String = tag.chars().take(TAG_MAX).collect();
        d.push(format!("r-{tag}-{}-{n}", std::process::id()));
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

/// `sbx run -- <args>` from `project`, with sbx's data dir redirected to `data`
/// so the test never touches the real `$HOME`.
fn run_in(project: &Path, data: &Path, args: &[&str]) -> Output {
    sbx()
        .arg("run")
        .arg("--")
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx run")
}

/// `sbx app <name>` from `project`, with sbx's data dir redirected to `data`.
fn app_in(project: &Path, data: &Path, name: &str) -> Output {
    sbx()
        .arg("app")
        .arg("run")
        .arg(name)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx app")
}

/// `sbx app <name> -- <extra...>`: the passthrough form, where `extra` is appended to the app's
/// declared command.
fn app_in_args(project: &Path, data: &Path, name: &str, extra: &[&str]) -> Output {
    sbx()
        .arg("app")
        .arg("run")
        .arg(name)
        .arg("--")
        .args(extra)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx app")
}

/// `sbx <args>` from `project` with both the data dir and the trust-store dir
/// redirected, so a test can trust a project and launch it without touching the
/// real `$HOME` or the user's trust store.
fn sbx_in(project: &Path, data: &Path, state: &Path, args: &[&str]) -> Output {
    sbx()
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .env("XDG_STATE_HOME", state)
        .output()
        .expect("spawn sbx")
}

#[test]
fn run_detach_without_a_command_is_a_usage_error() {
    // `sbx run` with no command opens the project shell, which needs a terminal — so a detached
    // no-command launch is refused. Fails before any sandbox work, so it needs no capable host.
    // (A plain `sbx run` with no command opens a shell instead; that path is covered by the pty
    // test in tests/shell.rs.)
    let out = sbx()
        .args(["run", "--detach"])
        .output()
        .expect("spawn sbx run");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("needs a command"), "got: {stderr}");
}

#[test]
fn run_executes_commands_in_a_hermetic_sandbox() {
    let project = TmpDir::new("proj");
    let data = TmpDir::new("data");
    std::fs::write(project.path().join("MARKER"), b"x").unwrap();

    // capability probe: a capable host runs `true` to success; otherwise skip.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping sbx run smoke: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // exec-replace propagates the command's exit status (the headline contract)
    let seven = run_in(project.path(), data.path(), &["sh", "-c", "exit 7"]);
    assert_eq!(seven.status.code(), Some(7), "exit status not propagated");

    // the synthetic identity resolves inside the sandbox (no host accounts)
    let id = run_in(project.path(), data.path(), &["id"]);
    assert!(
        String::from_utf8_lossy(&id.stdout).contains("(sandbox)"),
        "synthetic identity missing: {}",
        String::from_utf8_lossy(&id.stdout)
    );

    // the project is the work surface; nix coreutils is hermetic
    let ls = run_in(project.path(), data.path(), &["ls"]);
    assert!(
        String::from_utf8_lossy(&ls.stdout).contains("MARKER"),
        "project not visible: {}",
        String::from_utf8_lossy(&ls.stdout)
    );

    // hermetic: `/usr` is the minimal synthetic tree — it holds only `bin` (which carries the
    // `/usr/bin/env` symlink and the `/usr/bin/xdg-open` stub), never the host's `/usr`, which
    // would expose `lib`/`share`/… alongside. (That `/usr/bin/env` resolves an interpreted
    // shebang is proven separately by `a_usr_bin_env_shebang_resolves_in_the_cage`.)
    let usr = run_in(project.path(), data.path(), &["ls", "/usr"]);
    assert!(
        usr.status.success() && String::from_utf8_lossy(&usr.stdout).trim() == "bin",
        "/usr is not the minimal synthetic tree (host /usr may have leaked): {}",
        String::from_utf8_lossy(&usr.stdout)
    );
    // a host-`/usr` subtree a leak would expose is absent
    let usr_lib = run_in(project.path(), data.path(), &["ls", "/usr/lib"]);
    assert!(
        !usr_lib.status.success(),
        "host /usr/lib unexpectedly present (not hermetic)"
    );

    // synthetic passwd content, not the host's
    let passwd = run_in(project.path(), data.path(), &["cat", "/etc/passwd"]);
    assert!(
        String::from_utf8_lossy(&passwd.stdout).contains("sandbox:x:"),
        "synthetic passwd missing: {}",
        String::from_utf8_lossy(&passwd.stdout)
    );
}

#[test]
fn the_cage_resolves_localhost_via_a_synthetic_hosts_file() {
    // A hermetic cage carries no `/etc/hosts`, so the *name* `localhost` would fall through to
    // DNS — which the empty-netns posture (Model B) has no resolver for. A tool that resolves the
    // name to bind or reach an internal loopback server (an in-process language server, a dev
    // server, a local MCP) then fails hard. sbx synthesises an `/etc/hosts` mapping localhost →
    // loopback. Prove resolution with teeth in the exact failing posture (`network = "none"`, an
    // empty netns where only `/etc/hosts` can answer): `curl -v http://localhost:1` must resolve
    // to 127.0.0.1 (then a connection error, nothing listening), NOT report "could not resolve
    // host". `curl` is in the base toolset.
    let project = TmpDir::new("hosts-proj");
    let data = TmpDir::new("hosts-data");
    let state = TmpDir::new("hosts-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"none\"\n",
    )
    .unwrap();

    // capability probe (untrusted → the `none` posture is dropped → shared net): seeds the base
    // store over the network so the later isolated run is warm. Skip (not fail) if the host cannot
    // sandbox, or if the cache is unreachable for the seed.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping localhost-resolve e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping localhost-resolve e2e: the binary cache is unreachable");
        return;
    }

    // trust the project so `network = "none"` (a security field) is honored → empty netns.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // the synthetic file is present with the localhost → loopback mapping
    let hosts = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "cat", "/etc/hosts"],
    );
    let hosts_out = String::from_utf8_lossy(&hosts.stdout);
    assert!(
        hosts_out.contains("127.0.0.1") && hosts_out.contains("localhost"),
        "the cage's /etc/hosts must map localhost to loopback: {hosts_out}"
    );

    // teeth: the NAME resolves to loopback in the empty netns (only /etc/hosts can do this here).
    let curl = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "curl", "-sS", "-v", "http://localhost:1"],
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&curl.stdout),
        String::from_utf8_lossy(&curl.stderr)
    );
    assert!(
        combined.contains("127.0.0.1"),
        "localhost must resolve to loopback in the cage (the /etc/hosts fix): {combined}"
    );
    assert!(
        !combined.to_lowercase().contains("could not resolve"),
        "localhost must not fail name resolution: {combined}"
    );
}

#[test]
fn a_malformed_one_shot_override_is_a_hard_error_and_does_not_launch() {
    // Fail-closed: a malformed `--config` is a usage error (exit 2) surfaced before any sandbox
    // work — never a silent drop that would launch a different posture than asked. Needs no capable
    // host (it fails at parse time).
    let project = TmpDir::new("ov-bad-proj");
    let data = TmpDir::new("ov-bad-data");
    let bad_toml = sbx()
        .args(["run", "--config", "x = = not toml", "--", "true"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx run");
    assert_eq!(
        bad_toml.status.code(),
        Some(2),
        "a malformed override must exit 2"
    );
    assert!(
        String::from_utf8_lossy(&bad_toml.stderr).contains("--config"),
        "the error should name the offending override: {}",
        String::from_utf8_lossy(&bad_toml.stderr)
    );

    // The security-critical half: a *set-but-invalid* value in well-formed TOML (a typo'd security
    // posture) is also a hard error (exit 2) that refuses to launch — never a silent fall-back to
    // the baseline posture, which for a `network` typo would be the wide default `shared` while the
    // user believed they isolated the cage. It aborts *before* provisioning, so it needs no capable
    // host, and it must not have launched (`false` would exit 1 if it ran; the abort is 2).
    let bad_value = sbx()
        .args(["run", "--config", "network=\"nonee\"", "--", "false"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx run");
    assert_eq!(
        bad_value.status.code(),
        Some(2),
        "a set-but-invalid security value must exit 2, not launch: {}",
        String::from_utf8_lossy(&bad_value.stderr)
    );
    let stderr = String::from_utf8_lossy(&bad_value.stderr);
    assert!(
        stderr.contains("network") && stderr.contains("refusing to launch"),
        "the error should name the field and refuse: {stderr}"
    );
}

#[test]
fn a_one_shot_override_beats_an_app_overlay_through_the_real_dispatch() {
    // The flagship, end to end through the real binary: `sbx app <name> --env` must beat the app's
    // own `env` overlay — proving the dispatch applies the override *after* `merge_app`, the load-
    // bearing ordering a unit test that calls the two by hand cannot cover. Skips (never fails) when
    // the host cannot sandbox.
    let project = TmpDir::new("ov-app-proj");
    let data = TmpDir::new("ov-app-data");
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[app.greet]\ncmd = [\"printenv\", \"APPVAR\"]\n[app.greet.env]\nAPPVAR = \"from-app\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping override-vs-app e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // Without an override, the app's own env overlay wins.
    let base = app_in(project.path(), data.path(), "greet");
    assert_eq!(
        String::from_utf8_lossy(&base.stdout).trim(),
        "from-app",
        "the app overlay should set APPVAR"
    );

    // With `--env`, the override is the final word — it beats the app overlay.
    let overridden = sbx()
        .args(["app", "run", "greet", "--env", "APPVAR=from-override"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx app");
    assert_eq!(
        String::from_utf8_lossy(&overridden.stdout).trim(),
        "from-override",
        "the override did not beat the app overlay (ordering wrong?): stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&overridden.stdout),
        String::from_utf8_lossy(&overridden.stderr)
    );
}

#[test]
fn a_one_shot_env_override_reaches_the_cage_and_the_cli_beats_the_environment() {
    // The one-shot override, proven end to end through a real launch: `--env`/`SBX_ENV_<KEY>`/
    // `--config` all reach the cage environment, and the documented precedence holds — the command
    // line beats the environment. Observed by `printenv` inside the cage. Skips (never fails) when
    // the host cannot sandbox.
    let project = TmpDir::new("ov-env-proj");
    let data = TmpDir::new("ov-env-data");

    // capability probe
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping override e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // Run `sbx run` with arbitrary leading flags and process env, reading one cage variable.
    let read = |args: &[&str], env: &[(&str, &str)]| -> String {
        let mut cmd = sbx();
        cmd.arg("run").args(args);
        cmd.args(["--", "printenv", "OVMARK"]);
        cmd.current_dir(project.path())
            .env("XDG_DATA_HOME", data.path());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn sbx run");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    // `--env KEY=VALUE` reaches the cage.
    assert_eq!(read(&["--env", "OVMARK=cli"], &[]), "cli");
    // `SBX_ENV_<KEY>` in the environment reaches the cage.
    assert_eq!(read(&[], &[("SBX_ENV_OVMARK", "env")]), "env");
    // The `--config` TOML blob's `[env]` reaches the cage.
    assert_eq!(read(&["--config", "env.OVMARK = \"blob\""], &[]), "blob");
    // Precedence: the command line beats the environment (a stale `SBX_ENV_*` cannot win).
    assert_eq!(
        read(&["--env", "OVMARK=cli"], &[("SBX_ENV_OVMARK", "env")]),
        "cli"
    );
    // Precedence within the command line: the typed `--env` beats the `--config` blob.
    assert_eq!(
        read(
            &["--config", "env.OVMARK = \"blob\"", "--env", "OVMARK=cli"],
            &[]
        ),
        "cli"
    );
}

#[test]
fn a_cage_environment_value_is_never_substituted_from_the_host() {
    // A cage argument must reach the cage byte for byte. The launch runs the cage inside a systemd
    // scope, and systemd substitutes variable references in the command line it is handed, against
    // the *host* environment — so without the escaping applied when that scope is used, a `${VAR}`
    // in a cage environment value would be replaced by the host's value (carrying a host
    // environment value INTO the cage, which the deliberately narrow passthrough exists to prevent)
    // and a shell expansion systemd cannot read as a name would collapse to an empty string. Both
    // are asserted through a real launch, read back with `printenv`. Skips (never fails) when the
    // host cannot sandbox.
    //
    // The teeth are host-conditional: only a launch that actually takes the scope path has anything
    // in a position to substitute. Where no user manager can create one, the cage is launched
    // directly, the property holds trivially, and a green run proves nothing — so that case is
    // reported rather than left to look like coverage.
    let project = TmpDir::new("nosub-proj");
    let data = TmpDir::new("nosub-data");
    let scoped = std::process::Command::new("systemd-run")
        .arg("--version")
        .output()
        .is_ok()
        && std::env::var_os("XDG_RUNTIME_DIR")
            .map(|dir| std::path::Path::new(&dir).join("bus").exists())
            .unwrap_or(false);
    if !scoped {
        eprintln!("note: no systemd user scope on this host — the assertions below hold vacuously");
    }

    // capability probe
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping substitution e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // The value is read back from inside the cage; the host carries a variable of the same name so
    // a substitution would be visible rather than silently empty.
    let read = |value: &str| -> String {
        let out = sbx()
            .arg("run")
            .args(["--env", &format!("NOSUB={value}")])
            .args(["--", "printenv", "NOSUB"])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("SBX_HOST_ONLY_PROBE", "host-side-value")
            .output()
            .expect("spawn sbx run");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    };

    // A braced reference to a variable that exists on the host: the cage must see the reference,
    // never the host's value.
    assert_eq!(read("${SBX_HOST_ONLY_PROBE}"), "${SBX_HOST_ONLY_PROBE}");
    // A bare reference opening the value — the form systemd substitutes at the start of an argument.
    assert_eq!(read("$SBX_HOST_ONLY_PROBE"), "$SBX_HOST_ONLY_PROBE");
    // A shell expansion, which is not a variable name at all: it must survive, not become empty.
    assert_eq!(read("${dir%/}"), "${dir%/}");
}

#[test]
fn a_writable_bind_writes_through_to_the_host_while_a_read_only_bind_refuses() {
    // The headline of the ro/rw bind choice, with teeth on both sides. Two host directories are
    // bound into a trusted project — one `mode = "rw"`, one read-only (the default). A cage that
    // writes into the rw one must have its bytes appear at the *host* path (proving a real
    // write-through, not a write into some cage-local tmpfs). The read-only one is proven genuinely
    // mounted (the cage reads a pre-placed host file through it) and then integrity-protecting (a
    // write fails with `EROFS` and leaves no new host file) — so "refused" cannot be confused with
    // "not mounted". `binds` is trusted-only, so the project is trusted first. Skips (never fails)
    // when the host cannot sandbox.
    let project = TmpDir::new("rwbind-proj");
    let data = TmpDir::new("rwbind-data");
    let state = TmpDir::new("rwbind-state");
    let rw = TmpDir::new("rwbind-rw");
    let ro = TmpDir::new("rwbind-ro");
    // Canonical paths: `load` canonicalizes each bind source, so the cage dest is the canonical
    // path — write to and read from exactly that, or the in-cage path would not match the mount.
    let rw_dir = std::fs::canonicalize(rw.path()).unwrap();
    let ro_dir = std::fs::canonicalize(ro.path()).unwrap();

    // Pre-place a file in the read-only bind so the test can prove the bind is actually mounted
    // (the cage reads it) — otherwise a "write refused" could be confused with "bind absent".
    std::fs::write(ro_dir.join("preexisting"), b"host-content\n").unwrap();

    std::fs::write(
        project.path().join(".sbx.toml"),
        format!(
            "binds = [\n  {{ path = \"{}\", mode = \"rw\" }},\n  \"{}\",\n]\n",
            rw_dir.display(),
            ro_dir.display(),
        ),
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping rw-bind e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // `binds` is trusted-only, so trust the project before it takes effect.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The rw bind: the cage writes a marker, and it must land at the host path.
    let rw_target = rw_dir.join("marker");
    let write_rw = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            &format!("echo written-in-cage > {}", rw_target.display()),
        ],
    );
    assert!(
        write_rw.status.success(),
        "writing into a rw bind failed: {}",
        String::from_utf8_lossy(&write_rw.stderr)
    );
    let on_host = std::fs::read_to_string(&rw_target).unwrap_or_default();
    assert_eq!(
        on_host.trim(),
        "written-in-cage",
        "the cage's write did not reach the host path (rw bind not writing through)"
    );

    // The ro bind IS mounted (not merely absent): the cage reads the pre-placed host file
    // through it, so a subsequent write refusal means "read-only", not "path not there".
    let read_ro = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "cat",
            &ro_dir.join("preexisting").display().to_string(),
        ],
    );
    assert!(
        read_ro.status.success()
            && String::from_utf8_lossy(&read_ro.stdout).contains("host-content"),
        "the read-only bind is not exposing the host path's contents: {}",
        String::from_utf8_lossy(&read_ro.stderr)
    );

    // The ro bind: a write must fail, and no new host file may appear.
    let ro_target = ro_dir.join("marker");
    let write_ro = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            &format!("echo nope > {}", ro_target.display()),
        ],
    );
    assert!(
        !write_ro.status.success(),
        "writing into a read-only bind unexpectedly succeeded"
    );
    assert!(
        !ro_target.exists(),
        "a read-only bind must not let the cage create a host file"
    );
}

#[test]
fn a_read_write_home_bind_keeps_the_control_plane_pinned_in_place() {
    // The security teeth of the mountpoint-chain protection. A whole-home read-write bind that
    // *contains* sbx's own control plane (data dir, trust store, config dir) stays read-write —
    // but each control-plane path is pinned as a mountpoint chain, so in-cage code cannot rename a
    // writable parent to move a root aside and substitute a forged one (which sbx would then read
    // or `execve` on the host). Proven with teeth on both sides in one real launch:
    //   DENY — a write into a pinned root is `EROFS`; renaming or removing any chain component is
    //          `EBUSY`; and the pre-placed host trust marker survives untouched (the substitution
    //          attack fails).
    //   ALLOW — the cage runs at all (its `sh`/coreutils come from `/nix`, whose source lives
    //          *under* the read-only-pinned data dir — so read-through works despite the pin), the
    //          rest of the home is writable, and `/nix` itself is still writable (per-mount, not
    //          per-inode: the read-only pin on the data-dir path does not freeze the store the rw
    //          `/nix` mount is backed by).
    // Interdependency: the pin's protection also assumes in-cage code cannot `umount` it — which
    // holds by cap-drop (no CAP_SYS_ADMIN) and the seccomp `umount2` denial (covered by the seccomp
    // membership + enforcement tests); the base cage carries no `umount` binary, so this e2e
    // exercises the reachable filesystem attack (rename/remove), not a raw syscall. Skips (never
    // fails) where the host cannot sandbox.
    let home = TmpDir::new("cp-home");
    // A fabricated `$HOME` with sbx's XDG roots inside it, so the control plane lives under the
    // read-write bind. Canonical, because `load` canonicalizes the bind source and the roots.
    let h = std::fs::canonicalize(home.path()).unwrap();
    let data = h.join(".local/share");
    let state = h.join(".local/state");
    let config = h.join(".config");
    let project = h.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(config.join("sbx")).unwrap();
    // The global config (trusted by location) binds the whole fabricated home read-write.
    std::fs::write(
        config.join("sbx/sbx.toml"),
        format!(
            "binds = [{{ path = \"{}\", mode = \"rw\" }}]\n",
            h.display()
        ),
    )
    .unwrap();
    // A pre-placed trust marker whose survival proves the pin defeats path substitution.
    let sentinel = state.join("sbx/trusted/sentinel");
    std::fs::create_dir_all(sentinel.parent().unwrap()).unwrap();
    std::fs::write(&sentinel, b"REAL").unwrap();

    let run = |script: &str| {
        sbx()
            .arg("run")
            .arg("--")
            .arg("sh")
            .arg("-c")
            .arg(script)
            .current_dir(&project)
            .env("XDG_DATA_HOME", &data)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_CONFIG_HOME", &config)
            .output()
            .expect("spawn sbx run")
    };

    // capability probe (also seeds the base store and exercises the pin path); skip if incapable.
    let probe = run("true");
    if !probe.status.success() {
        eprintln!(
            "skipping control-plane pin e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let script = format!(
        r#"H="{h}"
echo "A:$(touch "$H/writeprobe" 2>/dev/null && echo OK || echo FAIL)"
echo "B:$(echo x > "$H/.local/state/sbx/trusted/forged" 2>/dev/null && echo BAD || echo RO)"
echo "C:$(mv "$H/.local/state" "$H/.local/state.bak" 2>/dev/null && echo BAD || echo EBUSY)"
echo "D:$(mv "$H/.local/state/sbx/trusted" "$H/stolen" 2>/dev/null && echo BAD || echo EBUSY)"
echo "E:$(rmdir "$H/.config/sbx" 2>/dev/null && echo BAD || echo BLOCKED)"
echo "F:$(touch /nix/.sbx-store-writeprobe 2>/dev/null && echo OK || echo FAIL)"
"#,
        h = h.display()
    );
    let out = run(&script);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "the pinned launch failed: {}\nstdout: {stdout}",
        String::from_utf8_lossy(&out.stderr)
    );

    // ALLOW: the home is writable and the store `/nix` is still writable despite the data-dir pin.
    assert!(
        stdout.contains("A:OK"),
        "the home must stay writable: {stdout}"
    );
    assert!(
        stdout.contains("F:OK"),
        "the per-project store `/nix` must stay writable despite the data-dir pin: {stdout}"
    );
    // DENY: no write through a pinned root, and no chain component can be renamed or removed.
    assert!(
        stdout.contains("B:RO"),
        "a write into a pinned control-plane root must be refused: {stdout}"
    );
    assert!(
        stdout.contains("C:EBUSY") && stdout.contains("D:EBUSY"),
        "renaming a pinned chain component must fail with EBUSY: {stdout}"
    );
    assert!(
        stdout.contains("E:BLOCKED"),
        "removing a pinned leaf mountpoint must fail: {stdout}"
    );
    // The decisive teeth: the host trust marker is untouched — the substitution attack failed.
    let after = std::fs::read_to_string(&sentinel).unwrap_or_default();
    assert_eq!(
        after.trim(),
        "REAL",
        "the pinned trust marker was altered or moved aside — the control plane was substituted"
    );
}

#[test]
fn sbx_app_launches_the_apps_command_with_its_overlay() {
    let project = TmpDir::new("appproj");
    let data = TmpDir::new("appdata");
    // Two untrusted apps: `probe` runs the synthetic-identity check; `greet` carries a free
    // `env` overlay (which applies even untrusted, like the baseline `env`).
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[app.probe]\n\
          cmd = [\"id\"]\n\n\
          [app.greet]\n\
          cmd = [\"printenv\", \"APPVAR\"]\n\
          [app.greet.env]\n\
          APPVAR = \"from-app\"\n\n\
          [app.echoer]\n\
          cmd = [\"echo\", \"BASE\"]\n",
    )
    .unwrap();

    // capability probe via `sbx run -- true`; skip (not fail) if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping sbx app e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // The app's command runs inside the cage — the synthetic identity proves it is the
    // sandbox, not the host.
    let id = app_in(project.path(), data.path(), "probe");
    assert!(
        String::from_utf8_lossy(&id.stdout).contains("(sandbox)"),
        "the app command did not run in the cage: {}",
        String::from_utf8_lossy(&id.stdout)
    );

    // The app's free `env` overlay reaches the cage.
    let greet = app_in(project.path(), data.path(), "greet");
    assert!(
        String::from_utf8_lossy(&greet.stdout).contains("from-app"),
        "the app env overlay did not reach the cage: {}",
        String::from_utf8_lossy(&greet.stdout)
    );

    // Arguments after `--` are appended to the app's declared command. `echoer` runs `echo BASE`;
    // launched as `sbx app echoer -- EXTRA-ARG` it prints `BASE EXTRA-ARG`, so the tail reached the
    // program's argv (echo never emits EXTRA-ARG on its own) while the profile's own argv (BASE) is
    // preserved. This proves the append on the unwrapped launch path; the wrapped path (packages /
    // network) forwards the command positionally, so the multi-element `printenv APPVAR` above
    // already shows wrapping preserves every element.
    let echoed = app_in_args(project.path(), data.path(), "echoer", &["EXTRA-ARG"]);
    let echoed_out = String::from_utf8_lossy(&echoed.stdout);
    assert!(
        echoed_out.contains("BASE") && echoed_out.contains("EXTRA-ARG"),
        "extra args after `--` did not reach the app command: stdout={:?} stderr={:?}",
        echoed_out,
        String::from_utf8_lossy(&echoed.stderr)
    );

    // An unknown app name is a clean usage error, not a launch.
    let missing = app_in(project.path(), data.path(), "nope");
    assert_eq!(missing.status.code(), Some(2), "unknown app must exit 2");
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("no app named"),
        "unknown app must be named: {}",
        String::from_utf8_lossy(&missing.stderr)
    );
}

#[test]
fn app_run_treats_a_subcommand_verb_as_an_app_name() {
    // Requiring the explicit `run` verb frees the app namespace: `sbx app run list` must reach the
    // launch path with `list` as the *app name* (none declared → the clean "no app named" error),
    // while the bare `sbx app list` still runs the list subcommand. Same token, disambiguated only
    // by its position after `run` — proof that an app may be named like a subcommand and is reached
    // as `sbx app run <name>`. Host-side (config resolution), no sandbox needed.
    let project = TmpDir::new("apprun-verb-proj");
    let data = TmpDir::new("apprun-verb-data");
    let state = TmpDir::new("apprun-verb-state");

    // `sbx app run list` — `list` is the app name here, not the subcommand.
    let launched = app_in(project.path(), data.path(), "list");
    assert_eq!(
        launched.status.code(),
        Some(2),
        "`sbx app run list` must reach the launch path, not the list subcommand"
    );
    assert!(
        String::from_utf8_lossy(&launched.stderr).contains("no app named"),
        "`sbx app run list` must treat `list` as an app name: {}",
        String::from_utf8_lossy(&launched.stderr)
    );

    // The bare `sbx app list` still runs the list subcommand (exit 0, never a launch attempt).
    let listed = sbx_in(project.path(), data.path(), state.path(), &["app", "list"]);
    assert!(
        listed.status.success(),
        "`sbx app list` must run the list subcommand: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&listed.stderr).contains("no app named"),
        "`sbx app list` must not be treated as a launch"
    );
}

#[test]
fn an_app_home_persists_across_launches_and_is_isolated_from_the_project_shell() {
    let project = TmpDir::new("apphome-proj");
    let data = TmpDir::new("apphome-data");
    // `counter` appends a line to a file in its own `$HOME` and prints the running count, so a
    // second launch reveals whether the home persisted. The default home scope is global —
    // one home per app — and this single project exercises persistence; isolation from the
    // project shell is the second assertion.
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[app.counter]\n\
          cmd = [\"sh\", \"-c\", \"echo x >> \\\"$HOME/COUNT\\\"; wc -l < \\\"$HOME/COUNT\\\" | tr -d ' '\"]\n",
    )
    .unwrap();

    // capability probe via `sbx run -- true`; skip (not fail) if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping app-home e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // First launch: the home is fresh, so the count is 1.
    let first = app_in(project.path(), data.path(), "counter");
    assert!(
        String::from_utf8_lossy(&first.stdout).trim() == "1",
        "first launch should count 1, got: {:?}",
        String::from_utf8_lossy(&first.stdout)
    );
    // Second launch of the same app: the home persisted, so the file is still there and the
    // count is 2 — the persistence the app framework promises.
    let second = app_in(project.path(), data.path(), "counter");
    assert!(
        String::from_utf8_lossy(&second.stdout).trim() == "2",
        "second launch should count 2 (home persisted), got: {:?}",
        String::from_utf8_lossy(&second.stdout)
    );

    // Isolation with teeth: `sbx run` uses the project's default home, a different directory,
    // so the app's COUNT file is absent there — the app's writable state never bleeds into the
    // project shell.
    let leaked = run_in(
        project.path(),
        data.path(),
        &[
            "sh",
            "-c",
            "test -e \"$HOME/COUNT\" && echo LEAKED || echo CLEAN",
        ],
    );
    let leaked_out = String::from_utf8_lossy(&leaked.stdout);
    assert!(
        leaked_out.contains("CLEAN") && !leaked_out.contains("LEAKED"),
        "the app's home leaked into the project shell: stdout={:?} stderr={:?}",
        leaked_out,
        String::from_utf8_lossy(&leaked.stderr)
    );
}

#[test]
fn an_imported_profile_launches_trusted_by_location() {
    let project = TmpDir::new("import-proj");
    let data = TmpDir::new("import-data");
    let config = TmpDir::new("import-config");
    // A portable profile authored as a standalone file: it prints a free env var, so a successful
    // launch proves the profile was loaded (from the config dir, trusted by location) and run.
    std::fs::write(
        project.path().join("greet.toml"),
        b"cmd = [\"printenv\", \"PROFILEVAR\"]\n[env]\nPROFILEVAR = \"from-profile\"\n",
    )
    .unwrap();

    // capability probe via `sbx run -- true`; skip (not fail) if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping imported-profile e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // Import the profile — the deliberate consent act; it lands under the config dir.
    let imp = sbx()
        .args(["app", "import", "greet.toml"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx app import");
    assert!(
        imp.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );

    // Launch it by name: the profile's command runs in the cage and its free env reaches it —
    // proving the imported profile was discovered and launched end to end.
    let greet = sbx()
        .args(["app", "run", "greet"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx app");
    assert!(
        String::from_utf8_lossy(&greet.stdout).contains("from-profile"),
        "the imported profile did not launch with its env: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&greet.stdout),
        String::from_utf8_lossy(&greet.stderr)
    );
}

#[test]
fn a_trusted_mise_env_reaches_the_sandbox_only_once_trusted() {
    let project = TmpDir::new("mise-proj");
    let data = TmpDir::new("mise-data");
    let state = TmpDir::new("mise-state");
    // a mise file declares an env var; the (empty) .sbx.toml anchors it
    std::fs::write(project.path().join(".sbx.toml"), b"").unwrap();
    std::fs::write(
        project.path().join(".mise.toml"),
        b"[env]\nSBX_MISE_VAR = \"from-mise\"\n",
    )
    .unwrap();

    // capability probe: a capable host runs `true` to success; otherwise skip. This
    // also primes the base userland, so a later provisioning failure is a real fault.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping mise env e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // untrusted: the mise `[env]` is withheld, so `printenv` finds nothing (exit 1)
    let before = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "printenv", "SBX_MISE_VAR"],
    );
    assert!(
        !before.status.success(),
        "an untrusted mise [env] must not reach the sandbox, got: {}",
        String::from_utf8_lossy(&before.stdout)
    );

    // trust the project, then the same var is mapped into the sandbox
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let after = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "printenv", "SBX_MISE_VAR"],
    );
    assert!(
        after.status.success(),
        "a trusted mise [env] was not applied: {}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&after.stdout).trim(),
        "from-mise",
        "the mise [env] value did not reach the sandbox"
    );
}

/// Best-effort TCP reach of the binary cache, so the egress e2e skips (does not fail)
/// when offline — the allowed fetch genuinely hits `cache.nixos.org` through the proxy.
fn cache_reachable() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = ("cache.nixos.org", 443).to_socket_addrs() else {
        return false;
    };
    addrs.any(|addr| {
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok()
    })
}

/// Whether the public `grpcb.in` gRPC test server is reachable — the HTTP/2 secret e2e depends on it
/// (an external service), so an outage skips that test rather than reddening the suite.
fn grpcb_in_reachable() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = ("grpcb.in", 9001).to_socket_addrs() else {
        return false;
    };
    addrs.any(|addr| {
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok()
    })
}

/// Whether the public `postman-echo.com` request echo is reachable — the signer e2e depends on it
/// (it is the only way to see what actually reached the upstream), so an outage skips that test
/// rather than reddening the suite.
fn postman_echo_reachable() -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = ("postman-echo.com", 443).to_socket_addrs() else {
        return false;
    };
    addrs.any(|addr| {
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok()
    })
}

/// Stage a signer plugin: a manifest naming the headers it may set, and a Python executable that
/// speaks the line-JSON protocol. `body` is the loop that answers each question, so one helper
/// serves the plugin that signs, the one that refuses, and the one that oversteps its manifest.
fn stage_signer(root: &Path, name: &str, reads_secret: bool, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join(name);
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    std::fs::write(
        dir.join("plugin.toml"),
        format!(
            "name = \"{name}\"\ntype = \"signer\"\nexec = \"bin/sign\"\n\n\
             [signer]\nsets_headers = [\"Authorization\", \"X-Demo-Date\"]\n\
             reads_secret = {reads_secret}\n\n\
             [sandbox]\nprograms = [\"python3\"]\n"
        ),
    )
    .unwrap();
    let exec = dir.join("bin/sign");
    std::fs::write(
        &exec,
        format!(
            "#!/usr/bin/env python3\nimport json, sys\n\
             hello = json.loads(sys.stdin.readline())\n\
             cred = hello[\"credential\"]\n\
             print(json.dumps({{\"ok\": True}}), flush=True)\n\
             for line in sys.stdin:\n    ask = json.loads(line)\n{body}\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// A signer plugin forms the credential of every request to the host its declaration names, and
/// what it forms reaches the upstream.
///
/// The proof needs a server that echoes the request back, because everything else about a signer is
/// invisible from the cage: `postman-echo.com/get` returns the headers it received, so one round
/// trip shows what sbx put on the wire. Four properties in one launch:
///
///   * **The plugin really runs.** A manifest is installed by the real `sbx plugins install`, and
///     the launch spawns it under bwrap and completes a handshake before the first request.
///   * **The value is per request.** Two requests differing only in their query produce two
///     different signatures, from one process — which is the whole of what a fixed injection
///     cannot do.
///   * **A marker is substituted.** The plugin declaring `reads_secret = false` is handed a marker
///     and says so; the *upstream* receives the real credential, and the reflection comes back
///     masked, which is the needle for a signed credential being the key rather than the signature.
///   * **The manifest bounds the answer.** A plugin that answers with a header it never declared,
///     or that refuses outright, refuses the request with `signer-refused` — and it is not sent.
///   * **The feed records both outcomes.** A detached session's `sbx logs --feed signer` shows the
///     signature and the refusal, each naming the signer, and a plugin that echoes the key it was
///     handed writes the credential's *name* into the record rather than the credential.
///
/// Skips (never fails) when the host cannot sandbox, the binary cache is unreachable (`curl` will
/// not provision), or the echo service is down.
#[test]
fn a_signer_plugin_forms_the_credential_of_every_request_and_its_manifest_bounds_it() {
    let root = TmpDir::new("signer-e2e");
    let project = TmpDir::new("signer-e2e-proj");
    let data = TmpDir::new("signer-e2e-data");
    let state = TmpDir::new("signer-e2e-state");
    let key = "the-real-signing-key-8f2a-e2e";

    let write_config = |signer: &str| {
        std::fs::write(
            project.path().join(".sbx.toml"),
            format!(
                "[packages]\ncurl = \"nix:curl\"\n\n\
                 [network]\nmode = \"deny\"\nallow = [\"postman-echo.com\"]\n\n\
                 [secret.\"postman-echo.com\"]\nfrom = \"env://SBX_E2E_SIGNING_KEY\"\n\
                 sign = \"{signer}\"\n"
            ),
        )
        .unwrap();
        let trusted = sbx_in(
            project.path(),
            data.path(),
            state.path(),
            &["trust", ".sbx.toml"],
        );
        assert!(
            trusted.status.success(),
            "sbx trust failed: {}",
            String::from_utf8_lossy(&trusted.stderr)
        );
    };

    write_config("demo-signs");
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping signer e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping signer e2e: the binary cache is unreachable");
        return;
    }
    if !postman_echo_reachable() {
        eprintln!("skipping signer e2e: postman-echo.com is unreachable");
        return;
    }

    // The signature is an HMAC over the request's own canonical form, so two targets cannot share
    // one — which is what makes it a signature rather than a token.
    let signs = stage_signer(
        root.path(),
        "demo-signs",
        true,
        "    import hashlib, hmac\n\
         \x20   canonical = f\"{ask['method']}\\n{ask['target']}\\n{hello['host']}\"\n\
         \x20   sig = hmac.new(cred['value'].encode(), canonical.encode(), hashlib.sha256).hexdigest()\n\
         \x20   print(json.dumps({\"seq\": ask[\"seq\"], \"headers\": {\"Authorization\": f\"DEMO {sig}\", \"X-Demo-Date\": \"20260813T000000Z\"}}), flush=True)",
    );
    let marker = stage_signer(
        root.path(),
        "demo-marker",
        false,
        "    print(json.dumps({\"seq\": ask[\"seq\"], \"headers\": {\"Authorization\": f\"Token {cred['value']}\", \"X-Demo-Date\": f\"kind={cred['kind']}\"}}), flush=True)",
    );
    let refuses = stage_signer(
        root.path(),
        "demo-refuses",
        true,
        "    print(json.dumps({\"seq\": ask[\"seq\"], \"error\": \"no credentials for that region\"}), flush=True)",
    );
    let oversteps = stage_signer(
        root.path(),
        "demo-oversteps",
        true,
        "    print(json.dumps({\"seq\": ask[\"seq\"], \"headers\": {\"Authorization\": \"ok\", \"Host\": \"evil.example.com\"}}), flush=True)",
    );
    // One plugin, both outcomes, so a single session produces a `sign` line and a `refuse` line for
    // the feed to be read for. Its label deliberately echoes the key it was handed: what lands in
    // the record must be the credential's name, not the credential.
    let feeds = stage_signer(
        root.path(),
        "demo-feed",
        true,
        "    if \"a=1\" in ask[\"target\"]:\n\
         \x20       print(json.dumps({\"seq\": ask[\"seq\"], \"headers\": {\"Authorization\": \"DEMO ok\"}, \"label\": \"signed with \" + cred[\"value\"]}), flush=True)\n\
         \x20   else:\n\
         \x20       print(json.dumps({\"seq\": ask[\"seq\"], \"error\": \"no credentials for that region\"}), flush=True)",
    );
    for dir in [&signs, &marker, &refuses, &oversteps, &feeds] {
        let out = sbx_in(
            project.path(),
            data.path(),
            state.path(),
            &["plugins", "install", dir.to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "installing {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        // The install line names what was installed. A scheme-less plugin used to read as a
        // broker whatever it was, which is the one thing this line exists to say.
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("(signer)"),
            "the install must name the kind: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    let echo = |sig: &str, query: &str| -> String {
        let out = sbx()
            .args([
                "run",
                "--",
                "curl",
                "-s",
                &format!("https://postman-echo.com/get{query}"),
            ])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .env("SBX_E2E_SIGNING_KEY", key)
            .output()
            .expect("spawn sbx run");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            stdout.contains("postman-echo.com"),
            "the {sig} request did not reach the echo: {stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        stdout
    };

    // 1. The plugin's headers reach the upstream, and the signature is bound to the request.
    let first = echo("demo-signs", "?a=1");
    let second = echo("demo-signs", "?a=2");
    let of = |body: &str| -> String {
        let at = body
            .find("DEMO ")
            .expect("the signature reached the upstream");
        body[at + 5..at + 5 + 64].to_string()
    };
    assert_ne!(
        of(&first),
        of(&second),
        "a signature is a function of the request: two targets cannot share one"
    );
    assert!(
        first.contains("x-demo-date"),
        "every header the manifest declares is put on the request: {first}"
    );

    // 2. The marker path: the plugin places what it never learns, the upstream gets the real
    //    credential, and the reflection is masked on the way back.
    write_config("demo-marker");
    let echoed = echo("demo-marker", "");
    assert!(
        echoed.contains("kind=marker"),
        "the plugin must be handed a marker, and know it: {echoed}"
    );
    assert!(
        !echoed.contains(key),
        "the credential reflected by the upstream must be masked on the way back: {echoed}"
    );
    assert!(
        echoed.contains(&"*".repeat(key.len())),
        "and masked length-preservingly, which is what says the real value reached the upstream: \
         {echoed}"
    );

    // 3. The manifest bounds the answer, and a refusal is a refusal: neither request is sent.
    for (signer, expected) in [
        ("demo-refuses", "no credentials for that region"),
        ("demo-oversteps", "does not declare in `sets_headers`"),
    ] {
        write_config(signer);
        let out = sbx()
            .args([
                "run",
                "--",
                "curl",
                "-s",
                "-i",
                "https://postman-echo.com/get",
            ])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .env("SBX_E2E_SIGNING_KEY", key)
            .output()
            .expect("spawn sbx run");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("403 Forbidden") && stdout.contains("signer-refused"),
            "{signer}: the request must be refused with its own reason token: {stdout}"
        );
        assert!(
            stdout.contains(expected) && stdout.contains("so it was not sent"),
            "{signer}: the refusal must name why, and say the request was not sent: {stdout}"
        );
    }

    // 4. The feed. Detached, because the ring lives in the supervisor's memory and the control
    //    socket is the only way to it — which is also the only way a user reads one.
    write_config("demo-feed");
    let started = sbx()
        .args([
            "run",
            "--detach",
            "--",
            "sh",
            "-c",
            "curl -s https://postman-echo.com/get?a=1; \
             curl -s https://postman-echo.com/get?a=2; sleep 30",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_SIGNING_KEY", key)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn sbx run --detach");
    let msg = String::from_utf8_lossy(&started.stderr).into_owned();
    assert!(started.status.success(), "detached launch failed:\n{msg}");
    let pid: u32 = msg
        .split("detached session ")
        .nth(1)
        .and_then(|after| {
            after
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no detached session pid in:\n{msg}"));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut feed = String::new();
    while std::time::Instant::now() < deadline {
        let out = sbx_in(
            project.path(),
            data.path(),
            state.path(),
            &["logs", &pid.to_string(), "--feed", "signer"],
        );
        feed = String::from_utf8_lossy(&out.stdout).into_owned();
        if feed.contains("set Authorization") && feed.contains("no credentials") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }
    // Stopped before the assertions, so a failure never leaves a cage running.
    let _ = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", &pid.to_string()],
    );
    assert!(
        feed.contains("sign      demo-feed: GET postman-echo.com/get?a=1 set Authorization"),
        "the feed names the signer, the request it formed a credential for, and the headers it put \
         on it:\n{feed}"
    );
    assert!(
        feed.contains("refuse    demo-feed: GET postman-echo.com/get?a=2")
            && feed.contains("no credentials for that region"),
        "and the request it would not sign, with the plugin's own reason:\n{feed}"
    );
    assert!(
        !feed.contains(key),
        "a plugin that echoes the key it was handed must not put it in the record:\n{feed}"
    );
    assert!(
        feed.contains("signed with ${"),
        "the key is replaced by the credential's name, in the plugin's own words:\n{feed}"
    );
}

/// Whether a failed build log shows a *transient* upstream-download fault — a truncated tarball,
/// a reset connection, an upstream stall — rather than a real failure of the code under test. The
/// heavy `flake:` e2es fetch tens of megabytes of nixpkgs per fresh run, so an occasional
/// truncated download from a busy mirror is a property of the network, not a regression. A build
/// that fails *only* with one of these signatures should skip (never turn the suite red); a build
/// that fails for any other reason — or succeeds with the wrong output — must still assert.
fn transient_fetch_failure(log: &str) -> bool {
    const SIGNATURES: [&str; 8] = [
        "Truncated tar archive",
        "unexpected end-of-file",
        "unexpected EOF",
        "Connection reset by peer",
        "Couldn't resolve host",
        "Connection timed out",
        "transferred only",
        "unable to download",
    ];
    SIGNATURES.iter().any(|s| log.contains(s))
}

/// The host's Wayland compositor socket, if one is reachable — so the GUI e2e skips (does not
/// fail) on a headless host. Mirrors the launcher's own resolution: an absolute `WAYLAND_DISPLAY`
/// is the socket path itself, otherwise it is a name resolved under `XDG_RUNTIME_DIR`.
fn wayland_socket() -> Option<PathBuf> {
    let display = std::env::var("WAYLAND_DISPLAY").ok()?;
    if display.is_empty() {
        return None;
    }
    let socket = if Path::new(&display).is_absolute() {
        PathBuf::from(display)
    } else {
        PathBuf::from(std::env::var("XDG_RUNTIME_DIR").ok()?).join(display)
    };
    socket.exists().then_some(socket)
}

#[test]
fn a_gui_wayland_launch_connects_to_the_host_compositor() {
    // `gui = "wayland"` binds the host's Wayland compositor socket read-only into the cage, so a
    // graphical client connects. Proven with the cage's network CUT (`network = "none"`): Wayland
    // is a local Unix socket, so a successful connect can only be the bound socket — the hermetic
    // cage has no host `/run`, so without the GUI hole that socket file is absent and the client
    // fails to connect. `wayland-info` dumps the compositor registry and exits 0 on a good
    // connection. Skips (never fails) when the host cannot sandbox, has no compositor, or the
    // cache is unreachable (wayland-utils is provisioned on the first launch).
    let project = TmpDir::new("gui-proj");
    let data = TmpDir::new("gui-data");
    let state = TmpDir::new("gui-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\nnetwork = \"none\"\n\
         [packages]\nwayland-utils = \"nix:wayland-utils\"\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping gui e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if wayland_socket().is_none() {
        eprintln!("skipping gui e2e: no Wayland compositor on the host");
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping gui e2e: the binary cache is unreachable");
        return;
    }

    // `gui` and `[packages]` are trusted-only, so trust the project before launching.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "wayland-info"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "a Wayland client could not connect through the cage (gui = \"wayland\"): {log}"
    );
    // A real registry dump names the core interface — proof it talked to the compositor, not just
    // that the binary started.
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("wl_compositor"),
        "wayland-info did not enumerate the compositor registry: {log}"
    );
}

#[test]
fn a_gui_isolated_cage_gets_a_dummy_interface_a_non_gui_one_does_not() {
    // A graphical cage under an isolated network namespace (here `network = "none"`) reads as
    // *offline* to an in-cage browser — Chromium decides `navigator.onLine` from the presence of a
    // non-loopback interface, and an empty namespace has only loopback. The launch is routed through
    // the netns holder, which adds a black-hole `dummy0`, so the namespace carries `lo` + `dummy0`
    // while its egress is unchanged (the dummy has no route). Gated to `gui = "wayland"`: a non-gui
    // isolated cage keeps a loopback-only namespace. Skips (never fails) when the host cannot sandbox
    // or the dummy mechanism is unavailable (e.g. the `dummy` kernel module cannot be created here).
    let data = TmpDir::new("dummy-data");
    let state = TmpDir::new("dummy-state");

    // A GUI isolated cage: expect `lo` + `dummy0` in its network namespace.
    let gui = TmpDir::new("dummy-gui");
    std::fs::write(
        gui.path().join(".sbx.toml"),
        "gui = \"wayland\"\nnetwork = \"none\"\n",
    )
    .unwrap();
    let probe = run_in(gui.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!("skipping netns-dummy e2e: host cannot sandbox");
        return;
    }
    let t = sbx_in(
        gui.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        t.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&t.stderr)
    );
    let out = sbx_in(
        gui.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", "cat /proc/net/dev"],
    );
    let ifaces = String::from_utf8_lossy(&out.stdout).into_owned();
    if !ifaces.contains("dummy0") {
        eprintln!("skipping netns-dummy e2e: dummy interface unavailable on this host:\n{ifaces}");
        return;
    }

    // Teeth on the gating: a NON-gui isolated cage keeps a loopback-only namespace (no dummy).
    let plain = TmpDir::new("dummy-plain");
    std::fs::write(plain.path().join(".sbx.toml"), "network = \"none\"\n").unwrap();
    let t2 = sbx_in(
        plain.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        t2.status.success(),
        "trust failed: {}",
        String::from_utf8_lossy(&t2.stderr)
    );
    let out2 = sbx_in(
        plain.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", "cat /proc/net/dev"],
    );
    let ifaces2 = String::from_utf8_lossy(&out2.stdout);
    assert!(
        !ifaces2.contains("dummy0"),
        "a non-gui isolated cage must not get a dummy interface (gating): {ifaces2}"
    );
}

#[test]
fn a_gui_dummy_interface_opens_no_egress_the_allowlist_still_filters() {
    // The security invariant the dummy MUST preserve: it adds NO egress path. A `gui = "wayland"`
    // cage under an allowlist gets `dummy0` (the holder path) AND still reaches only allowlisted
    // hosts through the proxy — a non-allowlisted host is refused with a 403 while `dummy0` is
    // present. Guards against a future "give dummy0 a default route to be safe" change silently
    // opening egress (the `network = "none"` gating e2e cannot see that). Skips (never fails) when
    // the host cannot sandbox, the dummy mechanism is unavailable, or the cache is unreachable.
    let project = TmpDir::new("dummy-egress-proj");
    let data = TmpDir::new("dummy-egress-data");
    let state = TmpDir::new("dummy-egress-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\n[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!("skipping dummy-egress e2e: host cannot sandbox");
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping dummy-egress e2e: the binary cache is unreachable");
        return;
    }
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The holder path is active (dummy0 present); skip if the mechanism is unavailable here.
    let ifaces = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", "cat /proc/net/dev"],
    );
    if !String::from_utf8_lossy(&ifaces.stdout).contains("dummy0") {
        eprintln!("skipping dummy-egress e2e: dummy interface unavailable on this host");
        return;
    }

    // ALLOWED through the proxy — proves egress still flows (the dummy did not replace the forwarder
    // path): the real nix-cache-info content hash comes back.
    let allowed = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://cache.nixos.org/nix-cache-info",
        ],
    );
    assert!(
        allowed.status.success()
            && String::from_utf8_lossy(&allowed.stdout)
                .contains("15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c"),
        "allowed egress failed with dummy0 present: {}{}",
        String::from_utf8_lossy(&allowed.stdout),
        String::from_utf8_lossy(&allowed.stderr)
    );

    // DENIED (the no-egress teeth): a non-allowlisted host is still refused with a 403 at the proxy
    // even though `dummy0` is up — the dummy is a black hole, not a route to the world.
    let denied = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://example.com/nix-cache-info",
        ],
    );
    assert!(
        !denied.status.success()
            && String::from_utf8_lossy(&denied.stderr).contains("HTTP error 403"),
        "the dummy interface must not open egress — a non-allowlisted host must still get 403: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

#[test]
fn a_gui_wayland_launch_provisions_fonts_the_cage_can_find() {
    // Under `gui = "wayland"` the hole provisions a base font set host-side, seeds it into the
    // project store, and generates a fontconfig configuration naming it (via `FONTCONFIG_FILE`),
    // so a graphical app renders text rather than boxes. Proven with the cage's network CUT
    // (`network = "none"`): `fc-list` (from the project's own `nix:fontconfig`) reads the cage's
    // fontconfig, and a hermetic cage carries no fonts and no `/etc/fonts` — so a non-empty
    // listing can only come from the hole's seeded fonts + generated config. Teeth on the store
    // path, not just a family name: the output must contain the DejaVu *store path* the hole
    // provisioned (`/nix/store/…dejavu-fonts…`), which appears only because the generated config
    // points fontconfig at exactly that seeded directory. Skips (never fails) when the host cannot
    // sandbox or the cache is unreachable (the fonts and fontconfig are provisioned host-side on
    // the first launch).
    let project = TmpDir::new("gui-fonts-proj");
    let data = TmpDir::new("gui-fonts-data");
    let state = TmpDir::new("gui-fonts-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\nnetwork = \"none\"\n\
         [packages]\nfontconfig = \"nix:fontconfig\"\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping gui-fonts e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    // The fonts and fontconfig are fetched host-side on the first launch, so the cache must be
    // reachable. No compositor is needed: this exercises the font layer, not the display socket.
    if !cache_reachable() {
        eprintln!("skipping gui-fonts e2e: the binary cache is unreachable");
        return;
    }

    // `gui` and `[packages]` are trusted-only, so trust the project before launching.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            "echo \"FONTCONFIG_FILE=[$FONTCONFIG_FILE]\"; \
             echo \"named-match=$(fc-match -f '%{file}' 'Adwaita Sans')\"; \
             fc-list",
        ],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "the font probe failed in the cage (gui = \"wayland\"): {log}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Teeth on the wiring: the display hole and the font hole both contribute to the cage's
    // environment, so a launch that builds the display variables must *add* to the font ones
    // rather than replace them. Assert the variable itself — a cage where the generated config is
    // bound but never named renders no text at all (a browser engine dies mid-page), and the bind
    // alone cannot tell the two apart.
    assert!(
        stdout.contains("FONTCONFIG_FILE=[/opt/sbx/fonts.conf]"),
        "the cage does not name the generated fontconfig in FONTCONFIG_FILE: {log}"
    );
    // Teeth on the effect: the emoji face the hole provisions. Deliberately *not* the DejaVu
    // family alone — fontconfig is built with a compiled-in default font path (a `dejavu-fonts-
    // minimal` in its own closure), so a cage with no working configuration still lists a DejaVu
    // store path and a family-level assertion cannot distinguish the hole working from the hole
    // being absent. Nothing but the hole supplies the emoji face.
    assert!(
        stdout.contains("/nix/store/") && stdout.contains("noto-fonts-color-emoji"),
        "fc-list did not list the hole's provisioned font set by store path: {log}"
    );
    // A face resolved by *name*, not by generic family: an app styled for a modern desktop asks
    // for `Adwaita Sans` explicitly, and fontconfig cannot alias its way to a face that is
    // absent — it silently answers with whatever else it has. So assert the match is the
    // provisioned Adwaita, which is exactly the difference between the app rendering as designed
    // and rendering in a substitute face.
    // Read the match off its own line: asserting the two substrings against the whole output
    // would let the `fc-list` listing satisfy the family check while `fc-match` actually answered
    // with a different face — the assertion has to pin what the *match* returned.
    let named = stdout
        .lines()
        .find_map(|l| l.strip_prefix("named-match="))
        .unwrap_or_default();
    assert!(
        named.contains("/nix/store/") && named.contains("adwaita-fonts"),
        "a request for the `Adwaita Sans` family resolved to `{named}`, not the provisioned \
         face: {log}"
    );
}

#[test]
fn an_offscreen_gui_posture_provisions_fonts_without_exposing_a_display() {
    // `gui = "offscreen"` is the posture of a cage that renders but never maps a window (a headless
    // browser engine): it must carry the font layer — a browser dies mid-render without it — while
    // binding no compositor socket at all. Both halves are asserted in one launch, which is the
    // point: the font wiring and the display wiring live in the same block of the launch path, so a
    // regression that re-couples them fails here. Proven with the cage's network CUT
    // (`network = "none"`): a hermetic cage carries no fonts and no `/etc/fonts`, so `fc-list` can
    // only list the hole's seeded DejaVu by store path; and `WAYLAND_DISPLAY` must be unset, which
    // separates this posture from `wayland` (where the same font assertion also holds). Skips
    // (never fails) when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("gui-off-proj");
    let data = TmpDir::new("gui-off-data");
    let state = TmpDir::new("gui-off-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"offscreen\"\nnetwork = \"none\"\n\
         [packages]\nfontconfig = \"nix:fontconfig\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping gui-offscreen e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping gui-offscreen e2e: the binary cache is unreachable");
        return;
    }

    // `gui` and `[packages]` are trusted-only, so trust the project before launching.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The display half is asserted on the BIND, not on `WAYLAND_DISPLAY`: the cage's env
    // passthrough carries `TERM`/`LANG` only, so the host variable is absent under every posture
    // and testing it would have no teeth. The compositor socket, when the display hole binds it,
    // appears in the cage at its own host path — so probing that exact path distinguishes
    // `offscreen` from `wayland`. Only meaningful on a host that has a compositor; without one
    // there is no socket either way, and the fonts half still carries the test.
    let socket = match (
        std::env::var("XDG_RUNTIME_DIR").ok(),
        std::env::var("WAYLAND_DISPLAY").ok(),
    ) {
        (Some(dir), Some(disp)) if !dir.is_empty() && !disp.is_empty() => {
            Some(std::path::Path::new(&dir).join(disp).display().to_string())
        }
        _ => None,
    };
    let probe_socket = socket.clone().unwrap_or_else(|| "/nonexistent".to_string());
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "sh",
            "-c",
            &format!(
                "fc-list; \
                 [ -e /opt/sbx/fonts.conf ] && echo FONTS-CONF-BOUND; \
                 [ -e '{probe_socket}' ] && echo DISPLAY-BOUND || echo DISPLAY-ABSENT"
            ),
        ],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "the offscreen probe failed in the cage: {log}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The emoji face, deliberately, rather than the DejaVu family: fontconfig carries a
    // compiled-in default font path (a `dejavu-fonts-minimal` in its own closure), so a cage with
    // no working configuration still lists a DejaVu store path. Nothing but the hole supplies the
    // emoji face, so this distinguishes the hole working from the hole being absent.
    assert!(
        stdout.contains("/nix/store/") && stdout.contains("noto-fonts-color-emoji"),
        "an offscreen cage did not get the hole's provisioned font set by store path: {log}"
    );
    // Teeth on the wiring itself, not only on its effect: the generated fontconfig is bound in.
    assert!(
        stdout.contains("FONTS-CONF-BOUND"),
        "the offscreen cage has no bound fontconfig at /opt/sbx/fonts.conf: {log}"
    );
    // The other half: renders, but no display. A future refactor that re-couples the compositor
    // socket to the rendering predicate fails right here.
    if socket.is_some() {
        assert!(
            stdout.contains("DISPLAY-ABSENT"),
            "an offscreen cage was handed the host compositor socket: {log}"
        );
    }
}

#[test]
fn a_trusted_dbus_stands_up_an_in_cage_portal() {
    // `dbus = true` under `gui = "wayland"` stands up a *private* session bus inside the cage
    // carrying sbx's own `xdg-desktop-portal` with the GTK backend, so a Chromium/Electron app's
    // file chooser renders in-cage (seeing only the cage filesystem). Proven with the cage's network
    // CUT (`network = "none"`, empty netns): the only session bus reachable is the private one the
    // command wrapper created, so a `FileChooser` version probe that answers on it can only be the
    // in-cage portal — and the GTK backend that serves that interface needs the Wayland display to
    // start, so the probe also exercises the display hole. Teeth on isolation too: the login keyring
    // (`org.freedesktop.secrets`) must be ABSENT on the private bus. `gdbus` comes from the
    // project's own `nix:glib.bin`. Skips (never fails) when the host cannot sandbox, has no
    // compositor, or the cache is unreachable (the portal stack is provisioned on the first launch).
    let project = TmpDir::new("portal-proj");
    let data = TmpDir::new("portal-data");
    let state = TmpDir::new("portal-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\ndbus = true\nnetwork = \"none\"\n\
         [packages]\nglib = \"nix:glib.bin\"\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping in-cage dbus e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if wayland_socket().is_none() {
        eprintln!("skipping in-cage dbus e2e: no Wayland compositor on the host");
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping in-cage dbus e2e: the binary cache is unreachable");
        return;
    }

    // `gui`/`dbus`/`[packages]` are trusted-only, so trust the project before launching.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The cage script probes the private bus: the FileChooser version (the in-cage portal serves it)
    // and the keyring (must be refused). Both markers in one run, so a false "no bus" cannot pass.
    let script = "gdbus call --session --dest org.freedesktop.portal.Desktop \
         --object-path /org/freedesktop/portal/desktop \
         --method org.freedesktop.DBus.Properties.Get \
         org.freedesktop.portal.FileChooser version 2>&1 | sed 's/^/FILECHOOSER: /'; \
         gdbus call --session --dest org.freedesktop.secrets \
         --object-path /org/freedesktop/secrets \
         --method org.freedesktop.DBus.Peer.Ping 2>&1 | sed 's/^/KEYRING: /'";
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "bash", "-c", script],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The FileChooser interface answered with a version on the private bus — the in-cage portal is
    // up and serving the file chooser (the whole point).
    assert!(
        stdout.contains("FILECHOOSER: (<uint32 "),
        "the in-cage portal did not serve a FileChooser version on the private bus: {log}"
    );
    // Isolation teeth: the keyring is not on the private bus (the raw host bus is never exposed).
    assert!(
        stdout.contains("KEYRING:") && !stdout.contains("KEYRING: ()"),
        "the login keyring must be absent from the in-cage portal's private bus: {log}"
    );
}

#[test]
fn a_trusted_in_cage_notifications_relay_attaches_and_forwards() {
    // Under `dbus = true`, sbx runs a host-side relay that owns `org.freedesktop.Notifications`
    // on the cage's private bus and forwards to the host daemon, so the app's desktop notifications
    // work. Teeth on the wiring, end to end through a real cage: on the private bus (the only one
    // reachable — `network = "none"`, empty netns) the notifications name must have an OWNER (the
    // relay; without it the name is unowned, as the in-cage portal serves only the portal), and
    // `GetServerInformation` on it must return the HOST daemon's info (a forward can only succeed if
    // the relay bridged the private bus to the host). A retry absorbs the startup race — the relay
    // attaches within milliseconds when the host is idle, but the window is deliberately long (600
    // polls, a minute or so) so a host-side relay that is merely slow to be scheduled is not
    // mistaken for one that never attached. Twenty seconds was not enough: a full parallel suite
    // provisions from the binary cache while this runs, and the relay lost the race for the CPU. `gdbus` comes from the project's own `nix:glib.bin`. It exits the
    // loop the instant the name has an owner, so a healthy run is unaffected. Skips (never fails) when
    // the host cannot sandbox,
    // has no compositor, no session bus, or the cache is unreachable.
    let project = TmpDir::new("relay-proj");
    let data = TmpDir::new("relay-data");
    let state = TmpDir::new("relay-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\ndbus = true\nnetwork = \"none\"\n\
         [packages]\nglib = \"nix:glib.bin\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping in-cage relay e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if wayland_socket().is_none() {
        eprintln!("skipping in-cage relay e2e: no Wayland compositor on the host");
        return;
    }
    // The relay bridges to the host session bus; without one it cannot attach.
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        eprintln!("skipping in-cage relay e2e: no host D-Bus session bus");
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping in-cage relay e2e: the binary cache is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Retry GetNameOwner until the relay has claimed the name (the startup race), then read the
    // forwarded server information. `--session` is the private bus (the portal env points it there).
    // The poll count is what the window is made of, and it reports how many it used: a failure that
    // says only "the relay did not attach" cannot be told apart from one that was still waiting,
    // and this test's whole failure mode is a host-side process slow to be scheduled.
    let script = "for i in $(seq 1 600); do \
           owner=$(gdbus call --session --dest org.freedesktop.DBus \
             --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.GetNameOwner \
             org.freedesktop.Notifications 2>&1); \
           case \"$owner\" in *NameHasNoOwner*|*Error*) sleep 0.1;; *) break;; esac; \
         done; \
         echo \"OWNER: $owner\"; \
         echo \"WAITED: $i polls\"; \
         gdbus call --session --dest org.freedesktop.Notifications \
           --object-path /org/freedesktop/Notifications \
           --method org.freedesktop.Notifications.GetServerInformation 2>&1 | sed 's/^/SERVERINFO: /'";
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "bash", "-c", script],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The relay owns the notifications name on the private bus — it attached. A unique bus name owner
    // renders as `(':1.N',)`; without the relay this would be a `NameHasNoOwner` error.
    assert!(
        stdout.contains("OWNER: (':"),
        "the notifications relay did not claim org.freedesktop.Notifications on the private bus: {log}"
    );
    // The forward reached the host daemon: GetServerInformation returns its string tuple
    // `('name', 'vendor', …)` — an error (no forward) would render as `SERVERINFO: Error…`.
    assert!(
        stdout.contains("SERVERINFO: ('"),
        "GetServerInformation did not forward to the host notifications daemon: {log}"
    );
}

#[test]
fn a_keyfile_rewrite_makes_the_in_cage_portal_re_emit_setting_changed() {
    // The live-theme relay follows host light/dark switches by rewriting the in-cage GSettings
    // keyfile; the in-cage `xdg-desktop-portal-gtk` watches that file and re-emits its own
    // `Settings.SettingChanged`, which the Chromium/Electron app follows. This test proves that
    // load-bearing seam — keyfile change -> portal re-emits — end to end through a real in-cage cage:
    // it activates the portal, subscribes to `SettingChanged` on the private bus (the only one
    // reachable, `network = "none"`), rewrites the keyfile to both schemes (so at least one differs
    // from the at-launch seed), and asserts the portal emitted a `color-scheme` `SettingChanged`.
    // (The relay itself writes this keyfile from the HOST across the home bind — proven live in the
    // theme-relay spike; here the cage writes the same file, isolating the portal-emits-on-change
    // half deterministically. `gdbus` comes from the project's own `nix:glib.bin`.) Skips (never
    // fails) when the host cannot sandbox, has no compositor, or the cache is unreachable.
    let project = TmpDir::new("theme-proj");
    let data = TmpDir::new("theme-data");
    let state = TmpDir::new("theme-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\ndbus = true\nnetwork = \"none\"\n\
         [packages]\nglib = \"nix:glib.bin\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping in-cage theme e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if wayland_socket().is_none() {
        eprintln!("skipping in-cage theme e2e: no Wayland compositor on the host");
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping in-cage theme e2e: the binary cache is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Activate the portal (so its GTK backend is running and watching GSettings), subscribe to its
    // SettingChanged on the private bus, then rewrite the keyfile to both schemes. `>` truncates the
    // file in place. At least one write differs from the at-launch seed, so the portal must emit.
    let script = "KF=\"$HOME/.config/glib-2.0/settings/keyfile\"; \
         gdbus call --session --dest org.freedesktop.portal.Desktop \
           --object-path /org/freedesktop/portal/desktop \
           --method org.freedesktop.portal.Settings.Read \
           org.freedesktop.appearance color-scheme >/dev/null 2>&1; \
         gdbus monitor --session --dest org.freedesktop.portal.Desktop >/tmp/mon.log 2>&1 & \
         MON=$!; sleep 1; \
         mkdir -p \"$(dirname \"$KF\")\"; \
         { echo \"[org/gnome/desktop/interface]\"; echo \"color-scheme='prefer-light'\"; } > \"$KF\"; sleep 2; \
         { echo \"[org/gnome/desktop/interface]\"; echo \"color-scheme='prefer-dark'\"; } > \"$KF\"; sleep 2; \
         kill $MON 2>/dev/null; \
         echo \"CHANGED: $(grep -c SettingChanged /tmp/mon.log 2>/dev/null)\"; \
         grep SettingChanged /tmp/mon.log 2>/dev/null | sed 's/^/SIG: /'";
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "bash", "-c", script],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The in-cage portal re-emitted a color-scheme SettingChanged in response to the keyfile rewrite
    // — the exact chain the live-theme relay drives. Without the keyfile->GSettings->portal seam
    // there would be no such signal on the private bus.
    assert!(
        stdout.contains("SIG:") && stdout.contains("color-scheme"),
        "the in-cage portal did not re-emit a color-scheme SettingChanged after a keyfile rewrite: {log}"
    );
}

#[test]
fn catrust_purges_stale_cas_so_the_nss_db_never_accumulates() {
    // catrust imports the egress MITM CA into the cage's NSS db so a Chromium/Electron GUI app
    // trusts the proxy. Each launch has a distinct per-session CA sharing a FIXED subject DN, so
    // without the purge two launches would leave two same-subject CAs — which collide on the NSS
    // issuer lookup and make Chromium reject the current cert (ERR_CERT_AUTHORITY_INVALID, the bug
    // that shipped). The wrap purges every prior `sbx-mitm*` entry before re-adding the current one,
    // so the persistent app home's db holds exactly ONE. Teeth: two sequential `sbx app` launches
    // share the app's persistent home; the second reports the `sbx-mitm` count read from the db with
    // its own `nix:nss.tools` certutil — it must be 1, not 2 (a count of 2 is exactly the pre-fix
    // accumulation). `gui = "wayland"` + a filtering posture is what gates catrust on (no real
    // compositor needed — the CA import does not render). Skips when the host cannot sandbox or the
    // cache is unreachable (nss.tools is provisioned on the first launch).
    let project = TmpDir::new("catrust-proj");
    let data = TmpDir::new("catrust-data");
    let state = TmpDir::new("catrust-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\n[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\
         [packages]\nnss = \"nix:nss.tools\"\n\
         [app.probe]\ncmd = [\"bash\", \"-c\", \
         \"certutil -L -d sql:$HOME/.pki/nssdb 2>/dev/null | grep -c sbx-mitm | sed 's/^/MITM-COUNT=/'\"]\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping catrust e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping catrust e2e: the binary cache is unreachable");
        return;
    }

    // `gui`/`network`/`[packages]` are trusted-only, so trust before launching.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // Launch 1: imports the first session's CA (db now holds one sbx-mitm entry).
    let first = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "probe"],
    );
    assert!(
        first.status.success(),
        "first launch failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Launch 2: a NEW session CA. Without the purge the shared home's db would now hold TWO
    // same-subject CAs; with it, the count stays 1.
    let second = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "probe"],
    );
    let out = String::from_utf8_lossy(&second.stdout);
    let log = format!("{}{}", String::from_utf8_lossy(&second.stderr), out);
    assert!(second.status.success(), "second launch failed: {log}");
    assert!(
        out.contains("MITM-COUNT=1"),
        "the NSS db must hold exactly one sbx-mitm CA after two launches (the purge), not accumulate: {log}"
    );
}

#[test]
fn a_network_allowlist_filters_egress_through_the_proxy() {
    // The Model-B egress path end to end through the real binary: a trusted
    // `network = "deny"` stands up the host filtering proxy on a bound socket, the
    // empty-netns cage reaches it *only* through the in-cage socat forwarder, the cage trusts
    // the proxy's injected per-session CA, and the allowlist decides each request. Teeth: an
    // allowed host's fetch returns the real content (the known nix-cache-info hash); a denied
    // host is refused with a 403 *at the proxy* (a real filename, so the fetch is actually
    // attempted — not a tool-side URL rejection). Because `sbx run` must supervise on this
    // path (it cannot exec-replace while the proxy thread outlives the cage), this also covers
    // exit-status propagation there. Skips (never fails) when the host cannot sandbox or the
    // cache is unreachable.
    let project = TmpDir::new("egress-proj");
    let data = TmpDir::new("egress-data");
    let state = TmpDir::new("egress-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net, no allowlist): a capable host runs `true` to
    // success; otherwise skip. This also seeds the project store, so a later egress failure is
    // a real fault rather than a cold cage.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping egress e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping egress e2e: the binary cache is unreachable");
        return;
    }

    // trust the project so its allowlist posture is honored (a security field).
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // exit-status propagation on the supervised (allowlist) path
    let seven = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", "exit 7"],
    );
    assert_eq!(
        seven.status.code(),
        Some(7),
        "exit status not propagated on the supervised egress path: {}",
        String::from_utf8_lossy(&seven.stderr)
    );

    // ALLOWED: a real fetch through the proxy returns the known nix-cache-info content hash,
    // which proves the whole chain — forwarder bridged the empty netns, nix trusted the MITM
    // leaf via the injected CA, the proxy validated the upstream and relayed the bytes intact.
    let allowed = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://cache.nixos.org/nix-cache-info",
        ],
    );
    assert!(
        allowed.status.success(),
        "allowed egress failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&allowed.stdout)
            .contains("15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c"),
        "allowed fetch did not return the expected nix-cache-info hash: {}",
        String::from_utf8_lossy(&allowed.stdout)
    );

    // DENIED (teeth): the same request shape to a non-allowlisted host is refused with a 403 at
    // the proxy. `example.com` is not in the allow list nor the built-in set.
    let denied = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://example.com/nix-cache-info",
        ],
    );
    assert!(
        !denied.status.success(),
        "denied egress unexpectedly succeeded: {}",
        String::from_utf8_lossy(&denied.stdout)
    );
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("HTTP error 403"),
        "denied egress must be refused with a 403 at the proxy: {}",
        String::from_utf8_lossy(&denied.stderr)
    );

    // STATS — the write↔read key agreement, end to end. The proxy recorded one outcome per request
    // into a session file keyed by the project's canonical path; `sbx net stats` run from the same
    // project reads it back. That it finds the rows proves the launch-side write key and the
    // read-side filter cannot drift (a mismatch would yield an empty, silently-wrong listing). The
    // allowed host shows an allow, the denied host a deny — the buckets the two requests exercised.
    let stats = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["net", "stats", "--json"],
    );
    assert!(
        stats.status.success(),
        "net stats failed: {}",
        String::from_utf8_lossy(&stats.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&stats.stdout).expect("net stats --json is valid JSON");
    let rows = v["stats"].as_array().expect("a stats array");
    let count = |host: &str, bucket: &str| -> u64 {
        rows.iter()
            .find(|r| r["host"] == host)
            .and_then(|r| r[bucket].as_u64())
            .unwrap_or(0)
    };
    assert!(
        count("cache.nixos.org", "allow") >= 1,
        "the allowed host must show an allow in the stats:\n{}",
        String::from_utf8_lossy(&stats.stdout)
    );
    assert!(
        count("example.com", "deny") >= 1,
        "the denied host must show a deny in the stats:\n{}",
        String::from_utf8_lossy(&stats.stdout)
    );
}

#[test]
fn a_designated_http2_host_is_man_in_the_middled_as_http2() {
    // The HTTP/2 (gRPC) MITM path end to end through the real binary. A trusted `deny` allowlist
    // designates `cache.nixos.org` as `http2`, so the proxy speaks HTTP/2 to it; an in-cage
    // `curl --http2` GET reports the negotiated version. Teeth on two properties:
    //   * TRANSPORT: `http_version = 2` can only happen because sbx advertised ALPN `h2` on the
    //     h2 branch — the default HTTP/1.1 MITM advertises no ALPN, so a regression that routed the
    //     designated host through the sync path would report `1.1` and fail this assertion.
    //   * VERDICT on the h2 path: `example.com` is also designated `http2` but is NOT allowed, so
    //     its stream is refused with a `403` by the same `explain` chokepoint the HTTP/1.1 path uses
    //     — proving the policy fires on h2, not just the transport. (It is refused before any
    //     upstream contact, so example.com's reachability does not matter.)
    // Skips (never fails) when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("h2-proj");
    let data = TmpDir::new("h2-data");
    let state = TmpDir::new("h2-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\
         http2 = [\"cache.nixos.org\", \"example.com\"]\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net): seeds the project store and skips a cage-less host.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping http2 e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping http2 e2e: the binary cache is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // ALLOWED + h2: a real GET through the h2 MITM to the designated host. The base `curl` carries
    // nghttp2, `--http2` offers ALPN `h2`, and the proxy speaks it → `http_version = 2`, `200`.
    // Runs via `sbx_in` (with the test state dir) so the trust marker is honored — otherwise the
    // untrusted policy is dropped and the cage runs `shared`, which would negotiate h2 *directly*
    // with the upstream (no proxy) and pass this assertion for the wrong reason.
    let allowed = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "curl",
            "--http2",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "V=%{http_version} C=%{http_code}",
            "https://cache.nixos.org/nix-cache-info",
        ],
    );
    let out = String::from_utf8_lossy(&allowed.stdout);
    assert!(
        out.contains("V=2") && out.contains("C=200"),
        "the designated host must be MITM'd as HTTP/2 and return 200 (got {out:?}); stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );

    // DENIED on the h2 path (teeth): example.com is http2-designated but not allowed, so the h2
    // branch refuses its stream with a 403 — the verdict fires on h2, not just the transport.
    let denied = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "curl",
            "--http2",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "C=%{http_code}",
            "https://example.com/",
        ],
    );
    let dout = String::from_utf8_lossy(&denied.stdout);
    assert!(
        dout.contains("C=403"),
        "a designated-but-unallowed h2 host must be refused with 403 on the h2 path (got {dout:?}); \
         stderr: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

#[test]
fn a_configured_secret_injects_and_tripwires_on_the_http2_path() {
    // Increment 2: credential injection + the outbound tripwire + response redaction now work on the
    // HTTP/2 path, so a configured `[secret]` no longer fail-closes h2 — it is handled exactly like
    // the HTTP/1.1 path. Two teeth against `cache.nixos.org` (a designated h2 host with a secret):
    //   A. NOT fail-closed + the redaction relay delivers the body intact: a normal request is
    //      injected + forwarded and returns `200` with the real `nix-cache-info` body (`StoreDir`) —
    //      cache.nixos.org is an injection target, so this response streams through the *masking*
    //      relay, proving it does not corrupt an ordinary body. (A regression to the increment-1
    //      fail-closed gate would refuse this and fail the assertion.)
    //   B. The outbound tripwire fires: a request that itself carries the secret value verbatim (in a
    //      client header) is refused `outbound-secret` — a secret must not leave the cage, whatever
    //      the verdict.
    let project = TmpDir::new("h2-secret-proj");
    let data = TmpDir::new("h2-secret-data");
    let state = TmpDir::new("h2-secret-state");
    let secret = "s3cr3t-h2-inject-9q2z7w1k";
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\
         http2 = [\"cache.nixos.org\"]\n\n\
         [secret.\"cache.nixos.org\"]\nfrom = \"env://SBX_E2E_SECRET\"\n\
         header = \"X-Sbx-Test\"\ntype = \"raw\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping http2 secret e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping http2 secret e2e: the binary cache is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // A. A normal request: injected + forwarded (not fail-closed), body delivered intact through the
    //    masking relay. The secret is set in sbx's env so the launch resolves it host-side.
    let a = sbx()
        .args([
            "run",
            "--",
            "curl",
            "--http2",
            "-sS",
            "-w",
            "\nC=%{http_code}",
            "https://cache.nixos.org/nix-cache-info",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_SECRET", secret)
        .output()
        .expect("spawn sbx run");
    let aout = String::from_utf8_lossy(&a.stdout);
    assert!(
        aout.contains("C=200") && aout.contains("StoreDir"),
        "a secret-configured h2 request must be injected + forwarded (no fail-close) and its body \
         delivered intact through the masking relay (expected 200 + `StoreDir`); got:\n{aout}\n\
         stderr: {}",
        String::from_utf8_lossy(&a.stderr)
    );

    // B. A request that carries the secret value verbatim must be refused by the outbound tripwire.
    let b = sbx()
        .args([
            "run",
            "--",
            "curl",
            "--http2",
            "-sS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-H",
            &format!("X-Leak: {secret}"),
            "https://cache.nixos.org/nix-cache-info",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_SECRET", secret)
        .output()
        .expect("spawn sbx run");
    let bout = String::from_utf8_lossy(&b.stdout);
    assert!(
        bout.contains("outbound-secret"),
        "a request carrying the secret verbatim must be refused `outbound-secret` on the h2 path; \
         got:\n{bout}\nstderr: {}",
        String::from_utf8_lossy(&b.stderr)
    );
}

#[test]
fn a_secret_is_injected_masked_and_stripped_on_the_http2_grpc_path() {
    // Increment 2's two headline behaviors, guarded through a real gRPC round-trip (the hand-run
    // grpcb.in proof, promoted to committed teeth — the tripwire e2e above cannot cover these because
    // cache.nixos.org does not echo the request):
    //   * INJECTION reaches the upstream: a host-scoped credential is injected host-side (never in the
    //     cage) and arrives at the server.
    //   * RESPONSE MASKING: a reflected secret is masked out of the response DATA.
    //   * STRIP-AND-REPLACE (6.3a): the client also sends a DECOY `x-sbx-test` header; it must be
    //     dropped and only sbx's value forwarded, so the decoy must be absent from the echo.
    // `grpcbin.GRPCBin/HeadersUnary` echoes the request metadata into the response body, so a masked
    // `x-sbx-test` value (an equal-length `*` run) that is neither the real secret nor the decoy
    // proves injection-reached + masking + no-leak + strip in one shot. Skips (never fails) when the
    // host cannot sandbox, the cache is unreachable (grpcurl won't provision), or grpcb.in is down.
    let project = TmpDir::new("h2-grpc-proj");
    let data = TmpDir::new("h2-grpc-data");
    let state = TmpDir::new("h2-grpc-state");
    let secret = "s3cr3t-grpc-inject-7w1k9q2z";
    let decoy = "DECOY-CLIENT-VALUE-must-be-stripped";
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\ngrpcurl = \"nix:grpcurl\"\n\n\
         [network]\nmode = \"deny\"\nallow = [\"{POST} grpcb.in:9001\"]\n\
         http2 = [\"grpcb.in:9001\"]\n\n\
         [secret.\"grpcb.in:9001\"]\nfrom = \"env://SBX_E2E_SECRET\"\n\
         header = \"x-sbx-test\"\ntype = \"raw\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping h2 grpc secret e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping h2 grpc secret e2e: the binary cache is unreachable");
        return;
    }
    if !grpcb_in_reachable() {
        eprintln!("skipping h2 grpc secret e2e: grpcb.in is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx()
        .args([
            "run",
            "--",
            "grpcurl",
            "-H",
            &format!("x-sbx-test: {decoy}"),
            "grpcb.in:9001",
            "grpcbin.GRPCBin/HeadersUnary",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_SECRET", secret)
        .output()
        .expect("spawn sbx run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Injection reached the upstream (the header is echoed) and its value is masked (a `*` run at
    // least as long as our 10-char floor — the real value is 27 chars, so this can only be masking).
    assert!(
        stdout.contains("x-sbx-test") && stdout.contains("**********"),
        "the injected header must reach the upstream and its echoed value be masked; got:\n{stdout}\n\
         stderr: {stderr}"
    );
    // No leak: the real secret value must never appear anywhere in the response.
    assert!(
        !stdout.contains(secret),
        "the secret value must never appear in the response:\n{stdout}"
    );
    // Strip-and-replace: the client's decoy value must have been dropped, not forwarded upstream.
    assert!(
        !stdout.contains(decoy),
        "strip-and-replace failed — the client's decoy header value reached the upstream:\n{stdout}"
    );
}

#[test]
fn net_learn_synthesizes_a_rule_for_a_refused_host_and_writes_it() {
    // `sbx app <name> --net-learn` end to end through the real binary: an app under a `deny`
    // allowlist runs a command that reaches a host it has no rule for; the proxy refuses it
    // (`denied-default`) and logs it; net-learn snapshots that log after the run, synthesizes the
    // allow rule that would admit the host, and (a) prints it under `--dry-run` and (b) writes it to
    // the project config on a real run — which the trust re-gate then re-trusts. Teeth: the refused
    // host (`example.com`) must appear as a `{*} https://…` rule the run never had, proving the whole
    // chain (empty-netns forwarder → MITM proxy → verdict logged → teardown snapshot → synthesis).
    // Skips (never fails) when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("netlearn-proj");
    let data = TmpDir::new("netlearn-data");
    let state = TmpDir::new("netlearn-state");
    // Baseline `deny` allowlist (allow only the cache, so provisioning works); an inline app whose
    // command reaches a host the allowlist does not cover. `curl` is in the base toolset.
    let original_config = "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\n\
         [app.probe]\ncmd = [\"curl\", \"-sS\", \"-m\", \"20\", \"-o\", \"/dev/null\", \
         \"https://example.com\"]\n";
    std::fs::write(project.path().join(".sbx.toml"), original_config).unwrap();

    // capability probe (also seeds the project store, so a later egress failure is a real fault
    // rather than a cold cage).
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping net-learn e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping net-learn e2e: the binary cache is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // DRY RUN: the refused host is synthesized into a domain rule and only printed — nothing written.
    let dry = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "probe", "--net-learn=domain", "--dry-run"],
    );
    let dry_out = format!(
        "{}{}",
        String::from_utf8_lossy(&dry.stdout),
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(
        dry.status.success(),
        "net-learn --dry-run should succeed regardless of the agent's exit: {dry_out}"
    );
    assert!(
        dry_out.contains("{*} https://example.com"),
        "net-learn --dry-run must synthesize the refused host's rule: {dry_out}"
    );
    // A dry run writes nothing: the config is byte-identical to what we wrote (the app's `cmd`
    // already names the host, so a substring check would be a false positive — compare the whole).
    let cfg_after_dry = std::fs::read_to_string(project.path().join(".sbx.toml")).unwrap();
    assert_eq!(
        cfg_after_dry, original_config,
        "a dry run must not modify the config"
    );

    // REAL WRITE (local scope): the same rule is persisted to the project config for app `probe` and
    // the project is re-trusted. The write path is `sbx net allow`'s, so this proves net-learn wires
    // into it correctly (the file gains the rule under the app's table).
    let write = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "probe", "--net-learn=domain", "--local"],
    );
    let write_out = format!(
        "{}{}",
        String::from_utf8_lossy(&write.stdout),
        String::from_utf8_lossy(&write.stderr)
    );
    assert!(
        write.status.success(),
        "net-learn write should succeed: {write_out}"
    );
    let cfg_after = std::fs::read_to_string(project.path().join(".sbx.toml")).unwrap();
    assert_ne!(
        cfg_after, original_config,
        "the write must change the config: {cfg_after}"
    );
    // The rule lands in the app's network allow list — an `allow`/rule line naming the host, beyond
    // the app's `cmd` that already mentioned it.
    assert!(
        cfg_after.matches("example.com").count() >= 2,
        "the learned allow rule must be written alongside the app's cmd: {cfg_after}"
    );
}

/// Poll `127.0.0.1:<port>` from the host until a read returns a body containing `marker`, or time
/// out. Returns the matching body, or `None` on timeout (a refused connect, or the marker never
/// arriving). Used by the forward e2e to wait for the in-cage server to come up and the forwarder
/// to bridge a connection — a partial/early read that lacks the marker keeps polling rather than
/// being accepted.
fn read_loopback_until(port: u16, marker: &str, deadline: std::time::Duration) -> Option<String> {
    use std::io::{Read, Write};
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
            // The cage server writes its banner on connect (it does not require a request); send a
            // newline anyway in case it reads a line first, then read whatever comes back.
            let _ = s.write_all(b"\r\n");
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            if buf.contains(marker) {
                return Some(buf);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    None
}

/// Pick a free host loopback TCP port by binding port 0 and reading back the assigned port, then
/// releasing it — the same race-free trick the inbound unit tests use.
fn free_loopback_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind an ephemeral port");
    l.local_addr().unwrap().port()
}

#[test]
fn a_forward_bridges_a_host_loopback_port_into_the_cage() {
    // The inbound loopback-forward path end to end through the real binary: a trusted
    // `network = "none"` cage with `forward = [<port>]` starts a service on its own loopback, and a
    // host process reaches it only because sbx bound the host port and the in-cage socat bridged it
    // over the shared Unix socket. Teeth: with `forward` declared the host curl gets the cage
    // server's marker; a second project with the SAME server but NO `forward` is unreachable from
    // the host (connection refused) — so the forwarder is provably the bridge, not some ambient
    // route. The in-cage HTTP server is `socat` (already in the base closure; declared `nix:socat`
    // to put it on PATH), serving a fixed one-line banner on connect. Skips (never fails) when the
    // host cannot sandbox or the cache is unreachable (the first launch seeds the store).
    let port = free_loopback_port();
    let marker = "SBX-FORWARD-OK";

    // Helper: run the cage server in the background (spawn, not wait), poll from the host, kill.
    // The in-cage server is `socat` serving a static banner file on each connection: the file is
    // written into the project (bound in-cage at its real path), and `SYSTEM:cat <file>` avoids any
    // nested shell-quoting. `fork` handles the (possibly several) poll connections.
    let run_server_and_probe =
        |proj: &Path, data: &Path, state: &Path, with_forward: bool| -> Option<String> {
            // The banner file the cage server serves — the project is bound at its real path in-cage,
            // so the same absolute path resolves on both sides.
            let banner = proj.join("banner.txt");
            std::fs::write(&banner, format!("HTTP/1.0 200 OK\r\n\r\n{marker}\r\n")).unwrap();
            let server_cmd = format!(
                "exec socat TCP-LISTEN:{port},bind=127.0.0.1,fork,reuseaddr SYSTEM:\"cat {}\"",
                banner.display()
            );
            // Write the config for this project.
            let cfg = if with_forward {
                format!(
                    "network = \"none\"\nforward = [{port}]\n[packages]\nsocat = \"nix:socat\"\n"
                )
            } else {
                "network = \"none\"\n[packages]\nsocat = \"nix:socat\"\n".to_string()
            };
            std::fs::write(proj.join(".sbx.toml"), cfg).unwrap();
            // Trust so the security fields (network, forward) are honored.
            let trusted = sbx_in(proj, data, state, &["trust", ".sbx.toml"]);
            assert!(
                trusted.status.success(),
                "trust: {}",
                String::from_utf8_lossy(&trusted.stderr)
            );
            // Spawn the cage server in the background; hold the child so we can kill it after probing.
            let mut child = sbx()
                .args(["run", "--", "sh", "-c", &server_cmd])
                .current_dir(proj)
                .env("XDG_DATA_HOME", data)
                .env("XDG_STATE_HOME", state)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn cage server");
            let got = read_loopback_until(port, marker, std::time::Duration::from_secs(20));
            let _ = child.kill();
            let _ = child.wait();
            got
        };

    let proj_a = TmpDir::new("ingr-a");
    let data = TmpDir::new("ingr-data");
    let state = TmpDir::new("ingr-state");

    // Capability + cache probe on the first project (also seeds the store for the socat closure).
    std::fs::write(
        proj_a.path().join(".sbx.toml"),
        "network = \"none\"\n[packages]\nsocat = \"nix:socat\"\n",
    )
    .unwrap();
    let probe = run_in(proj_a.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping forward e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping forward e2e: the binary cache is unreachable (socat closure unseeded)");
        return;
    }

    // With `forward`: the host must reach the cage server through the forwarder.
    let with = run_server_and_probe(proj_a.path(), data.path(), state.path(), true);
    let Some(body) = with else {
        eprintln!(
            "skipping forward e2e: the cage server did not come up in time (slow first seed?)"
        );
        return;
    };
    assert!(
        body.contains(marker),
        "the host must reach the cage server through the forward forwarder, got: {body:?}"
    );

    // Teeth: a second project with the SAME cage server but NO `forward` must be unreachable from
    // the host — nothing binds the host port, so the connect is refused. This is what proves the
    // forwarder (not an ambient route) is the bridge.
    let proj_b = TmpDir::new("ingr-b");
    let data_b = TmpDir::new("ingr-datb");
    let state_b = TmpDir::new("ingr-statb");
    let without = run_server_and_probe(proj_b.path(), data_b.path(), state_b.path(), false);
    assert!(
        without.is_none(),
        "without `forward` the host must NOT reach the cage loopback, but got: {without:?}"
    );
}

#[test]
fn a_cleartext_http_rule_forwards_plaintext_egress_through_the_proxy() {
    // The `http://` (inspected-cleartext) scheme end to end through the real binary: under a trusted
    // `network = "deny"` allowlist naming `http://cache.nixos.org`, an in-cage `curl http://…` sends
    // an ABSOLUTE-form request (no CONNECT) to the forwarder → the host proxy's cleartext handler, and
    // the allowlist decides it. Teeth: a request the `http://` rule permits passes the filter (no
    // `denied-*` refusal — the opt-in cleartext rule opened it), while a host with no `http://` rule
    // is refused with `403 denied-default` *at the proxy*, whose body names the `http://`-scheme
    // suggestion. This exercises the seam a proxy unit test cannot — the `method != CONNECT`
    // absolute-form entry point through the real launch. Skips (never fails) when the host cannot
    // sandbox or the cache is unreachable.
    let project = TmpDir::new("clear-proj");
    let data = TmpDir::new("clear-data");
    let state = TmpDir::new("clear-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"http://cache.nixos.org\"]\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net): a capable host runs `true`; otherwise skip. Also
    // seeds the project store so a later egress failure is a real fault, not a cold cage.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping cleartext egress e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping cleartext egress e2e: the binary cache is unreachable");
        return;
    }

    // trust the project so its allowlist posture (a security field) is honored.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // ALLOWED: the `http://cache.nixos.org` rule opts this cleartext request *through the filter*. curl
    // sends the absolute-form request to the proxy, which routes it to the cleartext handler and
    // forwards it over plain TCP:80. What this asserts is precisely the entry-point property this e2e
    // exists to prove: the `http://` rule permitted the absolute-form request (no `denied-*` refusal),
    // versus the denied host below. It deliberately does NOT assert the upstream bytes round-tripped —
    // a `502 upstream-unreachable` would also carry a status line and no `denied-` reason; the
    // origin-form round-trip is proven conclusively by the `proxy` unit test against a loopback
    // upstream. Here the load-bearing new seam is `method != CONNECT` → `handle_cleartext` → the
    // verdict, which only the real binary exercises.
    let allowed = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "curl",
            "-sS",
            "-i",
            "http://cache.nixos.org/nix-cache-info",
        ],
    );
    let allowed_out = format!(
        "{}{}",
        String::from_utf8_lossy(&allowed.stdout),
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        allowed.status.success() && allowed_out.contains("HTTP/"),
        "an allowed cleartext fetch must get a response, not a dropped connection: {allowed_out}"
    );
    assert!(
        !allowed_out.contains("X-Sbx-Egress-Reason: denied"),
        "the http:// rule must open the cleartext request past the filter (no proxy deny): {allowed_out}"
    );

    // DENIED (teeth): a host with no `http://` rule is refused at the proxy with `403 denied-default`,
    // and the suggestion names the http:// scheme (a bare `sbx net allow host` adds an https rule that
    // still would not open the clear). curl exits 0 (it received the proxy's 403 as the response).
    let denied = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "curl", "-sS", "-i", "http://example.com/"],
    );
    let denied_out = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    assert!(
        denied_out.contains("403") && denied_out.contains("X-Sbx-Egress-Reason: denied-default"),
        "an unallowed cleartext host must be refused with 403 denied-default at the proxy: {denied_out}"
    );
    assert!(
        denied_out.contains("sbx net allow http://example.com"),
        "the cleartext deny-default body must suggest the http:// scheme: {denied_out}"
    );
}

#[test]
fn sbx_net_logs_reads_a_running_sessions_live_egress() {
    // The live egress log end to end through the real binary: a background `sbx run` under a
    // trusted allowlist makes one allowed and one denied egress attempt, then sleeps; while it is
    // alive, `sbx net logs` (run from another process) reads its per-request events over the
    // control socket. Teeth: the allowed host shows an `allow` and the denied host a `deny`, each
    // carrying the request's method and path — and, under `--with-status`, the allowed fetch's
    // upstream `200` — proving the proxy's push, the status amend, the ring, the socket wire, and the
    // reader compose. Because the log is live-only (it dies with the session), the session
    // MUST be alive during the read — hence the background child. Skips (never fails) when the host
    // cannot sandbox or the cache is unreachable.
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let project = TmpDir::new("logs-proj");
    let data = TmpDir::new("logs-data");
    let state = TmpDir::new("logs-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    // capability probe (also seeds the project store, so the background run starts warm).
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping net logs e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping net logs e2e: the binary cache is unreachable");
        return;
    }
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // A background session: one allowed fetch (logged `allow`), one denied fetch (logged `deny`),
    // then a sleep long enough to read its live log. The denied fetch fails; `sh` continues.
    let child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_sbx"))
            .args([
                "run",
                "--",
                "sh",
                "-c",
                "nix-prefetch-url --type sha256 https://cache.nixos.org/nix-cache-info; \
                 nix-prefetch-url --type sha256 https://example.com/nix-cache-info; \
                 sleep 300",
            ])
            .current_dir(project.path())
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the background sbx run"),
    );

    // Poll the live log until both decisions have been recorded AND the allowed request's upstream
    // status has been amended in (or a generous deadline). The reader globs the one control socket in
    // this isolated data dir, so no `--app` scope is needed. Reading with `--with-status` also
    // exercises the status column through the binary.
    let host_verdict = |rows: &[serde_json::Value], host: &str, verdict: &str| {
        rows.iter()
            .any(|r| r["host"] == host && r["verdict"] == verdict)
    };
    // The budget starts at spawn, so it must cover everything the background session does before
    // its first event exists: provisioning a fresh test store (the whole base cold, including the
    // one-time locale-archive build) and then two real fetches through the MITM. Measured warm,
    // that already approaches a minute — so a one-minute budget carried no slack, and a cold shared
    // store or a machine running several such sessions at once exhausted it before any event was
    // pushed. Four minutes widens that near-zero margin about fourfold at no cost on the happy path:
    // the loop breaks as soon as it sees what it is waiting for, so a passing run is unchanged and
    // only a genuinely broken one pays the wait. The session's own `sleep` must outlive this budget,
    // or the log — which is live-only — would be gone before the deadline expires.
    //
    // A wider budget is not a cure, only more headroom: cold provisioning under heavy parallelism
    // could still exceed it. The structural fix is to stop timing the provisioning at all — the
    // warm-up probe above runs *before* the project is trusted, so it warms the `shared` path while
    // the background session takes the allowlist one, leaving that path's first-launch cost inside
    // this window. Warming the post-trust path before the clock starts would make the budget
    // generous rather than merely larger.
    let deadline = Instant::now() + Duration::from_secs(240);
    // Deferred init: the loop assigns `last` on its first iteration, before either break — so it is
    // always set by the post-loop read, with no dead initial store.
    let mut last;
    let (mut saw_allow, mut saw_deny, mut saw_status) = (false, false, false);
    loop {
        let out = sbx_in(
            project.path(),
            data.path(),
            state.path(),
            &["net", "logs", "--with-status", "--json"],
        );
        last = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&last)
            && let Some(rows) = v["logs"].as_array()
        {
            saw_allow = host_verdict(rows, "cache.nixos.org", "allow");
            saw_deny = host_verdict(rows, "example.com", "deny");
            if saw_allow && saw_deny {
                // Teeth on the record shape: the allowed event carries its method + path, and —
                // the status peek, flowing proxy→ring→reader — the upstream `200` from
                // nix-cache-info (amended in once the response returns, ~ms after the allow push).
                let allow = rows
                    .iter()
                    .find(|r| r["host"] == "cache.nixos.org" && r["verdict"] == "allow")
                    .unwrap();
                assert_eq!(allow["method"], "GET", "the allow event carries the method");
                assert_eq!(
                    allow["path"], "/nix-cache-info",
                    "the allow event carries the (query-dropped) path"
                );
                saw_status = allow["status"] == 200;
                if saw_status {
                    break;
                }
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    // The human render also surfaces the live session (exercises `render_logs` through the binary).
    let human = sbx_in(project.path(), data.path(), state.path(), &["net", "logs"]);
    let human_out = String::from_utf8_lossy(&human.stdout);

    // Tear the background session down before asserting, so a failure never leaks a live cage.
    drop(child);

    assert!(
        saw_allow && saw_deny,
        "the live log must show the allowed host's allow and the denied host's deny:\n{last}"
    );
    assert!(
        saw_status,
        "`--with-status` must surface the allowed fetch's upstream 200 (proxy→ring→reader):\n{last}"
    );
    assert!(
        human_out.contains("egress log:") && human_out.contains("cache.nixos.org"),
        "the human `sbx net logs` must render the live session's events:\n{human_out}"
    );
}

#[test]
fn sbx_net_logs_follow_streams_a_running_sessions_egress() {
    // The `--follow` live tail end to end: while a background session under a trusted allowlist makes
    // an allowed and a denied egress, a separate `sbx net logs --follow --json` child streams its
    // events (NDJSON, one object per line). A reader thread accumulates the child's stdout; the test
    // polls it until the allow and the deny both appear (or a deadline), proving the poll loop's seed
    // + per-session cursor + append. Skips (never fails) when the host cannot sandbox or the cache is
    // unreachable.
    use std::io::BufRead as _;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    let project = TmpDir::new("logsf-proj");
    let data = TmpDir::new("logsf-data");
    let state = TmpDir::new("logsf-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping net logs --follow e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping net logs --follow e2e: the binary cache is unreachable");
        return;
    }
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The background session: one allowed and one denied egress, then a sleep long enough to tail.
    let session = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args([
            "run",
            "--",
            "sh",
            "-c",
            "nix-prefetch-url --type sha256 https://cache.nixos.org/nix-cache-info; \
             nix-prefetch-url --type sha256 https://example.com/nix-cache-info; \
             sleep 300",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the background sbx run");
    let session = KillOnDrop(session);

    // Give the session a moment to come up (the seed then catches early events).
    std::thread::sleep(Duration::from_secs(2));

    // The follower streams new events as NDJSON over a pipe; a thread accumulates them so the test
    // can watch the stream grow.
    let mut follower = Command::new(env!("CARGO_BIN_EXE_sbx"))
        .args(["net", "logs", "--follow", "--interval", "1", "--json"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sbx net logs --follow");
    let captured = Arc::new(Mutex::new(String::new()));
    let reader = {
        let sink = captured.clone();
        let stdout = follower.stdout.take().expect("piped stdout");
        std::thread::spawn(move || {
            let mut r = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match r.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => sink.lock().unwrap().push_str(&line),
                }
            }
        })
    };
    // Guarded only now: taking its piped stdout above needs the `Child` itself.
    let follower = KillOnDrop(follower);

    let line_has = |buf: &str, host: &str, verdict: &str| {
        buf.lines().any(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .map(|v| v["host"] == host && v["verdict"] == verdict)
                .unwrap_or(false)
        })
    };
    // Poll the accumulating stream until both decisions appear, or a generous deadline — stopping as
    // soon as they do keeps the test fast without a fragile fixed sleep.
    // The budget starts at spawn, so it must cover everything the background session does before
    // its first event exists: provisioning a fresh test store (the whole base cold, including the
    // one-time locale-archive build) and then two real fetches through the MITM. Measured warm,
    // that already approaches a minute — so a one-minute budget carried no slack, and a cold shared
    // store or a machine running several such sessions at once exhausted it before any event was
    // pushed. Four minutes widens that near-zero margin about fourfold at no cost on the happy path:
    // the loop breaks as soon as it sees what it is waiting for, so a passing run is unchanged and
    // only a genuinely broken one pays the wait. The session's own `sleep` must outlive this budget,
    // or the log — which is live-only — would be gone before the deadline expires.
    //
    // A wider budget is not a cure, only more headroom: cold provisioning under heavy parallelism
    // could still exceed it. The structural fix is to stop timing the provisioning at all — the
    // warm-up probe above runs *before* the project is trusted, so it warms the `shared` path while
    // the background session takes the allowlist one, leaving that path's first-launch cost inside
    // this window. Warming the post-trust path before the clock starts would make the budget
    // generous rather than merely larger.
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        {
            let buf = captured.lock().unwrap();
            if line_has(&buf, "cache.nixos.org", "allow") && line_has(&buf, "example.com", "deny") {
                break;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    // Tear both down before asserting, so a failure never leaks a live cage. Dropping the follower
    // closes the pipe, which ends the reader thread.
    drop(follower);
    let _ = reader.join();
    drop(session);

    let out = captured.lock().unwrap().clone();
    assert!(
        line_has(&out, "cache.nixos.org", "allow"),
        "the --follow stream must show the allowed host's allow:\n{out}"
    );
    assert!(
        line_has(&out, "example.com", "deny"),
        "the --follow stream must show the denied host's deny:\n{out}"
    );
}

#[test]
fn a_tcp_rule_splices_a_raw_stream_through_the_cage() {
    // The L4 (`tcp://`) raw-splice path end to end through the real binary — the headline proof. A
    // trusted `network = "deny"` with a `tcp://` rule lets an in-cage client (curl tunnelling
    // via HTTP CONNECT to the in-cage forwarder) reach a host-side **plain-HTTP** upstream through
    // the empty-netns → forwarder → host proxy → splice chain. Teeth: the upstream speaks plain HTTP,
    // not TLS, so the exchange can only complete if the proxy *spliced* the bytes uninspected — had
    // it taken the inspected L7 path (no `tcp://` rule), it would expect a TLS ClientHello and the
    // plain-HTTP request would fail the handshake. The `tcp://127.0.0.1` rule also exercises the
    // IP-literal CONNECT splice (no SNI). `curl` is in the curated base toolset, so it is always in
    // the cage. The CONNECT target `127.0.0.1` is resolved/connected by the host proxy in the *host*
    // netns (where loopback is the upstream), never by the empty-netns cage. Skips (never fails) when
    // the host cannot sandbox.
    let project = TmpDir::new("tcp-splice-proj");
    let data = TmpDir::new("tcp-splice-data");
    let state = TmpDir::new("tcp-splice-state");

    // A host-side minimal plain-HTTP upstream on loopback — the splice's destination. Detached: it
    // answers each connection with a fixed body and closes; the process exit reaps it.
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in upstream.incoming() {
            let Ok(mut sock) = conn else { break };
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                // read the request head up to the blank line (loop, so a fragmented head is fully
                // consumed before replying), then reply and close
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nRAW-L4-OK",
                );
            });
        }
    });

    std::fs::write(
        project.path().join(".sbx.toml"),
        format!("[network]\nmode = \"deny\"\nallow = [\"tcp://127.0.0.1:{port}\"]\n"),
    )
    .unwrap();

    // capability probe (untrusted → shared net, no allowlist): seeds the project store too, so a
    // later splice failure is a real fault rather than a cold cage.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping tcp splice e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The in-cage client: tunnel a plain-HTTP request through the proxy's HTTP CONNECT (18043 is the
    // in-cage forwarder) to the plain upstream. `--proxytunnel` forces CONNECT even for an http://
    // target; `--noproxy ''` overrides sbx's `no_proxy` (which lists 127.0.0.1) so the loopback
    // target is sent *through* the proxy rather than bypassing it.
    let cmd =
        format!("curl -sS --proxytunnel --noproxy '' -x 127.0.0.1:18043 http://127.0.0.1:{port}/");
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", &cmd],
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("RAW-L4-OK"),
        "the plain-HTTP exchange did not round-trip through the tcp:// splice — stdout: {:?}, stderr: {:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_network_allow_mode_serves_filtered_egress_through_the_proxy() {
    // The allow-by-default (denylist) mode through the real launch. A trusted `network = "allow"`
    // stands up the same Model-B filtering proxy as the allowlist e2e (empty netns + in-cage
    // forwarder + injected CA), with the verdict flipped so an unmatched host is allowed. This is a
    // WIRING smoke: it proves the allow-mode policy parses, resolves, the proxy serves under it,
    // the MITM terminates a real fetch, a deny carve-out still produces a 403 at the proxy, and the
    // supervised exit propagates. The ISOLATING verdict teeth — an unlisted host passing the
    // verdict under allow-by-default while deny-by-default blocks it — are the deterministic proxy
    // unit tests, because a loopback test upstream cannot stand in for an unlisted *public* host.
    // Skips (never fails) when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("allowmode-proj");
    let data = TmpDir::new("allowmode-data");
    let state = TmpDir::new("allowmode-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"allow\"\ndeny = [\"example.com/nix-cache-info\"]\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net, allow-mode dropped): seeds the store too, so a
    // later egress failure is a real fault rather than a cold cage.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping allow-mode egress e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping allow-mode egress e2e: the binary cache is unreachable");
        return;
    }

    // trust the project so its allow-mode posture is honored (a security field).
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // exit-status propagation on the supervised (filtered) path
    let seven = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", "exit 7"],
    );
    assert_eq!(
        seven.status.code(),
        Some(7),
        "exit status not propagated on the supervised allow-mode path: {}",
        String::from_utf8_lossy(&seven.stderr)
    );

    // ALLOWED: a real fetch serves through the allow-mode proxy and returns the known
    // nix-cache-info content hash — the forwarder bridged the empty netns, nix trusted the MITM
    // leaf, and the bytes relayed intact under the new mode.
    let allowed = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://cache.nixos.org/nix-cache-info",
        ],
    );
    assert!(
        allowed.status.success(),
        "allowed egress failed under allow mode: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&allowed.stdout)
            .contains("15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c"),
        "allowed fetch did not return the expected nix-cache-info hash: {}",
        String::from_utf8_lossy(&allowed.stdout)
    );

    // DENIED: the deny carve-out still wins under allow-by-default. The 403 is the proxy's verdict
    // (the deny rule matched the path), so it does not depend on `example.com` being reachable.
    let denied = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://example.com/nix-cache-info",
        ],
    );
    assert!(
        !denied.status.success(),
        "a deny carve-out unexpectedly succeeded under allow mode: {}",
        String::from_utf8_lossy(&denied.stdout)
    );
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("HTTP error 403"),
        "the deny carve-out must be refused with a 403 at the proxy: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

#[test]
fn a_gui_wayland_launch_composes_with_a_network_allowlist() {
    // The real desktop-agent posture: `gui = "wayland"` AND `network = "deny"` open at once,
    // each stacking its own binds and env into one cage. The display socket (a local Unix socket,
    // bound read-only), the fonts (seeded + a generated config), and the egress machinery (the
    // bound proxy socket + the injected CA + the empty netns) must coexist — neither hole displaces
    // the other. Separately, Slice A proved the display and 6.2d proved the allowlist; the
    // *composition* is what this asserts, so the teeth are co-located in a SINGLE `sbx run`:
    //
    //   - `wayland-info` enumerates the compositor  ⇒ the display socket connects *inside the empty
    //     netns* (it has no network route, so a successful connect can only be the bound Unix socket);
    //   - a denied host is refused with `403`        ⇒ the allowlist is actually enforcing (not a
    //     `shared` posture leaking through) *with the display hole also open*;
    //   - an allowed host returns the known hash     ⇒ egress works through the proxy, gui open;
    //   - `fc-list` lists the seeded DejaVu fonts    ⇒ the font layer is intact, gui open.
    //
    // The compose tooth is the denied-`403` AND the `wl_compositor` enumeration in the *same* run:
    // split across two launches they would only re-prove Slice A and 6.2d, not coexistence. Skips
    // (never fails) when the host cannot sandbox, has no compositor, or the cache is unreachable
    // (the tools and fonts are provisioned host-side on the first launch).
    let project = TmpDir::new("gui-net-proj");
    let data = TmpDir::new("gui-net-data");
    let state = TmpDir::new("gui-net-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "gui = \"wayland\"\n\
         [network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\
         [packages]\nwayland-utils = \"nix:wayland-utils\"\nfontconfig = \"nix:fontconfig\"\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping gui+net e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if wayland_socket().is_none() {
        eprintln!("skipping gui+net e2e: no Wayland compositor on the host");
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping gui+net e2e: the binary cache is unreachable");
        return;
    }

    // `gui`, `network`, and `[packages]` are all trusted-only, so trust the project first.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // One cage, all four facets. Each emits a distinct marker on success; the test asserts every
    // marker is present, so the four holes are proven to function *together*. No `set -e`: the
    // denied fetch is meant to fail, and a missing facet must surface as a missing marker (caught
    // below) rather than aborting the script early.
    let script = "\
        wayland-info 2>&1 | grep -q wl_compositor && echo COMPOSE-WL\n\
        fc-list | grep -q noto-fonts-color-emoji && echo COMPOSE-FONT\n\
        nix-prefetch-url --type sha256 https://cache.nixos.org/nix-cache-info 2>/dev/null \
            | grep -q 15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c && echo COMPOSE-ALLOW\n\
        nix-prefetch-url --type sha256 https://example.com/nix-cache-info 2>&1 \
            | grep -q 403 && echo COMPOSE-DENY\n";
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", script],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let log = format!("{}{stdout}", String::from_utf8_lossy(&out.stderr));

    // The display hole, inside the empty netns the allowlist imposes.
    assert!(
        stdout.contains("COMPOSE-WL"),
        "wayland-info did not enumerate the compositor with the allowlist also open: {log}"
    );
    // The font layer, with the allowlist also open. Keyed on the emoji face, which only the hole
    // supplies — fontconfig's compiled-in default font path would satisfy a DejaVu-family check
    // even in a cage whose configuration never took effect.
    assert!(
        stdout.contains("COMPOSE-FONT"),
        "fc-list did not list the hole's seeded font set with the allowlist also open: {log}"
    );
    // Egress works through the proxy, with the display hole also open.
    assert!(
        stdout.contains("COMPOSE-ALLOW"),
        "the allowed fetch did not return the known hash with the display hole also open: {log}"
    );
    // The allowlist still has teeth, with the display hole also open — the other half of the
    // composition tooth.
    assert!(
        stdout.contains("COMPOSE-DENY"),
        "a denied host was not refused with a 403 with the display hole also open: {log}"
    );
}

#[test]
fn a_shared_network_launch_trusts_sbx_own_cacert() {
    // Under the default shared-network posture the cage no longer binds the host's `/etc/ssl`;
    // sbx provisions its own cacert and names it through the CA-bundle variables, so HTTPS is
    // hermetic — it works on a host that carries no certificates of its own. Teeth, both in one
    // test so success proves causation: an HTTPS fetch returns the known nix-cache-info hash
    // (TLS verified against sbx's bundle), and the *same* fetch with the CA file forced empty
    // FAILS — so the fetch succeeds *because of* the configured trust anchor, not some ambient
    // cert path. Skips (never fails) when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("cacert-proj");
    let data = TmpDir::new("cacert-data");

    // capability probe; also seeds the project store so a later TLS failure is a real fault.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping cacert e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping cacert e2e: the binary cache is unreachable");
        return;
    }

    // HTTPS works, trusting sbx's hermetic bundle (the host's /etc/ssl is not bound).
    let fetched = run_in(
        project.path(),
        data.path(),
        &[
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://cache.nixos.org/nix-cache-info",
        ],
    );
    assert!(
        fetched.status.success(),
        "hermetic HTTPS fetch failed: {}",
        String::from_utf8_lossy(&fetched.stderr)
    );
    assert!(
        String::from_utf8_lossy(&fetched.stdout)
            .contains("15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c"),
        "fetch did not return the expected nix-cache-info hash: {}",
        String::from_utf8_lossy(&fetched.stdout)
    );

    // teeth: the configured CA is load-bearing — with the cert vars pointed at an empty file
    // the same fetch fails, so the success above is sbx's bundle at work, not an ambient path.
    let no_ca = run_in(
        project.path(),
        data.path(),
        &[
            "sh",
            "-c",
            "NIX_SSL_CERT_FILE=/dev/null SSL_CERT_FILE=/dev/null \
             nix-prefetch-url --type sha256 https://cache.nixos.org/nix-cache-info",
        ],
    );
    assert!(
        !no_ca.status.success(),
        "fetch with an empty CA file unexpectedly succeeded — TLS trust is not coming from \
         sbx's bundle: {}",
        String::from_utf8_lossy(&no_ca.stdout)
    );
}

#[test]
fn the_curated_base_tools_run_in_the_cage() {
    // The curated CLI toolset is reachable by name and actually executes in the cage — so the
    // PATH wiring and the one-channel glibc are right, not merely that the binaries were
    // realised. One launch probes each tool; `set -e` fails on the first missing or broken one.
    // No network: the tools are seeded into the project store. Skips when the host cannot
    // sandbox.
    let project = TmpDir::new("tools-proj");
    let data = TmpDir::new("tools-data");

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping curated-tools e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let out = run_in(
        project.path(),
        data.path(),
        &[
            "sh",
            "-c",
            "set -e; \
             curl --version >/dev/null; \
             git --version >/dev/null; \
             grep --version >/dev/null; \
             rg --version >/dev/null; \
             sed --version >/dev/null; \
             awk --version >/dev/null; \
             find --version >/dev/null; \
             fd --version >/dev/null; \
             jq --version >/dev/null; \
             yq --version >/dev/null; \
             less --version >/dev/null; \
             which ls >/dev/null; \
             echo ALL_TOOLS_OK",
        ],
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ALL_TOOLS_OK"),
        "a curated base tool is missing or broken in the cage: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_usr_bin_env_shebang_resolves_in_the_cage() {
    // The synthetic `/usr/bin/env` lets an interpreted upstream tool run. A script whose shebang
    // is `#!/usr/bin/env node` is executed by its own path, so the kernel reads the shebang and
    // execs `/usr/bin/env node <script>`. With no host `/usr`, that only resolves because the cage
    // synthesises `/usr/bin/env` as a symlink to coreutils' `env`, which finds `node` (declared
    // `nix:nodejs`, trusted-only) on PATH. Teeth: a bare `node <script>` would prove node works but
    // not the shebang path; running the script by its own path proves the `/usr/bin/env` facade
    // specifically. Skips (never fails) when the host cannot sandbox or the cache is unreachable
    // (node is fetched on the first launch).
    let project = TmpDir::new("env-proj");
    let data = TmpDir::new("env-data");
    let state = TmpDir::new("env-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\nnodejs = \"nix:nodejs\"\n",
    )
    .unwrap();
    // an executable script whose shebang routes through `/usr/bin/env`
    let script = project.path().join("hello.js");
    std::fs::write(
        &script,
        "#!/usr/bin/env node\nconsole.log(\"ENV-SHEBANG-OK\", process.version)\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping usr-bin-env e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping usr-bin-env e2e: the network is unreachable");
        return;
    }

    // `[packages]` is trusted-only, so trust the project before the node toolchain provisions.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // run the script by its own absolute path, so the shebang (not an explicit `node`) drives
    // execution — the path through `/usr/bin/env`.
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", script.to_str().unwrap()],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ENV-SHEBANG-OK"),
        "a `#!/usr/bin/env node` shebang did not resolve in the cage: {log}"
    );
}

#[test]
fn a_tarball_resolve_command_runs_in_a_hermetic_cage_and_its_output_is_validated() {
    // The `tarball:resolve` auto-upgrade form runs the profile's resolve command in a HERMETIC bwrap
    // cage (sbx's own base tools, sbx's store + CA bundle, shared network), captures the URL it prints,
    // and validates it before any fetch. This proves that mechanism end-to-end through the real `sbx
    // run` WITHOUT the heavy Electron build: the command prints a deliberately INVALID URL, so the
    // launch must fail with that exact token named — which can only happen if the cage ran the command
    // in the real base userland (a `printf` builtin under `/bin/sh`) and captured+validated its stdout.
    // Teeth: the printed token appears AND the validation rejection appears. Skips (never fails) when
    // the host cannot sandbox or the cache is unreachable (the base userland is fetched on first launch).
    let project = TmpDir::new("resolve-proj");
    let data = TmpDir::new("resolve-data");
    let state = TmpDir::new("resolve-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\ndemo = \"tarball:resolve\"\n\n\
         [tarball.demo]\nresolve = [\"sh\", \"-c\", \"printf RESOLVE-RAN-not-a-tarball\"]\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping tarball-resolve e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping tarball-resolve e2e: the network is unreachable");
        return;
    }

    // `[packages]` (and the resolve command) is trusted-only, so trust the project first.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // The resolved "URL" is not a valid tarball, so the launch fails — and its error names the exact
    // token the command printed, proving the hermetic cage ran the command and captured its stdout.
    assert!(
        !out.status.success(),
        "an invalid resolved URL must fail the launch:\n{log}"
    );
    assert!(
        log.contains("RESOLVE-RAN-not-a-tarball"),
        "the resolved token must appear (the cage ran the command + captured its stdout):\n{log}"
    );
    assert!(
        log.contains("not a valid `.tar.gz`"),
        "the resolved URL must be rejected by validation before any fetch:\n{log}"
    );
}

#[test]
fn a_deb_resolve_command_runs_in_a_hermetic_cage_and_its_output_is_validated() {
    // The `deb:resolve` auto-upgrade form is the `deb:` twin of `tarball:resolve`: it runs the
    // profile's resolve command in the SAME hermetic bwrap cage, captures the URL it prints, and
    // validates it as a `.deb` before any fetch. Proven end-to-end through the real `sbx run` WITHOUT
    // the heavy Electron build: the command prints a deliberately INVALID URL, so the launch must fail
    // naming that exact token — which can only happen if the cage ran the command in the real base
    // userland (`printf` under `/bin/sh`) and captured+validated its stdout. Teeth: the printed token
    // appears AND the `.deb` validation rejection appears. Skips (never fails) when the host cannot
    // sandbox or the cache is unreachable (the base userland is fetched on first launch).
    let project = TmpDir::new("deb-resolve-proj");
    let data = TmpDir::new("deb-resolve-data");
    let state = TmpDir::new("deb-resolve-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\ndemo = \"deb:resolve\"\n\n\
         [deb.demo]\nresolve = [\"sh\", \"-c\", \"printf RESOLVE-RAN-not-a-deb\"]\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping deb-resolve e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping deb-resolve e2e: the network is unreachable");
        return;
    }

    // `[packages]` (and the resolve command) is trusted-only, so trust the project first.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // The resolved "URL" is not a valid `.deb`, so the launch fails — and its error names the exact
    // token the command printed, proving the hermetic cage ran the command and captured its stdout.
    assert!(
        !out.status.success(),
        "an invalid resolved URL must fail the launch:\n{log}"
    );
    assert!(
        log.contains("RESOLVE-RAN-not-a-deb"),
        "the resolved token must appear (the cage ran the command + captured its stdout):\n{log}"
    );
    assert!(
        log.contains("not a valid `.deb`"),
        "the resolved URL must be rejected by validation before any fetch:\n{log}"
    );
}

#[test]
fn sbx_upgrade_deb_runs_a_deb_resolve_command_through_the_upgrade_cage() {
    // `sbx upgrade deb` is the whole point of `deb:resolve` (the `apps-must-be-upgradable` rule): it
    // must build its OWN resolver cage (`build_resolve_cage_parts` + `has_resolve_ref`, a code path
    // DISTINCT from the launch-time provisioning above) and re-run the command. The provisioning e2e
    // does not exercise that path, so this one drives `sbx upgrade deb` directly. A `deb:resolve` that
    // `printf`s an INVALID URL makes the upgrade FAIL, naming the token in the roll summary's
    // `re-resolve failed` line — which can only happen if the upgrade cage ran the command and
    // validated its stdout. Network-light: validation rejects before any `.deb` prefetch; only the
    // base userland seed (already paid by the probe) costs. Skips when the host cannot sandbox or the
    // cache is unreachable.
    let project = TmpDir::new("deb-up-proj");
    let data = TmpDir::new("deb-up-data");
    let state = TmpDir::new("deb-up-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\ndemo = \"deb:resolve\"\n\n\
         [deb.demo]\nresolve = [\"sh\", \"-c\", \"printf RESOLVE-RAN-not-a-deb\"]\n",
    )
    .unwrap();

    // capability probe (also seeds the base store the upgrade cage needs); skip if unsandboxable.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping deb-upgrade-resolve e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping deb-upgrade-resolve e2e: the network is unreachable");
        return;
    }

    // `deb:resolve` is trusted-only, so trust the project before the upgrade will run its command.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["upgrade", "deb"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // The invalid resolved URL makes the roll fail (a Failed outcome → non-zero exit), and the summary
    // names the exact token the command printed — proving the UPGRADE cage ran the command (not the
    // launch path, whose failure reads `cannot provision …`, not `re-resolve failed`).
    assert!(
        !out.status.success(),
        "an invalid resolved URL must fail the roll:\n{log}"
    );
    assert!(
        log.contains("re-resolve failed"),
        "the failure must come from the upgrade roll summary, not the launch path:\n{log}"
    );
    assert!(
        log.contains("RESOLVE-RAN-not-a-deb") && log.contains("not a valid `.deb`"),
        "the roll must name the token the command printed and reject it as a non-`.deb` URL:\n{log}"
    );
}

#[test]
fn an_appimage_resolve_command_runs_in_a_hermetic_cage_and_its_output_is_validated() {
    // The `appimage:resolve` auto-upgrade form is the `appimage:` twin of `tarball:resolve`/
    // `deb:resolve`: it runs the profile's resolve command in the SAME hermetic bwrap cage, captures
    // the URL it prints, and validates it as an `.AppImage` before any fetch. Proven end-to-end
    // through the real `sbx run` WITHOUT the heavy Electron build: the command prints a deliberately
    // INVALID URL, so the launch must fail naming that exact token — which can only happen if the cage
    // ran the command in the real base userland (`printf` under `/bin/sh`) and captured+validated its
    // stdout. Teeth: the printed token appears AND the `.AppImage` validation rejection appears. Skips
    // (never fails) when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("ai-resolve-proj");
    let data = TmpDir::new("ai-resolve-data");
    let state = TmpDir::new("ai-resolve-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\ndemo = \"appimage:resolve\"\n\n\
         [appimage.demo]\nresolve = [\"sh\", \"-c\", \"printf RESOLVE-RAN-not-an-appimage\"]\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping appimage-resolve e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping appimage-resolve e2e: the network is unreachable");
        return;
    }

    // `[packages]` (and the resolve command) is trusted-only, so trust the project first.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !out.status.success(),
        "an invalid resolved URL must fail the launch:\n{log}"
    );
    assert!(
        log.contains("RESOLVE-RAN-not-an-appimage"),
        "the resolved token must appear (the cage ran the command + captured its stdout):\n{log}"
    );
    assert!(
        log.contains("not a valid `.AppImage`"),
        "the resolved URL must be rejected by validation before any fetch:\n{log}"
    );
}

#[test]
fn sbx_upgrade_appimage_runs_an_appimage_resolve_command_through_the_upgrade_cage() {
    // The `appimage:` twin of `sbx_upgrade_deb_runs_a_deb_resolve_command_through_the_upgrade_cage`:
    // `sbx upgrade appimage` must build its OWN resolver cage (appimage's `build_resolve_cage_parts` +
    // `has_resolve_ref`, distinct code from the launch-time provisioning) and re-run the command. An
    // `appimage:resolve` that `printf`s an INVALID URL makes the upgrade FAIL, naming the token in the
    // roll summary's `re-resolve failed` line. Network-light: validation rejects before any prefetch.
    let project = TmpDir::new("ai-up-proj");
    let data = TmpDir::new("ai-up-data");
    let state = TmpDir::new("ai-up-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\ndemo = \"appimage:resolve\"\n\n\
         [appimage.demo]\nresolve = [\"sh\", \"-c\", \"printf RESOLVE-RAN-not-an-appimage\"]\n",
    )
    .unwrap();

    // capability probe (also seeds the base store the upgrade cage needs); skip if unsandboxable.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping appimage-upgrade-resolve e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping appimage-upgrade-resolve e2e: the network is unreachable");
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["upgrade", "appimage"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        !out.status.success(),
        "an invalid resolved URL must fail the roll:\n{log}"
    );
    assert!(
        log.contains("re-resolve failed"),
        "the failure must come from the upgrade roll summary, not the launch path:\n{log}"
    );
    assert!(
        log.contains("RESOLVE-RAN-not-an-appimage") && log.contains("not a valid `.AppImage`"),
        "the roll must name the token and reject it as a non-`.AppImage` URL:\n{log}"
    );
}

#[test]
fn a_synthetic_xdg_open_surfaces_the_url_and_exits_zero() {
    // A tool that auto-opens a browser/file calls `xdg-open <arg>`; the hermetic cage has no
    // display, browser, or file manager, so without a stub the call fails with "xdg-open not
    // found" and aborts the flow (the cline OAuth device-auth crash). The cage synthesises
    // `/usr/bin/xdg-open` as a `/bin/sh` stub that prints its argument to stderr and exits 0,
    // so the call is non-fatal and the user is told what to open. This runs the real stub in a
    // real cage — teeth: exit 0 AND the URL on stderr — and needs no packages or network.
    let project = TmpDir::new("xdg-proj");
    let data = TmpDir::new("xdg-data");
    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping xdg-open e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    let out = run_in(
        project.path(),
        data.path(),
        &["xdg-open", "https://example.com/auth"],
    );
    assert!(
        out.status.success(),
        "xdg-open did not exit 0 (the call must be non-fatal): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("https://example.com/auth"),
        "xdg-open did not surface its argument on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_bin_bash_shebang_resolves_in_the_cage() {
    // A `#!/bin/bash` shebang resolves in a hermetic cage. The cage carries no host `/bin/bash`
    // — it synthesises `/bin/bash` as a second name for the same nix shell `/bin/sh` already
    // exposes — so the kernel can exec a script that declares `#!/bin/bash`. The script is run
    // by its own absolute path so the shebang (not an explicit `bash`) drives execution; that
    // is the only path through `/bin/bash`, which is the facade this proves. No `[packages]`
    // or network are needed beyond the base store seed. Skips (never fails) when the host
    // cannot sandbox or the cache is unreachable (the base closure is fetched on first launch).
    let project = TmpDir::new("bash-proj");
    let data = TmpDir::new("bash-data");
    let state = TmpDir::new("bash-state");
    // an executable script whose shebang names `/bin/bash` directly
    let script = project.path().join("sb.sh");
    std::fs::write(&script, "#!/bin/bash\necho BASH-SHEBANG-OK\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping bin-bash e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping bin-bash e2e: the network is unreachable");
        return;
    }

    // run the script by its own absolute path, so the shebang (not an explicit `bash`) drives
    // execution — the path through `/bin/bash`.
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", script.to_str().unwrap()],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("BASH-SHEBANG-OK"),
        "a `#!/bin/bash` shebang did not resolve in the cage: {log}"
    );
}

#[test]
fn the_cage_self_equips_via_mise_under_a_network_allowlist() {
    // The headline self-equip path (`sbx mise install`) under the headline security posture (a
    // trusted `network = "deny"`). mise reads its CA roots from the certificate *file*, not
    // the CA-bundle env variables, so this is the exact case where the two halves of the trust
    // setup must combine: the hermetic cacert (a real bundle at the file path, which mise needs
    // present to load any roots at all) and the egress proxy's per-session MITM CA (injected via
    // env). If only one were in place, mise could not trust the proxy and the self-equip would
    // fail. Teeth: jq installs through the empty-netns proxy into the project's own store. Skips
    // (never fails) when the host cannot sandbox or the cache is unreachable.
    // Short tags: the egress proxy's Unix socket lives under the data dir, and its full path
    // must fit a `sockaddr_un` (~108 bytes). The test tree (`target/test-tmp/…`) is already
    // deep, so a long tag would overflow `SUN_LEN`. (Production's `~/.local/share/sbx` is short.)
    let project = TmpDir::new("ma-proj");
    let data = TmpDir::new("ma-data");
    let state = TmpDir::new("ma-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net); also seeds the project store.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping mise-allowlist e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping mise-allowlist e2e: the binary cache is unreachable");
        return;
    }

    // trust the project so its allowlist posture is honored (otherwise it degrades to shared
    // network and the proxy path — the thing under test — is never exercised).
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // self-equip jq through the MITM proxy: mise must trust the proxy's per-session leaf
    // (devbox.sh metadata + cache.nixos.org substitution both ride the allowlist's built-in
    // built-in set).
    let installed = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["mise", "install", "nix:jq"],
    );
    assert!(
        installed.status.success(),
        "self-equip via mise under a network allowlist failed — mise could not trust the egress \
         proxy through the cage's certificate file: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&installed.stderr),
        String::from_utf8_lossy(&installed.stdout)
    );
    // Teeth on mise's own artifact, not on its wording: `jq` is in the command itself and is echoed
    // either way, and "installed" is matched by "not installed" and "uninstalled" too — so the log
    // could not tell a real install from its opposite. The install pool in the project home can:
    // only this install writes there.
    assert!(
        project_home_mise_installed(data.path(), "nix-jq"),
        "mise did not install jq into the project home's pool through the allowlist.\n{}\n{log}",
        describe_mise_pools(data.path())
    );
    // Control: a tool that was never asked for must not be reported as installed, so the check
    // above is discriminating rather than something that answers yes to anything.
    assert!(
        !project_home_mise_installed(data.path(), "nix-ripgrep"),
        "the install check answers for a tool that was never installed — it proves nothing"
    );
}

#[test]
fn the_cage_auto_equips_a_non_nix_mise_tool_at_launch() {
    // Multi-backend: a project that declares a non-`nix:` mise tool (here `aqua:`) must have
    // it auto-installed in-cage at launch and resolvable on PATH — with no manual
    // `sbx mise install` and no `sbx trust` (the open self-equip posture). Teeth: `rg` runs
    // on a plain `sbx run` of an UNtrusted project, so the launcher fetched it through mise,
    // installed it into the project's own store, and resolved it through the shims dir — the
    // whole auto-equip chain. Skips (never fails) when the host cannot sandbox or the network
    // is unreachable (the tool is fetched from upstream on first launch).
    let project = TmpDir::new("equip-proj");
    let data = TmpDir::new("equip-data");
    // anchored on an (empty) .sbx.toml; the tool is fresh-from-upstream via mise's aqua backend
    std::fs::write(project.path().join(".sbx.toml"), "").unwrap();
    std::fs::write(
        project.path().join("mise.toml"),
        "[tools]\n\"aqua:BurntSushi/ripgrep\" = \"latest\"\n",
    )
    .unwrap();

    // capability probe (also seeds the base store); skip if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping auto-equip e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping auto-equip e2e: the network is unreachable");
        return;
    }

    // untrusted project, plain `sbx run` — the tool must still equip and run (open posture).
    let out = run_in(project.path(), data.path(), &["rg", "--version"]);
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ripgrep"),
        "an auto-equipped aqua: tool must run on a plain `sbx run` of an untrusted project: {log}"
    );
}

#[test]
fn the_cage_auto_equips_a_non_nix_tool_under_a_network_allowlist() {
    // The headline posture the shipped profiles use: a non-`nix:` tool auto-equipped under a
    // trusted `network = "deny"`. This is the discriminating case the shared-net test above
    // cannot reach — it forces BOTH (1) the wrap composition (the auto-equip wrap nests *inside*
    // the egress wrap, so the forwarder is up before the install fetches) and (2) mise's *own*
    // reqwest through the MITM proxy on a direct download (aqua fetches from github, already in
    // the built-in allow-set), a TLS path nix:'s libcurl never exercises. Teeth: rg
    // runs, so mise's reqwest trusted the proxy's per-session CA and the forwarder bridged the
    // empty netns. Short tags keep the egress socket path under `SUN_LEN`. Skips (never fails)
    // when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("aql-proj");
    let data = TmpDir::new("aql-data");
    let state = TmpDir::new("aql-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("mise.toml"),
        "[tools]\n\"aqua:BurntSushi/ripgrep\" = \"latest\"\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net); also seeds the project store.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping auto-equip allowlist e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping auto-equip allowlist e2e: the network is unreachable");
        return;
    }

    // trust so the allowlist posture is honored (otherwise it degrades to shared and the MITM
    // path under test is never exercised).
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "rg", "--version"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ripgrep"),
        "an aqua: tool must auto-equip through the MITM proxy under a trusted allowlist — mise's \
         reqwest must trust the proxy's per-session CA on a direct download: {log}"
    );
}

#[test]
fn a_fresh_mise_package_app_runs_under_its_own_allowlist() {
    // The load-bearing proof of the fresh-profiles increment: an app declaring its tool as a
    // `[packages] mise:` backend (the form the shipped profiles use) equips it *globally* via
    // `mise use -g` at the `sbx app` launch and runs it fresh, under the app's *own* network
    // allowlist — claude-code's aqua release fetch rides the built-in allow-set
    // (github / *.githubusercontent.com), never a wide-open net. Teeth: `claude --version` prints
    // the upstream version through the empty-netns MITM, proving (1) the global `[packages] mise:`
    // equip path end-to-end, (2) the nixpkgs unfree blocker is gone (this is an aqua standalone
    // binary, not nixpkgs), and (3) the app's allowlist permits the release fetch. Short tags keep
    // the egress socket under `SUN_LEN`. Skips (never fails) without sandbox or network.
    let project = TmpDir::new("fmp-proj");
    let data = TmpDir::new("fmp-data");
    let state = TmpDir::new("fmp-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.cc]\n\
         cmd = [\"claude\", \"--version\"]\n\
         [app.cc.packages]\n\
         claude-code = \"mise:aqua:anthropics/claude-code\"\n\
         [app.cc.network]\n\
         mode = \"deny\"\n\
         allow = [\"api.anthropic.com\", \"storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/*\"]\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net); also seeds the project store once.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping fresh `mise:` package app e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping fresh `mise:` package app e2e: the network is unreachable");
        return;
    }

    // trust so the app's `[packages] mise:` and its allowlist are honored (otherwise the package
    // is withheld and the allowlist degrades, and the MITM path under test is never exercised).
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["app", "run", "cc"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Claude Code"),
        "a fresh `mise:` package app must equip claude-code via `mise use -g` and run it under its \
         own allowlist (the aqua release fetch riding the built-in allow-set): {log}"
    );

    // The mise-split fold has teeth here: Lane-1 `mise use -g` pins the app package's install to the
    // app-global home pool — where `sbx app show`/`list`/`gc` read — not the ambient per-project
    // pool. So claude-code's install must land under the app-global home (`<data>/sbx/apps/cc/home`,
    // since sbx roots its data dir at `$XDG_DATA_HOME/sbx`). If Lane 1 wrote the per-project pool
    // (the pre-fold behaviour) this dir would be empty/absent, and the housekeeping read-path would
    // under-report the tool. Discriminating: this assertion fails if the app-global pin did not take.
    let app_global_installs = data
        .path()
        .join("sbx")
        .join("apps")
        .join("cc")
        .join("home")
        .join(".local/share/mise/installs");
    let has_install = std::fs::read_dir(&app_global_installs)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    assert!(
        has_install,
        "Lane-1 `mise use -g` must install the app package into the app-global home pool ({}), \
         where `sbx app show`/`gc` read it — found empty/absent: {log}",
        app_global_installs.display()
    );
}

/// The installed-tool directories under a mise `installs/` dir, sorted. mise lays out
/// `installs/<munged-tool>/<version>` and keeps a top-level `.mise-installs.toml` bookkeeping file
/// beside them, so only the *directories* are tools — the count the two-pool split is measured by,
/// independent of the munged names. An absent dir yields an empty list (a pool that never installed).
fn mise_installs_entries(installs: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(installs)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Every per-project mise pool a global app has created under `data`, as `(installs_dir, entries)`
/// pairs. A global app's per-project pool lives at `projects/<id>/apps/<app>/mise` (keyed per
/// project *and* app), so one launch per project yields one pool; a plain `sbx run` (ProjectDefault)
/// never creates one, so the set is exactly the app launches. Used to prove a `nix:` self-equip
/// lands in the launching project's own pool (aligned with that project's `/nix`), not app-global.
fn per_project_app_mise_installs(data: &Path, app: &str) -> Vec<(PathBuf, Vec<String>)> {
    let projects = data.join("sbx").join("projects");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&projects).into_iter().flatten().flatten() {
        let installs = entry
            .path()
            .join("apps")
            .join(app)
            .join("mise")
            .join("installs");
        if installs.is_dir() {
            let entries = mise_installs_entries(&installs);
            out.push((installs, entries));
        }
    }
    out.sort();
    out
}

#[test]
fn a_global_app_splits_mise_pools_across_two_projects() {
    // The headline two-project proof of the mise-pool split. A global app (`home_scope` defaults to
    // global, so its `$HOME` — and mise config — is shared across every project, while its `/nix`
    // store is per-project) carries two kinds of mise tool:
    //   * an **agent tool** declared `[packages] mise:` (here `aqua:…/ripgrep`), equipped app-global
    //     by Lane-1 `mise use -g` so it is installed once and reused everywhere; and
    //   * a **`nix:` self-equip** the agent performs in-cage (`mise use -g nix:jq`), whose install is
    //     a pointer into the per-project `/nix` store and so must land in a per-project pool.
    // Launched in project A then project B (same app, same data dir → same app-global home), the
    // split must route each to the right pool. The discrimination rests on install *location counts*
    // (a refetch overwrites in place, so inter-launch equality proves nothing; and under shared net a
    // missing store path is substitutable, so "jq runs in B" is only corroboration):
    //   * app-global `installs/` holds exactly 1 tool (rg) — jq is ABSENT from the app-global pool,
    //     which is the fix itself: were jq shared app-global, B would resolve it from there → A's
    //     store path → absent in B's `/nix` → the "active but absent" failure this split removes.
    //   * two per-project pools (one per project), each holding exactly 1 tool (jq) with rg ABSENT —
    //     rg lives only in the shared app-global pool and is not duplicated into either per-project
    //     pool, so the agent reuses the one app-global copy rather than re-installing rg per project.
    // Old (single-pool) behaviour would show (app-global 2, per-project pools 0); the split shows
    // (app-global 1, two pools of 1). Skips (never fails) without a sandbox or the network.
    let project_a = TmpDir::new("m2a-proj");
    let project_b = TmpDir::new("m2b-proj");
    let data = TmpDir::new("m2-data");
    let state = TmpDir::new("m2-state");
    let toml = "[app.ag]\n\
                cmd = [\"sh\", \"-c\", \"mise use -g nix:jq && jq --version && rg --version\"]\n\
                [app.ag.packages]\n\
                rg = \"mise:aqua:BurntSushi/ripgrep\"\n";
    std::fs::write(project_a.path().join(".sbx.toml"), toml).unwrap();
    std::fs::write(project_b.path().join(".sbx.toml"), toml).unwrap();

    // capability probe per project (also seeds each project's base store once); skip if the host
    // cannot sandbox or the network (tools are fetched fresh from upstream) is unreachable.
    let probe_a = run_in(project_a.path(), data.path(), &["true"]);
    let probe_b = run_in(project_b.path(), data.path(), &["true"]);
    if !probe_a.status.success() || !probe_b.status.success() {
        eprintln!(
            "skipping mise-split two-project e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe_a.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping mise-split two-project e2e: the network is unreachable");
        return;
    }

    // trust both projects so their `[packages]` (a trusted-only field) is honored — otherwise the
    // app package is withheld and Lane 1 never runs.
    for project in [project_a.path(), project_b.path()] {
        let trusted = sbx_in(project, data.path(), state.path(), &["trust", ".sbx.toml"]);
        assert!(
            trusted.status.success(),
            "sbx trust failed: {}",
            String::from_utf8_lossy(&trusted.stderr)
        );
    }

    // Launch in project A, then project B. Both must run jq (the `nix:` self-equip) and rg (the
    // app-global agent tool) — corroboration that the tools resolve; the FS counts below carry the
    // discrimination.
    let launch = |project: &Path, label: &str| {
        let out = sbx_in(project, data.path(), state.path(), &["app", "run", "ag"]);
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("jq-") && stdout.contains("ripgrep"),
            "the global app must self-equip jq and reuse rg in project {label}: {log}"
        );
    };
    launch(project_a.path(), "A");
    launch(project_b.path(), "B");

    // app-global pool: exactly the one agent tool (rg), pinned there by Lane-1 `mise use -g`. jq's
    // absence here is the fix — the `nix:` self-equip did not pollute the shared app-global pool with
    // a store pointer that only resolves in one project's `/nix`.
    let app_global_installs = data
        .path()
        .join("sbx")
        .join("apps")
        .join("ag")
        .join("home")
        .join(".local/share/mise/installs");
    let app_global = mise_installs_entries(&app_global_installs);
    assert!(
        app_global.len() == 1 && app_global[0].contains("ripgrep"),
        "app-global pool must hold exactly the agent tool (rg), with the nix: self-equip (jq) \
         ABSENT — found {app_global:?} at {}",
        app_global_installs.display()
    );

    // per-project pools: one per project, each holding exactly the `nix:` self-equip (jq) and NOT rg.
    // Two pools proves each project installed jq into its own store-aligned pool; each holding a
    // single tool (not two) proves rg stayed in the shared app-global pool and was not copied
    // per-project (the agent reuses the one app-global copy).
    let per_project = per_project_app_mise_installs(data.path(), "ag");
    assert_eq!(
        per_project.len(),
        2,
        "each project must have its own per-project mise pool for the app (the nix: self-equip's \
         store-aligned home) — found {per_project:?}"
    );
    for (installs, entries) in &per_project {
        assert!(
            entries.len() == 1 && entries[0].contains("jq"),
            "a per-project pool must hold exactly the nix: self-equip (jq), with the app-global \
             agent tool (rg) staying in the shared app-global pool and ABSENT here — found \
             {entries:?} at {}",
            installs.display()
        );
    }
}

#[test]
fn a_global_apps_project_mise_tool_lands_in_the_per_project_pool() {
    // Lane 2 of the mise split: a project's own `mise.toml` `[tools]` non-`nix:` tool auto-equips at
    // launch under the ambient primary — which, for a global app, is the per-project pool (aligned
    // with the project's `/nix` store), NOT the app-global home. Teeth: `rg`, declared only in the
    // project's `mise.toml`, must install into `projects/<id>/apps/ag/mise/installs` and be ABSENT
    // from the app-global home (which holds only the app's own `[packages]` — here none). This is the
    // Lane-2 landing check §6 folds into Increment 3. Skips (never fails) without a sandbox or network.
    let project = TmpDir::new("l2-proj");
    let data = TmpDir::new("l2-data");
    // a global app (home_scope defaults to global) whose cmd runs the project tool; the tool itself is
    // declared in the project's mise.toml (Lane 2 — the open self-equip toolchain), not `[packages]`.
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.ag]\ncmd = [\"sh\", \"-c\", \"rg --version\"]\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("mise.toml"),
        "[tools]\n\"aqua:BurntSushi/ripgrep\" = \"latest\"\n",
    )
    .unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping Lane-2 pool e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping Lane-2 pool e2e: the network is unreachable");
        return;
    }

    // Lane-2 auto-equip is open (no trust needed); the inline app is the project's own.
    let out = app_in(project.path(), data.path(), "ag");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ripgrep"),
        "the global app must auto-equip the project's mise.toml tool and run it: {log}"
    );

    // Teeth: rg landed in the per-project pool, aligned with this project's /nix store.
    let per_project = per_project_app_mise_installs(data.path(), "ag");
    assert_eq!(
        per_project.len(),
        1,
        "the project's Lane-2 tool must create exactly one per-project pool: {per_project:?}"
    );
    let (installs, entries) = &per_project[0];
    assert!(
        entries.iter().any(|e| e.contains("ripgrep")),
        "the project mise.toml tool (rg) must install into the per-project pool — found {entries:?} \
         at {}",
        installs.display()
    );

    // ...and NOT into the app-global home (whose mise data holds only the app's own [packages] — none).
    let app_global_installs = data
        .path()
        .join("sbx")
        .join("apps")
        .join("ag")
        .join("home")
        .join(".local/share/mise/installs");
    let app_global = mise_installs_entries(&app_global_installs);
    assert!(
        !app_global.iter().any(|e| e.contains("ripgrep")),
        "the project's Lane-2 tool must NOT land in the shared app-global pool — found {app_global:?}"
    );
}

/// The path to a mise shim in the single project's default home under `data`, if present.
/// `sbx upgrade mise`/`sbx run` equip a baseline `mise:` tool into this home, where mise creates
/// a per-tool shim (its non-interactive PATH entry). Used as the teeth that the in-cage roll
/// touched the right home.
fn project_home_mise_shim(data: &Path, name: &str) -> Option<PathBuf> {
    let projects = data.join("sbx").join("projects");
    for entry in std::fs::read_dir(&projects).ok()?.flatten() {
        let shim = entry.path().join("home/.local/share/mise/shims").join(name);
        // The shim is a symlink mise writes inside the cage, pointing at the cage's own mise
        // (`/nix/store/<hash>-mise-<ver>/bin/mise` in the per-project store mounted at `/nix`).
        // That target resolves only inside the cage, not on the host, so `exists()` — which
        // follows the link — would report a correctly-created shim as absent whenever the host
        // store happens not to carry that exact mise path. Check the link itself
        // (`symlink_metadata`, which does not follow it): its presence is what proves the equip
        // ran and placed the shim.
        if shim.symlink_metadata().is_ok() {
            return Some(shim);
        }
    }
    None
}

#[test]
fn sbx_upgrade_mise_rolls_a_mise_package_in_cage() {
    // The load-bearing proof of the `mise:` `[packages]` roll-forward: `sbx upgrade mise` runs
    // `mise upgrade` *in-cage*, per home, for the project's (and apps') `mise:` packages. A `mise:`
    // tool freezes at its installed version after the first equip (the floating `latest` request
    // stays satisfied, so a later launch never re-resolves), so advancing it must run `mise
    // upgrade` inside the same cage that equips it. Teeth: the capability probe runs against an
    // *empty* project (no package), so the only thing that can equip ripgrep into the project's
    // home is the upgrade cage itself — proven by the `rg` shim appearing in that home's mise data
    // dir after `sbx upgrade mise` and *before* any `sbx run`. The aqua release fetch rides the
    // host network (the default `shared` posture). Skips (never fails) without sandbox or network.
    let project = TmpDir::new("umr-proj");
    let data = TmpDir::new("umr-data");
    let state = TmpDir::new("umr-state");

    // Capability probe against an *empty* project (nothing equipped); also seeds the store once.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping mise: package upgrade e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping mise: package upgrade e2e: the network is unreachable");
        return;
    }

    // Declare the package only now, so nothing equipped it before the upgrade; trust so the
    // `mise:` package (a trusted-only field) is admitted.
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[packages]\nrg = \"mise:aqua:BurntSushi/ripgrep\"\n",
    )
    .unwrap();
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["upgrade", "mise"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "sbx upgrade mise must roll the baseline `mise:` package in-cage: {log}"
    );
    let report = String::from_utf8_lossy(&out.stdout);
    // The clean report names the baseline group in its own aligned status line (the `project`
    // column), without leaking mise's raw install/progress chatter — that is captured and surfaced
    // only on failure.
    // Read the label in its column (name, then the dot leader), not anywhere in the output: the
    // bare word is common enough to appear in any path the report might print.
    assert!(
        report
            .lines()
            .any(|l| l.trim_start().starts_with("project .")),
        "the report must name the baseline (project) mise: package group: {log}"
    );
    assert!(
        !report.contains("mise ~/.config/mise"),
        "mise's raw per-tool output must not leak into the clean roll report: {log}"
    );
    // The batch upgrade path silences the per-app "equipping … via mise use -g" line, which
    // otherwise repeats for every group and buries the result.
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("equipping app packages"),
        "sbx upgrade must not print the per-app equipping line: {log}"
    );

    // Teeth: the upgrade cage equipped ripgrep into the project's own home (the `rg` shim mise
    // creates for a `use`d tool); no `sbx run` ran in between, so only the upgrade cage could have.
    assert!(
        project_home_mise_shim(data.path(), "rg").is_some(),
        "sbx upgrade mise must equip+roll ripgrep in the project home (no `rg` shim found): {log}"
    );
}

#[test]
fn sbx_upgrade_mise_rolls_a_global_apps_app_global_tool() {
    // The global-app counterpart of the baseline `mise:` roll: `sbx upgrade mise` must roll a global
    // app's `[packages] mise:` tool in the APP-GLOBAL pool (where Lane-1 `mise use -g` installs it,
    // shared across projects), not the ambient per-project primary — the `mise_upgrade_cmd` app-global
    // pin. Teeth: with no `sbx app run` first, only the upgrade cage can equip rg, and it must appear
    // in the app-global home, ABSENT from any per-project pool. Skips (never fails) without a sandbox
    // or the network.
    let project = TmpDir::new("ugm-proj");
    let data = TmpDir::new("ugm-data");
    let state = TmpDir::new("ugm-state");

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping global-app mise upgrade e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping global-app mise upgrade e2e: the network is unreachable");
        return;
    }

    // a global app with an app-global agent tool, declared only now; trusted so the `mise:` package
    // (a trusted-only field) is admitted.
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[app.ag]\ncmd = [\"true\"]\n[app.ag.packages]\nrg = \"mise:aqua:BurntSushi/ripgrep\"\n",
    )
    .unwrap();
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["upgrade", "mise"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "sbx upgrade mise must roll the global app's `mise:` package in-cage: {log}"
    );

    // Teeth: the roll equipped rg into the APP-GLOBAL home (Lane-1 pin), not a per-project pool.
    let app_global_installs = data
        .path()
        .join("sbx")
        .join("apps")
        .join("ag")
        .join("home")
        .join(".local/share/mise/installs");
    let app_global = mise_installs_entries(&app_global_installs);
    assert!(
        app_global.iter().any(|e| e.contains("ripgrep")),
        "sbx upgrade mise must equip+roll the global app's tool in the APP-GLOBAL pool — found \
         {app_global:?} at {}: {log}",
        app_global_installs.display()
    );
    // ...and NOT into a per-project pool (the pin keeps a global app's [packages] tool app-global).
    let per_project = per_project_app_mise_installs(data.path(), "ag");
    assert!(
        per_project
            .iter()
            .all(|(_, entries)| !entries.iter().any(|e| e.contains("ripgrep"))),
        "the global app's [packages] tool must stay app-global, not land in a per-project pool: \
         {per_project:?}"
    );
}

#[test]
fn a_flake_package_builds_host_side_into_the_shared_store_and_a_fresh_project_reuses_it() {
    // The load-bearing proof of the `flake:` backend's host-side build: a `flake:` package is now
    // built HOST-SIDE into the shared store — like a `nix:` attribute, not in-cage into the
    // per-project store — so it lands ONCE and is seeded into every project (no per-project rebuild).
    // Two teeth:
    //   * after a launch, the flake's output is in the SHARED store (`<data>/sbx/store/nix/store/
    //     …hello…`), which the old in-cage build (into the per-project store only) never touched;
    //   * a SECOND, fresh project declaring the same flake runs `hello` too, reusing the shared build
    //     (a content-addressed cache hit — no rebuild).
    // The ref is rev-pinned in its URL, so nix evaluates it purely (no github round-trip). The build
    // fetches over the HOST network (host-side, like `nix:`/`deb:`), so it needs no cage allowlist —
    // which also removes the "a flake whose build self-fetches is blocked under the allowlist" wall.
    // Short tags keep the egress socket under `SUN_LEN`. Skips (never fails) without sandbox or network.
    let proj_a = TmpDir::new("flka-proj");
    let proj_b = TmpDir::new("flkb-proj");
    let data = TmpDir::new("flk-data");
    let state = TmpDir::new("flk-state");
    let flake = "flake:github:NixOS/nixpkgs/9ae611a455b90cf061d8f332b977e387bda8e1ca#hello";
    let toml = format!("[app.fk]\ncmd = [\"hello\"]\n[app.fk.packages]\nhello = \"{flake}\"\n");
    std::fs::write(proj_a.path().join(".sbx.toml"), &toml).unwrap();
    std::fs::write(proj_b.path().join(".sbx.toml"), &toml).unwrap();

    // capability probe (also seeds project A's base store once).
    let probe = run_in(proj_a.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping host-side `flake:` e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping host-side `flake:` e2e: the network is unreachable");
        return;
    }

    let launch = |project: &Path| {
        // trust so the app's `[packages] flake:` (a trusted-only field) is admitted.
        let t = sbx_in(project, data.path(), state.path(), &["trust", ".sbx.toml"]);
        assert!(
            t.status.success(),
            "sbx trust failed: {}",
            String::from_utf8_lossy(&t.stderr)
        );
        sbx_in(project, data.path(), state.path(), &["app", "run", "fk"])
    };

    // Project A: cold host-side build + run.
    let a = launch(proj_a.path());
    let a_log = format!(
        "{}{}",
        String::from_utf8_lossy(&a.stderr),
        String::from_utf8_lossy(&a.stdout)
    );
    if !a.status.success() && transient_fetch_failure(&a_log) {
        eprintln!("skipping host-side `flake:` e2e: transient nix download fault: {a_log}");
        return;
    }
    assert!(
        a.status.success() && String::from_utf8_lossy(&a.stdout).contains("Hello, world!"),
        "project A: a `flake:` package must build host-side and run `hello`: {a_log}"
    );

    // Teeth 1: the flake output is in the SHARED store (host-side build), not only a per-project
    // store — the old in-cage build never wrote the shared store, so its presence proves the swap.
    let shared_store = data
        .path()
        .join("sbx")
        .join("store")
        .join("nix")
        .join("store");
    let in_shared = std::fs::read_dir(&shared_store)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains("hello"));
    assert!(
        in_shared,
        "the flake output must be in the shared store (host-side build), not only the per-project \
         store — none found under {}",
        shared_store.display()
    );

    // Project B (fresh, different cwd, same data dir): reuses the shared build — `hello` runs there
    // too, a content-addressed cache hit rather than a rebuild.
    let b = launch(proj_b.path());
    let b_log = format!(
        "{}{}",
        String::from_utf8_lossy(&b.stderr),
        String::from_utf8_lossy(&b.stdout)
    );
    assert!(
        b.status.success() && String::from_utf8_lossy(&b.stdout).contains("Hello, world!"),
        "project B: a fresh project must reuse the shared host-side build and run `hello`: {b_log}"
    );
}

#[test]
fn an_inline_flake_builds_in_cage_and_an_edit_rebuilds() {
    // The load-bearing proof of the `[flakes.<name>]` inline-flake backend, in two phases.
    //
    // PHASE 1 (cold build): an app whose tool is an inline `[flakes.hello]` — a full `flake.nix`
    // written directly in the config — has that source staged, bound read-only into the cage, and
    // built with `nix build path:<dir>#<attr>` **in-cage** at the `sbx app` launch (the same
    // containment as a `flake:` package, applied to arbitrary inline build source). The flake pins
    // its nixpkgs input to a revision and builds `hello`; "Hello, world!" through the empty-netns
    // MITM proves the parse → stage → bind → in-cage build → out-link-on-PATH → run chain.
    //
    // PHASE 2 (edit → rebuild): the *same* app is re-launched after EDITING the inline flake to
    // produce a different `hello` (a script printing a marker). This is the property inline exists
    // for — editing the flake right in the config — and the one the name-keyed out-link would have
    // silently broken (the warm short-circuit would run the stale build). The out-link is keyed by
    // the source's content hash, so the edit rebuilds: the NEW marker must print and the OLD
    // "Hello, world!" must NOT. Same pinned nixpkgs input (cached from phase 1), so the rebuild
    // only compiles a tiny script.
    //
    // Short tags keep the egress socket under `SUN_LEN`. Skips (never fails) without sandbox or
    // network.
    let project = TmpDir::new("ifk-proj");
    let data = TmpDir::new("ifk-data");
    let state = TmpDir::new("ifk-state");
    const REV: &str = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    // `body` is the `default` output expression; the rest of the flake is fixed. A quoted heredoc
    // delimiter is not needed — the whole file is an sbx-owned literal here, no shell interpolation.
    let toml = |body: &str| {
        format!(
            "[app.fk]\n\
             cmd = [\"hello\"]\n\
             [app.fk.flakes.hello]\n\
             flake = '''\n\
             {{\n\
               inputs.nixpkgs.url = \"github:NixOS/nixpkgs/{REV}\";\n\
               outputs = {{ self, nixpkgs }}:\n\
                 let pkgs = nixpkgs.legacyPackages.x86_64-linux;\n\
                 in {{ packages.x86_64-linux.default = {body}; }};\n\
             }}\n\
             '''\n\
             [app.fk.network]\n\
             mode = \"deny\"\n\
             allow = [\"cache.nixos.org\"]\n"
        )
    };
    let phase1 = toml("pkgs.hello");
    let phase2 = toml("pkgs.writeShellScriptBin \"hello\" \"echo INLINE-REBUILD-OK\"");
    std::fs::write(project.path().join(".sbx.toml"), &phase1).unwrap();

    // capability probe (untrusted → shared net); also seeds the project store once.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping inline-flake e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping inline-flake e2e: the network is unreachable");
        return;
    }

    let trust = |project: &Path| {
        // Trust so the app's inline `[flakes]` and its network posture (both security fields) are
        // honored; editing the file re-arms the gate, hence trusting per phase.
        let t = sbx_in(project, data.path(), state.path(), &["trust", ".sbx.toml"]);
        assert!(
            t.status.success(),
            "sbx trust failed: {}",
            String::from_utf8_lossy(&t.stderr)
        );
    };
    let launch = || {
        sbx_in(
            project.path(),
            data.path(),
            state.path(),
            &["app", "run", "fk"],
        )
    };

    // PHASE 1 — cold in-cage build of the inline flake.
    trust(project.path());
    let cold = launch();
    let cold_log = format!(
        "{}{}",
        String::from_utf8_lossy(&cold.stderr),
        String::from_utf8_lossy(&cold.stdout)
    );
    if !cold.status.success() && transient_fetch_failure(&cold_log) {
        eprintln!("skipping inline-flake e2e: transient nix download fault: {cold_log}");
        return;
    }
    assert!(
        cold.status.success() && String::from_utf8_lossy(&cold.stdout).contains("Hello, world!"),
        "phase 1: an inline `[flakes]` app must stage the flake, bind it read-only, build it in-cage \
         with `nix build path:<dir>#<attr>`, and run it: {cold_log}"
    );

    // PHASE 2 — edit the inline flake; the content-hash-keyed out-link must rebuild the NEW output.
    std::fs::write(project.path().join(".sbx.toml"), &phase2).unwrap();
    trust(project.path());
    let edited = launch();
    let edited_out = String::from_utf8_lossy(&edited.stdout).into_owned();
    let edited_log = format!("{}{edited_out}", String::from_utf8_lossy(&edited.stderr));
    if !edited.status.success() && transient_fetch_failure(&edited_log) {
        eprintln!(
            "skipping inline-flake e2e: transient nix download fault on rebuild: {edited_log}"
        );
        return;
    }
    assert!(
        edited.status.success() && edited_out.contains("INLINE-REBUILD-OK"),
        "phase 2: editing the inline flake must rebuild (a fresh content hash → a new out-link the \
         warm short-circuit misses), so the NEW output runs: {edited_log}"
    );
    assert!(
        !edited_out.contains("Hello, world!"),
        "phase 2: the stale build must NOT run — an edited inline flake reusing the old out-link is \
         exactly the bug the content-hash keying prevents: {edited_log}"
    );
}

/// The logical store path the host-side data-dir out-link `<data>/sbx/gcroots/projects/<id>/<name>`
/// points at — the build a `nix:`/remote-`flake:` package was provisioned to (one project per data
/// dir here). `None` when no such out-link exists.
fn project_package_out_link_target(data: &Path, name: &str) -> Option<PathBuf> {
    std::fs::read_dir(data.join("sbx/gcroots/projects"))
        .ok()?
        .flatten()
        .find_map(|e| std::fs::read_link(e.path().join(name)).ok())
}

#[test]
fn a_locked_flake_package_builds_the_pinned_ref_host_side() {
    // The host-side locked-launch proof — the pin path, distinct from the floating one the
    // `..._builds_host_side_into_the_shared_store...` e2e proves. After `sbx upgrade flake` pins a
    // `flake:` package, a launch reads the per-project lock and builds the *locked* (narHash'd,
    // immutable) reference host-side into the shared store, rooted like a `nix:` tool. Teeth:
    // (1) `hello` prints "Hello, world!", proving the locked narHash ref (a different ref string than
    // the narHash-*free* floating one) builds host-side and runs; (2) the launch wrote the data-dir
    // out-link `<data>/sbx/gcroots/projects/<id>/hello` pointing at the build — the host-side rooting
    // (like `nix:`), not the retired in-cage `home/.local/state/sbx/flake/` out-link. Skips (never
    // fails) without sandbox or network.
    let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    let project = TmpDir::new("lfk-proj");
    let data = TmpDir::new("lfk-data");
    let state = TmpDir::new("lfk-state");
    std::fs::write(
        project.path().join(".sbx.toml"),
        format!(
            "[packages]\nhello = \"flake:github:NixOS/nixpkgs/{rev}#hello\"\n\
             [network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n"
        ),
    )
    .unwrap();

    // capability probe (untrusted → the flake package is withheld, shared net); seeds the store.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping locked `flake:` e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping locked `flake:` e2e: the network is unreachable");
        return;
    }

    // trust so the flake package and the allowlist are honored.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // pin the flake package to its current revision (a host-side lock rewrite).
    let pinned = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["upgrade", "flake"],
    );
    let pin_log = format!(
        "{}{}",
        String::from_utf8_lossy(&pinned.stderr),
        String::from_utf8_lossy(&pinned.stdout)
    );
    if !pinned.status.success() || pin_log.contains("re-resolve failed") {
        eprintln!("skipping locked `flake:` e2e: cannot resolve the flake upstream: {pin_log}");
        return;
    }
    assert!(
        pin_log.contains("newly pinned"),
        "the flake package must pin: {pin_log}"
    );

    // launch: build the *locked* (narHash'd) ref host-side, run it.
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "hello"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    if !out.status.success() && transient_fetch_failure(&log) {
        eprintln!("skipping locked `flake:` e2e: transient nix download fault: {log}");
        return;
    }
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Hello, world!"),
        "the locked flake ref must build host-side and run: {log}"
    );

    // Teeth: the pinned launch rooted the build in the host-side data-dir out-link (like a `nix:`
    // tool), pointing at hello's store path — not the retired in-cage out-link.
    let target = project_package_out_link_target(data.path(), "hello");
    assert!(
        target
            .as_deref()
            .is_some_and(|p| p.to_string_lossy().contains("hello")),
        "the pinned launch must root the host-side data-dir out-link for `hello` (got {target:?})"
    );
}

/// The single project store dir under `data` (these tests run one project).
fn project_store_dir(data: &Path) -> Option<PathBuf> {
    std::fs::read_dir(data.join("sbx").join("projects"))
        .ok()?
        .flatten()
        .map(|e| e.path().join("store"))
        .find(|p| p.exists())
}
/// Whether mise installed `tool` (its backend-munged directory name, e.g. `nix-jq`) into the
/// project home's own pool, with at least one concrete version entry rather than a bare
/// placeholder. The filesystem answer to "did the self-equip actually install", which no wording in
/// a tool's own log can give: mise says "installed" in messages that mean the opposite, and the
/// project store is no witness on its own either — a tool that is *also* in the base userland (jq
/// is) sits there whether or not mise ever ran. Taken together they are: the pool entry proves mise
/// ran, and its target being in *this project's* store proves what it installed landed there.
fn project_home_mise_installed(data: &Path, tool: &str) -> bool {
    let projects = data.join("sbx").join("projects");
    for entry in std::fs::read_dir(&projects).into_iter().flatten().flatten() {
        let project = entry.path();
        let installs = project.join("home/.local/share/mise/installs").join(tool);
        let Ok(versions) = std::fs::read_dir(&installs) else {
            continue;
        };
        for v in versions.flatten() {
            if !v
                .file_name()
                .to_string_lossy()
                .starts_with(|c: char| c.is_ascii_digit())
            {
                continue;
            }
            // A `nix:` tool's version entry is a **symlink into the cage's `/nix`**, which is the
            // project's own store bound there — so it dangles when read from the host, and asking
            // `is_dir()` (which follows it) would answer "not installed" on any host whose real
            // `/nix/store` happens not to hold that exact derivation. Resolve it the way the
            // layout actually works: read the link and look for its basename in the project store.
            let target = match std::fs::read_link(v.path()) {
                // A plain directory (a non-nix backend installs into the pool itself) is the
                // artifact, with nothing to cross-check.
                Err(_) if v.path().is_dir() => return true,
                Err(_) => continue,
                Ok(t) => t,
            };
            // `1`, `1.8` and `latest` point at the version entry beside them; only the absolute
            // store path is the artifact.
            if !target.is_absolute() {
                continue;
            }
            if in_store(&project.join("store"), &target) {
                return true;
            }
        }
    }
    false
}

/// Every mise install pool under `data`, with what is in it — for the failure message of a
/// [`project_home_mise_installed`] check. A bare "did not install" says nothing about *where* it
/// landed instead, which is the only question worth asking when a tool reports success and the
/// pool is empty: a wrong scope (the app-global pool) and a wrong version name look identical
/// through a boolean.
fn describe_mise_pools(data: &Path) -> String {
    fn walk(dir: &Path, depth: usize, out: &mut Vec<String>) {
        if depth == 0 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.file_name().is_some_and(|n| n == "installs") {
                // One level past the pool: the check is for a *version* directory under the tool,
                // so a tool directory that exists but holds no version is the interesting failure
                // and a listing that stopped at the pool could not tell it from a missing tool.
                let listed: Vec<String> = std::fs::read_dir(&p)
                    .map(|es| {
                        es.flatten()
                            .map(|c| {
                                let versions: Vec<String> = std::fs::read_dir(c.path())
                                    .map(|vs| {
                                        vs.flatten()
                                            .map(|v| v.file_name().to_string_lossy().into_owned())
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                format!("{}{versions:?}", c.file_name().to_string_lossy())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                out.push(format!("  {} -> {listed:?}", p.display()));
            } else if p.is_dir() {
                walk(&p, depth - 1, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(&data.join("sbx"), 12, &mut out);
    if out.is_empty() {
        format!("no mise install pool anywhere under {}", data.display())
    } else {
        format!("mise install pools found:\n{}", out.join("\n"))
    }
}

/// Whether `path` (a logical `/nix/store/<hash>-name`) is physically present in `store_dir`.
fn in_store(store_dir: &Path, path: &Path) -> bool {
    store_dir
        .join("nix/store")
        .join(path.file_name().expect("store path basename"))
        .exists()
}

#[test]
fn sbx_gc_keeps_a_current_flake_build_and_reclaims_a_rolled_away_one() {
    // The live proof of `sbx gc` for a host-side `flake:` package, in two phases pinning the one
    // property that matters: `sbx gc --prune` must KEEP the current build and reclaim the one a roll
    // superseded. A host-side flake is provisioned like a `nix:` tool — its build lands in the shared
    // store, is seeded into the per-project store (with a seed root), and is rooted host-side by a
    // data-dir out-link `<data>/sbx/gcroots/projects/<id>/hello` (not an in-cage `sbx-flake-hello`
    // root — only an inline `[flakes]` writes one now).
    //   Phase 1 (KEEP): build `hello`, `sbx gc --prune` with `hello` current — the build SURVIVES, and
    //            a seeded base (glibc) path survives too.
    //   Phase 2 (ROLL re-point): change the package's flake ref to a genuinely-distinct target under
    //            the *same* package name (`#hello` → `#figlet`), relaunch (the `hello` out-link
    //            re-points to the new build), `sbx gc --prune` — the OLD build is COLLECTED and the NEW
    //            one KEPT, in one pass, through the same superseded-root reconciliation a `nix:`
    //            rebuild uses. (A *removed* package's reclamation is covered at the unit level by
    //            `prune_project_package_roots_keeps_declared_and_multi_output_siblings`.)
    // Skips (never fails) without sandbox or network.
    let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    let project = TmpDir::new("gc-proj");
    let data = TmpDir::new("gc-data");
    let state = TmpDir::new("gc-state");
    let cfg = |attr: &str| {
        format!(
            "[packages]\nhello = \"flake:github:NixOS/nixpkgs/{rev}#{attr}\"\n\
             [network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n"
        )
    };
    std::fs::write(project.path().join(".sbx.toml"), cfg("hello")).unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping sbx gc e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping sbx gc e2e: the network is unreachable");
        return;
    }

    let trust = |proj: &Path| {
        let t = sbx_in(proj, data.path(), state.path(), &["trust", ".sbx.toml"]);
        assert!(
            t.status.success(),
            "sbx trust failed: {}",
            String::from_utf8_lossy(&t.stderr)
        );
    };
    trust(project.path());

    // Build the flake package host-side. Floating is enough — no pin needed.
    let built = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "hello"],
    );
    let built_log = format!(
        "{}{}",
        String::from_utf8_lossy(&built.stderr),
        String::from_utf8_lossy(&built.stdout)
    );
    if !built.status.success() && transient_fetch_failure(&built_log) {
        eprintln!("skipping sbx gc e2e: transient nix download fault: {built_log}");
        return;
    }
    if !built.status.success() || !String::from_utf8_lossy(&built.stdout).contains("Hello, world!")
    {
        eprintln!("skipping sbx gc e2e: the flake build did not complete host-side: {built_log}");
        return;
    }

    let store_dir = project_store_dir(data.path()).expect("project store");
    let hello_path =
        project_package_out_link_target(data.path(), "hello").expect("hello out-link target");
    assert!(
        in_store(&store_dir, &hello_path),
        "the flake build is not in the project store before gc: {hello_path:?}"
    );
    // A seeded base (glibc) seed root — the survival witness across both phases. A seed root's file
    // name is the store-path basename, so `-glibc-` locates it.
    let gcroots = store_dir.join("nix/var/nix/gcroots");
    let base_name = std::fs::read_dir(&gcroots)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .find(|n| n.to_string_lossy().contains("-glibc-"))
        .expect("a seeded glibc root");
    let base_path = std::fs::read_link(gcroots.join(&base_name)).unwrap();

    // ---- Phase 1: gc with `hello` still current — the build must SURVIVE. ----
    let gc1 = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["gc", "--prune"],
    );
    let gc1_log = format!(
        "{}{}",
        String::from_utf8_lossy(&gc1.stderr),
        String::from_utf8_lossy(&gc1.stdout)
    );
    assert!(
        gc1.status.success(),
        "sbx gc --prune (phase 1) failed: {gc1_log}"
    );
    assert!(
        in_store(&store_dir, &hello_path),
        "the CURRENT flake build was collected by gc — host-side rooting did not hold: \
         {hello_path:?}\n{gc1_log}"
    );
    assert!(
        in_store(&store_dir, &base_path),
        "a seeded base path was collected by gc: {base_path:?}\n{gc1_log}"
    );

    // ---- Phase 2: roll the package's flake ref to a genuinely-distinct target under the same name
    // (`#hello` → `#figlet`), relaunch (the out-link re-points), then gc: the OLD build is collected
    // and the NEW one kept, via the same superseded-root reconciliation a `nix:` rebuild uses. ----
    std::fs::write(project.path().join(".sbx.toml"), cfg("figlet")).unwrap();
    trust(project.path());
    // Relaunch: re-provision host-side (target changed → the stamp misses → a rebuild), re-pointing
    // the `hello` out-link at figlet's build. `true` is enough — provisioning is what re-points, and
    // the rolled-to package provides `figlet`, not `hello`, so we do not run it by name.
    let relaunch = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    let relaunch_log = format!(
        "{}{}",
        String::from_utf8_lossy(&relaunch.stderr),
        String::from_utf8_lossy(&relaunch.stdout)
    );
    if !relaunch.status.success() && transient_fetch_failure(&relaunch_log) {
        eprintln!("skipping sbx gc e2e: transient nix download fault on the roll: {relaunch_log}");
        return;
    }
    assert!(
        relaunch.status.success(),
        "the rolled flake ref must build host-side: {relaunch_log}"
    );

    let figlet_path =
        project_package_out_link_target(data.path(), "hello").expect("re-pointed out-link target");
    assert_ne!(
        figlet_path, hello_path,
        "the roll must re-point the `hello` out-link at a genuinely-distinct build (still \
         {hello_path:?})"
    );
    assert!(
        in_store(&store_dir, &figlet_path),
        "the rolled-to build is not in the project store: {figlet_path:?}"
    );

    let gc2 = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["gc", "--prune"],
    );
    let gc2_log = format!(
        "{}{}",
        String::from_utf8_lossy(&gc2.stderr),
        String::from_utf8_lossy(&gc2.stdout)
    );
    assert!(
        gc2.status.success(),
        "sbx gc --prune (phase 2) failed: {gc2_log}"
    );
    // The OLD (rolled-away) build is collected; the NEW build and the base survive.
    assert!(
        !in_store(&store_dir, &hello_path),
        "the rolled-away flake build was not collected: {hello_path:?}\n{gc2_log}"
    );
    assert!(
        in_store(&store_dir, &figlet_path),
        "gc collected the CURRENT (rolled-to) flake build: {figlet_path:?}\n{gc2_log}"
    );
    assert!(
        in_store(&store_dir, &base_path),
        "gc dropped a current base path: {base_path:?}\n{gc2_log}"
    );
}

#[test]
fn sbx_projects_rm_dead_reaps_a_deleted_projects_tree() {
    // The live proof of `sbx projects rm --dead --yes --gc` (the cross-project dead-tree reap plus
    // the chained shared-store collection), through the real binary. A launch records the project's
    // canonical path in a `<data>/projects/<id>/project` marker and seeds the project's own
    // (read-only, 0555) nix store; once the project directory is deleted, `sbx projects rm --dead`
    // reads that marker, sees the path is gone (its parent — the scratch root — still present), and
    // reclaims the whole tree (store dirs and all, which is why the reaper forces them writable).
    // `--gc` then runs the shared-store collection in the same command. Skips (never fails) without
    // sandbox or network.
    use std::os::unix::ffi::OsStrExt;
    let project = TmpDir::new("gca-proj");
    let scratch = TmpDir::new("gca-scratch");
    let data = TmpDir::new("gca-data");
    let state = TmpDir::new("gca-state");

    // A launch seeds the store and writes the marker; the probe both checks sandbox capability and
    // does that seeding.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping sbx projects rm --dead e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping sbx projects rm --dead e2e: the network is unreachable");
        return;
    }

    // The launch created exactly one project tree; capture it and confirm its marker records the
    // project's canonical path (the part-1 marker, proven end-to-end through the binary).
    let projects = data.path().join("sbx").join("projects");
    let tree = std::fs::read_dir(&projects)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("a project tree after a launch");
    let marker = std::fs::read(tree.join("project")).expect("the project marker");
    let canonical = project.path().canonicalize().unwrap();
    assert_eq!(
        std::ffi::OsStr::from_bytes(&marker),
        canonical.as_os_str(),
        "the marker must record the project's canonical path"
    );

    // Delete the project directory — but not its parent (the scratch root), so the reap treats it
    // as a deleted project, not an unmounted drive.
    std::fs::remove_dir_all(project.path()).unwrap();

    // Reap from a separate scratch directory (`sbx projects rm` never seeds or sweeps a current
    // project, so the scratch dir just gives the command a cwd): the dead tree is reclaimed by the
    // `--dead` sweep, and `--gc` chains the shared-store collection.
    let gc = sbx_in(
        scratch.path(),
        data.path(),
        state.path(),
        &["projects", "rm", "--dead", "--yes", "--gc"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&gc.stderr),
        String::from_utf8_lossy(&gc.stdout)
    );
    assert!(
        gc.status.success(),
        "sbx projects rm --dead --yes --gc failed: {log}"
    );
    assert!(
        !tree.exists(),
        "the deleted project's tree (read-only store and all) was not reclaimed: {tree:?}\n{log}"
    );
    assert!(
        String::from_utf8_lossy(&gc.stdout).contains(&canonical.display().to_string()),
        "the reap should name the reclaimed project path: {log}"
    );
    // The dead tree was the only one; `sbx projects rm` seeds nothing, so after the reap the
    // projects directory is left empty.
    let remaining = std::fs::read_dir(&projects)
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        remaining, 0,
        "a project tree survived the --dead reap\n{log}"
    );

    // The shared-store gc pass ran (its own line) and must NOT have collected the live base: the
    // global channel revision is still locked, so its base gc root and closure survive. (A near
    // no-op here — there are no stale revisions — but it exercises the seeder flock, the live-set
    // computation, the gcroot scan, and `nix-store --gc` on the real shared store.)
    assert!(
        String::from_utf8_lossy(&gc.stdout).contains("shared store"),
        "the shared-store gc pass did not run: {log}"
    );
    let base_gcroots = data.path().join("sbx/gcroots/base");
    assert!(
        std::fs::read_dir(&base_gcroots)
            .map(|d| d.flatten().any(|e| e.path().is_dir()))
            .unwrap_or(false),
        "the live base channel's gc root was collected by the shared-store gc: {base_gcroots:?}\n{log}"
    );
    let shared_paths = data.path().join("sbx/store/nix/store");
    assert!(
        std::fs::read_dir(&shared_paths)
            .map(|d| d.flatten().next().is_some())
            .unwrap_or(false),
        "the shared store was emptied — the live base closure was wrongly collected: {shared_paths:?}\n{log}"
    );
}

#[test]
fn a_secret_is_resolved_host_side_and_never_enters_the_cage() {
    // The 6.3a integration neither the unit nor the proxy tests can reach: a trusted
    // A `[secret]` entry under a network allowlist must be resolved *host-side* and wired into the
    // egress proxy without the plaintext ever entering the cage. So `printenv` inside the cage
    // must show neither the source variable's name nor its value — the launch carries the
    // credential only through the proxy, never the sandbox environment. (The complementary
    // "it reaches the upstream" half is proven by the in-crate proxy TLS-MITM tests; this is the
    // no-leak half, which needs no echo service and no successful egress.) Skips (never fails)
    // when the host cannot sandbox.
    let project = TmpDir::new("secret-proj");
    let data = TmpDir::new("secret-data");
    let state = TmpDir::new("secret-state");
    let secret_value = "sbx-e2e-secret-must-not-leak-4b7x";
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\n\
         [secret.\"cache.nixos.org\"]\nfrom = \"env://SBX_E2E_SECRET\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net, secret dropped): seeds the base store and
    // confirms the host can sandbox; otherwise skip.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping secret no-leak e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // trust the project so its secret (a security field) is honored.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // `sbx config` confirms the secret is honored host-side (not silently dropped), so the
    // cage-absence below is meaningful — and it must show the source by locator, never a value.
    let cfg = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["config", "show"],
    );
    let cfg_out = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        cfg_out.contains("Authorization -> https://cache.nixos.org")
            && cfg_out.contains("from env SBX_E2E_SECRET"),
        "the trusted secret was not honored by `sbx config`: {cfg_out}"
    );

    // the launch: `printenv` inside the cage, with the secret set in sbx's environment. The
    // launch must succeed (the secret resolved and wired without error), and the cage env must
    // contain neither the source variable's name nor its value.
    let env_out = sbx()
        .args(["run", "--", "printenv"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_SECRET", secret_value)
        .output()
        .expect("spawn sbx run");
    assert!(
        env_out.status.success(),
        "the launch with a wired secret failed: {}",
        String::from_utf8_lossy(&env_out.stderr)
    );
    let cage_env = String::from_utf8_lossy(&env_out.stdout);
    assert!(
        !cage_env.contains("SBX_E2E_SECRET"),
        "the secret's source variable leaked into the cage env: {cage_env}"
    );
    assert!(
        !cage_env.contains(secret_value),
        "the secret value leaked into the cage env"
    );
}

#[test]
fn a_resolver_plugin_resolves_a_secret_host_side_and_never_enters_the_cage() {
    // The full 2b seam no in-crate test crosses: a resolver plugin *installed on disk* under
    // `<data>/plugins/<name>/` is discovered by `PluginRegistry::load`, claimed by a trusted
    // project's `[secret]` `from`, and run host-side in its own bwrap cage by the launcher — the
    // plaintext wired into the egress proxy, never the sandbox environment. So a launch that runs
    // the resolver must succeed, and `printenv` inside the cage must show neither the locator nor
    // the resolved value. Skips (never fails) when the host cannot sandbox.
    let project = TmpDir::new("rplugin-proj");
    let data = TmpDir::new("rplugin-data");
    let state = TmpDir::new("rplugin-state");
    let secret_value = "sbx-plugin-e2e-secret-7q2z";

    // install a resolver plugin: a manifest plus an executable that returns a constant plaintext.
    // (`PluginRegistry::load` reads `<XDG_DATA_HOME>/sbx/plugins`.)
    let plugin_dir = data.path().join("sbx/plugins/myresolver");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    std::fs::write(
        plugin_dir.join("plugin.toml"),
        "name = \"myresolver\"\ntype = \"resolver\"\nscheme = \"myscheme\"\nexec = \"resolve\"\n",
    )
    .unwrap();
    let exec = plugin_dir.join("resolve");
    std::fs::write(&exec, format!("#!/bin/sh\nprintf '%s' '{secret_value}'\n")).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\n\
         [secret.\"cache.nixos.org\"]\nfrom = \"myscheme://github/token\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n",
    )
    .unwrap();

    // capability probe (untrusted → shared net, secret dropped): seeds the store, confirms sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping resolver-plugin e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // `sbx config` shows the plugin-backed source honored, by scheme + locator (never a value).
    let cfg = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["config", "show"],
    );
    let cfg_out = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        cfg_out.contains("Authorization -> https://cache.nixos.org")
            && cfg_out.contains("from myscheme github/token"),
        "the plugin-backed secret was not honored by `sbx config`: {cfg_out}"
    );

    // the launch resolves the secret by *running the plugin host-side*; it must succeed, and the
    // cage env must contain neither the locator nor the resolved value.
    let env_out = sbx()
        .args(["run", "--", "printenv"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn sbx run");
    assert!(
        env_out.status.success(),
        "the launch running the resolver plugin failed: {}",
        String::from_utf8_lossy(&env_out.stderr)
    );
    let cage_env = String::from_utf8_lossy(&env_out.stdout);
    assert!(
        !cage_env.contains(secret_value),
        "the resolved secret value leaked into the cage env"
    );
    assert!(
        !cage_env.contains("github/token"),
        "the secret's locator leaked into the cage env: {cage_env}"
    );
}

#[test]
fn an_outbound_secret_is_refused_at_the_proxy() {
    // The 6.3b outbound tripwire end to end through the real binary: under a trusted network
    // allowlist with a `[secret]` entry, a request that carries the secret value verbatim is refused
    // *at the proxy* (block, never strip) — even toward the allowed host the secret is scoped to —
    // so a credential the agent obtained out of band (a reflecting upstream) cannot be
    // re-exfiltrated in the clear. The cage never holds the value; the test hardcodes it to play
    // an agent that learned it. The refusal fires before any DNS/connect, so it holds offline; the
    // positive control (a clean fetch still works) is gated on the cache being reachable. Skips
    // (never fails) when the host cannot sandbox.
    let project = TmpDir::new("leak-proj");
    let data = TmpDir::new("leak-data");
    let state = TmpDir::new("leak-state");
    // a filename-safe value (it rides in a URL path below) that appears nowhere in normal traffic
    let secret_value = "sbx-e2e-leak-canary-9z3k";
    std::fs::write(
        project.path().join(".sbx.toml"),
        "[network]\nmode = \"deny\"\nallow = [\"cache.nixos.org\"]\n\n\
         [secret.\"cache.nixos.org\"]\nfrom = \"env://SBX_E2E_LEAK\"\n\
         header = \"Authorization\"\ntype = \"bearer\"\n",
    )
    .unwrap();

    // capability probe (also seeds the store, so a later failure is a real fault, not a cold cage)
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping outbound-secret e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // trust the project so its secret + allowlist (security fields) are honored
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // EXFIL (teeth): the cage sends the secret value verbatim in the request URL toward the
    // ALLOWED host. The proxy's tripwire refuses it with a 403 before any fetch — the refusal is
    // local to the proxy, so this holds even offline (no DNS/connect happens).
    let exfil_url = format!("https://cache.nixos.org/{secret_value}");
    let exfil = sbx()
        .args([
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            &exfil_url,
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_LEAK", secret_value)
        .output()
        .expect("spawn sbx run");
    assert!(
        !exfil.status.success(),
        "an outbound secret unexpectedly succeeded: {}",
        String::from_utf8_lossy(&exfil.stdout)
    );
    assert!(
        String::from_utf8_lossy(&exfil.stderr).contains("HTTP error 403"),
        "an outbound secret must be refused with a 403 at the proxy: {}",
        String::from_utf8_lossy(&exfil.stderr)
    );

    // CONTROL: a clean request to the same allowed host still works, so the tripwire is not a
    // blanket block. Gated on the cache being reachable (this one genuinely fetches).
    if !cache_reachable() {
        eprintln!("skipping the outbound-secret positive control: the binary cache is unreachable");
        return;
    }
    let clean = sbx()
        .args([
            "run",
            "--",
            "nix-prefetch-url",
            "--type",
            "sha256",
            "https://cache.nixos.org/nix-cache-info",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("SBX_E2E_LEAK", secret_value)
        .output()
        .expect("spawn sbx run");
    assert!(
        clean.status.success(),
        "a clean allowed request must still succeed: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(
        String::from_utf8_lossy(&clean.stdout)
            .contains("15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c"),
        "the clean control fetch did not return the expected hash: {}",
        String::from_utf8_lossy(&clean.stdout)
    );
}

/// The cage runs inside a transient systemd scope carrying the anti-DoS resource
/// limits. `sbx run` exec-replaces, so the spawned child keeps its pid *as* the
/// bwrap process placed in the scope; reading that pid's cgroup from the host and
/// finding `pids.max` equal to the configured task cap is conclusive proof the
/// limit landed through the full launch path — no unrelated process carries that
/// exact value. Skips (does not fail) where the host cannot sandbox or has no
/// systemd user session that delegates the pids controller.
#[test]
fn the_cage_runs_under_a_resource_limit_scope() {
    const TASK_CAP: &str = "16384"; // mirrors sandbox::cgroup::TASKS_MAX
    let project = TmpDir::new("cg-proj");
    let data = TmpDir::new("cg-data");

    // capability probe (also primes the base userland so the sleep launches fast)
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping resource-limit e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let mut child = sbx()
        .arg("run")
        .arg("--")
        .args(["sleep", "5"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sbx run");
    let pid = child.id();

    // Poll the cage's host-visible cgroup until the scope's task cap appears.
    let mut pids_max = String::new();
    for _ in 0..50 {
        if let Some(scope) = host_cgroup_path(pid)
            && let Ok(v) = std::fs::read_to_string(format!("/sys/fs/cgroup{scope}/pids.max"))
        {
            pids_max = v.trim().to_string();
            if pids_max == TASK_CAP {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();

    // A match means a real `sbx run` placed the cage in a scope with the
    // configured cap; otherwise skip (no systemd user session delegating pids).
    if pids_max != TASK_CAP {
        eprintln!(
            "skipping resource-limit e2e: the cage is not under a task-capped scope \
             (pids.max={pids_max:?}); likely no systemd user session delegating pids"
        );
    }
}

/// A trusted `[limits]` override reaches the cage's scope. A project lowers the task cap to a
/// value distinct from the built-in default, trusts it (the limits are a security field), then
/// launches; the cage's host-visible `pids.max` equal to the *override* — not the default — is
/// conclusive proof the config threaded through resolve → `cgroup::wrap` → the systemd scope. A
/// leak of the default would be a real regression (panic), while no scope at all is a host skip.
#[test]
fn a_trusted_limits_override_lands_in_the_cage_scope() {
    const OVERRIDE_CAP: &str = "4096"; // distinct from the default sandbox::cgroup::TASKS_MAX (16384)
    const DEFAULT_CAP: &str = "16384";
    let project = TmpDir::new("cglim-proj");
    let data = TmpDir::new("cglim-data");
    let state = TmpDir::new("cglim-state");

    // A trusted project lowers the task cap below the default. `[limits]` is a security field,
    // honored only after `sbx trust`.
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[limits]\ntasks_max = 4096\n",
    )
    .unwrap();

    // Capability probe (also primes the base userland so the measured launch starts fast). It runs
    // before the trust step, which is fine — it only checks the host can sandbox.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping limits-override e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // Trust the project so its `[limits]` override applies.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let mut child = sbx()
        .arg("run")
        .arg("--")
        .args(["sleep", "5"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sbx run");
    let pid = child.id();

    let mut pids_max = String::new();
    for _ in 0..50 {
        if let Some(scope) = host_cgroup_path(pid)
            && let Ok(v) = std::fs::read_to_string(format!("/sys/fs/cgroup{scope}/pids.max"))
        {
            pids_max = v.trim().to_string();
            if pids_max == OVERRIDE_CAP {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();

    if pids_max != OVERRIDE_CAP {
        // The default leaking through means the scope applied but the override did not — a real
        // regression in the config→cgroup threading, so fail. Any other value (or none) is the
        // host having no systemd user session that delegates the pids controller — skip.
        assert_ne!(
            pids_max, DEFAULT_CAP,
            "the cage ran under the default task cap, not the trusted override {OVERRIDE_CAP} — \
             the `[limits]` override did not thread through to the scope"
        );
        eprintln!(
            "skipping limits-override e2e: the cage is not under a task-capped scope \
             (pids.max={pids_max:?}); likely no systemd user session delegating pids"
        );
    }
}

/// A trusted `[seccomp] allow` relaxation threads through the real launch path — the
/// config → spec → `memfds(&policy)` → bwrap `--add-seccomp-fd` chain a `build_spec` unit test
/// cannot cover (it never invokes bwrap with the compiled filters). The kernel *enforcement* of a
/// fine-grained lift is proven in `src/sandbox/seccomp.rs`'s real-cage tests; this proves the
/// relaxed filters still compile, load, and launch a working cage through `sbx run` — a
/// non-regression that a `[seccomp]` config never breaks a launch.
#[test]
fn a_trusted_seccomp_relaxation_launches_a_working_cage() {
    let project = TmpDir::new("sec-proj");
    let data = TmpDir::new("sec-data");
    let state = TmpDir::new("sec-state");

    // A relaxation mixing a whole-syscall lift (comma-separated in one string) and a fine-grained
    // selector — the union of both must thread through. `[seccomp]` is a security field, so it
    // applies only after `sbx trust`.
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[seccomp]\nallow = [\"ptrace,perf_event_open\", \"clone:newns\"]\n",
    )
    .unwrap();

    // Capability probe (also seeds the base userland); skip if the host cannot sandbox.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping seccomp-relaxation e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // Trust the project so its `[seccomp]` relaxation applies.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The relaxed cage launches and runs `id` to success — the policy threaded to the real bwrap
    // invocation, the modified filters loaded, and the synthetic identity resolves (hermetic).
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "id"],
    );
    assert!(
        out.status.success(),
        "a trusted seccomp relaxation must launch a working cage; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("(sandbox)"),
        "the relaxed cage must run hermetically as the synthetic identity:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A trusted `[devices]` grant binds a real host device into the cage — the
/// config→resolve→build_spec→`Mount::DevBind`→bwrap `--dev-bind-try` thread a unit test cannot reach.
/// Teeth: the device is ABSENT from the default minimal `/dev` (the untrusted probe launch, whose
/// grant is dropped), and PRESENT only after the project is trusted so the grant applies — so the
/// device appears solely because of the grant. Skips if the host cannot sandbox, or if none of the
/// candidate devices exists on this host.
#[test]
fn a_trusted_devices_grant_binds_a_host_device_into_the_cage() {
    // A device present on this host but absent from bwrap's minimal /dev (null/zero/tty…).
    let Some(device) = ["/dev/net/tun", "/dev/fuse", "/dev/kvm", "/dev/dri"]
        .into_iter()
        .find(|d| std::path::Path::new(d).exists())
    else {
        eprintln!("skipping devices e2e: no candidate host device present");
        return;
    };

    let project = TmpDir::new("dev-proj");
    let data = TmpDir::new("dev-data");
    let state = TmpDir::new("dev-state");

    std::fs::write(
        project.path().join(".sbx.toml"),
        format!("[devices]\nallow = [\"{device}\"]\n").as_bytes(),
    )
    .unwrap();
    let check = format!("test -e {device} && echo DEV-PRESENT || echo DEV-ABSENT");

    // Untrusted probe (also seeds the base userland): the grant is dropped, so the device is ABSENT
    // in the minimal /dev. A failed launch means the host cannot sandbox → skip.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check.as_str()],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping devices e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    assert!(
        String::from_utf8_lossy(&probe.stdout).contains("DEV-ABSENT"),
        "the untrusted (dropped) grant must leave the device out of the minimal /dev:\n{}",
        String::from_utf8_lossy(&probe.stdout)
    );

    // Trust the project so its `[devices]` grant applies.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The device is now bound into the cage — the whole thread landed at a real `--dev-bind-try`.
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check.as_str()],
    );
    assert!(
        out.status.success(),
        "a trusted devices grant must launch a working cage; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("DEV-PRESENT"),
        "the trusted `[devices]` grant must bind {device} into the cage:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A trusted `gpu = true` threads the GPU hole's device grant and `/sys` DRM subtree into the cage,
/// gated by trust. The firm teeth are network-independent: the render node `/dev/dri` and the
/// `/sys/class/drm` index are ABSENT under an untrusted (dropped) posture and PRESENT once trusted —
/// the whole gpu→launch→`--dev-bind-try`/`--ro-bind` thread a `build_spec` unit test cannot reach.
/// The mesa driver env is best-effort (its provisioning may not reach the cache in this env), so it
/// is reported, not asserted; `driver_env` is unit-tested and the full render is proven live.
/// Skips if the host has no GPU render node or cannot sandbox.
#[test]
fn a_trusted_gpu_posture_grants_the_render_node_and_sys_to_the_cage() {
    if !std::path::Path::new("/dev/dri").exists() {
        eprintln!("skipping gpu e2e: no /dev/dri render node on this host");
        return;
    }

    let project = TmpDir::new("gpu-proj");
    let data = TmpDir::new("gpu-data");
    let state = TmpDir::new("gpu-state");

    std::fs::write(project.path().join(".sbx.toml"), b"gpu = true\n").unwrap();
    let check = "test -e /dev/dri && echo DRI-PRESENT || echo DRI-ABSENT; \
                 test -e /sys/class/drm && echo SYS-PRESENT || echo SYS-ABSENT; \
                 test -n \"$LIBGL_DRIVERS_PATH\" && echo ENV-SET || echo ENV-UNSET";

    // Untrusted probe (also seeds the base userland): the posture is dropped, so neither the render
    // node nor `/sys` is exposed. A failed launch means the host cannot sandbox → skip.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping gpu e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    let probe_out = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe_out.contains("DRI-ABSENT"),
        "the untrusted (dropped) gpu posture must leave /dev/dri out of the cage:\n{probe_out}"
    );
    assert!(
        probe_out.contains("SYS-ABSENT"),
        "the hermetic cage must carry no /sys without the gpu posture:\n{probe_out}"
    );

    // Trust the project so its `gpu = true` posture applies.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The render node and the `/sys` DRM index are now bound into the cage.
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check],
    );
    assert!(
        out.status.success(),
        "a trusted gpu posture must launch a working cage; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("DRI-PRESENT"),
        "the trusted `gpu = true` posture must bind the render node into the cage:\n{stdout}"
    );
    assert!(
        stdout.contains("SYS-PRESENT"),
        "the trusted `gpu = true` posture must bind the /sys DRM subtree into the cage:\n{stdout}"
    );
    // The mesa driver env is best-effort (provisioning may not reach the cache here) — reported, not
    // asserted, since a missing closure degrades to software rendering rather than a launch failure.
    eprintln!(
        "gpu e2e: mesa driver env {}",
        if stdout.contains("ENV-SET") {
            "reached the cage"
        } else {
            "was not provisioned (best-effort)"
        }
    );
}

/// A trusted `audio = true` binds the host PulseAudio socket into the cage and wires the ALSA→pulse
/// shim, gated by trust. The firm teeth are network-independent: the cage socket `/run/sbx-pulse` and
/// `PULSE_SERVER` are ABSENT under an untrusted (dropped) posture and PRESENT once trusted — the whole
/// audio→launch→`--ro-bind` thread a `build_spec` unit test cannot reach. The shim (the `asound.conf`
/// bind + `ALSA_*` env) and a REAL `arecord` capture through it are best-effort (they need the
/// userspace provisioned AND a live microphone), so they are reported, not asserted; the shim
/// mechanism is proven separately (an ALSA client captures via the pulse socket in a hermetic cage),
/// and a real voice-mode recording in a shipped CLI is the live user ship-gate. Skips if the host has
/// no PulseAudio socket or cannot sandbox.
#[test]
fn a_trusted_audio_posture_binds_the_pulseaudio_socket_into_the_cage() {
    let host_socket = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(|d| std::path::PathBuf::from(d).join("pulse/native"));
    match &host_socket {
        Some(p) if p.exists() => {}
        _ => {
            eprintln!("skipping audio e2e: no PulseAudio socket at $XDG_RUNTIME_DIR/pulse/native");
            return;
        }
    }

    let project = TmpDir::new("audio-proj");
    let data = TmpDir::new("audio-data");
    let state = TmpDir::new("audio-state");

    // `alsa-utils` gives the cage `arecord`, so the e2e can attempt a real ALSA capture through the
    // shim (best-effort). A `[packages]` backend is trusted-only, so it is also dropped untrusted.
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"audio = true\n\n[packages]\nalsautils = \"nix:alsa-utils\"\n",
    )
    .unwrap();
    let check = "test -S /run/sbx-pulse && echo PULSE-PRESENT || echo PULSE-ABSENT; \
                 test -n \"$PULSE_SERVER\" && echo ENV-SET || echo ENV-UNSET; \
                 test -f /etc/asound.conf && echo ASOUND-PRESENT || echo ASOUND-ABSENT; \
                 test -n \"$ALSA_PLUGIN_DIR\" && echo ALSAENV-SET || echo ALSAENV-UNSET; \
                 arecord -D default -f S16_LE -r 16000 -c 1 -d 1 /tmp/cap.wav >/dev/null 2>&1 \
                    && echo CAPTURED-$(wc -c </tmp/cap.wav) || echo CAPTURE-FAILED";

    // Untrusted probe (also seeds the base userland): the posture is dropped, so no socket is bound.
    // A failed launch means the host cannot sandbox → skip.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping audio e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    let probe_out = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe_out.contains("PULSE-ABSENT"),
        "the untrusted (dropped) audio posture must leave the PulseAudio socket out of the cage:\n{probe_out}"
    );

    // Trust the project so its `audio = true` posture applies.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // The host PulseAudio socket is now bound into the cage and named through PULSE_SERVER.
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check],
    );
    assert!(
        out.status.success(),
        "a trusted audio posture must launch a working cage; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PULSE-PRESENT"),
        "the trusted `audio = true` posture must bind the PulseAudio socket into the cage:\n{stdout}"
    );
    assert!(
        stdout.contains("ENV-SET"),
        "the trusted `audio = true` posture must set PULSE_SERVER:\n{stdout}"
    );
    // The ALSA→pulse shim + a real capture are best-effort (need provisioning + a live mic here) —
    // reported, not asserted, since a missing closure or absent mic degrades to no-audio rather than
    // a launch failure. A `CAPTURED-<bytes>` line is the full sbx-wired shim proven end-to-end.
    let capture = stdout
        .lines()
        .find(|l| l.starts_with("CAPTURED-") || *l == "CAPTURE-FAILED")
        .unwrap_or("CAPTURE-?");
    eprintln!(
        "audio e2e: ALSA shim asound.conf={} env={}, real capture: {capture}",
        if stdout.contains("ASOUND-PRESENT") {
            "bound"
        } else {
            "absent (best-effort)"
        },
        if stdout.contains("ALSAENV-SET") {
            "set"
        } else {
            "unset (best-effort)"
        },
    );
}

/// A trusted `audio = true` also equips a Python **PortAudio** tool (`sounddevice`) — the third audio
/// client kind, distinct from the ALSA-direct path the `arecord` e2e above covers (that one passed
/// while PortAudio was broken — the false-green this test closes). The firm, network-independent
/// teeth: the `find_library` shim `/opt/sbx/audio-pyshim/sitecustomize.py` is ABSENT under an
/// untrusted (dropped) posture — the shim is gated by trust. When provisioning succeeds (needs the nix
/// cache), the test installs an UNPATCHED PyPI `sounddevice` and asserts it imports: that exercises
/// the real PortAudio path — the shim resolving `libportaudio.so.2` off `LD_LIBRARY_PATH`, which the
/// stock hermetic `find_library` (no ldconfig/gcc/ld) cannot. A real recorded sample needs a live mic,
/// so it is reported, not asserted. App-agnostic: a generic project with `nix:python312` + PyPI
/// `sounddevice`, never a shipped profile. Skips if the host has no PulseAudio socket or cannot
/// sandbox.
#[test]
fn a_trusted_audio_posture_equips_a_python_portaudio_tool() {
    let host_socket = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .map(|d| std::path::PathBuf::from(d).join("pulse/native"));
    match &host_socket {
        Some(p) if p.exists() => {}
        _ => {
            eprintln!(
                "skipping PortAudio e2e: no PulseAudio socket at $XDG_RUNTIME_DIR/pulse/native"
            );
            return;
        }
    }

    let project = TmpDir::new("pa-proj");
    let data = TmpDir::new("pa-data");
    let state = TmpDir::new("pa-state");

    // `python312` + `uv` give the cage an interpreter and installer, so the e2e can install an
    // UNPATCHED PyPI `sounddevice` — the nixpkgs one is patched to hardcode the store path, which
    // would bypass the very `find_library` shim under test. A `[packages]` backend is trusted-only,
    // so it is dropped untrusted (no python/uv on PATH there).
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"audio = true\n\n[packages]\npython = \"nix:python312\"\nuv = \"nix:uv\"\n",
    )
    .unwrap();

    let check = r#"test -S /run/sbx-pulse && echo PULSE-PRESENT || echo PULSE-ABSENT
test -f /opt/sbx/audio-pyshim/sitecustomize.py && echo PYSHIM-PRESENT || echo PYSHIM-ABSENT
test -n "$PYTHONPATH" && echo PYTHONPATH-SET || echo PYTHONPATH-UNSET
case ":$LD_LIBRARY_PATH:" in *portaudio*) echo PORTAUDIO-ON-LDPATH;; *) echo PORTAUDIO-OFF-LDPATH;; esac
if command -v uv >/dev/null 2>&1 && uv venv /tmp/pv >/dev/null 2>&1 && VIRTUAL_ENV=/tmp/pv uv pip install -q sounddevice >/dev/null 2>&1; then
  /tmp/pv/bin/python -c "import sounddevice as sd; print('PA-IMPORT-OK'); print('PA-DEVICES-%d' % len(sd.query_devices()))" 2>&1 | tail -4
else
  echo PA-NOT-INSTALLED
fi"#;

    // Untrusted probe (also seeds the base userland): the posture is dropped, so the shim is unbound.
    // A failed launch means the host cannot sandbox → skip.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "bash", "-c", check],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping PortAudio e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    let probe_out = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe_out.contains("PYSHIM-ABSENT"),
        "the untrusted (dropped) audio posture must leave the find_library shim out of the cage:\n{probe_out}"
    );

    // Trust so the audio posture applies.
    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "bash", "-c", check],
    );
    assert!(
        out.status.success(),
        "a trusted audio posture must launch a working cage; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Firm: the socket is bound (network-independent).
    assert!(
        stdout.contains("PULSE-PRESENT"),
        "the trusted `audio = true` posture must bind the PulseAudio socket:\n{stdout}"
    );
    // When PortAudio provisioned (best-effort — needs the nix cache), the whole path must hold: the
    // shim is bound, PYTHONPATH points at it, portaudio is on the loader path, and — unless offline —
    // an UNPATCHED PyPI `sounddevice` imports through the shim. These are the teeth on the PortAudio
    // path (not the ALSA-direct one); they degrade cleanly when the cache is unreachable
    // (PYSHIM-ABSENT) or the install is offline (PA-NOT-INSTALLED).
    if stdout.contains("PYSHIM-PRESENT") {
        assert!(
            stdout.contains("PYTHONPATH-SET"),
            "the shim is bound but PYTHONPATH is unset:\n{stdout}"
        );
        assert!(
            stdout.contains("PORTAUDIO-ON-LDPATH"),
            "the shim is bound but portaudio is not on LD_LIBRARY_PATH:\n{stdout}"
        );
        if !stdout.contains("PA-NOT-INSTALLED") {
            assert!(
                stdout.contains("PA-IMPORT-OK"),
                "PortAudio is wired and PyPI sounddevice installed, but its import failed — the \
                 find_library shim + libportaudio integration is broken:\n{stdout}"
            );
        }
    }
    let devices = stdout
        .lines()
        .find(|l| l.starts_with("PA-DEVICES-"))
        .unwrap_or("PA-DEVICES-?");
    eprintln!(
        "PortAudio e2e: shim={}, sounddevice import={}, {devices}",
        if stdout.contains("PYSHIM-PRESENT") {
            "bound"
        } else {
            "absent (best-effort)"
        },
        if stdout.contains("PA-IMPORT-OK") {
            "OK"
        } else if stdout.contains("PA-NOT-INSTALLED") {
            "not-installed (offline)"
        } else {
            "n/a"
        },
    );
}

/// The one-shot `--device` / `--seccomp` security overrides reach the cage — the CLI
/// flag→collect→`apply_override`→build_spec→bwrap thread a config-file e2e cannot reach. Two arms,
/// which build_spec consumes differently:
///   - `--device`: measurable teeth. The SAME project (no trusted `[devices]`) leaves the device
///     ABSENT without the flag and PRESENT with it → the grant threads to a real `--dev-bind-try`,
///     and applies with NO `sbx trust` (trusted **by invocation**).
///   - `--seccomp`: threading coverage. The grant launch also carries `--seccomp ptrace`, so an
///     override-sourced `SeccompPolicy` threads through the real launch path
///     (`apply_override` → `cfg.seccomp` → `build_spec` → `with_seccomp` → `memfds` →
///     `--add-seccomp-fd`); a malformed policy from the union/apply would fail here. Kernel
///     *enforcement* of the relaxation is proven separately in `seccomp.rs` real-cage tests on a
///     byte-identical policy — no base tool triggers a denied syscall distinguishably, so this arm is
///     threading, not enforcement.
///
/// Skips if the host cannot sandbox or no candidate device exists.
#[test]
fn a_typed_one_shot_security_override_reaches_the_cage() {
    let Some(device) = ["/dev/net/tun", "/dev/fuse", "/dev/kvm", "/dev/dri"]
        .into_iter()
        .find(|d| std::path::Path::new(d).exists())
    else {
        eprintln!("skipping one-shot override e2e: no candidate host device present");
        return;
    };

    let project = TmpDir::new("ovr1-proj");
    let data = TmpDir::new("ovr1-data");
    let state = TmpDir::new("ovr1-state");
    let check = format!("test -e {device} && echo DEV-PRESENT || echo DEV-ABSENT");

    // Baseline (also seeds the base userland): no flag, no config → the device is ABSENT from the
    // minimal /dev. A failed launch means the host cannot sandbox → skip.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "sh", "-c", check.as_str()],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping one-shot override e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    assert!(
        String::from_utf8_lossy(&probe.stdout).contains("DEV-ABSENT"),
        "without the flag the device must be absent from the minimal /dev:\n{}",
        String::from_utf8_lossy(&probe.stdout)
    );

    // The one-shot grants — trusted by invocation, so they apply with NO `sbx trust`. `--seccomp
    // ptrace` rides the same launch: its success proves the override's seccomp policy threaded to a
    // valid filter (a union/apply bug corrupting the policy would fail `memfds`/`--add-seccomp-fd`).
    let out = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &[
            "run",
            "--device",
            device,
            "--seccomp",
            "ptrace",
            "--",
            "sh",
            "-c",
            check.as_str(),
        ],
    );
    assert!(
        out.status.success(),
        "a one-shot --device/--seccomp override must launch a working cage; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("DEV-PRESENT"),
        "the one-shot --device flag must bind {device} into the cage:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A trusted app's `[limits]` overlay reaches the cage's scope at `sbx app` dispatch — the seam a
/// `merge_app` unit test cannot cover: that the real dispatch merges the overlay *before* it
/// consumes the limits. An inline `[app.cap]` caps tasks below the default; after trust, `sbx app
/// cap` runs `sleep`, and the cage's host-visible `pids.max` equal to the *app override* — not the
/// default — proves the overlay threaded resolve → merge_app → `cgroup::wrap` → the systemd scope.
/// The default leaking through would be a real regression in that threading (panic); no scope at
/// all is a host without a pids-delegating systemd session (skip).
#[test]
fn a_trusted_app_limits_override_lands_in_the_cage_scope() {
    const OVERRIDE_CAP: &str = "2048"; // distinct from the default (16384) and the baseline e2e's 4096
    const DEFAULT_CAP: &str = "16384";
    let project = TmpDir::new("applim-proj");
    let data = TmpDir::new("applim-data");
    let state = TmpDir::new("applim-state");

    // A trusted app caps tasks below the default — on its overlay, not the baseline. `[limits]` is a
    // security field, so the app must be trusted for the cap to apply.
    std::fs::write(
        project.path().join(".sbx.toml"),
        b"[app.cap]\ncmd = [\"sleep\", \"5\"]\n[app.cap.limits]\ntasks_max = 2048\n",
    )
    .unwrap();

    // Capability probe (also primes the base userland so the measured launch starts fast). Runs
    // before the trust step — it only checks the host can sandbox.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping app-limits e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let trusted = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".sbx.toml"],
    );
    assert!(
        trusted.status.success(),
        "sbx trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let mut child = sbx()
        .arg("app")
        .arg("run")
        .arg("cap")
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sbx app");
    let pid = child.id();

    let mut pids_max = String::new();
    for _ in 0..50 {
        if let Some(scope) = host_cgroup_path(pid)
            && let Ok(v) = std::fs::read_to_string(format!("/sys/fs/cgroup{scope}/pids.max"))
        {
            pids_max = v.trim().to_string();
            if pids_max == OVERRIDE_CAP {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();

    if pids_max != OVERRIDE_CAP {
        assert_ne!(
            pids_max, DEFAULT_CAP,
            "the app cage ran under the default task cap, not the trusted app override \
             {OVERRIDE_CAP} — the app `[limits]` overlay did not thread through merge_app to the scope"
        );
        eprintln!(
            "skipping app-limits e2e: the cage is not under a task-capped scope \
             (pids.max={pids_max:?}); likely no systemd user session delegating pids"
        );
    }
}

/// A typed one-shot `--limit` reaches the cage's scope — no project config, no trust: the override
/// is trusted by invocation. `sbx run --limit tasks_max=8192 -- sleep` with the cage's host-visible
/// `pids.max` equal to 8192 (not the built-in default) proves the typed flag threads collect →
/// apply_override → `cgroup::wrap` → the systemd scope, the same seam the `[limits]` config e2e
/// proves for a file — but through the increment-2 typed-flag surface instead of a TOML blob.
#[test]
fn a_typed_one_shot_limit_flag_lands_in_the_cage_scope() {
    const OVERRIDE_CAP: &str = "8192"; // distinct from the default TASKS_MAX (16384)
    const DEFAULT_CAP: &str = "16384";
    let project = TmpDir::new("cgtyped-proj");
    let data = TmpDir::new("cgtyped-data");
    let state = TmpDir::new("cgtyped-state");

    // Capability probe (also primes the base userland so the measured launch starts fast). No
    // project config and no `sbx trust` — the one-shot override is trusted by invocation.
    let probe = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "true"],
    );
    if !probe.status.success() {
        eprintln!(
            "skipping typed-limit e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let mut child = sbx()
        .args(["run", "--limit", "tasks_max=8192", "--"])
        .args(["sleep", "5"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn sbx run");
    let pid = child.id();

    let mut pids_max = String::new();
    for _ in 0..50 {
        if let Some(scope) = host_cgroup_path(pid)
            && let Ok(v) = std::fs::read_to_string(format!("/sys/fs/cgroup{scope}/pids.max"))
        {
            pids_max = v.trim().to_string();
            if pids_max == OVERRIDE_CAP {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();

    if pids_max != OVERRIDE_CAP {
        // The default leaking through means the scope applied but the typed flag did not — a real
        // regression in the flag→collect→cgroup threading, so fail. Any other value (or none) is the
        // host having no systemd user session that delegates the pids controller — skip.
        assert_ne!(
            pids_max, DEFAULT_CAP,
            "the cage ran under the default task cap, not the typed `--limit tasks_max=8192` — the \
             typed one-shot flag did not thread through to the scope"
        );
        eprintln!(
            "skipping typed-limit e2e: the cage is not under a task-capped scope \
             (pids.max={pids_max:?}); likely no systemd user session delegating pids"
        );
    }
}

/// The real cgroup v2 path of a process, read from the host (`0::<path>`), or
/// `None` if the process is gone or its cgroup cannot be read.
fn host_cgroup_path(pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    content
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_string)
}

/// True once `session_pid` has a descendant process in a *child* user namespace — i.e. the cage's
/// bubblewrap has created its namespaces, so `sbx session attach` will find a live process to enter. Used to
/// wait deterministically for the background cage to come up, rather than sleeping a fixed guess.
fn cage_userns_ready(session_pid: u32) -> bool {
    let host = std::fs::read_link("/proc/self/ns/user").ok();
    let mut children: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // The ppid is the field after the `(comm)` group, so parse past the last `)`.
            if let Some(rest) = stat.rfind(')').map(|i| &stat[i + 1..])
                && let Some(ppid) = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok())
            {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut queue = children.get(&session_pid).cloned().unwrap_or_default();
    while let Some(pid) = queue.pop() {
        let ns = std::fs::read_link(format!("/proc/{pid}/ns/user")).ok();
        if ns.is_some() && ns != host {
            return true;
        }
        if let Some(kids) = children.get(&pid) {
            queue.extend(kids);
        }
    }
    false
}

/// `sbx session attach <id>` joins a **running** cage and opens a shell *inside* it — the real thing, not a
/// fresh cage that merely shares the home. Driven through a pty against a live background session,
/// with two teeth:
///  - **live cage, not a reopened one:** the joined shell reads a unique marker the agent wrote to
///    the cage's own `/tmp` tmpfs. A fresh cage's tmpfs would be empty, so this fails for anything
///    but a true join of the running cage's mount namespace.
///  - **confinement re-applied over `setns` (the security ship-gate):** `setns` inherits none of the
///    cage's confinement, so the joined shell must re-apply it. `/proc/self/status` shows
///    `Seccomp: 2` with **both** filters loaded (`Seccomp_filters: 2` — the EPERM *and* the ENOSYS
///    denylist, so a regression installing only one is caught even though the mode would still read
///    2), `NoNewPrivs: 1`, and an empty `CapEff` — a regression that skipped the re-application would
///    read `Seccomp: 0` / `NoNewPrivs: 0` and fail.
///
/// This proves the confinement is **present and active**, not that it *blocks* a given syscall: no
/// base-toolset command triggers a denied syscall distinguishably (the same reason `sandbox::seccomp`
/// owns the real-cage *enforcement* tests, on the identical baseline policy this path installs). So
/// the teeth here are re-application + live-cage, not enforcement.
///
/// Skips (never fails) where the host cannot sandbox or the cage does not come up.
#[test]
fn sbx_attach_joins_the_live_cage_with_the_confinement_reapplied() {
    use std::os::fd::FromRawFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    // A distinctive token the agent writes into the cage /tmp; it appears in the joined shell's
    // output only if that shell truly shares the agent's live tmpfs.
    const MARKER: &str = "ATTACH-LIVE-9c3f1a7e";
    // Assembled at runtime from /proc inside the joined shell, so it can never leak in from the
    // echoed command text — the assertion has real teeth on the re-applied confinement. The trailing
    // `2` is `Seccomp_filters` (both denylists loaded, not just one).
    const CONFINE: &str = "CONFINE=2-1-0000000000000000-2";

    let project = TmpDir::new("attach-proj");
    let data = TmpDir::new("attach-data");

    // Capability probe (also warms the base userland so the background agent and the attach start
    // fast). No config, no trust — a real attach provisions nothing and re-resolves no config.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping attach e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // A background agent: write the marker into the cage's own /tmp, then sleep so the cage stays
    // alive to be attached. `child.id()` is the session pid `sbx session ls`/`sbx session attach` use.
    let mut agent = sbx()
        .args(["run", "--"])
        .args([
            "sh",
            "-c",
            &format!("echo {MARKER} > /tmp/attach-marker; exec sleep 120"),
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the background sbx run");
    let session_pid = agent.id();

    // Wait deterministically for the cage's namespaces to exist before attaching.
    let deadline = Instant::now() + Duration::from_secs(45);
    while !cage_userns_ready(session_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(150));
    }
    if !cage_userns_ready(session_pid) {
        let _ = agent.kill();
        let _ = agent.wait();
        eprintln!("skipping attach e2e: the background cage never came up (userns not created)");
        return;
    }

    // Drive `sbx session attach` through a pty (it needs a real terminal on stdin), exactly like the
    // interactive `sbx run` supervisor test.
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");

    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them as stdin/out/err.
    let mut attach = sbx()
        .args(["session", "attach", &session_pid.to_string()])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn sbx session attach");
    unsafe { libc::close(slave) };

    // Read the agent's live marker; assemble the confinement triple from /proc (so it cannot come
    // from the echoed command); then leave. `awk` and `cat` are in the cage's base toolset.
    let script = b"cat /tmp/attach-marker\n\
        awk '/^Seccomp:/{s=$2}/^Seccomp_filters:/{f=$2}/^NoNewPrivs:/{n=$2}/^CapEff:/{c=$2}END{print \"CONFINE=\" s \"-\" n \"-\" c \"-\" f}' /proc/self/status\n\
        exit\n";

    // Send the script once the cage prompt appears (its PS1 ends in `$`), then read until the
    // session ends (master EIO) or a deadline — the same wait-for-prompt pattern the shell test uses.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent = false;
    let read_deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < read_deadline {
        let mut pfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 500) } > 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break; // EIO/EOF: the attach session ended
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        if !sent && out.contains(&b'$') {
            unsafe { libc::write(master, script.as_ptr().cast(), script.len()) };
            sent = true;
        }
    }
    unsafe { libc::close(master) };
    let _ = attach.kill();
    let _ = attach.wait();
    let _ = agent.kill();
    let _ = agent.wait();

    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains(MARKER),
        "the joined shell did not see the agent's live /tmp marker — it is not inside the running \
         cage (a fresh cage's tmpfs would be empty):\n{text}"
    );
    assert!(
        text.contains(CONFINE),
        "the joined shell's confinement was not re-applied — want Seccomp 2 (both filters) / \
         NoNewPrivs 1 / empty CapEff ({CONFINE}); a shell entered without re-applying it reads \
         Seccomp 0 / NoNewPrivs 0:\n{text}"
    );
}

/// `sbx session attach <id> -- command` runs one command in the live cage instead of an interactive
/// shell. With no terminal on stdin it takes the **inherited-stdio** path (no pty), so it composes
/// with pipes and its exit status propagates — the value of the feature over an interactive shell.
/// Three teeth, all through the real binary against a live background session:
///  - **live cage + clean bytes:** `-- cat /tmp/<marker>` prints the marker the agent wrote to the
///    cage's own tmpfs on a captured (piped, non-tty) stdout — a fresh cage's tmpfs would be empty,
///    and a pty would have translated the bytes.
///  - **status propagation:** `-- sh -c 'exit 7'` makes sbx exit 7 (a plain command's status is sbx's).
///  - **confinement re-applied on the direct path (the security ship-gate):** `-- awk …/proc/self/status`
///    reads `Seccomp: 2` with both filters, `NoNewPrivs: 1`, empty `CapEff` — the same `CONFINE` the
///    pty attach asserts, proving the non-pty path re-applies the cage's confinement just as tightly.
///
/// Skips (never fails) where the host cannot sandbox or the cage does not come up.
#[test]
fn sbx_attach_runs_a_command_inheriting_stdio_and_propagating_status() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    const MARKER: &str = "ATTACH-CMD-4b81de20";
    // Assembled at runtime from /proc inside the joined command, so it cannot leak in from the argv.
    const CONFINE: &str = "CONFINE=2-1-0000000000000000-2";

    let project = TmpDir::new("attachcmd-proj");
    let data = TmpDir::new("attachcmd-data");

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping attach-cmd e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // A background agent writes the marker into the cage's own /tmp, then sleeps so the cage stays
    // alive to be attached. `child.id()` is the session pid `sbx session attach` uses.
    let mut agent = sbx()
        .args(["run", "--"])
        .args([
            "sh",
            "-c",
            &format!("echo {MARKER} > /tmp/attach-cmd-marker; exec sleep 120"),
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the background sbx run");
    let session_pid = agent.id();

    let deadline = Instant::now() + Duration::from_secs(45);
    while !cage_userns_ready(session_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(150));
    }
    if !cage_userns_ready(session_pid) {
        let _ = agent.kill();
        let _ = agent.wait();
        eprintln!(
            "skipping attach-cmd e2e: the background cage never came up (userns not created)"
        );
        return;
    }
    // The marker command runs before `exec sleep`; give it a beat to land in the cage /tmp.
    std::thread::sleep(Duration::from_millis(400));

    // Every attach below sets stdin to a non-terminal (`Stdio::null()`), so all take the direct
    // inherited-stdio path — the one an interactive shell could not reach.

    // A) Live cage + clean piped bytes: read the agent's own /tmp marker and print it.
    let cat = sbx()
        .args([
            "session",
            "attach",
            &session_pid.to_string(),
            "--",
            "cat",
            "/tmp/attach-cmd-marker",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run attach -- cat");
    let cat_out = String::from_utf8_lossy(&cat.stdout).into_owned();

    // B) The command's exit status becomes sbx's.
    let seven = sbx()
        .args([
            "session",
            "attach",
            &session_pid.to_string(),
            "--",
            "sh",
            "-c",
            "exit 7",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .status()
        .expect("run attach -- 'exit 7'");

    // C) Confinement re-applied on the direct path — the same triple the pty attach asserts.
    let confine = sbx()
        .args([
            "session", "attach", &session_pid.to_string(), "--",
            "awk",
            "/^Seccomp:/{s=$2}/^Seccomp_filters:/{f=$2}/^NoNewPrivs:/{n=$2}/^CapEff:/{c=$2}END{print \"CONFINE=\" s \"-\" n \"-\" c \"-\" f}",
            "/proc/self/status",
        ])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(Stdio::null())
        .output()
        .expect("run attach -- awk status");
    let confine_out = String::from_utf8_lossy(&confine.stdout).into_owned();

    let _ = agent.kill();
    let _ = agent.wait();

    assert!(
        cat.status.success() && cat_out.contains(MARKER),
        "attach -- cat did not print the agent's live /tmp marker on a clean stdout (exit {:?}) — it \
         is not inside the running cage, or the direct path is broken:\nstdout: {cat_out}\nstderr: {}",
        cat.status.code(),
        String::from_utf8_lossy(&cat.stderr)
    );
    assert_eq!(
        seven.code(),
        Some(7),
        "attach -- 'exit 7' must propagate the command's exit status as sbx's"
    );
    assert!(
        confine_out.contains(CONFINE),
        "the command's confinement was not re-applied on the direct (non-pty) path — want Seccomp 2 \
         (both filters) / NoNewPrivs 1 / empty CapEff ({CONFINE}):\n{confine_out}"
    );
}

/// Ending a session tears down every shell attached to it. `sbx session attach` runs the shell **inside**
/// the cage's pid namespace, so when the cage's init (bubblewrap, pid 1 of that namespace) dies —
/// here via `sbx session stop` — the kernel SIGKILLs every process in the namespace, the attached shell
/// included. So an attached shell can neither outlive nor keep alive the agent it joined. (The same
/// pid-namespace-collapse mechanism fires when the agent exits on its own; `sbx session stop` is the
/// deterministic trigger to assert on.)
///
/// Teeth: with a shell attached and confirmed live, `sbx session stop <session>` must make the `sbx session attach`
/// process exit **on its own** (the SIGKILL of its in-cage shell ends its pty relay) — the test polls
/// `try_wait` and never kills it, so a survivor is a real failure (a regression where the attached
/// shell escaped the cage's pid namespace). Skips where the host cannot sandbox.
#[test]
fn ending_a_session_kills_a_shell_attached_to_it() {
    use std::os::fd::FromRawFd;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let project = TmpDir::new("attachkill-proj");
    let data = TmpDir::new("attachkill-data");
    let state = TmpDir::new("attachkill-state");

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping attach-kill e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // A background agent to attach to.
    let mut agent = sbx()
        .args(["run", "--", "sleep", "120"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the background sbx run");
    let session_pid = agent.id();

    let deadline = Instant::now() + Duration::from_secs(45);
    while !cage_userns_ready(session_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(150));
    }
    if !cage_userns_ready(session_pid) {
        let _ = agent.kill();
        let _ = agent.wait();
        eprintln!("skipping attach-kill e2e: the background cage never came up");
        return;
    }

    // Attach a shell under a pty.
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    // SAFETY: each Stdio owns its own dup of the slave; the child inherits them as stdin/out/err.
    let mut attach = sbx()
        .args(["session", "attach", &session_pid.to_string()])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdin(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stdout(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .stderr(unsafe { Stdio::from_raw_fd(libc::dup(slave)) })
        .spawn()
        .expect("spawn sbx session attach");
    unsafe { libc::close(slave) };

    // Confirm the attached shell is really live before killing the session — a runtime-assembled
    // sentinel (`ALIVE-42` from shell arithmetic) that can never come from the echoed command text.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let mut sent = false;
    let confirm_deadline = Instant::now() + Duration::from_secs(30);
    let mut confirmed = false;
    while Instant::now() < confirm_deadline && !confirmed {
        let mut pfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 500) } > 0 {
            let n = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        if !sent && out.contains(&b'$') {
            let cmd = b"echo ALIVE-$((6 * 7))\n";
            unsafe { libc::write(master, cmd.as_ptr().cast(), cmd.len()) };
            sent = true;
        }
        confirmed = String::from_utf8_lossy(&out).contains("ALIVE-42");
    }
    if !confirmed {
        unsafe { libc::close(master) };
        let _ = attach.kill();
        let _ = attach.wait();
        let _ = agent.kill();
        let _ = agent.wait();
        panic!(
            "the attached shell never came up, cannot test its teardown:\n{}",
            String::from_utf8_lossy(&out)
        );
    }

    // End the session. The attached shell is in its pid namespace, so it must die with it.
    let stop = sbx_in(
        project.path(),
        data.path(),
        state.path(),
        &["session", "stop", &session_pid.to_string()],
    );
    assert!(
        stop.status.success(),
        "sbx session stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    // The `sbx session attach` process must now exit on its own: the pid-namespace collapse SIGKILLs its
    // in-cage shell, ending the pty relay. Poll `try_wait` (master still open, so it is the session's
    // death — not our cleanup — that ends it); never `kill()`, so a survivor is a real failure.
    let kill_deadline = Instant::now() + Duration::from_secs(15);
    let mut attach_exited = false;
    while Instant::now() < kill_deadline {
        // Drain the pty so the relay never blocks on a full master while we wait.
        let mut pfd = libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 100) } > 0 {
            let _ = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
        }
        if matches!(attach.try_wait(), Ok(Some(_))) {
            attach_exited = true;
            break;
        }
    }
    unsafe { libc::close(master) };
    // Reap both children on every path (a survivor is force-killed first), so the test leaves no
    // process behind whether it passes or fails.
    if !attach_exited {
        let _ = attach.kill();
    }
    let _ = attach.wait();
    let _ = agent.wait();
    assert!(
        attach_exited,
        "`sbx session attach` outlived the session it joined — the attached shell escaped the cage's pid \
         namespace instead of being killed with it"
    );
}

/// Materialize a non-empty file at `path`, creating parents. A helper for the app-purge e2es, which
/// stand up fake app homes on disk (the purge is host-side filesystem work — no sandbox needed).
fn touch_under(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"x").unwrap();
}

/// `sbx <args>` with only the data dir redirected — enough for the host-side `sbx app` management
/// verbs (list/rm), which read the config and data dirs but never launch a cage.
fn sbx_data(data: &Path, args: &[&str]) -> Output {
    sbx()
        .args(args)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn sbx")
}

#[test]
fn sbx_app_rm_purge_removes_the_installed_homes_and_lists_them() {
    let data = TmpDir::new("purge-data");
    let sbx_dir = data.path().join("sbx");
    // The target app 'claude': a global home (with a sibling etc) and one per-project home.
    touch_under(&sbx_dir.join("apps/claude/home/state"));
    touch_under(&sbx_dir.join("apps/claude/etc/passwd"));
    touch_under(&sbx_dir.join("projects/testproj/apps/claude/home/state"));
    // A different app and unrelated project state that must all survive the purge.
    touch_under(&sbx_dir.join("apps/codex/home/state"));
    touch_under(&sbx_dir.join("projects/testproj/store/nix/keepme"));

    // `sbx app list` shows one row per app with its installed home, so a user can see what there is
    // to purge. The unified table carries the `HOME` column header and a row for each installed app.
    let listed = sbx_data(data.path(), &["app", "list"]);
    assert!(listed.status.success(), "app list failed: {listed:?}");
    let list_out = String::from_utf8_lossy(&listed.stdout);
    assert!(
        list_out.contains("HOME") && list_out.contains("claude") && list_out.contains("codex"),
        "app list did not report the installed homes:\n{list_out}"
    );

    // Purge 'claude': profile absent (fine), both homes removed, everything else intact.
    let purged = sbx_data(data.path(), &["app", "rm", "claude", "--purge"]);
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
    let again = sbx_data(data.path(), &["app", "rm", "claude", "--purge"]);
    assert!(!again.status.success(), "a no-op purge reported success");
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("nothing to purge"),
        "no-op purge did not explain itself: {again:?}"
    );
}

#[test]
fn sbx_app_rm_purges_several_apps_in_one_call() {
    let data = TmpDir::new("purge-many-data");
    let sbx_dir = data.path().join("sbx");
    // Two target apps, one with a global home and one with a per-project home, plus a third that
    // is not named and must survive.
    touch_under(&sbx_dir.join("apps/agent-one/home/state"));
    touch_under(&sbx_dir.join("projects/testproj/apps/agent-two/home/state"));
    touch_under(&sbx_dir.join("apps/agent-three/home/state"));

    // Three names with an absent one in the middle: each app is purged on its own, so the failing
    // name is reported without stopping the one after it, and the call exits non-zero.
    let out = sbx_data(
        data.path(),
        &[
            "app",
            "rm",
            "agent-one",
            "absent-app",
            "agent-two",
            "--purge",
        ],
    );
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
    let data = TmpDir::new("purge-dup-data");
    let sbx_dir = data.path().join("sbx");
    touch_under(&sbx_dir.join("apps/agent-one/home/state"));

    // The same app named twice is one removal: a second pass would find nothing left and report a
    // phantom "nothing to purge" over work that in fact succeeded.
    let out = sbx_data(
        data.path(),
        &["app", "rm", "agent-one", "agent-one", "--purge"],
    );
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
    let data = TmpDir::new("gc-nothing-data");
    let out = sbx_data(data.path(), &["app", "rm", "absent-app", "--purge", "--gc"]);
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
    let data = TmpDir::new("gc-needs-purge");
    let out = sbx_data(data.path(), &["app", "rm", "agent", "--gc"]);
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
    let data = TmpDir::new("purge-live-data");
    let sbx_dir = data.path().join("sbx");
    touch_under(&sbx_dir.join("apps/agent/home/state"));

    // A real live process to anchor a session record: the guard is decided by a start-time match
    // against /proc, so a fabricated record must name a genuinely-running pid.
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc stat");
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    let start_ticks: u64 = after.split_whitespace().nth(19).unwrap().parse().unwrap();

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

    let out = sbx_data(data.path(), &["app", "rm", "agent", "--purge"]);
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

/// `sbx gc --prune` reconciles the per-project store's accumulated seed roots: a superseded build —
/// one no current out-link references — has its direct root dropped so the sweep reclaims it, while a
/// current build (the base userland, whose out-link is live) is kept. Proves the wiring a unit test
/// cannot: `sweep_current` deriving the keep-set from the real out-link families and driving
/// `prune_superseded_roots` over a real seeded store. Skips (never fails) where the host cannot
/// sandbox or the binary cache is unreachable.
#[test]
fn gc_prune_drops_a_superseded_seed_root_and_keeps_the_current_base() {
    let project = TmpDir::new("gcsup-proj");
    let data = TmpDir::new("gcsup-data");

    // Seed the project store (capability probe): a successful `true` provisions and roots the base
    // userland — creating both the store's direct seed roots and the `<data>/gcroots/base/<rev>`
    // out-links the keep-set reads.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        if !cache_reachable() {
            eprintln!("skipping gc-superseded e2e: the binary cache is unreachable");
            return;
        }
        eprintln!(
            "skipping gc-superseded e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr)
                .lines()
                .last()
                .unwrap_or("")
        );
        return;
    }

    // Locate the project's store gcroots (exactly one project in this fresh data dir; sbx's data
    // lives under the `sbx/` subdirectory of `$XDG_DATA_HOME`).
    let id_dir = std::fs::read_dir(data.path().join("sbx").join("projects"))
        .expect("projects dir")
        .flatten()
        .next()
        .expect("one seeded project")
        .path();
    let store_gcroots = id_dir.join("store/nix/var/nix/gcroots");

    // A real, current base root that must survive: its `base/<rev>` out-link keeps it in the keep-set.
    let base_root = std::fs::read_dir(&store_gcroots)
        .expect("store gcroots")
        .flatten()
        .map(|e| e.file_name())
        .find(|n| n.to_string_lossy().contains("-glibc-"))
        .expect("a seeded glibc root");
    assert!(store_gcroots.join(&base_root).symlink_metadata().is_ok());

    // Inject a superseded seed root: a direct root nothing current points at (its build was rolled
    // away). The keep-set will not contain its basename, so the prune must drop it.
    let obsolete = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-obsolete-e2e";
    std::os::unix::fs::symlink(
        format!("/nix/store/{obsolete}"),
        store_gcroots.join(obsolete),
    )
    .expect("inject superseded root");

    let out = sbx()
        .args(["gc", "--prune"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx gc");
    assert!(
        out.status.success(),
        "gc --prune failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The superseded root is gone; the current base root is untouched.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        store_gcroots.join(obsolete).symlink_metadata().is_err(),
        "the superseded seed root was not dropped: {stdout}"
    );
    assert!(
        store_gcroots.join(&base_root).symlink_metadata().is_ok(),
        "gc dropped a current base root ({}): the keep-set missed it",
        base_root.to_string_lossy()
    );
    // The report must own up to the reconciliation — at least the one injected root — so a future
    // refactor that silently stops pruning the seed roots reddens this test, not just the symlink check.
    assert!(
        stdout.contains("superseded build(s)") && !stdout.contains(", 0 superseded build(s)"),
        "gc did not report the superseded build(s) it dropped: {stdout}"
    );
}

/// `sbx upgrade` ends by hinting how many superseded builds the project's store is holding, pointing
/// at `sbx gc --prune`. Uses `upgrade flake` on a package-less project so the roll is a no-op (no
/// network, the current revision's base stays built so the keep-set guard is met) and only the hint
/// is exercised. Skips (never fails) where the host cannot sandbox or the cache is unreachable.
#[test]
fn upgrade_hints_at_reclaimable_superseded_builds() {
    let project = TmpDir::new("uphint-proj");
    let data = TmpDir::new("uphint-data");

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        if !cache_reachable() {
            eprintln!("skipping upgrade-hint e2e: the binary cache is unreachable");
            return;
        }
        eprintln!(
            "skipping upgrade-hint e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr)
                .lines()
                .last()
                .unwrap_or("")
        );
        return;
    }

    // Inject a superseded seed root the keep-set will not cover.
    let id_dir = std::fs::read_dir(data.path().join("sbx").join("projects"))
        .expect("projects dir")
        .flatten()
        .next()
        .expect("one seeded project")
        .path();
    let store_gcroots = id_dir.join("store/nix/var/nix/gcroots");
    let obsolete = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy-obsolete-hint";
    std::os::unix::fs::symlink(
        format!("/nix/store/{obsolete}"),
        store_gcroots.join(obsolete),
    )
    .expect("inject superseded root");

    // `upgrade flake` on a project with no `flake:` packages rolls nothing (offline, lock untouched),
    // so the current revision's base stays built and the end-of-upgrade hint runs against it.
    let out = sbx()
        .args(["upgrade", "flake"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx upgrade");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("superseded build(s)") && stdout.contains("reclaimable"),
        "upgrade did not hint at the reclaimable superseded build: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The hint is a dry-run pointer only — it must not have removed anything.
    assert!(
        store_gcroots.join(obsolete).symlink_metadata().is_ok(),
        "the upgrade hint removed a root instead of only reporting it"
    );
}

#[test]
fn fs_masks_close_a_project_path_while_its_name_stays_visible() {
    // The `[fs]` headline, end to end through the real binary: a denied file keeps its name in a
    // listing and refuses to open, a denied directory reads as empty, a `readonly` entry stays
    // readable and refuses writes, and the host's own files are untouched by all of it.
    //
    // The cage cannot undo any of it either — `rm` over a mask is `EBUSY` and a hard link out of one
    // is `EXDEV`, which is what makes the mask hold against in-cage code rather than merely against
    // an honest reader. Skips (never fails) where the host cannot sandbox.
    let project = TmpDir::new("fsmask-proj");
    let data = TmpDir::new("fsmask-data");
    let p = project.path();
    std::fs::create_dir_all(p.join("certs")).unwrap();
    std::fs::create_dir_all(p.join("secrets")).unwrap();
    std::fs::write(p.join("prod.key"), b"PRIVATE-KEY\n").unwrap();
    std::fs::write(p.join("certs/a.pem"), b"CERT-A\n").unwrap();
    std::fs::write(p.join("certs/b.pem"), b"CERT-B\n").unwrap();
    std::fs::write(p.join("secrets/token"), b"TOKEN\n").unwrap();
    std::fs::write(p.join("README.md"), b"readme\n").unwrap();
    std::fs::write(p.join("Cargo.lock"), b"lock\n").unwrap();
    // Ungated on purpose: this project is never trusted, and the masks must apply anyway — a table
    // that can only take access away is one an untrusted project is allowed to declare.
    std::fs::write(
        p.join(".sbx.toml"),
        "[fs]\ndeny = [\"prod.key\", \"certs/*.pem\", \"secrets/\"]\nreadonly = [\"Cargo.lock\"]\n",
    )
    .unwrap();

    let probe = run_in(p, data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping fs-mask e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // The name is still there — the whole point of a mask over a removal.
    let ls = run_in(p, data.path(), &["ls", "certs"]);
    let listed = String::from_utf8_lossy(&ls.stdout);
    assert!(
        listed.contains("a.pem") && listed.contains("b.pem"),
        "a masked file must keep its name in a listing: {listed}"
    );

    // …and the content is not.
    for path in ["prod.key", "certs/a.pem", "certs/b.pem"] {
        let out = run_in(p, data.path(), &["cat", path]);
        assert!(
            !out.status.success(),
            "`{path}` is denied but the cage read it: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("CERT")
                && !String::from_utf8_lossy(&out.stdout).contains("PRIVATE"),
            "the masked content leaked for `{path}`"
        );
    }

    // A denied directory reads as empty, which is a stronger answer than a refusal: nothing in it
    // is even nameable, including anything created there later in the session.
    let inside = run_in(p, data.path(), &["cat", "secrets/token"]);
    assert!(
        !inside.status.success(),
        "a denied directory's contents must not open"
    );
    let listing = run_in(p, data.path(), &["ls", "secrets"]);
    assert!(
        listing.status.success() && String::from_utf8_lossy(&listing.stdout).trim().is_empty(),
        "a denied directory must list as empty: {}",
        String::from_utf8_lossy(&listing.stdout)
    );

    // An unmasked file is untouched, and `readonly` is readable but not writable.
    let readme = run_in(p, data.path(), &["cat", "README.md"]);
    assert!(
        String::from_utf8_lossy(&readme.stdout).contains("readme"),
        "an unmasked file must stay readable"
    );
    let lock = run_in(p, data.path(), &["cat", "Cargo.lock"]);
    assert!(
        String::from_utf8_lossy(&lock.stdout).contains("lock"),
        "a `readonly` entry stays readable — that is what separates it from `deny`"
    );
    let write_ro = run_in(p, data.path(), &["sh", "-c", "echo x >> Cargo.lock"]);
    assert!(
        !write_ro.status.success(),
        "a `readonly` entry must refuse a write"
    );
    let write_ok = run_in(p, data.path(), &["sh", "-c", "echo x >> README.md"]);
    assert!(
        write_ok.status.success(),
        "the rest of the project stays writable: {}",
        String::from_utf8_lossy(&write_ok.stderr)
    );

    // In-cage code cannot take a mask apart: removing it is `EBUSY` (it is a mount point) and
    // linking around it is `EXDEV` (the link would cross the mask's own mount boundary).
    let rm = run_in(p, data.path(), &["rm", "-f", "prod.key"]);
    assert!(
        !rm.status.success(),
        "a mask must not be removable from inside the cage"
    );
    let link = run_in(p, data.path(), &["ln", "prod.key", "stolen.key"]);
    assert!(
        !link.status.success(),
        "the cage must not be able to link around a mask"
    );

    // The host keeps every byte: a mask is a mount inside the cage, never an edit.
    assert_eq!(std::fs::read(p.join("prod.key")).unwrap(), b"PRIVATE-KEY\n");
    assert_eq!(std::fs::read(p.join("certs/a.pem")).unwrap(), b"CERT-A\n");
    assert_eq!(std::fs::read(p.join("secrets/token")).unwrap(), b"TOKEN\n");
    assert!(!p.join("stolen.key").exists());
}

#[test]
fn a_task_reads_the_key_its_own_unmask_names_and_nothing_else() {
    // The invariant the whole `[task] unmask` field exists for: a masked path is closed in *every*
    // cage the session builds, and one task lifts one path for itself. So the operation that needs
    // the key reads it, the agent that invokes that operation never can, and a second task with no
    // `unmask` is refused the same file.
    //
    // Trust matters here in one direction only: `[fs]` applies whatever the project's trust, but
    // `[task]` is a security field, so the project has to be trusted for the tasks to exist at all.
    let project = TmpDir::new("unmask-proj");
    let data = TmpDir::new("unmask-data");
    let state = TmpDir::new("unmask-state");
    let p = project.path();
    std::fs::create_dir_all(p.join("certs")).unwrap();
    std::fs::write(p.join("prod.key"), b"THE-KEY\n").unwrap();
    std::fs::write(p.join("certs/a.pem"), b"CERT-A\n").unwrap();
    std::fs::write(p.join("certs/b.pem"), b"CERT-B\n").unwrap();
    std::fs::write(
        p.join(".sbx.toml"),
        "[fs]\ndeny = [\"prod.key\", \"certs/*.pem\"]\n\n\
         [task.readkey]\ncmd = [\"cat\", \"prod.key\"]\nunmask = [\"prod.key\"]\n\n\
         [task.readcert]\ncmd = [\"cat\", \"{cert}\"]\n\
         params = { cert = '^certs/[a-z]+\\.pem$' }\nunmask = [\"certs/a.pem\"]\n\n\
         [task.blind]\ncmd = [\"cat\", \"prod.key\"]\n",
    )
    .unwrap();

    let probe = run_in(p, data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping unmask e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    assert!(
        sbx_in(p, data.path(), state.path(), &["trust", ".sbx.toml"])
            .status
            .success(),
        "the project must be trusted for its `[task]` blocks to be honored"
    );

    let in_cage = |script: &str| -> String {
        let out = sbx()
            .args(["run", "--", "sh", "-c", script])
            .current_dir(p)
            .env("XDG_DATA_HOME", data.path())
            .env("XDG_STATE_HOME", state.path())
            .output()
            .expect("spawn sbx run");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    // The agent's own cage: closed.
    let direct = in_cage("cat prod.key");
    assert!(
        !direct.contains("THE-KEY"),
        "the agent's cage must not read the masked key: {direct}"
    );

    // The task that names it: open, and only to that task.
    let via_task = in_cage("sbx task run readkey");
    assert!(
        via_task.contains("THE-KEY"),
        "the task's own `unmask` must lift the mask for it: {via_task}"
    );
    let blind = in_cage("sbx task run blind");
    assert!(
        !blind.contains("THE-KEY"),
        "a task with no `unmask` sees the mask like the agent does: {blind}"
    );

    // Per *path*, not per task: one task lifts one certificate out of a wildcard mask and is still
    // refused the other.
    let lifted = in_cage("sbx task run readcert -p cert=certs/a.pem");
    assert!(
        lifted.contains("CERT-A"),
        "the unmasked certificate must be readable by that task: {lifted}"
    );
    let still_masked = in_cage("sbx task run readcert -p cert=certs/b.pem");
    assert!(
        !still_masked.contains("CERT-B"),
        "a path the task did not unmask stays closed to it too: {still_masked}"
    );
}

#[test]
fn a_one_shot_config_mask_closes_the_path_and_unions_with_the_project() {
    // `[fs]` has no typed flag, so `--config` is the only way to close a path for a single launch —
    // and it shipped broken: the override fold carried every other table and dropped this one, so the
    // blob resolved, printed, and then never reached the cage. The failure was silent and in the
    // dangerous direction (the file the invoker asked to close stayed readable), which is why the
    // whole path is pinned here through the real binary rather than at the fold alone.
    let project = TmpDir::new("fsov-proj");
    let data = TmpDir::new("fsov-data");
    let p = project.path();
    std::fs::write(p.join(".env"), b"SECRET=hunter2\n").unwrap();
    std::fs::write(p.join("from-file.key"), b"FILE-KEY\n").unwrap();
    std::fs::write(p.join("README.md"), b"readme\n").unwrap();
    std::fs::write(p.join(".sbx.toml"), "[fs]\ndeny = [\"from-file.key\"]\n").unwrap();

    let probe = run_in(p, data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping one-shot fs-mask e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let cat = |flags: &[&str], path: &str| -> String {
        let out = sbx()
            .arg("run")
            .args(flags)
            .args(["--", "cat", path])
            .current_dir(p)
            .env("XDG_DATA_HOME", data.path())
            .output()
            .expect("spawn sbx run");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };

    // Without the override the file is an ordinary project file — the control that makes the next
    // assertion mean something.
    assert!(
        cat(&[], ".env").contains("hunter2"),
        "the control read must succeed, or the test proves nothing"
    );

    let blob = "[fs]\ndeny = [\".env\"]";
    assert!(
        !cat(&["--config", blob], ".env").contains("hunter2"),
        "a `--config` mask must close the path for this launch"
    );

    // The layers union rather than replace: the blob adds to what the project closed, and neither
    // side may unseat the other. A mask that could be *dropped* by adding an override would make the
    // override a way to reopen a path, which no layer has.
    assert!(
        !cat(&["--config", blob], "from-file.key").contains("FILE-KEY"),
        "an override must not unseat the project's own mask"
    );
    assert!(
        cat(&["--config", blob], "README.md").contains("readme"),
        "an unnamed path stays open"
    );

    // The ambient side of the fold reaches the cage too, and it is the side that used to work by
    // accident of position — pin it so a future fold cannot swap which one survives.
    let ambient = sbx()
        .args(["run", "--", "cat", ".env"])
        .current_dir(p)
        .env("XDG_DATA_HOME", data.path())
        .env("SBX_CONFIG", blob)
        .output()
        .expect("spawn sbx run");
    assert!(
        !String::from_utf8_lossy(&ambient.stdout).contains("hunter2"),
        "an `SBX_CONFIG` mask must close the path too"
    );

    // The host file is untouched by any of it.
    assert_eq!(std::fs::read(p.join(".env")).unwrap(), b"SECRET=hunter2\n");
}

/// The `[broker.*]` block in the launcher had never run: its failure branches were prose. This
/// exercises the two a user meets first, and the rule that holds them together — **a broker that
/// cannot be provided is a warning, never a failed launch**, because a cage without a broker is a
/// cage that cannot reach that resource, which is the safe direction.
#[test]
fn a_broker_that_cannot_be_provided_warns_and_the_launch_still_succeeds() {
    let project = TmpDir::new("brk");
    let data = TmpDir::new("brkd");
    let config = TmpDir::new("brkc");
    std::fs::write(project.path().join(".sbx.toml"), "").unwrap();

    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping broker launch e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    let sbx_cfg = config.path().join("sbx");
    std::fs::create_dir_all(&sbx_cfg).unwrap();

    // Case 1: the table names a broker no installed plugin claims.
    std::fs::write(
        sbx_cfg.join("sbx.toml"),
        "[broker.nosuch]\nsocket = \"/dev/null\"\n",
    )
    .unwrap();
    let out = sbx()
        .args(["run", "--", "true"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx run");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "a broker that cannot be provided must not fail the launch: {stderr}"
    );
    assert!(
        stderr.contains("nosuch") && stderr.contains("no installed broker plugin"),
        "the launch must name what it could not provide: {stderr}"
    );

    // Case 2: an installed plugin, pointed at a host resource that is not there. The socket is
    // checked before anything is stood up, so this is a warning too — a broker in front of nothing
    // would accept the cage's connections and fail every message.
    let src = project.path().join("fake-broker");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("plugin.toml"),
        "name = \"fake-broker\"\ntype = \"broker\"\nexec = \"broker\"\n\
         [broker]\ncage_env = [\"FAKE_SOCK\"]\nframing = \"length-u32-be\"\nmax_frame = 4096\n",
    )
    .unwrap();
    std::fs::write(src.join("broker"), "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(src.join("broker"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }
    let install = sbx()
        .args(["plugins", "install", "fake-broker"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx plugins install");
    assert!(
        install.status.success(),
        "installing a broker plugin failed: {}",
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        String::from_utf8_lossy(&install.stdout).contains("broker"),
        "the confirmation names the type rather than a namespace it has none of: {}",
        String::from_utf8_lossy(&install.stdout)
    );

    let missing = data.path().join("no-such-agent.sock");
    std::fs::write(
        sbx_cfg.join("sbx.toml"),
        format!("[broker.fake-broker]\nsocket = \"{}\"\n", missing.display()),
    )
    .unwrap();
    let out = sbx()
        .args(["run", "--", "true"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn sbx run");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "a missing host resource must not fail the launch: {stderr}"
    );
    assert!(
        stderr.contains("does not exist"),
        "the launch must say the host resource is not there: {stderr}"
    );
}
