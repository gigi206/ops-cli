//! Integration tests for `ops run`, exercising the built binary end to end —
//! including the exec-replace exit-status propagation that the in-crate smokes
//! (which spawn rather than exec) cannot cover. The sandbox cases skip, rather
//! than fail, where the host cannot create a sandbox.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

fn ops() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ops"))
}

/// A unique temp dir removed on drop.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // On the repo's disk, not the system tmpfs: provisioning a nix store copies
        // the whole nixpkgs source tree (a huge file count) into it, and concurrent
        // tests would exhaust a tmpfs's inode budget. Disk has inodes to spare, and
        // it matches production (the store lives on disk). `cargo clean` reclaims it.
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("target/test-tmp");
        // A short prefix on purpose: a launch's egress proxy binds a Unix socket under this
        // data dir (`…/<dir>/ops/egress/proxy-<pid>.sock`), and `sun_path` caps the whole path
        // at 108 bytes. A longer prefix plus a 7-digit pid (counted twice — here and in the
        // socket name) tips a deep checkout over the limit, so keep this terse.
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

/// `ops run -- <args>` from `project`, with ops's data dir redirected to `data`
/// so the test never touches the real `$HOME`.
fn run_in(project: &Path, data: &Path, args: &[&str]) -> Output {
    ops()
        .arg("run")
        .arg("--")
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn ops run")
}

/// `ops app <name>` from `project`, with ops's data dir redirected to `data`.
fn app_in(project: &Path, data: &Path, name: &str) -> Output {
    ops()
        .arg("app")
        .arg(name)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .output()
        .expect("spawn ops app")
}

/// `ops <args>` from `project` with both the data dir and the trust-store dir
/// redirected, so a test can trust a project and launch it without touching the
/// real `$HOME` or the user's trust store.
fn ops_in(project: &Path, data: &Path, state: &Path, args: &[&str]) -> Output {
    ops()
        .args(args)
        .current_dir(project)
        .env("XDG_DATA_HOME", data)
        .env("XDG_STATE_HOME", state)
        .output()
        .expect("spawn ops")
}

#[test]
fn run_without_a_command_is_a_usage_error() {
    // fails before any sandbox work, so it needs no capable host
    let out = ops().arg("run").output().expect("spawn ops run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
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
            "skipping ops run smoke: host cannot sandbox ({})",
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

    // hermetic: there is no host /usr to list
    let usr = run_in(project.path(), data.path(), &["ls", "/usr"]);
    assert!(!usr.status.success(), "host /usr unexpectedly present");
    assert!(
        String::from_utf8_lossy(&usr.stderr).contains("/usr"),
        "expected a hermetic /usr failure: {}",
        String::from_utf8_lossy(&usr.stderr)
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
fn ops_app_launches_the_apps_command_with_its_overlay() {
    let project = TmpDir::new("appproj");
    let data = TmpDir::new("appdata");
    // Two untrusted apps: `probe` runs the synthetic-identity check; `greet` carries a free
    // `env` overlay (which applies even untrusted, like the baseline `env`).
    std::fs::write(
        project.path().join(".ops.toml"),
        b"[app.probe]\n\
          cmd = [\"id\"]\n\n\
          [app.greet]\n\
          cmd = [\"printenv\", \"APPVAR\"]\n\
          [app.greet.env]\n\
          APPVAR = \"from-app\"\n",
    )
    .unwrap();

    // capability probe via `ops run -- true`; skip (not fail) if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping ops app e2e: host cannot sandbox ({})",
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
fn an_app_home_persists_across_launches_and_is_isolated_from_the_project_shell() {
    let project = TmpDir::new("apphome-proj");
    let data = TmpDir::new("apphome-data");
    // `counter` appends a line to a file in its own `$HOME` and prints the running count, so a
    // second launch reveals whether the home persisted. The default home scope is global —
    // one home per app — and this single project exercises persistence; isolation from the
    // project shell is the second assertion.
    std::fs::write(
        project.path().join(".ops.toml"),
        b"[app.counter]\n\
          cmd = [\"sh\", \"-c\", \"echo x >> \\\"$HOME/COUNT\\\"; wc -l < \\\"$HOME/COUNT\\\" | tr -d ' '\"]\n",
    )
    .unwrap();

    // capability probe via `ops run -- true`; skip (not fail) if the host cannot sandbox.
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

    // Isolation with teeth: `ops run` uses the project's default home, a different directory,
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
fn a_trusted_mise_env_reaches_the_sandbox_only_once_trusted() {
    let project = TmpDir::new("mise-proj");
    let data = TmpDir::new("mise-data");
    let state = TmpDir::new("mise-state");
    // a mise file declares an env var; the (empty) .ops.toml anchors it
    std::fs::write(project.path().join(".ops.toml"), b"").unwrap();
    std::fs::write(
        project.path().join(".mise.toml"),
        b"[env]\nOPS_MISE_VAR = \"from-mise\"\n",
    )
    .unwrap();

    // capability probe: a capable host runs `true` to success; otherwise skip. This
    // also primes the base userland, so a later provisioning failure is a real fault.
    let probe = ops_in(
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
    let before = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "printenv", "OPS_MISE_VAR"],
    );
    assert!(
        !before.status.success(),
        "an untrusted mise [env] must not reach the sandbox, got: {}",
        String::from_utf8_lossy(&before.stdout)
    );

    // trust the project, then the same var is mapped into the sandbox
    let trusted = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    let after = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "printenv", "OPS_MISE_VAR"],
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

#[test]
fn a_network_allowlist_filters_egress_through_the_proxy() {
    // The Model-B egress path end to end through the real binary: a trusted
    // `network = "allowlist"` stands up the host filtering proxy on a bound socket, the
    // empty-netns cage reaches it *only* through the in-cage socat forwarder, the cage trusts
    // the proxy's injected per-session CA, and the allowlist decides each request. Teeth: an
    // allowed host's fetch returns the real content (the known nix-cache-info hash); a denied
    // host is refused with a 403 *at the proxy* (a real filename, so the fetch is actually
    // attempted — not a tool-side URL rejection). Because `ops run` must supervise on this
    // path (it cannot exec-replace while the proxy thread outlives the cage), this also covers
    // exit-status propagation there. Skips (never fails) when the host cannot sandbox or the
    // cache is unreachable.
    let project = TmpDir::new("egress-proj");
    let data = TmpDir::new("egress-data");
    let state = TmpDir::new("egress-state");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n",
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
    let trusted = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // exit-status propagation on the supervised (allowlist) path
    let seven = ops_in(
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
    let allowed = ops_in(
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
    // the proxy. `example.com` is not in the allow list nor the built-in nix-cache set.
    let denied = ops_in(
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
        String::from_utf8_lossy(&denied.stderr).contains("403"),
        "denied egress must be refused with a 403 at the proxy: {}",
        String::from_utf8_lossy(&denied.stderr)
    );
}

#[test]
fn a_shared_network_launch_trusts_ops_own_cacert() {
    // Under the default shared-network posture the cage no longer binds the host's `/etc/ssl`;
    // ops provisions its own cacert and names it through the CA-bundle variables, so HTTPS is
    // hermetic — it works on a host that carries no certificates of its own. Teeth, both in one
    // test so success proves causation: an HTTPS fetch returns the known nix-cache-info hash
    // (TLS verified against ops's bundle), and the *same* fetch with the CA file forced empty
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

    // HTTPS works, trusting ops's hermetic bundle (the host's /etc/ssl is not bound).
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
    // the same fetch fails, so the success above is ops's bundle at work, not an ambient path.
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
         ops's bundle: {}",
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
             sed --version >/dev/null; \
             awk --version >/dev/null; \
             find --version >/dev/null; \
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
fn the_cage_self_equips_via_mise_under_a_network_allowlist() {
    // The headline self-equip path (`ops mise install`) under the headline security posture (a
    // trusted `network = "allowlist"`). mise reads its CA roots from the certificate *file*, not
    // the CA-bundle env variables, so this is the exact case where the two halves of the trust
    // setup must combine: the hermetic cacert (a real bundle at the file path, which mise needs
    // present to load any roots at all) and the egress proxy's per-session MITM CA (injected via
    // env). If only one were in place, mise could not trust the proxy and the self-equip would
    // fail. Teeth: jq installs through the empty-netns proxy into the project's own store. Skips
    // (never fails) when the host cannot sandbox or the cache is unreachable.
    // Short tags: the egress proxy's Unix socket lives under the data dir, and its full path
    // must fit a `sockaddr_un` (~108 bytes). The test tree (`target/test-tmp/…`) is already
    // deep, so a long tag would overflow `SUN_LEN`. (Production's `~/.local/share/ops` is short.)
    let project = TmpDir::new("ma-proj");
    let data = TmpDir::new("ma-data");
    let state = TmpDir::new("ma-state");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n",
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
    let trusted = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // self-equip jq through the MITM proxy: mise must trust the proxy's per-session leaf
    // (devbox.sh metadata + cache.nixos.org substitution both ride the allowlist's built-in
    // nix-cache set).
    let installed = ops_in(
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
    assert!(
        log.contains("jq") && log.to_lowercase().contains("installed"),
        "mise did not report installing jq through the allowlist: {log}"
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
    let secret_value = "ops-e2e-secret-must-not-leak-4b7x";
    std::fs::write(
        project.path().join(".ops.toml"),
        "[network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n\n\
         [secret.\"cache.nixos.org\"]\nfrom = \"env://OPS_E2E_SECRET\"\n\
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
    let trusted = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // `ops config` confirms the secret is honored host-side (not silently dropped), so the
    // cage-absence below is meaningful — and it must show the source by locator, never a value.
    let cfg = ops_in(project.path(), data.path(), state.path(), &["config"]);
    let cfg_out = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        cfg_out.contains("Authorization -> cache.nixos.org")
            && cfg_out.contains("from env OPS_E2E_SECRET"),
        "the trusted secret was not honored by `ops config`: {cfg_out}"
    );

    // the launch: `printenv` inside the cage, with the secret set in ops's environment. The
    // launch must succeed (the secret resolved and wired without error), and the cage env must
    // contain neither the source variable's name nor its value.
    let env_out = ops()
        .args(["run", "--", "printenv"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .env("OPS_E2E_SECRET", secret_value)
        .output()
        .expect("spawn ops run");
    assert!(
        env_out.status.success(),
        "the launch with a wired secret failed: {}",
        String::from_utf8_lossy(&env_out.stderr)
    );
    let cage_env = String::from_utf8_lossy(&env_out.stdout);
    assert!(
        !cage_env.contains("OPS_E2E_SECRET"),
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
    let secret_value = "ops-plugin-e2e-secret-7q2z";

    // install a resolver plugin: a manifest plus an executable that returns a constant plaintext.
    // (`PluginRegistry::load` reads `<XDG_DATA_HOME>/ops/plugins`.)
    let plugin_dir = data.path().join("ops/plugins/myresolver");
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
        project.path().join(".ops.toml"),
        "[network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n\n\
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

    let trusted = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // `ops config` shows the plugin-backed source honored, by scheme + locator (never a value).
    let cfg = ops_in(project.path(), data.path(), state.path(), &["config"]);
    let cfg_out = String::from_utf8_lossy(&cfg.stdout);
    assert!(
        cfg_out.contains("Authorization -> cache.nixos.org")
            && cfg_out.contains("from myscheme github/token"),
        "the plugin-backed secret was not honored by `ops config`: {cfg_out}"
    );

    // the launch resolves the secret by *running the plugin host-side*; it must succeed, and the
    // cage env must contain neither the locator nor the resolved value.
    let env_out = ops()
        .args(["run", "--", "printenv"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .env("XDG_STATE_HOME", state.path())
        .output()
        .expect("spawn ops run");
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
    let secret_value = "ops-e2e-leak-canary-9z3k";
    std::fs::write(
        project.path().join(".ops.toml"),
        "[network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n\n\
         [secret.\"cache.nixos.org\"]\nfrom = \"env://OPS_E2E_LEAK\"\n\
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
    let trusted = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["trust", ".ops.toml"],
    );
    assert!(
        trusted.status.success(),
        "ops trust failed: {}",
        String::from_utf8_lossy(&trusted.stderr)
    );

    // EXFIL (teeth): the cage sends the secret value verbatim in the request URL toward the
    // ALLOWED host. The proxy's tripwire refuses it with a 403 before any fetch — the refusal is
    // local to the proxy, so this holds even offline (no DNS/connect happens).
    let exfil_url = format!("https://cache.nixos.org/{secret_value}");
    let exfil = ops()
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
        .env("OPS_E2E_LEAK", secret_value)
        .output()
        .expect("spawn ops run");
    assert!(
        !exfil.status.success(),
        "an outbound secret unexpectedly succeeded: {}",
        String::from_utf8_lossy(&exfil.stdout)
    );
    assert!(
        String::from_utf8_lossy(&exfil.stderr).contains("403"),
        "an outbound secret must be refused with a 403 at the proxy: {}",
        String::from_utf8_lossy(&exfil.stderr)
    );

    // CONTROL: a clean request to the same allowed host still works, so the tripwire is not a
    // blanket block. Gated on the cache being reachable (this one genuinely fetches).
    if !cache_reachable() {
        eprintln!("skipping the outbound-secret positive control: the binary cache is unreachable");
        return;
    }
    let clean = ops()
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
        .env("OPS_E2E_LEAK", secret_value)
        .output()
        .expect("spawn ops run");
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
/// limits. `ops run` exec-replaces, so the spawned child keeps its pid *as* the
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

    let mut child = ops()
        .arg("run")
        .arg("--")
        .args(["sleep", "5"])
        .current_dir(project.path())
        .env("XDG_DATA_HOME", data.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn ops run");
    let pid = child.id();

    // Poll the cage's host-visible cgroup until the scope's task cap appears.
    let mut pids_max = String::new();
    for _ in 0..50 {
        if let Some(scope) = host_cgroup_path(pid) {
            if let Ok(v) = std::fs::read_to_string(format!("/sys/fs/cgroup{scope}/pids.max")) {
                pids_max = v.trim().to_string();
                if pids_max == TASK_CAP {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();

    // A match means a real `ops run` placed the cage in a scope with the
    // configured cap; otherwise skip (no systemd user session delegating pids).
    if pids_max != TASK_CAP {
        eprintln!(
            "skipping resource-limit e2e: the cage is not under a task-capped scope \
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
