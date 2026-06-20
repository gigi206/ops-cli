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
        d.push(format!("ops-run-it-{tag}-{}-{n}", std::process::id()));
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
