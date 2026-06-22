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

    // hermetic: `/usr` is the minimal synthetic tree — it holds only `bin` (which carries the
    // single `/usr/bin/env` symlink), never the host's `/usr`, which would expose `lib`/`share`/…
    // alongside. (That `/usr/bin/env` resolves an interpreted shebang is proven separately by
    // `a_usr_bin_env_shebang_resolves_in_the_cage`.)
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

    // capability probe via `ops run -- true`; skip (not fail) if the host cannot sandbox.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping imported-profile e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }

    // Import the profile — the deliberate consent act; it lands under the config dir.
    let imp = ops()
        .args(["app", "import", "greet.toml"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops app import");
    assert!(
        imp.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );

    // Launch it by name: the profile's command runs in the cage and its free env reaches it —
    // proving the imported profile was discovered and launched end to end.
    let greet = ops()
        .args(["app", "greet"])
        .current_dir(project.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("XDG_DATA_HOME", data.path())
        .output()
        .expect("spawn ops app");
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
        project.path().join(".ops.toml"),
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

    let out = ops_in(
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
        project.path().join(".ops.toml"),
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

    let out = ops_in(
        project.path(),
        data.path(),
        state.path(),
        &["run", "--", "fc-list"],
    );
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success(),
        "fc-list failed in the cage (gui = \"wayland\"): {log}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The DejaVu store path is the proof: it appears only because the generated config's `<dir>`
    // names the seeded font directory and `FONTCONFIG_FILE` points fontconfig at it.
    assert!(
        stdout.contains("/nix/store/") && stdout.contains("dejavu-fonts"),
        "fc-list did not list the hole's provisioned DejaVu fonts by store path: {log}"
    );
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
fn a_gui_wayland_launch_composes_with_a_network_allowlist() {
    // The real desktop-agent posture: `gui = "wayland"` AND `network = "allowlist"` open at once,
    // each stacking its own binds and env into one cage. The display socket (a local Unix socket,
    // bound read-only), the fonts (seeded + a generated config), and the egress machinery (the
    // bound proxy socket + the injected CA + the empty netns) must coexist — neither hole displaces
    // the other. Separately, Slice A proved the display and 6.2d proved the allowlist; the
    // *composition* is what this asserts, so the teeth are co-located in a SINGLE `ops run`:
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
        project.path().join(".ops.toml"),
        "gui = \"wayland\"\n\
         [network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n\
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

    // One cage, all four facets. Each emits a distinct marker on success; the test asserts every
    // marker is present, so the four holes are proven to function *together*. No `set -e`: the
    // denied fetch is meant to fail, and a missing facet must surface as a missing marker (caught
    // below) rather than aborting the script early.
    let script = "\
        wayland-info 2>&1 | grep -q wl_compositor && echo COMPOSE-WL\n\
        fc-list | grep -q dejavu-fonts && echo COMPOSE-FONT\n\
        nix-prefetch-url --type sha256 https://cache.nixos.org/nix-cache-info 2>/dev/null \
            | grep -q 15sqg1j6gq6081nk0v5c6npadlswb9238l336wb2g9bmmrry779c && echo COMPOSE-ALLOW\n\
        nix-prefetch-url --type sha256 https://example.com/nix-cache-info 2>&1 \
            | grep -q 403 && echo COMPOSE-DENY\n";
    let out = ops_in(
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
    // The font layer, with the allowlist also open.
    assert!(
        stdout.contains("COMPOSE-FONT"),
        "fc-list did not list the seeded DejaVu fonts with the allowlist also open: {log}"
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
        project.path().join(".ops.toml"),
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

    // run the script by its own absolute path, so the shebang (not an explicit `node`) drives
    // execution — the path through `/usr/bin/env`.
    let out = ops_in(
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
fn the_cage_auto_equips_a_non_nix_mise_tool_at_launch() {
    // Multi-backend: a project that declares a non-`nix:` mise tool (here `aqua:`) must have
    // it auto-installed in-cage at launch and resolvable on PATH — with no manual
    // `ops mise install` and no `ops trust` (the open self-equip posture). Teeth: `rg` runs
    // on a plain `ops run` of an UNtrusted project, so the launcher fetched it through mise,
    // installed it into the project's own store, and resolved it through the shims dir — the
    // whole auto-equip chain. Skips (never fails) when the host cannot sandbox or the network
    // is unreachable (the tool is fetched from upstream on first launch).
    let project = TmpDir::new("equip-proj");
    let data = TmpDir::new("equip-data");
    // anchored on an (empty) .ops.toml; the tool is fresh-from-upstream via mise's aqua backend
    std::fs::write(project.path().join(".ops.toml"), "").unwrap();
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

    // untrusted project, plain `ops run` — the tool must still equip and run (open posture).
    let out = run_in(project.path(), data.path(), &["rg", "--version"]);
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ripgrep"),
        "an auto-equipped aqua: tool must run on a plain `ops run` of an untrusted project: {log}"
    );
}

#[test]
fn the_cage_auto_equips_a_non_nix_tool_under_a_network_allowlist() {
    // The headline posture the shipped profiles use: a non-`nix:` tool auto-equipped under a
    // trusted `network = "allowlist"`. This is the discriminating case the shared-net test above
    // cannot reach — it forces BOTH (1) the wrap composition (the auto-equip wrap nests *inside*
    // the egress wrap, so the forwarder is up before the install fetches) and (2) mise's *own*
    // reqwest through the MITM proxy on a direct download (aqua fetches from github, already in
    // the built-in nix-cache allow-set), a TLS path nix:'s libcurl never exercises. Teeth: rg
    // runs, so mise's reqwest trusted the proxy's per-session CA and the forwarder bridged the
    // empty netns. Short tags keep the egress socket path under `SUN_LEN`. Skips (never fails)
    // when the host cannot sandbox or the cache is unreachable.
    let project = TmpDir::new("aql-proj");
    let data = TmpDir::new("aql-data");
    let state = TmpDir::new("aql-state");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n",
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

    let out = ops_in(
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
    // `mise use -g` at the `ops app` launch and runs it fresh, under the app's *own* network
    // allowlist — claude-code's aqua release fetch rides the built-in nix-cache allow-set
    // (github / *.githubusercontent.com), never a wide-open net. Teeth: `claude --version` prints
    // the upstream version through the empty-netns MITM, proving (1) the global `[packages] mise:`
    // equip path end-to-end, (2) the nixpkgs unfree blocker is gone (this is an aqua standalone
    // binary, not nixpkgs), and (3) the app's allowlist permits the release fetch. Short tags keep
    // the egress socket under `SUN_LEN`. Skips (never fails) without sandbox or network.
    let project = TmpDir::new("fmp-proj");
    let data = TmpDir::new("fmp-data");
    let state = TmpDir::new("fmp-state");
    std::fs::write(
        project.path().join(".ops.toml"),
        "[app.cc]\n\
         cmd = [\"claude\", \"--version\"]\n\
         [app.cc.packages]\n\
         claude-code = \"mise:aqua:anthropics/claude-code\"\n\
         [app.cc.network]\n\
         mode = \"allowlist\"\n\
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

    let out = ops_in(project.path(), data.path(), state.path(), &["app", "cc"]);
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Claude Code"),
        "a fresh `mise:` package app must equip claude-code via `mise use -g` and run it under its \
         own allowlist (the aqua release fetch riding the nix-cache allow-set): {log}"
    );
}

/// The path to a mise shim in the single project's default home under `data`, if present.
/// `ops upgrade mise`/`ops run` equip a baseline `mise:` tool into this home, where mise creates
/// a per-tool shim (its non-interactive PATH entry). Used as the teeth that the in-cage roll
/// touched the right home.
fn project_home_mise_shim(data: &Path, name: &str) -> Option<PathBuf> {
    let projects = data.join("ops").join("projects");
    for entry in std::fs::read_dir(&projects).ok()?.flatten() {
        let shim = entry.path().join("home/.local/share/mise/shims").join(name);
        if shim.exists() {
            return Some(shim);
        }
    }
    None
}

#[test]
fn ops_upgrade_mise_rolls_a_mise_package_in_cage() {
    // The load-bearing proof of the `mise:` `[packages]` roll-forward: `ops upgrade mise` runs
    // `mise upgrade` *in-cage*, per home, for the project's (and apps') `mise:` packages. A `mise:`
    // tool freezes at its installed version after the first equip (the floating `latest` request
    // stays satisfied, so a later launch never re-resolves), so advancing it must run `mise
    // upgrade` inside the same cage that equips it. Teeth: the capability probe runs against an
    // *empty* project (no package), so the only thing that can equip ripgrep into the project's
    // home is the upgrade cage itself — proven by the `rg` shim appearing in that home's mise data
    // dir after `ops upgrade mise` and *before* any `ops run`. The aqua release fetch rides the
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
        project.path().join(".ops.toml"),
        "[packages]\nrg = \"mise:aqua:BurntSushi/ripgrep\"\n",
    )
    .unwrap();
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

    let out = ops_in(
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
        "ops upgrade mise must roll the baseline `mise:` package in-cage: {log}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("mise upgrade aqua:BurntSushi/ripgrep"),
        "the report must name the project's mise: package group: {log}"
    );

    // Teeth: the upgrade cage equipped ripgrep into the project's own home (the `rg` shim mise
    // creates for a `use`d tool); no `ops run` ran in between, so only the upgrade cage could have.
    assert!(
        project_home_mise_shim(data.path(), "rg").is_some(),
        "ops upgrade mise must equip+roll ripgrep in the project home (no `rg` shim found): {log}"
    );
}

#[test]
fn a_flake_package_app_builds_in_cage_then_reruns_offline_from_the_warm_out_link() {
    // The load-bearing proof of the `flake:` backend, in two phases.
    //
    // PHASE 1 (cold build under the allowlist): an app declaring its tool as a
    // `[packages] flake:<ref>` builds the flake **in-cage** with `nix build --out-link` at the
    // `ops app` launch — an uncurated third-party flake contained by the cage, not built
    // host-side like a `nix:` attribute — lands the result on PATH, and runs it under the app's
    // *own* network allowlist. The ref is a real, pinned flake (`nixpkgs#hello`); `hello` prints
    // "Hello, world!" through the empty-netns MITM, proving the parse → in-cage build →
    // out-link-on-PATH → run chain. Honest limitation: this flake's inputs (the nixpkgs tarball
    // from codeload, the `hello` closure from cache.nixos.org) ride the *built-in* nix-cache
    // allow-set, so it does NOT exercise a fetch from a host *outside* that set — the uv2nix/PyPI
    // friction a real profile like hermes hits is a heavier manual validation, not covered here.
    //
    // PHASE 2 (warm + offline reuse): the same project is re-launched with `network = "none"` (the
    // network cut entirely). With no egress, the build *cannot* re-run — so `hello` printing again
    // proves the warm/offline short-circuit: the out-link persisted in the app's home and its
    // closure in the per-project store are reused, no re-fetch. This is the teeth for the property
    // that justified building `nix build --out-link` (not `nix profile install`): a warm launch is
    // a no-op that works offline.
    //
    // Short tags keep the egress socket under `SUN_LEN`. Skips (never fails) without sandbox or
    // network.
    let project = TmpDir::new("flk-proj");
    let data = TmpDir::new("flk-data");
    let state = TmpDir::new("flk-state");
    let flake = "flake:github:NixOS/nixpkgs/9ae611a455b90cf061d8f332b977e387bda8e1ca#hello";
    let toml = |mode: &str, net: &str| {
        format!(
            "[app.fk]\n\
             cmd = [\"hello\"]\n\
             [app.fk.packages]\n\
             hello = \"{flake}\"\n\
             [app.fk.network]\n\
             mode = \"{mode}\"\n{net}"
        )
    };
    std::fs::write(
        project.path().join(".ops.toml"),
        toml("allowlist", "allow = [\"cache.nixos.org\"]\n"),
    )
    .unwrap();

    // capability probe (untrusted → shared net); also seeds the project store once.
    let probe = run_in(project.path(), data.path(), &["true"]);
    if !probe.status.success() {
        eprintln!(
            "skipping `flake:` package app e2e: host cannot sandbox ({})",
            String::from_utf8_lossy(&probe.stderr).trim()
        );
        return;
    }
    if !cache_reachable() {
        eprintln!("skipping `flake:` package app e2e: the network is unreachable");
        return;
    }

    let trust = |project: &Path| {
        // trust so the app's `[packages] flake:` and its network posture are honored (both
        // security fields); editing the network mode re-arms the gate, hence trusting per phase.
        let t = ops_in(project, data.path(), state.path(), &["trust", ".ops.toml"]);
        assert!(
            t.status.success(),
            "ops trust failed: {}",
            String::from_utf8_lossy(&t.stderr)
        );
    };
    let launch = || ops_in(project.path(), data.path(), state.path(), &["app", "fk"]);

    // PHASE 1 — cold build under the allowlist.
    trust(project.path());
    let cold = launch();
    let cold_log = format!(
        "{}{}",
        String::from_utf8_lossy(&cold.stderr),
        String::from_utf8_lossy(&cold.stdout)
    );
    assert!(
        cold.status.success() && String::from_utf8_lossy(&cold.stdout).contains("Hello, world!"),
        "phase 1: a `flake:` package app must build the flake in-cage with `nix build --out-link` \
         and run it under its own allowlist: {cold_log}"
    );

    // PHASE 2 — cut the network entirely and re-launch: the warm out-link must run offline.
    std::fs::write(project.path().join(".ops.toml"), toml("none", "")).unwrap();
    trust(project.path());
    let warm = launch();
    let warm_log = format!(
        "{}{}",
        String::from_utf8_lossy(&warm.stderr),
        String::from_utf8_lossy(&warm.stdout)
    );
    assert!(
        warm.status.success() && String::from_utf8_lossy(&warm.stdout).contains("Hello, world!"),
        "phase 2: with `network = \"none\"` (no egress) the warm out-link must run `hello` offline \
         — a re-fetch is impossible, so this proves the short-circuit reuses the prior build: \
         {warm_log}"
    );
}

/// The names under the (single) project default home's flake out-link directory, in `data`.
/// `ops run` builds a `flake:` package's out-link here; the name reveals whether the launch chose
/// the rev-keyed (locked) form or the floating one.
fn project_flake_out_links(data: &Path) -> Vec<String> {
    let projects = data.join("ops").join("projects");
    let Ok(entries) = std::fs::read_dir(&projects) else {
        return vec![];
    };
    for entry in entries.flatten() {
        let dir = entry.path().join("home/.local/state/ops/flake");
        if let Ok(links) = std::fs::read_dir(&dir) {
            return links
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
        }
    }
    vec![]
}

#[test]
fn a_locked_flake_package_builds_the_pinned_ref_into_a_rev_keyed_out_link() {
    // The load-bearing proof of the *locked* launch path — the entire launch-side deliverable of
    // the flake roll-forward. After `ops upgrade flake` pins a `flake:` package, a launch reads the
    // per-project lock and builds the *locked* (narHash'd, immutable) reference — not the declared
    // floating one — into an out-link keyed by the revision, in-cage through the allowlist. Teeth:
    // (1) `hello` prints "Hello, world!", proving the locked narHash ref builds in-cage through the
    // empty-netns MITM (the existing flake e2e builds a narHash-*free* ref, so this is the
    // first proof the narHash form works on the wire); (2) the out-link is the rev-keyed
    // `hello-<rev>`, not the floating `hello` — so `build()` took the `Some(pin)` branch and chose
    // the locked ref. Reuses the revision the in-cage flake build e2e already warms. Skips (never
    // fails) without sandbox or network.
    let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    let project = TmpDir::new("lfk-proj");
    let data = TmpDir::new("lfk-data");
    let state = TmpDir::new("lfk-state");
    std::fs::write(
        project.path().join(".ops.toml"),
        format!(
            "[packages]\nhello = \"flake:github:NixOS/nixpkgs/{rev}#hello\"\n\
             [network]\nmode = \"allowlist\"\nallow = [\"cache.nixos.org\"]\n"
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

    // pin the flake package to its current revision (a host-side lock rewrite).
    let pinned = ops_in(
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

    // launch: build the *locked* ref into the rev-keyed out-link, in-cage through the allowlist.
    let out = ops_in(
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
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("Hello, world!"),
        "the locked flake ref must build in-cage through the allowlist and run: {log}"
    );

    // Teeth: the launch built the rev-keyed out-link (the locked branch), not the floating one.
    let links = project_flake_out_links(data.path());
    assert!(
        links.iter().any(|n| n == &format!("hello-{rev}")),
        "the launch must build the rev-keyed out-link `hello-{rev}` (links: {links:?})"
    );
    assert!(
        !links.iter().any(|n| n == "hello"),
        "the floating out-link must not be built when the package is pinned (links: {links:?})"
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
