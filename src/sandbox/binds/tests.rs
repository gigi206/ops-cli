use super::synthetic::{Identity, group_contents, passwd_contents};
use super::*;
use crate::testutil::TmpDir;
use std::os::unix::fs::PermissionsExt;

#[test]
fn the_shell_rc_sets_a_cage_naming_prompt_before_sourcing_bashrc() {
    // The interactive prompt names the cage via `\h` (the `sbx-<slug>` hostname), and is
    // set *before* the home's own `.bashrc` is sourced, so a user's own `PS1` still wins.
    let rc = SHELL_RC_CONTENTS;
    let ps1 = rc.find("PS1=").expect("the rc sets a default PS1");
    let source = rc.find(".bashrc").expect("the rc sources the home .bashrc");
    assert!(
        ps1 < source,
        "PS1 is a default set before .bashrc can override it"
    );
    assert!(
        rc.contains("\\h"),
        "the prompt names the cage via its hostname"
    );
}

fn userland() -> Userland {
    Userland {
        base_roots: vec![
            PathBuf::from("/nix/store/glibc"),
            PathBuf::from("/nix/store/gcc"),
            PathBuf::from("/nix/store/bash"),
            PathBuf::from("/nix/store/coreutils"),
            PathBuf::from("/nix/store/nix-ld"),
        ],
        interp_src: PathBuf::from("/store/nix-ld/libexec/nix-ld"),
        interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
        base_loader: PathBuf::from("/nix/store/glibc/lib/ld-linux-x86-64.so.2"),
        foreign_lib_paths: vec![
            PathBuf::from("/nix/store/glibc/lib"),
            PathBuf::from("/nix/store/gcc/lib"),
        ],
        bin_paths: vec![
            PathBuf::from("/store/bash/bin"),
            PathBuf::from("/store/coreutils/bin"),
        ],
        shell_bin: PathBuf::from("/store/bash/bin/bash"),
        env_bin: PathBuf::from("/store/coreutils/bin/env"),
        ldd_bin: PathBuf::from("/store/glibc-bin/bin/ldd"),
        socat_bin: PathBuf::from("/store/socat/bin/socat"),
        mise_bin: PathBuf::from("/store/mise/bin/mise"),
        nix_bin: PathBuf::from("/store/nix/bin/nix"),
        locale_archive: PathBuf::from("/nix/store/locales/lib/locale/locale-archive"),
        zoneinfo_src: PathBuf::from("/nix/store/tzdata/share/zoneinfo"),
    }
}

/// A read-only `/nix` from a stand-in shared store — what the assembler binds
/// when the cage consumes the shared store directly (the per-project writable
/// store is supplied by the launcher).
fn nix_mount() -> NixMount {
    NixMount {
        src: PathBuf::from("/data/sbx/store/nix"),
        writable: false,
        on_btrfs: false,
    }
}

/// The resolved paths the assembler tests start from, with every *conditional* source absent.
///
/// One place to add a field, and one place a test overrides the field it is about
/// (`SandboxPaths { ssh_config_src: Some(..), ..base_paths() }`).
fn base_paths() -> SandboxPaths<'static> {
    SandboxPaths {
        project: Path::new("/home/u/proj"),
        home_src: Path::new("/data/sbx/projects/abc/home"),
        mise_project_src: None,
        passwd_src: Path::new("/data/sbx/projects/abc/etc/passwd"),
        group_src: Path::new("/data/sbx/projects/abc/etc/group"),
        mise_plugin_src: Path::new("/store/mise-plugin"),
        shell_rc_src: Path::new("/store/bashrc"),
        xdg_open_src: Path::new("/data/sbx/projects/abc/etc/open/xdg-open"),
        open_router_src: Path::new("/data/sbx/projects/abc/etc/open"),
        contract_src: Path::new("/store/egress-contract.md"),
        hosts_src: Path::new("/data/sbx/projects/abc/etc/hosts"),
        ssh_config_src: None,
        machine_id_src: Path::new("/data/sbx/projects/abc/etc/machine-id"),
        open_apps_src: None,
        open_mimeapps_src: None,
    }
}

fn assembled() -> SandboxSpec {
    assembled_with_ssh_config(None)
}

/// The spec `paths` assembles to under the default userland, store and posture — the shared
/// tail of every `assembled*` helper.
fn assembled_from(paths: &SandboxPaths) -> SandboxSpec {
    let env = [("TERM".to_string(), "xterm".to_string())];
    let overlay = Overlay {
        env: &env,
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    assemble(
        paths,
        &userland(),
        &nix_mount(),
        &overlay,
        &[],
        &[],
        NetPolicy::Shared,
        vec![OsString::from("/bin/sh")],
    )
    .expect("valid spec")
}

fn assembled_with_ssh_config(ssh_config_src: Option<&Path>) -> SandboxSpec {
    assembled_from(&SandboxPaths {
        ssh_config_src,
        ..base_paths()
    })
}

/// A spec in which every conditional mount is present: the ssh client config, a global app's
/// per-project mise pool, and both `[open]` destinations. The structural-dest guard walks this
/// rather than the bare `assembled()`, because a mount that only some configurations emit is
/// precisely the one that gets added without being listed.
fn assembled_with_every_conditional_mount() -> SandboxSpec {
    assembled_from(&SandboxPaths {
        mise_project_src: Some(Path::new("/data/sbx/projects/abc/mise")),
        ssh_config_src: Some(Path::new("/data/sbx/projects/abc/etc/ssh_config")),
        open_apps_src: Some(Path::new("/data/sbx/projects/abc/etc/applications")),
        open_mimeapps_src: Some(Path::new("/data/sbx/projects/abc/etc/mimeapps.list")),
        ..base_paths()
    })
}

#[test]
fn structural_dests_lists_every_fixed_mount_assemble_emits() {
    // The bind-nesting warning checks a config bind against STRUCTURAL_DESTS, a hand-kept copy
    // of the destinations `assemble` mounts. If a new structural mount is added without
    // extending the const, the warning silently goes blind to it — so pin the two together.
    //
    // Walked over a spec with *every* conditional source supplied, which is what the finding
    // behind this shape cost: `assembled()` leaves them all `None`, so the ssh-config mount was
    // invisible to this test and stayed unlisted. A conditional mount is exactly the kind that
    // gets forgotten, so the guard must see them all.
    let spec = assembled_with_every_conditional_mount();
    let project = Path::new("/home/u/proj");
    let home = Path::new(SANDBOX_HOME);
    for mount in &spec.mounts {
        let dest = mount.dest();
        // The project is mounted at its own runtime path, and the `[open]` destinations (and
        // the pins above them) are runtime-derived *under* the home — which is listed, so a
        // config bind that overlaps them is already caught by it.
        if dest == project || (dest.starts_with(home) && dest != home) {
            continue;
        }
        // The `/opt` pin is emitted before the config binds and therefore shadows none of them;
        // see the const's own note.
        if dest == Path::new(OPT_DIR) {
            continue;
        }
        assert!(
            STRUCTURAL_DESTS.iter().any(|s| Path::new(s) == dest),
            "structural mount destination {dest:?} is not in STRUCTURAL_DESTS — list it, or \
             the bind-nesting warning will not catch a config bind that overlaps it"
        );
    }
}

/// A destination whose name the file already maps gets no second line: the built-in one wins the
/// lookup, so a later line would only mislead a reader into thinking it took effect.
#[test]
fn a_hosts_line_is_never_written_for_a_name_the_file_already_maps() {
    use std::net::Ipv4Addr;
    let dest = |host: &str, addr, map_name| super::super::egress::TcpDestination {
        host: host.to_string(),
        ports: vec![5432],
        cage_addr: addr,
        map_name,
    };
    let h = hosts_contents(
        "sbx-agy",
        &[
            dest("db.internal", Ipv4Addr::new(127, 0, 0, 2), true),
            // Both of these are already on the built-in lines.
            dest("localhost", Ipv4Addr::LOCALHOST, true),
            dest("sbx-agy", Ipv4Addr::new(127, 0, 0, 3), true),
        ],
    );

    assert!(h.contains("127.0.0.2\tdb.internal\n"), "{h}");
    assert_eq!(
        h.lines()
            .filter(|l| l.split_whitespace().any(|f| f == "localhost"))
            .count(),
        2,
        "only the two built-in lines may name localhost: {h}"
    );
    assert!(
        !h.contains("127.0.0.3"),
        "the hostname must not be repointed: {h}"
    );
}

#[test]
fn assemble_binds_a_read_only_hosts_file() {
    // A hermetic cage has no `/etc/hosts`; without it a tool resolving the *name* `localhost`
    // (e.g. to bind an internal server on it) falls through to DNS, which the empty netns has
    // no resolver for, and fails hard. The bind must be read-only from the synthetic source,
    // so the agent cannot rewrite the name resolution it depends on.
    let spec = assembled();
    let hosts = spec
        .mounts
        .iter()
        .find(|m| m.dest() == Path::new("/etc/hosts"))
        .expect("a /etc/hosts mount is emitted");
    match hosts {
        Mount::RoBind { src, .. } => assert_eq!(
            src.as_path(),
            Path::new("/data/sbx/projects/abc/etc/hosts"),
            "bound from the synthetic source"
        ),
        other => panic!("/etc/hosts must be a read-only bind, got {other:?}"),
    }
}

/// The generated ssh config is mounted only when something needs it, and then read-only from
/// the synthetic source — the agent may override it from its own `~/.ssh/config` (this is the
/// lowest-precedence file ssh reads), but it cannot rewrite the one the cage was handed.
#[test]
fn the_ssh_config_is_mounted_read_only_and_only_when_needed() {
    let bare = assembled();
    assert!(
        !bare
            .mounts
            .iter()
            .any(|m| m.dest() == Path::new(SSH_CONFIG_INCAGE)),
        "no CONNECT-only destination, no file"
    );

    let src = Path::new("/data/sbx/projects/abc/etc/ssh_config");
    let spec = assembled_with_ssh_config(Some(src));
    let mount = spec
        .mounts
        .iter()
        .find(|m| m.dest() == Path::new(SSH_CONFIG_INCAGE))
        .expect("the ssh config is mounted");
    match mount {
        Mount::RoBind { src: got, .. } => assert_eq!(got.as_path(), src),
        other => panic!("the ssh config must be a read-only bind, got {other:?}"),
    }
}

#[test]
fn the_synthetic_hosts_maps_localhost_and_the_cage_hostname() {
    let h = hosts_contents("sbx-agy", &[]);
    assert!(
        h.contains("127.0.0.1\tlocalhost"),
        "localhost → IPv4 loopback: {h:?}"
    );
    assert!(
        h.contains("::1\tlocalhost"),
        "localhost → IPv6 loopback: {h:?}"
    );
    assert!(
        h.contains("sbx-agy"),
        "the cage's own hostname resolves too: {h:?}"
    );
    // Every entry maps to loopback — no host address is ever written into the cage.
    for line in h.lines() {
        assert!(
            line.starts_with("127.0.0.1") || line.starts_with("::1"),
            "every /etc/hosts entry maps to loopback: {line:?}"
        );
    }
}

#[test]
fn the_synthetic_machine_id_is_systemd_shaped_deterministic_and_per_home() {
    let a1 = machine_id_contents(Path::new("/data/sbx/apps/demo-app/home"));
    let a2 = machine_id_contents(Path::new("/data/sbx/apps/demo-app/home"));
    let b = machine_id_contents(Path::new("/data/sbx/apps/demo-tool/home"));
    // systemd format: exactly 32 lowercase hex digits + a trailing newline.
    let body = a1.strip_suffix('\n').expect("newline-terminated");
    assert_eq!(body.len(), 32, "32 hex digits: {a1:?}");
    assert!(
        body.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex only: {a1:?}"
    );
    // Never the degenerate all-cages id (sha256 of an empty string, truncated) a fingerprinting
    // app produces when the file is absent — the whole reason this exists. Computed rather than
    // written out: the literal that stood here was 33 characters against a body asserted to be 32
    // three lines above, so the comparison could not fail whatever the function did.
    let degenerate: String = {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"")[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    };
    assert_eq!(
        degenerate.len(),
        32,
        "the sentinel is the same width as a body"
    );
    assert_ne!(body, degenerate, "the all-cages id: {a1:?}");
    // Deterministic per home (stable across launches) and unique across homes.
    assert_eq!(a1, a2, "same home → same id across launches");
    assert_ne!(a1, b, "a different home → a different id");
}

#[test]
fn assemble_binds_a_read_only_machine_id_at_both_conventional_paths() {
    // A hermetic cage carries no `/etc/machine-id`, `/var/lib/dbus/machine-id`, or MAC, so a
    // desktop app fingerprinting the machine hashes an empty string — the same id in every cage.
    // Both conventional paths are bound read-only from the one synthetic source, so the agent
    // cannot forge its own machine identity.
    let spec = assembled();
    for dest in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        let m = spec
            .mounts
            .iter()
            .find(|m| m.dest() == Path::new(dest))
            .unwrap_or_else(|| panic!("a {dest} mount is emitted"));
        match m {
            Mount::RoBind { src, .. } => assert_eq!(
                src.as_path(),
                Path::new("/data/sbx/projects/abc/etc/machine-id"),
                "{dest} bound from the synthetic source"
            ),
            other => panic!("{dest} must be a read-only bind, got {other:?}"),
        }
    }
}

#[test]
fn structural_nesting_warning_flags_only_a_nesting_overlap() {
    // A descendant of a structural mount is shadowed by it.
    let w = structural_nesting_warning(Path::new("/tmp/secrets"), false, None)
        .expect("descendant warns");
    assert!(w.contains("shadowed"), "descendant message: {w}");
    assert!(w.contains("/tmp"));
    // A non-`/dev` shadowed bind carries no device hint.
    assert!(!w.contains("[devices]"), "no device hint off /dev: {w}");

    // A `/dev/*` bind is shadowed AND steered to `[devices]` (the field that actually exposes a
    // device with device access — a plain bind would be visible but `nodev`).
    let w = structural_nesting_warning(Path::new("/dev/dri"), false, None).expect("/dev/* warns");
    assert!(w.contains("shadowed"), "/dev message: {w}");
    assert!(
        w.contains("[devices]"),
        "a /dev/* bind must be steered to [devices]: {w}"
    );

    // An ancestor of structural files over-exposes the directory around them.
    let w = structural_nesting_warning(Path::new("/etc"), false, None).expect("ancestor warns");
    assert!(w.contains("contains"), "ancestor message: {w}");
    // A read-only ancestor says nothing about writing.
    assert!(
        !w.contains("write through"),
        "ro ancestor must not mention writing: {w}"
    );

    // A read-write ancestor additionally flags the host write-through.
    let w = structural_nesting_warning(Path::new("/etc"), true, None).expect("rw ancestor warns");
    assert!(
        w.contains("write through"),
        "a rw ancestor bind must flag host write-through: {w}"
    );

    // An exact match is reconciled by `assemble` (the structural mount wins) — not a footgun.
    assert!(structural_nesting_warning(Path::new("/nix"), false, None).is_none());
    assert!(structural_nesting_warning(Path::new("/etc/passwd"), true, None).is_none());

    // A path that neither contains nor sits under any structural mount is fine. `/etcdata`
    // shares a textual prefix with `/etc/...` but not a path lineage, so it must not warn.
    assert!(structural_nesting_warning(Path::new("/srv/data"), true, None).is_none());
    assert!(structural_nesting_warning(Path::new("/etcdata"), false, None).is_none());
    assert!(structural_nesting_warning(Path::new("/home/u/proj"), false, None).is_none());
}

#[test]
fn assemble_emits_the_zones_in_order_with_correct_modes() {
    let spec = assembled();
    let argv = super::super::argv::to_argv(&spec);
    let text: Vec<String> = argv
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // the store at /nix is a read-only bind of the shared store here.
    let nix = text.iter().position(|s| s == "/nix").unwrap();
    assert_eq!(text[nix - 1], "/data/sbx/store/nix");
    assert_eq!(text[nix - 2], "--ro-bind");
    // the standard interpreter is the nix-ld shim, read-only
    let interp = text
        .iter()
        .position(|s| s == "/lib64/ld-linux-x86-64.so.2")
        .unwrap();
    assert_eq!(text[interp - 1], "/store/nix-ld/libexec/nix-ld");
    assert_eq!(text[interp - 2], "--ro-bind");

    // the two read-write binds, in order: the home, then the project at its
    // own absolute path.
    let binds: Vec<usize> = text
        .iter()
        .enumerate()
        .filter(|(_, s)| *s == "--bind")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(binds.len(), 2, "exactly two read-write binds");
    assert_eq!(text[binds[0] + 2], "/home/sandbox");
    assert_eq!(text[binds[1] + 1], "/home/u/proj");
    assert_eq!(text[binds[1] + 2], "/home/u/proj");

    // synthetic identity is read-only
    let passwd = text.iter().position(|s| s == "/etc/passwd").unwrap();
    assert_eq!(text[passwd - 1], "/data/sbx/projects/abc/etc/passwd");
    assert_eq!(text[passwd - 2], "--ro-bind");

    // TLS is hermetic — the CA bundle is a firm bind of sbx's cacert (not the host's);
    // only DNS stays best-effort.
    let ssl = text
        .iter()
        .position(|s| s == "/etc/ssl/certs/ca-bundle.crt")
        .unwrap();
    assert_eq!(text[ssl - 1], "/store/cacert/etc/ssl/certs/ca-bundle.crt");
    assert_eq!(text[ssl - 2], "--ro-bind");
    let resolv = text.iter().position(|s| s == "/etc/resolv.conf").unwrap();
    assert_eq!(text[resolv - 1], "--ro-bind-try");
}

#[test]
fn assemble_binds_a_device_after_the_minimal_dev() {
    // A `[devices]` grant becomes a `--dev-bind-try` of the host device at its own path, emitted
    // *after* the minimal `--dev` so the real device layers over the hostless default rather than
    // being shadowed by it. Both granted devices must be present, each after the `--dev`.
    let paths = base_paths();
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let devices = [PathBuf::from("/dev/dri"), PathBuf::from("/dev/kvm")];
    let spec = assemble(
        &paths,
        &userland(),
        &nix_mount(),
        &overlay,
        &[],
        &devices,
        NetPolicy::Shared,
        vec![OsString::from("/bin/sh")],
    )
    .expect("valid spec");
    let text: Vec<String> = super::super::argv::to_argv(&spec)
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let dev = text
        .iter()
        .position(|s| s == "--dev")
        .expect("--dev present");
    for d in ["/dev/dri", "/dev/kvm"] {
        let src = text
            .iter()
            .position(|s| s == d)
            .unwrap_or_else(|| panic!("{d} not bound"));
        assert_eq!(text[src - 1], "--dev-bind-try", "{d} is a device bind");
        assert_eq!(
            text[src + 1],
            d,
            "{d} is bound at its own path (src == dest)"
        );
        assert!(src > dev, "{d} must be bound after the minimal --dev");
    }
}

#[test]
fn the_cage_trusts_sbx_own_ca_bundle_not_the_host() {
    // sbx's CA bundle is bound at both standard certificate paths (the NixOS and the
    // Debian/OpenSSL conventions), so the cage's TLS trust comes from sbx's store rather
    // than whatever the host happens to carry — and the host's own `/etc/ssl` is never a
    // bind source, so the cage cannot see it.
    let spec = assembled();
    let argv = super::super::argv::to_argv(&spec);
    let text: Vec<String> = argv
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    for dest in [
        "/etc/ssl/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
    ] {
        let i = text
            .iter()
            .position(|s| s == dest)
            .unwrap_or_else(|| panic!("{dest} not bound"));
        assert_eq!(
            text[i - 1],
            "/store/cacert/etc/ssl/certs/ca-bundle.crt",
            "{dest} must be sbx's cacert bundle, not the host's"
        );
        assert_eq!(text[i - 2], "--ro-bind", "{dest} must be a firm bind");
    }
    // the host's `/etc/ssl` is never a bind source (no `--ro-bind*` whose source is the
    // host tree), so the cage cannot see the host's certificates.
    assert!(
        !text.iter().any(|s| s == "/etc/ssl"),
        "the host's /etc/ssl must not be bound"
    );
}

#[test]
fn cacert_env_names_sbx_bundle_under_every_ca_key() {
    // One source of truth: the keys sbx sets equal the egress key set, each pointing at
    // sbx's in-cage bundle.
    let env = cacert_env();
    assert_eq!(env.len(), super::super::egress::CA_FILE_ENV_KEYS.len());
    for (k, v) in &env {
        assert!(
            super::super::egress::CA_FILE_ENV_KEYS.contains(&k.as_str()),
            "unexpected CA key {k}"
        );
        assert_eq!(v, CAGE_CA_BUNDLE, "{k} must name sbx's bundle");
    }
}

#[test]
fn assemble_builds_a_hermetic_environment() {
    let spec = assembled();
    let joined = env_strings(&spec);

    let path_i = joined.iter().position(|s| s == "PATH").unwrap();
    // the URL router leads, ahead of every writable directory; mise's shims dir sits between
    // the (here empty) declared tools and the base userland, so an agent-activated tool
    // surfaces ahead of base on a name clash; the synthetic `/usr/bin` (env + xdg-open) trails,
    // and `/opt/sbx/bin` trails both so the declared-operations client resolves by the name
    // the cage's own contract tells an agent to type.
    assert_eq!(
        joined[path_i + 1],
        "/opt/sbx/open:/home/sandbox/.local/share/mise/shims:/store/bash/bin:/store/coreutils/bin:/usr/bin:/opt/sbx/bin"
    );
    // foreign binaries reach the base glibc through the nix-ld shim, never the
    // global LD_LIBRARY_PATH (which would skew a differently-pinned nix tool)
    let nix_ld_i = joined.iter().position(|s| s == "NIX_LD").unwrap();
    assert_eq!(
        joined[nix_ld_i + 1],
        "/nix/store/glibc/lib/ld-linux-x86-64.so.2"
    );
    let nix_ld_lp_i = joined
        .iter()
        .position(|s| s == "NIX_LD_LIBRARY_PATH")
        .unwrap();
    assert_eq!(
        joined[nix_ld_lp_i + 1],
        "/nix/store/glibc/lib:/nix/store/gcc/lib"
    );
    assert!(
        !joined.iter().any(|s| s == "LD_LIBRARY_PATH"),
        "the base glibc must not be exposed on the global LD_LIBRARY_PATH"
    );
    let home_i = joined.iter().position(|s| s == "HOME").unwrap();
    assert_eq!(joined[home_i + 1], "/home/sandbox");
    // the passthrough variable survived
    assert!(joined.iter().any(|s| s == "TERM"));
    // the sandbox-awareness handles are present: a process can tell it is caged, and
    // find the egress contract describing its network posture
    let sandbox_i = joined.iter().position(|s| s == "SBX_SANDBOX").unwrap();
    assert_eq!(joined[sandbox_i + 1], "1");
    let contract_i = joined
        .iter()
        .position(|s| s == "SBX_EGRESS_CONTRACT")
        .unwrap();
    assert_eq!(
        joined[contract_i + 1],
        super::super::contract::EGRESS_CONTRACT_INCAGE
    );
}

#[test]
fn the_egress_contract_is_bound_read_only() {
    // The contract describes what the cage's network permits; it must be a read-only
    // bind from the synthetic source, so the agent cannot rewrite the contract it is
    // told to read.
    // Key off the bind *source* — unique in the argv — since the in-cage destination
    // path is also the value of the `SBX_EGRESS_CONTRACT` environment variable.
    let argv = argv_strings(&assembled());
    let src = argv
        .iter()
        .position(|s| s == "/store/egress-contract.md")
        .expect("the egress contract is bound");
    assert_eq!(
        argv[src - 1],
        "--ro-bind",
        "the egress contract must be read-only"
    );
    assert_eq!(
        argv[src + 1],
        super::super::contract::EGRESS_CONTRACT_INCAGE,
        "contract bound at the in-cage contract path"
    );
}

/// A bind inside the project is not a bind: the project is mounted over it. The launch says
/// so, because the alternative is a config line that reads as doing something and does nothing.
///
/// Asserted against the assembled mount list as well as against the warning, so the two cannot
/// drift: what makes the bind pointless is the *order* the mounts come out in, and a warning
/// that survived a changed order would be a confident statement of something untrue.
#[test]
fn a_bind_the_project_covers_is_named_rather_than_silently_lost() {
    // The project this fixture assembles for.
    let project = Path::new("/home/u/proj");
    let bind = |p: &str| crate::config::Bind {
        path: PathBuf::from(p),
        writable: false,
    };
    let binds = [
        bind("/home/u/proj/vendor"),
        bind("/home/u/proj"),
        bind("/home/u/other"),
        // A sibling whose name merely starts with the same letters is not inside it: the test
        // is about path components, not about a prefix of the string.
        bind("/home/u/proj-2/src"),
    ];

    let named: Vec<&Path> = binds
        .iter()
        .filter(|b| structural_nesting_warning(&b.path, b.writable, Some(project)).is_some())
        .map(|b| b.path.as_path())
        .collect();
    assert_eq!(
        named,
        vec![Path::new("/home/u/proj/vendor"), project],
        "only the ones the project's own mount lands on"
    );
    // The two are told apart, because the remedy differs: one bind does nothing, the other
    // says read-only and gets read-write.
    let inside = structural_nesting_warning(Path::new("/home/u/proj/vendor"), false, Some(project))
        .expect("a bind inside the project is named");
    assert!(inside.contains("sits inside the project") && inside.contains("`[fs] deny`"));
    let itself = structural_nesting_warning(project, false, Some(project))
        .expect("a bind of the project itself is named");
    assert!(itself.contains("is the project itself"));
    // With no project to compare against, the constant list is all that is checked.
    assert!(structural_nesting_warning(Path::new("/home/u/proj/vendor"), false, None).is_none());

    // And what makes them pointless is really the order assembly emits: the project comes
    // after them. Read off the argv, so a reordering has to be a deliberate edit here too.
    let argv = argv_strings(&assemble_with(&[], &binds, &[]));
    let first = |p: &str| {
        argv.iter()
            .position(|s| s == p)
            .unwrap_or_else(|| panic!("no mount at {p} in {argv:?}"))
    };
    // The project's own mount is the *last* mention of that path: the config bind of the same
    // path is emitted earlier, which is the whole point.
    let project_mount = argv
        .iter()
        .rposition(|s| s == "/home/u/proj")
        .expect("the project is mounted");
    assert!(
        first("/home/u/proj/vendor") < project_mount,
        "the project must be emitted after the bind it covers, or this warning is wrong"
    );
    assert!(
        first("/home/u/proj") < project_mount,
        "and after a config bind naming the project itself"
    );
    assert!(
        first("/home/u/other") < project_mount,
        "a bind outside it is emitted in the same place, and simply is not covered"
    );
}

#[test]
fn assemble_emits_launcher_extra_binds_after_the_structural_mounts() {
    // The egress machinery binds (the socket, the CA) must land *after* the tmpfs, so the
    // socket sits on a writable mountpoint, and carry their declared mode.
    let paths = base_paths();
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let extra = [
        ExtraBind {
            src: PathBuf::from("/data/sbx/egress/proxy.sock"),
            dest: PathBuf::from("/tmp/sbx-egress.sock"),
            writable: true,
        },
        ExtraBind {
            src: PathBuf::from("/data/sbx/egress/ca.pem"),
            dest: PathBuf::from("/opt/sbx/egress-ca.pem"),
            writable: false,
        },
    ];
    let spec = assemble(
        &paths,
        &userland(),
        &nix_mount(),
        &overlay,
        &extra,
        &[],
        NetPolicy::Isolated,
        vec![OsString::from("/bin/sh")],
    )
    .expect("valid spec");
    let text: Vec<String> = super::super::argv::to_argv(&spec)
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    // the socket is a read-write bind at its cage destination
    let sock = text
        .iter()
        .position(|s| s == "/tmp/sbx-egress.sock")
        .unwrap();
    assert_eq!(text[sock - 1], "/data/sbx/egress/proxy.sock");
    assert_eq!(text[sock - 2], "--bind");
    // the CA is a read-only bind
    let ca = text
        .iter()
        .position(|s| s == "/opt/sbx/egress-ca.pem")
        .unwrap();
    assert_eq!(text[ca - 1], "/data/sbx/egress/ca.pem");
    assert_eq!(text[ca - 2], "--ro-bind");
    // both come after the /tmp tmpfs — the socket needs a writable mountpoint under it
    let tmpfs = text.iter().position(|s| s == "--tmpfs").unwrap();
    assert!(
        sock > tmpfs && ca > tmpfs,
        "extra binds must follow the tmpfs"
    );
}

/// Assemble with explicit config-supplied extra env, binds, and
/// prepended tool `bin` directories.
fn assemble_with(
    extra_env: &[(String, String)],
    extra_binds: &[crate::config::Bind],
    extra_bin_paths: &[PathBuf],
) -> SandboxSpec {
    assemble_with_zone(DEFAULT_ZONE, extra_env, extra_binds, extra_bin_paths)
}

/// [`assemble_with`], with the cage's zone named — the one input the launcher resolves per
/// launch rather than deriving from the userland.
fn assemble_with_zone(
    zone: &str,
    extra_env: &[(String, String)],
    extra_binds: &[crate::config::Bind],
    extra_bin_paths: &[PathBuf],
) -> SandboxSpec {
    let paths = base_paths();
    let overlay = Overlay {
        env: extra_env,
        binds: extra_binds,
        bin_paths: extra_bin_paths,
        timezone: zone,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    assemble(
        &paths,
        &userland(),
        &nix_mount(),
        &overlay,
        &[],
        &[],
        NetPolicy::Shared,
        vec![OsString::from("/bin/sh")],
    )
    .expect("valid spec")
}

fn argv_strings(spec: &SandboxSpec) -> Vec<String> {
    super::super::argv::to_argv(spec)
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// The cage's environment as bwrap will parse it off the descriptor: the same `--setenv KEY
/// VALUE` triples, just not in the world-readable argument list. Its own helper, because the two
/// lists are genuinely different places and a test asserting on one must not read the other.
fn env_strings(spec: &SandboxSpec) -> Vec<String> {
    super::super::argv::env_args(spec)
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn the_cage_carries_the_zone_database_and_a_localtime_link_naming_its_zone() {
    // Both halves, and the *shape* of each: the database is a read-only bind at the FHS path,
    // and `/etc/localtime` is a SYMLINK whose target names the zone — a resolver reads the zone
    // name off that target, so a bind of the zone file here would answer the offset and lose
    // the name. Asserted against literal argv, not against the constants, so renaming a
    // destination has to be a deliberate edit here too.
    for zone in ["UTC", "Europe/Paris"] {
        let argv = argv_strings(&assemble_with_zone(zone, &[], &[], &[]));
        let db = argv
            .iter()
            .position(|s| s == "/nix/store/tzdata/share/zoneinfo")
            .unwrap_or_else(|| panic!("the zone database must be bound ({zone}):\n{argv:?}"));
        assert_eq!(argv[db - 1], "--ro-bind", "the database is read-only");
        assert_eq!(argv[db + 1], "/usr/share/zoneinfo");
        let link = argv
            .iter()
            .position(|s| s == "/etc/localtime")
            .unwrap_or_else(|| panic!("/etc/localtime must exist ({zone}):\n{argv:?}"));
        assert_eq!(argv[link - 2], "--symlink", "/etc/localtime is a symlink");
        assert_eq!(
            argv[link - 1],
            format!("/usr/share/zoneinfo/{zone}"),
            "the link target names the zone, through the in-cage database path"
        );
        // And the variable half, which has to agree with the link: `TZ` alone would move the
        // clock without moving the name, `TZDIR` alone would leave `TZ` unresolvable.
        let env = env_strings(&assemble_with_zone(zone, &[], &[], &[]));
        let at = |key: &str| {
            let i = env.iter().position(|s| s == key).expect(key);
            env[i + 1].clone()
        };
        assert_eq!(at("TZ"), zone);
        assert_eq!(at("TZDIR"), "/usr/share/zoneinfo");
    }
}

#[test]
fn a_config_env_value_overrides_the_structural_default() {
    // a trusted config can set PATH; its value wins, and the key is not emitted
    // twice (the structural default is replaced, not appended to).
    let spec = assemble_with(&[("PATH".to_string(), "/opt/bin".to_string())], &[], &[]);
    let argv = env_strings(&spec);
    let positions: Vec<usize> = argv
        .iter()
        .enumerate()
        .filter(|(_, s)| *s == "PATH")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(positions.len(), 1, "PATH must not be duplicated");
    assert_eq!(argv[positions[0] + 1], "/opt/bin");
}

#[test]
fn declared_tool_bins_are_prepended_to_the_structural_path() {
    // a project's tools win on a name collision, so their bin dirs come first,
    // ahead of the base userland's bash/coreutils.
    let spec = assemble_with(
        &[],
        &[],
        &[
            PathBuf::from("/nix/store/node/bin"),
            PathBuf::from("/nix/store/python/bin"),
        ],
    );
    let argv = env_strings(&spec);
    let path_i = argv.iter().position(|s| s == "PATH").unwrap();
    // the URL router first (the one name the cage may not shadow), then declared tools, then
    // mise's shims, then the base userland, then the synthetic `/usr/bin` (env + xdg-open).
    assert_eq!(
        argv[path_i + 1],
        "/opt/sbx/open:/nix/store/node/bin:/nix/store/python/bin:/home/sandbox/.local/share/mise/shims:/store/bash/bin:/store/coreutils/bin:/usr/bin:/opt/sbx/bin"
    );
}

#[test]
fn the_url_router_leads_path_ahead_of_every_writable_directory() {
    // The finding this ordering answers: the mise shims directory lives in the writable home
    // and used to precede the synthetic `/usr/bin`, so a process in the cage could drop its own
    // `xdg-open` there and every later caller resolved it — the read-only bind was never
    // reached. Asserted on the emitted PATH rather than on the vector that builds it, and by
    // *position*: the router must precede the shims directory, whatever else is declared.
    let spec = assemble_with(&[], &[], &[PathBuf::from("/nix/store/node/bin")]);
    let argv = env_strings(&spec);
    let path_i = argv.iter().position(|s| s == "PATH").unwrap();
    let dirs: Vec<&str> = argv[path_i + 1].split(':').collect();
    assert_eq!(
        dirs.first().copied(),
        Some(OPEN_ROUTER_DIR),
        "the router directory leads PATH"
    );
    let shims = dirs
        .iter()
        .position(|d| d.contains("mise/shims"))
        .expect("the mise shims dir is on PATH");
    assert!(
        shims > 0,
        "no writable directory may precede the router on PATH"
    );
    assert!(
        !dirs[1..].contains(&OPEN_ROUTER_DIR),
        "the router directory appears exactly once"
    );
}

#[test]
fn the_router_binds_the_same_stub_read_only_under_both_names() {
    // The router path is what PATH resolves; the FHS path stays for a caller that names
    // `/usr/bin/xdg-open` absolutely. One staged source, bound under both — a second copy
    // would be a second thing to keep in step. The PATH-resolved name comes from the bind of
    // the staged *directory*, which is why it is that source the argv carries.
    let argv = argv_strings(&assembled());
    let fhs = argv
        .iter()
        .position(|s| s == XDG_OPEN_INCAGE)
        .expect("the FHS name is synthesised");
    assert_eq!(
        argv[fhs - 1],
        "/data/sbx/projects/abc/etc/open/xdg-open",
        "the FHS name binds the staged stub"
    );
    let router = argv
        .iter()
        .position(|s| s == OPEN_ROUTER_DIR)
        .expect("the router directory is bound");
    assert_eq!(
        argv[router - 1],
        "/data/sbx/projects/abc/etc/open",
        "the router directory binds the directory that stub lives in"
    );
    assert_eq!(
        argv[router - 2],
        "--ro-bind",
        "the router directory is a read-only bind"
    );
    assert!(
        Path::new(OPEN_ROUTER_INCAGE).starts_with(OPEN_ROUTER_DIR),
        "the name PATH resolves is the one inside that directory"
    );
}

#[test]
fn every_component_of_the_router_directory_is_a_mountpoint() {
    // The finding this answers: only `/opt/sbx/open/xdg-open` was a mount, so `/opt` and
    // `/opt/sbx` were ordinary directories on the cage's writable root. The kernel refuses to
    // rename a mountpoint (EBUSY) but not an ancestor of one — the mounts simply travel with
    // the directory — so in-cage code could `mv /opt /opt.bak`, recreate
    // `/opt/sbx/open/xdg-open` as its own script, and own the `xdg-open` that leads PATH for
    // every later caller. Every component down to the router directory must therefore be a
    // mount of its own, and each must be established before the one below it: a child mounted
    // first is shadowed when its parent lands on top.
    let spec = assembled();
    let dests: Vec<&Path> = spec.mounts.iter().map(|m| m.dest()).collect();
    let at = |p: &str| {
        dests
            .iter()
            .position(|d| *d == Path::new(p))
            .unwrap_or_else(|| panic!("{p} is not a mountpoint: {dests:?}"))
    };
    let (opt, sbx, open) = (at(OPT_DIR), at(SBX_INCAGE_DIR), at(OPEN_ROUTER_DIR));
    assert!(
        opt < sbx && sbx < open,
        "the chain is laid shallow-to-deep: {dests:?}"
    );
    assert!(
        matches!(&spec.mounts[open], Mount::RoBind { .. }),
        "the router directory is read-only, so the cage cannot add a second name to the \
         directory that leads PATH"
    );
}

#[test]
fn the_opt_pin_does_not_shadow_a_config_bind_under_it() {
    // The `/opt` pin exists to make the path a mountpoint, not to own what is under it, so it
    // is the one structural mount emitted *before* the config binds. A `[[binds]]` under `/opt`
    // must still land inside the cage — the pin is not allowed to buy its guarantee by making
    // declared binds disappear.
    let bind = crate::config::Bind {
        path: PathBuf::from("/opt/vendor"),
        writable: false,
    };
    let spec = assemble_with(&[], std::slice::from_ref(&bind), &[]);
    let dests: Vec<&Path> = spec.mounts.iter().map(|m| m.dest()).collect();
    let opt = dests
        .iter()
        .position(|d| *d == Path::new(OPT_DIR))
        .expect("the pin is emitted");
    let vendor = dests
        .iter()
        .position(|d| *d == Path::new("/opt/vendor"))
        .expect("the config bind survives");
    assert!(
        opt < vendor,
        "the pin precedes the config bind, so the bind mounts inside it rather than being \
         shadowed by it: {dests:?}"
    );
}

#[test]
fn every_component_of_an_open_destination_is_a_mountpoint() {
    // Same finding as the router chain, in the home: the `[open]` files are bound read-only
    // *inside* a writable bind, and a read-only bind is unmovable only at its own path. With
    // `$HOME/.local` an ordinary directory, the cage renames it, recreates
    // `$HOME/.local/share/applications` with a desktop entry of its own, and the XDG lookup —
    // which asks for that path by name — reads the forgery. Every directory between the home
    // and each destination must be a mountpoint, laid shallow-to-deep, and still read-write:
    // pinning them read-only would freeze parts of the home the cage legitimately writes.
    let spec = assembled_with_every_conditional_mount();
    let dests: Vec<&Path> = spec.mounts.iter().map(|m| m.dest()).collect();
    for rel in [
        super::super::openuri::APPLICATIONS_REL,
        super::super::openuri::MIMEAPPS_REL,
    ] {
        let dest = PathBuf::from(format!("{SANDBOX_HOME}/{rel}"));
        let leaf = dests
            .iter()
            .position(|d| *d == dest)
            .unwrap_or_else(|| panic!("{} is not bound: {dests:?}", dest.display()));
        let mut previous = dests
            .iter()
            .position(|d| *d == Path::new(SANDBOX_HOME))
            .expect("the home is bound");
        for ancestor in dest.ancestors().collect::<Vec<_>>().iter().rev() {
            if !ancestor.starts_with(SANDBOX_HOME) || *ancestor == Path::new(SANDBOX_HOME) {
                continue;
            }
            let at = dests
                .iter()
                .position(|d| d == ancestor)
                .unwrap_or_else(|| panic!("{} is not a mountpoint: {dests:?}", ancestor.display()));
            assert!(
                at > previous,
                "{} must be mounted after its parent: {dests:?}",
                ancestor.display()
            );
            previous = at;
            if at != leaf {
                assert!(
                    matches!(&spec.mounts[at], Mount::Bind { .. }),
                    "{} is pinned read-write — the home stays writable",
                    ancestor.display()
                );
            }
        }
    }
}

#[test]
fn build_spec_refuses_an_open_pin_parent_the_cage_pointed_out_of_the_home() {
    // The pins `home_mountpoint_pins` emits are read-write binds whose *sources* are the home's
    // own `.config` and `.local/share`. Those sit below the writable home bind, so they are
    // entries in-cage code can replace with a symlink and leave behind — and the pin then binds
    // whatever the link named into the next cage, read-write. `create_dir_all` could not see
    // that: it stats through the link, finds a directory, and reports the parent made. Walking
    // the components with symlinks refused, anchored on the home's mount point, is what turns a
    // planted link into a failed launch instead of a bind of the host root at
    // `/home/sandbox/.config`.
    let data = TmpDir::new();
    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();

    let home = home_src(data.path(), project.path(), Runtime::ProjectDefault)
        .expect("the home path is derivable");
    std::fs::create_dir_all(&home).unwrap();
    let outside = data.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, home.join(".config")).unwrap();

    let mut open = std::collections::BTreeMap::new();
    open.insert(
        "https".to_string(),
        crate::config::OpenHandler {
            argv: vec!["firefox".to_string()],
            mode: crate::config::OpenMode::Exec,
        },
    );
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let err = build_spec(
        data.path(),
        project.path(),
        Runtime::ProjectDefault,
        &userland(),
        &nix_mount(),
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &open,
        vec![OsString::from("/bin/sh")],
    )
    .expect_err("a repointed pin parent must fail the launch");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
    assert!(
        std::fs::symlink_metadata(home.join(".config"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the planted link must be reported, not replaced"
    );
}

#[test]
fn usr_bin_env_is_symlinked_to_coreutils_env() {
    // An interpreted tool's `#!/usr/bin/env <interp>` shebang must resolve: the cage
    // synthesises `/usr/bin/env` as a symlink to coreutils' `env`, one of the FHS paths
    // beside `/bin/sh` and `/bin/bash`. bwrap creates the `/usr/bin` parent for the symlink.
    let argv = argv_strings(&assembled());
    let env = argv
        .iter()
        .position(|s| s == "/usr/bin/env")
        .expect("/usr/bin/env is synthesised");
    assert_eq!(
        argv[env - 1],
        "/store/coreutils/bin/env",
        "/usr/bin/env links to coreutils' env"
    );
    assert_eq!(argv[env - 2], "--symlink", "/usr/bin/env is a symlink");
}

#[test]
fn usr_bin_ldd_is_symlinked_to_the_base_glibcs_ldd() {
    // A program asking which C library it runs on reads `/usr/bin/ldd` by its literal path
    // rather than searching `PATH`, so a cage without the name leaves the question unanswered
    // instead of failing where the caller could handle it. Measured on a packaged Electron
    // application whose bundled `detect-libc` opens exactly this path: absent, the application
    // took `SIGILL` seconds into its run.
    //
    // Asserted as a symlink to the base glibc's own `ldd`, and not merely as "some `/usr/bin/ldd`
    // exists": what makes the answer true is that it is the libc the cage actually runs.
    let argv = argv_strings(&assembled());
    let ldd = argv
        .iter()
        .position(|s| s == "/usr/bin/ldd")
        .expect("/usr/bin/ldd is synthesised");
    assert_eq!(
        argv[ldd - 1],
        "/store/glibc-bin/bin/ldd",
        "/usr/bin/ldd links to the base glibc's ldd"
    );
    assert_eq!(argv[ldd - 2], "--symlink", "/usr/bin/ldd is a symlink");
}

#[test]
fn usr_bin_xdg_open_is_a_read_only_bind_of_the_stub() {
    // A tool that auto-opens a browser/file (an OAuth device-auth flow) calls
    // `xdg-open`; the hermetic cage has none, so the cage synthesises a stub at
    // `/usr/bin/xdg-open`. It is a read-only bind (not a symlink) of the staged
    // executable script, so a tool probing `$PATH` finds it and a call exits 0
    // instead of aborting the flow with "xdg-open not found".
    let argv = argv_strings(&assembled());
    let xdg = argv
        .iter()
        .position(|s| s == "/usr/bin/xdg-open")
        .expect("/usr/bin/xdg-open is synthesised");
    assert_eq!(
        argv[xdg - 1],
        "/data/sbx/projects/abc/etc/open/xdg-open",
        "/usr/bin/xdg-open binds the staged stub"
    );
    assert_eq!(
        argv[xdg - 2],
        "--ro-bind",
        "/usr/bin/xdg-open is a read-only bind"
    );
}

#[test]
fn the_staged_router_is_a_posix_sh_script_that_exits_zero() {
    // The router must be a valid `#!/bin/sh` script (the cage synthesises that path) that
    // exits 0 — the whole point is a tool calling `xdg-open` does not see a failure — and
    // surface its argument so the user can act on it. Asserted on what the module *emits*,
    // since that is the byte sequence the launch stages and binds.
    let staged = super::super::openuri::router(&Default::default());
    assert!(
        staged.starts_with("#!/bin/sh\n"),
        "the router is a /bin/sh script"
    );
    assert!(
        staged.contains("exit 0"),
        "it exits 0 so the caller treats the open as non-fatal"
    );
    assert!(
        staged.contains("\"$@\""),
        "it surfaces the argument the tool passed"
    );
}

#[test]
fn bin_bash_is_symlinked_to_the_same_shell_as_bin_sh() {
    // A `#!/bin/bash` shebang must resolve in a cage with no host `/bin/bash`: the cage
    // synthesises `/bin/bash` as a symlink to the SAME nix shell `/bin/sh` points at (bash
    // selects POSIX-vs-full mode from argv[0], so one binary serves both names).
    let argv = argv_strings(&assembled());
    let bash = argv
        .iter()
        .position(|s| s == "/bin/bash")
        .expect("/bin/bash is synthesised");
    assert_eq!(
        argv[bash - 1],
        "/store/bash/bin/bash",
        "/bin/bash links to the shell binary"
    );
    assert_eq!(argv[bash - 2], "--symlink", "/bin/bash is a symlink");
    // it points at the exact same target as `/bin/sh`, not a second shell
    let sh = argv
        .iter()
        .position(|s| s == "/bin/sh")
        .expect("/bin/sh is synthesised");
    assert_eq!(
        argv[bash - 1],
        argv[sh - 1],
        "/bin/bash and /bin/sh must be the same shell binary"
    );
}

#[test]
fn the_shell_rc_is_bound_read_only_for_mise_activation() {
    // an interactive `sbx run` points bash's `--rcfile` at this path; it must be a read-only bind
    // so the agent cannot rewrite the init its own interactive shell sources.
    let argv = argv_strings(&assembled());
    let rc = argv
        .iter()
        .position(|s| s == super::SHELL_RC_INCAGE)
        .expect("the shell rc is bound");
    assert_eq!(
        argv[rc - 1],
        "/store/bashrc",
        "rc bound from the synthetic source"
    );
    assert_eq!(argv[rc - 2], "--ro-bind", "the shell rc must be read-only");
}

/// A read-only config bind for the tests.
fn ro(path: &str) -> crate::config::Bind {
    crate::config::Bind {
        path: PathBuf::from(path),
        writable: false,
    }
}

/// A read-write config bind for the tests.
fn rw(path: &str) -> crate::config::Bind {
    crate::config::Bind {
        path: PathBuf::from(path),
        writable: true,
    }
}

#[test]
fn a_config_bind_precedes_the_structural_mounts() {
    // the extra bind is emitted first, so a colliding structural mount shadows
    // it — a config bind can never displace the store or the synthetic identity.
    let spec = assemble_with(&[], &[ro("/opt/data")], &[]);
    let argv = argv_strings(&spec);
    let extra = argv.iter().position(|s| s == "/opt/data").unwrap();
    let nix = argv.iter().position(|s| s == "/nix").unwrap();
    assert!(
        extra < nix,
        "the config bind must precede the structural /nix"
    );
    assert_eq!(argv[extra - 1], "--ro-bind", "a config bind is read-only");
}

#[test]
fn a_writable_config_bind_is_a_read_write_mount() {
    // `mode = "rw"` maps to bwrap's `--bind` (read-write), while the default is `--ro-bind`.
    let spec = assemble_with(&[], &[rw("/opt/data"), ro("/opt/ref")], &[]);
    let argv = argv_strings(&spec);
    let rw_i = argv.iter().position(|s| s == "/opt/data").unwrap();
    assert_eq!(argv[rw_i - 1], "--bind", "a rw config bind is read-write");
    let ro_i = argv.iter().position(|s| s == "/opt/ref").unwrap();
    assert_eq!(argv[ro_i - 1], "--ro-bind", "a ro config bind is read-only");
}

#[test]
fn a_writable_config_bind_at_a_structural_dest_is_shadowed() {
    // The safety invariant: a config bind — even read-write — is emitted before the
    // structural mounts, so a rw bind aimed at `/nix` cannot make the store writable; the
    // structural `/nix` mount is emitted last and wins. The rw bind still appears (earlier),
    // but the structural mount shadows it at that dest.
    let spec = assemble_with(&[], &[rw("/nix")], &[]);
    let argv = argv_strings(&spec);
    // The final mount at `/nix` is the structural store bind (from `nix_mount()`), read-only
    // in this fixture — so the config rw bind did not turn the store writable.
    let last_nix = argv
        .iter()
        .enumerate()
        .rfind(|(_, s)| s.as_str() == "/nix")
        .map(|(i, _)| i)
        .unwrap();
    assert_eq!(
        argv[last_nix - 1],
        "/data/sbx/store/nix",
        "the structural store bind is the last mount at /nix"
    );
    assert_eq!(
        argv[last_nix - 2],
        "--ro-bind",
        "the store stays read-only despite a rw config bind at /nix"
    );
}

#[test]
fn an_empty_config_adds_nothing() {
    // the additive promise: no config changes nothing — the first bind is still
    // the store, and the only environment is the structural set. That set carries
    // the always-on mise self-equip variables (the cage always lets an agent drive
    // mise); they come from the assembler, not the config, so an empty config still
    // adds nothing of its own.
    let spec = assemble_with(&[], &[], &[]);
    let argv = argv_strings(&spec);
    let first_ro = argv.iter().position(|s| s == "--ro-bind").unwrap();
    assert_eq!(
        argv[first_ro + 1],
        "/data/sbx/store/nix",
        "no extra bind may precede the store"
    );
    assert_eq!(argv[first_ro + 2], "/nix", "the store binds at /nix");
    let env = env_strings(&spec);
    let setenvs: Vec<&str> = env
        .iter()
        .enumerate()
        .filter(|(_, s)| *s == "--setenv")
        .map(|(i, _)| env[i + 1].as_str())
        .collect();
    assert_eq!(
        setenvs,
        [
            "HOME",
            "PATH",
            "NIX_LD",
            "NIX_LD_LIBRARY_PATH",
            "SBX_SANDBOX",
            "SBX_EGRESS_CONTRACT",
            "LOCALE_ARCHIVE",
            "LANG",
            "TZDIR",
            "TZ",
            "MISE_DATA_DIR",
            "MISE_EXPERIMENTAL",
            "MISE_YES",
            "NIX_CONFIG",
        ]
    );
}

#[test]
fn a_writable_nix_mount_is_a_read_write_bind_of_the_per_project_store() {
    // The open-cage posture: backed by a per-project store, `/nix` is a read-write
    // bind of it (the agent may write its own toolchain into the project's own
    // store), not the read-only bind of the shared store.
    let paths = base_paths();
    let nix = NixMount {
        src: PathBuf::from("/data/sbx/projects/abc/store/nix"),
        writable: true,
        on_btrfs: false,
    };
    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let spec = assemble(
        &paths,
        &userland(),
        &nix,
        &overlay,
        &[],
        &[],
        NetPolicy::Shared,
        vec![OsString::from("/bin/sh")],
    )
    .expect("valid spec");
    let argv = argv_strings(&spec);

    // a read-write bind: `--bind <per-project store> /nix`, never `--ro-bind`
    let nix_pos = argv.iter().position(|s| s == "/nix").unwrap();
    assert_eq!(argv[nix_pos - 1], "/data/sbx/projects/abc/store/nix");
    assert_eq!(argv[nix_pos - 2], "--bind");
}

#[test]
fn synthetic_etc_lives_outside_the_writable_home() {
    // The core integrity property holds for every runtime scope: the read-only identity
    // files have no read-write alias inside the sandbox.
    let data = Path::new("/data/sbx");
    let project = Path::new("/home/u/proj");
    for runtime in [
        Runtime::ProjectDefault,
        Runtime::GlobalApp("demo-app"),
        Runtime::ProjectApp("demo-app"),
    ] {
        let pr = project_runtime(data, project, runtime);
        assert!(
            !pr.etc_dir.starts_with(&pr.home_src),
            "synthetic /etc ({}) must not sit under the rw home ({})",
            pr.etc_dir.display(),
            pr.home_src.display(),
        );
        assert!(pr.home_src.ends_with("home"));
        assert!(pr.etc_dir.ends_with("etc"));
    }
}

#[test]
fn each_runtime_scope_keys_a_distinct_persistent_home() {
    // Isolation with teeth: the project default, a global app, a per-project app, and a
    // second app all resolve to different homes — so no two share writable state. The
    // global app's home is project-independent; the per-project app's nests under the
    // project.
    let data = Path::new("/data/sbx");
    let p1 = Path::new("/home/u/proj");
    let p2 = Path::new("/home/u/other");
    let home = |project: &Path, rt| project_runtime(data, project, rt).home_src;

    let default = home(p1, Runtime::ProjectDefault);
    let global_a = home(p1, Runtime::GlobalApp("demo-app"));
    let global_b = home(p1, Runtime::GlobalApp("other-app"));
    let proj_a = home(p1, Runtime::ProjectApp("demo-app"));

    // all four are distinct
    for (x, y) in [
        (&default, &global_a),
        (&default, &proj_a),
        (&global_a, &global_b),
        (&global_a, &proj_a),
    ] {
        assert_ne!(x, y, "runtime homes must not collide");
    }
    // a global app keeps the same home across projects; a per-project one does not
    assert_eq!(global_a, home(p2, Runtime::GlobalApp("demo-app")));
    assert_ne!(proj_a, home(p2, Runtime::ProjectApp("demo-app")));
    // the project default and a per-project app both nest under the same project dir
    let project_dir = data.join("projects").join(project_id(p1));
    assert!(default.starts_with(&project_dir));
    assert!(proj_a.starts_with(&project_dir));
    // a global app does not nest under any project dir
    assert!(!global_a.starts_with(data.join("projects")));
}

#[test]
fn synthetic_passwd_carries_the_identity_and_no_host_account() {
    let id = Identity {
        uid: 1000,
        gid: 1000,
        user: "sandbox".to_string(),
    };
    let passwd = passwd_contents(&id, SANDBOX_HOME, SANDBOX_SHELL);
    assert!(passwd.contains("sandbox:x:1000:1000:sandbox:/home/sandbox:/bin/sh"));
    assert!(passwd.contains("nobody:x:65534:"));
    // no real host login leaked in
    assert!(!passwd.contains("/home/gigi"));
    let group = group_contents(&id);
    assert!(group.contains("sandbox:x:1000:"));
    assert!(group.contains("nogroup:x:65534:"));
}

#[test]
fn materialize_etc_writes_owner_only_files_with_the_synthetic_content() {
    let base = TmpDir::new();
    let etc = base.join("etc");
    let id = Identity {
        uid: 4321,
        gid: 4321,
        user: "sandbox".to_string(),
    };

    let (passwd, group) = materialize_etc(&etc, &id).unwrap();
    assert_eq!(
        std::fs::metadata(&etc).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(std::fs::read_to_string(&passwd).unwrap().contains("4321"));
    assert!(std::fs::read_to_string(&group).unwrap().contains("nogroup"));
}

#[test]
fn re_materializing_the_identity_installs_a_new_inode_instead_of_rewriting_in_place() {
    // The finding: `passwd`/`group` were the only files staged in this directory written with a
    // plain `fs::write`, while the directory is shared by concurrent cages of one project and
    // both files are bound read-only into each of them. An in-place write truncates the file
    // the running cage is reading through that bind, so every `getpwuid` in it fails for the
    // width of the window; and even after the write it swaps the identity under a cage that
    // already resolved it. A temp-and-rename leaves the running cage on the inode it bound.
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    let base = TmpDir::new();
    let etc = base.join("etc");
    let first = Identity {
        uid: 4321,
        gid: 4321,
        user: "sandbox".to_string(),
    };
    let (passwd, group) = materialize_etc(&etc, &first).unwrap();
    let (passwd_ino, group_ino) = (
        std::fs::metadata(&passwd).unwrap().ino(),
        std::fs::metadata(&group).unwrap().ino(),
    );
    // The handle a running cage holds on the file it bound.
    let mut bound = std::fs::File::open(&passwd).unwrap();

    let second = Identity {
        uid: 5555,
        gid: 5555,
        user: "sandbox".to_string(),
    };
    let (passwd_again, group_again) = materialize_etc(&etc, &second).unwrap();
    assert_eq!((&passwd, &group), (&passwd_again, &group_again));

    let mut held = String::new();
    bound.read_to_string(&mut held).unwrap();
    assert!(
        held.contains("4321") && !held.contains("5555"),
        "a cage already bound to the file keeps its own complete view: {held}"
    );
    assert_ne!(
        std::fs::metadata(&passwd).unwrap().ino(),
        passwd_ino,
        "passwd is replaced by rename, not rewritten in place"
    );
    assert_ne!(
        std::fs::metadata(&group).unwrap().ino(),
        group_ino,
        "group is replaced by rename, not rewritten in place"
    );
    // The next launch does get the new identity — and no temp sibling is left behind, which
    // would be a second name in a directory the cage reads.
    assert!(
        std::fs::read_to_string(&passwd).unwrap().contains("5555"),
        "the new identity is what the path now names"
    );
    let staged: Vec<String> = std::fs::read_dir(&etc)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(staged.len(), 2, "no leftover temp file: {staged:?}");
}

#[test]
fn canonicalize_project_follows_symlinks_and_requires_a_directory() {
    let base = TmpDir::new();
    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = base.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    // a symlink to the dir resolves to the real path (TOCTOU pin)
    assert_eq!(
        canonicalize_project(&link).unwrap(),
        real.canonicalize().unwrap()
    );

    // a file is rejected
    let file = base.join("file");
    std::fs::write(&file, b"x").unwrap();
    assert!(canonicalize_project(&file).is_err());
}

#[test]
fn a_named_package_lifts_the_freshness_delay_and_an_unnamed_cage_carries_no_setting() {
    let get = |env: &[(String, String)], k: &str| {
        env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
    };
    // Absent, not empty: an empty list would be handed to mise as a set excluding nothing,
    // which reads in `mise settings` as a value sbx chose. Saying nothing leaves mise's own
    // default in place, which is what almost every cage wants.
    assert_eq!(
        get(
            &mise_env(false, false, &[], &[]),
            "MISE_MINIMUM_RELEASE_AGE_EXCLUDES"
        ),
        None
    );
    // The separator is a comma, and the expectation is written out rather than joined by the
    // same code the subject uses. mise is specific here: a space-, colon- or semicolon-joined
    // list is read as ONE entry that matches no tool, so a cage exempting two packages would
    // exempt neither and the failure would be silent — the package simply resolves to no
    // version, exactly as it did before the exemption was declared.
    let two = [
        "npm:@ampcode/cli".to_string(),
        "npm:@deepseek-ai/dsh".to_string(),
    ];
    assert_eq!(
        get(
            &mise_env(false, false, &two, &[]),
            "MISE_MINIMUM_RELEASE_AGE_EXCLUDES"
        ),
        Some("npm:@ampcode/cli,npm:@deepseek-ai/dsh".to_string())
    );
    // The setting rides the ambient environment, so it reaches the equip and the roll alike
    // rather than only whichever script it was written beside.
    assert!(
        mise_env(true, false, &two, &[])
            .iter()
            .any(|(k, _)| k == "MISE_MINIMUM_RELEASE_AGE_EXCLUDES"),
        "the per-project primary cage must carry it too"
    );
}

#[test]
fn an_ignored_project_mise_file_is_named_to_the_cage_s_own_mise() {
    use std::path::PathBuf;
    let get = |env: &[(String, String)], k: &str| {
        env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
    };
    // Absent, not empty: a project with nothing to skip leaves mise's own discovery alone.
    assert_eq!(
        get(
            &mise_env(false, false, &[], &[]),
            "MISE_IGNORED_CONFIG_PATHS"
        ),
        None
    );
    // Named by absolute path, because that is where the cage sees them: the project tree is
    // bound at its real path, which is the path mise reports when it reads one of these files.
    let files = [
        PathBuf::from("/home/u/proj/mise.toml"),
        PathBuf::from("/home/u/proj/.mise.toml"),
    ];
    assert_eq!(
        get(
            &mise_env(false, false, &[], &files),
            "MISE_IGNORED_CONFIG_PATHS"
        ),
        Some("/home/u/proj/mise.toml:/home/u/proj/.mise.toml".to_string())
    );
    // A path carrying the separator cannot be named in such a list. It is dropped rather than
    // joined: one file still read is a smaller failure than a list whose every entry is wrong.
    let colon = [
        PathBuf::from("/home/u/od:d/mise.toml"),
        PathBuf::from("/home/u/proj/mise.toml"),
    ];
    assert_eq!(
        get(
            &mise_env(false, false, &[], &colon),
            "MISE_IGNORED_CONFIG_PATHS"
        ),
        Some("/home/u/proj/mise.toml".to_string())
    );
}

#[test]
fn mise_env_moves_the_primary_and_adds_a_shared_fallback_for_a_global_app() {
    // A global app splits mise storage: the primary data dir moves to the per-project pool
    // (installs align with the per-project /nix store) while the app-global home's installs
    // become a read-only fallback so the agent's own tools are not rebuilt per project. Every
    // other runtime keeps the single app-global-home pool (the historical wiring).
    let get = |env: &[(String, String)], k: &str| {
        env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
    };

    let single = mise_env(false, false, &[], &[]);
    assert_eq!(
        get(&single, "MISE_DATA_DIR"),
        Some(format!("{SANDBOX_HOME}/{MISE_DATA_REL}"))
    );
    assert!(
        get(&single, "MISE_SHARED_INSTALL_DIRS").is_none(),
        "a single-pool cage has no shared-install fallback"
    );

    let split = mise_env(true, false, &[], &[]);
    assert_eq!(
        get(&split, "MISE_DATA_DIR"),
        Some(MISE_PROJECT_INCAGE.to_string()),
        "the split moves mise's primary to the per-project pool"
    );
    assert_eq!(
        get(&split, "MISE_SHARED_INSTALL_DIRS"),
        Some(format!("{SANDBOX_HOME}/{MISE_DATA_REL}/installs")),
        "the app-global installs are the read-only fallback (preserving agent-tool reuse)"
    );
    // The split never sets config/state/cache — mise derives those from $HOME (XDG), so a
    // global app's activation records and caches stay app-global. sbx must leave them unset.
    for k in ["MISE_CONFIG_DIR", "MISE_STATE_DIR", "MISE_CACHE_DIR"] {
        assert!(
            get(&split, k).is_none(),
            "{k} must stay mise's $HOME-derived default"
        );
    }
}

#[test]
fn a_btrfs_backed_store_makes_in_cage_nix_ignore_the_compression_attribute() {
    // On a compressed btrfs volume every file created under the per-project store
    // inherits the `btrfs.compression` attribute, and nix's canonicalisation —
    // which strips extended attributes — would abort a build on a read-only file.
    // The flag adds the ignore line; elsewhere the attribute cannot exist and the
    // line stays out.
    let nix_config = |on_btrfs: bool| {
        mise_env(false, on_btrfs, &[], &[])
            .into_iter()
            .find(|(k, _)| k == "NIX_CONFIG")
            .map(|(_, v)| v)
            .unwrap()
    };
    assert!(nix_config(true).contains("extra-ignored-acls = btrfs.compression"));
    assert!(!nix_config(false).contains("extra-ignored-acls"));
    // the three posture settings are carried either way
    for cfg in [nix_config(true), nix_config(false)] {
        assert!(cfg.contains("extra-experimental-features = nix-command flakes"));
        assert!(cfg.contains("sandbox = false"));
        assert!(cfg.contains("filter-syscalls = false"));
    }
}

#[test]
fn project_runtime_keys_the_per_project_mise_pool_per_project_and_app() {
    // The per-project mise pool exists only for a global app (whose home is app-global and thus
    // misaligned with the per-project /nix store); sbx run and a per-project app keep the single
    // pool. When present it is app-keyed under the project — projects/<id>/apps/<name>/mise — so
    // a tool the agent self-equips in app A stays private to app A.
    let data = Path::new("/data/sbx");
    let p1 = Path::new("/home/u/proj");
    let p2 = Path::new("/home/u/other");

    // sbx run and a per-project app: no split.
    assert!(
        project_runtime(data, p1, Runtime::ProjectDefault)
            .mise_project_src
            .is_none()
    );
    assert!(
        project_runtime(data, p1, Runtime::ProjectApp("demo-app"))
            .mise_project_src
            .is_none()
    );

    // A global app: the pool sits under projects/<id>/apps/<name>/mise (app-keyed, per-project).
    let pool = project_runtime(data, p1, Runtime::GlobalApp("demo-app"))
        .mise_project_src
        .expect("a global app has a per-project mise pool");
    let expected = data
        .join("projects")
        .join(project_id(p1))
        .join("apps")
        .join("demo-app")
        .join("mise");
    assert_eq!(pool, expected);

    // Per-project: the same global app in another project gets a distinct pool.
    let pool_p2 = project_runtime(data, p2, Runtime::GlobalApp("demo-app"))
        .mise_project_src
        .unwrap();
    assert_ne!(pool, pool_p2, "the pool is keyed per project");

    // Per-app: a different global app in the same project gets a distinct pool.
    let pool_other = project_runtime(data, p1, Runtime::GlobalApp("other-app"))
        .mise_project_src
        .unwrap();
    assert_ne!(pool, pool_other, "the pool is keyed per app (isolated)");

    // The pool nests under the project dir, so `sbx gc`/`projects rm` reclaim it with the tree.
    assert!(pool.starts_with(data.join("projects").join(project_id(p1))));
}

#[test]
fn assemble_binds_the_per_project_mise_pool_and_puts_both_shims_on_path() {
    // For a global app, assemble binds the per-project pool writable at MISE_PROJECT_INCAGE,
    // sets mise's primary there with the app-global installs as the shared fallback, and puts
    // BOTH shims dirs on PATH (the shim files must exist; the pool a tool resolves from is the
    // ambient env's, not PATH order).
    let pool = Path::new("/data/sbx/projects/abc/apps/demo-app/mise");
    let paths = SandboxPaths {
        project: Path::new("/home/u/proj"),
        home_src: Path::new("/data/sbx/apps/demo-app/home"),
        mise_project_src: Some(pool),
        passwd_src: Path::new("/data/sbx/apps/demo-app/etc/passwd"),
        group_src: Path::new("/data/sbx/apps/demo-app/etc/group"),
        mise_plugin_src: Path::new("/store/mise-plugin"),
        shell_rc_src: Path::new("/store/bashrc"),
        contract_src: Path::new("/store/egress-contract.md"),
        xdg_open_src: Path::new("/data/sbx/apps/demo-app/etc/open/xdg-open"),
        open_router_src: Path::new("/data/sbx/apps/demo-app/etc/open"),
        hosts_src: Path::new("/data/sbx/apps/demo-app/etc/hosts"),
        ssh_config_src: None,
        machine_id_src: Path::new("/data/sbx/apps/demo-app/etc/machine-id"),
        open_apps_src: None,
        open_mimeapps_src: None,
    };
    let env = [("TERM".to_string(), "xterm".to_string())];
    let overlay = Overlay {
        env: &env,
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let spec = assemble(
        &paths,
        &userland(),
        &nix_mount(),
        &overlay,
        &[],
        &[],
        NetPolicy::Shared,
        vec![OsString::from("/bin/sh")],
    )
    .expect("valid spec");

    // The pool is bound writable at the fixed cage path.
    assert!(
        spec.mounts.iter().any(|m| matches!(
            m,
            Mount::Bind { src, dest }
                if src == pool && dest == Path::new(MISE_PROJECT_INCAGE)
        )),
        "the per-project mise pool is bound writable at {MISE_PROJECT_INCAGE}"
    );

    let get = |k: &str| {
        spec.env
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(get("MISE_DATA_DIR"), Some(MISE_PROJECT_INCAGE.to_string()));
    assert_eq!(
        get("MISE_SHARED_INSTALL_DIRS"),
        Some(format!("{SANDBOX_HOME}/{MISE_DATA_REL}/installs"))
    );

    // Both shims dirs on PATH, per-project primary before the app-global fallback.
    let path = get("PATH").expect("PATH set");
    let per_project = format!("{MISE_PROJECT_INCAGE}/shims");
    let app_global = format!("{SANDBOX_HOME}/{MISE_SHIMS_REL}");
    let pp_i = path.split(':').position(|p| p == per_project);
    let ag_i = path.split(':').position(|p| p == app_global);
    assert!(pp_i.is_some(), "per-project shims on PATH");
    assert!(ag_i.is_some(), "app-global shims on PATH");
    assert!(
        pp_i < ag_i,
        "the per-project primary's shims come before the app-global fallback's"
    );
}

#[test]
fn a_single_pool_cage_neither_binds_a_per_project_mise_pool_nor_sets_a_shared_fallback() {
    // The negative: with no split (sbx run / per-project app), assemble binds no per-project
    // pool, sets no shared fallback, and leaves exactly the one app-global shims dir on PATH.
    let spec = assembled(); // its SandboxPaths carries mise_project_src: None
    assert!(
        !spec
            .mounts
            .iter()
            .any(|m| m.dest() == Path::new(MISE_PROJECT_INCAGE)),
        "no per-project mise pool is bound for a single-pool cage"
    );
    assert!(
        !spec
            .env
            .iter()
            .any(|(k, _)| k == "MISE_SHARED_INSTALL_DIRS"),
        "no shared-install fallback for a single-pool cage"
    );
    let path = spec
        .env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(
        !path
            .split(':')
            .any(|p| p == format!("{MISE_PROJECT_INCAGE}/shims")),
        "a single-pool cage has no per-project shims dir on PATH"
    );
}

#[test]
fn build_spec_registers_the_nix_plugin_under_both_pools_for_a_global_app() {
    // MISE_PLUGINS_DIR follows the primary MISE_DATA_DIR. A global app has two primaries — the
    // per-project pool (ambient, for a project `.mise.toml`/`nix:` self-equip) and the app-global
    // home (Lane-1 `mise use -g`) — so the nix: backend plugin must be registered under BOTH, or
    // whichever mise lacks it finds no nix: backend and self-equip breaks. On the critical path
    // of the fix, so proven not assumed.
    let data = TmpDir::new();
    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();

    let overlay = Overlay {
        env: &[],
        binds: &[],
        bin_paths: &[],
        timezone: DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let spec = build_spec(
        data.path(),
        project.path(),
        Runtime::GlobalApp("demo-app"),
        &userland(),
        &nix_mount(),
        &overlay,
        &[],
        NetPolicy::Shared,
        "",
        &Default::default(),
        crate::sandbox::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        vec![OsString::from("/bin/sh")],
    )
    .expect("build spec");

    // The spec binds the pool, so the registration dir is reachable in-cage.
    assert!(
        spec.mounts
            .iter()
            .any(|m| m.dest() == Path::new(MISE_PROJECT_INCAGE))
    );

    let id = project_id(&project.path().canonicalize().unwrap());
    let per_project_link = data
        .path()
        .join("projects")
        .join(&id)
        .join("apps")
        .join("demo-app")
        .join("mise")
        .join("plugins")
        .join(crate::sandbox::miseplugin::PLUGIN_NAME);
    assert_eq!(
        std::fs::read_link(&per_project_link).unwrap(),
        Path::new(crate::sandbox::miseplugin::INCAGE_DIR),
        "the nix: plugin is registered under the per-project primary"
    );
    // and ALSO under the app-global home's mise plugins (Lane-1 `mise use -g` runs there).
    let home_link = data
        .path()
        .join("apps")
        .join("demo-app")
        .join("home")
        .join(MISE_DATA_REL)
        .join("plugins")
        .join(crate::sandbox::miseplugin::PLUGIN_NAME);
    assert_eq!(
        std::fs::read_link(&home_link).unwrap(),
        Path::new(crate::sandbox::miseplugin::INCAGE_DIR),
        "the nix: plugin is also registered under the app-global home for a global app"
    );
}
