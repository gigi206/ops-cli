//! Building a concrete [`SandboxSpec`] for a project: the zones (hidden /
//! read-only / writable), a synthetic identity, and the hermetic-FHS userland
//! resolved elsewhere.
//!
//! The assembly itself ([`assemble`]) is pure — it turns already-resolved paths
//! into mounts and environment — so it is unit-testable without touching nix or
//! the filesystem. The surrounding I/O (canonicalising the project root,
//! materialising the synthetic `/etc` files, reading the host uid) is kept in
//! thin wrappers around it.
//!
//! Integrity note: the synthetic `/etc/passwd`/`/etc/group` are bound read-only,
//! but a read-only bind only freezes the *mountpoint*, not the *inode*. So the
//! files must live **outside** every read-write bind — otherwise a same-uid
//! process could rewrite the inode through that read-write alias and the change
//! would surface at the read-only `/etc/passwd`. [`project_runtime`] places them
//! in a sibling of the writable home for exactly this reason.

use super::spec::{Mount, NetPolicy, SandboxSpec, SpecError};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// The sandbox's `$HOME` inside the sandbox. Distinct from the host's, and the
/// passwd entry and the writable home bind all agree on it.
const SANDBOX_HOME: &str = "/home/sandbox";

/// The in-sandbox shell path. A hermetic sandbox has no host `/usr`, so `/bin/sh`
/// is synthesised as a symlink to the nix shell; scripts and `system(3)` resolve
/// here, and the synthetic passwd points its shell field at the same path.
const SANDBOX_SHELL: &str = "/bin/sh";

/// The resolved hermetic userland (provided by the nix resolver). A nix binary
/// finds its own libraries by absolute RPATH, so a read-only `/nix` suffices for
/// it and it is never steered by the sandbox's library search. *Foreign* binaries
/// (npm/pip artefacts) instead hard-code the standard interpreter `/lib64/ld-linux`;
/// the sandbox binds a small **nix-ld** shim there, which reads `NIX_LD` (the real
/// base loader) and `NIX_LD_LIBRARY_PATH` (the base libraries) and re-execs the
/// real loader for them. Crucially the base libraries are exposed *only* this way,
/// not on `LD_LIBRARY_PATH`: that keeps a nix tool pinned to a different glibc on
/// its own libc (via RPATH) instead of being forced onto the base one, which would
/// skew its ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Userland {
    /// The logical store roots of the base userland (glibc, the gcc runtime, the
    /// shell, coreutils, the nix-ld shim) — the closures a project's own store must
    /// carry to run the base. Surfaced explicitly by the resolver rather than
    /// reconstructed from the scattered sub-paths below, so none is forgotten.
    pub(crate) base_roots: Vec<PathBuf>,
    /// The nix-ld shim file, bound at the standard interpreter path so a foreign
    /// binary that hard-codes it is intercepted by it.
    pub(crate) interp_src: PathBuf,
    /// ops's own CA bundle (`cacert`'s `ca-bundle.crt`), bound read-only at the standard
    /// certificate paths so the cage's TLS trusts a known set of roots without depending on
    /// the host. A physical bind source (it backs a mount), unlike the logical store paths
    /// elsewhere on this type.
    pub(crate) ca_bundle_src: PathBuf,
    /// Where the interpreter shim is exposed (`/lib64/ld-linux-x86-64.so.2`).
    pub(crate) interp_dest: PathBuf,
    /// The real base loader the shim re-execs for a foreign binary, as the in-sandbox
    /// logical path it carries in `NIX_LD`.
    pub(crate) base_loader: PathBuf,
    /// Base library directories the shim exposes to foreign binaries via
    /// `NIX_LD_LIBRARY_PATH` — never `LD_LIBRARY_PATH` (see the type note).
    pub(crate) foreign_lib_paths: Vec<PathBuf>,
    /// Directories joined into `PATH`.
    pub(crate) bin_paths: Vec<PathBuf>,
    /// The shell binary `/bin/sh` links to and the default command runs.
    pub(crate) shell_bin: PathBuf,
    /// The in-cage egress forwarder (`socat`), as an in-sandbox logical path. Invoked
    /// by absolute path from the allowlist-posture wrapper; off `PATH` and untouched by
    /// other postures.
    pub(crate) socat_bin: PathBuf,
}

/// One explicit bind injected by the launcher after the structural mounts (so it is
/// neither shadowed by, nor shadows, them): a host source exposed at a distinct cage
/// destination. Used for the network-allowlist machinery — the bound egress socket and
/// the proxy's CA certificate — whose destinations are ops's, not the project's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtraBind {
    /// Host path bound into the cage.
    pub(crate) src: PathBuf,
    /// Cage path it appears at.
    pub(crate) dest: PathBuf,
    /// Read-write when true, read-only otherwise.
    pub(crate) writable: bool,
}

/// The host `nix/` tree to expose at `/nix`, and whether the cage may write to it.
///
/// A read-only mount of the shared store protects its integrity by freezing the
/// mountpoint. A *writable* mount is a per-project store seeded from the shared one:
/// the cage may write into `/nix` (an agent self-equipping its toolchain), and those
/// writes land only in that project's own physical copy — the shared store is never
/// in the cage, so its integrity is protected by physical separation rather than by
/// the read-only bind. Which store backs the cage is ops's decision, never a
/// configurable field, so an untrusted project cannot widen its own access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NixMount {
    /// The host `nix/` directory bound at `/nix`.
    pub(crate) src: PathBuf,
    /// Whether `/nix` is bound read-write (a per-project store) or read-only (the
    /// shared store).
    pub(crate) writable: bool,
}

/// The project's overlay onto the base sandbox: the configuration-supplied extra
/// environment, read-only host binds, and tool `bin` directories to prepend to
/// `PATH`. Grouped so the assembler and its constructor take one overlay rather
/// than three parallel slices.
pub(crate) struct Overlay<'a> {
    /// Extra environment, upserted over the structural defaults.
    pub(crate) env: &'a [(String, String)],
    /// Extra host paths to bind read-only (emitted before the structural mounts,
    /// so a colliding structural mount shadows them).
    pub(crate) ro_binds: &'a [PathBuf],
    /// Tool `bin` directories, prepended to `PATH` ahead of the base userland.
    pub(crate) bin_paths: &'a [PathBuf],
}

/// Host-side paths backing one project's sandbox. The writable home and the
/// read-only synthetic `/etc` are deliberately *siblings*: nothing read-write
/// contains the identity files (see the module integrity note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectRuntime {
    /// The sandbox `$HOME` on the host, bound read-write.
    pub(crate) home_src: PathBuf,
    /// Directory holding the synthetic `passwd`/`group`, bound read-only.
    pub(crate) etc_dir: PathBuf,
}

/// The synthetic sandbox identity. Same uid/gid as the host (the same-uid model),
/// but a synthetic name and no other host accounts — uid resolution works
/// without leaking `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) user: String,
}

/// Host-side locations of one sandbox's mount sources, passed to [`assemble`].
struct SandboxPaths<'a> {
    /// Canonical project root; bound read-write at the same absolute path.
    project: &'a Path,
    /// Host sandbox home; bound read-write at [`SANDBOX_HOME`].
    home_src: &'a Path,
    /// Synthetic identity files; bound read-only at `/etc/passwd`/`/etc/group`.
    passwd_src: &'a Path,
    group_src: &'a Path,
    /// Staged mise `nix:` backend plugin; bound read-only at the in-cage plugin dir.
    mise_plugin_src: &'a Path,
    /// Synthetic interactive-shell rc; bound read-only at [`SHELL_RC_INCAGE`].
    shell_rc_src: &'a Path,
}

/// Assemble a [`SandboxSpec`] from already-resolved host paths. Pure: no I/O, no
/// ambient state — every mount and variable derives from the arguments. This is
/// the audited core; [`build_spec`] feeds it real paths.
fn assemble(
    paths: &SandboxPaths,
    userland: &Userland,
    nix: &NixMount,
    overlay: &Overlay,
    extra_binds: &[ExtraBind],
    net: NetPolicy,
    cmd: Vec<OsString>,
) -> Result<SandboxSpec, SpecError> {
    // Config-declared read-only binds come first, so any structural mount below
    // shadows a colliding one — a config bind can never displace `/nix`, the
    // synthetic `/etc/passwd`/`group`, the loader, or the project itself.
    let mut mounts: Vec<Mount> = overlay
        .ro_binds
        .iter()
        .map(|src| Mount::RoBind {
            src: src.clone(),
            dest: src.clone(),
        })
        .collect();

    // Zone 1 — the store at `/nix`, read-write for a per-project store the cage may
    // write into, read-only for the shared store. It precedes every other structural
    // mount, so a config bind (emitted above) can never displace it.
    let nix_dest = PathBuf::from("/nix");
    mounts.push(if nix.writable {
        Mount::Bind {
            src: nix.src.clone(),
            dest: nix_dest,
        }
    } else {
        Mount::RoBind {
            src: nix.src.clone(),
            dest: nix_dest,
        }
    });

    mounts.extend([
        // Zone 1 — read-only userland: the nix-ld interpreter shim a foreign binary
        // is routed through (binaries otherwise resolve their libraries from `/nix`
        // by RPATH), then the synthetic `/bin/sh`.
        Mount::RoBind {
            src: userland.interp_src.clone(),
            dest: userland.interp_dest.clone(),
        },
        Mount::Symlink {
            target: userland.shell_bin.clone(),
            dest: PathBuf::from(SANDBOX_SHELL),
        },
        // Zone 1 — the embedded mise "nix" backend plugin, read-only: an agent's
        // in-cage mise resolves it (via a symlink in the writable mise data dir) to
        // self-equip the project's `nix:` tools. Read-only so the agent cannot rewrite
        // ops's own plugin code.
        Mount::RoBind {
            src: paths.mise_plugin_src.to_path_buf(),
            dest: PathBuf::from(super::miseplugin::INCAGE_DIR),
        },
        // Zone 1 — the synthetic interactive-shell rc, read-only: `ops shell` points
        // bash's `--rcfile` at it to activate mise. Sourced from outside every writable
        // mount, so the agent cannot rewrite its own shell init.
        Mount::RoBind {
            src: paths.shell_rc_src.to_path_buf(),
            dest: PathBuf::from(SHELL_RC_INCAGE),
        },
        // Zone 1 — synthetic identity (no host accounts leaked).
        Mount::RoBind {
            src: paths.passwd_src.to_path_buf(),
            dest: PathBuf::from("/etc/passwd"),
        },
        Mount::RoBind {
            src: paths.group_src.to_path_buf(),
            dest: PathBuf::from("/etc/group"),
        },
        // Zone 1 — TLS: ops's own CA bundle from its store rather than the host, so HTTPS
        // trust is hermetic. Bound at the two standard certificate paths a Linux toolchain
        // looks for by default — the NixOS `ca-bundle.crt` (nix's own libcurl) and the
        // Debian/OpenSSL `ca-certificates.crt` (a tool that reads the system store and does
        // not honor the CA-bundle env variables, e.g. mise's HTTP client) — both naming the
        // same bundle. This replaces a bind of the host's `/etc/ssl`, so the cage no longer
        // depends on — nor sees — the host's certificates. DNS stays host-provided for a
        // network-sharing shell (absent is fine; an isolated posture ignores it).
        Mount::RoBind {
            src: userland.ca_bundle_src.clone(),
            dest: PathBuf::from(CAGE_CA_BUNDLE),
        },
        Mount::RoBind {
            src: userland.ca_bundle_src.clone(),
            dest: PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
        },
        Mount::RoBindTry {
            src: PathBuf::from("/etc/resolv.conf"),
            dest: PathBuf::from("/etc/resolv.conf"),
        },
        // Fresh kernel views and a private tmp.
        Mount::Proc {
            dest: PathBuf::from("/proc"),
        },
        Mount::Dev {
            dest: PathBuf::from("/dev"),
        },
        Mount::Tmpfs {
            dest: PathBuf::from("/tmp"),
        },
        // Zone 2 — the writable work surface: a private home, and the project at
        // its own absolute path (tool compatibility; code is not a secret).
        Mount::Bind {
            src: paths.home_src.to_path_buf(),
            dest: PathBuf::from(SANDBOX_HOME),
        },
        Mount::Bind {
            src: paths.project.to_path_buf(),
            dest: paths.project.to_path_buf(),
        },
    ]);

    // Launcher-injected binds, emitted last so they neither shadow a structural mount nor
    // are shadowed by one. Their destinations are ops's (the egress socket under the tmpfs,
    // the proxy CA under `/opt/ops`), never a project path; their parents are already
    // mounted above (the tmpfs for the socket, the userland binds' `/opt/ops`).
    mounts.extend(extra_binds.iter().map(|b| {
        if b.writable {
            Mount::Bind {
                src: b.src.clone(),
                dest: b.dest.clone(),
            }
        } else {
            Mount::RoBind {
                src: b.src.clone(),
                dest: b.dest.clone(),
            }
        }
    }));

    // The sandbox PATH: the project's declared tools first, then mise's shims, then
    // the base userland, so a declared tool wins over an agent-activated one, which
    // wins over the base. A tool the in-cage mise has activated (`mise use`) gets a
    // shim in the shims dir, so a later `ops run -- <tool>` resolves it. `/bin/sh` and
    // the loader are wired by absolute path, not PATH, so prepending here never weakens
    // them.
    let mut path_dirs = overlay.bin_paths.to_vec();
    path_dirs.push(PathBuf::from(format!("{SANDBOX_HOME}/{MISE_SHIMS_REL}")));
    path_dirs.extend(userland.bin_paths.iter().cloned());

    // Structural environment first, then the extra (passthrough + config) entries
    // upserted over it: a trusted config's override wins, while an untrusted one —
    // already stripped of reserved keys upstream — can only add.
    //
    // The base glibc is offered to foreign binaries through the nix-ld shim
    // (`NIX_LD`/`NIX_LD_LIBRARY_PATH`), deliberately *not* on `LD_LIBRARY_PATH`: a
    // global `LD_LIBRARY_PATH` is searched ahead of a nix binary's own RPATH, so it
    // would force a tool pinned to another glibc onto the base one and skew its ABI.
    let mut env = vec![
        ("HOME".to_string(), SANDBOX_HOME.to_string()),
        ("PATH".to_string(), join_paths(&path_dirs)),
        (
            "NIX_LD".to_string(),
            userland.base_loader.to_string_lossy().into_owned(),
        ),
        (
            "NIX_LD_LIBRARY_PATH".to_string(),
            join_paths(&userland.foreign_lib_paths),
        ),
    ];
    env.extend(mise_env());
    for (key, val) in overlay.env {
        upsert_env(&mut env, key, val);
    }

    SandboxSpec::new(paths.project.to_path_buf(), mounts, env, net, cmd)
}

/// mise's data directory inside the cage, relative to the sandbox `$HOME`. The
/// in-cage mise keeps its plugins, installs and state here — under the writable
/// per-project home, so they persist across launches and never touch the host's
/// real mise state. Also where the plugin registration symlink is placed.
const MISE_DATA_REL: &str = ".local/share/mise";

/// mise's shims directory inside the cage, relative to the sandbox `$HOME`. mise
/// writes a shim here for every tool it has *activated* (`mise use`); putting this
/// directory on PATH is mise's documented mechanism for making those tools available
/// without a shell hook — exactly `ops run -- <cmd>`, which execs the command directly
/// with no shell to activate. The dir need not exist yet (an empty project has none);
/// a missing PATH entry is simply ignored.
const MISE_SHIMS_REL: &str = ".local/share/mise/shims";

/// Where the synthetic interactive-shell rc is bound read-only. `ops shell` starts
/// bash with `--rcfile` pointing here, so mise is activated in the interactive shell —
/// mise's documented interactive mechanism (a prompt hook that manages PATH/env for the
/// project's activated tools). `ops run` does not use it; its tools come from the shims
/// dir on PATH. Under `/opt/ops`, beside the mise plugin, colliding with no structural
/// mount.
pub(crate) const SHELL_RC_INCAGE: &str = "/opt/ops/bashrc";

/// The synthetic interactive-shell rc: source the home's own `.bashrc` if the agent has
/// written one, then activate mise so its activated tools manage PATH/env. Static (no
/// per-project data, so the same bytes back every cage), bound read-only from outside
/// every writable mount, so the agent cannot rewrite what its own shell sources.
const SHELL_RC_CONTENTS: &str = "\
[ -r \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\n\
command -v mise >/dev/null 2>&1 && eval \"$(mise activate bash)\"\n";

/// The structural environment that turns the cage's mise into a working
/// self-equip front-end. Lowest precedence (a trusted config may still override
/// it, which only harms that project's own in-cage builds):
/// - `MISE_DATA_DIR` anchors mise under the writable home, where ops has placed
///   the `nix:` backend plugin registration;
/// - `MISE_EXPERIMENTAL` enables mise's custom backends, the gate on `nix:`;
/// - `MISE_YES` auto-confirms prompts so a non-interactive `mise install` never
///   blocks;
/// - `NIX_CONFIG` carries three settings (newline-separated): it *appends* the
///   experimental features the plugin's `nix build` (a flake reference) needs —
///   `extra-`, so it adds to nix's compiled defaults rather than replacing them —
///   and it forces `sandbox = false` + `filter-syscalls = false`. The cage's
///   seccomp filter denies the mount/namespace syscalls nix's *inner* build
///   sandbox would use, so an in-cage build must run without it (the cage is the
///   boundary, not nix's inner sandbox); setting it here makes that deterministic
///   rather than relying on nix's silent fallback. These keys are on the
///   untrusted-only env denylist, so only ops sets them.
fn mise_env() -> Vec<(String, String)> {
    vec![
        (
            "MISE_DATA_DIR".to_string(),
            format!("{SANDBOX_HOME}/{MISE_DATA_REL}"),
        ),
        ("MISE_EXPERIMENTAL".to_string(), "1".to_string()),
        ("MISE_YES".to_string(), "1".to_string()),
        (
            "NIX_CONFIG".to_string(),
            "extra-experimental-features = nix-command flakes\n\
             sandbox = false\n\
             filter-syscalls = false"
                .to_string(),
        ),
    ]
}

/// Where ops's CA bundle appears in the cage. The cacert tree is bound at `/etc/ssl`
/// (replacing the host's), so the bundle sits at the path nix and OpenSSL look for by
/// default.
const CAGE_CA_BUNDLE: &str = "/etc/ssl/certs/ca-bundle.crt";

/// The CA-bundle environment, naming ops's own bundle so the cage's toolchains trust it
/// without depending on the host having certificates. It uses the exact key set the egress
/// proxy injects ([`super::egress::CA_FILE_ENV_KEYS`]) — one source of truth — so under a
/// network allowlist the proxy's per-session CA, layered *after* this by the launcher,
/// overrides every key (there the cage must trust the MITM leaf, not these roots). For the
/// shared and isolated postures this is the trust anchor. Carried in the overlay rather than
/// the structural defaults so it sits above host passthrough (which is not denylist-filtered)
/// yet below the egress wiring.
pub(crate) fn cacert_env() -> Vec<(String, String)> {
    super::egress::CA_FILE_ENV_KEYS
        .iter()
        .map(|k| ((*k).to_string(), CAGE_CA_BUNDLE.to_string()))
        .collect()
}

/// Set `key` to `val`, overriding an existing entry so a config-supplied value
/// wins over the structural default at the same key.
fn upsert_env(env: &mut Vec<(String, String)>, key: &str, val: &str) {
    match env.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = val.to_string(),
        None => env.push((key.to_string(), val.to_string())),
    }
}

/// Join store directories into a `:`-separated search path. The inputs are nix
/// store paths (ASCII), so the lossy conversion is exact.
fn join_paths(dirs: &[PathBuf]) -> String {
    dirs.iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join(":")
}

/// The synthetic `/etc/passwd`: the sandbox user (same uid/gid as the host) plus
/// `nobody`. No other host account appears.
fn passwd_contents(id: &Identity, home: &str, shell: &str) -> String {
    format!(
        "{user}:x:{uid}:{gid}:{user}:{home}:{shell}\n\
         nobody:x:65534:65534:nobody:/:/sbin/nologin\n",
        user = id.user,
        uid = id.uid,
        gid = id.gid,
    )
}

/// The synthetic `/etc/group`: the sandbox group plus `nogroup`.
fn group_contents(id: &Identity) -> String {
    format!(
        "{user}:x:{gid}:\nnogroup:x:65534:\n",
        user = id.user,
        gid = id.gid,
    )
}

/// Which persistent runtime a launch uses — the writable `$HOME` and its sibling synthetic
/// `/etc`. `ops run`/`ops shell` use the project's shared default; an app gets a dedicated,
/// persistent home so its config, login state, and history never bleed into the project shell
/// or another app. An app's home is either shared across projects (`GlobalApp`, one identity
/// everywhere) or keyed per-project (`ProjectApp`, isolated per project).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Runtime<'a> {
    /// The project's default shared home — `ops run` and `ops shell`.
    ProjectDefault,
    /// `ops app <name>` with one home per app, shared across every project.
    GlobalApp(&'a str),
    /// `ops app <name>` with a home per (project, app).
    ProjectApp(&'a str),
}

/// Host-side runtime paths for `project` under ops's data directory, for the given
/// [`Runtime`]. The home and the synthetic `/etc` are always siblings so the latter sits
/// outside every read-write bind (module integrity note). An app name is a validated single
/// path component (the config app-name check), so joining it cannot traverse out of the data
/// directory.
fn project_runtime(data_dir: &Path, project: &Path, runtime: Runtime) -> ProjectRuntime {
    let project_base = || data_dir.join("projects").join(project_id(project));
    let base = match runtime {
        Runtime::ProjectDefault => project_base(),
        // A global app's home is project-independent — keyed only by the app name, so the same
        // identity is reused in every project.
        Runtime::GlobalApp(name) => data_dir.join("apps").join(name),
        // A per-project app's home nests under the project, isolating its state per project.
        Runtime::ProjectApp(name) => project_base().join("apps").join(name),
    };
    ProjectRuntime {
        home_src: base.join("home"),
        etc_dir: base.join("etc"),
    }
}

/// A stable, collision-resistant directory name for a canonical project path.
fn project_id(project: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    project.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// The stable per-project identity ops keys runtime state on. The writable home,
/// the synthetic identity, and a project's garbage-collection roots all derive from
/// it, so housekeeping can reclaim a project's tools alongside the rest of its
/// runtime. Canonicalises first, so a relative or symlinked `cwd` maps to the same
/// identity as the real path (the same pin [`canonicalize_project`] applies to the
/// bind source).
pub(crate) fn project_runtime_id(cwd: &Path) -> io::Result<String> {
    Ok(project_id(&canonicalize_project(cwd)?))
}

/// Resolve `path` to a real, existing directory, following symlinks in the host
/// namespace. Canonicalising up front *narrows* the bind-source TOCTOU window:
/// the source is pinned to its real location, so a later project-controlled
/// symlink swap no longer trivially redirects the bind. It is not an absolute
/// guarantee — a parent component swapped between this call and the actual bind
/// still races — but the broader confinement of arbitrary, config-declared bind
/// paths is enforced where those binds are introduced.
fn canonicalize_project(path: &Path) -> io::Result<PathBuf> {
    let canon = path.canonicalize()?;
    if !canon.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("project path is not a directory: {}", canon.display()),
        ));
    }
    Ok(canon)
}

/// The host identity to reflect into the sandbox (same-uid model). Reads ambient
/// process state, so it is kept out of the pure assembly.
fn current_identity() -> Identity {
    // SAFETY: `getuid`/`getgid` always succeed and only read the caller's ids.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    Identity {
        uid,
        gid,
        user: "sandbox".to_string(),
    }
}

/// Materialise the synthetic `passwd`/`group` into `etc_dir` (created owner-only)
/// and return their paths, ready to bind read-only. The shell field matches the
/// in-sandbox `/bin/sh`, and `$HOME` matches the writable home bind.
fn materialize_etc(etc_dir: &Path, id: &Identity) -> io::Result<(PathBuf, PathBuf)> {
    use std::fs::{DirBuilder, Permissions};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(etc_dir)?;
    std::fs::set_permissions(etc_dir, Permissions::from_mode(0o700))?;

    let passwd = etc_dir.join("passwd");
    let group = etc_dir.join("group");
    std::fs::write(&passwd, passwd_contents(id, SANDBOX_HOME, SANDBOX_SHELL))?;
    std::fs::write(&group, group_contents(id))?;
    Ok((passwd, group))
}

/// Build a launch-ready [`SandboxSpec`] for `cwd` under ops's `data_dir`. This is
/// the I/O orchestration around the pure [`assemble`]: it canonicalises the
/// project root (pinning the bind source — see the module integrity note),
/// materialises the per-project writable home and read-only synthetic identity,
/// and hands resolved paths to `assemble`. The persistent runtime directories
/// are created owner-only; they outlive the process by design (later housekeeping
/// reclaims them).
///
/// `cwd` is bound **read-write at its own path** as the work surface — correct
/// when the user chose the directory. This is the shared chokepoint where that
/// surface is granted, so a caller launching an *untrusted* actor must first
/// confine the project root (e.g. refuse `$HOME` or `/`); otherwise `cd ~` would
/// expose the whole home read-write.
// The I/O orchestrator threads resolved inputs into the pure `assemble`; the grouping
// discipline (`SandboxPaths`) keeps that *audited* core at the argument limit, so the
// wrapper carrying one more resolved slice is the right place to absorb it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_spec(
    data_dir: &Path,
    cwd: &Path,
    runtime: Runtime,
    userland: &Userland,
    nix: &NixMount,
    overlay: &Overlay,
    extra_binds: &[ExtraBind],
    net: NetPolicy,
    cmd: Vec<OsString>,
) -> io::Result<SandboxSpec> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;

    let project = canonicalize_project(cwd)?;
    let rt = project_runtime(data_dir, &project, runtime);

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&rt.home_src)?;
    let (passwd, group) = materialize_etc(&rt.etc_dir, &current_identity())?;

    // Materialize the synthetic interactive-shell rc beside the synthetic identity
    // (outside every writable mount, so it has no writable alias the agent could use to
    // rewrite it); `ops shell` binds it read-only and points bash's `--rcfile` at it.
    let shell_rc = rt.etc_dir.join("bashrc");
    std::fs::write(&shell_rc, SHELL_RC_CONTENTS)?;

    // Materialize the embedded mise `nix:` backend plugin (read-only, content-keyed,
    // shared across projects) and register it for this cage's mise: a symlink in the
    // writable mise data dir pointing at the read-only in-cage plugin. Both run on
    // every launch so an ops upgrade (a changed embedded tree) re-stages and re-points.
    let mise_plugin = super::miseplugin::stage(data_dir)?;
    super::miseplugin::register(&rt.home_src.join(MISE_DATA_REL).join("plugins"))?;

    let paths = SandboxPaths {
        project: &project,
        home_src: &rt.home_src,
        passwd_src: &passwd,
        group_src: &group,
        mise_plugin_src: &mise_plugin,
        shell_rc_src: &shell_rc,
    };
    assemble(&paths, userland, nix, overlay, extra_binds, net, cmd).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid sandbox spec: {e:?}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

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
            socat_bin: PathBuf::from("/store/socat/bin/socat"),
        }
    }

    /// A read-only `/nix` from a stand-in shared store — what the assembler binds
    /// when the cage consumes the shared store directly (the per-project writable
    /// store is supplied by the launcher).
    fn nix_mount() -> NixMount {
        NixMount {
            src: PathBuf::from("/data/ops/store/nix"),
            writable: false,
        }
    }

    fn assembled() -> SandboxSpec {
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/ops/projects/abc/home"),
            passwd_src: Path::new("/data/ops/projects/abc/etc/passwd"),
            group_src: Path::new("/data/ops/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
        };
        let env = [("TERM".to_string(), "xterm".to_string())];
        let overlay = Overlay {
            env: &env,
            ro_binds: &[],
            bin_paths: &[],
        };
        assemble(
            &paths,
            &userland(),
            &nix_mount(),
            &overlay,
            &[],
            NetPolicy::Shared,
            vec![OsString::from("/bin/sh")],
        )
        .expect("valid spec")
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
        assert_eq!(text[nix - 1], "/data/ops/store/nix");
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
        assert_eq!(text[passwd - 1], "/data/ops/projects/abc/etc/passwd");
        assert_eq!(text[passwd - 2], "--ro-bind");

        // TLS is hermetic — the CA bundle is a firm bind of ops's cacert (not the host's);
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
    fn the_cage_trusts_ops_own_ca_bundle_not_the_host() {
        // ops's CA bundle is bound at both standard certificate paths (the NixOS and the
        // Debian/OpenSSL conventions), so the cage's TLS trust comes from ops's store rather
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
                "{dest} must be ops's cacert bundle, not the host's"
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
    fn cacert_env_names_ops_bundle_under_every_ca_key() {
        // One source of truth: the keys ops sets equal the egress key set, each pointing at
        // ops's in-cage bundle.
        let env = cacert_env();
        assert_eq!(env.len(), super::super::egress::CA_FILE_ENV_KEYS.len());
        for (k, v) in &env {
            assert!(
                super::super::egress::CA_FILE_ENV_KEYS.contains(&k.as_str()),
                "unexpected CA key {k}"
            );
            assert_eq!(v, CAGE_CA_BUNDLE, "{k} must name ops's bundle");
        }
    }

    #[test]
    fn assemble_builds_a_hermetic_environment() {
        let spec = assembled();
        let argv = super::super::argv::to_argv(&spec);
        let joined = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        let path_i = joined.iter().position(|s| s == "PATH").unwrap();
        // mise's shims dir sits between the (here empty) declared tools and the base
        // userland, so an agent-activated tool surfaces ahead of base on a name clash.
        assert_eq!(
            joined[path_i + 1],
            "/home/sandbox/.local/share/mise/shims:/store/bash/bin:/store/coreutils/bin"
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
    }

    #[test]
    fn assemble_emits_launcher_extra_binds_after_the_structural_mounts() {
        // The egress machinery binds (the socket, the CA) must land *after* the tmpfs, so the
        // socket sits on a writable mountpoint, and carry their declared mode.
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/ops/projects/abc/home"),
            passwd_src: Path::new("/data/ops/projects/abc/etc/passwd"),
            group_src: Path::new("/data/ops/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
        };
        let overlay = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &[],
        };
        let extra = [
            ExtraBind {
                src: PathBuf::from("/data/ops/egress/proxy.sock"),
                dest: PathBuf::from("/tmp/ops-egress.sock"),
                writable: true,
            },
            ExtraBind {
                src: PathBuf::from("/data/ops/egress/ca.pem"),
                dest: PathBuf::from("/opt/ops/egress-ca.pem"),
                writable: false,
            },
        ];
        let spec = assemble(
            &paths,
            &userland(),
            &nix_mount(),
            &overlay,
            &extra,
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
            .position(|s| s == "/tmp/ops-egress.sock")
            .unwrap();
        assert_eq!(text[sock - 1], "/data/ops/egress/proxy.sock");
        assert_eq!(text[sock - 2], "--bind");
        // the CA is a read-only bind
        let ca = text
            .iter()
            .position(|s| s == "/opt/ops/egress-ca.pem")
            .unwrap();
        assert_eq!(text[ca - 1], "/data/ops/egress/ca.pem");
        assert_eq!(text[ca - 2], "--ro-bind");
        // both come after the /tmp tmpfs — the socket needs a writable mountpoint under it
        let tmpfs = text.iter().position(|s| s == "--tmpfs").unwrap();
        assert!(
            sock > tmpfs && ca > tmpfs,
            "extra binds must follow the tmpfs"
        );
    }

    /// Assemble with explicit config-supplied extra env, read-only binds, and
    /// prepended tool `bin` directories.
    fn assemble_with(
        extra_env: &[(String, String)],
        extra_ro_binds: &[PathBuf],
        extra_bin_paths: &[PathBuf],
    ) -> SandboxSpec {
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/ops/projects/abc/home"),
            passwd_src: Path::new("/data/ops/projects/abc/etc/passwd"),
            group_src: Path::new("/data/ops/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
        };
        let overlay = Overlay {
            env: extra_env,
            ro_binds: extra_ro_binds,
            bin_paths: extra_bin_paths,
        };
        assemble(
            &paths,
            &userland(),
            &nix_mount(),
            &overlay,
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

    #[test]
    fn a_config_env_value_overrides_the_structural_default() {
        // a trusted config can set PATH; its value wins, and the key is not emitted
        // twice (the structural default is replaced, not appended to).
        let spec = assemble_with(&[("PATH".to_string(), "/opt/bin".to_string())], &[], &[]);
        let argv = argv_strings(&spec);
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
        let argv = argv_strings(&spec);
        let path_i = argv.iter().position(|s| s == "PATH").unwrap();
        // declared tools first, then mise's shims, then the base userland
        assert_eq!(
            argv[path_i + 1],
            "/nix/store/node/bin:/nix/store/python/bin:/home/sandbox/.local/share/mise/shims:/store/bash/bin:/store/coreutils/bin"
        );
    }

    #[test]
    fn the_shell_rc_is_bound_read_only_for_mise_activation() {
        // `ops shell` points bash's `--rcfile` at this path; it must be a read-only bind
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

    #[test]
    fn a_config_bind_precedes_the_structural_mounts() {
        // the extra bind is emitted first, so a colliding structural mount shadows
        // it — a config bind can never displace the store or the synthetic identity.
        let spec = assemble_with(&[], &[PathBuf::from("/opt/data")], &[]);
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
    fn an_empty_config_adds_nothing() {
        // the additive promise: no config changes nothing — the first bind is still
        // the store, and the only environment is the structural set. That set carries
        // the always-on mise self-equip variables (the cage always lets an agent drive
        // mise); they come from the assembler, not the config, so an empty config still
        // adds nothing of its own.
        let argv = argv_strings(&assemble_with(&[], &[], &[]));
        let first_ro = argv.iter().position(|s| s == "--ro-bind").unwrap();
        assert_eq!(
            argv[first_ro + 1],
            "/data/ops/store/nix",
            "no extra bind may precede the store"
        );
        assert_eq!(argv[first_ro + 2], "/nix", "the store binds at /nix");
        let setenvs: Vec<&str> = argv
            .iter()
            .enumerate()
            .filter(|(_, s)| *s == "--setenv")
            .map(|(i, _)| argv[i + 1].as_str())
            .collect();
        assert_eq!(
            setenvs,
            [
                "HOME",
                "PATH",
                "NIX_LD",
                "NIX_LD_LIBRARY_PATH",
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
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/ops/projects/abc/home"),
            passwd_src: Path::new("/data/ops/projects/abc/etc/passwd"),
            group_src: Path::new("/data/ops/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
        };
        let nix = NixMount {
            src: PathBuf::from("/data/ops/projects/abc/store/nix"),
            writable: true,
        };
        let overlay = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &[],
        };
        let spec = assemble(
            &paths,
            &userland(),
            &nix,
            &overlay,
            &[],
            NetPolicy::Shared,
            vec![OsString::from("/bin/sh")],
        )
        .expect("valid spec");
        let argv = argv_strings(&spec);

        // a read-write bind: `--bind <per-project store> /nix`, never `--ro-bind`
        let nix_pos = argv.iter().position(|s| s == "/nix").unwrap();
        assert_eq!(argv[nix_pos - 1], "/data/ops/projects/abc/store/nix");
        assert_eq!(argv[nix_pos - 2], "--bind");
    }

    #[test]
    fn synthetic_etc_lives_outside_the_writable_home() {
        // The core integrity property holds for every runtime scope: the read-only identity
        // files have no read-write alias inside the sandbox.
        let data = Path::new("/data/ops");
        let project = Path::new("/home/u/proj");
        for runtime in [
            Runtime::ProjectDefault,
            Runtime::GlobalApp("claude"),
            Runtime::ProjectApp("claude"),
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
        let data = Path::new("/data/ops");
        let p1 = Path::new("/home/u/proj");
        let p2 = Path::new("/home/u/other");
        let home = |project: &Path, rt| project_runtime(data, project, rt).home_src;

        let default = home(p1, Runtime::ProjectDefault);
        let global_a = home(p1, Runtime::GlobalApp("claude"));
        let global_b = home(p1, Runtime::GlobalApp("opencode"));
        let proj_a = home(p1, Runtime::ProjectApp("claude"));

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
        assert_eq!(global_a, home(p2, Runtime::GlobalApp("claude")));
        assert_ne!(proj_a, home(p2, Runtime::ProjectApp("claude")));
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
}

/// The whole constructor chain — resolve the real userland, materialise the
/// synthetic identity, assemble, and feed the *generated* argv to real bwrap —
/// must launch a working hermetic shell. The unit tests above check the argv
/// *structure*; only this proves the code's argv (not a hand-written one) runs:
/// the sandbox shell resolves the synthetic user, has no host `/usr`, and runs
/// nix coreutils. Skipped, not failed, where the prerequisites are absent.
#[cfg(test)]
mod smoke {
    use super::*;
    use crate::testutil::TmpDir;
    use std::process::Command;

    /// `(bwrap, nix)` when bwrap, a capability-bearing userns, and nix are all
    /// present; otherwise `None` to skip.
    fn prerequisites() -> Option<(PathBuf, PathBuf)> {
        let bwrap = crate::pathfind::find_on_path("bwrap")?;
        if !matches!(crate::probe_userns(), crate::Userns::Ok) {
            return None;
        }
        let nix = crate::store::resolve_nix()?;
        Some((bwrap, nix))
    }

    /// A sorted `(relative path, size)` fingerprint of a tree — sensitive to any
    /// addition, removal, or size change, enough to assert a store never moved.
    fn fingerprint(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = path.symlink_metadata() else {
                    continue;
                };
                let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                if meta.is_dir() {
                    out.push((rel, 0));
                    stack.push(path);
                } else {
                    out.push((rel, meta.len()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn the_generated_argv_launches_a_working_hermetic_shell() {
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping hermetic smoke: need bwrap, userns, and nix");
            return;
        };

        // a throwaway data dir + project; build_spec lays out the runtime exactly
        // as the launcher will, provisioning the userland into this store.
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve nixpkgs");
        let userland = super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
            .expect("resolve userland");

        let project = TmpDir::new();
        std::fs::write(project.path().join("README"), b"hi").unwrap();

        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            // resolve the synthetic user, prove no host /usr, list the project
            OsString::from("id -un; ls /usr 2>&1; ls"),
        ];
        let env = [("TERM".to_string(), "dumb".to_string())];
        let overlay = Overlay {
            env: &env,
            ro_binds: &[],
            bin_paths: &[],
        };
        // this smoke exercises the userland against the shared store, read-only — the
        // writable per-project store is the launcher's concern.
        let nix_mount = NixMount {
            src: crate::store::physical_path(&layout, Path::new("/nix")),
            writable: false,
        };
        let spec = build_spec(
            data.path(),
            project.path(),
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Shared,
            cmd,
        )
        .expect("build spec");

        let out = Command::new(&bwrap)
            .args(super::super::argv::to_argv(&spec))
            .output()
            .expect("spawn bwrap");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "bwrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // the synthetic passwd resolved the uid to the sandbox name
        assert!(
            stdout.contains("sandbox"),
            "synthetic identity not resolved:\n{stdout}"
        );
        // hermetic: there is no host /usr to list
        assert!(
            stdout.contains("cannot access '/usr'"),
            "host /usr leaked (not hermetic):\n{stdout}"
        );
        // nix coreutils ran and saw the project
        assert!(
            stdout.contains("README"),
            "coreutils did not see the project:\n{stdout}"
        );
    }

    /// The nix-ld substitution that replaces the global `LD_LIBRARY_PATH` with the
    /// shim must hold both ends at once: a *foreign* binary (one that hard-codes the
    /// standard `/lib64/ld-linux` and finds libc only through the loader) still runs,
    /// now served by the shim via `NIX_LD`; AND a nix tool from a *different* channel,
    /// and so a different glibc, runs without a skew. The old global `LD_LIBRARY_PATH`
    /// served foreign binaries but forced every tool onto the base glibc — an ABI
    /// mismatch (`GLIBC_PRIVATE`) for a differently-pinned one — while the shim serves
    /// foreign binaries and leaves each nix tool on its own glibc via RPATH. Both
    /// halves share one base userland (and so provision and run sequentially), which
    /// keeps a cold-cache suite run from standing up two userlands at once.
    #[test]
    fn the_nix_ld_shim_serves_foreign_binaries_and_unskews_cross_channel_tools() {
        use std::os::unix::fs::PermissionsExt;
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping nix-ld smoke: need bwrap, userns, and nix");
            return;
        };

        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let base_ref = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve base channel");
        let userland = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
            .expect("resolve userland");
        // both halves consume the shared store read-only (the userland is what is under
        // test); the writable per-project store is the launcher's concern.
        let nix_mount = NixMount {
            src: crate::store::physical_path(&layout, Path::new("/nix")),
            writable: false,
        };

        // Realise `<flake_ref>#<attr>` and report its logical store path.
        let realise = |flake_ref: &str, attr: &str, marker: &str, name: &str| {
            crate::store::provision(
                &nix,
                &layout,
                &data.path().join("roots").join(name),
                flake_ref,
                attr,
                marker,
            )
            .expect("provision")
        };
        let run = |spec: &SandboxSpec| {
            Command::new(&bwrap)
                .args(super::super::argv::to_argv(spec))
                .output()
                .expect("spawn bwrap")
        };

        // --- a foreign binary is served by the shim --------------------------------
        // Forge one: take a nix `hello`, repoint its interpreter at the standard
        // loader path and strip its RPATH, so — like a real npm/pip artefact — it can
        // only reach libc through the loader the sandbox provides, never its own
        // store path. Host-side patching needs the physical store path.
        let hello_base = crate::store::physical_path(
            &layout,
            &realise(&base_ref, "hello", "bin/hello", "hello"),
        )
        .join("bin/hello");
        let patchelf = crate::store::physical_path(
            &layout,
            &realise(&base_ref, "patchelf", "bin/patchelf", "patchelf"),
        )
        .join("bin/patchelf");

        let project = TmpDir::new();
        let proj = project.path().canonicalize().unwrap();
        let foreign = proj.join("foreign-hello");
        std::fs::copy(&hello_base, &foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pe = Command::new(&patchelf)
            .args([
                "--set-interpreter",
                "/lib64/ld-linux-x86-64.so.2",
                "--remove-rpath",
            ])
            .arg(&foreign)
            .output()
            .expect("run patchelf");
        assert!(
            pe.status.success(),
            "patchelf failed: {}",
            String::from_utf8_lossy(&pe.stderr)
        );

        let bare = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &[],
        };
        let foreign_spec = build_spec(
            data.path(),
            &proj,
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &bare,
            &[],
            NetPolicy::Shared,
            vec![foreign.clone().into_os_string()],
        )
        .expect("build foreign spec");
        let foreign_out = run(&foreign_spec);
        assert!(
            foreign_out.status.success(),
            "foreign binary failed under nix-ld: {}",
            String::from_utf8_lossy(&foreign_out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&foreign_out.stdout).contains("Hello, world!"),
            "foreign binary did not run through the shim: {}",
            String::from_utf8_lossy(&foreign_out.stdout)
        );

        // --- a cross-channel nix tool runs without a glibc skew --------------------
        let cross_ref = crate::store::LockTarget::global(&layout, Some("nixos-23.11"))
            .resolve(&nix, &layout)
            .expect("resolve cross channel");
        if cross_ref == base_ref {
            eprintln!(
                "skipping the cross-channel half: both channels resolved to the same revision"
            );
            return;
        }
        // the cross-channel tool's logical bin dir, prepended to PATH
        let bin_paths = vec![realise(&cross_ref, "hello", "bin/hello", "hello-cross").join("bin")];
        let with_tool = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &bin_paths,
        };
        let cross_spec = build_spec(
            data.path(),
            &proj,
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &with_tool,
            &[],
            NetPolicy::Shared,
            vec![OsString::from("hello")],
        )
        .expect("build cross spec");
        let cross_out = run(&cross_spec);
        assert!(
            cross_out.status.success(),
            "cross-channel tool failed — glibc skew not resolved: {}",
            String::from_utf8_lossy(&cross_out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&cross_out.stdout).contains("Hello, world!"),
            "cross-channel hello did not run: {}",
            String::from_utf8_lossy(&cross_out.stdout)
        );
    }

    /// The open-cage flip: a cage backed by a *writable per-project store* — seeded
    /// from the shared store with the base closure — must run the base userland
    /// entirely from that per-project store, with the shared store's `nix/store` not
    /// bound at `/nix` at all. This proves what the pure argv test cannot: the seed
    /// carried the *complete* base closure (a missing root would leave the shell unable
    /// to resolve a library), and the real `build_spec` path binds the per-project
    /// store read-write at `/nix`. The completeness check has teeth — every surfaced
    /// base root must be present in the per-project store, while a package realised into
    /// the shared store but left out of the seeded roots must be *absent*, so "present"
    /// means "seeded", not merely "somewhere in the shared store".
    #[test]
    fn the_cage_runs_from_a_writable_per_project_store_seeded_with_the_base_closure() {
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping per-project store flip smoke: need bwrap, userns, and nix");
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store() else {
            eprintln!("skipping per-project store flip smoke: need nix-store");
            return;
        };

        // provision the base userland into a throwaway shared store, plus an unrelated
        // package (`hello`) the seed must NOT drag in — it is not among the seeded roots,
        // nor in any base root's closure (a curated base tool would taint a closure-shared
        // witness, so this one is deliberately a leaf nothing in the base depends on).
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let base_ref = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve base channel");
        let userland = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
            .expect("resolve userland");
        let unseeded = crate::store::provision(
            &nix,
            &layout,
            &data.path().join("roots").join("hello"),
            &base_ref,
            "hello",
            "bin/hello",
        )
        .expect("provision hello");

        // a project whose own store is seeded with exactly the base roots (the launcher
        // collects base ∪ packages ∪ tools; the base closure is what backs the shell).
        let project = TmpDir::new();
        let proj = project.path().canonicalize().unwrap();
        std::fs::write(proj.join("MARKER"), b"x").unwrap();
        let id = super::project_runtime_id(&proj).expect("project id");
        let store =
            super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
                .expect("seed the per-project store");
        let in_store = |logical: &Path| {
            store
                .store_dir()
                .join("nix")
                .join("store")
                .join(logical.file_name().unwrap())
                .exists()
        };

        // every surfaced base root is present in the per-project store...
        for root in &userland.base_roots {
            assert!(
                in_store(root),
                "a base root is missing from the seeded store: {}",
                root.display()
            );
        }
        // ...while the unrelated package — in the shared store but not a seeded root —
        // is absent, so the completeness check distinguishes seeded from shared-at-large.
        assert!(
            !in_store(&unseeded),
            "an unseeded package leaked into the per-project store"
        );

        // the seeded store is internally consistent
        let verify = Command::new(&nix_store)
            .env("NIX_REMOTE", "")
            .arg("--store")
            .arg(store.store_dir())
            .args(["--verify", "--check-contents"])
            .output()
            .expect("spawn nix-store --verify");
        assert!(
            verify.status.success(),
            "the seeded per-project store failed verification: {}",
            String::from_utf8_lossy(&verify.stderr)
        );

        // back the cage with the per-project store, read-write — the shared store's
        // nix/store is not bound at /nix, so the shell, coreutils, and glibc must all
        // resolve from the per-project store.
        let nix_mount = NixMount {
            src: store.store_dir().join("nix"),
            writable: true,
        };
        let overlay = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &[],
        };
        // the cage reads the base userland AND writes into `/nix` — proving the rw bind
        // through the wired path. The write succeeding is itself proof `/nix` is
        // writable; where it lands is the multi-tenant non-negotiable, asserted below.
        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            OsString::from("id -un; ls; echo poison > /nix/POISON"),
        ];
        let spec = build_spec(
            data.path(),
            &proj,
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Shared,
            cmd,
        )
        .expect("build spec");

        // fingerprint the shared store's content paths just before the cage writes, so
        // any mutation through the rw `/nix` would show as a changed fingerprint after.
        let shared_paths = layout.store_dir().join("nix").join("store");
        let before = fingerprint(&shared_paths);

        let out = Command::new(&bwrap)
            .args(super::super::argv::to_argv(&spec))
            .output()
            .expect("spawn bwrap");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "the cage failed to run from / write to the per-project store: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("sandbox"),
            "the synthetic identity did not resolve from the per-project store:\n{stdout}"
        );
        assert!(
            stdout.contains("MARKER"),
            "coreutils from the per-project store did not see the project:\n{stdout}"
        );

        // the in-cage write landed in the project's OWN store copy...
        assert_eq!(
            std::fs::read_to_string(store.store_dir().join("nix").join("POISON"))
                .expect("the in-cage write did not land in the per-project store")
                .trim(),
            "poison"
        );
        // ...and the shared store's content paths are byte-identical — the write could
        // not reach it (it is not in the cage), the multi-tenant non-negotiable.
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store changed under an in-cage write"
        );
    }

    /// The open-cage payoff: the cage carries nix, and an agent uses it to build a
    /// **fresh** derivation **offline from the seeded base** — proving the per-project
    /// store is a self-sufficient nix store the agent can self-equip into, not just a
    /// read-only base. nix is invoked by *name* (so this also proves it is on the cage
    /// PATH), `substituters` is emptied (no network fetch is possible — the shared store
    /// is not even bound in the cage), and the derivation is novel with its output
    /// asserted **absent before** and **present after**, so a successful build can only
    /// be a real local build from the seeded bash+coreutils. nix needs *no* ops-supplied
    /// configuration: its compiled defaults resolve the store to the local `/nix` and
    /// build there. The teeth: a sibling derivation whose only input is a package realised
    /// into the shared store but **left out of the seed** must *fail* offline — proving
    /// "present" means "seeded", and the shared store is genuinely absent from the cage.
    #[test]
    fn the_cage_builds_a_fresh_derivation_offline_from_the_seeded_base() {
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping nix-in-cage smoke: need bwrap, userns, and nix");
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store() else {
            eprintln!("skipping nix-in-cage smoke: need nix-store");
            return;
        };

        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let base_ref = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve base channel");
        // the base userland now carries nix among its roots, so seeding the base closure
        // brings nix and its closure into the per-project store.
        let userland = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
            .expect("resolve userland");
        // jq: realised into the shared store but NOT a seeded root — the discriminant's
        // non-seeded dependency.
        let jq = crate::store::provision(
            &nix,
            &layout,
            &data.path().join("roots").join("jq"),
            &base_ref,
            "jq",
            "bin/jq",
        )
        .expect("provision jq");

        let project = TmpDir::new();
        let proj = project.path().canonicalize().unwrap();
        let id = super::project_runtime_id(&proj).expect("project id");
        let store =
            super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
                .expect("seed the per-project store");

        // the reuse derivation: build closure is bash + coreutils only, both seeded.
        // `builtins.storePath` validates them against the per-project store's own DB, so
        // a successful build proves the seeded store (paths AND database) is sufficient.
        let bash_store = userland.shell_bin.parent().unwrap().parent().unwrap();
        let cu_store = userland.bin_paths[1].parent().unwrap();
        let reuse = proj.join("reuse.nix");
        std::fs::write(
            &reuse,
            r#"let b = builtins.storePath "@BASH@"; c = builtins.storePath "@CU@"; in derivation { name = "ops-reuse-proof"; system = builtins.currentSystem; builder = "${b}/bin/bash"; args = ["-c" "${c}/bin/mkdir -p $out; ${c}/bin/echo ok > $out/result"]; }"#
                .replace("@BASH@", &bash_store.to_string_lossy())
                .replace("@CU@", &cu_store.to_string_lossy()),
        )
        .unwrap();
        // the discriminant: its only input is jq, which is in the shared store but not in
        // the seed — `builtins.storePath` against the per-project store rejects it, so the
        // build fails offline. That a *seeded* path succeeds while this one fails proves
        // the cage runs from the seed, not from the shared store at large.
        let discriminant = proj.join("discriminant.nix");
        std::fs::write(
            &discriminant,
            r#"let j = builtins.storePath "@JQ@"; in derivation { name = "ops-discriminant"; system = builtins.currentSystem; builder = "${j}/bin/jq"; args = ["-n" "null"]; }"#
                .replace("@JQ@", &jq.to_string_lossy()),
        )
        .unwrap();

        // The agent's commands. nix is invoked by name (cage PATH), with substituters
        // emptied so nothing can be fetched. Pre/post existence of the reuse output is
        // probed against the cage's own store (`/nix` = the per-project store).
        let script = format!(
            "set +e\n\
             command -v nix-build > /dev/null && echo 'NIX_ON_PATH=yes' || echo 'NIX_ON_PATH=no'\n\
             drv=$(nix-instantiate {reuse} 2>/dev/null)\n\
             outp=$(nix-store -q --outputs \"$drv\" 2>/dev/null)\n\
             echo \"OUTPATH=$outp\"\n\
             if [ -e \"$outp\" ]; then echo PRE=present; else echo PRE=absent; fi\n\
             nix-build --no-out-link --option substituters '' --option builders '' {reuse} > /dev/null 2>&1\n\
             echo \"REUSE_EXIT=$?\"\n\
             if [ -e \"$outp\" ]; then echo POST=present; else echo POST=absent; fi\n\
             echo \"RESULT=$(cat \"$outp/result\" 2>/dev/null)\"\n\
             nix-build --no-out-link --option substituters '' --option builders '' {disc} > /dev/null 2>&1\n\
             echo \"DISC_EXIT=$?\"\n",
            reuse = reuse.display(),
            disc = discriminant.display(),
        );

        let nix_mount = NixMount {
            src: store.store_dir().join("nix"),
            writable: true,
        };
        let overlay = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &[],
        };
        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            OsString::from(script),
        ];
        let spec = build_spec(
            data.path(),
            &proj,
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Shared,
            cmd,
        )
        .expect("build spec");

        // the shared store must not change under an in-cage build (multi-tenant).
        let shared_paths = layout.store_dir().join("nix").join("store");
        let before = fingerprint(&shared_paths);

        let out = Command::new(&bwrap)
            .args(super::super::argv::to_argv(&spec))
            .output()
            .expect("spawn bwrap");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "the cage script failed: {}\nstdout:\n{stdout}",
            String::from_utf8_lossy(&out.stderr)
        );
        let marker = |key: &str| {
            stdout
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing marker {key} in:\n{stdout}"))
        };

        // nix is on the cage PATH, the agent reached it by name
        assert_eq!(
            marker("NIX_ON_PATH"),
            "yes",
            "nix-build not on the cage PATH"
        );
        // the reuse output was absent before and present after — a genuine fresh build
        assert_eq!(marker("PRE"), "absent", "the reuse output pre-existed");
        assert_eq!(marker("REUSE_EXIT"), "0", "the offline reuse build failed");
        assert_eq!(
            marker("POST"),
            "present",
            "the reuse output was not produced"
        );
        assert_eq!(marker("RESULT"), "ok", "the builder did not run");
        // the output landed in the per-project store (the only store bound at /nix)
        let outp = marker("OUTPATH");
        let outp_name = Path::new(outp).file_name().expect("an output path");
        assert!(
            store
                .store_dir()
                .join("nix")
                .join("store")
                .join(outp_name)
                .exists(),
            "the build output is not in the per-project store: {outp}"
        );
        // the discriminant — a non-seeded dependency — failed offline, so "present"
        // really means "seeded", not "anywhere in the shared store"
        assert_ne!(
            marker("DISC_EXIT"),
            "0",
            "a build whose only input is unseeded succeeded offline — the cage is not running from the seed alone"
        );

        // the shared store is byte-identical: the in-cage build could not reach it
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store changed under an in-cage build"
        );
    }

    /// Best-effort TCP reach of the binary cache, so the network smoke below skips
    /// (does not fail) when offline — its install fetches from nixhub and the cache.
    fn network_reachable() -> bool {
        use std::net::ToSocketAddrs;
        let Ok(mut addrs) = ("cache.nixos.org", 443).to_socket_addrs() else {
            return false;
        };
        addrs.any(|addr| {
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5)).is_ok()
        })
    }

    /// The `ops mise` payoff: an agent self-equips a project's `nix:` tool from inside
    /// the open cage. The cage carries mise (in the base userland) with the embedded
    /// `nix:` backend plugin registered, so `mise install nix:jq` resolves jq through
    /// nixhub and builds it into the project's **own** writable store. Two things are
    /// proven: the tool genuinely installs and runs (the plugin path works end to end
    /// against the relocated single-user store), and — the multi-tenant boundary — the
    /// **shared store stays byte-identical**, since an in-cage install can only reach
    /// the project's store. Untrusted by construction (no `ops trust`): the open-cage
    /// self-equip posture works regardless of trust, unlike host-side provisioning.
    ///
    /// This is the project's first *network* smoke (nixhub + the binary cache), heavier
    /// than the offline ones; it skips when the network is unreachable, and uses jq
    /// (cache-substitutable) to stay fast.
    #[test]
    fn the_cage_self_equips_a_nix_tool_via_mise() {
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping mise self-equip smoke: need bwrap, userns, and nix");
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store() else {
            eprintln!("skipping mise self-equip smoke: need nix-store");
            return;
        };
        if !network_reachable() {
            eprintln!("skipping mise self-equip smoke: the binary cache is unreachable");
            return;
        }

        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let base_ref = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve base channel");
        // the base userland carries mise, so seeding the base closure brings mise and
        // its closure into the per-project store — the agent reaches it by name.
        let userland = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
            .expect("resolve userland");

        let project = TmpDir::new();
        let proj = project.path().canonicalize().unwrap();
        let id = super::project_runtime_id(&proj).expect("project id");
        let store =
            super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
                .expect("seed the per-project store");

        // The agent's commands: self-equip jq, then prove it installed and runs. A
        // successful `mise install nix:<pkg>` is itself the proof the plugin is wired —
        // the backend resolved and built — so no separate registration check is needed
        // (a first `mise --version` warms the data dir, as a real session would). The
        // install writes to the cage's `/nix` (the per-project store); its diagnostics
        // go to the test's stderr.
        let script = "set +e\n\
             mise --version > /dev/null 2>&1\n\
             mise install nix:jq 1>&2\n\
             echo \"INSTALL_EXIT=$?\"\n\
             p=$(ls -d /nix/store/*-jq-*/bin/jq 2>/dev/null | head -1)\n\
             if [ -n \"$p\" ]; then echo JQSTORE=present; echo \"JQVER=$(\"$p\" --version 2>/dev/null)\"; \
             else echo JQSTORE=absent; echo JQVER=; fi\n";

        let nix_mount = NixMount {
            src: store.store_dir().join("nix"),
            writable: true,
        };
        let overlay = Overlay {
            env: &[],
            ro_binds: &[],
            bin_paths: &[],
        };
        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            OsString::from(script),
        ];
        let spec = build_spec(
            data.path(),
            &proj,
            Runtime::ProjectDefault,
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Shared,
            cmd,
        )
        .expect("build spec");

        // the shared store must not change under an in-cage install (multi-tenant).
        let shared_paths = layout.store_dir().join("nix").join("store");
        let before = fingerprint(&shared_paths);

        let out = Command::new(&bwrap)
            .args(super::super::argv::to_argv(&spec))
            .output()
            .expect("spawn bwrap");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "the cage script failed: {}\nstdout:\n{stdout}",
            String::from_utf8_lossy(&out.stderr)
        );
        let marker = |key: &str| {
            stdout
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing marker {key} in:\n{stdout}"))
        };

        // jq self-equipped: the install succeeded, which means the embedded `nix:`
        // backend plugin resolved through nixhub and built into the cage's store.
        assert_eq!(
            marker("INSTALL_EXIT"),
            "0",
            "`mise install nix:jq` failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // it landed in the per-project store — the only store bound at `/nix`
        assert_eq!(
            marker("JQSTORE"),
            "present",
            "the installed jq is not in the per-project store"
        );
        // and it actually runs (the binary executes from the self-equipped install)
        assert!(
            marker("JQVER").starts_with("jq"),
            "the self-equipped jq did not run: {}",
            marker("JQVER")
        );
        // the boundary: the shared store is byte-identical — the in-cage install
        // could not reach it
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store changed under an in-cage mise install"
        );
    }

    /// The activation payoff: a tool the agent *activates* in the cage (`mise use -g
    /// nix:<pkg>`) is on PATH in a **later, separate** launch — without re-declaring it
    /// and without touching the project's repo. Both mechanisms are proven against a
    /// fresh spec over the same project: the **shims dir on PATH** for the
    /// non-interactive `ops run` (a bare `jq` resolves *through the shim*), and
    /// **`mise activate`** for the interactive shell (bash started with the synthetic
    /// `--rcfile` puts the *real* tool bin on PATH). The first cage activates jq into the
    /// project's own store and persistent home; the second is a brand-new spec, so "on
    /// PATH" can only come from the persisted activation. The shared store stays
    /// byte-identical throughout. A network smoke (the activation needs jq actually
    /// installed): it skips when the cache is unreachable.
    #[test]
    fn a_mise_used_tool_is_activated_on_path_in_a_later_launch() {
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping mise activation smoke: need bwrap, userns, and nix");
            return;
        };
        let Some(nix_store) = crate::store::resolve_nix_store() else {
            eprintln!("skipping mise activation smoke: need nix-store");
            return;
        };
        if !network_reachable() {
            eprintln!("skipping mise activation smoke: the binary cache is unreachable");
            return;
        }

        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let base_ref = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve base channel");
        let userland = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
            .expect("resolve userland");

        let project = TmpDir::new();
        let proj = project.path().canonicalize().unwrap();
        let id = super::project_runtime_id(&proj).expect("project id");

        // Run `script` in a fresh spec over the same project — exactly as a separate
        // launch would: re-seed (a top-up, so jq installed by an earlier cage survives),
        // back `/nix` read-write, build, run. Returns (success, stdout, stderr).
        let run_script = |script: &str| {
            let store =
                super::super::projectstore::prepare(&nix_store, &layout, &id, &userland.base_roots)
                    .expect("seed the per-project store");
            let nix_mount = NixMount {
                src: store.store_dir().join("nix"),
                writable: true,
            };
            let overlay = Overlay {
                env: &[],
                ro_binds: &[],
                bin_paths: &[],
            };
            let cmd = vec![
                userland.shell_bin.clone().into_os_string(),
                OsString::from("-c"),
                OsString::from(script.to_string()),
            ];
            let spec = build_spec(
                data.path(),
                &proj,
                Runtime::ProjectDefault,
                &userland,
                &nix_mount,
                &overlay,
                &[],
                NetPolicy::Shared,
                cmd,
            )
            .expect("build spec");
            let out = Command::new(&bwrap)
                .args(super::super::argv::to_argv(&spec))
                .output()
                .expect("spawn bwrap");
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        };

        // the shared store must stay byte-identical across the whole sequence
        let shared_paths = layout.store_dir().join("nix").join("store");
        let before = fingerprint(&shared_paths);

        // cage 1: activate jq — writes the global mise config + a shim into the
        // persistent home, builds jq into the project's own store.
        let (ok, _out, err) = run_script("mise use -g nix:jq 1>&2");
        assert!(ok, "`mise use -g nix:jq` failed:\n{err}");

        // cage 2: a brand-new spec. The shims dir on PATH resolves jq for a direct
        // (non-interactive) command; bash with the synthetic `--rcfile` activates mise,
        // which puts the real jq bin on PATH. The inner interactive bash has no
        // controlling terminal here, so its job-control notice is sent to /dev/null.
        let script = "set +e\n\
             echo \"SHIM_WHICH=$(command -v jq || echo NONE)\"\n\
             echo \"SHIM_VER=$(jq --version 2>/dev/null)\"\n\
             bash --rcfile /opt/ops/bashrc -i -c 'echo \"ACT_WHICH=$(command -v jq || echo NONE)\"; echo \"ACT_VER=$(jq --version 2>/dev/null)\"' 2>/dev/null\n";
        let (ok, out, err) = run_script(script);
        assert!(ok, "the later launch failed:\n{err}\nstdout:\n{out}");
        let marker = |key: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing marker {key} in:\n{out}"))
        };

        // `ops run` (non-interactive): jq is on PATH via the shims dir, resolved through
        // the shim itself, and runs.
        assert!(
            marker("SHIM_WHICH").ends_with("/shims/jq"),
            "jq did not resolve through the shims dir: {}",
            marker("SHIM_WHICH")
        );
        assert!(
            marker("SHIM_VER").starts_with("jq"),
            "the shimmed jq did not run: {}",
            marker("SHIM_VER")
        );

        // `ops shell` (interactive): mise activate (via `--rcfile`) puts the *real* tool
        // bin on PATH — ending in `/bin/jq`, not `/shims/jq`, so this proves activation
        // engaged rather than the shim doing the work again.
        assert!(
            marker("ACT_WHICH").ends_with("/bin/jq") && marker("ACT_WHICH").contains("/nix/store/"),
            "mise activate did not put the real jq bin on PATH: {}",
            marker("ACT_WHICH")
        );
        assert!(
            marker("ACT_VER").starts_with("jq"),
            "the activated jq did not run: {}",
            marker("ACT_VER")
        );

        // the shared store is byte-identical — every launch only read it
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store changed under the activation launches"
        );
    }
}
