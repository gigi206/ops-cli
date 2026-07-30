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
pub(super) const SANDBOX_SHELL: &str = "/bin/sh";

/// Where the **nix-ld** shim is bound: the standard interpreter path a *foreign* (non-nix) binary
/// hard-codes. A nix-built binary finds its loader by absolute RPATH and never comes here; an npm
/// or pip artefact does, and the shim then re-execs it against the base loader named by `NIX_LD`.
/// This is the value `resolve_userland` produces as `interp_dest`, named here so a cage assembled
/// from another cage's mounts can recognise it without carrying the userland along.
pub(super) const LOADER_DEST: &str = "/lib64/ld-linux-x86-64.so.2";

/// The in-sandbox `/bin/bash`, synthesised as a symlink to the same nix shell as
/// `/bin/sh`. A great many upstream scripts carry a `#!/bin/bash` shebang (a host
/// path a hermetic cage lacks), so the kernel cannot exec them without this name.
/// It is the *same* binary `/bin/sh` already exposes — a second name for an
/// interpreter already present, not a new mount — so it adds no exposure, only the
/// name a `#!/bin/bash` shebang assumes. Also the shell `sbx session attach` execs inside a
/// running cage (an absolute path that resolves in the cage's own mount namespace).
pub(crate) const SANDBOX_BASH: &str = "/bin/bash";

/// The in-sandbox `/usr/bin/env`, synthesised as a symlink to coreutils' `env`. An
/// interpreted tool's `#!/usr/bin/env <interp>` shebang resolves through it (a hermetic
/// cage has no host `/usr`). With `/bin/sh` and `/bin/bash` these are the three FHS
/// paths nix's own ecosystem standardises, so synthesising it follows nix convention
/// rather than working around it.
pub(super) const SANDBOX_ENV: &str = "/usr/bin/env";

/// The in-sandbox `/usr/bin/xdg-open`, synthesised as a tiny shell script. A
/// hermetic cage has no host display, no browser, and no file manager, so a tool
/// that calls `xdg-open <file|url>` (an OAuth device-auth flow that auto-opens the
/// verification URL, a "open the docs" link, an image viewer) would otherwise fail
/// with `Executable not found in $PATH: "xdg-open"` and abort the flow. The stub
/// surfaces the argument on stderr so the user can act on it (open the URL in their
/// host browser, view the file), and exits 0 so the caller treats the open as
/// non-fatal and continues — a device-auth flow then proceeds while the user
/// completes auth. Like the other synthetic FHS affordances it adds no exposure:
/// it owns no data, opens nothing.
const XDG_OPEN_INCAGE: &str = "/usr/bin/xdg-open";

/// The synthetic `xdg-open` body. POSIX `sh` (the cage's `/bin/sh`), prints every
/// argument (the common call is a single file or URL) to stderr with an `sbx:`
/// prefix, then exits 0. Robust to any argv a tool passes: it never inspects or
/// forks — `xdg-open` may be asked to open anything, not only a URL.
const XDG_OPEN_CONTENTS: &str = "#!/bin/sh\n\
echo \"sbx: open on the host:\" \"$@\" >&2\n\
exit 0\n";

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
    /// sbx's own CA bundle (`cacert`'s `ca-bundle.crt`), bound read-only at the standard
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
    /// The coreutils `env` binary `/usr/bin/env` links to, so an interpreted tool's
    /// `#!/usr/bin/env <interp>` shebang resolves. A hermetic cage has no host `/usr`;
    /// `/bin/sh`, `/bin/bash` and `/usr/bin/env` are the FHS paths nix's own ecosystem
    /// standardizes, so synthesising it follows nix convention. An in-sandbox logical
    /// path (it resolves through the store bound at `/nix`).
    pub(crate) env_bin: PathBuf,
    /// The in-cage egress forwarder (`socat`), as an in-sandbox logical path. Invoked
    /// by absolute path from the allowlist-posture wrapper; off `PATH` and untouched by
    /// other postures.
    pub(crate) socat_bin: PathBuf,
    /// The in-cage mise engine, as an in-sandbox logical path. On `PATH` so an agent drives
    /// it directly, but invoked by *absolute* path from the auto-equip wrapper so a persisted
    /// shim named `mise` cannot shadow it.
    pub(crate) mise_bin: PathBuf,
    /// The in-cage nix, as an in-sandbox logical path. On `PATH` (the agent self-equips with
    /// it), but invoked by *absolute* path from the `flake:` build wrapper so a persisted shim
    /// cannot shadow it.
    pub(crate) nix_bin: PathBuf,
    /// sbx's own compiled UTF-8 locale archive, as an in-sandbox logical path. Named in
    /// `LOCALE_ARCHIVE` so the cage's glibc can load a UTF-8 `LANG` without a host
    /// `/usr/lib/locale`; ships no binary, so it is off `PATH`.
    pub(crate) locale_archive: PathBuf,
}

/// One explicit bind injected by the launcher after the structural mounts (so it is
/// neither shadowed by, nor shadows, them): a host source exposed at a distinct cage
/// destination. Used for the network-allowlist machinery — the bound egress socket and
/// the proxy's CA certificate — whose destinations are sbx's, not the project's.
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
/// the read-only bind. Which store backs the cage is sbx's decision, never a
/// configurable field, so an untrusted project cannot widen its own access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NixMount {
    /// The host `nix/` directory bound at `/nix`.
    pub(crate) src: PathBuf,
    /// Whether `/nix` is bound read-write (a per-project store) or read-only (the
    /// shared store).
    pub(crate) writable: bool,
    /// Whether the backing tree sits on btrfs, where files can inherit the
    /// `btrfs.compression` attribute that in-cage nix must then leave in place
    /// (see [`mise_env`]). Probed by the launcher, carried as data so assembly
    /// stays pure.
    pub(crate) on_btrfs: bool,
}

/// The project's overlay onto the base sandbox: the configuration-supplied extra
/// environment, read-only host binds, and tool `bin` directories to prepend to
/// `PATH`. Grouped so the assembler and its constructor take one overlay rather
/// than three parallel slices.
pub(crate) struct Overlay<'a> {
    /// Extra environment, upserted over the structural defaults.
    pub(crate) env: &'a [(String, String)],
    /// Extra host paths to bind, each read-only or read-write (emitted before the structural
    /// mounts, so a colliding structural mount shadows them — a config bind can never displace
    /// `/nix`, the identity files, or the loader, whatever its mode).
    pub(crate) binds: &'a [crate::config::Bind],
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
    /// For a **global app** only: the host path of the per-project mise data pool, bound writable
    /// as mise's primary [`MISE_PROJECT_INCAGE`] so a `nix:` self-equip's install aligns with the
    /// per-project `/nix` store. `None` for `sbx run` and a per-project app, whose home — and thus
    /// mise's data dir — is already per-project, so they keep the single-pool wiring.
    pub(crate) mise_project_src: Option<PathBuf>,
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
    /// For a global app only: the host per-project mise data pool, bound writable at
    /// [`MISE_PROJECT_INCAGE`] (mise's primary for the split). `None` keeps the single app-global
    /// pool ([`mise_env`] then reads its whole install/shim set from the home).
    mise_project_src: Option<&'a Path>,
    /// Synthetic identity files; bound read-only at `/etc/passwd`/`/etc/group`.
    passwd_src: &'a Path,
    group_src: &'a Path,
    /// Staged mise `nix:` backend plugin; bound read-only at the in-cage plugin dir.
    mise_plugin_src: &'a Path,
    /// Synthetic interactive-shell rc; bound read-only at [`SHELL_RC_INCAGE`].
    shell_rc_src: &'a Path,
    /// Generated egress contract; bound read-only at [`super::contract::EGRESS_CONTRACT_INCAGE`].
    contract_src: &'a Path,
    /// Synthetic `xdg-open` script; bound read-only at [`XDG_OPEN_INCAGE`].
    xdg_open_src: &'a Path,
    /// Synthetic `/etc/hosts`; bound read-only at `/etc/hosts`.
    hosts_src: &'a Path,
    /// Synthetic `/etc/machine-id`; bound read-only at `/etc/machine-id` and
    /// `/var/lib/dbus/machine-id`.
    machine_id_src: &'a Path,
}

/// Assemble a [`SandboxSpec`] from already-resolved host paths. Pure: no I/O, no
/// ambient state — every mount and variable derives from the arguments. This is
/// the audited core; [`build_spec`] feeds it real paths.
#[allow(clippy::too_many_arguments)]
fn assemble(
    paths: &SandboxPaths,
    userland: &Userland,
    nix: &NixMount,
    overlay: &Overlay,
    extra_binds: &[ExtraBind],
    devices: &[PathBuf],
    net: NetPolicy,
    cmd: Vec<OsString>,
) -> Result<SandboxSpec, SpecError> {
    // Config-declared binds come first, so any structural mount below shadows a colliding one —
    // a config bind can never displace `/nix`, the synthetic `/etc/passwd`/`group`, the loader,
    // or the project itself, whether it is read-only or read-write. A `mode = "rw"` bind is a
    // read-write mount (the cage writes through to the host path); the default is read-only.
    let mut mounts: Vec<Mount> = overlay
        .binds
        .iter()
        .map(|b| {
            let (src, dest) = (b.path.clone(), b.path.clone());
            if b.writable {
                Mount::Bind { src, dest }
            } else {
                Mount::RoBind { src, dest }
            }
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
        // Zone 1 — the synthetic `/bin/bash`: a second name for the same shell, so a
        // `#!/bin/bash` shebang (extremely common in upstream scripts) resolves. A
        // hermetic cage has no host `/bin/bash`; without this name the kernel refuses
        // such scripts with "bad interpreter: No such file or directory".
        Mount::Symlink {
            target: userland.shell_bin.clone(),
            dest: PathBuf::from(SANDBOX_BASH),
        },
        // Zone 1 — the synthetic `/usr/bin/env`: an interpreted tool's
        // `#!/usr/bin/env <interp>` shebang resolves here to coreutils' `env`. The cage
        // carries no host `/usr`; this is the third FHS path (beside `/bin/sh` and
        // `/bin/bash`) that nix's own ecosystem standardises, the affordance every
        // shebang-based CLI assumes.
        Mount::Symlink {
            target: userland.env_bin.clone(),
            dest: PathBuf::from(SANDBOX_ENV),
        },
        // Zone 1 — the synthetic `/usr/bin/xdg-open`: a stub that prints its
        // argument and exits 0. A tool that auto-opens a browser or file (an OAuth
        // device-auth flow, a docs link) calls `xdg-open <file|url>`; the hermetic
        // cage has no display, browser, or file manager, so without this stub the
        // call fails with "xdg-open not found" and aborts the flow. The stub surfaces
        // the argument for the user to act on (open the URL in their host browser,
        // view the file) and signals success, so the flow continues. bwrap
        // auto-creates the `/usr/bin` parent (already created for `/usr/bin/env`
        // above); like it, this adds only the name a tool assumes.
        Mount::RoBind {
            src: paths.xdg_open_src.to_path_buf(),
            dest: PathBuf::from(XDG_OPEN_INCAGE),
        },
        // Zone 1 — the embedded mise "nix" backend plugin, read-only: an agent's
        // in-cage mise resolves it (via a symlink in the writable mise data dir) to
        // self-equip the project's `nix:` tools. Read-only so the agent cannot rewrite
        // sbx's own plugin code.
        Mount::RoBind {
            src: paths.mise_plugin_src.to_path_buf(),
            dest: PathBuf::from(super::miseplugin::INCAGE_DIR),
        },
        // Zone 1 — the synthetic interactive-shell rc, read-only: an interactive `sbx run` points
        // bash's `--rcfile` at it to activate mise. Sourced from outside every writable
        // mount, so the agent cannot rewrite its own shell init.
        Mount::RoBind {
            src: paths.shell_rc_src.to_path_buf(),
            dest: PathBuf::from(SHELL_RC_INCAGE),
        },
        // Zone 1 — the generated egress contract, read-only: a description of what the
        // cage's network posture permits (reachable hosts, why a direct connection or
        // `ping` fails). Informational only — it enforces nothing; the empty netns and the
        // host proxy are the boundary. Bound from outside every writable mount so the agent
        // cannot rewrite the contract it is told to read.
        Mount::RoBind {
            src: paths.contract_src.to_path_buf(),
            dest: PathBuf::from(super::contract::EGRESS_CONTRACT_INCAGE),
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
        // Zone 1 — a synthetic `/etc/hosts` mapping `localhost` (and the cage's own
        // hostname) to loopback. A hermetic cage carries no `/etc/hosts`, so a tool that
        // resolves the *name* `localhost` — e.g. to bind an internal server on it — falls
        // through the file lookup to DNS, which the empty netns has no resolver for, and
        // fails hard. The loopback interface itself is already up (the egress forwarder binds
        // `127.0.0.1`); this only adds the name resolution. Synthetic, like the identity files
        // — it exposes no host data (never the host's own `/etc/hosts`), so it is bound
        // read-only from outside every writable mount.
        Mount::RoBind {
            src: paths.hosts_src.to_path_buf(),
            dest: PathBuf::from("/etc/hosts"),
        },
        // Zone 1 — a synthetic `/etc/machine-id` (and its dbus alias), stable per app-home and
        // unique per home, never the host's. A hermetic cage carries neither file nor a MAC, so a
        // desktop app that derives a device id from them (some editors run
        // `cat /var/lib/dbus/machine-id /etc/machine-id || hostname`) otherwise hashes an empty
        // string — the same id in every cage, which the app's anti-abuse reads as one machine
        // running countless accounts. A distinct per-home id gives each app its own persistent
        // machine identity. Synthetic and bound read-only from outside every writable mount, like
        // the identity files — it leaks no host data (never the host's real machine-id).
        Mount::RoBind {
            src: paths.machine_id_src.to_path_buf(),
            dest: PathBuf::from("/etc/machine-id"),
        },
        Mount::RoBind {
            src: paths.machine_id_src.to_path_buf(),
            dest: PathBuf::from("/var/lib/dbus/machine-id"),
        },
        // Zone 1 — TLS: sbx's own CA bundle from its store rather than the host, so HTTPS
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

    // Zone 2 — a global app's per-project mise data pool, bound writable. A global app's home
    // (and its default mise pool) is shared across projects, but mise's *primary* data dir must be
    // per-project so a `nix:` self-equip's install record aligns with the per-project `/nix` store
    // rather than trusting a stale app-global record that points at another project's store; the
    // app-global pool's installs stay reachable as a read-only fallback (see [`mise_env`]). Only a
    // global app supplies this (`sbx run` and a per-project app already root their home
    // per-project). Its dest ([`MISE_PROJECT_INCAGE`]) is under `/opt/sbx`, disjoint from every
    // structural mount and from the config binds/devices/launcher binds.
    if let Some(src) = paths.mise_project_src {
        mounts.push(Mount::Bind {
            src: src.to_path_buf(),
            dest: PathBuf::from(MISE_PROJECT_INCAGE),
        });
    }

    // Host device nodes from a trusted `[devices]` grant, bound at their own `/dev/*` paths with
    // device access. Emitted *after* the `Mount::Dev` above (part of the structural block), so each
    // real device layers over the minimal, hostless `/dev` rather than being shadowed by it. A `-try`
    // bind (see `Mount::DevBind`) skips a device absent on this host, so a portable profile still
    // launches everywhere. Their destinations are `/dev/*`, disjoint from the config binds, every
    // structural mount, and the launcher's extra binds below.
    mounts.extend(devices.iter().map(|d| Mount::DevBind {
        src: d.clone(),
        dest: d.clone(),
    }));

    // Launcher-injected binds, emitted last so they neither shadow a structural mount nor
    // are shadowed by one. Their destinations are sbx's (the egress socket under the tmpfs,
    // the proxy CA under `/opt/sbx`), never a project path; their parents are already
    // mounted above (the tmpfs for the socket, the userland binds' `/opt/sbx`).
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
    // shim in the shims dir, so a later `sbx run -- <tool>` resolves it. `/bin/sh` and
    // the loader are wired by absolute path, not PATH, so prepending here never weakens
    // them.
    let mut path_dirs = overlay.bin_paths.to_vec();
    // For a global app, the per-project primary's shims come first (project + `nix:` tools the agent
    // self-equips), then the app-global pool's shims (the agent's own `mise:` tools reached through
    // the shared-install fallback). A shim only re-resolves from the ambient `MISE_DATA_DIR` at exec,
    // so both dirs must be on PATH for the shim *files* to exist; the pool a tool resolves from is
    // still chosen by the ambient env, not by PATH order.
    if paths.mise_project_src.is_some() {
        path_dirs.push(PathBuf::from(format!("{MISE_PROJECT_INCAGE}/shims")));
    }
    path_dirs.push(PathBuf::from(format!("{SANDBOX_HOME}/{MISE_SHIMS_REL}")));
    path_dirs.extend(userland.bin_paths.iter().cloned());
    // The synthetic `/usr/bin` (only `env` and `xdg-open`, both sbx-owned — no host
    // leak) is on PATH last, so a tool that calls `xdg-open` by name resolves the
    // stub. Last so declared tools, mise shims, and the base userland all win on a
    // name collision; `/usr/bin/env` is the same coreutils `env` already on PATH.
    path_dirs.push(PathBuf::from("/usr/bin"));

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
        // The sandbox-awareness handle: `SBX_SANDBOX=1` lets a process tell it is running
        // inside an sbx cage, and `SBX_EGRESS_CONTRACT` points it at the read-only contract
        // describing the cage's network posture. Both are structural (lowest precedence): a
        // trusted `[env]` could override them, but that only mispoints the project's own
        // tools at its own value — self-sabotage of an informational handle, not an escape
        // (the same class as `FONTCONFIG_FILE`/`WAYLAND_DISPLAY`) — so neither needs a
        // denylist entry.
        ("SBX_SANDBOX".to_string(), "1".to_string()),
        (
            "SBX_EGRESS_CONTRACT".to_string(),
            super::contract::EGRESS_CONTRACT_INCAGE.to_string(),
        ),
        // Locale. `LOCALE_ARCHIVE` names sbx's own UTF-8 locale archive so the cage's glibc
        // can load a UTF-8 `LANG` — a hermetic cage has no host `/usr/lib/locale`, so without
        // it glibc falls back to the C locale and byte-escapes accented text and filenames.
        // `LANG` defaults to the always-available compiled `C.UTF-8` so a cage with no host
        // locale is still UTF-8-clean; the host's `LANG` passes through the overlay and
        // upserts over this floor, loading fully from the archive when it is a locale the
        // archive carries. Both are structural (lowest precedence): a trusted `[env]` may
        // override them, which only mis-sets the project's own cage locale (self-sabotage,
        // the same class as `FONTCONFIG_FILE`), so neither needs a denylist entry.
        (
            "LOCALE_ARCHIVE".to_string(),
            userland.locale_archive.to_string_lossy().into_owned(),
        ),
        ("LANG".to_string(), "C.UTF-8".to_string()),
    ];
    env.extend(mise_env(paths.mise_project_src.is_some(), nix.on_btrfs));
    for (key, val) in overlay.env {
        upsert_env(&mut env, key, val);
    }

    SandboxSpec::new(paths.project.to_path_buf(), mounts, env, net, cmd)
}

/// The fixed in-cage destinations the structural mounts in [`assemble`] occupy — every mount
/// destination that does not depend on the specific project or app. The runtime-derived paths are
/// deliberately excluded (the project is mounted at its own absolute path, and a config bind that
/// overlaps the project tree is normal; the launcher's extra binds live at sbx's own paths), while
/// the fixed `SANDBOX_HOME` is listed. A config bind whose canonical destination *nests* with one
/// of these is not reconciled by the exact-destination shadowing `assemble` relies on, so
/// [`structural_nesting_warning`] surfaces it. Kept in lockstep with `assemble` by
/// `structural_dests_lists_every_fixed_mount_assemble_emits`, which fails if a new structural mount
/// is added without being listed here.
pub(super) const STRUCTURAL_DESTS: &[&str] = &[
    "/nix",
    "/proc",
    "/dev",
    "/tmp",
    "/etc/passwd",
    "/etc/group",
    "/etc/hosts",
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/etc/resolv.conf",
    "/etc/ssl/certs/ca-certificates.crt",
    LOADER_DEST,
    SANDBOX_HOME,
    SANDBOX_SHELL,
    SANDBOX_BASH,
    SANDBOX_ENV,
    XDG_OPEN_INCAGE,
    CAGE_CA_BUNDLE,
    SHELL_RC_INCAGE,
    super::miseplugin::INCAGE_DIR,
    MISE_PROJECT_INCAGE,
    super::contract::EGRESS_CONTRACT_INCAGE,
];

/// How a config bind's destination overlaps a structural mount destination.
enum Nesting {
    /// The bind sits at or under the structural path: the cage mounts over it, so the bind is
    /// shadowed and never appears inside.
    Shadowed,
    /// The bind contains the structural path: the cage mounts that path over part of the bound
    /// directory, so that sub-path inside the cage is sbx's, not the bind's.
    Contains,
}

/// If the canonical config-bind destination `dest` *nests* with a fixed structural mount
/// destination — it is a strict ancestor or descendant of one — return that structural path and
/// the relationship. An *exact* match is deliberately not reported: that collision is reconciled
/// correctly by [`assemble`] (the structural mount wins — the control that stops a config bind
/// displacing `/nix`). A nesting overlap is *not* reconciled — a descendant is shadowed by the
/// later mount and vanishes; an ancestor over-exposes the host directory around the structural
/// files — so it is the footgun worth surfacing.
fn structural_nesting_conflict(dest: &Path) -> Option<(&'static str, Nesting)> {
    STRUCTURAL_DESTS.iter().find_map(|s| {
        let structural = Path::new(s);
        if dest == structural {
            None
        } else if dest.starts_with(structural) {
            Some((*s, Nesting::Shadowed))
        } else if structural.starts_with(dest) {
            Some((*s, Nesting::Contains))
        } else {
            None
        }
    })
}

/// A warning when a config bind's canonical destination `dest` nests with one of the cage's own
/// structural mounts, or `None` when it does not. `writable` marks a `mode = "rw"` bind, which the
/// `Contains` case flags specially: a read-write ancestor bind grants the cage write-through to the
/// host files around the structural mount. The `binds` field is trusted-only, so this is an
/// ergonomics tripwire (the launch does not drop the bind), not a security control — it tells the
/// user their bind will not behave as a naive reading suggests.
pub(crate) fn structural_nesting_warning(dest: &Path, writable: bool) -> Option<String> {
    structural_nesting_conflict(dest).map(|(structural, nesting)| match nesting {
        Nesting::Shadowed => {
            // A `/dev/*` path is the common case worth steering: a plain bind of a device node is
            // both shadowed here *and* (were it not) `nodev` — visible but unusable. `[devices]` is
            // the field that actually exposes a host device with device access.
            let dev_hint = if structural == "/dev" {
                " — to expose a host device with device access, use `[devices]` instead"
            } else {
                ""
            };
            format!(
                "bind `{}` sits at or under the sandbox's own mount `{structural}` — the cage mounts \
                 over it, so the bind is shadowed and will not appear inside{dev_hint}",
                dest.display()
            )
        }
        Nesting::Contains => {
            let write_note = if writable {
                " — and being read-write, the cage can write through to the host files around it"
            } else {
                ""
            };
            format!(
                "bind `{}` contains the sandbox's own mount `{structural}` — the cage mounts that \
                 path over part of it, so `{structural}` inside the cage is sbx's, not your \
                 bind's{write_note}",
                dest.display()
            )
        }
    })
}

/// mise's data directory inside the cage, relative to the sandbox `$HOME`. The
/// in-cage mise keeps its plugins, installs and state here — under the writable
/// per-project home, so they persist across launches and never touch the host's
/// real mise state. Also where the plugin registration symlink is placed.
const MISE_DATA_REL: &str = ".local/share/mise";

/// mise's shims directory inside the cage, relative to the sandbox `$HOME`. mise
/// writes a shim here for every tool it has *activated* (`mise use`); putting this
/// directory on PATH is mise's documented mechanism for making those tools available
/// without a shell hook — exactly `sbx run -- <cmd>`, which execs the command directly
/// with no shell to activate. The dir need not exist yet (an empty project has none);
/// a missing PATH entry is simply ignored.
const MISE_SHIMS_REL: &str = ".local/share/mise/shims";

/// Where a global app's per-project mise data pool is bound writable inside the cage — mise's
/// *primary* `MISE_DATA_DIR` for a global app. A global app's home (and thus its app-global mise
/// pool: installs, shims, global config) is shared across every project, but mise's install pool
/// must be per-project so a `nix:`-via-mise self-equip's install record aligns with the per-project
/// `/nix` store rather than trusting a stale app-global record that points at another project's
/// store. The app-global pool's installs stay reachable as a read-only shared fallback
/// (`MISE_SHARED_INSTALL_DIRS`), preserving cross-project reuse of the agent's own tools. mise
/// derives its config/state/cache dirs from `$HOME` (XDG), so those stay app-global untouched — only
/// the data dir (installs, shims, plugins, downloads) moves. Under `/opt/sbx`, disjoint from every
/// structural mount. Only a global app supplies it; `sbx run` and a per-project app already root
/// their home — and therefore mise's data dir — per-project, so they keep the single-pool wiring.
const MISE_PROJECT_INCAGE: &str = "/opt/sbx/mise-project";

/// mise's app-global data dir inside the cage — the sandbox `$HOME`'s mise dir. For a global app,
/// Lane-1 `mise use -g` of an app `[packages] mise:` tool must run pinned here (not the per-project
/// primary [`MISE_PROJECT_INCAGE`]) so the tool is installed once and shared across every project,
/// and so the housekeeping read-path (`sbx app show`/`list`/`gc`, which enumerate the home's mise
/// installs) sees it. For `sbx run`/a per-project app this is already mise's ambient primary, so the
/// pin is a no-op. A fixed cage path (no per-launch data), returned as an owned `String` for the
/// launch's equip wrap.
pub(crate) fn mise_app_global_data_dir() -> String {
    format!("{SANDBOX_HOME}/{MISE_DATA_REL}")
}

/// Where a `flake:` package's `nix build --out-link` gcroot lives inside the cage,
/// relative to the sandbox `$HOME`. Each package gets `<this>/<name>`, a symlink into
/// `/nix` (the per-project store); its `<name>/bin` joins PATH. Under the persistent home,
/// so the out-link survives across launches (the warm-launch short-circuit reuses it).
pub(crate) const FLAKE_ROOTS_REL: &str = ".local/state/sbx/flake";

/// The directory holding every `flake:` package's out-link inside the cage (the parent the
/// build wrapper creates before `nix build`). A fixed, sbx-owned path under the home.
pub(crate) fn flake_roots_dir() -> PathBuf {
    PathBuf::from(format!("{SANDBOX_HOME}/{FLAKE_ROOTS_REL}"))
}

/// The in-cage out-link path for the `flake:` package named `name` — the gcroot `nix build
/// --out-link` writes, and the symlink whose `/bin` joins PATH. The name is a validated
/// package name (no path separators), so this never escapes [`flake_roots_dir`].
pub(crate) fn flake_out_link(name: &str) -> PathBuf {
    flake_roots_dir().join(name)
}

/// The content-hash-keyed in-cage out-link for the inline flake `name` whose source hashes to
/// `hash` — an inline `[flakes.<name>]` has no revision to key by, so its source content hash
/// distinguishes builds. Editing the flake changes the hash, so the out-link path is absent and the
/// warm short-circuit rebuilds (the stale build is left unrooted, so `sbx gc` reclaims it). `name`
/// is a validated package name and `hash` is hex, so neither escapes [`flake_roots_dir`].
///
/// Residual (the same class as the rev-keyed remote out-links, but accruing per *edit* rather than
/// per `sbx upgrade`): each edit leaves the old `<name>-<oldhash>` symlink dangling in the home. The
/// store path it pointed at is reclaimed (its `sbx-flake-<name>` gcroot was re-pointed to the new
/// build), so only the dead symlink lingers; re-editing back to a prior source reuses its surviving
/// out-link. Cleaning the dead symlinks is an `sbx gc` concern, not a per-launch one.
pub(crate) fn flake_out_link_hash(name: &str, hash: &str) -> PathBuf {
    flake_roots_dir().join(format!("{name}-{hash}"))
}

/// Where an inline `[flakes.<name>]` flake's staged directory is bound read-only inside the cage,
/// so the in-cage `nix build path:<this>#<attr>` reads exactly the trusted source. Under `/opt/sbx`,
/// beside the mise plugin and synthetic rc, colliding with no structural mount. `name` is a
/// validated package name (no path separators), so this never escapes `/opt/sbx/flakes`.
pub(crate) fn flake_inline_incage(name: &str) -> PathBuf {
    PathBuf::from(format!("/opt/sbx/flakes/{name}"))
}

/// Where the synthetic interactive-shell rc is bound read-only. an interactive `sbx run` starts
/// bash with `--rcfile` pointing here, so mise is activated in the interactive shell —
/// mise's documented interactive mechanism (a prompt hook that manages PATH/env for the
/// project's activated tools). `sbx run` does not use it; its tools come from the shims
/// dir on PATH. Under `/opt/sbx`, beside the mise plugin, colliding with no structural
/// mount.
pub(crate) const SHELL_RC_INCAGE: &str = "/opt/sbx/bashrc";

/// The synthetic interactive-shell rc: set a default prompt that names the cage, show the
/// egress contract once (to stderr, so a captured stdout stays clean), source the home's own
/// `.bashrc` if the agent has written one, then activate mise so its activated tools manage
/// PATH/env. Static (no per-project data, so the same bytes back every cage), bound read-only
/// from outside every writable mount, so the agent cannot rewrite what its own shell sources.
/// The prompt uses `\h`, which resolves to the cage's `sbx-<slug>` hostname, so an interactive `sbx run`
/// reads `(sbx-<slug>) <cwd>$` instead of the bare `bash-<v>$` default — set *before* the
/// `.bashrc` source so a home's own `PS1` still wins. The contract `cat` is guarded on the
/// variable being set and readable, so it is a no-op where the handle is absent.
const SHELL_RC_CONTENTS: &str = "\
PS1='(\\h) \\w\\$ '\n\
[ -r \"$SBX_EGRESS_CONTRACT\" ] && cat \"$SBX_EGRESS_CONTRACT\" >&2\n\
[ -r \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\n\
command -v mise >/dev/null 2>&1 && eval \"$(mise activate bash)\"\n";

/// The structural environment that turns the cage's mise into a working
/// self-equip front-end. Lowest precedence (a trusted config may still override
/// it, which only harms that project's own in-cage builds):
/// - `MISE_DATA_DIR` anchors mise's install/shim/plugin pool, where sbx has placed
///   the `nix:` backend plugin registration. It is the app-global home's mise dir
///   for `sbx run` and a per-project app (whose home is already per-project), but the
///   dedicated per-project pool ([`MISE_PROJECT_INCAGE`]) for a **global app**, whose
///   home — and therefore whose default mise dir — is shared across every project;
/// - `MISE_SHARED_INSTALL_DIRS` (global app only) points mise at the app-global pool's
///   installs as a **read-only fallback**, searched only when the per-project primary
///   lacks a tool. This preserves cross-project reuse of the agent's own tools after the
///   primary moves per-project. mise derives its config/state/cache dirs from `$HOME`
///   (XDG), so a global app's activation records and caches stay app-global untouched —
///   only the data dir moves;
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
///   rather than relying on nix's silent fallback. A btrfs-backed store
///   (`store_on_btrfs`, probed by the launcher off the `/nix` mount source) adds a
///   fourth line, `extra-ignored-acls = btrfs.compression`, mirroring the
///   host-side invocations: on a compressed btrfs volume every file created under
///   the per-project store inherits that attribute, and nix's store
///   canonicalisation — which strips extended attributes — fails with
///   `Permission denied` on a file the builder already made read-only; ignoring
///   the attribute keeps in-cage builds working there. The `NIX_CONFIG` key is on the
///   untrusted-only env denylist. `MISE_DATA_DIR`/`MISE_SHARED_INSTALL_DIRS` are data
///   paths (not code-load paths like `NIX_LD`), so — like `MISE_EXPERIMENTAL`/`MISE_YES`
///   — they are not denylisted: an untrusted `[env]` override only mispoints the
///   project's own cage's mise (self-sabotage), never a loader/`AT_SECURE` escape.
///
/// `per_project_primary` selects the split: `true` for a global app (primary moves
/// per-project, app-global installs become the read-only fallback), `false` otherwise
/// (single app-global-home pool, the historical wiring).
fn mise_env(per_project_primary: bool, store_on_btrfs: bool) -> Vec<(String, String)> {
    let mut nix_config = "extra-experimental-features = nix-command flakes\n\
                          sandbox = false\n\
                          filter-syscalls = false"
        .to_string();
    if store_on_btrfs {
        nix_config.push_str("\nextra-ignored-acls = btrfs.compression");
    }
    let mut env = vec![
        (
            "MISE_DATA_DIR".to_string(),
            if per_project_primary {
                MISE_PROJECT_INCAGE.to_string()
            } else {
                format!("{SANDBOX_HOME}/{MISE_DATA_REL}")
            },
        ),
        ("MISE_EXPERIMENTAL".to_string(), "1".to_string()),
        ("MISE_YES".to_string(), "1".to_string()),
        ("NIX_CONFIG".to_string(), nix_config),
    ];
    if per_project_primary {
        env.push((
            "MISE_SHARED_INSTALL_DIRS".to_string(),
            format!("{SANDBOX_HOME}/{MISE_DATA_REL}/installs"),
        ));
    }
    env
}

/// Where sbx's CA bundle appears in the cage. The cacert tree is bound at `/etc/ssl`
/// (replacing the host's), so the bundle sits at the path nix and OpenSSL look for by
/// default.
pub(super) const CAGE_CA_BUNDLE: &str = "/etc/ssl/certs/ca-bundle.crt";

/// The CA-bundle environment, naming sbx's own bundle so the cage's toolchains trust it
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

/// The synthetic `/etc/hosts`: `localhost` (and the cage's own `sbx-<slug>` hostname) mapped to
/// loopback, so a name lookup of either resolves via the file without reaching DNS — which the
/// cage's empty netns has no resolver for. Only these loopback mappings appear; no host entry is
/// leaked. The hostname is placed on the `localhost` lines so a tool that resolves its own
/// hostname (`gethostname` → `getaddrinfo`) also gets a loopback answer instead of a DNS failure.
fn hosts_contents(hostname: &str) -> String {
    format!(
        "127.0.0.1\tlocalhost {hostname}\n\
         ::1\tlocalhost ip6-localhost ip6-loopback {hostname}\n"
    )
}

/// A synthetic `/etc/machine-id` (systemd format: 32 lowercase hex digits, newline-terminated),
/// deterministically derived from the cage's own home path so it is **stable across launches of the
/// same app-home and unique per home** — never the host's real machine-id (which the hermetic cage
/// does not carry, and which would leak a host identifier). A hermetic cage otherwise has no
/// `/etc/machine-id`, `/var/lib/dbus/machine-id`, or MAC, so a desktop app that fingerprints the
/// machine (some editors read `cat /var/lib/dbus/machine-id /etc/machine-id || hostname` to build
/// a device id) falls back to hashing an empty string — producing the *same* id in every such cage,
/// which the app's server-side anti-abus then reads as one machine running countless accounts. A
/// per-home synthetic id gives each app a distinct, persistent machine identity instead. The input is
/// domain-separated so the raw home path is not recoverable from the id.
fn machine_id_contents(home_src: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sbx-cage-machine-id\0");
    h.update(home_src.as_os_str().as_encoded_bytes());
    let digest = h.finalize();
    let mut id = String::with_capacity(33);
    for byte in &digest[..16] {
        id.push_str(&format!("{byte:02x}"));
    }
    id.push('\n');
    id
}

/// Which persistent runtime a launch uses — the writable `$HOME` and its sibling synthetic
/// `/etc`. `sbx run` use the project's shared default; an app gets a dedicated,
/// persistent home so its config, login state, and history never bleed into the project shell
/// or another app. An app's home is either shared across projects (`GlobalApp`, one identity
/// everywhere) or keyed per-project (`ProjectApp`, isolated per project).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Runtime<'a> {
    /// The project's default shared home — `sbx run`.
    ProjectDefault,
    /// `sbx app <name>` with one home per app, shared across every project.
    GlobalApp(&'a str),
    /// `sbx app <name>` with a home per (project, app).
    ProjectApp(&'a str),
}

/// Host-side runtime paths for `project` under sbx's data directory, for the given
/// [`Runtime`]. The home and the synthetic `/etc` are always siblings so the latter sits
/// outside every read-write bind (module integrity note). An app name is a validated single
/// path component (the config app-name check), so joining it cannot traverse out of the data
/// directory.
fn project_runtime(data_dir: &Path, project: &Path, runtime: Runtime) -> ProjectRuntime {
    let project_base = || data_dir.join("projects").join(project_id(project));
    let (base, mise_project_src) = match runtime {
        Runtime::ProjectDefault => (project_base(), None),
        // A global app's home is project-independent — keyed only by the app name, so the same
        // identity is reused in every project. Its mise data pool, however, is keyed per (project,
        // app) — `projects/<id>/apps/<name>/mise`, the same base a per-project app roots its home
        // under, plus `/mise` — so a `nix:` self-equip's install record aligns with the per-project
        // `/nix` store and never points at another project's store. App-keyed (not project-keyed),
        // so a tool the agent self-equips in app A stays private to app A, preserving per-app
        // isolation for mise install records exactly as before the split.
        Runtime::GlobalApp(name) => (
            data_dir.join("apps").join(name),
            Some(project_base().join("apps").join(name).join("mise")),
        ),
        // A per-project app's home nests under the project, isolating its state per project — its
        // mise data dir is therefore already per-project-aligned, so it keeps the single-pool wiring.
        Runtime::ProjectApp(name) => (project_base().join("apps").join(name), None),
    };
    ProjectRuntime {
        home_src: base.join("home"),
        etc_dir: base.join("etc"),
        mise_project_src,
    }
}

/// The host path of the cage's persistent `$HOME` for this launch — the exact directory
/// [`build_spec`] binds writable as the home (derived identically: canonicalise the cwd, then
/// [`project_runtime`]). Lets a host-side helper place a file the cage reads through the home bind
/// (the live-theme keyfile the in-cage portal watches).
pub(crate) fn home_src(data_dir: &Path, cwd: &Path, runtime: Runtime) -> io::Result<PathBuf> {
    let project = canonicalize_project(cwd)?;
    Ok(project_runtime(data_dir, &project, runtime).home_src)
}

/// A collision-resistant directory name for a canonical project path, stable within a given binary
/// build. Housekeeping hashes a running session's recorded canonical path with this to match it
/// against a runtime tree's id, so it can skip a tree a live session still holds. The hash is
/// `DefaultHasher`, whose output std does not guarantee equal across toolchain/std versions, so a
/// future build could re-key a project's trees (GC/re-seed heals the orphaned ones); switch to a
/// specified hash here if cross-build stability is ever required.
pub(crate) fn project_id(project: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    project.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// The stable per-project identity sbx keys runtime state on. The writable home,
/// the synthetic identity, and a project's garbage-collection roots all derive from
/// it, so housekeeping can reclaim a project's tools alongside the rest of its
/// runtime. Canonicalises first, so a relative or symlinked `cwd` maps to the same
/// identity as the real path (the same pin [`canonicalize_project`] applies to the
/// bind source).
pub(crate) fn project_runtime_id(cwd: &Path) -> io::Result<String> {
    Ok(project_identity(cwd)?.0)
}

/// The per-project identity together with the canonical project path it derives from. The id keys
/// the project's runtime tree (home, store, gcroots); the canonical path is what a launch records
/// in a durable marker so housekeeping can later recognise — and reclaim — that tree once the
/// project directory is gone (the id alone is a one-way hash). Canonicalises once, so id and path
/// agree and both match the bind source's pinned location.
pub(crate) fn project_identity(cwd: &Path) -> io::Result<(String, PathBuf)> {
    let canonical = canonicalize_project(cwd)?;
    let id = project_id(&canonical);
    Ok((id, canonical))
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

/// Build a launch-ready [`SandboxSpec`] for `cwd` under sbx's `data_dir`. This is
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
/// Write `bytes` to `path` atomically: a unique temp sibling (named by pid, so concurrent launches
/// do not collide on it) written then renamed over `path`. A concurrent cage that binds this file
/// read-only then sees either the complete old or complete new content — never a torn half-write —
/// and, because the rename installs a fresh inode, a cage already bound to the prior inode keeps its
/// own view rather than observing a later launch's overwrite.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

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
    egress_contract: &str,
    seccomp: super::seccomp::SeccompPolicy,
    devices: &[PathBuf],
    cmd: Vec<OsString>,
) -> io::Result<SandboxSpec> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let project = canonicalize_project(cwd)?;
    let rt = project_runtime(data_dir, &project, runtime);

    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&rt.home_src)?;
    let (passwd, group) = materialize_etc(&rt.etc_dir, &current_identity())?;

    // Materialize the synthetic interactive-shell rc beside the synthetic identity
    // (outside every writable mount, so it has no writable alias the agent could use to
    // rewrite it); an interactive `sbx run` binds it read-only and points bash's `--rcfile` at it.
    let shell_rc = rt.etc_dir.join("bashrc");
    write_atomic(&shell_rc, SHELL_RC_CONTENTS.as_bytes())?;

    // Materialize the generated egress contract beside the rc (same outside-every-writable-
    // mount placement, for the same reason: the agent must not be able to rewrite the
    // contract it is told to read). Regenerated each launch, so it never goes stale. Written
    // atomically (temp + rename) because this directory is shared by concurrent cages of the
    // same project — an in-place write could show a running cage a torn, half-written file.
    let contract = rt.etc_dir.join("egress-contract.md");
    write_atomic(&contract, egress_contract.as_bytes())?;

    // Materialize the synthetic `xdg-open` stub beside the other synthetic files
    // (outside every writable mount, so it has no writable alias the agent could
    // rewrite), then make it executable so a tool calling `xdg-open` runs it.
    let xdg_open = rt.etc_dir.join("xdg-open");
    write_atomic(&xdg_open, XDG_OPEN_CONTENTS.as_bytes())?;
    std::fs::set_permissions(&xdg_open, std::fs::Permissions::from_mode(0o755))?;

    // Materialize the embedded mise `nix:` backend plugin (read-only, content-keyed,
    // shared across projects) and register it for this cage's mise: a symlink in the
    // writable mise data dir pointing at the read-only in-cage plugin. Both run on
    // every launch so an sbx upgrade (a changed embedded tree) re-stages and re-points.
    //
    // The registration goes under mise's *primary* data dir, which `MISE_PLUGINS_DIR`
    // follows. The app-global home's mise dir is always a primary: it is the sole pool for
    // `sbx run`/a per-project app, and for a global app it is where Lane-1 `mise use -g` of
    // an app `[packages] mise:` tool runs (pinned there so the tool is shared across projects).
    // A global app *additionally* has the per-project pool ([`MISE_PROJECT_INCAGE`]) as the
    // ambient primary for a project `.mise.toml`/`nix:` self-equip, so the plugin is registered
    // there too (and the pool created owner-only, so the writable bind has an existing source) —
    // otherwise that mise would find no `nix:` backend and self-equip would break.
    let mise_plugin = super::miseplugin::stage(data_dir)?;
    let mut mise_plugin_dirs = vec![rt.home_src.join(MISE_DATA_REL).join("plugins")];
    if let Some(pool) = &rt.mise_project_src {
        DirBuilder::new().recursive(true).mode(0o700).create(pool)?;
        mise_plugin_dirs.push(pool.join("plugins"));
    }
    for dir in &mise_plugin_dirs {
        super::miseplugin::register(dir)?;
    }

    // The cage's readable name: the app name for `sbx app <name>`, else the project's own
    // directory name. Carried on the spec so the scope, hostname, and session listing all
    // read the same slug. Computed here (not only at the end) because the synthetic
    // `/etc/hosts` maps the cage hostname derived from it.
    let app = match runtime {
        Runtime::ProjectDefault => None,
        Runtime::GlobalApp(name) | Runtime::ProjectApp(name) => Some(name),
    };
    let slug = super::naming::cage_slug(app, &project);

    // Materialize the synthetic `/etc/hosts` beside the other synthetic files (outside every
    // writable mount, so the agent has no writable alias to rewrite the name resolution it
    // relies on). It maps `localhost` and the cage's own `sbx-<slug>` hostname to loopback;
    // the hostname matches the `--hostname` the launch sets, both from this same slug.
    let hosts = rt.etc_dir.join("hosts");
    write_atomic(
        &hosts,
        hosts_contents(&super::naming::cage_hostname(&slug)).as_bytes(),
    )?;

    // A synthetic `/etc/machine-id`, stable per app-home and unique per home, materialized beside
    // the other synthetic `/etc` files (outside every writable mount, so the agent has no writable
    // alias to forge its own machine identity). Bound read-only at both conventional paths so a
    // desktop app's fingerprinting reads a distinct, persistent id instead of hashing an empty
    // string (identical in every hermetic cage).
    let machine_id = rt.etc_dir.join("machine-id");
    write_atomic(&machine_id, machine_id_contents(&rt.home_src).as_bytes())?;

    let paths = SandboxPaths {
        project: &project,
        home_src: &rt.home_src,
        mise_project_src: rt.mise_project_src.as_deref(),
        passwd_src: &passwd,
        group_src: &group,
        mise_plugin_src: &mise_plugin,
        shell_rc_src: &shell_rc,
        contract_src: &contract,
        xdg_open_src: &xdg_open,
        hosts_src: &hosts,
        machine_id_src: &machine_id,
    };
    assemble(
        &paths,
        userland,
        nix,
        overlay,
        extra_binds,
        devices,
        net,
        cmd,
    )
    .map(|spec| spec.with_cage_slug(slug).with_seccomp(seccomp))
    .map_err(|e| {
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
            socat_bin: PathBuf::from("/store/socat/bin/socat"),
            mise_bin: PathBuf::from("/store/mise/bin/mise"),
            nix_bin: PathBuf::from("/store/nix/bin/nix"),
            locale_archive: PathBuf::from("/nix/store/locales/lib/locale/locale-archive"),
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

    fn assembled() -> SandboxSpec {
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/sbx/projects/abc/home"),
            mise_project_src: None,
            passwd_src: Path::new("/data/sbx/projects/abc/etc/passwd"),
            group_src: Path::new("/data/sbx/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
            contract_src: Path::new("/store/egress-contract.md"),
            xdg_open_src: Path::new("/data/sbx/projects/abc/etc/xdg-open"),
            hosts_src: Path::new("/data/sbx/projects/abc/etc/hosts"),
            machine_id_src: Path::new("/data/sbx/projects/abc/etc/machine-id"),
        };
        let env = [("TERM".to_string(), "xterm".to_string())];
        let overlay = Overlay {
            env: &env,
            binds: &[],
            bin_paths: &[],
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

    #[test]
    fn structural_dests_lists_every_fixed_mount_assemble_emits() {
        // The bind-nesting warning checks a config bind against STRUCTURAL_DESTS, a hand-kept copy
        // of the destinations `assemble` mounts. If a new structural mount is added without
        // extending the const, the warning silently goes blind to it — so pin the two together.
        // `assembled()` has no config binds and no extra binds, so its only runtime-variable
        // destination is the project path; every other destination must be listed in the const.
        let spec = assembled();
        let project = Path::new("/home/u/proj");
        for mount in &spec.mounts {
            let dest = mount.dest();
            if dest == project {
                continue;
            }
            assert!(
                STRUCTURAL_DESTS.iter().any(|s| Path::new(s) == dest),
                "structural mount destination {dest:?} is not in STRUCTURAL_DESTS — list it, or \
                 the bind-nesting warning will not catch a config bind that overlaps it"
            );
        }
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

    #[test]
    fn the_synthetic_hosts_maps_localhost_and_the_cage_hostname() {
        let h = hosts_contents("sbx-agy");
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
        // app produces when the file is absent — the whole reason this exists.
        assert_ne!(body, "e3b0c44298fc1c149afbf4c8996fb9242");
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
        let w =
            structural_nesting_warning(Path::new("/tmp/secrets"), false).expect("descendant warns");
        assert!(w.contains("shadowed"), "descendant message: {w}");
        assert!(w.contains("/tmp"));
        // A non-`/dev` shadowed bind carries no device hint.
        assert!(!w.contains("[devices]"), "no device hint off /dev: {w}");

        // A `/dev/*` bind is shadowed AND steered to `[devices]` (the field that actually exposes a
        // device with device access — a plain bind would be visible but `nodev`).
        let w = structural_nesting_warning(Path::new("/dev/dri"), false).expect("/dev/* warns");
        assert!(w.contains("shadowed"), "/dev message: {w}");
        assert!(
            w.contains("[devices]"),
            "a /dev/* bind must be steered to [devices]: {w}"
        );

        // An ancestor of structural files over-exposes the directory around them.
        let w = structural_nesting_warning(Path::new("/etc"), false).expect("ancestor warns");
        assert!(w.contains("contains"), "ancestor message: {w}");
        // A read-only ancestor says nothing about writing.
        assert!(
            !w.contains("write through"),
            "ro ancestor must not mention writing: {w}"
        );

        // A read-write ancestor additionally flags the host write-through.
        let w = structural_nesting_warning(Path::new("/etc"), true).expect("rw ancestor warns");
        assert!(
            w.contains("write through"),
            "a rw ancestor bind must flag host write-through: {w}"
        );

        // An exact match is reconciled by `assemble` (the structural mount wins) — not a footgun.
        assert!(structural_nesting_warning(Path::new("/nix"), false).is_none());
        assert!(structural_nesting_warning(Path::new("/etc/passwd"), true).is_none());

        // A path that neither contains nor sits under any structural mount is fine. `/etcdata`
        // shares a textual prefix with `/etc/...` but not a path lineage, so it must not warn.
        assert!(structural_nesting_warning(Path::new("/srv/data"), true).is_none());
        assert!(structural_nesting_warning(Path::new("/etcdata"), false).is_none());
        assert!(structural_nesting_warning(Path::new("/home/u/proj"), false).is_none());
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
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/sbx/projects/abc/home"),
            mise_project_src: None,
            passwd_src: Path::new("/data/sbx/projects/abc/etc/passwd"),
            group_src: Path::new("/data/sbx/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
            contract_src: Path::new("/store/egress-contract.md"),
            xdg_open_src: Path::new("/data/sbx/projects/abc/etc/xdg-open"),
            hosts_src: Path::new("/data/sbx/projects/abc/etc/hosts"),
            machine_id_src: Path::new("/data/sbx/projects/abc/etc/machine-id"),
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
            bin_paths: &[],
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
        let argv = super::super::argv::to_argv(&spec);
        let joined = argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        let path_i = joined.iter().position(|s| s == "PATH").unwrap();
        // mise's shims dir sits between the (here empty) declared tools and the base
        // userland, so an agent-activated tool surfaces ahead of base on a name clash; the
        // synthetic `/usr/bin` (env + xdg-open) trails so `xdg-open` resolves by name.
        assert_eq!(
            joined[path_i + 1],
            "/home/sandbox/.local/share/mise/shims:/store/bash/bin:/store/coreutils/bin:/usr/bin"
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

    #[test]
    fn assemble_emits_launcher_extra_binds_after_the_structural_mounts() {
        // The egress machinery binds (the socket, the CA) must land *after* the tmpfs, so the
        // socket sits on a writable mountpoint, and carry their declared mode.
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/sbx/projects/abc/home"),
            mise_project_src: None,
            passwd_src: Path::new("/data/sbx/projects/abc/etc/passwd"),
            group_src: Path::new("/data/sbx/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
            contract_src: Path::new("/store/egress-contract.md"),
            xdg_open_src: Path::new("/data/sbx/projects/abc/etc/xdg-open"),
            hosts_src: Path::new("/data/sbx/projects/abc/etc/hosts"),
            machine_id_src: Path::new("/data/sbx/projects/abc/etc/machine-id"),
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
            bin_paths: &[],
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
        let paths = SandboxPaths {
            project: Path::new("/home/u/proj"),
            home_src: Path::new("/data/sbx/projects/abc/home"),
            mise_project_src: None,
            passwd_src: Path::new("/data/sbx/projects/abc/etc/passwd"),
            group_src: Path::new("/data/sbx/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
            contract_src: Path::new("/store/egress-contract.md"),
            xdg_open_src: Path::new("/data/sbx/projects/abc/etc/xdg-open"),
            hosts_src: Path::new("/data/sbx/projects/abc/etc/hosts"),
            machine_id_src: Path::new("/data/sbx/projects/abc/etc/machine-id"),
        };
        let overlay = Overlay {
            env: extra_env,
            binds: extra_binds,
            bin_paths: extra_bin_paths,
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
        // declared tools first, then mise's shims, then the base userland, then the
        // synthetic `/usr/bin` (env + xdg-open, sbx-owned) so `xdg-open` resolves by name.
        assert_eq!(
            argv[path_i + 1],
            "/nix/store/node/bin:/nix/store/python/bin:/home/sandbox/.local/share/mise/shims:/store/bash/bin:/store/coreutils/bin:/usr/bin"
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
            "/data/sbx/projects/abc/etc/xdg-open",
            "/usr/bin/xdg-open binds the staged stub"
        );
        assert_eq!(
            argv[xdg - 2],
            "--ro-bind",
            "/usr/bin/xdg-open is a read-only bind"
        );
    }

    #[test]
    fn xdg_open_contents_is_a_posix_sh_script_that_exits_zero() {
        // The stub must be a valid `#!/bin/sh` script (the cage synthesises that
        // path) that exits 0 — the whole point is a tool calling `xdg-open` does not
        // see a failure — and surface its argument so the user can act on it.
        assert!(
            XDG_OPEN_CONTENTS.starts_with("#!/bin/sh\n"),
            "the stub is a /bin/sh script"
        );
        assert!(
            XDG_OPEN_CONTENTS.contains("exit 0"),
            "the stub exits 0 so the caller treats the open as non-fatal"
        );
        assert!(
            XDG_OPEN_CONTENTS.contains("\"$@\""),
            "the stub surfaces the argument the tool passed"
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
        let argv = argv_strings(&assemble_with(&[], &[], &[]));
        let first_ro = argv.iter().position(|s| s == "--ro-bind").unwrap();
        assert_eq!(
            argv[first_ro + 1],
            "/data/sbx/store/nix",
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
                "SBX_SANDBOX",
                "SBX_EGRESS_CONTRACT",
                "LOCALE_ARCHIVE",
                "LANG",
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
            home_src: Path::new("/data/sbx/projects/abc/home"),
            mise_project_src: None,
            passwd_src: Path::new("/data/sbx/projects/abc/etc/passwd"),
            group_src: Path::new("/data/sbx/projects/abc/etc/group"),
            mise_plugin_src: Path::new("/store/mise-plugin"),
            shell_rc_src: Path::new("/store/bashrc"),
            contract_src: Path::new("/store/egress-contract.md"),
            xdg_open_src: Path::new("/data/sbx/projects/abc/etc/xdg-open"),
            hosts_src: Path::new("/data/sbx/projects/abc/etc/hosts"),
            machine_id_src: Path::new("/data/sbx/projects/abc/etc/machine-id"),
        };
        let nix = NixMount {
            src: PathBuf::from("/data/sbx/projects/abc/store/nix"),
            writable: true,
            on_btrfs: false,
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
            bin_paths: &[],
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
    fn mise_env_moves_the_primary_and_adds_a_shared_fallback_for_a_global_app() {
        // A global app splits mise storage: the primary data dir moves to the per-project pool
        // (installs align with the per-project /nix store) while the app-global home's installs
        // become a read-only fallback so the agent's own tools are not rebuilt per project. Every
        // other runtime keeps the single app-global-home pool (the historical wiring).
        let get = |env: &[(String, String)], k: &str| {
            env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone())
        };

        let single = mise_env(false, false);
        assert_eq!(
            get(&single, "MISE_DATA_DIR"),
            Some(format!("{SANDBOX_HOME}/{MISE_DATA_REL}"))
        );
        assert!(
            get(&single, "MISE_SHARED_INSTALL_DIRS").is_none(),
            "a single-pool cage has no shared-install fallback"
        );

        let split = mise_env(true, false);
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
            mise_env(false, on_btrfs)
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
        assert!(project_runtime(data, p1, Runtime::ProjectDefault)
            .mise_project_src
            .is_none());
        assert!(project_runtime(data, p1, Runtime::ProjectApp("demo-app"))
            .mise_project_src
            .is_none());

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
            xdg_open_src: Path::new("/data/sbx/apps/demo-app/etc/xdg-open"),
            hosts_src: Path::new("/data/sbx/apps/demo-app/etc/hosts"),
            machine_id_src: Path::new("/data/sbx/apps/demo-app/etc/machine-id"),
        };
        let env = [("TERM".to_string(), "xterm".to_string())];
        let overlay = Overlay {
            env: &env,
            binds: &[],
            bin_paths: &[],
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
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
            vec![OsString::from("/bin/sh")],
        )
        .expect("build spec");

        // The spec binds the pool, so the registration dir is reachable in-cage.
        assert!(spec
            .mounts
            .iter()
            .any(|m| m.dest() == Path::new(MISE_PROJECT_INCAGE)));

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
        let nix = crate::store::resolve_nix(None)?;
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
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };

        let project = TmpDir::new();
        std::fs::write(project.path().join("README"), b"hi").unwrap();

        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            // resolve the synthetic user, show `/usr` is the minimal synthetic tree (only
            // `bin`, never the host's), show `/usr/bin/env` resolves into sbx's store, list
            // the project
            OsString::from(
                "id -un; echo USR=$(ls /usr | tr '\\n' ','); echo ENV=$(readlink /usr/bin/env); ls",
            ),
        ];
        let env = [("TERM".to_string(), "dumb".to_string())];
        let overlay = Overlay {
            env: &env,
            binds: &[],
            bin_paths: &[],
        };
        // this smoke exercises the userland against the shared store, read-only — the
        // writable per-project store is the launcher's concern.
        let nix_mount = NixMount {
            src: crate::store::physical_path(&layout, Path::new("/nix")),
            writable: false,
            on_btrfs: false,
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
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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
        // hermetic: `/usr` is the minimal synthetic tree — only `bin` (which holds the
        // `env` symlink and the `xdg-open` stub), never the host's `/usr` (which would carry `lib`/`share`/…
        // alongside). The cage synthesises `/usr/bin/env` and nothing else under `/usr`.
        assert!(
            stdout.contains("USR=bin,"),
            "/usr is not the minimal synthetic tree (host /usr may have leaked):\n{stdout}"
        );
        // `/usr/bin/env` is the synthetic symlink into sbx's store, so an interpreted
        // tool's `#!/usr/bin/env <interp>` shebang resolves
        assert!(
            stdout.contains("ENV=/nix/store") && stdout.contains("bin/env"),
            "/usr/bin/env does not resolve into sbx's store:\n{stdout}"
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
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };
        // both halves consume the shared store read-only (the userland is what is under
        // test); the writable per-project store is the launcher's concern.
        let nix_mount = NixMount {
            src: crate::store::physical_path(&layout, Path::new("/nix")),
            writable: false,
            on_btrfs: false,
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
        // Forging runs the provisioned `patchelf` host-side. Its ELF interpreter is an absolute
        // `/nix/store/<glibc>/…ld-linux` path that resolves against the *host* store, not this
        // relocated one — so on a host whose system `/nix` lacks the channel's exact glibc build
        // (a fresh rolling-channel revision), `execve` returns ENOENT. That is an environment
        // limitation of host-side forging, not a sandbox fault: skip, do not fail.
        let pe = match Command::new(&patchelf)
            .args([
                "--set-interpreter",
                "/lib64/ld-linux-x86-64.so.2",
                "--remove-rpath",
            ])
            .arg(&foreign)
            .output()
        {
            Ok(pe) => pe,
            Err(e) => {
                eprintln!(
                    "skipping nix-ld smoke: cannot run a relocated-store patchelf host-side \
                     (its loader is not in the host /nix store): {e}"
                );
                return;
            }
        };
        if !pe.status.success() {
            eprintln!(
                "skipping nix-ld smoke: patchelf failed: {}",
                String::from_utf8_lossy(&pe.stderr)
            );
            return;
        }

        let bare = Overlay {
            env: &[],
            binds: &[],
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
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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
            binds: &[],
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
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
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
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };
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
            on_btrfs: false,
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
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
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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
    /// be a real local build from the seeded bash+coreutils. nix needs *no* sbx-supplied
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
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
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
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };
        // hello: realised into the shared store but NOT a seeded root — the discriminant's
        // non-seeded dependency. (jq was the original probe but is now in the curated base
        // toolset, so it IS seeded and could no longer serve as the non-seeded discriminant.)
        let hello = crate::store::provision(
            &nix,
            &layout,
            &data.path().join("roots").join("hello"),
            &base_ref,
            "hello",
            "bin/hello",
        )
        .expect("provision hello");

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
            r#"let b = builtins.storePath "@BASH@"; c = builtins.storePath "@CU@"; in derivation { name = "sbx-reuse-proof"; system = builtins.currentSystem; builder = "${b}/bin/bash"; args = ["-c" "${c}/bin/mkdir -p $out; ${c}/bin/echo ok > $out/result"]; }"#
                .replace("@BASH@", &bash_store.to_string_lossy())
                .replace("@CU@", &cu_store.to_string_lossy()),
        )
        .unwrap();
        // the discriminant: its only input is hello, which is in the shared store but not
        // in the seed — `builtins.storePath` against the per-project store rejects it, so
        // the build fails offline. That a *seeded* path succeeds while this one fails
        // proves the cage runs from the seed, not from the shared store at large.
        let discriminant = proj.join("discriminant.nix");
        std::fs::write(
            &discriminant,
            r#"let j = builtins.storePath "@HELLO@"; in derivation { name = "sbx-discriminant"; system = builtins.currentSystem; builder = "${j}/bin/hello"; args = []; }"#
                .replace("@HELLO@", &hello.to_string_lossy()),
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
            on_btrfs: false,
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
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
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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

    /// The `sbx mise` payoff: an agent self-equips a project's `nix:` tool from inside
    /// the open cage. The cage carries mise (in the base userland) with the embedded
    /// `nix:` backend plugin registered, so `mise install nix:jq` resolves jq through
    /// nixhub and builds it into the project's **own** writable store. Two things are
    /// proven: the tool genuinely installs and runs (the plugin path works end to end
    /// against the relocated single-user store), and — the multi-tenant boundary — the
    /// **shared store stays byte-identical**, since an in-cage install can only reach
    /// the project's store. Untrusted by construction (no `sbx trust`): the open-cage
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
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
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
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };

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
            on_btrfs: false,
        };
        let overlay = Overlay {
            env: &[],
            binds: &[],
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
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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
    /// non-interactive `sbx run` (a bare `jq` resolves *through the shim*), and
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
        let Some(nix_store) = crate::store::resolve_nix_store(None) else {
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
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &base_ref, &base_ref)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };

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
                on_btrfs: false,
            };
            let overlay = Overlay {
                env: &[],
                binds: &[],
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
                "",
                crate::sandbox::seccomp::SeccompPolicy::default(),
                &[],
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

        // cage 1: activate rg (ripgrep) — writes the global mise config + a shim into
        // the persistent home, builds rg into the project's own store. rg is chosen over
        // jq because jq is in the curated base toolset, so the base `jq` bin would already
        // be on PATH and muddy the shim-vs-real-bin distinction this test asserts.
        let (ok, _out, err) = run_script("mise use -g nix:ripgrep 1>&2");
        assert!(ok, "`mise use -g nix:ripgrep` failed:\n{err}");

        // cage 2: a brand-new spec. The shims dir on PATH resolves rg for a direct
        // (non-interactive) command; bash with the synthetic `--rcfile` activates mise,
        // which puts the real rg bin on PATH. The inner interactive bash has no
        // controlling terminal here, so its job-control notice is sent to /dev/null.
        let script = "set +e\n\
             echo \"SHIM_WHICH=$(command -v rg || echo NONE)\"\n\
             echo \"SHIM_VER=$(rg --version 2>/dev/null)\"\n\
             bash --rcfile /opt/sbx/bashrc -i -c 'echo \"ACT_WHICH=$(command -v rg || echo NONE)\"; echo \"ACT_VER=$(rg --version 2>/dev/null)\"' 2>/dev/null\n";
        let (ok, out, err) = run_script(script);
        assert!(ok, "the later launch failed:\n{err}\nstdout:\n{out}");
        let marker = |key: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or_else(|| panic!("missing marker {key} in:\n{out}"))
        };

        // `sbx run` (non-interactive): rg is on PATH via the shims dir, resolved through
        // the shim itself, and runs.
        assert!(
            marker("SHIM_WHICH").ends_with("/shims/rg"),
            "rg did not resolve through the shims dir: {}",
            marker("SHIM_WHICH")
        );
        assert!(
            marker("SHIM_VER").starts_with("ripgrep"),
            "the shimmed rg did not run: {}",
            marker("SHIM_VER")
        );

        // an interactive `sbx run`: mise activate (via `--rcfile`) puts the *real* tool
        // bin on PATH — ending in `/bin/rg`, not `/shims/rg`, so this proves activation
        // engaged rather than the shim doing the work again.
        assert!(
            marker("ACT_WHICH").ends_with("/bin/rg") && marker("ACT_WHICH").contains("/nix/store/"),
            "mise activate did not put the real rg bin on PATH: {}",
            marker("ACT_WHICH")
        );
        assert!(
            marker("ACT_VER").starts_with("ripgrep"),
            "the activated rg did not run: {}",
            marker("ACT_VER")
        );

        // the shared store is byte-identical — every launch only read it
        assert_eq!(
            before,
            fingerprint(&shared_paths),
            "the shared store changed under the activation launches"
        );
    }

    #[test]
    fn a_global_app_cage_puts_both_mise_shims_dirs_on_path_and_splits_the_pool() {
        // The real launch path (build_spec → to_argv → bwrap) must thread the global-app mise
        // split all the way into the cage: mise's primary at the per-project pool, the app-global
        // installs as the read-only fallback, and BOTH shims dirs on PATH. A unit test proves the
        // spec; only a real launch proves the generated argv carries it.
        let Some((bwrap, nix)) = prerequisites() else {
            eprintln!("skipping mise-split smoke: need bwrap, userns, and nix");
            return;
        };
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve nixpkgs");
        let Ok(userland) = super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
        else {
            eprintln!("skipping: base userland provisioning failed (cache or channel drift)");
            return;
        };

        let project = TmpDir::new();
        std::fs::write(project.path().join("README"), b"hi").unwrap();

        let cmd = vec![
            userland.shell_bin.clone().into_os_string(),
            OsString::from("-c"),
            OsString::from(
                "printf 'PATH=%s\\nDATA=%s\\nSHARED=%s\\n' \
                 \"$PATH\" \"$MISE_DATA_DIR\" \"$MISE_SHARED_INSTALL_DIRS\"",
            ),
        ];
        let env = [("TERM".to_string(), "dumb".to_string())];
        let overlay = Overlay {
            env: &env,
            binds: &[],
            bin_paths: &[],
        };
        let nix_mount = NixMount {
            src: crate::store::physical_path(&layout, Path::new("/nix")),
            writable: false,
            on_btrfs: false,
        };
        let spec = build_spec(
            data.path(),
            project.path(),
            Runtime::GlobalApp("demo-app"),
            &userland,
            &nix_mount,
            &overlay,
            &[],
            NetPolicy::Shared,
            "",
            crate::sandbox::seccomp::SeccompPolicy::default(),
            &[],
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
        // both shims dirs are on PATH (the per-project primary's and the app-global fallback's)
        assert!(
            stdout.contains(&format!("{MISE_PROJECT_INCAGE}/shims")),
            "per-project shims dir missing from PATH:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("{SANDBOX_HOME}/{MISE_SHIMS_REL}")),
            "app-global shims dir missing from PATH:\n{stdout}"
        );
        // mise's primary is the per-project pool, with the app-global installs as the fallback
        assert!(
            stdout.contains(&format!("DATA={MISE_PROJECT_INCAGE}")),
            "MISE_DATA_DIR is not the per-project pool:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("SHARED={SANDBOX_HOME}/{MISE_DATA_REL}/installs")),
            "MISE_SHARED_INSTALL_DIRS is not the app-global installs:\n{stdout}"
        );
    }
}
