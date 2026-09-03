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

mod nesting;
mod runtime;
mod synthetic;

use super::spec::{Mount, NetPolicy, SandboxSpec, SpecError};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

pub(crate) use self::nesting::structural_nesting_warning;
pub(crate) use self::runtime::{
    Runtime, home_src, project_id, project_identity, project_runtime_id,
};
use self::runtime::{canonicalize_project, project_runtime};
pub(super) use self::synthetic::hosts_contents;
use self::synthetic::{SHELL_RC_CONTENTS, current_identity, machine_id_contents, materialize_etc};

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
///
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

/// The in-sandbox `/usr/bin/ldd`, synthesised as a symlink to glibc's own `ldd`. A hermetic cage
/// has no host `/usr`, and the absence is not merely a missing convenience: a program that asks
/// which C library it is running on reads this **literal path** rather than searching `PATH`, so
/// it gets neither an answer nor an error it can act on. That was measured, on an Electron
/// application whose bundled `detect-libc` opens exactly this path: without it the application
/// took `SIGILL` seconds after start, and with it the same launch runs.
///
/// Like the other synthetic FHS names it adds no exposure — the answer it gives is which libc the
/// cage already runs, and the file it links to is in the base closure the cage already carries.
pub(super) const SANDBOX_LDD: &str = "/usr/bin/ldd";

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

/// The directory holding sbx's URL router, placed **first** on `PATH` — and the one place the
/// cage's `PATH` order is sbx's rather than the project's.
///
/// Everything else on `PATH` follows the rule stated where it is built: a declared tool wins over
/// an agent-activated one, which wins over the base userland, and the synthetic `/usr/bin` comes
/// last so it shadows nothing. That order leaves `xdg-open` resolvable from a directory the cage
/// can write: the mise shims directory lives in the writable home and precedes `/usr/bin`, so a
/// process inside the cage can drop its own `xdg-open` there and every later caller resolves it
/// — the read-only bind at [`XDG_OPEN_INCAGE`] is simply never reached.
///
/// What that substitution buys is narrow but real, and it is worth naming precisely. The cage is
/// one trust domain: a process inside it can already execute whatever it likes, so this is not an
/// escape and not a privilege boundary. What it buys is the ability to **substitute the page the
/// user asked for** — the user clicks "sign in", the application hands the URL to the router, and
/// a look-alike opens in the in-cage browser instead of the provider. Credentials the user types
/// there are for a third-party service the cage otherwise never sees. Displaying a page is
/// something anything in the cage can do unaided; intercepting a URL the *user* initiated is not.
///
/// So this directory is first, and it holds exactly one name — the router. The inversion is
/// bounded to that name deliberately: it is the name no project can usefully own (a hermetic cage
/// has no desktop, so a real `xdg-utils` here would open nothing), and the one profiles already
/// rewrite by hand for want of a way to declare it.
///
/// Both halves of that are enforced by the mount plan rather than merely arranged: every component
/// of this path is a mountpoint, so no ancestor can be renamed aside and rebuilt around a forged
/// router, and the directory itself is a read-only bind, so nothing in the cage can drop a second
/// name into the directory that leads `PATH`. See [`cage_mounts`] for the chain.
const OPEN_ROUTER_DIR: &str = "/opt/sbx/open";

/// Where the router is bound inside [`OPEN_ROUTER_DIR`]. The same file as [`XDG_OPEN_INCAGE`],
/// exposed under a second name: the FHS path stays for anything that calls it absolutely, and this
/// one is what `PATH` resolves.
const OPEN_ROUTER_INCAGE: &str = "/opt/sbx/open/xdg-open";

/// sbx's own directory inside the cage: the parent of [`OPEN_ROUTER_DIR`] and of everything else
/// the launcher mounts for its own plumbing (the egress CA, the task client, the mise pools).
const SBX_INCAGE_DIR: &str = "/opt/sbx";

/// The FHS parent of [`SBX_INCAGE_DIR`]. Named because the cage mounts it: it is the first link of
/// the router's mountpoint chain (see [`cage_mounts`]), not a path anything is bound *at*.
const OPT_DIR: &str = "/opt";

/// Where sbx's IANA zone database appears in the cage: the FHS path glibc, `iana-time-zone` and
/// every language runtime look under, so `TZDIR` names it and [`CAGE_LOCALTIME`] points into it.
pub(super) const CAGE_ZONEINFO: &str = "/usr/share/zoneinfo";

/// The cage's local-zone pointer. A **symlink** into [`CAGE_ZONEINFO`], never a copy of the zone
/// file: an FHS resolver reads the zone *name* by resolving this link and stripping the database
/// prefix, so a regular file here answers "what offset" but not "which zone" — the very question
/// the resolvers that failed without it are asking.
pub(super) const CAGE_LOCALTIME: &str = "/etc/localtime";

/// The zone a cage runs in when no config named one. UTC, not "absent": a cage with no
/// `/etc/localtime` fails an FHS zone resolver outright, and this is the one zone that is a real,
/// resolvable answer while disclosing nothing about where the host is. Naming a different zone is
/// the user's call ([`crate::config::Resolved::timezone`]), because *which* zone is a location
/// signal.
pub(crate) const DEFAULT_ZONE: &str = "UTC";

/// Where the synthetic ssh client config is bound read-only. This is OpenSSH's compiled-in
/// **system-wide** path (verified against the binary the cage actually runs), which is the last file
/// an ssh client reads: since the first value obtained for a keyword wins, a `~/.ssh/config` block
/// of the cage's own overrides everything written here. A hermetic cage carries no `/etc/ssh`, so
/// this shadows nothing.
pub(crate) const SSH_CONFIG_INCAGE: &str = "/etc/ssh/ssh_config";

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
    /// The glibc `ldd` `/usr/bin/ldd` links to. A hermetic cage has no host `/usr`, and a
    /// packaged application that asks which libc it is running on reads **that literal path**
    /// rather than searching `PATH` — `detect-libc`, bundled in a great many Node applications,
    /// is the one this was measured on. An in-sandbox logical path (it resolves through the store
    /// bound at `/nix`), and glibc's own `bin` output rather than the `out` the loader comes from,
    /// because `ldd` ships only in `bin`.
    pub(crate) ldd_bin: PathBuf,
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
    /// sbx's own IANA zone database (tzdata's `share/zoneinfo`), bound read-only at
    /// [`CAGE_ZONEINFO`] so a cage can resolve a zone name at all. A physical bind source (it
    /// backs a mount), like `ca_bundle_src` and unlike the locale archive, which is named by
    /// store path rather than bound. Ships only data, so it is off `PATH`.
    pub(crate) zoneinfo_src: PathBuf,
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
    /// The IANA zone the cage runs in — [`DEFAULT_ZONE`] unless a config named one, already
    /// validated against the provisioned database by the launcher (assembly stays pure, so a name
    /// reaching here is one the database carries). It is interpolated into the [`CAGE_LOCALTIME`]
    /// link target and into `TZ`.
    pub(crate) timezone: &'a str,
    /// The `mise:` tokens whose vendor a trusted layer declared as publishing continuously, so the
    /// cage's mise accepts a release with no cooling-off period for them. Empty for almost every
    /// cage; when it is empty no variable is set at all, so mise keeps its own default.
    pub(crate) fresh_release_tokens: &'a [String],
    /// The project mise files sbx declared inert, named to the cage's own mise so it skips them
    /// too. Empty whenever the project has none, or has one that is honored.
    pub(crate) ignored_mise_paths: &'a [std::path::PathBuf],
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
    /// Synthetic `xdg-open` script; bound read-only at [`XDG_OPEN_INCAGE`]. It is the single file
    /// inside [`Self::open_router_src`], so both in-cage names serve one staged source.
    xdg_open_src: &'a Path,
    /// The directory holding exactly that script and nothing else; bound read-only at
    /// [`OPEN_ROUTER_DIR`], the directory that leads the cage's `PATH`. Bound as a *directory* on
    /// purpose — see the mount in [`cage_mounts`] for the rename it is what refuses.
    open_router_src: &'a Path,
    /// Synthetic `/etc/hosts`; bound read-only at `/etc/hosts`.
    hosts_src: &'a Path,
    /// Synthetic system-wide ssh client config; bound read-only at `/etc/ssh/ssh_config`. `None`
    /// when no declared destination needs one, so no cage carries a file with nothing in it.
    ssh_config_src: Option<&'a Path>,
    /// Synthetic `/etc/machine-id`; bound read-only at `/etc/machine-id` and
    /// `/var/lib/dbus/machine-id`.
    machine_id_src: &'a Path,
    /// The generated desktop-entry directory and mime defaults, present only when `[open]` declares
    /// a handler. Bound read-only *inside the writable home*, at the locations the XDG lookup
    /// prefers: `$XDG_DATA_HOME` and `$XDG_CONFIG_HOME` are unset in the cage, so their defaults
    /// under `$HOME` are the highest-priority ones, and a copy anywhere else would be shadowed by
    /// one written there. Freezing the mountpoint is enough for exactly that reason — the lookup
    /// asks for these paths by name, and a read-only bind refuses both the write and the unlink
    /// that would replace them. Freezing the leaf alone was *not* enough: the directories above it
    /// were writable and renaming one carries the mount along, so [`cage_mounts`] pins every
    /// component of the path as a mountpoint too.
    ///
    /// The entry is bound as its whole *directory* rather than as one file, which is what makes the
    /// portal answer at all rather than only what makes it answer correctly — see
    /// [`super::openuri::APPLICATIONS_REL`].
    open_apps_src: Option<&'a Path>,
    /// The generated mime defaults; see [`Self::open_apps_src`]. Always set together with it.
    open_mimeapps_src: Option<&'a Path>,
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
    let mounts = cage_mounts(paths, userland, nix, overlay, extra_binds, devices);
    let env = cage_env(paths, userland, nix, overlay);
    SandboxSpec::new(paths.project.to_path_buf(), mounts, env, net, cmd)
}

/// The cage's mount plan, in the order bubblewrap will apply it.
///
/// **Order is the invariant.** bwrap acts on its argv in sequence, so a later mount shadows an
/// earlier one at the same target; the config-declared binds are therefore laid down first and every
/// structural mount below may shadow a colliding one. Nothing here reorders, and the comments at the
/// individual mounts record which of them depend on that.
///
/// The single mount emitted *before* the config binds is the [`OPT_DIR`] pin, and it is placed there
/// precisely so it shadows nothing: it exists to make the path a mountpoint, not to own what is
/// under it.
fn cage_mounts(
    paths: &SandboxPaths,
    userland: &Userland,
    nix: &NixMount,
    overlay: &Overlay,
    extra_binds: &[ExtraBind],
    devices: &[PathBuf],
) -> Vec<Mount> {
    // The first link of the router's mountpoint chain, and the one mount that precedes the config
    // binds. Without it `/opt` is an ordinary directory on the cage's writable root, and an ordinary
    // directory can be renamed even while it holds mountpoints: the kernel refuses the rename of a
    // mountpoint itself with `EBUSY`, but nothing stops `mv /opt /opt.bak` followed by recreating
    // `/opt/sbx/open/xdg-open` as the cage's own script — which every later `xdg-open` then
    // resolves, since that directory leads `PATH` ([`OPEN_ROUTER_DIR`]). A tmpfs here is a
    // mountpoint, so the rename fails. It is emitted before the config binds rather than with the
    // structural block because it must shadow nothing: a `[[binds]]` under `/opt` still lands inside
    // this tmpfs, and one *at* `/opt` replaces it with a mount of its own, which keeps the property
    // the pin is here for.
    let mut mounts: Vec<Mount> = vec![Mount::Tmpfs {
        dest: PathBuf::from(OPT_DIR),
    }];

    // Config-declared binds come next, so any structural mount below shadows a colliding one —
    // a config bind can never displace `/nix`, the synthetic `/etc/passwd`/`group`, the loader,
    // or the project itself, whether it is read-only or read-write. A `mode = "rw"` bind is a
    // read-write mount (the cage writes through to the host path); the default is read-only.
    mounts.extend(overlay.binds.iter().map(|b| {
        let (src, dest) = (b.path.clone(), b.path.clone());
        if b.writable {
            Mount::Bind { src, dest }
        } else {
            Mount::RoBind { src, dest }
        }
    }));

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
        // Zone 1 — the synthetic `/usr/bin/ldd`: what a program consults to learn whether it runs
        // on glibc or on musl. It reads this exact path instead of searching `PATH`, so a cage
        // without it leaves the question unanswered rather than failing in a way the caller can
        // handle — see [`SANDBOX_LDD`] for the failure that was measured. glibc is already in the
        // base closure; only its `bin` output, which is where `ldd` lives, joins it for this.
        Mount::Symlink {
            target: userland.ldd_bin.clone(),
            dest: PathBuf::from(SANDBOX_LDD),
        },
        // Zone 1 — the second link of the router's mountpoint chain: sbx's own in-cage directory,
        // a mountpoint so it cannot be renamed aside either (pinning only the leaf is useless —
        // renaming any ancestor moves the whole subtree, mounts included). A tmpfs rather than a
        // bind because everything else sbx mounts under it — the egress CA, the task client, the
        // mise pools — needs bwrap to create a mountpoint here, which a read-only bind refuses.
        // Structural, so a config bind inside sbx's own directory is shadowed by it.
        Mount::Tmpfs {
            dest: PathBuf::from(SBX_INCAGE_DIR),
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
        // Zone 1 — the third and last link of the chain: the staged directory holding that same
        // script, read-only, so the cage reaches it at [`OPEN_ROUTER_INCAGE`] — the copy `PATH`
        // actually resolves. Two names for one source rather than a move: the FHS path is what a
        // tool calling `/usr/bin/xdg-open` absolutely expects to find.
        //
        // The *directory* is bound, not the file, and that is what makes the two claims at
        // [`OPEN_ROUTER_DIR`] true. Binding only the file left the directory around it a writable
        // directory on the cage's root: it could be renamed aside and rebuilt with a forged router
        // in it, and it could be given a second name — which matters because this directory leads
        // `PATH`, so any name dropped in it shadows every declared tool. A read-only bind refuses
        // both (`EBUSY` on the rename, `EROFS` on the create).
        Mount::RoBind {
            src: paths.open_router_src.to_path_buf(),
            dest: PathBuf::from(OPEN_ROUTER_DIR),
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
        // Zone 1 — the IANA zone database from sbx's own store, at the FHS path every resolver
        // looks under, and the `/etc/localtime` link into it. A hermetic cage carries neither, and
        // a tool that resolves the local zone the FHS way then does not fall back to UTC: it fails
        // (a Rust agent's scheduler reports "local timezone could not be determined" and gives up).
        // The link is what carries the answer — a resolver reads the zone *name* from its target,
        // which is why it points at the in-cage database path rather than at the store — and it
        // exists in every cage, naming [`DEFAULT_ZONE`] unless a config chose otherwise. Both are
        // read-only from outside every writable mount, like the identity files: the database is
        // sbx's, and the link is the answer to a question the cage should not be able to rewrite
        // under a tool that already read it. The database discloses nothing about the host (it is
        // the same file everywhere); *which* zone the link names is the config's decision.
        Mount::RoBind {
            src: userland.zoneinfo_src.clone(),
            dest: PathBuf::from(CAGE_ZONEINFO),
        },
        Mount::Symlink {
            target: PathBuf::from(format!("{CAGE_ZONEINFO}/{}", overlay.timezone)),
            dest: PathBuf::from(CAGE_LOCALTIME),
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

    // Zone 1 — the synthetic system-wide ssh client config, present only when a declared `tcp://`
    // destination needs one: a privileged port gets no in-cage listener, so ssh has to ask the
    // cage's CONNECT proxy for it, and this is where that instruction is written. Read-only and
    // sourced from outside every writable mount, like the other synthetic `/etc` files. It is the
    // *system-wide* path on purpose — the last file ssh consults — so the cage's own
    // `~/.ssh/config` still wins, which keeps this an affordance rather than a constraint.
    if let Some(src) = paths.ssh_config_src {
        mounts.push(Mount::RoBind {
            src: src.to_path_buf(),
            dest: PathBuf::from(SSH_CONFIG_INCAGE),
        });
    }

    // What the in-cage portal reads to reach the router. Emitted *after* the writable home above,
    // so they layer over it rather than being shadowed by it — the whole point is that these paths
    // inside a writable directory are the ones the cage cannot rewrite.
    //
    // Both are preceded by a pin of every directory between the home and them, because a read-only
    // bind is unmovable only at its own path: `$HOME/.local` and `$HOME/.config` were ordinary
    // writable directories, and renaming one takes the mountpoint under it along, after which the
    // cage recreates the path with a desktop entry of its own and the XDG lookup — which asks for
    // these paths by name — reads that instead. The pins re-mount each intermediate on itself,
    // read-write, so the tree stays as writable as it was while every component of the path is a
    // mountpoint the kernel refuses to rename (`EBUSY`). Same shape, and the same reason, as the
    // control-plane pins the config loader emits around sbx's own roots.
    let open_rels: Vec<&str> = paths
        .open_apps_src
        .map(|_| super::openuri::APPLICATIONS_REL)
        .into_iter()
        .chain(
            paths
                .open_mimeapps_src
                .map(|_| super::openuri::MIMEAPPS_REL),
        )
        .collect();
    mounts.extend(home_mountpoint_pins(paths.home_src, &open_rels));
    if let Some(src) = paths.open_apps_src {
        mounts.push(Mount::RoBind {
            src: src.to_path_buf(),
            dest: PathBuf::from(format!(
                "{SANDBOX_HOME}/{}",
                super::openuri::APPLICATIONS_REL
            )),
        });
    }
    if let Some(src) = paths.open_mimeapps_src {
        mounts.push(Mount::RoBind {
            src: src.to_path_buf(),
            dest: PathBuf::from(format!("{SANDBOX_HOME}/{}", super::openuri::MIMEAPPS_REL)),
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
    // are shadowed by one. Most are sbx's own destinations (the egress socket under the tmpfs,
    // the proxy CA under `/opt/sbx`), whose parents are already mounted above (the tmpfs for the
    // socket, the userland binds' `/opt/sbx`).
    //
    // Two kinds deliberately land *on* a host path the structural block already mounted, and both
    // depend on arriving after it: the control-plane pins, which freeze sbx's own roots inside a
    // read-write bind, and the `[fs]` masks, which close a project path by mounting a decoy over
    // it. For those, "emitted last" is not tidiness but the mechanism.
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
    mounts
}

/// Make every directory between the writable home and each of `rels` a mountpoint of its own, so a
/// read-only bind at one of those paths cannot be moved out of the way by renaming a parent.
///
/// Read-write binds of the host home's own subdirectories: same source, same content, same mode —
/// all they change is that the kernel now refuses to rename or remove those components.
///
/// Returned shallow-to-deep, so a parent is mounted before its child: a child mounted first would be
/// shadowed when the parent landed on top of it, silently undoing the pin. A prefix two `rels`
/// share is pinned once — mounting it twice would work, but the second mount would hide the first
/// and leave the plan reading as though one of them were redundant.
///
/// The last component of each `rel` is deliberately not pinned: that is the path the caller binds.
///
/// The sources are the home's own subdirectories, which the caller has created (see `build_spec`) —
/// bwrap fails a bind whose source does not exist. Those subdirectories sit below a cage-writable
/// bind, so the caller creates them through [`super::cagedir::ensure_under`] anchored on the home's
/// mount point; a component the cage replaced with a symlink fails the launch there rather than
/// becoming the source of a read-write bind here. This function is pure and cannot check that
/// itself: it joins the paths the caller has already confined.
fn home_mountpoint_pins(home_src: &Path, rels: &[&str]) -> Vec<Mount> {
    let mut pinned: Vec<PathBuf> = Vec::new();
    for rel in rels {
        let mut relative = PathBuf::new();
        let components: Vec<&str> = rel.split('/').collect();
        for component in &components[..components.len().saturating_sub(1)] {
            relative.push(component);
            if !pinned.contains(&relative) {
                pinned.push(relative.clone());
            }
        }
    }
    pinned
        .into_iter()
        .map(|rel| Mount::Bind {
            src: home_src.join(&rel),
            dest: PathBuf::from(format!("{SANDBOX_HOME}/{}", rel.display())),
        })
        .collect()
}

/// The cage's environment: the sandbox `PATH` and the variables that describe the userland to what
/// runs inside it. Independent of the mount plan — it reads the same resolved paths but none of
/// [`cage_mounts`]'s output — which is why the two are assembled separately and joined only in
/// [`assemble`].
fn cage_env(
    paths: &SandboxPaths,
    userland: &Userland,
    nix: &NixMount,
    overlay: &Overlay,
) -> Vec<(String, String)> {
    // The sandbox PATH: sbx's URL router first, then the project's declared tools, then mise's
    // shims, then the base userland, so a declared tool wins over an agent-activated one, which
    // wins over the base. A tool the in-cage mise has activated (`mise use`) gets a shim in the
    // shims dir, so a later `sbx run -- <tool>` resolves it. `/bin/sh` and the loader are wired by
    // absolute path, not PATH, so prepending here never weakens them.
    //
    // The router leads, and it is the single exception to "a declared tool wins": the shims
    // directory sits in the writable home, so any other order lets the cage substitute its own
    // `xdg-open` for every later caller. The directory holds that one name and nothing else, which
    // is what keeps the exception from being a general inversion — see [`OPEN_ROUTER_DIR`] for what
    // the substitution would buy and why it is worth one name.
    let mut path_dirs = vec![PathBuf::from(OPEN_ROUTER_DIR)];
    path_dirs.extend(overlay.bin_paths.iter().cloned());
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
    // leak) is on PATH last, so declared tools, mise shims, and the base userland all win on a
    // name collision; `/usr/bin/env` is the same coreutils `env` already on PATH. It is no longer
    // how a bare `xdg-open` resolves — the router directory at the head is — so this entry now
    // serves only a caller that names `/usr/bin` explicitly.
    path_dirs.push(PathBuf::from("/usr/bin"));

    // Where the declared-operations client is bound, when the session offers any. On PATH because
    // the contract the cage reads tells an agent to run `sbx task run <name>` — an instruction that
    // resolves to nothing is worse than no instruction, since the agent concludes the operation is
    // unavailable and reaches for the underlying tool instead. Absent from a session that declares
    // no operation, and a PATH entry that does not exist costs nothing. Last, like the stub above,
    // so it can shadow nothing a project declared.
    path_dirs.push(PathBuf::from("/opt/sbx/bin"));

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
        // Timezone. `TZDIR` names the bound database so a runtime that resolves a zone by name
        // (glibc, and every language runtime that defers to it) finds one, and `TZ` states the
        // cage's zone outright so a tool that reads the variable agrees with the `/etc/localtime`
        // link rather than falling back to UTC beside it. The two are set *together*, never `TZ`
        // alone: with no database to resolve it against, glibc reads a zone name as a POSIX
        // abbreviation at offset zero, so a lone `TZ=Europe/Paris` leaves the cage printing
        // "Europe" as its zone at UTC — worse than unset. Structural (lowest precedence), like the
        // locale pair above: a trusted `[env]` may override them, which only mis-sets the
        // project's own cage clock.
        ("TZDIR".to_string(), CAGE_ZONEINFO.to_string()),
        ("TZ".to_string(), overlay.timezone.to_string()),
    ];
    env.extend(mise_env(
        paths.mise_project_src.is_some(),
        nix.on_btrfs,
        overlay.fresh_release_tokens,
        overlay.ignored_mise_paths,
    ));
    for (key, val) in overlay.env {
        upsert_env(&mut env, key, val);
    }
    env
}

/// The fixed in-cage destinations the structural mounts in [`assemble`] occupy — every mount
/// destination that does not depend on the specific project or app. The runtime-derived paths are
/// deliberately excluded (the project is mounted at its own absolute path, and a config bind that
/// overlaps the project tree is normal; the launcher's extra binds live at sbx's own paths), while
/// the fixed `SANDBOX_HOME` is listed. [`OPT_DIR`] is excluded for a different reason: it is the one
/// structural mount emitted *before* the config binds, so it shadows nothing and there is nothing to
/// warn about. A config bind whose canonical destination *nests* with one
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
    CAGE_ZONEINFO,
    CAGE_LOCALTIME,
    "/etc/resolv.conf",
    "/etc/ssl/certs/ca-certificates.crt",
    LOADER_DEST,
    SANDBOX_HOME,
    SANDBOX_SHELL,
    SANDBOX_BASH,
    SANDBOX_ENV,
    SANDBOX_LDD,
    XDG_OPEN_INCAGE,
    SBX_INCAGE_DIR,
    OPEN_ROUTER_DIR,
    OPEN_ROUTER_INCAGE,
    CAGE_CA_BUNDLE,
    SHELL_RC_INCAGE,
    SSH_CONFIG_INCAGE,
    super::miseplugin::INCAGE_DIR,
    MISE_PROJECT_INCAGE,
    super::contract::EGRESS_CONTRACT_INCAGE,
];

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
/// Residual, and this form is the only one that has it: a remote `flake:` package is built
/// host-side under one project gcroot that moves with the lock, while each edit here leaves the old
/// `<name>-<oldhash>` symlink dangling in the home. The
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
fn mise_env(
    per_project_primary: bool,
    store_on_btrfs: bool,
    fresh_release_tokens: &[String],
    ignored_mise_paths: &[std::path::PathBuf],
) -> Vec<(String, String)> {
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
    // Set here, in the cage's ambient environment, rather than in either of the two scripts that
    // invoke mise: the delay governs the **equip** (`mise use -g --pin`, at first launch) as much as
    // the roll (`mise upgrade --bump`), and those are built by different functions. One definition
    // is what makes a package that needs the exemption get it on both paths; putting it beside the
    // roll's own `MISE_DATA_DIR` prefix would have fixed the upgrade and left the launch failing.
    //
    // The separator is a comma, which mise is specific about: a space-, colon- or semicolon-joined
    // list is read as one unmatchable entry, so a cage exempting two packages would exempt neither.
    //
    // Absent rather than empty when nothing is named, so mise applies its own default instead of
    // being handed a list that excludes nothing.
    if !fresh_release_tokens.is_empty() {
        env.push((
            "MISE_MINIMUM_RELEASE_AGE_EXCLUDES".to_string(),
            fresh_release_tokens.join(","),
        ));
    }

    // The project mise files sbx declared inert, named to the cage's own mise so it declines them
    // too. Without this the verdict holds on one side of the cage wall only: sbx refuses to fold
    // the file into the resolved configuration and says so, while mise — which walks the working
    // directory, and the project tree is bound there at its real path — reads it anyway, resolves
    // the tools it declares and reaches for the network to do it. What the user sees of that is a
    // refused request against a host their configuration never named.
    //
    // This one is read while mise is still discovering config files, before any of them is parsed,
    // so it is an environment variable or nothing: setting it inside a config file would arrive
    // after the decision it governs.
    //
    // The separator is the platform's path separator. A path that contains one cannot be expressed
    // in such a list at all, so it is left out rather than joined into an entry that would name
    // neither it nor its neighbour — an unexpressible path is one file still read, where corrupting
    // the list would be every file in it.
    let nameable: Vec<String> = ignored_mise_paths
        .iter()
        .map(|p| p.display().to_string())
        .filter(|p| !p.contains(':'))
        .collect();
    if !nameable.is_empty() {
        env.push(("MISE_IGNORED_CONFIG_PATHS".to_string(), nameable.join(":")));
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
///
/// It carries one argument more than clippy's threshold, deliberately: the grouping discipline
/// (`SandboxPaths`) keeps the *audited* core — the pure [`assemble`] — at the limit, so the I/O
/// wrapper around it is the right place to absorb the extra resolved slice rather than widening
/// the surface a security review reads.
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
    tcp: &super::egress::TcpPlan,
    seccomp: super::seccomp::SeccompPolicy,
    devices: &[PathBuf],
    open: &std::collections::BTreeMap<String, crate::config::OpenHandler>,
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
    // rewrite it); an interactive `sbx run` binds it read-only and points bash's `--rcfile` at it.
    let shell_rc = rt.etc_dir.join("bashrc");
    super::atomicfile::write_atomic(&shell_rc, SHELL_RC_CONTENTS.as_bytes())?;

    // Materialize the generated egress contract beside the rc (same outside-every-writable-
    // mount placement, for the same reason: the agent must not be able to rewrite the
    // contract it is told to read). Regenerated each launch, so it never goes stale. Written
    // atomically (temp + rename) because this directory is shared by concurrent cages of the
    // same project — an in-place write could show a running cage a torn, half-written file.
    let contract = rt.etc_dir.join("egress-contract.md");
    super::atomicfile::write_atomic(&contract, egress_contract.as_bytes())?;

    // Materialize the URL router beside the other synthetic files (outside every writable mount, so
    // it has no writable alias the agent could rewrite), then make it executable so a tool calling
    // `xdg-open` runs it. Undeclared, it is the printing stub; with `[open]` it routes by scheme.
    // Regenerated every launch, so a handler removed from the config is gone from the next run.
    //
    // In a directory of its own, holding nothing else: that directory is what the cage binds at
    // [`OPEN_ROUTER_DIR`], and it leads the cage's `PATH`, so every name in it is a name the cage
    // resolves ahead of the project's tools. `write_atomic`'s temp sibling is the one other name
    // that appears here, briefly and never as an executable one.
    let open_router = rt.etc_dir.join("open");
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&open_router)?;
    let xdg_open = open_router.join("xdg-open");
    super::atomicfile::write_atomic_mode(
        &xdg_open,
        super::openuri::router(open).as_bytes(),
        Some(0o755),
    )?;

    // The portal's route to the same router: a desktop-entry directory and the mime defaults naming
    // it, staged here (outside every writable mount, like the router) and bound read-only at the
    // `$HOME` paths the XDG lookup prefers. Written only when a handler is declared — with none,
    // there is nothing to route and no reason to freeze a directory the cage did not ask for.
    // Regenerated every launch; a directory left by a previous launch of the same home is emptied
    // first, so a scheme dropped from the config stops being claimed.
    let (open_apps, open_mimeapps) = (
        rt.etc_dir.join("applications"),
        rt.etc_dir.join("mimeapps.list"),
    );
    let (open_apps_src, open_mimeapps_src) = if open.is_empty() {
        let _ = std::fs::remove_dir_all(&open_apps);
        let _ = std::fs::remove_file(&open_mimeapps);
        (None, None)
    } else {
        let _ = std::fs::remove_dir_all(&open_apps);
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&open_apps)?;
        super::atomicfile::write_atomic(
            &open_apps.join(super::openuri::DESKTOP_FILE),
            super::openuri::desktop_entry(open, OPEN_ROUTER_INCAGE).as_bytes(),
        )?;
        // The index the portal reads to find the claimants of a scheme. Generated because the
        // directory carrying it is read-only in the cage, so `update-desktop-database` cannot
        // produce it there.
        super::atomicfile::write_atomic(
            &open_apps.join("mimeinfo.cache"),
            super::openuri::mimeinfo_cache(open).as_bytes(),
        )?;
        super::atomicfile::write_atomic(&open_mimeapps, super::openuri::mimeapps(open).as_bytes())?;
        // bwrap creates a missing mountpoint, but it would create it in the *host* home this bind
        // exposes — leaving a stray empty file or directory behind after the cage is gone. Creating
        // the parents here (owner-only, like the mise pool) keeps that placement sbx's decision
        // rather than a side effect. They are also the *sources* of the mountpoint pins the cage
        // lays over them (see `home_mountpoint_pins`), and bwrap fails a bind whose source is
        // missing, so this loop is what makes those pins bindable at all.
        //
        // Anchored on `rt.home_src` through `cagedir`, not `create_dir_all`, because these parents
        // sit *below* a bind the cage owns: `.config` and `.local/share` are entries in-cage code
        // can replace with a symlink and leave behind for the next launch. `create_dir_all` stats
        // through such a link, finds a directory and reports the parents made; the pin then binds
        // whatever the link named — read-write, since these pins are read-write — into the next
        // cage. `ensure_under` refuses a component that is not a real directory, and the home's
        // mount point is the one component the cage cannot exchange, so it is the anchor.
        for rel in [
            super::openuri::APPLICATIONS_REL,
            super::openuri::MIMEAPPS_REL,
        ] {
            if let Some((parent, _)) = rel.rsplit_once('/') {
                super::cagedir::ensure_under(&rt.home_src, parent, 0o700)?;
            }
        }
        (Some(open_apps.as_path()), Some(open_mimeapps.as_path()))
    };

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
    // Each registration is given its **anchor** and the path below it, rather than one joined path:
    // everything under a bind's mount point is cage-writable, so `register` has to know where the
    // trusted prefix ends in order to refuse a component the cage repointed.
    let mut mise_plugin_dirs = vec![(rt.home_src.clone(), format!("{MISE_DATA_REL}/plugins"))];
    if let Some(pool) = &rt.mise_project_src {
        DirBuilder::new().recursive(true).mode(0o700).create(pool)?;
        mise_plugin_dirs.push((pool.clone(), "plugins".to_string()));
    }
    for (root, rel) in &mise_plugin_dirs {
        super::miseplugin::register(root, rel)?;
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
    super::atomicfile::write_atomic(
        &hosts,
        hosts_contents(&super::naming::cage_hostname(&slug), &tcp.destinations).as_bytes(),
    )?;

    // The synthetic ssh client config, materialized beside the other synthetic `/etc` files (and,
    // like them, outside every writable mount — the agent may override it from its own home, but
    // not rewrite the file the cage is handed). Written only when a declared destination needs one;
    // otherwise no such mount exists at all. A stale file from a previous launch of the same home is
    // removed rather than left behind, so the cage never reads a rule the current config dropped.
    let ssh_config = rt.etc_dir.join("ssh_config");
    let ssh_config_src =
        match super::egress::ssh_config_contents(&userland.socat_bin, &tcp.connect_only) {
            Some(contents) => {
                super::atomicfile::write_atomic(&ssh_config, contents.as_bytes())?;
                Some(ssh_config.as_path())
            }
            None => {
                let _ = std::fs::remove_file(&ssh_config);
                None
            }
        };

    // A synthetic `/etc/machine-id`, stable per app-home and unique per home, materialized beside
    // the other synthetic `/etc` files (outside every writable mount, so the agent has no writable
    // alias to forge its own machine identity). Bound read-only at both conventional paths so a
    // desktop app's fingerprinting reads a distinct, persistent id instead of hashing an empty
    // string (identical in every hermetic cage).
    let machine_id = rt.etc_dir.join("machine-id");
    super::atomicfile::write_atomic(&machine_id, machine_id_contents(&rt.home_src).as_bytes())?;

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
        open_router_src: &open_router,
        hosts_src: &hosts,
        ssh_config_src,
        machine_id_src: &machine_id,
        open_apps_src,
        open_mimeapps_src,
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
mod tests;

/// The whole constructor chain — resolve the real userland, materialise the
/// synthetic identity, assemble, and feed the *generated* argv to real bwrap —
/// must launch a working hermetic shell. The unit tests above check the argv
/// *structure*; only this proves the code's argv (not a hand-written one) runs:
/// the sandbox shell resolves the synthetic user, has no host `/usr`, and runs
/// nix coreutils. Skipped, not failed, where the prerequisites are absent.
#[cfg(test)]
mod smoke_tests;
