//! The user-owned, daemonless nix store.
//!
//! sbx provisions a project's tools into a store it owns under its own data
//! directory, never the host's `/nix`. The shared store is a single flat tree —
//! deduplicated across projects, written only while sbx itself provisions into it
//! on the host side; a sandbox then consumes a per-project copy seeded from it,
//! bound read-write so an agent can self-equip, while the shared tree stays
//! read-only. This module computes the
//! on-disk layout, bootstraps it, and builds the daemonless nix invocation that
//! drives it.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The default nixpkgs source sbx tracks — a rolling-release branch, like a
/// rolling-distro base. The *source* is a constant; the concrete *revision* it
/// resolves to is recorded as state (see [`resolve_ref`]) so it stays fixed across
/// sbx binary updates and only advances on an explicit upgrade.
const DEFAULT_SOURCE: &str = "nixos-unstable";

/// The flake-reference prefix every nixpkgs source expands under. A source is the
/// branch/channel or revision that follows it; constraining selection to this prefix
/// is a security floor (an untrusted-influenced value cannot point at a fork).
const NIXPKGS_FLAKE_PREFIX: &str = "github:NixOS/nixpkgs/";

/// The file (under the data directory, or a project's runtime tree) recording a
/// resolved nixpkgs source + revision — the "installed snapshot". Seeded on first
/// use, then reused; refreshing it (an explicit upgrade) is what rolls tool versions
/// forward, never an sbx binary update.
const NIXPKGS_LOCK: &str = "nixpkgs.lock";

/// The file (under the data directory) recording the mise engine's resolved source +
/// revision — a dedicated lock so an explicit `sbx upgrade mise` advances the engine
/// independently of the base channel (`nixpkgs.lock`). The engine tracks the global
/// channel source, but pinning it here on its own means rolling the base never bumps the
/// engine, and rolling the engine never bumps the base.
const MISE_ENGINE_LOCK: &str = "mise-engine.lock";

/// On-disk layout of the user-owned store, rooted at sbx's private data
/// directory. Pure path derivation — holds no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    data_dir: PathBuf,
}

impl Layout {
    /// Resolve the layout from the environment, highest precedence first:
    /// `$SBX_DATA_DIR` names the data directory outright, else `$XDG_DATA_HOME/sbx`,
    /// else `$HOME/.local/share/sbx`. `None` when nothing yields a usable base.
    ///
    /// A relative `$SBX_DATA_DIR` is **refused**, not ignored: it would otherwise
    /// resolve against whatever directory sbx happens to be launched from, letting a
    /// checked-out repository decide where the store lives — and a store is trusted by
    /// location. Falling back silently would put the data somewhere the user did not
    /// ask for, so the refusal yields `None` and is reported on stderr. Every command
    /// that needs the data directory then stops; the one that merely inventories on-disk
    /// locations reports the base as unresolved rather than inventing one. An overlong
    /// `$SBX_DATA_DIR` is refused the same way — see [`check_data_dir_override`].
    pub(crate) fn from_env() -> Option<Self> {
        let over = std::env::var_os("SBX_DATA_DIR");
        let data_dir = data_dir_from(
            over.as_deref(),
            std::env::var_os("XDG_DATA_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        );
        if data_dir.is_none() {
            // The decision came from `data_dir_from`; the wording comes from the same
            // check it consulted, so the two cannot describe different refusals.
            if let Some(over) = over.as_deref().filter(|o| !o.is_empty()) {
                if let Err(why) = check_data_dir_override(over) {
                    crate::diag::error(&format!("sbx: {why}"));
                }
            }
        }
        let mut data_dir = data_dir?;

        // An explicit override is the invoker's word and settles it. Otherwise a pointer in
        // the default directory says the data has moved into a volume, and sbx follows it —
        // mounting it if need be, so no shell has to remember to.
        if over.as_deref().is_none_or(|o| o.is_empty()) {
            match follow_volume(&data_dir) {
                None => {}
                Some(Ok(mounted)) => data_dir = mounted,
                Some(Err(why)) => {
                    // Fail closed. The mount point exists only while mounted, and it lives
                    // under `/run` — a tmpfs. Carrying on with the unmounted path would
                    // provision gigabytes into RAM and present an empty store as the truth.
                    crate::diag::error(&format!(
                        "sbx: sbx's data is in a volume that could not be mounted: {why}"
                    ));
                    crate::diag::error(
                        "sbx: refusing to continue rather than use an empty data directory",
                    );
                    return None;
                }
            }
        }

        // Guard the directory sbx will actually use — after a volume pointer may have swapped
        // it for a short mount point. A derived `$HOME`/`$XDG_DATA_HOME` too long for the
        // sockets sbx binds under it would otherwise fail deep at launch, talking about a socket
        // rather than the directory; refuse here, with the remedy, at the moment it is resolved.
        // `sbx storage` anchors to `default_data_dir`, not this path, so a volume can still be
        // adopted to fix it.
        if let Err(why) = check_resolved_data_dir(&data_dir) {
            crate::diag::error(&format!("sbx: {why}"));
            return None;
        }
        Some(Self { data_dir })
    }

    /// The data directory sbx would use with no volume in play — the plain XDG computation.
    ///
    /// This is where the volume's image and pointer live, so it must stay reachable even once
    /// a pointer has redirected everything else.
    pub(crate) fn default_data_dir() -> Option<PathBuf> {
        data_dir_from(
            None,
            std::env::var_os("XDG_DATA_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
    }

    /// Pure constructor: the layout rooted at a given data directory. Split out
    /// so the derived paths are testable without touching the environment.
    #[cfg(test)]
    pub(crate) fn under(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
        }
    }

    /// The argument passed to `nix --store`: the directory that *contains* the
    /// `nix/` tree. A daemonless build into it yields `<store_dir>/nix/store`,
    /// owned by the invoking user.
    pub(crate) fn store_dir(&self) -> PathBuf {
        self.data_dir.join("store")
    }

    /// The root of sbx's private data directory — the parent of the store and of
    /// the per-project sandbox runtime trees.
    pub(crate) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Where sbx places a nix engine it owns — the store-driving `nix`/`nix-store`
    /// binary, as opposed to the host's. Distinct from the in-cage nix an agent
    /// self-equips with: this one runs on the host to provision the store. The
    /// engine resolver consults it ahead of the host `PATH`.
    pub(crate) fn engine_dir(&self) -> PathBuf {
        self.data_dir.join("engine")
    }

    /// Where installed resolver plugins live, one directory per plugin. Trusted by
    /// location: a project cannot write here, so a plugin's presence is the user's act.
    pub(crate) fn plugins_dir(&self) -> PathBuf {
        self.data_dir.join("plugins")
    }

    /// Where configured remote plugin stores are cached, one directory per store. Like
    /// the plugins tree, trusted by location (owner-only), so the verified catalogue and
    /// fetched artifacts cannot be tampered with by a project.
    pub(crate) fn stores_dir(&self) -> PathBuf {
        self.data_dir.join("stores")
    }

    /// The cache directory of one named remote store: `<stores>/<name>/`, holding its
    /// `store.toml` (url + public key), `checkout/` (the verified git clone), and
    /// `catalogue.lock` (the catalogue revision last accepted).
    pub(crate) fn store_path(&self, name: &str) -> PathBuf {
        self.stores_dir().join(name)
    }
}

/// Follow a volume pointer in `default_dir`, mounting the volume if it is not already.
/// `None` when there is no pointer — the ordinary case, and the one that must stay free.
///
/// Resolved once per process: the answer cannot change under us, and a single launch asks for
/// the layout dozens of times. Only the mount is memoised, so nothing is cached before a
/// pointer is found.
fn follow_volume(default_dir: &Path) -> Option<Result<PathBuf, String>> {
    static RESOLVED: std::sync::OnceLock<Option<Result<PathBuf, String>>> =
        std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(|| {
            let image = crate::storage::read_pointer(default_dir)?;
            Some(crate::storage::ensure_mounted(&image))
        })
        .clone()
}

/// Whether `$SBX_DATA_DIR` is what selected the data directory. Surfaced by `doctor` so a
/// shell that carries the override is distinguishable from one that does not — otherwise a
/// store that looks unexpectedly empty has no visible explanation.
pub(crate) fn data_dir_overridden() -> bool {
    std::env::var_os("SBX_DATA_DIR")
        .filter(|v| !v.is_empty())
        .is_some_and(|v| check_data_dir_override(&v).is_ok())
}

/// The longest path a Unix-domain socket can carry, minus its terminator: `sun_path` is a
/// fixed 108-byte field and the kernel needs the trailing NUL.
const SUN_PATH_MAX: usize = 107;

/// The longest socket name any feature appends to the data directory. Every feature that binds
/// an `AF_UNIX` socket under the data directory contributes one; the widest is what the cap must
/// reserve for. With a 7-digit pid and a 5-digit port:
///   `/egress/proxy-<pid>.sock`         (26)  egress proxy, bound into the cage
///   `/egress/control-<pid>.sock`       (28)  egress live control
///   `/fs/control-<pid>.sock`           (24)  exec-enforcement control
///   `/forward/fwd-<pid>/p-<port>.sock` (33)  port forwarding — the widest, a per-launch subdir
///                                            holding one socket per forwarded port
/// A new feature whose host socket path is wider than this must widen the sample below, or a
/// data directory the cap accepts would still overrun `sun_path` at that feature's first launch.
const LONGEST_SOCKET_SUFFIX: usize = "/forward/fwd-1234567/p-65535.sock".len();

/// The most a data directory may measure and still host those sockets.
const DATA_DIR_MAX: usize = SUN_PATH_MAX - LONGEST_SOCKET_SUFFIX;

/// Validate an explicit `$SBX_DATA_DIR`, returning the directory or why it was refused.
/// One function so the decision and the diagnostic can never disagree.
///
/// The length bound is not cosmetic. Egress filtering, the D-Bus filter, port forwarding and
/// exec enforcement each bind an `AF_UNIX` socket *under* the data directory, and a socket
/// path that overruns `sun_path` fails at launch — well after the choice was made, with a
/// message about a socket rather than about the directory. Refusing here turns a puzzling
/// runtime failure into an answerable one, at the moment the path is chosen.
fn check_data_dir_override(value: &OsStr) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "SBX_DATA_DIR must be an absolute path (got {})",
            path.display()
        ));
    }
    let len = value.as_encoded_bytes().len();
    if len > DATA_DIR_MAX {
        return Err(format!(
            "SBX_DATA_DIR is {len} bytes; at most {DATA_DIR_MAX} fit, because sbx binds \
             sockets under it and a Unix socket path cannot exceed {SUN_PATH_MAX} bytes \
             (got {})",
            path.display()
        ));
    }
    Ok(path)
}

/// Refuse a *resolved* data directory whose path is too long to host sbx's sockets.
///
/// [`check_data_dir_override`] guards only an explicit `$SBX_DATA_DIR`; a directory sbx
/// *derives* — `$XDG_DATA_HOME/sbx` or `$HOME/.local/share/sbx` — is not handed in and so
/// escapes it, yet overruns `sun_path` just the same when `$HOME` is long. This runs on the
/// **final** directory, after a volume pointer has had its say, so an adopted volume — whose
/// mount point under `/run` is short — passes silently even when the plain derived path would
/// not. That is deliberate: adopting a volume is one of the two remedies, and it must not be
/// refused as a side effect of the very problem it solves. An override that reached here already
/// passed the stricter check above, so it too passes without a second, differently-worded refusal.
fn check_resolved_data_dir(dir: &Path) -> Result<(), String> {
    let len = dir.as_os_str().as_encoded_bytes().len();
    if len > DATA_DIR_MAX {
        return Err(format!(
            "sbx's data directory is {len} bytes ({}); at most {DATA_DIR_MAX} fit, because sbx \
             binds sockets under it and a Unix socket path cannot exceed {SUN_PATH_MAX} bytes. \
             Set SBX_DATA_DIR to a shorter path, or adopt a storage volume — its mount point is short.",
            dir.display()
        ));
    }
    Ok(())
}

/// Pure core of [`Layout::from_env`]: an absolute `SBX_DATA_DIR` wins outright, else
/// prefer an absolute `XDG_DATA_HOME`, else fall back to `HOME/.local/share`.
///
/// The two overrides differ in kind, so they differ in treatment. `XDG_DATA_HOME` is a
/// *base* shared with every other application, so `sbx` is appended and a relative value
/// is ignored, as the base-directory specification requires. `SBX_DATA_DIR` names sbx's
/// own directory, so it is used verbatim — and a relative value yields `None` rather than
/// falling through, because quietly using a different directory than the one asked for
/// would strand the user's projects and apps somewhere they never look. An unset *or
/// empty* value is simply absent, so clearing the variable restores the default.
fn data_dir_from(
    sbx: Option<&OsStr>,
    xdg: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(sbx) = sbx.filter(|s| !s.is_empty()) {
        return check_data_dir_override(sbx).ok();
    }
    if let Some(xdg) = xdg {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("sbx"));
        }
    }
    Some(PathBuf::from(home?).join(".local/share/sbx"))
}

/// Create the store's directory skeleton if absent and tighten its permissions
/// to owner-only. Idempotent, and fail-closed: a directory that already existed
/// with looser permissions is tightened, never left group/world-accessible.
/// Never touches the host `/nix`. Called lazily, the first time a sandbox
/// consumes the store or sbx provisions into it.
pub(crate) fn ensure(layout: &Layout) -> io::Result<()> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    for dir in [layout.data_dir.clone(), layout.store_dir()] {
        // Create owner-only from the start, so a loose umask never leaves a
        // world-readable window between creation and tightening...
        DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        // ...and tighten a directory that already existed with looser bits.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Environment override naming an explicit `nix` binary for sbx to drive, ahead of
/// every other source. Lets a power user — or a test — point sbx at a chosen engine.
/// It names `nix` itself; the sibling commands (`nix-store`, …) are found beside it,
/// since one multi-call binary backs them all in every nix distribution.
///
/// A value that does not point at an existing `nix` is ignored (resolution falls
/// through), so a stale override never strands sbx. But once it *does* resolve, it is
/// **authoritative**: every engine binary is taken from beside it, never mixed with
/// the host's — a missing sibling there fails closed rather than silently driving the
/// store with two different engines.
const ENGINE_OVERRIDE_ENV: &str = "SBX_NIX_BIN";

/// Locate the `nix` binary that drives the store.
///
/// Resolution precedence: the [`ENGINE_OVERRIDE_ENV`] override, then a nix engine sbx
/// owns under the data directory (`<data>/engine/`), then the host `PATH`. The
/// data-directory tier is where sbx will place an engine it ships itself; consulting
/// it here puts the seam in place, while the `PATH` fallback keeps sbx working until
/// then. `layout` is `None` only when the data directory cannot be resolved (no
/// `$HOME`), in which case that middle tier is skipped.
///
/// Pure resolution — it never writes — so a read-only caller (`sbx doctor`) is safe.
pub(crate) fn resolve_nix(layout: Option<&Layout>) -> Option<PathBuf> {
    resolve_engine_bin("nix", layout)
}

/// Locate the `nix-store` binary, the classic command exposing the store's
/// registration database (`--dump-db`/`--load-db`). The same multi-call binary as
/// `nix`, dispatched by argv0, so it is resolved by the same precedence as
/// [`resolve_nix`]. Consumed by the per-project store seed the launcher backs the
/// cage's writable `/nix` with.
pub(crate) fn resolve_nix_store(layout: Option<&Layout>) -> Option<PathBuf> {
    resolve_engine_bin("nix-store", layout)
}

/// The static nix engine sbx ships inside its own binary, embedded by `build.rs` when the
/// `bundled-nix` feature is on. `NIX_BIN` is the raw bytes of the statically-linked `nix`;
/// `NIX_SHA256` is their hash, baked at build time so a launch compares the on-disk marker
/// without re-hashing tens of megabytes. Materialized into the owned engine directory by
/// [`ensure_owned_engine`].
#[cfg(feature = "bundled-nix")]
mod bundled {
    include!(concat!(env!("OUT_DIR"), "/bundled_nix.rs"));
}

/// The in-cage exec-enforcement shim sbx carries inside its own binary, built from `proc-shim/`
/// and embedded by `build.rs`. Unconditional, unlike the engines: there is no host copy to fall
/// back to, and no other binary may take its place inside a cage.
mod proc_shim_blob {
    include!(concat!(env!("OUT_DIR"), "/proc_shim.rs"));
}

/// The name the shim is materialized under, in the owned engine directory.
const PROC_SHIM_NAME: &str = "proc-shim";

/// The embedded shim's bytes, so the enforcement tests can exercise the artifact sbx actually binds
/// rather than a stand-in that reimplements it. A stand-in would pass while the shipped shim drifted.
#[cfg(test)]
pub(crate) fn embedded_proc_shim() -> &'static [u8] {
    proc_shim_blob::PROC_SHIM_BIN
}

/// Materialize the embedded exec shim into the owned engine directory and return its path.
///
/// Unlike the engines' best-effort placement, a failure here is returned rather than swallowed:
/// the caller is standing up enforcement, and the honest response to "the shim is not on disk" is
/// to refuse the launch, never to bind something else in its place.
///
/// Placement is atomic and idempotent on the same principle as the engines: a unique temp sibling
/// is written, made executable and renamed over the target, and a `.proc-shim.sha256` marker is
/// stamped **last** so an interrupted run re-materializes next time instead of trusting a
/// half-written binary. A new sbx carrying a newer shim changes the hash and replaces it; the
/// rename leaves a running cage's shim on its old inode.
pub(crate) fn ensure_proc_shim(layout: &Layout) -> io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let dir = layout.engine_dir();
    let shim = dir.join(PROC_SHIM_NAME);
    let marker = dir.join(".proc-shim.sha256");
    let sha = proc_shim_blob::PROC_SHIM_SHA256;
    if shim.is_file() && std::fs::read_to_string(&marker).ok().as_deref() == Some(sha) {
        return Ok(shim);
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    let tmp = dir.join(format!(".{PROC_SHIM_NAME}.tmp.{}", std::process::id()));
    std::fs::write(&tmp, proc_shim_blob::PROC_SHIM_BIN)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp, &shim)?;
    std::fs::write(&marker, sha)?;
    Ok(shim)
}

/// Read an engine-override env var as an **absolute** path, ignoring (with a warning) a relative
/// value. A relative override would be resolved against the current working directory — an
/// attacker-controlled project directory — so the host-side engine choice must not depend on it;
/// this mirrors the absolute-path requirement on the store directory.
fn absolute_override(env_key: &str) -> Option<PathBuf> {
    let value = std::env::var_os(env_key)?;
    let path = PathBuf::from(&value);
    if path.is_absolute() {
        Some(path)
    } else {
        eprintln!(
            "sbx: ignoring {env_key}={} — an engine override must be an absolute path",
            path.display()
        );
        None
    }
}

/// Shared resolution for an engine command `name` (`nix`/`nix-store`), reading the
/// real environment, data directory, and `PATH`. The precedence is factored into
/// [`pick_engine_bin`] so it is unit-testable without touching any of them.
fn resolve_engine_bin(name: &str, layout: Option<&Layout>) -> Option<PathBuf> {
    let override_nix = absolute_override(ENGINE_OVERRIDE_ENV);
    let owned_dir = layout.map(Layout::engine_dir);
    // When sbx ships its own static nix, lay it into the owned engine directory (once;
    // idempotent thereafter) so the owned tier below resolves it. Best-effort: a failure
    // leaves that tier empty and resolution falls through to `PATH`, exactly as it would
    // without the feature. The explicit `SBX_NIX_BIN` override still wins over it.
    #[cfg(feature = "bundled-nix")]
    if let Some(dir) = owned_dir.as_deref() {
        let _ = ensure_owned_engine(dir, bundled::NIX_BIN, bundled::NIX_SHA256);
    }
    pick_engine_bin(
        name,
        override_nix.as_deref(),
        owned_dir.as_deref(),
        &|p| engine_probe(p),
        &|n| crate::pathfind::find_all_on_path(n),
    )
}

/// Materialize sbx's bundled static nix into the owned engine directory, idempotently.
///
/// Lays down `<dir>/nix` (the real binary, executable) plus the multi-call sibling
/// `<dir>/nix-store -> nix` (one binary dispatches both off argv0). A `<dir>/.sha256`
/// marker records the embedded hash so a launch re-materializes only when the engine
/// changed (a new sbx binary), not on every resolution. The binary lands atomically — a
/// unique temp sibling written, made executable, then renamed over `nix` — so a
/// concurrent or interrupted launch never leaves a partial engine at the resolved path,
/// and a running engine keeps its old inode across a replacement.
///
/// `sha256` is the embedded engine's precomputed hash, compared as a string against the
/// marker; nothing is re-hashed here. Best-effort by contract: every error is returned for
/// the caller to ignore.
#[cfg(any(feature = "bundled-nix", test))]
fn ensure_owned_engine(dir: &Path, bytes: &[u8], sha256: &str) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let nix = dir.join("nix");
    let store_link = dir.join("nix-store");
    let marker = dir.join(".sha256");
    // Already fully in place at this exact engine version — the binary, the multi-call
    // sibling, AND the marker. Checking the sibling too means an interrupted symlink
    // replacement re-materializes rather than stranding `nix-store` forever behind a
    // marker that still matches.
    if nix.is_file()
        && store_link.exists()
        && std::fs::read_to_string(&marker).ok().as_deref() == Some(sha256)
    {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".nix.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp, &nix)?;
    // Place the sibling atomically too: a unique temp link renamed over `nix-store` leaves
    // no window where it is absent (a concurrent first launch would otherwise see a removed
    // link); a lost race simply discards an identical link.
    let tmp_link = dir.join(format!(".nix-store.tmp.{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp_link);
    std::os::unix::fs::symlink("nix", &tmp_link)?;
    std::fs::rename(&tmp_link, &store_link)?;
    // Stamp the version last: an interrupted run leaves a stale/absent marker and
    // re-materializes next time rather than trusting a half-written engine.
    std::fs::write(&marker, sha256)?;
    Ok(())
}

/// The trust state of a candidate engine binary, distinguishing "not there" from "there
/// but not trustworthy". The two must not collapse: an explicit override that is
/// present-but-unsafe is **refused outright** (never silently replaced by a lower tier),
/// whereas an absent override merely yields to the next tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineProbe {
    /// No file at the path.
    Absent,
    /// A file is present but fails the ownership/permission check.
    Untrusted,
    /// A regular file owned by us or root and not world-writable — safe to `execve`.
    Trusted,
}

/// Pure ownership/permission verdict for an engine binary about to be `execve`d.
///
/// Mirrors the config-file safety gate, with one deliberate difference: an engine may
/// legitimately be owned by **root** (the host `/usr/bin/bwrap` is `root:root`, and an
/// override may point at a system binary), so ownership by uid 0 is accepted alongside our
/// own euid — neither is writable by an unprivileged attacker. A non-regular file
/// (FIFO/device/dir, which could hang a launch or feed back attacker-controlled bytes) or a
/// world-writable one (anyone could swap it) is refused; group-writable is tolerated, as for
/// config files — the owner-only engine directory is the real boundary for the owned tier.
/// `mode` is the full `st_mode`, type bits included.
fn engine_verdict(file_uid: u32, mode: u32, euid: u32) -> Result<(), String> {
    if mode & libc::S_IFMT != libc::S_IFREG {
        return Err("not a regular file".into());
    }
    if file_uid != euid && file_uid != 0 {
        return Err(format!("owned by uid {file_uid}, expected {euid} or root"));
    }
    if mode & 0o002 != 0 {
        return Err("world-writable".into());
    }
    Ok(())
}

/// Probe a candidate engine path: absent, present-but-untrusted, or trusted. Metadata is read
/// through the path — following a symlink, since that is what `execve` runs (e.g. the
/// `nix-store -> nix` multi-call link). A present-but-untrusted binary at a resolved tier is
/// **warned** about by name and reason (a swapped or loosely-permissioned engine is exactly
/// the case worth surfacing); the caller then decides refuse-vs-fall-through.
///
/// This is a static-posture check (`stat` then `execve`), not a TOCTOU-proof gate: against a
/// same-uid attacker — who already owns the account and could replace sbx itself — nothing at
/// this layer is a boundary. Its value is defense-in-depth: a foreign-owned or world-writable
/// engine (a loosely-permissioned data dir, a world-writable match on `PATH`) is refused
/// rather than run. The `PATH` tier scans every match (`find_all_on_path`) and skips an
/// untrusted one in favour of the next, so a world-writable early entry does not shadow a
/// legitimate engine further down `PATH` — short of the same-uid attacker above, a poisoned
/// early match is a non-event rather than a denial.
fn engine_probe(path: &Path) -> EngineProbe {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return EngineProbe::Absent,
    };
    let euid = unsafe { libc::geteuid() };
    match engine_verdict(meta.uid(), meta.mode(), euid) {
        Ok(()) => EngineProbe::Trusted,
        Err(why) => {
            eprintln!(
                "sbx: ignoring untrusted engine binary {}: {why}",
                path.display()
            );
            EngineProbe::Untrusted
        }
    }
}

/// Pick the engine binary `name` from the three sources, in precedence order: the override,
/// then an sbx-owned engine directory, then `PATH`. The trust probe and the `PATH` lookup are
/// injected so the precedence — including the untrusted branches — is testable in isolation.
///
/// A *resolved* override (one whose `nix` is present and trusted) is authoritative: `name` is
/// taken from beside it and a missing or untrusted sibling yields `None` (fail-closed), never a
/// fall-back to the host's `PATH` — which would drive one store with two different engines. An
/// override whose `nix` is **absent** is treated as unset and the next tier applies; one that
/// is **present but untrusted** is refused outright (`None`), since it is a deliberate choice
/// and silently substituting another engine would be worse. A lower tier (owned, then `PATH`)
/// that is untrusted is skipped — with a warning — in favour of the next; on `PATH` that means
/// scanning past an untrusted match to a later trusted one, so a world-writable early entry does
/// not shadow the legitimate engine.
fn pick_engine_bin(
    name: &str,
    override_nix: Option<&Path>,
    owned_dir: Option<&Path>,
    probe: &dyn Fn(&Path) -> EngineProbe,
    on_path: &dyn Fn(&str) -> Vec<PathBuf>,
) -> Option<PathBuf> {
    if let Some(nix) = override_nix {
        match probe(nix) {
            EngineProbe::Absent => {}
            EngineProbe::Untrusted => return None,
            EngineProbe::Trusted => {
                let bin = engine_sibling(nix, name);
                return matches!(probe(bin.as_path()), EngineProbe::Trusted).then_some(bin);
            }
        }
    }
    if let Some(dir) = owned_dir {
        // Sibling-paired like the override, anchored on the owned `nix`: only when that anchor is
        // trusted does the owned tier apply, and then `name` is taken from beside it (a missing or
        // untrusted sibling yields None, fail-closed). Resolving `name` independently here would let
        // a trusted owned `nix` pair with a `nix-store` from `PATH` — one store driven by two
        // different engines. An absent/untrusted anchor skips the owned tier for every name alike,
        // so nix and nix-store fall through together.
        let anchor = dir.join("nix");
        if matches!(probe(anchor.as_path()), EngineProbe::Trusted) {
            let bin = dir.join(name);
            return matches!(probe(bin.as_path()), EngineProbe::Trusted).then_some(bin);
        }
    }
    on_path(name)
        .into_iter()
        .find(|p| matches!(probe(p.as_path()), EngineProbe::Trusted))
}

/// Given the path of the `nix` binary, the path of its sibling command `name` in the
/// same directory; `name == "nix"` is the binary itself.
fn engine_sibling(nix: &Path, name: &str) -> PathBuf {
    if name == "nix" {
        return nix.to_path_buf();
    }
    match nix.parent() {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

/// Environment override naming an explicit `bwrap` binary, ahead of every other source —
/// the testing/escape-hatch tier, mirroring [`ENGINE_OVERRIDE_ENV`] for the sandbox engine.
/// A value that does not point at an existing file is ignored. Once it resolves it wins
/// unconditionally: the user (or a test) has taken responsibility for the chosen engine,
/// including that it is AppArmor-profiled where that matters (see [`resolve_bwrap`]).
const BWRAP_OVERRIDE_ENV: &str = "SBX_BWRAP_BIN";

/// The kernel sysctl that, when non-zero, restricts unprivileged user-namespace creation to
/// binaries carrying an AppArmor profile that grants `userns` (Ubuntu 24.04+). The shipped
/// profile attaches that grant **by path** to `/usr/bin/bwrap`, so a bwrap materialized
/// elsewhere cannot create a namespace under this restriction — which is why
/// [`resolve_bwrap`] prefers the host engine when it is in force.
const APPARMOR_USERNS_RESTRICT: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// The static bwrap (bubblewrap) engine sbx ships inside its own binary, embedded by
/// `build.rs` when the `bundled-bwrap` feature is on. `BWRAP_BIN` is the raw bytes of the
/// statically-linked `bwrap`; `BWRAP_SHA256` is their hash, baked at build time so a launch
/// compares the on-disk marker without re-hashing. Materialized by [`ensure_owned_bwrap`].
#[cfg(feature = "bundled-bwrap")]
mod bundled_bwrap {
    include!(concat!(env!("OUT_DIR"), "/bundled_bwrap.rs"));
}

/// Which source supplied the resolved `bwrap`, for an honest `sbx doctor` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BwrapSource {
    /// The [`BWRAP_OVERRIDE_ENV`] override.
    Override,
    /// A bwrap sbx owns under `<data>/engine/` (the embedded static engine).
    Bundled,
    /// The host's bwrap on `PATH`.
    HostPath,
}

impl BwrapSource {
    /// A short label naming the source.
    pub(crate) fn label(self) -> &'static str {
        match self {
            BwrapSource::Override => "override (SBX_BWRAP_BIN)",
            BwrapSource::Bundled => "bundled engine",
            BwrapSource::HostPath => "host PATH",
        }
    }
}

/// A resolved sandbox engine: its path, where it came from, and whether the host is
/// enforcing the AppArmor unprivileged-userns restriction (which is *why* the host engine
/// may have been chosen over the bundled one). Callers that only launch use [`Self::path`];
/// `sbx doctor` reports all three so the user is never surprised which `bwrap` ran.
#[derive(Debug, Clone)]
pub(crate) struct BwrapChoice {
    pub(crate) path: PathBuf,
    pub(crate) source: BwrapSource,
    pub(crate) apparmor_restricted: bool,
}

/// Locate the `bwrap` binary that launches the sandbox.
///
/// Resolution precedence: the [`BWRAP_OVERRIDE_ENV`] override always wins; otherwise the
/// order depends on the host. Where unprivileged user namespaces are **not** AppArmor-path-
/// restricted (the common case, and every non-Ubuntu distro), the bundled engine sbx owns
/// under `<data>/engine/` leads — self-contained and a known-good pinned version — falling
/// back to the host `PATH`. Where the restriction **is** in force, only the path-profiled
/// `/usr/bin/bwrap` can create a namespace, so the host engine leads and the bundled one is
/// the fallback; sbx is **non-regressive by construction** there — it uses exactly the host
/// bwrap it always has. `layout` is `None` only when the data directory cannot be resolved,
/// in which case the owned tier is skipped.
///
/// Under the `bundled-bwrap` feature this materializes the embedded engine into the owned
/// directory (once; idempotent) before resolving; best-effort, so a failure simply leaves
/// that tier empty and resolution falls through.
pub(crate) fn resolve_bwrap(layout: Option<&Layout>) -> Option<BwrapChoice> {
    let override_bin = absolute_override(BWRAP_OVERRIDE_ENV);
    let owned_dir = layout.map(Layout::engine_dir);
    #[cfg(feature = "bundled-bwrap")]
    if let Some(dir) = owned_dir.as_deref() {
        let _ = ensure_owned_bwrap(dir, bundled_bwrap::BWRAP_BIN, bundled_bwrap::BWRAP_SHA256);
    }
    let apparmor_restricted = apparmor_userns_restricted();
    let (path, source) = pick_bwrap(
        apparmor_restricted,
        override_bin.as_deref(),
        owned_dir.as_deref(),
        &|p| engine_probe(p),
        &|n| crate::pathfind::find_all_on_path(n),
    )?;
    Some(BwrapChoice {
        path,
        source,
        apparmor_restricted,
    })
}

/// Whether the host enforces the AppArmor unprivileged-userns restriction: the sysctl
/// reads a non-zero value. Absent, unreadable, or zero ⇒ not restricted (prefer the bundled
/// engine). A non-numeric value is treated as not restricted — the sysctl is a 0/1 boolean.
fn apparmor_userns_restricted() -> bool {
    match std::fs::read_to_string(APPARMOR_USERNS_RESTRICT) {
        Ok(s) => s.trim().parse::<i64>().map(|v| v != 0).unwrap_or(false),
        Err(_) => false,
    }
}

/// Materialize sbx's bundled static bwrap into the owned engine directory, idempotently.
///
/// Lays down `<dir>/bwrap` (the real binary, executable) atomically — a unique temp sibling
/// written, made executable, then renamed over `bwrap` — so a concurrent or interrupted
/// launch never leaves a partial engine at the resolved path, and a running engine keeps its
/// old inode across a replacement. A `<dir>/.bwrap.sha256` marker records the embedded hash
/// so a launch re-materializes only when the engine changed, not on every resolution.
///
/// The marker is named distinctly from the nix engine's `.sha256` because both engines share
/// `<data>/engine/`; the two never clobber each other's markers. `sha256` is the embedded
/// engine's precomputed hash, compared as a string; nothing is re-hashed here. Best-effort by
/// contract: every error is returned for the caller to ignore.
#[cfg(any(feature = "bundled-bwrap", test))]
fn ensure_owned_bwrap(dir: &Path, bytes: &[u8], sha256: &str) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let bwrap = dir.join("bwrap");
    let marker = dir.join(".bwrap.sha256");
    if bwrap.is_file() && std::fs::read_to_string(&marker).ok().as_deref() == Some(sha256) {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".bwrap.tmp.{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp, &bwrap)?;
    // Stamp the version last: an interrupted run leaves a stale/absent marker and
    // re-materializes next time rather than trusting a half-written engine.
    std::fs::write(&marker, sha256)?;
    Ok(())
}

/// Pick the `bwrap` binary and its source from the override, the sbx-owned engine directory,
/// and `PATH`, in an order that depends on `restricted` (the AppArmor userns restriction). The
/// trust probe and the `PATH` lookup are injected so the precedence — including the AppArmor
/// branch (which a host without the restriction cannot exercise live) and the untrusted
/// branches — is unit-testable in isolation.
///
/// The override, when present and trusted, is authoritative; present-but-untrusted is refused
/// outright (`None`), absent yields to the host-dependent order. Otherwise: not restricted ⇒
/// the owned engine leads, then `PATH`; restricted ⇒ the host `PATH` engine leads (the same
/// bwrap sbx uses today — on a standard host the path-profiled `/usr/bin/bwrap`, the only one
/// able to create a namespace under the restriction), then the owned engine as a last resort.
/// An untrusted owned or `PATH` engine is skipped (with a warning) in favour of the next tier.
fn pick_bwrap(
    restricted: bool,
    override_bin: Option<&Path>,
    owned_dir: Option<&Path>,
    probe: &dyn Fn(&Path) -> EngineProbe,
    on_path: &dyn Fn(&str) -> Vec<PathBuf>,
) -> Option<(PathBuf, BwrapSource)> {
    if let Some(bin) = override_bin {
        match probe(bin) {
            EngineProbe::Absent => {}
            EngineProbe::Untrusted => return None,
            EngineProbe::Trusted => return Some((bin.to_path_buf(), BwrapSource::Override)),
        }
    }
    // Probe each tier lazily so only the tier actually consulted is examined — probing eagerly
    // would warn (via `probe`) about an untrusted candidate in the fallback tier even when the
    // leading tier resolves and the fallback is never used.
    let owned = || {
        owned_dir
            .map(|d| d.join("bwrap"))
            .filter(|p| matches!(probe(p.as_path()), EngineProbe::Trusted))
            .map(|p| (p, BwrapSource::Bundled))
    };
    let host = || {
        on_path("bwrap")
            .into_iter()
            .find(|p| matches!(probe(p.as_path()), EngineProbe::Trusted))
            .map(|p| (p, BwrapSource::HostPath))
    };
    if restricted {
        host().or_else(owned)
    } else {
        owned().or_else(host)
    }
}

/// Locate the `git` binary that fetches a remote plugin store. Resolved from `PATH`;
/// needed only by `sbx plugins store` (a remote store is a git repository), not by a
/// launch — so its absence is a feature gap, never a boundary failure.
pub(crate) fn resolve_git() -> Option<PathBuf> {
    crate::pathfind::find_on_path("git")
}

/// Build a daemonless nix invocation against the user-owned store: the daemon is
/// disabled (`NIX_REMOTE` empty), so nix runs as the invoking user with no
/// privileged helper, and `--store` points at the user-owned tree. Callers
/// append the subcommand. A store on btrfs additionally carries
/// [`btrfs_nix_config`]'s setting, so a compressed volume stays buildable.
pub(crate) fn nix_command(nix: &Path, layout: &Layout) -> Command {
    let mut cmd = Command::new(nix);
    cmd.env("NIX_REMOTE", "");
    let store_dir = layout.store_dir();
    if crate::storage::on_btrfs(&store_dir) {
        cmd.env(
            "NIX_CONFIG",
            btrfs_nix_config(std::env::var("NIX_CONFIG").ok().as_deref()),
        );
    }
    cmd.arg("--store").arg(store_dir);
    cmd
}

/// The nix setting a btrfs-backed store needs, appended to whatever `NIX_CONFIG`
/// the environment already carries (never replacing it — the caller's own
/// settings stay in force, ours only extends the list).
///
/// `extra-ignored-acls = btrfs.compression`: on a compressed btrfs volume the
/// mount root carries the `btrfs.compression` attribute, which every file
/// created beneath inherits. Nix strips extended attributes while canonicalising
/// a store path, and removing that attribute from a file a builder already made
/// read-only fails with `Permission denied`, aborting the build (substitutions
/// survive only because their files are still writable at that instant).
/// Ignoring the attribute costs nothing: compression is decided when the data is
/// written, so the store stays compressed either way. `extra-` appends to nix's
/// compiled default set rather than replacing it.
fn btrfs_nix_config(inherited: Option<&str>) -> String {
    const OURS: &str = "extra-ignored-acls = btrfs.compression";
    match inherited {
        Some(base) if !base.trim().is_empty() => format!("{base}\n{OURS}"),
        _ => OURS.to_string(),
    }
}

/// Where a `nixpkgs` source was chosen — carried so the same wording reaches the
/// user from `sbx config`, `sbx upgrade`, and `sbx doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The default rolling channel (no override anywhere).
    Default,
    /// A global-config `nixpkgs` override.
    Global,
    /// A trusted project's `nixpkgs` pin.
    ProjectPin,
}

impl Origin {
    /// A short label for display.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Origin::Default => "default",
            Origin::Global => "global",
            Origin::ProjectPin => "project pin",
        }
    }
}

/// The single channel a launch resolves against: a concrete `source` and the lock
/// file that pins it, plus where the source came from (for display). One launch uses
/// exactly one of these for the **whole** sandbox — base userland and tools alike.
///
/// This is the one place the "which source, which lock" decision is represented, so
/// the launch (resolve), `sbx upgrade` (refresh), and `sbx config` (display) all act
/// on the same lock and can never drift. A per-project lock is reachable **only**
/// through [`LockTarget::project`], which the caller builds only for a current
/// trusted pin — so a dropped or now-untrusted pin can never resurface a stale
/// per-project lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockTarget {
    source: String,
    lock_path: PathBuf,
    origin: Origin,
}

impl LockTarget {
    /// The global channel target: a global-config override or the default rolling
    /// channel, pinned in the shared data-dir lock.
    pub(crate) fn global(layout: &Layout, override_source: Option<&str>) -> Self {
        let (source, origin) = global_source(override_source);
        Self {
            source,
            lock_path: global_lock_path(layout),
            origin,
        }
    }

    /// The mise engine target: it tracks the **global** channel source (a global override
    /// applies; a project pin never does — the engine runs in its own relocated-store view,
    /// free of the one-channel rule that binds the base to its pin), but pins it in a
    /// dedicated lock so `sbx upgrade mise` advances the engine independently of the base
    /// channel that `sbx upgrade nix` rolls.
    pub(crate) fn engine(layout: &Layout, override_source: Option<&str>) -> Self {
        let (source, origin) = global_source(override_source);
        Self {
            source,
            lock_path: engine_lock_path(layout),
            origin,
        }
    }

    /// A trusted project's pin, in its per-project lock — so the project's tools (and
    /// base) are reproducible independent of the rolling global channel.
    pub(crate) fn project(layout: &Layout, project_id: &str, source: &str) -> Self {
        Self {
            source: source.to_string(),
            lock_path: project_lock_path(layout, project_id),
            origin: Origin::ProjectPin,
        }
    }

    /// The configured source (a branch/channel or a 40-hex revision).
    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    /// Where this source was chosen.
    pub(crate) fn origin(&self) -> Origin {
        self.origin
    }

    /// The revision currently locked for **this** source — `None` when no lock exists
    /// or it records a different source (which a launch would re-resolve). So a stale
    /// lock never displays as current. Pure file read: no nix, no network.
    pub(crate) fn locked_revision(&self) -> Option<String> {
        read_lock(&self.lock_path).and_then(|(s, r)| (s == self.source).then_some(r))
    }

    /// Resolve to a pinned `github:NixOS/nixpkgs/<rev>`, reusing the lock when its
    /// source matches and resolving (and recording) otherwise.
    pub(crate) fn resolve(&self, nix: &Path, layout: &Layout) -> io::Result<String> {
        resolve_ref(nix, layout, &self.source, &self.lock_path)
    }

    /// Force a fresh resolution of this source and rewrite the lock — the explicit
    /// roll-forward `sbx upgrade` performs. Reports the previous revision (for this
    /// source) so the caller can show what changed.
    pub(crate) fn refresh(&self, nix: &Path, layout: &Layout) -> io::Result<Upgrade> {
        refresh_ref(nix, layout, &self.source, &self.lock_path)
    }
}

/// The (source, origin) the global channel resolves to: a global-config override, else
/// the default rolling channel. Shared by the global channel and the mise engine — they
/// track the same source but pin it in separate locks.
fn global_source(override_source: Option<&str>) -> (String, Origin) {
    match override_source {
        Some(s) => (s.to_string(), Origin::Global),
        None => (DEFAULT_SOURCE.to_string(), Origin::Default),
    }
}

/// The shared data-dir lock pinning the global channel's revision.
fn global_lock_path(layout: &Layout) -> PathBuf {
    layout.data_dir().join(NIXPKGS_LOCK)
}

/// The dedicated data-dir lock pinning the mise engine's revision, independent of the
/// global channel lock so the two roll forward separately.
fn engine_lock_path(layout: &Layout) -> PathBuf {
    layout.data_dir().join(MISE_ENGINE_LOCK)
}

/// A project's own lock, under its runtime tree, pinning a trusted pin's revision.
fn project_lock_path(layout: &Layout, project_id: &str) -> PathBuf {
    layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join(NIXPKGS_LOCK)
}

/// The global channel's recorded `(source, revision)`, read straight from the shared
/// lock — what `sbx doctor` shows as the host-level channel state, independent of any
/// project. `None` when nothing has been resolved yet. Pure file read.
pub(crate) fn read_global_lock(layout: &Layout) -> Option<(String, String)> {
    read_lock(&global_lock_path(layout))
}

/// The base-channel revisions a shared-store gc must keep: the global channel's, plus the pin of
/// every project whose lock is still on disk. The GUI font set is keyed by the same channel
/// revision as the base userland, so this set covers both `gcroots/base/<rev>/` and
/// `gcroots/gui/<rev>/` — any revision outside it is stale. Reads the locks straight from disk,
/// so a dead project reaped before the gc no longer contributes its pin (and on a dry run, where
/// dead projects still exist, their pins keep their revisions, making the dry run a lower bound on
/// what `--prune` frees). Pure file reads, no nix.
pub(crate) fn live_base_revisions(layout: &Layout) -> BTreeSet<String> {
    let mut revs = BTreeSet::new();
    if let Some((_, rev)) = read_global_lock(layout) {
        revs.insert(rev);
    }
    if let Ok(entries) = std::fs::read_dir(layout.data_dir().join("projects")) {
        for entry in entries.flatten() {
            if let Some((_, rev)) = read_lock(&entry.path().join(NIXPKGS_LOCK)) {
                revs.insert(rev);
            }
        }
    }
    revs
}

/// The mise engine revisions a shared-store gc must keep: the engine lock's, or — when the engine
/// lock has not been written yet (an install still running its engine seeded from the global
/// channel) — the global channel's. This mirrors [`resolve_engine_ref`]'s seed-from-global
/// fallback, so the engine a launch is actually running is never collected. Pure file reads.
pub(crate) fn live_mise_revisions(layout: &Layout) -> BTreeSet<String> {
    let mut revs = BTreeSet::new();
    match read_lock(&engine_lock_path(layout)) {
        Some((_, rev)) => {
            revs.insert(rev);
        }
        None => {
            if let Some((_, rev)) = read_global_lock(layout) {
                revs.insert(rev);
            }
        }
    }
    revs
}

/// Resolve the mise engine reference, seeding its dedicated lock from the global channel
/// lock on first use. Used in place of [`LockTarget::engine`]'s plain `resolve` so two
/// properties hold across this feature's introduction:
///
/// - **A binary update never moves the engine.** Every install that predates the engine
///   lock has `nixpkgs.lock` but no `mise-engine.lock`; a plain resolve would hit the
///   network and re-pin `nixos-unstable` to its *current* revision, bumping the in-cage
///   mise on a mere binary update — exactly what the seeded-not-baked model forbids.
/// - **The first launch still works offline.** That fresh resolution would otherwise fail
///   with no network, where the base (resolved from its own lock) does not.
///
/// So when the engine lock is absent, the engine is seeded from the global channel lock
/// when that records the same source — no nix, the engine starting on exactly the
/// revision the base is already on. The launcher resolves the base before the engine, so
/// even a fresh install has `nixpkgs.lock` written by then and base == engine from the
/// start; they diverge only on an explicit `sbx upgrade mise`. Only when neither lock has
/// the source (a pinned-only user who has never resolved the global channel) does it
/// resolve fresh, which then needs nix.
pub(crate) fn resolve_engine_ref(
    nix: &Path,
    layout: &Layout,
    global_override: Option<&str>,
) -> io::Result<String> {
    let engine = LockTarget::engine(layout, global_override);
    // The engine's own lock already pins this source: reuse it (no nix), like any launch.
    if let Some(rev) = engine.locked_revision() {
        return Ok(format!("{NIXPKGS_FLAKE_PREFIX}{rev}"));
    }
    // First use of the engine lock: seed it from the global channel lock when that records
    // the same source, so the engine starts where the base already is — no network, and a
    // binary update never bumps it.
    if let Some(rev) = LockTarget::global(layout, global_override).locked_revision() {
        ensure(layout)?;
        write_lock(&engine.lock_path, &engine.source, &rev)?;
        return Ok(format!("{NIXPKGS_FLAKE_PREFIX}{rev}"));
    }
    // Neither lock pins this source yet: a genuine first resolution (needs nix), recorded
    // in the engine's own lock so later launches reuse it.
    engine.resolve(nix, layout)
}

/// Whether a source is itself a fixed 40-hex revision (a frozen pin that an upgrade
/// can never roll), as opposed to a branch/channel that tracks new revisions.
pub(crate) fn is_pinned_revision(source: &str) -> bool {
    valid_revision(source).is_some()
}

/// The outcome of forcing a channel to re-resolve: the source asked for, the
/// revision it now points at, and the revision it pointed at before (for the same
/// source), so a caller can report first-pin / unchanged / rolled-forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Upgrade {
    /// The source that was refreshed.
    pub(crate) source: String,
    /// The revision previously locked for this source, if any. `None` on a first
    /// resolution or after a source switch (the prior lock pinned a different source).
    pub(crate) previous: Option<String>,
    /// The freshly resolved revision now recorded.
    pub(crate) revision: String,
}

/// The revision component of a pinned `github:NixOS/nixpkgs/<rev>` reference — its
/// last path segment. Used to key per-revision on-disk state (a channel's base
/// userland), so two launches on the same revision share it and a rolled channel
/// gets its own.
pub(crate) fn revision_of(flake_ref: &str) -> &str {
    flake_ref.rsplit('/').next().unwrap_or(flake_ref)
}

/// Resolve `source` (a branch/channel or a 40-hex revision under `NixOS/nixpkgs`) to
/// a pinned `github:NixOS/nixpkgs/<rev>`, using `lock_path` as a source-aware cache:
/// the locked revision is reused **only** when the lock records the same source, so
/// changing the source re-resolves while an unchanged one stays fixed (an sbx binary
/// update never moves it; an explicit upgrade rewrites the lock). Pinning a concrete
/// revision is also the security floor — names resolve against one fixed,
/// signed-cache-built catalogue.
fn resolve_ref(nix: &Path, layout: &Layout, source: &str, lock_path: &Path) -> io::Result<String> {
    ensure(layout)?;
    if let Some((locked_source, locked_rev)) = read_lock(lock_path) {
        if locked_source == source {
            return Ok(format!("{NIXPKGS_FLAKE_PREFIX}{locked_rev}"));
        }
    }
    let rev = resolve_source_rev(nix, source)?;
    write_lock(lock_path, source, &rev)?;
    Ok(format!("{NIXPKGS_FLAKE_PREFIX}{rev}"))
}

/// Force a fresh resolution of `source`, ignoring any matching lock, and rewrite
/// `lock_path` — the explicit roll-forward. Records the previous revision (only when
/// the lock already pinned this same source) so the caller can report the change. A
/// 40-hex source resolves to itself with no nix call, so refreshing a fixed pin is a
/// well-defined no-op.
fn refresh_ref(nix: &Path, layout: &Layout, source: &str, lock_path: &Path) -> io::Result<Upgrade> {
    ensure(layout)?;
    let previous = read_lock(lock_path).and_then(|(s, r)| (s == source).then_some(r));
    let revision = resolve_source_rev(nix, source)?;
    write_lock(lock_path, source, &revision)?;
    Ok(Upgrade {
        source: source.to_string(),
        previous,
        revision,
    })
}

/// Resolve a source to its revision: a 40-hex source already *is* the revision (an
/// exact pin, needing no nix); a branch/channel is resolved via `nix flake metadata`.
fn resolve_source_rev(nix: &Path, source: &str) -> io::Result<String> {
    if let Some(rev) = valid_revision(source) {
        return Ok(rev);
    }
    resolve_channel_rev(nix, &format!("{NIXPKGS_FLAKE_PREFIX}{source}"))
}

/// Read a source-aware lock as `(source, revision)`. The format is two lines —
/// `<source>\n<rev>` — but a legacy single-line lock holding only a 40-hex revision
/// is read as the default channel's pin, so an existing lock keeps working. `None`
/// when the file is absent or its revision is malformed, so resolution re-runs rather
/// than trusting a corrupt revision.
fn read_lock(lock_path: &Path) -> Option<(String, String)> {
    let contents = std::fs::read_to_string(lock_path).ok()?;
    let mut lines = contents.lines();
    let first = lines.next()?.trim();
    match lines.next() {
        Some(second) => valid_revision(second.trim()).map(|rev| (first.to_string(), rev)),
        // a legacy single-line lock is a bare revision on the default channel
        None => valid_revision(first).map(|rev| (DEFAULT_SOURCE.to_string(), rev)),
    }
}

/// Write a source-aware lock as `<source>\n<rev>`, creating the parent directory
/// owner-only first (a per-project lock lives under a project's runtime tree).
///
/// The write is atomic: a per-pid temp beside the target is written then renamed
/// over it (`rename` is atomic on a POSIX filesystem). So a concurrent reader —
/// another launch resolving, or a second `sbx upgrade` — sees either the old lock
/// or the new one, never a half-written file. Two upgrades racing settle on a
/// last-writer-wins of two valid revisions, which the next upgrade reconciles.
fn write_lock(lock_path: &Path, source: &str, rev: &str) -> io::Result<()> {
    if let Some(parent) = lock_path.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let tmp = lock_path.with_extension(format!("tmp.{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, format!("{source}\n{rev}\n")) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, lock_path)
}

/// Resolve a channel reference to its current locked revision via
/// `nix flake metadata`, so provisioning can pin that exact revision.
fn resolve_channel_rev(nix: &Path, channel: &str) -> io::Result<String> {
    let out = Command::new(nix)
        .env("NO_COLOR", "1")
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["flake", "metadata", channel])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix flake metadata {channel} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    revision_from_metadata(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no revision in `nix flake metadata {channel}` output"),
        )
    })
}

/// Extract the revision from `nix flake metadata` text output: the first 40-hex
/// token on its `Revision:` line. Scanning by token (not a prefix strip) tolerates
/// the bold ANSI codes nix wraps the label in. Pure, so it is testable without
/// invoking nix.
fn revision_from_metadata(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .filter(|l| l.contains("Revision:"))
        .flat_map(str::split_whitespace)
        .find_map(valid_revision)
}

/// A git revision is exactly 40 lowercase hex characters; reject anything else so
/// a malformed lock or metadata line can never become a flake reference.
fn valid_revision(s: &str) -> Option<String> {
    let ok = s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    ok.then(|| s.to_string())
}

/// The host-side path backing a logical store path. `nix build --print-out-paths`
/// reports the *logical* path (`/nix/store/<hash>-<name>`), which is what resolves
/// *inside* the sandbox (where the store is bound at `/nix`); on the host the same
/// content lives under the store root, so a bind *source* must use this physical
/// path. Inside-sandbox uses (`PATH`, the loader) keep the logical path.
pub(crate) fn physical_path(layout: &Layout, logical: &Path) -> PathBuf {
    layout
        .store_dir()
        .join(logical.strip_prefix("/").unwrap_or(logical))
}

/// Provision `<flake_ref>#<attr>` into the user-owned store and return its
/// *logical* store path, rooting it against garbage collection with an out-link
/// at `gcroot`. `flake_ref` is the pinned reference from [`nixpkgs_ref`].
///
/// The build runs daemonless with the build sandbox on (safe here, in plain host
/// context outside the agent's cap-dropped cage). A derivation can have several
/// outputs (e.g. a `-man` beside the binary), so the output is selected by which
/// one actually contains `marker` — by content, not by order. nix's progress (the
/// first-run cache fetch) streams to the user; only the out-paths are captured.
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    gcroot: &Path,
    flake_ref: &str,
    attr: &str,
    marker: &str,
) -> io::Result<PathBuf> {
    provision_licensed(nix, layout, gcroot, flake_ref, attr, marker, false)
}

/// Like [`provision`], but permits an **unfree**-licensed attribute (a proprietary vendor
/// binary packaged in nixpkgs — e.g. an agent CLI whose upstream ships closed-source
/// releases). nixpkgs refuses to evaluate such a package unless allowed, so this builds it
/// through a **pure** expression that re-imports the pinned nixpkgs with a scoped
/// `config.allowUnfree = true` (see [`provision_command`]) — *not* `--impure`. Evaluation
/// therefore stays pure (`builtins.getEnv` reads nothing, no impure paths are touched) and the
/// unfree allowance is confined to this one import rather than being a global switch. The
/// resulting derivation is byte-identical to the `flake_ref#attr` build (same `.drv`), so the
/// output is as reproducible as the free path — only the licence gate changes.
///
/// Reachable **only** from the trusted-only `[packages]` `nix:` provisioning path (an
/// untrusted project's `[packages]` are dropped before provisioning), never from the
/// in-cage `sbx mise install nix:` self-equip path (a different builder that does not go
/// through here). So no untrusted input can trigger an unfree build, and — unfree being a
/// *licensing* gate, orthogonal to sbx's code-trust boundary — permitting it here changes
/// no security property.
pub(crate) fn provision_unfree(
    nix: &Path,
    layout: &Layout,
    gcroot: &Path,
    flake_ref: &str,
    attr: &str,
    marker: &str,
) -> io::Result<PathBuf> {
    provision_licensed(nix, layout, gcroot, flake_ref, attr, marker, true)
}

/// Assemble (without spawning) the `nix build` invocation [`provision_licensed`] runs, so its
/// argv is unit-testable without a real nix. A free build selects `<flake_ref>#<attr>`
/// positionally; an unfree build instead evaluates a **pure** `--expr` that re-imports the pinned
/// nixpkgs with a scoped `config.allowUnfree = true` — no `--impure`. Only stdout/stderr wiring is
/// left to the caller.
fn provision_command(
    nix: &Path,
    layout: &Layout,
    gcroot: &Path,
    flake_ref: &str,
    attr: &str,
    allow_unfree: bool,
) -> Command {
    let mut cmd = nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .arg("build")
        .args(["--option", "sandbox", "true"])
        .arg("--out-link")
        .arg(gcroot)
        .arg("--print-out-paths");
    if allow_unfree {
        // Permit an unfree attribute by re-importing the PINNED nixpkgs with a scoped
        // `config.allowUnfree = true`, evaluated purely — never `--impure`. `builtins.getFlake` on
        // a locked ref (a rev) is pure; the system is passed explicitly, so no impure
        // `builtins.currentSystem` is consulted; and the allowance is confined to this one import,
        // not a global eval switch. The derivation is byte-identical to the `flake_ref#attr` build
        // (same `.drv`), so nothing is unpinned — only the licence gate opens. `attr` is a dotted
        // attr-path (`python3Packages.foo` → nested access, matching the flakeref `#attr` form); a
        // segment containing `+` (which `is_valid_attr` admits) would parse here as the addition
        // operator and fail the build — vanishingly rare for an unfree package, and fail-closed.
        let system = format!("{}-linux", std::env::consts::ARCH);
        cmd.arg("--expr").arg(format!(
            "(import (builtins.getFlake \"{flake_ref}\").outPath \
             {{ config.allowUnfree = true; system = \"{system}\"; }}).{attr}"
        ));
    } else {
        cmd.arg(format!("{flake_ref}#{attr}"));
    }
    cmd
}

/// Shared body of [`provision`] / [`provision_unfree`]: build `<flake_ref>#<attr>` into the
/// user-owned store, rooted at `gcroot`, selecting the output that contains `marker`.
/// `allow_unfree` opts the one build into the unfree-permitting invocation described on
/// [`provision_unfree`].
fn provision_licensed(
    nix: &Path,
    layout: &Layout,
    gcroot: &Path,
    flake_ref: &str,
    attr: &str,
    marker: &str,
    allow_unfree: bool,
) -> io::Result<PathBuf> {
    ensure(layout)?;
    if let Some(parent) = gcroot.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    let mut cmd = provision_command(nix, layout, gcroot, flake_ref, attr, allow_unfree);
    cmd.stdout(Stdio::piped())
        // Nix's own progress is left visible on purpose. On a TTY it prints an `evaluating
        // derivation` line per flake-attr build (cheap eval-cache hits) and, on a cold launch, the
        // `copying path …` download progress — both worth seeing. An earlier `--log-format raw` hid
        // the eval chatter but also silenced the cold download (a first launch looked hung); the real
        // per-launch cost it papered over was the `--expr` re-evaluation, since removed by
        // [`provision_expr`]'s short-circuit, so there is nothing worth hiding here.
        .stderr(Stdio::inherit());

    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix build {flake_ref}#{attr} failed"
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    select_marked_output(layout, &stdout, attr, marker)
}

/// The out-link rooting the pinned channel's own flake **source**, placed beside the base
/// userland's out-links (see [`root_channel_source`]).
const CHANNEL_SOURCE_ROOT: &str = "channel-source";

/// Root the pinned channel's flake **source** against the shared store's collector.
///
/// Evaluating `<flake_ref>#<attr>` materializes nixpkgs' own source tree — a few hundred MiB — in
/// the store, and nothing rooted it: the out-links [`provision`] leaves point at build *outputs*,
/// never at the source they were evaluated from. So every shared-store collection reclaimed it and
/// the very next command that resolved the channel wrote it straight back: the collection reported
/// bytes it never durably freed, and a data directory that only grows paid the rewrite each time
/// (short of the filesystem's own trim, freed blocks are not returned to the host).
///
/// The root goes beside the base userland's, in the same `gcroots/base/<rev>/` directory, because
/// the source belongs to exactly that revision: the revision's own lifecycle then keeps it while
/// the channel is in use and prunes it when the channel moves on — no new root family for the
/// collector to learn, and no source outliving its revision.
///
/// **Cheap when warm, and best-effort.** A link that still resolves short-circuits before any nix
/// runs, so `nix flake metadata` is paid once per revision rather than once per launch. Every
/// failure path leaves the source unrooted — precisely the previous behaviour — and never fails a
/// launch: this reclaims churn, it is not a correctness control.
pub(crate) fn root_channel_source(nix: &Path, layout: &Layout, roots: &Path, flake_ref: &str) {
    let link = roots.join(CHANNEL_SOURCE_ROOT);
    // The link points at the *logical* `/nix/store/...` path, which does not exist on the host, so
    // its target is probed through `physical_path` — never followed — exactly as the marked-output
    // reuse does. A dangling link (its revision collected) falls through and is re-rooted.
    if let Ok(logical) = std::fs::read_link(&link) {
        if physical_path(layout, &logical).symlink_metadata().is_ok() {
            return;
        }
    }

    let Some(source) = channel_source_path(nix, layout, flake_ref) else {
        return;
    };
    let Some(nix_store) = resolve_nix_store(Some(layout)) else {
        return;
    };
    if let Some(parent) = link.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    // `--indirect` registers the link in the store's own `gcroots/auto/`, which is what makes it a
    // root the collector honours; `--realise` is how `nix-store` names the path to root.
    let _ = Command::new(nix_store)
        .env("NIX_REMOTE", "")
        .arg("--store")
        .arg(layout.store_dir())
        .arg("--add-root")
        .arg(&link)
        .arg("--indirect")
        .arg("--realise")
        .arg(&source)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// The store path of `flake_ref`'s source tree, read from `nix flake metadata`. `None` when nix
/// fails or reports no usable path — the caller then simply leaves the source unrooted.
fn channel_source_path(nix: &Path, layout: &Layout, flake_ref: &str) -> Option<PathBuf> {
    let out = nix_command(nix, layout)
        .env("NO_COLOR", "1")
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["flake", "metadata", flake_ref])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| source_path_from_metadata(&String::from_utf8_lossy(&out.stdout)))?
}

/// Extract the source path from `nix flake metadata` text output: the first token on its `Path:`
/// line that is a logical store path. Scanning by token (not a prefix strip) tolerates the ANSI
/// codes nix wraps the label in, mirroring [`revision_from_metadata`]. Requiring the `/nix/store/`
/// prefix is what keeps a surprising line from turning into an arbitrary path in a command. Pure,
/// so it is testable without invoking nix.
fn source_path_from_metadata(stdout: &str) -> Option<PathBuf> {
    stdout
        .lines()
        .filter(|l| l.contains("Path:"))
        .flat_map(str::split_whitespace)
        .find(|t| {
            t.strip_prefix("/nix/store/")
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        })
        .map(PathBuf::from)
}

/// Provision a `flake:` package from a full flake build *target* into the user-owned store,
/// gcrooted at `gcroot` — the same store setup, sandboxed build, and marked-output selection as
/// [`provision`], only the target is passed verbatim rather than assembled from `<flake_ref>#<attr>`.
/// The target is what a `flake:` package resolves to: a declared `github:owner/repo#attr`, a locked
/// `github:owner/repo/<rev>#attr`, or a bare `github:owner/repo` (the flake's default package). So a
/// `flake:` package builds host-side exactly like a `nix:` one — into the shared store, seeded per
/// project — instead of in-cage per project. The build sandbox is on (safe in plain host context);
/// build-time fetches use the host network, so a flake whose build self-fetches is unaffected by the
/// cage's egress allowlist. `--no-write-lock-file` leaves the flake's own lock untouched (the source
/// is a remote, read-only ref). `label` names the build in an error and drives the output selection.
///
/// Short-circuits on the target like [`provision_expr`], for a reason that does not apply to a `nix:`
/// attribute: a `nix:` target names the *pinned* channel revision, so `nix build` is a fast eval-cache
/// hit that never re-resolves; but a **floating** `flake:` target (no revision — e.g. `…#default`) would
/// re-resolve the flake's latest revision after nix's `tarball-ttl` and silently roll the tool. Keying a
/// `<gcroot>.expr` stamp on the *target string* and reusing the built output when the target is unchanged
/// **freezes a floating flake at its first build** until `sbx upgrade flake` pins it (which changes the
/// target to a locked ref → a rebuild), and makes a pinned flake a warm no-op until a roll changes its
/// locked ref. The reuse also lets a warm launch — and a fresh project seeding the shared build — skip
/// nix entirely, so it works offline.
pub(crate) fn provision_flake(
    nix: &Path,
    layout: &Layout,
    gcroot: &Path,
    target: &str,
    label: &str,
    marker: &str,
) -> io::Result<PathBuf> {
    ensure(layout)?;
    if let Some(parent) = gcroot.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    let stamp = expr_stamp_path(gcroot);
    let digest = expr_digest(target);
    if let Some(path) = reuse_built_expr(layout, gcroot, marker, &stamp, &digest) {
        return Ok(path);
    }

    let mut cmd = nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        // Nix's own progress (the first-run cache fetch / build) streams to the user, as in
        // [`provision`]. This build runs only when the short-circuit above misses — a cold or
        // retargeted (rolled/pinned) flake.
        .arg("build")
        .args(["--option", "sandbox", "true"])
        .arg("--no-write-lock-file")
        .arg("--out-link")
        .arg(gcroot)
        .arg("--print-out-paths")
        .arg(target)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!("nix build {target} failed")));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let resolved = select_marked_output(layout, &stdout, label, marker)?;
    // Stamp only after a successful, marked build, so a failed build never leaves a stamp that would
    // short-circuit to a nonexistent output next launch.
    write_expr_stamp(&stamp, &digest);
    Ok(resolved)
}

/// Provision a package built from a Nix *expression* into the user-owned store, gcrooted at
/// `gcroot`. The same store setup, gcroot, sandboxed build, and marked-output selection as
/// [`provision`], only the build target differs: `--expr <expr>` instead of `<flake_ref>#<attr>`.
/// It is for a package that cannot be named by a flake attribute path — an `.override { … }`,
/// notably — so the expression must reference nixpkgs itself; a `builtins.getFlake` on a
/// rev-pinned `github:NixOS/nixpkgs/<rev>` reference is a *locked* flake, so it evaluates purely
/// (no `--impure`). `label` names the build in an error and drives the marked-output selection.
///
/// Unlike a flake-attr build, an `--expr` build is **not** covered by nix's flake eval-cache, so
/// `nix build` re-evaluates the whole `getFlake` expression (~1s) on every launch even when the
/// output is fully built. To avoid that, this short-circuits: a sibling stamp (`<gcroot>.expr`)
/// records the SHA-256 of the expression that produced the current out-link, and when a launch's
/// expression hashes the same *and* the out-link still carries `marker`, the built output is
/// returned without spawning nix. Keying on the expression (not just the gcroot path) is
/// load-bearing: the expression is sbx-controlled and changes across sbx releases — a rev/system
/// change is in it too — so a changed expression mismatches and falls through to a rebuild, which
/// re-points the same out-link (no stale-serve, no accumulation). The one residual is that skipping
/// nix forfeits its self-heal of an out-of-band-corrupted store closure; that degrades to a loud
/// failure downstream (the per-project seed's `nix-store -qR`/copy aborts), never a silent bad cage.
pub(crate) fn provision_expr(
    nix: &Path,
    layout: &Layout,
    gcroot: &Path,
    expr: &str,
    label: &str,
    marker: &str,
) -> io::Result<PathBuf> {
    ensure(layout)?;
    if let Some(parent) = gcroot.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    let stamp = expr_stamp_path(gcroot);
    let digest = expr_digest(expr);
    if let Some(path) = reuse_built_expr(layout, gcroot, marker, &stamp, &digest) {
        return Ok(path);
    }

    let mut cmd = nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .arg("build")
        // Nix's own progress is left visible (see [`provision`]). This build now runs only when the
        // short-circuit above misses — a cold or changed expression — exactly when the evaluation and
        // download progress is worth showing.
        .args(["--option", "sandbox", "true"])
        .arg("--out-link")
        .arg(gcroot)
        .arg("--print-out-paths")
        .arg("--expr")
        .arg(expr)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix build --expr ({label}) failed"
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let resolved = select_marked_output(layout, &stdout, label, marker)?;
    // Stamp only after a successful, marked build, so a failed or partial build never leaves a stamp
    // that would short-circuit to a nonexistent output on the next launch.
    write_expr_stamp(&stamp, &digest);
    Ok(resolved)
}

/// The sibling stamp recording which expression built a gcroot's output: `<gcroot>.expr`. Appended
/// (not `with_extension`, which would eat a `.` in the gcroot name) so it never collides with the
/// out-link itself. It is a plain file, so it is inert to the gcroot symlink walks.
fn expr_stamp_path(gcroot: &Path) -> PathBuf {
    let mut s = gcroot.as_os_str().to_owned();
    s.push(".expr");
    PathBuf::from(s)
}

/// The SHA-256 (hex) of a provisioning expression — the key deciding whether a prior build can be
/// reused. The expression carries the nixpkgs revision, system, and every sbx-controlled input
/// verbatim, so an equal hash means an identical derivation and output.
fn expr_digest(expr: &str) -> String {
    Sha256::digest(expr.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The already-built output for an expression, when it can be reused without rebuilding: the stamp
/// records this exact expression's digest, the out-link still resolves, and its output still carries
/// `marker`. `None` (⇒ rebuild) on any miss — absent/stale stamp, a dangling or garbage-collected
/// out-link, or a missing marker — so a changed expression or a vanished output always rebuilds. The
/// out-link points at the logical `/nix/store/<hash>` path (mapped through [`physical_path`] for the
/// marker probe, never followed, exactly as [`select_marked_output`] does).
fn reuse_built_expr(
    layout: &Layout,
    gcroot: &Path,
    marker: &str,
    stamp: &Path,
    digest: &str,
) -> Option<PathBuf> {
    if std::fs::read_to_string(stamp).ok()?.trim() != digest {
        return None;
    }
    let logical = std::fs::read_link(gcroot).ok()?;
    physical_path(layout, &logical)
        .join(marker)
        .symlink_metadata()
        .ok()?;
    Some(logical)
}

/// Write the expression stamp atomically (temp + rename). Best-effort: a write failure just makes
/// the next launch rebuild instead of short-circuiting — slower, never incorrect.
fn write_expr_stamp(stamp: &Path, digest: &str) {
    let mut tmp = stamp.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, digest).is_ok() {
        let _ = std::fs::rename(&tmp, stamp);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Pick, among the logical store paths a build printed (`--print-out-paths` may list several —
/// e.g. a `-man` beside the binary), the one whose tree carries `marker`.
///
/// The entry is probed with `symlink_metadata` (lstat), not `Path::exists` (which follows
/// symlinks): a marker can be an *absolute in-store symlink* into a sibling output — for instance
/// nixpkgs' wrapped `nix`, whose installed `bin/nix` points at `/nix/store/<unwrapped>/bin/nix`.
/// That absolute path resolves *inside the cage* (where `/nix` IS this store) but not on the host
/// (where `/nix` is the host's own store), so following it would wrongly reject the bin-bearing
/// output and abort provisioning. The symlink target is in the output's closure, so the per-project
/// seed copies it and it resolves in-cage — selecting the output is correct; only the host-side
/// probe must not chase the link.
fn select_marked_output(
    layout: &Layout,
    stdout: &str,
    attr: &str,
    marker: &str,
) -> io::Result<PathBuf> {
    stdout
        .lines()
        .map(PathBuf::from)
        .find(|logical| {
            physical_path(layout, logical)
                .join(marker)
                .symlink_metadata()
                .is_ok()
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("no provisioned output of {attr} contains {marker}"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn layout_derives_store_paths_from_data_dir() {
        let layout = Layout::under(Path::new("/data/sbx"));
        assert_eq!(layout.data_dir.as_path(), Path::new("/data/sbx"));
        assert_eq!(layout.store_dir(), Path::new("/data/sbx/store"));
    }

    #[test]
    fn data_dir_prefers_absolute_xdg_else_falls_back_to_home() {
        assert_eq!(
            data_dir_from(None, Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/xdg/sbx"))
        );
        // a relative XDG_DATA_HOME is ignored; HOME is used instead
        assert_eq!(
            data_dir_from(
                None,
                Some(OsStr::new("rel/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            Some(PathBuf::from("/home/u/.local/share/sbx"))
        );
        assert_eq!(
            data_dir_from(None, None, Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.local/share/sbx"))
        );
        assert_eq!(data_dir_from(None, None, None), None);
    }

    #[test]
    fn an_absolute_data_dir_override_wins_verbatim_and_a_relative_one_is_refused() {
        // It outranks both lower sources, and names the directory itself: no `sbx`
        // is appended, unlike the shared XDG base.
        let over = data_dir_from(
            Some(OsStr::new("/vol/data")),
            Some(OsStr::new("/xdg")),
            Some(OsStr::new("/home/u")),
        );
        assert_eq!(over, Some(PathBuf::from("/vol/data")));
        assert_ne!(over, Some(PathBuf::from("/vol/data/sbx")));

        // A relative override is refused outright — crucially it does NOT fall
        // through to a lower source, which would silently use another directory.
        assert_eq!(
            data_dir_from(
                Some(OsStr::new("rel/data")),
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            None
        );

        // Empty reads as absent, so clearing the variable restores the default.
        assert_eq!(
            data_dir_from(
                Some(OsStr::new("")),
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            Some(PathBuf::from("/xdg/sbx"))
        );
    }

    #[test]
    fn a_data_dir_override_too_long_to_host_a_unix_socket_is_refused() {
        // The bound is what is left of `sun_path` once the widest socket name sbx
        // appends is accounted for, so a directory at the limit still works...
        let at_limit = format!("/{}", "d".repeat(DATA_DIR_MAX - 1));
        assert_eq!(at_limit.len(), DATA_DIR_MAX);
        assert!(check_data_dir_override(OsStr::new(&at_limit)).is_ok());

        // ...and one byte more does not. Teeth: the longest socket path that
        // directory would have to carry must actually overrun the kernel's field.
        let over = format!("/{}", "d".repeat(DATA_DIR_MAX));
        assert_eq!(over.len(), DATA_DIR_MAX + 1);
        assert!(over.len() + LONGEST_SOCKET_SUFFIX > SUN_PATH_MAX);
        let why = check_data_dir_override(OsStr::new(&over)).unwrap_err();
        assert!(why.contains("at most"), "{why}");

        // And it is refused, not silently swapped for a lower source.
        assert_eq!(
            data_dir_from(
                Some(OsStr::new(&over)),
                Some(OsStr::new("/xdg")),
                Some(OsStr::new("/home/u"))
            ),
            None
        );
    }

    #[test]
    fn a_derived_data_dir_too_long_for_a_socket_is_caught_but_still_adoptable() {
        // A directory at the limit passes; one byte more overruns the widest socket path.
        let at_limit = PathBuf::from(format!("/{}", "d".repeat(DATA_DIR_MAX - 1)));
        assert_eq!(at_limit.as_os_str().len(), DATA_DIR_MAX);
        assert!(check_resolved_data_dir(&at_limit).is_ok());

        let over = PathBuf::from(format!("/{}", "d".repeat(DATA_DIR_MAX)));
        assert_eq!(over.as_os_str().len(), DATA_DIR_MAX + 1);
        assert!(over.as_os_str().len() + LONGEST_SOCKET_SUFFIX > SUN_PATH_MAX);
        let why = check_resolved_data_dir(&over).unwrap_err();
        assert!(why.contains("at most"), "{why}");
        assert!(why.contains("SBX_DATA_DIR"), "names the remedy: {why}");

        // The derivation itself does NOT drop a long `$HOME` — `data_dir_from` still returns it,
        // so `sbx storage` (which anchors to that path, not the guarded resolution) can create
        // the image and adopt a volume whose short mount point then passes the guard.
        let long_home = "/".to_string() + &"h".repeat(DATA_DIR_MAX);
        let derived = data_dir_from(None, None, Some(OsStr::new(&long_home)))
            .expect("a long derived home still resolves to a path storage can adopt from");
        assert!(check_resolved_data_dir(&derived).is_err());
    }

    #[test]
    fn ensure_creates_dirs_owner_only_and_is_idempotent() {
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));

        ensure(&layout).unwrap();
        for dir in [layout.data_dir.clone(), layout.store_dir()] {
            assert!(dir.is_dir(), "{} should exist", dir.display());
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} should be owner-only", dir.display());
        }
        // idempotent: a second call succeeds and leaves perms owner-only
        ensure(&layout).unwrap();
        let mode = std::fs::metadata(layout.store_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn ensure_tightens_a_preexisting_loose_store_root() {
        let base = TmpDir::new();
        let data = base.join("sbx");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777)).unwrap();

        ensure(&Layout::under(&data)).unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "loose perms must be tightened");
    }

    #[test]
    fn nix_command_is_daemonless_and_targets_the_store() {
        let layout = Layout::under(Path::new("/data/sbx"));
        let cmd = nix_command(Path::new("/usr/bin/nix"), &layout);

        // the daemon is disabled
        let remote = cmd
            .get_envs()
            .find(|(k, _)| *k == OsStr::new("NIX_REMOTE"))
            .map(|(_, v)| v);
        assert_eq!(remote, Some(Some(OsStr::new(""))));

        // the user-owned store is targeted
        let args: Vec<_> = cmd.get_args().collect();
        assert_eq!(
            args,
            vec![OsStr::new("--store"), OsStr::new("/data/sbx/store")]
        );
    }

    /// The `NIX_CONFIG` a [`nix_command`] carries, if any.
    fn nix_config_of(cmd: &Command) -> Option<String> {
        cmd.get_envs()
            .find(|(k, _)| *k == OsStr::new("NIX_CONFIG"))
            .and_then(|(_, v)| v)
            .and_then(|v| v.to_str())
            .map(str::to_string)
    }

    #[test]
    fn nix_command_leaves_nix_config_alone_off_btrfs() {
        // `/proc` is never btrfs, so the nearest-ancestor filesystem probe is
        // deterministic here: no accommodation is injected, and whatever
        // `NIX_CONFIG` the environment carries reaches nix untouched.
        let layout = Layout::under(Path::new("/proc/sbx-absent-by-construction"));
        let cmd = nix_command(Path::new("/usr/bin/nix"), &layout);
        assert_eq!(nix_config_of(&cmd), None);
    }

    #[test]
    fn nix_command_ignores_the_compression_attribute_on_a_btrfs_store() {
        // Needs a real btrfs mount to point the store at; skip where the host has none.
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        let Some(btrfs_mount) = mounts.lines().find_map(|l| {
            let mut f = l.split_whitespace();
            let (_, mnt, kind) = (f.next()?, f.next()?, f.next()?);
            (kind == "btrfs").then(|| PathBuf::from(mnt))
        }) else {
            eprintln!("skipping: no btrfs mount on this host");
            return;
        };
        let layout = Layout::under(&btrfs_mount);
        let cmd = nix_command(Path::new("/usr/bin/nix"), &layout);
        let cfg = nix_config_of(&cmd).expect("a btrfs store must carry NIX_CONFIG");
        assert!(
            cfg.contains("extra-ignored-acls = btrfs.compression"),
            "{cfg}"
        );
    }

    #[test]
    fn btrfs_nix_config_appends_to_an_inherited_value_and_stands_alone_without_one() {
        assert_eq!(
            btrfs_nix_config(None),
            "extra-ignored-acls = btrfs.compression"
        );
        assert_eq!(
            btrfs_nix_config(Some("")),
            "extra-ignored-acls = btrfs.compression"
        );
        // the environment's own settings stay in force, first
        assert_eq!(
            btrfs_nix_config(Some("substituters = https://example.org")),
            "substituters = https://example.org\nextra-ignored-acls = btrfs.compression"
        );
    }

    #[test]
    fn provision_command_permits_unfree_via_a_pure_expr_only_when_asked() {
        let layout = Layout::under(Path::new("/data/sbx"));
        let has_env = |cmd: &Command| {
            cmd.get_envs()
                .any(|(k, _)| k == OsStr::new("NIXPKGS_ALLOW_UNFREE"))
        };
        let has_impure = |cmd: &Command| cmd.get_args().any(|a| a == OsStr::new("--impure"));
        // The single argument following `--expr`, if any.
        let expr_arg = |cmd: &Command| -> Option<String> {
            let args: Vec<_> = cmd.get_args().collect();
            let i = args.iter().position(|a| *a == OsStr::new("--expr"))?;
            args.get(i + 1).map(|a| a.to_string_lossy().into_owned())
        };

        // The unfree path evaluates a PURE `--expr` that re-imports the pinned nixpkgs with a scoped
        // `config.allowUnfree = true` — so a proprietary attribute evaluates instead of being
        // refused — while carrying NEITHER `--impure` NOR the allow-env, so evaluation stays pure.
        let unfree = provision_command(
            Path::new("/nix"),
            &layout,
            Path::new("/g"),
            "nixpkgs",
            "kiro-cli",
            true,
        );
        assert!(
            !has_env(&unfree),
            "unfree build must not set NIXPKGS_ALLOW_UNFREE"
        );
        assert!(
            !has_impure(&unfree),
            "unfree build must stay pure (no --impure)"
        );
        let expr = expr_arg(&unfree).expect("unfree build must select via --expr");
        assert!(
            expr.contains("config.allowUnfree = true")
                && expr.contains("builtins.getFlake")
                && expr.contains(").kiro-cli"),
            "the expr must scope allowUnfree over the pinned flake's attr:\n{expr}"
        );
        // The positional `flake_ref#attr` installable must be absent — the expr is the installable.
        assert!(
            !unfree
                .get_args()
                .any(|a| a == OsStr::new("nixpkgs#kiro-cli")),
            "unfree build must not also pass the positional installable"
        );

        // The free path (every base-userland / fonts / gpu provision) selects the positional
        // `flake_ref#attr` with no `--expr`, no `--impure`, and no allow-env — nothing silently
        // loosens the licence gate for sbx's own components.
        let free = provision_command(
            Path::new("/nix"),
            &layout,
            Path::new("/g"),
            "nixpkgs",
            "hello",
            false,
        );
        assert!(
            !has_env(&free),
            "free build must not set NIXPKGS_ALLOW_UNFREE"
        );
        assert!(
            !has_impure(&free),
            "free build must stay pure (no --impure)"
        );
        assert!(expr_arg(&free).is_none(), "free build must not use --expr");
        assert!(
            free.get_args().any(|a| a == OsStr::new("nixpkgs#hello")),
            "free build must select the positional installable"
        );
    }

    #[test]
    fn physical_path_maps_a_logical_store_path_under_the_store_root() {
        let layout = Layout::under(Path::new("/data/sbx"));
        assert_eq!(
            physical_path(&layout, Path::new("/nix/store/abc-hello")),
            PathBuf::from("/data/sbx/store/nix/store/abc-hello")
        );
        assert_eq!(
            physical_path(&layout, Path::new("/nix")),
            PathBuf::from("/data/sbx/store/nix")
        );
    }

    #[test]
    fn select_marked_output_accepts_a_marker_that_is_an_absolute_in_store_symlink() {
        // A wrapped output (nixpkgs' `nix`) carries its marker as an absolute in-store symlink
        // into a sibling output. That target only resolves inside the cage (`/nix` == the store),
        // not on the host, so the selection must probe with lstat, never follow the link.
        use std::os::unix::fs::symlink;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());

        // `<store>/nix/store/out-man` — no marker.
        let man = physical_path(&layout, Path::new("/nix/store/out-man"));
        std::fs::create_dir_all(&man).unwrap();
        // `<store>/nix/store/out/bin/nix` — a symlink to an absolute /nix path absent on the host.
        let out_bin = physical_path(&layout, Path::new("/nix/store/out")).join("bin");
        std::fs::create_dir_all(&out_bin).unwrap();
        symlink("/nix/store/unwrapped/bin/nix", out_bin.join("nix")).unwrap();
        assert!(
            !out_bin.join("nix").exists(),
            "the absolute symlink must be unresolvable on the host (the bug's precondition)"
        );

        let stdout = "/nix/store/out-man\n/nix/store/out\n";
        assert_eq!(
            select_marked_output(&layout, stdout, "nix", "bin/nix").unwrap(),
            PathBuf::from("/nix/store/out"),
            "the bin-bearing output is selected by the symlink entry, not by following it"
        );

        // and a genuinely-absent marker still errors (no false positive).
        assert!(select_marked_output(&layout, stdout, "nix", "bin/absent").is_err());
    }

    #[test]
    fn revision_parsing_takes_the_metadata_revision_line() {
        let meta = "Resolved URL:  github:NixOS/nixpkgs/nixos-unstable\n\
                    Locked URL:    github:NixOS/nixpkgs/9ae611a455b90cf061d8f332b977e387bda8e1ca\n\
                    Revision:      9ae611a455b90cf061d8f332b977e387bda8e1ca\n\
                    Last modified: 2026-06-14\n";
        assert_eq!(
            revision_from_metadata(meta).as_deref(),
            Some("9ae611a455b90cf061d8f332b977e387bda8e1ca")
        );
        // the label may be wrapped in bold ANSI codes — still parse the revision
        let colored = "\u{1b}[1mRevision:\u{1b}[0m      9ae611a455b90cf061d8f332b977e387bda8e1ca\n";
        assert_eq!(
            revision_from_metadata(colored).as_deref(),
            Some("9ae611a455b90cf061d8f332b977e387bda8e1ca")
        );
        assert_eq!(revision_from_metadata("no revision here\n"), None);
    }

    /// The channel source is what the collector kept reclaiming and the next command kept writing
    /// back, so reading its path out of the metadata is what makes rooting it possible at all.
    #[test]
    fn source_path_parsing_takes_the_metadata_path_line() {
        // The real shape, ANSI-bold labels included: `Path:` is not the only line, and `Locked URL`
        // sits right above it.
        let meta = "\u{1b}[1mResolved URL:\u{1b}[0m  github:NixOS/nixpkgs/nixos-unstable\n\
                    \u{1b}[1mLocked URL:\u{1b}[0m    github:NixOS/nixpkgs/9ae611a4?narHash=sha256-x\n\
                    \u{1b}[1mPath:\u{1b}[0m          /nix/store/llgwlxshmy0ifvxh7f8wq53vk5x7vd13-source\n\
                    \u{1b}[1mRevision:\u{1b}[0m      9ae611a455b90cf061d8f332b977e387bda8e1ca\n";
        assert_eq!(
            source_path_from_metadata(meta),
            Some(PathBuf::from(
                "/nix/store/llgwlxshmy0ifvxh7f8wq53vk5x7vd13-source"
            ))
        );

        // No `Path:` line at all — the caller then leaves the source unrooted rather than guessing.
        assert_eq!(source_path_from_metadata("Revision: abc\n"), None);

        // The prefix requirement is a guard, not decoration: only a logical store path may reach
        // the command that roots it, so a `Path:` naming anything else yields nothing.
        assert_eq!(source_path_from_metadata("Path:  /etc/passwd\n"), None);
        assert_eq!(source_path_from_metadata("Path:  relative/thing\n"), None);
        // A *sub*-path is not a store path either: rooting `…-source/pkgs` would root nothing.
        assert_eq!(
            source_path_from_metadata("Path:  /nix/store/abc-source/pkgs\n"),
            None
        );
        assert_eq!(source_path_from_metadata("Path:  /nix/store/\n"), None);
    }

    #[test]
    fn valid_revision_requires_40_lowercase_hex() {
        let good = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
        assert_eq!(valid_revision(good).as_deref(), Some(good));
        assert_eq!(valid_revision(""), None);
        assert_eq!(valid_revision("9ae611a4"), None); // too short
        assert_eq!(valid_revision(&"z".repeat(40)), None); // not hex
        assert_eq!(valid_revision(&good.to_uppercase()), None); // not lowercase
    }

    const REV: &str = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
    const BOGUS_NIX: &str = "/nonexistent-nix";

    #[test]
    fn a_seeded_lock_is_reused_without_invoking_nix() {
        // The headline guarantee: with the revision already recorded for the same
        // source, an sbx binary update (or any later run) reuses it and never
        // re-resolves. Proven with a bogus nix path — if the early return ever
        // regressed, resolution would invoke it and the call would fail. Uses a
        // legacy single-line lock, which also proves backward compatibility.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(layout.data_dir().join(NIXPKGS_LOCK), format!("{REV}\n")).unwrap();

        let got = LockTarget::global(&layout, None)
            .resolve(Path::new(BOGUS_NIX), &layout)
            .expect("lock reused");
        assert_eq!(got, format!("{NIXPKGS_FLAKE_PREFIX}{REV}"));
    }

    #[test]
    fn a_malformed_lock_self_heals_instead_of_being_trusted() {
        // A corrupt lock must fall through to resolution, never become a flake
        // reference; with a bogus nix that resolution fails, proving we did not
        // early-return on a garbage revision.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(layout.data_dir().join(NIXPKGS_LOCK), "garbage\n").unwrap();

        assert!(LockTarget::global(&layout, None)
            .resolve(Path::new(BOGUS_NIX), &layout)
            .is_err());
    }

    #[test]
    fn live_base_revisions_collects_the_global_and_each_project_pin() {
        const REV_B: &str = "0123456789abcdef0123456789abcdef01234567";
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        // the global channel revision
        write_lock(&layout.data_dir().join(NIXPKGS_LOCK), "nixos-unstable", REV).unwrap();
        // a pinned project contributes its own revision
        let p1 = layout.data_dir().join("projects").join("p1");
        std::fs::create_dir_all(&p1).unwrap();
        write_lock(&p1.join(NIXPKGS_LOCK), "nixos-23.11", REV_B).unwrap();
        // a non-pinned project (no lock) contributes nothing — it rides the global rev
        std::fs::create_dir_all(layout.data_dir().join("projects").join("p2")).unwrap();

        let live = live_base_revisions(&layout);
        assert!(live.contains(REV), "the global rev must be live");
        assert!(live.contains(REV_B), "a pinned project's rev must be live");
        assert_eq!(
            live.len(),
            2,
            "only the global and the one pin are live: {live:?}"
        );
    }

    #[test]
    fn live_mise_revisions_falls_back_to_the_global_lock_when_the_engine_lock_is_absent() {
        const ENGINE_REV: &str = "fedcba9876543210fedcba9876543210fedcba98";
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        write_lock(&layout.data_dir().join(NIXPKGS_LOCK), "nixos-unstable", REV).unwrap();

        // no engine lock yet → the engine runs on the global rev, which must be kept
        assert!(
            live_mise_revisions(&layout).contains(REV),
            "an absent engine lock must fall back to the global rev"
        );

        // once the engine lock exists it is the sole authority
        write_lock(&engine_lock_path(&layout), "nixos-unstable", ENGINE_REV).unwrap();
        assert_eq!(
            live_mise_revisions(&layout),
            BTreeSet::from([ENGINE_REV.to_string()])
        );
    }

    #[test]
    fn write_lock_is_atomic_and_leaves_no_temp_file() {
        // The atomic write renames a temp over the target, so after it returns only
        // the final lock remains — no stray temp beside it for a reader to trip on.
        let base = TmpDir::new();
        let dir = base.join("sbx");
        std::fs::create_dir_all(&dir).unwrap();
        let lock = dir.join(NIXPKGS_LOCK);
        write_lock(&lock, "nixos-unstable", REV).unwrap();

        assert_eq!(
            read_lock(&lock),
            Some(("nixos-unstable".to_string(), REV.to_string()))
        );
        let temps: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(temps.is_empty(), "a temp file was left behind: {temps:?}");
    }

    #[test]
    fn read_lock_parses_two_line_and_legacy_formats() {
        let base = TmpDir::new();
        let two_line = base.join("two.lock");
        std::fs::write(&two_line, format!("nixos-23.11\n{REV}\n")).unwrap();
        assert_eq!(
            read_lock(&two_line),
            Some(("nixos-23.11".to_string(), REV.to_string()))
        );
        // a legacy single-line lock is read as a bare revision on the default source
        let legacy = base.join("legacy.lock");
        std::fs::write(&legacy, format!("{REV}\n")).unwrap();
        assert_eq!(
            read_lock(&legacy),
            Some((DEFAULT_SOURCE.to_string(), REV.to_string()))
        );
        // a malformed revision is not trusted
        let bad = base.join("bad.lock");
        std::fs::write(&bad, "nixos-23.11\nnot-a-rev\n").unwrap();
        assert_eq!(read_lock(&bad), None);
        assert_eq!(read_lock(&base.join("absent.lock")), None);
    }

    #[test]
    fn changing_the_source_re_resolves_a_pinned_lock() {
        // A lock pinned to one source must not satisfy a request for a different
        // source: the catalogue moved, so it re-resolves (here, against a bogus nix,
        // so the attempt fails — proving the early return did not fire).
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(
            layout.data_dir().join(NIXPKGS_LOCK),
            format!("nixos-unstable\n{REV}\n"),
        )
        .unwrap();

        assert!(LockTarget::global(&layout, Some("nixos-23.11"))
            .resolve(Path::new(BOGUS_NIX), &layout)
            .is_err());
    }

    #[test]
    fn a_revision_source_is_used_without_invoking_nix_and_is_locked() {
        // A 40-hex source is already a revision: it pins directly, with no nix call,
        // and is recorded so later runs reuse it.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));

        let got = LockTarget::global(&layout, Some(REV))
            .resolve(Path::new(BOGUS_NIX), &layout)
            .expect("rev pins directly");
        assert_eq!(got, format!("{NIXPKGS_FLAKE_PREFIX}{REV}"));
        assert_eq!(
            read_lock(&layout.data_dir().join(NIXPKGS_LOCK)),
            Some((REV.to_string(), REV.to_string()))
        );
    }

    #[test]
    fn lock_target_construction_sets_source_path_and_origin() {
        let layout = Layout::under(Path::new("/data/sbx"));

        let default = LockTarget::global(&layout, None);
        assert_eq!(default.source(), DEFAULT_SOURCE);
        assert_eq!(default.origin(), Origin::Default);
        assert_eq!(default.lock_path, PathBuf::from("/data/sbx/nixpkgs.lock"));

        let over = LockTarget::global(&layout, Some("nixos-23.11"));
        assert_eq!(over.source(), "nixos-23.11");
        assert_eq!(over.origin(), Origin::Global);
        assert_eq!(over.lock_path, PathBuf::from("/data/sbx/nixpkgs.lock"));

        let proj = LockTarget::project(&layout, "abc", "nixos-23.11");
        assert_eq!(proj.source(), "nixos-23.11");
        assert_eq!(proj.origin(), Origin::ProjectPin);
        assert_eq!(
            proj.lock_path,
            PathBuf::from("/data/sbx/projects/abc/nixpkgs.lock")
        );

        // the engine tracks the same source as the global channel (default, or a global
        // override) but pins it in its OWN lock — never the shared nixpkgs.lock — so the
        // two roll forward independently.
        let engine = LockTarget::engine(&layout, None);
        assert_eq!(engine.source(), DEFAULT_SOURCE);
        assert_eq!(engine.origin(), Origin::Default);
        assert_eq!(
            engine.lock_path,
            PathBuf::from("/data/sbx/mise-engine.lock")
        );
        let engine_over = LockTarget::engine(&layout, Some("nixos-23.11"));
        assert_eq!(engine_over.source(), "nixos-23.11");
        assert_eq!(engine_over.origin(), Origin::Global);
        assert_eq!(
            engine_over.lock_path,
            PathBuf::from("/data/sbx/mise-engine.lock")
        );
    }

    #[test]
    fn a_project_target_pins_its_source_in_a_per_project_lock() {
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));

        // a revision source pins without nix, into the project's own lock
        let got = LockTarget::project(&layout, "abc", REV)
            .resolve(Path::new(BOGUS_NIX), &layout)
            .expect("pinned");
        assert_eq!(got, format!("{NIXPKGS_FLAKE_PREFIX}{REV}"));
        let lock = project_lock_path(&layout, "abc");
        assert_eq!(read_lock(&lock), Some((REV.to_string(), REV.to_string())));
    }

    #[test]
    fn locked_revision_honors_the_source() {
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let lock = global_lock_path(&layout);

        // a lock recording this target's source reports its revision
        std::fs::write(&lock, format!("nixos-unstable\n{REV}\n")).unwrap();
        assert_eq!(
            LockTarget::global(&layout, None)
                .locked_revision()
                .as_deref(),
            Some(REV)
        );
        // a lock recording a *different* source reads as not-current (the launch
        // would re-resolve it), so it must not display as this source's revision
        std::fs::write(&lock, format!("nixos-23.11\n{REV}\n")).unwrap();
        assert_eq!(LockTarget::global(&layout, None).locked_revision(), None);
        // and read_global_lock still reports what is actually on disk
        assert_eq!(
            read_global_lock(&layout),
            Some(("nixos-23.11".to_string(), REV.to_string()))
        );
    }

    #[test]
    fn refresh_forces_resolution_even_when_the_lock_matches() {
        // Upgrade must re-resolve the channel, never reuse a matching lock — proven
        // with a bogus nix: a channel source must invoke it (and so fail), where a
        // plain resolve would have early-returned the locked revision.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(
            global_lock_path(&layout),
            format!("nixos-unstable\n{REV}\n"),
        )
        .unwrap();

        assert!(LockTarget::global(&layout, None)
            .refresh(Path::new(BOGUS_NIX), &layout)
            .is_err());
        // a failed upgrade is non-destructive: the prior lock is left intact, never
        // truncated, so the next launch still resolves the known-good revision
        assert_eq!(
            read_lock(&global_lock_path(&layout)),
            Some(("nixos-unstable".to_string(), REV.to_string()))
        );
    }

    #[test]
    fn refresh_of_a_revision_pin_is_a_noop_without_nix() {
        // A 40-hex source resolves to itself with no nix call, so refreshing a fixed
        // pin reports the same revision as previous and new — an explicit no-op.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(global_lock_path(&layout), format!("{REV}\n{REV}\n")).unwrap();

        let up = LockTarget::global(&layout, Some(REV))
            .refresh(Path::new(BOGUS_NIX), &layout)
            .expect("a revision pin refreshes without nix");
        assert_eq!(up.source, REV);
        assert_eq!(up.previous.as_deref(), Some(REV));
        assert_eq!(up.revision, REV);
        assert!(is_pinned_revision(&up.source), "the source is a fixed pin");
    }

    #[test]
    fn refresh_reports_no_previous_after_a_source_switch() {
        // When the lock records a *different* source than the one being refreshed, the
        // prior revision belongs to another channel, so it is not reported as this
        // source's previous (a switch reads as a first pin).
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let old = "0".repeat(40);
        std::fs::write(global_lock_path(&layout), format!("nixos-23.11\n{old}\n")).unwrap();

        // refresh to a revision source (no nix needed), distinct from the locked source
        let up = LockTarget::global(&layout, Some(REV))
            .refresh(Path::new(BOGUS_NIX), &layout)
            .expect("revision refresh needs no nix");
        assert_eq!(
            up.previous, None,
            "a source switch has no comparable previous"
        );
        assert_eq!(up.revision, REV);
    }

    #[test]
    fn engine_seeds_from_the_global_lock_so_a_binary_update_never_moves_it() {
        // The migration path: an established install has nixpkgs.lock but no engine lock.
        // The engine must seed its revision FROM the global lock — no nix, no version
        // bump — so a mere binary update never advances the in-cage mise, and the first
        // launch still works offline. Proven with a bogus nix: if the engine resolved
        // fresh instead of seeding, it would invoke nix and the call would fail.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(
            layout.data_dir().join(NIXPKGS_LOCK),
            format!("nixos-unstable\n{REV}\n"),
        )
        .unwrap();
        // no mise-engine.lock yet
        assert!(!layout.data_dir().join(MISE_ENGINE_LOCK).exists());

        let got = resolve_engine_ref(Path::new(BOGUS_NIX), &layout, None)
            .expect("engine seeds from the global lock with no nix");
        assert_eq!(got, format!("{NIXPKGS_FLAKE_PREFIX}{REV}"));
        // it recorded the seed in the engine's own lock, so later launches reuse it
        assert_eq!(
            read_lock(&engine_lock_path(&layout)),
            Some(("nixos-unstable".to_string(), REV.to_string()))
        );
        // a second resolution now reuses the engine lock directly (still no nix)
        assert_eq!(
            resolve_engine_ref(Path::new(BOGUS_NIX), &layout, None).unwrap(),
            format!("{NIXPKGS_FLAKE_PREFIX}{REV}")
        );
    }

    #[test]
    fn engine_with_no_lock_anywhere_resolves_fresh_and_so_needs_nix() {
        // A pinned-only user who has never resolved the global channel has neither lock for
        // this source: the engine has nothing to seed from, so it resolves fresh — which
        // needs nix (here a bogus one, so it fails, proving no spurious seed happened).
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        assert!(resolve_engine_ref(Path::new(BOGUS_NIX), &layout, None).is_err());
    }

    #[test]
    fn revision_of_takes_the_last_path_segment() {
        assert_eq!(revision_of(&format!("{NIXPKGS_FLAKE_PREFIX}{REV}")), REV);
        assert_eq!(revision_of("no-slashes"), "no-slashes");
    }

    #[test]
    fn is_pinned_revision_only_for_a_40_hex_source() {
        assert!(is_pinned_revision(REV));
        assert!(!is_pinned_revision("nixos-unstable"));
        assert!(!is_pinned_revision("nixos-23.11"));
    }

    #[test]
    fn engine_sibling_resolves_nix_and_its_neighbours() {
        let nix = Path::new("/opt/engine/bin/nix");
        // `nix` itself is the override path verbatim.
        assert_eq!(
            engine_sibling(nix, "nix"),
            PathBuf::from("/opt/engine/bin/nix")
        );
        // a sibling command shares the directory.
        assert_eq!(
            engine_sibling(nix, "nix-store"),
            PathBuf::from("/opt/engine/bin/nix-store")
        );
        // no parent → the bare command name.
        assert_eq!(
            engine_sibling(Path::new("nix"), "nix-store"),
            PathBuf::from("nix-store")
        );
    }

    #[test]
    fn engine_verdict_accepts_us_or_root_and_refuses_the_rest() {
        let reg = |perm: u32| perm | libc::S_IFREG;
        // owned by us, not world-writable → trusted (group-writable is tolerated)
        assert!(engine_verdict(1000, reg(0o755), 1000).is_ok());
        assert!(engine_verdict(1000, reg(0o775), 1000).is_ok());
        // root-owned is accepted — the host /usr/bin/bwrap is root:root and an override may be a
        // system binary; neither is writable by an unprivileged attacker.
        assert!(engine_verdict(0, reg(0o755), 1000).is_ok());
        // a foreign, non-root owner is refused, naming the uid
        let e = engine_verdict(1234, reg(0o755), 1000).unwrap_err();
        assert!(e.contains("owned by uid 1234"), "got: {e}");
        // world-writable is refused even when owned by us
        assert!(engine_verdict(1000, reg(0o757), 1000)
            .unwrap_err()
            .contains("world-writable"));
        // a non-regular file (here a directory) is refused
        assert!(engine_verdict(1000, libc::S_IFDIR | 0o755, 1000)
            .unwrap_err()
            .contains("not a regular file"));
    }

    #[test]
    fn pick_engine_bin_follows_override_then_owned_then_path() {
        let over = Path::new("/over/nix");
        let owned = Path::new("/data/engine");
        let on_path = |n: &str| vec![PathBuf::from(format!("/usr/bin/{n}"))];

        // The override wins when its file is present and trusted; nix-store derives as a sibling.
        let all = |_: &Path| EngineProbe::Trusted;
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &all, &on_path),
            Some(PathBuf::from("/over/nix"))
        );
        assert_eq!(
            pick_engine_bin("nix-store", Some(over), Some(owned), &all, &on_path),
            Some(PathBuf::from("/over/nix-store"))
        );

        // A resolved override is authoritative: a missing sibling fails closed rather
        // than mixing in the host's nix-store, while `nix` itself still resolves.
        let only_override_nix = |p: &Path| {
            if p == Path::new("/over/nix") {
                EngineProbe::Trusted
            } else {
                EngineProbe::Absent
            }
        };
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &only_override_nix, &on_path),
            Some(PathBuf::from("/over/nix"))
        );
        assert_eq!(
            pick_engine_bin(
                "nix-store",
                Some(over),
                Some(owned),
                &only_override_nix,
                &on_path
            ),
            None
        );

        // An override whose `nix` is absent is treated as unset: the next tier (here
        // the sbx-owned engine directory) applies.
        let only_owned = |p: &Path| {
            if p.starts_with("/data/engine") {
                EngineProbe::Trusted
            } else {
                EngineProbe::Absent
            }
        };
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &only_owned, &on_path),
            Some(PathBuf::from("/data/engine/nix"))
        );

        // With neither override nor owned engine present, it falls to the (trusted) host `PATH`.
        let host_only = |p: &Path| {
            if p.starts_with("/usr/bin") {
                EngineProbe::Trusted
            } else {
                EngineProbe::Absent
            }
        };
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &host_only, &on_path),
            Some(PathBuf::from("/usr/bin/nix"))
        );

        // No layout (no owned dir) simply skips that tier.
        assert_eq!(
            pick_engine_bin("nix-store", None, None, &host_only, &on_path),
            Some(PathBuf::from("/usr/bin/nix-store"))
        );

        // Nothing anywhere → None; the caller turns it into a pointed error.
        let no_path = |_: &str| Vec::<PathBuf>::new();
        assert_eq!(
            pick_engine_bin("nix", None, None, &host_only, &no_path),
            None
        );

        // An override present but UNtrusted is refused outright — never silently replaced by
        // the (here trusted) owned tier; the deliberate choice fails closed.
        let over_untrusted = |p: &Path| {
            if p.starts_with("/over") {
                EngineProbe::Untrusted
            } else {
                EngineProbe::Trusted
            }
        };
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &over_untrusted, &on_path),
            None
        );

        // An untrusted owned engine is skipped (warned) and resolution falls through to `PATH`.
        let owned_untrusted = |p: &Path| {
            if p.starts_with("/data/engine") {
                EngineProbe::Untrusted
            } else {
                EngineProbe::Trusted
            }
        };
        assert_eq!(
            pick_engine_bin("nix", None, Some(owned), &owned_untrusted, &on_path),
            Some(PathBuf::from("/usr/bin/nix"))
        );

        // An untrusted engine resolved from `PATH` (e.g. a poisoned entry) is not used.
        let path_untrusted = |_: &Path| EngineProbe::Untrusted;
        assert_eq!(
            pick_engine_bin("nix", None, None, &path_untrusted, &on_path),
            None
        );
    }

    #[test]
    fn pick_engine_bin_pairs_the_owned_tier_and_never_mixes_with_path() {
        let owned = Path::new("/data/engine");
        let on_path = |n: &str| vec![PathBuf::from(format!("/usr/bin/{n}"))];
        // The owned `nix` is trusted, but its `nix-store` sibling is absent. `nix-store` must NOT
        // fall through to the host `PATH` — driving one store with an owned nix and a PATH
        // nix-store is the mix this pairing forbids; it fails closed instead.
        // Trusted: the owned `nix` and everything on the host `PATH`. The owned `nix-store` sibling
        // is absent, so the pairing must refuse rather than borrow the host's.
        let owned_nix_only = |p: &Path| {
            if p == Path::new("/data/engine/nix") || p.starts_with("/usr/bin") {
                EngineProbe::Trusted
            } else {
                EngineProbe::Absent
            }
        };
        assert_eq!(
            pick_engine_bin("nix", None, Some(owned), &owned_nix_only, &on_path),
            Some(PathBuf::from("/data/engine/nix"))
        );
        assert_eq!(
            pick_engine_bin("nix-store", None, Some(owned), &owned_nix_only, &on_path),
            None,
            "owned nix-store missing must fail closed, not borrow the host's"
        );
    }

    #[test]
    fn pick_engine_bin_skips_an_untrusted_path_match_for_a_later_trusted_one() {
        // `PATH` yields two `nix` candidates in order; the early one is world-writable
        // (untrusted), the later one is fine. Resolution must scan past the bad match rather
        // than stop at it — a poisoned early `PATH` entry does not shadow the real engine.
        let early = PathBuf::from("/early/nix");
        let late = PathBuf::from("/late/nix");
        let two = {
            let early = early.clone();
            let late = late.clone();
            move |_: &str| vec![early.clone(), late.clone()]
        };
        let early_untrusted = {
            let early = early.clone();
            move |p: &Path| {
                if p == early {
                    EngineProbe::Untrusted
                } else {
                    EngineProbe::Trusted
                }
            }
        };
        assert_eq!(
            pick_engine_bin("nix", None, None, &early_untrusted, &two),
            Some(late)
        );

        // Every match untrusted → nothing resolves (the skip exhausts the list, fail-closed).
        let all_untrusted = |_: &Path| EngineProbe::Untrusted;
        assert_eq!(
            pick_engine_bin("nix", None, None, &all_untrusted, &two),
            None
        );
    }

    #[test]
    fn ensure_owned_engine_lays_down_an_executable_nix_with_a_multicall_symlink() {
        let base = TmpDir::new();
        let dir = base.join("engine");
        let bytes = b"static-nix-binary-bytes";
        let sha = "deadbeef";

        ensure_owned_engine(&dir, bytes, sha).expect("materialize the engine");

        // the real binary lands with its bytes and an executable bit
        let nix = dir.join("nix");
        assert_eq!(std::fs::read(&nix).unwrap(), bytes);
        assert!(
            std::fs::metadata(&nix).unwrap().permissions().mode() & 0o111 != 0,
            "nix is not executable"
        );
        // the sibling command is a relative symlink onto the one multi-call binary
        assert_eq!(
            std::fs::read_link(dir.join("nix-store")).unwrap(),
            PathBuf::from("nix")
        );
        // the version marker records the embedded hash
        assert_eq!(std::fs::read_to_string(dir.join(".sha256")).unwrap(), sha);
        // no temp artifact is left behind
        assert!(!dir
            .join(format!(".nix.tmp.{}", std::process::id()))
            .exists());
    }

    #[test]
    fn ensure_owned_engine_is_idempotent_until_the_engine_hash_changes() {
        let base = TmpDir::new();
        let dir = base.join("engine");
        ensure_owned_engine(&dir, b"v1-bytes", "hash-v1").expect("first materialize");

        // Overwrite the placed binary, then call again at the SAME hash: the marker matches
        // and the sibling is present, so nothing is rewritten and our sentinel survives —
        // proving the cheap skip path.
        std::fs::write(dir.join("nix"), b"sentinel").unwrap();
        ensure_owned_engine(&dir, b"v1-bytes", "hash-v1").expect("idempotent re-call");
        assert_eq!(std::fs::read(dir.join("nix")).unwrap(), b"sentinel");

        // A missing multi-call sibling heals on the next call even at the same hash: the
        // fast-path also checks the symlink, so an interrupted replacement cannot strand
        // `nix-store` behind a still-matching marker.
        std::fs::remove_file(dir.join("nix-store")).unwrap();
        ensure_owned_engine(&dir, b"v1-bytes", "hash-v1").expect("heal the missing sibling");
        assert_eq!(
            std::fs::read_link(dir.join("nix-store")).unwrap(),
            PathBuf::from("nix")
        );

        // A different hash (a new sbx binary carrying a newer engine) re-materializes.
        ensure_owned_engine(&dir, b"v2-bytes", "hash-v2").expect("re-materialize on change");
        assert_eq!(std::fs::read(dir.join("nix")).unwrap(), b"v2-bytes");
        assert_eq!(
            std::fs::read_to_string(dir.join(".sha256")).unwrap(),
            "hash-v2"
        );
    }

    #[test]
    fn pick_bwrap_prefers_bundled_unless_apparmor_restricted() {
        let over = Path::new("/over/bwrap");
        let owned = Path::new("/data/engine");
        let host = |n: &str| vec![PathBuf::from(format!("/usr/bin/{n}"))];
        let owned_bwrap = PathBuf::from("/data/engine/bwrap");
        let host_bwrap = PathBuf::from("/usr/bin/bwrap");

        // Not restricted, both present and trusted: the bundled engine leads (self-contained).
        let all = |_: &Path| EngineProbe::Trusted;
        assert_eq!(
            pick_bwrap(false, None, Some(owned), &all, &host),
            Some((owned_bwrap.clone(), BwrapSource::Bundled))
        );
        // Restricted, both present: the path-profiled host engine leads — the only one able
        // to create a namespace under the AppArmor restriction. This is the branch a host
        // without the restriction cannot exercise live, so the unit test is the proof.
        assert_eq!(
            pick_bwrap(true, None, Some(owned), &all, &host),
            Some((host_bwrap.clone(), BwrapSource::HostPath))
        );

        // The override wins regardless of the restriction — the user owns that choice.
        assert_eq!(
            pick_bwrap(false, Some(over), Some(owned), &all, &host),
            Some((over.to_path_buf(), BwrapSource::Override))
        );
        assert_eq!(
            pick_bwrap(true, Some(over), Some(owned), &all, &host),
            Some((over.to_path_buf(), BwrapSource::Override))
        );
        // An override whose file is absent is treated as unset: the next tier applies.
        let only_owned = |p: &Path| {
            if p.starts_with("/data/engine") {
                EngineProbe::Trusted
            } else {
                EngineProbe::Absent
            }
        };
        assert_eq!(
            pick_bwrap(false, Some(over), Some(owned), &only_owned, &host),
            Some((owned_bwrap.clone(), BwrapSource::Bundled))
        );

        // Not restricted but no bundled engine present → fall back to the (trusted) host.
        let host_only = |p: &Path| {
            if p.starts_with("/usr/bin") {
                EngineProbe::Trusted
            } else {
                EngineProbe::Absent
            }
        };
        assert_eq!(
            pick_bwrap(false, None, Some(owned), &host_only, &host),
            Some((host_bwrap.clone(), BwrapSource::HostPath))
        );
        // Restricted with no host engine → the bundled one is the last resort (it will fail
        // at userns creation, but that is a separate, already-reported failure, not a reason
        // to resolve nothing).
        let no_host = |_: &str| Vec::<PathBuf>::new();
        assert_eq!(
            pick_bwrap(true, None, Some(owned), &all, &no_host),
            Some((owned_bwrap.clone(), BwrapSource::Bundled))
        );
        // No layout (no owned dir) simply skips that tier.
        assert_eq!(
            pick_bwrap(false, None, None, &host_only, &host),
            Some((host_bwrap.clone(), BwrapSource::HostPath))
        );
        // Nothing anywhere → None; the caller turns it into a pointed error.
        assert_eq!(pick_bwrap(false, None, None, &host_only, &no_host), None);

        // An override present but UNtrusted is refused outright, regardless of the restriction —
        // never silently replaced by a lower (here trusted) tier.
        let over_untrusted = |p: &Path| {
            if p.starts_with("/over") {
                EngineProbe::Untrusted
            } else {
                EngineProbe::Trusted
            }
        };
        assert_eq!(
            pick_bwrap(false, Some(over), Some(owned), &over_untrusted, &host),
            None
        );
        assert_eq!(
            pick_bwrap(true, Some(over), Some(owned), &over_untrusted, &host),
            None
        );

        // An untrusted owned engine is skipped (warned) and resolution falls through to the host.
        let owned_untrusted = |p: &Path| {
            if p.starts_with("/data/engine") {
                EngineProbe::Untrusted
            } else {
                EngineProbe::Trusted
            }
        };
        assert_eq!(
            pick_bwrap(false, None, Some(owned), &owned_untrusted, &host),
            Some((host_bwrap, BwrapSource::HostPath))
        );

        // An untrusted host engine on `PATH` (a poisoned entry) is not used; with no owned
        // engine, nothing resolves.
        let host_untrusted = |_: &Path| EngineProbe::Untrusted;
        assert_eq!(pick_bwrap(false, None, None, &host_untrusted, &host), None);

        // Skip-and-continue on the host `PATH`: an untrusted early `bwrap` does not shadow a
        // later trusted one. This matters most under the AppArmor restriction, where the host
        // tier leads — a poisoned early entry must not deny resolution of the real engine.
        let early = PathBuf::from("/early/bwrap");
        let late = PathBuf::from("/late/bwrap");
        let two_hosts = {
            let early = early.clone();
            let late = late.clone();
            move |_: &str| vec![early.clone(), late.clone()]
        };
        let early_host_untrusted = {
            let early = early.clone();
            move |p: &Path| {
                if p == early {
                    EngineProbe::Untrusted
                } else {
                    EngineProbe::Trusted
                }
            }
        };
        assert_eq!(
            pick_bwrap(true, None, None, &early_host_untrusted, &two_hosts),
            Some((late, BwrapSource::HostPath))
        );
    }

    #[test]
    fn ensure_owned_bwrap_lays_down_an_executable_bwrap_beside_an_independent_nix_marker() {
        let base = TmpDir::new();
        let dir = base.join("engine");

        ensure_owned_bwrap(&dir, b"static-bwrap-bytes", "bw-hash").expect("materialize bwrap");
        let bwrap = dir.join("bwrap");
        assert_eq!(std::fs::read(&bwrap).unwrap(), b"static-bwrap-bytes");
        assert!(
            std::fs::metadata(&bwrap).unwrap().permissions().mode() & 0o111 != 0,
            "bwrap is not executable"
        );
        // The marker is the bwrap-specific one, distinct from the nix engine's `.sha256`.
        assert_eq!(
            std::fs::read_to_string(dir.join(".bwrap.sha256")).unwrap(),
            "bw-hash"
        );
        assert!(
            !dir.join(".sha256").exists(),
            "bwrap must not write nix's marker"
        );
        assert!(!dir
            .join(format!(".bwrap.tmp.{}", std::process::id()))
            .exists());

        // Idempotent at the same hash: a sentinel overwrite survives a re-call.
        std::fs::write(&bwrap, b"sentinel").unwrap();
        ensure_owned_bwrap(&dir, b"static-bwrap-bytes", "bw-hash").expect("idempotent re-call");
        assert_eq!(std::fs::read(&bwrap).unwrap(), b"sentinel");
        // A new hash re-materializes.
        ensure_owned_bwrap(&dir, b"v2-bwrap", "bw-hash-2").expect("re-materialize on change");
        assert_eq!(std::fs::read(&bwrap).unwrap(), b"v2-bwrap");

        // Both engines coexist in the one owned directory with independent markers: laying
        // nix down does not disturb bwrap's binary or marker, and vice versa.
        ensure_owned_engine(&dir, b"static-nix", "nix-hash").expect("materialize nix beside it");
        assert_eq!(std::fs::read(dir.join("nix")).unwrap(), b"static-nix");
        assert_eq!(std::fs::read(&bwrap).unwrap(), b"v2-bwrap");
        assert_eq!(
            std::fs::read_to_string(dir.join(".sha256")).unwrap(),
            "nix-hash"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(".bwrap.sha256")).unwrap(),
            "bw-hash-2"
        );
    }

    #[test]
    fn expr_stamp_path_and_digest_are_well_formed() {
        // The stamp is a sibling of the out-link, appended (not extension-replaced) so a dotted
        // gcroot name keeps all of it.
        assert_eq!(
            expr_stamp_path(Path::new("/g/guidata")),
            PathBuf::from("/g/guidata.expr")
        );
        assert_eq!(
            expr_stamp_path(Path::new("/g/deb-a.b")),
            PathBuf::from("/g/deb-a.b.expr")
        );
        // The digest is a stable 64-hex SHA-256 that distinguishes expressions.
        assert_eq!(expr_digest("x").len(), 64);
        assert_eq!(expr_digest("x"), expr_digest("x"));
        assert_ne!(expr_digest("x"), expr_digest("y"));
    }

    #[test]
    fn reuse_built_expr_reuses_only_the_same_expression_and_a_live_marked_output() {
        // The correctness spine of the `provision_expr` short-circuit, without a real nix: it must
        // reuse a build only when the expression is unchanged AND the marked output is still there,
        // and must fall through to a rebuild (None) on any change — above all a changed expression.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));

        // A fabricated built output: a logical /nix/store path whose physical copy carries the marker.
        let logical = PathBuf::from("/nix/store/00000000000000000000000000000000-probe");
        let physical = physical_path(&layout, &logical);
        std::fs::create_dir_all(physical.join("bin")).unwrap();
        std::fs::write(physical.join("bin").join("tool"), b"x").unwrap();

        // The out-link points at the logical path, exactly as `nix build --out-link` leaves it.
        let gcroot = base.join("roots").join("probe");
        std::fs::create_dir_all(gcroot.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&logical, &gcroot).unwrap();

        let marker = "bin/tool";
        let stamp = expr_stamp_path(&gcroot);
        let da = expr_digest("EXPR-A");
        let db = expr_digest("EXPR-B");

        // No stamp yet (a first provision) → rebuild.
        assert!(reuse_built_expr(&layout, &gcroot, marker, &stamp, &da).is_none());

        // Stamp records EXPR-A and the marked out-link is live → reuse, returning the logical path.
        std::fs::write(&stamp, &da).unwrap();
        assert_eq!(
            reuse_built_expr(&layout, &gcroot, marker, &stamp, &da),
            Some(logical.clone())
        );

        // THE headline: a changed expression (EXPR-B) over the SAME stamp/out-link must rebuild
        // (None), never serve the stale EXPR-A output. A naive rev-only key would fail here.
        assert!(reuse_built_expr(&layout, &gcroot, marker, &stamp, &db).is_none());

        // A missing marker → rebuild, even though the stamp matches (the output is not the one wanted).
        assert!(reuse_built_expr(&layout, &gcroot, "bin/gone", &stamp, &da).is_none());

        // A garbage-collected output (the out-link's target is gone) → rebuild rather than reuse.
        std::fs::remove_dir_all(&physical).unwrap();
        assert!(reuse_built_expr(&layout, &gcroot, marker, &stamp, &da).is_none());
    }
}

/// Provisioning a real package needs a real nix, so this is an integration check:
/// it skips where nix is absent, and otherwise asserts that `provision` realises a
/// pinned package into the user-owned store, rooted by a gcroot.
#[cfg(test)]
mod provision_tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn provision_realises_a_pinned_package_into_the_user_store_with_a_gcroot() {
        let Some(nix) = resolve_nix(None) else {
            eprintln!("skipping provision: no nix on PATH");
            return;
        };
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        let nixpkgs = LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .expect("resolve pinned nixpkgs");
        let gcroot = base.join("roots").join("hello");

        let logical = provision(&nix, &layout, &gcroot, &nixpkgs, "hello", "bin/hello")
            .expect("provision hello");

        // the reported path is the in-sandbox logical form
        assert!(
            logical.starts_with("/nix/store"),
            "not logical: {}",
            logical.display()
        );
        // it physically exists in sbx's store, never the host
        assert!(
            physical_path(&layout, &logical).join("bin/hello").exists(),
            "hello missing from sbx's store"
        );
        // a gcroot symlink was created to keep it alive across GC
        assert!(
            std::fs::symlink_metadata(&gcroot).is_ok(),
            "no gcroot created at {}",
            gcroot.display()
        );
        // the channel revision was recorded so it stays fixed across sbx updates
        assert!(
            layout.data_dir().join(NIXPKGS_LOCK).is_file(),
            "channel lock not seeded"
        );
    }

    #[test]
    fn provision_expr_short_circuits_a_repeat_and_rebuilds_a_changed_expression() {
        let Some(nix) = resolve_nix(None) else {
            eprintln!("skipping provision_expr: no nix on PATH");
            return;
        };
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        let Ok(nixpkgs) = LockTarget::global(&layout, None).resolve(&nix, &layout) else {
            eprintln!("skipping provision_expr: cannot resolve nixpkgs (offline?)");
            return;
        };
        let system = format!("{}-linux", std::env::consts::ARCH);
        let gcroot = base.join("roots").join("probe");
        // A trivial `getFlake` runCommand whose output differs by `tag`; `--expr` is pure (the rev is
        // locked), so no `--impure` is needed.
        let expr = |tag: &str| {
            format!(
                "let pkgs = (builtins.getFlake \"{nixpkgs}\").legacyPackages.{system}; \
                 in pkgs.runCommand \"sbx-scprobe\" {{}} ''mkdir -p $out; echo {tag} > $out/tag''"
            )
        };
        let read_tag = |p: &Path| {
            std::fs::read_to_string(physical_path(&layout, p).join("tag"))
                .unwrap()
                .trim()
                .to_string()
        };

        // First build (real nix): produces the AAA output and writes the expr stamp.
        let Ok(out_a) = provision_expr(&nix, &layout, &gcroot, &expr("AAA"), "probe", "tag") else {
            eprintln!("skipping provision_expr: cold build failed (cache unreachable?)");
            return;
        };
        assert_eq!(read_tag(&out_a), "AAA");
        assert!(
            expr_stamp_path(&gcroot).exists(),
            "a successful build stamps the expression"
        );

        // The same expression again short-circuits WITHOUT spawning nix — proven by passing a
        // nonexistent nix binary: reaching the build would error, so returning the same output is
        // proof the reuse path was taken.
        let out_a2 = provision_expr(
            Path::new("/nonexistent/sbx-nix"),
            &layout,
            &gcroot,
            &expr("AAA"),
            "probe",
            "tag",
        )
        .expect("an unchanged expression must reuse the build without spawning nix");
        assert_eq!(out_a2, out_a);

        // A changed expression MUST rebuild through real nix (not serve the stale AAA out-link).
        let out_b = provision_expr(&nix, &layout, &gcroot, &expr("BBB"), "probe", "tag")
            .expect("a changed expression rebuilds");
        assert_ne!(
            out_b, out_a,
            "a changed expression must produce a new output"
        );
        assert_eq!(read_tag(&out_b), "BBB");
    }
}
