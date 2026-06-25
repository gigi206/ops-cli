//! The user-owned, daemonless nix store.
//!
//! ops provisions a project's tools into a store it owns under its own data
//! directory, never the host's `/nix`. The store is a single shared flat tree:
//! deduplicated across projects, bound read-only when a sandbox consumes it and
//! writable only while ops itself provisions into it. This module computes the
//! on-disk layout, bootstraps it, and builds the daemonless nix invocation that
//! drives it.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The default nixpkgs source ops tracks — a rolling-release branch, like a
/// rolling-distro base. The *source* is a constant; the concrete *revision* it
/// resolves to is recorded as state (see [`resolve_ref`]) so it stays fixed across
/// ops binary updates and only advances on an explicit upgrade.
const DEFAULT_SOURCE: &str = "nixos-unstable";

/// The flake-reference prefix every nixpkgs source expands under. A source is the
/// branch/channel or revision that follows it; constraining selection to this prefix
/// is a security floor (an untrusted-influenced value cannot point at a fork).
const NIXPKGS_FLAKE_PREFIX: &str = "github:NixOS/nixpkgs/";

/// The file (under the data directory, or a project's runtime tree) recording a
/// resolved nixpkgs source + revision — the "installed snapshot". Seeded on first
/// use, then reused; refreshing it (an explicit upgrade) is what rolls tool versions
/// forward, never an ops binary update.
const NIXPKGS_LOCK: &str = "nixpkgs.lock";

/// The file (under the data directory) recording the mise engine's resolved source +
/// revision — a dedicated lock so an explicit `ops upgrade mise` advances the engine
/// independently of the base channel (`nixpkgs.lock`). The engine tracks the global
/// channel source, but pinning it here on its own means rolling the base never bumps the
/// engine, and rolling the engine never bumps the base.
const MISE_ENGINE_LOCK: &str = "mise-engine.lock";

/// On-disk layout of the user-owned store, rooted at ops's private data
/// directory. Pure path derivation — holds no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    data_dir: PathBuf,
}

impl Layout {
    /// Resolve the layout from the environment: `$XDG_DATA_HOME/ops` when that
    /// is set to an absolute path, otherwise `$HOME/.local/share/ops`. `None`
    /// only when neither variable yields a usable base.
    pub(crate) fn from_env() -> Option<Self> {
        let data_dir = data_dir_from(
            std::env::var_os("XDG_DATA_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )?;
        Some(Self { data_dir })
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

    /// The root of ops's private data directory — the parent of the store and of
    /// the per-project sandbox runtime trees.
    pub(crate) fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Where ops places a nix engine it owns — the store-driving `nix`/`nix-store`
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

/// Pure core of [`Layout::from_env`]: prefer an absolute `XDG_DATA_HOME`, else
/// fall back to `HOME/.local/share`, with `ops` appended. A relative
/// `XDG_DATA_HOME` is ignored, as the base-directory specification requires.
fn data_dir_from(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    if let Some(xdg) = xdg {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("ops"));
        }
    }
    Some(PathBuf::from(home?).join(".local/share/ops"))
}

/// Create the store's directory skeleton if absent and tighten its permissions
/// to owner-only. Idempotent, and fail-closed: a directory that already existed
/// with looser permissions is tightened, never left group/world-accessible.
/// Never touches the host `/nix`. Called lazily, the first time a sandbox
/// consumes the store or ops provisions into it.
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

/// Environment override naming an explicit `nix` binary for ops to drive, ahead of
/// every other source. Lets a power user — or a test — point ops at a chosen engine.
/// It names `nix` itself; the sibling commands (`nix-store`, …) are found beside it,
/// since one multi-call binary backs them all in every nix distribution.
///
/// A value that does not point at an existing `nix` is ignored (resolution falls
/// through), so a stale override never strands ops. But once it *does* resolve, it is
/// **authoritative**: every engine binary is taken from beside it, never mixed with
/// the host's — a missing sibling there fails closed rather than silently driving the
/// store with two different engines.
const ENGINE_OVERRIDE_ENV: &str = "OPS_NIX_BIN";

/// Locate the `nix` binary that drives the store.
///
/// Resolution precedence: the [`ENGINE_OVERRIDE_ENV`] override, then a nix engine ops
/// owns under the data directory (`<data>/engine/`), then the host `PATH`. The
/// data-directory tier is where ops will place an engine it ships itself; consulting
/// it here puts the seam in place, while the `PATH` fallback keeps ops working until
/// then. `layout` is `None` only when the data directory cannot be resolved (no
/// `$HOME`), in which case that middle tier is skipped.
///
/// Pure resolution — it never writes — so a read-only caller (`ops doctor`) is safe.
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

/// The static nix engine ops ships inside its own binary, embedded by `build.rs` when the
/// `bundled-nix` feature is on. `NIX_BIN` is the raw bytes of the statically-linked `nix`;
/// `NIX_SHA256` is their hash, baked at build time so a launch compares the on-disk marker
/// without re-hashing tens of megabytes. Materialized into the owned engine directory by
/// [`ensure_owned_engine`].
#[cfg(feature = "bundled-nix")]
mod bundled {
    include!(concat!(env!("OUT_DIR"), "/bundled_nix.rs"));
}

/// Shared resolution for an engine command `name` (`nix`/`nix-store`), reading the
/// real environment, data directory, and `PATH`. The precedence is factored into
/// [`pick_engine_bin`] so it is unit-testable without touching any of them.
fn resolve_engine_bin(name: &str, layout: Option<&Layout>) -> Option<PathBuf> {
    let override_nix = std::env::var_os(ENGINE_OVERRIDE_ENV).map(PathBuf::from);
    let owned_dir = layout.map(Layout::engine_dir);
    // When ops ships its own static nix, lay it into the owned engine directory (once;
    // idempotent thereafter) so the owned tier below resolves it. Best-effort: a failure
    // leaves that tier empty and resolution falls through to `PATH`, exactly as it would
    // without the feature. The explicit `OPS_NIX_BIN` override still wins over it.
    #[cfg(feature = "bundled-nix")]
    if let Some(dir) = owned_dir.as_deref() {
        let _ = ensure_owned_engine(dir, bundled::NIX_BIN, bundled::NIX_SHA256);
    }
    pick_engine_bin(
        name,
        override_nix.as_deref(),
        owned_dir.as_deref(),
        &|p| p.is_file(),
        &|n| crate::pathfind::find_on_path(n),
    )
}

/// Materialize ops's bundled static nix into the owned engine directory, idempotently.
///
/// Lays down `<dir>/nix` (the real binary, executable) plus the multi-call sibling
/// `<dir>/nix-store -> nix` (one binary dispatches both off argv0). A `<dir>/.sha256`
/// marker records the embedded hash so a launch re-materializes only when the engine
/// changed (a new ops binary), not on every resolution. The binary lands atomically — a
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

/// Pick the engine binary `name` from the three sources, in precedence order: the
/// override, then an ops-owned engine directory, then `PATH`. File existence and the
/// `PATH` lookup are injected so the precedence is testable in isolation.
///
/// A *resolved* override (one whose `nix` exists) is authoritative: `name` is taken
/// from beside it and a missing sibling yields `None` (fail-closed), never a fall-back
/// to the host's `PATH` — which would drive one store with two different engines. An
/// override whose `nix` is absent is treated as unset and the next tier applies.
fn pick_engine_bin(
    name: &str,
    override_nix: Option<&Path>,
    owned_dir: Option<&Path>,
    exists: &dyn Fn(&Path) -> bool,
    on_path: &dyn Fn(&str) -> Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(nix) = override_nix {
        if exists(nix) {
            let bin = engine_sibling(nix, name);
            return exists(&bin).then_some(bin);
        }
    }
    if let Some(dir) = owned_dir {
        let bin = dir.join(name);
        if exists(&bin) {
            return Some(bin);
        }
    }
    on_path(name)
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
const BWRAP_OVERRIDE_ENV: &str = "OPS_BWRAP_BIN";

/// The kernel sysctl that, when non-zero, restricts unprivileged user-namespace creation to
/// binaries carrying an AppArmor profile that grants `userns` (Ubuntu 24.04+). The shipped
/// profile attaches that grant **by path** to `/usr/bin/bwrap`, so a bwrap materialized
/// elsewhere cannot create a namespace under this restriction — which is why
/// [`resolve_bwrap`] prefers the host engine when it is in force.
const APPARMOR_USERNS_RESTRICT: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";

/// The static bwrap (bubblewrap) engine ops ships inside its own binary, embedded by
/// `build.rs` when the `bundled-bwrap` feature is on. `BWRAP_BIN` is the raw bytes of the
/// statically-linked `bwrap`; `BWRAP_SHA256` is their hash, baked at build time so a launch
/// compares the on-disk marker without re-hashing. Materialized by [`ensure_owned_bwrap`].
#[cfg(feature = "bundled-bwrap")]
mod bundled_bwrap {
    include!(concat!(env!("OUT_DIR"), "/bundled_bwrap.rs"));
}

/// Which source supplied the resolved `bwrap`, for an honest `ops doctor` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BwrapSource {
    /// The [`BWRAP_OVERRIDE_ENV`] override.
    Override,
    /// A bwrap ops owns under `<data>/engine/` (the embedded static engine).
    Bundled,
    /// The host's bwrap on `PATH`.
    HostPath,
}

impl BwrapSource {
    /// A short label naming the source.
    pub(crate) fn label(self) -> &'static str {
        match self {
            BwrapSource::Override => "override (OPS_BWRAP_BIN)",
            BwrapSource::Bundled => "bundled engine",
            BwrapSource::HostPath => "host PATH",
        }
    }
}

/// A resolved sandbox engine: its path, where it came from, and whether the host is
/// enforcing the AppArmor unprivileged-userns restriction (which is *why* the host engine
/// may have been chosen over the bundled one). Callers that only launch use [`Self::path`];
/// `ops doctor` reports all three so the user is never surprised which `bwrap` ran.
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
/// restricted (the common case, and every non-Ubuntu distro), the bundled engine ops owns
/// under `<data>/engine/` leads — self-contained and a known-good pinned version — falling
/// back to the host `PATH`. Where the restriction **is** in force, only the path-profiled
/// `/usr/bin/bwrap` can create a namespace, so the host engine leads and the bundled one is
/// the fallback; ops is **non-regressive by construction** there — it uses exactly the host
/// bwrap it always has. `layout` is `None` only when the data directory cannot be resolved,
/// in which case the owned tier is skipped.
///
/// Under the `bundled-bwrap` feature this materializes the embedded engine into the owned
/// directory (once; idempotent) before resolving; best-effort, so a failure simply leaves
/// that tier empty and resolution falls through.
pub(crate) fn resolve_bwrap(layout: Option<&Layout>) -> Option<BwrapChoice> {
    let override_bin = std::env::var_os(BWRAP_OVERRIDE_ENV).map(PathBuf::from);
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
        &|p| p.is_file(),
        &|n| crate::pathfind::find_on_path(n),
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

/// Materialize ops's bundled static bwrap into the owned engine directory, idempotently.
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

/// Pick the `bwrap` binary and its source from the override, the ops-owned engine directory,
/// and `PATH`, in an order that depends on `restricted` (the AppArmor userns restriction).
/// File existence and the `PATH` lookup are injected so the precedence — including the
/// AppArmor branch, which a host without the restriction cannot exercise live — is
/// unit-testable in isolation.
///
/// The override, when it resolves, is authoritative. Otherwise: not restricted ⇒ the owned
/// engine leads, then `PATH`; restricted ⇒ the host `PATH` engine leads (the same bwrap ops
/// uses today — on a standard host that is the path-profiled `/usr/bin/bwrap`, the only one
/// able to create a namespace under the restriction), then the owned engine as a last resort.
fn pick_bwrap(
    restricted: bool,
    override_bin: Option<&Path>,
    owned_dir: Option<&Path>,
    exists: &dyn Fn(&Path) -> bool,
    on_path: &dyn Fn(&str) -> Option<PathBuf>,
) -> Option<(PathBuf, BwrapSource)> {
    if let Some(bin) = override_bin {
        if exists(bin) {
            return Some((bin.to_path_buf(), BwrapSource::Override));
        }
    }
    let owned = owned_dir
        .map(|d| d.join("bwrap"))
        .filter(|p| exists(p))
        .map(|p| (p, BwrapSource::Bundled));
    let host = on_path("bwrap").map(|p| (p, BwrapSource::HostPath));
    if restricted {
        host.or(owned)
    } else {
        owned.or(host)
    }
}

/// Locate the `git` binary that fetches a remote plugin store. Resolved from `PATH`;
/// needed only by `ops plugins store` (a remote store is a git repository), not by a
/// launch — so its absence is a feature gap, never a boundary failure.
pub(crate) fn resolve_git() -> Option<PathBuf> {
    crate::pathfind::find_on_path("git")
}

/// Build a daemonless nix invocation against the user-owned store: the daemon is
/// disabled (`NIX_REMOTE` empty), so nix runs as the invoking user with no
/// privileged helper, and `--store` points at the user-owned tree. Callers
/// append the subcommand.
pub(crate) fn nix_command(nix: &Path, layout: &Layout) -> Command {
    let mut cmd = Command::new(nix);
    cmd.env("NIX_REMOTE", "");
    cmd.arg("--store").arg(layout.store_dir());
    cmd
}

/// Where a `nixpkgs` source was chosen — carried so the same wording reaches the
/// user from `ops config`, `ops upgrade`, and `ops doctor`.
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
/// the launch (resolve), `ops upgrade` (refresh), and `ops config` (display) all act
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
    /// dedicated lock so `ops upgrade mise` advances the engine independently of the base
    /// channel that `ops upgrade nix` rolls.
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
    /// roll-forward `ops upgrade` performs. Reports the previous revision (for this
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
/// lock — what `ops doctor` shows as the host-level channel state, independent of any
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
/// start; they diverge only on an explicit `ops upgrade mise`. Only when neither lock has
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
/// changing the source re-resolves while an unchanged one stays fixed (an ops binary
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
/// another launch resolving, or a second `ops upgrade` — sees either the old lock
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
    ensure(layout)?;
    if let Some(parent) = gcroot.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    let mut cmd = nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"])
        .arg("build")
        .args(["--option", "sandbox", "true"])
        .arg("--out-link")
        .arg(gcroot)
        .arg("--print-out-paths")
        .arg(format!("{flake_ref}#{attr}"))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let out = cmd.spawn()?.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "nix build {flake_ref}#{attr} failed"
        )));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .map(PathBuf::from)
        .find(|logical| physical_path(layout, logical).join(marker).exists())
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
        let layout = Layout::under(Path::new("/data/ops"));
        assert_eq!(layout.data_dir.as_path(), Path::new("/data/ops"));
        assert_eq!(layout.store_dir(), Path::new("/data/ops/store"));
    }

    #[test]
    fn data_dir_prefers_absolute_xdg_else_falls_back_to_home() {
        assert_eq!(
            data_dir_from(Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/xdg/ops"))
        );
        // a relative XDG_DATA_HOME is ignored; HOME is used instead
        assert_eq!(
            data_dir_from(Some(OsStr::new("rel/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.local/share/ops"))
        );
        assert_eq!(
            data_dir_from(None, Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.local/share/ops"))
        );
        assert_eq!(data_dir_from(None, None), None);
    }

    #[test]
    fn ensure_creates_dirs_owner_only_and_is_idempotent() {
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("ops"));

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
        let data = base.join("ops");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777)).unwrap();

        ensure(&Layout::under(&data)).unwrap();
        let mode = std::fs::metadata(&data).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "loose perms must be tightened");
    }

    #[test]
    fn nix_command_is_daemonless_and_targets_the_store() {
        let layout = Layout::under(Path::new("/data/ops"));
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
            vec![OsStr::new("--store"), OsStr::new("/data/ops/store")]
        );
    }

    #[test]
    fn physical_path_maps_a_logical_store_path_under_the_store_root() {
        let layout = Layout::under(Path::new("/data/ops"));
        assert_eq!(
            physical_path(&layout, Path::new("/nix/store/abc-hello")),
            PathBuf::from("/data/ops/store/nix/store/abc-hello")
        );
        assert_eq!(
            physical_path(&layout, Path::new("/nix")),
            PathBuf::from("/data/ops/store/nix")
        );
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
        // source, an ops binary update (or any later run) reuses it and never
        // re-resolves. Proven with a bogus nix path — if the early return ever
        // regressed, resolution would invoke it and the call would fail. Uses a
        // legacy single-line lock, which also proves backward compatibility.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let dir = base.join("ops");
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));

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
        let layout = Layout::under(Path::new("/data/ops"));

        let default = LockTarget::global(&layout, None);
        assert_eq!(default.source(), DEFAULT_SOURCE);
        assert_eq!(default.origin(), Origin::Default);
        assert_eq!(default.lock_path, PathBuf::from("/data/ops/nixpkgs.lock"));

        let over = LockTarget::global(&layout, Some("nixos-23.11"));
        assert_eq!(over.source(), "nixos-23.11");
        assert_eq!(over.origin(), Origin::Global);
        assert_eq!(over.lock_path, PathBuf::from("/data/ops/nixpkgs.lock"));

        let proj = LockTarget::project(&layout, "abc", "nixos-23.11");
        assert_eq!(proj.source(), "nixos-23.11");
        assert_eq!(proj.origin(), Origin::ProjectPin);
        assert_eq!(
            proj.lock_path,
            PathBuf::from("/data/ops/projects/abc/nixpkgs.lock")
        );

        // the engine tracks the same source as the global channel (default, or a global
        // override) but pins it in its OWN lock — never the shared nixpkgs.lock — so the
        // two roll forward independently.
        let engine = LockTarget::engine(&layout, None);
        assert_eq!(engine.source(), DEFAULT_SOURCE);
        assert_eq!(engine.origin(), Origin::Default);
        assert_eq!(
            engine.lock_path,
            PathBuf::from("/data/ops/mise-engine.lock")
        );
        let engine_over = LockTarget::engine(&layout, Some("nixos-23.11"));
        assert_eq!(engine_over.source(), "nixos-23.11");
        assert_eq!(engine_over.origin(), Origin::Global);
        assert_eq!(
            engine_over.lock_path,
            PathBuf::from("/data/ops/mise-engine.lock")
        );
    }

    #[test]
    fn a_project_target_pins_its_source_in_a_per_project_lock() {
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("ops"));

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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
        let layout = Layout::under(&base.join("ops"));
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
    fn pick_engine_bin_follows_override_then_owned_then_path() {
        let over = Path::new("/over/nix");
        let owned = Path::new("/data/engine");
        let on_path = |n: &str| Some(PathBuf::from(format!("/usr/bin/{n}")));

        // The override wins when its file exists; nix-store derives as a sibling.
        let all = |_: &Path| true;
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
        let only_override_nix = |p: &Path| p == Path::new("/over/nix");
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
        // the ops-owned engine directory) applies.
        let only_owned = |p: &Path| p.starts_with("/data/engine");
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &only_owned, &on_path),
            Some(PathBuf::from("/data/engine/nix"))
        );

        // With neither override nor owned engine present, it falls to `PATH`.
        let none_exist = |_: &Path| false;
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &none_exist, &on_path),
            Some(PathBuf::from("/usr/bin/nix"))
        );

        // No layout (no owned dir) simply skips that tier.
        assert_eq!(
            pick_engine_bin("nix-store", None, None, &none_exist, &on_path),
            Some(PathBuf::from("/usr/bin/nix-store"))
        );

        // Nothing anywhere → None; the caller turns it into a pointed error.
        let no_path = |_: &str| None;
        assert_eq!(
            pick_engine_bin("nix", None, None, &none_exist, &no_path),
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

        // A different hash (a new ops binary carrying a newer engine) re-materializes.
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
        let host = |n: &str| Some(PathBuf::from(format!("/usr/bin/{n}")));
        let owned_bwrap = PathBuf::from("/data/engine/bwrap");
        let host_bwrap = PathBuf::from("/usr/bin/bwrap");

        // Not restricted, both present: the bundled engine leads (self-contained, pinned).
        let all = |_: &Path| true;
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
        let only_owned = |p: &Path| p.starts_with("/data/engine");
        assert_eq!(
            pick_bwrap(false, Some(over), Some(owned), &only_owned, &host),
            Some((owned_bwrap.clone(), BwrapSource::Bundled))
        );

        // Not restricted but no bundled engine present → fall back to the host.
        let none_exist = |_: &Path| false;
        assert_eq!(
            pick_bwrap(false, None, Some(owned), &none_exist, &host),
            Some((host_bwrap.clone(), BwrapSource::HostPath))
        );
        // Restricted with no host engine → the bundled one is the last resort (it will fail
        // at userns creation, but that is a separate, already-reported failure, not a reason
        // to resolve nothing).
        let no_host = |_: &str| None;
        assert_eq!(
            pick_bwrap(true, None, Some(owned), &all, &no_host),
            Some((owned_bwrap, BwrapSource::Bundled))
        );
        // No layout (no owned dir) simply skips that tier.
        assert_eq!(
            pick_bwrap(false, None, None, &none_exist, &host),
            Some((host_bwrap, BwrapSource::HostPath))
        );
        // Nothing anywhere → None; the caller turns it into a pointed error.
        assert_eq!(pick_bwrap(false, None, None, &none_exist, &no_host), None);
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
        let layout = Layout::under(&base.join("ops"));
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
        // it physically exists in ops's store, never the host
        assert!(
            physical_path(&layout, &logical).join("bin/hello").exists(),
            "hello missing from ops's store"
        );
        // a gcroot symlink was created to keep it alive across GC
        assert!(
            std::fs::symlink_metadata(&gcroot).is_ok(),
            "no gcroot created at {}",
            gcroot.display()
        );
        // the channel revision was recorded so it stays fixed across ops updates
        assert!(
            layout.data_dir().join(NIXPKGS_LOCK).is_file(),
            "channel lock not seeded"
        );
    }
}
