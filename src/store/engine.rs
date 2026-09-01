//! Which host binaries sbx execs, where each may come from, and whether one may be run.
//!
//! `nix` and its multi-call siblings, `bwrap`, `git`, and the exec-enforcement shim sbx carries
//! inside its own binary. Nothing here concerns the store's *content* — only the programs that
//! act on it, which is why the trust verdict lives here too and is asked of plugin-declared
//! programs that have nothing to do with a store.
//!
//! Resolution is the same shape for each: an explicit environment override first, then a copy sbx
//! owns under its own data directory, then the host `PATH` — and each tier is admitted only if
//! ownership and mode say the file cannot be rewritten by someone else before sbx runs it.

use super::layout::Layout;
use std::io;
use std::path::{Path, PathBuf};

/// Environment override naming an explicit `nix` binary for sbx to drive, ahead of
/// every other source. Lets a power user — or a test — point sbx at a chosen engine.
///
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
/// then. `layout` is `None` whenever [`Layout::from_env`] declined — no `$HOME`/XDG base, or a
/// base that resolved and was then refused — in which case that middle tier is simply skipped and
/// resolution falls through to the host `PATH`.
///
/// Pure resolution — it never writes — so a read-only caller (`sbx doctor`) is safe.
///
/// The `Option` form, for the many callers that only need the binary or a message of their own; a
/// caller that *reports the failure to the user* wants [`try_resolve_nix`] instead, which says
/// whether the engine was missing or refused — two failures with opposite remedies.
pub(crate) fn resolve_nix(layout: Option<&Layout>) -> Option<PathBuf> {
    try_resolve_nix(layout).ok()
}

/// [`resolve_nix`], keeping why it failed — see [`EngineMiss`].
pub(crate) fn try_resolve_nix(layout: Option<&Layout>) -> Result<PathBuf, EngineMiss> {
    resolve_engine_bin("nix", layout)
}

/// Locate the `nix-store` binary, the classic command exposing the store's
/// registration database (`--dump-db`/`--load-db`). The same multi-call binary as
/// `nix`, dispatched by argv0, so it is resolved by the same precedence as
/// [`resolve_nix`]. Consumed by the per-project store seed the launcher backs the
/// cage's writable `/nix` with.
pub(crate) fn resolve_nix_store(layout: Option<&Layout>) -> Option<PathBuf> {
    try_resolve_nix_store(layout).ok()
}

/// [`resolve_nix_store`], keeping why it failed — see [`EngineMiss`].
pub(crate) fn try_resolve_nix_store(layout: Option<&Layout>) -> Result<PathBuf, EngineMiss> {
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
fn resolve_engine_bin(name: &str, layout: Option<&Layout>) -> Result<PathBuf, EngineMiss> {
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

/// Why an engine did not resolve: nothing usable was found anywhere sbx looks, or sbx found the
/// binary the invoker named and refused it.
///
/// The two must reach the caller apart, because the remedies are opposites. A refused override is
/// not a missing engine — the binary is installed and sitting at the path the variable names — so a
/// reporting site that collapses them tells a user whose `nix` is merely world-writable to install
/// nix, and sends them after a package they already have instead of the permissions that were
/// actually refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EngineMiss {
    /// No trusted binary at any tier sbx consults.
    NotFound,
    /// The override variable named a binary that is present and fails the trust check. sbx refuses
    /// it outright rather than substituting another engine, so nothing resolved.
    Refused {
        /// The variable that named it — [`ENGINE_OVERRIDE_ENV`] or [`BWRAP_OVERRIDE_ENV`].
        env: &'static str,
        /// The path it named.
        path: PathBuf,
    },
}

impl EngineMiss {
    /// The clause naming what happened to the engine `what`, for a caller composing one line about
    /// one engine. Callers add their own consequence ("the sandbox cannot run", "cannot upgrade").
    pub(crate) fn clause(&self, what: &str) -> String {
        match self {
            EngineMiss::NotFound => format!("{what} not found"),
            EngineMiss::Refused { env, path } => format!(
                "{what} refused: {env} names {}, which sbx will not run",
                path.display()
            ),
        }
    }
}

/// Refuse an engine override that is present but untrusted: say so, and return the miss that
/// carries the disposition to the caller.
///
/// Refused rather than skipped, because an override is a deliberate choice and quietly running a
/// different engine against the same store would be worse than stopping. Both engines refuse in
/// the same words from here, so the two overrides cannot drift into describing the same decision
/// differently — and the caller gets [`EngineMiss::Refused`] rather than a bare "nothing found",
/// which is what keeps the failure from being reported as a missing engine.
fn refuse_override(env: &'static str, path: &Path) -> EngineMiss {
    eprintln!(
        "sbx: refusing {env}={} — sbx will not silently substitute another engine. Fix the \
         file's ownership or permissions, or unset the variable.",
        path.display()
    );
    EngineMiss::Refused {
        env,
        path: path.to_path_buf(),
    }
}

/// Pure ownership/permission verdict for a **host binary sbx is about to `execve`**: an engine
/// (`nix`, `bwrap`) picked off `PATH`, or a program a resolver plugin's manifest declares.
///
/// Mirrors the config-file safety gate, with one deliberate difference: such a binary may
/// legitimately be owned by **root** (the host `/usr/bin/bwrap` is `root:root`, and an
/// override may point at a system binary), so ownership by uid 0 is accepted alongside our
/// own euid — neither is writable by an unprivileged attacker. A non-regular file
/// (FIFO/device/dir, which could hang a launch or feed back attacker-controlled bytes) or a
/// world-writable one (anyone could swap it) is refused; group-writable is tolerated, as for
/// config files — the owner-only engine directory is the real boundary for the owned tier.
///
/// `mode` is the full `st_mode`, type bits included.
///
/// Shared rather than re-derived: a second copy would be a second place for the owned-by-root
/// branch to drift.
pub(crate) fn host_exec_verdict(file_uid: u32, mode: u32, euid: u32) -> Result<(), String> {
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
    match host_exec_verdict(meta.uid(), meta.mode(), euid) {
        Ok(()) => EngineProbe::Trusted,
        Err(why) => {
            // States the fact, not the disposition: this probe serves all three tiers, and they
            // dispose of an untrusted binary differently — the override is refused outright, a
            // lower tier is skipped in favour of the next. Each tier says which below, so neither
            // has to be implied by a word chosen here.
            eprintln!("sbx: untrusted engine binary {}: {why}", path.display());
            EngineProbe::Untrusted
        }
    }
}

/// Pick the engine binary `name` from the three sources, in precedence order: the override,
/// then an sbx-owned engine directory, then `PATH`. The trust probe and the `PATH` lookup are
/// injected so the precedence — including the untrusted branches — is testable in isolation.
///
/// A *resolved* override (one whose `nix` is present and trusted) is authoritative: `name` is
/// taken from beside it and a missing or untrusted sibling fails closed, never a fall-back to the
/// host's `PATH` — which would drive one store with two different engines. An override whose `nix`
/// is **absent** is treated as unset and the next tier applies; one that is **present but
/// untrusted** is refused outright, since it is a deliberate choice and silently substituting
/// another engine would be worse — and that refusal reaches the caller as
/// [`EngineMiss::Refused`], not as "nothing found". A lower tier (owned, then `PATH`) that is
/// untrusted is skipped — with a warning — in favour of the next; on `PATH` that means scanning
/// past an untrusted match to a later trusted one, so a world-writable early entry does not shadow
/// the legitimate engine.
fn pick_engine_bin(
    name: &str,
    override_nix: Option<&Path>,
    owned_dir: Option<&Path>,
    probe: &dyn Fn(&Path) -> EngineProbe,
    on_path: &dyn Fn(&str) -> Vec<PathBuf>,
) -> Result<PathBuf, EngineMiss> {
    if let Some(nix) = override_nix {
        match probe(nix) {
            EngineProbe::Absent => {}
            EngineProbe::Untrusted => return Err(refuse_override(ENGINE_OVERRIDE_ENV, nix)),
            EngineProbe::Trusted => {
                let bin = engine_sibling(nix, name);
                return match probe(bin.as_path()) {
                    EngineProbe::Trusted => Ok(bin),
                    _ => Err(EngineMiss::NotFound),
                };
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
            return match probe(bin.as_path()) {
                EngineProbe::Trusted => Ok(bin),
                _ => Err(EngineMiss::NotFound),
            };
        }
    }
    on_path(name)
        .into_iter()
        .find(|p| matches!(probe(p.as_path()), EngineProbe::Trusted))
        .ok_or(EngineMiss::NotFound)
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
///
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
/// bwrap it always has. `layout` is `None` whenever [`Layout::from_env`] declined — no `$HOME`/XDG
/// base, or a base that resolved and was then refused — in which case the owned tier is skipped.
///
/// Under the `bundled-bwrap` feature this materializes the embedded engine into the owned
/// directory (once; idempotent) before resolving; best-effort, so a failure simply leaves
/// that tier empty and resolution falls through.
pub(crate) fn resolve_bwrap(layout: Option<&Layout>) -> Option<BwrapChoice> {
    try_resolve_bwrap(layout).ok()
}

/// [`resolve_bwrap`], keeping why it failed — see [`EngineMiss`].
pub(crate) fn try_resolve_bwrap(layout: Option<&Layout>) -> Result<BwrapChoice, EngineMiss> {
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
    Ok(BwrapChoice {
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
/// outright — reaching the caller as [`EngineMiss::Refused`], not as "nothing found" — while an
/// absent one yields to the host-dependent order. Otherwise: not restricted ⇒
/// the owned engine leads, then `PATH`; restricted ⇒ the host `PATH` engine leads (the same
/// bwrap sbx uses today — on a standard host the path-profiled `/usr/bin/bwrap`, the only one
/// able to create a namespace under the restriction), then the owned engine as a last resort.
///
/// An untrusted owned or `PATH` engine is skipped (with a warning) in favour of the next tier.
fn pick_bwrap(
    restricted: bool,
    override_bin: Option<&Path>,
    owned_dir: Option<&Path>,
    probe: &dyn Fn(&Path) -> EngineProbe,
    on_path: &dyn Fn(&str) -> Vec<PathBuf>,
) -> Result<(PathBuf, BwrapSource), EngineMiss> {
    if let Some(bin) = override_bin {
        match probe(bin) {
            EngineProbe::Absent => {}
            EngineProbe::Untrusted => return Err(refuse_override(BWRAP_OVERRIDE_ENV, bin)),
            EngineProbe::Trusted => return Ok((bin.to_path_buf(), BwrapSource::Override)),
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
        host().or_else(owned).ok_or(EngineMiss::NotFound)
    } else {
        owned().or_else(host).ok_or(EngineMiss::NotFound)
    }
}

/// Locate the `git` binary that fetches a remote plugin store. Resolved from `PATH`;
/// needed only by `sbx plugins store` (a remote store is a git repository), not by a
/// launch — so its absence is a feature gap, never a boundary failure.
pub(crate) fn resolve_git() -> Option<PathBuf> {
    crate::pathfind::find_on_path("git")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;
    use std::os::unix::fs::PermissionsExt;

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
        assert!(host_exec_verdict(1000, reg(0o755), 1000).is_ok());
        assert!(host_exec_verdict(1000, reg(0o775), 1000).is_ok());
        // root-owned is accepted — the host /usr/bin/bwrap is root:root and an override may be a
        // system binary; neither is writable by an unprivileged attacker.
        assert!(host_exec_verdict(0, reg(0o755), 1000).is_ok());
        // a foreign, non-root owner is refused, naming the uid
        let e = host_exec_verdict(1234, reg(0o755), 1000).unwrap_err();
        assert!(e.contains("owned by uid 1234"), "got: {e}");
        // world-writable is refused even when owned by us
        assert!(
            host_exec_verdict(1000, reg(0o757), 1000)
                .unwrap_err()
                .contains("world-writable")
        );
        // a non-regular file (here a directory) is refused
        assert!(
            host_exec_verdict(1000, libc::S_IFDIR | 0o755, 1000)
                .unwrap_err()
                .contains("not a regular file")
        );
    }

    /// Every site that reports an unresolved engine composes its line from this clause, so the
    /// word "found" must never appear for a binary that is present and was refused: that is the
    /// sentence which sends a user to install an engine they already have.
    #[test]
    fn the_miss_clause_never_calls_a_refused_override_missing() {
        assert_eq!(
            EngineMiss::NotFound.clause("nix (the store engine)"),
            "nix (the store engine) not found"
        );
        let refused = EngineMiss::Refused {
            env: ENGINE_OVERRIDE_ENV,
            path: PathBuf::from("/over/nix"),
        };
        assert_eq!(
            refused.clause("nix (the store engine)"),
            "nix (the store engine) refused: SBX_NIX_BIN names /over/nix, which sbx will not run"
        );
        assert!(!refused.clause("nix").contains("not found"));
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
            Ok(PathBuf::from("/over/nix"))
        );
        assert_eq!(
            pick_engine_bin("nix-store", Some(over), Some(owned), &all, &on_path),
            Ok(PathBuf::from("/over/nix-store"))
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
            Ok(PathBuf::from("/over/nix"))
        );
        assert_eq!(
            pick_engine_bin(
                "nix-store",
                Some(over),
                Some(owned),
                &only_override_nix,
                &on_path
            ),
            Err(EngineMiss::NotFound),
            "an authoritative override with no sibling is a miss, not a refusal"
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
            Ok(PathBuf::from("/data/engine/nix"))
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
            Ok(PathBuf::from("/usr/bin/nix"))
        );

        // No layout (no owned dir) simply skips that tier.
        assert_eq!(
            pick_engine_bin("nix-store", None, None, &host_only, &on_path),
            Ok(PathBuf::from("/usr/bin/nix-store"))
        );

        // Nothing anywhere → the caller turns it into a pointed error, and this is the one case
        // where "not found" is the honest word for it.
        let no_path = |_: &str| Vec::<PathBuf>::new();
        assert_eq!(
            pick_engine_bin("nix", None, None, &host_only, &no_path),
            Err(EngineMiss::NotFound)
        );

        // An override present but UNtrusted is refused outright — never silently replaced by
        // the (here trusted) owned tier; the deliberate choice fails closed. The refusal is what
        // the caller receives, distinct from "not found": the binary is installed, and reporting
        // it as absent would send its owner to install an engine they already have.
        let over_untrusted = |p: &Path| {
            if p.starts_with("/over") {
                EngineProbe::Untrusted
            } else {
                EngineProbe::Trusted
            }
        };
        assert_eq!(
            pick_engine_bin("nix", Some(over), Some(owned), &over_untrusted, &on_path),
            Err(EngineMiss::Refused {
                env: ENGINE_OVERRIDE_ENV,
                path: over.to_path_buf()
            })
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
            Ok(PathBuf::from("/usr/bin/nix"))
        );

        // An untrusted engine resolved from `PATH` (e.g. a poisoned entry) is not used. No
        // override was named, so nothing was refused on the invoker's behalf: this is a miss.
        let path_untrusted = |_: &Path| EngineProbe::Untrusted;
        assert_eq!(
            pick_engine_bin("nix", None, None, &path_untrusted, &on_path),
            Err(EngineMiss::NotFound)
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
            Ok(PathBuf::from("/data/engine/nix"))
        );
        assert_eq!(
            pick_engine_bin("nix-store", None, Some(owned), &owned_nix_only, &on_path),
            Err(EngineMiss::NotFound),
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
            Ok(late)
        );

        // Every match untrusted → nothing resolves (the skip exhausts the list, fail-closed).
        let all_untrusted = |_: &Path| EngineProbe::Untrusted;
        assert_eq!(
            pick_engine_bin("nix", None, None, &all_untrusted, &two),
            Err(EngineMiss::NotFound)
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
        assert!(
            !dir.join(format!(".nix.tmp.{}", std::process::id()))
                .exists()
        );
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
            Ok((owned_bwrap.clone(), BwrapSource::Bundled))
        );
        // Restricted, both present: the path-profiled host engine leads — the only one able
        // to create a namespace under the AppArmor restriction. This is the branch a host
        // without the restriction cannot exercise live, so the unit test is the proof.
        assert_eq!(
            pick_bwrap(true, None, Some(owned), &all, &host),
            Ok((host_bwrap.clone(), BwrapSource::HostPath))
        );

        // The override wins regardless of the restriction — the user owns that choice.
        assert_eq!(
            pick_bwrap(false, Some(over), Some(owned), &all, &host),
            Ok((over.to_path_buf(), BwrapSource::Override))
        );
        assert_eq!(
            pick_bwrap(true, Some(over), Some(owned), &all, &host),
            Ok((over.to_path_buf(), BwrapSource::Override))
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
            Ok((owned_bwrap.clone(), BwrapSource::Bundled))
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
            Ok((host_bwrap.clone(), BwrapSource::HostPath))
        );
        // Restricted with no host engine → the bundled one is the last resort (it will fail
        // at userns creation, but that is a separate, already-reported failure, not a reason
        // to resolve nothing).
        let no_host = |_: &str| Vec::<PathBuf>::new();
        assert_eq!(
            pick_bwrap(true, None, Some(owned), &all, &no_host),
            Ok((owned_bwrap.clone(), BwrapSource::Bundled))
        );
        // No layout (no owned dir) simply skips that tier.
        assert_eq!(
            pick_bwrap(false, None, None, &host_only, &host),
            Ok((host_bwrap.clone(), BwrapSource::HostPath))
        );
        // Nothing anywhere → the caller turns it into a pointed error, and "not found" is the
        // honest word for it here.
        assert_eq!(
            pick_bwrap(false, None, None, &host_only, &no_host),
            Err(EngineMiss::NotFound)
        );

        // An override present but UNtrusted is refused outright, regardless of the restriction —
        // never silently replaced by a lower (here trusted) tier. The caller receives the refusal
        // rather than "not found": bubblewrap is installed, and reporting it as absent would send
        // its owner to install an engine they already have.
        let over_untrusted = |p: &Path| {
            if p.starts_with("/over") {
                EngineProbe::Untrusted
            } else {
                EngineProbe::Trusted
            }
        };
        assert_eq!(
            pick_bwrap(false, Some(over), Some(owned), &over_untrusted, &host),
            Err(EngineMiss::Refused {
                env: BWRAP_OVERRIDE_ENV,
                path: over.to_path_buf()
            })
        );
        assert_eq!(
            pick_bwrap(true, Some(over), Some(owned), &over_untrusted, &host),
            Err(EngineMiss::Refused {
                env: BWRAP_OVERRIDE_ENV,
                path: over.to_path_buf()
            })
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
            Ok((host_bwrap, BwrapSource::HostPath))
        );

        // An untrusted host engine on `PATH` (a poisoned entry) is not used; with no owned
        // engine, nothing resolves. No override was named, so nothing was refused on the
        // invoker's behalf: this is a miss.
        let host_untrusted = |_: &Path| EngineProbe::Untrusted;
        assert_eq!(
            pick_bwrap(false, None, None, &host_untrusted, &host),
            Err(EngineMiss::NotFound)
        );

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
            Ok((late, BwrapSource::HostPath))
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
        assert!(
            !dir.join(format!(".bwrap.tmp.{}", std::process::id()))
                .exists()
        );

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
