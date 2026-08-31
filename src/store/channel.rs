//! The nixpkgs channel pin: which source a launch resolves against, which lock file records it,
//! and whether a pinned revision is one nixpkgs history actually contains.
//!
//! A source is a constant; the revision it resolves to is *state*, seeded on first use and
//! advanced only by an explicit upgrade — that seeded-not-baked rule is what keeps tool versions
//! fixed across sbx binary updates, and it is spelled out on the types that implement it. One lock
//! file per scope (global, engine, project, app) so rolling one never rolls another.
//!
//! This module never resolves a binary: every entry point that needs nix takes `nix: &Path` from
//! its caller, so the channel state machine can be read — and tested — without the engine
//! resolution beside it.

use super::layout::{Layout, ensure};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

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
pub(super) const NIXPKGS_LOCK: &str = "nixpkgs.lock";

/// The file (under the data directory) recording the mise engine's resolved source +
/// revision — a dedicated lock so an explicit `sbx upgrade mise` advances the engine
/// independently of the base channel (`nixpkgs.lock`). The engine tracks the global
/// channel source, but pinning it here on its own means rolling the base never bumps the
/// engine, and rolling the engine never bumps the base.
const MISE_ENGINE_LOCK: &str = "mise-engine.lock";

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
    /// Another lock to take this one's first revision from, when this lock does not exist yet and
    /// that one already records **this** source. Set on the targets that were carved out of the
    /// global channel after the fact (the mise engine, an app): every install that predates the
    /// carve-out has `nixpkgs.lock` and nothing else, so resolving fresh would hit the network and
    /// re-pin them to the day's revision — advancing an engine, or an app, on a mere binary update.
    /// That is what the seeded-not-baked model forbids, and it would also make the first launch
    /// need a network the base does not.
    ///
    /// So the seed is not a cache: it is what makes the carve-out invisible until something is
    /// rolled on purpose. `None` for the two targets that were always their own source of truth.
    seed_from: Option<PathBuf>,
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
            seed_from: None,
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
            seed_from: Some(global_lock_path(layout)),
        }
    }

    /// A trusted project's pin, in its per-project lock — so the project's tools (and
    /// base) are reproducible independent of the rolling global channel.
    pub(crate) fn project(layout: &Layout, project_id: &str, source: &str) -> Self {
        Self {
            source: source.to_string(),
            lock_path: project_lock_path(layout, project_id),
            origin: Origin::ProjectPin,
            seed_from: None,
        }
    }

    /// One app's own target: the **global** channel source, pinned in a lock beside that app's
    /// state, so `sbx upgrade nix --app <name>` advances one app and a global roll leaves it where
    /// it is. Same shape as [`Self::engine`] — the source is not the app's to choose (writing
    /// `nixpkgs` under an app is a refused key), only the resolution is frozen per app.
    ///
    /// Reachable **only** when no trusted project pin applies: an app launch inherits the
    /// baseline's packages, so under a pin those tools must build from the pinned revision or the
    /// pin's whole promise is void. [`crate::sandbox::effective_lock_target`] is where that
    /// precedence lives.
    ///
    /// Errors when the name is not a single safe path component — defence at the sink, since this
    /// joins onto sbx's data directory. Every name that reaches here has already passed
    /// [`crate::config::is_valid_app_name`].
    pub(crate) fn app(
        layout: &Layout,
        name: &str,
        override_source: Option<&str>,
    ) -> io::Result<Self> {
        let (source, origin) = global_source(override_source);
        Ok(Self {
            source,
            lock_path: app_lock_path(layout, name)?,
            origin,
            seed_from: Some(global_lock_path(layout)),
        })
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

    /// The revision recorded here before a roll, **whatever source recorded it**.
    ///
    /// Deliberately not [`Self::locked_revision`], which is scoped to the current source so that a
    /// stale lock never *displays* as current. This answers a different question: "was there a
    /// build here that this roll supersedes?" — and a lock recording another source answers yes.
    /// Switching a pin repoints the store exactly as rolling one forward does, so a caller asking
    /// what a roll invalidated must see both. Pure file read: no nix, no network.
    pub(crate) fn previously_locked(&self) -> Option<String> {
        read_lock(&self.lock_path).map(|(_, rev)| rev)
    }

    /// Resolve to a pinned `github:NixOS/nixpkgs/<rev>`, reusing the lock when its
    /// source matches and resolving (and recording) otherwise.
    pub(crate) fn resolve(&self, nix: &Path, layout: &Layout) -> io::Result<String> {
        resolve_ref(
            nix,
            layout,
            &self.source,
            &self.lock_path,
            self.seed_from.as_deref(),
        )
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

/// One app's own lock, beside that app's state under `<data>/apps/<name>/`. That directory is what
/// `sbx app rm --purge` removes, so an app's pin goes when the app does rather than outliving it as
/// an orphan nothing names.
///
/// Refuses a name that is not a single path component: this is the sink, and a name that traversed
/// would write a lock outside sbx's data directory.
fn app_lock_path(layout: &Layout, name: &str) -> io::Result<PathBuf> {
    if !crate::config::is_valid_app_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{name}` is not a usable app name, so it cannot key a channel lock"),
        ));
    }
    Ok(layout.data_dir().join("apps").join(name).join(NIXPKGS_LOCK))
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

/// The base-channel revisions a shared-store gc must keep: the global channel's, the pin of
/// every project whose lock is still on disk, and the pin of every app that has one. The GUI font
/// set is keyed by the same channel revision as the base userland, so this set covers both
/// `gcroots/base/<rev>/` and `gcroots/gui/<rev>/` — any revision outside it is stale. Reads the
/// locks straight from disk, so a dead project reaped before the gc no longer contributes its pin
/// (and on a dry run, where dead projects still exist, their pins keep their revisions, making the
/// dry run a lower bound on what `--prune` frees). Pure file reads, no nix.
///
/// An app lock has to be read here for the same reason a project's is: an app that has been rolled
/// on its own sits on a revision no other lock records, and collecting it would leave that app's
/// home holding store paths that are gone — the failure a per-app lock exists to make *less*
/// frequent, recreated by the mechanism itself.
pub(crate) fn live_base_revisions(layout: &Layout) -> BTreeSet<String> {
    let mut revs = BTreeSet::new();
    if let Some((_, rev)) = read_global_lock(layout) {
        revs.insert(rev);
    }
    for dir in ["projects", "apps"] {
        if let Ok(entries) = std::fs::read_dir(layout.data_dir().join(dir)) {
            for entry in entries.flatten() {
                if let Some((_, rev)) = read_lock(&entry.path().join(NIXPKGS_LOCK)) {
                    revs.insert(rev);
                }
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

/// Resolve the mise engine reference. The engine's lock is seeded from the global channel lock on
/// first use ([`LockTarget::seed_from`]), which is what makes two properties hold across this
/// feature's introduction:
///
/// - **A binary update never moves the engine.** Every install that predates the engine
///   lock has `nixpkgs.lock` but no `mise-engine.lock`; a plain resolve would hit the
///   network and re-pin `nixos-unstable` to its *current* revision, bumping the in-cage
///   mise on a mere binary update — exactly what the seeded-not-baked model forbids.
/// - **The first launch still works offline.** That fresh resolution would otherwise fail
///   with no network, where the base (resolved from its own lock) does not.
///
/// The launcher resolves the base before the engine, so even a fresh install has `nixpkgs.lock`
/// written by then and base == engine from the start; they diverge only on an explicit
/// `sbx upgrade mise`. Only when neither lock has the source (a pinned-only user who has never
/// resolved the global channel) does it resolve fresh, which then needs nix.
pub(crate) fn resolve_engine_ref(
    nix: &Path,
    layout: &Layout,
    global_override: Option<&str>,
) -> io::Result<String> {
    LockTarget::engine(layout, global_override).resolve(nix, layout)
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
///
/// `seed_from` is the lock this one takes its **first** revision from ([`LockTarget::seed_from`]):
/// consulted only when this lock does not already pin this source, and only when the seed pins the
/// same source. Seeding writes the revision here, so the seed is read once and everything after
/// reads this lock alone — a later roll of either lock moves only its own target.
fn resolve_ref(
    nix: &Path,
    layout: &Layout,
    source: &str,
    lock_path: &Path,
    seed_from: Option<&Path>,
) -> io::Result<String> {
    ensure(layout)?;
    if let Some((locked_source, locked_rev)) = read_lock(lock_path)
        && locked_source == source
    {
        return Ok(format!("{NIXPKGS_FLAKE_PREFIX}{locked_rev}"));
    }
    if let Some(seed) = seed_from
        && let Some((seed_source, seed_rev)) = read_lock(seed)
        && seed_source == source
    {
        write_lock(lock_path, source, &seed_rev)?;
        return Ok(format!("{NIXPKGS_FLAKE_PREFIX}{seed_rev}"));
    }
    let rev = resolve_source_rev(nix, layout, source, false)?;
    write_lock(lock_path, source, &rev)?;
    Ok(format!("{NIXPKGS_FLAKE_PREFIX}{rev}"))
}

/// Force a fresh resolution of `source`, ignoring any matching lock, and rewrite
/// `lock_path` — the explicit roll-forward. Records the previous revision (only when
/// the lock already pinned this same source) so the caller can report the change. A
/// 40-hex source resolves to itself without a channel lookup, so refreshing a fixed pin rewrites
/// the lock with the revision it already carried. Not a no-op end to end: the pinned form is still
/// witnessed against the repository, which is a nix-driven HTTPS request that degrades silently
/// when it cannot run.
fn refresh_ref(nix: &Path, layout: &Layout, source: &str, lock_path: &Path) -> io::Result<Upgrade> {
    ensure(layout)?;
    let previous = read_lock(lock_path).and_then(|(s, r)| (s == source).then_some(r));
    let revision = resolve_source_rev(nix, layout, source, true)?;
    write_lock(lock_path, source, &revision)?;
    Ok(Upgrade {
        source: source.to_string(),
        previous,
        revision,
    })
}

/// Resolve a source to its revision: a 40-hex source already *is* the revision, so it needs no
/// channel resolution — though it is still witnessed against the repository below, which does spawn
/// nix; a branch/channel is resolved via `nix flake metadata`.
///
/// `fresh` is passed to the witness the pinned form goes through, so it asks with the same currency
/// as the caller: an upgrade re-asks, a launch may reuse a cached answer. Checking a fresh claim
/// against a stale answer, or the reverse, is what would produce a warning a re-run cannot clear.
fn resolve_source_rev(
    nix: &Path,
    layout: &Layout,
    source: &str,
    fresh: bool,
) -> io::Result<String> {
    if let Some(rev) = valid_revision(source) {
        // Witnessed here and not below: a pinned revision is opaque, and nothing about the name it
        // was written under says it belongs to nixpkgs. The branch form needs no witness, and
        // asking one of a release branch's head would report an ordinary configuration.
        witness_revision(nix, layout, &rev, fresh);
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
pub(super) fn revision_from_metadata(stdout: &str) -> Option<String> {
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

/// The branch a pinned revision must be reachable from for `github:NixOS/nixpkgs/<rev>` to mean
/// what its name says.
///
/// `master` rather than a channel, because every channel branch is cut from it: a revision
/// reachable from a channel is reachable from here too. The converse is what the choice costs. A
/// fix backported to a release branch *after* that branch was cut belongs to no `master` history,
/// and reads exactly like a revision that never belonged to nixpkgs at all. That is the reason the
/// witness warns and never refuses.
const NIXPKGS_WITNESS_BRANCH: &str = "master";

/// What could be established about a revision's place in nixpkgs history.
#[derive(Debug, PartialEq, Eq)]
enum Reachability {
    /// The branch's history contains the revision, so the pin is what its name says.
    InHistory,
    /// The repository answered, and its history does not contain the revision.
    Absent,
    /// Nothing to build on: offline, rate-limited, or a body that did not parse. Not evidence
    /// either way, so it is kept silent rather than turned into an accusation.
    Unknown,
}

/// The comparison the witness asks GitHub. `rev` is 40-hex by the time it reaches here, so it
/// carries nothing that could escape either the URL or the nix string literal the fetch
/// interpolates it into.
fn reachability_url(rev: &str) -> String {
    format!("https://api.github.com/repos/NixOS/nixpkgs/compare/{NIXPKGS_WITNESS_BRANCH}...{rev}")
}

/// How many commits the compared revision carries that the branch does not. Zero is the whole
/// question: it means the branch's history already contains the revision.
fn ahead_by(answer: &serde_json::Value) -> Option<u64> {
    answer.get("ahead_by")?.as_u64()
}

/// Ask the party that hosts nixpkgs whether `rev` is part of its history.
///
/// Fetching `github:NixOS/nixpkgs/<rev>` proves less than it reads. GitHub keeps pull-request heads
/// in the *upstream* repository's ref namespace, so a revision pushed to a fork and never merged is
/// served in full under the upstream name, and the reference alone says nothing about where the
/// revision came from. Whoever named it is the only thing standing behind it, which is fine for a
/// branch nix resolved itself and is not fine for an opaque 40-hex string.
///
/// The witness adds no trust root of its own: GitHub already serves the artefact, so asking GitHub
/// about reachability introduces nothing new to manage. What it closes is the *index*, not GitHub.
fn reachability(nix: &Path, layout: &Layout, rev: &str, fresh: bool) -> Reachability {
    let Some(rev) = valid_revision(rev) else {
        return Reachability::Unknown;
    };
    let compared =
        crate::sandbox::nixhub::fetch_url_json(nix, layout, &reachability_url(&rev), fresh)
            .ok()
            .map(|answer| ahead_by(&answer));
    // Short-circuiting: the control question is asked only when the first one came back with
    // nothing, which is the only case where its answer changes anything.
    let endpoint_answers = compared.is_some()
        || crate::sandbox::nixhub::fetch_url_json(
            nix,
            layout,
            &reachability_url(NIXPKGS_WITNESS_BRANCH),
            fresh,
        )
        .is_ok();
    verdict(compared, endpoint_answers)
}

/// Read a verdict from what the comparison said, and — when it said nothing at all — from whether
/// the endpoint answers a question whose answer is already known.
///
/// Pure, and that is the point. A failed fetch has two reasons that do not mean the same thing: a
/// revision the repository does not have is answered `404`, the strongest signal there is, while a
/// rate limit or an unplugged cable is no answer at all. Telling them apart by a control request
/// rather than by matching text in an error message keeps the rule off a message that is part of no
/// contract; keeping the rule itself out of the request keeps it off a budget of sixty questions an
/// hour, shared with everything else on the host that asks GitHub anything.
fn verdict(compared: Option<Option<u64>>, endpoint_answers: bool) -> Reachability {
    match compared {
        // Zero commits the branch does not already have is the whole question.
        Some(Some(0)) => Reachability::InHistory,
        Some(Some(_)) => Reachability::Absent,
        // A body that carries no comparison to read: an error object, or a shape that moved.
        Some(None) => Reachability::Unknown,
        None if endpoint_answers => Reachability::Absent,
        None => Reachability::Unknown,
    }
}

/// Say so when a revision about to be pinned is not one nixpkgs history contains.
///
/// Called where a revision arrives as an opaque string, which is where the question has an answer
/// worth having: a package index's reply, and a revision written by hand into a config. A branch is
/// not witnessed, because nix resolved it against the repository itself and a branch head is in its
/// own history by construction.
pub(crate) fn witness_revision(nix: &Path, layout: &Layout, rev: &str, fresh: bool) {
    if reachability(nix, layout, rev, fresh) == Reachability::Absent {
        crate::diag::warn(&format!(
            "`{rev}` is being pinned under `NixOS/nixpkgs`, whose `{NIXPKGS_WITNESS_BRANCH}` \
             history does not contain it. A revision pushed to a fork or left on a pull request is \
             served under the upstream name exactly like one that belongs, so this is the shape a \
             corrupted or hostile package index produces. A fix backported to a release branch \
             after that branch was cut reads the same way, and is the benign case. Nothing was \
             refused: check where the revision came from before trusting what it builds."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::resolve_nix;
    use crate::testutil::TmpDir;

    #[test]
    fn the_witness_asks_about_the_revision_it_was_handed() {
        assert_eq!(
            reachability_url("044bfe75bfe4c7bbe043dc17b5e42ea823b84a09"),
            concat!(
                "https://api.github.com/repos/NixOS/nixpkgs/compare/",
                "master...044bfe75bfe4c7bbe043dc17b5e42ea823b84a09"
            )
        );
    }

    #[test]
    fn a_comparison_answers_the_one_question_the_witness_asks() {
        // Bodies in the shapes the endpoint returns: a revision the branch already contains, one
        // carrying commits the branch does not, and the error body for a revision the repository
        // does not have. Written out rather than fetched, so the test states its own expectation.
        let contained = serde_json::json!({"status": "behind", "ahead_by": 0, "behind_by": 5279});
        let carried = serde_json::json!({"status": "diverged", "ahead_by": 2, "behind_by": 15});
        let absent = serde_json::json!({"message": "Not Found", "status": "404"});
        assert_eq!(ahead_by(&contained), Some(0));
        assert_eq!(ahead_by(&carried), Some(2));
        assert_eq!(
            ahead_by(&absent),
            None,
            "an error body carries no comparison to read"
        );
    }

    #[test]
    fn a_verdict_reads_the_comparison_or_the_control() {
        // The comparison was read.
        assert_eq!(verdict(Some(Some(0)), true), Reachability::InHistory);
        assert_eq!(verdict(Some(Some(2)), true), Reachability::Absent);
        // Read, but carrying no comparison: an error object, or a shape that moved.
        assert_eq!(verdict(Some(None), true), Reachability::Unknown);
        // Nothing came back. The endpoint is answering us, so the failure was about the revision
        // itself, which is the `404` for one the repository does not have.
        assert_eq!(verdict(None, true), Reachability::Absent);
        // Nothing came back and the endpoint is not answering either: no evidence, and a rate
        // limit must never read as an accusation.
        assert_eq!(verdict(None, false), Reachability::Unknown);
    }

    #[test]
    fn the_witness_separates_a_revision_nixpkgs_holds_from_ones_it_merely_serves() {
        let Some(nix) = resolve_nix(None) else {
            skip_incapable!("skipping the nixpkgs witness: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());

        // An ancestor of `master`: what an honest index answers with.
        let held = "044bfe75bfe4c7bbe043dc17b5e42ea823b84a09";
        // A commit backported onto `nixos-25.05` after that branch was cut. It is a real nixpkgs
        // commit and it is in no `master` history, so it exercises the answered-but-not-contained
        // branch, and it is the benign case the warning's own wording names.
        let off_branch = "6c62d013b36c589618eec5a8d450506e15b9cb31";
        // A revision the repository does not have at all: answered `404`, which is a *failed*
        // fetch, so this is also what exercises the control request that tells a `404` apart from
        // a rate limit.
        let never = "0".repeat(40);

        let verdicts = [
            reachability(&nix, &layout, held, false),
            reachability(&nix, &layout, off_branch, false),
            reachability(&nix, &layout, &never, false),
        ];
        // Any `Unknown` is a skip, and that is safe here because no mutation hides behind it: the
        // rule itself is held by `a_verdict_reads_the_comparison_or_the_control`, which needs no
        // endpoint. What this test adds is the part a pure function cannot state, that the live
        // endpoint really does separate the two revisions.
        if verdicts.contains(&Reachability::Unknown) {
            skip_unreachable!("skipping the nixpkgs witness: github answered nothing to build on");
            return;
        }
        assert_eq!(
            verdicts[0],
            Reachability::InHistory,
            "an ancestor of master"
        );
        assert_eq!(verdicts[1], Reachability::Absent, "a post-cut backport");
        assert_eq!(
            verdicts[2],
            Reachability::Absent,
            "a revision github does not have"
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

        assert!(
            LockTarget::global(&layout, None)
                .resolve(Path::new(BOGUS_NIX), &layout)
                .is_err()
        );
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

        assert!(
            LockTarget::global(&layout, Some("nixos-23.11"))
                .resolve(Path::new(BOGUS_NIX), &layout)
                .is_err()
        );
    }

    #[test]
    fn a_revision_source_is_used_without_invoking_nix_and_is_locked() {
        // A 40-hex source is already a revision: it pins directly, with no channel lookup,
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

        assert!(
            LockTarget::global(&layout, None)
                .refresh(Path::new(BOGUS_NIX), &layout)
                .is_err()
        );
        // a failed upgrade is non-destructive: the prior lock is left intact, never
        // truncated, so the next launch still resolves the known-good revision
        assert_eq!(
            read_lock(&global_lock_path(&layout)),
            Some(("nixos-unstable".to_string(), REV.to_string()))
        );
    }

    #[test]
    fn refresh_of_a_revision_pin_reports_itself_even_when_the_witness_cannot_run() {
        // A 40-hex source resolves to itself without a channel lookup, so refreshing a fixed pin
        // reports the same revision as previous and new. `BOGUS_NIX` is the point: the pinned form
        // is still witnessed against the repository, and that witness spawns nix — this pins that
        // a witness which cannot run degrades to the pin rather than failing the refresh. It is
        // not, as the name used to say, a path that never reaches nix at all.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(global_lock_path(&layout), format!("{REV}\n{REV}\n")).unwrap();

        let up = LockTarget::global(&layout, Some(REV))
            .refresh(Path::new(BOGUS_NIX), &layout)
            .expect("a revision pin refreshes even when the witness cannot run");
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
    fn an_app_seeds_from_the_global_lock_and_then_stops_following_it() {
        // The whole point of a per-app lock, in one run. An app that has never been resolved takes
        // its first revision from the global lock (no nix — proven by the bogus one), records it in
        // its own lock, and from then on a global roll leaves it where it is. Without the seed,
        // shipping this feature would re-pin every existing app to the day's revision on its next
        // launch; without the lock, the app would keep following the global channel and the verb
        // that rolls one app would have nothing to roll.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        std::fs::write(
            layout.data_dir().join(NIXPKGS_LOCK),
            format!("nixos-unstable\n{REV}\n"),
        )
        .unwrap();

        let app = LockTarget::app(&layout, "demo-app", None).expect("a valid app name");
        assert_eq!(
            app.resolve(Path::new(BOGUS_NIX), &layout)
                .expect("the app seeds from the global lock with no nix"),
            format!("{NIXPKGS_FLAKE_PREFIX}{REV}")
        );
        // Recorded beside that app's state, which is what `sbx app rm --purge` removes.
        assert_eq!(
            read_lock(&layout.data_dir().join("apps/demo-app").join(NIXPKGS_LOCK)),
            Some(("nixos-unstable".to_string(), REV.to_string()))
        );

        // The global channel moves on (as `sbx upgrade nix` would move it). The app does not: its
        // own lock answers, and the seed is never consulted again.
        let rolled = "1111111111111111111111111111111111111111";
        std::fs::write(
            layout.data_dir().join(NIXPKGS_LOCK),
            format!("nixos-unstable\n{rolled}\n"),
        )
        .unwrap();
        assert_eq!(
            app.resolve(Path::new(BOGUS_NIX), &layout).unwrap(),
            format!("{NIXPKGS_FLAKE_PREFIX}{REV}"),
            "a global roll must not move an app that has its own lock"
        );
        assert_eq!(app.locked_revision().as_deref(), Some(REV));
    }

    #[test]
    fn an_app_with_no_lock_anywhere_resolves_fresh_and_so_needs_nix() {
        // Same floor as the engine's: nothing to seed from means a genuine first resolution, which
        // needs nix. Proves the seed branch is not silently inventing a revision.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let app = LockTarget::app(&layout, "demo-app", None).unwrap();
        assert!(app.resolve(Path::new(BOGUS_NIX), &layout).is_err());
    }

    #[test]
    fn an_app_lock_is_refused_for_a_name_that_is_not_one_path_component() {
        // Defence at the sink: this joins onto sbx's data directory, so a name that traversed would
        // write a lock outside it. The refusal names the offending value.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        for bad in ["", ".", "..", "../etc", "a/b", "/abs"] {
            let err = LockTarget::app(&layout, bad, None)
                .expect_err("a name that is not a single component must be refused");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
        assert!(LockTarget::app(&layout, "demo-app", None).is_ok());
    }

    #[test]
    fn live_base_revisions_keeps_what_an_app_is_pinned_to() {
        // A gc that does not read the app locks collects the base an app is frozen on, leaving that
        // app's home pointing into a store path that is gone — the exact failure a per-app lock is
        // meant to make rarer, recreated by the lock itself.
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        let d = layout.data_dir();
        std::fs::create_dir_all(d).unwrap();
        let app_rev = "2222222222222222222222222222222222222222";
        let project_rev = "3333333333333333333333333333333333333333";
        std::fs::write(d.join(NIXPKGS_LOCK), format!("nixos-unstable\n{REV}\n")).unwrap();
        write_lock(
            &d.join("apps/demo-app").join(NIXPKGS_LOCK),
            "nixos-unstable",
            app_rev,
        )
        .unwrap();
        write_lock(
            &d.join("projects/abcdef0123456789").join(NIXPKGS_LOCK),
            "nixos-24.11",
            project_rev,
        )
        .unwrap();

        let live = live_base_revisions(&layout);
        assert!(live.contains(REV), "the global channel's revision");
        assert!(live.contains(project_rev), "a project's pin");
        assert!(live.contains(app_rev), "an app's own pin");
        assert_eq!(live.len(), 3);
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
}
