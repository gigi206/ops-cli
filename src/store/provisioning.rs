//! Turning a pinned reference into a built store path.
//!
//! The daemonless nix invocation every build runs under, the four provision entry points (free and
//! unfree, flake and expression), the expression-stamp short-circuit that lets a repeat build
//! answer without spawning nix, and the selection of the output that actually carries what the
//! caller asked for.
//!
//! Named `provisioning` rather than `provision` on purpose: [`provision`] is a function of this
//! module and the docs link to it repeatedly, and a module sharing that name would make every one
//! of those links ambiguous under rustdoc's `-D warnings`.

use super::engine::resolve_nix_store;
use super::layout::{Layout, ensure, physical_path};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
///
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

/// Provision `<flake_ref>#<attr>` into the user-owned store and return its
/// *logical* store path, rooting it against garbage collection with an out-link
/// at `gcroot`. `flake_ref` is the pinned reference from [`super::channel::LockTarget::resolve`].
///
/// The build runs daemonless with the build sandbox on (safe here, in plain host
/// context outside the agent's cap-dropped cage). A derivation can have several
/// outputs (e.g. a `-man` beside the binary), so the output is selected by which
/// one actually contains `marker` — by content, not by order. nix's progress (the
/// first-run cache fetch) streams to the user; only the out-paths are captured.
///
/// This is the path for sbx's **own furniture** — the portal, the font layer, the storage
/// helpers — where the attribute is one sbx names itself and is free by construction. What the
/// *user* declares goes through [`provision_unfree`] instead; the split is by who chose the
/// attribute, not by what the licence turned out to be.
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

/// Provision a **user-declared** attribute, permitting an **unfree** licence.
///
/// Despite the name this is not a special case taken for known-proprietary packages: it is the
/// single path every `nix:` entry in `[packages]` takes (`sandbox::packages`), free or
/// not. sbx cannot know a licence before evaluating, and an attribute is not asked twice, so the
/// allowance is decided by *who named the attribute* rather than by what its licence turns out to
/// be. A free package builds through here byte for byte as it would through [`provision`]; the
/// difference shows only on an attribute nixpkgs would otherwise refuse.
///
/// The consequence to be honest about: declaring `nix:<attr>` accepts that attribute's licence
/// terms on the user's behalf, and some are proprietary (a vendor agent CLI whose upstream ships
/// closed-source releases; a BUSL-licensed server tool). sbx neither asks nor reports which of a
/// project's packages were unfree, so the guide shows how to ask nixpkgs directly.
///
/// nixpkgs refuses to evaluate an unfree package unless allowed, so this builds it
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
    // The licensed path is the one that *interpolates* the attribute into an expression rather than
    // handing it to nix positionally, so it answers to the same rule as a prebuilt package's
    // library list. Refused here rather than left to fail as a syntax error from inside the
    // derivation, which names neither the attribute nor the field that carried it.
    if !crate::config::is_bare_nix_attr(attr) {
        return Err(io::Error::other(format!(
            "cannot build `{attr}` with its licence allowed: this attribute is written into a nix \
             expression, where a `+` reads as the addition operator rather than as part of a name"
        )));
    }
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
        // attr-path (`python3Packages.foo` → nested access, matching the flakeref `#attr` form),
        // and it has passed `is_bare_nix_attr` at the entry point: a segment carrying the `+` that
        // `is_valid_attr` admits would parse here as the addition operator, so it is refused where
        // the caller can be told why rather than left to fail inside the derivation.
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
///
/// `allow_unfree` opts the one build into the unfree-permitting invocation described on
/// [`provision_unfree`].
///
/// Writes the out-link and no stamp, deliberately: a `nix:` attribute names the pinned channel
/// revision, so `nix build` is an eval-cache hit and there is nothing for a short-circuit to save.
/// It may nevertheless repoint an out-link that a stamping provisioner wrote — `[packages]` roots
/// every entry at `<gcroots>/<name>` whatever backend declared it — which is why the stamp records
/// its target and [`reuse_built_expr`] checks it, rather than each non-stamping writer being made
/// to clear a stamp it does not know about.
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
    if let Ok(logical) = std::fs::read_link(&link)
        && physical_path(layout, &logical).symlink_metadata().is_ok()
    {
        return;
    }

    let Some(source) = channel_source_path(nix, layout, flake_ref) else {
        return;
    };
    let Some(nix_store) = resolve_nix_store(Some(layout)) else {
        return;
    };
    if let Some(parent) = link.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
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
/// codes nix wraps the label in, mirroring [`super::channel::revision_from_metadata`]. Requiring
/// the `/nix/store/` prefix is what keeps a surprising line from turning into an arbitrary path in
/// a command. Pure, so it is testable without invoking nix.
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
///
/// The stamp records the out-link's target beside the digest, and [`reuse_built_expr`] requires both:
/// this gcroot is shared with the `nix:` path, which writes the out-link and stamps nothing.
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
    write_expr_stamp(&stamp, &digest, &resolved);
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
/// records the SHA-256 of the expression that produced the current out-link *and the store path it
/// produced*, and when a launch's expression hashes the same, the out-link still points at that
/// path, and it still carries `marker`, the built output is returned without spawning nix. Keying on the expression (not just the gcroot path) is
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
    write_expr_stamp(&stamp, &digest, &resolved);
    Ok(resolved)
}

/// The sibling stamp recording which expression built a gcroot's output, and which output that
/// was: `<gcroot>.expr`. Appended
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
/// records this exact expression's digest **and the out-link it was written for**, the out-link
/// still points there, and its output still carries `marker`. `None` (⇒ rebuild) on any miss —
/// absent/stale stamp, an out-link that has moved, a dangling or garbage-collected out-link, or a
/// missing marker — so a changed expression or a vanished output always rebuilds. The out-link
/// points at the logical `/nix/store/<hash>` path (mapped through [`physical_path`] for the marker
/// probe, never followed, exactly as [`select_marked_output`] does).
///
/// Recording the target is what keeps the stamp honest about a gcroot it does not own alone. The
/// same out-link is written by provisioners that stamp ([`provision_flake`], [`provision_expr`])
/// and by ones that do not ([`provision_licensed`], the `nix:` path) — `[packages]` roots every
/// entry at `<gcroots>/<name>` whatever backend it declares — so a package moved from `flake:` to
/// `nix:` and back would find its own digest still stamped over an out-link the nix build had
/// repointed, and serve nixpkgs' output under the flake package's name without ever building the
/// flake. A digest alone cannot see that: it describes the expression, and the expression did not
/// change. Binding it to the target it described makes the reuse answer for the whole claim, and
/// it holds against any future writer of a gcroot rather than against the ones known today.
///
/// A stamp from before this shape carries the digest alone, mismatches, and rebuilds once. That is
/// the only direction this can fail in: it forfeits a short-circuit, never serves a wrong output.
fn reuse_built_expr(
    layout: &Layout,
    gcroot: &Path,
    marker: &str,
    stamp: &Path,
    digest: &str,
) -> Option<PathBuf> {
    let recorded = std::fs::read_to_string(stamp).ok()?;
    let (recorded_digest, recorded_target) = recorded.split_once('\n')?;
    if recorded_digest.trim() != digest {
        return None;
    }
    let logical = std::fs::read_link(gcroot).ok()?;
    if Path::new(recorded_target.trim()) != logical {
        return None;
    }
    physical_path(layout, &logical)
        .join(marker)
        .symlink_metadata()
        .ok()?;
    Some(logical)
}

/// Write the expression stamp atomically (temp + rename): the digest, then the logical out-link
/// target it describes, one per line. Best-effort: a write failure just makes the next launch
/// rebuild instead of short-circuiting — slower, never incorrect. A target that is not UTF-8 writes
/// no stamp at all, for the same reason and with the same consequence; a store path is ASCII, so
/// this is a shape that does not arise rather than a case being handled.
fn write_expr_stamp(stamp: &Path, digest: &str, target: &Path) {
    let Some(target) = target.to_str() else {
        return;
    };
    let mut tmp = stamp.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    if std::fs::write(&tmp, format!("{digest}\n{target}\n")).is_ok() {
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
    use std::ffi::OsStr;

    #[test]
    fn an_unfree_attribute_nix_would_read_as_an_operator_is_refused_before_the_build() {
        // The free path hands `<flakeref>#<attr>` to nix positionally, where a `+` is just a
        // character. The licensed path interpolates the same attribute into an expression, where it
        // is the addition operator, so the two do not accept the same names.
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let e = provision_unfree(
            Path::new("/nonexistent-nix"),
            &layout,
            &data.path().join("root"),
            "github:NixOS/nixpkgs/abc",
            "demoPackages.libstdc++",
            "marker",
        )
        .expect_err("an attribute that cannot be interpolated must not reach nix");
        assert!(
            e.to_string().contains("addition operator"),
            "the refusal says why: {e}"
        );
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
            skip_incapable!("skipping: no btrfs mount on this host");
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

    /// The single argument following `--expr`, if any. Shared by the two tests that examine the
    /// unfree path: one asserts what the expression says, the other hands it to nix.
    fn expr_arg(cmd: &Command) -> Option<String> {
        let args: Vec<_> = cmd.get_args().collect();
        let i = args.iter().position(|a| *a == OsStr::new("--expr"))?;
        args.get(i + 1).map(|a| a.to_string_lossy().into_owned())
    }

    #[test]
    fn provision_command_permits_unfree_via_a_pure_expr_only_when_asked() {
        let layout = Layout::under(Path::new("/data/sbx"));
        let has_env = |cmd: &Command| {
            cmd.get_envs()
                .any(|(k, _)| k == OsStr::new("NIXPKGS_ALLOW_UNFREE"))
        };
        let has_impure = |cmd: &Command| cmd.get_args().any(|a| a == OsStr::new("--impure"));

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

    /// The test above asserts what the unfree expression says; this asks nix whether it is an
    /// expression. See [`crate::testutil::assert_nix_parses`]: the `contains` above survives a
    /// brace left open, and the failure would then land on a user installing a proprietary package,
    /// at the one moment sbx claims to have re-scoped `allowUnfree` for them.
    #[test]
    fn the_unfree_expr_is_one_nix_accepts() {
        let Some(instantiate) = crate::testutil::nix_instantiate() else {
            skip_incapable!("skipping unfree expr parse: no nix-instantiate on this host");
            return;
        };
        let layout = Layout::under(Path::new("/data/sbx"));
        let unfree = provision_command(
            Path::new("/nix"),
            &layout,
            Path::new("/g"),
            "nixpkgs",
            "kiro-cli",
            true,
        );
        let expr = expr_arg(&unfree).expect("unfree build must select via --expr");
        crate::testutil::assert_nix_parses(&instantiate, "store: the unfree build --expr", &expr);
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
        // reuse a build only when the expression is unchanged, the out-link still points where the
        // stamp says, and the marked output is still there — and must fall through to a rebuild
        // (None) on any change, above all a changed expression or a repointed out-link.
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
        write_expr_stamp(&stamp, &da, &logical);
        assert_eq!(
            reuse_built_expr(&layout, &gcroot, marker, &stamp, &da),
            Some(logical.clone())
        );

        // THE headline: a changed expression (EXPR-B) over the SAME stamp/out-link must rebuild
        // (None), never serve the stale EXPR-A output. A naive rev-only key would fail here.
        assert!(reuse_built_expr(&layout, &gcroot, marker, &stamp, &db).is_none());

        // The second headline, and the one a digest alone cannot answer: the out-link repointed
        // under a stamp nobody updated. That is what a `[packages]` entry moved from `flake:` to
        // `nix:` and back leaves behind — both roots at `<gcroots>/<name>`, only one of them
        // stamps — and reusing here would serve nixpkgs' output under the flake package's name
        // without ever building the flake.
        let other = PathBuf::from("/nix/store/11111111111111111111111111111111-other");
        let other_physical = physical_path(&layout, &other);
        std::fs::create_dir_all(other_physical.join("bin")).unwrap();
        std::fs::write(other_physical.join("bin").join("tool"), b"x").unwrap();
        std::fs::remove_file(&gcroot).unwrap();
        std::os::unix::fs::symlink(&other, &gcroot).unwrap();
        assert!(
            reuse_built_expr(&layout, &gcroot, marker, &stamp, &da).is_none(),
            "the expression is unchanged, but the out-link it was stamped for has moved"
        );
        std::fs::remove_file(&gcroot).unwrap();
        std::os::unix::fs::symlink(&logical, &gcroot).unwrap();

        // A stamp written before the target was recorded carries the digest alone: it rebuilds
        // once rather than short-circuiting on a claim it cannot support.
        std::fs::write(&stamp, &da).unwrap();
        assert!(reuse_built_expr(&layout, &gcroot, marker, &stamp, &da).is_none());
        write_expr_stamp(&stamp, &da, &logical);
        assert!(reuse_built_expr(&layout, &gcroot, marker, &stamp, &da).is_some());

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
    use crate::store::channel::NIXPKGS_LOCK;
    use crate::store::{LockTarget, resolve_nix};

    use crate::testutil::TmpDir;

    #[test]
    fn provision_realises_a_pinned_package_into_the_user_store_with_a_gcroot() {
        let Some(nix) = resolve_nix(None) else {
            skip_incapable!("skipping provision: no nix on PATH");
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
            skip_incapable!("skipping provision_expr: no nix on PATH");
            return;
        };
        let base = TmpDir::new();
        let layout = Layout::under(&base.join("sbx"));
        let Ok(nixpkgs) = LockTarget::global(&layout, None).resolve(&nix, &layout) else {
            skip_incapable!("skipping provision_expr: cannot resolve nixpkgs (offline?)");
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
            skip_unreachable!("skipping provision_expr: cold build failed (cache unreachable?)");
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
