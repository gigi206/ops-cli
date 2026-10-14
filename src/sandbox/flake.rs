//! Pinning `flake:` `[packages]` to a fixed revision for `sbx upgrade`.
//!
//! A `flake:<ref>` package is a remote reference, so it is built **host-side** into sbx's store
//! and seeded per project, the way a `nix:` tool is; only an inline `[flakes.<name>]` builds in
//! the cage. By default the ref *floats* — each cold launch resolves the flake's latest revision. `sbx upgrade` pins
//! it: it resolves each declared ref to its current immutable revision with `nix flake
//! metadata` and records `(declared ref → revision, locked ref)` in a per-project lock. A launch
//! then builds the *locked* ref rather than the declared one (`packages::realise`), host-side into
//! the shared store under the package's own project gcroot — so a lock change changes the build
//! target, the next launch builds the new revision and the gcroot moves to it, with no home
//! enumerated: the host-side lock rewrite is the whole roll. A package with no lock entry keeps the
//! floating behaviour, so a project that never runs `sbx upgrade` is unchanged.
//!
//! The revision is recorded and displayed, not used as a path: nothing here is keyed by it. Only an
//! **inline** flake has a content-keyed out-link (`binds::flake_out_link_hash`), because it builds
//! in the cage and has no revision to name.
//!
//! The lock is keyed by the *declared* reference (the floating `flake:<ref>` value), not the
//! package name: two packages naming the same ref in different homes share one pin, and a
//! package whose declared ref changes re-resolves rather than reusing a stale pin.

use crate::store::{self, Layout};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

const FLAKE_LOCK: &str = "flake-packages.lock";

/// A locked flake package: the immutable revision (40-hex, recorded and displayed only — nothing
/// here is keyed by it, as the module header explains) and the immutable build reference (the
/// locked URL plus any `#<attr>` from the declared ref), which is what the launch actually builds
/// and what the out-link is named beside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FlakePin {
    pub(crate) rev: String,
    pub(crate) locked_ref: String,
}

/// A git revision: exactly 40 lowercase hex characters. Validated before a stored value flows
/// back into a flake reference or an on-disk path component. Lowercase-only, matching how nix and
/// `crate::store::valid_revision` spell a rev — an off-case value is a corrupt lock line, refused.
fn is_rev(s: &str) -> bool {
    lower_hex(s, 40)
}

/// Exactly `len` lowercase hex characters.
fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A locked reference is the metadata URL (plus optional `#<attr>`): non-empty, single-line, no
/// control characters or whitespace — so a corrupt lock line can never inject into the build.
fn is_locked_ref(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b > 0x20 && b != 0x7f)
}

/// The per-project flake lock path, beside the other per-project locks.
///
/// The id must be one `binds::project_id` spells, 16 lowercase hex characters, before it is joined:
/// it names a directory under the data dir, and a `..` or a `/` in it would name another one. Every
/// caller passes `project_runtime_id`'s answer today; the check is what keeps the read and the write
/// of this lock from following one that is not.
fn lock_path(layout: &Layout, project_id: &str) -> io::Result<PathBuf> {
    if !lower_hex(project_id, 16) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{project_id}` is not a project id"),
        ));
    }
    Ok(layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join(FLAKE_LOCK))
}

/// Split a declared `flake:` reference (the value after the `flake:` prefix) into its flake
/// reference and optional output attribute. The `#` separates the fragment (the output) from
/// the flake itself; `nix flake metadata` operates on the flake, the attribute is reattached to
/// the locked reference for the build.
fn split_attr(reference: &str) -> (&str, Option<&str>) {
    match reference.split_once('#') {
        Some((base, attr)) => (base, Some(attr)),
        None => (reference, None),
    }
}

/// The locked pins recorded for a project, keyed by the declared reference. Empty when the lock
/// is absent (the floating behaviour); a corrupt line self-heals by being dropped, and so does a
/// line that is not UTF-8, so one bad line never costs the others their pins.
///
/// Any other failure to read the lock is an error. Read as "nothing pinned", it would have a launch
/// build every `flake:` package at its latest upstream revision, and `sbx upgrade` rewrite the lock
/// from what it resolved alone, dropping every pin it did not roll: the unpinning the pin model
/// exists to forbid.
pub(crate) fn pins(layout: &Layout, project_id: &str) -> io::Result<BTreeMap<String, FlakePin>> {
    let path = lock_path(layout, project_id)?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!("cannot read the flake lock {}: {e}", path.display()),
            ));
        }
    };
    let mut entries = BTreeMap::new();
    for line in bytes.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Ok(line) = std::str::from_utf8(line) else {
            continue;
        };
        if let [declared, rev, locked] = line.split('\t').collect::<Vec<_>>()[..]
            && is_rev(rev)
            && is_locked_ref(locked)
        {
            entries.insert(
                declared.to_string(),
                FlakePin {
                    rev: rev.to_string(),
                    locked_ref: locked.to_string(),
                },
            );
        }
    }
    Ok(entries)
}

/// The pinned revisions for a project's `flake:` packages, keyed by the declared reference —
/// which is byte-identical to a package's locator, so a caller can look each up directly. Reads
/// only the per-project lock, exactly as the launch path does, so surfacing a pin realises and
/// fetches nothing — the property `sbx config` relies on. Empty when the data dir or the project
/// identity is unavailable, or nothing is pinned (the floating state). A lock that cannot be read is
/// warned about and shown as no pins: the pins are a detail of the view, not its subject.
pub(crate) fn pinned_revs(cwd: &Path) -> BTreeMap<String, String> {
    let Some(layout) = store::Layout::from_env() else {
        return BTreeMap::new();
    };
    let Ok(id) = super::binds::project_runtime_id(cwd) else {
        return BTreeMap::new();
    };
    match pins(&layout, &id) {
        Ok(pins) => pins
            .into_iter()
            .map(|(declared, pin)| (declared, pin.rev))
            .collect(),
        Err(e) => {
            crate::diag::warn(&format!("the `flake:` pins are not shown: {e}"));
            BTreeMap::new()
        }
    }
}

/// Write the lock atomically (temp + rename), creating the owner-only parent — so a concurrent
/// launch reading it sees the old or the new file, never a torn one.
fn write_pins(
    layout: &Layout,
    project_id: &str,
    entries: &BTreeMap<String, FlakePin>,
) -> io::Result<()> {
    let path = lock_path(layout, project_id)?;
    let mut body = String::new();
    for (declared, pin) in entries {
        body.push_str(&format!("{declared}\t{}\t{}\n", pin.rev, pin.locked_ref));
    }
    super::atomicfile::write_atomic(&path, body.as_bytes())
}

/// How long a `nix flake metadata` may take.
///
/// Not a handful of HTTP requests: to report the `narHash` nix fetches the source itself, so a cold
/// `flake metadata` on nixpkgs took 31 s on this host over a good link. Five minutes is the same
/// window a human-paced host step of the secret chain gets, and it leaves that measurement an
/// order of magnitude of headroom for a slow one. The bound is not about how long a resolution
/// should take; it is so that a far end which accepts and then says nothing cannot hold the launch
/// for as long as it cares to.
pub(crate) const FLAKE_METADATA_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// The error for a `nix flake metadata` that exited non-zero, for both calls that run one: this
/// module's [`resolve`] and the nixpkgs channel's revision in `crate::store::channel`. nix spreads
/// its message over several lines and quotes the reference it was fetching, text a config chose,
/// so the message goes through [`super::resolver::one_line`]: whole, on the one line a terminal
/// shows as written.
pub(crate) fn metadata_failed(reference: &str, stderr: &[u8]) -> io::Error {
    let detail = super::resolver::one_line(stderr);
    io::Error::other(format!(
        "`nix flake metadata {reference}` failed{}",
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    ))
}

/// Resolve a declared `flake:` reference to its current immutable pin via `nix flake metadata`.
/// The flake (the part before `#`) is locked to a revision and an immutable URL; the output
/// attribute is reattached, so the result is the exact reference a launch builds. Uses sbx's
/// nix with the flakes feature, like the nixhub fetcher.
fn resolve(nix: &Path, layout: &Layout, reference: &str) -> io::Result<FlakePin> {
    let (base, attr) = split_attr(reference);
    // Bounded: this reaches the network, and `output()` waits for as long as the far end keeps the
    // connection open without sending. See [`FLAKE_METADATA_DEADLINE`] for why the window is wide.
    //
    // The flake follows a `--`. The reference is the config's, and its flake part is what is left
    // before the `#`: `--impure#x:y` leaves `--impure`, which nix would take as an option with no
    // reference after it, and resolve the flake of the directory sbx runs in instead.
    let out = crate::sandbox::resolver::output_within(
        store::nix_command(nix, layout)
            .args(["--extra-experimental-features", "nix-command flakes"])
            .args(["flake", "metadata", "--json", "--"])
            .arg(base),
        FLAKE_METADATA_DEADLINE,
        &format!("`nix flake metadata {base}`"),
    )?;
    if !out.status.success() {
        return Err(metadata_failed(base, &out.stderr));
    }
    let value: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| io::Error::other(format!("parsing flake metadata for {base}: {e}")))?;
    let rev = value
        .get("revision")
        .and_then(serde_json::Value::as_str)
        .filter(|r| is_rev(r))
        .ok_or_else(|| io::Error::other(format!("{base} resolved to no usable revision")))?;
    let url = value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .filter(|u| is_locked_ref(u))
        .ok_or_else(|| io::Error::other(format!("{base} resolved to no usable locked url")))?;
    // The last place a local source can be refused before it is pinned and built host-side: the
    // declaration was refused on one, and so is what nix answered for it.
    if crate::config::names_a_local_flake_source(url) {
        return Err(io::Error::other(format!(
            "{base} resolved to a local source, `{url}`, which a `flake:` package never builds from"
        )));
    }
    let locked_ref = match attr {
        Some(attr) => format!("{url}#{attr}"),
        None => url.to_string(),
    };
    // The reference a launch builds is checked whole, the attribute with it: it is written to the
    // lock as one field of a line, and read back only if it still is one.
    if !is_locked_ref(&locked_ref) {
        return Err(io::Error::other(format!(
            "{base} resolved to a reference that cannot be locked, whitespace or a control \
             character in it"
        )));
    }
    Ok(FlakePin {
        rev: rev.to_string(),
        locked_ref,
    })
}

/// The outcome of rolling one declared `flake:` reference, for the report.
pub(crate) enum FlakeUpgrade {
    /// Re-resolved to the same revision it was already pinned to.
    Unchanged { reference: String, rev: String },
    /// Rolled from one pinned revision to a newer one.
    Rolled {
        reference: String,
        from: String,
        to: String,
    },
    /// Pinned for the first time (no prior lock entry).
    Pinned { reference: String, rev: String },
    /// A lock entry whose reference is no longer declared, removed from the lock.
    Pruned { reference: String },
    /// Re-resolution failed; the prior pin (if any) is kept.
    Failed {
        reference: String,
        error: String,
        kept: Option<String>,
    },
}

/// The two views `sbx upgrade` needs of a project's declared `flake:` references, collected
/// in one pass over the baseline and each app overlay (see [`declared`]).
struct Declared {
    /// Deterministic, deduplicated, **trusted-only** — the set to roll forward (baseline first,
    /// then apps in name order, first occurrence kept).
    trusted: Vec<String>,
    /// Every declared reference **regardless of trust** — the universe the lock is pruned against,
    /// so an entry is removed only when its package is genuinely gone from the config, never merely
    /// because the project is currently untrusted.
    all: std::collections::BTreeSet<String>,
}

/// Collect both views in a single walk of the layers. Each app overlay is materialized once (a
/// `merge_app` clone), then contributes to both the trusted roll set and the trust-agnostic prune
/// universe — so `sbx upgrade` walks the apps once, not twice.
///
/// Which layers are visited, and which of them `sbx upgrade --app <name>` still offers for
/// rolling, is [`super::packages::walk_roll_layers`]'s rule — the same walk the prebuilt backends
/// run. It applies here for the same reason: the `flake:` lock is one per project, so a narrowed
/// roll must leave the baseline alone while the prune universe stays project-wide, and no per-app
/// roll can unpin another app's reference.
fn declared(cfg: &crate::config::Resolved, only: Option<&str>) -> Declared {
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted = Vec::new();
    let mut all = std::collections::BTreeSet::new();
    super::packages::walk_roll_layers(cfg, only, |pkgs, roll| {
        if roll {
            for (_, reference) in super::packages::flake_packages(pkgs) {
                if seen.insert(reference.clone()) {
                    trusted.push(reference);
                }
            }
        }
        for p in pkgs {
            if let crate::config::Backend::Flake(reference) = &p.backend {
                all.insert(reference.clone());
            }
        }
    });
    Declared { trusted, all }
}

/// How many declared `flake:` packages are withheld for being untrusted — across the project
/// baseline and each app's own overlay. A count only: the per-package withholding reason is
/// already warned on the launch path, so `sbx upgrade` just needs to not read as "none declared".
pub(crate) fn withheld(cfg: &crate::config::Resolved, only: Option<&str>) -> usize {
    let untrusted_flake = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Flake(_))
                    && p.state != crate::trust::TrustState::Trusted
            })
            .count()
    };
    super::packages::count_in_roll_layers(cfg, only, untrusted_flake)
}

/// Re-resolve a project's declared `flake:` references against their upstreams and rewrite the
/// per-project lock — pinning new ones, rolling changed ones forward, and pruning entries whose
/// reference is no longer declared (so a removed-then-readded package never reuses a stale pin).
/// References are collected generically by [`declared`]; resolution is best-effort per
/// reference (a failure keeps the prior pin and is reported), and the lock is rewritten once at
/// the end — or, under [`super::RollMode::DryRun`], left as it is.
pub(crate) fn upgrade(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
    only: Option<&str>,
    mode: super::RollMode,
) -> io::Result<Vec<FlakeUpgrade>> {
    let project_id = super::binds::project_runtime_id(project)?;
    let project_id = project_id.as_str();
    // One walk of the layers yields both the trusted roll set and the trust-agnostic prune universe.
    let Declared {
        trusted: declared,
        all: prune_universe,
    } = declared(cfg, only);
    let snapshot = pins(layout, project_id)?;
    let mut outcomes = Vec::new();

    // Prune entries whose reference is truly no longer declared — measured against ALL declared
    // refs regardless of trust, NOT the trusted-only roll set. A withheld (untrusted/Changed)
    // project's refs are absent from that set, so pruning against it would drop a still-declared
    // package's pin, silently unpinning it — a later re-trust would then float to the latest
    // upstream revision, exactly the movement the pin model forbids. Re-resolution below stays
    // trusted-only (over `declared`); pruning is state-agnostic.
    //
    // Not under a selector: pruning says "no layer declares this any more", which is a statement
    // about the project that a roll narrowed to one app never makes.
    let stale: Vec<(String, FlakePin)> = if only.is_some() {
        Vec::new()
    } else {
        snapshot
            .iter()
            .filter(|(k, _)| !prune_universe.contains(k.as_str()))
            .map(|(k, pin)| (k.clone(), pin.clone()))
            .collect()
    };
    for (reference, _) in &stale {
        outcomes.push(FlakeUpgrade::Pruned {
            reference: reference.clone(),
        });
    }

    let mut resolved = BTreeMap::new();
    for reference in &declared {
        let previous = snapshot.get(reference).map(|p| p.rev.clone());
        match resolve(nix, layout, reference) {
            Ok(pin) => {
                let outcome = match &previous {
                    Some(old) if old == &pin.rev => FlakeUpgrade::Unchanged {
                        reference: reference.clone(),
                        rev: pin.rev.clone(),
                    },
                    Some(old) => FlakeUpgrade::Rolled {
                        reference: reference.clone(),
                        from: old.clone(),
                        to: pin.rev.clone(),
                    },
                    None => FlakeUpgrade::Pinned {
                        reference: reference.clone(),
                        rev: pin.rev.clone(),
                    },
                };
                resolved.insert(reference.clone(), pin);
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(FlakeUpgrade::Failed {
                reference: reference.clone(),
                error: e.to_string(),
                kept: previous,
            }),
        }
    }

    if !mode.applies() {
        return Ok(outcomes);
    }
    // Under the lock's writer guard, as the prebuilt rolls write theirs, and from what the lock
    // holds now rather than from the snapshot: the resolutions above reach the network and can take
    // minutes, and another `sbx upgrade` of this project (another app's, say) may have written its
    // pins meanwhile. An entry is pruned only if it is still exactly as the snapshot found it, a
    // resolution just made lands over whatever its key holds, every other key is left as found, and
    // a roll that changed nothing leaves the file as it was.
    let _writing = store::hold_lock_for_write(
        &lock_path(layout, project_id)?,
        &store::waiting_for_writer("the flake lock"),
    )?;
    let mut disk = pins(layout, project_id)?;
    let before = disk.clone();
    for (key, previous) in stale {
        if disk.get(&key) == Some(&previous) {
            disk.remove(&key);
        }
    }
    disk.extend(resolved);
    if disk != before {
        write_pins(layout, project_id, &disk)?;
    }
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TmpDir, app_with, resolved};

    const REV: &str = "11707dc2f618dd54ca8739b309ec4fc024de578b";
    /// A project id as `binds::project_id` spells one, for a test that needs no real project.
    const PROJ: &str = "0123456789abcdef";

    /// A `nix flake metadata` that fails is reported with all of nix's message, on one line
    /// nothing in it can drive or reorder, and a message that folds to nothing adds nothing.
    #[test]
    fn a_failed_flake_metadata_is_reported_as_one_line_that_drives_nothing() {
        use crate::testutil::{HOSTILE_STDERR, HOSTILE_STDERR_SHOWN, failing_with, write_script};
        let data = TmpDir::new();
        let nix = data.path().join("nix");
        write_script(&nix, &failing_with(HOSTILE_STDERR));
        let layout = Layout::under(data.path());
        let err = crate::testutil::result_past_etxtbsy("nix", || {
            resolve(&nix, &layout, "path:/nowhere#hello")
        })
        .expect_err("a nix that exits 1 fails the resolution");
        assert_eq!(
            err.to_string(),
            format!("`nix flake metadata path:/nowhere` failed: {HOSTILE_STDERR_SHOWN}")
        );
        assert_eq!(
            metadata_failed("path:/nowhere", b" \n\x1b\n").to_string(),
            "`nix flake metadata path:/nowhere` failed"
        );
    }

    /// The flake handed to `nix flake metadata` follows a `--`, so a flake part that reads as an
    /// option is taken as a reference. Without it, `--impure#x:y` left nix `--impure` and no
    /// reference, and nix resolved the flake of the directory sbx ran in, a local one.
    #[test]
    fn the_flake_resolved_follows_a_double_dash() {
        let data = TmpDir::new();
        let nix = data.path().join("nix");
        crate::testutil::write_script(
            &nix,
            &format!(
                "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/argv\"\n\
                 printf '{{\"revision\":\"{REV}\",\"url\":\"github:o/r/{REV}\"}}'"
            ),
        );
        let layout = Layout::under(data.path());
        let pin =
            crate::testutil::result_past_etxtbsy("nix", || resolve(&nix, &layout, "--impure#x:y"))
                .expect("the stand-in answers");
        let argv = std::fs::read_to_string(data.path().join("argv")).unwrap();
        let argv: Vec<&str> = argv.lines().collect();
        assert_eq!(
            argv[argv.len().saturating_sub(2)..],
            ["--", "--impure"],
            "the flake is last, behind a `--`: {argv:?}"
        );
        assert_eq!(pin.locked_ref, format!("github:o/r/{REV}#x:y"));
    }

    /// What `resolve` pins is checked whole before it is: a reference whose attribute would break
    /// its lock line is refused, and so is a locked url naming a local source, the last place one
    /// can be stopped before a launch builds it host-side. Every shape is checked before the test
    /// fails.
    #[test]
    fn resolve_pins_nothing_a_lock_line_or_the_local_source_rule_refuses() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let mut pinned = Vec::new();
        for (reference, url) in [
            ("github:o/r#a\tb", format!("github:o/r/{REV}")),
            ("github:o/r#a b", format!("github:o/r/{REV}")),
            ("github:o/r", format!("git+file:///srv/r?rev={REV}")),
            ("github:o/r", format!("path:/srv/r?rev={REV}")),
        ] {
            let nix = data.path().join("nix");
            crate::testutil::write_script(
                &nix,
                &format!("printf '{{\"revision\":\"{REV}\",\"url\":\"{url}\"}}'"),
            );
            let resolved =
                crate::testutil::result_past_etxtbsy("nix", || resolve(&nix, &layout, reference));
            if let Ok(pin) = resolved {
                pinned.push(format!("{reference:?} -> {:?}", pin.locked_ref));
            }
        }
        assert!(pinned.is_empty(), "{pinned:#?}");
    }

    #[test]
    fn split_attr_separates_the_output_fragment() {
        assert_eq!(
            split_attr("github:o/r#default"),
            ("github:o/r", Some("default"))
        );
        assert_eq!(split_attr("github:o/r"), ("github:o/r", None));
        // Only the first `#` splits — an attribute path may itself be dotted, never `#`-ed.
        assert_eq!(
            split_attr("github:o/r#packages.x86_64-linux.hello"),
            ("github:o/r", Some("packages.x86_64-linux.hello"))
        );
    }

    #[test]
    fn is_rev_accepts_only_40_lowercase_hex() {
        assert!(is_rev(REV));
        assert!(!is_rev("abc"));
        assert!(!is_rev(&"z".repeat(40)));
        assert!(!is_rev(&format!("{REV}0")));
        // Uppercase hex is refused — nix and `store::valid_revision` spell a rev lowercase, so an
        // off-case value is a corrupt lock line.
        assert!(!is_rev(&REV.to_uppercase()));
    }

    fn flake_pkg(name: &str, reference: &str, trusted: bool) -> crate::config::Package {
        crate::config::Package {
            name: name.into(),
            backend: crate::config::Backend::Flake(reference.into()),
            state: if trusted {
                crate::trust::TrustState::Trusted
            } else {
                crate::trust::TrustState::Untrusted
            },
            libs: Vec::new(),
            main: String::new(),
        }
    }

    #[test]
    fn declared_trusted_covers_baseline_and_apps_dedups_and_drops_untrusted() {
        let cfg = resolved(
            vec![
                flake_pkg("a", "github:o/a#default", true),
                flake_pkg("evil", "github:o/evil#x", false), // untrusted: dropped
            ],
            vec![
                // an app with its own flake ref, plus one that repeats the baseline ref
                (
                    "alpha",
                    app_with(vec![
                        flake_pkg("b", "github:o/b#default", true),
                        flake_pkg("a2", "github:o/a#default", true), // duplicate ref: deduped
                    ]),
                ),
                ("beta", app_with(vec![])), // no flake package: contributes nothing
            ],
        );
        let refs = declared(&cfg, None).trusted;
        // Baseline first, then the app's new ref; the duplicate and the untrusted one are gone.
        assert_eq!(refs, vec!["github:o/a#default", "github:o/b#default"]);
    }

    #[test]
    fn the_prune_universe_keeps_untrusted_refs_so_upgrade_never_prunes_a_withheld_pin() {
        // The prune universe must NOT drop a still-declared ref just because the project is
        // untrusted — otherwise `sbx upgrade` on a Changed project unpins it and a later
        // re-trust floats to latest. Unlike the trusted roll set, `declared().all` keeps the ref.
        let cfg = resolved(
            vec![
                flake_pkg("a", "github:o/a#default", true),
                flake_pkg("evil", "github:o/evil#x", false), // untrusted: still in the universe
            ],
            vec![],
        );
        let universe = declared(&cfg, None).all;
        assert!(universe.contains("github:o/a#default"));
        assert!(
            universe.contains("github:o/evil#x"),
            "a withheld-but-declared ref must survive pruning"
        );
    }

    #[test]
    fn pins_round_trip_through_the_lock_and_a_corrupt_line_self_heals() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let mut entries = BTreeMap::new();
        entries.insert(
            "github:o/r#default".to_string(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/r/{REV}?narHash=sha256-x#default"),
            },
        );
        write_pins(&layout, PROJ, &entries).unwrap();

        // A round trip preserves the pin.
        let read = pins(&layout, PROJ).unwrap();
        assert_eq!(
            read.get("github:o/r#default"),
            entries.get("github:o/r#default")
        );

        // A corrupt line (a non-rev second field) is dropped, the valid one kept.
        let path = lock_path(&layout, PROJ).unwrap();
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("github:o/bad\tnot-a-rev\tref\n");
        std::fs::write(&path, text).unwrap();
        let read = pins(&layout, PROJ).unwrap();
        assert_eq!(read.len(), 1, "only the valid pin survives");
        assert!(read.contains_key("github:o/r#default"));
    }

    /// A dry run reports the entry a roll would prune and leaves it in the lock; the roll then
    /// removes it. Offline: nothing is declared, so nothing is resolved.
    #[test]
    fn a_dry_run_reports_the_prune_and_leaves_the_lock_whole() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let reference = "github:o/gone#default".to_string();
        let mut entries = BTreeMap::new();
        entries.insert(
            reference.clone(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/gone/{REV}#default"),
            },
        );
        write_pins(&layout, &id, &entries).unwrap();
        let seeded = std::fs::read(lock_path(&layout, &id).unwrap()).unwrap();
        let cfg = resolved(vec![], vec![]);
        let nix = Path::new("/nonexistent/nix");

        let dry = upgrade(
            nix,
            &layout,
            project.path(),
            &cfg,
            None,
            crate::sandbox::RollMode::DryRun,
        )
        .unwrap();
        assert!(
            matches!(dry.as_slice(), [FlakeUpgrade::Pruned { reference: r }] if *r == reference)
        );
        assert_eq!(
            std::fs::read(lock_path(&layout, &id).unwrap()).unwrap(),
            seeded,
            "a dry run writes nothing"
        );

        upgrade(
            nix,
            &layout,
            project.path(),
            &cfg,
            None,
            crate::sandbox::RollMode::Apply,
        )
        .unwrap();
        assert!(
            pins(&layout, &id).unwrap().is_empty(),
            "the roll prunes what the dry run named"
        );
    }

    /// A roll writes the lock from what it holds once the resolutions are done, under its writer
    /// guard, not from the snapshot taken before they went to the network. The stand-in nix is
    /// another sbx here, writing to the lock while this roll resolves its own app: a pin it adds is
    /// kept, and an entry the roll found stale and would prune is kept too once it has re-pinned it.
    #[test]
    fn a_pin_written_while_the_roll_resolves_is_kept() {
        use std::os::unix::ffi::OsStrExt as _;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let (app, other) = ("github:o/app#default", "github:o/other#default");
        let cfg = resolved(
            vec![],
            vec![("alpha", app_with(vec![flake_pkg("a", app, true)]))],
        );
        let gone = "github:o/gone#default";
        let mut entries = BTreeMap::new();
        entries.insert(
            gone.to_string(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/gone/{REV}#default"),
            },
        );
        write_pins(&layout, &id, &entries).unwrap();
        let lock = lock_path(&layout, &id).unwrap();
        let repinned = "22707dc2f618dd54ca8739b309ec4fc024de578b";
        // The stand-in reads the lock's path and the line to append from files beside it, so the
        // script names no path a root with a space in it could split.
        std::fs::write(data.path().join("lockpath"), lock.as_os_str().as_bytes()).unwrap();
        std::fs::write(
            data.path().join("meanwhile"),
            format!(
                "{other}\t{REV}\tgithub:o/other/{REV}#default\n\
                 {gone}\t{repinned}\tgithub:o/gone/{repinned}#default\n"
            ),
        )
        .unwrap();
        let nix = data.path().join("nix");
        crate::testutil::write_script(
            &nix,
            &format!(
                "here=$(dirname \"$0\")\n\
                 cat \"$here/meanwhile\" >> \"$(cat \"$here/lockpath\")\"\n\
                 printf '{{\"revision\":\"{REV}\",\"url\":\"github:o/app/{REV}\"}}'"
            ),
        );

        crate::testutil::result_past_etxtbsy("nix", || {
            upgrade(
                &nix,
                &layout,
                project.path(),
                &cfg,
                None,
                crate::sandbox::RollMode::Apply,
            )
        })
        .expect("the roll resolves its app");
        let after = pins(&layout, &id).unwrap();
        assert!(
            after.contains_key(app),
            "the roll pinned its app: {after:?}"
        );
        assert!(
            after.contains_key(other),
            "the pin written meanwhile is kept: {after:?}"
        );
        assert_eq!(
            after.get(gone).map(|pin| pin.rev.as_str()),
            Some(repinned),
            "a stale entry re-pinned meanwhile is not pruned"
        );
    }

    /// The roll's write waits for the lock's writer guard: while another sbx holds it, the lock is
    /// neither read again nor written, and the roll lands once the guard is let go. The guard is
    /// released before the join, so a roll that did not wait fails the test rather than hangs it.
    #[test]
    fn a_roll_waits_for_the_lock_writer_guard() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let app = "github:o/app#default";
        let cfg = resolved(vec![flake_pkg("a", app, true)], vec![]);
        let nix = data.path().join("nix");
        crate::testutil::write_script(
            &nix,
            &format!("printf '{{\"revision\":\"{REV}\",\"url\":\"github:o/app/{REV}\"}}'"),
        );
        let lock = lock_path(&layout, &id).unwrap();
        let guard = store::hold_lock_for_write(&lock, &|_| {}).expect("the guard");

        let roll = {
            let (layout, project, nix) =
                (layout.clone(), project.path().to_path_buf(), nix.clone());
            std::thread::spawn(move || {
                crate::testutil::result_past_etxtbsy("nix", || {
                    upgrade(
                        &nix,
                        &layout,
                        &project,
                        &cfg,
                        None,
                        crate::sandbox::RollMode::Apply,
                    )
                })
            })
        };
        std::thread::sleep(std::time::Duration::from_secs(1));
        let waited = !roll.is_finished();
        let untouched = !lock.exists();
        drop(guard);
        let rolled = roll.join().unwrap();

        assert!(waited, "the roll did not wait for the guard");
        assert!(untouched, "the lock was written while the guard was held");
        rolled.expect("the roll lands once the guard is let go");
        assert!(pins(&layout, &id).unwrap().contains_key(app));
    }

    /// A roll that changes nothing leaves the lock as it was, the same file: written anyway, it
    /// would be replaced by a new one each time.
    #[test]
    fn a_roll_that_changes_nothing_leaves_the_lock_as_it_was() {
        use std::os::unix::fs::MetadataExt as _;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let app = "github:o/app#default";
        let mut entries = BTreeMap::new();
        entries.insert(
            app.to_string(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/app/{REV}#default"),
            },
        );
        write_pins(&layout, &id, &entries).unwrap();
        let cfg = resolved(vec![flake_pkg("a", app, true)], vec![]);
        let nix = data.path().join("nix");
        crate::testutil::write_script(
            &nix,
            &format!("printf '{{\"revision\":\"{REV}\",\"url\":\"github:o/app/{REV}\"}}'"),
        );
        let lock = lock_path(&layout, &id).unwrap();
        let before = std::fs::metadata(&lock).unwrap().ino();

        let rolled = crate::testutil::result_past_etxtbsy("nix", || {
            upgrade(
                &nix,
                &layout,
                project.path(),
                &cfg,
                None,
                crate::sandbox::RollMode::Apply,
            )
        })
        .expect("the roll resolves its package");
        assert!(
            matches!(rolled.as_slice(), [FlakeUpgrade::Unchanged { .. }]),
            "the package resolved to the revision it was pinned to"
        );
        assert_eq!(
            std::fs::metadata(&lock).unwrap().ino(),
            before,
            "the lock is the same file"
        );
    }

    /// A lock line that is not UTF-8 is dropped like any corrupt line, and the other lines keep
    /// their pins: read whole as text, one such byte cost every pin in the file.
    #[test]
    fn a_lock_line_that_is_not_utf8_costs_only_itself() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let mut entries = BTreeMap::new();
        entries.insert(
            "github:o/r#default".to_string(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/r/{REV}#default"),
            },
        );
        write_pins(&layout, PROJ, &entries).unwrap();
        let path = lock_path(&layout, PROJ).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        // A line whose declared reference carries a byte that is not UTF-8, then a bare one.
        bytes.extend_from_slice(b"github:o/\xff\t");
        bytes.extend_from_slice(REV.as_bytes());
        bytes.extend_from_slice(b"\tgithub:o/x\ngithub:o/\xff\n");
        std::fs::write(&path, bytes).unwrap();

        let read = pins(&layout, PROJ);
        assert_eq!(read.ok(), Some(entries), "the valid line keeps its pin");
    }

    /// A lock that cannot be read fails the roll and is left as it was. Read as "nothing pinned",
    /// the roll rewrote it from what it resolved alone: narrowed to one app, it dropped the
    /// baseline's pin, which the next launch then built at its latest revision.
    #[test]
    fn an_unreadable_lock_fails_the_roll_and_keeps_every_pin() {
        use std::os::unix::fs::PermissionsExt as _;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let (base, app) = ("github:o/base#default", "github:o/app#default");
        let entries: BTreeMap<String, FlakePin> = [base, app]
            .into_iter()
            .map(|reference| {
                let pin = FlakePin {
                    rev: REV.to_string(),
                    locked_ref: format!("{reference}-{REV}"),
                };
                (reference.to_string(), pin)
            })
            .collect();
        write_pins(&layout, &id, &entries).unwrap();
        let cfg = resolved(
            vec![flake_pkg("b", base, true)],
            vec![("alpha", app_with(vec![flake_pkg("a", app, true)]))],
        );
        let nix = data.path().join("nix");
        crate::testutil::write_script(
            &nix,
            &format!("printf '{{\"revision\":\"{REV}\",\"url\":\"github:o/app/{REV}\"}}'"),
        );
        let lock = lock_path(&layout, &id).unwrap();
        let seeded = std::fs::read(&lock).unwrap();

        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
        // The failure provoked is a lock this process may not read, which a process allowed past
        // the mode never meets: the probe asks this process rather than its uid. The mode is
        // restored before anything is asserted.
        let meets_it =
            std::fs::read(&lock).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let rolled = meets_it.then(|| {
            crate::testutil::result_past_etxtbsy("nix", || {
                upgrade(
                    &nix,
                    &layout,
                    project.path(),
                    &cfg,
                    Some("alpha"),
                    crate::sandbox::RollMode::Apply,
                )
            })
        });
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let Some(rolled) = rolled else {
            skip_incapable!(
                "skipping the unreadable-lock roll: this process reads a file without a read bit"
            );
            return;
        };
        assert!(rolled.is_err(), "the roll read an unreadable lock as empty");
        assert_eq!(
            std::fs::read(&lock).unwrap(),
            seeded,
            "the lock is left as it was"
        );
    }

    /// A launch whose flake lock cannot be read fails naming the lock, rather than building the
    /// declared reference at its latest revision as though nothing were pinned.
    #[test]
    fn a_launch_over_an_unreadable_lock_fails_rather_than_floats() {
        use std::os::unix::fs::PermissionsExt as _;
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let reference = "github:o/r#default";
        let mut entries = BTreeMap::new();
        entries.insert(
            reference.to_string(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/r/{REV}#default"),
            },
        );
        write_pins(&layout, &id, &entries).unwrap();
        let lock = lock_path(&layout, &id).unwrap();

        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
        // The probe asks this process rather than its uid, and the mode is restored before
        // anything is asserted.
        let meets_it =
            std::fs::read(&lock).is_err_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
        let provisioned = meets_it.then(|| {
            super::super::packages::provision(
                Path::new("/nonexistent/nix"),
                &layout,
                project.path(),
                &format!("github:NixOS/nixpkgs/{REV}"),
                &[flake_pkg("tool", reference, true)],
            )
        });
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        let Some(provisioned) = provisioned else {
            skip_incapable!(
                "skipping the unreadable-lock launch: this process reads a file without a read bit"
            );
            return;
        };
        let err = provisioned.err().map(|e| e.to_string());
        assert!(
            err.as_deref().is_some_and(|e| e.contains("flake lock")),
            "{err:?}"
        );
    }

    /// The lock is addressed only by an id `binds::project_id` spells, so a `..` or a `/` in what a
    /// caller hands over never names a directory beside the project's: the read and the write both
    /// refuse it, and every shape is checked before the test fails.
    #[test]
    fn the_lock_is_addressed_only_by_a_project_id() {
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let mut followed = Vec::new();
        for id in ["../x", "0123456789abcde/", "0123456789ABCDEF", ""] {
            if pins(&layout, id).is_ok() {
                followed.push(format!("pins read under `{id}`"));
            }
            if write_pins(&layout, id, &BTreeMap::new()).is_ok() {
                followed.push(format!("write_pins wrote under `{id}`"));
            }
        }
        assert!(followed.is_empty(), "{followed:#?}");
    }

    #[test]
    fn a_pin_is_keyed_by_the_real_project_runtime_id() {
        // `sbx upgrade` (the writer) and `sbx config`/launch (the readers, via `pinned_revs`)
        // both key the per-project lock by `binds::project_runtime_id(cwd)` — the same function on
        // the same project path — so a pin written for a project is read back for it, and never for
        // a different one. Exercise that shared keying through the real id derivation (no nix, no
        // network): the silent-miss the display would otherwise hide is a divergence here.
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let proj = TmpDir::new();
        let other = TmpDir::new();
        let id = super::super::binds::project_runtime_id(proj.path()).expect("project id");
        let other_id =
            super::super::binds::project_runtime_id(other.path()).expect("other project id");
        assert_ne!(id, other_id, "distinct projects must key to distinct ids");

        let reference = "github:o/r#default".to_string();
        let mut entries = BTreeMap::new();
        entries.insert(
            reference.clone(),
            FlakePin {
                rev: REV.to_string(),
                locked_ref: format!("github:o/r/{REV}?narHash=sha256-x#default"),
            },
        );
        write_pins(&layout, &id, &entries).unwrap();

        // The owning project reads its pin back, the `rev` flattened exactly as `pinned_revs` does.
        let read = pins(&layout, &id).unwrap();
        assert_eq!(read.get(&reference).map(|p| p.rev.as_str()), Some(REV));

        // A different project sees nothing — the lock is project-scoped by the runtime id.
        assert!(pins(&layout, &other_id).unwrap().is_empty());
    }
}
