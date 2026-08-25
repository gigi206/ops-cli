//! Pinning `flake:` `[packages]` to a fixed revision for `sbx upgrade`.
//!
//! A `flake:<ref>` package is a remote reference, so it is built **host-side** into sbx's store
//! and seeded per project, the way a `nix:` tool is; only an inline `[flakes.<name>]` builds in
//! the cage. By default the ref *floats* — each cold launch resolves the flake's latest revision. `sbx upgrade flake` pins
//! it: it resolves each declared ref to its current immutable revision with `nix flake
//! metadata` and records `(declared ref → revision, locked ref)` in a per-project lock. A launch
//! then builds the *locked* ref rather than the declared one (`packages::realise`), host-side into
//! the shared store under the package's own project gcroot — so a lock change changes the build
//! target, the next launch builds the new revision and the gcroot moves to it, with no home
//! enumerated: the host-side lock rewrite is the whole roll. A package with no lock entry keeps the
//! floating behaviour, so a project that never runs `sbx upgrade flake` is unchanged.
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

/// A locked flake package: the immutable revision (40-hex, which keys the out-link) and the
/// immutable build reference (the locked URL plus any `#<attr>` from the declared ref) the
/// launch builds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FlakePin {
    pub(crate) rev: String,
    pub(crate) locked_ref: String,
}

/// A git revision: exactly 40 lowercase hex characters. Validated before a stored value flows
/// back into a flake reference or an on-disk path component. Lowercase-only, matching how nix and
/// `crate::store::valid_revision` spell a rev — an off-case value is a corrupt lock line, refused.
fn is_rev(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A locked reference is the metadata URL (plus optional `#<attr>`): non-empty, single-line, no
/// control characters or whitespace — so a corrupt lock line can never inject into the build.
fn is_locked_ref(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b > 0x20 && b != 0x7f)
}

/// The per-project flake lock path, beside the other per-project locks.
fn lock_path(layout: &Layout, project_id: &str) -> PathBuf {
    layout
        .data_dir()
        .join("projects")
        .join(project_id)
        .join(FLAKE_LOCK)
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
/// is absent or unreadable (the floating behaviour); a corrupt line self-heals by being dropped.
pub(crate) fn pins(layout: &Layout, project_id: &str) -> BTreeMap<String, FlakePin> {
    let mut entries = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(lock_path(layout, project_id)) {
        for line in text.lines() {
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
    }
    entries
}

/// The pinned revisions for a project's `flake:` packages, keyed by the declared reference —
/// which is byte-identical to a package's locator, so a caller can look each up directly. Reads
/// only the per-project lock, exactly as the launch path does, so surfacing a pin realises and
/// fetches nothing — the property `sbx config` relies on. Empty when the data dir or the project
/// identity is unavailable, or nothing is pinned (the floating state).
pub(crate) fn pinned_revs(cwd: &Path) -> BTreeMap<String, String> {
    let Some(layout) = store::Layout::from_env() else {
        return BTreeMap::new();
    };
    let Ok(id) = super::binds::project_runtime_id(cwd) else {
        return BTreeMap::new();
    };
    pins(&layout, &id)
        .into_iter()
        .map(|(declared, pin)| (declared, pin.rev))
        .collect()
}

/// Write the lock atomically (temp + rename), creating the owner-only parent — so a concurrent
/// launch reading it sees the old or the new file, never a torn one.
fn write_pins(
    layout: &Layout,
    project_id: &str,
    entries: &BTreeMap<String, FlakePin>,
) -> io::Result<()> {
    let path = lock_path(layout, project_id);
    if let Some(parent) = path.parent() {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut body = String::new();
    for (declared, pin) in entries {
        body.push_str(&format!("{declared}\t{}\t{}\n", pin.rev, pin.locked_ref));
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, body) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    std::fs::rename(&tmp, &path)
}

/// Resolve a declared `flake:` reference to its current immutable pin via `nix flake metadata`.
/// The flake (the part before `#`) is locked to a revision and an immutable URL; the output
/// attribute is reattached, so the result is the exact reference a launch builds. Uses sbx's
/// nix with the flakes feature, like the nixhub fetcher.
fn resolve(nix: &Path, layout: &Layout, reference: &str) -> io::Result<FlakePin> {
    let (base, attr) = split_attr(reference);
    let out = store::nix_command(nix, layout)
        .args(["--extra-experimental-features", "nix-command flakes"])
        .args(["flake", "metadata", base, "--json"])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "`nix flake metadata {base}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
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
    let locked_ref = match attr {
        Some(attr) => format!("{url}#{attr}"),
        None => url.to_string(),
    };
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

/// The two views `sbx upgrade flake` needs of a project's declared `flake:` references, collected
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
fn declared(cfg: &crate::config::Resolved) -> Declared {
    let mut seen = std::collections::BTreeSet::new();
    let mut trusted = Vec::new();
    let mut all = std::collections::BTreeSet::new();
    let mut absorb = |pkgs: &[crate::config::Package]| {
        for (_, reference) in super::packages::flake_packages(pkgs) {
            if seen.insert(reference.clone()) {
                trusted.push(reference);
            }
        }
        for p in pkgs {
            if let crate::config::Backend::Flake(reference) = &p.backend {
                all.insert(reference.clone());
            }
        }
    };
    absorb(&cfg.packages);
    for app in cfg.apps.values() {
        let mut merged = cfg.clone();
        merged.merge_app(app.clone());
        absorb(&merged.packages);
    }
    Declared { trusted, all }
}

/// How many declared `flake:` packages are withheld for being untrusted — across the project
/// baseline and each app's own overlay. A count only: the per-package withholding reason is
/// already warned on the launch path, so `sbx upgrade` just needs to not read as "none declared".
pub(crate) fn withheld(cfg: &crate::config::Resolved) -> usize {
    let untrusted_flake = |pkgs: &[crate::config::Package]| {
        pkgs.iter()
            .filter(|p| {
                matches!(p.backend, crate::config::Backend::Flake(_))
                    && p.state != crate::trust::TrustState::Trusted
            })
            .count()
    };
    untrusted_flake(&cfg.packages)
        + cfg
            .apps
            .values()
            .map(|app| untrusted_flake(&app.packages))
            .sum::<usize>()
}

/// Re-resolve a project's declared `flake:` references against their upstreams and rewrite the
/// per-project lock — pinning new ones, rolling changed ones forward, and pruning entries whose
/// reference is no longer declared (so a removed-then-readded package never reuses a stale pin).
/// References are collected generically by [`declared`]; resolution is best-effort per
/// reference (a failure keeps the prior pin and is reported), and the lock is rewritten once at
/// the end.
pub(crate) fn upgrade(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    cfg: &crate::config::Resolved,
) -> io::Result<Vec<FlakeUpgrade>> {
    let project_id = super::binds::project_runtime_id(project)?;
    let project_id = project_id.as_str();
    // One walk of the layers yields both the trusted roll set and the trust-agnostic prune universe.
    let Declared {
        trusted: declared,
        all: prune_universe,
    } = declared(cfg);
    let mut lock = pins(layout, project_id);
    let mut outcomes = Vec::new();

    // Prune entries whose reference is truly no longer declared — measured against ALL declared
    // refs regardless of trust, NOT the trusted-only roll set. A withheld (untrusted/Changed)
    // project's refs are absent from that set, so pruning against it would drop a still-declared
    // package's pin, silently unpinning it — a later re-trust would then float to the latest
    // upstream revision, exactly the movement the pin model forbids. Re-resolution below stays
    // trusted-only (over `declared`); pruning is state-agnostic.
    let stale: Vec<String> = lock
        .keys()
        .filter(|k| !prune_universe.contains(k.as_str()))
        .cloned()
        .collect();
    for reference in stale {
        lock.remove(&reference);
        outcomes.push(FlakeUpgrade::Pruned { reference });
    }

    for reference in &declared {
        let previous = lock.get(reference).map(|p| p.rev.clone());
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
                lock.insert(reference.clone(), pin);
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(FlakeUpgrade::Failed {
                reference: reference.clone(),
                error: e.to_string(),
                kept: previous,
            }),
        }
    }

    write_pins(layout, project_id, &lock)?;
    Ok(outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TmpDir, app_with, resolved};

    const REV: &str = "11707dc2f618dd54ca8739b309ec4fc024de578b";

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
        let refs = declared(&cfg).trusted;
        // Baseline first, then the app's new ref; the duplicate and the untrusted one are gone.
        assert_eq!(refs, vec!["github:o/a#default", "github:o/b#default"]);
    }

    #[test]
    fn the_prune_universe_keeps_untrusted_refs_so_upgrade_never_prunes_a_withheld_pin() {
        // The prune universe must NOT drop a still-declared ref just because the project is
        // untrusted — otherwise `sbx upgrade flake` on a Changed project unpins it and a later
        // re-trust floats to latest. Unlike the trusted roll set, `declared().all` keeps the ref.
        let cfg = resolved(
            vec![
                flake_pkg("a", "github:o/a#default", true),
                flake_pkg("evil", "github:o/evil#x", false), // untrusted: still in the universe
            ],
            vec![],
        );
        let universe = declared(&cfg).all;
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
        write_pins(&layout, "proj", &entries).unwrap();

        // A round trip preserves the pin.
        let read = pins(&layout, "proj");
        assert_eq!(
            read.get("github:o/r#default"),
            entries.get("github:o/r#default")
        );

        // A corrupt line (a non-rev second field) is dropped, the valid one kept.
        let path = lock_path(&layout, "proj");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("github:o/bad\tnot-a-rev\tref\n");
        std::fs::write(&path, text).unwrap();
        let read = pins(&layout, "proj");
        assert_eq!(read.len(), 1, "only the valid pin survives");
        assert!(read.contains_key("github:o/r#default"));
    }

    #[test]
    fn a_pin_is_keyed_by_the_real_project_runtime_id() {
        // `sbx upgrade flake` (the writer) and `sbx config`/launch (the readers, via `pinned_revs`)
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
        let read = pins(&layout, &id);
        assert_eq!(read.get(&reference).map(|p| p.rev.as_str()), Some(REV));

        // A different project sees nothing — the lock is project-scoped by the runtime id.
        assert!(pins(&layout, &other_id).is_empty());
    }
}
