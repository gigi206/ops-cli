//! Remote plugin stores: fetch, verify, and cache.
//!
//! A remote plugin store is a git repository whose root carries a signed `catalogue.toml`
//! (and a detached `catalogue.toml.sig`) plus the plugin directories the catalogue pins.
//! This module is the impure shell around [`crate::plugins::catalogue`]'s pure trust core: it
//! drives `git` to fetch a store, verifies the catalogue's Ed25519 signature against the
//! store's configured public key, and — only on success — caches the result under
//! `<data>/stores/<name>/`, where it is trusted by location (owner-only, a project cannot
//! write there).
//!
//! The fetch is **clone-always into a private staging tree, then an atomic swap**: a store
//! is cloned fresh, verified, and the whole staged directory is `rename`d into place in one
//! step. There is no in-place `git pull`, so there is no merge, dirty-tree, or partial-write
//! state to reason about — a failed or unverifiable fetch leaves any prior cache untouched
//! and places nothing. Authenticity rests entirely on the signature: git moves bytes and
//! checks their integrity, never their origin, so the transport is not a trust boundary.

use super::ensure_owner_only;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The file names a store repository must carry at its root.
const CATALOGUE: &str = "catalogue.toml";
const CATALOGUE_SIG: &str = "catalogue.toml.sig";

/// The bookkeeping a configured store's cache directory holds alongside its `checkout/`:
/// the origin and pinned trust anchor, and the highest catalogue revision yet accepted.
const STORE_TOML: &str = "store.toml";
const CATALOGUE_LOCK: &str = "catalogue.lock";
const CHECKOUT: &str = "checkout";

/// The public-key file a store repository carries at its root, read only by a trust-on-first-use
/// add (`--trust`) to learn the key it then pins. A pinned add (`--key`) ignores it entirely, and
/// `update` never reads it — the trust anchor is always the key recorded in `store.toml`.
const REPO_PUBKEY: &str = "pubkey";

/// The git attribute file a publish writes at the store root, disabling end-of-line conversion for
/// every file so the signed catalogue bytes survive a clone unchanged.
const GITATTRIBUTES: &str = ".gitattributes";

/// What a successful add cached: the store's name, the verified catalogue it now holds, the
/// public key that was pinned, and whether that key was accepted on first use — enough for the
/// command surface to report what was configured (and to warn on a TOFU pin) without re-reading
/// the cache.
#[derive(Debug)]
pub(crate) struct Added {
    pub(crate) name: String,
    pub(crate) catalogue: crate::plugins::catalogue::Catalogue,
    pub(crate) pubkey: [u8; 32],
    pub(crate) tofu: bool,
}

/// How an add — or a rotation — learns the key it pins: a key the user supplied out of band (the
/// strong form), or trust on first use, accepting the key the store ships and pinning it, verifying
/// the catalogue against that very key. TOFU has no first-fetch authenticity (a malicious author
/// controls both the key and the catalogue); its value is establishing the pin that every later
/// `update` then enforces.
pub(crate) enum TrustChoice {
    Pinned([u8; 32]),
    Tofu,
}

/// Configure a new remote plugin store and fetch it for the first time with a **pinned** key the
/// user supplied out of band. The repository is cloned, its catalogue verified against `pubkey`,
/// and the verified result cached under `<data>/stores/<name>/`.
pub(crate) fn add(
    layout: &crate::store::Layout,
    name: &str,
    url: &str,
    pubkey: [u8; 32],
    git: &Path,
) -> Result<Added, String> {
    add_inner(layout, name, url, TrustChoice::Pinned(pubkey), git)
}

/// Configure a new remote plugin store on **trust on first use**: clone it, read the public key it
/// ships, pin that key, and verify the catalogue against it. The pinned key is what every later
/// `update` enforces, so a subsequent re-key by the remote is refused — re-keying is the deliberate
/// `rm` + `add`. Weaker first-fetch trust than a pinned `add`; the caller is expected to surface the
/// pinned key for out-of-band verification.
pub(crate) fn add_tofu(
    layout: &crate::store::Layout,
    name: &str,
    url: &str,
    git: &Path,
) -> Result<Added, String> {
    add_inner(layout, name, url, TrustChoice::Tofu, git)
}

/// The shared body of [`add`] and [`add_tofu`]. Fail-closed and all-or-nothing — a bad name, an
/// already-configured store, an unreachable or malformed repository, a missing key (TOFU) or a
/// missing or invalid signature each refuse before anything is placed, and a failure removes the
/// staging tree so no partial store is ever left behind.
fn add_inner(
    layout: &crate::store::Layout,
    name: &str,
    url: &str,
    trust: TrustChoice,
    git: &Path,
) -> Result<Added, String> {
    // The name becomes a directory under the data dir, so it is held to the same safe
    // single-component rule as an installed plugin's name.
    crate::plugins::validate_install_name(name)?;
    validate_url(url)?;

    let dest = layout.store_path(name);
    if dest.exists() {
        return Err(format!(
            "a store named `{name}` is already configured — remove it first with \
             `sbx plugins store rm {name}`"
        ));
    }

    // The trust-by-location root must be owner-only before anything is placed under it.
    ensure_owner_only(layout.data_dir())?;

    // Stage the whole store directory (its checkout, config, and lock) in a private sibling
    // of the final location, so a crash or a concurrent add never leaves a half-built store
    // at the real name. The guard removes the stage on every exit path.
    let stage = Stage(layout.data_dir().join(format!(
        ".store-stage-{}-{}",
        std::process::id(),
        unique()
    )));
    let _ = std::fs::remove_dir_all(&stage.0);
    ensure_owner_only(&stage.0)?;

    let checkout = stage.0.join(CHECKOUT);
    clone(git, url, &checkout)?;

    // The key to verify against: the one the user pinned, or — on trust on first use — the one the
    // store ships, learned only now. Either way the catalogue must verify against it, so a TOFU pin
    // is still self-consistent (the catalogue is signed by the very key being pinned).
    let (pubkey, tofu) = match trust {
        TrustChoice::Pinned(k) => (k, false),
        TrustChoice::Tofu => (read_repo_pubkey(&checkout)?, true),
    };

    // Verify before trusting: read the catalogue and its detached signature, check the
    // signature against the key, and parse the *same* bytes. Only a verified catalogue is ever
    // cached, so a later read of the cache can trust it by location.
    let catalogue_bytes = read_file(&checkout.join(CATALOGUE))?;
    let signature = read_signature(&checkout.join(CATALOGUE_SIG))?;
    let catalogue =
        crate::plugins::catalogue::verified_catalogue(&catalogue_bytes, &signature, &pubkey)?;

    // The cached tree is a plain content tree, not a working git repository — drop the
    // `.git` directory so no git metadata (or hooks) sits in the trusted data dir; the next
    // update re-clones from scratch.
    let _ = std::fs::remove_dir_all(checkout.join(".git"));

    write_file(
        &stage.0.join(STORE_TOML),
        store_toml(url, &pubkey, tofu).as_bytes(),
    )?;
    write_file(
        &stage.0.join(CATALOGUE_LOCK),
        format!("{}\n", catalogue.rev).as_bytes(),
    )?;

    ensure_owner_only(&layout.stores_dir())?;
    match std::fs::rename(&stage.0, &dest) {
        Ok(()) => Ok(Added {
            name: name.to_string(),
            catalogue,
            pubkey,
            tofu,
        }),
        Err(e) => {
            // A non-empty destination means a store of that name appeared between the check
            // and the rename — refuse rather than overwrite. The stage guard cleans up.
            if dest.exists() {
                Err(format!(
                    "a store named `{name}` appeared concurrently — remove it first with \
                     `sbx plugins store rm {name}`"
                ))
            } else {
                Err(format!("could not place the store cache: {e}"))
            }
        }
    }
}

/// Read the public key a store repository ships at its root (`pubkey`, hex-encoded) — the key a
/// trust-on-first-use add pins. A store that ships none cannot be trusted on first use: refuse and
/// point at the pinned `--key` alternative.
///
/// Through [`read_store_file`], like the catalogue and the signature. This is a root file of a
/// freshly cloned, entirely untrusted repository, and it is read **earlier than either of them** —
/// before any signature exists to check — so it is the read that most needs the guard, not the one
/// that can do without it. A plain `read_to_string` followed the leaf symlink and had no ceiling: a
/// `pubkey -> /dev/zero` in a store repository read until the host ran out of memory, and a
/// `pubkey -> /dev/urandom` never returned at all.
fn read_repo_pubkey(checkout: &Path) -> Result<[u8; 32], String> {
    let bytes = read_store_file(
        &checkout.join(REPO_PUBKEY),
        REPO_PUBKEY,
        &format!(
            "this store ships no `{REPO_PUBKEY}` file, so there is no key to trust on first use — \
             supply `--key <hex|@file>` to pin a key you obtained out of band"
        ),
    )?;
    let hex = String::from_utf8(bytes)
        .map_err(|_| format!("the store's `{REPO_PUBKEY}` is not valid text"))?;
    decode_key(&hex)
}

/// What [`verify_key`] found. The supplied key matched in both cases — a mismatch is an error, not
/// a variant — and they differ only in whether that clears a standing caution: a key accepted on
/// first use is now confirmed and its record says so, or it had been supplied out of band all
/// along and there was nothing left to record.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verified {
    /// The supplied key matched the pinned one, which is no longer marked as merely accepted.
    Confirmed,
    /// The supplied key matched, and the store was already configured from a key the user supplied
    /// — there was no standing caution to clear, so nothing was written. An idempotent no-op, not a
    /// skipped comparison: a key that does not match is refused whichever way the store was pinned.
    AlreadyPinned,
}

/// Confirm a store's pinned key against one the user obtained elsewhere, closing the open end of
/// trust-on-first-use: the key was accepted from the store itself, and only a second source can say
/// it is the author's.
///
/// This changes **no** enforcement — the pinned key is unchanged, and a fetch already verifies the
/// catalogue against it either way. It records that the key has been confirmed, so the standing
/// caution stops being shown. That matters because a caution with no way out is one a user learns
/// to ignore.
///
/// A mismatch is refused loudly and changes nothing: the store is not the one the supplied key
/// belongs to. No fetch and no network — only the owner-only cache is read and rewritten.
///
/// The comparison comes **before** the idempotence check, and the order is the whole command. A
/// key supplied out of band at `add` time is not thereby the right key: the usual way to end up
/// pinned to an attacker's key is to have pasted it from a page the attacker controls, and this is
/// the one command that exists to catch that. Returning early on a pinned store would answer
/// `verified`, with exit 0, to a key nothing had looked at — so `AlreadyPinned` means "it matched,
/// and there was no standing caution left to clear", never "I did not look".
pub(crate) fn verify_key(
    layout: &crate::store::Layout,
    name: &str,
    supplied: [u8; 32],
) -> Result<Verified, String> {
    let cfg = read_configured(layout, name)?;
    if cfg.pubkey != supplied {
        return Err(format!(
            "the key pinned for store `{name}` is not the one you supplied — this store is not \
             the one that key belongs to, and nothing was changed\n  pinned:   {}\n  \
             supplied: {}",
            crate::plugins::catalogue::to_hex(&cfg.pubkey),
            crate::plugins::catalogue::to_hex(&supplied)
        ));
    }
    if !cfg.tofu {
        return Ok(Verified::AlreadyPinned);
    }

    // `store.toml` carries the trust anchor: a partial write would leave the store unreadable
    // (a missing or malformed one is a hard failure, deliberately). Write a private temp file and
    // rename over it, so a reader sees the old record or the new one and never a torn file.
    let dir = layout.store_path(name);
    let tmp = dir.join(format!(".store-toml-{}-{}", std::process::id(), unique()));
    let _ = std::fs::remove_file(&tmp);
    write_file(&tmp, store_toml(&cfg.url, &cfg.pubkey, false).as_bytes())?;
    if let Err(e) = std::fs::rename(&tmp, dir.join(STORE_TOML)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("cannot record the confirmation: {e}"));
    }
    Ok(Verified::Confirmed)
}

/// The public key a store repository ships, fetched and then thrown away — what `store add`
/// reports when no trust anchor was supplied, so the user can see the key *before* deciding what
/// to do with it rather than after pinning it.
///
/// No store is configured and the fetch does not persist: the clone lands in a private staging
/// directory the guard removes on every exit path, and no `store.toml` is written. The data
/// directory itself is created if missing, as it is by any verb that stages under it. Reading a key
/// this way proves nothing about the store — whoever controls the URL controls the key it ships —
/// so this is a display aid for a decision the user still has to make, never a trust decision.
pub(crate) fn shipped_pubkey(
    layout: &crate::store::Layout,
    url: &str,
    git: &Path,
) -> Result<[u8; 32], String> {
    validate_url(url)?;
    ensure_owner_only(layout.data_dir())?;
    let stage = Stage(layout.data_dir().join(format!(
        ".store-probe-{}-{}",
        std::process::id(),
        unique()
    )));
    let _ = std::fs::remove_dir_all(&stage.0);
    ensure_owner_only(&stage.0)?;
    let checkout = stage.0.join(CHECKOUT);
    clone(git, url, &checkout)?;
    read_repo_pubkey(&checkout)
}

/// What a successful publish produced: the public key the catalogue is now signed with (to be
/// distributed and pinned by consumers), the revision stamped, and the plugins listed.
#[derive(Debug)]
pub(crate) struct Published {
    pub(crate) pubkey: [u8; 32],
    pub(crate) rev: u64,
    pub(crate) plugins: Vec<(String, String)>,
}

/// Sign a directory of resolver plugins into a store: produce the `catalogue.toml` (pinning each
/// plugin by the digest of its own subdirectory), a detached `catalogue.toml.sig`, the store's
/// `pubkey`, and a `.gitattributes` that keeps the signed bytes byte-exact across a clone. The
/// operator then commits and hosts the result; sbx does not touch git here. The producing
/// counterpart of [`add`]: it builds exactly what `add`/`update`/`install` later verify, reusing
/// the very digest function the verifier reproduces so the two can never drift.
pub(crate) fn publish(dir: &Path, key_path: &Path, rev: Option<u64>) -> Result<Published, String> {
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("cannot access `{}`: {e}", dir.display()))?;
    let plugins_dir = dir.join("plugins");
    if !plugins_dir.is_dir() {
        return Err(format!(
            "`{}` has no `plugins/` directory — a store repository holds its plugins under \
             `plugins/`",
            dir.display()
        ));
    }

    // Validate the tree exactly as a consumer's registry will, so a published store lists only
    // installable plugins. `load` reports a malformed manifest or an ambiguous scheme as a
    // warning and drops the plugin; for a deliberate publish that is a hard refusal, not a
    // silent omission.
    let mut warnings = Vec::new();
    let registry = crate::plugins::PluginRegistry::load(&plugins_dir, &mut warnings);
    if !warnings.is_empty() {
        return Err(format!(
            "refusing to publish — the plugins tree has problems:\n  {}",
            warnings.join("\n  ")
        ));
    }
    // `load` skips a directory with no `plugin.toml` silently; for a publish that is almost always
    // a mistake (a renamed or half-added plugin), so name the offenders rather than drop them.
    let skipped = subdirs_without_manifest(&plugins_dir)?;
    if !skipped.is_empty() {
        return Err(format!(
            "refusing to publish — these directories under `plugins/` have no `plugin.toml`: {} \
             (remove them or add a manifest)",
            skipped.join(", ")
        ));
    }
    // Every kind is published from one tree and one key. The store is not the boundary any of them
    // is fenced by — installing a broker grants nothing until a global `[broker.<name>] socket`
    // binds it to a host resource, and installing a signer grants nothing until a `[[secret]]`
    // names it — so a second store would add a trust ritual where nothing is decided, and a second
    // catalogue to keep in step for no property gained.
    struct Listed<'a> {
        name: &'a str,
        dir: &'a Path,
        exec: &'a Path,
        kind: crate::plugins::PluginKind,
        scheme: Option<String>,
        version: Option<&'a String>,
        description: Option<&'a String>,
    }
    let listed: Vec<Listed<'_>> = registry
        .resolvers()
        .map(|p| Listed {
            name: &p.name,
            dir: &p.dir,
            exec: &p.exec,
            kind: crate::plugins::PluginKind::Resolver,
            scheme: Some(p.scheme.clone()),
            version: p.version.as_ref(),
            description: p.description.as_ref(),
        })
        .chain(registry.brokers().map(|p| Listed {
            name: &p.name,
            dir: &p.dir,
            exec: &p.exec,
            kind: crate::plugins::PluginKind::Broker,
            scheme: None,
            version: p.version.as_ref(),
            description: p.description.as_ref(),
        }))
        .chain(registry.signers().map(|p| Listed {
            name: &p.name,
            dir: &p.dir,
            exec: &p.exec,
            kind: crate::plugins::PluginKind::Signer,
            scheme: None,
            version: p.version.as_ref(),
            description: p.description.as_ref(),
        }))
        .collect();
    if listed.is_empty() {
        return Err("refusing to publish — no plugins found under `plugins/`".to_string());
    }

    // Build the catalogue: each plugin pinned by the digest of its own subdirectory (`dir_digest`,
    // the exact function a consumer reproduces at install time).
    let mut entries: std::collections::BTreeMap<String, crate::plugins::catalogue::CatalogueEntry> =
        std::collections::BTreeMap::new();
    let mut listing = Vec::new();
    for p in &listed {
        // The name becomes the catalogue key and, on a consumer, the install directory. The loader
        // does not constrain a manifest's `name`, so hold it here to the installer's safe
        // single-component rule — named at its source rather than surfaced only as a downstream
        // parse failure of the catalogue we are about to write.
        crate::plugins::validate_install_name(p.name)
            .map_err(|e| format!("plugin in `{}`: {e}", p.dir.display()))?;
        if !p.exec.is_file() {
            return Err(format!(
                "plugin `{}` names an executable that is not a regular file: {}",
                p.name,
                p.exec.display()
            ));
        }
        let rel = p
            .dir
            .strip_prefix(&dir)
            .map_err(|_| format!("plugin `{}` is not under `{}`", p.name, dir.display()))?;
        let path = rel
            .to_str()
            .ok_or_else(|| format!("plugin `{}` has a non-UTF-8 path", p.name))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        let sha256 =
            crate::plugins::catalogue::to_hex(&crate::plugins::catalogue::dir_digest(p.dir)?);
        // The catalogue is keyed by the manifest `name`, so two plugins declaring one name would
        // collapse to whichever the iteration reaches last while the confirmation below still
        // listed both — a store that publishes one tree under the name of another, past every
        // signature and digest check. The loader refuses that *within* a namespace (two brokers,
        // two signers), but a resolver is indexed by its scheme and a broker or signer by its name,
        // so a resolver and a signer sharing a name reach here unremarked. The key is formed here,
        // so it is checked here; and brokers and signers are chained after the resolvers, which
        // makes which of the two survives the collision the attacker's to choose.
        if let Some(previous) = entries.get(p.name) {
            return Err(format!(
                "refusing to publish — `{}` and `{path}` both declare `name = \"{}\"`, and a \
                 catalogue entry is keyed by that name, so only one of them would be published \
                 (give one of them a different `name`)",
                previous.path, p.name
            ));
        }
        // What the publish confirmation shows, spelled here rather than by the renderer: a resolver
        // by the namespace it answers for, `scheme://` and all, and a broker by its type — it has
        // no namespace to name, and a `broker://` would read as one it claimed.
        listing.push((
            p.name.to_string(),
            match &p.scheme {
                Some(scheme) => format!("{scheme}://"),
                None => p.kind.token().to_string(),
            },
        ));
        entries.insert(
            p.name.to_string(),
            crate::plugins::catalogue::CatalogueEntry {
                kind: p.kind,
                scheme: p.scheme.clone(),
                version: p.version.cloned().unwrap_or_default(),
                description: p.description.cloned().unwrap_or_default(),
                path,
                sha256,
            },
        );
    }

    let rev = match rev {
        Some(r) => r,
        None => next_rev(&dir)?,
    };
    let catalogue = crate::plugins::catalogue::Catalogue {
        rev,
        plugins: entries,
    };
    let bytes = crate::plugins::catalogue::serialize_catalogue(&catalogue)?;

    // The bytes we are about to sign must parse back to the very catalogue we built, so a publish
    // never emits a listing our own verifier would reject.
    let reparsed = crate::plugins::catalogue::Catalogue::parse(bytes.as_bytes())
        .map_err(|e| format!("internal error: produced an unparseable catalogue: {e}"))?;
    if reparsed != catalogue {
        return Err(
            "internal error: the catalogue did not round-trip through serialization".to_string(),
        );
    }

    // The signing key: reuse an existing one (so a consumer's pinned key keeps verifying across
    // publishes) or generate and persist a fresh one. A present-but-corrupt key is a hard error,
    // never silently replaced — replacing it would re-key the store and break every consumer's pin.
    let keypair = load_or_generate_key(key_path)?;
    let pubkey: [u8; 32] = keypair
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| "the signing key produced a public key of the wrong length".to_string())?;
    let signature = keypair.sign(bytes.as_bytes());

    // The four store-root artifacts, overwriting any from a prior publish. These are the operator's
    // repository files (to be committed), not sbx's owner-only cache, so a plain write is correct.
    overwrite(&dir.join(CATALOGUE), bytes.as_bytes())?;
    overwrite(
        &dir.join(CATALOGUE_SIG),
        format!(
            "{}\n",
            crate::plugins::catalogue::to_hex(signature.as_ref())
        )
        .as_bytes(),
    )?;
    overwrite(
        &dir.join(REPO_PUBKEY),
        crate::plugins::catalogue::to_hex(&pubkey).as_bytes(),
    )?;
    // git must deliver the signed bytes verbatim: `* -text` disables end-of-line conversion so the
    // catalogue a consumer clones is byte-identical to the one signed here. (sbx's own fetch also
    // nulls git's config, neutralizing this verifier-side; the attribute protects other clients.)
    overwrite(&dir.join(GITATTRIBUTES), b"* -text\n")?;

    listing.sort();
    Ok(Published {
        pubkey,
        rev,
        plugins: listing,
    })
}

/// Directories directly under `plugins/` that carry no `plugin.toml`, sorted — the ones `load`
/// would skip silently, surfaced so a publish can refuse a typo'd or half-added plugin.
fn subdirs_without_manifest(plugins_dir: &Path) -> Result<Vec<String>, String> {
    let mut bad = Vec::new();
    let rd = std::fs::read_dir(plugins_dir)
        .map_err(|e| format!("cannot read `{}`: {e}", plugins_dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("cannot read `{}`: {e}", plugins_dir.display()))?;
        // `file_type` does not follow a symlink, so a symlinked entry is not treated as a plugin
        // directory here; a symlinked dir the registry does load is refused later by `dir_digest`.
        let ft = entry
            .file_type()
            .map_err(|e| format!("cannot stat `{}`: {e}", entry.path().display()))?;
        if ft.is_dir() && !entry.path().join("plugin.toml").is_file() {
            bad.push(entry.file_name().to_str().unwrap_or("?").to_string());
        }
    }
    bad.sort();
    Ok(bad)
}

/// The revision to stamp when none is given: one past the existing catalogue's, or 1 for a first
/// publish. A present-but-unparseable catalogue is an error (a silent default could roll the store
/// backwards and a consumer's anti-rollback would then refuse the update).
fn next_rev(dir: &Path) -> Result<u64, String> {
    match std::fs::read(dir.join(CATALOGUE)) {
        Ok(bytes) => {
            let existing = crate::plugins::catalogue::Catalogue::parse(&bytes).map_err(|e| {
                format!(
                    "cannot determine the next revision: the existing `{CATALOGUE}` does not parse \
                     ({e}) — pass an explicit `--rev`"
                )
            })?;
            existing
                .rev
                .checked_add(1)
                .ok_or_else(|| "the catalogue revision is at its maximum".to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(1),
        Err(e) => Err(format!("cannot read the existing `{CATALOGUE}`: {e}")),
    }
}

/// Reuse the Ed25519 signing key at `path`, or generate and persist a fresh one if the file does
/// not exist. The three cases are distinct on purpose: a valid key is reused (so the store keeps
/// its identity across publishes), an absent one is created owner-only, and a present-but-invalid
/// one is a hard error — never regenerated, because silently re-keying would invalidate every
/// consumer's pinned key.
fn load_or_generate_key(path: &Path) -> Result<Ed25519KeyPair, String> {
    match std::fs::read(path) {
        Ok(pkcs8) => Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| {
            format!(
                "the signing key `{}` is not a valid Ed25519 PKCS#8 key — refusing to overwrite \
                 it (move it aside to start a new key)",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| "could not generate a signing key".to_string())?;
            write_private_key(path, pkcs8.as_ref())?;
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .map_err(|_| "could not load the freshly generated signing key".to_string())
        }
        Err(e) => Err(format!(
            "cannot read the signing key `{}`: {e}",
            path.display()
        )),
    }
}

/// Write a freshly generated private key owner-only, refusing to clobber an existing file (so a
/// race that creates the key between the read and the write never overwrites it).
fn write_private_key(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create the signing key `{}`: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write the signing key `{}`: {e}", path.display()))
}

/// Write (or overwrite) one of the operator's store-repository files. Unlike the owner-only cache
/// writer, these are public files destined for git, so a plain overwrite is correct.
fn overwrite(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// A configured remote store as recorded in its owner-only cache: where it is fetched from,
/// the public key its catalogue must verify against (the trust anchor, pinned at add time),
/// the highest catalogue revision yet accepted (the rollback floor), and whether the key was
/// accepted on first use (informational — once pinned, `update` enforces it identically either
/// way).
#[derive(Debug)]
pub(crate) struct Configured {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) pubkey: [u8; 32],
    pub(crate) locked_rev: u64,
    pub(crate) tofu: bool,
}

#[derive(serde::Deserialize)]
struct RawStoreToml {
    url: String,
    pubkey: String,
    /// How the key was first trusted: `"tofu"` or `"pinned"`. Optional and defaulted so a store
    /// configured before this field existed still parses (absent ⇒ a pinned key, the strong form).
    #[serde(default)]
    trust: Option<String>,
}

/// Read a configured store's origin, pinned key, and accepted revision from its cache. The
/// cache is trusted by location (owner-only under the data dir), so this does not re-verify a
/// signature — but the two bookkeeping files degrade oppositely and deliberately. `store.toml`
/// holds the trust anchor (the pinned public key): a missing or malformed one is a **hard
/// failure**, because there is no key to fall back to. `catalogue.lock` holds only the rollback
/// floor: a missing or malformed one degrades to `0` (the weakest floor), which is safe —
/// anyone able to corrupt the lock could rewrite the whole owner-only cache, so the floor is
/// not itself a trust boundary.
pub(crate) fn read_configured(
    layout: &crate::store::Layout,
    name: &str,
) -> Result<Configured, String> {
    crate::plugins::validate_install_name(name)?;
    let dir = layout.store_path(name);
    if !dir.exists() {
        return Err(format!("no store named `{name}` is configured"));
    }

    let toml_bytes = std::fs::read(dir.join(STORE_TOML))
        .map_err(|e| format!("cannot read the configuration of store `{name}`: {e}"))?;
    let text = std::str::from_utf8(&toml_bytes)
        .map_err(|_| format!("the configuration of store `{name}` is not valid UTF-8"))?;
    let raw: RawStoreToml = toml::from_str(text)
        .map_err(|e| format!("the configuration of store `{name}` is malformed: {e}"))?;
    let pubkey = decode_key(&raw.pubkey)
        .map_err(|e| format!("the configuration of store `{name}` has an invalid key: {e}"))?;

    // The floor is best-effort: a missing or unparsable lock means "no floor yet" (0), never an
    // error, so a legacy or truncated lock cannot wedge a store.
    let locked_rev = std::fs::read_to_string(dir.join(CATALOGUE_LOCK))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    // Informational only: any value other than `"tofu"` (including absent or unknown) reads as a
    // pinned key — the safe default, since this never gates verification.
    let tofu = raw.trust.as_deref() == Some("tofu");

    Ok(Configured {
        name: name.to_string(),
        url: raw.url,
        pubkey,
        locked_rev,
        tofu,
    })
}

/// The names of every configured remote store, sorted. Non-directories and dot-prefixed
/// bookkeeping entries (a staging tree never fully swapped in) are skipped; a missing stores
/// directory simply means none is configured.
pub(crate) fn list(layout: &crate::store::Layout) -> Vec<String> {
    let mut names: Vec<String> = match std::fs::read_dir(layout.stores_dir()) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.starts_with('.'))
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

/// Parse the cached catalogue of a configured store, trusting it by location: it was
/// signature-verified before it was written into this owner-only cache, so a read re-checks
/// only its structure, not the signature.
pub(crate) fn cached_catalogue(
    layout: &crate::store::Layout,
    name: &str,
) -> Result<crate::plugins::catalogue::Catalogue, String> {
    crate::plugins::validate_install_name(name)?;
    let path = layout.store_path(name).join(CHECKOUT).join(CATALOGUE);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read the cached catalogue of store `{name}`: {e}"))?;
    crate::plugins::catalogue::Catalogue::parse(&bytes)
}

/// Install a resolver plugin from a configured store by name, gated by the catalogue's per-plugin
/// content hash. The store's cached catalogue is trusted by location — its signature was verified
/// when the store was added or updated — so this reads it without re-verifying the signature; the
/// install-time gate is instead the content hash, which pins the plugin's directory to exactly what
/// the signed catalogue listed. On a match the verified directory is handed to
/// [`crate::plugins::install_from_store`], which reconciles the catalogue's advertised name and
/// scheme against the plugin's manifest and places it exactly as a local install would. Fail-closed:
/// an unconfigured store, an unlisted plugin, a missing or content-mismatched directory each refuse
/// before anything is installed. No fetch and no network — only the owner-only cache is read.
pub(crate) fn install_plugin(
    layout: &crate::store::Layout,
    store_name: &str,
    plugin_name: &str,
) -> Result<crate::plugins::Installed, String> {
    place_plugin(layout, store_name, plugin_name, false)
}

/// Replace an installed plugin with what the store's catalogue lists now — `sbx plugins upgrade`.
/// Every gate an install runs is run again here (the checkout must be a real directory, its content
/// must reproduce the signed `sha256`, and its manifest must agree with the catalogue's advertised
/// name and scheme), because an upgrade installs code exactly as an install does. The only
/// difference is that the name being taken is the point rather than a refusal — and the swap keeps
/// the installed plugin until the new one is in place.
pub(crate) fn upgrade_plugin(
    layout: &crate::store::Layout,
    store_name: &str,
    plugin_name: &str,
) -> Result<crate::plugins::Installed, String> {
    place_plugin(layout, store_name, plugin_name, true)
}

/// The shared body: verify a store's listed plugin and place it, replacing an existing one or not.
fn place_plugin(
    layout: &crate::store::Layout,
    store_name: &str,
    plugin_name: &str,
    replace: bool,
) -> Result<crate::plugins::Installed, String> {
    crate::plugins::validate_install_name(store_name)?;
    if !layout.store_path(store_name).exists() {
        return Err(format!(
            "no store named `{store_name}` is configured \
             (configure one with `sbx plugins store add`)"
        ));
    }

    let catalogue = cached_catalogue(layout, store_name)?;
    let entry = catalogue.plugins.get(plugin_name).ok_or_else(|| {
        format!(
            "store `{store_name}` lists no plugin named `{plugin_name}` \
             (see `sbx plugins store info {store_name}`)"
        )
    })?;

    // The catalogue's `path` is validated repo-relative (no `..`, no absolute part) when the
    // catalogue is parsed, so this join stays inside the store's checkout.
    let plugin_dir = layout
        .store_path(store_name)
        .join(CHECKOUT)
        .join(&entry.path);
    // A real directory — `symlink_metadata` does not follow, so a symlinked checkout entry reads as
    // "not a directory" and is refused here (and `verify_entry`/`dir_digest` refuse a symlink root
    // too, as the load-bearing backstop). An *intermediate* symlink within `entry.path` (e.g. a
    // symlinked `plugins/`) is not checked component-by-component, but it stays fail-closed via the
    // content gate: git cannot commit files *under* a symlinked directory, so a clone resolves such a
    // path to an attacker-uncontrolled location whose digest cannot match the pinned `sha256`.
    let is_real_dir = std::fs::symlink_metadata(&plugin_dir)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !is_real_dir {
        return Err(format!(
            "store `{store_name}` lists plugin `{plugin_name}` at `{}`, but that directory is not \
             in the cached checkout — try `sbx plugins store update {store_name}`",
            entry.path
        ));
    }

    // The content gate: the directory must reproduce the digest the signed catalogue pinned, so the
    // bytes about to be installed are exactly what was listed and signed.
    crate::plugins::catalogue::verify_entry(entry, &plugin_dir)?;

    // The store's URL is carried into the record so a later listing still names where the plugin
    // came from after the store itself is removed; a store whose configuration cannot be read is
    // no reason to refuse an install whose content gate has already passed.
    let url = read_configured(layout, store_name).ok().map(|c| c.url);
    let origin = crate::plugins::origin::Origin::Store {
        store: store_name.to_string(),
        url,
        sha256: Some(entry.sha256.clone()),
    };
    if replace {
        crate::plugins::replace_from_store(
            layout,
            &plugin_dir,
            crate::plugins::StoreClaim {
                name: plugin_name,
                kind: entry.kind,
                scheme: entry.scheme.as_deref(),
            },
            origin,
        )
    } else {
        crate::plugins::install_from_store(
            layout,
            &plugin_dir,
            crate::plugins::StoreClaim {
                name: plugin_name,
                kind: entry.kind,
                scheme: entry.scheme.as_deref(),
            },
            origin,
        )
    }
}

/// What a successful [`rekey`] replaced: the key that was pinned, the one now pinned, and how the
/// new one was obtained — so the report can be as explicit as the act deserves.
#[derive(Debug)]
pub(crate) struct Rekeyed {
    pub(crate) name: String,
    pub(crate) old_pubkey: [u8; 32],
    pub(crate) new_pubkey: [u8; 32],
    pub(crate) tofu: bool,
    pub(crate) rev: u64,
    pub(crate) catalogue: crate::plugins::catalogue::Catalogue,
}

/// Replace the key pinned for a configured store, for the case a store legitimately rotates its
/// signing key — which `update` otherwise refuses, correctly and permanently.
///
/// It is a **separate verb on purpose**: an existing `update` in a script must never start
/// accepting a new signing identity because a repository decided to ship one. The caller is
/// responsible for the warning and the confirmation; this performs the exchange, and only when the
/// new key actually verifies the fetched catalogue.
///
/// The rollback floor is carried over: a new key does not reopen the door to a superseded
/// catalogue. A key identical to the pinned one is refused — nothing would rotate, and treating it
/// as a success would hide whatever else made `update` fail.
pub(crate) fn rekey(
    layout: &crate::store::Layout,
    name: &str,
    trust: TrustChoice,
    git: &Path,
) -> Result<Rekeyed, String> {
    let cfg = read_configured(layout, name)?;

    ensure_owner_only(layout.data_dir())?;
    let stage = Stage(layout.data_dir().join(format!(
        ".store-stage-{}-{}",
        std::process::id(),
        unique()
    )));
    let _ = std::fs::remove_dir_all(&stage.0);
    ensure_owner_only(&stage.0)?;
    let checkout = stage.0.join(CHECKOUT);
    clone(git, &cfg.url, &checkout)?;

    let (pubkey, tofu) = match trust {
        TrustChoice::Pinned(k) => (k, false),
        TrustChoice::Tofu => (read_repo_pubkey(&checkout)?, true),
    };
    if pubkey == cfg.pubkey {
        return Err(format!(
            "store `{name}` is already pinned to that key — nothing to rotate"
        ));
    }

    // The new key must actually verify what the store now serves; otherwise the rotation would
    // leave a store pinned to a key that signs nothing it holds.
    let catalogue_bytes = read_file(&checkout.join(CATALOGUE))?;
    let signature = read_signature(&checkout.join(CATALOGUE_SIG))?;
    let catalogue =
        crate::plugins::catalogue::verified_catalogue(&catalogue_bytes, &signature, &pubkey)
            .map_err(|why| {
                format!("{why} — the key you supplied does not sign this store's catalogue")
            })?;
    if catalogue.rev < cfg.locked_rev {
        return Err(format!(
            "refusing to roll back store `{name}`: the fetched catalogue is revision {} but \
             revision {} was already accepted",
            catalogue.rev, cfg.locked_rev
        ));
    }

    let _ = std::fs::remove_dir_all(checkout.join(".git"));
    write_file(
        &stage.0.join(STORE_TOML),
        store_toml(&cfg.url, &pubkey, tofu).as_bytes(),
    )?;
    write_file(
        &stage.0.join(CATALOGUE_LOCK),
        format!("{}\n", catalogue.rev).as_bytes(),
    )?;
    swap_into_place(&stage.0, &layout.store_path(name))?;

    Ok(Rekeyed {
        name: name.to_string(),
        old_pubkey: cfg.pubkey,
        new_pubkey: pubkey,
        tofu,
        rev: catalogue.rev,
        catalogue,
    })
}

/// What a successful [`update`] changed: a revision moves forward only, so the report names the
/// old and new floor and carries the freshly verified catalogue.
#[derive(Debug)]
pub(crate) struct Updated {
    pub(crate) name: String,
    pub(crate) old_rev: u64,
    pub(crate) new_rev: u64,
    pub(crate) catalogue: crate::plugins::catalogue::Catalogue,
}

/// Re-fetch a configured store and atomically replace its cache, enforcing two invariants the
/// transport cannot. The catalogue must still verify against the **pinned** public key — read
/// from the cache, never supplied anew — so a compromised remote cannot rotate the key out from
/// under the user; re-keying a store is the deliberate `rm` + `add`. And the catalogue's
/// revision must not regress below the highest already accepted, so a validly-signed but
/// withdrawn or downgraded listing cannot be replayed. Fail-closed and all-or-nothing: any
/// failure leaves the existing cache exactly as it was.
pub(crate) fn update(
    layout: &crate::store::Layout,
    name: &str,
    git: &Path,
) -> Result<Updated, String> {
    let cfg = read_configured(layout, name)?;

    ensure_owner_only(layout.data_dir())?;
    let stage = Stage(layout.data_dir().join(format!(
        ".store-stage-{}-{}",
        std::process::id(),
        unique()
    )));
    let _ = std::fs::remove_dir_all(&stage.0);
    ensure_owner_only(&stage.0)?;

    let checkout = stage.0.join(CHECKOUT);
    clone(git, &cfg.url, &checkout)?;

    // Verify against the pinned key, then enforce the rollback floor — in that order, so a
    // fetch signed by the wrong key is refused before its `rev` is even consulted.
    let catalogue_bytes = read_file(&checkout.join(CATALOGUE))?;
    let signature = read_signature(&checkout.join(CATALOGUE_SIG))?;
    let catalogue = crate::plugins::catalogue::verified_catalogue(
        &catalogue_bytes,
        &signature,
        &cfg.pubkey,
    )
    .map_err(|why| {
        // The verifier is deliberately an opaque "it did not verify" (no oracle). But the single
        // likeliest cause is one this side *can* name without weakening that: the store now ships a
        // different key than the one pinned. Saying so turns an unactionable failure into a
        // decision — a rotation the author announced, or a store that is no longer the same one.
        match read_repo_pubkey(&checkout) {
            Ok(shipped) if shipped != cfg.pubkey => format!(
                "the catalogue is no longer signed by the key pinned for store `{name}` — the \
                 key this store ships has CHANGED\n  pinned: {}\n  now:    {}\n  an \
                 announced rotation is legitimate; an unannounced one is what a takeover looks \
                 like. Confirm the new key from a source this store does not control, then:\n    \
                 sbx plugins store rekey {name} --key <the new key you obtained>",
                crate::plugins::catalogue::to_hex(&cfg.pubkey),
                crate::plugins::catalogue::to_hex(&shipped)
            ),
            _ => why,
        }
    })?;

    if catalogue.rev < cfg.locked_rev {
        return Err(format!(
            "refusing to roll back store `{name}`: the fetched catalogue is revision {} but \
             revision {} was already accepted",
            catalogue.rev, cfg.locked_rev
        ));
    }

    let _ = std::fs::remove_dir_all(checkout.join(".git"));
    write_file(
        &stage.0.join(STORE_TOML),
        store_toml(&cfg.url, &cfg.pubkey, cfg.tofu).as_bytes(),
    )?;
    write_file(
        &stage.0.join(CATALOGUE_LOCK),
        format!("{}\n", catalogue.rev).as_bytes(),
    )?;

    // The store is already configured, so the cache directory exists: exchange the staged tree
    // with it atomically. After the swap the old tree sits at the stage path, where the guard
    // removes it.
    swap_into_place(&stage.0, &layout.store_path(name))?;

    Ok(Updated {
        name: name.to_string(),
        old_rev: cfg.locked_rev,
        new_rev: catalogue.rev,
        catalogue,
    })
}

/// Remove a configured store from the cache, deleting its whole directory. A name that is not
/// configured is a clear error rather than a silent success.
///
/// The directory is renamed aside first (an atomic step), then the renamed tree is deleted — so a
/// concurrent reader sees the store either fully present or fully gone, never the half-deleted tree
/// an in-place `remove_dir_all` would leave if it failed partway.
pub(crate) fn remove(layout: &crate::store::Layout, name: &str) -> Result<(), String> {
    crate::plugins::validate_install_name(name)?;
    let dir = layout.store_path(name);
    if !dir.exists() {
        return Err(format!("no store named `{name}` is configured"));
    }
    let tomb = dir.with_file_name(format!(".{name}.removing.{}", std::process::id()));
    std::fs::rename(&dir, &tomb).map_err(|e| format!("cannot remove store `{name}`: {e}"))?;
    // The store is already gone from its real path; a failure to delete the renamed tree only
    // leaves a collectable leftover, not a torn store.
    let _ = std::fs::remove_dir_all(&tomb);
    Ok(())
}

/// Atomically replace the live store directory `dest` with the freshly staged `stage` by
/// exchanging the two in a single `renameat2(RENAME_EXCHANGE)`: after it returns, `dest` holds
/// the new tree and `stage` holds the old one (which the staging guard then removes). There is
/// no window in which `dest` is absent or half-built, and it is the only placement path, so it
/// is fully testable. A filesystem that cannot exchange atomically is a hard, named failure —
/// never a silent non-atomic dance that could tear a trusted cache.
///
/// It is issued through the raw `renameat2` syscall rather than a libc wrapper, because the
/// wrapper is not exposed on every target this binary is built for (the syscall number is).
fn swap_into_place(stage: &Path, dest: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let c_stage = std::ffi::CString::new(stage.as_os_str().as_bytes())
        .map_err(|_| "the staging path contains a NUL byte".to_string())?;
    let c_dest = std::ffi::CString::new(dest.as_os_str().as_bytes())
        .map_err(|_| "the store path contains a NUL byte".to_string())?;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            c_stage.as_ptr(),
            libc::AT_FDCWD,
            c_dest.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::ENOTSUP) => Err(format!(
            "the data directory's filesystem does not support atomic store replacement \
             (renameat2 RENAME_EXCHANGE): {err}"
        )),
        _ => Err(format!("could not replace the store cache: {err}")),
    }
}

/// Clone a git repository into `dest` (which must not yet exist) with a hardened `git`
/// invocation. Shallow (`--depth 1`, honored over `file://` and `https://`) and single-branch
/// — a store is fetched for its current content, never its history.
fn clone(git: &Path, url: &str, dest: &Path) -> Result<(), String> {
    let out = git_command(git)
        .args(["clone", "--quiet", "--depth", "1", "--single-branch", "--"])
        .arg(url)
        .arg(dest)
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    // git's own diagnosis is the useful part; trim it to the last non-empty lines so a
    // verbose transport error stays legible.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let detail = stderr
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("git clone failed");
    Err(format!("could not fetch the store: {detail}"))
}

/// A `git` command with its configuration and credential surface neutralized. Host-side git
/// against remote content is a wide attack surface, so the global and system config files are
/// nulled (defeating `insteadOf` URL rewrites and `core.hooksPath`/template hook injection),
/// the credential prompt is disabled (a fetch never blocks on a password), and the allowed
/// transports are restricted to the two a store uses. git also accepts config through the
/// environment, independent of the config files, so the indexed (`GIT_CONFIG_COUNT` +
/// `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`) and the legacy `GIT_CONFIG_PARAMETERS` channels
/// are removed too — otherwise an inherited one would inject arbitrary config straight past the
/// nulled files. The rest of the environment is kept so the system CA bundle and resolver
/// remain available for `https`.
fn git_command(git: &Path) -> Command {
    let mut cmd = Command::new(git);
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", "file:https")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_CONFIG_PARAMETERS");
    cmd
}

/// Parse a `--key` argument into a 32-byte Ed25519 public key. A leading `@` reads the key
/// from a file (its hex contents); otherwise the argument is the hex key itself. Either way
/// the decoded key must be exactly 32 bytes, fail-closed.
pub(crate) fn parse_pubkey_arg(arg: &str) -> Result<[u8; 32], String> {
    let hex = match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read the public key file `{path}`: {e}"))?,
        None => arg.to_string(),
    };
    decode_key(&hex)
}

/// Decode a hex string into a 32-byte Ed25519 public key, fail-closed on bad hex or the wrong
/// length. Shared by the `--key` argument and the pinned key read back from a store's cache.
fn decode_key(hex: &str) -> Result<[u8; 32], String> {
    let bytes = crate::plugins::catalogue::decode_hex(hex)
        .map_err(|e| format!("the public key is not valid hex: {e}"))?;
    bytes.try_into().map_err(|b: Vec<u8>| {
        format!(
            "an Ed25519 public key is 32 bytes (64 hex characters); got {}",
            b.len()
        )
    })
}

/// The most a store-root artifact (catalogue or signature) may be — a generous bound over any real
/// catalogue, so a fetched store cannot make sbx read an unbounded file (a symlink to `/dev/zero`)
/// into memory before its signature is even checked.
const STORE_FILE_MAX: u64 = 8 * 1024 * 1024;

/// Read a store-root file into memory, refusing a symlink or a non-regular file and bounding the
/// size — these bytes come from an untrusted fetched repository and are read BEFORE the Ed25519
/// verification, so the read itself must not be a lever (an unbounded `/dev/zero` symlink, a device
/// node). `O_NOFOLLOW` refuses a symlink at the leaf without a TOCTOU window; the size is checked on
/// the open fd. `missing` is the precise message when the file is simply absent.
fn read_store_file(path: &Path, what: &str, missing: &str) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => missing.to_string(),
            _ => format!("cannot read `{what}`: {e} (a symlink is refused)"),
        })?;
    let meta = f
        .metadata()
        .map_err(|e| format!("cannot read `{what}`: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!("`{what}` is not a regular file"));
    }
    if meta.len() > STORE_FILE_MAX {
        return Err(format!(
            "`{what}` is too large ({} bytes; the limit is {STORE_FILE_MAX})",
            meta.len()
        ));
    }
    let mut buf = Vec::new();
    f.take(STORE_FILE_MAX)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read `{what}`: {e}"))?;
    Ok(buf)
}

/// Read the detached signature file and decode it from hex. The signature is stored hex-encoded
/// (not raw bytes) so it survives a git checkout unchanged regardless of the repository's
/// line-ending configuration.
fn read_signature(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_store_file(
        path,
        CATALOGUE_SIG,
        &format!("the store has no `{CATALOGUE_SIG}` (an unsigned store is refused)"),
    )?;
    let text =
        String::from_utf8(bytes).map_err(|_| format!("the `{CATALOGUE_SIG}` is not valid text"))?;
    crate::plugins::catalogue::decode_hex(&text)
        .map_err(|e| format!("the catalogue signature is not valid hex: {e}"))
}

/// Read the catalogue file, mapping its absence to a precise refusal (a repository without a
/// catalogue is not a plugin store).
fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    read_store_file(
        path,
        CATALOGUE,
        &format!("the store has no `{CATALOGUE}` (it is not a plugin store)"),
    )
}

/// A store URL: non-empty and free of control characters. The latter keeps the URL a single
/// well-formed line in `store.toml` (a newline would otherwise produce a file that fails to
/// parse on the next read) and rejects a terminal-escape smuggled through a git error message.
fn validate_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("the store URL is empty".to_string());
    }
    if url.chars().any(|c| c.is_control()) {
        return Err("the store URL contains a control character".to_string());
    }
    Ok(())
}

/// The `store.toml` recording a configured store's origin and trust anchor: the git URL it is
/// fetched from, the hex public key its catalogue must verify against, and how that key was first
/// trusted (`"tofu"` or `"pinned"`, informational).
fn store_toml(url: &str, pubkey: &[u8; 32], tofu: bool) -> String {
    // The URL is a TOML basic string; a store URL is a plain ASCII git URL, but escape the
    // two characters that would break the string just in case.
    let url = url.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "url = \"{url}\"\npubkey = \"{}\"\ntrust = \"{}\"\n",
        crate::plugins::catalogue::to_hex(pubkey),
        if tofu { "tofu" } else { "pinned" }
    )
}

/// Write a file owner-readable/writable only, creating it fresh.
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// A per-call-unique suffix for the staging directory, so two adds in one process never
/// collide. A monotonic process-local counter — no clock or RNG.
fn unique() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

/// A staging directory removed when it goes out of scope, so a fetch never leaks its tree —
/// on success (after the atomic rename has consumed it, where the removal is a no-op) or on
/// any error path.
struct Stage(PathBuf);

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::catalogue::{dir_digest, to_hex};
    use std::os::unix::fs::PermissionsExt;

    fn keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    #[test]
    fn read_store_file_reads_a_regular_file_but_refuses_a_symlink() {
        let dir = crate::testutil::TmpDir::new();
        let real = dir.path().join("catalogue.toml");
        std::fs::write(&real, b"name = \"x\"\n").unwrap();
        assert_eq!(
            read_store_file(&real, "catalogue.toml", "missing").unwrap(),
            b"name = \"x\"\n"
        );
        // A symlink (the untrusted repo's own leaf) is refused, so a `/dev/zero`-style unbounded
        // read can never happen before verification.
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_store_file(&link, "catalogue.toml", "missing").is_err());
        // An absent file maps to the precise `missing` message.
        let gone = dir.path().join("nope.toml");
        assert_eq!(
            read_store_file(&gone, "catalogue.toml", "the-missing-note").unwrap_err(),
            "the-missing-note"
        );
    }

    /// `pubkey` is a root file of a freshly cloned, entirely untrusted repository, and it is read
    /// **before** the catalogue and its signature — earlier than anything there is to verify. It was
    /// the one store-root read that went through a plain `read_to_string`, so it followed a leaf
    /// symlink and had no ceiling: `pubkey -> /dev/zero` read until the host ran out of memory.
    #[test]
    fn the_repo_pubkey_is_read_under_the_same_guard_as_the_catalogue() {
        let dir = crate::testutil::TmpDir::new();
        let checkout = dir.path();

        // A symlinked `pubkey` is refused rather than followed, even when its target is a perfectly
        // good key — the point is that the read itself must not be a lever.
        let real = dir.path().join("elsewhere.hex");
        std::fs::write(&real, "00".repeat(32)).unwrap();
        std::os::unix::fs::symlink(&real, checkout.join(REPO_PUBKEY)).unwrap();
        let err = read_repo_pubkey(checkout).expect_err("a symlinked pubkey must be refused");
        assert!(err.contains("symlink"), "{err}");

        // The ordinary case still reads, so the guard is not simply refusing everything.
        std::fs::remove_file(checkout.join(REPO_PUBKEY)).unwrap();
        std::fs::write(checkout.join(REPO_PUBKEY), "00".repeat(32)).unwrap();
        assert_eq!(read_repo_pubkey(checkout).unwrap(), [0u8; 32]);

        // And an absent one still gives the message that points at `--key`, which is the whole
        // reason `read_store_file` takes a caller-supplied `missing` note.
        std::fs::remove_file(checkout.join(REPO_PUBKEY)).unwrap();
        let err = read_repo_pubkey(checkout).expect_err("absent");
        assert!(err.contains("--key"), "{err}");
    }

    fn pubkey_of(kp: &Ed25519KeyPair) -> [u8; 32] {
        kp.public_key().as_ref().try_into().unwrap()
    }

    /// The scheme the proto-signer's plugin manifest always claims. It is deliberately *different*
    /// from the plugin's name (`pass`), so a test that threads a name and a scheme separately —
    /// install-from-store's reconciliation — cannot pass by accident if the two are swapped.
    const MANIFEST_SCHEME: &str = "secret-store";

    /// Write a one-plugin store under `dir`: a `pass` plugin whose manifest claims
    /// [`MANIFEST_SCHEME`], a `catalogue.toml` stamped at `rev` that *advertises* `advertised_scheme`
    /// for it, and a detached signature over the catalogue by `kp`. For a well-formed store the two
    /// schemes are equal (see [`sign_store`]); passing a different `advertised_scheme` simulates a
    /// catalogue that misadvertises what it pins — the signature and the per-plugin `sha256` stay
    /// valid (the `sha256` is computed with the very `dir_digest` the verifier uses, so signer and
    /// verifier never drift), so only the install-time reconciliation can catch the divergence. It
    /// overwrites any prior catalogue and signature, so a second call re-publishes the store at a
    /// new revision and/or under a new key — exactly the moves an update must police.
    fn sign_store_with(dir: &Path, rev: u64, kp: &Ed25519KeyPair, advertised_scheme: &str) {
        let plugin = dir.join("plugins/pass");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(
            plugin.join("plugin.toml"),
            format!(
                "name = \"pass\"\ntype = \"resolver\"\nscheme = \"{MANIFEST_SCHEME}\"\n\
                 exec = \"resolve\"\nversion = \"0.1.0\"\n\
                 description = \"the password-store resolver\"\n"
            ),
        )
        .unwrap();
        let exec = plugin.join("resolve");
        std::fs::write(&exec, "#!/bin/sh\necho secret\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();

        let sha = to_hex(&dir_digest(&plugin).unwrap());
        let catalogue = format!(
            "rev = {rev}\n[plugin.pass]\nscheme = \"{advertised_scheme}\"\nversion = \"0.1.0\"\n\
             description = \"the password-store resolver\"\npath = \"plugins/pass\"\n\
             sha256 = \"{sha}\"\n"
        );
        std::fs::write(dir.join(CATALOGUE), &catalogue).unwrap();
        let sig = kp.sign(catalogue.as_bytes());
        std::fs::write(
            dir.join(CATALOGUE_SIG),
            format!("{}\n", to_hex(sig.as_ref())),
        )
        .unwrap();
    }

    /// A well-formed one-plugin store: the catalogue advertises exactly the scheme the manifest
    /// claims. The common case for the add/update/list/info tests.
    fn sign_store(dir: &Path, rev: u64, kp: &Ed25519KeyPair) {
        sign_store_with(dir, rev, kp, MANIFEST_SCHEME);
    }

    /// Build a signed store under `dir` at `rev` with a fresh key, returning that key's public
    /// half — the shape the `add` tests want when they do not need to re-sign later.
    fn build_signed_store(dir: &Path, rev: u64) -> [u8; 32] {
        let kp = keypair();
        sign_store(dir, rev, &kp);
        pubkey_of(&kp)
    }

    /// Ship a public key as the store's root `pubkey` file (hex) — what a trust-on-first-use add
    /// reads. A well-formed TOFU store ships the same key its catalogue is signed with.
    fn ship_pubkey(dir: &Path, pubkey: &[u8; 32]) {
        std::fs::write(dir.join("pubkey"), to_hex(pubkey)).unwrap();
    }

    /// Build an *unsigned* source plugin under `<dir>/plugins/<name>/` — a manifest claiming
    /// `scheme` and an executable — the raw tree a publish signs (as opposed to [`sign_store`],
    /// which hand-builds an already-signed store the way `add`/`update` expect to find one).
    fn write_source_plugin(dir: &Path, name: &str, scheme: &str) {
        let plugin = dir.join("plugins").join(name);
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(
            plugin.join("plugin.toml"),
            format!(
                "name = \"{name}\"\ntype = \"resolver\"\nscheme = \"{scheme}\"\nexec = \"resolve\"\n\
                 version = \"0.1.0\"\ndescription = \"a test resolver\"\n"
            ),
        )
        .unwrap();
        let exec = plugin.join("resolve");
        std::fs::write(&exec, "#!/bin/sh\necho secret\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Run a git subcommand in `dir` with an explicit identity and no signing, independent of
    /// the host's git configuration. Asserts success.
    fn git_run(git: &Path, dir: &Path, args: &[&str]) {
        let ok = Command::new(git)
            .args(["-C", dir.to_str().unwrap()])
            .args([
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "init.defaultBranch=main",
            ])
            .args(args)
            .status()
            .unwrap()
            .success();
        assert!(ok, "git {args:?} failed");
    }

    /// Stage and commit the current tree — a publish, or a re-publish on a later call.
    fn commit_all(git: &Path, dir: &Path, message: &str) {
        git_run(git, dir, &["add", "-A"]);
        git_run(git, dir, &["commit", "-q", "-m", message]);
    }

    /// Initialize `dir` as a git repository, commit its tree, and return a `file://` URL for it.
    fn commit_repo(git: &Path, dir: &Path) -> String {
        git_run(git, dir, &["init", "-q"]);
        commit_all(git, dir, "store");
        format!("file://{}", dir.to_str().unwrap())
    }

    /// The revision recorded in a configured store's `catalogue.lock`.
    fn read_lock(layout: &crate::store::Layout, name: &str) -> u64 {
        std::fs::read_to_string(layout.store_path(name).join(CATALOGUE_LOCK))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    /// `git`, or skip the test (CI without git). The crate's other tool-dependent tests skip
    /// the same way rather than fail when the host lacks a prerequisite.
    fn git_or_skip() -> Option<PathBuf> {
        let git = crate::store::resolve_git();
        if git.is_none() {
            skip_incapable!("skipping remote-store test: git is not on PATH");
        }
        git
    }

    #[test]
    fn add_clones_verifies_and_caches_a_signed_store() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 3);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let added = add(&layout, "default", &url, pubkey, &git).expect("add the signed store");
        assert_eq!(added.name, "default");
        assert_eq!(added.catalogue.rev, 3);
        assert!(added.catalogue.plugins.contains_key("pass"));

        // the cache is populated: config, the verified checkout, and the revision lock
        let store = layout.store_path("default");
        assert!(store.join("store.toml").is_file());
        assert!(store.join("checkout").join(CATALOGUE).is_file());
        assert!(store.join("checkout/plugins/pass/plugin.toml").is_file());
        assert_eq!(
            std::fs::read_to_string(store.join("catalogue.lock"))
                .unwrap()
                .trim(),
            "3"
        );
        // the working git metadata is not carried into the trusted cache
        assert!(!store.join("checkout/.git").exists());
        // no staging tree leaked
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn add_refuses_a_catalogue_signed_by_another_key_and_places_nothing() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        // a public key that does not match the signing key
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let other = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let wrong: [u8; 32] = other.public_key().as_ref().try_into().unwrap();

        let err = add(&layout, "default", &url, wrong, &git).unwrap_err();
        assert!(err.contains("signature"), "{err}");
        // fail-closed: nothing was placed, no stage leaked
        assert!(!layout.store_path("default").exists());
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn add_refuses_a_tampered_catalogue() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        // tamper the catalogue *after* signing, so the signature no longer matches its bytes
        let cat = repo.path().join(CATALOGUE);
        let mut bytes = std::fs::read(&cat).unwrap();
        bytes[0] ^= 0x01;
        std::fs::write(&cat, &bytes).unwrap();
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let err = add(&layout, "default", &url, pubkey, &git).unwrap_err();
        assert!(err.contains("signature"), "{err}");
        assert!(!layout.store_path("default").exists());
    }

    #[test]
    fn add_refuses_an_unsigned_store() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        std::fs::remove_file(repo.path().join(CATALOGUE_SIG)).unwrap();
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let err = add(&layout, "default", &url, pubkey, &git).unwrap_err();
        assert!(err.contains("unsigned"), "{err}");
        assert!(!layout.store_path("default").exists());
    }

    #[test]
    fn add_refuses_a_repository_that_is_not_a_store() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        std::fs::write(repo.path().join("README"), "not a store").unwrap();
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        // any key; the catalogue is missing before verification is reached
        let err = add(&layout, "default", &url, [0u8; 32], &git).unwrap_err();
        assert!(err.contains("not a plugin store"), "{err}");
        assert!(!layout.store_path("default").exists());
    }

    #[test]
    fn add_refuses_an_already_configured_store() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("first add");
        let err = add(&layout, "default", &url, pubkey, &git).unwrap_err();
        assert!(err.contains("already configured"), "{err}");
    }

    #[test]
    fn add_refuses_an_unsafe_store_name() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let git = PathBuf::from("/nonexistent/git");
        // the name is validated before git is ever consulted, so a bad name fails fast
        assert!(add(&layout, "../evil", "file:///x", [0u8; 32], &git).is_err());
        assert!(add(&layout, ".hidden", "file:///x", [0u8; 32], &git).is_err());
    }

    #[test]
    fn parse_pubkey_accepts_hex_and_a_file_and_rejects_the_wrong_length() {
        let key = [0xabu8; 32];
        let hex = to_hex(&key);
        assert_eq!(parse_pubkey_arg(&hex).unwrap(), key);

        let dir = crate::testutil::TmpDir::new();
        let file = dir.path().join("key.hex");
        std::fs::write(&file, format!("{hex}\n")).unwrap();
        assert_eq!(
            parse_pubkey_arg(&format!("@{}", file.to_str().unwrap())).unwrap(),
            key
        );

        // 31 bytes is not a key
        assert!(parse_pubkey_arg(&"ab".repeat(31)).is_err());
        assert!(parse_pubkey_arg("not-hex").is_err());
        assert!(parse_pubkey_arg("@/nonexistent/key").is_err());
    }

    #[test]
    fn the_git_command_neutralizes_config_and_credential_surface() {
        let cmd = git_command(Path::new("/usr/bin/git"));
        let mut set: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut removed: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (k, v) in cmd.get_envs() {
            let Some(k) = k.to_str() else { continue };
            match v {
                Some(v) => {
                    set.insert(k.to_string(), v.to_str().unwrap().to_string());
                }
                None => {
                    removed.insert(k.to_string());
                }
            }
        }
        assert_eq!(
            set.get("GIT_CONFIG_GLOBAL").map(String::as_str),
            Some("/dev/null")
        );
        assert_eq!(
            set.get("GIT_CONFIG_SYSTEM").map(String::as_str),
            Some("/dev/null")
        );
        assert_eq!(
            set.get("GIT_TERMINAL_PROMPT").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            set.get("GIT_ALLOW_PROTOCOL").map(String::as_str),
            Some("file:https")
        );
        // the environment-based config channels must be stripped, not merely the config files
        assert!(
            removed.contains("GIT_CONFIG_COUNT"),
            "GIT_CONFIG_COUNT must be removed"
        );
        assert!(
            removed.contains("GIT_CONFIG_PARAMETERS"),
            "GIT_CONFIG_PARAMETERS must be removed"
        );
    }

    #[test]
    fn a_url_with_a_control_character_is_refused() {
        assert!(validate_url("https://example.com/store.git").is_ok());
        assert!(validate_url("file:///tmp/x").is_ok());
        assert!(validate_url("").is_err());
        assert!(validate_url("https://example.com/\nhooksPath=/evil").is_err());
    }

    #[test]
    fn update_refetches_and_advances_the_revision() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 3, &kp);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey_of(&kp), &git).expect("add at rev 3");

        // the store author re-publishes at rev 5, signed by the same key
        sign_store(repo.path(), 5, &kp);
        commit_all(&git, repo.path(), "rev 5");

        let updated = update(&layout, "default", &git).expect("update to rev 5");
        assert_eq!(updated.old_rev, 3);
        assert_eq!(updated.new_rev, 5);
        assert_eq!(read_lock(&layout, "default"), 5);
        // the replacement is a fresh checkout, with no git metadata and no leaked staging tree
        assert!(!layout.store_path("default").join("checkout/.git").exists());
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn update_refuses_a_rollback_and_keeps_the_cache() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 5, &kp);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey_of(&kp), &git).expect("add at rev 5");

        // a validly-signed but *older* catalogue — a withdrawn listing replayed
        sign_store(repo.path(), 2, &kp);
        commit_all(&git, repo.path(), "rev 2");

        let err = update(&layout, "default", &git).unwrap_err();
        assert!(err.contains("roll back"), "{err}");
        // the cache is untouched: still the accepted revision
        assert_eq!(read_lock(&layout, "default"), 5);
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn update_refuses_a_catalogue_resigned_with_a_different_key() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 3, &kp);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey_of(&kp), &git).expect("add at rev 3");

        // the remote is taken over: re-signed with a new key AND a higher revision, so only the
        // pinned-key check — not the rollback floor — can refuse it.
        let attacker = keypair();
        sign_store(repo.path(), 9, &attacker);
        commit_all(&git, repo.path(), "key rotation + rev bump");

        let err = update(&layout, "default", &git).unwrap_err();
        assert!(err.contains("signature"), "{err}");
        // the pinned key held: the cache is still the original revision
        assert_eq!(read_lock(&layout, "default"), 3);
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn update_on_an_unconfigured_store_is_an_error() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // git is never reached: an unconfigured store has no pinned key to fetch against
        let git = PathBuf::from("/nonexistent/git");
        let err = update(&layout, "default", &git).unwrap_err();
        assert!(err.contains("configured"), "{err}");
    }

    #[test]
    fn remove_deletes_a_configured_store() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add");

        assert!(layout.store_path("default").exists());
        remove(&layout, "default").expect("remove the store");
        assert!(!layout.store_path("default").exists());
        // removing a store that is not configured is a clear error
        assert!(remove(&layout, "default").is_err());
    }

    #[test]
    fn list_returns_configured_store_names_sorted_ignoring_bookkeeping() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        // two stores from one repo, added out of order
        add(&layout, "beta", &url, pubkey, &git).expect("add beta");
        add(&layout, "alpha", &url, pubkey, &git).expect("add alpha");
        // a dot-prefixed entry under the stores dir must be ignored
        std::fs::create_dir_all(layout.stores_dir().join(".scratch")).unwrap();

        assert_eq!(list(&layout), vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[test]
    fn read_configured_floors_a_bad_lock_but_hard_fails_a_missing_store_toml() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 4);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add at rev 4");

        let cfg = read_configured(&layout, "default").expect("read the freshly added store");
        assert_eq!(cfg.locked_rev, 4);
        assert_eq!(cfg.pubkey, pubkey);

        // a corrupt lock degrades to the floor (0), not an error
        std::fs::write(
            layout.store_path("default").join(CATALOGUE_LOCK),
            "not-a-number",
        )
        .unwrap();
        assert_eq!(read_configured(&layout, "default").unwrap().locked_rev, 0);

        // a missing store.toml is the opposite: there is no trust anchor, so it hard-fails
        std::fs::remove_file(layout.store_path("default").join(STORE_TOML)).unwrap();
        assert!(read_configured(&layout, "default").is_err());
    }

    #[test]
    fn add_tofu_pins_the_key_the_store_ships() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 3, &kp);
        ship_pubkey(repo.path(), &pubkey_of(&kp));
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let added = add_tofu(&layout, "acme", &url, &git).expect("trust-on-first-use add");
        assert!(added.tofu);
        // Teeth: it pins the EXACT key the test generated, not the signature bytes or a zero key.
        assert_eq!(added.pubkey, pubkey_of(&kp));
        assert_eq!(added.catalogue.rev, 3);
        assert!(added.catalogue.plugins.contains_key("pass"));

        // The cache records that exact pinned key and marks the store as trusted on first use.
        let cfg = read_configured(&layout, "acme").expect("read the configured store");
        assert_eq!(cfg.pubkey, pubkey_of(&kp));
        assert_eq!(cfg.locked_rev, 3);
        assert!(cfg.tofu);
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn add_tofu_refuses_a_store_without_a_pubkey() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 1, &kp);
        // no ship_pubkey: the store carries a catalogue and signature but no key to trust
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let err = add_tofu(&layout, "acme", &url, &git).unwrap_err();
        assert!(err.contains("pubkey"), "{err}");
        assert!(!layout.store_path("acme").exists());
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn add_tofu_refuses_a_pubkey_that_does_not_verify_the_catalogue() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        // Asymmetric: the catalogue is signed by `signer`, but the store ships `other`'s key. A TOFU
        // pin must still be self-consistent (the catalogue must verify against the shipped key), so
        // this is refused on the signature — the shipped key alone is not enough.
        let signer = keypair();
        let other = keypair();
        sign_store(repo.path(), 1, &signer);
        ship_pubkey(repo.path(), &pubkey_of(&other));
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let err = add_tofu(&layout, "acme", &url, &git).unwrap_err();
        assert!(err.contains("signature"), "{err}");
        assert!(!layout.store_path("acme").exists());
    }

    #[test]
    fn add_tofu_refuses_a_malformed_pubkey() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 1, &kp);
        std::fs::write(repo.path().join("pubkey"), "not-a-valid-hex-key").unwrap();
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());

        let err = add_tofu(&layout, "acme", &url, &git).unwrap_err();
        assert!(err.contains("hex"), "{err}");
        assert!(!layout.store_path("acme").exists());
    }

    #[test]
    fn update_after_tofu_uses_the_pinned_key_not_the_repos() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 3, &kp);
        ship_pubkey(repo.path(), &pubkey_of(&kp));
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add_tofu(&layout, "acme", &url, &git).expect("tofu add at rev 3");

        // (a) The load-bearing POSITIVE: the author re-publishes at rev 5 signed by the SAME key —
        // an update verified against the pinned key SUCCEEDS, and the TOFU mark is preserved.
        sign_store(repo.path(), 5, &kp);
        ship_pubkey(repo.path(), &pubkey_of(&kp));
        commit_all(&git, repo.path(), "rev 5");
        let updated = update(&layout, "acme", &git).expect("update with the pinned key");
        assert_eq!(updated.new_rev, 5);
        assert!(read_configured(&layout, "acme").unwrap().tofu);

        // (b) The load-bearing REFUSAL: the remote is taken over — re-signed with a NEW key AND the
        // repo now ships that new key, at a higher rev so only the key check can refuse it. Because
        // `update` verifies against the PINNED key from `store.toml`, never the repo's `pubkey`
        // file, it is refused on the signature. This is the whole TOFU security property.
        let attacker = keypair();
        sign_store(repo.path(), 9, &attacker);
        ship_pubkey(repo.path(), &pubkey_of(&attacker));
        commit_all(&git, repo.path(), "re-key");
        let err = update(&layout, "acme", &git).unwrap_err();
        // The refusal *is* the TOFU property. The message names why — the key this store ships
        // changed — which is what lets a user tell an announced rotation from this takeover.
        assert!(err.contains("has CHANGED"), "{err}");
        assert!(err.contains("store rekey acme"), "{err}");
        assert_eq!(read_lock(&layout, "acme"), 5);
        assert!(!leaked_stage(data.path()));
    }

    #[test]
    fn read_configured_defaults_to_pinned_without_a_trust_field() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 4);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "legacy", &url, pubkey, &git).expect("pinned add");

        // Simulate a store configured before the `trust` field existed: strip it from store.toml.
        // It must still parse and report a pinned key (the safe default), not hard-fail the store.
        let toml_path = layout.store_path("legacy").join(STORE_TOML);
        let stripped: String = std::fs::read_to_string(&toml_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim_start().starts_with("trust"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(!stripped.contains("trust"));
        std::fs::write(&toml_path, stripped).unwrap();

        let cfg = read_configured(&layout, "legacy").expect("legacy store.toml still parses");
        assert!(!cfg.tofu);
        assert_eq!(cfg.pubkey, pubkey);
    }

    #[test]
    fn cached_catalogue_reads_the_location_trusted_catalogue() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 2);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add at rev 2");

        let cat = cached_catalogue(&layout, "default").expect("read the cached catalogue");
        assert_eq!(cat.rev, 2);
        assert!(cat.plugins.contains_key("pass"));
    }

    #[test]
    fn install_plugin_places_a_verified_plugin_from_a_store() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add the store");

        // Simulate a fetch under a group-writable umask: git pins only the executable bit, so a
        // checkout can leave the executable group/other-writable. The install must canonicalize the
        // mode rather than refuse it (and the content gate, which reads only the exec bit, still
        // passes). Forcing it here makes the assertion below umask-independent.
        let cached_exec = layout
            .store_path("default")
            .join("checkout/plugins/pass/resolve");
        std::fs::set_permissions(&cached_exec, std::fs::Permissions::from_mode(0o775)).unwrap();

        let installed = install_plugin(&layout, "default", "pass").expect("install from the store");
        assert_eq!(installed.name, "pass");
        // Teeth on the (name, scheme) threading through stores → plugins: the installed scheme is
        // the catalogue's *advertised* scheme, which differs from the plugin's name — a swapped
        // argument in the call would refuse the install (a name/scheme mismatch) instead of landing
        // here with the right scheme.
        assert_eq!(installed.scheme.as_deref(), Some("secret-store"));

        // placed under the manifest name, and the live registry resolves it under its scheme
        let dest = layout.plugins_dir().join("pass");
        assert!(dest.join("plugin.toml").is_file());
        // the executable's mode is canonical (0755), independent of the fetch umask
        let mode = std::fs::metadata(dest.join("resolve"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o755,
            "a store install canonicalizes the executable mode"
        );
        let mut warnings = Vec::new();
        let reg = crate::plugins::PluginRegistry::load(&layout.plugins_dir(), &mut warnings);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
        assert!(
            reg.resolver("secret-store").is_some(),
            "the installed plugin resolves under its advertised scheme"
        );

        // The provenance a listing later reports: which store it came from, where that store is
        // fetched from (so the answer survives `store rm`), and the content hash the catalogue
        // pinned at install time.
        let catalogue = cached_catalogue(&layout, "default").expect("cached catalogue");
        assert_eq!(
            crate::plugins::origin::read(&layout, "pass"),
            crate::plugins::origin::Origin::Store {
                store: "default".to_string(),
                url: Some(url.clone()),
                sha256: Some(catalogue.plugins["pass"].sha256.clone()),
            }
        );
    }

    #[test]
    fn two_stores_listing_one_name_the_second_install_names_the_holder() {
        let Some(git) = git_or_skip() else { return };
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        // Two independently-signed stores that happen to list a plugin of the same name — the
        // install namespace is flat, so only one of them can hold it.
        let first_repo = crate::testutil::TmpDir::new();
        let first_key = build_signed_store(first_repo.path(), 1);
        let first_url = commit_repo(&git, first_repo.path());
        add(&layout, "first", &first_url, first_key, &git).expect("add the first store");
        let second_repo = crate::testutil::TmpDir::new();
        let second_key = build_signed_store(second_repo.path(), 1);
        let second_url = commit_repo(&git, second_repo.path());
        add(&layout, "second", &second_url, second_key, &git).expect("add the second store");

        install_plugin(&layout, "first", "pass").expect("install from the first store");
        // The second store's copy is refused, and the refusal says which store holds the name —
        // otherwise "already installed" leaves the user with no way to tell the two apart.
        let err = install_plugin(&layout, "second", "pass").unwrap_err();
        assert!(
            err.contains("already installed (from store 'first')"),
            "{err}"
        );
        assert_eq!(
            crate::plugins::origin::read(&layout, "pass"),
            crate::plugins::origin::Origin::Store {
                store: "first".to_string(),
                url: Some(first_url),
                sha256: Some(
                    cached_catalogue(&layout, "first").unwrap().plugins["pass"]
                        .sha256
                        .clone()
                ),
            },
            "the failed second install must not rewrite the first store's provenance"
        );
    }

    #[test]
    fn verify_key_confirms_a_tofu_pin_and_refuses_a_key_that_does_not_match() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        sign_store(repo.path(), 1, &kp);
        ship_pubkey(repo.path(), &pubkey_of(&kp));
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add_tofu(&layout, "hub", &url, &git).expect("add on first use");
        assert!(read_configured(&layout, "hub").unwrap().tofu);

        // A key from somewhere else that is NOT this store's: the caution stands, untouched.
        let other = pubkey_of(&keypair());
        let err = verify_key(&layout, "hub", other).unwrap_err();
        assert!(err.contains("is not the one you supplied"), "{err}");
        assert!(
            read_configured(&layout, "hub").unwrap().tofu,
            "a mismatch must leave the record exactly as it was"
        );

        // The real key, obtained out of band: the pin is confirmed and the caution ends.
        assert_eq!(
            verify_key(&layout, "hub", pubkey_of(&kp)).unwrap(),
            Verified::Confirmed
        );
        let cfg = read_configured(&layout, "hub").unwrap();
        assert!(!cfg.tofu);
        // Confirming records only that: the key, the URL, and the revision floor are untouched, so
        // nothing about what a later fetch enforces has changed.
        assert_eq!(cfg.pubkey, pubkey_of(&kp));
        assert_eq!(cfg.url, url);
        assert_eq!(cfg.locked_rev, 1);

        // Idempotent: a store whose key was supplied out of band has nothing left to confirm.
        assert_eq!(
            verify_key(&layout, "hub", pubkey_of(&kp)).unwrap(),
            Verified::AlreadyPinned
        );
        // No torn-write temp survives the rewrite of the file that carries the trust anchor.
        let leaked: Vec<_> = std::fs::read_dir(layout.store_path("hub"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(".store-toml-"))
            .collect();
        assert!(leaked.is_empty(), "a temp record leaked: {leaked:?}");
    }

    /// Write a configured store's trust anchor straight into the owner-only cache: `store.toml`
    /// alone, no checkout and no git. Enough for the paths that only consult the pinned key, and it
    /// lets those run on a host without git rather than skipping.
    fn pin_store(layout: &crate::store::Layout, name: &str, pubkey: &[u8; 32], tofu: bool) {
        let dir = layout.store_path(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(STORE_TOML),
            store_toml("https://example.invalid/store.git", pubkey, tofu),
        )
        .unwrap();
    }

    #[test]
    fn verify_key_compares_the_supplied_key_even_when_the_store_was_pinned_out_of_band() {
        // `store verify` exists to catch a mis-pin, and the realistic mis-pin is a `--key` pasted
        // from a page the attacker controls — which records the store as `pinned`, not `tofu`.
        // Answering `verified` on that path without comparing anything would report success for the
        // very case the command was written for, and the user would take it as proof of the store.
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let pinned = pubkey_of(&keypair());
        pin_store(&layout, "vendor", &pinned, false);

        // The genuine key, obtained out of band, against a store pinned to someone else's.
        let genuine = pubkey_of(&keypair());
        let err = verify_key(&layout, "vendor", genuine)
            .expect_err("a key that is not the pinned one must be refused");
        assert!(err.contains("is not the one you supplied"), "{err}");
        let cfg = read_configured(&layout, "vendor").expect("the record still reads");
        assert_eq!(cfg.pubkey, pinned, "a mismatch changes nothing");
        assert!(!cfg.tofu);

        // The matching key on the same store is still the idempotent no-op: there was no standing
        // caution to clear, so nothing is written — but it got there by comparing.
        assert_eq!(
            verify_key(&layout, "vendor", pinned).unwrap(),
            Verified::AlreadyPinned
        );
    }

    #[test]
    fn a_changed_store_key_is_named_by_update_and_rotated_only_on_purpose() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let first = keypair();
        sign_store(repo.path(), 1, &first);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "hub", &url, pubkey_of(&first), &git).expect("add");

        // The store re-signs with a different identity, as a real rotation would.
        let second = keypair();
        sign_store(repo.path(), 2, &second);
        ship_pubkey(repo.path(), &pubkey_of(&second));
        commit_all(&git, repo.path(), "rotate");

        // `update` still refuses — but it now says *why*, which an opaque signature failure could
        // not: the user has to be able to tell a rotation from a takeover.
        let err = update(&layout, "hub", &git).unwrap_err();
        assert!(err.contains("has CHANGED"), "{err}");
        assert!(err.contains(&to_hex(&pubkey_of(&first))), "{err}");
        assert!(err.contains(&to_hex(&pubkey_of(&second))), "{err}");
        assert!(err.contains("store rekey hub"), "{err}");
        assert_eq!(
            read_configured(&layout, "hub").unwrap().pubkey,
            pubkey_of(&first),
            "a refused update must leave the pin untouched"
        );

        // A rotation to a key that does not sign this store is refused: the pin would end up on a
        // key that verifies nothing the store holds.
        let unrelated = pubkey_of(&keypair());
        let err = rekey(&layout, "hub", TrustChoice::Pinned(unrelated), &git).unwrap_err();
        assert!(err.contains("does not sign this store"), "{err}");
        assert_eq!(
            read_configured(&layout, "hub").unwrap().pubkey,
            pubkey_of(&first)
        );

        // Rotating to the key already pinned is not a rotation, and must not read as success —
        // whatever made `update` fail would otherwise be papered over.
        let err = rekey(&layout, "hub", TrustChoice::Pinned(pubkey_of(&first)), &git).unwrap_err();
        assert!(err.contains("already pinned to that key"), "{err}");

        // The real new key: the pin moves, the floor is carried over, and the store works again.
        let done = rekey(
            &layout,
            "hub",
            TrustChoice::Pinned(pubkey_of(&second)),
            &git,
        )
        .expect("rotate to the announced key");
        assert_eq!(done.old_pubkey, pubkey_of(&first));
        assert_eq!(done.new_pubkey, pubkey_of(&second));
        assert!(!done.tofu, "a supplied key is pinned, not accepted");
        let cfg = read_configured(&layout, "hub").unwrap();
        assert_eq!(cfg.pubkey, pubkey_of(&second));
        assert_eq!(cfg.locked_rev, 2);
        update(&layout, "hub", &git).expect("the store verifies against the new key");
    }

    #[test]
    fn a_rotation_never_reopens_the_rollback_floor() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let first = keypair();
        sign_store(repo.path(), 5, &first);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "hub", &url, pubkey_of(&first), &git).expect("add at rev 5");

        // A new key signing an *older* catalogue is exactly how a rotation could be used to replay
        // a withdrawn one. The floor outlives the key it was recorded under.
        let second = keypair();
        sign_store(repo.path(), 4, &second);
        ship_pubkey(repo.path(), &pubkey_of(&second));
        commit_all(&git, repo.path(), "rotate to an older catalogue");
        let err = rekey(
            &layout,
            "hub",
            TrustChoice::Pinned(pubkey_of(&second)),
            &git,
        )
        .unwrap_err();
        assert!(err.contains("refusing to roll back"), "{err}");
        assert_eq!(
            read_configured(&layout, "hub").unwrap().pubkey,
            pubkey_of(&first)
        );
    }

    #[test]
    fn verify_key_refuses_a_store_that_is_not_configured() {
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let err = verify_key(&layout, "ghost", [0u8; 32]).unwrap_err();
        assert!(err.contains("no store named `ghost`"), "{err}");
    }

    #[test]
    fn install_plugin_refuses_a_content_mismatch() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add the store");

        // Tamper the *cached* checkout so the plugin's content no longer reproduces the digest the
        // catalogue pinned — the content gate must catch it and place nothing.
        let cached_exec = layout
            .store_path("default")
            .join("checkout/plugins/pass/resolve");
        std::fs::write(&cached_exec, "#!/bin/sh\necho TAMPERED\n").unwrap();

        let err = install_plugin(&layout, "default", "pass").unwrap_err();
        assert!(err.contains("does not match the catalogue"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
    }

    #[test]
    fn install_plugin_refuses_a_plugin_dir_missing_from_the_checkout() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add the store");

        // The catalogue still lists `pass`, but its directory is gone from the cached checkout.
        std::fs::remove_dir_all(layout.store_path("default").join("checkout/plugins/pass"))
            .unwrap();

        let err = install_plugin(&layout, "default", "pass").unwrap_err();
        assert!(err.contains("not in the cached checkout"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
    }

    #[test]
    fn install_plugin_refuses_a_symlinked_plugin_dir() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add the store");

        // Swap the cached plugin directory for a symlink pointing at an attacker-chosen directory.
        // The guard reads it as "not a directory" (symlink_metadata does not follow) and refuses, so
        // a tampered checkout can never redirect an install outside the verified tree.
        let plugin_dir = layout.store_path("default").join("checkout/plugins/pass");
        let elsewhere = crate::testutil::TmpDir::new();
        std::fs::write(elsewhere.path().join("plugin.toml"), "name = \"x\"\n").unwrap();
        std::fs::remove_dir_all(&plugin_dir).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), &plugin_dir).unwrap();

        let err = install_plugin(&layout, "default", "pass").unwrap_err();
        assert!(err.contains("not in the cached checkout"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
    }

    #[test]
    fn install_plugin_refuses_a_catalogue_that_misadvertises_the_scheme() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let kp = keypair();
        // The manifest claims `secret-store`, but the catalogue advertises `vault`. The catalogue is
        // signed correctly and its `sha256` matches the (unchanged) content, so the signature gate
        // and the content gate both pass — only the install-time reconciliation can refuse it.
        sign_store_with(repo.path(), 1, &kp, "vault");
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey_of(&kp), &git).expect("add the store");

        let err = install_plugin(&layout, "default", "pass").unwrap_err();
        assert!(err.contains("advertises scheme `vault://`"), "{err}");
        assert!(!layout.plugins_dir().join("pass").exists());
    }

    #[test]
    fn install_plugin_refuses_an_unlisted_plugin() {
        let Some(git) = git_or_skip() else { return };
        let repo = crate::testutil::TmpDir::new();
        let data = crate::testutil::TmpDir::new();
        let pubkey = build_signed_store(repo.path(), 1);
        let url = commit_repo(&git, repo.path());
        let layout = crate::store::Layout::under(data.path());
        add(&layout, "default", &url, pubkey, &git).expect("add the store");

        let err = install_plugin(&layout, "default", "ghost").unwrap_err();
        assert!(err.contains("lists no plugin named `ghost`"), "{err}");
    }

    #[test]
    fn install_plugin_refuses_an_unconfigured_store() {
        // No git needed: an unconfigured store is refused before any cache is read.
        let data = crate::testutil::TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let err = install_plugin(&layout, "nope", "pass").unwrap_err();
        assert!(err.contains("no store named `nope`"), "{err}");
    }

    #[test]
    fn swap_into_place_exchanges_two_directories_atomically() {
        let root = crate::testutil::TmpDir::new();
        let new = root.path().join("new");
        let live = root.path().join("live");
        std::fs::create_dir(&new).unwrap();
        std::fs::create_dir(&live).unwrap();
        std::fs::write(new.join("mark"), b"new").unwrap();
        std::fs::write(live.join("mark"), b"old").unwrap();

        swap_into_place(&new, &live).expect("exchange the trees");
        // after the exchange the live path holds the new tree and the stage path holds the old
        assert_eq!(std::fs::read(live.join("mark")).unwrap(), b"new");
        assert_eq!(std::fs::read(new.join("mark")).unwrap(), b"old");
    }

    // --- publish (the signer) ---

    #[test]
    fn publish_signs_a_tree_that_verifies_and_pins_each_plugin() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "pass", "secret-store");
        write_source_plugin(repo.path(), "vault", "vault");
        let key = repo.path().join("store.key");

        let published = publish(repo.path(), &key, Some(3)).unwrap();
        assert_eq!(published.rev, 3);
        assert_eq!(published.plugins.len(), 2);

        // Read the artifacts back from disk — exactly what a consumer fetches.
        let cat_bytes = std::fs::read(repo.path().join(CATALOGUE)).unwrap();
        let sig = crate::plugins::catalogue::decode_hex(
            &std::fs::read_to_string(repo.path().join(CATALOGUE_SIG)).unwrap(),
        )
        .unwrap();
        let pubkey: [u8; 32] = crate::plugins::catalogue::decode_hex(
            &std::fs::read_to_string(repo.path().join(REPO_PUBKEY)).unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        // The shipped `pubkey` file is the key a `--trust` consumer pins — it must be the very key
        // the catalogue was signed with.
        assert_eq!(pubkey, published.pubkey);

        // Verify with the pubkey *from disk*, then check each plugin's pin against its subdirectory:
        // the full consumer chain, which only passes if signer and verifier share one digest and
        // one serialization (the anti-drift guarantee).
        let cat = crate::plugins::catalogue::verified_catalogue(&cat_bytes, &sig, &pubkey).unwrap();
        assert_eq!(cat.rev, 3);
        assert_eq!(cat.plugins.len(), 2);
        for entry in cat.plugins.values() {
            crate::plugins::catalogue::verify_entry(entry, &repo.path().join(&entry.path)).unwrap();
        }

        // The end-of-line guard that keeps the signed bytes byte-exact across a clone is shipped.
        assert_eq!(
            std::fs::read_to_string(repo.path().join(GITATTRIBUTES)).unwrap(),
            "* -text\n"
        );
    }

    #[test]
    fn publish_reuses_an_existing_signing_key() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "pass", "secret-store");
        let key = repo.path().join("store.key");

        let first = publish(repo.path(), &key, Some(1)).unwrap();
        let key_bytes_1 = std::fs::read(&key).unwrap();
        let second = publish(repo.path(), &key, Some(2)).unwrap();
        let key_bytes_2 = std::fs::read(&key).unwrap();

        assert_eq!(
            first.pubkey, second.pubkey,
            "the key must be reused, not regenerated"
        );
        assert_eq!(
            key_bytes_1, key_bytes_2,
            "the key file must be untouched on reuse"
        );
    }

    #[test]
    fn publish_defaults_the_revision_to_one_past_the_existing() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "pass", "secret-store");
        let key = repo.path().join("store.key");

        assert_eq!(publish(repo.path(), &key, None).unwrap().rev, 1);
        assert_eq!(publish(repo.path(), &key, None).unwrap().rev, 2);
        assert_eq!(publish(repo.path(), &key, None).unwrap().rev, 3);
    }

    #[test]
    fn publish_refuses_an_ambiguous_scheme() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "a", "dup");
        write_source_plugin(repo.path(), "b", "dup");
        let key = repo.path().join("store.key");

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        assert!(err.contains("scheme") && err.contains("refusing"), "{err}");
        // A refused publish validates before it touches the key, so none was generated.
        assert!(!key.exists());
    }

    #[test]
    fn publish_refuses_a_subdir_without_a_manifest() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "pass", "secret-store");
        std::fs::create_dir_all(repo.path().join("plugins/stray")).unwrap();
        let key = repo.path().join("store.key");

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        assert!(
            err.contains("stray") && err.contains("plugin.toml"),
            "{err}"
        );
    }

    #[test]
    fn publish_refuses_an_empty_tree() {
        let repo = crate::testutil::TmpDir::new();
        std::fs::create_dir_all(repo.path().join("plugins")).unwrap();
        let key = repo.path().join("store.key");

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        assert!(err.contains("no plugins found"), "{err}");
    }

    #[test]
    fn publish_refuses_a_corrupt_signing_key() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "pass", "secret-store");
        let key = repo.path().join("store.key");
        std::fs::write(&key, b"not a pkcs8 key").unwrap();

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        assert!(err.contains("not a valid Ed25519"), "{err}");
        // A corrupt key is never silently overwritten (which would re-key the store).
        assert_eq!(std::fs::read(&key).unwrap(), b"not a pkcs8 key");
    }

    #[test]
    fn publish_refuses_a_plugin_with_an_unusable_name() {
        let repo = crate::testutil::TmpDir::new();
        let plugin = repo.path().join("plugins/ok-dir");
        std::fs::create_dir_all(&plugin).unwrap();
        // The manifest `name` (not the directory name) is what becomes the catalogue key; the
        // loader does not constrain it, so a space here must be refused at the source.
        std::fs::write(
            plugin.join("plugin.toml"),
            "name = \"bad name\"\ntype = \"resolver\"\nscheme = \"secret-store\"\nexec = \"resolve\"\n",
        )
        .unwrap();
        let exec = plugin.join("resolve");
        std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = repo.path().join("store.key");

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        // A clear refusal at the source, never the round-trip guard's "internal error".
        assert!(
            err.contains("bad name") && !err.contains("internal error"),
            "{err}"
        );
        assert!(!key.exists());
    }

    /// A catalogue is keyed by the manifest `name`, and the map that builds it would take the last
    /// of two claimants while the publish confirmation listed both: two plugins reported shipped, one
    /// in the store, nothing saying which was lost. It never gets that far — the loader's
    /// name-ambiguity rule disables every claimant and `publish` refuses the tree — and this pins
    /// that, because the guard is in a different module from the map that depends on it and a
    /// signer (unlike a resolver, whose `scheme` must be unique on its own account) has no second
    /// rule standing behind it.
    #[test]
    fn publish_refuses_two_plugins_claiming_one_name() {
        let repo = crate::testutil::TmpDir::new();
        for dir in ["plugins/first", "plugins/second"] {
            let plugin = repo.path().join(dir);
            std::fs::create_dir_all(&plugin).unwrap();
            // A signer, not a resolver: a resolver's `scheme` must already be unique, so the name
            // collision would be caught by that rule and never reach this one. A signer claims no
            // scheme, which is exactly where the name was the only key and nothing checked it.
            std::fs::write(
                plugin.join("plugin.toml"),
                "name = \"shared\"\ntype = \"signer\"\nexec = \"resolve\"\n\
                 [signer]\nsets_headers = [\"Authorization\"]\n",
            )
            .unwrap();
            let exec = plugin.join("resolve");
            std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let key = repo.path().join("store.key");

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        assert!(
            err.contains("shared") && err.contains("first") && err.contains("second"),
            "the refusal must name the claim and both claimants: {err}"
        );
        assert!(
            !err.contains("internal error"),
            "refused before the catalogue is built, not by the round-trip guard: {err}"
        );
        assert!(
            !key.exists(),
            "nothing is signed for a tree that cannot publish"
        );
    }

    /// The name collision the loader cannot see. A resolver is indexed by its scheme and a signer
    /// by its name, so two plugins under one name land in different indexes and nothing warns —
    /// while the catalogue, keyed by name alone, keeps whichever comes last. Brokers and signers
    /// are chained after the resolvers, so that is always the one the reviewer did not intend: a
    /// store publishes the signer's tree under the resolver's trusted name, and every downstream
    /// signature, revision floor and per-plugin digest checks out.
    #[test]
    fn publish_refuses_a_resolver_and_a_signer_that_share_one_name() {
        let repo = crate::testutil::TmpDir::new();
        write_source_plugin(repo.path(), "pass", "secret-store");
        let signer = repo.path().join("plugins/pgsign");
        std::fs::create_dir_all(&signer).unwrap();
        std::fs::write(
            signer.join("plugin.toml"),
            "name = \"pass\"\ntype = \"signer\"\nexec = \"resolve\"\n\
             [signer]\nsets_headers = [\"Authorization\"]\n",
        )
        .unwrap();
        let exec = signer.join("resolve");
        std::fs::write(&exec, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&exec, std::fs::Permissions::from_mode(0o755)).unwrap();
        let key = repo.path().join("store.key");

        let err = publish(repo.path(), &key, Some(1)).unwrap_err();
        assert!(
            err.contains("plugins/pass")
                && err.contains("plugins/pgsign")
                && err.contains("name = \"pass\""),
            "the refusal must name the claim and both claimants: {err}"
        );
        assert!(
            !err.contains("internal error"),
            "refused where the key is formed, not by the round-trip guard: {err}"
        );
        assert!(
            !key.exists(),
            "nothing is signed for a tree that cannot publish"
        );
        assert!(
            !repo.path().join(CATALOGUE).exists(),
            "and no catalogue is left behind for the operator to commit"
        );
    }

    /// Whether any `.store-stage-` staging tree survives under the data directory.
    fn leaked_stage(data: &Path) -> bool {
        std::fs::read_dir(data)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(".store-stage-"))
    }
}
