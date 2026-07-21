//! The remote signed plugin store — its offline trust core.
//!
//! A plugin store is a git repository of resolver plugins that sbx fetches on the
//! user's behalf. Because the user does not inspect what is fetched, authenticity
//! cannot come from the transport (git moves bytes and checks their integrity, not
//! their origin); it comes from an Ed25519 signature over a `catalogue.toml` that
//! pins every plugin by a content hash. The trust chain is: the store's public key
//! verifies the catalogue signature, the catalogue's per-plugin `sha256` pins each
//! plugin's directory, and the plugin's own `plugin.toml` is re-validated at install
//! exactly as a locally installed one. Every link fails closed.
//!
//! This module is the link that needs no network and no transport: parse and verify
//! the catalogue, and recompute a plugin directory's content digest. The git fetch,
//! the per-store cache, and the embedded default public key live with their
//! consumers (`crate::stores` and the `plugins` command surface).

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};

/// One plugin as listed in a store's signed catalogue.
///
/// The fields are the store's *pre-fetch claims*: `scheme`/`version`/`description`
/// let the user browse without fetching, while `sha256` is the load-bearing pin —
/// the [`dir_digest`] a plugin's directory must reproduce once fetched. Authoritative
/// validation is still the plugin's own `plugin.toml` at install time, so a catalogue
/// claim that disagrees with the manifest is reconciled there (fail-closed), not
/// trusted blindly here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogueEntry {
    pub scheme: String,
    pub version: String,
    pub description: String,
    pub path: String,
    pub sha256: String,
}

/// A store's catalogue: a monotonic revision and its plugins keyed by name, in sorted
/// order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Catalogue {
    /// A monotonically increasing revision the store author stamps on each publish. It
    /// anchors freshness: a fetch refuses a catalogue whose `rev` is below the one last
    /// accepted, so a validly-signed but *stale* listing cannot replay a withdrawn or
    /// downgraded plugin. Absent in the TOML means `0` (an unversioned store, the floor).
    pub rev: u64,
    pub plugins: BTreeMap<String, CatalogueEntry>,
}

#[derive(Debug, Deserialize)]
struct RawCatalogue {
    #[serde(default)]
    rev: u64,
    #[serde(default)]
    plugin: BTreeMap<String, RawEntry>,
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    scheme: String,
    version: String,
    #[serde(default)]
    description: String,
    path: String,
    sha256: String,
}

impl Catalogue {
    /// Parse and validate a `catalogue.toml`. Pure: it checks structure only — the
    /// name and scheme charsets (the same rules the installer enforces, so a listed
    /// plugin can actually be installed under its name), a repo-relative `path` with
    /// no `..`, and a 64-hex `sha256`. It does **not** verify the signature; that is
    /// [`verify_catalogue`], and the two are composed by [`verified_catalogue`] so
    /// verification always runs on the exact bytes parsed.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Catalogue, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "catalogue.toml is not valid UTF-8")?;
        let raw: RawCatalogue =
            toml::from_str(text).map_err(|e| format!("invalid catalogue.toml: {e}"))?;
        let mut plugins = BTreeMap::new();
        for (name, entry) in raw.plugin {
            let here = |e: String| format!("catalogue entry `{name}`: {e}");
            crate::plugins::validate_install_name(&name).map_err(here)?;
            crate::plugins::validate_scheme(&entry.scheme).map_err(here)?;
            validate_repo_path(&entry.path).map_err(here)?;
            validate_sha256(&entry.sha256).map_err(here)?;
            // The free-text fields are displayed verbatim (`sbx plugins store list/info`), and a
            // TOML basic string can carry a control byte via a `\uXXXX` escape; the serializer
            // refuses control chars, so mirror that on the consuming side (a legitimately-published
            // store never carries one) to keep a TOFU-pinned store from injecting terminal escapes.
            validate_free_text("version", &entry.version).map_err(here)?;
            validate_free_text("description", &entry.description).map_err(here)?;
            plugins.insert(
                name,
                CatalogueEntry {
                    scheme: entry.scheme,
                    version: entry.version,
                    description: entry.description,
                    path: entry.path,
                    sha256: entry.sha256,
                },
            );
        }
        Ok(Catalogue {
            rev: raw.rev,
            plugins,
        })
    }
}

/// Verify a detached Ed25519 signature over the catalogue bytes with a store's
/// public key. Fail-closed: a wrong key, tampered bytes, or a malformed signature all
/// return the same opaque error (no verification oracle).
pub(crate) fn verify_catalogue(
    catalogue_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<(), String> {
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(catalogue_bytes, signature)
        .map_err(|_| "store catalogue signature verification failed".to_string())
}

/// Verify a catalogue's signature and parse the **same** bytes — the single
/// chokepoint that binds the verdict to the consumed artifact, so a re-serialized or
/// swapped buffer can never be parsed as if it were the signed one. Verify first;
/// parse only on success.
pub(crate) fn verified_catalogue(
    catalogue_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<Catalogue, String> {
    verify_catalogue(catalogue_bytes, signature, public_key)?;
    Catalogue::parse(catalogue_bytes)
}

/// The deterministic content digest of a plugin directory, as pinned by a catalogue
/// entry's `sha256`. It covers exactly what git records — the set of regular files,
/// their repo-relative paths (`/`-separated), the executable bit, and their bytes — so
/// a clone of the store reproduces it; it ignores mtime, owner, and the non-exec mode
/// bits, which git does not track. The framing per file, in path-sorted order, is
/// `relpath ‖ 0x00 ‖ ('1'|'0') ‖ 0x00 ‖ sha256(bytes) ‖ '\n'`, hashed with SHA-256. A
/// symlink or any non-regular file is refused (fail-closed: a store must not smuggle a
/// link or device into a trusted tree).
pub(crate) fn dir_digest(root: &Path) -> Result<[u8; 32], String> {
    // The children of every directory are lstat'd as they are walked, refusing any symlink or
    // non-regular file — but the root handed in is not walked, only read, so check it here too.
    // A symlinked root would otherwise be followed by `read_dir`, letting a fetched store redirect
    // a plugin's whole directory outside the verified checkout; refuse it fail-closed at the source,
    // so `verify_entry` and every other caller inherit the guarantee.
    let root_meta =
        std::fs::symlink_metadata(root).map_err(|e| format!("stat {}: {e}", root.display()))?;
    if root_meta.file_type().is_symlink() {
        return Err(format!("plugin root is a symlink: {}", root.display()));
    }
    if !root_meta.is_dir() {
        return Err(format!(
            "plugin root is not a directory: {}",
            root.display()
        ));
    }

    let mut entries: Vec<(String, bool, [u8; 32])> = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut h = Sha256::new();
    for (rel, exec, file_hash) in &entries {
        h.update(rel.as_bytes());
        h.update([0u8]);
        h.update([if *exec { b'1' } else { b'0' }]);
        h.update([0u8]);
        h.update(file_hash);
        h.update(*b"\n");
    }
    Ok(h.finalize().into())
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, bool, [u8; 32])>,
) -> Result<(), String> {
    let rd = std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("reading {}: {e}", dir.display()))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("stat {}: {e}", path.display()))?;
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(format!(
                "plugin tree contains a symlink: {}",
                path.display()
            ));
        } else if ft.is_dir() {
            collect_files(root, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|_| format!("path {} is not under the plugin root", path.display()))?;
            let rel = repo_rel(rel)?;
            let bytes =
                std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            let exec = (meta.permissions().mode() & 0o111) != 0;
            out.push((rel, exec, Sha256::digest(&bytes).into()));
        } else {
            return Err(format!(
                "plugin tree contains a non-regular file: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// A path relative to the plugin root, as a `/`-joined string of plain components —
/// the stable key the digest sorts and frames by. A non-`Normal` component or a
/// non-UTF-8 name is refused (it could not be reproduced portably across a clone).
fn repo_rel(rel: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(s) => {
                let s = s.to_str().ok_or_else(|| {
                    format!("plugin tree has a non-UTF-8 path: {}", rel.display())
                })?;
                parts.push(s);
            }
            _ => {
                return Err(format!(
                    "plugin tree has an unexpected path: {}",
                    rel.display()
                ))
            }
        }
    }
    Ok(parts.join("/"))
}

/// Whether a fetched plugin directory reproduces the digest the catalogue pinned —
/// the content half of the trust chain, checked after the signature gate. Fail-closed
/// and named, so a mismatch points at the offending plugin.
pub(crate) fn verify_entry(entry: &CatalogueEntry, root: &Path) -> Result<(), String> {
    let got = to_hex(&dir_digest(root)?);
    if got == entry.sha256 {
        Ok(())
    } else {
        Err(format!(
            "plugin content does not match the catalogue (expected {}, got {got})",
            entry.sha256
        ))
    }
}

/// A `path` field from the catalogue: a non-empty, repo-relative location with no
/// `..`, `.`, or absolute parts — so a fetched plugin can never be read from outside
/// the cloned store.
fn validate_repo_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("`path` is empty".to_string());
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(format!(
            "`path` `{path}` must be relative to the repository"
        ));
    }
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(format!(
            "`path` `{path}` must be a plain path inside the repository \
             (no `..`, `.`, or absolute parts)"
        ));
    }
    Ok(())
}

/// A `sha256` field from the catalogue: exactly 64 lowercase hex characters, the
/// shape [`to_hex`] produces, so the comparison in [`verify_entry`] is well-defined.
fn validate_sha256(hash: &str) -> Result<(), String> {
    let ok = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "`sha256` `{hash}` must be 64 lowercase hex characters"
        ))
    }
}

/// Lowercase hex of a byte string — the encoding a catalogue's `sha256`, a store's
/// public key, and a detached signature all travel in (text-safe across a git clone,
/// unlike raw bytes). The inverse of [`decode_hex`].
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Serialize a catalogue back to the exact `[plugin.<name>]` TOML shape [`Catalogue::parse`]
/// accepts — the producing side of the format, used when signing a store. Deterministic: the
/// `rev` first, then each plugin in the map's sorted order, fields in a fixed order, so the same
/// catalogue always yields the same bytes (the bytes a signature is taken over). Every name and
/// value is emitted as a quoted TOML string, which round-trips any valid install name (including
/// one with a `.`, which a bare key would mis-parse as nested tables) and any manifest text. A
/// control character (including a newline) in a free field — `version` or `description` from a
/// plugin's manifest — is refused fail-closed rather than escaped, so a manifest cannot smuggle a
/// second key/value into the signed catalogue. The constrained fields (`scheme`/`path`/`sha256`)
/// carry no such characters, but pass through the same guard uniformly.
pub(crate) fn serialize_catalogue(cat: &Catalogue) -> Result<String, String> {
    let mut out = format!("rev = {}\n", cat.rev);
    for (name, entry) in &cat.plugins {
        out.push('\n');
        out.push_str(&format!("[plugin.{}]\n", toml_quoted(name)?));
        out.push_str(&format!("scheme = {}\n", toml_quoted(&entry.scheme)?));
        out.push_str(&format!("version = {}\n", toml_quoted(&entry.version)?));
        out.push_str(&format!(
            "description = {}\n",
            toml_quoted(&entry.description)?
        ));
        out.push_str(&format!("path = {}\n", toml_quoted(&entry.path)?));
        out.push_str(&format!("sha256 = {}\n", toml_quoted(&entry.sha256)?));
    }
    Ok(out)
}

/// Refuse a control character in a catalogue free-text field (`version`/`description`), which is
/// displayed verbatim. The serializer refuses them too, so this is symmetric: no legitimately-
/// published store carries one, and a malicious TOFU-pinned store cannot smuggle a terminal escape.
fn validate_free_text(field: &str, s: &str) -> Result<(), String> {
    match s.chars().find(|c| c.is_control()) {
        Some(bad) => Err(format!(
            "`{field}` contains a control character (U+{:04X})",
            bad as u32
        )),
        None => Ok(()),
    }
}

/// Render a string as a TOML basic string (`"..."`), refusing any control character and escaping
/// the two characters a basic string cannot carry raw (`\` and `"`). The same rules apply to a
/// quoted bare key, so this renders both a `[plugin."<name>"]` key and a field value.
fn toml_quoted(s: &str) -> Result<String, String> {
    if let Some(bad) = s.chars().find(|c| c.is_control()) {
        return Err(format!(
            "value `{}` contains a control character (U+{:04X}) and cannot be serialized",
            s.escape_default(),
            bad as u32
        ));
    }
    Ok(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// Decode a lowercase-hex string back to bytes, trimming surrounding ASCII whitespace
/// first (a `.sig` or key file committed to git may carry a trailing newline). Strict
/// on the hex itself: an odd length or a non-`[0-9a-f]` character is refused, so a
/// malformed signature or key fails closed rather than decoding to silent garbage.
pub(crate) fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("hex input has an odd number of digits".to_string());
    }
    let val = |b: u8| -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(format!("hex input has a non-hex character `{}`", b as char)),
        }
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push(val(pair[0])? << 4 | val(pair[1])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::os::unix::ffi::OsStrExt;

    fn gen_key() -> (Ed25519KeyPair, [u8; 32]) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        (kp, pk)
    }

    fn sign(kp: &Ed25519KeyPair, msg: &[u8]) -> Vec<u8> {
        kp.sign(msg).as_ref().to_vec()
    }

    fn write(path: &Path, bytes: &[u8], exec: bool) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, bytes).unwrap();
        let mode = if exec { 0o755 } else { 0o644 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn sample_catalogue() -> String {
        let h = "a".repeat(64);
        format!(
            "[plugin.pass]\n\
             scheme = \"pass\"\n\
             version = \"0.1.0\"\n\
             description = \"the password-store resolver\"\n\
             path = \"plugins/pass\"\n\
             sha256 = \"{h}\"\n\
             \n\
             [plugin.vault]\n\
             scheme = \"vault\"\n\
             version = \"0.2.0\"\n\
             description = \"the HashiCorp Vault resolver\"\n\
             path = \"plugins/vault\"\n\
             sha256 = \"{h}\"\n"
        )
    }

    // --- the digest: independent golden, sort, and the discriminants it must catch ---

    #[test]
    fn dir_digest_matches_an_independently_constructed_preimage() {
        let root = crate::testutil::TmpDir::new();
        // Three files whose repo-relative paths sort non-trivially: byte order puts
        // `a/z` (`a`,0x2f,…) before `ab` (`a`,0x62,…), then `plugin.toml`. So the test
        // also exercises the sort, not just the per-file framing.
        write(&root.path().join("ab"), b"one", false);
        write(&root.path().join("a/z"), b"two", true);
        write(&root.path().join("plugin.toml"), b"three", false);

        // Rebuild the expected digest by hand from the documented framing — NOT by
        // capturing `dir_digest`'s own output, so a wrong sort or framing fails here.
        let mut pre = Vec::new();
        for (rel, exec, content) in [
            ("a/z", true, &b"two"[..]),
            ("ab", false, &b"one"[..]),
            ("plugin.toml", false, &b"three"[..]),
        ] {
            pre.extend_from_slice(rel.as_bytes());
            pre.push(0);
            pre.push(if exec { b'1' } else { b'0' });
            pre.push(0);
            pre.extend_from_slice(&Sha256::digest(content));
            pre.push(b'\n');
        }
        let expected: [u8; 32] = Sha256::digest(&pre).into();

        assert_eq!(dir_digest(root.path()).unwrap(), expected);
    }

    #[test]
    fn changing_a_file_changes_the_digest() {
        let a = crate::testutil::TmpDir::new();
        let b = crate::testutil::TmpDir::new();
        write(&a.path().join("resolve"), b"original", true);
        write(&b.path().join("resolve"), b"tampered", true);
        assert_ne!(dir_digest(a.path()).unwrap(), dir_digest(b.path()).unwrap());
    }

    #[test]
    fn flipping_the_exec_bit_changes_the_digest() {
        let a = crate::testutil::TmpDir::new();
        let b = crate::testutil::TmpDir::new();
        write(&a.path().join("resolve"), b"same", true);
        write(&b.path().join("resolve"), b"same", false);
        assert_ne!(dir_digest(a.path()).unwrap(), dir_digest(b.path()).unwrap());
    }

    #[test]
    fn a_symlink_in_the_tree_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write(&root.path().join("plugin.toml"), b"x", false);
        std::os::unix::fs::symlink("/etc/passwd", root.path().join("link")).unwrap();
        assert!(dir_digest(root.path()).is_err());
    }

    #[test]
    fn a_symlink_root_is_refused() {
        // A real plugin directory, plus a symlink pointing *at* it. Digesting through the symlink
        // must be refused (the children-only symlink check would otherwise follow the root).
        let real = crate::testutil::TmpDir::new();
        write(&real.path().join("plugin.toml"), b"x", false);
        let link = real.path().join("link-root");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        let err = dir_digest(&link).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn a_non_regular_file_in_the_tree_is_refused() {
        let root = crate::testutil::TmpDir::new();
        write(&root.path().join("plugin.toml"), b"x", false);
        let fifo = root.path().join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(dir_digest(root.path()).is_err());
    }

    #[test]
    fn verify_entry_passes_then_fails_when_the_content_drifts() {
        let root = crate::testutil::TmpDir::new();
        write(&root.path().join("plugin.toml"), b"hello", false);
        let entry = CatalogueEntry {
            scheme: "pass".into(),
            version: "0.1.0".into(),
            description: String::new(),
            path: "plugins/pass".into(),
            sha256: to_hex(&dir_digest(root.path()).unwrap()),
        };
        verify_entry(&entry, root.path()).unwrap();

        write(&root.path().join("plugin.toml"), b"changed", false);
        assert!(verify_entry(&entry, root.path()).is_err());
    }

    // --- the signature ---

    #[test]
    fn a_valid_signature_verifies_and_a_tampered_one_does_not() {
        let (kp, pk) = gen_key();
        let msg = sample_catalogue();
        let sig = sign(&kp, msg.as_bytes());

        verify_catalogue(msg.as_bytes(), &sig, &pk).unwrap();
        // tampered bytes
        let mut bad = msg.clone().into_bytes();
        bad[0] ^= 0x01;
        assert!(verify_catalogue(&bad, &sig, &pk).is_err());
        // tampered signature
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(verify_catalogue(msg.as_bytes(), &bad_sig, &pk).is_err());
    }

    #[test]
    fn a_signature_from_another_key_is_refused() {
        let (kp1, _) = gen_key();
        let (_, pk2) = gen_key();
        let msg = sample_catalogue();
        let sig = sign(&kp1, msg.as_bytes());
        assert!(verify_catalogue(msg.as_bytes(), &sig, &pk2).is_err());
    }

    #[test]
    fn verified_catalogue_verifies_before_it_parses() {
        let (kp, pk) = gen_key();
        let (other, _) = gen_key();

        // a signature by the right key over a good catalogue → verify, then parse
        let good = sample_catalogue();
        let cat = verified_catalogue(good.as_bytes(), &sign(&kp, good.as_bytes()), &pk).unwrap();
        assert_eq!(cat.plugins.len(), 2);

        // Unparseable bytes prove the *ordering*, not just the outcome: with the
        // wrong key the error is the signature (parse never ran), with the right key
        // the error is the parse (verify passed, then parse ran) — so a bad signature
        // short-circuits before the parser ever sees the bytes.
        let junk = b"not valid toml @@@";
        let by_wrong = verified_catalogue(junk, &sign(&other, junk), &pk).unwrap_err();
        assert!(by_wrong.contains("signature"), "{by_wrong}");
        let by_right = verified_catalogue(junk, &sign(&kp, junk), &pk).unwrap_err();
        assert!(by_right.contains("invalid catalogue.toml"), "{by_right}");
    }

    // --- catalogue parsing and validation ---

    #[test]
    fn a_well_formed_catalogue_parses_every_field() {
        let cat = Catalogue::parse(sample_catalogue().as_bytes()).unwrap();
        // `rev` is absent in the sample → the unversioned floor.
        assert_eq!(cat.rev, 0);
        assert_eq!(cat.plugins.len(), 2);
        let vault = &cat.plugins["vault"];
        assert_eq!(vault.scheme, "vault");
        assert_eq!(vault.version, "0.2.0");
        assert_eq!(vault.description, "the HashiCorp Vault resolver");
        assert_eq!(vault.path, "plugins/vault");
        assert_eq!(vault.sha256, "a".repeat(64));
    }

    #[test]
    fn a_catalogue_revision_parses() {
        let with_rev = format!("rev = 7\n{}", sample_catalogue());
        let cat = Catalogue::parse(with_rev.as_bytes()).unwrap();
        assert_eq!(cat.rev, 7);
        assert_eq!(cat.plugins.len(), 2);
    }

    #[test]
    fn an_empty_catalogue_is_valid_and_empty() {
        let cat = Catalogue::parse(b"").unwrap();
        assert_eq!(cat.rev, 0);
        assert!(cat.plugins.is_empty());
    }

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(
            decode_hex("000fa5ff").unwrap(),
            vec![0x00, 0x0f, 0xa5, 0xff]
        );
        // a trailing newline (as a committed `.sig`/key file carries) is tolerated
        assert_eq!(decode_hex("00ff\n").unwrap(), vec![0x00, 0xff]);
        // odd length, a non-hex digit, and uppercase are all refused
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
        assert!(decode_hex("00FF").is_err());
    }

    #[test]
    fn a_catalogue_round_trips_through_serialization() {
        // A free-text description with the two characters TOML basic strings must escape, and a
        // dotted name a bare key would mis-parse — both must survive serialize → parse unchanged.
        let mut plugins = BTreeMap::new();
        plugins.insert(
            "pass.v2".to_string(),
            CatalogueEntry {
                scheme: "secret-store".into(),
                version: "0.1.0".into(),
                description: r#"a "quoted" \back\slash"#.into(),
                path: "plugins/pass".into(),
                sha256: "a".repeat(64),
            },
        );
        plugins.insert(
            "vault".to_string(),
            CatalogueEntry {
                scheme: "vault".into(),
                version: String::new(),
                description: String::new(),
                path: "plugins/vault".into(),
                sha256: "b".repeat(64),
            },
        );
        let cat = Catalogue { rev: 9, plugins };
        let text = serialize_catalogue(&cat).unwrap();
        assert_eq!(Catalogue::parse(text.as_bytes()).unwrap(), cat);
    }

    #[test]
    fn serializing_a_control_character_is_refused() {
        let mut plugins = BTreeMap::new();
        plugins.insert(
            "pass".to_string(),
            CatalogueEntry {
                scheme: "pass".into(),
                version: "0.1.0".into(),
                // A newline in the description would otherwise smuggle a second TOML line into the
                // signed catalogue.
                description: "line one\nkey = \"evil\"".into(),
                path: "plugins/pass".into(),
                sha256: "a".repeat(64),
            },
        );
        let err = serialize_catalogue(&Catalogue { rev: 1, plugins }).unwrap_err();
        assert!(err.contains("control character"), "{err}");
    }

    fn one_entry(field: &str, value: &str) -> String {
        let mut scheme = "pass".to_string();
        let mut version = "0.1.0".to_string();
        let mut path = "plugins/pass".to_string();
        let mut sha256 = "a".repeat(64);
        match field {
            "scheme" => scheme = value.to_string(),
            "version" => version = value.to_string(),
            "path" => path = value.to_string(),
            "sha256" => sha256 = value.to_string(),
            other => panic!("unknown field `{other}`"),
        }
        format!(
            "[plugin.pass]\nscheme = \"{scheme}\"\nversion = \"{version}\"\n\
             path = \"{path}\"\nsha256 = \"{sha256}\"\n"
        )
    }

    #[test]
    fn a_bad_sha256_is_refused() {
        assert!(Catalogue::parse(one_entry("sha256", "deadbeef").as_bytes()).is_err());
        assert!(Catalogue::parse(one_entry("sha256", &"A".repeat(64)).as_bytes()).is_err());
    }

    #[test]
    fn a_control_character_in_a_free_text_field_is_refused() {
        // A `\uXXXX` escape decodes to a real control byte in the value; the serializer refuses
        // control chars, so the parser must too — a TOFU-pinned store cannot smuggle a terminal
        // escape sequence into the verbatim-displayed version/description (the escape is U+001B).
        assert!(Catalogue::parse(one_entry("version", "\\u001b]0;x").as_bytes()).is_err());
        // a clean value still parses
        assert!(Catalogue::parse(one_entry("version", "1.2.3").as_bytes()).is_ok());
    }

    #[test]
    fn a_path_escaping_the_repository_is_refused() {
        assert!(Catalogue::parse(one_entry("path", "../etc").as_bytes()).is_err());
        assert!(Catalogue::parse(one_entry("path", "/etc/passwd").as_bytes()).is_err());
    }

    #[test]
    fn a_bad_name_or_a_builtin_scheme_is_refused() {
        // a name that could not be an install directory
        let bad_name = "[plugin.\".hidden\"]\nscheme = \"pass\"\nversion = \"0\"\n\
                        path = \"p\"\nsha256 = \""
            .to_string()
            + &"a".repeat(64)
            + "\"\n";
        assert!(Catalogue::parse(bad_name.as_bytes()).is_err());
        // a built-in scheme a plugin may never claim
        assert!(Catalogue::parse(one_entry("scheme", "env").as_bytes()).is_err());
    }
}
