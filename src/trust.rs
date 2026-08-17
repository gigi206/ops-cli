//! The project-config trust store (the direnv model).
//!
//! A project's `.sbx.toml` is attacker-controlled, so its security-relevant
//! fields are honored only once the user has vouched for the file's *contents*.
//! `sbx trust` records a marker keyed by the config's canonical path, holding a
//! SHA-256 of the whole file. Any later edit changes that hash, so the marker no
//! longer matches and the project must be re-trusted — exactly like `direnv
//! allow` re-arming when `.envrc` changes.
//!
//! Hashing the whole file (not a parsed subset of "security fields") keeps this
//! gate independent of the config schema and faithful to direnv: any change at
//! all re-prompts, which is the safe superset of "a security-relevant change
//! re-prompts". The cryptographic hash is load-bearing — a forgeable hash would
//! let an attacker craft a malicious config that matches a trusted marker.
//!
//! A project may also declare tools in a sibling `mise` file, which is itself
//! attacker-controlled and drives host-side resolution once provisioning lands.
//! So trust is the single authority over *both* declarative inputs: the recorded
//! hash folds in the mise file's contents too, and editing either file re-arms
//! the gate. The mise file is anchored on the `.sbx.toml`: it is hashed (and
//! later honored) only beside one, keyed by the `.sbx.toml` path.

use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

/// A project's mise files as validated input: each as `(filename, bytes)`, in
/// precedence order. The trust hash folds these in, and the launcher maps them — so
/// the same type carries the bytes from the safety gate to both consumers.
pub(crate) type MiseInputs = Vec<(String, Vec<u8>)>;

/// Lowercase hex SHA-256 of a buffer. The single hasher for both the marker key
/// (a path string) and the content hash, so the two can never diverge.
pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Candidate mise config filenames beside the `.sbx.toml`, highest precedence
/// first. Every one that exists is part of "the project's mise configuration" — all
/// are folded into the trust hash. The set covers mise's *same-directory* discovery
/// names: the local override, the two canonical config files, and the idiomatic
/// `.tool-versions`. It stays in lockstep with the set a later stage authorizes mise
/// to read, or an unhashed file would reach resolution — which is why the wider
/// reaches of mise's own discovery (parent-directory configs, the user-global config,
/// env-specific `mise.<env>.toml`) are deliberately *out*: they live outside the
/// project root the trust gate anchors on, so admitting them would let a file sbx
/// never hashed steer resolution.
const MISE_CONFIG_NAMES: &[&str] = &[
    "mise.local.toml",
    ".mise.toml",
    "mise.toml",
    ".tool-versions",
];

/// Every mise file beside `config_path` (the `.sbx.toml`) that exists, in
/// precedence order — empty when the directory has none. *All* of them are folded
/// into the trust hash, not just the first: the direnv "any change re-prompts"
/// superset, so a tool entry hidden in a lower-precedence file cannot ride along
/// unhashed. Pure path logic; the authoritative, safety-gated read is
/// [`mise_inputs_for`]. The set folded here is the contract for what a later stage
/// may authorize mise to read — they must stay identical, or an unhashed file
/// would reach resolution.
pub(crate) fn mise_files_for(config_path: &Path) -> Vec<PathBuf> {
    match config_path.parent() {
        Some(dir) => MISE_CONFIG_NAMES
            .iter()
            .map(|name| dir.join(name))
            .filter(|p| p.exists())
            .collect(),
        None => Vec::new(),
    }
}

/// Read every mise file beside `config_path` through the same safety gate the
/// `.sbx.toml` uses, returning each as `(filename, bytes)` in precedence order for
/// folding into the trust hash. Empty when the project has none; `Err` when any is
/// present but unsafe or unreadable. The error is load-bearing: an unverifiable
/// companion file means the project's trusted content cannot be confirmed, so every
/// caller must fail closed rather than fall back to the `.sbx.toml` alone.
pub(crate) fn mise_inputs_for(config_path: &Path) -> io::Result<MiseInputs> {
    let mut out = Vec::new();
    for path in mise_files_for(config_path) {
        let bytes = crate::config::safety::read_safe_bytes(&path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push((name, bytes));
    }
    Ok(out)
}

/// The trust content hash for a project: the `.sbx.toml` bytes alone when the
/// project has no mise file — so a project that never had one keeps a marker
/// byte-identical to hashing the single file — or an unambiguous framing of the
/// `.sbx.toml` and *every* mise file when it has some. Each part is domain-tagged
/// (the mise parts by filename) and length-prefixed, never a bare concatenation, so
/// among *has-mise* inputs no two distinct sets share an encoding: a change to any
/// file — or moving an entry between files — always changes the hash.
///
/// The no-mise fast path is an intentional exception (it hashes the raw file, for the
/// backward-compatible marker). A cross-mode collision — a no-mise state hashing the same
/// as a has-mise one — would require the trusted `.sbx.toml` bytes to *begin with the internal
/// framing header* (`sbx.toml\0` + a length), which a real, user-reviewed TOML config never does
/// (it embeds a NUL), so the "any change re-arms trust" guarantee holds for every real input.
pub(crate) fn content_hash(sbx_bytes: &[u8], mise_inputs: &[(String, Vec<u8>)]) -> String {
    if mise_inputs.is_empty() {
        return hash_bytes(sbx_bytes);
    }
    let extra: usize = mise_inputs.iter().map(|(n, b)| n.len() + b.len()).sum();
    let mut buf = Vec::with_capacity(sbx_bytes.len() + extra + 32);
    frame(&mut buf, b"sbx.toml", sbx_bytes);
    for (name, bytes) in mise_inputs {
        frame(&mut buf, name.as_bytes(), bytes);
    }
    hash_bytes(&buf)
}

/// Append `tag\0`, the 8-byte little-endian length of `bytes`, then `bytes`. The
/// tag and length make the boundary between framed parts unambiguous.
fn frame(buf: &mut Vec<u8>, tag: &[u8], bytes: &[u8]) {
    buf.extend_from_slice(tag);
    buf.push(0);
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Trust state of a project config relative to a store dir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TrustState {
    /// A marker exists and its stored hash matches the file's current contents.
    Trusted,
    /// No marker for this config path — never approved.
    Untrusted,
    /// A marker exists but the stored hash differs: the file changed since it was
    /// trusted, so it must be re-approved before its security fields apply again.
    Changed,
}

/// Default trust store dir: `$XDG_STATE_HOME/sbx/trusted` when that is an
/// absolute path, else `$HOME/.local/state/sbx/trusted`. `None` when neither
/// yields an absolute base.
///
/// The absolute-path requirement is a security control, not a nicety: a relative
/// base would resolve the store against the process's current directory, so a
/// cloned repo could ship its own `…/sbx/trusted/<key>` next to a malicious
/// `.sbx.toml` and pre-approve itself. A relative value is therefore ignored,
/// never trusted.
pub(crate) fn default_store_dir() -> Option<PathBuf> {
    store_dir_from(
        std::env::var_os("XDG_STATE_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

/// Pure core of [`default_store_dir`], so the absolute-path guard is testable
/// without touching the environment.
fn store_dir_from(xdg: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    if let Some(xdg) = xdg {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return Some(p.join("sbx").join("trusted"));
        }
    }
    let home = PathBuf::from(home?);
    if home.is_absolute() {
        return Some(home.join(".local/state/sbx/trusted"));
    }
    None
}

/// Canonicalized path string used as the marker key. When the file itself cannot
/// be canonicalized (typically: it no longer exists), its parent is canonicalized
/// and the file name re-appended, so `sbx trust` (file present) and a later
/// `sbx untrust` (file deleted) still derive the same key. Only when even the
/// parent is gone does it fall back to the raw path. Never panics.
fn canonical_string(config_path: &Path) -> String {
    let resolved = config_path.canonicalize().unwrap_or_else(|_| {
        match (config_path.parent(), config_path.file_name()) {
            (Some(parent), Some(name)) => parent
                .canonicalize()
                .map(|p| p.join(name))
                .unwrap_or_else(|_| config_path.to_path_buf()),
            _ => config_path.to_path_buf(),
        }
    });
    resolved.to_string_lossy().into_owned()
}

/// Marker file path: `store_dir/<sha256 of the canonical config-path string>`.
pub(crate) fn marker_path(store_dir: &Path, config_path: &Path) -> PathBuf {
    let key = hash_bytes(canonical_string(config_path).as_bytes());
    store_dir.join(key)
}

/// Trust verdict for a config whose current content hash is already known.
///
/// Lets a caller read the file once (hash and parse the same bytes), so the hash
/// that is compared and the bytes that are applied cannot diverge.
pub(crate) fn verdict_for_hash(
    store_dir: &Path,
    config_path: &Path,
    current_hash: &str,
) -> TrustState {
    let marker = marker_path(store_dir, config_path);
    let contents = match std::fs::read_to_string(&marker) {
        Ok(c) => c,
        Err(_) => return TrustState::Untrusted,
    };
    // Marker layout: line 1 = canonical path, line 2 = stored content hash. A
    // marker that exists but is malformed (the hash line missing — a truncated
    // write or manual edit) still proves a trust WAS recorded, so it is reported
    // `Changed` (re-approval needed), never `Untrusted` (never approved).
    let stored_hash = match contents.lines().nth(1) {
        Some(h) => h.trim(),
        None => return TrustState::Changed,
    };
    if stored_hash == current_hash {
        TrustState::Trusted
    } else {
        TrustState::Changed
    }
}

/// Current trust state of `config_path` under `store_dir`. Reads through the same
/// safety gate the loader uses, so a file the loader would reject (world-writable,
/// foreign-owned) or cannot read is reported `Untrusted`, never `Trusted` — the
/// displayed verdict matches what a launch would actually act on. A sibling mise
/// file that is present but unsafe is also reported `Untrusted`: the trusted
/// content folds in that file, and an unverifiable one cannot yield `Trusted`.
pub(crate) fn state(store_dir: &Path, config_path: &Path) -> TrustState {
    let sbx_bytes = match crate::config::safety::read_safe_bytes(config_path) {
        Ok(b) => b,
        Err(_) => return TrustState::Untrusted,
    };
    let mise_inputs = match mise_inputs_for(config_path) {
        Ok(m) => m,
        Err(_) => return TrustState::Untrusted,
    };
    verdict_for_hash(
        store_dir,
        config_path,
        &content_hash(&sbx_bytes, &mise_inputs),
    )
}

/// Record trust for `config_path`: hash the file's current contents — and those of
/// a sibling mise file, when present — and write the marker. Every byte is read
/// through the safety gate, so a world-writable or foreign-owned `.sbx.toml` *or*
/// mise file is refused rather than blessed, and the hash covers exactly the gated
/// bytes of both.
pub(crate) fn trust(store_dir: &Path, config_path: &Path) -> io::Result<()> {
    // Every error out of this function opens with the file it is about, so a caller can name the
    // action alone (`could not re-trust {e}`) instead of prefixing a path the message already
    // carries. The two reads get that from the safety gate, which is also the only layer that knows
    // *which* of the two files failed (the config, or the sibling mise file its hash covers); the
    // store-side failures are given it here, plus the store path, because "the marker could not be
    // written" is a different fact from "this file cannot be read" and the reader needs both.
    let store_err = |e: io::Error| {
        io::Error::new(
            e.kind(),
            format!(
                "{}: cannot write its trust marker under {}: {e}",
                config_path.display(),
                store_dir.display()
            ),
        )
    };
    let sbx_bytes = crate::config::safety::read_safe_bytes(config_path)?;
    let mise_inputs = mise_inputs_for(config_path)?;
    let hash = content_hash(&sbx_bytes, &mise_inputs);

    // Create the store owner-only from the start, so a loose umask never leaves a
    // world-readable window between creation and tightening, and tighten a dir
    // that already existed with looser bits. Each marker records a path you trust
    // — not a secret, but no reason to expose your project layout to other users.
    {
        use std::fs::{DirBuilder, Permissions};
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(store_dir)
            .map_err(&store_err)?;
        std::fs::set_permissions(store_dir, Permissions::from_mode(0o700)).map_err(&store_err)?;
    }
    let body = format!("{}\n{}\n", canonical_string(config_path), hash);
    std::fs::write(marker_path(store_dir, config_path), body).map_err(&store_err)
}

/// Remove any trust marker for `config_path`. Returns whether one existed, so the
/// caller can tell "revoked" from "was not trusted". A missing marker is success,
/// not an error.
pub(crate) fn untrust(store_dir: &Path, config_path: &Path) -> io::Result<bool> {
    match std::fs::remove_file(marker_path(store_dir, config_path)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn both_error_families_open_with_the_file_they_are_about() {
        use std::os::unix::fs::PermissionsExt as _;
        // A caller renders these under an action alone (`cannot trust {e}`), so an error that does
        // not name its file leaves the reader with none. The gate supplies that for the read side;
        // the store side is the branch that would otherwise come back pathless, and it also has to
        // say which of the two facts failed, since "cannot read this config" and "cannot write its
        // marker" call for different remedies.
        let tmp = TmpDir::new();
        let cfg = tmp.join("sbx.toml");
        std::fs::write(&cfg, b"network = \"none\"\n").unwrap();

        let loose = tmp.join("loose.toml");
        std::fs::write(&loose, b"network = \"none\"\n").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = trust(&tmp.join("store"), &loose).unwrap_err().to_string();
        assert!(err.starts_with(&*loose.display().to_string()), "{err}");
        assert_eq!(
            err.matches(&*loose.display().to_string()).count(),
            1,
            "named once: {err}"
        );

        let ro = tmp.join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        let err = trust(&ro.join("store"), &cfg).unwrap_err().to_string();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.starts_with(&*cfg.display().to_string()), "{err}");
        assert!(err.contains("cannot write its trust marker under"), "{err}");
    }

    #[test]
    fn hash_bytes_is_sha256_hex() {
        // the canonical empty-input SHA-256 digest
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // distinct inputs hash distinctly
        assert_ne!(hash_bytes(b"a"), hash_bytes(b"b"));
    }

    #[test]
    fn store_dir_prefers_absolute_xdg_then_absolute_home() {
        assert_eq!(
            store_dir_from(Some(OsStr::new("/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/xdg/sbx/trusted"))
        );
        // a relative XDG is ignored (it must never resolve against the cwd); HOME
        // is used instead
        assert_eq!(
            store_dir_from(Some(OsStr::new("rel/xdg")), Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.local/state/sbx/trusted"))
        );
        assert_eq!(
            store_dir_from(None, Some(OsStr::new("/home/u"))),
            Some(PathBuf::from("/home/u/.local/state/sbx/trusted"))
        );
        // no absolute base anywhere ⇒ refuse rather than fall back to the cwd
        assert_eq!(
            store_dir_from(Some(OsStr::new("rel")), Some(OsStr::new("rel"))),
            None
        );
        assert_eq!(store_dir_from(None, None), None);
    }

    #[test]
    fn trust_then_state_is_trusted_and_an_edit_makes_it_changed() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"network = \"isolated\"\n").unwrap();

        assert_eq!(state(store.path(), &cfg), TrustState::Untrusted);

        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);

        // an edit re-arms the gate (direnv model)
        std::fs::write(&cfg, b"network = \"isolated\"\nbinds = [\"/etc/ssh\"]\n").unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);

        // re-trusting the new contents clears it again
        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);
    }

    #[test]
    fn untrust_reports_whether_a_marker_existed_and_reverts_to_untrusted() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();

        trust(store.path(), &cfg).unwrap();
        assert!(untrust(store.path(), &cfg).unwrap(), "a marker existed");
        assert_eq!(state(store.path(), &cfg), TrustState::Untrusted);
        // a second untrust is a no-op success
        assert!(
            !untrust(store.path(), &cfg).unwrap(),
            "no marker the second time"
        );
    }

    #[test]
    fn untrust_finds_the_marker_after_the_config_is_deleted() {
        // canonical_string falls back to canonicalising the parent and
        // re-appending the file name, so a config present when trusted and gone
        // when untrusted still derives the same marker key.
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();

        trust(store.path(), &cfg).unwrap();
        std::fs::remove_file(&cfg).unwrap();

        assert!(
            untrust(store.path(), &cfg).unwrap(),
            "the marker keyed by the now-deleted config must still be found"
        );
    }

    #[test]
    fn a_malformed_marker_is_changed_not_untrusted() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();

        // a marker with only the path line (hash line lost to a truncated write)
        std::fs::create_dir_all(store.path()).unwrap();
        std::fs::write(marker_path(store.path(), &cfg), b"/some/path\n").unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);
    }

    #[test]
    fn trust_refuses_a_world_writable_config() {
        use std::os::unix::fs::PermissionsExt;
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o666)).unwrap();

        assert!(
            trust(store.path(), &cfg).is_err(),
            "must not trust a world-writable file"
        );
        assert_eq!(state(store.path(), &cfg), TrustState::Untrusted);
    }

    /// One mise input `(filename, bytes)` for the `content_hash` tests.
    fn mise(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        vec![(".mise.toml".to_string(), bytes.to_vec())]
    }

    #[test]
    fn content_hash_without_a_mise_file_equals_hashing_the_sbx_file() {
        // A project that never had a mise file keeps a marker byte-identical to the
        // single-file hash, so no existing trust churns when the mise path lands.
        assert_eq!(content_hash(b"a = 1\n", &[]), hash_bytes(b"a = 1\n"));
    }

    #[test]
    fn content_hash_with_a_mise_file_differs_and_is_unambiguous() {
        // Folding a mise file in changes the hash...
        assert_ne!(
            content_hash(b"sbx", &mise(b"mise")),
            content_hash(b"sbx", &[])
        );
        // ...and the framing is unambiguous: shifting a byte across the sbx/mise
        // boundary (a bare concatenation would collide here) hashes distinctly.
        assert_ne!(
            content_hash(b"ab", &mise(b"c")),
            content_hash(b"a", &mise(b"bc"))
        );
        // Editing the mise file alone changes the hash.
        assert_ne!(
            content_hash(b"sbx", &mise(b"v1")),
            content_hash(b"sbx", &mise(b"v2"))
        );
        // The filename is bound in: the same bytes under a different candidate name
        // hash distinctly, so moving an entry between files re-arms.
        assert_ne!(
            content_hash(b"sbx", &[(".mise.toml".into(), b"x".to_vec())]),
            content_hash(b"sbx", &[("mise.toml".into(), b"x".to_vec())])
        );
    }

    #[test]
    fn mise_files_for_discovers_every_candidate_in_precedence_order() {
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        assert!(mise_files_for(&cfg).is_empty(), "no mise file yet");

        // the lowest-precedence name alone is found
        std::fs::write(proj.join(".tool-versions"), b"").unwrap();
        assert_eq!(mise_files_for(&cfg), vec![proj.join(".tool-versions")]);

        // every same-directory candidate is returned, highest precedence first —
        // none is dropped, so a tool or env entry in any of them is hashed
        std::fs::write(proj.join("mise.toml"), b"").unwrap();
        std::fs::write(proj.join(".mise.toml"), b"").unwrap();
        std::fs::write(proj.join("mise.local.toml"), b"").unwrap();
        assert_eq!(
            mise_files_for(&cfg),
            vec![
                proj.join("mise.local.toml"),
                proj.join(".mise.toml"),
                proj.join("mise.toml"),
                proj.join(".tool-versions"),
            ]
        );
    }

    #[test]
    fn editing_the_idiomatic_or_local_files_re_arms_the_gate() {
        // The widened set must re-arm trust on an edit just like the canonical
        // config files do, so a tool pinned in `.tool-versions` or an env override in
        // `mise.local.toml` cannot change unnoticed under a stale marker.
        for name in ["mise.local.toml", ".tool-versions"] {
            let store = TmpDir::new();
            let proj = TmpDir::new();
            let cfg = proj.join(".sbx.toml");
            std::fs::write(&cfg, b"x = 1\n").unwrap();
            std::fs::write(proj.join(name), b"node 20\n").unwrap();

            trust(store.path(), &cfg).unwrap();
            assert_eq!(state(store.path(), &cfg), TrustState::Trusted, "{name}");

            std::fs::write(proj.join(name), b"node 22\n").unwrap();
            assert_eq!(
                state(store.path(), &cfg),
                TrustState::Changed,
                "editing {name} must re-arm the gate"
            );
        }
    }

    #[test]
    fn editing_any_candidate_mise_file_re_arms_even_a_lower_precedence_one() {
        // The direnv superset: trust folds in *every* candidate, so a tool entry in a
        // lower-precedence file cannot be edited without re-arming the gate.
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();
        std::fs::write(proj.join(".mise.toml"), b"[tools]\na = \"1\"\n").unwrap();
        std::fs::write(proj.join("mise.toml"), b"[tools]\nb = \"1\"\n").unwrap();

        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);

        std::fs::write(proj.join("mise.toml"), b"[tools]\nb = \"2\"\n").unwrap();
        assert_eq!(
            state(store.path(), &cfg),
            TrustState::Changed,
            "editing a lower-precedence candidate must still re-arm"
        );
    }

    #[test]
    fn a_mise_file_folds_into_trust_and_editing_either_file_re_arms() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        let mise = proj.join(".mise.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();
        std::fs::write(&mise, b"[tools]\nnode = \"20\"\n").unwrap();

        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);

        // editing the mise file re-arms the gate, just like editing the .sbx.toml
        std::fs::write(&mise, b"[tools]\nnode = \"22\"\n").unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);

        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);

        // editing the .sbx.toml re-arms it too
        std::fs::write(&cfg, b"x = 2\n").unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);
    }

    #[test]
    fn adding_or_removing_a_mise_file_re_arms_a_trusted_project() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        let mise = proj.join(".mise.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();

        // trusted with no mise file
        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);

        // adding one re-arms (the trusted surface grew)
        std::fs::write(&mise, b"[tools]\nnode = \"20\"\n").unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);

        // trusting both, then removing the mise file re-arms again (the surface shrank)
        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);
        std::fs::remove_file(&mise).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);
    }

    #[test]
    fn a_world_writable_mise_file_is_refused_and_never_trusted() {
        use std::os::unix::fs::PermissionsExt;
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        let mise = proj.join(".mise.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();
        std::fs::write(&mise, b"[tools]\nnode = \"20\"\n").unwrap();
        std::fs::set_permissions(&mise, std::fs::Permissions::from_mode(0o666)).unwrap();

        // an unsafe companion file blocks recording trust...
        assert!(
            trust(store.path(), &cfg).is_err(),
            "must not trust a project whose mise file is world-writable"
        );
        // ...and is never reported Trusted even if the .sbx.toml was trusted earlier
        // (here it was not), failing closed on the unverifiable file.
        assert_eq!(state(store.path(), &cfg), TrustState::Untrusted);
    }
}
