//! The project-config trust store (the direnv model).
//!
//! A project's `.sbx.toml` is attacker-controlled, so its security-relevant
//! fields are honored only once the user has vouched for the file's *contents*.
//! `sbx trust` records a marker keyed by the config's canonical *directory* and
//! file name, holding a SHA-256 of the whole file. Any later edit changes that hash, so the marker no
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

/// Canonicalized path string used as the marker key, or `None` when that path is not valid UTF-8.
///
/// What is canonicalized is the **directory**, with the config's own file name re-appended
/// verbatim. That is what binds a verdict to the project the launch is actually for. Resolving the
/// config file itself followed a symlink, and the trust store is keyed by the result: a hostile
/// repo whose `.sbx.toml` was a symlink to a trusted project's config read back the trusted
/// project's marker over the trusted project's bytes, and the cage started on the attacker's tree
/// with that project's `binds`, ssh-agent grant and injected credentials. The gate reads the file
/// through the safety gate, which follows the link on purpose (a global config kept in a dotfiles
/// repo is a symlink in the ordinary case) — so it is the *key* that must name the directory,
/// not the read that must refuse one.
///
/// Resolving the directory rather than nothing at all is what keeps one project from having two
/// keys: a `..` component, a symlinked parent, or a relative invocation all name the same config,
/// and each must derive the same marker. It also keeps `sbx trust` (file present) and a later
/// `sbx untrust` (file deleted) agreeing, since the file's own existence never enters the key. Only
/// when the directory itself cannot be resolved does it fall back to the raw path. Never panics.
///
/// The conversion is `into_string`, not `to_string_lossy`: this string is what tells one config
/// apart from another, and a lossy one does not — see [`marker_path`] for what that costs.
fn canonical_string(config_path: &Path) -> Option<String> {
    let resolved = match config_path.file_name() {
        // A bare `.sbx.toml` has an empty parent, which canonicalizes to nothing: the directory it
        // means is the one the process is in.
        Some(name) => {
            let parent = match config_path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            parent
                .canonicalize()
                .map(|dir| dir.join(name))
                .unwrap_or_else(|_| config_path.to_path_buf())
        }
        // No file name at all (a bare `/`, or a path ending in `..`): nothing to re-append, so the
        // whole path is resolved as before.
        None => config_path
            .canonicalize()
            .unwrap_or_else(|_| config_path.to_path_buf()),
    };
    resolved.into_os_string().into_string().ok()
}

/// Marker file path: `store_dir/<sha256 of the canonical config-path string>`, or `None` when that
/// path is not valid UTF-8.
///
/// The marker's *name* is what identifies which config a recorded trust belongs to, so the string
/// it is derived from has to distinguish paths the filesystem distinguishes — and has to name the
/// project the launch is for, which is why [`canonical_string`] resolves the directory and leaves
/// the file name alone rather than following a symlinked config to wherever it points. A lossy conversion
/// does not: every invalid byte becomes the same U+FFFD, so two projects whose paths differ only in
/// bytes the encoding cannot represent hash to one name — and a trust granted to the first is read
/// back for the second. Refusing is the only answer that stays sound, and it is the same rule this
/// repository applies to every other path gate: convert with `to_str`, and treat the `None` as the
/// refusal rather than as a value to repair.
pub(crate) fn marker_path(store_dir: &Path, config_path: &Path) -> Option<PathBuf> {
    let key = hash_bytes(canonical_string(config_path)?.as_bytes());
    Some(store_dir.join(key))
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
    // No representable marker name means no marker can have been written for this path, so the
    // verdict is the one a missing marker gets. Fail-closed either way: a path sbx cannot name is
    // never trusted.
    let Some(marker) = marker_path(store_dir, config_path) else {
        return TrustState::Untrusted;
    };
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
    trust_inner(store_dir, config_path, None)
}

/// [`trust`] over bytes the caller already holds, for a caller that has just *written* the file.
///
/// The difference is one read, and it is the whole point. `trust` reads `config_path` back and
/// attests to whatever is there at that moment; a caller that composed and wrote the file already
/// knows what it meant to bless, and the project tree is bound read-write into the cage — so a
/// payload that writes between the caller's write and `trust`'s read gets its own config attested.
/// Hashing the given bytes instead means a file changed underneath simply no longer matches its
/// marker, and the next launch drops it: the fail-safe answer, and the one the caller's own gate
/// already assumes it gets.
///
/// The sibling mise files are still read here, because the caller did not write those — attesting
/// to bytes it never composed would be inventing them.
pub(crate) fn trust_written(
    store_dir: &Path,
    config_path: &Path,
    sbx_bytes: &[u8],
) -> io::Result<()> {
    trust_inner(store_dir, config_path, Some(sbx_bytes))
}

/// The body of both: `written` is the config's bytes when the caller composed them, `None` to read
/// them from `config_path`.
fn trust_inner(store_dir: &Path, config_path: &Path, written: Option<&[u8]>) -> io::Result<()> {
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
    // The safety gate still runs on the path even when the bytes are given: it is what refuses a
    // world-writable or foreign-owned file, and that question is about the file on disk, not about
    // what the caller holds. Only the *hashed* bytes come from the caller.
    let read_back = crate::config::safety::read_safe_bytes(config_path)?;
    let sbx_bytes = written.map(|b| b.to_vec()).unwrap_or(read_back);
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
    // A path sbx cannot name is refused rather than recorded under a name it shares with another
    // path — see `marker_path`. This is the only branch that reports it, because it is the only one
    // where the user asked for something and must be told it did not happen: reading a verdict for
    // such a path answers `Untrusted`, and revoking answers "was not trusted".
    let (Some(canonical), Some(marker)) = (
        canonical_string(config_path),
        marker_path(store_dir, config_path),
    ) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{}: cannot record trust for a path that is not valid UTF-8",
                config_path.display()
            ),
        ));
    };
    let body = format!("{canonical}\n{hash}\n");
    // Written through a temporary and renamed, like every other record this repository keeps: a
    // crash mid-write would otherwise leave a marker carrying its path line and no hash line, which
    // reads as `Changed` — safe, but it makes a trusted config ask for re-approval for a reason the
    // user cannot see. The temporary is a dotfile beside the marker so a listing of the store shows
    // markers only, and it lands in the same 0o700 directory, on the same filesystem.
    let tmp = marker.with_file_name(format!(
        ".{}.tmp",
        marker.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp, body).map_err(&store_err)?;
    std::fs::rename(&tmp, &marker).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        store_err(e)
    })
}

/// Remove any trust marker for `config_path`. Returns whether one existed, so the
/// caller can tell "revoked" from "was not trusted". A missing marker is success,
/// not an error.
pub(crate) fn untrust(store_dir: &Path, config_path: &Path) -> io::Result<bool> {
    // A path with no representable marker name never had one written: nothing to revoke, and
    // saying so is the same answer as for a path that was simply never trusted.
    let Some(marker) = marker_path(store_dir, config_path) else {
        return Ok(false);
    };
    match std::fs::remove_file(marker) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {

    /// Trust attests to the bytes the caller wrote, not to whatever is on disk afterwards.
    ///
    /// `sbx net allow --local` writes a project config and then blesses it. The project tree is
    /// bound read-write into the cage, so if the marker were taken from a *re-read* an in-cage
    /// payload writing between the two would have its own config attested — and its security fields
    /// would apply from the next launch. Here the racing write is simulated by simply writing
    /// something else after the composed bytes: the marker must not match it.
    #[test]
    fn trust_attests_to_what_was_written_not_to_a_later_writer() {
        let dir = crate::testutil::TmpDir::new();
        let store = dir.path().join("store");
        let config = dir.path().join(crate::config::PROJECT_CONFIG);

        // What sbx composed and wrote.
        let composed = "[network]\nmode = \"deny\"\nallow = [\"example.com\"]\n";
        std::fs::write(&config, composed).expect("write the composed config");

        // The racing writer lands between the write and the trust.
        let hostile = "[network]\nmode = \"allow\"\n";
        std::fs::write(&config, hostile).expect("the racing write");

        trust_written(&store, &config, composed.as_bytes()).expect("record trust");

        // `Changed`, not `Trusted`: there *is* a marker (sbx wrote one), and the file no longer
        // matches it — which is precisely the signal a launch drops the security fields on. Had the
        // marker been taken from a re-read, this would say `Trusted` and the racing write would
        // apply.
        assert_eq!(
            state(&store, &config),
            TrustState::Changed,
            "the racing write was blessed — the marker covered the file on disk, not what sbx wrote"
        );

        // And the composed bytes are what the marker does cover: put them back and it is trusted.
        std::fs::write(&config, composed).expect("restore the composed config");
        assert_eq!(
            state(&store, &config),
            TrustState::Trusted,
            "the bytes that were attested to must be the ones that verify"
        );
    }
    use super::*;
    use crate::testutil::TmpDir;

    /// A trust marker names the project the launch is for, not the inode a symlink points at.
    ///
    /// The key was the *canonicalized config path*, and the safety gate opens without `O_NOFOLLOW`
    /// (a global config kept in a dotfiles repo is a symlink in the ordinary case), so a hostile
    /// repo whose `.sbx.toml` was a symlink into a trusted project read back the trusted project's
    /// marker over the trusted project's bytes: the verdict came back `Trusted` and the cage started
    /// on the attacker's tree with that project's `binds`, ssh-agent grant and injected credentials.
    /// Nothing tied the verdict to the directory, and `sbx untrust` in the hostile repo revoked the
    /// *other* project's trust.
    #[test]
    fn a_symlinked_config_does_not_inherit_another_projects_trust() {
        let tmp = TmpDir::new();
        let store = tmp.path().join("store");
        let work = tmp.path().join("work");
        let evil = tmp.path().join("evil");
        std::fs::create_dir_all(&work).expect("the trusted project");
        std::fs::create_dir_all(&evil).expect("the hostile project");

        let trusted = work.join(crate::config::PROJECT_CONFIG);
        std::fs::write(&trusted, "[ssh_agent]\nallow = [\"SHA256:deploy\"]\n").expect("write");
        trust(&store, &trusted).expect("the user vouches for their own project");
        assert_eq!(state(&store, &trusted), TrustState::Trusted);

        // The hostile repo ships a `.sbx.toml` that is a link to the trusted one, so the bytes read
        // are byte-identical and their hash matches the marker the user granted.
        let linked = evil.join(crate::config::PROJECT_CONFIG);
        std::os::unix::fs::symlink(&trusted, &linked).expect("the hostile symlink");
        assert_eq!(
            state(&store, &linked),
            TrustState::Untrusted,
            "a trust granted to one project must not be read back for another"
        );

        // And the two keys are distinct in both directions: revoking the hostile one leaves the
        // trusted project trusted.
        assert!(
            !untrust(&store, &linked).expect("revoking is not an error"),
            "the hostile project had no marker of its own to revoke"
        );
        assert_eq!(state(&store, &trusted), TrustState::Trusted);
    }

    /// The key resolves the *directory*, so the spellings that name one project still share a
    /// marker: a `..` component, and a symlinked parent directory.
    #[test]
    fn two_spellings_of_one_projects_directory_share_its_trust() {
        let tmp = TmpDir::new();
        let store = tmp.path().join("store");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).expect("the project");
        let config = work.join(crate::config::PROJECT_CONFIG);
        std::fs::write(&config, "[network]\nmode = \"deny\"\n").expect("write");
        trust(&store, &config).expect("record trust");

        // Spelled as one relative segment that leaves the project and comes straight back, so the
        // path never escapes the fixture it is joined to.
        let detoured = tmp
            .path()
            .join("work/../work")
            .join(crate::config::PROJECT_CONFIG);
        assert_eq!(state(&store, &detoured), TrustState::Trusted);

        let link = tmp.path().join("by-link");
        std::os::unix::fs::symlink(&work, &link).expect("a symlinked project directory");
        assert_eq!(
            state(&store, &link.join(crate::config::PROJECT_CONFIG)),
            TrustState::Trusted,
            "a link to the directory names the same project"
        );
    }

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

        // The store side fails because its parent is a regular file, so the `mkdir` answers
        // `ENOTDIR`. A mode-locked directory would say the same thing to an ordinary user and
        // nothing at all to root, who ignores the mode and writes the marker — leaving this branch
        // untested on any host that runs the suite as root. What is under test is the *shape* of
        // the error, not which refusal produced it, so the refusal that holds for every uid is the
        // one to provoke.
        let blocked = tmp.join("blocked");
        std::fs::write(&blocked, b"not a directory\n").unwrap();
        let err = trust(&blocked.join("store"), &cfg).unwrap_err().to_string();
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
    fn two_paths_that_differ_only_in_invalid_bytes_do_not_share_a_trust() {
        // The marker's name is derived from the config's path, so that derivation has to tell apart
        // every pair of paths the filesystem tells apart. A lossy conversion does not: both of the
        // directories below render as the same `p\u{FFFD}`. If the derivation collapsed them,
        // approving the first would silently approve the second — and the two configs here carry
        // the SAME bytes, so their content hashes match too and nothing downstream would notice.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tmp = TmpDir::new();
        let store = tmp.path().join("store");
        let mut made = Vec::new();
        for raw in [b"p\xff".as_slice(), b"p\xfe".as_slice()] {
            let dir = tmp.path().join(OsStr::from_bytes(raw));
            std::fs::create_dir_all(&dir).unwrap();
            let cfg = dir.join(".sbx.toml");
            std::fs::write(&cfg, b"network = \"none\"\n").unwrap();
            made.push(cfg);
        }
        let (first, second) = (&made[0], &made[1]);
        assert_ne!(first, second, "the two fixtures must be distinct paths");
        assert_eq!(
            first.to_string_lossy(),
            second.to_string_lossy(),
            "the fixture is only meaningful if the two paths collide under a lossy conversion"
        );

        // Refused, and told: this is the one caller that asked for something and did not get it.
        let refused = trust(&store, first).expect_err("a path sbx cannot name is not recorded");
        assert!(
            refused.to_string().contains("not valid UTF-8"),
            "the refusal must name its reason: {refused}"
        );
        // And the verdict for BOTH is the fail-closed one, whichever way the marker went.
        for cfg in [first, second] {
            assert_eq!(
                state(&store, cfg),
                TrustState::Untrusted,
                "{} must not read as trusted",
                cfg.display()
            );
        }
        assert!(
            !store.exists() || std::fs::read_dir(&store).unwrap().next().is_none(),
            "a refused trust must leave no marker behind"
        );
    }

    #[test]
    fn a_recorded_trust_leaves_the_marker_and_nothing_beside_it() {
        // The marker is written through a temporary and renamed. What a test can hold is the
        // aftermath: the store carries the marker and no leftover, so a reader listing it never
        // sees a half-written record, and a failed rename does not accumulate debris.
        let tmp = TmpDir::new();
        let store = tmp.path().join("store");
        let cfg = tmp.path().join(".sbx.toml");
        std::fs::write(&cfg, b"network = \"none\"\n").unwrap();

        trust(&store, &cfg).expect("the fixture path is representable");
        let entries: Vec<_> = std::fs::read_dir(&store)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "the store should hold the marker alone, found {entries:?}"
        );
        let marker = marker_path(&store, &cfg).expect("a UTF-8 fixture path");
        assert_eq!(
            entries[0],
            marker.file_name().unwrap().to_string_lossy(),
            "the surviving entry is the marker, not the temporary"
        );
        assert_eq!(state(&store, &cfg), TrustState::Trusted);
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
        let marker = marker_path(store.path(), &cfg).expect("a UTF-8 fixture path");
        std::fs::write(marker, b"/some/path\n").unwrap();
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
