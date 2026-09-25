//! The project-config trust store (the direnv model).
//!
//! A project's `.sbx.toml` is attacker-controlled, so its security-relevant
//! fields are honored only once the user has vouched for the file's *contents*.
//! `sbx trust` records a marker keyed by the config's location — its directory
//! canonicalized, its own name kept as written, see [`canonical_string`] for why
//! the leaf is deliberately not resolved — holding a SHA-256 of the whole file.
//! Any later edit changes that hash, so the marker no longer matches and the
//! project must be re-trusted — exactly like `direnv allow` re-arming when
//! `.envrc` changes.
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
//!
//! A project may name a SOPS-encrypted file as a secret's source, and its metadata decides where
//! the host's `sops` goes for the key, with the user's credentials. A file in the project is one
//! the cage can rewrite, so the hash folds in every such file the `.sbx.toml` names
//! ([`sops_inputs_for`]), and a resolution hands `sops` only bytes that hash still covers
//! ([`covered_sops_bytes`]).
//!
//! Beside each marker sits the record of what it approved: the bytes of the `.sbx.toml`, of every
//! mise file and of every sops file it names, as they were hashed ([`approved`]). The hash alone answers *whether* the
//! project changed; `sbx trust` needs *what* changed, so that re-approving shows the reader the
//! contents they are about to grant instead of asking them to vouch for bytes they never saw.

use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

/// A project's mise files as validated input: each as `(filename, bytes)`, in
/// precedence order. The trust hash folds these in, and the launcher maps them — so
/// the same type carries the bytes from the safety gate to both consumers.
pub(crate) type MiseInputs = Vec<(String, Vec<u8>)>;

/// Every file the trust hash covers beside the `.sbx.toml`, as `(tag, bytes)`: the mise files
/// ([`MiseInputs`]) then the sops files the config names, the latter tagged under
/// [`SOPS_TAG_PREFIX`]. The launcher maps only the mise half; the gate hashes and records both.
pub(crate) type TrustInputs = Vec<(String, Vec<u8>)>;

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

/// Candidate mise config paths beside the `.sbx.toml`, highest precedence first. Every one
/// that exists is part of "the project's mise configuration" — all are folded into the trust
/// hash. The set is mise's *same-directory* discovery, all of it: the two local overrides, the
/// two canonical config files, the three a project may keep in a subdirectory rather than at
/// its top level, and the idiomatic `.tool-versions`. It stays in lockstep with the set a later
/// stage authorizes mise to read, or an unhashed file would reach resolution — which is why the
/// wider reaches of mise's own discovery (parent-directory configs, the user-global config,
/// env-specific `mise.<env>.toml`) are deliberately *out*: they live outside the project root
/// the trust gate anchors on, so admitting them would let a file sbx never hashed steer
/// resolution.
///
/// Three of these name a file in a subdirectory, so an entry here is a relative path rather
/// than a filename. Two of them end in `config.toml`, which is why [`mise_inputs_for`] tags a
/// part of the hash with this whole path: two files sharing a tag would cost the framing the
/// property it exists for.
pub(crate) const MISE_CONFIG_NAMES: &[&str] = &[
    ".mise.local.toml",
    "mise.local.toml",
    ".mise.toml",
    "mise.toml",
    "mise/config.toml",
    ".mise/config.toml",
    ".config/mise.toml",
    ".config/mise/config.toml",
    ".tool-versions",
];

/// Every mise file under the directory of `config_path` (the `.sbx.toml`) that
/// exists, in precedence order — empty when the directory has none. *All* of them are folded
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
    let dir = config_path.parent();
    let mut out = Vec::new();
    for path in mise_files_for(config_path) {
        let bytes = crate::config::safety::read_safe_bytes(&path)?;
        // The path relative to the project, not the filename: `.config/mise/config.toml` and
        // `.mise/config.toml` share the second and would share a tag, which is exactly what the
        // framing in `content_hash` may not allow.
        let name = dir
            .and_then(|d| path.strip_prefix(d).ok())
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        out.push((name, bytes));
    }
    Ok(out)
}

/// What a sops file's part of the hash is tagged with, before the file as the config spells it. No
/// entry of [`MISE_CONFIG_NAMES`] begins so, which keeps every tag of one hash distinct.
const SOPS_TAG_PREFIX: &str = "sops:";

/// The directory a project's relative paths resolve against, resolved as far as it exists, so the
/// same project yields the same sops parts whichever spelling of its config path was given.
fn project_root_of(config_path: &Path) -> PathBuf {
    canonicalize_existing_prefix(config_path.parent().unwrap_or(Path::new("")))
}

/// Whether `path` is in the project under `root`, the tree the cage is given to write: under it as
/// spelled, or once the part of it that exists is resolved. Either answer counts, so a path that
/// only reaches the project through a link is treated as the project's.
fn in_project(root: &Path, path: &Path) -> bool {
    path.starts_with(root) || canonicalize_existing_prefix(path).starts_with(root)
}

/// Every sops file a config names: the file of each `sops://` reference, wherever it appears
/// (`from`, a task's variable, a broker's secret), and each `file` of a `[… .sops]` defaults table,
/// which a terse `key` expands through. Read from the raw TOML rather than from the resolved
/// config, so the set does not depend on which fields the schema honours. A name missed here is
/// never covered, and [`covered_sops_bytes`] refuses it: an omission fails closed.
fn sops_files_named(sbx_bytes: &[u8]) -> std::collections::BTreeSet<PathBuf> {
    fn walk(value: &toml::Value, out: &mut std::collections::BTreeSet<PathBuf>) {
        match value {
            toml::Value::String(s) => out.extend(crate::config::sops_ref_file(s)),
            toml::Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            toml::Value::Table(table) => {
                for (key, v) in table {
                    if key == "sops"
                        && let Some(file) = v.get("file").and_then(toml::Value::as_str)
                    {
                        out.insert(PathBuf::from(file));
                    }
                    walk(v, out);
                }
            }
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    if let Some(table) = std::str::from_utf8(sbx_bytes)
        .ok()
        .and_then(|text| text.parse::<toml::Table>().ok())
    {
        walk(&toml::Value::Table(table), &mut out);
    }
    out
}

/// Read every sops file the `.sbx.toml` bytes name that lies in the project, through the safety
/// gate the config uses, as `(tag, bytes)` for folding into the trust hash. A file outside the
/// project is left out (the cage is not given it to write), as is one that does not exist: a file
/// that appears later changes the hash a resolution recomputes, so it is refused, not admitted.
/// `Err` when one is present but unsafe or unreadable, for the reason [`mise_inputs_for`] gives.
pub(crate) fn sops_inputs_for(config_path: &Path, sbx_bytes: &[u8]) -> io::Result<TrustInputs> {
    let root = project_root_of(config_path);
    let mut out = Vec::new();
    for file in sops_files_named(sbx_bytes) {
        let path = crate::sandbox::egress::sops_path(&file, &root);
        if !in_project(&root, &path) {
            continue;
        }
        match crate::config::safety::read_safe_bytes_as(&path, "sops file") {
            Ok(bytes) => out.push((format!("{SOPS_TAG_PREFIX}{}", file.display()), bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            // `sbx trust` cannot clear this refusal, since it reads the same file; the way out is
            // the one the hash leaves open, a file outside the project.
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "{e}; {} names it, so its trust must cover it: fix it, or keep it outside \
                         the project and name it by its absolute path",
                        crate::config::PROJECT_CONFIG
                    ),
                ));
            }
        }
    }
    Ok(out)
}

/// Every file the trust of `config_path` covers beside it: the mise files, then the sops files
/// `sbx_bytes` names. What the gate hashes and records, and what [`trust_written`] compares.
pub(crate) fn trust_inputs_for(config_path: &Path, sbx_bytes: &[u8]) -> io::Result<TrustInputs> {
    let mut inputs = mise_inputs_for(config_path)?;
    inputs.extend(sops_inputs_for(config_path, sbx_bytes)?);
    Ok(inputs)
}

/// The bytes `sops` may be handed for `file`, a sops source resolved against `project_root`.
///
/// `Ok(None)` when the file is outside the project: the cage is not given it to write, and it is
/// decrypted where it is. A file in the project is one the cage can rewrite, and its metadata
/// decides where `sops` fetches the key, with the user's credentials. So it is decrypted only as
/// the bytes the project's trust covers: `Ok(Some(bytes))` when the `.sbx.toml` names it and the
/// project reads `Trusted` over those very bytes, which are the ones returned, so nothing written
/// after the check reaches `sops`. `Err` otherwise, naming the file and why it is not covered.
pub(crate) fn covered_sops_bytes(
    store_dir: Option<&Path>,
    project_root: &Path,
    file: &Path,
) -> io::Result<Option<Vec<u8>>> {
    let root = canonicalize_existing_prefix(project_root);
    let path = crate::sandbox::egress::sops_path(file, &root);
    if !in_project(&root, &path) {
        return Ok(None);
    }
    let config = root.join(crate::config::PROJECT_CONFIG);
    let refuse = |why: &str| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is in the project, which the cage can write, and {why}: name it in {} and run \
                 `sbx trust`, or keep it outside the project",
                path.display(),
                crate::config::PROJECT_CONFIG
            ),
        )
    };
    let Some(store) = store_dir else {
        return Err(refuse(
            "no trust store can be located to confirm it was approved",
        ));
    };
    let sbx_bytes = crate::config::safety::read_safe_bytes(&config).map_err(|e| {
        refuse(&match e.kind() {
            io::ErrorKind::NotFound => format!("no {} covers it", crate::config::PROJECT_CONFIG),
            _ => format!("its approval cannot be confirmed ({e})"),
        })
    })?;
    let inputs = trust_inputs_for(&config, &sbx_bytes)
        .map_err(|e| refuse(&format!("its approval cannot be confirmed ({e})")))?;
    match verdict_for_hash(store, &config, &content_hash(&sbx_bytes, &inputs)) {
        TrustState::Trusted => {}
        TrustState::Untrusted => return Err(refuse("the project is not trusted")),
        TrustState::Changed => {
            return Err(refuse(
                "the project, or a file its trust covers, changed since it was trusted",
            ));
        }
    }
    inputs
        .into_iter()
        .find_map(|(tag, bytes)| {
            let named = tag.strip_prefix(SOPS_TAG_PREFIX)?;
            (crate::sandbox::egress::sops_path(Path::new(named), &root) == path).then_some(bytes)
        })
        .map(Some)
        .ok_or_else(|| {
            refuse("the trusted config does not name it, so its trust does not cover it")
        })
}

/// The trust content hash for a project: the `.sbx.toml` bytes alone when the
/// project has no mise file and names no sops file in it — so a project that never had
/// one keeps a marker byte-identical to hashing the single file — or an unambiguous
/// framing of the `.sbx.toml` and *every* covered file ([`trust_inputs_for`]) when it
/// has some. Each part is domain-tagged (the mise parts by path, the sops parts under
/// [`SOPS_TAG_PREFIX`]) and length-prefixed, never a bare concatenation, so among
/// *has-companion* inputs no two distinct sets share an encoding: a change to any
/// file — or moving an entry between files — always changes the hash.
///
/// The no-mise fast path is an intentional exception (it hashes the raw file, for the
/// backward-compatible marker). A cross-mode collision — a no-mise state hashing the same
/// as a has-mise one — would require the trusted `.sbx.toml` bytes to *begin with the internal
/// framing header* (`sbx.toml\0` + a length), which a real, user-reviewed TOML config never does
/// (it embeds a NUL), so the "any change re-arms trust" guarantee holds for every real input.
pub(crate) fn content_hash(sbx_bytes: &[u8], inputs: &[(String, Vec<u8>)]) -> String {
    if inputs.is_empty() {
        return hash_bytes(sbx_bytes);
    }
    let extra: usize = inputs.iter().map(|(n, b)| n.len() + b.len()).sum();
    let mut buf = Vec::with_capacity(sbx_bytes.len() + extra + 32);
    frame(&mut buf, b"sbx.toml", sbx_bytes);
    for (name, bytes) in inputs {
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

/// Split a buffer written by [`frame`] back into its `(tag, bytes)` parts, or `None` when it is
/// not a whole sequence of frames — a truncated or hand-edited record is no record at all.
fn unframe(mut buf: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let nul = buf.iter().position(|&b| b == 0)?;
        let tag = std::str::from_utf8(&buf[..nul]).ok()?.to_string();
        let rest = &buf[nul + 1..];
        let len_bytes: [u8; 8] = rest.get(..8)?.try_into().ok()?;
        let len = usize::try_from(u64::from_le_bytes(len_bytes)).ok()?;
        let body = rest.get(8..8usize.checked_add(len)?)?;
        out.push((tag, body.to_vec()));
        buf = &rest[8 + len..];
    }
    Some(out)
}

/// The tag the `.sbx.toml` part of an approved record is written under. A mise part is tagged by
/// its path relative to the project and a sops part under [`SOPS_TAG_PREFIX`], neither of which
/// has this spelling.
const APPROVED_SBX_TAG: &str = "sbx.toml";

/// Where the approved contents of `config_path` are kept: beside its marker, under the marker's
/// name with an `.approved` suffix. `None` exactly when [`marker_path`] is.
fn approved_path(store_dir: &Path, config_path: &Path) -> Option<PathBuf> {
    let mut name = marker_path(store_dir, config_path)?.into_os_string();
    name.push(".approved");
    Some(PathBuf::from(name))
}

/// The contents a recorded trust approved: the `.sbx.toml` bytes and the files its trust covers
/// ([`TrustInputs`]), as they were hashed. `None` when nothing is recorded — never trusted, trusted by a version of sbx
/// that kept only the hash, or a record that cannot be read back whole.
///
/// This is a display input, never a verdict: whether the project is trusted is the marker's hash
/// alone ([`verdict_for_hash`]), so a record that was tampered with can mislead a diff but cannot
/// make anything trusted.
pub(crate) fn approved(store_dir: &Path, config_path: &Path) -> Option<(Vec<u8>, TrustInputs)> {
    let bytes = std::fs::read(approved_path(store_dir, config_path)?).ok()?;
    let mut parts = unframe(&bytes)?.into_iter();
    let (tag, sbx) = parts.next()?;
    (tag == APPROVED_SBX_TAG).then(|| (sbx, parts.collect()))
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

/// Canonicalize the longest existing prefix of `path`, re-appending verbatim the components that
/// do not exist yet. A path that exists in full is plain `canonicalize`; one whose tail has not
/// been created is still expressed in the symlink-resolved namespace of the part that does exist.
///
/// `Path::canonicalize` is all-or-nothing — it fails unless every component resolves — so a path
/// naming something not created yet comes back untouched, and an unresolved path compared against
/// a canonical one matches nothing. Two callers need the difference: the trust marker key (a
/// config trusted while it exists must derive the same key once it is deleted) and sbx's own
/// control-plane roots (a root the user has not created yet must still be recognised inside a bind
/// that contains it).
///
/// Best effort by construction: a path with no existing ancestor at all — or one whose components
/// cannot be walked, such as a trailing `..` — is returned unchanged, which is the same answer
/// `canonicalize` refused to give.
pub(crate) fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    // An empty path is what `Path::new("cfg.toml").parent()` yields, and it denotes the current
    // directory, which `canonicalize` will not resolve under that spelling. Naming it explicitly is
    // what keeps a relative path keyed by an absolute one.
    let dot = Path::new(".");
    let start = if path.as_os_str().is_empty() {
        dot
    } else {
        path
    };
    let mut missing: Vec<&OsStr> = Vec::new();
    let mut cursor = start;
    loop {
        if let Ok(mut resolved) = cursor.canonicalize() {
            for name in missing.iter().rev() {
                resolved.push(name);
            }
            return resolved;
        }
        match (cursor.parent(), cursor.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name);
                cursor = if parent.as_os_str().is_empty() {
                    dot
                } else {
                    parent
                };
            }
            // Nothing left to walk up to, or a component that carries no name to re-append (a
            // trailing `.` or `..`): hand back what was asked for rather than a half-built path.
            _ => return path.to_path_buf(),
        }
    }
}

/// Canonicalized path string used as the marker key, or `None` when that path is not valid UTF-8.
///
/// The **final component is never resolved**: only the directories above it are canonicalized, and
/// the file name is re-appended verbatim. That is a security property rather than a convenience.
/// `realpath(3)` resolves the leaf too, and the config's bytes are read through the same leaf — so
/// a hostile repository shipping its `.sbx.toml` as a symlink to another project's config (git
/// records symlinks, so one survives a clone) would key on *that* project's marker, match its
/// stored hash, and inherit its verdict, while the secrets, egress allowances and binds it unlocks
/// are applied to the hostile tree. Keying on the path the user is standing in keeps a trust
/// decision the property of one directory, which is the whole model.
///
/// The parent is canonicalized as far as it exists ([`canonicalize_existing_prefix`]), so `sbx
/// trust` (file present) and a later `sbx untrust` (file deleted) still derive the same key, and a
/// relative path still keys by its absolute location. Never panics.
///
/// The conversion is `into_string`, not `to_string_lossy`: this string is what tells one config
/// apart from another, and a lossy one does not — see [`marker_path`] for what that costs.
fn canonical_string(config_path: &Path) -> Option<String> {
    let resolved = match (config_path.parent(), config_path.file_name()) {
        (Some(parent), Some(name)) => canonicalize_existing_prefix(parent).join(name),
        // No file name to hold apart from its directory (a root, a trailing `..`): there is no leaf
        // to protect, so resolve what was given.
        _ => canonicalize_existing_prefix(config_path),
    };
    resolved.into_os_string().into_string().ok()
}

/// Marker file path: `store_dir/<sha256 of the canonical config-path string>`, or `None` when that
/// path is not valid UTF-8.
///
/// The marker's *name* is what identifies which config a recorded trust belongs to, so the string
/// it is derived from has to distinguish paths the filesystem distinguishes. A lossy conversion
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
/// file, or a sops file the config names, that is present but unsafe is also reported
/// `Untrusted`: the trusted content folds in that file, and an unverifiable one cannot
/// yield `Trusted`.
pub(crate) fn state(store_dir: &Path, config_path: &Path) -> TrustState {
    state_with_inputs(store_dir, config_path).0
}

/// [`state`], handing back the covered files ([`TrustInputs`]) the verdict was computed over.
///
/// A caller that gates a write on the verdict and then blesses what it wrote needs both: the
/// verdict to admit the write, and those very bytes to hand to [`trust_written`], which attests to
/// nothing else. Reading the covered files again at bless time would answer the same question
/// twice, and the project tree is bound read-write into the cage — so the two answers can differ by
/// an in-cage write, and the second one was admitted by nobody. An unreadable or unsafe file yields
/// `(Untrusted, empty)`: the verdict the fail-closed arms of this function already give, paired
/// with the expectation only a project with no covered file at all can meet.
pub(crate) fn state_with_inputs(store_dir: &Path, config_path: &Path) -> (TrustState, TrustInputs) {
    let sbx_bytes = match crate::config::safety::read_safe_bytes(config_path) {
        Ok(b) => b,
        Err(_) => return (TrustState::Untrusted, Vec::new()),
    };
    let inputs = match trust_inputs_for(config_path, &sbx_bytes) {
        Ok(m) => m,
        Err(_) => return (TrustState::Untrusted, Vec::new()),
    };
    let verdict = verdict_for_hash(store_dir, config_path, &content_hash(&sbx_bytes, &inputs));
    (verdict, inputs)
}

/// Record trust for `config_path`: hash the file's current contents — and those of
/// every file its trust covers ([`trust_inputs_for`]) — and write the marker. Every byte
/// is read through the safety gate, so a world-writable or foreign-owned `.sbx.toml`,
/// mise file or sops file is refused rather than blessed, and the hash covers exactly
/// the gated bytes of all of them.
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
/// The covered files — the sibling mise files and the sops files the config names — are still read
/// here, because the caller did not write those — attesting to bytes it never composed would be
/// inventing them. `expected` is what the caller's *gate* read of them ([`state_with_inputs`]), and
/// the read here must still match it: the marker covers them too, a `nix:` tool in a mise file is
/// provisioned host-side the moment the project reads `Trusted`, and a sops file's metadata is what
/// the host's `sops` acts on. A file that changed, appeared or vanished in between is content no
/// gate admitted, so it is refused rather than blessed.
pub(crate) fn trust_written(
    store_dir: &Path,
    config_path: &Path,
    sbx_bytes: &[u8],
    expected: &TrustInputs,
) -> io::Result<()> {
    trust_inner(store_dir, config_path, Some((sbx_bytes, expected)))
}

/// The body of both: `written` is the config's bytes as the caller composed them, paired with the
/// covered files its gate admitted; `None` to read both back from `config_path`.
fn trust_inner(
    store_dir: &Path,
    config_path: &Path,
    written: Option<(&[u8], &TrustInputs)>,
) -> io::Result<()> {
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
    let sbx_bytes = written.map(|(b, _)| b.to_vec()).unwrap_or(read_back);
    let inputs = trust_inputs_for(config_path, &sbx_bytes)?;
    // The covered files have no composed bytes to stand in for them, so they are read from disk
    // here — a second read of files the caller's gate already judged. Anything that changed between
    // the two reads was admitted by nobody, and pinning it would hand the marker to an in-cage
    // writer: the marker is what releases a mise file's `nix:` provisioning on the host, and a sops
    // file's metadata to the host's `sops`. Refusing instead leaves the project `Changed` and the
    // verb reporting that it wrote but could not re-trust — the fail-safe the `.sbx.toml` half
    // already gets from hashing the composed bytes. A sops file the composed config names and the
    // gate's did not is refused the same way: nobody reviewed it.
    if let Some((_, expected)) = written
        && inputs != *expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{}: a mise or sops file its trust covers is not the one sbx read before writing, \
                 so the trust marker would cover content that was never reviewed",
                config_path.display()
            ),
        ));
    }
    let hash = content_hash(&sbx_bytes, &inputs);

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
    // user cannot see. Staged by [`crate::sandbox::atomicfile`] rather than here: this call site
    // once named its own temp from the marker alone, which two `sbx trust` runs on the same config
    // share, and a shared temp is the one thing the rename cannot make atomic — the second writer
    // truncates the inode the first is still filling. That the marker's torn form reads `Changed`
    // makes the outcome safe, not correct.
    crate::sandbox::atomicfile::write_atomic(&marker, body.as_bytes()).map_err(&store_err)?;
    // The record of what was approved, after the marker. The other order has a failure that lies:
    // a record written and a marker that is not leaves the previous approval in force beside a
    // record of the new contents, and the next `sbx trust` shows no change where there is one.
    // This order fails towards showing more — a record that could not be written is removed, and
    // the next review shows the whole file. The trust itself is recorded either way, which is why a
    // record that fails is not this function's error.
    let mut record = Vec::new();
    frame(&mut record, APPROVED_SBX_TAG.as_bytes(), &sbx_bytes);
    for (name, bytes) in &inputs {
        frame(&mut record, name.as_bytes(), bytes);
    }
    if let Some(at) = approved_path(store_dir, config_path)
        && crate::sandbox::atomicfile::write_atomic(&at, &record).is_err()
    {
        let _ = std::fs::remove_file(at);
    }
    Ok(())
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
    // The record of approved contents goes with the trust it documents; without a marker it
    // describes an approval that no longer exists.
    if let Some(at) = approved_path(store_dir, config_path)
        && let Err(e) = std::fs::remove_file(at)
        && e.kind() != io::ErrorKind::NotFound
    {
        return Err(e);
    }
    match std::fs::remove_file(marker) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {

    /// Every re-trust that follows a write sbx composed hashes that text; the two verbs that hash
    /// the *path* are named here, and nothing else in the crate may.
    ///
    /// A verb that writes a config and then blesses it has one obligation: attest to the delta it
    /// authored. `trust` reads the path back, so it attests to whatever is there at that moment —
    /// and the project tree is bind-mounted read-write into the cage, so a payload writing between
    /// the verb's write and that read has its own `.sbx.toml` blessed, with its `[network]` and
    /// `[binds]` honored from the next launch. The write succeeds in both cases, which is what makes
    /// the difference invisible at the call site and worth a guard rather than a convention.
    ///
    /// **The population is the whole crate, and that is the point.** A guard whose population is one
    /// file reports on one file: a verb written elsewhere — or moved elsewhere by a refactor —
    /// satisfies it by absence. So every `.rs` under `src/` is read, and each is asked the same
    /// question.
    ///
    /// One caller legitimately hashes the path, and it is named with the count it carries:
    /// `src/cli/config/edit.rs`, the `sbx config edit --trust` path — the editor showed the user
    /// the file and left what they saved, and sbx composed none of it. The `sbx trust <path>` verb
    /// is not one: it prints the contents it is about to grant and asks, so the bytes it attests to
    /// are the ones it showed, and it sits in the second table.
    ///
    /// The count is pinned rather than the file merely admitted, so a second re-reading call added
    /// inside that file fails here as loudly as one added anywhere else.
    ///
    /// The second table is the other half of the same rule: the writers that do attest to their own
    /// text, with how many such calls each holds. It is what catches a verb that drops its re-trust
    /// altogether — an absence no other test sees, because the write still succeeds and the file is
    /// simply left untrusted until the user notices.
    #[test]
    fn every_re_trust_after_a_write_sbx_composed_attests_to_that_text() {
        /// The files admitted to hash the path, and how many such calls each holds.
        const HASHES_THE_PATH: &[(&str, usize)] = &[("src/cli/config/edit.rs", 1)];
        /// The files that attest to bytes they hold, and how many such calls each holds: the
        /// egress, proc and `[fs]` mask add paths, the proc-learn write, the shared removal path,
        /// the tail of the four key-writing `sbx config` verbs, and `sbx trust` over the contents
        /// it showed.
        const HASHES_ITS_OWN_TEXT: &[(&str, usize)] = &[
            ("src/main.rs", 5),
            ("src/cli/config/edit.rs", 1),
            ("src/cli/trust.rs", 1),
        ];

        let root = format!("{}/", env!("CARGO_MANIFEST_DIR"));
        let mut reread: Vec<(String, usize)> = Vec::new();
        let mut attested: Vec<(String, usize)> = Vec::new();
        for file in crate::testutil::crate_sources() {
            if crate::testutil::is_test_only_source(&file) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let production = crate::testutil::production_half(&text);
            let relative = file.display().to_string().replacen(&root, "", 1);
            // `trust::trust_written(` does not contain `trust::trust(` — the character after the
            // second `trust` is `_`, not `(` — so the two counts never overlap.
            let rereads = production.matches("trust::trust(").count();
            if rereads > 0 {
                reread.push((relative.clone(), rereads));
            }
            let writes = production.matches("trust::trust_written(").count();
            if writes > 0 {
                attested.push((relative, writes));
            }
        }
        reread.sort();
        attested.sort();

        let expect = |table: &[(&str, usize)]| {
            let mut v: Vec<(String, usize)> =
                table.iter().map(|(f, n)| ((*f).to_string(), *n)).collect();
            v.sort();
            v
        };
        assert_eq!(
            reread,
            expect(HASHES_THE_PATH),
            "a re-trust after a write sbx composed must hash that text (`trust_written`), never \
             read the file back; only `sbx config edit` blesses bytes sbx neither authored nor \
             showed"
        );
        assert_eq!(
            attested,
            expect(HASHES_ITS_OWN_TEXT),
            "a verb that writes a project config and blesses it in one step must re-trust the \
             text it wrote"
        );
    }

    /// A mise file rewritten between the gate and the bless is refused, never attested to.
    ///
    /// The marker covers the `.sbx.toml` *and* every mise file beside it, and a mise file that
    /// reads `Trusted` has its `nix:` tools resolved and built on the host. `sbx net allow --local`
    /// reads those files once to admit the write and would otherwise read them again to bless it —
    /// two reads of a file the cage can write, with the command's own write in between. The racing
    /// in-cage write is simulated by rewriting the mise file after the composed config: the marker
    /// must not cover it, and the project must not come back trusted.
    #[test]
    fn a_mise_file_rewritten_after_the_gate_is_not_blessed() {
        let dir = crate::testutil::TmpDir::new();
        let store = dir.path().join("store");
        let config = dir.path().join(crate::config::PROJECT_CONFIG);
        let mise = dir.path().join(".mise.toml");
        std::fs::write(&config, "[network]\nmode = \"deny\"\n").expect("the starting config");
        std::fs::write(&mise, "[tools]\nnode = \"22\"\n").expect("the reviewed mise file");
        trust(&store, &config).expect("trust the reviewed project");

        // What the verb's gate read, and what it admitted the write on.
        let (admitted_state, admitted_mise) = state_with_inputs(&store, &config);
        assert_eq!(
            admitted_state,
            TrustState::Trusted,
            "the gate must admit this"
        );

        // What sbx composed and wrote.
        let composed = "[network]\nmode = \"deny\"\nallow = [\"example.com\"]\n";
        std::fs::write(&config, composed).expect("write the composed config");

        // The racing writer lands on the file the caller did not compose.
        std::fs::write(&mise, "[tools]\nfoo = \"nix:hostile\"\n").expect("the racing write");

        assert!(
            trust_written(&store, &config, composed.as_bytes(), &admitted_mise).is_err(),
            "the racing mise write was folded into the marker"
        );
        assert_ne!(
            state(&store, &config),
            TrustState::Trusted,
            "the project reads trusted over a mise file no gate admitted"
        );
    }

    /// The bootstrap arm keeps its promise: a mise file that appears during the write is not blessed.
    ///
    /// A `--local` save into a project with no config is admitted precisely because there is
    /// nothing else to bless (`local_save_permitted`'s `(false, false)` arm). A mise file created
    /// inside that window is exactly what the neighbouring `(false, true)` arm refuses, so it must
    /// not ride along on the marker the save writes.
    #[test]
    fn a_mise_file_created_after_a_bootstrap_gate_is_not_blessed() {
        let dir = crate::testutil::TmpDir::new();
        let store = dir.path().join("store");
        let config = dir.path().join(crate::config::PROJECT_CONFIG);

        // The gate: no config, no mise file beside it.
        let (admitted_state, admitted_mise) = state_with_inputs(&store, &config);
        assert_eq!(admitted_state, TrustState::Untrusted);
        assert!(admitted_mise.is_empty(), "nothing was there to admit");

        let composed = "[network]\nmode = \"deny\"\n";
        std::fs::write(&config, composed).expect("write the composed config");
        std::fs::write(
            dir.path().join(".mise.toml"),
            "[tools]\nfoo = \"nix:hostile\"\n",
        )
        .expect("the racing write");

        assert!(
            trust_written(&store, &config, composed.as_bytes(), &admitted_mise).is_err(),
            "a mise file that appeared during the write was blessed with the config"
        );
        assert_ne!(
            state(&store, &config),
            TrustState::Trusted,
            "the bootstrap save blessed a file the user never reviewed"
        );
    }

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

        trust_written(&store, &config, composed.as_bytes(), &MiseInputs::new())
            .expect("record trust");

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

    /// A sops file the config names in the project is part of what `sbx trust` approves: a rewrite
    /// of it re-arms the gate. One outside the project, or one the config does not name, is not.
    #[test]
    fn a_sops_file_the_config_names_in_the_project_is_covered_by_the_hash() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let outside = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::create_dir(proj.join("secrets")).unwrap();
        std::fs::write(proj.join("secrets/prod.enc.yaml"), b"sops:\n  kms: a\n").unwrap();
        std::fs::write(proj.join("stray.enc.yaml"), b"sops: {}\n").unwrap();
        std::fs::write(outside.join("far.enc.yaml"), b"sops: {}\n").unwrap();
        std::fs::write(
            &cfg,
            format!(
                "[secret.\"api.example.com\"]\nfrom = \"sops://secrets/prod.enc.yaml#tok\"\n\
                 [task.t]\ncmd = [\"true\"]\n[task.t.secret]\nX = \"sops://{}#k\"\n",
                outside.join("far.enc.yaml").display()
            ),
        )
        .unwrap();

        let (_, inputs) = state_with_inputs(store.path(), &cfg);
        let tags: Vec<&str> = inputs.iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(
            tags,
            ["sops:secrets/prod.enc.yaml"],
            "only the named, in-project file"
        );

        trust(store.path(), &cfg).unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Trusted);

        std::fs::write(proj.join("stray.enc.yaml"), b"sops: {changed: 1}\n").unwrap();
        std::fs::write(outside.join("far.enc.yaml"), b"sops: {changed: 1}\n").unwrap();
        assert_eq!(
            state(store.path(), &cfg),
            TrustState::Trusted,
            "an unnamed or outside file does not re-arm the gate"
        );

        std::fs::write(proj.join("secrets/prod.enc.yaml"), b"sops:\n  kms: b\n").unwrap();
        assert_eq!(state(store.path(), &cfg), TrustState::Changed);
    }

    /// A terse `key` names its sops file through a `[… .sops] file` defaults table; that file is
    /// covered too, and a config naming no sops file keeps the hash of its bytes alone.
    #[test]
    fn a_sops_defaults_file_is_covered_and_a_config_without_one_hashes_alone() {
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(proj.join("prod.yaml"), b"sops: {}\n").unwrap();
        let text = b"[secret.defaults]\norder = [\"sops\"]\n[secret.defaults.sops]\nfile = \"prod.yaml\"\n";
        let inputs = sops_inputs_for(&cfg, text).unwrap();
        assert_eq!(
            inputs,
            [("sops:prod.yaml".to_string(), b"sops: {}\n".to_vec())]
        );

        let plain = b"network = \"isolated\"\n";
        assert!(sops_inputs_for(&cfg, plain).unwrap().is_empty());
        assert_eq!(content_hash(plain, &[]), hash_bytes(plain));
    }

    /// A sops file the gate refuses (here, one over the size ceiling) makes the project
    /// unverifiable, and `sbx trust` cannot fix that: the refusal names the file as a sops file,
    /// not a config, and points at the way out, an absolute path outside the project.
    #[test]
    fn a_refused_sops_file_is_named_with_its_way_out() {
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        let big = vec![b'a'; 1024 * 1024 + 1];
        std::fs::write(proj.join("big.enc.yaml"), &big).unwrap();
        let err = sops_inputs_for(&cfg, b"x = \"sops://big.enc.yaml#k\"\n").unwrap_err();
        let text = err.to_string();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{text}");
        for part in ["big.enc.yaml", "sops file", "larger than", "absolute path"] {
            assert!(text.contains(part), "missing `{part}`: {text}");
        }
        assert!(
            !text.contains("config"),
            "a sops file is not a config: {text}"
        );
    }

    /// The bytes a resolution may hand `sops`: `None` outside the project, the approved bytes for a
    /// covered file, and a refusal for every way a file in the project is not covered.
    #[test]
    fn covered_sops_bytes_answers_each_case() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let outside = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        let far = outside.join("far.enc.yaml");
        std::fs::write(&far, b"x").unwrap();
        assert_eq!(
            covered_sops_bytes(Some(store.path()), proj.path(), &far).unwrap(),
            None,
            "a file outside the project is decrypted where it is"
        );

        let file = Path::new("prod.enc.yaml");
        std::fs::write(proj.path().join(file), b"approved\n").unwrap();
        let refused = |why: &str| {
            let err = covered_sops_bytes(Some(store.path()), proj.path(), file).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            assert!(err.to_string().contains(why), "{why}: {err}");
        };
        refused("no .sbx.toml covers it");

        std::fs::write(&cfg, b"network = \"isolated\"\n").unwrap();
        trust(store.path(), &cfg).unwrap();
        refused("does not name it");

        std::fs::write(&cfg, b"x = \"sops://prod.enc.yaml#k\"\n").unwrap();
        refused("changed since it was trusted");
        trust(store.path(), &cfg).unwrap();
        assert_eq!(
            covered_sops_bytes(Some(store.path()), proj.path(), file).unwrap(),
            Some(b"approved\n".to_vec())
        );
        // The same file named absolutely is the same file.
        assert_eq!(
            covered_sops_bytes(Some(store.path()), proj.path(), &proj.path().join(file)).unwrap(),
            Some(b"approved\n".to_vec())
        );

        std::fs::write(proj.path().join(file), b"rewritten by the cage\n").unwrap();
        refused("changed since it was trusted");

        untrust(store.path(), &cfg).unwrap();
        refused("not trusted");
        let err = covered_sops_bytes(None, proj.path(), file).unwrap_err();
        assert!(err.to_string().contains("no trust store"), "{err}");
    }

    /// A link the cage plants in the project cannot carry a file out of the gate's reach: a path
    /// that reaches the project only through a link is still the project's.
    #[test]
    fn a_path_reaching_the_project_through_a_link_is_the_projects() {
        let store = TmpDir::new();
        let proj = TmpDir::new();
        let elsewhere = TmpDir::new();
        std::fs::write(proj.join("prod.enc.yaml"), b"x").unwrap();
        let link = elsewhere.join("into-project");
        std::os::unix::fs::symlink(proj.path(), &link).unwrap();
        let err = covered_sops_bytes(Some(store.path()), proj.path(), &link.join("prod.enc.yaml"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
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
    fn a_recorded_trust_leaves_the_marker_its_record_and_nothing_else() {
        // The marker and the record are written through temporaries and renamed. What a test can
        // hold is the aftermath: the store carries the marker, the record of what it approved and
        // no leftover, so a reader listing it never sees a half-written file, and a failed rename
        // does not accumulate debris.
        let tmp = TmpDir::new();
        let store = tmp.path().join("store");
        let cfg = tmp.path().join(".sbx.toml");
        std::fs::write(&cfg, b"network = \"none\"\n").unwrap();

        trust(&store, &cfg).expect("the fixture path is representable");
        let mut entries: Vec<_> = std::fs::read_dir(&store)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        let marker = marker_path(&store, &cfg).expect("a UTF-8 fixture path");
        let marker = marker.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            entries,
            [marker.clone(), format!("{marker}.approved")],
            "the store should hold the marker and its record alone"
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
        // canonical_string canonicalises the parent and re-appends the file name,
        // so a config present when trusted and gone when untrusted still derives
        // the same marker key.
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
    fn a_symlinked_config_does_not_inherit_the_trust_of_the_file_it_points_at() {
        // The marker key names the directory whose launch the config governs, not wherever the
        // config's final component resolves to. Git records symlinks, so a hostile repository can
        // ship `.sbx.toml` as one pointing at a project the user has already trusted; the safety
        // gate follows it (a symlink's own mode is meaningless on Linux, and the target is a
        // perfectly ordinary user-owned file), so the bytes read — and therefore the content hash
        // — are the trusted project's exactly. Resolving the leaf made the key the trusted
        // project's too, and the verdict came back `Trusted`: another project's secrets, egress
        // allowances and binds applied to a cage rooted in the hostile tree.
        let store = TmpDir::new();
        let trusted = TmpDir::new();
        let hostile = TmpDir::new();

        let real = trusted.join(".sbx.toml");
        std::fs::write(&real, b"network = \"allow\"\nbinds = [\"/etc/ssh\"]\n").unwrap();
        trust(store.path(), &real).unwrap();
        assert_eq!(state(store.path(), &real), TrustState::Trusted);

        let planted = hostile.join(".sbx.toml");
        std::os::unix::fs::symlink(&real, &planted).unwrap();
        assert_eq!(
            std::fs::read(&planted).unwrap(),
            std::fs::read(&real).unwrap(),
            "the fixture only bites while both paths read the same bytes"
        );
        assert_eq!(
            state(store.path(), &planted),
            TrustState::Untrusted,
            "a config in a directory that was never trusted must not read as trusted"
        );

        // The two keys are distinct, so blessing the planted one records a second marker rather
        // than overwriting the first: a trust decision belongs to one directory.
        assert_ne!(
            marker_path(store.path(), &real).expect("a UTF-8 fixture path"),
            marker_path(store.path(), &planted).expect("a UTF-8 fixture path"),
            "two directories must not share one trust record"
        );
        trust(store.path(), &planted).unwrap();
        assert_eq!(state(store.path(), &real), TrustState::Trusted);
        assert_eq!(state(store.path(), &planted), TrustState::Trusted);
    }

    #[test]
    fn canonicalize_existing_prefix_resolves_what_exists_and_keeps_what_does_not() {
        // `canonicalize` is all-or-nothing, so a path naming something not created yet used to come
        // back in whatever namespace it was written in. Both callers compare their result against
        // canonicalized paths, so an unresolved one silently matches nothing.
        let tmp = TmpDir::new();
        let real = tmp.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = tmp.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canon_real = real.canonicalize().expect("the fixture directory exists");

        // A fully existing path is plain canonicalization.
        assert_eq!(canonicalize_existing_prefix(&link), canon_real);
        // A tail that does not exist yet is re-appended to the resolved prefix, however deep.
        assert_eq!(
            canonicalize_existing_prefix(&link.join("sbx").join("trusted")),
            canon_real.join("sbx").join("trusted")
        );
        // A relative path is still keyed by an absolute one — the empty parent means "here".
        assert!(canonicalize_existing_prefix(Path::new("nowhere-at-all")).is_absolute());
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
        // none is dropped, so a tool or env entry in any of them is hashed. Three sit in a
        // subdirectory of the project, which mise reads the same way it reads the top-level ones.
        for dir in [".config/mise", ".mise", "mise"] {
            std::fs::create_dir_all(proj.join(dir)).unwrap();
        }
        for name in [
            "mise.toml",
            ".mise.toml",
            "mise.local.toml",
            ".mise.local.toml",
            "mise/config.toml",
            ".mise/config.toml",
            ".config/mise.toml",
            ".config/mise/config.toml",
        ] {
            std::fs::write(proj.join(name), b"").unwrap();
        }
        assert_eq!(
            mise_files_for(&cfg),
            vec![
                proj.join(".mise.local.toml"),
                proj.join("mise.local.toml"),
                proj.join(".mise.toml"),
                proj.join("mise.toml"),
                proj.join("mise/config.toml"),
                proj.join(".mise/config.toml"),
                proj.join(".config/mise.toml"),
                proj.join(".config/mise/config.toml"),
                proj.join(".tool-versions"),
            ]
        );
    }

    #[test]
    fn a_mise_file_in_a_subdirectory_re_arms_the_gate_like_a_top_level_one() {
        // The five names the set did not carry. mise reads them from the project directory the
        // same way it reads `mise.toml`, so a `[tools]`, an `[env]` or a `_.source` in one of them
        // steers what the cage runs — and a marker that does not cover them says the project is
        // unchanged while that file says something new. The four the set already carried are the
        // witness: they are edited in the same loop, and they re-arm.
        for name in [
            ".mise.local.toml",
            "mise/config.toml",
            ".mise/config.toml",
            ".config/mise.toml",
            ".config/mise/config.toml",
            // the witnesses
            "mise.local.toml",
            ".mise.toml",
            "mise.toml",
            ".tool-versions",
        ] {
            let store = TmpDir::new();
            let proj = TmpDir::new();
            let cfg = proj.join(".sbx.toml");
            std::fs::write(&cfg, b"x = 1\n").unwrap();
            if let Some(parent) = std::path::Path::new(name).parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(proj.path().join(parent)).unwrap();
            }
            std::fs::write(proj.join(name), b"[env]\nA = \"1\"\n").unwrap();

            trust(store.path(), &cfg).unwrap();
            assert_eq!(state(store.path(), &cfg), TrustState::Trusted, "{name}");

            std::fs::write(proj.join(name), b"[env]\nA = \"2\"\n").unwrap();
            assert_eq!(
                state(store.path(), &cfg),
                TrustState::Changed,
                "editing {name} must re-arm the gate"
            );
        }
    }

    #[test]
    fn two_mise_files_named_config_toml_are_told_apart_by_the_hash() {
        // `.mise/config.toml` and `.config/mise/config.toml` share a filename. The framing tags
        // each part, so tagging by filename would give the two the same tag and let their contents
        // be swapped under one marker.
        let proj = TmpDir::new();
        let cfg = proj.join(".sbx.toml");
        std::fs::write(&cfg, b"x = 1\n").unwrap();
        std::fs::create_dir_all(proj.join(".mise")).unwrap();
        std::fs::create_dir_all(proj.join(".config/mise")).unwrap();
        std::fs::write(proj.join(".mise/config.toml"), b"a\n").unwrap();
        std::fs::write(proj.join(".config/mise/config.toml"), b"b\n").unwrap();
        let before = content_hash(b"x = 1\n", &mise_inputs_for(&cfg).unwrap());

        // Swap the two bodies: the set of (name, bytes) pairs is different, so the hash must be.
        std::fs::write(proj.join(".mise/config.toml"), b"b\n").unwrap();
        std::fs::write(proj.join(".config/mise/config.toml"), b"a\n").unwrap();
        let after = content_hash(b"x = 1\n", &mise_inputs_for(&cfg).unwrap());
        assert_ne!(before, after, "the two files are told apart by their tag");

        let tags: Vec<String> = mise_inputs_for(&cfg)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(tags, vec![".mise/config.toml", ".config/mise/config.toml"]);
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

    #[test]
    fn a_recorded_trust_keeps_the_bytes_it_approved_and_untrust_drops_them() {
        let tmp = TmpDir::new();
        let store = tmp.path().join("store");
        let cfg = tmp.path().join(".sbx.toml");
        std::fs::write(&cfg, b"binds = [\"/srv/a\"]\n").unwrap();
        std::fs::write(tmp.path().join("mise.toml"), b"[tools]\nnode = \"22\"\n").unwrap();

        assert_eq!(
            approved(&store, &cfg),
            None,
            "nothing is recorded before a trust"
        );
        trust(&store, &cfg).unwrap();
        let (sbx, mise) = approved(&store, &cfg).expect("a trust records what it approved");
        assert_eq!(sbx, b"binds = [\"/srv/a\"]\n");
        assert_eq!(
            mise,
            vec![(
                "mise.toml".to_string(),
                b"[tools]\nnode = \"22\"\n".to_vec()
            )]
        );

        // An edit after the trust does not move the record: it is what was approved, not what is.
        std::fs::write(&cfg, b"binds = [\"/srv/b\"]\n").unwrap();
        assert_eq!(approved(&store, &cfg).unwrap().0, b"binds = [\"/srv/a\"]\n");

        assert!(untrust(&store, &cfg).unwrap());
        assert_eq!(
            approved(&store, &cfg),
            None,
            "a revoked trust keeps no record"
        );
    }

    #[test]
    fn a_truncated_record_reads_as_no_record() {
        let mut buf = Vec::new();
        frame(&mut buf, b"sbx.toml", b"network = \"none\"\n");
        frame(&mut buf, b"mise.toml", b"[tools]\n");
        assert_eq!(unframe(&buf).map(|p| p.len()), Some(2));
        for cut in 1..buf.len() {
            let parts = unframe(&buf[..cut]);
            assert!(
                parts.as_ref().is_none_or(|p| p.len() < 2),
                "a record cut at {cut} must never read back whole: {parts:?}"
            );
        }
    }
}
