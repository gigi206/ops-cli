//! The presentation-agnostic management engine for the on-disk config files.
//!
//! Where [`super::view`] projects the *resolved* configuration for reading, this edits the *raw*
//! layer files — a single `.ops.toml` (the project or global file, or an explicit path) — by
//! dotted key, preserving comments and formatting (`toml_edit`). It returns plain data and typed
//! [`ManageError`]s; the CLI maps those to messages, exit codes, and the trust interaction, and a
//! future management front-end maps them to its own surface. It deliberately does no trust work
//! and no resolution itself — a write changes a file, and the caller decides what that means for
//! the whole-file trust hash.
//!
//! Scope: `get`/`set`/`unset` address a *scalar string* leaf (`env.FOO`, `network`, `nixpkgs`,
//! `packages.jq`). Array and table-of-table fields (`binds`, an allowlist, `[secret]`, `[app]`)
//! are reported as non-scalar — they are edited through `$EDITOR`, not a single typed value.

use std::path::{Path, PathBuf};

use toml_edit::{value, DocumentMut, Item, Table, Value};

/// Which config file an operation targets.
pub(crate) enum Scope {
    /// The project's `.ops.toml` in the working directory — the default.
    Local,
    /// The user's global `ops.toml`.
    Global,
    /// An explicit file path.
    File(PathBuf),
}

/// A typed failure from a management operation. The CLI renders it (and picks an exit code); a
/// front-end maps it to its own error shape.
#[derive(Debug)]
pub(crate) enum ManageError {
    /// No global config directory could be determined for a `--global` operation.
    NoGlobalDir,
    /// Reading the target file failed (an I/O error other than "absent").
    Read(PathBuf, String),
    /// Writing the target file failed.
    Write(PathBuf, String),
    /// The existing file is not valid TOML, so it cannot be edited without clobbering it.
    Parse(PathBuf, String),
    /// The dotted key is empty or has an empty segment.
    BadKey(String),
    /// The key resolves onto or through a non-scalar (an array or a table) — use `$EDITOR`.
    NotScalar(String),
}

impl std::fmt::Display for ManageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManageError::NoGlobalDir => {
                write!(f, "no global config directory (set XDG_CONFIG_HOME or HOME)")
            }
            ManageError::Read(p, e) => write!(f, "cannot read {}: {e}", p.display()),
            ManageError::Write(p, e) => write!(f, "cannot write {}: {e}", p.display()),
            ManageError::Parse(p, e) => write!(f, "{} is not valid TOML: {e}", p.display()),
            ManageError::BadKey(k) => write!(f, "invalid key {k:?}"),
            ManageError::NotScalar(k) => write!(
                f,
                "{k} is not a single value (it is an array or table) — edit it with `ops config edit`"
            ),
        }
    }
}

/// Resolve a scope to the concrete file path it targets. The file need not exist yet (a `set`
/// creates it); `get`/`unset` simply treat an absent file as having no keys.
pub(crate) fn scope_path(scope: &Scope, cwd: &Path) -> Result<PathBuf, ManageError> {
    match scope {
        Scope::Local => Ok(cwd.join(super::PROJECT_CONFIG)),
        Scope::Global => super::global_path().ok_or(ManageError::NoGlobalDir),
        Scope::File(p) => Ok(p.clone()),
    }
}

/// The declared value at a dotted key in the target file, or `None` if it (or any parent) is
/// absent. A string is returned unquoted; another scalar (number, bool) is rendered as written;
/// a non-scalar leaf is a [`ManageError::NotScalar`].
pub(crate) fn get(path: &Path, key: &str) -> Result<Option<String>, ManageError> {
    let doc = read_or_empty(path)?;
    let segments = split_key(key)?;
    let (parents, leaf) = segments.split_at(segments.len() - 1);

    let mut table = doc.as_table();
    for seg in parents {
        match table.get(seg).and_then(Item::as_table) {
            Some(t) => table = t,
            None => return Ok(None),
        }
    }
    match table.get(leaf[0]) {
        None => Ok(None),
        Some(Item::Value(v)) if v.is_str() => Ok(v.as_str().map(str::to_string)),
        Some(Item::Value(v)) if !v.is_array() && !v.is_inline_table() => {
            Ok(Some(v.to_string().trim().to_string()))
        }
        Some(_) => Err(ManageError::NotScalar(key.to_string())),
    }
}

/// Set a string value at a dotted key, preserving the rest of the file. Creates the file and any
/// intermediate tables as needed. Returns whether the key was created (vs updated in place).
pub(crate) fn set(path: &Path, key: &str, val: &str) -> Result<bool, ManageError> {
    let mut doc = read_or_empty(path)?;
    let segments = split_key(key)?;
    let (parents, leaf) = segments.split_at(segments.len() - 1);

    let mut table = doc.as_table_mut();
    for seg in parents {
        table = table
            .entry(seg)
            .or_insert_with(|| Item::Table(Table::new()))
            .as_table_mut()
            .ok_or_else(|| ManageError::NotScalar(key.to_string()))?;
    }
    let created = match table.get_mut(leaf[0]) {
        // A new key: insert it with default formatting.
        None => {
            table.insert(leaf[0], value(val));
            true
        }
        // An existing scalar: replace only its content, keeping the surrounding decor (the
        // comments and whitespace around it) — a plain `insert` would drop them.
        Some(Item::Value(v)) if !v.is_array() && !v.is_inline_table() => {
            let mut replacement = Value::from(val);
            *replacement.decor_mut() = v.decor().clone();
            *v = replacement;
            false
        }
        // An array or table leaf: refuse rather than silently drop what the user meant to edit.
        Some(_) => return Err(ManageError::NotScalar(key.to_string())),
    };
    write_doc(path, &doc)?;
    Ok(created)
}

/// Remove a dotted key. Returns whether it existed. An absent file or parent is simply "not
/// present" (returns `false`), never an error.
pub(crate) fn unset(path: &Path, key: &str) -> Result<bool, ManageError> {
    let mut doc = read_or_empty(path)?;
    let segments = split_key(key)?;
    let (parents, leaf) = segments.split_at(segments.len() - 1);

    let mut table = doc.as_table_mut();
    for seg in parents {
        match table.get_mut(seg).and_then(Item::as_table_mut) {
            Some(t) => table = t,
            None => return Ok(false),
        }
    }
    let existed = table.remove(leaf[0]).is_some();
    if existed {
        write_doc(path, &doc)?;
    }
    Ok(existed)
}

/// Split a dotted key into its segments, rejecting an empty key or an empty segment (`a..b`).
fn split_key(key: &str) -> Result<Vec<&str>, ManageError> {
    if key.is_empty() {
        return Err(ManageError::BadKey(key.to_string()));
    }
    let segments: Vec<&str> = key.split('.').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(ManageError::BadKey(key.to_string()));
    }
    Ok(segments)
}

/// Parse the file into an editable document, treating an absent file as an empty one (so a `set`
/// can create it and a `get`/`unset` simply finds nothing).
fn read_or_empty(path: &Path) -> Result<DocumentMut, ManageError> {
    match std::fs::read_to_string(path) {
        Ok(text) => text
            .parse::<DocumentMut>()
            .map_err(|e| ManageError::Parse(path.to_path_buf(), e.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(e) => Err(ManageError::Read(path.to_path_buf(), e.to_string())),
    }
}

/// Write the document atomically (temp sibling then rename), so a crash mid-write never leaves a
/// truncated config a launch would then fail to parse. Creates the parent directory as needed —
/// the global config dir (or an explicit `-c dir/file.toml` whose directory does not exist yet)
/// may be absent on a first write.
fn write_doc(path: &Path, doc: &DocumentMut) -> Result<(), ManageError> {
    let err = |e: std::io::Error| ManageError::Write(path.to_path_buf(), e.to_string());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(err)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ops.toml");
    let tmp = dir.join(format!(".{name}.ops-tmp"));
    std::fs::write(&tmp, doc.to_string()).map_err(err)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        err(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_at(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join(".ops.toml");
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn get_reads_a_scalar_and_a_nested_key() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "nixpkgs = \"nixos-23.11\"\n[env]\nFOO = \"bar\"\n",
        );
        assert_eq!(get(&p, "nixpkgs").unwrap().as_deref(), Some("nixos-23.11"));
        assert_eq!(get(&p, "env.FOO").unwrap().as_deref(), Some("bar"));
        assert_eq!(get(&p, "env.MISSING").unwrap(), None);
        assert_eq!(get(&p, "absent").unwrap(), None);
    }

    #[test]
    fn get_on_a_table_or_array_is_not_scalar() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "binds = [\"/a\"]\n[env]\nFOO = \"bar\"\n");
        assert!(matches!(get(&p, "binds"), Err(ManageError::NotScalar(_))));
        assert!(matches!(get(&p, "env"), Err(ManageError::NotScalar(_))));
    }

    #[test]
    fn set_preserves_comments_and_other_keys() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "# keep me\nnixpkgs = \"old\"\n\n[env]\nFOO = \"bar\" # inline\n",
        );
        assert!(
            !set(&p, "nixpkgs", "new").unwrap(),
            "nixpkgs already existed"
        );
        assert!(set(&p, "env.BAZ", "qux").unwrap(), "env.BAZ is new");
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("# keep me"), "comment preserved:\n{after}");
        assert!(
            after.contains("# inline"),
            "inline comment preserved:\n{after}"
        );
        assert!(
            after.contains("nixpkgs = \"new\""),
            "value updated:\n{after}"
        );
        assert!(after.contains("FOO = \"bar\""), "sibling kept:\n{after}");
        assert!(after.contains("BAZ = \"qux\""), "new key added:\n{after}");
    }

    #[test]
    fn set_creates_a_missing_file_and_its_tables() {
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join(".ops.toml");
        assert!(set(&p, "env.A", "1").unwrap(), "created in a new file");
        assert_eq!(get(&p, "env.A").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn set_creates_a_missing_parent_directory() {
        // The global config dir, or an explicit `-c nested/dir/file.toml`, may not exist on a
        // first write — the atomic placement must create the directory, not fail on it.
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join("nested").join("dir").join("ops.toml");
        assert!(set(&p, "env.A", "1").unwrap(), "created under a new dir");
        assert_eq!(get(&p, "env.A").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn set_refuses_to_clobber_a_table_or_array() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "binds = [\"/a\"]\n[env]\nFOO = \"x\"\n");
        assert!(matches!(
            set(&p, "binds", "y"),
            Err(ManageError::NotScalar(_))
        ));
        assert!(matches!(
            set(&p, "env", "y"),
            Err(ManageError::NotScalar(_))
        ));
    }

    #[test]
    fn unset_removes_a_key_and_reports_existence() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[env]\nFOO = \"bar\"\nBAZ = \"qux\"\n");
        assert!(unset(&p, "env.FOO").unwrap(), "FOO existed");
        assert!(!unset(&p, "env.FOO").unwrap(), "already gone");
        assert!(!unset(&p, "absent.key").unwrap(), "absent parent");
        assert_eq!(get(&p, "env.BAZ").unwrap().as_deref(), Some("qux"));
    }

    #[test]
    fn a_bad_key_is_rejected() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "a = \"b\"\n");
        assert!(matches!(get(&p, ""), Err(ManageError::BadKey(_))));
        assert!(matches!(set(&p, "a..b", "1"), Err(ManageError::BadKey(_))));
    }
}
