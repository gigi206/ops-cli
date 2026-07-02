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

use toml_edit::{value, Array, DocumentMut, Item, Table, Value};

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
    /// A `deny` rule was added but there is no filtering posture to carry it (and a `deny` must
    /// not silently create an open denylist) — the user must set a posture first.
    DenyNeedsPosture,
    /// The target's network is explicitly `shared`/`none` (a non-filtering posture); adding a rule
    /// would silently flip a deliberate choice, so refuse and let the user change it explicitly.
    NonFilteringPosture(String),
    /// The `network` field is neither a posture string nor a table (a malformed config) — refuse
    /// rather than guess.
    MalformedNetwork(String),
}

/// Which egress list a rule is added to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressList {
    Allow,
    Deny,
}

impl EgressList {
    fn key(self) -> &'static str {
        match self {
            EgressList::Allow => "allow",
            EgressList::Deny => "deny",
        }
    }
}

/// The result of adding an egress rule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AddOutcome {
    /// The rule was added. `created_mode` is the mode of a `[network]` table this call created —
    /// either by bootstrapping a fresh allowlist (`"deny"`) or by promoting a bare-string posture
    /// to the table form (the kept mode) — or `None` when it appended to an existing table.
    Added { created_mode: Option<String> },
    /// The rule was already present (an exact-string match): a no-op.
    AlreadyPresent,
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
            ManageError::DenyNeedsPosture => write!(
                f,
                "no filtering network posture is set, and a `deny` rule must not open one — set a \
                 posture first: `ops config set network allow` (a denylist) then `ops trust`"
            ),
            ManageError::NonFilteringPosture(p) => write!(
                f,
                "the network is explicitly `{p}`; change the posture first \
                 (`ops config set network deny|allow`) before adding rules"
            ),
            ManageError::MalformedNetwork(s) => {
                write!(f, "the `network` field is malformed ({s}) — edit it with `ops config edit`")
            }
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

/// Resolve a scope to the file an **app-scoped** operation targets. This diverges from
/// [`scope_path`] only for [`Scope::Global`]: a global app lives as a profile file under
/// `apps/<name>.toml` (an inline `[app.<name>]` in `ops.toml` is forbidden), so an app-scoped
/// global write reaches the profile, not the global config. [`Scope::Local`] still targets the
/// project `.ops.toml` (a project-scoped `[app.<name>]` overlay is allowed), and [`Scope::File`]
/// targets the explicit path unchanged. The file need not exist yet — an app-scoped global write
/// creates the profile.
pub(crate) fn scope_app_path(scope: &Scope, cwd: &Path, app: &str) -> Result<PathBuf, ManageError> {
    match scope {
        Scope::Local => Ok(cwd.join(super::PROJECT_CONFIG)),
        Scope::Global => super::profile_path(app).ok_or(ManageError::NoGlobalDir),
        Scope::File(p) => Ok(p.clone()),
    }
}

/// One config file in resolution order, for `ops config path`'s overview. `path` is `None` only
/// for the global layer when no config directory resolves (no `$XDG_CONFIG_HOME`/`$HOME`).
pub(crate) struct Layer {
    /// A short label (`"global"` / `"project"`).
    pub(crate) label: &'static str,
    /// The layer's file, derived through [`scope_path`] so the overview can never disagree with
    /// the scoped single-path forms.
    pub(crate) path: Option<PathBuf>,
}

/// The config files a launch resolves, in order: the global `ops.toml` (the base layer) then the
/// project `.ops.toml`, which overlays it (so the project wins). Each path comes through
/// [`scope_path`] — the same primitive `--global`/`--local` target — so this overview and those
/// single-path forms stay byte-identical.
pub(crate) fn resolution_layers(cwd: &Path) -> Vec<Layer> {
    vec![
        Layer {
            label: "global",
            path: scope_path(&Scope::Global, cwd).ok(),
        },
        Layer {
            label: "project",
            path: scope_path(&Scope::Local, cwd).ok(),
        },
    ]
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

/// Add an egress `rule` to the `list` (allow/deny) of the target file's network policy — the
/// baseline `[network]` when `app` is `None`, or `[app.<name>.network]` when `Some(name)`.
///
/// The posture matrix (the caller's trust check is separate and runs first): an absent network with
/// `allow` bootstraps a deny-by-default allowlist with the rule, while with `deny` it is a
/// [`ManageError::DenyNeedsPosture`] (a deny must not open a posture); a bare-string
/// `deny`/`allow`/`allowlist` is promoted to the table form keeping its mode; a bare-string
/// `shared`/`none` is a [`ManageError::NonFilteringPosture`] (do not flip a deliberate choice); and
/// an existing `[network]` table (regular or inline) gets the rule appended, idempotent on the exact
/// string. Preserves comments/formatting and writes atomically. The outcome names any posture it
/// created.
pub(crate) fn add_egress_rule(
    path: &Path,
    app: Option<&str>,
    list: EgressList,
    rule: &str,
) -> Result<AddOutcome, ManageError> {
    // Inspect the current `network` field into an owned decision first, so the read borrow is
    // released before the document is mutated below.
    enum NetCase {
        Absent,
        BareFiltering(String),
        BareNonFiltering(String),
        Table,
        Inline,
        Malformed(String),
    }

    let mut doc = read_or_empty(path)?;
    let parent = network_parent(&mut doc, app)?;
    let case = match parent.get("network") {
        None => NetCase::Absent,
        Some(Item::Value(v)) if v.is_str() => {
            let s = v.as_str().unwrap_or_default().to_string();
            match s.as_str() {
                "deny" | "allow" | "allowlist" | "ask" => NetCase::BareFiltering(s),
                "shared" | "none" => NetCase::BareNonFiltering(s),
                _ => NetCase::Malformed(format!("unknown posture {s:?}")),
            }
        }
        Some(Item::Table(_)) => NetCase::Table,
        Some(Item::Value(v)) if v.is_inline_table() => NetCase::Inline,
        Some(_) => NetCase::Malformed("not a posture string or table".into()),
    };

    let outcome = match case {
        NetCase::Absent => {
            // A deny rule must not silently create an open denylist; only `allow` bootstraps, into
            // the most restrictive (deny-by-default) posture.
            if list == EgressList::Deny {
                return Err(ManageError::DenyNeedsPosture);
            }
            parent.insert(
                "network",
                Item::Table(new_network_table("deny", list, rule)),
            );
            AddOutcome::Added {
                created_mode: Some("deny".into()),
            }
        }
        NetCase::BareFiltering(mode) => {
            // Promote the bare-string posture to the table form, keeping its mode, with the rule.
            parent.insert("network", Item::Table(new_network_table(&mode, list, rule)));
            AddOutcome::Added {
                created_mode: Some(mode),
            }
        }
        NetCase::BareNonFiltering(p) => return Err(ManageError::NonFilteringPosture(p)),
        NetCase::Malformed(m) => return Err(ManageError::MalformedNetwork(m)),
        NetCase::Table => {
            let t = parent["network"]
                .as_table_mut()
                .expect("inspected as a regular table");
            // A `[network] mode = "shared"/"none"` table ignores the allow/deny lists at
            // resolution, so appending a rule would be inert — refuse it like the bare-string path,
            // rather than report a rule "added" that never takes effect.
            refuse_non_filtering(t.get("mode").and_then(Item::as_str))?;
            let arr = t
                .entry(list.key())
                .or_insert_with(|| value(Array::new()))
                .as_array_mut()
                .ok_or_else(|| {
                    ManageError::MalformedNetwork(format!("`{}` is not an array", list.key()))
                })?;
            push_outcome(arr, rule)
        }
        NetCase::Inline => {
            let it = parent["network"]
                .as_value_mut()
                .and_then(Value::as_inline_table_mut)
                .expect("inspected as an inline table");
            refuse_non_filtering(it.get("mode").and_then(Value::as_str))?;
            let arr = it
                .entry(list.key())
                .or_insert_with(|| Value::Array(Array::new()))
                .as_array_mut()
                .ok_or_else(|| {
                    ManageError::MalformedNetwork(format!("`{}` is not an array", list.key()))
                })?;
            push_outcome(arr, rule)
        }
    };

    write_doc(path, &doc)?;
    Ok(outcome)
}

/// Refuse adding an allow/deny rule to an explicit non-filtering posture (`shared`/`none`), where
/// the lists are ignored at resolution — the same guard the bare-string path applies, so the table
/// and inline-table forms cannot silently accept an inert rule. A missing or filtering `mode` is
/// fine (the rule takes effect).
fn refuse_non_filtering(mode: Option<&str>) -> Result<(), ManageError> {
    match mode {
        Some(m @ ("shared" | "none")) => Err(ManageError::NonFilteringPosture(m.to_string())),
        _ => Ok(()),
    }
}

/// The table where the `network` key lives: the document root for the baseline, or the
/// `[app.<name>]` table (created if absent) for an app overlay.
fn network_parent<'a>(
    doc: &'a mut DocumentMut,
    app: Option<&str>,
) -> Result<&'a mut Table, ManageError> {
    match app {
        None => Ok(doc.as_table_mut()),
        Some(name) => {
            // Create the `[app]` and `[app.<name>]` parents as *implicit* tables so a fresh one
            // prints no empty header — only the `[app.<name>.network]` we fill renders. An existing
            // table is left as-is (its own contents decide whether its header shows).
            let root = doc.as_table_mut();
            if !root.contains_key("app") {
                root.insert("app", Item::Table(implicit_table()));
            }
            let apps = root
                .get_mut("app")
                .and_then(Item::as_table_mut)
                .ok_or_else(|| ManageError::NotScalar("app".into()))?;
            if !apps.contains_key(name) {
                apps.insert(name, Item::Table(implicit_table()));
            }
            apps.get_mut(name)
                .and_then(Item::as_table_mut)
                .ok_or_else(|| ManageError::NotScalar(format!("app.{name}")))
        }
    }
}

/// A table whose header is hidden when it carries only sub-tables (a structural parent).
fn implicit_table() -> Table {
    let mut t = Table::new();
    t.set_implicit(true);
    t
}

/// A fresh `[network]` table carrying `mode` and one `rule` in `list`.
fn new_network_table(mode: &str, list: EgressList, rule: &str) -> Table {
    let mut t = Table::new();
    t.insert("mode", value(mode));
    let mut arr = Array::new();
    arr.push(rule);
    t.insert(list.key(), value(arr));
    t
}

/// Push `rule` into `arr` unless an exact-string match is already present, reporting which.
fn push_outcome(arr: &mut Array, rule: &str) -> AddOutcome {
    if arr.iter().any(|v| v.as_str() == Some(rule)) {
        return AddOutcome::AlreadyPresent;
    }
    arr.push(rule);
    AddOutcome::Added { created_mode: None }
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
    fn resolution_layers_match_the_scoped_paths_they_overview() {
        // The overview must never drift from the single-path forms `--global`/`--local` print, so
        // its layers are derived through `scope_path` — pin that here.
        let cwd = Path::new("/some/project");
        let layers = resolution_layers(cwd);
        assert_eq!(layers[0].label, "global");
        assert_eq!(layers[0].path, scope_path(&Scope::Global, cwd).ok());
        assert_eq!(layers[1].label, "project");
        assert_eq!(
            layers[1].path,
            Some(scope_path(&Scope::Local, cwd).unwrap())
        );
        assert_eq!(layers[1].path, Some(cwd.join(".ops.toml")));
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

    #[test]
    fn add_egress_rule_bootstraps_an_allowlist_for_allow_on_a_fresh_config() {
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join(".ops.toml");
        let out = add_egress_rule(&p, None, EgressList::Allow, "github.com").unwrap();
        assert_eq!(
            out,
            AddOutcome::Added {
                created_mode: Some("deny".into())
            }
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("mode = \"deny\"") && body.contains("allow = [\"github.com\"]"),
            "{body}"
        );
    }

    #[test]
    fn add_egress_rule_refuses_a_deny_with_no_posture_without_writing() {
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join(".ops.toml");
        assert!(matches!(
            add_egress_rule(&p, None, EgressList::Deny, "evil.com"),
            Err(ManageError::DenyNeedsPosture)
        ));
        assert!(!p.exists(), "a refused deny must not create the file");
    }

    #[test]
    fn add_egress_rule_promotes_a_bare_string_posture_keeping_its_mode() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "network = \"allow\"\n");
        let out = add_egress_rule(&p, None, EgressList::Deny, "evil.com").unwrap();
        assert_eq!(
            out,
            AddOutcome::Added {
                created_mode: Some("allow".into())
            }
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("[network]") && body.contains("mode = \"allow\""),
            "{body}"
        );
        assert!(body.contains("deny = [\"evil.com\"]"), "{body}");
        assert!(
            !body.contains("network = \"allow\""),
            "the bare string must be promoted, not kept:\n{body}"
        );
    }

    #[test]
    fn add_egress_rule_refuses_an_explicit_non_filtering_posture() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "network = \"shared\"\n");
        assert!(matches!(
            add_egress_rule(&p, None, EgressList::Allow, "x.com"),
            Err(ManageError::NonFilteringPosture(s)) if s == "shared"
        ));
    }

    #[test]
    fn add_egress_rule_refuses_a_non_filtering_table_and_inline_table() {
        // A `[network] mode = "shared"/"none"` table (or its inline form) ignores allow/deny at
        // resolution, so appending a rule must be refused — not reported "added" yet inert.
        for body in [
            "[network]\nmode = \"shared\"\n",
            "[network]\nmode = \"none\"\nallow = []\n",
            "network = { mode = \"shared\" }\n",
        ] {
            let tmp = crate::testutil::TmpDir::new();
            let p = doc_at(tmp.path(), body);
            assert!(
                matches!(
                    add_egress_rule(&p, None, EgressList::Deny, "evil.com"),
                    Err(ManageError::NonFilteringPosture(_))
                ),
                "expected a non-filtering refusal for {body:?}"
            );
        }
    }

    #[test]
    fn add_egress_rule_appends_to_a_table_and_is_idempotent() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "[network]\nmode = \"deny\"\nallow = [\"a.com\"]\n",
        );
        assert_eq!(
            add_egress_rule(&p, None, EgressList::Allow, "b.com").unwrap(),
            AddOutcome::Added { created_mode: None }
        );
        assert_eq!(
            add_egress_rule(&p, None, EgressList::Deny, "evil.com").unwrap(),
            AddOutcome::Added { created_mode: None }
        );
        // An exact-string match already present is a no-op.
        assert_eq!(
            add_egress_rule(&p, None, EgressList::Allow, "b.com").unwrap(),
            AddOutcome::AlreadyPresent
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("\"a.com\"")
                && body.contains("\"b.com\"")
                && body.contains("\"evil.com\""),
            "{body}"
        );
    }

    #[test]
    fn add_egress_rule_writes_the_apps_own_network_table_with_implicit_parents() {
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join(".ops.toml");
        add_egress_rule(&p, Some("claude"), EgressList::Allow, "api.anthropic.com").unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("[app.claude.network]") && body.contains("api.anthropic.com"),
            "{body}"
        );
        // The structural parents are implicit, so no empty `[app]` / `[app.claude]` headers.
        assert!(
            !body.contains("[app]\n") && !body.contains("[app.claude]\n"),
            "parent tables must be implicit:\n{body}"
        );
    }

    #[test]
    fn scope_app_path_local_targets_the_project_config_and_file_the_explicit_path() {
        // `Local` targets the project `.ops.toml` (a project-scoped `[app.<name>]` overlay is still
        // allowed); `File` targets the explicit path unchanged. The `Global` arm depends on the
        // config-home env, so it is covered hermetically by the integration test
        // `net_allow_app_save_global_writes_to_profile_and_preserves_profile_fields` instead.
        let cwd = std::path::Path::new("/some/cwd");
        assert_eq!(
            scope_app_path(&Scope::Local, cwd, "claude").unwrap(),
            cwd.join(crate::config::PROJECT_CONFIG)
        );
        let explicit = std::path::PathBuf::from("/etc/ops.toml");
        assert_eq!(
            scope_app_path(&Scope::File(explicit.clone()), cwd, "x").unwrap(),
            explicit
        );
    }

    #[test]
    fn add_egress_rule_writes_a_top_level_network_table_into_a_profile_file() {
        // A global app lives as a profile file (`apps/<name>.toml`), a top-level `RawApp` whose
        // network lives at `[network]` (not `[app.<name>.network]`). An app-scoped global
        // allow-rule save passes `app = None` so `add_egress_rule` writes the top-level table. On a
        // fresh profile the Absent bootstrap creates a deny-by-default allowlist with the host.
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join("apps").join("demo.toml");
        add_egress_rule(&p, None, EgressList::Allow, "api.x.com").unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("[network]")
                && body.contains("mode = \"deny\"")
                && body.contains("api.x.com"),
            "{body}"
        );
        assert!(
            !body.contains("[app."),
            "a profile carries a top-level `[network]`, never `[app.<name>.network]`:\n{body}"
        );
        // The written file parses as a top-level `RawApp` carrying the network field.
        let app = crate::config::schema::parse_app(body.as_bytes()).expect("parses as a RawApp");
        assert!(
            app.network.is_some(),
            "the profile carries the network field"
        );
    }

    #[test]
    fn add_egress_rule_appends_into_an_inline_table() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "network = { mode = \"deny\", allow = [\"a.com\"] }\n",
        );
        assert_eq!(
            add_egress_rule(&p, None, EgressList::Allow, "b.com").unwrap(),
            AddOutcome::Added { created_mode: None }
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("a.com") && body.contains("b.com"), "{body}");
        // Idempotent within the inline form too.
        assert_eq!(
            add_egress_rule(&p, None, EgressList::Allow, "b.com").unwrap(),
            AddOutcome::AlreadyPresent
        );
    }

    #[test]
    fn add_egress_rule_refuses_a_malformed_network_field() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "network = 42\n");
        assert!(matches!(
            add_egress_rule(&p, None, EgressList::Allow, "x.com"),
            Err(ManageError::MalformedNetwork(_))
        ));
    }
}
