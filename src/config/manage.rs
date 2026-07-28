//! The presentation-agnostic management engine for the on-disk config files.
//!
//! Where [`super::view`] projects the *resolved* configuration for reading, this edits the *raw*
//! layer files — a single `.sbx.toml` (the project or global file, or an explicit path) — by
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

use toml_edit::{value, Array, DocumentMut, Item, Table, TableLike, Value};

/// Which config file an operation targets.
pub(crate) enum Scope {
    /// The project's `.sbx.toml` in the working directory — the default.
    Local,
    /// The user's global `sbx.toml`.
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
    /// The value would make the whole layer unparseable (a type the schema rejects), so the write
    /// was refused rather than committed — a committed invalid layer is silently dropped at load.
    InvalidValue(String, String),
    /// A `deny` rule was added but there is no filtering posture to carry it (and a `deny` must
    /// not silently create an open denylist) — the user must set a posture first.
    DenyNeedsPosture,
    /// A `mute` rule was added but there is no filtering posture to carry it — a mute suppresses a
    /// *denied* request's log line, so with no proxy (a non-filtering posture) there is nothing to
    /// mute; refuse rather than write an inert rule.
    MuteNeedsPosture,
    /// The target's network is explicitly `shared`/`none` (a non-filtering posture); adding a rule
    /// would silently flip a deliberate choice, so refuse and let the user change it explicitly.
    NonFilteringPosture(String),
    /// The `network` field is neither a posture string nor a table (a malformed config) — refuse
    /// rather than guess.
    MalformedNetwork(String),
    /// An egress-group import named one or more groups that already exist and `--force` was not
    /// given — nothing was written, so the user can decide (overwrite with `--force`, or rename).
    GroupCollision(Vec<String>),
    /// The same, for a bundle import. A distinct variant rather than a shared one carrying a noun:
    /// the message names what the user actually typed, and a misnamed collision is exactly the kind
    /// of small lie that makes an error message useless.
    BundleCollision(Vec<String>),
    /// An `allow` proc rule was added but the `[proc]` mode is not `ask` — an allow rule only takes
    /// effect under `ask` (under `enforce` everything not denied already runs, so the rule would be
    /// inert). Refuse rather than write a rule that does nothing.
    ProcAllowNeedsPosture,
    /// A proc rule was added but the `[proc]` mode is `off`/`observe` — a non-enforcing mode ignores
    /// the allow/deny lists, so the rule would be inert; set an enforcing mode first.
    ProcNonEnforcingPosture(String),
    /// A `deny` proc rule was added to an existing `[proc]` table that carries no `mode` — its
    /// effective mode is ambiguous to a file writer (it may inherit a baseline), so refuse and let
    /// the user set one explicitly.
    ProcNeedsMode,
    /// The `proc` field is neither a mode string nor a table (a malformed config) — refuse rather
    /// than guess.
    MalformedProc(String),
}

/// Which egress list a rule is added to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressList {
    Allow,
    Deny,
    /// The `mute` list — a `dontaudit` log filter (a denied request's line is suppressed from the
    /// default `sbx net log`), never a verdict. Same on-disk shape and grammar as `allow`/`deny`.
    Mute,
}

impl EgressList {
    fn key(self) -> &'static str {
        match self {
            EgressList::Allow => "allow",
            EgressList::Deny => "deny",
            EgressList::Mute => "mute",
        }
    }
}

/// Which process/exec list a rule is added to (`[proc].allow` / `[proc].deny`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcList {
    Allow,
    Deny,
}

impl ProcList {
    fn key(self) -> &'static str {
        match self {
            ProcList::Allow => "allow",
            ProcList::Deny => "deny",
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
                "{k} is not a single value (it is an array or table) — edit it with `sbx config edit`"
            ),
            ManageError::InvalidValue(k, detail) => write!(
                f,
                "the value for {k} is not valid there ({detail}) — nothing was written; \
                 check the expected type with `sbx config edit`"
            ),
            ManageError::DenyNeedsPosture => write!(
                f,
                "no filtering network posture is set, and a `deny` rule must not open one — set a \
                 posture first: `sbx config set network allow` (a denylist) then `sbx trust`"
            ),
            ManageError::MuteNeedsPosture => write!(
                f,
                "no filtering network posture is set, so a `mute` rule would be inert (there is no \
                 proxy to suppress a refusal from) — set a posture first \
                 (`sbx config set network deny|allow`), then `sbx net mute`"
            ),
            ManageError::NonFilteringPosture(p) => write!(
                f,
                "the network is explicitly `{p}`; change the posture first \
                 (`sbx config set network deny|allow`) before adding rules"
            ),
            ManageError::MalformedNetwork(s) => {
                write!(f, "the `network` field is malformed ({s}) — edit it with `sbx config edit`")
            }
            ManageError::GroupCollision(names) => write!(
                f,
                "{} already defined: {} — re-run with --force to overwrite",
                if names.len() == 1 { "group" } else { "groups" },
                names.join(", ")
            ),
            ManageError::BundleCollision(names) => write!(
                f,
                "{} already defined: {} — re-run with --force to overwrite",
                if names.len() == 1 { "bundle" } else { "bundles" },
                names.join(", ")
            ),
            ManageError::ProcAllowNeedsPosture => write!(
                f,
                "an `allow` rule only takes effect under `[proc] mode = \"ask\"` (under `enforce` \
                 everything not denied already runs) — set `mode = \"ask\"` first with \
                 `sbx config edit`, or use `deny`"
            ),
            ManageError::ProcNonEnforcingPosture(m) => write!(
                f,
                "the `[proc]` mode is `{m}`, which ignores allow/deny rules — set `mode = \"enforce\"` \
                 (or `\"ask\"`) first with `sbx config edit`"
            ),
            ManageError::ProcNeedsMode => write!(
                f,
                "the `[proc]` table has no `mode` — set `mode = \"enforce\"` (or `\"ask\"`) first with \
                 `sbx config edit` so the rule takes effect"
            ),
            ManageError::MalformedProc(s) => {
                write!(f, "the `proc` field is malformed ({s}) — edit it with `sbx config edit`")
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
/// `apps/<name>.toml` (an inline `[app.<name>]` in `sbx.toml` is forbidden), so an app-scoped
/// global write reaches the profile, not the global config. [`Scope::Local`] still targets the
/// project `.sbx.toml` (a project-scoped `[app.<name>]` overlay is allowed), and [`Scope::File`]
/// targets the explicit path unchanged. The file need not exist yet — an app-scoped global write
/// creates the profile.
pub(crate) fn scope_app_path(scope: &Scope, cwd: &Path, app: &str) -> Result<PathBuf, ManageError> {
    match scope {
        Scope::Local => Ok(cwd.join(super::PROJECT_CONFIG)),
        Scope::Global => super::profile_path(app).ok_or(ManageError::NoGlobalDir),
        Scope::File(p) => Ok(p.clone()),
    }
}

/// One config file in resolution order, for `sbx config path`'s overview. `path` is `None` only
/// for the global layer when no config directory resolves (no `$XDG_CONFIG_HOME`/`$HOME`).
pub(crate) struct Layer {
    /// A short label (`"global"` / `"project"`).
    pub(crate) label: &'static str,
    /// The layer's file, derived through [`scope_path`] so the overview can never disagree with
    /// the scoped single-path forms.
    pub(crate) path: Option<PathBuf>,
}

/// The config files a launch resolves, in order: the global `sbx.toml` (the base layer) then the
/// project `.sbx.toml`, which overlays it (so the project wins). Each path comes through
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

    let mut table: &dyn TableLike = doc.as_table();
    for seg in parents {
        // Descend through both regular and inline tables, so a key inside `network = { ... }` is
        // read, not misreported as absent.
        match table.get(seg).and_then(Item::as_table_like) {
            Some(t) => table = t,
            None => return Ok(None),
        }
    }
    match table.get(leaf[0]) {
        None => Ok(None),
        Some(Item::Value(v)) if v.is_str() => Ok(v.as_str().map(str::to_string)),
        Some(Item::Value(v)) if !v.is_array() && !v.is_inline_table() => {
            // Render only the value literal — clearing the decor drops any trailing inline comment
            // (`4096 # note`) so `get` returns a clean, scriptable scalar like the string branch.
            let mut v = v.clone();
            v.decor_mut().set_prefix("");
            v.decor_mut().set_suffix("");
            Ok(Some(v.to_string().trim().to_string()))
        }
        Some(_) => Err(ManageError::NotScalar(key.to_string())),
    }
}

/// Set a value at a dotted key, preserving the rest of the file. Creates the file and any
/// intermediate tables as needed. Returns whether the key was created (vs updated in place).
///
/// The value is written with its natural TOML type — a bare `true`/`false` as a boolean, a bare
/// integer as an integer — so a typed schema key (a `bool`/number knob) round-trips; a value that
/// leaves the layer unparseable in the typed form is retried as a plain string. A value that makes
/// the layer invalid in BOTH forms is **refused without writing**: a committed unparseable layer is
/// silently dropped whole at the next load (e.g. a filtering `network` posture reverting to open
/// egress), so this fails closed and loud rather than reporting success over a broken file.
pub(crate) fn set(path: &Path, key: &str, val: &str) -> Result<bool, ManageError> {
    let mut doc = read_or_empty(path)?;
    let created = put_scalar(&mut doc, key, scalar_value(val))?;
    if validate_layer(&doc).is_err() {
        // The natural type broke the layer — write the value as a string instead.
        put_scalar(&mut doc, key, Value::from(val))?;
        if let Err(detail) = validate_layer(&doc) {
            return Err(ManageError::InvalidValue(key.to_string(), detail));
        }
    }
    write_doc(path, &doc)?;
    Ok(created)
}

/// Insert or replace a scalar leaf at a dotted `key`, creating intermediate tables as needed.
/// Returns whether the leaf was created (vs replaced in place, keeping its surrounding comments).
fn put_scalar(doc: &mut DocumentMut, key: &str, v: Value) -> Result<bool, ManageError> {
    let segments = split_key(key)?;
    let (parents, leaf) = segments.split_at(segments.len() - 1);

    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for seg in parents {
        // Create a missing parent as a regular table; descend through an existing regular OR inline
        // table, so a scalar can be set inside `network = { ... }` instead of failing as non-scalar.
        if !table.contains_key(seg) {
            table.insert(seg, Item::Table(Table::new()));
        }
        table = table
            .get_mut(seg)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| ManageError::NotScalar(key.to_string()))?;
    }
    match table.get_mut(leaf[0]) {
        // A new key: insert it with default formatting.
        None => {
            table.insert(leaf[0], Item::Value(v));
            Ok(true)
        }
        // An existing scalar: replace only its content, keeping the surrounding decor (the
        // comments and whitespace around it) — a plain `insert` would drop them.
        Some(Item::Value(existing)) if !existing.is_array() && !existing.is_inline_table() => {
            let mut replacement = v;
            *replacement.decor_mut() = existing.decor().clone();
            *existing = replacement;
            Ok(false)
        }
        // An array or table leaf: refuse rather than silently drop what the user meant to edit.
        Some(_) => Err(ManageError::NotScalar(key.to_string())),
    }
}

/// The TOML value for a raw command-line string: a bare `true`/`false` becomes a boolean and a bare
/// integer becomes an integer, so a typed schema key round-trips; anything else stays a string. The
/// caller validates the result and falls back to a string, so an over-eager guess is never
/// committed — the point is only to let `sbx config set network.stats false` write a real boolean.
fn scalar_value(val: &str) -> Value {
    match val {
        "true" => Value::from(true),
        "false" => Value::from(false),
        _ => match val.parse::<i64>() {
            // Reject forms an integer render would not reproduce (`+1`, `007`), so they stay
            // strings and round-trip verbatim.
            Ok(n) if n.to_string() == val => Value::from(n),
            _ => Value::from(val),
        },
    }
}

/// Whether the edited document still parses as a config layer. A `set`/`unset` that leaves the
/// layer unparseable is worse than a no-op: the loader drops the WHOLE layer with only a warning,
/// silently reverting every security field it carried, so a write is validated before it commits.
fn validate_layer(doc: &DocumentMut) -> Result<(), String> {
    super::schema::parse(doc.to_string().as_bytes()).map(|_| ())
}

/// Remove a dotted key. Returns whether it existed. An absent file or parent is simply "not
/// present" (returns `false`), never an error.
pub(crate) fn unset(path: &Path, key: &str) -> Result<bool, ManageError> {
    let mut doc = read_or_empty(path)?;
    let segments = split_key(key)?;
    let (parents, leaf) = segments.split_at(segments.len() - 1);

    let mut table: &mut dyn TableLike = doc.as_table_mut();
    for seg in parents {
        // Descend through both regular and inline tables, so a key inside `network = { ... }` is
        // removed, not reported as already-absent.
        match table.get_mut(seg).and_then(Item::as_table_like_mut) {
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
/// `deny`/`allow` is promoted to the table form keeping its mode; a bare-string
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
    let parent = layer_parent(&mut doc, app)?;
    let case = match parent.get("network") {
        None => NetCase::Absent,
        Some(Item::Value(v)) if v.is_str() => {
            let s = v.as_str().unwrap_or_default().to_string();
            match s.as_str() {
                "deny" | "allow" | "ask" => NetCase::BareFiltering(s),
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
            // Only `allow` bootstraps a posture (the most restrictive, deny-by-default allowlist). A
            // `deny` must not silently open a denylist, and a `mute` with no filtering posture is
            // inert (nothing to suppress) — each needs the user to set a posture first.
            match list {
                EgressList::Deny => return Err(ManageError::DenyNeedsPosture),
                EgressList::Mute => return Err(ManageError::MuteNeedsPosture),
                EgressList::Allow => {}
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

/// Add a process/exec `rule` to the `[proc]` `list` of the target file (baseline or `[app.<name>]`).
///
/// The posture guard mirrors `[network]`'s, adapted to `[proc]`'s denylist-by-default. With no
/// `[proc]` field, a `deny` bootstraps `mode = "enforce"` (a denylist — the rule takes effect at
/// once) while an `allow` is refused (an allow is inert without `mode = "ask"`). A bare-string
/// `proc = "<mode>"` is promoted to the table form keeping its mode, subject to the same per-list
/// guard. An existing `[proc]` table (regular or inline) has the rule appended after the guard,
/// idempotent on the exact string. Preserves comments/formatting and writes atomically. The outcome
/// names any mode it created (only the `deny`-bootstrap does).
pub(crate) fn add_proc_rule(
    path: &Path,
    app: Option<&str>,
    list: ProcList,
    rule: &str,
) -> Result<AddOutcome, ManageError> {
    enum ProcCase {
        Absent,
        BareMode(String),
        Table,
        Inline,
        Malformed(String),
    }

    let mut doc = read_or_empty(path)?;
    let parent = layer_parent(&mut doc, app)?;
    let case = match parent.get("proc") {
        None => ProcCase::Absent,
        Some(Item::Value(v)) if v.is_str() => {
            ProcCase::BareMode(v.as_str().unwrap_or_default().to_string())
        }
        Some(Item::Table(_)) => ProcCase::Table,
        Some(Item::Value(v)) if v.is_inline_table() => ProcCase::Inline,
        Some(_) => ProcCase::Malformed("not a mode string or table".into()),
    };

    let outcome = match case {
        ProcCase::Absent => match list {
            // A `deny` bootstraps the denylist posture (`enforce`) so the rule takes effect at once;
            // an `allow` is inert without `mode = "ask"`, so refuse rather than write a no-op.
            ProcList::Deny => {
                parent.insert("proc", Item::Table(new_proc_table("enforce", list, rule)));
                AddOutcome::Added {
                    created_mode: Some("enforce".into()),
                }
            }
            ProcList::Allow => return Err(ManageError::ProcAllowNeedsPosture),
        },
        ProcCase::BareMode(mode) => {
            // Promote the bare-string mode to the table form keeping its mode, with the rule — but
            // only if that mode makes the rule live (the guard refuses an inert allow/deny).
            guard_proc_mode(Some(&mode), list)?;
            parent.insert("proc", Item::Table(new_proc_table(&mode, list, rule)));
            AddOutcome::Added { created_mode: None }
        }
        ProcCase::Malformed(m) => return Err(ManageError::MalformedProc(m)),
        ProcCase::Table => {
            let t = parent["proc"]
                .as_table_mut()
                .expect("inspected as a regular table");
            guard_proc_mode(t.get("mode").and_then(Item::as_str), list)?;
            let arr = t
                .entry(list.key())
                .or_insert_with(|| value(Array::new()))
                .as_array_mut()
                .ok_or_else(|| {
                    ManageError::MalformedProc(format!("`{}` is not an array", list.key()))
                })?;
            push_outcome(arr, rule)
        }
        ProcCase::Inline => {
            let it = parent["proc"]
                .as_value_mut()
                .and_then(Value::as_inline_table_mut)
                .expect("inspected as an inline table");
            guard_proc_mode(it.get("mode").and_then(Value::as_str), list)?;
            let arr = it
                .entry(list.key())
                .or_insert_with(|| Value::Array(Array::new()))
                .as_array_mut()
                .ok_or_else(|| {
                    ManageError::MalformedProc(format!("`{}` is not an array", list.key()))
                })?;
            push_outcome(arr, rule)
        }
    };

    write_doc(path, &doc)?;
    Ok(outcome)
}

/// Guard the `mode` of a `[proc]` table/bare-string before appending an allow/deny rule to it. A
/// `deny` is live under an enforcing mode (`enforce`/`ask`) and inert under `off`/`observe`; an
/// `allow` is live **only** under `ask` (under `enforce` everything not denied already runs, so an
/// allow changes nothing). A mode-less table is ambiguous to a writer (it may inherit a baseline),
/// and an unknown mode is dropped at resolution — both are refused rather than accept an inert rule.
fn guard_proc_mode(mode: Option<&str>, list: ProcList) -> Result<(), ManageError> {
    match (list, mode) {
        (ProcList::Deny, Some("enforce" | "ask")) => Ok(()),
        (ProcList::Deny, Some(m @ ("off" | "observe"))) => {
            Err(ManageError::ProcNonEnforcingPosture(m.to_string()))
        }
        (ProcList::Allow, Some("ask")) => Ok(()),
        (ProcList::Allow, Some("enforce" | "off" | "observe")) => {
            Err(ManageError::ProcAllowNeedsPosture)
        }
        // A mode-less field: an allow needs `ask` specifically; a deny is ambiguous (it may inherit).
        (ProcList::Allow, None) => Err(ManageError::ProcAllowNeedsPosture),
        (ProcList::Deny, None) => Err(ManageError::ProcNeedsMode),
        (_, Some(other)) => Err(ManageError::MalformedProc(format!(
            "unknown mode {other:?}"
        ))),
    }
}

/// A fresh `[proc]` table carrying `mode` and one `rule` in `list`.
fn new_proc_table(mode: &str, list: ProcList, rule: &str) -> Table {
    let mut t = Table::new();
    t.insert("mode", value(mode));
    let mut arr = Array::new();
    arr.push(rule);
    t.insert(list.key(), value(arr));
    t
}

/// The result of removing an egress rule.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RemoveOutcome {
    /// The rule was present and removed.
    Removed,
    /// The rule was not present (nothing changed): an idempotent no-op.
    NotPresent,
}

/// Remove an egress `rule` from the `list` of the target's `[network]` table — the inverse of
/// [`add_egress_rule`]. An absent file, an absent `[network]`, a bare-string posture (which carries
/// no lists), or a rule simply not in the list are all a clean [`RemoveOutcome::NotPresent`], never
/// an error, so `sbx net unmute` of something already gone is idempotent. Unlike the add path it
/// **never creates** the app/network scaffolding — there is nothing to remove from a table that does
/// not exist. Preserves comments/formatting and writes atomically only when it actually removed
/// something.
pub(crate) fn remove_egress_rule(
    path: &Path,
    app: Option<&str>,
    list: EgressList,
    rule: &str,
) -> Result<RemoveOutcome, ManageError> {
    if !path.exists() {
        return Ok(RemoveOutcome::NotPresent);
    }
    let mut doc = read_or_empty(path)?;
    // Navigate to the table holding `network` WITHOUT creating anything (the add path creates the
    // `[app.<name>]` scaffolding; removal must not).
    let parent = match app {
        None => Some(doc.as_table_mut()),
        Some(name) => doc
            .as_table_mut()
            .get_mut("app")
            .and_then(Item::as_table_mut)
            .and_then(|apps| apps.get_mut(name))
            .and_then(Item::as_table_mut),
    };
    let Some(parent) = parent else {
        return Ok(RemoveOutcome::NotPresent);
    };
    let removed = match parent.get_mut("network") {
        Some(Item::Table(t)) => {
            let hit = t
                .get_mut(list.key())
                .and_then(Item::as_array_mut)
                .is_some_and(|arr| remove_from_array(arr, rule));
            // Drop a now-empty list so no `mute = []` residue is left behind.
            if hit
                && t.get(list.key())
                    .and_then(Item::as_array)
                    .is_some_and(Array::is_empty)
            {
                t.remove(list.key());
            }
            hit
        }
        Some(Item::Value(v)) if v.is_inline_table() => {
            let it = v
                .as_inline_table_mut()
                .expect("inspected as an inline table");
            let hit = it
                .get_mut(list.key())
                .and_then(Value::as_array_mut)
                .is_some_and(|arr| remove_from_array(arr, rule));
            if hit
                && it
                    .get(list.key())
                    .and_then(Value::as_array)
                    .is_some_and(Array::is_empty)
            {
                it.remove(list.key());
            }
            hit
        }
        // Absent, a bare-string posture (no lists), or a malformed field: nothing to remove.
        _ => false,
    };
    if !removed {
        return Ok(RemoveOutcome::NotPresent);
    }
    write_doc(path, &doc)?;
    Ok(RemoveOutcome::Removed)
}

/// Remove the first exact-string match of `rule` from `arr`, reporting whether one was removed.
fn remove_from_array(arr: &mut Array, rule: &str) -> bool {
    let idx = arr.iter().position(|v| v.as_str() == Some(rule));
    match idx {
        Some(i) => {
            arr.remove(i);
            true
        }
        None => false,
    }
}

/// Validate the `mode` of a `[network]` table/inline-table before appending an allow/deny rule to
/// it — the same guard the bare-string path applies, so the table forms cannot silently accept an
/// inert rule. A filtering mode (or a missing one, left to the schema) takes the rule; an explicit
/// non-filtering `shared`/`none` is refused (its lists are ignored at resolution); and an unknown
/// mode is refused too — it is dropped at resolution, so appending to it would report a rule "added"
/// that never takes effect.
fn refuse_non_filtering(mode: Option<&str>) -> Result<(), ManageError> {
    match mode {
        None | Some("deny" | "allow" | "ask") => Ok(()),
        Some(m @ ("shared" | "none")) => Err(ManageError::NonFilteringPosture(m.to_string())),
        Some(other) => Err(ManageError::MalformedNetwork(format!(
            "unknown mode {other:?}"
        ))),
    }
}

/// The table where a baseline-or-app field (`network`, `proc`, …) lives: the document root for the
/// baseline, or the `[app.<name>]` table (created if absent) for an app overlay.
fn layer_parent<'a>(
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
///
/// A fresh file is written owner-only (`0600`), independent of the caller's umask, so sbx's own
/// write always passes its safety gate (a world-writable config is later refused); an existing
/// file keeps its mode. The temp name carries the pid so two concurrent writers do not collide.
fn write_doc(path: &Path, doc: &DocumentMut) -> Result<(), ManageError> {
    use std::os::unix::fs::PermissionsExt as _;
    let err = |e: std::io::Error| ManageError::Write(path.to_path_buf(), e.to_string());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(err)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sbx.toml");
    let mode = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    let tmp = dir.join(format!(".{name}.sbx-tmp.{}", std::process::id()));
    std::fs::write(&tmp, doc.to_string()).map_err(err)?;
    if let Err(e) = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err(e));
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        err(e)
    })
}

/// The result of [`import_net_groups`]: the group names newly added and those overwritten (only
/// possible under `force`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ImportOutcome {
    pub(crate) added: Vec<String>,
    pub(crate) overwritten: Vec<String>,
}

/// Serialize a set of tool bundles as a portable `[bundle.<name>]` TOML fragment — what
/// `sbx bundle export` writes. Fresh formatting (source comments are not carried); empty fields
/// are omitted, so a bundle that carries only packages exports as one table. The inverse merge is
/// [`import_bundles`], and the fragment round-trips through [`super::read_bundle_fragment`].
///
/// Serialized through `serde` rather than assembled with `toml_edit`: a bundle is a nested shape
/// (four maps, three arrays, and the flattened `[secret]` hosts), and re-deriving that structure by
/// hand would be a second, drift-prone description of a type that already knows how to write
/// itself.
pub(crate) fn export_bundles(
    bundles: &std::collections::BTreeMap<String, super::RawBundle>,
) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct Fragment<'a> {
        bundle: &'a std::collections::BTreeMap<String, super::RawBundle>,
    }
    toml::to_string(&Fragment { bundle: bundles }).map_err(|e| e.to_string())
}

/// Merge bundle definitions into the config at `path` (the global config), preserving every
/// existing bundle, comment and formatting via `toml_edit`. A bundle whose name already exists is
/// overwritten only when `force` is set; otherwise the collisions are returned and **nothing is
/// written**, so the merge is all-or-nothing. Written atomically.
///
/// Each incoming bundle is rendered by `serde` and re-parsed into an item, for the same reason
/// [`export_bundles`] serializes: the nested shape is the type's business, not this function's.
/// Only the *target* document is edited in place, so the user's own comments survive.
pub(crate) fn import_bundles(
    path: &Path,
    bundles: &std::collections::BTreeMap<String, super::RawBundle>,
    force: bool,
) -> Result<ImportOutcome, ManageError> {
    let mut doc = read_or_empty(path)?;
    let table = doc
        .as_table_mut()
        .entry("bundle")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| ManageError::NotScalar("bundle".to_string()))?;
    // Implicit so only the `[bundle.<name>]` headers are emitted, never a bare `[bundle]`.
    table.set_implicit(true);

    // Collision check first, so a refused import writes nothing (all-or-nothing).
    if !force {
        let collisions: Vec<String> = bundles
            .keys()
            .filter(|n| table.contains_key(n))
            .cloned()
            .collect();
        if !collisions.is_empty() {
            return Err(ManageError::BundleCollision(collisions));
        }
    }

    let mut added = Vec::new();
    let mut overwritten = Vec::new();
    for (name, bundle) in bundles {
        let rendered =
            toml::to_string(bundle).map_err(|e| ManageError::NotScalar(e.to_string()))?;
        let parsed: DocumentMut = rendered
            .parse()
            .map_err(|e: toml_edit::TomlError| ManageError::NotScalar(e.to_string()))?;
        if table.contains_key(name) {
            overwritten.push(name.clone());
        } else {
            added.push(name.clone());
        }
        table.insert(name, Item::Table(parsed.as_table().clone()));
    }
    write_doc(path, &doc)?;
    Ok(ImportOutcome { added, overwritten })
}

/// Serialize a set of egress groups as a portable `[net.groups]` TOML fragment — the value
/// `sbx net groups export` writes. Fresh formatting (source comments are not carried); each name
/// maps to its entries as a string array, in the map's (sorted) order. The inverse merge is
/// [`import_net_groups`], and the fragment round-trips through [`super::read_net_groups_fragment`].
pub(crate) fn export_net_groups(
    groups: &std::collections::BTreeMap<String, Vec<String>>,
) -> String {
    let mut inner = Table::new();
    for (name, entries) in groups {
        let mut arr = Array::new();
        for e in entries {
            arr.push(e.as_str());
        }
        inner.insert(name, value(arr));
    }
    // Nest as `[net.groups]`, marking `[net]` implicit so only the `[net.groups]` header is emitted.
    let mut net = Table::new();
    net.set_implicit(true);
    net.insert("groups", Item::Table(inner));
    let mut doc = DocumentMut::new();
    doc.insert("net", Item::Table(net));
    doc.to_string()
}

/// Merge egress-group definitions into the config at `path` (the global config), preserving every
/// existing group, comment and formatting via `toml_edit`. A group whose name already exists is
/// overwritten only when `force` is set; otherwise the collisions are returned and **nothing is
/// written**, so the merge is all-or-nothing. Written atomically.
pub(crate) fn import_net_groups(
    path: &Path,
    groups: &std::collections::BTreeMap<String, Vec<String>>,
    force: bool,
) -> Result<ImportOutcome, ManageError> {
    let mut doc = read_or_empty(path)?;
    // Navigate to (creating if absent) the `[net.groups]` table, keeping `[net]` implicit.
    let net = doc
        .as_table_mut()
        .entry("net")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| ManageError::NotScalar("net".to_string()))?;
    net.set_implicit(true);
    let groups_tbl = net
        .entry("groups")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| ManageError::NotScalar("net.groups".to_string()))?;

    // Collision check first, so a refused import writes nothing (all-or-nothing).
    if !force {
        let collisions: Vec<String> = groups
            .keys()
            .filter(|n| groups_tbl.contains_key(n))
            .cloned()
            .collect();
        if !collisions.is_empty() {
            return Err(ManageError::GroupCollision(collisions));
        }
    }

    let mut added = Vec::new();
    let mut overwritten = Vec::new();
    for (name, entries) in groups {
        if groups_tbl.contains_key(name) {
            overwritten.push(name.clone());
        } else {
            added.push(name.clone());
        }
        let mut arr = Array::new();
        for e in entries {
            arr.push(e.as_str());
        }
        groups_tbl.insert(name, value(arr));
    }
    write_doc(path, &doc)?;
    Ok(ImportOutcome { added, overwritten })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_at(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join(".sbx.toml");
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
        assert_eq!(layers[1].path, Some(cwd.join(".sbx.toml")));
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
        let p = tmp.path().join(".sbx.toml");
        assert!(set(&p, "env.A", "1").unwrap(), "created in a new file");
        assert_eq!(get(&p, "env.A").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn set_creates_a_missing_parent_directory() {
        // The global config dir, or an explicit `-c nested/dir/file.toml`, may not exist on a
        // first write — the atomic placement must create the directory, not fail on it.
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join("nested").join("dir").join("sbx.toml");
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
    fn set_writes_a_typed_key_with_its_natural_type_and_keeps_the_layer_valid() {
        // A bool-valued schema knob must be written as a real boolean, not the string "false" —
        // the string form makes the untagged `network` field unparseable, so the loader would drop
        // the WHOLE layer (reverting the filtering posture to open egress). Pin that it round-trips.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[network]\nmode = \"deny\"\n");
        assert!(set(&p, "network.stats", "false").unwrap(), "stats is new");
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(
            after.contains("stats = false"),
            "written as a boolean, not a string:\n{after}"
        );
        assert!(
            super::super::schema::parse(after.as_bytes()).is_ok(),
            "the edited layer still parses, so a load honors it:\n{after}"
        );
    }

    #[test]
    fn set_refuses_a_value_that_would_invalidate_the_layer_without_writing() {
        // A value the schema rejects in every form must fail closed: the file is left untouched, so
        // a launch keeps honoring the last-good layer instead of silently dropping it as invalid.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[network]\nmode = \"deny\"\n");
        let before = std::fs::read_to_string(&p).unwrap();
        assert!(matches!(
            set(&p, "network.stats", "maybe"),
            Err(ManageError::InvalidValue(_, _))
        ));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            before,
            "a refused set must leave the file byte-for-byte unchanged"
        );
    }

    #[test]
    fn get_set_unset_descend_into_an_inline_table() {
        // A key inside `network = { ... }` must be readable, settable, and removable — the inline
        // form is a first-class shape the same module authors elsewhere, not an absent key.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "network = { mode = \"deny\", stats = true }\n");
        assert_eq!(get(&p, "network.mode").unwrap().as_deref(), Some("deny"));
        // set a new inline key and flip an existing one
        assert!(!set(&p, "network.stats", "false").unwrap(), "stats existed");
        assert_eq!(get(&p, "network.stats").unwrap().as_deref(), Some("false"));
        assert!(unset(&p, "network.stats").unwrap(), "stats removed");
        assert_eq!(get(&p, "network.stats").unwrap(), None);
        // the field stays inline and valid after editing
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains('{'), "still inline:\n{after}");
        assert!(super::super::schema::parse(after.as_bytes()).is_ok());
    }

    #[test]
    fn get_strips_a_trailing_comment_from_a_non_string_scalar() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[limits]\ntasks_max = 4096 # per advisor\n");
        assert_eq!(
            get(&p, "limits.tasks_max").unwrap().as_deref(),
            Some("4096")
        );
    }

    #[test]
    fn add_egress_rule_refuses_an_unknown_mode_rather_than_reporting_an_inert_rule() {
        // An unknown mode is dropped at resolution, so appending to it would silently be inert.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[network]\nmode = \"bogus\"\n");
        assert!(matches!(
            add_egress_rule(&p, None, EgressList::Allow, "example.com"),
            Err(ManageError::MalformedNetwork(_))
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
        let p = tmp.path().join(".sbx.toml");
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
    fn mute_rule_add_and_remove_round_trip_on_a_table() {
        let tmp = crate::testutil::TmpDir::new();
        // A filtering posture already exists (the common `sbx net mute -a <app>` case).
        let p = doc_at(
            tmp.path(),
            "[network]\nmode = \"deny\"\nallow = [\"api.test\"]\n",
        );

        // Add a mute rule → it lands in a `mute` array beside `allow`, the verdict lists untouched.
        let added = add_egress_rule(&p, None, EgressList::Mute, "play.googleapis.com").unwrap();
        assert_eq!(added, AddOutcome::Added { created_mode: None });
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("mute = [\"play.googleapis.com\"]"), "{body}");
        assert!(
            body.contains("allow = [\"api.test\"]"),
            "the allow list is untouched:\n{body}"
        );

        // Adding the same rule again is idempotent.
        assert_eq!(
            add_egress_rule(&p, None, EgressList::Mute, "play.googleapis.com").unwrap(),
            AddOutcome::AlreadyPresent
        );

        // Remove it → gone; a second removal is a reported no-op.
        assert_eq!(
            remove_egress_rule(&p, None, EgressList::Mute, "play.googleapis.com").unwrap(),
            RemoveOutcome::Removed
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            !body.contains("play.googleapis.com"),
            "the mute rule is removed:\n{body}"
        );
        assert!(
            !body.contains("mute"),
            "removing the last entry drops the key — no empty `mute = []` residue:\n{body}"
        );
        // The verdict lists it sat beside are untouched by the mute removal.
        assert!(body.contains("allow = [\"api.test\"]"), "{body}");
        assert_eq!(
            remove_egress_rule(&p, None, EgressList::Mute, "play.googleapis.com").unwrap(),
            RemoveOutcome::NotPresent
        );
    }

    #[test]
    fn a_mute_rule_needs_a_filtering_posture() {
        let tmp = crate::testutil::TmpDir::new();
        // No `[network]` at all → a mute would be inert, so it is refused (like a posture-less deny),
        // and nothing is written.
        let p = tmp.path().join(".sbx.toml");
        assert!(matches!(
            add_egress_rule(&p, None, EgressList::Mute, "x.test"),
            Err(ManageError::MuteNeedsPosture)
        ));
        assert!(!p.exists(), "a refused mute writes nothing");
    }

    #[test]
    fn add_egress_rule_on_a_mode_less_table_keeps_it_mode_less() {
        // A `[network]` table that inherits its mode (no `mode` key) must stay mode-less after
        // `sbx net allow` appends a rule — materializing a `mode` would silently pin it and break
        // the inheritance the author chose.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[network]\nallow = [\"a.test\"]\n");
        add_egress_rule(&p, None, EgressList::Allow, "b.test").unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("\"a.test\"") && body.contains("\"b.test\""),
            "both rules must be present:\n{body}"
        );
        assert!(
            !body.contains("mode"),
            "appending a rule must not materialize a `mode` on a mode-less table:\n{body}"
        );
    }

    #[test]
    fn add_egress_rule_refuses_a_deny_with_no_posture_without_writing() {
        let tmp = crate::testutil::TmpDir::new();
        let p = tmp.path().join(".sbx.toml");
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
        let p = tmp.path().join(".sbx.toml");
        add_egress_rule(&p, Some("demo-app"), EgressList::Allow, "api.example.com").unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("[app.demo-app.network]") && body.contains("api.example.com"),
            "{body}"
        );
        // The structural parents are implicit, so no empty `[app]` / `[app.demo-app]` headers.
        assert!(
            !body.contains("[app]\n") && !body.contains("[app.demo-app]\n"),
            "parent tables must be implicit:\n{body}"
        );
    }

    #[test]
    fn scope_app_path_local_targets_the_project_config_and_file_the_explicit_path() {
        // `Local` targets the project `.sbx.toml` (a project-scoped `[app.<name>]` overlay is still
        // allowed); `File` targets the explicit path unchanged. The `Global` arm depends on the
        // config-home env, so it is covered hermetically by the integration test
        // `net_allow_app_save_global_writes_to_profile_and_preserves_profile_fields` instead.
        let cwd = std::path::Path::new("/some/cwd");
        assert_eq!(
            scope_app_path(&Scope::Local, cwd, "demo-app").unwrap(),
            cwd.join(crate::config::PROJECT_CONFIG)
        );
        let explicit = std::path::PathBuf::from("/etc/sbx.toml");
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

    fn groups_of(pairs: &[(&str, &[&str])]) -> std::collections::BTreeMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(n, es)| (n.to_string(), es.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    #[test]
    fn export_net_groups_emits_a_net_groups_fragment() {
        let g = groups_of(&[("mcp", &["{*} a.example.com:443"]), ("t", &["*.x.com:*"])]);
        let out = export_net_groups(&g);
        assert!(out.contains("[net.groups]"), "{out}");
        // `[net]` is implicit — only the `[net.groups]` header is emitted.
        assert!(
            !out.contains("[net]"),
            "the [net] header must stay implicit:\n{out}"
        );
        assert!(out.contains("mcp = [\"{*} a.example.com:443\"]"), "{out}");
        assert!(out.contains("t = [\"*.x.com:*\"]"), "{out}");
    }

    #[test]
    fn import_net_groups_merges_preserving_existing_and_refuses_collisions() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "# keep me\n[net.groups]\n# existing\nother = [\"github.com:443\"]\n",
        );

        // A fresh name is added; the existing group and its comment survive.
        let out = import_net_groups(
            &p,
            &groups_of(&[("mcp", &["{*} a.example.com:443"])]),
            false,
        )
        .unwrap();
        assert_eq!(out.added, vec!["mcp".to_string()]);
        assert!(out.overwritten.is_empty());
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(
            body.contains("# keep me") && body.contains("other") && body.contains("mcp"),
            "the merge preserves existing content:\n{body}"
        );

        // A colliding name without force is refused and writes nothing.
        let before = std::fs::read_to_string(&p).unwrap();
        let clash = groups_of(&[("mcp", &["{*} b.example.com:443"])]);
        match import_net_groups(&p, &clash, false) {
            Err(ManageError::GroupCollision(names)) => assert_eq!(names, vec!["mcp".to_string()]),
            other => panic!("expected a collision, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            before,
            "a refused import must write nothing"
        );

        // With force, the colliding group is overwritten.
        let out = import_net_groups(&p, &clash, true).unwrap();
        assert_eq!(out.overwritten, vec!["mcp".to_string()]);
        assert!(
            std::fs::read_to_string(&p)
                .unwrap()
                .contains("b.example.com"),
            "force must overwrite the entry"
        );
    }

    #[test]
    fn add_proc_rule_bootstraps_enforce_for_a_deny_on_a_fresh_config() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "");
        let out = add_proc_rule(&p, None, ProcList::Deny, "curl").unwrap();
        assert_eq!(
            out,
            AddOutcome::Added {
                created_mode: Some("enforce".into())
            }
        );
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("[proc]"), "{body}");
        assert!(body.contains("mode = \"enforce\""), "{body}");
        assert!(body.contains("deny = [\"curl\"]"), "{body}");
    }

    #[test]
    fn add_proc_rule_refuses_an_allow_with_no_posture_without_writing() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "");
        assert!(matches!(
            add_proc_rule(&p, None, ProcList::Allow, "git"),
            Err(ManageError::ProcAllowNeedsPosture)
        ));
        // A fresh file must not be created by a refused write.
        assert!(!p.exists() || std::fs::read_to_string(&p).unwrap().is_empty());
    }

    #[test]
    fn add_proc_rule_refuses_an_inert_allow_under_enforce() {
        // The load-bearing guard: an `allow` is inert under `enforce` (everything not denied already
        // runs), so appending one would silently do nothing — refuse it, exactly as under off/observe.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "[proc]\nmode = \"enforce\"\ndeny = [\"curl\"]\n",
        );
        assert!(matches!(
            add_proc_rule(&p, None, ProcList::Allow, "git"),
            Err(ManageError::ProcAllowNeedsPosture)
        ));
        // The deny still appends fine under enforce.
        assert_eq!(
            add_proc_rule(&p, None, ProcList::Deny, "ssh").unwrap(),
            AddOutcome::Added { created_mode: None }
        );
    }

    #[test]
    fn add_proc_rule_appends_an_allow_under_ask() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[proc]\nmode = \"ask\"\n");
        assert_eq!(
            add_proc_rule(&p, None, ProcList::Allow, "git").unwrap(),
            AddOutcome::Added { created_mode: None }
        );
        assert!(std::fs::read_to_string(&p)
            .unwrap()
            .contains("allow = [\"git\"]"));
    }

    #[test]
    fn add_proc_rule_refuses_a_rule_on_a_non_enforcing_mode() {
        for mode in ["off", "observe"] {
            let tmp = crate::testutil::TmpDir::new();
            let p = doc_at(tmp.path(), &format!("[proc]\nmode = \"{mode}\"\n"));
            assert!(
                matches!(
                    add_proc_rule(&p, None, ProcList::Deny, "curl"),
                    Err(ManageError::ProcNonEnforcingPosture(_))
                ),
                "a deny into a `{mode}` table must be refused"
            );
        }
    }

    #[test]
    fn add_proc_rule_promotes_a_bare_string_mode_keeping_it() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "proc = \"enforce\"\n");
        let out = add_proc_rule(&p, None, ProcList::Deny, "curl").unwrap();
        assert_eq!(out, AddOutcome::Added { created_mode: None });
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("[proc]"), "{body}");
        assert!(body.contains("mode = \"enforce\""), "{body}");
        assert!(body.contains("deny = [\"curl\"]"), "{body}");
    }

    #[test]
    fn add_proc_rule_appends_to_a_table_and_is_idempotent() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(
            tmp.path(),
            "[proc]\nmode = \"enforce\"\ndeny = [\"curl\"]\n",
        );
        assert_eq!(
            add_proc_rule(&p, None, ProcList::Deny, "ssh").unwrap(),
            AddOutcome::Added { created_mode: None }
        );
        assert_eq!(
            add_proc_rule(&p, None, ProcList::Deny, "ssh").unwrap(),
            AddOutcome::AlreadyPresent
        );
    }

    #[test]
    fn add_proc_rule_refuses_a_mode_less_table_for_a_deny() {
        // A `[proc]` table with no `mode` has an ambiguous effective mode to a writer (it may inherit
        // a baseline), so a deny is refused rather than written into a possibly-inert table.
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "[proc]\nallow = [\"git\"]\n");
        assert!(matches!(
            add_proc_rule(&p, None, ProcList::Deny, "curl"),
            Err(ManageError::ProcNeedsMode)
        ));
    }

    #[test]
    fn add_proc_rule_writes_an_apps_own_proc_table_with_implicit_parents() {
        let tmp = crate::testutil::TmpDir::new();
        let p = doc_at(tmp.path(), "");
        add_proc_rule(&p, Some("demo-app"), ProcList::Deny, "ssh").unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("[app.demo-app.proc]"), "{body}");
        assert!(body.contains("mode = \"enforce\""), "{body}");
        assert!(body.contains("deny = [\"ssh\"]"), "{body}");
        // The `[app]` / `[app.demo-app]` parents are implicit — no bare empty header.
        assert!(!body.contains("[app]\n"), "no empty [app] header:\n{body}");
    }
}
