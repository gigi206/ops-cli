//! The key-editing verbs behind `sbx config`: `get`, `set`, `add`, `rm`, `unset`, `path`, `edit`.
//!
//! This is the half of the family that touches the filesystem, the trust store and `$EDITOR`.
//! Every write-side security decision is here — which scopes carry a trust gate at all, what
//! `--trust` may bless before a write happens, and what an edit does to a trusted file's marker —
//! with no rendering code around it.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::confirm::{
    render_config_same_value, render_config_unchanged, render_config_write, render_list_edit,
    render_list_unchanged, render_trusted_whole_file,
};
use crate::{ScopeArgs, config_cwd, split_scope};
use crate::{config, diag, style, trust};

use super::config_usage;

/// Rewrite a dotted `key` to address it under app `name`'s table — the `--app <name>` sugar, so
/// `set --app demo network shared` writes `app.demo.network`.
///
/// The name keys a single TOML table segment, so a name that carries a `.` (which `sbx net … -a`
/// and the loader both accept) is quoted: `--app my.app` addresses `app."my.app".<key>`, which the
/// quote-aware key splitter behind every read and write reads back as the one segment `my.app`. A
/// name that needs no quoting keeps the bare spelling, so the common key is unchanged. Quoting is
/// unconditionally safe here because a valid app name cannot itself contain a quote — the charset
/// [`config::is_valid_app_name`] admits is `[A-Za-z0-9._-]` — and a name that no app could ever
/// carry is rejected outright before any rewriting.
fn app_prefixed_key(name: &str, key: &str) -> Result<String, String> {
    if !config::is_valid_app_name(name) {
        return Err(format!("invalid app name `{name}`: 1–64 of [A-Za-z0-9._-]"));
    }
    if name.contains('.') {
        return Ok(format!("app.\"{name}\".{key}"));
    }
    Ok(format!("app.{name}.{key}"))
}

/// `sbx config get <key>`: print the value declared at a dotted key in the target layer file
/// (`--local` by default). This reads the *raw declared* value in that one file; for the
/// *effective resolved* value across layers, use `sbx config show` / `sbx config show --json`. An
/// unset key OR a read/parse error both exit 1 (each prints a distinct stderr line saying which); a
/// usage problem exits 2.
pub(super) fn config_get(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config get: {e}"));
            return config_usage("get");
        }
    };
    if let Some(code) = reject_trust("get", trust) {
        return code;
    }
    if positionals.len() != 1 {
        return config_usage("get");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, _gated) =
        match resolve_key_target("get", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    match config::manage::get(&path, &key) {
        Ok(Some(v)) => {
            println!("{v}");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            diag::error(&format!(
                "sbx: config: `{}` is not set in {}",
                key,
                path.display()
            ));
            ExitCode::from(1)
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Reject `--app` on a verb that takes no key (`path` prints a file path; `edit` opens the whole
/// file) — there is nothing for the app rewrite to apply to. Returns the usage exit code when an
/// `--app` was passed, else `None`.
fn reject_app(verb: &str, app: &Option<String>) -> Option<ExitCode> {
    if app.is_some() {
        diag::error(&format!(
            "sbx: config {verb}: `--app` does not apply to `{verb}` (it takes no key)"
        ));
        Some(config_usage(verb))
    } else {
        None
    }
}

/// Reject `--trust` on a verb that writes nothing (`get` reads a value; `path` prints a file path).
///
/// [`crate::split_scope`] parses the flag for every verb that takes a scope, so a read-only verb
/// receives it and has nothing to do with it. Accepting it silently is the worst of the three
/// options: it tells whoever typed `get` where they meant `set` — or who believes `path --trust`
/// arms something — that a security setting was recorded when none was, and it is the same
/// mistaken belief the trust-carrying verbs answer with a note. The neighbouring [`reject_app`]
/// already refuses an inapplicable flag rather than dropping it; this holds `--trust` to that.
///
/// Returns the usage exit code when `--trust` was passed, else `None`.
fn reject_trust(verb: &str, trust: bool) -> Option<ExitCode> {
    if trust {
        diag::error(&format!(
            "sbx: config {verb}: `--trust` does not apply to `{verb}` (it writes nothing)"
        ));
        Some(config_usage(verb))
    } else {
        None
    }
}

/// Whether a write to this scope passes a trust gate at all.
///
/// The global config is trusted **by location**: the loader consults no marker for it, so one written
/// there is never read back. Everything else a write can target (a project `.sbx.toml`, an explicit
/// `-c` file) is hashed and gated.
///
/// One definition, shared by the key-writing verbs and by `edit`, because a second one is exactly how
/// `edit` came to write a marker nothing reads and report a gate that does not exist.
fn scope_is_gated(scope: &config::manage::Scope) -> bool {
    !matches!(scope, config::manage::Scope::Global)
}

/// Read the trust verdict for a write, **before** the write happens, and refuse the one write that
/// would bless bytes the user has never approved.
///
/// Two answers in one pass, because both come from the same read and both must precede the edit:
///
/// - The returned `was_trusted` is what [`report_write_trust`] needs to say whether this edit
///   re-armed a gate. It has to be read first: the write changes the file, and so its verdict.
/// - `--trust` on a file that exists and is not trusted is **refused** (exit 2), because the flag
///   blesses the whole current file — every security field in it, including the ones the user has
///   not read. It is the same admission [`crate::local_save_permitted`] applies to `sbx net allow
///   --local`, and calling that function is the point: one definition of when sbx may bless.
///
/// The refusal lands before the edit deliberately. Writing and *then* declining to bless would leave
/// a modified, untrusted file — worse than either outcome, since the user must now review bytes sbx
/// changed under them.
///
/// Scope decides the gate, not the verb: a `-c <file>` target carries a trust marker like any
/// project config, so it is admitted the same way. Only the global config and the app profiles are
/// exempt, and they are exempt because they are trusted by *location* — there is no marker to bless.
fn admit_config_write(
    verb: &str,
    path: &Path,
    gated: bool,
    trust_flag: bool,
    store_dir: Option<&Path>,
) -> Result<bool, ExitCode> {
    if !gated {
        return Ok(false);
    }
    // No store means no marker can be read and none can be written: `--trust` cannot bless anything,
    // which `report_write_trust` says in its own words. Nothing to admit.
    let Some(dir) = store_dir else {
        return Ok(false);
    };
    let state = trust::state(dir, path);
    let has_mise = !trust::mise_files_for(path).is_empty();
    if trust_flag && !crate::local_save_permitted(path.exists(), state, has_mise) {
        // A project with no config yet and a mise file beside it is a third case, and it names a
        // different file: `--trust` there would bless the mise file along with the one line sbx is
        // about to write. Saying the missing config "is not trusted" would point at the wrong file
        // and offer a command that cannot run on a file that does not exist.
        if !path.exists() {
            let names = trust::mise_files_for(path)
                .iter()
                .filter_map(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(", ");
            diag::error(&format!(
                "sbx: config {verb}: `--trust` here would also trust {names} beside the config it \
                 creates — content sbx did not write and you have not reviewed"
            ));
            diag::hint(&format!(
                "       create the config (`touch {}` is enough), review {names}, run \
                 `sbx trust {}`, then retry",
                path.display(),
                path.display()
            ));
            return Err(ExitCode::from(2));
        }
        // The two refused states read very differently to whoever hit them. "Never trusted" is a
        // file you have not vetted; "changed since" is one you *did* vet, whose current bytes are
        // not the ones you approved.
        let why = if state == trust::TrustState::Changed {
            "changed since you trusted it"
        } else {
            "is not trusted"
        };
        diag::error(&format!(
            "sbx: config {verb}: {} {why} — `--trust` blesses the whole file, \
             including what you have not read",
            path.display()
        ));
        diag::hint(&format!(
            "       review it and run `sbx trust {}`, then retry — or use `sbx config edit --trust`, \
             which opens the file first",
            path.display()
        ));
        return Err(ExitCode::from(2));
    }
    Ok(state == trust::TrustState::Trusted)
}

/// Resolve the file a key-taking verb (`get`/`set`/`unset`) targets and the dotted key within it,
/// applying the `--app <name>` routing and reporting whether the target is trust-gated.
///
/// The routing mirrors `sbx net … -a <name>`: a **global** app lives in its own profile file
/// `apps/<name>.toml` with **top-level** keys, so the key is used as-is; an app declared **inline**
/// (a project `.sbx.toml` or a `-c` file) is addressed under its `app.<name>.` table, with the name
/// quoted when it carries a `.` ([`app_prefixed_key`]). Every name the loader accepts is therefore
/// addressable in both scopes — at `-g` it keys the profile *filename*, inline it keys one table
/// segment — so the two agree on which apps exist.
///
/// The returned `gated` flag drives the trust note: the global config and the app profiles under
/// `apps/` are trusted **by location**, so a write to either is never gated (and never re-arms a trust
/// marker); a project (or explicit `-c`) file is. Any resolution error is already reported to stderr,
/// so the caller just returns the carried exit code.
fn resolve_key_target(
    verb: &str,
    scope: &config::manage::Scope,
    app: Option<&str>,
    raw_key: &str,
    cwd: &Path,
) -> Result<(PathBuf, String, bool), ExitCode> {
    use config::manage::{self, Scope};
    let gated = scope_is_gated(scope);
    let scope_path = |scope: &Scope| {
        manage::scope_path(scope, cwd).map_err(|e| {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        })
    };
    match (app, scope) {
        (None, _) => Ok((scope_path(scope)?, raw_key.to_string(), gated)),
        (Some(name), Scope::Global) => {
            // A global app is its own profile file with top-level keys. The name keys that
            // filename, so validate it (anti-traversal) the way `sbx net … -a <name> -g` does.
            if !config::is_valid_app_name(name) {
                diag::error(&format!("sbx: config {verb}: invalid app name `{name}`"));
                return Err(config_usage(verb));
            }
            let path = manage::scope_app_path(scope, cwd, name).map_err(|e| {
                diag::error(&format!("sbx: config: {e}"));
                ExitCode::FAILURE
            })?;
            Ok((path, raw_key.to_string(), false))
        }
        (Some(name), _) => {
            // An inline app (project `.sbx.toml` or a `-c` file) is addressed under `app.<name>.`.
            let key = app_prefixed_key(name, raw_key).map_err(|e| {
                diag::error(&format!("sbx: config {verb}: {e}"));
                config_usage(verb)
            })?;
            Ok((scope_path(scope)?, key, gated))
        }
    }
}

/// `sbx config set <key> <value>`: write a string value at a dotted key in the target layer file
/// (`--local` by default), preserving the rest of the file's comments and formatting. Because the
/// trust gate hashes the whole file, any edit re-arms it — so a write to a trusted file warns that
/// its security fields will not apply until `sbx trust`, and `--trust` re-trusts in one step.
pub(super) fn config_set(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config set: {e}"));
            return config_usage("set");
        }
    };
    if positionals.len() != 2 {
        return config_usage("set");
    }
    let val = &positionals[1];
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target("set", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = match admit_config_write("set", &path, gated, trust, store_dir.as_deref()) {
        Ok(t) => t,
        Err(code) => return code,
    };

    match config::manage::set(&path, &key, val) {
        Ok(written) if written.outcome == config::manage::SetOutcome::Unchanged => {
            // Nothing was written, so the trust marker still matches and the gate is not re-armed —
            // the same reasoning (and the same silence about trust) as `add`/`rm` on a no-op.
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_same_value(&key, &path, &pal));
            ExitCode::SUCCESS
        }
        Ok(written) => {
            let verb = if written.outcome == config::manage::SetOutcome::Created {
                "set"
            } else {
                "updated"
            };
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write(verb, &key, &path, &pal));
            report_write_trust(
                &path,
                &key,
                was_trusted,
                trust,
                store_dir.as_deref(),
                gated,
                &written.text,
            )
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Which end of a list `config add`/`config rm` works on. The two verbs differ only in the call and
/// the words they print, so they share one implementation — the scope parsing, the trust capture,
/// and the no-op reporting are the parts that must not drift between them.
#[derive(Clone, Copy)]
pub(super) enum ListEdit {
    Add,
    Remove,
}

/// `sbx config add <key> <entry>` / `sbx config rm <key> <entry>`: edit ONE entry of a list field,
/// leaving the rest of the list (and the file's comments) alone. This is the ergonomic half of
/// `set`, which replaces a whole list: adding a mask or a host is the common act, and doing it by
/// rewriting the entire array invites dropping an entry by mistake.
///
/// An entry already present (or already absent, for `rm`) leaves the file untouched and says so.
/// That is a security property, not a nicety: an unchanged file keeps its trust marker, so repeating
/// a command cannot disarm a trusted config's security fields behind the user's back.
pub(super) fn config_list_edit(args: &[OsString], op: ListEdit) -> ExitCode {
    let verb = match op {
        ListEdit::Add => "add",
        ListEdit::Remove => "rm",
    };
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config {verb}: {e}"));
            return config_usage(verb);
        }
    };
    if positionals.len() != 2 {
        return config_usage(verb);
    }
    let entry = &positionals[1];
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target(verb, &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = match admit_config_write(verb, &path, gated, trust, store_dir.as_deref()) {
        Ok(t) => t,
        Err(code) => return code,
    };

    let outcome = match op {
        ListEdit::Add => config::manage::add(&path, &key, entry),
        ListEdit::Remove => config::manage::remove(&path, &key, entry),
    };
    match outcome {
        Ok(written) if written.outcome => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            let (done, preposition) = match op {
                ListEdit::Add => ("added", "to"),
                ListEdit::Remove => ("removed", "from"),
            };
            println!(
                "{}",
                render_list_edit(done, preposition, entry, &key, &path, &pal)
            );
            report_write_trust(
                &path,
                &key,
                was_trusted,
                trust,
                store_dir.as_deref(),
                gated,
                &written.text,
            )
        }
        Ok(_) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            let why = match op {
                ListEdit::Add => "is already in",
                ListEdit::Remove => "is not in",
            };
            println!("{}", render_list_unchanged(entry, why, &key, &path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx config unset <key>`: remove a dotted key from the target layer file. Removing a key that
/// was not set is a no-op (exit 0) that changes nothing — so it never re-arms trust. A removal
/// that does change a trusted file re-arms it, with the same warning as `set`.
pub(super) fn config_unset(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config unset: {e}"));
            return config_usage("unset");
        }
    };
    if positionals.len() != 1 {
        return config_usage("unset");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let (path, key, gated) =
        match resolve_key_target("unset", &scope, app.as_deref(), &positionals[0], &cwd) {
            Ok(t) => t,
            Err(code) => return code,
        };
    let store_dir = trust::default_store_dir();
    let was_trusted = match admit_config_write("unset", &path, gated, trust, store_dir.as_deref()) {
        Ok(t) => t,
        Err(code) => return code,
    };

    match config::manage::unset(&path, &key) {
        Ok(written) if written.outcome => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_write("unset", &key, &path, &pal));
            report_write_trust(
                &path,
                &key,
                was_trusted,
                trust,
                store_dir.as_deref(),
                gated,
                &written.text,
            )
        }
        Ok(_) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_config_unchanged(&key, &path, &pal));
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx config path`: with no scope flag, show the config files a launch resolves, in order, each
/// with whether it exists — so it is clear where sbx looks (and that a default project `.sbx.toml`
/// need not exist). With an explicit scope (`-l`/`-g`/`-c`), print the single bare path that scope
/// targets — the file `set`/`unset`/`edit` would touch, for scripting and for finding the global
/// config.
pub(super) fn config_path_cmd(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        scope_explicit,
        trust,
        app,
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config path: {e}"));
            return config_usage("path");
        }
    };
    if let Some(code) = reject_app("path", &app) {
        return code;
    }
    if let Some(code) = reject_trust("path", trust) {
        return code;
    }
    if !positionals.is_empty() {
        return config_usage("path");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };

    if !scope_explicit {
        // The useful default: the resolution overview. A successful listing even when nothing
        // exists yet — that is the common first-run state, not an error.
        let layers = config::manage::resolution_layers(&cwd);
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        print!("{}", render_resolution_layers(&layers, &pal));
        return ExitCode::SUCCESS;
    }

    match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => {
            println!("{}", p.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            ExitCode::FAILURE
        }
    }
}

/// Render the config-file resolution overview: each layer in order (global base, project overlay)
/// with its path and whether the file is present. Returned as a string so a test can assert it
/// without a terminal. The label column is padded as plain text before color is applied, so the
/// path column stays aligned regardless of styling.
fn render_resolution_layers(layers: &[config::manage::Layer], pal: &style::Palette) -> String {
    use std::fmt::Write as _;
    let (h, nm, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{h}config files in resolution order{r} \
         {dim}(global is the base; the project overlays it){r}"
    );
    for layer in layers {
        let label = format!("{:<8}", layer.label);
        match &layer.path {
            Some(p) => {
                let (state, hue) = if p.try_exists().unwrap_or(false) {
                    ("present", ok)
                } else {
                    ("absent", dim)
                };
                let _ = writeln!(o, "  {nm}{label}{r}{}  {hue}({state}){r}", p.display());
            }
            None => {
                let _ = writeln!(o, "  {nm}{label}{r}{dim}(no config directory){r}");
            }
        }
    }
    let _ = writeln!(
        o,
        "{}",
        style::dim_prose("for the resolved values, see `sbx config show`.", pal)
    );
    o
}

/// `sbx config edit`: open the target layer file in `$VISUAL`/`$EDITOR` (falling back to `vi`).
/// The escape hatch for what `set` does not handle — arrays, secrets, and app tables. Runs through
/// a shell so an editor carrying arguments (e.g. `code --wait`) works, with the path passed as a
/// positional so it needs no quoting. Because the trust gate hashes the whole file, an edit that
/// changes a trusted file re-arms it — detected after the editor exits (the verdict becomes
/// Changed) and warned, or applied at once with `--trust`.
///
/// All of that is about a **gated** target. The global config is trusted by location, so it has no
/// marker to re-arm and none to write: `--trust` there is answered with the note the key-writing
/// verbs give, and nothing is stored. See [`scope_is_gated`].
///
/// A `--trust` on a gated target that could not be recorded fails the verb, exactly as it does for
/// the key-writing verbs and through the same tail ([`record_trust`]): the editor's changes are on
/// disk, and their security fields are inert until a marker exists.
///
/// # Two limits of running an editor, stated rather than implied
///
/// **The editor inherits the invoking environment whole.** It is a program of the user's choosing,
/// named by `$VISUAL`/`$EDITOR`, and it is run on the host with the user's own privileges — sbx
/// neither sandboxes it nor trims what it is handed. That is what makes an editor with a
/// configuration, plugins and credentials work at all, and it is the same trust the shell that
/// invoked `sbx` already extends to it. It also means this verb is not a confinement boundary: an
/// editor is a program, and running one is running it.
///
/// **The file is edited in place.** sbx stages no temporary copy and performs no atomic replace,
/// because the write is the editor's and the editor owns how it makes it — most replace through a
/// temporary of their own, some truncate and rewrite. So an editor killed mid-write can leave a
/// truncated or unparseable config, which the loader then drops whole with a warning; a gated file
/// in that state also no longer matches its marker, so its security fields are inert until it is
/// reviewed and re-trusted, which is the fail-safe direction. What sbx does own is what follows: a
/// non-zero exit stops before anything is trusted, and the trust verdict is read from the file as
/// the editor left it.
pub(super) fn config_edit(args: &[OsString]) -> ExitCode {
    let ScopeArgs {
        positionals,
        scope,
        trust: trust_flag,
        app,
        ..
    } = match split_scope(args) {
        Ok(parsed) => parsed,
        Err(e) => {
            diag::error(&format!("sbx: config edit: {e}"));
            return config_usage("edit");
        }
    };
    if let Some(code) = reject_app("edit", &app) {
        return code;
    }
    if !positionals.is_empty() {
        return config_usage("edit");
    }
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
    };
    let path = match config::manage::scope_path(&scope, &cwd) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: config: {e}"));
            return ExitCode::FAILURE;
        }
    };
    // Make sure the parent directory exists so the editor can save a new file (the global config
    // directory may not exist yet).
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        diag::error(&format!(
            "sbx: config: cannot create {}: {e}",
            parent.display()
        ));
        return ExitCode::FAILURE;
    }

    // Whether this target passes a trust gate at all. A non-gated one (the global config) carries no
    // marker: writing one would leave a file nothing ever reads, and reporting one would announce a
    // gate that does not exist. Both are settled before the editor runs, so the answer cannot depend
    // on what was saved.
    //
    // This verb deliberately skips [`admit_config_write`]: `--trust` here blesses a file the editor
    // just showed, which is the one case where blessing bytes sbx did not author is what the user
    // asked for. It is the escape hatch the other four verbs point at when they refuse.
    let gated = scope_is_gated(&scope);
    let store_dir = trust::default_store_dir();
    let was_trusted = gated
        && store_dir
            .as_deref()
            .is_some_and(|d| trust::state(d, &path) == trust::TrustState::Trusted);

    let editor_os = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| OsString::from("vi"));
    let editor = editor_os.to_string_lossy();
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$@\""))
        .arg("sh")
        .arg(&path)
        .status();
    let code = match status {
        Ok(code) => code,
        Err(e) => {
            diag::error(&format!(
                "sbx: config: could not launch the editor `{editor}`: {e}"
            ));
            return ExitCode::FAILURE;
        }
    };
    // `Ok` says **`sh`** ran, not that the editor did. `$VISUAL`/`$EDITOR` naming a program this
    // host does not have (`code --wait` over ssh, a container without the editor installed) makes
    // `sh` exit 127 having shown nothing; an editor the user deliberately aborted (`vi`'s `:cq`)
    // exits non-zero on purpose. Both used to fall through to the `--trust` branch below, which
    // blessed the whole file — so `sbx config edit --trust` on a cloned repo could print
    // `sh: 1: code: not found` and then `trusted <path>`, and every later launch honoured a config
    // the user never saw a byte of. That is the exact inverse of what this verb's skipping of
    // `admit_config_write` is justified by: "`--trust` here blesses a file the editor just showed".
    //
    // So a non-zero exit stops here, before anything is trusted and before a trust state is
    // reported for an edit that did not happen. It is also the only way this function's own exit
    // code can mean anything, since it returned SUCCESS whatever the editor did.
    if !code.success() {
        diag::error(&format!(
            "sbx: config: the editor `{editor}` exited {code} — {} was not edited, and nothing was \
             trusted",
            path.display()
        ));
        return ExitCode::FAILURE;
    }

    if !gated {
        // Say so only when `--trust` was asked for: the flag is what carries the mistaken belief,
        // and an unasked-for note on every global edit would be noise. The same sentence the
        // key-writing verbs use, since it is the same fact.
        if trust_flag {
            diag::note(&format!(
                "{} is trusted by location; `--trust` is not needed",
                path.display()
            ));
        }
    } else if trust_flag {
        // The same tail the key-writing verbs use, and a failure for the same reason: the editor
        // saved the file, so its security fields are on disk and inert until the marker exists.
        // Reporting success would tell `sbx config edit --trust && sbx run …` that the gate was
        // armed when it was not, and the launch that follows would run against a config whose
        // `[network]`, `[binds]`, `[fs]` and `[secret]` are dropped.
        // The one path that hashes the file rather than composed text, and the only admitted
        // caller of [`crate::trust::trust`] outside `sbx trust`: sbx wrote none of these bytes —
        // the editor showed the user the file and left what they saved, which is what they are
        // approving. There is nothing else here to attest to.
        if let Err(code) = record_trust(&path, store_dir.as_deref(), "the file was saved", |dir| {
            trust::trust(dir, &path)
        }) {
            return code;
        }
    } else if was_trusted {
        // Only warn if the edit actually changed the file (the verdict is now Changed).
        let now = store_dir.as_deref().map(|d| trust::state(d, &path));
        if now == Some(trust::TrustState::Changed) {
            diag::warn(&format!(
                "your edit re-armed the trust gate for {}",
                path.display()
            ));
            diag::hint(&format!(
                "       run `sbx trust {}` to re-apply its security fields",
                path.display()
            ));
        }
    }
    ExitCode::SUCCESS
}

/// Report the trust consequence of a write, the load-bearing UX of `set`/`unset`: the whole-file
/// trust hash means any edit re-arms the gate. `--trust` re-trusts in one step (blessing the whole
/// current file); otherwise a write to a previously-trusted file warns that its security fields
/// will not apply until `sbx trust`, and a write of a security field to an untrusted file notes it
/// needs trust to take effect. A free `env` write to an untrusted file needs neither.
fn report_write_trust(
    path: &Path,
    key: &str,
    was_trusted: bool,
    trust_flag: bool,
    store_dir: Option<&Path>,
    gated: bool,
    text: &str,
) -> ExitCode {
    // The global config and the app profiles under `apps/` are trusted **by location** — they carry
    // no per-file trust marker, so a write never re-arms a gate and needs no `sbx trust`. Reporting
    // one would be a false positive (the field applies as soon as the file is read), so say nothing —
    // beyond noting that an explicit `--trust` is unnecessary here.
    if !gated {
        if trust_flag {
            diag::note(&format!(
                "{} is trusted by location; `--trust` is not needed",
                path.display()
            ));
        }
        return ExitCode::SUCCESS;
    }
    if trust_flag {
        // Attested from the text the verb composed, never from a second read of the path: the
        // reasoning is [`record_trust`]'s and [`crate::trust::trust_written`]'s.
        return match record_trust(path, store_dir, "the field was written", |dir| {
            trust::trust_written(dir, path, text.as_bytes())
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(code) => code,
        };
    }
    if was_trusted {
        diag::warn(&format!(
            "this edit re-armed the trust gate for {}",
            path.display()
        ));
        diag::hint(&format!(
            "       its security fields will not apply until you run `sbx trust {}`",
            path.display()
        ));
    } else if is_security_key(key) {
        diag::note(&format!(
            "`{key}` is a security field; it applies only once {} is trusted (`sbx trust`)",
            path.display()
        ));
    }
    ExitCode::SUCCESS
}

/// Record `--trust` for `path` and report the outcome: the whole-file marker on success, a refusal
/// on either way it can fail (no trust store to write into, or the store rejecting the file).
///
/// One tail shared by `edit` and the key-writing verbs, because the two states the failure leaves
/// behind are the same state: the file is on disk carrying security fields, and they are inert
/// until the marker exists. A `--trust` that could not be recorded is therefore a **failure**, not
/// a warning — reporting success tells a script (`sbx config … --trust && sbx run …`) that the
/// security setting took effect when it did not, which is the one direction this must not be wrong
/// in. `edit` had that wrong on its own copy of these three arms, which is why there is now one.
///
/// `saved` names what the caller already put on disk — "the field was written", "the file was
/// saved" — so the remediation hint describes the state the user is actually in.
///
/// **What is attested to is the caller's, and it is passed in rather than chosen here.** `attest`
/// is handed the trust store directory and records the marker: the key-writing verbs pass
/// [`crate::trust::trust_written`] over the text they composed, `edit` passes
/// [`crate::trust::trust`] because there the bytes on disk are exactly what the user approved. The
/// distinction is a security property, not a preference — a re-read blesses whatever a concurrent
/// writer left, and the project tree is bound read-write into the cage — so this tail is unable to
/// make the choice on a caller's behalf. A verb that wants the re-reading form has to write the
/// call itself, where a reader (and the guard in [`crate::trust`]) can see it.
fn record_trust(
    path: &Path,
    store_dir: Option<&Path>,
    saved: &str,
    attest: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<(), ExitCode> {
    match store_dir {
        Some(dir) => match attest(dir) {
            Ok(()) => {
                let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                println!("{}", render_trusted_whole_file(path, &pal));
                Ok(())
            }
            Err(e) => {
                diag::error(&format!("sbx: could not trust {e}"));
                diag::hint(&format!(
                    "       {saved} but does not apply; run `sbx trust {}`",
                    path.display()
                ));
                Err(ExitCode::FAILURE)
            }
        },
        None => {
            diag::error("sbx: no trust store available; cannot --trust");
            diag::hint(&format!(
                "       {saved} but does not apply until it is trusted"
            ));
            Err(ExitCode::FAILURE)
        }
    }
}

/// Whether a dotted config key names a security-relevant field. The only field applied without
/// trust (minus the untrusted-env denylist) is the free `env` table — both the baseline `env.*`
/// and an app's `app.<name>.env.*`; everything else is gated, so setting one on an untrusted file
/// is worth a note.
///
/// The key is read the way the write read it, quotes included: an app name carrying a `.` is one
/// quoted segment (`app."my.app".env.FOO`), so splitting on every dot would walk through the quotes
/// and mistake an app's free `env` table for a gated field — sending the user to bless a whole file
/// to fix a variable that already applies. Anything this cannot take apart is reported as gated,
/// the answer that over-reports rather than under-reports.
fn is_security_key(key: &str) -> bool {
    let field = strip_app_prefix(key).unwrap_or(key);
    let free_env_table = field == "env" || field.starts_with("env.");
    !free_env_table
}

/// Strip a leading `app.<name>.` from a dotted key, returning what it names inside that app's
/// table, or `None` when the key does not address an app's field.
///
/// `<name>` may be quoted to carry dots, in either of the two spellings TOML allows (`"my.app"`,
/// `'my.app'`) — the same rule `config::manage::split_key` applies when the write walks the same
/// key, and the reason this cannot be a plain `split('.')`.
fn strip_app_prefix(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("app.")?;
    let after_name = match rest.chars().next() {
        Some(quote @ ('"' | '\'')) => {
            let opened = quote.len_utf8();
            // An unbalanced quote is not a key any write accepted, so there is no app table here.
            let closed = opened + rest[opened..].find(quote)?;
            &rest[closed + quote.len_utf8()..]
        }
        _ => &rest[rest.find('.')?..],
    };
    after_name.strip_prefix('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sbx config set|add|rm|unset --trust` blesses the text it composed, never a second read of
    /// the path.
    ///
    /// The tail these four verbs share writes the file and then records trust for it. A marker taken
    /// from a re-read attests to whatever is on disk at that moment, and the project tree is bound
    /// read-write into the cage — so a payload writing between the two has its own `.sbx.toml`
    /// blessed, and its `[network]` and `[binds]` apply from the next launch. The write succeeds
    /// either way, which is what makes the difference invisible at the call site.
    ///
    /// The racing write is simulated by writing something else after the composed bytes, the same
    /// shape `crate::trust`'s own test uses: the marker must not cover it. Both halves are asserted,
    /// because a marker that matches nothing would satisfy the first on its own.
    #[test]
    fn a_key_write_with_trust_attests_to_the_text_it_composed() {
        let dir = crate::testutil::TmpDir::new();
        let store = dir.path().join("store");
        let path = dir.path().join(config::PROJECT_CONFIG);
        std::fs::write(&path, "# project config\n").expect("the starting config");
        trust::trust(&store, &path).expect("trust the starting config");

        let written = config::manage::set(&path, "network.stats", "false").expect("the write");

        let hostile = "[network]\nmode = \"shared\"\nbinds = [\"/:rw\"]\n";
        std::fs::write(&path, hostile).expect("the racing write");

        let _ = report_write_trust(
            &path,
            "network.stats",
            true,
            true,
            Some(&store),
            true,
            &written.text,
        );

        assert_eq!(
            trust::state(&store, &path),
            trust::TrustState::Changed,
            "the racing write was blessed — the marker covered the file on disk, not what sbx wrote"
        );

        std::fs::write(&path, &written.text).expect("restore the composed config");
        assert_eq!(
            trust::state(&store, &path),
            trust::TrustState::Trusted,
            "the bytes that were attested to must be the ones that verify"
        );
    }

    #[test]
    fn is_security_key_treats_only_the_env_table_as_free() {
        // the free `env` table — baseline and per-app — is not gated
        assert!(!is_security_key("env.FOO"));
        assert!(!is_security_key("env"));
        assert!(!is_security_key("app.demo-app.env.FOO"));
        // everything else is a security field, including an app's own security overlay
        assert!(is_security_key("binds"));
        assert!(is_security_key("network"));
        assert!(is_security_key("app.demo-app.network"));
        assert!(is_security_key("app.demo-app.cmd"));
        // a bare app table (no field) is gated too
        assert!(is_security_key("app.demo-app"));
    }

    #[test]
    fn is_security_key_reads_a_quoted_app_name_as_one_segment() {
        // An app name may carry a `.` — the loader accepts one and `sbx net allow -a my.app` writes
        // one — and it is then addressed as a quoted segment. Splitting the key on every dot walked
        // straight through the quotes, so `app."my.app".env.FOO` had `app"` where the `env` table
        // should be and the write was answered with a note calling a free variable a security
        // field, sending the user to bless the whole file to fix something already in effect.
        assert!(!is_security_key("app.\"my.app\".env.FOO"));
        assert!(!is_security_key("app.'my.app'.env"));
        // The quoting must not swallow the field either: the same app's gated fields stay gated.
        assert!(is_security_key("app.\"my.app\".network"));
        assert!(is_security_key("app.\"my.app\".cmd"));
        // A key whose quote never closed is not one any write accepted; report it gated, the answer
        // that over-reports rather than under-reports.
        assert!(is_security_key("app.\"my.app.env.FOO"));
    }

    #[test]
    fn resolution_layers_render_marks_presence_and_stays_plain_uncolored() {
        use config::manage::Layer;
        let tmp = crate::testutil::TmpDir::new();
        let present = tmp.path().join("here.toml");
        std::fs::write(&present, "x = 1\n").unwrap();
        let absent = tmp.path().join("gone.toml");
        let layers = vec![
            Layer {
                label: "global",
                path: Some(absent.clone()),
            },
            Layer {
                label: "project",
                path: Some(present.clone()),
            },
        ];
        let plain = render_resolution_layers(&layers, &style::Palette::plain());
        assert!(plain.contains("resolution order"), "header:\n{plain}");
        assert!(
            plain.contains(&format!("{}  (absent)", absent.display())),
            "an absent layer must be marked absent:\n{plain}"
        );
        assert!(
            plain.contains(&format!("{}  (present)", present.display())),
            "a present layer must be marked present:\n{plain}"
        );
        // The colored path wraps the marker in its hue and resets it — pad-then-color keeps the
        // path column aligned, which only ever shows here.
        let c = style::Palette::colored();
        let colored = render_resolution_layers(&layers, &c);
        assert!(
            colored.contains(&format!("{}(present){}", c.ok, c.reset)),
            "a present marker must be wrapped in the ok span and reset:\n{colored}"
        );
    }

    #[test]
    fn resolution_layers_render_handles_a_missing_config_directory() {
        // The global layer can have no path (no $XDG_CONFIG_HOME/$HOME) — it must not error the
        // listing, just say so.
        use config::manage::Layer;
        let layers = vec![Layer {
            label: "global",
            path: None,
        }];
        let plain = render_resolution_layers(&layers, &style::Palette::plain());
        assert!(
            plain.contains("global") && plain.contains("(no config directory)"),
            "a pathless global layer must read as no config directory:\n{plain}"
        );
    }

    #[test]
    fn resolve_key_target_routes_by_scope_and_app() {
        // The routing behind `config get/set/unset`. Env-independent arms are asserted here; the
        // `--app <name> --global` profile arm resolves the config home, so it is covered by the
        // `config show --app` / profile integration tests instead (same convention as
        // `egress_write_target` above).
        use config::manage::Scope;
        let cwd = std::path::Path::new("/some/cwd");
        let proj = cwd.join(config::PROJECT_CONFIG);

        // No app: the raw key, the scope's file, and gated for a project write.
        let (path, key, gated) =
            resolve_key_target("set", &Scope::Local, None, "network", cwd).unwrap();
        assert_eq!((path, key.as_str(), gated), (proj.clone(), "network", true));

        // An inline app (project scope) addresses `app.<name>.<key>` and stays gated.
        let (path, key, gated) =
            resolve_key_target("set", &Scope::Local, Some("demo"), "network", cwd).unwrap();
        assert_eq!(
            (path, key.as_str(), gated),
            (proj, "app.demo.network", true)
        );

        // A `-c` file with an app: the file itself, the prefixed key, still gated (not trusted by
        // location).
        let explicit = std::path::PathBuf::from("/etc/sbx.toml");
        let (path, key, gated) = resolve_key_target(
            "set",
            &Scope::File(explicit.clone()),
            Some("demo"),
            "cmd",
            cwd,
        )
        .unwrap();
        assert_eq!(
            (path, key.as_str(), gated),
            (explicit, "app.demo.cmd", true)
        );

        // An app name with a `.` is addressed inline as one quoted segment, so every name the
        // loader accepts is reachable from the key verbs and not only from `sbx net … -a`.
        let (_, key, _) =
            resolve_key_target("set", &Scope::Local, Some("a.b"), "network", cwd).unwrap();
        assert_eq!(key, "app.\"a.b\".network");

        // An invalid charset can never key a profile filename (validated before the config home is
        // even resolved, so this arm stays env-independent). A name that merely coincides with a
        // subcommand verb (`import`, `show`, …) is valid — launching goes through `sbx app run` —
        // so that arm resolves the config home and is covered by the profile integration tests.
        assert!(
            resolve_key_target("set", &Scope::Global, Some("bad/name"), "network", cwd).is_err(),
            "an invalid app name cannot name a global-app profile"
        );
    }

    /// Whether two exit codes are the same code. [`ExitCode`] carries no `PartialEq` and no
    /// accessor, but its `Debug` names the status byte it holds, so two codes are equal exactly
    /// when their debug forms are. Every test that uses this asserts first that two *different*
    /// codes compare unequal, so a `Debug` that stopped naming the byte fails the assertion rather
    /// than letting the test pass on a comparison that can no longer distinguish anything.
    fn same_exit_code(a: ExitCode, b: ExitCode) -> bool {
        format!("{a:?}") == format!("{b:?}")
    }

    #[test]
    fn a_read_only_verb_refuses_trust_instead_of_dropping_it() {
        // `--trust` rides the shared scope parser, so `get` and `path` are handed a flag they have
        // no behaviour for, and they used to discard it without a word: `sbx config get -c <file>
        // --trust` printed the value and exited 0. It is the one flag whose entire meaning is a
        // security decision, and the neighbouring typo `--truts` is already refused — so silently
        // accepting it told whoever typed `get` where they meant `set` that a gate had been armed.
        assert!(
            !same_exit_code(ExitCode::SUCCESS, ExitCode::from(2)),
            "two different exit codes must compare unequal, or the assertions below prove nothing"
        );

        let tmp = crate::testutil::TmpDir::new();
        let cfg = tmp.join("layer.toml");
        std::fs::write(&cfg, "network = \"deny\"\n").unwrap();
        // The read passes the same safety gate a launch applies, which refuses a world-writable
        // file — so pin the mode rather than inherit whatever umask the run happens to carry.
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let file = cfg.to_str().unwrap();
        let argv = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();

        // Without the flag both verbs do their work, so what is refused below is the flag itself.
        assert!(same_exit_code(
            config_get(&argv(&["-c", file, "network"])),
            ExitCode::SUCCESS
        ));
        assert!(same_exit_code(
            config_path_cmd(&argv(&["-c", file])),
            ExitCode::SUCCESS
        ));

        // With it, both exit 2 with the verb's usage — the treatment an inapplicable `--app`
        // already gets.
        assert!(same_exit_code(
            config_get(&argv(&["-c", file, "--trust", "network"])),
            ExitCode::from(2)
        ));
        assert!(same_exit_code(
            config_path_cmd(&argv(&["-c", file, "--trust"])),
            ExitCode::from(2)
        ));
    }

    #[test]
    fn config_edit_trust_fails_when_the_trust_could_not_be_recorded() {
        // `edit --trust` treated a trust it could not record as advisory: it warned and returned
        // success, so `sbx config edit --trust && sbx run agent` proceeded to launch against a
        // project config whose `[network]`, `[binds]`, `[fs]` and `[secret]` the gate then dropped
        // — the cage running with open egress on the strength of an exit code that said the
        // security setting had been applied. The key-writing verbs have always exited 1 here.
        let _lock = crate::testutil::env_lock();
        let tmp = crate::testutil::TmpDir::new();
        let cfg = tmp.join("edited.toml");
        std::fs::write(&cfg, "[network]\nmode = \"deny\"\n").unwrap();

        // An editor that saves nothing and exits 0, so the run reaches the `--trust` tail; and no
        // absolute `HOME`/`XDG_STATE_HOME`, which is what leaves `trust::default_store_dir` with
        // nowhere to write a marker.
        let _visual = crate::testutil::EnvVar::set("VISUAL", "true");
        let _editor = crate::testutil::EnvVar::set("EDITOR", "true");
        let _home = crate::testutil::EnvVar::unset("HOME");
        let _state = crate::testutil::EnvVar::unset("XDG_STATE_HOME");

        assert!(
            !same_exit_code(ExitCode::SUCCESS, ExitCode::FAILURE),
            "two different exit codes must compare unequal, or the assertion below proves nothing"
        );
        let args = [
            OsString::from("-c"),
            OsString::from(cfg.as_os_str()),
            OsString::from("--trust"),
        ];
        assert!(
            same_exit_code(config_edit(&args), ExitCode::FAILURE),
            "a `--trust` that recorded nothing must not report success"
        );
    }

    #[test]
    fn app_prefixed_key_quotes_a_dotted_name_and_leaves_a_plain_one_bare() {
        // The `--app` sugar puts the key under the app's table; a dotted leaf key composes.
        assert_eq!(
            app_prefixed_key("demo", "network").unwrap(),
            "app.demo.network"
        );
        assert_eq!(
            app_prefixed_key("demo", "env.FOO").unwrap(),
            "app.demo.env.FOO"
        );
        // A name carrying a `.` is one quoted segment, which is how the key splitter behind every
        // read and write reads it back. `sbx net allow -a my.app` and the loader both accept such a
        // name, so refusing it here left an app that could be created and shown but not edited.
        assert_eq!(
            app_prefixed_key("my.app", "cmd").unwrap(),
            "app.\"my.app\".cmd"
        );
        // Quoting stays confined to the names that need it: the common spelling is unchanged.
        assert!(!app_prefixed_key("demo", "cmd").unwrap().contains('"'));
        // A name no app could ever carry is rejected outright, before any rewriting — so nothing
        // that would need escaping can reach the quoted form.
        assert!(app_prefixed_key("bad name", "cmd").is_err());
        assert!(app_prefixed_key("bad\"name", "cmd").is_err());
    }
}
