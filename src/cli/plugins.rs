//! `sbx plugins <subcommand>`: inspect and manage resolver plugins and the signed plugin stores —
//! `list`/`info` (host-level inspection), `install`/`rm` (place a local or built-in plugin), and
//! `store add|publish|update|install|info|list|rm` (the git-hosted, Ed25519-signed catalogue). The
//! user-facing confirmation renderers it calls (`render_plugin_installed`/`render_store_*`/…) stay
//! at the crate root, shared with the `app`/`config` confirmations and their common test.

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::confirm::{
    render_plugin_installed, render_publish_key_warning, render_published, render_removed,
    render_store_configured, render_store_needs_key, render_store_rekey_alert,
    render_store_rekeyed, render_store_tofu, render_store_updated, render_store_verified,
};
use crate::plugins::{catalogue, stores};
use crate::{diag, help, plugins, store, style};

/// `sbx plugins <subcommand>`: inspect the installed resolver plugins. Host-level, like `doctor`
/// — it reads `<data>/plugins`, not a project's `.sbx.toml`. A read-only diagnostic for now;
/// installation and the signed plugin store are later increments, so the dispatch only knows the
/// inspection verbs and names them on anything else (no inert stubs).
pub(crate) fn plugins_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => {
            match crate::cli::reject_extra(&["plugins", "list"], &args[1..]) {
                Err(code) => code,
                Ok(()) => plugins_list(),
            }
        }
        Some("info") => {
            match crate::cli::reject_extra(&["plugins", "info"], args.get(2..).unwrap_or(&[])) {
                Err(code) => code,
                Ok(()) => plugins_info(args.get(1).and_then(|a| a.to_str())),
            }
        }
        Some("install") => {
            match crate::cli::reject_extra(&["plugins", "install"], args.get(2..).unwrap_or(&[])) {
                Err(code) => code,
                Ok(()) => plugins_install(args.get(1)),
            }
        }
        Some("rm") => plugins_remove(&args[1..]),
        Some("upgrade") => plugins_upgrade(&args[1..]),
        Some("verify") => {
            match crate::cli::reject_extra(&["plugins", "verify"], args.get(2..).unwrap_or(&[])) {
                Err(code) => code,
                Ok(()) => plugins_verify(args.get(1).and_then(|a| a.to_str())),
            }
        }
        Some("store") => plugins_store(&args[1..]),
        // Unknown or no subcommand: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `sbx net`/`sbx config`.
        other => {
            if let Some(tok) = other {
                diag::error(&format!("sbx: plugins: unknown subcommand {tok:?}"));
            }
            eprint!("{}", help::page_usage(&["plugins"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// Resolve the registry of installed resolver plugins from the data directory, or report why it
/// could not be located. Shared by `list` and `info`; the layout is returned alongside so a caller
/// can also read each plugin's recorded origin, and the validation warnings so it can surface them
/// (the diagnostic for a plugin that was discovered but dropped as malformed).
fn load_plugin_registry() -> Option<(store::Layout, plugins::PluginRegistry, Vec<String>)> {
    let layout = store::Layout::from_env()?;
    let mut warnings = Vec::new();
    // The quiet form: a scheme conflict is rendered from the registry itself here (naming every
    // claimant and the way out), so relaying it as a warning too would say it twice.
    let registry = plugins::PluginRegistry::load_quiet(&layout.plugins_dir(), &mut warnings);
    Some((layout, registry, warnings))
}

/// What is installed right now, in the two shapes a store listing has to answer: which install
/// *names* are taken (and by which origin), and which *schemes* are claimed. Both matter, because
/// an install refuses on either — so a listing that only knew about names would still let a user
/// pick an entry that cannot be installed.
struct InstalledIndex {
    /// Every plugin directory under `<data>/plugins`, keyed by its directory name — the name an
    /// install would take. A directory whose manifest is malformed is included: it holds the name
    /// regardless, so a listing must report it as taken.
    by_name: std::collections::BTreeMap<String, InstalledPlugin>,
    /// Scheme → the directory name claiming it, for the plugins the registry actually resolved.
    by_scheme: std::collections::BTreeMap<String, String>,
    /// Scheme → every directory name claiming it, when more than one does. An ambiguous scheme
    /// resolves to nothing, so it is absent from `by_scheme` — but an install is refused on it all
    /// the same, so a listing that stayed silent here would offer an entry that cannot be placed.
    conflicts: std::collections::BTreeMap<String, Vec<String>>,
}

/// Order two version strings when — and only when — both are plainly ordered: dot-separated
/// numbers with an optional pre-release suffix after a `-`. A manifest's `version` is free-form,
/// and a store's is whatever it published, so anything else (a date, a git describe, a letter, an
/// overflowing component) yields `None` and the caller says "differs" instead of inventing a
/// direction. Guessing here would be the one failure mode that matters: telling a user they are
/// up to date when they are not.
fn version_order(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    /// `(numeric components, pre-release)`, or `None` when the core is not plainly numeric.
    fn split(v: &str) -> Option<(Vec<u64>, Option<&str>)> {
        let v = v.trim().strip_prefix('v').unwrap_or(v.trim());
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) if !pre.is_empty() => (core, Some(pre)),
            Some(_) => return None,
            None => (v, None),
        };
        if core.is_empty() {
            return None;
        }
        let nums: Option<Vec<u64>> = core.split('.').map(|c| c.parse::<u64>().ok()).collect();
        nums.filter(|n| !n.is_empty()).map(|n| (n, pre))
    }
    let (a_nums, a_pre) = split(a)?;
    let (b_nums, b_pre) = split(b)?;
    // `1.8` against `1.8.2`: a missing component is zero, so the shorter one sorts first.
    for i in 0..a_nums.len().max(b_nums.len()) {
        let (x, y) = (
            a_nums.get(i).copied().unwrap_or(0),
            b_nums.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    match (a_pre, b_pre) {
        // A release outranks a pre-release of the same core (`1.2.0` over `1.2.0-rc1`).
        (None, None) => Some(std::cmp::Ordering::Equal),
        (None, Some(_)) => Some(std::cmp::Ordering::Greater),
        (Some(_), None) => Some(std::cmp::Ordering::Less),
        // Two pre-releases: identical is equal, and anything else is not ours to rank
        // (`rc2` vs `beta` has no numeric answer).
        (Some(x), Some(y)) if x == y => Some(std::cmp::Ordering::Equal),
        (Some(_), Some(_)) => None,
    }
}

/// How to phrase an installed build the store no longer lists. The *fact* is always the digest
/// difference; the version strings only name it, and only as far as they can be ordered — an
/// unorderable pair says the two differ rather than which is newer, and a republish under the same
/// version string says exactly that.
fn drift_wording(have: &str, listed: &str) -> String {
    if have.is_empty() || listed.is_empty() {
        return "installed, the store lists a different build".to_string();
    }
    if have == listed {
        return format!("installed v{have}, the store lists a different build of v{listed}");
    }
    match version_order(have, listed) {
        Some(std::cmp::Ordering::Less) => format!("update available: v{have} → v{listed}"),
        Some(std::cmp::Ordering::Greater) => {
            format!("ahead of the store: installed v{have}, listed v{listed}")
        }
        // Equal-but-different strings (`1.0` vs `1.0.0`) are still a different build.
        Some(std::cmp::Ordering::Equal) => {
            format!("installed v{have}, the store lists a different build (v{listed})")
        }
        None => format!("installed v{have}, the store lists v{listed}"),
    }
}

/// One installed plugin, as a store listing needs it: where it came from, the version its own
/// manifest declares (absent when the manifest did not load or declares none), and the scheme it
/// is disabled over, if any.
struct InstalledPlugin {
    origin: plugins::origin::Origin,
    version: Option<String>,
    /// The digest recorded when this plugin was placed, when there is one — the installed side of
    /// the comparison against a catalogue's pinned `sha256`.
    digest: Option<String>,
    /// The ambiguous key this plugin claims, when it is one of several claimants — the plugin is
    /// in place but disabled, which a bare `[installed]` marker would hide.
    disabled_over: Option<Contested>,
}

/// The key an installed plugin is disabled over, in the namespace it claims it in. Both are
/// carried, rather than the scheme alone, because a plugin reached by name is disabled by the same
/// rule and would otherwise render as installed and working.
#[derive(Clone)]
enum Contested {
    Scheme(String),
    Name(String),
}

impl Contested {
    /// How a listing says it, naming the namespace: the remedy is the same (`plugins rm`), but
    /// which key to look at is not.
    fn phrase(&self) -> String {
        match self {
            Contested::Scheme(scheme) => format!("scheme {scheme}:// in conflict"),
            Contested::Name(name) => format!("the name {name} claimed twice"),
        }
    }
}

impl InstalledIndex {
    /// Scan the plugins directory: the directory names (with their recorded origins) and the
    /// schemes the registry resolved.
    fn scan(layout: &store::Layout) -> Self {
        let mut warnings = Vec::new();
        let plugins_dir = layout.plugins_dir();
        let registry = plugins::PluginRegistry::load_quiet(&plugins_dir, &mut warnings);
        // Key the manifest data by *directory* name, which is what an install collides on — a
        // hand-placed plugin may declare a manifest `name` that differs from its directory.
        let mut versions = std::collections::BTreeMap::new();
        let mut by_scheme = std::collections::BTreeMap::new();
        for p in registry.resolvers() {
            versions.insert(p.dir_name().to_string(), p.version.clone());
            by_scheme.insert(p.scheme.clone(), p.dir_name().to_string());
        }
        // Every kind carries a version, and a listing that only read the resolvers would call a
        // broker or a signer versionless whatever its manifest declared. Only the scheme index is
        // a resolver's alone.
        for (dir_name, version) in registry
            .brokers()
            .map(|p| (p.dir_name(), p.version.clone()))
            .chain(
                registry
                    .signers()
                    .map(|p| (p.dir_name(), p.version.clone())),
            )
        {
            versions.insert(dir_name.to_string(), version);
        }
        // A conflict's claimants are disabled, so they carry no manifest data here — only the key
        // that disabled them, which is what their marker has to say.
        let mut conflicts = std::collections::BTreeMap::new();
        let mut disabled = std::collections::BTreeMap::new();
        for (scheme, claimants) in registry.conflicts() {
            for dir_name in claimants {
                disabled.insert(dir_name.clone(), Contested::Scheme(scheme.to_string()));
            }
            conflicts.insert(scheme.to_string(), claimants.to_vec());
        }
        // A contested *name* disables its claimants exactly as a contested scheme does. Not folded
        // into `conflicts`, which is the scheme map an install is checked against: this one only
        // marks the claimants, so a plugin in place and reaching nothing does not read as working.
        for (name, claimants) in registry.name_conflicts() {
            for dir_name in claimants {
                disabled.insert(dir_name.clone(), Contested::Name(name.to_string()));
            }
        }

        let mut by_name = std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(&plugins_dir) {
            for e in entries.flatten() {
                if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let Ok(name) = e.file_name().into_string() else {
                    continue;
                };
                // Dot-prefixed entries are sbx's own bookkeeping (the origin records, a staging
                // tree caught mid-install), never a plugin: an install name may not begin with a
                // dot.
                if name.starts_with('.') {
                    continue;
                }
                let version = versions.get(&name).cloned().flatten();
                let origin = plugins::origin::read(layout, &name);
                let disabled_over = disabled.get(&name).cloned();
                let digest = origin.digest().map(str::to_string);
                by_name.insert(
                    name,
                    InstalledPlugin {
                        origin,
                        version,
                        digest,
                        disabled_over,
                    },
                );
            }
        }
        InstalledIndex {
            by_name,
            by_scheme,
            conflicts,
        }
    }

    /// Whether the installed plugin of this name came from *this* store — the single fact behind
    /// both the `[installed]` marker and the `--installed` filter, so the two can never disagree
    /// about what "installed" means.
    fn installed_from(&self, name: &str, store: &str) -> bool {
        self.by_name
            .get(name)
            .is_some_and(|p| p.origin.is_store(store))
    }

    /// The trailing marker for one entry of a store's listing: whether it is installed from this
    /// very store, or blocked because its name or scheme is already taken by something else. An
    /// entry a user can simply install carries no marker.
    fn marker(
        &self,
        name: &str,
        scheme: Option<&str>,
        listed_version: Option<&str>,
        listed_sha256: Option<&str>,
        store: &str,
        pal: &style::Palette,
    ) -> String {
        let r = pal.reset;
        if let Some(installed) = self.by_name.get(name) {
            if !self.installed_from(name, store) {
                // The two-stores-one-name case (and the local-install-shadows-a-store case): the
                // name is taken, so installing this entry would be refused. Name the holder rather
                // than claiming the entry is installed — it is not *this* plugin that is.
                return format!(
                    "  {}[name taken by {}]{r}",
                    pal.warn,
                    installed.origin.short()
                );
            }
            // In place, but claiming a scheme someone else claims too: it resolves nothing, so a
            // bare `[installed]` would read as working.
            if let Some(over) = &installed.disabled_over {
                return format!("  {}[installed, disabled: {}]{r}", pal.err, over.phrase());
            }
            // Is what is installed the artifact this store lists *now*? The digests answer that
            // exactly — the catalogue pins the tree it offers, and the install recorded the tree it
            // placed — so this is a fact, not the guess a version comparison would make. It also
            // catches the case versions cannot: a republish under the same version string.
            let listed = listed_version.unwrap_or("").trim();
            let have = installed.version.as_deref().unwrap_or("").trim();
            if let (Some(theirs), Some(ours)) = (listed_sha256, installed.digest.as_deref()) {
                if theirs != ours {
                    return format!("  {}[{}]{r}", pal.warn, drift_wording(have, listed));
                }
                return format!("  {}[installed]{r}", pal.ok);
            }
            // No digest on one side (a record predating them, or a source that pins none): fall
            // back to reporting the version strings without claiming a direction.
            if !listed.is_empty() && !have.is_empty() && listed != have {
                return format!("  {}[installed v{have}, listed v{listed}]{r}", pal.warn);
            }
            return format!("  {}[installed]{r}", pal.ok);
        }
        // The name is free, but a scheme is claimed by exactly one plugin — an install would be
        // refused for the scheme instead, which is far from obvious from a listing.
        // A broker claims no scheme, so neither of the two scheme collisions below can apply to
        // one: its namespace is its name, which the `by_name` check above already answered.
        let Some(scheme) = scheme else {
            return String::new();
        };
        if let Some(other) = self.by_scheme.get(scheme) {
            return format!(
                "  {}[scheme {scheme}:// taken by the installed plugin '{other}']{r}",
                pal.warn
            );
        }
        // The name is free and nothing *resolves* that scheme — but several plugins claim it, and
        // an install is refused on that too.
        if let Some(claimants) = self.conflicts.get(scheme) {
            return format!(
                "  {}[scheme {scheme}:// in conflict between {}]{r}",
                pal.err,
                plugins::quoted_list(claimants)
            );
        }
        String::new()
    }
}

/// `sbx plugins list`: the reserved built-in schemes (never claimable by a plugin) and every
/// installed resolver plugin — its scheme, name, version, network grant, and one-line
/// description. A plugin whose executable would be refused at launch (not owner-only, not a
/// regular file) is flagged here, using the very check the runner enforces, so the gap between
/// "discovered" and "runnable" is visible. Discovery warnings (a malformed manifest, an ambiguous
/// scheme) go to stderr. No nix, no network, no launch.
fn plugins_list() -> ExitCode {
    let Some((layout, registry, warnings)) = load_plugin_registry() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    println!(
        "{h}built-in schemes{r} (always resolve, never a plugin): {n}{}{r}",
        plugins::builtin_schemes().join(", ")
    );
    if registry.is_empty() {
        // "none" means none that *resolve*: a plugin contesting a scheme is installed but
        // disabled, so point at the section that accounts for it rather than imply an empty tree.
        // Deliberately not a claim about *every* plugin present — one may have been dropped as
        // malformed, which is a different reason reported on a different stream.
        let why = if registry.conflicts().next().is_some() {
            " (none resolving — see the scheme conflicts below)"
        } else {
            " (none)"
        };
        println!("{h}installed resolver plugins:{r}{why}");
    } else {
        println!("{h}installed resolver plugins:{r}");
        for p in registry.resolvers() {
            let net = if p.sandbox.network {
                "network"
            } else {
                "no-network"
            };
            print!("  {n}{}://{r}  {n}{}{r}", p.scheme, p.name);
            if let Some(v) = &p.version {
                print!("  v{v}");
            }
            print!("  {dim}{net}{r}");
            print_health(&layout, p.dir_name(), p.check_exec(), &pal);
            println!();
            print_description(p.description.as_deref(), &pal);
            print_provenance(&layout, p.dir_name(), &pal);
        }
        println!("{dim}(remove one with: sbx plugins rm <name>){r}");
    }
    // Brokers are listed apart from resolvers, and named by what reaches them. The two answer
    // different questions — a resolver is asked for a value, a broker stands in front of a host
    // resource — and folding them into one list would suggest a `scheme://` reaches a broker.
    if registry.brokers().next().is_some() {
        println!("{h}installed broker plugins:{r}");
        for p in registry.brokers() {
            print!("  {n}{}{r}", p.name);
            if let Some(v) = &p.version {
                print!("  v{v}");
            }
            print!(
                "  {dim}{} frames, max {} bytes{r}",
                p.broker.framing.token(),
                p.broker.max_frame
            );
            if p.broker.inspect_replies {
                print!("  {dim}rules on replies{r}");
            }
            print_health(&layout, p.dir_name(), p.check_exec(), &pal);
            println!();
            print_description(p.description.as_deref(), &pal);
            println!(
                "    {dim}found in the cage: {}{r}",
                how_the_cage_finds_it(p)
            );
            print_provenance(&layout, p.dir_name(), &pal);
        }
    }
    // Signers are listed apart again, and named by what a `[[secret]]` writes to be signed by them.
    // What identifies one is the headers it may set: that is the whole of what it can put on a
    // request, and the line says it rather than making the reader open the manifest.
    if registry.signers().next().is_some() {
        println!("{h}installed signer plugins:{r}");
        for p in registry.signers() {
            print!("  {n}{}{r}", p.name);
            if let Some(v) = &p.version {
                print!("  v{v}");
            }
            print!("  {dim}sets {}{r}", p.signer.sets_headers.join(", "));
            if p.signer.reads_secret {
                print!("  {dim}reads the secret{r}");
            }
            print_health(&layout, p.dir_name(), p.check_exec(), &pal);
            println!();
            print_description(p.description.as_deref(), &pal);
            print_provenance(&layout, p.dir_name(), &pal);
        }
    }
    print_conflicts(&layout, &registry, None, &pal);
    println!("{dim}(browse the configured stores with: sbx plugins store list){r}");
    for w in &warnings {
        diag::warn(w);
    }
    ExitCode::SUCCESS
}

/// The two markers that say something is wrong with an installed plugin, printed at the end of its
/// line (no newline of their own): an executable the runner would refuse, and drift since the
/// install measured against the digest recorded then.
///
/// Only the states that say something is wrong are shown. A plugin that matches its digest, or one
/// that never had a digest recorded, would otherwise add a column of noise to every line.
fn print_health(
    layout: &store::Layout,
    dir_name: &str,
    runnable: Result<(), String>,
    pal: &style::Palette,
) {
    let (err, r) = (pal.err, pal.reset);
    if let Err(why) = runnable {
        print!("  {err}[not runnable: {why}]{r}");
    }
    match plugins::integrity(layout, dir_name) {
        plugins::Integrity::Modified => print!("  {err}[modified since install]{r}"),
        plugins::Integrity::Unreadable(_) => print!("  {err}[cannot be hashed]{r}"),
        plugins::Integrity::Intact | plugins::Integrity::Unrecorded => {}
    }
}

/// The manifest's one-line description, indented under the plugin, when it has one.
fn print_description(description: Option<&str>, pal: &style::Palette) {
    if let Some(desc) = description {
        println!("    {}{desc}{}", pal.dim, pal.reset);
    }
}

/// Where a plugin came from. A manifest is identical whatever the source, so the origin record is
/// the only place the answer exists. Keyed on the directory name, which is what the install (and
/// the record) uses and which may differ from the manifest's `name` for a hand-placed tree.
fn print_provenance(layout: &store::Layout, dir_name: &str, pal: &style::Palette) {
    println!(
        "    {}from: {}{}",
        pal.dim,
        plugins::origin::read(layout, dir_name).label(),
        pal.reset
    );
}

/// The ambiguous keys, if any: a key claimed by more than one installed plugin resolves to nothing
/// and every claimant is disabled. Reported on stdout, beside the plugins that *do* resolve,
/// because it is the state of the installed set — not a passing diagnostic — and it stays until the
/// user removes all but one claimant. `only` narrows the report to a single key, for the caller
/// that was asked about that one.
///
/// Both namespaces are rendered here: a resolver's `scheme://`, and the **name** a broker and a
/// signer are each reached by. They are separate sections because the remedy reads differently
/// (one says a scheme must be unique, the other a name), and one function because a caller that
/// showed only one would leave a plugin listed nowhere and explained nowhere.
fn print_conflicts(
    layout: &store::Layout,
    registry: &plugins::PluginRegistry,
    only: Option<&str>,
    pal: &style::Palette,
) {
    let (n, dim, err, r) = (pal.name, pal.dim, pal.err, pal.reset);
    let claimant_lines = |claimants: &[String]| {
        for dir_name in claimants {
            println!(
                "    {n}{dir_name}{r}  {dim}from: {}{r}",
                plugins::origin::read(layout, dir_name).label()
            );
        }
    };
    let mut any = false;
    for (scheme, claimants) in registry.conflicts() {
        if only.is_some_and(|want| want != scheme) {
            continue;
        }
        if !any {
            println!("{err}scheme conflicts{r} (every claimant below is disabled):");
            any = true;
        }
        println!(
            "  {n}{scheme}://{r}  {err}claimed by {} plugins{r}",
            claimants.len()
        );
        claimant_lines(claimants);
    }
    if any {
        println!(
            "{dim}(a scheme must be unique: remove all but one with sbx plugins rm <name>){r}"
        );
    }
    let mut any_name = false;
    for (name, claimants) in registry.name_conflicts() {
        if only.is_some_and(|want| want != name) {
            continue;
        }
        if !any_name {
            println!("{err}name conflicts{r} (every claimant below is disabled):");
            any_name = true;
        }
        println!(
            "  {n}{name}{r}  {err}claimed by {} plugins{r}",
            claimants.len()
        );
        claimant_lines(claimants);
    }
    if any_name {
        println!(
            "{dim}(a plugin's name must be unique: remove all but one with sbx plugins rm \
             <name>){r}"
        );
    }
}

/// `sbx plugins install <dir>`: copy a local plugin directory into the data dir, where it becomes
/// trusted by location. A deliberate user act (an agent in the cage cannot run it); the staged copy
/// is validated exactly as the launcher will and refused, fail-closed, on any flaw. The other way
/// in is `sbx plugins store install <store> <plugin>`, which adds a signature and a content hash to
/// the same placement. No fetch, no network.
fn plugins_install(source: Option<&OsString>) -> ExitCode {
    let Some(source) = source else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "install"])
        ));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    match plugins::install(&layout, Path::new(source)) {
        Ok(installed) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_plugin_installed(
                    &installed.name,
                    installed.scheme.as_deref(),
                    installed.kind,
                    None,
                    &pal,
                )
            );
            provision_configured_programs(&layout, &installed.name)
        }
        Err(why) => {
            diag::error(&format!("sbx: cannot install plugin: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// Build whatever `[plugin.<name>] programs` names for the plugin that just claimed `scheme`, and
/// report it.
///
/// Runs here rather than at launch because a plugin's program is **project-independent**: it is
/// installed once and any project's secret may route through it, so provisioning it during a launch
/// would run a project-scoped path to produce a project-independent artifact and re-ask the question
/// every time. This is also the moment a user expects a build, having just asked for a plugin.
///
/// Re-running the install is therefore how a `programs` entry added *after* installing takes
/// effect, which is what the launch-time refusal for a missing program tells the user to do.
///
/// A build failure fails the command. The install itself already succeeded and is not undone: the
/// plugin is there, and what could not be built is named so the user can fix the attribute and run
/// the install again. Reporting success over a program the plugin cannot start would only move the
/// failure to the first secret.
fn provision_configured_programs(layout: &store::Layout, plugin_name: &str) -> ExitCode {
    let mut load_warnings = Vec::new();
    let registry = plugins::PluginRegistry::load_quiet(&layout.plugins_dir(), &mut load_warnings);
    // Looked up by *name*, which is the key `[plugin.<name>]` answers under — and the one key every
    // plugin type shares. A resolver is indexed by its scheme and the others by their name, but
    // what is being provisioned here is the manifest's `programs`, which no index is about: every
    // kind runs a program, so every kind is searched.
    let Some((programs, dir_name)) = registry
        .resolvers()
        .find(|p| p.name == plugin_name)
        .map(|p| (&p.sandbox.programs, p.dir_name()))
        .or_else(|| {
            registry
                .brokers()
                .find(|p| p.name == plugin_name)
                .map(|p| (&p.sandbox.programs, p.dir_name()))
        })
        .or_else(|| {
            registry
                .signers()
                .find(|p| p.name == plugin_name)
                .map(|p| (&p.sandbox.programs, p.dir_name()))
        })
    else {
        return ExitCode::SUCCESS;
    };
    let Ok(cwd) = std::env::current_dir() else {
        return ExitCode::SUCCESS;
    };
    let resolved = crate::config::load(&cwd);
    let Some(raw) = resolved.plugin.get(plugin_name) else {
        return ExitCode::SUCCESS;
    };
    let mut warnings = Vec::new();
    let wanted =
        crate::config::validated_programs(plugin_name, programs, &raw.programs, &mut warnings);
    for w in &warnings {
        diag::warn(w);
    }
    if wanted.is_empty() {
        return ExitCode::SUCCESS;
    }
    let Some(nix) = store::resolve_nix(Some(layout)) else {
        diag::error(&format!(
            "sbx: `[plugin.{}] programs` names a package to provision, but there is no nix to \
             build it with",
            plugin_name
        ));
        return ExitCode::FAILURE;
    };
    // The **global** channel pin, never a project's: this artifact outlives the directory the
    // install happened to be run from, so pinning it to that project's nixpkgs would make one
    // plugin's tool differ per project while a single out-link claims to hold all of them.
    let nixpkgs = match store::LockTarget::global(layout, resolved.nixpkgs_global.as_deref())
        .resolve(&nix, layout)
    {
        Ok(n) => n,
        Err(e) => {
            diag::error(&format!("sbx: cannot resolve the nixpkgs channel: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match plugins::programs::provision(layout, &nix, &nixpkgs, dir_name, &wanted) {
        Ok(done) => {
            for one in &done {
                match one {
                    plugins::programs::Provisioned::OnPath { path } => println!(
                        "  {}: already on PATH at {} (the configured package is unused)",
                        plugin_name,
                        path.display()
                    ),
                    plugins::programs::Provisioned::Built { program, path } => println!(
                        "  {}: provisioned `{program}` at {}",
                        plugin_name,
                        path.display()
                    ),
                }
            }
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&format!("sbx: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store <subcommand>`: the plugin stores. `list` shows the built-in (embedded)
/// store and every configured remote store; `add` configures and fetches a remote signed store
/// (a git repository whose catalogue is verified against a public key); `update` re-fetches one
/// or all configured stores (re-verifying against the pinned key and refusing a revision that
/// would roll back); `install` installs a plugin a configured store lists; `verify` confirms a
/// store's key against one obtained elsewhere; `info` details one configured store; `rm` removes
/// one.
fn plugins_store(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("list") | Some("ls") => plugins_store_list_cmd(&args[1..]),
        Some("add") => plugins_store_add(&args[1..]),
        Some("publish") => plugins_store_publish(&args[1..]),
        Some("update") => plugins_store_update(&args[1..]),
        Some("install") => plugins_store_install(&args[1..]),
        Some("verify") => plugins_store_verify(&args[1..]),
        Some("rekey") => plugins_store_rekey(&args[1..]),
        Some("info") => match crate::cli::reject_extra(
            &["plugins", "store", "info"],
            args.get(2..).unwrap_or(&[]),
        ) {
            Err(code) => code,
            Ok(()) => plugins_store_info(args.get(1).and_then(|a| a.to_str())),
        },
        Some("rm") => match crate::cli::reject_extra(
            &["plugins", "store", "rm"],
            args.get(2..).unwrap_or(&[]),
        ) {
            Err(code) => code,
            Ok(()) => plugins_store_remove(args.get(1).and_then(|a| a.to_str())),
        },
        // Unknown or no subcommand: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `sbx net`/`sbx config`.
        other => {
            if let Some(tok) = other {
                diag::error(&format!("sbx: plugins store: unknown subcommand {tok:?}"));
            }
            eprint!(
                "{}",
                help::page_usage(&["plugins", "store"]).unwrap_or_default()
            );
            ExitCode::from(2)
        }
    }
}

/// `sbx plugins store add --name <n> --url <git-url> (--key <hex|@file> | --trust)`: configure a
/// remote signed plugin store and fetch it for the first time. The repository is cloned, its
/// catalogue verified, and the verified result cached under the data directory. A deliberate user
/// act (an agent in the cage cannot run it). The store's trust anchor comes from exactly one of two
/// mutually exclusive flags: `--key` pins a public key the user obtained out of band (the strong
/// form), while `--trust` accepts the key the store ships on first use (weaker — no first-fetch
/// authenticity; the pinned key's fingerprint is printed for out-of-band verification). One of the
/// two is required: a store with no verifying key would be unsigned, refused fail-closed.
fn plugins_store_add(args: &[OsString]) -> ExitCode {
    let usage = format!(
        "sbx: usage: {}",
        help::synopsis_of(&["plugins", "store", "add"])
    );
    let (mut name, mut url, mut key) = (None, None, None);
    let mut trust = false;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        match flag.to_str() {
            Some("--name") => name = it.next().and_then(|v| v.to_str()),
            Some("--url") => url = it.next().and_then(|v| v.to_str()),
            Some("--key") => key = it.next().and_then(|v| v.to_str()),
            Some("--trust") => trust = true,
            other => {
                diag::error(&format!(
                    "sbx: unexpected argument '{}'",
                    other.unwrap_or("(non-UTF-8)")
                ));
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(name), Some(url)) = (name, url) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };

    // The trust anchor is exactly one of --key (pin a known key) or --trust (accept the shipped one).
    if key.is_some() && trust {
        diag::error(
            "sbx: --key and --trust are mutually exclusive: --key pins a key you supply, \
             --trust accepts the key the store ships",
        );
        return ExitCode::from(2);
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        diag::error("sbx: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };

    // No trust anchor: refuse, but refuse *usefully*. A store that ships a key is fetched into a
    // throwaway staging clone so the key can be shown before any decision — naming the two flags
    // without showing what `--trust` would pin put the key in front of the user only after it had
    // been trusted. No store is configured here: the fetch is discarded and the exit is non-zero.
    if key.is_none() && !trust {
        return report_missing_trust_anchor(&layout, name, url, &git);
    }

    let result = match key {
        Some(key) => {
            let pubkey = match stores::parse_pubkey_arg(key) {
                Ok(k) => k,
                Err(why) => {
                    diag::error(&format!("sbx: invalid --key: {why}"));
                    return ExitCode::from(2);
                }
            };
            stores::add(&layout, name, url, pubkey, &git)
        }
        None => stores::add_tofu(&layout, name, url, &git),
    };

    match result {
        Ok(added) => {
            // Trust on first use pinned a key sbx could not pre-verify: surface it loudly on stderr
            // (so it is never silently swallowed in a scripted run) with the full key for an
            // out-of-band comparison, while the configured-store report goes to stdout. Each line's
            // palette is decided from the stream it actually goes to.
            if added.tofu {
                let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
                eprintln!(
                    "{}",
                    render_store_tofu(&catalogue::to_hex(&added.pubkey), &added.name, &epal)
                );
            }
            let cat = &added.catalogue;
            let labels: Vec<(String, String)> = cat
                .plugins
                .values()
                .map(|e| (catalogue_label(e), e.version.clone()))
                .collect();
            let plugins: Vec<(&str, &str, &str)> = cat
                .plugins
                .keys()
                .zip(labels.iter())
                .map(|(p, (what, version))| (p.as_str(), what.as_str(), version.as_str()))
                .collect();
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            print!(
                "{}",
                render_store_configured(&added.name, cat.rev, &plugins, &pal)
            );
            if added.tofu {
                offer_verification(&layout, &added.name);
            }
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&format!("sbx: cannot add store: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// Ask, right after a trust-on-first-use add, whether the user already holds the store's key from
/// somewhere else — and confirm it on the spot if so, saving a second command. Only on a terminal
/// (both stdin and stderr): a scripted or piped run behaves exactly as it did, and the printed
/// `next:` step is the whole instruction there.
///
/// The question is deliberately about *where the key came from*, and it never offers the key just
/// printed as an answer: the point of confirming is a second source, so a prompt that invited a
/// paste of the store's own key would only make the caution disappear without making it false.
/// Declining is the default and costs nothing — the same command remains available later.
fn offer_verification(layout: &store::Layout, name: &str) {
    use std::io::{BufRead, Write};
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return;
    }
    let pal = style::Palette::for_stream(true);
    let (dim, r) = (pal.dim, pal.reset);
    eprint!("\n  do you have this key from a source this store does not control? {dim}[y/N]{r} ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return;
    }
    if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return;
    }
    eprint!("  paste it {dim}(hex, or @file — empty to skip){r}: ");
    let _ = std::io::stderr().flush();
    let mut key = String::new();
    if std::io::stdin().lock().read_line(&mut key).is_err() {
        return;
    }
    let key = key.trim();
    if key.is_empty() {
        return;
    }
    let pubkey = match stores::parse_pubkey_arg(key) {
        Ok(k) => k,
        Err(why) => {
            diag::error(&format!("sbx: invalid key: {why}"));
            diag::hint(
                "     the store is configured; confirm it later with `sbx plugins store verify`",
            );
            return;
        }
    };
    match stores::verify_key(layout, name, pubkey) {
        Ok(outcome) => eprintln!(
            "{}",
            render_store_verified(name, outcome == stores::Verified::AlreadyPinned, &pal)
        ),
        // A mismatch does not undo the add: a mistyped paste is far likelier than a substituted
        // store, and the resulting state (configured, still flagged) is exactly the one the add
        // produced. What it must not do is stay quiet about which way the disagreement could go.
        Err(why) => {
            diag::error(&format!("sbx: {why}"));
            diag::hint(&format!(
                "     if that key is the one this store should have, it is not this store — \
                 remove it with `sbx plugins store rm {name}`"
            ));
        }
    }
}

/// The refusal for `store add` with no `--key` and no `--trust`, made actionable: fetch the key the
/// store ships (into a staging clone that is thrown away) and print it with the two commands that
/// act on it. Always non-zero, and no store is configured whatever the probe finds — the fetch's
/// only trace is the data directory itself, created if missing as any staging verb would.
///
/// A store that ships no key, an unreachable URL, or an unusable repository each fall back to
/// naming the two flags: the probe is a convenience, so its failure must not obscure the actual
/// requirement (its reason is still reported, since it is usually the real problem).
fn report_missing_trust_anchor(
    layout: &store::Layout,
    name: &str,
    url: &str,
    git: &Path,
) -> ExitCode {
    match stores::shipped_pubkey(layout, url, git) {
        Ok(pubkey) => {
            let pal = style::Palette::for_stream(std::io::stderr().is_terminal());
            eprint!(
                "{}",
                render_store_needs_key(name, url, &catalogue::to_hex(&pubkey), &pal)
            );
        }
        Err(why) => {
            diag::error(&format!("sbx: {why}"));
            diag::error(
                "sbx: supply --key <hex|@file> to pin a known key, or --trust to accept the key \
                 the store ships on first use",
            );
        }
    }
    ExitCode::from(2)
}

/// `sbx plugins store publish <dir> --key <key-file> [--rev <n>]`: sign a directory of resolver
/// plugins into a store. It writes a `catalogue.toml` (pinning each plugin by a content digest), a
/// detached signature, the store's `pubkey`, and a `.gitattributes`; the operator then commits and
/// hosts the result. The producing counterpart of `store add` — an operator tool, never reachable
/// from a cage. The signing key is reused if the file exists (so the store keeps its identity
/// across publishes) or generated and persisted owner-only on first use; it is the store's secret
/// and never leaves the operator's host.
fn plugins_store_publish(args: &[OsString]) -> ExitCode {
    let usage = format!(
        "sbx: usage: {}",
        help::synopsis_of(&["plugins", "store", "publish"])
    );
    let mut dir: Option<&OsStr> = None;
    let mut key: Option<&OsStr> = None;
    let mut rev: Option<u64> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--key") => key = it.next().map(|v| v.as_os_str()),
            Some("--rev") => {
                let Some(value) = it.next().and_then(|v| v.to_str()) else {
                    eprintln!("{usage}");
                    return ExitCode::from(2);
                };
                match value.parse::<u64>() {
                    Ok(n) => rev = Some(n),
                    Err(_) => {
                        diag::error("sbx: --rev must be a non-negative integer");
                        return ExitCode::from(2);
                    }
                }
            }
            Some(flag) if flag.starts_with('-') => {
                diag::error(&format!("sbx: unexpected argument '{flag}'"));
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
            // Anything else (including a non-UTF-8 path) is the positional directory.
            _ => {
                if dir.is_some() {
                    diag::error("sbx: publish takes a single directory");
                    eprintln!("{usage}");
                    return ExitCode::from(2);
                }
                dir = Some(arg.as_os_str());
            }
        }
    }
    let (Some(dir), Some(key)) = (dir, key) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };

    match stores::publish(Path::new(dir), Path::new(key), rev) {
        Ok(published) => {
            // The key file just written or reused is the store's identity; warn loudly so it is
            // never treated as a throwaway. The public key, on stdout, is what consumers pin. Each
            // line's palette is decided from the stream it actually goes to.
            let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
            eprintln!("{}", render_publish_key_warning(Path::new(key), &epal));
            let pubkey = catalogue::to_hex(&published.pubkey);
            let plugins: Vec<(&str, &str)> = published
                .plugins
                .iter()
                .map(|(name, scheme)| (name.as_str(), scheme.as_str()))
                .collect();
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_published(published.rev, &plugins, &pubkey, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&format!("sbx: cannot publish store: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store update [name]`: re-fetch one configured remote store, or every configured
/// store when no name is given. Each re-fetch re-verifies the catalogue against the store's
/// pinned key (a compromised remote cannot rotate it) and refuses a revision that would roll
/// back, replacing the cache atomically. A deliberate user act. When updating all stores, a
/// failure on one is reported and the rest still run, with a non-zero exit if any failed.
fn plugins_store_update(args: &[OsString]) -> ExitCode {
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        diag::error("sbx: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };

    let names: Vec<String> = match args.first() {
        Some(arg) => {
            let Some(name) = arg.to_str() else {
                diag::error("sbx: a store name must be valid UTF-8");
                return ExitCode::from(2);
            };
            vec![name.to_string()]
        }
        None => {
            let all = stores::list(&layout);
            if all.is_empty() {
                let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
                let (dim, r) = (pal.dim, pal.reset);
                println!(
                    "{dim}no remote stores are configured \
                     (add one with: sbx plugins store add --name <n> --url <git-url> --key <hex>){r}"
                );
                return ExitCode::SUCCESS;
            }
            all
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut failed = false;
    for name in &names {
        match stores::update(&layout, name, &git) {
            Ok(u) => {
                println!(
                    "{}",
                    render_store_updated(
                        &u.name,
                        u.old_rev,
                        u.new_rev,
                        u.catalogue.plugins.len(),
                        &pal
                    )
                );
            }
            Err(why) => {
                diag::error(&format!("sbx: cannot update store '{name}': {why}"));
                failed = true;
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `sbx plugins store install <store> <plugin>`: install a resolver plugin a configured store
/// lists, by name. The store's cached catalogue (verified when the store was added or updated)
/// pins the plugin's content by hash; the install verifies that hash, reconciles the catalogue's
/// advertised name and scheme against the plugin's manifest, and places it exactly as a local
/// install would. A deliberate user act. Reads only the owner-only cache — no fetch, no network.
fn plugins_store_install(args: &[OsString]) -> ExitCode {
    let (Some(store_name), Some(plugin_name)) = (
        args.first().and_then(|a| a.to_str()),
        args.get(1).and_then(|a| a.to_str()),
    ) else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "store", "install"])
        ));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    match stores::install_plugin(&layout, store_name, plugin_name) {
        Ok(installed) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_plugin_installed(
                    &installed.name,
                    installed.scheme.as_deref(),
                    installed.kind,
                    Some(store_name),
                    &pal,
                )
            );
            provision_configured_programs(&layout, &installed.name)
        }
        Err(why) => {
            diag::error(&format!("sbx: cannot install plugin: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store info <name>`: a configured remote store in detail — its origin URL, the
/// pinned public key, the accepted catalogue revision, and each plugin it lists. Reads only the
/// owner-only cache (trusted by location): no fetch, no network.
fn plugins_store_info(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "store", "info"])
        ));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let cfg = match stores::read_configured(&layout, name) {
        Ok(cfg) => cfg,
        Err(why) => {
            diag::error(&format!("sbx: {why}"));
            return ExitCode::FAILURE;
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    println!("{h}store{r} {n}'{}'{r}", cfg.name);
    println!("  url:      {}", cfg.url);
    println!("  key:      {}", catalogue::to_hex(&cfg.pubkey));
    if cfg.tofu {
        // Three facts a user has to hold together, so none is left implied: the catalogue *is*
        // checked, that check cannot establish whose key it is, and the pin still has teeth.
        println!("  trust:    the key this store shipped, accepted on first use");
        println!("            the catalogue verifies against it on every fetch, but nothing");
        println!("            outside this store confirms the key is its author's");
        println!("            (a later key change is still refused)");
        println!(
            "            {dim}confirm it with: sbx plugins store verify {name} \
             --key <the key you obtained>{r}"
        );
    } else {
        println!("  trust:    a key you supplied out of band, pinned");
    }
    println!("  revision: {}", cfg.locked_rev);
    match stores::cached_catalogue(&layout, name) {
        Ok(cat) if cat.plugins.is_empty() => println!("  plugins:  (none)"),
        Ok(cat) => {
            // The same rows `store list` prints, including which are already in place and what
            // holds the name or scheme of those that are not — the catalogue alone cannot say.
            let installed = InstalledIndex::scan(&layout);
            println!("  plugins:");
            print_listed(
                &listed_from_catalogue(&cat),
                name,
                Some(&installed),
                false,
                "    ",
                &pal,
            );
            println!("  {dim}(install one with: sbx plugins store install {name} <plugin>){r}");
        }
        Err(why) => diag::warn(&format!("cannot read the cached catalogue: {why}")),
    }
    ExitCode::SUCCESS
}

/// `sbx plugins store verify <name> --key <hex|@file>`: confirm a configured store's pinned key
/// against one obtained from a source the store does not control. It is the way out of the
/// trust-on-first-use caution, which otherwise stands forever — a warning that can never be
/// resolved is one a user stops reading.
///
/// It changes no enforcement: the pinned key is untouched, and a fetch verifies the catalogue
/// against it either way. A mismatch is refused and changes nothing. No fetch, no network.
fn plugins_store_verify(args: &[OsString]) -> ExitCode {
    let usage = format!(
        "sbx: usage: {}",
        help::synopsis_of(&["plugins", "store", "verify"])
    );
    let (mut name, mut key) = (None, None);
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.to_str() {
            Some("--key") => key = it.next().and_then(|v| v.to_str()),
            Some(other) if !other.starts_with("--") && name.is_none() => name = Some(other),
            other => {
                diag::error(&format!(
                    "sbx: unexpected argument '{}'",
                    other.unwrap_or("(non-UTF-8)")
                ));
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(name), Some(key)) = (name, key) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let pubkey = match stores::parse_pubkey_arg(key) {
        Ok(k) => k,
        Err(why) => {
            diag::error(&format!("sbx: invalid --key: {why}"));
            return ExitCode::from(2);
        }
    };
    match stores::verify_key(&layout, name, pubkey) {
        Ok(outcome) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_store_verified(name, outcome == stores::Verified::AlreadyPinned, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&format!("sbx: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store rekey <name> (--key <hex|@file> | --trust) [--yes]`: replace the key pinned
/// for a configured store, for a store that legitimately rotated its signing key — which `update`
/// refuses, correctly, since a pinned key is the whole point.
///
/// Loud by construction: the alert names both keys and what the exchange means, and a terminal is
/// asked to confirm. Without a terminal it refuses unless `--yes` says the operator meant it, so
/// nothing rotates a signing identity unattended by accident. `--trust` re-accepts whatever the
/// store now ships, which is the weak form and is flagged as such afterwards.
fn plugins_store_rekey(args: &[OsString]) -> ExitCode {
    let usage = format!(
        "sbx: usage: {}",
        help::synopsis_of(&["plugins", "store", "rekey"])
    );
    let (mut name, mut key) = (None, None);
    let (mut trust, mut yes) = (false, false);
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.to_str() {
            Some("--key") => key = it.next().and_then(|v| v.to_str()),
            Some("--trust") => trust = true,
            Some("--yes") => yes = true,
            Some(other) if !other.starts_with('-') && name.is_none() => name = Some(other),
            other => {
                diag::error(&format!(
                    "sbx: unexpected argument '{}'",
                    other.unwrap_or("(non-UTF-8)")
                ));
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    if key.is_some() && trust {
        diag::error(
            "sbx: --key and --trust are mutually exclusive: --key pins a key you supply, \
             --trust re-accepts the one the store now ships",
        );
        return ExitCode::from(2);
    }
    if key.is_none() && !trust {
        diag::error(
            "sbx: supply --key <hex|@file> with the new key, or --trust to re-accept the one \
             the store now ships (weaker)",
        );
        return ExitCode::from(2);
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        diag::error("sbx: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };
    let cfg = match stores::read_configured(&layout, name) {
        Ok(cfg) => cfg,
        Err(why) => {
            diag::error(&format!("sbx: {why}"));
            return ExitCode::FAILURE;
        }
    };
    let choice = match key {
        Some(k) => match stores::parse_pubkey_arg(k) {
            Ok(k) => stores::TrustChoice::Pinned(k),
            Err(why) => {
                diag::error(&format!("sbx: invalid --key: {why}"));
                return ExitCode::from(2);
            }
        },
        None => stores::TrustChoice::Tofu,
    };

    // The alert precedes the fetch: what it describes — replacing this store's signing identity —
    // is decided here, whatever the new key turns out to be.
    let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
    let new_shown = match &choice {
        stores::TrustChoice::Pinned(k) => catalogue::to_hex(k),
        stores::TrustChoice::Tofu => "(whatever key the store now ships)".to_string(),
    };
    eprint!(
        "{}",
        render_store_rekey_alert(name, &catalogue::to_hex(&cfg.pubkey), &new_shown, &epal)
    );
    if !yes && !confirm_rotation() {
        diag::error("sbx: not rotating the store's key");
        return ExitCode::FAILURE;
    }

    match stores::rekey(&layout, name, choice, &git) {
        Ok(done) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_store_rekeyed(
                    &done.name,
                    &catalogue::to_hex(&done.old_pubkey),
                    &catalogue::to_hex(&done.new_pubkey),
                    done.tofu,
                    done.rev,
                    done.catalogue.plugins.len(),
                    &pal
                )
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&format!("sbx: cannot rotate the store's key: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// Ask a terminal to confirm a key rotation. Without a terminal there is nobody to ask, and an
/// unattended run must not rotate a signing identity on its own — `--yes` is how a script says it
/// meant to. Anything but an explicit yes is a no.
fn confirm_rotation() -> bool {
    use std::io::{BufRead, Write};
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        diag::hint("     pass --yes if this rotation is intentional (no terminal to confirm at)");
        return false;
    }
    eprint!("  rotate this store's key? [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `sbx plugins store rm <name>`: remove a configured remote store from the cache. Host-level,
/// like `add`; refuses a name that is not configured.
fn plugins_store_remove(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "store", "rm"])
        ));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    match stores::remove(&layout, name) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(Some("store"), name, &pal));
            ExitCode::SUCCESS
        }
        Err(why) => {
            diag::error(&format!("sbx: cannot remove store: {why}"));
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store list`: every configured store with its accepted revision, expanded to the
/// plugins it lists — each with its scheme, version, description, and whether it is already
/// installed from that store. No fetch, no network.
fn plugins_store_list_cmd(args: &[OsString]) -> ExitCode {
    let (only_installed, only_store) = match parse_store_list_args(args) {
        Ok(parsed) => parsed,
        Err(bad) => {
            diag::error(&format!("sbx: unexpected argument '{bad}'"));
            eprintln!(
                "sbx: usage: {}",
                help::synopsis_of(&["plugins", "store", "list"])
            );
            return ExitCode::from(2);
        }
    };
    plugins_store_list(only_installed, only_store.as_deref())
}

/// Split `store list`'s arguments into (`--installed`, the store to restrict to), or the first
/// argument that is neither. Pure, so the accepted shapes are pinned without a data directory.
///
/// A bare word names the store. Listing every configured store stays the default, but once there
/// is more than one that stops answering "what does *this* one offer" without the reader
/// filtering by eye. A second bare word is an error rather than a silent overwrite: it means the
/// caller expected something the verb does not do.
fn parse_store_list_args(args: &[OsString]) -> Result<(bool, Option<String>), String> {
    let mut only_installed = false;
    let mut only_store: Option<String> = None;
    for a in args {
        match a.to_str() {
            Some("--installed") => only_installed = true,
            Some(word) if !word.starts_with('-') && only_store.is_none() => {
                only_store = Some(word.to_string());
            }
            other => return Err(other.unwrap_or("(non-UTF-8)").to_string()),
        }
    }
    Ok((only_installed, only_store))
}

/// One listed plugin: the shape `store list` and `store info` both reduce a catalogue to.
/// Rendering them through one function keeps the two listings identical in what they show and in
/// what `--installed` means.
struct Listed<'a> {
    name: &'a str,
    /// What kind of plugin the source lists. It decides how the entry names itself, since only one
    /// kind has a namespace to name.
    kind: crate::plugins::PluginKind,
    /// The scheme, for a resolver. `None` for a broker, which claims none.
    scheme: Option<&'a str>,
    version: Option<&'a str>,
    description: Option<&'a str>,
    /// The digest the catalogue pins for this entry, when it comes from one. It is the exact
    /// artifact the store lists, so comparing it against what an install recorded answers "is what
    /// I have the build this store offers" without reading a version string at all.
    sha256: Option<&'a str>,
}

/// Print one source's entries at `indent`, keeping only the installed ones when asked, and return
/// how many were shown — so the caller can say a source has nothing installed rather than leaving a
/// bare heading. Every entry carries the marker that says whether it is in place, or what holds its
/// name or scheme.
fn print_listed(
    entries: &[Listed],
    store: &str,
    installed: Option<&InstalledIndex>,
    only_installed: bool,
    indent: &str,
    pal: &style::Palette,
) -> usize {
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    let mut shown = 0;
    for e in entries {
        if only_installed && !installed.is_some_and(|i| i.installed_from(e.name, store)) {
            continue;
        }
        shown += 1;
        print!(
            "{indent}{n}{}{r}  {dim}({}){r}",
            e.name,
            match e.scheme {
                Some(scheme) => format!("{scheme}://"),
                None => e.kind.token().to_string(),
            }
        );
        if let Some(v) = e.version.filter(|v| !v.is_empty()) {
            print!("  v{v}");
        }
        if let Some(i) = installed {
            print!(
                "{}",
                i.marker(e.name, e.scheme, e.version, e.sha256, store, pal)
            );
        }
        println!();
        if let Some(d) = e.description.filter(|d| !d.is_empty()) {
            println!("{indent}  {dim}{d}{r}");
        }
    }
    shown
}

/// The line closing a source's block: how to install from it, or — under `--installed`, with
/// nothing shown — that nothing from it is in place. One of the two always prints, so a source is
/// never left as a heading with no explanation.
fn print_source_footer(
    shown: usize,
    only_installed: bool,
    indent: &str,
    what: &str,
    install_cmd: &str,
    pal: &style::Palette,
) {
    let (dim, r) = (pal.dim, pal.reset);
    if !only_installed {
        println!("{indent}{dim}(install one with: {install_cmd}){r}");
    } else if shown == 0 {
        println!("{indent}{dim}(nothing from {what} is installed){r}");
    }
}

/// How a catalogue entry names its namespace: the scheme a resolver answers for, or the type of a
/// plugin that claims none. One place, so a listing and a confirmation never spell it differently.
fn catalogue_label(e: &catalogue::CatalogueEntry) -> String {
    match &e.scheme {
        Some(scheme) => format!("{scheme}://"),
        None => e.kind.token().to_string(),
    }
}

/// The entries a remote catalogue lists, in the shared shape.
fn listed_from_catalogue(cat: &catalogue::Catalogue) -> Vec<Listed<'_>> {
    cat.plugins
        .iter()
        .map(|(name, e)| Listed {
            name,
            kind: e.kind,
            scheme: e.scheme.as_deref(),
            version: Some(&e.version),
            description: Some(&e.description),
            sha256: Some(&e.sha256),
        })
        .collect()
}

/// The body of `store list`. `only_installed` keeps just the entries in place from the source being
/// listed, for answering "what do I actually have from here" without reading past everything on
/// offer. The sources themselves are still all shown: a store with nothing installed says so,
/// rather than vanishing and leaving the user unsure whether it is configured at all.
fn plugins_store_list(only_installed: bool, only_store: Option<&str>) -> ExitCode {
    let layout = store::Layout::from_env();
    // Without a data directory nothing is installed as far as this listing can tell, so every entry
    // renders unmarked rather than the command failing on an inspection verb.
    let installed = layout.as_ref().map(InstalledIndex::scan);
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);

    // Configured stores, read from their owner-only caches (trusted by location). Each is expanded
    // down to its plugins: a bare count would say a store has something to offer without saying
    // what, which is the one question this command exists to answer.
    let mut names = layout.as_ref().map(stores::list).unwrap_or_default();
    // A name that matches nothing is refused rather than rendered as an empty listing: "no such
    // store" and "this store lists nothing" are different answers, and only one of them is a typo.
    if let Some(want) = only_store {
        if !names.iter().any(|n| n == want) {
            diag::error(&format!("sbx: no configured plugin store named '{want}'"));
            if !names.is_empty() {
                eprintln!("sbx: configured stores: {}", names.join(", "));
            }
            return ExitCode::from(2);
        }
        names.retain(|n| n == want);
    }
    if names.is_empty() {
        println!("{h}configured plugin stores:{r} (none)");
        println!(
            "  {dim}(add one with: sbx plugins store add --name <n> --url <git-url> \
             --key <hex>){r}"
        );
        return ExitCode::SUCCESS;
    }
    let Some(layout) = layout.as_ref() else {
        return ExitCode::SUCCESS;
    };
    println!("{h}configured plugin stores{r} (update with: sbx plugins store update <name>):");
    for name in &names {
        let cfg = match stores::read_configured(layout, name) {
            Ok(cfg) => cfg,
            Err(why) => {
                diag::warn(&format!("store '{name}': {why}"));
                continue;
            }
        };
        let catalogue = stores::cached_catalogue(layout, name);
        let detail = match &catalogue {
            Ok(cat) => {
                let count = cat.plugins.len();
                format!("{count} plugin{}", if count == 1 { "" } else { "s" })
            }
            Err(_) => "catalogue unreadable".to_string(),
        };
        // What is missing is a *second source* for the key, not verification as such: the catalogue
        // is signature-checked against this key on every fetch. The marker states the gap; the line
        // under it names the command that closes it, because a flag with no way out is one a user
        // learns to scroll past. A key the user supplied needs neither.
        let marker = if cfg.tofu {
            format!("  {}[key not confirmed elsewhere]{r}", pal.warn)
        } else {
            String::new()
        };
        println!(
            "  {n}{name}{r}  {dim}(rev {}, {detail}){r}{marker}",
            cfg.locked_rev
        );
        if cfg.tofu {
            println!(
                "    {dim}(confirm its key with: sbx plugins store verify {name} \
                 --key <the key you obtained>){r}"
            );
        }
        match &catalogue {
            Ok(cat) => {
                let shown = print_listed(
                    &listed_from_catalogue(cat),
                    name,
                    installed.as_ref(),
                    only_installed,
                    "    ",
                    &pal,
                );
                print_source_footer(
                    shown,
                    only_installed,
                    "    ",
                    "this store",
                    &format!("sbx plugins store install {name} <plugin>"),
                    &pal,
                );
            }
            Err(why) => diag::warn(&format!("store '{name}': {why}")),
        }
    }
    ExitCode::SUCCESS
}

/// `sbx plugins rm <name>...`: remove installed resolver plugins by name (the token `list` shows).
/// Host-level, like `install`; refuses an unsafe name or a directory that is not a plugin.
///
/// Several names may be given in one call, like `sbx app rm`. Each is removed independently, so one
/// name failing (not installed, or a directory carrying no `plugin.toml`) leaves the others removed
/// and only colours the exit code. Every name is validated *before* the first removal — a removal is
/// destructive, so a typo at the end of the list must not cost the plugins before it — which is also
/// what keeps an unsafe name away from the data directory it would be joined to.
fn plugins_remove(args: &[OsString]) -> ExitCode {
    let mut names: Vec<&str> = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some(tok) if tok.starts_with('-') => {
                diag::error(&format!("sbx: plugins rm: unknown option `{tok}`"));
                diag::error(&format!(
                    "sbx: usage: {}",
                    help::synopsis_of(&["plugins", "rm"])
                ));
                return ExitCode::from(2);
            }
            Some(tok) => names.push(tok),
            None => {
                diag::error("sbx: plugins rm: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    if names.is_empty() {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "rm"])
        ));
        return ExitCode::from(2);
    }
    for name in &names {
        if let Err(why) = plugins::validate_install_name(name) {
            diag::error(&format!("sbx: cannot remove plugin: {why}"));
            return ExitCode::FAILURE;
        }
    }
    crate::cli::dedupe_names(&mut names);
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut had_error = false;
    for name in &names {
        match plugins::remove(&layout, name) {
            Ok(()) => println!("{}", render_removed(None, name, &pal)),
            Err(why) => {
                diag::error(&format!("sbx: cannot remove plugin: {why}"));
                had_error = true;
            }
        }
    }
    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// What an installed plugin's store says about it now — the one comparison `upgrade` and the store
/// listings both make. Everything is read from the *cached* catalogue, so it is only as current as
/// the last `sbx plugins store update`; the revision travels with the verdict so no output can
/// claim currency without saying against what.
struct StoreVerdict {
    store: String,
    rev: u64,
    listed_version: String,
    /// `false` when the catalogue pins a different tree than the one that was installed.
    current: bool,
    /// Why no comparison was possible, when none was.
    unknown: Option<String>,
}

/// Ask a plugin's origin store what it lists for it now.
fn store_verdict(
    layout: &store::Layout,
    dir_name: &str,
    installed: &InstalledPlugin,
) -> Option<StoreVerdict> {
    let plugins::origin::Origin::Store { store: name, .. } = &installed.origin else {
        return None;
    };
    let unknown = |why: String| {
        Some(StoreVerdict {
            store: name.clone(),
            rev: 0,
            listed_version: String::new(),
            current: false,
            unknown: Some(why),
        })
    };
    let catalogue = match stores::cached_catalogue(layout, name) {
        Ok(c) => c,
        Err(why) => return unknown(format!("its store's catalogue cannot be read ({why})")),
    };
    let Some(entry) = catalogue.plugins.get(dir_name) else {
        return unknown(format!(
            "store '{name}' no longer lists a plugin named `{dir_name}`"
        ));
    };
    let Some(ours) = installed.digest.as_deref() else {
        return unknown(
            "no digest was recorded when it was installed — reinstall it to make it comparable"
                .to_string(),
        );
    };
    Some(StoreVerdict {
        store: name.clone(),
        rev: catalogue.rev,
        listed_version: entry.version.clone(),
        current: entry.sha256 == ours,
        unknown: None,
    })
}

/// `sbx plugins upgrade [<name>] [--dry-run]`: replace installed plugins with what their store
/// lists now. Bare, it considers every plugin installed from a store, like `store update`.
///
/// The decision is the **digest**, not the version string: the catalogue pins the tree it offers
/// and the install recorded the tree it placed, so "you already have this" is a fact rather than a
/// version comparison's guess — and a republish under an unchanged version is still seen.
///
/// The replacement keeps the installed plugin until the new tree is in place, so an upgrade that
/// fails leaves what was there. That is the whole reason this is a verb and not documentation
/// telling a user to `rm` and install again: `rm` deletes first, and a failure after it leaves
/// nothing installed.
fn plugins_upgrade(args: &[OsString]) -> ExitCode {
    let mut name: Option<&str> = None;
    let mut dry_run = false;
    for a in args {
        match a.to_str() {
            Some("--dry-run") => dry_run = true,
            Some(tok) if !tok.starts_with('-') && name.is_none() => name = Some(tok),
            other => {
                diag::error(&format!(
                    "sbx: plugins upgrade: unexpected argument {:?}",
                    other.unwrap_or("(not utf-8)")
                ));
                diag::note(&format!(
                    "usage: {}",
                    help::synopsis_of(&["plugins", "upgrade"])
                ));
                return ExitCode::from(2);
            }
        }
    }
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let index = InstalledIndex::scan(&layout);
    let targets: Vec<String> = match name {
        Some(one) => {
            if !index.by_name.contains_key(one) {
                diag::error(&format!("sbx: no installed plugin named `{one}`"));
                return ExitCode::from(2);
            }
            vec![one.to_string()]
        }
        None => index.by_name.keys().cloned().collect(),
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (n, dim, ok, warn, r) = (pal.name, pal.dim, pal.ok, pal.warn, pal.reset);

    let mut stale: Vec<(String, StoreVerdict)> = Vec::new();
    for dir_name in &targets {
        let Some(installed) = index.by_name.get(dir_name) else {
            continue;
        };
        match store_verdict(&layout, dir_name, installed) {
            // Not from a store: there is nothing to upgrade *from*. Named only when it was asked
            // for by name, so a bare run is not a list of things it will never do.
            None => {
                if name.is_some() {
                    println!(
                        "  {n}{dir_name}{r}  {dim}installed from {} — no store to upgrade from{r}",
                        installed.origin.short()
                    );
                }
            }
            Some(v) if v.unknown.is_some() => {
                println!(
                    "  {n}{dir_name}{r}  {warn}cannot be compared{r} {dim}({}){r}",
                    v.unknown.as_deref().unwrap_or_default()
                );
            }
            Some(v) if v.current => {
                println!(
                    "  {n}{dir_name}{r}  {ok}already the build store '{}' lists{r} {dim}(rev {}){r}",
                    v.store, v.rev
                );
            }
            Some(v) => stale.push((dir_name.clone(), v)),
        }
    }

    if stale.is_empty() {
        // The claim is only ever about the cached catalogue, so it says so rather than implying a
        // freshness nothing checked.
        println!(
            "{dim}(compared against the cached catalogues — `sbx plugins store update` re-fetches them){r}"
        );
        return ExitCode::SUCCESS;
    }

    let mut failed = 0usize;
    for (dir_name, v) in &stale {
        let have = index
            .by_name
            .get(dir_name)
            .and_then(|p| p.version.as_deref())
            .unwrap_or("")
            .trim();
        let wording = drift_wording(have, v.listed_version.trim());
        if dry_run {
            println!(
                "  {n}{dir_name}{r}  {warn}{wording}{r} {dim}(store '{}', rev {}){r}",
                v.store, v.rev
            );
            continue;
        }
        match stores::upgrade_plugin(&layout, &v.store, dir_name) {
            // Past tense needs its own sentence: the pending wording ("update available: …") reads
            // as a thing still to do once it has been done.
            Ok(_) => {
                let listed = v.listed_version.trim();
                let moved = if have.is_empty() || listed.is_empty() {
                    format!("from store '{}'", v.store)
                } else if have == listed {
                    format!("to a new build of v{listed}")
                } else {
                    format!("v{have} → v{listed}")
                };
                println!("  {n}{dir_name}{r}  {ok}upgraded{r} {dim}({moved}){r}");
            }
            Err(why) => {
                failed += 1;
                diag::error(&format!("sbx: cannot upgrade `{dir_name}`: {why}"));
            }
        }
    }
    if dry_run {
        println!(
            "{dim}(run without --dry-run to apply; compared against the cached catalogues){r}"
        );
    }
    if failed > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// `sbx plugins verify [<name>]`: re-hash one installed plugin's tree — or every one — and compare
/// it against the digest recorded when it was placed. On demand only: it reads every file of every
/// plugin, which is why it is a verb of its own and never runs on the launch path.
///
/// Exit is non-zero when a tree **changed**. A plugin with no recorded digest is reported plainly
/// and does not fail the command: nothing was attested, which is a different answer from "this was
/// tampered with" and calls for a different action (reinstall, which records one).
fn plugins_verify(name: Option<&str>) -> ExitCode {
    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let index = InstalledIndex::scan(&layout);
    let names: Vec<String> = match name {
        Some(one) => {
            if !index.by_name.contains_key(one) {
                // A usage exit, not a verification failure: this command promises that non-zero
                // *one* means "a tree changed", so a name that names nothing must not be able to
                // impersonate that answer for a script branching on the status.
                diag::error(&format!("sbx: no installed plugin named `{one}`"));
                return ExitCode::from(2);
            }
            vec![one.to_string()]
        }
        None => index.by_name.keys().cloned().collect(),
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (n, dim, ok, warn, err, r) = (pal.name, pal.dim, pal.ok, pal.warn, pal.err, pal.reset);
    if names.is_empty() {
        println!("no installed resolver plugins to verify");
        return ExitCode::SUCCESS;
    }
    let mut changed = 0usize;
    for dir_name in &names {
        let verdict = plugins::integrity(&layout, dir_name);
        let line = match &verdict {
            plugins::Integrity::Intact => {
                format!("{ok}unchanged since install{r}")
            }
            plugins::Integrity::Modified => {
                changed += 1;
                format!("{err}MODIFIED since install{r}")
            }
            plugins::Integrity::Unrecorded => format!(
                "{warn}no digest recorded{r} {dim}(installed before sbx recorded one, or placed \
                 by hand — reinstall to record one){r}"
            ),
            plugins::Integrity::Unreadable(why) => {
                changed += 1;
                format!("{err}cannot be hashed{r} {dim}({why}){r}")
            }
        };
        println!("  {n}{dir_name}{r}  {line}");
        if verdict == plugins::Integrity::Modified {
            println!(
                "    {dim}from: {}{r}",
                plugins::origin::read(&layout, dir_name).label()
            );
        }
    }
    if changed == 0 {
        return ExitCode::SUCCESS;
    }
    // What this does and does not mean, stated where the user reads the bad news — an integrity
    // indicator mistaken for a boundary is worse than none.
    diag::error(&format!(
        "sbx: {changed} plugin{} no longer match{} what was installed — reinstall to restore a \
         known tree (`sbx plugins rm <name>`, then install it again). This detects drift, not an \
         attacker: the record lives in the same owner-only directory as the plugin",
        if changed == 1 { "" } else { "s" },
        if changed == 1 { "es" } else { "" },
    ));
    ExitCode::FAILURE
}

/// `sbx plugins info <scheme>`: the full manifest and sandbox grant of the plugin claiming
/// `scheme`. A built-in scheme is reported as such (not an error); an unknown scheme is a
/// non-zero "no such plugin". Like `list`, host-level and side-effect-free.
fn plugins_info(scheme: Option<&str>) -> ExitCode {
    let Some(scheme) = scheme else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "info"])
        ));
        return ExitCode::from(2);
    };
    if plugins::builtin_schemes().contains(&scheme) {
        println!("{scheme}: a built-in resolver (compiled into sbx, not a plugin)");
        return ExitCode::SUCCESS;
    }
    let Some((layout, registry, warnings)) = load_plugin_registry() else {
        diag::error(
            "sbx: cannot locate the data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    // A broker and a signer claim no scheme, so each is looked up by the name it is registered
    // under — the same token `sbx plugins list` prints, and the one a config names. Tried before
    // the scheme index reports a miss, because a plugin that is listed and cannot be inspected
    // reads as a plugin that is not really installed. One name can reach only one of them: the
    // registry disables both when two plugins claim it.
    if let Some(b) = registry.broker(scheme) {
        return info_broker(&layout, b, &pal);
    }
    if let Some(s) = registry.signer(scheme) {
        return info_signer(&layout, s, &pal);
    }
    let Some(p) = registry.resolver(scheme) else {
        // A key can be absent for four different reasons, and `info <key>` is exactly the command a
        // user runs to learn which: nothing claims it, several plugins claim it as a scheme or
        // several claim it as a name (the answer is the conflict itself, so it is reported in
        // full), or the one that does is malformed (that reason lives in the load warnings,
        // re-emitted here).
        if let Some(claimants) = registry.conflict(scheme) {
            print_conflicts(&layout, &registry, Some(scheme), &pal);
            diag::error(&format!(
                "sbx: the scheme '{scheme}' is claimed by {} installed plugins and resolves to \
                 nothing until exactly one remains",
                claimants.len()
            ));
            return ExitCode::FAILURE;
        }
        if let Some(claimants) = registry.name_conflict(scheme) {
            print_conflicts(&layout, &registry, Some(scheme), &pal);
            diag::error(&format!(
                "sbx: the name '{scheme}' is claimed by {} installed plugins and reaches none of \
                 them until exactly one remains",
                claimants.len()
            ));
            return ExitCode::FAILURE;
        }
        for w in &warnings {
            diag::warn(w);
        }
        diag::error(&format!(
            "sbx: no installed resolver plugin claims the scheme '{scheme}'"
        ));
        return ExitCode::FAILURE;
    };
    let (h, n, err, r) = (pal.head, pal.name, pal.err, pal.reset);
    println!("{h}resolver plugin:{r} {n}{}{r}", p.name);
    println!("  scheme:      {n}{}://{r}", p.scheme);
    print_about(
        &layout,
        About {
            version: p.version.as_deref(),
            description: p.description.as_deref(),
            dir_name: p.dir_name(),
            exec: &p.exec,
        },
        p.check_exec(),
        &pal,
    );
    println!("  sandbox grant:");
    println!("    network:     {}", p.sandbox.network);
    // Named even when absent, and named *loudly* when present: every other line of this grant is
    // read-only, so the one that is not is the line a reader most needs to find.
    match p.sandbox.state {
        true => println!(
            "    state:       yes — a private writable directory that survives the run ({})",
            crate::sandbox::resolver::state_dir(p)
                .unwrap_or_default()
                .display()
        ),
        false => println!("    state:       no (nothing the plugin writes outlives the run)"),
    }
    print_grant_programs(&layout, p, err, r);
    print_grant_paths("allow_paths", &p.sandbox.allow_paths);
    print_grant_masks(&p.sandbox.mask_paths);
    print_grant_env("allow_env", &p.sandbox.allow_env);
    print_grant_env_paths(&p.sandbox.allow_env_paths, err, r);
    print_grant_brokers(&p.sandbox.brokers);
    // The closure, when a declared program lives in the nix store. Shown because it is the one
    // part of the grant no manifest names, so it would otherwise be the largest thing a launch
    // binds and the only one a reader cannot see coming.
    if let Some(n) = crate::sandbox::resolver::nix_closure_paths(&p.sandbox.programs) {
        println!("    nix closure: {n} store paths, so a store-installed program can run");
    }
    print_plugin_host_config(&p.name, &p.sandbox, err, r);
    ExitCode::SUCCESS
}

/// What an installed plugin says about itself, whatever its type: the manifest's display fields,
/// plus the two facts only the data directory holds — where it came from and whether it still
/// matches what was installed.
struct About<'a> {
    version: Option<&'a str>,
    description: Option<&'a str>,
    /// The directory name, which is what the origin record and the digest are filed under. It may
    /// differ from the manifest's `name` for a hand-placed tree, and these two lines are about the
    /// tree on disk rather than about what the manifest calls itself.
    dir_name: &'a str,
    exec: &'a Path,
}

/// The `sbx plugins info` block every type shares, under the line naming the plugin.
///
/// Unlike `list`, every integrity state is named here: `info` is the detail view, and "this matches
/// what was installed" is exactly the reassurance a user opens it for.
fn print_about(
    layout: &store::Layout,
    about: About<'_>,
    runnable: Result<(), String>,
    pal: &style::Palette,
) {
    let (err, r) = (pal.err, pal.reset);
    println!("  version:     {}", about.version.unwrap_or("(unset)"));
    println!("  description: {}", about.description.unwrap_or("(none)"));
    println!(
        "  origin:      {}",
        plugins::origin::read(layout, about.dir_name).label()
    );
    println!(
        "  integrity:   {}",
        match plugins::integrity(layout, about.dir_name) {
            plugins::Integrity::Intact => "unchanged since install".to_string(),
            plugins::Integrity::Modified =>
                format!("{err}MODIFIED since install{r} (verify with: sbx plugins verify)"),
            plugins::Integrity::Unrecorded =>
                "no digest recorded (installed before sbx recorded one, or placed by hand)"
                    .to_string(),
            plugins::Integrity::Unreadable(why) => format!("{err}cannot be hashed{r} ({why})"),
        }
    );
    print!("  exec:        {}", about.exec.display());
    match runnable {
        Ok(()) => println!(),
        Err(why) => println!("  {err}[not runnable: {why}]{r}"),
    }
}

/// One `sbx plugins info` grant line per declared program, resolved **here and now** against the
/// same `PATH` a launch would search, so the listing answers the question a user actually has:
/// will this plugin find its tool on *this* machine, and which one will it get. A program that
/// resolves to nothing is flagged rather than merely listed — it is the difference between a
/// plugin that works and one that fails at the first secret.
/// Four states are possible and each has a different remedy, so each is said rather than collapsed
/// into "found" and "missing": on `PATH` (any configured package is inert); not on `PATH` but
/// already provisioned; not on `PATH`, configured, and **not yet built** — the state a user reaches
/// by adding `programs` after installing, whose remedy is to re-run the install; and neither, which
/// is what fails a launch. Nothing here builds: the answer must be free to ask.
fn print_grant_programs(
    layout: &store::Layout,
    plugin: &crate::plugins::ResolverPlugin,
    err: &str,
    r: &str,
) {
    if plugin.sandbox.programs.is_empty() {
        println!("    programs:    (none)");
        return;
    }
    let configured: std::collections::BTreeMap<String, String> = std::env::current_dir()
        .ok()
        .map(|cwd| crate::config::load(&cwd))
        .and_then(|c| c.plugin.get(&plugin.name).cloned())
        .map(|raw| {
            let mut ignored = Vec::new();
            crate::config::validated_programs(
                &plugin.name,
                &plugin.sandbox.programs,
                &raw.programs,
                &mut ignored,
            )
            .into_iter()
            .collect()
        })
        .unwrap_or_default();

    let shown = plugin
        .sandbox
        .programs
        .iter()
        .map(|name| {
            if let Some(path) = crate::sandbox::resolver::locate_program(name) {
                let mut line = format!("{name} -> {}", path.display());
                if configured.contains_key(name) {
                    line.push_str(" (on PATH, so the configured package is unused)");
                }
                return line;
            }
            if let Some(path) = plugins::programs::provisioned(layout, plugin.dir_name(), name) {
                return format!("{name} -> {} (provisioned)", path.display());
            }
            match configured.get(name) {
                Some(attr) => format!(
                    "{name} -> {err}nix:{attr} configured but not built{r} (run: sbx plugins \
                     install {})",
                    plugin.dir_name()
                ),
                None => format!("{name} -> {err}not on PATH{r}"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    println!("    programs:    {shown}");
}

/// One `sbx plugins info` grant line listing read-only path binds, or `(none)`.
fn print_grant_paths(label: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        println!("    {label}:  (none)");
    } else {
        let joined = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("    {label}:  {joined}");
    }
}

/// One `sbx plugins info` grant line listing the paths hidden inside the grant, or `(none)`.
///
/// Printed right under `allow_paths` because it only ever reads against it: a mask is a subtraction
/// from a path the line above granted, and the two apart would leave a reader summing them by hand.
/// Always printed, even empty — a grant block whose shape changes per plugin cannot be compared
/// across two of them, and "nothing is hidden here" is itself the answer to a fair question.
fn print_grant_masks(paths: &[PathBuf]) {
    if paths.is_empty() {
        println!("    mask_paths:   (none)");
        return;
    }
    let joined = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    println!("    mask_paths:   {joined} (hidden inside the grant above)");
}

/// One `sbx plugins info` grant line listing passed-through environment variables, or `(none)`.
fn print_grant_env(label: &str, keys: &[String]) {
    if keys.is_empty() {
        println!("    {label}:    (none)");
    } else {
        println!("    {label}:    {}", keys.join(", "));
    }
}

/// `sbx plugins info <name>` for a broker plugin.
///
/// The same detail view a resolver gets, minus the scheme it has none of, plus the protocol facts
/// that decide what a launch does with it. Kept beside the resolver's rather than merged with it:
/// the two share an identity and a grant, and nothing else — a single function would spend its
/// length saying which half applies.
fn info_broker(
    layout: &crate::store::Layout,
    p: &crate::plugins::broker::BrokerPlugin,
    pal: &style::Palette,
) -> ExitCode {
    let (h, n, err, r) = (pal.head, pal.name, pal.err, pal.reset);
    println!("{h}broker plugin:{r} {n}{}{r}", p.name);
    print_about(
        layout,
        About {
            version: p.version.as_deref(),
            description: p.description.as_deref(),
            dir_name: p.dir_name(),
            exec: &p.exec,
        },
        p.check_exec(),
        pal,
    );
    println!("  protocol:");
    println!("    framing:     {}", p.broker.framing.token());
    println!("    max frame:   {} bytes", p.broker.max_frame);
    println!(
        "    host wait:   {} seconds for one exchange",
        p.broker.host_deadline.as_secs()
    );
    println!("    found in the cage: {}", how_the_cage_finds_it(p));
    println!(
        "    greeting:    {}",
        match p.broker.host_greets {
            true => "the host resource speaks first",
            false => "the cage speaks first",
        }
    );
    println!(
        "    replies:     {}",
        match p.broker.inspect_replies {
            true => "ruled on by the plugin",
            false => "passed through unseen",
        }
    );
    println!(
        "    credential:  {}",
        match p.broker.uses_secret {
            true => "may be handed a marker standing in for one (`[broker.<name>] secret`)",
            false => "never handed one",
        }
    );
    // The host resource is the config's to name, so it is read from there rather than from the
    // manifest — and a broker nothing binds is the difference between installed and in use.
    let bound = std::env::current_dir()
        .map(|cwd| crate::config::load(&cwd))
        .ok()
        .and_then(|cfg| {
            cfg.brokers
                .iter()
                .find(|b| b.name == p.name)
                .map(|b| (b.socket.describe(), b.allow.clone()))
        });
    match bound {
        Some((socket, allow)) => {
            println!("  bound by the global config:");
            println!("    socket:      {n}{socket}{r}");
            println!(
                "    allow:       {}",
                match allow.is_empty() {
                    true => "(none — the plugin is handed an empty grant)".to_string(),
                    false => allow.join(", "),
                }
            );
        }
        None => println!(
            "  bound by the global config: no — add `[broker.{}] socket` to stand it up",
            p.name
        ),
    }
    print_plugin_host_config(&p.name, &p.sandbox, err, r);
    ExitCode::SUCCESS
}

/// `sbx plugins info <name>` for a signer plugin. Two questions it has to answer that no other
/// type does: exactly which headers this plugin may put on a request, and whether it is handed the
/// credential's plaintext or a marker standing in for one.
fn info_signer(
    layout: &store::Layout,
    p: &crate::plugins::signer::SignerPlugin,
    pal: &style::Palette,
) -> ExitCode {
    let (h, n, err, r) = (pal.head, pal.name, pal.err, pal.reset);
    println!("{h}signer plugin:{r} {n}{}{r}", p.name);
    print_about(
        layout,
        About {
            version: p.version.as_deref(),
            description: p.description.as_deref(),
            dir_name: p.dir_name(),
            exec: &p.exec,
        },
        p.check_exec(),
        pal,
    );
    println!("  auth point:");
    println!("    sets:        {}", p.signer.sets_headers.join(", "));
    println!(
        "    sees:        {}",
        match p.signer.sees_headers.is_empty() {
            true => "the method, the host and the target only".to_string(),
            false => format!(
                "the method, the host and the target, plus {}",
                p.signer.sees_headers.join(", ")
            ),
        }
    );
    println!(
        "    credential:  {}",
        match p.signer.reads_secret {
            true => "the plaintext, which it needs to compute a signature from",
            false => "a marker standing in for it, which sbx substitutes on the way out",
        }
    );
    print_plugin_host_config(&p.name, &p.sandbox, err, r);
    ExitCode::SUCCESS
}

/// What this host answers a plugin, from `[plugin.<name>]` in the resolved config.
///
/// Read through the config layer rather than from the manifest, because that is where the table is
/// layered and gated: an untrusted project's is already dropped by the time it gets here, so what
/// is printed is what a launch would use. Kept on its own lines under the grant — the grant is what
/// the plugin asked for and was signed with, this is what the machine supplies, and reading them as
/// one block would blur which of the two a line came from.
///
/// A variable the manifest does not declare is shown as ignored rather than omitted: the config
/// says it, so the answer to "why is it not applying" belongs here. One printer for every type,
/// because `[plugin.<name>]` means the same thing whatever the plugin does with it.
fn print_plugin_host_config(name: &str, grant: &plugins::SandboxGrant, err: &str, r: &str) {
    let Ok(cwd) = std::env::current_dir() else {
        return;
    };
    let resolved = crate::config::load(&cwd);
    let Some(raw) = resolved.plugin.get(name) else {
        return;
    };
    if raw.env.is_empty() {
        return;
    }
    println!("  host config (`[plugin.{name}]`):");
    for (k, v) in &raw.env {
        let declared =
            grant.allow_env.iter().any(|d| d == k) || grant.allow_env_paths.iter().any(|d| d == k);
        match declared {
            true => println!("    {k}={v}"),
            false => println!("    {k}={v}  {err}[ignored: the manifest does not declare it]{r}"),
        }
    }
}

/// How a cage reaches this broker's socket, in the terms its own manifest declared: the variables
/// pointed at it, the address it stands at, or both.
///
/// Every form is named, because a listing that showed only one of them printed an empty list for a
/// broker declaring the others — and an empty list reads as "reaches nothing", which is the one
/// thing it never means.
fn how_the_cage_finds_it(p: &crate::plugins::broker::BrokerPlugin) -> String {
    let mut parts = Vec::new();
    if p.broker.at_host_path {
        parts.push("at the host resource's own path".to_string());
    }
    if !p.broker.cage_env.is_empty() {
        parts.push(format!("${}", p.broker.cage_env.join(", $")));
    }
    if !p.broker.cage_env_dir.is_empty() {
        parts.push(format!(
            "${} (the directory holding it)",
            p.broker.cage_env_dir.join(", $")
        ));
    }
    parts.join(", ")
}

/// The `brokers` grant, and whether this machine answers it.
///
/// Shown even when empty, like every other line of the grant, and resolved against the config
/// rather than printed from the manifest: a name no global `[broker.<name>]` binds is answered by
/// nothing at launch, and a reader asking "does my `pass://` reach the agent?" is asking exactly
/// that. The plugin's own directory is never consulted here — only the two declarations that have
/// to agree.
fn print_grant_brokers(names: &[String]) {
    if names.is_empty() {
        println!("    brokers:     (none)");
        return;
    }
    let bound: Vec<String> = std::env::current_dir()
        .map(|cwd| crate::config::load(&cwd))
        .map(|cfg| cfg.brokers.iter().map(|b| b.name.clone()).collect())
        .unwrap_or_default();
    let shown: Vec<String> = names
        .iter()
        .map(|name| match bound.contains(name) {
            true => name.clone(),
            false => format!("{name} (no `[broker.{name}]` binds it — the plugin runs without it)"),
        })
        .collect();
    println!("    brokers:     {}", shown.join(", "));
}

/// The `allow_env_paths` grant, resolved the way a launch would resolve it: each variable with the
/// path it currently names, so the answer to "will my relocated store be reachable?" comes before
/// the first secret rather than during it.
///
/// An unset variable is not a fault — the manifest's own `allow_paths` then apply — so it is said
/// plainly. A relative value is called out, since a launch drops it.
fn print_grant_env_paths(keys: &[String], err: &str, r: &str) {
    if keys.is_empty() {
        println!("    allow_env_paths: (none)");
        return;
    }
    let shown: Vec<String> = keys
        .iter()
        .map(|k| match std::env::var(k) {
            Ok(v) if std::path::Path::new(&v).is_absolute() => format!("{k} -> {v}"),
            Ok(v) => format!("{k} -> {err}{v} (not absolute, would be dropped){r}"),
            Err(_) => format!("{k} -> unset (the manifest's own paths apply)"),
        })
        .collect();
    println!("    allow_env_paths: {}", shown.join(", "));
}

#[cfg(test)]
mod tests {
    #[test]
    fn store_list_takes_a_store_name_a_flag_or_both() {
        use std::ffi::OsString;
        let os = |v: &[&str]| -> Vec<OsString> { v.iter().map(OsString::from).collect() };
        assert_eq!(
            super::parse_store_list_args(&os(&[])).unwrap(),
            (false, None)
        );
        assert_eq!(
            super::parse_store_list_args(&os(&["--installed"])).unwrap(),
            (true, None)
        );
        assert_eq!(
            super::parse_store_list_args(&os(&["sbx-plugins"])).unwrap(),
            (false, Some("sbx-plugins".to_string()))
        );
        // Order must not matter: a user types whichever came to mind first.
        assert_eq!(
            super::parse_store_list_args(&os(&["--installed", "sbx-plugins"])).unwrap(),
            (true, Some("sbx-plugins".to_string()))
        );
        assert_eq!(
            super::parse_store_list_args(&os(&["sbx-plugins", "--installed"])).unwrap(),
            (true, Some("sbx-plugins".to_string()))
        );
        // An unknown flag, and a second name, are refused rather than absorbed.
        assert_eq!(
            super::parse_store_list_args(&os(&["--nope"])).unwrap_err(),
            "--nope"
        );
        assert_eq!(
            super::parse_store_list_args(&os(&["a", "b"])).unwrap_err(),
            "b"
        );
    }

    use super::*;
    use crate::plugins::origin::Origin;
    use std::collections::BTreeMap;

    /// An index describing exactly what a test needs installed, without touching a data directory.
    fn index(entries: &[(&str, &str, Origin, Option<&str>)]) -> InstalledIndex {
        let mut by_name = BTreeMap::new();
        let mut by_scheme = BTreeMap::new();
        for (name, scheme, origin, version) in entries {
            by_name.insert(
                (*name).to_string(),
                InstalledPlugin {
                    origin: origin.clone(),
                    version: version.map(str::to_string),
                    digest: origin.digest().map(str::to_string),
                    disabled_over: None,
                },
            );
            by_scheme.insert((*scheme).to_string(), (*name).to_string());
        }
        InstalledIndex {
            by_name,
            by_scheme,
            conflicts: BTreeMap::new(),
        }
    }

    /// An index whose only installed plugins are the claimants of one ambiguous scheme: in place,
    /// resolving nothing. The scheme is deliberately absent from `by_scheme` — that is exactly what
    /// the registry does with it.
    fn conflicted_index(scheme: &str, claimants: &[&str], origin: Origin) -> InstalledIndex {
        let mut by_name = BTreeMap::new();
        for name in claimants {
            by_name.insert(
                (*name).to_string(),
                InstalledPlugin {
                    origin: origin.clone(),
                    version: None,
                    digest: None,
                    disabled_over: Some(Contested::Scheme(scheme.to_string())),
                },
            );
        }
        InstalledIndex {
            by_name,
            by_scheme: BTreeMap::new(),
            conflicts: BTreeMap::from([(
                scheme.to_string(),
                claimants.iter().map(|c| (*c).to_string()).collect(),
            )]),
        }
    }

    fn plain() -> style::Palette {
        style::Palette::for_stream(false)
    }

    #[test]
    fn a_plugin_installed_from_this_store_reads_installed() {
        let idx = index(&[(
            "kp",
            "kp",
            Origin::Store {
                store: "mine".to_string(),
                url: None,
                sha256: None,
            },
            Some("1.0.0"),
        )]);
        assert_eq!(
            idx.marker("kp", Some("kp"), Some("1.0.0"), None, "mine", &plain()),
            "  [installed]"
        );
    }

    #[test]
    fn two_stores_listing_one_name_name_the_holder_instead_of_claiming_installed() {
        // Only one plugin can hold a name: an install from the second store would be refused, so
        // its listing must say who holds it rather than showing a misleading `[installed]`.
        let idx = index(&[(
            "kp",
            "kp",
            Origin::Store {
                store: "mine".to_string(),
                url: None,
                sha256: None,
            },
            None,
        )]);
        assert_eq!(
            idx.marker("kp", Some("kp"), None, None, "other", &plain()),
            "  [name taken by store 'mine']"
        );
        // The same rule across sources: a local install shadows a store's entry, and a built-in
        // shadows both.
        let idx = index(&[(
            "kp",
            "kp",
            Origin::Local {
                path: None,
                sha256: None,
            },
            None,
        )]);
        assert_eq!(
            idx.marker("kp", Some("kp"), None, None, "mine", &plain()),
            "  [name taken by a local install]"
        );
        // A plugin installed before origins were recorded holds the name just as firmly.
        let idx = index(&[("kp", "kp", Origin::Unknown, None)]);
        assert_eq!(
            idx.marker("kp", Some("kp"), None, None, "mine", &plain()),
            "  [name taken by an unknown source]"
        );
    }

    #[test]
    fn a_free_name_whose_scheme_is_taken_says_so() {
        // The install would be refused on the scheme, not the name — invisible from a catalogue.
        let idx = index(&[(
            "other",
            "kp",
            Origin::Local {
                path: None,
                sha256: None,
            },
            None,
        )]);
        assert_eq!(
            idx.marker("kp", Some("kp"), None, None, "mine", &plain()),
            "  [scheme kp:// taken by the installed plugin 'other']"
        );
    }

    #[test]
    fn a_scheme_claimed_twice_blocks_the_entry_and_names_every_claimant() {
        // Nothing resolves the scheme, yet an install is refused on it — so the entry is not
        // offered, and the marker says who has to be removed for it to become installable.
        let idx = conflicted_index(
            "kp",
            &["one", "two"],
            Origin::Local {
                path: None,
                sha256: None,
            },
        );
        assert_eq!(
            idx.marker("kp", Some("kp"), None, None, "mine", &plain()),
            "  [scheme kp:// in conflict between `one`, `two`]"
        );
    }

    #[test]
    fn a_claimant_of_a_conflicted_scheme_is_not_reported_as_working() {
        // It is installed from this very store, so the name path would have said `[installed]` —
        // which for a plugin that resolves nothing is the most misleading answer available.
        let store = Origin::Store {
            store: "mine".to_string(),
            url: None,
            sha256: None,
        };
        let idx = conflicted_index("kp", &["kp", "kp-fork"], store);
        assert_eq!(
            idx.marker("kp", Some("kp"), Some("1.0.0"), None, "mine", &plain()),
            "  [installed, disabled: scheme kp:// in conflict]"
        );
    }

    #[test]
    fn an_installable_entry_carries_no_marker() {
        let idx = index(&[(
            "other",
            "vault",
            Origin::Local {
                path: None,
                sha256: None,
            },
            None,
        )]);
        assert_eq!(
            idx.marker("kp", Some("kp"), Some("1.0.0"), None, "mine", &plain()),
            ""
        );
    }

    #[test]
    fn a_version_that_drifted_from_the_listing_reports_both() {
        // With no digest on either side there is nothing to compare but the strings, so neither is
        // called newer — the fallback for a record predating digests.
        let store = |v: Option<&str>| {
            index(&[(
                "kp",
                "kp",
                Origin::Store {
                    store: "mine".to_string(),
                    url: None,
                    sha256: None,
                },
                v,
            )])
        };
        assert_eq!(
            store(Some("1.0.0")).marker("kp", Some("kp"), Some("2.0.0"), None, "mine", &plain()),
            "  [installed v1.0.0, listed v2.0.0]"
        );
        // A version missing on either side is not a drift, just less to say.
        assert_eq!(
            store(None).marker("kp", Some("kp"), Some("2.0.0"), None, "mine", &plain()),
            "  [installed]"
        );
    }

    /// An installed plugin from store 'mine' pinning `digest`, at `version`.
    fn store_index(digest: &str, version: &str) -> InstalledIndex {
        index(&[(
            "kp",
            "kp",
            Origin::Store {
                store: "mine".to_string(),
                url: None,
                sha256: Some(digest.to_string()),
            },
            Some(version),
        )])
    }

    #[test]
    fn the_digest_decides_whether_a_listing_offers_an_upgrade() {
        // Same tree: nothing to do, whatever the version strings would suggest.
        let idx = store_index(&"a".repeat(64), "1.0.0");
        assert_eq!(
            idx.marker(
                "kp",
                Some("kp"),
                Some("1.0.0"),
                Some(&"a".repeat(64)),
                "mine",
                &plain()
            ),
            "  [installed]"
        );
        // A different tree with an ordered pair of versions: a direction can be named.
        assert_eq!(
            idx.marker(
                "kp",
                Some("kp"),
                Some("1.1.0"),
                Some(&"b".repeat(64)),
                "mine",
                &plain()
            ),
            "  [update available: v1.0.0 → v1.1.0]"
        );
        // The case a version comparison cannot see at all: a republish under the same version.
        assert_eq!(
            idx.marker(
                "kp",
                Some("kp"),
                Some("1.0.0"),
                Some(&"b".repeat(64)),
                "mine",
                &plain()
            ),
            "  [installed v1.0.0, the store lists a different build of v1.0.0]"
        );
        // A store that rolled back is not an upgrade, and saying so is the point of ordering.
        assert_eq!(
            idx.marker(
                "kp",
                Some("kp"),
                Some("0.9.0"),
                Some(&"b".repeat(64)),
                "mine",
                &plain()
            ),
            "  [ahead of the store: installed v1.0.0, listed v0.9.0]"
        );
    }

    #[test]
    fn version_order_refuses_to_guess_what_it_cannot_order() {
        use std::cmp::Ordering;
        assert_eq!(version_order("1.0.0", "1.1.0"), Some(Ordering::Less));
        assert_eq!(version_order("2", "1.9.9"), Some(Ordering::Greater));
        // A missing component is zero, so a shorter version sorts before a longer one.
        assert_eq!(version_order("1.8", "1.8.2"), Some(Ordering::Less));
        assert_eq!(version_order("1.8", "1.8.0"), Some(Ordering::Equal));
        assert_eq!(version_order("v1.2.3", "1.2.3"), Some(Ordering::Equal));
        // A release outranks its own pre-release; two different pre-releases have no numeric answer.
        assert_eq!(version_order("1.2.0", "1.2.0-rc1"), Some(Ordering::Greater));
        assert_eq!(
            version_order("1.2.0-rc1", "1.2.0-rc1"),
            Some(Ordering::Equal)
        );
        assert_eq!(version_order("1.2.0-rc2", "1.2.0-beta"), None);
        // Free-form strings: a manifest's `version` is not constrained, so these must not be
        // ranked. Claiming "up to date" from a bad guess is the failure that matters.
        assert_eq!(version_order("2026-08-01", "2026-08-02"), None);
        assert_eq!(version_order("1.0.0a", "1.0.1"), None);
        assert_eq!(version_order("latest", "1.0.0"), None);
        assert_eq!(version_order("", "1.0.0"), None);
    }

    #[test]
    fn drift_wording_states_a_difference_when_it_cannot_state_a_direction() {
        assert_eq!(
            drift_wording("2026-08-01", "2026-08-02"),
            "installed v2026-08-01, the store lists v2026-08-02"
        );
        assert_eq!(
            drift_wording("", "1.0.0"),
            "installed, the store lists a different build"
        );
    }
}
