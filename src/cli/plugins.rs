//! `sbx plugins <subcommand>`: inspect and manage resolver plugins and the signed plugin stores —
//! `list`/`info` (host-level inspection), `install`/`rm` (place a local or built-in plugin), and
//! `store add|publish|update|install|info|list|rm` (the git-hosted, Ed25519-signed catalogue). The
//! user-facing confirmation renderers it calls (`render_plugin_installed`/`render_store_*`/…) stay
//! at the crate root, shared with the `app`/`config` confirmations and their common test.

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::{diag, help, plugin_store, plugins, store, stores, style};
use crate::{
    render_plugin_installed, render_publish_key_warning, render_published, render_removed,
    render_store_configured, render_store_tofu, render_store_updated,
};

/// `sbx plugins <subcommand>`: inspect the installed resolver plugins. Host-level, like `doctor`
/// — it reads `<data>/plugins`, not a project's `.sbx.toml`. A read-only diagnostic for now;
/// installation and the signed plugin store are later increments, so the dispatch only knows the
/// inspection verbs and names them on anything else (no inert stubs).
pub(crate) fn plugins_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("list") => plugins_list(),
        Some("info") => plugins_info(args.get(1).and_then(|a| a.to_str())),
        Some("install") => plugins_install(args.get(1)),
        Some("rm") => plugins_remove(args.get(1).and_then(|a| a.to_str())),
        Some("store") => plugins_store(&args[1..]),
        // Unknown or no subcommand: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `sbx net`/`sbx config`.
        other => {
            if let Some(tok) = other {
                eprintln!("sbx: plugins: unknown subcommand {tok:?}");
            }
            eprint!("{}", help::page_usage(&["plugins"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// Resolve the registry of installed resolver plugins from the data directory, or report why it
/// could not be located. Shared by `list` and `info`; the load warnings are returned so the
/// caller can surface them (the diagnostic for a plugin that was discovered but dropped).
fn load_plugin_registry() -> Option<(plugins::PluginRegistry, Vec<String>)> {
    let layout = store::Layout::from_env()?;
    let mut warnings = Vec::new();
    let registry = plugins::PluginRegistry::load(&layout.plugins_dir(), &mut warnings);
    Some((registry, warnings))
}

/// `sbx plugins list`: the reserved built-in schemes (never claimable by a plugin) and every
/// installed resolver plugin — its scheme, name, version, network grant, and one-line
/// description. A plugin whose executable would be refused at launch (not owner-only, not a
/// regular file) is flagged here, using the very check the runner enforces, so the gap between
/// "discovered" and "runnable" is visible. Discovery warnings (a malformed manifest, an ambiguous
/// scheme) go to stderr. No nix, no network, no launch.
fn plugins_list() -> ExitCode {
    let Some((registry, warnings)) = load_plugin_registry() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, err, r) = (pal.head, pal.name, pal.dim, pal.err, pal.reset);
    println!(
        "{h}built-in schemes{r} (always resolve, never a plugin): {n}{}{r}",
        plugins::builtin_schemes().join(", ")
    );
    if registry.is_empty() {
        println!("{h}installed resolver plugins:{r} (none)");
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
            if let Err(why) = p.check_exec() {
                print!("  {err}[not runnable: {why}]{r}");
            }
            println!();
            if let Some(desc) = &p.description {
                println!("    {dim}{desc}{r}");
            }
        }
        println!("{dim}(remove one with: sbx plugins rm <name>){r}");
    }
    println!("{dim}(browse the built-in store with: sbx plugins store list){r}");
    for w in &warnings {
        diag::warn(w);
    }
    ExitCode::SUCCESS
}

/// `sbx plugins install <name | dir>`: place a resolver plugin into the data dir, where it becomes
/// trusted by location. A bare `name` installs a plugin from the built-in store (bundled in the
/// binary); a path-like argument (`./dir`, `/abs/dir`) copies a local directory. A deliberate user
/// act (an agent in the cage cannot run it); either way the staged copy is validated exactly as the
/// launcher will and refused, fail-closed, on any flaw. No fetch, no network, no signature.
fn plugins_install(source: Option<&OsString>) -> ExitCode {
    let Some(source) = source else {
        eprintln!("sbx: usage: {}", help::synopsis_of(&["plugins", "install"]));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    // The rule is syntactic, not based on what exists on disk, so the command's meaning never
    // depends on the current directory's contents: a path-like argument is a local directory, a
    // bare token is a built-in store name.
    let result = if is_path_like(source) {
        plugins::install(&layout, Path::new(source))
    } else if let Some(name) = source.to_str() {
        plugins::install_embedded(&layout, name)
    } else {
        eprintln!("sbx: a built-in plugin name must be valid UTF-8 (use ./<dir> for a local path)");
        return ExitCode::from(2);
    };
    match result {
        Ok(installed) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_plugin_installed(&installed.name, &installed.scheme, None, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("sbx: cannot install plugin: {why}");
            ExitCode::FAILURE
        }
    }
}

/// Whether an install argument names a local path rather than a built-in store plugin: it begins
/// with `.` (`./dir`, `../dir`) or contains a `/` (`/abs/dir`, `sub/dir`). A bare `name` is looked
/// up in the built-in store. Syntactic by design — the dispatch must not depend on the cwd.
fn is_path_like(arg: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let bytes = arg.as_bytes();
    bytes.first() == Some(&b'.') || bytes.contains(&b'/')
}

/// `sbx plugins store <subcommand>`: the plugin stores. `list` shows the built-in (embedded)
/// store and every configured remote store; `add` configures and fetches a remote signed store
/// (a git repository whose catalogue is verified against a public key); `update` re-fetches one
/// or all configured stores (re-verifying against the pinned key and refusing a revision that
/// would roll back); `install` installs a plugin a configured store lists; `info` details one
/// configured store; `rm` removes one.
fn plugins_store(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("list") => plugins_store_list(),
        Some("add") => plugins_store_add(&args[1..]),
        Some("publish") => plugins_store_publish(&args[1..]),
        Some("update") => plugins_store_update(&args[1..]),
        Some("install") => plugins_store_install(&args[1..]),
        Some("info") => plugins_store_info(args.get(1).and_then(|a| a.to_str())),
        Some("rm") => plugins_store_remove(args.get(1).and_then(|a| a.to_str())),
        // Unknown or no subcommand: name the mistake (if any), then print the full page so its
        // Subcommands list guides, like bare `sbx net`/`sbx config`.
        other => {
            if let Some(tok) = other {
                eprintln!("sbx: plugins store: unknown subcommand {tok:?}");
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
                eprintln!(
                    "sbx: unexpected argument '{}'",
                    other.unwrap_or("(non-UTF-8)")
                );
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
        eprintln!(
            "sbx: --key and --trust are mutually exclusive: --key pins a key you supply, \
             --trust accepts the key the store ships"
        );
        return ExitCode::from(2);
    }
    if key.is_none() && !trust {
        eprintln!(
            "sbx: supply --key <hex|@file> to pin a known key, or --trust to accept the key the \
             store ships on first use"
        );
        return ExitCode::from(2);
    }

    let Some(layout) = store::Layout::from_env() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        eprintln!("sbx: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };

    let result = match key {
        Some(key) => {
            let pubkey = match stores::parse_pubkey_arg(key) {
                Ok(k) => k,
                Err(why) => {
                    eprintln!("sbx: invalid --key: {why}");
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
                    render_store_tofu(&plugin_store::to_hex(&added.pubkey), &added.name, &epal)
                );
            }
            let cat = &added.catalogue;
            let plugins: Vec<(&str, &str, &str)> = cat
                .plugins
                .iter()
                .map(|(p, e)| (p.as_str(), e.scheme.as_str(), e.version.as_str()))
                .collect();
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            print!(
                "{}",
                render_store_configured(&added.name, cat.rev, &plugins, &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("sbx: cannot add store: {why}");
            ExitCode::FAILURE
        }
    }
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
                        eprintln!("sbx: --rev must be a non-negative integer");
                        return ExitCode::from(2);
                    }
                }
            }
            Some(flag) if flag.starts_with('-') => {
                eprintln!("sbx: unexpected argument '{flag}'");
                eprintln!("{usage}");
                return ExitCode::from(2);
            }
            // Anything else (including a non-UTF-8 path) is the positional directory.
            _ => {
                if dir.is_some() {
                    eprintln!("sbx: publish takes a single directory");
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
            let pubkey = plugin_store::to_hex(&published.pubkey);
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
            eprintln!("sbx: cannot publish store: {why}");
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
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let Some(git) = store::resolve_git() else {
        eprintln!("sbx: git is not on PATH — a remote plugin store is a git repository");
        return ExitCode::FAILURE;
    };

    let names: Vec<String> = match args.first() {
        Some(arg) => {
            let Some(name) = arg.to_str() else {
                eprintln!("sbx: a store name must be valid UTF-8");
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
                eprintln!("sbx: cannot update store '{name}': {why}");
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
        eprintln!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "store", "install"])
        );
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match stores::install_plugin(&layout, store_name, plugin_name) {
        Ok(installed) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!(
                "{}",
                render_plugin_installed(&installed.name, &installed.scheme, Some(store_name), &pal)
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("sbx: cannot install plugin: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store info <name>`: a configured remote store in detail — its origin URL, the
/// pinned public key, the accepted catalogue revision, and each plugin it lists. Reads only the
/// owner-only cache (trusted by location): no fetch, no network.
fn plugins_store_info(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "store", "info"])
        );
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let cfg = match stores::read_configured(&layout, name) {
        Ok(cfg) => cfg,
        Err(why) => {
            eprintln!("sbx: {why}");
            return ExitCode::FAILURE;
        }
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    println!("{h}store{r} {n}'{}'{r}", cfg.name);
    println!("  url:      {}", cfg.url);
    println!("  key:      {}", plugin_store::to_hex(&cfg.pubkey));
    println!(
        "  trust:    {}",
        if cfg.tofu {
            "trust-on-first-use (verify the key out of band)"
        } else {
            "pinned key (supplied out of band)"
        }
    );
    println!("  revision: {}", cfg.locked_rev);
    match stores::cached_catalogue(&layout, name) {
        Ok(cat) if cat.plugins.is_empty() => println!("  plugins:  (none)"),
        Ok(cat) => {
            println!("  plugins:");
            for (pname, entry) in &cat.plugins {
                print!("    {n}{pname}{r}  {dim}({}://){r}", entry.scheme);
                if !entry.version.is_empty() {
                    print!("  v{}", entry.version);
                }
                println!();
                if !entry.description.is_empty() {
                    println!("      {dim}{}{r}", entry.description);
                }
            }
        }
        Err(why) => diag::warn(&format!("cannot read the cached catalogue: {why}")),
    }
    ExitCode::SUCCESS
}

/// `sbx plugins store rm <name>`: remove a configured remote store from the cache. Host-level,
/// like `add`; refuses a name that is not configured.
fn plugins_store_remove(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!(
            "sbx: usage: {}",
            help::synopsis_of(&["plugins", "store", "rm"])
        );
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match stores::remove(&layout, name) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(Some("store"), name, &pal));
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("sbx: cannot remove store: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins store list`: the resolver plugins bundled in the binary, each with its scheme,
/// version, description, and whether it is already installed, followed by every configured
/// remote store with its accepted revision and plugin count. No fetch, no network.
fn plugins_store_list() -> ExitCode {
    let layout = store::Layout::from_env();
    let installed_dir = layout.as_ref().map(|l| l.plugins_dir());
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);
    println!("{h}built-in plugin store{r} (install one with: sbx plugins install <name>):");
    for entry in plugins::embedded_listing() {
        let scheme = entry.scheme.as_deref().unwrap_or("?");
        print!("  {n}{}{r}  {dim}({scheme}://){r}", entry.name);
        if let Some(v) = &entry.version {
            print!("  v{v}");
        }
        let is_installed = installed_dir
            .as_ref()
            .is_some_and(|d| d.join(&entry.name).is_dir());
        if is_installed {
            print!("  {}[installed]{r}", pal.ok);
        }
        println!();
        if let Some(desc) = &entry.description {
            println!("    {dim}{desc}{r}");
        }
    }

    // Configured remote stores, read from their owner-only caches (trusted by location).
    if let Some(layout) = &layout {
        let names = stores::list(layout);
        if !names.is_empty() {
            println!(
                "{h}configured remote stores{r} (update with: sbx plugins store update <name>):"
            );
            for name in &names {
                match stores::read_configured(layout, name) {
                    Ok(cfg) => {
                        let detail = match stores::cached_catalogue(layout, name) {
                            Ok(cat) => {
                                let count = cat.plugins.len();
                                format!("{count} plugin{}", if count == 1 { "" } else { "s" })
                            }
                            Err(_) => "catalogue unreadable".to_string(),
                        };
                        let marker = if cfg.tofu {
                            format!("  {}[tofu]{r}", pal.warn)
                        } else {
                            String::new()
                        };
                        println!(
                            "  {n}{name}{r}  {dim}(rev {}, {detail}){r}{marker}",
                            cfg.locked_rev
                        );
                    }
                    Err(why) => diag::warn(&format!("store '{name}': {why}")),
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// `sbx plugins rm <name>`: remove an installed resolver plugin by its name (the token `list`
/// shows). Host-level, like `install`; refuses an unsafe name or a directory that is not a plugin.
fn plugins_remove(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        eprintln!("sbx: usage: {}", help::synopsis_of(&["plugins", "rm"]));
        return ExitCode::from(2);
    };
    let Some(layout) = store::Layout::from_env() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    match plugins::remove(&layout, name) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(None, name, &pal));
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("sbx: cannot remove plugin: {why}");
            ExitCode::FAILURE
        }
    }
}

/// `sbx plugins info <scheme>`: the full manifest and sandbox grant of the plugin claiming
/// `scheme`. A built-in scheme is reported as such (not an error); an unknown scheme is a
/// non-zero "no such plugin". Like `list`, host-level and side-effect-free.
fn plugins_info(scheme: Option<&str>) -> ExitCode {
    let Some(scheme) = scheme else {
        eprintln!("sbx: usage: {}", help::synopsis_of(&["plugins", "info"]));
        return ExitCode::from(2);
    };
    if plugins::builtin_schemes().contains(&scheme) {
        println!("{scheme}: a built-in resolver (compiled into sbx, not a plugin)");
        return ExitCode::SUCCESS;
    }
    let Some((registry, warnings)) = load_plugin_registry() else {
        eprintln!("sbx: cannot locate the data directory (set $HOME or $XDG_DATA_HOME)");
        return ExitCode::FAILURE;
    };
    let Some(p) = registry.resolver(scheme) else {
        // A scheme can be absent because nothing claims it — or because it was *dropped* (two
        // plugins claimed it, or its manifest is malformed). That reason lives in the load
        // warnings, and `info <scheme>` is exactly the command a user runs to learn why their
        // plugin is not picked up, so re-emit them before the generic miss.
        for w in &warnings {
            diag::warn(w);
        }
        eprintln!("sbx: no installed resolver plugin claims the scheme '{scheme}'");
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, err, r) = (pal.head, pal.name, pal.err, pal.reset);
    println!("{h}resolver plugin:{r} {n}{}{r}", p.name);
    println!("  scheme:      {n}{}://{r}", p.scheme);
    println!(
        "  version:     {}",
        p.version.as_deref().unwrap_or("(unset)")
    );
    println!(
        "  description: {}",
        p.description.as_deref().unwrap_or("(none)")
    );
    print!("  exec:        {}", p.exec.display());
    match p.check_exec() {
        Ok(()) => println!(),
        Err(why) => println!("  {err}[not runnable: {why}]{r}"),
    }
    println!("  sandbox grant:");
    println!("    network:     {}", p.sandbox.network);
    print_grant_paths("allow_paths", &p.sandbox.allow_paths);
    print_grant_env("allow_env", &p.sandbox.allow_env);
    ExitCode::SUCCESS
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

/// One `sbx plugins info` grant line listing passed-through environment variables, or `(none)`.
fn print_grant_env(label: &str, keys: &[String]) {
    if keys.is_empty() {
        println!("    {label}:    (none)");
    } else {
        println!("    {label}:    {}", keys.join(", "));
    }
}
