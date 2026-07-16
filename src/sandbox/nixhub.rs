//! Resolving a project's `nix:` mise tools to pinned nixpkgs references.
//!
//! mise's `[tools]` may name a tool through the `nix` backend as `nix:<pkg>` (e.g.
//! `nix:nodejs`). For those, ops resolves each `(<pkg>, <version>)` to the *exact*
//! nixpkgs revision that shipped it — the same thing the mise-nix plugin does, but
//! performed by ops so the realisation runs through ops's own provisioning path. The
//! mapping `(<pkg>, <version>) -> <commit>#<attr>` is answered by a single nixhub GET,
//! which ops fetches with nix's *own* fetcher — so no HTTP client dependency is added.
//!
//! Only the `nix:` prefix is in scope. The part after it is already the nixhub /
//! nixpkgs package name (used verbatim), so there is no tool-name translation to do. A
//! tool named through any other backend (a bare `node`, an `npm:` package) is out of
//! scope here and is reported so the caller can warn rather than silently drop it.
//!
//! Two pieces, split so the policy is testable without the network: parsing the
//! declared tools out of the project's mise files (pure), and selecting the nixpkgs
//! pin for a tool from nixhub metadata (pure) — with the one impure step, the metadata
//! GET, isolated in [`resolve`].

use super::packages::Provisioned;
use crate::store::{self, Layout};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;

/// The mise backend prefix ops resolves through nix; the remainder of the tool token
/// is the nixhub/nixpkgs package name.
const NIX_PREFIX: &str = "nix:";

/// The nixhub metadata endpoint. A single GET of `<base><pkg>` returns the package's
/// releases and, per release, the nixpkgs commit and attribute that shipped it.
const NIXHUB_BASE: &str = "https://search.devbox.sh/v2/pkg?name=";

/// The nixhub fuzzy-search endpoint. A GET of `<base><url-encoded query>` returns the
/// matching packages with a name and one-line summary each. Used by `ops search`.
pub(crate) const NIXHUB_SEARCH_BASE: &str = "https://search.devbox.sh/v2/search?q=";

/// The idiomatic version file, which is line-oriented rather than TOML.
const TOOL_VERSIONS: &str = ".tool-versions";

/// The output subdirectory a tool exposes its executables under, and the marker
/// selecting the bin-bearing output of a multi-output derivation.
const BIN: &str = "bin";

/// The per-project file caching tool resolutions, so nixhub is queried once per
/// `(tool, version)` and a launch works offline after the first.
const TOOLS_LOCK: &str = "tools.lock";

/// A `nix:`-declared tool: the nixhub/nixpkgs package name and the requested version
/// spec (a concrete version, or an alias such as `latest`/`stable`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NixTool {
    /// The package name as nixhub indexes it (the token after `nix:`).
    pub(crate) pkg: String,
    /// The requested version: a concrete version, or `latest`/`stable`.
    pub(crate) version: String,
}

/// A resolved nixpkgs pin: the revision and attribute that shipped the chosen version
/// of a tool. `<commit>#<attr>` is what provisioning realises against
/// `github:NixOS/nixpkgs/<commit>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pin {
    /// The 40-hex nixpkgs commit the tool's version was built from.
    pub(crate) commit: String,
    /// The nixpkgs attribute path to realise at that commit.
    pub(crate) attr: String,
    /// The concrete version nixhub resolved the request to (for display and locking).
    pub(crate) version: String,
}

/// A tool declared through a mise backend other than `nix:` (a backend prefix such as
/// `aqua:`/`github:`/`npm:`, or a plain registry tool like `node`). ops does not
/// host-provision these; the launcher auto-equips them in-cage via mise, so the token is
/// kept exactly as written together with its requested version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MiseTool {
    /// The tool token as written in the mise file, e.g. `aqua:BurntSushi/ripgrep` or `node`.
    pub(crate) token: String,
    /// The requested version: a concrete version, or an alias such as `latest`.
    pub(crate) version: String,
}

/// A project's declared `[tools]`, split by how ops handles each: the valid `nix:` tools
/// it resolves and host-provisions (in precedence order, the first declaration of a token
/// winning); the tools for any other mise backend it auto-equips in-cage; and the `nix:`
/// tokens it cannot resolve. Every token lands in exactly one bucket — none is dropped.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DeclaredTools {
    /// The `nix:` tools ops will resolve and provision, highest precedence first.
    pub(crate) nix: Vec<NixTool>,
    /// Tools for another mise backend, auto-equipped in-cage (kept with their version).
    pub(crate) non_nix: Vec<MiseTool>,
    /// `nix:` tokens ops cannot resolve (a malformed package name or version), reported so
    /// the declaration can be fixed.
    pub(crate) malformed: Vec<String>,
}

/// Parse the `nix:` tools out of a project's mise files. `files` are the authorized
/// `(filename, bytes)` in precedence order (highest first); the first declaration of a
/// given tool token wins, so a higher-precedence file overrides a lower one. Pure: the
/// declaration policy is decided here without touching nix or the network.
pub(crate) fn parse_nix_tools(files: &[(String, Vec<u8>)]) -> DeclaredTools {
    let mut out = DeclaredTools::default();
    let mut seen: HashSet<String> = HashSet::new();
    for (name, bytes) in files {
        let entries = if name == TOOL_VERSIONS {
            parse_tool_versions(bytes)
        } else {
            parse_toml_tools(bytes)
        };
        for (token, version) in entries {
            // The merge key is the tool token exactly as written: `nix:nodejs` and a
            // bare `nodejs` are distinct tools to mise, so they are distinct here. The
            // first occurrence wins, matching the precedence order of `files`.
            if !seen.insert(token.clone()) {
                continue;
            }
            match token.strip_prefix(NIX_PREFIX) {
                Some(pkg) if is_valid_pkg(pkg) && is_valid_version(&version) => {
                    out.nix.push(NixTool {
                        pkg: pkg.to_string(),
                        version,
                    });
                }
                // a `nix:` token whose package name or version cannot be safely resolved:
                // surfaced so the declaration can be fixed.
                Some(_) => out.malformed.push(token),
                // any other backend (or a plain registry tool): not host-provisioned, but
                // auto-equipped in-cage by mise — kept with its version for the install.
                None => out.non_nix.push(MiseTool { token, version }),
            }
        }
    }
    out
}

/// Extract `(tool, version)` pairs from a TOML mise file's `[tools]` table. A value
/// may be a bare version string, a table carrying a `version` key, or an array of
/// versions (the first is taken). Entries come in sorted key order (a TOML table is not
/// insertion-ordered) — deterministic, and ordering among one file's own tools is not
/// load-bearing. An unreadable or non-TOML file yields nothing — the bytes were already
/// safety-gated and trust-hashed, so a parse failure degrades to "no tools" here.
fn parse_toml_tools(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let Some(tools) = value.get("tools").and_then(toml::Value::as_table) else {
        return Vec::new();
    };
    tools
        .iter()
        .filter_map(|(name, spec)| version_of(spec).map(|v| (name.clone(), v)))
        .collect()
}

/// The requested version a `[tools]` value carries: a bare string, a table's `version`
/// field, or the first element of an array. `None` for a shape with no version string.
fn version_of(spec: &toml::Value) -> Option<String> {
    match spec {
        toml::Value::String(s) => Some(s.clone()),
        toml::Value::Table(t) => t
            .get("version")
            .and_then(toml::Value::as_str)
            .map(String::from),
        toml::Value::Array(a) => a.first().and_then(toml::Value::as_str).map(String::from),
        _ => None,
    }
}

/// Extract `(tool, version)` pairs from a `.tool-versions` file: one tool per
/// non-comment line, `<tool> <version> [more...]`, the first version taken. Blank lines
/// and `#` comments are skipped.
fn parse_tool_versions(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let tool = parts.next()?;
            let version = parts.next()?;
            Some((tool.to_string(), version.to_string()))
        })
        .collect()
}

/// The nix system string for the current host (`x86_64-linux`, `aarch64-linux`), used
/// to pick the matching nixhub platform. Linux-only, matching the rest of the sandbox.
pub(crate) fn current_system() -> String {
    format!("{}-linux", std::env::consts::ARCH)
}

/// Provision a trusted project's declared `nix:` tools into ops's store and report the
/// `bin` directories to prepend to the sandbox PATH, plus a warning for any malformed
/// `nix:` token. Resolution is cached in a per-project lock so nixhub is queried once
/// per `(tool, version)` rather than on every launch — seeded then reused, like the
/// channel lock, so a launch is reproducible and works offline after the first.
///
/// `nix:` provisioning is trusted-only: an untrusted project's `nix:` tools are withheld
/// with a hint. A tool declared through any other backend is *not* handled here — the
/// launcher auto-equips it in-cage via mise (the open self-equip path), so it is neither
/// provisioned nor warned about here. A declared, admitted `nix:` tool that fails to resolve
/// or realise is a hard error naming it — a stated requirement, unlike a best-effort bind.
pub(crate) fn provision(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    files: &[(String, Vec<u8>)],
    trusted: bool,
    system: &str,
) -> io::Result<Provisioned> {
    let declared = parse_nix_tools(files);
    let mut warnings = Vec::new();
    // A non-`nix:` backend is not a problem — the launcher auto-equips it in-cage via mise —
    // so it is not warned here. A malformed `nix:` token cannot be resolved, so it is.
    for token in &declared.malformed {
        warnings.push(format!(
            "tool `{token}` has a malformed `nix:` name or version and cannot be resolved — fix the declaration or use `[packages]`"
        ));
    }
    if declared.nix.is_empty() {
        return Ok(Provisioned {
            bins: Vec::new(),
            roots: Vec::new(),
            warnings,
        });
    }
    if !trusted {
        for tool in &declared.nix {
            warnings.push(format!(
                "withholding nix tool `{}` (project untrusted — run `ops trust`)",
                tool.pkg
            ));
        }
        return Ok(Provisioned {
            bins: Vec::new(),
            roots: Vec::new(),
            warnings,
        });
    }

    let id = super::binds::project_runtime_id(project)?;
    let lock_path = layout
        .data_dir()
        .join("projects")
        .join(&id)
        .join(TOOLS_LOCK);
    // A subdirectory of the project's gcroots, distinct from native `[packages]` roots
    // so the two tool sources cannot collide on a shared name.
    let roots = layout
        .data_dir()
        .join("gcroots")
        .join("projects")
        .join(&id)
        .join("nix-tools");

    let mut lock = ResolutionLock::read(&lock_path);
    let mut bins = Vec::with_capacity(declared.nix.len());
    let mut tool_roots = Vec::with_capacity(declared.nix.len());
    for tool in &declared.nix {
        let pin = match lock.get(&tool.pkg, &tool.version, system) {
            Some(pin) => pin,
            None => {
                let pin = resolve(nix, layout, tool, system, false).map_err(|e| {
                    io::Error::other(format!(
                        "cannot resolve nix tool `{}@{}`: {e}",
                        tool.pkg, tool.version
                    ))
                })?;
                lock.insert(&tool.pkg, &tool.version, system, &pin);
                // Persist each freshly-resolved pin at once, ADDITIVELY: re-read the on-disk lock,
                // merge just this pin, and write. This way a later tool's provision failure does not
                // discard the pins resolved so far (the old whole-loop write-at-the-end lost them),
                // and a concurrent `ops upgrade mise` that rolled a *different* entry is merged in
                // rather than clobbered by a stale whole-lock rewrite.
                let mut disk = ResolutionLock::read(&lock_path);
                disk.insert(&tool.pkg, &tool.version, system, &pin);
                disk.write(&lock_path)?;
                pin
            }
        };
        let flake_ref = format!("github:NixOS/nixpkgs/{}", pin.commit);
        let logical = store::provision(
            nix,
            layout,
            &roots.join(&tool.pkg),
            &flake_ref,
            &pin.attr,
            BIN,
        )
        .map_err(|e| {
            io::Error::other(format!(
                "cannot provision nix tool `{}` ({}@{} -> {}#{}): {e}",
                tool.pkg, tool.pkg, pin.version, pin.commit, pin.attr
            ))
        })?;
        bins.push(logical.join(BIN));
        tool_roots.push(logical);
    }
    // No final whole-lock rewrite: each new pin was already persisted additively above, so a warm
    // launch (every tool already pinned) writes nothing and cannot clobber a concurrent upgrade.
    Ok(Provisioned {
        bins,
        roots: tool_roots,
        warnings,
    })
}

/// The outcome of re-resolving one declared tool — or pruning a stale entry, or noting a
/// token ops does not handle — during an explicit tools roll. Pure data, so the report is
/// rendered and unit-tested without touching nix or the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ToolUpgrade {
    /// A request that resolves to the version it was already at — an exact pin (which can
    /// never roll, so the network is skipped), or a floating request whose newest build
    /// is unchanged.
    Unchanged {
        pkg: String,
        request: String,
        version: String,
    },
    /// A floating request (`latest`/`stable`/a prefix) that rolled to a newer version.
    Rolled {
        pkg: String,
        request: String,
        from: String,
        to: String,
    },
    /// A request with no prior lock entry, resolved and pinned for the first time.
    Pinned {
        pkg: String,
        request: String,
        version: String,
    },
    /// A re-resolution that failed; the prior pin (if any) is kept and the roll reports a
    /// non-zero exit. `kept` is the surviving version, `None` when there was no prior pin.
    Failed {
        pkg: String,
        request: String,
        error: String,
        kept: Option<String>,
    },
    /// A lock entry for a tool no longer declared on this system, dropped from the lock.
    Pruned { pkg: String, request: String },
    /// A declared token `ops upgrade` does not roll, reported so it is never a silent
    /// omission. `mise_managed` distinguishes a tool for another mise backend (equipped
    /// in-cage, so mise tracks its freshness) from a malformed `nix:` token (unresolvable).
    Ignored { token: String, mise_managed: bool },
}

/// Re-resolve a trusted project's declared `nix:` tools against nixhub and rewrite the
/// per-project resolution lock — the explicit roll-forward `ops upgrade mise` performs.
/// Only the lock is rewritten; the new pins are realised on the next launch, exactly as a
/// channel roll downloads its base on the next launch.
///
/// A request that is an exact version already locked to itself can never roll (nixhub maps
/// a version to a fixed commit, and an exact match always wins), so its network query is
/// skipped. Every other request — an alias (`latest`/`stable`), a prefix (`20` → `20.x`),
/// or an as-yet-unlocked tool — is re-resolved. Best-effort: a tool that fails to resolve
/// keeps its prior pin and is reported, and the roll continues (the caller exits non-zero).
///
/// Stale entries are pruned: a lock entry whose `(pkg, request)` is no longer declared is
/// dropped — but only for the current `system`, so a data directory shared across machines
/// never loses another host's still-valid pins. The caller invokes this only for a trusted
/// project (an untrusted one's tools are never locked).
pub(crate) fn upgrade_tools(
    nix: &Path,
    layout: &Layout,
    project: &Path,
    files: &[(String, Vec<u8>)],
    system: &str,
) -> io::Result<Vec<ToolUpgrade>> {
    let declared = parse_nix_tools(files);
    let id = super::binds::project_runtime_id(project)?;
    let lock_path = layout
        .data_dir()
        .join("projects")
        .join(&id)
        .join(TOOLS_LOCK);
    let mut lock = ResolutionLock::read(&lock_path);
    let mut outcomes = Vec::new();

    for tool in &declared.nix {
        let existing = lock.get(&tool.pkg, &tool.version, system);
        // An exact concrete request already resolved to itself is frozen — skip the query.
        if let Some(pin) = &existing {
            if pin.version == tool.version {
                outcomes.push(ToolUpgrade::Unchanged {
                    pkg: tool.pkg.clone(),
                    request: tool.version.clone(),
                    version: pin.version.clone(),
                });
                continue;
            }
        }
        match resolve(nix, layout, tool, system, true) {
            Ok(pin) => {
                let outcome = match &existing {
                    None => ToolUpgrade::Pinned {
                        pkg: tool.pkg.clone(),
                        request: tool.version.clone(),
                        version: pin.version.clone(),
                    },
                    Some(old) if old.commit == pin.commit => ToolUpgrade::Unchanged {
                        pkg: tool.pkg.clone(),
                        request: tool.version.clone(),
                        version: pin.version.clone(),
                    },
                    Some(old) => ToolUpgrade::Rolled {
                        pkg: tool.pkg.clone(),
                        request: tool.version.clone(),
                        from: old.version.clone(),
                        to: pin.version.clone(),
                    },
                };
                lock.insert(&tool.pkg, &tool.version, system, &pin);
                outcomes.push(outcome);
            }
            Err(e) => outcomes.push(ToolUpgrade::Failed {
                pkg: tool.pkg.clone(),
                request: tool.version.clone(),
                error: e.to_string(),
                kept: existing.map(|p| p.version),
            }),
        }
    }

    // Prune entries for this system whose request is no longer declared. Other-system
    // entries are left untouched so a shared data dir keeps the other host's valid pins.
    let declared_keys: HashSet<(&str, &str)> = declared
        .nix
        .iter()
        .map(|t| (t.pkg.as_str(), t.version.as_str()))
        .collect();
    let stale: Vec<(String, String, String)> = lock
        .entries
        .keys()
        .filter(|(pkg, req, sys)| {
            sys == system && !declared_keys.contains(&(pkg.as_str(), req.as_str()))
        })
        .cloned()
        .collect();
    for (pkg, request, sys) in stale {
        lock.entries.remove(&(pkg.clone(), request.clone(), sys));
        outcomes.push(ToolUpgrade::Pruned { pkg, request });
    }

    for tool in declared.non_nix {
        outcomes.push(ToolUpgrade::Ignored {
            token: tool.token,
            mise_managed: true,
        });
    }
    for token in declared.malformed {
        outcomes.push(ToolUpgrade::Ignored {
            token,
            mise_managed: false,
        });
    }

    lock.write(&lock_path)?;
    Ok(outcomes)
}

/// A per-project cache of `(pkg, version, system) -> Pin`: a tool is resolved against
/// nixhub once and reused on later launches. The version request is part of the key, so
/// changing it re-resolves. The system is in the key too, since a release's pin is
/// platform-specific. The lock grows as tools are added; an explicit roll
/// ([`upgrade_tools`]) prunes entries whose tool has left the config and re-resolves the
/// floating pins.
struct ResolutionLock {
    entries: BTreeMap<(String, String, String), Pin>,
}

impl ResolutionLock {
    /// Read the lock, skipping any malformed line so a corrupt entry self-heals by being
    /// re-resolved rather than trusted. An absent file is an empty lock. Each line is
    /// `<pkg>\t<version>\t<system>\t<commit>\t<attr>\t<resolved-version>`, every field
    /// validated before it is trusted to flow back into a flake reference.
    fn read(path: &Path) -> Self {
        let mut entries = BTreeMap::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if let [pkg, version, system, commit, attr, resolved] =
                    line.split('\t').collect::<Vec<_>>()[..]
                {
                    if is_valid_pkg(pkg)
                        && is_valid_version(version)
                        && is_valid_system(system)
                        && is_commit(commit)
                        && is_valid_attr(attr)
                        && is_valid_version(resolved)
                    {
                        entries.insert(
                            (pkg.to_string(), version.to_string(), system.to_string()),
                            Pin {
                                commit: commit.to_string(),
                                attr: attr.to_string(),
                                version: resolved.to_string(),
                            },
                        );
                    }
                }
            }
        }
        Self { entries }
    }

    /// The cached pin for a request, if any.
    fn get(&self, pkg: &str, version: &str, system: &str) -> Option<Pin> {
        self.entries
            .get(&(pkg.to_string(), version.to_string(), system.to_string()))
            .cloned()
    }

    /// Record a fresh resolution.
    fn insert(&mut self, pkg: &str, version: &str, system: &str, pin: &Pin) {
        self.entries.insert(
            (pkg.to_string(), version.to_string(), system.to_string()),
            pin.clone(),
        );
    }

    /// Write the lock atomically (temp + rename), creating the owner-only parent — so a
    /// concurrent launch reading it sees the old or the new file, never a torn one.
    fn write(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            use std::fs::DirBuilder;
            use std::os::unix::fs::DirBuilderExt;
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        let mut body = String::new();
        for ((pkg, version, system), pin) in &self.entries {
            body.push_str(&format!(
                "{pkg}\t{version}\t{system}\t{}\t{}\t{}\n",
                pin.commit, pin.attr, pin.version
            ));
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        if let Err(e) = std::fs::write(&tmp, body) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, path)
    }
}

/// Resolve a `nix:` tool to its nixpkgs pin via nixhub. Fetches the package's metadata
/// with nix's own fetcher and selects the release matching `tool.version` on `system`.
/// `Err` when the package is unknown to nixhub, the fetch fails, or no release matches.
pub(crate) fn resolve(
    nix: &Path,
    layout: &Layout,
    tool: &NixTool,
    system: &str,
    fresh: bool,
) -> io::Result<Pin> {
    let metadata = fetch_metadata(nix, layout, &tool.pkg, fresh)?;
    select_release(&metadata, &tool.version, system).ok_or_else(|| {
        io::Error::other(format!(
            "no nixpkgs release of `{}` matches version `{}` for {system}",
            tool.pkg, tool.version
        ))
    })
}

/// Fetch a package's nixhub metadata as JSON. `pkg` is re-validated here so a value
/// that somehow reached this point cannot break out of the request URL, then the GET
/// rides the shared fetcher. Exposed so `ops search` can show an exact match's versions.
pub(crate) fn fetch_metadata(
    nix: &Path,
    layout: &Layout,
    pkg: &str,
    fresh: bool,
) -> io::Result<serde_json::Value> {
    if !is_valid_pkg(pkg) {
        return Err(io::Error::other(format!(
            "refusing to fetch metadata for invalid package name `{pkg}`"
        )));
    }
    // `pkg` is restricted to `[A-Za-z0-9._+-]`, so it carries no quote, `$`, or backslash to
    // escape the quoted nix string. Percent-encode it into the query nonetheless, so a legal `+`
    // reaches nixhub as `%2B` rather than being decoded server-side as a space (a wrong lookup).
    let encoded = super::search::percent_encode(pkg);
    fetch_url_json(nix, layout, &format!("{NIXHUB_BASE}{encoded}"), fresh)
}

/// Fetch a URL's body and parse it as JSON, using nix's `fetchurl` + `readFile` so the
/// request rides nix's own HTTP+TLS fetcher (no added HTTP dependency) and the body
/// lands in ops's own store, never the host's `/nix`. The `{ url; name; }` form gives
/// the store path a fixed name, so a URL carrying a query string — including
/// percent-encoding, whose `%` is illegal in a derived store-path name — fetches
/// cleanly. `url` must already be safe to place in a nix string literal: callers build
/// it from a validated package name or a percent-encoded query, so it carries no quote,
/// `$`, or backslash to escape the expression.
pub(crate) fn fetch_url_json(
    nix: &Path,
    layout: &Layout,
    url: &str,
    fresh: bool,
) -> io::Result<serde_json::Value> {
    let body = fetch_url_bytes(nix, layout, url, fresh)?;
    serde_json::from_slice(&body)
        .map_err(|e| io::Error::other(format!("parsing JSON from {url}: {e}")))
}

/// Fetch a URL's body as raw UTF-8 text (the sibling of [`fetch_url_json`], sharing the same nix
/// `fetchurl` + `readFile` fetch). Used for a plain-text index — an apt `Packages` file — rather
/// than JSON. The same injection constraint applies: `url` must already be safe in a nix string
/// literal (callers charset-validate it first).
pub(crate) fn fetch_url_text(
    nix: &Path,
    layout: &Layout,
    url: &str,
    fresh: bool,
) -> io::Result<String> {
    let body = fetch_url_bytes(nix, layout, url, fresh)?;
    String::from_utf8(body)
        .map_err(|e| io::Error::other(format!("body of {url} is not valid UTF-8: {e}")))
}

/// Fetch a URL's body via nix's `fetchurl` + `readFile`, so the request rides nix's own HTTP+TLS
/// fetcher (no added HTTP dependency) and the body lands in ops's own store, never the host's
/// `/nix`. The `{ url; name; }` form gives the store path a fixed name, so a URL carrying a query
/// string — including percent-encoding, whose `%` is illegal in a derived store-path name — fetches
/// cleanly. `url` must already be safe to place in a nix string literal: callers build it from a
/// validated package name, a percent-encoded query, or a charset-validated URL, so it carries no
/// quote, `$`, or backslash to escape the expression.
fn fetch_url_bytes(nix: &Path, layout: &Layout, url: &str, fresh: bool) -> io::Result<Vec<u8>> {
    let expr = format!(
        "builtins.readFile (builtins.fetchurl {{ url = \"{url}\"; name = \"ops-nixhub\"; }})"
    );
    let mut cmd = store::nix_command(nix, layout);
    cmd.args(["--extra-experimental-features", "nix-command flakes"]);
    // `builtins.fetchurl` caches by `tarball-ttl` (an hour by default), so a repeat within the
    // window returns the OLD body. `ops upgrade` explicitly wants the newest metadata, so it forces
    // a re-fetch with `tarball-ttl 0`; the launch/search paths keep the cache for speed.
    if fresh {
        cmd.args(["--option", "tarball-ttl", "0"]);
    }
    let out = cmd
        .args(["eval", "--impure", "--raw", "--expr", &expr])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "fetching {url} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Select the nixpkgs pin for `version_req` on `system` from a package's nixhub
/// metadata. Only releases that ship a build for `system` are considered (nixhub lists
/// them newest-first). `latest`/`stable`/empty take the newest; otherwise an exact
/// version match wins, falling back to the newest whose version extends the request at
/// a component boundary (so `20` selects the newest `20.x`, `1.6` selects `1.6-bin`).
/// The commit and attribute are validated before they can flow into a flake reference.
/// Pure, so selection is testable against captured metadata.
fn select_release(metadata: &serde_json::Value, version_req: &str, system: &str) -> Option<Pin> {
    let releases = metadata.get("releases")?.as_array()?;
    let compatible: Vec<&serde_json::Value> = releases
        .iter()
        .filter(|r| platform_for(r, system).is_some())
        .collect();
    let chosen = match version_req {
        // nixhub lists releases newest-first, so the newest compatible build is the
        // first one. `stable` is treated as `latest` (nixpkgs releases are stable
        // builds); it does not additionally skip prereleases the way the mise-nix
        // plugin's `stable` does — a deliberate, recorded simplification.
        "" | "latest" | "stable" => *compatible.first()?,
        req => pick_by_version(&compatible, req)?,
    };
    let platform = platform_for(chosen, system)?;
    let commit = platform
        .get("commit_hash")?
        .as_str()
        .filter(|c| is_commit(c))?;
    let attr = platform
        .get("attribute_path")?
        .as_str()
        .filter(|a| is_valid_attr(a))?;
    // validate the resolved version too: it is stored tab-separated in the resolution
    // lock, so it must carry no separator or control character.
    let version = chosen
        .get("version")?
        .as_str()
        .filter(|v| is_valid_version(v))?;
    Some(Pin {
        commit: commit.to_string(),
        attr: attr.to_string(),
        version: version.to_string(),
    })
}

/// Pick a release by version request from `compatible` (newest-first): an exact match
/// wins outright; otherwise the newest whose version extends the request at a `.`/`-`
/// boundary, so `20` matches `20.11.0` but not `200`.
fn pick_by_version<'a>(
    compatible: &[&'a serde_json::Value],
    req: &str,
) -> Option<&'a serde_json::Value> {
    let dotted = format!("{req}.");
    let dashed = format!("{req}-");
    // `compatible` is newest-first, so a forward scan meets the newest match first.
    let mut prefix_match = None;
    for release in compatible.iter() {
        let Some(version) = release.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        if version == req {
            return Some(release);
        }
        if prefix_match.is_none() && (version.starts_with(&dotted) || version.starts_with(&dashed))
        {
            prefix_match = Some(*release);
        }
    }
    prefix_match
}

/// The platform entry of `release` whose `system` matches, or `None` when the release
/// ships no build for it. Exposed so `ops search` reads a release's per-system commit
/// and attribute through the same accessor the resolver uses (no shape drift).
pub(crate) fn platform_for<'a>(
    release: &'a serde_json::Value,
    system: &str,
) -> Option<&'a serde_json::Value> {
    release
        .get("platforms")?
        .as_array()?
        .iter()
        .find(|p| p.get("system").and_then(|s| s.as_str()) == Some(system))
}

/// A nixhub/nixpkgs package name: non-empty and built only from characters a real
/// package name uses, so a declared value cannot smuggle URL- or shell-significant
/// characters into the metadata fetch.
fn is_valid_pkg(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// A requested version: non-empty and restricted to the characters a version or alias
/// uses. A token with a `/` or `@` (a mise idiomatic alias or a flake-ref escape hatch)
/// is out of scope for the nixhub path and is rejected here.
fn is_valid_version(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+' | '~'))
}

/// A nixpkgs attribute path, validated before it flows into a flake reference — the
/// same restriction the native `[packages]` attribute uses.
fn is_valid_attr(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// A nix system double like `x86_64-linux`: non-empty, lowercase alphanumerics plus `_`/`-`. The
/// `system` field is only a lock map key, but validating it too keeps the whole line's provenance
/// clean (a corrupt line self-heals by re-resolution rather than seeding an odd key).
fn is_valid_system(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// A git revision: exactly 40 lowercase hex characters, so nixhub-supplied metadata
/// can never put a malformed value into a `github:NixOS/nixpkgs/<commit>` reference.
fn is_commit(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(entries: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
        entries
            .iter()
            .map(|(n, b)| (n.to_string(), b.as_bytes().to_vec()))
            .collect()
    }

    #[test]
    fn parses_nix_tools_from_toml_and_separates_other_backends() {
        let f = files(&[(
            ".mise.toml",
            "[tools]\n\
             \"nix:nodejs\" = \"20\"\n\
             \"nix:ripgrep\" = \"latest\"\n\
             node = \"18\"\n\
             \"npm:prettier\" = \"3\"\n",
        )]);
        let got = parse_nix_tools(&f);
        assert_eq!(
            got.nix,
            vec![
                NixTool {
                    pkg: "nodejs".into(),
                    version: "20".into()
                },
                NixTool {
                    pkg: "ripgrep".into(),
                    version: "latest".into()
                },
            ]
        );
        // the non-`nix:` backends are kept with their version (the launcher auto-equips
        // them in-cage), never silently dropped
        assert!(got.non_nix.contains(&MiseTool {
            token: "node".into(),
            version: "18".into()
        }));
        assert!(got.non_nix.contains(&MiseTool {
            token: "npm:prettier".into(),
            version: "3".into()
        }));
        assert!(got.malformed.is_empty());
    }

    #[test]
    fn parses_table_and_array_version_shapes() {
        let f = files(&[(
            ".mise.toml",
            "[tools]\n\
             \"nix:python3\" = { version = \"3.12\" }\n\
             \"nix:go\" = [\"1.22\", \"1.21\"]\n",
        )]);
        let got = parse_nix_tools(&f);
        // a TOML table iterates in sorted key order (`go` before `python3`), which is
        // deterministic; ordering across a single file's own tools is not load-bearing
        // (the cross-file precedence is what matters). A table takes its `version` key;
        // an array takes its first element.
        assert_eq!(
            got.nix,
            vec![
                NixTool {
                    pkg: "go".into(),
                    version: "1.22".into()
                },
                NixTool {
                    pkg: "python3".into(),
                    version: "3.12".into()
                },
            ]
        );
    }

    #[test]
    fn parses_tool_versions_lines() {
        let f = files(&[(
            ".tool-versions",
            "# a comment\n\
             nix:nodejs 20.11.0\n\
             \n\
             python 3.12\n",
        )]);
        let got = parse_nix_tools(&f);
        assert_eq!(
            got.nix,
            vec![NixTool {
                pkg: "nodejs".into(),
                version: "20.11.0".into()
            }]
        );
        assert_eq!(
            got.non_nix,
            vec![MiseTool {
                token: "python".into(),
                version: "3.12".into()
            }]
        );
    }

    #[test]
    fn highest_precedence_file_wins_for_a_repeated_token() {
        // files are highest-precedence first; the first declaration of a token wins
        let f = files(&[
            ("mise.local.toml", "[tools]\n\"nix:nodejs\" = \"22\"\n"),
            (".mise.toml", "[tools]\n\"nix:nodejs\" = \"20\"\n"),
        ]);
        let got = parse_nix_tools(&f);
        assert_eq!(
            got.nix,
            vec![NixTool {
                pkg: "nodejs".into(),
                version: "22".into()
            }]
        );
    }

    #[test]
    fn a_malformed_nix_token_is_reported_not_resolved() {
        // a package name carrying a URL-significant character cannot reach the fetch
        let f = files(&[(".mise.toml", "[tools]\n\"nix:bad name\" = \"1\"\n")]);
        let got = parse_nix_tools(&f);
        assert!(got.nix.is_empty());
        // a malformed `nix:` token is reported as such — distinct from a non-`nix:` backend
        assert_eq!(got.malformed, vec!["nix:bad name".to_string()]);
        assert!(got.non_nix.is_empty());
    }

    /// Captured nixhub metadata shape (trimmed), in nixhub's real order — **newest
    /// first**: the newest release (1.7.1) is Darwin-only, then a Linux-only 1.7, then
    /// the oldest 1.6 with both a Linux and a Darwin build. The descending order is what
    /// makes "latest = the newest *compatible* build" a non-trivial assertion.
    fn metadata() -> serde_json::Value {
        serde_json::json!({
            "releases": [
                { "version": "1.7.1", "platforms": [
                    { "system": "aarch64-darwin", "commit_hash": "d".repeat(40), "attribute_path": "jq" }
                ]},
                { "version": "1.7", "platforms": [
                    { "system": "x86_64-linux", "commit_hash": "c".repeat(40), "attribute_path": "jq" }
                ]},
                { "version": "1.6", "platforms": [
                    { "system": "x86_64-linux", "commit_hash": "a".repeat(40), "attribute_path": "jq" },
                    { "system": "aarch64-darwin", "commit_hash": "b".repeat(40), "attribute_path": "jq" }
                ]}
            ]
        })
    }

    #[test]
    fn selects_latest_compatible_release_for_the_system() {
        // 1.7.1 is Darwin-only, so the newest x86_64-linux release is 1.7
        let pin = select_release(&metadata(), "latest", "x86_64-linux").unwrap();
        assert_eq!(pin.version, "1.7");
        assert_eq!(pin.commit, "c".repeat(40));
        assert_eq!(pin.attr, "jq");
    }

    #[test]
    fn selects_an_exact_version_and_its_per_system_commit() {
        let pin = select_release(&metadata(), "1.6", "x86_64-linux").unwrap();
        assert_eq!(pin.version, "1.6");
        assert_eq!(pin.commit, "a".repeat(40));
        // the Darwin commit of the same release is never chosen on Linux
        assert_ne!(pin.commit, "b".repeat(40));
    }

    #[test]
    fn a_bare_major_prefix_matches_the_newest_in_that_series() {
        // `1` extends to the newest compatible `1.x`, here 1.7 (1.7.1 is Darwin-only)
        let pin = select_release(&metadata(), "1", "x86_64-linux").unwrap();
        assert_eq!(pin.version, "1.7");
    }

    #[test]
    fn no_match_or_no_compatible_platform_yields_none() {
        // an unknown version
        assert!(select_release(&metadata(), "9.9", "x86_64-linux").is_none());
        // a system nixhub has no build for
        assert!(select_release(&metadata(), "latest", "riscv64-linux").is_none());
    }

    #[test]
    fn validators_reject_injection_and_malformed_values() {
        assert!(is_valid_pkg("nodejs") && is_valid_pkg("python3") && is_valid_pkg("gcc-unwrapped"));
        for bad in ["", "a b", "a\"b", "a$b", "a/b", "a;b"] {
            assert!(!is_valid_pkg(bad), "{bad} should be rejected");
        }
        assert!(
            is_valid_version("20") && is_valid_version("1.7-bin") && is_valid_version("latest")
        );
        for bad in ["", "lts/iron", "a@b", "a b"] {
            assert!(!is_valid_version(bad), "{bad} should be rejected");
        }
        assert!(is_commit(&"a".repeat(40)));
        assert!(!is_commit(&"A".repeat(40)) && !is_commit("abc") && !is_commit(&"a".repeat(39)));
    }

    #[test]
    fn resolution_lock_roundtrips_and_skips_corrupt_entries() {
        use crate::testutil::TmpDir;
        let dir = TmpDir::new();
        let path = dir.join("tools.lock");

        // an absent lock is empty
        assert!(ResolutionLock::read(&path)
            .get("jq", "latest", "x86_64-linux")
            .is_none());

        // a recorded pin round-trips through write + read
        let pin = Pin {
            commit: "a".repeat(40),
            attr: "jq".into(),
            version: "1.7".into(),
        };
        let mut lock = ResolutionLock::read(&path);
        lock.insert("jq", "latest", "x86_64-linux", &pin);
        lock.write(&path).unwrap();
        assert_eq!(
            ResolutionLock::read(&path).get("jq", "latest", "x86_64-linux"),
            Some(pin)
        );
        // the version request is part of the key, so a different one is a miss
        assert!(ResolutionLock::read(&path)
            .get("jq", "1.6", "x86_64-linux")
            .is_none());

        // a corrupt line (non-hex commit) is skipped, so the entry re-resolves
        std::fs::write(&path, "jq\tlatest\tx86_64-linux\tNOTHEX\tjq\t1.7\n").unwrap();
        assert!(ResolutionLock::read(&path)
            .get("jq", "latest", "x86_64-linux")
            .is_none());
    }
}

/// Resolving against the real nixhub needs the network and a real nix, so this is an
/// integration check: it skips where nix is absent, and otherwise proves the GET +
/// selection yields a well-formed pin for a known package.
#[cfg(test)]
mod resolve_tests {
    use super::*;
    use crate::testutil::TmpDir;

    #[test]
    fn resolves_a_known_package_to_a_pinned_commit_and_attribute() {
        let Some(nix) = store::resolve_nix(None) else {
            eprintln!("skipping nixhub resolution: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());

        let tool = NixTool {
            pkg: "jq".into(),
            version: "latest".into(),
        };
        let pin = match resolve(&nix, &layout, &tool, &current_system(), false) {
            Ok(p) => p,
            Err(e) => {
                // the GET needs the network; treat an unreachable nixhub as a skip
                eprintln!("skipping nixhub resolution: {e}");
                return;
            }
        };
        assert!(
            is_commit(&pin.commit),
            "not a 40-hex commit: {}",
            pin.commit
        );
        assert_eq!(pin.attr, "jq", "jq resolves to the jq attribute");
        assert!(!pin.version.is_empty());
    }

    #[test]
    fn provisions_a_trusted_nix_tool_and_withholds_an_untrusted_one() {
        let Some(nix) = store::resolve_nix(None) else {
            eprintln!("skipping nix-tool provisioning: no nix on PATH");
            return;
        };
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let proj = TmpDir::new();
        // a `nix:` tool ops provisions, beside a non-`nix:` tool the launcher auto-equips
        // in-cage (so `provision` neither realises nor warns about it) and a malformed `nix:`
        // token it does warn about
        let files = vec![(
            ".mise.toml".to_string(),
            b"[tools]\n\"nix:jq\" = \"latest\"\nnode = \"20\"\n\"nix:bad name\" = \"1\"\n".to_vec(),
        )];

        // untrusted: nothing is realised — the nix tool is withheld, the malformed one warned
        let out = provision(&nix, &layout, proj.path(), &files, false, &current_system())
            .expect("untrusted provisioning withholds rather than failing");
        assert!(
            out.bins.is_empty(),
            "an untrusted project provisions no tools"
        );
        assert!(out.roots.is_empty(), "an untrusted project seeds no roots");
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("withholding") && w.contains("jq")));
        // the malformed `nix:` token is reported; the non-`nix:` `node` is NOT (it is
        // auto-equipped by the launcher, not provisioned here)
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("malformed") && w.contains("bad name")));
        assert!(
            !out.warnings.iter().any(|w| w.contains("node")),
            "a non-nix: tool is auto-equipped in-cage, so `provision` must not warn about it"
        );

        // trusted: jq is resolved via nixhub and realised onto a bin dir (needs the net)
        let out = match provision(&nix, &layout, proj.path(), &files, true, &current_system()) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("skipping nix-tool provisioning: {e}");
                return;
            }
        };
        assert_eq!(out.bins.len(), 1, "only the `nix:` tool is provisioned");
        assert_eq!(out.roots.len(), 1, "the provisioned tool surfaces one root");
        assert!(
            store::physical_path(&layout, &out.bins[0])
                .join("jq")
                .exists(),
            "jq missing from the provisioned bin dir"
        );
        // the surfaced root is the logical store path the bin dir sits under
        assert_eq!(out.bins[0], out.roots[0].join("bin"));
        // the resolution was locked, so a later launch need not query nixhub again
        let projects = layout.data_dir().join("projects");
        let locked = std::fs::read_dir(&projects)
            .map(|dir| dir.flatten().any(|e| e.path().join("tools.lock").is_file()))
            .unwrap_or(false);
        assert!(locked, "the tool resolution was not written to a lock");
    }

    #[test]
    fn an_untrusted_projects_nix_tools_are_withheld_without_invoking_nix() {
        // The trust-boundary property — an untrusted project's `nix:` tools are withheld — is
        // decided BEFORE any nix is invoked, so it is verifiable in the pipeline (no `resolve_nix`
        // skip) with a bogus nix path. A regression that dropped the gate would now fail in CI.
        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let proj = TmpDir::new();
        let files = vec![(
            ".mise.toml".to_string(),
            b"[tools]\n\"nix:jq\" = \"latest\"\nnode = \"20\"\n\"nix:bad name\" = \"1\"\n".to_vec(),
        )];
        let out = provision(
            Path::new("/nonexistent/ops-test-nix"),
            &layout,
            proj.path(),
            &files,
            false,
            &current_system(),
        )
        .expect("untrusted provisioning withholds rather than failing, touching no nix");
        assert!(
            out.bins.is_empty(),
            "an untrusted project provisions no tools"
        );
        assert!(out.roots.is_empty(), "an untrusted project seeds no roots");
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("withholding") && w.contains("jq")));
        assert!(out
            .warnings
            .iter()
            .any(|w| w.contains("malformed") && w.contains("bad name")));
    }

    #[test]
    fn upgrade_tools_classifies_prunes_and_is_best_effort() {
        use crate::store::Layout;
        use crate::testutil::TmpDir;

        let data = TmpDir::new();
        let layout = Layout::under(data.path());
        let project = TmpDir::new();
        let system = current_system();

        // Seed the per-project lock the same way the launcher would, then drive an
        // upgrade. A non-existent nix makes every re-resolution fail, so each branch is
        // exercised offline: the exact-locked tool skips the query, the floating ones take
        // the best-effort path keeping their prior pin, and the stale entry is pruned.
        let id = super::super::binds::project_runtime_id(project.path()).expect("project id");
        let lock_path = layout
            .data_dir()
            .join("projects")
            .join(&id)
            .join(TOOLS_LOCK);
        let commit = "a".repeat(40);
        let pin = |v: &str| Pin {
            commit: commit.clone(),
            attr: "x".to_string(),
            version: v.to_string(),
        };
        let mut seed = ResolutionLock::read(Path::new("/nonexistent-seed"));
        seed.insert("jq", "1.7.1", &system, &pin("1.7.1")); // exact-locked → Unchanged, no query
        seed.insert("ripgrep", "latest", &system, &pin("14.1.0")); // floating-locked → Failed, kept
        seed.insert("oldtool", "1.0", &system, &pin("1.0")); // not declared → Pruned
        seed.insert("jq", "1.7.1", "x999-other", &pin("1.7.1")); // other system → kept silently
        seed.write(&lock_path).expect("seed the lock");

        let mise_files = vec![(
            ".mise.toml".to_string(),
            "[tools]\n\
             \"nix:jq\" = \"1.7.1\"\n\
             \"nix:ripgrep\" = \"latest\"\n\
             \"nix:newtool\" = \"latest\"\n\
             node = \"18\"\n"
                .as_bytes()
                .to_vec(),
        )];

        let bogus_nix = Path::new("/nonexistent/ops-test-nix");
        let outcomes = upgrade_tools(bogus_nix, &layout, project.path(), &mise_files, &system)
            .expect("upgrade_tools rewrites the lock");

        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ToolUpgrade::Unchanged { pkg, .. } if pkg == "jq")),
            "an exact-locked tool is unchanged without a query: {outcomes:?}"
        );
        assert!(
            outcomes.iter().any(|o| matches!(
                o,
                ToolUpgrade::Failed { pkg, kept: Some(v), .. } if pkg == "ripgrep" && v == "14.1.0"
            )),
            "a floating-locked tool that fails to re-resolve keeps its pin: {outcomes:?}"
        );
        assert!(
            outcomes.iter().any(|o| matches!(
                o,
                ToolUpgrade::Failed { pkg, kept: None, .. } if pkg == "newtool"
            )),
            "an unlocked tool that fails to re-resolve is reported with no pin: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ToolUpgrade::Pruned { pkg, .. } if pkg == "oldtool")),
            "an undeclared entry on this system is pruned: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, ToolUpgrade::Ignored { token, mise_managed: true } if token == "node")),
            "a non-nix: backend is reported as mise-managed, never silently dropped: {outcomes:?}"
        );
        assert!(
            !outcomes
                .iter()
                .any(|o| matches!(o, ToolUpgrade::Pruned { pkg, .. } if pkg == "jq")),
            "the other-system entry must not be pruned: {outcomes:?}"
        );

        // The persisted lock reflects the same decisions.
        let after = ResolutionLock::read(&lock_path);
        assert!(
            after.get("jq", "1.7.1", &system).is_some(),
            "the declared current-system tool stays"
        );
        assert!(
            after.get("jq", "1.7.1", "x999-other").is_some(),
            "another host's still-valid pin is preserved"
        );
        assert!(
            after.get("ripgrep", "latest", &system).is_some(),
            "a failed re-resolution keeps the prior pin (best effort)"
        );
        assert!(
            after.get("oldtool", "1.0", &system).is_none(),
            "the stale entry was pruned from the lock"
        );
        assert!(
            after.get("newtool", "latest", &system).is_none(),
            "a tool that never resolved is not written to the lock"
        );
    }
}
