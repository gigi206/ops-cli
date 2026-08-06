//! `sbx upgrade [all|nix|mise|flake|deb|appimage|tarball] [--project <path>]`: roll the managed
//! channels and `[packages]` backends forward by re-resolving and rewriting their locks, so
//! versions advance only on an explicit upgrade, never on an sbx binary update. `--project`
//! retargets every roll at another project, exactly as running the command from that directory
//! would. The lock-rewriting parts need nix to resolve but not the sandbox boundary; the in-cage
//! `mise:` roll needs the cage and degrades to a warning where it is unavailable.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{config, diag, help, sandbox, short_rev, store, style, trust};

/// The known upgrade targets. Kept as one list so the parser and the error message cannot drift.
const TARGETS: &[&str] = &["all", "nix", "mise", "flake", "deb", "appimage", "tarball"];

/// Map a target word to its `'static` spelling, so a parsed target outlives the borrowed argv.
fn known_target(s: &str) -> Option<&'static str> {
    TARGETS.iter().copied().find(|&t| t == s)
}

/// The outcome of parsing `sbx upgrade`'s arguments: show help, run with a resolved target and an
/// optional `--project` path, or a usage error (already-formatted message, exit 2).
#[derive(Debug, PartialEq)]
enum ParsedArgs {
    Help,
    Run {
        what: &'static str,
        project: Option<OsString>,
    },
    Error(String),
}

/// Parse an optional target word and an optional `--project <path>`, in any order. Pure — no I/O —
/// so the grammar (default target, duplicate/second-token rejection, the `--project`/`--project=`
/// value forms) is unit-tested without invoking nix or the sandbox. A present-but-unrecognized
/// target (including one that is not valid UTF-8) is an error, not a silent fall-through to `all`.
fn parse_upgrade_args(args: &[OsString]) -> ParsedArgs {
    let mut what: Option<&'static str> = None;
    let mut project: Option<OsString> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.to_str() {
            Some("--help" | "-h") => return ParsedArgs::Help,
            // `--project <path>`: the value is the next argument, kept as a raw `OsString` so a
            // non-UTF-8 path survives.
            Some("--project") => {
                let Some(val) = args.get(i + 1) else {
                    return ParsedArgs::Error(
                        "sbx: upgrade: --project needs a directory path.".into(),
                    );
                };
                if project.is_some() {
                    return ParsedArgs::Error(
                        "sbx: upgrade: --project given more than once.".into(),
                    );
                }
                project = Some(val.clone());
                i += 2;
            }
            // `--project=<path>`: the value is inline (UTF-8 only; use the space form for a
            // non-UTF-8 path).
            Some(s) if s.starts_with("--project=") => {
                let val = &s["--project=".len()..];
                if val.is_empty() {
                    return ParsedArgs::Error(
                        "sbx: upgrade: --project needs a directory path.".into(),
                    );
                }
                if project.is_some() {
                    return ParsedArgs::Error(
                        "sbx: upgrade: --project given more than once.".into(),
                    );
                }
                project = Some(OsString::from(val));
                i += 1;
            }
            Some(s) if known_target(s).is_some() => {
                // A second target is rejected, not silently swallowed (so `sbx upgrade nix mise`
                // does not roll only `nix`).
                if what.is_some() {
                    return ParsedArgs::Error(format!("sbx: usage: {}", help::synopsis("upgrade")));
                }
                what = known_target(s);
                i += 1;
            }
            _ => {
                return ParsedArgs::Error(format!(
                    "sbx: unknown upgrade target '{}' (known: {})",
                    arg.to_string_lossy(),
                    TARGETS.join(", ")
                ));
            }
        }
    }
    ParsedArgs::Run {
        what: what.unwrap_or("all"),
        project,
    }
}

/// `sbx upgrade [all|nix|mise] [--project <path>]`: roll managed channels forward by
/// re-resolving and rewriting their locks, so versions advance only here, never on an sbx
/// binary update. `nix` rolls the nixpkgs channel the target directory tracks (a trusted
/// project pin, else the global channel) — base and native `nix:` `[packages]`. `mise` rolls
/// the mise engine (its own dedicated lock), the project's `nix:` tools, and the project's and
/// apps' `mise:` `[packages]` (the last in-cage). `all` rolls every one. `--project <path>`
/// runs the whole thing against another project instead of the current directory. The
/// lock-rewriting parts need nix (to resolve) but not the sandbox boundary; the in-cage `mise:`
/// roll needs the sandbox and degrades to a warning where it is unavailable.
pub(crate) fn upgrade_cmd(args: Vec<OsString>) -> ExitCode {
    // Parse an optional target word and an optional `--project <path>`, in any order, before
    // touching anything so a typo fails cleanly.
    let (what, project_arg) = match parse_upgrade_args(&args) {
        ParsedArgs::Help => return help::show(&["upgrade"]),
        ParsedArgs::Run { what, project } => (what, project),
        ParsedArgs::Error(message) => {
            diag::error(&message);
            return ExitCode::from(2);
        }
    };

    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot resolve the data directory (no $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME).",
        );
        return ExitCode::FAILURE;
    };
    let Some(nix) = store::resolve_nix(Some(&layout)) else {
        diag::error("sbx: nix not found — cannot upgrade. See `sbx doctor`.");
        return ExitCode::FAILURE;
    };
    // `--project <path>` retargets the whole upgrade at another project — exactly as `cd <path>
    // && sbx upgrade` would: the path is canonicalized (so the per-project lock derivation matches
    // a launch from there) and every roll below reads its config and rewrites its locks. Default
    // is the current directory.
    let cwd = match &project_arg {
        Some(path) => match std::fs::canonicalize(path) {
            Ok(canon) if canon.is_dir() => canon,
            Ok(canon) => {
                diag::error(&format!(
                    "sbx: upgrade: --project is not a directory: {}",
                    canon.display()
                ));
                return ExitCode::from(2);
            }
            Err(e) => {
                diag::error(&format!(
                    "sbx: upgrade: --project {}: {e}",
                    Path::new(path).display()
                ));
                return ExitCode::from(2);
            }
        },
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                diag::error(&format!("sbx: cannot read the current directory: {e}"));
                return ExitCode::FAILURE;
            }
        },
    };

    // Load the config so a project pin — and any reason one was dropped — is honored
    // exactly as a launch would; surfacing the warnings explains a pin that did not
    // take (so an untrusted pin silently rolling the global channel is never a mystery).
    let cfg = config::load(&cwd);
    for warning in &cfg.warnings {
        diag::warn(warning);
    }

    // `all` rolls every managed channel and reports the worst exit — a tool that fails to
    // re-resolve must not be masked by a clean roll elsewhere. `mise` rolls three distinct
    // things: the engine (host-global, in every cage, so it rolls regardless of any project's
    // trust), the project's `nix:` tools (trusted-only), and the project's and apps' `mise:`
    // `[packages]` (in-cage, trusted-only). Rolling them as separate, unconditional calls keeps
    // the engine's trust-independence structural rather than dependent on an earlier path not
    // early-returning.
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut ok = true;
    if matches!(what, "nix" | "all") {
        ok &= upgrade_nix_channel(&nix, &layout, &cwd, &cfg, &pal);
    }
    if matches!(what, "mise" | "all") {
        ok &= upgrade_mise_engine(&nix, &layout, &cfg, &pal);
        ok &= upgrade_mise_tools(&nix, &layout, &cwd, &cfg, &pal);
        // The project's and apps' `mise:` `[packages]` are equipped in-cage, not host-side, so
        // their roll runs `mise upgrade` inside a cage (per home) rather than rewriting a lock.
        // Pass the target directory and its already-loaded config: the groups are computed from the
        // config before any sandbox work (so a project with no `mise:` package keeps this cheap and
        // sandbox-free), and the cage is built against `cwd` so `--project` retargets it too.
        ok &= sandbox::upgrade_mise_packages(&cwd, &cfg, &pal);
    }
    if matches!(what, "flake" | "all") {
        // The project's and apps' `flake:` `[packages]` re-resolve to a fixed revision and the
        // per-project flake lock is rewritten — a host-side lock rewrite (the new pin builds
        // in-cage at the next launch), like the `nix:` tools.
        ok &= upgrade_flake_packages(&nix, &layout, &cwd, &cfg, &pal);
    }
    if matches!(what, "deb" | "all") {
        // The project's and apps' `deb:` `[packages]` re-resolve their `.deb` URL to a new content
        // hash and the per-project deb lock is rewritten — a host-side lock rewrite (the new hash
        // builds host-side at the next launch), like the `nix:` tools and `flake:` packages.
        ok &= upgrade_deb_packages(&nix, &layout, &cwd, &cfg, &pal);
    }
    if matches!(what, "appimage" | "all") {
        // The project's and apps' `appimage:` `[packages]` re-resolve their `.AppImage` URL to a new
        // content hash and the per-project appimage lock is rewritten — the exact `deb:` shape.
        ok &= upgrade_appimage_packages(&nix, &layout, &cwd, &cfg, &pal);
    }
    if matches!(what, "tarball" | "all") {
        // The project's and apps' `tarball:` `[packages]` re-resolve their `.tar.gz` URL to a new
        // content hash and the per-project tarball lock is rewritten — the exact `deb:` shape.
        ok &= upgrade_tarball_packages(&nix, &layout, &cwd, &cfg, &pal);
    }
    // A roll is what eventually supersedes a build. Point the user at `sbx gc --prune` when the
    // project's store is already holding superseded builds — cheap, filesystem-only, and silent
    // when there is nothing to reclaim (see the function).
    sandbox::superseded_reclaimable_hint(&layout, &cwd, &cfg, &pal);

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Roll the nixpkgs channel the current directory tracks — a trusted project pin, else
/// the global channel — forcing a fresh resolution and rewriting that lock. Returns
/// whether it succeeded; the base and `[packages]` download on the next launch.
fn upgrade_nix_channel(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let target = match sandbox::effective_lock_target(cwd, layout, cfg) {
        Ok(t) => t,
        Err(e) => {
            diag::error(&format!("sbx: cannot resolve the channel target: {e}"));
            return false;
        }
    };
    let upgrade = match target.refresh(nix, layout) {
        Ok(u) => u,
        Err(e) => {
            diag::error(&format!("sbx: cannot upgrade the nixpkgs channel: {e}"));
            return false;
        }
    };
    for line in channel_upgrade_summary(
        "sbx upgrade — nix channel",
        "channel",
        "the new base and tools download",
        target.origin().label(),
        &upgrade,
        pal,
    ) {
        println!("{line}");
    }
    true
}

/// Roll the mise engine: force a fresh resolution of its dedicated lock (the global
/// channel source, in `mise-engine.lock`) and rewrite it, so the engine advances
/// independently of the base channel that `sbx upgrade nix` rolls. Host-global and
/// present in every cage, so it rolls regardless of any project's trust — unlike the
/// project's `nix:` tools. Returns whether it succeeded; the new engine is provisioned
/// on the next launch.
fn upgrade_mise_engine(
    nix: &Path,
    layout: &store::Layout,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let target = store::LockTarget::engine(layout, cfg.nixpkgs_global.as_deref());
    let upgrade = match target.refresh(nix, layout) {
        Ok(u) => u,
        Err(e) => {
            diag::error(&format!("sbx: cannot upgrade the mise engine: {e}"));
            return false;
        }
    };
    for line in channel_upgrade_summary(
        "sbx upgrade — mise engine",
        "engine",
        "the new engine is provisioned",
        target.origin().label(),
        &upgrade,
        pal,
    ) {
        println!("{line}");
    }
    true
}

/// Roll the project's `nix:` mise tools: re-resolve the floating pins against nixhub and
/// prune stale entries, rewriting the per-project resolution lock. Returns whether it
/// succeeded — a tool that fails to re-resolve keeps its prior pin and makes this `false`,
/// but never aborts the others. Trusted-only, mirroring how the tools are provisioned: an
/// untrusted project's tools are never locked, so there is nothing to roll.
fn upgrade_mise_tools(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let Some(mise) = &cfg.mise else {
        for line in upgrade_tools_summary(&[], pal) {
            println!("{line}");
        }
        return true;
    };
    if mise.state != trust::TrustState::Trusted {
        diag::warn(&format!(
            "mise file `{}` withheld ({}): its `nix:` tools are not rolled",
            mise.name,
            config::untrusted_reason(mise.state)
        ));
        return true;
    }
    let outcomes =
        match sandbox::upgrade_tools(nix, layout, cwd, &mise.files, &sandbox::current_system()) {
            Ok(o) => o,
            Err(e) => {
                diag::error(&format!("sbx: cannot roll the mise tools: {e}"));
                return false;
            }
        };
    for line in upgrade_tools_summary(&outcomes, pal) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::ToolUpgrade::Failed { .. }))
}

/// The human-readable summary of a mise tools roll: one line per declared tool (rolled,
/// unchanged, newly pinned, or failed), the entries pruned, and any token sbx does not
/// handle. Pure, so every outcome is unit-tested without invoking nix.
fn upgrade_tools_summary(outcomes: &[sandbox::ToolUpgrade], pal: &style::Palette) -> Vec<String> {
    use sandbox::ToolUpgrade::*;
    let (h, n, ok, warn, err, dim, r) = (
        pal.head, pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset,
    );
    let mut lines = vec![format!("{h}sbx upgrade — mise tools{r}")];
    if outcomes.is_empty() {
        lines.push(format!("  {dim}no nix: tools to roll.{r}"));
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { pkg, version, .. } => {
                format!("  {n}nix:{pkg}{r}: {n}{version}{r} — {dim}unchanged.{r}")
            }
            Rolled { pkg, from, to, .. } => {
                format!("  {n}nix:{pkg}{r}: {n}{from}{r} → {n}{to}{r} — {ok}rolled forward.{r}")
            }
            Pinned { pkg, version, .. } => {
                format!("  {n}nix:{pkg}{r}: {n}{version}{r} — {ok}newly pinned.{r}")
            }
            Failed {
                pkg, error, kept, ..
            } => match kept {
                Some(v) => format!(
                    "  {n}nix:{pkg}{r}: {err}re-resolve failed{r}, kept {n}{v}{r} — {error}"
                ),
                None => format!("  {n}nix:{pkg}{r}: {err}re-resolve failed{r} — {error}"),
            },
            Pruned { pkg, request } => format!(
                "  {n}nix:{pkg}{r} ({request}): {dim}removed from the lock (no longer declared).{r}"
            ),
            Ignored {
                token,
                mise_managed,
            } => {
                if *mise_managed {
                    format!("  {n}{token}{r}: {dim}equipped in-cage by mise — not rolled here.{r}")
                } else {
                    format!("  {n}{token}{r}: {warn}malformed nix: token{r} — cannot resolve.")
                }
            }
        });
    }
    lines
}

/// Roll the project's and its apps' `flake:` `[packages]`: re-resolve each declared reference to
/// its current immutable revision and rewrite the per-project flake lock (pinning, rolling, and
/// pruning). Returns whether it succeeded — a reference that fails to re-resolve keeps its prior
/// pin and makes this `false`, but never aborts the others. Trusted-only, like the `nix:` tools:
/// an untrusted project's flake reference is never collected, so there is nothing to roll. Needs
/// nix (to resolve) but not the sandbox boundary — the new pin builds in-cage at the next launch.
fn upgrade_flake_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_flake(nix, layout, cwd, cfg) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the flake packages: {e}"));
            return false;
        }
    };
    for line in flake_upgrade_summary(&outcomes, sandbox::withheld_flake_packages(cfg), pal) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::FlakeUpgrade::Failed { .. }))
}

/// The human-readable summary of a flake roll: one line per declared reference (newly pinned,
/// rolled, unchanged, or failed) plus the entries pruned, and a note for any reference withheld
/// for being untrusted (so an untrusted project does not read as "none declared" — parity with
/// the `nix:` tools path). Pure, so every outcome is unit-tested without invoking nix.
fn flake_upgrade_summary(
    outcomes: &[sandbox::FlakeUpgrade],
    withheld: usize,
    pal: &style::Palette,
) -> Vec<String> {
    use sandbox::FlakeUpgrade::*;
    let (h, n, ok, warn, err, dim, r) = (
        pal.head, pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset,
    );
    let mut lines = vec![format!("{h}sbx upgrade — flake packages{r}")];
    let withheld_note = || {
        style::prose(
            &format!(
                "  {warn}{withheld} flake: package(s) withheld (untrusted){r} — not rolled; \
                 run `sbx trust`."
            ),
            pal,
        )
    };
    if outcomes.is_empty() {
        lines.push(if withheld > 0 {
            withheld_note()
        } else {
            format!("  {dim}no flake: packages to roll.{r}")
        });
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { reference, rev } => format!(
                "  {n}flake:{reference}{r}: {n}{}{r} — {dim}unchanged.{r}",
                short_rev(rev)
            ),
            Rolled {
                reference,
                from,
                to,
            } => format!(
                "  {n}flake:{reference}{r}: {n}{}{r} → {n}{}{r} — {ok}rolled forward.{r}",
                short_rev(from),
                short_rev(to)
            ),
            Pinned { reference, rev } => format!(
                "  {n}flake:{reference}{r}: {n}{}{r} — {ok}newly pinned.{r}",
                short_rev(rev)
            ),
            Pruned { reference } => format!(
                "  {n}flake:{reference}{r}: {dim}removed from the lock (no longer declared).{r}"
            ),
            Failed {
                reference,
                error,
                kept,
            } => match kept {
                Some(rev) => format!(
                    "  {n}flake:{reference}{r}: {err}re-resolve failed{r}, kept {n}{}{r} — {error}",
                    short_rev(rev)
                ),
                None => {
                    format!("  {n}flake:{reference}{r}: {err}re-resolve failed{r} — {error}")
                }
            },
        });
    }
    if withheld > 0 {
        lines.push(withheld_note());
    }
    lines
}

/// Roll the project's and apps' `deb:` `[packages]`: re-resolve each `.deb` URL to its current
/// content hash and rewrite the per-project deb lock (the new hash builds host-side at the next
/// launch), like the `nix:` tools and `flake:` packages. Returns whether every reference re-resolved.
fn upgrade_deb_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_deb(nix, layout, cwd, cfg) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the deb packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary("deb", &outcomes, sandbox::withheld_deb_packages(cfg), pal)
    {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::DebUpgrade::Failed { .. }))
}

/// A short, recognisable form of an SRI content hash for display (`sha256-<base64>` → the first
/// few base64 characters), the deb analogue of a short git revision.
fn short_hash(hash: &str) -> &str {
    let body = hash.strip_prefix("sha256-").unwrap_or(hash);
    &body[..body.len().min(8)]
}

/// The human-readable summary of a prebuilt roll, shared by the three backends that pin a URL to a
/// content hash — `deb:`, `appimage:` and `tarball:`, whose outcomes are one and the same type. One
/// line per declared URL (newly pinned, rolled, unchanged, or failed) plus the entries pruned, and a
/// note for any reference withheld for being untrusted (so an untrusted project does not read as
/// "none declared"). `kind` is the backend's own word and the only thing that separates the three
/// reports: it names the heading, the token each line carries, and both notes — the same way
/// `channel_upgrade_summary` below is told its heading rather than being written twice. Pure, so
/// every outcome is unit-tested without invoking nix.
fn prebuilt_upgrade_summary(
    kind: &str,
    outcomes: &[sandbox::PrebuiltUpgrade],
    withheld: usize,
    pal: &style::Palette,
) -> Vec<String> {
    use sandbox::PrebuiltUpgrade::*;
    let (h, n, ok, warn, err, dim, r) = (
        pal.head, pal.name, pal.ok, pal.warn, pal.err, pal.dim, pal.reset,
    );
    let mut lines = vec![format!("{h}sbx upgrade — {kind} packages{r}")];
    let withheld_note = || {
        style::prose(
            &format!(
                "  {warn}{withheld} {kind}: package(s) withheld (untrusted){r} — not rolled; \
                 run `sbx trust`."
            ),
            pal,
        )
    };
    if outcomes.is_empty() {
        lines.push(if withheld > 0 {
            withheld_note()
        } else {
            format!("  {dim}no {kind}: packages to roll.{r}")
        });
        return lines;
    }
    for outcome in outcomes {
        lines.push(match outcome {
            Unchanged { url, hash } => format!(
                "  {n}{kind}:{url}{r}: {n}{}{r} — {dim}unchanged.{r}",
                short_hash(hash)
            ),
            Rolled { url, from, to } => format!(
                "  {n}{kind}:{url}{r}: {n}{}{r} → {n}{}{r} — {ok}rolled forward.{r}",
                short_hash(from),
                short_hash(to)
            ),
            Pinned { url, hash } => format!(
                "  {n}{kind}:{url}{r}: {n}{}{r} — {ok}newly pinned.{r}",
                short_hash(hash)
            ),
            Pruned { url } => {
                format!("  {n}{kind}:{url}{r}: {dim}removed from the lock (no longer declared).{r}")
            }
            Failed { url, error } => {
                format!("  {n}{kind}:{url}{r}: {err}re-resolve failed{r} — {error}")
            }
        });
    }
    if withheld > 0 {
        lines.push(withheld_note());
    }
    lines
}

/// Roll the project's and apps' `appimage:` `[packages]` — the `deb:` twin, re-resolving each
/// `.AppImage` URL to its current content hash and rewriting the per-project appimage lock. Returns
/// whether every reference re-resolved.
fn upgrade_appimage_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_appimage(nix, layout, cwd, cfg) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the appimage packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary(
        "appimage",
        &outcomes,
        sandbox::withheld_appimage_packages(cfg),
        pal,
    ) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::AppImageUpgrade::Failed { .. }))
}

/// Roll the project's and apps' `tarball:` `[packages]` — the `deb:` twin, re-resolving each archive
/// URL to its current content hash and rewriting the per-project tarball lock. Returns whether every
/// reference re-resolved.
fn upgrade_tarball_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_tarball(nix, layout, cwd, cfg) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the tarball packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary(
        "tarball",
        &outcomes,
        sandbox::withheld_tarball_packages(cfg),
        pal,
    ) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::TarballUpgrade::Failed { .. }))
}

/// The human-readable summary of a channel-style roll (the nix channel or the mise
/// engine): the `heading`, the source under its `item` word (channel/engine) and where it
/// came from, then what changed — a first resolution, an unchanged channel, a fixed
/// revision that cannot roll, or a roll-forward — naming what `downloads`/re-provisions on
/// the next launch. Pure, so every outcome is unit-tested without invoking nix.
fn channel_upgrade_summary(
    heading: &str,
    item: &str,
    downloads: &str,
    origin: &str,
    up: &store::Upgrade,
    pal: &style::Palette,
) -> Vec<String> {
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut lines = vec![
        format!("{h}{heading}{r}"),
        format!("  {item}: {n}{}{r}  ({dim}{origin}{r})", up.source),
    ];
    let outcome = match &up.previous {
        None => format!(
            "  resolved to {n}{}{r} {ok}(first pin){r} — {downloads} on the next launch.",
            short_rev(&up.revision)
        ),
        Some(prev) if prev == &up.revision && store::is_pinned_revision(&up.source) => format!(
            "  pinned to a fixed revision {n}{}{r} — {dim}nothing to roll.{r}",
            short_rev(&up.revision)
        ),
        Some(prev) if prev == &up.revision => format!(
            "  already at the latest revision {n}{}{r} — {dim}nothing to do.{r}",
            short_rev(&up.revision)
        ),
        Some(prev) => format!(
            "  {ok}rolled forward{r} {n}{}{r} → {n}{}{r} — {downloads} on the next launch.",
            short_rev(prev),
            short_rev(&up.revision)
        ),
    };
    lines.push(outcome);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TmpDir;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn parse_defaults_to_all_with_no_args() {
        assert_eq!(
            parse_upgrade_args(&[]),
            ParsedArgs::Run {
                what: "all",
                project: None
            }
        );
    }

    #[test]
    fn parse_accepts_a_bare_target() {
        for t in TARGETS {
            assert_eq!(
                parse_upgrade_args(&os(&[t])),
                ParsedArgs::Run {
                    what: t,
                    project: None
                }
            );
        }
    }

    #[test]
    fn parse_reads_project_in_both_forms_and_either_order() {
        let want = ParsedArgs::Run {
            what: "deb",
            project: Some(OsString::from("/some/dir")),
        };
        // space form, target first
        assert_eq!(
            parse_upgrade_args(&os(&["deb", "--project", "/some/dir"])),
            want
        );
        // space form, flag first
        assert_eq!(
            parse_upgrade_args(&os(&["--project", "/some/dir", "deb"])),
            want
        );
        // inline form
        assert_eq!(
            parse_upgrade_args(&os(&["deb", "--project=/some/dir"])),
            want
        );
        // `--project` alone keeps the default `all` target
        assert_eq!(
            parse_upgrade_args(&os(&["--project", "/some/dir"])),
            ParsedArgs::Run {
                what: "all",
                project: Some(OsString::from("/some/dir"))
            }
        );
    }

    #[test]
    fn parse_help_wins_and_bad_input_is_an_error() {
        assert_eq!(parse_upgrade_args(&os(&["--help"])), ParsedArgs::Help);
        assert_eq!(parse_upgrade_args(&os(&["-h"])), ParsedArgs::Help);
        // an unknown target
        assert!(matches!(
            parse_upgrade_args(&os(&["frob"])),
            ParsedArgs::Error(_)
        ));
        // two targets
        assert!(matches!(
            parse_upgrade_args(&os(&["nix", "mise"])),
            ParsedArgs::Error(_)
        ));
        // `--project` with no value
        assert!(matches!(
            parse_upgrade_args(&os(&["--project"])),
            ParsedArgs::Error(_)
        ));
        // `--project=` empty value
        assert!(matches!(
            parse_upgrade_args(&os(&["--project="])),
            ParsedArgs::Error(_)
        ));
        // `--project` twice
        assert!(matches!(
            parse_upgrade_args(&os(&["--project", "/a", "--project", "/b"])),
            ParsedArgs::Error(_)
        ));
    }

    #[test]
    fn upgrade_summary_distinguishes_the_outcomes() {
        let rev = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
        let newer = "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c";
        let text = |up| {
            channel_upgrade_summary(
                "sbx upgrade — nix channel",
                "channel",
                "the new base and tools download",
                "default",
                &up,
                &style::Palette::plain(),
            )
            .join("\n")
        };

        // a first resolution
        assert!(text(store::Upgrade {
            source: "nixos-unstable".into(),
            previous: None,
            revision: rev.into(),
        })
        .contains("first pin"));

        // an unchanged channel
        assert!(text(store::Upgrade {
            source: "nixos-unstable".into(),
            previous: Some(rev.into()),
            revision: rev.into(),
        })
        .contains("already at the latest"));

        // a fixed revision pin cannot roll
        assert!(text(store::Upgrade {
            source: rev.into(),
            previous: Some(rev.into()),
            revision: rev.into(),
        })
        .contains("fixed revision"));

        // a roll-forward shows old → new
        let rolled = text(store::Upgrade {
            source: "nixos-unstable".into(),
            previous: Some(rev.into()),
            revision: newer.into(),
        });
        assert!(rolled.contains("rolled forward"));
        assert!(rolled.contains("9ae611a") && rolled.contains("1c1c1c1"));

        // the same renderer, parameterised for the mise engine: a distinct heading, the
        // `engine` item word, and the engine-specific "provisioned" tail — so the two
        // roll commands read differently.
        let engine = channel_upgrade_summary(
            "sbx upgrade — mise engine",
            "engine",
            "the new engine is provisioned",
            "default",
            &store::Upgrade {
                source: "nixos-unstable".into(),
                previous: Some(rev.into()),
                revision: newer.into(),
            },
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(engine.contains("mise engine"));
        assert!(engine.contains("engine: nixos-unstable"));
        assert!(engine.contains("the new engine is provisioned"));
        assert!(!engine.contains("base and tools"));

        // Colored: the heading rides the head span and the roll-forward outcome the ok span,
        // each closed by a reset — the feature a captured (plain) stream never exercises.
        let p = style::Palette::colored();
        let colored = channel_upgrade_summary(
            "sbx upgrade — nix channel",
            "channel",
            "the new base and tools download",
            "default",
            &store::Upgrade {
                source: "nixos-unstable".into(),
                previous: Some(rev.into()),
                revision: newer.into(),
            },
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}sbx upgrade — nix channel{}", p.head, p.reset)));
        assert!(colored.contains(&format!("{}rolled forward{}", p.ok, p.reset)));
    }

    #[test]
    fn upgrade_mise_and_upgrade_nix_roll_separate_locks() {
        // The decoupling guarantee at the file level: rolling the engine must leave the
        // base channel lock byte-identical, and rolling the base must leave the engine
        // lock byte-identical. Proven deterministically with revision sources, which
        // resolve without nix — so a bogus nix path is never invoked. The roll mechanics
        // are already covered by store.rs's `refresh*` tests (which `LockTarget::engine`
        // reuses verbatim); what is net-new here is that the two commands write two
        // distinct files.
        let bogus_nix = Path::new("/nonexistent-nix");
        let rev_a = "a".repeat(40);
        let rev_b = "b".repeat(40);
        let cfg = |global: &str| config::Resolved {
            fs: Default::default(),
            fs_origin: crate::config::Provenance::Default,
            notify: Default::default(),
            notify_origin: Default::default(),
            ssh_agent_confirm: false,
            env: vec![],
            env_layer: Default::default(),
            binds: vec![],
            bind_layer: Default::default(),
            packages: vec![],
            nixpkgs_global: Some(global.to_string()),
            nixpkgs_project: None,
            mise: None,
            network: config::NetworkPolicy::Shared,
            network_origin: Default::default(),
            egress_stats: true,
            gui: config::GuiPolicy::default(),
            gui_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gpu: false,
            audio: false,
            dbus: false,
            gpu_origin: Default::default(),
            audio_origin: Default::default(),
            dbus_origin: Default::default(),
            forward: vec![],
            forward_origin: Default::default(),
            limits: Default::default(),
            limits_origin: Default::default(),
            secrets: vec![],
            tasks: vec![],
            seccomp: Default::default(),
            seccomp_origin: Default::default(),
            devices: Vec::new(),
            devices_origin: Default::default(),
            ssh_agent: vec![],
            ssh_agent_origin: Default::default(),
            declared_secrets: vec![],
            apps: std::collections::BTreeMap::new(),
            warnings: vec![],
        };

        let data = TmpDir::new();
        let layout = store::Layout::under(data.path());
        std::fs::create_dir_all(layout.data_dir()).unwrap();
        let nix_lock = layout.data_dir().join("nixpkgs.lock");
        let engine_lock = layout.data_dir().join("mise-engine.lock");

        // seed both locks at REV_A (same global override, so each resolves REV_A with no nix)
        let plain = style::Palette::plain();
        assert!(upgrade_mise_engine(
            bogus_nix,
            &layout,
            &cfg(&rev_a),
            &plain
        ));
        assert!(upgrade_nix_channel(
            bogus_nix,
            &layout,
            data.path(),
            &cfg(&rev_a),
            &plain
        ));
        let nix_seed = std::fs::read(&nix_lock).unwrap();

        // roll ONLY the engine to REV_B: the base lock is untouched, the engine advanced
        assert!(upgrade_mise_engine(
            bogus_nix,
            &layout,
            &cfg(&rev_b),
            &plain
        ));
        assert_eq!(
            std::fs::read(&nix_lock).unwrap(),
            nix_seed,
            "upgrade mise must not touch nixpkgs.lock"
        );
        assert!(
            std::fs::read_to_string(&engine_lock)
                .unwrap()
                .contains(&rev_b),
            "the engine lock advanced to REV_B"
        );

        // re-seed the engine at REV_A, then roll ONLY the base to REV_B: now the engine
        // lock is untouched and the base advanced
        assert!(upgrade_mise_engine(
            bogus_nix,
            &layout,
            &cfg(&rev_a),
            &plain
        ));
        let engine_reseed = std::fs::read(&engine_lock).unwrap();
        assert!(upgrade_nix_channel(
            bogus_nix,
            &layout,
            data.path(),
            &cfg(&rev_b),
            &plain
        ));
        assert_eq!(
            std::fs::read(&engine_lock).unwrap(),
            engine_reseed,
            "upgrade nix must not touch mise-engine.lock"
        );
        assert!(
            std::fs::read_to_string(&nix_lock).unwrap().contains(&rev_b),
            "the base lock advanced to REV_B"
        );
    }

    #[test]
    fn upgrade_tools_summary_distinguishes_the_outcomes() {
        use sandbox::ToolUpgrade::*;

        // an empty roll (no nix: tools, or no mise file) says so plainly
        let empty = upgrade_tools_summary(&[], &style::Palette::plain()).join("\n");
        assert!(empty.contains("no nix: tools"));

        let text = upgrade_tools_summary(
            &[
                Unchanged {
                    pkg: "jq".into(),
                    request: "1.7.1".into(),
                    version: "1.7.1".into(),
                },
                Rolled {
                    pkg: "ripgrep".into(),
                    request: "latest".into(),
                    from: "14.1.0".into(),
                    to: "14.1.1".into(),
                },
                Pinned {
                    pkg: "nodejs".into(),
                    request: "20".into(),
                    version: "20.11.0".into(),
                },
                Failed {
                    pkg: "fd".into(),
                    request: "latest".into(),
                    error: "nixhub unreachable".into(),
                    kept: Some("9.0.0".into()),
                },
                Failed {
                    pkg: "bat".into(),
                    request: "latest".into(),
                    error: "nixhub unreachable".into(),
                    kept: None,
                },
                Pruned {
                    pkg: "oldtool".into(),
                    request: "1.0".into(),
                },
                Ignored {
                    token: "node".into(),
                    mise_managed: true,
                },
                Ignored {
                    token: "nix:bad name".into(),
                    mise_managed: false,
                },
            ],
            &style::Palette::plain(),
        )
        .join("\n");

        assert!(text.contains("nix:jq: 1.7.1 — unchanged"));
        assert!(text.contains("nix:ripgrep: 14.1.0 → 14.1.1 — rolled forward"));
        assert!(text.contains("nix:nodejs: 20.11.0 — newly pinned"));
        assert!(text.contains("nix:fd: re-resolve failed, kept 9.0.0"));
        assert!(text.contains("nix:bat: re-resolve failed — nixhub unreachable"));
        assert!(text.contains("nix:oldtool (1.0): removed from the lock"));
        assert!(text.contains("node: equipped in-cage by mise — not rolled here"));
        assert!(text.contains("nix:bad name: malformed nix: token — cannot resolve"));

        // Colored: the package identifier rides the name span and the failure rides err.
        let p = style::Palette::colored();
        let colored = upgrade_tools_summary(
            &[Failed {
                pkg: "fd".into(),
                request: "latest".into(),
                error: "nixhub unreachable".into(),
                kept: None,
            }],
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}nix:fd{}", p.name, p.reset)));
        assert!(colored.contains(&format!("{}re-resolve failed{}", p.err, p.reset)));
    }

    #[test]
    fn flake_upgrade_summary_distinguishes_the_outcomes() {
        use sandbox::FlakeUpgrade::*;

        // an empty roll (no flake: packages) says so plainly
        let empty = flake_upgrade_summary(&[], 0, &style::Palette::plain()).join("\n");
        assert!(empty.starts_with("sbx upgrade — flake packages"));
        assert!(empty.contains("no flake: packages"));

        // an empty roll on an untrusted project names the withheld package instead of "none"
        let withheld = flake_upgrade_summary(&[], 2, &style::Palette::plain()).join("\n");
        assert!(withheld.contains("2 flake: package(s) withheld (untrusted)"));
        assert!(!withheld.contains("no flake: packages"));

        let rev_a = "11707dc2f618dd54ca8739b309ec4fc024de578b";
        let rev_b = "9ae611a455b90cf061d8f332b977e387bda8e1ca";
        let text = flake_upgrade_summary(
            &[
                Unchanged {
                    reference: "github:o/a#default".into(),
                    rev: rev_a.into(),
                },
                Rolled {
                    reference: "github:o/b#default".into(),
                    from: rev_a.into(),
                    to: rev_b.into(),
                },
                Pinned {
                    reference: "github:o/c".into(),
                    rev: rev_b.into(),
                },
                Pruned {
                    reference: "github:o/old#x".into(),
                },
                Failed {
                    reference: "github:o/d#default".into(),
                    error: "metadata unreachable".into(),
                    kept: Some(rev_a.into()),
                },
                Failed {
                    reference: "github:o/e#default".into(),
                    error: "metadata unreachable".into(),
                    kept: None,
                },
            ],
            0,
            &style::Palette::plain(),
        )
        .join("\n");

        // Revisions are shortened to the first seven hex in the report.
        assert!(text.contains("flake:github:o/a#default: 11707dc — unchanged"));
        assert!(text.contains("flake:github:o/b#default: 11707dc → 9ae611a — rolled forward"));
        assert!(text.contains("flake:github:o/c: 9ae611a — newly pinned"));
        assert!(text.contains("flake:github:o/old#x: removed from the lock"));
        assert!(text.contains("flake:github:o/d#default: re-resolve failed, kept 11707dc"));
        assert!(text.contains("flake:github:o/e#default: re-resolve failed — metadata unreachable"));

        // Colored: the reference rides the name span and the withheld note rides warn.
        let p = style::Palette::colored();
        let colored = flake_upgrade_summary(
            &[Pinned {
                reference: "github:o/c".into(),
                rev: rev_b.into(),
            }],
            2,
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}flake:github:o/c{}", p.name, p.reset)));
        assert!(colored.contains(&format!("{}newly pinned.{}", p.ok, p.reset)));
        assert!(colored.contains(&format!(
            "{}2 flake: package(s) withheld (untrusted){}",
            p.warn, p.reset
        )));
    }

    #[test]
    fn short_hash_takes_the_base64_body_prefix() {
        assert_eq!(
            short_hash("sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w="),
            "jBGtMS5l"
        );
        // no prefix and a short value degrade gracefully (no panic, min(8))
        assert_eq!(short_hash("short"), "short");
        assert_eq!(short_hash("sha256-ab"), "ab");
    }

    #[test]
    fn prebuilt_upgrade_summary_distinguishes_the_outcomes_for_deb() {
        use sandbox::PrebuiltUpgrade::*;

        // an empty roll (no deb: packages) says so plainly; an untrusted one names the withheld
        let empty = prebuilt_upgrade_summary("deb", &[], 0, &style::Palette::plain()).join("\n");
        assert!(empty.starts_with("sbx upgrade — deb packages"));
        assert!(empty.contains("no deb: packages"));
        let withheld = prebuilt_upgrade_summary("deb", &[], 1, &style::Palette::plain()).join("\n");
        assert!(withheld.contains("1 deb: package(s) withheld (untrusted)"));
        assert!(!withheld.contains("no deb: packages"));

        let h_a = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";
        let h_b = "sha256-XH0ykkcZdoyYdI7tQAS55CsvPwv96Tlr2lYF30qltkE=";
        let text = prebuilt_upgrade_summary(
            "deb",
            &[
                Unchanged {
                    url: "https://e/a.deb".into(),
                    hash: h_a.into(),
                },
                Rolled {
                    url: "https://e/b.deb".into(),
                    from: h_a.into(),
                    to: h_b.into(),
                },
                Pinned {
                    url: "https://e/c.deb".into(),
                    hash: h_b.into(),
                },
                Pruned {
                    url: "https://e/old.deb".into(),
                },
                Failed {
                    url: "https://e/d.deb".into(),
                    error: "prefetch unreachable".into(),
                },
            ],
            0,
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(text.contains("deb:https://e/a.deb: jBGtMS5l — unchanged"));
        assert!(text.contains("deb:https://e/b.deb: jBGtMS5l → XH0ykkcZ — rolled forward"));
        assert!(text.contains("deb:https://e/c.deb: XH0ykkcZ — newly pinned"));
        assert!(text.contains("deb:https://e/old.deb: removed from the lock"));
        assert!(text.contains("deb:https://e/d.deb: re-resolve failed — prefetch unreachable"));

        // The withheld note also rides *after* a roll that did happen, not only in place of the
        // "none declared" line. Colored: the URL rides the name span, the note rides warn.
        let p = style::Palette::colored();
        let colored = prebuilt_upgrade_summary(
            "deb",
            &[Pinned {
                url: "https://e/c.deb".into(),
                hash: h_b.into(),
            }],
            2,
            &p,
        )
        .join("\n");
        assert!(colored.contains(&format!("{}deb:https://e/c.deb{}", p.name, p.reset)));
        assert!(colored.contains(&format!("{}newly pinned.{}", p.ok, p.reset)));
        assert!(colored.contains(&format!(
            "{}2 deb: package(s) withheld (untrusted){}",
            p.warn, p.reset
        )));
    }

    #[test]
    fn prebuilt_upgrade_summary_distinguishes_the_outcomes_for_appimage() {
        use sandbox::PrebuiltUpgrade::*;

        // an empty roll (no appimage: packages) says so plainly; an untrusted one names the withheld
        let empty =
            prebuilt_upgrade_summary("appimage", &[], 0, &style::Palette::plain()).join("\n");
        assert!(empty.starts_with("sbx upgrade — appimage packages"));
        assert!(empty.contains("no appimage: packages"));
        let withheld =
            prebuilt_upgrade_summary("appimage", &[], 1, &style::Palette::plain()).join("\n");
        assert!(withheld.contains("1 appimage: package(s) withheld (untrusted)"));
        assert!(!withheld.contains("no appimage: packages"));

        let h_a = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";
        let h_b = "sha256-XH0ykkcZdoyYdI7tQAS55CsvPwv96Tlr2lYF30qltkE=";
        let text = prebuilt_upgrade_summary(
            "appimage",
            &[
                Unchanged {
                    url: "https://e/a.AppImage".into(),
                    hash: h_a.into(),
                },
                Rolled {
                    url: "https://e/b.AppImage".into(),
                    from: h_a.into(),
                    to: h_b.into(),
                },
                Pinned {
                    url: "https://e/c.AppImage".into(),
                    hash: h_b.into(),
                },
                Pruned {
                    url: "https://e/old.AppImage".into(),
                },
                Failed {
                    url: "https://e/d.AppImage".into(),
                    error: "prefetch unreachable".into(),
                },
            ],
            0,
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(text.contains("appimage:https://e/a.AppImage: jBGtMS5l — unchanged"));
        assert!(
            text.contains("appimage:https://e/b.AppImage: jBGtMS5l → XH0ykkcZ — rolled forward")
        );
        assert!(text.contains("appimage:https://e/c.AppImage: XH0ykkcZ — newly pinned"));
        assert!(text.contains("appimage:https://e/old.AppImage: removed from the lock"));
        assert!(text
            .contains("appimage:https://e/d.AppImage: re-resolve failed — prefetch unreachable"));

        // The withheld note also rides *after* a roll that did happen, not only in place of the
        // "none declared" line.
        let trailing = prebuilt_upgrade_summary(
            "appimage",
            &[Pinned {
                url: "https://e/c.AppImage".into(),
                hash: h_b.into(),
            }],
            2,
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(trailing.contains("appimage:https://e/c.AppImage: XH0ykkcZ — newly pinned"));
        assert!(trailing.contains("2 appimage: package(s) withheld (untrusted)"));
    }

    #[test]
    fn prebuilt_upgrade_summary_distinguishes_the_outcomes_for_tarball() {
        use sandbox::PrebuiltUpgrade::*;

        // an empty roll (no tarball: packages) says so plainly; an untrusted one names the withheld
        let empty =
            prebuilt_upgrade_summary("tarball", &[], 0, &style::Palette::plain()).join("\n");
        assert!(empty.starts_with("sbx upgrade — tarball packages"));
        assert!(empty.contains("no tarball: packages"));
        let withheld =
            prebuilt_upgrade_summary("tarball", &[], 1, &style::Palette::plain()).join("\n");
        assert!(withheld.contains("1 tarball: package(s) withheld (untrusted)"));
        assert!(!withheld.contains("no tarball: packages"));

        let h_a = "sha256-jBGtMS5lpJWVXe+KzQgRSho8BcaEzGvONzIbAWled0w=";
        let h_b = "sha256-XH0ykkcZdoyYdI7tQAS55CsvPwv96Tlr2lYF30qltkE=";
        let text = prebuilt_upgrade_summary(
            "tarball",
            &[
                Unchanged {
                    url: "https://e/a.tar.gz".into(),
                    hash: h_a.into(),
                },
                Rolled {
                    url: "https://e/b.tar.gz".into(),
                    from: h_a.into(),
                    to: h_b.into(),
                },
                Pinned {
                    url: "https://e/c.tar.gz".into(),
                    hash: h_b.into(),
                },
                Pruned {
                    url: "https://e/old.tar.gz".into(),
                },
                Failed {
                    url: "https://e/d.tar.gz".into(),
                    error: "prefetch unreachable".into(),
                },
            ],
            0,
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(text.contains("tarball:https://e/a.tar.gz: jBGtMS5l — unchanged"));
        assert!(text.contains("tarball:https://e/b.tar.gz: jBGtMS5l → XH0ykkcZ — rolled forward"));
        assert!(text.contains("tarball:https://e/c.tar.gz: XH0ykkcZ — newly pinned"));
        assert!(text.contains("tarball:https://e/old.tar.gz: removed from the lock"));
        assert!(
            text.contains("tarball:https://e/d.tar.gz: re-resolve failed — prefetch unreachable")
        );

        // The withheld note also rides *after* a roll that did happen, not only in place of the
        // "none declared" line.
        let trailing = prebuilt_upgrade_summary(
            "tarball",
            &[Pinned {
                url: "https://e/c.tar.gz".into(),
                hash: h_b.into(),
            }],
            2,
            &style::Palette::plain(),
        )
        .join("\n");
        assert!(trailing.contains("tarball:https://e/c.tar.gz: XH0ykkcZ — newly pinned"));
        assert!(trailing.contains("2 tarball: package(s) withheld (untrusted)"));
    }
}
