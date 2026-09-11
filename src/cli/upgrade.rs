//! `sbx upgrade [all|nix|mise|flake|deb|appimage|tarball|binary|distro|provision] [--project <path>]`: roll the
//! managed channels and `[packages]` backends forward by re-resolving and rewriting their locks, so
//! versions advance only on an explicit upgrade, never on an sbx binary update. `--project`
//! retargets every roll at another project, exactly as running the command from that directory
//! would. The lock-rewriting parts need nix to resolve but not the sandbox boundary; the in-cage
//! `mise:` roll needs the cage and degrades to a warning where it is unavailable.
//!
//! `provision` is the odd one out: an agent its bundle INSTALLS has no lock to rewrite, so what
//! advances it is running that install again, in the app's own cage. `all` runs those steps too —
//! anything else would make "bring everything up to date" walk past a whole class of agent — but
//! with each step's own guard in charge, so a step installs when something moved and stands down
//! when nothing did. The `provision` verb is the one that installs REGARDLESS, which is what an
//! agent whose guard cannot detect a new release needs, and what a wrong guard needs.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::{config, diag, help, layout_or_fail, sandbox, short_rev, store, style, trust};

/// The known upgrade targets. Kept as one list so the parser and the error message cannot drift.
/// Visible to the sibling modules so the completion tests can walk it and assert the page offers
/// every target the parser accepts.
///
/// The five package backends — `flake`, `deb`, `appimage`, `tarball`, `binary` — are deliberately
/// **not** here, and `all` still rolls every one of them. They existed as targets only because
/// there was no per-app unit to narrow by, so a user who wanted to advance one app had to know
/// which backend it rode. `--app <name>` is that unit now, and narrowing by app is the question a
/// user actually has; narrowing by backend was a way of spelling it that required reading the
/// app's profile first. What remains is what names work no app carries: the nixpkgs revision, the
/// mise engine with the project's `nix:` tools and task pool, and the distribution image — plus
/// `provision`, which is not a backend at all but the forcing of an install step.
pub(crate) const TARGETS: &[&str] = &["all", "nix", "mise", "distro", "provision"];

/// Map a target word to its `'static` spelling, so a parsed target outlives the borrowed argv.
fn known_target(s: &str) -> Option<&'static str> {
    TARGETS.iter().copied().find(|&t| t == s)
}

/// The outcome of parsing `sbx upgrade`'s arguments: show help, run with a resolved target, an
/// optional `--project` path and an optional `--app` selector, or a usage error (already-formatted
/// message, exit 2).
#[derive(Debug, PartialEq)]
enum ParsedArgs {
    Help,
    Run {
        what: &'static str,
        project: Option<OsString>,
        app: Option<String>,
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
    let mut app: Option<String> = None;
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
            // `-a <name>` / `--app <name>`: narrow an in-cage roll to one app's cage. UTF-8 only —
            // an app name is validated against a narrow character set before it can ever name a
            // profile, so a non-UTF-8 word here cannot be one.
            Some("--app" | "-a") => {
                let Some(val) = args.get(i + 1).and_then(|a| a.to_str()) else {
                    return ParsedArgs::Error("sbx: upgrade: --app needs an app name.".into());
                };
                if app.is_some() {
                    return ParsedArgs::Error("sbx: upgrade: --app given more than once.".into());
                }
                app = Some(val.to_string());
                i += 2;
            }
            Some(s) if s.starts_with("--app=") => {
                let val = &s["--app=".len()..];
                if val.is_empty() {
                    return ParsedArgs::Error("sbx: upgrade: --app needs an app name.".into());
                }
                if app.is_some() {
                    return ParsedArgs::Error("sbx: upgrade: --app given more than once.".into());
                }
                app = Some(val.to_string());
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
                // The word is not a target, and the likeliest reason is that it is an APP name:
                // "advance this one thing" is the common request, and a target list alone answers
                // it with eight words that are not what was typed. Naming the selector costs no
                // I/O, which is what lets this stay in a parser that reads no config — it cannot
                // know whether the word IS an app, so it says what to do with one either way.
                return ParsedArgs::Error(format!(
                    "sbx: unknown upgrade target '{}' (known: {}) — to advance one app, \
                     `sbx upgrade --app {0}`.",
                    arg.to_string_lossy(),
                    TARGETS.join(", ")
                ));
            }
        }
    }
    // Every remaining target takes `--app`, so the grammar has nothing left to refuse here. Which
    // targets select no work for a GIVEN app is a different question, answered against the resolved
    // config by `app_selector_refusal` — this parser reads no config and must not pretend to.
    let what = what.unwrap_or("all");
    ParsedArgs::Run { what, project, app }
}

/// `sbx upgrade [all|nix|mise] [--project <path>]`: roll managed channels forward by
/// re-resolving and rewriting their locks, so versions advance only here, never on an sbx
/// binary update. `nix` rolls the nixpkgs channel the target directory tracks (a trusted
/// project pin, else the global channel) — base and native `nix:` `[packages]`. `mise` rolls
/// the mise engine (its own dedicated lock), the project's `nix:` tools, and the project's and
/// apps' `mise:` `[packages]` (the last in-cage). `all` rolls every one of them and runs the
/// bundles' install steps under their own guards. `--project <path>`
/// runs the whole thing against another project instead of the current directory. The
/// lock-rewriting parts need nix (to resolve) but not the sandbox boundary; the in-cage `mise:`
/// roll needs the sandbox and degrades to a warning where it is unavailable.
pub(crate) fn upgrade_cmd(args: &[OsString]) -> ExitCode {
    // Parse an optional target word and an optional `--project <path>`, in any order, before
    // touching anything so a typo fails cleanly.
    let (what, project_arg, app_arg) = match parse_upgrade_args(args) {
        ParsedArgs::Help => return help::show(&["upgrade"]),
        ParsedArgs::Run { what, project, app } => (what, project, app),
        ParsedArgs::Error(message) => {
            diag::error(&message);
            return ExitCode::from(2);
        }
    };
    run_upgrade("upgrade", what, project_arg.as_deref(), app_arg.as_deref())
}

/// The roll itself, behind both spellings that reach it: `sbx upgrade [target] [--app <name>]` and
/// `sbx app upgrade <name>`, which is that command with the target defaulted and the app named.
///
/// One body rather than two, because the two commands answer the same question and a second
/// implementation of it is a second set of answers waiting to diverge — which is exactly what the
/// per-app verb had become: it rolled two channels and *named* the rest, while `--app` on the same
/// app rolled whichever channel was typed.
///
/// `verb` is what precedes the colon in a refusal, so each spelling names itself.
fn run_upgrade(
    verb: &'static str,
    what: &'static str,
    project_arg: Option<&std::ffi::OsStr>,
    app_arg: Option<&str>,
) -> ExitCode {
    // `--project <path>` retargets the whole upgrade at another project — exactly as `cd <path>
    // && sbx upgrade` would: the path is canonicalized (so the per-project lock derivation matches
    // a launch from there) and every roll below reads its config and rewrites its locks. Default
    // is the current directory.
    let cwd = match project_arg {
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
        None => match crate::config_cwd() {
            Ok(d) => d,
            Err(code) => return code,
        },
    };

    // Load the config so a project pin — and any reason one was dropped — is honored
    // exactly as a launch would; surfacing the warnings explains a pin that did not
    // take (so an untrusted pin silently rolling the global channel is never a mystery).
    let cfg = config::load(&cwd);
    for warning in &cfg.warnings {
        diag::warn_config(warning);
    }

    // `--app <name>` is checked against the resolved config before any roll starts: a name that
    // selects no work must say which of the three ways it selects none, since each has a different
    // answer, and it must say so instead of printing a clean "nothing to roll" that reads as
    // success.
    if let Some(name) = app_arg
        && let Some(message) = app_selector_refusal(&cfg, name, what, verb)
    {
        diag::error(&message);
        return ExitCode::from(2);
    }
    let only = app_arg;

    // The store and the engine are resolved only now, AFTER the name has been judged. A name that
    // selects no work is a question the config alone answers, and answering it first is what keeps
    // a typo from being reported as a broken installation on a host whose data directory or nix is
    // unusable. Nothing above this line touches either.
    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };
    let nix = match store::try_resolve_nix(Some(&layout)) {
        Ok(nix) => nix,
        // Not always "not found": an override sbx refused leaves the engine installed at the path
        // the variable names, and saying it is missing points at the wrong remedy.
        Err(miss) => {
            diag::error(&format!(
                "sbx: {} — cannot upgrade. See `sbx doctor`.",
                miss.clause("nix")
            ));
            return ExitCode::FAILURE;
        }
    };

    // `all` rolls every managed channel and reports the worst exit — a tool that fails to
    // re-resolve must not be masked by a clean roll elsewhere. `mise` rolls three distinct
    // things: the engine (host-global, in every cage, so it rolls regardless of any project's
    // trust), the project's `nix:` tools (trusted-only), and the project's and apps' `mise:`
    // `[packages]` (in-cage, trusted-only). Rolling them as separate, unconditional calls keeps
    // the engine's trust-independence structural rather than dependent on an earlier path not
    // early-returning.
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut ok = true;
    // Whether this run replaced a locked revision, and so repointed store paths. Tracked across
    // the three channels that build through nix — `nix`, `mise` (its project `nix:` tools) and
    // `flake` — and read once at the close (below).
    let mut moved_store_paths = false;
    if matches!(what, "nix" | "all") {
        let roll = upgrade_nix_channel(&nix, &layout, &cwd, &cfg, only, &pal);
        ok &= roll.ok;
        moved_store_paths |= roll.moved;
    }
    if matches!(what, "mise" | "all") {
        // Under `--app`, the engine and the project's `nix:` tools are deliberately left alone:
        // both are project-wide (the engine is host-global, the tools are the project's own), so
        // rolling them here would make a flag that reads as "only this app" do project-wide work.
        if only.is_none() {
            // The engine is deliberately not tracked as moving anything: it runs host-side, out of
            // its own private home under sbx's data directory, so no app home ever holds a path
            // into it. The project's `nix:` tools are the opposite — they resolve to store paths
            // the cage binds, so rolling one repoints exactly what a home can hold.
            ok &= upgrade_mise_engine(&nix, &layout, &cfg, &pal);
            let roll = upgrade_mise_tools(&nix, &layout, &cwd, &cfg, &pal);
            ok &= roll.ok;
            moved_store_paths |= roll.moved;
        }
        // The project's and apps' `mise:` `[packages]` are equipped in-cage, not host-side, so
        // their roll runs `mise upgrade` inside a cage (per home) rather than rewriting a lock.
        // Pass the target directory and its already-loaded config: the groups are computed from the
        // config before any sandbox work (so a project with no `mise:` package keeps this cheap and
        // sandbox-free), and the cage is built against `cwd` so `--project` retargets it too.
        ok &= sandbox::upgrade_mise_packages(&cwd, &cfg, &pal, only);
    }
    if matches!(what, "all") {
        // The project's and apps' `flake:` `[packages]` re-resolve to a fixed revision and the
        // per-project flake lock is rewritten — a host-side lock rewrite (the new pin builds
        // in-cage at the next launch), like the `nix:` tools.
        let roll = upgrade_flake_packages(&nix, &layout, &cwd, &cfg, only, &pal);
        ok &= roll.ok;
        moved_store_paths |= roll.moved;
    }
    if matches!(what, "all") {
        // The project's and apps' `deb:` `[packages]` re-resolve their `.deb` URL to a new content
        // hash and the per-project deb lock is rewritten — a host-side lock rewrite (the new hash
        // builds host-side at the next launch), like the `nix:` tools and `flake:` packages.
        ok &= upgrade_deb_packages(&nix, &layout, &cwd, &cfg, only, &pal);
    }
    if matches!(what, "all") {
        // The project's and apps' `appimage:` `[packages]` re-resolve their `.AppImage` URL to a new
        // content hash and the per-project appimage lock is rewritten — the exact `deb:` shape.
        ok &= upgrade_appimage_packages(&nix, &layout, &cwd, &cfg, only, &pal);
    }
    if matches!(what, "all") {
        // The project's and apps' `binary:` `[packages]` re-resolve to a new content hash and the
        // per-project binary lock is rewritten — the same shape as the three archive backends.
        ok &= upgrade_binary_packages(&nix, &layout, &cwd, &cfg, only, &pal);
    }
    if matches!(what, "distro" | "all") && only.is_none() {
        // The declared distribution image: its tag is re-resolved to whatever digest the registry
        // serves now and the lock is rewritten — a host-side lock rewrite like the channels above,
        // and the new root filesystem is unpacked at the next launch.
        //
        // Left alone under `--app`, and this is the one target for which that is structural rather
        // than a choice: `ResolvedApp` carries no `distro` field, so the image is the project's and
        // there is no per-app unit to select. `sbx upgrade distro --app <name>` is refused before
        // this point; what this guard covers is the defaulted `all`.
        ok &= upgrade_distro(&layout, &cwd, &cfg, &pal);
    }
    if matches!(what, "all") {
        // The project's and apps' `tarball:` `[packages]` re-resolve their `.tar.gz` URL to a new
        // content hash and the per-project tarball lock is rewritten — the exact `deb:` shape.
        ok &= upgrade_tarball_packages(&nix, &layout, &cwd, &cfg, only, &pal);
    }
    // The bundles' install steps: an agent with no `[packages]` backend has no lock to rewrite, so
    // what advances it is running its install again. Part of `all`, because "bring everything up to
    // date" that walks past a whole class of agent is not what the word means — and because the
    // objection this channel was once excluded for does not survive reading: `all` already builds a
    // cage per app for the `mise` roll, so these add cages to a command that has them, not a new
    // kind of cost.
    //
    // What differs is WHO decides to install. Under `all` the steps run with their own guards in
    // charge (`force = false`): one that compares an upstream release to what is installed
    // re-installs exactly when something moved, and one that can only ask whether the agent exists
    // reports nothing to do. The `provision` verb keeps `SBX_UPGRADE` raised, which is the only
    // thing that advances an agent whose guard cannot tell — a checkout of a branch has no version
    // to compare — and the way to re-install over a guard that is wrong.
    if matches!(what, "provision" | "all") {
        // ONE rule for forcing, written once. Naming a single app is a request to re-install it,
        // not to poll it: the user who typed the name has already decided, and that is the same
        // reading the `provision` verb carries. So `sbx upgrade provision`, `sbx upgrade --app
        // <name>` and `sbx app upgrade <name>` all force, and only an unscoped `all` leaves each
        // step's own guard in charge — where forcing would mean a cage and a download per app
        // across the project.
        let force = what == "provision" || only.is_some();
        // Named BEFORE the cage is built, not reported after it: under a selector this step is the
        // one part of the run that costs a download, and it runs without a flag to gate it.
        if let Some(name) = only
            && cfg.apps.get(name).is_some_and(|a| !a.provisions.is_empty())
        {
            println!("{}", install_step_notice(name, &cfg, &pal));
        }
        ok &= sandbox::upgrade_provision_steps(&cwd, &cfg, &pal, only, force);
    }
    match closing_note(what, moved_store_paths) {
        ClosingNote::StoreMoved => store_moved_hint(&cfg, only, &pal),
        ClosingNote::None => {}
    }
    // A roll is what eventually supersedes a build. Point the user at `sbx gc --prune` when the
    // project's store is already holding superseded builds — cheap, filesystem-only, and silent
    // when there is nothing to reclaim (see the function).
    sandbox::superseded_reclaimable_hint(&layout, &cwd, &cfg, only, &pal);

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The closing note a run owes the reader, if any.
#[derive(Debug, PartialEq, Eq)]
enum ClosingNote {
    /// A channel that resolves through nix replaced a locked revision, so store paths moved and
    /// the homes built against them may hold a reference to a path that is gone.
    StoreMoved,
    /// Nothing to say — the common close.
    None,
}

/// Decide which note closes a run, from the target and whether a locked revision was replaced.
///
/// Pure, so the choice is unit-tested without nix — and the three cases are **mutually exclusive
/// by construction**, which is what keeps one run from printing two notes about the same apps.
///
/// The scope is bounded by which channels can report a move at all: [`upgrade_nix_channel`],
/// [`upgrade_mise_tools`] and [`upgrade_flake_packages`] are the three that return a [`Roll`], and
/// they are exactly the three the `StoreMoved` arm below names — plus `all`, which runs them.
fn closing_note(what: &str, moved_store_paths: bool) -> ClosingNote {
    match what {
        // The channel that runs the install steps has nothing to point at: it just ran them.
        "provision" => ClosingNote::None,
        // Named, not defaulted. These three resolve to nix store paths, so rolling one repoints a
        // path and a home that holds it is left dangling: `nix` rolls the channel, `flake` builds
        // through `nix build`, and `mise` rolls the project's `nix:` tools (its engine moves
        // nothing a home holds, and its `mise:` packages are per-home downloads — the tools are
        // what qualifies it). The rest are excluded on their mechanism: `deb`, `appimage`,
        // `tarball` and `binary` place their own content-hashed artifacts, so none of them moves a
        // path a home points into, and claiming otherwise would be an unmeasured warning.
        //
        // `all` is here because it runs all three, and because it is the case the note is now most
        // worth printing for: `all` has just run the install steps with their own guards in charge,
        // and a guard that compares an upstream version cannot see that a store path moved under
        // the home it built. That is precisely what `sbx upgrade provision` is for.
        "nix" | "flake" | "mise" | "all" if moved_store_paths => ClosingNote::StoreMoved,
        _ => ClosingNote::None,
    }
}

/// Resolve `<name>` to an app that can actually be rolled, or the refusal that says why it cannot.
///
/// Two refusals, and neither is about a channel: the name matches no app, or it matches one that
/// never launches. Split out because **two commands ask this same question** — `sbx upgrade
/// <target> --app <name>` and `sbx app upgrade <name>` — and a sentence written twice is a sentence
/// that drifts. `verb` is what precedes the colon, so each command names itself.
///
/// What deliberately stays with the caller is the per-target half. It is a refusal only for
/// `sbx upgrade <target> --app`, where the user named a channel and the app does not ride it; for
/// `sbx app upgrade` the same fact is not an error at all — it is a channel that does not apply,
/// and the verb dispatches on the ones that do.
fn launchable_app<'a>(
    cfg: &'a config::Resolved,
    name: &str,
    verb: &str,
) -> Result<&'a config::ResolvedApp, String> {
    let Some(app) = cfg.apps.get(name) else {
        return Err(format!(
            "sbx: {verb}: no app named `{name}` — `sbx app ls` lists the ones this project has."
        ));
    };
    // An app with no command never launches, so it equips nothing and installs nothing: rolling it
    // would build a cage to run no work. Reported apart from "declares none", which is about what
    // the app asks for rather than whether it can run at all.
    if app.cmd.is_empty() {
        return Err(format!(
            "sbx: {verb}: app `{name}` declares no command, so it never launches — there is \
             nothing in its cage to roll."
        ));
    }
    Ok(app)
}

/// Why `--app <name>` selects no work for this target, or `None` when it selects some.
///
/// Three refusals, three answers, because an app can select nothing in three different ways and
/// only one of them is a typo. The first two come from [`launchable_app`], which the per-app verb
/// shares; the per-target arms below are this command's alone. Pure over the resolved config, so
/// the taxonomy is unit-tested.
fn app_selector_refusal(
    cfg: &config::Resolved,
    name: &str,
    what: &str,
    verb: &str,
) -> Option<String> {
    let app = match launchable_app(cfg, name, verb) {
        Ok(app) => app,
        Err(refusal) => return Some(refusal),
    };
    match what {
        "provision" if app.provisions.is_empty() => Some(format!(
            "sbx: {verb}: app `{name}` declares no install step — it rides a `[packages]` \
             backend, so `sbx upgrade --app {name}` advances it."
        )),
        "mise" if !declares_mise_package(cfg, app) => Some(format!(
            "sbx: {verb}: app `{name}` declares no `mise:` package — `sbx upgrade --app {name}` \
             rolls the backends it does declare."
        )),
        // The one target with no per-app unit at all, and structurally so: `ResolvedApp` carries no
        // `distro` field, so the distribution image is the project's and no app can name one of its
        // own. This is a different answer from the two above — they say "not this app", this one
        // says "not any app" — so it names the command without the selector rather than a narrower
        // one that would refuse in turn.
        "distro" => Some(format!(
            "sbx: {verb}: the distribution image is the project's — no app declares one, so there \
             is nothing for `--app {name}` to select. `sbx upgrade distro` rolls it."
        )),
        // The defaulted target, which is what `sbx upgrade --app <name>` and `sbx app upgrade
        // <name>` both resolve to. An app that declares nothing and installs nothing would
        // otherwise print a header, roll nothing and exit 0 — a clean report of work that never
        // existed. Measured over what a narrowed roll can reach: the app's own layer (its
        // `[packages]` and the bundles folded under it), its install steps, and the `mise:` set its
        // cage equips, which is the one of the three that folds the baseline in.
        "all"
            if app.packages.is_empty()
                && app.provisions.is_empty()
                && !declares_mise_package(cfg, app) =>
        {
            Some(format!(
                "sbx: {verb}: app `{name}` declares no packages and no install step — there is \
                 nothing of its own to advance. `sbx upgrade` rolls the project it launches in."
            ))
        }
        _ => None,
    }
}

/// Whether this app's cage equips any `mise:` package — its own or one the project baseline folds
/// in, since an app's cage equips both layers.
///
/// Asks the question the roll asks, of the set the roll sees: the **merged** one, through
/// `merge_app` itself. The two layers were tested separately, which is not how they meet — a
/// package is folded by *name*, so an app re-declaring a baseline `mise:` tool as `nix:` replaces
/// it, and asking each layer on its own still found the baseline's. The selector then accepted the
/// app, the roll equipped no mise package, and the run printed the "nothing rolled" these refusals
/// exist to replace with a reason.
///
/// A package an untrusted layer declared is withheld from the equip, so `mise_packages` (the
/// roll's own filter) is what decides, not the backend alone. The withheld ones are surfaced by
/// the roll's own warning either way.
fn declares_mise_package(cfg: &config::Resolved, app: &config::ResolvedApp) -> bool {
    let mut merged = cfg.clone();
    merged.merge_app(app.clone());
    !sandbox::mise_packages(&merged.packages).is_empty()
}

/// What the install step is about to cost, said before it is paid.
///
/// Naming one app runs the step without a flag to gate it, and FORCES it past its own guard, which
/// is only defensible if the reader is told what is starting: a cage and a download, not a lock
/// rewrite. So the line goes out *before* [`sandbox::upgrade_provision_steps`] rather than
/// describing it afterwards, and it names the narrower command for the times the packages are all
/// that was wanted.
///
/// "regardless of its guard" is load-bearing rather than decorative. An unscoped `sbx upgrade`
/// leaves each guard in charge, so a reader who has only ever run that one has been trained to
/// expect a cheap channel read; under a selector the same step installs whatever the guard would
/// have said, and this line is the only place that difference is visible before the download
/// starts.
///
/// The narrower command is named **only when it would work**. `sbx upgrade mise --app <name>`
/// refuses an app that declares no `mise:` package, and for five of the shipped profiles the
/// install step is the whole of what advances them — offering an escape hatch there would send the
/// reader to a refusal, which is the failure this notice exists to remove, reintroduced one line
/// above the work.
///
/// Pure over the resolved config, so the wording is pinned by a test rather than by a reading of
/// the code.
fn install_step_notice(name: &str, cfg: &config::Resolved, pal: &style::Palette) -> String {
    let (dim, r) = (pal.dim, pal.reset);
    let rolls_mise = cfg
        .apps
        .get(name)
        .is_some_and(|app| declares_mise_package(cfg, app));
    let cheaper = if rolls_mise {
        format!(" — `sbx upgrade mise --app {name}` rolls only the packages.")
    } else {
        ".".to_string()
    };
    style::prose(
        &format!(
            "  {dim}the install step below re-runs in {name}'s own cage regardless of its guard, \
             which downloads again{cheaper}{r}"
        ),
        pal,
    )
}

/// `sbx app upgrade <name>`: advance one app — every channel it rides, not a chosen one.
///
/// The same roll as `sbx upgrade --app <name>`, reached through [`run_upgrade`] with the target
/// defaulted to `all`. It exists as its own spelling because "advance this app" is the question a
/// user actually has, and answering it should not require knowing which backend the app's profile
/// declares.
///
/// It used to roll two channels and merely *name* the rest, on the ground that the other backends
/// rewrite a project-wide lock. That limit is gone: the roll takes a selector now, so a narrowed
/// run resolves only what the named app declares and leaves the lock's other entries — and its
/// prune — alone.
pub(crate) fn app_upgrade_cmd(args: &[OsString]) -> ExitCode {
    let name = match crate::cli::one_name(args, &["app", "upgrade"], &[], "name an app") {
        Ok((name, _)) => name,
        Err(code) => return code,
    };
    run_upgrade("app upgrade", "all", None, Some(name))
}

/// The launchable apps whose bundles carry an install step, named once and in a stable order.
///
/// One selector, so nothing that reasons about this set can disagree with anything else about which
/// apps ride an install step. It served two notes until `all` began running the steps itself, which
/// left the question "what did `all` leave out?" with no answer to give.
fn apps_with_install_steps(cfg: &config::Resolved) -> Vec<&str> {
    let mut apps: Vec<&str> = cfg
        .apps
        .iter()
        .filter(|(_, app)| !app.cmd.is_empty() && !app.provisions.is_empty())
        .map(|(name, _)| name.as_str())
        .collect();
    apps.sort_unstable();
    apps
}

/// What a roll that moved nix store paths did to the app homes built against them.
///
/// `nix`, `flake` and `mise` reach this — the three channels that resolve through `nix build`, so
/// rolling any of them **repoints store paths**, and a home holding a reference into the old path (a
/// virtualenv whose `bin/python` symlinks into the store, a build linked against a store library) is
/// left dangling. `mise` qualifies through the project's `nix:` tools, not through its engine (which
/// runs out of its own private home, so no app home holds a path into it) and not through its
/// `mise:` packages (per-home downloads inside a cage). The other channels are deliberately excluded
/// — `deb`/`appimage`/`tarball`/`binary` place their own content-hashed artifacts, so none of them
/// moves the paths a home points into, and claiming otherwise would be noise.
///
/// The question is what the roll invalidated, and it is one no guard inside a step can answer: a
/// guard comparing an upstream release sees nothing wrong with a home whose `bin/python` symlinks
/// into a store path that moved. So this note stands even after `all` has run the steps.
///
/// `only` is the roll's `--app` selector, and it narrows this the same way it narrowed the roll: a
/// roll that moved one app's store paths must not name the apps it left alone. Without it the note
/// would be right about the event and wrong about the subject — the same defect as the reserve
/// below, by inclusion instead of omission.
///
/// **Reserve, structural**: an app that installs from its own `cmd` rather than from a bundle's
/// install step cannot be named here, because it declares no step to select on. The shipped
/// catalogue has **two**: `open-design`, which clones and installs on every launch, and `aionui`,
/// which stages a runtime out of the store into its home. Neither is left broken — the work runs
/// inside the `cmd`, so it repairs itself exactly as a step does; what they lose is the notice.
/// And they lose all of it, not a name in a list: both consume the `opencode` bundle, which carries
/// no step, so their `provisions` is empty and this function returns `None` for a project holding
/// only them. In a project that also declares one of the bundles that *do* carry a step, the note
/// prints, names those, and omits these two; in a project that declares neither, the roll closes in
/// silence. The second outcome is the sharper statement of the same gap and the one to weigh
/// against the cost of closing it. What bounds that cost is per app, not shared: `aionui`'s guard
/// runs the staged binary, so a store move trips it and the restage announces itself on stderr,
/// leaving only the advance notice missing; `open-design`'s install is keyed on the checked-out
/// commit, which a store move does not change, and that key is right for what it guards, because
/// the tree it installs holds no store path of its own. What its home does hold is Corepack's
/// shims, which are symlinks into the store, and its `cmd` rewrites those on every launch after
/// dropping any the reclaimed revision left resolving nowhere. So on a store move it re-installs
/// nothing, repairs the one thing that moved, and says nothing about either.
///
/// That self-repair is a property of the guard each one writes, not of the shape: `aionui`'s guard
/// tested that the staged tree was *there* rather than that it *ran*, and skipped the repair for as
/// long as the tree existed. Widening this note to cover them would mean detecting staging inside a
/// shell string, which the config cannot do; what closes the gap is a declarative signal, not a
/// better guess. Both signals that would work move something a caller cannot: a field an app sets
/// to declare that its home holds store content, or a bundle of its own to host the step — which in
/// this catalogue means the namesake shape (a bundle's profile is thin and names only it, pinned in
/// `src/config/tests.rs`) that a consumer profile is precisely not.
fn store_moved_note(cfg: &config::Resolved, only: Option<&str>) -> Option<String> {
    let apps: Vec<&str> = apps_with_install_steps(cfg)
        .into_iter()
        .filter(|name| only.is_none_or(|want| want == *name))
        .collect();
    if apps.is_empty() {
        return None;
    }
    Some(format!(
        "the store paths moved: the install steps of {} build against them, so an app home may now \
         hold a reference to a path that is gone. Each repairs itself at its next launch — or now, \
         with `sbx upgrade provision`.",
        apps.join(", ")
    ))
}

/// Print [`store_moved_note`], when this roll has an app it applies to.
fn store_moved_hint(cfg: &config::Resolved, only: Option<&str>, pal: &style::Palette) {
    let Some(note) = store_moved_note(cfg, only) else {
        return;
    };
    let (dim, r) = (pal.dim, pal.reset);
    println!("{}", style::prose(&format!("  {dim}{note}{r}"), pal));
}

/// The outcome of a roll: whether it succeeded, and whether it *replaced* a revision that was
/// already locked.
///
/// The two are independent, and only the second one invalidates anything. A roll that succeeds and
/// re-resolves to the revision already pinned moves no store path, so every home built against it
/// stays valid; a first-time pin creates paths rather than moving them, so no existing home can
/// hold a reference to what it replaced. Only a replacement can leave a home pointing at a path
/// that is gone.
struct Roll {
    ok: bool,
    moved: bool,
}

impl Roll {
    /// A roll that could not run: nothing succeeded, so nothing moved.
    const FAILED: Self = Self {
        ok: false,
        moved: false,
    };

    /// A roll with nothing to do: it succeeded, and moved nothing.
    const CLEAN: Self = Self {
        ok: true,
        moved: false,
    };
}

/// Roll the nixpkgs channel the current directory tracks — a trusted project pin, else
/// the global channel — forcing a fresh resolution and rewriting that lock. Returns
/// whether it succeeded and whether it replaced a locked revision; the base and `[packages]`
/// download on the next launch.
fn upgrade_nix_channel(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    only: Option<&str>,
    pal: &style::Palette,
) -> Roll {
    let target = match sandbox::effective_lock_target(cwd, layout, cfg, only) {
        Ok(t) => t,
        Err(e) => {
            diag::error(&format!("sbx: cannot resolve the channel target: {e}"));
            return Roll::FAILED;
        }
    };
    // `--app` asked for one app, and a trusted project pin outranks an app's own lock (the app
    // builds this project's declared packages too, so it has to be on the pinned revision). The
    // target that came back is therefore the *project's*, and refreshing it would roll the whole
    // project under a flag that reads "only this app". Refuse instead, and say where the decision
    // came from — read off the target, so this can never disagree with what was chosen.
    if only.is_some() && target.origin() == store::Origin::ProjectPin {
        diag::error(&format!(
            "sbx: upgrade: this project pins nixpkgs ({}), and an app inherits that pin — so \
             there is no app-only revision to roll here. Run `sbx upgrade nix` to roll the pin \
             for the whole project, or launch the app from a directory that does not pin.",
            target.source()
        ));
        return Roll::FAILED;
    }
    // Read what was locked BEFORE the roll, and read it across sources. `Upgrade::previous` cannot
    // answer this: it is scoped to the current source, so it reports `None` both for a first-ever
    // pin (nothing to invalidate) and for a changed pin (which repoints the store exactly like a
    // roll forward). Those two must not collapse — the second is precisely the case that leaves a
    // home holding a path that is gone.
    let before = target.previously_locked();
    let upgrade = match target.refresh(nix, layout) {
        Ok(u) => u,
        Err(e) => {
            diag::error(&format!("sbx: cannot upgrade the nixpkgs channel: {e}"));
            return Roll::FAILED;
        }
    };
    let moved = before.is_some_and(|prev| prev != upgrade.revision);
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
    Roll { ok: true, moved }
}

/// Roll the declared distribution image: re-resolve its locator against the registry and rewrite
/// the lock, so the cage root advances only here.
///
/// Silent when no layer declared one, which is every cage on the hermetic nix userland: a channel
/// nothing selected has nothing to report, and `sbx upgrade` with no argument runs this alongside
/// the rest.
fn upgrade_distro(
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> bool {
    // Only a private registry needs one, so bubblewrap is resolved only when a credential was
    // declared: a roll of a public image must not fail on a host that cannot sandbox, and the
    // resolver needs bwrap solely to run a resolver plugin under least privilege.
    let Some(locator) = cfg.distro.as_deref() else {
        return true;
    };
    let lock = match sandbox::distro_lock_path(cwd, layout, cfg) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!("sbx: cannot identify the project directory: {e}"));
            return false;
        }
    };
    let credential = if cfg.distro_auth.is_some() {
        let Some(bwrap) = store::resolve_bwrap(Some(layout)) else {
            diag::error(
                "sbx: the `distro` credential is resolved under bubblewrap, which is not usable here.",
            );
            return false;
        };
        match sandbox::distro::credential(cfg, cwd, &bwrap.path) {
            Ok(c) => c,
            Err(e) => {
                diag::error(&format!(
                    "sbx: cannot resolve the `distro` registry credential: {e}"
                ));
                return false;
            }
        }
    } else {
        None
    };
    let rolled = match sandbox::distro::store::refresh(
        layout,
        locator,
        &cfg.distro_run,
        &lock,
        credential.as_deref(),
    ) {
        Ok(r) => r,
        Err(e) => {
            diag::error(&format!("sbx: cannot upgrade the `{locator}` image: {e}"));
            return false;
        }
    };
    for line in distro_upgrade_summary(cfg.distro_origin, &rolled, pal) {
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
    let target = store::LockTarget::engine(
        layout,
        cfg.mise_engine.as_deref(),
        cfg.nixpkgs_global.as_deref(),
    );
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
/// but never aborts the others — and whether any tool actually rolled, since these resolve
/// to store paths exactly as the channel does. Trusted-only, mirroring how the tools are
/// provisioned: an untrusted project's tools are never locked, so there is nothing to roll.
fn upgrade_mise_tools(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    pal: &style::Palette,
) -> Roll {
    let Some(mise) = &cfg.mise else {
        for line in upgrade_tools_summary(&[], pal) {
            println!("{line}");
        }
        return Roll::CLEAN;
    };
    if mise.state != trust::TrustState::Trusted {
        diag::warn(&format!(
            "mise file `{}` withheld ({}): its `nix:` tools are not rolled",
            mise.name,
            config::untrusted_reason(mise.state)
        ));
        return Roll::CLEAN;
    }
    let outcomes =
        match sandbox::upgrade_tools(nix, layout, cwd, &mise.files, &sandbox::current_system()) {
            Ok(o) => o,
            Err(e) => {
                diag::error(&format!("sbx: cannot roll the mise tools: {e}"));
                return Roll::FAILED;
            }
        };
    for line in upgrade_tools_summary(&outcomes, pal) {
        println!("{line}");
    }
    Roll {
        ok: !outcomes
            .iter()
            .any(|o| matches!(o, sandbox::ToolUpgrade::Failed { .. })),
        // Same rule as the other two: only a version that *replaced* a locked one repoints a
        // path. A first pin creates one, and an unchanged request keeps the one already there.
        moved: outcomes
            .iter()
            .any(|o| matches!(o, sandbox::ToolUpgrade::Rolled { .. })),
    }
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
    only: Option<&str>,
    pal: &style::Palette,
) -> Roll {
    let outcomes = match sandbox::upgrade_flake(nix, layout, cwd, cfg, only) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the flake packages: {e}"));
            return Roll::FAILED;
        }
    };
    for line in flake_upgrade_summary(&outcomes, sandbox::withheld_flake_packages(cfg, only), pal) {
        println!("{line}");
    }
    Roll {
        ok: !outcomes
            .iter()
            .any(|o| matches!(o, sandbox::FlakeUpgrade::Failed { .. })),
        // Only `Rolled` replaces a revision. `Pinned` is a first pin (nothing existed to
        // supersede), `Unchanged` re-resolved to the same revision, and `Pruned` drops a reference
        // the config no longer declares — none of the three moves a path a home already holds.
        moved: outcomes
            .iter()
            .any(|o| matches!(o, sandbox::FlakeUpgrade::Rolled { .. })),
    }
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
    only: Option<&str>,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_deb(nix, layout, cwd, cfg, only) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the deb packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary(
        "deb",
        &outcomes,
        sandbox::withheld_deb_packages(cfg, only),
        pal,
    ) {
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
    only: Option<&str>,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_appimage(nix, layout, cwd, cfg, only) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the appimage packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary(
        "appimage",
        &outcomes,
        sandbox::withheld_appimage_packages(cfg, only),
        pal,
    ) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::AppImageUpgrade::Failed { .. }))
}

/// Roll the project's and apps' `binary:` `[packages]` — the `tarball:` twin for a download that is
/// the program itself, re-resolving each URL to its current content hash and rewriting the
/// per-project binary lock. Returns whether every reference re-resolved.
fn upgrade_binary_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    only: Option<&str>,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_binary(nix, layout, cwd, cfg, only) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the binary packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary(
        "binary",
        &outcomes,
        sandbox::withheld_binary_packages(cfg, only),
        pal,
    ) {
        println!("{line}");
    }
    !outcomes
        .iter()
        .any(|o| matches!(o, sandbox::BinaryUpgrade::Failed { .. }))
}

/// Roll the project's and apps' `tarball:` `[packages]` — the `deb:` twin, re-resolving each archive
/// URL to its current content hash and rewriting the per-project tarball lock. Returns whether every
/// reference re-resolved.
fn upgrade_tarball_packages(
    nix: &Path,
    layout: &store::Layout,
    cwd: &Path,
    cfg: &config::Resolved,
    only: Option<&str>,
    pal: &style::Palette,
) -> bool {
    let outcomes = match sandbox::upgrade_tarball(nix, layout, cwd, cfg, only) {
        Ok(o) => o,
        Err(e) => {
            diag::error(&format!("sbx: cannot roll the tarball packages: {e}"));
            return false;
        }
    };
    for line in prebuilt_upgrade_summary(
        "tarball",
        &outcomes,
        sandbox::withheld_tarball_packages(cfg, only),
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

/// The four outcomes a distribution roll can have, in the wording the channel rolls use.
///
/// Written out rather than routed through [`channel_upgrade_summary`], which reads a
/// [`store::Upgrade`] and decides "pinned, nothing to roll" by asking whether the *source* is a
/// 40-hex nixpkgs revision. A digest locator is pinned by a different grammar, so sharing that
/// function would mean teaching it a second one — and the branch that matters here (a digest
/// resolving to itself) would silently take the wrong arm.
fn distro_upgrade_summary(
    origin: config::Provenance,
    rolled: &sandbox::distro::store::Rolled,
    pal: &style::Palette,
) -> Vec<String> {
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let origin = match origin {
        config::Provenance::Project => "project",
        config::Provenance::Global => "global",
        config::Provenance::Override => "override",
        config::Provenance::Default => "default",
    };
    let pinned = crate::sandbox::distro::reference::parse(&rolled.locator).is_some_and(|i| {
        matches!(
            i.reference,
            crate::sandbox::distro::reference::Reference::Digest(_)
        )
    });
    let short = |key: &str| {
        short_rev(
            key.trim_start_matches(crate::sandbox::distro::store::DERIVED_PREFIX)
                .trim_start_matches("sha256:"),
        )
        .to_string()
    };
    let now = short(&rolled.key);
    let derived = rolled.key != rolled.base;
    let noun = if derived { "userland" } else { "image" };
    let outcome = match &rolled.previous {
        None => format!(
            "  resolved to {n}{now}{r} {ok}(first pin){r} — the {noun} is built on the next launch."
        ),
        Some(prev) if prev == &rolled.key && pinned && !derived => {
            format!("  pinned to a fixed digest {n}{now}{r} — {dim}nothing to roll.{r}")
        }
        Some(prev) if prev == &rolled.key => {
            format!("  already at {n}{now}{r} — {dim}nothing to do.{r}")
        }
        // A derived userland changed for one of two reasons, and saying which is the whole value of
        // the line: the base moved under the same commands, or the commands were edited.
        Some(prev) if derived => {
            let why = match &rolled.previous_base {
                Some(before) if before != &rolled.base => format!(
                    "the base moved {n}{}{r} → {n}{}{r}",
                    short(before),
                    short(&rolled.base)
                ),
                Some(_) => format!("{n}run{r} changed"),
                None => "the base it was built from is no longer recorded".to_string(),
            };
            format!(
                "  {ok}rebuilt{r} {n}{}{r} → {n}{now}{r} ({why}) — built on the next launch.",
                short(prev)
            )
        }
        Some(prev) => format!(
            "  {ok}rolled forward{r} {n}{}{r} → {n}{now}{r} — the {noun} is unpacked on the next \
             launch.",
            short(prev)
        ),
    };
    vec![
        format!("{h}sbx upgrade — distribution image{r}"),
        format!("  image: {n}{}{r}  ({dim}{origin}{r})", rolled.locator),
        outcome,
    ]
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
                project: None,
                app: None,
            }
        );
    }

    /// The digest a lock records, in the shape `refresh` hands back.
    fn rolled(
        locator: &str,
        digest: &str,
        previous: Option<&str>,
    ) -> sandbox::distro::store::Rolled {
        let full = |c: &str| format!("sha256:{}", c.repeat(64 / c.len()));
        sandbox::distro::store::Rolled {
            locator: locator.to_string(),
            key: full(digest),
            previous: previous.map(&full),
            base: full(digest),
            previous_base: previous.map(&full),
        }
    }

    #[test]
    fn a_distribution_roll_reports_its_four_outcomes_apart() {
        let pal = style::Palette::plain();
        let tag = "oci:docker.io/library/debian:10";
        let pin = "oci:docker.io/library/debian@sha256:".to_string() + &"a".repeat(64);

        let first =
            distro_upgrade_summary(config::Provenance::Global, &rolled(tag, "a", None), &pal);
        assert!(first[2].contains("(first pin)"), "{first:?}");
        assert!(first[1].contains("(global)"), "{first:?}");

        let moved = distro_upgrade_summary(
            config::Provenance::Project,
            &rolled(tag, "b", Some("a")),
            &pal,
        );
        assert!(moved[2].contains("rolled forward"), "{moved:?}");
        assert!(
            moved[2].contains("aaaaaaa") && moved[2].contains("bbbbbbb"),
            "{moved:?}"
        );
        assert!(moved[1].contains("(project)"), "{moved:?}");

        let still = distro_upgrade_summary(
            config::Provenance::Global,
            &rolled(tag, "a", Some("a")),
            &pal,
        );
        assert!(still[2].contains("already at"), "{still:?}");

        // A locator that names a digest resolves to itself, and says so in the word a pin earns
        // rather than in the word a tag that did not move earns.
        let pinned = distro_upgrade_summary(
            config::Provenance::Global,
            &rolled(&pin, "a", Some("a")),
            &pal,
        );
        assert!(pinned[2].contains("pinned to a fixed digest"), "{pinned:?}");
    }

    #[test]
    fn a_derived_userland_says_whether_the_base_moved_or_the_commands_did() {
        // The only question a roll is asked, and the two answers are different work for the reader:
        // a base that moved is upstream's doing, an edited `run` is theirs.
        let pal = style::Palette::plain();
        let tag = "oci:docker.io/library/debian:10";
        let full = |c: &str| format!("sha256:{}", c.repeat(64 / c.len()));
        let derived = |c: &str| format!("derived:sha256:{}", c.repeat(64 / c.len()));

        let base_moved = sandbox::distro::store::Rolled {
            locator: tag.to_string(),
            key: derived("d"),
            previous: Some(derived("c")),
            base: full("b"),
            previous_base: Some(full("a")),
        };
        let out = distro_upgrade_summary(config::Provenance::Global, &base_moved, &pal);
        assert!(out[2].contains("rebuilt"), "{out:?}");
        assert!(out[2].contains("the base moved"), "{out:?}");
        assert!(
            out[2].contains("aaaaaaa") && out[2].contains("bbbbbbb"),
            "{out:?}"
        );

        let run_changed = sandbox::distro::store::Rolled {
            locator: tag.to_string(),
            key: derived("d"),
            previous: Some(derived("c")),
            base: full("a"),
            previous_base: Some(full("a")),
        };
        let out = distro_upgrade_summary(config::Provenance::Project, &run_changed, &pal);
        assert!(out[2].contains("rebuilt"), "{out:?}");
        assert!(out[2].contains("run"), "{out:?}");
        assert!(!out[2].contains("the base moved"), "{out:?}");

        // A derived userland that has not changed says so without claiming a pin: the locator is a
        // tag, and what pins the result is the commands as much as the digest.
        let same = sandbox::distro::store::Rolled {
            locator: tag.to_string(),
            key: derived("c"),
            previous: Some(derived("c")),
            base: full("a"),
            previous_base: Some(full("a")),
        };
        let out = distro_upgrade_summary(config::Provenance::Global, &same, &pal);
        assert!(out[2].contains("already at"), "{out:?}");
        assert!(!out[2].contains("rebuilt"), "{out:?}");
    }

    #[test]
    fn parse_accepts_a_bare_target() {
        for t in TARGETS {
            assert_eq!(
                parse_upgrade_args(&os(&[t])),
                ParsedArgs::Run {
                    what: t,
                    project: None,
                    app: None,
                }
            );
        }
    }

    /// A roll that repoints store paths can leave an app home holding a reference to a path that
    /// is gone — measured once for real: rolling the channel moved the store, a virtualenv's
    /// interpreter symlink died, and the run said nothing. The close must name the apps that build
    /// against those paths — and it stands even now that `all` runs the steps itself, because no
    /// guard inside a step can see that the store moved under the home it built.
    #[test]
    fn a_roll_that_moved_store_paths_names_the_homes_built_against_them() {
        let mut cfg = crate::testutil::resolved(vec![], vec![]);
        assert!(
            store_moved_note(&cfg, None).is_none(),
            "a project with no app says nothing"
        );

        let mut installs = crate::testutil::app_with(vec![]);
        installs.provisions = vec![config::BundleProvision {
            bundle: "odysseus".into(),
            argv: vec!["true".into()],
        }];
        cfg.apps.insert("odysseus".into(), installs);
        cfg.apps
            .insert("plain".into(), crate::testutil::app_with(vec![]));

        let note = store_moved_note(&cfg, None).expect("an app with a step must be named");
        assert!(note.contains("odysseus"), "{note}");
        assert!(
            !note.contains("plain"),
            "an app with no step is not named: {note}"
        );
        assert!(
            note.contains("sbx upgrade provision"),
            "the note must name the command that reconciles now: {note}"
        );
        assert!(
            note.contains("next launch"),
            "the note must say the home also repairs itself, or it reads as breakage: {note}"
        );
        assert!(
            !note.contains("not rolled"),
            "the store note is about what a roll invalidated, never about what it skipped: {note}"
        );

        // A roll narrowed to one app moved only that app's store paths, so the note is narrowed the
        // same way: naming an app the roll never touched would be right about the event and wrong
        // about the subject.
        let mut other = crate::testutil::app_with(vec![]);
        other.provisions = vec![config::BundleProvision {
            bundle: "other-bundle".into(),
            argv: vec!["true".into()],
        }];
        cfg.apps.insert("untouched".into(), other);
        let narrowed =
            store_moved_note(&cfg, Some("odysseus")).expect("the rolled app is still named");
        assert!(narrowed.contains("odysseus"), "{narrowed}");
        assert!(
            !narrowed.contains("untouched"),
            "an app this roll did not touch must not be named: {narrowed}"
        );
        // And an app that rides no install step selects nothing, so the roll closes silently.
        assert!(store_moved_note(&cfg, Some("plain")).is_none());
    }

    /// The scope of the store note, asserted where it is decided. Removing the guard that keeps it
    /// off the channels that place their own artifacts must fail here.
    #[test]
    fn only_the_channels_that_build_through_nix_close_on_the_store_note() {
        // `mise` is in this list on account of the project's `nix:` tools, which resolve to store
        // paths like the channel does — not its engine (host-side, in its own home) and not its
        // `mise:` packages (per-home downloads).
        for what in ["nix", "flake", "mise"] {
            assert_eq!(
                closing_note(what, true),
                ClosingNote::StoreMoved,
                "{what} resolves to store paths, so a replaced revision moved them"
            );
            assert_eq!(
                closing_note(what, false),
                ClosingNote::None,
                "{what} re-resolved to the revision already pinned: nothing moved, so say nothing"
            );
        }
        // These place their own content-hashed artifacts, so none of them moves a path an app home
        // points into. `moved` is passed true to prove the silence comes from the target and not
        // from the flag never being set.
        for what in ["deb", "appimage", "tarball", "binary"] {
            assert_eq!(
                closing_note(what, true),
                ClosingNote::None,
                "{what} does not move the paths a home holds"
            );
        }
        // `all` runs the three channels that move store paths, so it owes the same note they do.
        // It used to be excluded because it printed a note of its own about the steps it skipped;
        // it no longer skips them, so the exclusion went with the reason for it.
        assert_eq!(
            closing_note("all", true),
            ClosingNote::StoreMoved,
            "`all` runs nix/flake/mise, so a moved store path is its note too"
        );
        assert_eq!(
            closing_note("all", false),
            ClosingNote::None,
            "and it says nothing when no revision was replaced"
        );
        assert_eq!(
            closing_note("provision", true),
            ClosingNote::None,
            "the channel that just ran the steps has nothing left to point at"
        );
    }

    #[test]
    fn parse_reads_project_in_both_forms_and_either_order() {
        let want = ParsedArgs::Run {
            what: "distro",
            project: Some(OsString::from("/some/dir")),
            app: None,
        };
        // space form, target first
        assert_eq!(
            parse_upgrade_args(&os(&["distro", "--project", "/some/dir"])),
            want
        );
        // space form, flag first
        assert_eq!(
            parse_upgrade_args(&os(&["--project", "/some/dir", "distro"])),
            want
        );
        // inline form
        assert_eq!(
            parse_upgrade_args(&os(&["distro", "--project=/some/dir"])),
            want
        );
        // `--project` alone keeps the default `all` target
        assert_eq!(
            parse_upgrade_args(&os(&["--project", "/some/dir"])),
            ParsedArgs::Run {
                what: "all",
                project: Some(OsString::from("/some/dir")),
                app: None,
            }
        );
    }

    /// `--app` is read in every spelling and accepted on every target — including the one nobody
    /// types, since `all` is what a bare `sbx upgrade --app x` resolves to, and that is the case
    /// the flag exists for.
    #[test]
    fn parse_reads_app_in_both_forms_and_offers_it_on_every_target() {
        for args in [
            os(&["provision", "--app", "demo-app"]),
            os(&["--app", "demo-app", "provision"]),
            os(&["provision", "--app=demo-app"]),
            os(&["-a", "demo-app", "provision"]),
        ] {
            assert_eq!(
                parse_upgrade_args(&args),
                ParsedArgs::Run {
                    what: "provision",
                    project: None,
                    app: Some("demo-app".to_string()),
                },
                "{args:?}"
            );
        }
        // It composes with `--project`.
        assert_eq!(
            parse_upgrade_args(&os(&["mise", "--app", "demo-app", "--project=/some/dir"])),
            ParsedArgs::Run {
                what: "mise",
                project: Some(OsString::from("/some/dir")),
                app: Some("demo-app".to_string()),
            }
        );

        // EVERY target takes the selector — the invariant the surface now rests on, walked over
        // `TARGETS` itself so a target added later is covered without touching this test. The
        // grammar refuses nothing here: which targets select no work for a GIVEN app is a question
        // about the resolved config, answered by `app_selector_refusal`, and a parser that reads no
        // config must not pre-empt it.
        for t in TARGETS {
            assert_eq!(
                parse_upgrade_args(&os(&[t, "--app", "demo-app"])),
                ParsedArgs::Run {
                    what: t,
                    project: None,
                    app: Some("demo-app".to_string()),
                },
                "`{t}` must accept --app"
            );
        }

        // The defaulted target carries the selector too: `sbx upgrade --app x` is `all` narrowed to
        // one app, which is the whole point of the flag and used to be the one case that refused.
        assert_eq!(
            parse_upgrade_args(&os(&["--app", "demo-app"])),
            ParsedArgs::Run {
                what: "all",
                project: None,
                app: Some("demo-app".to_string()),
            }
        );

        // The five package backends are no longer targets, and the refusal a user meets when they
        // type one — or, far likelier, an app name — names the selector. Spelled out rather than
        // derived from `TARGETS`, so re-adding one of them fails here instead of quietly passing.
        for gone in ["flake", "deb", "appimage", "tarball", "binary"] {
            let ParsedArgs::Error(message) = parse_upgrade_args(&os(&[gone])) else {
                panic!("`{gone}` must no longer be a target");
            };
            assert!(message.contains("unknown upgrade target"), "{message}");
        }
        let ParsedArgs::Error(typo) = parse_upgrade_args(&os(&["freebuff-desktop"])) else {
            panic!("an app name is not a target");
        };
        assert!(
            typo.contains("sbx upgrade --app freebuff-desktop"),
            "the refusal must name what to do with an app name: {typo}"
        );

        // Value forms that carry no name, and a repeat.
        for bad in [
            os(&["provision", "--app"]),
            os(&["provision", "--app="]),
            os(&["provision", "--app", "a", "--app", "b"]),
        ] {
            assert!(
                matches!(parse_upgrade_args(&bad), ParsedArgs::Error(_)),
                "{bad:?}"
            );
        }
    }

    /// An app name that selects no work gets the reason it selects none — the three cases have
    /// three different answers, and only one of them is a typo.
    #[test]
    fn the_app_selector_says_which_way_it_selected_nothing() {
        let mut cfg = crate::testutil::resolved(vec![], vec![]);
        let mut installs = crate::testutil::app_with(vec![]);
        installs.provisions = vec![config::BundleProvision {
            bundle: "trae".into(),
            argv: vec!["true".into()],
        }];
        cfg.apps.insert("trae".into(), installs);
        cfg.apps
            .insert("plain".into(), crate::testutil::app_with(vec![]));
        let mut unlaunchable = crate::testutil::app_with(vec![]);
        unlaunchable.cmd.clear();
        cfg.apps.insert("ghost".into(), unlaunchable);

        // The app that has a step: no refusal, the roll runs.
        assert!(app_selector_refusal(&cfg, "trae", "provision", "upgrade").is_none());

        // A name no app carries — the typo case, pointed at the listing.
        let unknown =
            app_selector_refusal(&cfg, "nope", "provision", "upgrade").expect("unknown is refused");
        assert!(unknown.contains("no app named"), "{unknown}");
        assert!(unknown.contains("sbx app ls"), "{unknown}");

        // An app that cannot launch is its own case: it is not "declares none", it can never run.
        let dead = app_selector_refusal(&cfg, "ghost", "provision", "upgrade")
            .expect("unlaunchable refused");
        assert!(dead.contains("no command"), "{dead}");

        // An app that rides a backend instead: named with the command that DOES advance it.
        let backend =
            app_selector_refusal(&cfg, "plain", "provision", "upgrade").expect("no step refused");
        assert!(backend.contains("no install step"), "{backend}");
        assert!(backend.contains("sbx upgrade --app plain"), "{backend}");

        // The same taxonomy for the other in-cage roll: no `mise:` package, no work.
        let no_mise =
            app_selector_refusal(&cfg, "trae", "mise", "upgrade").expect("no mise package refused");
        assert!(no_mise.contains("no `mise:` package"), "{no_mise}");

        // An app whose only `mise:` package is withheld for being untrusted has nothing to roll
        // either: the equip drops it, so accepting the name here would end in a bare "nothing
        // rolled" — exactly what these three messages replace. The refusal asks the roll's own
        // question, so the two cannot drift apart.
        let mut untrusted = crate::testutil::app_with(vec![]);
        untrusted.packages = vec![config::Package {
            name: "evil".into(),
            backend: config::Backend::Mise("aqua:attacker/x".into()),
            state: crate::trust::TrustState::Untrusted,
            libs: Vec::new(),
            main: String::new(),
        }];
        cfg.apps.insert("shady".into(), untrusted);
        let withheld =
            app_selector_refusal(&cfg, "shady", "mise", "upgrade").expect("withheld-only refused");
        assert!(withheld.contains("no `mise:` package"), "{withheld}");

        // The layers meet by *name*, so an app that re-declares a baseline `mise:` tool under
        // another backend replaces it — its cage equips no mise package at all. Asking each layer
        // on its own still found the baseline's, so the selector accepted the app, the roll
        // equipped nothing, and the run ended in the bare "nothing rolled" these messages replace.
        let mut baseline = crate::testutil::resolved(vec![], vec![]);
        baseline.packages = vec![pkg("tool", config::Backend::Mise("aqua:demo/tool".into()))];
        let mut overrides = crate::testutil::app_with(vec![]);
        overrides.packages = vec![pkg("tool", config::Backend::Nix("hello".into()))];
        baseline.apps.insert("swapped".into(), overrides);
        let shadowed = app_selector_refusal(&baseline, "swapped", "mise", "upgrade")
            .expect("an overridden tool is gone");
        assert!(shadowed.contains("no `mise:` package"), "{shadowed}");

        // The image is the project's, and no app can declare one: a different answer from the two
        // above, so it names the command WITHOUT the selector rather than a narrower one that
        // would refuse in turn.
        let image = app_selector_refusal(&cfg, "trae", "distro", "upgrade")
            .expect("no app declares a distribution image");
        assert!(image.contains("the project's"), "{image}");
        assert!(image.contains("sbx upgrade distro"), "{image}");
        assert!(
            !image.contains("sbx upgrade distro --app"),
            "the way out must not carry the selector it just refused: {image}"
        );

        // The defaulted target, which both `sbx upgrade --app x` and `sbx app upgrade x` resolve
        // to. An app that declares nothing and installs nothing would otherwise print a header,
        // roll nothing and exit 0 — a clean report of work that never existed.
        let empty = app_selector_refusal(&cfg, "plain", "all", "upgrade")
            .expect("an app with nothing of its own is refused");
        assert!(empty.contains("no packages and no install step"), "{empty}");
        // And the control: an app that has a step is not refused on the defaulted target.
        assert!(app_selector_refusal(&cfg, "trae", "all", "upgrade").is_none());

        // Each spelling names itself. One definition, two verbs.
        let via_app_verb = app_selector_refusal(&cfg, "plain", "all", "app upgrade")
            .expect("the per-app verb refuses it too");
        assert!(
            via_app_verb.starts_with("sbx: app upgrade:"),
            "{via_app_verb}"
        );

        // The control, one name apart: an app that adds its own tool beside the baseline's still
        // has work, and so does one that inherits the baseline's untouched.
        let mut beside = crate::testutil::app_with(vec![]);
        beside.packages = vec![pkg("other", config::Backend::Nix("hello".into()))];
        baseline.apps.insert("beside".into(), beside);
        assert!(
            app_selector_refusal(&baseline, "beside", "mise", "upgrade").is_none(),
            "the baseline's tool is still equipped when the app names a different one"
        );
    }

    /// An inline flake rides no channel at all: the `flake:` roll's own selector skips it.
    ///
    /// Asserted against that selector rather than against a second copy of the rule —
    /// [`sandbox::flake_packages`] is what the roll walks, and it returns nothing for an inline
    /// flake, which pins itself in its own source and rebuilds when that source changes. It
    /// matters to the per-app roll too: `sbx upgrade --app <name>` narrows the same selector, so an
    /// app whose only package is an inline flake rolls nothing here and is not told otherwise.
    #[test]
    fn an_inline_flake_is_not_selected_by_the_roll_that_skips_it() {
        let inline = pkg(
            "gizmo",
            config::Backend::FlakeInline {
                content: "{ outputs = _: {}; }".into(),
                attr: "default".into(),
            },
        );
        assert!(
            sandbox::flake_packages(std::slice::from_ref(&inline)).is_empty(),
            "the `flake:` roll does not select an inline flake"
        );

        // The counter-case, so this does not pass by selecting no flake at all: a remote reference
        // IS what that roll advances.
        let remote = pkg(
            "remote",
            config::Backend::Flake("github:owner/repo#attr".into()),
        );
        assert_eq!(
            sandbox::flake_packages(std::slice::from_ref(&remote)).len(),
            1
        );
    }

    /// A package with one backend, trusted unless said otherwise.
    fn pkg(name: &str, backend: config::Backend) -> config::Package {
        config::Package {
            name: name.into(),
            backend,
            state: crate::trust::TrustState::Trusted,
            libs: Vec::new(),
            main: String::new(),
        }
    }

    /// Every `Backend` gets one of the three answers, and the answers are pinned by hand.
    ///
    /// The compiler already refuses a new variant (the match in [`advance_of`] has no `_` arm), so
    /// what this adds is the *content* of the answer: a variant swept into the wrong arm of an
    /// existing group compiles fine and would send the reader to a command that does not roll it.
    #[test]
    fn the_install_step_says_what_it_costs_before_it_runs() {
        let plain = style::Palette::plain();
        let mut cfg = crate::testutil::resolved(vec![], vec![]);
        let mut with_mise = crate::testutil::app_with(vec![]);
        with_mise.packages = vec![pkg("tool", config::Backend::Mise("aqua:demo/tool".into()))];
        cfg.apps.insert("junie".into(), with_mise);
        cfg.apps
            .insert("trae".into(), crate::testutil::app_with(vec![]));

        let line = install_step_notice("junie", &cfg, &plain);
        assert!(line.contains("re-runs in junie's own cage"), "{line}");
        assert!(line.contains("downloads again"), "{line}");
        // The forcing is named, not implied. An unscoped `sbx upgrade` leaves each guard in
        // charge; under a selector the step installs regardless, and this is the only line a
        // reader sees before the download starts.
        assert!(line.contains("regardless of its guard"), "{line}");
        // The escape hatch, named rather than implied: the surface already has the narrower verb.
        assert!(line.contains("sbx upgrade mise --app junie"), "{line}");

        // But not offered where it would refuse. `sbx upgrade mise --app trae` answers "declares no
        // `mise:` package" for an app the install step is the whole of, and pointing a reader at a
        // refusal one line before the work is this notice's own failure mode, reintroduced.
        let line = install_step_notice("trae", &cfg, &plain);
        assert!(line.contains("downloads again."), "{line}");
        assert!(
            !line.contains("sbx upgrade mise"),
            "an app with no `mise:` package must not be sent to the roll that refuses it: {line}"
        );
    }

    /// The two commands that resolve an app name give the same two sentences, differing only in the
    /// verb that names itself.
    ///
    /// One definition, asserted rather than assumed: these sentences were written for `sbx upgrade
    /// --app` and are now also what `sbx app upgrade` refuses with, so a change to one must reach
    /// the other.
    #[test]
    fn both_commands_refuse_an_unusable_name_with_one_definition() {
        let mut cfg = crate::testutil::resolved(vec![], vec![]);
        let mut unlaunchable = crate::testutil::app_with(vec![]);
        unlaunchable.cmd.clear();
        cfg.apps.insert("ghost".into(), unlaunchable);

        for name in ["nope", "ghost"] {
            let via_channel = app_selector_refusal(&cfg, name, "mise", "upgrade").expect("refused");
            let Err(via_app_verb) = launchable_app(&cfg, name, "app upgrade") else {
                panic!("`{name}` must be refused by the per-app verb too");
            };
            assert_eq!(
                via_channel.replacen("sbx: upgrade: ", "sbx: app upgrade: ", 1),
                via_app_verb,
                "the two verbs must differ only in their own name"
            );
        }
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
        assert!(
            text(store::Upgrade {
                source: "nixos-unstable".into(),
                previous: None,
                revision: rev.into(),
            })
            .contains("first pin")
        );

        // an unchanged channel
        assert!(
            text(store::Upgrade {
                source: "nixos-unstable".into(),
                previous: Some(rev.into()),
                revision: rev.into(),
            })
            .contains("already at the latest")
        );

        // a fixed revision pin cannot roll
        assert!(
            text(store::Upgrade {
                source: rev.into(),
                previous: Some(rev.into()),
                revision: rev.into(),
            })
            .contains("fixed revision")
        );

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
    fn rolling_one_app_is_refused_where_the_project_pin_would_be_rolled_instead() {
        // `--app` narrows `nix` because an app has its own lock — but a trusted project pin
        // outranks that lock, so under a pin the target that comes back is the project's. Rolling
        // it would do project-wide work under a flag that reads "only this app", so it is refused,
        // and nothing is written. The condition is read off the resolved target's origin, never
        // re-derived from the config here, so the refusal cannot disagree with the choice.
        let data = TmpDir::new();
        let proj = TmpDir::new();
        let layout = store::Layout::under(data.path());
        let mut cfg = crate::testutil::resolved(vec![], vec![]);
        cfg.nixpkgs_project = Some("f".repeat(40));

        let roll = upgrade_nix_channel(
            Path::new("/nonexistent-nix"),
            &layout,
            proj.path(),
            &cfg,
            Some("demo-app"),
            &style::Palette::plain(),
        );
        assert!(!roll.ok, "the roll must refuse rather than run");
        assert!(!roll.moved);
        assert!(
            !layout.data_dir().join("projects").exists(),
            "a refused roll writes no project lock"
        );
        assert!(!layout.data_dir().join("apps").exists());

        // Without a pin the same call is the app's own roll, and it succeeds: a 40-hex source
        // resolves with no nix, and the revision lands in that app's lock.
        let mut unpinned = crate::testutil::resolved(vec![], vec![]);
        unpinned.nixpkgs_global = Some("e".repeat(40));
        let roll = upgrade_nix_channel(
            Path::new("/nonexistent-nix"),
            &layout,
            proj.path(),
            &unpinned,
            Some("demo-app"),
            &style::Palette::plain(),
        );
        assert!(roll.ok);
        assert!(
            layout
                .data_dir()
                .join("apps/demo-app/nixpkgs.lock")
                .is_file()
        );
        assert!(
            !layout.data_dir().join("nixpkgs.lock").exists(),
            "an app roll must not touch the global channel lock"
        );
    }

    #[test]
    fn upgrade_mise_and_upgrade_nix_roll_separate_locks() {
        // The decoupling guarantee at the file level: rolling the engine must leave the
        // base channel lock byte-identical, and rolling the base must leave the engine
        // lock byte-identical. Proven deterministically with revision sources, which
        // resolve without nix — so a bogus nix path is never invoked. The roll mechanics
        // are already covered by store/channel.rs's `refresh*` tests (which `LockTarget::engine`
        // reuses verbatim); what is net-new here is that the two commands write two
        // distinct files.
        let bogus_nix = Path::new("/nonexistent-nix");
        let rev_a = "a".repeat(40);
        let rev_b = "b".repeat(40);
        let cfg = |global: &str| config::Resolved {
            apps_share_install_pools: false,
            apps_share_install_pools_origin: Default::default(),
            distro_run: Vec::new(),
            accepts_fresh_releases: Default::default(),
            timezone: None,
            timezone_origin: config::Provenance::Default,
            distro: None,
            distro_auth: None,
            distro_origin: config::Provenance::Default,
            plugin: Default::default(),
            net_groups: Default::default(),
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
            open: Default::default(),
            service: Default::default(),
            provisions: Default::default(),
            nixpkgs_global: Some(global.to_string()),
            mise_engine: None,
            nixpkgs_project: None,
            mise: None,
            mise_ignored: Vec::new(),
            network: config::NetworkPolicy::Shared,
            network_origin: Default::default(),
            egress_stats: true,
            redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
            redact_min_len_origin: Default::default(),
            observe_record: false,
            observe_record_origin: Default::default(),
            gui: config::GuiPolicy::default(),
            gui_origin: Default::default(),
            proc: Default::default(),
            proc_origin: Default::default(),
            gpu: false,
            allow_insecure_http: false,
            audio: false,
            dbus: false,
            gpu_origin: Default::default(),
            allow_insecure_http_origin: Default::default(),
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
            brokers: Vec::new(),
            declared_secrets: vec![],
            apps: std::collections::BTreeMap::new(),
            warnings: vec![],
            refused: None,
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
        let seed = upgrade_nix_channel(bogus_nix, &layout, data.path(), &cfg(&rev_a), None, &plain);
        assert!(seed.ok);
        assert!(
            !seed.moved,
            "a first resolution pins a revision, it replaces none — nothing a home holds moved"
        );
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
        let rolled =
            upgrade_nix_channel(bogus_nix, &layout, data.path(), &cfg(&rev_b), None, &plain);
        assert!(rolled.ok);
        assert!(
            rolled.moved,
            "REV_A was locked and REV_B replaced it: the store paths moved"
        );
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
        assert!(
            text.contains("flake:github:o/e#default: re-resolve failed — metadata unreachable")
        );

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
        assert!(
            text.contains(
                "appimage:https://e/d.AppImage: re-resolve failed — prefetch unreachable"
            )
        );

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
