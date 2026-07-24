//! `sbx app <subcommand>`: launch and manage named application profiles — `run <name>` (launch an
//! app inside the project sandbox) and `import`/`export`/`rm`/`list`/`show`/`prune` (manage the
//! profiles and their per-app isolated homes). The launch verb is mandatory, so the first token is
//! always a subcommand and an app name can never collide with one. The shared confirmation
//! renderers (`render_app_imported`/`render_app_exported`/`render_removed`) stay at the crate root.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::confirm::{render_app_exported, render_app_imported, render_removed};
use crate::{
    build_override, config_cwd, egress_write_target, flag_name, net_mode_word, persist_egress_rule,
    take_override_flag,
};
use crate::{config, diag, help, sandbox, session, store, style, trust};

/// `sbx app <subcommand>`: launch or manage named application profiles. `run <name>` launches an
/// app (an `[app.<name>]` table from the global or project config, or an imported `<name>.toml`
/// profile) inside the project sandbox; `import`/`export`/`rm`/`list`/`show`/`prune` manage them.
/// Launching goes through the explicit `run` verb, so the first token is always a subcommand and an
/// app name can never collide with one — an app may be named `run`, `show`, etc., and is reached as
/// `sbx app run <name>`.
pub(crate) fn app_cmd(args: Vec<OsString>) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("run") => app_run(&args[1..]),
        Some("import") => app_import(&args[1..]),
        Some("export") => app_export(&args[1..]),
        Some("rm") => app_rm(&args[1..]),
        Some("list" | "ls") => app_list(),
        Some("show") => app_show(&args[1..]),
        Some("prune") => app_prune(&args[1..]),
        // No valid subcommand: a bare `sbx app`, an unknown token, a leading flag, or a non-UTF-8
        // token. There is no launch to act on — name the launch verb and print the usage page.
        _ => {
            diag::error(
                "sbx: app needs a subcommand — to launch an app, use `sbx app run <name>`.",
            );
            eprint!("{}", help::page_usage(&["app"]).unwrap_or_default());
            ExitCode::from(2)
        }
    }
}

/// `sbx app run <name> [--detach] [--net-learn…] [override flags] [-- <args>…]`: launch a named
/// application profile inside the project sandbox. The name, `--detach`, `--net-learn`, and the
/// one-shot overrides are read from the head (see [`parse_app_launch`]); tokens after a `--` are
/// appended verbatim to the app's declared command.
fn app_run(args: &[OsString]) -> ExitCode {
    match parse_app_launch(args) {
        Ok(launch) => {
            let ov = match build_override(launch.cli) {
                Ok(ov) => ov,
                Err(code) => return code,
            };
            let outcome = sandbox::app(
                &launch.name,
                launch.detach,
                launch.observe,
                launch.tail,
                ov,
                launch.net_learn.as_ref().map(|nl| nl.gran),
            );
            match (outcome.learned, launch.net_learn) {
                (Some(synth), Some(nl)) => finish_net_learn(&launch.name, synth, &nl),
                _ => outcome.code,
            }
        }
        Err(code) => code,
    }
}

/// Apply the rules `sbx app <name> --net-learn` synthesized from the run: surface the notes (nothing
/// is dropped silently), then either preview the diff (`--dry-run`) or write each rule to the chosen
/// profile. The exit code reflects the *learning* outcome, not the agent's exit — a `--net-learn` run
/// is expected to fail hosts it lacks rules for, so its non-zero exit is not this command's failure;
/// only a write error is.
fn finish_net_learn(name: &str, synth: sandbox::Synthesis, nl: &NetLearn) -> ExitCode {
    use config::manage::EgressList;
    for note in &synth.notes {
        diag::warn(note);
    }
    if synth.rules.is_empty() {
        let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
        println!(
            "{}",
            style::prose(
                &format!(
                    "sbx net-learn: no new egress rules — app `{name}` was refused nothing it lacked a rule for."
                ),
                &pal
            )
        );
        return ExitCode::SUCCESS;
    }
    let cwd = match config_cwd() {
        Ok(c) => c,
        Err(code) => return code,
    };
    // Resolve the human target once (the file the rules land in), shared by the preview and the write
    // messages so they cannot disagree about where the rules go.
    let target = match egress_write_target(&nl.scope, Some(name), &cwd) {
        Ok((_, _, target)) => target,
        Err((code, msg)) => {
            diag::error(&format!("sbx net-learn: {msg}"));
            return ExitCode::from(code);
        }
    };
    if nl.dry_run {
        println!(
            "sbx net-learn ({}): {} rule(s) would be added to {target} (dry run — nothing written):",
            nl.gran.as_str(),
            synth.rules.len()
        );
        for rule in &synth.rules {
            println!("  allow {rule}");
        }
        return ExitCode::SUCCESS;
    }
    // Write each rule through the shared persister, so a project write is trust-gated and re-trusted
    // exactly like `sbx net allow`. One rule per call (each re-trusts a gated project write); a batch
    // writer is a future refinement.
    let mut failed = false;
    for rule in &synth.rules {
        match persist_egress_rule(EgressList::Allow, rule, &nl.scope, Some(name), &cwd) {
            Ok(msg) => println!(
                "{}",
                style::prose(
                    &msg,
                    &style::Palette::for_stream(std::io::stdout().is_terminal())
                )
            ),
            Err((_, msg)) => {
                diag::error(&format!("sbx net-learn: {msg}"));
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

/// Parse the launch form of `sbx app run`: split sbx's own arguments from the app command's trailing
/// arguments at the first `--`, then read the app name and `--detach` from the head. Tokens after
/// `--` are appended verbatim to the app's declared `cmd` (e.g. `sbx app run demo-app -- -c` passes
/// `-c` to the launched command, so an agent can resume a session or tweak a flag without editing the
/// profile). An unknown flag or a second name in the head is a usage error, so a typo cannot
/// silently launch a different posture (a mistyped `--detach` running attached, or extra tokens
/// dropped without a word). The passthrough arguments are host-user input at invocation time, so
/// they carry no config trust — an untrusted project cannot inject them, and the `cmd` integrity
/// gate (which blocks a config-supplied `cmd` override) is a separate, intact vector. A pure
/// parser so the split and the head rules are unit-tested without launching a cage; the caller
/// maps `Err(code)` to an exit.
///
/// A one-shot override (`--config <toml|@file>`/`--env KEY=VALUE`, repeatable) is read from the head
/// too, in any order with the name and `--detach`; the collected values are returned for the caller
/// to build the override (kept out of this pure parser, which reads no environment). The head is
/// parsed as a mutable queue so a value-taking flag can pull its argument.
fn parse_app_launch(args: &[OsString]) -> Result<AppLaunch, ExitCode> {
    use config::manage::Scope;
    let (mut head, tail): (Vec<OsString>, Vec<OsString>) = match args.iter().position(|a| a == "--")
    {
        Some(i) => (args[..i].to_vec(), args[i + 1..].to_vec()),
        None => (args.to_vec(), Vec::new()),
    };
    let mut detach = false;
    let mut observe = false;
    let mut name: Option<String> = None;
    let mut cli = config::CliOverrides::default();
    // `--net-learn` state: the granularity (once seen), the write scope, and whether to only preview.
    // The scope/`--dry-run` flags are meaningful only with `--net-learn`, enforced after the loop.
    let mut learn_gran: Option<sandbox::Granularity> = None;
    let mut scope = Scope::Local;
    let mut scope_seen = false;
    let mut dry_run = false;
    while !head.is_empty() {
        // Decide on the leading token, then act — the match ends the immutable borrow so a
        // value-taking flag can mutate the queue.
        let Some(raw) = head[0].to_str().map(str::to_string) else {
            diag::error(&format!(
                "sbx: app name must be valid text — usage: {}",
                help::synopsis_of(&["app", "run"])
            ));
            return Err(ExitCode::from(2));
        };
        match flag_name(&raw) {
            "--detach" => {
                detach = true;
                head.remove(0);
            }
            "--observe" => {
                observe = true;
                head.remove(0);
            }
            // `--net-learn[=domain|path|exact]`: the value after `=` picks the granularity; a bare
            // flag is the widest, `domain`.
            "--net-learn" => {
                let gran = match raw.split_once('=') {
                    Some((_, value)) => match sandbox::Granularity::parse(value) {
                        Ok(g) => g,
                        Err(e) => {
                            diag::error(&format!("sbx: {e}"));
                            return Err(ExitCode::from(2));
                        }
                    },
                    None => sandbox::Granularity::default(),
                };
                learn_gran = Some(gran);
                head.remove(0);
            }
            "--dry-run" => {
                dry_run = true;
                head.remove(0);
            }
            "--global" | "-g" => {
                scope = Scope::Global;
                scope_seen = true;
                head.remove(0);
            }
            "--local" | "-l" => {
                scope = Scope::Local;
                scope_seen = true;
                head.remove(0);
            }
            // A one-shot override flag, an unknown flag, or the app name.
            _ => match take_override_flag(&mut head, &mut cli, "app") {
                Some(res) => res?,
                None => {
                    if raw.starts_with('-') {
                        diag::error(&format!(
                            "sbx: unknown flag {raw} — usage: {}",
                            help::synopsis_of(&["app", "run"])
                        ));
                        return Err(ExitCode::from(2));
                    }
                    if name.is_some() {
                        diag::error(&format!(
                            "sbx: app takes a single name — usage: {}",
                            help::synopsis_of(&["app", "run"])
                        ));
                        return Err(ExitCode::from(2));
                    }
                    name = Some(raw);
                    head.remove(0);
                }
            },
        }
    }
    let Some(name) = name else {
        // `sbx app run` with no name (or only flags): print the run page so its synopsis and
        // options guide, like bare `sbx net`/`sbx config`.
        eprint!("{}", help::page_usage(&["app", "run"]).unwrap_or_default());
        return Err(ExitCode::from(2));
    };
    // `--net-learn` reviews and writes rules in the foreground; `--detach` has no session to observe.
    if learn_gran.is_some() && detach {
        diag::error(
            "sbx: --net-learn cannot be combined with --detach (it observes a foreground run).",
        );
        return Err(ExitCode::from(2));
    }
    // The write scope and `--dry-run` only shape where `--net-learn` puts its rules; refuse them on a
    // plain launch rather than silently ignoring a flag the user expected to matter.
    if learn_gran.is_none() && (scope_seen || dry_run) {
        diag::error("sbx: --global/--local/--dry-run apply only with --net-learn.");
        return Err(ExitCode::from(2));
    }
    let net_learn = learn_gran.map(|gran| NetLearn {
        gran,
        scope,
        dry_run,
    });
    Ok(AppLaunch {
        name,
        detach,
        observe,
        tail,
        cli,
        net_learn,
    })
}

/// The parsed launch form of `sbx app`: the app name, `--detach`, the passthrough args after `--`,
/// the one-shot overrides, and the optional `--net-learn` intent.
struct AppLaunch {
    name: String,
    detach: bool,
    observe: bool,
    tail: Vec<OsString>,
    cli: config::CliOverrides,
    net_learn: Option<NetLearn>,
}

/// The `--net-learn` intent: how wide to synthesize rules, which profile to write them to, and
/// whether to only preview the diff.
struct NetLearn {
    gran: sandbox::Granularity,
    scope: config::manage::Scope,
    dry_run: bool,
}

/// `sbx app import <file> [--as <name>] [--force]`: validate a portable app profile and place it
/// under the imported-profiles directory, where it is trusted by location (honored even on an
/// untrusted project). The deliberate command IS the consent — an agent in the cage cannot run it,
/// and the profile stays inert until `sbx app <name>` launches it — so there is no interactive
/// prompt, but the granted posture is printed so the act is informed. The bytes are copied
/// verbatim (comments and formatting preserved); the name comes from `--as` or the source file
/// stem, never the file's contents, so the profile is name-agnostic and re-namable for free.
fn app_import(args: &[OsString]) -> ExitCode {
    let mut source: Option<&OsString> = None;
    let mut as_name: Option<String> = None;
    let mut force = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--as") => match it.next().and_then(|a| a.to_str()) {
                Some(n) => as_name = Some(n.to_string()),
                None => {
                    diag::error("sbx: --as needs a name");
                    return ExitCode::from(2);
                }
            },
            Some("--force") => force = true,
            Some(flag) if flag.starts_with("--") => {
                diag::error(&format!(
                    "sbx: unknown flag '{flag}' (usage: {})",
                    help::synopsis_of(&["app", "import"])
                ));
                return ExitCode::from(2);
            }
            _ if source.is_none() => source = Some(arg),
            _ => {
                diag::error("sbx: sbx app import takes a single file");
                return ExitCode::from(2);
            }
        }
    }
    let Some(source) = source else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["app", "import"])
        ));
        return ExitCode::from(2);
    };
    let src_path = Path::new(source);

    // The app name: `--as`, else the source file stem. It keys an on-disk file, so it is validated
    // for charset/length and refused otherwise — fail-closed.
    let name = match as_name {
        Some(n) => n,
        None => match src_path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => {
                diag::error(&format!(
                    "sbx: cannot derive a name from {} — pass --as <name>",
                    src_path.display()
                ));
                return ExitCode::from(2);
            }
        },
    };
    if !config::is_valid_app_name(&name) {
        diag::error(&format!(
            "sbx: '{name}' is not a usable app name (1–64 of [A-Za-z0-9._-], not `.`/`..`)"
        ));
        return ExitCode::from(2);
    }

    let Some(dir) = config::profiles_dir() else {
        diag::error("sbx: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return ExitCode::FAILURE;
    };

    // Read the source through the same safety gate every config file passes (owner-owned,
    // non-world-writable, regular file), then validate it is a real profile before writing.
    let bytes = match config::safety::read_safe_bytes(src_path) {
        Ok(b) => b,
        Err(e) => {
            diag::error(&format!("sbx: cannot read {}: {e}", src_path.display()));
            return ExitCode::FAILURE;
        }
    };
    let preview = match config::validate_profile(&bytes) {
        Ok(p) => p,
        Err(e) => {
            diag::error(&format!(
                "sbx: {} is not a valid app profile: {e}",
                src_path.display()
            ));
            return ExitCode::FAILURE;
        }
    };

    let dest = dir.join(format!("{name}.toml"));
    if dest.exists() && !force {
        diag::error(&format!(
            "sbx: a profile '{name}' already exists at {} (use --force to overwrite)",
            dest.display()
        ));
        return ExitCode::FAILURE;
    }
    if let Err(e) = write_profile_file(&dir, &dest, &bytes) {
        diag::error(&format!("sbx: cannot write {}: {e}", dest.display()));
        return ExitCode::FAILURE;
    }

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!(
        "{}",
        render_app_imported(&name, &dest, &preview.summary, &pal)
    );
    ExitCode::SUCCESS
}

/// Write a profile's bytes to `dest`, owner-only, creating the profiles directory owner-only if
/// it is missing. The bytes go to a sibling temp file (owner-only from creation, so a later read
/// passes the safety gate) and are then renamed into place — atomic, like every other on-disk
/// placement sbx makes: a failed or interrupted write never leaves a partial profile at the real
/// name, and a `--force` overwrite keeps the previous profile until the new one is fully written.
fn write_profile_file(dir: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let tmp = dir.join(format!(".import-{}.tmp", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    if let Err(e) = f.write_all(bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// `sbx app export <name> [--out <file>]`: write a named app out as a portable profile — an
/// imported profile verbatim, or an inline app serialized to a minimal top-level profile (as
/// authored, security fields and all; import is the trust act, not export). Writes to stdout by
/// default (composable and clobber-safe — `sbx app export demo-app > demo-app.toml`), or to `--out
/// <file>` directly. The exported file re-imports identically (the round-trip the feature sells).
fn app_export(args: &[OsString]) -> ExitCode {
    let mut name: Option<&str> = None;
    let mut out: Option<&OsString> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--out") => match it.next() {
                Some(p) => out = Some(p),
                None => {
                    diag::error("sbx: --out needs a file");
                    return ExitCode::from(2);
                }
            },
            Some(flag) if flag.starts_with("--") => {
                diag::error(&format!(
                    "sbx: unknown flag '{flag}' (usage: {})",
                    help::synopsis_of(&["app", "export"])
                ));
                return ExitCode::from(2);
            }
            Some(n) if name.is_none() => name = Some(n),
            None if name.is_none() => {
                diag::error("sbx: the app name must be valid UTF-8");
                return ExitCode::from(2);
            }
            _ => {
                diag::error("sbx: sbx app export takes a single name");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        diag::error(&format!(
            "sbx: usage: {}",
            help::synopsis_of(&["app", "export"])
        ));
        return ExitCode::from(2);
    };
    // The name reaches a filesystem lookup, so validate it (charset/length, no traversal).
    if !config::is_valid_app_name(name) {
        diag::error(&format!("sbx: '{name}' is not a valid app name"));
        return ExitCode::from(2);
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            diag::error(&format!("sbx: cannot read the current directory: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let bytes = match config::export_profile(&cwd, name) {
        Ok(b) => b,
        Err(e) => {
            diag::error(&format!("sbx: {e}"));
            return ExitCode::FAILURE;
        }
    };
    match out {
        None => {
            use std::io::Write as _;
            if let Err(e) = std::io::stdout().write_all(&bytes) {
                diag::error(&format!("sbx: cannot write the profile: {e}"));
                return ExitCode::FAILURE;
            }
        }
        Some(path) => {
            let path = Path::new(path);
            if let Err(e) = std::fs::write(path, &bytes) {
                diag::error(&format!("sbx: cannot write {}: {e}", path.display()));
                return ExitCode::FAILURE;
            }
            // The confirmation goes to stderr (stdout is reserved for the profile bytes), so its
            // palette is decided from stderr's stream, not stdout's.
            let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
            eprintln!("{}", render_app_exported(name, path, &epal));
        }
    }
    ExitCode::SUCCESS
}

/// `sbx app rm <name> [--purge] [--gc]`: remove an app.
///
/// By default this removes only the imported **profile** (a file in the profiles directory) — a
/// project `[app.<name>]` overlay lives in that project's `.sbx.toml` and is the user's to edit
/// there. With `--purge` it also removes the app's isolated **runtime state**: its per-app home(s)
/// (the mise tools its `mise:` backends installed, its config, and its login/session state), which
/// is freed immediately. `--gc` (which requires `--purge`) then sweeps the **current project's**
/// nix store — reclaiming the app's now-unreferenced `nix:`/`flake:` closures in one command for the
/// common single-project case (see [`app_rm_purge`]). The name is validated before it is joined to
/// any path (anti-traversal).
fn app_rm(args: &[OsString]) -> ExitCode {
    let (purge, gc, name) = match parse_app_rm(args) {
        AppRmArgs::Ok { purge, gc, name } => (purge, gc, name),
        AppRmArgs::MissingName => {
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["app", "rm"])
            ));
            return ExitCode::from(2);
        }
        AppRmArgs::UnknownOption(tok) => {
            diag::error(&format!("sbx: app rm: unknown option `{tok}`"));
            diag::error(&format!(
                "sbx: usage: {}",
                help::synopsis_of(&["app", "rm"])
            ));
            return ExitCode::from(2);
        }
        AppRmArgs::Extra(tok) => {
            diag::error(&format!(
                "sbx: app rm: unexpected argument `{tok}` (one app name only)"
            ));
            return ExitCode::from(2);
        }
        AppRmArgs::NonUtf8 => {
            diag::error("sbx: app rm: argument is not valid UTF-8");
            return ExitCode::from(2);
        }
    };
    if !config::is_valid_app_name(name) {
        diag::error(&format!("sbx: '{name}' is not a valid app name"));
        return ExitCode::from(2);
    }
    // `--gc` reclaims the store an app's homes referenced, so it only makes sense alongside the
    // home removal `--purge` performs — never on a bare profile removal.
    if gc && !purge {
        diag::error(
            "sbx: app rm: `--gc` requires `--purge` (it sweeps the store the purged home used)",
        );
        return ExitCode::from(2);
    }
    if purge {
        app_rm_purge(name, gc)
    } else {
        app_rm_profile(name)
    }
}

/// The structural parse of `sbx app rm` arguments (before name validation). Kept pure so the flag/
/// positional handling — `--purge`, `--gc`, and the single app name in any order — is unit-tested.
/// The name's charset validation and the `--gc`-requires-`--purge` rule are the caller's next steps.
enum AppRmArgs<'a> {
    Ok {
        purge: bool,
        gc: bool,
        name: &'a str,
    },
    MissingName,
    UnknownOption(&'a str),
    Extra(&'a str),
    NonUtf8,
}

fn parse_app_rm(args: &[OsString]) -> AppRmArgs<'_> {
    let mut purge = false;
    let mut gc = false;
    let mut name: Option<&str> = None;
    for arg in args {
        match arg.to_str() {
            Some("--purge") => purge = true,
            Some("--gc") => gc = true,
            Some(tok) if tok.starts_with('-') => return AppRmArgs::UnknownOption(tok),
            Some(tok) if name.is_none() => name = Some(tok),
            Some(tok) => return AppRmArgs::Extra(tok),
            None => return AppRmArgs::NonUtf8,
        }
    }
    match name {
        Some(name) => AppRmArgs::Ok { purge, gc, name },
        None => AppRmArgs::MissingName,
    }
}

/// Remove app `name`'s imported profile only (the default `sbx app rm`). A missing profile is an
/// error here — the user asked to remove a profile and there is none to remove (with `--purge` a
/// missing profile is tolerated, since the homes may still exist).
fn app_rm_profile(name: &str) -> ExitCode {
    let Some(dir) = config::profiles_dir() else {
        diag::error("sbx: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return ExitCode::FAILURE;
    };
    let path = dir.join(format!("{name}.toml"));
    match std::fs::remove_file(&path) {
        Ok(()) => {
            let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
            println!("{}", render_removed(Some("app profile"), name, &pal));
            ExitCode::SUCCESS
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            diag::error(&format!(
                "sbx: no imported profile '{name}' (a project [app.{name}] overlay lives in a \
                 project's .sbx.toml — edit it there). To also remove an app's home/tools, use \
                 `sbx app rm {name} --purge`."
            ));
            ExitCode::FAILURE
        }
        Err(e) => {
            diag::error(&format!("sbx: cannot remove {}: {e}", path.display()));
            ExitCode::FAILURE
        }
    }
}

/// `sbx app rm <name> --purge`: remove the profile **and** the app's isolated runtime state.
///
/// The runtime state is the per-app home(s): the global `<data>/apps/<name>/` and each per-project
/// `<data>/projects/<id>/apps/<name>/`. They hold the tools the app's `mise:` backends installed
/// (under the home's mise data dir), the app's config, and its login/session state — all removed
/// immediately, so "delete from mise" is satisfied here, not deferred. What this does **not** touch
/// is the shared per-project nix store: it backs every app in a project, so a purged app's
/// `nix:`/`flake:` closures are reclaimed by `sbx gc`, which the closing note points at.
///
/// A running session of the app is a hard stop — deleting its home mid-run would corrupt it — so
/// this refuses until the session is stopped (the same live guard `sbx gc` applies). Under `--purge`
/// a missing profile is tolerated (the homes may still exist), but finding *nothing at all* — no
/// profile and no home — is reported as a no-op so a typo never silently "succeeds".
///
/// When `gc` is set (the `--gc` flag), it then sweeps the **current project's** store via the same
/// path as `sbx gc --prune`, reclaiming the app's now-unreferenced closures there in one command.
/// The sweep is a distinct step with its own prerequisites (a capable host, nix); its failure is
/// reflected in the exit code but never undoes the purge that already happened.
fn app_rm_purge(name: &str, gc: bool) -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (ok, n, warn, dim, r) = (pal.ok, pal.name, pal.warn, pal.dim, pal.reset);

    let Some(layout) = store::Layout::from_env() else {
        diag::error(
            "sbx: cannot locate sbx's data directory (set $SBX_DATA_DIR, $XDG_DATA_HOME or $HOME)",
        );
        return ExitCode::FAILURE;
    };

    // Live-session guard: a session running as this app holds its home open. Refuse until it is
    // stopped, and fail closed if the registry cannot be read (a purge must not run unproven).
    match session::Registry::at(layout.data_dir()).list() {
        Ok(sessions) => {
            let pids: Vec<String> = sessions
                .iter()
                .filter(|s| s.app() == Some(name))
                .map(|s| s.pid.to_string())
                .collect();
            if !pids.is_empty() {
                diag::error(&format!(
                    "sbx: app '{name}' has a running session (pid {}); stop it first \
                     (see `sbx session ls`; then `sbx session stop {}`).",
                    pids.join(", "),
                    pids.join(" ")
                ));
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            diag::error(&format!(
                "sbx: cannot read the session registry ({e}); not purging '{name}'."
            ));
            return ExitCode::FAILURE;
        }
    }

    // 1. The profile (if any). Under --purge a missing profile is not fatal — the homes may still
    //    exist (an app whose profile was already removed, or a project/inline app that has none).
    let profile_removed = match config::profile_path(name) {
        Some(path) => match std::fs::remove_file(&path) {
            Ok(()) => {
                println!("{}", render_removed(Some("app profile"), name, &pal));
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                diag::error(&format!("sbx: cannot remove {}: {e}", path.display()));
                false
            }
        },
        None => false,
    };

    // 2. The isolated home(s): mise tools + config + login state, freed immediately.
    let report = sandbox::purge_app_homes(layout.data_dir(), name);
    for home in &report.removed {
        println!(
            "{ok}removed{r} home {n}{}{r} {dim}({}){r}",
            home.path.display(),
            sandbox::human_bytes(home.bytes)
        );
    }
    for (path, e) in &report.failed {
        diag::error(&format!(
            "{warn}sbx: could not remove {}: {e}{r}",
            path.display()
        ));
    }

    // 3. Nothing found across either source → a no-op (likely a typo); do not report success.
    if !profile_removed && report.found_nothing() {
        diag::error(&format!(
            "sbx: nothing to purge for '{name}' (no profile and no home)"
        ));
        return ExitCode::FAILURE;
    }

    // Name only what was actually removed: a purge with no profile present must not claim one.
    let removed_what = if profile_removed {
        "profile + mise tools + login state"
    } else {
        "mise tools + login state"
    };
    // A partial failure (a home that would not delete) is not a clean purge — say so, so the green
    // summary never contradicts the non-zero exit below.
    let verb = if report.failed.is_empty() {
        format!("{ok}purged{r}")
    } else {
        format!("{warn}purged with errors{r}")
    };
    println!(
        "{verb} app {n}{name}{r} — freed {n}{}{r} {dim}({removed_what}){r}",
        sandbox::human_bytes(report.freed())
    );
    // The purge itself left state behind if a home would not delete — surface it in the exit code.
    let purge_ok = report.failed.is_empty();

    // Any `nix:`/`flake:` tool closures the app built live in the shared per-project store, which
    // backs every app in a project. `--gc` sweeps the *current* project's store now; without it, the
    // reclamation is a separate manual step, and either way other projects need their own sweep.
    if gc {
        println!();
        let gc_code = sandbox::gc(true, false, false, &pal);
        println!(
            "{}",
            style::dim_prose(
                "note: `--gc` swept this project's store; run `sbx gc --prune` in the app's other \
                 projects to reclaim their copies too.",
                &pal
            )
        );
        // The purge succeeded independently of the sweep; when it did, defer to the sweep's own exit
        // code so a sweep that could not run (no capable host, nix missing) is not hidden — but never
        // undo the purge's failure signal.
        return if purge_ok { gc_code } else { ExitCode::FAILURE };
    }

    println!(
        "{}",
        style::dim_prose(
            "note: an app's nix:/flake: tool closures live in the shared per-project store; \
             run `sbx gc --prune` in a project to reclaim any no longer referenced there \
             (or re-run with --gc for the current project).",
            &pal
        )
    );
    if purge_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// `sbx app list`: what is on disk to manage, one row per app — whether it has an imported
/// **profile** (`import`/`rm` artifacts) and whether it has an **installed home** (its mise tools +
/// login state, with disk size, which `--purge` removes). The two are distinct: an app can have a
/// profile with no home yet (never launched), or a home with no profile (launched from an
/// inline/project app, or a profile since removed) — so a name may carry a profile, a home, or both.
/// The full resolved app set — inline, project, and profile apps with their gating — is
/// `sbx config show`.
fn app_list() -> ExitCode {
    use std::collections::{BTreeMap, BTreeSet};

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, dim, r) = (pal.head, pal.name, pal.dim, pal.reset);

    // Imported profiles under <config>/sbx/apps/*.toml.
    let profiles_dir = config::profiles_dir();
    let mut profiles: BTreeSet<String> = BTreeSet::new();
    if let Some(dir) = &profiles_dir {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|x| x.to_str()) == Some("toml") {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            profiles.insert(stem.to_string());
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                diag::error(&format!("sbx: cannot read {}: {e}", dir.display()));
                return ExitCode::FAILURE;
            }
        }
    }

    // Installed homes under the data dir (an app can have one with no profile).
    let installed = store::Layout::from_env()
        .map(|l| sandbox::installed_app_homes(l.data_dir()))
        .unwrap_or_default();
    let homes: BTreeMap<&str, &sandbox::InstalledApp> =
        installed.iter().map(|a| (a.name.as_str(), a)).collect();

    if profiles.is_empty() && installed.is_empty() {
        println!(
            "{dim}no imported app profiles and no installed app homes \
             (import one with: sbx app import <file>){r}"
        );
        return ExitCode::SUCCESS;
    }

    // One row per app: the union of profile names and installed-home names.
    let mut names: BTreeSet<&str> = profiles.iter().map(String::as_str).collect();
    names.extend(homes.keys().copied());

    // The disk footprint mirrors `sbx projects`: the count of apps and the total across every
    // installed home (a profile with no home contributes nothing).
    let total_bytes: u64 = installed.iter().map(|a| a.total_bytes()).sum();
    let disk = sandbox::human_bytes(total_bytes);
    match &profiles_dir {
        Some(dir) => println!(
            "{h}apps{r} {dim}({} app(s), {disk} on disk; profiles in {}){r}:",
            names.len(),
            dir.display()
        ),
        None => println!(
            "{h}apps{r} {dim}({} app(s), {disk} on disk){r}:",
            names.len()
        ),
    }

    // `NAME` and `PROFILE` are the padded columns; `HOME` is last, so it needs no trailing width.
    let name_w = names
        .iter()
        .map(|s| s.len())
        .max()
        .unwrap_or(0)
        .max("NAME".len());
    let prof_w = "PROFILE".len();
    println!(
        "  {dim}{:<name_w$}  {:<prof_w$}  HOME{r}",
        "NAME", "PROFILE"
    );

    for name in &names {
        let profile_cell = if profiles.contains(*name) {
            "yes"
        } else {
            "—"
        };
        let home_cell = match homes.get(name) {
            Some(app) => format!(
                "{} ({})",
                sandbox::human_bytes(app.total_bytes()),
                describe_home_locations(app),
            ),
            None => "—".to_string(),
        };
        let name_pad = format!("{name:<name_w$}");
        let prof_pad = format!("{profile_cell:<prof_w$}");
        println!("  {n}{name_pad}{r}  {dim}{prof_pad}  {home_cell}{r}");
    }

    println!(
        "{dim}(remove a profile: sbx app rm <name>; also remove its home + tools: \
         sbx app rm <name> --purge){r}"
    );
    ExitCode::SUCCESS
}

/// `sbx app show <name>`: the realized-on-disk detail for one app — its profile source, its
/// isolated home(s) with size (and the mise-data breakdown), and each declared package annotated
/// with whether it is **actually installed**: a `mise:` tool is read from the app home; a `deb:` /
/// `appimage:` / `flake:` build lives in the per-project store, so it is reported from the per-tree
/// pins ("pinned in N tree(s)"); a `nix:` package is built per-project (`sbx projects show` details
/// it). A package declared by an untrusted layer reads `withheld`, distinct from `not installed`, so
/// it is not mistaken for a failed provision. Read-only: no trust gate, no launch, no network.
/// `--json` emits the same model.
fn app_show(args: &[OsString]) -> ExitCode {
    let mut name: Option<&str> = None;
    let mut json = false;
    for a in args {
        match a.to_str() {
            Some("--json") => json = true,
            Some("--help") | Some("-h") => return help::show(&["app", "show"]),
            Some(flag) if flag.starts_with('-') => {
                diag::error(&format!("sbx: app show: unknown flag `{flag}`"));
                diag::hint("       run `sbx help app show` for usage.");
                return ExitCode::from(2);
            }
            Some(other) if name.is_none() => name = Some(other),
            Some(extra) => {
                diag::error(&format!(
                    "sbx: app show: unexpected extra argument `{extra}`"
                ));
                return ExitCode::from(2);
            }
            None => {
                diag::error("sbx: app show: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        diag::error(&format!(
            "sbx: app show: name an app — usage: {}",
            help::synopsis_of(&["app", "show"])
        ));
        return ExitCode::from(2);
    };
    let cwd = match config_cwd() {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error("sbx: app show: cannot locate sbx's data directory.");
        return ExitCode::FAILURE;
    };

    let resolved = config::load(&cwd);
    let app = resolved.apps.get(name);
    let homes = sandbox::inspect::app_home_dirs(layout.data_dir(), name);
    // An app that is neither declared for this directory nor has an installed home on disk does not
    // exist — surface the declared set, like `config show --app`.
    if app.is_none() && homes.is_empty() {
        diag::error(&format!("sbx: app show: no app named {name:?}"));
        let declared: Vec<String> = resolved.apps.keys().cloned().collect();
        if declared.is_empty() {
            diag::error("sbx: no apps are declared for this directory");
        } else {
            diag::error(&format!("sbx: declared apps: {}", declared.join(", ")));
        }
        return ExitCode::FAILURE;
    }

    let view = build_app_show(name, app, &resolved.network, &homes, layout.data_dir());
    if json {
        return match serde_json::to_string_pretty(&view) {
            Ok(doc) => {
                println!("{doc}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                diag::error(&format!("sbx: app show: cannot serialize: {e}"));
                ExitCode::FAILURE
            }
        };
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    print!("{}", render_app_show(&view, &pal));
    ExitCode::SUCCESS
}

/// The realized state of one declared package for `sbx app show`.
#[derive(serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum PackageInstalled {
    /// A `mise:` tool present in the app home, or a prebuilt pinned in project tree(s).
    Installed { detail: String },
    /// A trusted, launchable package with no realized state yet (offline first launch equips it).
    NotInstalled,
    /// A `nix:`/inline-flake package whose build lives in the per-project store — `sbx projects
    /// show` reports it per tree.
    PerProject,
    /// Declared by an untrusted or changed layer, so a launch would not provision it.
    Withheld,
}

/// One declared package plus where it is realized, for `sbx app show`.
#[derive(serde::Serialize)]
struct PackageShow {
    backend: &'static str,
    locator: String,
    installed: PackageInstalled,
}

/// One isolated home an app has on disk, sized with its mise-data share broken out, for `sbx app
/// show`.
#[derive(serde::Serialize)]
struct AppHomeShow {
    /// `global`, or `project <id>`.
    location: String,
    bytes: u64,
    /// Bytes under the mise data dir (the installed tools) — the rest is config/login/state.
    tools_bytes: u64,
}

/// A global app's per-project mise pool for `sbx app show`: which project, its size, and the tools
/// self-equipped there. These are the `nix:`-via-mise self-equips (and project `.mise.toml` tools)
/// kept aligned with each project's `/nix` store — distinct from the app-global home's declared
/// tools, which is why they get their own section rather than folding into the home's package view.
#[derive(serde::Serialize)]
struct AppMisePoolShow {
    /// The project tree id the pool belongs to.
    project_id: String,
    /// Total bytes of the pool dir.
    bytes: u64,
    /// The tools self-equipped into the pool, each named as a `[packages]` value would
    /// (`mise:nix:jq`) with its versions — undeclared per-project state, listed for visibility.
    tools: Vec<OrphanTool>,
}

/// A mise tool present in a home but not matched to any declared package — the literal
/// "everything actually installed" that the declared-package list does not name (a leftover from a
/// removed profile, or a tool a `mise:` backend pulled in as a dependency).
#[derive(serde::Serialize)]
struct OrphanTool {
    /// The tool as a `[packages]` value would name it: the `mise:` backend prefix plus its real
    /// token (`mise:pipx:demo-agent`), or the munged directory name when mise recorded no token.
    name: String,
    versions: Vec<String>,
}

/// The full `sbx app show` model — serialized directly for `--json`.
#[derive(serde::Serialize)]
struct AppShow {
    name: String,
    /// The imported profile path, when the app comes from one.
    profile: Option<String>,
    /// The app's home key: `global` (shared across projects) or `per-project`.
    home_scope: Option<&'static str>,
    /// The effective network posture label, when the app is declared.
    network: Option<&'static str>,
    homes: Vec<AppHomeShow>,
    /// A global app's per-project mise pools — the `nix:`-via-mise self-equips aligned with each
    /// project's `/nix` store. Empty for a per-project app (its mise data lives under its home).
    pools: Vec<AppMisePoolShow>,
    total_bytes: u64,
    packages: Vec<PackageShow>,
    /// Installed mise tools that no declared package accounts for.
    orphans: Vec<OrphanTool>,
}

/// Assemble the [`AppShow`] model from the resolved app (its declared packages/posture) and the
/// on-disk homes. `app` is `None` for a home-only app (installed, no current declaration) — then
/// only the realized state is shown. Pure over its inputs; the disk reads happen in
/// [`sandbox::inspect`].
fn build_app_show(
    name: &str,
    app: Option<&config::ResolvedApp>,
    baseline_network: &config::NetworkPolicy,
    homes: &[sandbox::inspect::AppHome],
    data_dir: &Path,
) -> AppShow {
    use crate::config::Backend;

    // The mise tools realized across every home of this app — the authoritative installed set for
    // `mise:` packages (which are app-home-scoped, unlike the per-project prebuilt backends).
    let installed_tools: Vec<sandbox::inspect::InstalledTool> = homes
        .iter()
        .flat_map(|h| sandbox::inspect::mise_installed(&h.dir))
        .collect();

    let home_views: Vec<AppHomeShow> = homes
        .iter()
        .map(|h| {
            // Size the app's own directory (the parent of `home`), matching `sbx app list`; the mise
            // data dir is broken out so the tools' share of the home is visible.
            let app_dir = h.dir.parent().unwrap_or(&h.dir);
            let bytes = sandbox::tree_size(app_dir);
            let tools_bytes = sandbox::tree_size(&h.dir.join(".local/share/mise"));
            AppHomeShow {
                location: if h.global {
                    "global".to_string()
                } else {
                    format!("project {}", h.project_id.as_deref().unwrap_or("?"))
                },
                bytes,
                tools_bytes,
            }
        })
        .collect();
    // A global app's per-project mise pools — its `nix:`-via-mise self-equips, which the split routes
    // per project (aligned with each project's `/nix` store) rather than into the app-global home. A
    // per-project app has none (its mise data lives under its per-project home). Kept distinct from the
    // home's declared tools, and their bytes counted in the disk total.
    let pools: Vec<AppMisePoolShow> = sandbox::inspect::app_per_project_mise_pools(data_dir, name)
        .into_iter()
        .map(|pool| {
            let bytes = sandbox::tree_size(&pool.dir);
            let tools = sandbox::inspect::mise_installed_in(&pool.dir.join("installs"))
                .iter()
                .map(|t| OrphanTool {
                    name: format!("mise:{}", t.label()),
                    versions: sandbox::inspect::concrete_versions(t),
                })
                .collect();
            AppMisePoolShow {
                project_id: pool.project_id,
                bytes,
                tools,
            }
        })
        .collect();

    let total_bytes = home_views.iter().map(|h| h.bytes).sum::<u64>()
        + pools.iter().map(|p| p.bytes).sum::<u64>();

    let packages = app
        .map(|a| {
            a.packages
                .iter()
                .map(|pkg| {
                    let backend = pkg.backend.label();
                    let locator = pkg.backend.locator().to_string();
                    let installed = if pkg.state != trust::TrustState::Trusted {
                        PackageInstalled::Withheld
                    } else if let Backend::Mise(token) = &pkg.backend {
                        match installed_tools.iter().find(|t| t.is(token)) {
                            Some(t) => {
                                let versions = sandbox::inspect::concrete_versions(t).join(", ");
                                PackageInstalled::Installed {
                                    detail: if versions.is_empty() {
                                        "installed".to_string()
                                    } else {
                                        format!("installed {versions}")
                                    },
                                }
                            }
                            None => PackageInstalled::NotInstalled,
                        }
                    } else if matches!(pkg.backend, Backend::FlakeInline { .. }) {
                        // An inline `[flakes.<name>]` is built in-cage and lands a warm out-link in the
                        // cage home (keyed `<name>-<hash>`, matched by the same name), whose target
                        // store path is in the per-project store. A remote `flake:` is built host-side
                        // instead — handled with `nix:` below.
                        match homes
                            .iter()
                            .find_map(|h| sandbox::inspect::flake_built(&h.dir, &pkg.name))
                        {
                            Some(detail) => PackageInstalled::Installed {
                                detail: format!("built {detail}"),
                            },
                            None => PackageInstalled::NotInstalled,
                        }
                    } else if let Some(lockfile) = sandbox::inspect::prebuilt_lockfile(&pkg.backend)
                    {
                        // A `*:resolve` package's pin is keyed `resolve:<name>`, not by the `resolve`
                        // sentinel `locator` carries — look it up by that key so a built one is found.
                        let key = sandbox::inspect::prebuilt_pin_key(&pkg.backend, &pkg.name);
                        let hits = sandbox::inspect::prebuilt_pin_trees(data_dir, lockfile, &key);
                        match hits.first() {
                            Some((_, short)) => PackageInstalled::Installed {
                                detail: format!("pinned in {} ({short})", plural_trees(hits.len())),
                            },
                            None => PackageInstalled::NotInstalled,
                        }
                    } else if matches!(pkg.backend, Backend::Nix(_) | Backend::Flake(_)) {
                        // A `nix:` package — and now a remote `flake:` package — builds host-side into
                        // the shared store and is seeded into each project's per-project store, gcrooted
                        // per tree (bare `<name>`), so its realized signal is which trees built it,
                        // mirroring the deb:/appimage: per-tree report above.
                        let trees = sandbox::inspect::nix_built_trees(data_dir, &pkg.name);
                        match trees.len() {
                            0 => PackageInstalled::NotInstalled,
                            n => PackageInstalled::Installed {
                                detail: format!("built in {}", plural_trees(n)),
                            },
                        }
                    } else {
                        // A backend with no specific realized-signal reader falls back here; its build
                        // is in the per-project store, which `sbx projects show` details per tree.
                        PackageInstalled::PerProject
                    };
                    PackageShow {
                        backend,
                        locator,
                        installed,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // Orphans: installed mise tools no declared `mise:` package accounts for. A home-only app
    // (nothing declared) surfaces its whole installed set here — the literal "everything actually
    // installed". Named by their real backend token (recovered from mise's metadata), deduped
    // across homes, versions unioned.
    let declared_mise: Vec<&str> = app
        .map(|a| {
            a.packages
                .iter()
                .filter_map(|p| match &p.backend {
                    Backend::Mise(token) => Some(token.as_str()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let mut orphan_versions: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    for tool in &installed_tools {
        if declared_mise.iter().any(|d| tool.is(d)) {
            continue;
        }
        // Prefix the mise backend so the name reads like the `packages:` section and is the exact
        // `[packages]` value that would adopt it (`mise:pipx:demo-agent`, not a bare `pipx:…`).
        orphan_versions
            .entry(format!("mise:{}", tool.label()))
            .or_default()
            .extend(sandbox::inspect::concrete_versions(tool));
    }
    let orphans: Vec<OrphanTool> = orphan_versions
        .into_iter()
        .map(|(name, versions)| OrphanTool {
            name,
            versions: versions.into_iter().collect(),
        })
        .collect();

    let profile = config::profiles_dir()
        .map(|d| d.join(format!("{name}.toml")))
        .filter(|p| p.is_file())
        .map(|p| p.display().to_string());

    AppShow {
        name: name.to_string(),
        profile,
        home_scope: app.map(|a| match a.home_scope {
            config::AppHomeScope::Global => "global",
            config::AppHomeScope::Project => "per-project",
        }),
        // The effective posture: the app's own when it set one, else the baseline it inherits. The
        // label matches `config show` exactly (a filtering posture is its mode word `deny`/`allow`/
        // `ask` — deny = allowlist, allow = denylist — not a single "allowlist"), so the two views
        // never disagree.
        network: app.map(|a| match a.network.as_ref().unwrap_or(baseline_network) {
            config::NetworkPolicy::Shared => "shared",
            config::NetworkPolicy::Isolated => "none",
            config::NetworkPolicy::Allowlist(pol) => net_mode_word(pol.default_action().into()),
        }),
        homes: home_views,
        pools,
        total_bytes,
        packages,
        orphans,
    }
}

/// `1 tree` / `N trees` for the pinned-in count.
fn plural_trees(n: usize) -> String {
    if n == 1 {
        "1 tree".to_string()
    } else {
        format!("{n} trees")
    }
}

/// Render the `sbx app show` model — a pure presenter (every color span is empty under a
/// non-terminal, so captured output is the plain text the tests pin).
fn render_app_show(v: &AppShow, pal: &style::Palette) -> String {
    use std::fmt::Write;
    let (h, n, ok, warn, dim, r) = (pal.head, pal.name, pal.ok, pal.warn, pal.dim, pal.reset);
    let mut s = String::new();
    let _ = writeln!(s, "{h}app{r} {n}{}{r}", v.name);
    match &v.profile {
        Some(p) => {
            let _ = writeln!(s, "  profile:  {p}");
        }
        None if v.home_scope.is_some() => {
            let _ = writeln!(s, "  profile:  {dim}inline (no imported profile){r}");
        }
        None => {
            let _ = writeln!(
                s,
                "  profile:  {dim}— (installed home only, no declaration){r}"
            );
        }
    }
    if let Some(scope) = v.home_scope {
        let phrase = match scope {
            "global" => "global (shared across projects)",
            _ => "per-project",
        };
        let _ = writeln!(s, "  home:     {phrase}");
    }
    if let Some(net) = v.network {
        let _ = writeln!(s, "  network:  {net}");
    }
    // On-disk usage: the total, then one breakdown line per home (its mise-tools share vs the rest),
    // then one per per-project mise pool (all mise data — its self-equips aligned with the project store).
    if v.homes.is_empty() && v.pools.is_empty() {
        let _ = writeln!(s, "  disk:     {dim}— (not launched yet){r}");
    } else {
        let _ = writeln!(s, "  disk:     {}", sandbox::human_bytes(v.total_bytes));
        for home in &v.homes {
            let state = home.bytes.saturating_sub(home.tools_bytes);
            let _ = writeln!(
                s,
                "    {} · {}  {dim}(tools {} · state {}){r}",
                home.location,
                sandbox::human_bytes(home.bytes),
                sandbox::human_bytes(home.tools_bytes),
                sandbox::human_bytes(state),
            );
        }
        for pool in &v.pools {
            let _ = writeln!(
                s,
                "    project {} {dim}(mise pool){r} · {}",
                pool.project_id,
                sandbox::human_bytes(pool.bytes),
            );
        }
    }
    // Packages, each `backend:locator` (the declaration syntax) with its realized state.
    if v.packages.is_empty() {
        let _ = writeln!(s, "  packages: {dim}none declared{r}");
    } else {
        let _ = writeln!(s, "  packages:");
        for p in &v.packages {
            let (tag, hue) = match &p.installed {
                PackageInstalled::Installed { detail } => (detail.clone(), ok),
                PackageInstalled::NotInstalled => ("not installed".to_string(), warn),
                PackageInstalled::PerProject => {
                    ("built per-project (sbx projects show)".to_string(), dim)
                }
                PackageInstalled::Withheld => {
                    ("withheld (untrusted — run `sbx trust`)".to_string(), warn)
                }
            };
            let _ = writeln!(s, "    {n}{}:{}{r}  {hue}{tag}{r}", p.backend, p.locator);
        }
    }
    // Installed mise tools no declared package accounts for — a leftover profile or a mise-pulled
    // dependency. Each `name` already carries the `mise:` backend prefix (see `build_app_show`), so
    // the provider reads like the `packages:` section above (`mise:pipx:demo-agent`).
    if !v.orphans.is_empty() {
        let _ = writeln!(s, "  installed (undeclared):");
        for t in &v.orphans {
            let versions = t.versions.join(", ");
            let suffix = if versions.is_empty() {
                String::new()
            } else {
                format!("  {dim}{versions}{r}")
            };
            let _ = writeln!(s, "    {n}{}{r}{suffix}", t.name);
        }
    }
    // A global app's per-project self-equips: the `nix:`-via-mise tools each project resolved into its
    // own `/nix`-aligned pool, listed per project. Distinct from the app-global declared tools above —
    // these are transient per-project state, re-resolved when the project's store lacks them.
    let pools_with_tools: Vec<&AppMisePoolShow> =
        v.pools.iter().filter(|p| !p.tools.is_empty()).collect();
    if !pools_with_tools.is_empty() {
        let _ = writeln!(s, "  per-project self-equips:");
        for pool in pools_with_tools {
            for t in &pool.tools {
                let versions = t.versions.join(", ");
                let suffix = if versions.is_empty() {
                    String::new()
                } else {
                    format!("  {dim}{versions}{r}")
                };
                let _ = writeln!(
                    s,
                    "    {dim}project {}{r}  {n}{}{r}{suffix}",
                    pool.project_id, t.name
                );
            }
        }
    }
    s
}

/// `sbx app prune <name> [--yes]`: remove the mise tools an app's home(s) carry that the app's
/// config does **not** declare — the `installed (undeclared)` leftovers `sbx app show` surfaces (a
/// former profile's tool, or one added by hand). Each is deleted from the home's mise `installs/`
/// and dropped from its `config.toml` `[tools]` so it does not re-equip. Previews by default; `--yes`
/// applies. Declared tools, login/session state, and any `nix:`/`deb:`/`flake:` build are untouched.
fn app_prune(args: &[OsString]) -> ExitCode {
    let mut name: Option<&str> = None;
    let mut apply = false;
    for a in args {
        match a.to_str() {
            Some("-y") | Some("--yes") => apply = true,
            Some("--help") | Some("-h") => return help::show(&["app", "prune"]),
            Some(flag) if flag.starts_with('-') => {
                diag::error(&format!("sbx: app prune: unknown flag `{flag}`"));
                diag::hint("       run `sbx help app prune` for usage.");
                return ExitCode::from(2);
            }
            Some(other) if name.is_none() => name = Some(other),
            Some(extra) => {
                diag::error(&format!(
                    "sbx: app prune: unexpected extra argument `{extra}`"
                ));
                return ExitCode::from(2);
            }
            None => {
                diag::error("sbx: app prune: argument is not valid UTF-8");
                return ExitCode::from(2);
            }
        }
    }
    let Some(name) = name else {
        diag::error(&format!(
            "sbx: app prune: name an app — usage: {}",
            help::synopsis_of(&["app", "prune"])
        ));
        return ExitCode::from(2);
    };
    let cwd = match config_cwd() {
        Ok(c) => c,
        Err(code) => return code,
    };
    let Some(layout) = store::Layout::from_env() else {
        diag::error("sbx: app prune: cannot locate sbx's data directory.");
        return ExitCode::FAILURE;
    };

    let resolved = config::load(&cwd);
    let app = resolved.apps.get(name);
    let homes = sandbox::inspect::app_home_dirs(layout.data_dir(), name);
    if app.is_none() && homes.is_empty() {
        diag::error(&format!("sbx: app prune: no app named {name:?}"));
        let declared: Vec<String> = resolved.apps.keys().cloned().collect();
        if !declared.is_empty() {
            diag::error(&format!("sbx: declared apps: {}", declared.join(", ")));
        }
        return ExitCode::FAILURE;
    }
    // The app's declared `mise:` tokens; a tool matching none of them is undeclared. A home-only app
    // (no config) declares nothing, so every mise tool in its home is prunable.
    let declared: Vec<&str> = app
        .map(|a| {
            a.packages
                .iter()
                .filter_map(|p| match &p.backend {
                    config::Backend::Mise(token) => Some(token.as_str()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut total_bytes = 0u64;
    let mut count = 0usize;
    for home in &homes {
        let pruned = sandbox::prune_app_tools(&home.dir, &declared, apply);
        if pruned.is_empty() {
            continue;
        }
        let location = if home.global {
            "global home".to_string()
        } else {
            format!("project {} home", home.project_id.as_deref().unwrap_or("?"))
        };
        println!("{dim}{location}:{r}");
        for p in &pruned {
            count += 1;
            total_bytes += p.bytes;
            println!(
                "  {n}{}{r}  {dim}{}{r}",
                p.token,
                sandbox::human_bytes(p.bytes)
            );
        }
    }
    if count == 0 {
        println!("{h}sbx app prune{r} {dim}— {name}: no undeclared mise tools to prune.{r}");
        return ExitCode::SUCCESS;
    }
    let size = sandbox::human_bytes(total_bytes);
    if apply {
        println!("{ok}pruned {count} undeclared tool(s), freeing {size}.{r}");
    } else {
        println!(
            "{}",
            style::dim_prose(
                &format!("would prune {count} undeclared tool(s) ({size}) — re-run with `--yes` to apply."),
                &pal
            )
        );
    }
    ExitCode::SUCCESS
}

/// A compact description of where an app's isolated state lives — `global`, `N project home(s)`, and
/// `N project mise pool(s)`, joined with ` + ` — for the `sbx app list` installed-homes line. A
/// per-project *home* belongs to a `home_scope = "project"` app; a global app instead gets a
/// per-project mise pool holding what the agent self-equipped there, which is state on disk (and
/// purged with the app) but not a second home, so the two are named apart rather than counted
/// together. An app whose only per-project state is the empty pool a launch creates counts neither,
/// and reads as its global home alone.
fn describe_home_locations(app: &sandbox::InstalledApp) -> String {
    let mut parts = Vec::new();
    if app.global_bytes.is_some() {
        parts.push("global".to_string());
    }
    match app.project_homes {
        0 => {}
        1 => parts.push("1 project home".to_string()),
        n => parts.push(format!("{n} project homes")),
    }
    match app.project_pools {
        0 => {}
        1 => parts.push("1 project mise pool".to_string()),
        n => parts.push(format!("{n} project mise pools")),
    }
    if parts.is_empty() {
        // The app is listed, so it has *some* state, yet nothing countable: only empty pools —
        // reachable when its global home was removed by hand after a launch. Name that rather than
        // render an empty cell.
        return "empty mise pool".to_string();
    }
    parts.join(" + ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_app_rm_handles_flag_and_name_in_either_order() {
        let os = |s: &str| OsString::from(s);
        // name only
        assert!(matches!(
            parse_app_rm(&[os("demo-app")]),
            AppRmArgs::Ok {
                purge: false,
                gc: false,
                name: "demo-app"
            }
        ));
        // --purge before the name
        assert!(matches!(
            parse_app_rm(&[os("--purge"), os("demo-app")]),
            AppRmArgs::Ok {
                purge: true,
                gc: false,
                name: "demo-app"
            }
        ));
        // --purge after the name (either order)
        assert!(matches!(
            parse_app_rm(&[os("demo-app"), os("--purge")]),
            AppRmArgs::Ok {
                purge: true,
                gc: false,
                name: "demo-app"
            }
        ));
        // --purge and --gc together, name interleaved between the flags
        assert!(matches!(
            parse_app_rm(&[os("--gc"), os("demo-app"), os("--purge")]),
            AppRmArgs::Ok {
                purge: true,
                gc: true,
                name: "demo-app"
            }
        ));
        // --gc alone parses; the --gc-requires---purge rule is the caller's, not the parser's
        assert!(matches!(
            parse_app_rm(&[os("--gc"), os("demo-app")]),
            AppRmArgs::Ok {
                purge: false,
                gc: true,
                name: "demo-app"
            }
        ));
        // no name — even with the flag, --purge alone must never mean "purge everything"
        assert!(matches!(parse_app_rm(&[]), AppRmArgs::MissingName));
        assert!(matches!(
            parse_app_rm(&[os("--purge")]),
            AppRmArgs::MissingName
        ));
        // unknown option and a second positional are distinct errors
        assert!(matches!(
            parse_app_rm(&[os("--nope"), os("demo-app")]),
            AppRmArgs::UnknownOption("--nope")
        ));
        assert!(matches!(
            parse_app_rm(&[os("demo-app"), os("demo-tool")]),
            AppRmArgs::Extra("demo-tool")
        ));
    }

    #[test]
    fn describe_home_locations_names_each_scope() {
        let app = |global: Option<u64>, homes: usize, pools: usize| sandbox::InstalledApp {
            name: "x".to_string(),
            global_bytes: global,
            project_homes: homes,
            project_pools: pools,
            project_bytes: 0,
        };
        assert_eq!(describe_home_locations(&app(Some(1), 0, 0)), "global");
        assert_eq!(describe_home_locations(&app(None, 1, 0)), "1 project home");
        assert_eq!(describe_home_locations(&app(None, 3, 0)), "3 project homes");
        assert_eq!(
            describe_home_locations(&app(Some(1), 2, 0)),
            "global + 2 project homes"
        );
        // A global app's per-project mise pool is state on disk but not a second home: it is named
        // as a pool, never folded into the home count.
        assert_eq!(
            describe_home_locations(&app(Some(1), 0, 1)),
            "global + 1 project mise pool"
        );
        assert_eq!(
            describe_home_locations(&app(Some(1), 0, 4)),
            "global + 4 project mise pools"
        );
        // Nothing countable (only empty pools, the global home removed by hand): named, not blank.
        assert_eq!(describe_home_locations(&app(None, 0, 0)), "empty mise pool");
    }

    #[test]
    fn parse_app_launch_splits_the_name_flags_and_passthrough_args() {
        use std::ffi::OsString;
        let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };

        // A bare name: no detach, no passthrough, no override, no net-learn.
        let a = parse_app_launch(&v(&["demo-app"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("demo-app", false));
        assert!(a.tail.is_empty() && a.cli.config.is_empty() && a.cli.env.is_empty());
        assert!(a.net_learn.is_none());

        // `--detach` before the (absent) `--` sets the flag.
        let a = parse_app_launch(&v(&["demo-app", "--detach"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("demo-app", true));
        assert!(a.tail.is_empty());
        assert!(!a.observe, "no --observe by default");

        // `--observe` sets the feed flag and leaves the name intact.
        let a = parse_app_launch(&v(&["demo-app", "--observe"])).unwrap();
        assert_eq!((a.name.as_str(), a.observe), ("demo-app", true));
        assert!(!a.detach);

        // `--` separates sbx's args from the passthrough tail, appended verbatim.
        let a = parse_app_launch(&v(&["demo-app", "--", "-c"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("demo-app", false));
        assert_eq!(a.tail, v(&["-c"]));

        // A flag before `--` is sbx's; the same token after `--` is the program's (passthrough).
        let a = parse_app_launch(&v(&["demo-app", "--detach", "--", "-c", "--foo"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("demo-app", true));
        assert_eq!(a.tail, v(&["-c", "--foo"]));
        let a = parse_app_launch(&v(&["demo-app", "--", "--detach"])).unwrap();
        assert!(
            !a.detach,
            "`--detach` after `--` is the program's, not sbx's"
        );
        assert_eq!(a.tail, v(&["--detach"]));

        // A trailing `--` with nothing after it is an empty tail, not an error.
        let a = parse_app_launch(&v(&["demo-app", "--"])).unwrap();
        assert_eq!(a.name, "demo-app");
        assert!(a.tail.is_empty());

        // A one-shot override is collected from the head, in any order with the name/`--detach`, and
        // stops at `--` (a later `--config` after `--` is the program's argument, not sbx's).
        let a = parse_app_launch(&v(&[
            "--env",
            "FOO=bar",
            "demo-app",
            "--config",
            "network=\"none\"",
            "--",
            "--config",
            "x",
        ]))
        .unwrap();
        assert_eq!(a.name, "demo-app");
        assert_eq!(a.cli.config, vec!["network=\"none\"".to_string()]);
        assert_eq!(a.cli.env, vec!["FOO=bar".to_string()]);
        assert_eq!(a.tail, v(&["--config", "x"]));
        // The `--flag=value` inline form is accepted too.
        let a =
            parse_app_launch(&v(&["demo-app", "--config=gui=\"wayland\"", "--env=A=1"])).unwrap();
        assert_eq!(a.cli.config, vec!["gui=\"wayland\"".to_string()]);
        assert_eq!(a.cli.env, vec!["A=1".to_string()]);

        // `--net-learn`: bare is `domain` (the default), the local scope, no dry-run.
        let a = parse_app_launch(&v(&["demo-app", "--net-learn"])).unwrap();
        let nl = a.net_learn.expect("net-learn set");
        assert_eq!(nl.gran, sandbox::Granularity::Domain);
        assert!(matches!(nl.scope, config::manage::Scope::Local) && !nl.dry_run);
        // `=level`, `--dry-run`, and `-g` compose, in any order with the name.
        let a = parse_app_launch(&v(&["--net-learn=path", "demo-app", "--dry-run", "-g"])).unwrap();
        let nl = a.net_learn.expect("net-learn set");
        assert_eq!(nl.gran, sandbox::Granularity::Path);
        assert!(matches!(nl.scope, config::manage::Scope::Global) && nl.dry_run);
        // A bad granularity, `--net-learn` with `--detach`, and a scope/`--dry-run` without
        // `--net-learn` are each usage errors (never a silently-ignored flag).
        assert!(parse_app_launch(&v(&["demo-app", "--net-learn=subtree"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--net-learn", "--detach"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--dry-run"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "-g"])).is_err());

        // The typed security flags are collected into their own fields, in any order with the name.
        let a = parse_app_launch(&v(&[
            "--net",
            "none",
            "demo-app",
            "--bind",
            "/data:rw",
            "--forward",
            "1455",
            "--limit",
            "tasks_max=4096",
            "--gui",
            "wayland",
            "--nixpkgs",
            "nixos-23.11",
            "--package",
            "hello=nix:hello",
        ]))
        .unwrap();
        assert_eq!(a.name, "demo-app");
        assert_eq!(a.cli.net, vec!["none".to_string()]);
        assert_eq!(a.cli.gui, vec!["wayland".to_string()]);
        assert_eq!(a.cli.nixpkgs, vec!["nixos-23.11".to_string()]);
        assert_eq!(a.cli.binds, vec!["/data:rw".to_string()]);
        assert_eq!(a.cli.forward, vec!["1455".to_string()]);
        assert_eq!(a.cli.limits, vec!["tasks_max=4096".to_string()]);
        assert_eq!(a.cli.packages, vec!["hello=nix:hello".to_string()]);

        // The boolean flags are optional-value and must never consume the following token: a bare
        // `--gpu` placed right before the name still leaves `demo-app` as the name (not swallowed as a
        // value), normalizing to `"true"`; the inline `--dbus=false` form carries its value.
        let a = parse_app_launch(&v(&["--gpu", "demo-app", "--dbus=false"])).unwrap();
        assert_eq!(a.name, "demo-app");
        assert_eq!(a.cli.gpu, vec!["true".to_string()]);
        assert_eq!(a.cli.dbus, vec!["false".to_string()]);

        // Errors: a second name, an unknown flag, no name at all, `--` with no name before it, and a
        // value-taking flag with no value.
        assert!(parse_app_launch(&v(&["demo-app", "extra"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--unknown"])).is_err());
        assert!(parse_app_launch(&v(&[])).is_err());
        assert!(parse_app_launch(&v(&["--", "-c"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--config"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--net"])).is_err());
    }

    #[test]
    fn app_show_surfaces_a_global_apps_per_project_mise_pools() {
        use crate::testutil::TmpDir;
        // A global app self-equipped `nix:jq` into two projects' per-project pools. `app show` must
        // surface both — the correctness the pool split otherwise loses, since the pools are
        // `.../mise` (mise's own data dir), not `.../home`, so `app_home_dirs` alone misses them.
        let data = TmpDir::new();
        let d = data.path();
        // the app-global home holds the declared agent tool (rg), which `app_home_dirs` does read
        std::fs::create_dir_all(
            d.join("apps/ag/home/.local/share/mise/installs/aqua-burnt-sushi-ripgrep/14.1.1"),
        )
        .unwrap();
        // two per-project pools, each with the `nix:` self-equip (installs directly under the pool)
        for id in ["p1", "p2"] {
            let inst = d.join(format!("projects/{id}/apps/ag/mise/installs/nix-jq"));
            std::fs::create_dir_all(inst.join("1.8.1")).unwrap();
            std::fs::write(inst.join(".mise.backend.toml"), "short = \"nix:jq\"\n").unwrap();
        }

        let homes = sandbox::inspect::app_home_dirs(d, "ag");
        let view = build_app_show("ag", None, &config::NetworkPolicy::Shared, &homes, d);

        // both pools captured, each holding exactly the self-equip; the pool tools are kept separate
        // from the app-global home's tools (the declared-package matching stays home-only).
        assert_eq!(
            view.pools
                .iter()
                .map(|p| p.project_id.as_str())
                .collect::<Vec<_>>(),
            ["p1", "p2"]
        );
        assert!(
            view.pools
                .iter()
                .all(|p| p.tools.len() == 1 && p.tools[0].name == "mise:nix:jq"),
            "each pool lists exactly its nix: self-equip: {:?}",
            view.pools
                .iter()
                .map(|p| p.tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        );

        // the rendered output surfaces the pools: a disk line per pool + the self-equips section
        let out = render_app_show(&view, &style::Palette::plain());
        assert!(out.contains("(mise pool)"), "disk names the pools:\n{out}");
        assert!(
            out.contains("per-project self-equips"),
            "the self-equips section is shown:\n{out}"
        );
        assert!(
            out.contains("mise:nix:jq"),
            "the self-equipped tool is named:\n{out}"
        );
    }
}
