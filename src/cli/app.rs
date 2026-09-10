//! `sbx app <subcommand>`: launch and manage named application profiles — `run <name>` (launch an
//! app inside the project sandbox), `upgrade <name>` (advance it, dispatching on what it declares)
//! and `import`/`export`/`rm`/`list`/`show`/`prune` (manage the profiles and their per-app isolated
//! homes). The launch verb is mandatory, so the first token is always a subcommand and an app name
//! can never collide with one. The shared confirmation renderers
//! (`render_app_imported`/`render_app_exported`/`render_removed`) stay at the crate root.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::confirm::{render_app_exported, render_app_imported, render_removed};
use crate::cli::{import_remedy, refuse_flag_value};
use crate::{
    build_override, config_cwd, egress_write_target, flag_name, net_mode_word, persist_egress_rule,
    print_json, take_override_flag,
};
use crate::{config, diag, help, layout_or_fail, sandbox, session, store, style, trust};

/// `sbx app <subcommand>`: launch or manage named application profiles. `run <name>` launches an
/// app (an `[app.<name>]` table from the global or project config, or an imported `<name>.toml`
/// profile) inside the project sandbox; `upgrade <name>` advances it;
/// `import`/`export`/`rm`/`list`/`show`/`prune` manage them. Launching goes through the explicit
/// `run` verb, so the first token is always a subcommand and an app name can never collide with one
/// — an app may be named `run`, `upgrade`, `show`, etc., and is reached as `sbx app run <name>`.
/// That invariant is what makes adding a subcommand here safe: it can never shadow an app.
pub(crate) fn app_cmd(args: &[OsString]) -> ExitCode {
    match args.first().and_then(|a| a.to_str()) {
        Some("run") => app_run(&args[1..]),
        Some("upgrade") => crate::cli::upgrade::app_upgrade_cmd(&args[1..]),
        Some("import") => app_import(&args[1..]),
        Some("export") => app_export(&args[1..]),
        Some("rm") => app_rm(&args[1..]),
        Some("list" | "ls") => {
            let (json, rest) = crate::split_json_flag(&args[1..]);
            match crate::cli::reject_extra(&["app", "list"], &rest) {
                Err(code) => code,
                Ok(()) => app_list(json),
            }
        }
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
            let ov = match build_override(&launch.cli) {
                Ok(ov) => ov,
                Err(code) => return code,
            };
            let outcome = sandbox::app(
                &launch.name,
                launch.detach,
                launch.observe,
                launch.tail,
                ov,
                launch.learn.as_ref().and_then(|l| l.net),
                launch.learn.as_ref().and_then(|l| l.proc),
            );
            match &launch.learn {
                Some(learn) => finish_learning(&launch.name, &outcome, learn),
                None => outcome.code,
            }
        }
        Err(code) => code,
    }
}

/// Apply what a learning run synthesized: the egress rules, the exec rules, or both, each through
/// the same review-then-write path. The exit code reflects the *learning* outcome, not the agent's —
/// a learning run is expected to hit things it has no rule for, so its non-zero exit is not this
/// command's failure; only a write error is.
fn finish_learning(name: &str, outcome: &sandbox::AppOutcome, learn: &Learning) -> ExitCode {
    use config::manage::EgressList;
    let cwd = match config_cwd() {
        Ok(c) => c,
        Err(code) => return code,
    };
    let mut code = ExitCode::SUCCESS;
    if let Some((synth, gran)) = outcome.learned.as_ref().zip(learn.net) {
        // Written one rule at a time: each re-trusts a gated project write, and the messages are
        // joined so the whole list is reported in one place.
        let persist = |rules: &[String]| {
            let mut lines: Vec<String> = Vec::new();
            let mut errs: Vec<String> = Vec::new();
            for rule in rules {
                match persist_egress_rule(EgressList::Allow, rule, &learn.scope, Some(name), &cwd) {
                    Ok(msg) => lines.push(msg),
                    Err((_, msg)) => errs.push(msg),
                }
            }
            Written {
                lines,
                failure: (!errs.is_empty()).then(|| errs.join("\n")),
            }
        };
        let target = match egress_write_target(&learn.scope, Some(name), &cwd) {
            Ok((_, _, target)) => target,
            Err((c, msg)) => {
                diag::error(&format!("sbx net-learn: {msg}"));
                return ExitCode::from(c);
            }
        };
        code = finish_learn(
            name,
            synth,
            &LearnWrite {
                label: "net-learn",
                refused: "was refused nothing it lacked a rule for",
                noun: "egress",
                gran: gran.as_str(),
                dry_run: learn.dry_run,
                target,
                also: None,
                persist: &persist,
            },
        );
    }
    if let Some((synth, gran)) = outcome.proc_learned.as_ref().zip(learn.proc) {
        // One call for the whole list, so a gated project config is re-trusted once: either every
        // rule landed or none did, and there is no half-written list to name.
        let persist = |rules: &[String]| match crate::persist_learned_proc_rules(
            rules,
            &learn.scope,
            Some(name),
            &cwd,
        ) {
            Ok(msg) => Written {
                lines: vec![msg],
                failure: None,
            },
            Err((_, msg)) => Written {
                lines: Vec::new(),
                failure: Some(msg),
            },
        };
        let target = match egress_write_target(&learn.scope, Some(name), &cwd) {
            Ok((_, _, target)) => target,
            Err((c, msg)) => {
                diag::error(&format!("sbx proc-learn: {msg}"));
                return ExitCode::from(c);
            }
        };
        let proc_code = finish_learn(
            name,
            synth,
            &LearnWrite {
                label: "proc-learn",
                refused: "ran nothing its `[proc]` rules did not already name",
                noun: "exec",
                gran: gran.as_str(),
                dry_run: learn.dry_run,
                target,
                also: Some(
                    "the write also sets `[proc] mode = \"ask\"`, the posture an allow list is live \
                     under",
                ),
                persist: &persist,
            },
        );
        if proc_code != ExitCode::SUCCESS {
            code = proc_code;
        }
    }
    code
}

/// How one lens's learned rules are reviewed and written. The parts the two lenses genuinely differ
/// in — what they are called, what they write, and where — and nothing else: the order (notes, then
/// the empty case, then preview or write) is the same for both, so it is written once.
struct LearnWrite<'a> {
    /// The flag's own name, which prefixes every line this prints.
    label: &'a str,
    /// How a run that learned nothing is described, after "app `x` ".
    refused: &'a str,
    /// What the rules are about, for the count line.
    noun: &'a str,
    gran: &'a str,
    dry_run: bool,
    /// The file the rules land in, resolved once so the preview and the write cannot disagree.
    target: String,
    /// A second thing this write does, said in the preview as well as before it happens.
    also: Option<&'a str>,
    persist: &'a Persist<'a>,
}

/// How a lens writes the whole list it learned, returning the line to print or the refusal to
/// report. Taking the list rather than one rule lets a lens that can write in one act do so, and one
/// that cannot loop inside its own closure.
type Persist<'a> = dyn Fn(&[String]) -> Written + 'a;

/// What a write reports: the lines naming what landed, and the refusal when part of it did not.
///
/// Not a `Result`, because a list write is not all-or-nothing: the egress path persists one rule per
/// call, so a failure on the third leaves the first two written — and a caller that printed only the
/// error would leave the operator believing nothing was.
struct Written {
    lines: Vec<String>,
    failure: Option<String>,
}

/// Surface the notes (nothing is dropped silently), then either preview the diff (`--dry-run`) or
/// write the rules.
fn finish_learn(name: &str, synth: &sandbox::Synthesis, w: &LearnWrite) -> ExitCode {
    for note in &synth.notes {
        diag::warn(note);
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    if synth.rules.is_empty() {
        println!(
            "{}",
            style::prose(
                &format!(
                    "sbx {}: no new {} rules — app `{name}` {}.",
                    w.label, w.noun, w.refused
                ),
                &pal
            )
        );
        return ExitCode::SUCCESS;
    }
    if w.dry_run {
        println!(
            "sbx {} ({}): {} {} rule(s) would be added to {} (dry run — nothing written):",
            w.label,
            w.gran,
            synth.rules.len(),
            w.noun,
            w.target
        );
        for rule in &synth.rules {
            // The preview is the only per-rule review a learning run offers, and a learned rule is
            // built from something the cage chose. The synthesizers already refuse a rule their own
            // gate rejects, so nothing reaches here carrying a control byte; sanitising anyway is
            // what keeps that true of this line rather than of the gate behind it.
            println!("  allow {}", crate::sandbox::sanitize(rule));
        }
        if let Some(also) = w.also {
            println!("{}", style::prose(&format!("  ({also})"), &pal));
        }
        return ExitCode::SUCCESS;
    }
    let written = (w.persist)(&synth.rules);
    // What landed is named first, and named even when part of the list did not: a write that failed
    // on its third rule still wrote the first two, and reporting only the error would leave the
    // operator believing their config was untouched.
    for line in &written.lines {
        println!("{}", style::prose(line, &pal));
    }
    match &written.failure {
        None => ExitCode::SUCCESS,
        Some(msg) => {
            diag::error(&format!("sbx {}: {msg}", w.label));
            ExitCode::FAILURE
        }
    }
}

/// The pure booleans `sbx app run` reads before the app name, which therefore take no `=value`.
/// The two learning flags are not among them: each reads its own optional `=granularity` suffix.
const APP_LAUNCH_VALUELESS_FLAGS: &[&str] = &[
    "--detach",
    "--observe",
    "--dry-run",
    "--global",
    "-g",
    "--local",
    "-l",
];

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
    // Learning state: each lens's granularity (once its flag is seen), the write scope, and whether
    // to only preview. The scope/`--dry-run` flags are meaningful only with a learning flag, enforced
    // after the loop.
    let mut learn_gran: Option<sandbox::NetGranularity> = None;
    let mut proc_gran: Option<sandbox::ProcGranularity> = None;
    let mut scope = Scope::Local;
    let mut scope_seen = false;
    let mut dry_run = false;
    while !head.is_empty() {
        // Decide on the leading token, then act — the match ends the immutable borrow so a
        // value-taking flag can mutate the queue.
        // The flag *name*, not the whole token: `--bind=<bytes>` is a flag whose value is not
        // text, and reading the token whole reported it as a malformed app name — naming the
        // wrong mistake, and on the `run` verb dropping the override in silence instead.
        let Some(flag) = flag_name(&head[0]).map(str::to_string) else {
            diag::error(&format!(
                "sbx: app name must be valid text — usage: {}",
                help::synopsis_of(&["app", "run"])
            ));
            return Err(ExitCode::from(2));
        };
        if let Some(code) = refuse_flag_value(&head[0], APP_LAUNCH_VALUELESS_FLAGS, &["app", "run"])
        {
            return Err(code);
        }
        match flag.as_str() {
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
                let gran = match crate::flag_inline(&head[0]) {
                    // The value decides how widely learned rules are written, so one the parser
                    // cannot read is refused rather than quietly taken as the widest default.
                    Some(inline) => {
                        let Some(value) = inline.to_str() else {
                            return Err(crate::refuse_nontext_value("app", &flag, inline));
                        };
                        match sandbox::NetGranularity::parse(value) {
                            Ok(g) => g,
                            Err(e) => {
                                diag::error(&format!("sbx: {e}"));
                                return Err(ExitCode::from(2));
                            }
                        }
                    }
                    None => sandbox::NetGranularity::default(),
                };
                learn_gran = Some(gran);
                head.remove(0);
            }
            // `--proc-learn[=name|path]`: the value after `=` picks the granularity; a bare flag is
            // `name`, the one that survives a channel roll.
            "--proc-learn" => {
                let gran = match crate::flag_inline(&head[0]) {
                    Some(inline) => {
                        let Some(value) = inline.to_str() else {
                            return Err(crate::refuse_nontext_value("app", &flag, inline));
                        };
                        match sandbox::ProcGranularity::parse(value) {
                            Ok(g) => g,
                            Err(e) => {
                                diag::error(&format!("sbx: {e}"));
                                return Err(ExitCode::from(2));
                            }
                        }
                    }
                    None => sandbox::ProcGranularity::default(),
                };
                proc_gran = Some(gran);
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
                    if flag.starts_with('-') {
                        diag::error(&format!(
                            "sbx: unknown flag {flag} — usage: {}",
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
                    // The name is the whole token: nothing was cut from it — a name carrying an
                    // `=` is not a flag — and quoting it back as typed is what makes the
                    // "no app named" report recognizable.
                    let Some(whole) = head[0].to_str().map(str::to_string) else {
                        diag::error(&format!(
                            "sbx: app name must be valid text — usage: {}",
                            help::synopsis_of(&["app", "run"])
                        ));
                        return Err(ExitCode::from(2));
                    };
                    name = Some(whole);
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
    let learning = learn_gran.is_some() || proc_gran.is_some();
    // A learning run reviews and writes rules in the foreground; `--detach` has no session to watch.
    if learning && detach {
        diag::error(
            "sbx: --net-learn/--proc-learn cannot be combined with --detach (they observe a \
             foreground run).",
        );
        return Err(ExitCode::from(2));
    }
    // The write scope and `--dry-run` only shape where a learning run puts its rules; refuse them on
    // a plain launch rather than silently ignoring a flag the user expected to matter.
    if !learning && (scope_seen || dry_run) {
        diag::error("sbx: --global/--local/--dry-run apply only with --net-learn/--proc-learn.");
        return Err(ExitCode::from(2));
    }
    let learn = learning.then_some(Learning {
        net: learn_gran,
        proc: proc_gran,
        scope,
        dry_run,
    });
    Ok(AppLaunch {
        name,
        detach,
        observe,
        tail,
        cli,
        learn,
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
    learn: Option<Learning>,
}

/// The learning intent of one launch: which lenses were asked to learn and how wide, which profile
/// the rules land in, and whether to only preview the diff.
///
/// One struct for both flags because the scope and the preview are the *run's*, not the lens's: a
/// launch that learns both its egress and its execs writes them to the same profile, in the same
/// act, and previewing one while writing the other would be a surprise.
struct Learning {
    net: Option<sandbox::NetGranularity>,
    proc: Option<sandbox::ProcGranularity>,
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
    let mut with_deps = false;
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
            Some("--with-deps") => with_deps = true,
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
            diag::error(&format!("sbx: cannot read {e}"));
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

    // What the profile references that this machine does not declare, resolved BEFORE anything is
    // written. Computed even without `--with-deps`, from one filter per kind, so the warnings and
    // the writes can never disagree about what "missing" means.
    let (declared_bundles, _) = config::bundles();
    let missing_bundles = super::missing_refs(
        &preview.uses,
        &declared_bundles,
        src_path,
        "bundle",
        config::read_bundle_fragment,
    );
    // Only the profile's OWN group references are visible from these bytes — validation resolves
    // nothing from disk. The groups its bundles reference come from the bundle files themselves,
    // which only `--with-deps` reads; without it they are reported by `sbx bundle import`.
    let (declared_groups, _) = config::net_groups();
    let missing_groups = super::missing_refs(
        &preview.groups,
        &declared_groups,
        src_path,
        "net-groups",
        config::read_net_groups_fragment,
    );
    // `--with-deps` promises all-or-nothing across two writers that are each all-or-nothing on
    // their own, which two calls are not. Resolve and validate the whole plan here, so a refusal
    // lands before the first byte does and only I/O can fail afterwards.
    let plan = if with_deps {
        match dep_plan(
            &missing_bundles,
            &missing_groups,
            &declared_groups,
            src_path,
        ) {
            Ok(plan) => Some(plan),
            Err(e) => {
                diag::error(&format!("sbx: app import --with-deps: {e}"));
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };

    // `--force` replaces a file the user may have edited: a per-machine allow rule, a `[secret]`
    // block, a package they swapped. The write, the refusal and the copy kept beside it are the
    // same for all three imported kinds, so they have one definition.
    let installed = match crate::cli::install_named_file(&dir, &name, &bytes, force, "profile") {
        Ok(i) => i,
        Err(code) => return code,
    };
    let dest = &installed.dest;

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    println!(
        "{}",
        render_app_imported(&name, dest, &preview.summary, &pal)
    );
    // An overwrite is the one import that can LOSE something. Name what the incoming profile no
    // longer carries — a diff of the two files would bury it in prose, and the settings are what a
    // reader stands to lose — and point at the copy kept beside it.
    if let Some(replaced) = &installed.replaced {
        let dropped = super::settings_dropped_by(
            &String::from_utf8_lossy(&replaced.previous),
            &String::from_utf8_lossy(&bytes),
        );
        diag::warn(&render_replaced_profile(&dropped, &replaced.kept));
    }
    // A profile is NOT self-contained, and what it is short of is not only a bundle. Both kinds of
    // reference resolve against the global config, both are silent at launch in the way that matters
    // (an absent tool, a dropped egress rule), and import is the moment to act on it or say so — it
    // is when the user is holding the file.
    match plan {
        Some(plan) => {
            if let Err(code) = write_deps(&plan) {
                return code;
            }
        }
        None => report_missing_refs(&name, &missing_bundles, &missing_groups),
    }
    ExitCode::SUCCESS
}

/// What `--with-deps` will merge into the global config alongside the profile: the bundles the
/// profile names that nothing declares, and the groups those bundles and the profile reference that
/// nothing defines. Both maps hold **only the referenced names** — a fragment may declare more, and
/// writing the rest would widen the import past what the reference asked for, which is the whole
/// reason this is opt-in.
struct DepPlan {
    bundles: Vec<DepEntry<config::RawBundle>>,
    groups: Vec<DepEntry<Vec<String>>>,
}

/// One dependency the plan will install: the name it is filed under, the bytes to copy, and the
/// value they parsed to.
///
/// The bytes ride along because an import is a **copy** — the author's comments and layout survive
/// — while the parsed value is what the announcements read: what naming this bundle would grant,
/// and which groups it references.
struct DepEntry<T> {
    name: String,
    bytes: Vec<u8>,
    value: T,
}

/// Read and validate everything `--with-deps` would write, or say why it cannot. Called before the
/// profile is written, so an unresolvable reference costs nothing: the user is left exactly where
/// they were, with the name that could not be found.
///
/// A group a bundle references is only visible once that bundle's file has been read, so the group
/// set is the profile's own references plus the ones the bundles bring in. A group referenced by a
/// bundle that is **already declared** is deliberately out of scope: that bundle arrived through
/// `sbx bundle import`, which named the gap at the moment it was created.
fn dep_plan(
    missing_bundles: &[super::MissingRef],
    missing_groups: &[super::MissingRef],
    declared_groups: &std::collections::BTreeMap<String, Vec<String>>,
    src: &Path,
) -> Result<DepPlan, String> {
    let mut bundles = Vec::new();
    for m in missing_bundles {
        // A name keys a referenceable identifier and, if invalid, is dropped at load — the silent
        // shortfall this whole path exists to remove. Fail closed, naming the offender, and BEFORE
        // asking whether a file backs it: the reader refuses an unusable file name too, so the
        // question "which file declares this" would answer "none" and hide why.
        if !config::is_valid_bundle_name(&m.name) {
            return Err(format!(
                "invalid bundle name `{}` (1–64 of [A-Za-z0-9._-]); nothing was written",
                m.name
            ));
        }
        let Some(file) = m.file.as_ref() else {
            return Err(unresolvable("bundle", &m.name, src));
        };
        let bytes = config::safety::read_safe_bytes(file)
            .map_err(|e| nothing_written(&format!("cannot read {e}")))?;
        let value = config::validate_bundle(&bytes)
            .map_err(|e| nothing_written(&format!("{}: {e}", file.display())))?;
        bundles.push(DepEntry {
            name: m.name.clone(),
            bytes,
            value,
        });
    }

    let mut wanted: Vec<super::MissingRef> = missing_groups.to_vec();
    for m in super::bundle::undefined_groups(&bundle_values(&bundles), src, declared_groups) {
        if !wanted.iter().any(|w| w.name == m.name) {
            wanted.push(m);
        }
    }
    let mut groups = Vec::new();
    for m in &wanted {
        // Before the file question, for the reason the bundle loop above states.
        if !config::is_valid_group_name(&m.name) {
            return Err(format!(
                "invalid group name `{}` (1–64 of [A-Za-z0-9._-]); nothing was written",
                m.name
            ));
        }
        let Some(file) = m.file.as_ref() else {
            return Err(unresolvable("egress group", &m.name, src));
        };
        let bytes = config::safety::read_safe_bytes(file)
            .map_err(|e| nothing_written(&format!("cannot read {e}")))?;
        let value = config::validate_group_file(&bytes)
            .map_err(|e| nothing_written(&format!("{}: {e}", file.display())))?;
        groups.push(DepEntry {
            name: m.name.clone(),
            bytes,
            value,
        });
    }
    Ok(DepPlan { bundles, groups })
}

fn nothing_written(e: &str) -> String {
    format!("{e}; nothing was written")
}

/// A reference `--with-deps` cannot follow. It names the sibling layout it looked in rather than
/// only the reference, because the fix is to fetch that file or run the import by hand — and the
/// command that would do so is the one the plain import prints.
fn unresolvable(kind: &str, name: &str, src: &Path) -> String {
    format!(
        "no file beside {} declares the {kind} `{name}` this profile names — import it by hand \
         first (`sbx {} <file>`), or drop --with-deps to import the profile alone; nothing was \
         written",
        src.display(),
        if kind == "bundle" {
            "bundle import"
        } else {
            "net groups import"
        },
    )
}

/// The parsed bundles of a plan, keyed by name — what the announcements read.
fn bundle_values(
    entries: &[DepEntry<config::RawBundle>],
) -> std::collections::BTreeMap<String, config::RawBundle> {
    entries
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect()
}

/// Install everything the plan holds: one file per bundle under `bundles/`, one per group under
/// `net-groups/`.
///
/// **All-or-nothing across both kinds.** Every destination is checked free before the first byte is
/// written, because `--with-deps` promises one act where there are now many writes: a collision
/// found halfway would leave a profile beside some of the dependencies it needs and not the others,
/// which is the half-installed state the flag exists to avoid. Only I/O can fail after that point.
fn write_deps(plan: &DepPlan) -> Result<(), ExitCode> {
    if plan.bundles.is_empty() && plan.groups.is_empty() {
        return Ok(());
    }
    let (Some(bundles_dir), Some(groups_dir)) = (config::bundles_dir(), config::net_groups_dir())
    else {
        diag::error("sbx: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return Err(ExitCode::from(1));
    };
    let planned: Vec<(&Path, &str, &str, &[u8])> = plan
        .bundles
        .iter()
        .map(|e| {
            (
                bundles_dir.as_path(),
                "bundle",
                e.name.as_str(),
                e.bytes.as_slice(),
            )
        })
        .chain(plan.groups.iter().map(|e| {
            (
                groups_dir.as_path(),
                "egress group",
                e.name.as_str(),
                e.bytes.as_slice(),
            )
        }))
        .collect();
    for (dir, noun, name, _) in &planned {
        let dest = dir.join(format!("{name}.toml"));
        if dest.exists() {
            diag::error(&format!(
                "sbx: app import --with-deps: a {noun} '{name}' already exists at {} — nothing was \
                 written",
                dest.display()
            ));
            return Err(ExitCode::from(1));
        }
    }
    for (dir, noun, name, bytes) in &planned {
        // Never `--force`: the plan holds only names nothing declares, and the pre-check above
        // proved each destination free.
        let installed = crate::cli::install_named_file(dir, name, bytes, false, noun)?;
        println!("imported {noun} `{name}` into {}", installed.dest.display());
    }
    // The grant belongs to the bytes, not to the verb that wrote them: this is the one import where
    // a reader did not name the bundle themselves, so it is the one where an unannounced credential
    // or egress rule would be least expected.
    if let Some(note) = super::bundle::granting_note(&bundle_values(&plan.bundles)) {
        diag::warn(&note);
    }
    Ok(())
}

/// Name what the profile still references and nothing declares — the plain import's half of the
/// job, and what `--with-deps` would have written.
fn report_missing_refs(name: &str, bundles: &[super::MissingRef], groups: &[super::MissingRef]) {
    if !bundles.is_empty() {
        let remedy = import_remedy("bundle import", bundles);
        diag::warn(&format!(
            "'{name}' names {} not declared here: {} — import {} too ({remedy}, or re-run with \
             --with-deps), or the app launches without the tool and egress it names",
            if bundles.len() == 1 {
                "a bundle"
            } else {
                "bundles"
            },
            bundles
                .iter()
                .map(|m| m.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            if bundles.len() == 1 { "it" } else { "them" },
        ));
    }
    // A group is global-only, so an undefined one is dropped at the fold and the app is launched
    // with LESS egress than it names — the failure mode a reader is least likely to attribute to a
    // missing import.
    if !groups.is_empty() {
        let remedy = import_remedy("net groups import", groups);
        diag::warn(&format!(
            "'{name}' references {} no `[network.groups]` here defines: {} — import {} too \
             ({remedy}, or re-run with --with-deps), or those entries are ignored and the app \
             reaches less than it names",
            if groups.len() == 1 {
                "an egress group"
            } else {
                "egress groups"
            },
            groups
                .iter()
                .map(|m| format!("@{}", m.name))
                .collect::<Vec<_>>()
                .join(", "),
            if groups.len() == 1 { "it" } else { "them" },
        ));
    }
}

/// Remove the copy a `--force` import kept, if there is one. Called from every path that removes a
/// profile: the copy belongs to the profile, not to the directory, and one left behind would
/// outlive the app and read as a profile that is still there. Best-effort — a missing copy is the
/// common case, and a removal that fails must not fail the removal of the app.
fn drop_replaced_copy(name: &str) {
    if let Some(dir) = config::profiles_dir() {
        let _ = std::fs::remove_file(dir.join(format!("{name}.toml.replaced")));
    }
}

/// The overwrite warning: what the replacement no longer carries, and where the previous bytes are.
/// A few dropped settings are named in full (the point is to recognize one's own edit); beyond that
/// the count stands in, because the file itself is kept and is the better place to read the rest.
fn render_replaced_profile(dropped: &[String], kept: &Path) -> String {
    const NAMED: usize = 3;
    let kept = kept.display();
    if dropped.is_empty() {
        return format!(
            "replaced a profile that differed only in comments or layout — the previous file is \
             kept at {kept}"
        );
    }
    let named = dropped
        .iter()
        .take(NAMED)
        .map(|l| format!("`{l}`"))
        .collect::<Vec<_>>()
        .join(", ");
    let rest = dropped.len().saturating_sub(NAMED);
    let more = if rest > 0 {
        format!(" (and {rest} more)")
    } else {
        String::new()
    };
    format!(
        "replaced a profile carrying {} the new one does not set: {named}{more} — the previous \
         file is kept at {kept}, so a per-machine setting can be read back and re-applied",
        if dropped.len() == 1 {
            "1 line".to_string()
        } else {
            format!("{} lines", dropped.len())
        },
    )
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
    let cwd = match config_cwd() {
        Ok(d) => d,
        Err(code) => return code,
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
            // Through the writer the other two exporters use: a profile is written to be imported
            // back, and a straight `fs::write` truncates first, so an interrupted export leaves a
            // fragment at the destination that `sbx app import` will happily read as a whole
            // profile. It also follows a symlink at the destination, which `--out` into a
            // cage-writable directory turns into a write through somebody else's name.
            //
            // No mode of sbx's own, which is the same decision `sbx bundle export` states: `--out
            // <file>` and a shell redirect are one command spelled two ways, so the destination
            // takes the umask like any other file the user asked for at a path they named. The
            // owner-only rule holds for what sbx writes *unasked* into its own directories, which
            // is the snapshot `keep_replaced_file` keeps, not for an artifact handed on.
            let text = String::from_utf8_lossy(&bytes);
            if let Err(e) = config::manage::write_text(path, &text, None) {
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

/// `sbx app rm <name>... [--purge] [--gc]`: remove one or more apps.
///
/// By default this removes only the imported **profile** (a file in the profiles directory) — a
/// project `[app.<name>]` overlay lives in that project's `.sbx.toml` and is the user's to edit
/// there. With `--purge` it also removes the app's isolated **runtime state**: its per-app home(s)
/// (the mise tools its `mise:` backends installed, its config, and its login/session state), which
/// is freed immediately. `--gc` (which requires `--purge`) then sweeps the **current project's**
/// nix store — reclaiming the apps' now-unreferenced `nix:`/`flake:` closures in one command for the
/// common single-project case (see [`app_rm_purge`]).
///
/// Several names may be named in one call, like `sbx projects rm`. Each is removed independently:
/// one name failing (no profile, a live session, a home that will not delete) never stops the ones
/// after it, and the exit code reports the batch. Every name is validated *before* the first removal
/// — the removal is destructive, so a typo at the end of the list must not cost the names before it
/// — and only a validated name is ever joined to a path (anti-traversal).
fn app_rm(args: &[OsString]) -> ExitCode {
    let (purge, gc, mut names) = match parse_app_rm(args) {
        AppRmArgs::Ok { purge, gc, names } => (purge, gc, names),
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
        AppRmArgs::NonUtf8 => {
            diag::error("sbx: app rm: argument is not valid UTF-8");
            return ExitCode::from(2);
        }
    };
    for name in &names {
        if !config::is_valid_app_name(name) {
            diag::error(&format!("sbx: '{name}' is not a valid app name"));
            return ExitCode::from(2);
        }
    }
    // `--gc` reclaims the store an app's homes referenced, so it only makes sense alongside the
    // home removal `--purge` performs — never on a bare profile removal.
    if gc && !purge {
        diag::error(
            "sbx: app rm: `--gc` requires `--purge` (it sweeps the store the purged home used)",
        );
        return ExitCode::from(2);
    }
    crate::cli::dedupe_names(&mut names);
    if purge {
        app_rm_purge(&names, gc)
    } else {
        app_rm_profiles(&names)
    }
}

/// The structural parse of `sbx app rm` arguments (before name validation). Kept pure so the flag/
/// positional handling — `--purge`, `--gc`, and one or more app names in any order — is unit-tested.
/// The names' charset validation, deduplication, and the `--gc`-requires-`--purge` rule are the
/// caller's next steps.
enum AppRmArgs<'a> {
    Ok {
        purge: bool,
        gc: bool,
        names: Vec<&'a str>,
    },
    MissingName,
    UnknownOption(&'a str),
    NonUtf8,
}

fn parse_app_rm(args: &[OsString]) -> AppRmArgs<'_> {
    let mut purge = false;
    let mut gc = false;
    let mut names: Vec<&str> = Vec::new();
    for arg in args {
        match arg.to_str() {
            Some("--purge") => purge = true,
            Some("--gc") => gc = true,
            Some(tok) if tok.starts_with('-') => return AppRmArgs::UnknownOption(tok),
            Some(tok) => names.push(tok),
            None => return AppRmArgs::NonUtf8,
        }
    }
    if names.is_empty() {
        AppRmArgs::MissingName
    } else {
        AppRmArgs::Ok { purge, gc, names }
    }
}

/// Remove the imported profiles of `names` only (the default `sbx app rm`, without `--purge`). A
/// missing profile is an error here — the user asked to remove a profile and there is none to remove
/// (with `--purge` a missing profile is tolerated, since the homes may still exist). Each name is
/// independent: a failing one leaves the others removed and only colours the exit code.
fn app_rm_profiles(names: &[&str]) -> ExitCode {
    let Some(dir) = config::profiles_dir() else {
        diag::error("sbx: cannot locate the config directory (set $HOME or $XDG_CONFIG_HOME)");
        return ExitCode::FAILURE;
    };
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let mut had_error = false;
    for name in names {
        let path = dir.join(format!("{name}.toml"));
        match std::fs::remove_file(&path) {
            Ok(()) => {
                drop_replaced_copy(name);
                println!("{}", render_removed(Some("app profile"), name, &pal));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                diag::error(&format!(
                    "sbx: no imported profile '{name}' (a project [app.{name}] overlay lives in a \
                     project's .sbx.toml — edit it there). To also remove an app's home/tools, use \
                     `sbx app rm {name} --purge`."
                ));
                had_error = true;
            }
            Err(e) => {
                diag::error(&format!("sbx: cannot remove {}: {e}", path.display()));
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

/// `sbx app rm <name>... --purge`: remove the profiles **and** the apps' isolated runtime state.
///
/// The runtime state is the per-app home(s): the global `<data>/apps/<name>/` and each per-project
/// `<data>/projects/<id>/apps/<name>/`. They hold the tools the app's `mise:` backends installed
/// (under the home's mise data dir), the app's config, and its login/session state — all removed
/// immediately, so "delete from mise" is satisfied here, not deferred. What this does **not** touch
/// is the shared per-project nix store: it backs every app in a project, so a purged app's
/// `nix:`/`flake:` closures are reclaimed by `sbx gc`, which the closing note points at.
///
/// The session registry is read **once** for the whole call: it decides the live-app guard for every
/// name, and a registry that cannot be read fails the batch closed (a purge must not run unproven).
/// Each name is then purged on its own by [`app_rm_purge_one`], so one refusal leaves the rest of
/// the batch to run and only colours the exit code.
///
/// When `gc` is set (the `--gc` flag), it then sweeps the **current project's** store via the same
/// path as `sbx gc --prune`, reclaiming the apps' now-unreferenced closures there in one command.
/// The sweep and its closing note are batch-level — the store is shared, so one sweep covers every
/// name. The sweep is a distinct step with its own prerequisites (a capable host, nix); its failure
/// is reflected in the exit code but never undoes the purge that already happened.
fn app_rm_purge(names: &[&str], gc: bool) -> ExitCode {
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());

    let layout = match layout_or_fail() {
        Ok(l) => l,
        Err(code) => return code,
    };

    // Read once for the batch, and fail closed for all of it: without the registry no name can be
    // proven idle, so none of them may be purged. Asked through `live` rather than `list`, because a
    // guard should not reclaim the directory it is questioning — `list` unlinks every record it
    // finds dead, and reclaiming belongs to the verbs that mean it and report the count.
    let sessions = match session::Registry::at(layout.data_dir()).live() {
        Ok(sessions) => sessions,
        Err(e) => {
            let listed: Vec<String> = names.iter().map(|name| format!("'{name}'")).collect();
            diag::error(&format!(
                "sbx: cannot read the session registry ({e}); not purging {}.",
                listed.join(", ")
            ));
            return ExitCode::FAILURE;
        }
    };

    let mut had_error = false;
    let mut purged_any = false;
    for name in names {
        let outcome = app_rm_purge_one(name, &sessions, &layout, &pal);
        had_error |= !outcome.ok;
        purged_any |= outcome.acted;
    }

    // Nothing came off disk for any name (a typo, or every name refused): the per-app errors above
    // already said why, and there is no reclamation to point at — neither the sweep nor its note.
    if !purged_any {
        return ExitCode::FAILURE;
    }

    // Any `nix:`/`flake:` tool closures the apps built live in the shared per-project store, which
    // backs every app in a project. `--gc` sweeps the *current* project's store now; without it, the
    // reclamation is a separate manual step, and either way other projects need their own sweep.
    if gc {
        println!();
        let gc_code = sandbox::gc(true, false, false, &pal);
        println!(
            "{}",
            style::dim_prose(
                "note: `--gc` swept this project's store; run `sbx gc --prune` in the apps' other \
                 projects to reclaim their copies too.",
                &pal
            )
        );
        // The purge succeeded independently of the sweep; when it did, defer to the sweep's own exit
        // code so a sweep that could not run (no capable host, nix missing) is not hidden — but never
        // undo the purge's failure signal.
        return if had_error {
            ExitCode::FAILURE
        } else {
            gc_code
        };
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
    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// What purging a single app under `--purge` did, as the batch in [`app_rm_purge`] needs to see it.
struct AppPurgeOutcome {
    /// The purge was clean: nothing refused it, and every home it found went away.
    ok: bool,
    /// Something was actually there to act on (a profile, or at least one home). It gates the
    /// batch's store sweep — a call that removed nothing has earned no reclamation.
    acted: bool,
}

/// The refusal for a purge that took nothing off disk, told apart by whether the profile was
/// *absent* or merely *undeletable*.
///
/// The two are different answers and only one of them is a typo. Reporting the undeletable profile
/// as "no profile" contradicts the `cannot remove <path>` line printed immediately above it, and a
/// reader takes the last sentence for the verdict — so the name that survived is named again here,
/// with what to do about it.
fn nothing_purged_message(name: &str, profile_failed: bool) -> String {
    if profile_failed {
        return format!(
            "sbx: nothing was purged for '{name}': its profile could not be removed (above) \
             and it has no home on disk"
        );
    }
    format!("sbx: nothing to purge for '{name}' (no profile and no home)")
}

/// Purge one app: its profile (if any) and its isolated home(s). `sessions` is the batch's single
/// read of the registry, so the live-app guard costs one listing no matter how many names are given.
///
/// A running session of the app is a hard stop — deleting its home mid-run would corrupt it — so
/// this refuses until the session is stopped (the same live guard `sbx gc` applies). Under `--purge`
/// a missing profile is tolerated (the homes may still exist), but finding *nothing at all* — no
/// profile and no home — is reported as a no-op so a typo never silently "succeeds".
fn app_rm_purge_one(
    name: &str,
    sessions: &[session::Session],
    layout: &store::Layout,
    pal: &style::Palette,
) -> AppPurgeOutcome {
    let (ok, n, warn, dim, r) = (pal.ok, pal.name, pal.warn, pal.dim, pal.reset);

    // Live-session guard: a session running as this app holds its home open.
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
        return AppPurgeOutcome {
            ok: false,
            acted: false,
        };
    }

    // 1. The profile (if any). Under --purge a missing profile is not fatal — the homes may still
    //    exist (an app whose profile was already removed, or a project/inline app that has none).
    //    A profile that could not be *deleted* is a different answer from one that was not there,
    //    and collapsing them into one `false` is what let a failed purge print `purged` and exit 0:
    //    the flag fed the "nothing found" check and the summary's wording, and nothing else, while
    //    `ok` was computed from the home removals alone. The sibling `app_rm_profiles` has always
    //    set `had_error` on this exact arm.
    let mut profile_failed = false;
    let profile_removed = match config::profile_path(name) {
        Some(path) => match std::fs::remove_file(&path) {
            Ok(()) => {
                drop_replaced_copy(name);
                println!("{}", render_removed(Some("app profile"), name, pal));
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => {
                diag::error(&format!("sbx: cannot remove {}: {e}", path.display()));
                profile_failed = true;
                false
            }
        },
        None => false,
    };

    // 2. The isolated home(s): mise tools + config + login state, freed immediately. A per-app
    //    tree that carried no home is removed too (it holds the app's channel lock), and named for
    //    what it is rather than as a home the app never had.
    let report = sandbox::purge_app_homes(layout.data_dir(), name);
    for home in &report.removed {
        println!(
            "{ok}removed{r} {} {n}{}{r} {dim}({}){r}",
            if home.carried_home { "home" } else { "state" },
            home.path.display(),
            sandbox::human_bytes(home.bytes)
        );
    }
    // Coloured for **stderr**, which is where `diag::error` writes — `pal` was chosen from stdout,
    // so with one stream redirected and the other a terminal this wrote escape codes into a file.
    // The stderr-derived palette is the idiom the rest of this module already uses.
    {
        let epal = style::Palette::for_stream(std::io::stderr().is_terminal());
        for (path, e) in &report.failed {
            diag::error(&format!(
                "{}sbx: could not remove {}: {e}{}",
                epal.warn,
                path.display(),
                epal.reset
            ));
        }
    }

    // 3. Nothing found across either source → a no-op (likely a typo); do not report success.
    //    A profile that refused to be *deleted* is not "nothing found": the line above has just
    //    named the file and the error that kept it, and denying its existence on the next line
    //    leaves the reader with two verdicts that contradict each other — the second one reading
    //    as the answer. It is still a no-op (nothing came off disk), so the outcome is unchanged.
    if !profile_removed && report.found_nothing() {
        diag::error(&nothing_purged_message(name, profile_failed));
        return AppPurgeOutcome {
            ok: false,
            acted: false,
        };
    }

    // Name only what was actually removed: a purge with no profile present must not claim one, and
    // one that found no home must not claim tools and login state that were never there — an app
    // may have nothing on disk but its channel lock.
    let any_home = report.removed.iter().any(|h| h.carried_home);
    let removed_what = match (profile_removed, any_home) {
        (true, true) => "profile + mise tools + login state",
        (true, false) => "profile + channel pin",
        (false, true) => "mise tools + login state",
        (false, false) => "channel pin",
    };
    // A partial failure (a home that would not delete) is not a clean purge — say so, so the green
    // summary never contradicts the non-zero exit the batch will carry.
    let clean = report.failed.is_empty() && !profile_failed;
    let verb = if clean {
        format!("{ok}purged{r}")
    } else {
        format!("{warn}purged with errors{r}")
    };
    println!(
        "{verb} app {n}{name}{r} — freed {n}{}{r} {dim}({removed_what}){r}",
        sandbox::human_bytes(report.freed())
    );
    // The purge left state behind if a home or the profile would not delete — surface it in the
    // exit code. A surviving profile is the more consequential of the two: `sbx app run <name>`
    // still resolves it, so the app is not gone in the way the word `purged` says it is.
    AppPurgeOutcome {
        ok: clean,
        acted: true,
    }
}

/// `sbx app list`: what is on disk to manage, one row per app — whether it has an imported
/// **profile** (`import`/`rm` artifacts) and whether it has an **installed home** (its mise tools +
/// login state, with disk size, which `--purge` removes). The two are distinct: an app can have a
/// profile with no home yet (never launched), or a home with no profile (launched from an
/// inline/project app, or a profile since removed) — so a name may carry a profile, a home, or both.
/// The full resolved app set — inline, project, and profile apps with their gating — is
/// `sbx config show`.
fn app_list(json: bool) -> ExitCode {
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
                    if path.extension().and_then(|x| x.to_str()) == Some("toml")
                        && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    {
                        profiles.insert(stem.to_string());
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

    // One row per app: the union of profile names and installed-home names.
    let mut names: BTreeSet<&str> = profiles.iter().map(String::as_str).collect();
    names.extend(homes.keys().copied());

    if json {
        // Bytes, not `12.4 MiB`: a consumer compares and sums, and the human column is a rendering
        // of this number rather than the other way round. The empty case is an empty array, so a
        // script never has to tell "no apps" from a parse failure.
        let rows: Vec<serde_json::Value> = names
            .iter()
            .map(|name| {
                let home = homes.get(name);
                serde_json::json!({
                    "name": name,
                    "profile": profiles.contains(*name),
                    "home_bytes": home.map(|a| a.total_bytes()),
                    "home_locations": home.map(|a| describe_home_locations(a)),
                })
            })
            .collect();
        if let Err(code) = crate::print_json(
            "app list",
            &serde_json::json!({
                "apps": rows,
                "total_bytes": installed.iter().map(sandbox::InstalledApp::total_bytes).sum::<u64>(),
                "profiles_dir": profiles_dir.as_ref().map(|d| d.display().to_string()),
            }),
        ) {
            return code;
        }
        return ExitCode::SUCCESS;
    }

    if profiles.is_empty() && installed.is_empty() {
        println!(
            "{dim}no imported app profiles and no installed app homes \
             (import one with: sbx app import <file>){r}"
        );
        return ExitCode::SUCCESS;
    }

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
    // The sizes above are what each home reads, which is not what removing it returns. Printed
    // whenever a size was, so the figure and its caveat are never read apart.
    if !installed.is_empty() {
        println!(
            "{}",
            style::dim_prose(
                &format!(
                    "sizes are of the data each home holds; {}",
                    sandbox::SIZE_CAVEAT
                ),
                &pal
            )
        );
    }
    ExitCode::SUCCESS
}

/// What a read-only `sbx app <verb> <name>` needs before it can say anything about the app: the
/// configuration resolved for the working directory, the data-directory layout, and the app's
/// installed home(s) on disk.
struct AppTarget {
    resolved: config::Resolved,
    layout: store::Layout,
    homes: Vec<sandbox::inspect::AppHome>,
}

/// Resolve the app `name` for a read-only `sbx app` verb, or report why it cannot be. An app that is
/// neither declared for this directory nor installed on disk does not exist, and the refusal —
/// tagged with `verb` — names the apps that *are* declared, or says that none is: that sentence is
/// what separates a misspelled name from the wrong directory, so both verbs owe it.
fn open_app(verb: &str, name: &str) -> Result<AppTarget, ExitCode> {
    let cwd = config_cwd()?;
    let layout = layout_or_fail()?;
    let resolved = config::load(&cwd);
    let homes = sandbox::inspect::app_home_dirs(layout.data_dir(), name);
    if !resolved.apps.contains_key(name) && homes.is_empty() {
        diag::error(&format!("sbx: {verb}: no app named {name:?}"));
        let declared: Vec<String> = resolved.apps.keys().cloned().collect();
        if declared.is_empty() {
            diag::error("sbx: no apps are declared for this directory");
        } else {
            diag::error(&format!("sbx: declared apps: {}", declared.join(", ")));
        }
        return Err(ExitCode::FAILURE);
    }
    Ok(AppTarget {
        resolved,
        layout,
        homes,
    })
}

/// `sbx app show <name>`: the realized-on-disk detail for one app — its profile source, its
/// isolated home(s) with size (and the mise-data breakdown), and each declared package annotated
/// with whether it is **actually installed**: a `mise:` tool is read from the app home; a `deb:` /
/// `appimage:` / `flake:` build lives in the per-project store, so it is reported from the per-tree
/// pins ("pinned in N tree(s)"); a `nix:` package is built per-project (`sbx projects show` details
/// it). A package declared by an untrusted layer reads `withheld`, distinct from `not installed`, so
/// it is not mistaken for a failed provision. Read-only: no trust gate, no launch, no network.
///
/// `--json` emits the same model.
fn app_show(args: &[OsString]) -> ExitCode {
    let (name, json) =
        match crate::cli::one_name(args, &["app", "show"], &["--json"], "name an app") {
            Ok(parsed) => parsed,
            Err(code) => return code,
        };
    let AppTarget {
        resolved,
        layout,
        homes,
    } = match open_app("app show", name) {
        Ok(t) => t,
        Err(code) => return code,
    };
    let app = resolved.apps.get(name);

    let view = build_app_show(name, app, &resolved.network, &homes, layout.data_dir());
    if json {
        if let Err(code) = print_json("app show", &view) {
            return code;
        }
        return ExitCode::SUCCESS;
    }
    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    crate::cli::print_document(&render_app_show(&view, &pal));
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
    /// What the home is made of, largest first — see [`sandbox::inspect::home_composition`]. The
    /// home is not split by a rule about which directory means what, because no such rule holds:
    /// a package manager's downloads and an app's own data sit side by side and are told apart by
    /// the reader, not by their names.
    entries: Vec<sandbox::inspect::HomeEntry>,
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
            // Size the app's own directory (the parent of `home`), matching `sbx app list`, and
            // read what the home holds so the figure is answerable rather than a single total.
            let app_dir = h.dir.parent().unwrap_or(&h.dir);
            let bytes = sandbox::tree_size(app_dir);
            let entries = sandbox::inspect::home_composition(&h.dir);
            AppHomeShow {
                location: if h.global {
                    "global".to_string()
                } else {
                    format!("project {}", h.project_id.as_deref().unwrap_or("?"))
                },
                bytes,
                entries,
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
                    let installed = package_installed(pkg, &installed_tools, homes, data_dir);
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

/// Whether one declared package is realized on this host, and how to say so.
///
/// `installed_tools` is passed in rather than derived here on purpose: the caller builds it once by
/// flat-mapping `mise_installed` over every app home, and computing it inside would re-walk the
/// filesystem once per declared package.
fn package_installed(
    pkg: &config::Package,
    installed_tools: &[sandbox::inspect::InstalledTool],
    homes: &[sandbox::inspect::AppHome],
    data_dir: &Path,
) -> PackageInstalled {
    use crate::config::Backend;
    if pkg.state != trust::TrustState::Trusted {
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
    } else if let Some(lockfile) = sandbox::inspect::prebuilt_lockfile(&pkg.backend) {
        // A `*:resolve` package's pin is keyed `resolve:<name>`, not by the `resolve`
        // sentinel `locator` carries — look it up by that key so a built one is found.
        let key = sandbox::inspect::prebuilt_pin_key(&pkg.backend, &pkg.name);
        let hits = sandbox::inspect::prebuilt_pin_trees(data_dir, &lockfile, &key);
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
            let _ = writeln!(
                s,
                "    {} · {}",
                home.location,
                sandbox::human_bytes(home.bytes),
            );
            // Percentages are of the home rather than of the app directory the total covers, so a
            // level's shares add up to what the reader sees listed.
            let held: u64 = home
                .entries
                .iter()
                .filter(|e| e.depth == 0)
                .map(|e| e.bytes)
                .sum();
            for entry in &home.entries {
                let share = (entry.bytes * 100).checked_div(held).unwrap_or(0);
                // The indent is part of the name column rather than added before it, so the sizes
                // stay in one column however deep the view went.
                let name = format!("{:indent$}{}", "", entry.rel, indent = entry.depth * 2);
                let _ = writeln!(
                    s,
                    "      {name:<34} {:>10}  {dim}{share}%{r}",
                    sandbox::human_bytes(entry.bytes),
                );
            }
        }
        for pool in &v.pools {
            let _ = writeln!(
                s,
                "    project {} {dim}(mise pool){r} · {}",
                pool.project_id,
                sandbox::human_bytes(pool.bytes),
            );
        }
        // Attached to the figures rather than to the verb, and only on the branch that printed
        // any: the `not launched yet` case has no size to qualify.
        let _ = writeln!(
            s,
            "    {dim}sizes are of the data held; {}{r}",
            sandbox::SIZE_CAVEAT
        );
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

/// What `sbx app prune` was asked to do: which app(s), whether the caches go too, and whether this
/// is the applying run.
struct PruneArgs {
    /// The named app, or `None` under `--all`.
    name: Option<String>,
    /// `--all`: every app with an installed home, rather than one named.
    all: bool,
    /// `--stale`: also drop installed versions no activation asks for.
    stale: bool,
    /// `--drop <entry>`: named entries of each home to take, relative to the home. Repeatable.
    drop: Vec<String>,
    /// `--reset`: take everything each home holds, leaving the app's declaration.
    reset: bool,
    /// `--yes`: apply, rather than preview.
    apply: bool,
}

/// Parse `<name> | --all` plus `[--caches] [-y|--yes]`. A dedicated parser rather than
/// [`crate::cli::one_name`], which reads exactly one name and one switch: this verb has a bulk
/// selector that stands *instead* of the name, and two switches that compose.
fn parse_prune_args(args: &[OsString]) -> Result<PruneArgs, ExitCode> {
    let (mut name, mut all, mut apply) = (None, false, false);
    let (mut stale, mut reset) = (false, false);
    let mut drop: Vec<String> = Vec::new();
    let mut want_entry = false;
    for a in args {
        // `--drop` takes the next argument, which may look like anything a directory can be named.
        if want_entry {
            let Some(entry) = a.to_str() else {
                diag::error("sbx: app prune: --drop takes a path, and this one is not valid UTF-8");
                return Err(ExitCode::from(2));
            };
            // A forgotten entry would otherwise make the next flag the thing to delete, silently.
            // An entry really starting with `-` is unreachable this way, and reachable as `./-x`.
            if entry.starts_with('-') {
                diag::error(&format!(
                    "sbx: app prune: --drop takes an entry to remove, got the flag `{entry}`"
                ));
                diag::hint("       name it as `sbx app show` lists it, e.g. `--drop .rustup`.");
                return Err(ExitCode::from(2));
            }
            drop.push(entry.to_string());
            want_entry = false;
            continue;
        }
        match a.to_str() {
            Some("--all") => all = true,
            Some("--stale") => stale = true,
            Some("--reset") => reset = true,
            Some("--drop") => want_entry = true,
            Some("-y") | Some("--yes") => apply = true,
            Some("--help") | Some("-h") => return Err(help::show(&["app", "prune"])),
            Some(flag) if flag.starts_with('-') => {
                diag::error(&format!("sbx: app prune: unknown flag `{flag}`"));
                diag::hint("       run `sbx help app prune` for usage.");
                return Err(ExitCode::from(2));
            }
            Some(n) if name.is_none() => name = Some(n.to_string()),
            Some(n) => {
                diag::error(&format!(
                    "sbx: app prune: name one app, not two (`{}` and `{n}`) — or use --all.",
                    name.unwrap_or_default()
                ));
                return Err(ExitCode::from(2));
            }
            None => {
                diag::error("sbx: app prune: argument is not valid UTF-8");
                return Err(ExitCode::from(2));
            }
        }
    }
    // The two selectors are alternatives, and naming both leaves it unsaid which one governs.
    if name.is_some() && all {
        diag::error("sbx: app prune: name an app or use --all, not both.");
        return Err(ExitCode::from(2));
    }
    if name.is_none() && !all {
        diag::error("sbx: app prune: name an app, or use --all to sweep every installed one.");
        diag::hint("       `sbx app list` names them.");
        return Err(ExitCode::from(2));
    }
    if want_entry {
        diag::error("sbx: app prune: --drop needs the entry to take, as `sbx app show` names it.");
        return Err(ExitCode::from(2));
    }
    // `--reset` takes everything, so pairing it with a narrower selector says two things at once
    // and only one of them happens.
    if reset && (!drop.is_empty() || stale) {
        diag::error("sbx: app prune: --reset already takes everything the other flags select.");
        return Err(ExitCode::from(2));
    }
    // Refused rather than supported: emptying every app's home in one gesture is not something a
    // command line says by accident, and there is no reading of it that a per-app run does not
    // cover more safely.
    if reset && all {
        diag::error("sbx: app prune: --reset acts on one named app, not on --all.");
        diag::hint("       run it per app; `sbx app list` names them.");
        return Err(ExitCode::from(2));
    }
    Ok(PruneArgs {
        name,
        all,
        stale,
        drop,
        reset,
        apply,
    })
}

#[cfg(test)]
mod prune_args_tests {
    use super::parse_prune_args;
    use std::ffi::OsString;

    fn parse(args: &[&str]) -> Result<super::PruneArgs, std::process::ExitCode> {
        let owned: Vec<OsString> = args.iter().map(OsString::from).collect();
        parse_prune_args(&owned)
    }

    #[test]
    fn drop_collects_every_entry_it_is_given() {
        let Ok(parsed) = parse(&["demo", "--drop", ".rustup", "--drop", ".local/share/pnpm"])
        else {
            panic!("two entries must parse");
        };
        assert_eq!(parsed.drop, [".rustup", ".local/share/pnpm"]);
        assert_eq!(parsed.name.as_deref(), Some("demo"));
        assert!(!parsed.reset && !parsed.apply);
    }

    #[test]
    fn drop_refuses_the_flag_that_follows_a_forgotten_entry() {
        // Without this, `--drop --reset` reads as "remove the entry named `--reset`", and the flag
        // the user meant to pass is silently gone.
        assert!(parse(&["demo", "--drop", "--reset"]).is_err());
        assert!(parse(&["demo", "--drop"]).is_err());
    }

    #[test]
    fn reset_stands_alone() {
        // It already takes everything the others select, and it acts on one app.
        assert!(parse(&["demo", "--reset", "--caches"]).is_err());
        assert!(parse(&["demo", "--reset", "--stale"]).is_err());
        assert!(parse(&["demo", "--reset", "--drop", ".npm"]).is_err());
        assert!(parse(&["--all", "--reset"]).is_err());
        assert!(parse(&["demo", "--reset", "--yes"]).is_ok());
    }
}

/// What one app's prune freed (or would free), for the run's totals.
#[derive(Default)]
struct PruneTotals {
    tools: usize,
    versions: usize,
    /// Home entries taken by `--drop` or `--reset`.
    entries: usize,
    bytes: u64,
}

/// `sbx app prune <name>|--all [--caches] [--yes]`: remove the mise tools an app's home(s) carry
/// that the app's config does **not** declare — the `installed (undeclared)` leftovers `sbx app
/// show` surfaces (a former profile's tool, or one added by hand). Each is deleted from the home's
/// mise `installs/` and dropped from its `config.toml` `[tools]` so it does not re-equip. With
/// `--caches`, each home's cache directory is emptied as well. Previews by default; `--yes` applies.
/// Declared tools, login/session state, and any `nix:`/`deb:`/`flake:` build are untouched.
fn app_prune(args: &[OsString]) -> ExitCode {
    let PruneArgs {
        name,
        all,
        stale,
        drop,
        reset,
        apply,
    } = match parse_prune_args(args) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };

    // Resolved once, whether one app or seventy: the configuration for this directory does not
    // change between apps, and re-reading it per app would read the same files each time.
    let (resolved, layout) = if let Some(name) = &name {
        match open_app("app prune", name) {
            Ok(t) => (t.resolved, t.layout),
            Err(code) => return code,
        }
    } else {
        let cwd = match config_cwd() {
            Ok(c) => c,
            Err(code) => return code,
        };
        match layout_or_fail() {
            Ok(l) => (config::load(&cwd), l),
            Err(code) => return code,
        }
    };

    let targets: Vec<String> = match &name {
        Some(n) => vec![n.clone()],
        // Only apps with an installed home: an app is nothing to prune until it has one, and a
        // profile with no home would report an empty sweep for every app the user ever imported.
        None => sandbox::installed_app_homes(layout.data_dir())
            .into_iter()
            .map(|a| a.name)
            .collect(),
    };

    let pal = style::Palette::for_stream(std::io::stdout().is_terminal());
    let (h, n, ok, dim, r) = (pal.head, pal.name, pal.ok, pal.dim, pal.reset);
    let mut totals = PruneTotals::default();
    let mut skipped: Vec<String> = Vec::new();
    let mut had_error = false;

    // The live-session guard below reads the registry once for the whole sweep, and an error
    // reading it refuses the run rather than defaulting to an empty answer. `unwrap_or_default`
    // here would turn "cannot know" into "nothing is running", so the one check standing between
    // `--yes` and a running agent's home would pass by failing. [`session::Registry::scan`] already
    // skips a single unreadable record so one bad entry cannot blank the answer, and treats a
    // missing directory as no sessions; what reaches this `Err` is the sessions directory itself
    // being unreadable, which is exactly the state a destructive verb must not act through.
    //
    // The same rule and the same shape as [`app_rm`]'s purge path above, which reads the registry
    // once for its batch and refuses all of it when it cannot: the two destructive verbs in this
    // file are allowed to delete out of an app home only because the registry says no session of
    // that app is live, so neither may read "cannot know" as "nothing there". This one asks through
    // `live` rather than `list`, because a guard should not reclaim the directory it is questioning.
    //
    // Read only when applying: the preview deletes nothing, so it stays available on a host whose
    // registry cannot be read — which is also where a user would go looking for what happened.
    let live_sessions = if apply {
        match session::Registry::at(layout.data_dir()).live() {
            Ok(live) => live,
            Err(e) => {
                diag::error(&format!(
                    "sbx app prune: cannot read the session registry ({e}) — refusing to prune, \
                     because a live session of the app cannot be ruled out."
                ));
                diag::hint(
                    "       re-run without `--yes` to see what would go, or fix the data \
                     directory's permissions",
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };

    for app_name in &targets {
        let homes = sandbox::inspect::app_home_dirs(layout.data_dir(), app_name);
        // A prune deletes trees out of the home a running session of this app is using: its `PATH`
        // entries and interpreters are in `installs/`, and a cache is written to while the app runs,
        // so work in flight loses a tool or a cache mid-command and reports something that looks
        // nothing like what happened. The preview is always safe, so only the applying form is held
        // back. Named, it is refused outright: there is no reading of `sbx app prune <name> --yes`
        // under which deleting a live agent's state is the intent. Under `--all` the app is skipped
        // and named instead, so one running agent does not stand between the user and the rest.
        if apply {
            let mut pids: Vec<u32> = live_sessions
                .iter()
                .filter(|s| s.app() == Some(app_name.as_str()))
                .map(|s| s.pid)
                .collect();
            // The registry sorts by project then pid, so an app with a session in two projects
            // would list its pids out of order; the message names them ascending either way.
            pids.sort_unstable();
            if !pids.is_empty() {
                let rendered: Vec<String> = pids.iter().map(u32::to_string).collect();
                let listed = rendered.join(", ");
                if all {
                    skipped.push(format!("{app_name} (pid {listed})"));
                    continue;
                }
                diag::error(&format!(
                    "sbx: app prune: {app_name} has a live session (pid {listed}) whose home this \
                     would delete from — refusing to act under a running agent"
                ));
                diag::hint(&format!(
                    "       stop it with `sbx session stop {}`, or re-run without `--yes` to see \
                     what would go",
                    rendered.join(" ")
                ));
                return ExitCode::FAILURE;
            }
        }

        let declared = declared_mise_tokens(&resolved, app_name);
        let declared: Vec<&str> = declared.iter().map(String::as_str).collect();
        for home in &homes {
            // `--reset` stands instead of the tool sweep rather than beside it: it takes the
            // directory the sweep would have worked through.
            let pruned = if reset {
                Vec::new()
            } else {
                sandbox::prune_app_tools(&home.dir, &declared, apply)
            };
            let taken = if reset {
                sandbox::reset_home(&home.dir, apply)
            } else if drop.is_empty() {
                Vec::new()
            } else {
                sandbox::drop_home_entries(&home.dir, &drop, apply)
            };
            if pruned.is_empty() && taken.is_empty() {
                continue;
            }
            let location = if home.global {
                "global home".to_string()
            } else {
                format!("project {} home", home.project_id.as_deref().unwrap_or("?"))
            };
            // Under `--all` the app has to be named, or a line cannot be attributed; named, the
            // heading would repeat what the command line already said.
            if all {
                println!("{n}{app_name}{r} {dim}{location}:{r}");
            } else {
                println!("{dim}{location}:{r}");
            }
            for p in &pruned {
                totals.tools += 1;
                totals.bytes += p.bytes;
                println!(
                    "  {n}{}{r}  {dim}{}{r}",
                    p.token,
                    sandbox::human_bytes(p.bytes)
                );
            }
            for e in &taken {
                totals.entries += 1;
                totals.bytes += e.bytes;
                println!(
                    "  {n}{}{r}  {dim}{}{r}",
                    e.rel,
                    sandbox::human_bytes(e.bytes)
                );
            }
        }

        // A global app's state is not all in its home: the two-scope split puts what it
        // self-equipped per project in a pool of its own, and a reset that left those standing
        // would leave the app equipped in some projects and bare in others.
        if reset {
            for pool in sandbox::inspect::app_per_project_mise_pools(layout.data_dir(), app_name) {
                let taken = sandbox::reset_home(&pool.dir, apply);
                if taken.is_empty() {
                    continue;
                }
                let location = format!("project {} mise pool", pool.project_id);
                if all {
                    println!("{n}{app_name}{r} {dim}{location}:{r}");
                } else {
                    println!("{dim}{location}:{r}");
                }
                for e in &taken {
                    totals.entries += 1;
                    totals.bytes += e.bytes;
                    println!(
                        "  {n}{}{r}  {dim}{}{r}",
                        e.rel,
                        sandbox::human_bytes(e.bytes)
                    );
                }
            }
        }

        if !stale {
            continue;
        }
        // A home's own activation record governs its own pool, and nothing else reaches it.
        for home in &homes {
            let specs = sandbox::mise_tool_specs(&home.dir.join(".config/mise/config.toml"));
            let installs = home.dir.join(".local/share/mise/installs");
            let stale_versions = sandbox::prune_stale_versions(&installs, &specs, apply);
            report_stale(
                &stale_versions,
                app_name,
                "global home",
                all,
                &pal,
                &mut totals,
            );
        }
        // A per-project pool is governed by two files: the app's own activation record, which is
        // app-global and stays in its home, and the project's mise file, where a `mise use` without
        // `-g` writes. Reading only the first would call stale a version the project asks for.
        for pool in sandbox::inspect::app_per_project_mise_pools(layout.data_dir(), app_name) {
            let tree = layout.data_dir().join("projects").join(&pool.project_id);
            let Some(project) = sandbox::read_marker(&tree) else {
                continue;
            };
            // The project directory is gone, so its mise file cannot be read and what it asked for
            // is unknown. A tree in that state is removed whole by `sbx projects rm --dead`, which
            // is the verb for it; guessing here would delete on a reading that was never made.
            if !project.is_dir() {
                continue;
            }
            let activation_of = |app: &str| {
                layout
                    .data_dir()
                    .join("apps")
                    .join(app)
                    .join("home/.config/mise/config.toml")
            };
            let mut specs = sandbox::mise_tool_specs(&activation_of(app_name));
            for file in crate::trust::mise_files_for(&project.join(".sbx.toml")) {
                for (tool, versions) in sandbox::mise_tool_specs(&file) {
                    specs.entry(tool).or_default().extend(versions);
                }
            }
            // And the other apps of this project, because `apps_share_install_pools` lets one
            // resolve out of another's pool: a tool this app equipped once and no longer asks for
            // may be the one a neighbour found here and therefore never installed itself, so
            // reading this app's activations alone would empty a pool under a running neighbour.
            // Not gated on the grant, which lives in the project's config rather than on disk here:
            // when it is off those activations name versions no launch resolves from this pool, so
            // the widening only ever keeps a version, and keeping one is this sweep's stated bias
            // (see `prune_stale_versions`, which leaves a tool with no spec entirely alone).
            for (neighbour, _) in
                sandbox::inspect::project_mise_pools(layout.data_dir(), &pool.project_id, app_name)
            {
                for (tool, versions) in sandbox::mise_tool_specs(&activation_of(&neighbour)) {
                    specs.entry(tool).or_default().extend(versions);
                }
            }
            let stale_versions =
                sandbox::prune_stale_versions(&pool.dir.join("installs"), &specs, apply);
            let where_ = format!("project {} mise pool", pool.project_id);
            report_stale(&stale_versions, app_name, &where_, all, &pal, &mut totals);
        }
    }

    for line in &skipped {
        diag::note(&format!(
            "sbx: app prune: skipped {line} — a live session holds that home"
        ));
        had_error = true;
    }

    if totals.tools == 0 && totals.versions == 0 && totals.entries == 0 {
        let subject = match &name {
            Some(n) => n.clone(),
            None => "no app".to_string(),
        };
        // Names what was asked for, so an empty run reads as an answer to the question rather than
        // to a different one: `--reset` and `--drop` stand on their own, and the other two compose.
        let what = if reset {
            "state"
        } else if !drop.is_empty() {
            "named entry"
        } else if stale {
            "undeclared mise tools or stale versions"
        } else {
            "undeclared mise tools"
        };
        println!("{h}sbx app prune{r} {dim}— {subject}: no {what} to prune.{r}");
        return if had_error {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        };
    }

    let size = sandbox::human_bytes(totals.bytes);
    let subject = prune_subject(totals.tools, totals.versions, totals.entries);
    if apply {
        println!("{ok}pruned {subject}, freeing {size} of data.{r}");
    } else {
        println!(
            "{}",
            style::dim_prose(
                &format!("would prune {subject} ({size} of data) — re-run with `--yes` to apply."),
                &pal
            )
        );
    }
    // The figure is the size of what was removed, which is what the caller can be told before the
    // fact. What the disk gets back is another number: a compressing volume stored those bytes
    // smaller, and a block shared with another tree stays until its last reference goes. Only the
    // filesystem knows either, so the line points at the verb that asks it rather than guessing.
    println!(
        "{}",
        style::dim_prose(
            &format!("that is the size of the data; {}", sandbox::SIZE_CAVEAT),
            &pal
        )
    );
    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Print one pool's stale versions and fold them into the run's totals. Written once because the
/// homes and the per-project pools report identically and differ only in where they are.
fn report_stale(
    versions: &[sandbox::PrunedVersion],
    app_name: &str,
    location: &str,
    all: bool,
    pal: &style::Palette,
    totals: &mut PruneTotals,
) {
    if versions.is_empty() {
        return;
    }
    let (n, dim, r) = (pal.name, pal.dim, pal.reset);
    if all {
        println!("{n}{app_name}{r} {dim}{location}:{r}");
    } else {
        println!("{dim}{location}:{r}");
    }
    for v in versions {
        totals.versions += 1;
        totals.bytes += v.bytes;
        println!(
            "  {n}{}@{}{r}  {dim}{} (no activation asks for it){r}",
            v.token,
            v.version,
            sandbox::human_bytes(v.bytes)
        );
    }
}

/// The app's declared `mise:` tokens; a tool matching none of them is undeclared. A home-only app
/// (no config) declares nothing, so every mise tool in its home is prunable.
fn declared_mise_tokens(resolved: &config::Resolved, name: &str) -> Vec<String> {
    resolved
        .apps
        .get(name)
        .map(|a| {
            a.packages
                .iter()
                .filter_map(|p| match &p.backend {
                    config::Backend::Mise(token) => Some(token.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `2 undeclared tool(s) and 3 cache(s)`, dropping either half when it is empty — the phrase both
/// the preview and the applied line are built from, so the two can never describe the same run
/// differently.
fn prune_subject(tools: usize, versions: usize, entries: usize) -> String {
    let mut parts = Vec::new();
    if tools > 0 {
        parts.push(format!("{tools} undeclared tool(s)"));
    }
    if versions > 0 {
        parts.push(format!("{versions} stale version(s)"));
    }
    if entries > 0 {
        parts.push(format!("{entries} home entry(ies)"));
    }
    match parts.len() {
        0 => "nothing".to_string(),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap_or_default();
            format!("{} and {last}", parts.join(", "))
        }
    }
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

    /// A successful `sbx app rm` parse as a comparable tuple; any error arm panics, so a regression
    /// reads as the arm that was actually taken rather than as a silent non-match.
    fn parse_rm_ok(args: &[OsString]) -> (bool, bool, Vec<String>) {
        match parse_app_rm(args) {
            AppRmArgs::Ok { purge, gc, names } => {
                (purge, gc, names.into_iter().map(str::to_string).collect())
            }
            _ => panic!("expected a successful parse"),
        }
    }

    #[test]
    fn parse_app_rm_handles_flag_and_name_in_either_order() {
        let os = |s: &str| OsString::from(s);
        let one = |name: &str| vec![name.to_string()];
        // name only
        assert_eq!(
            parse_rm_ok(&[os("demo-app")]),
            (false, false, one("demo-app"))
        );
        // --purge before the name
        assert_eq!(
            parse_rm_ok(&[os("--purge"), os("demo-app")]),
            (true, false, one("demo-app"))
        );
        // --purge after the name (either order)
        assert_eq!(
            parse_rm_ok(&[os("demo-app"), os("--purge")]),
            (true, false, one("demo-app"))
        );
        // --purge and --gc together, name interleaved between the flags
        assert_eq!(
            parse_rm_ok(&[os("--gc"), os("demo-app"), os("--purge")]),
            (true, true, one("demo-app"))
        );
        // --gc alone parses; the --gc-requires---purge rule is the caller's, not the parser's
        assert_eq!(
            parse_rm_ok(&[os("--gc"), os("demo-app")]),
            (false, true, one("demo-app"))
        );
        // no name — even with the flag, --purge alone must never mean "purge everything"
        assert!(matches!(parse_app_rm(&[]), AppRmArgs::MissingName));
        assert!(matches!(
            parse_app_rm(&[os("--purge")]),
            AppRmArgs::MissingName
        ));
        // a leading dash is an option, never a name
        assert!(matches!(
            parse_app_rm(&[os("--nope"), os("demo-app")]),
            AppRmArgs::UnknownOption("--nope")
        ));
    }

    #[test]
    fn parse_app_rm_takes_several_names_in_the_order_given() {
        let os = |s: &str| OsString::from(s);
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Several positionals are several apps, kept in the order the user typed them.
        assert_eq!(
            parse_rm_ok(&[os("demo-app"), os("demo-tool")]),
            (false, false, names(&["demo-app", "demo-tool"]))
        );
        // Flags may sit anywhere among the names; they apply to the whole call.
        assert_eq!(
            parse_rm_ok(&[os("--purge"), os("demo-app"), os("--gc"), os("demo-tool")]),
            (true, true, names(&["demo-app", "demo-tool"]))
        );
        // A repeat is preserved by the parser — deduplication is the caller's step.
        assert_eq!(
            parse_rm_ok(&[os("demo-app"), os("demo-app")]),
            (false, false, names(&["demo-app", "demo-app"]))
        );
    }

    #[test]
    fn a_replaced_profile_reports_settings_and_ignores_prose() {
        let previous = "# an old comment\ncmd = \"demo-app\"\n[network]\nmode = \"deny\"\n    \
                        allow = [\"api.example.com\"]\nforward = [7000]\n";
        // Same settings, rewritten prose and re-indented: nothing was lost.
        let reworded = "# a NEW comment, rewritten wholesale\ncmd = \"demo-app\"\n[network]\n\
                        mode = \"deny\"\nallow = [\"api.example.com\"]\n  forward = [7000]\n";
        assert!(
            super::super::settings_dropped_by(previous, reworded).is_empty(),
            "comments and indentation are not settings"
        );
        // A value the incoming profile no longer sets IS a loss, and only that value is named.
        let without =
            "cmd = \"demo-app\"\n[network]\nmode = \"deny\"\nallow = [\"api.example.com\"]\n";
        assert_eq!(
            super::super::settings_dropped_by(previous, without),
            vec!["forward = [7000]"]
        );
        // A setting that merely moved elsewhere in the file is not a loss.
        let moved = "forward = [7000]\ncmd = \"demo-app\"\n[network]\nmode = \"deny\"\n\
                     allow = [\"api.example.com\"]\n";
        assert!(super::super::settings_dropped_by(previous, moved).is_empty());
    }

    #[test]
    fn the_overwrite_warning_names_a_few_losses_and_counts_the_rest() {
        let kept = Path::new("/config/sbx/apps/demo-app.toml.replaced");
        let one = render_replaced_profile(&["forward = [7000]".to_string()], kept);
        assert!(
            one.contains("1 line") && one.contains("`forward = [7000]`"),
            "{one}"
        );
        assert!(one.contains("demo-app.toml.replaced"), "{one}");
        // Beyond a few, the count stands in — the kept file is where the rest is read.
        let many: Vec<String> = (0..5).map(|i| format!("k{i} = {i}")).collect();
        let lots = render_replaced_profile(&many, kept);
        assert!(
            lots.contains("5 lines") && lots.contains("(and 2 more)"),
            "{lots}"
        );
        assert!(
            lots.contains("`k0 = 0`") && !lots.contains("`k4 = 4`"),
            "{lots}"
        );
        // A file that differs only in prose still names where the previous bytes went.
        let none = render_replaced_profile(&[], kept);
        assert!(
            none.contains("comments or layout") && none.contains(".replaced"),
            "{none}"
        );
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
    fn a_write_that_fails_part_way_still_names_what_it_wrote() {
        // The egress path persists one rule per call, so a refusal on the third leaves the first two
        // in the file. Reporting only the error would tell the operator their config was untouched
        // when it was not — and it is the shape a shared applier makes easy to lose, because a
        // `Result` has room for one of the two answers.
        let seen = std::cell::RefCell::new(Vec::new());
        let persist = |rules: &[String]| {
            seen.borrow_mut().extend_from_slice(rules);
            Written {
                lines: vec!["added allow a to the project config".to_string()],
                failure: Some("could not write b".to_string()),
            }
        };
        let synth = sandbox::Synthesis {
            rules: vec!["a".to_string(), "b".to_string()],
            notes: Vec::new(),
        };
        let code = finish_learn(
            "demo-app",
            &synth,
            &LearnWrite {
                label: "net-learn",
                refused: "was refused nothing",
                noun: "egress",
                gran: "domain",
                dry_run: false,
                target: "the project config".to_string(),
                also: None,
                persist: &persist,
            },
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::FAILURE));
        // The whole list reached the writer: a failure part way does not stop the rules after it
        // from being attempted, and what it wrote is carried back to be named.
        assert_eq!(*seen.borrow(), vec!["a".to_string(), "b".to_string()]);

        // A dry run writes nothing at all, whatever the persister would have done.
        seen.borrow_mut().clear();
        let code = finish_learn(
            "demo-app",
            &synth,
            &LearnWrite {
                label: "proc-learn",
                refused: "ran nothing new",
                noun: "exec",
                gran: "name",
                dry_run: true,
                target: "the project config".to_string(),
                also: Some("and sets the posture"),
                persist: &persist,
            },
        );
        assert_eq!(format!("{code:?}"), format!("{:?}", ExitCode::SUCCESS));
        assert!(seen.borrow().is_empty(), "a dry run must not write");
    }

    #[test]
    fn parse_app_launch_splits_the_name_flags_and_passthrough_args() {
        use std::ffi::OsString;
        let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };

        // A bare name: no detach, no passthrough, no override, no net-learn.
        let a = parse_app_launch(&v(&["demo-app"])).unwrap();
        assert_eq!((a.name.as_str(), a.detach), ("demo-app", false));
        assert!(a.tail.is_empty() && a.cli.config.is_empty() && a.cli.env.is_empty());
        assert!(a.learn.is_none());

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
        let nl = a.learn.expect("net-learn set");
        assert_eq!(nl.net, Some(sandbox::NetGranularity::Domain));
        assert!(matches!(nl.scope, config::manage::Scope::Local) && !nl.dry_run);
        // `=level`, `--dry-run`, and `-g` compose, in any order with the name.
        let a = parse_app_launch(&v(&["--net-learn=path", "demo-app", "--dry-run", "-g"])).unwrap();
        let nl = a.learn.expect("net-learn set");
        assert_eq!(nl.net, Some(sandbox::NetGranularity::Path));
        assert!(matches!(nl.scope, config::manage::Scope::Global) && nl.dry_run);
        // A bad granularity, `--net-learn` with `--detach`, and a scope/`--dry-run` without
        // `--net-learn` are each usage errors (never a silently-ignored flag).
        assert!(parse_app_launch(&v(&["demo-app", "--net-learn=subtree"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--net-learn", "--detach"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--dry-run"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "-g"])).is_err());

        // `--proc-learn` reads its own granularity and shares the scope and the preview with its
        // egress twin: one launch can learn both, and both land in the same place.
        let a = parse_app_launch(&v(&["demo-app", "--proc-learn"])).unwrap();
        let l = a.learn.expect("proc-learn set");
        assert_eq!(l.proc, Some(sandbox::ProcGranularity::Name));
        assert_eq!(l.net, None);
        let a = parse_app_launch(&v(&[
            "--proc-learn=path",
            "demo-app",
            "--net-learn=exact",
            "--dry-run",
        ]))
        .unwrap();
        let l = a.learn.expect("both flags set");
        assert_eq!(l.proc, Some(sandbox::ProcGranularity::Path));
        assert_eq!(l.net, Some(sandbox::NetGranularity::Exact));
        assert!(l.dry_run);
        // The same three usage errors, in its own vocabulary — and the scope flags are no longer a
        // usage error once *either* learning flag is present.
        assert!(parse_app_launch(&v(&["demo-app", "--proc-learn=basename"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--proc-learn", "--detach"])).is_err());
        assert!(parse_app_launch(&v(&["demo-app", "--proc-learn", "-g"])).is_ok());

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

    /// A profile that refused to be deleted is not an absent one. `--purge` prints
    /// `cannot remove <path>: Permission denied` and then, when the app has no home either, the
    /// no-op refusal — which claimed "no profile and no home" about the file the previous line had
    /// just named. The reader takes the second sentence for the verdict, so it must not deny what
    /// the first one reported.
    #[test]
    fn a_profile_that_would_not_delete_is_not_reported_as_an_absent_one() {
        let absent = nothing_purged_message("demo-app", false);
        assert!(absent.contains("no profile and no home"), "{absent}");

        let failed = nothing_purged_message("demo-app", true);
        assert!(
            !failed.contains("no profile"),
            "the refusal must not deny a profile the previous line named: {failed}"
        );
        assert!(
            failed.contains("could not be removed"),
            "and must say what survived, since that is what the user has to act on: {failed}"
        );
        assert!(failed.contains("demo-app"), "{failed}");
    }

    /// The pure booleans decide the launch posture, so a `=value` suffix is refused rather than
    /// stripped. Dispatching them through `flag_name` — which exists so that `--config` and
    /// `--config=x` reach one arm — discarded the value and switched the flag on regardless, so
    /// `--observe=false` turned the exec feed on and `--net-learn --dry-run=false` wrote the
    /// learned rules into the profile when a preview was what was asked for.
    #[test]
    fn a_valueless_app_launch_flag_refuses_a_value_rather_than_switching_itself_on() {
        use std::ffi::OsString;
        let v = |xs: &[&str]| -> Vec<OsString> { xs.iter().map(OsString::from).collect() };
        for bad in [
            v(&["demo-app", "--detach=false"]),
            v(&["demo-app", "--observe=false"]),
            v(&["demo-app", "--net-learn", "--dry-run=false"]),
            v(&["demo-app", "--net-learn", "--global=false"]),
            v(&["demo-app", "--net-learn", "-l=1"]),
        ] {
            assert!(parse_app_launch(&bad).is_err(), "{bad:?}");
        }
        // The optional-value booleans keep their inline form — they are not these flags, and the
        // `--gpu=false` grammar is exactly what leads a caller to try `--detach=false` — and so
        // does `--net-learn`, which reads its own suffix.
        let a = parse_app_launch(&v(&["demo-app", "--gpu=false", "--net-learn=path"])).unwrap();
        assert_eq!(a.cli.gpu, vec!["false".to_string()]);
        assert_eq!(
            a.learn
                .expect("net-learn set")
                .net
                .expect("net granularity"),
            sandbox::NetGranularity::Path
        );
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
