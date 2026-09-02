use super::*;
use crate::store::Origin;
use crate::testutil::TmpDir;
use std::path::PathBuf;

/// Which argv shapes take an `$0` filler before the caller's `-- <args>` are appended, and
/// which must be left exactly as the profile wrote them.
///
/// Every case is a literal argv, never one assembled by the code under test: the whole point
/// is to pin the shape from the outside, so a detector that drifts has nothing to agree with.
#[test]
fn only_a_trailing_shell_script_takes_an_argv0_filler() {
    let argv = |v: &[&str]| -> Vec<OsString> { v.iter().map(OsString::from).collect() };

    // The shape that eats an argument: the script is the last element, so whatever follows
    // becomes the shell's `$0`.
    assert!(ends_with_shell_payload(&argv(&["bash", "-c", "exec foo"])));
    // Combined short flags still end in `c`, so the script still follows.
    assert!(ends_with_shell_payload(&argv(&["bash", "-lc", "exec foo"])));
    assert!(ends_with_shell_payload(&argv(&["sh", "-euc", "exec foo"])));
    // The shell is matched on its file name, so an absolute path counts.
    assert!(ends_with_shell_payload(&argv(&[
        "/bin/dash",
        "-c",
        "exec foo"
    ])));
    assert!(ends_with_shell_payload(&argv(&["zsh", "-c", "exec foo"])));
    // A leading wrapper does not hide the shape — only the last three elements decide.
    assert!(ends_with_shell_payload(&argv(&[
        "env", "-i", "bash", "-c", "exec foo"
    ])));

    // Already carries its own `$0`: the profile said which name its script reports, and the
    // append lands on `$1` unaided. Touching this would rename the script.
    assert!(!ends_with_shell_payload(&argv(&[
        "bash", "-c", "exec foo", "foo"
    ])));
    // A plain argv: the appended arguments are the program's own, with nothing to shift.
    assert!(!ends_with_shell_payload(&argv(&["foo", "--flag", "value"])));
    // Not a shell whose `-c` binds `$0` this way.
    assert!(!ends_with_shell_payload(&argv(&[
        "python3", "-c", "print(1)"
    ])));
    // A flag that does not end in `c` does not make the next element a script.
    assert!(!ends_with_shell_payload(&argv(&["bash", "-i", "exec foo"])));
    assert!(!ends_with_shell_payload(&argv(&[
        "bash", "-ci", "exec foo"
    ])));
    // Too short to carry the shape at all — must not panic on the slice.
    assert!(!ends_with_shell_payload(&argv(&["bash", "-c"])));
    assert!(!ends_with_shell_payload(&argv(&["foo"])));
    assert!(!ends_with_shell_payload(&argv(&[])));
}

const REV: &str = "9ae611a455b90cf061d8f332b977e387bda8e1ca";

/// `--observe` is accepted on every launch, but its inline feed is emitted on one path only.
///
/// Every launch that takes the feed away has to say so, because a flag that prints nothing and
/// streams nothing is indistinguishable from one that worked.
///
/// The enforcing case is the one this was written for: it is not one mode but three, and a check
/// that named `enforce` alone would leave `ask` and `confine` silently featureless. The pairing
/// with [`observation_flags`] is asserted rather than assumed — the warning has to fire exactly
/// when the poller that feeds the stream is off, or the two drift apart.
#[test]
fn a_launch_that_cannot_show_the_observe_feed_says_so() {
    use crate::proc_policy::{ProcMode, ProcPolicy};

    let with = |mode| ProcPolicy {
        mode,
        ..ProcPolicy::default()
    };

    // The path the feed rides: asked for, no terminal to fight, a mode that leaves the poller on.
    for mode in [ProcMode::Off, ProcMode::Observe] {
        let policy = with(mode);
        assert_eq!(
            observe_feed_absent_reason(true, false, &policy),
            None,
            "{mode:?}: the feed is emitted here, so there is nothing to warn about"
        );
        assert!(
            observation_flags(&policy, true).0,
            "{mode:?}: and the poller that feeds it is on"
        );
    }

    // Every enforcing mode, not just the obvious one.
    for mode in [ProcMode::Enforce, ProcMode::Ask, ProcMode::Confine] {
        let policy = with(mode);
        let reason = observe_feed_absent_reason(true, false, &policy)
            .unwrap_or_else(|| panic!("{mode:?}: no feed and no warning is the silent case"));
        assert!(
            reason.contains("seccomp lens"),
            "{mode:?}: the reason names where the events are instead: {reason}"
        );
        assert!(
            !observation_flags(&policy, true).0,
            "{mode:?}: the warning fires exactly when the poller is off"
        );
    }

    // A terminal takes the inline feed away too, and keeps its own reason.
    let interactive = observe_feed_absent_reason(true, true, &with(ProcMode::Observe))
        .expect("an interactive terminal has no inline feed either");
    assert!(interactive.contains("interactive terminal"));

    // Enforcement is named first: it is the reason that holds whether or not there is a
    // terminal, and the one a reader would otherwise not guess.
    assert_eq!(
        observe_feed_absent_reason(true, true, &with(ProcMode::Enforce)),
        observe_feed_absent_reason(true, false, &with(ProcMode::Enforce))
    );

    // And nothing is said to a launch that never asked.
    for mode in [ProcMode::Off, ProcMode::Observe, ProcMode::Enforce] {
        assert_eq!(observe_feed_absent_reason(false, true, &with(mode)), None);
    }
}

/// Observation and the `exec`-replace shortcut cannot coexist: the observer's control socket,
/// its ring and its poll thread hang off *this* process, and an `exec` replaces the process
/// that owns them.
///
/// Both guardless launch paths used to decide the shortcut from the `--observe` flag rather
/// than from the resolved policy, so a project whose config declares `[proc] mode = "observe"`
/// lost observation in two different ways with no error on either: the detached daemon started
/// the observer and then exec'd straight over it, and the foreground non-tty path never started
/// one at all. Both now ask [`may_exec_replace`], which reads the same
/// [`observation_flags`] pair that decides whether to start the observer.
///
/// What is pinned here is the predicate's own answer. That the two launch paths ask it — the
/// half that was actually written wrong — is guarded by
/// `the_guardless_launch_paths_ask_the_predicate_and_not_the_observe_flag`, because a call site
/// can go back to reading the flag while every assertion below still holds.
#[test]
fn config_declared_observation_blocks_the_exec_replace_shortcut() {
    use crate::proc_policy::{ProcMode, ProcPolicy};

    let with = |mode| ProcPolicy {
        mode,
        ..ProcPolicy::default()
    };

    // The regression: no flag, but the policy alone turns the poll exec lens on.
    let declared = with(ProcMode::Observe);
    assert!(
        observation_flags(&declared, false).0,
        "a config-declared observe mode runs the poll lens without `--observe`"
    );
    assert!(
        !may_exec_replace(&declared, false),
        "so a guardless launch must fork+wait — an exec would replace the observer's own parent"
    );

    // The flag alone, on a policy that declares nothing, blocks it too (the fs lens follows
    // the flag).
    assert!(!may_exec_replace(&with(ProcMode::Off), true));
    // Including under enforcement, where the poller is off but the inotify lens still runs.
    assert!(!may_exec_replace(&with(ProcMode::Enforce), true));

    // And the shortcut is still granted where it belongs, or this guard would be satisfiable
    // by refusing every launch: with nothing observed there is nothing to outlive the cage.
    assert!(may_exec_replace(&with(ProcMode::Off), false));
    // An unasked enforcing launch keeps it here as well — its seccomp supervisor arrives as a
    // `LaunchGuard`, and it is the guard, not this predicate, that forces supervision.
    assert!(may_exec_replace(&with(ProcMode::Enforce), false));
}

/// The predicate is half the fix; the other half is that the two guardless launch paths
/// actually ask it. Both used to decide the `exec`-replace shortcut from the `--observe` flag
/// alone — `None if !observe` — and that is the shape the defect takes if it returns:
/// [`may_exec_replace`] can keep every semantic the test above pins while a call site goes on
/// reading the raw flag, losing a config-declared `[proc] mode = "observe"` exactly as before
/// (the detached daemon starts the observer and execs over it, the foreground path starts none).
///
/// Neither `launch_foreground` nor `detached_child` is reachable from a unit test — both take a
/// whole `Prepared`, build a real cage, and end in `exec` or `process::exit` — and nothing else
/// in the crate calls them, so the decision at those two sites is guarded here on the source, the
/// way `the_wraps_nest_around_the_composed_startup_and_not_the_bare_command` guards `build`'s own
/// ordering from beside it in `build.rs`, because the alternative is no check at all.
///
/// The two sites now sit in different files — the foreground path here, the daemon in `detach.rs` —
/// so each is read from the file it lives in.
#[test]
fn the_guardless_launch_paths_ask_the_predicate_and_not_the_observe_flag() {
    // Each file is production code whole: its tests live in a sibling module and quote these very
    // fragments, so there is nothing to cut them off from.
    for (name, production) in [
        ("launch_foreground", include_str!("mod.rs")),
        ("detached_child", include_str!("detach.rs")),
    ] {
        let start = production
            .find(&format!("\nfn {name}("))
            .unwrap_or_else(|| panic!("`{name}` is where a guardless launch decides to exec"));
        // A top-level `}` in the first column ends the function.
        let rest = &production[start + 1..];
        let body = &rest[..rest
            .find("\n}\n")
            .unwrap_or_else(|| panic!("`{name}` never closes"))];

        // The pair that decides whether an observer is started at all.
        assert!(
            body.contains("observation_flags(&prep.cfg.proc, observe)"),
            "`{name}` no longer reads the resolved policy to decide observation"
        );

        let arms: Vec<&str> = body
            .match_indices("None if ")
            .map(|(at, kw)| {
                let cond = &body[at + kw.len()..];
                &cond[..cond.find(" =>").unwrap_or(cond.len())]
            })
            .collect();
        assert_eq!(
            arms.len(),
            1,
            "`{name}` has {} guardless arms: a second one can reinstate the flag-only \
             decision for whichever matches first ({arms:?})",
            arms.len()
        );
        assert_eq!(
            arms[0], "may_exec_replace(&prep.cfg.proc, observe)",
            "`{name}` decides the exec-replace shortcut with `{}` instead of asking \
             `may_exec_replace`, so a config-declared `[proc] mode = \"observe\"` — which sets \
             no flag — takes the shortcut again and its observation is lost with no error",
            arms[0]
        );
    }
}

/// Every warning a config produced reaches the terminal through [`crate::diag::warn_config`], which
/// filters it, and never through the unfiltered [`crate::diag::warn`].
///
/// The text of such a warning names the key or value it is complaining about, and for an untrusted
/// project that name is the project's to spell. Control bytes in it reach the launching terminal at
/// the exact moment sbx is reporting what it refused, so an escape run can erase the trust warnings
/// printed just above. The repo already found this once, in the `[tools]` table, and answered it
/// with `mise_token_display` plus a regression test; every other table printed its warnings raw.
///
/// Counted rather than trusted to stay converted, because the failure is silent: a new warning
/// producer with a plain `warn` looks exactly like a correct one, and there are nine of these loops
/// across four files. The loop variable is the tell — a `warn` whose argument is a bare `warning`
/// or `w` is printing somebody else's string.
///
/// **What this does not cover, stated because the count reads stronger than it is:** the *inline*
/// form, `warn(&format!("… {key} …"))`, where a config-chosen value arrives through interpolation
/// and never becomes a loop variable. Seventeen of those in `build.rs` were converted by reading
/// every one of them, and no mechanical rule separates them from the sites that interpolate only
/// sbx's own values — the format string has to be read. A new one is therefore not caught here; the
/// [`crate::diag::warn_config`] doc is where that rule is written for a reader adding a warning.
#[test]
fn no_config_warning_reaches_the_terminal_unfiltered() {
    for (name, source) in [
        ("launch/build.rs", include_str!("build.rs")),
        ("launch/reclaim.rs", include_str!("reclaim.rs")),
        ("launch/detach.rs", include_str!("detach.rs")),
        ("main.rs", include_str!("../../main.rs")),
    ] {
        let production = source
            .rsplit_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        for raw in ["warn(warning)", "warn(w)"] {
            assert_eq!(
                production.matches(raw).count(),
                0,
                "{name} prints a config-chosen warning through the unfiltered `warn`; use \
                 `diag::warn_config`, the rule `mise_token_display` already applies to `[tools]`"
            );
        }
    }
}

/// A diagnostic that names an identifier goes through [`crate::diag::error`], which styles it.
///
/// Forty raw `eprintln!("sbx…")` lines live in these files, and converting all of them would be a
/// change with no observable effect: `highlight` paints backticked spans and leaves everything else
/// byte-identical, so a message with no identifier in it renders the same either way. Four carried
/// one and lost it: the `[fs] scan` scanner, the `[fs]` mask staging, and the two broker failures,
/// which name the broker the user configured — the one word a reader needs to find in the message.
///
/// So the rule is enforced where it bites rather than by converting thirty-six sites that gain
/// nothing: a raw diagnostic may not carry a backtick. A `sbx gc:` / `sbx session attach:` line is
/// held to it too — the prefix says which verb speaks, not whether the message names anything.
///
/// The window runs to the call's closing `);` rather than reading one line, and that is what found
/// the fourth: a grep for a backtick on the `eprintln!` line itself sees three, because the mask
/// staging spells its format string on the line below.
///
/// What it cannot see: an identifier that arrives by interpolation. A format string with no
/// backtick still renders one when the value it prints carries it — `{e}` on an error from the
/// credential chain reaches the terminal naming a resolver plugin in backticks, unstyled, and this
/// guard passes the call. Reading the source cannot settle that, because it is a property of the
/// error at run time; the egress proxy's failure in `build.rs` is the site where it was measured,
/// and it goes through `diag::error` for that reason rather than because of its own text. Any new
/// raw diagnostic printing an error from another module is subject to the same gap.
#[test]
fn no_raw_diagnostic_names_an_identifier_it_cannot_style() {
    for (name, source) in [
        ("launch/build.rs", include_str!("build.rs")),
        ("launch/cage.rs", include_str!("cage.rs")),
        ("launch/mod.rs", include_str!("mod.rs")),
        ("launch/reclaim.rs", include_str!("reclaim.rs")),
        ("launch/session.rs", include_str!("session.rs")),
        ("launch/detach.rs", include_str!("detach.rs")),
    ] {
        let production = source
            .rsplit_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        // A call may spell its format string on the `eprintln!(` line or on the lines under it, so
        // the window runs to the call's own closing `);` rather than stopping at the first line.
        let lines: Vec<&str> = production.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("eprintln!(") {
                continue;
            }
            let mut call = String::new();
            for l in lines[i..].iter().take(8) {
                call.push_str(l);
                call.push(' ');
                if l.trim_end().ends_with(");") {
                    break;
                }
            }
            assert!(
                !(call.contains("\"sbx") && call.contains('`')),
                "{name}:{} prints an identifier through a raw `eprintln!`, which cannot style it; \
                 use `diag::error` — {}",
                i + 1,
                line.trim()
            );
        }
    }
}

#[test]
fn no_pin_targets_the_global_lock_ignoring_any_stale_project_lock() {
    // Without a current pin the decision is the global channel, so the per-project
    // lock is never even named — a stale one left on disk cannot resurface. The
    // common path also does not canonicalise the cwd, so an arbitrary path is fine.
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    std::fs::create_dir_all(layout.data_dir()).unwrap();
    std::fs::write(
        layout.data_dir().join("nixpkgs.lock"),
        format!("nixos-unstable\n{REV}\n"),
    )
    .unwrap();

    let target = effective_lock_target(
        Path::new("/nonexistent"),
        &layout,
        &crate::testutil::resolved_channels(None, None),
        None,
    )
    .expect("global target needs no canonicalisation");
    assert_eq!(target.origin(), Origin::Default);
    assert_eq!(target.source(), "nixos-unstable");
    // it reads the global lock, never a per-project one
    assert_eq!(target.locked_revision().as_deref(), Some(REV));
}

#[test]
fn a_global_override_targets_the_global_lock_under_that_source() {
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let target = effective_lock_target(
        Path::new("/nonexistent"),
        &layout,
        &crate::testutil::resolved_channels(Some("nixos-23.11"), None),
        None,
    )
    .expect("global override needs no canonicalisation");
    assert_eq!(target.origin(), Origin::Global);
    assert_eq!(target.source(), "nixos-23.11");
}

#[test]
fn a_trusted_pin_targets_a_per_project_lock() {
    // A pin canonicalises the cwd to key its own lock; resolving a revision pin
    // (no nix needed) records it there, not in the global lock.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());

    let target = effective_lock_target(
        proj.path(),
        &layout,
        &crate::testutil::resolved_channels(None, Some(REV)),
        None,
    )
    .expect("canonicalise the project");
    assert_eq!(target.origin(), Origin::ProjectPin);
    assert_eq!(target.source(), REV);

    target
        .resolve(Path::new("/nonexistent-nix"), &layout)
        .expect("a revision pin resolves without nix");
    // the global lock stays untouched; a per-project lock was written instead
    assert!(!layout.data_dir().join("nixpkgs.lock").exists());
    let projects = layout.data_dir().join("projects");
    let has_lock = std::fs::read_dir(&projects)
        .map(|e| e.flatten().any(|d| d.path().join("nixpkgs.lock").is_file()))
        .unwrap_or(false);
    assert!(has_lock, "a trusted pin must record a per-project lock");
}

#[test]
fn an_app_without_a_pin_targets_its_own_lock() {
    // The app branch: no project pin, so the app resolves against a lock keyed by its name and
    // sitting beside its state. The source is still the global one — an app cannot choose a
    // channel — so what is per-app here is the revision, nothing else.
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());

    let target = effective_lock_target(
        Path::new("/nonexistent"),
        &layout,
        &crate::testutil::resolved_channels(None, None),
        Some("demo-app"),
    )
    .expect("the app branch needs no canonicalisation either");
    assert_eq!(target.origin(), Origin::Default);
    assert_eq!(target.source(), "nixos-unstable");

    // Resolving a fixed pin needs no nix, and records the revision in the app's own lock —
    // never the global one, which is what makes `sbx upgrade nix` leave this app alone.
    let pinned = effective_lock_target(
        Path::new("/nonexistent"),
        &layout,
        &crate::testutil::resolved_channels(Some(REV), None),
        Some("demo-app"),
    )
    .unwrap();
    pinned
        .resolve(Path::new("/nonexistent-nix"), &layout)
        .expect("a revision source resolves without nix");
    assert!(
        layout
            .data_dir()
            .join("apps/demo-app/nixpkgs.lock")
            .is_file(),
        "the revision lands in the app's own lock"
    );
    assert!(!layout.data_dir().join("nixpkgs.lock").exists());
}

#[test]
fn a_project_pin_wins_over_an_app_lock() {
    // The precedence that keeps the one-channel rule true: an app launch also builds the
    // project's declared packages (`merge_app` overrides by name, it does not replace the
    // list), so under a trusted pin those tools must come from the pinned revision. The app's
    // own lock is therefore not even named here.
    let data = TmpDir::new();
    let proj = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());

    let target = effective_lock_target(
        proj.path(),
        &layout,
        &crate::testutil::resolved_channels(None, Some(REV)),
        Some("demo-app"),
    )
    .expect("canonicalise the project");
    assert_eq!(target.origin(), Origin::ProjectPin);
    assert_eq!(target.source(), REV);

    target
        .resolve(Path::new("/nonexistent-nix"), &layout)
        .expect("a revision pin resolves without nix");
    assert!(
        !layout.data_dir().join("apps/demo-app").exists(),
        "under a pin, no app lock is written"
    );
}

#[test]
fn collect_roots_unions_base_then_packages_then_tools_then_fonts() {
    // The seed's completeness rides on this collection: every provisioner's roots
    // must reach it. The order is base, then packages, then tools, then fonts.
    let userland = Userland {
        base_roots: vec![
            PathBuf::from("/nix/store/glibc"),
            PathBuf::from("/nix/store/bash"),
        ],
        interp_src: PathBuf::from("/store/nix-ld"),
        interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
        base_loader: PathBuf::from("/nix/store/glibc/lib/ld"),
        foreign_lib_paths: vec![],
        bin_paths: vec![],
        shell_bin: PathBuf::from("/nix/store/bash/bin/bash"),
        env_bin: PathBuf::from("/nix/store/coreutils/bin/env"),
        socat_bin: PathBuf::from("/nix/store/socat/bin/socat"),
        mise_bin: PathBuf::from("/nix/store/mise/bin/mise"),
        nix_bin: PathBuf::from("/nix/store/nix/bin/nix"),
        locale_archive: PathBuf::from("/nix/store/locales/lib/locale/locale-archive"),
        zoneinfo_src: PathBuf::from("/nix/store/tzdata/share/zoneinfo"),
    };
    let pkg_roots = [PathBuf::from("/nix/store/jq")];
    let tool_roots = [PathBuf::from("/nix/store/nodejs")];
    let font_roots = [PathBuf::from("/nix/store/dejavu")];

    assert_eq!(
        collect_roots(&userland, &pkg_roots, &tool_roots, &font_roots),
        vec![
            PathBuf::from("/nix/store/glibc"),
            PathBuf::from("/nix/store/bash"),
            PathBuf::from("/nix/store/jq"),
            PathBuf::from("/nix/store/nodejs"),
            PathBuf::from("/nix/store/dejavu"),
        ]
    );

    // teeth: dropping a source loses exactly its roots — a launch that forgot to
    // forward the tools' (or packages', or fonts') roots would seed an incomplete
    // closure, and the cage would silently re-fetch the missing one.
    assert!(
        !collect_roots(&userland, &pkg_roots, &[], &font_roots)
            .contains(&PathBuf::from("/nix/store/nodejs"))
    );
    assert!(
        !collect_roots(&userland, &[], &tool_roots, &font_roots)
            .contains(&PathBuf::from("/nix/store/jq"))
    );
    assert!(
        !collect_roots(&userland, &pkg_roots, &tool_roots, &[])
            .contains(&PathBuf::from("/nix/store/dejavu"))
    );
}
