use super::*;
use crate::store::Origin;
use crate::testutil::TmpDir;
use std::path::PathBuf;

/// The zone a cage ends up in, held against a database that really is on disk.
///
/// The config layer already refused the shapes that are not zone names; what only this side can
/// decide is whether the database *carries* the zone, so the cases here are the ones that turn
/// on a file existing.
#[test]
fn a_zone_the_database_does_not_carry_falls_back_to_the_default() {
    // The database sits one level inside the fixture, so the traversal case below resolves to a
    // sibling the fixture owns rather than to a name outside the tree this test may write.
    let base = TmpDir::new();
    let db = base.path().join("zoneinfo");
    std::fs::create_dir_all(db.join("Europe")).unwrap();
    std::fs::write(db.join("Europe/Paris"), b"TZif").unwrap();
    std::fs::write(db.join("UTC"), b"TZif").unwrap();

    // Nothing declared: the built-in zone, which is a zone and not an absence.
    assert_eq!(cage_timezone(None, &db), "UTC");
    // Declared and present: taken.
    assert_eq!(cage_timezone(Some("Europe/Paris"), &db), "Europe/Paris");
    // Declared and absent: the default, not a refused launch — a misspelled zone costs a wrong
    // clock, never the session.
    assert_eq!(cage_timezone(Some("Europe/Pariss"), &db), "UTC");
    // A directory inside the database is not a zone: `Europe` resolves to something that
    // exists, so only the is-a-file test tells the two apart.
    assert_eq!(cage_timezone(Some("Europe"), &db), "UTC");
    // The shape rule is applied here too, at the join site: a traversal that would otherwise
    // resolve to a real file outside the database never becomes a link target.
    std::fs::write(base.path().join("escaped"), b"x").unwrap();
    assert_eq!(cage_timezone(Some("../escaped"), &db), "UTC");
    // And a database that is not there at all still yields a launchable cage.
    assert_eq!(
        cage_timezone(Some("Europe/Paris"), Path::new("/nonexistent-zoneinfo")),
        "UTC"
    );
}

/// Which of the two ways to name a zone decides the link. The property under test is not a
/// precedence preference, it is that **one** value drives both halves: `TZ` is what the cage's
/// clock will read, so the link has to follow it or the two answer differently with no error.
#[test]
fn the_link_follows_whatever_tz_will_finally_read() {
    let env = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    };

    // Neither: nothing is declared, and the caller falls back to the built-in zone.
    assert_eq!(declared_zone(&env(&[("LANG", "C.UTF-8")]), None), None);
    // The field alone.
    assert_eq!(
        declared_zone(&env(&[]), Some("Europe/Paris")),
        Some("Europe/Paris")
    );
    // `TZ` alone — the case that used to move the clock and leave the link behind.
    assert_eq!(
        declared_zone(&env(&[("TZ", "Asia/Tokyo")]), None),
        Some("Asia/Tokyo")
    );
    // Both, disagreeing: `TZ` wins, because `TZ` is what the cage will actually read.
    assert_eq!(
        declared_zone(&env(&[("TZ", "Asia/Tokyo")]), Some("Europe/Paris")),
        Some("Asia/Tokyo")
    );
    // Two layers both setting it: the later one wins, exactly as the assembler's upsert does.
    assert_eq!(
        declared_zone(&env(&[("TZ", "Asia/Tokyo"), ("TZ", "UTC")]), None),
        Some("UTC")
    );
}

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
/// ordering, because the alternative is no check at all.
#[test]
fn the_guardless_launch_paths_ask_the_predicate_and_not_the_observe_flag() {
    // The whole file is production code: the tests live in this sibling and quote these very
    // fragments, so there is nothing to cut them off from any more.
    let production = include_str!("../launch.rs");

    for name in ["launch_foreground", "detached_child"] {
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

/// `sbx gc` collects a store a live cage is reading and writing, so the live-session check is
/// the only thing standing between a running sandbox and a sweep of its own store. It used to
/// be written `if let Ok(sessions) = …`, which silently read an unreadable registry as an empty
/// one — the failure mode that matters is precisely the one where the answer is unknown, and it
/// took the permissive branch. Refuse instead, and say which of the two refusals it is.
#[test]
fn gc_refuses_when_the_session_registry_cannot_be_read() {
    use crate::session::{Kind, Session, SessionRuntime};

    let project = PathBuf::from("/home/u/proj");
    let session = |p: &str| Session {
        project: PathBuf::from(p),
        pid: 4321,
        start_ticks: 99,
        kind: Kind::Run,
        runtime: SessionRuntime::Project,
        detached: true,
    };

    // The regression: an unreadable registry is not an empty one.
    let refusal = gc_live_session_refusal(
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        &project,
    )
    .expect("an unreadable registry cannot rule out a live cage, so gc must refuse");
    assert!(
        refusal.contains("cannot read the session registry"),
        "and it must name the real reason, not claim a sandbox is running: {refusal}"
    );

    // The refusal it already had, unchanged.
    let running = gc_live_session_refusal(Ok(vec![session("/home/u/proj")]), &project)
        .expect("a live session in this project still refuses");
    assert!(running.contains("a sandbox is running in this project"));

    // And gc still runs where it should, or this guard would be satisfied by refusing
    // everything: an empty registry (a cold data dir lists empty, it does not error), and a
    // registry holding only some *other* project's live session.
    assert_eq!(gc_live_session_refusal(Ok(Vec::new()), &project), None);
    assert_eq!(
        gc_live_session_refusal(Ok(vec![session("/home/u/other")]), &project),
        None
    );
}

/// The inline-flake keep-set is read for one purpose: deciding which `sbx-flake-<name>` roots
/// `sbx gc --prune` drops. A dropped root means the build is collected, so the question it must
/// answer is "is this flake still declared?", never "is this project still trusted?" — reading
/// it off the trusted-only provisioning filter meant a single edit to `sbx.toml` (which turns
/// every package `Changed` until re-approved) presented as a wholesale removal, and the next
/// prune threw away builds the config still asks for.
#[test]
fn a_lapse_in_trust_does_not_look_like_a_removed_inline_flake() {
    use crate::config::{Backend, Package};
    use crate::trust::TrustState;

    let inline = |name: &str, state| Package {
        name: name.to_string(),
        backend: Backend::FlakeInline {
            content: "{ outputs = _: {}; }".to_string(),
            attr: "default".to_string(),
        },
        state,
        libs: Vec::new(),
    };

    let declared = vec![
        inline("trusted-one", TrustState::Trusted),
        inline("edited-one", TrustState::Changed),
        inline("never-approved", TrustState::Untrusted),
        // A `nix:` package roots as a data-dir out-link, not as `sbx-flake-<name>`; including
        // it here would make the prune keep a root that this set does not own.
        Package {
            name: "ripgrep".to_string(),
            backend: Backend::Nix("ripgrep".to_string()),
            state: TrustState::Trusted,
            libs: Vec::new(),
        },
    ];

    assert_eq!(
        inline_flake_gcroot_names(&declared),
        vec![
            "trusted-one".to_string(),
            "edited-one".to_string(),
            "never-approved".to_string(),
        ],
        "every declared inline flake keeps its root, whatever its trust; nothing else is in \
         this set"
    );

    // A flake actually removed from the config is absent — which is what makes the prune work
    // at all, and what stops this test being satisfiable by keeping everything.
    assert!(
        !inline_flake_gcroot_names(&declared[..1]).contains(&"edited-one".to_string()),
        "a flake no longer declared is a removal, and its root is dropped"
    );
}

/// Nothing a cage's environment carries may reach bubblewrap's **argument list**:
/// `/proc/<pid>/cmdline` is mode `444`, so every uid on the machine could read it for as long as
/// the cage runs, while `/proc/<pid>/environ` is `400`. Measured on a live invocation before
/// this existed — the sentinel was sitting there next to `--setenv`.
///
/// This asserts on the production function, so the property holds for whatever a spec is built
/// from rather than for one hand-written argv.
#[test]
fn no_variable_reaches_the_world_readable_argument_list() {
    use std::io::Read;
    const SENTINEL: &str = "s3nt1nel-v4lue-xyz";
    const WRITTEN: &str = "hardcoded-in-a-config";

    let spec = SandboxSpec::new(
        PathBuf::from("/w"),
        Vec::new(),
        vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("API_TOKEN".to_string(), WRITTEN.to_string()),
        ],
        NetPolicy::Isolated,
        vec![OsString::from("/bin/true")],
    )
    .expect("spec")
    .with_secret_env(vec![("PGPASSWORD".to_string(), SENTINEL.to_string())]);

    let (argv, files) = seccomp_argv(&spec).expect("argv");
    let flat: Vec<String> = argv
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    for hidden in [SENTINEL, WRITTEN] {
        assert!(
            !flat.iter().any(|a| a.contains(hidden)),
            "no value may be in the argument list: {flat:?}"
        );
    }
    for name in ["PGPASSWORD", "API_TOKEN"] {
        assert!(
            !flat.iter().any(|a| a == name),
            "nor a name, which would say which variable to go and read: {flat:?}"
        );
    }
    assert!(
        !flat.iter().any(|a| a == "--setenv"),
        "the whole environment travels on the descriptor: {flat:?}"
    );

    // It reaches bwrap on a descriptor instead, spliced where the placeholder was — after
    // `--clearenv`, which would otherwise wipe everything it sets.
    let at = flat.iter().position(|a| a == "--args").expect("--args");
    let fd: i32 = flat[at + 1]
        .parse()
        .expect("a descriptor number, not the placeholder");
    assert!(
        flat.iter()
            .position(|a| a == "--clearenv")
            .expect("--clearenv")
            < at,
        "spliced before the clear, its variables would be wiped: {flat:?}"
    );

    let mut carried = String::new();
    files
        .iter()
        .find(|f| f.as_raw_fd() == fd)
        .expect("the descriptor the argv names is one of the files kept alive")
        .try_clone()
        .expect("clone")
        .read_to_string(&mut carried)
        .expect("read");
    // Credentials first, so a variable named after the cage's own plumbing wins over one that
    // took its name. bwrap reads NUL-separated arguments.
    assert_eq!(
        carried,
        format!(
            "--setenv\0PGPASSWORD\0{SENTINEL}\0--setenv\0PATH\0/bin\0--setenv\0API_TOKEN\0{WRITTEN}\0"
        )
    );
}

/// A cage that sets no variables at all gains no descriptor — an unused mechanism leaves no
/// trace to explain.
#[test]
fn a_spec_with_no_environment_gains_no_descriptor() {
    let spec = SandboxSpec::new(
        PathBuf::from("/w"),
        Vec::new(),
        Vec::new(),
        NetPolicy::Isolated,
        vec![OsString::from("/bin/true")],
    )
    .expect("spec");
    let (argv, _files) = seccomp_argv(&spec).expect("argv");
    assert!(
        !argv.iter().any(|a| a == "--args"),
        "an unused mechanism must leave no trace in the argv"
    );
}

/// The project root reaches the control-plane pin computation, which is the whole point: it is
/// bound read-write structurally rather than as a config bind, so it used to be invisible here
/// — and `cd ~ && sbx run` then handed the cage sbx's own data dir, trust store and global
/// config read-write with nothing pinning them.
#[test]
fn the_project_root_is_one_of_the_binds_the_control_plane_is_pinned_against() {
    let tmp = crate::testutil::TmpDir::new();
    let project = tmp.path().join("work");
    std::fs::create_dir_all(&project).expect("project dir");

    let declared = vec![crate::config::Bind {
        path: PathBuf::from("/srv/data"),
        writable: true,
    }];
    let sources = pin_sources(&declared, &project);

    assert!(
        sources.iter().any(|b| b.path == Path::new("/srv/data")),
        "the declared binds still reach the pins: {sources:?}"
    );
    let canon = std::fs::canonicalize(&project).expect("the project exists");
    let entry = sources
        .iter()
        .find(|b| b.path == canon)
        .expect("the project root is among the pin sources");
    assert!(
        entry.writable,
        "it has to be read-write to be pinned at all — `control_plane_pins` only walks writable binds"
    );
}

/// And it arrives canonicalized, because the roots it is tested for containment against are.
///
/// A symlinked component would otherwise mean the project never looks like it contains anything.
#[test]
fn the_project_root_is_canonicalized_before_it_is_pinned_against() {
    let tmp = crate::testutil::TmpDir::new();
    let real = tmp.path().join("real-home");
    std::fs::create_dir_all(&real).expect("real dir");
    let link = tmp.path().join("via-link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let sources = pin_sources(&[], &link);
    let only = sources.last().expect("the project is always pushed");
    assert_eq!(
        only.path,
        std::fs::canonicalize(&real).expect("canonical real"),
        "the symlink was carried through instead of being resolved: {sources:?}"
    );
}

#[test]
fn establish_control_plane_pins_creates_each_pin_and_preserves_its_mode() {
    // A pin's host path is created (so a not-yet-existent control-plane root is present to be
    // frozen) and turned into a same-path extra bind that carries the pin's mode: a read-write
    // intermediate, a read-only leaf.
    let tmp = TmpDir::new();
    let inter = tmp.path().join("chain/intermediate");
    let leaf = tmp.path().join("chain/intermediate/root");
    let pins = vec![
        crate::config::Bind {
            path: inter.clone(),
            writable: true,
        },
        crate::config::Bind {
            path: leaf.clone(),
            writable: false,
        },
    ];
    let binds = establish_control_plane_pins(&pins).expect("pins establish");
    assert!(inter.is_dir() && leaf.is_dir(), "each pin path is created");
    assert_eq!(binds.len(), 2);
    assert_eq!(binds[0].src, inter);
    assert_eq!(binds[0].dest, inter);
    assert!(binds[0].writable, "the intermediate is read-write");
    assert_eq!(binds[1].dest, leaf);
    assert!(!binds[1].writable, "the leaf is read-only");
}

#[test]
fn establish_control_plane_pins_fails_closed_when_a_pin_cannot_be_created() {
    // If a pin's path cannot be established (here a file sits where a parent directory must be),
    // the helper errors rather than returning a partial set — so the launch aborts instead of
    // running with the containing read-write bind left unprotected. The failure names the path.
    let tmp = TmpDir::new();
    let blocker = tmp.path().join("blocker");
    std::fs::write(&blocker, b"a file, not a directory").unwrap();
    let pins = vec![crate::config::Bind {
        // Under a regular file, so `create_dir_all` cannot succeed.
        path: blocker.join("root"),
        writable: false,
    }];
    let err = establish_control_plane_pins(&pins).expect_err("a blocked pin must fail closed");
    assert!(
        err.to_string().contains("blocker"),
        "the failure names the unestablishable path: {err}"
    );
}

#[test]
fn mise_transitions_extracts_the_version_rolls_from_captured_output() {
    // The exact shape a captured (non-TTY) `mise upgrade` produces: the `X → Y` summary goes to
    // stdout under an "Upgraded N tool:" header, the install/uninstall progress to stderr — this
    // fixture concatenates both, as `run_captured` does. Only the transition line is surfaced.
    let captured = "\
\nUpgraded 1 tool:\n  shfmt 3.7.0 → 3.13.1\n\
mise shfmt@3.13.1    [1/2] install\n\
mise shfmt@3.13.1  ✓ installed\n\
mise uninstall shfmt@3.7.0 ✓ done\n";
    assert_eq!(mise_transitions(captured), vec!["shfmt 3.7.0 → 3.13.1"]);

    // A group that rolls several tokens surfaces one transition line each; the full-token form
    // (as an `aqua:`/`pipx:` roll prints) is kept verbatim.
    let multi = "\
Upgraded 2 tools:\n  aqua:example/demo-tool 0.144.4 → 0.144.5\n  pipx:demo-agent 2.20.0 → 2.21.0\n";
    assert_eq!(
        mise_transitions(multi),
        vec![
            "aqua:example/demo-tool 0.144.4 → 0.144.5",
            "pipx:demo-agent 2.20.0 → 2.21.0"
        ]
    );

    // No roll (the progress/equip preamble carries no ` → `) → nothing surfaced, so the caller
    // falls through to the up-to-date / generic branch.
    let none =
        "mise ~/.config/mise/config.toml tools: npm:demo-tool@3.0.40\nadded 3 packages in 617ms\n";
    assert!(mise_transitions(none).is_empty());
}

#[test]
fn mise_up_to_date_detects_the_no_op_roll() {
    // mise prints this to stderr when a roll finds every tool already current.
    assert!(mise_up_to_date("mise All tools are up to date\n"));
    assert!(!mise_up_to_date(
        "Upgraded 1 tool:\n  shfmt 3.7.0 → 3.13.1\n"
    ));
}

/// The `sbx upgrade` report never replays the cage's bytes unfiltered.
///
/// `run_captured` hands back the combined output of a process that ran *inside* the cage:
/// mise's own lines, and through its registry/`aqua:`/`npm:` backends whatever third-party
/// installer it fetched and ran. The report interleaves those with sbx's own trust warnings and
/// failure verdicts on the operator's terminal, so a CSI erase among them rewrites what sbx
/// just said and an OSC-52 sequence writes to the operator's clipboard. Both readers of that
/// buffer — the roll's transition summary and the failure dump — have to filter it, which is
/// the doctrine [`crate::sandbox::sanitize`] states and `mise_token_display` already applies to
/// the sibling announcement.
#[test]
fn the_upgrade_report_cannot_be_rewritten_by_the_bytes_the_cage_printed() {
    // A rolled version carrying an erase sequence and a forged line behind it.
    let captured = "Upgraded 1 tool:\n  aqua:example/demo 1.0 → 2.0\u{1b}[2K\rsbx: trusted\n";
    let rolled = mise_transitions(captured);
    assert_eq!(rolled.len(), 1);
    assert!(
        !rolled[0].contains('\u{1b}') && !rolled[0].contains('\r'),
        "a control character reached the roll line: {:?}",
        rolled[0]
    );
    // Filtered, not truncated: the version delta a reader came for survives intact.
    assert!(rolled[0].starts_with("aqua:example/demo 1.0 → 2.0"));

    // The failure dump is the wider surface — there every captured line reaches the terminal.
    let dumped = cage_output_line("mise \u{1b}]52;c;cGF5bG9hZA==\u{7}installed");
    assert!(
        !dumped.contains('\u{1b}') && !dumped.contains('\u{7}'),
        "a control character reached the failure dump: {dumped:?}"
    );
    assert!(dumped.starts_with("       mise "));
}

/// A captured cage run bounds what it keeps without bounding what it reads.
///
/// `sbx upgrade` is the one path that reads a cage's output into the supervisor's own memory.
///
/// Reading it to EOF with no ceiling — which `Command::output()` does — makes that memory a
/// function of what the cage chooses to print, and the cgroup limits do not cover it: they
/// govern the transient scope the cage runs in, not the sbx process reading it. So the keep has
/// to be capped. It must not be capped by *stopping*, though: a reader that stopped at the cap
/// would leave the cage blocked writing into a full pipe and never exiting, which is the hang
/// the cap exists to prevent.
#[test]
fn a_captured_run_bounds_what_it_keeps_without_leaving_the_cage_blocked_on_a_full_pipe() {
    let flood = vec![b'A'; 1024 * 1024];
    let mut src = std::io::Cursor::new(flood.clone());
    let (kept, cut) = drain_capped(&mut src, 4096);
    assert_eq!(kept.len(), 4096, "only the cap is kept");
    assert!(cut, "the caller is told the output was cut");
    assert_eq!(
        src.position(),
        flood.len() as u64,
        "the stream is still drained to EOF, so the cage is never blocked on a full pipe"
    );

    // Under the cap nothing is lost and nothing is reported as cut.
    let mut small = std::io::Cursor::new(b"ok\n".to_vec());
    let (kept, cut) = drain_capped(&mut small, 4096);
    assert_eq!(kept, b"ok\n".to_vec());
    assert!(!cut);
}

#[test]
fn mise_roll_recap_names_what_rolled_and_tallies_the_rest() {
    // The headline case: two advanced out of many — the recap names them and tallies the
    // untouched majority, so "what is concerned?" reads at a glance. No noun on the count: the
    // names are usually apps, but the task tool pool rolls under this same recap and is not one.
    assert_eq!(
        mise_roll_recap(&["demo-app".into(), "other-app".into()], 15, 0, 0),
        "2 rolled: demo-app, other-app (15 up to date)."
    );
    // Nothing advanced, everything current — collapse to one reassuring line, not "0 rolled".
    assert_eq!(mise_roll_recap(&[], 17, 0, 0), "all 17 up to date.");
    // A mixed tally (skips + failures) still surfaces.
    assert_eq!(
        mise_roll_recap(&["demo-app".into()], 0, 1, 2),
        "1 rolled: demo-app (1 skipped, 2 failed)."
    );
    // Nothing rolled but not a clean no-op — say what got in the way.
    assert_eq!(
        mise_roll_recap(&[], 10, 2, 1),
        "nothing rolled (10 up to date, 2 skipped, 1 failed)."
    );
    // Degenerate empty run (no groups reached the loop).
    assert_eq!(mise_roll_recap(&[], 0, 0, 0), "nothing to roll.");
}

#[test]
fn session_runtime_maps_each_launch_runtime_to_its_owned_form() {
    // The owned record runtime `sbx session attach` reads back must mirror the launch-side runtime, so
    // an app session is reproduced in the app's home rather than the project's default.
    assert_eq!(
        session_runtime(binds::Runtime::ProjectDefault),
        session::SessionRuntime::Project
    );
    assert_eq!(
        session_runtime(binds::Runtime::GlobalApp("demo-app")),
        session::SessionRuntime::GlobalApp("demo-app".to_string())
    );
    assert_eq!(
        session_runtime(binds::Runtime::ProjectApp("agent")),
        session::SessionRuntime::ProjectApp("agent".to_string())
    );
}

#[test]
fn session_verb_confirmations_are_plain_text_when_uncolored() {
    // A plain palette must leave every confirmation byte-for-byte plain, so a captured stream
    // (and the existing `sbx session stop --all` substring assertion) stays unchanged.
    let p = crate::style::Palette::plain();
    let grace = Duration::from_secs(10);
    assert_eq!(
        render_attaching(4242, "app:demo-app", &p),
        "sbx: attaching to session 4242 (app:demo-app) \
         (a shell in its live cage — type `exit` to leave the agent running)"
    );
    assert_eq!(
        render_no_active_sessions(&p),
        "sbx session stop: no active sessions to stop."
    );
    assert_eq!(
        render_gui_stop_hint("demo-app", 4242, &p),
        "sbx: demo-app is graphical — press Ctrl+C twice here to quit (closing its window may only \
         hide it — a tray app keeps running); `sbx session stop 4242` also stops it."
    );
    assert_eq!(
        render_stop_outcome(4242, "run", &session::StopOutcome::Terminated, grace, &p),
        "sbx session stop: stopped session 4242 (run)."
    );
    assert_eq!(
        render_stop_outcome(
            7,
            "app:agent",
            &session::StopOutcome::AlreadyGone,
            grace,
            &p
        ),
        "sbx session stop: session 7 (app:agent) had already exited."
    );
    assert_eq!(
        render_stop_outcome(9, "shell", &session::StopOutcome::Killed, grace, &p),
        "sbx session stop: session 9 (shell) did not exit within 10s — sent SIGKILL."
    );
    // A refused handle must not read like the no-op above: it names the reason and says the
    // session may still be running, because nothing was signalled.
    assert_eq!(
        render_stop_outcome(
            11,
            "app:agent",
            &session::StopOutcome::NotSignalled(libc::EINVAL),
            grace,
            &p
        ),
        "sbx session stop: cannot stop session 11 (app:agent): Invalid argument (os error 22) \
         — it was not signalled and may still be running."
    );
}

#[test]
fn a_stop_that_left_something_running_outranks_an_id_that_matched_nothing() {
    // Nothing wrong is a plain success; an id that named no live session is the long-standing
    // 2; a session the host refused a handle on is 1 — and when both happened in one run it is
    // still 1, because a cage that may still be up is what the caller has to act on.
    assert_eq!(stop_exit_code(false, false), 0);
    assert_eq!(stop_exit_code(false, true), 2);
    assert_eq!(stop_exit_code(true, false), 1);
    assert_eq!(stop_exit_code(true, true), 1);
}

#[test]
fn a_stop_that_signalled_nothing_keeps_the_session_record() {
    // The reap is what makes `sbx session ls` clean the moment a stop lands. Applied to a stop
    // that did *not* land, it would delete the only handle on a cage that is still up: the
    // session would vanish from every listing and no second `sbx session stop <pid>` could
    // name it. So the record survives exactly one outcome, and this test is the contrast —
    // same call, same registry, two records that differ only in why their pid has no handle.
    let data = TmpDir::new();
    let reg = session::Registry::at(data.path());
    let pal = crate::style::Palette::plain();
    let sessions = data.path().join("sessions");
    let record_at = |pid: u32| session::Session {
        project: PathBuf::from("/work/probe"),
        pid,
        start_ticks: 1,
        kind: session::Kind::Run,
        runtime: session::SessionRuntime::Project,
        detached: false,
    };
    let count = || {
        std::fs::read_dir(&sessions)
            .map(|d| d.filter_map(Result::ok).count())
            .unwrap_or(0)
    };

    // Pid 0 is not a pid a process can hold: `pidfd_open` refuses it with `EINVAL`, which says
    // nothing about a process being alive — the stop reports it and keeps the record.
    let refused = record_at(0);
    reg.register(&refused).unwrap();
    assert!(!stop_session(&reg, &refused, Duration::from_secs(0), &pal));
    assert_eq!(count(), 1, "an unsignalled session must stay addressable");

    // A pid above the kernel's ceiling cannot exist, so the same call answers `ESRCH` — truly
    // gone — and the record goes with it.
    let gone = record_at(1 << 30);
    reg.register(&gone).unwrap();
    assert!(stop_session(&reg, &gone, Duration::from_secs(0), &pal));
    assert_eq!(count(), 1, "only the unsignalled record is left");
}

#[test]
fn launch_display_name_prefers_the_app_then_the_program_basename() {
    // An `sbx app` launch names the app; a plain `sbx run` into a GUI project names the
    // program by its basename (never a store path); an empty command falls back cleanly.
    assert_eq!(
        launch_display_name(&binds::Runtime::GlobalApp("demo-app"), &[]),
        "demo-app"
    );
    assert_eq!(
        launch_display_name(&binds::Runtime::ProjectApp("agent"), &[]),
        "agent"
    );
    let cmd = vec![
        OsString::from("/nix/store/abc-foo/bin/foo"),
        OsString::from("--flag"),
    ];
    assert_eq!(
        launch_display_name(&binds::Runtime::ProjectDefault, &cmd),
        "foo"
    );
    assert_eq!(
        launch_display_name(&binds::Runtime::ProjectDefault, &[]),
        "the app"
    );
}

#[test]
fn session_verb_confirmations_color_their_outcome_and_identifier_spans() {
    // The hue carries the meaning: a clean stop is a real change (green), a forced kill is the
    // caution hue (yellow), a stop that could not happen is the error hue (red), a no-op is
    // dim, and an identifier is cyan. The verb of an attach announcement stays plain (it is not
    // a completed state change).
    let p = crate::style::Palette::colored();
    let grace = Duration::from_secs(10);

    let stopped = render_stop_outcome(4242, "run", &session::StopOutcome::Terminated, grace, &p);
    assert!(stopped.contains(&format!("{}stopped{}", p.ok, p.reset)));
    assert!(stopped.contains(&format!("{}4242{}", p.name, p.reset)));

    let gone = render_stop_outcome(
        7,
        "app:agent",
        &session::StopOutcome::AlreadyGone,
        grace,
        &p,
    );
    assert!(gone.contains(&format!("{}had already exited{}", p.dim, p.reset)));

    let killed = render_stop_outcome(9, "shell", &session::StopOutcome::Killed, grace, &p);
    assert!(killed.contains(&format!("{}sent SIGKILL{}", p.warn, p.reset)));

    let refused = render_stop_outcome(
        11,
        "app:agent",
        &session::StopOutcome::NotSignalled(libc::EMFILE),
        grace,
        &p,
    );
    assert!(refused.contains(&format!("{}cannot stop{}", p.err, p.reset)));
    // Not the dim of a no-op: this one did not happen, it is not a state that was already
    // reached.
    assert!(!refused.contains(&format!("{}cannot stop", p.dim)));

    let attach = render_attaching(4242, "app:demo-app", &p);
    assert!(attach.contains(&format!("{}4242{}", p.name, p.reset)));
    assert!(attach.contains(&format!("{}app:demo-app{}", p.name, p.reset)));
    // The announcement verb is not green — only a completed change earns that.
    assert!(!attach.contains(&format!("{}attaching", p.ok)));

    // The graphical stop hint colors only its app-name identifier (cyan) and names the pid.
    let hint = render_gui_stop_hint("demo-app", 4242, &p);
    assert!(hint.contains(&format!("{}demo-app{}", p.name, p.reset)));
    assert!(hint.contains("sbx session stop 4242"));

    assert!(render_no_active_sessions(&p).contains(p.dim));
}

/// A minimal resolved config carrying only the channel choices the builder reads.
///
/// A config whose only interesting fields are the two `nixpkgs` pins these tests vary.
fn resolved(global: Option<&str>, project: Option<&str>) -> crate::config::Resolved {
    let mut cfg = crate::testutil::resolved(vec![], vec![]);
    cfg.nixpkgs_global = global.map(String::from);
    cfg.nixpkgs_project = project.map(String::from);
    cfg
}

fn mise_pkg(name: &str, token: &str, trusted: bool) -> crate::config::Package {
    crate::config::Package {
        name: name.into(),
        backend: crate::config::Backend::Mise(token.into()),
        state: if trusted {
            crate::trust::TrustState::Trusted
        } else {
            crate::trust::TrustState::Untrusted
        },
        libs: Vec::new(),
    }
}

fn nix_pkg(name: &str, attr: &str) -> crate::config::Package {
    crate::config::Package {
        name: name.into(),
        backend: crate::config::Backend::Nix(attr.into()),
        state: crate::trust::TrustState::Trusted,
        libs: Vec::new(),
    }
}

fn app_overlay(
    cmd: &[&str],
    scope: crate::config::AppHomeScope,
    packages: Vec<crate::config::Package>,
) -> crate::config::ResolvedApp {
    crate::config::ResolvedApp {
        accepts_fresh_releases: Default::default(),
        provisions: Vec::new(),
        open: Default::default(),
        service: Default::default(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        cmd: cmd.iter().map(|s| s.to_string()).collect(),
        home_scope: scope,
        env: vec![],
        binds: vec![],
        packages,
        network: None,
        gui: None,
        gpu: None,
        allow_insecure_http: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        forward: vec![],
        secrets: vec![],
        tasks: vec![],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        allow_insecure_http_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward_origin: Default::default(),
        limits_origin: Default::default(),
        seccomp: Default::default(),
        seccomp_origin: Default::default(),
        devices: Vec::new(),
        devices_origin: Default::default(),
        proc: None,
        proc_origin: Default::default(),
        home_scope_origin: None,
        warnings: vec![],
    }
}

/// The roll's unit of work: only apps, only those whose bundles install, each in the home its
/// launch would use. A `provision` is a bundle's field and a bundle only folds into an app, so
/// unlike the `mise:` roll there is no project-baseline group to find here.
#[test]
fn provision_groups_takes_only_the_apps_whose_bundles_install() {
    use crate::config::{AppHomeScope, BundleProvision};
    let step = |bundle: &str| BundleProvision {
        bundle: bundle.into(),
        argv: vec!["bash".into(), "-c".into(), "install".into()],
    };
    let mut cfg = resolved(None, None);
    let mut apps = std::collections::BTreeMap::new();

    let mut installs = app_overlay(&["alpha"], AppHomeScope::Global, vec![]);
    installs.provisions = vec![step("alpha-bundle")];
    apps.insert("alpha".to_string(), installs);

    // Rides a backend: nothing to re-run.
    apps.insert(
        "beta".to_string(),
        app_overlay(&["beta"], AppHomeScope::Project, vec![]),
    );

    // Declares a step but has no command: never launchable, so nothing installs for it.
    let mut unlaunchable = app_overlay(&[], AppHomeScope::Global, vec![]);
    unlaunchable.provisions = vec![step("ghost")];
    apps.insert("gamma".to_string(), unlaunchable);

    // Two bundles that install, in `use` order, in a per-project home.
    let mut two = app_overlay(&["delta"], AppHomeScope::Project, vec![]);
    two.provisions = vec![step("first"), step("second")];
    apps.insert("delta".to_string(), two);
    cfg.apps = apps;

    let groups = provision_groups(&cfg, None);
    assert_eq!(groups.len(), 2, "only alpha and delta install");
    assert!(matches!(&groups[0].home, GroupHome::GlobalApp(n) if n == "alpha"));
    assert_eq!(groups[0].steps.len(), 1);
    assert!(matches!(&groups[1].home, GroupHome::ProjectApp(n) if n == "delta"));
    assert_eq!(
        groups[1].steps.len(),
        2,
        "both bundles' steps, in use order"
    );
    assert_eq!(step_bundles(&groups[1].steps), "first, second");
    // A bundle named twice contributes one name to the line, not two.
    assert_eq!(step_bundles(&[step("dup"), step("dup")]), "dup");

    // `--app <name>` narrows the roll to that app's cage and takes nothing else with it.
    let only = provision_groups(&cfg, Some("delta"));
    assert_eq!(only.len(), 1, "the selector takes one app, not two");
    assert!(matches!(&only[0].home, GroupHome::ProjectApp(n) if n == "delta"));
    assert_eq!(only[0].steps.len(), 2, "that app keeps all of its steps");
    // A name the selector matches but that has nothing to roll still yields no group here; the
    // CLI is what refuses it by name, so this stays a plain filter.
    assert!(provision_groups(&cfg, Some("beta")).is_empty());
    assert!(provision_groups(&cfg, Some("nope")).is_empty());
}

/// The roll runs the install and stops there: chaining the app's command onto it would make a
/// version roll a launch. The steps are quoted for the same reason the launch quotes them.
#[test]
fn an_install_roll_runs_the_steps_alone_and_never_the_app() {
    use crate::config::BundleProvision;
    let steps = vec![
        BundleProvision {
            bundle: "alpha".into(),
            argv: vec!["bash".into(), "-c".into(), "first $HOME".into()],
        },
        BundleProvision {
            bundle: "beta".into(),
            argv: vec!["installer".into(), "it's here".into()],
        },
    ];
    let cmd = provision_only_cmd(&steps);
    assert_eq!(cmd[0], OsString::from("bash"));
    assert_eq!(cmd[1], OsString::from("-c"));
    let script = cmd[2].to_string_lossy().to_string();
    assert!(
        !script.contains("exec"),
        "the app's command must not be chained on: {script}"
    );
    assert!(
        script.contains("'first $HOME'") && script.contains(r#"'it'\''s here'"#),
        "each argument stays data, not shell syntax: {script}"
    );
    assert_eq!(
        script.matches("&&").count(),
        1,
        "two steps, one `&&` — a failed step stops the chain: {script}"
    );
    assert_eq!(cmd.len(), 4, "a label for $0 and nothing positional");
}

#[test]
fn the_install_roll_recap_names_what_ran_and_tallies_the_rest() {
    assert_eq!(
        provision_roll_recap(&["trae".to_string(), "odysseus".to_string()], 0, 0),
        "re-installed: trae, odysseus"
    );
    assert_eq!(
        provision_roll_recap(&[], 2, 1),
        "nothing re-installed · 2 skipped · 1 failed"
    );
}

#[test]
fn mise_package_groups_covers_the_baseline_and_each_app_generically() {
    use crate::config::AppHomeScope;
    let mut cfg = resolved(None, None);
    cfg.packages = vec![
        mise_pkg("other-tool", "other-tool", true),
        nix_pkg("jq", "jq"), // a nix package is not a mise token
        mise_pkg("evil", "aqua:attacker/x", false), // untrusted: dropped
    ];
    let mut apps = std::collections::BTreeMap::new();
    // An app with its own mise: package, in a shared (global) home.
    apps.insert(
        "alpha".to_string(),
        app_overlay(
            &["alpha"],
            AppHomeScope::Global,
            vec![mise_pkg("foo", "aqua:foo", true)],
        ),
    );
    // An app with only a nix: package — no mise: group.
    apps.insert(
        "beta".to_string(),
        app_overlay(
            &["beta"],
            AppHomeScope::Project,
            vec![nix_pkg("rg", "ripgrep")],
        ),
    );
    // An app with a mise: package but no command — never launchable, so skipped.
    apps.insert(
        "gamma".to_string(),
        app_overlay(
            &[],
            AppHomeScope::Global,
            vec![mise_pkg("g", "aqua:g", true)],
        ),
    );
    cfg.apps = apps;

    let groups = mise_package_groups(&cfg, None);
    // Three groups: the project baseline plus each launchable app — beta inherits the
    // baseline `mise:` tool (an app's cage equips both layers), so even a nix-only app gets
    // a group. gamma has no command, so it is skipped.
    assert_eq!(groups.len(), 3);

    // The baseline group rolls only the trusted mise token, in the default home.
    let base = &groups[0];
    assert!(matches!(base.home, GroupHome::ProjectDefault));
    assert_eq!(base.tokens, vec!["other-tool".to_string()]);

    // alpha rolls in its own (global) home; its tokens are the merged set (baseline + app).
    let alpha = groups
        .iter()
        .find(|g| matches!(&g.home, GroupHome::GlobalApp(n) if n == "alpha"))
        .expect("alpha has a global-home group");
    assert!(alpha.tokens.contains(&"other-tool".to_string()));
    assert!(alpha.tokens.contains(&"aqua:foo".to_string()));

    // beta rolls in its own per-project home, inheriting only the baseline mise tool.
    let beta = groups
        .iter()
        .find(|g| matches!(&g.home, GroupHome::ProjectApp(n) if n == "beta"))
        .expect("beta inherits the baseline mise tool in its per-project home");
    assert_eq!(beta.tokens, vec!["other-tool".to_string()]);

    // The command-less app produced no group.
    assert!(!groups.iter().any(|g| g.home.label().contains("gamma")));

    // `--app <name>` narrows to that app's cage AND drops the project baseline, which is not
    // an app: keeping it would make a per-app flag roll project-wide work. The app's own group
    // still carries the merged token set, since its cage equips both layers.
    let only = mise_package_groups(&cfg, Some("alpha"));
    assert_eq!(only.len(), 1, "one app, and no baseline group beside it");
    assert!(matches!(&only[0].home, GroupHome::GlobalApp(n) if n == "alpha"));
    assert!(only[0].tokens.contains(&"other-tool".to_string()));
    assert!(only[0].tokens.contains(&"aqua:foo".to_string()));
    assert!(mise_package_groups(&cfg, Some("gamma")).is_empty());
    assert!(mise_package_groups(&cfg, Some("nope")).is_empty());

    // The withheld count follows the selector: a roll narrowed to one app must not report a
    // package withheld from a different one, or the line contradicts what the roll just did.
    // The fixture's untrusted `mise:` package is the project baseline's, which every app's
    // cage folds in — so it counts for an app, and once, not once per app.
    assert_eq!(withheld_mise_packages(&cfg, None), 1);
    assert_eq!(withheld_mise_packages(&cfg, Some("alpha")), 1);
    assert_eq!(
        withheld_mise_packages(&cfg, Some("nope")),
        0,
        "a name no app carries withholds nothing"
    );
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
        &resolved(None, None),
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
        &resolved(Some("nixos-23.11"), None),
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

    let target = effective_lock_target(proj.path(), &layout, &resolved(None, Some(REV)), None)
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
        &resolved(None, None),
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
        &resolved(Some(REV), None),
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
        &resolved(None, Some(REV)),
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
fn keep_passthrough_drops_bare_c_locale_but_keeps_real_ones() {
    let out = keep_passthrough([
        ("TERM".to_string(), "xterm".to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "fr_FR.UTF-8".to_string()),
    ]);
    // TERM always passes; a bare `C` LANG is dropped so it cannot break the UTF-8 floor;
    // a real locale is kept
    assert!(out.iter().any(|(k, v)| k == "TERM" && v == "xterm"));
    assert!(!out.iter().any(|(k, _)| k == "LANG"));
    assert!(out.iter().any(|(k, v)| k == "LC_ALL" && v == "fr_FR.UTF-8"));

    // `POSIX` is dropped too (case-insensitive), while `C.UTF-8` — a real UTF-8 locale — passes
    let out = keep_passthrough([
        ("LC_ALL".to_string(), "posix".to_string()),
        ("LANG".to_string(), "C.UTF-8".to_string()),
    ]);
    assert!(!out.iter().any(|(k, _)| k == "LC_ALL"));
    assert!(out.iter().any(|(k, v)| k == "LANG" && v == "C.UTF-8"));
}

// The in-cage task client is a script, so the programs its shebang and its body name must be the
// ones the CAGE resolves. Naming the host's would produce a client that cannot run where it is
// bound — and the tests that exercise the client run it with the host's, so this is what pins
// the shipped pairing.
#[test]
fn the_task_client_is_written_against_the_cages_own_programs() {
    let userland = Userland {
        base_roots: vec![],
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
    let (bash, socat, head) = task_client_programs(&userland);
    assert_eq!(bash, PathBuf::from("/nix/store/bash/bin/bash"));
    assert_eq!(socat, PathBuf::from("/nix/store/socat/bin/socat"));
    assert_eq!(
        head,
        PathBuf::from("/nix/store/coreutils/bin/head"),
        "`head` comes from the same coreutils the cage already has"
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

/// Every program a wrap's preamble execs is pinned read-only, from sbx's own store.
///
/// The exec-enforcement shim is the innermost wrap, so each preamble around it runs before any
/// filter exists. Those preambles name absolute paths in `/nix` — the project's own store,
/// bound read-write — so without these pins in-cage code replaces `bash`, `socat`, `mise`,
/// `nix` or the loader they all run under, and its replacement is the cage's first process,
/// unfiltered by the `[proc]` policy and the `[fs] scan` lens the launch reports as active.
///
/// What the pin has to get right is all three of: the whole store path (not the file, whose
/// directory would stay renameable), read-only, and sourced from the **shared** store — a pin
/// taken from the project's copy would freeze a trojan already planted there.
#[test]
fn the_programs_every_wrap_preamble_execs_are_pinned_read_only_from_the_shared_store() {
    let userland = Userland {
        base_roots: vec![],
        interp_src: PathBuf::from("/store/nix-ld"),
        interp_dest: PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
        ca_bundle_src: PathBuf::from("/store/cacert/etc/ssl/certs/ca-bundle.crt"),
        base_loader: PathBuf::from("/nix/store/hash-glibc/lib/ld-linux-x86-64.so.2"),
        foreign_lib_paths: vec![],
        bin_paths: vec![],
        shell_bin: PathBuf::from("/nix/store/hash-bash/bin/bash"),
        env_bin: PathBuf::from("/nix/store/hash-coreutils/bin/env"),
        socat_bin: PathBuf::from("/nix/store/hash-socat/bin/socat"),
        mise_bin: PathBuf::from("/nix/store/hash-mise/bin/mise"),
        nix_bin: PathBuf::from("/nix/store/hash-nix/bin/nix"),
        locale_archive: PathBuf::from("/nix/store/hash-locales/lib/locale/locale-archive"),
        zoneinfo_src: PathBuf::from("/nix/store/hash-tzdata/share/zoneinfo"),
    };
    let layout = crate::store::Layout::under(Path::new("/data/sbx"));
    // The two GUI holes contribute a preamble program each; they exist only under
    // `gui = "wayland"`, so they arrive as an explicit list rather than on `Userland`.
    let certutil = PathBuf::from("/nix/store/hash-nss-tools/bin/certutil");
    let dbus = PathBuf::from("/nix/store/hash-dbus/bin/dbus-daemon");
    let gui_programs = [certutil.as_path(), dbus.as_path()];
    let pins = plumbing_pins(&userland, &gui_programs, &layout);

    for program in [
        &userland.shell_bin,
        &userland.socat_bin,
        &userland.mise_bin,
        &userland.nix_bin,
        &userland.base_loader,
        &certutil,
        &dbus,
    ] {
        let pin = pins
            .iter()
            .find(|b| program.starts_with(&b.dest))
            .unwrap_or_else(|| panic!("{} is left on the writable store", program.display()));
        assert!(
            !pin.writable,
            "{} is pinned writable, which pins nothing",
            pin.dest.display()
        );
        assert_ne!(
            &pin.dest, program,
            "the pin must cover the whole store path, not just the binary: a writable \
             directory around it can be renamed aside and rebuilt with a forged binary"
        );
        assert_eq!(
            pin.src,
            PathBuf::from("/data/sbx/store/nix/store").join(pin.dest.file_name().unwrap()),
            "the pinned bytes must come from sbx's own store, not the project's copy"
        );
    }

    // Seven distinct store paths, so no pin is dropped by the de-duplication that keeps a
    // shared root from being mounted twice — and a launch with no GUI hole pins only the five
    // every posture runs.
    assert_eq!(pins.len(), 7);
    assert_eq!(plumbing_pins(&userland, &[], &layout).len(), 5);

    // A path that does not resolve through the store is not a store path and must not be
    // mounted over — the pin set is derived, never assumed.
    assert_eq!(store_root_of(Path::new("/opt/sbx/proc-shim")), None);
    assert_eq!(store_root_of(Path::new("/nix/store")), None);
}

#[test]
fn egress_ca_overrides_the_structural_cacert() {
    // The assembler upserts the overlay env on last-occurrence, so the winner for a key is
    // its last entry in this layering. Under a network allowlist the cage must trust the
    // egress proxy's per-session CA, not sbx's root bundle: egress is layered after cacert,
    // so it wins. A trusted config, layered last, still has the final say (self-harm only).
    let winner = |env: &[(String, String)]| {
        env.iter()
            .rev()
            .find(|(k, _)| k == "SSL_CERT_FILE")
            .map(|(_, v)| v.clone())
    };

    let cacert = || {
        vec![(
            "SSL_CERT_FILE".to_string(),
            "/etc/ssl/certs/ca-bundle.crt".to_string(),
        )]
    };
    let egress = || {
        vec![(
            "SSL_CERT_FILE".to_string(),
            "/opt/sbx/egress-ca.pem".to_string(),
        )]
    };

    let env = extra_cage_env(vec![
        (EnvLayer::Cacert, cacert()),
        (EnvLayer::Egress, egress()),
    ]);
    assert_eq!(
        winner(&env).as_deref(),
        Some("/opt/sbx/egress-ca.pem"),
        "egress CA must override the structural cacert"
    );

    let cfg = vec![("SSL_CERT_FILE".to_string(), "/cfg/ca.pem".to_string())];
    let env = extra_cage_env(vec![
        (EnvLayer::Cacert, cacert()),
        (EnvLayer::Egress, egress()),
        (EnvLayer::Config, cfg),
    ]);
    assert_eq!(
        winner(&env).as_deref(),
        Some("/cfg/ca.pem"),
        "a trusted config has the final say over the CA"
    );

    // with no egress (shared/isolated posture) the structural cacert stands
    let env = extra_cage_env(vec![(EnvLayer::Cacert, cacert())]);
    assert_eq!(
        winner(&env).as_deref(),
        Some("/etc/ssl/certs/ca-bundle.crt"),
        "without egress the hermetic cacert is the trust anchor"
    );
}

/// The nesting is the enum's, not the order the blocks in `build` happen to run in.
///
/// Each marker wrap prepends its own name, so the composed argv reads outermost first — which is
/// also the order the preambles run in. Registering them shuffled and still getting that order
/// is what the layer tag buys: the four constraints below used to hold only because their blocks
/// The composed startup is what the wraps nest around, not a peer of it.
///
/// `build` takes a `&Prepared`, so no unit test can reach it, and this ordering lives nowhere
/// else: [`wrap_cage_command`] cannot tell a bare command from a composed one, and every test of
/// [`compose_startup_cmd`] hands it a `cmd` directly. So the check is on the source, the way the
/// cage-suite and docs guards are, because the alternative is no check at all.
///
/// What it protects is not a style preference. An install step finishes making the command
/// runnable, so it needs everything the command needs. Composed *after* the wraps it ran outside
/// every layer: before the mise equip lanes, so a step asking `mise where` about a package found
/// nothing and aborted the launch before the equip that would have installed it; and before the
/// egress forwarder, so a step that downloads got `https_proxy` pointed at a port with nothing
/// listening. Measured on three shipped bundles whose step does exactly that.
#[test]
fn the_wraps_nest_around_the_composed_startup_and_not_the_bare_command() {
    // The whole file is production code now that the tests live in this sibling, so no cut is
    // needed to keep the tests' own calls to these helpers out of the search.
    let body = include_str!("../launch.rs");
    let compose = body
        .find("compose_startup_cmd(&prep.cfg.provisions")
        .expect("`build` composes the startup from the resolved provisions");
    let wrap = body
        .find("wrap_cage_command(startup_cmd, wraps)")
        .expect("`build` nests the wraps around the composed startup, by that name");
    assert!(
        compose < wrap,
        "`build` applies its wraps at byte {wrap} and composes the startup at {compose}: the \
         composition has moved back outside the nesting, so every bundle's install step runs \
         before the mise equip lanes and before the egress forwarder is up"
    );
    // The bare command must no longer be wrapped anywhere: a second call site would reinstate
    // the old order for whichever branch reached it first.
    assert!(
        !body.contains("wrap_cage_command(cmd, wraps)"),
        "`build` still wraps the bare command somewhere, so a launch can take the old order"
    );
}

/// sat in the right places, hundreds of lines apart, and nothing checked it.
#[test]
fn the_wraps_nest_by_layer_however_the_blocks_registered_them() {
    let marker = |name: &'static str| -> CommandWrap<'static> {
        Box::new(move |cmd: Vec<OsString>| {
            let mut out = vec![OsString::from(name)];
            out.extend(cmd);
            out
        })
    };

    // Deliberately not in layer order, and with the two mise lanes registered in the order
    // `build` registers them: lane 2 (`install`) then lane 1 (`use -g`).
    let wraps = vec![
        (WrapLayer::Portal, marker("portal")),
        (WrapLayer::MiseEquip, marker("mise-install")),
        (WrapLayer::Egress, marker("egress")),
        (WrapLayer::ProcEnforce, marker("proc")),
        (WrapLayer::MiseEquip, marker("mise-use-g")),
        (WrapLayer::CaTrust, marker("catrust")),
        (WrapLayer::FlakeEquip, marker("flake")),
        (WrapLayer::Forward, marker("forward")),
    ];
    let out = wrap_cage_command(vec![OsString::from("the-command")], wraps);

    assert_eq!(
        out,
        [
            "portal",
            "catrust",
            "egress",
            "forward",
            "flake",
            "mise-use-g",
            "mise-install",
            "proc",
            "the-command",
        ]
        .map(OsString::from)
    );
}

/// A launch that contributes nothing runs its command bare — no preamble, no shell.
#[test]
fn a_launch_with_no_wraps_leaves_the_command_untouched() {
    let cmd = vec![OsString::from("jq"), OsString::from("--version")];
    assert_eq!(wrap_cage_command(cmd.clone(), vec![]), cmd);
}

/// The precedence is the enum's, not the caller's. Listing the layers backwards must produce
/// exactly the same environment as listing them in order — that is the whole reason the sources
/// carry a tag instead of riding an argument list, where two of them swapped would compile in
/// silence and change which CA the cage trusts.
#[test]
fn the_layer_decides_precedence_not_the_order_the_caller_lists_them_in() {
    let key = "SSL_CERT_FILE".to_string();
    let in_order = vec![
        (EnvLayer::Passthrough, vec![(key.clone(), "/host".into())]),
        (EnvLayer::Cacert, vec![(key.clone(), "/hermetic".into())]),
        (EnvLayer::Egress, vec![(key.clone(), "/mitm".into())]),
        (EnvLayer::Config, vec![(key.clone(), "/cfg".into())]),
    ];
    let mut backwards = in_order.clone();
    backwards.reverse();

    assert_eq!(extra_cage_env(in_order.clone()), extra_cage_env(backwards));
    assert_eq!(
        extra_cage_env(in_order).last().map(|(_, v)| v.clone()),
        Some("/cfg".to_string()),
        "the config layer stays last however the caller lists it"
    );
}

/// A caller contributing one layer in two pieces must keep the pieces in the order it gave
/// them: within a layer there is no precedence to derive, so only a stable sort is correct.
#[test]
fn two_pieces_of_one_layer_keep_the_order_they_were_given() {
    let env = extra_cage_env(vec![
        (EnvLayer::Gui, vec![("WAYLAND_DISPLAY".into(), "a".into())]),
        (
            EnvLayer::Cacert,
            vec![("SSL_CERT_FILE".into(), "ca".into())],
        ),
        (EnvLayer::Gui, vec![("WAYLAND_DISPLAY".into(), "b".into())]),
    ]);
    let seen: Vec<&str> = env
        .iter()
        .filter(|(k, _)| k == "WAYLAND_DISPLAY")
        .map(|(_, v)| v.as_str())
        .collect();
    assert_eq!(seen, ["a", "b"]);
}

#[test]
fn auto_equip_tokens_formats_non_nix_tools_and_ignores_trust() {
    // no mise file → nothing to equip
    assert!(auto_equip_tokens(&resolved(None, None)).is_empty());

    // a mise file mixing a `nix:` tool (host-provisioned), a backend-prefixed tool, and a
    // plain registry tool: only the non-`nix:` ones become `token@version` install specs.
    // The state is Untrusted on purpose — auto-equip is the open self-equip path, so it is
    // independent of the project's trust verdict (the egress allowlist is the control).
    let mut cfg = resolved(None, None);
    cfg.mise = Some(crate::config::MiseConfig {
        name: "mise.toml".into(),
        state: crate::trust::TrustState::Untrusted,
        files: vec![(
            "mise.toml".into(),
            b"[tools]\n\"nix:jq\" = \"latest\"\n\"aqua:BurntSushi/ripgrep\" = \"latest\"\nnode = \"20\"\n"
                .to_vec(),
        )],
    });
    assert_eq!(
        auto_equip_tokens(&cfg),
        vec![
            "aqua:BurntSushi/ripgrep@latest".to_string(),
            "node@20".to_string(),
        ]
    );
}

/// A detached session's trust-drop note is redacted against the launch's credential set, and
/// that set lives behind an `RwLock` whose only other reader is the notifier's delivery thread.
/// A panic there poisons the lock, and this reader used to take it with `read().ok()` — which
/// mapped "poisoned" onto `None`, the branch that writes the warning **unredacted**, into a log
/// file that outlives the session. The one event most likely to leave a half-populated needle
/// set behind would have been the event that stopped redacting against it, so recover the set
/// instead: what a panicking holder had already put there still names real credentials.
#[test]
fn a_poisoned_needle_set_still_redacts_the_trust_drop_note() {
    use crate::sandbox::proxy::SecretNeedle;
    use std::sync::{Arc, RwLock};

    let secret = "hunter2-actual-token";
    let warning = format!("project: dropped `network.allow` (token {secret}) — run `sbx trust`");
    let needles: crate::sandbox::notify_sink::Needles =
        Arc::new(RwLock::new(vec![SecretNeedle::named(
            "TOKEN",
            secret.as_bytes().to_vec(),
        )]));

    // Poison it exactly as a panic on the delivery thread would.
    let poisoner = Arc::clone(&needles);
    let _ = std::thread::spawn(move || {
        let _guard = poisoner.write().unwrap();
        panic!("delivery thread died holding the needle set");
    })
    .join();
    assert!(
        needles.read().is_err(),
        "the lock is poisoned for this reader"
    );

    let notes = trust_drop_notes(std::slice::from_ref(&warning), Some(&needles));
    assert_eq!(notes.len(), 1, "the trust drop is still recorded");
    assert!(
        !notes[0].contains(secret),
        "a poisoned lock must not fall back to writing the secret verbatim: {}",
        notes[0]
    );
    // Redacted, not discarded — the reader still learns which field was dropped and how to
    // get it back, or the note would be worthless.
    assert!(notes[0].contains("`network.allow`") && notes[0].contains("`sbx trust`"));

    // And with no wiring at all there is nothing to redact against, so the note goes out as
    // the terminal already had it — this guard must not be satisfiable by blanking everything.
    assert_eq!(
        trust_drop_notes(std::slice::from_ref(&warning), None),
        vec![warning.clone()]
    );
    // A warning that is not a trust drop is not noted here at all.
    assert!(
        trust_drop_notes(&["project: some other warning".to_string()], Some(&needles)).is_empty()
    );
}

/// `wrap_mise_equip` already proves a hostile `.mise.toml` token cannot inject *shell*. The
/// other end of the same token is the launching terminal, which reads escapes: the two launch
/// messages that name these tools printed them verbatim, so a `[tools]` key of
/// `"x\u{1b}[2K\rsbx: trusted"` — a quoted TOML key is an arbitrary string — could erase the
/// trust warnings sbx had just printed above it and write a reassuring line of its own. The
/// terminal is where sbx says what it dropped and why; a repo must not be able to edit that.
#[test]
fn a_hostile_mise_token_cannot_rewrite_the_launching_terminal() {
    let tokens = [
        "node@22".to_string(),
        "x\u{1b}[2K\rsbx: project trusted\n@1.0".to_string(),
    ];
    let shown = mise_token_display(tokens.iter());

    assert!(
        !shown.contains('\u{1b}') && !shown.contains('\r') && !shown.contains('\n'),
        "no escape, carriage return or newline may reach the terminal: {shown:?}"
    );
    assert!(
        !shown.chars().any(char::is_control),
        "and nothing else the terminal acts on either: {shown:?}"
    );
    // The forged text itself is left visible rather than dropped — the reader should see the
    // token the project actually declared, only stripped of the bytes that move the cursor.
    assert!(shown.contains("sbx: project trusted"));

    // And an ordinary declaration is untouched, or this guard would be satisfied by mangling
    // every token: the message has to stay readable for the tools people really declare.
    assert!(shown.starts_with("node@22, "));
    assert_eq!(
        mise_token_display(["aqua:BurntSushi/ripgrep@latest".to_string()].iter()),
        "aqua:BurntSushi/ripgrep@latest"
    );
}

#[test]
fn wrap_autoequip_passes_tokens_and_command_positionally() {
    // The install tokens and the real command both ride `"$@"`, so a token from an
    // untrusted project config can never inject shell: only the absolute mise path and
    // the integer count ever reach the script string.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec![
        "aqua:BurntSushi/ripgrep@latest".to_string(),
        // a hostile token must stay a single positional arg, never reach the script
        "node@20; rm -rf /".to_string(),
    ];
    let cmd = vec![OsString::from("demo-app"), OsString::from("--print")];

    let argv = wrap_mise_equip(&mise, &bash, "install", &tokens, None, cmd);

    assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
    assert_eq!(argv[1], OsString::from("-c"));
    let script = argv[2].to_string_lossy();
    // mise by absolute path; the slice/shift use the count, not the tokens; the command
    // is exec'd (so it stays the cage's main process) after the tokens are shifted off.
    assert!(script.contains("/nix/store/mise/bin/mise install \"${@:1:2}\""));
    assert!(script.contains("shift 2;"));
    assert!(script.trim_end().ends_with("exec \"$@\""));
    assert!(
        !script.contains("rm -rf"),
        "a hostile token must never be interpolated into the script: {script}"
    );
    // label, then the tokens, then the command — all positional
    assert_eq!(argv[3], OsString::from("sbx-mise-equip"));
    assert_eq!(argv[4], OsString::from("aqua:BurntSushi/ripgrep@latest"));
    assert_eq!(argv[5], OsString::from("node@20; rm -rf /"));
    assert_eq!(argv[6], OsString::from("demo-app"));
    assert_eq!(argv[7], OsString::from("--print"));
}

#[test]
fn wrap_mise_equip_uses_the_global_verb_for_app_packages() {
    // The app's `[packages] mise:` tools are equipped globally (`mise use -g`), so the verb
    // is interpolated literally (an sbx-chosen constant, never config) while the token stays
    // positional — proving the same no-shell-injection shape for the global lane.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let cmd = vec![OsString::from("demo-app")];

    let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, None, cmd);

    let script = argv[2].to_string_lossy();
    assert!(script.contains("/nix/store/mise/bin/mise use -g \"${@:1:1}\""));
    assert!(script.contains("shift 1;"));
    // no data-dir override: the equip runs under the ambient primary
    assert!(!script.contains("MISE_DATA_DIR="));
    // the token is a positional arg, never in the script
    assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
    assert_eq!(argv[5], OsString::from("demo-app"));
}

/// The launch freezes a `mise:` package at its installed version and the roll is what moves it.
/// Both halves are needed and each breaks the other's guarantee when removed, so they are
/// asserted together rather than one per test.
#[test]
fn a_mise_package_is_pinned_at_equip_and_only_a_bump_roll_moves_it() {
    // Equip: the resolved version is written into the cage's config. Without this the config
    // keeps the floating request, the tool's mise shim re-resolves it on every exec, and the
    // app stops launching as soon as upstream publishes a version the pool does not hold.
    assert!(
        MISE_EQUIP_VERB.contains("--pin"),
        "the equip must pin, or a launch re-resolves: {MISE_EQUIP_VERB}"
    );
    assert!(
        MISE_EQUIP_VERB.starts_with("use -g"),
        "the app lane equips globally: {MISE_EQUIP_VERB}"
    );

    // Roll: an exact pin is a range a plain `mise upgrade` treats as already satisfied, so
    // without `--bump` the shipped roll would report every tool up to date and move nothing.
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];

    let plain = mise_upgrade_cmd(binds::Runtime::ProjectDefault, &mise, &bash, &tokens);
    assert_eq!(plain[1], OsString::from("upgrade"));
    assert_eq!(
        plain[2],
        OsString::from("--bump"),
        "a pinned tool only advances with --bump"
    );
    assert_eq!(plain[3], OsString::from("aqua:example/demo-tool"));

    // The same on the global-app lane, where the roll runs through a shell to pin the pool.
    let global = mise_upgrade_cmd(binds::Runtime::GlobalApp("demo-app"), &mise, &bash, &tokens);
    assert!(
        global[2]
            .to_string_lossy()
            .contains("upgrade --bump \"$@\""),
        "the global lane bumps too: {}",
        global[2].to_string_lossy()
    );
}

/// What the launch says it is about to do is what it does.
///
/// The announcement carried a hand-written copy of the verb, so it kept saying `mise use -g`
/// after the equip started pinning: a reader who reproduced the printed command by hand got a
/// floating install and no hint that the two had parted. Reading both from one constant is the
/// fix; this holds it there.
#[test]
fn the_equip_line_names_the_invocation_it_runs() {
    let line = equip_announcement(&[
        "aqua:example/demo-tool".to_string(),
        "npm:demo-cli".to_string(),
    ]);

    assert!(
        line.contains(&format!("mise {MISE_EQUIP_VERB}:")),
        "the printed verb must be the one the equip uses: {line}"
    );
    // The tools are named too, and separately: this line is how a user learns which package a
    // slow launch is fetching.
    assert!(
        line.contains("aqua:example/demo-tool, npm:demo-cli"),
        "{line}"
    );
}

#[test]
fn wrap_mise_equip_pins_the_app_global_data_dir_for_the_global_lane() {
    // For a global app, Lane-1 `mise use -g` is pinned to the app-global home pool so the app
    // tool installs there (shared across projects, read by `sbx app show`/`gc`) while the
    // ambient primary stays the per-project pool. The pin applies to the equip step only — the
    // exec'd command keeps the ambient value — and the value is single-quoted (injection-safe,
    // an sbx-owned fixed path).
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let cmd = vec![OsString::from("demo-app")];
    let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

    let argv = wrap_mise_equip(&mise, &bash, "use -g", &tokens, Some(&data_dir), cmd);

    let script = argv[2].to_string_lossy();
    // the equip's MISE_DATA_DIR is pinned to the app-global home, single-quoted, before mise
    assert!(
        script.contains(&format!(
            "MISE_DATA_DIR='{data_dir}' /nix/store/mise/bin/mise use -g"
        )),
        "the global lane must pin the app-global data dir: {script}"
    );
    // the pin is only on the equip command, not the exec'd command
    assert!(script.trim_end().ends_with("exec \"$@\""));
    // the token still rides positionally
    assert_eq!(argv[4], OsString::from("aqua:example/demo-tool"));
}

#[test]
fn mise_upgrade_cmd_pins_the_app_global_pool_only_for_a_global_app() {
    // `sbx upgrade mise` rolls `[packages] mise:` tools, which for a global app live in the
    // app-global home pool. The cage's ambient primary for a global app is the per-project pool
    // (the split), which does not hold them, so the roll must be pinned to the app-global pool —
    // else `mise upgrade` finds nothing and silently rolls nothing (a shipped-command regression).
    let mise = PathBuf::from("/nix/store/mise/bin/mise");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let tokens = vec!["aqua:example/demo-tool".to_string()];
    let data_dir = crate::sandbox::binds::mise_app_global_data_dir();

    // global app: pinned to the app-global pool via a bash MISE_DATA_DIR prefix
    let g = mise_upgrade_cmd(binds::Runtime::GlobalApp("cc"), &mise, &bash, &tokens);
    assert_eq!(g[0], OsString::from("/nix/store/bash/bin/bash"));
    let script = g[2].to_string_lossy();
    assert!(
        script.contains(&format!(
            "MISE_DATA_DIR='{data_dir}' exec /nix/store/mise/bin/mise upgrade"
        )),
        "the global-app roll must pin the app-global data dir: {script}"
    );
    assert_eq!(g[4], OsString::from("aqua:example/demo-tool")); // token positional

    // sbx run / a per-project app: single pool (the ambient primary), plain unwrapped command
    for rt in [
        binds::Runtime::ProjectDefault,
        binds::Runtime::ProjectApp("cc"),
    ] {
        let c = mise_upgrade_cmd(rt, &mise, &bash, &tokens);
        assert_eq!(c[0], OsString::from("/nix/store/mise/bin/mise"));
        assert_eq!(c[1], OsString::from("upgrade"));
        // `--bump` sits between the verb and the tokens on this lane too: the launch pins the
        // config at the installed version, and a pinned range is one a plain roll would call
        // already satisfied.
        assert_eq!(c[2], OsString::from("--bump"));
        assert_eq!(c[3], OsString::from("aqua:example/demo-tool"));
    }
}

#[test]
fn wrap_flake_equip_passes_quads_and_command_positionally() {
    // Each (ref, target, good, key) rides `"$@"`, so a value from an untrusted-but-trusted-app
    // config can never inject shell: only the absolute nix path, the out-link parent, and the
    // integer quad count reach the script string. The per-quad build, the good-out-link
    // promotion, the fallback branch, the `<target>.failed` marker, and the host-resolvable gc
    // root (keyed by package name, the `$key` positional, never interpolated) are all present.
    let nix = PathBuf::from("/nix/store/nix/bin/nix");
    let bash = PathBuf::from("/nix/store/bash/bin/bash");
    let dir = PathBuf::from("/home/sandbox/.local/state/sbx/flake");
    let quads = vec![
        (
            "github:example/flake-tool#tui".to_string(),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool-rev"),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/flake-tool"),
            "flake-tool".to_string(),
        ),
        // a hostile ref must stay a single positional arg, never reach the script
        (
            "github:evil/x#bin; rm -rf /".to_string(),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil-rev"),
            PathBuf::from("/home/sandbox/.local/state/sbx/flake/evil"),
            "evil".to_string(),
        ),
    ];
    let cmd = vec![OsString::from("flake-tool"), OsString::from("-z")];

    let argv = wrap_flake_equip(&nix, &bash, &dir, &quads, cmd);

    assert_eq!(argv[0], OsString::from("/nix/store/bash/bin/bash"));
    assert_eq!(argv[1], OsString::from("-c"));
    let script = argv[2].to_string_lossy();
    // nix by absolute path; the quad count drives the loop, not the refs; the command is exec'd
    // after the quads are shifted.
    assert!(script.contains("n=2"));
    assert!(script.contains(
        "'/nix/store/nix/bin/nix' build \"$ref\" --no-write-lock-file --out-link \"$target\""
    ));
    assert!(script.contains("mkdir -p '/home/sandbox/.local/state/sbx/flake'"));
    // the fallback machinery: the per-revision failed-marker, the promotion of the good
    // out-link on success, and the loud notice when a pinned build fails.
    assert!(script.contains("touch \"$target.failed\""));
    assert!(script.contains("ln -sfn \"$sp\" \"$good\""));
    assert!(script.contains("falling back to the last good build"));
    assert!(script.contains("there is no prior build to fall back to"));
    // the gc root is keyed by the `$key` positional (the package name), targeting the used
    // build's store path resolved by `readlink -f` — host-resolvable, overwritten each launch
    assert!(script.contains("ln -sfn \"$sp\" \"/nix/var/nix/gcroots/sbx-flake-$key\""));
    assert!(script.contains("shift 4"));
    assert!(script.trim_end().ends_with("exec \"$@\""));
    assert!(
        !script.contains("rm -rf"),
        "a hostile ref must never be interpolated into the script: {script}"
    );
    // label, then interleaved (ref, target, good, key) quads, then the command — all positional
    assert_eq!(argv[3], OsString::from("sbx-flake-equip"));
    assert_eq!(argv[4], OsString::from("github:example/flake-tool#tui"));
    assert_eq!(
        argv[5],
        OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool-rev")
    );
    assert_eq!(
        argv[6],
        OsString::from("/home/sandbox/.local/state/sbx/flake/flake-tool")
    );
    assert_eq!(argv[7], OsString::from("flake-tool"));
    assert_eq!(argv[8], OsString::from("github:evil/x#bin; rm -rf /"));
    assert_eq!(
        argv[9],
        OsString::from("/home/sandbox/.local/state/sbx/flake/evil-rev")
    );
    assert_eq!(
        argv[10],
        OsString::from("/home/sandbox/.local/state/sbx/flake/evil")
    );
    assert_eq!(argv[11], OsString::from("evil"));
    assert_eq!(argv[12], OsString::from("flake-tool"));
    assert_eq!(argv[13], OsString::from("-z"));
}

/// Write `body` to `path` as an executable file (a stub used to drive the flake-equip script).
#[cfg(test)]
fn write_exec(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

#[test]
fn wrap_flake_equip_falls_back_to_the_last_good_build_when_a_pinned_build_fails() {
    // The headline of the fallback feature, run for real: when the content-keyed build
    // fails, the launch must run the last good build instead of breaking — and must not
    // re-attempt the doomed build on the next launch (the `<target>.failed` marker).
    let tmp = crate::testutil::TmpDir::new();
    let flake = tmp.path().join("flake");
    std::fs::create_dir_all(&flake).unwrap();

    // A `nix` that always fails the build, recording each call so we can prove the marker
    // stops the second attempt.
    let calls = tmp.path().join("nixcalls");
    let fake_nix = tmp.path().join("nix");
    write_exec(
        &fake_nix,
        &format!("#!/bin/sh\necho call >> '{}'\nexit 1\n", calls.display()),
    );

    // A pre-existing good build (the previous version) the fallback resolves to.
    let good_store = tmp.path().join("goodstore");
    std::fs::create_dir_all(good_store.join("bin")).unwrap();
    let good = flake.join("tool");
    std::os::unix::fs::symlink(&good_store, &good).unwrap();
    let target = flake.join("tool-deadbeef"); // content-keyed, does not exist

    let quads = vec![(
        "github:o/tool#default".to_string(),
        target.clone(),
        good.clone(),
        "tool".to_string(),
    )];
    // The command the wrap execs once equip is done — reaching it proves we did NOT exit 1.
    let cmd = vec![OsString::from("echo"), OsString::from("FELL-BACK")];
    let argv = wrap_flake_equip(&fake_nix, &PathBuf::from("bash"), &flake, &quads, cmd);

    let run = || {
        std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .expect("run the flake-equip script")
    };

    // First launch: build fails → fall back to the good build, exec the command, mark the failure.
    let out1 = run();
    assert!(out1.status.success(), "must fall back, not exit 1");
    assert!(
        String::from_utf8_lossy(&out1.stdout).contains("FELL-BACK"),
        "the command must run off the good build after a failed pinned build"
    );
    assert!(
        String::from_utf8_lossy(&out1.stderr).contains("falling back to the last good build"),
        "the fallback must be announced loudly on stderr"
    );
    assert!(
        flake.join("tool-deadbeef.failed").exists(),
        "a failed pinned build must be marked so it is not re-attempted every launch"
    );
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap().lines().count(),
        1,
        "the failing build is attempted exactly once"
    );

    // Second launch: the marker short-circuits the doomed rebuild — still falls back, no new call.
    let out2 = run();
    assert!(out2.status.success());
    assert!(String::from_utf8_lossy(&out2.stdout).contains("FELL-BACK"));
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap().lines().count(),
        1,
        "the marker must stop a second attempt at the same failing revision"
    );
}

#[test]
fn wrap_flake_equip_hard_fails_when_a_build_fails_and_no_good_build_exists() {
    // With no prior good build to fall back to, a failed build is a hard error (exit 1) — the
    // app cannot run, and that must surface, not be masked.
    let tmp = crate::testutil::TmpDir::new();
    let flake = tmp.path().join("flake");
    std::fs::create_dir_all(&flake).unwrap();
    let fake_nix = tmp.path().join("nix");
    write_exec(&fake_nix, "#!/bin/sh\nexit 1\n");

    let good = flake.join("tool"); // does NOT exist
    let target = flake.join("tool-deadbeef");
    let quads = vec![(
        "github:o/tool#default".to_string(),
        target,
        good,
        "tool".to_string(),
    )];
    let cmd = vec![OsString::from("echo"), OsString::from("SHOULD-NOT-RUN")];
    let argv = wrap_flake_equip(&fake_nix, &PathBuf::from("bash"), &flake, &quads, cmd);

    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .expect("run the flake-equip script");
    assert!(!out.status.success(), "no good build → must hard-fail");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("SHOULD-NOT-RUN"),
        "the command must not run when there is nothing to fall back to"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("no prior build to fall back to"));
}

#[test]
fn net_policy_maps_the_config_posture_to_the_cage_posture() {
    // the cheap, total map between the two posture vocabularies — the one place
    // a `network = "none"` config becomes an isolated cage.
    assert_eq!(
        net_policy(&crate::config::NetworkPolicy::Shared),
        NetPolicy::Shared
    );
    assert_eq!(
        net_policy(&crate::config::NetworkPolicy::Isolated),
        NetPolicy::Isolated
    );
    // an allowlist posture maps to an isolated (empty) namespace by design — the Model-B
    // foundation: the cage's only egress is the bound socket to the host filtering proxy,
    // never the shared host network.
    assert_eq!(
        net_policy(&crate::config::NetworkPolicy::Allowlist(
            crate::allowlist::EgressPolicy::default()
        )),
        NetPolicy::Isolated
    );
}

#[test]
fn resolve_wayland_hole_binds_the_socket_file_never_the_runtime_dir() {
    // The load-bearing invariant of the GUI hole: a relative display resolves under
    // XDG_RUNTIME_DIR to the socket *file*, never the runtime directory — which also holds the
    // dbus session bus, pulse, and the gpg/ssh agents a directory bind would leak.
    let (socket, env) = resolve_wayland_hole(Some("wayland-0"), Some("/run/user/1000")).unwrap();
    assert_eq!(socket, PathBuf::from("/run/user/1000/wayland-0"));
    assert_ne!(
        socket,
        PathBuf::from("/run/user/1000"),
        "the bind target must be the socket file, never the runtime directory"
    );
    assert_eq!(socket.file_name().unwrap(), "wayland-0");
    assert!(env.contains(&("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string())));
    assert!(env.contains(&("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string())));

    // An absolute display is the socket path verbatim (XDG_RUNTIME_DIR is not needed to
    // locate it, per the Wayland convention).
    let (socket, env) = resolve_wayland_hole(Some("/tmp/wl.sock"), Some("/run/user/1000")).unwrap();
    assert_eq!(socket, PathBuf::from("/tmp/wl.sock"));
    assert!(env.contains(&("WAYLAND_DISPLAY".to_string(), "/tmp/wl.sock".to_string())));

    // No display, an empty display, or a relative display with no runtime dir cannot be
    // located → error, so the caller warns and runs without a display (fail-closed — it
    // never binds a wrong or guessed path).
    assert!(resolve_wayland_hole(None, Some("/run/user/1000")).is_err());
    assert!(resolve_wayland_hole(Some(""), Some("/run/user/1000")).is_err());
    assert!(resolve_wayland_hole(Some("wayland-0"), None).is_err());
}

#[test]
fn exec_refuses_a_private_tty_spec() {
    // a private-tty spec must go through the pty supervisor; exec-replace has
    // no pty to offer, so it must refuse *before* actually exec'ing anything.
    let spec = SandboxSpec::new(
        PathBuf::from("/work"),
        vec![],
        vec![],
        NetPolicy::Shared,
        vec![OsString::from("/bin/true")],
    )
    .unwrap()
    .with_private_tty();

    let err = exec(
        Path::new("/bin/true"),
        &spec,
        &super::super::cgroup::Limits::default(),
    );
    assert!(
        err.to_string().contains("pty supervisor"),
        "exec must refuse a private-tty spec; got: {err}"
    );
}

#[test]
fn detach_log_path_is_keyed_by_pid_under_logs() {
    // The daemon, the reporting parent and `sbx session logs` must agree on the log location;
    // all three derive it from the session pid, so this is the single source of that name.
    let path = detach_log_path(Path::new("/var/lib/sbx"), 4242);
    assert_eq!(path, PathBuf::from("/var/lib/sbx/logs/4242.log"));
}

#[test]
fn the_header_open_detach_log_writes_is_the_one_the_parser_reads() {
    // The writer/parser seam. Both halves live in this file precisely so a change to one is
    // caught here: a header the parser no longer recognises does not fail loudly, it makes
    // `sbx session logs` silently replay a *previous* session's output as the current one's.
    // So this drives the real writer and parses what actually landed on disk.
    let dir = crate::testutil::TmpDir::new();
    let path = dir.join("logs").join("nested.log");
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let file = open_detach_log(&path).expect("open the session log");
    drop(file);

    let bytes = std::fs::read(&path).expect("read the session log back");
    let first = bytes.split(|&b| b == b'\n').next().expect("a first line");
    let header = parse_session_header(first).expect("the written header must parse");
    assert_eq!(
        header.pid,
        std::process::id(),
        "the header must name the session whose output follows it"
    );
    assert!(
        header.started >= before,
        "started={} must be the wall clock at open (>= {before})",
        header.started
    );

    // Appending a second session's header is what a reused pid does; both must parse, so the
    // reader can tell the two apart rather than running them together.
    let file = open_detach_log(&path).expect("reopen the session log");
    drop(file);
    let bytes = std::fs::read(&path).expect("read back after the second open");
    let headers = bytes
        .split(|&b| b == b'\n')
        .filter_map(parse_session_header)
        .count();
    assert_eq!(headers, 2, "each open must mark its own session");
}

#[test]
fn a_detached_log_notes_the_trust_drops_and_nothing_else() {
    // The record that outlives the launching terminal a detached session is about to lose.
    // Three properties hold it up, and each fails silently if it breaks: only a trust drop is
    // noted, the warning survives verbatim (a reader has to be able to act on it), and a note
    // can never be read as a session boundary — which would hide every line before it.
    let dir = crate::testutil::TmpDir::new();
    let path = dir.join("logs").join("notes.log");
    let file = open_detach_log(&path).expect("open the session log");
    note_trust_drops(
        &file,
        &[
            ".sbx.toml: ignoring `gpu` posture (untrusted — run `sbx trust`)".to_string(),
            ".sbx.toml: ignoring malformed nixpkgs source `nope`".to_string(),
        ],
        None,
    );
    drop(file);

    let text = std::fs::read_to_string(&path).expect("read the session log back");
    assert!(
        text.contains(
            "=== sbx trust-drop: .sbx.toml: ignoring `gpu` posture \
             (untrusted — run `sbx trust`) ==="
        ),
        "the dropped security field must survive the terminal that announced it: {text}"
    );
    assert!(
        !text.contains("malformed nixpkgs"),
        "a warning that is not a trust drop is not this record's business: {text}"
    );

    let notes: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("=== sbx trust-drop: "))
        .collect();
    assert_eq!(notes.len(), 1, "one note per dropped field: {text}");
    for note in notes {
        assert!(
            parse_session_header(note.as_bytes()).is_none(),
            "a note must not read as a session boundary: {note}"
        );
    }

    // A pid the kernel reuses appends a second session to this same file, and each note must
    // land on its own session's side of the boundary. A reader shows only what follows the
    // last header, so a note written before it would be attributed to the session that ended.
    let file = open_detach_log(&path).expect("reopen the session log");
    note_trust_drops(
        &file,
        &[".sbx.toml: ignoring `forward` ports (untrusted — run `sbx trust`)".to_string()],
        None,
    );
    drop(file);

    let text = std::fs::read_to_string(&path).expect("read back after the second open");
    let shape: Vec<&str> = text
        .lines()
        .map(|l| {
            if parse_session_header(l.as_bytes()).is_some() {
                "header"
            } else if l.starts_with("=== sbx trust-drop: ") {
                "note"
            } else {
                "other"
            }
        })
        .collect();
    assert_eq!(
        shape,
        ["header", "note", "header", "note"],
        "each note must follow its own session's header: {text}"
    );
}

#[test]
fn a_session_header_needs_every_field_to_parse() {
    // A line an agent prints that merely resembles a header must not be taken for one, or its
    // output would be read as a session boundary and hide everything before it.
    assert!(parse_session_header(b"=== sbx session 12 started=99 ===").is_some());
    for lookalike in [
        &b"=== sbx session 12 started=later ==="[..],
        &b"=== sbx session twelve started=99 ==="[..],
        &b"=== sbx session 12 ==="[..],
        &b"=== sbx session 12 started=99"[..],
        &b"plain agent output"[..],
    ] {
        assert!(
            parse_session_header(lookalike).is_none(),
            "must not parse: {}",
            String::from_utf8_lossy(lookalike)
        );
    }
}

/// The C strings an `attach_argv` result carries, as UTF-8 for assertion.
fn argv_strings(argv: &[CString]) -> Vec<String> {
    argv.iter()
        .map(|c| c.to_str().unwrap().to_string())
        .collect()
}

#[test]
fn attach_argv_with_no_command_is_the_interactive_rc_shell() {
    // A bare attach reuses the same rc shell as an interactive `sbx run`, so the joined shell gets mise
    // activation and the `(sbx-<slug>)` prompt.
    let argv = attach_argv(&[]).expect("shell argv builds");
    assert_eq!(
        argv_strings(&argv),
        vec![
            binds::SANDBOX_BASH.to_string(),
            "--rcfile".to_string(),
            binds::SHELL_RC_INCAGE.to_string(),
        ]
    );
}

#[test]
fn install_steps_run_in_order_ahead_of_the_command_and_stop_the_chain_on_failure() {
    // The composition is what makes a bundle's install step reach a launch, and three
    // properties of it are the contract: the steps run in the order they were folded, the app's
    // command runs last and as `exec` (so the app keeps the process, its signals and its exit
    // status), and `&&` joins them so a step that fails never reaches the command.
    let steps = vec![
        crate::config::BundleProvision {
            bundle: "alpha".into(),
            argv: vec!["bash".into(), "-c".into(), "first-step".into()],
        },
        crate::config::BundleProvision {
            bundle: "beta".into(),
            argv: vec!["second-step".into()],
        },
    ];
    let cmd: Vec<OsString> = ["agent", "--flag"].iter().map(OsString::from).collect();

    let out = compose_startup_cmd(&steps, &Default::default(), &[], cmd);
    let script = out[2].to_string_lossy().to_string();
    assert_eq!(out[0], OsString::from("bash"));
    assert_eq!(out[1], OsString::from("-c"));
    assert!(
        script.starts_with("'bash' '-c' 'first-step' && 'second-step' || exit $?\n"),
        "steps run in fold order, each still its own argv, and a failure ends the launch: \
         {script}"
    );
    assert!(
        script.ends_with("exec \"$@\"\n"),
        "the app's command runs last, and as exec: {script}"
    );
    // The app's argv is positional, never pasted into the script: `$0` then the command.
    assert_eq!(
        out[3..],
        [
            OsString::from("sbx"),
            OsString::from("agent"),
            OsString::from("--flag")
        ]
    );
}

#[test]
fn an_install_step_argument_is_data_not_shell_syntax() {
    // A step's own arguments reach the chaining shell as one word each, whatever they contain.
    // Without quoting, a step carrying a space would split into two commands and one carrying a
    // `$` or a backtick would be evaluated — a bundle author writing an argv would be writing
    // shell by accident.
    let steps = vec![crate::config::BundleProvision {
        bundle: "quoting".into(),
        argv: vec![
            "installer".into(),
            "--dir=/opt/a b".into(),
            "$(whoami)".into(),
            "it's".into(),
        ],
    }];
    let out = compose_startup_cmd(
        &steps,
        &Default::default(),
        &[],
        vec![OsString::from("agent")],
    );
    let script = out[2].to_string_lossy().to_string();
    assert!(
        script.starts_with("'installer' '--dir=/opt/a b' '$(whoami)' 'it'\\''s' || exit $?"),
        "every element is one quoted word, an interior quote closed and reopened: {script}"
    );
}

/// A `[service]` entry with just an argv, for the start-up composition tests.
fn service(argv: &[&str]) -> crate::config::ServiceSpec {
    crate::config::ServiceSpec {
        argv: argv.iter().map(|s| (*s).to_string()).collect(),
        enable: Vec::new(),
        ready: None,
    }
}

#[test]
fn a_service_starts_after_the_install_and_before_the_command() {
    // The order is the whole reason install steps and services are composed by one function: a
    // service started before the install that puts its program on PATH would fail on a first
    // launch, and nesting two wrappers would settle that order by accident.
    let steps = vec![crate::config::BundleProvision {
        bundle: "alpha".into(),
        argv: vec!["install-it".into()],
    }];
    let mut services = std::collections::BTreeMap::new();
    services.insert("chroma".to_string(), service(&["chroma", "run"]));

    let out = compose_startup_cmd(&steps, &services, &[], vec![OsString::from("agent")]);
    let script = out[2].to_string_lossy().to_string();
    let install = script.find("install-it").expect("the install step runs");
    let start = script.find("'chroma' 'run'").expect("the service starts");
    let exec = script.find("exec \"$@\"").expect("the command runs");
    assert!(
        install < start && start < exec,
        "install, then service, then command: {script}"
    );
    assert!(
        script.contains(
            "( 'chroma' 'run' ) >>\"${HOME:-/tmp}\"/.sbx-service-chroma.log 2>&1 </dev/null &"
        ),
        "a service is backgrounded with its output in its own log, off the app's terminal: \
         {script}"
    );
}

#[test]
fn a_failed_service_does_not_fail_the_launch_but_a_failed_install_does() {
    // The two are joined differently on purpose. An install that did not finish must never
    // reach the app (it would run against a half-equipped cage); a service that will not start
    // leaves a degraded app, which is the trade the hand-written `nohup` already made — and the
    // app is the thing the person asked for.
    let steps = vec![crate::config::BundleProvision {
        bundle: "alpha".into(),
        argv: vec!["install-it".into()],
    }];
    let mut services = std::collections::BTreeMap::new();
    services.insert("gateway".to_string(), service(&["gateway", "run"]));

    let script = compose_startup_cmd(&steps, &services, &[], vec![OsString::from("agent")])[2]
        .to_string_lossy()
        .to_string();
    assert!(
        script.contains("'install-it' || exit $?"),
        "the install chain ends the launch on failure: {script}"
    );
    let after_install = &script[script.find("|| exit $?").unwrap()..];
    assert!(
        !after_install.contains("exit $?") || after_install.matches("exit $?").count() == 1,
        "nothing after the install chain aborts the launch: {script}"
    );
}

#[test]
fn a_service_argument_is_data_except_a_leading_home_tilde() {
    // One expansion and one only. `~/` is expanded because a service is declared where the
    // home's path cannot be known; everything else stays the characters it was written as, or a
    // profile author writing an argv would be writing shell without meaning to.
    let mut services = std::collections::BTreeMap::new();
    services.insert(
        "chroma".to_string(),
        service(&["chroma", "--path", "~/chroma-data", "--tag", "$(whoami)"]),
    );

    let script = compose_startup_cmd(&[], &services, &[], vec![OsString::from("agent")])[2]
        .to_string_lossy()
        .to_string();
    assert!(
        script.contains("'--path' \"${HOME}\"/'chroma-data'"),
        "a leading `~/` becomes the cage's home, the rest still one quoted word: {script}"
    );
    assert!(
        script.contains("'$(whoami)'"),
        "a `$` is data, not a substitution: {script}"
    );
}

/// A `[service]` entry gated on an environment condition.
fn gated(argv: &[&str], var: &str, equals: bool, value: &str) -> crate::config::ServiceSpec {
    crate::config::ServiceSpec {
        argv: argv.iter().map(|s| (*s).to_string()).collect(),
        enable: vec![crate::config::EnvCondition {
            var: var.to_string(),
            equals,
            values: vec![value.to_string()],
        }],
        ready: None,
    }
}

#[test]
fn an_enable_condition_decides_before_the_script_is_written_not_inside_it() {
    // The runtime switch the field exists for: `--env NAME=value` turns a declared service off
    // for one launch, without editing the profile. It is answered against the environment this
    // launch composed — sbx builds that from a cleared one, so the answer is already known — and
    // a service that fails leaves no trace in the script at all, rather than a shell `if` around
    // a decision that was made before the shell existed.
    let mut services = std::collections::BTreeMap::new();
    services.insert("on-by-default".to_string(), gated(&["a"], "GW", false, "0"));
    services.insert("opt-in".to_string(), gated(&["b"], "EXTRA", true, "on"));

    // Nothing set: an unset variable compares as empty, which is what makes `!= 0` the on-by-
    // default form and `== on` the opt-in one, without anyone setting anything.
    let script = compose_startup_cmd(&[], &services, &[], vec![OsString::from("agent")])[2]
        .to_string_lossy()
        .to_string();
    assert!(
        script.contains("( 'a' )"),
        "`!= 0` is on by default: {script}"
    );
    assert!(
        !script.contains("( 'b' )"),
        "`== on` is off by default: {script}"
    );
    assert!(
        !script.contains("if ["),
        "no condition survives into the script: {script}"
    );

    // Both variables set to flip both conditions, as a `--env` pair would.
    let env = [
        ("GW".to_string(), "0".to_string()),
        ("EXTRA".to_string(), "on".to_string()),
    ];
    let script = compose_startup_cmd(&[], &services, &env, vec![OsString::from("agent")])[2]
        .to_string_lossy()
        .to_string();
    assert!(!script.contains("( 'a' )"), "`!= 0` is off now: {script}");
    assert!(script.contains("( 'b' )"), "`== on` is on now: {script}");
    assert!(
        script.ends_with("exec \"$@\"\n"),
        "a gated-out service changes nothing else about the launch: {script}"
    );
}

#[test]
fn a_list_of_conditions_is_an_and_and_one_failure_is_enough() {
    // What a list promises: every condition holds, or the service does not start. The failing
    // case is the one worth pinning, because a conjunction that started on a partial match
    // would be indistinguishable from an `or` on the profiles that use one condition.
    let mut services = std::collections::BTreeMap::new();
    services.insert(
        "svc".to_string(),
        crate::config::ServiceSpec {
            argv: vec!["daemon".into()],
            enable: vec![
                crate::config::EnvCondition {
                    var: "A".into(),
                    equals: false,
                    values: vec!["0".into()],
                },
                crate::config::EnvCondition {
                    var: "B".into(),
                    equals: true,
                    values: vec!["1".into()],
                },
            ],
            ready: None,
        },
    );
    let script = |env: &[(String, String)]| {
        compose_startup_cmd(&[], &services, env, vec![OsString::from("agent")])[2]
            .to_string_lossy()
            .to_string()
    };
    let set = |k: &str, v: &str| (k.to_string(), v.to_string());

    assert!(
        script(&[set("B", "1")]).contains("'daemon'"),
        "both hold (A unset compares as empty, which is not `0`)"
    );
    assert!(
        !script(&[]).contains("'daemon'"),
        "the second fails: B is unset, which is not `1`"
    );
    assert!(
        !script(&[set("A", "0"), set("B", "1")]).contains("'daemon'"),
        "the first fails, and one failure is enough"
    );
}

#[test]
fn a_repeated_environment_key_is_answered_with_the_value_the_cage_will_see() {
    // The launch upserts its environment layers in order, so a key set twice reaches the cage
    // with the LAST value. A condition answered from the first would gate on a value that was
    // overwritten before the cage ever started — the `--env` override being exactly the layer
    // that comes last.
    let mut services = std::collections::BTreeMap::new();
    services.insert("svc".to_string(), gated(&["a"], "GW", false, "0"));
    let env = [
        ("GW".to_string(), "1".to_string()),
        ("GW".to_string(), "0".to_string()),
    ];

    let script = compose_startup_cmd(&[], &services, &env, vec![OsString::from("agent")])[2]
        .to_string_lossy()
        .to_string();
    assert!(
        !script.contains("( 'a' )"),
        "the overriding value decides: {script}"
    );
}

#[test]
fn a_readiness_gate_waits_for_the_port_then_starts_the_app_regardless() {
    // The gate exists so the app does not race the service. It must not become a way for a slow
    // auxiliary process to prevent the app from running at all, so expiry is a message on
    // stderr and the launch goes on — which is what the hand-written probe it replaces did.
    let mut services = std::collections::BTreeMap::new();
    services.insert(
        "chroma".to_string(),
        crate::config::ServiceSpec {
            argv: vec!["chroma".into()],
            enable: Vec::new(),
            ready: Some(crate::config::ServiceReady {
                tcp: 8100,
                timeout: std::time::Duration::from_secs(15),
            }),
        },
    );

    let script = compose_startup_cmd(&[], &services, &[], vec![OsString::from("agent")])[2]
        .to_string_lossy()
        .to_string();
    assert!(
        script.contains("for _ in $(seq 1 30); do"),
        "the wait polls twice a second for the declared budget: {script}"
    );
    assert!(
        script.contains("if ( exec 3<>/dev/tcp/127.0.0.1/8100 ) 2>/dev/null; then"),
        "readiness is a TCP connect on the cage loopback, needing no extra tool: {script}"
    );
    assert!(
        script.contains("did not answer on port 8100 within 15s — starting anyway"),
        "expiry names the service and continues: {script}"
    );
    assert!(
        script.ends_with("exec \"$@\"\n"),
        "the command still runs after an expired gate: {script}"
    );
}

#[test]
fn attach_argv_with_a_command_runs_it_positionally_through_bash() {
    // The command is passed positionally after `bash -c 'exec "$@"' bash`, so bash resolves it
    // on the cage PATH and execs it in place — and no argument is ever interpreted as shell
    // syntax (the injection guard: a value like `; rm -rf /` is one literal argv element).
    let cmd = vec![
        OsString::from("grep"),
        OsString::from("-n"),
        OsString::from("; rm -rf /"),
    ];
    let argv = attach_argv(&cmd).expect("command argv builds");
    assert_eq!(
        argv_strings(&argv),
        vec![
            binds::SANDBOX_BASH.to_string(),
            "-c".to_string(),
            "exec \"$@\"".to_string(),
            "bash".to_string(),
            "grep".to_string(),
            "-n".to_string(),
            "; rm -rf /".to_string(),
        ]
    );
}

#[test]
fn attach_argv_rejects_a_command_argument_with_an_interior_nul() {
    // A NUL cannot be a C-string argument; it must fail closed rather than truncate the argv.
    use std::os::unix::ffi::OsStrExt;
    let cmd = vec![
        OsString::from("echo"),
        std::ffi::OsStr::from_bytes(b"a\0b").to_os_string(),
    ];
    assert!(attach_argv(&cmd).is_err());
}
