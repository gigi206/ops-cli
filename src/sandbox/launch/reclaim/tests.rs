use super::*;

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
        main: String::new(),
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
            main: String::new(),
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

/// A reclaim prepares for a reclaim.
///
/// The two preparations are interchangeable at the call site: both take the same inputs, both
/// return a `Prepared`, and both work. What separates them is that the launch preparation
/// provisions the declared distribution, so a sweep taken through it fetches an image and runs the
/// project's build commands in order to decide what to free, and on a project whose derived tree
/// does not exist yet it creates one on the way. The sweep reads neither: it keys what to keep on
/// the locks on disk and the sessions that are live.
///
/// Guarded by reading this module because the failure is a substitution and not an absence: the
/// wrong preparation compiles, reports the same numbers, and differs only in what it did first, so
/// nothing in the sweep's own output says which one ran. The behaviour is pinned as well, by an
/// end-to-end test that declares an image no registry answers for and reads a launch and a sweep
/// apart; that one needs a project store and a host that can sandbox, and this one needs neither.
#[test]
fn the_sweep_prepares_without_provisioning_a_distribution() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/sandbox/launch/reclaim.rs"),
    )
    .expect("this module's own source");
    assert!(
        crate::testutil::calls_function(&text, "prepare_to_reclaim("),
        "the sweep must prepare for a reclaim"
    );
    for launch in ["prepare_with(", "prepare_in(", "prepare_engines("] {
        assert!(
            !crate::testutil::calls_function(&text, launch),
            "`{launch}` provisions the declared distribution, which a sweep must never ask for"
        );
    }
}

/// What an app declares is read from its profile, and a profile the load could not read or parse
/// is dropped: the app then reads as declaring nothing, and every package it declares as removed.
/// The sweep of removed packages' roots drops nothing then, and says why; once the profile is gone
/// for good, its packages are removed and their roots go.
#[test]
fn a_profile_that_cannot_be_loaded_drops_no_package_root() {
    use crate::testutil::{EnvVar, TmpDir, env_lock};
    use std::os::unix::fs::PermissionsExt as _;
    let _lock = env_lock();
    let (cfg_home, data, state, proj) =
        (TmpDir::new(), TmpDir::new(), TmpDir::new(), TmpDir::new());
    let _cfg = EnvVar::set("XDG_CONFIG_HOME", cfg_home.path());
    let _data = EnvVar::set("SBX_DATA_DIR", data.path());
    let _state = EnvVar::set("XDG_STATE_HOME", state.path());
    let apps = cfg_home.path().join("sbx/apps");
    let bundles = cfg_home.path().join("sbx/bundles");
    std::fs::create_dir_all(&apps).unwrap();
    std::fs::create_dir_all(&bundles).unwrap();
    std::fs::write(
        bundles.join("b1.toml"),
        "[packages]\nhello = \"nix:hello\"\n",
    )
    .unwrap();
    let profile = apps.join("p1.toml");
    std::fs::write(&profile, "cmd = [\"true\"]\nuse = [\"b1\"]\n").unwrap();
    let gcroots = data.path().join("gcroots");
    let out_link = gcroots.join("projects/p/hello");
    std::fs::create_dir_all(out_link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink("/nix/store/h-hello", &out_link).unwrap();
    let store = TmpDir::new();
    let sweep = || {
        let cfg = crate::config::load(proj.path());
        prune_undeclared_roots(&cfg, store.path(), &gcroots, "p", true)
    };

    // Declared: the root stays.
    assert_eq!(sweep(), Ok(0));
    assert!(out_link.symlink_metadata().is_ok());

    // A profile that does not parse, a directory of profiles that cannot be read, a bundle that
    // does not parse: what the app declares cannot be told, and nothing goes.
    // How each shape is made, and undone.
    type Step<'a> = Box<dyn Fn() + 'a>;
    let shapes: [(&str, Step, Step); 3] = [
        (
            "a profile that does not parse",
            Box::new(|| std::fs::write(&profile, "cmd = [\"true\"\n").unwrap()),
            Box::new(|| std::fs::write(&profile, "cmd = [\"true\"]\nuse = [\"b1\"]\n").unwrap()),
        ),
        (
            "a directory of profiles that cannot be read",
            Box::new(|| {
                std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o000)).unwrap()
            }),
            Box::new(|| {
                std::fs::set_permissions(&apps, std::fs::Permissions::from_mode(0o700)).unwrap()
            }),
        ),
        (
            "a bundle that does not parse",
            Box::new(|| std::fs::write(bundles.join("b1.toml"), "[packages\n").unwrap()),
            Box::new(|| {
                std::fs::write(
                    bundles.join("b1.toml"),
                    "[packages]\nhello = \"nix:hello\"\n",
                )
                .unwrap()
            }),
        ),
    ];
    for (shape, break_it, mend_it) in &shapes {
        break_it();
        if *shape == "a directory of profiles that cannot be read"
            && std::fs::read_dir(&apps).is_ok()
        {
            mend_it();
            skip_incapable!("running as root, which reads a directory its mode refuses");
            return;
        }
        let swept = sweep();
        mend_it();
        assert!(swept.is_err(), "{shape}: {swept:?}");
        assert!(
            out_link.symlink_metadata().is_ok(),
            "{shape}: the root was dropped"
        );
    }

    // The profile removed: the app is gone, its packages are removed, and their roots go.
    std::fs::remove_file(&profile).unwrap();
    assert_eq!(sweep(), Ok(1));
    assert!(out_link.symlink_metadata().is_err());
}
