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
/// Guarded by reading this module rather than by running one, because the failure is a
/// substitution and not an absence. The wrong preparation compiles, reports the same numbers, and
/// differs only in what it did first. Driving it instead would need a project store, which only a
/// real launch creates.
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
