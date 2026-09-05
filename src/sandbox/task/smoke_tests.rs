use super::*;
use crate::config::{Encoding, OutputDisposition, ParamBound, TaskParam, TaskSecret};
use crate::testutil::{EnvVar, TmpDir, env_lock};

/// The engine, wired to a real provisioned userland — or `None` to skip. `pool`, when given,
/// points the engine at a task tool pool already realized on disk.
fn engine_with(
    tasks: Vec<TaskSpec>,
    project: &Path,
    pool: Option<&Path>,
    slug: &str,
) -> Option<(TaskEngine, TmpDir)> {
    let (engine, data) = engine_for(tasks, project, slug)?;
    Some(match pool {
        Some(p) => (
            engine.with_pool(p.to_path_buf(), PathBuf::from("/nonexistent/mise")),
            data,
        ),
        None => (engine, data),
    })
}

/// The engine, wired to a real provisioned userland — or `None` to skip.
///
/// `slug` has to be this test's alone. It names the cage, and from there the systemd scope
/// (`sbx-<slug>-task<n>-<seq>-<pid>.scope`), the cage hostname, and the tool pool. A distinct
/// slug is what keeps each test's cages legible as its own; the scope name would stay unique
/// without it, since the launcher counts the scopes it asks for, but two tests sharing a slug
/// would then be indistinguishable in `systemctl --user` and would share a tool pool.
fn engine_for(tasks: Vec<TaskSpec>, project: &Path, slug: &str) -> Option<(TaskEngine, TmpDir)> {
    engine_on(tasks, project, slug, None)
}

/// [`engine_for`] against a declared distribution, so what the engine derives from is an agent cage
/// whose root is an image rather than bubblewrap's own tmpfs. `distro` is the image locator; `None`
/// is the hermetic userland.
fn engine_on(
    tasks: Vec<TaskSpec>,
    project: &Path,
    slug: &str,
    distro: Option<&str>,
) -> Option<(TaskEngine, TmpDir)> {
    let bwrap = crate::pathfind::find_on_path("bwrap")?;
    if !matches!(crate::probe_userns(), crate::Userns::Ok) {
        return None;
    }
    let nix = crate::store::resolve_nix(None)?;
    let data = TmpDir::new();
    let layout = crate::store::Layout::under(data.path());
    let nixpkgs = crate::store::LockTarget::global(&layout, None)
        .resolve(&nix, &layout)
        .ok()?;
    let mut userland =
        super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs).ok()?;
    if let Some(locator) = distro {
        let lock = data.path().join("distro.lock");
        userland.distro = Some(
            crate::sandbox::distro::store::provision(
                &layout, locator, &lock, "smoke000", None, None,
            )
            .ok()?,
        );
    }

    // Assemble an agent cage exactly as the launcher would, then derive the engine from it — the
    // same path production takes, so what this exercises is the real derivation.
    let overlay = super::super::binds::Overlay {
        env: &[("TERM".to_string(), "dumb".to_string())],
        binds: &[],
        bin_paths: &[],
        timezone: super::super::binds::DEFAULT_ZONE,
        fresh_release_tokens: &[],
        ignored_mise_paths: &[],
    };
    let nix_mount = super::super::binds::NixMount {
        src: crate::store::physical_path(&layout, Path::new("/nix")),
        writable: false,
        on_btrfs: false,
    };
    let cage = super::super::binds::build_spec(
        data.path(),
        project,
        super::super::binds::Runtime::ProjectDefault,
        &userland,
        &nix_mount,
        &overlay,
        &[],
        NetPolicy::Isolated,
        "",
        &Default::default(),
        super::super::seccomp::SeccompPolicy::default(),
        &[],
        &Default::default(),
        vec![OsString::from("/bin/true")],
    )
    .ok()?;
    let engine = TaskEngine::from_cage(
        &bwrap,
        &cage,
        &layout,
        project,
        project,
        tasks,
        super::super::cgroup::Limits::default(),
        slug,
        None,
        CageForwarder {
            socat: crate::pathfind::find_on_path("socat")
                .unwrap_or_else(|| PathBuf::from("/nonexistent/socat")),
            shell: crate::pathfind::find_on_path("bash")
                .unwrap_or_else(|| PathBuf::from("/nonexistent/bash")),
        },
        crate::sandbox::redact::MIN_LEN_DEFAULT,
    );
    Some((engine, data))
}

/// A task that prints its credential and its parameter, so both paths are observable at once.
fn echo_task(shell: &str) -> TaskSpec {
    TaskSpec {
        unmask: Vec::new(),
        name: "echo-secret".into(),
        description: Some("prints the credential and the parameter".into()),
        cmd: vec![
            shell.to_string(),
            "-c".into(),
            "echo \"tok=$DEMO_TOKEN arg=$1\"".into(),
            "sh".into(),
            "{value}".into(),
        ],
        params: vec![TaskParam {
            name: "value".into(),
            bound: ParamBound::Pattern("^[a-z ]+$".into()),
            default: None,
        }],
        secrets: vec![TaskSecret {
            var: "DEMO_TOKEN".into(),
            sources: vec![crate::config::SecretSource::Env(
                "SBX_SMOKE_TASK_TOKEN".into(),
            )],
            encode: Encoding::Raw,
            description: None,
        }],
        injections: vec![],
        env: BTreeMap::new(),
        env_allow: vec![],
        stdout: OutputDisposition::Show,
        stderr: OutputDisposition::Show,
        timeout: Duration::from_secs(30),
        max_output: 4096,
        network: vec![],
        nonce: false,
        packages: vec![],
        spawn: None,
        exec: Default::default(),
        output: false,
        origin: crate::config::TaskOrigin::Project,
        timeout_from: crate::config::Ceiling::Declared,
        max_output_from: crate::config::Ceiling::Declared,
    }
}

fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn a_declared_task_runs_in_a_sibling_cage_and_comes_back_substituted() {
    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();
    // The credential is read host-side from sbx's own environment, so the value never has to be
    // written anywhere the cage can see.
    let _lock = env_lock();
    let _token = EnvVar::set("SBX_SMOKE_TASK_TOKEN", "smoke-token-abcdef");

    let shell = match crate::store::resolve_nix(None).and_then(|nix| {
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .ok()?;
        super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
            .ok()
            .map(|u| u.shell_bin)
    }) {
        Some(shell) => shell,
        None => {
            skip_incapable!("skipping task smoke: need nix and a provisioned userland");
            return;
        }
    };
    let Some((engine, _data)) = engine_for(
        vec![echo_task(&shell.to_string_lossy())],
        project.path(),
        "smoke-declared",
    ) else {
        skip_incapable!("skipping task smoke: need bwrap, userns, and nix");
        return;
    };

    let outcome = engine
        .run(
            "echo-secret",
            &params(&[("value", "hello there")]),
            &BTreeMap::new(),
            1,
        )
        .expect("the task runs");

    assert_eq!(outcome.exit, 0, "stderr: {:?}", outcome.stderr);
    let stdout = outcome.stdout.expect("stdout is shown");
    // The credential reached the command (it printed something for it) but comes back named,
    // never in the clear — and the parameter arrived as ONE argument, spaces included.
    assert!(
        stdout.contains("tok=${DEMO_TOKEN}"),
        "the credential must come back substituted: {stdout}"
    );
    assert!(
        !stdout.contains("smoke-token-abcdef"),
        "the plaintext must never reach the caller: {stdout}"
    );
    assert!(
        stdout.contains("arg=hello there"),
        "the parameter must arrive as one argument: {stdout}"
    );
    assert_eq!(outcome.redacted, 1, "one substitution, counted host-side");
    assert!(!outcome.timed_out && !outcome.truncated);

    // A value outside its bound never reaches the cage at all.
    let refused = engine.run(
        "echo-secret",
        &params(&[("value", "DROP TABLE t")]),
        &BTreeMap::new(),
        1,
    );
    assert!(
        matches!(refused, Err(TaskError::Refused(_))),
        "an out-of-bound value must be refused: {refused:?}"
    );
}

/// A withheld stream's substitution count does not go back to the caller, and the host-side log
/// still holds it.
///
/// The two streams are given **different** dispositions on purpose: it proves the split is
/// decided per stream rather than by one switch over the pair, which is the shape a caller
/// receiving half the output needs. The command prints the credential once on each, so a count
/// that leaked would be visible as an off-by-one rather than as nothing at all.
#[test]
fn a_withheld_streams_substitution_count_stays_host_side() {
    let project = TmpDir::new();
    let _lock = env_lock();
    let _token = EnvVar::set("SBX_SMOKE_COUNT_TOKEN", "count-token-abcdef");

    let shell = match crate::store::resolve_nix(None).and_then(|nix| {
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .ok()?;
        super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
            .ok()
            .map(|u| u.shell_bin)
    }) {
        Some(shell) => shell,
        None => {
            skip_incapable!("skipping count smoke: need nix and a provisioned userland");
            return;
        }
    };

    let mut task = echo_task(&shell.to_string_lossy());
    task.name = "print-both".into();
    task.cmd = vec![
        shell.to_string_lossy().into_owned(),
        "-c".into(),
        "echo \"$DEMO_TOKEN\"; echo \"$DEMO_TOKEN\" >&2".into(),
    ];
    task.params = vec![];
    task.secrets = vec![TaskSecret {
        var: "DEMO_TOKEN".into(),
        sources: vec![crate::config::SecretSource::Env(
            "SBX_SMOKE_COUNT_TOKEN".into(),
        )],
        encode: Encoding::Raw,
        description: None,
    }];
    task.stdout = OutputDisposition::Hide;
    task.stderr = OutputDisposition::Show;

    let Some((engine, _data)) = engine_for(vec![task], project.path(), "smoke-withheld") else {
        skip_incapable!("skipping count smoke: need bwrap, userns, and nix");
        return;
    };

    let outcome = engine
        .run("print-both", &BTreeMap::new(), &BTreeMap::new(), 1)
        .expect("the task runs");

    assert!(outcome.stdout.is_none(), "stdout is withheld");
    assert_eq!(
        outcome.redacted, 1,
        "only the shown stream's substitution is the caller's: {outcome:?}"
    );
    assert_eq!(
        outcome.redacted_withheld, 1,
        "and the withheld stream's is kept apart, not dropped: {outcome:?}"
    );
}

/// The paths an exec refusal names are substituted, proven through the real supervisor rather
/// than against the helper alone: the command writes the credential into a program name and
/// reaches for it, `spawn` refuses the `execve`, and what comes back to the caller is the
/// credential's **name**.
///
/// The file has to be created first. A refusal only counts as one when the target was *there* —
/// a `PATH` walk refuses a candidate per directory and those are not reported — so reaching for
/// a path that never existed would prove nothing. It is created with shell redirection alone,
/// because `spawn` is declared empty here: the command may run, and nothing else may.
#[test]
fn a_credential_in_a_refused_exec_path_is_substituted_by_the_real_supervisor() {
    let project = TmpDir::new();
    // Its own variable and its own value: the environment is process-global, so sharing the
    // other smoke test's name would have each one clearing the other's credential mid-run.
    let _lock = env_lock();
    let _token = EnvVar::set("SBX_SMOKE_REFUSAL_TOKEN", "refusal-token-abcdef");

    let shell = match crate::store::resolve_nix(None).and_then(|nix| {
        let data = TmpDir::new();
        let layout = crate::store::Layout::under(data.path());
        let nixpkgs = crate::store::LockTarget::global(&layout, None)
            .resolve(&nix, &layout)
            .ok()?;
        super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
            .ok()
            .map(|u| u.shell_bin)
    }) {
        Some(shell) => shell,
        None => {
            skip_incapable!("skipping refusal smoke: need nix and a provisioned userland");
            return;
        }
    };

    let mut task = echo_task(&shell.to_string_lossy());
    task.name = "reach-for-it".into();
    task.secrets = vec![TaskSecret {
        var: "DEMO_TOKEN".into(),
        sources: vec![crate::config::SecretSource::Env(
            "SBX_SMOKE_REFUSAL_TOKEN".into(),
        )],
        encode: Encoding::Raw,
        description: None,
    }];
    task.cmd = vec![
        shell.to_string_lossy().into_owned(),
        "-c".into(),
        ": > \"/tmp/$DEMO_TOKEN\"; exec \"/tmp/$DEMO_TOKEN\"".into(),
    ];
    task.params = vec![];
    // Declared and empty: stand the supervisor up, and let the command run nothing further.
    task.spawn = Some(vec![]);

    let Some((engine, _data)) = engine_for(vec![task], project.path(), "smoke-refusal") else {
        skip_incapable!("skipping refusal smoke: need bwrap, userns, and nix");
        return;
    };

    let outcome = engine
        .run("reach-for-it", &BTreeMap::new(), &BTreeMap::new(), 1)
        .expect("the task runs");

    let refused = &outcome.refused;
    assert!(
        !refused.is_empty(),
        "the supervisor must have refused the exec: {outcome:?}"
    );
    assert!(
        refused.iter().any(|r| r.target == "/tmp/${DEMO_TOKEN}"),
        "the refused path must come back named: {refused:?}"
    );
    assert!(
        !refused
            .iter()
            .any(|r| r.caller.contains("refusal-token-abcdef")
                || r.target.contains("refusal-token-abcdef")),
        "the plaintext must never reach the caller in a refusal: {refused:?}"
    );
}

/// The task tool pool, end to end in a real cage: a tool realized in the pool exactly as mise
/// lays one out is found by **name** (so the pool reached `PATH`), it is a `#!/bin/sh` script
/// (so the cage kept the synthetic shell a shebang needs — the affordance a mise-installed tool
/// almost always relies on), and the pool it came from is **read-only** inside the cage.
///
/// A pool realized by hand rather than by a real `mise install`, on purpose: what needs proving
/// here is sbx's wiring — the mount, its mode, its path, and the `PATH` prefix — and a real
/// install would make this a network test of mise's backends instead.
#[test]
fn a_pool_tool_runs_by_name_and_its_pool_is_read_only() {
    let project = TmpDir::new();
    let pool_base = TmpDir::new();
    let pool = pool_base.join("task-mise");
    // The install record, so the pool reports the tool as realized...
    std::fs::create_dir_all(pool.join("installs/demo-tool/1.0")).unwrap();
    // The recorded spec `mise use -g` writes: a token counts as satisfied only when the
    // install and the record agree, since the record is what a shim resolves through.
    std::fs::create_dir_all(pool.join("config")).unwrap();
    std::fs::write(
        pool.join("config/config.toml"),
        "[tools]\ndemo-tool = \"latest\"\n",
    )
    .unwrap();
    // ...and the shim, which is what `PATH` actually resolves through. A plain script rather
    // than mise's real trampoline: the wiring under test is sbx's — the mount, its mode, its
    // path, the `PATH` prefix — and driving mise here would make this a network test of its
    // backends. It is a `#!/bin/sh` script, so it also proves the cage kept the synthetic shell
    // that a mise-installed tool's shebang almost always needs.
    let shims = pool.join("shims");
    std::fs::create_dir_all(&shims).unwrap();
    std::fs::write(
        shims.join("demo-tool"),
        "#!/bin/sh\necho \"pool-tool ran\"\n\
         if echo x > /opt/sbx/task-mise/probe 2>/dev/null; then echo POOL-WRITABLE; fi\n",
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            shims.join("demo-tool"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let spec = TaskSpec {
        unmask: Vec::new(),
        name: "pool-tool".into(),
        description: None,
        cmd: vec!["demo-tool".into()],
        params: vec![],
        secrets: vec![],
        injections: vec![],
        env: BTreeMap::new(),
        env_allow: vec![],
        stdout: OutputDisposition::Show,
        stderr: OutputDisposition::Show,
        timeout: Duration::from_secs(30),
        max_output: 4096,
        network: vec![],
        nonce: false,
        packages: vec!["demo-tool".into()],
        spawn: None,
        exec: Default::default(),
        output: false,
        origin: crate::config::TaskOrigin::Project,
        timeout_from: crate::config::Ceiling::Declared,
        max_output_from: crate::config::Ceiling::Declared,
    };

    let Some((engine, _data)) = engine_with(vec![spec], project.path(), Some(&pool), "smoke-pool")
    else {
        skip_incapable!("skipping task pool smoke: need bwrap, userns, and nix");
        return;
    };
    let outcome = engine
        .run("pool-tool", &BTreeMap::new(), &BTreeMap::new(), 1)
        .expect("the pool task runs");

    let stdout = outcome.stdout.unwrap_or_default();
    assert_eq!(
        outcome.exit, 0,
        "stdout: {stdout:?} stderr: {:?}",
        outcome.stderr
    );
    assert!(
        stdout.contains("pool-tool ran"),
        "the pool's tool must resolve by name on PATH: {stdout}"
    );
    assert!(
        !stdout.contains("POOL-WRITABLE"),
        "the pool must be read-only inside the cage: {stdout}"
    );
    assert!(
        !pool.join("probe").exists(),
        "nothing in the cage may write through to the pool on the host"
    );
}

#[test]
fn the_timeout_kills_a_hanging_task_and_the_cap_truncates_a_loud_one() {
    let project = TmpDir::new();
    let shell = match crate::pathfind::find_on_path("bwrap")
        .and(crate::store::resolve_nix(None))
        .and_then(|nix| {
            let data = TmpDir::new();
            let layout = crate::store::Layout::under(data.path());
            let nixpkgs = crate::store::LockTarget::global(&layout, None)
                .resolve(&nix, &layout)
                .ok()?;
            super::super::fhs::resolve_userland(&nix, &layout, &nixpkgs, &nixpkgs)
                .ok()
                .map(|u| u.shell_bin)
        }) {
        Some(shell) => shell,
        None => {
            skip_incapable!("skipping task ceiling smoke: need bwrap, userns, and nix");
            return;
        }
    };

    let mut hang = echo_task(&shell.to_string_lossy());
    hang.name = "hang".into();
    hang.cmd = vec![
        shell.to_string_lossy().into_owned(),
        "-c".into(),
        "sleep 30".into(),
    ];
    hang.params.clear();
    hang.secrets.clear();
    hang.timeout = Duration::from_millis(600);

    let mut loud = echo_task(&shell.to_string_lossy());
    loud.name = "loud".into();
    loud.cmd = vec![
        shell.to_string_lossy().into_owned(),
        "-c".into(),
        "yes abcdefghij | head -c 20000".into(),
    ];
    loud.params.clear();
    loud.secrets.clear();
    loud.max_output = 256;

    let Some((engine, _data)) = engine_for(vec![hang, loud], project.path(), "smoke-timeout")
    else {
        skip_incapable!("skipping task ceiling smoke: prerequisites absent");
        return;
    };

    // Each invocation draws its id the way production does, rather than naming one. The id is
    // part of the cage name and therefore of the systemd scope (`sbx-<slug>-task<n>-<pid>.scope`),
    // and this is the only test here that runs *two* commands: with a literal id on both, they
    // asked for one scope name twice, and systemd refused the second outright ("was already
    // loaded or has a fragment file") because the first had just been killed by the timeout and
    // its unit was still loaded. Production cannot reach that — [`next_invocation`] is a
    // monotonic counter — so the collision was the test's alone. Drawing from the same counter
    // keeps it that way for whatever runs next.
    let killed = engine
        .run(
            "hang",
            &BTreeMap::new(),
            &BTreeMap::new(),
            next_invocation(),
        )
        .expect("the hanging task returns");
    assert!(killed.timed_out, "the timeout must fire");
    assert_ne!(killed.exit, 0, "a killed command does not report success");

    let cut = engine
        .run(
            "loud",
            &BTreeMap::new(),
            &BTreeMap::new(),
            next_invocation(),
        )
        .expect("the loud task returns");
    // The command has to have *run* for the cap to mean anything: a cage that failed to start
    // also produces no output, which is how the scope collision above read as an untruncated
    // stream for as long as it did.
    assert_eq!(
        cut.exit, 0,
        "the loud command must actually run: {:?}",
        cut.stderr
    );
    assert!(cut.truncated, "the output cap must report the truncation");
    assert!(
        cut.stdout.as_deref().map(str::len).unwrap_or(0) <= 256,
        "no more than the declared ceiling is kept"
    );
}

/// A declared operation runs on the substrate its session was declared on.
///
/// Under `[distro]` the sibling cage takes the same structural skeleton, and the skeleton is
/// nothing without the ground it stands on: the image root at mount zero. The command here exists
/// only in the image, so a cage that kept the destinations and lost the root cannot run it at all,
/// while one that quietly fell back to the hermetic base would answer with a different program.
///
/// Skipped rather than failed where the registry does not answer: what the arm proves needs a real
/// image, and an unreachable registry is not a verdict about the derivation.
#[test]
fn a_declared_task_runs_on_the_distribution_the_session_declared() {
    let project = TmpDir::new();
    std::fs::write(project.path().join("README"), b"hi").unwrap();

    // `dpkg` is the image's own, and no hermetic cage carries it: what answers says which
    // substrate ran. Read through the image's `/bin/sh`, which is likewise the image's.
    let mut task = echo_task("/bin/sh");
    task.name = "on-the-image".into();
    task.cmd = vec![
        "/bin/sh".to_string(),
        "-c".into(),
        "dpkg --version | head -1; . /etc/os-release; echo ID=$ID".into(),
    ];
    task.params = Vec::new();
    task.secrets = Vec::new();

    // The two reasons this cannot run are not the same reason. A host with no cage is one this
    // test was meant to run on and could not, which the capable-host run turns into a failure; a
    // registry that did not answer is not a verdict about the derivation either way.
    if crate::pathfind::find_on_path("bwrap").is_none()
        || !matches!(crate::probe_userns(), crate::Userns::Ok)
        || crate::store::resolve_nix(None).is_none()
    {
        skip_incapable!("skipping the distribution task smoke: need bwrap, userns, and nix");
        return;
    }
    let Some((engine, _data)) = engine_on(
        vec![task],
        project.path(),
        "smoke-distro",
        Some("oci:docker.io/library/debian:10-slim"),
    ) else {
        skip_unreachable!("skipping the distribution task smoke: the registry did not answer");
        return;
    };

    let outcome = engine
        .run("on-the-image", &BTreeMap::new(), &BTreeMap::new(), 1)
        .expect("the task runs");
    let stdout = outcome.stdout.clone().unwrap_or_default();
    assert_eq!(
        outcome.exit, 0,
        "a task naming a program of the declared distribution must run; stdout: {stdout}, \
         stderr: {:?}",
        outcome.stderr
    );
    assert!(
        stdout.contains("ID=debian"),
        "the cage's root must be the declared image: {stdout}"
    );
    assert!(
        stdout.contains("Debian"),
        "the image's own package tool must be the one that answered: {stdout}"
    );
}
