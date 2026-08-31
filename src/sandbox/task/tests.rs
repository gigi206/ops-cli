use super::*;
use crate::config::{Encoding, ParamBound, TaskParam, TaskSecret};

// --- what a launcher leaves open ---

/// Whether this process still holds the file identified by `(dev, ino)` open.
///
/// Asked by identity rather than by descriptor number: a number freed by a close is reused
/// immediately, and the harness runs other tests on other threads, so a number-based check would
/// answer about whatever opened next.
fn holds_open(dev: u64, ino: u64) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .flatten()
        .any(|entry| {
            std::fs::metadata(entry.path())
                .map(|m| m.dev() == dev && m.ino() == ino)
                .unwrap_or(false)
        })
}

/// A launcher's `--args` file holds the invocation's resolved credential in plaintext and is
/// deliberately **not** close-on-exec, so bwrap can still read it after the exec. A descriptor
/// with that property survives *every* exec this process makes while it is open — so one kept
/// for the length of a run is inherited by every sibling cage spawned during it, and a task cage
/// runs a program from the project tree, which the agent's own cage may write. That walks around
/// the pid namespace keeping a task's `/proc/<pid>/environ` out of the agent's reach.
///
/// The descriptors have done their whole job once `spawn` has forked, which is why they are
/// taken by value here and the caller is handed back only the child.
#[test]
fn a_launchers_credential_memfds_do_not_outlive_the_fork_that_carries_them() {
    use std::os::unix::fs::MetadataExt;

    let args = super::super::memfd::write(c"sbx-args", b"--setenv\0DB_PASSWORD\0hunter2\0")
        .expect("an anonymous file");
    let meta = args.metadata().expect("the anonymous file's identity");
    let (dev, ino) = (meta.dev(), meta.ino());
    assert!(
        holds_open(dev, ino),
        "the fixture must start with the descriptor open"
    );

    let mut child = spawn_launcher(
        Command::new("/bin/sh")
            .args(["-c", ":"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
        vec![args],
    )
    .expect("a launcher that exists");

    assert!(
        !holds_open(dev, ino),
        "the invocation's credential file is still open, so every cage spawned while this one \
         runs inherits it"
    );
    let _ = child.wait();
}

// --- how many run at once ---

/// The registry admits [`MAX_LIVE`] invocations and refuses the next, whether or not anyone is
/// waiting for them.
///
/// A caller waiting for its invocation was what stood in for this bound, and it counts callers:
/// the cage opens as many connections as the plane serves, each blocking on an invocation of its
/// own, so the wait bounds one per connection and nothing per session.
#[test]
fn live_invocations_are_capped_whether_or_not_a_caller_is_waiting() {
    let engine = TaskEngine::inventory_only(Vec::new());
    let mut held: Vec<_> = (0..MAX_LIVE as u64)
        .map(|id| {
            engine
                .enter(id, "probe", false)
                .expect("every invocation under the cap is admitted")
        })
        .collect();

    // Matched rather than `expect_err`, which would ask the guard to be printable for a case
    // that never produces one.
    let refused = match engine.enter(900, "probe", false) {
        Ok(_) => panic!("past the cap, an invocation must be refused"),
        Err(why) => why,
    };
    assert!(
        refused.contains("invocations are already running"),
        "the refusal must say what the limit is about: {refused}"
    );

    // The cap is on what is live, not on what has run: a finished invocation gives its slot back.
    held.pop();
    engine
        .enter(901, "probe", false)
        .expect("a slot given back admits the next caller");
}

/// A registry that cannot be read admits nothing, attached invocations included.
///
/// It used to admit them, and the reason was that a caller waiting for its invocation bounded
/// it without any lock being consulted. `MAX_LIVE` is a bound that cannot be known without the
/// lock, so admitting past a poisoned one would make poisoning it the way around the cap. The
/// registry is poisoned here the way production would poison it: a thread that panics holding
/// it (the panic message below is the test doing that, not a failure).
#[test]
fn a_registry_that_cannot_be_read_admits_nothing() {
    let engine = TaskEngine::inventory_only(Vec::new());
    let registry = engine.running.clone();
    let poisoner = std::thread::spawn(move || {
        let _held = registry.lock().expect("the registry");
        panic!("a handler failed while holding the registry");
    })
    .join();
    assert!(poisoner.is_err(), "the poisoning thread must have panicked");

    for detached in [false, true] {
        let refused = match engine.enter(1, "probe", detached) {
            Ok(_) => panic!("a cap that cannot be evaluated must not be assumed satisfied"),
            Err(why) => why,
        };
        assert!(
            refused.contains("the invocation registry is unavailable"),
            "detached={detached}: {refused}"
        );
    }
}

/// The detached cap still bites first, and says so: it is the tighter of the two, and its
/// refusal is the one that tells a caller `--detach` is what it ran out of.
#[test]
fn the_detached_cap_is_the_one_that_answers_a_detached_caller() {
    let engine = TaskEngine::inventory_only(Vec::new());
    let _held: Vec<_> = (0..MAX_DETACHED as u64)
        .map(|id| {
            engine
                .enter(id, "probe", true)
                .expect("under the detached cap")
        })
        .collect();

    let refused = match engine.enter(900, "probe", true) {
        Ok(_) => panic!("past the detached cap, an invocation must be refused"),
        Err(why) => why,
    };
    assert!(
        refused.contains("detached invocations are already running"),
        "{refused}"
    );
    // And the wider cap has room left, so an attached caller is still served: a full detached
    // slate must not refuse the call that would inspect it.
    engine
        .enter(901, "probe", false)
        .expect("an attached invocation with the detached slate full");
}

/// The registry entry an admission holds can be taken out of it, and the invocation keeps
/// reading as running until whoever took it lets go.
///
/// That is what the detached path rests on. Left inside the admission, the entry is released
/// the moment the run returns, and the result it will answer with is stored two statements
/// later; an invocation caught in between reads as neither running nor holding a result, and
/// the reader's remaining branches call it unknown or evicted. Both are false, and a caller
/// that asks once acts on them.
#[test]
fn a_taken_registration_keeps_the_invocation_visible_until_it_is_dropped() {
    let engine = TaskEngine::inventory_only(vec![task()]);
    let mut admitted = engine
        .admit(
            "db-query",
            &values(&[("sql", "SELECT one")]),
            &values(&[]),
            7,
            true,
        )
        .expect("the admission");

    let live = admitted.hold_registration().expect("the entry, once");
    assert!(
        admitted.hold_registration().is_none(),
        "there is one entry, and the first caller has it"
    );

    // Everything else the admission holds goes; the entry does not.
    drop(admitted);
    assert!(
        engine.running().iter().any(|row| row.id == 7),
        "the invocation must still read as running while its registration is held"
    );

    drop(live);
    assert!(
        !engine.running().iter().any(|row| row.id == 7),
        "and stop reading as running once it is let go"
    );
}

fn task() -> TaskSpec {
    TaskSpec {
        unmask: Vec::new(),
        name: "db-query".into(),
        description: None,
        cmd: vec!["psql".into(), "-c".into(), "{sql}".into()],
        params: vec![TaskParam {
            name: "sql".into(),
            bound: ParamBound::Pattern("^SELECT [a-z]+$".into()),
            default: None,
        }],
        secrets: vec![],
        injections: vec![],
        env: BTreeMap::new(),
        env_allow: vec!["PGCONNECT_TIMEOUT".into()],
        stdout: OutputDisposition::Show,
        stderr: OutputDisposition::Show,
        timeout: Duration::from_secs(5),
        max_output: 1024,
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

fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// A value fills the element that holds the placeholder and never becomes a second argument —
// the property that keeps a caller from restructuring the command.
#[test]
fn substitution_stays_inside_one_argv_element() {
    let argv = substitute(&task().cmd, &values(&[("sql", "SELECT one two")])).unwrap();
    assert_eq!(
        argv,
        vec![
            OsString::from("psql"),
            OsString::from("-c"),
            OsString::from("SELECT one two")
        ],
        "a value with spaces stays one element"
    );
}

#[test]
fn substitution_handles_several_placeholders_and_literal_braces() {
    let cmd = vec!["prog".to_string(), "{a}-{b}".to_string(), "{}".to_string()];
    let argv = substitute(&cmd, &values(&[("a", "1"), ("b", "2")])).unwrap();
    assert_eq!(argv[1], OsString::from("1-2"));
    assert_eq!(
        argv[2],
        OsString::from("{}"),
        "an empty brace pair is literal"
    );
}

// The paths an exec refusal names reach the caller like the output does, so they are scanned
// like the output — otherwise the one text a caller receives that the *command* composed would
// be the one spelling the substituter never saw.
#[test]
fn a_credential_spelled_into_an_exec_path_comes_back_substituted() {
    let needles = vec![crate::sandbox::proxy::SecretNeedle::named(
        "DEMO_API_KEY",
        b"s3cr3t-value".to_vec(),
    )];
    let refusals = vec![
        crate::sandbox::proc_enforce::Refusal {
            caller: "/nix/store/demo/bin/sh".to_string(),
            target: "/nix/store/demo/bin/s3cr3t-value".to_string(),
        },
        // The caller is attacker-influenced too the moment a command is composed rather than
        // declared, so both fields are scanned, not just the target.
        crate::sandbox::proc_enforce::Refusal {
            caller: "/tmp/s3cr3t-value".to_string(),
            target: "/nix/store/demo/bin/curl".to_string(),
        },
    ];

    let out = TaskEngine::substituted_refusals(refusals, &needles, &Placeholder::Plain);

    assert_eq!(
        out[0].target, "/nix/store/demo/bin/${DEMO_API_KEY}",
        "the credential must not reach the caller in the program name"
    );
    assert_eq!(
        out[1].caller, "/tmp/${DEMO_API_KEY}",
        "nor in the name of the program that reached for it"
    );
    assert_eq!(
        out[0].caller, "/nix/store/demo/bin/sh",
        "a path carrying no credential is left exactly as the kernel reported it"
    );
    assert_eq!(out[1].target, "/nix/store/demo/bin/curl");
}

// An empty caller is the policy deciding by target alone; scanning must not invent a value for
// it, because the wire writes `-` for empty and a fabricated one would change the field count.
#[test]
fn a_refusal_with_no_caller_keeps_its_empty_caller() {
    let needles = vec![crate::sandbox::proxy::SecretNeedle::named(
        "DEMO_API_KEY",
        b"s3cr3t-value".to_vec(),
    )];
    let out = TaskEngine::substituted_refusals(
        vec![crate::sandbox::proc_enforce::Refusal {
            caller: String::new(),
            target: "/nix/store/demo/bin/base64".to_string(),
        }],
        &needles,
        &Placeholder::Plain,
    );
    assert!(out[0].caller.is_empty(), "an empty caller stays empty");
}

// A caller's value is re-checked against the bound at invocation, not just at declaration.
#[test]
fn a_value_outside_its_bound_is_refused() {
    let e = resolve_params(&task(), &values(&[("sql", "DROP TABLE t")])).unwrap_err();
    assert!(e.contains("sql"), "{e}");
}

#[test]
fn a_missing_required_parameter_is_refused_rather_than_emptied() {
    let e = resolve_params(&task(), &BTreeMap::new()).unwrap_err();
    assert!(e.contains("required"), "{e}");
}

#[test]
fn an_undeclared_parameter_is_refused() {
    let e = resolve_params(&task(), &values(&[("sql", "SELECT one"), ("limit", "1")])).unwrap_err();
    assert!(e.contains("limit"), "{e}");
}

#[test]
fn a_default_fills_in_for_an_absent_value() {
    let mut t = task();
    t.params[0].default = Some("SELECT one".into());
    let resolved = resolve_params(&t, &BTreeMap::new()).unwrap();
    assert_eq!(resolved.get("sql").map(String::as_str), Some("SELECT one"));
}

// The environment allowlist refuses rather than drops: a caller that believes it set a variable
// must not be silently overruled.
#[test]
fn an_unlisted_environment_name_is_refused() {
    let e = caller_env(&task(), &values(&[("LD_PRELOAD", "/evil.so")])).unwrap_err();
    assert!(e.contains("LD_PRELOAD"), "{e}");
    let ok = caller_env(&task(), &values(&[("PGCONNECT_TIMEOUT", "5")])).unwrap();
    assert_eq!(ok, vec![("PGCONNECT_TIMEOUT".to_string(), "5".to_string())]);
}

// The mount derivation is the security core of the sibling cage: the skeleton is kept, `/nix`
// is repointed at the immutable shared store, writable binds are demoted, and every channel the
// agent cage carries is dropped.
#[test]
fn the_task_cage_keeps_the_skeleton_and_drops_every_channel() {
    let agent = vec![
        // the per-project store, read-WRITE in the agent's cage
        Mount::Bind {
            src: PathBuf::from("/data/projects/abc/store/nix"),
            dest: PathBuf::from("/nix"),
        },
        Mount::Symlink {
            target: PathBuf::from("/nix/store/abc-bash/bin/sh"),
            dest: PathBuf::from(super::super::binds::SANDBOX_SHELL),
        },
        Mount::RoBind {
            src: PathBuf::from("/data/projects/abc/etc/passwd"),
            dest: PathBuf::from("/etc/passwd"),
        },
        // a config bind, a GUI hole and a relay socket: all channels, none structural
        Mount::Bind {
            src: PathBuf::from("/home/u/secrets"),
            dest: PathBuf::from("/mnt/secrets"),
        },
        Mount::RoBind {
            src: PathBuf::from("/run/user/1000/wayland-0"),
            dest: PathBuf::from("/run/user/1000/wayland-0"),
        },
        Mount::Bind {
            src: PathBuf::from("/data/egress/cage-1"),
            dest: PathBuf::from("/run/sbx"),
        },
        Mount::DevBind {
            src: PathBuf::from("/dev/dri"),
            dest: PathBuf::from("/dev/dri"),
        },
        // The task plane's own two mounts. Both MUST be dropped: a task cage that carried the
        // socket could invoke tasks recursively, and one that carried sbx's binary would hand a
        // credential-bearing command the client to reach it with.
        Mount::Bind {
            src: PathBuf::from("/data/tasks/42/control.sock"),
            dest: PathBuf::from(super::super::task_control::CAGE_TASK_UDS),
        },
        Mount::RoBind {
            src: PathBuf::from("/usr/local/bin/sbx"),
            dest: PathBuf::from(super::super::task_control::TASK_SHIM_INCAGE),
        },
    ];
    let out = task_mounts(&agent, Path::new("/data/shared/store/nix"));
    assert!(
        !out.iter().any(|m| {
            let d = mount_dest(m);
            d == Path::new(super::super::task_control::CAGE_TASK_UDS)
                || d == Path::new(super::super::task_control::TASK_SHIM_INCAGE)
        }),
        "the task socket and the task client must never reach a task cage: {out:?}"
    );

    assert_eq!(
        out,
        vec![
            Mount::RoBind {
                src: PathBuf::from("/data/shared/store/nix"),
                dest: PathBuf::from("/nix"),
            },
            Mount::Symlink {
                target: PathBuf::from("/nix/store/abc-bash/bin/sh"),
                dest: PathBuf::from(super::super::binds::SANDBOX_SHELL),
            },
            Mount::RoBind {
                src: PathBuf::from("/data/projects/abc/etc/passwd"),
                dest: PathBuf::from("/etc/passwd"),
            },
        ],
        "only the skeleton survives, and /nix comes from the shared store read-only"
    );
}

/// The allowlist is matched on *exact* destinations, so an entry that names no real mount keeps
/// nothing while reading as though it did — `/bin` does not keep `/bin/sh`, `/etc/ssl` does not
/// keep the CA bundle. Pin every entry against the set the cage assembler actually emits.
#[test]
fn every_kept_destination_is_one_the_cage_emits() {
    for dest in KEPT_DESTS {
        assert!(
            super::super::binds::STRUCTURAL_DESTS.contains(dest),
            "`{dest}` is not a destination the cage emits — it keeps nothing"
        );
    }
}

/// The hermetic userland a *foreign* binary needs: the nix-ld shim's mount and the two variables
/// it reads. A mise-installed tool is typically foreign, so losing either half leaves a task
/// cage that holds the program and cannot exec it.
#[test]
fn a_foreign_binarys_loader_survives_with_its_environment() {
    let agent = vec![
        Mount::RoBind {
            src: PathBuf::from("/nix/store/abc-nix-ld/lib/ld.so"),
            dest: PathBuf::from(super::super::binds::LOADER_DEST),
        },
        Mount::Symlink {
            target: PathBuf::from("/nix/store/abc-bash/bin/sh"),
            dest: PathBuf::from(super::super::binds::SANDBOX_SHELL),
        },
        Mount::Symlink {
            target: PathBuf::from("/nix/store/abc-coreutils/bin/env"),
            dest: PathBuf::from(super::super::binds::SANDBOX_ENV),
        },
    ];
    let kept: Vec<PathBuf> = task_mounts(&agent, Path::new("/shared/nix"))
        .iter()
        .map(|m| mount_dest(m).to_path_buf())
        .collect();
    assert_eq!(
        kept,
        vec![
            PathBuf::from(super::super::binds::LOADER_DEST),
            PathBuf::from(super::super::binds::SANDBOX_SHELL),
            PathBuf::from(super::super::binds::SANDBOX_ENV),
        ]
    );

    let env = task_env(&[
        (
            "NIX_LD".to_string(),
            "/nix/store/glibc/lib/ld.so".to_string(),
        ),
        (
            "NIX_LD_LIBRARY_PATH".to_string(),
            "/nix/store/glibc/lib".to_string(),
        ),
    ]);
    assert_eq!(env.len(), 2, "the nix-ld shim's environment must survive");
}

/// A task resolves the local zone exactly as the session does. The question this asks is the
/// cross-plane one: everything a task cage gets is an allowlist entry, so a facility added to
/// the agent cage is absent here until it is named twice — and the halves are useless apart
/// (the link is a dangling pointer without the database, and `TZ` names a zone nothing can
/// resolve without `TZDIR`).
#[test]
fn the_zone_the_session_resolves_is_the_zone_a_task_resolves() {
    let agent = vec![
        Mount::RoBind {
            src: PathBuf::from("/nix/store/abc-tzdata/share/zoneinfo"),
            dest: PathBuf::from(super::super::binds::CAGE_ZONEINFO),
        },
        Mount::Symlink {
            target: PathBuf::from("/usr/share/zoneinfo/Europe/Paris"),
            dest: PathBuf::from(super::super::binds::CAGE_LOCALTIME),
        },
    ];
    let kept: Vec<PathBuf> = task_mounts(&agent, Path::new("/shared/nix"))
        .iter()
        .map(|m| mount_dest(m).to_path_buf())
        .collect();
    assert_eq!(
        kept,
        vec![
            PathBuf::from("/usr/share/zoneinfo"),
            PathBuf::from("/etc/localtime"),
        ],
        "both halves of the zone must reach a task cage"
    );

    let env = task_env(&[
        ("TZ".to_string(), "Europe/Paris".to_string()),
        ("TZDIR".to_string(), "/usr/share/zoneinfo".to_string()),
        ("SBX_EGRESS_CONTRACT".to_string(), "/opt/x".to_string()),
    ]);
    assert_eq!(
        env,
        vec![
            ("TZ".to_string(), "Europe/Paris".to_string()),
            ("TZDIR".to_string(), "/usr/share/zoneinfo".to_string()),
        ],
        "the zone variables survive the filter, and nothing else rides in with them"
    );
}

// A writable structural bind is demoted rather than dropped, so the userland stays complete
// while nothing in a task cage is writable except its own tmpfs.
#[test]
fn a_writable_structural_bind_is_demoted_to_read_only() {
    let agent = vec![Mount::Bind {
        src: PathBuf::from("/host/etc/hosts"),
        dest: PathBuf::from("/etc/hosts"),
    }];
    let out = task_mounts(&agent, Path::new("/shared/nix"));
    assert_eq!(
        out,
        vec![Mount::RoBind {
            src: PathBuf::from("/host/etc/hosts"),
            dest: PathBuf::from("/etc/hosts"),
        }]
    );
}

// The environment is filtered the same way, and for the same reason.
#[test]
fn the_task_environment_keeps_only_the_userland_plumbing() {
    let agent = vec![
        ("PATH".to_string(), "/bin".to_string()),
        ("LOCALE_ARCHIVE".to_string(), "/nix/locales".to_string()),
        (
            "https_proxy".to_string(),
            "http://127.0.0.1:3128".to_string(),
        ),
        ("ANTHROPIC_API_KEY".to_string(), "sk-secret".to_string()),
        ("WAYLAND_DISPLAY".to_string(), "wayland-0".to_string()),
    ];
    let kept = task_env(&agent);
    assert_eq!(
        kept,
        vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("LOCALE_ARCHIVE".to_string(), "/nix/locales".to_string()),
        ],
        "an agent's own credential, proxy pointer and display never reach a task"
    );
}

// The output cap keeps only the declared number of bytes but still drains the pipe, and says it
// cut — a truncated result that looked complete would be worse than no result.
#[test]
fn the_capture_cap_truncates_and_reports() {
    let mut src = std::io::Cursor::new(b"0123456789".to_vec());
    let (kept, cut) = read_capped(&mut src, 4, 0).unwrap();
    assert_eq!(kept, b"0123");
    assert!(cut);

    let mut fits = std::io::Cursor::new(b"ab".to_vec());
    let (kept, cut) = read_capped(&mut fits, 4, 0).unwrap();
    assert_eq!(kept, b"ab");
    assert!(!cut);
}

/// The scan runs on the kept bytes, and it searches for **whole** needles. So a credential lying
/// across the output ceiling was cut in half, its surviving prefix matched nothing, and the
/// caller received it in the clear — from the one path whose whole job is that it does not.
///
/// The margin is the scanner's, not the caller's: it is read so the needle is present whole when
/// the substitution runs, and cut back off afterwards.
#[test]
fn a_needle_lying_across_the_cap_is_read_whole_for_the_scan() {
    // `cap` falls in the middle of the secret.
    let cap = 8;
    let secret = "SECRETVALUE12345";
    let text = format!("....{secret}....");
    let margin = secret.len() - 1;

    let mut src = std::io::Cursor::new(text.clone().into_bytes());
    let (kept, cut) = read_capped(&mut src, cap, margin).unwrap();
    assert!(cut, "the caller still loses the tail, so it is still `cut`");
    assert!(
        String::from_utf8_lossy(&kept).contains(secret),
        "the scanner must see the needle whole: {:?}",
        String::from_utf8_lossy(&kept)
    );

    // And with no margin — what this used to do — the prefix survives and matches nothing.
    let mut bare = std::io::Cursor::new(text.into_bytes());
    let (kept, _) = read_capped(&mut bare, cap, 0).unwrap();
    let bare = String::from_utf8_lossy(&kept).into_owned();
    assert!(!bare.contains(secret), "the whole value is not there");
    assert!(
        bare.contains("SECR"),
        "but a plaintext prefix of it is, which is the leak: {bare:?}"
    );
}

/// A task that declares `network` must carry the egress forwarder into its cage. Its proxy
/// serves a Unix socket while its proxy variables name a TCP port, so without the bridge the
/// declaration reads as "this task may reach these hosts" and the cage reaches nothing.
#[test]
fn a_networked_task_carries_the_egress_forwarder_and_a_local_one_does_not() {
    let base = crate::testutil::TmpDir::new();
    let engine = engine_with_pool(&base.join("task-mise"), Vec::new());
    let bare = vec![
        OsString::from("curl"),
        OsString::from("https://example.com"),
    ];

    let mut local = task();
    local.network = Vec::new();
    assert_eq!(
        engine.cage_argv(bare.clone(), &local, &[]),
        bare,
        "a task with no egress must run exactly as declared — no shell it did not ask for"
    );

    let mut networked = task();
    networked.network = vec![crate::allowlist::classify("example.com").expect("a valid rule")];
    let wrapped = engine.cage_argv(bare.clone(), &networked, &[]);
    let script = wrapped
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        script.contains("TCP-LISTEN:") && script.contains("/tmp/sbx-egress.sock"),
        "the forwarder must bridge the cage port to the bound proxy socket: {script}"
    );
    assert!(
        wrapped.ends_with(&bare),
        "the declared command must still be what runs, positionally: {wrapped:?}"
    );
}

/// An engine wired to `pool`, with the given tasks. Built field-wise so a mount/PATH assertion
/// needs neither nix nor a kernel.
fn engine_with_pool(pool: &Path, tasks: Vec<TaskSpec>) -> TaskEngine {
    TaskEngine {
        fs_masks: None,
        notify: None,
        brokers: Vec::new(),
        egress_log: None,
        signer_log: None,
        redact_min_len: crate::sandbox::redact::MIN_LEN_DEFAULT,
        bwrap: PathBuf::from("/usr/bin/bwrap"),
        forwarder: CageForwarder {
            socat: PathBuf::from("/nix/store/base/bin/socat"),
            shell: PathBuf::from("/nix/store/base/bin/bash"),
        },
        base_mounts: vec![Mount::RoBind {
            src: PathBuf::from("/shared/nix"),
            dest: PathBuf::from("/nix"),
        }],
        base_env: vec![("PATH".to_string(), "/nix/store/base/bin".to_string())],
        project: PathBuf::from("/project"),
        config_root: PathBuf::from("/project"),
        tasks,
        limits: super::super::cgroup::Limits::default(),
        slug: "test".to_string(),
        layout: crate::store::Layout::under(Path::new("/data")),
        ca_bundle: None,
        pool: Some((
            pool.to_path_buf(),
            PathBuf::from("/nix/store/mise/bin/mise"),
        )),
        output_held: Arc::new(Mutex::new(BTreeSet::new())),
        running: Arc::new(Mutex::new(BTreeMap::new())),
    }
}

/// The same synthetic engine, rooted at a real data directory — what a test needs when the path
/// under exercise writes a per-invocation file under `<data>`.
fn engine_at(data: &Path, tasks: Vec<TaskSpec>) -> TaskEngine {
    let mut engine = TaskEngine {
        layout: crate::store::Layout::under(data),
        pool: None,
        ..engine_with_pool(Path::new("/nonexistent/pool"), tasks)
    };
    // The skeleton a task cage inherits carries the *agent's* hosts file; a networked task must
    // land on top of it.
    engine.base_mounts.push(Mount::RoBind {
        src: PathBuf::from("/host/etc/hosts"),
        dest: PathBuf::from("/etc/hosts"),
    });
    std::fs::create_dir_all(data.join("egress")).expect("the egress directory");
    engine
}

/// An engine whose `/nix` is a real directory on disk, with `programs` laid down executable in
/// the store — what a resolution test needs, since resolving asks the filesystem.
fn engine_with_store(root: &Path, programs: &[&str], tasks: Vec<TaskSpec>) -> TaskEngine {
    use std::os::unix::fs::PermissionsExt;
    let bin = root.join("nix/store/demo/bin");
    std::fs::create_dir_all(&bin).expect("the store bin");
    for p in programs {
        let path = bin.join(p);
        // An ELF header's first bytes, so these stand for *binaries*: a `#!` here would make
        // every fixture program a script, and the policy keys a program's node on what it is
        // entered as — which for a script is its interpreter, not the file.
        std::fs::write(&path, b"\x7fELF\x02\x01\x01\x00").expect("the program");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
    }
    let mut engine = engine_at(root, tasks);
    engine.base_mounts = vec![Mount::RoBind {
        src: root.join("nix"),
        dest: PathBuf::from("/nix"),
    }];
    engine.base_env = vec![("PATH".to_string(), "/nix/store/demo/bin".to_string())];
    engine
}

/// A declared name becomes the **absolute in-cage path** it will run as. That is the difference
/// between naming a program and naming a filename: a basename rule would admit any file so
/// called, including one written into the invocation's own tmpfs, while the resolved path names
/// the one in the read-only store.
#[test]
fn a_declared_name_resolves_to_the_program_in_the_store() {
    let root = crate::testutil::TmpDir::new();
    let task = task();
    let engine = engine_with_store(root.path(), &["psql", "less"], vec![task.clone()]);
    let dirs = vec![PathBuf::from("/nix/store/demo/bin")];

    assert_eq!(
        engine.resolve_spawn_entry("less", &dirs, &task).unwrap(),
        "/nix/store/demo/bin/less"
    );
    // An entry the author wrote as a path is theirs — kept verbatim, globs included.
    assert_eq!(
        engine
            .resolve_spawn_entry("/nix/store/*/bin/git", &dirs, &task)
            .unwrap(),
        "/nix/store/*/bin/git"
    );
    // A name that is nowhere refuses: a rule matching nothing would leave the program it names
    // unrunnable, which is not what the declaration says.
    let e = engine
        .resolve_spawn_entry("nosuchtool", &dirs, &task)
        .unwrap_err();
    assert!(e.contains("not on this task's path"), "{e}");

    // A glob in a bare entry matches no file, so it lands in the same branch — the message must
    // name the form rather than blame the lookup.
    let e = engine
        .resolve_spawn_entry("git*", &dirs, &task)
        .unwrap_err();
    assert!(
        e.contains("not a pattern"),
        "the refusal must point at the form: {e}"
    );
}

/// The policy a declaration produces: the shim may run the command because that exec is not
/// optional, the command may run what it declares, and **everything else is refused** — the
/// posture is an allowlist, not the session's denylist.
#[test]
fn a_declared_spawn_confines_the_cage_to_the_command_and_what_it_names() {
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.spawn = Some(vec!["less".to_string()]);
    let engine = engine_with_store(root.path(), &["psql", "less"], vec![task.clone()]);

    let policy = engine
        .spawn_policy(&task, task.spawn.as_ref().unwrap(), &engine.base_env)
        .expect("a policy");
    assert_eq!(policy.mode, crate::proc_policy::ProcMode::Confine);
    use crate::proc_policy::Verdict;
    let shim = [super::super::proc_enforce::SHIM_CAGE_PATH.to_string()];
    let command = ["/nix/store/demo/bin/psql".to_string()];
    assert_eq!(
        policy.decide(&shim, "/nix/store/demo/bin/psql"),
        Verdict::Allow,
        "the command itself must run, or the task refuses itself"
    );
    assert_eq!(
        policy.decide(&command, "/nix/store/demo/bin/less"),
        Verdict::Allow
    );
    assert_eq!(
        policy.decide(&command, "/bin/sh"),
        Verdict::Deny,
        "an undeclared program is refused — that is the whole field"
    );
    // The resolved path is what matches, so a same-named file elsewhere in the cage does not.
    assert_eq!(
        policy.decide(&command, "/tmp/less"),
        Verdict::Deny,
        "a file that merely shares the name must not satisfy the rule"
    );
    // No inheritance: the program the command was allowed to run has no node of its own, so it
    // may run nothing. Inheritance would hand back the shortcut the graph exists to remove.
    assert_eq!(
        policy.decide(
            &["/nix/store/demo/bin/less".to_string()],
            "/nix/store/demo/bin/less"
        ),
        Verdict::Deny,
        "a program with no node of its own may run nothing"
    );
    // A caller nobody could name is the one execve that must not run.
    assert_eq!(
        policy.decide(&[], "/nix/store/demo/bin/less"),
        Verdict::Deny
    );
}

/// A script's `spawn` governs its **interpreter**. The kernel loads that interpreter inside the
/// very `execve` that named the script, so from its first instruction the process is the
/// interpreter and the script is never a running program — a node keyed on the file would sit
/// there being read by nothing, and everything the script ran would be refused with the target
/// named in a list that was already naming it.
#[test]
fn a_script_commands_node_is_keyed_on_the_interpreter_that_runs_it() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.cmd = vec!["/nix/store/demo/bin/report.sh".to_string()];
    task.spawn = Some(vec!["less".to_string()]);
    let engine = engine_with_store(root.path(), &["sh", "less"], vec![task.clone()]);
    let script = root.path().join("nix/store/demo/bin/report.sh");
    std::fs::write(&script, b"#!/nix/store/demo/bin/sh -e\nless\n").expect("the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");

    let policy = engine
        .spawn_policy(&task, task.spawn.as_ref().unwrap(), &engine.base_env)
        .expect("a policy");
    use crate::proc_policy::Verdict;
    // Only the first token of the `#!` line: Linux hands the rest to the interpreter as one
    // argument, so `-e` is an argument and not a second program.
    assert_eq!(
        policy.decide(
            &["/nix/store/demo/bin/sh".to_string()],
            "/nix/store/demo/bin/less"
        ),
        Verdict::Allow,
        "the interpreter is what the declaration governs"
    );
    assert_eq!(
        policy.decide(&[task.cmd[0].clone()], "/nix/store/demo/bin/less"),
        Verdict::Deny,
        "and the file itself never runs, so a node on it would be read by nothing"
    );
}

/// The same rule, for the nodes `[exec.<program>]` declares — which skipped it.
///
/// `a_script_commands_node_is_keyed_on_the_interpreter_that_runs_it` holds the property for the
/// *command*'s node. Three lines below that in `spawn_policy`, the declared nodes were keyed on
/// the resolved script file instead, so a node for a script program governed a caller that never
/// exists. And it failed in the direction that refuses: an unmatched caller under a
/// `CallerGraph` takes `unmatched()`, which is `Deny` for the `confine` mode a task runs in, so
/// the declaration read as a grant and behaved as a denial.
#[test]
fn a_declared_scripts_node_is_keyed_on_its_interpreter_too() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.cmd = vec!["/bin/sh".to_string()];
    task.spawn = Some(vec!["build.sh".to_string()]);
    task.exec = [("build.sh".to_string(), vec!["psql".to_string()])]
        .into_iter()
        .collect();
    let engine = engine_with_store(root.path(), &["sh", "psql", "build.sh"], vec![task.clone()]);
    let script = root.path().join("nix/store/demo/bin/build.sh");
    std::fs::write(&script, b"#!/nix/store/demo/bin/sh\npsql\n").expect("the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");

    let policy = engine
        .spawn_policy(&task, task.spawn.as_ref().unwrap(), &engine.base_env)
        .expect("a policy");
    use crate::proc_policy::Verdict;
    // What the kernel actually reports as the caller once the script is running.
    assert_eq!(
        policy.decide(
            &["/nix/store/demo/bin/sh".to_string()],
            "/nix/store/demo/bin/psql"
        ),
        Verdict::Allow,
        "the declared node must govern the interpreter the script is entered as"
    );
    // And the file itself is never a running program, so a node on it would be read by nothing.
    assert_eq!(
        policy.decide(
            &["/nix/store/demo/bin/build.sh".to_string()],
            "/nix/store/demo/bin/psql"
        ),
        Verdict::Deny
    );
}

/// What a refusal announces is bounded where it is *built*, because the notifier keeps it: the
/// coalescer keys its repeat memory on the subject, one key per distinct problem for the
/// session's life. The name is whatever the cage put after `RUN `, capped by the crossing
/// socket at a mebibyte, so a cage naming tasks that do not exist could hold about a gibibyte
/// of supervisor memory in keys nothing evicts. The sink's guard does not reach it — that one
/// shapes what is shown, after the key is stored.
#[test]
fn a_refused_announcement_bounds_the_name_the_cage_chose() {
    // The bound `super::super::sanitize` applies, in characters.
    const MAX: usize = 512;
    let huge = "x".repeat(4096);
    let block = refusal_block(
        &huge,
        "undeclared",
        &TaskError::Unknown(huge.clone()).to_string(),
    );
    assert!(
        block.subject.chars().count() <= MAX,
        "the subject is what the repeat memory holds: {} characters",
        block.subject.chars().count()
    );
    assert!(
        block.detail.chars().count() <= MAX,
        "and the reason embeds the same name: {} characters",
        block.detail.chars().count()
    );
    // A newline in the name would forge a second line of whatever reads the announcement.
    let forged = refusal_block("first\nsecond", "refused", "a\nb");
    assert!(!forged.subject.contains('\n') && !forged.detail.contains('\n'));
    // An ordinary name is carried through untouched, or this would be mangling rather than
    // bounding — and the announcement would name a task nobody declared.
    let plain = refusal_block("db-query", "undeclared", "no such task `db-query`");
    assert_eq!(plain.subject, "db-query");
    assert_eq!(plain.detail, "no such task `db-query`");
    assert_eq!(plain.reason, "undeclared");
    assert_eq!(plain.event, crate::notify::NotifyEvent::Task);
}

/// A node whose program is spelled **relative** — `[exec."./build.sh"]`, the natural spelling
/// for a script that lives beside the project's own files — is keyed by what the supervisor
/// will read out of `/proc/<pid>/exe`, and that is an absolute path, always.
///
/// Keyed by the string as typed, such a node governed a caller that cannot exist, and it failed
/// in the direction that refuses: an unmatched caller under a `CallerGraph` takes `unmatched()`,
/// which is `Deny` for `confine`. So the whole list under the section was read by nothing and
/// the script could run none of it.
#[test]
fn a_relative_node_is_keyed_by_the_program_the_caller_will_report() {
    use std::os::unix::fs::PermissionsExt;
    let root = crate::testutil::TmpDir::new();
    let project = root.path().join("project");
    std::fs::create_dir_all(&project).expect("the project");
    let mut task = task();
    task.cmd = vec!["/bin/sh".to_string()];
    task.spawn = Some(vec!["./build.sh".to_string()]);
    task.exec = [("./build.sh".to_string(), vec!["psql".to_string()])]
        .into_iter()
        .collect();
    let mut engine = engine_with_store(root.path(), &["sh", "psql"], vec![task.clone()]);
    engine.project = project.clone();
    // The script the relative name points at: in the project, which is the cage's working
    // directory, entered as the interpreter its `#!` names.
    let script = project.join("build.sh");
    std::fs::write(&script, b"#!/nix/store/demo/bin/sh\npsql\n").expect("the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");

    let policy = engine
        .spawn_policy(&task, task.spawn.as_ref().unwrap(), &engine.base_env)
        .expect("a policy");
    use crate::proc_policy::Verdict;
    assert_eq!(
        policy.decide(
            &["/nix/store/demo/bin/sh".to_string()],
            "/nix/store/demo/bin/psql"
        ),
        Verdict::Allow,
        "the node must govern the program the script is entered as, wherever it was spelled \
         from"
    );
    // The other half of the declaration still holds: the command may run the script under the
    // relative name it was written with, because a *target* is matched against the path the
    // process asked for, not against `/proc/<pid>/exe`.
    assert_eq!(
        policy.decide(&["/bin/sh".to_string()], "./build.sh"),
        Verdict::Allow
    );
    // And the node grants only what it names — the guard cannot be satisfied by admitting
    // everything the interpreter reaches for.
    assert_eq!(
        policy.decide(
            &["/nix/store/demo/bin/sh".to_string()],
            "/nix/store/demo/bin/less"
        ),
        Verdict::Deny
    );
}

/// The value the graph exists for: a chain is permitted without the shortcut a flat set would
/// grant. The command may run `less` and only `less`; `less` may run `psql`; the command may
/// **not** run `psql` itself, which is precisely what naming all three in one list would allow.
#[test]
fn a_node_permits_a_chain_without_granting_the_shortcut() {
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.cmd = vec!["/bin/sh".to_string()];
    task.spawn = Some(vec!["less".to_string()]);
    task.exec = [("less".to_string(), vec!["psql".to_string()])]
        .into_iter()
        .collect();
    let engine = engine_with_store(root.path(), &["psql", "less"], vec![task.clone()]);

    let policy = engine
        .spawn_policy(&task, task.spawn.as_ref().unwrap(), &engine.base_env)
        .expect("a policy");
    use crate::proc_policy::Verdict;
    let command = ["/bin/sh".to_string()];
    let less = ["/nix/store/demo/bin/less".to_string()];
    assert_eq!(
        policy.decide(&command, "/nix/store/demo/bin/less"),
        Verdict::Allow
    );
    assert_eq!(
        policy.decide(&less, "/nix/store/demo/bin/psql"),
        Verdict::Allow,
        "the node is what makes the chain reachable"
    );
    assert_eq!(
        policy.decide(&command, "/nix/store/demo/bin/psql"),
        Verdict::Deny,
        "permitting a chain must not grant the command the far end of it"
    );
}

/// Nested mounts: the innermost is the one the kernel resolves through, so translation must pick
/// the longest match rather than the first.
#[test]
fn translating_an_in_cage_path_prefers_the_innermost_mount() {
    let root = crate::testutil::TmpDir::new();
    let mut engine = engine_with_store(root.path(), &[], vec![task()]);
    engine.base_mounts = vec![
        Mount::RoBind {
            src: PathBuf::from("/host/outer"),
            dest: PathBuf::from("/opt"),
        },
        Mount::RoBind {
            src: PathBuf::from("/host/inner"),
            dest: PathBuf::from("/opt/sbx/tools"),
        },
    ];
    assert_eq!(
        engine.host_path(Path::new("/opt/sbx/tools/bin/x"), &task()),
        Some(PathBuf::from("/host/inner/bin/x"))
    );
    assert_eq!(
        engine.host_path(Path::new("/opt/other"), &task()),
        Some(PathBuf::from("/host/outer/other"))
    );
    assert_eq!(
        engine.host_path(Path::new("/elsewhere"), &task()),
        None,
        "a path under no mount has no host counterpart — the cage is hermetic"
    );
}

/// An engine whose project really exists on disk, since the output directory is keyed on the
/// project's canonical path.
fn engine_with_project(root: &Path, tasks: Vec<TaskSpec>) -> TaskEngine {
    let project = root.join("project");
    std::fs::create_dir_all(&project).expect("the project");
    let mut engine = engine_at(root, tasks);
    engine.project = project;
    engine
}

/// A task declaring `output` gets exactly one writable mount, and it is the directory the claim
/// created — the single path in an otherwise ephemeral cage whose contents outlive the run.
#[test]
fn a_task_declaring_output_gets_one_writable_directory() {
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.output = true;
    let engine = engine_with_project(root.path(), vec![task.clone()]);

    let claim = engine.claim_output(&task).expect("the claim");
    let spec = engine
        .build_spec(
            vec![OsString::from("psql")],
            &engine.base_env,
            &task,
            &Invocation {
                number: 3,
                proxy_binds: &[],
                tcp: &Default::default(),
                output: Some(claim.dir.as_path()),
            },
        )
        .expect("the spec");

    let writable: Vec<_> = spec
        .mounts()
        .iter()
        .filter_map(|m| match m {
            Mount::Bind { src, dest } => Some((src.clone(), dest.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        writable,
        vec![(claim.dir.clone(), PathBuf::from(TASK_OUT_INCAGE))],
        "the output directory must be the only writable bind: {:?}",
        spec.mounts()
    );
}

/// And a task that declares none gets no writable path at all — the property the whole task cage
/// rests on, which the new mount must not quietly relax.
#[test]
fn a_task_without_output_keeps_a_cage_it_cannot_write() {
    let root = crate::testutil::TmpDir::new();
    let task = task();
    let engine = engine_with_project(root.path(), vec![task.clone()]);
    let spec = engine
        .build_spec(
            vec![OsString::from("psql")],
            &engine.base_env,
            &task,
            &Invocation {
                number: 4,
                proxy_binds: &[],
                tcp: &Default::default(),
                output: None,
            },
        )
        .expect("the spec");
    assert!(
        !spec
            .mounts()
            .iter()
            .any(|m| matches!(m, Mount::Bind { .. })),
        "nothing writable belongs in a task cage that asked for nothing: {:?}",
        spec.mounts()
    );
}

/// The directory is emptied when it is claimed. A predictable path is only honest if what sits
/// there is this invocation's work — otherwise a caller reads yesterday's artifact and cannot
/// tell.
#[test]
fn claiming_the_directory_clears_what_a_previous_invocation_left() {
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.output = true;
    let engine = engine_with_project(root.path(), vec![task.clone()]);

    let first = engine.claim_output(&task).expect("the first claim");
    std::fs::write(first.dir.join("stale.sql"), b"yesterday").expect("write");
    assert_eq!(first.size(), 9, "the size reports what is really there");
    drop(first);

    let second = engine.claim_output(&task).expect("the second claim");
    assert!(
        !second.dir.join("stale.sql").exists(),
        "a claim must not hand back the previous invocation's artifact"
    );
    assert_eq!(second.size(), 0);
}

/// Two invocations of the same task would write into one directory, so the second is refused
/// while the first holds it — and the hold is released when the invocation ends, however it ends.
#[test]
fn a_second_invocation_of_the_same_task_is_refused_while_the_first_holds_it() {
    let root = crate::testutil::TmpDir::new();
    let mut task = task();
    task.output = true;
    let engine = engine_with_project(root.path(), vec![task.clone()]);

    let held = engine.claim_output(&task).expect("the first claim");
    let e = engine.claim_output(&task).unwrap_err();
    assert!(e.contains("still writing"), "the refusal must say why: {e}");
    drop(held);
    engine
        .claim_output(&task)
        .expect("the hold is released with the invocation");
}

/// A destination plan for one `tcp://` rule, built the way a launch builds it.
fn tcp_plan(rule: &str) -> (Vec<crate::allowlist::Rule>, super::super::egress::TcpPlan) {
    let rules = vec![crate::allowlist::classify(rule).expect("a valid rule")];
    let policy = crate::allowlist::EgressPolicy::new(rules.clone(), Vec::new());
    (rules, super::super::egress::tcp_destinations(&policy))
}

/// A networked task resolves names through a hosts file of **its own**, bound over the one it
/// inherited. The inherited file maps the agent's destinations; a task's `network` is its own
/// declaration, so reading the agent's would let a task reach a name it never declared — and
/// miss the ones it did.
#[test]
fn a_networked_task_resolves_through_a_hosts_file_of_its_own() {
    let data = crate::testutil::TmpDir::new();
    let (rules, tcp) = tcp_plan("tcp://db.internal:5432");
    let mut networked = task();
    networked.network = rules;
    let engine = engine_at(data.path(), vec![networked.clone()]);

    let spec = engine
        .build_spec(
            vec![OsString::from("psql")],
            &engine.base_env,
            &networked,
            &Invocation {
                number: 7,
                proxy_binds: &[],
                tcp: &tcp,
                output: None,
            },
        )
        .expect("the spec");

    let hosts_mounts: Vec<_> = spec
        .mounts()
        .iter()
        .enumerate()
        .filter(|(_, m)| mount_dest(m) == Path::new("/etc/hosts"))
        .collect();
    assert_eq!(
        hosts_mounts.len(),
        2,
        "the task's own hosts file must be bound over the inherited one, not replace it in \
         place: {:?}",
        spec.mounts()
    );
    let (_, last) = hosts_mounts.last().expect("the winning mount");
    let src = match last {
        Mount::RoBind { src, .. } => src.clone(),
        other => panic!("the hosts file must be read-only in the cage: {other:?}"),
    };
    assert!(
        src.starts_with(data.join("egress")),
        "the task's hosts file belongs with the invocation's other runtime files, so gc \
         sweeps it: {src:?}"
    );
    let body = std::fs::read_to_string(&src).expect("the hosts file");
    assert!(
        body.contains("db.internal"),
        "the declared destination must be mapped: {body}"
    );
}

/// A task that declares no `tcp://` destination has nothing of its own to map, and keeps the
/// inherited file rather than being handed an emptier one.
#[test]
fn a_task_with_nothing_to_map_keeps_the_inherited_hosts_file() {
    let data = crate::testutil::TmpDir::new();
    let plain = task();
    let engine = engine_at(data.path(), vec![plain.clone()]);
    let spec = engine
        .build_spec(
            vec![OsString::from("psql")],
            &engine.base_env,
            &plain,
            &Invocation {
                number: 8,
                proxy_binds: &[],
                tcp: &Default::default(),
                output: None,
            },
        )
        .expect("the spec");
    assert_eq!(
        spec.mounts()
            .iter()
            .filter(|m| mount_dest(m) == Path::new("/etc/hosts"))
            .count(),
        1,
        "no destination to map means no second hosts file: {:?}",
        spec.mounts()
    );
}

/// If that file cannot be written the launch is refused — never run against the inherited
/// mapping, under which a declared name silently resolves elsewhere or not at all. The message
/// names the file, so an operator can see which directory failed them.
#[test]
fn a_hosts_file_that_cannot_be_written_refuses_the_task() {
    let data = crate::testutil::TmpDir::new();
    let (rules, tcp) = tcp_plan("tcp://db.internal:5432");
    let mut networked = task();
    networked.network = rules;
    let engine = engine_at(data.path(), vec![networked.clone()]);

    // A directory where the file goes: the write then fails for any uid, root included. The
    // invocation number is this test's alone — the pid in the name is shared with every other
    // test in the binary.
    let invocation = 9_000_001;
    let planted = data
        .join("egress")
        .join(format!("hosts-{}.t{invocation}", std::process::id()));
    std::fs::create_dir(&planted).expect("the planted directory");

    let err = engine
        .build_spec(
            vec![OsString::from("psql")],
            &engine.base_env,
            &networked,
            &Invocation {
                number: invocation,
                proxy_binds: &[],
                tcp: &tcp,
                output: None,
            },
        )
        .expect_err("a hosts file that cannot be written must refuse the launch");
    assert!(
        err.contains(&planted.display().to_string()),
        "the message must name the file it could not write: {err}"
    );
}

/// A task that declares a tool gets the pool — read-only, at the path the install used — and
/// that tool's directory at the *front* of its `PATH`. Read-only is the point: the pool is what
/// makes a `mise:` tool's provenance trustworthy, and a writable one would give that back.
#[test]
fn a_task_declaring_a_tool_gets_the_pool_read_only_and_on_its_path() {
    let base = crate::testutil::TmpDir::new();
    let pool = base.join("task-mise");
    std::fs::create_dir_all(pool.join("installs/demo-tool/1.0/bin")).unwrap();
    std::fs::create_dir_all(pool.join("config")).unwrap();
    std::fs::write(
        pool.join("config/config.toml"),
        "[tools]\ndemo-tool = \"latest\"\n",
    )
    .unwrap();

    let mut task = task();
    task.packages = vec!["demo-tool".to_string()];
    let engine = engine_with_pool(&pool, vec![task.clone()]);

    let spec = engine
        .build_spec(
            vec![OsString::from("demo-tool")],
            &engine.base_env,
            &task,
            &Invocation {
                number: 0,
                proxy_binds: &[],
                tcp: &Default::default(),
                output: None,
            },
        )
        .unwrap();
    assert!(
        spec.mounts().contains(&Mount::RoBind {
            src: pool.clone(),
            dest: PathBuf::from(super::super::taskpool::POOL_INCAGE),
        }),
        "the pool must be bound READ-ONLY at the install path: {:?}",
        spec.mounts()
    );

    let mut env = engine.base_env.clone();
    prepend_path(&mut env, &engine.pool_bins(&task).unwrap());
    assert_eq!(
        env.iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.as_str()),
        Some("/opt/sbx/task-mise/shims:/nix/store/base/bin"),
        "a declared tool wins over the base userland on a name collision"
    );
}

/// A task that declares nothing sees no pool at all — the mount is conditional on the
/// declaration, so an unrelated task is not handed the other tasks' tools.
#[test]
fn a_task_declaring_no_tool_gets_no_pool_mount() {
    let base = crate::testutil::TmpDir::new();
    let pool = base.join("task-mise");
    std::fs::create_dir_all(pool.join("installs/demo-tool/1.0/bin")).unwrap();
    std::fs::create_dir_all(pool.join("config")).unwrap();
    std::fs::write(
        pool.join("config/config.toml"),
        "[tools]\ndemo-tool = \"latest\"\n",
    )
    .unwrap();

    let task = task();
    let engine = engine_with_pool(&pool, vec![task.clone()]);
    let spec = engine
        .build_spec(
            vec![OsString::from("psql")],
            &engine.base_env,
            &task,
            &Invocation {
                number: 0,
                proxy_binds: &[],
                tcp: &Default::default(),
                output: None,
            },
        )
        .unwrap();
    assert!(
        !spec
            .mounts()
            .iter()
            .any(|m| mount_dest(m) == Path::new(super::super::taskpool::POOL_INCAGE)),
        "a task with no declared tool must not see the pool"
    );
    assert!(engine.pool_bins(&task).is_none());
}

/// The union across tasks is what the pool must hold, deduplicated — one install for a tool two
/// tasks share.
#[test]
fn the_pool_holds_the_union_of_every_tasks_tools() {
    let base = crate::testutil::TmpDir::new();
    let mut a = task();
    a.name = "a".into();
    a.packages = vec!["node@22".into(), "aqua:cli/gh".into()];
    let mut b = task();
    b.name = "b".into();
    b.packages = vec!["node@22".into(), "jq".into()];
    let engine = engine_with_pool(&base.join("task-mise"), vec![a, b]);
    assert_eq!(
        engine.declared_packages(),
        vec![
            "node@22".to_string(),
            "aqua:cli/gh".to_string(),
            "jq".to_string()
        ]
    );
}

/// A tool the pool does not hold is reported rather than turned into a dangling path entry: the
/// command then fails with a plain "not found", which is what actually happened.
#[test]
fn a_tool_absent_from_the_pool_is_reported_not_papered_over() {
    let base = crate::testutil::TmpDir::new();
    let mut task = task();
    task.packages = vec!["absent-tool".to_string()];
    let engine = engine_with_pool(&base.join("task-mise"), vec![task.clone()]);
    assert_eq!(
        engine.missing_packages(&task),
        vec!["absent-tool".to_string()]
    );
    assert!(engine.pool_bins(&task).is_none());
}

// A credential's every spelling is a needle under the variable's own name, so a value that
// reaches the output — plaintext or encoded — comes back as `${VAR}`.
#[test]
fn a_credentials_variants_are_all_named_after_the_variable() {
    let secret = TaskSecret {
        var: "PGPASSWORD".into(),
        sources: vec![],
        encode: Encoding::Base64,
        description: None,
    };
    let needles: Vec<SecretNeedle> = secret
        .encode
        .variants("hunter2-hunter2")
        .into_iter()
        .map(|b| SecretNeedle::named(&secret.var, b))
        .collect();
    let (out, hits) = redact_named(
        b"plain=hunter2-hunter2 b64=aHVudGVyMi1odW50ZXIy",
        &needles,
        &Placeholder::Plain,
    );
    assert_eq!(out, b"plain=${PGPASSWORD} b64=${PGPASSWORD}");
    assert_eq!(hits, 2);
}
