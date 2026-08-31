use super::*;

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
