use super::schema::{RawEnvDefaults, RawFileDefaults, RawSecretSection, RawSopsDefaults};
use super::*;
use crate::testutil::TmpDir;
use std::collections::BTreeMap;

#[test]
fn a_mise_nix_package_warns_to_use_the_plain_nix_backend() {
    // `mise:nix:<pkg>` routes `nix:` content through the mise backend, whose Lane-1 pin lands the
    // install record app-global while the store path is per-project — the misalignment the split
    // otherwise fixes. Warn, pointing at the aligned `nix:<pkg>` form; only for a *trusted* package
    // (a withheld one never equips), and never for a real shared mise backend or a plain `nix:`.
    let pkgs = vec![
        Package {
            name: "jq".into(),
            backend: Backend::Mise("nix:jq".into()),
            state: TrustState::Trusted,
        },
        Package {
            name: "rg".into(),
            backend: Backend::Mise("aqua:BurntSushi/ripgrep".into()),
            state: TrustState::Trusted,
        },
        Package {
            name: "hello".into(),
            backend: Backend::Nix("hello".into()),
            state: TrustState::Trusted,
        },
        Package {
            name: "fd".into(),
            backend: Backend::Mise("nix:fd".into()),
            state: TrustState::Untrusted,
        },
    ];
    let mut warnings = Vec::new();
    warn_mise_nix_packages("app `demo` ", &pkgs, &mut warnings);

    assert_eq!(
        warnings.len(),
        1,
        "only the trusted mise:nix: package warns: {warnings:?}"
    );
    let w = &warnings[0];
    assert!(w.contains("app `demo` package `jq`"), "{w}");
    assert!(w.contains("mise:nix:jq"), "{w}");
    assert!(w.contains("nix:jq"), "it points at the aligned form: {w}");
    // a shared mise backend, a plain nix:, and a withheld mise:nix: are all silent
    assert!(
        !w.contains("ripgrep") && !w.contains("hello") && !w.contains("fd"),
        "{w}"
    );
}

/// Test shim: [`super::validate_network`] with no egress groups and the built-in `Shared`
/// default as the inheritance parent — the common case in these unit tests. It shadows the
/// glob-imported real function so the many bare 3-argument calls read as before; the
/// `[net.groups]` expansion and the mode-inheritance tests call `super::validate_network`
/// directly with a populated group table or a specific parent posture.
fn validate_network(
    warnings: &mut Vec<String>,
    source_label: &str,
    field: NetworkField,
) -> Option<NetworkPolicy> {
    super::validate_network(
        warnings,
        source_label,
        field,
        &NetGroups::new(),
        &NetworkPolicy::default(),
    )
}

fn raw(env: &[(&str, &str)], binds: &[&str]) -> RawConfig {
    RawConfig {
        notify: None,
        rest: Default::default(),
        task: None,
        env: env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        binds: binds.iter().map(|s| RawBind::Path(s.to_string())).collect(),
        packages: BTreeMap::new(),
        bundle: BTreeMap::new(),
        flakes: BTreeMap::new(),
        tarball: BTreeMap::new(),
        deb: BTreeMap::new(),
        appimage: BTreeMap::new(),
        nixpkgs: None,
        network: None,
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        forward: None,
        secret: None,
        app: BTreeMap::new(),
        limits: None,
        seccomp: None,
        devices: None,
        ssh_agent: None,
        proc: None,
        net: Default::default(),
    }
}

/// Build a `[network]` field in table form for the egress-group tests.
fn net_field(mode: &str, allow: &[&str], deny: &[&str]) -> NetworkField {
    NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        capture: None,
        capture_max_kb: None,
        mode: Some(mode.into()),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        deny: deny.iter().map(|s| s.to_string()).collect(),
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
    })
}

/// Build and pre-classify a `[net.groups]` table from `(name, entries)` pairs, returning the
/// map and any warnings `build_net_groups` emitted.
fn make_groups(defs: &[(&str, &[&str])]) -> (NetGroups, Vec<String>) {
    let mut w = Vec::new();
    let raw: BTreeMap<String, Vec<String>> = defs
        .iter()
        .map(|(n, es)| (n.to_string(), es.iter().map(|s| s.to_string()).collect()))
        .collect();
    (build_net_groups(&mut w, raw), w)
}

#[test]
fn a_group_reference_expands_in_an_allow_list() {
    let (g, gw) = make_groups(&[("mcp", &["{*} a.example.com:443", "{*} b.example.com:443"])]);
    assert!(gw.is_empty(), "a clean group builds no warnings: {gw:?}");
    let mut w = Vec::new();
    let policy = super::validate_network(
        &mut w,
        GLOBAL_CONFIG,
        net_field("deny", &["@mcp", "c.example.com:443"], &[]),
        &g,
        &NetworkPolicy::default(),
    )
    .unwrap();
    let NetworkPolicy::Allowlist(p) = policy else {
        panic!("expected an allowlist policy");
    };
    // The two group entries plus the one literal → three allow rules.
    assert_eq!(p.allow_rules().len(), 3);
    assert!(w.is_empty(), "no warnings for a resolved reference: {w:?}");
}

#[test]
fn a_group_reference_expands_in_a_deny_list_too() {
    let (g, _) = make_groups(&[("telemetry", &["*.datadoghq.com:*", "*.sentry.io:*"])]);
    let mut w = Vec::new();
    let policy = super::validate_network(
        &mut w,
        GLOBAL_CONFIG,
        net_field("allow", &[], &["@telemetry"]),
        &g,
        &NetworkPolicy::default(),
    )
    .unwrap();
    let NetworkPolicy::Allowlist(p) = policy else {
        panic!("expected an allowlist policy");
    };
    assert_eq!(p.deny_rules().len(), 2);
}

#[test]
fn a_mute_list_classifies_and_expands_groups_like_allow_deny() {
    // `mute` (`dontaudit`) reuses the allow/deny grammar and `@group` expansion, and lands on the
    // policy's mute set without touching the verdict lists.
    let (g, _) = make_groups(&[("telemetry", &["play.googleapis.com", "*.datadoghq.com"])]);
    let mut w = Vec::new();
    let field = NetworkField::Table(NetworkTable {
        mode: Some("deny".into()),
        allow: vec![],
        deny: vec![],
        mute: vec!["@telemetry".into(), "telemetry.example.com".into()],
        http2: vec![],
        capture: None,
        capture_max_kb: None,
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
    });
    let policy =
        super::validate_network(&mut w, GLOBAL_CONFIG, field, &g, &NetworkPolicy::default())
            .unwrap();
    let NetworkPolicy::Allowlist(p) = policy else {
        panic!("expected an allowlist policy");
    };
    // Two group entries + one literal → three mute rules; the verdict lists stay empty.
    assert_eq!(p.mute_rules().len(), 3);
    assert!(p.allow_rules().is_empty() && p.deny_rules().is_empty());
    assert!(w.is_empty(), "a clean mute list warns nothing: {w:?}");
}

#[test]
fn an_undefined_group_reference_is_dropped_with_a_loud_warning() {
    let (g, _) = make_groups(&[("mcp", &["a.example.com:443"])]);
    let mut w = Vec::new();
    // Reference a group that does not exist, in a DENY list — the case where a silent drop
    // would fail open in intent (the host would no longer be blocked).
    let policy = super::validate_network(
        &mut w,
        GLOBAL_CONFIG,
        net_field("allow", &[], &["@telemetr"]),
        &g,
        &NetworkPolicy::default(),
    )
    .unwrap();
    let NetworkPolicy::Allowlist(p) = policy else {
        panic!("expected an allowlist policy");
    };
    assert!(
        p.deny_rules().is_empty(),
        "an unresolved reference denies nothing (fail closed)"
    );
    assert_eq!(w.len(), 1, "exactly one warning: {w:?}");
    assert!(
        w[0].contains("undefined group `@telemetr`"),
        "the warning is loud and names the reference: {}",
        w[0]
    );
    assert!(
        w[0].contains("nothing is denied"),
        "the warning spells out the deny-list consequence: {}",
        w[0]
    );
}

#[test]
fn a_group_admits_every_rule_form() {
    // A group entry is classified by the same `allowlist::classify` as a direct allow/deny entry,
    // so every rule form works inside a group: a `re:` regex, a `{VERB}`-scoped host, and a raw
    // `tcp://` L4 tunnel, on top of the host/subdomain/URL forms the other tests cover.
    let (g, w) = make_groups(&[(
        "mixed",
        &[
            "re:^https://api\\.example\\.com/v[0-9]+/",
            "{POST} write.example.com:443",
            "tcp://ssh.example.com:22",
        ],
    )]);
    assert!(w.is_empty(), "every form is valid, so no warnings: {w:?}");
    assert_eq!(
        g.get("mixed").map(|r| r.len()),
        Some(3),
        "all three forms classify into rules"
    );
}

#[test]
fn build_net_groups_validates_names_entries_and_rejects_nesting() {
    let (g, w) = make_groups(&[
        ("ok", &["good.example.com:443"]),
        ("bad name!", &["x.example.com:443"]), // invalid charset → skipped
        ("nested", &["@ok"]),                  // a nested reference → rejected
        ("malformed", &["https://*"]),         // a classify error → dropped
    ]);
    // The valid group is present with its one rule; the invalid-named one never lands.
    assert_eq!(g.get("ok").map(|r| r.len()), Some(1));
    assert!(!g.contains_key("bad name!"));
    // `nested` and `malformed` exist but drop their (only) offending entry → empty.
    assert_eq!(g.get("nested").map(|r| r.len()), Some(0));
    assert_eq!(g.get("malformed").map(|r| r.len()), Some(0));
    assert_eq!(
        w.len(),
        3,
        "one warning each for name/nesting/malformed: {w:?}"
    );
    assert!(w
        .iter()
        .any(|m| m.contains("ignoring net group `bad name!`")));
    assert!(w.iter().any(|m| m.contains("nested reference `@ok`")));
    assert!(w.iter().any(|m| m.contains("net group `malformed`")));
}

#[test]
fn an_at_sign_inside_an_entry_is_not_a_group_reference() {
    // Only a *leading* `@` is a reference; a `@` in a URL path is a normal part of the entry
    // and must classify as written, not be misread as a group reference.
    let (g, _) = make_groups(&[]);
    let mut w = Vec::new();
    let policy = super::validate_network(
        &mut w,
        GLOBAL_CONFIG,
        net_field("deny", &["example.com:443/@handle"], &[]),
        &g,
        &NetworkPolicy::default(),
    )
    .unwrap();
    let NetworkPolicy::Allowlist(p) = policy else {
        panic!("expected an allowlist policy");
    };
    assert_eq!(
        p.allow_rules().len(),
        1,
        "the URL-with-@ classifies as one rule"
    );
    assert!(w.is_empty(), "no undefined-group warning: {w:?}");
}

#[test]
fn an_app_references_a_global_egress_group() {
    // The DRY payoff, driven through the full resolve → resolve_apps → resolve_app path (not the
    // `validate_network` unit alone): a group declared once in the global config is referenced by
    // `@name` from an app declared in a *trusted project*, and the app's effective policy carries
    // the group's expanded rules — so a set of hosts is shared, not rewritten per app.
    let mut global = RawConfig::default();
    global.net.groups.insert(
        "mcp".into(),
        vec![
            "{*} a.example.com:443".into(),
            "{*} b.example.com:443".into(),
        ],
    );
    let app = raw_app(
        &["true"],
        &[],
        &[],
        &[],
        Some(net_field("deny", &["@mcp"], &[])),
    );
    let r = resolve_no_plugins(
        global,
        Some((raw_with_app("demo", app), TrustState::Trusted)),
    );
    let demo = r.apps.get("demo").expect("the app resolves");
    let Some(NetworkPolicy::Allowlist(p)) = &demo.network else {
        panic!("expected the app to carry an allowlist policy");
    };
    assert_eq!(
        p.allow_rules().len(),
        2,
        "the global group expanded into the project app's allow list"
    );
}

#[test]
fn a_project_net_groups_is_ignored_with_a_warning_even_when_trusted() {
    // Groups are global-only: a project's `[net.groups]` is not honored — even from a TRUSTED
    // project — so it warns, and a `@ref` to a project-defined group does not resolve (it is
    // undefined). This is the security property: a project cannot smuggle a group definition into
    // an app's egress, only reference one the global config already trusts.
    let mut project = RawConfig::default();
    project
        .net
        .groups
        .insert("evil".into(), vec!["evil.example.com:443".into()]);
    // An app in the same (trusted) project references its own project-defined group.
    project.app.insert(
        "demo".into(),
        raw_app(
            &["true"],
            &[],
            &[],
            &[],
            Some(net_field("deny", &["@evil"], &[])),
        ),
    );

    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
    // The baseline warns that the project's `[net.groups]` is ignored.
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("[net.groups]") && w.contains("global config only")),
        "a project's [net.groups] must warn: {:?}",
        r.warnings
    );
    // The app's `@evil` reference resolves to nothing (the group is undefined from a project),
    // and the app reports the reference as undefined.
    let demo = r.apps.get("demo").expect("the app resolves");
    let Some(NetworkPolicy::Allowlist(p)) = &demo.network else {
        panic!("expected the app to carry an allowlist policy");
    };
    assert!(
        p.allow_rules().is_empty(),
        "a project-defined group must not resolve: {:?}",
        p.allow_rules()
    );
    assert!(
        demo.warnings
            .iter()
            .any(|w| w.contains("undefined group `@evil`")),
        "the @evil reference must be reported undefined: {:?}",
        demo.warnings
    );
}

#[test]
fn a_bare_group_entry_inherits_the_apps_read_by_default_posture() {
    use crate::allowlist::Methods;
    // Security-relevant: a *method-less* group entry (the common case) must receive the Mode-B
    // app's read-by-default `{GET,HEAD}` posture at merge, exactly like a directly-written bare
    // host — otherwise a group would be a way to open a POST endpoint that a directly-written
    // entry would have kept read-only. `apply_default_methods` runs in `merge_app`, so this drives
    // the full resolve → merge_app path (past where the DRY test above stops, at `resolve_app`).
    let mut global = RawConfig::default();
    global
        .net
        .groups
        .insert("mcp".into(), vec!["m.example.com:443".into()]); // bare: no `{VERB}` prefix
    let app = raw_app(
        &["true"],
        &[],
        &[],
        &[],
        Some(net_field("deny", &["@mcp"], &[])),
    );
    let mut r = resolve_no_plugins(
        global,
        Some((raw_with_app("demo", app), TrustState::Trusted)),
    );
    let demo = r.apps.remove("demo").expect("the app resolves");
    r.merge_app(demo);
    let NetworkPolicy::Allowlist(p) = &r.network else {
        panic!("expected the merged app to carry an allowlist policy");
    };
    assert_eq!(
        p.allow_rules()[0].methods,
        Methods::Only(vec!["GET".into(), "HEAD".into()]),
        "a bare group entry inherits the app's {{GET,HEAD}} read-by-default posture, not all verbs"
    );
}

#[test]
fn read_net_groups_fragment_reads_groups_and_rejects_a_groupless_file() {
    let tmp = TmpDir::new();
    let good = tmp.path().join("frag.toml");
    std::fs::write(&good, "[net.groups]\nmcp = [\"{*} a.example.com:443\"]\n").unwrap();
    let g = read_net_groups_fragment(&good).expect("a `[net.groups]` fragment reads");
    assert_eq!(g.get("mcp").map(|v| v.len()), Some(1));

    // A file with no `[net.groups]` is the tell-tale of the wrong file — refused, not a silent
    // empty import.
    let bad = tmp.path().join("nope.toml");
    std::fs::write(&bad, "[env]\nFOO = \"bar\"\n").unwrap();
    let err = read_net_groups_fragment(&bad).unwrap_err();
    assert!(err.contains("no `[net.groups]`"), "{err}");
}

/// A resolved read-only bind at `path` (what `resolve` produces from a bare-string bind,
/// before `load`'s canonicalization).
fn ro_bind(path: &str) -> Bind {
    Bind {
        path: PathBuf::from(path),
        writable: false,
    }
}

/// A resolved read-write bind at `path` (what `resolve` produces from a `mode = "rw"` table).
fn rw_bind(path: &str) -> Bind {
    Bind {
        path: PathBuf::from(path),
        writable: true,
    }
}

/// A `RawConfig` declaring only `packages` (as `name -> attr`).
fn raw_packages(packages: &[(&str, &str)]) -> RawConfig {
    RawConfig {
        packages: packages
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring only a `nixpkgs` override.
fn raw_nixpkgs(source: &str) -> RawConfig {
    RawConfig {
        nixpkgs: Some(source.to_string()),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring only a `network` posture (string form).
fn raw_network(value: &str) -> RawConfig {
    RawConfig {
        network: Some(NetworkField::Posture(value.to_string())),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring a `network` allowlist (table form) with allow and deny lists.
fn raw_network_table(allow: &[&str], deny: &[&str]) -> RawConfig {
    RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".to_string()),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring only an allow list (no deny).
fn raw_network_allow(allow: &[&str]) -> RawConfig {
    raw_network_table(allow, &[])
}

/// A `RawConfig` declaring only a `gui` posture.
fn raw_gui(value: &str) -> RawConfig {
    RawConfig {
        gui: Some(value.to_string()),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring `forward` ports.
fn raw_forward(ports: &[u16]) -> RawConfig {
    RawConfig {
        forward: Some(ports.to_vec()),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring a `[devices] allow` list from the given paths.
fn raw_devices(paths: &[&str]) -> RawConfig {
    RawConfig {
        devices: Some(schema::RawDevices {
            rest: Default::default(),
            allow: paths.iter().map(|s| s.to_string()).collect(),
        }),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring an `[ssh_agent] allow` list from the given key identifiers.
fn raw_ssh_agent(keys: &[&str]) -> RawConfig {
    RawConfig {
        ssh_agent: Some(schema::RawSshAgent {
            confirm: None,
            rest: Default::default(),
            allow: keys.iter().map(|s| s.to_string()).collect(),
        }),
        ..RawConfig::default()
    }
}

fn raw_seccomp(tokens: &[&str]) -> RawConfig {
    RawConfig {
        seccomp: Some(schema::RawSeccomp {
            rest: Default::default(),
            allow: tokens.iter().map(|s| s.to_string()).collect(),
        }),
        ..RawConfig::default()
    }
}

/// A `RawConfig` declaring a `[limits]` table from optional string tokens (each `None` leaves
/// that field unset, falling back to the default).
fn raw_limits(
    memory_high: Option<&str>,
    memory_max: Option<&str>,
    tasks_max: Option<&str>,
) -> RawConfig {
    let text = |o: Option<&str>| o.map(|s| schema::RawLimit::Text(s.to_string()));
    RawConfig {
        limits: Some(schema::RawLimits {
            rest: Default::default(),
            memory_high: text(memory_high),
            memory_max: text(memory_max),
            tasks_max: text(tasks_max),
        }),
        ..RawConfig::default()
    }
}

/// A `RawApp` from its parts, for the app-layering tests.
fn raw_app(
    cmd: &[&str],
    env: &[(&str, &str)],
    binds: &[&str],
    packages: &[(&str, &str)],
    network: Option<NetworkField>,
) -> RawApp {
    RawApp {
        notify: None,
        ssh_agent: None,
        task: None,
        cmd: if cmd.is_empty() {
            None
        } else {
            Some(schema::RawCmd::Argv(
                cmd.iter().map(|s| s.to_string()).collect(),
            ))
        },
        uses: Vec::new(),
        env: env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        binds: binds.iter().map(|s| RawBind::Path(s.to_string())).collect(),
        packages: packages
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        flakes: BTreeMap::new(),
        tarball: BTreeMap::new(),
        deb: BTreeMap::new(),
        appimage: BTreeMap::new(),
        network,
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        forward: None,
        secret: None,
        limits: None,
        seccomp: None,
        devices: None,
        proc: None,
        home_scope: None,
    }
}

/// A `RawConfig` declaring a single `[app.<name>]`.
fn raw_with_app(name: &str, app: RawApp) -> RawConfig {
    RawConfig {
        app: std::iter::once((name.to_string(), app)).collect(),
        ..RawConfig::default()
    }
}

/// A `HeaderSecret` with an explicit `env://` source, for the overlay-merge tests (no
/// dependence on the default resolver order).
fn a_header_secret() -> HeaderSecret {
    let raw = RawHostSecret {
        name: None,
        description: None,
        kind: None,
        key: None,
        from: Some(SecretFrom::One("env://TOKEN".into())),
        header: Some("Authorization".into()),
        value_type: Some("bearer".into()),
        prefix: None,
    };
    validate(raw).unwrap()
}

#[test]
fn an_app_layers_global_under_project_overriding_the_command_and_unioning_fields() {
    let global = raw_with_app(
        "demo-app",
        raw_app(
            &["demo-app"],
            &[("BASE", "g")],
            &[],
            &[("tool", "nix:ripgrep")],
            None,
        ),
    );
    let project = raw_with_app(
        "demo-app",
        raw_app(&["demo-app", "--resume"], &[("EXTRA", "p")], &[], &[], None),
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    let app = &r.apps["demo-app"];
    // The project's command wins; the global one is replaced, not appended.
    assert_eq!(
        app.cmd,
        vec!["demo-app".to_string(), "--resume".to_string()]
    );
    // Free env is unioned across both layers.
    assert!(app.env.iter().any(|(k, v)| k == "BASE" && v == "g"));
    assert!(app.env.iter().any(|(k, v)| k == "EXTRA" && v == "p"));
    // The global package is carried, trusted by location.
    assert!(app
        .packages
        .iter()
        .any(|p| p.name == "tool" && p.state == TrustState::Trusted));
}

#[test]
fn an_untrusted_project_apps_security_fields_drop_but_env_packages_and_command_survive() {
    let project = raw_with_app(
        "probe",
        raw_app(
            &["id"],
            &[("OK", "v")],
            &["/etc/secret"],
            &[("pkg", "nix:ripgrep")],
            allowlist_net(&["x.com"]),
        ),
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["probe"];
    // Security fields drop under an untrusted project.
    assert!(app.binds.is_empty(), "binds must drop");
    assert!(app.network.is_none(), "network must drop");
    // Free fields and the command survive; the package is carried, stamped untrusted, for
    // the launcher to weigh.
    assert_eq!(app.cmd, vec!["id".to_string()]);
    assert!(app.env.iter().any(|(k, _)| k == "OK"));
    assert!(app
        .packages
        .iter()
        .any(|p| p.name == "pkg" && p.state == TrustState::Untrusted));
    // The drops are explained.
    assert!(app.warnings.iter().any(|w| w.contains("bind")));
    assert!(app.warnings.iter().any(|w| w.contains("network")));
}

#[test]
fn an_untrusted_project_app_cannot_widen_its_default_methods() {
    // The flagship-analog for `default_methods`: the override rides the trusted-only `[network]`
    // block, so an untrusted project app's `["*"]` widen attempt is dropped with the network —
    // the app falls to the built-in `{GET,HEAD}`, never all-verbs. (Read-by-default only ever
    // tightens; the only direction an untrusted layer could abuse is widening, which it cannot.)
    let net = NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        capture: None,
        capture_max_kb: None,
        mode: Some("deny".into()),
        allow: vec!["x.com".into()],
        deny: vec![],
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: Some(vec!["*".into()]),
        dns_cache_ttl: None,
    });
    let project = raw_with_app("probe", raw_app(&["id"], &[], &[], &[], Some(net)));
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["probe"];
    assert!(
        app.network.is_none(),
        "the untrusted network (and its default_methods override) is dropped"
    );
    assert_eq!(
        app.default_methods,
        builtin_app_default_methods(),
        "an untrusted app cannot widen to all-verbs — it keeps the built-in {{GET,HEAD}}"
    );
}

#[test]
fn an_untrusted_project_cannot_override_a_trusted_apps_command() {
    // The integrity-of-intent guard: `sbx app demo-app` against an untrusted repo must run
    // the trusted app's command, never one the repo substituted.
    let global = raw_with_app("demo-app", raw_app(&["demo-app"], &[], &[], &[], None));
    let project = raw_with_app("demo-app", raw_app(&["evil"], &[], &[], &[], None));
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    assert_eq!(app.cmd, vec!["demo-app".to_string()]);
    assert!(app.warnings.iter().any(|w| w.contains("cmd")));

    // A trusted project, by contrast, may override the command.
    let global = raw_with_app("demo-app", raw_app(&["demo-app"], &[], &[], &[], None));
    let project = raw_with_app(
        "demo-app",
        raw_app(&["demo-app", "--resume"], &[], &[], &[], None),
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert_eq!(
        r.apps["demo-app"].cmd,
        vec!["demo-app".to_string(), "--resume".to_string()]
    );
}

#[test]
fn an_untrusted_project_cannot_override_a_trusted_apps_package() {
    // The package half of the integrity-of-intent guard (mirror of `cmd`): `sbx app demo-app`
    // against an untrusted repo must keep the trusted app's tool, never one the repo
    // substituted — else the repo could deny the app its tool, or aim it at an attacker's.
    let global = raw_with_app(
        "demo-app",
        raw_app(
            &["demo-app"],
            &[],
            &[],
            &[("demo-tool", "mise:aqua:example/demo-tool")],
            None,
        ),
    );
    let project = raw_with_app(
        "demo-app",
        raw_app(
            &["demo-app"],
            &[],
            &[],
            &[("demo-tool", "mise:aqua:attacker/x")],
            None,
        ),
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    let p = app
        .packages
        .iter()
        .find(|p| p.name == "demo-tool")
        .expect("the app's package survives");
    // The trusted token survives, still trusted; the attacker's is refused with a warning.
    assert_eq!(p.backend, Backend::Mise("aqua:example/demo-tool".into()));
    assert_eq!(p.state, TrustState::Trusted);
    assert!(app
        .warnings
        .iter()
        .any(|w| w.contains("demo-tool") && w.contains("override")));
    // Security teeth: the attacker's token is not merely lower-priority — it is absent, so it
    // can never reach `mise use -g`. Exactly one `demo-tool`, and it is the trusted one.
    assert_eq!(
        app.packages
            .iter()
            .filter(|p| p.name == "demo-tool")
            .count(),
        1
    );
    assert!(
        !app.packages
            .iter()
            .any(|p| p.backend == Backend::Mise("aqua:attacker/x".into())),
        "the attacker token must be absent, never carried"
    );

    // A trusted project, by contrast, may override the package by name.
    let global = raw_with_app(
        "demo-app",
        raw_app(
            &["demo-app"],
            &[],
            &[],
            &[("demo-tool", "mise:aqua:example/demo-tool")],
            None,
        ),
    );
    let project = raw_with_app(
        "demo-app",
        raw_app(
            &["demo-app"],
            &[],
            &[],
            &[("demo-tool", "nix:demo-tool")],
            None,
        ),
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    let p = r.apps["demo-app"]
        .packages
        .iter()
        .find(|p| p.name == "demo-tool")
        .unwrap();
    assert_eq!(p.backend, Backend::Nix("demo-tool".into()));
}

#[test]
fn network_modes_set_the_egress_default_action() {
    use crate::allowlist::DefaultAction;
    let mut w = Vec::new();
    let tbl = |mode: &str, allow: &[&str], deny: &[&str]| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some(mode.into()),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })
    };

    // Bare-string `deny`/`allow` map to a filtered policy with the matching default action and
    // no carve-out lists.
    let deny =
        validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("deny".into())).unwrap();
    let allow =
        validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("allow".into())).unwrap();
    assert!(matches!(
        &deny,
        NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Deny && p.allow_rules().is_empty()
    ));
    assert!(matches!(
        &allow,
        NetworkPolicy::Allowlist(p) if p.default_action() == DefaultAction::Allow
    ));

    // Table form: `allow` mode carries the deny carve-outs and allow-by-default.
    let allow_tbl =
        validate_network(&mut w, GLOBAL_CONFIG, tbl("allow", &[], &["evil.com"])).unwrap();
    assert!(matches!(
        &allow_tbl,
        NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Allow && p.deny_rules().len() == 1
    ));

    assert!(w.is_empty(), "every valid mode warns nothing: {w:?}");

    // An unknown mode warns and yields nothing. This is *not* fail-closed: a dropped network
    // field resolves to `NetworkPolicy::default()` == `Shared` (the open host network), so an
    // invalid posture reopens the network — which is why the warning must be loud.
    assert!(
        validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("yolo".into())).is_none()
    );
    assert!(
        w.len() == 1 && w[0].contains("yolo"),
        "unknown mode must warn: {w:?}"
    );

    // `allowlist` was removed as an alias of `deny`; the table form now rejects it as an unknown
    // mode, by name (a future re-add of the arm without the message would fail this).
    let mut wr = Vec::new();
    assert!(
        validate_network(
            &mut wr,
            GLOBAL_CONFIG,
            tbl("allowlist", &["github.com"], &[])
        )
        .is_none(),
        "`allowlist` is no longer a valid mode"
    );
    assert!(
        wr.iter().any(|m| m.contains("unknown network mode")),
        "rejecting `allowlist` must warn by name: {wr:?}"
    );
}

#[test]
fn a_mode_less_table_inherits_a_filtering_parent_and_keeps_its_own_rules() {
    use crate::allowlist::{DefaultAction, EgressPolicy};
    // A `[network]` table that lists a rule but omits `mode`.
    let no_mode = || {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: None,
            allow: vec!["api.foo.com".to_string()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })
    };
    let filtering = |action| NetworkPolicy::Allowlist(EgressPolicy::default().with_default(action));
    // Resolve the mode-less table against a given parent, asserting the effective default action
    // and that the table's own allow rule survives (inheritance is of the mode only).
    let effective = |parent: &NetworkPolicy| {
        let mut w = Vec::new();
        let p =
            super::validate_network(&mut w, GLOBAL_CONFIG, no_mode(), &NetGroups::new(), parent)
                .unwrap();
        let NetworkPolicy::Allowlist(pol) = p else {
            panic!("a mode-less table always resolves to a filtering policy")
        };
        assert_eq!(pol.allow_rules().len(), 1, "the table keeps its own rule");
        assert!(w.is_empty(), "inheriting a mode warns nothing: {w:?}");
        pol.default_action()
    };
    // A filtering `deny`/`ask` parent is inherited.
    assert_eq!(
        effective(&filtering(DefaultAction::Deny)),
        DefaultAction::Deny
    );
    assert_eq!(
        effective(&filtering(DefaultAction::Ask)),
        DefaultAction::Ask
    );
    // An `allow` (allow-by-default denylist) parent is NOT inherited — it would make the child's
    // allow-list inert and leave it wide open. Falls back to the safe `deny`.
    assert_eq!(
        effective(&filtering(DefaultAction::Allow)),
        DefaultAction::Deny,
        "an allow-by-default parent must never be inherited into a rule-listing child"
    );
    // A non-filtering `shared`/`none` parent also falls back to `deny` (never to the open host
    // network — the child declared rules, so it wants filtering).
    assert_eq!(effective(&NetworkPolicy::Shared), DefaultAction::Deny);
    assert_eq!(effective(&NetworkPolicy::Isolated), DefaultAction::Deny);
}

#[test]
fn a_mode_less_project_network_table_inherits_the_global_mode() {
    use crate::allowlist::DefaultAction;
    // Global sets `ask`; a trusted project's `[network]` lists its own host but omits `mode`.
    let global = raw_network("ask");
    let project = RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: None,
            allow: vec!["api.proj.com".to_string()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    let NetworkPolicy::Allowlist(p) = &r.network else {
        panic!("a mode-less project table resolves to a filtering policy")
    };
    assert_eq!(
        p.default_action(),
        DefaultAction::Ask,
        "the project inherits the global's `ask` mode"
    );
    assert_eq!(p.allow_rules().len(), 1, "the project keeps its own rule");
    assert_eq!(r.network_origin, Provenance::Project);
}

#[test]
fn a_mode_less_app_network_table_inherits_the_baseline_mode() {
    use crate::allowlist::DefaultAction;
    // Baseline (global) is `ask`; a global app lists its own host but omits `mode`.
    let mut global = raw_network("ask");
    global.app.insert(
        "demo".to_string(),
        RawApp {
            cmd: Some(schema::RawCmd::Line("demo".to_string())),
            network: Some(NetworkField::Table(NetworkTable {
                mute: vec![],
                http2: vec![],
                capture: None,
                capture_max_kb: None,
                mode: None,
                allow: vec!["api.app.com".to_string()],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
                dns_cache_ttl: None,
            })),
            ..RawApp::default()
        },
    );
    let r = resolve_no_plugins(global, None);
    let app = r.apps.get("demo").expect("the app resolves");
    let NetworkPolicy::Allowlist(p) = app.network.as_ref().expect("the app sets a network") else {
        panic!("a mode-less app table resolves to a filtering policy")
    };
    assert_eq!(
        p.default_action(),
        DefaultAction::Ask,
        "the app inherits the baseline's `ask` mode"
    );
    assert_eq!(p.allow_rules().len(), 1, "the app keeps its own rule");
}

#[test]
fn dns_cache_ttl_flows_from_the_table_to_the_policy() {
    let dns_table = |ttl: Option<u64>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: vec!["cache.nixos.org".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: ttl,
        })
    };
    let mut w = Vec::new();

    // Unset → the policy carries None (the resolver applies its 60s default).
    let def = validate_network(&mut w, GLOBAL_CONFIG, dns_table(None)).unwrap();
    assert!(matches!(&def, NetworkPolicy::Allowlist(p) if p.dns_cache_ttl().is_none()));

    // An explicit TTL flows through; `0` disables the cache — a distinct value, not "unset".
    let set = validate_network(&mut w, GLOBAL_CONFIG, dns_table(Some(30))).unwrap();
    assert!(matches!(&set, NetworkPolicy::Allowlist(p)
            if p.dns_cache_ttl() == Some(std::time::Duration::from_secs(30))));
    let off = validate_network(&mut w, GLOBAL_CONFIG, dns_table(Some(0))).unwrap();
    assert!(matches!(&off, NetworkPolicy::Allowlist(p)
            if p.dns_cache_ttl() == Some(std::time::Duration::ZERO)));
    assert!(w.is_empty(), "valid values warn nothing: {w:?}");
}

#[test]
fn the_capture_level_flows_from_the_table_to_the_policy_and_fails_closed_on_a_typo() {
    use crate::sandbox::control::CaptureLevel;
    let capture_table = |level: Option<&str>, kb: Option<u64>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: level.map(str::to_string),
            capture_max_kb: kb,
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })
    };
    let mut w = Vec::new();

    // Unset → off, and nothing is captured.
    let def = validate_network(&mut w, GLOBAL_CONFIG, capture_table(None, None)).unwrap();
    assert!(matches!(&def, NetworkPolicy::Allowlist(p)
            if p.capture_level() == CaptureLevel::Off));
    assert!(w.is_empty());

    // Each level flows through, carrying its per-body cap.
    let heads =
        validate_network(&mut w, GLOBAL_CONFIG, capture_table(Some("headers"), None)).unwrap();
    assert!(matches!(&heads, NetworkPolicy::Allowlist(p)
            if p.capture_level() == CaptureLevel::Headers));
    let bodies = validate_network(
        &mut w,
        GLOBAL_CONFIG,
        capture_table(Some("bodies"), Some(64)),
    )
    .unwrap();
    assert!(matches!(&bodies, NetworkPolicy::Allowlist(p)
            if p.capture_level() == CaptureLevel::Bodies && p.capture_body_kb() == 64));
    assert!(w.is_empty(), "valid values warn nothing: {w:?}");

    // A typo does NOT silently pick a level: the capture stays off and the miss is named.
    let typo = validate_network(&mut w, GLOBAL_CONFIG, capture_table(Some("body"), None)).unwrap();
    assert!(
        matches!(&typo, NetworkPolicy::Allowlist(p) if p.capture_level() == CaptureLevel::Off),
        "an unknown level fails closed"
    );
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("unknown capture level"), "{w:?}");
}

/// The capture rides the `[network]` table, so it inherits that table's trust gate: an untrusted
/// project cannot start capturing its own traffic. Teeth: the SAME table, from a trusted vs an
/// untrusted project, must give opposite answers.
#[test]
fn an_untrusted_project_cannot_turn_the_capture_on() {
    use crate::sandbox::control::CaptureLevel;
    let project = || RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: Some("bodies".into()),
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })),
        ..RawConfig::default()
    };
    let level_of = |network: &NetworkPolicy| match network {
        NetworkPolicy::Allowlist(p) => p.capture_level(),
        _ => panic!("a filtering posture is expected"),
    };

    // A global baseline that already filters but captures nothing, so a dropped project table falls
    // back to a comparable posture rather than to "no network policy at all".
    let global = || RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })),
        ..RawConfig::default()
    };

    let trusted = resolve_no_plugins(global(), Some((project(), TrustState::Trusted)));
    assert_eq!(
        level_of(&trusted.network),
        CaptureLevel::Bodies,
        "a trusted project may capture its own traffic"
    );

    let untrusted = resolve_no_plugins(global(), Some((project(), TrustState::Untrusted)));
    assert_eq!(
        level_of(&untrusted.network),
        CaptureLevel::Off,
        "an untrusted project's whole `[network]` table drops, capture included"
    );
}

/// The `capture` field must stay a `[network]` key. Written after a `[table]` header in a TOML file
/// it would fold into that table and be silently lost, so this parses the real text and asserts the
/// field arrives where the launcher reads it.
#[test]
fn capture_parses_as_a_network_field_not_a_stray_key() {
    use crate::sandbox::control::CaptureLevel;
    let toml = r#"
[network]
mode = "deny"
capture = "bodies"
capture_max_kb = 32
allow = ["api.example.com"]
"#;
    let raw = crate::config::schema::parse(toml.as_bytes()).expect("the config parses");
    let mut w = Vec::new();
    let resolved = validate_network(
        &mut w,
        GLOBAL_CONFIG,
        raw.network.expect("a `[network]` table is present"),
    )
    .expect("the table resolves");
    let NetworkPolicy::Allowlist(p) = &resolved else {
        panic!("a filtering posture is expected")
    };
    assert_eq!(p.capture_level(), CaptureLevel::Bodies);
    assert_eq!(p.capture_body_kb(), 32);
    assert!(w.is_empty(), "a well-formed table warns nothing: {w:?}");
}

#[test]
fn ask_mode_parses_and_carries_an_optional_timeout() {
    use crate::allowlist::DefaultAction;
    let ask_table = |timeout: Option<&str>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("ask".into()),
            allow: vec![],
            deny: vec![],
            ask_timeout: timeout.map(|s| s.to_string()),
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })
    };
    let mut w = Vec::new();

    // Bare-string `ask` → ask-by-default with no timeout (an indefinite wait).
    let bare =
        validate_network(&mut w, GLOBAL_CONFIG, NetworkField::Posture("ask".into())).unwrap();
    assert!(matches!(&bare, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && p.ask_timeout().is_none()));

    // Table `ask` with a timeout → ask-by-default carrying the parsed duration.
    let timed = validate_network(&mut w, GLOBAL_CONFIG, ask_table(Some("90s"))).unwrap();
    assert!(matches!(&timed, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask
            && p.ask_timeout() == Some(std::time::Duration::from_secs(90))));
    assert!(w.is_empty(), "a valid ask config warns nothing: {w:?}");

    // A malformed timeout falls back to indefinite, warned — never a hard config failure.
    let fallback = validate_network(&mut w, GLOBAL_CONFIG, ask_table(Some("soon"))).unwrap();
    assert!(matches!(&fallback, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && p.ask_timeout().is_none()));
    assert!(
        w.iter().any(|m| m.contains("ask_timeout")),
        "a bad timeout must warn: {w:?}"
    );
    w.clear();

    // An `ask_timeout` under a non-ask mode is moot — warned and ignored.
    let moot = NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        capture: None,
        capture_max_kb: None,
        mode: Some("deny".into()),
        allow: vec![],
        deny: vec![],
        ask_timeout: Some("90s".into()),
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
    });
    let _ = validate_network(&mut w, GLOBAL_CONFIG, moot).unwrap();
    assert!(
        w.iter().any(|m| m.contains("ask_timeout")),
        "a moot timeout must warn: {w:?}"
    );
}

#[test]
fn ask_notice_defaults_on_and_can_be_silenced() {
    use crate::allowlist::DefaultAction;
    let ask = |notice: Option<bool>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("ask".into()),
            allow: vec![],
            deny: vec![],
            ask_timeout: None,
            ask_notice: notice,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })
    };
    let mut w = Vec::new();

    // Absent `ask_notice` → the park notice is shown (the default).
    let def = validate_network(&mut w, GLOBAL_CONFIG, ask(None)).unwrap();
    assert!(matches!(&def, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && p.ask_notice()));

    // `ask_notice = false` silences it.
    let off = validate_network(&mut w, GLOBAL_CONFIG, ask(Some(false))).unwrap();
    assert!(matches!(&off, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Ask && !p.ask_notice()));

    // `ask_notice = true` is the explicit default — still shown, no warning.
    let on = validate_network(&mut w, GLOBAL_CONFIG, ask(Some(true))).unwrap();
    assert!(matches!(&on, NetworkPolicy::Allowlist(p) if p.ask_notice()));
    assert!(w.is_empty(), "valid ask_notice configs warn nothing: {w:?}");

    // An `ask_notice` under a non-ask mode is moot — warned and ignored.
    let moot = NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        capture: None,
        capture_max_kb: None,
        mode: Some("deny".into()),
        allow: vec![],
        deny: vec![],
        ask_timeout: None,
        ask_notice: Some(false),
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
    });
    let _ = validate_network(&mut w, GLOBAL_CONFIG, moot).unwrap();
    assert!(
        w.iter().any(|m| m.contains("ask_notice")),
        "a moot ask_notice must warn: {w:?}"
    );
}

#[test]
fn parse_duration_handles_units_and_rejects_garbage() {
    use std::time::Duration;
    assert_eq!(parse_duration("90s"), Ok(Some(Duration::from_secs(90))));
    assert_eq!(parse_duration("90"), Ok(Some(Duration::from_secs(90))));
    assert_eq!(parse_duration("5m"), Ok(Some(Duration::from_secs(300))));
    assert_eq!(parse_duration("2h"), Ok(Some(Duration::from_secs(7200))));
    // A zero of any unit means indefinite — the same as omitting the field.
    assert_eq!(parse_duration("0"), Ok(None));
    assert_eq!(parse_duration("0m"), Ok(None));
    // Malformed values are refused (the caller then warns and falls back to indefinite).
    assert!(parse_duration("soon").is_err());
    assert!(parse_duration("9x").is_err());
    assert!(parse_duration("").is_err());
}

#[test]
fn a_global_apps_network_survives_an_untrusted_projects_override_attempt() {
    // A globally-declared app keeps its posture even when launched under an untrusted
    // project — the flagship use case: run an agent *on* untrusted code, safely.
    let global = raw_with_app(
        "demo-app",
        raw_app(
            &["demo-app"],
            &[],
            &[],
            &[],
            allowlist_net(&["api.example.com"]),
        ),
    );
    let mut widen = raw_app(&[], &[], &[], &[], None);
    widen.network = Some(NetworkField::Posture("shared".into()));
    let project = raw_with_app("demo-app", widen);
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    assert!(matches!(app.network, Some(NetworkPolicy::Allowlist(_))));
    assert!(app.warnings.iter().any(|w| w.contains("network")));
}

#[test]
fn a_global_apps_gui_survives_an_untrusted_projects_override_attempt() {
    // The flagship property for the GUI hole: a globally-declared app keeps its display
    // posture even under an untrusted project, which can neither close it nor (in the reverse
    // case) open one — running an agent *on* untrusted code never lets that code touch the
    // compositor exposure.
    let global = raw_with_app(
        "desktop",
        RawApp {
            gui: Some("wayland".into()),
            ..raw_app(&["agent"], &[], &[], &[], None)
        },
    );
    // The untrusted project tries to flip the app to no display.
    let project = raw_with_app(
        "desktop",
        RawApp {
            gui: Some("none".into()),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["desktop"];
    assert_eq!(
        app.gui,
        Some(GuiPolicy::Wayland),
        "an untrusted project may not change a trusted app's GUI posture"
    );
    assert!(app.warnings.iter().any(|w| w.contains("gui")));

    // The reverse: an untrusted project cannot *open* a display on its own app either.
    let project = raw_with_app(
        "mine",
        RawApp {
            gui: Some("wayland".into()),
            ..raw_app(&["tool"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["mine"];
    assert_eq!(app.gui, None, "an untrusted project may not open a display");
    assert!(app.warnings.iter().any(|w| w.contains("gui")));
}

#[test]
fn a_global_apps_forward_survives_an_untrusted_projects_override_attempt() {
    // The flagship property for the inbound hole: a globally-declared app keeps its forward
    // ports even under an untrusted project, which may neither remove them nor open its own.
    let global = raw_with_app(
        "demo-app",
        RawApp {
            forward: Some(vec![1455]),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    // An untrusted project tries to add a port to the trusted app — dropped.
    let project = raw_with_app(
        "demo-app",
        RawApp {
            forward: Some(vec![31337]),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    assert_eq!(
        app.forward,
        vec![1455],
        "an untrusted project may not add a forward port to a trusted app"
    );
    assert!(app.warnings.iter().any(|w| w.contains("forward")));

    // The reverse: an untrusted project cannot open an inbound hole on its own app either.
    let project = raw_with_app(
        "mine",
        RawApp {
            forward: Some(vec![8080]),
            ..raw_app(&["tool"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["mine"];
    assert!(
        app.forward.is_empty(),
        "an untrusted project may not open an inbound port"
    );
    assert!(app.warnings.iter().any(|w| w.contains("forward")));
}

#[test]
fn a_trusted_app_forward_is_honored() {
    // A trusted (global-declared) app's forward ports are honored and carried on the overlay.
    let global = raw_with_app(
        "demo-app",
        RawApp {
            forward: Some(vec![1455]),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.apps["demo-app"].forward, vec![1455]);
    assert_eq!(r.apps["demo-app"].forward_origin, Provenance::Global);
}

#[test]
fn a_global_apps_devices_grant_survives_an_untrusted_projects_override_attempt() {
    // The flagship property for devices: a globally-declared app keeps its device grant even
    // under an untrusted project, which may neither widen it nor grant its own.
    let global = raw_with_app(
        "demo-app",
        RawApp {
            devices: Some(schema::RawDevices {
                rest: Default::default(),
                allow: vec!["/dev/kvm".into()],
            }),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    // An untrusted project tries to add a device to the trusted app — dropped.
    let project = raw_with_app(
        "demo-app",
        RawApp {
            devices: Some(schema::RawDevices {
                rest: Default::default(),
                allow: vec!["/dev/dri".into()],
            }),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    assert_eq!(
        app.devices,
        vec![PathBuf::from("/dev/kvm")],
        "an untrusted project may not widen a trusted app's device grant"
    );
    assert!(app.warnings.iter().any(|w| w.contains("[devices]")));

    // The reverse: an untrusted project cannot grant a device on its own app either.
    let project = raw_with_app(
        "mine",
        RawApp {
            devices: Some(schema::RawDevices {
                rest: Default::default(),
                allow: vec!["/dev/kvm".into()],
            }),
            ..raw_app(&["tool"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["mine"];
    assert!(
        app.devices.is_empty(),
        "an untrusted project may not grant a device"
    );
    assert!(app.warnings.iter().any(|w| w.contains("[devices]")));
}

#[test]
fn a_trusted_app_devices_grant_is_honored() {
    // A trusted (global-declared) app's device grant is honored and carried on the overlay.
    let global = raw_with_app(
        "demo-app",
        RawApp {
            devices: Some(schema::RawDevices {
                rest: Default::default(),
                allow: vec!["/dev/kvm".into()],
            }),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.apps["demo-app"].devices, vec![PathBuf::from("/dev/kvm")]);
    assert_eq!(r.apps["demo-app"].devices_origin, Provenance::Global);
}

/// An `[ssh_agent]` table granting these entries.
fn app_raw_ssh_agent(allow: &[&str]) -> schema::RawSshAgent {
    schema::RawSshAgent {
        confirm: None,
        rest: Default::default(),
        allow: allow.iter().map(|s| s.to_string()).collect(),
    }
}

/// The point of the per-app field: a deploy key granted to one app, and to nothing else the
/// project launches.
#[test]
fn an_app_ssh_agent_grant_is_its_own_and_unions_onto_the_baseline() {
    let mut global = raw_with_app(
        "deployer",
        RawApp {
            ssh_agent: Some(app_raw_ssh_agent(&["deploy@example"])),
            ..raw_app(&["deployer"], &[], &[], &[], None)
        },
    );
    global.ssh_agent = Some(app_raw_ssh_agent(&["work@example"]));

    let r = resolve_no_plugins(global, None);
    assert_eq!(r.apps["deployer"].ssh_agent, vec!["deploy@example"]);
    assert_eq!(r.apps["deployer"].ssh_agent_origin, Provenance::Global);
    // The baseline — what a plain `sbx run` gets — is untouched by the app's grant.
    assert_eq!(r.ssh_agent, vec!["work@example"]);

    // Launching the app unions the two: an app adds a key, and can never take away one the
    // trusted baseline granted.
    let mut merged = r.clone();
    merged.merge_app(merged.apps["deployer"].clone());
    assert_eq!(merged.ssh_agent, vec!["deploy@example", "work@example"]);
}

#[test]
fn a_global_apps_ssh_agent_grant_survives_an_untrusted_projects_override_attempt() {
    // The flagship property, for the field where it matters most: a key the cage can sign with
    // authenticates as the user wherever that key is trusted, so an untrusted project may neither
    // widen a trusted app's grant nor grant one on an app of its own.
    let global = raw_with_app(
        "deployer",
        RawApp {
            ssh_agent: Some(app_raw_ssh_agent(&["deploy@example"])),
            ..raw_app(&["deployer"], &[], &[], &[], None)
        },
    );
    let project = raw_with_app(
        "deployer",
        RawApp {
            ssh_agent: Some(app_raw_ssh_agent(&["personal@example"])),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["deployer"];
    assert_eq!(
        app.ssh_agent,
        vec!["deploy@example"],
        "an untrusted project may not add a key to a trusted app's grant"
    );
    assert!(app.warnings.iter().any(|w| w.contains("[ssh_agent]")));

    let project = raw_with_app(
        "mine",
        RawApp {
            ssh_agent: Some(app_raw_ssh_agent(&["deploy@example"])),
            ..raw_app(&["tool"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["mine"];
    assert!(
        app.ssh_agent.is_empty(),
        "an untrusted project may not grant a key at all"
    );
    assert!(app.warnings.iter().any(|w| w.contains("[ssh_agent]")));
}

/// A trusted project may grant its own app a key — the same gate as `[devices]`, and the case a
/// per-repository deploy key is written for.
#[test]
fn a_trusted_project_app_may_grant_a_key() {
    let project = raw_with_app(
        "deployer",
        RawApp {
            ssh_agent: Some(app_raw_ssh_agent(&["deploy@example"])),
            ..raw_app(&["deployer"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
    assert_eq!(r.apps["deployer"].ssh_agent, vec!["deploy@example"]);
    assert_eq!(r.apps["deployer"].ssh_agent_origin, Provenance::Project);
}

/// Confirmation ORs across every layer: a layer may ask for the prompt, and none may take it away.
/// The direction matters — the layer most likely to try is the least trusted one.
#[test]
fn ssh_agent_confirmation_can_be_added_by_any_layer_and_removed_by_none() {
    let confirming = |allow: &str, confirm: Option<bool>| RawConfig {
        ssh_agent: Some(schema::RawSshAgent {
            rest: Default::default(),
            allow: vec![allow.to_string()],
            confirm,
        }),
        ..Default::default()
    };
    let global = confirming("work@example", Some(true));

    // A trusted project writing `confirm = false` does not turn the global's prompt off.
    let project = confirming("deploy@example", Some(false));
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert!(
        r.ssh_agent_confirm,
        "a layer may add the prompt, never remove it"
    );
    assert_eq!(r.ssh_agent, vec!["deploy@example", "work@example"]);

    // And the other direction: a project may turn it on over a global that did not ask.
    let r = resolve_no_plugins(
        confirming("work@example", None),
        Some((
            confirming("deploy@example", Some(true)),
            TrustState::Trusted,
        )),
    );
    assert!(r.ssh_agent_confirm);

    // An *untrusted* project's `[ssh_agent]` is dropped whole, so it can neither grant a key nor
    // touch the confirmation posture — in either direction.
    let r = resolve_no_plugins(
        confirming("work@example", None),
        Some((
            confirming("deploy@example", Some(true)),
            TrustState::Untrusted,
        )),
    );
    assert!(
        !r.ssh_agent_confirm,
        "an untrusted layer contributes nothing"
    );
    assert_eq!(r.ssh_agent, vec!["work@example"]);
}

/// An app may ask for the prompt for its own launches, and a merge never loses the baseline's.
#[test]
fn an_app_may_add_the_confirmation_prompt_but_not_drop_it() {
    let mut global = raw_with_app(
        "deployer",
        RawApp {
            ssh_agent: Some(schema::RawSshAgent {
                rest: Default::default(),
                allow: vec!["deploy@example".into()],
                confirm: Some(true),
            }),
            ..raw_app(&["deployer"], &[], &[], &[], None)
        },
    );
    global.ssh_agent = Some(app_raw_ssh_agent(&["work@example"]));

    let r = resolve_no_plugins(global, None);
    assert!(
        !r.ssh_agent_confirm,
        "the baseline is unaffected by what an app asks for"
    );
    assert!(r.apps["deployer"].ssh_agent_confirm);

    let mut merged = r.clone();
    merged.merge_app(merged.apps["deployer"].clone());
    assert!(
        merged.ssh_agent_confirm,
        "launching the app turns the prompt on for that launch"
    );
}

/// An entry the baseline would refuse is refused here too — the validation is one function, so a
/// per-app grant cannot become the place a wildcard slips in.
#[test]
fn an_app_grant_refuses_what_the_baseline_grant_refuses() {
    let global = raw_with_app(
        "deployer",
        RawApp {
            ssh_agent: Some(app_raw_ssh_agent(&[
                "*",
                "SHA256:tooshort",
                "deploy@example",
            ])),
            ..raw_app(&["deployer"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, None);
    let app = &r.apps["deployer"];
    assert_eq!(app.ssh_agent, vec!["deploy@example"]);
    assert_eq!(
        app.warnings
            .iter()
            .filter(|w| w.contains("`[ssh_agent] allow` entry"))
            .count(),
        2,
        "both bad entries are named: {:?}",
        app.warnings
    );
}

/// Build a `RawLimits` from optional tokens, for the per-app overlay tests.
fn app_raw_limits(
    memory_high: Option<&str>,
    memory_max: Option<&str>,
    tasks_max: Option<&str>,
) -> schema::RawLimits {
    let text = |o: Option<&str>| o.map(|s| schema::RawLimit::Text(s.to_string()));
    schema::RawLimits {
        rest: Default::default(),
        memory_high: text(memory_high),
        memory_max: text(memory_max),
        tasks_max: text(tasks_max),
    }
}

#[test]
fn a_trusted_project_app_overrides_limits_per_field() {
    // An app's `[limits]` overlay layers like its `network`/`gui`: a trusted project tunes a
    // field its global definition set, the others standing. The global app caps tasks and
    // memory; the trusted project lowers only the ceiling.
    let global = raw_with_app(
        "agent",
        RawApp {
            limits: Some(app_raw_limits(None, Some("16G"), Some("8192"))),
            ..raw_app(&["agent"], &[], &[], &[], None)
        },
    );
    let project = raw_with_app(
        "agent",
        RawApp {
            limits: Some(app_raw_limits(None, Some("8G"), None)),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    let app = &r.apps["agent"];
    assert_eq!(
        app.limits.memory_max.as_deref(),
        Some("8G"),
        "the trusted project overrides the ceiling"
    );
    assert_eq!(
        app.limits.tasks_max.as_deref(),
        Some("8192"),
        "the global task cap stands"
    );
    assert_eq!(
        app.limits.memory_high, None,
        "neither layer set the throttle"
    );
}

#[test]
fn an_untrusted_projects_app_limits_are_dropped_and_a_global_apps_survive() {
    // The flagship property for the limits overlay: a globally-declared app keeps its tight
    // cap even under an untrusted project, which can neither loosen it nor set a limit on its
    // own app — running an agent *on* untrusted code never lets that code weaken the anti-DoS.
    let global = raw_with_app(
        "agent",
        RawApp {
            limits: Some(app_raw_limits(None, None, Some("4096"))),
            ..raw_app(&["agent"], &[], &[], &[], None)
        },
    );
    let project = raw_with_app(
        "agent",
        RawApp {
            limits: Some(app_raw_limits(None, None, Some("infinity"))),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["agent"];
    assert_eq!(
        app.limits.tasks_max.as_deref(),
        Some("4096"),
        "an untrusted project may not loosen a trusted app's task cap"
    );
    assert!(app.warnings.iter().any(|w| w.contains("[limits]")));

    // The reverse: an untrusted project cannot set a limit on its own app either.
    let project = raw_with_app(
        "mine",
        RawApp {
            limits: Some(app_raw_limits(None, None, Some("infinity"))),
            ..raw_app(&["tool"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let app = &r.apps["mine"];
    assert_eq!(
        app.limits,
        crate::sandbox::cgroup::Limits::default(),
        "an untrusted project's own app limits are dropped"
    );
    assert!(app.warnings.iter().any(|w| w.contains("[limits]")));
}

#[test]
fn an_apps_scalar_origins_record_which_app_layer_set_each_field() {
    // The data behind `config show --app`: each scalar the app overlay sets is attributed to
    // its app layer; an untouched scalar keeps the default origin, so the detail view shows it
    // inherited from the baseline.
    let global = raw_with_app(
        "demo",
        RawApp {
            limits: Some(app_raw_limits(None, None, Some("2048"))),
            ..raw_app(
                &["demo-agent"],
                &[],
                &[],
                &[],
                Some(NetworkField::Posture("none".into())),
            )
        },
    );
    let resolved = resolve_no_plugins(global, None);
    let app = &resolved.apps["demo"];
    assert_eq!(
        app.cmd_origin,
        Provenance::Global,
        "the global app set the command"
    );
    assert_eq!(app.network_origin, Provenance::Global, "and the network");
    assert_eq!(
        app.limits_origin.tasks_max,
        Provenance::Global,
        "and the task cap"
    );
    // A scalar the app left alone keeps its default origin and sets no value of its own.
    assert_eq!(app.gui_origin, Provenance::Default);
    assert!(app.gui.is_none());
    assert_eq!(app.home_scope_origin, None);
    assert_eq!(app.limits_origin.memory_high, Provenance::Default);

    // A trusted project overriding a field is attributed to the project layer, while a field it
    // does not touch keeps the global app's attribution.
    let global = raw_with_app(
        "demo",
        raw_app(
            &["demo-agent"],
            &[],
            &[],
            &[],
            Some(NetworkField::Posture("none".into())),
        ),
    );
    let project = raw_with_app(
        "demo",
        raw_app(
            &[],
            &[],
            &[],
            &[],
            Some(NetworkField::Posture("shared".into())),
        ),
    );
    let resolved = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    let app = &resolved.apps["demo"];
    assert_eq!(
        app.network_origin,
        Provenance::Project,
        "the project overrode the network"
    );
    assert_eq!(
        app.cmd_origin,
        Provenance::Global,
        "the command stayed the global app's"
    );
}

#[test]
fn an_app_home_scope_defaults_to_global_and_a_trusted_layer_may_set_project() {
    // Unset → the global default. A trusted layer (here the global config) may pin it.
    let plain = raw_with_app("demo-app", raw_app(&["demo-app"], &[], &[], &[], None));
    let r = resolve_no_plugins(plain, None);
    assert_eq!(r.apps["demo-app"].home_scope, AppHomeScope::Global);

    let scoped = raw_with_app(
        "review",
        RawApp {
            home_scope: Some("project".into()),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(scoped, None);
    assert_eq!(r.apps["review"].home_scope, AppHomeScope::Project);
}

#[test]
fn an_untrusted_project_cannot_widen_a_trusted_apps_home_scope_to_global() {
    // The integrity guard, mirroring `cmd`: a trusted app pinned to a per-project home must
    // not be flipped to the shared global home by an untrusted repo (the contamination
    // vector). The safe direction — narrowing to `project` — and an untrusted project's own
    // app are both allowed.
    let global = raw_with_app(
        "demo-app",
        RawApp {
            home_scope: Some("project".into()),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let project = raw_with_app(
        "demo-app",
        RawApp {
            home_scope: Some("global".into()),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    assert_eq!(
        app.home_scope,
        AppHomeScope::Project,
        "the widening is refused"
    );
    assert!(app.warnings.iter().any(|w| w.contains("home_scope")));

    // An untrusted project's OWN app (nothing trusted to override) may set any scope.
    let project = raw_with_app(
        "mine",
        RawApp {
            home_scope: Some("global".into()),
            ..raw_app(&["tool"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    assert_eq!(r.apps["mine"].home_scope, AppHomeScope::Global);
}

#[test]
fn proc_is_trusted_gated_and_the_app_overlay_replaces_the_baseline() {
    use crate::config::schema::{ProcField, ProcTable};
    use crate::proc_policy::ProcMode;
    let proc = |mode: &str, deny: &[&str]| {
        Some(ProcField::Table(ProcTable {
            mode: Some(mode.into()),
            allow: Vec::new(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
        }))
    };

    // Global is trusted by location — its `[proc]` applies in full.
    let r = resolve_no_plugins(
        RawConfig {
            proc: proc("enforce", &["curl"]),
            ..RawConfig::default()
        },
        None,
    );
    assert_eq!(r.proc.mode, ProcMode::Enforce);
    assert_eq!(r.proc.deny.len(), 1);
    assert_eq!(r.proc_origin, Provenance::Global);

    // An UNTRUSTED project's `[proc]` is dropped with a warning — the baseline stays off.
    let untrusted = RawConfig {
        proc: proc("enforce", &["id"]),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((untrusted, TrustState::Untrusted)),
    );
    assert_eq!(
        r.proc.mode,
        ProcMode::Off,
        "an untrusted project may not enforce its own agent"
    );
    assert!(r.warnings.iter().any(|w| w.contains("ignoring `proc`")));

    // A TRUSTED project's `[proc]` applies.
    let trusted = RawConfig {
        proc: proc("ask", &["ssh"]),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(RawConfig::default(), Some((trusted, TrustState::Trusted)));
    assert_eq!(r.proc.mode, ProcMode::Ask);
    assert_eq!(r.proc_origin, Provenance::Project);

    // A globally-declared app's own `[proc]` is trusted by location and resolves to `Some`.
    let app = RawApp {
        proc: proc("enforce", &["curl"]),
        ..raw_app(&["true"], &[], &[], &[], None)
    };
    let r = resolve_no_plugins(raw_with_app("probe", app), None);
    let resolved_app = &r.apps["probe"];
    assert_eq!(
        resolved_app.proc.as_ref().map(|p| p.mode),
        Some(ProcMode::Enforce),
        "a global app's own proc applies (trusted by location)"
    );
}

#[test]
fn global_limits_are_honored_by_location() {
    // The global config is trusted by location, so its whole `[limits]` table applies.
    let global = raw_limits(Some("70%"), Some("16G"), Some("8192"));
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.limits.memory_high.as_deref(), Some("70%"));
    assert_eq!(r.limits.memory_max.as_deref(), Some("16G"));
    assert_eq!(r.limits.tasks_max.as_deref(), Some("8192"));
}

#[test]
fn a_trusted_project_overrides_limits_per_field() {
    // Per-field layering (the `env` model, not wholesale): the project sets only the ceiling,
    // so it overrides `memory_max` while the global throttle and task cap stand.
    let global = raw_limits(Some("70%"), Some("16G"), Some("8192"));
    let project = raw_limits(None, Some("8G"), None);
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert_eq!(
        r.limits.memory_high.as_deref(),
        Some("70%"),
        "global throttle stands"
    );
    assert_eq!(
        r.limits.memory_max.as_deref(),
        Some("8G"),
        "project overrides the ceiling"
    );
    assert_eq!(
        r.limits.tasks_max.as_deref(),
        Some("8192"),
        "global task cap stands"
    );
}

#[test]
fn an_untrusted_projects_limits_are_dropped_with_a_warning() {
    // Loosening the anti-DoS limits is a security choice — an untrusted project may not make
    // it. The whole `[limits]` table is dropped and the built-in defaults (all-None) stand.
    let project = raw_limits(Some("100%"), Some("infinity"), Some("infinity"));
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    assert_eq!(r.limits, crate::sandbox::cgroup::Limits::default());
    assert!(r.warnings.iter().any(|w| w.contains("[limits]")));
}

#[test]
fn a_value_set_to_its_default_still_records_its_layer_not_default() {
    // The discriminating provenance property — the whole reason the feature exists. A layer
    // that sets a value *to the built-in default* is still recorded as the origin, so
    // `sbx config` distinguishes "shared because I chose it" from "shared because nothing set
    // it". `network = "shared"` and `gui = "none"` ARE the defaults, and `tasks_max = 16384` is
    // the documented default task cap — all three, set explicitly, must read as `Global`, never
    // `Default`. (If `validate_network` ever normalized "shared" to "unset", this would fail.)
    let global = RawConfig {
        network: Some(NetworkField::Posture("shared".into())),
        gui: Some("none".into()),
        limits: Some(schema::RawLimits {
            rest: Default::default(),
            memory_high: None,
            memory_max: None,
            tasks_max: Some(schema::RawLimit::Number(16384)),
        }),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, None);
    assert_eq!(
        r.network,
        NetworkPolicy::Shared,
        "shared is honored as a posture"
    );
    assert_eq!(
        r.network_origin,
        Provenance::Global,
        "explicit shared is global-set"
    );
    assert_eq!(
        r.gui_origin,
        Provenance::Global,
        "explicit none is global-set"
    );
    assert_eq!(
        r.limits_origin.tasks_max,
        Provenance::Global,
        "an explicit default-valued task cap is still global-set"
    );
    // The contrast that gives the above its meaning: a field no layer set stays `Default`.
    assert_eq!(r.limits_origin.memory_high, Provenance::Default);

    // With nothing declared at all, every scalar origin reads `Default`.
    let bare = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(bare.network_origin, Provenance::Default);
    assert_eq!(bare.gui_origin, Provenance::Default);
    assert_eq!(bare.limits_origin.tasks_max, Provenance::Default);
}

#[test]
fn a_trusted_project_records_its_layer_as_the_origin() {
    // The project path records origin too, per field: a trusted project sets the network and
    // the ceiling (attributed `Project`), while a global-set task cap stays `Global`.
    let global = raw_limits(None, None, Some("8192"));
    let project = RawConfig {
        network: Some(NetworkField::Posture("none".into())),
        limits: Some(schema::RawLimits {
            rest: Default::default(),
            memory_high: None,
            memory_max: Some(schema::RawLimit::Text("8G".into())),
            tasks_max: None,
        }),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert_eq!(r.network_origin, Provenance::Project);
    assert_eq!(
        r.limits_origin.memory_max,
        Provenance::Project,
        "the project-set ceiling is attributed to the project"
    );
    assert_eq!(
        r.limits_origin.tasks_max,
        Provenance::Global,
        "the global-set task cap the project did not touch stays global"
    );
}

#[test]
fn an_invalid_limits_value_is_dropped_and_the_field_keeps_its_default() {
    // A value systemd would reject (`2GB` — no `B` suffix) must never reach `systemd-run`, or
    // it would brick every launch. It is dropped (warned by field name) while the valid
    // siblings apply.
    let global = raw_limits(Some("80%"), Some("2GB"), Some("8192"));
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.limits.memory_high.as_deref(), Some("80%"));
    assert_eq!(
        r.limits.memory_max, None,
        "the invalid ceiling falls back to the default"
    );
    assert_eq!(r.limits.tasks_max.as_deref(), Some("8192"));
    assert!(r.warnings.iter().any(|w| w.contains("limits.memory_max")));
}

#[test]
fn a_bare_small_memory_number_is_refused_as_a_likely_percentage_typo() {
    // The `memory_max = 90` footgun: a bare integer is *bytes*, so `90` means 90 bytes — almost
    // certainly a percentage missing its `%`. It is dropped (with a "did you mean" hint) and
    // the field falls back to its default, rather than reaching systemd and bricking the launch.
    let global = RawConfig {
        limits: Some(schema::RawLimits {
            memory_max: Some(schema::RawLimit::Number(90)),
            ..Default::default()
        }),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.limits.memory_max, None, "the bare byte count is refused");
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("did you mean") && w.contains("memory_max")));

    // A deliberate unit or percentage is honored — the guard only catches the bare small int.
    let global = raw_limits(None, Some("90%"), None);
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.limits.memory_max.as_deref(), Some("90%"));
    let global = raw_limits(None, Some("16G"), None);
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.limits.memory_max.as_deref(), Some("16G"));
}

#[test]
fn an_unknown_home_scope_defaults_to_global_with_a_warning() {
    let global = raw_with_app(
        "demo-app",
        RawApp {
            home_scope: Some("frobnicate".into()),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, None);
    let app = &r.apps["demo-app"];
    assert_eq!(app.home_scope, AppHomeScope::Global);
    assert!(app.warnings.iter().any(|w| w.contains("home_scope")));
}

#[test]
fn an_app_with_an_unsafe_name_is_dropped_before_it_can_key_a_directory() {
    // An app name keys an on-disk home directory, so a traversal or odd-charset name must
    // never reach the launcher. It is dropped at resolve time with a baseline warning.
    for bad in ["../escape", "a/b", "..", ".", "with space", ""] {
        let global = raw_with_app(bad, raw_app(&["x"], &[], &[], &[], None));
        let r = resolve_no_plugins(global, None);
        assert!(
            !r.apps.contains_key(bad),
            "app `{bad}` must be dropped, not resolved"
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("ignoring app")),
            "a dropped app `{bad}` must warn"
        );
    }
    // A conventional name survives.
    assert!(is_valid_app_name("demo-app"));
    assert!(is_valid_app_name("other-tool-2.dev_x"));
}

#[test]
fn a_subcommand_verb_is_a_usable_app_name() {
    // Launching an app goes through `sbx app run <name>`, so the first `sbx app` token is always
    // a subcommand and an app name can never collide with one. A name that coincides with a verb
    // (`run`, `show`, `import`, …) is therefore a perfectly usable app — reachable as
    // `sbx app run <verb>` — and must resolve rather than be dropped.
    for verb in ["run", "show", "import", "export", "rm", "list", "prune"] {
        assert!(
            is_valid_app_name(verb),
            "`{verb}` is a valid path component"
        );
        let global = raw_with_app(verb, raw_app(&["x"], &[], &[], &[], None));
        let r = resolve_no_plugins(global, None);
        assert!(
            r.apps.contains_key(verb),
            "an app named `{verb}` must resolve now that launch requires `run`"
        );
    }
}

#[test]
fn validating_a_profile_requires_a_command_and_summarizes_its_posture() {
    // A complete profile validates and its granted posture is summarized for display.
    let ok = validate_profile(
        br#"
            cmd = "demo-app"
            [network]
            mode = "deny"
            allow = ["api.example.com"]
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            "#,
    )
    .unwrap();
    let joined = ok.summary.join("\n");
    assert!(joined.contains("command: demo-app"), "{joined}");
    assert!(joined.contains("network: deny"), "{joined}");
    // The secret shows its destination and source locator — never a value (a profile has none).
    assert!(
        joined.contains("api.example.com") && joined.contains("env://DEMO_API_KEY"),
        "{joined}"
    );
    // `deny`/`allow`/`ask` are all filtering postures, so a secret declared under any of them
    // carries no "would not be injected" note. (The `deny` profile above already has a secret
    // and is filtering, so its summary must not warn.)
    assert!(
        !joined.contains("injected only under"),
        "a filtering-posture profile must not warn its secrets are uninjected:\n{joined}"
    );
    let deny = validate_profile(
        br#"
            cmd = "demo-app"
            network = "deny"
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            "#,
    )
    .unwrap();
    let deny_joined = deny.summary.join("\n");
    assert!(deny_joined.contains("network: deny"), "{deny_joined}");
    assert!(
        !deny_joined.contains("injected only under"),
        "a bare `deny` posture is filtering, so its secret must not warn:\n{deny_joined}"
    );

    // A non-filtering posture (`shared`) with a secret DOES carry the note — there is no proxy
    // to inject under, so the summary must say so rather than imply working injection.
    let shared = validate_profile(
        br#"
            cmd = "demo-app"
            network = "shared"
            [secret."api.example.com"]
            from = "env://DEMO_API_KEY"
            header = "x-api-key"
            type = "raw"
            "#,
    )
    .unwrap();
    assert!(
        shared.summary.join("\n").contains("injected only under"),
        "a non-filtering posture must warn its secrets are uninjected:\n{}",
        shared.summary.join("\n")
    );

    // A profile with no command is refused — and so is a file wrapped in `[app.<name>]` (it
    // parses as an empty app, so it trips the same gate with a helpful hint).
    assert!(validate_profile(b"[env]\nA = \"1\"\n").is_err());
    let wrapped = validate_profile(b"[app.demo-app]\ncmd = \"demo-app\"\n").unwrap_err();
    assert!(wrapped.contains("cmd"), "{wrapped}");

    // An imported profile lands in the *global* config, where it is trusted by location — so every
    // grant it arrives with must be in the consent report, or the import is consent to something
    // unstated. The ssh-agent one most of all: it asks the user's own agent to sign.
    let granting = validate_profile(
        br#"
            cmd = "demo-app"
            [ssh_agent]
            allow = ["deploy@example"]
            [devices]
            allow = ["/dev/kvm"]
            [seccomp]
            allow = ["userfaultfd"]
            "#,
    )
    .unwrap();
    let joined = granting.summary.join("\n");
    assert!(
        joined.contains("ssh-agent: deploy@example") && joined.contains("ask your agent to sign"),
        "the key grant is stated in words: {joined}"
    );
    assert!(joined.contains("devices: /dev/kvm"), "{joined}");
    assert!(joined.contains("seccomp allow: userfaultfd"), "{joined}");
}

#[test]
fn merge_app_overlays_the_baseline_with_app_precedence() {
    let mut base = resolve_no_plugins(raw(&[("A", "base"), ("B", "base")], &[]), None);
    // Seed the baseline limits so the per-field overlay is observable: the app tightens only
    // the task cap, and must inherit the baseline's memory limits untouched.
    base.limits = crate::sandbox::cgroup::Limits {
        memory_high: Some("70%".into()),
        memory_max: Some("16G".into()),
        tasks_max: Some("8192".into()),
    };
    // Seed a baseline device so the app's grant is observably *unioned*, not replaced.
    base.devices = vec![PathBuf::from("/dev/dri")];
    // Baseline GPU off, so the app turning it on is an observable *replace* (like `gui`).
    base.gpu = false;
    // Baseline D-Bus off, so the app turning it on is an observable *replace* too.
    base.dbus = false;
    let app = ResolvedApp {
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        cmd: vec!["x".into()],
        home_scope: AppHomeScope::Global,
        env: vec![("A".into(), "app".into()), ("C".into(), "app".into())],
        binds: vec![],
        packages: vec![],
        network: Some(NetworkPolicy::Isolated),
        gui: None,
        gpu: Some(true),
        audio: Some(true),
        dbus: Some(true),
        limits: crate::sandbox::cgroup::Limits {
            tasks_max: Some("4096".into()),
            ..Default::default()
        },
        secrets: vec![],
        tasks: vec![],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
        forward_origin: Default::default(),
        limits_origin: Default::default(),
        seccomp: Default::default(),
        seccomp_origin: Default::default(),
        devices: vec![PathBuf::from("/dev/kvm")],
        devices_origin: Default::default(),
        proc: None,
        proc_origin: Default::default(),
        home_scope_origin: None,
        warnings: vec![],
    };
    base.merge_app(app);
    // The app's device grant unions onto the baseline's (sorted), never replacing it.
    assert_eq!(
        base.devices,
        vec![PathBuf::from("/dev/dri"), PathBuf::from("/dev/kvm")],
        "app devices union onto the baseline"
    );
    // App env wins on a collision; baseline-only and app-only keys both survive.
    assert!(base.env.iter().any(|(k, v)| k == "A" && v == "app"));
    assert!(base.env.iter().any(|(k, v)| k == "B" && v == "base"));
    assert!(base.env.iter().any(|(k, v)| k == "C" && v == "app"));
    // The app's posture replaces the baseline's.
    assert!(matches!(base.network, NetworkPolicy::Isolated));
    // The app's GPU posture (`Some(true)`) replaces the baseline's `false`, like `network`/`gui`.
    assert!(base.gpu, "the app's gpu posture replaces the baseline's");
    assert!(base.dbus, "the app's dbus posture replaces the baseline's");
    // The app's limit override replaces the baseline per field; unset fields inherit it.
    assert_eq!(
        base.limits.tasks_max.as_deref(),
        Some("4096"),
        "app overrides the task cap"
    );
    assert_eq!(
        base.limits.memory_high.as_deref(),
        Some("70%"),
        "baseline throttle inherited"
    );
    assert_eq!(
        base.limits.memory_max.as_deref(),
        Some("16G"),
        "baseline ceiling inherited"
    );
}

#[test]
fn merge_app_clears_secrets_when_the_effective_posture_is_not_an_allowlist() {
    let mut base = resolve_no_plugins(raw_network("shared"), None);
    let app = ResolvedApp {
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        tasks: vec![],
        cmd: vec!["x".into()],
        home_scope: AppHomeScope::Global,
        env: vec![],
        binds: vec![],
        packages: vec![],
        network: None, // inherits the baseline's shared posture
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        secrets: vec![a_header_secret()],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
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
    };
    base.merge_app(app);
    assert!(base.secrets.is_empty());
    assert!(base
        .warnings
        .iter()
        .any(|w| w.contains("credential injection requires")));
}

#[test]
fn merge_app_keeps_secrets_under_an_allowlist_the_app_declares() {
    let mut base = resolve_no_plugins(raw_network("shared"), None);
    let app = ResolvedApp {
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        tasks: vec![],
        cmd: vec!["x".into()],
        home_scope: AppHomeScope::Global,
        env: vec![],
        binds: vec![],
        packages: vec![],
        network: Some(NetworkPolicy::Allowlist(
            crate::allowlist::EgressPolicy::new(vec![], vec![]),
        )),
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        secrets: vec![a_header_secret()],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
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
    };
    base.merge_app(app);
    assert_eq!(base.secrets.len(), 1);
    assert!(matches!(base.network, NetworkPolicy::Allowlist(_)));
}

#[test]
fn merge_app_applies_the_apps_default_methods_to_its_effective_allowlist() {
    use crate::allowlist::{classify, EgressPolicy, Methods};
    let read_default = Methods::Only(vec!["GET".to_string(), "HEAD".to_string()]);
    let app_with = |network: Option<NetworkPolicy>, default_methods: Methods| ResolvedApp {
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        cmd: vec!["x".into()],
        home_scope: AppHomeScope::Global,
        env: vec![],
        binds: vec![],
        packages: vec![],
        network,
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        secrets: vec![],
        tasks: vec![],
        default_methods,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
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
    };

    // (a) the app declares its own allowlist: an unscoped rule inherits the app's read-by-default
    // posture; an explicit `{*}` rule keeps all verbs.
    let mut base = resolve_no_plugins(raw_network("shared"), None);
    base.merge_app(app_with(
        Some(NetworkPolicy::Allowlist(EgressPolicy::new(
            vec![
                classify("read.test").unwrap(),
                classify("{*} write.test").unwrap(),
            ],
            vec![],
        ))),
        read_default.clone(),
    ));
    let NetworkPolicy::Allowlist(p) = &base.network else {
        panic!("expected an allowlist");
    };
    assert_eq!(
        p.allow_rules()[0].methods,
        read_default,
        "an unscoped rule inherits the app's {{GET,HEAD}} default"
    );
    assert_eq!(
        p.allow_rules()[1].methods,
        Methods::Any,
        "an explicit {{*}} rule keeps every verb"
    );

    // (b) the app sets no network (inherits the baseline allowlist) — the app's default still
    // narrows the inherited rules at merge time (the forced read-by-default reaches Mode-B apps
    // regardless of whose allowlist they run under).
    let mut base2 = resolve_no_plugins(raw_network("shared"), None);
    base2.network = NetworkPolicy::Allowlist(EgressPolicy::new(
        vec![classify("inherited.test").unwrap()],
        vec![],
    ));
    base2.merge_app(app_with(None, Methods::Only(vec!["GET".to_string()])));
    let NetworkPolicy::Allowlist(p2) = &base2.network else {
        panic!("expected an allowlist");
    };
    assert_eq!(
        p2.allow_rules()[0].methods,
        Methods::Only(vec!["GET".to_string()]),
        "an inherited baseline rule is narrowed by the app's default at merge"
    );
}

#[test]
fn a_baseline_default_methods_is_ignored_with_a_warning() {
    use crate::allowlist::{Decision, Methods};
    // `default_methods` is an app-only posture; on the baseline `[network]` it is parsed but
    // ignored (Mode-A `sbx run` stays all-verbs), with a warning so it is not silent.
    let global = RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: vec!["h.test".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: Some(vec!["GET".into()]),
            dns_cache_ttl: None,
        })),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, None);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("default_methods") && w.contains("baseline")),
        "a baseline `default_methods` must warn: {:?}",
        r.warnings
    );
    // The baseline rule is NOT narrowed — the interactive shell stays open.
    let NetworkPolicy::Allowlist(p) = &r.network else {
        panic!("expected an allowlist");
    };
    assert_eq!(
        p.allow_rules()[0].methods,
        Methods::Unspecified,
        "the baseline rule keeps all verbs (Mode A open)"
    );
    assert!(
        matches!(
            p.explain("h.test", 443, "/", "POST"),
            Decision::AllowedBy(_)
        ),
        "a POST on the baseline is allowed — run/shell is not read-by-default"
    );
}

#[test]
fn merge_app_dedups_a_secret_the_app_redeclares_for_the_same_host_and_header() {
    // A baseline credential and an app credential to the same host + header must collapse to
    // one (the app shadowing the baseline, like env/packages) — never two identical header
    // lines injected upstream.
    let mut base = resolve_no_plugins(raw_network("shared"), None);
    base.network = NetworkPolicy::Allowlist(crate::allowlist::EgressPolicy::new(vec![], vec![]));
    base.declared_secrets = vec![a_header_secret()];
    base.secrets = vec![a_header_secret()];
    let app = ResolvedApp {
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        tasks: vec![],
        cmd: vec!["x".into()],
        home_scope: AppHomeScope::Global,
        env: vec![],
        binds: vec![],
        packages: vec![],
        network: None,
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        secrets: vec![a_header_secret()],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
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
    };
    base.merge_app(app);
    assert_eq!(
        base.secrets.len(),
        1,
        "the app secret shadows its baseline twin, not duplicated"
    );
}

#[test]
fn merge_app_inherits_a_baseline_secret_when_the_app_opens_a_filtering_posture() {
    // A baseline credential declared under a non-filtering baseline posture (the `shared`
    // default) is absent from the baseline-effective set, but an app that opens a filtering
    // posture must still inherit it — the proxy under the app's posture is what injects it.
    let mut base = resolve_no_plugins(raw_network("shared"), None);
    base.declared_secrets = vec![a_header_secret()];
    assert!(
        base.secrets.is_empty(),
        "the baseline-effective set is cleared under a shared posture"
    );
    let app = ResolvedApp {
        notify: None,
        notify_origin: Default::default(),
        ssh_agent_confirm: false,
        ssh_agent_origin: Default::default(),
        ssh_agent: Vec::new(),
        cmd: vec!["x".into()],
        home_scope: AppHomeScope::Global,
        env: vec![],
        binds: vec![],
        packages: vec![],
        network: Some(NetworkPolicy::Allowlist(
            crate::allowlist::EgressPolicy::new(vec![], vec![]),
        )),
        gui: None,
        gpu: None,
        audio: None,
        dbus: None,
        limits: Default::default(),
        secrets: vec![],
        tasks: vec![],
        default_methods: crate::allowlist::Methods::Unspecified,
        cmd_origin: Default::default(),
        network_origin: Default::default(),
        gui_origin: Default::default(),
        gpu_origin: Default::default(),
        audio_origin: Default::default(),
        dbus_origin: Default::default(),
        forward: vec![],
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
    };
    base.merge_app(app);
    assert_eq!(
        base.secrets.len(),
        1,
        "the app's filtering posture inherits the baseline credential"
    );
}

fn pkg<'a>(packages: &'a [Package], name: &str) -> Option<&'a Package> {
    packages.iter().find(|p| p.name == name)
}

fn get<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
    env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

#[test]
fn global_only_is_honored_in_full() {
    let r = resolve_no_plugins(raw(&[("FOO", "g")], &["/srv/data"]), None);
    assert_eq!(get(&r.env, "FOO"), Some("g"));
    assert_eq!(r.binds, vec![ro_bind("/srv/data")]);
    assert!(r.warnings.is_empty());
}

#[test]
fn a_trusted_project_overrides_env_and_adds_binds() {
    let r = resolve_no_plugins(
        raw(&[("FOO", "global"), ("ONLYG", "g")], &["/srv/global"]),
        Some((
            raw(&[("FOO", "proj")], &["/srv/project"]),
            TrustState::Trusted,
        )),
    );
    // project wins on the shared key, global-only key survives
    assert_eq!(get(&r.env, "FOO"), Some("proj"));
    assert_eq!(get(&r.env, "ONLYG"), Some("g"));
    // binds are the union, global first
    assert_eq!(
        r.binds,
        vec![ro_bind("/srv/global"), ro_bind("/srv/project")]
    );
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_keeps_free_env_but_drops_binds() {
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw(&[("PROJVAR", "v")], &["/etc/ssh"]),
            TrustState::Untrusted,
        )),
    );
    // the free env field still applies
    assert_eq!(get(&r.env, "PROJVAR"), Some("v"));
    // the security bind is dropped, with a first-approval hint
    assert!(r.binds.is_empty());
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("untrusted"));
    assert!(r.warnings[0].contains("run `sbx trust`"));
}

#[test]
fn a_changed_project_drops_binds_with_a_reapproval_hint() {
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((raw(&[], &["/etc/ssh"]), TrustState::Changed)),
    );
    assert!(r.binds.is_empty());
    assert!(r.warnings[0].contains("changed since it was trusted"));
    assert!(r.warnings[0].contains("re-run `sbx trust`"));
}

/// A `RawConfig` whose only field is the given `binds` list (raw, un-canonicalized).
fn raw_with_binds(binds: Vec<RawBind>) -> RawConfig {
    RawConfig {
        binds,
        ..RawConfig::default()
    }
}

#[test]
fn a_trusted_rw_bind_resolves_writable() {
    // A `{ path = "...", mode = "rw" }` bind from a trusted source resolves read-write; a
    // bare-string sibling stays read-only. `resolve` does not canonicalize, so the paths are
    // the declared ones.
    let r = resolve_no_plugins(
        raw_with_binds(vec![
            RawBind::Path("/srv/ro".into()),
            RawBind::Detailed(schema::RawBindTable {
                path: Some("/srv/rw".into()),
                mode: Some("rw".into()),
            }),
        ]),
        None,
    );
    assert_eq!(r.binds, vec![ro_bind("/srv/ro"), rw_bind("/srv/rw")]);
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_cannot_obtain_a_writable_bind() {
    // The flagship property: a writable bind is strictly more privilege than a read-only one,
    // and an untrusted project gets no bind at all — so it can never open a rw hole to the host.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_with_binds(vec![RawBind::Detailed(schema::RawBindTable {
                path: Some("/etc".into()),
                mode: Some("rw".into()),
            })]),
            TrustState::Untrusted,
        )),
    );
    assert!(r.binds.is_empty(), "an untrusted rw bind must drop");
    assert!(r.warnings.iter().any(|w| w.contains("untrusted")));
}

#[test]
fn an_unknown_bind_mode_falls_closed_to_read_only() {
    // A misspelled mode must not be guessed into a wider exposure — it binds read-only, with a
    // warning naming the path and the accepted values.
    let r = resolve_no_plugins(
        raw_with_binds(vec![RawBind::Detailed(schema::RawBindTable {
            path: Some("/srv/data".into()),
            mode: Some("RW".into()),
        })]),
        None,
    );
    assert_eq!(r.binds, vec![ro_bind("/srv/data")]);
    assert!(r.warnings.iter().any(|w| w.contains("unknown mode `RW`")));
}

#[test]
fn an_app_bind_overrides_a_baseline_binds_mode_by_path() {
    // `merge_app` merges by path: an app bind whose path the baseline exposes overrides it in
    // place (the app's mode wins, consistent with every other overlay field), and a distinct
    // app path is added. Built through the real resolve + merge path (a global config is
    // trusted by location, so the app's rw binds are honored).
    let mut cfg = raw_with_binds(vec![RawBind::Path("/shared".into())]);
    cfg.app.insert(
        "demo".into(),
        RawApp {
            cmd: Some(schema::RawCmd::Argv(vec!["demo".into()])),
            binds: vec![
                RawBind::Detailed(schema::RawBindTable {
                    path: Some("/shared".into()),
                    mode: Some("rw".into()),
                }),
                RawBind::Detailed(schema::RawBindTable {
                    path: Some("/app-only".into()),
                    mode: Some("rw".into()),
                }),
            ],
            ..RawApp::default()
        },
    );
    let mut r = resolve_no_plugins(cfg, None);
    let app = r.apps["demo"].clone();
    r.merge_app(app);
    assert_eq!(
        r.binds,
        vec![rw_bind("/shared"), rw_bind("/app-only")],
        "the app's mode wins on a path collision (in place); a new app path is added"
    );
}

#[test]
fn an_app_bind_can_flip_a_baseline_rw_bind_back_to_read_only_in_place() {
    // The reverse of the previous test — the flip must work in *both* directions (an
    // upgrade-only merge would pass the ro→rw test yet silently keep a baseline rw bind
    // writable). The baseline carries two rw binds so the override's *position* is pinned: the
    // app downgrades the first to ro and leaves the second untouched, in place.
    let mut cfg = raw_with_binds(vec![
        RawBind::Detailed(schema::RawBindTable {
            path: Some("/first".into()),
            mode: Some("rw".into()),
        }),
        RawBind::Detailed(schema::RawBindTable {
            path: Some("/second".into()),
            mode: Some("rw".into()),
        }),
    ]);
    cfg.app.insert(
        "demo".into(),
        RawApp {
            cmd: Some(schema::RawCmd::Argv(vec!["demo".into()])),
            binds: vec![RawBind::Path("/first".into())],
            ..RawApp::default()
        },
    );
    let mut r = resolve_no_plugins(cfg, None);
    let app = r.apps["demo"].clone();
    r.merge_app(app);
    assert_eq!(
        r.binds,
        vec![ro_bind("/first"), rw_bind("/second")],
        "the app downgrades the first bind to read-only in place, leaving the second rw"
    );
}

#[test]
fn expand_bind_path_expands_a_leading_home_or_runtime_variable() {
    let home = Path::new("/home/u");
    let runtime = Path::new("/run/user/1000");
    let h = Some(home);
    let r = Some(runtime);

    // A bare `~`/`$HOME` becomes the home directory; a suffix joins under it.
    assert_eq!(expand_bind_path("~", h, r).unwrap(), home);
    assert_eq!(expand_bind_path("$HOME", h, r).unwrap(), home);
    assert_eq!(
        expand_bind_path("~/projects/x", h, r).unwrap(),
        Path::new("/home/u/projects/x")
    );
    assert_eq!(
        expand_bind_path("$HOME/.config", h, r).unwrap(),
        Path::new("/home/u/.config")
    );
    // `$XDG_RUNTIME_DIR` expands to the runtime directory (runtime sockets live there).
    assert_eq!(
        expand_bind_path("$XDG_RUNTIME_DIR/gnupg", h, r).unwrap(),
        Path::new("/run/user/1000/gnupg")
    );
}

#[test]
fn expand_bind_path_keeps_a_literal_path_verbatim_including_a_dollar_past_the_head() {
    let h = Some(Path::new("/home/u"));
    let r = Some(Path::new("/run/user/1000"));

    // An absolute literal is unchanged.
    assert_eq!(
        expand_bind_path("/data/work", h, r).unwrap(),
        Path::new("/data/work")
    );
    // The intentional divergence from `allow_paths`: a literal `$` *past* the head is kept —
    // a real mount source may contain one (an exFAT/NTFS recycle bin), so it must not be
    // rejected as a variable.
    assert_eq!(
        expand_bind_path("/mnt/win/$RECYCLE.BIN", h, r).unwrap(),
        Path::new("/mnt/win/$RECYCLE.BIN")
    );
    // A relative literal is returned as-is (Ok) so the caller's absolute-path check still
    // drops it with the "non-absolute" warning — expansion never invents a root.
    let rel = expand_bind_path("relative/dir", h, r).unwrap();
    assert!(
        !rel.is_absolute(),
        "a relative literal stays relative: {rel:?}"
    );
    // `~user` is not a supported form: no `$`, not `~`, so it stays literal (and non-absolute,
    // dropped downstream) rather than being mistaken for a variable.
    let tilde_user = expand_bind_path("~alice/x", h, r).unwrap();
    assert_eq!(tilde_user, Path::new("~alice/x"));
}

#[test]
fn expand_bind_path_rejects_unsupported_and_unset_variables() {
    let h = Some(Path::new("/home/u"));
    let r = Some(Path::new("/run/user/1000"));

    // An unrecognized `$VAR` at the head is refused — no arbitrary environment interpolation.
    assert!(expand_bind_path("$SECRET_DIR/x", h, r).is_err());
    assert!(expand_bind_path("$PATH", h, r).is_err());
    // A recognized head whose variable is unset is refused (fail closed, named in the message)
    // rather than silently expanding to an empty/relative path.
    assert!(expand_bind_path("~/x", None, r).is_err());
    assert!(expand_bind_path("$HOME", None, r).is_err());
    assert!(expand_bind_path("$XDG_RUNTIME_DIR/s", h, None).is_err());
}

#[test]
fn an_unknown_bind_mode_hints_a_case_variant() {
    // A mere case slip (`"RW"`) earns a "did you mean" nudge, while a genuinely unknown
    // token does not — both still fall closed to read-only.
    let (writable, reason) = bind_mode(Some("RW"));
    assert!(!writable);
    let reason = reason.expect("an unknown mode reports a reason");
    assert!(
        reason.contains("did you mean `\"rw\"`?"),
        "reason: {reason}"
    );

    let (_, reason) = bind_mode(Some("write"));
    assert!(
        !reason.unwrap().contains("did you mean"),
        "an unrelated token gets no case hint"
    );

    assert_eq!(bind_mode(None), (false, None));
    assert_eq!(bind_mode(Some("ro")), (false, None));
    assert_eq!(bind_mode(Some("rw")), (true, None));
}

#[test]
fn an_untrusted_project_cannot_set_reserved_env_keys() {
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw(
                &[
                    ("LD_PRELOAD", "/tmp/evil.so"),
                    ("PATH", "/tmp/bin"),
                    ("BASH_ENV", "/tmp/rc"),
                    ("SAFE", "ok"),
                ],
                &[],
            ),
            TrustState::Untrusted,
        )),
    );
    // the three reserved keys are refused, the ordinary one is kept
    assert_eq!(get(&r.env, "LD_PRELOAD"), None);
    assert_eq!(get(&r.env, "PATH"), None);
    assert_eq!(get(&r.env, "BASH_ENV"), None);
    assert_eq!(get(&r.env, "SAFE"), Some("ok"));
    assert_eq!(r.warnings.len(), 3, "one warning per refused key");
    assert!(r.warnings.iter().all(|w| w.contains("reserved env key")));
}

#[test]
fn a_trusted_project_may_set_reserved_env_keys() {
    // vouching for a config honors the whole schema; overriding PATH/LD_PRELOAD
    // harms only its own sandbox (out of scope by design).
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw(
                &[("LD_PRELOAD", "/opt/lib/shim.so"), ("PATH", "/opt/bin")],
                &[],
            ),
            TrustState::Trusted,
        )),
    );
    assert_eq!(get(&r.env, "LD_PRELOAD"), Some("/opt/lib/shim.so"));
    assert_eq!(get(&r.env, "PATH"), Some("/opt/bin"));
    assert!(r.warnings.is_empty());
}

#[test]
fn reserved_key_predicate_covers_the_ld_family_and_startup_hooks() {
    for k in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "HOME",
        "PATH",
        "NIX_LD",
        "NIX_LD_LIBRARY_PATH",
        "NIX_CONFIG",
        "NIX_USER_CONF_FILES",
        "NIX_CONF_DIR",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PS1",
        "IFS",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "NLSPATH",
        "HOSTALIASES",
        // GPU driver-load paths (mesa `dlopen`s a `.so` from these): an untrusted `[env]` must
        // not aim a trusted GPU-enabled app's mesa at an attacker library — code-load, like `LD_*`.
        "LIBGL_DRIVERS_PATH",
        "GBM_BACKENDS_PATH",
        "__EGL_VENDOR_LIBRARY_DIRS",
        // proxy-control (either case) and the CA-bundle keys: under an allowlist
        // the cage's only egress is sbx's filtering proxy, so an untrusted project
        // may not redirect it or swap the CA it trusts.
        "http_proxy",
        "HTTPS_PROXY",
        "no_proxy",
        "all_proxy",
        "ws_proxy",
        "WSS_PROXY",
        "NIX_SSL_CERT_FILE",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "npm_config_cafile",
        // the CA-bundle keys are matched case-insensitively (a nonstandard tool may read a
        // lowercase variant), so an off-case spelling is reserved too.
        "ssl_cert_file",
        "Curl_CA_Bundle",
    ] {
        assert!(is_reserved_env_key(k), "{k} should be reserved");
    }
    // a nix variable that does not inject configuration stays allowed — the
    // denylist closes the config-injection vectors, not nix's whole namespace.
    // `proxychains`/`NIX_PATH` look proxy/nix-ish but are neither a proxy-control
    // nor a CA/config-injection key.
    for k in [
        "EDITOR",
        "RUST_LOG",
        "MY_TOKEN",
        "LDFLAGS",
        "NIX_PATH",
        "PROXY_HOST",
    ] {
        assert!(!is_reserved_env_key(k), "{k} should be allowed");
    }
}

#[test]
fn a_non_absolute_bind_is_dropped() {
    // even a trusted project's relative bind is refused — extra binds are
    // out-of-project absolute paths by construction.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((raw(&[], &["relative/dir", "/abs/ok"]), TrustState::Trusted)),
    );
    assert_eq!(r.binds, vec![ro_bind("/abs/ok")]);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("non-absolute bind `relative/dir`"));
}

#[test]
fn a_malformed_env_key_is_dropped() {
    // a quoted TOML key could carry `=`; it must never reach `--setenv`
    let r = resolve_no_plugins(raw(&[("A=B", "x"), ("OK", "y")], &[]), None);
    assert_eq!(get(&r.env, "OK"), Some("y"));
    assert!(r.env.iter().all(|(k, _)| k != "A=B"));
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("malformed env key"));
}

#[test]
fn is_valid_env_key_rejects_empty_equals_and_control() {
    assert!(is_valid_env_key("FOO_BAR"));
    assert!(!is_valid_env_key(""));
    assert!(!is_valid_env_key("A=B"));
    assert!(!is_valid_env_key("A\nB"));
    assert!(!is_valid_env_key("A\0B"));
}

#[test]
fn global_packages_are_trusted_by_location() {
    let r = resolve_no_plugins(raw_packages(&[("node", "nix:nodejs_20")]), None);
    let node = pkg(&r.packages, "node").expect("global package present");
    assert_eq!(node.backend, Backend::Nix("nodejs_20".into()));
    assert_eq!(
        node.state,
        TrustState::Trusted,
        "a global package is trusted by location"
    );
    assert!(r.warnings.is_empty());
}

#[test]
fn a_trusted_project_package_overrides_the_global_one_by_name() {
    let r = resolve_no_plugins(
        raw_packages(&[("node", "nix:nodejs_20"), ("onlyg", "nix:ripgrep")]),
        Some((
            raw_packages(&[("node", "nix:nodejs_22")]),
            TrustState::Trusted,
        )),
    );
    // the project pins the shared name; the global-only tool survives
    let node = pkg(&r.packages, "node").unwrap();
    assert_eq!(node.backend, Backend::Nix("nodejs_22".into()));
    assert_eq!(node.state, TrustState::Trusted);
    assert_eq!(
        pkg(&r.packages, "onlyg").unwrap().backend,
        Backend::Nix("ripgrep".into())
    );
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_package_is_carried_but_flagged_untrusted() {
    // The launcher, not this stage, decides admission — so the package is kept,
    // stamped with its source's trust, with no drop and no warning here.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_packages(&[("node", "nix:nodejs_20")]),
            TrustState::Untrusted,
        )),
    );
    let node = pkg(&r.packages, "node").expect("untrusted package still carried");
    assert_eq!(node.backend, Backend::Nix("nodejs_20".into()));
    assert_eq!(node.state, TrustState::Untrusted);
    assert!(
        r.warnings.is_empty(),
        "admission warnings belong to the launcher, not the pure merge"
    );
}

#[test]
fn a_changed_project_package_keeps_the_changed_state_distinct_from_untrusted() {
    // The Changed≠Untrusted distinction must survive onto the package: a changed
    // project points the user at re-approval, not first approval.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_packages(&[("node", "nix:nodejs_20")]),
            TrustState::Changed,
        )),
    );
    assert_eq!(pkg(&r.packages, "node").unwrap().state, TrustState::Changed);
    assert_eq!(
        untrusted_reason(TrustState::Changed),
        "changed since it was trusted — re-run `sbx trust`"
    );
    assert_eq!(
        untrusted_reason(TrustState::Untrusted),
        "untrusted — run `sbx trust`"
    );
}

#[test]
fn a_malformed_or_unprefixed_package_is_dropped() {
    let r = resolve_no_plugins(
        raw_packages(&[
            ("../escape", "nix:hello"), // label escapes its directory
            ("ok", "nix:bad attr!"),    // attribute carries an illegal character
            ("bare", "nodejs_20"),      // no backend prefix — fail-closed, not a silent nix
            ("node", "nix:nodejs_20"),  // the well-formed one survives
        ]),
        None,
    );
    assert!(pkg(&r.packages, "../escape").is_none());
    assert!(pkg(&r.packages, "ok").is_none());
    assert!(
        pkg(&r.packages, "bare").is_none(),
        "a value with no nix:/mise: prefix is dropped, never treated as a bare nix attr"
    );
    assert_eq!(
        pkg(&r.packages, "node").unwrap().backend,
        Backend::Nix("nodejs_20".into())
    );
    assert_eq!(r.warnings.len(), 3, "one warning per dropped package");
    // the bare one names the fix, not a generic error
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("bare") && w.contains("backend prefix")));
}

#[test]
fn a_mise_prefixed_package_parses_as_a_mise_backend() {
    // `mise:<token>` routes to the in-cage mise equip; the token is kept verbatim, including
    // a `nix:`-prefixed nixhub token (`mise:nix:...`), which is mise's concern.
    let r = resolve_no_plugins(
        raw_packages(&[
            ("demo-tool", "mise:aqua:example/demo-tool"),
            ("other-tool", "mise:other-tool"),
            ("nixhub", "mise:nix:jq"),
        ]),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "demo-tool").unwrap().backend,
        Backend::Mise("aqua:example/demo-tool".into())
    );
    assert_eq!(
        pkg(&r.packages, "other-tool").unwrap().backend,
        Backend::Mise("other-tool".into())
    );
    assert_eq!(
        pkg(&r.packages, "nixhub").unwrap().backend,
        Backend::Mise("nix:jq".into())
    );
    assert!(r.warnings.is_empty());
}

#[test]
fn a_flake_prefixed_package_parses_as_a_flake_backend_and_rejects_local_sources() {
    // `flake:<ref>` routes to the in-cage `nix build`; a remote ref is kept verbatim, while a
    // local source (`path:`/`git+file:`) is refused — a package must never point the build at
    // the host filesystem.
    let r = resolve_no_plugins(
        raw_packages(&[
            ("flake-tool", "flake:github:example/flake-tool#tui"),
            ("pinned", "flake:github:o/r/abc123#default"),
            ("local", "flake:path:/etc"), // local scheme: refused
            ("localgit", "flake:git+file:///etc"), // local git scheme: refused
            ("filescheme", "flake:file:///etc/x.tar.gz"), // file:// tarball: refused
            ("tarballfile", "flake:tarball+file:///etc/x.tar.gz"), // tarball+file: refused
            ("bare", "flake:/etc"),       // bare absolute path: refused
            ("dotted", "flake:./x"),      // bare relative path: refused
            ("tilde", "flake:~/x"),       // bare home path: refused
            ("indirect", "flake:nixpkgs"), // registry-indirect (no scheme): refused
            ("spacey", "flake:github:o/r#a b"), // whitespace: refused
        ]),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "flake-tool").unwrap().backend,
        Backend::Flake("github:example/flake-tool#tui".into())
    );
    assert_eq!(
        pkg(&r.packages, "pinned").unwrap().backend,
        Backend::Flake("github:o/r/abc123#default".into())
    );
    for refused in [
        "local",
        "localgit",
        "filescheme",
        "tarballfile",
        "bare",
        "dotted",
        "tilde",
        "indirect",
        "spacey",
    ] {
        assert!(
            pkg(&r.packages, refused).is_none(),
            "{refused} should be refused"
        );
    }
    assert_eq!(r.warnings.len(), 9, "one warning per refused flake ref");
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("local") && w.contains("flake reference")));
}

fn raw_flakes(flakes: &[(&str, &str, Option<&str>)]) -> RawConfig {
    RawConfig {
        flakes: flakes
            .iter()
            .map(|(name, content, attr)| {
                (
                    name.to_string(),
                    RawInlineFlake {
                        flake: content.to_string(),
                        attr: attr.map(str::to_string),
                    },
                )
            })
            .collect(),
        ..RawConfig::default()
    }
}

const FLAKE_SRC: &str = "{ outputs = { self }: { packages.x86_64-linux.default = 1; }; }";

#[test]
fn an_inline_flake_folds_into_the_tool_set_with_the_right_attr() {
    // A `[flakes.<name>]` becomes a `Backend::FlakeInline` tool: the `flake` body is the
    // content, the `attr` defaults to `default` and is honored when set. The global layer is
    // trusted by location, so it is stamped Trusted (the launcher builds it).
    let r = resolve_no_plugins(
        raw_flakes(&[
            ("defaulted", FLAKE_SRC, None),
            ("explicit", FLAKE_SRC, Some("packages.x86_64-linux.tui")),
        ]),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "defaulted").unwrap().backend,
        Backend::FlakeInline {
            content: FLAKE_SRC.into(),
            attr: "default".into(),
        }
    );
    assert_eq!(
        pkg(&r.packages, "explicit").unwrap().backend,
        Backend::FlakeInline {
            content: FLAKE_SRC.into(),
            attr: "packages.x86_64-linux.tui".into(),
        }
    );
    assert!(r.packages.iter().all(|p| p.state == TrustState::Trusted));
}

#[test]
fn an_untrusted_projects_inline_flake_is_stamped_untrusted() {
    // Trust is recorded, not enforced, at resolve: an untrusted project's inline flake is
    // present but stamped Untrusted, so the launcher (`flake_inline_packages`, trusted-only)
    // withholds it — exactly like a `flake:` package.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_flakes(&[("tool", FLAKE_SRC, None)]),
            TrustState::Untrusted,
        )),
    );
    assert_eq!(
        pkg(&r.packages, "tool").unwrap().state,
        TrustState::Untrusted
    );
}

#[test]
fn a_malformed_inline_flake_is_dropped_with_a_warning() {
    // An empty `flake` body (could never build) and an invalid output attribute are both
    // dropped fail-closed, each with a warning; a well-formed sibling survives.
    let r = resolve_no_plugins(
        raw_flakes(&[
            ("empty", "   \n", None),
            ("badattr", FLAKE_SRC, Some("has space")),
            ("ok", FLAKE_SRC, None),
        ]),
        None,
    );
    assert!(pkg(&r.packages, "empty").is_none());
    assert!(pkg(&r.packages, "badattr").is_none());
    assert!(pkg(&r.packages, "ok").is_some());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("empty") && w.contains("flake")));
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("badattr") && w.contains("attribute")));
}

#[test]
fn a_name_in_both_packages_and_flakes_warns_and_the_inline_flake_wins() {
    // Declaring one name in both `[packages]` and `[flakes]` is a mistake — warn, and resolve
    // to the `[flakes]` inline source (applied last), never a silent drop.
    let mut raw = raw_packages(&[("dup", "nix:jq")]);
    raw.flakes.insert(
        "dup".to_string(),
        RawInlineFlake {
            flake: FLAKE_SRC.to_string(),
            attr: None,
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(matches!(
        pkg(&r.packages, "dup").unwrap().backend,
        Backend::FlakeInline { .. }
    ));
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("dup") && w.contains("both")));
}

#[test]
fn apply_flakes_refuses_an_untrusted_override_of_a_trusted_tool() {
    // The flagship integrity guard, at the tool granularity: with `protect_trusted`, an
    // untrusted layer's inline flake may not replace a tool a trusted layer already supplied
    // (else an untrusted project could swap a trusted app's tool for its own build), but it may
    // add a new one.
    let mut out = vec![Package {
        name: "guarded".into(),
        backend: Backend::Nix("jq".into()),
        state: TrustState::Trusted,
    }];
    let mut warnings = Vec::new();
    let flakes: BTreeMap<String, RawInlineFlake> = [("guarded", FLAKE_SRC), ("fresh", FLAKE_SRC)]
        .into_iter()
        .map(|(n, c)| {
            (
                n.to_string(),
                RawInlineFlake {
                    flake: c.to_string(),
                    attr: None,
                },
            )
        })
        .collect();
    apply_flakes(
        &mut out,
        &mut warnings,
        "project",
        flakes,
        TrustState::Untrusted,
        true,
    );
    // The trusted tool is untouched; the new one is added (untrusted, withheld at launch).
    assert_eq!(
        pkg(&out, "guarded").unwrap().backend,
        Backend::Nix("jq".into())
    );
    assert!(matches!(
        pkg(&out, "fresh").unwrap().backend,
        Backend::FlakeInline { .. }
    ));
    assert!(warnings.iter().any(|w| w.contains("guarded")));
}

#[test]
fn a_deb_prefixed_package_parses_as_a_deb_backend_and_requires_https_dot_deb() {
    // `deb:<url>` routes to the host-side prebuilt-.deb provisioner. Must be an `https://` URL
    // ending in `.deb` (a `.deb` is executed after autoPatchelf, so a plaintext or mistyped
    // source is refused) and carry no shell/nix metacharacter.
    let r = resolve_no_plugins(
        raw_packages(&[
            (
                "ocd",
                "deb:https://github.com/o/r/releases/latest/download/app-linux-amd64.deb",
            ),
            ("plain", "deb:http://example.com/x.deb"), // not https: refused
            ("notdeb", "deb:https://example.com/x.tar.gz"), // wrong extension: refused
            ("empty", "deb:https://"),                 // no path: refused
            ("spacey", "deb:https://example.com/a b.deb"), // whitespace: refused
        ]),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "ocd").unwrap().backend,
        Backend::Deb("https://github.com/o/r/releases/latest/download/app-linux-amd64.deb".into())
    );
    for refused in ["plain", "notdeb", "empty", "spacey"] {
        assert!(
            pkg(&r.packages, refused).is_none(),
            "{refused} should be refused"
        );
    }
    assert!(is_valid_deb_url(
        "https://github.com/o/r/releases/latest/download/app-linux-amd64.deb"
    ));
    assert!(!is_valid_deb_url("http://example.com/x.deb"));
    assert!(!is_valid_deb_url("https://example.com/x.tar.gz"));
    assert!(!is_valid_deb_url("https://example.com/a b.deb"));
    // the bare `deb:resolve` sentinel is not a locator: it is bound to its `[deb.<name>]` table
    // by `apply_tools`, so parsing it as a backend locator is refused (checked before the `deb:`
    // strip, or it would parse as a `deb:` URL `resolve` and be rejected for the wrong reason).
    assert!(parse_backend("deb:resolve").is_err());
}

#[test]
fn a_deb_github_locator_parses_as_a_deb_backend_and_is_charset_validated() {
    // `deb:github:<owner>/<repo>` routes to the same host-side provisioner, resolving the repo's
    // latest release to a `.deb` asset — so a project whose asset name embeds the version rolls
    // forward. The locator is stored verbatim in `Backend::Deb`.
    let r = resolve_no_plugins(
        raw_packages(&[
            ("demo-app", "deb:github:example/demo-app"),
            ("norepo", "deb:github:example"), // one segment: refused
            ("extra", "deb:github:a/b/c"),    // three segments: refused
            ("dots", "deb:github:../evil"),   // traversal segment: refused
            ("meta", "deb:github:o/r$x"),     // metacharacter: refused
        ]),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "demo-app").unwrap().backend,
        Backend::Deb("github:example/demo-app".into())
    );
    for refused in ["norepo", "extra", "dots", "meta"] {
        assert!(
            pkg(&r.packages, refused).is_none(),
            "{refused} should be refused"
        );
    }
    // the validator directly: two safe segments accepted, everything malformed rejected.
    assert!(is_valid_deb_github_locator("github:NixOS/nixpkgs"));
    assert!(is_valid_deb_github_locator("github:a-b.c/d_e-f.g"));
    for bad in [
        "NixOS/nixpkgs",       // no github: prefix
        "github:only",         // one segment
        "github:a/b/c",        // three segments
        "github:/repo",        // empty owner
        "github:owner/",       // empty repo
        "github:../repo",      // traversal
        "github:owner/re po",  // whitespace
        "github:owner/re\"po", // quote
    ] {
        assert!(
            !is_valid_deb_github_locator(bad),
            "{bad} should be rejected"
        );
    }
}

#[test]
fn a_deb_apt_locator_parses_as_a_deb_backend_and_is_charset_validated() {
    // `deb:apt:<https-Packages-url>` routes to the same host-side deb provisioner, tracking an
    // apt repo's highest-version `.deb` (for a vendor pool with no `latest` alias). The locator is
    // stored verbatim in `Backend::Deb`; the index URL points at the Packages index, not a `.deb`,
    // so the `.deb` suffix is not required.
    let idx =
        "apt:https://apt.example.com/demo-app/apt/stable/dists/stable/main/binary-amd64/Packages";
    let r = resolve_no_plugins(
        raw_packages(&[
            ("demo-app", &format!("deb:{idx}")),
            ("plain", "deb:http://h/x/Packages"), // not https: refused
            ("meta", "deb:apt:https://h/x$y/Packages"), // metacharacter: refused
            ("bare", "deb:apt:"),                 // empty url: refused
        ]),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "demo-app").unwrap().backend,
        Backend::Deb(idx.into())
    );
    for refused in ["plain", "meta", "bare"] {
        assert!(
            pkg(&r.packages, refused).is_none(),
            "{refused} should be refused"
        );
    }
    // the validator directly: an https Packages URL (no `.deb` suffix) is accepted; a plaintext,
    // metacharacter-bearing, non-`apt:`, or empty value is rejected.
    assert!(is_valid_deb_apt_locator(idx));
    for bad in [
        "https://h/x/Packages",    // no apt: prefix
        "apt:http://h/x/Packages", // plaintext
        "apt:https://h/x$y",       // metacharacter
        "apt:",                    // empty url
        "apt:https://",            // empty host
    ] {
        assert!(!is_valid_deb_apt_locator(bad), "{bad} should be rejected");
    }
}

#[test]
fn an_appimage_prefixed_package_parses_as_an_appimage_backend() {
    // `appimage:<url>` / `appimage:github:<owner>/<repo>` routes to the host-side prebuilt-AppImage
    // provisioner. A direct URL must be `https://` ending in `.AppImage` (case-insensitively) and
    // carry no shell/nix metacharacter; the `github:` form reuses the shared locator validator.
    let r = resolve_no_plugins(
            raw_packages(&[
                (
                    "demo-app",
                    "appimage:https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage",
                ),
                ("demo-repo", "appimage:github:example/demo-app"),
                ("plain", "appimage:http://example.com/x.AppImage"), // not https: refused
                ("notimg", "appimage:https://example.com/x.deb"),    // wrong extension: refused
                ("spacey", "appimage:https://example.com/a b.AppImage"), // whitespace: refused
                ("badrepo", "appimage:github:only"),                 // one segment: refused
            ]),
            None,
        );
    assert_eq!(
            pkg(&r.packages, "demo-app").unwrap().backend,
            Backend::AppImage(
                "https://github.com/example/demo-app/releases/download/v0.0.28/demo-app-0.0.28-x86_64.AppImage".into()
            )
        );
    assert_eq!(
        pkg(&r.packages, "demo-repo").unwrap().backend,
        Backend::AppImage("github:example/demo-app".into())
    );
    for refused in ["plain", "notimg", "spacey", "badrepo"] {
        assert!(
            pkg(&r.packages, refused).is_none(),
            "{refused} should be refused"
        );
    }
    // the validator directly: `.AppImage` and lowercase `.appimage` both accepted.
    assert!(is_valid_appimage_url("https://e/App-1.0-x86_64.AppImage"));
    assert!(is_valid_appimage_url("https://e/app.appimage"));
    assert!(!is_valid_appimage_url("http://e/x.AppImage")); // not https
    assert!(!is_valid_appimage_url("https://e/x.deb")); // wrong extension
    assert!(!is_valid_appimage_url("https://e/a b.AppImage")); // whitespace
                                                               // the bare `appimage:resolve` sentinel is not a locator: it is bound to its
                                                               // `[appimage.<name>]` table by `apply_tools`, so parsing it as a backend locator is refused
                                                               // (checked before the `appimage:` strip, or it would parse as an `appimage:` URL `resolve`).
    assert!(parse_backend("appimage:resolve").is_err());
}

#[test]
fn tarball_backend_parses_and_validates() {
    // a direct `.tar.gz`/`.tgz` https URL routes to Backend::Tarball; the percent-encoded space
    // a vendor filename can carry (`My%20App.tar.gz`) is accepted.
    assert_eq!(
        parse_backend("tarball:https://example.com/x/1.0/linux-x64/My%20App.tar.gz"),
        Ok(Backend::Tarball(
            "https://example.com/x/1.0/linux-x64/My%20App.tar.gz".into()
        ))
    );
    assert!(matches!(
        parse_backend("tarball:https://e/app.tgz"),
        Ok(Backend::Tarball(_))
    ));
    // the validator directly.
    assert!(is_valid_tarball_url("https://e/app.tar.gz"));
    assert!(is_valid_tarball_url("https://e/APP.TGZ")); // extension is case-insensitive
    assert!(is_valid_tarball_url("https://e/My%20App.tar.gz")); // %-encoded space
    assert!(!is_valid_tarball_url("http://e/app.tar.gz")); // not https
    assert!(!is_valid_tarball_url("https://e/app.deb")); // wrong extension
    assert!(!is_valid_tarball_url("https://e/app.tar")); // not gz-compressed
    assert!(!is_valid_tarball_url("https://e/a b.tar.gz")); // raw whitespace
                                                            // a mistyped form is refused up front; the bare `tarball:resolve` sentinel is refused here
                                                            // too (it is bound to its table by `apply_tools`, not parsed as a locator).
    assert!(parse_backend("tarball:https://e/app.zip").is_err());
    assert!(parse_backend("tarball:not-a-url").is_err());
    assert!(parse_backend("tarball:resolve").is_err());
}

/// A `RawConfig` declaring one `tarball:resolve` package: the `[packages]` sentinel plus its
/// paired `[tarball.<name>]` table carrying the resolver command argv.
fn raw_tarball_resolve(name: &str, command: &[&str]) -> RawConfig {
    let mut raw = raw_packages(&[(name, TARBALL_RESOLVE_SENTINEL)]);
    raw.tarball.insert(
        name.to_string(),
        RawResolve {
            resolve: command.iter().map(|s| s.to_string()).collect(),
        },
    );
    raw
}

const CMD: &[&str] = &[
    "sh",
    "-c",
    "curl -s https://api.example.com/releases | sed -n 1p",
];

#[test]
fn a_tarball_resolve_sentinel_binds_to_its_table() {
    // `[packages] app = "tarball:resolve"` + `[tarball.app]` folds into one TarballResolve
    // tool carrying the resolver command; the global layer is trusted by location.
    let r = resolve_no_plugins(raw_tarball_resolve("app", CMD), None);
    assert_eq!(
        pkg(&r.packages, "app").unwrap().backend,
        Backend::TarballResolve {
            command: CMD.iter().map(|s| s.to_string()).collect(),
        }
    );
    assert_eq!(pkg(&r.packages, "app").unwrap().state, TrustState::Trusted);
}

#[test]
fn an_orphan_tarball_table_is_ignored_with_a_warning() {
    // A `[tarball.<name>]` table with no matching `<name> = "tarball:resolve"` sentinel is not a
    // tool — the sentinel is the opt-in that keeps `[packages]` the canonical list.
    let mut raw = RawConfig::default();
    raw.tarball.insert(
        "orphan".to_string(),
        RawResolve {
            resolve: CMD.iter().map(|s| s.to_string()).collect(),
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "orphan").is_none());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("orphan") && w.contains("[packages]")));
}

#[test]
fn an_orphan_tarball_sentinel_is_ignored_with_a_warning() {
    // A `<name> = "tarball:resolve"` with no `[tarball.<name>]` table can never resolve.
    let r = resolve_no_plugins(raw_packages(&[("lonely", TARBALL_RESOLVE_SENTINEL)]), None);
    assert!(pkg(&r.packages, "lonely").is_none());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("lonely") && w.contains("[tarball.lonely]")));
}

#[test]
fn an_empty_tarball_resolve_command_is_dropped_with_a_warning() {
    // A `resolve` command that is empty (or only blanks) could never run — fail-closed.
    let r = resolve_no_plugins(raw_tarball_resolve("a", &["", "  "]), None);
    assert!(pkg(&r.packages, "a").is_none());
    assert!(r.warnings.iter().any(|w| w.contains("resolve")));
}

#[test]
fn an_untrusted_projects_tarball_resolve_is_stamped_untrusted() {
    // Trust is recorded, not enforced, at resolve: the launcher (`tarball_resolve_packages`,
    // trusted-only) withholds it and NEVER runs its command, like the direct `tarball:` form.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((raw_tarball_resolve("app", CMD), TrustState::Untrusted)),
    );
    assert_eq!(
        pkg(&r.packages, "app").unwrap().state,
        TrustState::Untrusted
    );
}

#[test]
fn apply_tarball_resolvers_refuses_an_untrusted_override_of_a_trusted_tool() {
    // The flagship integrity guard at tool granularity: with `protect_trusted`, an untrusted
    // layer's tarball resolver may not replace a tool a trusted layer already supplied, but may
    // add a new one — so an untrusted project cannot swap a trusted app's tool for its own command.
    let mut out = vec![Package {
        name: "guarded".into(),
        backend: Backend::Nix("jq".into()),
        state: TrustState::Trusted,
    }];
    let mut warnings = Vec::new();
    let tarball: BTreeMap<String, RawResolve> = ["guarded", "fresh"]
        .into_iter()
        .map(|n| {
            (
                n.to_string(),
                RawResolve {
                    resolve: CMD.iter().map(|s| s.to_string()).collect(),
                },
            )
        })
        .collect();
    let names: BTreeSet<String> = ["guarded".to_string(), "fresh".to_string()].into();
    apply_resolvers(
        &mut out,
        &mut warnings,
        "project",
        tarball,
        &names,
        TrustState::Untrusted,
        true,
        TARBALL_RESOLVE_SENTINEL,
        "tarball",
        |command| Backend::TarballResolve { command },
    );
    // The trusted tool is untouched; the new one is added (untrusted, withheld at launch).
    assert_eq!(
        pkg(&out, "guarded").unwrap().backend,
        Backend::Nix("jq".into())
    );
    assert!(matches!(
        pkg(&out, "fresh").unwrap().backend,
        Backend::TarballResolve { .. }
    ));
    assert!(warnings.iter().any(|w| w.contains("guarded")));
}

/// A `RawConfig` declaring one `deb:resolve` package: the `[packages]` sentinel plus its paired
/// `[deb.<name>]` table carrying the resolver command argv — the `deb:` twin of
/// [`raw_tarball_resolve`].
fn raw_deb_resolve(name: &str, command: &[&str]) -> RawConfig {
    let mut raw = raw_packages(&[(name, DEB_RESOLVE_SENTINEL)]);
    raw.deb.insert(
        name.to_string(),
        RawResolve {
            resolve: command.iter().map(|s| s.to_string()).collect(),
        },
    );
    raw
}

#[test]
fn a_deb_resolve_sentinel_binds_to_its_table() {
    // `[packages] app = "deb:resolve"` + `[deb.app]` folds into one DebResolve tool carrying the
    // resolver command; the global layer is trusted by location. The `deb:` analogue of
    // `a_tarball_resolve_sentinel_binds_to_its_table`.
    let r = resolve_no_plugins(raw_deb_resolve("app", CMD), None);
    assert_eq!(
        pkg(&r.packages, "app").unwrap().backend,
        Backend::DebResolve {
            command: CMD.iter().map(|s| s.to_string()).collect(),
        }
    );
    assert_eq!(pkg(&r.packages, "app").unwrap().state, TrustState::Trusted);
}

#[test]
fn an_orphan_deb_table_is_ignored_with_a_warning() {
    // A `[deb.<name>]` table with no matching `<name> = "deb:resolve"` sentinel is not a tool —
    // the sentinel is the opt-in that keeps `[packages]` the canonical list.
    let mut raw = RawConfig::default();
    raw.deb.insert(
        "orphan".to_string(),
        RawResolve {
            resolve: CMD.iter().map(|s| s.to_string()).collect(),
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "orphan").is_none());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("orphan") && w.contains("[packages]")));
}

#[test]
fn an_orphan_deb_sentinel_is_ignored_with_a_warning() {
    // A `<name> = "deb:resolve"` with no `[deb.<name>]` table can never resolve.
    let r = resolve_no_plugins(raw_packages(&[("lonely", DEB_RESOLVE_SENTINEL)]), None);
    assert!(pkg(&r.packages, "lonely").is_none());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("lonely") && w.contains("[deb.lonely]")));
}

#[test]
fn an_empty_deb_resolve_command_is_dropped_with_a_warning() {
    // A `resolve` command that is empty (or only blanks) could never run — fail-closed.
    let r = resolve_no_plugins(raw_deb_resolve("a", &["", "  "]), None);
    assert!(pkg(&r.packages, "a").is_none());
    assert!(r.warnings.iter().any(|w| w.contains("resolve")));
}

#[test]
fn an_untrusted_projects_deb_resolve_is_stamped_untrusted() {
    // Trust is recorded, not enforced, at resolve: the launcher (`deb_resolve_packages`,
    // trusted-only) withholds it and NEVER runs its command, like the direct `deb:` form.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((raw_deb_resolve("app", CMD), TrustState::Untrusted)),
    );
    assert_eq!(
        pkg(&r.packages, "app").unwrap().state,
        TrustState::Untrusted
    );
}

/// A `RawConfig` declaring one `appimage:resolve` package: the `[packages]` sentinel plus its
/// paired `[appimage.<name>]` table — the `appimage:` twin of [`raw_deb_resolve`].
fn raw_appimage_resolve(name: &str, command: &[&str]) -> RawConfig {
    let mut raw = raw_packages(&[(name, APPIMAGE_RESOLVE_SENTINEL)]);
    raw.appimage.insert(
        name.to_string(),
        RawResolve {
            resolve: command.iter().map(|s| s.to_string()).collect(),
        },
    );
    raw
}

#[test]
fn an_appimage_resolve_sentinel_binds_to_its_table() {
    // `[packages] app = "appimage:resolve"` + `[appimage.app]` folds into one AppImageResolve tool
    // carrying the resolver command; the global layer is trusted by location.
    let r = resolve_no_plugins(raw_appimage_resolve("app", CMD), None);
    assert_eq!(
        pkg(&r.packages, "app").unwrap().backend,
        Backend::AppImageResolve {
            command: CMD.iter().map(|s| s.to_string()).collect(),
        }
    );
    assert_eq!(pkg(&r.packages, "app").unwrap().state, TrustState::Trusted);
}

#[test]
fn an_orphan_appimage_table_is_ignored_with_a_warning() {
    // An `[appimage.<name>]` table with no matching `<name> = "appimage:resolve"` sentinel is not
    // a tool — the sentinel is the opt-in that keeps `[packages]` the canonical list.
    let mut raw = RawConfig::default();
    raw.appimage.insert(
        "orphan".to_string(),
        RawResolve {
            resolve: CMD.iter().map(|s| s.to_string()).collect(),
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "orphan").is_none());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("orphan") && w.contains("[packages]")));
}

#[test]
fn an_orphan_appimage_sentinel_is_ignored_with_a_warning() {
    // A `<name> = "appimage:resolve"` with no `[appimage.<name>]` table can never resolve.
    let r = resolve_no_plugins(raw_packages(&[("lonely", APPIMAGE_RESOLVE_SENTINEL)]), None);
    assert!(pkg(&r.packages, "lonely").is_none());
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("lonely") && w.contains("[appimage.lonely]")));
}

#[test]
fn an_untrusted_projects_appimage_resolve_is_stamped_untrusted() {
    // Trust is recorded, not enforced, at resolve: the launcher (`appimage_resolve_packages`,
    // trusted-only) withholds it and NEVER runs its command, like the direct `appimage:` form.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((raw_appimage_resolve("app", CMD), TrustState::Untrusted)),
    );
    assert_eq!(
        pkg(&r.packages, "app").unwrap().state,
        TrustState::Untrusted
    );
}

#[test]
fn the_three_resolve_forms_coexist_as_distinct_backends() {
    // The three sentinels bind to distinct tables (`[tarball.<name>]` / `[deb.<name>]` /
    // `[appimage.<name>]`) and build distinct backends, so three resolver packages (one of each
    // form) coexist — each is bound by its own sentinel, not confused for another's.
    let mut raw = raw_packages(&[
        ("web", TARBALL_RESOLVE_SENTINEL),
        ("app", DEB_RESOLVE_SENTINEL),
        ("img", APPIMAGE_RESOLVE_SENTINEL),
    ]);
    let cmd = || RawResolve {
        resolve: CMD.iter().map(|s| s.to_string()).collect(),
    };
    raw.tarball.insert("web".to_string(), cmd());
    raw.deb.insert("app".to_string(), cmd());
    raw.appimage.insert("img".to_string(), cmd());
    let r = resolve_no_plugins(raw, None);
    assert!(matches!(
        pkg(&r.packages, "web").unwrap().backend,
        Backend::TarballResolve { .. }
    ));
    assert!(matches!(
        pkg(&r.packages, "app").unwrap().backend,
        Backend::DebResolve { .. }
    ));
    assert!(matches!(
        pkg(&r.packages, "img").unwrap().backend,
        Backend::AppImageResolve { .. }
    ));
}

#[test]
fn package_name_and_attribute_validators() {
    for n in ["node", "python3", "rust-analyzer", "a.b", "_x"] {
        assert!(is_valid_package_name(n), "{n} should be a valid name");
    }
    for n in ["", ".", "..", "a/b", "a b", "a\0b"] {
        assert!(!is_valid_package_name(n), "{n} should be rejected");
    }
    for a in [
        "hello",
        "nodejs_20",
        "python3Packages.requests",
        "gcc-wrapper",
        "libstdc++",
    ] {
        assert!(is_valid_attr(a), "{a} should be a valid attribute");
    }
    for a in ["", "a b", "a#b", "a;b", "a$b", "a\"b"] {
        assert!(!is_valid_attr(a), "{a} should be rejected");
    }
    // mise tokens: the everyday forms plus PEP 508 extras (`pkg[web]`, `pkg[web,messaging]`)
    // admitted so a Python install can select optional dependency groups, and the
    // whitespace/control characters that a real token never carries still refused.
    for t in [
        "aqua:example/demo-tool",
        "bare-tool",
        "npm:@example/demo-tool",
        "aqua:example/demo-tool@0.141.0",
        "pipx:demo-agent",
        "pipx:demo-agent[web]",
        "pipx:demo-agent[web,messaging]",
    ] {
        assert!(is_valid_mise_token(t), "{t} should be a valid mise token");
    }
    for t in ["", "a b", "a$b", "a\"b", "a;b", "a\0b"] {
        assert!(!is_valid_mise_token(t), "{t} should be rejected");
    }
}

#[test]
fn a_global_nixpkgs_override_is_honored_a_trusted_project_overrides_it() {
    // global is trusted by location
    let r = resolve_no_plugins(raw_nixpkgs("nixos-23.11"), None);
    assert_eq!(r.nixpkgs_global.as_deref(), Some("nixos-23.11"));
    assert_eq!(r.nixpkgs_project, None);
    assert!(r.warnings.is_empty());

    // a trusted project sets its own (the launcher prefers it for the tools)
    let r = resolve_no_plugins(
        raw_nixpkgs("nixos-unstable"),
        Some((raw_nixpkgs("nixos-23.11"), TrustState::Trusted)),
    );
    assert_eq!(r.nixpkgs_global.as_deref(), Some("nixos-unstable"));
    assert_eq!(r.nixpkgs_project.as_deref(), Some("nixos-23.11"));
}

#[test]
fn an_untrusted_project_nixpkgs_override_is_dropped_with_a_warning() {
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((raw_nixpkgs("nixos-23.11"), state)),
        );
        assert_eq!(
            r.nixpkgs_project, None,
            "an untrusted project may not repoint the catalogue"
        );
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("nixpkgs"));
    }
}

#[test]
fn a_malformed_nixpkgs_source_is_dropped() {
    // a full flake reference is not (yet) a valid source: it must not reach nix
    let r = resolve_no_plugins(raw_nixpkgs("github:evil/nixpkgs"), None);
    assert_eq!(r.nixpkgs_global, None);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("malformed nixpkgs source"));
}

#[test]
fn the_default_network_posture_is_shared() {
    // No declared posture anywhere means the host network — the documented
    // default until the egress allowlist ships.
    assert_eq!(
        resolve_no_plugins(RawConfig::default(), None).network,
        NetworkPolicy::Shared
    );
}

#[test]
fn a_global_network_posture_is_honored_a_trusted_project_overrides_it() {
    // global is trusted by location
    let r = resolve_no_plugins(raw_network("none"), None);
    assert_eq!(r.network, NetworkPolicy::Isolated);
    assert!(r.warnings.is_empty());

    // a trusted project sets its own, overriding the global posture
    let r = resolve_no_plugins(
        raw_network("none"),
        Some((raw_network("shared"), TrustState::Trusted)),
    );
    assert_eq!(r.network, NetworkPolicy::Shared);
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_network_posture_is_dropped_with_a_warning() {
    // an untrusted project may not change the network — its choice is dropped and
    // the default (or the global posture) stands.
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(RawConfig::default(), Some((raw_network("none"), state)));
        assert_eq!(
            r.network,
            NetworkPolicy::Shared,
            "an untrusted project may not narrow the network"
        );
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("network"));
    }
}

#[test]
fn an_untrusted_project_cannot_widen_a_globally_isolated_network() {
    // The gate cuts both ways: with the global config isolating the network, an
    // untrusted project asking for `"shared"` cannot reopen it.
    let r = resolve_no_plugins(
        raw_network("none"),
        Some((raw_network("shared"), TrustState::Untrusted)),
    );
    assert_eq!(r.network, NetworkPolicy::Isolated);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("network"));
}

#[test]
fn an_unknown_network_posture_is_dropped_with_a_warning() {
    // a typo must not silently leave the network in the wrong posture
    let r = resolve_no_plugins(raw_network("offline"), None);
    assert_eq!(r.network, NetworkPolicy::Shared);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("unknown network policy `offline`"));
}

#[test]
fn the_default_gui_posture_is_none() {
    // No declared posture anywhere means no display — the cage exposes no compositor.
    assert_eq!(
        resolve_no_plugins(RawConfig::default(), None).gui,
        GuiPolicy::None
    );
}

#[test]
fn a_global_gui_posture_is_honored_a_trusted_project_overrides_it() {
    // global is trusted by location
    let r = resolve_no_plugins(raw_gui("wayland"), None);
    assert_eq!(r.gui, GuiPolicy::Wayland);
    assert!(r.warnings.is_empty());

    // a trusted project sets its own, overriding the global posture
    let r = resolve_no_plugins(
        raw_gui("wayland"),
        Some((raw_gui("none"), TrustState::Trusted)),
    );
    assert_eq!(r.gui, GuiPolicy::None);
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_gui_posture_is_dropped_with_a_warning() {
    // the flagship property at the baseline: an untrusted project may not open a display —
    // its `gui = "wayland"` is dropped and the default (no display) stands.
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(RawConfig::default(), Some((raw_gui("wayland"), state)));
        assert_eq!(
            r.gui,
            GuiPolicy::None,
            "an untrusted project may not open a display"
        );
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("gui"));
    }
}

#[test]
fn an_untrusted_project_cannot_close_a_globally_opened_gui() {
    // The gate cuts both ways: with the global config opening the display, an untrusted
    // project asking for `none` cannot touch it (it may not change a security field at all).
    let r = resolve_no_plugins(
        raw_gui("wayland"),
        Some((raw_gui("none"), TrustState::Untrusted)),
    );
    assert_eq!(r.gui, GuiPolicy::Wayland);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("gui"));
}

#[test]
fn the_offscreen_gui_posture_resolves_and_is_gated_like_wayland() {
    // `offscreen` is a real posture, not a typo swallowed by the fail-closed default.
    let r = resolve_no_plugins(raw_gui("offscreen"), None);
    assert_eq!(r.gui, GuiPolicy::Offscreen);
    assert!(r.warnings.is_empty());

    // It rides the same trust gate as every other `gui` value: an untrusted project cannot set it.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((raw_gui("offscreen"), TrustState::Untrusted)),
    );
    assert_eq!(r.gui, GuiPolicy::None);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("gui"));
}

#[test]
fn only_the_drawing_gui_postures_render() {
    // The single predicate behind the in-cage rendering prerequisites (fonts, the NSS CA import,
    // the netns dummy). `none` must never pull them in; both drawing postures must.
    assert!(!GuiPolicy::None.renders());
    assert!(GuiPolicy::Offscreen.renders());
    assert!(GuiPolicy::Wayland.renders());
}

#[test]
fn an_unknown_gui_posture_is_dropped_with_a_warning() {
    // a typo (or an X11 request, which is never offered) must not silently mis-set the posture
    let r = resolve_no_plugins(raw_gui("x11"), None);
    assert_eq!(r.gui, GuiPolicy::None);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("unknown gui posture `x11`"));
}

#[test]
fn the_default_forward_is_empty() {
    // No declared ports means no inbound hole — the cage exposes no forwarded port.
    assert!(resolve_no_plugins(RawConfig::default(), None)
        .forward
        .is_empty());
}

#[test]
fn a_trusted_project_forward_unions_onto_the_global_set() {
    // global is trusted by location; a trusted project *adds* ports (the union model), it does
    // not replace — and the merged set is sorted+deduped.
    let r = resolve_no_plugins(
        raw_forward(&[1455]),
        Some((raw_forward(&[8080, 1455]), TrustState::Trusted)),
    );
    assert_eq!(
        r.forward,
        vec![1455, 8080],
        "the project adds, never replaces"
    );
    assert!(r.warnings.is_empty());
    assert_eq!(r.forward_origin, Provenance::Project);
}

#[test]
fn an_untrusted_project_forward_is_dropped_but_the_global_survives() {
    // The flagship property: an untrusted project may not open a host port. Its `forward` is
    // dropped with a warning, and a globally-declared port survives intact (an agent runs *on*
    // untrusted code without that code opening an inbound hole).
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(raw_forward(&[1455]), Some((raw_forward(&[9090]), state)));
        assert_eq!(
            r.forward,
            vec![1455],
            "the trusted global port survives an untrusted overlay"
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("forward")),
            "the dropped untrusted forward must warn"
        );
    }
}

#[test]
fn a_zero_forward_port_is_dropped_with_a_warning() {
    // Port 0 is not a real port — dropped (warned), the rest kept.
    let r = resolve_no_plugins(raw_forward(&[0, 1455]), None);
    assert_eq!(r.forward, vec![1455]);
    assert!(r.warnings.iter().any(|w| w.contains("forward")));
}

#[test]
fn validate_device_path_accepts_devs_and_rejects_the_rest() {
    // A device node and a directory of them under `/dev/` are accepted verbatim.
    for good in [
        "/dev/dri",
        "/dev/kvm",
        "/dev/net/tun",
        "/dev/dri/renderD128",
    ] {
        assert_eq!(
            validate_device_path(good),
            Ok(PathBuf::from(good)),
            "{good}"
        );
    }
    // Everything outside `/dev/`, the degenerate `/dev`/`/dev/`, a relative path, and any `..`
    // component (which could escape `/dev`) is rejected — fail-closed.
    for bad in [
        "/etc/shadow",    // not under /dev
        "/devil/x",       // a textual prefix of /dev, not a path under it
        "/dev",           // the whole tree — would defeat the minimal /dev
        "/dev/",          // the degenerate bare tree
        "dev/dri",        // relative
        "/dev/../etc",    // escapes via ..
        "/dev/dri/../..", // escapes via ..
    ] {
        assert!(validate_device_path(bad).is_err(), "{bad} must be rejected");
    }
}

#[test]
fn the_default_devices_grant_is_empty() {
    // No `[devices]` means the cage keeps its minimal, hostless `/dev`.
    assert!(resolve_no_plugins(RawConfig::default(), None)
        .devices
        .is_empty());
}

#[test]
fn a_trusted_project_devices_grant_unions_onto_the_global_set() {
    // global is trusted by location; a trusted project *adds* devices (the union model), it does
    // not replace — and the merged set is sorted+deduped.
    let r = resolve_no_plugins(
        raw_devices(&["/dev/dri"]),
        Some((raw_devices(&["/dev/kvm", "/dev/dri"]), TrustState::Trusted)),
    );
    assert_eq!(
        r.devices,
        vec![PathBuf::from("/dev/dri"), PathBuf::from("/dev/kvm")],
        "the project adds, never replaces; deduped and sorted"
    );
    assert!(r.warnings.is_empty());
    assert_eq!(r.devices_origin, Provenance::Project);
}

#[test]
fn an_untrusted_project_devices_grant_is_dropped_but_the_global_survives() {
    // The flagship property: an untrusted project may not expose a host device. Its `[devices]`
    // is dropped with a warning, and a globally-granted device survives intact (an agent runs
    // *on* untrusted code without that code widening the kernel attack surface).
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(
            raw_devices(&["/dev/dri"]),
            Some((raw_devices(&["/dev/kvm"]), state)),
        );
        assert_eq!(
            r.devices,
            vec![PathBuf::from("/dev/dri")],
            "the trusted global device survives an untrusted overlay"
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("[devices]")),
            "the dropped untrusted device grant must warn"
        );
    }
}

#[test]
fn the_default_ssh_agent_grant_is_empty() {
    // No `[ssh_agent]` means no agent in the cage at all — not an agent holding no keys.
    let r = resolve_no_plugins(RawConfig::default(), None);
    assert!(r.ssh_agent.is_empty());
    assert_eq!(r.ssh_agent_origin, Provenance::Default);
}

#[test]
fn a_trusted_project_ssh_agent_grant_unions_onto_the_global_set() {
    // Global is trusted by location; a trusted project *adds* keys, it does not replace — and the
    // merged set is sorted and deduped, like the device grant.
    let r = resolve_no_plugins(
        raw_ssh_agent(&["deploy-key"]),
        Some((
            raw_ssh_agent(&["build-key", "deploy-key"]),
            TrustState::Trusted,
        )),
    );
    assert_eq!(
        r.ssh_agent,
        vec!["build-key".to_string(), "deploy-key".to_string()],
        "the project adds, never replaces; deduped and sorted"
    );
    assert!(r.warnings.is_empty());
    assert_eq!(r.ssh_agent_origin, Provenance::Project);
}

#[test]
fn an_untrusted_project_ssh_agent_grant_is_dropped_but_the_global_survives() {
    // The flagship property, on the field where it bites hardest: a key the cage can sign with
    // authenticates as the user everywhere that key is trusted, so untrusted code may not name one.
    // What the *user* granted globally still stands.
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(
            raw_ssh_agent(&["build-key"]),
            Some((raw_ssh_agent(&["deploy-key"]), state)),
        );
        assert_eq!(
            r.ssh_agent,
            vec!["build-key".to_string()],
            "the trusted global grant survives an untrusted overlay"
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("[ssh_agent]")),
            "the dropped untrusted grant must warn"
        );
    }
}

#[test]
fn an_unmatchable_ssh_agent_entry_is_dropped_and_the_rest_kept() {
    // The two spellings that would silently never match anything: a wildcard (there is none — a
    // grant names each key so it can be audited) and a fingerprint that lost its tail to a
    // copy-paste. Both are dropped with a warning; the valid entries beside them survive.
    let full = "SHA256:asAp51067jpFuXnlqkJj32f+5u0IhJDux0qGku0+XHs";
    let r = resolve_no_plugins(
        raw_ssh_agent(&[
            "*",
            "SHA256:asAp51067jpFuXnlq",
            full,
            "ansible on host-b",
            "  ",
        ]),
        None,
    );
    assert_eq!(
        r.ssh_agent,
        vec![full.to_string(), "ansible on host-b".to_string()],
        "a comment is free-form (spaces and all); only the unmatchable spellings go"
    );
    assert_eq!(
        r.warnings
            .iter()
            .filter(|w| w.contains("[ssh_agent] allow"))
            .count(),
        2,
        "one warning per dropped entry — a blank one is not an entry"
    );
    assert!(r.warnings.iter().any(|w| w.contains("no wildcard")));
}

#[test]
fn a_malformed_device_entry_is_dropped_and_the_rest_kept() {
    // A bad entry is dropped (warned), the valid ones kept — a collection, not all-or-nothing.
    let r = resolve_no_plugins(raw_devices(&["/etc/shadow", "/dev/kvm"]), None);
    assert_eq!(r.devices, vec![PathBuf::from("/dev/kvm")]);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("[devices] allow") && w.contains("/etc/shadow")));
}

#[test]
fn network_posture_validator() {
    let mut w = Vec::new();
    assert_eq!(
        validate_network(&mut w, "t", NetworkField::Posture("none".into())),
        Some(NetworkPolicy::Isolated)
    );
    assert_eq!(
        validate_network(&mut w, "t", NetworkField::Posture("shared".into())),
        Some(NetworkPolicy::Shared)
    );
    assert!(w.is_empty());
    assert_eq!(
        validate_network(&mut w, "t", NetworkField::Posture("bogus".into())),
        None
    );
    assert_eq!(w.len(), 1);
}

#[test]
fn a_trusted_project_allowlist_is_classified() {
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_network_allow(&["github.com", "*.nixos.org", "1.2.3.4", "ex.com/p"]),
            TrustState::Trusted,
        )),
    );
    match &r.network {
        NetworkPolicy::Allowlist(a) => {
            assert!(a.permits("github.com", 443, "/"));
            assert!(a.permits("cache.nixos.org", 443, "/nar/x"));
            assert!(a.permits("1.2.3.4", 443, "/"));
            assert!(
                !a.permits("1.2.3.4", 80, "/"),
                "a bare IP defaults to the https port only"
            );
            assert!(a.permits("ex.com", 443, "/p"));
            assert!(
                !a.permits("ex.com", 443, "/other"),
                "URL rule is path-exact"
            );
            assert!(!a.permits("evil.com", 443, "/"));
        }
        other => panic!("expected an allowlist, got {other:?}"),
    }
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_allowlist_is_dropped_with_a_warning() {
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((raw_network_allow(&["github.com"]), state)),
        );
        assert_eq!(
            r.network,
            NetworkPolicy::Shared,
            "an untrusted project may not set an egress allowlist"
        );
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("network"));
    }
}

#[test]
fn a_trusted_project_deny_carves_out_of_allow() {
    // deny always wins: a broad allow with a deny carve-out blocks the carve-out.
    let r = resolve_no_plugins(
        raw_network_table(&["*.nixos.org"], &["evil.nixos.org"]),
        Some((RawConfig::default(), TrustState::Trusted)),
    );
    match &r.network {
        NetworkPolicy::Allowlist(a) => {
            assert!(a.permits("cache.nixos.org", 443, "/"));
            assert!(!a.permits("evil.nixos.org", 443, "/"), "deny wins");
        }
        other => panic!("expected an allowlist, got {other:?}"),
    }
    assert!(r.warnings.is_empty());
}

#[test]
fn a_malformed_entry_in_either_list_is_dropped_keeping_the_valid_ones() {
    // global is trusted by location; a bad entry fails closed (that host stays
    // unreachable / its carve-out absent), the valid ones are kept, each drop named.
    let r = resolve_no_plugins(
        raw_network_table(&["github.com", "bad host"], &["evil.com", "also bad"]),
        None,
    );
    match &r.network {
        NetworkPolicy::Allowlist(a) => {
            assert_eq!(
                a.allow_rules().len(),
                1,
                "the malformed allow entry is dropped"
            );
            assert_eq!(
                a.deny_rules().len(),
                1,
                "the malformed deny entry is dropped"
            );
            assert!(a.permits("github.com", 443, "/"));
            assert!(!a.permits("evil.com", 443, "/"), "the kept deny still wins");
        }
        other => panic!("expected an allowlist, got {other:?}"),
    }
    assert_eq!(r.warnings.len(), 2);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("ignoring allow entry")));
    assert!(r.warnings.iter().any(|w| w.contains("ignoring deny entry")));
}

#[test]
fn an_unknown_network_mode_is_dropped_with_a_warning() {
    let r = resolve_no_plugins(
        RawConfig {
            network: Some(NetworkField::Table(NetworkTable {
                mute: vec![],
                http2: vec![],
                capture: None,
                capture_max_kb: None,
                mode: Some("bogus".into()),
                allow: vec![],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
                dns_cache_ttl: None,
            })),
            ..RawConfig::default()
        },
        None,
    );
    assert_eq!(r.network, NetworkPolicy::Shared);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("unknown network mode"));
}

#[test]
fn nixpkgs_source_validator() {
    for s in [
        "nixos-unstable",
        "nixos-23.11",
        "release-23.11",
        "master",
        "staging-next",
        "9ae611a455b90cf061d8f332b977e387bda8e1ca",
    ] {
        assert!(is_valid_nixpkgs_source(s), "{s} should be valid");
    }
    for s in [
        "",
        "github:NixOS/nixpkgs",
        "git+https://x",
        "path:/etc",
        "a b",
        "a;b",
    ] {
        assert!(!is_valid_nixpkgs_source(s), "{s} should be rejected");
    }
}

#[allow(clippy::too_many_arguments)]
fn raw_secret(
    from_env: Option<&str>,
    from_file: Option<&str>,
    to: &str,
    header: &str,
    ty: Option<&str>,
    prefix: Option<&str>,
) -> (String, RawHostSecret) {
    // Map the convenience params onto a `from` ref so the many call sites stay terse. The
    // host is returned alongside the secret, since it is the section key in the new shape.
    let from = match (from_env, from_file) {
        (Some(v), None) => Some(SecretFrom::One(format!("env://{v}"))),
        (None, Some(p)) => Some(SecretFrom::One(format!("file://{p}"))),
        (None, None) => None,
        (Some(_), Some(_)) => panic!("test helper: set at most one of from_env / from_file"),
    };
    (
        to.into(),
        RawHostSecret {
            name: None,
            description: None,
            kind: Some("http-header".into()),
            key: None,
            from,
            header: Some(header.into()),
            value_type: ty.map(String::from),
            prefix: prefix.map(String::from),
        },
    )
}

/// Group `(host, secret)` pairs into a `[secret]` section, collapsing repeats of the same
/// host into a `[[secret."host"]]` array (so the duplicate-target and multi-header cases are
/// expressible).
fn raw_secret_section(secrets: Vec<(String, RawHostSecret)>) -> RawSecretSection {
    let mut hosts: BTreeMap<String, RawHostSecrets> = BTreeMap::new();
    for (host, s) in secrets {
        match hosts.remove(&host) {
            None => {
                hosts.insert(host, RawHostSecrets::One(s));
            }
            Some(RawHostSecrets::One(first)) => {
                hosts.insert(host, RawHostSecrets::Many(vec![first, s]));
            }
            Some(RawHostSecrets::Many(mut v)) => {
                v.push(s);
                hosts.insert(host, RawHostSecrets::Many(v));
            }
        }
    }
    RawSecretSection {
        defaults: None,
        hosts,
    }
}

/// A `RawConfig` declaring a network allowlist (so secrets are not dropped by the
/// allowlist dependency) plus the given secrets.
fn raw_secrets(allow: &[&str], secrets: Vec<(String, RawHostSecret)>) -> RawConfig {
    RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
        })),
        secret: Some(raw_secret_section(secrets)),
        ..RawConfig::default()
    }
}

/// A `RawHostSecret` whose `from` is the given resolver-ref list, for the validation tests.
fn raw_secret_from(from: Vec<&str>) -> RawHostSecret {
    RawHostSecret {
        name: None,
        description: None,
        kind: Some("http-header".into()),
        key: None,
        from: Some(SecretFrom::Many(
            from.into_iter().map(String::from).collect(),
        )),
        header: Some("Authorization".into()),
        value_type: Some("bearer".into()),
        prefix: None,
    }
}

/// Validate a host secret against empty defaults, for the source/parse tests. The host is a
/// fixed concrete target so the tests focus on the source form.
fn validate(secret: RawHostSecret) -> Result<HeaderSecret, String> {
    vhs("api.github.com", secret, &SecretDefaults::default())
}

// A credential with no `name` is still named — after its destination host, the section key — so
// the inventory and a redacted value always have something to print.
#[test]
fn a_secret_without_a_name_is_named_after_its_host() {
    let secret = validate(raw_secret_from(vec!["env://TOKEN"])).unwrap();
    assert_eq!(secret.name, "api.github.com");
    assert_eq!(secret.description, None);
}

// An explicit name and description survive validation; the description is the label the inventory
// prints beside the name.
#[test]
fn an_explicit_name_and_description_are_kept() {
    let mut raw = raw_secret_from(vec!["env://TOKEN"]);
    raw.name = Some("gh_token".into());
    raw.description = Some("Read-only GitHub API token".into());
    let secret = validate(raw).unwrap();
    assert_eq!(secret.name, "gh_token");
    assert_eq!(
        secret.description.as_deref(),
        Some("Read-only GitHub API token")
    );
}

// The name is rendered into output as `${name}`, so a character that could close the placeholder
// or drive a terminal is refused at validation rather than reaching a text sink.
#[test]
fn a_name_carrying_a_placeholder_or_control_character_is_refused() {
    for bad in ["gh}token", "gh token", "gh\ntoken", "gh$token", ""] {
        let mut raw = raw_secret_from(vec!["env://TOKEN"]);
        raw.name = Some(bad.into());
        assert!(
            validate(raw).is_err(),
            "a name of {bad:?} must be refused — it is rendered into output"
        );
    }
}

// A description is a label, not a document: control characters become spaces (so it can neither
// forge a second output line nor emit an escape sequence), whitespace runs collapse, and the
// result is capped. A sloppy description is cleaned, never a reason to drop the credential.
#[test]
fn a_description_is_flattened_to_one_capped_line() {
    let mut raw = raw_secret_from(vec!["env://TOKEN"]);
    raw.description = Some("first\nsecond\t\tthird\u{1b}[31m".into());
    let secret = validate(raw).unwrap();
    assert_eq!(
        secret.description.as_deref(),
        Some("first second third [31m")
    );

    let mut long = raw_secret_from(vec!["env://TOKEN"]);
    long.description = Some("x".repeat(500));
    let capped = validate(long).unwrap().description.unwrap();
    assert_eq!(capped.chars().count(), 200, "the description is capped");
}

// Two credentials may legally share a name (it is a label, not a key), but a redacted value
// prints only the name — so the reader could not tell which was withheld. Warn, naming both
// destinations, and keep both.
#[test]
fn two_secrets_sharing_a_name_warn_and_both_survive() {
    let mut a = raw_secret_from(vec!["env://A"]);
    a.name = Some("shared".into());
    let mut b = raw_secret_from(vec!["env://B"]);
    b.name = Some("shared".into());
    let first = vhs("api.github.com", a, &SecretDefaults::default()).unwrap();
    let second = vhs("api.npmjs.org", b, &SecretDefaults::default()).unwrap();

    let mut out = Vec::new();
    let mut warnings = Vec::new();
    upsert_secret(&mut out, &mut warnings, "global config", first);
    upsert_secret(&mut out, &mut warnings, "global config", second);

    assert_eq!(out.len(), 2, "both credentials are kept");
    assert_eq!(warnings.len(), 1, "the name clash warns once: {warnings:?}");
    let w = &warnings[0];
    assert!(w.contains("shared"), "the warning names the name: {w}");
    assert!(w.contains("api.github.com"), "and the first target: {w}");
    assert!(w.contains("api.npmjs.org"), "and the second target: {w}");
}

/// [`validate_host_secret`] with no installed plugins — the default for the secret tests,
/// which exercise the built-in resolvers. The plugin-scheme tests build a registry explicitly.
fn vhs(
    host: &str,
    secret: RawHostSecret,
    defaults: &SecretDefaults,
) -> Result<HeaderSecret, String> {
    validate_host_secret(host, secret, defaults, &PluginRegistry::default())
}

/// [`resolve`] with no installed plugins — the default for the layering tests.
fn resolve_no_plugins(global: RawConfig, project: Option<(RawConfig, TrustState)>) -> Resolved {
    super::resolve(global, project, &PluginRegistry::default())
}

// --- one-shot override application (`apply_override` / `apply_override_channel`) ---

/// Apply a one-shot override built from `raw` onto a resolved config, returning the result.
/// Expects the override to be valid (the hard-error path is covered by its own test).
fn with_override(mut resolved: Resolved, raw: RawConfig) -> Resolved {
    resolved
        .apply_override(Override::for_test(raw))
        .expect("the override applies");
    resolved
}

#[test]
fn a_set_but_invalid_override_security_value_is_a_hard_error_and_mutates_nothing() {
    // The fail-closed contract on the security half: a typo'd `network` value has no safe
    // fallback — it must be a hard error, never a silent revert to the (possibly wider) baseline.
    let mut resolved = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(resolved.network, NetworkPolicy::Shared);
    let errs = resolved
        .apply_override(Override::for_test(RawConfig {
            network: Some(NetworkField::Posture("nonee".into())),
            ..RawConfig::default()
        }))
        .unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("network")),
        "the error should name the offending field: {errs:?}"
    );
    // and nothing was applied — the baseline posture stands (never a silent wider fallback).
    assert_eq!(resolved.network, NetworkPolicy::Shared);
    assert_eq!(resolved.network_origin, Provenance::Default);
}

#[test]
fn an_override_dbus_flag_applies_the_bool() {
    // `--dbus` (bare = true) stands up the in-cage portal for one launch (trusted by invocation).
    // `dbus` is a bool, so — unlike `gui`/`network` — no value can be invalid at this layer; a
    // bad `--dbus=incage`-style string is rejected earlier, at flag parse (see overrides.rs).
    let mut resolved = resolve_no_plugins(RawConfig::default(), None);
    assert!(!resolved.dbus);
    resolved
        .apply_override(Override::for_test(RawConfig {
            dbus: Some(true),
            ..RawConfig::default()
        }))
        .unwrap();
    assert!(resolved.dbus);
    assert_eq!(resolved.dbus_origin, Provenance::Override);
}

#[test]
fn an_override_proc_posture_applies_and_beats_the_baseline_both_directions() {
    use crate::proc_policy::ProcMode;
    use schema::ProcField;

    // Raise: a baseline with no proc (`off`) is lifted to `enforce` by the override — the final
    // word — and the origin stamps `Override`.
    let mut raised = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(raised.proc.mode, ProcMode::Off);
    raised = with_override(
        raised,
        RawConfig {
            proc: Some(ProcField::Mode("enforce".into())),
            ..RawConfig::default()
        },
    );
    assert_eq!(raised.proc.mode, ProcMode::Enforce);
    assert_eq!(raised.proc_origin, Provenance::Override);

    // Lower/disable: a globally-declared `enforce` baseline can be turned *off* for one launch by
    // the override (top authority by invocation — the parity with `--gpu=false`).
    let global = RawConfig {
        proc: Some(ProcField::Mode("enforce".into())),
        ..RawConfig::default()
    };
    let mut disabled = resolve_no_plugins(global, None);
    assert_eq!(disabled.proc.mode, ProcMode::Enforce);
    disabled = with_override(
        disabled,
        RawConfig {
            proc: Some(ProcField::Mode("off".into())),
            ..RawConfig::default()
        },
    );
    assert_eq!(disabled.proc.mode, ProcMode::Off);
    assert_eq!(disabled.proc_origin, Provenance::Override);
}

#[test]
fn a_mode_less_override_proc_table_inherits_the_baseline_mode() {
    use crate::proc_policy::ProcMode;
    use schema::{ProcField, ProcTable};

    // A `--config` blob's `[proc]\ndeny=[…]` with no `mode` keeps the baseline's effective mode
    // (here a global `enforce`) while adding its deny rule — the parent-mode inheritance, so the
    // override does not silently reset the posture to `off`.
    let global = RawConfig {
        proc: Some(ProcField::Mode("enforce".into())),
        ..RawConfig::default()
    };
    let resolved = with_override(
        resolve_no_plugins(global, None),
        RawConfig {
            proc: Some(ProcField::Table(ProcTable {
                mode: None,
                allow: vec![],
                deny: vec!["curl".into()],
            })),
            ..RawConfig::default()
        },
    );
    assert_eq!(resolved.proc.mode, ProcMode::Enforce);
    assert_eq!(resolved.proc.deny.len(), 1);
    assert_eq!(resolved.proc_origin, Provenance::Override);
}

#[test]
fn a_set_but_invalid_override_proc_mode_is_a_hard_error_and_mutates_nothing() {
    use crate::proc_policy::ProcMode;
    use schema::ProcField;

    // A mistyped proc mode has no safe fallback: keeping the baseline (here `enforce`) would run a
    // *different* posture than the user's explicit intent, so it is fatal — never a silent revert.
    let global = RawConfig {
        proc: Some(ProcField::Mode("enforce".into())),
        ..RawConfig::default()
    };
    let mut resolved = resolve_no_plugins(global, None);
    let errs = resolved
        .apply_override(Override::for_test(RawConfig {
            proc: Some(ProcField::Mode("enfroce".into())),
            ..RawConfig::default()
        }))
        .unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("proc")),
        "the error should name the offending field: {errs:?}"
    );
    // and nothing was applied — the baseline posture stands.
    assert_eq!(resolved.proc.mode, ProcMode::Enforce);
    assert_eq!(resolved.proc_origin, Provenance::Global);
}

#[test]
fn a_set_but_invalid_override_channel_is_a_hard_error() {
    let mut resolved = resolve_no_plugins(RawConfig::default(), None);
    let err = resolved
        .apply_override_channel(&Override::for_test(RawConfig {
            nixpkgs: Some("git+https://evil".into()),
            ..RawConfig::default()
        }))
        .unwrap_err();
    assert!(err.contains("nixpkgs"), "{err}");
    assert_eq!(resolved.nixpkgs_project, None);
}

#[test]
fn an_additive_override_field_fails_closed_by_skipping_a_bad_entry() {
    // An override's *additive* fields (a relative bind here) fail closed — the bad entry is
    // dropped with a warning, not a hard error, because a missing bind is less capability, never
    // a wider posture. So this must still be `Ok` (unlike an invalid scalar posture).
    let resolved = resolve_no_plugins(RawConfig::default(), None);
    let before = resolved.binds.len();
    let r = with_override(
        resolved,
        RawConfig {
            binds: vec![RawBind::Path("relative/path".into())],
            ..RawConfig::default()
        },
    );
    assert_eq!(r.binds.len(), before, "the relative bind is dropped");
    assert!(
        r.warnings.iter().any(|w| w.contains("override")),
        "the dropped bind should be warned: {:?}",
        r.warnings
    );
}

#[test]
fn an_override_replaces_the_network_posture_and_beats_a_trusted_project() {
    // A trusted project sets an allowlist; the override forces `none`. The override wins, and the
    // winning posture is stamped `Override` for `sbx config show`.
    let project = RawConfig {
        network: Some(net_field("deny", &["github.com"], &[])),
        ..RawConfig::default()
    };
    let resolved = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
    assert!(matches!(resolved.network, NetworkPolicy::Allowlist(_)));
    let r = with_override(
        resolved,
        RawConfig {
            network: Some(NetworkField::Posture("none".into())),
            ..RawConfig::default()
        },
    );
    assert_eq!(r.network, NetworkPolicy::Isolated);
    assert_eq!(r.network_origin, Provenance::Override);
}

#[test]
fn an_override_beats_an_app_overlay() {
    // The flagship: `sbx app <name> --config network="shared"` must beat the app's own posture,
    // because the override is applied *after* the app overlay merges.
    let app = raw_app(
        &["true"],
        &[],
        &[],
        &[],
        Some(net_field("deny", &["github.com"], &[])),
    );
    let mut resolved = resolve_no_plugins(raw_with_app("demo", app), None);
    let app_cfg = resolved.apps.remove("demo").expect("the app resolves");
    resolved.merge_app(app_cfg);
    assert!(matches!(resolved.network, NetworkPolicy::Allowlist(_)));
    let r = with_override(
        resolved,
        RawConfig {
            network: Some(NetworkField::Posture("shared".into())),
            ..RawConfig::default()
        },
    );
    assert_eq!(r.network, NetworkPolicy::Shared);
    assert_eq!(r.network_origin, Provenance::Override);
}

#[test]
fn an_override_upserts_env_over_the_baseline_with_override_provenance() {
    let resolved = resolve_no_plugins(
        RawConfig {
            env: BTreeMap::from([("FOO".to_string(), "base".to_string())]),
            ..RawConfig::default()
        },
        None,
    );
    let r = with_override(
        resolved,
        RawConfig {
            env: BTreeMap::from([
                ("FOO".to_string(), "over".to_string()),
                ("NEW".to_string(), "1".to_string()),
            ]),
            ..RawConfig::default()
        },
    );
    assert_eq!(
        r.env
            .iter()
            .find(|(k, _)| k == "FOO")
            .map(|(_, v)| v.as_str()),
        Some("over")
    );
    assert_eq!(r.env_layer.get("FOO").copied(), Some(Provenance::Override));
    assert_eq!(r.env_layer.get("NEW").copied(), Some(Provenance::Override));
}

#[test]
fn an_override_gui_and_limits_win_and_are_stamped_override() {
    let resolved = resolve_no_plugins(RawConfig::default(), None);
    let r = with_override(
        resolved,
        RawConfig {
            gui: Some("wayland".into()),
            limits: Some(schema::RawLimits {
                rest: Default::default(),
                memory_high: None,
                memory_max: None,
                tasks_max: Some(schema::RawLimit::Number(4096)),
            }),
            ..RawConfig::default()
        },
    );
    assert_eq!(r.gui, GuiPolicy::Wayland);
    assert_eq!(r.gui_origin, Provenance::Override);
    assert_eq!(r.limits.tasks_max.as_deref(), Some("4096"));
    assert_eq!(r.limits_origin.tasks_max, Provenance::Override);
}

#[test]
fn an_override_relaxes_seccomp_and_grants_a_device_stamped_override() {
    // Trusted by invocation: a one-shot override may relax the denylist and grant a device that a
    // config file gates trusted-only. Both land, stamped `Override`.
    let resolved = resolve_no_plugins(RawConfig::default(), None);
    assert!(resolved.seccomp.is_empty() && resolved.devices.is_empty());
    let r = with_override(
        resolved,
        RawConfig {
            seccomp: raw_seccomp(&["ptrace"]).seccomp,
            devices: raw_devices(&["/dev/kvm"]).devices,
            ..RawConfig::default()
        },
    );
    assert!(
        r.seccomp.tokens().iter().any(|t| t == "ptrace"),
        "the override relaxes the denylist: {:?}",
        r.seccomp.tokens()
    );
    assert_eq!(r.seccomp_origin, Provenance::Override);
    assert_eq!(r.devices, vec![PathBuf::from("/dev/kvm")]);
    assert_eq!(r.devices_origin, Provenance::Override);
}

#[test]
fn an_override_seccomp_and_devices_union_onto_a_trusted_baseline() {
    // The override *adds* to what a trusted global already granted (the additive/union model),
    // never dropping the baseline's relaxation or device.
    let resolved = resolve_no_plugins(
        RawConfig::default(),
        Some((
            RawConfig {
                seccomp: raw_seccomp(&["unshare"]).seccomp,
                devices: raw_devices(&["/dev/dri"]).devices,
                ..RawConfig::default()
            },
            TrustState::Trusted,
        )),
    );
    let r = with_override(
        resolved,
        RawConfig {
            seccomp: raw_seccomp(&["ptrace"]).seccomp,
            devices: raw_devices(&["/dev/kvm"]).devices,
            ..RawConfig::default()
        },
    );
    let toks = r.seccomp.tokens();
    assert!(
        toks.iter().any(|t| t == "unshare") && toks.iter().any(|t| t == "ptrace"),
        "both the baseline and override relaxations survive: {toks:?}"
    );
    assert_eq!(
        r.devices,
        vec![PathBuf::from("/dev/dri"), PathBuf::from("/dev/kvm")],
        "the override device unions onto the baseline's, sorted"
    );
}

#[test]
fn an_override_with_a_malformed_seccomp_or_device_fails_closed() {
    // Additive fields: a bad token/path is warned and skipped (Ok), less relaxation not more —
    // never a hard error like a scalar posture.
    let resolved = resolve_no_plugins(RawConfig::default(), None);
    let r = with_override(
        resolved,
        RawConfig {
            seccomp: raw_seccomp(&["not_a_syscall"]).seccomp,
            devices: raw_devices(&["/etc/shadow"]).devices,
            ..RawConfig::default()
        },
    );
    assert!(
        r.seccomp.is_empty(),
        "an unknown token grants no relaxation"
    );
    assert!(r.devices.is_empty(), "a non-/dev path grants no device");
    assert!(
        r.warnings.iter().filter(|w| w.contains("override")).count() >= 2,
        "both bad entries warn: {:?}",
        r.warnings
    );
}

#[test]
fn the_override_channel_pins_nixpkgs_authoritatively() {
    let mut resolved = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(resolved.nixpkgs_project, None);
    resolved
        .apply_override_channel(&Override::for_test(RawConfig {
            nixpkgs: Some("nixos-23.11".into()),
            ..RawConfig::default()
        }))
        .expect("a valid channel applies");
    assert_eq!(resolved.nixpkgs_project.as_deref(), Some("nixos-23.11"));
}

#[test]
fn an_empty_override_leaves_the_resolved_config_untouched() {
    let resolved = resolve_no_plugins(RawConfig::default(), None);
    let (net, origin, warns) = (
        resolved.network.clone(),
        resolved.network_origin,
        resolved.warnings.len(),
    );
    let r = with_override(resolved, RawConfig::default());
    assert_eq!(r.network, net);
    assert_eq!(r.network_origin, origin);
    assert_eq!(r.warnings.len(), warns);
}

#[test]
fn the_egress_stats_toggle_defaults_on_and_is_gated_trusted_only() {
    // A `[network]` table carrying an explicit `stats` value.
    let net = |stats: Option<bool>| RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: vec!["github.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats,
            default_methods: None,
            dns_cache_ttl: None,
        })),
        ..RawConfig::default()
    };

    // Default: nothing set → recording is on.
    assert!(resolve_no_plugins(RawConfig::default(), None).egress_stats);
    // A bare-string posture carries no `stats` key → stays on.
    assert!(resolve_no_plugins(raw_network("deny"), None).egress_stats);
    // Global `stats = false` (trusted by location) → off.
    assert!(!resolve_no_plugins(net(Some(false)), None).egress_stats);
    // A TRUSTED project may turn its own audit off.
    assert!(
        !resolve_no_plugins(
            RawConfig::default(),
            Some((net(Some(false)), TrustState::Trusted))
        )
        .egress_stats
    );
    // An UNTRUSTED project's `stats = false` is dropped with its whole `[network]` table — it
    // cannot disable the auditing of its own egress.
    assert!(
        resolve_no_plugins(
            RawConfig::default(),
            Some((net(Some(false)), TrustState::Untrusted))
        )
        .egress_stats
    );
    // Layering: a trusted project's `stats = true` overrides a global `false`.
    assert!(
        resolve_no_plugins(
            net(Some(false)),
            Some((net(Some(true)), TrustState::Trusted))
        )
        .egress_stats
    );
}

#[test]
fn an_apps_network_stats_toggle_is_warned_and_ignored() {
    // The egress-stats switch is baseline-only, so a `stats` key inside an `[app.<name>.network]`
    // table is parsed but has no effect — warned, never silently dropped (every shipped profile
    // declares its network as a table, so an author would otherwise believe it took).
    let app = raw_app(
        &["true"],
        &[],
        &[],
        &[],
        Some(NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: Some(false),
            default_methods: None,
            dns_cache_ttl: None,
        })),
    );
    let r = resolve_no_plugins(raw_with_app("demo", app), None);
    assert!(
        r.egress_stats,
        "an app's stats toggle must not change the baseline (it is baseline-only)"
    );
    // The warning lives on the app (surfaced when `sbx app demo` launches, via `merge_app`
    // folding it into the baseline warnings), not on the baseline read.
    let demo = r.apps.get("demo").expect("the app resolves");
    assert!(
        demo.warnings
            .iter()
            .any(|w| w.contains("stats") && w.contains("baseline-only")),
        "the ignored app stats toggle must be warned: {:?}",
        demo.warnings
    );
}

/// A terse `RawHostSecret` — `key` only, no explicit `from` — for the expansion tests.
fn terse(key: &str) -> RawHostSecret {
    RawHostSecret {
        name: None,
        description: None,
        kind: None,
        key: Some(key.into()),
        from: None,
        header: Some("Authorization".into()),
        value_type: Some("bearer".into()),
        prefix: None,
    }
}

/// A terse `RawHostSecret` that also omits `header` and `type`, so they must come from
/// `[secret.defaults]` — for the default-header/type tests.
fn terse_bare(key: &str) -> RawHostSecret {
    RawHostSecret {
        name: None,
        description: None,
        kind: None,
        key: Some(key.into()),
        from: None,
        header: None,
        value_type: None,
        prefix: None,
    }
}

/// A raw `[secret.defaults]` table from its parts, for the expansion and layering tests.
fn raw_defaults(
    order: &[&str],
    sops_file: Option<&str>,
    env_case: Option<&str>,
    file_dir: Option<&str>,
) -> RawSecretDefaults {
    RawSecretDefaults {
        order: order.iter().map(|s| s.to_string()).collect(),
        header: None,
        value_type: None,
        sops: sops_file.map(|f| RawSopsDefaults { file: f.into() }),
        env: env_case.map(|c| RawEnvDefaults {
            case: Some(c.into()),
        }),
        file: file_dir.map(|d| RawFileDefaults { dir: d.into() }),
    }
}

/// A trusted-shaped network allowlist for the given hosts.
fn allowlist_net(allow: &[&str]) -> Option<NetworkField> {
    Some(NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        capture: None,
        capture_max_kb: None,
        mode: Some("deny".into()),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        deny: vec![],
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
    }))
}

/// A `[secret]` section with the given defaults and one terse host entry.
fn terse_section(defaults: RawSecretDefaults, host: &str, key: &str) -> RawSecretSection {
    let mut hosts = BTreeMap::new();
    hosts.insert(host.to_string(), RawHostSecrets::One(terse(key)));
    RawSecretSection {
        defaults: Some(defaults),
        hosts,
    }
}

#[test]
fn a_from_chain_parses_into_ordered_sources() {
    let s = validate(raw_secret_from(vec![
        "env://GH_TOKEN",
        "file:///run/secrets/gh",
    ]))
    .unwrap();
    assert_eq!(
        s.sources,
        vec![
            SecretSource::Env("GH_TOKEN".into()),
            SecretSource::File("/run/secrets/gh".into()),
        ]
    );
    // the chain is shown by locator (never a value), precedence visible
    assert_eq!(
        s.describe_sources(),
        "env GH_TOKEN, then file /run/secrets/gh"
    );
}

#[test]
fn a_single_string_from_parses_to_one_source() {
    let mut raw = raw_secret_from(vec!["env://GH_TOKEN"]);
    raw.from = Some(SecretFrom::One("env://GH_TOKEN".into()));
    let s = validate(raw).unwrap();
    assert_eq!(s.sources, vec![SecretSource::Env("GH_TOKEN".into())]);
}

#[test]
fn an_empty_from_list_is_rejected() {
    let err = validate(raw_secret_from(vec![])).unwrap_err();
    assert!(err.contains("empty list"), "{err}");
}

#[test]
fn a_from_entry_without_a_scheme_is_rejected() {
    let err = validate(raw_secret_from(vec!["GH_TOKEN"])).unwrap_err();
    assert!(err.contains("needs a scheme"), "{err}");
}

#[test]
fn an_unknown_resolver_scheme_is_rejected() {
    let err = validate(raw_secret_from(vec!["vault://secret/x#f"])).unwrap_err();
    assert!(
        err.contains("unknown secret resolver scheme") && err.contains("vault"),
        "{err}"
    );
}

#[test]
fn a_secret_with_no_source_at_all_is_rejected() {
    let mut raw = raw_secret_from(vec!["env://X"]);
    raw.from = None;
    let err = validate(raw).unwrap_err();
    assert!(err.contains("needs a source"), "{err}");
}

#[test]
fn a_secret_to_host_rejects_a_method_prefix() {
    // a credential is host-scoped (injected on every verb), so a `{...}` method prefix on the
    // `to` host would inject wider than written — rejected fail-closed. A bare host still parses.
    assert!(validate_secret_target("api.example.com").is_ok());
    let err = validate_secret_target("{POST} api.example.com").unwrap_err();
    assert!(err.contains("no method prefix"), "{err}");
}

#[test]
fn a_secret_to_host_rejects_a_raw_or_cleartext_scheme() {
    // A header credential can only be injected on the inspected-over-TLS path — a `tcp://` (raw
    // L4) destination is spliced byte-for-byte (no head to inject into), and an `http://`
    // (cleartext L7) destination has a head but a bearer must never travel in the clear. Both are
    // rejected fail-closed rather than silently never injecting (or injecting over plaintext). The
    // bare/https form still parses; each rejection names the exact scheme to remove.
    assert!(validate_secret_target("https://api.example.com").is_ok());
    let tcp = validate_secret_target("tcp://api.example.com:443").unwrap_err();
    assert!(
        tcp.contains("inspected-over-TLS destination") && tcp.contains("tcp://"),
        "{tcp}"
    );
    let http = validate_secret_target("http://api.example.com").unwrap_err();
    assert!(
        http.contains("inspected-over-TLS destination") && http.contains("http://"),
        "{http}"
    );
}

#[test]
fn a_sops_ref_parses_to_a_file_and_key() {
    let s = validate(raw_secret_from(vec![
        "sops://secrets/prod.yaml#db.password",
    ]))
    .unwrap();
    assert_eq!(
        s.sources,
        vec![SecretSource::Sops {
            file: "secrets/prod.yaml".into(),
            key: Some("db.password".into()),
        }]
    );
    assert_eq!(s.describe_sources(), "sops secrets/prod.yaml#db.password");
}

#[test]
fn a_sops_ref_without_a_key_decrypts_the_whole_file() {
    let s = validate(raw_secret_from(vec!["sops:///abs/secrets.yaml"])).unwrap();
    assert_eq!(
        s.sources,
        vec![SecretSource::Sops {
            file: "/abs/secrets.yaml".into(),
            key: None,
        }]
    );
}

#[test]
fn a_sops_key_with_an_invalid_segment_is_rejected() {
    let err = validate(raw_secret_from(vec!["sops://f.yaml#db.pa$$word"])).unwrap_err();
    assert!(err.contains("invalid segment"), "{err}");
}

#[test]
fn a_sops_ref_with_a_trailing_hash_or_empty_segment_is_rejected() {
    let err = validate(raw_secret_from(vec!["sops://f.yaml#"])).unwrap_err();
    assert!(err.contains("empty key"), "{err}");
    let err = validate(raw_secret_from(vec!["sops://f.yaml#a..b"])).unwrap_err();
    assert!(err.contains("empty path segment"), "{err}");
}

// --- the terse `key` form + `[secret.defaults]` ------------------------------------------

#[test]
fn a_terse_key_expands_through_the_default_order() {
    // order [env, sops] with an env case + a sops file: the key becomes a fallback chain, env
    // first (upcased), then sops (joined onto the bound file). The chain reuses the existing
    // source types, so everything downstream is unchanged.
    let d = SecretDefaults::from_raw(&raw_defaults(
        &["env", "sops"],
        Some("prod.yaml"),
        Some("upper"),
        None,
    ));
    let s = vhs("api.github.com", terse("github_token"), &d).unwrap();
    assert_eq!(
        s.sources,
        vec![
            SecretSource::Env("GITHUB_TOKEN".into()),
            SecretSource::Sops {
                file: "prod.yaml".into(),
                key: Some("github_token".into()),
            },
        ]
    );
    assert_eq!(
        s.describe_sources(),
        "env GITHUB_TOKEN, then sops prod.yaml#github_token"
    );
}

#[test]
fn a_pinned_resolver_overrides_the_order() {
    // `key@sops` ignores the default order and uses sops only
    let d = SecretDefaults::from_raw(&raw_defaults(&["env"], Some("prod.yaml"), None, None));
    let s = vhs("api.github.com", terse("tok@sops"), &d).unwrap();
    assert_eq!(
        s.sources,
        vec![SecretSource::Sops {
            file: "prod.yaml".into(),
            key: Some("tok".into()),
        }]
    );
}

#[test]
fn a_pin_can_reorder_several_resolvers() {
    // `key@sops,env` is that order for this secret only, regardless of the default
    let d = SecretDefaults::from_raw(&raw_defaults(&["env"], Some("prod.yaml"), None, None));
    let s = vhs("api.github.com", terse("tok@sops,env"), &d).unwrap();
    assert_eq!(
        s.sources,
        vec![
            SecretSource::Sops {
                file: "prod.yaml".into(),
                key: Some("tok".into()),
            },
            SecretSource::Env("tok".into()),
        ]
    );
}

#[test]
fn a_terse_file_key_joins_the_base_dir() {
    let d = SecretDefaults::from_raw(&raw_defaults(&["file"], None, None, Some("/run/secrets")));
    let s = vhs("h.test", terse("npm"), &d).unwrap();
    assert_eq!(
        s.sources,
        vec![SecretSource::File("/run/secrets/npm".into())]
    );
}

#[test]
fn a_relative_file_dir_is_rejected_naming_the_binding() {
    // a relative `[secret.defaults.file] dir` fails closed with a message naming the binding,
    // not the joined path
    let d = SecretDefaults::from_raw(&raw_defaults(&["file"], None, None, Some("rel/secrets")));
    let err = vhs("h.test", terse("npm"), &d).unwrap_err();
    assert!(
        err.contains("[secret.defaults.file] dir") && err.contains("absolute"),
        "{err}"
    );
}

#[test]
fn a_terse_key_using_an_unbound_resolver_is_rejected() {
    // sops is in the order but no `[secret.defaults.sops] file` is set — fail closed
    let d = SecretDefaults::from_raw(&raw_defaults(&["sops"], None, None, None));
    let err = vhs("h.test", terse("tok"), &d).unwrap_err();
    assert!(err.contains("sops") && err.contains("unset"), "{err}");
}

#[test]
fn a_terse_key_with_no_order_and_no_pin_is_rejected() {
    // no default order and no `@resolver` — there is nothing to resolve through
    let err = vhs("h.test", terse("tok"), &SecretDefaults::default()).unwrap_err();
    assert!(err.contains("no resolver for key"), "{err}");
}

#[test]
fn a_terse_key_with_a_path_separator_is_rejected() {
    // a terse key may not carry a `/` — it would traverse out of a file/sops base
    let d = SecretDefaults::from_raw(&raw_defaults(&["file"], None, None, Some("/run/secrets")));
    let err = vhs("h.test", terse("../../etc/shadow"), &d).unwrap_err();
    assert!(err.contains("segment"), "{err}");
}

#[test]
fn an_unknown_env_case_is_rejected() {
    let d = SecretDefaults::from_raw(&raw_defaults(&["env"], None, Some("title"), None));
    let err = vhs("h.test", terse("tok"), &d).unwrap_err();
    assert!(err.contains("unknown env `case`"), "{err}");
}

#[test]
fn key_and_from_together_is_rejected() {
    let mut s = terse("tok");
    s.from = Some(SecretFrom::One("env://TOK".into()));
    let err = validate(s).unwrap_err();
    assert!(err.contains("not both"), "{err}");
}

/// A test resolver plugin claiming `scheme`. The exec path and sandbox grant are
/// placeholders — the config layer only records them, it never runs the plugin.
fn plugin(scheme: &str) -> crate::plugins::ResolverPlugin {
    crate::plugins::ResolverPlugin {
        name: scheme.to_string(),
        scheme: scheme.to_string(),
        dir: PathBuf::from(format!("/data/plugins/{scheme}")),
        exec: PathBuf::from(format!("/data/plugins/{scheme}/resolve")),
        sandbox: crate::plugins::SandboxGrant::default(),
        version: None,
        description: None,
    }
}

/// [`validate_host_secret`] against a given registry, for the plugin-scheme tests.
fn vhs_with(secret: RawHostSecret, plugins: &PluginRegistry) -> Result<HeaderSecret, String> {
    validate_host_secret(
        "api.github.com",
        secret,
        &SecretDefaults::default(),
        plugins,
    )
}

#[test]
fn a_from_ref_resolves_through_a_registered_plugin() {
    let reg = PluginRegistry::with([plugin("pass")]);
    let s = vhs_with(raw_secret_from(vec!["pass://github/token"]), &reg).unwrap();
    match &s.sources[..] {
        [SecretSource::Plugin { plugin, locator }] => {
            assert_eq!(plugin.scheme, "pass");
            assert_eq!(locator, "github/token");
        }
        other => panic!("expected one plugin source, got {other:?}"),
    }
}

#[test]
fn a_plugin_describes_without_the_value() {
    let reg = PluginRegistry::with([plugin("pass")]);
    let s = vhs_with(raw_secret_from(vec!["pass://github/token"]), &reg).unwrap();
    assert_eq!(s.describe_sources(), "pass github/token");
}

#[test]
fn an_unregistered_plugin_scheme_is_rejected() {
    // no plugin claims `vault` → the scheme stays unknown and fails closed
    let err = vhs_with(
        raw_secret_from(vec!["vault://secret/x"]),
        &PluginRegistry::default(),
    )
    .unwrap_err();
    assert!(err.contains("vault://"), "{err}");
    assert!(err.contains("plugin"), "{err}");
}

#[test]
fn a_plugin_can_follow_a_builtin_in_a_fallback_chain() {
    let reg = PluginRegistry::with([plugin("pass")]);
    let s = vhs_with(
        raw_secret_from(vec!["env://TOK", "pass://github/token"]),
        &reg,
    )
    .unwrap();
    assert!(matches!(s.sources[0], SecretSource::Env(_)));
    assert!(matches!(s.sources[1], SecretSource::Plugin { .. }));
}

#[test]
fn a_plugin_locator_with_a_control_character_is_rejected() {
    let reg = PluginRegistry::with([plugin("pass")]);
    let err = vhs_with(raw_secret_from(vec!["pass://bad\nref"]), &reg).unwrap_err();
    assert!(err.contains("control character"), "{err}");
}

#[test]
fn an_empty_plugin_locator_is_rejected() {
    let reg = PluginRegistry::with([plugin("pass")]);
    let err = vhs_with(raw_secret_from(vec!["pass://"]), &reg).unwrap_err();
    assert!(err.contains("empty locator"), "{err}");
}

#[test]
fn a_terse_key_never_resolves_a_plugin_scheme() {
    // a terse `key` pinned to a plugin name is not a plugin binding — it is an unknown
    // resolver binding (terse plugin bindings are deliberately out of scope)
    let reg = PluginRegistry::with([plugin("pass")]);
    let err = validate_host_secret(
        "api.github.com",
        terse("tok@pass"),
        &SecretDefaults::default(),
        &reg,
    )
    .unwrap_err();
    assert!(err.contains("pass"), "{err}");
}

#[test]
fn a_trusted_project_terse_secret_expands_through_global_defaults() {
    // the resolver defaults are global; a trusted project's terse `key` resolves through them
    let global = RawConfig {
        network: allowlist_net(&["api.github.com"]),
        secret: Some(RawSecretSection {
            defaults: Some(raw_defaults(
                &["sops"],
                Some("secrets/prod.yaml"),
                None,
                None,
            )),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    let proj = RawConfig {
        secret: Some(terse_section(
            RawSecretDefaults::default(),
            "api.github.com",
            "gh_token",
        )),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
    assert_eq!(r.secrets.len(), 1);
    assert_eq!(
        r.secrets[0].sources,
        vec![SecretSource::Sops {
            file: "secrets/prod.yaml".into(),
            key: Some("gh_token".into()),
        }]
    );
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_trusted_project_overrides_a_global_default_binding() {
    // global points sops at prod; the project, with an empty order (inherited), overrides the
    // sops file to staging — the project's binding wins, the order is inherited
    let global = RawConfig {
        network: allowlist_net(&["api.github.com"]),
        secret: Some(RawSecretSection {
            defaults: Some(raw_defaults(&["sops"], Some("prod.yaml"), None, None)),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    let proj = RawConfig {
        secret: Some(terse_section(
            raw_defaults(&[], Some("staging.yaml"), None, None),
            "api.github.com",
            "tok",
        )),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
    assert_eq!(
        r.secrets[0].sources,
        vec![SecretSource::Sops {
            file: "staging.yaml".into(),
            key: Some("tok".into()),
        }]
    );
}

#[test]
fn a_project_secret_default_reaches_a_project_app_but_not_a_global_app() {
    // A trusted project's `[secret.defaults]` steers its OWN apps' secret resolution, while a
    // globally-declared app keeps the global defaults — so a project cannot redirect how a
    // global app's credentials resolve, but its own apps honor its resolver order/bindings.
    let app_with_secret = |host: &str, key: &str| RawApp {
        cmd: Some(schema::RawCmd::Line("run".into())),
        network: allowlist_net(&[host]),
        secret: Some(terse_section(RawSecretDefaults::default(), host, key)),
        ..RawApp::default()
    };
    let mut global = RawConfig {
        secret: Some(RawSecretSection {
            defaults: Some(raw_defaults(&["sops"], Some("prod.yaml"), None, None)),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    global.app.insert(
        "globalapp".into(),
        app_with_secret("api.example.com", "gtok"),
    );
    let mut proj = RawConfig {
        // the project overrides the sops binding to staging; the order is inherited from global
        secret: Some(RawSecretSection {
            defaults: Some(raw_defaults(&[], Some("staging.yaml"), None, None)),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    proj.app
        .insert("projapp".into(), app_with_secret("api.example.com", "ptok"));
    let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
    // the project app resolved through the PROJECT's sops binding (staging)
    assert_eq!(
        r.apps["projapp"].secrets[0].sources,
        vec![SecretSource::Sops {
            file: "staging.yaml".into(),
            key: Some("ptok".into()),
        }],
        "a project app must honor the project's `[secret.defaults]`"
    );
    // the global app kept the GLOBAL sops binding (prod), untouched by the project's default
    assert_eq!(
        r.apps["globalapp"].secrets[0].sources,
        vec![SecretSource::Sops {
            file: "prod.yaml".into(),
            key: Some("gtok".into()),
        }],
        "a global app must NOT inherit the project's `[secret.defaults]`"
    );
}

#[test]
fn an_untrusted_project_secret_section_steers_nothing() {
    // neither an explicit `sops://` source nor the terse `key` + `[secret.defaults]` is honored
    // from an untrusted project: the whole section — defaults included — is dropped, so it can
    // neither inject a credential nor redirect a secret's source.
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "api.github.com".to_string(),
            RawHostSecrets::One(RawHostSecret {
                name: None,
                description: None,
                kind: None,
                key: None,
                from: Some(SecretFrom::One("sops://prod.yaml#tok".into())),
                header: Some("Authorization".into()),
                value_type: Some("bearer".into()),
                prefix: None,
            }),
        );
        hosts.insert(
            "api2.example.com".to_string(),
            RawHostSecrets::One(terse("demo_key")),
        );
        let proj = RawConfig {
            secret: Some(RawSecretSection {
                defaults: Some(raw_defaults(
                    &["env", "sops"],
                    Some("prod.yaml"),
                    None,
                    None,
                )),
                hosts,
            }),
            ..RawConfig::default()
        };
        let global = RawConfig {
            network: allowlist_net(&["api.github.com", "api2.example.com"]),
            ..RawConfig::default()
        };
        let r = resolve_no_plugins(global, Some((proj, state)));
        assert!(
            r.secrets.is_empty(),
            "an untrusted project may not inject or redirect"
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("ignoring 2 secret(s)")),
            "{:?}",
            r.warnings
        );
    }
}

#[test]
fn two_headers_to_one_host_both_survive() {
    // the array form (`[[secret."host"]]`) keeps several credentials for one host: a different
    // header is not a duplicate, so both are kept
    let r = resolve_no_plugins(
        raw_secrets(
            &["api.github.com"],
            vec![
                raw_secret(
                    Some("A"),
                    None,
                    "api.github.com",
                    "Authorization",
                    Some("bearer"),
                    None,
                ),
                raw_secret(
                    Some("B"),
                    None,
                    "api.github.com",
                    "X-Api-Key",
                    Some("raw"),
                    None,
                ),
            ],
        ),
        None,
    );
    assert_eq!(
        r.secrets.len(),
        2,
        "different headers to one host both survive"
    );
}

// --- default `header` / `type` in `[secret.defaults]` -------------------------------------

/// `[secret.defaults]` with a default header + type, plus the given resolver order/sops file.
fn defaults_with_shape(order: &[&str], sops_file: Option<&str>) -> RawSecretDefaults {
    let mut d = raw_defaults(order, sops_file, None, None);
    d.header = Some("Authorization".into());
    d.value_type = Some("bearer".into());
    d
}

#[test]
fn a_terse_entry_inherits_the_default_header_and_type() {
    let d = SecretDefaults::from_raw(&defaults_with_shape(&["sops"], Some("prod.yaml")));
    let s = vhs("api.github.com", terse_bare("gh_token"), &d).unwrap();
    assert_eq!(s.header, "Authorization");
    assert_eq!(s.shape.format("abc"), "Bearer abc");
    assert_eq!(
        s.sources,
        vec![SecretSource::Sops {
            file: "prod.yaml".into(),
            key: Some("gh_token".into()),
        }]
    );
}

#[test]
fn a_per_secret_header_and_type_override_the_defaults() {
    let d = SecretDefaults::from_raw(&defaults_with_shape(&["sops"], Some("prod.yaml")));
    let mut secret = terse_bare("k");
    secret.header = Some("X-Api-Key".into());
    secret.value_type = Some("raw".into());
    let s = vhs("h.test", secret, &d).unwrap();
    assert_eq!(
        s.header, "X-Api-Key",
        "the entry's header wins over the default"
    );
    assert_eq!(s.shape.format("abc"), "abc", "the entry's raw type wins");
}

#[test]
fn neither_a_secret_nor_a_default_header_is_an_error() {
    // no `header` on the entry and none in the defaults — the same explicit error as before,
    // never a silent built-in default
    let d = SecretDefaults::from_raw(&raw_defaults(&["sops"], Some("p.yaml"), None, None));
    let err = vhs("h.test", terse_bare("k"), &d).unwrap_err();
    assert!(err.contains("set `header`"), "{err}");
}

#[test]
fn neither_a_secret_nor_a_default_type_is_an_error() {
    // header is supplied by the defaults but type is set nowhere — still an explicit error
    let mut raw = raw_defaults(&["sops"], Some("p.yaml"), None, None);
    raw.header = Some("Authorization".into());
    let d = SecretDefaults::from_raw(&raw);
    let err = vhs("h.test", terse_bare("k"), &d).unwrap_err();
    assert!(err.contains("missing `type`"), "{err}");
}

#[test]
fn a_default_header_collapses_array_entries_that_omit_it() {
    // the sharp edge: two `[[secret."host"]]` entries that both inherit the default header
    // collapse on `(host, header)` to the last one (with a warning) — fail-closed, never two
    // silent header copies upstream
    let mut hosts = BTreeMap::new();
    hosts.insert(
        "api.github.com".to_string(),
        RawHostSecrets::Many(vec![terse_bare("a"), terse_bare("b")]),
    );
    let global = RawConfig {
        network: allowlist_net(&["api.github.com"]),
        secret: Some(RawSecretSection {
            defaults: Some(defaults_with_shape(&["sops"], Some("prod.yaml"))),
            hosts,
        }),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, None);
    assert_eq!(
        r.secrets.len(),
        1,
        "entries that both inherit the default header collapse to one"
    );
    assert!(r.warnings.iter().any(|w| w.contains("overrides")));
    assert_eq!(
        r.secrets[0].sources,
        vec![SecretSource::Sops {
            file: "prod.yaml".into(),
            key: Some("b".into()),
        }],
        "last wins"
    );
}

#[test]
fn a_global_default_header_and_type_reach_a_project_through_merge() {
    // global sets the default header/type; a trusted project that declares its OWN
    // `[secret.defaults]` (so `merged_with` runs) but omits header/type inherits them, while a
    // per-entry header still wins after the merge — pins both merged_with header/type lines.
    let global = RawConfig {
        network: allowlist_net(&["a.test", "b.test"]),
        secret: Some(RawSecretSection {
            defaults: Some(defaults_with_shape(&["sops"], Some("prod.yaml"))),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    let mut hosts = BTreeMap::new();
    // inherits the global default header *and* type through the merge
    hosts.insert("a.test".to_string(), RawHostSecrets::One(terse_bare("ka")));
    // overrides the header per-entry, after the merge
    let mut overriding = terse_bare("kb");
    overriding.header = Some("X-Api-Key".into());
    hosts.insert("b.test".to_string(), RawHostSecrets::One(overriding));
    let proj = RawConfig {
        // the project's own defaults set only the order, so header/type come from the global
        secret: Some(RawSecretSection {
            defaults: Some(raw_defaults(&["sops"], Some("prod.yaml"), None, None)),
            hosts,
        }),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(global, Some((proj, TrustState::Trusted)));
    assert_eq!(r.secrets.len(), 2);
    let a = r
        .secrets
        .iter()
        .find(|s| s.header == "Authorization")
        .expect("a.test inherits the global default header through the merge");
    assert_eq!(
        a.shape.format("x"),
        "Bearer x",
        "and the global default type"
    );
    assert!(
        r.secrets.iter().any(|s| s.header == "X-Api-Key"),
        "a per-entry header still wins after the merge"
    );
}

#[test]
fn a_trusted_project_header_secret_is_honored() {
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_secrets(
                &["api.github.com"],
                vec![raw_secret(
                    Some("GH_TOKEN"),
                    None,
                    "api.github.com",
                    "Authorization",
                    Some("bearer"),
                    None,
                )],
            ),
            TrustState::Trusted,
        )),
    );
    assert_eq!(r.secrets.len(), 1);
    let s = &r.secrets[0];
    assert_eq!(s.sources, vec![SecretSource::Env("GH_TOKEN".into())]);
    assert_eq!(s.header, "Authorization");
    assert_eq!(s.to, crate::allowlist::classify("api.github.com").unwrap());
    assert_eq!(s.shape.format("abc"), "Bearer abc");
    assert!(r.warnings.is_empty());
}

#[test]
fn a_global_secret_is_honored_by_location() {
    let r = resolve_no_plugins(
        raw_secrets(
            &["api.github.com"],
            vec![raw_secret(
                Some("GH_TOKEN"),
                None,
                "api.github.com",
                "Authorization",
                Some("bearer"),
                None,
            )],
        ),
        None,
    );
    assert_eq!(r.secrets.len(), 1);
    assert!(r.warnings.is_empty());
}

#[test]
fn an_untrusted_project_secret_is_dropped_with_a_warning() {
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((
                raw_secrets(
                    &["api.github.com"],
                    vec![raw_secret(
                        Some("GH"),
                        None,
                        "api.github.com",
                        "Authorization",
                        Some("bearer"),
                        None,
                    )],
                ),
                state,
            )),
        );
        assert!(
            r.secrets.is_empty(),
            "an untrusted project may not inject credentials"
        );
        assert!(r.warnings.iter().any(|w| w.contains("secret")));
    }
}

#[test]
fn a_secret_without_an_allowlist_is_dropped_with_a_warning() {
    // a secret declared while the network stays shared (no filtering proxy) has
    // nowhere to inject; it is cleared with a warning, never a silent no-op.
    let r = resolve_no_plugins(
        RawConfig {
            secret: Some(raw_secret_section(vec![raw_secret(
                Some("GH"),
                None,
                "api.github.com",
                "Authorization",
                Some("bearer"),
                None,
            )])),
            ..RawConfig::default()
        },
        None,
    );
    assert!(r.secrets.is_empty());
    assert_eq!(r.network, NetworkPolicy::Shared);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("requires") && w.contains("filtering")));
}

#[test]
fn a_wildcard_or_regex_secret_target_is_rejected() {
    for to in ["*.github.com", "re:^https://api\\.github\\.com/"] {
        let r = resolve_no_plugins(
            raw_secrets(
                &["api.github.com"],
                vec![raw_secret(
                    Some("GH"),
                    None,
                    to,
                    "Authorization",
                    Some("bearer"),
                    None,
                )],
            ),
            None,
        );
        assert!(r.secrets.is_empty(), "{to} must be rejected as a target");
        assert!(r.warnings.iter().any(|w| w.contains("concrete host")));
    }
}

#[test]
fn a_missing_or_unknown_secret_type_is_rejected() {
    let missing = resolve_no_plugins(
        raw_secrets(
            &["api.github.com"],
            vec![raw_secret(
                Some("GH"),
                None,
                "api.github.com",
                "Authorization",
                None,
                None,
            )],
        ),
        None,
    );
    assert!(missing.secrets.is_empty());
    assert!(missing
        .warnings
        .iter()
        .any(|w| w.contains("missing `type`")));

    let unknown = resolve_no_plugins(
        raw_secrets(
            &["api.github.com"],
            vec![raw_secret(
                Some("GH"),
                None,
                "api.github.com",
                "Authorization",
                Some("digest"),
                None,
            )],
        ),
        None,
    );
    assert!(unknown.secrets.is_empty());
    assert!(unknown
        .warnings
        .iter()
        .any(|w| w.contains("unknown `type`")));
}

#[test]
fn a_secret_with_no_source_is_dropped_with_a_warning() {
    let r = resolve_no_plugins(
        raw_secrets(
            &["h.test"],
            vec![raw_secret(None, None, "h.test", "H", Some("raw"), None)],
        ),
        None,
    );
    assert!(r.secrets.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("needs a source")));
}

#[test]
fn a_duplicate_target_header_secret_is_last_wins_with_a_warning() {
    let r = resolve_no_plugins(
        raw_secrets(
            &["h.test"],
            vec![
                raw_secret(
                    Some("FIRST"),
                    None,
                    "h.test",
                    "Authorization",
                    Some("raw"),
                    None,
                ),
                // same host, same header (different case) — collapses to the later one
                raw_secret(
                    Some("SECOND"),
                    None,
                    "h.test",
                    "authorization",
                    Some("raw"),
                    None,
                ),
            ],
        ),
        None,
    );
    assert_eq!(
        r.secrets.len(),
        1,
        "a duplicate (host, header) collapses to one"
    );
    assert_eq!(
        r.secrets[0].sources,
        vec![SecretSource::Env("SECOND".into())],
        "last wins"
    );
    assert!(r.warnings.iter().any(|w| w.contains("overrides")));
}

#[test]
fn a_non_absolute_from_file_is_rejected() {
    let r = resolve_no_plugins(
        raw_secrets(
            &["h.test"],
            vec![raw_secret(
                None,
                Some("relative/tok"),
                "h.test",
                "H",
                Some("raw"),
                None,
            )],
        ),
        None,
    );
    assert!(r.secrets.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("absolute path")));
}

#[test]
fn an_unknown_secret_kind_and_a_bad_header_name_are_rejected() {
    let mut bad_kind = raw_secret(Some("X"), None, "h.test", "H", Some("raw"), None);
    bad_kind.1.kind = Some("ssh-agent".into());
    let r = resolve_no_plugins(raw_secrets(&["h.test"], vec![bad_kind]), None);
    assert!(r.secrets.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("unknown kind")));

    let r = resolve_no_plugins(
        raw_secrets(
            &["h.test"],
            vec![raw_secret(
                Some("X"),
                None,
                "h.test",
                "Bad: Header",
                Some("raw"),
                None,
            )],
        ),
        None,
    );
    assert!(r.secrets.is_empty());
    assert!(r.warnings.iter().any(|w| w.contains("`header`")));
}

#[test]
fn header_shape_formats_each_type_and_prefix() {
    let shape = |ty, prefix| validate_header_shape(Some(ty), prefix).unwrap();
    assert_eq!(shape("bearer", None).format("tok"), "Bearer tok");
    assert_eq!(shape("raw", None).format("tok"), "tok");
    assert_eq!(shape("raw", Some("token ")).format("tok"), "token tok");
    assert_eq!(
        shape("bearer", Some("token ")).format("tok"),
        "token tok",
        "an explicit prefix overrides the type default"
    );
    // basic base64s a user:pass pair under the "Basic " prefix
    assert_eq!(
        shape("basic", None).format("user:pass"),
        "Basic dXNlcjpwYXNz"
    );
}

#[test]
fn an_inline_global_app_is_dropped_in_favour_of_the_profile() {
    // A global app lives only as a profile file; an inline `[app.<name>]` in `sbx.toml` is
    // forbidden and dropped inert with a migration warning, so it can never shadow an imported
    // profile of the same name. The profile takes the name; a non-colliding profile is added.
    let mut global = raw_with_app("demo-app", raw_app(&["inline"], &[], &[], &[], None));
    let profiles: BTreeMap<String, RawApp> = [
        (
            "demo-app".to_string(),
            raw_app(&["profile"], &[], &[], &[], None),
        ),
        (
            "review".to_string(),
            raw_app(&["review"], &[], &[], &[], None),
        ),
    ]
    .into_iter()
    .collect();
    let mut warnings = Vec::new();
    merge_profile_apps(&mut global, profiles, &mut warnings);
    // The inline definition is gone; the profile of the same name replaces it.
    assert_eq!(
        global.app["demo-app"]
            .cmd
            .as_ref()
            .map(|c| c.clone().into_argv()),
        Some(vec!["profile".to_string()])
    );
    assert!(global.app.contains_key("review"));
    // Exactly the colliding inline app warns, with the "a profile already provides it" remedy —
    // delete the stub, not re-export it (the profile already exists). The non-colliding profile
    // `review` is added silently.
    assert_eq!(warnings.len(), 1, "only the inline app warns: {warnings:?}");
    let w = &warnings[0];
    assert!(
        w.contains("demo-app") && w.contains("ignored") && w.contains("already provides it"),
        "the colliding inline must be told to delete the stub: {w}"
    );
    assert!(
        !w.contains("sbx app export"),
        "when a profile already exists, do not suggest export: {w}"
    );
}

#[test]
fn every_shipped_bundle_matches_the_agent_profile_it_was_derived_from() {
    // The shipped bundles under `examples/bundle/` restate what the agent profile of the same name
    // under `examples/app/` declares, so an orchestrator can name the agent instead of copying it.
    // Two artifacts describing one tool is the drift risk this whole feature exists to remove — so
    // it is pinned here, and it is pinnable *because* both are authored in this repo for the same
    // agent. (The general form — inferring the same obligation between two unrelated profiles — is
    // NOT sound: a front-end legitimately exposes a smaller surface than the agent it embeds. Here
    // the obligation is declared by construction, which is the whole difference.)
    //
    // Containment, not equality: a bundle may carry LESS than its profile (the profile also holds a
    // `cmd`, postures, and any stack that only works under a `gui` posture a bundle cannot set). It
    // must never carry something the profile does not, which is what would make it a second, drifting
    // source of truth.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("examples/bundle");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/bundle/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();

        // Parsed with sbx's own parser, so a fragment this test accepts is one `sbx bundle import`
        // accepts — and a field written in the wrong TOML place (an `allow` under `[…packages]`,
        // which parses as an unknown key and vanishes) fails the containment below rather than
        // passing unnoticed.
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let bundle = raw.bundle.get(&name).unwrap_or_else(|| {
            panic!("{name}.toml must declare `[bundle.{name}]` (keyed by its file stem)")
        });

        let profile_path = root.join(format!("examples/app/{name}.toml"));
        let profile = schema::parse_app(
            &std::fs::read(&profile_path)
                .unwrap_or_else(|e| panic!("bundle `{name}` has no namesake agent profile: {e}")),
        )
        .unwrap();

        for (tool, locator) in &bundle.packages {
            assert_eq!(
                profile.packages.get(tool),
                Some(locator),
                "bundle `{name}` provisions {tool} = {locator}, which `examples/app/{name}.toml` \
                 does not declare identically — one of the two moved"
            );
        }
        for (key, value) in &bundle.env {
            assert_eq!(
                profile.env.get(key),
                Some(value),
                "bundle `{name}` sets {key}, which its profile does not set identically"
            );
        }

        // The egress lists live in the profile's `[network]` table. A bundle carrying rules whose
        // profile declares no table would mean the rules were invented here, not derived.
        let (allow, deny, mute) = match &profile.network {
            Some(schema::NetworkField::Table(t)) => (&t.allow, &t.deny, &t.mute),
            other => {
                assert!(
                    bundle.allow.is_empty() && bundle.deny.is_empty() && bundle.mute.is_empty(),
                    "bundle `{name}` carries egress rules but its profile declares no `[network]` \
                     table (it is {other:?}) — they came from nowhere"
                );
                checked += 1;
                continue;
            }
        };
        for (label, from, into) in [
            ("allow", &bundle.allow, allow),
            ("deny", &bundle.deny, deny),
            ("mute", &bundle.mute, mute),
        ] {
            for rule in from {
                assert!(
                    into.contains(rule),
                    "bundle `{name}` has the {label} rule {rule:?}, absent from \
                     `examples/app/{name}.toml` — the two have drifted apart"
                );
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 16,
        "expected the shipped agent bundles to be checked, saw {checked}"
    );
}

#[test]
fn an_unknown_key_is_named_rather_than_passed_over_in_silence() {
    // Unknown keys stay ignored — that is the forward-compatibility contract — but a misspelling
    // and a field from a newer sbx are indistinguishable in silence, and only one is harmless.
    let mut raw = RawConfig::default();
    raw.rest.insert("netowrk".into(), schema::RawIgnored);
    raw.limits = Some(schema::RawLimits {
        memory_max: Some(schema::RawLimit::Text("8G".into())),
        rest: [("memory_maxx".to_string(), schema::RawIgnored)]
            .into_iter()
            .collect(),
        ..Default::default()
    });
    let r = resolve_no_plugins(raw, None);

    assert!(
        r.warnings.iter().any(|w| w.contains("`netowrk`")),
        "a misspelled top-level field must be named: {:?}",
        r.warnings
    );
    let limit_warning = r
        .warnings
        .iter()
        .find(|w| w.contains("`memory_maxx`"))
        .unwrap_or_else(|| panic!("{:?}", r.warnings));
    assert!(
        limit_warning.contains("[limits]"),
        "and placed in its table: {limit_warning}"
    );
    // The layer still loads: the sibling that *was* understood is in effect.
    assert_eq!(r.limits.memory_max.as_deref(), Some("8G"));
}

#[test]
fn an_untrusted_projects_unknown_key_is_reported_too() {
    // A spelling question is not a capability, so withholding the answer from an untrusted project
    // would only leave its author guessing.
    let mut proj = RawConfig::default();
    proj.rest.insert("bindz".into(), schema::RawIgnored);
    let r = resolve_no_plugins(RawConfig::default(), Some((proj, TrustState::Untrusted)));
    assert!(
        r.warnings.iter().any(|w| w.contains("`bindz`")),
        "{:?}",
        r.warnings
    );
}

/// EVERY producer of a dropped-for-want-of-trust warning must be recognised as one.
///
/// There is more than one, and they are worded differently: the `ignoring \`<field>\` (…)` family
/// built from `untrusted_reason`, and `binds`, which has its own sentence. A reworded producer that
/// stopped matching would silently stop the launch announcing dropped fields — a failure of silence,
/// which is exactly what nothing else would catch.
#[test]
fn every_dropped_security_field_warning_is_recognised_as_a_trust_drop() {
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let from_reason = format!(
            "{PROJECT_CONFIG}: ignoring `network` policy ({})",
            super::untrusted_reason(state)
        );
        assert!(
            super::is_trust_drop(&from_reason),
            "{state:?} must be recognised: {from_reason}"
        );
        // `binds` does not use `untrusted_reason` — it has its own wording, and it is the field
        // whose silent absence is hardest to diagnose from inside the cage.
        let from_binds = super::dropped_binds_warning(state, 2);
        assert!(
            super::is_trust_drop(&from_binds),
            "{state:?} binds must be recognised: {from_binds}"
        );
    }
    // An ordinary warning is not one.
    assert!(!super::is_trust_drop(
        "sbx.toml: ignoring unknown notify event `egress`"
    ));
}

/// A real resolution of an untrusted project: every warning about a dropped security field is
/// recognised, so the launch announces all of them and not merely the ones phrased one way.
#[test]
fn an_untrusted_projects_dropped_fields_are_all_recognised() {
    let project: RawConfig = toml::from_str(
        "binds = [\"/etc\"]\nnetwork = \"shared\"\nnotify = \"off\"\ngui = \"wayland\"",
    )
    .unwrap();
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    let announced: Vec<&String> = r
        .warnings
        .iter()
        .filter(|w| super::is_trust_drop(w))
        .collect();
    for field in ["bind", "network", "notify", "gui"] {
        assert!(
            announced.iter().any(|w| w.contains(field)),
            "the dropped `{field}` must be announced; got {announced:?}"
        );
    }
}

// --- `[notify]` — the refusal-notification policy ---

/// The three TOML spellings all resolve, and the short one sets every event.
#[test]
fn notify_parses_the_bare_mode_the_list_and_the_per_event_table() {
    use crate::notify::{NotifyEvent, NotifyMode};

    // `notify = "always"` — one mode for everything.
    let bare: RawConfig = toml::from_str("notify = \"always\"").unwrap();
    let r = resolve_no_plugins(bare, None);
    for e in NotifyEvent::ALL {
        assert_eq!(r.notify.mode_for(e), NotifyMode::Always, "{e:?}");
    }

    // A list is an inclusion: the named events keep the table's mode, the rest go quiet.
    let list: RawConfig =
        toml::from_str("[notify]\nmode = \"always\"\nevents = [\"network\", \"proc\"]").unwrap();
    let r = resolve_no_plugins(list, None);
    assert_eq!(r.notify.mode_for(NotifyEvent::Network), NotifyMode::Always);
    assert_eq!(r.notify.mode_for(NotifyEvent::Proc), NotifyMode::Always);
    assert_eq!(
        r.notify.mode_for(NotifyEvent::Task),
        NotifyMode::Off,
        "an event left out of the list is silenced"
    );

    // A table sets a mode per event over the table's own mode.
    let table: RawConfig =
        toml::from_str("[notify]\nmode = \"off\"\n[notify.events]\nnetwork = \"always\"").unwrap();
    let r = resolve_no_plugins(table, None);
    assert_eq!(r.notify.mode_for(NotifyEvent::Network), NotifyMode::Always);
    assert_eq!(r.notify.mode_for(NotifyEvent::Trust), NotifyMode::Off);
}

/// With nothing declared, every occurrence is announced.
#[test]
fn notify_defaults_to_always_for_every_event() {
    use crate::notify::{NotifyEvent, NotifyMode};
    let r = resolve_no_plugins(RawConfig::default(), None);
    for e in NotifyEvent::ALL {
        assert_eq!(r.notify.mode_for(e), NotifyMode::Always, "{e:?}");
    }
    assert_eq!(r.notify_origin, Provenance::Default);
}

/// A project `[notify]` table with no `mode` refines one event and inherits the rest per event from
/// the global layer — it must not reset the others to a default.
#[test]
fn a_project_notify_table_without_a_mode_inherits_per_event() {
    use crate::notify::{NotifyEvent, NotifyMode};
    let global: RawConfig = toml::from_str("notify = \"always\"").unwrap();
    let project: RawConfig = toml::from_str("[notify]\n[notify.events]\ntask = \"off\"").unwrap();
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert_eq!(r.notify.mode_for(NotifyEvent::Task), NotifyMode::Off);
    assert_eq!(
        r.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Always,
        "an event the project did not name keeps the global mode"
    );
}

/// An untrusted project may not quieten its own refusals — the whole point of the field being
/// security-gated: silencing the notification is the cheapest way to make a boundary look like it
/// never bit.
#[test]
fn an_untrusted_project_cannot_silence_its_own_refusals() {
    use crate::notify::{NotifyEvent, NotifyMode};
    let project: RawConfig = toml::from_str("notify = \"off\"").unwrap();
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Untrusted)));
    assert_eq!(
        r.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Always,
        "the default stands; the untrusted project's `off` is dropped"
    );
    assert!(r.warnings.iter().any(|w| w.contains("ignoring `notify`")));

    // The same file, trusted, applies.
    let project: RawConfig = toml::from_str("notify = \"off\"").unwrap();
    let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
    assert_eq!(r.notify.mode_for(NotifyEvent::Network), NotifyMode::Off);
}

/// A misspelled event or mode is named, never passed over — a typo that silently meant "never tell
/// me" would be precisely the failure this field exists to prevent.
#[test]
fn an_unknown_notify_event_or_mode_is_named() {
    use crate::notify::{NotifyEvent, NotifyMode};

    let bad_event: RawConfig =
        toml::from_str("[notify]\nmode = \"once\"\n[notify.events]\negress = \"always\"").unwrap();
    let r = resolve_no_plugins(bad_event, None);
    let named = r
        .warnings
        .iter()
        .any(|w| w.contains("unknown notify event `egress`") && w.contains("network"));
    assert!(
        named,
        "the key and the vocabulary must both be named: {:?}",
        r.warnings
    );

    // An unknown *mode* keeps the layer below rather than guessing a quieter one.
    let bad_mode: RawConfig = toml::from_str("notify = \"one\"").unwrap();
    let r = resolve_no_plugins(bad_mode, None);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("unknown notify mode `one`")));
    assert_eq!(
        r.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Always,
        "an unrecognised mode must never silently disable notifications"
    );
}

/// `repeat_after` resolves, inherits, and is refused politely when it cannot mean anything.
#[test]
fn notify_repeat_after_resolves_and_is_flagged_where_it_cannot_bite() {
    use std::time::Duration;

    let cfg: RawConfig =
        toml::from_str("[notify]\nmode = \"always\"\nrepeat_after = \"5m\"").unwrap();
    let r = resolve_no_plugins(cfg, None);
    assert_eq!(r.notify.repeat_after(), Some(Duration::from_secs(300)));

    // A project that only refines events inherits the global period rather than losing it.
    let global: RawConfig =
        toml::from_str("[notify]\nmode = \"always\"\nrepeat_after = \"5m\"").unwrap();
    let project: RawConfig = toml::from_str("[notify]\n[notify.events]\ntask = \"off\"").unwrap();
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert_eq!(r.notify.repeat_after(), Some(Duration::from_secs(300)));

    // A malformed duration keeps what was in effect — never "announce every occurrence".
    let bad: RawConfig =
        toml::from_str("[notify]\nmode = \"always\"\nrepeat_after = \"soon\"").unwrap();
    let r = resolve_no_plugins(bad, None);
    assert_eq!(r.notify.repeat_after(), None);
    assert!(r
        .warnings
        .iter()
        .any(|w| w.contains("invalid `repeat_after`")));

    // Set where nothing ever repeats, it is called out rather than silently ignored.
    let moot: RawConfig =
        toml::from_str("[notify]\nmode = \"once\"\nrepeat_after = \"5m\"").unwrap();
    let r = resolve_no_plugins(moot, None);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("`repeat_after` has no effect")),
        "{:?}",
        r.warnings
    );
}

#[test]
fn an_override_notify_mode_applies_and_beats_the_baseline_both_directions() {
    use crate::notify::{NotifyEvent, NotifyMode};
    use schema::NotifyField;

    // Silence: the invoker turns off a baseline `always` for one launch, every event at once.
    let mut quiet = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(
        quiet.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Always
    );
    quiet = with_override(
        quiet,
        RawConfig {
            notify: Some(NotifyField::Mode("off".into())),
            ..RawConfig::default()
        },
    );
    for event in crate::notify::NotifyEvent::ALL {
        assert_eq!(quiet.notify.mode_for(event), NotifyMode::Off, "{event:?}");
    }
    assert_eq!(quiet.notify_origin, Provenance::Override);

    // And back up: a global that silences everything is overruled by the person at the keyboard,
    // who wants this one launch to say what it refused.
    let global: RawConfig = toml::from_str("notify = \"off\"").unwrap();
    let mut loud = resolve_no_plugins(global, None);
    assert_eq!(loud.notify.mode_for(NotifyEvent::Network), NotifyMode::Off);
    loud = with_override(
        loud,
        RawConfig {
            notify: Some(NotifyField::Mode("always".into())),
            ..RawConfig::default()
        },
    );
    assert_eq!(
        loud.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Always
    );
    assert_eq!(loud.notify_origin, Provenance::Override);
}

#[test]
fn a_bare_override_notify_mode_keeps_the_configured_repeat_period() {
    use crate::notify::{NotifyEvent, NotifyMode};
    use schema::NotifyField;
    use std::time::Duration;

    // A bare mode sets every event's mode and says nothing about the period, so the period keeps
    // what the layers below configured — the same parent-inheritance `proc` has for its lists. It
    // matters here because the alternative is worse in a specific way: turning the announcements up
    // for one launch would silently also remove the spacing that made `always` bearable.
    let global: RawConfig =
        toml::from_str("[notify]\nmode = \"once\"\nrepeat_after = \"5m\"").unwrap();
    let resolved = with_override(
        resolve_no_plugins(global, None),
        RawConfig {
            notify: Some(NotifyField::Mode("always".into())),
            ..RawConfig::default()
        },
    );
    assert_eq!(
        resolved.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Always
    );
    assert_eq!(
        resolved.notify.repeat_after(),
        Some(Duration::from_secs(300)),
        "a bare mode must not take the configured period with it"
    );
}

#[test]
fn a_set_but_invalid_override_notify_mode_is_a_hard_error_and_mutates_nothing() {
    use crate::notify::{NotifyEvent, NotifyMode};
    use schema::NotifyField;

    // A mistyped notify mode is fatal rather than a silent revert to the baseline: reverting could
    // leave a launch quieter than the invoker asked for, and a refusal nobody hears is the one
    // failure this feature exists to prevent.
    let global: RawConfig = toml::from_str("notify = \"off\"").unwrap();
    let mut resolved = resolve_no_plugins(global, None);
    let errs = resolved
        .apply_override(Override::for_test(RawConfig {
            notify: Some(NotifyField::Mode("alwyas".into())),
            ..RawConfig::default()
        }))
        .unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("notify")),
        "the error should name the offending field: {errs:?}"
    );
    // and nothing was applied — the baseline stands.
    assert_eq!(
        resolved.notify.mode_for(NotifyEvent::Network),
        NotifyMode::Off
    );
    assert_eq!(resolved.notify_origin, Provenance::Global);
}
