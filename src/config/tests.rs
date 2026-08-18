use super::schema::{
    RawEnvDefaults, RawFileDefaults, RawForward, RawResolverDefaults, RawSecretSection,
    RawSopsDefaults,
};
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
            libs: Vec::new(),
        },
        Package {
            name: "rg".into(),
            backend: Backend::Mise("aqua:BurntSushi/ripgrep".into()),
            state: TrustState::Trusted,
            libs: Vec::new(),
        },
        Package {
            name: "hello".into(),
            backend: Backend::Nix("hello".into()),
            state: TrustState::Trusted,
            libs: Vec::new(),
        },
        Package {
            name: "fd".into(),
            backend: Backend::Mise("nix:fd".into()),
            state: TrustState::Untrusted,
            libs: Vec::new(),
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
/// `[network.groups]` expansion and the mode-inheritance tests call `super::validate_network`
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
        timezone: None,
        plugin: Default::default(),
        broker: Default::default(),
        fs: None,
        redact: None,
        notify: None,
        rest: Default::default(),
        task: None,
        env: env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<BTreeMap<_, _>>(),
        binds: binds.iter().map(|s| RawBind::Path(s.to_string())).collect(),
        packages: BTreeMap::new(),
        open: Default::default(),
        service: Default::default(),
        bundle: BTreeMap::new(),
        flakes: BTreeMap::new(),
        tarball: BTreeMap::new(),
        deb: BTreeMap::new(),
        appimage: BTreeMap::new(),
        binary: BTreeMap::new(),
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
    }
}

/// Declare egress groups on a raw layer, in the one place they live: the `groups` table of its
/// `[network]`. A layer with no posture yet gains the table form, since that is the only shape
/// with room for the sub-table.
fn declare_groups(raw: &mut RawConfig, defs: &[(&str, &[&str])]) {
    let table = match raw
        .network
        .get_or_insert_with(|| net_field("deny", &[], &[]))
    {
        NetworkField::Table(t) => t,
        NetworkField::Posture(p) => panic!("`network = \"{p}\"` has no room for a groups table"),
    };
    for (name, entries) in defs {
        table.groups.insert(
            (*name).to_string(),
            entries.iter().map(|s| (*s).to_string()).collect(),
        );
    }
}

/// An all-absent `[network]` table, to be spread over by a test that cares about two of its
/// fields. `NetworkTable` deliberately derives no `Default`: a literal that names every field is
/// what makes the compiler refuse the next schema addition until each site says what it does with
/// it. That guard belongs on the resolver, not on a test spelling out sixteen `None`s to reach one.
fn net_table_defaults() -> NetworkTable {
    NetworkTable {
        mode: None,
        allow: vec![],
        deny: vec![],
        mute: vec![],
        http2: vec![],
        capture: None,
        websocket_secret: None,
        capture_max_kb: None,
        groups: Default::default(),
        rest: Default::default(),
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
    }
}

/// Build a `[network]` field in table form for the egress-group tests.
fn net_field(mode: &str, allow: &[&str], deny: &[&str]) -> NetworkField {
    NetworkField::Table(NetworkTable {
        mode: Some(mode.into()),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        deny: deny.iter().map(|s| s.to_string()).collect(),
        ..net_table_defaults()
    })
}

/// Build and pre-classify a `[network.groups]` table from `(name, entries)` pairs, returning the
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
        websocket_secret: None,
        capture_max_kb: None,
        groups: Default::default(),
        rest: Default::default(),
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
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
fn an_undefined_group_in_a_mute_list_says_nothing_is_muted() {
    // The same drop, in the third list. A `mute` reference that resolves to nothing changes no
    // verdict — the refusals it would have silenced simply keep being logged — so the warning must
    // say *muted*, not borrow the allow list's "nothing is allowed for it", which reads as a host
    // being cut off. Each list states its own consequence.
    let (g, _) = make_groups(&[("mcp", &["a.example.com:443"])]);
    let mut w = Vec::new();
    let mut field = net_field("deny", &["github.com"], &[]);
    let NetworkField::Table(t) = &mut field else {
        panic!("net_field builds a table");
    };
    t.mute = vec!["@noisy".into()];
    super::validate_network(&mut w, GLOBAL_CONFIG, field, &g, &NetworkPolicy::default()).unwrap();
    assert_eq!(w.len(), 1, "exactly one warning: {w:?}");
    assert!(
        w[0].contains("undefined group `@noisy`") && w[0].contains("nothing is muted"),
        "a mute miss states the mute consequence, not the allow one: {}",
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
    assert!(
        w.iter()
            .any(|m| m.contains("ignoring net group `bad name!`"))
    );
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
    declare_groups(
        &mut global,
        &[("mcp", &["{*} a.example.com:443", "{*} b.example.com:443"])],
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
fn an_apps_own_network_table_defines_no_group() {
    // An `[app.<name>.network]` is a posture, not a vocabulary. It sits under the same `[network]`
    // shape as the baseline's, so a `groups` table is expressible there and has to be answered:
    // ignored, named, and pointed at the reference form. The app is declared in the GLOBAL config —
    // the trusted layer — so the drop is about *where a group may be defined*, not about trust.
    let mut global = RawConfig::default();
    declare_groups(&mut global, &[("ci", &["{*} a.example.com:443"])]);
    let mut app_net = NetworkTable {
        mode: Some("deny".into()),
        allow: vec!["@ci".into()],
        ..net_table_defaults()
    };
    app_net
        .groups
        .insert("smuggled".into(), vec!["evil.example.com:443".into()]);
    global.app.insert(
        "demo".into(),
        raw_app(&["true"], &[], &[], &[], Some(NetworkField::Table(app_net))),
    );

    let r = resolve_no_plugins(global, None);
    // An app reports against itself, so the drop is named where the app is read.
    let demo = r.apps.get("demo").expect("the app resolves");
    assert!(
        demo.warnings
            .iter()
            .any(|w| w.contains("`groups` under `[network]`")),
        "an app's groups table must be named: {:?}",
        demo.warnings
    );
    // The app keeps what it may have: the reference to the global group resolves, its own
    // definition does not.
    let Some(NetworkPolicy::Allowlist(policy)) = &demo.network else {
        panic!("a filtering posture: {:?}", demo.network);
    };
    let hosts: Vec<String> = policy.allow_rules().iter().map(|r| r.to_string()).collect();
    assert!(
        hosts.iter().any(|h| h.contains("a.example.com")),
        "the `@ci` reference resolves: {hosts:?}"
    );
    assert!(
        !hosts.iter().any(|h| h.contains("evil.example.com")),
        "and the app-defined group opens nothing: {hosts:?}"
    );
}

#[test]
fn a_project_net_groups_is_ignored_with_a_warning_even_when_trusted() {
    // Groups are global-only: a project's `[network.groups]` is not honored — even from a TRUSTED
    // project — so it warns, and a `@ref` to a project-defined group does not resolve (it is
    // undefined). This is the security property: a project cannot smuggle a group definition into
    // an app's egress, only reference one the global config already trusts.
    let mut project = RawConfig::default();
    declare_groups(&mut project, &[("evil", &["evil.example.com:443"])]);
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
    // The baseline warns that the project's `[network.groups]` is ignored.
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("`groups` under `[network]`") && w.contains("global config only")),
        "a project's [network.groups] must warn: {:?}",
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
    // bare entry: no `{VERB}` prefix
    declare_groups(&mut global, &[("mcp", &["m.example.com:443"])]);
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
    std::fs::write(
        &good,
        "[network.groups]\nmcp = [\"{*} a.example.com:443\"]\n",
    )
    .unwrap();
    let g = read_net_groups_fragment(&good).expect("a `[network.groups]` fragment reads");
    assert_eq!(g.get("mcp").map(|v| v.len()), Some(1));

    // A file with no `[network.groups]` is the tell-tale of the wrong file — refused, not a silent
    // empty import.
    let bad = tmp.path().join("nope.toml");
    std::fs::write(&bad, "[env]\nFOO = \"bar\"\n").unwrap();
    let err = read_net_groups_fragment(&bad).unwrap_err();
    assert!(err.contains("no `[network.groups]`"), "{err}");
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".to_string()),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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

/// A `RawConfig` declaring `forward` ports in the bare same-port form.
fn raw_forward(ports: &[u16]) -> RawConfig {
    raw_forward_entries(
        &ports
            .iter()
            .copied()
            .map(RawForward::Port)
            .collect::<Vec<_>>(),
    )
}

/// A `RawConfig` declaring `forward` entries in whichever form the caller wrote — the way in for a
/// test that needs the `"host:cage"` remap form alongside bare ports.
fn raw_forward_entries(entries: &[RawForward]) -> RawConfig {
    RawConfig {
        forward: Some(entries.to_vec()),
        ..RawConfig::default()
    }
}

/// The resolved same-port forwards for `ports` — what a bare `forward = [...]` resolves to.
fn same_forwards(ports: &[u16]) -> Vec<ForwardPort> {
    ports.iter().copied().map(ForwardPort::same).collect()
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
        rest: Default::default(),
        open: Default::default(),
        service: Default::default(),
        fs: None,
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
        provisions: Vec::new(),
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
        binary: BTreeMap::new(),
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
        sign: None,
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
    assert!(
        app.packages
            .iter()
            .any(|p| p.name == "tool" && p.state == TrustState::Trusted)
    );
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
    assert!(
        app.packages
            .iter()
            .any(|p| p.name == "pkg" && p.state == TrustState::Untrusted)
    );
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
        websocket_secret: None,
        capture_max_kb: None,
        groups: Default::default(),
        rest: Default::default(),
        mode: Some("deny".into()),
        allow: vec!["x.com".into()],
        deny: vec![],
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: Some(vec!["*".into()]),
        dns_cache_ttl: None,
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
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
    assert!(
        app.warnings
            .iter()
            .any(|w| w.contains("demo-tool") && w.contains("override"))
    );
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some(mode.into()),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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

    // An unknown mode warns and yields nothing, which now *is* fail-closed: a dropped network
    // field resolves to `NetworkPolicy::default()`, the deny-by-default allowlist. A typo costs
    // the reach the author meant to grant rather than the confinement they meant to keep — the
    // warning stays loud, but it no longer stands between a typo and the open host network.
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
fn an_unconfigured_cage_defaults_to_the_ruleless_deny_allowlist() {
    use crate::allowlist::DefaultAction;
    // The built-in posture, pinned. With neither layer saying anything about the network, a cage
    // filters. This is also the posture an *untrusted* project actually gets, since its own
    // `network` is dropped whichever way it points — so this one value decides whether a repository
    // sbx knows nothing about reaches the host's loopback and LAN (`Shared`) or only the self-equip
    // set the proxy unions in (a `deny` allowlist carrying no rules of its own).
    let r = resolve_no_plugins(RawConfig::default(), None);
    assert!(
        matches!(&r.network, NetworkPolicy::Allowlist(p)
            if p.default_action() == DefaultAction::Deny
                && p.allow_rules().is_empty()
                && p.deny_rules().is_empty()),
        "the built-in default must be the ruleless deny allowlist: {:?}",
        r.network
    );
    // And it must read as the default rather than as a layer's choice, so `sbx config show` does
    // not credit a config that said nothing.
    assert_eq!(r.network_origin, Provenance::Default);
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: None,
            allow: vec!["api.foo.com".to_string()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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

/// What declaring a table costs, said in the layer that declares it.
///
/// The mode is the one thing a table inherits, so a reader has every reason to think the rest of
/// the layer below comes with it — every other layered table amends. This is the case that made it
/// worth saying: `sbx net allow --local` writes a one-rule `[network]` into a project, and the
/// settings the global config carried stop applying to that project.
#[test]
fn a_table_names_the_settings_of_the_layer_below_it_gives_up() {
    use crate::allowlist::EgressPolicy;
    use crate::sandbox::control::CaptureLevel;
    // The table `sbx net allow --local` writes: a mode and one rule, no settings of its own.
    let one_rule = || {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".to_string()),
            allow: vec!["example.com".to_string()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
        })
    };
    let warn = |parent: &NetworkPolicy| {
        let mut w = Vec::new();
        super::validate_network(
            &mut w,
            PROJECT_CONFIG,
            one_rule(),
            &NetGroups::new(),
            parent,
        )
        .expect("a table with a mode always resolves");
        w
    };

    // Two settings below: both named, in the order the config file declares them, plural.
    let w = warn(&NetworkPolicy::Allowlist(
        EgressPolicy::default()
            .with_ca_roots(false)
            .with_capture(CaptureLevel::Bodies, None),
    ));
    assert_eq!(w.len(), 1, "one line names them all: {w:?}");
    assert!(
        w[0].contains("replaces the layer below rather than adding to it"),
        "{}",
        w[0]
    );
    assert!(
        w[0].contains("settings it carried do not apply here: `ca_roots`, `capture`"),
        "{}",
        w[0]
    );
    assert!(w[0].contains("re-declare them"), "{}", w[0]);

    // A setting added to the table has to appear here too, or a layer would give it up without a
    // word. The exhaustive destructure in `settings_dropped_from` is what makes that a compile
    // error rather than an omission; this is what makes it a message.
    let w = warn(&NetworkPolicy::Allowlist(
        EgressPolicy::default().with_websocket_secret(crate::allowlist::WebsocketSecret::Block),
    ));
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].contains("does not apply here: `websocket_secret`"),
        "{}",
        w[0]
    );

    // One setting: the singular form, because a message that reads as generated invites being
    // skimmed past.
    let w = warn(&NetworkPolicy::Allowlist(
        EgressPolicy::default().with_ca_roots(false),
    ));
    assert!(
        w[0].contains("setting it carried does not apply here: `ca_roots`"),
        "{}",
        w[0]
    );
    assert!(w[0].contains("re-declare it"), "{}", w[0]);

    // The two silent cases, which is what keeps this off every project that adds a rule: a parent
    // carrying nothing, and a non-filtering parent that has no settings to carry.
    assert!(
        warn(&NetworkPolicy::Allowlist(EgressPolicy::default())).is_empty(),
        "a neutral parent gives nothing up"
    );
    assert!(
        warn(&NetworkPolicy::Shared).is_empty(),
        "a shared parent runs no proxy, so it carries no proxy setting"
    );
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: None,
            allow: vec!["api.proj.com".to_string()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
                websocket_secret: None,
                capture_max_kb: None,
                groups: Default::default(),
                rest: Default::default(),
                mode: None,
                allow: vec!["api.app.com".to_string()],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
                dns_cache_ttl: None,
                pool: None,
                idle_timeout: None,
                max_connections: None,
                body_max_mb: None,
                ca_roots: None,
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

/// `pool` reaches the policy from a layer entitled to set it, and only from one. The reuse of an
/// upstream connection is a transport decision the proxy makes on a request that a credential may
/// ride, so it belongs to the same trusted `[network]` table as the rest: an untrusted project's
/// table is dropped whole, and its `pool` with it.
#[test]
fn the_pool_toggle_defaults_on_and_is_gated_trusted_only() {
    let pool_table = |pool: Option<bool>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
        })
    };
    let mut w = Vec::new();
    let pool_of = |network: &NetworkPolicy| match network {
        NetworkPolicy::Allowlist(p) => p.pool(),
        _ => panic!("a filtering posture is expected"),
    };

    // Unset, and explicitly on, are the same posture: a finished connection carries the next
    // request.
    for value in [None, Some(true)] {
        let got = validate_network(&mut w, GLOBAL_CONFIG, pool_table(value)).unwrap();
        assert!(pool_of(&got), "reuse is the default posture: {value:?}");
    }
    let off = validate_network(&mut w, GLOBAL_CONFIG, pool_table(Some(false))).unwrap();
    assert!(!pool_of(&off), "a trusted layer can turn reuse off");
    assert!(w.is_empty(), "valid values warn nothing: {w:?}");

    // An untrusted project can do neither, in the direction that matters now that reuse is the
    // default: its whole `[network]` table is dropped before this field is ever read, so it cannot
    // move a launch off the posture the trusted layer gave it.
    let project = || RawConfig {
        network: Some(pool_table(Some(false))),
        ..RawConfig::default()
    };
    let global = || RawConfig {
        network: Some(pool_table(None)),
        ..RawConfig::default()
    };
    let trusted = resolve_no_plugins(global(), Some((project(), TrustState::Trusted)));
    assert!(
        !pool_of(&trusted.network),
        "a trusted project may turn reuse off"
    );
    let untrusted = resolve_no_plugins(global(), Some((project(), TrustState::Untrusted)));
    assert!(
        pool_of(&untrusted.network),
        "an untrusted project's whole `[network]` table drops, its `pool` included"
    );
}

/// `ca_roots` is a preference, and a `tcp://` rule is not obliged to honour it. Dropping the public
/// roots is safe while every rule is inspected — the session CA verifies each byte — but a spliced
/// stream is authenticated by the client against the real server, so removing them there would break
/// the connection the rule exists to allow. The override must also be audible: a setting silently
/// ignored reads as applied.
#[test]
fn ca_roots_defaults_on_and_a_splice_overrides_a_request_to_drop_them() {
    let ca_table = |ca_roots: Option<bool>, entry: &str| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec![entry.into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots,
        })
    };
    let roots_of = |network: &NetworkPolicy| match network {
        NetworkPolicy::Allowlist(p) => p.ca_roots(),
        _ => panic!("a filtering posture is expected"),
    };

    // Unset and explicitly on are the same posture: the cage gets an ordinary, full bundle.
    let mut w = Vec::new();
    for value in [None, Some(true)] {
        let got =
            validate_network(&mut w, GLOBAL_CONFIG, ca_table(value, "api.example.com")).unwrap();
        assert!(roots_of(&got), "a full bundle is the default: {value:?}");
    }
    let off = validate_network(
        &mut w,
        GLOBAL_CONFIG,
        ca_table(Some(false), "api.example.com"),
    )
    .unwrap();
    assert!(
        !roots_of(&off),
        "a trusted layer can ask for the MITM CA alone"
    );
    assert!(w.is_empty(), "valid values warn nothing: {w:?}");

    // With a splice in the same table the request is refused, not applied, and it says so.
    let spliced = validate_network(
        &mut w,
        GLOBAL_CONFIG,
        ca_table(Some(false), "tcp://db.example.com:5432"),
    )
    .unwrap();
    assert!(
        roots_of(&spliced),
        "a spliced stream needs the public roots whatever the field asked for"
    );
    assert_eq!(w.len(), 1, "the override is announced once: {w:?}");
    assert!(
        w[0].contains("ca_roots") && w[0].contains("tcp://"),
        "the warning names the field and the reason: {}",
        w[0]
    );

    // The field rides the same trust gate as the rest of the table.
    let project = || RawConfig {
        network: Some(ca_table(Some(false), "api.example.com")),
        ..RawConfig::default()
    };
    let global = || RawConfig {
        network: Some(ca_table(None, "api.example.com")),
        ..RawConfig::default()
    };
    let trusted = resolve_no_plugins(global(), Some((project(), TrustState::Trusted)));
    assert!(
        !roots_of(&trusted.network),
        "a trusted project may ask for the minimal bundle"
    );
    let untrusted = resolve_no_plugins(global(), Some((project(), TrustState::Untrusted)));
    assert!(
        roots_of(&untrusted.network),
        "an untrusted project's whole `[network]` table drops, its `ca_roots` included"
    );
}

#[test]
fn dns_cache_ttl_flows_from_the_table_to_the_policy() {
    let dns_table = |ttl: Option<u64>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["cache.nixos.org".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: ttl,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
fn the_connection_settings_flow_from_the_table_and_fail_closed_on_a_value_that_would_bite() {
    let conn_table = |idle: Option<&str>, max: Option<usize>, body_mb: Option<u64>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: idle.map(str::to_string),
            max_connections: max,
            body_max_mb: body_mb,
            ca_roots: None,
        })
    };
    let policy = |w: &mut Vec<String>, idle, max, body_mb| match validate_network(
        w,
        GLOBAL_CONFIG,
        conn_table(idle, max, body_mb),
    )
    .unwrap()
    {
        NetworkPolicy::Allowlist(p) => p,
        _ => panic!("a filtering posture is expected"),
    };
    let mut w = Vec::new();

    // Unset → the policy carries None, and the proxy applies its own defaults.
    let def = policy(&mut w, None, None, None);
    assert!(def.idle_timeout().is_none());
    assert!(def.max_connections().is_none());
    assert!(def.body_max().is_none());

    // Set → the value flows through, in the duration grammar `ask_timeout` already uses.
    let set = policy(&mut w, Some("2m"), Some(64), Some(256));
    assert_eq!(
        set.idle_timeout(),
        Some(std::time::Duration::from_secs(120))
    );
    assert_eq!(set.max_connections(), Some(64));
    assert_eq!(
        set.body_max(),
        Some(256 * 1024 * 1024),
        "the field is written in MiB and the policy carries bytes"
    );
    assert!(w.is_empty(), "valid values warn nothing: {w:?}");

    // A zero idle bound is `pool = false` said less clearly, and reading it as a bound would leave a
    // launch reusing connections it closes at once. Refused, and the built-in stays.
    let zero = policy(&mut w, Some("0s"), None, None);
    assert!(zero.idle_timeout().is_none(), "the built-in bound stays");
    assert!(
        w.iter()
            .any(|m| m.contains("idle_timeout") && m.contains("pool = false")),
        "the warning must name the field that actually turns reuse off: {w:?}"
    );

    // A cap of zero would refuse every connection — far likelier a typo than an intent.
    w.clear();
    let none_at_all = policy(&mut w, None, Some(0), None);
    assert!(
        none_at_all.max_connections().is_none(),
        "the built-in cap stays"
    );
    assert!(
        w.iter().any(|m| m.contains("max_connections = 0")),
        "the warning must name the value it refused: {w:?}"
    );

    // A malformed duration falls back to the built-in, warned, and never fails the launch.
    w.clear();
    let junk = policy(&mut w, Some("soon"), None, None);
    assert!(junk.idle_timeout().is_none());
    assert!(
        w.iter().any(|m| m.contains("invalid `idle_timeout`")),
        "a malformed duration must say so: {w:?}"
    );

    // A zero body ceiling would refuse every streamed upload and every signed request.
    w.clear();
    let no_body = policy(&mut w, None, None, Some(0));
    assert!(no_body.body_max().is_none(), "the built-in ceiling stays");
    assert!(
        w.iter().any(|m| m.contains("body_max_mb = 0")),
        "the warning must name the value it refused: {w:?}"
    );
}

/// The WebSocket-secret posture flows from the table to the policy, and an unknown value keeps the
/// default rather than picking one.
///
/// The default is the one that does not tear a live tunnel down, so "fails closed" is the wrong
/// frame here and the reason is written where the value is parsed: closing on a value nobody chose
/// ends a conversation, and the setting exists because that is a cost only its author can weigh.
#[test]
fn the_websocket_secret_posture_flows_from_the_table_and_keeps_the_default_on_a_typo() {
    use crate::allowlist::WebsocketSecret;
    let table = |raw: Option<&str>| {
        NetworkField::Table(NetworkTable {
            mute: vec![],
            http2: vec![],
            capture: None,
            capture_max_kb: None,
            websocket_secret: raw.map(str::to_string),
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
        })
    };
    let mut w = Vec::new();

    let unset = validate_network(&mut w, GLOBAL_CONFIG, table(None)).unwrap();
    assert!(matches!(&unset, NetworkPolicy::Allowlist(p)
            if p.websocket_secret() == WebsocketSecret::Warn));

    let blocking = validate_network(&mut w, GLOBAL_CONFIG, table(Some("block"))).unwrap();
    assert!(matches!(&blocking, NetworkPolicy::Allowlist(p)
            if p.websocket_secret() == WebsocketSecret::Block));
    let warning = validate_network(&mut w, GLOBAL_CONFIG, table(Some("warn"))).unwrap();
    assert!(matches!(&warning, NetworkPolicy::Allowlist(p)
            if p.websocket_secret() == WebsocketSecret::Warn));
    assert!(w.is_empty(), "valid values warn nothing: {w:?}");

    let typo = validate_network(&mut w, GLOBAL_CONFIG, table(Some("blocked"))).unwrap();
    assert!(
        matches!(&typo, NetworkPolicy::Allowlist(p)
            if p.websocket_secret() == WebsocketSecret::Warn),
        "an unknown value keeps the default rather than choosing one"
    );
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("websocket_secret"), "{w:?}");
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
            websocket_secret: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
            websocket_secret: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("ask".into()),
            allow: vec![],
            deny: vec![],
            ask_timeout: timeout.map(|s| s.to_string()),
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
        websocket_secret: None,
        capture_max_kb: None,
        groups: Default::default(),
        rest: Default::default(),
        mode: Some("deny".into()),
        allow: vec![],
        deny: vec![],
        ask_timeout: Some("90s".into()),
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("ask".into()),
            allow: vec![],
            deny: vec![],
            ask_timeout: None,
            ask_notice: notice,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
        websocket_secret: None,
        capture_max_kb: None,
        groups: Default::default(),
        rest: Default::default(),
        mode: Some("deny".into()),
        allow: vec![],
        deny: vec![],
        ask_timeout: None,
        ask_notice: Some(false),
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
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
            forward: Some(vec![RawForward::Port(1455)]),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    // An untrusted project tries to add a port to the trusted app — dropped.
    let project = raw_with_app(
        "demo-app",
        RawApp {
            forward: Some(vec![RawForward::Port(31337)]),
            ..raw_app(&[], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    let app = &r.apps["demo-app"];
    assert_eq!(
        app.forward,
        same_forwards(&[1455]),
        "an untrusted project may not add a forward port to a trusted app"
    );
    assert!(app.warnings.iter().any(|w| w.contains("forward")));

    // The reverse: an untrusted project cannot open an inbound hole on its own app either.
    let project = raw_with_app(
        "mine",
        RawApp {
            forward: Some(vec![RawForward::Port(8080)]),
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
            forward: Some(vec![RawForward::Port(1455)]),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.apps["demo-app"].forward, same_forwards(&[1455]));
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

/// A `[broker.<name>]` table with a socket, as the global config alone may write it.
fn raw_broker(socket: Option<&str>, allow: &[&str]) -> crate::config::schema::RawBrokerConfig {
    crate::config::schema::RawBrokerConfig {
        socket: socket.map(str::to_string),
        allow: allow.iter().map(|s| (*s).to_string()).collect(),
        secret: None,
        rest: Default::default(),
    }
}

fn with_broker(
    mut cfg: RawConfig,
    name: &str,
    table: crate::config::schema::RawBrokerConfig,
) -> RawConfig {
    cfg.broker.insert(name.to_string(), table);
    cfg
}

/// The split that carries the security property: the global config says *which host resource* is
/// exposed, a trusted project says only *what may be done with it*.
#[test]
fn a_project_may_set_a_brokers_policy_but_never_the_resource_it_brokers() {
    let global = with_broker(
        raw(&[], &[]),
        "gpg-agent",
        raw_broker(Some("/run/host/S.gpg-agent"), &["sign"]),
    );
    let project = with_broker(
        raw(&[], &[]),
        "gpg-agent",
        raw_broker(Some("/tmp/attacker.sock"), &["sign", "decrypt"]),
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Trusted)));
    assert_eq!(r.brokers.len(), 1);
    assert_eq!(
        r.brokers[0].socket,
        crate::config::BrokerTarget::Unix(std::path::PathBuf::from("/run/host/S.gpg-agent")),
        "a project may not repoint a broker at another host resource"
    );
    assert_eq!(
        r.brokers[0].allow,
        vec!["sign".to_string(), "decrypt".to_string()],
        "but its policy is honored"
    );
    assert_eq!(r.brokers[0].origin, Provenance::Project);
    assert!(
        r.warnings.iter().any(|w| w.contains("socket")),
        "the dropped socket is named: {:?}",
        r.warnings
    );
}

/// A broker plugin whose manifest reads `env`, for the `[plugin.<name>]` tests.
fn broker_plugin_reading(name: &str, env: &[&str]) -> crate::plugins::broker::BrokerPlugin {
    crate::plugins::broker::BrokerPlugin {
        name: name.to_string(),
        dir: PathBuf::from(format!("/data/plugins/{name}")),
        exec: PathBuf::from(format!("/data/plugins/{name}/broker")),
        sandbox: crate::plugins::SandboxGrant {
            allow_env: env.iter().map(|s| (*s).to_string()).collect(),
            ..Default::default()
        },
        broker: crate::plugins::broker::BrokerSpec {
            cage_env: vec!["X_SOCK".to_string()],
            cage_env_dir: Vec::new(),
            socket_name: format!("{name}.sock"),
            at_host_path: false,
            framing: crate::plugins::broker::Framing::Line,
            max_frame: 1024,
            deny_frame: None,
            uses_secret: false,
            host_greets: false,
            host_deadline: crate::plugins::broker::DEFAULT_HOST_DEADLINE,
            inspect_replies: false,
        },
        version: None,
        description: None,
        host: Default::default(),
    }
}

/// `[plugin.<name>]` reaches a **broker**, not only a resolver. It is the one table that says what
/// this host answers a plugin, and a broker is a plugin: leaving it unapplied dropped the values in
/// silence, reported the table as matching nothing, and still showed it in `sbx plugins info`.
#[test]
fn a_plugin_table_naming_a_broker_is_applied_to_it_and_counts_as_used() {
    let reg = PluginRegistry::with_brokers([broker_plugin_reading("gpg-agent", &["GNUPGHOME"])]);
    let mut global = with_broker(
        raw(&[], &[]),
        "gpg-agent",
        raw_broker(Some("/run/host/S.gpg-agent"), &["sign"]),
    );
    global.plugin = raw_plugin_table(
        "gpg-agent",
        &[("GNUPGHOME", "/srv/keys"), ("NOT_DECLARED", "x")],
    )
    .plugin;

    let r = super::resolve(global, None, &reg);
    assert_eq!(
        r.brokers[0].host.env,
        vec![("GNUPGHOME".to_string(), "/srv/keys".to_string())],
        "the declared variable reaches the broker"
    );
    assert!(
        r.warnings.iter().any(|w| w.contains("NOT_DECLARED")),
        "and the undeclared one is dropped by name: {:?}",
        r.warnings
    );
    assert!(
        !r.warnings
            .iter()
            .any(|w| w.contains("no secret uses a plugin")),
        "a table naming a broker is not an unused table: {:?}",
        r.warnings
    );
}

/// A broker may stand in front of a TCP endpoint, not only a Unix socket. The endpoint is parsed
/// here; whether the cage may reach it is the allowlist's answer, given at launch.
#[test]
fn a_broker_target_may_be_a_tcp_endpoint() {
    let global = with_broker(
        raw(&[], &[]),
        "pg",
        raw_broker(Some("tcp://db.internal:5432"), &[]),
    );
    let r = resolve_no_plugins(global, None);
    assert_eq!(
        r.brokers[0].socket,
        crate::config::BrokerTarget::Tcp {
            host: "db.internal".to_string(),
            port: 5432
        }
    );
}

/// A malformed endpoint is refused rather than half-read: a missing port would leave sbx guessing
/// which service a broker stands in front of.
#[test]
fn a_tcp_endpoint_without_a_usable_port_is_refused() {
    for bad in [
        "tcp://db.internal",
        "tcp://db.internal:0",
        "tcp://db:http",
        "tcp://:5432",
    ] {
        let global = with_broker(raw(&[], &[]), "pg", raw_broker(Some(bad), &[]));
        let r = resolve_no_plugins(global, None);
        assert!(r.brokers.is_empty(), "{bad} must not bind a broker");
        assert!(
            r.warnings.iter().any(|w| w.contains("not started")),
            "{bad}: {:?}",
            r.warnings
        );
    }
}

/// An untrusted project's whole section is dropped, and named — so "not configured" and "not
/// trusted" never look alike.
#[test]
fn an_untrusted_projects_broker_section_is_dropped_whole() {
    let global = raw(&[], &[]);
    let project = with_broker(
        raw(&[], &[]),
        "gpg-agent",
        raw_broker(Some("/tmp/attacker.sock"), &["everything"]),
    );
    let r = resolve_no_plugins(global, Some((project, TrustState::Untrusted)));
    assert!(r.brokers.is_empty());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("[broker.*]") && w.contains("gpg-agent")),
        "{:?}",
        r.warnings
    );
}

/// A project cannot introduce a broker the global config never bound: without a global socket
/// there is nothing to broker, and the table is reported rather than half-honored.
#[test]
fn a_trusted_project_cannot_introduce_a_broker_the_global_config_never_bound() {
    let project = with_broker(raw(&[], &[]), "gpg-agent", raw_broker(None, &["sign"]));
    let r = resolve_no_plugins(raw(&[], &[]), Some((project, TrustState::Trusted)));
    assert!(r.brokers.is_empty());
    assert!(
        r.warnings.iter().any(|w| w.contains("gpg-agent")),
        "{:?}",
        r.warnings
    );
}

/// A table that binds nothing is not a binding: it is dropped, named, and nothing is started.
#[test]
fn a_broker_table_without_a_socket_binds_nothing() {
    let global = with_broker(raw(&[], &[]), "gpg-agent", raw_broker(None, &["sign"]));
    let r = resolve_no_plugins(global, None);
    assert!(r.brokers.is_empty());
    assert!(
        r.warnings.iter().any(|w| w.contains("no `socket`")),
        "{:?}",
        r.warnings
    );
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
    // its app layer; an untouched scalar keeps the default origin, which is what lets the detail
    // view tell "the baseline set this" from "nobody did".
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("did you mean") && w.contains("memory_max"))
    );

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
    // The two kinds of second file an app can be short of, side by side in one profile. Both are
    // surfaced so the importer can name what is undeclared; neither is resolved here.
    let referencing = validate_profile(
        br#"
            cmd = "demo-app"
            use = ["demo-tool"]
            [network]
            mode = "deny"
            allow = ["@demo-lane", "api.example.com/@handle"]
            deny  = ["re:^https://x@y/"]
            mute  = ["@demo-lane", "@demo-noise"]
            "#,
    )
    .unwrap();
    assert_eq!(referencing.uses, vec!["demo-tool".to_string()]);
    // Sorted and deduplicated across all three lists — and a `@` that is not the FIRST character
    // is part of the entry (a URL path, a `re:` pattern), never a reference. Assert the exact set:
    // a `contains` would pass while a bogus extra reference is reported to the user as missing.
    assert_eq!(
        referencing.groups,
        vec!["demo-lane".to_string(), "demo-noise".to_string()],
    );
    // The bare-string posture form has no lists at all, so it can reference nothing.
    let posture = validate_profile(b"cmd = \"demo-app\"\nnetwork = \"deny\"\n").unwrap();
    assert!(posture.groups.is_empty() && posture.uses.is_empty());
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
        provisions: Vec::new(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
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
        open: Default::default(),
        service: Default::default(),
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
        provisions: Vec::new(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
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
        open: Default::default(),
        service: Default::default(),
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
    assert!(
        base.warnings
            .iter()
            .any(|w| w.contains("credential injection requires"))
    );
}

#[test]
fn merge_app_keeps_secrets_under_an_allowlist_the_app_declares() {
    let mut base = resolve_no_plugins(raw_network("shared"), None);
    let app = ResolvedApp {
        provisions: Vec::new(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
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
        open: Default::default(),
        service: Default::default(),
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
    use crate::allowlist::{EgressPolicy, Methods, classify};
    let read_default = Methods::Only(vec!["GET".to_string(), "HEAD".to_string()]);
    let app_with = |network: Option<NetworkPolicy>, default_methods: Methods| ResolvedApp {
        provisions: Vec::new(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
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
        open: Default::default(),
        service: Default::default(),
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["h.test".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: Some(vec!["GET".into()]),
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
        provisions: Vec::new(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
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
        open: Default::default(),
        service: Default::default(),
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
        provisions: Vec::new(),
        fs: Default::default(),
        fs_origin: crate::config::Provenance::Default,
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
        open: Default::default(),
        service: Default::default(),
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

/// A `RawConfig` whose only field is an `[open]` table with one entry.
fn raw_with_open(scheme: &str, entry: schema::RawOpen) -> RawConfig {
    RawConfig {
        open: BTreeMap::from([(scheme.to_string(), entry)]),
        ..RawConfig::default()
    }
}

/// A bare-argv `[open]` entry.
fn open_argv(argv: &[&str]) -> schema::RawOpen {
    schema::RawOpen::Argv(schema::RawCmd::Argv(
        argv.iter().map(|s| s.to_string()).collect(),
    ))
}

#[test]
fn an_untrusted_project_cannot_declare_a_uri_handler() {
    // The property the whole feature rests on. sbx puts the router first on PATH and freezes the
    // portal's route so nothing in the cage can answer a link in its place; honoring `[open]` from
    // an untrusted project would hand that answer straight back, through the config instead of
    // through the filesystem.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            raw_with_open("https", open_argv(&["attacker-browser"])),
            TrustState::Untrusted,
        )),
    );
    assert!(r.open.is_empty(), "no handler survives: {:?}", r.open);
    assert!(
        r.warnings.iter().any(|w| w.contains("`[open]`")),
        "the drop is reported: {:?}",
        r.warnings
    );
}

#[test]
fn a_trusted_layer_resolves_a_handler_and_its_mode() {
    let r = resolve_no_plugins(
        RawConfig {
            open: BTreeMap::from([
                ("https".to_string(), open_argv(&["chromium", "--flag"])),
                (
                    "cursor".to_string(),
                    schema::RawOpen::Detailed(schema::RawOpenTable {
                        cmd: schema::RawCmd::Argv(vec!["cursor".into(), "--open-url".into()]),
                        mode: Some("detach".into()),
                    }),
                ),
            ]),
            ..RawConfig::default()
        },
        None,
    );
    assert_eq!(
        r.open.get("https").map(|h| (h.argv.clone(), h.mode)),
        Some((
            vec!["chromium".to_string(), "--flag".to_string()],
            crate::config::OpenMode::Exec
        )),
        "a bare argv defaults to exec"
    );
    assert_eq!(
        r.open.get("cursor").map(|h| h.mode),
        Some(crate::config::OpenMode::Detach)
    );
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_handler_sbx_cannot_honor_is_dropped_rather_than_guessed() {
    // Three ways an entry can be unusable, each dropped with its scheme named. Dropping is the
    // safe direction: an unhandled link is printed and the launch goes on, while a handler kept
    // despite a value sbx did not understand would route a real sign-in click.
    let r = resolve_no_plugins(
        RawConfig {
            open: BTreeMap::from([
                // not a scheme: a reader may reach for a MIME type or a whole URL
                ("text/html".to_string(), open_argv(&["viewer"])),
                // a mode that does not exist: silently treating it as `exec` would hang the very
                // caller `detach` was misspelled for
                (
                    "https".to_string(),
                    schema::RawOpen::Detailed(schema::RawOpenTable {
                        cmd: schema::RawCmd::Argv(vec!["chromium".into()]),
                        mode: Some("background".into()),
                    }),
                ),
                // no program at all
                ("cursor".to_string(), open_argv(&[])),
            ]),
            ..RawConfig::default()
        },
        None,
    );
    assert!(r.open.is_empty(), "none is honored: {:?}", r.open);
    assert_eq!(r.warnings.len(), 3, "each is reported: {:?}", r.warnings);
    for scheme in ["text/html", "https", "cursor"] {
        assert!(
            r.warnings.iter().any(|w| w.contains(scheme)),
            "`{scheme}` is named: {:?}",
            r.warnings
        );
    }
}

/// A bare-argv `[service]` entry.
fn service_argv(argv: &[&str]) -> schema::RawService {
    schema::RawService::Argv(schema::RawCmd::Argv(
        argv.iter().map(|s| s.to_string()).collect(),
    ))
}

#[test]
fn an_untrusted_project_cannot_declare_a_service() {
    // A service runs a program of its own choosing at every launch, before anything else. That is
    // the grant an untrusted project is already refused for `cmd`, and declaring it under another
    // field's name would not make it a different grant.
    let r = resolve_no_plugins(
        RawConfig::default(),
        Some((
            RawConfig {
                service: BTreeMap::from([(
                    "miner".to_string(),
                    service_argv(&["attacker-daemon"]),
                )]),
                ..RawConfig::default()
            },
            TrustState::Untrusted,
        )),
    );
    assert!(r.service.is_empty(), "none survives: {:?}", r.service);
    assert!(
        r.warnings.iter().any(|w| w.contains("`[service]`")),
        "the drop is reported: {:?}",
        r.warnings
    );
}

#[test]
fn a_trusted_layer_resolves_a_service_with_its_condition_and_gate() {
    let r = resolve_no_plugins(
        RawConfig {
            service: BTreeMap::from([
                ("gateway".to_string(), service_argv(&["hermes", "gateway"])),
                (
                    "chroma".to_string(),
                    schema::RawService::Detailed(schema::RawServiceTable {
                        cmd: schema::RawCmd::Argv(vec!["chroma".into(), "run".into()]),
                        enable: Some(schema::RawEnable::One(schema::RawEnableCond {
                            env: "NO_CHROMA".into(),
                            is: None,
                            not: Some(schema::RawValues::One("1".into())),
                        })),
                        ready: Some(schema::RawServiceReady {
                            tcp: 8100,
                            timeout: Some("30s".into()),
                        }),
                    }),
                ),
            ]),
            ..RawConfig::default()
        },
        None,
    );
    let gateway = r.service.get("gateway").expect("the bare argv resolves");
    assert_eq!(
        gateway.argv,
        vec!["hermes".to_string(), "gateway".to_string()]
    );
    assert!(
        gateway.enable.is_empty() && gateway.ready.is_none(),
        "a bare argv starts unconditionally and is waited on for nothing"
    );
    let chroma = r.service.get("chroma").expect("the table form resolves");
    assert_eq!(
        chroma
            .enable
            .iter()
            .map(crate::config::EnvCondition::display)
            .collect::<Vec<_>>(),
        vec!["NO_CHROMA != 1".to_string()]
    );
    assert_eq!(
        chroma.ready.map(|g| (g.tcp, g.timeout.as_secs())),
        Some((8100, 30))
    );
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_service_sbx_cannot_honor_is_dropped_and_a_bad_qualifier_only_costs_its_qualifier() {
    // The two directions are different on purpose. An entry with no program cannot start anything,
    // so it goes; a gate sbx cannot read is a *qualifier* on a service that is otherwise fine, so
    // the service stays and only the qualifier is dropped. Losing the whole service over its
    // timeout would take away the process the profile is for.
    let r = resolve_no_plugins(
        RawConfig {
            service: BTreeMap::from([
                ("empty".to_string(), service_argv(&[])),
                ("bad name".to_string(), service_argv(&["daemon"])),
                (
                    "gated".to_string(),
                    schema::RawService::Detailed(schema::RawServiceTable {
                        cmd: schema::RawCmd::Argv(vec!["daemon".into()]),
                        enable: None,
                        // A wait that never gives up would hang the launch on a service that never
                        // binds, which is the one outcome the gate exists to avoid.
                        ready: Some(schema::RawServiceReady {
                            tcp: 8100,
                            timeout: Some("0".into()),
                        }),
                    }),
                ),
            ]),
            ..RawConfig::default()
        },
        None,
    );
    assert!(!r.service.contains_key("empty"), "no program, no service");
    assert!(
        !r.service.contains_key("bad name"),
        "a name that reaches a log file and every diagnostic is held to a shape"
    );
    let gated = r.service.get("gated").expect("the service itself survives");
    assert!(gated.ready.is_none(), "only the unusable gate is dropped");
    for named in ["empty", "bad name", "gated"] {
        assert!(
            r.warnings.iter().any(|w| w.contains(named)),
            "`{named}` is named in a warning: {:?}",
            r.warnings
        );
    }
}

#[test]
fn a_condition_disjoins_over_the_values_of_one_variable() {
    // The "or" that a start condition actually needs: "off" is written `0`, `false` or `no`
    // depending on who typed it, and asking which one is not a question a profile should have to
    // answer. It costs no boolean structure — the comparison already had a value, and now it may
    // have a set of them — and it stops there: across DIFFERENT variables a list stays an `and`.
    let r = resolve_no_plugins(
        RawConfig {
            service: BTreeMap::from([(
                "daemon".to_string(),
                schema::RawService::Detailed(schema::RawServiceTable {
                    cmd: schema::RawCmd::Argv(vec!["daemon".into()]),
                    enable: Some(schema::RawEnable::One(schema::RawEnableCond {
                        env: "SWITCH".into(),
                        is: None,
                        not: Some(schema::RawValues::Any(vec![
                            "0".into(),
                            "false".into(),
                            "no".into(),
                        ])),
                    })),
                    ready: None,
                }),
            )]),
            ..RawConfig::default()
        },
        None,
    );
    let cond = &r.service["daemon"].enable;
    assert_eq!(cond.len(), 1, "one condition, not three");
    assert_eq!(cond[0].values, vec!["0", "false", "no"]);
    assert!(!cond[0].equals);
    assert_eq!(cond[0].display(), "SWITCH != 0|false|no");

    // Each of the three, and only those three, turns it off; anything else leaves it on.
    let env = |v: &str| [("SWITCH".to_string(), v.to_string())];
    for off in ["0", "false", "no"] {
        assert!(!cond[0].holds(&env(off)), "`{off}` turns it off");
    }
    for on in ["1", "yes", "", "NO"] {
        assert!(cond[0].holds(&env(on)), "`{on}` leaves it on");
    }
    assert!(
        cond[0].holds(&[]),
        "unset compares as empty, so it stays on"
    );
}

#[test]
fn an_enable_condition_that_compares_nothing_is_dropped_alone() {
    // The two ways a condition can be unusable are the two ways its pair of comparisons can be
    // wrong, and both are refused rather than guessed: with `is` and `not` both set there is no
    // saying which was meant, and with neither there is nothing to compare. The service survives
    // either way — a qualifier sbx cannot read must not cost the process the profile is for, and
    // starting is what the profile asks for when nothing says otherwise.
    let entry = |enable: schema::RawEnableCond| {
        schema::RawService::Detailed(schema::RawServiceTable {
            cmd: schema::RawCmd::Argv(vec!["daemon".into()]),
            enable: Some(schema::RawEnable::One(enable)),
            ready: None,
        })
    };
    let r = resolve_no_plugins(
        RawConfig {
            service: BTreeMap::from([
                (
                    "both".to_string(),
                    entry(schema::RawEnableCond {
                        env: "A".into(),
                        is: Some(schema::RawValues::One("1".into())),
                        not: Some(schema::RawValues::One("0".into())),
                    }),
                ),
                (
                    "neither".to_string(),
                    entry(schema::RawEnableCond {
                        env: "B".into(),
                        is: None,
                        not: None,
                    }),
                ),
                (
                    "nameless".to_string(),
                    entry(schema::RawEnableCond {
                        env: String::new(),
                        is: Some(schema::RawValues::One("1".into())),
                        not: None,
                    }),
                ),
                (
                    "good".to_string(),
                    entry(schema::RawEnableCond {
                        env: "C".into(),
                        is: None,
                        not: Some(schema::RawValues::One("0".into())),
                    }),
                ),
            ]),
            ..RawConfig::default()
        },
        None,
    );
    for name in ["both", "neither", "nameless"] {
        let svc = r.service.get(name).expect("the service itself survives");
        assert!(svc.enable.is_empty(), "`{name}` loses only its condition");
        assert!(
            r.warnings.iter().any(|w| w.contains(name)),
            "`{name}` is named in a warning: {:?}",
            r.warnings
        );
    }
    assert_eq!(
        r.service
            .get("good")
            .map(|s| s
                .enable
                .iter()
                .map(crate::config::EnvCondition::display)
                .collect::<Vec<_>>())
            .unwrap_or_default(),
        vec!["C != 0".to_string()]
    );
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
        // the signal `sbx upgrade provision` raises for a bundle's install step: sbx sets it, so
        // an untrusted project may not, or every launch would re-run the install as a download.
        "SBX_UPGRADE",
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("bare") && w.contains("backend prefix"))
    );
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("local") && w.contains("flake reference"))
    );
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("empty") && w.contains("flake"))
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("badattr") && w.contains("attribute"))
    );
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("dup") && w.contains("both"))
    );
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
        libs: Vec::new(),
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

/// `binary:` accepts a URL to the program itself, and the sentinel is bound to its table elsewhere.
///
/// The interesting half is what this backend does NOT check. It has no extension to require, so the
/// test says so explicitly: a URL ending in anything at all is accepted, and what is refused is the
/// scheme, the injection charset, and a locator that is not a path to something.
#[test]
fn a_binary_backend_takes_a_url_to_the_program_itself() {
    assert!(matches!(
        parse_backend("binary:https://e/cli/demo-1.2.3-linux-x86_64"),
        Ok(Backend::Binary(_))
    ));

    // No extension is required, and that is the point of this backend.
    assert!(is_valid_binary_url("https://e/cli/demo-1.2.3-linux-x86_64"));
    assert!(is_valid_binary_url("https://e/d/My%20Program")); // %-encoded space
    assert!(is_valid_binary_url("https://e/cli/demo.tar.gz")); // an extension is not forbidden either

    // What IS refused: a plaintext scheme (the file is executed after autoPatchelf), anything
    // carrying a shell/nix metacharacter (the value is interpolated into a generated derivation and
    // a prefetch argument), and a locator naming no path — a program is never the bare host.
    assert!(!is_valid_binary_url("http://e/cli/demo")); // not https
    assert!(!is_valid_binary_url("https://e/cli/de mo")); // raw whitespace
    assert!(!is_valid_binary_url("https://e/cli/$(id)")); // command substitution
    assert!(!is_valid_binary_url("https://e/cli/demo\";x")); // quote + separator
    assert!(!is_valid_binary_url("https://e")); // no path at all
    assert!(!is_valid_binary_url("https://e/")); // a directory, not a program
    assert!(!is_valid_binary_url("https://")); // no host
    assert!(!is_valid_binary_url("ftp://e/cli/demo")); // wrong scheme entirely

    // A mistyped form is refused up front; the bare sentinel is refused here too, since it is bound
    // to its `[binary.<name>]` table by `apply_tools` rather than parsed as a locator.
    assert!(parse_backend("binary:not-a-url").is_err());
    assert!(parse_backend("binary:resolve").is_err());
}

/// A `RawConfig` declaring one `tarball:resolve` package: the `[packages]` sentinel plus its
/// paired `[tarball.<name>]` table carrying the resolver command argv.
fn raw_tarball_resolve(name: &str, command: &[&str]) -> RawConfig {
    let mut raw = raw_packages(&[(name, TARBALL_RESOLVE_SENTINEL)]);
    raw.tarball.insert(
        name.to_string(),
        RawResolve {
            resolve: command.iter().map(|s| s.to_string()).collect(),
            libs: Vec::new(),
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
            libs: Vec::new(),
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "orphan").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("orphan") && w.contains("[packages]"))
    );
}

#[test]
fn an_orphan_tarball_sentinel_is_ignored_with_a_warning() {
    // A `<name> = "tarball:resolve"` with no `[tarball.<name>]` table can never resolve.
    let r = resolve_no_plugins(raw_packages(&[("lonely", TARBALL_RESOLVE_SENTINEL)]), None);
    assert!(pkg(&r.packages, "lonely").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("lonely") && w.contains("[tarball.lonely]"))
    );
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
    // Trust is recorded, not enforced, at resolve: the launcher's admitted-resolver list is
    // trusted-only, so it withholds this one and NEVER runs its command, like the direct
    // `tarball:` form.
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
        libs: Vec::new(),
    }];
    let mut warnings = Vec::new();
    let tarball: BTreeMap<String, RawResolve> = ["guarded", "fresh"]
        .into_iter()
        .map(|n| {
            (
                n.to_string(),
                RawResolve {
                    resolve: CMD.iter().map(|s| s.to_string()).collect(),
                    libs: Vec::new(),
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
            libs: Vec::new(),
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
            libs: Vec::new(),
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "orphan").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("orphan") && w.contains("[packages]"))
    );
}

/// A `[deb.<name>]` table carrying only `libs` — no `resolve`, so it decorates a package declared
/// with a fixed URL or a `github:` locator rather than declaring one.
fn raw_deb_libs(name: &str, locator: &str, libs: &[&str]) -> RawConfig {
    let mut raw = raw_packages(&[(name, locator)]);
    raw.deb.insert(
        name.to_string(),
        RawResolve {
            resolve: Vec::new(),
            libs: libs.iter().map(|s| s.to_string()).collect(),
        },
    );
    raw
}

#[test]
fn a_deb_table_carrying_only_libs_decorates_the_package_without_a_sentinel() {
    // The shape a GTK/WebKit app needs: the package is declared the ordinary way, and its table
    // only names the extra attributes its ELFs must be patched against. That is NOT an orphan
    // table — the "no matching sentinel" warning would be noise here, and the libs must land.
    let r = resolve_no_plugins(
        raw_deb_libs(
            "app",
            "deb:https://example.com/app.deb",
            &["webkitgtk_4_1", "gst_all_1.gst-plugins-base"],
        ),
        None,
    );
    let p = pkg(&r.packages, "app").unwrap();
    assert_eq!(p.libs, vec!["webkitgtk_4_1", "gst_all_1.gst-plugins-base"]);
    assert!(
        !r.warnings.iter().any(|w| w.contains("no matching")),
        "a libs-only table is not an orphan: {:?}",
        r.warnings
    );
}

#[test]
fn an_apps_libs_survive_the_merge_onto_the_baseline() {
    // The launch reads the app through `merge_app`, not through `apps[…]`: a `libs` list that
    // resolves correctly but is dropped by the merge reaches the builder empty, and the package is
    // patched against the built-in set alone — the build then fails on the very NEEDED entries the
    // list was there to satisfy.
    let mut app = raw_app(
        &["demo-desktop"],
        &[],
        &[],
        &[("demo-desktop", "deb:https://example.com/app.deb")],
        None,
    );
    app.deb = std::iter::once((
        "demo-desktop".to_string(),
        RawResolve {
            resolve: Vec::new(),
            libs: vec!["webkitgtk_4_1".to_string()],
        },
    ))
    .collect();
    let r = resolve_no_plugins(raw_with_app("demo-app", app), None);
    let mut merged = r.clone();
    merged.merge_app(r.apps["demo-app"].clone());
    assert_eq!(
        pkg(&merged.packages, "demo-desktop").unwrap().libs,
        vec!["webkitgtk_4_1"]
    );
}

#[test]
fn a_resolve_sentinel_can_carry_libs_alongside_its_command() {
    // The two fields coexist: the command still declares the package, the libs still decorate it.
    let mut raw = raw_deb_resolve("app", CMD);
    raw.deb.get_mut("app").unwrap().libs = vec!["webkitgtk_4_1".to_string()];
    let r = resolve_no_plugins(raw, None);
    let p = pkg(&r.packages, "app").unwrap();
    assert_eq!(
        p.backend,
        Backend::DebResolve {
            command: CMD.iter().map(|s| s.to_string()).collect(),
        }
    );
    assert_eq!(p.libs, vec!["webkitgtk_4_1"]);
}

#[test]
fn an_invalid_library_attribute_is_dropped_on_its_own() {
    // Each name is interpolated into the generated derivation, so it passes the same charset
    // barrier as a `nix:` attribute. One bad entry drops itself, not the whole list.
    let r = resolve_no_plugins(
        raw_deb_libs(
            "app",
            "deb:https://example.com/app.deb",
            &["webkitgtk_4_1", "evil; rm -rf /", "libsoup_3"],
        ),
        None,
    );
    assert_eq!(
        pkg(&r.packages, "app").unwrap().libs,
        vec!["webkitgtk_4_1", "libsoup_3"]
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("invalid library attribute"))
    );
}

#[test]
fn libs_on_a_non_prebuilt_package_are_ignored_with_a_warning() {
    // `libs` feeds an autoPatchelf that only the prebuilt backends run. Naming a `nix:` package
    // silently would leave the user believing a library set was applied somewhere.
    let r = resolve_no_plugins(raw_deb_libs("app", "nix:hello", &["webkitgtk_4_1"]), None);
    assert!(pkg(&r.packages, "app").unwrap().libs.is_empty());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("libs") && w.contains("prebuilt"))
    );
}

#[test]
fn an_untrusted_project_cannot_repatch_a_trusted_apps_package() {
    // The `libs` half of the integrity-of-intent guard: an untrusted repo may not choose what a
    // trusted app's prebuilt package is patched against — that decides which store paths enter the
    // app's closure, so it is the same class of substitution as replacing the tool outright.
    let deb_table = |libs: &[&str]| {
        std::iter::once((
            "demo-desktop".to_string(),
            RawResolve {
                resolve: Vec::new(),
                libs: libs.iter().map(|s| s.to_string()).collect(),
            },
        ))
        .collect::<BTreeMap<_, _>>()
    };
    let mut global_app = raw_app(
        &["demo-desktop"],
        &[],
        &[],
        &[("demo-desktop", "deb:https://example.com/app.deb")],
        None,
    );
    global_app.deb = deb_table(&["gtk3"]);
    let mut project_app = raw_app(
        &["demo-desktop"],
        &[],
        &[],
        &[("demo-desktop", "deb:https://example.com/app.deb")],
        None,
    );
    project_app.deb = deb_table(&["attacker_lib"]);

    let r = resolve_no_plugins(
        raw_with_app("demo-app", global_app),
        Some((raw_with_app("demo-app", project_app), TrustState::Untrusted)),
    );
    let app = &r.apps["demo-app"];
    let p = app
        .packages
        .iter()
        .find(|p| p.name == "demo-desktop")
        .expect("the app's package survives");
    assert_eq!(p.libs, vec!["gtk3"], "the trusted library set must stand");
    assert!(
        app.warnings
            .iter()
            .any(|w| w.contains("libs") && w.contains("trusted"))
    );
}

#[test]
fn libs_naming_no_package_at_all_are_ignored_with_a_warning() {
    let mut raw = RawConfig::default();
    raw.deb.insert(
        "ghost".to_string(),
        RawResolve {
            resolve: Vec::new(),
            libs: vec!["webkitgtk_4_1".to_string()],
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "ghost").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("ghost") && w.contains("[packages]"))
    );
}

#[test]
fn an_orphan_deb_sentinel_is_ignored_with_a_warning() {
    // A `<name> = "deb:resolve"` with no `[deb.<name>]` table can never resolve.
    let r = resolve_no_plugins(raw_packages(&[("lonely", DEB_RESOLVE_SENTINEL)]), None);
    assert!(pkg(&r.packages, "lonely").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("lonely") && w.contains("[deb.lonely]"))
    );
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
    // Trust is recorded, not enforced, at resolve: the launcher's admitted-resolver list is
    // trusted-only, so it withholds this one and NEVER runs its command, like the direct
    // `deb:` form.
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
            libs: Vec::new(),
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
            libs: Vec::new(),
        },
    );
    let r = resolve_no_plugins(raw, None);
    assert!(pkg(&r.packages, "orphan").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("orphan") && w.contains("[packages]"))
    );
}

#[test]
fn an_orphan_appimage_sentinel_is_ignored_with_a_warning() {
    // A `<name> = "appimage:resolve"` with no `[appimage.<name>]` table can never resolve.
    let r = resolve_no_plugins(raw_packages(&[("lonely", APPIMAGE_RESOLVE_SENTINEL)]), None);
    assert!(pkg(&r.packages, "lonely").is_none());
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("lonely") && w.contains("[appimage.lonely]"))
    );
}

#[test]
fn an_untrusted_projects_appimage_resolve_is_stamped_untrusted() {
    // Trust is recorded, not enforced, at resolve: the launcher's admitted-resolver list is
    // trusted-only, so it withholds this one and NEVER runs its command, like the direct
    // `appimage:` form.
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
        libs: Vec::new(),
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
    // The four after the quote are the ones that matter to the `--expr` the unfree provisioning
    // branch interpolates into: a brace ends the attribute set being spliced, a backslash escapes
    // inside a nix string, and a newline ends the line the expression is written on. Pinned here
    // because this charset is the whole barrier on that path.
    for a in [
        "", "a b", "a#b", "a;b", "a$b", "a\"b", "a{b", "a}b", "a\\b", "a\nb", "a'b", "a(b",
    ] {
        assert!(!is_valid_attr(a), "{a:?} should be rejected");
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
    // the default (or the global posture) stands. What it falls back *to* is the whole point of
    // the built-in default: the project asking to isolate itself is refused, and what it gets is
    // the filtering allowlist, not the open host network its own declaration was never trusted
    // to leave behind.
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(RawConfig::default(), Some((raw_network("none"), state)));
        assert_eq!(
            r.network,
            NetworkPolicy::default(),
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
    // a typo must not silently leave the network in the wrong posture: the value is dropped, and
    // what stands is the built-in default, so `offline` costs its author reach rather than
    // confinement.
    let r = resolve_no_plugins(raw_network("offline"), None);
    assert_eq!(r.network, NetworkPolicy::default());
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
    assert!(
        resolve_no_plugins(RawConfig::default(), None)
            .forward
            .is_empty()
    );
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
        same_forwards(&[1455, 8080]),
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
            same_forwards(&[1455]),
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
    assert_eq!(r.forward, same_forwards(&[1455]));
    assert!(r.warnings.iter().any(|w| w.contains("forward")));
}

#[test]
fn a_remap_moves_the_host_side_and_leaves_the_cage_side_alone() {
    // The remap form parses into the two distinct ports it names — the whole point of the syntax.
    let r = resolve_no_plugins(
        raw_forward_entries(&[RawForward::Remap("9200:9119".into())]),
        None,
    );
    assert_eq!(
        r.forward,
        vec![ForwardPort {
            host: 9200,
            cage: 9119
        }]
    );
    assert!(r.warnings.is_empty());
}

#[test]
fn a_trusted_project_remap_moves_a_global_forward_instead_of_adding_one() {
    // The load-bearing property. A global (or an app profile) publishes the caged service on the
    // port it listens on; a higher layer that names the SAME cage port is not asking for a second
    // hole, it is saying where that one service should answer from. Union by cage port, so the
    // global's 9119 host binding is replaced rather than kept alongside — which is what makes the
    // remap resolve a host-port collision instead of adding to it.
    let r = resolve_no_plugins(
        raw_forward(&[9119]),
        Some((
            raw_forward_entries(&[RawForward::Remap("9200:9119".into())]),
            TrustState::Trusted,
        )),
    );
    assert_eq!(
        r.forward,
        vec![ForwardPort {
            host: 9200,
            cage: 9119
        }],
        "a remap of an already-forwarded cage port moves it, never doubles it"
    );
    assert!(
        !r.forward.iter().any(|f| f.host == 9119),
        "the replaced host port must not stay bound — that would leave the collision in place"
    );
}

#[test]
fn a_layer_may_move_a_forward_but_never_close_one() {
    // The invariant the additive model exists for, restated for the keyed merge: whatever a higher
    // layer says, every cage port a lower layer published is still published afterwards. A layer
    // changes where a forward answers; it cannot make one disappear.
    let r = resolve_no_plugins(
        raw_forward(&[9119, 4096]),
        Some((
            raw_forward_entries(&[
                RawForward::Remap("9200:9119".into()),
                RawForward::Port(3080),
            ]),
            TrustState::Trusted,
        )),
    );
    let cage_ports: Vec<u16> = r.forward.iter().map(|f| f.cage).collect();
    assert_eq!(
        cage_ports,
        vec![3080, 4096, 9119],
        "every lower-layer cage port survives, and the higher layer's is added"
    );
    assert_eq!(
        r.forward.iter().find(|f| f.cage == 9119).map(|f| f.host),
        Some(9200),
        "the remapped one answers from the higher layer's host port"
    );
    assert_eq!(
        r.forward.iter().find(|f| f.cage == 4096).map(|f| f.host),
        Some(4096),
        "an untouched forward keeps its own host port"
    );
}

#[test]
fn one_list_naming_a_cage_port_twice_keeps_the_last_and_warns() {
    // Not the layering case: one author wrote the same forward twice. Keeping both would wire two
    // in-cage socats onto one socket path, where the second loses the race and its host port
    // answers into nothing — silently. Last wins, and the dropped host port is named.
    let r = resolve_no_plugins(
        raw_forward_entries(&[
            RawForward::Remap("9200:9119".into()),
            RawForward::Remap("9300:9119".into()),
        ]),
        None,
    );
    assert_eq!(
        r.forward,
        vec![ForwardPort {
            host: 9300,
            cage: 9119
        }]
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("9119") && w.contains("9300") && w.contains("9200")),
        "the warning must name the cage port and both host ports: {:?}",
        r.warnings
    );
}

#[test]
fn a_malformed_remap_is_dropped_with_a_warning_and_the_rest_survives() {
    // A config file is a collection: one bad entry warns and is skipped, it never voids the layer.
    // Each rejected form is listed separately, because each is a different mistake to explain.
    for bad in [
        "9200:9119:8787", // more than one `:`
        "nope:9119",      // host side is not a port
        "9200:nope",      // cage side is not a port
        "9200:0",         // zero is not a real port, on either side
        "0:9119",
        "9200", // a port written as a string is not a remap
        ":9119",
        "9200:",
        "",
    ] {
        let r = resolve_no_plugins(
            raw_forward_entries(&[RawForward::Remap(bad.into()), RawForward::Port(4096)]),
            None,
        );
        assert_eq!(
            r.forward,
            same_forwards(&[4096]),
            "`{bad}` must be dropped and the valid entry kept"
        );
        assert!(
            r.warnings.iter().any(|w| w.contains("forward")),
            "`{bad}` must warn"
        );
    }
}

#[test]
fn a_same_port_forward_serializes_as_the_integer_it_was_written_as() {
    // The round-trip rule, asserted on the EMITTED bytes: a bare port must not come back out as
    // `"9119:9119"`. `sbx config --json` is read by things that parsed integers before this field
    // learned a second form, and an entry that never remapped must not change shape under them.
    let same = serde_json::to_string(&ForwardPort::same(9119)).unwrap();
    assert_eq!(same, "9119");
    let remap = serde_json::to_string(&ForwardPort {
        host: 9200,
        cage: 9119,
    })
    .unwrap();
    assert_eq!(remap, "\"9200:9119\"");
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
    assert!(
        resolve_no_plugins(RawConfig::default(), None)
            .devices
            .is_empty()
    );
}

/// A `RawConfig` declaring an `[fs]` table carrying content-scan patterns.
fn raw_fs_scan(scan: &[&str], scan_max_kb: Option<u64>) -> RawConfig {
    RawConfig {
        fs: Some(schema::RawFs {
            rest: Default::default(),
            scan: scan.iter().map(|s| s.to_string()).collect(),
            scan_max_kb,
            ..Default::default()
        }),
        ..RawConfig::default()
    }
}

#[test]
fn a_scan_pattern_that_is_not_a_regex_is_dropped_and_says_what_is_lost() {
    let r = resolve_no_plugins(
        raw_fs_scan(&[r"sk-[A-Za-z0-9]{20,}", "(unclosed"], None),
        None,
    );
    assert_eq!(
        r.fs.scan,
        vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        "the valid pattern survives its neighbour's failure"
    );
    let w = r
        .warnings
        .iter()
        .find(|w| w.contains("(unclosed"))
        .unwrap_or_else(|| panic!("no warning names the broken pattern: {:?}", r.warnings));
    assert!(
        w.contains("no file is closed"),
        "the warning must say what protection is lost, not merely that a line was ignored: {w}"
    );
}

/// A `--config` blob carrying nothing but a content scan must reach the launch.
///
/// It did not: the override site asked `is_empty`, which answers "are there mounts to lay down",
/// and a scan lays down none — so the whole table was dropped after its own validation had already
/// printed warnings about it. Measured on the shipped binary, same project each time: `[fs] deny`
/// through `--config` refused the file (rc=1), `[fs] scan` through `--config` did not (rc=0), the
/// same scan in a `.sbx.toml` did, and adding an unrelated `deny` to the blob made the scan work
/// again — which is what named `is_empty` as the cause rather than the table or the layering.
#[test]
fn a_one_shot_override_carrying_only_a_scan_still_closes_the_file() {
    let resolved = with_override(
        resolve_no_plugins(RawConfig::default(), None),
        raw_fs_scan(&[r"sk-[A-Za-z0-9]{20,}"], Some(64)),
    );
    assert_eq!(
        resolved.fs.scan,
        vec![r"sk-[A-Za-z0-9]{20,}".to_string()],
        "an override that closes files by content may not be dropped for laying down no mount"
    );
    assert_eq!(resolved.fs.scan_max_kb, Some(64));
    assert_eq!(
        resolved.fs_origin,
        Provenance::Override,
        "and the invoker's word must be visible as such in `config show`"
    );
}

#[test]
fn a_scan_ceiling_of_zero_is_refused_rather_than_obeyed() {
    let r = resolve_no_plugins(raw_fs_scan(&[r"sk-[A-Za-z0-9]{20,}"], Some(0)), None);
    assert_eq!(
        r.fs.scan_max_kb, None,
        "a ceiling of zero must fall back to the built-in one: obeying it would read nothing and \
         call every file clean while `config show` still listed a scan"
    );
    assert!(
        r.warnings.iter().any(|w| w.contains("scan_max_kb = 0")),
        "the refusal must be visible: {:?}",
        r.warnings
    );
}

#[test]
fn scan_patterns_union_across_layers_and_the_tighter_ceiling_wins() {
    let mut base = super::fspolicy::FsPolicy {
        scan: vec!["a".into()],
        scan_max_kb: Some(512),
        ..Default::default()
    };
    base.union(super::fspolicy::FsPolicy {
        scan: vec!["a".into(), "b".into()],
        scan_max_kb: Some(64),
        ..Default::default()
    });
    assert_eq!(
        base.scan,
        vec!["a".to_string(), "b".to_string()],
        "a layer adds shapes and never removes one below it"
    );
    assert_eq!(
        base.scan_max_kb,
        Some(64),
        "the tighter ceiling wins: a layer raising it would widen what an inner one narrowed"
    );
}

fn raw_fs(deny: &[&str], readonly: &[&str]) -> RawConfig {
    RawConfig {
        fs: Some(schema::RawFs {
            rest: Default::default(),
            deny: deny.iter().map(|s| s.to_string()).collect(),
            readonly: readonly.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }),
        ..RawConfig::default()
    }
}

#[test]
fn an_untrusted_projects_fs_masks_are_honored() {
    // The property that separates `[fs]` from every other security table: it can only *close*
    // paths, so an untrusted project declaring one gains nothing it could turn on the user — while
    // dropping it would leave a file the project asked to close wide open. Honored from both
    // untrusted states, and unioned onto whatever the global layer closed.
    for state in [TrustState::Untrusted, TrustState::Changed] {
        let r = resolve_no_plugins(
            raw_fs(&["global.key"], &[]),
            Some((raw_fs(&["local.key"], &["Cargo.lock"]), state)),
        );
        assert_eq!(
            r.fs.deny,
            vec!["global.key".to_string(), "local.key".to_string()],
            "an untrusted project closes its own files; the global mask survives"
        );
        assert_eq!(r.fs.readonly, vec!["Cargo.lock".to_string()]);
        assert_eq!(r.fs_origin, Provenance::Project);
        assert!(
            !r.warnings.iter().any(|w| w.contains("[fs]")),
            "nothing was dropped, so nothing warns: {:?}",
            r.warnings
        );
    }
}

#[test]
fn a_project_can_never_reopen_what_the_global_layer_closed() {
    // The union direction is the whole safety story: there is no syntax for removal, so a project
    // repeating the global entry changes nothing and adding one only closes more.
    let r = resolve_no_plugins(
        raw_fs(&["shared.key"], &["Cargo.lock"]),
        Some((raw_fs(&["shared.key"], &[]), TrustState::Untrusted)),
    );
    assert_eq!(r.fs.deny, vec!["shared.key".to_string()], "deduped");
    assert_eq!(
        r.fs.readonly,
        vec!["Cargo.lock".to_string()],
        "still closed"
    );
}

#[test]
fn a_refused_fs_entry_is_dropped_with_a_warning_that_says_the_path_stays_open() {
    // A dropped mask fails *open* — the file stays readable — so the warning has to say so rather
    // than read like a tidy-up note.
    let r = resolve_no_plugins(
        raw_fs(&["**/*.pem", "/etc/shadow", "../up.key"], &["ok.txt"]),
        None,
    );
    assert!(
        r.fs.deny.is_empty(),
        "every bad entry dropped: {:?}",
        r.fs.deny
    );
    assert_eq!(
        r.fs.readonly,
        vec!["ok.txt".to_string()],
        "the good one stays"
    );
    let warned: Vec<&String> = r.warnings.iter().filter(|w| w.contains("[fs]")).collect();
    assert_eq!(warned.len(), 3, "one warning per refused entry: {warned:?}");
    assert!(
        warned.iter().all(|w| w.contains("stays open to the cage")),
        "each warning says what the drop costs: {warned:?}"
    );
}

#[test]
fn an_apps_fs_masks_union_onto_the_baseline() {
    // An app closes more of the project for its own cage, and can never reopen what the baseline
    // closed. Ungated like the baseline table.
    let global = raw_with_app(
        "demo-app",
        RawApp {
            fs: Some(schema::RawFs {
                rest: Default::default(),
                deny: vec!["app-only.key".into()],
                readonly: vec![],
                ..Default::default()
            }),
            ..raw_app(&["demo-app"], &[], &[], &[], None)
        },
    );
    let r = resolve_no_plugins(global, None);
    assert_eq!(r.apps["demo-app"].fs.deny, vec!["app-only.key".to_string()]);
    assert_eq!(r.apps["demo-app"].fs_origin, Provenance::Global);
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("[devices] allow") && w.contains("/etc/shadow"))
    );
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
        // The built-in default is a `deny` allowlist too, so equality against it — rather than a
        // `matches!` on the variant — is what proves the *rules* were dropped: the resolved policy
        // carries no allow entry, and `github.com` reaches nothing the built-in set does not.
        assert_eq!(
            r.network,
            NetworkPolicy::default(),
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("ignoring allow entry"))
    );
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
                websocket_secret: None,
                capture_max_kb: None,
                groups: Default::default(),
                rest: Default::default(),
                mode: Some("bogus".into()),
                allow: vec![],
                deny: vec![],
                ask_timeout: None,
                ask_notice: None,
                stats: None,
                default_methods: None,
                dns_cache_ttl: None,
                pool: None,
                idle_timeout: None,
                max_connections: None,
                body_max_mb: None,
                ca_roots: None,
            })),
            ..RawConfig::default()
        },
        None,
    );
    assert_eq!(r.network, NetworkPolicy::default());
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
            sign: None,
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
        sign: None,
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

/// A config carrying nothing but a zone, for the layering test below.
fn zoned(zone: &str) -> RawConfig {
    RawConfig {
        timezone: Some(zone.to_string()),
        ..Default::default()
    }
}

#[test]
fn the_timezone_layers_from_any_source_and_a_bad_name_leaves_the_zone_in_effect() {
    // `timezone` is a **free** field, so this asserts the property the security postures beside it
    // do NOT have: an *untrusted* project's zone applies. The reason is in the schema — the value
    // reads nothing from the host, and `[env] TZ` is already free — so a future gate on this field
    // has to break this test deliberately.
    let r = resolve_no_plugins(zoned("Europe/Paris"), None);
    assert_eq!(r.timezone.as_deref(), Some("Europe/Paris"));
    assert_eq!(r.timezone_origin, Provenance::Global);

    let r = resolve_no_plugins(
        zoned("Europe/Paris"),
        Some((zoned("Asia/Tokyo"), TrustState::Untrusted)),
    );
    assert_eq!(r.timezone.as_deref(), Some("Asia/Tokyo"));
    assert_eq!(r.timezone_origin, Provenance::Project);

    // No layer named one: the field stays unset, and it is the *launcher* that turns that into UTC
    // — so a test reading `Some("UTC")` here would be asserting the wrong layer's job.
    let r = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(r.timezone, None);
    assert_eq!(r.timezone_origin, Provenance::Default);

    // A value that is not a zone name is dropped with a warning and the layer below stands. Each of
    // these would otherwise become a link target under the zone database: the traversal and the
    // absolute path are the two that matter, the rest pin the charset.
    for bad in [
        "../../etc/shadow",
        "/etc/shadow",
        "Europe/../etc",
        "Europe/Paris/",
        "",
        "Europe/Paris\n",
        "Europe Paris",
        "Europe/Paris;rm -rf /",
    ] {
        let r = resolve_no_plugins(
            zoned("Europe/Paris"),
            Some((zoned(bad), TrustState::Trusted)),
        );
        assert_eq!(
            r.timezone.as_deref(),
            Some("Europe/Paris"),
            "{bad:?} must not take effect"
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("not an IANA zone name")),
            "{bad:?} must say why it was dropped: {:?}",
            r.warnings
        );
    }

    // And the names that ARE zones, including the awkward ones the charset has to admit: three
    // segments, a `+`, and a hyphen.
    for good in [
        "UTC",
        "Europe/Paris",
        "America/Argentina/Salta",
        "Etc/GMT+3",
        "America/Port-au-Prince",
    ] {
        let r = resolve_no_plugins(
            RawConfig::default(),
            Some((zoned(good), TrustState::Trusted)),
        );
        assert_eq!(r.timezone.as_deref(), Some(good), "{good} is a zone name");
        assert!(
            r.warnings.is_empty(),
            "{good} must not warn: {:?}",
            r.warnings
        );
    }

    // The one-shot override, the last layer and the one the guide tells a reader to use. The
    // overlay fold that carries it is a hand-written field list, and its own comment records having
    // dropped a field in silence three times — the compiler catches an unnamed field there, nothing
    // catches a named one that is never applied.
    let base = resolve_no_plugins(zoned("Europe/Paris"), None);
    let r = with_override(base, zoned("Asia/Tokyo"));
    assert_eq!(r.timezone.as_deref(), Some("Asia/Tokyo"));
    assert_eq!(r.timezone_origin, Provenance::Override);

    // And a bad one is not fatal here, unlike a scalar *security* posture: it warns, and the layer
    // below stands, because falling back to a resolvable zone is the fail-closed direction.
    let base = resolve_no_plugins(zoned("Europe/Paris"), None);
    let r = with_override(base, zoned("../../etc/shadow"));
    assert_eq!(r.timezone.as_deref(), Some("Europe/Paris"));
    assert_eq!(r.timezone_origin, Provenance::Global);
}

#[test]
fn a_baseline_only_field_written_under_an_app_says_so_instead_of_vanishing() {
    // The motivating case is `timezone`, and it is the shape of the problem rather than one field:
    // an app profile is a subset of the baseline schema, so a key a reader met in the guide can be
    // real *and* have no effect here. Before this, serde dropped it and the only symptom was the
    // value not applying.
    let global: RawConfig = toml::from_str(
        "[app.demo]\ncmd = \"demo\"\ntimezone = \"Europe/Paris\"\nmemory_maxx = \"8G\"\n",
    )
    .unwrap();
    let r = resolve_no_plugins(global, None);
    let app = &r.apps["demo"];
    for key in ["timezone", "memory_maxx"] {
        assert!(
            app.warnings.iter().any(|w| w.contains(key)),
            "`{key}` must be named, not dropped in silence: {:?}",
            app.warnings
        );
    }
    // And the baseline is untouched by it: a zone written in the wrong place sets no zone.
    assert_eq!(r.timezone, None);

    // The keys an app *does* know stay silent, or the message would be noise on every profile.
    let global: RawConfig =
        toml::from_str("[app.demo]\ncmd = \"demo\"\ngui = \"wayland\"\nhome_scope = \"project\"\n")
            .unwrap();
    let r = resolve_no_plugins(global, None);
    assert!(
        r.apps["demo"].warnings.is_empty(),
        "a well-spelled profile must not warn: {:?}",
        r.apps["demo"].warnings
    );
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
fn a_one_shot_forward_remap_moves_the_resolved_host_port() {
    // The headline path, end to end: a profile publishes its dashboard on the port the caged
    // server listens on, that port is taken on this machine, and `--forward 9200:9119` republishes
    // the SAME caged service on a free one for this launch. It has to *move* the forward, not add
    // a second: adding would leave 9119 bound and the launch would still fail closed on it.
    let r = with_override(
        resolve_no_plugins(raw_forward(&[9119]), None),
        raw_forward_entries(&[RawForward::Remap("9200:9119".into())]),
    );
    assert_eq!(
        r.forward,
        vec![ForwardPort {
            host: 9200,
            cage: 9119
        }],
        "the override moves the forward rather than opening a second hole"
    );
    assert_eq!(r.forward_origin, Provenance::Override);

    // And the other half of the keyed rule: a cage port the config does not forward is *added*,
    // leaving the config's own forwards where they were.
    let r = with_override(
        resolve_no_plugins(raw_forward(&[9119]), None),
        raw_forward_entries(&[RawForward::Remap("3080:4096".into())]),
    );
    assert_eq!(
        r.forward,
        vec![
            ForwardPort {
                host: 3080,
                cage: 4096
            },
            ForwardPort::same(9119),
        ],
        "an override naming an unforwarded cage port adds it and disturbs nothing"
    );
}

#[test]
fn a_one_shot_override_resolves_global_egress_groups() {
    // An override is the invoker's word, and it outranks every config layer — so it could always
    // have written a group's hosts out by hand. What it gains here is the *name*: `@ci` on a launch
    // line reads against the same vocabulary `sbx net groups` prints, which is what makes a
    // one-shot widening auditable afterwards. The vocabulary still comes from the global config;
    // the override defines nothing.
    //
    // Several references in one list, mixed with a literal host, because that is how a launch line
    // is actually written: each entry is expanded on its own, so the list is the union of every
    // group it names plus whatever it spells out.
    let mut global = RawConfig::default();
    declare_groups(
        &mut global,
        &[
            ("ci", &["{*} a.example.com:443", "{*} b.example.com:443"]),
            ("mirror", &["{*} c.example.org:443"]),
        ],
    );
    let base = resolve_no_plugins(global, None);
    let r = with_override(
        base,
        RawConfig {
            network: Some(net_field(
                "deny",
                &["@ci", "@mirror", "{*} direct.example.net:443"],
                &[],
            )),
            ..RawConfig::default()
        },
    );
    let NetworkPolicy::Allowlist(policy) = &r.network else {
        panic!("a filtering posture: {:?}", r.network);
    };
    let hosts: Vec<String> = policy.allow_rules().iter().map(|r| r.to_string()).collect();
    for host in [
        "a.example.com",
        "b.example.com",
        "c.example.org",
        "direct.example.net",
    ] {
        assert!(
            hosts.iter().any(|h| h.contains(host)),
            "the list must carry {host}: {hosts:?}"
        );
    }
}

#[test]
fn one_undefined_reference_does_not_take_its_neighbours_down() {
    // The drop is per entry, not per list: a typo among several references must cost exactly the
    // group it names. Losing the whole list would be the fail-open direction on a `deny`, and on an
    // `allow` it would silently close doors the launch asked for by name.
    let mut global = RawConfig::default();
    declare_groups(&mut global, &[("ci", &["{*} a.example.com:443"])]);
    let base = resolve_no_plugins(global, None);
    let r = with_override(
        base,
        RawConfig {
            network: Some(net_field("deny", &["@nope", "@ci"], &[])),
            ..RawConfig::default()
        },
    );
    let NetworkPolicy::Allowlist(policy) = &r.network else {
        panic!("a filtering posture: {:?}", r.network);
    };
    let hosts: Vec<String> = policy.allow_rules().iter().map(|r| r.to_string()).collect();
    assert!(
        hosts.iter().any(|h| h.contains("a.example.com")),
        "the defined group survives its neighbour: {hosts:?}"
    );
    assert!(
        r.warnings.iter().any(|w| w.contains("@nope")),
        "and the miss is still named: {:?}",
        r.warnings
    );
}

#[test]
fn an_override_reference_to_an_undefined_group_is_dropped_with_a_warning() {
    // The other half of the contract: the override reads the global vocabulary, it does not get a
    // private one. A name no group defines is dropped and named, so an `allow` list that meant to
    // open something ends up opening nothing rather than opening it by accident.
    let base = resolve_no_plugins(RawConfig::default(), None);
    let r = with_override(
        base,
        RawConfig {
            network: Some(net_field("deny", &["@nope"], &[])),
            ..RawConfig::default()
        },
    );
    assert!(
        r.warnings.iter().any(|w| w.contains("@nope")),
        "the undefined reference must be named: {:?}",
        r.warnings
    );
    let NetworkPolicy::Allowlist(policy) = &r.network else {
        panic!("a filtering posture: {:?}", r.network);
    };
    assert!(
        policy.allow_rules().is_empty(),
        "and nothing opened: {:?}",
        policy.allow_rules()
    );
}

/// The one-shot plane rebuilds the policy exactly as a config layer does, so it gives up the same
/// settings — and says so under its own source label. It is the plane where a reader is least
/// likely to expect it: `--config '[network] allow=[…]'` reads as adding one rule for one launch.
#[test]
fn a_one_shot_override_says_what_its_network_table_gives_up() {
    let table = |capture: Option<&str>, allow: &[&str]| {
        NetworkField::Table(NetworkTable {
            mode: Some("deny".to_string()),
            allow: allow.iter().map(|h| h.to_string()).collect(),
            capture: capture.map(str::to_string),
            mute: vec![],
            http2: vec![],
            capture_max_kb: None,
            websocket_secret: None,
            groups: Default::default(),
            rest: Default::default(),
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: None,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
        })
    };
    let with_capture = RawConfig {
        network: Some(table(Some("bodies"), &[])),
        ..RawConfig::default()
    };
    let one_rule = RawConfig {
        network: Some(table(None, &["example.com"])),
        ..RawConfig::default()
    };
    let applied = with_override(resolve_no_plugins(with_capture, None), one_rule);
    let said = applied
        .warnings
        .iter()
        .find(|w| w.contains("replaces the layer below"))
        .unwrap_or_else(|| panic!("the override plane says it too: {:?}", applied.warnings));
    assert!(said.starts_with("override: "), "{said}");
    assert!(
        said.contains("setting it carried does not apply here: `capture`"),
        "{said}"
    );
}

#[test]
fn a_set_but_invalid_override_security_value_is_a_hard_error_and_mutates_nothing() {
    // The fail-closed contract on the security half: a typo'd `network` value has no safe
    // fallback — it must be a hard error, never a silent revert to the (possibly wider) baseline.
    // The baseline is declared `shared` rather than left to the (filtering) built-in default, so a
    // silent revert would be visible: reverting to the default would *narrow* the posture, and the
    // contract is that nothing moves at all.
    let mut resolved = resolve_no_plugins(raw_network("shared"), None);
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
    assert_eq!(resolved.network_origin, Provenance::Global);
}

/// A `--config` blob may move the redaction floor for one launch (trusted by invocation), and an
/// unusable value is fatal rather than a silent revert: an override that meant to move the floor
/// and instead left the baseline's would watch the launch to a depth nobody chose.
#[test]
fn an_override_redaction_floor_applies_and_a_zero_is_a_hard_error() {
    let redact = |min_len: u64| RawConfig {
        redact: Some(schema::RawRedact {
            min_len: Some(min_len),
            rest: Default::default(),
        }),
        ..RawConfig::default()
    };

    let applied = with_override(resolve_no_plugins(redact(16), None), redact(4));
    assert_eq!(applied.redact_min_len, 4);
    assert_eq!(applied.redact_min_len_origin, Provenance::Override);

    let mut resolved = resolve_no_plugins(redact(16), None);
    let errs = resolved
        .apply_override(Override::for_test(redact(0)))
        .unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("redact.min_len")),
        "the error names the offending field: {errs:?}"
    );
    assert_eq!(resolved.redact_min_len, 16, "and nothing was applied");
    assert_eq!(resolved.redact_min_len_origin, Provenance::Global);
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["github.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats,
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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

/// The floor a needle must clear, its default, and the gate: raising it drops credentials out of
/// the tripwires, so an untrusted project may not touch it.
#[test]
fn the_redaction_floor_defaults_to_eight_and_is_gated_trusted_only() {
    let redact = |min_len: u64| RawConfig {
        redact: Some(schema::RawRedact {
            min_len: Some(min_len),
            rest: Default::default(),
        }),
        ..RawConfig::default()
    };

    // Nothing set → the built-in floor, and `sbx config` says so rather than naming a layer.
    let base = resolve_no_plugins(RawConfig::default(), None);
    assert_eq!(base.redact_min_len, 8);
    assert_eq!(base.redact_min_len_origin, Provenance::Default);

    // Global (trusted by location) → honored, in both directions.
    let lowered = resolve_no_plugins(redact(4), None);
    assert_eq!(lowered.redact_min_len, 4);
    assert_eq!(lowered.redact_min_len_origin, Provenance::Global);
    assert_eq!(resolve_no_plugins(redact(32), None).redact_min_len, 32);

    // A TRUSTED project may set its own floor, and it replaces the global one.
    let project = resolve_no_plugins(redact(4), Some((redact(20), TrustState::Trusted)));
    assert_eq!(project.redact_min_len, 20);
    assert_eq!(project.redact_min_len_origin, Provenance::Project);

    // An UNTRUSTED project's floor is dropped: raising it is how a project would stop sbx watching
    // its own egress for the credentials sbx injects on its behalf.
    let untrusted = resolve_no_plugins(redact(4), Some((redact(64), TrustState::Untrusted)));
    assert_eq!(untrusted.redact_min_len, 4, "the global floor stands");
    assert!(
        untrusted.warnings.iter().any(|w| w.contains("[redact]")),
        "the drop is named, never silent: {:?}",
        untrusted.warnings
    );
}

/// Zero is not a stricter floor but a meaningless one — a zero-length needle matches at every
/// offset — so it is refused and the floor in effect stands.
#[test]
fn a_zero_redaction_floor_is_refused_and_the_layer_below_stands() {
    let redact = |min_len: u64| RawConfig {
        redact: Some(schema::RawRedact {
            min_len: Some(min_len),
            rest: Default::default(),
        }),
        ..RawConfig::default()
    };

    let global = resolve_no_plugins(redact(0), None);
    assert_eq!(global.redact_min_len, 8, "the built-in floor is kept");
    assert_eq!(global.redact_min_len_origin, Provenance::Default);
    assert!(
        global.warnings.iter().any(|w| w.contains("min_len")),
        "and the refusal is stated: {:?}",
        global.warnings
    );

    // A trusted project's zero leaves the global floor in place, not the built-in one.
    let over_global = resolve_no_plugins(redact(16), Some((redact(0), TrustState::Trusted)));
    assert_eq!(over_global.redact_min_len, 16);
    assert_eq!(over_global.redact_min_len_origin, Provenance::Global);
}

/// A misspelled key inside `[redact]` is a floor the author asked for and did not get, which is the
/// case where silence costs the most.
#[test]
fn an_unknown_key_under_redact_is_named() {
    let raw = RawConfig {
        redact: Some(schema::RawRedact {
            min_len: None,
            rest: [("min_length".to_string(), schema::RawIgnored)]
                .into_iter()
                .collect(),
        }),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(raw, None);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("min_length") && w.contains("[redact]")),
        "the unknown key is named under its table: {:?}",
        r.warnings
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
            websocket_secret: None,
            capture_max_kb: None,
            groups: Default::default(),
            rest: Default::default(),
            mode: Some("deny".into()),
            allow: vec!["api.example.com".into()],
            deny: vec![],
            ask_timeout: None,
            ask_notice: None,
            stats: Some(false),
            default_methods: None,
            dns_cache_ttl: None,
            pool: None,
            idle_timeout: None,
            max_connections: None,
            body_max_mb: None,
            ca_roots: None,
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
        sign: None,
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
        sign: None,
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
        resolver: BTreeMap::new(),
    }
}

/// A raw `[secret.defaults]` table binding one plugin scheme, `locator` unset meaning the
/// identity — for the plugin-expansion tests.
fn raw_plugin_defaults(order: &[&str], scheme: &str, locator: Option<&str>) -> RawSecretDefaults {
    let mut resolver = BTreeMap::new();
    resolver.insert(
        scheme.to_string(),
        RawResolverDefaults {
            locator: locator.map(str::to_string),
        },
    );
    RawSecretDefaults {
        resolver,
        ..raw_defaults(order, None, None, None)
    }
}

/// A trusted-shaped network allowlist for the given hosts.
fn allowlist_net(allow: &[&str]) -> Option<NetworkField> {
    Some(NetworkField::Table(NetworkTable {
        mute: vec![],
        http2: vec![],
        capture: None,
        websocket_secret: None,
        capture_max_kb: None,
        groups: Default::default(),
        rest: Default::default(),
        mode: Some("deny".into()),
        allow: allow.iter().map(|s| s.to_string()).collect(),
        deny: vec![],
        ask_timeout: None,
        ask_notice: None,
        stats: None,
        default_methods: None,
        dns_cache_ttl: None,
        pool: None,
        idle_timeout: None,
        max_connections: None,
        body_max_mb: None,
        ca_roots: None,
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
        host: Default::default(),
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

/// [`validate_host_secret`] against both a registry and a defaults table, for the terse plugin
/// expansions (where the binding and the installed plugin have to meet).
fn vhs_with_defaults(
    secret: RawHostSecret,
    defaults: &SecretDefaults,
    plugins: &PluginRegistry,
) -> Result<HeaderSecret, String> {
    validate_host_secret("api.github.com", secret, defaults, plugins)
}

/// A plugin declaring the variables it reads, so the `[plugin.<name>]` validation has something
/// to check a config against.
fn plugin_reading(
    scheme: &str,
    env: &[&str],
    env_paths: &[&str],
) -> crate::plugins::ResolverPlugin {
    let mut p = plugin(scheme);
    p.sandbox.allow_env = env.iter().map(|s| s.to_string()).collect();
    p.sandbox.allow_env_paths = env_paths.iter().map(|s| s.to_string()).collect();
    p
}

/// A config whose only content is one `[plugin.<name>]` table.
fn raw_plugin_table(name: &str, env: &[(&str, &str)]) -> RawConfig {
    raw_plugin_table_with(name, env, &[])
}

/// The same, with `programs` entries as well.
fn raw_plugin_table_with(name: &str, env: &[(&str, &str)], programs: &[(&str, &str)]) -> RawConfig {
    let mut cfg = raw(&[], &[]);
    cfg.plugin.insert(
        name.to_string(),
        crate::config::schema::RawPluginConfig {
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            programs: programs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        },
    );
    cfg
}

/// A secret whose single source is `<scheme>://x`, so a resolved config carries that plugin.
fn secret_using(scheme: &str) -> RawConfig {
    let mut cfg = raw(&[], &[]);
    let reff = format!("{scheme}://x");
    let sec = raw_secret_from(vec![reff.as_str()]);
    cfg.secret = Some(raw_secret_section(vec![(
        "api.example.com".to_string(),
        sec,
    )]));
    cfg
}

#[test]
fn a_plugin_table_supplies_only_the_variables_the_manifest_reads() {
    let reg = PluginRegistry::with([plugin_reading("vault", &["VAULT_ADDR"], &["VAULT_CACERT"])]);
    let mut global = secret_using("vault");
    global.plugin = raw_plugin_table(
        "vault",
        &[
            ("VAULT_ADDR", "https://vault.example.com"),
            ("VAULT_CACERT", "/etc/ca/vault.pem"),
            ("VAULT_TOKEN_HELPER", "/usr/local/bin/helper"),
        ],
    )
    .plugin;
    let r = super::resolve(global, None, &reg);
    let host = match &r.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    // The two the manifest declares are supplied, in the order the config lists them.
    assert_eq!(
        host.env,
        vec![
            (
                "VAULT_ADDR".to_string(),
                "https://vault.example.com".to_string()
            ),
            ("VAULT_CACERT".to_string(), "/etc/ca/vault.pem".to_string()),
        ]
    );
    // The third is refused: a config may not put a variable the plugin does not read into the
    // environment of a binary that runs host-side on the plaintext path.
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("VAULT_TOKEN_HELPER") && w.contains("does not read")),
        "the refusal names the variable: {:?}",
        r.warnings
    );
}

#[test]
fn a_plugin_reached_only_from_a_task_still_gets_its_host_table() {
    let reg = PluginRegistry::with([plugin_reading("vault", &["VAULT_ADDR"], &[])]);
    // No `[secret]` at all: the only user of the plugin is a declared operation, which resolves
    // its credential host-side through the very same chain.
    let global: RawConfig = toml::from_str(
        r#"
        [plugin.vault]
        env = { VAULT_ADDR = "https://vault.example.com" }

        [task.q]
        description = "one"
        cmd = ["true"]

        [task.q.secret]
        TOKEN = "vault://x"
        "#,
    )
    .unwrap();
    let r = super::resolve(global, None, &reg);
    let host = match &r.tasks[0].secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    assert_eq!(
        host.env,
        vec![(
            "VAULT_ADDR".to_string(),
            "https://vault.example.com".to_string()
        )]
    );
    // And the table is not reported as naming nothing, which is the visible half of the same bug:
    // the name was correct, so a "check the spelling" warning would send the user looking for a
    // typo that is not there.
    assert!(
        !r.warnings.iter().any(|w| w.contains("no secret uses")),
        "the table matched a task, so nothing is unmatched: {:?}",
        r.warnings
    );
}

#[test]
fn a_plugin_table_supplies_a_package_only_for_a_program_the_manifest_runs() {
    let mut p = plugin_reading("vault", &[], &[]);
    p.sandbox.programs = vec!["vault".to_string()];
    let reg = PluginRegistry::with([p]);
    let mut global = secret_using("vault");
    global.plugin = raw_plugin_table_with(
        "vault",
        &[],
        &[("vault", "nix:vault"), ("curl", "nix:curl")],
    )
    .plugin;
    let r = super::resolve(global, None, &reg);
    let host = match &r.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    // The declared one is kept, with the `nix:` prefix stripped: what is stored is the attribute.
    assert_eq!(
        host.programs,
        vec![("vault".to_string(), "vault".to_string())]
    );
    // `curl` is refused. The manifest is the list of tools this resolver runs, and a launch binds
    // exactly those, so building anything else would be a package no plugin could ever invoke.
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("curl") && w.contains("does not run it")),
        "the refusal names the program: {:?}",
        r.warnings
    );
}

/// What follows `nix:` here reaches the `--expr` of the unfree provisioning branch, so it obeys the
/// rule `[packages]` already applies to the same syntax. The pair matters: a shell metacharacter is
/// dropped with its reason, and an ordinary attribute — dots, dashes, digits, the `+` of a C++
/// library — still goes through, because a guard that also refused those would be worse than the
/// hole it closes.
#[test]
fn a_plugin_table_refuses_an_attribute_that_is_not_one() {
    let mut p = plugin_reading("vault", &[], &[]);
    p.sandbox.programs = vec!["vault".to_string()];
    let reg = PluginRegistry::with([p]);

    let mut hostile = secret_using("vault");
    hostile.plugin =
        raw_plugin_table_with("vault", &[], &[("vault", "nix:vault\"; echo pwned; \"")]).plugin;
    let r = super::resolve(hostile, None, &reg);
    let host = match &r.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    assert!(
        host.programs.is_empty(),
        "nothing is supplied: {:?}",
        host.programs
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("is not a nix attribute")),
        "the refusal names the attribute and why: {:?}",
        r.warnings
    );

    let mut ordinary = secret_using("vault");
    ordinary.plugin =
        raw_plugin_table_with("vault", &[], &[("vault", "nix:python3Packages.hvac-1.2+x")]).plugin;
    let ok = super::resolve(ordinary, None, &reg);
    let host = match &ok.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    assert_eq!(
        host.programs,
        vec![(
            "vault".to_string(),
            "python3Packages.hvac-1.2+x".to_string()
        )],
        "an ordinary nixpkgs attribute must still be supplied"
    );
}

#[test]
fn a_plugin_table_refuses_every_backend_but_nix() {
    let mut p = plugin_reading("vault", &[], &[]);
    p.sandbox.programs = vec!["vault".to_string()];
    let reg = PluginRegistry::with([p]);
    let mut global = secret_using("vault");
    global.plugin =
        raw_plugin_table_with("vault", &[], &[("vault", "mise:aqua:hashicorp/vault")]).plugin;
    let r = super::resolve(global, None, &reg);
    let host = match &r.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    // `nix:` is the only backend that can be built host-side and project-independently at the
    // moment a plugin is installed; a `mise:` tool is equipped inside a cage that does not exist
    // here. Refusing by name is what keeps the field from reading as a general backend selector.
    assert!(
        host.programs.is_empty(),
        "nothing is supplied: {:?}",
        host.programs
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("mise:aqua:hashicorp/vault") && w.contains("nix:<attribute>")),
        "the refusal quotes the value and names the only accepted form: {:?}",
        r.warnings
    );
}

#[test]
fn an_untrusted_projects_plugin_table_is_dropped_and_named() {
    let reg = PluginRegistry::with([plugin_reading("vault", &["VAULT_ADDR"], &[])]);
    let project = raw_plugin_table("vault", &[("VAULT_ADDR", "https://attacker.example")]);
    let r = super::resolve(
        secret_using("vault"),
        Some((project, TrustState::Untrusted)),
        &reg,
    );
    let host = match &r.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    assert!(
        host.env.is_empty(),
        "an untrusted project supplies nothing: {:?}",
        host.env
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("[plugin.*]") && w.contains("vault")),
        "the drop is named: {:?}",
        r.warnings
    );
}

#[test]
fn a_trusted_projects_plugin_table_layers_over_the_global_one() {
    let reg = PluginRegistry::with([plugin_reading("vault", &["VAULT_ADDR"], &[])]);
    let mut global = secret_using("vault");
    global.plugin = raw_plugin_table("vault", &[("VAULT_ADDR", "https://global.example")]).plugin;
    let project = raw_plugin_table("vault", &[("VAULT_ADDR", "https://project.example")]);
    let r = super::resolve(global, Some((project, TrustState::Trusted)), &reg);
    let host = match &r.secrets[0].sources[0] {
        SecretSource::Plugin { plugin, .. } => &plugin.host,
        other => panic!("expected a plugin source, got {other:?}"),
    };
    // A hard-coded literal, not a value recomputed from the input: the project layer wins.
    assert_eq!(
        host.env,
        vec![(
            "VAULT_ADDR".to_string(),
            "https://project.example".to_string()
        )]
    );
}

#[test]
fn a_plugin_table_naming_no_installed_plugin_is_reported() {
    let reg = PluginRegistry::with([plugin_reading("vault", &["VAULT_ADDR"], &[])]);
    let mut global = secret_using("vault");
    global.plugin = raw_plugin_table("valut", &[("VAULT_ADDR", "https://x.example")]).plugin;
    let r = super::resolve(global, None, &reg);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("valut") && w.contains("no secret uses")),
        "a typo is named rather than left inert in silence: {:?}",
        r.warnings
    );
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
fn a_terse_key_pinned_to_a_plugin_scheme_resolves_through_it() {
    // With no binding declared, a plugin scheme expands to the key alone: `pass://tok`. That is
    // what a source addressed by host or by name wants, and it needs no table at all.
    let reg = PluginRegistry::with([plugin("pass")]);
    let s = validate_host_secret(
        "api.github.com",
        terse("tok@pass"),
        &SecretDefaults::default(),
        &reg,
    )
    .unwrap();
    match &s.sources[..] {
        [SecretSource::Plugin { plugin, locator }] => {
            assert_eq!(plugin.scheme, "pass");
            assert_eq!(locator, "tok");
        }
        other => panic!("expected one pass:// source, got {other:?}"),
    }
}

#[test]
fn a_terse_key_expands_through_a_plugin_locator_template() {
    // The template is what lets a source whose locator has a fixed part — a vault file, a folder —
    // be named once instead of in every entry.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let d = SecretDefaults::from_raw(&raw_plugin_defaults(
        &["keepassxc"],
        "keepassxc",
        Some("agents.kdbx/{key}#password"),
    ));
    let s = vhs_with_defaults(terse("github"), &d, &reg).unwrap();
    match &s.sources[..] {
        [SecretSource::Plugin { locator, .. }] => {
            assert_eq!(locator, "agents.kdbx/github#password");
        }
        other => panic!("expected one keepassxc:// source, got {other:?}"),
    }
}

#[test]
fn a_plugin_locator_template_that_never_writes_the_key_is_rejected() {
    // Every terse key would resolve the same secret, so one entry's credential would answer for
    // another's — silently, and only on the wire.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let d = SecretDefaults::from_raw(&raw_plugin_defaults(
        &["keepassxc"],
        "keepassxc",
        Some("agents.kdbx/shared"),
    ));
    let err = vhs_with_defaults(terse("github"), &d, &reg).unwrap_err();
    assert!(err.contains("never writes `{key}`"), "{err}");
}

#[test]
fn a_plugin_locator_template_with_an_unknown_placeholder_is_rejected() {
    // Passed through, it would reach the plugin's `argv[1]` as literal braces: a locator the user
    // believes carries a value and the plugin looks up verbatim.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let d = SecretDefaults::from_raw(&raw_plugin_defaults(
        &["keepassxc"],
        "keepassxc",
        Some("{host}/{key}"),
    ));
    let err = vhs_with_defaults(terse("github"), &d, &reg).unwrap_err();
    assert!(err.contains("{host}") && err.contains("{key}"), "{err}");
}

#[test]
fn a_plugin_locator_template_carrying_a_control_character_is_rejected() {
    // The expansion is not a shortcut around the ref validation: what a template builds is checked
    // exactly as a hand-written `from` ref is, so a newline from the config file cannot reach the
    // plugin's `argv[1]`.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let d = SecretDefaults::from_raw(&raw_plugin_defaults(
        &["keepassxc"],
        "keepassxc",
        Some("agents.kdbx\n/{key}"),
    ));
    let err = vhs_with_defaults(terse("github"), &d, &reg).unwrap_err();
    assert!(err.contains("control character"), "{err}");
}

#[test]
fn a_terse_key_naming_no_installed_plugin_is_rejected() {
    // The registry is the same one an explicit `from` ref is parsed against, so a misspelled
    // scheme fails closed here exactly as it would there.
    let reg = PluginRegistry::with([plugin("pass")]);
    let err = validate_host_secret(
        "api.github.com",
        terse("tok@pas"),
        &SecretDefaults::default(),
        &reg,
    )
    .unwrap_err();
    assert!(err.contains("pas") && err.contains("plugins list"), "{err}");
}

#[test]
fn a_plugin_scheme_in_the_default_order_serves_every_terse_key() {
    // The point of the binding: the vault is named once, and switching to another one is a single
    // edit rather than one per entry.
    let reg = PluginRegistry::with([plugin("keepassxc-browser")]);
    let d = SecretDefaults::from_raw(&raw_plugin_defaults(
        &["keepassxc-browser"],
        "keepassxc-browser",
        None,
    ));
    for key in ["api.github.com", "api.npmjs.org"] {
        let s = vhs_with_defaults(terse(key), &d, &reg).unwrap();
        match &s.sources[..] {
            [SecretSource::Plugin { plugin, locator }] => {
                assert_eq!(plugin.scheme, "keepassxc-browser");
                assert_eq!(locator, key);
            }
            other => panic!("expected one keepassxc-browser:// source, got {other:?}"),
        }
    }
}

#[test]
fn a_plugin_scheme_falls_back_to_a_builtin_in_the_default_order() {
    // A terse chain crossing the plugin boundary: the vault first, the environment behind it.
    let reg = PluginRegistry::with([plugin("keepassxc-browser")]);
    let d = SecretDefaults::from_raw(&RawSecretDefaults {
        env: Some(RawEnvDefaults {
            case: Some("upper".into()),
        }),
        ..raw_plugin_defaults(&["keepassxc-browser", "env"], "keepassxc-browser", None)
    });
    let s = vhs_with_defaults(terse("gh_token"), &d, &reg).unwrap();
    match &s.sources[..] {
        [SecretSource::Plugin { locator, .. }, SecretSource::Env(var)] => {
            assert_eq!(locator, "gh_token");
            assert_eq!(var, "GH_TOKEN");
        }
        other => panic!("expected a plugin source then an env one, got {other:?}"),
    }
}

#[test]
fn a_project_binds_one_scheme_without_unbinding_the_others() {
    // The bindings merge per scheme, like every other default: a project that retemplates one
    // vault keeps the global template for the vault it never mentions.
    let global = SecretDefaults::from_raw(&RawSecretDefaults {
        resolver: BTreeMap::from([
            (
                "keepassxc".to_string(),
                RawResolverDefaults {
                    locator: Some("shared.kdbx/{key}".into()),
                },
            ),
            (
                "pass".to_string(),
                RawResolverDefaults {
                    locator: Some("team/{key}".into()),
                },
            ),
        ]),
        ..raw_defaults(&["keepassxc"], None, None, None)
    });
    let merged = global.merged_with(&raw_plugin_defaults(
        &[],
        "keepassxc",
        Some("mine.kdbx/{key}"),
    ));
    let reg = PluginRegistry::with([plugin("keepassxc"), plugin("pass")]);

    let s = vhs_with_defaults(terse("gh@keepassxc"), &merged, &reg).unwrap();
    match &s.sources[..] {
        [SecretSource::Plugin { locator, .. }] => assert_eq!(locator, "mine.kdbx/gh"),
        other => panic!("expected the project's template, got {other:?}"),
    }
    let s = vhs_with_defaults(terse("gh@pass"), &merged, &reg).unwrap();
    match &s.sources[..] {
        [SecretSource::Plugin { locator, .. }] => assert_eq!(locator, "team/gh"),
        other => panic!("expected the global template, got {other:?}"),
    }
}

#[test]
fn a_task_credential_expands_a_terse_key_through_a_plugin() {
    // A declared operation resolves through the same chain, so the binding serves it too.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let mut task = RawTask {
        cmd: vec!["/bin/true".into()],
        ..RawTask::default()
    };
    task.secret
        .insert("PGPASSWORD".into(), RawTaskSecret::Ref("db".into()));
    let cfg = RawConfig {
        secret: Some(RawSecretSection {
            defaults: Some(raw_plugin_defaults(
                &["keepassxc"],
                "keepassxc",
                Some("agents.kdbx/{key}"),
            )),
            hosts: BTreeMap::new(),
        }),
        task: Some(RawTaskSection {
            defaults: None,
            tasks: BTreeMap::from([("q".to_string(), task)]),
        }),
        ..RawConfig::default()
    };

    let resolved = super::resolve(cfg, None, &reg);
    let spec = resolved
        .tasks
        .iter()
        .find(|t| t.name == "q")
        .expect("the task resolves");
    match &spec.secrets[0].sources[..] {
        [SecretSource::Plugin { locator, .. }] => assert_eq!(locator, "agents.kdbx/db"),
        other => panic!("expected the bound keepassxc locator, got {other:?}"),
    }
}

#[test]
fn a_task_terse_key_reaches_a_template_that_itself_carries_a_scheme() {
    // A task's one-liner accepts both a bare key and a full ref, and it tells them apart by the
    // `://` in what the *config* wrote. A template like `https://{key}` puts a `://` in the
    // expansion but not in the key, so the two consumers must still agree: the host path and the
    // task path both expand, neither reads the key as a ref.
    let reg = PluginRegistry::with([plugin("keepassxc-browser")]);
    let mut task = RawTask {
        cmd: vec!["/bin/true".into()],
        ..RawTask::default()
    };
    task.secret.insert(
        "API_TOKEN".into(),
        RawTaskSecret::Ref("api.example.com".into()),
    );
    let defaults = raw_plugin_defaults(
        &["keepassxc-browser"],
        "keepassxc-browser",
        Some("https://{key}"),
    );
    let cfg = RawConfig {
        secret: Some(RawSecretSection {
            defaults: Some(defaults.clone()),
            hosts: BTreeMap::from([(
                "api.example.com".to_string(),
                RawHostSecrets::One(terse("api.example.com")),
            )]),
        }),
        task: Some(RawTaskSection {
            defaults: None,
            tasks: BTreeMap::from([("q".to_string(), task)]),
        }),
        network: allowlist_net(&["api.example.com"]),
        ..RawConfig::default()
    };

    let resolved = super::resolve(cfg, None, &reg);
    let task_locator = match &resolved.tasks[0].secrets[0].sources[..] {
        [SecretSource::Plugin { locator, .. }] => locator.clone(),
        other => panic!("expected an expanded plugin source on the task path, got {other:?}"),
    };
    let host_locator = match &resolved.secrets[0].sources[..] {
        [SecretSource::Plugin { locator, .. }] => locator.clone(),
        other => panic!("expected an expanded plugin source on the host path, got {other:?}"),
    };
    assert_eq!(task_locator, "https://api.example.com");
    assert_eq!(host_locator, task_locator);
}

#[test]
fn a_resolver_binding_naming_no_installed_plugin_warns() {
    // The table binds nothing and nothing will ever reach it: the same gap `[plugin.<name>]`
    // reports for a name no secret uses.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let global = RawConfig {
        secret: Some(RawSecretSection {
            defaults: Some(raw_plugin_defaults(&[], "keepasxc", Some("db/{key}"))),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    let resolved = super::resolve(global, None, &reg);
    assert!(
        resolved
            .warnings
            .iter()
            .any(|w| w.contains("keepasxc") && w.contains("no installed resolver plugin")),
        "a misspelled scheme must be named: {:?}",
        resolved.warnings
    );
}

#[test]
fn a_resolver_binding_naming_a_builtin_is_refused() {
    // `env`, `file` and `sops` have binding tables of their own, with a shape this one cannot
    // express. Two mechanisms for one expansion is the ambiguity worth naming.
    let reg = PluginRegistry::with([plugin("keepassxc")]);
    let global = RawConfig {
        secret: Some(RawSecretSection {
            defaults: Some(raw_plugin_defaults(&["env"], "env", Some("{key}_TOKEN"))),
            hosts: BTreeMap::new(),
        }),
        ..RawConfig::default()
    };
    let resolved = super::resolve(global, None, &reg);
    assert!(
        resolved
            .warnings
            .iter()
            .any(|w| w.contains("[secret.defaults.env]") && w.contains("built-in")),
        "the built-in's own table must be named: {:?}",
        resolved.warnings
    );
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
                sign: None,
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
    // a secret declared while the network is shared (no filtering proxy) has nowhere to inject;
    // it is cleared with a warning, never a silent no-op. The posture is spelled out because the
    // built-in default now filters: leaving it implicit would test the opposite case, where the
    // proxy exists and the secret is honored.
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
            ..raw_network("shared")
        },
        None,
    );
    assert!(r.secrets.is_empty());
    assert_eq!(r.network, NetworkPolicy::Shared);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("requires") && w.contains("filtering"))
    );
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
    assert!(
        missing
            .warnings
            .iter()
            .any(|w| w.contains("missing `type`"))
    );

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
    assert!(
        unknown
            .warnings
            .iter()
            .any(|w| w.contains("unknown `type`"))
    );
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

/// Every shipped profile whose `cmd` is a shell script forwards `"$@"`.
///
/// `sbx app run <name> -- <args>` is in the verb's own synopsis, and sbx honours it by appending
/// the trailing arguments to the declared `cmd`. A profile that wraps its command in `<shell> -c`
/// and never expands `"$@"` therefore accepts those arguments and drops them, exit code 0 — the
/// promise is kept by the launcher and broken by the profile, which is the half no launcher-side
/// fix can reach.
///
/// The shape is re-derived here rather than borrowed from `sandbox::launch`: a net that shares its
/// rule with the code it guards agrees with that code when the rule itself is what drifted. A plain
/// argv needs nothing — sbx appends to it and the program reads its own arguments.
#[test]
fn no_shipped_profile_carries_a_key_sbx_does_not_know() {
    // The catalogue is the population the new app-scoped unknown-key report is loudest on: 71
    // profiles, each parsed on import, each warning surfacing at launch. A key that is real on the
    // baseline and inert here would have been invisible before; now it would be a line on every
    // launch of that app, so the catalogue has to be clean for the message to mean anything.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/app");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/app/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let raw = schema::parse_app(&std::fs::read(&path).expect("read the profile")).unwrap();
        assert!(
            raw.rest.is_empty(),
            "{}: unknown key(s) {:?}",
            path.display(),
            raw.rest.keys().collect::<Vec<_>>()
        );
        checked += 1;
    }
    // The bundles beside them, on the same rule: a bundle carries no `cmd` and no posture, so one
    // written there would be dropped in silence, and the shipped set is where that would be
    // loudest.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/bundle");
    let mut bundles = 0;
    for entry in std::fs::read_dir(&dir).expect("examples/bundle/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle"))
            .expect("the bundle parses");
        for (name, bundle) in &raw.bundle {
            assert!(
                bundle.rest.is_empty(),
                "{} (`{name}`): unknown key(s) {:?}",
                path.display(),
                bundle.rest.keys().collect::<Vec<_>>()
            );
            bundles += 1;
        }
    }
    // The guard asserts its own precondition: a `read_dir` that found nothing would pass in silence.
    assert!(checked >= 60, "only {checked} profiles were read");
    assert!(bundles >= 60, "only {bundles} bundles were read");
}

#[test]
fn every_shipped_shell_profile_forwards_its_trailing_arguments() {
    const SHELLS: [&str; 4] = ["bash", "sh", "zsh", "dash"];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("examples/app");
    let (mut shell_profiles, mut plain) = (0, 0);
    for entry in std::fs::read_dir(&dir).expect("examples/app/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse_app(&std::fs::read(&path).expect("read the profile")).unwrap();
        let argv = match raw.cmd {
            Some(cmd) => cmd.into_argv(),
            None => continue,
        };
        // The script is whatever follows a `-…c` flag that follows a shell. Anything else is a
        // program, and its arguments are its own.
        let script = argv.windows(2).position(|w| {
            let is_shell = std::path::Path::new(&w[0])
                .file_name()
                .is_some_and(|s| SHELLS.iter().any(|k| s == *k));
            let is_c_flag = w[1].strip_prefix('-').is_some_and(|rest| {
                rest.ends_with('c') && rest.bytes().all(|b| b.is_ascii_lowercase())
            });
            is_shell && is_c_flag
        });
        let Some(i) = script.and_then(|i| argv.get(i + 2)) else {
            plain += 1;
            continue;
        };
        shell_profiles += 1;
        assert!(
            i.contains("\"$@\""),
            "`examples/app/{name}.toml` wraps its command in a shell but never expands `\"$@\"`, so \
             `sbx app run {name} -- <args>` accepts arguments and silently drops them. Add `\"$@\"` \
             to the final `exec`, or drop the shell if the command is a plain argv."
        );
    }
    // The precondition, asserted rather than assumed: a catalogue that stopped using shell commands
    // would pass this test vacuously, and it would then be guarding nothing.
    assert!(
        shell_profiles >= 15,
        "expected the shipped catalogue to still carry shell-wrapped profiles to guard, found \
         {shell_profiles} (plain argv: {plain})"
    );
}

#[test]
fn a_runtime_staged_out_of_the_store_is_restaged_once_it_stops_running() {
    // `aionui` is the one shipped profile whose wrapper copies a tree OUT of the nix store into the
    // app's persistent home, because the app rewrites files inside it and the store is read-only.
    // The copy keeps the store paths of the revision it came from — `bin/node`'s ELF interpreter,
    // the shebangs of the npm and corepack shims beside it — so a launch that resolves against a
    // newer revision, plus a `gc --prune` of the old one, leaves a tree that is still present, still
    // executable and still writable, and that cannot run. A guard keyed on the tree's presence skips
    // it forever, and the app reports only that its installation is incomplete.
    //
    // This runs the SHIPPED script, unmodified, against a stand-in app root: the profile's own
    // `command -v aionui` lookup and its own `$HOME` are what place the two trees.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let profile = root.join("examples/app/aionui.toml");
    let raw = schema::parse_app(&std::fs::read(&profile).expect("read the profile")).unwrap();
    let argv = raw.cmd.expect("aionui ships a command").into_argv();
    let script = argv.last().expect("the wrapper script").clone();
    assert!(
        script.contains("managed-resources/node"),
        "`examples/app/aionui.toml` no longer stages the bundled Node runtime; this guard now \
         asserts nothing and must be retargeted or removed"
    );

    let tmp = TmpDir::new();
    let (app, home) = (tmp.path().join("approot"), tmp.path().join("home"));
    let src =
        app.join("opt/AionUi/resources/bundled-aioncore/linux-x64/managed-resources/node/v24/bin");
    let dest = home.join(".config/AionUi/aionui/runtime/node/v24");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(app.join("bin")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // The launcher the script derives the app root from, and the runtime it stages. Both are given
    // the store's own modes: read-only, executable, which is the state the staging exists to escape.
    let write_exec = |path: &std::path::Path, body: &str, mode: u32| {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    write_exec(&app.join("bin/aionui"), "#!/bin/sh\nexit 0\n", 0o555);
    write_exec(&src.join("node"), "#!/bin/sh\necho v24.0.0\n", 0o555);

    let launch = || {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&script)
            .env("HOME", &home)
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", app.join("bin").display()),
            )
            .output()
            .expect("run the shipped wrapper");
        assert!(out.status.success(), "the wrapper failed: {out:?}");
    };
    let node = dest.join("bin/node");
    let runs = || {
        std::process::Command::new(&node)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    };

    // 1. Nothing staged yet: the runtime lands, writable, and runs.
    launch();
    assert!(runs(), "the first launch did not stage a runnable runtime");
    assert!(
        !node.metadata().unwrap().permissions().readonly(),
        "staged read-only"
    );

    // 2. A relaunch leaves it alone — the marker survives, so nothing was re-copied. Restaging is not
    //    free: it discards whatever the app installed into the tree.
    let marker = dest.join(".installed-by-the-app");
    std::fs::write(&marker, "x").unwrap();
    launch();
    assert!(
        marker.exists(),
        "a healthy runtime was restaged, discarding the app's own install"
    );

    // 3. The revision it was copied from is reclaimed: the file is there, executable and writable,
    //    and its interpreter is not. Presence says fine; running says otherwise.
    write_exec(
        &node,
        "#!/nix/store/0000000000000000-reclaimed/bin/sh\n",
        0o755,
    );
    assert!(!runs(), "the broken-runtime state was not reproduced");
    launch();
    assert!(
        runs(),
        "a runtime whose interpreter was reclaimed was left in place"
    );
    assert!(!marker.exists(), "the tree was not replaced");

    // 4. A stage that never got its write bits: the repair must be able to remove what it replaces,
    //    which `rm -rf` cannot do inside directories it may not write.
    for p in [dest.join("bin"), dest.clone()] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o555)).unwrap();
    }
    write_exec(&node, "#!/bin/sh\necho v24.0.0\n", 0o555);
    launch();
    assert!(runs(), "a read-only stage was not repaired");
    assert!(
        !node.metadata().unwrap().permissions().readonly(),
        "still read-only"
    );
}

#[test]
fn every_shipped_bundle_matches_the_agent_profile_it_was_derived_from() {
    // The shipped bundles under `examples/bundle/` are the single source of truth for what each
    // agent needs: the namesake profile under `examples/app/` no longer restates any of it — it
    // names the bundle with `use = ["<name>"]` and declares nothing the bundle provides. Two
    // artifacts describing one tool is the drift risk this whole feature exists to remove — so it
    // is pinned here, and it is pinnable *because* both are authored in this repo for the same
    // agent. (The general form — inferring the same obligation between two unrelated profiles — is
    // NOT sound: a front-end legitimately exposes a smaller surface than the agent it embeds. Here
    // the obligation is declared by construction, which is the whole difference.)
    //
    // The old containment direction (bundle ⊆ profile) is gone: after the thin-profile sweep the
    // profile declares none of the bundle's packages, env or egress, so containment would compare
    // against empty lists and prove nothing. Three invariants replace it, still pinnable against
    // the real artifacts:
    //   1. The namesake profile names THIS bundle — `use = ["<name>"]`, nothing else.
    //   2. No duplication: the profile carries no package, env key or egress rule the bundle
    //      provides. (It may carry things the bundle does not — hermes keeps the in-cage
    //      chromium/agent-browser for its web variants, openfox a wider npm rule — but a second
    //      copy of the same requirement is exactly the drift this feature removes.)
    //   3. Every `@group` reference — from a bundle or its namesake profile — resolves to a
    //      shipped fragment under `examples/net-groups/`, so a header's REQUIRES block (and an
    //      app's allow list) can never point at a fragment that does not exist.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let groups_dir = root.join("examples/net-groups");
    let mut shipped_groups = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&groups_dir).expect("examples/net-groups/ dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // Parsed with sbx's own parser, so a fragment this test accepts is one `sbx net groups
        // import` accepts.
        schema::parse(&std::fs::read(&path).expect("read the group fragment")).unwrap();
        shipped_groups.insert(path.file_stem().unwrap().to_str().unwrap().to_string());
    }

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
        // which parses as an unknown key and vanishes) fails the checks below rather than passing
        // unnoticed.
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

        // Invariant 1: the namesake profile is thin and names this bundle, and only it.
        assert_eq!(
            profile.uses,
            vec![name.clone()],
            "bundle `{name}` must be named by `use = [\"{name}\"]` in `examples/app/{name}.toml` — \
             the namesake profile is thin and names its bundle"
        );

        // Invariant 2: nothing the bundle provides is restated in the profile.
        for key in profile.packages.keys() {
            assert!(
                !bundle.packages.contains_key(key),
                "`examples/app/{name}.toml` declares the package {key}, which the `{name}` bundle \
                 already provisions — one of the two moved"
            );
        }
        for key in profile.env.keys() {
            assert!(
                !bundle.env.contains_key(key),
                "`examples/app/{name}.toml` sets the env var {key}, which the `{name}` bundle \
                 already sets — one of the two moved"
            );
        }
        if let Some(schema::NetworkField::Table(t)) = &profile.network {
            for (label, from, into) in [
                ("allow", &t.allow, &bundle.allow),
                ("deny", &t.deny, &bundle.deny),
                ("mute", &t.mute, &bundle.mute),
            ] {
                for rule in from {
                    if rule.starts_with('@') {
                        // A shared-group reference belongs to the profile (the bundle may carry
                        // group references of its own); it must still resolve — invariant 3.
                        continue;
                    }
                    assert!(
                        !into.contains(rule),
                        "`examples/app/{name}.toml` carries the {label} rule {rule:?}, which the \
                         `{name}` bundle already provides — one of the two moved"
                    );
                }
            }
        }

        // Invariant 3: every @group reference resolves to a shipped fragment.
        for (label, list) in [
            ("allow", &bundle.allow),
            ("deny", &bundle.deny),
            ("mute", &bundle.mute),
        ] {
            for rule in list {
                if let Some(group) = rule.strip_prefix('@') {
                    assert!(
                        shipped_groups.contains(group),
                        "bundle `{name}` references @{group} in its {label} list, but \
                         `examples/net-groups/{group}.toml` does not exist — the header's REQUIRES \
                         block would import nothing"
                    );
                }
            }
        }
        if let Some(schema::NetworkField::Table(t)) = &profile.network {
            for (label, list) in [("allow", &t.allow), ("deny", &t.deny), ("mute", &t.mute)] {
                for rule in list {
                    if let Some(group) = rule.strip_prefix('@') {
                        assert!(
                            shipped_groups.contains(group),
                            "`examples/app/{name}.toml` references @{group} in its {label} list, \
                             but `examples/net-groups/{group}.toml` does not exist"
                        );
                    }
                }
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 36,
        "expected the shipped agent bundles to be checked, saw {checked}"
    );
}

#[test]
fn every_shipped_install_step_yields_to_the_upgrade_signal() {
    // `sbx upgrade provision` re-runs a bundle's install step in the app's cage with
    // `SBX_UPGRADE=1` set. The step's own "already installed" guard is what keeps an ordinary
    // launch from re-installing every time, so a step that never reads that variable takes the
    // guard's short path and does nothing — while the roll, which only sees exit status 0, prints
    // `re-installed`. The channel would be inert for that app and say the opposite, which is
    // exactly what this guard exists to prevent for the steps this repository ships.
    //
    // The variable is looked for in the step's own argv rather than in the file text, and the
    // script's whole-line shell comments are dropped before the search. Both filters are load
    // bearing and were each proven by mutation: every bundle carrying a step explains the channel
    // in a TOML comment above it *and* in a shell comment inside it, so a search over either the
    // file or the raw script passes on a script whose guard no longer reads the variable. A
    // trailing comment on a line of code is not stripped — it would take a shell parser to tell
    // one from a `#` inside a string, and a guard that reads the variable on the same line is not
    // the regression this is watching for.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;
    for entry in std::fs::read_dir(root.join("examples/bundle"))
        .expect("examples/bundle/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let raw = schema::parse(&std::fs::read(&path).expect("read the bundle")).unwrap();
        let Some(provision) = raw
            .bundle
            .get(&name)
            .and_then(|bundle| bundle.provision.clone())
        else {
            continue;
        };
        let script: String = provision
            .into_argv()
            .join(" ")
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            script.contains("SBX_UPGRADE"),
            "`examples/bundle/{name}.toml` carries a `provision` whose script never reads \
             SBX_UPGRADE — `sbx upgrade provision` would run it, its own guard would skip the \
             install, and the roll would still report it as re-installed"
        );
        checked += 1;
    }
    assert!(
        checked >= 8,
        "expected the shipped install steps to be checked, saw {checked}"
    );
}

#[test]
fn every_shipped_profile_resolves_the_egress_groups_it_references() {
    // Invariant 3 of the bundle test above reaches a profile only through its namesake bundle, so
    // the profiles that have none — the desktop and web builds, and the agents packaged by a
    // bootstrap or a source checkout — were never checked. They reference groups too, and a
    // reference to a fragment that does not ship is fail-closed: the launch loses the whole lane,
    // and the header's `sbx net groups import` line points at a file that is not there.
    //
    // This walks `examples/app/` directly, so a profile is covered whether or not a bundle exists
    // for it.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut shipped_groups = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(root.join("examples/net-groups"))
        .expect("examples/net-groups/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            shipped_groups.insert(path.file_stem().unwrap().to_str().unwrap().to_string());
        }
    }

    let mut checked = 0;
    for entry in std::fs::read_dir(root.join("examples/app"))
        .expect("examples/app/ dir exists")
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        let profile = schema::parse_app(&std::fs::read(&path).expect("read the profile")).unwrap();
        if let Some(schema::NetworkField::Table(t)) = &profile.network {
            for (label, list) in [("allow", &t.allow), ("deny", &t.deny), ("mute", &t.mute)] {
                for rule in list {
                    if let Some(group) = rule.strip_prefix('@') {
                        assert!(
                            shipped_groups.contains(group),
                            "`examples/app/{name}.toml` references @{group} in its {label} list, \
                             but `examples/net-groups/{group}.toml` does not exist — the lane it \
                             names would resolve to nothing"
                        );
                    }
                }
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 60,
        "expected the shipped profiles to be checked, saw {checked}"
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
fn an_unknown_key_under_network_is_named() {
    // `[network]` is the largest table in the schema and the one most often written by hand, so a
    // key it does not know is the one most likely to read as a rule in force while deciding
    // nothing. Ignoring it is the forward-compatibility contract; passing over it in silence is
    // not, and this table carried no report of its own until it held the egress groups.
    let raw = RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mode: Some("deny".into()),
            rest: [("alow".to_string(), schema::RawIgnored)]
                .into_iter()
                .collect(),
            ..net_table_defaults()
        })),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(raw, None);
    let w = r
        .warnings
        .iter()
        .find(|w| w.contains("`alow`"))
        .unwrap_or_else(|| panic!("the key must be named: {:?}", r.warnings));
    assert!(w.contains("[network]"), "and placed in its table: {w}");
    // The layer still loads: the mode written beside the typo is in effect.
    assert!(
        matches!(r.network, NetworkPolicy::Allowlist(_)),
        "{:?}",
        r.network
    );
}

#[test]
fn an_unknown_key_under_network_is_named_even_under_a_non_filtering_posture() {
    // `none`/`shared` return before any rule is classified, so a report placed with the rules would
    // never run for them — the posture that carries no lists is exactly where a stray key is
    // hardest to notice.
    let raw = RawConfig {
        network: Some(NetworkField::Table(NetworkTable {
            mode: Some("shared".into()),
            rest: [("alow".to_string(), schema::RawIgnored)]
                .into_iter()
                .collect(),
            ..net_table_defaults()
        })),
        ..RawConfig::default()
    };
    let r = resolve_no_plugins(raw, None);
    assert!(
        r.warnings.iter().any(|w| w.contains("`alow`")),
        "{:?}",
        r.warnings
    );
    assert!(
        matches!(r.network, NetworkPolicy::Shared),
        "{:?}",
        r.network
    );
}

#[test]
fn a_net_table_is_an_unknown_section_like_any_other() {
    // There is one network namespace, `[network]`. `[net]` is not a second spelling of it and gets
    // no hint pointing at one: it lands in the top-level catch-all, named the way any unknown
    // section is, and nothing it holds is read.
    let raw = schema::parse(b"[net.groups]\nci = [\"github.com\"]\n").expect("parses");
    let r = resolve_no_plugins(raw, None);
    let w = r
        .warnings
        .iter()
        .find(|w| w.contains("`net`"))
        .unwrap_or_else(|| panic!("the section must be named: {:?}", r.warnings));
    assert!(
        !w.contains("network.groups"),
        "no hint pointing at the new spelling: {w}"
    );
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

/// Every bare key comes before the first `[table]` header: a key written after one folds into that
/// table, and the field would never reach its trust gate at all.
const EVERY_GATED_FIELD: &str = "nixpkgs = \"nixos-25.05\"\n\
     network = \"shared\"\n\
     proc = \"enforce\"\n\
     notify = \"off\"\n\
     gui = \"wayland\"\n\
     gpu = true\n\
     audio = true\n\
     dbus = true\n\
     forward = [8080]\n\
     [limits]\nmemory = \"1G\"\n\
     [seccomp]\nallow = [\"userfaultfd\"]\n\
     [devices]\nallow = [\"/dev/kvm\"]\n\
     [ssh_agent]\nallow = [\"deploy@example\"]\n\
     [secret.\"api.example.com\"]\n\
     from = \"env://DEMO_API_KEY\"\nheader = \"x-api-key\"\ntype = \"raw\"\n\
     [task.build]\ncmd = [\"cargo\", \"build\"]\n";

/// The remedy every trust-gated refusal ends on, per trust state.
///
/// Spelled out here rather than read back from `untrusted_reason`, which is the code these nets
/// exist to hold: taking the expected text from the function under test moves both sides of the
/// comparison together, so the remedy would be pinned by nothing. Rewording it takes two edits, and
/// that is what makes the second one deliberate. It is not decoration — `is_trust_drop` recognises
/// a dropped security field by this text, and the launch announces dropped fields through it, so a
/// refusal that lost it is one nobody is told about.
const REFUSAL_REASONS: [(TrustState, &str); 2] = [
    (TrustState::Untrusted, "untrusted — run `sbx trust`"),
    (
        TrustState::Changed,
        "changed since it was trusted — re-run `sbx trust`",
    ),
];

/// How each trust-gated field names itself when it is refused, in the order the resolver walks them.
///
/// The nouns are deliberately not uniform — `gpu` has a "posture", `forward` has "ports",
/// `[devices]` has none — and that is what a user reads, so it is pinned rather than tidied.
const GATED_REFUSALS: &[&str] = &[
    "`nixpkgs` override",
    "`network` policy",
    "`proc` policy",
    "`notify` policy",
    "`gui` posture",
    "`gpu` posture",
    "`audio` posture",
    "`dbus` posture",
    "`forward` ports",
    "`[limits]`",
    "`[seccomp]`",
    "`[devices]`",
    "`[ssh_agent]`",
    "1 secret(s)",
    "1 task(s)",
];

/// Every trust-gated field of an untrusted project says which field it dropped, verbatim.
///
/// The refusal is the only user-visible output of the gate: nothing else tells anyone that a
/// declared field is not in effect. A change to how the gate is written would otherwise compile,
/// keep every provenance assertion green, and quietly reword — or drop — what the launch says.
#[test]
fn every_trust_gated_project_field_names_itself_in_its_refusal() {
    for (state, reason) in REFUSAL_REASONS {
        let project: RawConfig = toml::from_str(EVERY_GATED_FIELD).unwrap();
        let r = resolve_no_plugins(RawConfig::default(), Some((project, state)));
        for what in GATED_REFUSALS {
            let expected = format!("{PROJECT_CONFIG}: ignoring {what} ({reason})");
            assert!(
                r.warnings.contains(&expected),
                "{state:?}: expected exactly {expected:?}\ngot {:#?}",
                r.warnings
            );
        }
    }
}

/// The app layer refuses in the same words, naming the app's own source instead of the project file.
///
/// It is a second, independent walk over the same fields, so a change that fixed one block and not
/// the other would leave an app's refusals worded differently from a project's — invisible to
/// anything that only resolves a project.
#[test]
fn every_trust_gated_app_field_names_itself_in_its_refusal() {
    let toml_src = format!(
        "[app.mine]\ncmd = \"demo-app\"\n{}",
        EVERY_GATED_FIELD
            .lines()
            // `nixpkgs` is not an app field, and the app's own tables nest under `[app.mine.<t>]`.
            .filter(|l| !l.starts_with("nixpkgs"))
            .map(|l| match l.strip_prefix('[') {
                Some(rest) => format!("[app.mine.{rest}"),
                None => l.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n")
    );
    let (state, reason) = REFUSAL_REASONS[0];
    let project: RawConfig = toml::from_str(&toml_src).unwrap();
    let r = resolve_no_plugins(RawConfig::default(), Some((project, state)));
    let app = &r.apps["mine"];
    for what in GATED_REFUSALS.iter().filter(|w| !w.contains("nixpkgs")) {
        assert!(
            app.warnings
                .iter()
                .any(|w| w.ends_with(&format!(": ignoring {what} ({reason})"))),
            "expected an app refusal ending in {:?}\ngot {:#?}",
            format!(": ignoring {what} ({reason})"),
            app.warnings
        );
    }
}

/// A trusted app, declaring one facet of every kind an untrusted layer may not override.
const TRUSTED_APP: &str = "\
     [bundle.demo-bundle]\n\
     packages = { bundled-tool = \"mise:aqua:example/bundled-tool\" }\n\
     [app.demo-app]\n\
     cmd = \"demo-app\"\nhome_scope = \"project\"\n\
     [app.demo-app.packages]\n\
     demo-tool = \"mise:aqua:example/demo-tool\"\n\
     demo-flake = \"nix:jq\"\ndemo-tar = \"nix:jq\"\n";

/// An untrusted project reaching for every one of them at once, by the app's own name.
const OVERRIDING_PROJECT: &str = "\
     [app.demo-app]\n\
     use = [\"demo-bundle\"]\ncmd = \"evil\"\nhome_scope = \"global\"\n\
     [app.demo-app.packages]\n\
     demo-tool = \"mise:aqua:attacker/x\"\ndemo-tar = \"tarball:resolve\"\n\
     [app.demo-app.flakes.demo-flake]\n\
     flake = \"{ outputs = _: {}; }\"\n\
     [app.demo-app.tarball.demo-tar]\n\
     resolve = [\"echo\", \"https://example.com/x.tar.gz\"]\n";

/// How each facet of a trusted app names itself when an untrusted layer tries to override it.
///
/// A different gate from [`GATED_REFUSALS`]: those fields are refused because the layer declaring
/// them is untrusted, and that alone. These are refused because the layer is untrusted **and** a
/// trusted layer already supplied that facet — an untrusted project may still declare its own app's
/// command, tools and home scope, so the refusal has to say it is the *override* being dropped.
const TRUSTED_OVERRIDE_REFUSALS: &[&str] = &[
    "`use` of bundle(s) `demo-bundle`",
    "package `demo-tool` override of a trusted app",
    "inline flake `demo-flake` override of a trusted app",
    "tarball resolver `demo-tar` override of a trusted app",
    "`cmd` override of a trusted app",
    "`home_scope` override of a trusted app",
];

/// Every refused override of a trusted app says what it dropped and how to apply it, verbatim.
///
/// These refusals are the integrity guard's only user-visible output, and each one is written by
/// hand at its own site rather than by the layer's gate — so a reworded or truncated one would
/// compile, leave the behavioural assertions on `cmd`, `packages` and `home_scope` green, and
/// change what the user is told. Losing the remedy costs more than wording: [`is_trust_drop`] finds
/// a dropped security field by it, so a refusal without it is one the launch stops announcing.
#[test]
fn every_untrusted_override_of_a_trusted_app_names_itself_in_its_refusal() {
    for (state, reason) in REFUSAL_REASONS {
        let global: RawConfig = toml::from_str(TRUSTED_APP).unwrap();
        let project: RawConfig = toml::from_str(OVERRIDING_PROJECT).unwrap();
        let r = resolve_no_plugins(global, Some((project, state)));
        let app = &r.apps["demo-app"];
        // Written out rather than built from `project_app_source`: an expectation computed by the
        // code under test survives that code changing its answer.
        let source = ".sbx.toml [app.demo-app]";
        for what in TRUSTED_OVERRIDE_REFUSALS {
            let expected = format!("{source}: ignoring {what} ({reason})");
            assert!(
                app.warnings.contains(&expected),
                "{state:?}: expected exactly {expected:?}\ngot {:#?}",
                app.warnings
            );
        }
        // And nothing besides: a facet gated later has to be named above, where the whole refused
        // surface reads at once. This is the half that catches a *new* site written its own way.
        assert_eq!(
            app.warnings.len(),
            TRUSTED_OVERRIDE_REFUSALS.len(),
            "{state:?}: an unlisted refusal appeared\n{:#?}",
            app.warnings
        );
        for w in &app.warnings {
            assert!(
                super::is_trust_drop(w),
                "{state:?}: the launch would not announce this drop: {w}"
            );
        }
    }
}

/// Every trust-gated field lands in its own slot, stamps its own provenance, and moves nothing else.
///
/// A gated field is wired by naming a value slot and a provenance slot side by side. Naming a
/// neighbour's compiles, keeps every refusal green, and silently writes one field's value over
/// another's — a mis-wiring no test that only resolves untrusted configs can see. So the check is
/// that declaring one field **alone**, on a trusted project, moves exactly that field: its value
/// arrives, its provenance says `Project`, and every other gated field is still untouched at
/// `Default`.
#[test]
fn a_trusted_field_lands_in_its_own_slot_and_moves_no_other() {
    /// Which gated fields this resolution claims came from the project layer.
    fn claimed(r: &Resolved) -> Vec<&'static str> {
        [
            ("network", r.network_origin),
            ("proc", r.proc_origin),
            ("notify", r.notify_origin),
            ("gui", r.gui_origin),
            ("gpu", r.gpu_origin),
            ("audio", r.audio_origin),
            ("dbus", r.dbus_origin),
            ("forward", r.forward_origin),
            ("devices", r.devices_origin),
            ("ssh_agent", r.ssh_agent_origin),
        ]
        .into_iter()
        .filter(|(_, o)| *o == Provenance::Project)
        .map(|(n, _)| n)
        .collect()
    }

    // One field per case, declared alone, with what proves *that* field's value arrived.
    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, &str, Box<dyn Fn(&Resolved) -> bool>)> = vec![
        (
            "network",
            "network = \"shared\"",
            Box::new(|r: &Resolved| matches!(r.network, NetworkPolicy::Shared)),
        ),
        (
            "proc",
            "proc = \"enforce\"",
            Box::new(|r: &Resolved| r.proc.mode == crate::proc_policy::ProcMode::Enforce),
        ),
        (
            "notify",
            "notify = \"off\"",
            Box::new(|r: &Resolved| {
                r.notify.mode_for(crate::notify::NotifyEvent::Network)
                    == crate::notify::NotifyMode::Off
            }),
        ),
        (
            "gui",
            "gui = \"wayland\"",
            Box::new(|r: &Resolved| r.gui.renders()),
        ),
        ("gpu", "gpu = true", Box::new(|r: &Resolved| r.gpu)),
        ("audio", "audio = true", Box::new(|r: &Resolved| r.audio)),
        ("dbus", "dbus = true", Box::new(|r: &Resolved| r.dbus)),
        (
            "forward",
            "forward = [8080]",
            Box::new(|r: &Resolved| r.forward == same_forwards(&[8080])),
        ),
        (
            "devices",
            "[devices]\nallow = [\"/dev/kvm\"]",
            Box::new(|r: &Resolved| r.devices == vec![PathBuf::from("/dev/kvm")]),
        ),
        (
            "ssh_agent",
            "[ssh_agent]\nallow = [\"deploy@example\"]",
            Box::new(|r: &Resolved| r.ssh_agent == vec!["deploy@example".to_string()]),
        ),
    ];

    for (field, toml_src, landed) in cases {
        let project: RawConfig = toml::from_str(toml_src).unwrap();
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
        assert!(
            landed(&r),
            "`{field}` was declared by a trusted project and did not arrive in its own slot"
        );
        assert_eq!(
            claimed(&r),
            vec![field],
            "declaring `{field}` alone must stamp `{field}` and nothing else"
        );
    }

    // A trusted layer that declares a set and contributes nothing to it claims no provenance:
    // `config show` would otherwise point at a layer that added nothing. Every empty-set spelling,
    // since each one reaches the union by a different route.
    for empty in [
        "forward = []",
        "[devices]\nallow = []",
        "[ssh_agent]\nallow = []",
    ] {
        let project: RawConfig = toml::from_str(empty).unwrap();
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
        assert!(
            claimed(&r).is_empty(),
            "an empty {empty:?} contributed nothing and must claim nothing; claimed {:?}",
            claimed(&r)
        );
    }
}

/// The app layer's fields land in their own slots too — a second, independent walk over the same
/// ten fields, wired against `Option` slots rather than plain ones.
///
/// Half of the gated sites are here, and they are the half where the wiring is least mechanical (an
/// app's scalar is an `Option`, so its layering wraps). Nothing else looks at an app's slot/origin
/// pairing: the refusal test sees a gate opened or closed, never a value put in the wrong place.
#[test]
fn a_trusted_apps_field_lands_in_its_own_slot_and_moves_no_other() {
    fn claimed(app: &ResolvedApp) -> Vec<&'static str> {
        [
            ("network", app.network_origin),
            ("proc", app.proc_origin),
            ("notify", app.notify_origin),
            ("gui", app.gui_origin),
            ("gpu", app.gpu_origin),
            ("audio", app.audio_origin),
            ("dbus", app.dbus_origin),
            ("forward", app.forward_origin),
            ("devices", app.devices_origin),
            ("ssh_agent", app.ssh_agent_origin),
        ]
        .into_iter()
        .filter(|(_, o)| *o == Provenance::Project)
        .map(|(n, _)| n)
        .collect()
    }

    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, &str, Box<dyn Fn(&ResolvedApp) -> bool>)> = vec![
        (
            "network",
            "network = \"shared\"",
            Box::new(|a: &ResolvedApp| matches!(a.network, Some(NetworkPolicy::Shared))),
        ),
        (
            "proc",
            "proc = \"enforce\"",
            Box::new(|a: &ResolvedApp| {
                a.proc.as_ref().map(|p| p.mode) == Some(crate::proc_policy::ProcMode::Enforce)
            }),
        ),
        (
            "notify",
            "notify = \"off\"",
            Box::new(|a: &ResolvedApp| {
                a.notify
                    .as_ref()
                    .map(|n| n.mode_for(crate::notify::NotifyEvent::Network))
                    == Some(crate::notify::NotifyMode::Off)
            }),
        ),
        (
            "gui",
            "gui = \"wayland\"",
            Box::new(|a: &ResolvedApp| a.gui.map(|g| g.renders()) == Some(true)),
        ),
        (
            "gpu",
            "gpu = true",
            Box::new(|a: &ResolvedApp| a.gpu == Some(true)),
        ),
        (
            "audio",
            "audio = true",
            Box::new(|a: &ResolvedApp| a.audio == Some(true)),
        ),
        (
            "dbus",
            "dbus = true",
            Box::new(|a: &ResolvedApp| a.dbus == Some(true)),
        ),
        (
            "forward",
            "forward = [8080]",
            Box::new(|a: &ResolvedApp| a.forward == same_forwards(&[8080])),
        ),
        (
            "devices",
            "[app.mine.devices]\nallow = [\"/dev/kvm\"]",
            Box::new(|a: &ResolvedApp| a.devices == vec![PathBuf::from("/dev/kvm")]),
        ),
        (
            "ssh_agent",
            "[app.mine.ssh_agent]\nallow = [\"deploy@example\"]",
            Box::new(|a: &ResolvedApp| a.ssh_agent == vec!["deploy@example".to_string()]),
        ),
    ];

    for (field, decl, landed) in cases {
        let src = format!("[app.mine]\ncmd = \"demo-app\"\n{decl}");
        let project: RawConfig = toml::from_str(&src).unwrap();
        let r = resolve_no_plugins(RawConfig::default(), Some((project, TrustState::Trusted)));
        let app = &r.apps["mine"];
        assert!(
            landed(app),
            "an app's `{field}` was declared by a trusted project and did not arrive in its own slot"
        );
        assert_eq!(
            claimed(app),
            vec![field],
            "declaring an app's `{field}` alone must stamp `{field}` and nothing else"
        );
    }
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("unknown notify mode `one`"))
    );
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
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains("invalid `repeat_after`"))
    );

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
