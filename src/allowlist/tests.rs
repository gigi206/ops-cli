use super::*;

fn rule(s: &str) -> Rule {
    classify(s).unwrap_or_else(|e| panic!("classify({s:?}) failed: {e}"))
}

/// A deny rule refuses a WebSocket like it refuses anything else.
///
/// The `WS` opt-in exists so an *allowance* cannot hand out a capability nobody asked for. It
/// was asked of deny rules too, where it does the opposite: it narrowed every deny an operator
/// can write against the one capability the tunnel calls distinct, unredactable and
/// bidirectional. And the cage chooses which question is asked — `tunnel.rs` reads the verb as
/// `WS` precisely because the request carried the upgrade headers the cage put there — so the
/// verb that dodged the deny list was the caller's to pick.
#[test]
fn a_deny_refuses_a_websocket_however_the_deny_is_spelled() {
    for spelling in [
        "evil.com",
        "evil.com:*",
        "{*} evil.com",
        "{GET,WS} evil.com",
    ] {
        let p = EgressPolicy::new(vec![rule("{*,WS} evil.com")], vec![rule(spelling)]);
        assert!(
            matches!(
                p.explain("evil.com", 443, "/ws", "WS"),
                Decision::DeniedBy(_)
            ),
            "`deny {spelling}` did not refuse a WebSocket"
        );
    }
    // A deny the operator scoped to particular verbs stays scoped — `{GET}` denies GET, and a
    // WebSocket is not a GET. Breadth is for the deny that names no verbs; this is the other
    // half of the same rule, and getting it wrong in this direction would make every
    // method-scoped deny secretly total.
    let scoped = EgressPolicy::new(vec![rule("{*,WS} evil.com")], vec![rule("{GET} evil.com")]);
    assert!(
        matches!(
            scoped.explain("evil.com", 443, "/ws", "WS"),
            Decision::AllowedBy(_)
        ),
        "a `{{GET}}`-scoped deny must not reach a WebSocket"
    );
    assert!(
        matches!(
            scoped.explain("evil.com", 443, "/ws", "GET"),
            Decision::DeniedBy(_)
        ),
        "...while still denying the verb it names"
    );
    // The path-scoped case, which is the one an operator reaches for: the host is granted WS,
    // one path is carved out, and the carve-out has to hold for a WS as it does for a GET.
    let p = EgressPolicy::new(
        vec![rule("{*,WS} api.example.com")],
        vec![rule("api.example.com/admin/*")],
    );
    assert!(
        matches!(
            p.explain("api.example.com", 443, "/admin/x", "GET"),
            Decision::DeniedBy(_)
        ),
        "the control: a GET to the denied path is refused"
    );
    assert!(
        matches!(
            p.explain("api.example.com", 443, "/admin/x", "WS"),
            Decision::DeniedBy(_)
        ),
        "a WebSocket reached a path the operator denied"
    );
    // And the grant still works where nothing denies it, so this did not just refuse everything.
    assert!(
        matches!(
            p.explain("api.example.com", 443, "/feed", "WS"),
            Decision::AllowedBy(_)
        ),
        "the `{{WS}}` grant must still open a WebSocket off the denied path"
    );
}

/// The `{WS}` grant is the only thing that opens a WebSocket, in **every** posture.
///
/// The opt-in is a statement about the capability, not about deny-by-default. Reaching the
/// default action, a denylist granted a WebSocket to every host with no rule naming one, and
/// `ask` parked a WebSocket to an explicitly denied host for a person to answer — where
/// `DefaultAction::Ask` promises deny rules still auto-fail.
#[test]
fn no_posture_opens_a_websocket_without_a_rule_naming_it() {
    for action in [
        DefaultAction::Allow,
        DefaultAction::Ask,
        DefaultAction::Deny,
    ] {
        let bare = EgressPolicy::new(vec![], vec![]).with_default(action);
        assert!(
            matches!(
                bare.explain("anywhere.example", 443, "/ws", "WS"),
                Decision::DeniedDefault
            ),
            "{action:?} opened a WebSocket with no rule naming one"
        );
        let denied = EgressPolicy::new(vec![], vec![rule("evil.com:*")]).with_default(action);
        assert!(
            !matches!(
                denied.explain("evil.com", 443, "/ws", "WS"),
                Decision::AllowedDefault | Decision::Ask
            ),
            "{action:?} let a WebSocket to an explicitly denied host through"
        );
    }
    // An ordinary verb still follows its posture — this narrowed `WS`, nothing else.
    let open = EgressPolicy::new(vec![], vec![]).with_default(DefaultAction::Allow);
    assert!(matches!(
        open.explain("anywhere.example", 443, "/", "GET"),
        Decision::AllowedDefault
    ));
}

/// A policy carrying every setting a layer can set, for the comparison below to have something
/// to give up. Each value differs from the neutral one, which is the only property that matters
/// here: `pool` and `ca_roots` are `true` unset, so they are set `false`.
fn every_setting() -> EgressPolicy {
    use std::time::Duration;
    EgressPolicy::new(Vec::new(), Vec::new())
        .with_mute(vec![rule("telemetry.example.com")])
        .with_http2(vec![
            Http2Host::parse("grpc.example.com").expect("a plain host parses"),
        ])
        .with_dns_cache_ttl(Some(Duration::from_secs(300)))
        .with_pool(false)
        .with_idle_timeout(Some(Duration::from_secs(45)))
        .with_max_connections(Some(128))
        .with_body_max(Some(64 * 1024 * 1024))
        .with_ca_roots(false)
        .with_capture(crate::sandbox::control::CaptureLevel::Bodies, Some(32))
        .with_ask_timeout(Some(Duration::from_secs(90)))
        .with_ask_notice(false)
}

/// What a layer gives up by declaring a `[network]` table: everything the layer below carried,
/// because the table rebuilds the policy instead of amending it.
///
/// The expectation is a **literal list in the config file's own order**, never re-derived from
/// the policy the test just built — a table that computes its own answer agrees with any
/// implementation, including one that forgot a field. The neutral child is the case that
/// matters, because `sbx net allow --local` writes exactly that: a table of one rule.
#[test]
fn a_table_gives_up_every_setting_the_layer_below_carried() {
    let parent = every_setting().with_default(DefaultAction::Ask);
    let one_rule =
        |action| EgressPolicy::new(vec![rule("example.com")], Vec::new()).with_default(action);
    assert_eq!(
        one_rule(DefaultAction::Ask).settings_dropped_from(&parent),
        vec![
            "mute",
            "http2",
            "dns_cache_ttl",
            "pool",
            "idle_timeout",
            "max_connections",
            "body_max_mb",
            "ca_roots",
            "capture",
            "ask_timeout",
            "ask_notice",
        ],
        "a table of one rule keeps none of the settings under it"
    );

    // The same table under a mode of its own gives up the same settings *except* the two that
    // belong to the parked wait: leaving `ask` is not dropping them, and the layer is already
    // told so wherever it declared one. Naming them here would contradict that line.
    assert_eq!(
        one_rule(DefaultAction::Deny).settings_dropped_from(&parent),
        vec![
            "mute",
            "http2",
            "dns_cache_ttl",
            "pool",
            "idle_timeout",
            "max_connections",
            "body_max_mb",
            "ca_roots",
            "capture",
        ],
        "the `ask` settings are the mode's, not this table's to keep"
    );
}

/// The two ways a layer gives up nothing, which is what keeps the warning off the common case:
/// re-declaring the same value, and replacing one in the open. Both are compared by **effect**,
/// so neither depends on which keys the layer happened to write.
#[test]
fn re_declaring_or_replacing_a_setting_gives_nothing_up() {
    let parent = every_setting();
    assert!(
        parent.settings_dropped_from(&parent).is_empty(),
        "a layer that carries the same settings gives none of them up"
    );

    let replaced = every_setting()
        .with_capture(crate::sandbox::control::CaptureLevel::Headers, None)
        .with_max_connections(Some(8));
    assert!(
        replaced.settings_dropped_from(&parent).is_empty(),
        "a setting declared with a different value was replaced in the open, not dropped"
    );

    // And a neutral parent has nothing to give up, whatever this layer declares — the global
    // layer's own case, where `parent` is the built-in default.
    assert!(
        every_setting()
            .settings_dropped_from(&EgressPolicy::new(Vec::new(), Vec::new()))
            .is_empty(),
        "nothing was carried below, so nothing is given up"
    );
}

/// The separator rule of `*.domain`, on the shape that decides it rather than on a policy.
///
/// Every expectation is a **literal**, never re-derived from a `".{domain}"` the code could
/// build the same wrong way: a table that computes its own answer agrees with any
/// implementation, including a broken one. The entries are the ones where a suffix test can go
/// wrong: the apex itself, a real subdomain, a name that merely *ends* with the domain, a
/// domain that appears in the middle, an empty side, and a leading dot.
#[test]
fn a_wildcard_domain_matches_its_apex_and_below_but_never_a_bare_suffix() {
    for (domain, host, expected) in [
        ("example.com", "example.com", true),
        ("example.com", "a.example.com", true),
        ("example.com", "a.b.example.com", true),
        ("example.com", "xexample.com", false),
        ("example.com", "example.com.evil.net", false),
        ("example.com", "a.example.com.evil.net", false),
        ("example.com", ".example.com", true),
        ("example.com", "", false),
        ("example.com", "com", false),
        ("", "example.com", false),
        ("", "", true),
        (".example.com", "a.example.com", false),
        (".example.com", "a..example.com", true),
    ] {
        assert_eq!(
            apex_or_subdomain(domain, host),
            expected,
            "`*.{domain}` against `{host}`"
        );
    }
}

#[test]
fn the_default_policy_is_the_constructor_and_keeps_connection_reuse() {
    // The regression this replaced a `derive(Default)` for: a derived default fills each field
    // with its *type's* default, so `pool` came out `false` while `new` sets it `true`. It was
    // invisible while the built-in posture was `shared` (this policy was never the one a launch
    // used); the day the default posture became an allowlist, every unconfigured cage lost
    // connection reuse and paid a fresh upstream handshake per request, silently.
    assert_eq!(
        EgressPolicy::default(),
        EgressPolicy::new(Vec::new(), Vec::new())
    );
    assert!(
        EgressPolicy::default().pool(),
        "an unconfigured cage keeps connection reuse"
    );
    // And the posture a config-less launch resolves to carries it too, which is the path that
    // actually broke.
    match crate::config::NetworkPolicy::default() {
        crate::config::NetworkPolicy::Allowlist(p) => assert!(p.pool()),
        other => panic!("the built-in posture is a filtering one: {other:?}"),
    }
}

/// An allow-only policy (no deny rules), for the single-list matching tests.
fn allow(entries: &[&str]) -> EgressPolicy {
    EgressPolicy::new(entries.iter().map(|s| rule(s)).collect(), vec![])
}

#[test]
fn rule_equality_ignores_group_provenance() {
    // A rule's identity is its match (kind/methods/layer), not which `[network.groups]` group it was
    // expanded from — so a `group` tag never affects equality (and thus never affects dedup or an
    // `EgressPolicy` comparison). This is the load-bearing property that lets provenance travel
    // on the rule without disturbing matching.
    let a = rule("github.com");
    let mut tagged = rule("github.com");
    tagged.group = Some("gh".into());
    assert_eq!(a, tagged, "group provenance must not affect rule equality");
    assert_eq!(
        EgressPolicy::new(vec![a], vec![]),
        EgressPolicy::new(vec![tagged], vec![]),
        "a policy comparison must be unaffected by a rule's group tag"
    );
}

#[test]
fn classifies_each_granularity() {
    assert_eq!(
        rule("1.2.3.4").kind,
        RuleKind::Ip("1.2.3.4".parse().unwrap(), Ports::default())
    );
    assert_eq!(
        rule("::1").kind,
        RuleKind::Ip("::1".parse().unwrap(), Ports::default())
    );
    assert_eq!(
        rule("github.com").kind,
        RuleKind::Host("github.com".into(), Ports::default())
    );
    assert_eq!(
        rule("*.nixos.org").kind,
        RuleKind::Subdomain("nixos.org".into(), Ports::default())
    );
    // a `/` makes it a path rule; a bare host defaults to the HTTPS port {443}
    assert_eq!(
        rule("example.com/exact/path").kind,
        RuleKind::Url {
            host: "example.com".into(),
            ports: Ports::default(),
            path: "/exact/path".into(),
            subtree: false,
        }
    );
    // a trailing /* marks a subtree rule
    assert_eq!(
        rule("example.com/area/*").kind,
        RuleKind::Url {
            host: "example.com".into(),
            ports: Ports::default(),
            path: "/area/*".into(),
            subtree: true,
        }
    );
}

#[test]
fn a_path_rule_carries_the_same_port_syntax_as_a_host() {
    // a bare `host/` is the root path on the default HTTPS port {443}
    assert_eq!(
        rule("example.com/").kind,
        RuleKind::Url {
            host: "example.com".into(),
            ports: Ports::default(),
            path: "/".into(),
            subtree: false,
        }
    );
    // an explicit single port pins exactly that port for the path
    assert_eq!(
        rule("example.com:8443/x").kind,
        RuleKind::Url {
            host: "example.com".into(),
            ports: Ports::Ranges(vec![(8443, 8443)]),
            path: "/x".into(),
            subtree: false,
        }
    );
    // `:*` opens the path on any port; a list/range works too
    assert_eq!(
        rule("example.com:*/admin").kind,
        RuleKind::Url {
            host: "example.com".into(),
            ports: Ports::Any,
            path: "/admin".into(),
            subtree: false,
        }
    );
    // an IPv6 host with a port and a path
    assert_eq!(
        rule("[::1]:8080/admin").kind,
        RuleKind::Url {
            host: "::1".into(),
            ports: Ports::Ranges(vec![(8080, 8080)]),
            path: "/admin".into(),
            subtree: false,
        }
    );
}

#[test]
fn a_scheme_selects_the_enforcement_layer() {
    // `https://` (and a bare host) is inspected L7; `tcp://` is raw L4. The scheme selects only
    // the layer, never a port — so `https://h` and bare `h` are the same rule.
    assert_eq!(rule("https://example.com"), rule("example.com"));
    assert_eq!(rule("example.com").layer, Layer::L7);
    assert_eq!(rule("https://example.com:8443/x").layer, Layer::L7);
    assert_eq!(
        rule("tcp://ssh.example.com:22").kind,
        RuleKind::Host("ssh.example.com".into(), Ports::Ranges(vec![(22, 22)]))
    );
    assert_eq!(rule("tcp://ssh.example.com:22").layer, Layer::L4);
    // `tcp://` works on the IP and subdomain host kinds too.
    assert_eq!(
        rule("tcp://1.2.3.4:5432").kind,
        RuleKind::Ip(
            "1.2.3.4".parse().unwrap(),
            Ports::Ranges(vec![(5432, 5432)])
        )
    );
    assert_eq!(rule("tcp://1.2.3.4:5432").layer, Layer::L4);
    assert_eq!(rule("tcp://*.corp:22").layer, Layer::L4);
    assert!(matches!(
        rule("tcp://*.corp:22").kind,
        RuleKind::Subdomain(..)
    ));
}

#[test]
fn rejects_an_unsupported_or_misplaced_scheme() {
    // An arbitrary scheme is rejected with a pointer at the supported schemes rather than
    // mis-reading it as a host. `http://` and `https://`/`tcp://` are handled; `ssh`/`udp` are
    // not, so they land here.
    for bad in ["ssh://host:22", "udp://host:53"] {
        let err = classify(bad).unwrap_err();
        assert!(
            err.contains("not supported in a rule") && err.contains("tcp://"),
            "{bad:?} should be rejected with a layer pointer, got: {err}"
        );
    }
}

#[test]
fn an_http_scheme_selects_the_cleartext_layer() {
    // `http://` is inspected-cleartext (L7Clear), defaulting to port 80 — distinct from the
    // bare/`https://` inspected-over-TLS default (443). It keeps the full HTTP vocabulary
    // (method prefix, path), unlike a raw `tcp://` rule.
    let r = rule("http://example.com");
    assert_eq!(r.layer, Layer::L7Clear);
    assert_eq!(
        r.kind,
        RuleKind::Host("example.com".into(), Ports::Ranges(vec![(80, 80)]))
    );
    // A bare `http://host` (port 80) is NOT the same rule as the bare/`https://` host (port 443).
    assert_ne!(rule("http://example.com"), rule("example.com"));
    // An explicit `:port` overrides the scheme default; a path and a method prefix are allowed.
    assert_eq!(
        rule("http://example.com:8080").kind,
        RuleKind::Host("example.com".into(), Ports::Ranges(vec![(8080, 8080)]))
    );
    assert_eq!(
        rule("{POST} http://api.example.com/v1").layer,
        Layer::L7Clear
    );
    assert!(matches!(
        rule("http://api.example.com/v1").kind,
        RuleKind::Url { .. }
    ));
    // The port-80 default renders compact (`:80` omitted), and every form round-trips through
    // classify back to itself.
    assert_eq!(rule("http://example.com").to_string(), "http://example.com");
    for entry in [
        "http://example.com",
        "http://example.com:8080",
        "http://[::1]:8080/admin",
        "{POST} http://api.example.com/v1",
    ] {
        assert_eq!(
            rule(entry).to_string(),
            entry,
            "http:// rule should round-trip through classify → Display"
        );
    }
}

#[test]
fn explain_clear_opens_only_on_an_explicit_http_rule() {
    // Cleartext is strictly opt-in: only an `http://` allow rule permits it. A bare/`https://`
    // allow (the inspected-over-TLS layer) does NOT open the same host in the clear.
    let tls_only = allow(&["example.com"]);
    assert!(matches!(
        tls_only.explain_clear("example.com", 80, "/", "GET"),
        Decision::DeniedDefault
    ));
    // An explicit `http://` allow permits the cleartext request.
    let clear = allow(&["http://example.com"]);
    assert!(matches!(
        clear.explain_clear("example.com", 80, "/", "GET"),
        Decision::AllowedBy(_)
    ));
    // The same `http://` allow does not open a different host, nor a different port than 80.
    assert!(matches!(
        clear.explain_clear("other.com", 80, "/", "GET"),
        Decision::DeniedDefault
    ));
    assert!(matches!(
        clear.explain_clear("example.com", 8080, "/", "GET"),
        Decision::DeniedDefault
    ));
}

#[test]
fn a_websocket_pseudo_verb_needs_an_explicit_ws_grant() {
    // WS is a distinct capability: neither an unrestricted `{*}` nor a bare rule grants it — only
    // a rule that names `WS`. A method-restricted HTTP rule never opens a WebSocket either.
    let any = allow(&["{*} example.com"]);
    assert!(matches!(
        any.explain("example.com", 443, "/", "GET"),
        Decision::AllowedBy(_)
    ));
    assert!(
        matches!(
            any.explain("example.com", 443, "/", "WS"),
            Decision::DeniedDefault
        ),
        "`{{*}}` must not grant WS"
    );

    let bare = allow(&["example.com"]);
    assert!(
        matches!(
            bare.explain("example.com", 443, "/", "WS"),
            Decision::DeniedDefault
        ),
        "a bare rule must not grant WS"
    );

    let get = allow(&["{GET} example.com"]);
    assert!(
        matches!(
            get.explain("example.com", 443, "/", "WS"),
            Decision::DeniedDefault
        ),
        "`{{GET}}` must not grant WS"
    );

    // An explicit `{WS}` grants the upgrade — but not an HTTP GET (a different capability).
    let ws = allow(&["{WS} example.com"]);
    assert!(matches!(
        ws.explain("example.com", 443, "/", "WS"),
        Decision::AllowedBy(_)
    ));
    assert!(
        matches!(
            ws.explain("example.com", 443, "/", "GET"),
            Decision::DeniedDefault
        ),
        "`{{WS}}` alone does not grant an HTTP GET"
    );

    // `{GET,WS}` grants both explicitly.
    let both = allow(&["{GET,WS} example.com"]);
    assert!(matches!(
        both.explain("example.com", 443, "/", "GET"),
        Decision::AllowedBy(_)
    ));
    assert!(matches!(
        both.explain("example.com", 443, "/", "WS"),
        Decision::AllowedBy(_)
    ));
}

#[test]
fn a_star_ws_prefix_grants_every_http_verb_and_the_websocket() {
    // `{*,WS}` is the ergonomic "all HTTP methods AND WebSocket" — a `*` inside the set means
    // every verb, and the explicit `WS` adds the upgrade. It round-trips through classify/render.
    let r = classify("{*,WS} example.com").unwrap();
    assert_eq!(
        r.to_string(),
        "{*,WS} https://example.com",
        "the `*,WS` set round-trips through classify/render"
    );

    let p = allow(&["{*,WS} example.com"]);
    for verb in ["GET", "POST", "PUT", "DELETE", "PATCH", "PROPFIND"] {
        assert!(
            matches!(
                p.explain("example.com", 443, "/", verb),
                Decision::AllowedBy(_)
            ),
            "`{{*,WS}}` admits every HTTP verb, including {verb}"
        );
    }
    assert!(
        matches!(
            p.explain("example.com", 443, "/", "WS"),
            Decision::AllowedBy(_)
        ),
        "`{{*,WS}}` admits the WebSocket upgrade"
    );

    // The distinction stays sharp: a `*` alone (`{*}`) is all-HTTP but NOT WS; only the explicit
    // `WS` token opens the upgrade — so `{*,WS}` and two rules `{*}` + `{WS}` are equivalent.
    assert!(matches!(
        allow(&["{*} example.com"]).explain("example.com", 443, "/", "WS"),
        Decision::DeniedDefault
    ));

    // A bogus token beside `*` is still rejected (fail-closed).
    assert!(
        classify("{*,ws} example.com").is_err(),
        "lowercase verb rejected"
    );
}

#[test]
fn explain_clear_never_consults_the_default_action() {
    // The opt-in property mirrors the L4 splice: even a denylist (`Allow`-by-default) or an
    // `ask` posture does NOT auto-open a cleartext request — only an explicit `http://` allow
    // does. So a host nothing named in the clear is DeniedDefault under every default action.
    for action in [
        DefaultAction::Allow,
        DefaultAction::Ask,
        DefaultAction::Deny,
    ] {
        let p = EgressPolicy::new(vec![], vec![]).with_default(action);
        assert!(
            matches!(
                p.explain_clear("anything.example", 80, "/", "GET"),
                Decision::DeniedDefault
            ),
            "cleartext must not be opened by the {action:?} default action"
        );
    }
}

#[test]
fn explain_clear_deny_wins_layer_agnostically() {
    // Deny wins across every layer (matched by kind), like the splice suppression: an inspected
    // (bare) deny on the cleartext port, and an `http://` deny, both block a matching `http://`
    // allow.
    let p = EgressPolicy::new(
        vec![rule("http://evil.com")],
        vec![rule("evil.com:80")], // a bare (inspected) deny naming the cleartext port
    );
    assert!(matches!(
        p.explain_clear("evil.com", 80, "/", "GET"),
        Decision::DeniedBy(_)
    ));
    // But a deny scoped to the wrong port (the bare 443 default) does NOT block port 80 — the
    // same consequence the splice documents: use a port-agnostic or `:80` deny to block a host.
    let q = EgressPolicy::new(vec![rule("http://evil.com")], vec![rule("evil.com")]);
    assert!(matches!(
        q.explain_clear("evil.com", 80, "/", "GET"),
        Decision::AllowedBy(_)
    ));
}

/// A **cleartext** deny refuses a WebSocket like it refuses anything else.
///
/// The plaintext plane read its deny list through the allow side's `WS` opt-in, which inverts
/// what that opt-in is for: it exists so an *allowance* cannot hand out a capability nobody
/// asked for, and asking it of a deny narrows every deny an operator can write — a bare
/// `deny host`, a `deny host:*`, an `http://` deny and an explicit `{*}` deny all failed to
/// reach a WebSocket, which a `{WS} http://host` allow then admitted. The inspected plane
/// already answers the deny question broadly; this pins the cleartext sibling to the same
/// reading, so `sbx test net -X WS http://…` cannot report ALLOWED for a destination the
/// operator denied.
#[test]
fn a_cleartext_deny_refuses_a_websocket_however_the_deny_is_spelled() {
    for spelling in [
        "ws.internal:*",
        "ws.internal:8080",
        "http://ws.internal:8080",
        "{*} ws.internal:*",
    ] {
        let p = EgressPolicy::new(
            vec![rule("{WS} http://ws.internal:8080")],
            vec![rule(spelling)],
        );
        assert!(
            matches!(
                p.explain_clear("ws.internal", 8080, "/x", "WS"),
                Decision::DeniedBy(_)
            ),
            "`deny {spelling}` did not refuse a cleartext WebSocket"
        );
    }
    // A deny the operator scoped to particular verbs stays scoped — breadth belongs to the deny
    // that names no verbs, and reading it the other way would make every method-scoped deny
    // secretly total. The same half-and-half as the inspected plane.
    let scoped = EgressPolicy::new(
        vec![rule("{WS} http://ws.internal:8080")],
        vec![rule("{GET} ws.internal:*")],
    );
    assert!(
        matches!(
            scoped.explain_clear("ws.internal", 8080, "/x", "WS"),
            Decision::AllowedBy(_)
        ),
        "a `{{GET}}`-scoped deny must not reach a WebSocket"
    );
    assert!(
        matches!(
            scoped.explain_clear("ws.internal", 8080, "/x", "GET"),
            Decision::DeniedBy(_)
        ),
        "...while still denying the verb it names"
    );
}

#[test]
fn explain_clear_honors_method_scope() {
    // An `http://` allow keeps the method vocabulary: `{GET}` permits GET but not POST, and
    // `method_denied_clear` distinguishes "wrong verb" from "host not allowed at all".
    let p = allow(&["{GET} http://api.example.com"]);
    assert!(matches!(
        p.explain_clear("api.example.com", 80, "/", "GET"),
        Decision::AllowedBy(_)
    ));
    assert!(matches!(
        p.explain_clear("api.example.com", 80, "/", "POST"),
        Decision::DeniedDefault
    ));
    assert!(p.method_denied_clear("api.example.com", 80, "/", "POST"));
    assert!(!p.method_denied_clear("unlisted.example.com", 80, "/", "POST"));
}

#[test]
fn apply_default_methods_rewrites_cleartext_allows() {
    // An `http://` allow rule is HTTP-inspected, so an app's read-by-default posture must narrow
    // it exactly like an `https://`/bare rule — else a cleartext rule silently escapes to
    // all-verbs, which is why the narrowing must cover `L7Clear` and not `L7` alone.
    let mut p = allow(&["http://api.example.com"]);
    p.apply_default_methods(&Methods::Only(vec!["GET".into(), "HEAD".into()]));
    // POST is now denied purely by method (the rule was narrowed to GET/HEAD), GET is allowed.
    assert!(matches!(
        p.explain_clear("api.example.com", 80, "/", "GET"),
        Decision::AllowedBy(_)
    ));
    assert!(p.method_denied_clear("api.example.com", 80, "/", "POST"));
}

#[test]
fn a_tcp_rule_forbids_a_method_prefix_and_a_path() {
    // L4 splices a raw stream: it has no HTTP method to filter and no path to match, so either
    // on a `tcp://` rule is rejected fail-closed.
    let m = classify("{GET} tcp://host:22").unwrap_err();
    assert!(m.contains("method prefix"), "got: {m}");
    let p = classify("tcp://host:22/admin").unwrap_err();
    assert!(p.contains("host:port only"), "got: {p}");
}

/// A `tcp://` host reaches a **shell script**: the cage preamble writes a `socat` clause per
/// destination, interpolating the host as written. `sandbox::egress::wrap_command` says out loud
/// that it rests on this grammar for that, and names the one place it re-checks instead
/// (`ssh_config_host_ok`, where a `Host` line is a pattern rather than a name). This is the
/// property it rests on, kept here rather than only in a sentence there.
///
/// The charset is ASCII letters, digits, `-` and `.`, so no byte a shell reads as syntax can be
/// in a host that reaches a listener. An address literal is the other admissible spelling, and
/// it parses as one or it is not admitted.
#[test]
fn a_tcp_host_cannot_carry_a_byte_a_shell_would_read() {
    for hostile in [
        "tcp://a;rm -rf ~:22",
        "tcp://$(id):22",
        "tcp://`id`:22",
        "tcp://a|b:22",
        "tcp://a&b:22",
        "tcp://a b:22",
        "tcp://a\nb:22",
        "tcp://a'b:22",
        "tcp://a\"b:22",
        "tcp://a<b:22",
        "tcp://a*b:22",
        "tcp://a$b:22",
    ] {
        assert!(
            classify(hostile).is_err(),
            "`{hostile}` must not become a host a socat clause is written around"
        );
    }
    // ...while the spellings a real destination uses are admitted.
    for fine in [
        "tcp://db.internal:5432",
        "tcp://10.0.0.5:5432",
        "tcp://a-b.c:22",
    ] {
        assert!(
            classify(fine).is_ok(),
            "`{fine}` is an ordinary destination"
        );
    }
}

#[test]
fn a_tcp_rule_requires_an_explicit_port() {
    // a raw splice must name the port it opens — a port-less `tcp://` rule is rejected (unlike a
    // bare L7 host, which defaults to 443). `:*` (every port) and an explicit port are fine.
    for ok in [
        "tcp://host:22",
        "tcp://host:*",
        "tcp://[::1]:443",
        "tcp://*.corp:5432",
    ] {
        assert!(classify(ok).is_ok(), "{ok} should classify");
    }
    for bad in ["tcp://host", "tcp://*.corp", "tcp://[::1]", "tcp://1.2.3.4"] {
        let e = classify(bad).unwrap_err();
        assert!(
            e.contains("explicit `:port`"),
            "{bad} should require a port, got: {e}"
        );
    }
}

#[test]
fn a_bare_host_defaults_to_the_https_port() {
    // the implicit scheme is https → a bare host's default port set is exactly {443}.
    assert_eq!(
        rule("github.com").kind,
        RuleKind::Host("github.com".into(), Ports::Ranges(vec![(443, 443)]))
    );
    assert_eq!(Ports::default(), Ports::Ranges(vec![(443, 443)]));
    // bare and https:// classify identically (same layer, same default port).
    assert_eq!(
        classify("github.com").unwrap(),
        classify("https://github.com").unwrap()
    );
}

#[test]
fn a_tcp_rule_round_trips_through_display() {
    for s in [
        "tcp://ssh.example.com:22",
        "tcp://*.corp:5432",
        "tcp://[::1]:22",
        // Port 443 must stay explicit on an L4 rule — the `:443`-omitting shortcut an L7 host
        // rule uses would render this as `tcp://host`, which re-classifies as an error.
        "tcp://host.example.com:443",
    ] {
        assert_eq!(rule(s).to_string(), s, "{s} should round-trip");
    }
    // an L7 host rule always shows the implicit `https://`, so a bare-typed host re-renders as
    // its explicit equal form (`https://github.com`), and an `https://` rule round-trips exactly.
    assert_eq!(rule("github.com").to_string(), "https://github.com");
    assert_eq!(rule("https://github.com").to_string(), "https://github.com");
    // both re-classify to the same rule — the canonical form is stable.
    assert_eq!(
        classify("github.com").unwrap(),
        classify("https://github.com").unwrap()
    );
}

#[test]
fn classifies_port_specs() {
    assert_eq!(
        rule("github.com:443").kind,
        RuleKind::Host("github.com".into(), Ports::Ranges(vec![(443, 443)]))
    );
    assert_eq!(
        rule("github.com:80,443,8443").kind,
        RuleKind::Host(
            "github.com".into(),
            Ports::Ranges(vec![(80, 80), (443, 443), (8443, 8443)])
        )
    );
    // a comma list is sorted and de-duplicated
    assert_eq!(
        rule("github.com:443,80,443").kind,
        RuleKind::Host(
            "github.com".into(),
            Ports::Ranges(vec![(80, 80), (443, 443)])
        )
    );
    // an inclusive range
    assert_eq!(
        rule("internal.test:8000-8100").kind,
        RuleKind::Host("internal.test".into(), Ports::Ranges(vec![(8000, 8100)]))
    );
    // ranges and singles mix
    assert_eq!(
        rule("internal.test:22,8000-8100").kind,
        RuleKind::Host(
            "internal.test".into(),
            Ports::Ranges(vec![(22, 22), (8000, 8100)])
        )
    );
    // :* is any port
    assert_eq!(
        rule("github.com:*").kind,
        RuleKind::Host("github.com".into(), Ports::Any)
    );
    // works on IP and subdomain kinds too
    assert_eq!(
        rule("1.2.3.4:8080,9090").kind,
        RuleKind::Ip(
            "1.2.3.4".parse().unwrap(),
            Ports::Ranges(vec![(8080, 8080), (9090, 9090)])
        )
    );
    assert_eq!(
        rule("*.nixos.org:443").kind,
        RuleKind::Subdomain("nixos.org".into(), Ports::Ranges(vec![(443, 443)]))
    );
}

#[test]
fn classifies_bracketed_ipv6_with_ports() {
    // bare IPv6 needs no brackets, at the default ports
    assert_eq!(
        rule("::1").kind,
        RuleKind::Ip("::1".parse().unwrap(), Ports::default())
    );
    // bracketed, no port -> default ports
    assert_eq!(
        rule("[::1]").kind,
        RuleKind::Ip("::1".parse().unwrap(), Ports::default())
    );
    // bracketed with a port spec
    assert_eq!(
        rule("[::1]:443").kind,
        RuleKind::Ip("::1".parse().unwrap(), Ports::Ranges(vec![(443, 443)]))
    );
    assert_eq!(
        rule("[2001:db8::1]:8080").kind,
        RuleKind::Ip(
            "2001:db8::1".parse().unwrap(),
            Ports::Ranges(vec![(8080, 8080)])
        )
    );
    // :* on IPv6
    assert_eq!(
        rule("[fe80::1]:*").kind,
        RuleKind::Ip("fe80::1".parse().unwrap(), Ports::Any)
    );
}

#[test]
fn rejects_malformed_ipv6_brackets() {
    for bad in [
        "[::1",          // unterminated
        "[notanip]:443", // not an IP inside the brackets
        "[::1]443",      // missing the `:` before the port
        "[::1]:",        // empty port spec
        "[::1]x",        // trailing junk
    ] {
        assert!(classify(bad).is_err(), "{bad:?} should be rejected");
    }
}

#[test]
fn rejects_malformed_port_specs() {
    for bad in [
        "github.com:",
        "github.com:abc",
        "github.com:0",
        "github.com:99999",
        "github.com:80,",
        "github.com:,80",
        "github.com:20-1",
        "github.com:1-",
        "github.com:-20",
    ] {
        assert!(classify(bad).is_err(), "{bad:?} should be rejected");
    }
}

#[test]
fn a_bare_host_opens_only_https() {
    // A bare host is `https://` implicitly, so it admits only 443 — least privilege. Open the
    // HTTP port (or any other) explicitly with `:80`/`:*`; never silently from a bare host.
    let a = allow(&["github.com"]);
    assert!(a.permits("github.com", 443, "/"));
    assert!(
        !a.permits("github.com", 80, "/"),
        "no plaintext HTTP from a bare host"
    );
    assert!(
        !a.permits("github.com", 22, "/"),
        "no SSH tunnel through an allowed host"
    );
    assert!(!a.permits("github.com", 8080, "/"));
    // the explicit forms open exactly what they name.
    assert!(allow(&["github.com:80"]).permits("github.com", 80, "/"));
    assert!(allow(&["github.com:*"]).permits("github.com", 22, "/"));
}

#[test]
fn a_port_list_and_range_match_only_listed_ports() {
    let a = allow(&["internal.test:8080,9000-9002"]);
    assert!(a.permits("internal.test", 8080, "/"));
    assert!(a.permits("internal.test", 9000, "/"));
    assert!(a.permits("internal.test", 9002, "/"));
    assert!(!a.permits("internal.test", 9003, "/"), "above the range");
    assert!(!a.permits("internal.test", 443, "/"), "443 not listed");
}

#[test]
fn a_star_port_matches_any_port() {
    let a = allow(&["internal.test:*"]);
    for p in [22u16, 80, 443, 8080, 65535] {
        assert!(a.permits("internal.test", p, "/"), "port {p}");
    }
    assert!(!a.permits("other.test", 80, "/"));
}

#[test]
fn a_port_can_be_denied_out_of_an_open_host() {
    // open every port, then carve one out — deny wins
    let p = EgressPolicy::new(
        vec![rule("internal.test:*")],
        vec![rule("internal.test:22")],
    );
    assert!(p.permits("internal.test", 443, "/"));
    assert!(
        !p.permits("internal.test", 22, "/"),
        "the denied port wins over the open allow"
    );
}

#[test]
fn a_bracketed_ipv6_rule_matches_the_address_on_its_ports() {
    let a = allow(&["[2001:db8::1]:8080"]);
    assert!(a.permits("2001:db8::1", 8080, "/"));
    assert!(!a.permits("2001:db8::1", 443, "/"), "443 not in the set");
    assert!(!a.permits("2001:db8::2", 8080, "/"), "a different address");
    // bare IPv6 opens the HTTPS port only
    let b = allow(&["::1"]);
    assert!(b.permits("::1", 443, "/"));
    assert!(!b.permits("::1", 8080, "/"));
}

#[test]
fn classification_is_case_insensitive_on_the_host() {
    assert_eq!(
        rule("GitHub.COM").kind,
        RuleKind::Host("github.com".into(), Ports::default())
    );
    assert_eq!(
        rule("*.NixOS.org").kind,
        RuleKind::Subdomain("nixos.org".into(), Ports::default())
    );
}

#[test]
fn rejects_malformed_entries() {
    for bad in [
        "",
        "  ",
        "*.",
        "*. bad",
        "has space",
        "a..b",
        "-leading.com",
        "bad host/x",             // a space in the host of a path rule
        "example.com:notaport/x", // a non-numeric port before the path
        "/x",                     // no host before the path
        "*.evil.com/x",           // a wildcard host with a path is not expressible
    ] {
        assert!(classify(bad).is_err(), "{bad:?} should be rejected");
    }
}

/// Every scheme-free spelling of the bare `*` host: plain, with a port spec, and as a path rule.
/// (A *scheme*-prefixed `*` is rejected one step earlier by the scheme guard — see
/// `rejects_a_scheme_in_an_entry`.)
const CATCH_ALL_SPELLINGS: [&str; 5] = ["*", "*:*", "*:80", "*/path", "*:*/admin"];

#[test]
fn rejects_the_catch_all_wildcard_with_a_pointer_to_shared() {
    // The default slot is `allow`, where opening everything is what the author meant: the
    // message points at the posture switch `mode = "shared"` rather than the generic error.
    for bad in CATCH_ALL_SPELLINGS {
        let err = classify(bad).unwrap_err();
        assert!(
            err.contains("mode = \"shared\""),
            "{bad:?} should be rejected with a pointer to `mode = \"shared\"`, got: {err}"
        );
    }
}

#[test]
fn the_catch_all_refusal_points_where_each_list_was_going() {
    // The refusal is one syntax check serving four slots, so the way out it offers must be the
    // one *that* author was reaching for. The load-bearing case is `deny`: a `deny = ["*"]`
    // author wants everything **closed**, and a shared message telling them to set
    // `mode = "shared"` points the exact opposite way. Nor may a mute — which changes no
    // verdict — or a test *target* be answered with a posture switch at all.
    for bad in CATCH_ALL_SPELLINGS {
        let deny = classify_in(bad, Slot::Deny).unwrap_err();
        assert!(
            deny.contains("mode = \"none\"") && !deny.contains("shared"),
            "a deny `{bad}` must be pointed at closing the network, never at opening it: {deny}"
        );

        let mute = classify_in(bad, Slot::Mute).unwrap_err();
        assert!(
            mute.contains("re:.*") && !mute.contains("mode ="),
            "a mute `{bad}` is a log filter, so it gets no posture switch: {mute}"
        );

        let target = classify_in(bad, Slot::Target).unwrap_err();
        assert!(
            target.contains("not a host") && !target.contains("mode ="),
            "a test target `{bad}` is a request, not a declaration: {target}"
        );
    }
}

#[test]
fn the_catch_all_refusal_does_not_overclaim() {
    // The message the `allow` slot once carried said a catch-all is something "an allowlist
    // cannot express" — which `re:.*` disproves: it is accepted, and it does match every host.
    // The refusal is a legibility guardrail, not a boundary, so the text must not claim a reach
    // it has not got, and must name the escape hatch it leaves open.
    let err = classify("*").unwrap_err();
    assert!(
        !err.contains("cannot express"),
        "the message must not claim an allowlist cannot express a catch-all: {err}"
    );
    assert!(
        err.contains("re:.*"),
        "the message must name the regex escape hatch it leaves open: {err}"
    );
    let catch_all = classify("re:.*").expect("a catch-all regex stays accepted");
    assert!(
        rule_matches(&catch_all, "anything.example.test", 443, "/"),
        "`re:.*` matches every host — the very thing the `*` refusal cannot prevent"
    );
}

#[test]
fn a_catch_all_regex_is_recognised_however_it_is_spelled() {
    // The refusal of `*` buys legibility, which a catch-all regex would quietly spend: these
    // three spellings have the same reach and none of them says so. `re:` is the sharp one —
    // an empty pattern matches every string, so a bare `re:` *is* `re:.*`.
    for spelling in ["re:.*", "re:", "re:^https://", "re:.", "{GET} re:.*"] {
        assert!(
            classify(spelling).unwrap().opens_every_host(),
            "{spelling:?} opens every host and must be recognised as such"
        );
    }
    // A pattern that pins any part of the host is not a catch-all, and neither is any kind that
    // names its host — including the bounded subdomain wildcard, the widest non-regex rule.
    for bounded in [
        "re:^https://github\\.com/",
        "re:\\.example\\.test",
        "*.nixos.org",
        "github.com:*",
        "10.0.0.5",
        "example.com/api/*",
        "tcp://db.internal:5432",
    ] {
        assert!(
            !classify(bounded).unwrap().opens_every_host(),
            "{bounded:?} is bounded and must not be labelled a catch-all"
        );
    }
}

#[test]
fn a_catch_all_regex_that_only_matches_through_the_canonical_url_is_still_labelled() {
    // The sentinels must be asked the question the matcher answers, not a narrower one. A `re:`
    // rule matches the request as sent *or* its canonical rebuild, and the rebuild is the one
    // form with no query string — so a pattern that cannot hold in the presence of a `?` misses
    // the query-bearing sentinel while matching every real request through the canonical form.
    // Probing only the sent form let such a rule through unlabelled: no `catch_all` flag in
    // `sbx net rules`, no "matches every host" note in `sbx test net`, for a rule that opens the
    // whole network. The label is the whole reason the grammar can refuse a bare `*` and point
    // its author at `re:.*` instead.
    let sneaky = classify("re:^https://[^?]*$").expect("a query-free catch-all compiles");
    assert!(
        sneaky.opens_every_host(),
        "a regex matching every request through its canonical form is a catch-all"
    );
    // Not a false positive: it really does reach every host, on any port and any path —
    // including one whose sent form carries the very query the pattern forbids.
    for (host, port, target) in [
        ("anything.example.test", 443, "/"),
        ("other.example.test", 8443, "/deep/path?q=1"),
    ] {
        assert!(
            rule_matches(&sneaky, host, port, target),
            "`re:^https://[^?]*$` matches {host}:{port}{target}"
        );
    }
    // And the probe is still a probe: matching the canonical form does not make a host-pinned
    // pattern unbounded (the rebuild resolves the path, never the host).
    assert!(
        !classify("re:^https://github\\.com[^?]*$")
            .unwrap()
            .opens_every_host(),
        "a host-pinned pattern must not be labelled a catch-all"
    );
}

#[test]
fn a_catch_all_test_target_is_refused_as_a_request() {
    // The request parsers share the same guard, and there the entry is not a rule at all: no
    // list to point at, no posture to switch, just "name one concrete destination".
    for target in ["https://*", "https://*:8443/x"] {
        let err = parse_url_target(target).unwrap_err();
        assert!(
            err.contains("not a host") && !err.contains("mode ="),
            "{target:?} is a request, so it gets no posture advice: {err}"
        );
    }
    let err = parse_tcp_target("tcp://*:22").unwrap_err();
    assert!(
        err.contains("not a host") && !err.contains("mode ="),
        "a tcp:// target gets the same request-shaped refusal: {err}"
    );
}

#[test]
fn the_bounded_subdomain_wildcard_is_not_a_catch_all() {
    // `*.domain` is a bounded subdomain wildcard, distinct from the rejected bare `*`.
    assert_eq!(
        rule("*.nixos.org").kind,
        RuleKind::Subdomain("nixos.org".into(), Ports::default())
    );
}

#[test]
fn ip_rule_matches_only_that_ip_on_the_default_port() {
    let a = allow(&["1.2.3.4"]);
    assert!(a.permits("1.2.3.4", 443, "/anything"));
    assert!(
        !a.permits("1.2.3.4", 80, "/other"),
        "a bare IP opens only 443 (https implicit)"
    );
    assert!(
        !a.permits("1.2.3.4", 8080, "/"),
        "a bare host opens only the https port"
    );
    assert!(!a.permits("1.2.3.5", 443, "/"));
    assert!(!a.permits("example.com", 443, "/"));
}

#[test]
fn host_rule_is_exact_not_subdomain() {
    let a = allow(&["github.com"]);
    assert!(a.permits("github.com", 443, "/any"));
    assert!(
        a.permits("GITHUB.COM", 443, "/any"),
        "host match is case-insensitive"
    );
    assert!(
        !a.permits("api.github.com", 443, "/"),
        "exact host must not match a subdomain"
    );
}

#[test]
fn subdomain_rule_matches_apex_and_subdomains_only() {
    let a = allow(&["*.nixos.org"]);
    assert!(a.permits("nixos.org", 443, "/"), "apex is included");
    assert!(a.permits("cache.nixos.org", 443, "/nar/x"));
    assert!(a.permits("a.b.nixos.org", 443, "/"));
    assert!(
        !a.permits("nixos.org.evil.com", 443, "/"),
        "suffix spoof must not match"
    );
    assert!(!a.permits("notnixos.org", 443, "/"));
}

#[test]
fn url_rule_is_exact_by_default() {
    let a = allow(&["example.com/ok"]);
    assert!(a.permits("example.com", 443, "/ok"));
    assert!(
        a.permits("example.com", 443, "/ok?x=1"),
        "a query is the same resource"
    );
    assert!(
        a.permits("example.com", 443, "/ok/"),
        "a trailing slash is the same resource"
    );
    assert!(
        !a.permits("example.com", 443, "/ok/sub"),
        "a sub-path is a different resource (use /ok/* for the subtree)"
    );
    assert!(!a.permits("example.com", 443, "/okay"));
    assert!(
        !a.permits("example.com", 8443, "/ok"),
        "a different port is denied"
    );
    assert!(!a.permits("other.com", 443, "/ok"));
}

#[test]
fn a_url_subtree_rule_covers_the_path_and_below() {
    let a = allow(&["example.com/area/*"]);
    assert!(a.permits("example.com", 443, "/area"), "the prefix itself");
    assert!(a.permits("example.com", 443, "/area/sub"));
    assert!(a.permits("example.com", 443, "/area/a/b?x=1"));
    assert!(
        !a.permits("example.com", 443, "/areax"),
        "segment-aware: not a different first segment"
    );
    assert!(!a.permits("example.com", 443, "/other"));
}

#[test]
fn a_url_deny_cannot_be_dodged_for_the_same_resource() {
    // the in-cage agent controls the request; canonicalization makes every same-resource
    // variant of `/secret` reduce to it, so an exact deny cannot be evaded. A *different*
    // sub-resource is a deliberate choice (deny `/secret/*` to include the subtree).
    let p = EgressPolicy::new(vec![rule("github.com")], vec![rule("github.com/secret")]);
    assert!(
        p.permits("github.com", 443, "/public"),
        "unrelated path allowed"
    );
    for same in [
        "/secret",
        "/secret?x=1",    // query append
        "/secret/",       // trailing slash
        "/foo/../secret", // dot-segment
        "/./secret",      // current-dir
        "/%73ecret",      // percent-encoded 's'
    ] {
        assert!(
            !p.permits("github.com", 443, same),
            "exact deny must catch the same-resource variant `{same}`"
        );
    }
    // a genuinely different sub-resource is allowed by the host rule — by design
    assert!(p.permits("github.com", 443, "/secret/sub"));

    // the subtree form blocks the whole tree, including the encoded-slash dodge
    let q = EgressPolicy::new(vec![rule("github.com")], vec![rule("github.com/secret/*")]);
    for blocked in ["/secret", "/secret/sub", "/secret/a/b", "/secret%2fsub"] {
        assert!(
            !q.permits("github.com", 443, blocked),
            "subtree deny must block `{blocked}`"
        );
    }
    assert!(
        q.permits("github.com", 443, "/public"),
        "outside the subtree still allowed"
    );
}

#[test]
fn canonical_segments_normalizes_the_path() {
    assert_eq!(canonical_segments("/a/b/c"), ["a", "b", "c"]);
    assert_eq!(canonical_segments("/a//b/"), ["a", "b"]);
    assert_eq!(canonical_segments("/a/./b/../c"), ["a", "c"]);
    assert_eq!(canonical_segments("/secret?x=1"), ["secret"]);
    assert_eq!(canonical_segments("/%73ecret"), ["secret"]);
    assert_eq!(
        canonical_segments("/a%2fb"),
        ["a", "b"],
        "encoded slash splits"
    );
    assert_eq!(canonical_segments("/"), [] as [&str; 0]);
    // a double-encoded slash stays literal (single-level decode)
    assert_eq!(canonical_segments("/a%252fb"), ["a%2fb"]);
}

#[test]
fn percent_decode_decodes_pairs_and_leaves_stray_percents() {
    assert_eq!(percent_decode("/%41%42"), "/AB");
    assert_eq!(percent_decode("100%"), "100%");
    assert_eq!(percent_decode("a%zzb"), "a%zzb", "non-hex pair left as-is");
}

#[test]
fn classifies_a_regex_entry() {
    assert_eq!(
        rule("re:^https://github\\.com/myorg/").kind,
        RuleKind::Regex {
            pattern: "^https://github\\.com/myorg/".into(),
            re: Regex::new("^https://github\\.com/myorg/").unwrap(),
        }
    );
}

#[test]
fn a_bad_regex_is_rejected() {
    let err = classify("re:(unclosed").unwrap_err();
    assert!(err.contains("invalid regex"), "{err}");
}

#[test]
fn regex_matches_the_reconstructed_url_including_query_and_port() {
    // the regex sees `https://host[:port]path` (path includes any query)
    let a = allow(&["re:^https://api\\.github\\.com/repos/.*\\?.*per_page="]);
    assert!(a.permits("api.github.com", 443, "/repos/x?per_page=100"));
    assert!(
        !a.permits("api.github.com", 443, "/repos/x"),
        "the query the pattern requires is absent"
    );
    // a non-default port shows in the reconstructed URL
    let b = allow(&["re:^https://host\\.test:8443/"]);
    assert!(b.permits("host.test", 8443, "/x"));
    assert!(
        !b.permits("host.test", 443, "/x"),
        "port 443 omits the :port"
    );
}

/// A `re:` rule is matched against the request as sent **and** against its canonical form, and
/// each form catches what the other cannot.
///
/// A deny anchored on a path saw only the raw string, so `/foo/../admin` walked past it while
/// the origin server resolved it to `/admin` and served it — the evasion the canonical segments
/// exist to close, still open on this one rule kind. Canonicalizing *instead* would have broken
/// the other half: a regex naming a query string finds nothing in a form the query was removed
/// from, and a deny that stops matching opens what it was written to close.
#[test]
fn a_regex_rule_sees_both_the_request_as_sent_and_its_canonical_form() {
    // Only the canonical form can satisfy this one.
    let d = deny_with_allow_all(&["re:^https://api\\.example\\.com/admin$"]);
    assert!(
        !d.permits("api.example.com", 443, "/admin"),
        "the plain path"
    );
    assert!(
        !d.permits("api.example.com", 443, "/foo/../admin"),
        "dot segments the origin server would resolve"
    );
    assert!(
        !d.permits("api.example.com", 443, "/admin?x=1"),
        "a query the anchored pattern cannot see past"
    );
    assert!(
        d.permits("api.example.com", 443, "/admins"),
        "the negative control: a neighbouring path is not caught"
    );

    // Only the raw form can satisfy this one, and it still works.
    let q = deny_with_allow_all(&["re:.*\\?debug=1$"]);
    assert!(!q.permits("api.example.com", 443, "/x?debug=1"));
    assert!(q.permits("api.example.com", 443, "/x"));
}

/// An allow-everything policy with one regex deny, which is how a deny is exercised alone.
fn deny_with_allow_all(deny: &[&str]) -> EgressPolicy {
    EgressPolicy::new(
        vec![rule("api.example.com")],
        deny.iter().map(|d| rule(d)).collect(),
    )
}

#[test]
fn a_structured_host_never_matches_a_lookalike_or_subdomain() {
    // the user's requirement: an exact `Host` (no `re:`) matches only that host —
    // never `<host>.evil.com` nor a `<prefix>host`, which a fumbled regex would.
    let a = allow(&["api.github.com"]);
    assert!(a.permits("api.github.com", 443, "/"));
    assert!(!a.permits("api.github.com.evil.com", 443, "/"));
    assert!(!a.permits("myapi.github.com", 443, "/"));
    assert!(!a.permits("evil.com", 443, "/?u=api.github.com"));
}

#[test]
fn a_regex_deny_carves_out_of_an_allow() {
    // deny still wins when the deny rule is a regex
    let p = EgressPolicy::new(
        vec![rule("github.com")],
        vec![rule("re:^https://github\\.com/.*/secrets")],
    );
    assert!(p.permits("github.com", 443, "/myorg/repo"));
    assert!(
        !p.permits("github.com", 443, "/myorg/secrets"),
        "the regex deny wins over the host allow"
    );
}

#[test]
fn explain_names_the_deciding_rule() {
    let p = EgressPolicy::new(vec![rule("*.nixos.org")], vec![rule("evil.nixos.org")]);
    // allowed by the subdomain rule
    match p.explain("cache.nixos.org", 443, "/x", "GET") {
        Decision::AllowedBy(r) => assert_eq!(r.to_string(), "https://*.nixos.org"),
        d => panic!("expected AllowedBy, got {d:?}"),
    }
    // denied by the deny rule, which wins over the matching subdomain allow
    match p.explain("evil.nixos.org", 443, "/x", "GET") {
        Decision::DeniedBy(r) => assert_eq!(r.to_string(), "https://evil.nixos.org"),
        d => panic!("expected DeniedBy, got {d:?}"),
    }
    // denied by default when no allow matches
    assert_eq!(
        p.explain("other.com", 443, "/", "GET"),
        Decision::DeniedDefault
    );
}

#[test]
fn rule_matches_canonicalizes_like_explain() {
    // the same canonicalization explain uses: an exact host/path rule matches a
    // same-resource variant of the path, and not a different host or sub-resource.
    let r = rule("github.com/secret");
    assert!(rule_matches(&r, "github.com", 443, "/secret"));
    assert!(
        rule_matches(&r, "GITHUB.COM", 443, "/secret?x=1"),
        "host case and a query are the same request"
    );
    assert!(
        rule_matches(&r, "github.com", 443, "/foo/../secret"),
        "a dot-segment resolves to the same path"
    );
    assert!(!rule_matches(&r, "github.com", 443, "/other"));
    assert!(!rule_matches(&r, "evil.com", 443, "/secret"));
    // a bare host rule matches any path on its web ports, not an off port
    let h = rule("api.github.com");
    assert!(rule_matches(&h, "api.github.com", 443, "/anything"));
    assert!(!rule_matches(&h, "api.github.com", 22, "/"));
}

#[test]
fn parse_url_target_extracts_host_port_and_path() {
    assert_eq!(
        parse_url_target("https://github.com/a/b?x=1").unwrap(),
        ("github.com".to_string(), 443, "/a/b?x=1".to_string())
    );
    assert_eq!(
        parse_url_target("https://h.test:8443").unwrap(),
        ("h.test".to_string(), 8443, "/".to_string())
    );
    // a bracketed IPv6 host, with and without an explicit port
    assert_eq!(
        parse_url_target("https://[::1]:8080/x").unwrap(),
        ("::1".to_string(), 8080, "/x".to_string())
    );
    assert_eq!(
        parse_url_target("https://[2001:db8::1]/a/b").unwrap(),
        ("2001:db8::1".to_string(), 443, "/a/b".to_string())
    );
    // an IP-literal host is canonicalized (one spelling, so a string-matched URL host
    // cannot be dodged by an alternate form)
    assert_eq!(
        parse_url_target("https://[0:0:0:0:0:0:0:1]/x").unwrap(),
        ("::1".to_string(), 443, "/x".to_string())
    );
    assert!(
        parse_url_target("https://[::1/x").is_err(),
        "unterminated bracket rejected"
    );
    assert!(
        parse_url_target("https://[notanip]/x").is_err(),
        "non-IP inside brackets rejected"
    );
    assert!(
        parse_url_target("ftp://x/").is_err(),
        "non-http(s) rejected"
    );
    assert!(parse_url_target("not a url").is_err());
}

#[test]
fn a_url_rule_matches_an_ipv6_host() {
    let a = allow(&["[::1]:8080/secret"]);
    assert!(a.permits("::1", 8080, "/secret"));
    assert!(!a.permits("::1", 443, "/secret"), "wrong port");
    assert!(!a.permits("::1", 8080, "/other"), "wrong path");
    assert!(!a.permits("::2", 8080, "/secret"), "a different address");
}

#[test]
fn ipv6_host_forms_normalize_so_a_url_deny_is_not_dodged() {
    // the rule and the request use DIFFERENT textual forms of the same IPv6 address.
    // a `Url` host is matched as a plain string, so without canonicalization a literal-path
    // deny would fail open for an alternate spelling — the host analog of the path dodge.
    let p = EgressPolicy::new(vec![rule("[::1]:*")], vec![rule("[::1]/secret")]);
    // the long form must still be caught by the deny written in the short form
    assert!(
        !p.permits("0:0:0:0:0:0:0:1", 443, "/secret"),
        "a deny must catch a different spelling of the same address"
    );
    // the allow still applies on another resource/port
    assert!(p.permits("0:0:0:0:0:0:0:1", 8080, "/elsewhere"));
    // a leading-zeros spelling normalizes too
    assert!(!p.permits("::0001", 443, "/secret"));
}

#[test]
fn deny_always_wins_over_allow() {
    // a broad allow carved out by a host deny
    let p = EgressPolicy::new(vec![rule("*.nixos.org")], vec![rule("evil.nixos.org")]);
    assert!(p.permits("cache.nixos.org", 443, "/"), "allowed subdomain");
    assert!(
        !p.permits("evil.nixos.org", 443, "/"),
        "deny wins over the allowing subdomain rule"
    );

    // a host allow carved out by an exact-URL deny: only that path is blocked
    let p = EgressPolicy::new(vec![rule("github.com")], vec![rule("github.com/secret")]);
    assert!(p.permits("github.com", 443, "/public"));
    assert!(
        !p.permits("github.com", 443, "/secret"),
        "the denied exact URL is blocked while the rest of the host is allowed"
    );
}

#[test]
fn a_deny_with_no_matching_allow_is_still_denied() {
    // deny never *grants* anything: a host only in the deny list is not reachable
    let p = EgressPolicy::new(vec![], vec![rule("evil.com")]);
    assert!(!p.permits("evil.com", 443, "/"));
    assert!(
        !p.permits("other.com", 443, "/"),
        "empty allow permits nothing"
    );
}

#[test]
fn an_empty_policy_permits_nothing() {
    let p = EgressPolicy::default();
    assert!(!p.permits("example.com", 443, "/"));
    assert!(p.allow_rules().is_empty() && p.deny_rules().is_empty());
}

#[test]
fn ask_notice_shows_by_default_and_inverts_cleanly() {
    // The notice is shown by default, and crucially `new()` and the derived `default()` must
    // agree (the field is stored inverted so the derive's `false` means "shown").
    assert!(EgressPolicy::new(vec![], vec![]).ask_notice());
    assert!(EgressPolicy::default().ask_notice());
    // `with_ask_notice(false)` silences it; `true` restores it.
    assert!(!EgressPolicy::default().with_ask_notice(false).ask_notice());
    assert!(
        EgressPolicy::default()
            .with_ask_notice(false)
            .with_ask_notice(true)
            .ask_notice()
    );
}

#[test]
fn default_deny_is_the_constructor_default() {
    // `new` and `Default` both deny by default: an unmatched host gets `DeniedDefault`.
    let p = EgressPolicy::new(vec![rule("github.com")], vec![]);
    assert_eq!(p.default_action(), DefaultAction::Deny);
    assert_eq!(
        p.explain("other.com", 443, "/", "GET"),
        Decision::DeniedDefault
    );
    assert_eq!(
        EgressPolicy::default().default_action(),
        DefaultAction::Deny
    );
}

#[test]
fn mute_is_a_log_filter_that_never_touches_the_verdict() {
    // A deny-by-default policy that mutes one host. `mute` is a `dontaudit` log filter — it must
    // change no verdict, only whether the refusal is reported by `muted`.
    let policy = EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("play.googleapis.com")]);

    // The muted host is still DENIED (mute changed the verdict of nothing) ...
    assert_eq!(
        policy.explain("play.googleapis.com", 443, "/log", "POST"),
        Decision::DeniedDefault
    );
    // ... and it reports muted, so the proxy keeps its refusal out of the default log.
    assert!(policy.muted("play.googleapis.com", 443, Some("/log"), Some("POST")));

    // A different denied host is NOT muted — its refusal still logs.
    assert!(!policy.muted("api.example.com", 443, Some("/x"), Some("GET")));
    // A policy with no mute rules mutes nothing.
    assert!(!EgressPolicy::new(vec![], vec![]).muted(
        "play.googleapis.com",
        443,
        Some("/log"),
        None
    ));
    // The mute set is surfaced for `sbx net rules` / `sbx config show`.
    assert_eq!(policy.mute_rules().len(), 1);
}

#[test]
fn mute_honors_method_and_path_scope_like_a_verdict_rule() {
    // A method- and path-scoped mute entry: only a matching verb+path is muted, so a mute reads
    // identically to an allow/deny rule and never over-suppresses.
    let policy =
        EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("{POST} play.googleapis.com/log")]);
    assert!(policy.muted("play.googleapis.com", 443, Some("/log"), Some("POST")));
    // A different verb to the same path is not muted (its refusal still logs).
    assert!(!policy.muted("play.googleapis.com", 443, Some("/log"), Some("GET")));
    // A different path is not muted.
    assert!(!policy.muted("play.googleapis.com", 443, Some("/other"), Some("POST")));
    // A method-less request (an early-CONNECT block) does not match a method-scoped mute — the
    // safe direction (show the log) when the verb is unknown.
    assert!(!policy.muted("play.googleapis.com", 443, None, None));
}

#[test]
fn mute_covers_cleartext_port_80_and_is_transport_agnostic() {
    // A bare-host mute is a pure log-noise filter: it silences the host's refusals on EVERY port
    // and scheme, so a component-updater's cleartext `http://host:80` noise is muted by the same
    // `host` entry that mutes its `:443` traffic — the port is not load-bearing for `mute`.
    let policy = EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("update.googleapis.com")]);
    // :443 (TLS) — muted, as before.
    let p = Some("/service/update2/json");
    assert!(policy.muted("update.googleapis.com", 443, p, Some("POST")));
    // :80 (cleartext HTTP) — now ALSO muted (the gap this fix closes).
    assert!(policy.muted("update.googleapis.com", 80, p, Some("POST")));
    // An arbitrary other port too — `mute` names a host, not a port.
    assert!(policy.muted("update.googleapis.com", 8080, Some("/x"), Some("GET")));
    // A different host is still not muted.
    assert!(!policy.muted("api.example.com", 80, Some("/x"), Some("GET")));

    // Transport-agnostic on the RULE side too: an `http://` mute (an `L7Clear` rule, previously
    // ignored by `muted`) now silences the host on both schemes.
    let clear =
        EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("http://clients2.google.com")]);
    assert!(clear.muted(
        "clients2.google.com",
        80,
        Some("/time/1/current"),
        Some("GET")
    ));
    assert!(clear.muted("clients2.google.com", 443, Some("/x"), Some("GET")));

    // Path/method scope stays precise even though the port is ignored.
    let scoped = EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("{POST} host.example/log")]);
    assert!(scoped.muted("host.example", 80, Some("/log"), Some("POST")));
    assert!(!scoped.muted("host.example", 80, Some("/log"), Some("GET")));
    assert!(!scoped.muted("host.example", 80, Some("/other"), Some("POST")));

    // And `mute` still changes NO verdict — a muted cleartext host is still denied.
    assert_eq!(
        policy.explain_clear("update.googleapis.com", 80, "/service/update2/json", "POST"),
        Decision::DeniedDefault
    );
}

#[test]
fn default_allow_permits_the_unmatched_but_deny_still_wins() {
    // A denylist: allow-by-default with a deny carve-out. The default action flips the verdict
    // for an unmatched host, but deny still wins and a matching allow is still named.
    let p = EgressPolicy::new(vec![], vec![rule("evil.com")]).with_default(DefaultAction::Allow);
    assert_eq!(p.default_action(), DefaultAction::Allow);

    // an unlisted host is now permitted (the whole point of allow-by-default)
    assert!(p.permits("anything.example", 443, "/"));
    assert_eq!(
        p.explain("anything.example", 443, "/", "GET"),
        Decision::AllowedDefault
    );

    // a deny rule still wins, even under allow-by-default
    assert!(!p.permits("evil.com", 443, "/"));
    assert!(matches!(
        p.explain("evil.com", 443, "/", "GET"),
        Decision::DeniedBy(_)
    ));

    // an explicit allow rule is still reported as `AllowedBy` (it names the deciding rule),
    // which the SSRF private-host exception relies on — `AllowedDefault` has no such rule
    let q = EgressPolicy::new(vec![rule("10.0.0.1")], vec![]).with_default(DefaultAction::Allow);
    assert!(matches!(
        q.explain("10.0.0.1", 443, "/", "GET"),
        Decision::AllowedBy(_)
    ));
}

#[test]
fn a_trailing_dot_fqdn_cannot_dodge_a_deny() {
    // `evil.com.` is the absolute-FQDN spelling — DNS resolves it identically, but rules are
    // always dot-free. canonical_host strips the trailing dot so the request still hits the
    // deny; under allow-by-default it must NOT slip through to AllowedDefault.
    let p = EgressPolicy::new(vec![], vec![rule("evil.com")]).with_default(DefaultAction::Allow);
    // one trailing dot, and a doubled dot (which DNS resolves to the same host) — both denied
    for host in ["evil.com.", "evil.com..", "evil.com..."] {
        assert!(!p.permits(host, 443, "/"), "{host} must be denied");
        assert!(matches!(
            p.explain(host, 443, "/", "GET"),
            Decision::DeniedBy(_)
        ));
    }
    // a subdomain deny is likewise not dodged by trailing dots
    let q = EgressPolicy::new(vec![], vec![rule("*.evil.com")]).with_default(DefaultAction::Allow);
    assert!(!q.permits("api.evil.com.", 443, "/"));
    assert!(!q.permits("api.evil.com..", 443, "/"));
}

#[test]
fn display_round_trips_each_kind() {
    // every L7 host kind renders the implicit `https://`; the default port 443 is absorbed
    // (renders bare), an explicit non-default port set is kept.
    assert_eq!(rule("1.2.3.4").to_string(), "https://1.2.3.4");
    assert_eq!(rule("github.com").to_string(), "https://github.com");
    assert_eq!(rule("*.nixos.org").to_string(), "https://*.nixos.org");
    // a path rule carries the scheme too
    assert_eq!(rule("example.com/x").to_string(), "https://example.com/x");
    assert_eq!(
        rule("example.com:8443/x").to_string(),
        "https://example.com:8443/x"
    );
    assert_eq!(
        rule("example.com:*/admin").to_string(),
        "https://example.com:*/admin"
    );
    // an explicit :443 equals the default, so it renders bare (== `https://github.com`)
    assert_eq!(rule("github.com:443").to_string(), "https://github.com");
    assert_eq!(
        rule("github.com:80,443,8443").to_string(),
        "https://github.com:80,443,8443"
    );
    assert_eq!(
        rule("internal.test:8000-8100").to_string(),
        "https://internal.test:8000-8100"
    );
    assert_eq!(rule("github.com:*").to_string(), "https://github.com:*");
    // {80,443} is no longer the default, so it now renders explicitly (sorted)
    assert_eq!(
        rule("github.com:443,80").to_string(),
        "https://github.com:80,443"
    );
    // IPv6: bare needs no brackets; a non-default port spec re-brackets it; :443 is absorbed
    assert_eq!(rule("::1").to_string(), "https://::1");
    assert_eq!(rule("[::1]:443").to_string(), "https://::1");
    assert_eq!(
        rule("[2001:db8::1]:*").to_string(),
        "https://[2001:db8::1]:*"
    );
    // a path rule with an IPv6 host stays bracketed
    assert_eq!(
        rule("[::1]:8080/secret").to_string(),
        "https://[::1]:8080/secret"
    );
    assert_eq!(
        rule("[2001:db8::1]/a/b").to_string(),
        "https://[2001:db8::1]/a/b"
    );
    // every rendered form re-classifies to the same rule (canonical, stable)
    for s in [
        "1.2.3.4",
        "github.com",
        "*.nixos.org",
        "example.com:8443/x",
        "github.com:80,443,8443",
        "[2001:db8::1]:*",
    ] {
        assert_eq!(
            classify(s).unwrap(),
            classify(&rule(s).to_string()).unwrap()
        );
    }
}

#[test]
fn a_method_prefix_attaches_to_each_kind_and_a_bare_rule_is_unspecified() {
    // a method-less rule is `Unspecified` (all verbs now, but a per-app default may narrow it);
    // an explicit `{*}` is `Any` (all verbs, never narrowed).
    assert_eq!(rule("github.com").methods, Methods::Unspecified);
    assert_eq!(rule("{*} github.com").methods, Methods::Any);
    // the prefix attaches to every structured kind and to a regex, verbs sorted + de-duped
    assert_eq!(
        rule("{GET,HEAD} github.com").methods,
        Methods::Only(vec!["GET".into(), "HEAD".into()])
    );
    assert_eq!(
        rule("{POST,GET,GET} *.nixos.org").methods,
        Methods::Only(vec!["GET".into(), "POST".into()]),
        "verbs are sorted and de-duplicated"
    );
    assert_eq!(
        rule("{GET} 1.2.3.4").methods,
        Methods::Only(vec!["GET".into()])
    );
    assert_eq!(
        rule("{PUT} example.com:443/path").methods,
        Methods::Only(vec!["PUT".into()])
    );
    // the prefix sits before `re:`, so the regex body's own `{n,m}` quantifiers are untouched
    let r = rule("{POST} re:^https://x\\.test/a{2,3}$");
    assert_eq!(r.methods, Methods::Only(vec!["POST".into()]));
    assert!(matches!(r.kind, RuleKind::Regex { .. }));
    // the kind is parsed correctly behind the prefix
    assert_eq!(
        rule("{GET} github.com:443").kind,
        RuleKind::Host("github.com".into(), Ports::Ranges(vec![(443, 443)]))
    );
}

#[test]
fn a_method_prefix_round_trips_through_display() {
    // a qualified rule renders `{V,V} <scheme><rule>` and round-trips; the verbs are normalized,
    // the implicit https:// shown, and the default :443 absorbed.
    assert_eq!(
        rule("{GET,HEAD} github.com:443").to_string(),
        "{GET,HEAD} https://github.com"
    );
    // a regex shows its method prefix but no scheme (the pattern carries its own)
    assert_eq!(rule("{POST} re:^x$").to_string(), "{POST} re:^x$");
    assert_eq!(
        rule("{HEAD,GET} example.com/p").to_string(),
        "{GET,HEAD} https://example.com/p",
        "display shows the sorted set and the scheme"
    );
    // a method-less L7 rule renders the implicit scheme (its canonical equal form)
    assert_eq!(rule("github.com").to_string(), "https://github.com");
    // an explicit `{*}` (all verbs) round-trips with its prefix
    assert_eq!(rule("{*} github.com").to_string(), "{*} https://github.com");
}

#[test]
fn apply_default_methods_rewrites_only_unspecified_l7_allow_rules() {
    // An app's read-by-default posture: an unscoped (Unspecified) L7 allow inherits the default;
    // an explicit `{*}` or `{VERB}` keeps its verbs; a deny is untouched (stays broad); a raw
    // `tcp://` rule has no methods and must not gain an (invalid) prefix. Distinct hosts so each
    // verdict is unambiguous.
    let mut p = EgressPolicy::new(
        vec![
            rule("read.test"),           // Unspecified L7 → rewritten to the default
            rule("{*} open.test"),       // explicit all-verbs → kept
            rule("{POST} post.test"),    // explicit set → kept
            rule("tcp://raw.test:5432"), // L4 raw → untouched (no methods)
        ],
        vec![rule("evil.test")], // deny stays broad (all verbs)
    );
    p.apply_default_methods(&Methods::Only(vec!["GET".into(), "HEAD".into()]));
    let allow = p.allow_rules();
    assert_eq!(
        allow[0].methods,
        Methods::Only(vec!["GET".into(), "HEAD".into()]),
        "an Unspecified L7 allow inherits the default"
    );
    assert_eq!(allow[1].methods, Methods::Any, "an explicit {{*}} is kept");
    assert_eq!(
        allow[2].methods,
        Methods::Only(vec!["POST".into()]),
        "an explicit verb set is kept"
    );
    assert_eq!(
        allow[3].methods,
        Methods::Unspecified,
        "a raw tcp:// rule keeps no methods (it would be an invalid prefix)"
    );
    assert_eq!(
        p.deny_rules()[0].methods,
        Methods::Unspecified,
        "a deny rule is never narrowed by default_methods"
    );

    // The effect is real at match time: the unscoped host is now read-only.
    assert!(p.permits("read.test", 443, "/"), "GET still passes");
    assert!(
        matches!(
            p.explain("read.test", 443, "/", "POST"),
            Decision::DeniedDefault
        ),
        "POST to the unscoped host is denied after the default narrows it"
    );
    // the {*} host still takes every verb.
    assert!(matches!(
        p.explain("open.test", 443, "/", "POST"),
        Decision::AllowedBy(_)
    ));

    // an `Any` default (an app's `default_methods = ["*"]`) is a no-op — it leaves rules
    // all-verbs (Unspecified), so the app opts out of read-by-default.
    let mut q = EgressPolicy::new(vec![rule("read.test")], vec![]);
    q.apply_default_methods(&Methods::Any);
    assert_eq!(q.allow_rules()[0].methods, Methods::Unspecified);

    // parse_default_methods: `["*"]` → Any; a verb list → Only; empty / mixed-`*` rejected.
    assert_eq!(parse_default_methods(&["*".into()]).unwrap(), Methods::Any);
    assert_eq!(
        parse_default_methods(&["POST".into(), "GET".into()]),
        Ok(Methods::Only(vec!["GET".into(), "POST".into()])),
        "verbs are sorted and de-duplicated"
    );
    assert!(parse_default_methods(&[]).is_err());
    assert!(parse_default_methods(&["GET".into(), "*".into()]).is_err());
    assert!(parse_default_methods(&["lower".into()]).is_err());
}

#[test]
fn rejects_a_malformed_method_prefix() {
    for bad in [
        "{} github.com",         // empty set
        "{GET,} github.com",     // trailing empty item
        "{,GET} github.com",     // leading empty item
        "{get} github.com",      // lowercase
        "{GET POST} github.com", // space instead of comma (not all uppercase)
        "{GET github.com",       // unterminated
        "{GE1} github.com",      // a digit is not a method letter
    ] {
        assert!(classify(bad).is_err(), "{bad:?} should be rejected");
    }
}

#[test]
fn a_method_restricted_rule_matches_only_those_verbs() {
    // a GET/HEAD-only allow: reads pass, a write falls to deny-by-default
    let p = allow(&["{GET,HEAD} api.test:443"]);
    assert!(
        p.permits("api.test", 443, "/x"),
        "GET (the permits default) passes"
    );
    assert!(
        matches!(
            p.explain("api.test", 443, "/x", "head"),
            Decision::AllowedBy(_)
        ),
        "method match is case-insensitive (HEAD)"
    );
    assert_eq!(
        p.explain("api.test", 443, "/x", "POST"),
        Decision::DeniedDefault,
        "a write is not permitted by a GET/HEAD-only allow"
    );
    // a method-less rule admits every verb
    let q = allow(&["other.test:443"]);
    assert!(matches!(
        q.explain("other.test", 443, "/x", "DELETE"),
        Decision::AllowedBy(_)
    ));
}

#[test]
fn a_method_can_be_denied_out_of_an_open_host() {
    // open the host for all verbs, then deny just POST — deny wins for that verb only
    let p = EgressPolicy::new(
        vec![rule("api.test:443")],
        vec![rule("{POST} api.test:443")],
    );
    assert!(matches!(
        p.explain("api.test", 443, "/x", "GET"),
        Decision::AllowedBy(_)
    ));
    assert!(matches!(
        p.explain("api.test", 443, "/x", "POST"),
        Decision::DeniedBy(_)
    ));
}

#[test]
fn method_denied_distinguishes_a_verb_block_from_an_unknown_host() {
    let p = allow(&["{GET} api.test:443"]);
    // the host is allowed, but POST is not its verb → "denied because of method"
    assert!(p.method_denied("api.test", 443, "/x", "POST"));
    assert!(
        p.method_denied("api.test", 443, "/x", "post"),
        "case-insensitive"
    );
    // GET is permitted, so it is not a method-block
    assert!(!p.method_denied("api.test", 443, "/x", "GET"));
    // a host no allow rule names at all is not a method-block (it is just unknown)
    assert!(!p.method_denied("other.test", 443, "/x", "POST"));
    // a method-less allow never reports a method-block
    let q = allow(&["api.test:443"]);
    assert!(!q.method_denied("api.test", 443, "/x", "POST"));
}

#[test]
fn a_tcp_allow_splices_only_its_host_and_port() {
    let p = allow(&["tcp://ssh.example.com:22"]);
    assert!(matches!(
        p.l4_decision("ssh.example.com", 22),
        L4Decision::Splice(_)
    ));
    // a different port on the same host is not the splice's concern → falls to the L7 path
    assert_eq!(p.l4_decision("ssh.example.com", 2222), L4Decision::NoMatch);
    // a different host is not spliced
    assert_eq!(p.l4_decision("other.example.com", 22), L4Decision::NoMatch);
    // and the host carries no L7 rule, so the inspected path denies it
    assert_eq!(
        p.explain("ssh.example.com", 22, "/", "GET"),
        Decision::DeniedDefault
    );
}

#[test]
fn only_an_allowed_tcp_rule_reports_that_a_splice_can_happen() {
    // What the cage's trust anchor has to carry hangs on this one answer, so each way of *not*
    // being a splice is asserted rather than assumed.
    assert!(!allow(&[]).splices_any(), "an empty policy splices nothing");
    assert!(
        !allow(&["api.example.com", "http://plain.example.com/x"]).splices_any(),
        "both inspected layers terminate at the proxy's own leaf"
    );
    assert!(
        allow(&["api.example.com", "tcp://db.example.com:5432"]).splices_any(),
        "one tcp:// rule among inspected ones is enough"
    );
    // A deny never opens a splice, so a tcp:// deny alone does not report one.
    assert!(
        !EgressPolicy::new(vec![], vec![rule("tcp://db.example.com:5432")]).splices_any(),
        "a deny names a destination that is never reached"
    );
    // And a deny that suppresses the only splice still reports one: the answer over-reports on
    // purpose (roots nothing needs cost bytes; missing roots would fail a handshake).
    let suppressed = EgressPolicy::new(
        vec![rule("tcp://db.example.com:5432")],
        vec![rule("db.example.com:*")],
    );
    assert!(matches!(
        suppressed.l4_decision("db.example.com", 5432),
        L4Decision::Suppressed(_)
    ));
    assert!(suppressed.splices_any());
}

#[test]
fn the_l4_and_l7_layers_are_partitioned() {
    // an L7 allow never enables a raw splice...
    let l7 = allow(&["api.example.com:443"]);
    assert_eq!(l7.l4_decision("api.example.com", 443), L4Decision::NoMatch);
    // ...and a tcp:// (L4) allow never satisfies the inspected L7 verdict.
    let l4 = allow(&["tcp://api.example.com:443"]);
    assert_eq!(
        l4.explain("api.example.com", 443, "/", "GET"),
        Decision::DeniedDefault
    );
    assert!(matches!(
        l4.l4_decision("api.example.com", 443),
        L4Decision::Splice(_)
    ));
}

/// The partition holds for **deny** as well as for allow, and the two other planes do not
/// share it. Pinned because nothing else states it and the three planes disagree on purpose.
///
/// The inspected plane consults only its own layer's denies: a `tcp://` or `http://` deny names
/// a plane, and naming one plane is not naming another. The cleartext and splice planes match a
/// deny by host and port whatever layer wrote it, which is what makes a **host-level** deny the
/// one spelling that reaches everywhere — the spelling the guide tells an operator to use.
///
/// So the asymmetry is real and it is one-way, and a reader who does not know which way round
/// it goes cannot work it out from the rules: that is what this test is for.
#[test]
fn a_scheme_qualified_deny_names_a_plane_and_only_binds_that_plane() {
    let inspected_allow = || vec![rule("api.example.com:443")];

    // A `tcp://` deny does not reach the inspected verdict...
    let by_tcp = EgressPolicy::new(inspected_allow(), vec![rule("tcp://api.example.com:443")]);
    assert!(
        matches!(
            by_tcp.explain("api.example.com", 443, "/", "GET"),
            Decision::AllowedBy(_)
        ),
        "a tcp:// deny governs the splice decision, not the inspected one"
    );
    // ...nor does an `http://` one, on the port it would have to name to match at all.
    let by_http = EgressPolicy::new(inspected_allow(), vec![rule("http://api.example.com:443")]);
    assert!(matches!(
        by_http.explain("api.example.com", 443, "/", "GET"),
        Decision::AllowedBy(_)
    ));

    // The spelling that does reach it is the host-level one, which is what the guide shows.
    let bare = EgressPolicy::new(inspected_allow(), vec![rule("api.example.com:443")]);
    assert!(matches!(
        bare.explain("api.example.com", 443, "/", "GET"),
        Decision::DeniedBy(_)
    ));

    // And the other two planes take that same `tcp://` deny, whatever layer wrote it: the
    // inspected plane is the one that scopes, not the schemes that are scoped.
    let clear = EgressPolicy::new(
        vec![rule("http://api.example.com:443")],
        vec![rule("tcp://api.example.com:443")],
    );
    assert!(matches!(
        clear.explain_clear("api.example.com", 443, "/", "GET"),
        Decision::DeniedBy(_)
    ));
    let spliced = EgressPolicy::new(
        vec![rule("tcp://api.example.com:443")],
        vec![rule("http://api.example.com:443")],
    );
    assert!(matches!(
        spliced.l4_decision("api.example.com", 443),
        L4Decision::Suppressed(_)
    ));
}

#[test]
fn a_host_level_deny_suppresses_a_splice_deny_wins() {
    // an L7 bare deny on the host suppresses a tcp:// allow → Suppressed (the connection goes to
    // the inspected path, where it is denied) — `deny host` cannot be bypassed by a `tcp://` allow.
    let p = EgressPolicy::new(
        vec![rule("tcp://api.example.com:443")],
        vec![rule("api.example.com")],
    );
    assert!(matches!(
        p.l4_decision("api.example.com", 443),
        L4Decision::Suppressed(_)
    ));

    // a tcp:// subdomain allow carved by a tcp:// host deny: the carved host is suppressed, a
    // sibling still splices.
    let q = EgressPolicy::new(
        vec![rule("tcp://*.corp:5432")],
        vec![rule("tcp://secret.corp:5432")],
    );
    assert!(matches!(
        q.l4_decision("secret.corp", 5432),
        L4Decision::Suppressed(_)
    ));
    assert!(matches!(
        q.l4_decision("db.corp", 5432),
        L4Decision::Splice(_)
    ));

    // a *path-specific* deny does NOT suppress a splice: it cannot match the path-less CONNECT
    // request (a raw stream has no path) — the documented L4 tradeoff. A *host-level* regex deny,
    // which carries no path, does suppress (the dedicated test below).
    let r = EgressPolicy::new(
        vec![rule("tcp://api.example.com:443")],
        vec![rule("api.example.com/secret")],
    );
    assert!(matches!(
        r.l4_decision("api.example.com", 443),
        L4Decision::Splice(_)
    ));
}

#[test]
fn a_host_level_regex_or_url_deny_suppresses_a_splice() {
    // The deny-wins guarantee reaches the splice path: a deny that matches the path-less CONNECT
    // request (`https://host[:port]/`) suppresses a `tcp://` allow, so `deny host` cannot be
    // bypassed by raw-splicing the same host. (Ports below are 443, which lies in both the old
    // {80,443} bare default and the later {443} one, so these stay stable across that change.)

    // a host-level regex deny (no path) matches the synthetic URL → suppresses the splice, and
    // the decision names the deciding deny (so `sbx test net` can explain why it did not splice).
    let p = EgressPolicy::new(
        vec![rule("tcp://evil.com:443")],
        vec![rule(r"re:^https://evil\.com")],
    );
    assert!(matches!(
        p.l4_decision("evil.com", 443),
        L4Decision::Suppressed(_)
    ));

    // a Url deny on the root subtree (`/*`) matches the path-less request → suppresses.
    let q = EgressPolicy::new(vec![rule("tcp://evil.com:443")], vec![rule("evil.com/*")]);
    assert!(matches!(
        q.l4_decision("evil.com", 443),
        L4Decision::Suppressed(_)
    ));

    // a *path-specific* regex deny does NOT match the path-less request → the splice proceeds
    // (the raw stream has no path; block the host with a host-level deny instead).
    let r = EgressPolicy::new(
        vec![rule("tcp://evil.com:443")],
        vec![rule(r"re:^https://evil\.com/secret")],
    );
    assert!(matches!(
        r.l4_decision("evil.com", 443),
        L4Decision::Splice(_)
    ));

    // a regex deny on a *different* host does not suppress.
    let s = EgressPolicy::new(
        vec![rule("tcp://evil.com:443")],
        vec![rule(r"re:^https://other\.com")],
    );
    assert!(matches!(
        s.l4_decision("evil.com", 443),
        L4Decision::Splice(_)
    ));
}

#[test]
fn a_splice_suppression_is_port_scoped_for_structured_denies_but_not_regex() {
    // The asymmetry to know: a host-level regex deny matches *every* port (the synthetic URL is
    // `https://host:port/`, and `^https://h` matches any of them), so it blocks a splice on any
    // port. A *structured* host deny is bound to its port set, so it blocks only those ports.
    // (Port 22 is outside both the old {80,443} and the later {443} bare default, so the
    // structured-deny case stays `Splice` across that change — a stable assertion.)
    let by_regex = EgressPolicy::new(
        vec![rule("tcp://evil.com:22")],
        vec![rule(r"re:^https://evil\.com")],
    );
    assert!(matches!(
        by_regex.l4_decision("evil.com", 22),
        L4Decision::Suppressed(_)
    ));

    // an explicit `:*` deny is port-agnostic and also suppresses every port.
    let by_star = EgressPolicy::new(vec![rule("tcp://evil.com:22")], vec![rule("evil.com:*")]);
    assert!(matches!(
        by_star.l4_decision("evil.com", 22),
        L4Decision::Suppressed(_)
    ));

    // a bare structured host deny (default port only) does NOT reach a :22 splice — to block all
    // ports use `deny evil.com:*` or a port-agnostic regex.
    let by_bare = EgressPolicy::new(vec![rule("tcp://evil.com:22")], vec![rule("evil.com")]);
    assert!(matches!(
        by_bare.l4_decision("evil.com", 22),
        L4Decision::Splice(_)
    ));
}

#[test]
fn a_splice_is_strictly_opt_in_even_under_allow_by_default() {
    // a denylist (allow-by-default) posture must NOT silently splice everything — only an
    // explicit tcp:// allow does, so an un-ruled host still takes the inspected L7 path.
    let p = EgressPolicy::new(vec![], vec![]).with_default(DefaultAction::Allow);
    assert_eq!(
        p.l4_decision("anything.example.com", 22),
        L4Decision::NoMatch
    );
}

#[test]
fn parse_tcp_target_requires_an_explicit_port() {
    assert_eq!(
        parse_tcp_target("tcp://ssh.example.com:22").unwrap(),
        ("ssh.example.com".to_string(), 22)
    );
    assert_eq!(
        parse_tcp_target("tcp://[2001:db8::1]:5432").unwrap(),
        ("2001:db8::1".to_string(), 5432)
    );
    // a bare IPv4 with a port
    assert_eq!(
        parse_tcp_target("tcp://10.0.0.1:6379").unwrap(),
        ("10.0.0.1".to_string(), 6379)
    );
    // the port is required, a path is rejected, the scheme must be tcp://, and 0 is invalid
    assert!(parse_tcp_target("tcp://ssh.example.com").is_err());
    assert!(parse_tcp_target("tcp://ssh.example.com:22/x").is_err());
    assert!(parse_tcp_target("https://ssh.example.com:22").is_err());
    assert!(parse_tcp_target("tcp://ssh.example.com:0").is_err());
    assert!(parse_tcp_target("tcp://ssh.example.com:notaport").is_err());
}

#[test]
fn l4_l7_conflicts_flags_an_overlapping_host_conservatively() {
    // exact host + overlapping ports between a tcp:// allow and an L7 rule → flagged
    let p = EgressPolicy::new(
        vec![
            rule("tcp://api.example.com:443"),
            rule("api.example.com:443"),
        ],
        vec![],
    );
    assert_eq!(p.l4_l7_conflicts(), vec!["api.example.com".to_string()]);

    // an L7 *path* deny on the same host:port is the real footgun (the deny can't apply to the
    // spliced traffic) — flagged too
    let q = EgressPolicy::new(
        vec![rule("tcp://api.example.com:443")],
        vec![rule("api.example.com/secret")],
    );
    assert_eq!(q.l4_l7_conflicts(), vec!["api.example.com".to_string()]);

    // disjoint ports are NOT a conflict (tcp on :22, the bare L7 host on {80,443})
    let r = EgressPolicy::new(
        vec![rule("tcp://ssh.example.com:22"), rule("ssh.example.com")],
        vec![],
    );
    assert!(r.l4_l7_conflicts().is_empty());

    // a `*.domain` or `re:` host is not flagged (overlap undecidable → no false positive), and a
    // host reached only by L4 has no conflict
    let s = EgressPolicy::new(
        vec![rule("tcp://*.corp:5432"), rule("db.corp:5432")],
        vec![rule("re:.*example.*")],
    );
    assert!(s.l4_l7_conflicts().is_empty());

    // each conflicting host is reported once, even with several matching L7 rules
    let t = EgressPolicy::new(
        vec![rule("tcp://h.example:443"), rule("h.example:443")],
        vec![rule("h.example/a"), rule("h.example/b")],
    );
    assert_eq!(t.l4_l7_conflicts(), vec!["h.example".to_string()]);
}

#[test]
fn a_secret_to_rule_is_l7_by_construction() {
    // a `tcp://` rule is host-level only and `host_port_rule` (the ask-remembered rule) is L7 —
    // both feed paths that must never be raw-spliced credential targets. (The secret `to`
    // validator rejecting a tcp:// `to` is covered in the config tests; here just pin the layer.)
    assert_eq!(host_port_rule("h", 443).layer, Layer::L7);
}

#[test]
fn http2_host_parses_bare_host_and_host_port() {
    // A bare host matches any port; a `host:port` pins that port. The host is canonicalized (the
    // trailing FQDN dot is stripped, matching the proxy's `connect_host`).
    let bare = Http2Host::parse("grpc.example.com").unwrap();
    assert_eq!(bare.display(), "grpc.example.com");
    let scoped = Http2Host::parse("grpc.example.com:9001").unwrap();
    assert_eq!(scoped.display(), "grpc.example.com:9001");
    assert_eq!(
        Http2Host::parse("grpc.example.com.:443").unwrap().display(),
        "grpc.example.com:443"
    );
    // A `*.domain` wildcard round-trips through display, with and without a port.
    assert_eq!(
        Http2Host::parse("*.example.com").unwrap().display(),
        "*.example.com"
    );
    assert_eq!(
        Http2Host::parse("*.example.com:443").unwrap().display(),
        "*.example.com:443"
    );
    // Malformed → None (dropped with a warning by the config layer, fail-closed): an empty
    // entry, a bare `*.` with no domain, or a port that is not a valid u16.
    assert!(Http2Host::parse("").is_none());
    assert!(Http2Host::parse("   ").is_none());
    assert!(Http2Host::parse("*.").is_none());
    assert!(Http2Host::parse("host:99999").is_none());
}

#[test]
fn http2_host_matches_by_optional_port() {
    // A `None` port matches any port; a `Some(port)` matches only that port.
    let any = Http2Host::parse("h.example.com").unwrap();
    assert!(any.matches("h.example.com", 443));
    assert!(any.matches("h.example.com", 9001));
    assert!(!any.matches("other.example.com", 443));

    let pinned = Http2Host::parse("h.example.com:9001").unwrap();
    assert!(pinned.matches("h.example.com", 9001));
    assert!(!pinned.matches("h.example.com", 443));

    // A `*.domain` wildcard matches the apex and any subdomain, spoof-safe (a leading `.` is
    // required), and still honours the optional port. This is the same suffix-safe rule the
    // `allow`/`deny` `*.domain` kind uses.
    let wild = Http2Host::parse("*.example.net").unwrap();
    assert!(wild.matches("example.net", 443)); // apex
    assert!(wild.matches("api5.example.net", 443)); // subdomain
    assert!(wild.matches("agent.api5.example.net", 443)); // nested subdomain
    assert!(!wild.matches("example.net.evil.com", 443)); // lookalike suffix → no match
    assert!(!wild.matches("notexample.net", 443)); // must break on a dot, not a substring
    let wild_pinned = Http2Host::parse("*.example.net:443").unwrap();
    assert!(wild_pinned.matches("api5.example.net", 443));
    assert!(!wild_pinned.matches("api5.example.net", 8443)); // wrong port
}

#[test]
fn speaks_http2_only_for_designated_hosts() {
    // `speaks_http2` is orthogonal to the verdict — it just selects the transport for a CONNECT
    // target. It survives the built-in union and carries the port granularity.
    let policy = EgressPolicy::new(vec![rule("grpc.example.com:9001")], vec![])
        .with_http2(vec![Http2Host::parse("grpc.example.com:9001").unwrap()]);
    assert!(policy.speaks_http2("grpc.example.com", 9001));
    assert!(!policy.speaks_http2("grpc.example.com", 443));
    assert!(!policy.speaks_http2("rest.example.com", 443));
    // A policy with no http2 entry never selects h2.
    assert!(!EgressPolicy::new(vec![], vec![]).speaks_http2("grpc.example.com", 9001));
}
