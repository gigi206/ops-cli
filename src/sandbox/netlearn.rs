//! Synthesize allowlist rules from a run's egress log — the pure core of `sbx app <name> --net-learn`.
//!
//! An app run under its real (unchanged) posture logs every destination it was refused for lack of a
//! rule. `--net-learn` turns those refusals into the allowlist rules that would admit them, so they
//! can be written to the app's profile. Nothing is opened during the run: a refused request stays
//! refused; only what it *announced* (the host/verb/path it lacked) is collected.
//!
//! ONLY the two "not in the allowlist yet" refusal reasons are learnable: `denied-default` (the host
//! is not allowed at all) and `denied-method` (the host is allowed, but not for this verb — including
//! the `WS` pseudo-verb). Every other refusal is deliberately left alone:
//!   - `denied-by-rule` — a deliberate deny the user wrote; auto-overriding it would silently re-open
//!     what they closed.
//!   - a security block (`ssrf-blocked`, `host-mismatch`, `outbound-secret`, `bad-request`, …) —
//!     auto-allowing a security refusal would turn a convenience into a hole.
//!
//! So the reason whitelist is the security boundary of this feature.
//!
//! # Plane
//!
//! A rule's scheme names a plane, so it is taken from the refusal's `proto` and never guessed from
//! the port: a cleartext (`http://`) refusal yields an `http://` rule at whatever port it used, an
//! inspected one an `https://` rule. Subsumption against the current policy is asked of that same
//! plane — cleartext is strictly opt-in, so an `https://` rule never counts as already covering a
//! cleartext refusal.
//!
//! # Granularity
//!
//! How wide a rule to synthesize is the caller's choice ([`Granularity`]):
//!   - [`Granularity::Domain`] (the default) — one whole-host rule per host: `{*} https://host`
//!     (`{WS} https://host` for a WebSocket). The verb collapses to `{*}`; the path is ignored.
//!   - [`Granularity::Path`] — a subtree per host and top-level path section: `{*} https://host/v1/*`.
//!     Each refused path opens its first path segment as a subtree, so `/v1/chat` + `/v2/models` yield
//!     `/v1/*` **and** `/v2/*` — a predictable one-level section, and never a silent widen to the whole
//!     host. A refusal for the bare root (`/`, no segments) falls back to the host rule.
//!   - [`Granularity::Exact`] — the exact endpoint per distinct `(host, port, method, path)`:
//!     `{POST} https://host/v1/chat`. The observed verb is kept; the query string is dropped.
//!
//! Nothing is ever dropped silently: a learnable refusal that cannot become a rule (an unusable host,
//! a candidate the classifier rejects) and a verb-widening (a method-scoped host opened to `{*}`) are
//! surfaced as [`Synthesis::notes`] for the caller to print.

use std::collections::BTreeSet;

use super::control::{LogEvent, Proto};
use crate::allowlist::{Decision, EgressPolicy, canonical_segments, classify};

/// The refusal reasons that mean "this destination is simply not in the allowlist yet" — the only
/// ones a candidate rule may be synthesized from.
const LEARNABLE: [&str; 2] = ["denied-default", "denied-method"];

/// How wide a rule `--net-learn` synthesizes for each refused destination.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Granularity {
    /// One whole-host rule per host (`{*} https://host`) — the widest, the default.
    #[default]
    Domain,
    /// A path subtree per host and top-level section (`{*} https://host/v1/*`).
    Path,
    /// The exact endpoint per `(host, port, method, path)` (`{POST} https://host/v1/chat`).
    Exact,
}

impl Granularity {
    /// Parse the `--net-learn=<level>` value, or an error naming the accepted levels.
    pub(crate) fn parse(s: &str) -> Result<Self, String> {
        match s {
            "domain" => Ok(Self::Domain),
            "path" => Ok(Self::Path),
            "exact" => Ok(Self::Exact),
            other => Err(format!(
                "unknown --net-learn granularity `{other}` (expected `domain`, `path`, or `exact`)"
            )),
        }
    }

    /// The stable token for this level (for help/diagnostics).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Path => "path",
            Self::Exact => "exact",
        }
    }
}

/// The result of turning a run's egress log into rules: the rule strings to add (sorted, deduped, each
/// classifier-valid), and human notes about anything worth the user seeing — a refusal that produced
/// no rule, or a host whose verb scope was widened.
pub(crate) struct Synthesis {
    pub(crate) rules: Vec<String>,
    pub(crate) notes: Vec<String>,
}

/// Turn the refusals in `events` into the allowlist rules that would admit them at the requested
/// `gran`ularity. Skips any the current `policy` already allows (subsumption against the effective
/// policy the run actually used, not string-dedup). Never emits a rule the write path would reject,
/// and never drops a learnable refusal without a note.
pub(crate) fn synthesize(
    events: &[LogEvent],
    policy: &EgressPolicy,
    gran: Granularity,
) -> Synthesis {
    let mut notes: Vec<String> = Vec::new();

    // Learnable, not-already-allowed refusals that name a usable host. A refusal we cannot even shape
    // into a host token is surfaced here, never silently dropped.
    let mut usable: Vec<&LogEvent> = Vec::new();
    for e in events {
        if !LEARNABLE.contains(&e.reason.as_str()) {
            continue;
        }
        if already_allowed(policy, e) {
            continue;
        }
        if host_token(&e.host, e.port, e.proto).is_none() {
            notes.push(format!(
                "skipped an egress refusal for an unusable host `{}:{}`",
                e.host, e.port
            ));
            continue;
        }
        usable.push(e);
    }

    let mut rules: BTreeSet<String> = BTreeSet::new();
    // Hosts a `denied-method` opened to all verbs (`{*}`) — surfaced so the widening is never silent.
    let mut widened: BTreeSet<String> = BTreeSet::new();
    match gran {
        Granularity::Domain => build_domain(&usable, &mut rules, &mut widened),
        Granularity::Path => build_path(&usable, &mut rules, &mut widened),
        Granularity::Exact => build_exact(&usable, &mut rules, &mut notes),
    }

    for host in &widened {
        notes.push(format!(
            "the verb filter on `{host}` was widened to all verbs (`{{*}}`) — it was previously \
             method-scoped"
        ));
    }

    // Final gate: never hand the write path a rule its own classifier would reject. A drop here is
    // rare (the host already passed a sanity gate) but is surfaced, not swallowed.
    let mut out: Vec<String> = Vec::new();
    for r in rules {
        if classify(&r).is_ok() {
            out.push(r);
        } else {
            notes.push(format!(
                "skipped a synthesized rule the classifier rejected: `{r}`"
            ));
        }
    }

    dedup_stable(&mut notes);
    Synthesis { rules: out, notes }
}

/// One whole-host rule per host: `{*} https://host` (`{WS} https://host` for a WebSocket). The verb
/// collapses to `{*}` and the path is ignored — the widest learn. A `denied-method` that becomes
/// `{*}` widened a method-scoped host, recorded in `widened`.
fn build_domain(
    events: &[&LogEvent],
    rules: &mut BTreeSet<String>,
    widened: &mut BTreeSet<String>,
) {
    for e in events {
        let host = host_token(&e.host, e.port, e.proto).expect("filtered to usable hosts");
        if is_ws(e) {
            rules.insert(format!("{{WS}} {host}"));
        } else {
            rules.insert(format!("{{*}} {host}"));
            if e.reason == "denied-method" {
                widened.insert(host);
            }
        }
    }
}

/// A path subtree per host and top-level section: each refused path opens its **first** segment as a
/// subtree (`/v1/chat` → `host/v1/*`), so divergent sections (`/v1/…` vs `/v2/…`) become separate
/// one-level subtrees rather than collapsing to the whole host — the predictable middle ground
/// between the whole-host `domain` and the exact-endpoint `exact`. A refusal for the bare root (no
/// segments) has no section to scope and falls back to a host rule.
fn build_path(events: &[&LogEvent], rules: &mut BTreeSet<String>, widened: &mut BTreeSet<String>) {
    for e in events {
        let host = host_token(&e.host, e.port, e.proto).expect("filtered to usable hosts");
        let ws = is_ws(e);
        let verb = if ws { "WS" } else { "*" };
        let segs = canonical_segments(e.path.as_deref().unwrap_or(""));
        match segs.first() {
            Some(section) => {
                rules.insert(format!("{{{verb}}} {host}/{section}/*"));
            }
            // A bare-root refusal (no path segments) has no subtree to scope — open the host.
            None => {
                rules.insert(format!("{{{verb}}} {host}"));
            }
        }
        if !ws && e.reason == "denied-method" {
            widened.insert(host);
        }
    }
}

/// The exact endpoint per distinct `(host, port, method, path)`: `{POST} https://host/v1/chat`. The
/// observed verb is kept and the query string is dropped (an exact rule matches the path, not the
/// query). A refusal with no usable method cannot become an exact rule and is surfaced.
fn build_exact(events: &[&LogEvent], rules: &mut BTreeSet<String>, notes: &mut Vec<String>) {
    for e in events {
        let host = host_token(&e.host, e.port, e.proto).expect("filtered to usable hosts");
        let Some(method) = e.method.as_deref() else {
            notes.push(format!(
                "skipped `{host}` for `exact` — the refusal carries no method"
            ));
            continue;
        };
        if !is_verb(method) {
            notes.push(format!(
                "skipped `{host}` for `exact` — unusable method `{method}`"
            ));
            continue;
        }
        let path = exact_path(e.path.as_deref());
        rules.insert(format!("{{{method}}} {host}{path}"));
    }
}

/// Whether the current policy already admits the destination this event names — using the event's own
/// path/verb (a missing verb reads as `GET`, the read default). Defensive: a refused event was not
/// admitted, but a manual edit between iterations could have added it.
///
/// Subsumption is asked of the plane that actually refused: a cleartext refusal goes to
/// [`EgressPolicy::explain_clear`], everything else to [`EgressPolicy::explain`]. Asking the inspected
/// plane about a cleartext refusal would report an `https://` rule as already covering it and drop the
/// `http://` rule that is the only thing which can open it.
fn already_allowed(policy: &EgressPolicy, e: &LogEvent) -> bool {
    let path = e.path.as_deref().unwrap_or("/");
    let method = e.method.as_deref().unwrap_or("GET");
    let decision = match e.proto {
        Proto::Http => policy.explain_clear(&e.host, e.port, path, method),
        _ => policy.explain(&e.host, e.port, path, method),
    };
    matches!(decision, Decision::AllowedBy(_) | Decision::AllowedDefault)
}

/// Whether this refusal was a WebSocket (evaluated under the `WS` pseudo-verb). A WebSocket is a
/// distinct capability `{*}` does not grant, so it always yields a `{WS}` rule at the chosen level.
fn is_ws(e: &LogEvent) -> bool {
    e.method.as_deref() == Some("WS")
}

/// The host part of a rule, shaped from the plane that refused the request and its port. The scheme
/// comes from the event's [`Proto`], never from the port: a cleartext refusal on `:8080` was shaped
/// `https://h:8080`, a rule that names the inspected plane and so can never admit the cleartext
/// request it was learned from (`explain_clear` opens only on an `http://` rule). The port is omitted
/// only when it is the scheme's own default — 443 for `https://`, 80 for `http://` — so the shorthand
/// never silently narrows a non-standard port. `None` for an empty or malformed host — a rule must
/// name a concrete, sane destination.
fn host_token(host: &str, port: u16, proto: Proto) -> Option<String> {
    if !host_is_sane(host) {
        return None;
    }
    // Only the cleartext plane is `http://`. A splice (`Tcp`) and an unknown transport (`Other`)
    // never carry a learnable reason, so they read as the inspected plane rather than inventing a
    // scheme for a refusal this feature cannot learn from anyway.
    let (scheme, default_port) = match proto {
        Proto::Http => ("http", 80),
        _ => ("https", 443),
    };
    Some(if port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

/// A conservative host-charset gate, so a malformed log host can never be shaped into a rule string
/// that the classifier would then have to reject (or worse, mis-parse). The real validation is the
/// classifier at write time; this just keeps obvious junk out of the candidate list.
fn host_is_sane(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        })
}

/// An HTTP verb (or the `WS` pseudo-verb) is uppercase ASCII letters — the same shape the rule
/// grammar accepts in a `{...}` prefix.
fn is_verb(method: &str) -> bool {
    !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase())
}

/// The exact request path for an `exact` rule: the canonical segments (query dropped, percent-decoded,
/// dot-segments resolved — the same canonicalization the matcher applies) rejoined as `/a/b`, or `/`
/// for the root. Canonicalizing here keeps the rule's path identical to what a live request reduces
/// to, so the exact match is faithful.
fn exact_path(raw: Option<&str>) -> String {
    let segs = canonical_segments(raw.unwrap_or("/"));
    if segs.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segs.join("/"))
    }
}

/// Drop later duplicate notes while keeping first-seen order — the same refusal can surface twice
/// (e.g. two events for one unusable host).
fn dedup_stable(notes: &mut Vec<String>) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    notes.retain(|n| seen.insert(n.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::classify;
    use crate::sandbox::control::{LogEvent, LogVerdict};

    fn ev(
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        reason: &str,
    ) -> LogEvent {
        ev_on(host, port, method, path, reason, Proto::Https)
    }

    /// The same refusal, on a named plane — the cleartext plane logs `Proto::Http`, and the scheme of
    /// the rule learned from it must follow the plane, not the port.
    fn ev_on(
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        reason: &str,
        proto: Proto,
    ) -> LogEvent {
        LogEvent {
            seq: 0,
            at_epoch_ms: 0,
            host: host.to_string(),
            port,
            method: method.map(str::to_string),
            path: path.map(str::to_string),
            verdict: LogVerdict::Deny,
            proto,
            http_ver: crate::sandbox::control::HttpVer::Unknown,
            rpc: crate::sandbox::control::RpcKind::None,
            reason: reason.to_string(),
            muted: false,
            status: None,
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        }
    }

    fn empty_policy() -> EgressPolicy {
        EgressPolicy::new(vec![], vec![])
    }

    fn rules(events: &[LogEvent], gran: Granularity) -> Vec<String> {
        synthesize(events, &empty_policy(), gran).rules
    }

    // ---- Domain ----

    #[test]
    fn domain_a_denied_default_host_becomes_a_wildcard_https_rule() {
        let got = rules(
            &[ev("api.test", 443, None, None, "denied-default")],
            Granularity::Domain,
        );
        assert_eq!(got, vec!["{*} https://api.test".to_string()]);
    }

    #[test]
    fn domain_collapses_the_verb_to_wildcard_but_keeps_websockets_distinct() {
        // A method-scoped denial widens to `{*}` (domain = whole host); a WebSocket denial stays `{WS}`
        // because `{*}` does not grant one.
        let got = rules(
            &[
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/x"),
                    "denied-method",
                ),
                ev(
                    "chat.test",
                    443,
                    Some("WS"),
                    Some("/socket"),
                    "denied-method",
                ),
            ],
            Granularity::Domain,
        );
        assert_eq!(
            got,
            vec![
                "{*} https://api.test".to_string(),
                "{WS} https://chat.test".to_string(),
            ]
        );
    }

    #[test]
    fn domain_surfaces_a_verb_widening_note() {
        let out = synthesize(
            &[ev(
                "api.test",
                443,
                Some("POST"),
                Some("/v1/x"),
                "denied-method",
            )],
            &empty_policy(),
            Granularity::Domain,
        );
        assert_eq!(out.rules, vec!["{*} https://api.test".to_string()]);
        assert!(
            out.notes
                .iter()
                .any(|n| n.contains("all verbs") && n.contains("api.test")),
            "a method-scoped widen must be surfaced: {:?}",
            out.notes
        );
    }

    #[test]
    fn domain_the_plane_shapes_the_scheme_and_the_port_only_the_suffix() {
        // The scheme follows the refusing plane, the port only decides whether the `:port` suffix is
        // needed. An inspected refusal on 80 is `https://h:80`, not `http://h` — inferring the scheme
        // from the port would learn a rule for a plane that never refused anything.
        let got = rules(
            &[
                ev("tls.test", 443, None, None, "denied-default"),
                ev_on("clear.test", 80, None, None, "denied-default", Proto::Http),
                ev("alt.test", 8443, None, None, "denied-default"),
                ev("tls80.test", 80, None, None, "denied-default"),
            ],
            Granularity::Domain,
        );
        assert_eq!(
            got,
            vec![
                "{*} http://clear.test".to_string(),
                "{*} https://alt.test:8443".to_string(),
                "{*} https://tls.test".to_string(),
                "{*} https://tls80.test:80".to_string(),
            ]
        );
    }

    #[test]
    fn a_cleartext_refusal_learns_a_rule_that_actually_admits_it() {
        // The defect this pins: the scheme used to come from the port, so a cleartext refusal on any
        // port but 80 became an `https://` rule — and cleartext is strictly opt-in, so that rule could
        // never admit the request it was learned from. Assert the end-to-end property (the learned
        // rule readmits the refusal on the cleartext plane), at every granularity.
        for gran in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            let got = rules(
                &[ev_on(
                    "clear.test",
                    8080,
                    Some("GET"),
                    Some("/v1/health"),
                    "denied-default",
                    Proto::Http,
                )],
                gran,
            );
            assert_eq!(got.len(), 1, "one rule at {gran:?}: {got:?}");
            assert!(
                got[0].contains("http://clear.test:8080"),
                "the cleartext plane must yield an `http://` rule at {gran:?}: {got:?}"
            );
            let learned = EgressPolicy::new(vec![classify(&got[0]).unwrap()], vec![]);
            assert!(
                matches!(
                    learned.explain_clear("clear.test", 8080, "/v1/health", "GET"),
                    Decision::AllowedBy(_)
                ),
                "the learned rule must readmit the refusal it came from at {gran:?}: {got:?}"
            );
        }
    }

    #[test]
    fn an_https_rule_does_not_subsume_a_cleartext_refusal() {
        // Subsumption is asked of the plane that refused. An `https://` allow does not open cleartext,
        // so a cleartext refusal for that host must still learn its `http://` rule; the inverse (an
        // inspected refusal for a host an `https://` rule already opens) must still be skipped, so the
        // guard cannot be satisfied by simply never subsuming anything.
        // The rule spans every port, so the inspected plane really would admit the cleartext
        // request's host/port/path — only the plane separates them.
        let policy = EgressPolicy::new(vec![classify("{*} https://api.test:*").unwrap()], vec![]);
        let got = synthesize(
            &[ev_on(
                "api.test",
                80,
                Some("GET"),
                Some("/v1/x"),
                "denied-default",
                Proto::Http,
            )],
            &policy,
            Granularity::Domain,
        )
        .rules;
        assert_eq!(
            got,
            vec!["{*} http://api.test".to_string()],
            "an https allow must not subsume a cleartext refusal"
        );
        assert!(
            synthesize(
                &[ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some("/v1/x"),
                    "denied-default"
                )],
                &policy,
                Granularity::Domain,
            )
            .rules
            .is_empty(),
            "the inspected plane must still subsume against its own https rule"
        );
    }

    #[test]
    fn domain_a_wildcard_and_a_websocket_on_one_host_coexist() {
        let got = rules(
            &[
                ev("api.test", 443, None, None, "denied-default"),
                ev("api.test", 443, Some("WS"), Some("/ws"), "denied-method"),
            ],
            Granularity::Domain,
        );
        assert_eq!(
            got,
            vec![
                "{*} https://api.test".to_string(),
                "{WS} https://api.test".to_string(),
            ]
        );
    }

    // ---- Path ----

    #[test]
    fn path_opens_the_first_segment_section() {
        // Several endpoints under one section collapse to that one-level subtree.
        let got = rules(
            &[
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/chat"),
                    "denied-default",
                ),
                ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some("/v1/messages"),
                    "denied-default",
                ),
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/chat/completions"),
                    "denied-default",
                ),
            ],
            Granularity::Path,
        );
        assert_eq!(got, vec!["{*} https://api.test/v1/*".to_string()]);
    }

    #[test]
    fn path_keeps_divergent_sections_separate_never_widening_to_the_host() {
        // The reason `path` exists: two top-level sections must not collapse to `{*} host`.
        let got = rules(
            &[
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/chat"),
                    "denied-default",
                ),
                ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some("/v2/models"),
                    "denied-default",
                ),
            ],
            Granularity::Path,
        );
        assert_eq!(
            got,
            vec![
                "{*} https://api.test/v1/*".to_string(),
                "{*} https://api.test/v2/*".to_string(),
            ]
        );
    }

    #[test]
    fn path_a_single_endpoint_opens_its_section_not_the_exact_endpoint() {
        // A lone `/v1/chat` opens the `/v1` section (matching the level `domain < path < exact`),
        // not `/v1/chat/*` — `path` is the section tier, `exact` is the endpoint tier.
        let got = rules(
            &[ev(
                "api.test",
                443,
                Some("POST"),
                Some("/v1/chat"),
                "denied-default",
            )],
            Granularity::Path,
        );
        assert_eq!(got, vec!["{*} https://api.test/v1/*".to_string()]);
    }

    #[test]
    fn path_a_root_refusal_falls_back_to_the_host() {
        let got = rules(
            &[ev(
                "api.test",
                443,
                Some("GET"),
                Some("/"),
                "denied-default",
            )],
            Granularity::Path,
        );
        assert_eq!(got, vec!["{*} https://api.test".to_string()]);
    }

    #[test]
    fn path_groups_websockets_separately() {
        let got = rules(
            &[
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/chat"),
                    "denied-default",
                ),
                ev(
                    "api.test",
                    443,
                    Some("WS"),
                    Some("/v1/socket"),
                    "denied-method",
                ),
            ],
            Granularity::Path,
        );
        assert_eq!(
            got,
            vec![
                "{*} https://api.test/v1/*".to_string(),
                "{WS} https://api.test/v1/*".to_string(),
            ]
        );
    }

    // ---- Exact ----

    #[test]
    fn exact_keeps_the_verb_and_the_path() {
        let got = rules(
            &[
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/chat"),
                    "denied-default",
                ),
                ev(
                    "chat.test",
                    443,
                    Some("WS"),
                    Some("/socket"),
                    "denied-method",
                ),
            ],
            Granularity::Exact,
        );
        assert_eq!(
            got,
            vec![
                "{POST} https://api.test/v1/chat".to_string(),
                "{WS} https://chat.test/socket".to_string(),
            ]
        );
    }

    #[test]
    fn exact_drops_the_query_string() {
        let got = rules(
            &[ev(
                "api.test",
                443,
                Some("GET"),
                Some("/search?q=secret&n=1"),
                "denied-default",
            )],
            Granularity::Exact,
        );
        assert_eq!(got, vec!["{GET} https://api.test/search".to_string()]);
    }

    #[test]
    fn exact_distinct_verbs_on_one_path_are_distinct_rules() {
        let got = rules(
            &[
                ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some("/v1/x"),
                    "denied-default",
                ),
                ev(
                    "api.test",
                    443,
                    Some("POST"),
                    Some("/v1/x"),
                    "denied-default",
                ),
            ],
            Granularity::Exact,
        );
        assert_eq!(
            got,
            vec![
                "{GET} https://api.test/v1/x".to_string(),
                "{POST} https://api.test/v1/x".to_string(),
            ]
        );
    }

    #[test]
    fn exact_a_root_refusal_is_the_root_path() {
        let got = rules(
            &[ev(
                "api.test",
                443,
                Some("GET"),
                Some("/"),
                "denied-default",
            )],
            Granularity::Exact,
        );
        assert_eq!(got, vec!["{GET} https://api.test/".to_string()]);
    }

    // ---- Cross-cutting ----

    #[test]
    fn the_security_filter_excludes_deliberate_and_security_refusals() {
        // A deliberate deny and every security block must NEVER become a rule — auto-allowing them
        // would re-open a closed host or defeat a security check. Holds at every granularity.
        let events = [
            ev("evil.test", 443, None, None, "denied-by-rule"),
            ev("internal.test", 443, None, None, "ssrf-blocked"),
            ev("spoof.test", 443, Some("GET"), Some("/x"), "host-mismatch"),
            ev(
                "leak.test",
                443,
                Some("POST"),
                Some("/x"),
                "outbound-secret",
            ),
            ev("bad.test", 443, None, None, "bad-request"),
            ev("ok.test", 443, None, None, "allowed"),
        ];
        for gran in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            assert!(rules(&events, gran).is_empty(), "leaked at {:?}", gran);
        }
    }

    #[test]
    fn duplicate_refusals_collapse_to_one_rule() {
        for gran in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            let got = rules(
                &[
                    ev(
                        "api.test",
                        443,
                        Some("GET"),
                        Some("/v1/x"),
                        "denied-default",
                    ),
                    ev(
                        "api.test",
                        443,
                        Some("GET"),
                        Some("/v1/x"),
                        "denied-default",
                    ),
                ],
                gran,
            );
            assert_eq!(
                got.len(),
                1,
                "duplicates must collapse at {gran:?}: {got:?}"
            );
        }
    }

    #[test]
    fn a_candidate_the_policy_already_allows_is_skipped() {
        // The host is already open for all verbs; a stray refusal event for it (e.g. a manual edit
        // between iterations) must not re-emit a redundant rule — at any granularity.
        let policy = EgressPolicy::new(vec![classify("{*} https://api.test").unwrap()], vec![]);
        for gran in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            let got = synthesize(
                &[ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some("/v1/x"),
                    "denied-method",
                )],
                &policy,
                gran,
            )
            .rules;
            assert!(
                got.is_empty(),
                "already-allowed host must be subsumed at {gran:?}: {got:?}"
            );
        }
    }

    #[test]
    fn every_synthesized_rule_parses_as_a_real_rule() {
        // A candidate must round-trip through the classifier the write path uses, or it would be a
        // rule the launch then drops. Exercised across all three granularities.
        let events = [
            ev("api.test", 443, None, Some("/v1/chat"), "denied-default"),
            ev(
                "chat.test",
                443,
                Some("WS"),
                Some("/v1/stream"),
                "denied-method",
            ),
            ev(
                "clear.test",
                80,
                Some("GET"),
                Some("/health"),
                "denied-default",
            ),
            ev(
                "alt.test",
                8443,
                Some("POST"),
                Some("/v2/run"),
                "denied-method",
            ),
        ];
        for gran in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            for rule in rules(&events, gran) {
                assert!(
                    classify(&rule).is_ok(),
                    "must classify at {gran:?}: {rule:?}"
                );
            }
        }
    }

    #[test]
    fn a_junk_host_is_dropped_with_a_note_not_shaped_into_a_rule() {
        let out = synthesize(
            &[ev("no spaces/here", 443, None, None, "denied-default")],
            &empty_policy(),
            Granularity::Domain,
        );
        assert!(
            out.rules.is_empty(),
            "a malformed host must not become a rule: {:?}",
            out.rules
        );
        assert!(
            out.notes.iter().any(|n| n.contains("unusable host")),
            "the drop must be surfaced: {:?}",
            out.notes
        );
    }

    #[test]
    fn granularity_parse_round_trips_and_rejects_junk() {
        for g in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            assert_eq!(Granularity::parse(g.as_str()), Ok(g));
        }
        assert!(Granularity::parse("subtree").is_err());
    }
}
