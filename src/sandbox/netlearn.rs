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
//! So the reason whitelist is the security boundary of this feature. A reason counts only on the
//! event it was written for: a `deny` on one of the two inspected planes (`https` or `http`), the
//! only events the proxy records those two reasons on ([`learnable`]).
//!
//! Two gates sit beside it.
//!
//! The first is the **plane**. The events come from one ring per session, and a declared operation's
//! per-invocation proxy shares it (its own control socket is not one `sbx net logs` finds) while
//! enforcing the task's own, deliberately narrower `network` list. Such a proxy is hardwired to
//! deny-by-default, so its misses log the learnable `denied-default` — but they say what the *task*
//! was not granted, and writing them into the app's profile would widen the **agent's** allowlist
//! for a destination the operator was never asked about. Every event names the proxy that pushed it
//! ([`LogEvent::plane`]), and only [`Plane::Agent`] is learned from.
//!
//! The second is the **posture**: a refusal is skipped when the policy being learned would have
//! *asked a person* about that destination rather than refusing it. An answer the posture puts to a
//! person is not one a run may pre-empt by being run.
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
//!     host. A refusal for the bare root (`/`, no segments) falls back to the host rule, with a note.
//!   - [`Granularity::Exact`] — the exact endpoint per distinct `(host, port, method, path)`:
//!     `{POST} https://host/v1/chat`. The observed verb is kept; the query string is dropped.
//!
//! Nothing is ever dropped silently: a learnable refusal that cannot become a rule (an unusable host,
//! a path no rule can match on its own, a candidate the classifier rejects) and a widening (a
//! method-scoped host opened to `{*}`, a bare root opened to the whole host) are surfaced as
//! [`Synthesis::notes`] for the caller to print.

use std::collections::BTreeSet;

use super::control::{LogEvent, LogVerdict, Plane, Proto};
use super::learn::Synthesis;
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

/// Turn the refusals in `events` into the allowlist rules that would admit them at the requested
/// `gran`ularity. Reads only the agent's own plane ([`from_agent`]); skips any refusal the current
/// `policy` already allows (subsumption against the effective policy the run actually used, not
/// string-dedup), and any it would put to a person instead of refusing ([`would_ask`]). Never emits
/// a rule the write path would reject, and never drops a learnable refusal without a note.
pub(crate) fn synthesize(
    events: &[LogEvent],
    policy: &EgressPolicy,
    gran: Granularity,
) -> Synthesis {
    let mut notes: Vec<String> = Vec::new();

    // Learnable, not-already-allowed refusals, each with the host part of its rule. A refusal we
    // cannot even shape into a host token is surfaced here, never silently dropped.
    let mut usable: Vec<(&LogEvent, String)> = Vec::new();
    // Refusals another plane's proxy pushed into this session's ring, collapsed into one note: they
    // are counted rather than listed, because a task loop can produce thousands of them and the
    // operator's question is "did any of my rules come from somewhere else?", not "which".
    let mut foreign = 0usize;
    for e in events {
        if !learnable(e) {
            continue;
        }
        if !from_agent(e) {
            foreign += 1;
            continue;
        }
        if already_allowed(policy, e) {
            continue;
        }
        if would_ask(policy, e) {
            notes.push(format!(
                "skipped an egress refusal for `{}:{}` — this posture asks a person about that \
                 destination, so the answer is theirs to give, not this run's to learn",
                e.host, e.port
            ));
            continue;
        }
        let Some(host) = host_token(&e.host, e.port, e.proto) else {
            notes.push(format!(
                "skipped an egress refusal for an unusable host `{}:{}`",
                e.host, e.port
            ));
            continue;
        };
        usable.push((e, host));
    }
    if foreign > 0 {
        notes.push(format!(
            "skipped {foreign} egress refusal(s) another plane logged into this session's ring — \
             a declared task's proxy, a distro build's, or one whose origin was not recorded. \
             What such a refusal asked for is declared with the task or the build, so opening it \
             here would widen this profile for something the app never asked for"
        ));
    }

    let mut rules: BTreeSet<String> = BTreeSet::new();
    // Hosts a `denied-method` opened to all verbs (`{*}`) — surfaced so the widening is never silent.
    let mut widened: BTreeSet<String> = BTreeSet::new();
    match gran {
        Granularity::Domain => build_domain(&usable, &mut rules, &mut widened),
        Granularity::Path => build_path(&usable, &mut rules, &mut widened, &mut notes),
        Granularity::Exact => build_exact(&usable, &mut rules, &mut notes),
    }

    for host in &widened {
        notes.push(format!(
            "the verb filter on `{host}` was widened to all verbs (`{{*}}`) — it was previously \
             method-scoped"
        ));
    }

    // Final gate: never hand the write path a rule its own classifier would reject. The host
    // already passed a sanity gate, but the path did not: it comes from `canonical_segments`, which
    // percent-decodes, so a request the cage chose reaches the rule text as the bytes it decodes to
    // rather than as the characters that were sent. A drop is surfaced, not swallowed -- and the
    // note goes through the crate's sanitiser, because a note that quoted such a rule verbatim
    // would put on the operator's terminal exactly what dropping the rule kept off it.
    let mut out: Vec<String> = Vec::new();
    for r in rules {
        if classify(&r).is_ok() {
            out.push(r);
        } else {
            notes.push(format!(
                "skipped a synthesized rule the classifier rejected: `{}`",
                crate::sandbox::sanitize(&r)
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
    events: &[(&LogEvent, String)],
    rules: &mut BTreeSet<String>,
    widened: &mut BTreeSet<String>,
) {
    for (e, host) in events {
        if is_ws(e) {
            rules.insert(format!("{{WS}} {host}"));
        } else {
            rules.insert(format!("{{*}} {host}"));
            if e.reason == "denied-method" {
                widened.insert(host.clone());
            }
        }
    }
}

/// A path subtree per host and top-level section: each refused path opens its **first** segment as a
/// subtree (`/v1/chat` → `host/v1/*`), so divergent sections (`/v1/…` vs `/v2/…`) become separate
/// one-level subtrees rather than collapsing to the whole host — the predictable middle ground
/// between the whole-host `domain` and the exact-endpoint `exact`. A refusal for the bare root (no
/// segments) has no section to scope and falls back to a host rule, which is noted because it opens
/// more than `path` promises. A section no rule can name on its own ([`written_as_is`]) is skipped
/// with a note.
fn build_path(
    events: &[(&LogEvent, String)],
    rules: &mut BTreeSet<String>,
    widened: &mut BTreeSet<String>,
    notes: &mut Vec<String>,
) {
    for (e, host) in events {
        let ws = is_ws(e);
        let verb = if ws { "WS" } else { "*" };
        let segs = canonical_segments(e.path.as_deref().unwrap_or(""));
        match segs.first() {
            Some(section) if !written_as_is(std::slice::from_ref(section)) => {
                notes.push(unwritable_path(host, e, "path"));
                continue;
            }
            Some(section) => {
                rules.insert(format!("{{{verb}}} {host}/{section}/*"));
            }
            // A bare-root refusal (no path segments) has no subtree to scope — open the host.
            None => {
                rules.insert(format!("{{{verb}}} {host}"));
                notes.push(format!(
                    "`{host}` was refused at its root, which has no path section, so `path` opened \
                     the whole host"
                ));
            }
        }
        if !ws && e.reason == "denied-method" {
            widened.insert(host.clone());
        }
    }
}

/// The exact endpoint per distinct `(host, port, method, path)`: `{POST} https://host/v1/chat`. The
/// observed verb is kept and the query string is dropped (an exact rule matches the path, not the
/// query). A refusal with no usable method, or whose path no rule can name on its own
/// ([`written_as_is`]), cannot become an exact rule and is surfaced.
fn build_exact(
    events: &[(&LogEvent, String)],
    rules: &mut BTreeSet<String>,
    notes: &mut Vec<String>,
) {
    for (e, host) in events {
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
        let segs = canonical_segments(e.path.as_deref().unwrap_or("/"));
        if !written_as_is(&segs) {
            notes.push(unwritable_path(host, e, "exact"));
            continue;
        }
        let path = exact_path(e.path.as_deref());
        rules.insert(format!("{{{method}}} {host}{path}"));
    }
}

/// What the current policy makes of the destination this event names — using the event's own
/// path/verb (a missing verb reads as `GET`, the read default).
///
/// Asked of the plane that actually refused: a cleartext refusal goes to
/// [`EgressPolicy::explain_clear`], everything else to [`EgressPolicy::explain`]. Asking the inspected
/// plane about a cleartext refusal would report an `https://` rule as already covering it and drop the
/// `http://` rule that is the only thing which can open it.
fn verdict_for<'a>(policy: &'a EgressPolicy, e: &LogEvent) -> Decision<'a> {
    let path = e.path.as_deref().unwrap_or("/");
    let method = e.method.as_deref().unwrap_or("GET");
    match e.proto {
        Proto::Http => policy.explain_clear(&e.host, e.port, path, method),
        _ => policy.explain(&e.host, e.port, path, method),
    }
}

/// Whether the current policy already admits the destination this event names. Defensive: a refused
/// event was not admitted, but a manual edit between iterations could have added it.
fn already_allowed(policy: &EgressPolicy, e: &LogEvent) -> bool {
    matches!(
        verdict_for(policy, e),
        Decision::AllowedBy(_) | Decision::AllowedDefault
    )
}

/// Whether `e` is a refusal one of the [`LEARNABLE`] reasons may be read from: a `deny`, on one of the
/// two inspected planes.
///
/// The reason is not read on its own. Those two reasons are only ever recorded with a `deny`, by the
/// inspected planes' verdicts, and those planes are the only ones a rule this module writes can
/// open: an `https://` or `http://` rule never admits a raw splice, and a resolution is not a
/// request. An event carrying such a reason anywhere else is one this module was not written for,
/// and turning it into an `https://` rule would open a plane nothing asked for.
fn learnable(e: &LogEvent) -> bool {
    LEARNABLE.contains(&e.reason.as_str())
        && e.verdict == LogVerdict::Deny
        && matches!(e.proto, Proto::Https | Proto::Http)
}

/// Whether a rule written with these canonical path segments matches the path they came from and no
/// other.
///
/// The segments are percent-decoded, and a rule's path is decoded again when it is read, so a
/// decoded `%` re-reads as an escape (`/%2541` yields `/%41`, a rule for `/A`) and a decoded `/`
/// splits one segment into two. Those are caught by reading the written path back. A decoded `*`
/// reads back unchanged but is grammar: as the last segment of an exact rule it is the trailing
/// `/*` that opens a whole subtree, so `/v1/%2A` would have learned every path under `/v1`.
fn written_as_is(segs: &[String]) -> bool {
    !segs.iter().any(|s| s.contains('*'))
        && canonical_segments(&format!("/{}", segs.join("/"))) == segs
}

/// The note for a refusal whose path [`written_as_is`] turns down at `level`. It quotes the path as
/// logged rather than the decoded segments, which may hold any byte the cage encoded.
fn unwritable_path(host: &str, e: &LogEvent, level: &str) -> String {
    format!(
        "skipped `{host}` for `{level}` — its path `{}` decodes to one no rule can match on its own",
        crate::sandbox::sanitize(e.path.as_deref().unwrap_or("/"))
    )
}

/// Whether this refusal is the agent's own to learn from — the plane gate.
///
/// A session's event ring is shared: a declared operation's per-invocation proxy appends to it so
/// its decisions reach `sbx net logs` (see [`crate::sandbox::egress::Egress::event_log`]), while
/// enforcing the task's `network` list and nothing else. Being hardwired to deny-by-default, that
/// proxy logs a [`LEARNABLE`] `denied-default` for every destination outside the task's list, so the
/// reason alone cannot tell the planes apart — only [`LogEvent::plane`] can.
///
/// Learning such a refusal would write into the **agent's** profile a destination that only a task
/// wanted, one the operator was never asked about and that the task's own declaration deliberately
/// withholds. A task's egress is declared with the task; it is not something a run discovers on the
/// app's behalf.
///
/// [`Plane::Unknown`] is refused for the same reason it exists: an event whose origin was not
/// recorded cannot be shown to be the agent's.
fn from_agent(e: &LogEvent) -> bool {
    matches!(e.plane, Plane::Agent)
}

/// Whether this policy would **park** the destination for a live human decision rather than refuse
/// it outright ([`Decision::Ask`], an `ask` posture with no rule either way).
///
/// A rule the operator is asked about is theirs to decide, and a run cannot pre-answer the question
/// by being run. Under `ask` the agent's own proxy parks such a request and logs the operator's
/// answer (`asked-denied`, not [`LEARNABLE`]), so an event that reaches this gate and would park is
/// one the posture changed under, or one the plane gate has yet to reject — either way its rule is
/// not this run's to propose.
///
/// What still learns normally is everything an `ask` posture genuinely refuses on its own — a
/// WebSocket (opt-in, so it never reaches the default action) and a cleartext request (opt-in for
/// the same reason) both return a real denial from the policy above and are learned as ever.
fn would_ask(policy: &EgressPolicy, e: &LogEvent) -> bool {
    matches!(verdict_for(policy, e), Decision::Ask)
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
/// never silently narrows a non-standard port. `None` for a host the proxy's planes would never hand
/// on ([`crate::allowlist::is_request_host`]): the proxy reports only such hosts, already in their
/// one canonical spelling, so anything else is not a destination a rule could reach.
fn host_token(host: &str, port: u16, proto: Proto) -> Option<String> {
    if host.len() > 253 || !crate::allowlist::is_request_host(host) {
        return None;
    }
    // Only the cleartext plane is `http://`; [`learnable`] has already kept every other plane but
    // the inspected one out.
    let (scheme, default_port) = match proto {
        Proto::Http => ("http", 80),
        _ => ("https", 443),
    };
    // Bracketed where it has to be: an IPv6 literal followed by `:port` reads back as a different
    // address, so the rule this offers would admit something other than the request it was learned
    // from. `display_host` is the one place that answers it, and the two producers of this text
    // share it for the reason the comment on `rule_destination` gives.
    let host = crate::allowlist::display_host(host);
    Some(if port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

/// An HTTP verb (or the `WS` pseudo-verb) is uppercase ASCII letters — the same shape the rule
/// grammar accepts in a `{...}` prefix.
fn is_verb(method: &str) -> bool {
    !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase())
}

/// The exact request path for an `exact` rule: the canonical segments (query and fragment dropped,
/// percent-decoded, `;parameters` dropped, dot-segments resolved — the same canonicalization the
/// matcher applies) rejoined as `/a/b`, or `/` for the root. Canonicalizing here keeps the rule's
/// path identical to what a live request reduces to, so the exact match is faithful. Dropping the
/// parameters is what keeps a learned rule usable: an observed `/v1/chat;jsessionid=…` would
/// otherwise be written into the allowlist bound to one expired session.
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
    use crate::allowlist::{DefaultAction, classify};
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
        ev_from(host, port, method, path, reason, proto, Plane::Agent)
    }

    /// The same refusal, attributed to a named proxy — a declared task's per-invocation proxy shares
    /// the agent's ring, so a plane is what tells its refusals from the agent's.
    fn ev_from(
        host: &str,
        port: u16,
        method: Option<&str>,
        path: Option<&str>,
        reason: &str,
        proto: Proto,
        plane: Plane,
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
            plane,
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

    /// Under an `ask` posture a `denied-default` for an undecided destination is not this run's to
    /// answer: the agent's own proxy parks such a request and logs the operator's answer
    /// (`asked-denied`, not learnable), and a rule the posture puts to a person stays theirs to
    /// decide.
    ///
    /// The two halves that must not move with it: the deny posture the feature exists for still
    /// learns the identical refusal, and what an `ask` posture genuinely refuses on its own — the
    /// opt-in capabilities, which never reach the default action — is still learned.
    #[test]
    fn a_refusal_the_posture_would_put_to_a_person_is_never_learned() {
        let asking = || {
            EgressPolicy::new(vec![classify("api.internal").unwrap()], vec![])
                .with_default(DefaultAction::Ask)
        };
        let refused = ev("evil.test", 443, Some("GET"), Some("/x"), "denied-default");

        let out = synthesize(
            std::slice::from_ref(&refused),
            &asking(),
            Granularity::Domain,
        );
        assert!(
            out.rules.is_empty(),
            "an `ask` posture's answer must not be pre-empted by a refusal: {:?}",
            out.rules
        );
        assert!(
            out.notes.iter().any(|n| n.contains("evil.test")),
            "and the skip must be surfaced, not silent: {:?}",
            out.notes
        );

        // The posture the feature exists for is untouched: the same refusal under deny-by-default
        // still learns its rule, so the gate cannot be satisfied by learning nothing.
        assert_eq!(
            synthesize(&[refused], &empty_policy(), Granularity::Domain).rules,
            vec!["{*} https://evil.test".to_string()]
        );

        // A WebSocket is opt-in, so it never reaches the default action: under `ask` the policy
        // refuses it outright rather than parking it, and that refusal is genuinely the agent's.
        assert_eq!(
            synthesize(
                &[ev(
                    "chat.test",
                    443,
                    Some("WS"),
                    Some("/socket"),
                    "denied-default"
                )],
                &asking(),
                Granularity::Domain,
            )
            .rules,
            vec!["{WS} https://chat.test".to_string()]
        );
    }

    /// A declared task's per-invocation proxy is hardwired to deny-by-default and shares the
    /// session's ring, so its misses land here as learnable `denied-default` events under a policy
    /// that is not the agent's. Learning them would widen the **app's** allowlist for a destination
    /// only the task reached — and the task's `network` list is declared with the task precisely so
    /// that no run has to discover it.
    ///
    /// The half that must not move with it: the identical refusal on the agent's plane is still
    /// learned, so the gate cannot be satisfied by learning nothing.
    #[test]
    fn a_refusal_from_a_declared_tasks_own_proxy_is_never_learned() {
        let task_refusal = || {
            ev_from(
                "evil.test",
                443,
                Some("GET"),
                Some("/x"),
                "denied-default",
                Proto::Https,
                Plane::Task,
            )
        };

        let out = synthesize(&[task_refusal()], &empty_policy(), Granularity::Domain);
        assert!(
            out.rules.is_empty(),
            "a task's refusal must not become an app rule: {:?}",
            out.rules
        );
        assert!(
            out.notes.iter().any(|n| n.contains("another plane")),
            "and the skip must be surfaced, not silent: {:?}",
            out.notes
        );

        // An unattributed event is refused for the same reason: nothing shows it to be the agent's.
        let unknown = ev_from(
            "evil.test",
            443,
            Some("GET"),
            Some("/x"),
            "denied-default",
            Proto::Https,
            Plane::Unknown,
        );
        assert!(
            synthesize(&[unknown], &empty_policy(), Granularity::Domain)
                .rules
                .is_empty(),
            "an event with no recorded plane must not be read as the agent's"
        );

        // The agent's own refusal for the same destination is learned exactly as before.
        assert_eq!(
            synthesize(
                &[ev(
                    "evil.test",
                    443,
                    Some("GET"),
                    Some("/x"),
                    "denied-default"
                )],
                &empty_policy(),
                Granularity::Domain,
            )
            .rules,
            vec!["{*} https://evil.test".to_string()]
        );
    }

    /// A rule this synthesizer proposes is one the write path would take, whatever the cage wrote
    /// in the request that produced it.
    ///
    /// The path a learned rule carries comes from [`canonical_segments`], which percent-decodes:
    /// a request for `/a%1B%5B31mRED` reduces to a segment holding a raw escape sequence, and the
    /// three printable characters the cage sent are not what ends up in the rule. That rule is then
    /// echoed by the `--dry-run` preview and by `sbx net rules`, so a cage that chooses its own
    /// request paths chooses text on the operator's terminal.
    ///
    /// Both granularities that read a path are covered, and the witness is the same refusal with a
    /// plain path: it still learns, so this cannot be satisfied by a synthesizer that proposes
    /// nothing.
    #[test]
    fn a_rule_the_write_path_would_refuse_is_never_proposed() {
        for gran in [Granularity::Path, Granularity::Exact] {
            let painted = ev(
                "esc.test",
                443,
                Some("GET"),
                Some("/a%1B%5B31mRED/b"),
                "denied-default",
            );
            let out = synthesize(&[painted], &empty_policy(), gran);
            assert!(
                out.rules.iter().all(|r| classify(r).is_ok()),
                "{gran:?}: a proposed rule must be one the write path takes: {:?}",
                out.rules
            );
            assert!(
                out.rules.iter().all(|r| !r.chars().any(char::is_control)),
                "{gran:?}: and it must carry no control byte: {:?}",
                out.rules
            );
            assert!(
                !out.notes.is_empty(),
                "{gran:?}: a learnable refusal dropped without a note is a silent drop"
            );
            assert!(
                out.notes.iter().all(|n| !n.chars().any(char::is_control)),
                "{gran:?}: and the note that says so must not itself carry the bytes it is \
                 reporting: {:?}",
                out.notes
            );

            // The witness: the same refusal with an ordinary path still becomes a rule.
            let plain = ev(
                "plain.test",
                443,
                Some("GET"),
                Some("/a/b"),
                "denied-default",
            );
            assert!(
                !synthesize(&[plain], &empty_policy(), gran).rules.is_empty(),
                "{gran:?}: an ordinary refusal must still be learned"
            );
        }
    }

    /// Every plane the ring can carry that is not the agent's is named here, so the gate stays a
    /// positive list.
    ///
    /// [`from_agent`] admits [`Plane::Agent`] and nothing else, which is the shape that holds: a
    /// plane added later is excluded until someone says otherwise. Rewritten as a negative list —
    /// "everything except a task's" — it would admit each new plane silently, and a distro build's
    /// refusals are exactly the ones that would then widen the agent's allowlist for commands the
    /// project's own build wrote. Naming each plane is what makes that rewrite fail here.
    #[test]
    fn no_plane_but_the_agents_is_learned_from() {
        for plane in [Plane::Task, Plane::Build, Plane::Unknown] {
            let refusal = ev_from(
                "evil.test",
                443,
                Some("GET"),
                Some("/x"),
                "denied-default",
                Proto::Https,
                plane,
            );
            let out = synthesize(&[refusal], &empty_policy(), Granularity::Domain);
            assert!(
                out.rules.is_empty(),
                "a refusal on {plane:?} must not become an app rule: {:?}",
                out.rules
            );
            assert!(
                out.notes.iter().any(|n| n.contains("another plane")),
                "and the skip must be surfaced, not silent, on {plane:?}: {:?}",
                out.notes
            );
        }

        // The witness: the identical refusal on the agent's own plane is still learned, so the
        // assertions above cannot be satisfied by a synthesizer that learns nothing at all.
        assert_eq!(
            synthesize(
                &[ev(
                    "evil.test",
                    443,
                    Some("GET"),
                    Some("/x"),
                    "denied-default"
                )],
                &empty_policy(),
                Granularity::Domain,
            )
            .rules,
            vec!["{*} https://evil.test".to_string()]
        );
    }

    #[test]
    fn granularity_parse_round_trips_and_rejects_junk() {
        for g in [Granularity::Domain, Granularity::Path, Granularity::Exact] {
            assert_eq!(Granularity::parse(g.as_str()), Ok(g));
        }
        assert!(Granularity::parse("subtree").is_err());
    }

    /// An IPv6 literal on a non-default port is offered as a rule that admits the request refused.
    ///
    /// Appending `:port` to a bare `2001:db8::1` reads back as another address entirely: the
    /// grammar splits on the last colon, so the rule names the host `2001:db8:` on that port. The
    /// suggestion a refusal prints, the notification's copy of it and the candidate net-learn
    /// records are one text by design, so the bracketing lives in the one function that knows when
    /// an address needs it. The witnesses are a name and an IPv4, which must not change.
    #[test]
    fn an_ipv6_literal_is_offered_as_a_rule_that_reads_back_as_itself() {
        for (host, port, expect) in [
            ("2001:db8::1", 8443u16, "https://[2001:db8::1]:8443"),
            ("::1", 1u16, "https://[::1]:1"),
            ("2001:db8::1", 443u16, "https://[2001:db8::1]"),
            ("api.example.test", 8443u16, "https://api.example.test:8443"),
            ("203.0.113.7", 8443u16, "https://203.0.113.7:8443"),
        ] {
            let token = host_token(host, port, crate::sandbox::control::Proto::Https)
                .unwrap_or_else(|| panic!("`{host}` is a sane host"));
            assert_eq!(token, expect);
            // And the rule text parses back to the host and port it was made from, which is the
            // property the composition exists for.
            crate::allowlist::classify_in(&token, crate::allowlist::Slot::Allow)
                .unwrap_or_else(|e| panic!("`{token}` must be a rule: {e}"));
        }
    }

    /// Neither of the two events the transparent-capture tap writes may become a rule.
    ///
    /// A resolution is not a refusal: the tap answers **every** name without consulting the
    /// allowlist, so learning from those would write an allow for each host the cage merely asked
    /// about — including the ones it asked about precisely because they were not allowed. A bypass
    /// *is* a refusal, but of a connection to a bare address, and an address is not something a
    /// learned rule may name on the reader's behalf: the remedy is for the client to resolve the
    /// name. The gate is the reason, not the verdict, and this pins that it holds for both.
    #[test]
    fn nothing_the_capture_tap_reports_is_learned_into_the_allowlist() {
        let tap_event = |host: &str, port: u16, verdict, reason: &str, proto| LogEvent {
            seq: 1,
            at_epoch_ms: 0,
            host: host.to_string(),
            port,
            method: None,
            path: None,
            verdict,
            reason: reason.to_string(),
            proto,
            http_ver: crate::sandbox::control::HttpVer::Unknown,
            rpc: crate::sandbox::control::RpcKind::None,
            muted: false,
            status: None,
            plane: crate::sandbox::control::Plane::Agent,
            amend_seq: None,
            awaiting_capture: false,
            secrets_seen: Vec::new(),
        };
        for ev in [
            tap_event(
                "exfiltration.test",
                53,
                LogVerdict::Resolved,
                "resolved",
                Proto::Dns,
            ),
            tap_event(
                "93.184.216.34",
                443,
                LogVerdict::Blocked,
                "dns-bypassed",
                Proto::Tcp,
            ),
        ] {
            let reason = ev.reason.clone();
            assert!(
                rules(&[ev], Granularity::Domain).is_empty(),
                "a `{reason}` event must never become an allow rule"
            );
        }
    }

    /// Whether `rule` admits a `GET` for `path` on `api.test:443`.
    fn admits(rule: &str, path: &str) -> bool {
        let policy =
            EgressPolicy::new(vec![classify(rule).expect("a learned rule parses")], vec![]);
        matches!(
            policy.explain("api.test", 443, path, "GET"),
            Decision::AllowedBy(_)
        )
    }

    /// Every rule `exact` learns admits the request it came from and no other path. A path whose
    /// decoded segments a rule cannot spell back is skipped with a note quoting the path as logged:
    /// a decoded `*` as the last segment is the subtree wildcard, and a decoded `%` re-reads as an
    /// escape naming another path.
    #[test]
    fn exact_learns_only_a_rule_that_admits_its_own_request_and_nothing_else() {
        for path in ["/v1/chat", "/a%2Fb", "/v1/%2A", "/%2541", "/a%2A"] {
            let out = synthesize(
                &[ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some(path),
                    "denied-default",
                )],
                &empty_policy(),
                Granularity::Exact,
            );
            let shown = (&out.rules, &out.notes);
            for rule in &out.rules {
                assert!(admits(rule, path), "{rule} must admit {path}");
                for other in ["/v1/other", "/v1/chat/x", "/A", "/a/b/c", "/zzz"] {
                    if canonical_segments(other) != canonical_segments(path) {
                        assert!(
                            !admits(rule, other),
                            "{rule}, learned from {path}, admits {other}"
                        );
                    }
                }
            }
            let skipped = out
                .notes
                .iter()
                .any(|n| n.contains("no rule can match on its own") && n.contains(path));
            assert_eq!(
                out.rules.is_empty(),
                skipped,
                "{path}: a path is learned or skipped with a note, never both or neither: {shown:?}"
            );
        }
        for (path, learned) in [
            ("/v1/chat", true),
            ("/a%2Fb", true),
            ("/v1/%2A", false),
            ("/%2541", false),
        ] {
            let out = synthesize(
                &[ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some(path),
                    "denied-default",
                )],
                &empty_policy(),
                Granularity::Exact,
            );
            let shown = (&out.rules, &out.notes);
            assert_eq!(!out.rules.is_empty(), learned, "{path}: {shown:?}");
        }
    }

    /// `path` skips a section no rule can name on its own, with a note, and still learns a plain one.
    #[test]
    fn path_skips_a_section_no_rule_can_name() {
        for (path, learned) in [("/v1/x", true), ("/%2541/x", false), ("/%2A/x", false)] {
            let out = synthesize(
                &[ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some(path),
                    "denied-default",
                )],
                &empty_policy(),
                Granularity::Path,
            );
            let shown = (&out.rules, &out.notes);
            assert_eq!(!out.rules.is_empty(), learned, "{path}: {shown:?}");
            assert_eq!(
                out.notes
                    .iter()
                    .any(|n| n.contains("no rule can match on its own")),
                !learned,
                "{path}: {shown:?}"
            );
            for rule in &out.rules {
                assert!(admits(rule, path), "{rule} must admit {path}");
            }
        }
    }

    /// A refusal at the root has no section, so `path` opens the whole host and says so.
    #[test]
    fn path_says_when_a_root_refusal_opened_the_whole_host() {
        for path in ["/", "/?q=1"] {
            let out = synthesize(
                &[ev(
                    "api.test",
                    443,
                    Some("GET"),
                    Some(path),
                    "denied-default",
                )],
                &empty_policy(),
                Granularity::Path,
            );
            assert_eq!(out.rules, vec!["{*} https://api.test".to_string()]);
            assert!(
                out.notes
                    .iter()
                    .any(|n| n.contains("opened the whole host")),
                "{path}: {:?}",
                out.notes
            );
        }
        let out = synthesize(
            &[ev(
                "api.test",
                443,
                Some("GET"),
                Some("/v1/x"),
                "denied-default",
            )],
            &empty_policy(),
            Granularity::Path,
        );
        assert!(
            !out.notes
                .iter()
                .any(|n| n.contains("opened the whole host")),
            "{:?}",
            out.notes
        );
    }

    /// A learnable reason is read only on a `deny` from an inspected plane.
    #[test]
    fn a_learnable_reason_counts_only_on_an_inspected_deny() {
        let mut allowed = ev("api.test", 443, Some("GET"), Some("/"), "denied-default");
        allowed.verdict = LogVerdict::Allow;
        let mut events = vec![allowed];
        for proto in [Proto::Tcp, Proto::Other, Proto::Dns] {
            events.push(ev_on(
                "api.test",
                443,
                Some("GET"),
                Some("/"),
                "denied-default",
                proto,
            ));
        }
        let out = synthesize(&events, &empty_policy(), Granularity::Domain);
        let shown = (&out.rules, &out.notes);
        assert!(out.rules.is_empty(), "{shown:?}");
        for proto in [Proto::Https, Proto::Http] {
            let out = synthesize(
                &[ev_on(
                    "api.test",
                    443,
                    Some("GET"),
                    Some("/"),
                    "denied-default",
                    proto,
                )],
                &empty_policy(),
                Granularity::Domain,
            );
            let shown = (&out.rules, &out.notes);
            assert_eq!(out.rules.len(), 1, "{proto:?}: {shown:?}");
        }
    }

    /// Only a host in the one spelling the proxy reports is shaped into a rule.
    #[test]
    fn a_host_the_proxy_would_not_report_is_unusable() {
        for host in ["API.test", "api.test.", "[::1]", "a:b", "api.123"] {
            let out = synthesize(
                &[ev(host, 443, Some("GET"), Some("/"), "denied-default")],
                &empty_policy(),
                Granularity::Domain,
            );
            let shown = (&out.rules, &out.notes);
            assert!(out.rules.is_empty(), "{host}: {shown:?}");
            assert!(
                out.notes.iter().any(|n| n.contains("unusable host")),
                "{host}: {shown:?}"
            );
        }
    }
}
