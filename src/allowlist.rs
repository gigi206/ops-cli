//! The network egress policy: classify the entries a config declares into typed match
//! rules, and decide whether a request is permitted.
//!
//! A policy is an **allow** list plus an optional **deny** list, and **deny always wins**:
//! a request is permitted only when it matches some allow rule and matches no deny rule.
//! Deny lets a broad allow be carved out — `allow *.nixos.org` together with
//! `deny evil.nixos.org`, or `allow github.com` with `deny github.com/secret`.
//!
//! Each entry (in either list) is one of five kinds, told apart by syntax: a literal IP,
//! an exact domain, a `*.domain` wildcard (the domain and any subdomain) — each host kind
//! optionally `:port`-qualified (a comma list of ports and/or `lo-hi` ranges, or `:*`,
//! defaulting to {443}) — a `host[:port]/path` URL (exact, or a `/*`-suffixed subtree),
//! or a `re:<pattern>` regex. A rule may carry a scheme that selects its enforcement **layer**: a
//! bare host or `https://` is an **inspected-over-TLS** rule (the proxy man-in-the-middles the TLS
//! and enforces the full path / method / regex / redaction / anti-fronting policy); `http://host` is
//! an **inspected-cleartext** rule (the same HTTP policy on a plaintext connection — no TLS to
//! terminate, so the bytes travel in the clear); `tcp://host:port` is a **raw L4** rule (the proxy
//! splices the byte stream uninspected — host:port plus the SSRF guard are the only controls, for a
//! non-HTTP protocol such as SSH). The scheme selects the **layer and the default port**: bare or
//! `https://` is inspected-over-TLS on 443, `http://` is inspected-cleartext on 80, `tcp://` is L4
//! and must name an explicit `:port` (a raw splice names the port it opens); a `:port` overrides the
//! default, so `https://h` and bare `h` are the same rule (443). Both the cleartext and the raw
//! paths are **strictly opt-in** — only an explicit `http://`/`tcp://` allow rule enables them, and
//! neither consults the default action (a denylist/ask posture never silently opens a plaintext or a
//! raw connection). A `tcp://` rule is host:port only: it carries no `/path` and no `{method}` prefix
//! (a raw stream has no HTTP to inspect); an `http://` rule carries the full HTTP vocabulary (path,
//! method) like the TLS default. `udp://` is not yet supported, and any other scheme is rejected (a
//! scheme stays meaningful on a *request*, e.g. `ops test net https://…`, `ops test net http://…`, or
//! `ops test net tcp://host:22`).
//! Any L7 entry may carry a leading **method prefix** `{VERB,VERB,...}` (uppercase verbs, e.g.
//! `{GET,HEAD} github.com`) that scopes the rule to those HTTP methods only — a rule with no
//! prefix applies to every verb. The leading `{` is an unambiguous sentinel (no rule kind starts
//! with one), so it never collides with the `{n,m}` quantifiers a `re:` body may contain. A method
//! constraint narrows an allow to particular verbs — `{GET,HEAD} host` permits reads but forbids
//! writes — but it bounds what the agent can drive the upstream's API to do per the upstream's own
//! verb semantics; it is **not** raw-exfiltration protection (a GET URL still carries data out).
//! Classification
//! happens once when the config is resolved, so a malformed entry (including an
//! uncompilable regex) is rejected up front rather than silently mis-read at request time.
//! The matcher is shared by the config layer (which classifies and displays the rules) and
//! the filtering proxy (which matches live requests).
//!
//! The structured host kinds (IP, host, subdomain) are spoof-safe by construction: an
//! exact `Host` matches only that host — never a subdomain of it nor a lookalike like
//! `<host>.evil.com`; an `Ip` kind matches the request's literal host (not a name that
//! resolves to it). Each carries a **port set**: a bare entry (`github.com`) defaults to
//! the HTTPS port {443}; a `:`-suffixed comma list of ports and/or `lo-hi` ranges pins
//! exactly those (`github.com:8443`, `internal:8000-8100`, `1.2.3.4:80,443,8443`); and
//! `:*` (`github.com:*`) matches any port. An IPv6 literal is bracketed when it carries a
//! port (`[::1]:8443`, `[2001:db8::1]:*`) and bare otherwise (`::1`). A `host[:port]/path` URL
//! kind (`github.com/secret`, `github.com:443/secret`, `[::1]:8080/admin`) carries the same
//! port set as the host kinds (a bare host defaulting to {443}) and matches the path
//! **exactly** by default (`…/secret` matches `/secret`, not
//! `/secret/sub`), or the path and its whole subtree when written with a trailing `/*`
//! (`…/secret/*` covers `/secret/sub` too — segment-aware, so not `/secretarial`). Its host is
//! concrete (an exact host or IP); a `*.domain` wildcard with a path is not expressible — use
//! `re:` for that. The
//! request path is canonicalized first (percent-decoded, `.`/`..` resolved, query dropped),
//! so a deny on a given resource cannot be dodged by `/secret?x`, `/secret/`, `%2f`, or
//! `/foo/../secret` (all the same resource) — the in-cage agent controls the request, so
//! raw-string path matching would be a hole. A different sub-resource is a deliberate
//! choice (`/secret/*` to include it); for a query-specific or arbitrary pattern, use `re:`.
//!
//! A `re:<pattern>` kind matches the request's **whole reconstructed URL** —
//! `https://<host>[:<port>]<path>` (the port omitted when it is 443, `<path>` percent-decoded
//! and including any query string) — with the [`regex`] engine (linear-time, no catastrophic
//! backtracking). The regex is matched unanchored, so the pattern author owns anchoring and
//! escaping (an unanchored `api\.github\.com` would also match `evil.com/?x=api.github.com`);
//! for pinning a host, prefer the exact `Host`/`Subdomain` kinds, which cannot be fumbled.
//! Unlike a structured `Url` rule, the regex path is **not** `.`/`..`-resolved, so a `re:`
//! deny can be dodged by `/foo/../secret` — anchor and structure the pattern accordingly, or
//! use a structured rule when a dot-segment-proof deny is what you need.

use std::fmt;
use std::net::IpAddr;

use regex::Regex;

/// One classified match rule, used in either the allow or the deny list: a syntactic [`RuleKind`],
/// the set of HTTP [`Methods`] it applies to, and the enforcement [`Layer`] its scheme selects. A
/// rule with no `{...}` method prefix carries [`Methods::Unspecified`] (later resolved to the
/// context default by `apply_default_methods`); a method-qualified rule (`{GET,HEAD} host`) applies
/// only to those verbs, and an explicit `{*}` is [`Methods::Any`]. A bare or `https://` rule is
/// [`Layer::L7`] (inspected, the default); a `tcp://` rule is [`Layer::L4`] (raw-spliced, host:port).
#[derive(Debug, Clone)]
pub(crate) struct Rule {
    pub(crate) kind: RuleKind,
    pub(crate) methods: Methods,
    pub(crate) layer: Layer,
    /// The `[net.groups]` group this rule was expanded from (`@<name>`), or `None` for a
    /// directly-written or built-in rule. Display-only provenance for `ops net rules` — it names
    /// where a rule came from, and is deliberately **excluded from equality** (a rule's identity is
    /// its match, not its origin), so adding it changes no matching, dedup, or policy-comparison
    /// behavior. It travels with the rule: `apply_default_methods` mutates methods in place and
    /// `merge_app` moves the whole policy, so the origin survives to the point it is rendered.
    pub(crate) group: Option<String>,
}

/// Equality ignores [`Rule::group`] — a rule's identity is what it matches (kind, methods, layer),
/// not which group it was expanded from — so provenance never affects matching, dedup, or the
/// derived equality of an [`EgressPolicy`] built from these rules.
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.methods == other.methods && self.layer == other.layer
    }
}

impl Eq for Rule {}

/// The enforcement path a rule's scheme selects. [`Layer::L7`] (the default — a bare or `https://`
/// rule) is **inspected over TLS**: the proxy terminates the TLS (a MITM), parses the HTTP request,
/// and enforces the full path / method / regex / redaction / anti-fronting policy. [`Layer::L7Clear`]
/// (an `http://` rule) is **inspected in the clear**: the same HTTP policy, but on a plaintext
/// connection — there is no TLS to terminate, so the proxy forwards the absolute-form request the
/// client sends and no leaf is minted. [`Layer::L4`] (a `tcp://` rule) is a **raw splice**: the proxy
/// copies the TCP byte stream verbatim without terminating TLS or inspecting it, for a non-HTTP
/// protocol such as SSH. An L4 rule's only controls are its host:port match and the SSRF guard; it
/// has no path, no method, and no Host/SNI anti-fronting.
///
/// Both the splice and the cleartext path are **strictly opt-in** — only an explicit `tcp://` /
/// `http://` allow rule enables them, so a host with no such rule is always the inspected-over-TLS
/// path, and the default action is never consulted for either (a denylist or ask posture does not
/// silently open a raw or a plaintext connection). `http://` differs from `tcp://` in that it keeps
/// the full HTTP policy (path, method, the outbound-secret tripwire) — its one loss is transport
/// confidentiality (the bytes are cleartext on the wire) and, like a splice, **credential
/// injection**: a header secret is never injected into a cleartext request (the secret-target
/// validator rejects an `http://`/`tcp://` `to`, so a secret host must be inspected-over-TLS), since
/// sending a bearer in the clear would downgrade it. The credential machinery is bypassed wholesale
/// on a **spliced** host (no request head to inspect at all — injection, response redaction, and the
/// outbound tripwire are all inert); cleartext keeps the outbound tripwire (it has a head to scan)
/// but not injection. Both opt-in paths are trusted-only and self-authored, the blast radius stays
/// that one host, and each is loud, so both are within the threat model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Layer {
    /// Inspected over TLS (a bare or `https://` rule) — the MITM path. The default.
    #[default]
    L7,
    /// Inspected in the clear (an `http://` rule) — the same HTTP policy on a plaintext connection,
    /// no TLS termination and no credential injection.
    L7Clear,
    /// Raw L4 (a `tcp://` rule) — the splice path: host:port + the SSRF guard, no inspection.
    L4,
}

impl Layer {
    /// The default port a rule of this layer's scheme takes when it names none: 443 for the
    /// inspected-over-TLS default (bare/`https://`), 80 for cleartext (`http://`). L4 (`tcp://`)
    /// requires an explicit port, so its default is never consulted — 443 is an inert placeholder.
    fn default_port(self) -> u16 {
        match self {
            Layer::L7 | Layer::L4 => 443,
            Layer::L7Clear => 80,
        }
    }

    /// Whether this layer inspects the HTTP head (both TLS and cleartext L7), as opposed to the raw
    /// L4 splice. The inspected layers share the path / method / redaction / anti-fronting policy and
    /// the read-by-default (`default_methods`) rewrite; only the transport differs.
    fn inspected(self) -> bool {
        matches!(self, Layer::L7 | Layer::L7Clear)
    }
}

/// The syntactic kind of a match rule, inferred from an entry's syntax at config resolution; an
/// entry that matches none is a hard error, never a silent drop.
#[derive(Debug, Clone)]
pub(crate) enum RuleKind {
    /// A literal IP with a port set: matches a request whose host is exactly this address
    /// and whose port the set admits (any path).
    Ip(IpAddr, Ports),
    /// An exact hostname with a port set: matches that host only — not its subdomains — on
    /// a port the set admits (any path).
    Host(String, Ports),
    /// A `*.domain` wildcard with a port set: matches the apex `domain` and any subdomain,
    /// on a port the set admits (any path).
    Subdomain(String, Ports),
    /// A `host[:ports]/path` URL rule: matches this host on a port the set admits, and the
    /// path — **exactly** by default, or the path and its subtree when declared with a trailing
    /// `/*` (`subtree`). The host is concrete (an exact host or IP); a `*.domain` wildcard with
    /// a path is not expressible — use `re:` for that.
    Url {
        host: String,
        ports: Ports,
        /// The declared path, including a trailing `/*` when `subtree`.
        path: String,
        /// Set when the declared path ended in `/*`: match the path and its subtree, not just
        /// the exact path.
        subtree: bool,
    },
    /// A `re:<pattern>` regex over the request's whole reconstructed URL. The pattern is
    /// kept for display and equality; the compiled engine does the matching.
    Regex { pattern: String, re: Regex },
}

/// The HTTP methods a rule applies to.
///
/// - [`Methods::Unspecified`] — the rule carried no `{...}` prefix. It matches **every** verb on its
///   own (the no-regression default), but it is the only state a per-app `default_methods` rewrites:
///   at policy resolution an `Unspecified` allow rule becomes `Only(default_methods)` when that app
///   declares one, so an unscoped host inherits the app's read-by-default posture.
/// - [`Methods::Any`] — the rule carried an explicit `{*}` prefix: **all verbs, on purpose**. Unlike
///   `Unspecified` it is never rewritten by `default_methods`, so `{*}` is how a rule opts a host
///   back out to every verb under a read-by-default app.
/// - [`Methods::Only`] — an explicit, non-empty set of uppercase verbs (sorted and de-duplicated so
///   equal specs compare and display identically).
///
/// A method constraint narrows a rule to particular verbs — `{GET,HEAD} host` permits reads but
/// forbids writes to that host. It bounds what the agent can drive the upstream's API to do per the
/// upstream's own verb semantics; it is **not** raw-exfiltration protection (a GET URL still carries
/// data out).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Methods {
    /// No method prefix — all verbs, but subject to a per-app `default_methods` rewrite.
    #[default]
    Unspecified,
    /// An explicit `{*}` prefix — all verbs, never rewritten by `default_methods`.
    Any,
    /// An explicit, non-empty set of uppercase verbs, sorted and de-duplicated.
    Only(Vec<String>),
}

impl Methods {
    /// Whether this set applies to `method` (already uppercased by the caller). `Unspecified` and
    /// `Any` both admit every HTTP verb (the difference between them is only whether `default_methods`
    /// may rewrite them, resolved before matching); `Only` admits exactly the listed ones.
    ///
    /// `WS` (the WebSocket-upgrade pseudo-verb the proxy checks for an `Upgrade: websocket` handshake)
    /// is special: it is a distinct, unredactable bidirectional capability, not just another HTTP
    /// method, so an unrestricted allowance does NOT grant it — only a rule that names `WS` explicitly
    /// (`{WS}` or `{…,WS}`) admits it. Neither a bare/`Unspecified` rule nor `{*}` opens a WebSocket.
    ///
    /// A `*` **inside** an `Only` set (`{*,WS}`) means "every HTTP verb" alongside the named extras, so
    /// `{*,WS}` reads as "all HTTP methods **and** WebSocket" in one rule — the ergonomic form of an
    /// all-verbs host that also needs the WS capability. `*` never matches the `WS` pseudo-verb (that
    /// still needs an explicit `WS`), so `{*}`-widening a host and `WS`-opting it stay separate choices.
    fn admits(&self, method: &str) -> bool {
        if method == "WS" {
            return matches!(self, Methods::Only(ms) if ms.iter().any(|m| m == "WS"));
        }
        match self {
            Methods::Unspecified | Methods::Any => true,
            Methods::Only(ms) => ms.iter().any(|m| m == method || m == "*"),
        }
    }

    /// The display prefix: empty for `Unspecified` (the rule renders bare), `{*} ` for `Any`, else
    /// `{V,V,...} ` with the verbs comma-joined and a trailing space before the rule body.
    fn prefix(&self) -> String {
        match self {
            Methods::Unspecified => String::new(),
            Methods::Any => "{*} ".to_string(),
            Methods::Only(ms) => format!("{{{}}} ", ms.join(",")),
        }
    }
}

/// The set of ports a host-level rule (`Ip`/`Host`/`Subdomain`) admits. A bare entry defaults to
/// the HTTPS port {443} — `https` is the implicit scheme, so `github.com` and `https://github.com`
/// are the same rule; a `:`-suffixed spec pins an explicit set — a comma list of single ports
/// and/or inclusive `lo-hi` ranges; `:*` admits any port. The least privilege of the bare default
/// keeps `allow github.com` from being CONNECT-tunnelled to an arbitrary port like 22 (open the
/// HTTP port explicitly with `:80`/`:*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ports {
    /// `:*` — any port.
    Any,
    /// A set of inclusive `(lo, hi)` ranges (a single port is `(p, p)`), sorted and
    /// de-duplicated so equal specs compare and display identically. The default is `[(443, 443)]`.
    Ranges(Vec<(u16, u16)>),
}

impl Default for Ports {
    /// The implicit port set of a host with no `:port` — the HTTPS port. This is the *L7 web*
    /// default a bare/`https://` host gets, not a universal one: a `tcp://` rule must name its port
    /// explicitly, and an `http://` rule carries its own (80). The classify path threads the
    /// scheme's default through [`Ports::single`]; this `Default` is the 443 case, used where a rule
    /// is built directly (tests, fixtures) with no scheme in view.
    fn default() -> Self {
        Ports::Ranges(vec![(443, 443)])
    }
}

impl Ports {
    /// A single-port set `[(p, p)]` — the classify default for a host with no `:port`, `p` being the
    /// scheme's default port (443 inspected-over-TLS, 80 cleartext). Keeps the default port a
    /// property of the scheme rather than hard-coding 443 in every split.
    fn single(p: u16) -> Self {
        Ports::Ranges(vec![(p, p)])
    }

    /// Whether `port` falls in the set.
    fn admits(&self, port: u16) -> bool {
        match self {
            Ports::Any => true,
            Ports::Ranges(rs) => rs.iter().any(|(lo, hi)| port >= *lo && port <= *hi),
        }
    }

    /// Whether this set shares at least one port with `other` — `Any` overlaps everything, two
    /// range sets overlap when any range of one meets any range of the other. Used to flag an
    /// L4/L7 rule overlap on the same host.
    fn intersects(&self, other: &Ports) -> bool {
        match (self, other) {
            (Ports::Any, _) | (_, Ports::Any) => true,
            (Ports::Ranges(a), Ports::Ranges(b)) => a
                .iter()
                .any(|(alo, ahi)| b.iter().any(|(blo, bhi)| alo <= bhi && blo <= ahi)),
        }
    }

    /// Render the `:port` suffix, omitting the single-port default `Some(p)` (443 for the
    /// inspected-over-TLS default `https`, 80 for cleartext `http`) so a scheme-default host renders
    /// compact — empty for that default, `:*` for any, else `:` plus a comma list where each item is
    /// `p` or `lo-hi`. `None` never omits (an L4 `tcp://` rule, which must always name its port so
    /// `tcp://host:443` round-trips rather than rendering as `tcp://host`).
    fn render_suffix(&self, omit_default: Option<u16>) -> String {
        match self {
            Ports::Any => ":*".to_string(),
            Ports::Ranges(rs) if omit_default.is_some_and(|d| rs.as_slice() == [(d, d)]) => {
                String::new()
            }
            Ports::Ranges(rs) => {
                let parts: Vec<String> = rs
                    .iter()
                    .map(|(lo, hi)| {
                        if lo == hi {
                            lo.to_string()
                        } else {
                            format!("{lo}-{hi}")
                        }
                    })
                    .collect();
                format!(":{}", parts.join(","))
            }
        }
    }
}

/// A request to match, pre-canonicalized once so every rule sees the same normalized
/// view — the key to closing adversary path-evasion. The in-cage agent controls the raw
/// request, so the target is percent-decoded, its `.`/`..` resolved, and its query split
/// off **before** matching; otherwise a literal `deny /secret` is trivially dodged by
/// `/secret?x`, `/secret/`, `%2f`, or `/foo/../secret`. The proxy that enforces the policy
/// must build this *identically* to the `ops test net` tester, or the tester would mispredict.
pub(crate) struct Request {
    /// The request host, lowercased and (for an IP literal) canonicalized.
    host: String,
    /// The request port.
    port: u16,
    /// The canonical path segments: percent-decoded, `.`/`..` resolved, empties dropped,
    /// query removed. `/a//b/../c?x=1` → `["a", "c"]`.
    segs: Vec<String>,
    /// The canonical URL a `re:` rule matches against: `https://host[:port]<decoded-target>`
    /// (the port shown only when it is not 443, an IPv6 host bracketed). Egress is HTTPS, so
    /// the scheme is always `https`. Decoded so a regex deny is not dodged by encoding.
    url: String,
}

impl Request {
    /// Build a request from the host, port, and raw target (`path` with any query).
    pub(crate) fn new(host: &str, port: u16, target: &str) -> Self {
        let host = canonical_host(host);
        let segs = canonical_segments(target);
        let decoded = percent_decode(target);
        let url = if port == 443 {
            format!("https://{}{decoded}", display_host(&host))
        } else {
            format!("https://{}:{port}{decoded}", display_host(&host))
        };
        Request {
            host,
            port,
            segs,
            url,
        }
    }
}

impl Rule {
    /// Whether this rule matches the (already-canonicalized) request for `method` (uppercased by
    /// the caller): its method set must admit the verb **and** its [`RuleKind`] must match the
    /// host/port/path. The method is a separate dimension, kept out of the canonical URL the
    /// `RuleKind` matches. Host-level callers that are method-agnostic by construction (credential
    /// injection, live `ask`-session rules) go straight through [`RuleKind::matches`] instead.
    fn matches(&self, req: &Request, method: &str) -> bool {
        self.methods.admits(method) && self.kind.matches(req)
    }

    /// Whether this rule silences a denied request's log line for `method` — the `mute` match. Like
    /// [`Self::matches`] but **port- and transport-agnostic** (via [`RuleKind::matches_any_port`]):
    /// `mute` is a `dontaudit` log filter, so naming a host suppresses its refusals on every port
    /// and scheme (a bare-host mute covers the host's cleartext `:80` noise as well as `:443`), and
    /// the rule's own layer is irrelevant. Method and path scope are still honored, so a
    /// `{POST} host/log` mute stays precise.
    fn matches_mute(&self, req: &Request, method: &str) -> bool {
        self.methods.admits(method) && self.kind.matches_any_port(req)
    }
}

impl RuleKind {
    /// Whether this kind matches the (already-canonicalized) request. A `Url` kind needs the
    /// host and port to be equal and the path to satisfy [`path_matches`] — exact by default,
    /// or the path and its subtree when the rule was declared with a trailing `/*`. The
    /// canonicalization means `/secret?x`, `/secret/`, `%2f`, and `/foo/../secret` all reduce
    /// to the same path, so a deny cannot be dodged. A `Regex` kind matches the canonical URL.
    fn matches(&self, req: &Request) -> bool {
        match self {
            RuleKind::Ip(ip, ports) => {
                ports.admits(req.port)
                    && req
                        .host
                        .parse::<IpAddr>()
                        .map(|h| &h == ip)
                        .unwrap_or(false)
            }
            RuleKind::Host(h, ports) => ports.admits(req.port) && &req.host == h,
            RuleKind::Subdomain(d, ports) => {
                ports.admits(req.port) && (&req.host == d || req.host.ends_with(&format!(".{d}")))
            }
            RuleKind::Url {
                host: h,
                ports,
                path: pa,
                subtree,
            } => &req.host == h && ports.admits(req.port) && path_matches(&req.segs, pa, *subtree),
            RuleKind::Regex { re, .. } => re.is_match(&req.url),
        }
    }

    /// Like [`Self::matches`] but **ignoring the port** — used only for `mute` (via
    /// [`Rule::matches_mute`]), a pure log-noise filter keyed by host/path: a named host's refusals
    /// are silenced on every port, so a bare-host mute (implicitly the 443 web port) also covers that
    /// host's cleartext `:80` noise. The verdict path never uses this — there the port is
    /// load-bearing (opening `:80` cleartext is a real posture, distinct from `:443`).
    fn matches_any_port(&self, req: &Request) -> bool {
        match self {
            RuleKind::Ip(ip, _) => req
                .host
                .parse::<IpAddr>()
                .map(|h| &h == ip)
                .unwrap_or(false),
            RuleKind::Host(h, _) => &req.host == h,
            RuleKind::Subdomain(d, _) => &req.host == d || req.host.ends_with(&format!(".{d}")),
            RuleKind::Url {
                host: h,
                path: pa,
                subtree,
                ..
            } => &req.host == h && path_matches(&req.segs, pa, *subtree),
            RuleKind::Regex { re, .. } => re.is_match(&req.url),
        }
    }
}

/// Whether a request's canonical path segments satisfy a URL rule's path. **Exact** equality
/// by default — `…/secret` matches only `/secret` (and its same-resource canonical variants),
/// not `/secret/sub`. A **subtree** rule, declared with a trailing `/*`, matches the path and
/// everything under it via a segment-prefix (`…/secret/*` covers `/secret` and `/secret/sub`,
/// but not `/secretarial` — the prefix is segment-aware). The rule path is canonicalized the
/// same way as the request, and the trailing `/*` is stripped before comparison.
fn path_matches(req_segs: &[String], rule_path: &str, subtree: bool) -> bool {
    let base = if subtree {
        rule_path.strip_suffix("/*").unwrap_or(rule_path)
    } else {
        rule_path
    };
    let rule_segs = canonical_segments(base);
    if subtree {
        req_segs.starts_with(&rule_segs)
    } else {
        req_segs == rule_segs.as_slice()
    }
}

/// Canonicalize a raw request target into path segments for matching: drop the query,
/// percent-decode, then resolve `.`/`..` and drop empty segments. The result is what
/// segment-prefix matching compares, so an encoded or dot-laden path cannot slip past a
/// rule. (Single-level decoding — a double-encoded `%252f` stays literal, matching a
/// server that decodes once.)
pub(crate) fn canonical_segments(target: &str) -> Vec<String> {
    let path = target.split('?').next().unwrap_or("");
    let decoded = percent_decode(path);
    let mut out: Vec<String> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s.to_string()),
        }
    }
    out
}

/// Percent-decode a string once: `%XX` (two hex digits) becomes that byte; a stray `%`
/// or a non-hex pair is left as-is. Invalid UTF-8 from decoding is replaced lossily — the
/// result is only ever compared, never executed.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The value of one hex digit, or `None` if the byte is not `[0-9A-Fa-f]`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Canonicalize a host for matching: lowercase it, drop a trailing DNS root dot, and if it is an
/// IP literal, normalize it to its canonical textual form so every spelling of one address compares
/// equal (`::1` and `0:0:0:0:0:0:0:1` both become `::1`). A hostname passes through lowercased and
/// dot-stripped. Applied on both sides — the rule (`parse_url_target`) and the request
/// (`Request::new`) — so a `Url`/`Host`/`Subdomain` host cannot be dodged by an alternate IPv6
/// spelling or a fully-qualified trailing dot (`evil.com.`, which DNS resolves identically but rules
/// can never carry, since `is_valid_hostname` rejects it). The filtering proxy reuses it to compare
/// the CONNECT host, the TLS SNI, and the decrypted `Host` header against one normal form (anti
/// domain-fronting).
pub(crate) fn canonical_host(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    // Strip every trailing dot: `evil.com.` is the absolute-FQDN form and `evil.com..` resolves to
    // the same host, while rules are always dot-free — so normalize the request side to one dot-free
    // form. (The proxy connects to this canonicalized host, so the connect target is clean too; an
    // IP literal never carries a trailing dot, so this is a no-op for those.)
    let lower = lower.trim_end_matches('.');
    match lower.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => lower.to_string(),
    }
}

/// Format a host for display in a URL context, bracketing an IPv6 literal so a following
/// `:port` is unambiguous (`2001:db8::1` → `[2001:db8::1]`); a hostname or IPv4 is unchanged.
fn display_host(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_ipv6() => format!("[{host}]"),
        _ => host.to_string(),
    }
}

/// Two kinds are equal when they are the same variant with the same data; for a regex that is
/// the same pattern string (the compiled engine has no equality of its own). [`Rule`] then
/// derives equality over its kind and method set.
impl PartialEq for RuleKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (RuleKind::Ip(a, pa), RuleKind::Ip(b, pb)) => a == b && pa == pb,
            (RuleKind::Host(a, pa), RuleKind::Host(b, pb)) => a == b && pa == pb,
            (RuleKind::Subdomain(a, pa), RuleKind::Subdomain(b, pb)) => a == b && pa == pb,
            (
                RuleKind::Url {
                    host: h1,
                    ports: p1,
                    path: pa1,
                    ..
                },
                RuleKind::Url {
                    host: h2,
                    ports: p2,
                    path: pa2,
                    ..
                },
            ) => h1 == h2 && p1 == p2 && pa1 == pa2,
            (RuleKind::Regex { pattern: a, .. }, RuleKind::Regex { pattern: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl Eq for RuleKind {}

/// A rule renders as its optional method prefix (`{GET,HEAD} ` — empty for [`Methods::Any`], and
/// always empty for L4), then a scheme that always names the layer, then its kind. The scheme is
/// `tcp://` for [`Layer::L4`], `http://` for [`Layer::L7Clear`], and `https://` for an inspected-
/// over-TLS host-level kind (`Ip`/`Host`/`Subdomain`/`Url`) — so the layer is visible wherever rules
/// are listed (`ops net rules`, `ops config`). A `re:` regex carries its own scheme inside the
/// pattern (the matched URL is `https://…`), so it shows none. Every form round-trips through
/// [`classify`]: a bare-typed host re-renders as `https://host` (the explicit equal form), and
/// `{GET} https://h`, `http://h`, `tcp://h:port` reparse to themselves.
impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.layer {
            Layer::L4 => "tcp://",
            Layer::L7Clear => "http://",
            // A regex's pattern is already a full URL with its own scheme — prefixing it would be
            // meaningless and non-round-trippable; a structured L7 kind shows the implicit `https://`.
            Layer::L7 if matches!(self.kind, RuleKind::Regex { .. }) => "",
            Layer::L7 => "https://",
        };
        // The port suffix omits each scheme's default so a bare host renders compact: 443 for
        // `https://`, 80 for `http://`. L4 must always name its port (a `tcp://host` with no port
        // fails to re-classify), so it renders the port explicit (omit nothing).
        let omit_default = match self.layer {
            Layer::L4 => None,
            other => Some(other.default_port()),
        };
        let kind = self.kind.render(omit_default);
        write!(f, "{}{scheme}{kind}", self.methods.prefix())
    }
}

impl RuleKind {
    /// Render the kind, omitting the single-port default `omit_default` from the `:port` suffix (443
    /// for `https`, 80 for `http`) so a scheme-default host renders compact; `None` forces the port
    /// explicit (L4, so `tcp://host:443` round-trips).
    fn render(&self, omit_default: Option<u16>) -> String {
        let suffix = |ports: &Ports| ports.render_suffix(omit_default);
        match self {
            RuleKind::Ip(ip, ports) => {
                let s = suffix(ports);
                // bracket an IPv6 literal when it carries a port, so `:port` is unambiguous
                if !s.is_empty() && ip.is_ipv6() {
                    format!("[{ip}]{s}")
                } else {
                    format!("{ip}{s}")
                }
            }
            RuleKind::Host(h, ports) => format!("{h}{}", suffix(ports)),
            RuleKind::Subdomain(d, ports) => format!("*.{d}{}", suffix(ports)),
            RuleKind::Url {
                host, ports, path, ..
            } => format!("{}{}{path}", display_host(host), suffix(ports)),
            RuleKind::Regex { pattern, .. } => format!("re:{pattern}"),
        }
    }
}

impl fmt::Display for RuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(Some(443)))
    }
}

/// What a request that matches no rule gets — the policy's default action, orthogonal to
/// the allow/deny lists. `Deny` is the classic allowlist (nothing reaches but the listed
/// hosts); `Allow` is a denylist (everything public reaches *except* the listed hosts), with
/// the filtering proxy still active so deny carve-outs, the SSRF guard, credential injection,
/// and redaction all keep working. `Ask` parks an undecided request for a live human decision
/// (allow rules auto-pass, deny rules auto-fail, everything else waits).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DefaultAction {
    /// No rule matched ⇒ deny (the classic allowlist; the default).
    #[default]
    Deny,
    /// No rule matched ⇒ allow (a denylist; the proxy stays active for the matched-deny,
    /// SSRF, injection, and redaction paths).
    Allow,
    /// No rule matched ⇒ park the request for a live decision (allow rules still auto-pass,
    /// deny rules still auto-fail). The proxy blocks the connection until a host-side
    /// `ops net pending allow|deny` answers it or the configured timeout elapses (deny).
    Ask,
}

/// A classified egress policy: an allow list, a deny list, and a default action for a request
/// that matches neither. Deny always wins. Under [`DefaultAction::Deny`] an empty allow list
/// permits nothing; under [`DefaultAction::Allow`] the allow list's only remaining effect is the
/// SSRF private-host exception (every public host is already permitted). Under
/// [`DefaultAction::Ask`] `ask_timeout` bounds how long a parked request waits for a decision
/// (`None` = wait indefinitely until answered); it is inert under the other defaults. The `ask`
/// park notice is printed to stderr by default; a policy may suppress it (the request still parks).
/// A `[network] http2` entry: a canonicalized host and an optional port. The egress proxy speaks
/// HTTP/2 (ALPN `h2`, for gRPC) to a CONNECT target matching one of these; a `None` port matches
/// any port, a `Some(port)` only that port. It selects the transport only — the host must still be
/// permitted by an `allow` rule, and every stream is verdict-checked like the HTTP/1.1 path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http2Host {
    host: String,
    port: Option<u16>,
}

impl Http2Host {
    /// Parse a config entry `host` or `host:port`. Returns `None` for a malformed entry (empty host,
    /// or a `:suffix` that is not a valid port) — the caller drops it with a warning, fail-closed
    /// (that host simply keeps HTTP/1.1). A hostname is expected: an h2 target needs an SNI, and the
    /// proxy refuses IP-literal CONNECT targets, so the `:port` split (rightmost colon, numeric
    /// suffix) does not attempt to parse a bracketed IPv6 literal.
    pub(crate) fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }
        if let Some((h, p)) = entry.rsplit_once(':') {
            if !h.is_empty() && !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                let port: u16 = p.parse().ok()?;
                return Some(Self {
                    host: canonical_host(h),
                    port: Some(port),
                });
            }
        }
        Some(Self {
            host: canonical_host(entry),
            port: None,
        })
    }

    /// The canonical entry text (for `ops config show`): `host` or `host:port`.
    pub(crate) fn display(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }

    /// Whether a CONNECT to `host:port` (host already canonicalized) matches this entry.
    fn matches(&self, host: &str, port: u16) -> bool {
        self.host == host && self.port.map(|p| p == port).unwrap_or(true)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EgressPolicy {
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    /// Log-suppression rules (SELinux `dontaudit`): a **denied** request matching one of these is
    /// still refused and still counted in `ops net stats`, but its refusal is kept out of the
    /// default `ops net log` view (`ops net log --all` shows it). Consulted only at logging time via
    /// [`Self::muted`], never in [`Self::explain`] — so a mute entry can never change a verdict.
    mute: Vec<Rule>,
    default_action: DefaultAction,
    ask_timeout: Option<std::time::Duration>,
    /// Stored inverted so the derived `Default` (and [`Self::new`]) both mean "notice shown".
    /// Read via [`Self::ask_notice`].
    suppress_ask_notice: bool,
    /// DNS cache TTL for the proxy's host-side resolver. `None` means the default (60s) is applied at
    /// the resolver build site; `Some(0)` disables the cache. Read via [`Self::dns_cache_ttl`].
    dns_cache_ttl: Option<std::time::Duration>,
    /// The `[network] http2` hosts: CONNECT targets the proxy man-in-the-middles as **HTTP/2**
    /// (ALPN `h2`, for gRPC) instead of the default HTTP/1.1. Consulted only at connection time via
    /// [`Self::speaks_http2`] to pick the TLS ALPN — never a verdict (a host must still be allowed by
    /// an `allow` rule). Read via [`Self::http2_hosts`].
    http2: Vec<Http2Host>,
}

impl EgressPolicy {
    /// A deny-by-default policy (the classic allowlist). Use [`Self::with_default`] to make it
    /// a denylist.
    pub(crate) fn new(allow: Vec<Rule>, deny: Vec<Rule>) -> Self {
        Self {
            allow,
            deny,
            mute: Vec::new(),
            default_action: DefaultAction::Deny,
            ask_timeout: None,
            suppress_ask_notice: false,
            dns_cache_ttl: None,
            http2: Vec::new(),
        }
    }

    /// Attach the log-suppression (`mute`) rules, returning the policy (builder style). A denied
    /// request matching one is refused as usual and counted in stats, but kept out of the default
    /// `ops net log` view. Purely a logging filter — never consulted by [`Self::explain`].
    pub(crate) fn with_mute(mut self, mute: Vec<Rule>) -> Self {
        self.mute = mute;
        self
    }

    /// Set the action a request matching no rule gets, returning the policy (builder style).
    pub(crate) fn with_default(mut self, action: DefaultAction) -> Self {
        self.default_action = action;
        self
    }

    /// Set how long an `ask`-default request parks before timing out to a deny, returning the
    /// policy (builder style). `None` (the default) waits indefinitely. Inert unless the
    /// default action is [`DefaultAction::Ask`].
    pub(crate) fn with_ask_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.ask_timeout = timeout;
        self
    }

    /// Set whether the `ask`-mode park notice is printed to stderr (builder style). `true` (the
    /// default) shows it; `false` silences the inline alert — the request still parks, answerable
    /// via `ops net pending`. Inert unless the default action is [`DefaultAction::Ask`].
    pub(crate) fn with_ask_notice(mut self, show: bool) -> Self {
        self.suppress_ask_notice = !show;
        self
    }

    pub(crate) fn default_action(&self) -> DefaultAction {
        self.default_action
    }

    /// Whether the proxy prints the `ask` park notice to stderr — `true` by default. The proxy
    /// reads this only under [`DefaultAction::Ask`].
    pub(crate) fn ask_notice(&self) -> bool {
        !self.suppress_ask_notice
    }

    /// How long a parked `ask` request waits before timing out to a deny — `None` means wait
    /// indefinitely. The proxy reads this only under [`DefaultAction::Ask`].
    pub(crate) fn ask_timeout(&self) -> Option<std::time::Duration> {
        self.ask_timeout
    }

    /// The DNS cache TTL for the proxy's resolver — `None` means "apply the default at build time"
    /// (the resolver treats it as 60s), `Some(0)` disables the cache. Set from `[network]
    /// dns_cache_ttl`.
    pub(crate) fn with_dns_cache_ttl(mut self, ttl: Option<std::time::Duration>) -> Self {
        self.dns_cache_ttl = ttl;
        self
    }

    /// The configured DNS cache TTL (raw `Option` — the resolver applies the 60s default for `None`).
    pub(crate) fn dns_cache_ttl(&self) -> Option<std::time::Duration> {
        self.dns_cache_ttl
    }

    /// Attach the `[network] http2` host set, returning the policy (builder style). Each entry names
    /// a CONNECT target the proxy speaks HTTP/2 to (ALPN `h2`, for gRPC) — never a verdict.
    pub(crate) fn with_http2(mut self, http2: Vec<Http2Host>) -> Self {
        self.http2 = http2;
        self
    }

    /// The configured HTTP/2 hosts (for `ops config show`).
    pub(crate) fn http2_hosts(&self) -> &[Http2Host] {
        &self.http2
    }

    /// Whether the proxy should man-in-the-middle a CONNECT to `host:port` as HTTP/2 (ALPN `h2`)
    /// rather than the default HTTP/1.1. `host` must already be canonicalized (as the proxy's
    /// `connect_host` is). This only selects the transport; the request is still verdict-checked per
    /// stream exactly like the HTTP/1.1 path.
    pub(crate) fn speaks_http2(&self, host: &str, port: u16) -> bool {
        self.http2.iter().any(|h| h.matches(host, port))
    }

    pub(crate) fn allow_rules(&self) -> &[Rule] {
        &self.allow
    }

    pub(crate) fn deny_rules(&self) -> &[Rule] {
        &self.deny
    }

    pub(crate) fn mute_rules(&self) -> &[Rule] {
        &self.mute
    }

    /// Whether a **denied** request to `host:port` for `path`/`method` matches a mute rule — a
    /// LOG-ONLY filter (SELinux `dontaudit`): it never affects the verdict (only [`Self::explain`]
    /// does), only whether the refusal enters the default `ops net log` view. The proxy consults it
    /// at logging time, after the verdict, and still counts a muted refusal in `ops net stats`.
    /// Matching is deliberately **port- and transport-agnostic** ([`Rule::matches_mute`]): a mute
    /// names a *host* to silence, so a bare-host mute suppresses that host's refusals on every port
    /// and scheme — its cleartext `http://…:80` noise (a component updater, an NTP-over-HTTP probe)
    /// as well as its `:443` traffic, and whether the rule was written bare, `https://`, `http://`,
    /// or `tcp://`. Method and path scope are still honored, so a `{POST} host/log` mute stays
    /// precise. A method-less request (an early-CONNECT block) is matched with an empty method, so a
    /// method-scoped mute rule does not match it — failing toward *showing* the log, the safe
    /// direction when the verb is unknown.
    pub(crate) fn muted(
        &self,
        host: &str,
        port: u16,
        path: Option<&str>,
        method: Option<&str>,
    ) -> bool {
        if self.mute.is_empty() {
            return false;
        }
        let req = Request::new(host, port, path.unwrap_or("/"));
        let method = method.unwrap_or("").to_ascii_uppercase();
        self.mute.iter().any(|r| r.matches_mute(&req, &method))
    }

    /// Whether a request to `host`:`port` for `path` is permitted: it must match some
    /// allow rule and no deny rule — **deny always wins**. A thin bool view over
    /// [`Self::explain`], for the verb `GET` (these tests exercise method-agnostic rules).
    /// The filtering proxy and the `ops test net` tester both decide through [`Self::explain`]
    /// (they need the deciding rule and the request's actual method), so this convenience view is
    /// exercised only by tests.
    #[allow(dead_code)]
    pub(crate) fn permits(&self, host: &str, port: u16, path: &str) -> bool {
        matches!(
            self.explain(host, port, path, "GET"),
            Decision::AllowedBy(_) | Decision::AllowedDefault
        )
    }

    /// Explain the verdict for a request to `host`:`port` for `path` with HTTP `method`, naming
    /// the deciding rule. Deny wins: a matching deny rule decides even when an allow rule also
    /// matches; otherwise a matching allow rule; otherwise the policy's default action (deny- or
    /// allow-by-default). A rule matches only when its method set admits `method` (a method-less
    /// rule admits every verb), so a `{GET,HEAD} host` allow does not match a POST. The request is
    /// canonicalized once (host lowercased, path percent-decoded / `.`/`..` resolved / query
    /// dropped) so every rule sees the same evasion-proof view; `method` is uppercased here so the
    /// caller need not. Only [`Layer::L7`] (inspected) rules participate — a `tcp://` (L4) rule
    /// governs the raw-splice decision at CONNECT time ([`Self::l4_decision`]), never the inspected
    /// HTTP verdict, so the two layers stay cleanly partitioned.
    pub(crate) fn explain(&self, host: &str, port: u16, path: &str, method: &str) -> Decision<'_> {
        let req = Request::new(host, port, path);
        let method = method.to_ascii_uppercase();
        if let Some(rule) = self
            .deny
            .iter()
            .find(|r| r.layer == Layer::L7 && r.matches(&req, &method))
        {
            return Decision::DeniedBy(rule);
        }
        if let Some(rule) = self
            .allow
            .iter()
            .find(|r| r.layer == Layer::L7 && r.matches(&req, &method))
        {
            return Decision::AllowedBy(rule);
        }
        match self.default_action {
            DefaultAction::Deny => Decision::DeniedDefault,
            DefaultAction::Allow => Decision::AllowedDefault,
            DefaultAction::Ask => Decision::Ask,
        }
    }

    /// Whether a request is denied *purely* because of its method: an allow rule matches the
    /// host/port/path (its [`RuleKind`]) but its method set excludes `method` — so a different
    /// verb to the same destination would be allowed. Lets the proxy report a `denied-method`
    /// reason distinct from "this host is not allowed at all". Meaningful only on the
    /// deny-by-default path (deny rules are already decided by [`Self::explain`]); reuses the same
    /// kind matcher, so it cannot drift from the verdict. `method` is uppercased here to match
    /// [`Self::explain`], so the caller need not.
    pub(crate) fn method_denied(&self, host: &str, port: u16, path: &str, method: &str) -> bool {
        let req = Request::new(host, port, path);
        let method = method.to_ascii_uppercase();
        self.allow
            .iter()
            .filter(|r| r.layer == Layer::L7)
            .any(|r| r.kind.matches(&req) && !r.methods.admits(&method))
    }

    /// Explain the verdict for a **cleartext** (`http://`) request — the plaintext sibling of
    /// [`Self::explain`], used by the proxy's absolute-form handler and `ops test net http://…`.
    /// Cleartext is **strictly opt-in**, exactly like the [`Self::l4_decision`] splice: only an
    /// explicit `http://` ([`Layer::L7Clear`]) allow rule permits it, and the policy's **default
    /// action is never consulted** — so a `mode = "allow"` denylist does not silently open cleartext,
    /// and under `mode = "ask"` an unmatched cleartext request **denies rather than parks** (an
    /// interactive `ops net pending` prompt cannot convey "this connection is unencrypted"; opening
    /// cleartext is a deliberate config act, not a live one). A regex or a bare/`https://` allow rule
    /// never opens cleartext (they are the inspected-over-TLS layer).
    ///
    /// **Deny wins, layer-agnostically** — mirroring [`Self::l4_decision`]: any deny rule (of any
    /// layer) whose [`RuleKind`] matches the request denies it, so an inspected deny (`deny evil.com`)
    /// and an `http://` deny both suppress cleartext. Its consequence is the same as the splice's: a
    /// deny scoped to a path or a non-matching port does not block the host outright — a bare
    /// `deny evil.com` (port 443) does not stop `http://evil.com` (port 80); use `deny evil.com:*`
    /// (or `deny http://evil.com`). The request is canonicalized once (the same evasion-proof view as
    /// [`Self::explain`]); `method` is uppercased here so the caller need not.
    pub(crate) fn explain_clear(
        &self,
        host: &str,
        port: u16,
        path: &str,
        method: &str,
    ) -> Decision<'_> {
        let req = Request::new(host, port, path);
        let method = method.to_ascii_uppercase();
        // Deny wins, across every layer (matched by kind), like the splice suppression.
        if let Some(rule) = self.deny.iter().find(|r| r.matches(&req, &method)) {
            return Decision::DeniedBy(rule);
        }
        // Allow only via an explicit `http://` rule; the default action is never consulted.
        match self
            .allow
            .iter()
            .find(|r| r.layer == Layer::L7Clear && r.matches(&req, &method))
        {
            Some(rule) => Decision::AllowedBy(rule),
            None => Decision::DeniedDefault,
        }
    }

    /// The cleartext sibling of [`Self::method_denied`]: whether an `http://` request is denied
    /// *purely* by its method (an `http://` allow rule matches host/port/path but not the verb), so
    /// the proxy can report `denied-method` rather than "cleartext is not allowed here". Filters to
    /// [`Layer::L7Clear`] allow rules — the only ones that could open this request — so it cannot
    /// drift from [`Self::explain_clear`]'s allow arm.
    pub(crate) fn method_denied_clear(
        &self,
        host: &str,
        port: u16,
        path: &str,
        method: &str,
    ) -> bool {
        let req = Request::new(host, port, path);
        let method = method.to_ascii_uppercase();
        self.allow
            .iter()
            .filter(|r| r.layer == Layer::L7Clear)
            .any(|r| r.kind.matches(&req) && !r.methods.admits(&method))
    }

    /// Decide, from the CONNECT authority alone (host:port, pre-decrypt), whether a connection is a
    /// raw L4 splice or must take the inspected L7 path. A splice is **strictly opt-in**: it happens
    /// only when an explicit `tcp://` ([`Layer::L4`]) allow rule matches host:port — the default
    /// action is never consulted, so a denylist posture does not silently stop inspecting everything.
    /// A regex can never *open* a splice; only an explicit `tcp://` allow does.
    ///
    /// **Deny wins**, even over a `tcp://` allow: any deny rule matching the connection suppresses the
    /// splice and sends it to the inspected L7 path instead (where [`Self::explain`] denies it, or — if
    /// an L7 rule also allows it — inspects it; or, if the stream is not TLS, the MITM handshake fails
    /// closed). Each deny is tested against a **path-less** request (`https://host[:port]/`) built from
    /// the CONNECT authority — all that is known pre-decrypt — so a `Url`/`Regex` deny participates
    /// through its own [`RuleKind::matches`]. Two consequences follow:
    /// - A host-level deny suppresses on its **port set only**: `deny evil.com` (the bare default
    ///   port) does not block a `tcp://evil.com:22` splice; `deny evil.com:*` — or a port-agnostic
    ///   `re:^https://evil\.com`, which matches every port via the synthetic URL — does.
    /// - A deny **specific to a path** (`re:…/secret`, `evil.com/secret`) does not match the path-less
    ///   request, so it does not suppress the splice: a raw splice has no HTTP path to enforce a path
    ///   rule against. To block a host outright, use a host-level deny, not a path deny.
    ///
    /// L4 allow rules carry no path or method, so only host:port is matched. The filtering proxy and
    /// `ops test net tcp://…` both decide through this one function, so enforcement cannot drift from
    /// the tester.
    pub(crate) fn l4_decision(&self, host: &str, port: u16) -> L4Decision<'_> {
        let req = Request::new(host, port, "/");
        let Some(allow) = self
            .allow
            .iter()
            .find(|r| r.layer == Layer::L4 && r.kind.matches(&req))
        else {
            return L4Decision::NoMatch;
        };
        match self.deny.iter().find(|r| r.kind.matches(&req)) {
            Some(deny) => L4Decision::Suppressed(deny),
            None => L4Decision::Splice(allow),
        }
    }

    /// Apply an app's read-by-default posture: rewrite every **allow** rule whose methods are
    /// [`Methods::Unspecified`] (no explicit prefix) to `default`. Only a concrete [`Methods::Only`]
    /// set narrows — an app whose default is [`Methods::Any`] (declared `default_methods = ["*"]`) or
    /// an empty set leaves its unscoped rules all-verbs (a no-op). Explicit `{*}` ([`Methods::Any`])
    /// and `{VERB}` rules keep their verbs (so `{*}` re-opens a host), **deny rules are untouched** (a
    /// deny stays broad — narrowing it would weaken it), and a raw `tcp://` (L4) rule keeps no methods
    /// (a prefix on it is rejected at classify). Both **inspected** layers are rewritten — an
    /// `http://` (L7Clear) allow rule is HTTP-inspected too, so it must inherit the app's read-by-
    /// default posture; leaving it all-verbs would let a cleartext rule silently escape the
    /// `{GET,HEAD}` default a `default_methods` sets. Applied once, at app-policy resolution, so the
    /// proxy, `ops test net`, and `ops net rules` all consume the same resolved policy and cannot
    /// diverge.
    pub(crate) fn apply_default_methods(&mut self, default: &Methods) {
        let Methods::Only(set) = default else { return };
        if set.is_empty() {
            return;
        }
        for rule in &mut self.allow {
            if rule.layer.inspected() && rule.methods == Methods::Unspecified {
                rule.methods = default.clone();
            }
        }
    }

    /// The exact hosts that carry **both** a raw `tcp://` (L4) allow rule and an inspected rule
    /// (allow or deny, over TLS or cleartext) on an **overlapping** port — so the inspected rule is
    /// silently ineffective on that host's spliced traffic (a splice is uninspected). For surfacing a
    /// config warning, never for enforcement (the layer partition is the control). Conservative by
    /// construction: it flags only an **exact-host** overlap (`Ip`/`Host`/`Url` kinds, whose host is
    /// one concrete name) with intersecting port sets; a `*.domain` or `re:` host — whose overlap is
    /// not decidable here — is not flagged, so the check yields a missed warning rather than a false
    /// one. Each host is reported once.
    pub(crate) fn l4_l7_conflicts(&self) -> Vec<String> {
        let l7: Vec<(String, &Ports)> = self
            .allow
            .iter()
            .chain(self.deny.iter())
            .filter(|r| r.layer.inspected())
            .filter_map(|r| exact_host_ports(&r.kind))
            .collect();
        let mut hosts: Vec<String> = Vec::new();
        for l4 in self.allow.iter().filter(|r| r.layer == Layer::L4) {
            let Some((h4, p4)) = exact_host_ports(&l4.kind) else {
                continue;
            };
            if !hosts.contains(&h4) && l7.iter().any(|(h7, p7)| *h7 == h4 && p4.intersects(p7)) {
                hosts.push(h4);
            }
        }
        hosts
    }
}

/// The exact host name and port set of a host-level rule kind, for the L4/L7 overlap check — `None`
/// for a `*.domain` (its host is not one concrete name) or a `re:` regex (no structured host), which
/// the conservative check skips rather than guess an overlap.
fn exact_host_ports(kind: &RuleKind) -> Option<(String, &Ports)> {
    match kind {
        RuleKind::Ip(ip, ports) => Some((ip.to_string(), ports)),
        RuleKind::Host(h, ports) => Some((h.clone(), ports)),
        RuleKind::Url { host, ports, .. } => Some((host.clone(), ports)),
        RuleKind::Subdomain(..) | RuleKind::Regex { .. } => None,
    }
}

/// The CONNECT-time verdict for a connection's enforcement layer, from [`EgressPolicy::l4_decision`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum L4Decision<'a> {
    /// A `tcp://` allow rule opts this host:port into a raw splice and no host-level deny suppresses
    /// it: the proxy splices the TCP stream uninspected. Carries the deciding allow rule, so the
    /// SSRF guard can apply its exact-host exception (a deliberate internal target).
    Splice(&'a Rule),
    /// A `tcp://` allow matched, but a deny rule suppressed the splice (**deny wins**): the
    /// connection takes the inspected L7 path (the MITM) instead, where the HTTP verdict — or, for a
    /// non-TLS stream, a failed handshake — decides it. Carries the deciding deny rule. The proxy
    /// treats this exactly like [`Self::NoMatch`] (it splices only on [`Self::Splice`]); the
    /// distinction exists so `ops test net` can explain *why* a covered host did not splice.
    Suppressed(&'a Rule),
    /// No `tcp://` allow opts this host:port into a splice: the connection takes the inspected L7
    /// path (the MITM), where the HTTP verdict decides it.
    NoMatch,
}

/// The verdict [`EgressPolicy::explain`] reaches for one request, with the rule that
/// decided it — for the `ops test net` URL tester. Deny wins, so `DeniedBy` can name a deny
/// rule even when an allow rule also matched.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Decision<'a> {
    /// A deny rule matched (it wins, even over a matching allow rule).
    DeniedBy(&'a Rule),
    /// An allow rule matched and no deny rule did.
    AllowedBy(&'a Rule),
    /// No rule matched, and the policy denies by default (the classic allowlist).
    DeniedDefault,
    /// No rule matched, and the policy allows by default (a denylist). There is no deciding
    /// rule, so the SSRF guard treats this like an unnamed host (private addresses refused).
    AllowedDefault,
    /// No rule matched, and the policy asks by default: the request parks for a live decision.
    /// The proxy blocks until answered or the ask timeout elapses; the `ops test net` tester
    /// reports it as "would ask" since there is no static verdict.
    Ask,
}

/// Whether `rule`'s host/port/path matches a request to `host`:`port` for `target`, canonicalized
/// exactly the way [`EgressPolicy::explain`] canonicalizes it (host lowercased, path
/// percent-decoded / `.`/`..`-resolved / query dropped). **Method-agnostic by design** — it tests
/// the [`RuleKind`] only, never the method set. The filtering proxy uses it to decide whether a
/// per-host credential injection applies to a request it has already allowed, and the live `ask`
/// overlay to match a remembered host rule; both deal in host-scoped, method-less rules, and a
/// credential is injected for the destination regardless of verb. So the injection sees the
/// identical normalized view as the verdict, and a host or path dodge cannot separate the two.
pub(crate) fn rule_matches(rule: &Rule, host: &str, port: u16, target: &str) -> bool {
    rule.kind.matches(&Request::new(host, port, target))
}

/// An exact-host rule scoped to a single port — what a live `ask` decision remembers: exactly the
/// `host:port` the answered request named, so re-running *that* request is decided without re-asking
/// and nothing wider is opened. The host is canonicalized the same way the matcher canonicalizes a
/// request host, so the remembered rule and a later request compare equal. (Deliberately *not*
/// `classify(host)`, which defaults to the https port {443} and would fail to match a request that
/// asked on a non-standard port — the very reason it reached `ask`.)
pub(crate) fn host_port_rule(host: &str, port: u16) -> Rule {
    // Method-agnostic by design ([`Methods::Unspecified`]): a live `ask` answer approves the *host*,
    // not a particular verb, so re-running any method to it is not re-asked. `Unspecified` (rather
    // than `Any`) keeps the remembered rule rendering bare — the user never typed a `{*}` — and is
    // safe because a live `ask` overlay is never run through `apply_default_methods` (that rewrites
    // a config-resolved *app* policy, not the runtime ask rules). Inspected ([`Layer::L7`]): an `ask`
    // park only ever happens on the MITM path, so the remembered rule is an L7 host rule.
    Rule {
        kind: RuleKind::Host(canonical_host(host), Ports::Ranges(vec![(port, port)])),
        methods: Methods::Unspecified,
        layer: Layer::L7,
        group: None,
    }
}

/// Classify one declared entry (allow or deny) by its syntax, or report why it is malformed. The
/// optional pieces are peeled in order: a leading `{VERB,...}` method prefix, then — for a non-`re:`
/// entry — a `tcp://`/`http://`/`https://` scheme that selects the enforcement [`Layer`]. A `re:`
/// regex is never scheme-split (its pattern may itself contain `://`) and is always inspected over
/// TLS. A `tcp://` (raw L4) rule is constrained: it carries no method prefix and no `/path` (a raw
/// stream has no HTTP), so either is rejected. An `http://` (cleartext L7) rule carries the full HTTP
/// vocabulary (method, path) like the default inspected layer, only on a plaintext transport. A value
/// that fits no kind is rejected so it can never be read as an unintended kind.
pub(crate) fn classify(entry: &str) -> Result<Rule, String> {
    let (methods, rest) = split_method_prefix(entry.trim())?;
    let rest = rest.trim();
    // `re:` patterns may contain `://`, so they are never scheme-split — always inspected over TLS.
    if let Some(pattern) = rest.strip_prefix("re:") {
        let re = Regex::new(pattern).map_err(|e| format!("invalid regex `{pattern}`: {e}"))?;
        return Ok(Rule {
            kind: RuleKind::Regex {
                pattern: pattern.to_string(),
                re,
            },
            methods,
            layer: Layer::L7,
            group: None,
        });
    }
    let (layer, body) = split_scheme(rest)?;
    // The scheme carries the default port (443 for `https`/bare, 80 for `http`); a `:port` in the
    // body overrides it. L4 requires an explicit port, so its default is inert.
    let kind = classify_kind(body.trim(), layer.default_port())?;
    if layer == Layer::L4 {
        if methods != Methods::Unspecified {
            return Err(format!(
                "a `tcp://` (raw L4) rule carries no `{{...}}` method prefix (not even `{{*}}`) — \
                 remove it from `{entry}` (a raw stream is spliced byte-for-byte; it has no HTTP \
                 method to filter)"
            ));
        }
        if let RuleKind::Url { .. } = kind {
            return Err(format!(
                "a `tcp://` (raw L4) rule is host:port only — remove the `/path` from `{entry}` \
                 (a raw TCP stream has no HTTP path); use `tcp://host:port`"
            ));
        }
        if !has_explicit_port(body.trim()) {
            return Err(format!(
                "a `tcp://` (raw L4) rule needs an explicit `:port` — `{entry}` names none (a raw \
                 splice must name the port it opens); use e.g. `tcp://host:22`, or `tcp://host:*` \
                 for every port"
            ));
        }
    }
    Ok(Rule {
        kind,
        methods,
        layer,
        group: None,
    })
}

/// Split an optional scheme prefix off a rule body (the method prefix and any `re:` already handled),
/// returning the enforcement [`Layer`] it selects and the rest. `tcp://` selects raw L4 (the proxy
/// splices the stream uninspected, so the rule must name an explicit `:port`); `http://` selects
/// inspected cleartext L7 (plaintext, default port 80); `https://` selects inspected-over-TLS L7 (the
/// MITM path, default port 443). The scheme selects the **layer and the default port**: `https://h`
/// and bare `h` are the same rule (both L7, 443); a `:port` overrides the default. A recognizable but
/// unsupported scheme (`udp://`, `ssh://`, …) is rejected with a pointer rather than mis-read as a
/// host. No scheme means inspected-over-TLS L7 (the default).
fn split_scheme(s: &str) -> Result<(Layer, &str), String> {
    if let Some(rest) = s.strip_prefix("tcp://") {
        return Ok((Layer::L4, rest));
    }
    if let Some(rest) = s.strip_prefix("http://") {
        return Ok((Layer::L7Clear, rest));
    }
    if let Some(rest) = s.strip_prefix("https://") {
        return Ok((Layer::L7, rest));
    }
    if let Some((scheme, _)) = s.split_once("://") {
        return Err(format!(
            "scheme `{scheme}://` is not supported in a rule — use `tcp://host:port` for a raw \
             (uninspected) L4 tunnel, `http://host` for an inspected cleartext rule, or `https://` \
             (or a bare host) for an inspected-over-TLS rule; the scheme selects the layer and the \
             default port (override the port with `:port`). `udp://` is not yet supported"
        ));
    }
    Ok((Layer::L7, s))
}

/// Split an optional leading `{VERB,VERB,...}` method prefix off an entry, returning the method
/// set and the rest (the rule body, still to be trimmed). A leading `{` is an unambiguous sentinel
/// that a method spec is present — no rule kind (`re:`, a host, a path, an IP) ever starts with one
/// — so it never collides with the `{n,m}` quantifiers a `re:` body may contain (those sit after
/// `re:`, never at the very start). No `{` means [`Methods::Any`] and the whole entry as the body.
fn split_method_prefix(s: &str) -> Result<(Methods, &str), String> {
    let Some(after) = s.strip_prefix('{') else {
        // No prefix: all verbs now, but a per-app `default_methods` may narrow it at resolution.
        return Ok((Methods::Unspecified, s));
    };
    let Some(close) = after.find('}') else {
        return Err(
            "unterminated `{` in the method prefix (expected `{GET,POST} <rule>`)".to_string(),
        );
    };
    let spec = after[..close].trim();
    // `{*}` is the explicit all-verbs escape — distinct from no prefix, it is never rewritten by
    // `default_methods`, so it re-opens a host to every verb under a read-by-default app.
    let methods = if spec == "*" {
        Methods::Any
    } else {
        parse_methods(spec)?
    };
    Ok((methods, &after[close + 1..]))
}

/// Parse the inside of a `{...}` method prefix into a [`Methods::Only`] set: a non-empty,
/// comma-separated list of verbs, each non-empty uppercase ASCII letters (`GET`, `POST`,
/// `PROPFIND`, …), or the wildcard `*` meaning "every HTTP verb" (so `{*,WS}` reads as "all HTTP
/// methods and WebSocket"). Sorted and de-duplicated so equal specs compare and display
/// identically. An empty set (`{}`), an empty item (`{GET,}`), or a non-uppercase/non-`*` verb is
/// rejected — fail-closed, never a rule that can match nothing or a typo that silently never fires.
/// (A lone `{*}` never reaches here — it is the [`Methods::Any`] escape, handled by the caller.)
fn parse_methods(spec: &str) -> Result<Methods, String> {
    let mut verbs: Vec<String> = Vec::new();
    for part in spec.split(',') {
        let v = part.trim();
        if v.is_empty() {
            return Err(
                "empty method in the `{...}` prefix (expected e.g. `{GET,POST}`)".to_string(),
            );
        }
        if v != "*" && !v.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(format!(
                "method `{v}` must be uppercase ASCII letters (e.g. GET, POST, DELETE) or `*`"
            ));
        }
        verbs.push(v.to_string());
    }
    verbs.sort();
    verbs.dedup();
    Ok(Methods::Only(verbs))
}

/// Parse a config `default_methods` list into the app default it expresses: `["*"]` →
/// [`Methods::Any`] (all verbs — the unscoped rules are not narrowed), else a non-empty list of
/// uppercase verbs → [`Methods::Only`] (sorted, de-duplicated, the same per-verb validation as a
/// `{...}` prefix). An empty list, a `*` mixed with other verbs, or a non-uppercase verb is rejected
/// (fail-closed) so a malformed override falls back to the built-in app default rather than silently
/// narrowing to nothing or widening everything.
pub(crate) fn parse_default_methods(verbs: &[String]) -> Result<Methods, String> {
    if verbs.iter().any(|v| v.trim() == "*") {
        return if verbs.len() == 1 {
            Ok(Methods::Any)
        } else {
            Err(
                "`*` (all verbs) cannot be combined with other verbs in `default_methods`"
                    .to_string(),
            )
        };
    }
    if verbs.is_empty() {
        return Err(
            "`default_methods` is empty (use e.g. [\"GET\", \"HEAD\"], or [\"*\"] for all verbs)"
                .to_string(),
        );
    }
    parse_methods(&verbs.join(","))
}

/// Classify the syntactic [`RuleKind`] of an entry (already trimmed, with any method prefix and
/// scheme already stripped by [`classify`], and `re:` already handled there). `default_port` is the
/// scheme's default (443 for `https`/bare, 80 for `http`), used for a host that names no explicit
/// `:port`. Order matters: a `/`-bearing `host[:ports]/path` URL rule, then the `*.` wildcard, then
/// an IP literal, then a bare hostname.
fn classify_kind(s: &str, default_port: u16) -> Result<RuleKind, String> {
    if s.is_empty() {
        return Err("empty entry".to_string());
    }
    // A `/` marks a `host[:ports]/path` URL rule; without one the entry is host-level.
    if let Some(i) = s.find('/') {
        return parse_path_rule(s, i, default_port);
    }
    let (host, ports) = split_host_ports(s, default_port)?;
    reject_catch_all(host)?;
    if let Some(domain) = host.strip_prefix("*.") {
        if is_valid_hostname(domain) {
            return Ok(RuleKind::Subdomain(domain.to_ascii_lowercase(), ports));
        }
        return Err(format!("invalid subdomain wildcard `{s}`"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(RuleKind::Ip(ip, ports));
    }
    if is_valid_hostname(host) {
        return Ok(RuleKind::Host(host.to_ascii_lowercase(), ports));
    }
    Err(format!(
        "unrecognized entry `{s}` (expected an IP, a domain, `*.domain`, a `host[:port]/path` URL, or `re:<regex>`, each host optionally `:port`-qualified)"
    ))
}

/// `*` as a host is a request to allow *every* host, which an allowlist entry deliberately
/// cannot express — the point of `mode = "deny"` is deny-by-construction. Catch the bare
/// wildcard in any port form (`*`, `*:*`, `*:80`, and the `https://`/`tcp://` equivalents after the
/// scheme is stripped) and point the author at the posture switch instead of the generic
/// "unrecognized entry"/"invalid port" message. `*.domain` is a *bounded* subdomain wildcard and is
/// unaffected (its host is `*.domain`, not `*`).
fn reject_catch_all(host: &str) -> Result<(), String> {
    if host == "*" {
        return Err(
            "`*` matches every host, which an allowlist cannot express; to open the \
                    network fully set `[network] mode = \"shared\"`"
                .to_string(),
        );
    }
    Ok(())
}

/// The scheme prefix length and default port for a URL entry, or `None` if it is not a
/// URL. Only `https`/`http` are recognised — egress is HTTPS, `http` is for completeness.
fn scheme_of(s: &str) -> Option<(usize, u16)> {
    if s.starts_with("https://") {
        Some(("https://".len(), 443))
    } else if s.starts_with("http://") {
        Some(("http://".len(), 80))
    } else {
        None
    }
}

/// Split an optional `:port-spec` suffix off a host-level entry, returning the host and its
/// port set. A bare entry (`github.com`) gets the default HTTPS port {443}; `:*` admits
/// any port; a comma list of single ports and/or `lo-hi` ranges (`:80,443,8000-8100`) pins
/// exactly those. An IPv6 literal carrying a port is **bracketed** (`[::1]:443`,
/// `[2001:db8::1]:*`) so its own colons do not confuse the split; bare, it needs no brackets
/// (`::1`), taken whole at the default ports.
/// Whether a host-level rule body (no scheme, no `/path`) carries an explicit `:port` spec, as
/// opposed to taking the default. Mirrors [`split_host_ports`]'s split exactly: a bracketed IPv6
/// has a port iff something follows the `]`; a bare IP literal (incl. `::1`, whose colons are the
/// address) never does; a hostname has one iff it contains a `:`. Used to require a port on a
/// `tcp://` rule — a raw splice must name the port it opens.
fn has_explicit_port(body: &str) -> bool {
    if let Some(rest) = body.strip_prefix('[') {
        return rest
            .split_once(']')
            .is_some_and(|(_, after)| !after.is_empty());
    }
    if body.parse::<IpAddr>().is_ok() {
        return false;
    }
    body.contains(':')
}

fn split_host_ports(s: &str, default_port: u16) -> Result<(&str, Ports), String> {
    // a bracketed IPv6 literal, optionally `:port-spec` after the `]`
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated `[` in `{s}`"))?;
        if addr.parse::<IpAddr>().is_err() {
            return Err(format!("invalid IP literal `[{addr}]`"));
        }
        let ports = match after {
            "" => Ports::single(default_port),
            a => match a.strip_prefix(':') {
                Some(spec) => parse_ports(spec)?,
                None => return Err(format!("expected `:port` after `]` in `{s}`")),
            },
        };
        return Ok((addr, ports));
    }
    // a bare IP literal (including an unbracketed IPv6 like `::1`, whose own colons would
    // confuse the port split) is the whole string, at the scheme's default port
    if s.parse::<IpAddr>().is_ok() {
        return Ok((s, Ports::single(default_port)));
    }
    match s.rsplit_once(':') {
        Some((host, spec)) => Ok((host, parse_ports(spec)?)),
        None => Ok((s, Ports::single(default_port))),
    }
}

/// Parse a port spec into a [`Ports`]: `*` for any; otherwise a non-empty comma list whose
/// items are a single port or an inclusive `lo-hi` range. Ports are `1..=65535` (0 rejected),
/// a range needs `lo <= hi`, and the result is sorted and de-duplicated so equal specs
/// compare and display identically. Anything malformed is an error — fail-closed, never a
/// silent widening.
fn parse_ports(spec: &str) -> Result<Ports, String> {
    let spec = spec.trim();
    if spec == "*" {
        return Ok(Ports::Any);
    }
    if spec.is_empty() {
        return Err("empty port spec (expected `*`, a port, or a `lo-hi` range)".to_string());
    }
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        let range = match part.split_once('-') {
            Some((lo, hi)) => {
                let lo = parse_port(lo)?;
                let hi = parse_port(hi)?;
                if lo > hi {
                    return Err(format!("invalid port range `{part}` (lo > hi)"));
                }
                (lo, hi)
            }
            None => {
                let p = parse_port(part)?;
                (p, p)
            }
        };
        ranges.push(range);
    }
    ranges.sort_unstable();
    ranges.dedup();
    Ok(Ports::Ranges(ranges))
}

/// Parse one port (`1..=65535`); reject 0 and non-numeric.
fn parse_port(s: &str) -> Result<u16, String> {
    let port: u16 = s
        .trim()
        .parse()
        .map_err(|_| format!("invalid port `{s}`"))?;
    if port == 0 {
        return Err("port 0 is not a valid port".to_string());
    }
    Ok(port)
}

/// Split an http(s) URL naming one **request** into the `(host, port, path)` the matcher
/// tests: `host` lowercased (an IPv6 host bracketed in the URL, returned bare), `port` from an
/// explicit `:port` or the scheme default, `path` everything after the authority (the root `/`
/// if none) **including any query string**. The host must be a hostname, an IPv4 literal, or a
/// bracketed IPv6 literal (`https://[::1]:8080/x`). This is the *request* parser — a request is
/// a concrete connection, so it keeps the scheme (which sets the port); the `ops test net`
/// tester is its only caller. Allow/deny *rules* are scheme-free and parsed by [`classify`].
pub(crate) fn parse_url_target(url: &str) -> Result<(String, u16, String), String> {
    let Some((scheme_len, default_port)) = scheme_of(url) else {
        return Err(format!("`{url}` is not an http(s) URL"));
    };
    let after = &url[scheme_len..];
    let (authority, path) = match after.find('/') {
        Some(i) => (&after[..i], after[i..].to_string()),
        None => (after, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(format!("URL `{url}` has no host"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // a bracketed IPv6 host, optionally `:port` after the `]`
        let (addr, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("URL `{url}` has an unterminated `[`"))?;
        if addr.parse::<IpAddr>().is_err() {
            return Err(format!("URL `{url}` has an invalid IP literal `[{addr}]`"));
        }
        let port = match tail {
            "" => default_port,
            t => {
                let p = t
                    .strip_prefix(':')
                    .ok_or_else(|| format!("URL `{url}` has unexpected text after `]`"))?;
                p.parse::<u16>()
                    .map_err(|_| format!("URL `{url}` has an invalid port `{p}`"))?
            }
        };
        (addr, port)
    } else {
        let (h, port_spec) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        reject_catch_all(h)?;
        let port = match port_spec {
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| format!("URL `{url}` has an invalid port `{p}`"))?,
            None => default_port,
        };
        (h, port)
    };
    if !(is_valid_hostname(host) || host.parse::<IpAddr>().is_ok()) {
        return Err(format!("URL `{url}` has an invalid host `{host}`"));
    }
    Ok((canonical_host(host), port, path))
}

/// Parse a `tcp://host:port` target naming one **L4 request** (for `ops test net tcp://…`) into
/// `(host, port)`. The port is **required** — an L4 test names one concrete port (there is no scheme
/// default to fall back on, and a raw splice has no notion of the web ports). The host is a hostname,
/// an IPv4 literal, or a bracketed IPv6 literal (`tcp://[::1]:22`); a raw stream carries no path, so
/// any trailing `/…` is rejected. Like [`parse_url_target`], this is the *request* parser; allow/deny
/// rules are parsed by [`classify`].
pub(crate) fn parse_tcp_target(target: &str) -> Result<(String, u16), String> {
    let authority = target
        .strip_prefix("tcp://")
        .ok_or_else(|| format!("`{target}` is not a tcp:// target"))?;
    if authority.contains('/') {
        return Err(format!(
            "a tcp:// target is host:port only — `{target}` carries a path (a raw TCP stream has no HTTP path)"
        ));
    }
    if authority.is_empty() {
        return Err(format!("tcp:// target `{target}` has no host"));
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // a bracketed IPv6 host, `:port` required after the `]`
        let (addr, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("tcp:// target `{target}` has an unterminated `[`"))?;
        if addr.parse::<IpAddr>().is_err() {
            return Err(format!(
                "tcp:// target `{target}` has an invalid IP literal `[{addr}]`"
            ));
        }
        let p = tail.strip_prefix(':').ok_or_else(|| {
            format!("tcp:// target `{target}` needs an explicit `:port` (e.g. `tcp://[::1]:22`)")
        })?;
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("tcp:// target `{target}` has an invalid port `{p}`"))?;
        (addr, port)
    } else {
        let (h, p) = authority.rsplit_once(':').ok_or_else(|| {
            format!("tcp:// target `{target}` needs an explicit `:port` (e.g. `tcp://host:22`)")
        })?;
        reject_catch_all(h)?;
        let port = p
            .parse::<u16>()
            .map_err(|_| format!("tcp:// target `{target}` has an invalid port `{p}`"))?;
        (h, port)
    };
    if port == 0 {
        return Err(format!(
            "tcp:// target `{target}` has port 0, which is not valid"
        ));
    }
    if !(is_valid_hostname(host) || host.parse::<IpAddr>().is_ok()) {
        return Err(format!(
            "tcp:// target `{target}` has an invalid host `{host}`"
        ));
    }
    Ok((canonical_host(host), port))
}

/// Parse a `host[:ports]/path` entry into a `Url` rule. The part before the first `/` is the
/// authority, parsed for its host and port set exactly like a host-level entry — so a path rule
/// supports the same `:port`, comma-list, `lo-hi` range, and `:*` qualifiers (a bare host defaulting
/// to `default_port`, the scheme's default: 443 for `https`/bare, 80 for `http`). The rest, including
/// the leading `/`, is the path. The host must be concrete — an exact hostname or IP literal
/// (bracketed for IPv6); a `*.domain` wildcard with a path is rejected (use `re:`). A trailing `/*`
/// marks a subtree rule (the path and everything under it); without it the path matches exactly.
fn parse_path_rule(s: &str, slash: usize, default_port: u16) -> Result<RuleKind, String> {
    let (authority, path) = (&s[..slash], &s[slash..]);
    if authority.is_empty() {
        return Err(format!("entry `{s}` has no host before the path"));
    }
    let (host, ports) = split_host_ports(authority, default_port)?;
    reject_catch_all(host)?;
    if !(is_valid_hostname(host) || host.parse::<IpAddr>().is_ok()) {
        return Err(format!(
            "entry `{s}` has an invalid host `{host}` before the path (a path rule needs a \
             concrete host or IP; use `re:` for a wildcard host)"
        ));
    }
    let subtree = path.ends_with("/*");
    Ok(RuleKind::Url {
        host: canonical_host(host),
        ports,
        path: path.to_string(),
        subtree,
    })
}

/// A syntactically valid hostname: dot-separated labels of letters, digits, and hyphens
/// (no leading/trailing hyphen per label), non-empty, no leading/trailing/double dot,
/// within length limits. Strict enough that a hostname rule can never carry a path
/// separator, port, scheme, or shell-significant character.
fn is_valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with('.')
        && !h.ends_with('.')
        && !h.contains("..")
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> Rule {
        classify(s).unwrap_or_else(|e| panic!("classify({s:?}) failed: {e}"))
    }

    /// An allow-only policy (no deny rules), for the single-list matching tests.
    fn allow(entries: &[&str]) -> EgressPolicy {
        EgressPolicy::new(entries.iter().map(|s| rule(s)).collect(), vec![])
    }

    #[test]
    fn rule_equality_ignores_group_provenance() {
        // A rule's identity is its match (kind/methods/layer), not which `[net.groups]` group it was
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
        // all-verbs. The advisor-flagged bug: this must include L7Clear.
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

    #[test]
    fn rejects_the_catch_all_wildcard_with_a_pointer_to_shared() {
        // every scheme-free spelling of the bare `*` host — plain, with a port spec, and as a
        // path rule — is rejected, and the message points at the posture switch `mode = "shared"`
        // rather than the generic error. (A *scheme*-prefixed `*` is rejected one step earlier by
        // the scheme guard — see `rejects_a_scheme_in_an_entry`.)
        for bad in ["*", "*:*", "*:80", "*/path", "*:*/admin"] {
            let err = classify(bad).unwrap_err();
            assert!(
                err.contains("mode = \"shared\""),
                "{bad:?} should be rejected with a pointer to `mode = \"shared\"`, got: {err}"
            );
        }
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
        assert!(EgressPolicy::default()
            .with_ask_notice(false)
            .with_ask_notice(true)
            .ask_notice());
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
        // The mute set is surfaced for `ops net rules` / `ops config show`.
        assert_eq!(policy.mute_rules().len(), 1);
    }

    #[test]
    fn mute_honors_method_and_path_scope_like_a_verdict_rule() {
        // A method- and path-scoped mute entry: only a matching verb+path is muted, so a mute reads
        // identically to an allow/deny rule and never over-suppresses.
        let policy = EgressPolicy::new(vec![], vec![])
            .with_mute(vec![rule("{POST} play.googleapis.com/log")]);
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
        let policy =
            EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("update.googleapis.com")]);
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
        let scoped =
            EgressPolicy::new(vec![], vec![]).with_mute(vec![rule("{POST} host.example/log")]);
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
        let p =
            EgressPolicy::new(vec![], vec![rule("evil.com")]).with_default(DefaultAction::Allow);
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
        let q =
            EgressPolicy::new(vec![rule("10.0.0.1")], vec![]).with_default(DefaultAction::Allow);
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
        let p =
            EgressPolicy::new(vec![], vec![rule("evil.com")]).with_default(DefaultAction::Allow);
        // one trailing dot, and a doubled dot (which DNS resolves to the same host) — both denied
        for host in ["evil.com.", "evil.com..", "evil.com..."] {
            assert!(!p.permits(host, 443, "/"), "{host} must be denied");
            assert!(matches!(
                p.explain(host, 443, "/", "GET"),
                Decision::DeniedBy(_)
            ));
        }
        // a subdomain deny is likewise not dodged by trailing dots
        let q =
            EgressPolicy::new(vec![], vec![rule("*.evil.com")]).with_default(DefaultAction::Allow);
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
        // the decision names the deciding deny (so `ops test net` can explain why it did not splice).
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
        // Malformed → None (dropped with a warning by the config layer, fail-closed): an empty
        // entry, or a port that is not a valid u16.
        assert!(Http2Host::parse("").is_none());
        assert!(Http2Host::parse("   ").is_none());
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
}
