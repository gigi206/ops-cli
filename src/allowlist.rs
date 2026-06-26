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
//! defaulting to {80, 443}) — a `host[:port]/path` URL (exact, or a `/*`-suffixed subtree),
//! or a `re:<pattern>` regex. A rule carries **no scheme**: `http`/`https` would only pick a
//! default port, which the `:port` qualifier already expresses, so a scheme in an entry is
//! rejected (it stays meaningful only on a *request*, e.g. `ops test net https://…`).
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
//! the web ports {80, 443}; a `:`-suffixed comma list of ports and/or `lo-hi` ranges pins
//! exactly those (`github.com:8443`, `internal:8000-8100`, `1.2.3.4:80,443,8443`); and
//! `:*` (`github.com:*`) matches any port. An IPv6 literal is bracketed when it carries a
//! port (`[::1]:443`, `[2001:db8::1]:*`) and bare otherwise (`::1`). A `host[:port]/path` URL
//! kind (`github.com/secret`, `github.com:443/secret`, `[::1]:8080/admin`) carries the same
//! port set as the host kinds (a bare host defaulting to {80, 443}) and matches the path
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

/// One classified match rule, used in either the allow or the deny list. The kind is
/// inferred from the entry's syntax at config resolution; an entry that matches none is a
/// hard error, never a silent drop.
#[derive(Debug, Clone)]
pub(crate) enum Rule {
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

/// The set of ports a host-level rule (`Ip`/`Host`/`Subdomain`) admits. A bare entry
/// defaults to the web ports {80, 443}; a `:`-suffixed spec pins an explicit set — a comma
/// list of single ports and/or inclusive `lo-hi` ranges; `:*` admits any port. The least
/// privilege of the bare default keeps `allow github.com` from being CONNECT-tunnelled to
/// an arbitrary port like 22.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ports {
    /// `:*` — any port.
    Any,
    /// A set of inclusive `(lo, hi)` ranges (a single port is `(p, p)`), sorted and
    /// de-duplicated so equal specs compare and display identically. The default is
    /// `[(80, 80), (443, 443)]`.
    Ranges(Vec<(u16, u16)>),
}

impl Default for Ports {
    fn default() -> Self {
        Ports::Ranges(vec![(80, 80), (443, 443)])
    }
}

impl Ports {
    /// Whether `port` falls in the set.
    fn admits(&self, port: u16) -> bool {
        match self {
            Ports::Any => true,
            Ports::Ranges(rs) => rs.iter().any(|(lo, hi)| port >= *lo && port <= *hi),
        }
    }

    /// The display suffix: empty for the default {80, 443} (rendered as a bare host), `:*`
    /// for any, else `:` plus a comma list where each item is `p` or `lo-hi`.
    fn suffix(&self) -> String {
        match self {
            Ports::Any => ":*".to_string(),
            Ports::Ranges(rs)
                if rs.len() == 2 && rs.contains(&(80, 80)) && rs.contains(&(443, 443)) =>
            {
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
    /// Whether this rule matches the (already-canonicalized) request. A `Url` rule needs the
    /// host and port to be equal and the path to satisfy [`path_matches`] — exact by default,
    /// or the path and its subtree when the rule was declared with a trailing `/*`. The
    /// canonicalization means `/secret?x`, `/secret/`, `%2f`, and `/foo/../secret` all reduce
    /// to the same path, so a deny cannot be dodged. A `Regex` rule matches the canonical URL.
    fn matches(&self, req: &Request) -> bool {
        match self {
            Rule::Ip(ip, ports) => {
                ports.admits(req.port)
                    && req
                        .host
                        .parse::<IpAddr>()
                        .map(|h| &h == ip)
                        .unwrap_or(false)
            }
            Rule::Host(h, ports) => ports.admits(req.port) && &req.host == h,
            Rule::Subdomain(d, ports) => {
                ports.admits(req.port) && (&req.host == d || req.host.ends_with(&format!(".{d}")))
            }
            Rule::Url {
                host: h,
                ports,
                path: pa,
                subtree,
            } => &req.host == h && ports.admits(req.port) && path_matches(&req.segs, pa, *subtree),
            Rule::Regex { re, .. } => re.is_match(&req.url),
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
fn canonical_segments(target: &str) -> Vec<String> {
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

/// Canonicalize a host for matching: lowercase it, and if it is an IP literal, normalize it
/// to its canonical textual form so every spelling of one address compares equal (`::1` and
/// `0:0:0:0:0:0:0:1` both become `::1`). A hostname passes through lowercased. Applied on both
/// sides — the rule (`parse_url_target`) and the request (`Request::new`) — so a `Url` host,
/// which is matched as a plain string, cannot be dodged by an alternate IPv6 spelling. The
/// filtering proxy reuses it to compare the CONNECT host, the TLS SNI, and the decrypted
/// `Host` header against one normal form (anti domain-fronting).
pub(crate) fn canonical_host(host: &str) -> String {
    let lower = host.to_ascii_lowercase();
    match lower.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => lower,
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

/// Two rules are equal when they are the same kind with the same data; for a regex that is
/// the same pattern string (the compiled engine has no equality of its own).
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Rule::Ip(a, pa), Rule::Ip(b, pb)) => a == b && pa == pb,
            (Rule::Host(a, pa), Rule::Host(b, pb)) => a == b && pa == pb,
            (Rule::Subdomain(a, pa), Rule::Subdomain(b, pb)) => a == b && pa == pb,
            (
                Rule::Url {
                    host: h1,
                    ports: p1,
                    path: pa1,
                    ..
                },
                Rule::Url {
                    host: h2,
                    ports: p2,
                    path: pa2,
                    ..
                },
            ) => h1 == h2 && p1 == p2 && pa1 == pa2,
            (Rule::Regex { pattern: a, .. }, Rule::Regex { pattern: b, .. }) => a == b,
            _ => false,
        }
    }
}

impl Eq for Rule {}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Ip(ip, ports) => {
                let suffix = ports.suffix();
                // bracket an IPv6 literal when it carries a port, so `:port` is unambiguous
                if !suffix.is_empty() && ip.is_ipv6() {
                    write!(f, "[{ip}]{suffix}")
                } else {
                    write!(f, "{ip}{suffix}")
                }
            }
            Rule::Host(h, ports) => write!(f, "{h}{}", ports.suffix()),
            Rule::Subdomain(d, ports) => write!(f, "*.{d}{}", ports.suffix()),
            Rule::Url {
                host, ports, path, ..
            } => write!(f, "{}{}{path}", display_host(host), ports.suffix()),
            Rule::Regex { pattern, .. } => write!(f, "re:{pattern}"),
        }
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
/// (`None` = wait indefinitely until answered); it is inert under the other defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EgressPolicy {
    allow: Vec<Rule>,
    deny: Vec<Rule>,
    default_action: DefaultAction,
    ask_timeout: Option<std::time::Duration>,
}

impl EgressPolicy {
    /// A deny-by-default policy (the classic allowlist). Use [`Self::with_default`] to make it
    /// a denylist.
    pub(crate) fn new(allow: Vec<Rule>, deny: Vec<Rule>) -> Self {
        Self {
            allow,
            deny,
            default_action: DefaultAction::Deny,
            ask_timeout: None,
        }
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

    pub(crate) fn default_action(&self) -> DefaultAction {
        self.default_action
    }

    /// How long a parked `ask` request waits before timing out to a deny — `None` means wait
    /// indefinitely. The proxy reads this only under [`DefaultAction::Ask`].
    pub(crate) fn ask_timeout(&self) -> Option<std::time::Duration> {
        self.ask_timeout
    }

    pub(crate) fn allow_rules(&self) -> &[Rule] {
        &self.allow
    }

    pub(crate) fn deny_rules(&self) -> &[Rule] {
        &self.deny
    }

    /// Whether a request to `host`:`port` for `path` is permitted: it must match some
    /// allow rule and no deny rule — **deny always wins**. A thin bool view over
    /// [`Self::explain`]. The filtering proxy and the `ops test net` tester both decide
    /// through [`Self::explain`] (they need the deciding rule), so this convenience view is
    /// exercised only by tests.
    #[allow(dead_code)]
    pub(crate) fn permits(&self, host: &str, port: u16, path: &str) -> bool {
        matches!(
            self.explain(host, port, path),
            Decision::AllowedBy(_) | Decision::AllowedDefault
        )
    }

    /// Explain the verdict for a request to `host`:`port` for `path`, naming the deciding
    /// rule. Deny wins: a matching deny rule decides even when an allow rule also matches;
    /// otherwise a matching allow rule; otherwise the policy's default action (deny- or
    /// allow-by-default). The request is canonicalized once (host lowercased, path
    /// percent-decoded / `.`/`..` resolved / query dropped) so every rule sees the same
    /// evasion-proof view.
    pub(crate) fn explain(&self, host: &str, port: u16, path: &str) -> Decision<'_> {
        let req = Request::new(host, port, path);
        if let Some(rule) = self.deny.iter().find(|r| r.matches(&req)) {
            return Decision::DeniedBy(rule);
        }
        if let Some(rule) = self.allow.iter().find(|r| r.matches(&req)) {
            return Decision::AllowedBy(rule);
        }
        match self.default_action {
            DefaultAction::Deny => Decision::DeniedDefault,
            DefaultAction::Allow => Decision::AllowedDefault,
            DefaultAction::Ask => Decision::Ask,
        }
    }
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

/// Whether `rule` matches a request to `host`:`port` for `target`, canonicalized exactly
/// the way [`EgressPolicy::explain`] canonicalizes it (host lowercased, path percent-decoded
/// / `.`/`..`-resolved / query dropped). The filtering proxy uses this to decide whether a
/// per-host credential injection applies to a request it has already allowed — so the
/// injection sees the identical normalized view as the verdict, and a host or path dodge
/// cannot separate the two.
pub(crate) fn rule_matches(rule: &Rule, host: &str, port: u16, target: &str) -> bool {
    rule.matches(&Request::new(host, port, target))
}

/// Classify one declared entry (allow or deny) by its syntax, or report why it is
/// malformed. Order matters: a `re:` regex, then a `/`-bearing `host[:ports]/path` URL rule,
/// then the `*.` wildcard, then an IP literal, then a bare hostname. A scheme (`https://`)
/// carries no meaning in a rule — it would only pick a default port the `:port` qualifier
/// already expresses — so it is rejected with a pointer to the scheme-free form. A value that
/// fits none is rejected so it can never be read as an unintended kind.
pub(crate) fn classify(entry: &str) -> Result<Rule, String> {
    let s = entry.trim();
    if s.is_empty() {
        return Err("empty entry".to_string());
    }
    if let Some(pattern) = s.strip_prefix("re:") {
        let re = Regex::new(pattern).map_err(|e| format!("invalid regex `{pattern}`: {e}"))?;
        return Ok(Rule::Regex {
            pattern: pattern.to_string(),
            re,
        });
    }
    // A scheme has no meaning in a rule (it would only select a default port), so reject it
    // rather than mis-read `https:` as a host. A scheme stays meaningful only on a *request*
    // (`ops test net <url>`), which names one concrete connection.
    if scheme_of(s).is_some() {
        return Err(format!(
            "remove the scheme from `{entry}` — a rule takes a bare host and path, e.g. \
             `example.com/path` or `example.com:443/path` (a scheme only names a request's port)"
        ));
    }
    // A `/` marks a `host[:ports]/path` URL rule; without one the entry is host-level.
    if let Some(i) = s.find('/') {
        return parse_path_rule(s, i);
    }
    let (host, ports) = split_host_ports(s)?;
    reject_catch_all(host)?;
    if let Some(domain) = host.strip_prefix("*.") {
        if is_valid_hostname(domain) {
            return Ok(Rule::Subdomain(domain.to_ascii_lowercase(), ports));
        }
        return Err(format!("invalid subdomain wildcard `{entry}`"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Rule::Ip(ip, ports));
    }
    if is_valid_hostname(host) {
        return Ok(Rule::Host(host.to_ascii_lowercase(), ports));
    }
    Err(format!(
        "unrecognized entry `{entry}` (expected an IP, a domain, `*.domain`, a `host[:port]/path` URL, or `re:<regex>`, each host optionally `:port`-qualified)"
    ))
}

/// `*` as a host is a request to allow *every* host, which an allowlist entry deliberately
/// cannot express — the point of `mode = "allowlist"` is deny-by-construction. Catch the bare
/// wildcard in any form (`*`, `*:*`, `*:80`, `http://*`, `https://*:*`) and point the author
/// at the posture switch instead of the generic "unrecognized entry"/"invalid port" message.
/// `*.domain` is a *bounded* subdomain wildcard and is unaffected (its host is `*.domain`, not
/// `*`).
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
/// port set. A bare entry (`github.com`) gets the default web ports {80, 443}; `:*` admits
/// any port; a comma list of single ports and/or `lo-hi` ranges (`:80,443,8000-8100`) pins
/// exactly those. An IPv6 literal carrying a port is **bracketed** (`[::1]:443`,
/// `[2001:db8::1]:*`) so its own colons do not confuse the split; bare, it needs no brackets
/// (`::1`), taken whole at the default ports.
fn split_host_ports(s: &str) -> Result<(&str, Ports), String> {
    // a bracketed IPv6 literal, optionally `:port-spec` after the `]`
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated `[` in `{s}`"))?;
        if addr.parse::<IpAddr>().is_err() {
            return Err(format!("invalid IP literal `[{addr}]`"));
        }
        let ports = match after {
            "" => Ports::default(),
            a => match a.strip_prefix(':') {
                Some(spec) => parse_ports(spec)?,
                None => return Err(format!("expected `:port` after `]` in `{s}`")),
            },
        };
        return Ok((addr, ports));
    }
    // a bare IP literal (including an unbracketed IPv6 like `::1`, whose own colons would
    // confuse the port split) is the whole string, at the default ports
    if s.parse::<IpAddr>().is_ok() {
        return Ok((s, Ports::default()));
    }
    match s.rsplit_once(':') {
        Some((host, spec)) => Ok((host, parse_ports(spec)?)),
        None => Ok((s, Ports::default())),
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

/// Parse a `host[:ports]/path` entry into a `Url` rule. The part before the first `/` is the
/// authority, parsed for its host and port set exactly like a host-level entry — so a path rule
/// supports the same `:port`, comma-list, `lo-hi` range, and `:*` qualifiers (a bare host
/// defaulting to the web ports {80, 443}). The rest, including the leading `/`, is the path. The
/// host must be concrete — an exact hostname or IP literal (bracketed for IPv6); a `*.domain`
/// wildcard with a path is rejected (use `re:`). A trailing `/*` marks a subtree rule (the path
/// and everything under it); without it the path matches exactly.
fn parse_path_rule(s: &str, slash: usize) -> Result<Rule, String> {
    let (authority, path) = (&s[..slash], &s[slash..]);
    if authority.is_empty() {
        return Err(format!("entry `{s}` has no host before the path"));
    }
    let (host, ports) = split_host_ports(authority)?;
    reject_catch_all(host)?;
    if !(is_valid_hostname(host) || host.parse::<IpAddr>().is_ok()) {
        return Err(format!(
            "entry `{s}` has an invalid host `{host}` before the path (a path rule needs a \
             concrete host or IP; use `re:` for a wildcard host)"
        ));
    }
    let subtree = path.ends_with("/*");
    Ok(Rule::Url {
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
    fn classifies_each_granularity() {
        assert_eq!(
            rule("1.2.3.4"),
            Rule::Ip("1.2.3.4".parse().unwrap(), Ports::default())
        );
        assert_eq!(
            rule("::1"),
            Rule::Ip("::1".parse().unwrap(), Ports::default())
        );
        assert_eq!(
            rule("github.com"),
            Rule::Host("github.com".into(), Ports::default())
        );
        assert_eq!(
            rule("*.nixos.org"),
            Rule::Subdomain("nixos.org".into(), Ports::default())
        );
        // a `/` makes it a path rule; a bare host defaults to the web ports {80, 443}
        assert_eq!(
            rule("example.com/exact/path"),
            Rule::Url {
                host: "example.com".into(),
                ports: Ports::default(),
                path: "/exact/path".into(),
                subtree: false,
            }
        );
        // a trailing /* marks a subtree rule
        assert_eq!(
            rule("example.com/area/*"),
            Rule::Url {
                host: "example.com".into(),
                ports: Ports::default(),
                path: "/area/*".into(),
                subtree: true,
            }
        );
    }

    #[test]
    fn a_path_rule_carries_the_same_port_syntax_as_a_host() {
        // a bare `host/` is the root path on the default web ports {80, 443}
        assert_eq!(
            rule("example.com/"),
            Rule::Url {
                host: "example.com".into(),
                ports: Ports::default(),
                path: "/".into(),
                subtree: false,
            }
        );
        // an explicit single port pins exactly that port for the path
        assert_eq!(
            rule("example.com:8443/x"),
            Rule::Url {
                host: "example.com".into(),
                ports: Ports::Ranges(vec![(8443, 8443)]),
                path: "/x".into(),
                subtree: false,
            }
        );
        // `:*` opens the path on any port; a list/range works too
        assert_eq!(
            rule("example.com:*/admin"),
            Rule::Url {
                host: "example.com".into(),
                ports: Ports::Any,
                path: "/admin".into(),
                subtree: false,
            }
        );
        // an IPv6 host with a port and a path
        assert_eq!(
            rule("[::1]:8080/admin"),
            Rule::Url {
                host: "::1".into(),
                ports: Ports::Ranges(vec![(8080, 8080)]),
                path: "/admin".into(),
                subtree: false,
            }
        );
    }

    #[test]
    fn rejects_a_scheme_in_an_entry() {
        // a scheme has no meaning in a rule (it would only pick a port); reject it with a
        // pointer to the scheme-free form rather than mis-reading `https:` as a host
        for bad in [
            "https://example.com/x",
            "http://example.com",
            "https://example.com:8443/x",
        ] {
            let err = classify(bad).unwrap_err();
            assert!(
                err.contains("remove the scheme"),
                "{bad:?} should be rejected with a scheme pointer, got: {err}"
            );
        }
    }

    #[test]
    fn classifies_port_specs() {
        assert_eq!(
            rule("github.com:443"),
            Rule::Host("github.com".into(), Ports::Ranges(vec![(443, 443)]))
        );
        assert_eq!(
            rule("github.com:80,443,8443"),
            Rule::Host(
                "github.com".into(),
                Ports::Ranges(vec![(80, 80), (443, 443), (8443, 8443)])
            )
        );
        // a comma list is sorted and de-duplicated; {80,443} is the default set
        assert_eq!(
            rule("github.com:443,80,443"),
            Rule::Host("github.com".into(), Ports::default())
        );
        // an inclusive range
        assert_eq!(
            rule("internal.test:8000-8100"),
            Rule::Host("internal.test".into(), Ports::Ranges(vec![(8000, 8100)]))
        );
        // ranges and singles mix
        assert_eq!(
            rule("internal.test:22,8000-8100"),
            Rule::Host(
                "internal.test".into(),
                Ports::Ranges(vec![(22, 22), (8000, 8100)])
            )
        );
        // :* is any port
        assert_eq!(
            rule("github.com:*"),
            Rule::Host("github.com".into(), Ports::Any)
        );
        // works on IP and subdomain kinds too
        assert_eq!(
            rule("1.2.3.4:8080,9090"),
            Rule::Ip(
                "1.2.3.4".parse().unwrap(),
                Ports::Ranges(vec![(8080, 8080), (9090, 9090)])
            )
        );
        assert_eq!(
            rule("*.nixos.org:443"),
            Rule::Subdomain("nixos.org".into(), Ports::Ranges(vec![(443, 443)]))
        );
    }

    #[test]
    fn classifies_bracketed_ipv6_with_ports() {
        // bare IPv6 needs no brackets, at the default ports
        assert_eq!(
            rule("::1"),
            Rule::Ip("::1".parse().unwrap(), Ports::default())
        );
        // bracketed, no port -> default ports
        assert_eq!(
            rule("[::1]"),
            Rule::Ip("::1".parse().unwrap(), Ports::default())
        );
        // bracketed with a port spec
        assert_eq!(
            rule("[::1]:443"),
            Rule::Ip("::1".parse().unwrap(), Ports::Ranges(vec![(443, 443)]))
        );
        assert_eq!(
            rule("[2001:db8::1]:8080"),
            Rule::Ip(
                "2001:db8::1".parse().unwrap(),
                Ports::Ranges(vec![(8080, 8080)])
            )
        );
        // :* on IPv6
        assert_eq!(
            rule("[fe80::1]:*"),
            Rule::Ip("fe80::1".parse().unwrap(), Ports::Any)
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
    fn a_bare_host_opens_only_the_web_ports() {
        let a = allow(&["github.com"]);
        assert!(a.permits("github.com", 80, "/"));
        assert!(a.permits("github.com", 443, "/"));
        assert!(
            !a.permits("github.com", 22, "/"),
            "no SSH tunnel through an allowed host"
        );
        assert!(!a.permits("github.com", 8080, "/"));
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
        // bare IPv6 opens the web ports only
        let b = allow(&["::1"]);
        assert!(b.permits("::1", 443, "/"));
        assert!(!b.permits("::1", 8080, "/"));
    }

    #[test]
    fn classification_is_case_insensitive_on_the_host() {
        assert_eq!(
            rule("GitHub.COM"),
            Rule::Host("github.com".into(), Ports::default())
        );
        assert_eq!(
            rule("*.NixOS.org"),
            Rule::Subdomain("nixos.org".into(), Ports::default())
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
            rule("*.nixos.org"),
            Rule::Subdomain("nixos.org".into(), Ports::default())
        );
    }

    #[test]
    fn ip_rule_matches_only_that_ip_on_the_default_ports() {
        let a = allow(&["1.2.3.4"]);
        assert!(a.permits("1.2.3.4", 443, "/anything"));
        assert!(a.permits("1.2.3.4", 80, "/other"));
        assert!(
            !a.permits("1.2.3.4", 8080, "/"),
            "a bare host opens only the web ports"
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
            rule("re:^https://github\\.com/myorg/"),
            Rule::Regex {
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
        match p.explain("cache.nixos.org", 443, "/x") {
            Decision::AllowedBy(r) => assert_eq!(r.to_string(), "*.nixos.org"),
            d => panic!("expected AllowedBy, got {d:?}"),
        }
        // denied by the deny rule, which wins over the matching subdomain allow
        match p.explain("evil.nixos.org", 443, "/x") {
            Decision::DeniedBy(r) => assert_eq!(r.to_string(), "evil.nixos.org"),
            d => panic!("expected DeniedBy, got {d:?}"),
        }
        // denied by default when no allow matches
        assert_eq!(p.explain("other.com", 443, "/"), Decision::DeniedDefault);
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
    fn default_deny_is_the_constructor_default() {
        // `new` and `Default` both deny by default: an unmatched host gets `DeniedDefault`.
        let p = EgressPolicy::new(vec![rule("github.com")], vec![]);
        assert_eq!(p.default_action(), DefaultAction::Deny);
        assert_eq!(p.explain("other.com", 443, "/"), Decision::DeniedDefault);
        assert_eq!(
            EgressPolicy::default().default_action(),
            DefaultAction::Deny
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
            p.explain("anything.example", 443, "/"),
            Decision::AllowedDefault
        );

        // a deny rule still wins, even under allow-by-default
        assert!(!p.permits("evil.com", 443, "/"));
        assert!(matches!(
            p.explain("evil.com", 443, "/"),
            Decision::DeniedBy(_)
        ));

        // an explicit allow rule is still reported as `AllowedBy` (it names the deciding rule),
        // which the SSRF private-host exception relies on — `AllowedDefault` has no such rule
        let q =
            EgressPolicy::new(vec![rule("10.0.0.1")], vec![]).with_default(DefaultAction::Allow);
        assert!(matches!(
            q.explain("10.0.0.1", 443, "/"),
            Decision::AllowedBy(_)
        ));
    }

    #[test]
    fn display_round_trips_each_kind() {
        assert_eq!(rule("1.2.3.4").to_string(), "1.2.3.4");
        assert_eq!(rule("github.com").to_string(), "github.com");
        assert_eq!(rule("*.nixos.org").to_string(), "*.nixos.org");
        // a path rule is scheme-free; default ports render bare, an explicit port is kept
        assert_eq!(rule("example.com/x").to_string(), "example.com/x");
        assert_eq!(rule("example.com:8443/x").to_string(), "example.com:8443/x");
        assert_eq!(
            rule("example.com:*/admin").to_string(),
            "example.com:*/admin"
        );
        // port specs round-trip; the default {80,443} renders bare
        assert_eq!(rule("github.com:443").to_string(), "github.com:443");
        assert_eq!(
            rule("github.com:80,443,8443").to_string(),
            "github.com:80,443,8443"
        );
        assert_eq!(
            rule("internal.test:8000-8100").to_string(),
            "internal.test:8000-8100"
        );
        assert_eq!(rule("github.com:*").to_string(), "github.com:*");
        assert_eq!(
            rule("github.com:443,80").to_string(),
            "github.com",
            "the default set renders as a bare host"
        );
        // IPv6: bare needs no brackets, a port spec re-brackets it
        assert_eq!(rule("::1").to_string(), "::1");
        assert_eq!(rule("[::1]:443").to_string(), "[::1]:443");
        assert_eq!(rule("[2001:db8::1]:*").to_string(), "[2001:db8::1]:*");
        // a path rule with an IPv6 host stays bracketed
        assert_eq!(rule("[::1]:8080/secret").to_string(), "[::1]:8080/secret");
        assert_eq!(rule("[2001:db8::1]/a/b").to_string(), "[2001:db8::1]/a/b");
    }
}
