//! The egress-rule grammar: parse a textual allowlist entry (an IP/host/subdomain, a
//! `host[:ports]/path` URL, a `re:` regex, or a `tcp://`/`http://` scheme) into a [`Rule`],
//! and parse a request target / method set. Turns text into the matcher's data model; the
//! matching itself lives in [`super`].

use super::*;

/// Where an entry was written, so the one refusal that offers a way out — the bare `*` catch-all,
/// see [`reject_catch_all`] — offers the way out that *that* list's author was reaching for. Every
/// other diagnostic is list-agnostic (a malformed port is malformed wherever it sits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    /// An `allow` list: the entries a filtering posture lets through.
    Allow,
    /// A `deny` list: the entries subtracted from what the allow side lets through.
    Deny,
    /// A `mute` list: a log filter that changes no verdict.
    Mute,
    /// Not a rule at all — the concrete host or URL `sbx test net` tests a policy against.
    Target,
}

impl Slot {
    /// The config key this slot is written under, for a diagnostic that names the list an entry sat
    /// in. [`Slot::Target`] has no key (it is a request, not a declaration) and renders as `target`.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Slot::Allow => "allow",
            Slot::Deny => "deny",
            Slot::Mute => "mute",
            Slot::Target => "target",
        }
    }
}

/// Classify one declared entry by its syntax, or report why it is malformed, as a [`Slot::Allow`]
/// entry — the shape every caller that names one destination declares (a task's `network` list, a
/// secret's `to`, a synthesized learned rule). The `allow`/`deny`/`mute` lists of a `[network]`
/// table, and the `sbx net allow|deny|mute` write path, go through [`classify_in`] instead so a
/// refused catch-all names their own escape hatch.
pub(crate) fn classify(entry: &str) -> Result<Rule, String> {
    classify_in(entry, Slot::Allow)
}

/// Classify one declared entry (in `slot`'s list) by its syntax, or report why it is malformed. The
/// optional pieces are peeled in order: a leading `{VERB,...}` method prefix, then — for a non-`re:`
/// entry — a `tcp://`/`http://`/`https://` scheme that selects the enforcement [`Layer`]. A `re:`
/// regex is never scheme-split (its pattern may itself contain `://`) and is always inspected over
/// TLS. A `tcp://` (raw L4) rule is constrained: it carries no method prefix and no `/path` (a raw
/// stream has no HTTP), so either is rejected. An `http://` (cleartext L7) rule carries the full HTTP
/// vocabulary (method, path) like the default inspected layer, only on a plaintext transport. A value
/// that fits no kind is rejected so it can never be read as an unintended kind.
pub(crate) fn classify_in(entry: &str, slot: Slot) -> Result<Rule, String> {
    let (methods, rest) = split_method_prefix(entry.trim())?;
    let rest = rest.trim();
    // `re:` patterns may contain `://`, so they are never scheme-split — always inspected over TLS.
    if let Some(pattern) = rest.strip_prefix("re:") {
        // A pattern anchored on a scheme other than `https` can never fire, so it is refused at
        // parse time rather than accepted and silently inert. `Request::new` reconstructs the URL
        // it matches against as `https://<authority><path>` for *every* request, the cleartext
        // plane included — so `re:^http://internal\.corp`, the natural spelling for narrowing a
        // cleartext host one has just opened, matched nothing and said nothing. A deny that cannot
        // deny is the worst shape a rule can take: it reads as protection.
        for scheme in ["http://", "tcp://", "ws://", "wss://", "ftp://"] {
            if let Some(anchored) = pattern.strip_prefix('^')
                && anchored.starts_with(scheme)
            {
                return Err(format!(
                    "entry `{entry}` anchors a `re:` pattern on `{scheme}`, which can never match \
                     — the URL a `re:` rule is tested against is always rebuilt as `https://…`, \
                     whatever transport the request used. Drop the scheme from the pattern (the \
                     layer is chosen by the rule's own scheme, not by its regex)"
                ));
            }
        }
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
    let kind = classify_kind(body.trim(), layer.default_port(), slot)?;
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
/// `re:`, never at the very start). No `{` means [`Methods::Unspecified`] and the whole entry as the
/// body: all verbs on its own, but the one state a per-app `default_methods` narrows at resolution.
/// An explicit `{*}` is [`Methods::Any`] instead — the same verbs today, but never rewritten, which
/// is how a rule opts a host back out to every verb under a read-by-default app.
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
fn classify_kind(s: &str, default_port: u16, slot: Slot) -> Result<RuleKind, String> {
    if s.is_empty() {
        return Err("empty entry".to_string());
    }
    // A `/` marks a `host[:ports]/path` URL rule; without one the entry is host-level.
    if let Some(i) = s.find('/') {
        return parse_path_rule(s, i, default_port, slot);
    }
    let (host, ports) = split_host_ports(s, default_port)?;
    reject_catch_all(host, slot)?;
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

/// `*` as a host is a request to match *every* host. The grammar deliberately has no such spelling:
/// widening or closing a whole posture is what `[network] mode` is for, and a rule that quietly did
/// it would make the mode unreadable. Catch the bare wildcard in any port form (`*`, `*:*`, `*:80`,
/// and the `https://`/`tcp://` equivalents after the scheme is stripped) rather than let it fall
/// through to the generic "unrecognized entry"/"invalid port" message. `*.domain` is a *bounded*
/// subdomain wildcard and is unaffected (its host is `*.domain`, not `*`).
///
/// The refusal is **not** a security boundary, and the message says so honestly rather than claiming
/// a reach it does not have: `re:.*` (or any regex that matches everything) is accepted and does
/// widen an allow list to every host. What it buys is that opening or closing everything stays an
/// explicit act, spelled where a reader looks for it. So each [`Slot`] is answered with the escape
/// hatch its own author was reaching for — an `allow` catch-all wants a wider posture, a `deny`
/// catch-all wants a *narrower* one (telling that author to open the network, as one shared message
/// once did, points the exact wrong way), a `mute` changes no verdict at all, and a
/// [`Slot::Target`] is not a rule in the first place.
fn reject_catch_all(host: &str, slot: Slot) -> Result<(), String> {
    if host != "*" {
        return Ok(());
    }
    Err(match slot {
        Slot::Allow => {
            "`*` matches every host: as an allow entry it would widen the list to everything, \
             which is a posture rather than a rule. To open the network fully set `[network] mode \
             = \"shared\"` (no proxy at all, the host's own network); to allow everything but keep \
             every request proxied, logged, and refusable by a `deny` entry, set `mode = \"allow\"`. \
             The catch-all regex `re:.*` reaches just as far and is accepted — it is a rule, so each \
             request it lets through names it — but prefer the posture, which reads as what it does"
        }
        Slot::Deny => {
            "`*` matches every host: as a deny entry it would close everything, which is a posture \
             rather than a carve-out (a deny entry subtracts from what the allow side lets \
             through). To let nothing out at all set `[network] mode = \"none\"`; to let through \
             only what you name, set `mode = \"deny\"` and list those hosts in `allow`"
        }
        Slot::Mute => {
            "`*` matches every host: as a mute entry it would silence every refusal, leaving the \
             log empty of the thing it exists to show. Name the noisy hosts, or — deliberately — \
             write the catch-all regex `re:.*` (a mute changes no verdict, only what `sbx net logs` \
             shows by default; `--all` brings muted lines back either way)"
        }
        Slot::Target => {
            "`*` is not a host: a target names the one concrete host or URL to test the policy \
             against (a *rule* may carry a wildcard; the request it is tested with may not). Test \
             a real destination, e.g. `sbx test net https://github.com`"
        }
    }
    .to_string())
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

/// Split an optional `:port-spec` suffix off a host-level entry, returning the host and its
/// port set. A bare entry (`github.com`) gets the default HTTPS port {443}; `:*` admits
/// any port; a comma list of single ports and/or `lo-hi` ranges (`:80,443,8000-8100`) pins
/// exactly those. An IPv6 literal carrying a port is **bracketed** (`[::1]:443`,
/// `[2001:db8::1]:*`) so its own colons do not confuse the split; bare, it needs no brackets
/// (`::1`), taken whole at the default ports.
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
/// a concrete connection, so it keeps the scheme (which sets the port). Its callers are the
/// `sbx test net` tester and the proxy's two absolute-form paths (`http://` cleartext and the
/// `https://` forward). Allow/deny *rules* are scheme-free and parsed by [`classify`].
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
        reject_catch_all(h, Slot::Target)?;
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

/// Parse a `tcp://host:port` target naming one **L4 request** (for `sbx test net tcp://…`) into
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
        reject_catch_all(h, Slot::Target)?;
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
fn parse_path_rule(
    s: &str,
    slash: usize,
    default_port: u16,
    slot: Slot,
) -> Result<RuleKind, String> {
    let (authority, path) = (&s[..slash], &s[slash..]);
    if authority.is_empty() {
        return Err(format!("entry `{s}` has no host before the path"));
    }
    let (host, ports) = split_host_ports(authority, default_port)?;
    reject_catch_all(host, slot)?;
    if !(is_valid_hostname(host) || host.parse::<IpAddr>().is_ok()) {
        return Err(format!(
            "entry `{s}` has an invalid host `{host}` before the path (a path rule needs a \
             concrete host or IP; use `re:` for a wildcard host)"
        ));
    }
    // A query written into a path rule is silently dropped on the request side and kept on the
    // rule's, so the rule matches the path alone while displaying a form that describes something
    // narrower. `allow = ["files.test/exec?cmd=ls"]`, written to open one call, opened every query
    // on `/exec` — and `sbx test net` printed the rule back with the query still on it. Refused
    // here, beside the wildcard-host refusal above and for the same reason: a rule that cannot mean
    // what it says is an error its author should see, not a silent widening.
    if let Some((before, _)) = path.split_once('?') {
        return Err(format!(
            "entry `{s}` writes a query string in a path rule — a rule matches the path only, so \
             this would open `{before}` with any query at all. Use `re:` to constrain a query"
        ));
    }
    let subtree = path.ends_with("/*");
    // A `*` anywhere but the trailing `/*` is a literal segment, and silently so: `deny =
    // ["api.test/*/secrets"]`, written to close that page for every organisation, matched only the
    // path that literally contains a star and refused nothing. That is a `deny` that reads as
    // narrower than it is, which is the direction this grammar refuses everywhere else -- a
    // wildcard host, an invalid port, an unsupported scheme and a query string are all errors their
    // author is shown. Refused here for the same reason, naming the two forms that do work.
    let literal = if subtree {
        &path[..path.len() - 2]
    } else {
        path
    };
    if literal.contains('*') {
        return Err(format!(
            "entry `{s}` writes `*` inside a path rule — a path rule matches its segments \
             literally, so this would match only a path that really contains a star. Use `re:` \
             for a pattern, or a trailing `/*` to cover a subtree"
        ));
    }
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
