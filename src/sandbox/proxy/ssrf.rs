//! The address a connect path is allowed to dial: resolve the host, classify what came back as
//! public / private / blocked, and decide whether the proxy may connect to it for this host and
//! deciding rule.
//!
//! The proxy runs on the host with full network reach, so an allowlisted *hostname* (or a rebound
//! DNS answer for it) resolving to an internal address would be an SSRF vector; the guard below is
//! applied before every upstream connection. It is reached only through [`resolve_checked`] /
//! [`checked_address`], which record the refusal as they make it -- so a connect path cannot turn a
//! request down here without the counter, the log and the notification saying so.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{ProxyCtx, StatKind};
use crate::allowlist::{self, Rule, RuleKind};
use crate::sandbox::control::{LogVerdict, Proto};

/// Whether a resolved address is public, a private/internal range, or one that is refused
/// outright. The proxy runs on the host with full network reach, so an allowlisted *hostname*
/// (or a rebound DNS answer for it) resolving to an internal address would be an SSRF vector;
/// this classification is the post-resolution guard.
enum IpClass {
    /// A routable public address — reachable subject to the policy.
    Public,
    /// A loopback / RFC1918 / ULA / CGNAT address — reachable only when the policy explicitly
    /// named this exact host (an intentional internal target).
    Private,
    /// Link-local (incl. cloud metadata `169.254.169.254` / `fe80::/10`), multicast, or the
    /// unspecified address — never reachable, even if explicitly listed.
    Blocked,
}

fn classify_ip(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        // An IPv6 address that embeds a v4 (mapped, NAT64, 6to4, Teredo) is classified as that v4,
        // so an internal/metadata v4 cannot dodge the v4 guard wearing a v6 spelling (e.g.
        // `64:ff9b::a9fe:a9fe`, NAT64 of `169.254.169.254`).
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

/// The IPv4 address an IPv6 address embeds through a translation/transition form, or `None`.
/// Covers IPv4-mapped (`::ffff:a.b.c.d`), NAT64 well-known (`64:ff9b::/96`, the v4 in the low 32
/// bits), 6to4 (`2002:AABB:CCDD::/16`), and Teredo (`2001:0::/32`, the client v4 in the last two
/// segments, bit-inverted). The host's stack actually routing these is what makes the SSRF real;
/// classifying them by their embedded v4 keeps the metadata/internal guard sound where it does.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    let v4_of =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // NAT64 well-known prefix 64:ff9b::/96 — the v4 is the low 32 bits.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return Some(v4_of(s[6], s[7]));
    }
    // 6to4 2002::/16 — the v4 is segments 1 and 2.
    if s[0] == 0x2002 {
        return Some(v4_of(s[1], s[2]));
    }
    // Teredo 2001:0::/32 — the client v4 is the last two segments, bit-inverted.
    if s[0] == 0x2001 && s[1] == 0x0000 {
        return Some(v4_of(!s[6], !s[7]));
    }
    None
}

fn classify_v4(v4: Ipv4Addr) -> IpClass {
    // link-local covers the cloud metadata address 169.254.169.254
    if v4.is_link_local() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() {
        return IpClass::Blocked;
    }
    let o = v4.octets();
    // loopback, RFC1918, and the CGNAT shared range 100.64.0.0/10
    if v4.is_loopback() || v4.is_private() || (o[0] == 100 && (64..=127).contains(&o[1])) {
        return IpClass::Private;
    }
    IpClass::Public
}

fn classify_v6(v6: Ipv6Addr) -> IpClass {
    let s = v6.segments();
    // link-local fe80::/10, multicast ff00::/8, unspecified ::
    if v6.is_unspecified() || v6.is_multicast() || (s[0] & 0xffc0) == 0xfe80 {
        return IpClass::Blocked;
    }
    // loopback ::1 and unique-local fc00::/7
    if v6.is_loopback() || (s[0] & 0xfe00) == 0xfc00 {
        return IpClass::Private;
    }
    IpClass::Public
}

/// Why the post-resolution guard refuses an address the policy permitted. Carried out of
/// [`ip_refusal`] so a caller can say *which* guard fired: the proxy only needs the boolean, but
/// `sbx test net` reports the reason, and both read it from the one decision below.
pub(crate) enum AddrRefusal {
    /// A private/loopback address whose deciding rule does not name that exact host.
    PrivateWithoutExactHost,
    /// Link-local (incl. cloud metadata), multicast, or the unspecified address: never reachable,
    /// however the policy is written.
    NeverReachable,
}

/// Why the proxy would refuse to connect to `ip` for a request to `host` that the policy permitted
/// via `deciding`, or `None` when it may connect. Public addresses are reachable; a private address
/// is reachable only when the deciding rule named this exact host (a deliberate internal target —
/// not a `*.domain`/regex/built-in match, which would turn into an SSRF wildcard); a blocked address
/// never is. The single decision behind both callers: the proxy's guarded resolution
/// ([`checked_address`]) and the `sbx test net` tester, which would otherwise mispredict a private
/// target.
pub(crate) fn ip_refusal(ip: IpAddr, host: &str, deciding: Option<&Rule>) -> Option<AddrRefusal> {
    match classify_ip(ip) {
        IpClass::Public => None,
        IpClass::Blocked => Some(AddrRefusal::NeverReachable),
        IpClass::Private if names_exact_host(host, deciding) => None,
        IpClass::Private => Some(AddrRefusal::PrivateWithoutExactHost),
    }
}

/// Whether the proxy may connect to `ip` for a request to `host` the policy permitted via
/// `deciding` — [`ip_refusal`] read as a boolean, which is all the connect paths need. Private to
/// this module: a path reaches it through [`checked_address`], never directly, so the refusal is
/// always recorded.
fn ip_permitted(ip: IpAddr, host: &str, deciding: Option<&Rule>) -> bool {
    ip_refusal(ip, host, deciding).is_none()
}

/// Why a connect path may not reach a host the policy allowed: the name did not resolve, or every
/// address it resolved to is one the guard refuses. Both are answered to the client, so each knows
/// the status to answer with, the stable `x-sbx-egress-reason` token, and the sentence the refusal
/// body repeats — the four connect paths differ in how they write a refusal, not in what it says.
pub(super) enum ConnectRefusal {
    /// The name did not resolve. An *error*, not a refusal: the policy said yes, so it is logged as
    /// one and moves no counter — the whole point of the distinction is that this reads differently
    /// from "we said no".
    Dns,
    /// Every resolved address was private or never-reachable, and the deciding rule names no exact
    /// host. A security guard firing, so it is counted and announced like the others.
    Ssrf,
}

impl ConnectRefusal {
    /// The status line the HTTP/1.1 paths write.
    pub(super) fn status_line(&self) -> &'static str {
        match self {
            Self::Dns => "502 Bad Gateway",
            Self::Ssrf => "403 Forbidden",
        }
    }

    /// The same status for the HTTP/2 path, which frames it rather than writing it.
    pub(super) fn status(&self) -> http::StatusCode {
        match self {
            Self::Dns => http::StatusCode::BAD_GATEWAY,
            Self::Ssrf => http::StatusCode::FORBIDDEN,
        }
    }

    /// The stable reason token: the `x-sbx-egress-reason` header, and the reason in the log.
    pub(super) fn tag(&self) -> &'static str {
        match self {
            Self::Dns => "dns-failure",
            Self::Ssrf => "ssrf-blocked",
        }
    }

    /// The sentence the refusal body carries, naming the host the client asked for.
    pub(super) fn message(&self, host: &str) -> String {
        match self {
            Self::Dns => format!("DNS resolution failed for `{host}`"),
            Self::Ssrf => format!(
                "`{host}` resolved only to disallowed addresses (a private or metadata range)"
            ),
        }
    }
}

/// Resolve `host` host-side, then settle on the one address the proxy may dial for it: the first
/// resolved address the guard permits for `deciding`. A resolution failure for an allowed host is
/// an error the client is told about (a clean `502`), not a dropped connection.
pub(super) fn resolve_checked(
    ctx: &ProxyCtx,
    proto: Proto,
    host: &str,
    port: u16,
    method: Option<&str>,
    path: Option<&str>,
    deciding: Option<&Rule>,
) -> Result<IpAddr, ConnectRefusal> {
    let Ok(ips) = (ctx.resolve)(host) else {
        ctx.push_log(
            proto,
            host,
            port,
            method,
            path,
            LogVerdict::Error,
            ConnectRefusal::Dns.tag(),
        );
        return Err(ConnectRefusal::Dns);
    };
    checked_address(ctx, proto, host, port, method, path, deciding, ips)
}

/// The guard alone, over addresses already in hand — for the raw splice, whose target may be an IP
/// literal it holds without resolving anything. [`resolve_checked`] is this with the resolution in
/// front of it.
#[allow(clippy::too_many_arguments)]
pub(super) fn checked_address(
    ctx: &ProxyCtx,
    proto: Proto,
    host: &str,
    port: u16,
    method: Option<&str>,
    path: Option<&str>,
    deciding: Option<&Rule>,
    ips: Vec<IpAddr>,
) -> Result<IpAddr, ConnectRefusal> {
    let Some(ip) = ips.into_iter().find(|ip| ip_permitted(*ip, host, deciding)) else {
        ctx.outcome(
            proto,
            host,
            port,
            method,
            path,
            StatKind::Blocked,
            ConnectRefusal::Ssrf.tag(),
        );
        return Err(ConnectRefusal::Ssrf);
    };
    Ok(ip)
}

/// Whether `deciding` is an explicit, exact-host rule for `host` (not a wildcard/regex). Used to
/// gate the private-IP exception. With no deciding rule — an allow-by-default verdict — the
/// exception never applies, so a private/loopback address is refused (a denylist opens public
/// egress, not the host's own internal services).
pub(crate) fn names_exact_host(host: &str, deciding: Option<&Rule>) -> bool {
    let Some(deciding) = deciding else {
        return false;
    };
    let h = allowlist::canonical_host(host);
    match &deciding.kind {
        RuleKind::Host(rh, _) => *rh == h,
        RuleKind::Url { host: rh, .. } => *rh == h,
        RuleKind::Ip(rip, _) => rip.to_string() == h,
        RuleKind::Subdomain(..) | RuleKind::Regex { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connect_boolean_and_the_reported_reason_are_one_decision() {
        // The proxy reads a boolean and `sbx test net` reads the reason; if they ever came from two
        // decisions the tester would mispredict exactly what it exists to predict. Pin them to the
        // same call across all three classes and both sides of the exact-host exception.
        let exact = allowlist::classify("10.0.0.5").unwrap();
        let wild = allowlist::classify("re:.*").unwrap();
        for (ip, host, deciding) in [
            ("93.184.216.34", "93.184.216.34", Some(&wild)),
            ("10.0.0.5", "10.0.0.5", Some(&exact)),
            ("10.0.0.5", "10.0.0.5", Some(&wild)),
            ("127.0.0.1", "127.0.0.1", None),
            ("169.254.169.254", "169.254.169.254", Some(&exact)),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(
                ip_permitted(ip, host, deciding),
                ip_refusal(ip, host, deciding).is_none(),
                "the two readings of the guard disagree on {ip} for {host}"
            );
        }
        // And the reason discriminates the two refusing classes, which is what the reader needs.
        assert!(matches!(
            ip_refusal("10.0.0.5".parse().unwrap(), "10.0.0.5", Some(&wild)),
            Some(AddrRefusal::PrivateWithoutExactHost)
        ));
        assert!(matches!(
            ip_refusal(
                "169.254.169.254".parse().unwrap(),
                "169.254.169.254",
                Some(&exact)
            ),
            Some(AddrRefusal::NeverReachable)
        ));
    }

    #[test]
    fn classify_ip_unwraps_v6_embedded_v4_translation_forms() {
        let c = |s: &str| classify_ip(s.parse::<IpAddr>().unwrap());
        // NAT64 well-known of the metadata address 169.254.169.254 → blocked, not public
        assert!(matches!(c("64:ff9b::a9fe:a9fe"), IpClass::Blocked));
        // NAT64 of loopback → private
        assert!(matches!(c("64:ff9b::7f00:1"), IpClass::Private));
        // 6to4 of 10.0.0.1 (RFC1918) → private
        assert!(matches!(c("2002:0a00:0001::"), IpClass::Private));
        // Teredo carrying 169.254.169.254 (client v4 bit-inverted: !0xa9fe = 0x5601) → blocked
        assert!(matches!(c("2001:0:0:0:0:0:5601:5601"), IpClass::Blocked));
        // a genuine public v6 (no embedded v4) stays public
        assert!(matches!(c("2606:4700:4700::1111"), IpClass::Public));
        // the pre-existing v4-mapped case still folds to its v4 class
        assert!(matches!(c("::ffff:127.0.0.1"), IpClass::Private));
    }
}
