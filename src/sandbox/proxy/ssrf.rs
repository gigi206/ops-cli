//! The post-resolution SSRF guard: classify a resolved address as public / private / blocked, and
//! decide whether the proxy may connect to it for a given host and deciding rule.
//!
//! The proxy runs on the host with full network reach, so an allowlisted *hostname* (or a rebound
//! DNS answer for it) resolving to an internal address would be an SSRF vector; these functions are
//! the post-resolution guard applied before every upstream connection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::allowlist::{self, Rule, RuleKind};

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

/// Whether the proxy may connect to `ip` for a request to `host` that the policy permitted via
/// `deciding`. Public addresses are reachable; a private address is reachable only when the
/// deciding rule named this exact host (a deliberate internal target — not a `*.domain`/regex/
/// built-in match, which would turn into an SSRF wildcard); a blocked address never is.
pub(super) fn ip_permitted(ip: IpAddr, host: &str, deciding: Option<&Rule>) -> bool {
    match classify_ip(ip) {
        IpClass::Public => true,
        IpClass::Blocked => false,
        IpClass::Private => names_exact_host(host, deciding),
    }
}

/// Whether `deciding` is an explicit, exact-host rule for `host` (not a wildcard/regex). Used to
/// gate the private-IP exception. With no deciding rule — an allow-by-default verdict — the
/// exception never applies, so a private/loopback address is refused (a denylist opens public
/// egress, not the host's own internal services).
pub(super) fn names_exact_host(host: &str, deciding: Option<&Rule>) -> bool {
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
