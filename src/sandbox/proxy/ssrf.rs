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
    /// An address that is not the public Internet's: loopback, RFC1918, ULA, CGNAT, and the ranges
    /// IANA set aside for something else (TEST-NET, benchmarking, documentation, reserved).
    ///
    /// Reachable only when the policy explicitly named this exact host (an intentional internal
    /// target).
    ///
    /// The set-aside ranges sit here rather than under [`Self::Blocked`] because a lab or a VPN does put
    /// them on a local interface — 198.18.0.0/15 is what several VPN and DNS clients route
    /// internally — so refusing them outright would deny a destination a user deliberately
    /// configured, with no way to say otherwise. This class is exactly the bargain that case wants:
    /// a wildcard or a regex cannot reach them, and a rule naming the host can.
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
///
/// Covers IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`), NAT64 well-known
/// (`64:ff9b::/96`, the v4 in the low 32 bits), 6to4 (`2002:AABB:CCDD::/16`), and Teredo
/// (`2001:0::/32`, the client v4 in the last two segments, bit-inverted). The host's stack actually
/// routing these is what makes the SSRF real; classifying them by their embedded v4 keeps the
/// metadata/internal guard sound where it does.
///
/// **`::` and `::1` are deliberately not unwrapped**, though they match the IPv4-compatible shape.
/// They denote the unspecified and loopback addresses in their own right, and [`classify_v6`]
/// already answers for both (`Blocked` and `Private`). Unwrapping them is not a wash: `::1` becomes
/// `0.0.0.1`, which is not loopback, not private and not unspecified, so [`classify_v4`] calls it
/// `Public` and the loopback guard comes off for the one spelling most likely to be tried. This is
/// why the check below is written out rather than delegated to `Ipv6Addr::to_ipv4`, which unwraps
/// those two along with everything else.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let s = v6.segments();
    let v4_of =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    // IPv4-compatible `::a.b.c.d` (RFC 4291 §2.5.5.1): 96 zero bits, then the v4. Deprecated as a
    // transition mechanism and still unwrapped by host stacks, which is what makes it reachable —
    // `::127.0.0.1` is not `::1`, not `fe80::/10` and not `fc00::/7`, so the v6 classifier called
    // it public while every other spelling of that address is refused.
    if s[..6] == [0, 0, 0, 0, 0, 0] && !(s[6] == 0 && matches!(s[7], 0 | 1)) {
        return Some(v4_of(s[6], s[7]));
    }
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
    // The ranges IANA set aside for something other than the public Internet: TEST-NET-1/2/3
    // (RFC 5737), the RFC 2544 benchmarking range 198.18.0.0/15, and the reserved 240.0.0.0/4.
    // Falling through to `Public` said they were ordinary destinations, which is a wrong answer in
    // the one place a wrong answer is read out loud: `sbx test net` shares this decision, so it
    // predicted `198.18.0.0/15` reachable while a real request to it dies at the dial with
    // `502 upstream-unreachable`. The broadcast address is a member of the last range and was
    // already refused above, which is why that check comes first.
    //
    // Written by octets, like the CGNAT range beside it, because `is_benchmarking` and
    // `is_reserved` are still unstable; `is_documentation` is not, so TEST-NET uses it.
    if v4.is_documentation() || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) || o[0] >= 240 {
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
    // loopback ::1, unique-local fc00::/7, and the documentation prefix 2001:db8::/32 — the v6
    // half of the same rule the v4 classifier applies to TEST-NET.
    if v6.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] == 0x2001 && s[1] == 0x0db8) {
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
/// is reachable only when [`opens_private_address`] says so (a deliberate internal target — not a
/// `*.domain`/regex/built-in match, which would turn into an SSRF wildcard); a blocked address never
/// is. The single decision behind both callers: the proxy's guarded resolution
/// ([`checked_address`]) and the `sbx test net` tester, which would otherwise mispredict a private
/// target.
pub(crate) fn ip_refusal(ip: IpAddr, host: &str, deciding: Option<&Rule>) -> Option<AddrRefusal> {
    match classify_ip(ip) {
        IpClass::Public => None,
        IpClass::Blocked => Some(AddrRefusal::NeverReachable),
        IpClass::Private if opens_private_address(host, deciding) => None,
        IpClass::Private => Some(AddrRefusal::PrivateWithoutExactHost),
    }
}

/// Whether the rule that permitted this request may reach a **private** address for `host`: it names
/// the exact host ([`names_exact_host`]) *and* somebody wrote it.
///
/// The origin half is the one the contract above always claimed and the code did not have. The
/// built-in self-equip allow set ([`builtin_allow_rules`](super::builtin_allow_rules)) is unioned
/// into every policy in every posture, and six of its eight entries are bare hosts — `github.com`,
/// `api.github.com`, `codeload.github.com`, `cache.nixos.org`, `search.devbox.sh`,
/// `mise-versions.jdx.dev` — which classify as `RuleKind::Host` and therefore satisfied the
/// exact-host test. (The two `*.` entries are `Subdomain` and were correctly excluded, which is what
/// made the asymmetry invisible on a casual read.) So a cage with an empty allowlist reached a
/// private address for a name no user ever wrote down, whenever the host's own resolver mapped one
/// of those six somewhere internal — split-horizon DNS pointing `github.com` at an appliance on
/// 10.x, a `address=/github.com/127.0.0.1` blocklist entry, an NXDOMAIN-hijacking resolver.
///
/// The exception exists for a target the operator deliberately named; a rule nobody wrote names
/// nothing, so the built-in lane can only ever reach a public address. Compared by value rather than
/// by an origin flag on [`Rule`]: `Rule`'s equality is its match (kind, methods, layer), the built-in
/// entries all carry an explicit `{GET,HEAD}` prefix that no `apply_default_methods` pass rewrites,
/// and the comparison is reached only for an address already classified private whose rule already
/// names the host — so it costs nothing on any live path.
pub(crate) fn opens_private_address(host: &str, deciding: Option<&Rule>) -> bool {
    names_exact_host(host, deciding) && !decided_by_builtin(deciding)
}

/// Whether the deciding rule is one of the always-on self-equip entries rather than one the user
/// wrote.
fn decided_by_builtin(deciding: Option<&Rule>) -> bool {
    let Some(rule) = deciding else {
        return false;
    };
    super::builtin_allow_rules()
        .iter()
        .any(|builtin| builtin == rule)
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

/// Resolve `host` host-side, then hand back every address the proxy may dial for it: the resolved
/// addresses the guard permits for `deciding`, in resolution order. A resolution failure for an
/// allowed host is an error the client is told about (a clean `502`), not a dropped connection.
///
/// A list rather than one address, because one was a bug: a host whose first record is out of
/// service was answered `502` where any ordinary client would have tried the next. Dial them with
/// [`first_reachable`], which is where the order is honoured.
pub(super) fn resolve_checked(
    ctx: &ProxyCtx,
    proto: Proto,
    host: &str,
    port: u16,
    method: Option<&str>,
    path: Option<&str>,
    deciding: Option<&Rule>,
) -> Result<Vec<IpAddr>, ConnectRefusal> {
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
) -> Result<Vec<IpAddr>, ConnectRefusal> {
    // *Every* permitted address, in resolution order — not the first one. The guard is applied to
    // each, so nothing here widens what may be dialled; what changes is that a caller can move on
    // from an address that will not connect. Keeping only the first meant a multi-homed host whose
    // first A record was out of service answered `502 upstream-unreachable`, where an ordinary
    // client — which walks the list — would have reached the second.
    let permitted: Vec<IpAddr> = ips
        .into_iter()
        .filter(|ip| ip_permitted(*ip, host, deciding))
        .collect();
    if permitted.is_empty() {
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
    }
    Ok(permitted)
}

/// Dial the permitted addresses in order, answering with the first that connects.
///
/// The list comes from [`checked_address`], so the SSRF guard has already passed on **each** of
/// them — walking it cannot reach an address the guard refused, which is the property that makes
/// the walk safe rather than a second chance at the same question. The last error is the one
/// reported: a caller that could reach none of them is told about the last thing it tried, and the
/// Open one TCP connection to `ip:port`, bounded by `timeout`.
///
/// The bound is the whole point, and it is what every caller here was missing. `TcpStream::connect`
/// has no deadline of its own: a destination that drops SYN silently -- a firewall configured to
/// blackhole rather than reject, which is the common shape -- holds the calling thread for the
/// kernel's own retry schedule, which is on the order of two minutes. These are the proxy's
/// synchronous planes, so that thread is one of a bounded pool serving the cage; enough such
/// requests and the pool is gone, and every later egress attempt is refused with the connection cap
/// while nothing is actually connected.
///
/// `ctx.timeout` is the right bound because it is already what the sockets below get for reads and
/// writes: a caller that would not wait this long for a byte has no reason to wait longer for the
/// handshake that precedes it. The asynchronous h2 plane already wraps its own connect in
/// `tokio::time::timeout(ctx.timeout, ..)`; this is that rule for the three synchronous ones.
pub(super) fn dial_bounded(
    ip: IpAddr,
    port: u16,
    timeout: std::time::Duration,
) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, port), timeout)
}

/// refusal it renders is the same one a single-address failure produced.
pub(super) fn first_reachable<T, E>(
    ips: &[IpAddr],
    mut dial: impl FnMut(IpAddr) -> Result<T, E>,
) -> Result<T, E> {
    let mut last = None;
    for ip in ips {
        match dial(*ip) {
            Ok(v) => return Ok(v),
            Err(e) => last = Some(e),
        }
    }
    // `checked_address` never returns an empty list (it refuses instead), and it is the only
    // producer, so the `expect` is unreachable rather than a case left unhandled.
    Err(last.expect("the permitted-address list is never empty"))
}

/// Whether `deciding` is an explicit, exact-host rule for `host` (not a wildcard/regex). With no
/// deciding rule — an allow-by-default verdict — it is not, so a private/loopback address is refused
/// (a denylist opens public egress, not the host's own internal services).
///
/// This is the *syntactic* half of the private-IP exception; [`opens_private_address`] is the whole
/// of it and is what the guard reads. The credential planes use this one directly, to ask whether an
/// injection's `to` rule names the host a response came from — a question about the rule's shape, not
/// about who wrote it.
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

    /// A destination that never answers gives the dial back on the deadline instead of holding the
    /// thread for the kernel's retry schedule.
    ///
    /// `192.0.2.0/24` is TEST-NET-1, reserved by RFC 5737 and routed nowhere, so the SYN goes
    /// unanswered rather than refused. Without a bound this call returns after the kernel has
    /// finished retrying, which is on the order of two minutes; the assertion is on the clock
    /// because that duration is the entire finding. A host that answers instantly with
    /// `EHOSTUNREACH` also satisfies it, which is correct: what must never happen is the wait.
    #[test]
    fn a_dial_to_a_blackholed_address_ends_on_its_deadline() {
        let start = std::time::Instant::now();
        let got = dial_bounded(
            IpAddr::from([192, 0, 2, 1]),
            443,
            std::time::Duration::from_millis(200),
        );
        let waited = start.elapsed();
        assert!(
            got.is_err(),
            "nothing may answer on a reserved address, so this must not connect"
        );
        assert!(
            waited < std::time::Duration::from_secs(5),
            "the dial waited {waited:?} for a deadline of 200ms, so it is not the deadline that \
             ended it"
        );
    }

    /// No synchronous plane opens an upstream connection without a deadline.
    ///
    /// The three of them each spelled `TcpStream::connect(..)`, whose only bound is the kernel's,
    /// while the asynchronous h2 plane wrapped its own in `tokio::time::timeout`. Counted rather
    /// than trusted, because the two forms look alike and the difference only shows against a
    /// destination that is deliberately silent.
    #[test]
    fn no_synchronous_plane_dials_without_a_deadline() {
        for (name, source) in [
            ("proxy/mod.rs", include_str!("mod.rs")),
            ("proxy/cleartext.rs", include_str!("cleartext.rs")),
            ("proxy/splice.rs", include_str!("splice.rs")),
        ] {
            let production = source
                .rsplit_once("#[cfg(test)]")
                .map_or(source, |(before, _)| before);
            assert_eq!(
                production.matches("TcpStream::connect(").count(),
                0,
                "{name} opens an upstream with no deadline — use `ssrf::dial_bounded`, which is \
                 the one definition of that dial"
            );
        }
    }
    use super::*;

    #[test]
    fn the_connect_boolean_and_the_reported_reason_are_one_decision() {
        // The proxy reads a boolean and `sbx test net` reads the reason; if they ever came from two
        // decisions the tester would mispredict exactly what it exists to predict. Pin them to the
        // same call across all three classes and both sides of the exact-host exception.
        //
        // Each case carries the verdict it *should* get, rather than asserting the boolean against
        // `ip_refusal(..).is_none()`: `ip_permitted` is defined as exactly that expression, so
        // comparing the two was a tautology that held whatever the classifier did — the shape of
        // test that cannot fail. Spelling the answer out means a change to `classify_ip` or to the
        // exact-host exception is caught here, and the two readings are still pinned together
        // because both are asserted per case.
        let exact = allowlist::classify("10.0.0.5").unwrap();
        let wild = allowlist::classify("re:.*").unwrap();
        for (ip, host, deciding, permitted) in [
            // Public: reachable however the rule is written.
            ("93.184.216.34", "93.184.216.34", Some(&exact), true),
            ("93.184.216.34", "93.184.216.34", Some(&wild), true),
            // Private: reachable only when the deciding rule names this exact host.
            ("10.0.0.5", "10.0.0.5", Some(&exact), true),
            ("10.0.0.5", "10.0.0.5", Some(&wild), false),
            // No deciding rule at all (an allow-by-default verdict) is not an exact host either.
            ("127.0.0.1", "127.0.0.1", None, false),
            // Blocked: never reachable, even named exactly.
            ("169.254.169.254", "169.254.169.254", Some(&exact), false),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(
                ip_permitted(ip, host, deciding),
                permitted,
                "the guard's boolean is wrong for {ip} via {deciding:?}"
            );
            assert_eq!(
                ip_refusal(ip, host, deciding).is_none(),
                permitted,
                "the reported reason disagrees with the boolean for {ip} via {deciding:?}"
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

    /// The private-address exception belongs to a rule the operator wrote, never to the always-on
    /// self-equip lane.
    ///
    /// `ip_refusal`'s contract names three shapes the exception excludes — `*.domain`, regex, and
    /// built-in — and the code implemented two. Six of the eight built-in entries are bare hosts, so
    /// they classify as `RuleKind::Host` and satisfied the exact-host test; the two `*.` entries are
    /// `Subdomain` and were excluded, which is what made the gap invisible. A cage with an *empty*
    /// allowlist therefore reached a private address for `github.com` whenever the host's own
    /// resolver said so — split-horizon DNS to an appliance on 10.x, a Pi-hole `address=` entry, an
    /// NXDOMAIN-hijacking resolver — with no rule of the user's authorising anything.
    ///
    /// The user-written arm is asserted in the same breath: the exception has to keep working for the
    /// deliberate internal target it exists for, or this would be satisfied by refusing everything.
    #[test]
    fn the_private_address_exception_is_not_granted_to_a_built_in_rule() {
        let private: IpAddr = "127.0.0.1".parse().unwrap();
        let public: IpAddr = "93.184.216.34".parse().unwrap();

        for builtin in super::super::builtin_allow_rules() {
            // The host each built-in entry names, read back off the rule so the two cannot drift.
            let RuleKind::Host(host, _) = &builtin.kind else {
                continue; // the `*.` entries are `Subdomain` and were never granted the exception
            };
            let host = host.clone();
            assert!(
                matches!(
                    ip_refusal(private, &host, Some(&builtin)),
                    Some(AddrRefusal::PrivateWithoutExactHost)
                ),
                "the built-in lane must not reach a private address for `{host}`"
            );
            assert!(
                ip_refusal(public, &host, Some(&builtin)).is_none(),
                "and it must still reach `{host}` on the public Internet"
            );
        }

        // A rule the user wrote for the same host keeps the exception — that is what it is for.
        let mine = allowlist::classify("github.com").unwrap();
        assert!(
            ip_refusal(private, "github.com", Some(&mine)).is_none(),
            "a rule naming the exact host is the deliberate internal target the exception exists for"
        );
        // ...and a wildcard still does not, so the built-in exclusion did not replace that one.
        let wild = allowlist::classify("*.github.com").unwrap();
        assert!(
            matches!(
                ip_refusal(private, "api.github.com", Some(&wild)),
                Some(AddrRefusal::PrivateWithoutExactHost)
            ),
            "a `*.domain` match is still an SSRF wildcard"
        );
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

        // IPv4-compatible `::a.b.c.d`, the one v4 spelling this function did not unwrap:
        // `::127.0.0.1` is not `::1`, not `fe80::/10` and not `fc00::/7`, so the v6 classifier
        // called it public while every other spelling of that address is refused.
        assert!(matches!(c("::127.0.0.1"), IpClass::Private));
        assert!(matches!(c("::169.254.169.254"), IpClass::Blocked));
        assert!(matches!(c("::10.0.0.1"), IpClass::Private));
        // ...and one that carries a genuinely public v4 still reads public, so the unwrap is not a
        // blanket refusal of the shape.
        assert!(matches!(c("::1.1.1.1"), IpClass::Public));
    }

    /// `::` and `::1` match the IPv4-compatible shape and must **not** be unwrapped: they denote
    /// the unspecified and loopback addresses themselves. The teeth are on `::1`. Unwrapping it
    /// yields `0.0.0.1`, which is not loopback, not private and not unspecified, so the v4
    /// classifier calls it `Public` — swapping `to_ipv4_mapped` for `to_ipv4` to close the
    /// compatible-form gap would have opened the loopback in the same edit, and both assertions
    /// below would read `Public`. `::` survives that swap by accident (`0.0.0.0` is unspecified on
    /// both sides), which is exactly why it cannot be the case the guard is trusted on.
    #[test]
    fn the_two_addresses_that_look_ipv4_compatible_keep_their_own_class() {
        let c = |s: &str| classify_ip(s.parse::<IpAddr>().unwrap());
        assert!(
            matches!(c("::1"), IpClass::Private),
            "the v6 loopback is private, not a compatible-form embedding of 0.0.0.1"
        );
        assert!(
            matches!(c("::"), IpClass::Blocked),
            "the unspecified address is blocked"
        );
        // The neighbour on either side of the carve-out is unwrapped normally, so the exclusion is
        // exactly two addresses wide and not a hole in the range.
        assert!(matches!(c("::2"), IpClass::Public));
    }

    /// The ranges IANA set aside for something other than the public Internet are not public
    /// addresses, and the classification is what `sbx test net` reads to predict a destination.
    ///
    /// They are `Private` rather than `Blocked` on purpose: a lab or a VPN does put them on a local
    /// interface, so a rule that names the host reaches them and a wildcard does not.
    ///
    /// Teeth: with them falling through to `Public`, every assertion below reads `Public`, and the
    /// tester tells an operator that `198.18.0.1` is reachable while the request dies at the dial.
    #[test]
    fn the_ranges_iana_set_aside_are_not_public_addresses() {
        let c = |s: &str| classify_ip(s.parse::<IpAddr>().unwrap());
        for set_aside in [
            "192.0.2.1",          // TEST-NET-1
            "198.51.100.7",       // TEST-NET-2
            "203.0.113.9",        // TEST-NET-3
            "198.18.0.1",         // RFC 2544 benchmarking, low half
            "198.19.255.254",     // ...and its high half
            "240.0.0.1",          // reserved
            "255.255.255.254",    // reserved, one below the broadcast address
            "2001:db8::1",        // the v6 documentation prefix
            "::ffff:203.0.113.9", // and a set-aside v4 wearing a v6 spelling
        ] {
            assert!(
                matches!(c(set_aside), IpClass::Private),
                "{set_aside} is not a public destination"
            );
        }
        // The broadcast address is in the last range and stays refused outright, because the
        // never-reachable test runs first.
        assert!(matches!(c("255.255.255.255"), IpClass::Blocked));
        // The neighbours of each range are ordinary public addresses and must stay that way.
        for public in [
            "198.17.255.255",
            "198.20.0.1",
            "192.0.3.1",
            "203.0.114.1",
            "2001:db9::1",
        ] {
            assert!(
                matches!(c(public), IpClass::Public),
                "{public} is an ordinary destination and must not be swept in"
            );
        }
        // 240.0.0.0/4 has no ordinary neighbour below it: 224.0.0.0/4 is multicast, so every
        // address just under the reserved range is already refused outright and the boundary
        // between the two cannot be observed from here. It is written as the range's own, from
        // RFC 1112, rather than as whatever number happens to be indistinguishable.
        assert!(matches!(c("239.255.255.254"), IpClass::Blocked));
    }
}
