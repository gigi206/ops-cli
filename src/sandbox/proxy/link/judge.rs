//! The supervisor's own answer to the question the proxy puts before every upstream connection: may
//! this request reach its host, at which addresses, and through which connection.
//!
//! The proxy decides every request against its policy, and once it runs apart it may be what an
//! attacker controls. So it does not resolve a name or open a connection itself: it asks. The judge
//! answers from the supervisor's own copy of everything that decision reads, through the same
//! functions the proxy decided with: the policy, decoded from the same bytes the proxy's is and
//! unioned with the built-in rules the same way; the `--session` overlay as the supervisor sent it;
//! the one-shot allows an operator gave to parked requests. An honest proxy therefore hears
//! the verdict it reached itself, and a compromised one gets no connection its policy would not
//! give. The bound is the host and port the policy admits, not the method or the path: those are
//! the proxy's to report, and a proxy that lies about them reaches only a host and port some request
//! to them could have reached. The host is taken only as the proxy's planes spell one
//! ([`is_request_host`]): no byte of it ends the host where a `re:` rule reads it while the
//! resolver reads on.
//!
//! Two questions, asked where the proxy used to do the work itself. A **check** replaces the
//! resolution and the address guard: it answers whether the request may connect, and keeps the
//! addresses it found. A **connect** replaces the dial: it judges again, dials the addresses the
//! check kept, and hands the connection over. Two, because a proxy does things between the two that
//! a request refused by the guard must never reach (it reads the body, asks a signer, learns the
//! credentials the request carries), and one connect in place of both would move those refusals
//! after them.

use super::Overlay;
use crate::allowlist::{Decision, EgressPolicy, L4Decision, Rule, is_request_host};
use crate::sandbox::locks::{locked, read_locked, write_locked};
use crate::sandbox::proxy::dns::{SharedResolver, caching_resolver};
use crate::sandbox::proxy::ssrf::{ConnectRefusal, dial_bounded, permitted};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// How long an operator's one-shot allow waits to be taken by the request it was given for, and
/// how long a check keeps what it found for the connects that follow it. Between the answer and the
/// dial a proxy may read a whole request body, which a slow client can take minutes to send; a
/// request that outlives this is refused rather than let through on an allow nobody is holding.
const GRANT_TTL: Duration = Duration::from_secs(10 * 60);

/// What the proxy asks about: the destination, and the request its decision was made for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Asked {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) plane: Plane,
}

/// Which of the policy's decisions the request was made under, with what that decision reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Plane {
    /// An inspected request, decided by [`EgressPolicy::explain`]: `method` as the decision read it
    /// (`WS` for an upgrade) and `path` unmasked, as it read it.
    Inspected { method: String, path: String },
    /// A cleartext `http://` request, decided by [`EgressPolicy::explain_clear`].
    Clear { method: String, path: String },
    /// A raw `tcp://` splice, decided by [`EgressPolicy::l4_decision`] from the host and port
    /// alone.
    Splice,
}

impl Asked {
    /// An inspected request to `host:port`.
    pub(crate) fn inspected(host: &str, port: u16, method: &str, path: &str) -> Self {
        Asked {
            host: host.to_string(),
            port,
            plane: Plane::Inspected {
                method: method.to_string(),
                path: path.to_string(),
            },
        }
    }

    /// A cleartext request to `host:port`.
    pub(crate) fn clear(host: &str, port: u16, method: &str, path: &str) -> Self {
        Asked {
            host: host.to_string(),
            port,
            plane: Plane::Clear {
                method: method.to_string(),
                path: path.to_string(),
            },
        }
    }

    /// A raw splice to `host:port`.
    pub(crate) fn splice(host: &str, port: u16) -> Self {
        Asked {
            host: host.to_string(),
            port,
            plane: Plane::Splice,
        }
    }
}

/// Where a request goes, and under which of the policy's decisions: what a connection has to share
/// with the check it names. Kept in place of the request itself, whose method and path the check no
/// longer needs once it is answered, so a record holds a name that resolved and not a path the
/// caller chose the length of.
struct Destination {
    host: String,
    port: u16,
    plane: std::mem::Discriminant<Plane>,
}

impl Destination {
    fn of(asked: &Asked) -> Self {
        Destination {
            host: asked.host.clone(),
            port: asked.port,
            plane: std::mem::discriminant(&asked.plane),
        }
    }

    /// Whether `asked` goes here under the same decision.
    fn holds(&self, asked: &Asked) -> bool {
        self.host == asked.host
            && self.port == asked.port
            && self.plane == std::mem::discriminant(&asked.plane)
    }
}

/// The supervisor's copy of what a proxy's decisions read, and the bound on how many of its
/// questions are answered at once.
pub(crate) struct Judge {
    /// The policy, decoded from the bytes the proxy's copy was decoded from and unioned with the
    /// built-in rules as the proxy's is.
    policy: EgressPolicy,
    /// The `--session` overlay as last sent to the proxy, and the version it was sent as. Noted
    /// before it is sent, so this copy may be ahead of the proxy's and never behind it.
    overlay: RwLock<(u64, Arc<Overlay>)>,
    /// The one-shot allows an operator gave to requests the proxy parked, not yet taken by a check.
    grants: Mutex<VecDeque<Grant>>,
    /// What each recent check found, for the connects that name it. Past [`Self::cap`] records
    /// the oldest one that holds no operator's allow is let go; one that holds an allow stays until
    /// it lapses, so the checks of other requests cannot take a request's allow away before its
    /// connection. Those are as many as an operator allowed within [`GRANT_TTL`].
    kept: Mutex<VecDeque<Kept>>,
    resolve: RwLock<SharedResolver>,
    /// How long one dial waits for its handshake.
    timeout: RwLock<Duration>,
    /// The most questions answered at once; one more is refused.
    cap: usize,
    /// The questions being answered now.
    serving: AtomicUsize,
    grant_ttl: Duration,
}

/// An operator's allow for a parked request to `host:port`.
struct Grant {
    host: String,
    port: u16,
    at: Instant,
}

/// What a check found: the addresses its host resolved to, and whether it took an operator's allow.
struct Kept {
    id: u64,
    destination: Destination,
    ips: Vec<IpAddr>,
    granted: bool,
    at: Instant,
}

/// A question being answered, counted against [`Judge::cap`] until it is dropped.
pub(crate) struct Serving(Arc<Judge>);

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.serving.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Judge {
    /// A judge over the policy `bytes` encode, with the resolver, the dial bound and the cap that
    /// policy sets: twice its connection bound.
    pub(crate) fn new(bytes: &[u8]) -> io::Result<Self> {
        let policy = crate::sandbox::proxy::union_with_builtin(EgressPolicy::decode(bytes)?);
        // Every request is resolved again, and a long build fetching one host thousands of times
        // would hit the resolver each time (and any hiccup fails a fetch). A short-TTL cache
        // resolves each host once and reuses it: `[network] dns_cache_ttl`, where `0` disables the
        // cache and an unset field takes the named default.
        let resolve = caching_resolver(
            policy
                .dns_cache_ttl()
                .unwrap_or(crate::allowlist::DEFAULT_DNS_CACHE_TTL),
        );
        // Twice the proxy's own connection bound: a connection of an honest proxy asks one question
        // at a time, and an HTTP/2 tunnel two (a stream's check beside another's connection), so an
        // honest proxy never meets this bound.
        let cap = policy
            .max_connections()
            .unwrap_or(crate::allowlist::DEFAULT_MAX_CONNECTIONS)
            .saturating_mul(2);
        Ok(Judge {
            policy,
            overlay: RwLock::new((0, Arc::new(Overlay::default()))),
            grants: Mutex::new(VecDeque::new()),
            kept: Mutex::new(VecDeque::new()),
            resolve: RwLock::new(Arc::from(resolve)),
            timeout: RwLock::new(crate::sandbox::proxy::ctx::UPSTREAM_TIMEOUT),
            cap,
            serving: AtomicUsize::new(0),
            grant_ttl: GRANT_TTL,
        })
    }

    /// The policy this judge decides with.
    pub(crate) fn policy(&self) -> &EgressPolicy {
        &self.policy
    }

    /// Note the overlay sent to the proxy as `version`, unless a later one already is.
    pub(crate) fn sent(&self, version: u64, overlay: &Overlay) {
        let mut current = write_locked(&self.overlay);
        if version > current.0 {
            *current = (version, Arc::new(overlay.clone()));
        }
    }

    /// Note an operator's allow for the request the proxy parked for `host:port`, for the check that
    /// request makes next. At most [`crate::sandbox::control::ASK_PENDING_CAP`] wait at once, the
    /// oldest let go first.
    pub(crate) fn grant(&self, host: &str, port: u16) {
        let mut grants = locked(&self.grants);
        grants.retain(|g| g.at.elapsed() < self.grant_ttl);
        if grants.len() >= crate::sandbox::control::ASK_PENDING_CAP {
            grants.pop_front();
        }
        grants.push_back(Grant {
            host: host.to_string(),
            port,
            at: Instant::now(),
        });
    }

    /// Count one more question being answered, or `None` when [`Self::cap`] already are.
    pub(crate) fn enter(self: &Arc<Self>) -> Option<Serving> {
        if self.serving.fetch_add(1, Ordering::SeqCst) >= self.cap {
            self.serving.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Serving(Arc::clone(self)))
    }

    /// Whether the request `asked` may connect: decided, resolved and guarded as the proxy would, the
    /// addresses kept under `id` for the connects that follow. An operator's allow waiting for this
    /// destination is taken here when the policy leaves the request to one.
    pub(super) fn check(&self, id: u64, asked: &Asked) -> Result<(), ConnectRefusal> {
        let mut granted = false;
        let deciding = self.decide(asked, || {
            granted = self.take_grant(&asked.host, asked.port);
            granted
        })?;
        let ips = self.resolved(asked)?;
        permitted(&ips, &asked.host, deciding.as_ref())?;
        let mut kept = locked(&self.kept);
        kept.retain(|k| k.at.elapsed() < self.grant_ttl);
        if kept.len() >= self.cap
            && let Some(oldest) = kept.iter().position(|k| !k.granted)
        {
            kept.remove(oldest);
        }
        kept.push_back(Kept {
            id,
            destination: Destination::of(asked),
            ips,
            granted,
            at: Instant::now(),
        });
        Ok(())
    }

    /// A connection for the request `asked`: judged again, the addresses the check named `check`
    /// kept (resolved again when it kept none for this destination) guarded again, and dialled in
    /// order from the `from`th. The connection, the position it was reached at, and how many
    /// addresses there are, so a proxy whose handshake fails on one can ask for the next.
    pub(super) fn connect(
        &self,
        asked: &Asked,
        check: Option<u64>,
        from: usize,
    ) -> Result<(TcpStream, usize, usize), ConnectRefusal> {
        let kept = check.and_then(|id| {
            locked(&self.kept)
                .iter()
                .find(|k| {
                    k.id == id && k.destination.holds(asked) && k.at.elapsed() < self.grant_ttl
                })
                .map(|k| (k.ips.clone(), k.granted))
        });
        let granted = kept.as_ref().is_some_and(|(_, granted)| *granted);
        let deciding = self.decide(asked, || granted)?;
        let ips = match kept {
            Some((ips, _)) => ips,
            None => self.resolved(asked)?,
        };
        let ips = permitted(&ips, &asked.host, deciding.as_ref())?;
        let timeout = *read_locked(&self.timeout);
        // Walked in order from `from`. Every address on the list passed the guard just above, so
        // moving on from one that will not connect cannot reach one it refused: the walk is not a
        // second chance at the same question.
        for (at, ip) in ips.iter().enumerate().skip(from) {
            if let Ok(stream) = dial_bounded(*ip, asked.port, timeout) {
                return Ok((stream, at, ips.len()));
            }
        }
        Err(ConnectRefusal::Unreachable)
    }

    /// The rule that decides `asked` under this judge's policy and overlay (the proxy's own
    /// decision, through the same functions), or a refusal. A request the policy leaves to an
    /// operator is decided by `granted`, which says whether one allowed it. A host no plane of the
    /// proxy would hand on is refused before any rule reads it: a check and a connect both come
    /// here before they resolve.
    fn decide(
        &self,
        asked: &Asked,
        granted: impl FnOnce() -> bool,
    ) -> Result<Option<Rule>, ConnectRefusal> {
        if !is_request_host(&asked.host) {
            return Err(ConnectRefusal::Supervisor);
        }
        let overlay = Arc::clone(&read_locked(&self.overlay).1);
        let policy = crate::sandbox::proxy::ctx::folded(&self.policy, &overlay);
        let (host, port) = (asked.host.as_str(), asked.port);
        match &asked.plane {
            Plane::Inspected { method, path } => match policy.explain(host, port, path, method) {
                Decision::AllowedBy(rule) => Ok(Some(rule.clone())),
                Decision::AllowedDefault => Ok(None),
                // The rule the proxy decides with once an operator allowed the request it parked.
                Decision::Ask if granted() => {
                    Ok(Some(crate::allowlist::host_port_rule(host, port)))
                }
                Decision::Ask | Decision::DeniedBy(_) | Decision::DeniedDefault => {
                    Err(ConnectRefusal::Supervisor)
                }
            },
            Plane::Clear { method, path } => match policy.explain_clear(host, port, path, method) {
                Decision::AllowedBy(rule) => Ok(Some(rule.clone())),
                _ => Err(ConnectRefusal::Supervisor),
            },
            Plane::Splice => match policy.l4_decision(host, port) {
                L4Decision::Splice(rule) => Ok(Some(rule.clone())),
                _ => Err(ConnectRefusal::Supervisor),
            },
        }
    }

    /// Take the operator's allow waiting for `host:port`, if one is.
    fn take_grant(&self, host: &str, port: u16) -> bool {
        let mut grants = locked(&self.grants);
        grants.retain(|g| g.at.elapsed() < self.grant_ttl);
        let found = grants.iter().position(|g| g.host == host && g.port == port);
        found.map(|at| grants.remove(at)).is_some()
    }

    /// The addresses `asked`'s host resolves to. A splice may name an address outright, which is
    /// then the only one; every other plane hands the name to the resolver, a literal included, as
    /// the proxy did.
    fn resolved(&self, asked: &Asked) -> Result<Vec<IpAddr>, ConnectRefusal> {
        if matches!(asked.plane, Plane::Splice)
            && let Ok(ip) = asked.host.parse::<IpAddr>()
        {
            return Ok(vec![ip]);
        }
        let resolve = Arc::clone(&*read_locked(&self.resolve));
        resolve(&asked.host).map_err(|_| ConnectRefusal::Dns)
    }
}

#[cfg(test)]
impl Judge {
    /// Resolve with `resolve` instead, so a test can map a host to a fixed address.
    pub(crate) fn set_resolver(&self, resolve: SharedResolver) {
        *write_locked(&self.resolve) = resolve;
    }

    /// Bound a dial by `timeout` instead.
    pub(crate) fn set_timeout(&self, timeout: Duration) {
        *write_locked(&self.timeout) = timeout;
    }

    /// Answer at most `cap` questions at once.
    pub(crate) fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap;
        self
    }

    /// Let an operator's allow, and what a check kept, lapse after `ttl`.
    pub(crate) fn with_grant_ttl(mut self, ttl: Duration) -> Self {
        self.grant_ttl = ttl;
        self
    }
}

#[cfg(test)]
impl Judge {
    /// Whether this judge admits the request `asked`, with no operator's allow held for it: what a
    /// test outside the proxy asks of the supervisor's copy of the policy.
    pub(crate) fn admits(&self, asked: &Asked) -> bool {
        self.decide(asked, || false).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{DefaultAction, RuleKind, classify};
    use std::net::TcpListener;
    use std::sync::atomic::AtomicUsize;

    /// A judge over a policy allowing `entries`, deciding the rest as `default` does, resolving every
    /// name to `ips`.
    fn judge(entries: &[&str], default: DefaultAction, ips: Vec<IpAddr>) -> Judge {
        let policy = EgressPolicy::new(
            entries.iter().map(|e| classify(e).unwrap()).collect(),
            vec![],
        )
        .with_default(default);
        let judge = Judge::new(&policy.encode().unwrap()).unwrap();
        judge.set_resolver(Arc::new(move |_| Ok(ips.clone())));
        judge
    }

    /// A listener on a loopback address, and the port it took.
    fn listening(ip: [u8; 4]) -> (TcpListener, u16) {
        let listener = TcpListener::bind((IpAddr::from(ip), 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    const LOOPBACK: [u8; 4] = [127, 0, 0, 1];

    /// An operator's allow is taken by the one check the request it was given for makes, and lasts
    /// for every connection that check names: the request's connection, and the one it asks for
    /// again when a handshake fails or a reused connection turns out dead. A second check finds none.
    #[test]
    fn an_operators_allow_is_taken_by_one_check_and_lasts_for_its_connections() {
        let (_listener, port) = listening(LOOPBACK);
        let judge = judge(&[], DefaultAction::Ask, vec![IpAddr::from(LOOPBACK)]);
        let asked = Asked::inspected("api.test", port, "GET", "/");
        judge.grant("api.test", port);
        assert_eq!(judge.check(1, &asked), Ok(()));
        for _ in 0..2 {
            let (_, at, of) = judge.connect(&asked, Some(1), 0).unwrap();
            assert_eq!((at, of), (0, 1));
        }
        assert_eq!(
            judge.check(2, &asked),
            Err(ConnectRefusal::Supervisor),
            "the allow was one request's"
        );
    }

    /// An operator's allow outlives the checks of other requests: however many come between a
    /// request's check and its connection, the record holding the allow is not the one let go.
    #[test]
    fn an_operators_allow_outlives_the_checks_of_other_requests() {
        let (_listener, port) = listening(LOOPBACK);
        let judge = judge(
            &["other.test:*"],
            DefaultAction::Ask,
            vec![IpAddr::from(LOOPBACK)],
        )
        .with_cap(2);
        let asked = Asked::inspected("api.test", port, "GET", "/");
        judge.grant("api.test", port);
        assert_eq!(judge.check(1, &asked), Ok(()));
        for id in 2..6 {
            assert_eq!(
                judge.check(id, &Asked::inspected("other.test", port, "GET", "/")),
                Ok(())
            );
        }
        assert!(judge.connect(&asked, Some(1), 0).is_ok());
    }

    /// A connection takes from the check it names only what that check was for: named by a
    /// connection to another host, port or plane, the check gives neither the operator's allow it
    /// took nor the addresses it found, which are resolved again.
    #[test]
    fn a_check_gives_nothing_to_a_connection_for_another_destination() {
        let (_listener, port) = listening(LOOPBACK);
        let judge_asking = judge(&[], DefaultAction::Ask, vec![IpAddr::from(LOOPBACK)]);
        judge_asking.grant("api.test", port);
        let asked = Asked::inspected("api.test", port, "GET", "/");
        assert_eq!(judge_asking.check(1, &asked), Ok(()));
        assert_eq!(
            judge_asking
                .connect(
                    &Asked::inspected("other.test", port, "GET", "/"),
                    Some(1),
                    0
                )
                .map(|_| ()),
            Err(ConnectRefusal::Supervisor),
            "an allow taken for one host is not another's"
        );

        let splice = format!("tcp://api.test:{port}");
        // Named exactly, so the loopback address each resolves to is one it may reach.
        let judge = judge(
            &["api.test:*", "other.test:*", &splice],
            DefaultAction::Deny,
            vec![],
        );
        let resolved = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&resolved);
        judge.set_resolver(Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(vec![IpAddr::from(LOOPBACK)])
        }));
        assert_eq!(judge.check(1, &asked), Ok(()));
        for other in [
            Asked::inspected("other.test", port, "GET", "/"),
            Asked::inspected("api.test", port.wrapping_add(1), "GET", "/"),
            Asked::splice("api.test", port),
        ] {
            let before = resolved.load(Ordering::SeqCst);
            let _ = judge.connect(&other, Some(1), 0);
            assert_eq!(
                resolved.load(Ordering::SeqCst),
                before + 1,
                "addresses found for one destination are not another's: {other:?}"
            );
        }
    }

    /// A request left to an operator that no operator allowed is refused, checked or not.
    #[test]
    fn a_request_left_to_an_operator_that_none_allowed_is_refused() {
        let judge = judge(&[], DefaultAction::Ask, vec![IpAddr::from(LOOPBACK)]);
        let asked = Asked::inspected("api.test", 443, "GET", "/");
        judge.grant("other.test", 443);
        judge.grant("api.test", 8443);
        assert_eq!(judge.check(1, &asked), Err(ConnectRefusal::Supervisor));
        assert_eq!(
            judge.connect(&asked, None, 0).map(|_| ()),
            Err(ConnectRefusal::Supervisor)
        );
    }

    /// An allow nobody took lapses, and so does what a check kept: a connection asked for past it is
    /// judged without the allow.
    #[test]
    fn an_allow_and_what_a_check_kept_lapse() {
        let (_listener, port) = listening(LOOPBACK);
        let ttl = Duration::from_secs(1);
        let judge =
            judge(&[], DefaultAction::Ask, vec![IpAddr::from(LOOPBACK)]).with_grant_ttl(ttl);
        let asked = Asked::inspected("api.test", port, "GET", "/");

        judge.grant("api.test", port);
        std::thread::sleep(ttl + Duration::from_millis(200));
        assert_eq!(
            judge.check(1, &asked),
            Err(ConnectRefusal::Supervisor),
            "an allow nobody took in time"
        );

        judge.grant("api.test", port);
        assert_eq!(judge.check(2, &asked), Ok(()));
        std::thread::sleep(ttl + Duration::from_millis(200));
        assert_eq!(
            judge.connect(&asked, Some(2), 0).map(|_| ()),
            Err(ConnectRefusal::Supervisor),
            "a check whose record lapsed carries no allow"
        );
    }

    /// The private-address exception is the proxy's: a rule somebody wrote naming the host opens a
    /// private address, a built-in rule naming it does not.
    #[test]
    fn a_private_address_opens_to_a_written_rule_and_not_to_a_built_in_one() {
        let private = vec![IpAddr::from([10, 0, 0, 7])];
        let github = Asked::inspected("github.com", 443, "GET", "/");
        let builtin_only = judge(&[], DefaultAction::Deny, private.clone());
        assert_eq!(builtin_only.check(1, &github), Err(ConnectRefusal::Ssrf));
        let written = judge(&["github.com"], DefaultAction::Deny, private);
        assert_eq!(written.check(1, &github), Ok(()));
    }

    /// A check resolves and guards and dials nothing: the connection is the connect's.
    #[test]
    fn a_check_opens_no_connection() {
        let (listener, port) = listening(LOOPBACK);
        listener.set_nonblocking(true).unwrap();
        let judge = judge(
            &["api.test:*"],
            DefaultAction::Deny,
            vec![IpAddr::from(LOOPBACK)],
        );
        assert_eq!(
            judge.check(1, &Asked::inspected("api.test", port, "GET", "/")),
            Ok(())
        );
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "nothing connected"
        );
    }

    /// A request resolves its host once: at its check. Its connections, the first and any asked for
    /// again, dial what the check kept.
    #[test]
    fn a_request_resolves_its_host_once() {
        let (_listener, port) = listening(LOOPBACK);
        let judge = judge(&["api.test:*"], DefaultAction::Deny, vec![]);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        judge.set_resolver(Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(vec![IpAddr::from(LOOPBACK)])
        }));
        let asked = Asked::inspected("api.test", port, "GET", "/");
        judge.check(7, &asked).unwrap();
        judge.connect(&asked, Some(7), 0).unwrap();
        judge.connect(&asked, Some(7), 0).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // A connect naming no check of this destination resolves for itself.
        judge
            .connect(&Asked::inspected("api.test", port, "POST", "/"), Some(8), 0)
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A connection is asked for from a position, and says where it was reached: past an address
    /// that refuses, at the next; from past the last, nowhere.
    #[test]
    fn a_connection_starts_from_the_position_asked_and_says_where_it_was_reached() {
        let (_listener, port) = listening(LOOPBACK);
        // 127.0.0.2 is loopback with nothing listening on this port: the dial is refused at once.
        let judge = judge(
            &["api.test:*"],
            DefaultAction::Deny,
            vec![IpAddr::from([127, 0, 0, 2]), IpAddr::from(LOOPBACK)],
        );
        let asked = Asked::inspected("api.test", port, "GET", "/");
        judge.check(1, &asked).unwrap();
        for from in [0, 1] {
            let (_, at, of) = judge.connect(&asked, Some(1), from).unwrap();
            assert_eq!((at, of), (1, 2), "from {from}");
        }
        assert_eq!(
            judge.connect(&asked, Some(1), 2).map(|_| ()),
            Err(ConnectRefusal::Unreachable)
        );
    }

    /// A splice may name an address outright, which is then dialled as it is; every other plane
    /// hands a literal to the resolver, as the proxy did.
    #[test]
    fn a_splice_to_an_address_resolves_nothing() {
        let (_listener, port) = listening(LOOPBACK);
        let judge = judge(
            &[&format!("tcp://127.0.0.1:{port}")],
            DefaultAction::Deny,
            vec![],
        );
        judge.set_resolver(Arc::new(|_| Err(io::Error::other("no resolver here"))));
        assert!(
            judge
                .connect(&Asked::splice("127.0.0.1", port), None, 0)
                .is_ok()
        );
    }

    /// The judge answers twice the policy's connection bound at once: a connection of an honest
    /// proxy asks one question at a time and an HTTP/2 tunnel two, so an honest proxy never meets
    /// it.
    #[test]
    fn the_cap_is_twice_the_connection_bound() {
        let policy = EgressPolicy::default().with_max_connections(Some(3));
        let judge = Arc::new(Judge::new(&policy.encode().unwrap()).unwrap());
        let held: Vec<Serving> = (0..6).map(|_| judge.enter().expect("room")).collect();
        assert!(judge.enter().is_none(), "no room past twice the bound");
        drop(held);
    }

    /// No more questions are answered at once than the cap, and one that ends makes room.
    #[test]
    fn no_more_questions_than_the_cap_are_answered_at_once() {
        let judge = Arc::new(judge(&[], DefaultAction::Deny, vec![]).with_cap(2));
        let first = judge.enter().expect("room for one");
        let second = judge.enter().expect("room for two");
        assert!(judge.enter().is_none(), "no room for a third");
        drop(first);
        assert!(judge.enter().is_some(), "an answered question makes room");
        drop(second);
    }

    /// A host no plane of the proxy hands on is refused before any rule reads it or any resolver
    /// sees it, by a check and by a connect that names none.
    ///
    /// Under `re:^https://allowed\.test/`, the host `allowed.test/.attacker.test` rebuilds a URL
    /// the pattern matches, while a resolver that takes the whole string asks for a name in the
    /// zone `attacker.test`. Each byte tried is one that splits the two readings; the host rule and
    /// the subdomain rule are there so the refusal is seen whatever rule would have admitted it.
    #[test]
    fn a_host_no_plane_hands_on_is_refused_before_it_is_decided_or_resolved() {
        // A judge that records every name it resolves, to an address routed nowhere which the
        // guard opens to an exact rule alone: a host let through by mistake fails without a packet
        // leaving the machine.
        let recording = |rules: &[&str]| {
            let resolved = Arc::new(Mutex::new(Vec::<String>::new()));
            let seen = Arc::clone(&resolved);
            let judge = judge(rules, DefaultAction::Deny, vec![]);
            judge.set_timeout(Duration::from_millis(50));
            judge.set_resolver(Arc::new(move |host: &str| {
                locked(&seen).push(host.to_string());
                Ok(vec![IpAddr::from([192, 0, 2, 1])])
            }));
            (judge, resolved)
        };
        let (judge, resolved) = recording(&[
            "re:^https://allowed\\.test/",
            "allowed.test",
            "*.allowed.test",
        ]);
        let mut refused: Vec<String> = ["ALLOWED.test", "allowed.test."]
            .iter()
            .map(|h| h.to_string())
            .collect();
        for byte in ["/", "?", "#", "@", ":", "%", " ", "\\"] {
            refused.push(format!("allowed.test{byte}.attacker.test"));
            refused.push(format!("attacker.test{byte}.allowed.test"));
        }
        for host in &refused {
            let asked = Asked::inspected(host, 443, "GET", "/");
            assert_eq!(
                judge.check(1, &asked),
                Err(ConnectRefusal::Supervisor),
                "{host:?}"
            );
            assert!(
                matches!(
                    judge.connect(&asked, None, 0),
                    Err(ConnectRefusal::Supervisor)
                ),
                "{host:?}"
            );
        }
        let so_far = locked(&resolved).clone();
        assert!(so_far.is_empty(), "resolved: {so_far:?}");

        // What the rules admit spelled as a host still passes, underscore included.
        for host in ["allowed.test", "foo_bar.allowed.test"] {
            assert!(
                judge.admits(&Asked::inspected(host, 443, "GET", "/")),
                "{host:?}"
            );
        }
        // And the name resolved is the one decided.
        let (exact, resolved) = recording(&["allowed.test"]);
        exact
            .check(2, &Asked::inspected("allowed.test", 443, "GET", "/"))
            .unwrap();
        assert_eq!(*locked(&resolved), ["allowed.test"]);
    }

    /// A name that ends in a number is refused before any rule reads it: a rule would read a name
    /// that an address rule never matches, and the resolver the address it spells.
    #[test]
    fn a_name_that_ends_in_a_number_is_refused_before_an_address_rule_can_miss_it() {
        let policy = EgressPolicy::new(vec![], vec![classify("1.1.1.1").unwrap()])
            .with_default(DefaultAction::Allow);
        let judge = Judge::new(&policy.encode().unwrap()).unwrap();
        let resolved = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&resolved);
        // An address the guard refuses to a request no exact rule decides: a host let through by
        // mistake fails without a packet leaving the machine.
        judge.set_resolver(Arc::new(move |host: &str| {
            locked(&seen).push(host.to_string());
            Ok(vec![IpAddr::from([192, 0, 2, 1])])
        }));
        for host in [
            "1.1.1.1",
            "0x01010101",
            "16843009",
            "1.1.257",
            "01.01.01.01",
        ] {
            let asked = Asked::inspected(host, 443, "GET", "/");
            assert_eq!(
                judge.check(1, &asked),
                Err(ConnectRefusal::Supervisor),
                "{host:?}"
            );
        }
        let so_far = locked(&resolved).clone();
        assert!(so_far.is_empty(), "resolved: {so_far:?}");
    }

    /// An IPv6 address that embeds an IPv4 is refused before any rule reads it: an address rule
    /// would compare it as IPv6, and the host's stack dial the IPv4 it carries.
    #[test]
    fn an_ipv6_spelling_of_an_ipv4_is_refused_before_an_address_rule_can_miss_it() {
        let policy = EgressPolicy::new(vec![], vec![classify("1.1.1.1").unwrap()])
            .with_default(DefaultAction::Allow);
        let judge = Judge::new(&policy.encode().unwrap()).unwrap();
        let resolved = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = Arc::clone(&resolved);
        // An address the guard refuses to a request no exact rule decides: a host let through by
        // mistake fails without a packet leaving the machine.
        judge.set_resolver(Arc::new(move |host: &str| {
            locked(&seen).push(host.to_string());
            Ok(vec![IpAddr::from([192, 0, 2, 1])])
        }));
        for host in ["::ffff:1.1.1.1", "64:ff9b::101:101", "2002:101:101::"] {
            let asked = Asked::inspected(host, 443, "GET", "/");
            assert_eq!(
                judge.check(1, &asked),
                Err(ConnectRefusal::Supervisor),
                "{host:?}"
            );
        }
        let so_far = locked(&resolved).clone();
        assert!(so_far.is_empty(), "resolved: {so_far:?}");
    }

    /// The judge reaches the verdict the proxy reaches, deciding rule and its flags included, on
    /// every shipped policy, for requests to the hosts it names and to the built-in ones: the two
    /// copies are decoded from the same bytes and unioned the same way, and a copy that is not
    /// (the union left out) is what this catches.
    #[test]
    fn the_judge_reaches_the_proxys_verdict_on_every_shipped_policy() {
        use crate::sandbox::proxy::{AskPosture, ProxyCtx, decide_https};
        type Verdict = Option<Option<(Rule, bool, Option<String>)>>;
        let flagged = |rule: Option<&Rule>| rule.map(|r| (r.clone(), r.builtin, r.group.clone()));
        let (mut compared, mut admitted_by_builtin) = (0usize, 0usize);
        for (name, policy) in crate::config::catalogue_tests::shipped_egress_policies() {
            let judge = Judge::new(&policy.encode().unwrap()).unwrap();
            let ctx = ProxyCtx::new(
                Arc::new(crate::sandbox::proxy::Ca::ephemeral().unwrap()),
                policy.clone(),
            )
            .unwrap();
            let mut hosts: Vec<String> = vec!["unlisted.example".into()];
            for rule in ctx
                .policy
                .allow_rules()
                .iter()
                .chain(ctx.policy.deny_rules())
            {
                match &rule.kind {
                    RuleKind::Host(host, _) => hosts.push(host.clone()),
                    RuleKind::Subdomain(domain, _) => hosts.push(format!("any.{domain}")),
                    RuleKind::Url { host, .. } => hosts.push(host.clone()),
                    RuleKind::Ip(ip, _) => hosts.push(ip.to_string()),
                    RuleKind::Regex { .. } => {}
                }
            }
            for host in &hosts {
                for port in [443, 80, 22, 8443] {
                    let questions = [
                        Asked::inspected(host, port, "GET", "/"),
                        Asked::inspected(host, port, "POST", "/v1/messages"),
                        Asked::inspected(host, port, "WS", "/"),
                        Asked::clear(host, port, "GET", "/"),
                        Asked::splice(host, port),
                    ];
                    for asked in questions {
                        let effective = crate::sandbox::proxy::ctx::effective_policy(&ctx);
                        let proxy: Verdict = match &asked.plane {
                            Plane::Inspected { method, path } => decide_https(
                                &ctx,
                                host,
                                port,
                                path,
                                method,
                                AskPosture::RefuseUnsupported,
                            )
                            .ok()
                            .map(|rule| flagged(rule.as_ref())),
                            Plane::Clear { method, path } => {
                                match effective.explain_clear(host, port, path, method) {
                                    Decision::AllowedBy(rule) => Some(flagged(Some(rule))),
                                    _ => None,
                                }
                            }
                            Plane::Splice => match effective.l4_decision(host, port) {
                                L4Decision::Splice(rule) => Some(flagged(Some(rule))),
                                _ => None,
                            },
                        };
                        let judged: Verdict = judge
                            .decide(&asked, || false)
                            .ok()
                            .map(|rule| flagged(rule.as_ref()));
                        assert_eq!(proxy, judged, "{name}: {asked:?}");
                        compared += 1;
                        if matches!(&judged, Some(Some((_, true, _)))) {
                            admitted_by_builtin += 1;
                        }
                    }
                }
            }
        }
        assert!(compared > 10_000, "only {compared} requests were compared");
        assert!(
            admitted_by_builtin > 0,
            "no request was admitted by a built-in rule, so the union went unwatched"
        );
    }
}
