//! Host-side DNS resolution for the proxy, with a short-TTL cache.
//!
//! The cage resolves nothing itself (it lives in an empty netns); every name is resolved here, on
//! the host. The resolver is injectable so tests can map a name to a fixed address deterministically,
//! and wrapped in a small cache so a proxy fronting a long `nix`/flake build does not re-resolve the
//! same host thousands of times.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::sandbox::locks::locked;

/// A host name resolver, injectable so tests can map a name to a fixed address deterministically.
pub(super) type Resolver = Box<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

/// A [`Resolver`] held where more than one side resolves with it: the one a test injects reaches the
/// supervisor, which resolves for every connection it opens, and the proxy's HTTP/2 plane.
pub(super) type SharedResolver = Arc<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

fn default_resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    // the port is immaterial to name resolution; 443 is a placeholder so `to_socket_addrs` runs
    Ok((host, 443u16)
        .to_socket_addrs()?
        .map(|sa| sa.ip())
        .collect())
}

/// How long a caller waits for a name before the resolution is given up on.
///
/// Above any healthy lookup and below what a host resolver left to its own devices can take: glibc
/// tries each nameserver in turn with its own timeout and its own retry count, so a
/// `/etc/resolv.conf` naming several unreachable servers reaches tens of seconds before it answers
/// at all. The proxy is what the cage waits on, so that number becomes the cage's.
const RESOLVE_DEADLINE: Duration = Duration::from_secs(10);

/// What a lookup leaves for the callers waiting on it. `io::Error` is not `Clone` and one answer is
/// read by every caller that joined the lookup, so an error travels as its kind and its text.
type Answer = Result<Vec<IpAddr>, (io::ErrorKind, String)>;

/// One name being looked up, shared by every caller that asks for it while the lookup runs.
type InFlight = Arc<(Mutex<Option<Answer>>, Condvar)>;

/// Name lookups under a deadline: one per name at a time, and at most `cap` at once.
///
/// `getaddrinfo` is a blocking call with no cancellation and no timeout of its own. Run on the
/// connection's thread, a resolver that accepts queries and never answers pinned that thread for its
/// whole libc timeout, and on the HTTP/2 plane that thread is the tunnel's runtime — so every stream
/// multiplexed onto it waited for a name only one of them had asked for. Each lookup therefore runs
/// on a thread of its own, and the caller waits at most `deadline` for it.
///
/// The deadline frees the *caller*, not the work: the lookup thread stays until libc returns. Two
/// bounds keep those threads from piling up while a resolver hangs. A caller asking for a name
/// already being looked up joins that lookup instead of starting another, so a client that retries
/// a failing name costs no new thread. And no more than `cap` names are in flight at once: past it a
/// lookup is refused at once rather than queued, which turns a flood of invented names into refused
/// connections instead of a thread per name.
///
/// The table and the answer slots recover from a poisoned lock ([`locked`]): their mutations are
/// single calls with nothing that can panic under them, and a lookup that refused to hand out its
/// table would leave every caller of every name waiting for an answer that cannot arrive.
struct Lookups<F> {
    resolve: Arc<F>,
    in_flight: Arc<Mutex<HashMap<String, InFlight>>>,
    cap: usize,
    deadline: Duration,
    /// How a lookup gets its thread: [`spawn_lookup`], replaced in tests to stand for a host that
    /// has no thread to give.
    spawn: fn(Box<dyn FnOnce() + Send>) -> io::Result<()>,
}

/// Start one lookup on a thread of its own.
fn spawn_lookup(work: Box<dyn FnOnce() + Send>) -> io::Result<()> {
    std::thread::Builder::new()
        .name("sbx-dns".to_string())
        .spawn(work)
        .map(drop)
}

impl<F> Lookups<F>
where
    F: Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
{
    fn new(resolve: F, cap: usize, deadline: Duration) -> Self {
        Lookups {
            resolve: Arc::new(resolve),
            in_flight: Arc::default(),
            cap,
            deadline,
            spawn: spawn_lookup,
        }
    }

    /// Resolve `host`, joining the lookup already in flight for it if there is one.
    fn lookup(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let slot = {
            let mut table = locked(&self.in_flight);
            match table.get(host) {
                Some(slot) => Arc::clone(slot),
                None => {
                    if table.len() >= self.cap {
                        return Err(io::Error::other(format!(
                            "resolving `{host}` was refused: {} lookups are already in flight",
                            self.cap
                        )));
                    }
                    let slot = InFlight::default();
                    let (name, mine, in_flight) = (
                        host.to_string(),
                        Arc::clone(&slot),
                        Arc::clone(&self.in_flight),
                    );
                    let resolve = Arc::clone(&self.resolve);
                    // The table stays locked across the spawn, so the lookup cannot settle and
                    // remove its entry before the entry is there. Its `Settle` is built inside the
                    // thread, never before: a spawn that fails drops the closure on this thread,
                    // which holds the table, and a `Settle` dropped here would lock it again.
                    (self.spawn)(Box::new(move || {
                        let mut settle = Settle {
                            name,
                            slot: mine,
                            in_flight,
                            answer: None,
                        };
                        settle.answer = Some(match resolve(&settle.name) {
                            Ok(ips) if ips.is_empty() => Err((
                                io::ErrorKind::NotFound,
                                format!("`{}` resolved to no address", settle.name),
                            )),
                            Ok(ips) => Ok(ips),
                            Err(e) => Err((e.kind(), e.to_string())),
                        });
                    }))
                    .map_err(|e| {
                        io::Error::new(
                            e.kind(),
                            format!("resolving `{host}` could not start a lookup: {e}"),
                        )
                    })?;
                    table.insert(host.to_string(), Arc::clone(&slot));
                    slot
                }
            }
        };
        let (answer, ready) = &*slot;
        let (answer, _) = ready
            .wait_timeout_while(locked(answer), self.deadline, |a| a.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &*answer {
            Some(Ok(ips)) => Ok(ips.clone()),
            Some(Err((kind, text))) => Err(io::Error::new(*kind, text.clone())),
            None => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "resolving `{host}` took longer than {}s",
                    self.deadline.as_secs()
                ),
            )),
        }
    }
}

/// The end of one lookup, run when its thread ends however it ends: the answer is published to the
/// callers waiting on it and the name leaves the table. A lookup that panicked publishes an error
/// rather than leaving its name in flight for good, where every later caller would wait out the
/// deadline on it and it would hold one of the `cap` places forever.
struct Settle {
    name: String,
    slot: InFlight,
    in_flight: Arc<Mutex<HashMap<String, InFlight>>>,
    answer: Option<Answer>,
}

impl Drop for Settle {
    fn drop(&mut self) {
        let answer = self.answer.take().unwrap_or_else(|| {
            Err((
                io::ErrorKind::Other,
                format!("the lookup for `{}` ended without an answer", self.name),
            ))
        });
        let (stored, ready) = &*self.slot;
        *locked(stored) = Some(answer);
        ready.notify_all();
        let mut table = locked(&self.in_flight);
        if table
            .get(&self.name)
            .is_some_and(|s| Arc::ptr_eq(s, &self.slot))
        {
            table.remove(&self.name);
        }
    }
}

/// The form a host takes as a lookup and a cache key: lowercase and without trailing dots, so
/// `Example.COM.` and `example.com` are one entry. The same spelling `canonical_host` in the
/// allowlist gives the host the proxy connects to, so a name that reaches here through the proxy
/// is already in it. Refused when it
/// cannot be a name at all — empty, longer than the 253 bytes DNS allows, or carrying whitespace or
/// a control byte — before it reaches `getaddrinfo` or an error message.
fn lookup_name(host: &str) -> io::Result<String> {
    let name = host.trim_end_matches('.');
    if name.is_empty()
        || name.len() > 253
        || name.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a host name a lookup can take (empty, over 253 bytes, or with whitespace or a \
             control character)",
        ));
    }
    Ok(name.to_ascii_lowercase())
}

/// A [`Resolver`] wrapping [`default_resolve`] with a short-TTL cache — the resolution resilience a
/// proxy fronting a long `nix`/flake build needs. A build fetches from one host (`cache.nixos.org`)
/// thousands of times; re-resolving per request wastes lookups and turns any single resolver hiccup
/// into a failed fetch. The cache resolves each host **once** and reuses the address for `ttl` (a
/// `Duration::ZERO` ttl disables it, resolving every request). Only successful, non-empty resolutions
/// are cached (a failure is never cached, so the client's own retry re-resolves). A transient failure
/// is not retried here: the client (nix/git/curl) already retries the whole request, which re-triggers
/// this resolution, so a proxy-level retry would be redundant. It holds at most
/// [`DNS_CACHE_CAP`] hosts. Each lookup runs under [`RESOLVE_DEADLINE`], joined by every caller of
/// the same name, with at most `cap` names in flight at once ([`Lookups`]).
pub(super) fn caching_resolver(ttl: Duration, cap: usize) -> Resolver {
    let lookups = Lookups::new(default_resolve, cap, RESOLVE_DEADLINE);
    cached_resolver(ttl, move |host| lookups.lookup(host))
}

/// The most hosts cached at once. Past it a host is resolved per request but not stored, so a name
/// nothing bounds cannot grow host memory without end.
///
/// The same number the leaf certificate cache holds, and the same number by derivation rather than
/// by coincidence: both are keyed by the hosts one launch actually talks to, and in both the key is
/// chosen by the cage. Which hosts those are is not "a handful" whenever a rule is a pattern — a
/// `re:.*` or a `*.example.com` admits as many distinct names as an agent cares to invent, and each
/// one resolved was an entry that stayed for the life of the launch.
pub(super) const DNS_CACHE_CAP: usize = super::ca::LEAF_CACHE_CAP;

/// The cache core of [`caching_resolver`], parameterised by the inner resolver so its behaviour is
/// unit-testable without real DNS. Only a successful, non-empty resolution is cached; `ttl == 0`
/// disables the cache (resolve every request); any error propagates unchanged. The host is put in
/// its [`lookup_name`] form first, for the lookup and the key alike.
fn cached_resolver<F>(ttl: Duration, inner: F) -> Resolver
where
    F: Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
{
    use std::time::Instant;
    // host name -> (resolved addresses, when they were resolved)
    type DnsCache = Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>;
    let cache: Arc<DnsCache> = Arc::new(Mutex::new(HashMap::new()));
    Box::new(move |host: &str| {
        let host = lookup_name(host)?;
        let host = host.as_str();
        if !ttl.is_zero()
            && let Ok(map) = cache.lock()
            && let Some((ips, at)) = map.get(host)
            && at.elapsed() < ttl
        {
            return Ok(ips.clone());
        }
        let ips = inner(host)?;
        if !ips.is_empty()
            && !ttl.is_zero()
            && let Ok(mut map) = cache.lock()
        {
            if map.len() >= DNS_CACHE_CAP {
                // The ttl governed reads only, so an entry for a host never asked for again stayed
                // until the launch ended. Sweeping here is what makes the ceiling one on entries
                // that are still worth something rather than on how many names were ever resolved.
                map.retain(|_, (_, at)| at.elapsed() < ttl);
            }
            // Past the ceiling a host still resolves, it is simply not remembered — the same answer
            // the leaf cache gives, and for the same reason: refusing to serve would turn a memory
            // bound into a functional one.
            if map.len() < DNS_CACHE_CAP {
                map.insert(host.to_string(), (ips.clone(), Instant::now()));
            }
        }
        Ok(ips)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A counting resolver: the number of times the inner one was actually called is how a test
    /// sees the cache, which has no other handle on it.
    fn counting_resolver(ttl: Duration) -> (Resolver, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let r = cached_resolver(ttl, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(vec![IpAddr::from([1, 2, 3, 4])])
        });
        (r, calls)
    }

    /// A flood of distinct names stops being remembered at the ceiling, and what was cached under
    /// it still is.
    ///
    /// The ceiling exists because "a proxy fronts a handful of hosts" stops being true the moment a
    /// rule is a pattern: a `re:.*` admits as many names as an agent invents, and each resolved one
    /// used to stay for the life of the launch.
    #[test]
    fn a_flood_of_distinct_hosts_stops_being_remembered_at_the_ceiling() {
        use std::sync::atomic::Ordering;
        // Long enough that nothing expires during the test: what is measured here is the ceiling,
        // not the sweep.
        let (r, calls) = counting_resolver(Duration::from_secs(600));
        for i in 0..DNS_CACHE_CAP {
            r(&format!("h{i}.example.com")).unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), DNS_CACHE_CAP);

        // Past the ceiling: resolved every time, remembered never.
        r("flood.example.com").unwrap();
        r("flood.example.com").unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            DNS_CACHE_CAP + 2,
            "a host past the ceiling must resolve rather than be refused, and not be stored"
        );

        // And the ceiling did not cost what was already held.
        r("h0.example.com").unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            DNS_CACHE_CAP + 2,
            "an entry under the ceiling must survive the flood"
        );
    }

    /// The ttl frees room, because it now governs more than reads.
    ///
    /// It only ever governed reads: an entry for a host never asked for again was never removed, so
    /// a cache filled once stayed filled. Without the sweep a ceiling would turn that into a cache
    /// that stops working after the first flood.
    #[test]
    fn an_expired_entry_makes_room_rather_than_holding_the_ceiling() {
        use std::sync::atomic::Ordering;
        let ttl = Duration::from_millis(50);
        let (r, calls) = counting_resolver(ttl);
        for i in 0..DNS_CACHE_CAP {
            r(&format!("h{i}.example.com")).unwrap();
        }
        std::thread::sleep(ttl * 3);

        // The first insert past the ceiling sweeps what expired, so this one is remembered...
        r("later.example.com").unwrap();
        let after_insert = calls.load(Ordering::SeqCst);
        r("later.example.com").unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            after_insert,
            "a cache full of expired entries must take a new one"
        );
    }

    #[test]
    fn the_dns_cache_resolves_a_host_once_and_reuses_it() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let r = cached_resolver(Duration::from_secs(60), move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(vec![IpAddr::from([1, 2, 3, 4])])
        });
        assert_eq!(
            r("cache.nixos.org").unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
        assert_eq!(
            r("cache.nixos.org").unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the second resolve of the same host is a cache hit"
        );
        // a different host is a separate cache entry
        r("pypi.org").unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A resolver held shut until the test opens it, counting how many lookups it was asked for and
    /// signalling each one as it starts.
    struct Gate {
        open: Arc<(Mutex<bool>, Condvar)>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        started: std::sync::mpsc::Receiver<String>,
    }

    fn gated(
        answer: Vec<IpAddr>,
    ) -> (
        Gate,
        impl Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
    ) {
        let open: Arc<(Mutex<bool>, Condvar)> = Arc::default();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (tell, started) = std::sync::mpsc::channel();
        let tell = Mutex::new(tell);
        let (o, c) = (Arc::clone(&open), Arc::clone(&calls));
        let resolve = move |host: &str| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = locked(&tell).send(host.to_string());
            let (gate, opened) = &*o;
            let _held = opened
                .wait_while(locked(gate), |open| !*open)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Ok(answer.clone())
        };
        (
            Gate {
                open,
                calls,
                started,
            },
            resolve,
        )
    }

    impl Gate {
        fn release(&self) {
            let (gate, opened) = &*self.open;
            *locked(gate) = true;
            opened.notify_all();
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn callers_of_one_name_share_one_lookup() {
        let (gate, resolve) = gated(vec![IpAddr::from([1, 2, 3, 4])]);
        let lookups = Arc::new(Lookups::new(resolve, 8, Duration::from_secs(10)));
        let first = {
            let l = Arc::clone(&lookups);
            std::thread::spawn(move || l.lookup("a.test"))
        };
        gate.started.recv().unwrap();
        let second = {
            let l = Arc::clone(&lookups);
            std::thread::spawn(move || l.lookup("a.test"))
        };
        // Wait until the second caller holds the in-flight slot too: the table's entry, the lookup's
        // own end and the two callers make four holders.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while locked(&lookups.in_flight)
            .get("a.test")
            .is_none_or(|slot| Arc::strong_count(slot) < 4)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the second caller never joined"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        gate.release();
        assert_eq!(
            first.join().unwrap().unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
        assert_eq!(
            second.join().unwrap().unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
        assert_eq!(
            gate.calls(),
            1,
            "two callers of one name started two lookups"
        );
    }

    #[test]
    fn a_caller_past_the_deadline_leaves_and_a_retry_joins_the_hanging_lookup() {
        let (gate, resolve) = gated(vec![IpAddr::from([1, 2, 3, 4])]);
        let lookups = Lookups::new(resolve, 8, Duration::from_millis(50));
        let late = lookups.lookup("hang.test").unwrap_err();
        assert_eq!(late.kind(), io::ErrorKind::TimedOut, "{late}");
        let again = lookups.lookup("hang.test").unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::TimedOut, "{again}");
        assert_eq!(
            gate.calls(),
            1,
            "a retry of a hanging name started another lookup"
        );
        gate.release();
    }

    #[test]
    fn names_past_the_cap_are_refused_at_once_instead_of_each_taking_a_thread() {
        let (gate, resolve) = gated(vec![IpAddr::from([1, 2, 3, 4])]);
        let lookups = Arc::new(Lookups::new(resolve, 1, Duration::from_secs(10)));
        let held = {
            let l = Arc::clone(&lookups);
            std::thread::spawn(move || l.lookup("one.test"))
        };
        gate.started.recv().unwrap();
        let started = std::time::Instant::now();
        let refused = lookups.lookup("two.test").unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a name past the cap waited instead of being refused: {refused}"
        );
        assert_eq!(refused.kind(), io::ErrorKind::Other, "{refused}");
        assert_eq!(gate.calls(), 1);
        gate.release();
        held.join().unwrap().unwrap();
        // Settled, the place is free again.
        lookups.lookup("two.test").unwrap();
        assert_eq!(gate.calls(), 2);
    }

    #[test]
    fn a_lookup_that_panics_answers_an_error_and_frees_its_name() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let lookups = Lookups::new(
            move |_: &str| -> io::Result<Vec<IpAddr>> {
                if c.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    panic!("resolver failure");
                }
                Ok(vec![IpAddr::from([1, 2, 3, 4])])
            },
            1,
            Duration::from_secs(10),
        );
        let failed = lookups.lookup("p.test").unwrap_err();
        assert_eq!(failed.kind(), io::ErrorKind::Other, "{failed}");
        // Neither the name nor the cap's one place is held by the dead lookup.
        assert_eq!(
            lookups.lookup("p.test").unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
    }

    #[test]
    fn a_lookup_with_no_thread_to_run_on_answers_an_error_and_wedges_nothing() {
        // A failed spawn drops the closure on the caller's thread, which holds the table — the
        // way std's own spawn does when `pthread_create` refuses.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let mut lookups = Lookups::new(
            move |_: &str| {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec![IpAddr::from([1, 2, 3, 4])])
            },
            8,
            Duration::from_secs(10),
        );
        lookups.spawn = |work| {
            drop(work);
            Err(io::Error::other("no thread to give"))
        };
        let lookups = Arc::new(lookups);
        for attempt in 0..2 {
            let (tell, told) = std::sync::mpsc::channel();
            let l = Arc::clone(&lookups);
            std::thread::spawn(move || {
                let _ = tell.send(l.lookup("t.test").map_err(|e| e.to_string()));
            });
            let answer = told
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|_| panic!("attempt {attempt}: the lookup hung"));
            assert!(answer.is_err(), "attempt {attempt}: {answer:?}");
        }
        assert!(
            locked(&lookups.in_flight).is_empty(),
            "a failed spawn left its name in flight"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn a_lookup_with_no_address_is_an_error_not_an_empty_success() {
        let lookups = Lookups::new(|_: &str| Ok(Vec::new()), 8, Duration::from_secs(10));
        let empty = lookups.lookup("nothing.test").unwrap_err();
        assert_eq!(empty.kind(), io::ErrorKind::NotFound, "{empty}");
    }

    #[test]
    fn one_name_in_any_spelling_is_one_cache_entry_and_a_non_name_is_never_looked_up() {
        use std::sync::atomic::Ordering;
        let (r, calls) = counting_resolver(Duration::from_secs(60));
        for spelling in [
            "example.com",
            "Example.COM",
            "example.com.",
            "example.com..",
        ] {
            r(spelling).unwrap();
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one name cached under three keys"
        );
        let long = "a".repeat(254);
        for bad in ["", ".", "a b.test", "a\nb.test", long.as_str()] {
            let refused = r(bad).unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a non-name reached the resolver"
        );
        // An address literal is a name a lookup takes, IPv6 included.
        r("::1").unwrap();
        r("127.0.0.1").unwrap();
    }

    #[test]
    fn a_zero_ttl_disables_the_dns_cache() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let r = cached_resolver(Duration::ZERO, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(vec![IpAddr::from([1, 2, 3, 4])])
        });
        r("h").unwrap();
        r("h").unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "ttl = 0 resolves on every request (no cache)"
        );
    }
}
