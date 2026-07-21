//! Host-side DNS resolution for the proxy, with a short-TTL cache.
//!
//! The cage resolves nothing itself (it lives in an empty netns); every name is resolved here, on
//! the host. The resolver is injectable so tests can map a name to a fixed address deterministically,
//! and wrapped in a small cache so a proxy fronting a long `nix`/flake build does not re-resolve the
//! same host thousands of times.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// A host name resolver, injectable so tests can map a name to a fixed address deterministically.
pub(super) type Resolver = Box<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;

fn default_resolve(host: &str) -> io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    // the port is immaterial to name resolution; 443 is a placeholder so `to_socket_addrs` runs
    Ok((host, 443u16)
        .to_socket_addrs()?
        .map(|sa| sa.ip())
        .collect())
}

/// A [`Resolver`] wrapping [`default_resolve`] with a short-TTL cache — the resolution resilience a
/// proxy fronting a long `nix`/flake build needs. A build fetches from one host (`cache.nixos.org`)
/// thousands of times; re-resolving per request wastes lookups and turns any single resolver hiccup
/// into a failed fetch. The cache resolves each host **once** and reuses the address for `ttl` (a
/// `Duration::ZERO` ttl disables it, resolving every request). Only successful, non-empty resolutions
/// are cached (a failure is never cached, so the client's own retry re-resolves). A transient failure
/// is not retried here: the client (nix/git/curl) already retries the whole request, which re-triggers
/// this resolution, so a proxy-level retry would be redundant. The cache is unbounded but a proxy
/// fronts a handful of hosts and dies with its launch.
pub(super) fn caching_resolver(ttl: Duration) -> Resolver {
    cached_resolver(ttl, default_resolve)
}

/// The cache core of [`caching_resolver`], parameterised by the inner resolver so its behaviour is
/// unit-testable without real DNS. Only a successful, non-empty resolution is cached; `ttl == 0`
/// disables the cache (resolve every request); any error propagates unchanged.
fn cached_resolver<F>(ttl: Duration, inner: F) -> Resolver
where
    F: Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
{
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;
    // host name -> (resolved addresses, when they were resolved)
    type DnsCache = Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>;
    let cache: Arc<DnsCache> = Arc::new(Mutex::new(HashMap::new()));
    Box::new(move |host: &str| {
        if !ttl.is_zero() {
            if let Ok(map) = cache.lock() {
                if let Some((ips, at)) = map.get(host) {
                    if at.elapsed() < ttl {
                        return Ok(ips.clone());
                    }
                }
            }
        }
        let ips = inner(host)?;
        if !ips.is_empty() && !ttl.is_zero() {
            if let Ok(mut map) = cache.lock() {
                map.insert(host.to_string(), (ips.clone(), Instant::now()));
            }
        }
        Ok(ips)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
