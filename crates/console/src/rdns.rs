//! Forward-confirmed reverse DNS for the IP-detail page. Opt-in: this is the ONE outbound lookup in
//! the console's otherwise egress-free enrichment (a PTR query goes to the address owner's own DNS,
//! which also tells them they are being profiled), so it stays off until `PROPOLIS_CONSOLE_RDNS_ENABLED`.
//! Uses the system resolver via libc `getnameinfo` (reverse) and std `ToSocketAddrs` (forward) - no
//! async DNS dependency. Display-only: a PTR record is set by the IP's owner, so a claimed hostname
//! is trustworthy only after forward-confirmation, and is NEVER a suppression signal (that is ASN's
//! job; PTR is spoofable).

use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::os::raw::c_char;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

/// One IP's reverse-DNS result, as rendered. `hostname == None` means no PTR record (or the lookup
/// failed). `verified` is true only when the PTR hostname forward-resolves back to the same IP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Rdns {
    pub hostname: Option<String>,
    pub verified: bool,
}

/// Cache TTL. Reverse DNS rarely changes; a modest TTL stops repeat detail-page views from
/// re-querying and bounds how long a stale or poisoned answer would persist.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Most distinct IPs the cache holds. Without a bound, a session paging through many IP detail
/// pages grew the map for the life of the process. Each entry is a hostname and an `Instant`, so
/// 4096 stays well under a megabyte while covering far more IPs than an operator views in one TTL.
const CACHE_CAPACITY: usize = 4096;

/// One per process. Holds the opt-in flag and an in-memory TTL cache keyed by IP, bounded to
/// [`CACHE_CAPACITY`] entries.
pub struct RdnsResolver {
    enabled: bool,
    /// Always [`CACHE_CAPACITY`] and [`CACHE_TTL`] outside tests; fields so the tests can use
    /// small ones.
    capacity: usize,
    ttl: Duration,
    cache: Mutex<HashMap<IpAddr, (Rdns, Instant)>>,
}

impl RdnsResolver {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            capacity: CACHE_CAPACITY,
            ttl: CACHE_TTL,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            capacity: CACHE_CAPACITY,
            ttl: CACHE_TTL,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Forward-confirmed reverse lookup. BLOCKING (system resolver) - the caller runs it inside
    /// `spawn_blocking` with a timeout. Returns `None` (the outer Option) when disabled, so the
    /// caller renders "not enabled" distinct from "enabled, no PTR" (`Some(Rdns::default())`).
    pub fn lookup(&self, ip: IpAddr) -> Option<Rdns> {
        if !self.enabled {
            return None;
        }
        if let Some(hit) = self.cached(ip) {
            return Some(hit);
        }
        let rdns = match reverse_lookup(ip) {
            Some(hostname) => Rdns {
                verified: forward_contains(&hostname, ip),
                hostname: Some(hostname),
            },
            None => Rdns::default(),
        };
        self.store(ip, rdns.clone());
        Some(rdns)
    }

    fn cached(&self, ip: IpAddr) -> Option<Rdns> {
        let cache = self.cache.lock().ok()?;
        let (rdns, at) = cache.get(&ip)?;
        (at.elapsed() < self.ttl).then(|| rdns.clone())
    }

    /// Inserts `ip`'s result after dropping every expired entry, then, if still full, the oldest
    /// one. A linear scan over at most `capacity` entries finds it; a separate insertion-order
    /// structure would be one more collection to bound. A poisoned lock skips caching: this is
    /// display-only enrichment, not worth failing the page for.
    fn store(&self, ip: IpAddr, rdns: Rdns) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        let ttl = self.ttl;
        cache.retain(|_, (_, at)| at.elapsed() < ttl);

        if !cache.contains_key(&ip) && cache.len() >= self.capacity {
            let oldest = cache
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(ip, _)| *ip);
            match oldest {
                Some(victim) => {
                    cache.remove(&victim);
                }
                // Capacity 0: nothing to evict, so the result is returned uncached.
                None => return,
            }
        }
        cache.insert(ip, (rdns, Instant::now()));
    }
}

/// Does `hostname` resolve (A/AAAA, via the system resolver) to a set that includes `ip`? This is the
/// forward-confirmation that stops a forged PTR (an attacker setting reverse DNS to `microsoft.com`)
/// from being shown as verified.
fn forward_contains(hostname: &str, ip: IpAddr) -> bool {
    match (hostname, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|s| s.ip()).any(|resolved| resolved == ip),
        Err(_) => false,
    }
}

/// Reverse lookup via `getnameinfo` (system resolver, thread-safe unlike `gethostbyaddr`). `None`
/// for no PTR record or any error - `NI_NAMEREQD` makes a missing name a nonzero return, not a
/// numeric-string fallback.
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let mut host = [0 as c_char; libc::NI_MAXHOST as usize];
    let rc = match ip {
        IpAddr::V4(v4) => {
            let sa = sockaddr_in_for(v4);
            unsafe {
                libc::getnameinfo(
                    std::ptr::addr_of!(sa) as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            let sa = sockaddr_in6_for(v6);
            unsafe {
                libc::getnameinfo(
                    std::ptr::addr_of!(sa) as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: on a zero return, getnameinfo has written a NUL-terminated hostname into `host`.
    let cstr = unsafe { CStr::from_ptr(host.as_ptr()) };
    cstr.to_str()
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn sockaddr_in_for(ip: Ipv4Addr) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is plain-old-data; an all-zero value is valid, then we set the fields.
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    // s_addr is network byte order; an Ipv4Addr's octets ARE the network-order bytes, so a
    // native-endian read of them yields the u32 whose in-memory layout is that byte order.
    sa.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    sa
}

fn sockaddr_in6_for(ip: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: as above for sockaddr_in6.
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_addr.s6_addr = ip.octets();
    sa
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_resolver_returns_none() {
        assert_eq!(
            RdnsResolver::disabled().lookup("8.8.8.8".parse().unwrap()),
            None
        );
    }

    /// Direct constructor for the tests below: overrides `capacity`/`ttl` and drives `store`/
    /// `cached` straight, never touching `reverse_lookup` (real DNS) or the `enabled` gate.
    /// Only possible because `mod tests` is a descendant of `rdns` and can see its private
    /// fields - see the `capacity`/`ttl` field doc comment.
    fn test_resolver(capacity: usize, ttl: Duration) -> RdnsResolver {
        RdnsResolver {
            enabled: true,
            capacity,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn store_evicts_the_single_oldest_entry_once_capacity_is_reached() {
        let resolver = test_resolver(2, CACHE_TTL);
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "203.0.113.2".parse().unwrap();
        let c: IpAddr = "203.0.113.3".parse().unwrap();

        resolver.store(a, Rdns::default());
        // Guarantees `a`'s Instant sorts strictly earlier than `b`'s even on a coarse clock.
        std::thread::sleep(Duration::from_millis(5));
        resolver.store(b, Rdns::default());
        assert_eq!(resolver.cache.lock().unwrap().len(), 2);

        resolver.store(c, Rdns::default());

        let cache = resolver.cache.lock().unwrap();
        assert_eq!(cache.len(), 2, "the cache must never grow past capacity");
        assert!(
            !cache.contains_key(&a),
            "the oldest entry (a) must be the one evicted to make room for c"
        );
        assert!(cache.contains_key(&b) && cache.contains_key(&c));
    }

    #[test]
    fn store_declines_to_cache_rather_than_exceed_a_zero_capacity() {
        let resolver = test_resolver(0, CACHE_TTL);
        let ip: IpAddr = "203.0.113.9".parse().unwrap();

        resolver.store(ip, Rdns::default());

        assert!(
            resolver.cache.lock().unwrap().is_empty(),
            "a zero capacity must never be exceeded, even by the first insert"
        );
    }

    #[test]
    fn store_re_inserting_an_already_cached_ip_does_not_grow_the_map() {
        // A cache hit (`cached` returning `Some`) never calls `store` at all - `lookup`'s doc
        // comment - so this covers the other path that revisits an existing key: an expired
        // entry that is still physically present until the next `store` sweeps it, then gets
        // overwritten in place rather than counted as a second distinct entry.
        let resolver = test_resolver(2, Duration::from_millis(5));
        let ip: IpAddr = "203.0.113.4".parse().unwrap();

        resolver.store(ip, Rdns::default());
        std::thread::sleep(Duration::from_millis(20));
        resolver.store(ip, Rdns::default());

        assert_eq!(resolver.cache.lock().unwrap().len(), 1);
    }

    #[test]
    fn store_sweeps_an_expired_entry_on_the_next_insert() {
        let resolver = test_resolver(10, Duration::from_millis(10));
        let stale: IpAddr = "203.0.113.5".parse().unwrap();
        let fresh: IpAddr = "203.0.113.6".parse().unwrap();

        resolver.store(stale, Rdns::default());
        std::thread::sleep(Duration::from_millis(30));
        resolver.store(fresh, Rdns::default());

        let cache = resolver.cache.lock().unwrap();
        assert_eq!(
            cache.len(),
            1,
            "the expired entry must be swept on the next insert, not linger until it is looked \
             up again"
        );
        assert!(cache.contains_key(&fresh) && !cache.contains_key(&stale));
    }

    #[test]
    fn cached_treats_an_expired_entry_as_a_miss_without_removing_it() {
        // `cached` only reads; sweeping happens in `store` (the finding's "on insertion"), so an
        // expired-but-not-yet-swept row is still physically present here.
        let resolver = test_resolver(10, Duration::from_millis(10));
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        resolver.store(ip, Rdns::default());
        std::thread::sleep(Duration::from_millis(30));

        assert_eq!(resolver.cached(ip), None);
        assert_eq!(
            resolver.cache.lock().unwrap().len(),
            1,
            "a read must not itself remove the stale row"
        );
    }

    #[test]
    fn a_poisoned_cache_lock_degrades_to_a_miss_and_a_declined_store_instead_of_panicking() {
        let resolver = test_resolver(CACHE_CAPACITY, CACHE_TTL);
        let ip: IpAddr = "203.0.113.8".parse().unwrap();

        // Poison the mutex the way a panicking holder would, with no second OS thread needed:
        // `catch_unwind` still unwinds through the guard's `Drop`, which is what marks a
        // `std::sync::Mutex` poisoned.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = resolver.cache.lock().unwrap();
            panic!("simulated panic while holding the rdns cache lock");
        }));
        assert!(unwound.is_err(), "the panic must have actually unwound");
        assert!(resolver.cache.is_poisoned());

        // Both paths that touch the lock must degrade, never propagate the poison as a panic.
        assert_eq!(
            resolver.cached(ip),
            None,
            "a poisoned lock must read as a cache miss"
        );
        resolver.store(ip, Rdns::default());
        assert!(
            resolver.cache.is_poisoned(),
            "store must not have attempted to recover/clear the poison itself"
        );
    }

    #[test]
    fn forward_confirmation_matches_the_ip_and_rejects_a_mismatch() {
        // `localhost` resolves via /etc/hosts (nsswitch files) with no network, so this is
        // deterministic offline: it forward-resolves to 127.0.0.1 but not to a documentation IP.
        assert!(forward_contains("localhost", "127.0.0.1".parse().unwrap()));
        assert!(!forward_contains(
            "localhost",
            "203.0.113.7".parse().unwrap()
        ));
    }

    // A real reverse lookup needs network + DNS; kept `#[ignore]` so the default suite stays
    // offline-deterministic. Run manually (`cargo test -p console -- --ignored rdns`) to validate
    // the getnameinfo FFI end to end.
    #[test]
    #[ignore]
    fn live_forward_confirmed_reverse_lookup_of_a_stable_public_ip() {
        let got = RdnsResolver::new(true)
            .lookup("8.8.8.8".parse().unwrap())
            .unwrap();
        assert!(
            got.hostname.as_deref().unwrap_or("").contains("dns.google"),
            "unexpected hostname: {got:?}"
        );
        assert!(got.verified, "8.8.8.8 rDNS should forward-confirm: {got:?}");
    }
}
