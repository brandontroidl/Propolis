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

/// One per process. Holds the opt-in flag and an in-memory TTL cache keyed by IP.
pub struct RdnsResolver {
    enabled: bool,
    cache: Mutex<HashMap<IpAddr, (Rdns, Instant)>>,
}

impl RdnsResolver {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
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
        (at.elapsed() < CACHE_TTL).then(|| rdns.clone())
    }

    fn store(&self, ip: IpAddr, rdns: Rdns) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(ip, (rdns, Instant::now()));
        }
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
