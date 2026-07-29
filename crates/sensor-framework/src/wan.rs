//! WAN attribution: maps the local socket address a connection or datagram landed on to the
//! operator's externally reachable WAN IP. See "WAN attribution" and the `wan_ip` field of the
//! frozen wire contract in `internal/design/02-sensor-framework.md`: where NAT or DNAT sits in
//! front of the host, the address a listener binds is not the address the internet sees, and
//! `wan_ip` is the per-hit attribution the breadth-of-sighting scoring model depends on.
//! Resolution runs once per accepted connection or datagram, inside the sensor's own handler
//! (not the framework's listener loop - see `listener.rs`, a later task), against an
//! operator-supplied table built once at startup.

use std::collections::HashMap;
use std::net::IpAddr;

/// Resolves a locally bound address to the WAN IP it is reachable as, via an operator-supplied
/// table. A local address with no entry (a corroborating sensor with no bindable WAN IP) resolves
/// to `None`, which the caller stamps as a null `wan_ip` on the event - the wire contract's
/// documented case, not an error condition.
pub struct WanResolver {
    map: HashMap<IpAddr, IpAddr>,
}

impl WanResolver {
    /// `map` is the operator's local-address-to-WAN-IP table, built once at startup. A host with
    /// no NAT in front of it carries an identity entry (local == WAN) rather than omitting the
    /// address, so `resolve` never special-cases the no-NAT deployment.
    pub fn new(map: HashMap<IpAddr, IpAddr>) -> Self {
        Self { map }
    }

    /// Look up the WAN IP for the local address a connection landed on. `None` means no mapping
    /// is configured for that address, not a failure.
    pub fn resolve(&self, local_addr: IpAddr) -> Option<IpAddr> {
        self.map.get(&local_addr).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn resolve_with_mapping() {
        let mut map = std::collections::HashMap::new();
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let wan: IpAddr = "198.51.100.4".parse().unwrap();
        map.insert(local, wan);
        let resolver = WanResolver::new(map);
        assert_eq!(resolver.resolve(local), Some(wan));
    }

    #[test]
    fn resolve_without_mapping_returns_none() {
        let resolver = WanResolver::new(std::collections::HashMap::new());
        let addr: IpAddr = "10.0.0.99".parse().unwrap();
        assert_eq!(resolver.resolve(addr), None);
    }

    #[test]
    fn resolve_direct_wan_no_nat() {
        // When local == WAN (no NAT), the mapping contains an identity entry.
        let mut map = std::collections::HashMap::new();
        let addr: IpAddr = "198.51.100.4".parse().unwrap();
        map.insert(addr, addr);
        let resolver = WanResolver::new(map);
        assert_eq!(resolver.resolve(addr), Some(addr));
    }
}
