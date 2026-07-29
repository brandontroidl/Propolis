//! The exclusion engine: a fail-closed filter that keeps private, reserved, allowlisted, or
//! delisted addresses out of every export. See `internal/design/05-blocklist-feed.md`
//! ("Exclusion engine"). Applied at build time here; the publisher (a later task in this
//! sub-project) re-validates every entry again before writing, as defense-in-depth.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::LazyLock;

use ipnet::IpNet;

/// Special-purpose ranges no blocklist entry may ever carry, regardless of operator
/// configuration: RFC1918 private space, RFC5737 documentation ranges, loopback, link-local,
/// multicast, the limited broadcast address, and their IPv6 equivalents (loopback, link-local,
/// unique-local, multicast, and the documentation range). Fixed and not operator-configurable,
/// so this is computed once and shared by every `ExclusionEngine` instance.
static RESERVED_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        // RFC1918 private address space.
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        // RFC5737 documentation ranges (TEST-NET-1/2/3).
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        // Loopback.
        "127.0.0.0/8",
        "::1/128",
        // Link-local.
        "169.254.0.0/16",
        "fe80::/10",
        // Multicast.
        "224.0.0.0/4",
        "ff00::/8",
        // Limited broadcast.
        "255.255.255.255/32",
        // IPv6 unique local addresses (ULA).
        "fc00::/7",
        // IPv6 documentation range.
        "2001:db8::/32",
    ]
    .iter()
    .map(|s| {
        s.parse()
            .expect("hardcoded reserved-range literal must parse")
    })
    .collect()
});

fn is_reserved(ip: IpAddr) -> bool {
    RESERVED_RANGES.iter().any(|net| net.contains(&ip))
}

/// Fail-closed address filter. `is_excluded` is a total, infallible function over
/// already-validated in-memory data, so there is no "cannot evaluate" outcome at this layer - an
/// unreadable allowlist source (the design's example of a check that "cannot be evaluated") fails
/// earlier, at config load, before an `ExclusionEngine` is ever constructed.
#[derive(Debug, Clone)]
pub struct ExclusionEngine {
    allowlist: Vec<IpNet>,
    delist: HashSet<IpAddr>,
}

impl ExclusionEngine {
    pub fn new(allowlist: Vec<IpNet>, delist: Vec<IpAddr>) -> Self {
        Self {
            allowlist,
            delist: delist.into_iter().collect(),
        }
    }

    /// True if `ip` must never reach an export: a reserved/special-purpose range, an
    /// operator-allowlisted range, or an explicitly delisted address.
    pub fn is_excluded(&self, ip: IpAddr) -> bool {
        is_reserved(ip)
            || self.allowlist.iter().any(|net| net.contains(&ip))
            || self.delist.contains(&ip)
    }
}
