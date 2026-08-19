//! The exclusion engine: a fail-closed filter that keeps private, reserved, allowlisted, or
//! delisted addresses out of every export. See `internal/design/05-blocklist-feed.md`
//! ("Exclusion engine"). Applied at build time here; the publisher (a later task in this
//! sub-project) re-validates every entry again before writing, as defense-in-depth.

use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

/// The reserved-range table now lives in `core_scoring::net` so the vendor submission path can
/// apply the identical rule - it previously had no such guard at all. This is a delegation, not a
/// second definition: one list, both outbound paths.
use core_scoring::is_reserved_ip as is_reserved;

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
