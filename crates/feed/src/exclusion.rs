//! The exclusion engine: a fail-closed filter that keeps private, reserved, allowlisted, or
//! delisted addresses out of every export. See `internal/design/05-blocklist-feed.md`
//! ("Exclusion engine"). Applied at build time here; the publisher (a later task in this
//! sub-project) re-validates every entry again before writing, as defense-in-depth.
//!
//! The operator allowlist (CIDR ranges, `PROPOLIS_FEED_ALLOWLIST_FILE` range files, and the
//! trusted-org ASN list) is defined once in [`core_scoring::allowlist`], because the review stage
//! applies the same list to its vendor-report queue. This engine delegates to it rather than
//! keeping a second matcher, so the feed and the review stage cannot disagree about who is
//! allowlisted. The file parser and its width caps are re-exported below for existing callers.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use core_scoring::OperatorAllowlist;
pub use core_scoring::allowlist::{
    ALLOWLIST_FILE_MAX_BYTES, ALLOWLIST_FILE_MAX_ENTRIES, ALLOWLIST_FILE_MIN_PREFIX_V4,
    ALLOWLIST_FILE_MIN_PREFIX_V6, AllowlistFileError, load_allowlist_file, parse_allowlist_text,
};

/// The reserved-range table now lives in `core_scoring::net` so the vendor submission path can
/// apply the identical rule - it previously had no such guard at all. This is a delegation, not a
/// second definition: one list, both outbound paths.
use core_scoring::is_reserved_ip as is_reserved;

/// Fail-closed address filter. `is_excluded` is a total, infallible function over
/// already-validated in-memory data, so there is no "cannot evaluate" outcome at this layer - an
/// unreadable allowlist source (the design's example of a check that "cannot be evaluated") fails
/// earlier, at config load, before an `ExclusionEngine` is ever constructed. The ASN database is
/// likewise loaded (or degraded to disabled) at startup, so the ASN lookup is infallible too.
#[derive(Debug, Clone)]
pub struct ExclusionEngine {
    allowlist: Arc<OperatorAllowlist>,
    delist: HashSet<IpAddr>,
}

impl ExclusionEngine {
    /// Construct with the CIDR allowlist and delist only; ASN suppression disabled. This is the
    /// baseline every caller (and every existing test) uses; production layers ASN suppression on
    /// via [`ExclusionEngine::with_asn_allowlist`] or hands in a ready list via
    /// [`ExclusionEngine::from_allowlist`].
    pub fn new(allowlist: Vec<IpNet>, delist: Vec<IpAddr>) -> Self {
        Self::from_allowlist(Arc::new(OperatorAllowlist::new(allowlist)), delist)
    }

    /// Construct from the shared operator allowlist, the same value the review stage is given.
    pub fn from_allowlist(allowlist: Arc<OperatorAllowlist>, delist: Vec<IpAddr>) -> Self {
        Self {
            allowlist,
            delist: delist.into_iter().collect(),
        }
    }

    /// Enable ASN-allowlist suppression: any address whose GeoLite2 ASN is in `asn_allowlist` is
    /// excluded. `geoip` is the shared reader (typically `GeoIp::load_asn_only`); an empty
    /// `asn_allowlist` leaves suppression off and skips the lookup entirely.
    pub fn with_asn_allowlist(
        mut self,
        asn_allowlist: HashSet<u32>,
        geoip: Arc<geoip::GeoIp>,
    ) -> Self {
        let cidrs_and_asns = (*self.allowlist).clone().with_asns(asn_allowlist, geoip);
        self.allowlist = Arc::new(cidrs_and_asns);
        self
    }

    /// True if `ip` must never reach an export: a reserved/special-purpose range, an
    /// operator-allowlisted range or ASN, or an explicitly delisted address.
    pub fn is_excluded(&self, ip: IpAddr) -> bool {
        is_reserved(ip) || self.allowlist.contains(ip) || self.delist.contains(&ip)
    }

    /// Number of operator-allowlisted CIDR ranges.
    pub fn allowlist_len(&self) -> usize {
        self.allowlist.cidr_len()
    }

    /// Number of explicitly delisted addresses.
    pub fn delist_len(&self) -> usize {
        self.delist.len()
    }

    /// Number of trusted-org ASNs configured for suppression.
    pub fn asn_allowlist_len(&self) -> usize {
        self.allowlist.asn_len()
    }

    /// Whether the GeoLite2-ASN database actually loaded. `false` with a non-empty ASN allowlist
    /// means suppression is configured but INERT (the counts alone would mislead), so the feed
    /// status surface reports both.
    pub fn asn_db_loaded(&self) -> bool {
        self.allowlist.asn_db_loaded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_and_delist_still_apply_alongside_the_asn_allowlist() {
        let e = ExclusionEngine::new(Vec::new(), vec!["203.0.113.9".parse().unwrap()])
            .with_asn_allowlist(
                [8075].into_iter().collect(),
                Arc::new(geoip::GeoIp::disabled()),
            );
        assert!(
            e.is_excluded("10.0.0.1".parse().unwrap()),
            "reserved range still excluded"
        );
        assert!(
            e.is_excluded("203.0.113.9".parse().unwrap()),
            "delisted address still excluded"
        );
    }

    #[test]
    fn with_asn_allowlist_keeps_the_cidr_ranges_already_configured() {
        let e = ExclusionEngine::new(vec!["45.10.30.0/24".parse().unwrap()], Vec::new())
            .with_asn_allowlist(
                [8075].into_iter().collect(),
                Arc::new(geoip::GeoIp::disabled()),
            );
        assert!(e.is_excluded("45.10.30.9".parse().unwrap()));
        assert_eq!(e.allowlist_len(), 1);
        assert_eq!(e.asn_allowlist_len(), 1);
    }
}
