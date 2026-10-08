//! The exclusion engine: a fail-closed filter that keeps private, reserved, allowlisted, or
//! delisted addresses out of every export. See `internal/design/05-blocklist-feed.md`
//! ("Exclusion engine"). Applied at build time here; the publisher (a later task in this
//! sub-project) re-validates every entry again before writing, as defense-in-depth.
//!
//! ASN allowlist (Phase C): on top of the operator's manual CIDR allowlist, an optional
//! ASN-number allowlist suppresses trusted-org infrastructure (e.g. Microsoft AS8075, Google
//! AS15169, named security scanners) from the public feed, keyed off the offline GeoLite2-ASN
//! database. ASN ownership is RIR-registered and not per-IP spoofable, unlike a reverse-DNS PTR
//! record - so this is a safe suppression signal, whereas PTR would be an evasion vector. It stays
//! opt-in (empty by default) so an operator, not this code, decides what is suppressed.
//!
//! Operator range files: `PROPOLIS_FEED_ALLOWLIST_FILE` names a local text file of CIDRs (for
//! example a declared crawler operator's published ranges) merged into the same allowlist. It is
//! the only way an address is exempted on a crawler's say-so, and the exemption rests on the
//! address being in a range the operator put in the file - never on a User-Agent, which any client
//! can send. See [`load_allowlist_file`].

use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;

/// The reserved-range table now lives in `core_scoring::net` so the vendor submission path can
/// apply the identical rule - it previously had no such guard at all. This is a delegation, not a
/// second definition: one list, both outbound paths.
use core_scoring::is_reserved_ip as is_reserved;

/// Largest allowlist file read. A published crawler range list is a few KiB; anything near this
/// bound is the wrong file (a download that returned a web page, a log), not a list.
pub const ALLOWLIST_FILE_MAX_BYTES: usize = 1 << 20;
/// Most entries one allowlist file may carry.
pub const ALLOWLIST_FILE_MAX_ENTRIES: usize = 50_000;
/// Widest accepted IPv4 entry (shortest prefix). A file entry is bulk data an operator pastes or a
/// scheduled job writes, so a `0.0.0.0/0` (or any prefix that swallows a large share of the
/// address space) is refused as an error rather than silently excluding every attacker.
pub const ALLOWLIST_FILE_MIN_PREFIX_V4: u8 = 8;
/// Widest accepted IPv6 entry; see [`ALLOWLIST_FILE_MIN_PREFIX_V4`].
pub const ALLOWLIST_FILE_MIN_PREFIX_V6: u8 = 16;

/// Why an allowlist file was rejected. Every variant means NO entry from the file is used: the
/// caller refuses to start rather than running with a partial or guessed list.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum AllowlistFileError {
    #[error("cannot read {path}: {reason}")]
    Unreadable { path: String, reason: String },
    #[error("file is larger than {ALLOWLIST_FILE_MAX_BYTES} bytes")]
    TooLarge,
    #[error("file is not valid UTF-8 text")]
    NotText,
    #[error("more than {ALLOWLIST_FILE_MAX_ENTRIES} entries")]
    TooManyEntries,
    #[error(
        "line {line}: {value:?} is not a valid CIDR (a bare address without a prefix length is rejected)"
    )]
    InvalidCidr { line: usize, value: String },
    #[error(
        "line {line}: {value:?} is wider than /{ALLOWLIST_FILE_MIN_PREFIX_V4} (IPv4) or /{ALLOWLIST_FILE_MIN_PREFIX_V6} (IPv6) and would exclude a large share of the address space"
    )]
    TooWide { line: usize, value: String },
}

/// Parse allowlist file text: one CIDR per line, blank lines ignored, `#` starts a comment (whole
/// line or trailing). All-or-nothing: the first bad line fails the whole parse, so a truncated or
/// corrupted file can never yield a partial list that looks valid. An empty list is valid and
/// excludes nothing.
pub fn parse_allowlist_text(text: &str) -> Result<Vec<IpNet>, AllowlistFileError> {
    let mut nets = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let entry = raw.split('#').next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        let net: IpNet = entry.parse().map_err(|_| AllowlistFileError::InvalidCidr {
            line,
            value: entry.to_string(),
        })?;
        let min = match net {
            IpNet::V4(_) => ALLOWLIST_FILE_MIN_PREFIX_V4,
            IpNet::V6(_) => ALLOWLIST_FILE_MIN_PREFIX_V6,
        };
        if net.prefix_len() < min {
            return Err(AllowlistFileError::TooWide {
                line,
                value: entry.to_string(),
            });
        }
        if nets.len() == ALLOWLIST_FILE_MAX_ENTRIES {
            return Err(AllowlistFileError::TooManyEntries);
        }
        nets.push(net);
    }
    Ok(nets)
}

/// Read and parse an allowlist file (see [`parse_allowlist_text`]). The read is bounded, so a
/// path pointed at a huge or endless file cannot exhaust memory. This is a local file read only:
/// nothing here fetches from the network.
pub fn load_allowlist_file(path: &Path) -> Result<Vec<IpNet>, AllowlistFileError> {
    let unreadable = |e: std::io::Error| AllowlistFileError::Unreadable {
        path: path.display().to_string(),
        reason: e.to_string(),
    };
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::new();
    file.take(ALLOWLIST_FILE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > ALLOWLIST_FILE_MAX_BYTES {
        return Err(AllowlistFileError::TooLarge);
    }
    let text = String::from_utf8(bytes).map_err(|_| AllowlistFileError::NotText)?;
    parse_allowlist_text(&text)
}

/// Fail-closed address filter. `is_excluded` is a total, infallible function over
/// already-validated in-memory data, so there is no "cannot evaluate" outcome at this layer - an
/// unreadable allowlist source (the design's example of a check that "cannot be evaluated") fails
/// earlier, at config load, before an `ExclusionEngine` is ever constructed. The ASN database is
/// likewise loaded (or degraded to disabled) at startup, so `asn_of` here is infallible too.
#[derive(Debug, Clone)]
pub struct ExclusionEngine {
    allowlist: Vec<IpNet>,
    delist: HashSet<IpAddr>,
    asn_allowlist: HashSet<u32>,
    geoip: Arc<geoip::GeoIp>,
}

impl ExclusionEngine {
    /// Construct with the CIDR allowlist and delist only; ASN suppression disabled. This is the
    /// baseline every caller (and every existing test) uses; production layers ASN suppression on
    /// via [`ExclusionEngine::with_asn_allowlist`].
    pub fn new(allowlist: Vec<IpNet>, delist: Vec<IpAddr>) -> Self {
        Self {
            allowlist,
            delist: delist.into_iter().collect(),
            asn_allowlist: HashSet::new(),
            geoip: Arc::new(geoip::GeoIp::disabled()),
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
        self.asn_allowlist = asn_allowlist;
        self.geoip = geoip;
        self
    }

    /// True if `ip` must never reach an export: a reserved/special-purpose range, an
    /// operator-allowlisted range, an explicitly delisted address, or an address whose ASN is in
    /// the trusted-org allowlist.
    pub fn is_excluded(&self, ip: IpAddr) -> bool {
        is_reserved(ip)
            || self.allowlist.iter().any(|net| net.contains(&ip))
            || self.delist.contains(&ip)
            || self.asn_matches(self.lookup_asn(ip))
    }

    /// The address's ASN, or `None` when ASN suppression is not configured. Short-circuits before
    /// touching the database when the allowlist is empty (the default), so an operator who never
    /// configures ASN suppression pays nothing.
    fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        if self.asn_allowlist.is_empty() {
            return None;
        }
        self.geoip.asn_of(ip)
    }

    /// Whether an ASN (as resolved for some address) is in the trusted-org allowlist. Split out so
    /// the membership decision is unit-testable without a real `.mmdb` on disk.
    fn asn_matches(&self, asn: Option<u32>) -> bool {
        asn.is_some_and(|a| self.asn_allowlist.contains(&a))
    }

    /// Number of operator-allowlisted CIDR ranges.
    pub fn allowlist_len(&self) -> usize {
        self.allowlist.len()
    }

    /// Number of explicitly delisted addresses.
    pub fn delist_len(&self) -> usize {
        self.delist.len()
    }

    /// Number of trusted-org ASNs configured for suppression.
    pub fn asn_allowlist_len(&self) -> usize {
        self.asn_allowlist.len()
    }

    /// Whether the GeoLite2-ASN database actually loaded. `false` with a non-empty ASN allowlist
    /// means suppression is configured but INERT (the counts alone would mislead), so the feed
    /// status surface reports both.
    pub fn asn_db_loaded(&self) -> bool {
        self.geoip.is_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with_asns(asns: &[u32]) -> ExclusionEngine {
        ExclusionEngine::new(Vec::new(), Vec::new()).with_asn_allowlist(
            asns.iter().copied().collect(),
            Arc::new(geoip::GeoIp::disabled()),
        )
    }

    #[test]
    fn asn_matches_only_for_an_allowlisted_asn() {
        let e = engine_with_asns(&[8075, 15169]);
        assert!(e.asn_matches(Some(8075)), "allowlisted ASN must match");
        assert!(e.asn_matches(Some(15169)));
        assert!(
            !e.asn_matches(Some(64500)),
            "a non-allowlisted ASN must not match"
        );
        assert!(
            !e.asn_matches(None),
            "an address with no ASN record must not match"
        );
    }

    #[test]
    fn an_empty_asn_allowlist_skips_the_database_lookup() {
        // The default: no ASN suppression configured. `lookup_asn` short-circuits to None without
        // consulting the database, so `is_excluded` reduces to the reserved/CIDR/delist checks and
        // the ASN path contributes nothing. (Every test-safe range - RFC5737/1918 - is itself
        // reserved, so this asserts the short-circuit directly rather than via a non-excluded IP.)
        let e = ExclusionEngine::new(Vec::new(), Vec::new());
        assert_eq!(e.lookup_asn("203.0.113.7".parse().unwrap()), None);
        // Even with a disabled geoip and a non-empty allowlist, a lookup yields nothing to match.
        let with_asns = engine_with_asns(&[8075]);
        assert!(!with_asns.asn_matches(with_asns.lookup_asn("203.0.113.7".parse().unwrap())));
    }

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
}
