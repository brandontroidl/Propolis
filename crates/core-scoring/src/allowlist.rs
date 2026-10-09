//! The operator allowlist: the one definition of "this address belongs to a declared crawler or
//! trusted organisation and must not leave this system", shared by every stage that acts on it.
//!
//! It lives in `core-scoring` because two crates that do not depend on each other need the same
//! rule: the blocklist feed (`feed::ExclusionEngine`) keeps allowlisted addresses out of the
//! published export, and the review stage (`review::ReviewQueue`, `review::SubmissionRunner`)
//! keeps them out of the vendor-report queue and refuses to submit them. Scoring is unaffected:
//! an allowlisted address is still scored and still shown honestly in the console.
//!
//! Two sources feed one list. CIDR ranges come from `PROPOLIS_FEED_ALLOWLIST` and
//! `PROPOLIS_FEED_ALLOWLIST_FILE` (for example a declared crawler operator's published ranges);
//! ASNs come from `PROPOLIS_FEED_ASN_ALLOWLIST`, resolved through the offline GeoLite2-ASN
//! database. ASN ownership is RIR-registered and not per-IP spoofable, unlike a reverse-DNS PTR
//! record, so it is a safe suppression signal. The exemption rests on the address being in a range
//! the operator listed - never on a User-Agent, which any client can send.
//!
//! The list is read once at startup; an edit takes effect on restart.

use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;

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

/// Parse a comma-separated CIDR list (`PROPOLIS_FEED_ALLOWLIST`). Blank or absent yields an empty
/// list. Each entry needs an explicit prefix length. `Err` carries the first offending entry, so
/// each binary can wrap it in its own config error naming the variable.
pub fn parse_cidr_csv(raw: &str) -> Result<Vec<IpNet>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<IpNet>().map_err(|_| s.to_string()))
        .collect()
}

/// Parse a comma-separated AS-number list (`PROPOLIS_FEED_ASN_ALLOWLIST`): bare numbers, with or
/// without an `AS`/`as` prefix. Blank or absent yields an empty set (ASN suppression off). `Err`
/// carries the first offending entry.
pub fn parse_asn_csv(raw: &str) -> Result<HashSet<u32>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let digits = s
                .strip_prefix("AS")
                .or_else(|| s.strip_prefix("as"))
                .unwrap_or(s);
            digits.parse::<u32>().map_err(|_| s.to_string())
        })
        .collect()
}

/// The operator allowlist: CIDR ranges plus trusted-org ASNs. [`OperatorAllowlist::contains`] is a
/// total, infallible function over already-validated in-memory data; an unreadable source fails
/// earlier, at config load, before one of these is ever constructed.
#[derive(Debug, Clone)]
pub struct OperatorAllowlist {
    cidrs: Vec<IpNet>,
    asns: HashSet<u32>,
    geoip: Arc<geoip::GeoIp>,
}

impl Default for OperatorAllowlist {
    /// Matches nothing: the safe default when the operator configures no exemptions.
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl OperatorAllowlist {
    /// CIDR ranges only; ASN matching off.
    pub fn new(cidrs: Vec<IpNet>) -> Self {
        Self {
            cidrs,
            asns: HashSet::new(),
            geoip: Arc::new(geoip::GeoIp::disabled()),
        }
    }

    /// Enable ASN matching: any address whose GeoLite2 ASN is in `asns` matches. `geoip` is the
    /// shared reader (typically `GeoIp::load_asn_only`); an empty `asns` leaves matching off and
    /// skips the lookup entirely.
    pub fn with_asns(mut self, asns: HashSet<u32>, geoip: Arc<geoip::GeoIp>) -> Self {
        self.asns = asns;
        self.geoip = geoip;
        self
    }

    /// Build from parsed config. When `asns` is non-empty the ASN database is read from
    /// `geoip_dir` (a synchronous file read: call from `spawn_blocking` in async code). A missing
    /// directory or database warns and leaves ASN matching inert - fail open for that one signal
    /// only; the CIDR list and the reserved-range checks are untouched and startup is not blocked.
    pub fn from_config(cidrs: Vec<IpNet>, asns: HashSet<u32>, geoip_dir: Option<&Path>) -> Self {
        let list = Self::new(cidrs);
        if asns.is_empty() {
            return list;
        }
        let geoip = match geoip_dir {
            Some(dir) => geoip::GeoIp::load_asn_only(dir),
            None => {
                tracing::warn!(
                    "PROPOLIS_FEED_ASN_ALLOWLIST is set but PROPOLIS_GEOIP_DIR is not; ASN suppression is inert"
                );
                geoip::GeoIp::disabled()
            }
        };
        if !geoip.is_enabled() {
            tracing::warn!(
                "PROPOLIS_FEED_ASN_ALLOWLIST is set but the GeoLite2-ASN database did not load; ASN suppression is inert"
            );
        }
        list.with_asns(asns, Arc::new(geoip))
    }

    /// True if `ip` is in an allowlisted range or belongs to an allowlisted ASN.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip)) || self.asn_matches(self.lookup_asn(ip))
    }

    /// True when nothing is configured, so callers can skip per-address work entirely.
    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.asns.is_empty()
    }

    /// The address's ASN, or `None` when ASN matching is not configured. Short-circuits before
    /// touching the database when the ASN set is empty (the default).
    fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        if self.asns.is_empty() {
            return None;
        }
        self.geoip.asn_of(ip)
    }

    /// Whether an ASN (as resolved for some address) is allowlisted. Split out so the membership
    /// decision is unit-testable without a real `.mmdb` on disk.
    fn asn_matches(&self, asn: Option<u32>) -> bool {
        asn.is_some_and(|a| self.asns.contains(&a))
    }

    /// Number of allowlisted CIDR ranges.
    pub fn cidr_len(&self) -> usize {
        self.cidrs.len()
    }

    /// Number of allowlisted ASNs.
    pub fn asn_len(&self) -> usize {
        self.asns.len()
    }

    /// Whether the GeoLite2-ASN database actually loaded. `false` with a non-empty ASN set means
    /// ASN matching is configured but INERT (the counts alone would mislead).
    pub fn asn_db_loaded(&self) -> bool {
        self.geoip.is_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_with_asns(asns: &[u32]) -> OperatorAllowlist {
        OperatorAllowlist::new(Vec::new()).with_asns(
            asns.iter().copied().collect(),
            Arc::new(geoip::GeoIp::disabled()),
        )
    }

    #[test]
    fn asn_matches_only_for_an_allowlisted_asn() {
        let l = list_with_asns(&[8075, 15169]);
        assert!(l.asn_matches(Some(8075)), "allowlisted ASN must match");
        assert!(l.asn_matches(Some(15169)));
        assert!(
            !l.asn_matches(Some(64500)),
            "a non-allowlisted ASN must not match"
        );
        assert!(
            !l.asn_matches(None),
            "an address with no ASN record must not match"
        );
    }

    #[test]
    fn an_empty_asn_set_skips_the_database_lookup() {
        let l = OperatorAllowlist::default();
        assert_eq!(l.lookup_asn("45.10.30.7".parse().unwrap()), None);
        // A non-empty set with a disabled database resolves no ASN, so nothing matches.
        let with_asns = list_with_asns(&[8075]);
        assert!(!with_asns.contains("45.10.30.7".parse().unwrap()));
    }

    #[test]
    fn cidr_membership_is_exact_and_default_matches_nothing() {
        let l = OperatorAllowlist::new(vec!["45.10.30.0/24".parse().unwrap()]);
        assert!(l.contains("45.10.30.9".parse().unwrap()));
        assert!(!l.contains("45.10.31.9".parse().unwrap()));
        assert!(!OperatorAllowlist::default().contains("45.10.30.9".parse().unwrap()));
        assert!(OperatorAllowlist::default().is_empty());
        assert!(!l.is_empty());
        assert!(!list_with_asns(&[1]).is_empty());
    }

    #[test]
    fn csv_parsers_trim_skip_blanks_and_name_the_bad_entry() {
        assert_eq!(parse_cidr_csv("  ").unwrap(), Vec::<IpNet>::new());
        assert_eq!(
            parse_cidr_csv(" 10.0.0.0/8 , 9.9.9.9/32 ").unwrap().len(),
            2
        );
        assert_eq!(parse_cidr_csv("9.9.9.9").unwrap_err(), "9.9.9.9");
        assert_eq!(
            parse_asn_csv(" 8075, AS15169 ,as13335 ").unwrap(),
            [8075u32, 15169, 13335].into_iter().collect()
        );
        assert_eq!(parse_asn_csv("8075,notanasn").unwrap_err(), "notanasn");
    }
}
