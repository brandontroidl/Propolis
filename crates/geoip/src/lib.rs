//! Offline IP geolocation and ASN enrichment from MaxMind GeoLite2 databases. Egress-free by
//! construction: every lookup is a local file read, never a network call, so the honeypot never
//! reveals which addresses it has captured. Shared by the console (IP-detail "network profile"
//! display) and the feed (ASN-allowlist suppression of trusted-org infrastructure), so both use one
//! reader. Both databases are optional - when the configured directory is absent or a file is
//! missing, lookups return `None`/`None` and callers degrade gracefully. The operator drops
//! `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` into `PROPOLIS_GEOIP_DIR` (see `INSTALL.md`).

use std::net::IpAddr;
use std::path::Path;

use maxminddb::{Reader, geoip2};
use serde::Serialize;

/// Enrichment for one IP. Every field is optional: a database may hold no record for an address, or
/// only one of the two databases may be configured.
#[derive(Debug, Default, Serialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub org: Option<String>,
}

/// Loaded GeoLite2 readers. Either or both may be absent (unconfigured, or the file was missing at
/// startup), in which case the corresponding lookups simply yield nothing.
pub struct GeoIp {
    city: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
}

// `maxminddb::Reader` is not `Debug`; a manual impl reports only whether each database loaded so
// consumers that derive `Debug` (e.g. the feed's `ExclusionEngine`) can hold a `GeoIp` without
// dumping the whole in-memory database.
impl std::fmt::Debug for GeoIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIp")
            .field("city", &self.city.is_some())
            .field("asn", &self.asn.is_some())
            .finish()
    }
}

impl GeoIp {
    /// A fully-disabled resolver (no databases). Every lookup returns `None`. Used when
    /// `PROPOLIS_GEOIP_DIR` is unset, when ASN suppression is not configured, and by tests.
    pub fn disabled() -> Self {
        Self {
            city: None,
            asn: None,
        }
    }

    /// Load whatever GeoLite2 databases exist under `dir` (City + ASN). A missing directory or file
    /// is not an error - the corresponding reader stays `None` and callers degrade gracefully. Only
    /// a present-but-unreadable file is logged (a warning), so a corrupt drop-in is visible without
    /// taking down the process.
    pub fn load(dir: &Path) -> Self {
        Self {
            city: open_db(&dir.join("GeoLite2-City.mmdb")),
            asn: open_db(&dir.join("GeoLite2-ASN.mmdb")),
        }
    }

    /// Load only the ASN database from `dir`. For the feed's ASN-allowlist suppression, which never
    /// needs city/country data - avoids loading the (much larger) City database in the feed process.
    pub fn load_asn_only(dir: &Path) -> Self {
        Self {
            city: None,
            asn: open_db(&dir.join("GeoLite2-ASN.mmdb")),
        }
    }

    /// True if at least one database loaded, i.e. enrichment/suppression should run rather than the
    /// "not configured" behaviour.
    pub fn is_enabled(&self) -> bool {
        self.city.is_some() || self.asn.is_some()
    }

    /// Enrich one IP. Returns `None` when no database is configured (the caller renders "not
    /// configured"); returns `Some` - possibly with all-`None` fields - when a database is present
    /// but holds no record for this address.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        if !self.is_enabled() {
            return None;
        }
        let mut info = GeoInfo::default();
        if let Some(reader) = &self.city
            && let Ok(result) = reader.lookup(ip)
            && let Ok(Some(city)) = result.decode::<geoip2::City>()
        {
            info.country = city.country.names.english.map(|s| s.to_string());
            info.country_code = city.country.iso_code.map(|s| s.to_string());
            info.city = city.city.names.english.map(|s| s.to_string());
        }
        if let Some(reader) = &self.asn
            && let Ok(result) = reader.lookup(ip)
            && let Ok(Some(asn)) = result.decode::<geoip2::Asn>()
        {
            info.asn = asn.autonomous_system_number;
            info.org = asn.autonomous_system_organization.map(|s| s.to_string());
        }
        Some(info)
    }

    /// The autonomous system number for `ip`, or `None` when the ASN database is not configured or
    /// holds no record. The lean lookup the feed's suppression gate uses - no allocation, no
    /// city/country decode.
    pub fn asn_of(&self, ip: IpAddr) -> Option<u32> {
        let reader = self.asn.as_ref()?;
        let result = reader.lookup(ip).ok()?;
        result
            .decode::<geoip2::Asn>()
            .ok()?? // outer ?: decode error; inner ?: no record for this IP
            .autonomous_system_number
    }
}

/// Open one `.mmdb` reader, or `None` if the file is absent (the common, expected case on a host
/// that has not installed the GeoLite2 data). A present-but-unreadable file logs a warning and is
/// treated as absent rather than propagating an error.
fn open_db(path: &Path) -> Option<Reader<Vec<u8>>> {
    // `is_file()` (not `exists()`): a FIFO, device node, or socket at this path would make the
    // `open_readfile` -> `fs::read` below block the thread forever (a FIFO with no writer) or read
    // unbounded data. The path is operator-controlled, but a botched provisioning script or stale
    // mount should degrade to disabled, never hang startup.
    if !path.is_file() {
        return None;
    }
    match Reader::open_readfile(path) {
        Ok(reader) => Some(reader),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to open GeoLite2 database; geo enrichment disabled for it"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_resolver_is_not_enabled_and_looks_up_nothing() {
        let g = GeoIp::disabled();
        assert!(!g.is_enabled());
        assert!(g.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(g.asn_of("8.8.8.8".parse().unwrap()).is_none());
    }

    #[test]
    fn a_missing_database_directory_loads_as_disabled_rather_than_erroring() {
        // The common deployment case: PROPOLIS_GEOIP_DIR points somewhere with no .mmdb files.
        let g = GeoIp::load(Path::new("/nonexistent/propolis/geoip/dir"));
        assert!(!g.is_enabled());
        assert!(g.lookup("203.0.113.7".parse().unwrap()).is_none());
    }

    #[test]
    fn asn_only_load_skips_city_and_a_missing_asn_db_degrades() {
        let g = GeoIp::load_asn_only(Path::new("/nonexistent/propolis/geoip/dir"));
        assert!(!g.is_enabled());
        assert!(g.asn_of("203.0.113.7".parse().unwrap()).is_none());
    }

    #[test]
    fn a_non_regular_file_at_the_db_path_degrades_to_disabled() {
        // A directory (or FIFO/device) where a `.mmdb` is expected must not be opened: the
        // `is_file()` guard keeps `open_readfile`/`fs::read` from hanging or reading unbounded data.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("GeoLite2-City.mmdb")).unwrap();
        std::fs::create_dir(dir.path().join("GeoLite2-ASN.mmdb")).unwrap();
        let g = GeoIp::load(dir.path());
        assert!(!g.is_enabled());
    }
}
