//! Offline IP geolocation and ASN enrichment from MaxMind GeoLite2 databases. Egress-free by
//! construction: every lookup is a local file read, never a network call, so the honeypot never
//! reveals which addresses it has captured. Both databases are optional - when the configured
//! directory is absent or a file is missing, lookups return `None` and the detail page shows the
//! "not configured" placeholder. The operator drops `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`
//! into `PROPOLIS_GEOIP_DIR` (see `INSTALL.md`).

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

impl GeoIp {
    /// A fully-disabled resolver (no databases). `lookup` always returns `None`, so the panel
    /// renders "not configured". Used by the unified daemon/console when `PROPOLIS_GEOIP_DIR` is
    /// unset and by tests.
    pub fn disabled() -> Self {
        Self {
            city: None,
            asn: None,
        }
    }

    /// Load whatever GeoLite2 databases exist under `dir`. A missing directory or missing file is
    /// not an error - the corresponding reader stays `None` and the panel degrades gracefully. Only
    /// a present-but-unreadable file is logged (a warning), so a corrupt drop-in is visible without
    /// taking down the console.
    pub fn load(dir: &Path) -> Self {
        Self {
            city: open_db(&dir.join("GeoLite2-City.mmdb")),
            asn: open_db(&dir.join("GeoLite2-ASN.mmdb")),
        }
    }

    /// True if at least one database loaded, i.e. the panel should render geo/ASN data rather than
    /// the "not configured" placeholder.
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
}

/// Open one `.mmdb` reader, or `None` if the file is absent (the common, expected case on a host
/// that has not installed the GeoLite2 data). A present-but-unreadable file logs a warning and is
/// treated as absent rather than propagating an error.
fn open_db(path: &Path) -> Option<Reader<Vec<u8>>> {
    if !path.exists() {
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
    }

    #[test]
    fn a_missing_database_directory_loads_as_disabled_rather_than_erroring() {
        // The common deployment case: PROPOLIS_GEOIP_DIR points somewhere with no .mmdb files.
        let g = GeoIp::load(Path::new("/nonexistent/propolis/geoip/dir"));
        assert!(!g.is_enabled());
        assert!(g.lookup("203.0.113.7".parse().unwrap()).is_none());
    }
}
