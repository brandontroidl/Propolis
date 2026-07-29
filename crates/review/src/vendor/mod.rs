//! Vendor adapters: the common `VendorAdapter` trait every vendor client
//! implements, the `VendorReport` submitted through it, the static
//! protocol_label + `Category` -> vendor-specific abuse category mapping,
//! and the per-vendor HTTP configuration. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("Vendor adapters" /
//! "Category mapping").

pub mod abuseipdb;
pub mod dshield;
pub mod otx;

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use core_scoring::Category;
use rust_decimal::Decimal;

pub use abuseipdb::AbuseIpDb;
pub use dshield::DShield;
pub use otx::OtxAdapter;

/// Evidence for one vendor submission: the reported IP, the vendor-specific
/// category codes for THIS vendor (already resolved via
/// [`build_categories`]/[`build_dshield_categories`]/[`build_otx_categories`]
/// by the caller - one `VendorReport` per vendor, since each vendor wants
/// different codes for the same underlying event), a human-readable
/// evidence summary, and the observed activity window (first_seen..last_seen).
#[derive(Debug, Clone, PartialEq)]
pub struct VendorReport {
    pub source_ip: IpAddr,
    pub categories: Vec<String>,
    pub comment: String,
    pub evidence_window: (DateTime<Utc>, DateTime<Utc>),
}

/// A vendor's response to an accepted submission.
#[derive(Debug, Clone, PartialEq)]
pub struct VendorResponse {
    pub status: u16,
    pub body: String,
    pub accepted: bool,
}

/// Why a submission attempt did not succeed, per the design spec's "Error
/// handling": `Transient` covers a 5xx response and any error that never
/// produced a response at all (connection refused, timeout, DNS failure -
/// `status: 0` marks this sub-case since no real HTTP status exists yet).
/// The submission stays in the queue and is retried on the next poll cycle.
/// `Permanent` covers any other 4xx - the submission is marked failed and
/// not automatically retried; the operator can manually re-queue it.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum VendorError {
    #[error("transient vendor error (status {status}): {body}")]
    Transient { status: u16, body: String },
    #[error("permanent vendor error (status {status}): {body}")]
    Permanent { status: u16, body: String },
}

/// One vendor client. Implementations hold their own API key and never
/// place it in `VendorReport`, `VendorResponse`, or `VendorError` - it lives
/// only on the adapter struct and is attached directly to the outgoing HTTP
/// request, so nothing on the `submit` return path can carry it into a log
/// line.
#[async_trait]
pub trait VendorAdapter: Send + Sync {
    /// The vendor name used as `vendor_submission.vendor` (e.g. "abuseipdb").
    fn name(&self) -> &str;
    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError>;
}

/// The full per-vendor configuration (design spec "Configuration"): every
/// field [`crate::gatekeeper::VendorConfig`] has, plus the two fields the
/// gate checks never touch but the adapters need to make the HTTP call.
///
/// Kept as a separate type rather than widening `gatekeeper::VendorConfig`:
/// that type's own doc comment documents the `api_key`/`api_url` omission as
/// deliberate (the gate checks must never see the key), and adding them
/// there would undo that separation. [`Self::gate_config`] derives the
/// gatekeeper-scoped view from this one, so the shared fields have a single
/// place they are written down.
#[derive(Debug, Clone)]
pub struct FullVendorConfig {
    pub name: String,
    pub enabled: bool,
    /// From `EnvironmentFile`, never logged, never stored on disk outside
    /// the process environment (design spec "Configuration").
    pub api_key: String,
    pub api_url: String,
    pub cooldown_hours: u32,
    pub rate_limit: u32,
    pub rate_window_hours: u32,
    pub score_floor: Option<Decimal>,
    pub category_filter: Option<Vec<String>>,
}

impl FullVendorConfig {
    /// The gatekeeper-scoped view of this config: every field `check` reads,
    /// with `api_key`/`api_url` dropped.
    pub fn gate_config(&self) -> crate::gatekeeper::VendorConfig {
        crate::gatekeeper::VendorConfig {
            name: self.name.clone(),
            enabled: self.enabled,
            cooldown_hours: self.cooldown_hours,
            rate_limit: self.rate_limit,
            rate_window_hours: self.rate_window_hours,
            score_floor: self.score_floor,
            category_filter: self.category_filter.clone(),
        }
    }
}

/// One row's vendor-specific codes in the static category mapping table.
struct CodeSet {
    abuseipdb: &'static str,
    dshield: &'static str,
    otx: &'static str,
}

/// Rows keyed by a known `protocol_label` (the exact lowercase L7 label from
/// event metadata - see `internal/architecture/frozen-contracts.md`). A
/// recognized `protocol_label` wins outright, independent of `Category`:
/// this is the design spec's combined "Honeypot/Auth" cell for `ssh` -
/// `HoneypotLoginAttempt` (Category::Honeypot) and `SshBruteForce`
/// (Category::Auth) both carry `protocol_label = "ssh"` and both map to the
/// same vendor codes (`core_scoring::domain::weights::signal_weight`).
const PROTOCOL_TABLE: &[(&str, CodeSet)] = &[
    (
        "ssh",
        CodeSet {
            abuseipdb: "22",
            dshield: "ssh",
            otx: "ssh-bruteforce",
        },
    ),
    (
        "telnet",
        CodeSet {
            abuseipdb: "23",
            dshield: "telnet",
            otx: "telnet-bruteforce",
        },
    ),
    (
        "ftp",
        CodeSet {
            abuseipdb: "5",
            dshield: "ftp",
            otx: "ftp-bruteforce",
        },
    ),
];

/// Rows keyed by `Category`, used when `protocol_label` is absent or does
/// not match [`PROTOCOL_TABLE`] (an unrecognized or daemon-style label per
/// the frozen-contracts note, or a category with no protocol-speaking
/// sensor at all - Suricata, WAF, the catchall probe).
const CATEGORY_TABLE: &[(Category, CodeSet)] = &[
    (
        Category::Network,
        CodeSet {
            abuseipdb: "14",
            dshield: "scan",
            otx: "portscan",
        },
    ),
    (
        Category::Waf,
        CodeSet {
            abuseipdb: "21",
            dshield: "web",
            otx: "web-attack",
        },
    ),
    (
        Category::Ids,
        CodeSet {
            abuseipdb: "15",
            dshield: "intrusion",
            otx: "intrusion-attempt",
        },
    ),
];

/// Resolve the vendor-specific [`CodeSet`] for `(protocol_label, category)`.
///
/// `protocol_label` is tried first; a match in [`PROTOCOL_TABLE`] wins
/// regardless of `category`. Otherwise falls through to [`CATEGORY_TABLE`]
/// keyed by `category`. `Category::Honeypot` and `Category::Auth` have no
/// row of their own in `CATEGORY_TABLE` - given the current
/// `SignalType` -> `Category` assignments
/// (`core_scoring::domain::weights::signal_weight`), every signal type
/// carrying one of those two categories is emitted only by a
/// protocol-speaking sensor, which always sets `protocol_label`, so this arm
/// is not reachable today. It exists so `resolve` stays total (every
/// `Category` variant handled) rather than panicking if a future sensor ever
/// emits one of these two categories with an unrecognized or missing
/// `protocol_label` - exactly the "silently collapses to the generic
/// category with no error" case `internal/design/02-sensor-framework.md`
/// warns about for an unpinned label. It falls back to the `Ids` row (the
/// broadest "uncategorized abuse" bucket of the three) rather than
/// inventing a code the spec never defined for these two categories.
fn resolve(protocol_label: Option<&str>, category: Category) -> &'static CodeSet {
    if let Some(label) = protocol_label
        && let Some((_, codes)) = PROTOCOL_TABLE.iter().find(|(l, _)| *l == label)
    {
        return codes;
    }
    let effective = match category {
        Category::Network | Category::Waf | Category::Ids => category,
        Category::Honeypot | Category::Auth => Category::Ids,
    };
    CATEGORY_TABLE
        .iter()
        .find(|(c, _)| *c == effective)
        .map(|(_, codes)| codes)
        .expect("CATEGORY_TABLE has a row for every Category resolve maps `effective` to")
}

/// AbuseIPDB numeric category code for `(protocol_label, category)`, per the
/// design spec's static mapping table (e.g. `ssh` -> `["22"]`).
pub fn build_categories(protocol_label: Option<&str>, category: Category) -> Vec<String> {
    vec![resolve(protocol_label, category).abuseipdb.to_string()]
}

/// DShield's category/protocol tag for `(protocol_label, category)` (e.g.
/// `ssh` -> `["ssh"]`).
pub fn build_dshield_categories(protocol_label: Option<&str>, category: Category) -> Vec<String> {
    vec![resolve(protocol_label, category).dshield.to_string()]
}

/// OTX tag for `(protocol_label, category)` (e.g. `ssh` -> `["ssh-bruteforce"]`).
pub fn build_otx_categories(protocol_label: Option<&str>, category: Category) -> Vec<String> {
    vec![resolve(protocol_label, category).otx.to_string()]
}

/// Send `builder` and classify the outcome per the design spec's "Error
/// handling": 2xx is success; a connection-level failure (no response at
/// all) or a 5xx is transient; any other 4xx is permanent. Shared by every
/// adapter so the status-code policy has one implementation; a vendor's own
/// quirks on top of it (AbuseIPDB's 429 meaning "already reported") are
/// layered by the caller, not here.
pub(crate) async fn send_and_classify(
    builder: reqwest::RequestBuilder,
) -> Result<VendorResponse, VendorError> {
    let resp = builder.send().await.map_err(|e| VendorError::Transient {
        status: 0,
        body: format!("request error: {e}"),
    })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if status.is_success() {
        return Ok(VendorResponse {
            status: status.as_u16(),
            body,
            accepted: true,
        });
    }
    if status.is_server_error() {
        return Err(VendorError::Transient {
            status: status.as_u16(),
            body,
        });
    }
    Err(VendorError::Permanent {
        status: status.as_u16(),
        body,
    })
}
