//! DShield HTTP adapter. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("DShield adapter").
//!
//! Two simplifications versus the spec's prose, both forced by the shapes
//! already frozen elsewhere in this sub-project rather than chosen here:
//!
//! - The spec's payload wants "destination port" and "protocol", but
//!   [`VendorReport`] (frozen by this task's own brief) carries neither a
//!   port nor an L4/L7 protocol field, only `categories`. This adapter
//!   treats `categories` as already holding DShield's tag (via
//!   [`super::build_dshield_categories`] - `"ssh"`, `"telnet"`, `"ftp"`,
//!   `"scan"`, `"web"`, or `"intrusion"`) and derives a canonical
//!   `dest_port` from the three protocol-speaking tags via
//!   [`well_known_port`] (0 for the three generic tags, which have no
//!   single canonical port).
//! - The spec says DShield auth is "API key + user ID", but the frozen
//!   `VendorConfig`/`FullVendorConfig` (design spec "Configuration") has
//!   only one credential field, `api_key`. This adapter sends only that
//!   single value (as the `X-Api-Key` header); there is nowhere to carry a
//!   separate user ID without adding a field to that frozen struct, which
//!   is a decision for whoever owns the spec, not this task.
//!
//! DShield's real submission API was not reachable to verify live while
//! implementing this (see task report); the payload shape below follows the
//! design spec's abstracted description as given, not a verified wire
//! contract.

use async_trait::async_trait;

use super::{VendorAdapter, VendorError, VendorReport, VendorResponse, send_and_classify};

pub const DEFAULT_BASE_URL: &str = "https://www.dshield.org";

pub struct DShield {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl DShield {
    pub fn new(
        client: reqwest::Client,
        api_key: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            client,
            api_key: api_key.into(),
            base_url: base_url.into(),
        }
    }
}

/// The canonical well-known port for the three protocol-speaking DShield
/// tags; 0 (not applicable) for the three generic tags, which name a class
/// of activity rather than a single service.
fn well_known_port(tag: &str) -> u16 {
    match tag {
        "ssh" => 22,
        "telnet" => 23,
        "ftp" => 21,
        _ => 0,
    }
}

#[derive(serde::Serialize)]
struct SubmitPayload<'a> {
    ip: String,
    port: u16,
    protocol: &'a str,
    timestamp: String,
}

#[async_trait]
impl VendorAdapter for DShield {
    fn name(&self) -> &str {
        "dshield"
    }

    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError> {
        let url = format!("{}/api/submit", self.base_url);
        let tag = report.categories.first().map(String::as_str).unwrap_or("");
        let payload = SubmitPayload {
            ip: report.source_ip.to_string(),
            port: well_known_port(tag),
            protocol: tag,
            timestamp: report.evidence_window.1.to_rfc3339(),
        };
        let builder = self
            .client
            .post(url)
            .header("X-Api-Key", &self.api_key)
            .json(&payload);

        send_and_classify(builder).await
    }
}
