//! OTX (LevelBlue/AlienVault Open Threat Exchange) pulse adapter. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("OTX adapter").
//!
//! Endpoint and body shape verified live against
//! `otx.alienvault.com/assets/static/external_api.html` while implementing
//! this adapter: `POST /api/v1/pulses/create`, JSON body with `name`,
//! `public`, `description`, `tags`, and an `indicators` array of
//! `{indicator, type, description}`. Auth via `X-OTX-API-Key` header.
//! Pulses must be `public: true` or OTX rejects with a ToS error.
//! Verified live 2026-08-19.
//!
//! The indicator `type` is per-indicator and address-family-specific: OTX
//! names them `IPv4` and `IPv6` and validates the value against the declared
//! type, so an IPv6 address submitted as `IPv4` is the adapter mislabelling
//! its own evidence. `VendorReport::source_ip` is an `IpAddr` and the review
//! queue surfaces both families, so the type is derived from the address
//! rather than fixed - see [`indicator_type`].

use std::net::IpAddr;

use async_trait::async_trait;

use super::{VendorAdapter, VendorError, VendorReport, VendorResponse, send_and_classify};

pub const DEFAULT_BASE_URL: &str = "https://otx.alienvault.com";

/// OTX's indicator type name for `ip`'s address family.
///
/// Its own vocabulary, not ours: OTX spells these `IPv4` and `IPv6`, and a
/// pulse whose indicator value and declared type disagree is rejected (or,
/// worse, accepted and indexed under the wrong family). An IPv4-mapped IPv6
/// address is reported as `IPv6` on purpose - it arrived over IPv6 and that
/// is the family the indicator's text form will parse as at the far end.
fn indicator_type(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "IPv4",
        IpAddr::V6(_) => "IPv6",
    }
}

pub struct OtxAdapter {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl OtxAdapter {
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

#[derive(serde::Serialize)]
struct Indicator {
    indicator: String,
    #[serde(rename = "type")]
    kind: &'static str,
    description: String,
}

#[derive(serde::Serialize)]
struct PulsePayload {
    name: String,
    public: bool,
    description: String,
    tags: Vec<String>,
    indicators: Vec<Indicator>,
}

#[async_trait]
impl VendorAdapter for OtxAdapter {
    fn name(&self) -> &str {
        "otx"
    }

    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError> {
        let url = format!("{}/api/v1/pulses/create", self.base_url);
        let kind = indicator_type(report.source_ip);
        let ip = report.source_ip.to_string();
        let payload = PulsePayload {
            name: format!("propolis: {ip} ({})", report.evidence_window.1.to_rfc3339()),
            public: true,
            description: report.comment.clone(),
            tags: report.categories.clone(),
            indicators: vec![Indicator {
                indicator: ip,
                kind,
                description: report.comment.clone(),
            }],
        };
        let builder = self
            .client
            .post(url)
            .header("X-OTX-API-Key", &self.api_key)
            .json(&payload);

        send_and_classify(builder).await
    }
}
