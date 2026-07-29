//! OTX (LevelBlue/AlienVault Open Threat Exchange) pulse adapter. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("OTX adapter").
//!
//! Endpoint and body shape verified live against
//! `otx.alienvault.com/assets/static/external_api.html` while implementing
//! this adapter: `POST /api/v1/pulses/create`, JSON body with `name`,
//! `public`, `description`, `tags`, and an `indicators` array of
//! `{indicator, type, description}`. The docs did not name the auth header
//! explicitly; `X-OTX-API-Key` is OTX's documented convention elsewhere and
//! is used here [unverified against a live authenticated call].

use async_trait::async_trait;

use super::{VendorAdapter, VendorError, VendorReport, VendorResponse, send_and_classify};

pub const DEFAULT_BASE_URL: &str = "https://otx.alienvault.com";

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
        let ip = report.source_ip.to_string();
        let payload = PulsePayload {
            name: format!("propolis: {ip} ({})", report.evidence_window.1.to_rfc3339()),
            public: false,
            description: report.comment.clone(),
            tags: report.categories.clone(),
            indicators: vec![Indicator {
                indicator: ip,
                kind: "IPv4",
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
