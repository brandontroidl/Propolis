//! AbuseIPDB REST adapter. See
//! `internal/design/04-review-gatekeeper-reporting.md` ("AbuseIPDB adapter").
//!
//! Endpoint contract verified live against `docs.abuseipdb.com` while
//! implementing this adapter: `POST /api/v2/report`,
//! `application/x-www-form-urlencoded` body (not JSON), auth via the
//! `X-Key` header. The live docs' duplicate-report response text
//! ("You can only report the same IP address ... once in 15 minutes") does
//! not literally contain the design spec's paraphrase "already reported",
//! and AbuseIPDB does not document any other use of 429 - so this adapter
//! keys the "already reported" carve-out on the status code alone rather
//! than a body substring that has already drifted from the spec's own
//! example text.

use async_trait::async_trait;

use super::{VendorAdapter, VendorError, VendorReport, VendorResponse, send_and_classify};

/// Real endpoint base; adapters accept a configurable base URL (see
/// `Self::new`) so tests can point this at a local mock server instead.
pub const DEFAULT_BASE_URL: &str = "https://api.abuseipdb.com";

pub struct AbuseIpDb {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl AbuseIpDb {
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
struct ReportPayload<'a> {
    ip: String,
    categories: String,
    comment: &'a str,
    timestamp: String,
}

#[async_trait]
impl VendorAdapter for AbuseIpDb {
    fn name(&self) -> &str {
        "abuseipdb"
    }

    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError> {
        let url = format!("{}/api/v2/report", self.base_url);
        let payload = ReportPayload {
            ip: report.source_ip.to_string(),
            categories: report.categories.join(","),
            comment: &report.comment,
            timestamp: report.evidence_window.1.to_rfc3339(),
        };
        let builder = self
            .client
            .post(url)
            .header("X-Key", &self.api_key)
            .header("Accept", "application/json")
            .form(&payload);

        match send_and_classify(builder).await {
            // AbuseIPDB overloads 429 to mean "duplicate report within the
            // per-IP cooldown window" (verified live - see module doc),
            // never a generic rate limit. Design spec "Error handling":
            // treated as success.
            Err(VendorError::Permanent { status: 429, body }) => Ok(VendorResponse {
                status: 429,
                body,
                accepted: true,
            }),
            other => other,
        }
    }
}
