//! DShield / SANS ISC submission adapter.
//!
//! Submits honeypot observations to `POST /submitapi/` using ISC's HMAC-SHA256
//! authentication, verified against the reference client at
//! `github.com/DShield-ISC/dshield/srv/dshield/DShield.py`.
//!
//! Auth: `X-ISC-Authorization: ISC-HMAC-SHA256 Credentials=<hash> Userid=<id> Nonce=<nonce>`
//! where hash = base64(HMAC-SHA256(key=nonce+userid, msg=api_key)).
//!
//! The `api_key` field arrives as `"userid:apikey"` from config.rs (which concatenates
//! PROPOLIS_VENDOR_DSHIELD_USER and PROPOLIS_VENDOR_DSHIELD_KEY). This adapter splits
//! on the first `:` to recover both parts.

use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::{VendorAdapter, VendorError, VendorReport, VendorResponse, send_and_classify};

pub const DEFAULT_BASE_URL: &str = "https://www.dshield.org";

pub struct DShield {
    client: reqwest::Client,
    user_id: String,
    api_key: String,
    base_url: String,
}

impl DShield {
    pub fn new(
        client: reqwest::Client,
        combined_key: impl Into<String>,
        base_url: impl Into<String>,
    ) -> Self {
        let combined = combined_key.into();
        let (user_id, api_key) = match combined.split_once(':') {
            Some((u, k)) => (u.to_string(), k.to_string()),
            None => (String::new(), combined),
        };
        Self {
            client,
            user_id,
            api_key,
            base_url: base_url.into(),
        }
    }

    fn build_auth_header(&self) -> String {
        let nonce_bytes: [u8; 8] = rand::random();
        let nonce = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);

        let hmac_key = format!("{}{}", nonce, self.user_id);
        let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(self.api_key.as_bytes());
        let hash = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        format!(
            "ISC-HMAC-SHA256 Credentials={hash} Userid={} Nonce={nonce}",
            self.user_id
        )
    }
}

fn log_type_for_tag(tag: &str) -> &str {
    match tag {
        "ssh" => "sshlogin",
        "telnet" => "telnetlogin",
        _ => "firewall",
    }
}

fn well_known_port(tag: &str) -> u16 {
    match tag {
        "ssh" => 22,
        "telnet" => 23,
        "ftp" => 21,
        _ => 0,
    }
}

#[derive(serde::Serialize)]
struct SubmitPayload {
    r#type: String,
    logs: Vec<LogEntry>,
    authheader: String,
}

#[derive(serde::Serialize)]
struct LogEntry {
    time: i64,
    source: String,
    port: u16,
}

#[async_trait]
impl VendorAdapter for DShield {
    fn name(&self) -> &str {
        "dshield"
    }

    async fn submit(&self, report: &VendorReport) -> Result<VendorResponse, VendorError> {
        if self.user_id.is_empty() || self.api_key.is_empty() {
            return Err(VendorError::Permanent {
                status: 0,
                body: "DShield requires both PROPOLIS_VENDOR_DSHIELD_USER and PROPOLIS_VENDOR_DSHIELD_KEY".into(),
            });
        }

        let url = format!("{}/submitapi/", self.base_url);
        let tag = report.categories.first().map(String::as_str).unwrap_or("");
        let log_type = log_type_for_tag(tag);

        let auth_header = self.build_auth_header();

        let payload = SubmitPayload {
            r#type: log_type.to_string(),
            logs: vec![LogEntry {
                time: report.evidence_window.1.timestamp(),
                source: report.source_ip.to_string(),
                port: well_known_port(tag),
            }],
            authheader: auth_header.clone(),
        };

        let builder = self
            .client
            .post(url)
            .header("X-ISC-Authorization", &auth_header)
            .header("X-ISC-LogType", log_type)
            .header("User-Agent", "Propolis/0.1")
            .json(&payload);

        match send_and_classify(builder).await {
            Ok(resp) if resp.body.starts_with("ERROR") => Err(VendorError::Permanent {
                status: resp.status,
                body: resp.body,
            }),
            other => other,
        }
    }
}
