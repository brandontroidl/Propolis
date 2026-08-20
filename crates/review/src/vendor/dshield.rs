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

/// The log-type this adapter submits under, and the schema `LogEntry` below implements.
///
/// ISC accepts several (`firewall`, `sshlogin`, `telnetlogin`, `404report`, `httprequest`,
/// `webhoneypot`, `cowrie`), each with its OWN per-entry field names, and it does not reject an
/// entry whose fields it does not recognise - it answers `OK <n> Bytes received` and drops the
/// record. That is precisely what happened here: entries were sent as `{time, source, port}`,
/// which matches no schema ISC defines, so every submission was accepted and none was ever
/// attributed to the account.
///
/// `cowrie` is the honeypot-session schema, verified against Cowrie's own DShield output plugin
/// (`cowrie/src/cowrie/output/dshield.py`). It is used here in preference to `firewall` because
/// it needs no field this crate would have to invent: the `firewall` schema wants
/// `sip`/`dip`/`sport`/`dport`/`proto`, of which only the source IP is actually known at
/// submission time - a destination IP and an attacker source port would both have to be
/// fabricated or omitted, and a fabricated field is how a record gets silently dropped.
const LOG_TYPE: &str = "cowrie";

#[derive(serde::Serialize)]
struct SubmitPayload {
    r#type: String,
    logs: Vec<LogEntry>,
    authheader: String,
}

/// One honeypot session, in ISC's `cowrie` schema.
///
/// `user` and `last_command` are carried as empty strings rather than omitted: the fields are part
/// of the schema, and this crate's `VendorReport` does not currently thread the captured username
/// or command through to the vendor layer. Populating them is a worthwhile follow-up - both are
/// already captured per session - but it means transmitting attacker-supplied strings to a third
/// party, which is an operator's decision to make rather than a detail to slip in with a bug fix.
///
/// There is deliberately no `password` field even though the schema defines one. This honeypot
/// drops captured passwords immediately by design and has none to send.
#[derive(serde::Serialize)]
struct LogEntry {
    timestamp: String,
    source_ip: String,
    user: String,
    #[serde(rename = "lastcommand")]
    last_command: String,
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
        let auth_header = self.build_auth_header();

        let payload = SubmitPayload {
            r#type: LOG_TYPE.to_string(),
            logs: vec![LogEntry {
                timestamp: report.evidence_window.1.to_rfc3339(),
                source_ip: report.source_ip.to_string(),
                user: String::new(),
                last_command: String::new(),
            }],
            authheader: auth_header.clone(),
        };

        let builder = self
            .client
            .post(url)
            .header("X-ISC-Authorization", &auth_header)
            .header("X-ISC-LogType", LOG_TYPE)
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
