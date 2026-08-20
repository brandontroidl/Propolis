//! Mock-HTTP-server tests for the vendor adapters (Task 3): payload
//! construction per vendor, category mapping, and the shared response
//! classification (success / "already reported" / transient 5xx / permanent
//! 4xx).
//!
//! No `wiremock`-class dependency: a small hand-rolled tokio `TcpListener`
//! speaks just enough HTTP/1.1 (headers + `Content-Length` body, no chunked
//! transfer-encoding - reqwest never sends chunked requests for the small
//! bodies these adapters build) to serve one canned response and capture the
//! one request the adapter under test sends. See `respond_once`.
//!
//! Unlike `gatekeeper_test.rs`/`queue_test.rs`, nothing here touches the
//! shared `propolis_test` database - every test binds its own OS-assigned
//! loopback port, so this file runs safely under the default parallel test
//! runner (no `--test-threads=1` needed).
//!
//! AbuseIPDB's real endpoint accepts `application/x-www-form-urlencoded`
//! only, verified live against `docs.abuseipdb.com` while implementing the
//! adapter (see `crates/review/src/vendor/abuseipdb.rs`), so its captured
//! body is decoded with `url::form_urlencoded` rather than `serde_json`.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use core_scoring::Category;
use rust_decimal::Decimal;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use review::vendor::{
    AbuseIpDb, DShield, FullVendorConfig, OtxAdapter, VendorAdapter, VendorError, VendorReport,
    build_categories, build_dshield_categories, build_otx_categories,
};

// ---------------------------------------------------------------------
// Mock HTTP server
// ---------------------------------------------------------------------

/// One request as the mock server saw it, for the test to assert against.
struct CapturedRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

/// Starts a one-shot mock HTTP server on an OS-assigned loopback port,
/// replies to the single request it receives with `status`/`reason`/`body`,
/// and returns the server's base URL plus a join handle that resolves to the
/// captured request once the adapter under test has called it. Await the
/// handle only after the adapter's `submit` call has returned.
async fn respond_once(
    status: u16,
    reason: &'static str,
    body: &'static str,
) -> (String, tokio::task::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let captured = read_request(&mut stream).await;
        write_response(&mut stream, status, reason, body).await;
        captured
    });
    (format!("http://{addr}"), handle)
}

/// A loopback URL nothing is listening on: bind then immediately drop the
/// listener, so a client connecting to it gets an instant connection
/// refusal (used to exercise the connection-level-failure path, which never
/// produces an HTTP response at all).
async fn unreachable_base_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

async fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before headers were complete");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "connection closed before body was complete");
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[body_start..body_start + content_length]).into_owned();

    CapturedRequest {
        method,
        path,
        headers,
        body,
    }
}

async fn write_response(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    let _ = stream.shutdown().await;
}

fn sample_report(categories: Vec<String>) -> VendorReport {
    let now = Utc::now();
    VendorReport {
        source_ip: "203.0.113.50".parse().unwrap(),
        categories,
        comment: "repeated ssh login attempts against the honeypot".to_string(),
        evidence_window: (now - Duration::hours(2), now),
    }
}

// ---------------------------------------------------------------------
// Category mapping (build_categories / build_dshield_categories / build_otx_categories)
// ---------------------------------------------------------------------

#[test]
fn ssh_maps_regardless_of_honeypot_or_auth_category() {
    // SignalType::HoneypotLoginAttempt (Category::Honeypot) and
    // SignalType::SshBruteForce (Category::Auth) both carry
    // protocol_label = "ssh" and must map to the same vendor codes - the
    // design spec's combined "Honeypot/Auth" cell for the ssh row.
    for category in [Category::Honeypot, Category::Auth] {
        assert_eq!(
            build_categories(Some("ssh"), category),
            vec!["22".to_string()]
        );
        assert_eq!(
            build_dshield_categories(Some("ssh"), category),
            vec!["ssh".to_string()]
        );
        assert_eq!(
            build_otx_categories(Some("ssh"), category),
            vec!["ssh-bruteforce".to_string()]
        );
    }
}

#[test]
fn telnet_and_ftp_map_to_their_own_codes() {
    assert_eq!(
        build_categories(Some("telnet"), Category::Honeypot),
        vec!["23".to_string()]
    );
    assert_eq!(
        build_categories(Some("ftp"), Category::Honeypot),
        vec!["5".to_string()]
    );
}

#[test]
fn generic_categories_fall_through_when_protocol_label_absent() {
    assert_eq!(
        build_categories(None, Category::Network),
        vec!["14".to_string()]
    );
    assert_eq!(
        build_categories(None, Category::Waf),
        vec!["21".to_string()]
    );
    assert_eq!(
        build_categories(None, Category::Ids),
        vec!["15".to_string()]
    );
}

#[test]
fn unrecognized_protocol_label_collapses_to_generic_category() {
    // A daemon-style label or near miss (per
    // internal/design/02-sensor-framework.md's own example: "ftpd",
    // "mysqld", "mysql", "http") that does not match ssh/telnet/ftp
    // silently falls through to the Category-keyed row - no error.
    assert_eq!(
        build_categories(Some("mysqld"), Category::Network),
        vec!["14".to_string()]
    );
    assert_eq!(
        build_dshield_categories(Some("http"), Category::Waf),
        vec!["web".to_string()]
    );
}

#[test]
fn unmapped_honeypot_or_auth_falls_back_to_ids_row() {
    // Not reachable from any currently defined SignalType (see
    // `review::vendor::resolve`'s doc comment), but must not panic.
    assert_eq!(
        build_categories(None, Category::Honeypot),
        vec!["15".to_string()]
    );
    assert_eq!(
        build_otx_categories(Some("smtp"), Category::Auth),
        vec!["intrusion-attempt".to_string()]
    );
}

// ---------------------------------------------------------------------
// FullVendorConfig reconciliation with gatekeeper::VendorConfig
// ---------------------------------------------------------------------

#[test]
fn full_vendor_config_gate_config_drops_secrets_keeps_gate_fields() {
    let full = FullVendorConfig {
        name: "abuseipdb".to_string(),
        enabled: true,
        api_key: "super-secret-key".to_string(),
        api_url: "https://api.abuseipdb.com".to_string(),
        cooldown_hours: 24,
        rate_limit: 15,
        rate_window_hours: 1,
        score_floor: Some(Decimal::from(50)),
        category_filter: Some(vec!["Honeypot".to_string()]),
    };
    let gate = full.gate_config();
    assert_eq!(gate.name, "abuseipdb");
    assert!(gate.enabled);
    assert_eq!(gate.cooldown_hours, 24);
    assert_eq!(gate.rate_limit, 15);
    assert_eq!(gate.rate_window_hours, 1);
    assert_eq!(gate.score_floor, Some(Decimal::from(50)));
    assert_eq!(gate.category_filter, Some(vec!["Honeypot".to_string()]));
    // gatekeeper::VendorConfig has no api_key/api_url field at all, so this
    // holds by construction; assert it explicitly anyway via Debug so a
    // future field addition to that struct cannot silently smuggle the
    // secret back in without this test catching it.
    assert!(!format!("{gate:?}").contains("super-secret-key"));
}

#[test]
fn adapter_names_match_vendor_submission_table_convention() {
    let client = reqwest::Client::new();
    assert_eq!(
        AbuseIpDb::new(client.clone(), "k", "http://127.0.0.1:1").name(),
        "abuseipdb"
    );
    assert_eq!(
        DShield::new(client.clone(), "k", "http://127.0.0.1:1").name(),
        "dshield"
    );
    assert_eq!(
        OtxAdapter::new(client, "k", "http://127.0.0.1:1").name(),
        "otx"
    );
}

// ---------------------------------------------------------------------
// AbuseIPDB
// ---------------------------------------------------------------------

#[tokio::test]
async fn abuseipdb_payload_has_ip_categories_and_comment() {
    let (base_url, server) = respond_once(
        200,
        "OK",
        r#"{"data":{"ipAddress":"203.0.113.50","abuseConfidenceScore":50}}"#,
    )
    .await;
    let adapter = AbuseIpDb::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_categories(Some("ssh"), Category::Auth));

    let result = adapter.submit(&report).await.unwrap();
    assert!(result.accepted);
    assert_eq!(result.status, 200);

    let captured = server.await.unwrap();
    assert_eq!(captured.method, "POST");
    assert!(captured.path.ends_with("/api/v2/report"));
    // `Key`, not `X-Key`. The adapter sent `X-Key` originally and every live submission came back
    // 401; the API's own documentation and a manual curl both confirm `Key`. This test asserted
    // the broken header and so agreed with the bug, which cost a full debugging round to find -
    // it never ran, because the CI gate was failing at the format step before reaching the tests.
    assert_eq!(
        captured.headers.get("key").map(String::as_str),
        Some("test-key")
    );
    let form: HashMap<String, String> = url::form_urlencoded::parse(captured.body.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(form.get("ip").unwrap(), "203.0.113.50");
    assert_eq!(form.get("categories").unwrap(), "22");
    assert_eq!(
        form.get("comment").unwrap(),
        "repeated ssh login attempts against the honeypot"
    );
    assert!(form.contains_key("timestamp"));
}

#[tokio::test]
async fn abuseipdb_429_already_reported_is_treated_as_success() {
    // Live-verified real response text ("You can only report the same IP
    // address ... once in 15 minutes") - see abuseipdb.rs's module doc for
    // why the adapter keys this off status alone, not this body text.
    let (base_url, server) = respond_once(
        429,
        "Too Many Requests",
        r#"{"errors":[{"detail":"You can only report the same IP address (`203.0.113.50`) once in 15 minutes.","status":429}]}"#,
    )
    .await;
    let adapter = AbuseIpDb::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_categories(Some("ssh"), Category::Auth));

    let result = adapter.submit(&report).await.unwrap();
    assert!(result.accepted);
    assert_eq!(result.status, 429);
    server.await.unwrap();
}

#[tokio::test]
async fn abuseipdb_5xx_is_transient() {
    let (base_url, server) = respond_once(503, "Service Unavailable", "upstream down").await;
    let adapter = AbuseIpDb::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_categories(Some("ssh"), Category::Auth));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Transient { status: 503, .. }),
        "expected Transient(503), got {err:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn abuseipdb_4xx_non_429_is_permanent() {
    let (base_url, server) = respond_once(
        422,
        "Unprocessable Entity",
        r#"{"errors":[{"detail":"invalid ip","status":422}]}"#,
    )
    .await;
    let adapter = AbuseIpDb::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_categories(Some("ssh"), Category::Auth));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Permanent { status: 422, .. }),
        "expected Permanent(422), got {err:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn abuseipdb_connection_failure_is_transient() {
    let base_url = unreachable_base_url().await;
    let adapter = AbuseIpDb::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_categories(Some("ssh"), Category::Auth));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Transient { status: 0, .. }),
        "expected Transient(0) for a connection failure, got {err:?}"
    );
}

#[tokio::test]
async fn permanent_error_never_echoes_the_api_key() {
    let (base_url, server) =
        respond_once(400, "Bad Request", r#"{"errors":[{"detail":"bad ip"}]}"#).await;
    let adapter = AbuseIpDb::new(
        reqwest::Client::new(),
        "super-secret-abuseipdb-key",
        base_url,
    );
    let report = sample_report(build_categories(Some("ssh"), Category::Auth));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(!format!("{err}").contains("super-secret-abuseipdb-key"));
    assert!(!format!("{err:?}").contains("super-secret-abuseipdb-key"));
    server.await.unwrap();
}

// ---------------------------------------------------------------------
// DShield
// ---------------------------------------------------------------------

#[tokio::test]
async fn dshield_payload_has_ip_port_and_protocol() {
    let (base_url, server) = respond_once(200, "OK", r#"{"status":"ok"}"#).await;
    let adapter = DShield::new(reqwest::Client::new(), "test-user:test-key", base_url);
    let report = sample_report(build_dshield_categories(Some("telnet"), Category::Honeypot));

    let result = adapter.submit(&report).await.unwrap();
    assert!(result.accepted);

    let captured = server.await.unwrap();
    // Every value below was wrong in this test until it was finally run. It asserted
    // `/api/submit` with an `X-Api-Key` header - neither exists. The real endpoint is
    // `/submitapi/`, authenticated with an ISC-HMAC-SHA256 credential that must appear in BOTH
    // the `X-ISC-Authorization` header AND the JSON body's `authheader` field; sending only the
    // header returns "ERROR: no authinfo", and the wrong path returns the site's HTML landing
    // page with a 200, which the adapter had been recording as a successful submission.
    assert!(
        captured.path.ends_with("/submitapi/"),
        "path was {}",
        captured.path
    );
    let auth = captured
        .headers
        .get("x-isc-authorization")
        .expect("X-ISC-Authorization header missing");
    assert!(
        auth.starts_with("ISC-HMAC-SHA256 Credentials=") && auth.contains("Userid=test-user"),
        "unexpected auth header: {auth}"
    );
    // ISC's own log-type vocabulary, not the protocol tag: "telnetlogin", not "telnet".
    assert_eq!(
        captured.headers.get("x-isc-logtype").map(String::as_str),
        Some("telnetlogin")
    );

    let json: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(json["type"], "telnetlogin");
    assert_eq!(
        json["authheader"], *auth,
        "the body's authheader must carry the same credential as the header"
    );
    let log = &json["logs"][0];
    assert_eq!(log["source"], "203.0.113.50");
    assert_eq!(log["port"], 23);
    assert!(log.get("time").is_some());
}

#[tokio::test]
async fn dshield_body_level_error_is_permanent_despite_http_200() {
    // The failure that made this adapter look healthy for a full day: DShield answers a rejected
    // submission with HTTP 200 and an "ERROR: ..." body, so classifying on status alone recorded
    // 34 consecutive failures as successes.
    let (base_url, server) = respond_once(200, "OK", "ERROR: no authinfo").await;
    let adapter = DShield::new(reqwest::Client::new(), "test-user:test-key", base_url);
    let report = sample_report(build_dshield_categories(Some("ssh"), Category::Honeypot));

    let result = adapter.submit(&report).await;
    let _ = server.await;

    match result {
        Err(VendorError::Permanent { status, body }) => {
            assert_eq!(status, 200);
            assert!(body.starts_with("ERROR"), "body was {body}");
        }
        other => panic!("a 200 carrying an ERROR body must not count as accepted: {other:?}"),
    }
}

#[tokio::test]
async fn dshield_without_a_userid_refuses_to_submit_at_all() {
    // The credential is `userid:apikey`. A key alone cannot produce a valid HMAC, so the adapter
    // must refuse locally rather than send a request that will be rejected server-side.
    let adapter = DShield::new(
        reqwest::Client::new(),
        "key-only",
        "http://127.0.0.1:1".to_string(),
    );
    let report = sample_report(build_dshield_categories(Some("ssh"), Category::Honeypot));

    match adapter.submit(&report).await {
        Err(VendorError::Permanent { body, .. }) => {
            assert!(body.contains("DSHIELD_USER"), "body was {body}");
        }
        other => panic!("expected a local refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn dshield_5xx_is_transient() {
    let (base_url, server) = respond_once(500, "Internal Server Error", "oops").await;
    let adapter = DShield::new(reqwest::Client::new(), "test-user:test-key", base_url);
    let report = sample_report(build_dshield_categories(Some("ftp"), Category::Honeypot));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Transient { status: 500, .. }),
        "expected Transient(500), got {err:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn dshield_4xx_is_permanent() {
    let (base_url, server) = respond_once(401, "Unauthorized", "bad api key").await;
    let adapter = DShield::new(reqwest::Client::new(), "test-user:test-key", base_url);
    let report = sample_report(build_dshield_categories(Some("ftp"), Category::Honeypot));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Permanent { status: 401, .. }),
        "expected Permanent(401), got {err:?}"
    );
    server.await.unwrap();
}

// ---------------------------------------------------------------------
// OTX
// ---------------------------------------------------------------------

#[tokio::test]
async fn otx_payload_creates_pulse_with_correct_indicator_and_tags() {
    let (base_url, server) = respond_once(201, "Created", r#"{"id":"abc123"}"#).await;
    let adapter = OtxAdapter::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_otx_categories(Some("ssh"), Category::Auth));

    let result = adapter.submit(&report).await.unwrap();
    assert!(result.accepted);
    assert_eq!(result.status, 201);

    let captured = server.await.unwrap();
    assert!(captured.path.ends_with("/api/v1/pulses/create"));
    assert_eq!(
        captured.headers.get("x-otx-api-key").map(String::as_str),
        Some("test-key")
    );
    let json: serde_json::Value = serde_json::from_str(&captured.body).unwrap();
    assert_eq!(json["tags"], serde_json::json!(["ssh-bruteforce"]));
    let indicators = json["indicators"].as_array().unwrap();
    assert_eq!(indicators.len(), 1);
    assert_eq!(indicators[0]["indicator"], "203.0.113.50");
    assert_eq!(indicators[0]["type"], "IPv4");
}

#[tokio::test]
async fn otx_5xx_is_transient() {
    let (base_url, server) = respond_once(502, "Bad Gateway", "upstream unreachable").await;
    let adapter = OtxAdapter::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_otx_categories(Some("ssh"), Category::Honeypot));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Transient { status: 502, .. }),
        "expected Transient(502), got {err:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn otx_4xx_is_permanent() {
    let (base_url, server) = respond_once(403, "Forbidden", "invalid api key").await;
    let adapter = OtxAdapter::new(reqwest::Client::new(), "test-key", base_url);
    let report = sample_report(build_otx_categories(Some("ssh"), Category::Honeypot));

    let err = adapter.submit(&report).await.unwrap_err();
    assert!(
        matches!(err, VendorError::Permanent { status: 403, .. }),
        "expected Permanent(403), got {err:?}"
    );
    server.await.unwrap();
}
