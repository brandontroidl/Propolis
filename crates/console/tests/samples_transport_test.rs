//! The samples page's Transport column joins spooled files to the fetcher's records by digest: the
//! file is named by its lowercase hex SHA-256, `fetch_attempt.sha256` holds the raw bytes, and the
//! query encodes them to match. Nothing else checks that join end to end; a mismatch would show
//! every fetched sample as "not recorded" without failing anything.
//!
//! A test binary of its own because the spool location comes from `PROPOLIS_SPOOL_ROOT`, a process
//! environment variable, and nothing else in this binary reads the environment.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower::ServiceExt;

fn state(db: PgPool) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([7u8; 32])),
        passwords: Arc::new(PasswordStore::new("samples-transport-test")),
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip: Arc::new(geoip::GeoIp::disabled()),
        rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
        feed_output_dir: None,
        fleet_listeners: Arc::new(Vec::new()),
        fleet_probe_interval: std::time::Duration::from_secs(300),
        deploy_stamp_path: None,
        startup_time: chrono::Utc::now(),
        binary_name: "console",
        version: "test",
        git_sha: "abc123abc123",
        built_at: "2026-09-09T00:00:00Z",
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(10)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: false,
        metrics_token: None,
        gave_up_subsystems: console::no_subsystem_health(),
        intake_lag: console::intake_lag::no_intake_lag(),
    }
}

/// Writes `body` into `<root>/<bucket>/` under its digest, as a spool does, and returns the digest.
fn spool(root: &std::path::Path, bucket: &str, body: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(body).to_vec();
    let dir = root.join(bucket);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(hex::encode(&digest)), body).unwrap();
    digest
}

async fn fetched(
    pool: &PgPool,
    url: &str,
    status: &str,
    sha256: &[u8],
    transport: &str,
    error: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO fetch_attempt \
             (url_hash, url, host, scheme, status, sha256, transport_auth, tls_verify_error, \
              last_attempt) \
         VALUES ($1, $2, 'malware.test', 'https', $3, $4, $5, $6, now())",
    )
    .bind(Sha256::digest(url.as_bytes()).to_vec())
    .bind(url)
    .bind(status)
    .bind(sha256)
    .bind(transport)
    .bind(error)
    .execute(pool)
    .await
    .unwrap();
}

/// The `<tr>` on the page that lists the sample with this digest.
fn row_for<'a>(page: &'a str, digest: &[u8]) -> &'a str {
    let short = &hex::encode(digest)[..12];
    let at = page
        .find(short)
        .unwrap_or_else(|| panic!("no row for {short}: {page}"));
    let start = page[..at].rfind("<tr").unwrap();
    let end = at + page[at..].find("</tr>").unwrap();
    &page[start..end]
}

#[sqlx::test(migrations = false)]
async fn each_sample_row_shows_how_its_fetches_were_authenticated(pool: PgPool) {
    let root = tempfile::tempdir().unwrap();
    // SAFETY: set before anything reads it, and nothing else in this binary reads the environment.
    unsafe { std::env::set_var("PROPOLIS_SPOOL_ROOT", root.path()) };

    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    review::migrator().run(&pool).await.unwrap();
    fleet::migrator().run(&pool).await.unwrap();

    let verified = spool(root.path(), "fetched", b"sample fetched over verified tls");
    fetched(
        &pool,
        "https://malware.test/a",
        "success",
        &verified,
        "verified",
        None,
    )
    .await;

    let mixed = spool(root.path(), "fetched", b"sample served two ways");
    fetched(
        &pool,
        "https://malware.test/b",
        "success",
        &mixed,
        "unverified",
        Some("invalid peer certificate: UnknownIssuer"),
    )
    .await;
    fetched(
        &pool,
        "http://malware.test/b",
        "success",
        &mixed,
        "plaintext",
        None,
    )
    .await;

    // Captured by a sensor, never fetched. A failed fetch attempt naming the same bytes must not
    // make it look fetched.
    let orphan = spool(root.path(), "fetched", b"body whose fetch record is gone");
    let captured = spool(root.path(), "ssh", b"sample a sensor captured");
    fetched(
        &pool,
        "http://malware.test/c",
        "timeout",
        &captured,
        "plaintext",
        None,
    )
    .await;

    // One body in each VirusTotal state: kept local for its type (-2), uploaded awaiting a
    // verdict (-1), and verdicted.
    for (digest, detected, total) in [(&verified, -2, -2), (&mixed, -1, -1), (&captured, 3, 70)] {
        sqlx::query(
            "INSERT INTO sample_analysis (sha256, detected, total, vt_link, analyzed_at) \
             VALUES ($1, $2, $3, '', now())",
        )
        .bind(hex::encode(digest))
        .bind(detected)
        .bind(total)
        .execute(&pool)
        .await
        .unwrap();
    }

    let state = state(pool);
    let (_, cookie) = state.sessions.create();
    let app =
        routes::router(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5555))));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/samples")
                .header("cookie", format!("{}={cookie}", auth::SESSION_COOKIE))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    let row = row_for(&page, &verified);
    assert!(
        row.contains("TLS verified") && !row.contains("not fetched"),
        "{row}"
    );
    assert!(
        row.contains("not uploaded (type)")
            && !row.contains("pending")
            && !row.contains("detections"),
        "a -2 sample is neither pending nor a zero-detection verdict: {row}"
    );
    let pending_row = row_for(&page, &mixed);
    assert!(
        pending_row.contains("pending") && !pending_row.contains("not uploaded"),
        "{pending_row}"
    );
    assert!(row_for(&page, &captured).contains("3/70 detected"));

    let row = row_for(&page, &mixed);
    assert!(row.contains("TLS unverified"), "{row}");
    assert!(
        row.contains(r#"title="invalid peer certificate: UnknownIssuer""#),
        "{row}"
    );
    assert!(row.contains("plaintext"), "{row}");
    assert!(!row.contains("TLS verified"), "{row}");

    let row = row_for(&page, &captured);
    assert!(
        row.contains("n/a, uploaded") && !row.contains("not fetched"),
        "a sensor upload is labelled an upload: {row}"
    );
    assert!(
        !row.contains("TLS") && !row.contains("plaintext"),
        "a failed fetch naming the same bytes must not give an upload a transport: {row}"
    );

    // A body in the fetcher's bucket that no successful fetch record names is a missing record,
    // not an upload.
    let orphan = row_for(&page, &orphan);
    assert!(
        orphan.contains("not recorded") && !orphan.contains("uploaded"),
        "{orphan}"
    );
}
