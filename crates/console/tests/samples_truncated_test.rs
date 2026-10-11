//! A sample a sensor kept only the first part of is labelled so on the samples list (in the
//! secondary line under its digest) and on its own page, from the upload events' `truncated`
//! flag; a whole sample is not.
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
        passwords: Arc::new(PasswordStore::new("samples-truncated-test")),
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

fn spool(root: &std::path::Path, bucket: &str, body: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(body));
    let dir = root.join(bucket);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(&digest), body).unwrap();
    digest
}

async fn upload_event(pool: &PgPool, sha256: &str, truncated: bool) {
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, hash, metadata) \
         VALUES ('203.0.113.9', 'ssh', 'honeypot_malware_upload', 'tcp', true, 'network', 1, 0.5, \
                 now(), sha256(convert_to($1, 'UTF8')), \
                 jsonb_build_object('sample_sha256', $1::text, 'truncated', $2::boolean, \
                                    'complete', true))",
    )
    .bind(sha256)
    .bind(truncated)
    .execute(pool)
    .await
    .unwrap();
}

async fn get(app: axum::Router, cookie: &str, uri: &str) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", format!("{}={cookie}", auth::SESSION_COOKIE))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{uri}");
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

/// The `<tr>` on the list that holds this digest's short form.
fn row_for<'a>(page: &'a str, sha256: &str) -> &'a str {
    let at = page
        .find(&sha256[..12])
        .unwrap_or_else(|| panic!("no row for {}: {page}", &sha256[..12]));
    let start = page[..at].rfind("<tr").unwrap();
    let end = at + page[at..].find("</tr>").unwrap();
    &page[start..end]
}

#[sqlx::test(migrations = false)]
async fn a_cut_short_sample_says_so_on_the_list_and_on_its_page_and_a_whole_one_does_not(
    pool: PgPool,
) {
    let root = tempfile::tempdir().unwrap();
    // SAFETY: set before anything reads it, and nothing else in this binary reads the environment.
    unsafe { std::env::set_var("PROPOLIS_SPOOL_ROOT", root.path()) };

    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    review::migrator().run(&pool).await.unwrap();
    fleet::migrator().run(&pool).await.unwrap();
    sqlx::query("ALTER TABLE event DISABLE TRIGGER USER")
        .execute(&pool)
        .await
        .unwrap();

    let cut = spool(root.path(), "ssh", b"the first part of a large upload");
    let whole = spool(root.path(), "ssh", b"a small upload that arrived whole");
    upload_event(&pool, &cut, true).await;
    upload_event(&pool, &whole, false).await;

    let state = state(pool);
    let (_, cookie) = state.sessions.create();
    let app =
        routes::router(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5555))));

    let list = get(app.clone(), &cookie, "/samples").await;
    let cut_row = row_for(&list, &cut);
    assert!(
        cut_row.contains(r#"<span class="c-sub">ssh, "#) && cut_row.contains(", truncated</span>"),
        "{cut_row}"
    );
    assert!(!row_for(&list, &whole).contains("truncated"));

    let cut_page = get(app.clone(), &cookie, &format!("/samples/{cut}")).await;
    assert!(
        cut_page.contains("truncated: the sensor kept only the first part"),
        "{cut_page}"
    );
    let whole_page = get(app, &cookie, &format!("/samples/{whole}")).await;
    assert!(!whole_page.contains("truncated"), "{whole_page}");
}
