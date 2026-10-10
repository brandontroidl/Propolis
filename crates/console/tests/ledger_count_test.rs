//! The fleet page's Ledger panel must not scan the event table on every load, and must not show an
//! estimate as a count. Below the counting cap the number is exact and unqualified; above it the
//! planner's estimate is shown as "about N" and labelled.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

fn state(db: PgPool) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([5u8; 32])),
        passwords: Arc::new(PasswordStore::new("ledger-count-test")),
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

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

/// `n` ledger rows written straight to the table with the chain trigger off: the console only
/// reads the ledger, and a hash-chained append per row would make the 100,000 needed here slow.
async fn bulk_events(pool: &PgPool, n: i64) {
    sqlx::query("ALTER TABLE event DISABLE TRIGGER USER")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, hash) \
         SELECT '203.0.113.9', 'telnet', 'honeypot_connection', 'tcp', false, 'network', 1, 0.5, \
                now(), sha256(convert_to(g::text, 'UTF8')) \
         FROM generate_series(1, $1) g",
    )
    .bind(n)
    .execute(pool)
    .await
    .unwrap();
}

/// The Ledger cell of the fleet band.
async fn ledger_cell(pool: PgPool) -> String {
    let state = state(pool);
    let (_, cookie) = state.sessions.create();
    let response = routes::router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5555))))
        .oneshot(
            Request::builder()
                .uri("/fleet")
                .header("cookie", format!("{}={cookie}", auth::SESSION_COOKIE))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let at = body.find(r#"<span class="label">Ledger</span>"#).unwrap();
    body[at..].to_string()
}

/// The band's Ledger cell, from `page` (what [`ledger_cell`] returns).
fn band(page: &str) -> &str {
    &page[..page.find("verify the chain").unwrap()]
}

/// The "Evidence chain" panel's Events row.
fn events_row(page: &str) -> &str {
    let at = page.find("<td>Events</td>").unwrap();
    &page[at..at + page[at..].find("</tr>").unwrap()]
}

#[sqlx::test(migrations = false)]
async fn a_small_ledger_shows_its_exact_count(pool: PgPool) {
    migrate(&pool).await;
    bulk_events(&pool, 37).await;
    let page = ledger_cell(pool).await;
    let cell = band(&page);
    assert!(
        cell.contains(r#"<div class="v">37</div>"#),
        "an exact count is a bare number: {cell}"
    );
    assert!(cell.contains("events recorded"), "{cell}");
    assert!(
        !cell.contains("about") && !cell.contains("estimate"),
        "an exact count is not labelled an estimate: {cell}"
    );
    let row = events_row(&page);
    assert!(
        row.contains(r#"<span class="mono">37</span>"#) && !row.contains("estimate"),
        "{row}"
    );
}

/// Once statistics exist the page reads the estimate without scanning; the label is the same.
#[sqlx::test(migrations = false)]
async fn an_analyzed_ledger_past_the_cap_reads_the_planners_estimate(pool: PgPool) {
    migrate(&pool).await;
    bulk_events(&pool, 100_003).await;
    sqlx::query("ANALYZE event").execute(&pool).await.unwrap();
    let page = ledger_cell(pool).await;
    let cell = band(&page);
    assert!(cell.contains("events recorded (estimate)"), "{cell}");
    assert!(cell.contains("about 100"), "{cell}");
}

#[sqlx::test(migrations = false)]
async fn a_ledger_past_the_counting_cap_is_labelled_an_estimate(pool: PgPool) {
    migrate(&pool).await;
    bulk_events(&pool, 100_003).await;
    let page = ledger_cell(pool).await;
    let cell = band(&page);
    assert!(cell.contains("events recorded (estimate)"), "{cell}");
    let row = events_row(&page);
    assert!(
        row.contains("about ") && row.contains("(estimate)"),
        "the Evidence chain panel labels it too: {row}"
    );
    let shown = cell
        .split("about ")
        .nth(1)
        .unwrap_or_else(|| panic!("an estimate reads 'about N': {cell}"))
        .split('<')
        .next()
        .unwrap()
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("a number follows 'about': {cell}"));
    // Never below what was counted before falling back (a never-analyzed table's reltuples is -1).
    assert!(shown >= 100_001, "{shown}: {cell}");
}
