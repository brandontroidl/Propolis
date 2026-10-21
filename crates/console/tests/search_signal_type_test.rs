//! The search page's signal-type filter and menu, through the route: what an operator sees. The
//! statements' plans are held in `ledger_scan_test.rs`.
//!
//! Each test runs on its own database; every address is RFC 5737 documentation space.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

const PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 55555);

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

fn state(db: PgPool) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([17u8; 32])),
        passwords: Arc::new(PasswordStore::new("search-signal-type-test-password")),
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip: Arc::new(geoip::GeoIp::disabled()),
        rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
        feed_output_dir: None,
        fleet_listeners: Arc::new(Vec::new()),
        fleet_probe_interval: Duration::from_secs(300),
        deploy_stamp_path: None,
        startup_time: chrono::Utc::now(),
        binary_name: "console",
        version: "test",
        git_sha: "abc123abc123",
        built_at: "2026-09-09T00:00:00Z",
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(100)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: false,
        metrics_token: None,
        gave_up_subsystems: console::no_subsystem_health(),
        intake_lag: console::intake_lag::no_intake_lag(),
        read_state: console::read_state::ReadState::uncached(),
    }
}

async fn get(pool: &PgPool, uri: &str) -> String {
    let state = state(pool.clone());
    let (_, cookie) = state.sessions.create();
    let response = routes::router(state)
        .layer(MockConnectInfo(PEER))
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

async fn put_event(pool: &PgPool, ip: &str, signal: &str) {
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         VALUES ($1::inet, 'ssh', $2::signal_type_enum, 'tcp', false, 'honeypot', 1, 0.5, \
                 now() - interval '5 minutes', '{}'::jsonb, \
                 sha256(convert_to(gen_random_uuid()::text, 'UTF8')))",
    )
    .bind(ip)
    .bind(signal)
    .execute(pool)
    .await
    .unwrap();
}

/// The menu offers the signal types the ledger holds, sorted by name as the `DISTINCT` it replaced
/// sorted them: a type with no events is not offered, as it never was, and appears when the first
/// event of it does. `port_scan` precedes `honeypot_session_end` in the enum and follows it
/// alphabetically, so only the alphabetical order passes.
#[sqlx::test(migrations = false)]
async fn the_menu_offers_the_signal_types_the_ledger_holds(pool: PgPool) {
    migrate(&pool).await;
    put_event(&pool, "203.0.113.5", "port_scan").await;
    put_event(&pool, "203.0.113.6", "honeypot_session_end").await;

    let page = get(&pool, "/search/events").await;
    let session_end = page.find(r#"<option value="honeypot_session_end""#);
    let port_scan = page.find(r#"<option value="port_scan""#);
    assert!(
        session_end.is_some() && port_scan.is_some() && session_end < port_scan,
        "both held types, alphabetically: {page}"
    );
    assert!(
        !page.contains(r#"<option value="syn_flood""#),
        "a type with no events is not offered: {page}"
    );

    put_event(&pool, "203.0.113.7", "syn_flood").await;
    let page = get(&pool, "/search/events").await;
    assert!(page.contains(r#"<option value="syn_flood""#), "{page}");
}

/// A signal type that exists finds its events, one that no event carries finds nothing, and a name
/// that is not a signal type finds nothing too (it must not reach the database as an enum value,
/// which would be an error) in both search modes.
#[sqlx::test(migrations = false)]
async fn the_filter_finds_a_type_and_tolerates_an_absent_or_unknown_one(pool: PgPool) {
    migrate(&pool).await;
    put_event(&pool, "203.0.113.5", "honeypot_login_attempt").await;
    put_event(&pool, "203.0.113.6", "honeypot_connection").await;

    for (mode, ip_in_results) in [("events", "203.0.113.5"), ("ips", "203.0.113.5")] {
        let found = get(
            &pool,
            &format!("/search/{mode}?signal_type=honeypot_login_attempt"),
        )
        .await;
        assert!(found.contains(ip_in_results), "{mode}: {found}");
        assert!(
            !found.contains("203.0.113.6"),
            "{mode} only the chosen type: {found}"
        );
        for name in ["syn_flood", "not_a_signal_type", "HONEYPOT_CONNECTION"] {
            let none = get(&pool, &format!("/search/{mode}?signal_type={name}")).await;
            assert!(
                !none.contains("203.0.113.5") && !none.contains("203.0.113.6"),
                "{mode} {name}: {none}"
            );
        }
    }
}
