//! The console's heavy synchronous work must not hold an async worker.
//!
//! The console runs inside the daemon, so a handler that spends 200 ms in synchronous code is 200
//! ms of scheduling lag for the intake tailers, the review loops and every database statement
//! sharing those workers (sqlx times a statement until its task is polled again). The two pages
//! measured as worst are the IP evidence list (200 events with up to 64 KiB of captured body each,
//! pretty-printed and HTML-escaped) and the feed Entries tab (a published feed of up to 50,000
//! entries read back and parsed).
//!
//! The events carry session ids (20 sessions of 10 events), as sensor traffic does: without them
//! the session-tag lookup returns before its first await and everything after the row build is
//! already off the worker whatever the handler does, so the fold and the render would go
//! unguarded. The tests pin the `core_scoring::off_worker` sites that can hold a worker past the
//! 100 ms bound: the evidence row build and both detail renders in `routes/detail.rs`, and the two
//! feed reads in `routes/feed.rs`; inlining one of those fails the test that requests it. The
//! group and fold steps in `routes/detail.rs` stay under 100 ms even on the worst page, and the
//! feed page render runs after the Entries read has already left the worker, so those sites are
//! deliberately not guarded here.
//!
//! Each test serves the request on a runtime with ONE worker and watches a ticker task on it: a
//! handler that keeps the worker for its CPU work freezes the ticker for that long, one that hands
//! the worker's queue to another thread (`core_scoring::off_worker`) does not. The runtime is the
//! test's own because `#[sqlx::test]` runs on a current-thread runtime, where there is no second
//! thread to hand to and the ticker would be starved whatever the handler did.
//!
//! Every address is RFC 5737 documentation space.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use http_body_util::BodyExt;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

const PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 55555);

/// The longest the ticker may go unpolled while a request is served. The worst page costs 150-250
/// ms of CPU on the development host, so a handler that holds the worker blows through this; the
/// handoff itself costs well under a millisecond.
const MAX_GAP: Duration = Duration::from_millis(100);

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

fn state(db: PgPool, feed_output_dir: Option<std::path::PathBuf>) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([11u8; 32])),
        passwords: Arc::new(PasswordStore::new("render-test-password")),
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        geoip: Arc::new(geoip::GeoIp::disabled()),
        rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
        feed_output_dir,
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
    }
}

/// Serves `uri` once on a one-worker runtime of its own, returning the body and the longest gap the
/// ticker task saw between two polls while the request was in flight.
fn serve_watching_ticker(
    opts: sqlx::postgres::PgConnectOptions,
    feed_dir: Option<std::path::PathBuf>,
    uri: String,
) -> (String, Duration) {
    // A thread of its own: `block_on` cannot run inside the harness's runtime.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let db = PgPoolOptions::new()
                .max_connections(4)
                .connect_with(opts)
                .await
                .unwrap();
            let state = state(db, feed_dir);
            let (_, cookie) = state.sessions.create();
            let app = routes::router(state).layer(MockConnectInfo(PEER));

            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worst_us = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let ticker = tokio::spawn({
                let (stop, worst_us) = (stop.clone(), worst_us.clone());
                async move {
                    let mut last = Instant::now();
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        let now = Instant::now();
                        worst_us.fetch_max(
                            (now - last).as_micros() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        last = now;
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Forget the ticker's start-up gaps; only the request's window counts.
            worst_us.store(0, std::sync::atomic::Ordering::Relaxed);

            // As a task, so the handler runs on the worker: `block_on`'s own future runs on this
            // thread and would hide a handler that never yields it.
            let (cookie, uri) = (cookie.clone(), uri.clone());
            let body = tokio::spawn(async move {
                let response = app
                    .oneshot(
                        Request::builder()
                            .uri(&uri)
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
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            ticker.await.unwrap();
            (
                body,
                Duration::from_micros(worst_us.load(std::sync::atomic::Ordering::Relaxed)),
            )
        })
    })
    .join()
    .unwrap()
}

/// 200 events of the largest body a sensor keeps (64 KiB, in the characters the escaper rewrites)
/// in 20 sessions of 10: the worst page an attacker can make an operator open.
async fn seed_sessions(pool: &PgPool, ip: &str) {
    let body = "<a href=\"x\">&'\n\t".repeat(4096);
    let ids: Vec<uuid::Uuid> = (0..20).map(|_| uuid::Uuid::now_v7()).collect();
    for i in 0..200usize {
        append_event(
            pool,
            EventInput::from_signal(
                ip.parse().unwrap(),
                None,
                "http".into(),
                SignalType::HoneypotCommandExec,
                Protocol::Tcp,
                false,
                chrono::Utc::now() - chrono::Duration::seconds(i as i64),
                serde_json::json!({ "command": "POST /", "body": body, "n": i }),
                Some(ids[i / 10]),
            ),
        )
        .await
        .unwrap();
    }
}

/// A published feed directory with `entries` (the most a feed holds is 50,000) in both tiers. The
/// addresses repeat, which the reader does not mind.
fn write_feed(entries: usize) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let valid_until = "2026-10-15T12:00:00Z";
    std::fs::write(
        dir.path().join("manifest.json"),
        serde_json::json!({
            "build_time": "2026-10-14T12:00:00Z",
            "tiers": {
                "aggressive": { "count": entries, "valid_until": valid_until },
                "standard": { "count": entries, "valid_until": valid_until },
            },
        })
        .to_string(),
    )
    .unwrap();
    let entries: Vec<serde_json::Value> = (0..entries)
        .map(|i| {
            serde_json::json!({
                "ip": format!("192.0.2.{}", i % 250),
                "first_seen": "2026-10-14T12:00:00Z",
                "last_seen": "2026-10-14T12:00:00Z",
                "events": 10,
                "signals": ["ssh_brute_force", "honeypot_command_exec"],
            })
        })
        .collect();
    let doc = serde_json::json!({ "entries": entries }).to_string();
    std::fs::write(dir.path().join("aggressive.json"), &doc).unwrap();
    std::fs::write(dir.path().join("standard.json"), &doc).unwrap();
    dir
}

#[sqlx::test(migrations = false)]
async fn the_evidence_fragment_does_not_hold_the_async_worker(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.50";
    seed_sessions(&pool, ip).await;
    let (html, gap) = serve_watching_ticker(
        (*pool.connect_options()).clone(),
        None,
        format!("/ip/{ip}/events?cursor=2099-01-01T00:00:00.000000Z,9223372036854775807"),
    );
    assert!(
        html.len() > 5_000_000,
        "the page must really carry the large captures ({} bytes)",
        html.len()
    );
    assert!(
        gap < MAX_GAP,
        "the evidence fragment held the only async worker for {gap:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_full_detail_page_does_not_hold_the_async_worker(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.52";
    seed_sessions(&pool, ip).await;
    let (html, gap) =
        serve_watching_ticker((*pool.connect_options()).clone(), None, format!("/ip/{ip}"));
    assert!(
        html.len() > 5_000_000,
        "the page must really carry the large captures ({} bytes)",
        html.len()
    );
    assert!(
        gap < MAX_GAP,
        "the full detail page held the only async worker for {gap:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn a_full_size_published_feed_does_not_hold_the_async_worker(pool: PgPool) {
    migrate(&pool).await;
    let dir = write_feed(50_000);
    let (html, gap) = serve_watching_ticker(
        (*pool.connect_options()).clone(),
        Some(dir.path().to_path_buf()),
        "/feed/entries/aggressive".to_string(),
    );
    assert!(html.contains("192.0.2."), "the load must render entries");
    assert!(
        gap < MAX_GAP,
        "the feed entries load held the only async worker for {gap:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_feed_page_entries_tab_does_not_hold_the_async_worker(pool: PgPool) {
    migrate(&pool).await;
    let dir = write_feed(50_000);
    let (html, gap) = serve_watching_ticker(
        (*pool.connect_options()).clone(),
        Some(dir.path().to_path_buf()),
        "/feed?tab=entries".to_string(),
    );
    assert!(html.contains("192.0.2."), "the tab must render entries");
    assert!(
        gap < MAX_GAP,
        "the feed page's entries tab held the only async worker for {gap:?}"
    );
}
