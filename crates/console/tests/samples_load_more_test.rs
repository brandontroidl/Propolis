//! The Samples list loads every spooled file once, in its ranked order, a load at a time: a digest
//! in two spools is listed once for each, and a sample gone from the spool since the page loaded
//! is reported rather than restarting the list.
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
        passwords: Arc::new(PasswordStore::new("samples-load-more-test")),
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

/// Each listed sample's digest and the spool its secondary line names, in order.
fn listed(body: &str) -> Vec<(String, String)> {
    body.split("<td class=\"s-hash stack-full\"><a class=\"mono\" href=\"/samples/")
        .skip(1)
        .map(|rest| {
            let sha = rest[..64].to_string();
            let sub = &rest[rest.find("<span class=\"c-sub\">").unwrap() + 20..];
            (sha, sub[..sub.find(',').unwrap()].to_string())
        })
        .collect()
}

fn load_more(body: &str) -> Option<String> {
    let at = body.find("<button hx-get=\"/samples/rows?")? + "<button hx-get=\"".len();
    Some(body[at..at + body[at..].find('"')?].to_string())
}

#[sqlx::test(migrations = false)]
async fn samples_load_every_spooled_file_once_in_order(pool: PgPool) {
    let root = tempfile::tempdir().unwrap();
    // SAFETY: set before anything reads it, and nothing else in this binary reads the environment.
    unsafe { std::env::set_var("PROPOLIS_SPOOL_ROOT", root.path()) };
    sqlx::migrate!("../core-scoring/migrations")
        .run(&pool)
        .await
        .unwrap();
    review::migrator().run(&pool).await.unwrap();
    fleet::migrator().run(&pool).await.unwrap();

    let mut digests: Vec<String> = (0..450)
        .map(|i| spool(root.path(), "ssh", format!("sample body {i}").as_bytes()))
        .collect();
    // The same two bodies in a second spool: listed once per spool, not once in all.
    for i in [3, 4] {
        digests.push(spool(
            root.path(),
            "fetched",
            format!("sample body {i}").as_bytes(),
        ));
    }

    let state = state(pool);
    let (_, cookie) = state.sessions.create();
    let app =
        routes::router(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5555))));

    let page = get(app.clone(), &cookie, "/samples").await;
    let mut rows = listed(&page);
    assert_eq!(rows.len(), 200);
    let mut next = load_more(&page).expect("a second load");
    let mut loads = 1;
    loop {
        let more = get(app.clone(), &cookie, &next).await;
        assert!(!more.contains("<html"), "a fragment, not a page: {more}");
        rows.extend(listed(&more));
        loads += 1;
        match load_more(&more) {
            Some(url) => next = url,
            None => break,
        }
    }
    assert_eq!(loads, 3, "200, 200, then the last 52");
    assert_eq!(rows.len(), 452, "every spooled file listed");
    let unique: std::collections::BTreeSet<&(String, String)> = rows.iter().collect();
    assert_eq!(unique.len(), 452, "and each once");
    // Nothing links these samples to a campaign, so the ranking falls to the digest.
    assert!(rows.windows(2).all(|w| w[0].0 <= w[1].0), "in digest order");

    let gone = get(
        app,
        &cookie,
        &format!("/samples/rows?after={}:ssh", "0".repeat(64)),
    )
    .await;
    assert!(
        gone.contains("no longer in a spool. Reload to continue."),
        "{gone}"
    );
    assert!(listed(&gone).is_empty());
}
