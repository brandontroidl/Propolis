//! Auth primitives (password, session, CSRF, rate limiter), the auth middleware, and the
//! health/readiness routes for sub-project 6 task 1
//! (`internal/plans/2026-07-30-console-observability.md`). Per that plan's global constraints,
//! auth tests are pure (no DB); `/ready` is the one exception, needing a real Postgres connection,
//! and uses `#[sqlx::test]` like the rest of the workspace.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Router, middleware};
use console::auth::{PasswordStore, RateLimiter, SessionStore};
use console::{AppState, auth, routes};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

fn test_secret() -> [u8; 32] {
    [7u8; 32]
}

/// A pool that never actually dials Postgres. Fine for tests that never touch `state.db` (`/health`,
/// the auth middleware): `connect_lazy` defers connecting until first use.
fn lazy_pool() -> PgPool {
    PgPool::connect_lazy("postgres://unused@localhost/unused").expect("lazy pool never connects")
}

fn test_state(db: PgPool) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new(test_secret())),
        passwords: Arc::new(PasswordStore::new("correct horse battery staple")),
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
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(1000)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: false,
        metrics_token: None,
        gave_up_subsystems: console::no_subsystem_health(),
    }
}

// --- PasswordStore ---

#[test]
fn password_hash_and_verify() {
    let store = PasswordStore::new("correct horse battery staple");
    assert!(store.verify("correct horse battery staple"));
}

#[test]
fn wrong_password_rejected() {
    let store = PasswordStore::new("correct horse battery staple");
    assert!(!store.verify("wrong password"));
}

// --- SessionStore ---

#[test]
fn session_create_and_validate() {
    let store = SessionStore::new(test_secret());
    let (id, cookie) = store.create();
    let session = store
        .validate(&cookie)
        .expect("valid cookie should validate");
    assert_eq!(session.id, id);
}

#[test]
fn expired_session_rejected() {
    // Zero TTL: expires_at == created_at, and Instant::now() by the time validate() runs is
    // strictly later, so this is deterministic with no sleep.
    let store = SessionStore::with_ttl(test_secret(), Duration::ZERO);
    let (_, cookie) = store.create();
    assert!(store.validate(&cookie).is_none());
}

#[test]
fn tampered_cookie_rejected() {
    let store = SessionStore::new(test_secret());
    let (_, cookie) = store.create();
    let mut tampered = cookie.clone();
    let flipped = if tampered.ends_with('0') { '1' } else { '0' };
    tampered.pop();
    tampered.push(flipped);
    assert!(store.validate(&tampered).is_none());
}

#[test]
fn hmac_valid_but_unknown_session_rejected() {
    // Two independent stores sharing a secret: the cookie's HMAC tag verifies fine under
    // `verifier`'s copy of the secret, but `verifier`'s session map never saw this session created.
    let secret = test_secret();
    let issuer = SessionStore::new(secret);
    let verifier = SessionStore::new(secret);
    let (_, cookie) = issuer.create();
    assert!(verifier.validate(&cookie).is_none());
}

#[test]
fn destroyed_session_rejected() {
    // Logout must invalidate server-side, not just clear the client cookie: a session that has
    // been destroyed must fail validation even though the cookie's HMAC tag is still perfectly
    // valid (unlike `tampered_cookie_rejected`, nothing here is corrupted - the session was
    // deliberately ended).
    let store = SessionStore::new(test_secret());
    let (id, cookie) = store.create();
    store.destroy(&id);
    assert!(store.validate(&cookie).is_none());
}

#[test]
fn destroying_unknown_session_is_a_no_op() {
    // Logout is idempotent: hitting it twice, or with a cookie for a session that already expired
    // or never existed, must not panic.
    let store = SessionStore::new(test_secret());
    store.destroy("no-such-session");
}

// --- CSRF ---

#[test]
fn csrf_generate_and_validate_roundtrip() {
    let store = SessionStore::new(test_secret());
    let (id, _) = store.create();
    let token = store.generate_csrf(&id).expect("session exists");
    assert!(store.validate_csrf(&id, &token));
}

#[test]
fn csrf_invalid_token_rejected() {
    let store = SessionStore::new(test_secret());
    let (id, _) = store.create();
    store.generate_csrf(&id).unwrap();
    assert!(!store.validate_csrf(&id, "not-the-real-token"));
}

#[test]
fn csrf_for_unknown_session_returns_none() {
    let store = SessionStore::new(test_secret());
    assert!(store.generate_csrf("no-such-session").is_none());
}

#[test]
fn csrf_token_stable_across_calls() {
    // Re-rendering a page must not invalidate a CSRF token already embedded in another open form.
    let store = SessionStore::new(test_secret());
    let (id, _) = store.create();
    let first = store.generate_csrf(&id).unwrap();
    let second = store.generate_csrf(&id).unwrap();
    assert_eq!(first, second);
}

// --- RateLimiter ---

#[test]
fn rate_limiter_blocks_after_five() {
    let limiter = RateLimiter::new(5, Duration::from_secs(60));
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)); // RFC5737 TEST-NET-2
    for _ in 0..5 {
        assert!(limiter.check(ip));
    }
    assert!(!limiter.check(ip));
}

#[test]
fn rate_limiter_reset_allows_again() {
    let limiter = RateLimiter::new(5, Duration::from_secs(60));
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
    for _ in 0..5 {
        assert!(limiter.check(ip));
    }
    assert!(!limiter.check(ip));
    limiter.reset(ip);
    assert!(limiter.check(ip));
}

#[test]
fn rate_limiter_tracks_ips_independently() {
    let limiter = RateLimiter::new(5, Duration::from_secs(60));
    let a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    let b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    for _ in 0..5 {
        assert!(limiter.check(a));
    }
    assert!(!limiter.check(a));
    assert!(limiter.check(b));
}

// --- /health, /ready ---

#[tokio::test]
async fn health_returns_200() {
    let app = routes::router(test_state(lazy_pool()));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], br#"{"status":"ok"}"#);
}

#[sqlx::test]
async fn ready_returns_200_when_db_up(pool: PgPool) {
    let app = routes::router(test_state(pool));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test]
async fn ready_returns_503_when_db_down(pool: PgPool) {
    pool.close().await;
    let app = routes::router(test_state(pool));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// A live database is not readiness: a daemon whose intake or a sensor tailer has exhausted its
/// restarts is serving pages while collecting nothing. `/ready` must say so, naming the dead
/// subsystems, so a probe that only saw "DB up" cannot call it ready.
#[sqlx::test]
async fn ready_returns_503_naming_subsystems_that_gave_up(pool: PgPool) {
    let mut state = test_state(pool);
    state.gave_up_subsystems = Arc::new(|| vec!["intake:ssh", "fetcher"]);
    let app = routes::router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        &body[..],
        br#"{"gave_up":["intake:ssh","fetcher"],"status":"unavailable"}"#
    );
}

// --- auth middleware ---
//
// Task 1 has no protected production routes yet (see `routes::mod`'s doc comment), so this
// exercises `auth::require_session` directly against a purpose-built router, the same way it will
// eventually be applied to the real `protected` group in task 2.

fn protected_test_router(state: AppState) -> Router {
    Router::new()
        .route("/protected", get(|| async { "ok" }))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ))
        .with_state(state)
}

#[tokio::test]
async fn unauthenticated_request_redirects_to_login() {
    let app = protected_test_router(test_state(lazy_pool()));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

/// An expired session on a POLLED page is the ordinary case after any restart: sessions live in
/// memory, a restart clears them, and the page keeps polling. A 303 is wrong there - the XHR
/// follows it, `/login` answers 200 with a whole HTML document, and HTMX swaps that document into
/// the container that issued the poll. The result looks like a success to HTMX, so the panel never
/// warns and never recovers; it silently becomes a login form inside the old page's chrome.
///
/// Reproduced live on a deployed box after `deploy/upgrade.sh` restarted the daemon: the fleet
/// pane's `#fleet-status` ended up holding `<html>`, `<head>`, a password input and a second copy
/// of the vendored Chart.js.
#[tokio::test]
async fn an_htmx_request_without_a_session_is_told_to_navigate_not_handed_a_page_to_swap() {
    let app = protected_test_router(test_state(lazy_pool()));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                // What HTMX sets on every request it issues.
                .header("HX-Request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "an unauthenticated API-shaped request deserves a truthful status"
    );
    assert_eq!(
        response.headers().get("hx-redirect").unwrap(),
        "/login",
        "HTMX must be told to navigate; it honours this header whatever the status"
    );
    assert!(
        response.headers().get("location").is_none(),
        "a 303 is what the XHR would follow into a swappable document"
    );

    // The body is the actual hazard: anything swappable here lands inside the polling container.
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(
        !text.contains("<html") && !text.contains("<form"),
        "the response must carry nothing HTMX could swap into the page, got: {text}"
    );
}

/// The ordinary browser navigation keeps its redirect - only HTMX requests change.
#[tokio::test]
async fn a_plain_navigation_without_a_session_still_redirects() {
    let app = protected_test_router(test_state(lazy_pool()));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
    assert!(response.headers().get("hx-redirect").is_none());
}

#[tokio::test]
async fn valid_session_passes_middleware() {
    let state = test_state(lazy_pool());
    let (_, cookie) = state.sessions.create();
    let app = protected_test_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("cookie", format!("{}={cookie}", auth::SESSION_COOKIE))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn invalid_session_cookie_redirects_to_login() {
    let state = test_state(lazy_pool());
    let app = protected_test_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header("cookie", format!("{}=garbage", auth::SESSION_COOKIE))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}
