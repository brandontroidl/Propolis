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
        feed_output_dir: None,
        startup_time: chrono::Utc::now(),
        version: "test",
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(1000)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
