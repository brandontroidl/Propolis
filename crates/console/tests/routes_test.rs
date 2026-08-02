//! HTTP-level tests for the dashboard, review queue, login, IP detail, feed status, and metrics
//! pages (`internal/plans/2026-07-30-console-observability.md`, tasks 2-4) via axum's `oneshot`
//! test utilities - no real TCP listener.
//!
//! Each test runs against a fresh, isolated database (`#[sqlx::test(migrations = false)]`
//! provisions and later drops a per-test Postgres database; `migrate` below then applies
//! core-scoring's migrations followed by review's, matching `review/tests/queue_test.rs`'s own
//! two-crate migration order). Isolation-per-test matters here specifically because
//! `routes::dashboard`'s stats are UNSCOPED aggregates (`COUNT(*) FROM ip_score`, with no
//! per-IP filter) - a shared persistent database would make those assertions order- and
//! leftover-data-dependent.
//!
//! `routes::login`'s POST handler extracts the client IP via `ConnectInfo<SocketAddr>` (see that
//! module's doc comment); `oneshot` never populates real connection info, so every test router
//! here is layered with `MockConnectInfo`, axum's documented test-only substitute.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::{AppState, routes};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use http_body_util::BodyExt;
use review::queue::ReviewQueue;
use sqlx::{PgPool, Row};
use tower::ServiceExt;

const TEST_PASSWORD: &str = "s3cret-test-operator-password";
const TEST_PEER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 55555);

fn test_secret() -> [u8; 32] {
    [11u8; 32]
}

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
}

fn test_state(db: PgPool) -> AppState {
    test_state_with_feed_dir(db, None)
}

fn test_state_with_feed_dir(db: PgPool, feed_output_dir: Option<PathBuf>) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new(test_secret())),
        passwords: Arc::new(PasswordStore::new(TEST_PASSWORD)),
        login_rate_limiter: Arc::new(RateLimiter::default()),
        templates: Arc::new(console::templates::environment()),
        feed_output_dir,
        startup_time: chrono::Utc::now(),
        version: "test",
    }
}

/// The full composed router, layered with `MockConnectInfo` so `routes::login`'s
/// `ConnectInfo<SocketAddr>` extractor resolves under `oneshot` (see the module doc comment).
fn test_app(state: AppState) -> Router {
    routes::router(state).layer(MockConnectInfo(TEST_PEER))
}

async fn body_text(response: Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Like [`ev`] but with an explicit `wan_ip` - `routes::detail`'s per-WAN breakdown query
/// (`WHERE wan_ip IS NOT NULL`) has nothing to show for any event `ev` itself produces.
fn ev_with_wan(
    ip: &str,
    wan_ip: &str,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    ts: &str,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        Some(wan_ip.parse().unwrap()),
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        serde_json::json!({}),
    )
}

fn ev(
    ip: &str,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    ts: &str,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        serde_json::json!({}),
    )
}

/// Seeds an eligible + vendor-recommended `ip_score` projection: one confirmed-real honeypot login
/// plus two corroborating categories - raw 85 (clears the 75 STANDARD floor), max_confidence 0.920
/// (clears the 0.70 STANDARD floor) -> tier Standard -> recommended_for_vendor. Exactly
/// `review/tests/queue_test.rs`'s `seed_recommended` recipe (a proven, already-verified path to a
/// recommended projection, not reinvented scoring math), EXCEPT the timestamp is anchored
/// `seconds_ago` seconds before `Utc::now()` rather than a hardcoded historical date:
/// `core_scoring::read_score` (which `routes::queue` uses for display) decays raw_score to now with
/// a 6-HOUR half-life (`HALF_LIFE_SECONDS`), so a fixed date from whenever this fixture was written
/// decays to ~0 the moment enough real-world time has passed - caught by actually rendering a page
/// and reading the HTML rather than trusting a passing-but-undiscriminating assertion. Keep
/// `seconds_ago` well under 21600 (one half-life) so the decayed display values stay close to the
/// pre-decay raw ones.
async fn seed_recommended(pool: &PgPool, ip: &str, seconds_ago: i64) {
    let start = chrono::Utc::now() - chrono::Duration::seconds(seconds_ago);
    append_event(
        pool,
        ev(
            ip,
            "honeypot-sensor",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
            &start.to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    append_event(
        pool,
        ev(
            ip,
            "ssh-sensor",
            SignalType::SshBruteForce,
            Protocol::Tcp,
            true,
            &(start + chrono::Duration::seconds(10)).to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    append_event(
        pool,
        ev(
            ip,
            "catchall-sensor",
            SignalType::CatchallProbe,
            Protocol::Udp,
            false,
            &(start + chrono::Duration::seconds(20)).to_rfc3339(),
        ),
    )
    .await
    .unwrap();
}

fn form_request(uri: &str, body: String, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        builder = builder.header("cookie", c.to_string());
    }
    builder.body(Body::from(body)).unwrap()
}

fn get_request(uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(c) = cookie {
        builder = builder.header("cookie", c.to_string());
    }
    builder.body(Body::empty()).unwrap()
}

/// Extracts `"propolis_session=<value>"` from a login response's `set-cookie` header, ready to use
/// as-is for a subsequent request's `cookie` header.
fn extract_session_cookie(response: &Response) -> String {
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("login success must set a session cookie")
        .to_str()
        .unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

// --- dashboard ---

#[sqlx::test(migrations = false)]
async fn dashboard_authenticated_returns_stats(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.10", 60).await;
    seed_recommended(&pool, "203.0.113.11", 60).await;
    // A single event never clears eligibility (`event_count >= 2` is required), so this IP gets an
    // `ip_score` row but is never surfaced into `review_queue`. That deliberately splits
    // total_scored_ips (3) from pending_reviews (2) so the two stats cannot coincidentally match
    // and mask one being wired to the wrong query.
    append_event(
        &pool,
        ev(
            "203.0.113.12",
            "catchall-sensor",
            SignalType::CatchallProbe,
            Protocol::Udp,
            false,
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<div class="value">3</div>"#),
        "expected total_scored_ips=3 in the rendered stats: {body}"
    );
    assert!(
        body.contains(r#"<div class="value">2</div>"#),
        "expected pending_reviews=2 in the rendered stats: {body}"
    );
    assert!(
        body.contains(r#"<div class="value">0</div>"#),
        "expected approved_today=0 in the rendered stats: {body}"
    );
    assert!(body.contains("Dashboard"));
}

#[sqlx::test(migrations = false)]
async fn dashboard_unauthenticated_redirects_to_login(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

// --- queue ---

#[sqlx::test(migrations = false)]
async fn queue_lists_pending_entries(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.20", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/queue",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("203.0.113.20"), "pending IP missing: {body}");
    assert!(body.contains("Approve") && body.contains("Reject") && body.contains("Snooze"));
    // The rendered tier BADGE TEXT specifically (">Standard<"), not the bare word "standard" -
    // which trivially also appears in base.html's static `.tier-standard { ... }` CSS rule
    // regardless of any row's actual data. Caught by rendering a real page and reading the HTML:
    // the original looser assertion passed even when every row's tier badge showed "-" (decayed to
    // None) because it was matching the CSS, not the data - see `seed_recommended`'s doc comment.
    assert!(
        body.contains(">Standard<"),
        "no row rendered a Standard tier badge: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn approve_changes_state_verified_via_db(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.30", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool.clone());
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    let response = app
        .oneshot(form_request(
            "/queue/203.0.113.30/approve",
            format!("csrf_token={csrf_token}&notes=reviewed-ok"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("approved"),
        "row partial missing new state: {body}"
    );
    assert!(body.contains("reviewed-ok"));

    // Verified via DB, not just the HTTP response, per the task's explicit requirement.
    let row = sqlx::query("SELECT state, notes FROM review_queue WHERE source_ip = $1::inet")
        .bind("203.0.113.30")
        .fetch_one(&pool)
        .await
        .unwrap();
    let state: core_scoring::ReviewState = row.get("state");
    let notes: Option<String> = row.get("notes");
    assert_eq!(state, core_scoring::ReviewState::Approved);
    assert_eq!(notes.as_deref(), Some("reviewed-ok"));
}

#[sqlx::test(migrations = false)]
async fn reject_changes_state(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.31", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool.clone());
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    let response = app
        .oneshot(form_request(
            "/queue/203.0.113.31/reject",
            format!("csrf_token={csrf_token}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let row = sqlx::query("SELECT state FROM review_queue WHERE source_ip = $1::inet")
        .bind("203.0.113.31")
        .fetch_one(&pool)
        .await
        .unwrap();
    let state: core_scoring::ReviewState = row.get("state");
    assert_eq!(state, core_scoring::ReviewState::Rejected);
}

#[sqlx::test(migrations = false)]
async fn snooze_changes_state(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.32", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool.clone());
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    let response = app
        .oneshot(form_request(
            "/queue/203.0.113.32/snooze",
            format!("csrf_token={csrf_token}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let row = sqlx::query("SELECT state FROM review_queue WHERE source_ip = $1::inet")
        .bind("203.0.113.32")
        .fetch_one(&pool)
        .await
        .unwrap();
    let state: core_scoring::ReviewState = row.get("state");
    assert_eq!(state, core_scoring::ReviewState::Snoozed);
}

#[sqlx::test(migrations = false)]
async fn post_without_csrf_token_returns_403(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.33", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool.clone());
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(form_request(
            "/queue/203.0.113.33/approve",
            "csrf_token=not-the-real-token".to_string(),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // Fails closed: no state change on a rejected CSRF check.
    let row = sqlx::query("SELECT state FROM review_queue WHERE source_ip = $1::inet")
        .bind("203.0.113.33")
        .fetch_one(&pool)
        .await
        .unwrap();
    let state: core_scoring::ReviewState = row.get("state");
    assert_eq!(state, core_scoring::ReviewState::Pending);
}

#[sqlx::test(migrations = false)]
async fn queue_sort_by_first_seen_orders_oldest_first(pool: PgPool) {
    migrate(&pool).await;
    // Same recipe (same raw score) for both, so the DEFAULT (score) sort ties them; only
    // `sort=first_seen` distinguishes the order, proving the sort wiring actually runs a
    // different comparison rather than always returning surface order.
    seed_recommended(&pool, "203.0.113.40", 60).await; // later (first_seen ~60s ago)
    seed_recommended(&pool, "203.0.113.41", 3600).await; // earlier (first_seen ~1h ago)
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/queue?sort=first_seen",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;

    let earlier_pos = body.find("203.0.113.41").expect("earlier IP present");
    let later_pos = body.find("203.0.113.40").expect("later IP present");
    assert!(
        earlier_pos < later_pos,
        "sort=first_seen must put the earlier-first-seen IP first: {body}"
    );
}

// --- login ---

#[sqlx::test(migrations = false)]
async fn login_form_renders(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/login", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    // `name="password"`, not `type="password"`: base.html's shared CSS has an
    // `input[type="password"] { ... }` selector present on EVERY page, so asserting on
    // `type="password"` alone would pass even if login.html's actual `<input>` element were
    // missing entirely - `name="password"` appears only on the real form field.
    assert!(body.contains(r#"name="password""#));
    assert!(body.contains("Sign in"));
}

#[sqlx::test(migrations = false)]
async fn login_with_correct_password_creates_session_and_redirects(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(form_request(
            "/login",
            format!("password={TEST_PASSWORD}"),
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/");
    let cookie = extract_session_cookie(&response);
    assert!(cookie.starts_with(&format!("{}=", auth::SESSION_COOKIE)));
}

#[sqlx::test(migrations = false)]
async fn login_with_wrong_password_rerenders_with_error(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(form_request(
            "/login",
            "password=totally-wrong".to_string(),
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_text(response).await;
    assert!(body.contains("Invalid password"));
}

#[sqlx::test(migrations = false)]
async fn login_rate_limited_after_five_failed_attempts(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    for _ in 0..5 {
        let response = app
            .clone()
            .oneshot(form_request(
                "/login",
                "password=totally-wrong".to_string(),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let sixth = app
        .oneshot(form_request(
            "/login",
            "password=totally-wrong".to_string(),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(sixth.status(), StatusCode::TOO_MANY_REQUESTS);
}

// --- detail ---

#[sqlx::test(migrations = false)]
async fn detail_shows_events_for_seeded_ip(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.50", 60).await;
    // A distinct signal type from `seed_recommended`'s own fixed recipe (HoneypotLoginAttempt,
    // SshBruteForce, CatchallProbe), so this event's presence in the rendered page is
    // attributable specifically to THIS append, not to the seed's baseline events.
    append_event(
        &pool,
        ev_with_wan(
            "203.0.113.50",
            "198.51.100.9",
            "catchall-sensor",
            SignalType::PortScan,
            Protocol::Tcp,
            true,
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.50",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("203.0.113.50"),
        "IP missing from page: {body}"
    );
    assert!(
        body.contains("198.51.100.9"),
        "per-WAN breakdown missing the seeded WAN IP: {body}"
    );
    assert!(
        body.contains("PortScan"),
        "evidence timeline missing the added event's signal type: {body}"
    );
    assert!(
        body.contains(">Standard<"),
        "score summary missing the Standard tier badge: {body}"
    );
    assert!(
        body.contains("honeypot"),
        "category breakdown missing: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_unknown_ip_returns_404(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.99",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = false)]
async fn detail_unauthenticated_redirects_to_login(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(get_request("/ip/203.0.113.50", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

// --- feed ---

#[sqlx::test(migrations = false)]
async fn feed_page_shows_no_builds_when_unconfigured(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/feed",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains("No feed builds yet"));
}

#[sqlx::test(migrations = false)]
async fn feed_page_reads_manifest_correctly(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":3,"sha256":"deadbeef","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":11,"sha256":"cafef00d","valid_until":"2026-07-31T14:00:00Z"}}}"#,
    )
    .unwrap();

    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/feed",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("2026-07-29T14:00:00Z"),
        "missing build time: {body}"
    );
    assert!(
        body.contains(r#"class="mono">3</td>"#),
        "missing aggressive count: {body}"
    );
    assert!(
        body.contains(r#"class="mono">11</td>"#),
        "missing standard count: {body}"
    );
    assert!(
        body.contains("2026-07-30T14:00:00Z"),
        "missing aggressive valid_until: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn feed_unauthenticated_redirects_to_login(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/feed", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

// --- metrics ---

#[sqlx::test(migrations = false)]
async fn metrics_returns_prometheus_text_format(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.60", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool);
    let app = test_app(state);

    // No session cookie at all: a Prometheus scraper cannot complete an interactive login.
    let response = app.oneshot(get_request("/metrics", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let body = body_text(response).await;
    assert!(body.contains("# TYPE propolis_ips_scored gauge"));
    assert!(
        body.contains("propolis_ips_scored 1\n"),
        "expected exactly one scored IP: {body}"
    );
    assert!(
        body.contains("propolis_review_queue_pending 1\n"),
        "expected exactly one pending review entry: {body}"
    );
    assert!(body.contains("propolis_ips_recommended_vendor 1\n"));
}

#[sqlx::test(migrations = false)]
async fn metrics_includes_vendor_submissions_by_vendor_and_status(pool: PgPool) {
    migrate(&pool).await;
    sqlx::query(
        "INSERT INTO vendor_submission (source_ip, vendor, idempotency_key, categories, comment, success) \
         VALUES ($1::inet, $2, $3, $4, $5, $6)",
    )
    .bind("203.0.113.70")
    .bind("abuseipdb")
    .bind("key-1")
    .bind(vec!["18".to_string()])
    .bind("test comment")
    .bind(true)
    .execute(&pool)
    .await
    .unwrap();

    let state = test_state(pool);
    let app = test_app(state);
    let response = app.oneshot(get_request("/metrics", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(
            r#"propolis_vendor_submissions_total{vendor="abuseipdb",status="success"} 1"#
        ),
        "missing vendor submission metric line: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn metrics_includes_feed_entries_when_manifest_present(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":4,"sha256":"x","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":9,"sha256":"y","valid_until":"2026-07-31T14:00:00Z"}}}"#,
    )
    .unwrap();

    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
    let app = test_app(state);
    let response = app.oneshot(get_request("/metrics", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(body.contains(r#"propolis_feed_entries{tier="aggressive"} 4"#));
    assert!(body.contains(r#"propolis_feed_entries{tier="standard"} 9"#));
    // 2026-07-29T14:00:00Z as Unix seconds (`date -u -d "2026-07-29T14:00:00Z" +%s`) - an exact
    // value, not a loose prefix match, so a wrong parse (wrong field, wrong unit) cannot pass by
    // accident.
    assert!(
        body.contains("propolis_feed_last_build_timestamp 1785333600\n"),
        "missing or wrong last-build-timestamp gauge: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn metrics_omits_feed_entries_when_unconfigured(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);
    let response = app.oneshot(get_request("/metrics", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(!body.contains("propolis_feed_entries"));
}
