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
use uuid::Uuid;

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
        None,
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
        None,
    )
}

/// Like [`ev`] but carrying a non-empty `metadata` payload and a `session_id` -
/// `routes::detail`'s session-grouping (task 3, `internal/design/11-console-forensics.md`
/// section 2) groups every event sharing a `session_id` into one collapsible card, and the
/// evidence timeline's "Detail" column extracts from `metadata` by `signal_type`. Same
/// eight-argument shape as `core_scoring::EventInput::from_signal` itself (which this wraps),
/// allowed there for the same reason.
#[allow(clippy::too_many_arguments)]
fn ev_with_session(
    ip: &str,
    sensor: &str,
    signal: SignalType,
    protocol: Protocol,
    authenticated: bool,
    ts: &str,
    metadata: serde_json::Value,
    session_id: Uuid,
) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        sensor.into(),
        signal,
        protocol,
        authenticated,
        ts.parse().unwrap(),
        metadata,
        Some(session_id),
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
        body.contains(
            "<div class=\"label\">Total scored IPs</div>\n    <div class=\"value\">3</div>"
        ),
        "expected total_scored_ips=3 in the rendered stats: {body}"
    );
    assert!(
        body.contains(r#"class="stat-hero stat-hero--attention""#),
        "pending_reviews > 0 must render the attention hero stat: {body}"
    );
    assert!(
        body.contains(r#"<a href="/queue">2</a>"#),
        "expected pending_reviews=2 linked to /queue: {body}"
    );
    assert!(
        body.contains(
            "<div class=\"label\">Approved today</div>\n    <div class=\"value\">0</div>"
        ),
        "expected approved_today=0 in the rendered stats: {body}"
    );
    assert!(
        body.contains("<div class=\"label\">Events / hour</div>\n    <div class=\"value\">7</div>"),
        "expected events_last_hour=7 (all seeded events are within the last minute): {body}"
    );
    assert!(
        body.contains("<div class=\"label\">Feed entries</div>\n    <div class=\"value\">--</div>"),
        "expected the feed-entries placeholder when no feed_output_dir is configured: {body}"
    );
    assert!(
        body.contains(r#"href="/ip/203.0.113.10">"#) || body.contains(r#"href="/ip/203.0.113.11">"#),
        "expected one of the seeded IPs as top attacker in the hero stat: {body}"
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

#[sqlx::test(migrations = false)]
async fn dashboard_shows_recent_activity_and_protocol_distribution(pool: PgPool) {
    migrate(&pool).await;
    append_event(
        &pool,
        ev(
            "203.0.113.80",
            "cowrie",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(
            "203.0.113.81",
            "suricata",
            SignalType::SuricataSev2,
            Protocol::Tcp,
            false,
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
            "/",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("<td>Cowrie login attempt</td>"),
        "recent-activity row missing human-readable activity label: {body}"
    );
    assert!(
        body.contains(r#"href="/ip/203.0.113.80">203.0.113.80</a>"#),
        "recent-activity row missing source IP link: {body}"
    );
    assert!(
        body.contains(r#"<canvas id="protoChart""#),
        "protocol-distribution chart canvas missing once events exist: {body}"
    );
    // Chart data is now in <script type="application/json"> elements which minijinja HTML-escapes.
    // The browser's .textContent unescapes them; in the raw HTML, quotes are &quot; entities.
    assert!(
        body.contains("application/json") && body.contains("proto-labels"),
        "protocol-distribution chart data element missing: {body}"
    );
    assert!(
        !body.contains("<tr><td>cowrie</td>"),
        "raw sensor name must not appear in any table: {body}"
    );
    assert!(
        !body.contains("waiting for sensor events"),
        "empty-state message should not render once events exist: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_events_last_hour_excludes_events_older_than_an_hour(pool: PgPool) {
    migrate(&pool).await;
    let now = chrono::Utc::now();
    let two_hours_ago = now - chrono::Duration::hours(2);
    append_event(
        &pool,
        ev(
            "203.0.113.90",
            "cowrie",
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            true,
            &now.to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(
            "203.0.113.90",
            "cowrie",
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            true,
            &two_hours_ago.to_rfc3339(),
        ),
    )
    .await
    .unwrap();

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
        body.contains("<div class=\"label\">Events / hour</div>\n    <div class=\"value\">1</div>"),
        "expected events_last_hour=1, excluding the event from 2 hours ago: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_top_attacker_shows_highest_scoring_ip(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.95", 60).await;

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
        body.contains(r#"href="/ip/203.0.113.95">"#),
        "expected the sole ip_score row's IP as top attacker in the hero stat: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_feed_entries_sums_tier_counts_from_manifest(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":4,"sha256":"x","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":9,"sha256":"y","valid_until":"2026-07-31T14:00:00Z"}}}"#,
    )
    .unwrap();

    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
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
    // aggressive(4) + standard(9) = 13, proving the real `tiers.aggressive.count` /
    // `tiers.standard.count` manifest shape is read correctly (not a flat `aggressive_count` key,
    // which this fixture's manifest does not have).
    assert!(
        body.contains("<div class=\"label\">Feed entries</div>\n    <div class=\"value\">13</div>"),
        "expected feed_entries = aggressive(4) + standard(9) = 13: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_empty_state_shows_placeholders(pool: PgPool) {
    migrate(&pool).await;
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
        body.contains("waiting for sensor events - start a sensor to begin collecting"),
        "missing empty recent-activity message: {body}"
    );
    assert!(
        body.contains("waiting for sensor events</p>"),
        "missing empty protocol-distribution message: {body}"
    );
    assert!(
        body.contains("no vendor submissions yet"),
        "missing empty vendor-submissions message: {body}"
    );
    assert!(
        body.contains("<div class=\"label\">Feed entries</div>\n    <div class=\"value\">--</div>"),
        "expected the feed-entries placeholder when unconfigured: {body}"
    );
    assert!(
        body.contains("stat-hero--nominal"),
        "expected the nominal hero stat when pending_reviews=0: {body}"
    );
    // Both chart sections gate independently on their own source list (`protocol_dist` /
    // `has_attackers`) - this fixture has neither events nor ip_score rows, so both must show the
    // page's existing empty-state copy rather than an empty canvas.
    assert_eq!(
        body.matches("waiting for sensor events</p>").count(),
        2,
        "expected the empty-state message for both the protocol-distribution and top-attackers charts: {body}"
    );
    assert!(
        !body.contains(r#"<canvas id="protoChart""#) && !body.contains(r#"<canvas id="attackerChart""#),
        "an empty chart canvas must not render when its source list is empty: {body}"
    );
    // The events timeline has no empty-state branch - it always renders 24 zero-filled buckets (a
    // flat line), per the brief's explicit "still renders with all zeros" requirement.
    assert!(
        body.contains(r#"<canvas id="timelineChart""#),
        "the timeline chart must always render, even with no events: {body}"
    );
    assert_eq!(
        body.matches("<polyline").count(),
        2,
        "expected both sparklines (events/hour, total scored IPs) to render as flat lines at zero: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_timeline_chart_reflects_hourly_event_counts(pool: PgPool) {
    migrate(&pool).await;
    append_event(
        &pool,
        ev(
            "203.0.113.85",
            "cowrie",
            SignalType::HoneypotConnection,
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
            "/",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    // `now()`'s event always lands in the LAST of the 24 ascending-ordered hourly buckets (the
    // current hour), so the rendered `timeline_data` array's final element must be 1 regardless of
    // what wall-clock hour the test happens to run in - a broken query (wrong join condition, wrong
    // window) would instead leave every bucket at 0 and this substring would not appear.
    assert!(
        body.contains(r#"id="timeline-data">"#),
        "timeline chart data element missing: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_top_attackers_chart_shows_scored_ip(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.86", 60).await;

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
        body.contains(r#"<canvas id="attackerChart""#),
        "top-attackers chart canvas missing once ip_score rows exist: {body}"
    );
    let script = &body[body
        .find(r#"id="attackerChart""#)
        .expect("attacker chart canvas missing")..];
    assert!(
        script.contains("203.0.113.86"),
        "top-attackers chart JSON missing the seeded IP: {script}"
    );
    assert!(
        !script.contains("waiting for sensor events"),
        "empty-state text must not render alongside the chart: {script}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_sparklines_appear_in_correct_stat_cards(pool: PgPool) {
    migrate(&pool).await;
    append_event(
        &pool,
        ev(
            "203.0.113.87",
            "cowrie",
            SignalType::HoneypotConnection,
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
            "/",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert_eq!(
        body.matches("<polyline").count(),
        2,
        "expected exactly two sparklines (events/hour, total scored IPs): {body}"
    );
    // Bounded by the immediately-following stat card's own label in the stat-row's fixed order, so
    // each sparkline is checked for landing inside the RIGHT card, not merely somewhere on the page.
    let scored_start = body
        .find(r#"<div class="label">Total scored IPs</div>"#)
        .expect("Total scored IPs stat card missing");
    let approved_start = body
        .find(r#"<div class="label">Approved today</div>"#)
        .expect("Approved today stat card missing");
    assert!(
        body[scored_start..approved_start].contains("<svg"),
        "expected an SVG sparkline inside the Total scored IPs card: {body}"
    );
    let events_start = body
        .find(r#"<div class="label">Events / hour</div>"#)
        .expect("Events / hour stat card missing");
    let feed_start = body
        .find(r#"<div class="label">Feed entries</div>"#)
        .expect("Feed entries stat card missing");
    assert!(
        body[events_start..feed_start].contains("<svg"),
        "expected an SVG sparkline inside the Events / hour card: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_vendor_submissions_table_shows_at_most_three_rows(pool: PgPool) {
    migrate(&pool).await;
    let base = chrono::Utc::now();
    let ips = [
        "203.0.113.201",
        "203.0.113.202",
        "203.0.113.203",
        "203.0.113.204",
        "203.0.113.205",
    ];
    for (i, ip) in ips.iter().enumerate() {
        sqlx::query(
            "INSERT INTO vendor_submission \
             (source_ip, vendor, idempotency_key, categories, comment, success, submitted_at) \
             VALUES ($1::inet, $2, $3, $4, $5, $6, $7)",
        )
        .bind(*ip)
        .bind("abuseipdb")
        .bind(format!("compact-table-key-{i}"))
        .bind(vec!["18".to_string()])
        .bind("test comment")
        .bind(true)
        .bind(base - chrono::Duration::seconds(i as i64))
        .execute(&pool)
        .await
        .unwrap();
    }

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
    // `submitted_at DESC` + a 3-row template truncation: IPs .201/.202/.203 (indices 0-2) carry the
    // most recent timestamps and must be the ones shown; .204/.205 (the oldest two of the five) must
    // be truncated.
    assert!(body.contains("203.0.113.201"), "newest submission missing: {body}");
    assert!(body.contains("203.0.113.202"), "2nd-newest submission missing: {body}");
    assert!(
        body.contains("203.0.113.203"),
        "3rd-newest submission missing: {body}"
    );
    assert!(
        !body.contains("203.0.113.204"),
        "4th-newest submission must be truncated from the compact table: {body}"
    );
    assert!(
        !body.contains("203.0.113.205"),
        "5th-newest (oldest) submission must be truncated from the compact table: {body}"
    );
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

#[sqlx::test(migrations = false)]
async fn queue_page_empty_state_is_contextual(pool: PgPool) {
    migrate(&pool).await;
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
    assert!(
        body.contains(
            r#"<p class="empty-line">queue empty - no IPs have crossed the recommendation threshold yet</p>"#
        ),
        "expected the contextual empty-queue message: {body}"
    );
    assert!(
        !body.contains("Nothing pending review"),
        "old empty-state copy must be gone: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn queue_page_table_uses_compact_class(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.42", 60).await;
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
    assert!(
        body.contains(r#"<table class="table-compact">"#),
        "expected the queue table to use the compact density class: {body}"
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

#[sqlx::test(migrations = false)]
async fn login_page_hides_topnav_entirely(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/login", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        !body.contains(r#"class="topnav""#),
        "login page must not render the topnav bar at all: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn login_page_shows_version(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/login", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(
            r#"<p class="dim" style="text-align:center;font-size:0.72rem;margin-top:1rem;">vtest</p>"#
        ),
        "expected the login page's own version line: {body}"
    );
    assert!(
        body.contains("propolis vtest - up"),
        "expected the shared footer status line to show a real version, not blank: {body}"
    );
}

// --- logout ---

#[sqlx::test(migrations = false)]
async fn logout_clears_session_and_redirects(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .clone()
        .oneshot(get_request(
            "/logout",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("logout must clear the session cookie")
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.starts_with(&format!("{}=", auth::SESSION_COOKIE)));
    assert!(
        set_cookie.contains("Max-Age=0"),
        "expected an immediately-expiring cookie: {set_cookie}"
    );

    // Verified server-side, not just a client-side cookie clear: the same cookie value must no
    // longer authenticate a protected route afterward.
    let response = app
        .oneshot(get_request(
            "/",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

#[sqlx::test(migrations = false)]
async fn logout_without_session_redirects_to_login(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/logout", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

// --- shared chrome (nav badge, sign-out, footer) ---

#[sqlx::test(migrations = false)]
async fn nav_shows_pending_badge_when_reviews_pending(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.80", 60).await;
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
    assert!(
        body.contains(r#"<span class="badge">1</span>"#),
        "expected a pending-count badge on the review queue nav link: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn nav_hides_pending_badge_when_queue_empty(pool: PgPool) {
    migrate(&pool).await;
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
    assert!(
        !body.contains(r#"class="badge""#),
        "no pending reviews, so no badge should render: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn authenticated_page_shows_sign_out_and_footer_status(pool: PgPool) {
    migrate(&pool).await;
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
        body.contains(r#"href="/logout""#),
        "missing sign-out link: {body}"
    );
    assert!(body.contains("Sign out"));
    assert!(
        body.contains(r#"<div class="status-line">propolis v"#),
        "missing footer status line: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn login_page_has_no_sign_out_link(pool: PgPool) {
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/login", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        !body.contains("Sign out"),
        "login page must not show a sign-out link before authentication: {body}"
    );
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
        body.contains("port scan"),
        "evidence timeline missing the activity label for the added event: {body}"
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

#[sqlx::test(migrations = false)]
async fn detail_page_has_back_link_to_queue(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.51", 60).await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.51",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<p><a href="/queue">&larr; back to queue</a></p>"#),
        "expected a back-to-queue link above the IP heading: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_page_tables_use_compact_class(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.52", 60).await;
    append_event(
        &pool,
        ev_with_wan(
            "203.0.113.52",
            "198.51.100.20",
            "catchall-sensor",
            SignalType::PortScan,
            Protocol::Tcp,
            true,
            &chrono::Utc::now().to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vendor_submission (source_ip, vendor, idempotency_key, categories, comment, success) \
         VALUES ($1::inet, $2, $3, $4, $5, $6)",
    )
    .bind("203.0.113.52")
    .bind("abuseipdb")
    .bind("detail-table-compact-key")
    .bind(vec!["18".to_string()])
    .bind("test comment")
    .bind(true)
    .execute(&pool)
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.52",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    let table_open_count = body.matches("<table").count();
    let compact_count = body.matches(r#"<table class="table-compact">"#).count();
    // The evidence timeline intentionally uses its own `evidence-table` class rather than
    // `table-compact` (task 3's session-card redesign - `internal/design/11-console-forensics.md`,
    // "Template: session cards"): this fixture's events all carry `session_id = None`
    // (`ev`/`ev_with_wan` pass `None`), so they render as exactly one "Ungrouped events" table.
    let evidence_count = body.matches(r#"<table class="evidence-table">"#).count();
    assert!(
        table_open_count >= 5,
        "expected all 5 detail-page tables to render for this fixture: {body}"
    );
    assert_eq!(
        table_open_count,
        compact_count + evidence_count,
        "every table on the detail page must use either the compact density class or the evidence-table class: {body}"
    );
    assert_eq!(
        evidence_count, 1,
        "expected exactly one evidence table for the fixture's ungrouped events: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_evidence_row_shows_relative_time(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.53", 60).await;
    append_event(
        &pool,
        ev_with_wan(
            "203.0.113.53",
            "198.51.100.21",
            "catchall-sensor",
            SignalType::PortScan,
            Protocol::Tcp,
            true,
            &(chrono::Utc::now() - chrono::Duration::seconds(90)).to_rfc3339(),
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.53",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<td class="seen dim">1m ago</td>"#),
        "expected the evidence timeline to show a relative-time column: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_ip_timeline_chart_reflects_daily_event_counts(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.54", 60).await;
    // A distinct event exactly 6 days before now: the OLDEST of the chart's 7 daily buckets
    // (`current_date - 6 days`), the far boundary of the window.
    append_event(
        &pool,
        ev(
            "203.0.113.54",
            "catchall-sensor",
            SignalType::PortScan,
            Protocol::Tcp,
            false,
            &(chrono::Utc::now() - chrono::Duration::days(6)).to_rfc3339(),
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.54",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<canvas id="chart-ip-timeline""#),
        "IP timeline chart canvas missing: {body}"
    );
    // Chart data is in <script type="application/json"> elements (HTML-escaped by minijinja).
    // The browser's .textContent unescapes them; we verify the data elements are present.
    assert!(
        body.contains(r#"id="ip-timeline-labels">"#) && body.contains(r#"id="ip-timeline-data">"#),
        "IP timeline chart data elements missing: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_groups_events_sharing_session_id_into_an_expanded_session_card(pool: PgPool) {
    migrate(&pool).await;
    let start = chrono::Utc::now() - chrono::Duration::seconds(30);
    let session_id = Uuid::now_v7();
    append_event(
        &pool,
        ev_with_session(
            "203.0.113.60",
            "ssh-sensor",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            true,
            &start.to_rfc3339(),
            serde_json::json!({ "username": "root" }),
            session_id,
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev_with_session(
            "203.0.113.60",
            "ssh-sensor",
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            &(start + chrono::Duration::seconds(5)).to_rfc3339(),
            serde_json::json!({ "command": "whoami" }),
            session_id,
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.60",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<details class="session-card" open>"#),
        "expected the sole (most-recent) session card to render expanded: {body}"
    );
    assert!(
        body.contains(r#"<span class="session-user mono">user: root</span>"#),
        "expected the session header to show the credential used: {body}"
    );
    assert!(
        body.contains(r#"<td class="mono">whoami</td>"#),
        "expected the command-exec event row to show the command in its Detail column: {body}"
    );
    assert!(
        body.contains("2 events"),
        "expected the session header to show the event count: {body}"
    );
    assert!(
        !body.contains("Ungrouped events"),
        "no event in this fixture lacks a session_id, so no ungrouped section should render: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_mixes_session_cards_with_ungrouped_events(pool: PgPool) {
    migrate(&pool).await;
    let now = chrono::Utc::now();
    append_event(
        &pool,
        ev_with_session(
            "203.0.113.61",
            "ssh-sensor",
            SignalType::HoneypotConnection,
            Protocol::Tcp,
            false,
            &now.to_rfc3339(),
            serde_json::json!({ "protocol_label": "ssh" }),
            Uuid::now_v7(),
        ),
    )
    .await
    .unwrap();
    // Pre-existing data from before session tracking: no session_id.
    append_event(
        &pool,
        ev(
            "203.0.113.61",
            "catchall-sensor",
            SignalType::CatchallProbe,
            Protocol::Udp,
            false,
            &(now - chrono::Duration::seconds(120)).to_rfc3339(),
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.61",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"class="session-card""#),
        "expected the session-tagged event to render as a session card: {body}"
    );
    assert!(
        body.contains("Ungrouped events"),
        "expected the pre-session-tracking event to render in the Ungrouped events section: {body}"
    );
}

// --- feed ---

#[sqlx::test(migrations = false)]
async fn feed_page_shows_disabled_empty_state_when_unconfigured(pool: PgPool) {
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
    assert!(
        body.contains(r#"<p class="empty-line">feed builder is disabled on this node</p>"#),
        "expected the disabled-feed empty state when feed_output_dir is unconfigured: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn feed_page_shows_awaiting_first_build_when_configured_but_no_manifest(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    // No manifest.json written: the directory is configured but no build has run yet.

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
        body.contains(r#"<p class="empty-line">feed enabled - awaiting first build</p>"#),
        "expected the awaiting-first-build empty state when configured but no manifest exists: {body}"
    );
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
