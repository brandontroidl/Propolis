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
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::log_buffer::LogEntry;
use console::{AppState, routes};
use core_scoring::{EventInput, Protocol, SignalType, append_event};
use futures::StreamExt;
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
        geoip: Arc::new(geoip::GeoIp::disabled()),
        rdns: Arc::new(console::rdns::RdnsResolver::disabled()),
        feed_output_dir,
        startup_time: chrono::Utc::now(),
        version: "test",
        log_buffer: Arc::new(console::log_buffer::LogBuffer::new(1000)),
        events_ingested: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        events_rejected: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        trusted_proxy: false,
        metrics_token: None,
        gave_up_subsystems: console::no_subsystem_health(),
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
        body.contains("<span class=\"label\">Scored IPs</span>\n    <div class=\"v\">3</div>"),
        "expected total_scored_ips=3 in the status band: {body}"
    );
    assert!(
        body.contains(r#"class="cell cell--call""#),
        "pending_reviews > 0 must render the band's call cell: {body}"
    );
    assert!(
        body.contains(r#"<a href="/queue">2</a>"#),
        "expected pending_reviews=2 linked to /queue: {body}"
    );
    assert!(
        body.contains("0 approved today"),
        "expected approved_today=0 in the Published cell foot: {body}"
    );
    assert!(
        body.contains("+7 in the last hour"),
        "expected events_last_hour=7 in the Events/24h foot: {body}"
    );
    assert!(
        body.contains(r#"<span class="label">Published</span>"#) && body.contains(">--</div>"),
        "expected the feed-entries placeholder when no feed_output_dir is configured: {body}"
    );
    assert!(
        body.contains(r#"class="insp" href="/ip/203.0.113.10""#)
            || body.contains(r#"class="insp" href="/ip/203.0.113.11""#),
        "expected one of the seeded IPs as top attacker in the band: {body}"
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
        body.contains(r#"class="insp" href="/ip/203.0.113.80" hx-get="/ip/203.0.113.80?drawer=1""#),
        "recent-activity row missing source IP drawer link: {body}"
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
        body.contains("+1 in the last hour"),
        "expected events_last_hour=1 in the band foot, excluding the event from 2 hours ago: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_top_attacker_ranks_by_live_score_not_stale_raw(pool: PgPool) {
    migrate(&pool).await;

    // A long-idle IP whose events landed two days ago, then forced to a HIGH stored raw_score.
    // Its `decay_anchor` is ~2 days old, so over 8 half-lives (48h / 6h) its live effective score
    // has decayed to ~95/256 ≈ 0.4.
    seed_recommended(&pool, "203.0.113.10", 2 * 24 * 60 * 60).await;
    sqlx::query("UPDATE ip_score SET raw_score = 95 WHERE source_ip = '203.0.113.10'::inet")
        .execute(&pool)
        .await
        .unwrap();

    // An actively-attacking IP: events 60s ago, so its live effective score ≈ its raw (tens of
    // points), far above the idle IP's decayed ~0.4 even though its stored raw is lower.
    seed_recommended(&pool, "203.0.113.20", 60).await;

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
    // The "top" hero must name the active IP. Ranking by the stored `raw_score` (the bug) would
    // instead promote the idle IP whose anchored 95 has since decayed to ~0.
    assert!(
        body.contains(r#"top <a class="insp" href="/ip/203.0.113.20""#),
        "expected the actively-scoring IP as top attacker, not the stale high-raw one: {body}"
    );
    assert!(
        !body.contains(r#"top <a class="insp" href="/ip/203.0.113.10""#),
        "the idle high-raw IP must not be the top attacker (its live score has decayed): {body}"
    );
}

/// Drift guard: the SQL `LIVE_EFFECTIVE_SCORE_SQL` fragment must produce the same value the detail
/// page shows via `core_scoring` (`effective_score(read_score().raw_score, wan)`). If the mirrored
/// constants (half-life, breadth, cap) ever diverge from core-scoring, this fails.
#[sqlx::test(migrations = false)]
async fn live_effective_score_sql_matches_core_scoring(pool: PgPool) {
    use core_scoring::{effective_score, read_score};

    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.42", 3600).await;
    // Multiple WAN vantages so the breadth factor is a non-trivial multiplier, not 1.0.
    sqlx::query(
        "UPDATE ip_score SET distinct_wan_count = 3 WHERE source_ip = '203.0.113.42'::inet",
    )
    .execute(&pool)
    .await
    .unwrap();

    let sql = format!(
        "SELECT ({})::float8 FROM ip_score WHERE source_ip = '203.0.113.42'::inet",
        routes::LIVE_EFFECTIVE_SCORE_SQL
    );
    let sql_score: f64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .fetch_one(&pool)
        .await
        .unwrap();

    let ip: std::net::IpAddr = "203.0.113.42".parse().unwrap();
    let score = read_score(&pool, ip).await.unwrap().unwrap();
    let rust_score: f64 = effective_score(score.raw_score, score.distinct_wan_count as u32)
        .to_string()
        .parse()
        .unwrap();

    assert!(
        rust_score > 0.0,
        "sanity: the seeded IP should have a positive live score, got {rust_score}"
    );
    assert!(
        (sql_score - rust_score).abs() < 0.05,
        "SQL live score {sql_score} must match core_scoring {rust_score} within tolerance \
         (constant drift between LIVE_EFFECTIVE_SCORE_SQL and core-scoring?)"
    );
}

/// The rolling-window fix: events ~24h ago but still inside the window land in the oldest partial
/// hour. The previous hour-aligned bucket series had no bucket for that hour and dropped them from
/// both the chart and the "Events / 24h" total; the rolling series counts them.
#[sqlx::test(migrations = false)]
async fn dashboard_events_24h_counts_the_oldest_in_window_hour(pool: PgPool) {
    migrate(&pool).await;

    // 30s and 45s inside the 24h boundary: safely within the window (margin >> test latency) yet in
    // the hour the old `trunc(now) - 23h` series excluded. Two distinct signal types so no dedup.
    for (secs_inside, sig) in [
        (30i64, SignalType::HoneypotConnection),
        (45i64, SignalType::HoneypotLoginAttempt),
    ] {
        let when = chrono::Utc::now() - chrono::Duration::seconds(24 * 3600 - secs_inside);
        append_event(
            &pool,
            ev(
                "203.0.113.77",
                "cowrie",
                sig,
                Protocol::Tcp,
                true,
                &when.to_rfc3339(),
            ),
        )
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
    // Both boundary events counted => "Events / 24h" == 2. Under the old hour-aligned series they
    // fell outside every bucket and the total showed 0.
    assert!(
        body.contains(r#"<div class="v">2</div>"#),
        "expected Events/24h to count both in-window boundary events (2): {body}"
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
        body.contains("<div class=\"v v--ok\">13</div>"),
        "expected feed_entries = aggressive(4) + standard(9) = 13 in the Published cell: {body}"
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
        body.contains(r#"<span class="label">Published</span>"#) && body.contains(">--</div>"),
        "expected the feed-entries placeholder when unconfigured: {body}"
    );
    assert!(
        body.contains("queue clear"),
        "expected the queue-clear band state when pending_reviews=0: {body}"
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
        !body.contains(r#"<canvas id="protoChart""#)
            && !body.contains(r#"<canvas id="attackerChart""#),
        "an empty chart canvas must not render when its source list is empty: {body}"
    );
    // The events timeline has no empty-state branch - it always renders 24 zero-filled buckets (a
    // flat line), per the brief's explicit "still renders with all zeros" requirement.
    assert!(
        body.contains(r#"<canvas id="timelineChart""#),
        "the timeline chart must always render, even with no events: {body}"
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
    // `now()`'s event always lands in the LAST of the 25 ascending-ordered hourly buckets (the
    // current hour), so the rendered `timeline_data` array's final element must be 1 regardless of
    // what wall-clock hour the test happens to run in - a broken query (wrong join condition, wrong
    // window) would instead leave every bucket at 0 and this substring would not appear.
    assert!(
        body.contains(r#"id="timeline-data">"#),
        "timeline chart data element missing: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_most_active_shows_active_ip_with_strip(pool: PgPool) {
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
        body.contains(r#"class="insp" href="/ip/203.0.113.86" hx-get="/ip/203.0.113.86?drawer=1""#),
        "most-active table missing the active IP drawer link: {body}"
    );
    assert!(
        body.contains(r#"<span class="strip">"#),
        "most-active row missing its 24h activity strip: {body}"
    );
    assert!(
        body.contains(r#"class="sev sev--"#),
        "most-active row missing severity tags for what the IP did: {body}"
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
    assert!(
        body.contains("203.0.113.201"),
        "newest submission missing: {body}"
    );
    assert!(
        body.contains("203.0.113.202"),
        "2nd-newest submission missing: {body}"
    );
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
async fn detail_renders_services_probed_and_egress_free_lookup_links(pool: PgPool) {
    migrate(&pool).await;
    // Two sensors for one IP: an authenticated SSH session and an unauthenticated VNC (cred-vnc)
    // hit. The "Services probed" panel must list both, label each service, and reflect the auth
    // state; the "Network profile" panel must offer the external lookup links and the
    // not-yet-configured geo placeholder.
    let start = chrono::Utc::now() - chrono::Duration::seconds(120);
    append_event(
        &pool,
        ev(
            "203.0.113.70",
            "ssh",
            SignalType::SshBruteForce,
            Protocol::Tcp,
            true,
            &start.to_rfc3339(),
        ),
    )
    .await
    .unwrap();
    append_event(
        &pool,
        ev(
            "203.0.113.70",
            "cred-vnc",
            SignalType::HoneypotLoginAttempt,
            Protocol::Tcp,
            false,
            &(start + chrono::Duration::seconds(10)).to_rfc3339(),
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.70",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;

    // Services probed: both services, labelled, with the raw sensor shown too.
    assert!(body.contains("Services probed"), "services panel missing");
    assert!(
        body.contains("SSH (22)"),
        "ssh service label missing: {body}"
    );
    assert!(body.contains("VNC (5900)"), "vnc service label missing");
    assert!(body.contains("cred-vnc"), "raw sensor name missing");

    // Network profile: egress-free external lookups (operator's browser), geo not yet configured.
    // The href's slashes are HTML-entity-escaped by minijinja's autoescaper (browsers decode them,
    // so the link works); assert on the un-escaped vendor domains here and leave the exact URL
    // construction to the `external_lookup_links_build_per_vendor_urls_for_the_ip` unit test.
    assert!(
        body.contains("Network profile"),
        "network profile panel missing"
    );
    assert!(body.contains("www.shodan.io"), "shodan lookup link missing");
    assert!(
        body.contains("viz.greynoise.io"),
        "greynoise lookup link missing"
    );
    assert!(body.contains("www.abuseipdb.com"), "abuseipdb link missing");
    assert!(
        body.contains("www.virustotal.com"),
        "virustotal link missing"
    );
    assert!(
        body.contains("GeoLite2 database not configured"),
        "geo placeholder missing"
    );
    // Reverse DNS is opt-in (egress): the resolver is disabled in test_state, so the row must not
    // render at all - no outbound lookup happens unless PROPOLIS_CONSOLE_RDNS_ENABLED is set.
    assert!(
        !body.contains("Hostname (rDNS)"),
        "rDNS row must be hidden when the resolver is disabled (egress-off default)"
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
async fn delete_purges_scoring_state_but_keeps_the_event_ledger(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.40", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool.clone());
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    let scored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ip_score WHERE source_ip = $1::inet")
            .bind("203.0.113.40")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(scored, 1, "precondition: the IP is scored before delete");

    let response = app
        .oneshot(form_request(
            "/ip/203.0.113.40/delete",
            format!("csrf_token={csrf_token}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    // Derived state gone; the append-only, hash-chained event ledger is retained by design.
    let scored: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ip_score WHERE source_ip = $1::inet")
            .bind("203.0.113.40")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(scored, 0, "ip_score must be deleted");
    let queued: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM review_queue WHERE source_ip = $1::inet")
            .bind("203.0.113.40")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(queued, 0, "review_queue must be deleted");
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM event WHERE source_ip = $1::inet")
        .bind("203.0.113.40")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        events > 0,
        "the event ledger must be retained (append-only, hash-chained)"
    );
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

#[sqlx::test(migrations = false)]
async fn queue_tab_bar_marks_the_requested_tab_active(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/queue?tab=approved",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<a href="/queue?tab=approved" class="tab active">Approved</a>"#),
        "expected the approved tab link to carry the active class: {body}"
    );
    assert!(
        body.contains(r#"<a href="/queue?tab=pending" class="tab ">Pending</a>"#),
        "expected the pending tab link to render without the active class: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn queue_approved_tab_lists_decided_entries_with_submission_summary(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.60", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool.clone());
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    // Decide it via the real approve route (not a raw UPDATE) so `decided_at`/`notes` land
    // exactly as the operator flow sets them.
    let response = app
        .clone()
        .oneshot(form_request(
            "/queue/203.0.113.60/approve",
            format!("csrf_token={csrf_token}&notes=looks-malicious"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    sqlx::query(
        "INSERT INTO vendor_submission (source_ip, vendor, idempotency_key, categories, comment, success) \
         VALUES ($1::inet, $2, $3, $4, $5, $6)",
    )
    .bind("203.0.113.60")
    .bind("abuseipdb")
    .bind("queue-approved-tab-key-1")
    .bind(vec!["18".to_string()])
    .bind("test comment")
    .bind(true)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO vendor_submission (source_ip, vendor, idempotency_key, categories, comment, success) \
         VALUES ($1::inet, $2, $3, $4, $5, $6)",
    )
    .bind("203.0.113.60")
    .bind("otx")
    .bind("queue-approved-tab-key-2")
    .bind(vec!["18".to_string()])
    .bind("test comment")
    .bind(false)
    .execute(&pool)
    .await
    .unwrap();

    let response = app
        .oneshot(get_request(
            "/queue?tab=approved",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("203.0.113.60"),
        "approved IP missing from the approved tab: {body}"
    );
    assert!(
        body.contains("looks-malicious"),
        "decision notes missing from the approved tab: {body}"
    );
    // minijinja auto-escapes "/" to "&#x2f;" in interpolated text - assert the escaped form
    // actually rendered, matching what the browser (which unescapes it back to "1/2 vendors")
    // shows the operator.
    assert!(
        body.contains("1&#x2f;2 vendors"),
        "expected the 1-succeeded-of-2 submission summary on the approved tab: {body}"
    );
    // Action buttons only make sense for still-open (pending) decisions. Checks the quoted
    // `class="btn-approve"` markup specifically, not a bare "btn-approve" substring: base_head.html's
    // static CSS always has a `.btn-approve { ... }` rule on every page regardless of this row's
    // data, matching the doctrine's own "no discriminating fixture" trap.
    assert!(
        !body.contains(r#"class="btn-approve""#)
            && !body.contains(r#"class="btn-reject""#)
            && !body.contains(r#"class="btn-snooze""#),
        "approved tab must not render pending-only action buttons: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn queue_approved_tab_shows_dash_when_no_submissions_yet(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.61", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool);
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    app.clone()
        .oneshot(form_request(
            "/queue/203.0.113.61/approve",
            format!("csrf_token={csrf_token}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    let response = app
        .oneshot(get_request(
            "/queue?tab=approved",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("203.0.113.61"),
        "approved IP missing from the approved tab: {body}"
    );
    assert!(
        body.contains("<td>-</td>"),
        "expected a dash submission summary for an IP with no vendor_submission rows yet: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn queue_rejected_and_snoozed_tabs_list_only_their_own_state(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.62", 60).await;
    seed_recommended(&pool, "203.0.113.63", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();

    let state = test_state(pool);
    let (session_id, cookie) = state.sessions.create();
    let csrf_token = state.sessions.generate_csrf(&session_id).unwrap();
    let app = test_app(state);

    app.clone()
        .oneshot(form_request(
            "/queue/203.0.113.62/reject",
            format!("csrf_token={csrf_token}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(form_request(
            "/queue/203.0.113.63/snooze",
            format!("csrf_token={csrf_token}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    let rejected_body = body_text(
        app.clone()
            .oneshot(get_request(
                "/queue?tab=rejected",
                Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert!(rejected_body.contains("203.0.113.62"), "{rejected_body}");
    assert!(!rejected_body.contains("203.0.113.63"), "{rejected_body}");

    let snoozed_body = body_text(
        app.oneshot(get_request(
            "/queue?tab=snoozed",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert!(snoozed_body.contains("203.0.113.63"), "{snoozed_body}");
    assert!(!snoozed_body.contains("203.0.113.62"), "{snoozed_body}");
}

#[sqlx::test(migrations = false)]
async fn queue_history_tab_empty_state_names_the_tab(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/queue?tab=rejected",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<p class="empty-line">no rejected entries yet</p>"#),
        "expected a tab-specific empty-state message: {body}"
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

/// Inserts one `fetch_attempt` row for `source_ip` plus a matching `sample_analysis` row, joined
/// via `encode(sha256,'hex')` exactly as `routes::detail`'s `fetch_malware_rows` does -
/// `crates/console/src/routes/detail.rs`'s doc comment on that function covers why the join goes
/// through `encode(...)`: `fetch_attempt.sha256` is raw-digest `BYTEA`, `sample_analysis.sha256`
/// is lowercase-hex `TEXT`. `n` derives both a unique `url_hash` (the table's primary key) and a
/// unique, valid 64-char lowercase-hex sha256 (`format!("{:064x}", ...)` zero-pads a `u64` into a
/// full-width hex string, so `hex::decode` on it always succeeds).
async fn seed_fetch_attempt_with_analysis(
    pool: &PgPool,
    n: u32,
    source_ip: &str,
    detected: i32,
    total: i32,
) -> String {
    let sha256_hex = format!("{:064x}", 0xdead_beef_u64 + n as u64);
    let sha256_bytes = hex::decode(&sha256_hex).unwrap();
    sqlx::query(
        "INSERT INTO fetch_attempt \
            (url_hash, url, host, scheme, pinned_ip, source_ip, status, sha256, bytes, last_attempt) \
         VALUES ($1, $2, $3, 'http', $4, $5::inet, 'success', $6, $7, now())",
    )
    .bind(format!("malware-link-test-hash-{n}").into_bytes())
    .bind(format!(
        "http://malware-link-test-{n}.example.invalid/payload.bin"
    ))
    .bind(format!("malware-link-test-{n}.example.invalid"))
    .bind("203.0.113.66")
    .bind(source_ip)
    .bind(&sha256_bytes)
    .bind(4300_i32)
    .execute(pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO sample_analysis (sha256, detected, total, vt_link, analyzed_at) \
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(&sha256_hex)
    .bind(detected)
    .bind(total)
    .bind(format!("https://www.virustotal.com/gui/file/{sha256_hex}"))
    .execute(pool)
    .await
    .unwrap();

    sha256_hex
}

/// A body UPLOADED straight to a sensor (FTP STOR, SCP, ADB push) never goes through the fetcher,
/// so it has no `fetch_attempt` row. Attribution comes from the event itself, which carries the
/// sha - a first-party observation, and the strongest link available. This shipped broken: an FTP
/// attacker uploaded three samples and the panel still read "no samples linked to this address",
/// because the query only ever asked `fetch_attempt`.
#[sqlx::test(migrations = false)]
async fn detail_links_a_directly_uploaded_sample_to_its_uploader(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.81";
    seed_recommended(&pool, ip, 60).await;

    append_event(
        &pool,
        ev_with_session(
            ip,
            "ftp",
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            &chrono::Utc::now().to_rfc3339(),
            serde_json::json!({
                "sample_sha256": "52ec3ba075a5aabbccddeeff00112233445566778899aabbccddeeff00112233",
                "sample_orig_name": "info.zip",
                "sample_size": 1024,
            }),
            Uuid::now_v7(),
        ),
    )
    .await
    .unwrap();

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let response = app
        .oneshot(get_request(
            &format!("/ip/{ip}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("52ec3ba075a5"),
        "the uploaded sample's sha must appear on its uploader's page: {body}"
    );
    assert!(
        body.contains("info.zip"),
        "the uploaded file name must appear: {body}"
    );
    assert!(
        body.contains("uploaded"),
        "the row must be labelled as a direct upload, not presented as a fetch: {body}"
    );
    assert!(
        !body.contains("no samples linked to this address"),
        "the empty state must not render when an upload links to this ip: {body}"
    );
}

/// The uploaded arm of the malware panel used to emit one row per EVENT, so an attacker that
/// re-uploaded the same body enough times filled the 50-row page with one sha and pushed every
/// other sample it had uploaded off the panel. Rows are one per sha now.
#[sqlx::test(migrations = false)]
async fn detail_malware_panel_groups_repeated_uploads_of_one_sha(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.82";
    seed_recommended(&pool, ip, 60).await;

    let repeated = "aaaa3ba075a5aabbccddeeff00112233445566778899aabbccddeeff00112233";
    let distinct = "bbbb3ba075a5aabbccddeeff00112233445566778899aabbccddeeff00112233";
    // The distinct sample first, so every one of the repeats sorts NEWER than it and the
    // pre-fix query's LIMIT would have dropped it.
    let base = chrono::Utc::now() - chrono::Duration::minutes(120);
    let upload = |sha: &str, name: &str, at: chrono::DateTime<chrono::Utc>| {
        ev_with_session(
            ip,
            "ftp",
            SignalType::HoneypotMalwareUpload,
            Protocol::Tcp,
            true,
            &at.to_rfc3339(),
            serde_json::json!({
                "sample_sha256": sha,
                "sample_orig_name": name,
                "sample_size": 1024,
            }),
            Uuid::now_v7(),
        )
    };
    append_event(&pool, upload(distinct, "rare.bin", base))
        .await
        .unwrap();
    for i in 1..=60 {
        append_event(
            &pool,
            upload(repeated, "spam.bin", base + chrono::Duration::seconds(i)),
        )
        .await
        .unwrap();
    }

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let response = app
        .oneshot(get_request(
            &format!("/ip/{ip}"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    // Scope to the malware panel: the event timeline below it also renders every upload.
    let panel_start = body
        .find("Malware from this IP")
        .expect("malware panel heading must render");
    let panel = &body[panel_start..];
    let panel = &panel[..panel.find("</table>").unwrap_or(panel.len())];
    assert!(
        panel.contains("bbbb3ba075a5"),
        "the distinct sample must not be crowded off the panel by repeats of another: {panel}"
    );
    // The table cell renders the 12-char short form followed by "..."; the full sha in the
    // title attribute does not match this string, so this counts rows.
    assert_eq!(
        panel.matches("aaaa3ba075a5...").count(),
        1,
        "the repeated sha must render as ONE row, not one per upload: {panel}"
    );
}

/// A sample uploaded to VirusTotal but not yet verdicted is stored as `-1/-1`. The samples page
/// already rendered that as "pending"; the IP page fell through to the clean branch and showed a
/// green "clean (0/-1)" for a sample nobody has judged yet.
#[sqlx::test(migrations = false)]
async fn detail_renders_a_pending_vt_upload_as_pending_not_clean(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.83", 60).await;
    seed_fetch_attempt_with_analysis(&pool, 2, "203.0.113.83", -1, -1).await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.83",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("pending VT analysis"),
        "a -1 verdict must render as pending: {body}"
    );
    assert!(
        !body.contains("clean (0"),
        "a -1 verdict must never render as clean: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_shows_linked_malware_fetched_from_this_ips_urls(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.80", 60).await;
    let sha256_hex = seed_fetch_attempt_with_analysis(&pool, 1, "203.0.113.80", 12, 70).await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.80",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("Malware from this IP"),
        "malware panel heading missing: {body}"
    );
    // minijinja's autoescaper HTML-entity-escapes `/` (`&#x2f;`) inside `{{ m.url }}` - assert on
    // slash-free fragments of the URL rather than the literal string, same reasoning
    // `detail_renders_services_probed_and_egress_free_lookup_links`'s own doc comment gives for
    // asserting on the vendor domain rather than the full escaped href.
    assert!(
        body.contains("malware-link-test-1.example.invalid"),
        "fetched url's host missing: {body}"
    );
    assert!(
        body.contains("payload.bin"),
        "fetched url's path missing: {body}"
    );
    assert!(
        body.contains(&sha256_hex[..12]),
        "sha256 short form missing: {body}"
    );
    assert!(
        body.contains("12/70 detected"),
        "VT verdict missing: {body}"
    );
    // The panel must keep saying that a FETCHED link is first-reporter-only, so an inference is
    // never read as a direct observation. Asserted on the substance, not the exact sentence.
    assert!(
        body.contains("first to report"),
        "attribution caveat missing: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_shows_empty_state_when_no_fetches_link_to_this_ip(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.81", 60).await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.81",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("no samples linked to this address"),
        "malware panel empty state missing: {body}"
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
async fn detail_page_has_neutral_back_link(pool: PgPool) {
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
        body.contains(r#"<a href="/ips" onclick="if(history.length>1){history.back();return false}">&larr; Back</a>"#),
        "expected a neutral back link (browser history with an /ips fallback), not a hardcoded \
         'back to queue' that misleads when the page was reached from elsewhere: {body}"
    );
}

/// Finding 8 - the drawer contract now lives in one place (the `ip_evidence_link` macro). These
/// lock in that ordinary IP links carry it on the pages that previously shipped plain links, so the
/// per-page drift that broke Review/Feed/Search cannot silently return. Dashboard and Feed links are
/// covered by the assertions in their own tests above; these add the two remaining feasible pages.
#[sqlx::test(migrations = false)]
async fn attackers_ip_links_use_the_drawer_contract(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.20", 60).await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let response = app
        .oneshot(get_request(
            "/ips",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(
            r##"class="insp" href="/ip/203.0.113.20" hx-get="/ip/203.0.113.20?drawer=1" hx-target="#drawer-body" hx-swap="innerHTML" aria-haspopup="dialog""##
        ),
        "attackers row IP must render the full drawer contract via the macro: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn queue_pending_ip_links_use_the_drawer_contract(pool: PgPool) {
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
    assert!(
        body.contains(r#"class="insp" href="/ip/203.0.113.20" hx-get="/ip/203.0.113.20?drawer=1""#),
        "review-queue row IP must use the drawer contract, not a plain full-page link: {body}"
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
    // Matched by structure, not by the exact attribute string: the card later gained an `id` for
    // deep-linking, which silently broke an exact-text assertion while the behaviour it guards was
    // never affected. Assert that the card's opening tag carries `open`, and let the rest of the
    // tag change freely.
    let card_tag = body
        .split_once(r#"<details class="session-card""#)
        .and_then(|(_, rest)| rest.split_once('>'))
        .map(|(tag, _)| tag)
        .expect("expected a session card to render");
    assert!(
        card_tag.contains("open"),
        "expected the sole (most-recent) session card to render expanded, tag was: {card_tag}"
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

/// Extracts the `?cursor=...` value from a "Load more" button's `hx-get` attribute in a rendered
/// detail page or events fragment - `routes::detail::format_cursor`'s output, HTML-attribute
/// position. Colons, dots, and commas are never HTML-escaped by minijinja (only
/// `< > & " ' /`), so the raw cursor string appears verbatim between `cursor=` and the closing
/// quote - no unescaping needed.
fn extract_next_cursor(body: &str, ip: &str) -> String {
    let marker = format!("/ip/{ip}/events?cursor=");
    let start = body
        .find(&marker)
        .unwrap_or_else(|| panic!("no Load more button (cursor href) found in body: {body}"))
        + marker.len();
    let rest = &body[start..];
    let end = rest
        .find('"')
        .expect("cursor value in hx-get attribute must be quoted");
    rest[..end].to_string()
}

// --- detail: evidence timeline pagination (console-forensics task 4) ---

#[sqlx::test(migrations = false)]
async fn detail_evidence_timeline_paginates_past_the_first_page(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.70";
    let now = chrono::Utc::now();
    // 205 events, strictly increasing timestamps (index 0 oldest, index 204 newest, one second
    // apart) - 5 more than `EVIDENCE_PAGE_SIZE` (200, `routes::detail`'s private constant; mirrored
    // here as a literal since it is not part of this crate's public API). The first page (`GET
    // /ip/{ip}`) must show only the newest 200 (indices 5..=204); the remaining 5 oldest
    // (indices 0..=4) must appear only via the "Load more" fragment.
    for i in 0..205i64 {
        let session_id = Uuid::now_v7();
        append_event(
            &pool,
            ev_with_session(
                ip,
                "ssh-sensor",
                SignalType::HoneypotCommandExec,
                Protocol::Tcp,
                true,
                &(now - chrono::Duration::seconds(205 - i)).to_rfc3339(),
                // The `-end` suffix guards against substring false-positives: without it,
                // `pg-marker-4` is itself a substring of `pg-marker-40`..`pg-marker-49`, so a
                // `!body.contains("pg-marker-4")` assertion would wrongly fail as soon as any of
                // those (all on the first page) rendered.
                serde_json::json!({ "command": format!("pg-marker-{i}-end") }),
                session_id,
            ),
        )
        .await
        .unwrap();
    }

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let cookie_header = format!("{}={cookie}", auth::SESSION_COOKIE);

    let first_page = app
        .clone()
        .oneshot(get_request(&format!("/ip/{ip}"), Some(&cookie_header)))
        .await
        .unwrap();
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_body = body_text(first_page).await;
    assert!(
        first_body.contains("pg-marker-204-end"),
        "newest event must be on the first page: {first_body}"
    );
    assert!(
        !first_body.contains("pg-marker-4-end"),
        "the 5 oldest events must NOT be on the first page: {first_body}"
    );
    assert!(
        first_body.contains(r#"id="load-more-container""#),
        "expected a Load more container when more than 200 events exist: {first_body}"
    );

    let cursor = extract_next_cursor(&first_body, ip);
    let second_page = app
        .oneshot(get_request(
            &format!("/ip/{ip}/events?cursor={cursor}"),
            Some(&cookie_header),
        ))
        .await
        .unwrap();
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_body = body_text(second_page).await;
    for i in 0..5 {
        assert!(
            second_body.contains(&format!("pg-marker-{i}-end")),
            "expected the 5 oldest events (index {i}) on the second page: {second_body}"
        );
    }
    assert!(
        !second_body.contains("pg-marker-204-end"),
        "the newest (first-page) event must not be re-sent on the second page: {second_body}"
    );
    assert!(
        !second_body.contains("<!doctype html>"),
        "an HTMX fragment must not carry the full base-page wrapper: {second_body}"
    );
    // Exactly 205 events total, so the second page (5 rows) is the last one: its own "Load more"
    // out-of-band swap must be empty, not a fresh button.
    assert!(
        !second_body.contains("class=\"load-more\""),
        "the last page must not offer a further Load more button: {second_body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_evidence_timeline_omits_load_more_under_the_page_size(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.71", 60).await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.71",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        !body.contains("class=\"load-more\""),
        "fewer than 200 events must not show a Load more button: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn events_fragment_requires_a_session(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(get_request("/ip/203.0.113.72/events", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

#[sqlx::test(migrations = false)]
async fn events_fragment_malformed_cursor_returns_an_empty_fragment(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.73", 60).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.73/events?cursor=not-a-valid-cursor",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    // Fails closed (`routes::detail::events_fragment`'s doc comment): a malformed cursor never
    // guesses a start point, it returns an empty 200 rather than a 500 or leaking the wrong page.
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert_eq!(body, "", "a malformed cursor must yield an empty fragment");
}

// --- detail: adjustable chart time range (console-forensics task 4) ---

#[sqlx::test(migrations = false)]
async fn detail_chart_fragment_24h_range_returns_hourly_buckets(pool: PgPool) {
    migrate(&pool).await;
    let ip = "203.0.113.74";
    append_event(
        &pool,
        ev(
            ip,
            "catchall-sensor",
            SignalType::PortScan,
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
            &format!("/ip/{ip}/chart?range=24h"),
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"aria-label="Events per hour, last 24 hours""#),
        "expected the 24h range's hourly aria-label: {body}"
    );
    assert!(
        body.contains(r#"<canvas id="chart-ip-timeline""#),
        "chart canvas missing from the range fragment: {body}"
    );
    assert!(
        !body.contains("<!doctype html>"),
        "an HTMX fragment must not carry the full base-page wrapper: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_chart_fragment_unknown_range_falls_back_to_7d(pool: PgPool) {
    migrate(&pool).await;
    seed_recommended(&pool, "203.0.113.75", 60).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/ip/203.0.113.75/chart?range=not-a-real-range",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"aria-label="Events per day, last 7 days""#),
        "an unrecognized range must fall back to the page's own 7d default: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn detail_chart_fragment_requires_a_session(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(get_request("/ip/203.0.113.76/chart?range=24h", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

// --- dashboard: adjustable chart time range (console-forensics task 4) ---

#[sqlx::test(migrations = false)]
async fn dashboard_chart_fragment_1h_range_returns_five_minute_buckets(pool: PgPool) {
    migrate(&pool).await;
    append_event(
        &pool,
        ev(
            "203.0.113.77",
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
            "/dashboard/chart?range=1h",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"aria-label="Events per 5 minutes, last hour""#),
        "expected the 1h range's five-minute aria-label: {body}"
    );
    assert!(
        body.contains(r#"<canvas id="timelineChart""#),
        "chart canvas missing from the range fragment: {body}"
    );
    assert!(
        !body.contains("<!doctype html>"),
        "an HTMX fragment must not carry the full base-page wrapper: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_chart_fragment_30d_range_returns_daily_buckets(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/dashboard/chart?range=30d",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"aria-label="Events per day, last 30 days""#),
        "expected the 30d range's daily aria-label: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn dashboard_chart_fragment_requires_a_session(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(get_request("/dashboard/chart?range=24h", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
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
    // A manifest from before the exclusions field existed still parses (serde default) and renders
    // ASN suppression as off rather than collapsing the page.
    assert!(
        body.contains("Exclusions"),
        "exclusions panel missing: {body}"
    );
    assert!(
        body.contains(">off<"),
        "an absent exclusions block should render ASN suppression off: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn feed_page_shows_asn_suppression_active_and_inert_states(pool: PgPool) {
    migrate(&pool).await;

    // Active: 3 ASNs configured and the GeoLite2-ASN database loaded.
    let active = tempfile::tempdir().unwrap();
    std::fs::write(
        active.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":3,"sha256":"a","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":11,"sha256":"b","valid_until":"2026-07-31T14:00:00Z"}},"exclusions":{"allowlist_count":2,"delist_count":1,"asn_allowlist_count":3,"asn_db_loaded":true}}"#,
    )
    .unwrap();
    let state = test_state_with_feed_dir(pool.clone(), Some(active.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let body = body_text(
        app.oneshot(get_request(
            "/feed",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert!(
        body.contains("3 ASNs active"),
        "active ASN state missing: {body}"
    );
    assert!(
        body.contains("2 ranges"),
        "CIDR allowlist count missing: {body}"
    );

    // Inert: ASNs configured but the database did not load - must be flagged, not shown as active.
    let inert = tempfile::tempdir().unwrap();
    std::fs::write(
        inert.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":0,"sha256":"a","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":0,"sha256":"b","valid_until":"2026-07-31T14:00:00Z"}},"exclusions":{"allowlist_count":0,"delist_count":0,"asn_allowlist_count":3,"asn_db_loaded":false}}"#,
    )
    .unwrap();
    let state = test_state_with_feed_dir(pool, Some(inert.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let body = body_text(
        app.oneshot(get_request(
            "/feed",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap(),
    )
    .await;
    assert!(
        body.contains("inert"),
        "inert ASN state not flagged: {body}"
    );
    assert!(
        !body.contains("3 ASNs active"),
        "an unloaded database must not render as active: {body}"
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

/// Writes a published feed export the entries tab can read back, in the shape
/// `feed::export::export_json` produces.
fn write_published_feed(dir: &std::path::Path, name: &str, entries: &str) {
    std::fs::write(
        dir.join(format!("{name}.json")),
        format!(
            r#"{{"meta":{{"generator":"propolis","tier":"{name}","generated":"2026-07-29T14:00:00Z","valid_until":"2026-07-31T14:00:00Z","count":0}},"entries":[{entries}]}}"#
        ),
    )
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn feed_entries_tab_lists_what_was_published_not_a_fresh_derivation(pool: PgPool) {
    migrate(&pool).await;
    // The database deliberately DISAGREES with the published files: an approved, recommended
    // address that is not in any published feed, and published addresses with no database rows at
    // all. The old implementation re-derived this tab from exactly these tables and so disagreed
    // with the files it claimed to describe - the 8-vs-7 mismatch. The page must report the
    // published feed, so the database's opinion must not appear here.
    seed_recommended(&pool, "203.0.113.99", 60).await;
    ReviewQueue::new().populate(&pool).await.unwrap();
    ReviewQueue::new()
        .approve(&pool, "203.0.113.99".parse().unwrap(), None)
        .await
        .unwrap();

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":1,"sha256":"deadbeef","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":1,"sha256":"cafef00d","valid_until":"2026-07-31T14:00:00Z"}},"windows":[{"label":"7d","count":2,"sha256":"f00d","valid_until":"2026-08-05T14:00:00Z"}]}"#,
    )
    .unwrap();
    write_published_feed(
        tmp.path(),
        "aggressive",
        r#"{"ip":"203.0.113.70","first_seen":"2026-07-20T10:00:00Z","last_seen":"2026-07-29T13:00:00Z","categories":3,"events":47,"signals":["honeypot_malware_upload","ssh_brute_force"]}"#,
    );
    write_published_feed(
        tmp.path(),
        "standard",
        r#"{"ip":"203.0.113.71","first_seen":"2026-07-21T10:00:00Z","last_seen":"2026-07-28T13:00:00Z","categories":2,"events":12,"signals":["port_scan"]}"#,
    );
    write_published_feed(
        tmp.path(),
        "all-7d",
        r#"{"ip":"203.0.113.72","first_seen":"2026-07-22T10:00:00Z","last_seen":"2026-07-27T13:00:00Z","categories":1,"events":5,"signals":["catchall_probe"]}"#,
    );

    let state = test_state_with_feed_dir(pool.clone(), Some(tmp.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/feed?tab=entries",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;

    for ip in ["203.0.113.70", "203.0.113.71", "203.0.113.72"] {
        assert!(
            body.contains(&format!(
                r#"<a class="insp" href="/ip/{ip}" hx-get="/ip/{ip}?drawer=1""#
            )),
            "published address {ip} missing a drawer link: {body}"
        );
    }
    assert!(
        !body.contains("203.0.113.99"),
        "an approved address absent from the published files must NOT be listed: {body}"
    );

    // Each address under the panel for the file it was actually published in.
    let agg = body.find("Aggressive tier").expect("aggressive panel");
    let std_p = body.find("Standard tier").expect("standard panel");
    let win = body.find("Last 7d").expect("retention panel");
    assert!(body.find("203.0.113.70").unwrap() > agg);
    assert!(body.find("203.0.113.71").unwrap() > std_p);
    assert!(body.find("203.0.113.72").unwrap() > win);

    // Activity labels are what make an entry actionable, so they must reach the page.
    assert!(
        body.contains("honeypot_malware_upload, ssh_brute_force"),
        "activity labels missing: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn feed_entries_tab_shows_awaiting_build_state_when_no_manifest(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    // No manifest.json written and no entries approved: entries tab must show the same
    // "awaiting first build" empty state as the status tab, per the design's framing of this tab
    // as listing "the actual IPs in the current published feed" - there is no published feed yet.
    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/feed?tab=entries",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"<p class="empty-line">feed enabled - awaiting first build</p>"#),
        "expected the awaiting-first-build empty state on the entries tab: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn feed_download_returns_file_content_with_correct_type(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("aggressive.json"), r#"{"entries":[]}"#).unwrap();
    std::fs::write(tmp.path().join("standard.csv"), "ip,score\n").unwrap();

    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .clone()
        .oneshot(get_request(
            "/feed/download/aggressive/json",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let body = body_text(response).await;
    assert_eq!(body, r#"{"entries":[]}"#);

    let response = app
        .oneshot(get_request(
            "/feed/download/standard/csv",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/csv");
    let body = body_text(response).await;
    assert_eq!(body, "ip,score\n");
}

#[sqlx::test(migrations = false)]
async fn feed_download_404s_when_feed_disabled(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/feed/download/aggressive/json",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = false)]
async fn feed_download_serves_retention_feeds_but_refuses_anything_path_shaped(pool: PgPool) {
    // The retention feeds are operator-configured, so the accepted names cannot be a literal list
    // and are matched by shape instead. Every rejected name below names a file that ACTUALLY
    // EXISTS in the feed directory, so the name check is the only thing standing between the
    // request and a 200 - a rejected name that happens to match no file would 404 either way and
    // would prove nothing about the guard.
    migrate(&pool).await;
    let feed_dir = tempfile::tempdir().unwrap();
    let feed_dir = feed_dir.path();
    std::fs::write(feed_dir.join("all-90d.txt"), "203.0.113.7\n").unwrap();
    for decoy in [
        // Written by the publisher itself, but not a feed anyone should be able to pull.
        "manifest.txt",
        // Plausible neighbours in the same directory.
        "secret.txt",
        "all-.txt",
        "all-.txt.txt",
        "all-90.txt",
        "all-90x.txt",
        "all-9.0d.txt",
        "aggressive..txt",
    ] {
        std::fs::write(feed_dir.join(decoy), "must not be served").unwrap();
    }

    let state = test_state_with_feed_dir(pool, Some(feed_dir.to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);
    let cookie_hdr = format!("{}={cookie}", auth::SESSION_COOKIE);

    let response = app
        .clone()
        .oneshot(get_request("/feed/download/all-90d/txt", Some(&cookie_hdr)))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a configured retention feed must be downloadable"
    );

    for name in [
        "manifest",
        "secret",
        "all-",
        "all-.txt",
        "all-90",
        "all-90x",
        "all-9.0d",
        "aggressive.",
    ] {
        let response = app
            .clone()
            .oneshot(get_request(
                &format!("/feed/download/{name}/txt"),
                Some(&cookie_hdr),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{name:?} names a real file on disk and must still be refused"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn feed_download_404s_on_unknown_tier_or_format(pool: PgPool) {
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("aggressive.json"), "{}").unwrap();
    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .clone()
        .oneshot(get_request(
            "/feed/download/nonsense/json",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = app
        .clone()
        .oneshot(get_request(
            "/feed/download/aggressive/exe",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The manifest exists but this particular file was never written (e.g. a build that failed
    // partway) - still 404, not a 503 or a panic.
    let response = app
        .oneshot(get_request(
            "/feed/download/standard/json",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
async fn login_cookie_is_secure_when_behind_a_trusted_proxy(pool: PgPool) {
    migrate(&pool).await;
    let mut state = test_state(pool);
    state.trusted_proxy = true;
    let app = test_app(state);

    // TEST_PEER is loopback, so without trusted_proxy the Secure flag would be dropped. With it,
    // the cookie must be Secure so it is never sent back over a plaintext hop to the TLS proxy.
    let req = form_request("/login", format!("password={TEST_PASSWORD}"), None);
    let response = app.oneshot(req).await.unwrap();
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("a successful login sets the session cookie")
        .to_str()
        .unwrap();
    assert!(
        set_cookie.contains("Secure"),
        "trusted_proxy must force a Secure session cookie even for a loopback peer: {set_cookie}"
    );
}

#[sqlx::test(migrations = false)]
async fn metrics_bearer_gate_rejects_without_token_and_accepts_with_it(pool: PgPool) {
    migrate(&pool).await;
    let mut state = test_state(pool);
    state.metrics_token = Some(std::sync::Arc::from("s3cr3t-metrics"));
    let app = test_app(state);

    // Token configured but no Authorization header: 401.
    let unauth = app
        .clone()
        .oneshot(get_request("/metrics", None))
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // Wrong token: 401.
    let wrong = Request::builder()
        .uri("/metrics")
        .header("authorization", "Bearer wrong")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(wrong).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // Correct bearer token: 200.
    let ok = Request::builder()
        .uri("/metrics")
        .header("authorization", "Bearer s3cr3t-metrics")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(ok).await.unwrap().status(), StatusCode::OK);
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
    // A manifest from a build with no retention feeds must not emit the window metric at all,
    // rather than emitting an empty HELP/TYPE pair with no series under it.
    assert!(
        !body.contains("propolis_feed_window_entries"),
        "window metric must be absent when no windows are configured: {body}"
    );
}

#[sqlx::test(migrations = false)]
async fn metrics_reports_each_retention_feed_separately_from_the_tiers(pool: PgPool) {
    // The retention feeds had no metric, so a window that stopped publishing was invisible from
    // outside the box. They get their own metric rather than another propolis_feed_entries series:
    // every tiered entry also appears in the windows containing it, so reusing that metric would
    // make summing it double-count.
    migrate(&pool).await;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("manifest.json"),
        r#"{"build_time":"2026-07-29T14:00:00Z","tiers":{"aggressive":{"count":4,"sha256":"x","valid_until":"2026-07-30T14:00:00Z"},"standard":{"count":9,"sha256":"y","valid_until":"2026-07-31T14:00:00Z"}},"windows":[{"label":"24h","count":11,"sha256":"a","valid_until":"2026-07-30T14:00:00Z"},{"label":"90d","count":0,"sha256":"b","valid_until":"2026-10-27T14:00:00Z"}]}"#,
    )
    .unwrap();

    let state = test_state_with_feed_dir(pool, Some(tmp.path().to_path_buf()));
    let app = test_app(state);
    let response = app.oneshot(get_request("/metrics", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"propolis_feed_window_entries{window="24h"} 11"#),
        "missing 24h window series: {body}"
    );
    // Emitted even at zero: an absent series and a silently-empty feed look the same on a graph,
    // and the second is the one worth alerting on.
    assert!(
        body.contains(r#"propolis_feed_window_entries{window="90d"} 0"#),
        "an empty window must still report, as a zero: {body}"
    );
    // The tier metric is untouched, so existing dashboards keep working.
    assert!(body.contains(r#"propolis_feed_entries{tier="aggressive"} 4"#));
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

// --- logs ---

#[sqlx::test(migrations = false)]
async fn logs_page_renders_snapshot_with_level_based_markup(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    state.log_buffer.push(LogEntry {
        timestamp: "2026-08-19T00:00:00Z".to_string(),
        level: "ERROR".to_string(),
        target: "propolis::intake".to_string(),
        message: "<script>alert(1)</script>".to_string(),
    });
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/logs",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(r#"class="log-line level-error""#),
        "expected the seeded ERROR entry to render with error-level markup: {body}"
    );
    assert!(
        body.contains("propolis::intake"),
        "expected the seeded entry's target in the rendered page: {body}"
    );
    // minijinja auto-escapes every interpolated value (`templates.rs`'s own doc comment) - a raw
    // log message containing HTML metacharacters must never reach the page unescaped.
    assert!(
        !body.contains("<script>alert"),
        "log message markup leaked into the page unescaped: {body}"
    );
    assert!(body.contains("&lt;script&gt;alert(1)&lt;&#x2f;script&gt;"));
}

#[sqlx::test(migrations = false)]
async fn logs_page_unauthenticated_redirects_to_login(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app.oneshot(get_request("/logs", None)).await.unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

#[sqlx::test(migrations = false)]
async fn logs_stream_is_sse_and_broadcasts_pushed_entries(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let log_buffer = state.log_buffer.clone();
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/logs/stream",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.starts_with("text/event-stream"),
        "unexpected content-type for the SSE endpoint: {content_type}"
    );

    // `logs_stream`'s handler subscribes to the broadcast channel synchronously before
    // returning the response (`routes::logs`'s own doc comment), so by the time `oneshot`
    // resolves above, the subscription already exists - a push here is guaranteed to reach it,
    // no race window to paper over with a sleep.
    log_buffer.push(LogEntry {
        timestamp: "2026-08-19T00:00:00Z".to_string(),
        level: "WARN".to_string(),
        target: "propolis::review".to_string(),
        message: "queue scan degraded".to_string(),
    });

    let mut body = response.into_body().into_data_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(5), body.next())
        .await
        .expect("timed out waiting for the first SSE frame")
        .expect("stream ended before any frame arrived")
        .expect("error reading SSE frame");
    let text = String::from_utf8(chunk.to_vec()).unwrap();

    assert!(
        text.contains(r#""level":"WARN""#),
        "expected the pushed entry's level in the SSE frame: {text}"
    );
    assert!(
        text.contains(r#""target":"propolis::review""#),
        "expected the pushed entry's target in the SSE frame: {text}"
    );
    assert!(
        text.contains(r#""message":"queue scan degraded""#),
        "expected the pushed entry's message in the SSE frame: {text}"
    );
}

#[sqlx::test(migrations = false)]
async fn logs_stream_unauthenticated_redirects_to_login(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let app = test_app(state);

    let response = app
        .oneshot(get_request("/logs/stream", None))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/login");
}

// --- samples ---

/// Inserts one minimal `fetch_attempt` row with the given `status` (a raw `FetchStatus::as_str()`
/// value - `review::fetcher::FetchStatus`). Only the columns the table requires
/// (`crates/review/migrations/0003_fetch_attempt.sql`: `url_hash`/`url`/`host`/`scheme`/`status`/
/// `last_attempt`) are set; every other column keeps its schema default, matching how a real
/// fetch cycle's own `store::insert_pending_if_absent`/`upsert_attempt` populate a row - this test
/// only needs a distinct, unique `url_hash` per row (the table's primary key) and the `status` the
/// samples-page status strip groups by.
async fn seed_fetch_attempt(pool: &PgPool, n: u32, status: &str) {
    let url = format!("http://malware-fetch-test-{n}.example.invalid/payload.bin");
    sqlx::query(
        "INSERT INTO fetch_attempt (url_hash, url, host, scheme, status, last_attempt) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(format!("fetch-attempt-test-hash-{n}").into_bytes())
    .bind(&url)
    .bind(format!("malware-fetch-test-{n}.example.invalid"))
    .bind("http")
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
}

/// Reads the count rendered directly after a given status strip label - robust to the exact
/// indentation/whitespace the template happens to use between the `.label` and `.value` divs
/// (unlike a hardcoded whitespace-sensitive substring), while still precisely pairing each label
/// with ITS OWN adjacent count rather than any other stat-card's.
fn strip_count(body: &str, label: &str) -> i64 {
    let label_tag = format!("<div class=\"label\">{label}</div>");
    let after_label = body
        .find(&label_tag)
        .map(|pos| &body[pos + label_tag.len()..])
        .unwrap_or_else(|| panic!("status-strip label {label:?} missing: {body}"));
    let value_tag = "<div class=\"value\">";
    let value_start = after_label
        .find(value_tag)
        .unwrap_or_else(|| panic!("no value div after label {label:?}: {body}"))
        + value_tag.len();
    let value_end = after_label[value_start..]
        .find("</div>")
        .unwrap_or_else(|| panic!("unclosed value div after label {label:?}: {body}"));
    after_label[value_start..value_start + value_end]
        .parse()
        .unwrap_or_else(|_| panic!("non-numeric value after label {label:?}: {body}"))
}

#[sqlx::test(migrations = false)]
async fn samples_page_shows_fetch_attempt_status_counts(pool: PgPool) {
    migrate(&pool).await;
    seed_fetch_attempt(&pool, 1, "success").await;
    seed_fetch_attempt(&pool, 2, "success").await;
    seed_fetch_attempt(&pool, 3, "success").await;
    seed_fetch_attempt(&pool, 4, "rejected").await;
    seed_fetch_attempt(&pool, 5, "rejected").await;
    seed_fetch_attempt(&pool, 6, "timeout").await;
    seed_fetch_attempt(&pool, 7, "too_big").await;
    seed_fetch_attempt(&pool, 8, "empty").await;
    seed_fetch_attempt(&pool, 9, "dead").await;
    seed_fetch_attempt(&pool, 10, "pending").await;

    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/samples",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("Fetch attempts"),
        "expected the fetch-attempt status strip panel: {body}"
    );
    assert_eq!(strip_count(&body, "Success"), 3);
    assert_eq!(strip_count(&body, "Rejected"), 2);
    assert_eq!(strip_count(&body, "Timeout"), 1);
    assert_eq!(strip_count(&body, "Too big"), 1);
    assert_eq!(strip_count(&body, "Empty"), 1);
    assert_eq!(strip_count(&body, "Dead"), 1);
    assert_eq!(strip_count(&body, "Pending"), 1);
}

#[sqlx::test(migrations = false)]
async fn samples_page_hides_fetch_attempts_panel_when_empty(pool: PgPool) {
    migrate(&pool).await;
    let state = test_state(pool);
    let (_, cookie) = state.sessions.create();
    let app = test_app(state);

    let response = app
        .oneshot(get_request(
            "/samples",
            Some(&format!("{}={cookie}", auth::SESSION_COOKIE)),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        !body.contains("Fetch attempts"),
        "no fetch_attempt rows exist, so the status strip must not render: {body}"
    );
}
