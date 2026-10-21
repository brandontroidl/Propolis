//! The pages that read the hourly roll-up (`console::rollup`) keep it current, say so when they
//! cannot, and the dashboard's most-active panel is held for a short while (`console::read_state`).
//!
//! The roll-up tests in `rollup_test.rs` call `refresh` themselves; these go through the routes,
//! which is where a removed call would go unnoticed (every count stays exact without the refresh,
//! only slower). Each test runs on its own database; every address is RFC 5737 documentation space.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use console::auth::{self, PasswordStore, RateLimiter, SessionStore};
use console::read_state::ReadState;
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

fn state(db: PgPool, read_state: Arc<ReadState>) -> AppState {
    AppState {
        db,
        sessions: Arc::new(SessionStore::new([13u8; 32])),
        passwords: Arc::new(PasswordStore::new("rollup-pages-test-password")),
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
        read_state,
    }
}

struct Console {
    app: Router,
    cookie: String,
}

impl Console {
    fn new(db: PgPool, read_state: Arc<ReadState>) -> Self {
        let state = state(db, read_state);
        let (_, cookie) = state.sessions.create();
        Self {
            app: routes::router(state).layer(MockConnectInfo(PEER)),
            cookie,
        }
    }

    async fn get(&self, uri: &str) -> String {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(
                        "cookie",
                        format!("{}={}", auth::SESSION_COOKIE, self.cookie),
                    )
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
}

/// `n` events from `ip`, the last hour, from sensor `sensor`. The chain trigger is off: the console
/// only reads the ledger.
async fn events(pool: &PgPool, ip: &str, sensor: &str, n: i32) {
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         SELECT $1::inet, $2, 'honeypot_login_attempt', 'tcp', false, 'honeypot', 1, 0.5, \
                now() - g * interval '1 second', jsonb_build_object('local_port', 22), \
                sha256(convert_to(gen_random_uuid()::text, 'UTF8')) \
         FROM generate_series(1, $3) g",
    )
    .bind(ip)
    .bind(sensor)
    .bind(n)
    .execute(pool)
    .await
    .unwrap();
}

async fn cursor_and_newest(pool: &PgPool) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT last_event_id FROM event_rollup_cursor), (SELECT max(id) FROM event)",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Every page that reads the roll-up folds the events appended since the last fold before it
/// reads. With the call removed every count on the page stays exact (the ledger covers what the
/// roll-up has not), so only the cursor shows it.
#[sqlx::test(migrations = false)]
async fn the_pages_that_read_the_roll_up_advance_it(pool: PgPool) {
    migrate(&pool).await;
    for (uri, name) in [
        ("/", "the dashboard"),
        ("/fleet/status", "the fleet pane's poll"),
        ("/dashboard/chart?range=24h", "the 24 hour chart"),
        ("/dashboard/chart?range=7d", "the 7 day chart"),
        ("/dashboard/chart?range=30d", "the 30 day chart"),
    ] {
        events(&pool, "203.0.113.5", "ssh", 30).await;
        let (cursor, newest) = cursor_and_newest(&pool).await;
        assert!(
            cursor < newest,
            "{name}: the fixture leaves events unfolded"
        );
        let console = Console::new(pool.clone(), ReadState::uncached());
        console.get(uri).await;
        let (cursor, newest) = cursor_and_newest(&pool).await;
        assert_eq!(cursor, newest, "{name} did not fold the new events");
    }
}

/// A refresh that keeps failing is named by the dashboard after the third time in a row and counted
/// by `/metrics`, and both clear when a refresh works again. Every page still renders, and its
/// counts still come from the ledger.
#[sqlx::test(migrations = false)]
async fn a_roll_up_that_cannot_be_refreshed_is_named_and_counted(pool: PgPool) {
    migrate(&pool).await;
    events(&pool, "203.0.113.5", "ssh", 40).await;
    for sql in [
        "CREATE FUNCTION refuse_cursor_update() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'cursor update refused'; END $$",
        "CREATE TRIGGER refuse BEFORE UPDATE ON event_rollup_cursor \
         FOR EACH ROW EXECUTE FUNCTION refuse_cursor_update()",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    let console = Console::new(pool.clone(), ReadState::uncached());
    let banner = "event roll-up refresh";

    for attempt in 1..=2 {
        let page = console.get("/").await;
        assert!(
            !page.contains(banner),
            "attempt {attempt} is not yet repeated failure"
        );
    }
    let page = console.get("/").await;
    assert!(
        page.contains(banner),
        "the third failure in a row is named: {page}"
    );
    assert!(
        page.contains("[40]"),
        "and the sensor split is still the ledger's 40 events: {page}"
    );
    let metrics = console.get("/metrics").await;
    assert!(
        metrics.contains("propolis_console_rollup_refresh_failures 3\n"),
        "{metrics}"
    );
    let fleet = console.get("/fleet/status").await;
    assert!(
        fleet.contains(banner),
        "the fleet pane names it too: {fleet}"
    );

    sqlx::query("DROP TRIGGER refuse ON event_rollup_cursor")
        .execute(&pool)
        .await
        .unwrap();
    let page = console.get("/").await;
    assert!(!page.contains(banner), "a refresh that works clears it");
    let metrics = console.get("/metrics").await;
    assert!(metrics.contains("propolis_console_rollup_refresh_failures 0\n"));
}

/// The most-active panel's markup (the recent-activity panel above it names addresses too).
fn most_active_panel(page: &str) -> &str {
    let from = page.find("Most active").expect("the panel renders");
    let to = page[from..]
        .find("Events timeline")
        .expect("the next panel");
    &page[from..from + to]
}

/// The most-active panel is served from what an earlier load computed while that is current, and
/// once the quarter hour turns the old panel is still what a load gets, with a new one computed
/// behind it for the next; a console told to hold nothing reads every time. The quarter hour is
/// injected, so the wall clock turning mid-test cannot change the outcome.
#[sqlx::test(migrations = false)]
async fn the_most_active_panel_is_served_stale_and_refreshed_behind(pool: PgPool) {
    migrate(&pool).await;
    events(&pool, "203.0.113.5", "ssh", 5).await;

    let quarter_hour = Arc::new(std::sync::atomic::AtomicU64::new(1000));
    let clock = Arc::clone(&quarter_hour);
    let holding = Console::new(
        pool.clone(),
        ReadState::with_most_active(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
            Duration::from_secs(5),
            true,
            move || clock.load(std::sync::atomic::Ordering::SeqCst),
        ),
    );
    let uncached = Console::new(pool.clone(), ReadState::uncached());
    let first = holding.get("/").await;
    assert!(most_active_panel(&first).contains("203.0.113.5"));

    // A busier address appears.
    events(&pool, "198.51.100.77", "telnet", 50).await;
    let fresh = uncached.get("/").await;
    assert!(
        most_active_panel(&fresh).contains("198.51.100.77"),
        "a console that holds nothing sees it at once"
    );
    let held = holding.get("/").await;
    assert!(
        !most_active_panel(&held).contains("198.51.100.77"),
        "the holding console still shows the earlier answer"
    );
    assert!(most_active_panel(&held).contains("203.0.113.5"));

    // The quarter hour turns: this load still answers from the old panel (it does not wait for the
    // aggregate) and starts the recomputation, which a later load sees.
    quarter_hour.store(1001, std::sync::atomic::Ordering::SeqCst);
    let stale = holding.get("/").await;
    assert!(
        !most_active_panel(&stale).contains("198.51.100.77"),
        "the load that finds the panel out of date is answered from the old one"
    );
    let mut refreshed = false;
    for _ in 0..400 {
        if most_active_panel(&holding.get("/").await).contains("198.51.100.77") {
            refreshed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(refreshed, "and the background recomputation replaces it");
}

/// A held panel older than the age cap is not shown: the load waits for a fresh computation, so a
/// stalled refresher cannot leave an old answer on the page.
#[sqlx::test(migrations = false)]
async fn a_panel_past_the_age_cap_is_recomputed_before_it_is_shown(pool: PgPool) {
    migrate(&pool).await;
    events(&pool, "203.0.113.5", "ssh", 5).await;

    // The panel's age is read from an injected clock, so how long a render takes on a loaded
    // machine cannot move it across the cap.
    let base = std::time::Instant::now();
    let elapsed_ms = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = Arc::clone(&elapsed_ms);
    let holding = Console::new(
        pool.clone(),
        ReadState::with_clocks(
            Duration::from_secs(3600),
            Duration::from_secs(900),
            Duration::from_secs(5),
            true,
            || 1000,
            move || base + Duration::from_millis(clock.load(std::sync::atomic::Ordering::SeqCst)),
        ),
    );
    let first = holding.get("/").await;
    assert!(most_active_panel(&first).contains("203.0.113.5"));
    events(&pool, "198.51.100.77", "telnet", 50).await;
    elapsed_ms.fetch_add(899_000, std::sync::atomic::Ordering::SeqCst);
    let held = holding.get("/").await;
    assert!(
        !most_active_panel(&held).contains("198.51.100.77"),
        "14:59 old is still served"
    );

    elapsed_ms.fetch_add(2_000, std::sync::atomic::Ordering::SeqCst);
    let past_cap = holding.get("/").await;
    assert!(
        most_active_panel(&past_cap).contains("198.51.100.77"),
        "past the cap the page shows a recomputed panel, not the held one"
    );
}
