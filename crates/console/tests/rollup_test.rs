//! The hourly roll-ups (`console::rollup`, core-scoring migration 0025) against the ledger they
//! summarise. The property that matters is not that the tables hold the right rows, though that is
//! tested too, but that a window assembled from the roll-up, the partial hour at its start and the
//! unfolded tail equals the same window grouped straight from the ledger, at every position of the
//! cursor. Every comparison runs both sides in ONE statement, so both see the same `now()`.

use console::rollup;
use sqlx::PgPool;

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

/// `n` ledger rows scattered over the last 40 days in an order unrelated to their ids (an intake
/// that is behind appends old events after new ones), from four sensors on two transports and
/// three ports (one in five unstamped), 37 source addresses and six signal types, with a few
/// events dated in the future (a sensor clock ahead). The chain trigger is off: the console only
/// reads the ledger.
async fn seed(pool: &PgPool, n: i32) {
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         SELECT '10.9.0.0'::inet + (g % 37), \
                (ARRAY['telnet', 'ssh', 'http', 'ftp'])[1 + g % 4], \
                (ARRAY['honeypot_connection', 'honeypot_login_attempt', 'honeypot_command_exec', \
                       'port_scan', 'honeypot_malware_upload', 'honeypot_session_end'])[1 + g % 6] \
                    ::signal_type_enum, \
                (ARRAY['tcp', 'udp'])[1 + g % 2]::protocol_enum, false, 'honeypot', 1, 0.5, \
                CASE WHEN g % 97 = 0 THEN now() + interval '2 hours' \
                     ELSE now() - ((g::bigint * 104729) % 3456000) * interval '1 second' END, \
                CASE WHEN g % 5 = 0 THEN '{}'::jsonb \
                     ELSE jsonb_build_object('local_port', 20 + g % 3) END, \
                sha256(convert_to(g::text, 'UTF8')) \
         FROM generate_series(1, $1) g",
    )
    .bind(n)
    .execute(pool)
    .await
    .unwrap();
    // Events packed around every window start the tests use (24 hours, 7 days and 30 days back),
    // two minutes apart for forty minutes either side, and exactly on every hour boundary of the
    // last two days: the places an off-by-one in the partial-hour rule would show.
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         SELECT '10.9.1.0'::inet + (k % 5), 'telnet', 'honeypot_connection', 'tcp', false, \
                'honeypot', 1, 0.5, at, '{}'::jsonb, sha256(convert_to(at::text || k::text, 'UTF8')) \
         FROM (SELECT now() - back + k * interval '1 minute' AS at, k \
               FROM unnest(ARRAY[interval '24 hours', interval '7 days', interval '30 days']) AS back, \
                    generate_series(-40, 40, 2) AS k \
               UNION ALL \
               SELECT event_hour(now()) - h * interval '1 hour', h FROM generate_series(0, 48) h \
               UNION ALL \
               SELECT event_hour(now() - interval '24 hours') + interval '1 hour', 99) p",
    )
    .execute(pool)
    .await
    .unwrap();
}

/// How many rows differ between `new_sql` and `old_sql` (two `SELECT`s with the same columns), in
/// either direction, and how many rows each has. All in one statement, so one `now()`.
async fn diff(pool: &PgPool, with: &str, new_sql: &str, old_sql: &str) -> (i64, i64, i64, i64) {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{with}, new AS ({new_sql}), old AS ({old_sql}) \
         SELECT (SELECT count(*) FROM new), (SELECT count(*) FROM old), \
                (SELECT count(*) FROM (SELECT * FROM new EXCEPT SELECT * FROM old) a), \
                (SELECT count(*) FROM (SELECT * FROM old EXCEPT SELECT * FROM new) b)"
    )))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// The listener window from `start`, by (sensor, protocol, port), against the ledger grouped
/// directly, with the cursor hint a page would pass (the stored cursor), none, and one below the
/// stored cursor (a page that read the cursor before another page advanced it).
async fn listener_window_matches_the_ledger(pool: &PgPool, start: &str) {
    let cursor = rollup::cursor(pool).await.unwrap();
    for hint in [cursor, 0, cursor / 2] {
        listener_window_matches_the_ledger_with(pool, start, hint).await;
    }
}

async fn listener_window_matches_the_ledger_with(pool: &PgPool, start: &str, hint: i64) {
    let with = rollup::listener_window_sql(start, hint);
    let (new, old, only_new, only_old) = diff(
        pool,
        &with,
        "SELECT sensor, protocol::text AS protocol, local_port, sum(events)::bigint AS events, \
                max(last_event_at) AS last_event_at FROM parts GROUP BY 1, 2, 3",
        &format!(
            "SELECT sensor, protocol::text, COALESCE(metadata->>'local_port', ''), count(*), \
                    max(observed_at) FROM event WHERE observed_at >= {start} GROUP BY 1, 2, 3"
        ),
    )
    .await;
    assert_eq!(new, old, "listener groups from {start}");
    assert!(new > 0, "the fixture reaches {start}");
    assert_eq!(
        (only_new, only_old),
        (0, 0),
        "listener counts from {start} differ from the ledger's"
    );
    // By hour as well: the same parts summed per hour.
    let (n, o, a, b) = diff(
        pool,
        &with,
        "SELECT hour, sum(events)::bigint FROM parts GROUP BY 1",
        &format!(
            "SELECT event_hour(observed_at), count(*) FROM event \
             WHERE observed_at >= {start} GROUP BY 1"
        ),
    )
    .await;
    assert_eq!((n, a, b), (o, 0, 0), "hourly counts from {start}");
}

const STARTS: [&str; 4] = [
    // A start inside an hour: the partial hour comes from the ledger.
    "now() - interval '24 hours'",
    // A start on an hour boundary: nothing partial.
    "date_trunc('hour', now()) - interval '5 hours'",
    "now() - interval '7 days'",
    "now() - interval '30 days'",
];

#[sqlx::test(migrations = false)]
async fn a_window_is_exact_at_every_position_of_the_cursor(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 4000).await;

    // Nothing folded: every window comes from the ledger's own tail.
    for start in STARTS {
        listener_window_matches_the_ledger(&pool, start).await;
    }
    // Then fold a little at a time, checking after every step, to the end and past it.
    let mut steps = 0;
    loop {
        let folded = rollup::refresh_with(&pool, 900, 1).await.unwrap();
        for start in STARTS {
            listener_window_matches_the_ledger(&pool, start).await;
        }
        steps += 1;
        if folded == 0 {
            break;
        }
    }
    assert!(steps >= 5, "the fixture needs several batches: {steps}");

    // Events appended after the last fold are counted from the ledger until the next one.
    seed(&pool, 700).await;
    for start in STARTS {
        listener_window_matches_the_ledger(&pool, start).await;
    }
}

/// The tables themselves equal a grouping of the ledger, event for event, once folded.
#[sqlx::test(migrations = false)]
async fn the_folded_tables_equal_the_ledger_grouped_by_hour(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 4000).await;
    let folded = rollup::refresh_with(&pool, 1000, 100).await.unwrap();
    assert!(folded >= 4000, "{folded}");

    let (_, _, a, b): (i64, i64, i64, i64) = sqlx::query_as(
        "WITH new AS (SELECT hour, sensor, protocol::text, local_port, events, last_event_at \
                      FROM event_hour_listener), \
              old AS (SELECT event_hour(observed_at), sensor, protocol::text, \
                             COALESCE(metadata->>'local_port', ''), count(*), max(observed_at) \
                      FROM event WHERE observed_at >= now() - interval '45 days' \
                      GROUP BY 1, 2, 3, 4) \
         SELECT (SELECT count(*) FROM new), (SELECT count(*) FROM old), \
                (SELECT count(*) FROM (SELECT * FROM new EXCEPT SELECT * FROM old) x), \
                (SELECT count(*) FROM (SELECT * FROM old EXCEPT SELECT * FROM new) y)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((a, b), (0, 0), "listener hours differ from the ledger's");

    // Caught up: a second refresh folds nothing, and changes nothing.
    assert_eq!(rollup::refresh(&pool).await.unwrap(), 0);
    let cursor: i64 = sqlx::query_scalar("SELECT last_event_id FROM event_rollup_cursor")
        .fetch_one(&pool)
        .await
        .unwrap();
    let newest: i64 = sqlx::query_scalar("SELECT max(id) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(cursor, newest);
}

/// Two refreshes at once fold each event once: the one that cannot take the lock does nothing.
#[sqlx::test(migrations = false)]
async fn concurrent_refreshes_fold_each_event_once(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 3000).await;
    let (a, b, c) = tokio::join!(
        rollup::refresh_with(&pool, 500, 20),
        rollup::refresh_with(&pool, 500, 20),
        rollup::refresh_with(&pool, 500, 20),
    );
    let covered = a.unwrap() + b.unwrap() + c.unwrap();
    let ids: i64 = sqlx::query_scalar("SELECT max(id) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        covered as i64, ids,
        "every id folded exactly once between them"
    );
    let total: i64 = sqlx::query_scalar("SELECT sum(events)::bigint FROM event_hour_listener")
        .fetch_one(&pool)
        .await
        .unwrap();
    let ledger: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM event WHERE observed_at >= now() - interval '45 days'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(total, ledger);
}

/// A cursor ahead of the ledger (its ids were reset) cannot be trusted at all: the tables are
/// rebuilt from the ledger, and a window is exact again.
#[sqlx::test(migrations = false)]
async fn a_cursor_past_the_ledger_starts_over(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 1000).await;
    rollup::refresh_with(&pool, 400, 10).await.unwrap();
    sqlx::query("TRUNCATE event RESTART IDENTITY")
        .execute(&pool)
        .await
        .unwrap();
    seed(&pool, 300).await;

    // The first refresh notices, discards what it held and folds the new ledger.
    rollup::refresh(&pool).await.unwrap();
    let cursor: i64 = sqlx::query_scalar("SELECT last_event_id FROM event_rollup_cursor")
        .fetch_one(&pool)
        .await
        .unwrap();
    let newest: i64 = sqlx::query_scalar("SELECT max(id) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        cursor, newest,
        "the cursor follows the new ledger, not the old one"
    );
    assert!(
        newest < 1000,
        "the ledger really is shorter than the old cursor"
    );
    for start in STARTS {
        listener_window_matches_the_ledger(&pool, start).await;
    }
}

/// Rows past the table's retention are dropped by the fold, and events that old are never folded.
#[sqlx::test(migrations = false)]
async fn hours_past_retention_are_dropped_and_not_folded(pool: PgPool) {
    migrate(&pool).await;
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO event_hour_listener VALUES (now() - interval '60 days', 'old', 'tcp', '', 5, now()), \
                                                (now() - interval '1 day', 'new', 'tcp', '', 5, now())",
    )
    .execute(&pool)
    .await
    .unwrap();
    // One event 50 days old (past the listener table's 45) and one an hour old.
    for age in ["50 days", "1 hour"] {
        sqlx::query(
            "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                                weight, confidence, observed_at, hash) \
             VALUES ('10.9.9.8', 'telnet', 'honeypot_connection', 'tcp', false, 'honeypot', 1, 0.5, \
                     now() - $1::interval, sha256(convert_to($1, 'UTF8')))",
        )
        .bind(age)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert_eq!(rollup::refresh(&pool).await.unwrap(), 2);

    let listener_sensors: Vec<String> =
        sqlx::query_scalar("SELECT sensor FROM event_hour_listener ORDER BY sensor")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        listener_sensors,
        ["new", "telnet"],
        "60-day-old hour dropped, 50-day-old event not folded"
    );
}

// --- the statements the pages run, held to the ledger they replace ---

/// A pool of one connection in time zone `zone`.
async fn pool_in_zone(pool: &PgPool, zone: &str) -> PgPool {
    let zone = zone.to_string();
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |conn, _| {
            let zone = zone.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(format!("SET TIME ZONE '{zone}'")))
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap()
}

type Hours = Vec<(chrono::DateTime<chrono::Utc>, i64)>;
type Days = Vec<(chrono::NaiveDate, i64)>;
type Sensors = Vec<(String, i64)>;

/// What the dashboard's timelines and the sensor split say now, from the roll-up statements and
/// from the ledger, in ONE transaction so both see one `now()`: each pair is (roll-up, ledger).
struct Charts {
    hourly: (Hours, Hours),
    daily7: (Days, Days),
    daily30: (Days, Days),
    sensors: (Sensors, Sensors),
}

async fn charts(pool: &PgPool) -> Charts {
    use console::routes::dashboard::{
        DAILY_SERIES_RAW_SQL, HOURLY_SERIES_RAW_SQL, daily_series_sql, hourly_series_sql,
        protocol_distribution_sql,
    };
    let hint = rollup::cursor(pool).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    let hourly_new = sqlx::query_as(sqlx::AssertSqlSafe(hourly_series_sql(hint)))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    let hourly_old = sqlx::query_as(HOURLY_SERIES_RAW_SQL)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    let mut daily = Vec::new();
    for days in [6i32, 29] {
        let new = sqlx::query_as(sqlx::AssertSqlSafe(daily_series_sql(hint)))
            .bind(days)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        let old = sqlx::query_as(DAILY_SERIES_RAW_SQL)
            .bind(days)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        daily.push((new, old));
    }
    let mut sensors_new: Sensors =
        sqlx::query_as(sqlx::AssertSqlSafe(protocol_distribution_sql(hint)))
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    let mut sensors_old: Sensors = sqlx::query_as(
        "SELECT sensor, COUNT(*) FROM event WHERE observed_at >= now() - interval '24 hours' \
         GROUP BY sensor",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    // Equal counts have no defined order.
    sensors_new.sort();
    sensors_old.sort();
    let daily30 = daily.pop().unwrap();
    let daily7 = daily.pop().unwrap();
    Charts {
        hourly: (hourly_new, hourly_old),
        daily7,
        daily30,
        sensors: (sensors_new, sensors_old),
    }
}

#[sqlx::test(migrations = false)]
async fn the_dashboards_charts_equal_the_ledger_at_every_position_of_the_cursor(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 4000).await;
    let mut steps = 0;
    loop {
        let c = charts(&pool).await;
        assert_eq!(
            c.hourly.0.len(),
            25,
            "the hourly chart always has 25 buckets"
        );
        assert!(
            c.hourly.1.iter().any(|(_, n)| *n > 0),
            "the fixture reaches the last day"
        );
        assert_eq!(c.hourly.0, c.hourly.1, "hourly chart after {steps} folds");
        assert_eq!(c.daily7.0, c.daily7.1, "7-day chart after {steps} folds");
        assert_eq!(c.daily30.0, c.daily30.1, "30-day chart after {steps} folds");
        assert!(c.daily30.1.iter().filter(|(_, n)| *n > 0).count() > 20);
        assert_eq!(c.sensors.0, c.sensors.1, "sensor split after {steps} folds");
        assert!(c.sensors.1.len() == 4);
        steps += 1;
        if rollup::refresh_with(&pool, 900, 1).await.unwrap() == 0 {
            break;
        }
    }
    assert!(steps >= 5, "{steps}");
    // And once more with events the roll-up has not seen.
    seed(&pool, 700).await;
    let c = charts(&pool).await;
    assert_eq!(c.hourly.0, c.hourly.1);
    assert_eq!(c.daily30.0, c.daily30.1);
    assert_eq!(c.sensors.0, c.sensors.1);
}

/// The charts answer from the roll-ups in any zone whose offset is a whole number of hours, DST
/// included, and name the zones they cannot answer in.
#[sqlx::test(migrations = false)]
async fn the_charts_hold_in_whole_hour_zones_and_decline_the_others(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 3000).await;
    rollup::refresh_with(&pool, 100_000, 5).await.unwrap();
    seed(&pool, 400).await; // an unfolded tail

    for zone in [
        "UTC",
        "America/Los_Angeles",
        "Europe/Berlin",
        "Pacific/Auckland",
        "Asia/Tokyo",
    ] {
        let p = pool_in_zone(&pool, zone).await;
        assert!(rollup::whole_hour_zone(&p).await.unwrap(), "{zone}");
        let c = charts(&p).await;
        assert_eq!(c.hourly.0, c.hourly.1, "hourly chart in {zone}");
        assert_eq!(c.daily7.0, c.daily7.1, "7-day chart in {zone}");
        assert_eq!(c.daily30.0, c.daily30.1, "30-day chart in {zone}");
        assert_eq!(c.sensors.0, c.sensors.1, "sensor split in {zone}");
    }
    for zone in ["Asia/Kolkata", "Asia/Kathmandu"] {
        let p = pool_in_zone(&pool, zone).await;
        assert!(
            !rollup::whole_hour_zone(&p).await.unwrap(),
            "{zone} is not a whole-hour zone"
        );
        let c = charts(&p).await;
        assert_ne!(
            c.daily30.0, c.daily30.1,
            "{zone}: the guard exists because the roll-up's days are wrong here"
        );
        assert_eq!(
            c.sensors.0, c.sensors.1,
            "the sensor split in {zone} needs no guard"
        );
    }
}

/// What an `EXPLAIN ANALYZE` says the statement touched in the ledger: the rows its scans of
/// `event` produced (rows times loops) plus every row a filter threw away.
fn event_rows_touched(plan: &[String]) -> f64 {
    let number_after = |line: &str, key: &str| -> f64 {
        let at = line.find(key).expect(key) + key.len();
        let end = line[at..]
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(line.len() - at);
        line[at..at + end].parse().unwrap()
    };
    plan.iter()
        .map(|l| {
            if l.contains(" on event ") && l.contains("(actual") {
                number_after(l, "rows=") * number_after(l, "loops=")
            } else if l.contains("Rows Removed by") {
                number_after(l, ": ")
            } else {
                0.0
            }
        })
        .sum()
}

/// A current roll-up must leave the ledger nearly untouched. The unfolded tail is the part a
/// planner can get wrong: given the cursor as a subquery, it cannot see that `id > cursor` keeps
/// nothing, and read the whole window by time instead (the cost the roll-up exists to remove).
#[sqlx::test(migrations = false)]
async fn a_current_rollup_leaves_the_ledger_nearly_untouched(pool: PgPool) {
    migrate(&pool).await;
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(&pool)
        .await
        .unwrap();
    // 300,000 events in the last 20 hours, appended in time order as a live ledger is (the ids and
    // the times are correlated, which is what makes a scan by time look cheap to a planner): all
    // inside the 24-hour window, none in its partial first hour.
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         SELECT '10.9.0.0'::inet + (g % 37), (ARRAY['telnet', 'ssh'])[1 + g % 2], \
                'honeypot_connection', 'tcp', false, 'honeypot', 1, 0.5, \
                now() - ((300000 - g)::bigint * 72000 / 300000) * interval '1 second', \
                jsonb_build_object('local_port', 23), \
                sha256(convert_to(g::text, 'UTF8')) \
         FROM generate_series(1, 300000) g",
    )
    .execute(&pool)
    .await
    .unwrap();
    rollup::refresh_with(&pool, 100_000, 5).await.unwrap();
    sqlx::query("ANALYZE").execute(&pool).await.unwrap();

    let hint = rollup::cursor(&pool).await.unwrap();
    for (name, sql) in [
        (
            "sensor split",
            console::routes::dashboard::protocol_distribution_sql(hint),
        ),
        (
            "fleet 24 hours",
            console::routes::fleet::listener_recent_sql(hint),
        ),
        (
            "hourly chart",
            console::routes::dashboard::hourly_series_sql(hint),
        ),
    ] {
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "EXPLAIN (ANALYZE, COSTS OFF) {sql}"
        )))
        .fetch_all(&pool)
        .await
        .unwrap();
        let touched = event_rows_touched(&plan);
        assert!(
            touched < 100.0,
            "{name} touched {touched} of 300,000 ledger rows with the roll-up current:\n{}",
            plan.join("\n")
        );
    }
}

/// Makes every fold fail at its last statement (the cursor update), so the roll-up stays where it
/// is and every refresh reports an error, while the readers keep working.
async fn break_refresh(pool: &PgPool) {
    for sql in [
        "CREATE FUNCTION refuse_cursor_update() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'cursor update refused'; END $$",
        "CREATE TRIGGER refuse BEFORE UPDATE ON event_rollup_cursor \
         FOR EACH ROW EXECUTE FUNCTION refuse_cursor_update()",
    ] {
        sqlx::query(sql).execute(pool).await.unwrap();
    }
}

/// A roll-up nobody maintains must cost about what the page cost before the roll-up, not more.
/// 200,000 events from ten days ago and 20,000 from the last hours, in time order, never folded:
/// the cursor is far behind in ids but the 24-hour window is a tenth of them. Reading everything
/// past the cursor (the id range) touches all 220,000; reading the window by time touches 20,000.
/// A statement that forces the id range (`observed_at + interval '0'`, the form this replaced)
/// measured 3.3 times the cost of the plain window read on a seeded ledger.
#[sqlx::test(migrations = false)]
async fn a_roll_up_that_is_not_maintained_costs_a_window_read_not_a_walk_of_the_ids(pool: PgPool) {
    migrate(&pool).await;
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(&pool)
        .await
        .unwrap();
    for (n, span_hours_ago_from, span_hours_ago_to) in
        [(200_000i64, 240i64, 230i64), (20_000, 20, 1)]
    {
        sqlx::query(
            "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                                weight, confidence, observed_at, metadata, hash) \
             SELECT '10.9.0.0'::inet + (g % 37), (ARRAY['telnet', 'ssh'])[1 + g % 2], \
                    'honeypot_connection', 'tcp', false, 'honeypot', 1, 0.5, \
                    now() - $2 * interval '1 hour' + (g::double precision / $1) * ($2 - $3) * interval '1 hour', \
                    jsonb_build_object('local_port', 23), \
                    sha256(convert_to(g::text || $2::text, 'UTF8')) \
             FROM generate_series(1, $1) g",
        )
        .bind(n)
        .bind(span_hours_ago_from)
        .bind(span_hours_ago_to)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("ANALYZE").execute(&pool).await.unwrap();
    break_refresh(&pool).await;

    let health = rollup::Health::default();
    let hint = health.refresh_for_page(&pool).await;
    assert_eq!(health.consecutive_failures(), 1);
    assert_eq!(hint, 0, "nothing was ever folded");

    let sql = console::routes::dashboard::protocol_distribution_sql(hint);
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, COSTS OFF) {sql}"
    )))
    .fetch_all(&pool)
    .await
    .unwrap();
    let touched = event_rows_touched(&plan);
    assert!(
        touched < 60_000.0,
        "an unmaintained roll-up walked {touched} of 220,000 ledger rows for a 20,000-row window:\n{}",
        plan.join("\n")
    );

    // And it is still exact.
    let (new, old, a, b) = diff(
        &pool,
        &rollup::listener_window_sql("now() - interval '24 hours'", hint),
        "SELECT sensor, sum(events)::bigint FROM parts GROUP BY 1",
        "SELECT sensor, count(*) FROM event WHERE observed_at >= now() - interval '24 hours' GROUP BY 1",
    )
    .await;
    assert_eq!((new, a, b), (old, 0, 0));
}

/// A whole-hour offset today is not enough: a zone whose daylight-saving shift is half an hour
/// (Lord Howe, +10:30 in winter and +11 in summer) has hours that start on a half hour for part of
/// the 45 days the roll-up keeps. Dates are fixed so the answer does not depend on the day the
/// test runs.
#[sqlx::test(migrations = false)]
async fn a_zone_that_was_off_the_hour_within_the_kept_days_is_declined(pool: PgPool) {
    use chrono::TimeZone;
    migrate(&pool).await;
    let p = pool_in_zone(&pool, "Australia/Lord_Howe").await;
    // 2026-10-14: +11 (daylight time began on 2026-10-04), 45 days earlier it was +10:30.
    let spring = chrono::Utc
        .with_ymd_and_hms(2026, 10, 14, 12, 0, 0)
        .unwrap();
    assert!(!rollup::whole_hour_zone_at(&p, Some(spring)).await.unwrap());
    // 2027-01-20: +11 for the whole span.
    let summer = chrono::Utc.with_ymd_and_hms(2027, 1, 20, 12, 0, 0).unwrap();
    assert!(rollup::whole_hour_zone_at(&p, Some(summer)).await.unwrap());
    // 2026-07-01: +10:30 now.
    let winter = chrono::Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    assert!(!rollup::whole_hour_zone_at(&p, Some(winter)).await.unwrap());
}

/// What the fleet pane's 24-hour read was before the roll-up.
const OLD_LISTENER_RECENT_SQL: &str = "\
    SELECT sensor, protocol::text AS protocol, COALESCE(metadata->>'local_port', '') AS local_port, \
           count(*) AS events_24h, max(observed_at) AS last_event_at \
    FROM event WHERE observed_at >= now() - interval '24 hours' GROUP BY 1, 2, 3";

#[sqlx::test(migrations = false)]
async fn the_fleet_panes_24_hour_read_equals_the_ledger_at_every_cursor(pool: PgPool) {
    migrate(&pool).await;
    seed(&pool, 4000).await;
    loop {
        let hint = rollup::cursor(&pool).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        type Row = (String, String, String, i64, chrono::DateTime<chrono::Utc>);
        let mut new: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(
            console::routes::fleet::listener_recent_sql(hint),
        ))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        let mut old: Vec<Row> = sqlx::query_as(OLD_LISTENER_RECENT_SQL)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        new.sort();
        old.sort();
        assert!(old.len() >= 8, "{old:?}");
        assert_eq!(new, old);
        if rollup::refresh_with(&pool, 900, 1).await.unwrap() == 0 {
            break;
        }
    }
}
