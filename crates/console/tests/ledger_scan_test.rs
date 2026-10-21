//! The console's page-load statements must not read the whole event ledger (or, for the score
//! ordering, every scored address) to answer a question that has a short answer.
//!
//! Row counts in a test database are too small for the planner to prefer an index, so a plan test
//! cannot ask "which plan does the planner pick". It asks the question that does not depend on
//! size: with sequential scans switched off, does any plan exist that avoids a scan of the table?
//! A statement with no usable index can only show `Seq Scan` (switching it off penalises the node
//! but cannot remove it); a statement shaped for an index shows the index and no scan. Each test
//! runs the statement text the page itself runs, taken from the route module, never a copy.

use sqlx::{Connection, PgPool};

async fn migrate(pool: &PgPool) {
    sqlx::migrate!("../core-scoring/migrations")
        .run(pool)
        .await
        .unwrap();
    review::migrator().run(pool).await.unwrap();
    fleet::migrator().run(pool).await.unwrap();
}

/// The plan of `sql` with sequential scans penalised, one line per node. `binds` are bound as
/// text, which every statement here casts itself.
async fn plan(pool: &PgPool, sql: &str, binds: &[&str]) -> String {
    let owned: Vec<String> = binds.iter().map(|b| b.to_string()).collect();
    plan_bound(pool, sql, |mut q| {
        for b in owned {
            q = q.bind(b);
        }
        q
    })
    .await
}

type PlanQuery = sqlx::query::QueryScalar<
    'static,
    sqlx::Postgres,
    String,
    <sqlx::Postgres as sqlx::Database>::Arguments,
>;

/// [`plan`] for a statement that binds something other than text: `bind` adds the parameters.
async fn plan_bound(pool: &PgPool, sql: &str, bind: impl FnOnce(PlanQuery) -> PlanQuery) -> String {
    let mut conn = pool.acquire().await.unwrap();
    sqlx::query("SET enable_seqscan = off")
        .execute(&mut *conn)
        .await
        .unwrap();
    let explain = format!("EXPLAIN (COSTS OFF) {sql}");
    let query = bind(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(
        explain,
    )));
    let lines: Vec<String> = query.fetch_all(&mut *conn).await.unwrap();
    conn.ping().await.unwrap();
    lines.join("\n")
}

fn assert_no_scan_of(plan: &str, table: &str, what: &str) {
    assert!(
        !plan.contains(&format!("Seq Scan on {table}")),
        "{what} scans {table} end to end:\n{plan}"
    );
}

/// `n` scored addresses with spread-out scores, ages and breadth.
async fn seed_scores(pool: &PgPool, n: i32) {
    sqlx::query(
        "INSERT INTO ip_score (source_ip, raw_score, decay_anchor, max_confidence, event_count, \
             distinct_categories, has_confirmed_real, distinct_wan_count, distinct_sensor_count, \
             first_seen, last_seen) \
         SELECT '10.1.0.0'::inet + i, (i * 37 % 97) + 1, now() - (i * 13 % 72) * interval '1 hour', \
                0.5, 1 + i % 50, 1, false, 1 + i % 4, 1, now() - interval '3 days', now() \
         FROM generate_series(1, $1) AS i",
    )
    .bind(n)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn top_attacker_and_the_attackers_score_sort_are_read_off_the_score_index(pool: PgPool) {
    migrate(&pool).await;
    seed_scores(&pool, 200).await;

    let top = plan(&pool, &console::routes::dashboard::top_attacker_sql(), &[]).await;
    assert_no_scan_of(&top, "ip_score", "the dashboard's top attacker");
    assert!(top.contains("ip_score_order_idx"), "{top}");

    for (desc, resuming) in [(true, false), (false, false), (true, true), (false, true)] {
        let sql = console::routes::ips::score_batch_sql(desc, resuming);
        let binds: &[&str] = if resuming { &["10.1.0.77"] } else { &[] };
        let p = plan(&pool, &sql, binds).await;
        assert_no_scan_of(&p, "ip_score", "an Attackers score-sort load");
        assert!(
            p.contains("ip_score_order_idx"),
            "desc={desc} resuming={resuming}:\n{p}"
        );
    }
}

/// The index key is only a faster way to ask the old question, so it must rank rows the way the
/// live effective score does: for addresses below the cap, the same order at the moment of the
/// read; for addresses at the cap (which tie on the live score), by how far past it they are. A
/// zero score sorts last.
#[sqlx::test(migrations = false)]
async fn the_score_order_key_ranks_rows_as_the_live_score_does(pool: PgPool) {
    migrate(&pool).await;
    // Scores up to well past the cap, anchors from now back four days, one to six vantages, and
    // one zero-score row.
    sqlx::query(
        "INSERT INTO ip_score (source_ip, raw_score, decay_anchor, max_confidence, event_count, \
             distinct_categories, has_confirmed_real, distinct_wan_count, distinct_sensor_count, \
             first_seen, last_seen) \
         SELECT '10.1.0.0'::inet + i, CASE WHEN i = 1 THEN 0 ELSE (i * 53 % 211) + 0.5 END, \
                now() - (i * 29 % 97) * interval '1 hour', 0.5, 1, 1, false, 1 + i % 6, 1, \
                now() - interval '5 days', now() \
         FROM generate_series(1, 600) AS i",
    )
    .execute(&pool)
    .await
    .unwrap();

    let by_key: Vec<(String, f64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT host(source_ip), ({live})::float8 FROM ip_score \
         ORDER BY {key} DESC, source_ip DESC",
        live = console::routes::LIVE_EFFECTIVE_SCORE_SQL,
        key = console::routes::SCORE_ORDER_KEY_SQL,
    )))
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(by_key.len(), 600);

    let live: Vec<f64> = by_key.iter().map(|(_, s)| *s).collect();
    assert!(
        live.windows(2).all(|w| w[0] >= w[1]),
        "ordering by the key must never put a lower live score above a higher one: {live:?}"
    );
    assert!(
        live.iter().any(|s| (*s - 100.0).abs() < 1e-9),
        "the fixture must include addresses at the cap, or the tie rule is untested"
    );
    assert!(
        live.iter().any(|s| *s < 100.0 && *s > 0.0),
        "the fixture must include addresses below the cap"
    );
    assert_eq!(
        by_key.last().unwrap().0,
        "10.1.0.1",
        "a zero score sorts last"
    );
    assert_eq!(*live.last().unwrap(), 0.0);
}

/// Turns the chain trigger off so a test can write ledger rows directly: the console only reads
/// the ledger, and these tests are about what it reads, not how rows get there.
async fn unchained(pool: &PgPool) {
    sqlx::query("ALTER TABLE event DISABLE TRIGGER trg_enforce_chain_linkage")
        .execute(pool)
        .await
        .unwrap();
}

/// One ledger row `age` ago (a Postgres interval), carrying `metadata`.
async fn put_event(
    pool: &PgPool,
    sensor: &str,
    signal: &str,
    protocol: &str,
    age: &str,
    metadata: &str,
) {
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         VALUES ('203.0.113.9', $1, $2::signal_type_enum, $3::protocol_enum, false, 'honeypot', 1, \
                 0.5, now() - $4::interval, $5::jsonb, \
                 sha256(convert_to(gen_random_uuid()::text, 'UTF8')))",
    )
    .bind(sensor)
    .bind(signal)
    .bind(protocol)
    .bind(age)
    .bind(metadata)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn the_search_filter_menus_do_not_read_the_ledger(pool: PgPool) {
    migrate(&pool).await;
    unchained(&pool).await;
    put_event(
        &pool,
        "telnet",
        "honeypot_connection",
        "tcp",
        "1 hour",
        "{}",
    )
    .await;
    put_event(
        &pool,
        "telnet",
        "honeypot_login_attempt",
        "tcp",
        "2 hours",
        "{}",
    )
    .await;
    put_event(&pool, "ssh", "honeypot_connection", "tcp", "3 hours", "{}").await;
    // A sensor whose only events are interaction telemetry still has events to search.
    put_event(
        &pool,
        "redis",
        "honeypot_session_end",
        "tcp",
        "4 hours",
        "{}",
    )
    .await;

    let p = plan(&pool, console::routes::search::FILTER_SENSORS_SQL, &[]).await;
    assert_no_scan_of(&p, "event", "the sensor menu");
    assert!(p.contains("event_listener_idx"), "{p}");
    // A DISTINCT over the index would avoid the table and still read every entry; the menu must
    // step from one sensor to the next.
    assert!(p.contains("Recursive Union"), "{p}");

    let menu: Vec<String> = sqlx::query_scalar(console::routes::search::FILTER_SENSORS_SQL)
        .fetch_all(&pool)
        .await
        .unwrap();
    let distinct: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT sensor FROM event ORDER BY sensor")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(menu, ["redis", "ssh", "telnet"]);
    assert_eq!(menu, distinct, "the menu is exactly the distinct sensors");
}

/// The names the search filter accepts (`SignalType::ALL` in its wire spelling) are the database
/// enum, value for value; the filter turns a name it does not know into "no match" rather than an
/// enum cast error, so a member missing from either side would silently stop matching.
#[sqlx::test(migrations = false)]
async fn the_signal_type_names_are_the_database_enum(pool: PgPool) {
    migrate(&pool).await;
    let mut in_database: Vec<String> =
        sqlx::query_scalar("SELECT unnest(enum_range(NULL::signal_type_enum))::text")
            .fetch_all(&pool)
            .await
            .unwrap();
    let mut known = console::routes::search::signal_type_names();
    in_database.sort();
    known.sort();
    assert_eq!(known, in_database);
}

/// The signal-type menu is the types the ledger holds, found by one index probe each, and is what
/// the `DISTINCT` it replaced gave.
#[sqlx::test(migrations = false)]
async fn the_signal_type_menu_probes_the_index_and_matches_the_distinct_types(pool: PgPool) {
    migrate(&pool).await;
    unchained(&pool).await;
    for signal in [
        "honeypot_login_attempt",
        "honeypot_connection",
        "honeypot_login_attempt",
        "port_scan",
    ] {
        put_event(&pool, "ssh", signal, "tcp", "1 hour", "{}").await;
    }

    let p = plan(&pool, console::routes::search::FILTER_SIGNAL_TYPES_SQL, &[]).await;
    assert_no_scan_of(&p, "event", "the signal-type menu");
    assert!(p.contains("event_signal_observed_idx"), "{p}");
    assert!(p.contains("Recursive Union"), "{p}");

    let menu: Vec<String> = sqlx::query_scalar(console::routes::search::FILTER_SIGNAL_TYPES_SQL)
        .fetch_all(&pool)
        .await
        .unwrap();
    let distinct: Vec<String> = sqlx::query_scalar(
        "SELECT signal_type::text FROM (SELECT DISTINCT signal_type FROM event) d \
         ORDER BY signal_type",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        menu,
        ["honeypot_connection", "honeypot_login_attempt", "port_scan"]
    );
    assert_eq!(menu, distinct);
}

/// The rows of `event` that `EXPLAIN (ANALYZE)` says a statement read (rows times loops of every
/// node on the table) plus every row a filter threw away.
fn event_rows_read(plan: &[String]) -> f64 {
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

/// An event search for a signal type the ledger holds none or few of must start from that type's
/// own index entries, not walk the ledger by time looking for matches. 60,000 events of two types
/// and one of a third; searching a type with none and the rare one each read a handful of rows.
/// Before the index and the enum-typed comparison the first read all 60,000 and returned nothing.
#[sqlx::test(migrations = false)]
async fn an_event_search_for_a_rare_or_absent_signal_type_does_not_walk_the_ledger(pool: PgPool) {
    migrate(&pool).await;
    unchained(&pool).await;
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         SELECT '10.9.0.0'::inet + (g % 37), 'ssh', \
                (CASE WHEN g = 7 THEN 'honeypot_malware_upload' \
                      WHEN g % 2 = 0 THEN 'honeypot_connection' \
                      ELSE 'honeypot_login_attempt' END)::signal_type_enum, \
                'tcp', false, 'honeypot', 1, 0.5, now() - g * interval '2 seconds', '{}'::jsonb, \
                sha256(convert_to(g::text, 'UTF8')) \
         FROM generate_series(1, 60000) g",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ANALYZE event").execute(&pool).await.unwrap();

    // The menu, with the planner free to choose: a plan test that forbids a sequential scan cannot
    // see a statement the planner would run as one.
    let menu_plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, COSTS OFF) {}",
        console::routes::search::FILTER_SIGNAL_TYPES_SQL
    )))
    .fetch_all(&pool)
    .await
    .unwrap();
    let menu_read = event_rows_read(&menu_plan);
    assert!(
        menu_read < 100.0,
        "the signal-type menu read {menu_read} of 60,000 ledger rows:\n{}",
        menu_plan.join("\n")
    );

    for (signal, expected_rows) in [("syn_flood", 0usize), ("honeypot_malware_upload", 1)] {
        let sql = format!(
            "EXPLAIN (ANALYZE, COSTS OFF) {}",
            console::routes::search::event_search_sql(true)
        );
        let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(None::<&str>)
            .bind(None::<&str>)
            .bind(Some(signal))
            .bind(None::<String>)
            .bind(None::<chrono::DateTime<chrono::Utc>>)
            .bind(None::<chrono::DateTime<chrono::Utc>>)
            .bind(None::<i64>)
            .bind(51i64)
            .fetch_all(&pool)
            .await
            .unwrap();
        let read = event_rows_read(&plan);
        assert!(
            read < 100.0,
            "the search for {signal} read {read} of 60,000 ledger rows:\n{}",
            plan.join("\n")
        );
        assert!(
            plan.iter().any(|l| l.contains("event_signal_observed_idx")),
            "{}",
            plan.join("\n")
        );
        let returned = sqlx::query(sqlx::AssertSqlSafe(
            console::routes::search::event_search_sql(true),
        ))
        .bind(None::<&str>)
        .bind(None::<&str>)
        .bind(Some(signal))
        .bind(None::<String>)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<i64>)
        .bind(51i64)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(returned.len(), expected_rows, "{signal}");
    }
}

/// The same search with the filter left out must still be served by time, not forced through the
/// signal-type index: a search with only a date range is the common one.
#[sqlx::test(migrations = false)]
async fn an_event_search_without_a_signal_type_still_reads_by_time(pool: PgPool) {
    migrate(&pool).await;
    unchained(&pool).await;
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         SELECT '10.9.0.0'::inet + (g % 37), 'ssh', 'honeypot_connection', 'tcp', false, \
                'honeypot', 1, 0.5, now() - g * interval '2 seconds', '{}'::jsonb, \
                sha256(convert_to(g::text, 'UTF8')) \
         FROM generate_series(1, 60000) g",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ANALYZE event").execute(&pool).await.unwrap();
    let sql = format!(
        "EXPLAIN (ANALYZE, COSTS OFF) {}",
        console::routes::search::event_search_sql(false)
    );
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(None::<&str>)
        .bind(None::<&str>)
        .bind(None::<&str>)
        .bind(None::<String>)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<i64>)
        .bind(51i64)
        .fetch_all(&pool)
        .await
        .unwrap();
    let read = event_rows_read(&plan);
    assert!(
        read < 200.0,
        "an unfiltered search read {read} rows:\n{}",
        plan.join("\n")
    );
}

/// What the fleet pane's 30-day read returned before it stepped through the index: the newest
/// event of every listener between 30 days and 24 hours ago, grouped over those events.
const OLD_LISTENER_NEWEST_SQL: &str = "\
    SELECT sensor, protocol::text AS protocol, metadata->>'local_port' AS local_port, \
           max(observed_at) AS last_event_at \
    FROM event \
    WHERE observed_at >= now() - interval '30 days' AND observed_at < now() - interval '24 hours' \
    GROUP BY 1, 2, 3";

#[sqlx::test(migrations = false)]
async fn the_fleet_pane_reads_each_listeners_newest_event_without_grouping_the_ledger(
    pool: PgPool,
) {
    migrate(&pool).await;
    unchained(&pool).await;
    // Stamped listeners, one quiet since the day before yesterday and one busy today.
    put_event(
        &pool,
        "telnet",
        "honeypot_connection",
        "tcp",
        "50 hours",
        r#"{"local_port": 23}"#,
    )
    .await;
    put_event(
        &pool,
        "telnet",
        "honeypot_connection",
        "tcp",
        "60 hours",
        r#"{"local_port": 23}"#,
    )
    .await;
    put_event(
        &pool,
        "telnet",
        "honeypot_connection",
        "tcp",
        "2 hours",
        r#"{"local_port": 23}"#,
    )
    .await;
    put_event(
        &pool,
        "telnet",
        "honeypot_connection",
        "tcp",
        "9 days",
        r#"{"local_port": 2323}"#,
    )
    .await;
    // History from before ports were stamped, on a sensor that also has stamped events (the NULL
    // key sorts after every port: a comparison with NULL would lose it), and on one that has none.
    put_event(
        &pool,
        "telnet",
        "honeypot_connection",
        "tcp",
        "20 days",
        "{}",
    )
    .await;
    put_event(
        &pool,
        "legacy",
        "honeypot_connection",
        "udp",
        "10 days",
        "{}",
    )
    .await;
    // A value that is not a port is its own key, merged with the unrecorded ones by the page.
    put_event(
        &pool,
        "ssh",
        "honeypot_connection",
        "tcp",
        "3 days",
        r#"{"local_port": "x"}"#,
    )
    .await;
    // One protocol of a sensor, then another.
    put_event(
        &pool,
        "dns",
        "honeypot_connection",
        "udp",
        "4 days",
        r#"{"local_port": 53}"#,
    )
    .await;
    put_event(
        &pool,
        "dns",
        "honeypot_connection",
        "tcp",
        "5 days",
        r#"{"local_port": 53}"#,
    )
    .await;
    // Outside the window on either side: older than 30 days, and inside the last 24 hours.
    put_event(
        &pool,
        "ancient",
        "honeypot_connection",
        "tcp",
        "40 days",
        r#"{"local_port": 1}"#,
    )
    .await;
    put_event(
        &pool,
        "today-only",
        "honeypot_connection",
        "tcp",
        "1 hour",
        r#"{"local_port": 2}"#,
    )
    .await;

    let p = plan(&pool, &console::routes::fleet::listener_newest_sql(), &[]).await;
    assert_no_scan_of(&p, "event", "the fleet pane's 30-day read");
    assert!(p.contains("event_listener_idx"), "{p}");

    type Row = (
        String,
        String,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    );
    let mut new: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT sensor, protocol, nullif(local_port, ''), last_event_at FROM ({}) q",
        console::routes::fleet::listener_newest_sql()
    )))
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut old: Vec<Row> = sqlx::query_as(OLD_LISTENER_NEWEST_SQL)
        .fetch_all(&pool)
        .await
        .unwrap();
    new.sort();
    old.sort();
    assert_eq!(
        old.len(),
        7,
        "the fixture has seven listeners in the window: {old:?}"
    );
    assert_eq!(new, old);
}

/// One ledger row from `ip`, `age` ago, with `metadata`: the sample and capture events below.
async fn put_event_from(
    pool: &PgPool,
    ip: &str,
    sensor: &str,
    signal: &str,
    age: &str,
    metadata: &str,
) {
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, metadata, hash) \
         VALUES ($1::inet, $2, $3::signal_type_enum, 'tcp', false, 'honeypot', 1, 0.5, \
                 now() - $4::interval, $5::jsonb, \
                 sha256(convert_to(gen_random_uuid()::text, 'UTF8')))",
    )
    .bind(ip)
    .bind(sensor)
    .bind(signal)
    .bind(age)
    .bind(metadata)
    .execute(pool)
    .await
    .unwrap();
}

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

/// Uploads of three samples from three addresses, plus a great deal of events that name none.
async fn seed_samples(pool: &PgPool) {
    unchained(pool).await;
    let upload = |sha: &str, extra: &str| {
        format!(r#"{{"sample_sha256": "{sha}", "complete": true {extra}}}"#)
    };
    put_event_from(
        pool,
        "198.51.100.1",
        "ftp",
        "honeypot_malware_upload",
        "5 hours",
        &upload(SHA_A, ""),
    )
    .await;
    put_event_from(
        pool,
        "198.51.100.2",
        "ftp",
        "honeypot_malware_upload",
        "3 hours",
        &upload(SHA_A, ""),
    )
    .await;
    put_event_from(
        pool,
        "198.51.100.2",
        "ssh",
        "honeypot_malware_upload",
        "2 hours",
        &upload(SHA_B, r#", "truncated": true"#),
    )
    .await;
    put_event_from(
        pool,
        "198.51.100.3",
        "ftp",
        "honeypot_malware_upload",
        "1 hour",
        &upload(SHA_C, ""),
    )
    .await;
    for i in 0..30 {
        put_event_from(
            pool,
            "198.51.100.4",
            "telnet",
            "honeypot_connection",
            &format!("{i} minutes"),
            "{}",
        )
        .await;
    }
}

/// What the Samples page's source-address read returned before it asked only about the digests on
/// the page: the pairs for every sample ever captured.
const OLD_SAMPLE_SOURCE_IPS_SQL: &str = "\
    SELECT e.metadata->>'sample_sha256' AS sha, host(e.source_ip) AS ip, \
           max(e.observed_at) AS at \
    FROM event e WHERE e.metadata->>'sample_sha256' IS NOT NULL GROUP BY 1, 2 ORDER BY at DESC";

#[sqlx::test(migrations = false)]
async fn the_samples_page_reads_its_digests_through_the_sample_index(pool: PgPool) {
    migrate(&pool).await;
    seed_samples(&pool).await;
    let page: Vec<String> = vec![SHA_A.into(), SHA_B.into()];

    let for_sources = plan_bound(
        &pool,
        console::routes::samples::SAMPLE_SOURCE_IPS_SQL,
        |q| q.bind(page.clone()),
    )
    .await;
    assert_no_scan_of(&for_sources, "event", "the Samples page's source addresses");
    assert!(
        for_sources.contains("event_sample_sha_idx"),
        "{for_sources}"
    );
    let for_truncated = plan_bound(
        &pool,
        console::routes::samples::TRUNCATED_SAMPLES_SQL,
        |q| q.bind(page.clone()),
    )
    .await;
    assert_no_scan_of(
        &for_truncated,
        "event",
        "the Samples page's truncated captures",
    );
    assert!(
        for_truncated.contains("event_sample_sha_idx"),
        "{for_truncated}"
    );

    // The listed digests get the same addresses, in the same order, as the old read over every
    // sample gave for them; a digest not on the page is not read.
    let new: Vec<(String, String)> =
        sqlx::query_as(console::routes::samples::SAMPLE_SOURCE_IPS_SQL)
            .bind(&page)
            .fetch_all(&pool)
            .await
            .unwrap();
    let old: Vec<(String, String, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(OLD_SAMPLE_SOURCE_IPS_SQL)
            .fetch_all(&pool)
            .await
            .unwrap();
    let wanted: Vec<(String, String)> = old
        .into_iter()
        .filter(|(sha, _, _)| page.contains(sha))
        .map(|(sha, ip, _)| (sha, ip))
        .collect();
    assert_eq!(
        wanted.len(),
        3,
        "A from two addresses, B from one: {wanted:?}"
    );
    assert_eq!(new, wanted);

    let truncated: Vec<String> =
        sqlx::query_scalar(console::routes::samples::TRUNCATED_SAMPLES_SQL)
            .bind(&page)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(truncated, [SHA_B]);
}

/// What an `EXPLAIN ANALYZE` says the statement touched in the ledger: the rows its scans of
/// `event` produced (rows times loops) plus every row a filter or recheck threw away. A plan that
/// reaches the few rows it wants through an index touches about those; one that reads an address's
/// whole history to find them touches the history.
fn event_rows_touched(plan: &str) -> f64 {
    let number_after = |line: &str, key: &str| -> f64 {
        let at = line.find(key).expect(key) + key.len();
        let end = line[at..]
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(line.len() - at);
        line[at..at + end].parse().unwrap()
    };
    plan.lines()
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

#[sqlx::test(migrations = false)]
async fn the_address_page_reads_its_samples_through_the_sample_index(pool: PgPool) {
    migrate(&pool).await;
    seed_samples(&pool).await;
    // One address with a long history and three uploads in it.
    unchained(&pool).await;
    sqlx::query(
        "INSERT INTO event (source_ip, sensor, signal_type, protocol, authenticated, category, \
                            weight, confidence, observed_at, hash) \
         SELECT '198.51.100.9', 'telnet', 'honeypot_connection', 'tcp', false, 'honeypot', 1, 0.5, \
                now() - g * interval '1 second', sha256(convert_to(g::text, 'UTF8')) \
         FROM generate_series(1, 20000) g",
    )
    .execute(&pool)
    .await
    .unwrap();
    for (i, sha) in [SHA_A, SHA_B, SHA_C].into_iter().enumerate() {
        put_event_from(
            &pool,
            "198.51.100.9",
            "ftp",
            "honeypot_malware_upload",
            &format!("{} hours", i + 1),
            &format!(r#"{{"sample_sha256": "{sha}"}}"#),
        )
        .await;
    }
    sqlx::query("ANALYZE event").execute(&pool).await.unwrap();

    // The planner's own choice on this ledger, not a forced one: the address is nearly the whole
    // table, so reading it through the address index is the plan to rule out.
    let mut conn = pool.acquire().await.unwrap();
    let plan: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, COSTS OFF) {}",
        console::routes::detail::MALWARE_SQL
    )))
    .bind("198.51.100.9")
    .bind(50i64)
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    let plan = plan.join("\n");
    let touched = event_rows_touched(&plan);
    assert!(
        touched < 100.0,
        "the address has 20,000 events and 3 name a sample; the panel touched {touched} ledger \
         rows:\n{plan}"
    );
}

#[sqlx::test(migrations = false)]
async fn the_fleet_capture_panel_reads_the_uploads_through_the_upload_index(pool: PgPool) {
    migrate(&pool).await;
    seed_samples(&pool).await;
    for (name, sql) in [
        ("capture rate", console::routes::fleet::capture_rows_sql()),
        ("end reasons", console::routes::fleet::top_end_reasons_sql()),
    ] {
        let p = plan(&pool, &sql, &[]).await;
        assert_no_scan_of(&p, "event", &format!("the fleet pane's {name}"));
        assert!(p.contains("event_upload_observed_idx"), "{name}:\n{p}");
    }
}

/// The address page's ATT&CK techniques are one address's tags, and the table has no retention.
#[sqlx::test(migrations = false)]
async fn the_address_page_reads_its_attack_tags_through_the_source_index(pool: PgPool) {
    migrate(&pool).await;
    let p = plan_bound(&pool, review::attack::SOURCE_TAGS_SQL, |q| {
        q.bind(vec!["198.51.100.2".to_string()])
    })
    .await;
    assert_no_scan_of(&p, "attack_tag", "the address page's technique read");
    assert!(p.contains("attack_tag_source_idx"), "{p}");
}
