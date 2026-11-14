//! Real-Postgres tests for the transactional append path and read projection.
//!
//! Run with `DATABASE_URL` exported (see `.env`):
//!   set -a; . ./.env; set +a; cargo test -p core-scoring --test repository
//! `#[sqlx::test]` provisions a fresh, isolated database per test and applies
//! the migrations, so the tests never share state.

use core_scoring::domain::enums::{Protocol, SignalType};
use core_scoring::domain::types::EventInput;
use core_scoring::repository::{
    RepoError, append_event, read_score, read_stored_score, rebuild_projection,
};

use rust_decimal_macros::dec;
use sqlx::PgPool;

/// A tcp + authenticated + honeypot event: latches `has_confirmed_real`.
fn auth_honeypot_input(ip: &str, ts: &str) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        "sensor-a".into(),
        SignalType::HoneypotCommandExec,
        Protocol::Tcp,
        true,
        ts.parse().unwrap(),
        serde_json::json!({}),
        None,
    )
}

/// A honeypot event whose weight is selected by `weight` (via the signal table,
/// so weight/confidence/category stay in sync). Only the weights used by the
/// tests are mapped.
fn honeypot_input(ip: &str, ts: &str, weight: u32) -> EventInput {
    let signal = match weight {
        40 => SignalType::HoneypotConnection,
        50 => SignalType::HoneypotLoginAttempt,
        60 => SignalType::HoneypotCommandExec,
        70 => SignalType::HoneypotFileDownload,
        80 => SignalType::HoneypotMalwareUpload,
        other => panic!("no honeypot signal with weight {other}"),
    };
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        "sensor-a".into(),
        signal,
        Protocol::Tcp,
        true,
        ts.parse().unwrap(),
        serde_json::json!({}),
        None,
    )
}

#[sqlx::test(migrations = "./migrations")]
async fn append_updates_projection_atomically(pool: PgPool) -> Result<(), RepoError> {
    let s = append_event(
        &pool,
        auth_honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z"),
    )
    .await?;
    assert_eq!(s.event_count, 1);
    assert!(s.has_confirmed_real);
    Ok(())
}

#[sqlx::test(migrations = "./migrations")]
async fn malformed_event_is_rejected_without_writing(pool: PgPool) {
    let mut bad = auth_honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z");
    bad.confidence = dec!(9); // out of range
    assert!(matches!(
        append_event(&pool, bad).await,
        Err(RepoError::Invalid(_))
    ));
    // Nothing written on the error path: validation happens before the tx opens.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn double_decay_guard_across_one_half_life(pool: PgPool) -> Result<(), RepoError> {
    // event A at t0; READ at t0+6h (projects raw to ~half); event B at t0+6h.
    // The write path for B must read the UN-projected stored raw, not the
    // read-projected one.
    let _a = append_event(
        &pool,
        honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z", 40),
    )
    .await?;
    // A pure read in between must NOT persist the projected value.
    let _ = read_score(&pool, "203.0.113.7".parse().unwrap()).await?;
    let b = append_event(
        &pool,
        honeypot_input("203.0.113.7", "2026-07-17T06:00:00Z", 40),
    )
    .await?;
    // stored raw at B = decay(40, 6h) + 40 = 20 + 40 = 60 (NOT decay(decay(40)) + 40).
    assert!((b.raw_score - dec!(60)).abs() < dec!(0.01));
    Ok(())
}

/// The dedup window, read through the indexed lookup: a same-source same-signal sighting within 60s
/// of the newest prior one (either direction, boundary included) adds no weight, and one at 61s
/// does. The newest prior is the MAX of every earlier row, not the previous append, so an
/// out-of-order sighting is measured against it. Another signal or another source is never a
/// duplicate. Every sighting still counts, and replay, which recomputes dedup in memory, agrees.
#[sqlx::test(migrations = "./migrations")]
async fn dedup_window_holds_in_order_out_of_order_and_at_the_boundary(
    pool: PgPool,
) -> Result<(), RepoError> {
    const IP: &str = "203.0.113.50";
    // (timestamp, weight selecting the signal, whether this sighting must add its weight)
    let steps: [(&str, u32, bool); 8] = [
        ("2026-07-17T00:00:00Z", 60, true),  // first sighting
        ("2026-07-17T00:00:30Z", 60, false), // 30s after the newest: duplicate
        ("2026-07-17T00:01:31Z", 60, true),  // 61s after the newest (00:00:30): counted
        ("2026-07-17T00:00:50Z", 60, false), // out of order, 41s before the newest: duplicate
        ("2026-07-17T00:00:20Z", 60, true),  // out of order, 71s before the newest: counted
        ("2026-07-17T00:02:31Z", 60, false), // exactly 60s after the newest: duplicate
        ("2026-07-17T00:03:32Z", 60, true),  // 61s after the newest: counted
        ("2026-07-17T00:03:40Z", 50, true),  // inside the window, but another signal
    ];
    // The raw score is clamped at 100, so the uncapped category weight is what shows whether a
    // sighting added anything.
    fn category_weight(s: &core_scoring::IpScore) -> rust_decimal::Decimal {
        s.category_breakdown
            .as_object()
            .expect("category_breakdown is a map")
            .values()
            .map(|stat| -> rust_decimal::Decimal {
                match &stat["weight"] {
                    serde_json::Value::String(w) => w.parse().expect("decimal weight"),
                    other => other.to_string().parse().expect("decimal weight"),
                }
            })
            .sum()
    }
    let mut previous = dec!(0);
    for (n, (ts, weight, adds)) in steps.into_iter().enumerate() {
        let s = append_event(&pool, honeypot_input(IP, ts, weight)).await?;
        assert_eq!(s.event_count, n as i32 + 1, "every sighting counts ({ts})");
        let now = category_weight(&s);
        let gained = now - previous;
        if adds {
            assert!(
                gained > dec!(49),
                "{ts} must add its weight, category weight went {previous} -> {now}"
            );
        } else {
            assert!(
                gained.abs() < dec!(1),
                "{ts} is a duplicate and must add nothing, category weight went {previous} -> {now}"
            );
        }
        previous = now;
    }

    // Same signal, inside the window, another source: not a duplicate of anything.
    let other = append_event(
        &pool,
        honeypot_input("203.0.113.51", "2026-07-17T00:03:33Z", 60),
    )
    .await?;
    assert_eq!(category_weight(&other), dec!(60));

    let ip = IP.parse().unwrap();
    let stored = read_stored_score(&pool, ip)
        .await?
        .expect("stored projection");
    let replayed = rebuild_projection(&pool, ip)
        .await?
        .expect("replayed projection");
    assert_eq!(replayed, stored, "replay must agree with the indexed dedup");
    Ok(())
}

/// The hash chain is unbroken after several appends across multiple sources:
/// row 1 has no predecessor, and every later row's `prev_hash` equals the
/// immediately prior row's `hash`, in `id` order. This verifies chain
/// linkage deterministically (single-threaded, sequential appends); it does
/// not attempt to exercise concurrent appends, which is inherently flaky -
/// the advisory lock that prevents forking under concurrency is instead
/// argued from the module-level doc comment and code inspection.
#[sqlx::test(migrations = "./migrations")]
async fn ledger_chain_is_linear_after_multiple_appends(pool: PgPool) -> Result<(), RepoError> {
    append_event(
        &pool,
        honeypot_input("203.0.113.7", "2026-07-17T00:00:00Z", 40),
    )
    .await?;
    append_event(
        &pool,
        auth_honeypot_input("198.51.100.9", "2026-07-17T00:01:00Z"),
    )
    .await?;
    append_event(
        &pool,
        honeypot_input("203.0.113.7", "2026-07-17T00:02:00Z", 50),
    )
    .await?;
    append_event(
        &pool,
        honeypot_input("198.51.100.9", "2026-07-17T00:03:00Z", 60),
    )
    .await?;
    append_event(
        &pool,
        honeypot_input("203.0.113.7", "2026-07-17T00:04:00Z", 70),
    )
    .await?;

    let rows: Vec<(Option<Vec<u8>>, Vec<u8>)> =
        sqlx::query_as("SELECT prev_hash, hash FROM event ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();

    assert_eq!(rows.len(), 5);
    assert!(rows[0].0.is_none(), "first row must have no predecessor");
    for i in 1..rows.len() {
        let (prev_hash_i, _) = &rows[i];
        let (_, hash_prior) = &rows[i - 1];
        assert_eq!(
            prev_hash_i.as_deref(),
            Some(hash_prior.as_slice()),
            "row {i}'s prev_hash must equal row {}'s hash",
            i - 1
        );
    }
    Ok(())
}

/// What one forged packet at the DNS or TFTP listener produces: a `honeypot_connection` over UDP.
fn datagram_input(ip: &str, ts: &str) -> EventInput {
    EventInput::from_signal(
        ip.parse().unwrap(),
        None,
        "dns".into(),
        SignalType::HoneypotConnection,
        Protocol::Udp,
        false,
        ts.parse().unwrap(),
        serde_json::json!({}),
        None,
    )
}

/// A datagram naming a listed address is stored and counted, and the stored row is otherwise
/// what it was: no decay, no re-derived tier, no moved clock. Replay agrees.
#[sqlx::test(migrations = "./migrations")]
async fn a_datagram_changes_only_the_record_of_the_sighting(pool: PgPool) -> Result<(), RepoError> {
    const IP: &str = "203.0.113.60";
    let ip = IP.parse().unwrap();
    append_event(&pool, honeypot_input(IP, "2026-09-01T00:00:00Z", 80)).await?;
    let listed = append_event(&pool, honeypot_input(IP, "2026-09-01T00:01:00Z", 60)).await?;
    assert!(listed.tier.is_some() && listed.eligible);
    let earned = listed
        .aggressive_earned_at
        .expect("earned at the second event");
    let before = read_stored_score(&pool, ip).await?.expect("stored");

    // Twelve hours later, when the score has decayed to a quarter.
    let returned = append_event(&pool, datagram_input(IP, "2026-09-01T12:01:00Z")).await?;
    let after = read_stored_score(&pool, ip).await?.expect("stored");
    assert_eq!(returned, after);
    let expected = core_scoring::IpScore {
        event_count: before.event_count + 1,
        last_seen: "2026-09-01T12:01:00Z".parse().unwrap(),
        distinct_sensor_count: 2,
        ..before.clone()
    };
    assert_eq!(after, expected);
    assert_eq!(after.aggressive_earned_at, Some(earned));
    assert_eq!(after.established_last_seen, before.established_last_seen);

    let stored_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM event WHERE source_ip = $1::inet")
            .bind(IP)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        stored_rows, 3,
        "the datagram is in the ledger like any other event"
    );

    let replayed = rebuild_projection(&pool, ip).await?.expect("replayed");
    assert_eq!(replayed, after);
    Ok(())
}

/// A datagram is never the prior a connection is deduplicated against, on any path: otherwise
/// one forged (or deliberate) packet a minute would make every real connection of the same
/// signal type a no-weight duplicate.
#[sqlx::test(migrations = "./migrations")]
async fn a_datagram_never_makes_a_connection_a_duplicate(pool: PgPool) -> Result<(), RepoError> {
    const IP: &str = "203.0.113.61";
    let ip = IP.parse().unwrap();
    // Datagrams on both sides of the connection, each well inside the 60 s window.
    append_event(&pool, datagram_input(IP, "2026-09-01T00:00:00Z")).await?;
    let s = append_event(&pool, honeypot_input(IP, "2026-09-01T00:00:20Z", 40)).await?;
    assert_eq!(s.raw_score, dec!(40), "the connection adds its full weight");
    append_event(&pool, datagram_input(IP, "2026-09-01T00:02:00Z")).await?;
    // 2 min 20 s after the last CONNECTION and 20 s after the last datagram: not a duplicate.
    let s = append_event(&pool, honeypot_input(IP, "2026-09-01T00:02:20Z", 40)).await?;
    assert!(
        s.raw_score > dec!(79),
        "a datagram 20 s earlier must not dedupe it: {}",
        s.raw_score
    );
    // A connection 30 s after that one is a duplicate, as it always was.
    let s = append_event(&pool, honeypot_input(IP, "2026-09-01T00:02:50Z", 40)).await?;
    assert!(
        s.raw_score < dec!(80),
        "connections still dedupe: {}",
        s.raw_score
    );
    assert_eq!((s.event_count, s.established_event_count), (5, 3));

    let stored = read_stored_score(&pool, ip).await?.expect("stored");
    let replayed = rebuild_projection(&pool, ip).await?.expect("replayed");
    assert_eq!(replayed, stored, "replay computes the same dedup");

    // The batched path, on a second address with the same history. Split so that each
    // connection's nearest datagram is once already in the ledger (the stored-prior read) and
    // once earlier in the same batch (the in-memory prior).
    const BATCHED: &str = "203.0.113.62";
    let batches = [
        vec![datagram_input(BATCHED, "2026-09-01T00:00:00Z")],
        vec![
            honeypot_input(BATCHED, "2026-09-01T00:00:20Z", 40),
            datagram_input(BATCHED, "2026-09-01T00:02:00Z"),
            honeypot_input(BATCHED, "2026-09-01T00:02:20Z", 40),
        ],
        vec![honeypot_input(BATCHED, "2026-09-01T00:02:50Z", 40)],
    ];
    for batch in batches {
        let sent = batch.len();
        let outcome = core_scoring::repository::append_events(&pool, batch).await;
        assert_eq!(outcome.appended, sent);
    }
    let batched = read_stored_score(&pool, BATCHED.parse().unwrap())
        .await?
        .expect("stored");
    let same_but_for_the_address = core_scoring::IpScore {
        source_ip: stored.source_ip,
        ..batched
    };
    assert_eq!(same_but_for_the_address, stored);
    Ok(())
}
