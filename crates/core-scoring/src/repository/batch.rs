//! Batched append: many events, one transaction, one acquisition of the append lock.
//!
//! [`append_events`] produces exactly the ledger rows, chain hashes, per-IP breadth sets and
//! `ip_score` rows that calling [`append_event`](super::events::append_event) /
//! [`append_telemetry_event`](super::events::append_telemetry_event) once per event, in the same
//! order, would have produced. It differs only in cost: one lock acquisition, one chain-head read,
//! one multi-row ledger insert, and one write per touched source instead of one of each per event.
//! `tests/batch_equivalence.rs` holds that to byte identity over generated streams.
//!
//! # How equivalence is kept
//!
//! The single-event path reads its inputs back from the database after every earlier event. This
//! path reads each input once, before the first insert, and carries the effect of every earlier
//! event of the batch in memory:
//!
//! - **Chain**: event k hashes against event k-1's hash, computed in order from the one head read.
//!   The `trg_enforce_chain_linkage` trigger still checks every row against the row before it, so
//!   a wrong link fails the statement instead of forking the chain.
//! - **Dedup**: the prior observation of (source, signal) is the newest of the database's value
//!   and every earlier same-key event of the batch, deduped ones included (the single path takes
//!   `MAX(observed_at)` over all earlier rows, not only those that scored).
//! - **Breadth**: the source's vantage and sensor sets are loaded once and folded per event, so
//!   event k counts the sets as they stood right after event k.
//! - **Score**: each source's `ip_score` is loaded once and folded through
//!   [`apply_event`](crate::scoring::engine::apply_event) once per event, in order. Coalescing the
//!   folds into one would change the result (decay, dedup and tier depend on order); what is saved
//!   is the database round trip per event, not the fold. Only the final state of each source is
//!   written.
//!
//! Telemetry events join the chain at their position and touch none of the scoring state.
//!
//! # Failure semantics
//!
//! One-at-a-time ingestion stops at the first failing event and leaves every event before it
//! committed. [`append_events`] keeps that contract: [`BatchAppend::appended`] leading events are
//! durable and [`BatchAppend::failure`] is the error of the event at that index. The whole batch
//! is one transaction, so a failure rolls it back as a unit; when the error is one a single event
//! can cause (see [`is_event_specific`]) the batch is then retried in halves, so the good prefix
//! still commits and the failing event is isolated in O(log n) transactions. Any other error (a
//! lost connection, a lock timeout) is not narrowed by retrying smaller, so it is returned at
//! once with nothing committed from the failed attempt.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgPool, Row};

use crate::domain::enums::{FeedTier, Protocol, SignalType};
use crate::domain::types::{EventInput, IpScore};
use crate::hashing::chain_hash;
use crate::scoring::breadth::{WanVantage, distinct_wan_count};
use crate::scoring::constants::{DEDUP_WINDOW_SECONDS, HALF_LIFE_SECONDS};
use crate::scoring::engine::apply_event;

use super::events::{APPEND_LOCK_KEY, RepoError, normalize_in_place, score_from_row};

/// Outcome of [`append_events`]. `events[..appended]` are durably in the ledger, in order;
/// `failure`, when set, is the error of `events[appended]`, and nothing after it was written.
#[derive(Debug)]
pub struct BatchAppend {
    pub appended: usize,
    pub failure: Option<RepoError>,
}

/// Append `events` in order, scored events and telemetry alike (each routed as the single-event
/// functions would), in as few transactions as the failure semantics above allow. Takes the
/// events by value: a batch can be a megabyte per line times a thousand lines, and the caller has
/// no use for the copy this would otherwise force.
pub async fn append_events(pool: &PgPool, mut events: Vec<EventInput>) -> BatchAppend {
    // Validation is per event and free, so the first invalid event bounds the prefix to append,
    // exactly where one-at-a-time ingestion would have stopped.
    let first_invalid = events
        .iter()
        .enumerate()
        .find_map(|(i, e)| e.validate().err().map(|v| (i, v)));
    events.truncate(first_invalid.as_ref().map_or(events.len(), |(i, _)| *i));
    events.iter_mut().for_each(normalize_in_place);
    let normalized = events;

    let mut done = 0;
    let mut end = normalized.len();
    while done < normalized.len() {
        match append_atomic(pool, &normalized[done..end]).await {
            Ok(()) => {
                done = end;
                end = normalized.len();
            }
            Err(e) if end - done > 1 && e.is_event_specific() => {
                end = done + (end - done) / 2;
            }
            Err(e) => {
                return BatchAppend {
                    appended: done,
                    failure: Some(e),
                };
            }
        }
    }

    BatchAppend {
        appended: done,
        failure: first_invalid.map(|(_, v)| RepoError::Invalid(v)),
    }
}

/// Everything the fold needs to know about one source, loaded once and updated in memory.
struct SourceState {
    score: Option<IpScore>,
    /// WAN -> saw an authenticated TCP event on it, as `ip_vantage` holds it.
    vantages: BTreeMap<IpAddr, bool>,
    sensors: BTreeSet<String>,
    /// WANs inserted or flipped to true by this batch; only these are written back.
    dirty_wans: BTreeSet<IpAddr>,
    new_sensors: BTreeSet<String>,
}

/// One transaction over `events` (already validated and normalized). All or nothing.
async fn append_atomic(pool: &PgPool, events: &[EventInput]) -> Result<(), RepoError> {
    let mut tx = pool.begin().await?;
    // Same preconditions as `append_event`: READ COMMITTED so the head read after the lock sees
    // the previous appender's commit, then the global lock before anything is read.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(APPEND_LOCK_KEY)
        .execute(&mut *tx)
        .await?;

    // Chain links, in order, from the one head read.
    let head: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT hash FROM event ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let mut prev_hashes: Vec<Option<Vec<u8>>> = Vec::with_capacity(events.len());
    let mut hashes: Vec<Vec<u8>> = Vec::with_capacity(events.len());
    let mut prev = head;
    for event in events {
        let hash = chain_hash(prev.as_deref(), event).to_vec();
        prev_hashes.push(prev.take());
        prev = Some(hash.clone());
        hashes.push(hash);
    }

    // Read every input the scored events need, before this batch's rows exist.
    let scored: Vec<&EventInput> = events
        .iter()
        .filter(|e| !e.signal_type.is_telemetry())
        .collect();
    let mut sources = load_sources(&mut tx, &scored).await?;
    let mut newest = load_dedup_priors(&mut tx, &scored).await?;

    // Fold in order.
    for event in &scored {
        let key = (event.source_ip, event.signal_type);
        let prior = newest.get(&key).copied().flatten();
        // Symmetric window, as in `append_event`: either time direction counts as a duplicate.
        let deduped = match prior {
            Some(prior) => (event.observed_at - prior).num_seconds().abs() <= DEDUP_WINDOW_SECONDS,
            None => false,
        };
        newest.insert(
            key,
            Some(prior.map_or(event.observed_at, |p| p.max(event.observed_at))),
        );

        let state = sources
            .get_mut(&event.source_ip)
            .expect("every scored source was loaded");
        if let Some(wan) = event.wan_ip {
            let auth_tcp = event.protocol == Protocol::Tcp && event.authenticated;
            match state.vantages.get_mut(&wan) {
                None => {
                    state.vantages.insert(wan, auth_tcp);
                    state.dirty_wans.insert(wan);
                }
                Some(flag) if auth_tcp && !*flag => {
                    *flag = true;
                    state.dirty_wans.insert(wan);
                }
                Some(_) => {}
            }
        }
        if state.sensors.insert(event.sensor.clone()) {
            state.new_sensors.insert(event.sensor.clone());
        }
        let vantages: Vec<WanVantage> = state
            .vantages
            .iter()
            .map(|(&wan_ip, &saw_authenticated_tcp)| WanVantage {
                wan_ip,
                saw_authenticated_tcp,
            })
            .collect();
        state.score = Some(apply_event(
            state.score.take(),
            event,
            HALF_LIFE_SECONDS,
            deduped,
            distinct_wan_count(&vantages) as i32,
            state.sensors.len() as i32,
        ));
    }

    insert_events(&mut tx, events, &prev_hashes, &hashes).await?;
    write_sources(&mut tx, &sources).await?;
    tx.commit().await?;
    Ok(())
}

fn ip_texts<'a>(ips: impl Iterator<Item = &'a IpAddr>) -> Vec<String> {
    ips.map(ToString::to_string).collect()
}

fn parse_ip(text: &str, what: &str) -> Result<IpAddr, RepoError> {
    text.parse()
        .map_err(|e| RepoError::Corrupt(format!("stored {what} {text}: {e}")))
}

/// Load score, vantages and sensors for every distinct source among `scored`.
async fn load_sources(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scored: &[&EventInput],
) -> Result<HashMap<IpAddr, SourceState>, RepoError> {
    let distinct: BTreeSet<IpAddr> = scored.iter().map(|e| e.source_ip).collect();
    let mut sources: HashMap<IpAddr, SourceState> = distinct
        .iter()
        .map(|&ip| {
            (
                ip,
                SourceState {
                    score: None,
                    vantages: BTreeMap::new(),
                    sensors: BTreeSet::new(),
                    dirty_wans: BTreeSet::new(),
                    new_sensors: BTreeSet::new(),
                },
            )
        })
        .collect();
    if distinct.is_empty() {
        return Ok(sources);
    }
    let ips = ip_texts(distinct.iter());

    let rows = sqlx::query(concat!(
        "SELECT ",
        super::events::stored_score_columns!(),
        " FROM ip_score WHERE source_ip = ANY($1::text[]::inet[])"
    ))
    .bind(&ips)
    .fetch_all(&mut **tx)
    .await?;
    for row in &rows {
        let score = score_from_row(row)?;
        if let Some(state) = sources.get_mut(&score.source_ip) {
            state.score = Some(score);
        }
    }

    let rows = sqlx::query(
        "SELECT host(source_ip) AS source_ip, host(wan_ip) AS wan, saw_authenticated_tcp \
         FROM ip_vantage WHERE source_ip = ANY($1::text[]::inet[])",
    )
    .bind(&ips)
    .fetch_all(&mut **tx)
    .await?;
    for row in &rows {
        let source = parse_ip(&row.try_get::<String, _>("source_ip")?, "source_ip")?;
        let wan = parse_ip(&row.try_get::<String, _>("wan")?, "wan_ip")?;
        if let Some(state) = sources.get_mut(&source) {
            state
                .vantages
                .insert(wan, row.try_get("saw_authenticated_tcp")?);
        }
    }

    let rows = sqlx::query(
        "SELECT host(source_ip) AS source_ip, sensor \
         FROM ip_sensor WHERE source_ip = ANY($1::text[]::inet[])",
    )
    .bind(&ips)
    .fetch_all(&mut **tx)
    .await?;
    for row in &rows {
        let source = parse_ip(&row.try_get::<String, _>("source_ip")?, "source_ip")?;
        if let Some(state) = sources.get_mut(&source) {
            state.sensors.insert(row.try_get("sensor")?);
        }
    }
    Ok(sources)
}

/// The dedup read of `append_event` for every distinct (source, signal) of the batch: the newest
/// observation already in the ledger. One correlated `MAX` per key keeps each lookup a single
/// backward step on `event_dedup_idx` whatever the source's history or the intake lag, the
/// property `dedup_read_plan_*` guards for the single path; `batch_dedup_read_plan_*` holds this
/// statement to it too.
pub(super) const DEDUP_PRIORS_SQL: &str = "SELECT host(k.ip) AS source_ip, k.st AS signal_type, \
            (SELECT MAX(e.observed_at) FROM event e WHERE e.source_ip = k.ip AND e.signal_type = k.st) AS prior \
     FROM unnest($1::text[]::inet[], $2::signal_type_enum[]) AS k(ip, st)";

async fn load_dedup_priors(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    scored: &[&EventInput],
) -> Result<HashMap<(IpAddr, SignalType), Option<DateTime<Utc>>>, RepoError> {
    let mut distinct: Vec<(IpAddr, SignalType)> = Vec::new();
    let mut seen: HashSet<(IpAddr, SignalType)> = HashSet::new();
    for e in scored {
        if seen.insert((e.source_ip, e.signal_type)) {
            distinct.push((e.source_ip, e.signal_type));
        }
    }
    let mut out = HashMap::with_capacity(distinct.len());
    if distinct.is_empty() {
        return Ok(out);
    }
    let ips: Vec<String> = distinct.iter().map(|(ip, _)| ip.to_string()).collect();
    let signals: Vec<SignalType> = distinct.iter().map(|&(_, s)| s).collect();
    let rows = sqlx::query(DEDUP_PRIORS_SQL)
        .bind(&ips)
        .bind(&signals)
        .fetch_all(&mut **tx)
        .await?;
    for row in &rows {
        let ip = parse_ip(&row.try_get::<String, _>("source_ip")?, "source_ip")?;
        let signal: SignalType = row.try_get("signal_type")?;
        out.insert((ip, signal), row.try_get("prior")?);
    }
    Ok(out)
}

/// One multi-row INSERT in chain order. The `ORDER BY` fixes the row order, and with it both the
/// ids and the trigger's view of "the previous row"; if the order were ever wrong the trigger
/// would reject the statement rather than commit a fork.
async fn insert_events(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    events: &[EventInput],
    prev_hashes: &[Option<Vec<u8>>],
    hashes: &[Vec<u8>],
) -> Result<(), RepoError> {
    sqlx::query(
        "INSERT INTO event \
         (source_ip, wan_ip, sensor, signal_type, protocol, authenticated, category, \
          weight, confidence, observed_at, metadata, prev_hash, hash, session_id) \
         SELECT t.source_ip::inet, t.wan_ip::inet, t.sensor, t.signal_type, t.protocol, \
                t.authenticated, t.category, t.weight, t.confidence, t.observed_at, t.metadata, \
                t.prev_hash, t.hash, t.session_id \
         FROM unnest($1::text[], $2::text[], $3::text[], $4::signal_type_enum[], \
                     $5::protocol_enum[], $6::bool[], $7::category_enum[], $8::int4[], \
                     $9::numeric[], $10::timestamptz[], $11::jsonb[], $12::bytea[], \
                     $13::bytea[], $14::uuid[]) \
              WITH ORDINALITY AS t(source_ip, wan_ip, sensor, signal_type, protocol, \
                                   authenticated, category, weight, confidence, observed_at, \
                                   metadata, prev_hash, hash, session_id, ord) \
         ORDER BY t.ord",
    )
    .bind(
        events
            .iter()
            .map(|e| e.source_ip.to_string())
            .collect::<Vec<_>>(),
    )
    .bind(
        events
            .iter()
            .map(|e| e.wan_ip.map(|ip| ip.to_string()))
            .collect::<Vec<_>>(),
    )
    .bind(events.iter().map(|e| e.sensor.as_str()).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.signal_type).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.protocol).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.authenticated).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.category).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.weight as i32).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.confidence).collect::<Vec<_>>())
    .bind(events.iter().map(|e| e.observed_at).collect::<Vec<_>>())
    .bind(events.iter().map(|e| &e.metadata).collect::<Vec<_>>())
    .bind(prev_hashes)
    .bind(hashes)
    .bind(events.iter().map(|e| e.session_id).collect::<Vec<_>>())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Write each touched source's final state: its changed vantages, new sensors and `ip_score`.
async fn write_sources(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sources: &HashMap<IpAddr, SourceState>,
) -> Result<(), RepoError> {
    // Sorted so concurrent writers (the console's delete, a rebuild) see one lock order.
    let ordered: BTreeMap<IpAddr, &SourceState> = sources.iter().map(|(&ip, s)| (ip, s)).collect();

    let (mut v_src, mut v_wan, mut v_flag) = (Vec::new(), Vec::new(), Vec::new());
    let (mut s_src, mut s_sensor) = (Vec::new(), Vec::new());
    for (&ip, state) in &ordered {
        for wan in &state.dirty_wans {
            v_src.push(ip.to_string());
            v_wan.push(wan.to_string());
            v_flag.push(state.vantages[wan]);
        }
        for sensor in &state.new_sensors {
            s_src.push(ip.to_string());
            s_sensor.push(sensor.clone());
        }
    }
    if !v_src.is_empty() {
        // The conflict clause is `fold_breadth_sets`' verbatim: write only when the flag turns
        // from false to true.
        sqlx::query(
            "INSERT INTO ip_vantage (source_ip, wan_ip, saw_authenticated_tcp) \
             SELECT s::inet, w::inet, f FROM unnest($1::text[], $2::text[], $3::bool[]) AS t(s, w, f) \
             ON CONFLICT (source_ip, wan_ip) DO UPDATE \
             SET saw_authenticated_tcp = ip_vantage.saw_authenticated_tcp OR EXCLUDED.saw_authenticated_tcp \
             WHERE EXCLUDED.saw_authenticated_tcp AND NOT ip_vantage.saw_authenticated_tcp",
        )
        .bind(&v_src)
        .bind(&v_wan)
        .bind(&v_flag)
        .execute(&mut **tx)
        .await?;
    }
    if !s_src.is_empty() {
        sqlx::query(
            "INSERT INTO ip_sensor (source_ip, sensor) \
             SELECT s::inet, n FROM unnest($1::text[], $2::text[]) AS t(s, n) \
             ON CONFLICT (source_ip, sensor) DO NOTHING",
        )
        .bind(&s_src)
        .bind(&s_sensor)
        .execute(&mut **tx)
        .await?;
    }

    let scores: Vec<&IpScore> = ordered.values().filter_map(|s| s.score.as_ref()).collect();
    if scores.is_empty() {
        return Ok(());
    }
    macro_rules! column {
        ($f:ident) => {
            scores.iter().map(|s| s.$f.clone()).collect::<Vec<_>>()
        };
    }
    // Same column list and conflict clause as `append_event`'s upsert; `delisted` is deliberately
    // absent from the update list there and here, so an operator's delisting survives.
    sqlx::query(
        "INSERT INTO ip_score \
         (source_ip, raw_score, decay_anchor, max_confidence, event_count, distinct_categories, \
          category_breakdown, has_confirmed_real, distinct_wan_count, distinct_sensor_count, \
          first_seen, last_seen, eligible, recommended_for_vendor, recommended_for_blocklist, \
          tier, delisted, active_days, last_active_day, established_event_count) \
         SELECT source_ip::inet, raw_score, decay_anchor, max_confidence, event_count, \
                distinct_categories, category_breakdown, has_confirmed_real, distinct_wan_count, \
                distinct_sensor_count, first_seen, last_seen, eligible, recommended_for_vendor, \
                recommended_for_blocklist, tier, delisted, active_days, last_active_day, \
                established_event_count \
         FROM unnest($1::text[], $2::numeric[], $3::timestamptz[], $4::numeric[], $5::int4[], \
                     $6::int4[], $7::jsonb[], $8::bool[], $9::int4[], $10::int4[], \
                     $11::timestamptz[], $12::timestamptz[], $13::bool[], $14::bool[], $15::bool[], \
                     $16::feed_tier_enum[], $17::bool[], $18::int4[], $19::date[], $20::int4[]) \
              AS t(source_ip, raw_score, decay_anchor, max_confidence, event_count, \
                   distinct_categories, category_breakdown, has_confirmed_real, distinct_wan_count, \
                   distinct_sensor_count, first_seen, last_seen, eligible, recommended_for_vendor, \
                   recommended_for_blocklist, tier, delisted, active_days, last_active_day, \
                   established_event_count) \
         ON CONFLICT (source_ip) DO UPDATE SET \
           raw_score = EXCLUDED.raw_score, \
           decay_anchor = EXCLUDED.decay_anchor, \
           max_confidence = EXCLUDED.max_confidence, \
           event_count = EXCLUDED.event_count, \
           distinct_categories = EXCLUDED.distinct_categories, \
           category_breakdown = EXCLUDED.category_breakdown, \
           has_confirmed_real = EXCLUDED.has_confirmed_real, \
           distinct_wan_count = EXCLUDED.distinct_wan_count, \
           distinct_sensor_count = EXCLUDED.distinct_sensor_count, \
           first_seen = EXCLUDED.first_seen, \
           last_seen = EXCLUDED.last_seen, \
           eligible = EXCLUDED.eligible, \
           recommended_for_vendor = EXCLUDED.recommended_for_vendor, \
           recommended_for_blocklist = EXCLUDED.recommended_for_blocklist, \
           tier = EXCLUDED.tier, \
           active_days = EXCLUDED.active_days, \
           last_active_day = EXCLUDED.last_active_day, \
           established_event_count = EXCLUDED.established_event_count",
    )
    .bind(scores.iter().map(|s| s.source_ip.to_string()).collect::<Vec<_>>())
    .bind(column!(raw_score))
    .bind(column!(decay_anchor))
    .bind(column!(max_confidence))
    .bind(column!(event_count))
    .bind(column!(distinct_categories))
    .bind(column!(category_breakdown))
    .bind(column!(has_confirmed_real))
    .bind(column!(distinct_wan_count))
    .bind(column!(distinct_sensor_count))
    .bind(column!(first_seen))
    .bind(column!(last_seen))
    .bind(column!(eligible))
    .bind(column!(recommended_for_vendor))
    .bind(column!(recommended_for_blocklist))
    .bind(scores.iter().map(|s| s.tier).collect::<Vec<Option<FeedTier>>>())
    .bind(column!(delisted))
    .bind(column!(active_days))
    .bind(scores.iter().map(|s| s.last_active_day).collect::<Vec<NaiveDate>>())
    .bind(column!(established_event_count))
    .execute(&mut **tx)
    .await?;
    Ok(())
}
