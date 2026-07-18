//! Replay rebuild + tamper-evident hash-chain verification over the ledger.
//!
//! Two independent read-only checks against the same append-only `event`
//! ledger that [`super::events::append_event`] writes:
//!
//! - [`rebuild_projection`] replays a single source's events from an empty
//!   projection and MUST reproduce, field for field, the projection the
//!   incremental write path arrived at. It does this by recomputing IN MEMORY,
//!   for each event in insertion (`id`) order, exactly the dedup / breadth /
//!   sensor inputs that `append_event` computed via SQL at the moment it
//!   appended that event, then folding through the same pure
//!   [`apply_event`](crate::scoring::engine::apply_event). Determinism is
//!   guaranteed BY CONSTRUCTION: same event order + same per-event inputs +
//!   same pure fold => same output. If the two ever diverge, the
//!   `replay_equals_incremental` test fails.
//!
//! - [`verify_chain`] recomputes every row's SHA-256 chain hash from its
//!   reconstructed [`EventInput`] and checks both the hash and the
//!   `prev_hash` linkage, returning the `id` of the first row that fails. It
//!   reconstructs each event from the STORED columns (including the stored
//!   `weight` / `confidence` / `category`), because those exact stored values
//!   are what were fed into the hash at append time - recomputing them from
//!   the signal-weight table would defeat tamper detection on those columns.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::domain::enums::{Category, Protocol, SignalType};
use crate::domain::types::{EventInput, IpScore};
use crate::hashing::chain_hash;
use crate::scoring::breadth::{WanVantage, distinct_wan_count};
use crate::scoring::constants::{DEDUP_WINDOW_SECONDS, HALF_LIFE_SECONDS};
use crate::scoring::engine::apply_event;

use super::events::RepoError;

/// Result of a full-ledger hash-chain verification.
///
/// `Intact` means every row's recomputed hash matched its stored hash AND
/// every row's `prev_hash` matched the immediately prior row's `hash` (with the
/// first row having `prev_hash IS NULL`). `Broken { first_bad_id }` names the
/// `id` of the FIRST row (in `id` order) that fails either check.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainStatus {
    Intact,
    Broken { first_bad_id: i64 },
}

/// Reconstruct an `EventInput` from a ledger row.
///
/// The two callers below select the same canonical column set with these exact
/// aliases. IPs use `host()` so they decode as plain strings we parse to
/// `IpAddr`, independent of any INET type mapping (matching the append/read
/// path).
///
/// Reads the STORED `weight` / `confidence` / `category` verbatim (does NOT
/// re-derive them from the signal-weight table): those stored values are what
/// were hashed and what the projection fold consumed, so faithful replay and
/// tamper detection both require reading them as-stored.
fn reconstruct_event(row: &PgRow) -> Result<EventInput, RepoError> {
    let source_ip_txt: String = row.try_get("source_ip")?;
    let source_ip: IpAddr = source_ip_txt
        .parse()
        .map_err(|e| RepoError::Corrupt(format!("stored source_ip {source_ip_txt}: {e}")))?;

    let wan_ip: Option<IpAddr> = match row.try_get::<Option<String>, _>("wan_ip")? {
        Some(txt) => Some(
            txt.parse()
                .map_err(|e| RepoError::Corrupt(format!("stored wan_ip {txt}: {e}")))?,
        ),
        None => None,
    };

    let weight: i32 = row.try_get("weight")?;

    Ok(EventInput {
        source_ip,
        wan_ip,
        sensor: row.try_get("sensor")?,
        signal_type: row.try_get::<SignalType, _>("signal_type")?,
        protocol: row.try_get::<Protocol, _>("protocol")?,
        authenticated: row.try_get("authenticated")?,
        category: row.try_get::<Category, _>("category")?,
        weight: weight as u32,
        confidence: row.try_get::<Decimal, _>("confidence")?,
        observed_at: row.try_get::<DateTime<Utc>, _>("observed_at")?,
        metadata: row.try_get("metadata")?,
    })
}

/// Rebuild a source's projection by replaying its ledger from empty.
///
/// Fetches this source's events in insertion (`id`) order - the SAME order
/// `append_event` applied them - and folds them through `apply_event` from
/// `None`, recomputing per-event dedup, breadth, and sensor inputs in memory to
/// mirror exactly what `append_event` computed via SQL when it appended each
/// event. Returns the final projection, anchored (like the stored row) at the
/// last event's `observed_at`.
///
/// Fails closed with [`RepoError::Corrupt`] if the source has no events (there
/// is no projection to rebuild) or a stored value cannot be parsed.
pub async fn rebuild_projection(pool: &PgPool, ip: IpAddr) -> Result<IpScore, RepoError> {
    let rows = sqlx::query(
        "SELECT host(source_ip) AS source_ip, host(wan_ip) AS wan_ip, sensor, signal_type, \
                protocol, authenticated, category, weight, confidence, observed_at, metadata \
         FROM event WHERE source_ip = $1::inet ORDER BY id",
    )
    .bind(ip.to_string())
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Err(RepoError::Corrupt(format!(
            "no events to replay for source {ip}"
        )));
    }

    let events: Vec<EventInput> = rows
        .iter()
        .map(reconstruct_event)
        .collect::<Result<_, _>>()?;

    let mut acc: Option<IpScore> = None;
    for k in 0..events.len() {
        let event = &events[k];

        // deduped_k: among already-processed events (0..k) with the SAME
        // signal_type, the most recent observed_at; deduped iff within window.
        // Mirrors `MAX(observed_at) WHERE signal_type = $ AND id < new_id`.
        let prior_observed = events[..k]
            .iter()
            .filter(|e| e.signal_type == event.signal_type)
            .map(|e| e.observed_at)
            .max();
        let deduped = match prior_observed {
            Some(prior) => (event.observed_at - prior).num_seconds() <= DEDUP_WINDOW_SECONDS,
            None => false,
        };

        // Breadth over events 0..=k: one vantage per distinct non-null wan_ip,
        // authenticated-TCP iff ANY event so far on that wan was tcp+auth.
        // Mirrors the `GROUP BY wan_ip, bool_or(protocol='tcp' AND authenticated)`
        // query (which sees exactly rows 0..=k at that transaction time).
        let mut vantages: Vec<WanVantage> = Vec::new();
        for e in &events[..=k] {
            let Some(wan_ip) = e.wan_ip else { continue };
            let auth_tcp = e.protocol == Protocol::Tcp && e.authenticated;
            match vantages.iter_mut().find(|v| v.wan_ip == wan_ip) {
                Some(v) => v.saw_authenticated_tcp |= auth_tcp,
                None => vantages.push(WanVantage {
                    wan_ip,
                    saw_authenticated_tcp: auth_tcp,
                }),
            }
        }
        let dwc = distinct_wan_count(&vantages) as i32;

        // Distinct sensors among 0..=k. Mirrors `COUNT(DISTINCT sensor)`.
        let mut sensors: Vec<&str> = events[..=k].iter().map(|e| e.sensor.as_str()).collect();
        sensors.sort_unstable();
        sensors.dedup();
        let dsc = sensors.len() as i32;

        acc = Some(apply_event(
            acc.take(),
            event,
            HALF_LIFE_SECONDS,
            deduped,
            dwc,
            dsc,
        ));
    }

    // Non-empty by the guard above, so the fold always produced a value.
    Ok(acc.expect("non-empty ledger yields a projection"))
}

/// Verify the whole-ledger hash chain, tamper-evidently.
///
/// Fetches ALL events in `id` order and, for each row, recomputes
/// `chain_hash(prev_row_hash, reconstructed_event)` and compares it to the
/// stored `hash`, and checks `row.prev_hash == prev_row.hash` (the first row
/// must have `prev_hash IS NULL`). Returns `Broken { first_bad_id }` at the
/// FIRST row failing either check, else `Intact`.
pub async fn verify_chain(pool: &PgPool) -> Result<ChainStatus, RepoError> {
    let rows = sqlx::query(
        "SELECT id, prev_hash, hash, host(source_ip) AS source_ip, host(wan_ip) AS wan_ip, \
                sensor, signal_type, protocol, authenticated, category, weight, confidence, \
                observed_at, metadata \
         FROM event ORDER BY id",
    )
    .fetch_all(pool)
    .await?;

    let mut prev_hash_of_prior_row: Option<Vec<u8>> = None;
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let stored_prev: Option<Vec<u8>> = row.try_get("prev_hash")?;
        let stored_hash: Vec<u8> = row.try_get("hash")?;

        // Linkage: this row's prev_hash must equal the prior row's stored hash
        // (None for the first row). This is what makes the chain a chain.
        if stored_prev != prev_hash_of_prior_row {
            return Ok(ChainStatus::Broken { first_bad_id: id });
        }

        // Content: recompute this row's hash from its reconstructed event bound
        // to the prior row's hash, and compare to the stored hash.
        let event = reconstruct_event(row)?;
        let recomputed = chain_hash(prev_hash_of_prior_row.as_deref(), &event);
        if recomputed.as_slice() != stored_hash.as_slice() {
            return Ok(ChainStatus::Broken { first_bad_id: id });
        }

        prev_hash_of_prior_row = Some(stored_hash);
    }

    Ok(ChainStatus::Intact)
}
