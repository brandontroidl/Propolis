//! `fetch_attempt` data-access layer: the dedup/backoff/recursion ledger `run_cycle` drives.
//!
//! `select_candidates` is the single entry point that turns both a `honeypot_file_download`
//! event and a prior cycle's backoff/recursion state into "what to try this cycle" - it first
//! syncs any not-yet-seen event URL into a fresh `pending` row (an idempotent claim: `ON
//! CONFLICT (url_hash) DO NOTHING`, so a URL reported by many events, or re-synced across
//! cycles, only ever gets one row), then selects rows that are either never-attempted or
//! backed off past their `next_attempt`. A `dead` (terminal, 3-attempt-capped) or `success` row
//! is never selected again - `status` alone gates eligibility, so there is exactly one source of
//! truth for "should this be tried now."

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

use super::FetchStatus;

/// One row eligible for a fetch attempt this cycle: a freshly-synced depth-0 URL from a
/// `honeypot_file_download` event, a backoff-eligible retry, or a depth>=1 synthetic row a
/// prior cycle's recursion enqueued.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub url_hash: Vec<u8>,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub port: Option<i32>,
    pub source_ip: Option<IpAddr>,
    pub parent_hash: Option<Vec<u8>>,
    pub depth: i32,
    pub attempts: i32,
}

/// Everything `upsert_attempt` needs to insert a brand-new row (a recursion child) or update an
/// already-selected candidate's row after a fetch attempt - one shape serves both, since an
/// `ON CONFLICT (url_hash) DO UPDATE` naturally covers "insert if absent, else record the new
/// outcome."
#[derive(Debug, Clone)]
pub struct AttemptResult {
    pub url_hash: Vec<u8>,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub port: Option<i32>,
    pub source_ip: Option<IpAddr>,
    pub parent_hash: Option<Vec<u8>>,
    pub depth: i32,
    pub status: FetchStatus,
    pub reject_reason: Option<String>,
    pub sha256: Option<Vec<u8>>,
    pub bytes: Option<i32>,
    pub content_type: Option<String>,
    pub pinned_ip: Option<String>,
    pub attempts: i32,
    pub next_attempt: Option<DateTime<Utc>>,
}

/// sha256 of the URL text (trimmed of surrounding ASCII whitespace) - the natural key the
/// migration comment calls "sha256(normalized url)". No further normalization (case-folding,
/// query-param sorting, etc.) is applied: two URL strings that a browser would treat as
/// equivalent but differ byte-for-byte get separate rows, which only ever costs a duplicate
/// fetch attempt, never a missed one.
pub fn url_hash(url: &str) -> Vec<u8> {
    Sha256::digest(url.trim().as_bytes()).to_vec()
}

/// Parse `url`'s scheme, host, and dial port (defaulting `tftp`'s to 69, since - like
/// `guard::vet` - the `url` crate only knows WHATWG "special scheme" defaults for
/// http/https/ws/wss/ftp). Returns `None` for anything `url::Url` cannot parse or that has no
/// host (e.g. `data:` URIs) - such a URL is simply never enqueued rather than stored with a
/// nonsensical host/scheme.
pub fn parse_url_parts(url: &str) -> Option<(String, String, Option<i32>)> {
    let parsed = url::Url::parse(url).ok()?;
    let scheme = parsed.scheme().to_string();
    let host = parsed.host_str()?.to_string();
    let port = parsed
        .port_or_known_default()
        .or(if scheme == "tftp" { Some(69) } else { None })
        .map(i32::from);
    Some((scheme, host, port))
}

/// Claim every not-yet-seen `honeypot_file_download` event URL into a pending depth-0 row via
/// `upsert_attempt`. Safe to call every cycle: the `NOT EXISTS` filter below means this only
/// ever runs against a URL with no row yet, so `upsert_attempt`'s `ON CONFLICT` branch is
/// unreachable here - idempotent by construction, not by relying on the conflict branch to no-op.
async fn sync_new_events(pool: &PgPool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT e.source_ip::text AS source_ip, e.metadata->>'url' AS url \
         FROM event e \
         WHERE e.signal_type = 'honeypot_file_download' \
           AND e.metadata->>'url' IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM fetch_attempt fa WHERE fa.url = e.metadata->>'url')",
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let url: String = row.get("url");
        let source_ip: Option<IpAddr> = row
            .get::<Option<String>, _>("source_ip")
            .and_then(|s| s.parse().ok());
        let Some((scheme, host, port)) = parse_url_parts(&url) else {
            continue;
        };
        upsert_attempt(
            pool,
            &AttemptResult {
                url_hash: url_hash(&url),
                url,
                host,
                scheme,
                port,
                source_ip,
                parent_hash: None,
                depth: 0,
                status: FetchStatus::Pending,
                reject_reason: None,
                sha256: None,
                bytes: None,
                content_type: None,
                pinned_ip: None,
                attempts: 0,
                next_attempt: None,
            },
        )
        .await?;
    }
    Ok(())
}

/// Sync new event URLs, then select up to `batch` rows eligible to try now: never-attempted
/// (`pending`), or a retryable failure (`rejected`/`too_big`/`timeout`/`empty`) whose
/// `next_attempt` has elapsed. `success` and `dead` are excluded by construction - neither
/// value appears in either branch of the `WHERE`.
pub async fn select_candidates(pool: &PgPool, batch: i64) -> Result<Vec<Candidate>, sqlx::Error> {
    sync_new_events(pool).await?;

    let rows = sqlx::query(
        "SELECT url_hash, url, host, scheme, port, source_ip::text AS source_ip, \
                parent_hash, depth, attempts \
         FROM fetch_attempt \
         WHERE status = 'pending' \
            OR (status IN ('rejected', 'too_big', 'timeout', 'empty') \
                AND next_attempt IS NOT NULL AND next_attempt <= now()) \
         ORDER BY first_seen \
         LIMIT $1",
    )
    .bind(batch)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| Candidate {
            url_hash: r.get("url_hash"),
            url: r.get("url"),
            host: r.get("host"),
            scheme: r.get("scheme"),
            port: r.get("port"),
            source_ip: r
                .get::<Option<String>, _>("source_ip")
                .and_then(|s| s.parse().ok()),
            parent_hash: r.get("parent_hash"),
            depth: r.get("depth"),
            attempts: r.get("attempts"),
        })
        .collect())
}

/// Insert-or-update a `fetch_attempt` row by `url_hash`: a recursion child that does not exist
/// yet is inserted; a candidate already selected this cycle is updated in place with its fetch
/// outcome. `last_attempt` always advances to `now()` regardless of which branch fires.
pub async fn upsert_attempt(pool: &PgPool, a: &AttemptResult) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO fetch_attempt \
         (url_hash, url, host, scheme, port, source_ip, parent_hash, depth, status, \
          reject_reason, sha256, bytes, content_type, pinned_ip, attempts, next_attempt, last_attempt) \
         VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16, now()) \
         ON CONFLICT (url_hash) DO UPDATE SET \
           status = EXCLUDED.status, \
           reject_reason = EXCLUDED.reject_reason, \
           sha256 = EXCLUDED.sha256, \
           bytes = EXCLUDED.bytes, \
           content_type = EXCLUDED.content_type, \
           pinned_ip = EXCLUDED.pinned_ip, \
           attempts = EXCLUDED.attempts, \
           next_attempt = EXCLUDED.next_attempt, \
           last_attempt = now()",
    )
    .bind(&a.url_hash)
    .bind(&a.url)
    .bind(&a.host)
    .bind(&a.scheme)
    .bind(a.port)
    .bind(a.source_ip.map(|ip| ip.to_string()))
    .bind(&a.parent_hash)
    .bind(a.depth)
    .bind(a.status.as_str())
    .bind(&a.reject_reason)
    .bind(&a.sha256)
    .bind(a.bytes)
    .bind(&a.content_type)
    .bind(&a.pinned_ip)
    .bind(a.attempts)
    .bind(a.next_attempt)
    .execute(pool)
    .await?;
    Ok(())
}

/// Count how many attempts (any completed outcome - never `pending`, which means "not fetched
/// yet") this host has had in the trailing hour. `run_cycle` seeds its per-cycle host budget
/// from this once per distinct host, rather than re-querying per URL (see the module doc in
/// `mod.rs` for why: an exact cap under bounded concurrency needs a single read per host, not
/// N racing reads of a not-yet-committed count).
pub async fn host_count_last_hour(pool: &PgPool, host: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM fetch_attempt \
         WHERE host = $1 AND status != 'pending' AND last_attempt >= now() - interval '1 hour'",
    )
    .bind(host)
    .fetch_one(pool)
    .await
}
