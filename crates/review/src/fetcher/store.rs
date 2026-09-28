//! `fetch_attempt` data-access layer: the dedup/backoff/recursion ledger `run_cycle` drives.
//!
//! `claim_candidates` is the single entry point that turns both a `honeypot_file_download`
//! event and a prior cycle's backoff/recursion state into "what to try this cycle" - it first
//! syncs any not-yet-seen event URL into a fresh `pending` row (an idempotent insert: `ON
//! CONFLICT (url_hash) DO NOTHING`, so a URL reported by many events, or re-synced across
//! cycles, only ever gets one row), then claims rows that are either never-attempted or
//! backed off past their `next_attempt`, within the per-host and daily budgets. A `dead`
//! (terminal, 3-attempt-capped) or `success` row is never selected again - `status` alone gates
//! eligibility, so there is exactly one source of truth for "should this be tried now." The
//! claim, the budgets and the daily charge live in the database, so every node sharing it draws
//! on the same ones.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

use super::{FetchStatus, TransportAuth};

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

/// A brand-new depth-0 or recursion-child row to claim if (and only if) `url_hash` has no row
/// yet. See [`insert_pending_if_absent`] - this is the ONLY shape that may create a new row, so
/// it deliberately excludes every outcome field (`status`/`attempts`/`sha256`/... are always the
/// same fixed "just discovered" values, hardcoded in the insert itself rather than left for a
/// caller to get wrong).
#[derive(Debug, Clone)]
pub struct NewPendingRow {
    pub url_hash: Vec<u8>,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub port: Option<i32>,
    pub source_ip: Option<IpAddr>,
    pub parent_hash: Option<Vec<u8>>,
    pub depth: i32,
}

/// Everything `upsert_attempt` needs to record the outcome of a candidate `select_candidates`
/// returned THIS cycle. Never used to create a brand-new row - see [`NewPendingRow`]/
/// [`insert_pending_if_absent`] for that.
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
    /// How the captured body's transport was authenticated; `None` when no body was captured,
    /// stored as `'unknown'` like every row recorded before this was tracked.
    pub transport_auth: Option<TransportAuth>,
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

/// Parse `url`'s scheme, host, and dial port (defaulting `tftp`'s to 69 only when the url carries
/// no port at all - like `guard::vet`, the `url` crate only knows WHATWG "special scheme"
/// defaults for http/https/ws/wss/ftp, so a bare `tftp://host/x` falls through to this explicit
/// fallback). An EXPLICIT port survives untouched regardless of scheme, tftp included: `Url`'s
/// authority parser recognizes a `:PORT` suffix for any scheme with a host, not just the
/// WHATWG-special ones, so `port_or_known_default()` (`self.port.or_else(default_port(scheme))`)
/// already returns the literal parsed port before the `.or(Some(69))` fallback below is ever
/// reached - the `69` default cannot silently override a differing explicit port. See
/// `fetcher::store::tests` for a regression lock on both cases. Returns `None` for anything
/// `url::Url` cannot parse, that has no host
/// (e.g. `data:` URIs), or whose scheme `RealFetcher` cannot dispatch at all
/// (http/https/tftp are the only ones it handles) - such a URL is simply never enqueued rather
/// than stored with a nonsensical host/scheme, or stored as a row that can only ever end up
/// `Rejected("unsupported_scheme")` after burning a backoff cycle and budget for nothing. A real
/// captured case: the shell sensor logs an `ftpget ftp://...` command as a
/// `honeypot_file_download` event with the `ftp://` url verbatim - ftp is deliberately out of the
/// fetcher's scope, so this is a filter, not a reason to add ftp support.
pub fn parse_url_parts(url: &str) -> Option<(String, String, Option<i32>)> {
    let parsed = url::Url::parse(url).ok()?;
    let scheme = parsed.scheme().to_string();
    if !matches!(scheme.as_str(), "http" | "https" | "tftp") {
        return None;
    }
    let host = parsed.host_str()?.to_string();
    let port = parsed
        .port_or_known_default()
        .or(if scheme == "tftp" { Some(69) } else { None })
        .map(i32::from);
    Some((scheme, host, port))
}

/// Claim every not-yet-seen `honeypot_file_download` event URL into a pending depth-0 row via
/// `insert_pending_if_absent`. Safe to call every cycle: a URL whose row already exists (from an
/// earlier sync, or because a recursion child happened to enqueue the same URL first) is left
/// completely untouched, never reset.
///
/// The `NOT EXISTS` pre-filter compares `TRIM()` of both sides rather than the raw strings, to
/// match the exact equivalence class `url_hash` (`sha256(trim(url))`) partitions the table by -
/// without this, two whitespace-variant spellings of the same URL would both pass the filter
/// (each looking "new" against the other's untrimmed text) while colliding on the same
/// `url_hash`, so only `insert_pending_if_absent`'s own `ON CONFLICT DO NOTHING` prevents a
/// row-reset once the pre-filter under-dedups. Matching the filter to the real key makes that
/// pre-filter accurate rather than merely lucky.
async fn sync_new_events(pool: &PgPool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        // host() not ::text: Postgres renders inet as "1.2.3.4/32" even for a plain address, and
        // IpAddr::from_str rejects the prefix, so ::text + .parse().ok() silently yielded None and
        // wrote NULL for every row - the attacker attribution was lost on every fetch.
        "SELECT host(e.source_ip) AS source_ip, e.metadata->>'url' AS url \
         FROM event e \
         WHERE e.signal_type = 'honeypot_file_download' \
           AND e.metadata->>'url' IS NOT NULL \
           AND NOT EXISTS ( \
               SELECT 1 FROM fetch_attempt fa \
               WHERE TRIM(fa.url) = TRIM(e.metadata->>'url') \
           )",
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
        insert_pending_if_absent(
            pool,
            &NewPendingRow {
                url_hash: url_hash(&url),
                url,
                host,
                scheme,
                port,
                source_ip,
                parent_hash: None,
                depth: 0,
            },
        )
        .await?;
    }
    Ok(())
}

/// The limits one claim is made under.
#[derive(Debug, Clone, Copy)]
pub struct ClaimLimits {
    /// Most rows this cycle looks at.
    pub batch: i64,
    /// Fetches per host per trailing hour, across every node sharing the database.
    pub per_host_hour: i64,
    /// Fetches per UTC day, across every node sharing the database.
    pub daily_cap: i64,
    /// How long a claim holds before another cycle may take the row. Must outlast the slowest
    /// cycle that could be processing it, or a second node fetches it too.
    pub lease: std::time::Duration,
}

/// What `claim_candidates` handed this cycle.
#[derive(Debug, Default)]
pub struct Claim {
    /// Rows this cycle now owns and must fetch, newest first.
    pub candidates: Vec<Candidate>,
    /// Eligible rows left unclaimed because their host had no hourly budget left.
    pub skipped_bucket: usize,
    /// Eligible rows left unclaimed because the daily cap was reached.
    pub skipped_daily: usize,
}

/// Sync new event URLs, then claim up to `limits.batch` rows eligible to try now: never-attempted
/// (`pending`), or a retryable failure (`rejected`/`too_big`/`timeout`/`empty`) whose
/// `next_attempt` has elapsed, and not currently claimed by another cycle. `success` and `dead`
/// are excluded by construction - neither value appears in either branch of the `WHERE`.
///
/// Newest-first (`ORDER BY first_seen DESC`), per spec section 9: a payload URL a botnet is
/// actively staging typically dies within minutes, so under a backlog larger than one cycle's
/// `batch`, oldest-first would spend the whole batch on urls most likely already gone while a
/// batch's worth of still-live ones waits behind them.
///
/// Everything that decides what to fetch happens in one transaction, so several nodes sharing
/// the database behave like one fetcher:
/// - today's `fetch_daily_usage` row is locked first, which serializes every claim across every
///   node - each claim then sees the previous one's committed claims and charges;
/// - a host's hourly usage counts its completed attempts in the trailing hour plus its rows
///   currently claimed (in flight on some node), so a node cannot spend budget another node has
///   already reserved;
/// - the chosen rows get `claim_expires`, which hides them from every other claim until the
///   outcome is recorded or the lease lapses;
/// - the daily cap is charged with exactly the number of rows claimed.
///
/// A database error fails the whole claim: nothing is claimed, nothing is fetched.
pub async fn claim_candidates(pool: &PgPool, limits: ClaimLimits) -> Result<Claim, sqlx::Error> {
    sync_new_events(pool).await?;

    let mut tx = pool.begin().await?;

    sqlx::query(
        "INSERT INTO fetch_daily_usage (day, used) VALUES ((now() AT TIME ZONE 'UTC')::date, 0) \
         ON CONFLICT (day) DO NOTHING",
    )
    .execute(&mut *tx)
    .await?;
    let used_today: i32 = sqlx::query_scalar(
        "SELECT used FROM fetch_daily_usage WHERE day = (now() AT TIME ZONE 'UTC')::date \
         FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let mut daily_remaining = (limits.daily_cap - i64::from(used_today)).max(0);

    let rows = sqlx::query(
        // host(), not ::text - see sync_new_events: the "/32" prefix ::text emits fails IpAddr parsing.
        "SELECT url_hash, url, host, scheme, port, host(source_ip) AS source_ip, \
                parent_hash, depth, attempts \
         FROM fetch_attempt \
         WHERE (status = 'pending' \
                OR (status IN ('rejected', 'too_big', 'timeout', 'empty') \
                    AND next_attempt IS NOT NULL AND next_attempt <= now())) \
           AND (claim_expires IS NULL OR claim_expires <= now()) \
         ORDER BY first_seen DESC \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(limits.batch)
    .fetch_all(&mut *tx)
    .await?;
    let eligible: Vec<Candidate> = rows
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
        .collect();

    let mut hosts: Vec<String> = eligible.iter().map(|c| c.host.clone()).collect();
    hosts.sort_unstable();
    hosts.dedup();
    let used_by_host: std::collections::HashMap<String, i64> = sqlx::query_as(
        "SELECT host, COUNT(*) FROM fetch_attempt \
         WHERE host = ANY($1) \
           AND ((status <> 'pending' AND last_attempt >= now() - interval '1 hour') \
                OR claim_expires > now()) \
         GROUP BY host",
    )
    .bind(&hosts)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();
    let mut host_remaining: std::collections::HashMap<String, i64> = hosts
        .into_iter()
        .map(|h| {
            let used = used_by_host.get(&h).copied().unwrap_or(0);
            (h, (limits.per_host_hour - used).max(0))
        })
        .collect();

    let mut claim = Claim::default();
    for candidate in eligible {
        let host_left = host_remaining.entry(candidate.host.clone()).or_insert(0);
        if *host_left <= 0 {
            claim.skipped_bucket += 1;
        } else if daily_remaining <= 0 {
            claim.skipped_daily += 1;
        } else {
            *host_left -= 1;
            daily_remaining -= 1;
            claim.candidates.push(candidate);
        }
    }

    if !claim.candidates.is_empty() {
        let hashes: Vec<Vec<u8>> = claim
            .candidates
            .iter()
            .map(|c| c.url_hash.clone())
            .collect();
        sqlx::query(
            "UPDATE fetch_attempt SET claim_expires = now() + make_interval(secs => $2) \
             WHERE url_hash = ANY($1)",
        )
        .bind(&hashes)
        .bind(limits.lease.as_secs_f64())
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE fetch_daily_usage SET used = used + $1 \
             WHERE day = (now() AT TIME ZONE 'UTC')::date",
        )
        .bind(claim.candidates.len() as i32)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(claim)
}

/// Claim `row.url_hash` as a fresh pending row - the ONLY way a new row is ever created, used by
/// both `sync_new_events` (a not-yet-seen event URL) and a recursion child enqueue
/// (`record_success` in `mod.rs`). `ON CONFLICT (url_hash) DO NOTHING`: a URL that already has a
/// row - at ANY status, `pending` through `dead` - is left completely untouched. This is what
/// keeps a script cycle (A's body references B, B's body references A again) from ping-ponging
/// forever: re-discovering A as a child never resets its already-advanced status/attempts/depth
/// back to a fresh pending row, so the second time around there is nothing left to re-fetch.
///
/// Returns whether a row was actually inserted, so a caller can tell a genuine new enqueue from
/// a no-op (`record_success` uses this to keep its `enqueued_children` stat honest).
pub async fn insert_pending_if_absent(
    pool: &PgPool,
    row: &NewPendingRow,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO fetch_attempt \
         (url_hash, url, host, scheme, port, source_ip, parent_hash, depth, status, attempts, last_attempt) \
         VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, 'pending', 0, now()) \
         ON CONFLICT (url_hash) DO NOTHING",
    )
    .bind(&row.url_hash)
    .bind(&row.url)
    .bind(&row.host)
    .bind(&row.scheme)
    .bind(row.port)
    .bind(row.source_ip.map(|ip| ip.to_string()))
    .bind(&row.parent_hash)
    .bind(row.depth)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Record the outcome of a candidate `claim_candidates` handed this cycle - update-only in
/// practice, since that candidate's row already exists (this function is never used to create a
/// new row - see [`insert_pending_if_absent`] for that). The `INSERT ... ON CONFLICT DO UPDATE`
/// shape is kept anyway as defense in depth for a future caller, guarded by `WHERE status NOT IN
/// ('success', 'dead')` so even a misuse against an already-terminal `url_hash` cannot regress
/// it: a conflicting row failing that condition is left untouched (`DO NOTHING` is applied)
/// rather than updated. `last_attempt` always advances to `now()` when the update does apply, and
/// the claim is released: from here the attempt counts against its host through `last_attempt`.
pub async fn upsert_attempt(pool: &PgPool, a: &AttemptResult) -> Result<(), sqlx::Error> {
    let (transport_auth, tls_verify_error) = match &a.transport_auth {
        Some(t) => (t.as_str(), t.verify_error()),
        None => ("unknown", None),
    };
    sqlx::query(
        "INSERT INTO fetch_attempt \
         (url_hash, url, host, scheme, port, source_ip, parent_hash, depth, status, \
          reject_reason, sha256, bytes, content_type, pinned_ip, transport_auth, tls_verify_error, \
          attempts, next_attempt, last_attempt) \
         VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18, now()) \
         ON CONFLICT (url_hash) DO UPDATE SET \
           status = EXCLUDED.status, \
           reject_reason = EXCLUDED.reject_reason, \
           sha256 = EXCLUDED.sha256, \
           bytes = EXCLUDED.bytes, \
           content_type = EXCLUDED.content_type, \
           pinned_ip = EXCLUDED.pinned_ip, \
           transport_auth = EXCLUDED.transport_auth, \
           tls_verify_error = EXCLUDED.tls_verify_error, \
           attempts = EXCLUDED.attempts, \
           next_attempt = EXCLUDED.next_attempt, \
           last_attempt = now(), \
           claim_expires = NULL \
         WHERE fetch_attempt.status NOT IN ('success', 'dead')",
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
    .bind(transport_auth)
    .bind(tls_verify_error)
    .bind(a.attempts)
    .bind(a.next_attempt)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tftp_default_port_is_69_when_url_has_no_explicit_port() {
        let (_, _, port) = parse_url_parts("tftp://8.8.8.8/mal").unwrap();
        assert_eq!(port, Some(69));
    }

    // F-4 investigation: the audit-accuracy concern was that `port_or_known_default().or(Some(69))`
    // might coerce ANY tftp url to port 69 regardless of an explicit differing port, since
    // `vet()` rejects a non-69 explicit tftp port only at actual fetch time (after this row is
    // already synced). Verified false: `port_or_known_default()` already resolves to the url's
    // literal explicit port before the `.or(69)` fallback is ever reached, for tftp same as any
    // other scheme - `Url`'s port parser is not restricted to the WHATWG-special schemes. This
    // locks that in as a regression test; no behavior changed.
    #[test]
    fn tftp_explicit_port_is_recorded_as_stated_not_coerced_to_69() {
        let (_, _, port) = parse_url_parts("tftp://8.8.8.8:6900/mal").unwrap();
        assert_eq!(port, Some(6900));
    }

    #[test]
    fn http_and_https_ports_are_unaffected() {
        assert_eq!(parse_url_parts("http://x/").unwrap().2, Some(80));
        assert_eq!(parse_url_parts("https://x/").unwrap().2, Some(443));
        assert_eq!(parse_url_parts("http://x:8080/").unwrap().2, Some(8080));
    }
}
