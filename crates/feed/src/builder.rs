//! The feed builder: reads approved, eligible, recommended-for-blocklist IP scores from
//! `ip_score`, re-derives their gate flags decayed to now, groups by tier, applies exclusions,
//! and coarsens every timestamp to an hour boundary. See
//! `internal/design/05-blocklist-feed.md` ("The feed builder").

use std::net::IpAddr;

use chrono::{DateTime, Duration, Timelike, Utc};
use sqlx::{PgPool, Row};

use core_scoring::{FeedTier, RepoError, read_score};

use crate::exclusion::ExclusionEngine;

/// Errors from building a `FeedSnapshot`. Every variant fails the whole build - there is no
/// partial/best-effort snapshot on error (the design's "Error handling": "A database error during
/// the build query fails the entire build. No partial feed is published.").
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// A database/driver error querying or re-reading candidate scores.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// `core_scoring::read_score` could not project a candidate's stored state (e.g. corrupt
    /// `category_breakdown`). This fails the whole build rather than silently skipping the row -
    /// a corrupt row is a data-integrity signal, not a benign absence.
    #[error("score read error: {0}")]
    Score(#[from] RepoError),
}

/// One entry in a `FeedSnapshot`. No raw score, no confidence: only what an operator needs to act
/// on the entry (which tier's TTL applies, when it was first/last seen at hour granularity, and
/// how much corroborating evidence backs it).
#[derive(Debug, Clone, PartialEq)]
pub struct FeedEntry {
    pub source_ip: IpAddr,
    pub tier: FeedTier,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: i32,
    pub distinct_categories: i32,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// An immutable, timestamped build of the two-tier blocklist. `aggressive` and `standard` are
/// each sorted by `source_ip` ascending; the tier grouping itself expresses the design's "sorted
/// by tier then by IP" - there is no single combined, cross-tier list to sort.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedSnapshot {
    pub build_time: DateTime<Utc>,
    pub aggressive: Vec<FeedEntry>,
    pub standard: Vec<FeedEntry>,
}

/// Builder-scoped configuration: how long each tier's entries stay valid from the coarsened build
/// time. The full environment-loaded configuration (`database_url`, `output_dir`,
/// `build_interval`, `allowlist`, `delist`) belongs to the publisher/binary added later in this
/// sub-project; `allowlist`/`delist` are already owned by `ExclusionEngine`, which `build` takes
/// as its own argument, so this type stays scoped to what the build step itself consumes.
#[derive(Debug, Clone)]
pub struct FeedConfig {
    pub aggressive_ttl: Duration,
    pub standard_ttl: Duration,
}

impl Default for FeedConfig {
    /// The spec's ratified defaults: Aggressive 24h, Standard 48h from coarsened build time.
    fn default() -> Self {
        Self {
            aggressive_ttl: Duration::hours(24),
            standard_ttl: Duration::hours(48),
        }
    }
}

/// Stateless namespace for the build step (mirrors the design's `FeedBuilder::build`).
pub struct FeedBuilder;

impl FeedBuilder {
    /// Build a `FeedSnapshot` from the current `ip_score` projection.
    ///
    /// 1. Pre-filters candidates on the STORED `recommended_for_blocklist`/`eligible` flags
    ///    (cheap, index-friendly). Decay only ever shrinks a score, so a row this filter excludes
    ///    can never newly qualify after decay - the filter is a sound superset, never a false
    ///    negative.
    /// 2. Re-derives every candidate on the current wall clock via `core_scoring::read_score`,
    ///    and re-checks `eligible`/`recommended_for_blocklist` on THAT fresh value - the stale
    ///    stored flags are never trusted past step 1.
    /// 3. Drops any candidate whose fresh `tier` is `None`: `recommended_for_blocklist` is gated
    ///    on the breadth-boosted effective score while `tier` is gated on the raw score alone, so
    ///    a candidate can satisfy the first without the second (see `core-scoring`'s
    ///    `breadth_raises_blocklist_never_vendor_tier` end-to-end test). The design calls this
    ///    "should not happen if the scoring logic is consistent", but fail-closed means excluding
    ///    it rather than assuming a tier.
    /// 4. Applies `exclusions.is_excluded` (reserved ranges, operator allowlist, delist).
    /// 5. Coarsens every timestamp to the hour and computes `valid_until` from the tier's TTL.
    ///
    /// Any database error aborts the whole build (`FeedError`); there is no partial snapshot.
    pub async fn build(
        pool: &PgPool,
        exclusions: &ExclusionEngine,
        config: &FeedConfig,
    ) -> Result<FeedSnapshot, FeedError> {
        let build_time = coarsen_to_hour(Utc::now());

        let rows = sqlx::query(
            "SELECT host(source_ip) AS source_ip FROM ip_score \
             WHERE recommended_for_blocklist = true AND eligible = true",
        )
        .fetch_all(pool)
        .await?;

        let mut aggressive = Vec::new();
        let mut standard = Vec::new();

        for row in rows {
            let ip_text: String = row.try_get("source_ip")?;
            let ip: IpAddr = match ip_text.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    // Fail closed: an unparseable stored IP is excluded, never guessed at.
                    tracing::warn!(
                        ip_text = %ip_text,
                        "feed builder: unparseable stored source_ip, excluding"
                    );
                    continue;
                }
            };

            // Re-derive on the current wall clock; never trust the stale stored flags past this
            // point (see the doc comment above).
            let Some(score) = read_score(pool, ip).await? else {
                // No delete path exists on `ip_score` (upsert-only), so this is unreachable in
                // practice; handled defensively rather than assumed.
                tracing::warn!(%ip, "feed builder: ip_score row vanished between query and read");
                continue;
            };

            if !score.eligible || !score.recommended_for_blocklist {
                continue; // decayed below the gate since the row was last written
            }

            let Some(tier) = score.tier else {
                tracing::warn!(
                    %ip,
                    "feed builder: recommended_for_blocklist but tier=None, excluding fail-closed"
                );
                continue;
            };

            if exclusions.is_excluded(ip) {
                continue;
            }

            let valid_from = build_time;
            let valid_until = valid_from
                + match tier {
                    FeedTier::Aggressive => config.aggressive_ttl,
                    FeedTier::Standard => config.standard_ttl,
                };

            let entry = FeedEntry {
                source_ip: ip,
                tier,
                first_seen: coarsen_to_hour(score.first_seen),
                last_seen: coarsen_to_hour(score.last_seen),
                event_count: score.event_count,
                distinct_categories: score.distinct_categories,
                valid_from,
                valid_until,
            };

            match tier {
                FeedTier::Aggressive => aggressive.push(entry),
                FeedTier::Standard => standard.push(entry),
            }
        }

        aggressive.sort_by_key(|e| e.source_ip);
        standard.sort_by_key(|e| e.source_ip);

        tracing::info!(
            aggressive = aggressive.len(),
            standard = standard.len(),
            "feed builder: build complete"
        );

        Ok(FeedSnapshot {
            build_time,
            aggressive,
            standard,
        })
    }
}

/// Truncate `dt` to its hour boundary (minutes, seconds, and nanoseconds zeroed).
///
/// Anti-deanonymization (the design's "Timestamp coarsening"): every timestamp the feed exports
/// goes through this so subtracting a publicly known tier TTL from one field can never recover a
/// more precise value of another.
pub fn coarsen_to_hour(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.date_naive()
        .and_hms_opt(dt.hour(), 0, 0)
        .expect("hour() is always < 24, so and_hms_opt(h, 0, 0) cannot fail")
        .and_utc()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarsen_to_hour_truncates_minutes_seconds_and_nanos() {
        let dt: DateTime<Utc> = "2026-07-29T14:37:52.123456789Z".parse().unwrap();
        assert_eq!(
            coarsen_to_hour(dt),
            "2026-07-29T14:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn coarsen_to_hour_is_idempotent_on_an_already_coarsened_value() {
        let dt: DateTime<Utc> = "2026-07-29T14:00:00Z".parse().unwrap();
        assert_eq!(coarsen_to_hour(dt), dt);
    }

    #[test]
    fn coarsen_to_hour_handles_the_last_hour_of_a_day() {
        let dt: DateTime<Utc> = "2026-07-29T23:59:59.999999999Z".parse().unwrap();
        assert_eq!(
            coarsen_to_hour(dt),
            "2026-07-29T23:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[test]
    fn feed_config_default_matches_the_spec_ttls() {
        let cfg = FeedConfig::default();
        assert_eq!(cfg.aggressive_ttl, Duration::hours(24));
        assert_eq!(cfg.standard_ttl, Duration::hours(48));
    }
}
