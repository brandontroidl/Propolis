//! The feed builder: reads approved, eligible, recommended-for-blocklist IP scores from
//! `ip_score`, gated on operator approval in `review_queue`, re-derives their gate flags
//! decayed to now, groups by tier, applies exclusions, and coarsens every timestamp to an
//! hour boundary. See `internal/design/05-blocklist-feed.md` ("The feed builder").

use std::net::IpAddr;

use chrono::{DateTime, Duration, Timelike, Utc};
use sqlx::{PgPool, Row};

use core_scoring::{FeedTier, RepoError};

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
    /// `None` for a volume-listed flood published only in the retention windows; `Some` for a
    /// score-tiered entry. Not serialized into the published files (each file's tier is its own
    /// name/label); used to route entries between the tier files and to re-validate.
    pub tier: Option<FeedTier>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: i32,
    pub distinct_categories: i32,
    /// The distinct signal types this address triggered, as the wire vocabulary
    /// (`ssh_brute_force`, `honeypot_malware_upload`, ...), sorted and deduplicated.
    ///
    /// `distinct_categories` above is a bare count over five coarse sensor classes, which tells a
    /// consumer how much corroboration an entry has but nothing about what the address actually
    /// did. This is the "what did it do" half, and it is what makes an entry actionable: an
    /// operator can drop the port-scan noise and keep the addresses that got as far as uploading
    /// malware.
    pub categories: Vec<String>,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
}

/// One retention feed, published as `all-{label}.*`.
///
/// `retention` travels with the entries rather than being looked up separately at publish time:
/// the exported file header states the window it covers, and deriving that from an entry (or from
/// a config lookup keyed by label) lets a file advertise a window its contents were not selected
/// for - and an empty window has no entry to derive it from at all.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowFeed {
    pub label: String,
    pub retention: Duration,
    pub entries: Vec<FeedEntry>,
}

/// An immutable, timestamped build of the two-tier blocklist. `aggressive` and `standard` are
/// each sorted by `source_ip` ascending; the tier grouping itself expresses the design's "sorted
/// by tier then by IP" - there is no single combined, cross-tier list to sort.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedSnapshot {
    pub build_time: DateTime<Utc>,
    pub aggressive: Vec<FeedEntry>,
    pub standard: Vec<FeedEntry>,
    /// One entry per configured retention window, published as `all-{label}.*`. Empty when no
    /// windows are configured.
    pub windows: Vec<WindowFeed>,
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
    /// Additional retention feeds, published as `all-{label}.*` alongside the two tiered feeds.
    /// Each holds every approved entry whose `last_seen` falls inside the window, regardless of
    /// tier, so the windows nest (30d contains everything in 7d). Empty disables them.
    pub windows: Vec<(String, Duration)>,
}

impl Default for FeedConfig {
    /// The spec's ratified defaults: Aggressive 24h, Standard 48h. Retention windows default to
    /// empty so an unconfigured deployment publishes exactly the two files it always has.
    fn default() -> Self {
        Self {
            aggressive_ttl: Duration::hours(24),
            standard_ttl: Duration::hours(48),
            windows: Vec::new(),
        }
    }
}

/// One approved IP as stored, before it is materialised into per-feed [`FeedEntry`] values.
///
/// Every field is read AS STORED - the values as of the IP's last event - never re-derived
/// against the current wall clock. That is the whole point: a re-derived tier slides across the
/// 90/75 thresholds as the score decays, so the same IP is filed as aggressive on one render and
/// standard on the next, and no two views taken minutes apart agree. Freezing the tier at
/// observation time means an IP enters one file and stays there for its window.
struct Candidate {
    ip: IpAddr,
    /// `None` for a volume-listed flood (no score-tier). Such a candidate is excluded from the
    /// aggressive/standard tier files (which filter on `Some(tier)`) and appears only in the
    /// retention windows.
    tier: Option<FeedTier>,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    event_count: i32,
    distinct_categories: i32,
    categories: Vec<String>,
}

/// Stateless namespace for the build step (mirrors the design's `FeedBuilder::build`).
pub struct FeedBuilder;

impl FeedBuilder {
    /// Build a `FeedSnapshot` from the current `ip_score` projection.
    ///
    /// Membership is decided by RETENTION, not by a live-decayed score:
    ///
    /// 1. Selects approved candidates on the STORED `recommended_for_blocklist`/`eligible` flags,
    ///    reading `tier`, `first_seen`, `last_seen` and the evidence counts AS STORED - i.e. as of
    ///    each IP's last event.
    /// 2. Applies `exclusions.is_excluded` (reserved ranges, operator allowlist, delist).
    /// 3. Keeps an entry while `last_seen` falls inside the relevant window: the tier's TTL for
    ///    `aggressive`/`standard`, or the window's own duration for each configured retention
    ///    feed. `valid_from`/`valid_until` are anchored on `last_seen`, so the published validity
    ///    window is the truth about when the entry expires.
    ///
    /// This deliberately does NOT re-derive scores against the current wall clock. Doing so made
    /// tier membership a function of when a page happened to render: an IP sliding from 90.0 to
    /// 89.0 silently moved from the aggressive file to the standard one, entries vanished roughly
    /// 2.5h after their last event while the file advertised 24-48h validity, and no two views
    /// taken minutes apart ever agreed on the counts. Decay still governs scoring, the review
    /// queue and the vendor gates - it just no longer decides what is published.
    ///
    /// Any database error aborts the whole build (`FeedError`); there is no partial snapshot.
    pub async fn build(
        pool: &PgPool,
        exclusions: &ExclusionEngine,
        config: &FeedConfig,
    ) -> Result<FeedSnapshot, FeedError> {
        let build_time = coarsen_to_hour(Utc::now());

        // The `categories` subquery is correlated but cheap: the outer set is already narrowed to
        // approved, eligible, tiered candidates, and `event_source_ip_idx` covers the lookup. It
        // reads `signal_type::text` rather than mapping through the Rust enum because the database
        // enum's labels ARE the wire vocabulary (`0001_enums.sql`), so there is no second casing
        // to keep in sync - and `SignalType`'s Serialize is frozen to bare Rust identifiers for
        // chain hashing, which is the wrong vocabulary to publish.
        let rows = sqlx::query(
            "SELECT host(s.source_ip) AS source_ip, s.tier, s.first_seen, s.last_seen, \
                    s.event_count, s.distinct_categories, \
                    ARRAY(SELECT DISTINCT e.signal_type::text FROM event e \
                          WHERE e.source_ip = s.source_ip ORDER BY 1) AS categories \
             FROM ip_score s \
             INNER JOIN review_queue q ON q.source_ip = s.source_ip \
             WHERE s.recommended_for_blocklist = true AND s.eligible = true \
               AND q.state = 'approved' AND s.tier IS NOT NULL",
        )
        .fetch_all(pool)
        .await?;

        let mut candidates = Vec::with_capacity(rows.len());

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

            if exclusions.is_excluded(ip) {
                continue;
            }

            // `tier IS NOT NULL` in the query above already excluded the untiered rows, so this
            // only fails on a value the enum cannot represent - fail closed rather than guess.
            let Some(tier): Option<FeedTier> = row.try_get("tier")? else {
                tracing::warn!(%ip, "feed builder: stored tier unreadable, excluding fail-closed");
                continue;
            };

            candidates.push(Candidate {
                ip,
                tier: Some(tier),
                first_seen: row.try_get("first_seen")?,
                last_seen: row.try_get("last_seen")?,
                event_count: row.try_get("event_count")?,
                distinct_categories: row.try_get("distinct_categories")?,
                categories: row.try_get("categories")?,
            });
        }

        // Volume-listed floods: recommended for the blocklist on connection volume alone (no
        // confirmed-real latch, so eligible = false, so tier = NULL and no operator approval). They
        // are auto-published into the RETENTION windows only - never the score-tiered files - so a
        // hyperactive flooder the dedup would otherwise erase still gets blocked. `eligible = false`
        // AND `recommended_for_blocklist = true` uniquely identifies them (see core-scoring's
        // derive_projection). Exclusions still apply, the same as for merit candidates.
        let volume_rows = sqlx::query(
            "SELECT host(s.source_ip) AS source_ip, s.first_seen, s.last_seen, \
                    s.event_count, s.distinct_categories, \
                    ARRAY(SELECT DISTINCT e.signal_type::text FROM event e \
                          WHERE e.source_ip = s.source_ip ORDER BY 1) AS categories \
             FROM ip_score s \
             WHERE s.recommended_for_blocklist = true AND s.eligible = false",
        )
        .fetch_all(pool)
        .await?;

        for row in volume_rows {
            let ip_text: String = row.try_get("source_ip")?;
            let ip: IpAddr = match ip_text.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    tracing::warn!(
                        ip_text = %ip_text,
                        "feed builder: unparseable stored source_ip (volume), excluding"
                    );
                    continue;
                }
            };
            if exclusions.is_excluded(ip) {
                continue;
            }
            candidates.push(Candidate {
                ip,
                tier: None,
                first_seen: row.try_get("first_seen")?,
                last_seen: row.try_get("last_seen")?,
                event_count: row.try_get("event_count")?,
                distinct_categories: row.try_get("distinct_categories")?,
                categories: row.try_get("categories")?,
            });
        }

        let now = Utc::now();
        let aggressive = materialize(&candidates, now, config.aggressive_ttl, |c| {
            c.tier == Some(FeedTier::Aggressive)
        });
        let standard = materialize(&candidates, now, config.standard_ttl, |c| {
            c.tier == Some(FeedTier::Standard)
        });
        let windows: Vec<WindowFeed> = config
            .windows
            .iter()
            .map(|(label, retention)| WindowFeed {
                label: label.clone(),
                retention: *retention,
                entries: materialize(&candidates, now, *retention, |_| true),
            })
            .collect();

        tracing::info!(
            aggressive = aggressive.len(),
            standard = standard.len(),
            windows = windows.len(),
            "feed builder: build complete"
        );

        Ok(FeedSnapshot {
            build_time,
            aggressive,
            standard,
            windows,
        })
    }
}

/// Select the candidates that `include` accepts and whose last event falls inside `ttl`, and
/// materialise them as [`FeedEntry`] values whose validity window is anchored on that last event.
///
/// Anchoring on `last_seen` rather than on build time is what makes the published `valid_until`
/// mean what it says: an entry is carried for a fixed period after the activity that justified it,
/// and leaves when that period lapses. Anchoring on build time instead would restart every
/// entry's clock on each build, so nothing would ever expire.
fn materialize(
    candidates: &[Candidate],
    now: DateTime<Utc>,
    ttl: Duration,
    include: impl Fn(&Candidate) -> bool,
) -> Vec<FeedEntry> {
    let mut out: Vec<FeedEntry> = candidates
        .iter()
        .filter(|c| include(c) && now - c.last_seen < ttl)
        .map(|c| {
            let valid_from = coarsen_to_hour(c.last_seen);
            FeedEntry {
                source_ip: c.ip,
                tier: c.tier,
                first_seen: coarsen_to_hour(c.first_seen),
                last_seen: valid_from,
                event_count: c.event_count,
                distinct_categories: c.distinct_categories,
                categories: c.categories.clone(),
                valid_from,
                valid_until: valid_from + ttl,
            }
        })
        .collect();
    out.sort_by_key(|e| e.source_ip);
    out
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

    /// A candidate last seen `hours_ago`, with a deliberately non-default value in every field so
    /// a carry-forward that drops one is visible rather than passing on a matching default.
    fn candidate(last_octet: u8, tier: FeedTier, hours_ago: i64, now: DateTime<Utc>) -> Candidate {
        Candidate {
            ip: format!("198.51.100.{last_octet}").parse().unwrap(),
            tier: Some(tier),
            first_seen: now - Duration::hours(hours_ago + 500),
            last_seen: now - Duration::hours(hours_ago),
            event_count: 37,
            distinct_categories: 3,
            categories: vec!["ssh_brute_force".into(), "honeypot_command_exec".into()],
        }
    }

    fn now_fixed() -> DateTime<Utc> {
        "2026-08-19T12:30:00Z".parse().unwrap()
    }

    #[test]
    fn an_entry_leaves_the_feed_once_its_ttl_lapses_since_last_activity() {
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 2, now),
            candidate(2, FeedTier::Aggressive, 23, now),
            candidate(3, FeedTier::Aggressive, 25, now),
        ];

        let out = materialize(&cands, now, Duration::hours(24), |_| true);

        let kept: Vec<String> = out.iter().map(|e| e.source_ip.to_string()).collect();
        assert_eq!(kept, ["198.51.100.1", "198.51.100.2"]);
    }

    #[test]
    fn validity_is_anchored_on_last_activity_not_on_build_time() {
        // The defect this guards: anchoring on build time restarts every entry's clock on each
        // build, so an address seen once and never again is republished with a fresh 24h validity
        // forever. Anchoring on last_seen means the published valid_until is the truth.
        let now = now_fixed();
        let cands = [candidate(1, FeedTier::Aggressive, 20, now)];

        let out = materialize(&cands, now, Duration::hours(24), |_| true);

        let entry = &out[0];
        assert_eq!(entry.valid_from, coarsen_to_hour(now - Duration::hours(20)));
        assert_eq!(entry.valid_until, entry.valid_from + Duration::hours(24));
        // Four hours of validity left, not a fresh twenty-four.
        assert_eq!(
            entry.valid_until - now,
            Duration::hours(3) + Duration::minutes(30)
        );
    }

    #[test]
    fn tier_is_taken_as_stored_so_membership_cannot_slide_between_builds() {
        // Both candidates carry identical evidence; only the stored tier differs. If the builder
        // re-derived tier from a decaying score, these would not stay in separate files.
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 1, now),
            candidate(2, FeedTier::Standard, 1, now),
        ];

        let aggressive = materialize(&cands, now, Duration::hours(24), |c| {
            c.tier == Some(FeedTier::Aggressive)
        });
        let standard = materialize(&cands, now, Duration::hours(48), |c| {
            c.tier == Some(FeedTier::Standard)
        });

        assert_eq!(aggressive.len(), 1);
        assert_eq!(aggressive[0].source_ip.to_string(), "198.51.100.1");
        assert_eq!(standard.len(), 1);
        assert_eq!(standard[0].source_ip.to_string(), "198.51.100.2");
    }

    // Executable documentation-truth check for README.md "## Scoring", bullet "Score decay and
    // retention": "Feed membership ... is decided by retention windows (24h aggressive, 48h
    // standard), not by the live score - a quiet attacker is retained for its window rather than
    // dropping out the moment its score falls. This is a retention feed, not a decay-out feed."
    // `materialize` takes NO score argument at all: an entry is kept iff its last activity is within
    // the retention window. So a quiet-but-recent attacker (whose live score would have decayed) is
    // retained, and an entry leaves only when the window lapses - never because a score fell. If
    // membership ever starts consulting a live/decayed score, this test's score-free premise breaks
    // and the README claim must be revisited.
    #[test]
    fn readme_feed_membership_is_retention_based_not_score_based() {
        let now = now_fixed();
        // Quiet-but-recent: last seen 23h ago (no recent activity, a live score would have decayed
        // over ~4 half-lives), still inside the 24h aggressive window.
        let quiet_but_recent = candidate(1, FeedTier::Aggressive, 23, now);
        // Same evidence, last seen 25h ago: outside the window.
        let aged_out = candidate(2, FeedTier::Aggressive, 25, now);

        let out = materialize(
            &[quiet_but_recent, aged_out],
            now,
            Duration::hours(24),
            |_| true,
        );
        let kept: Vec<String> = out.iter().map(|e| e.source_ip.to_string()).collect();

        // Retained purely because it is within the retention window - no score consulted. The 25h
        // one leaves only because the window lapsed, not because any score fell below a floor.
        assert_eq!(kept, ["198.51.100.1"]);
    }

    #[test]
    fn retention_windows_nest_and_ignore_tier() {
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 2, now),
            candidate(2, FeedTier::Standard, 100, now),
            candidate(3, FeedTier::Standard, 1_000, now),
        ];

        let day = materialize(&cands, now, Duration::days(1), |_| true);
        let week = materialize(&cands, now, Duration::days(7), |_| true);
        let month = materialize(&cands, now, Duration::days(90), |_| true);

        assert_eq!(day.len(), 1);
        assert_eq!(week.len(), 2);
        assert_eq!(month.len(), 3);
        // A consumer picks one file and gets a superset of every shorter one.
        for shorter in [&day, &week] {
            for entry in shorter {
                assert!(month.iter().any(|m| m.source_ip == entry.source_ip));
            }
        }
    }

    #[test]
    fn a_volume_flood_lands_in_retention_but_not_the_tier_files() {
        let now = now_fixed();
        // A volume-listed flood carries no score-tier (None). It must be excluded from the
        // aggressive/standard files (which filter on Some(tier)) and appear only in the
        // tier-agnostic retention windows.
        let mut flood = candidate(9, FeedTier::Aggressive, 1, now);
        flood.tier = None;
        let cands = [flood];

        let aggressive = materialize(&cands, now, Duration::hours(24), |c| {
            c.tier == Some(FeedTier::Aggressive)
        });
        let standard = materialize(&cands, now, Duration::hours(48), |c| {
            c.tier == Some(FeedTier::Standard)
        });
        let retention = materialize(&cands, now, Duration::days(1), |_| true);

        assert!(
            aggressive.is_empty(),
            "volume flood must not be in aggressive"
        );
        assert!(standard.is_empty(), "volume flood must not be in standard");
        assert_eq!(retention.len(), 1, "volume flood must be in retention");
        assert_eq!(retention[0].tier, None);
    }

    #[test]
    fn evidence_counts_survive_materialisation() {
        // The stored evidence is what an operator judges an entry by; a carry-forward that
        // zeroed it would still produce a well-formed feed.
        let now = now_fixed();
        let out = materialize(
            &[candidate(1, FeedTier::Aggressive, 1, now)],
            now,
            Duration::hours(24),
            |_| true,
        );
        assert_eq!(out[0].event_count, 37);
        assert_eq!(out[0].distinct_categories, 3);
        assert_eq!(
            out[0].categories,
            ["ssh_brute_force", "honeypot_command_exec"]
        );
        assert_eq!(out[0].tier, Some(FeedTier::Aggressive));
        assert_eq!(
            out[0].first_seen,
            coarsen_to_hour(now - Duration::hours(501))
        );
    }

    #[test]
    fn entries_are_sorted_by_ip() {
        let now = now_fixed();
        let cands = [
            candidate(30, FeedTier::Aggressive, 1, now),
            candidate(4, FeedTier::Aggressive, 1, now),
            candidate(200, FeedTier::Aggressive, 1, now),
        ];
        let out = materialize(&cands, now, Duration::hours(24), |_| true);
        let ips: Vec<String> = out.iter().map(|e| e.source_ip.to_string()).collect();
        assert_eq!(ips, ["198.51.100.4", "198.51.100.30", "198.51.100.200"]);
    }
}
