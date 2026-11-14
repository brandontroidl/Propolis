//! The feed builder: reads from `ip_score` the addresses that have earned a tier, gated on
//! operator approval in `review_queue`, files each by when it last earned its tier (never by a
//! score decayed to now), applies exclusions, and coarsens every timestamp to an hour boundary.
//! See `internal/design/05-blocklist-feed.md` ("The feed builder").
//!
//! Volume-listed addresses (a thousand or more established TCP events) are a second source,
//! published only in the retention windows. They too wait for an operator: the default build
//! takes one only when it is approved in `volume_review` (or already approved in
//! `review_queue`). [`FeedConfig::volume_auto_publish`] is the opt-in that publishes them with
//! no decision.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Duration, Timelike, Utc};
use sqlx::{PgPool, Row};

use core_scoring::{FeedTier, RepoError, VOLUME_LIST_THRESHOLD, off_worker};

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
    /// `None` for a volume-listed address published only in the retention windows; `Some` for a
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
    /// Publish volume-listed addresses in the retention feeds with no operator decision
    /// (`PROPOLIS_FEED_VOLUME_AUTO_PUBLISH`). Off by default: a volume listing rests on a count
    /// of events that a sensor's own log line declares, so the default build publishes one only
    /// after an operator approved it. See [`volume_candidates_sql`].
    pub volume_auto_publish: bool,
}

impl Default for FeedConfig {
    /// The spec's ratified defaults: Aggressive 24h, Standard 48h. Retention windows default to
    /// empty so an unconfigured deployment publishes exactly the two files it always has, and
    /// volume listings default to waiting for approval.
    fn default() -> Self {
        Self {
            aggressive_ttl: Duration::hours(24),
            standard_ttl: Duration::hours(48),
            windows: Vec::new(),
            volume_auto_publish: false,
        }
    }
}

/// One approved IP as stored, before it is materialised into per-feed [`FeedEntry`] values.
///
/// Every field is read AS STORED, never re-derived against the current wall clock. That is the
/// whole point: a re-derived tier slides across the 90/75 thresholds as the score decays, so the
/// same IP is filed as aggressive on one render and standard on the next, and no two views taken
/// minutes apart agree.
///
/// What decides a listing is when the address last EARNED it, which the scoring fold records
/// (`core_scoring::IpScore::aggressive_earned_at` and `standard_earned_at`: the last time an
/// established event left the address eligible and holding that tier). An entry stays in a tier
/// file for that tier's TTL after that time and in a retention window for the window's length
/// after the later of the two. A later event that leaves the address below the tier moves
/// neither time, so it cannot take the entry out early; a datagram naming the address moves
/// nothing at all, so it cannot keep the entry in.
struct Candidate {
    ip: IpAddr,
    /// When the address last earned the aggressive tier. `None` if it never has, and for a
    /// candidate listed on volume alone.
    aggressive_earned_at: Option<DateTime<Utc>>,
    /// The same for the standard tier.
    standard_earned_at: Option<DateTime<Utc>>,
    /// The address's last established sighting, for a candidate the volume rule lists (alone, or
    /// as well as on its score). It carries the entry in the retention windows only.
    volume_seen: Option<DateTime<Utc>>,
    first_seen: DateTime<Utc>,
    /// Established events only (`established_event_count`): the stored `event_count` also counts
    /// every datagram that named the address, which anyone can send.
    event_count: i32,
    distinct_categories: i32,
    categories: Vec<String>,
}

/// The time a feed's entry runs from, and the tier it is published with.
type Listing = (DateTime<Utc>, Option<FeedTier>);

/// Whether a listing that runs from `at` is still inside `ttl`. A time ahead of the clock is read
/// as now, as [`materialize`] reads it.
fn is_live(at: Option<DateTime<Utc>>, now: DateTime<Utc>, ttl: Duration) -> bool {
    at.is_some_and(|at| now - at.min(now) < ttl)
}

impl Candidate {
    /// The aggressive file: the address earned the aggressive tier.
    fn aggressive_listing(&self) -> Option<Listing> {
        self.aggressive_earned_at
            .map(|at| (at, Some(FeedTier::Aggressive)))
    }

    /// The standard file: the address earned the standard tier and is not in the aggressive
    /// file now. The two files never hold the same address, so one that earned both stays in
    /// the aggressive file for its full TTL and is then carried here for what is left of the
    /// standard one.
    fn standard_listing(&self, now: DateTime<Utc>, aggressive_ttl: Duration) -> Option<Listing> {
        if is_live(self.aggressive_earned_at, now, aggressive_ttl) {
            return None;
        }
        self.standard_earned_at
            .map(|at| (at, Some(FeedTier::Standard)))
    }

    /// A retention window of length `retention`: the latest of the times the address earned a
    /// tier and, for a volume listing, its last established sighting. The entry names the tier
    /// last earned if that is itself inside the window, and no tier when only the volume rule
    /// holds it there.
    fn window_listing(&self, now: DateTime<Utc>, retention: Duration) -> Option<Listing> {
        let earned = match (self.aggressive_earned_at, self.standard_earned_at) {
            (Some(aggressive), Some(standard)) if standard > aggressive => {
                Some((standard, FeedTier::Standard))
            }
            (Some(aggressive), _) => Some((aggressive, FeedTier::Aggressive)),
            (None, Some(standard)) => Some((standard, FeedTier::Standard)),
            (None, None) => None,
        };
        let tier = earned
            .filter(|&(at, _)| is_live(Some(at), now, retention))
            .map(|(_, tier)| tier);
        let clock = earned.map(|(at, _)| at).max(self.volume_seen)?;
        Some((clock, tier))
    }
}

/// Stateless namespace for the build step (mirrors the design's `FeedBuilder::build`).
pub struct FeedBuilder;

impl FeedBuilder {
    /// Build a `FeedSnapshot` from the current `ip_score` projection.
    ///
    /// Membership is decided by RETENTION, not by a live-decayed score:
    ///
    /// 1. Selects approved, not-delisted candidates that have earned a tier, reading the two
    ///    earned times, `first_seen` and the evidence counts AS STORED ([`Candidate`]). With
    ///    retention windows configured it then adds the volume-listed addresses, approved ones
    ///    only unless `config.volume_auto_publish` is set ([`volume_candidates_sql`]).
    /// 2. Applies `exclusions.is_excluded` (reserved ranges, operator allowlist, delist).
    /// 3. Keeps an entry while the time it runs from falls inside the relevant window: the
    ///    tier's TTL after the tier was last earned for `aggressive`/`standard`, or the window's
    ///    own duration for each configured retention feed. `valid_from`/`valid_until` are
    ///    anchored on that time, so the published validity window is the truth about when the
    ///    entry expires.
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

        // An entry leaves every feed once the time it runs from is older than the longest window
        // it can appear in, so a candidate past the longest one cannot be published and its signal
        // types are not worth reading. `materialize` applies the exact per-feed cutoffs; this is only the
        // superset those can never exceed (a minute of margin for the clock moving between this
        // read and `materialize`'s).
        let merit_horizon = [config.aggressive_ttl, config.standard_ttl]
            .into_iter()
            .chain(config.windows.iter().map(|(_, retention)| *retention))
            .max()
            .unwrap_or_else(Duration::zero);
        let merit_cutoff = Utc::now() - merit_horizon - Duration::minutes(1);

        let rows = sqlx::query(sqlx::AssertSqlSafe(merit_candidates_sql()))
            .bind(merit_cutoff)
            .fetch_all(pool)
            .await?;

        let mut candidates = Vec::with_capacity(rows.len());

        // The row loops decode, parse and test every address against the exclusions with no
        // await in between: 3 ms for 5,000 addresses and 31 ms for 50,000 (the `cpu_budget`
        // example), so they run off the async worker.
        off_worker(|| -> Result<(), FeedError> {
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

                candidates.push(Candidate {
                    ip,
                    aggressive_earned_at: row.try_get("aggressive_earned_at")?,
                    standard_earned_at: row.try_get("standard_earned_at")?,
                    volume_seen: None,
                    first_seen: row.try_get("first_seen")?,
                    event_count: row.try_get("event_count")?,
                    distinct_categories: row.try_get("distinct_categories")?,
                    categories: row.try_get("categories")?,
                });
            }
            Ok(())
        })?;

        // Volume-listed addresses: listed on connection volume alone (a thousand or more
        // established TCP events), with no score tier. They go into the RETENTION windows only -
        // never the score-tiered files - so a hyperactive flooder the dedup would otherwise erase
        // can still be blocked. Which of them are read depends on `volume_auto_publish`: by
        // default only those an operator approved, see `volume_candidates_sql`. Exclusions still
        // apply, the same as for merit candidates.
        //
        // Only a retention window can publish one, so with none configured there is nothing to
        // read, and with some the longest bounds the candidates as above.
        let volume_rows = match config.windows.iter().map(|(_, retention)| *retention).max() {
            None => Vec::new(),
            Some(longest) => {
                let sql = volume_candidates_sql(config.volume_auto_publish);
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(Utc::now() - longest - Duration::minutes(1))
                    .bind(i64::from(VOLUME_LIST_THRESHOLD))
                    .fetch_all(pool)
                    .await?
            }
        };

        // An approved address can meet the volume condition and be a merit candidate at once
        // (the approved leg of the statement does not require `eligible = false`). It is
        // published once: its volume row is not a second entry but a second clock on the merit
        // candidate. The two differ (the tier was earned days ago, the flood is an hour old), and
        // a window holds the entry while either is inside it.
        let merit_at: HashMap<IpAddr, usize> = candidates
            .iter()
            .enumerate()
            .map(|(at, c)| (c.ip, at))
            .collect();

        off_worker(|| -> Result<(), FeedError> {
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
                let volume_seen: Option<DateTime<Utc>> = row.try_get("established_last_seen")?;
                if let Some(&at) = merit_at.get(&ip) {
                    candidates[at].volume_seen = volume_seen;
                    continue;
                }
                candidates.push(Candidate {
                    ip,
                    aggressive_earned_at: None,
                    standard_earned_at: None,
                    volume_seen,
                    first_seen: row.try_get("first_seen")?,
                    event_count: row.try_get("event_count")?,
                    distinct_categories: row.try_get("distinct_categories")?,
                    categories: row.try_get("categories")?,
                });
            }
            Ok(())
        })?;

        let now = Utc::now();
        let aggressive = materialize(&candidates, now, config.aggressive_ttl, |c| {
            c.aggressive_listing()
        });
        let standard = materialize(&candidates, now, config.standard_ttl, |c| {
            c.standard_listing(now, config.aggressive_ttl)
        });
        let windows: Vec<WindowFeed> = config
            .windows
            .iter()
            .map(|(label, retention)| WindowFeed {
                label: label.clone(),
                retention: *retention,
                entries: materialize(&candidates, now, *retention, |c| {
                    c.window_listing(now, *retention)
                }),
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

/// The distinct signal types an address triggered over a completed TCP connection, as the wire
/// vocabulary, sorted by name: one index probe per member of the closed `signal_type_enum`
/// (`event_dedup_tcp_idx` holds the established rows only and starts with the source address
/// and then the signal type, so each probe is a single descent), keeping the members the address
/// has at least one such event of. The cost is the number of signal types (17), not the number
/// of events the address produced: `SELECT DISTINCT signal_type FROM event WHERE source_ip =
/// ...` read every one of them, 4.3 s for 5,566 addresses on the live node.
///
/// Established events only, like everything else an entry says: a datagram's source address is
/// whatever its sender wrote, so one forged packet at a UDP listener would otherwise add a
/// signal type of the sender's choosing to a third party's published entry.
///
/// The `LIMIT 1` inside a `LATERAL` keeps the planner from turning the probes back into a join
/// that reads the address's whole history, which `WHERE EXISTS (...)` does. It reads the enum's
/// labels as text rather than mapping through the Rust enum because the database enum's labels ARE
/// the wire vocabulary (`0001_enums.sql`), so there is no second casing to keep in sync - and
/// `SignalType`'s Serialize is frozen to bare Rust identifiers for chain hashing, which is the
/// wrong vocabulary to publish. `s` is the outer `ip_score` row.
const CATEGORIES_SQL: &str = "ARRAY(SELECT t.v::text \
         FROM unnest(enum_range(NULL::signal_type_enum)) AS t(v) \
         CROSS JOIN LATERAL ( \
             SELECT 1 FROM event e \
             WHERE e.source_ip = s.source_ip AND e.signal_type = t.v AND e.protocol = 'tcp' \
             ORDER BY e.observed_at DESC LIMIT 1 \
         ) x ORDER BY 1)";

/// The approved candidates that have earned a tier, read as stored. `$1` is the oldest earned
/// time any feed can still publish (see [`FeedBuilder::build`]).
///
/// The earned times are set only by an established event that left the address eligible and
/// tiered, so they stand in for the stored `eligible`, `recommended_for_blocklist` and `tier` this
/// statement used to read: those are whatever the address's LAST event left, and a later weak
/// event clearing them must not end a listing that still has time to run. The delist latch is
/// read directly, since delisting leaves the earned times in place.
pub fn merit_candidates_sql() -> String {
    format!(
        "SELECT host(s.source_ip) AS source_ip, s.aggressive_earned_at, s.standard_earned_at, \
                s.first_seen, s.established_event_count AS event_count, s.distinct_categories, \
                {CATEGORIES_SQL} AS categories \
         FROM ip_score s \
         INNER JOIN review_queue q ON q.source_ip = s.source_ip \
         WHERE q.state = 'approved' AND NOT s.delisted \
           AND GREATEST(s.aggressive_earned_at, s.standard_earned_at) > $1"
    )
}

/// The volume-listed addresses a retention window may publish. `$1` is the oldest established
/// sighting any retention window can still publish and `$2` the volume threshold (bind
/// `core_scoring::VOLUME_LIST_THRESHOLD`). Recency is `established_last_seen`, the last completed
/// TCP connection, never `last_seen`: a datagram naming the address must not keep it listed.
///
/// By default (`auto_publish` false) an address is read only when an operator approved it: it is
/// not delisted, its `established_event_count` is at least `$2`, and it has an Approved
/// `volume_review` row or an Approved `review_queue` row. An address already approved on its
/// score needs no second decision, which is also why this form does not require
/// `eligible = false`: an approved volume listing must not vanish when the address later becomes
/// eligible as well. It reads the count and the delist latch themselves rather than the stored
/// `recommended_for_blocklist` flag, so the condition is the volume rule's and not whatever else
/// set that flag.
///
/// With `auto_publish` (the opt-in `PROPOLIS_FEED_VOLUME_AUTO_PUBLISH` sets) the statement also
/// reads, with no decision asked, every address the stored projection lists on volume
/// (`recommended_for_blocklist = true AND eligible = false`). It still reads everything the
/// default form reads, so turning the opt-in on never takes an approved address out of a feed.
pub fn volume_candidates_sql(auto_publish: bool) -> String {
    let approved = "NOT s.delisted AND s.established_event_count >= $2 \
           AND (EXISTS (SELECT 1 FROM volume_review v \
                        WHERE v.source_ip = s.source_ip AND v.state = 'approved') \
                OR EXISTS (SELECT 1 FROM review_queue q \
                           WHERE q.source_ip = s.source_ip AND q.state = 'approved'))";
    let listed = if auto_publish {
        format!("((s.recommended_for_blocklist = true AND s.eligible = false) OR ({approved}))")
    } else {
        approved.to_owned()
    };
    format!(
        "SELECT host(s.source_ip) AS source_ip, s.first_seen, s.established_last_seen, \
                s.established_event_count AS event_count, s.distinct_categories, \
                {CATEGORIES_SQL} AS categories \
         FROM ip_score s \
         WHERE s.established_last_seen > $1 AND {listed}"
    )
}

/// Select the candidates `listing` places in this feed and whose listing time falls inside
/// `ttl`, and materialise them as [`FeedEntry`] values whose validity window is anchored on that
/// time. `listing` gives, for a candidate, the time its entry in this feed runs from and the tier
/// it is published with, or `None` when the candidate does not belong in the feed.
///
/// Anchoring on the time the listing was earned rather than on build time is what makes the
/// published `valid_until` mean what it says: an entry is carried for a fixed period after the
/// activity that justified it, and leaves when that period lapses. Anchoring on build time
/// instead would restart every entry's clock on each build, so nothing would ever expire. The
/// published `last_seen` is the same time: the last activity that earned the entry its place.
///
/// A listing time later than `now` is read as `now`. It is the timestamp an event carried, which
/// is whatever its log line said; taken as stored, a line dated a year ahead would keep the entry
/// in every window for that year plus the window, and publish a `valid_until` to match. Read as
/// `now`, the entry can never be valid past `now + ttl`.
fn materialize(
    candidates: &[Candidate],
    now: DateTime<Utc>,
    ttl: Duration,
    listing: impl Fn(&Candidate) -> Option<Listing>,
) -> Vec<FeedEntry> {
    let mut out: Vec<FeedEntry> = candidates
        .iter()
        .filter_map(|c| listing(c).map(|(at, tier)| (c, at.min(now), tier)))
        .filter(|(_, at, _)| now - *at < ttl)
        .map(|(c, at, tier)| {
            let valid_from = coarsen_to_hour(at);
            FeedEntry {
                source_ip: c.ip,
                tier,
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

    #[test]
    fn feed_config_default_does_not_publish_volume_listings_without_approval() {
        // Automatic publication is an opt-in. A config built with `..FeedConfig::default()` (the
        // standalone binary, every test) must get the approval-gated statement.
        assert!(!FeedConfig::default().volume_auto_publish);
        let gated = volume_candidates_sql(false);
        assert!(gated.contains("v.state = 'approved'"));
        assert!(
            gated.contains("s.established_last_seen > $1") && !gated.contains("s.last_seen"),
            "recency is the last connection, never the last sighting: {gated}"
        );
        assert!(
            !gated.contains("recommended_for_blocklist"),
            "the default statement reads no address without a decision: {gated}"
        );
        // The opt-in adds the automatic condition and keeps the approved one, so setting it
        // never takes an approved address out.
        let automatic = volume_candidates_sql(true);
        assert!(automatic.contains("s.recommended_for_blocklist = true AND s.eligible = false"));
        assert!(automatic.contains("v.state = 'approved'"));
    }

    /// A candidate that last earned `tier` `hours_ago`, with a deliberately non-default value in
    /// every field so a carry-forward that drops one is visible rather than passing on a
    /// matching default.
    fn candidate(last_octet: u8, tier: FeedTier, hours_ago: i64, now: DateTime<Utc>) -> Candidate {
        let earned = Some(now - Duration::hours(hours_ago));
        let (aggressive_earned_at, standard_earned_at) = match tier {
            FeedTier::Aggressive => (earned, None),
            FeedTier::Standard => (None, earned),
        };
        Candidate {
            ip: format!("198.51.100.{last_octet}").parse().unwrap(),
            aggressive_earned_at,
            standard_earned_at,
            volume_seen: None,
            first_seen: now - Duration::hours(hours_ago + 500),
            event_count: 37,
            distinct_categories: 3,
            categories: vec!["ssh_brute_force".into(), "honeypot_command_exec".into()],
        }
    }

    fn now_fixed() -> DateTime<Utc> {
        "2026-08-19T12:30:00Z".parse().unwrap()
    }

    const AGGRESSIVE_TTL: Duration = Duration::hours(24);
    const STANDARD_TTL: Duration = Duration::hours(48);

    fn aggressive_file(cands: &[Candidate], now: DateTime<Utc>) -> Vec<FeedEntry> {
        materialize(cands, now, AGGRESSIVE_TTL, |c| c.aggressive_listing())
    }

    fn standard_file(cands: &[Candidate], now: DateTime<Utc>) -> Vec<FeedEntry> {
        materialize(cands, now, STANDARD_TTL, |c| {
            c.standard_listing(now, AGGRESSIVE_TTL)
        })
    }

    fn window(cands: &[Candidate], now: DateTime<Utc>, retention: Duration) -> Vec<FeedEntry> {
        materialize(cands, now, retention, |c| c.window_listing(now, retention))
    }

    fn ips(entries: &[FeedEntry]) -> Vec<String> {
        entries.iter().map(|e| e.source_ip.to_string()).collect()
    }

    #[test]
    fn an_entry_leaves_the_feed_once_its_ttl_lapses_since_it_was_earned() {
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 2, now),
            candidate(2, FeedTier::Aggressive, 23, now),
            candidate(3, FeedTier::Aggressive, 25, now),
        ];

        let out = aggressive_file(&cands, now);

        assert_eq!(ips(&out), ["198.51.100.1", "198.51.100.2"]);
    }

    #[test]
    fn validity_is_anchored_on_when_the_listing_was_earned_not_on_build_time() {
        // The defect this guards: anchoring on build time restarts every entry's clock on each
        // build, so an address seen once and never again is republished with a fresh 24h validity
        // forever. Anchoring on the earned time means the published valid_until is the truth.
        let now = now_fixed();
        let cands = [candidate(1, FeedTier::Aggressive, 20, now)];

        let out = aggressive_file(&cands, now);

        let entry = &out[0];
        assert_eq!(entry.valid_from, coarsen_to_hour(now - Duration::hours(20)));
        assert_eq!(entry.last_seen, entry.valid_from);
        assert_eq!(entry.valid_until, entry.valid_from + Duration::hours(24));
        // Four hours of validity left, not a fresh twenty-four.
        assert_eq!(
            entry.valid_until - now,
            Duration::hours(3) + Duration::minutes(30)
        );
    }

    #[test]
    fn a_listing_time_in_the_future_is_read_as_now_so_validity_never_outlasts_the_ttl() {
        // The earned time is the timestamp an event carried. Taken as stored, a line dated a year
        // ahead passes `now - at < ttl` for that whole year and is published as valid until a
        // year and a day from now. The same holds for a volume listing's last sighting.
        let now = now_fixed();
        let mut ahead = candidate(1, FeedTier::Aggressive, 0, now);
        ahead.aggressive_earned_at = Some(now + Duration::days(365));
        let on_time = candidate(2, FeedTier::Aggressive, 0, now);
        let cands = [ahead, on_time];

        let out = aggressive_file(&cands, now);

        assert_eq!(out.len(), 2, "a future time is clamped, not dropped");
        for entry in &out {
            assert_eq!(entry.last_seen, coarsen_to_hour(now), "{}", entry.source_ip);
            assert_eq!(
                entry.valid_from,
                coarsen_to_hour(now),
                "{}",
                entry.source_ip
            );
            assert!(
                entry.valid_until <= now + Duration::hours(24),
                "{} is published as valid until {}",
                entry.source_ip,
                entry.valid_until
            );
        }
        // The two are the same entry apart from the address: the clamp treats the future-dated
        // one exactly as an address that earned its tier at build time.
        assert_eq!(out[0].valid_until, out[1].valid_until);

        let mut flood = candidate(3, FeedTier::Standard, 0, now);
        flood.standard_earned_at = None;
        flood.volume_seen = Some(now + Duration::days(365));
        let day = window(&[flood], now, Duration::days(1));
        assert_eq!(day.len(), 1);
        assert!(day[0].valid_until <= now + Duration::days(1));
    }

    #[test]
    fn each_tier_file_holds_what_earned_that_tier_and_the_two_never_overlap() {
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 1, now),
            candidate(2, FeedTier::Standard, 1, now),
        ];

        let aggressive = aggressive_file(&cands, now);
        let standard = standard_file(&cands, now);

        assert_eq!(ips(&aggressive), ["198.51.100.1"]);
        assert_eq!(aggressive[0].tier, Some(FeedTier::Aggressive));
        assert_eq!(ips(&standard), ["198.51.100.2"]);
        assert_eq!(standard[0].tier, Some(FeedTier::Standard));
    }

    #[test]
    fn an_address_that_earned_both_tiers_runs_out_the_aggressive_ttl_and_then_the_standard_one() {
        // Aggressive 20 hours ago; 15 hours ago a weaker event left it standard. It must not
        // leave the aggressive file for that: the file is for 24 hours after the tier was last
        // earned. When that lapses it is carried in the standard file for what is left of the
        // 48 hours the standard tier earned it.
        let earned_at = now_fixed();
        let mut both = candidate(1, FeedTier::Aggressive, 20, earned_at);
        both.standard_earned_at = Some(earned_at - Duration::hours(15));
        let cands = [both];

        let now = earned_at;
        assert_eq!(ips(&aggressive_file(&cands, now)), ["198.51.100.1"]);
        assert!(
            standard_file(&cands, now).is_empty(),
            "never in both files at once"
        );

        // Five hours on: 25 hours since aggressive, 20 since standard.
        let later = earned_at + Duration::hours(5);
        assert!(aggressive_file(&cands, later).is_empty());
        let standard = standard_file(&cands, later);
        assert_eq!(ips(&standard), ["198.51.100.1"]);
        assert_eq!(
            standard[0].valid_from,
            coarsen_to_hour(earned_at - Duration::hours(15)),
            "its standard listing runs from when standard was earned"
        );

        // 34 hours on: 49 since standard. Out of both.
        let gone = earned_at + Duration::hours(34);
        assert!(aggressive_file(&cands, gone).is_empty());
        assert!(standard_file(&cands, gone).is_empty());
    }

    // Executable documentation-truth check for README.md "## Scoring", bullet "Score decay and
    // retention": "Feed membership ... is decided by retention windows (24h aggressive, 48h
    // standard), not by the live score - a quiet attacker is retained for its window rather than
    // dropping out the moment its score falls. This is a retention feed, not a decay-out feed."
    // `materialize` takes NO score argument at all: an entry is kept iff the time it earned its
    // listing is within the retention window. So a quiet-but-recent attacker (whose live score
    // would have decayed) is retained, and an entry leaves only when the window lapses - never
    // because a score fell. If membership ever starts consulting a live/decayed score, this test's
    // score-free premise breaks and the README claim must be revisited.
    #[test]
    fn readme_feed_membership_is_retention_based_not_score_based() {
        let now = now_fixed();
        // Quiet-but-recent: earned 23h ago (no recent activity, a live score would have decayed
        // over ~4 half-lives), still inside the 24h aggressive window.
        let quiet_but_recent = candidate(1, FeedTier::Aggressive, 23, now);
        // Same evidence, earned 25h ago: outside the window.
        let aged_out = candidate(2, FeedTier::Aggressive, 25, now);

        let out = aggressive_file(&[quiet_but_recent, aged_out], now);

        // Retained purely because it is within the retention window - no score consulted. The 25h
        // one leaves only because the window lapsed, not because any score fell below a floor.
        assert_eq!(ips(&out), ["198.51.100.1"]);
    }

    #[test]
    fn retention_windows_nest_and_ignore_tier() {
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 2, now),
            candidate(2, FeedTier::Standard, 100, now),
            candidate(3, FeedTier::Standard, 1_000, now),
        ];

        let day = window(&cands, now, Duration::days(1));
        let week = window(&cands, now, Duration::days(7));
        let month = window(&cands, now, Duration::days(90));

        assert_eq!(day.len(), 1);
        assert_eq!(week.len(), 2);
        assert_eq!(month.len(), 3);
        // A consumer picks one file and gets a superset of every shorter one.
        for shorter in [&day, &week] {
            for entry in shorter {
                assert!(month.iter().any(|m| m.source_ip == entry.source_ip));
            }
        }
        assert_eq!(day[0].tier, Some(FeedTier::Aggressive));
        assert_eq!(week[1].tier, Some(FeedTier::Standard));
    }

    #[test]
    fn a_window_runs_from_the_later_of_the_two_earned_times() {
        let now = now_fixed();
        // Aggressive 10 days ago, standard 3 days ago.
        let mut both = candidate(1, FeedTier::Aggressive, 240, now);
        both.standard_earned_at = Some(now - Duration::hours(72));
        let week = window(&[both], now, Duration::days(7));
        assert_eq!(week.len(), 1);
        assert_eq!(
            week[0].valid_from,
            coarsen_to_hour(now - Duration::hours(72))
        );
        assert_eq!(
            week[0].tier,
            Some(FeedTier::Standard),
            "the tier last earned"
        );
    }

    #[test]
    fn a_volume_flood_lands_in_retention_but_not_the_tier_files() {
        let now = now_fixed();
        // A volume-listed flood has earned no tier. Once the build has taken it (by default only
        // with an operator's approval, see `tests/builder_test.rs`) it must be excluded from the
        // aggressive/standard files and appear only in the tier-agnostic retention windows.
        let mut flood = candidate(9, FeedTier::Aggressive, 1, now);
        flood.aggressive_earned_at = None;
        flood.volume_seen = Some(now - Duration::hours(1));
        let cands = [flood];

        let aggressive = aggressive_file(&cands, now);
        let standard = standard_file(&cands, now);
        let retention = window(&cands, now, Duration::days(1));

        assert!(
            aggressive.is_empty(),
            "volume flood must not be in aggressive"
        );
        assert!(standard.is_empty(), "volume flood must not be in standard");
        assert_eq!(retention.len(), 1, "volume flood must be in retention");
        assert_eq!(retention[0].tier, None);
    }

    #[test]
    fn an_address_listed_on_its_score_and_on_volume_is_in_each_window_either_clock_reaches() {
        // It earned standard ten days ago and has been flooding since; its last connection was
        // an hour ago. The volume rule puts it in the day and week windows, the score in the
        // month. Carried on the older clock alone it would be missing from the short windows
        // while it is flooding now.
        let now = now_fixed();
        let mut both = candidate(1, FeedTier::Standard, 240, now);
        both.volume_seen = Some(now - Duration::hours(1));
        let cands = [both];

        let day = window(&cands, now, Duration::days(1));
        let month = window(&cands, now, Duration::days(30));
        assert_eq!(day.len(), 1, "the flood is an hour old");
        assert_eq!(
            day[0].tier, None,
            "the day window holds it on volume, not on a tier"
        );
        assert_eq!(day[0].valid_from, coarsen_to_hour(now - Duration::hours(1)));
        assert_eq!(month.len(), 1);
        assert_eq!(month[0].tier, Some(FeedTier::Standard));
        assert_eq!(
            month[0].valid_from,
            coarsen_to_hour(now - Duration::hours(1)),
            "one entry, on the later clock"
        );
        // The volume clock never files it in a tier file.
        assert!(aggressive_file(&cands, now).is_empty());
        assert!(standard_file(&cands, now).is_empty());
    }

    // README "Score decay and retention": "retention windows (24h aggressive, 48h standard)". The
    // membership test above exercises only the 24h window; this covers BOTH documented windows and
    // their boundaries so a drift in either is caught. (The 24h/48h VALUES are the config defaults
    // PROPOLIS_FEED_AGGRESSIVE_TTL_HOURS / _STANDARD_TTL_HOURS, guarded in the propolis config tests;
    // here we verify the retention mechanism honors each window's boundary.)
    #[test]
    fn readme_both_documented_retention_windows_apply_at_their_boundaries() {
        let now = now_fixed();
        let cands = [
            candidate(1, FeedTier::Aggressive, 23, now), // within the 24h aggressive window
            candidate(2, FeedTier::Aggressive, 25, now), // outside it
            candidate(3, FeedTier::Standard, 47, now),   // within the 48h standard window
            candidate(4, FeedTier::Standard, 49, now),   // outside it
        ];

        assert_eq!(
            ips(&aggressive_file(&cands, now)),
            ["198.51.100.1"],
            "24h window keeps only the 23h-old entry"
        );
        assert_eq!(
            ips(&standard_file(&cands, now)),
            ["198.51.100.3"],
            "48h window keeps the 47h entry and not the 49h one"
        );
    }

    #[test]
    fn evidence_counts_survive_materialisation() {
        // The stored evidence is what an operator judges an entry by; a carry-forward that
        // zeroed it would still produce a well-formed feed.
        let now = now_fixed();
        let out = aggressive_file(&[candidate(1, FeedTier::Aggressive, 1, now)], now);
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
        let out = aggressive_file(&cands, now);
        assert_eq!(
            ips(&out),
            ["198.51.100.4", "198.51.100.30", "198.51.100.200"]
        );
    }
}
