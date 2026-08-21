use rust_decimal::Decimal;
use rust_decimal_macros::dec;

/// Default half-life for score decay, in seconds (6 hours).
pub const HALF_LIFE_SECONDS: i64 = 21600;

/// Dedup window, in seconds: a repeat sighting of the same `(source_ip,
/// signal_type)` within this window records the event but adds no weight.
/// Chosen default (60s) - a fixed source constant, not runtime-configurable.
pub const DEDUP_WINDOW_SECONDS: i64 = 60;

/// Upper bound a score is clamped to.
pub const SCORE_CAP: Decimal = dec!(100);

/// Breadth-factor increment per additional distinct WAN vantage beyond the first.
pub const BREADTH_PER_WAN: Decimal = dec!(0.15);

/// Upper bound on the breadth-factor bonus (i.e. factor saturates at `1 + BREADTH_CAP`).
pub const BREADTH_CAP: Decimal = dec!(0.60);

/// Minimum effective score to qualify for blocklist recommendation.
pub const BLOCKLIST_FLOOR: Decimal = dec!(50);

/// Persistence bonus - distinct-active-day points ADDED to the gate-facing score, so slow but
/// methodical attackers that the 6h decay would otherwise erase still earn their way onto the
/// tiers. The day count is unbounded and never decays (`ip_score.active_days`); the bonus itself
/// saturates at [`PERSIST_CAP`]. Additive, not multiplicative: a fixed day->tier mapping cannot be
/// hit by a multiplier, whose effect scales with per-session intensity.
///
/// Calibrated so a once-a-day authenticated attacker (command-exec, base ~60) reaches STANDARD
/// (75) at ~30 distinct active days and AGGRESSIVE (90) at ~60. Short-lived addresses accrue
/// nothing (grace), so their score is unchanged from before persistence existed. The confidence
/// and eligibility gates still apply, so a persistent low-confidence scanner is never promoted.
pub const PERSIST_PER_DAY: Decimal = dec!(0.55);

/// Distinct active days that earn no bonus. Two days is not persistence, and matches the
/// `event_count >= 2` eligibility floor - below this the score is byte-for-byte what it was.
pub const PERSIST_GRACE_DAYS: i64 = 2;

/// Upper bound on the persistence bonus, in score points.
pub const PERSIST_CAP: Decimal = dec!(60);

/// Connection-volume path onto the blocklist, independent of the confirmed-real latch. On a
/// honeypot every unsolicited connection is hostile, but the 60s same-signal dedup collapses a
/// continuous connection flood to a SINGLE scored event, so a high-volume flooder never earns a
/// score. An IP whose cumulative `event_count` crosses this threshold AND is still active within
/// [`VOLUME_LIST_WINDOW_SECONDS`] is recommended for the blocklist on volume alone. Cumulative count
/// is the volume proxy (the model has no windowed counter); the recency gate keeps a long-stopped
/// flood from lingering. Vendor reporting still requires confirmed-real, so a bare flood is blocked
/// locally but never reported upstream.
pub const VOLUME_LIST_THRESHOLD: u32 = 1000;
pub const VOLUME_LIST_WINDOW_SECONDS: i64 = 86_400;
