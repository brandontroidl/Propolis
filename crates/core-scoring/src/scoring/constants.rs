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
