use rust_decimal::Decimal;
use rust_decimal_macros::dec;

/// Default half-life for score decay, in seconds (6 hours).
pub const HALF_LIFE_SECONDS: i64 = 21600;

/// Upper bound a score is clamped to.
pub const SCORE_CAP: Decimal = dec!(100);
