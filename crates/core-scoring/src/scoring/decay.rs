use rust_decimal::Decimal;

/// Exponential decay of a score toward zero over time.
///
/// `factor = 0.5 ^ (elapsed_seconds / half_life_seconds)`.
///
/// The sole sanctioned `f64` touchpoint in this crate: `0.5^x` has no exact
/// decimal representation, so the exponent and `powf` are computed in `f64`
/// and the resulting factor is converted back to `Decimal` before being
/// multiplied into the score. The score itself is never stored or
/// accumulated through `f64` - only this one transcendental factor passes
/// through it, per call, and is immediately reconverted.
pub fn decay(prev: Decimal, elapsed_seconds: i64, half_life_seconds: i64) -> Decimal {
    if elapsed_seconds <= 0 {
        return prev; // clock-skew clamp: decay only ever shrinks
    }
    let exp = elapsed_seconds as f64 / half_life_seconds as f64;
    let factor = Decimal::from_f64_retain(0.5f64.powf(exp)).unwrap_or(Decimal::ZERO);
    prev * factor
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use proptest::prelude::*;

    #[test]
    fn clamps_nonpositive_elapsed() {
        assert_eq!(decay(dec!(50), 0, 21600), dec!(50));
        assert_eq!(decay(dec!(50), -100, 21600), dec!(50));
    }

    #[test]
    fn halves_at_exactly_one_half_life() {
        let out = decay(dec!(80), 21600, 21600);
        assert!((out - dec!(40)).abs() < dec!(0.0001));
    }

    proptest! {
        #[test]
        fn monotonic_non_increasing(prev in 0i64..100, elapsed in 0i64..1_000_000) {
            let p = Decimal::from(prev);
            prop_assert!(decay(p, elapsed, 21600) <= p);
        }
    }
}
