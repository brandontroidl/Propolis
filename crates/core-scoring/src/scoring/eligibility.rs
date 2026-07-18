use std::collections::BTreeMap;

use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use crate::domain::enums::Category;

pub type CategoryBreakdown = BTreeMap<Category, Decimal>;

pub fn distinct_categories(breakdown: &CategoryBreakdown) -> u32 {
    let threshold = &dec!(0.5);
    breakdown
        .values()
        .filter(|weight| *weight > threshold)
        .count() as u32
}

pub fn eligible(has_confirmed_real: bool, event_count: u32, distinct_categories: u32) -> bool {
    has_confirmed_real && event_count >= 2 && distinct_categories >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn eligibility_requires_all_three_legs() {
        assert!(eligible(true, 2, 2));
        assert!(!eligible(false, 5, 5));      // no confirmed-real
        assert!(!eligible(true, 1, 2));       // too few events
        assert!(!eligible(true, 2, 1));       // too few categories
    }

    #[test]
    fn distinct_categories_floor_is_strict_at_half() {
        let mut b = CategoryBreakdown::new();
        b.insert(Category::Honeypot, dec!(0.50));   // exactly 0.5 does NOT count
        b.insert(Category::Ids, dec!(0.51));
        assert_eq!(distinct_categories(&b), 1);
    }
}
