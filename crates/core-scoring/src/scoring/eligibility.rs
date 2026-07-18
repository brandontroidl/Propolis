pub fn eligible(has_confirmed_real: bool, event_count: u32, distinct_categories: u32) -> bool {
    has_confirmed_real && event_count >= 2 && distinct_categories >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_requires_all_three_legs() {
        assert!(eligible(true, 2, 2));
        assert!(!eligible(false, 5, 5)); // no confirmed-real
        assert!(!eligible(true, 1, 2)); // too few events
        assert!(!eligible(true, 2, 1)); // too few categories
    }
}
