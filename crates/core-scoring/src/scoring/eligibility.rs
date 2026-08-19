pub fn eligible(has_confirmed_real: bool, event_count: u32, _distinct_categories: u32) -> bool {
    has_confirmed_real && event_count >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_requires_confirmed_real_and_multiple_events() {
        assert!(eligible(true, 2, 1));
        assert!(eligible(true, 2, 2));
        assert!(!eligible(false, 5, 5));
        assert!(!eligible(true, 1, 2));
    }
}
