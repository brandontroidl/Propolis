pub fn eligible(
    has_confirmed_real: bool,
    event_count: u32,
    _distinct_categories: u32,
    delisted: bool,
) -> bool {
    !delisted && has_confirmed_real && event_count >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_requires_confirmed_real_and_multiple_events() {
        assert!(eligible(true, 2, 1, false));
        assert!(eligible(true, 2, 2, false));
        assert!(!eligible(false, 5, 5, false));
        assert!(!eligible(true, 1, 2, false));
    }

    #[test]
    fn delisted_ip_is_never_eligible() {
        assert!(!eligible(true, 100, 5, true));
    }
}
