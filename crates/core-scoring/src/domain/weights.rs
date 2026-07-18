use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use crate::domain::enums::{SignalType, Category};

pub struct SignalWeight { pub weight: u32, pub confidence: Decimal, pub category: Category }

pub fn signal_weight(s: SignalType) -> SignalWeight {
    use SignalType::*; use Category::*;
    let (weight, confidence, category) = match s {
        HoneypotConnection   => (40, dec!(0.900), Honeypot),
        HoneypotLoginAttempt => (50, dec!(0.920), Honeypot),
        HoneypotCommandExec  => (60, dec!(0.950), Honeypot),
        HoneypotMalwareUpload=> (80, dec!(0.980), Honeypot),
        HoneypotFileDownload => (70, dec!(0.960), Honeypot),
        SuricataSev1         => (30, dec!(0.700), Ids),
        SuricataSev2         => (15, dec!(0.500), Ids),
        SuricataSev3         => ( 5, dec!(0.300), Ids),
        PortScan             => (20, dec!(0.600), Network),
        SynFlood             => (25, dec!(0.700), Network),
        BlockedConnection    => ( 3, dec!(0.150), Network),
        WafSqliXss           => (35, dec!(0.850), Waf),
        WafGenericBlock      => (15, dec!(0.500), Waf),
        SshBruteForce        => (20, dec!(0.600), Auth),
        CatchallProbe        => (15, dec!(0.400), Network),
        RemoteAuthFailure    => (12, dec!(0.400), Auth),
    };
    SignalWeight { weight, confidence, category }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::enums::{SignalType, Category};
    #[test]
    fn every_signal_type_has_exactly_one_weight_row() {
        for s in SignalType::ALL { let _ = signal_weight(s); } // total: no panic, no default arm
    }
    #[test]
    fn spot_check_known_rows() {
        let w = signal_weight(SignalType::HoneypotMalwareUpload);
        assert_eq!(w.weight, 80);
        assert_eq!(w.confidence, dec!(0.980));
        assert_eq!(w.category, Category::Honeypot);
        assert_eq!(signal_weight(SignalType::BlockedConnection).weight, 3);
    }
}
