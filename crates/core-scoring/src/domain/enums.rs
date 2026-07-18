#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "protocol_enum", rename_all = "lowercase")]
pub enum Protocol { Tcp, Udp, Icmp }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "category_enum", rename_all = "lowercase")]
pub enum Category { Honeypot, Ids, Network, Waf, Auth }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "feed_tier_enum", rename_all = "lowercase")]
pub enum FeedTier { Aggressive, Standard }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "signal_type_enum", rename_all = "snake_case")]
pub enum SignalType {
    HoneypotConnection, HoneypotLoginAttempt, HoneypotCommandExec, HoneypotMalwareUpload,
    HoneypotFileDownload, SuricataSev1, SuricataSev2, SuricataSev3, PortScan, SynFlood,
    BlockedConnection, WafSqliXss, WafGenericBlock, SshBruteForce, CatchallProbe, RemoteAuthFailure,
}
impl SignalType {
    pub const ALL: [SignalType; 16] = [
        SignalType::HoneypotConnection, SignalType::HoneypotLoginAttempt, SignalType::HoneypotCommandExec,
        SignalType::HoneypotMalwareUpload, SignalType::HoneypotFileDownload, SignalType::SuricataSev1,
        SignalType::SuricataSev2, SignalType::SuricataSev3, SignalType::PortScan, SignalType::SynFlood,
        SignalType::BlockedConnection, SignalType::WafSqliXss, SignalType::WafGenericBlock,
        SignalType::SshBruteForce, SignalType::CatchallProbe, SignalType::RemoteAuthFailure,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "review_state_enum", rename_all = "lowercase")]
pub enum ReviewState { Pending, Approved, Rejected, Snoozed }

pub fn is_confirmed_real(p: Protocol, authenticated: bool, c: Category) -> bool {
    p == Protocol::Tcp && authenticated && c == Category::Honeypot
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signal_type_all_has_16_distinct_variants() {
        assert_eq!(SignalType::ALL.len(), 16);
        let mut seen = std::collections::HashSet::new();
        for s in SignalType::ALL { assert!(seen.insert(s), "duplicate {s:?}"); }
    }
    #[test]
    fn confirmed_real_predicate_only_tcp_auth_honeypot() {
        assert!(is_confirmed_real(Protocol::Tcp, true, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Udp, true, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Tcp, false, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Tcp, true, Category::Ids));
    }
}
