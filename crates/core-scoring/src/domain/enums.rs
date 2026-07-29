#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "protocol_enum", rename_all = "lowercase")]
// Deserialize-only (not the symmetric `rename_all = "..."` form): Serialize is deliberately left
// at its default (the bare Rust identifier, e.g. "Tcp") because `hashing.rs`'s FROZEN canonical
// byte encoding hashes `serde_json::to_vec(&event.protocol)` verbatim - flipping Serialize's
// casing here would silently change `canonical_bytes`/`chain_hash` output for every event and
// break `hashing::tests::golden_chain_hash_is_stable`'s pinned vector (confirmed empirically:
// applying the symmetric form breaks that exact test). Deserialize accepts the sensor-wire
// lowercase strings (`sensor_wire::PROTO_TCP` et al.) so `sensor-catchall`'s cross-crate test
// (and, later, intake) can `serde_json::from_str::<Protocol>` a wire record's protocol string
// directly. "lowercase" mirrors this enum's own `#[sqlx(rename_all = "lowercase")]` above; every
// variant here is a single word, so it is byte-identical to "snake_case" in practice.
#[serde(rename_all(deserialize = "lowercase"))]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    sqlx::Type,
)]
#[sqlx(type_name = "category_enum", rename_all = "lowercase")]
pub enum Category {
    Honeypot,
    Ids,
    Network,
    Waf,
    Auth,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "feed_tier_enum", rename_all = "lowercase")]
pub enum FeedTier {
    Aggressive,
    Standard,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "signal_type_enum", rename_all = "snake_case")]
// Deserialize-only - see `Protocol`'s identical-shaped attribute above for why: Serialize must
// stay at its default casing (the bare Rust identifier) so `hashing.rs`'s frozen `canonical_bytes`
// encoding - which hashes `serde_json::to_vec(&event.signal_type)` - never changes for an
// already-defined `EventInput`, which would break every existing chain hash and the pinned
// `golden_chain_hash_is_stable` vector. Deserialize accepting snake_case lets
// `serde_json::from_str::<SignalType>("\"catchall_probe\"")` succeed, matching every
// `sensor_wire::SIGNAL_*` constant.
#[serde(rename_all(deserialize = "snake_case"))]
pub enum SignalType {
    HoneypotConnection,
    HoneypotLoginAttempt,
    HoneypotCommandExec,
    HoneypotMalwareUpload,
    HoneypotFileDownload,
    SuricataSev1,
    SuricataSev2,
    SuricataSev3,
    PortScan,
    SynFlood,
    BlockedConnection,
    WafSqliXss,
    WafGenericBlock,
    SshBruteForce,
    CatchallProbe,
    RemoteAuthFailure,
}
impl SignalType {
    pub const ALL: [SignalType; 16] = [
        SignalType::HoneypotConnection,
        SignalType::HoneypotLoginAttempt,
        SignalType::HoneypotCommandExec,
        SignalType::HoneypotMalwareUpload,
        SignalType::HoneypotFileDownload,
        SignalType::SuricataSev1,
        SignalType::SuricataSev2,
        SignalType::SuricataSev3,
        SignalType::PortScan,
        SignalType::SynFlood,
        SignalType::BlockedConnection,
        SignalType::WafSqliXss,
        SignalType::WafGenericBlock,
        SignalType::SshBruteForce,
        SignalType::CatchallProbe,
        SignalType::RemoteAuthFailure,
    ];
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "review_state_enum", rename_all = "lowercase")]
pub enum ReviewState {
    Pending,
    Approved,
    Rejected,
    Snoozed,
}

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
        for s in SignalType::ALL {
            assert!(seen.insert(s), "duplicate {s:?}");
        }
    }
    #[test]
    fn confirmed_real_predicate_only_tcp_auth_honeypot() {
        assert!(is_confirmed_real(Protocol::Tcp, true, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Udp, true, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Tcp, false, Category::Honeypot));
        assert!(!is_confirmed_real(Protocol::Tcp, true, Category::Ids));
    }

    // The four tests below guard the asymmetric `rename_all(deserialize = "...")` attributes
    // added above so `sensor-catchall` (and later intake) can deserialize a `sensor-wire` NDJSON
    // record's `signal_type`/`protocol` strings directly into these enums. Expected strings are
    // hand-written literals, not derived from the enums' own `rename_all` logic under test, so a
    // broken transform cannot pass by agreeing with itself (see `hashing.rs`'s `canonical_bytes`,
    // which is the reason Serialize could not simply be flipped to match).

    #[test]
    fn signal_type_deserializes_from_every_snake_case_wire_string() {
        let cases: [(&str, SignalType); 16] = [
            ("honeypot_connection", SignalType::HoneypotConnection),
            ("honeypot_login_attempt", SignalType::HoneypotLoginAttempt),
            ("honeypot_command_exec", SignalType::HoneypotCommandExec),
            ("honeypot_malware_upload", SignalType::HoneypotMalwareUpload),
            ("honeypot_file_download", SignalType::HoneypotFileDownload),
            ("suricata_sev1", SignalType::SuricataSev1),
            ("suricata_sev2", SignalType::SuricataSev2),
            ("suricata_sev3", SignalType::SuricataSev3),
            ("port_scan", SignalType::PortScan),
            ("syn_flood", SignalType::SynFlood),
            ("blocked_connection", SignalType::BlockedConnection),
            ("waf_sqli_xss", SignalType::WafSqliXss),
            ("waf_generic_block", SignalType::WafGenericBlock),
            ("ssh_brute_force", SignalType::SshBruteForce),
            ("catchall_probe", SignalType::CatchallProbe),
            ("remote_auth_failure", SignalType::RemoteAuthFailure),
        ];
        for (wire_str, expected) in cases {
            let quoted = format!("\"{wire_str}\"");
            let parsed: SignalType = serde_json::from_str(&quoted)
                .unwrap_or_else(|e| panic!("{wire_str:?} must deserialize: {e}"));
            assert_eq!(parsed, expected, "wire string {wire_str:?}");
        }
    }

    #[test]
    fn signal_type_serialize_is_unchanged_bare_rust_identifier() {
        // Locks in the frozen `hashing.rs::canonical_bytes` encoding going forward: Serialize
        // must keep emitting the exact pre-existing casing, never the deserialize-side
        // `snake_case`, or every future chain hash silently diverges from already-computed ones.
        assert_eq!(
            serde_json::to_string(&SignalType::CatchallProbe).unwrap(),
            "\"CatchallProbe\""
        );
        assert_eq!(
            serde_json::to_string(&SignalType::HoneypotCommandExec).unwrap(),
            "\"HoneypotCommandExec\""
        );
    }

    #[test]
    fn protocol_deserializes_from_lowercase_wire_string() {
        let cases = [
            ("tcp", Protocol::Tcp),
            ("udp", Protocol::Udp),
            ("icmp", Protocol::Icmp),
        ];
        for (wire_str, expected) in cases {
            let quoted = format!("\"{wire_str}\"");
            let parsed: Protocol = serde_json::from_str(&quoted)
                .unwrap_or_else(|e| panic!("{wire_str:?} must deserialize: {e}"));
            assert_eq!(parsed, expected, "wire string {wire_str:?}");
        }
    }

    #[test]
    fn protocol_serialize_is_unchanged_bare_rust_identifier() {
        // Same frozen-encoding rationale as `signal_type_serialize_is_unchanged...` above.
        assert_eq!(serde_json::to_string(&Protocol::Tcp).unwrap(), "\"Tcp\"");
        assert_eq!(serde_json::to_string(&Protocol::Udp).unwrap(), "\"Udp\"");
    }
}
