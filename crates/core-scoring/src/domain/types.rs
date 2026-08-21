use std::net::IpAddr;

use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;

use crate::domain::enums::{Category, FeedTier, Protocol, SignalType};
use crate::domain::weights::signal_weight;

#[derive(Debug, Clone, PartialEq)]
pub struct EventInput {
    pub source_ip: IpAddr,
    pub wan_ip: Option<IpAddr>,
    pub sensor: String,
    pub signal_type: SignalType,
    pub protocol: Protocol,
    pub authenticated: bool,
    pub category: Category,
    pub weight: u32,
    pub confidence: Decimal,
    pub observed_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
    pub session_id: Option<uuid::Uuid>,
}

impl EventInput {
    /// Builds an `EventInput`, deriving `weight`/`confidence`/`category` from the
    /// signal weight table so a caller cannot desync them from `signal_type`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_signal(
        source_ip: IpAddr,
        wan_ip: Option<IpAddr>,
        sensor: String,
        signal_type: SignalType,
        protocol: Protocol,
        authenticated: bool,
        observed_at: DateTime<Utc>,
        metadata: serde_json::Value,
        session_id: Option<uuid::Uuid>,
    ) -> Self {
        let w = signal_weight(signal_type);
        EventInput {
            source_ip,
            wan_ip,
            sensor,
            signal_type,
            protocol,
            authenticated,
            category: w.category,
            weight: w.weight,
            confidence: w.confidence,
            observed_at,
            metadata,
            session_id,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.confidence < Decimal::ZERO || self.confidence > Decimal::ONE {
            return Err(ValidationError::ConfidenceOutOfRange);
        }
        if self.sensor.is_empty() {
            return Err(ValidationError::SensorEmpty);
        }
        // The signal weight table is the single source of truth for category/weight/confidence
        // per signal_type. Enforce that coupling at the write gate so a caller that builds
        // EventInput directly (bypassing from_signal) cannot desync a non-honeypot signal into
        // category=Honeypot to forge the confirmed-real latch (is_confirmed_real gates on
        // category), nor set an out-of-table weight that would corrupt the ledger. Decimal
        // equality is by value, so a scale variant of the same confidence (0.95 vs 0.950) passes.
        let w = signal_weight(self.signal_type);
        if self.category != w.category || self.weight != w.weight || self.confidence != w.confidence
        {
            return Err(ValidationError::SignalTypeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    ConfidenceOutOfRange,
    SensorEmpty,
    /// `category`/`weight`/`confidence` do not match `signal_weight(signal_type)` - a desynced
    /// event that could forge the confirmed-real latch or corrupt the ledger weight.
    SignalTypeMismatch,
}

/// Read model mirroring the `ip_score` table columns.
#[derive(Debug, Clone, PartialEq)]
pub struct IpScore {
    pub source_ip: IpAddr,
    pub raw_score: Decimal,
    pub decay_anchor: DateTime<Utc>,
    pub max_confidence: Decimal,
    pub event_count: i32,
    pub distinct_categories: i32,
    pub category_breakdown: serde_json::Value,
    pub has_confirmed_real: bool,
    pub distinct_wan_count: i32,
    pub distinct_sensor_count: i32,
    /// Unbounded, non-decaying count of distinct calendar days this address was seen. Drives the
    /// persistence bonus (`scoring::persistence`); folded in `engine::apply_event`.
    pub active_days: i32,
    /// The most recent calendar day (UTC) counted into `active_days`, so the next event knows
    /// whether it opens a new active day. Bookkeeping for the counter, not itself a score input.
    pub last_active_day: NaiveDate,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub eligible: bool,
    pub recommended_for_vendor: bool,
    pub recommended_for_blocklist: bool,
    pub tier: Option<FeedTier>,
    pub delisted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::enums::{Category, Protocol, SignalType};
    use rust_decimal_macros::dec;

    fn sample_event() -> EventInput {
        EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z".parse().unwrap(),
            serde_json::json!({}),
            None,
        )
    }

    #[test]
    fn from_signal_fills_weight_confidence_category_from_table() {
        let e = EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::HoneypotCommandExec,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z".parse().unwrap(),
            serde_json::json!({}),
            None,
        );
        assert_eq!(e.weight, 60);
        assert_eq!(e.confidence, dec!(0.950));
        assert_eq!(e.category, Category::Honeypot);
        assert!(e.validate().is_ok());
    }

    #[test]
    fn validate_rejects_out_of_range_confidence() {
        let mut e = sample_event();
        e.confidence = dec!(1.5);
        assert!(matches!(
            e.validate(),
            Err(ValidationError::ConfidenceOutOfRange)
        ));
    }

    #[test]
    fn validate_rejects_empty_sensor() {
        let mut e = sample_event();
        e.sensor = String::new();
        assert!(matches!(e.validate(), Err(ValidationError::SensorEmpty)));
    }

    #[test]
    fn validate_blocks_confirmed_real_forge_via_signal_type_desync() {
        // A SuricataSev3 (category Ids, weight 5, conf 0.300) relabeled as an authenticated
        // Honeypot handshake must be rejected: is_confirmed_real gates on category, so this
        // desync would otherwise forge has_confirmed_real from a non-honeypot signal.
        let mut forged = EventInput::from_signal(
            "203.0.113.7".parse().unwrap(),
            None,
            "sensor-a".into(),
            SignalType::SuricataSev3,
            Protocol::Tcp,
            true,
            "2026-07-17T00:00:00Z".parse().unwrap(),
            serde_json::json!({}),
            None,
        );
        forged.category = Category::Honeypot;
        forged.weight = 80;
        forged.confidence = dec!(0.98);
        assert!(matches!(
            forged.validate(),
            Err(ValidationError::SignalTypeMismatch)
        ));
    }

    #[test]
    fn validate_accepts_scale_variant_confidence_equal_by_value() {
        // 0.95 (scale 2) is value-equal to the table's 0.950 (scale 3): must not be rejected.
        let mut e = sample_event();
        e.confidence = dec!(0.95);
        assert!(e.validate().is_ok());
    }
}
