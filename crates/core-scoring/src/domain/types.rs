use std::net::IpAddr;

use chrono::{DateTime, Utc};
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
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.confidence < Decimal::ZERO || self.confidence > Decimal::ONE {
            return Err(ValidationError::ConfidenceOutOfRange);
        }
        if self.sensor.is_empty() {
            return Err(ValidationError::SensorEmpty);
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum ValidationError {
    ConfidenceOutOfRange,
    SensorEmpty,
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
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub eligible: bool,
    pub recommended_for_vendor: bool,
    pub recommended_for_blocklist: bool,
    pub tier: Option<FeedTier>,
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
}
