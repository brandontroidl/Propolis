//! The one parser for the `name:path,name:path` sensor-log list: `PROPOLIS_SENSOR_LOGS` on the
//! daemon, intake and the watcher, `SENSOR_LOGS` on the shipper. It lives here because every
//! reader of that list already depends on this crate, and it replaces three hand-kept copies of
//! the same grammar; each caller maps [`SensorLogsError`] into its own config
//! error so its messages still name the variable it read.

use std::fmt;
use std::path::PathBuf;

/// One entry of the list: a sensor's label and the path to its NDJSON event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensorLogConfig {
    pub name: String,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SensorLogsError {
    /// The list was empty or held only blank entries. At least one sensor is required: an empty
    /// list leaves every reader with nothing to do, which is a misconfiguration, not an idle state.
    Empty,
    /// An entry was not `name:path` with both sides non-empty. Carries the offending entry.
    InvalidEntry(String),
}

impl fmt::Display for SensorLogsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "at least one name:path entry is required"),
            Self::InvalidEntry(entry) => write!(f, "invalid entry {entry:?}, expected name:path"),
        }
    }
}

impl std::error::Error for SensorLogsError {}

/// Parses comma-separated `name:path` entries, trimming whitespace around each and skipping
/// blank ones. Splits each entry on the FIRST colon only: a label never contains one, but a log
/// path legally can.
pub fn parse_sensor_logs(raw: &str) -> Result<Vec<SensorLogConfig>, SensorLogsError> {
    let logs: Vec<SensorLogConfig> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| match entry.split_once(':') {
            Some((name, path)) if !name.is_empty() && !path.is_empty() => Ok(SensorLogConfig {
                name: name.to_string(),
                log_path: PathBuf::from(path),
            }),
            _ => Err(SensorLogsError::InvalidEntry(entry.to_string())),
        })
        .collect::<Result<_, _>>()?;
    if logs.is_empty() {
        return Err(SensorLogsError::Empty);
    }
    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, path: &str) -> SensorLogConfig {
        SensorLogConfig {
            name: name.to_string(),
            log_path: PathBuf::from(path),
        }
    }

    #[test]
    fn parses_pairs_in_order_and_trims_around_entries() {
        assert_eq!(
            parse_sensor_logs(" catchall:/var/log/a.jsonl , ssh:/var/log/b.jsonl ,").unwrap(),
            vec![
                entry("catchall", "/var/log/a.jsonl"),
                entry("ssh", "/var/log/b.jsonl")
            ]
        );
    }

    #[test]
    fn splits_on_the_first_colon_only() {
        assert_eq!(
            parse_sensor_logs("weird:/var/log/a:b.jsonl").unwrap(),
            vec![entry("weird", "/var/log/a:b.jsonl")]
        );
    }

    #[test]
    fn rejects_an_empty_list_and_malformed_entries() {
        assert_eq!(parse_sensor_logs(""), Err(SensorLogsError::Empty));
        assert_eq!(parse_sensor_logs(" , "), Err(SensorLogsError::Empty));
        for bad in ["not-a-pair", ":/var/log/x.jsonl", "ssh:"] {
            assert_eq!(
                parse_sensor_logs(&format!("ok:/a,{bad}")),
                Err(SensorLogsError::InvalidEntry(bad.to_string())),
                "{bad}"
            );
        }
    }
}
