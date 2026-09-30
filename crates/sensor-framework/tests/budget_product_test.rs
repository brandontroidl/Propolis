//! The memory a sensor can be made to hold is the number of connections it admits times what one
//! connection may hold. This test multiplies the two for each shell-serving sensor and holds the
//! product under half the sensor's `MemoryMax`, so raising a budget limit or a concurrency default
//! without the memory to back it fails the build instead of the service.
//!
//! The per-connection figure is `ConnectionBudget::max_resident_bytes`: overlay content, overlay
//! nodes at their worst-case path length, and one input line. It EXCLUDES
//! `ConnectionBounds::max_captured_bytes`. Captured bytes are governed separately, by the bound the
//! sensor's own read loop applies, and this test does not multiply them by `max_concurrent`.
//! Whether to also hold capture-bytes x concurrency under `MemoryMax` is an open OWNER decision
//! (lower `DEFAULT_MAX_CAPTURED_BYTES`, lower `max_concurrent`, or raise `MemoryMax`) that the
//! budget change deliberately does not make: at the current defaults (1_000_000 captured bytes,
//! 256 concurrent) the capture term alone is about 244 MiB per sensor, against a 128 MiB half of
//! the 256M units.
//!
//! The concurrency defaults and the `MemoryMax` values are read from the sources that set them
//! (`crates/sensor-*/src/main.rs` and `deploy/sensor-*.service`), not restated here, so a change
//! to either is what this test sees.

use sensor_framework::budget::{BudgetLimits, ConnectionBudget};
use sensor_framework::{ConnectionBounds, limits_from};

const SENSORS: [&str; 3] = ["ssh", "telnet", "adb"];

fn workspace_file(relative: &str) -> String {
    let path = format!("{}/../../{relative}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// `DEFAULT_MAX_CONCURRENT: u32 = N;` from a sensor's `main.rs`.
fn default_max_concurrent(sensor: &str) -> u64 {
    let source = workspace_file(&format!("crates/sensor-{sensor}/src/main.rs"));
    let line = source
        .lines()
        .find(|l| l.contains("const DEFAULT_MAX_CONCURRENT: u32 ="))
        .unwrap_or_else(|| panic!("sensor-{sensor}: no DEFAULT_MAX_CONCURRENT"));
    parse_const_value(line)
}

fn parse_const_value(line: &str) -> u64 {
    let value = line.split('=').nth(1).expect("a const has a value");
    value
        .trim()
        .trim_end_matches(';')
        .replace('_', "")
        .parse()
        .unwrap_or_else(|e| panic!("{line}: {e}"))
}

/// `MemoryMax=512M` from a sensor's unit, in bytes.
fn memory_max_bytes(sensor: &str) -> u64 {
    let unit = workspace_file(&format!("deploy/sensor-{sensor}.service"));
    let value = unit
        .lines()
        .find_map(|l| l.strip_prefix("MemoryMax="))
        .unwrap_or_else(|| panic!("sensor-{sensor}: no MemoryMax"))
        .trim();
    parse_size(value)
}

fn parse_size(value: &str) -> u64 {
    let (digits, unit) = value.split_at(value.len() - 1);
    let n: u64 = digits.parse().unwrap_or_else(|e| panic!("{value}: {e}"));
    n * match unit {
        "K" => 1 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        other => panic!("MemoryMax unit {other:?} is not K, M or G"),
    }
}

/// The bounds a sensor runs with, for `limits_from`. Only `max_concurrent` is per sensor here.
fn bounds(max_concurrent: u64) -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: std::time::Duration::from_secs(30),
        idle_timeout: std::time::Duration::from_secs(30),
        max_duration: std::time::Duration::from_secs(600),
        max_captured_bytes: 1_000_000,
        max_concurrent: u32::try_from(max_concurrent).expect("a u32 default"),
    }
}

#[test]
fn per_connection_budget_times_concurrency_stays_under_half_memorymax() {
    for sensor in SENSORS {
        let max_concurrent = default_max_concurrent(sensor);
        let memory_max = memory_max_bytes(sensor);
        let budget = ConnectionBudget::new(limits_from(&bounds(max_concurrent)));
        let per_connection = budget.max_resident_bytes();
        let product = max_concurrent * per_connection;
        assert!(
            product < memory_max / 2,
            "sensor-{sensor}: {max_concurrent} connections x {per_connection} resident bytes = \
             {product} bytes, not under half of MemoryMax ({} of {memory_max})",
            memory_max / 2
        );
    }
}

#[test]
fn the_product_inputs_are_read_from_the_real_sources() {
    assert_eq!(parse_size("512M"), 536_870_912);
    assert_eq!(parse_size("256M"), 268_435_456);
    for sensor in SENSORS {
        assert_eq!(default_max_concurrent(sensor), 256, "sensor-{sensor}");
    }
    assert_eq!(memory_max_bytes("ssh"), 512 << 20);
    assert_eq!(memory_max_bytes("telnet"), 256 << 20);
    assert_eq!(memory_max_bytes("adb"), 256 << 20);
}

#[test]
fn the_limits_a_sensor_runs_with_are_the_standard_ones() {
    assert_eq!(limits_from(&bounds(256)), BudgetLimits::standard());
}
