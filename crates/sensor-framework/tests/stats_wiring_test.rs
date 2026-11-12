//! Every sensor binary that drains a capture hand-off at shutdown also starts its `sensor_stats`
//! line, under its own name. The set is derived from the source tree, not from a list someone
//! keeps: a new capturing sensor that forgets `start_stats` fails here, and so does a rename that
//! leaves the name behind. The name must equal the crate's label because intake refuses a stats
//! line whose sensor differs from the log's label.

use std::path::Path;

#[test]
fn every_sensor_that_drains_a_hand_off_starts_stats_under_its_own_name() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut capturing = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap().flatten() {
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        let Some(label) = dir_name.strip_prefix("sensor-") else {
            continue;
        };
        let main = entry.path().join("src/main.rs");
        let Ok(source) = std::fs::read_to_string(&main) else {
            continue;
        };
        if !source.contains("handoff.drain(") {
            continue;
        }
        capturing.push(label.to_string());
        assert!(
            source.contains(&format!("handoff.start_stats(\"{label}\")")),
            "{dir_name}/src/main.rs drains a capture hand-off but never calls \
             `handoff.start_stats(\"{label}\")`, so its counters never reach the console"
        );
    }
    capturing.sort();
    assert_eq!(
        capturing,
        ["adb", "ftp", "mqtt", "ssh", "telnet", "tftp"],
        "the capturing sensors changed; update the docs that list them"
    );
}
