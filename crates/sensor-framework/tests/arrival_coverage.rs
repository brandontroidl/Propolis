//! Coverage gate for the arrival stamp (`sensor_framework::arrival`): every sensor crate in the
//! workspace must carry a `tests/arrival.rs` that drives its real listeners and checks
//! `metadata.local_port` on what they emit. The per-sensor tests check the stamp is right; this
//! checks no sensor was left without one, so a sensor added later, or one that binds its own
//! socket the way `sensor-dns` and `sensor-tftp` do, cannot ship events the fleet pane can only
//! file under "port not recorded".

use std::path::Path;

/// Workspace members named `crates/sensor-*`, minus the two that are not sensors.
fn sensor_crates(workspace: &Path) -> Vec<String> {
    let manifest = std::fs::read_to_string(workspace.join("Cargo.toml")).unwrap();
    let members = manifest
        .split("members")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("the workspace manifest lists its members");
    members
        .split('"')
        .filter_map(|m| m.strip_prefix("crates/"))
        .filter(|c| c.starts_with("sensor-") && !["sensor-framework", "sensor-wire"].contains(c))
        .map(str::to_string)
        .collect()
}

#[test]
fn every_sensor_crate_tests_its_arrival_stamp() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sensors = sensor_crates(&workspace);
    // A parse that found nothing would pass vacuously; the workspace has twelve sensors today.
    assert!(sensors.len() >= 12, "found only {sensors:?}");
    let missing: Vec<&String> = sensors
        .iter()
        .filter(|s| {
            std::fs::read_to_string(workspace.join("crates").join(s).join("tests/arrival.rs"))
                .map(|text| !text.contains("local_port"))
                .unwrap_or(true)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "sensor crates with no tests/arrival.rs checking local_port: {missing:?}"
    );
}
