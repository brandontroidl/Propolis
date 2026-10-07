//! Reading the derived `watch.env`: only the one key, the last assignment, nothing else.

use std::path::Path;

use watch::config::{SENSOR_LOGS_KEY, sensor_logs_from_file};

fn read(content: &str) -> Result<String, String> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("watch.env");
    std::fs::write(&path, content).unwrap();
    sensor_logs_from_file(&path).map(|s| {
        assert_eq!(s.from, path.display().to_string());
        s.raw
    })
}

#[test]
fn the_file_written_by_watch_env_sh_reads_back() {
    assert_eq!(
        read("PROPOLIS_SENSOR_LOGS=ssh:/var/log/propolis/ssh/events.jsonl\n").unwrap(),
        "ssh:/var/log/propolis/ssh/events.jsonl"
    );
}

#[test]
fn only_the_sensor_logs_key_is_taken_and_the_last_assignment_wins() {
    let content = "DATABASE_URL=postgres://u:EXAMPLE@h/db\n\
                   # PROPOLIS_SENSOR_LOGS=commented:/x\n\
                   PROPOLIS_SENSOR_LOGS=first:/a\n\
                   PROPOLIS_CONSOLE_PASSWORD=EXAMPLE\n\
                   PROPOLIS_SENSOR_LOGS_EXTRA=nope:/z\n\
                   PROPOLIS_SENSOR_LOGS=second:/b\n";
    assert_eq!(read(content).unwrap(), "second:/b");
}

#[test]
fn one_layer_of_matching_quotes_is_removed() {
    assert_eq!(read("PROPOLIS_SENSOR_LOGS=\"a:/x\"\n").unwrap(), "a:/x");
    assert_eq!(read("PROPOLIS_SENSOR_LOGS='a:/x'\n").unwrap(), "a:/x");
    assert_eq!(read("PROPOLIS_SENSOR_LOGS=\"a:/x'\n").unwrap(), "\"a:/x'");
}

#[test]
fn a_file_without_the_key_a_missing_file_and_an_oversized_file_are_errors() {
    let err = read("DATABASE_URL=postgres://u:EXAMPLE@h/db\n").unwrap_err();
    assert!(err.contains(SENSOR_LOGS_KEY), "{err}");
    assert!(
        !err.contains("EXAMPLE"),
        "an error must not echo other keys: {err}"
    );
    assert!(sensor_logs_from_file(Path::new("/nonexistent/watch.env")).is_err());
    assert!(read(&"#".repeat(70 * 1024)).is_err());
}
