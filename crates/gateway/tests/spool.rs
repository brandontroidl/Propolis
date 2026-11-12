//! Integration tests for `spool::SpoolWriter`: appending accepted records must reconstitute
//! byte-exact sensor NDJSON, one collector's spool must stay isolated from another's, and an
//! unsafe collector id must be rejected before any filesystem access - mirroring the fail-closed
//! discipline `state.rs` already enforces for `<dir>/<collector_id>.json`.

use gateway::SpoolWrite;
use gateway::spool::SpoolWriter;

#[test]
fn writes_two_records_as_byte_exact_ndjson_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let writer = SpoolWriter::new(dir.path().to_path_buf());

    let records = vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()];
    writer.write_records("c1", &records).expect("write");

    let content = std::fs::read(dir.path().join("c1").join("events.jsonl")).expect("read spool");
    let mut lines: Vec<&[u8]> = content.split(|&b| b == b'\n').collect();
    // A file ending in a newline splits into a trailing empty slice; drop it.
    assert_eq!(lines.pop(), Some(&b""[..]));
    assert_eq!(lines, vec![records[0].as_slice(), records[1].as_slice()]);
}

#[test]
fn different_collectors_land_in_separate_spool_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let writer = SpoolWriter::new(dir.path().to_path_buf());

    writer
        .write_records("c1", &[b"{\"a\":1}".to_vec()])
        .expect("write c1");
    writer
        .write_records("c2", &[b"{\"b\":2}".to_vec()])
        .expect("write c2");

    let c1 = std::fs::read(dir.path().join("c1").join("events.jsonl")).expect("read c1");
    let c2 = std::fs::read(dir.path().join("c2").join("events.jsonl")).expect("read c2");
    assert_eq!(c1, b"{\"a\":1}\n");
    assert_eq!(c2, b"{\"b\":2}\n");
}

#[test]
fn successive_writes_append_rather_than_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let writer = SpoolWriter::new(dir.path().to_path_buf());

    writer
        .write_records("c1", &[b"{\"a\":1}".to_vec()])
        .expect("first write");
    writer
        .write_records("c1", &[b"{\"b\":2}".to_vec()])
        .expect("second write");

    let content = std::fs::read(dir.path().join("c1").join("events.jsonl")).expect("read");
    assert_eq!(content, b"{\"a\":1}\n{\"b\":2}\n");
}

#[test]
fn an_unsafe_collector_id_is_rejected_and_creates_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let writer = SpoolWriter::new(dir.path().to_path_buf());

    for bad_id in ["../evil", "a/b", "..", ".", "c1\u{0000}bad", "", "a\\b"] {
        let result = writer.write_records(bad_id, &[b"{\"x\":1}".to_vec()]);
        assert!(result.is_err(), "id: {bad_id:?}");
    }

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .collect();
    assert!(
        entries.is_empty(),
        "an unsafe collector id must not create any directory or file"
    );
}
