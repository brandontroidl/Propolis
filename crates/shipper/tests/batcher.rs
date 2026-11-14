use collector_wire::frame::{Batch, MAX_FRAME_LEN, MAX_RECORD_LEN, decode_frame, encode_frame};
use collector_wire::hash::ZERO_HASH;
use log_tailer::LogTailer;
use shipper::batcher::{Batcher, MAX_RECORDS_FRAME_SAFE};

/// The label of the log every test here reads, as `PROPOLIS_SHIPPER_SENSOR_LOGS` would name it.
const LOG: &str = "ssh";

#[test]
fn builds_the_first_batch_from_whole_tailed_lines_then_drains_to_none() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n").unwrap();
    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));

    let batch1 = Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, 100)
        .batch
        .expect("three whole lines are available");
    assert_eq!(batch1.seq, 1);
    assert_eq!(batch1.prev_batch_hash, ZERO_HASH);
    assert_eq!(batch1.records.len(), 3);
    assert_eq!(batch1.records[0], b"{\"a\":1}".to_vec());
    assert_eq!(batch1.records[1], b"{\"b\":2}".to_vec());
    assert_eq!(batch1.records[2], b"{\"c\":3}".to_vec());

    // The tailer is drained: a second call must return None, not an empty-records batch
    // (`Batch::new` panics on empty records, so `None` is the only sane empty signal).
    assert!(
        Batcher::next_batch(&mut tailer, LOG, batch1.seq, batch1.batch_hash, 100)
            .batch
            .is_none()
    );

    // A new line arrives; the next batch chains onto batch1's hash and increments seq.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    use std::io::Write;
    f.write_all(b"{\"d\":4}\n").unwrap();
    drop(f);

    let batch2 = Batcher::next_batch(&mut tailer, LOG, batch1.seq, batch1.batch_hash, 100)
        .batch
        .expect("one more whole line is available");
    assert_eq!(batch2.seq, 2);
    assert_eq!(batch2.prev_batch_hash, batch1.batch_hash);
    assert_eq!(batch2.records, vec![b"{\"d\":4}".to_vec()]);
}

#[test]
fn caps_the_batch_at_max_records() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "1\n2\n3\n4\n5\n").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    let batch = Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, 2)
        .batch
        .unwrap();
    assert_eq!(batch.records.len(), 2);
    assert_eq!(batch.records, vec![b"1".to_vec(), b"2".to_vec()]);

    let batch2 = Batcher::next_batch(&mut tailer, LOG, batch.seq, batch.batch_hash, 2)
        .batch
        .unwrap();
    assert_eq!(batch2.records, vec![b"3".to_vec(), b"4".to_vec()]);
}

#[test]
fn an_empty_log_yields_no_batch() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    std::fs::write(&log_path, "").unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    assert!(
        Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, 100)
            .batch
            .is_none()
    );
}

#[test]
fn default_max_records_is_the_frame_safe_ceiling() {
    // See the module doc on `shipper::batcher::DEFAULT_MAX_RECORDS` for the exact accounting;
    // this just pins the chosen constant so a future change is deliberate, not accidental.
    assert_eq!(shipper::batcher::DEFAULT_MAX_RECORDS, 15);
    assert_eq!(MAX_RECORDS_FRAME_SAFE, 15);
}

/// Proves the guarantee `MAX_RECORDS_FRAME_SAFE` claims, at the wire encoding, not just in
/// arithmetic: a batch of `MAX_RECORDS_FRAME_SAFE` records each at the true `MAX_RECORD_LEN`
/// ceiling (the worst case a compromised or malfunctioning collector could actually produce,
/// since `log-tailer` bounds every tailed line to exactly `MAX_RECORD_LEN`) must still encode to
/// no more than `MAX_FRAME_LEN` bytes, and must round-trip cleanly through `decode_frame`.
#[test]
fn a_worst_case_max_size_batch_still_encodes_within_the_frame_bound() {
    let records: Vec<Vec<u8>> = (0..MAX_RECORDS_FRAME_SAFE)
        .map(|_| vec![b'a'; MAX_RECORD_LEN as usize])
        .collect();
    let batch = Batch::new(1, ZERO_HASH, records);

    let bytes = encode_frame(&batch);
    assert!(
        bytes.len() <= MAX_FRAME_LEN,
        "encoded frame of {} bytes exceeds MAX_FRAME_LEN ({})",
        bytes.len(),
        MAX_FRAME_LEN
    );

    let decoded = decode_frame(&bytes).expect("a within-bound frame must decode cleanly");
    assert_eq!(decoded, batch);
}

/// F2 regression proof: `log_tailer` decodes a raw tailed line with `String::from_utf8_lossy`,
/// which can expand invalid UTF-8 up to 3x (each bad byte becomes a 3-byte U+FFFD). A raw line at
/// or under log-tailer's own MAX_LINE_BYTES cap (== MAX_RECORD_LEN) can therefore come back from
/// `read_batch` as a record OVER MAX_RECORD_LEN. `next_batch` must not let such a record into the
/// batch it builds (an oversized record makes an unshippable frame the gateway rejects, and
/// because a rejected cycle never advances the cursor, the shipper would otherwise re-read - and
/// re-skip-or-reject - the same pathological line forever, wedging the whole collector's serial
/// chain). This exercises the `tracing::warn!` drop path in `Batcher::next_batch` (not asserted
/// on directly, since there is no log-capture harness in this crate's dev-dependencies) and
/// proves its effect: the oversized record is silently dropped while the following normal record
/// still ships.
#[test]
fn an_over_length_lossy_expanded_record_is_dropped_and_does_not_block_the_next_record() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    // 400_000 raw bytes of 0xFF: each byte is individually invalid UTF-8, so
    // `String::from_utf8_lossy` replaces each with a 3-byte U+FFFD, expanding this single line to
    // 1_200_000 bytes - over MAX_RECORD_LEN (1_048_576) - while the RAW line (400_000 bytes) stays
    // safely under log-tailer's own MAX_LINE_BYTES cap so it is not itself truncated or discarded
    // before ever reaching the batcher.
    let mut content = vec![0xFFu8; 400_000];
    content.push(b'\n');
    content.extend_from_slice(b"{\"a\":1}\n");
    std::fs::write(&log_path, &content).unwrap();

    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));
    let batch = Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, 100)
        .batch
        .expect("the normal second line still yields a batch");

    assert_eq!(
        batch.records.len(),
        1,
        "the over-length lossy-expanded record must be dropped, not shipped"
    );
    assert_eq!(batch.records[0], b"{\"a\":1}".to_vec());

    // Both raw lines were consumed from the tailer (the oversized one dropped, not left
    // unconsumed to be re-read forever) - a third call finds nothing left.
    assert!(
        Batcher::next_batch(&mut tailer, LOG, batch.seq, batch.batch_hash, 100)
            .batch
            .is_none()
    );
}

/// When EVERY line a read produces is over-length, `next_batch` must return `None` (not build a
/// zero-record batch, which `Batch::new` cannot represent) rather than stalling: the cursor still
/// advances past the dropped line so a later poll is not stuck re-reading it.
#[test]
fn a_read_where_every_line_is_over_length_yields_none_not_a_stall() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");

    let mut content = vec![0xFFu8; 400_000];
    content.push(b'\n');
    std::fs::write(&log_path, &content).unwrap();

    let mut tailer = LogTailer::new(log_path.clone(), dir.path().join("cursors"));
    assert!(
        Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, 100)
            .batch
            .is_none(),
        "a read producing only over-length records must yield None, not panic or an empty batch"
    );

    // The dropped line's bytes were still consumed (read_batch advanced the in-memory cursor),
    // so appending a normal line and reading again must return only the new line, proving the
    // tailer did not stall re-reading the same oversized line.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    use std::io::Write;
    f.write_all(b"{\"b\":2}\n").unwrap();
    drop(f);

    let batch = Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, 100)
        .batch
        .expect("the newly appended normal line yields a batch");
    assert_eq!(batch.records, vec![b"{\"b\":2}".to_vec()]);
}

/// Even when the caller asks for more than the frame-safe ceiling (e.g. the shipper config's
/// own default of 16, or any other larger value), `next_batch` must never hand back more than
/// `MAX_RECORDS_FRAME_SAFE` records - and must clamp at the tailer READ, not merely truncate the
/// result, so the untaken lines stay unread rather than being silently lost from the cursor.
#[test]
fn next_batch_never_exceeds_the_frame_safe_ceiling_even_when_asked_for_more() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let line_count = MAX_RECORDS_FRAME_SAFE + 5;
    let content: String = (0..line_count).map(|i| format!("{i}\n")).collect();
    std::fs::write(&log_path, content).unwrap();
    let mut tailer = LogTailer::new(log_path, dir.path().join("cursors"));

    let requested = MAX_RECORDS_FRAME_SAFE + 50; // deliberately far over the ceiling
    let batch = Batcher::next_batch(&mut tailer, LOG, 0, ZERO_HASH, requested)
        .batch
        .expect("lines are available");
    assert_eq!(batch.records.len(), MAX_RECORDS_FRAME_SAFE);
    for (i, record) in batch.records.iter().enumerate() {
        assert_eq!(record, &i.to_string().into_bytes());
    }

    // The 5 lines beyond the ceiling were never read (clamped at the tailer read, not dropped
    // after), so they are still there for the next batch.
    let batch2 = Batcher::next_batch(&mut tailer, LOG, batch.seq, batch.batch_hash, requested)
        .batch
        .expect("the remaining 5 lines are available");
    assert_eq!(batch2.records.len(), 5);
    for (i, record) in batch2.records.iter().enumerate() {
        assert_eq!(
            record,
            &(MAX_RECORDS_FRAME_SAFE + i).to_string().into_bytes()
        );
    }
}

fn event(sensor: &str, signal_type: &str, source_ip: &str) -> sensor_wire::SensorEvent {
    sensor_wire::SensorEvent {
        v: sensor_wire::WIRE_VERSION,
        source_ip: source_ip.parse().unwrap(),
        wan_ip: None,
        sensor: sensor.into(),
        signal_type: signal_type.into(),
        protocol: sensor_wire::PROTO_TCP.into(),
        authenticated: false,
        observed_at: "2026-11-13T10:00:00Z".parse().unwrap(),
        metadata: serde_json::json!({ "protocol_label": sensor }),
        sample: None,
        session_id: None,
        occurrence_id: None,
        reply: None,
    }
}

/// Writes `lines` as a log and returns a tailer at its start.
fn log_of(dir: &std::path::Path, lines: &[String]) -> LogTailer {
    std::fs::create_dir_all(dir).unwrap();
    let log_path = dir.join("events.jsonl");
    let content: String = lines.iter().map(|line| format!("{line}\n")).collect();
    std::fs::write(&log_path, content).unwrap();
    LogTailer::new(log_path, dir.join("cursors"))
}

fn json(event: &sensor_wire::SensorEvent) -> String {
    serde_json::to_string(event).unwrap()
}

/// The shipper is the last place a collector's logs are still one per sensor: the gateway spools
/// them all into one stream. A line in the catchall log that claims to be ssh's authenticated
/// upload, or that claims more than catchall can observe, must not leave the collector, and the
/// honest lines around it must.
#[test]
fn a_line_the_origin_policy_refuses_for_its_log_is_not_shipped_and_the_rest_of_the_batch_is() {
    use sensor_wire::{SIGNAL_CATCHALL_PROBE, SIGNAL_HONEYPOT_MALWARE_UPLOAD};
    let dir = tempfile::tempdir().unwrap();
    let honest = json(&event("catchall", SIGNAL_CATCHALL_PROBE, "203.0.113.55"));
    let mut forged = event("ssh", SIGNAL_HONEYPOT_MALWARE_UPLOAD, "203.0.113.80");
    forged.authenticated = true;
    let mut authenticated = event("catchall", SIGNAL_CATCHALL_PROBE, "203.0.113.80");
    authenticated.authenticated = true;
    let upload = event("catchall", SIGNAL_HONEYPOT_MALWARE_UPLOAD, "203.0.113.80");
    let mut summary = event("catchall", SIGNAL_CATCHALL_PROBE, "203.0.113.80");
    summary.metadata["event_summary"] = true.into();
    let unknown = event("backdoor", SIGNAL_CATCHALL_PROBE, "203.0.113.80");
    let last = json(&event("catchall", SIGNAL_CATCHALL_PROBE, "203.0.113.56"));
    let mut tailer = log_of(
        dir.path(),
        &[
            honest.clone(),
            json(&forged),
            json(&authenticated),
            json(&upload),
            json(&summary),
            json(&unknown),
            last.clone(),
        ],
    );

    let next = Batcher::next_batch(&mut tailer, "catchall", 0, ZERO_HASH, 100);
    assert_eq!(next.refused, 5);
    let batch = next.batch.expect("the honest lines still make a batch");
    assert_eq!(
        batch.records,
        vec![honest.into_bytes(), last.into_bytes()],
        "exactly the honest lines, byte for byte and in order"
    );
    assert_eq!(batch.seq, 1);

    // The refused lines were consumed with the rest: nothing is left to read or to re-ship.
    let after = Batcher::next_batch(&mut tailer, "catchall", batch.seq, batch.batch_hash, 100);
    assert_eq!((after.batch, after.refused), (None, 0));
}

/// The same lines are evidence when they come from the log of the sensor that writes them, and
/// a log that is not bound to a sensor (a label the shipped configuration does not use) carries
/// any known sensor's lines.
#[test]
fn the_policy_is_applied_for_the_label_of_the_log_the_line_was_read_from() {
    use sensor_wire::{SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_MALWARE_UPLOAD};
    let mut upload = event("ssh", SIGNAL_HONEYPOT_MALWARE_UPLOAD, "203.0.113.80");
    upload.authenticated = true;
    let lines = [
        json(&upload),
        json(&event("vnc", SIGNAL_HONEYPOT_CONNECTION, "203.0.113.81")),
    ];
    for (label, shipped, refused) in [
        ("ssh", vec![&lines[0]], 1),
        ("cred-vnc", vec![&lines[1]], 1),
        ("telnet", vec![], 2),
        ("my-sensors", vec![&lines[0], &lines[1]], 0),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = log_of(dir.path(), &lines);
        let next = Batcher::next_batch(&mut tailer, label, 0, ZERO_HASH, 100);
        assert_eq!(next.refused, refused, "{label}");
        let records = next.batch.map(|batch| batch.records).unwrap_or_default();
        let expected: Vec<Vec<u8>> = shipped.iter().map(|l| l.as_bytes().to_vec()).collect();
        assert_eq!(records, expected, "{label}");
    }
}

/// When the policy refuses every line of a read there is no batch to build, the count is still
/// reported, and the tailer has moved on: the next read returns what follows.
#[test]
fn a_read_where_every_line_is_refused_yields_no_batch_and_reports_the_count() {
    use sensor_wire::{SIGNAL_CATCHALL_PROBE, SIGNAL_HONEYPOT_LOGIN_ATTEMPT};
    let dir = tempfile::tempdir().unwrap();
    let forged = json(&event("ssh", SIGNAL_HONEYPOT_LOGIN_ATTEMPT, "203.0.113.80"));
    let mut tailer = log_of(dir.path(), &[forged.clone(), forged.clone(), forged]);

    let next = Batcher::next_batch(&mut tailer, "catchall", 0, ZERO_HASH, 100);
    assert_eq!((next.batch, next.refused), (None, 3));

    let honest = json(&event("catchall", SIGNAL_CATCHALL_PROBE, "203.0.113.55"));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.path().join("events.jsonl"))
        .unwrap();
    use std::io::Write;
    writeln!(f, "{honest}").unwrap();
    drop(f);
    let next = Batcher::next_batch(&mut tailer, "catchall", 0, ZERO_HASH, 100);
    assert_eq!(next.refused, 0);
    assert_eq!(next.batch.unwrap().records, vec![honest.into_bytes()]);
}

/// The shipper judges only what it can read as a sensor event. A line that does not parse is
/// shipped exactly as it is: the control plane rejects and counts it, and dropping it here would
/// hide a malfunctioning sensor from that count.
#[test]
fn a_line_that_does_not_parse_as_a_sensor_event_is_shipped_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let lines = [
        "not json at all".to_string(),
        "{\"v\":1,\"source_ip\":\"203.0.113.80\",\"sensor\":\"ssh\"".to_string(),
        "{\"sensor\":\"ssh\",\"signal_type\":\"honeypot_malware_upload\"}".to_string(),
        "[]".to_string(),
    ];
    let mut tailer = log_of(dir.path(), &lines);
    let next = Batcher::next_batch(&mut tailer, "catchall", 0, ZERO_HASH, 100);
    assert_eq!(next.refused, 0);
    let expected: Vec<Vec<u8>> = lines.iter().map(|l| l.as_bytes().to_vec()).collect();
    assert_eq!(next.batch.unwrap().records, expected);
}

fn stats_line(sensor: &str) -> String {
    let stats = sensor_wire::SensorStats {
        sensor: sensor.into(),
        uptime_secs: 61,
        is_final: false,
        dropped: 0,
        spool_refused: 0,
        truncated: 0,
        refused: 0,
        budget_current: 0,
        budget_high_water: 0,
        budget_refused: 0,
    };
    json(&stats.to_event("2026-11-13T10:00:00Z".parse().unwrap()))
}

/// A sensor's own stats line, in the log bound to that sensor, is shipped byte for byte: the
/// control plane stores it for this collector and that sensor.
#[test]
fn a_bound_logs_own_sensor_stats_line_is_shipped_unchanged() {
    for (label, sensor) in [("ssh", "ssh"), ("cred-pg", "postgresql")] {
        let dir = tempfile::tempdir().unwrap();
        let line = stats_line(sensor);
        let mut tailer = log_of(dir.path(), std::slice::from_ref(&line));
        let next = Batcher::next_batch(&mut tailer, label, 0, ZERO_HASH, 100);
        assert_eq!(next.refused, 0, "{label}");
        assert_eq!(
            next.batch.unwrap().records,
            vec![line.into_bytes()],
            "{label}"
        );
    }
}

/// The gateway spools every log of a collector into one stream and the control plane reads that
/// stream under one unbound label, so past this point a stats line naming ssh is ssh's row
/// whichever log it came from. A telnet log that writes ssh's counters is refused here, counted
/// like any other refused line, and read past, so the honest line after it still ships.
#[test]
fn a_sensor_stats_line_naming_a_sibling_sensor_is_refused_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let honest = stats_line("telnet");
    let mut tailer = log_of(dir.path(), &[stats_line("ssh"), honest.clone()]);

    let next = Batcher::next_batch(&mut tailer, "telnet", 0, ZERO_HASH, 100);
    assert_eq!(next.refused, 1);
    assert_eq!(next.batch.unwrap().records, vec![honest.into_bytes()]);

    let dir = tempfile::tempdir().unwrap();
    let mut tailer = log_of(dir.path(), &[stats_line("ssh")]);
    let next = Batcher::next_batch(&mut tailer, "telnet", 0, ZERO_HASH, 100);
    assert_eq!((next.batch, next.refused), (None, 1));
    let after = Batcher::next_batch(&mut tailer, "telnet", 0, ZERO_HASH, 100);
    assert_eq!(
        (after.batch, after.refused),
        (None, 0),
        "read past, not re-read"
    );
}

/// A stats line naming a sensor no shipped sensor writes would make the control plane refuse it
/// anyway; it is refused here from every log, bound or not.
#[test]
fn a_sensor_stats_line_naming_an_unknown_sensor_is_refused_from_every_log() {
    for label in ["ssh", "collector-01", "my-sensors"] {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = log_of(dir.path(), &[stats_line("nosuchsensor")]);
        let next = Batcher::next_batch(&mut tailer, label, 0, ZERO_HASH, 100);
        assert_eq!((next.batch, next.refused), (None, 1), "{label}");
    }
}

/// A stats line that is not a well-formed stats line (here, from a real source address instead
/// of the sentinel) cannot be checked against the log's sensor, and is refused.
#[test]
fn a_malformed_sensor_stats_line_is_refused() {
    let mut event: sensor_wire::SensorEvent = serde_json::from_str(&stats_line("ssh")).unwrap();
    event.source_ip = "203.0.113.80".parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut tailer = log_of(dir.path(), &[json(&event)]);
    let next = Batcher::next_batch(&mut tailer, "ssh", 0, ZERO_HASH, 100);
    assert_eq!((next.batch, next.refused), (None, 1));
}

/// The shipper accepts a log label that is bound to no sensor (one the shipped configuration
/// does not use). Such a log is not one sensor's, so, as for evidence lines, it may carry the
/// stats of any known sensor.
#[test]
fn an_unbound_logs_stats_lines_for_every_known_sensor_are_shipped() {
    let lines: Vec<String> = sensor_wire::origin::SENSORS
        .iter()
        .map(|row| stats_line(row.sensor))
        .collect();
    let dir = tempfile::tempdir().unwrap();
    let mut tailer = log_of(dir.path(), &lines);
    let mut shipped = Vec::new();
    let mut last = (0, ZERO_HASH);
    loop {
        let next = Batcher::next_batch(&mut tailer, "my-sensors", last.0, last.1, 100);
        assert_eq!(next.refused, 0);
        let Some(batch) = next.batch else { break };
        last = (batch.seq, batch.batch_hash);
        shipped.extend(batch.records);
    }
    let expected: Vec<Vec<u8>> = lines.into_iter().map(String::into_bytes).collect();
    assert_eq!(shipped, expected);
}
