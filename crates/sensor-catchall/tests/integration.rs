// The brief's given imports also included `use std::net::SocketAddr;`, but no test body below
// names `SocketAddr` bare (every socket address is inferred from `.parse()`'s call-site context),
// so keeping it would trip this workspace's `cargo clippy -D warnings` gate on an unused import.
// Dropped; everything else matches the brief verbatim.
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

// Helper: start the catch-all handler on ephemeral ports, return (tcp_addr, udp_addr, log_path)
// The test uses the handler module directly rather than starting the full binary,
// so it can control ports and read the log file.

#[tokio::test]
async fn tcp_probe_emits_catchall_probe_event() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, _handle) =
        sensor_catchall::start_test_listener("127.0.0.1:0".parse().unwrap(), log_path.clone())
            .await
            .unwrap();

    let mut conn = TcpStream::connect(tcp_addr).await.unwrap();
    conn.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let event: sensor_wire::SensorEvent =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(event.signal_type, sensor_wire::SIGNAL_CATCHALL_PROBE);
    assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
    assert!(!event.authenticated);
    assert_eq!(event.sensor, "catchall");
    // No protocol_label for catch-all (emulates no protocol).
    assert!(event.metadata.get("protocol_label").is_none());
    _handle.abort();
}

#[tokio::test]
async fn udp_probe_emits_event_and_zero_response() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (udp_addr, _handle) = sensor_catchall::start_test_udp_listener(
        "127.0.0.1:0".parse().unwrap(),
        sensor_framework::ConnectionBounds {
            read_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(5),
            max_duration: Duration::from_secs(30),
            max_captured_bytes: 5_000_000,
            max_concurrent: 100,
        },
        log_path.clone(),
    )
    .await
    .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"\x00\x01probe", udp_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify event emitted.
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let event: sensor_wire::SensorEvent =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(event.signal_type, sensor_wire::SIGNAL_CATCHALL_PROBE);
    assert_eq!(event.protocol, sensor_wire::PROTO_UDP);
    assert!(!event.authenticated);

    // Verify zero response bytes.
    let mut buf = [0u8; 1024];
    let result = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
    assert!(result.is_err(), "UDP must never respond");
    _handle.abort();
}

#[tokio::test]
async fn adversarial_input_drops_connection_not_crash() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, handle) =
        sensor_catchall::start_test_listener("127.0.0.1:0".parse().unwrap(), log_path.clone())
            .await
            .unwrap();

    // Send garbage, immediately close.
    for _ in 0..5 {
        if let Ok(mut conn) = TcpStream::connect(tcp_addr).await {
            let _ = conn.write_all(&[0xff; 1024]).await;
            drop(conn);
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Verify the listener is still accepting.
    let conn = TcpStream::connect(tcp_addr).await;
    assert!(conn.is_ok(), "accept loop must survive adversarial input");
    handle.abort();
}

#[tokio::test]
async fn log_forging_impossible_through_real_capture_path() {
    // Drive CR/LF/ANSI injection through the real sensor capture path
    // and assert on the raw log bytes - not on the sanitizer in isolation.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, _handle) =
        sensor_catchall::start_test_listener("127.0.0.1:0".parse().unwrap(), log_path.clone())
            .await
            .unwrap();

    // Send a payload containing CRLF + a fake JSON event line.
    let injection = b"GET /\r\n{\"v\":1,\"signal_type\":\"forged\",\"source_ip\":\"1.2.3.4\"}\r\n";
    let mut conn = TcpStream::connect(tcp_addr).await.unwrap();
    conn.write_all(injection).await.unwrap();
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    _handle.abort();

    // Read raw log bytes. Every line must be a parseable SensorEvent
    // with signal_type == catchall_probe. There must be exactly ONE line.
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "injection must not create extra log lines, got {}",
        lines.len()
    );
    let event: sensor_wire::SensorEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(
        event.signal_type,
        sensor_wire::SIGNAL_CATCHALL_PROBE,
        "the only event must be a real catchall_probe, not the forged line"
    );
}

#[tokio::test]
async fn non_utf8_payload_is_captured_losslessly_through_real_path() {
    // Not in the brief's given suite. `log_forging_impossible_through_real_capture_path` above
    // uses an all-ASCII injection payload, so every byte in it is already valid UTF-8 - it cannot
    // discriminate hex-encoding from a plausible-but-wrong alternative that decodes captured bytes
    // as a (possibly lossy) UTF-8 string before embedding them in `metadata`: serde_json's own
    // string escaping keeps *that* alternative's output on one valid NDJSON line too, for an
    // ASCII-only payload (confirmed by mutation - swapping `to_hex_bounded` for
    // `String::from_utf8_lossy(captured).to_string()` left the log-forging test above still
    // green, unchanged). What hex-encoding actually buys over a text/lossy alternative, which this
    // test targets directly, is a lossless round-trip on bytes that are not valid UTF-8 at all -
    // a raw TCP catch-all has no reason to expect attacker input is valid UTF-8 in the first
    // place, and `String::from_utf8_lossy` would silently replace such bytes with U+FFFD,
    // corrupting forensic evidence.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, _handle) =
        sensor_catchall::start_test_listener("127.0.0.1:0".parse().unwrap(), log_path.clone())
            .await
            .unwrap();

    // 0xFF/0xFE are never valid UTF-8 bytes; 0xC0/0xC1 are always-invalid overlong lead bytes;
    // a bare 0x80 continuation byte with no lead byte is invalid. None of this is a UTF-8 decode
    // accident - every byte here is deliberately, unambiguously invalid.
    let non_utf8: &[u8] = &[0xFF, 0xFE, 0x80, 0x01, 0x02, 0xC0, 0xC1];
    let mut conn = TcpStream::connect(tcp_addr).await.unwrap();
    conn.write_all(non_utf8).await.unwrap();
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let event: sensor_wire::SensorEvent =
        serde_json::from_str(content.lines().next().unwrap()).unwrap();
    let hex = event.metadata["payload_hex"].as_str().unwrap();
    let decoded: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    assert_eq!(
        decoded, non_utf8,
        "captured bytes must round-trip exactly through hex, never be lossily mangled"
    );
    _handle.abort();
}

#[tokio::test]
async fn wire_record_signal_types_map_to_valid_from_signal() {
    // Cross-crate test: verify that every signal type string constant in
    // sensor-wire maps to a valid core-scoring SignalType via serde.
    // This test requires core-scoring as a dev-dependency of sensor-catchall.
    let wire_signals = [
        sensor_wire::SIGNAL_CATCHALL_PROBE,
        sensor_wire::SIGNAL_HONEYPOT_CONNECTION,
        sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
        sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC,
        sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD,
        sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD,
    ];
    for wire_str in &wire_signals {
        let quoted = format!("\"{}\"", wire_str);
        let parsed: Result<core_scoring::SignalType, _> = serde_json::from_str(&quoted);
        assert!(
            parsed.is_ok(),
            "wire signal type '{}' must deserialize to a valid core_scoring::SignalType",
            wire_str
        );
    }
}
