//! Integration tests for `sensor_ssh::transport`: the wire-level behavior (real duplex streams,
//! real byte layout) that a unit test operating on in-memory buffers alone would not exercise.
//! Structural properties of the framing (padding bounds, block alignment) and of KEXINIT
//! (cookie randomness, malformed-input handling) are covered as unit tests inside
//! `src/transport/mod.rs` instead, next to the private helpers they call directly.

use sensor_ssh::transport::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn packet_round_trip() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let payload = vec![SSH_MSG_IGNORE, 0, 0, 0, 4, b't', b'e', b's', b't'];
    write_packet_unencrypted(&mut server, &payload)
        .await
        .unwrap();
    let received = read_packet_unencrypted(&mut client).await.unwrap();
    assert_eq!(received.payload, payload);
}

#[tokio::test]
async fn truncated_packet_returns_error() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    // Write a packet length header claiming 1000 bytes, then close.
    server.write_all(&1000u32.to_be_bytes()).await.unwrap();
    drop(server);
    let result = read_packet_unencrypted(&mut client).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn version_exchange_completes() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { do_version_exchange_server(&mut server).await });
    // Client side: send client version, read server version.
    client
        .write_all(b"SSH-2.0-TestClient_1.0\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    let server_version = String::from_utf8_lossy(&buf[..n]);
    assert!(server_version.starts_with("SSH-2.0-"));
    assert!(server_version.ends_with("\r\n"));
    let (client_ver, _server_ver) = server_task.await.unwrap().unwrap();
    assert!(client_ver.starts_with("SSH-2.0-TestClient"));
}

#[tokio::test]
async fn kexinit_round_trip() {
    let kexinit = build_kexinit();
    assert_eq!(kexinit[0], SSH_MSG_KEXINIT);
    let parsed = parse_kexinit(&kexinit).unwrap();
    assert!(parsed.kex_algorithms.contains("curve25519-sha256"));
    assert!(parsed.server_host_key_algorithms.contains("ssh-ed25519"));
    assert!(
        parsed
            .encryption_client_to_server
            .contains("chacha20-poly1305@openssh.com")
    );
}

// ---- Coverage beyond the brief's given suite ----
//
// The four tests above are the brief's dictated interface tests. The task explicitly calls out
// the packet-length bound as a memory-exhaustion guard and the version-line bound as an RFC
// limit; neither given test actually drives a claimed size over those ceilings (the truncation
// test uses length=1000, well under the 35000-byte cap). These tests close that gap.

#[tokio::test]
async fn oversized_packet_length_is_rejected_without_reading_a_body() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    // Claim far more than the RFC 4253 6.1 ceiling (35000); never send a body at all. A correct
    // implementation rejects this from the header alone, so the call below must not block
    // waiting for bytes that are never coming - the timeout turns a regression into a fast
    // assertion failure instead of a hung test.
    server.write_all(&40_000u32.to_be_bytes()).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), read_packet_unencrypted(&mut client))
        .await
        .expect("must reject on the length header alone, never block on an unsent body");
    assert!(result.is_err());
}

#[tokio::test]
async fn version_exchange_rejects_line_exceeding_rfc_limit() {
    let (mut client, mut server) = tokio::io::duplex(8192);
    let server_task = tokio::spawn(async move { do_version_exchange_server(&mut server).await });
    // 300 bytes with no terminating '\n' - over RFC 4253 4.2's 255-byte line cap.
    client.write_all(&vec![b'A'; 300]).await.unwrap();
    let result = server_task.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn version_exchange_reports_error_on_eof_before_newline() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { do_version_exchange_server(&mut server).await });
    client.write_all(b"SSH-2.0-Partial").await.unwrap();
    drop(client);
    let result = server_task.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn version_exchange_preserves_non_utf8_client_line_lossily() {
    // A malformed banner is itself attacker telemetry worth capturing, not a reason to drop the
    // only string that carries it - the wire-exchange layer never hard-fails on encoding alone.
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move { do_version_exchange_server(&mut server).await });
    let mut line = b"SSH-2.0-".to_vec();
    line.extend_from_slice(&[0xff, 0xfe]);
    line.extend_from_slice(b"\r\n");
    client.write_all(&line).await.unwrap();
    let (client_version, _server_version) = server_task.await.unwrap().unwrap();
    assert!(client_version.starts_with("SSH-2.0-"));
}

#[tokio::test]
async fn do_version_exchange_server_with_version_uses_the_given_software_version() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        do_version_exchange_server_with_version(&mut server, "customfirmware_9.9").await
    });
    client.write_all(b"SSH-2.0-TestClient\r\n").await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    let server_line = String::from_utf8_lossy(&buf[..n]);
    assert_eq!(server_line, "SSH-2.0-customfirmware_9.9\r\n");
    server_task.await.unwrap().unwrap();
}
