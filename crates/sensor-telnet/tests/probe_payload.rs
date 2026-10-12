//! A scanner speaking another protocol to the telnet port is recorded as probe evidence, never as
//! a malware sample; a real binary is still a sample, whatever it is prefixed with.
//!
//! Every payload here is built in the test. The probe fixtures are the shape a scanner sends
//! (a protocol header, a few bytes that read as a login, then binary), with filler instead of
//! any captured bytes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::{SIGNAL_CATCHALL_PROBE, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SensorEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

struct Rig {
    addr: std::net::SocketAddr,
    log: std::path::PathBuf,
    spool: std::path::PathBuf,
    _dir: tempfile::TempDir,
    handle: tokio::task::JoinHandle<()>,
}

impl Rig {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let spool = dir.path().join("spool");
        let (addr, handle) = sensor_telnet::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log.clone(),
            spool.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds(),
            "test".to_string(),
            dir.path().join("outbox"),
        )
        .await
        .unwrap();
        Self {
            addr,
            log,
            spool,
            _dir: dir,
            handle,
        }
    }

    /// Send `bytes` as one client write, then close.
    async fn send_and_close(&self, bytes: &[u8]) {
        let mut conn = TcpStream::connect(self.addr).await.unwrap();
        // The banner and login prompt arrive first; reading them keeps the exchange ordered the
        // way a scanner that ignores them would not, but the sensor does not depend on it.
        let mut buf = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_millis(500), conn.read(&mut buf)).await;
        conn.write_all(bytes).await.unwrap();
        conn.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(conn);
    }

    fn events(&self) -> Vec<SensorEvent> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn of(&self, signal: &str) -> Vec<SensorEvent> {
        self.events()
            .into_iter()
            .filter(|e| e.signal_type == signal)
            .collect()
    }

    /// Wait for the first event of `signal`, then give a wrong event of the other kind the time a
    /// worker takes to appear, so a test that asserts its absence is not asserting too early.
    async fn wait_for(&self, signal: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while self.of(signal).is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "no {signal} event; got {:?}",
                self.events()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    fn spooled(&self) -> usize {
        std::fs::read_dir(&self.spool)
            .map(|d| {
                d.flatten()
                    .filter(|e| {
                        sensor_framework::spool::is_canonical_sha256_hex(
                            &e.file_name().to_string_lossy(),
                        )
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A scanner's TLS hello as the telnet sensor sees it: the header, a line break inside the
/// random field that ends the "username", another that ends the "password", then binary the
/// shell capture keeps. `tail` is what follows.
fn tls_probe_with(tail: &[u8]) -> Vec<u8> {
    let mut b = vec![
        0x16, 0x03, 0x01, 0x00, 0x5a, 0x01, 0x00, 0x00, 0x56, 0x03, 0x03,
    ];
    b.push(0x0a);
    b.extend_from_slice(&[0xc3; 16]);
    b.push(0x0a);
    b.extend_from_slice(tail);
    b
}

#[tokio::test]
async fn a_tls_probe_with_a_binary_tail_is_recorded_as_a_probe_and_not_as_a_sample() {
    let rig = Rig::start().await;
    rig.send_and_close(&tls_probe_with(&[0xaa; 60])).await;
    rig.wait_for(SIGNAL_CATCHALL_PROBE).await;

    let probes = rig.of(SIGNAL_CATCHALL_PROBE);
    assert_eq!(probes.len(), 1, "{:?}", rig.events());
    let probe = &probes[0];
    assert_eq!(probe.sensor, "telnet");
    assert_eq!(probe.metadata["capture_reason"], "probe_payload");
    assert_eq!(probe.metadata["probe_protocol"], "tls");
    assert_eq!(probe.metadata["observed_len"], 89);
    assert_eq!(probe.metadata["local_port"], rig.addr.port());
    assert!(
        probe.metadata["payload_hex"]
            .as_str()
            .unwrap()
            .starts_with("16030100")
    );
    assert!(probe.sample.is_none());
    assert!(
        rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD).is_empty(),
        "a probe must not also be a malware upload: {:?}",
        rig.events()
    );
    assert_eq!(rig.spooled(), 0, "a probe is never spooled");
}

/// A hello with no line break never completes the login, so the session ends before any shell
/// capture exists; the probe is still evidence of what the scanner spoke.
#[tokio::test]
async fn a_probe_that_never_finishes_the_login_is_recorded() {
    let rig = Rig::start().await;
    let mut hello = vec![
        0x16, 0x03, 0x01, 0x00, 0x28, 0x01, 0x00, 0x00, 0x24, 0x03, 0x03,
    ];
    hello.extend_from_slice(&[0x41; 30]);
    rig.send_and_close(&hello).await;
    rig.wait_for(SIGNAL_CATCHALL_PROBE).await;
    let probes = rig.of(SIGNAL_CATCHALL_PROBE);
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].metadata["probe_protocol"], "tls");
    assert_eq!(probes[0].metadata["observed_len"], 41);
    assert!(rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD).is_empty());
}

#[tokio::test]
async fn a_plaintext_probe_is_recorded_too() {
    let rig = Rig::start().await;
    rig.send_and_close(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n")
        .await;
    rig.wait_for(SIGNAL_CATCHALL_PROBE).await;
    let probes = rig.of(SIGNAL_CATCHALL_PROBE);
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].metadata["probe_protocol"], "http");
    assert!(rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD).is_empty());
}

#[tokio::test]
async fn an_executable_behind_a_probe_prefix_is_still_a_sample() {
    let rig = Rig::start().await;
    let mut tail = b"\x7fELF\x02\x01\x01\x00".to_vec();
    tail.extend_from_slice(&[0xaa; 60]);
    rig.send_and_close(&tls_probe_with(&tail)).await;
    rig.wait_for(SIGNAL_HONEYPOT_MALWARE_UPLOAD).await;

    let uploads = rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD);
    assert_eq!(uploads.len(), 1);
    assert_eq!(
        uploads[0].metadata["capture_reason"],
        "binary_shell_payload"
    );
    assert!(uploads[0].sample.is_some());
    assert!(
        rig.of(SIGNAL_CATCHALL_PROBE).is_empty(),
        "a dropper hiding behind a protocol header is not a probe"
    );
    assert_eq!(rig.spooled(), 1);
}

#[tokio::test]
async fn a_session_past_the_probe_size_ceiling_is_a_sample_whatever_it_opens_with() {
    let rig = Rig::start().await;
    let tail = vec![0xaa; sensor_telnet::probe::MAX_PROBE_WIRE_BYTES as usize + 1];
    rig.send_and_close(&tls_probe_with(&tail)).await;
    rig.wait_for(SIGNAL_HONEYPOT_MALWARE_UPLOAD).await;
    assert!(rig.of(SIGNAL_CATCHALL_PROBE).is_empty());
    assert_eq!(rig.spooled(), 1);
}

#[tokio::test]
async fn a_binary_pushed_after_an_ordinary_login_is_still_a_sample() {
    let rig = Rig::start().await;
    let mut payload = b"\x7fELF\x01\x01\x01\x00".to_vec();
    payload.extend_from_slice(&[0xaa; 120]);
    let mut session = b"root\r\nsecret\r\n".to_vec();
    session.extend_from_slice(&payload);
    rig.send_and_close(&session).await;
    rig.wait_for(SIGNAL_HONEYPOT_MALWARE_UPLOAD).await;

    assert_eq!(rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD).len(), 1);
    assert!(rig.of(SIGNAL_CATCHALL_PROBE).is_empty());
    assert_eq!(rig.spooled(), 1);
}

#[tokio::test]
async fn random_bytes_after_an_ordinary_login_are_still_a_sample() {
    let rig = Rig::start().await;
    let mut session = b"admin\r\nadmin\r\n".to_vec();
    let mut x = 0x2545_f491_u32;
    for _ in 0..150 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        // Never a line break, so the bytes stay one binary run the capture keeps.
        let byte = (x >> 24) as u8;
        session.push(if matches!(byte, b'\r' | b'\n') {
            0xa5
        } else {
            byte
        });
    }
    rig.send_and_close(&session).await;
    rig.wait_for(SIGNAL_HONEYPOT_MALWARE_UPLOAD).await;
    assert_eq!(rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD).len(), 1);
    assert!(rig.of(SIGNAL_CATCHALL_PROBE).is_empty());
}

#[tokio::test]
async fn an_ordinary_login_and_commands_record_no_probe() {
    let rig = Rig::start().await;
    rig.send_and_close(b"root\r\nhunter2\r\nuname -a\r\nexit\r\n")
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(rig.of(SIGNAL_CATCHALL_PROBE).is_empty());
    assert!(rig.of(SIGNAL_HONEYPOT_MALWARE_UPLOAD).is_empty());
}
