//! The capture limit of a payload streamed over an exec's stdin or the shell is the spool's
//! per-file cap, 16 MiB. An upload under it is kept whole; one over it is cut at the limit and the
//! event says so (`truncated`), so a hash of the prefix is never read as the hash of the file. A
//! cut upload's `wire_size` is a lower bound: the bytes that had arrived when the input ended, the
//! limit rounded up to the SSH data packet that crossed it. The cases are a 6.6 MB worm that used
//! to be cut at 1,000,000 bytes and a body just past 10,000,000 (a live miner was cut there; its
//! true size is unknown).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_ssh::server::SPOOL_MAX_FILE_BYTES;

struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A body that is not a repeating pattern, so a cut at the wrong place changes its digest.
fn body_of(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}

/// Stream `body` to `cat > /tmp/payload` over an exec channel, to a server running with the
/// default capture limit, and return the one upload event it recorded.
async fn upload(body: &[u8]) -> sensor_wire::SensorEvent {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration: Duration::from_secs(120),
        max_captured_bytes: SPOOL_MAX_FILE_BYTES,
        max_concurrent: 64,
    };
    let (addr, handle) = sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        dir.path().join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();

    let mut session = russh::client::connect(
        Arc::new(russh::client::Config::default()),
        addr,
        TestHandler,
    )
    .await
    .unwrap();
    assert!(
        session
            .authenticate_password("root", "password")
            .await
            .unwrap()
            .success()
    );
    let mut channel = session.channel_open_session().await.unwrap();
    channel.exec(false, b"cat > /tmp/payload").await.unwrap();
    for piece in body.chunks(1 << 20) {
        // The server stops reading once it has the limit, so a late write may find the channel
        // closed; the capture is what is under test, not the transfer.
        // A client blocked on a window the server no longer opens is the same case.
        match tokio::time::timeout(Duration::from_secs(10), channel.data(piece)).await {
            Ok(Ok(())) => {}
            _ => break,
        }
    }
    let _ = channel.eof().await;
    let _ = tokio::time::timeout(Duration::from_secs(60), async {
        while channel.wait().await.is_some() {}
    })
    .await;
    // The capture is submitted when the connection ends.
    drop(channel);
    drop(session);

    let event = uploads(&log_path).await;
    handle.abort();
    event
}

async fn uploads(log_path: &std::path::Path) -> sensor_wire::SensorEvent {
    for _ in 0..400 {
        if let Ok(content) = tokio::fs::read_to_string(log_path).await {
            let found: Vec<sensor_wire::SensorEvent> = content
                .lines()
                .filter_map(|line| serde_json::from_str::<sensor_wire::SensorEvent>(line).ok())
                .filter(|event| event.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
                .collect();
            if let Some(event) = found.into_iter().next() {
                return event;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no upload was recorded");
}

#[test]
fn the_limit_is_the_spool_per_file_cap_of_16_mib() {
    assert_eq!(SPOOL_MAX_FILE_BYTES, 16 * 1024 * 1024);
}

/// A size just past the old 10,000,000-byte limit. A live miner was cut there on every attempt;
/// 10,027,008 is the limit rounded up to a 32 KiB packet (306 x 32,768) as that capture recorded
/// it, so it is a test size, not the miner's.
const MINER_BYTES: usize = 10_027_008;

#[tokio::test]
async fn a_10_027_008_byte_stdin_transfer_is_captured_whole() {
    let body = body_of(MINER_BYTES);
    let event = upload(&body).await;
    let sample = event.sample.as_ref().expect("the upload has a sample");
    assert_eq!(sample.size, MINER_BYTES as u64);
    assert_eq!(sample.sha256, sha256_hex(&body));
    assert_eq!(event.metadata["wire_size"], MINER_BYTES as u64);
    assert_eq!(event.metadata["truncated"], false);
    assert_eq!(event.metadata["complete"], true);
}

#[tokio::test]
async fn an_upload_just_under_the_limit_is_captured_whole() {
    let body = body_of(SPOOL_MAX_FILE_BYTES as usize - 1_000);
    let event = upload(&body).await;
    let sample = event.sample.as_ref().expect("the upload has a sample");
    assert_eq!(sample.size, body.len() as u64);
    assert_eq!(sample.sha256, sha256_hex(&body));
    assert_eq!(event.metadata["wire_size"], body.len() as u64);
    assert_eq!(event.metadata["truncated"], false);
    assert_eq!(event.metadata["complete"], true);
}

#[tokio::test]
async fn an_upload_just_over_the_limit_is_cut_at_it_and_flagged_truncated() {
    let body = body_of(SPOOL_MAX_FILE_BYTES as usize + 100_000);
    let event = upload(&body).await;
    let sample = event.sample.as_ref().expect("the upload has a sample");
    let kept = &body[..SPOOL_MAX_FILE_BYTES as usize];
    assert_eq!(sample.size, SPOOL_MAX_FILE_BYTES);
    assert_eq!(
        sample.sha256,
        sha256_hex(kept),
        "the sample is the first 16 MiB of the upload, byte for byte"
    );
    assert_eq!(event.metadata["truncated"], true);
    assert!(
        event.metadata["wire_size"].as_u64().unwrap() > SPOOL_MAX_FILE_BYTES,
        "wire_size is past what was kept (a lower bound on the upload, not its size)"
    );
}

/// `wire_size` of a cut shell or stdin capture is what had arrived when the input ended, the limit
/// rounded up to the SSH data packet that crossed it, not the transfer's size. A reader must not
/// take it for the size of what was sent (the docs say it is a lower bound).
#[tokio::test]
async fn a_cut_uploads_wire_size_is_a_lower_bound_not_the_transfer_size() {
    let body = body_of(SPOOL_MAX_FILE_BYTES as usize + 8 * 1024 * 1024);
    let event = upload(&body).await;
    let wire = event.metadata["wire_size"].as_u64().unwrap();
    assert_eq!(event.metadata["truncated"], true);
    assert!(wire >= SPOOL_MAX_FILE_BYTES, "{wire}");
    assert!(
        wire < SPOOL_MAX_FILE_BYTES + 1024 * 1024,
        "wire_size {wire} counted past the packet that crossed the limit"
    );
    assert!(wire < body.len() as u64, "the transfer was {}", body.len());
}
