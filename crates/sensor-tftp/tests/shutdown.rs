//! What the binary does on SIGTERM, which only a real process can show: `main` stops the request
//! loop and writes the rate-limited summaries whose window has not ended.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn rrq(name: &str) -> Vec<u8> {
    let mut v = vec![0, 1];
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    v.extend_from_slice(b"octet\0");
    v
}

/// Kills the sensor if the test fails before it exits, so a failing run leaves no process behind.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn sigterm_writes_the_rate_limited_summaries_still_accumulating() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_sensor-tftp"))
            .env_clear()
            .env("NO_COLOR", "1")
            .env("PROPOLIS_TFTP_BIND", "127.0.0.1:0")
            .env("PROPOLIS_TFTP_LOG_PATH", &log)
            .env("PROPOLIS_TFTP_SPOOL_DIR", dir.path().join("spool"))
            .env("PROPOLIS_TFTP_REPLY_RATE_PER_SOURCE", "1")
            .env("PROPOLIS_TFTP_REPLY_BURST_PER_SOURCE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let (lines_tx, lines) = mpsc::channel::<String>();
    let stdout = child.0.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let addr: SocketAddr = loop {
        let line = lines
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|e| panic!("no listening line: {e}"));
        if let Some(at) = line.find("local=") {
            let rest = &line[at + "local=".len()..];
            break rest.split_whitespace().next().unwrap().parse().unwrap();
        }
    };

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for i in 0..20 {
        client.send_to(&rrq(&format!("f{i}")), addr).unwrap();
    }
    let mut buf = [0u8; 64];
    let mut replies = 0;
    while client.recv_from(&mut buf).is_ok() {
        replies += 1;
    }
    assert_eq!(replies, 1, "a burst of one answers one request");

    let killed = Command::new("kill")
        .arg("-TERM")
        .arg(child.0.id().to_string())
        .status()
        .unwrap();
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "still running after SIGTERM");
        std::thread::sleep(Duration::from_millis(25));
    };
    reader.join().unwrap();
    assert_eq!(status.code(), Some(0), "a clean shutdown");

    let summaries: Vec<serde_json::Value> = std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["metadata"]["query_status"] == "rate_limited")
        .collect();
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0]["sensor"], "tftp");
    assert_eq!(summaries[0]["metadata"]["suppressed_count"], 19);
}
