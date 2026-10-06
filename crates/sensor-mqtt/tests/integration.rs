use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::{
    SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SensorEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        Self::start_with_bounds(test_bounds()).await
    }

    async fn start_with_bounds(bounds: ConnectionBounds) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_mqtt::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            wan_resolver,
            bounds,
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
            handle,
            _dir: dir,
        }
    }

    async fn raw_events(&self) -> String {
        tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default()
    }

    async fn events(&self) -> Vec<SensorEvent> {
        self.raw_events()
            .await
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }

    /// Poll the log until `want` events match `pred`, instead of sleeping a fixed time.
    async fn wait_for(&self, want: usize, pred: impl Fn(&SensorEvent) -> bool) -> Vec<SensorEvent> {
        for _ in 0..60 {
            let hits: Vec<SensorEvent> = self.events().await.into_iter().filter(&pred).collect();
            if hits.len() >= want {
                return hits;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {want} matching events");
    }
}

fn lenp(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

fn varint(mut v: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            return out;
        }
    }
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![first];
    p.extend(varint(body.len()));
    p.extend_from_slice(body);
    p
}

fn connect_packet(level: u8, flags: u8, rest: &[u8]) -> Vec<u8> {
    let mut b = if level == 3 {
        lenp(b"MQIsdp")
    } else {
        lenp(b"MQTT")
    };
    b.push(level);
    b.push(flags);
    b.extend_from_slice(&30u16.to_be_bytes());
    if level == 5 {
        b.push(0);
    }
    b.extend_from_slice(rest);
    packet(0x10, &b)
}

fn connect_with_creds() -> Vec<u8> {
    let mut rest = lenp(b"scanner-01");
    rest.extend(lenp(b"admin"));
    rest.extend(lenp(b"hunter2-secret"));
    connect_packet(4, 0xC2, &rest)
}

struct Client {
    stream: TcpStream,
}

impl Client {
    async fn connect(addr: std::net::SocketAddr) -> Client {
        Client {
            stream: TcpStream::connect(addr).await.unwrap(),
        }
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    async fn read_n(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(3), self.stream.read_exact(&mut buf))
            .await
            .expect("timeout")
            .expect("read error");
        buf
    }

    /// The server must close without sending another byte.
    async fn expect_closed(&mut self) {
        let mut buf = Vec::new();
        let res = tokio::time::timeout(Duration::from_secs(2), self.stream.read_to_end(&mut buf))
            .await
            .expect("server held the connection open instead of closing it");
        assert!(
            res.is_err() || buf.is_empty(),
            "unexpected bytes before close: {buf:?}"
        );
    }

    async fn handshake(&mut self) {
        self.send(&connect_with_creds()).await;
        assert_eq!(self.read_n(4).await, vec![0x20, 0x02, 0x00, 0x00]);
    }
}

fn is_signal(signal: &'static str) -> impl Fn(&SensorEvent) -> bool {
    move |e| e.signal_type == signal
}

fn command(name: &'static str) -> impl Fn(&SensorEvent) -> bool {
    move |e| {
        e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC
            && e.metadata.get("command").and_then(|v| v.as_str()) == Some(name)
    }
}

#[tokio::test]
async fn tcp_connect_emits_connection_event() {
    let srv = TestServer::start().await;
    let _client = Client::connect(srv.addr).await;
    let events = srv.wait_for(1, is_signal(SIGNAL_HONEYPOT_CONNECTION)).await;
    assert!(!events[0].authenticated);
    assert_eq!(events[0].sensor, "mqtt");
    srv.handle.abort();
}

#[tokio::test]
async fn connect_311_gets_connack_and_login_event_without_password() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;

    let login = srv
        .wait_for(1, is_signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT))
        .await;
    let m = &login[0].metadata;
    assert!(login[0].authenticated);
    assert_eq!(m["client_id"], "scanner-01");
    assert_eq!(m["username"], "admin");
    assert_eq!(m["protocol_level"], 4);
    assert_eq!(m["keepalive"], 30);
    assert_eq!(m["clean_session"], true);
    assert!(m.get("password").is_none());
    let raw = srv.raw_events().await;
    assert!(
        !raw.contains("hunter2"),
        "the password must never reach the log: {raw}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn connect_31_is_accepted_and_will_is_recorded() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    let mut rest = lenp(b"old-client");
    rest.extend(lenp(b"will/topic"));
    rest.extend(lenp(b"gone"));
    client.send(&connect_packet(3, 0x06, &rest)).await;
    assert_eq!(client.read_n(4).await, vec![0x20, 0x02, 0x00, 0x00]);

    let login = srv
        .wait_for(1, is_signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT))
        .await;
    assert_eq!(login[0].metadata["protocol_level"], 3);
    assert_eq!(login[0].metadata["will_topic"], "will/topic");
    assert_eq!(login[0].metadata["will_payload_len"], 4);
    srv.handle.abort();
}

#[tokio::test]
async fn connect_level5_is_declined_0x84_but_still_logged() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    let mut rest = lenp(b"v5-scanner");
    rest.extend(lenp(b"root"));
    rest.extend(lenp(b"toor-secret"));
    client.send(&connect_packet(5, 0xC2, &rest)).await;
    assert_eq!(client.read_n(5).await, vec![0x20, 0x03, 0x00, 0x84, 0x00]);
    client.expect_closed().await;

    let login = srv
        .wait_for(1, is_signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT))
        .await;
    assert_eq!(login[0].metadata["protocol_level"], 5);
    assert_eq!(login[0].metadata["client_id"], "v5-scanner");
    assert_eq!(login[0].metadata["username"], "root");
    assert!(!srv.raw_events().await.contains("toor-secret"));
    srv.handle.abort();
}

#[tokio::test]
async fn subscribe_gets_suback_and_topics_are_recorded() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;

    let mut body = vec![0x00, 0x10];
    body.extend(lenp(b"$SYS/#"));
    body.push(1);
    body.extend(lenp(b"home/+/temp"));
    body.push(2);
    client.send(&packet(0x82, &body)).await;
    assert_eq!(
        client.read_n(6).await,
        vec![0x90, 0x04, 0x00, 0x10, 0x01, 0x01]
    );

    let ev = srv.wait_for(1, command("SUBSCRIBE")).await;
    assert_eq!(ev[0].metadata["topics"][0], "$SYS/#");
    assert_eq!(ev[0].metadata["topics"][1], "home/+/temp");
    assert_eq!(ev[0].metadata["qos"][1], 2);
    srv.handle.abort();
}

#[tokio::test]
async fn publish_qos1_gets_puback_and_metadata_with_hash() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;

    let mut body = lenp(b"cmd/exec");
    body.extend_from_slice(&[0xAB, 0xCD]);
    body.extend_from_slice(b"hello");
    client.send(&packet(0x33, &body)).await; // qos1, retain
    assert_eq!(client.read_n(4).await, vec![0x40, 0x02, 0xAB, 0xCD]);

    let ev = srv.wait_for(1, command("PUBLISH")).await;
    let m = &ev[0].metadata;
    assert_eq!(m["topic"], "cmd/exec");
    assert_eq!(m["qos"], 1);
    assert_eq!(m["retain"], true);
    assert_eq!(m["dup"], false);
    assert_eq!(m["payload_len"], 5);
    assert_eq!(m["payload_preview"], "hello");
    assert_eq!(
        m["payload_sha256"],
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert!(ev[0].sample.is_none(), "metadata-only: no spooled sample");
    srv.handle.abort();
}

#[tokio::test]
async fn publish_qos2_flow_and_qos0_silence() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;

    let mut q2 = lenp(b"t");
    q2.extend_from_slice(&[0x00, 0x07]);
    q2.extend_from_slice(b"x");
    client.send(&packet(0x34, &q2)).await;
    assert_eq!(client.read_n(4).await, vec![0x50, 0x02, 0x00, 0x07]);
    client.send(&packet(0x62, &[0x00, 0x07])).await;
    assert_eq!(client.read_n(4).await, vec![0x70, 0x02, 0x00, 0x07]);

    // qos0 is silent; the PINGRESP that follows proves nothing was queued ahead of it.
    let mut q0 = lenp(b"t");
    q0.extend_from_slice(b"fire and forget");
    client.send(&packet(0x30, &q0)).await;
    client.send(&packet(0xC0, &[])).await;
    assert_eq!(client.read_n(2).await, vec![0xD0, 0x00]);
    srv.handle.abort();
}

#[tokio::test]
async fn pingreq_gets_pingresp_and_disconnect_closes() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;
    client.send(&packet(0xC0, &[])).await;
    assert_eq!(client.read_n(2).await, vec![0xD0, 0x00]);
    client.send(&packet(0xE0, &[])).await;
    client.expect_closed().await;
    srv.handle.abort();
}

#[tokio::test]
async fn unsubscribe_gets_unsuback() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;
    let mut body = vec![0x00, 0x21];
    body.extend(lenp(b"a/b"));
    client.send(&packet(0xA2, &body)).await;
    assert_eq!(client.read_n(4).await, vec![0xB0, 0x02, 0x00, 0x21]);
    srv.handle.abort();
}

async fn assert_malformed_closes_and_listener_survives(srv: &TestServer, bytes: &[u8], what: &str) {
    let mut client = Client::connect(srv.addr).await;
    let _ = client.stream.write_all(bytes).await;
    client.expect_closed().await;
    let mut probe = Client::connect(srv.addr).await;
    probe.handshake().await;
    let _ = what;
}

#[tokio::test]
async fn malformed_packets_close_without_panic() {
    let srv = TestServer::start().await;

    // 5-byte remaining-length varint.
    assert_malformed_closes_and_listener_survives(
        &srv,
        &[0x10, 0x80, 0x80, 0x80, 0x80, 0x01],
        "5-byte varint",
    )
    .await;
    // Remaining length over MAX_PACKET_BYTES (declared, never sent).
    let mut over = vec![0x10u8];
    over.extend(varint(sensor_mqtt::handler::MAX_PACKET_BYTES + 1));
    assert_malformed_closes_and_listener_survives(&srv, &over, "over cap").await;
    // CONNECT with the reserved flag bit set.
    assert_malformed_closes_and_listener_survives(
        &srv,
        &connect_packet(4, 0x03, &lenp(b"c")),
        "reserved connect flag",
    )
    .await;
    // Non-CONNECT first packets.
    assert_malformed_closes_and_listener_survives(&srv, &packet(0xC0, &[]), "pre-CONNECT PINGREQ")
        .await;
    let mut publish = lenp(b"t");
    publish.extend_from_slice(b"x");
    assert_malformed_closes_and_listener_survives(
        &srv,
        &packet(0x30, &publish),
        "pre-CONNECT PUBLISH",
    )
    .await;
    // Unknown type and bad fixed-header flags after a valid CONNECT.
    for bad in [
        packet(0x00, &[]),
        packet(0xF0, &[]),
        packet(0x80, &[0, 1, 0, 1, b't', 0]),
    ] {
        let mut client = Client::connect(srv.addr).await;
        client.handshake().await;
        client.send(&bad).await;
        client.expect_closed().await;
    }
    srv.handle.abort();
}

#[tokio::test]
async fn oversize_declared_length_is_refused_without_waiting_for_a_body() {
    // A 268 MB declaration with no body behind it. The idle timeout is 5 s, so a server that
    // tried to buffer the declared length would sit in read until then; a refusal on the
    // declaration alone closes at once.
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.send(&[0x10, 0xFF, 0xFF, 0xFF, 0x7F]).await;
    let started = std::time::Instant::now();
    client.expect_closed().await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "oversize declaration was not refused immediately"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn packets_per_connection_are_capped() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.send(&connect_with_creds()).await;
    let pings: Vec<u8> = std::iter::repeat_n([0xC0u8, 0x00], 1200)
        .flatten()
        .collect();
    let _ = client.stream.write_all(&pings).await;
    let mut buf = Vec::new();
    let ended =
        tokio::time::timeout(Duration::from_secs(3), client.stream.read_to_end(&mut buf)).await;
    assert!(
        ended.is_ok(),
        "the server must end the session, not keep serving"
    );
    // CONNACK (4 bytes) plus at most one PINGRESP per remaining packet of the MAX_PACKETS budget.
    // The server closes with unread input still queued, so the kernel may reset the connection
    // and drop some replies in flight: an upper bound, not an exact count.
    let pongs = (buf.len().saturating_sub(4)) / 2;
    assert!(
        pongs < sensor_mqtt::handler::MAX_PACKETS,
        "answered {pongs} packets, past the per-connection cap"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn captured_bytes_budget_ends_the_session() {
    let bounds = ConnectionBounds {
        max_captured_bytes: 200,
        ..test_bounds()
    };
    let srv = TestServer::start_with_bounds(bounds).await;
    let mut client = Client::connect(srv.addr).await;
    client.send(&connect_with_creds()).await;
    let pings: Vec<u8> = std::iter::repeat_n([0xC0u8, 0x00], 500).flatten().collect();
    let _ = client.stream.write_all(&pings).await;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), client.stream.read_to_end(&mut buf)).await;
    assert!(
        buf.len() < 4 + 2 * 100,
        "session must end near the budget, got {} bytes",
        buf.len()
    );
    srv.handle.abort();
}

#[tokio::test]
async fn idle_connection_is_closed_by_the_read_timeout() {
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_millis(300),
        ..test_bounds()
    };
    let srv = TestServer::start_with_bounds(bounds).await;
    let mut client = Client::connect(srv.addr).await;
    client.expect_closed().await;
    srv.handle.abort();
}

#[tokio::test]
async fn publish_is_never_delivered_to_a_subscriber_or_retained() {
    let srv = TestServer::start().await;
    let mut subscriber = Client::connect(srv.addr).await;
    subscriber.handshake().await;
    let mut sub = vec![0x00, 0x01];
    sub.extend(lenp(b"#"));
    sub.push(0);
    subscriber.send(&packet(0x82, &sub)).await;
    assert_eq!(
        subscriber.read_n(5).await,
        vec![0x90, 0x03, 0x00, 0x01, 0x00]
    );

    let mut publisher = Client::connect(srv.addr).await;
    publisher.handshake().await;
    let mut publish = lenp(b"secret/topic");
    publish.extend_from_slice(b"payload");
    publisher.send(&packet(0x31, &publish)).await; // retain
    srv.wait_for(1, command("PUBLISH")).await;

    // Nothing arrives for the live subscriber: the next bytes it sees are its own PINGRESP.
    subscriber.send(&packet(0xC0, &[])).await;
    assert_eq!(subscriber.read_n(2).await, vec![0xD0, 0x00]);

    // A late subscriber gets no retained message either.
    let mut late = Client::connect(srv.addr).await;
    late.handshake().await;
    late.send(&packet(0x82, &sub)).await;
    assert_eq!(late.read_n(5).await, vec![0x90, 0x03, 0x00, 0x01, 0x00]);
    late.send(&packet(0xC0, &[])).await;
    assert_eq!(late.read_n(2).await, vec![0xD0, 0x00]);
    srv.handle.abort();
}

#[tokio::test]
async fn never_connects_outbound() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let c = count.clone();
    let task = tokio::spawn(async move {
        loop {
            if target.accept().await.is_ok() {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    // A CONNECT will and a PUBLISH that both name the listening port as a lure.
    let mut rest = lenp(b"lure");
    rest.extend(lenp(format!("127.0.0.1:{target_port}").as_bytes()));
    rest.extend(lenp(format!("http://127.0.0.1:{target_port}/x").as_bytes()));
    client.send(&connect_packet(4, 0x06, &rest)).await;
    assert_eq!(client.read_n(4).await, vec![0x20, 0x02, 0x00, 0x00]);
    let mut publish = lenp(format!("127.0.0.1:{target_port}").as_bytes());
    publish.extend_from_slice(format!("http://127.0.0.1:{target_port}/").as_bytes());
    client.send(&packet(0x30, &publish)).await;
    client.send(&packet(0xC0, &[])).await;
    assert_eq!(client.read_n(2).await, vec![0xD0, 0x00]);

    tokio::time::sleep(Duration::from_millis(300)).await;
    srv.handle.abort();
    task.abort();
    assert_eq!(
        count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor-mqtt must never connect outbound"
    );
}

#[tokio::test]
async fn protocol_label_mqtt_on_all_events() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;
    let mut publish = lenp(b"t");
    publish.extend_from_slice(b"x");
    client.send(&packet(0x30, &publish)).await;
    srv.wait_for(1, command("PUBLISH")).await;
    let events = srv.events().await;
    assert_eq!(events.len(), 3, "connection + login + publish: {events:?}");
    for event in &events {
        assert_eq!(event.sensor, "mqtt");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("mqtt")
        );
    }
    srv.handle.abort();
}

#[tokio::test]
async fn garbage_and_truncated_streams_do_not_crash_the_listener() {
    let srv = TestServer::start().await;
    let valid = connect_with_creds();
    for seed in 0..12u8 {
        if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
            let garbage: Vec<u8> = (0..4096u32)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                .collect();
            let _ = conn.write_all(&garbage).await;
            drop(conn);
        }
        // Every truncation point of a valid CONNECT, then a hard close.
        if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
            let _ = conn
                .write_all(&valid[..(seed as usize * 3) % valid.len()])
                .await;
            drop(conn);
        }
    }
    let mut probe = Client::connect(srv.addr).await;
    probe.handshake().await;
    srv.handle.abort();
}

fn walk_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, files);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
    }
    walk(dir, &mut files);
    files
}

fn source_files_containing(needles: &[&str]) -> Vec<String> {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    walk_rs(&src_dir)
        .into_iter()
        .filter(|path| {
            let content = std::fs::read_to_string(path).unwrap_or_default();
            needles.iter().any(|n| content.contains(n))
        })
        .map(|p| p.display().to_string())
        .collect()
}

#[test]
fn never_exec_static_check() {
    let found = source_files_containing(&[
        "std::process::Command",
        "process::Command",
        "Command::new",
        "tokio::process",
    ]);
    assert!(
        found.is_empty(),
        "sensor-mqtt must not spawn processes: {found:?}"
    );
}

#[test]
fn never_outbound_static_check() {
    let found = source_files_containing(&[
        "TcpStream::connect",
        "UdpSocket",
        "std::net::TcpStream",
        "TcpSocket",
        ".connect(",
        "ToSocketAddrs",
    ]);
    assert!(
        found.is_empty(),
        "sensor-mqtt must not open outbound sockets: {found:?}"
    );
}

#[test]
fn manifest_has_no_http_client_and_no_tokio_process_feature() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .unwrap();
    for client in [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
    ] {
        assert!(
            !manifest.contains(client),
            "sensor-mqtt must not depend on {client}"
        );
    }
    let tokio_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("tokio"))
        .expect("tokio dependency");
    assert!(
        !tokio_line.contains("\"process\""),
        "tokio `process` feature must stay off"
    );
}
