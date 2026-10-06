use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::capture_budget::CAPTURE_CHUNK_BYTES;
use sensor_framework::{
    CaptureHandoff, CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M,
    WanResolver,
};
use sensor_wire::{
    SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SIGNAL_HONEYPOT_SESSION_END, SensorEvent,
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
    spool_dir: PathBuf,
    handle: JoinHandle<()>,
    handoff: Arc<CaptureHandoff>,
    budget: Arc<CaptureMemoryBudget>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        Self::start_with(test_bounds(), DEFAULT_CAPTURE_BUDGET_BYTES_256M).await
    }

    async fn start_with_bounds(bounds: ConnectionBounds) -> TestServer {
        Self::start_with(bounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M).await
    }

    async fn start_with_capture_budget(ceiling: u64) -> TestServer {
        Self::start_with(test_bounds(), ceiling).await
    }

    async fn start_with(bounds: ConnectionBounds, ceiling: u64) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let budget = Arc::new(CaptureMemoryBudget::new(ceiling));
        let (addr, handle, handoff) = sensor_mqtt::start_test_server_with_handoff(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            wan_resolver,
            bounds,
            "test".to_string(),
            dir.path().join("outbox"),
            budget.clone(),
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
            spool_dir,
            handle,
            handoff,
            budget,
            _dir: dir,
        }
    }

    async fn uploads(&self) -> Vec<SensorEvent> {
        self.events()
            .await
            .into_iter()
            .filter(|e| e.signal_type == SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .collect()
    }

    async fn wait_for_budget_current(&self, bytes: u64) {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while self.budget.current_bytes() != bytes {
            assert!(
                std::time::Instant::now() < deadline,
                "budget current stayed at {} (wanted {bytes})",
                self.budget.current_bytes()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
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

/// A 5.0 CONNECT with an explicit properties block (`props` is the block content).
fn connect_v5_packet(flags: u8, keepalive: u16, props: &[u8], rest: &[u8]) -> Vec<u8> {
    let mut b = lenp(b"MQTT");
    b.push(5);
    b.push(flags);
    b.extend_from_slice(&keepalive.to_be_bytes());
    b.extend(varint(props.len()));
    b.extend_from_slice(props);
    b.extend_from_slice(rest);
    packet(0x10, &b)
}

/// A properties block as it appears on the wire: length varint, then the content.
fn block(content: &[u8]) -> Vec<u8> {
    [varint(content.len()), content.to_vec()].concat()
}

fn prop_str(id: u8, s: &[u8]) -> Vec<u8> {
    [vec![id], lenp(s)].concat()
}

fn prop_pair(k: &[u8], v: &[u8]) -> Vec<u8> {
    [vec![0x26], lenp(k), lenp(v)].concat()
}

const V5_CONNACK: [u8; 5] = [0x20, 0x03, 0x00, 0x00, 0x00];

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

    async fn handshake_v5(&mut self) {
        self.send(&connect_v5_packet(0x02, 30, &[], &lenp(b"v5-client")))
            .await;
        assert_eq!(self.read_n(5).await, V5_CONNACK.to_vec());
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
async fn connect_level5_gets_v5_connack_and_logs_properties_without_credentials() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    let props = [
        prop_str(0x15, b"SCRAM-SHA-256"),
        prop_str(0x16, b"SECRET-AUTH-DATA"),
        vec![0x11, 0x00, 0x00, 0x0E, 0x10], // session expiry 3600
        vec![0x21, 0x00, 0x14],             // receive maximum 20
        prop_pair(b"agent", b"mqtt-scan/1.0"),
    ]
    .concat();
    let mut rest = lenp(b"v5-scanner");
    rest.extend(lenp(b"root"));
    rest.extend(lenp(b"toor-secret"));
    client
        .send(&connect_v5_packet(0xC2, 30, &props, &rest))
        .await;
    // CONNACK: ack flags 0, reason 0x00 (success), empty properties.
    assert_eq!(client.read_n(5).await, V5_CONNACK.to_vec());

    let login = srv
        .wait_for(1, is_signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT))
        .await;
    let m = &login[0].metadata;
    assert!(login[0].authenticated);
    assert_eq!(m["protocol_level"], 5);
    assert_eq!(m["client_id"], "v5-scanner");
    assert_eq!(m["username"], "root");
    assert_eq!(m["auth_method"], "SCRAM-SHA-256");
    assert_eq!(m["session_expiry"], 3600);
    assert_eq!(m["receive_max"], 20);
    assert_eq!(m["user_properties"][0]["name"], "agent");
    assert_eq!(m["user_properties"][0]["value"], "mqtt-scan/1.0");
    let raw = srv.raw_events().await;
    assert!(!raw.contains("toor-secret"), "password leaked: {raw}");
    assert!(!raw.contains("SECRET-AUTH-DATA"), "auth data leaked: {raw}");

    // The session stays engaged afterwards.
    client.send(&packet(0xC0, &[])).await;
    assert_eq!(client.read_n(2).await, vec![0xD0, 0x00]);
    srv.handle.abort();
}

#[tokio::test]
async fn level5_subscribe_publish_unsubscribe_are_parsed_answered_in_v5_form_and_logged() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake_v5().await;

    // SUBSCRIBE with a subscription-identifier and a user property; options carry no-local.
    let mut sub = vec![0x00, 0x10];
    sub.extend(block(&[vec![0x0B, 0x07], prop_pair(b"k", b"v")].concat()));
    sub.extend(lenp(b"$SYS/#"));
    sub.push(0x05); // qos 1, no-local
    sub.extend(lenp(b"home/+/temp"));
    sub.push(0x02);
    sub.extend(lenp(b"bad#"));
    sub.push(0x00);
    client.send(&packet(0x82, &sub)).await;
    // SUBACK: id, empty properties, granted 1, granted 1 (qos 2 lowered), 0x8F invalid filter.
    assert_eq!(
        client.read_n(8).await,
        vec![0x90, 0x06, 0x00, 0x10, 0x00, 0x01, 0x01, 0x8F]
    );

    // PUBLISH qos1 whose properties block is long enough for a two-byte length: the payload must
    // begin after it.
    let publish_props = [
        vec![0x01, 0x01],
        vec![0x23, 0x00, 0x05],
        prop_pair(b"trace", &[b'x'; 200]),
    ]
    .concat();
    let mut publish = lenp(b"cmd/exec");
    publish.extend_from_slice(&[0xAB, 0xCD]);
    publish.extend(block(&publish_props));
    publish.extend_from_slice(b"hello");
    client.send(&packet(0x32, &publish)).await;
    assert_eq!(client.read_n(4).await, vec![0x40, 0x02, 0xAB, 0xCD]);

    // UNSUBSCRIBE of two filters: UNSUBACK carries one reason code each.
    let mut unsub = vec![0x00, 0x21];
    unsub.extend(block(&[]));
    unsub.extend(lenp(b"a/b"));
    unsub.extend(lenp(b"c/d"));
    client.send(&packet(0xA2, &unsub)).await;
    assert_eq!(
        client.read_n(7).await,
        vec![0xB0, 0x05, 0x00, 0x21, 0x00, 0x00, 0x00]
    );

    let s = srv.wait_for(1, command("SUBSCRIBE")).await;
    assert_eq!(s[0].metadata["topics"][0], "$SYS/#");
    assert_eq!(s[0].metadata["topics"][1], "home/+/temp");
    assert_eq!(s[0].metadata["qos"][1], 2);
    assert_eq!(s[0].metadata["topic_count"], 3);
    let p = srv.wait_for(1, command("PUBLISH")).await;
    let m = &p[0].metadata;
    assert_eq!(m["topic"], "cmd/exec");
    assert_eq!(m["qos"], 1);
    assert_eq!(m["payload_len"], 5);
    assert_eq!(m["payload_preview"], "hello");
    assert_eq!(
        m["payload_sha256"],
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(m["topic_alias"], 5);
    srv.handle.abort();
}

#[tokio::test]
async fn level5_auth_is_completed_and_pubrel_is_answered() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake_v5().await;

    let auth_props = [
        prop_str(0x15, b"SCRAM-SHA-1"),
        prop_str(0x16, b"AUTHBLOB-SECRET"),
    ]
    .concat();
    let auth = [vec![0x19], block(&auth_props)].concat();
    client.send(&packet(0xF0, &auth)).await;
    assert_eq!(client.read_n(4).await, vec![0xF0, 0x02, 0x00, 0x00]);

    // PUBREL with a reason code and properties, answered with a PUBCOMP.
    let rel = [vec![0x00, 0x09, 0x00], block(&prop_str(0x1F, b"why"))].concat();
    client.send(&packet(0x62, &rel)).await;
    assert_eq!(client.read_n(4).await, vec![0x70, 0x02, 0x00, 0x09]);

    let ev = srv.wait_for(1, command("AUTH")).await;
    assert_eq!(ev[0].metadata["auth_method"], "SCRAM-SHA-1");
    assert_eq!(ev[0].metadata["reason_code"], 0x19);
    assert!(!srv.raw_events().await.contains("AUTHBLOB"));
    srv.handle.abort();
}

#[tokio::test]
async fn level5_malformed_properties_flag_but_do_not_close_and_overrun_does() {
    let srv = TestServer::start().await;
    // An unknown property identifier inside a block that fits: logged with the flag, accepted.
    let mut client = Client::connect(srv.addr).await;
    client
        .send(&connect_v5_packet(
            0x02,
            30,
            &[0x7E, 0x00],
            &lenp(b"odd-props"),
        ))
        .await;
    assert_eq!(client.read_n(5).await, V5_CONNACK.to_vec());
    let login = srv
        .wait_for(1, is_signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT))
        .await;
    assert_eq!(login[0].metadata["client_id"], "odd-props");
    assert_eq!(login[0].metadata["properties_parse_error"], true);

    // A declared properties length past the end of the packet: the boundary is unknowable, so the
    // CONNECT is malformed.
    let mut over = lenp(b"MQTT");
    over.extend_from_slice(&[5, 0x02, 0x00, 0x1E]);
    over.extend(varint(500));
    over.extend(lenp(b"c"));
    let mut bad = Client::connect(srv.addr).await;
    bad.send(&packet(0x10, &over)).await;
    bad.expect_closed().await;
    let ev = srv
        .wait_for(1, |e| {
            e.metadata.get("reason").and_then(|v| v.as_str()) == Some("malformed_connect")
        })
        .await;
    assert_eq!(ev[0].metadata["malformed"], true);
    srv.handle.abort();
}

#[tokio::test]
async fn malformed_first_packet_emits_a_malformed_connection_event() {
    let srv = TestServer::start().await;

    // Reserved connect-flag bit.
    let mut c = Client::connect(srv.addr).await;
    let bad_connect = connect_packet(4, 0x03, &lenp(b"c"));
    c.send(&bad_connect).await;
    c.expect_closed().await;
    // Non-CONNECT first packet.
    let mut c = Client::connect(srv.addr).await;
    c.send(&packet(0xC0, &[])).await;
    c.expect_closed().await;
    // 5-byte remaining-length varint.
    let mut c = Client::connect(srv.addr).await;
    c.send(&[0x10, 0x80, 0x80, 0x80, 0x80, 0x01]).await;
    c.expect_closed().await;
    // Oversize declaration.
    let mut c = Client::connect(srv.addr).await;
    c.send(&[0x10, 0xFF, 0xFF, 0xFF, 0x7F]).await;
    c.expect_closed().await;

    let by_reason = |reason: &'static str| {
        move |e: &SensorEvent| {
            e.signal_type == SIGNAL_HONEYPOT_CONNECTION
                && e.metadata.get("reason").and_then(|v| v.as_str()) == Some(reason)
        }
    };
    let ev = srv.wait_for(1, by_reason("malformed_connect")).await;
    let m = &ev[0].metadata;
    assert!(!ev[0].authenticated);
    assert_eq!(m["malformed"], true);
    assert_eq!(m["protocol_label"], "mqtt");
    assert_eq!(m["bytes_seen"], bad_connect.len());
    let hex: String = bad_connect.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(m["first_bytes_hex"], hex.as_str());

    let ev = srv.wait_for(1, by_reason("first_packet_not_connect")).await;
    assert_eq!(ev[0].metadata["bytes_seen"], 2);
    assert_eq!(ev[0].metadata["first_bytes_hex"], "c000");
    let ev = srv.wait_for(1, by_reason("bad_remaining_length")).await;
    assert_eq!(ev[0].metadata["first_bytes_hex"], "1080808080");
    srv.wait_for(1, by_reason("oversize_declaration")).await;
    srv.handle.abort();
}

#[tokio::test]
async fn silent_connections_and_valid_sessions_emit_no_malformed_event() {
    let srv = TestServer::start().await;
    let bounds_idle = Client::connect(srv.addr).await; // sends nothing, then drops
    drop(bounds_idle);
    let mut ok = Client::connect(srv.addr).await;
    ok.handshake().await;
    drop(ok);
    srv.wait_for(2, is_signal(SIGNAL_HONEYPOT_SESSION_END))
        .await;
    let malformed = srv
        .events()
        .await
        .into_iter()
        .filter(|e| e.metadata.get("malformed").is_some())
        .count();
    assert_eq!(malformed, 0);
    srv.handle.abort();
}

#[tokio::test]
async fn session_end_event_carries_the_counts() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    let connect = connect_with_creds();
    client.handshake().await;

    let mut publish = lenp(b"t");
    publish.extend_from_slice(b"x");
    let publish_pkt = packet(0x30, &publish);
    client.send(&publish_pkt).await;
    client.send(&publish_pkt).await;
    let mut sub = vec![0x00, 0x01];
    sub.extend(lenp(b"a/b"));
    sub.push(0);
    let sub_pkt = packet(0x82, &sub);
    client.send(&sub_pkt).await;
    assert_eq!(client.read_n(5).await, vec![0x90, 0x03, 0x00, 0x01, 0x00]);
    let ping = packet(0xC0, &[]);
    client.send(&ping).await;
    assert_eq!(client.read_n(2).await, vec![0xD0, 0x00]);
    let disconnect = packet(0xE0, &[]);
    client.send(&disconnect).await;
    client.expect_closed().await;

    let ends = srv
        .wait_for(1, is_signal(SIGNAL_HONEYPOT_SESSION_END))
        .await;
    assert_eq!(
        ends.len(),
        1,
        "exactly one session-end event per connection"
    );
    let m = &ends[0].metadata;
    assert_eq!(m["protocol_label"], "mqtt");
    assert_eq!(m["client_id"], "scanner-01");
    // CONNECT, 2 PUBLISH, SUBSCRIBE, PINGREQ, DISCONNECT.
    assert_eq!(m["packets"], 6);
    assert_eq!(m["publishes"], 2);
    assert_eq!(m["subscribes"], 1);
    let sent =
        connect.len() + 2 * publish_pkt.len() + sub_pkt.len() + ping.len() + disconnect.len();
    assert_eq!(m["bytes_in"], sent);
    assert!(m["duration_ms"].is_u64());
    assert!(!ends[0].authenticated);
    assert_eq!(ends[0].sensor, "mqtt");
    srv.handle.abort();
}

#[tokio::test]
async fn keepalive_bounds_the_idle_wait_after_connect() {
    // idle_timeout is 5 s; a keepalive of 1 s closes the silent client at 1.5 s, not 5 s.
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client
        .send(&connect_v5_packet(0x02, 1, &[], &lenp(b"quiet")))
        .await;
    assert_eq!(client.read_n(5).await, V5_CONNACK.to_vec());
    let started = std::time::Instant::now();
    client.expect_closed().await;
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(1300) && waited < Duration::from_secs(3),
        "closed after {waited:?}, expected about 1.5x the 1 s keepalive"
    );
    srv.wait_for(1, is_signal(SIGNAL_HONEYPOT_SESSION_END))
        .await;
    srv.handle.abort();
}

#[tokio::test]
async fn keepalive_zero_leaves_the_idle_timeout_in_charge() {
    let bounds = ConnectionBounds {
        idle_timeout: Duration::from_millis(600),
        ..test_bounds()
    };
    let srv = TestServer::start_with_bounds(bounds).await;
    let mut client = Client::connect(srv.addr).await;
    client
        .send(&connect_v5_packet(0x02, 0, &[], &lenp(b"no-ka")))
        .await;
    assert_eq!(client.read_n(5).await, V5_CONNACK.to_vec());
    let started = std::time::Instant::now();
    client.expect_closed().await;
    assert!(started.elapsed() >= Duration::from_millis(500));
    srv.handle.abort();
}

#[tokio::test]
async fn every_connect_across_connections_is_a_login_attempt() {
    // Accept-all auth stays: each connection's CONNECT, whatever the credential, is captured.
    let srv = TestServer::start().await;
    for i in 0..5u8 {
        let mut client = Client::connect(srv.addr).await;
        let mut rest = lenp(format!("brute-{i}").as_bytes());
        rest.extend(lenp(b"admin"));
        rest.extend(lenp(format!("guess-{i}").as_bytes()));
        client.send(&connect_packet(4, 0xC2, &rest)).await;
        assert_eq!(client.read_n(4).await, vec![0x20, 0x02, 0x00, 0x00]);
    }
    let logins = srv
        .wait_for(5, is_signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT))
        .await;
    assert_eq!(logins.len(), 5);
    assert!(logins.iter().all(|e| e.authenticated));
    assert!(!srv.raw_events().await.contains("guess-"));
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
    // Printed before the asserts so a panic's captured output names the failing case.
    eprintln!("malformed case: {what}");
    let mut client = Client::connect(srv.addr).await;
    let _ = client.stream.write_all(bytes).await;
    client.expect_closed().await;
    let mut probe = Client::connect(srv.addr).await;
    probe.handshake().await;
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

impl TestServer {
    /// The hand-off worker stores and fsyncs the body before it appends the event, off the
    /// connection's response path, so poll with a generous deadline rather than a fixed sleep.
    async fn wait_for_uploads(&self, n: usize) -> Vec<SensorEvent> {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let uploads = self.uploads().await;
            if uploads.len() >= n {
                return uploads;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {n} upload event(s), saw {}",
                uploads.len()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn elf_like(len: usize) -> Vec<u8> {
    let mut b = b"\x7fELF\x02\x01\x01\x00".to_vec();
    b.extend((0..len - b.len()).map(|i| (i % 251) as u8 | 0x80));
    b
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[tokio::test]
async fn binary_publish_is_spooled_and_text_publish_is_not() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;

    let text = br#"{"cmd":"status","id":7}"#;
    let mut t = lenp(b"dev/status");
    t.extend_from_slice(text);
    client.send(&packet(0x30, &t)).await;

    let payload = elf_like(4096);
    let mut b = lenp(b"fw/update");
    b.extend_from_slice(&[0x12, 0x34]);
    b.extend_from_slice(&payload);
    client.send(&packet(0x3B, &b)).await; // qos1, dup, retain
    assert_eq!(client.read_n(4).await, vec![0x40, 0x02, 0x12, 0x34]);

    let uploads = srv.wait_for_uploads(1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let uploads_after = srv.uploads().await;
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads_after.len(), 1, "the text PUBLISH is never spooled");

    let up = &uploads_after[0];
    let sample = up
        .sample
        .as_ref()
        .expect("a spooled PUBLISH carries a sample");
    assert_eq!(sample.sha256, sha256_hex(&payload));
    assert_eq!(sample.size, payload.len() as u64);
    assert_eq!(sample.orig_name, "fw/update");
    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, payload, "the spooled file is exactly the payload");
    let m = &up.metadata;
    assert_eq!(m["protocol_label"], "mqtt");
    assert_eq!(m["topic"], "fw/update");
    assert_eq!(m["qos"], 1);
    assert_eq!(m["retain"], true);
    assert_eq!(m["dup"], true);
    assert_eq!(m["capture_reason"], "binary_publish_payload");
    assert_eq!(m["wire_size"], payload.len());
    assert_eq!(m["truncated"], false);
    assert_eq!(m["complete"], true);
    assert!(up.authenticated);
    assert_eq!(up.sensor, "mqtt");
    assert!(up.occurrence_id.is_some());

    // Both PUBLISHes keep their metadata event, and only the spooled one carries a sample.
    let publishes = srv.wait_for(2, command("PUBLISH")).await;
    assert_eq!(publishes.len(), 2);
    assert!(publishes.iter().all(|e| e.sample.is_none()));
    let text_event = publishes
        .iter()
        .find(|e| e.metadata["topic"] == "dev/status")
        .unwrap();
    assert_eq!(text_event.metadata["payload_preview_encoding"], "text");

    assert_eq!(srv.budget.current_bytes(), 0, "released after spooling");
    srv.handle.abort();
}

#[tokio::test]
async fn level5_binary_publish_spools_only_the_payload_after_the_properties_block() {
    let srv = TestServer::start().await;
    let mut client = Client::connect(srv.addr).await;
    client.handshake_v5().await;

    let payload = elf_like(600);
    let props = [vec![0x23, 0x00, 0x05], prop_pair(b"trace", &[b'x'; 200])].concat();
    let mut p = lenp(b"cmd/exec");
    p.extend(block(&props));
    p.extend_from_slice(&payload);
    client.send(&packet(0x30, &p)).await;

    let uploads = srv.wait_for_uploads(1).await;
    let sample = uploads[0].sample.as_ref().unwrap();
    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, payload);
    assert_eq!(uploads[0].metadata["topic_alias"], 5);
    srv.handle.abort();
}

#[tokio::test]
async fn binary_publish_that_exhausts_the_budget_keeps_its_prefix() {
    let srv = TestServer::start_with_capture_budget(CAPTURE_CHUNK_BYTES).await;
    let kept = CAPTURE_CHUNK_BYTES as usize;
    let payload = elf_like(100_000);
    let mut p = lenp(b"big");
    p.extend_from_slice(&payload);
    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;
    client.send(&packet(0x30, &p)).await;

    let uploads = srv.wait_for_uploads(1).await;
    let sample = uploads[0].sample.as_ref().unwrap();
    assert_eq!(sample.size, kept as u64, "the prefix that fit is retained");
    assert_eq!(uploads[0].metadata["truncated"], true);
    assert_eq!(uploads[0].metadata["complete"], false);
    assert_eq!(uploads[0].metadata["wire_size"], payload.len());
    assert_eq!(uploads[0].metadata["end_reason"], "capture_memory_budget");
    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, payload[..kept]);
    assert_eq!(srv.handoff.truncated_capture_count(), 1);
    srv.wait_for_budget_current(0).await;
    assert!(srv.budget.high_water_bytes() <= CAPTURE_CHUNK_BYTES);

    // The room freed by spooling serves the next payload in full.
    let small = elf_like(64);
    let mut s = lenp(b"small");
    s.extend_from_slice(&small);
    client.send(&packet(0x30, &s)).await;
    let uploads = srv.wait_for_uploads(2).await;
    assert_eq!(uploads[1].sample.as_ref().unwrap().size, 64);
    assert_eq!(uploads[1].metadata["complete"], true);
    srv.handle.abort();
}

#[tokio::test]
async fn binary_publish_with_no_budget_left_is_refused_but_its_metadata_event_survives() {
    let srv = TestServer::start_with_capture_budget(CAPTURE_CHUNK_BYTES).await;
    let holder = srv
        .budget
        .try_reserve(CAPTURE_CHUNK_BYTES)
        .expect("the whole budget is free at start");

    let mut client = Client::connect(srv.addr).await;
    client.handshake().await;
    let mut p = lenp(b"starved");
    p.extend_from_slice(&elf_like(512));
    client.send(&packet(0x30, &p)).await;

    srv.wait_for(1, command("PUBLISH")).await;
    assert_eq!(srv.handoff.refused_capture_count(), 1);
    assert_eq!(srv.handoff.truncated_capture_count(), 0);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        srv.uploads().await.is_empty(),
        "zero bytes buffered, no sample"
    );

    drop(holder);
    let mut ok = lenp(b"later");
    ok.extend_from_slice(&elf_like(512));
    client.send(&packet(0x30, &ok)).await;
    let uploads = srv.wait_for_uploads(1).await;
    assert_eq!(uploads[0].metadata["topic"], "later");
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
