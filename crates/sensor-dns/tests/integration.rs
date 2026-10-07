//! UDP and TCP behavior against the real listeners, plus the static checks that keep the reply
//! surface to one budgeted UDP send and one framed TCP write.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sensor_dns::PlainListeners;
use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::{
    PROTO_TCP, PROTO_UDP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SensorEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const FLAG_RD: u16 = 0x0100;
const FLAG_CD: u16 = 0x0010;
const FLAG_AD: u16 = 0x0020;
const FLAG_QR: u16 = 0x8000;
const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const TYPE_IXFR: u16 = 251;
const TYPE_AXFR: u16 = 252;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_CH: u16 = 3;

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 262_144,
        max_concurrent: 100,
    }
}

struct Server {
    listeners: PlainListeners,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Server {
    async fn start() -> Server {
        Server::start_with(test_bounds(), HashMap::new()).await
    }

    async fn start_with(
        bounds: ConnectionBounds,
        wan: HashMap<std::net::IpAddr, std::net::IpAddr>,
    ) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let listeners = sensor_dns::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log.clone(),
            Arc::new(WanResolver::new(wan)),
            bounds,
        )
        .await
        .unwrap();
        Server {
            listeners,
            log,
            _dir: dir,
        }
    }

    fn events(&self) -> Vec<SensorEvent> {
        events(&self.log)
    }

    async fn wait_for(&self, what: &str, pred: impl Fn(&SensorEvent) -> bool) -> SensorEvent {
        wait_for(&self.log, what, pred).await
    }
}

/// Tolerates a missing log file: nothing emitted yet never creates it.
fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn wait_for(log: &Path, what: &str, pred: impl Fn(&SensorEvent) -> bool) -> SensorEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(e) = events(log).into_iter().find(&pred) {
            return e;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}: {:?}",
            events(log)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn query(id: u16, flags: u16, labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend(id.to_be_bytes());
    m.extend(flags.to_be_bytes());
    m.extend([0, 1, 0, 0, 0, 0, 0, 0]);
    for l in labels {
        m.push(l.len() as u8);
        m.extend_from_slice(l);
    }
    m.push(0);
    m.extend(qtype.to_be_bytes());
    m.extend(qclass.to_be_bytes());
    m
}

fn set_count(msg: &mut [u8], offset: usize, value: u16) {
    msg[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

/// Append an OPT RR (root owner, DO bit as given, options as (code, data)) and bump ARCOUNT.
fn with_opt(mut msg: Vec<u8>, udp_size: u16, do_bit: bool, options: &[(u16, &[u8])]) -> Vec<u8> {
    let mut rdata = Vec::new();
    for (code, data) in options {
        rdata.extend(code.to_be_bytes());
        rdata.extend((data.len() as u16).to_be_bytes());
        rdata.extend_from_slice(data);
    }
    msg.push(0);
    msg.extend(41u16.to_be_bytes());
    msg.extend(udp_size.to_be_bytes());
    msg.extend((if do_bit { 0x8000u32 } else { 0 }).to_be_bytes());
    msg.extend((rdata.len() as u16).to_be_bytes());
    msg.extend(rdata);
    let ar = u16::from_be_bytes([msg[10], msg[11]]) + 1;
    set_count(&mut msg, 10, ar);
    msg
}

fn example(id: u16) -> Vec<u8> {
    query(id, FLAG_RD, &[b"example", b"com"], TYPE_A, CLASS_IN)
}

/// The exact REFUSED echo the sensor must send for `msg` whose question ends at `end`.
fn expected_reply(msg: &[u8], end: usize) -> Vec<u8> {
    let mut out = msg[..end].to_vec();
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let rflags = FLAG_QR | (flags & (FLAG_RD | FLAG_CD)) | 5;
    out[2..4].copy_from_slice(&rflags.to_be_bytes());
    out[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    out
}

fn md<'a>(e: &'a SensorEvent, key: &str) -> &'a serde_json::Value {
    e.metadata.get(key).unwrap_or(&serde_json::Value::Null)
}

fn signals(e: &SensorEvent) -> Vec<String> {
    md(e, "probe_signals")
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

struct Client {
    socket: UdpSocket,
}

impl Client {
    async fn new() -> Client {
        Client {
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        }
    }

    async fn send(&self, to: SocketAddr, msg: &[u8]) {
        self.socket.send_to(msg, to).await.unwrap();
    }

    async fn recv_within(&self, wait: Duration) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(wait, self.socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => Some((buf[..n].to_vec(), from)),
            _ => None,
        }
    }

    async fn recv(&self) -> (Vec<u8>, SocketAddr) {
        self.recv_within(Duration::from_secs(3))
            .await
            .expect("expected a reply")
    }

    async fn assert_silent(&self, wait: Duration) {
        if let Some((got, from)) = self.recv_within(wait).await {
            panic!("expected no reply, got {got:?} from {from}");
        }
    }
}

#[tokio::test]
async fn udp_a_query_gets_one_refused_echo_no_larger_than_the_query() {
    let server = Server::start().await;
    let client = Client::new().await;
    let msg = example(0x4242);
    client.send(server.listeners.udp, &msg).await;
    let (reply, from) = client.recv().await;
    assert_eq!(from, server.listeners.udp);
    assert_eq!(reply, expected_reply(&msg, msg.len()));
    assert_eq!(u16::from_be_bytes([reply[2], reply[3]]), 0x8105);
    client.assert_silent(Duration::from_millis(150)).await;

    let e = server
        .wait_for("answered", |e| md(e, "query_status") == "answered")
        .await;
    assert_eq!(e.signal_type, SIGNAL_HONEYPOT_CONNECTION);
    assert_eq!(e.protocol, PROTO_UDP);
    assert_eq!(e.sensor, "dns");
    assert_eq!(md(&e, "reply_len"), msg.len() as u64);
    assert_eq!(md(&e, "query_len"), msg.len() as u64);
    assert_eq!(md(&e, "qname"), "example.com.");
    assert_eq!(e.source_ip, client.socket.local_addr().unwrap().ip());
    assert_eq!(server.events().len(), 1);
}

#[tokio::test]
async fn udp_reply_with_edns_drops_the_opt_and_records_it() {
    let server = Server::start().await;
    let client = Client::new().await;
    let base = example(7);
    let end = base.len();
    let msg = with_opt(
        base,
        4096,
        true,
        &[(10, &[1; 8]), (8, &[0, 1, 24, 0, 192, 0, 2])],
    );
    client.send(server.listeners.udp, &msg).await;
    let (reply, _) = client.recv().await;
    assert_eq!(reply, expected_reply(&msg, end));
    assert_eq!(&reply[10..12], &[0, 0], "ARCOUNT must be 0");
    assert!(reply.len() < msg.len());

    let e = server
        .wait_for("answered", |e| md(e, "query_status") == "answered")
        .await;
    let edns = md(&e, "edns");
    assert_eq!(edns["udp_payload_size"], 4096);
    assert_eq!(edns["do"], true);
    assert_eq!(edns["option_codes"], serde_json::json!([10, 8]));
}

async fn assert_rejected_silently(msg: Vec<u8>, reason: &str) {
    let server = Server::start().await;
    let client = Client::new().await;
    client.send(server.listeners.udp, &msg).await;
    client.assert_silent(Duration::from_millis(300)).await;
    let e = server
        .wait_for(reason, |e| md(e, "query_status") == "rejected")
        .await;
    assert_eq!(md(&e, "reject_reason"), reason);
    assert!(md(&e, "rcode").is_null() && md(&e, "reply_len").is_null());
    assert_eq!(server.events().len(), 1);
}

#[tokio::test]
async fn qr_set() {
    let mut msg = example(1);
    msg[2] |= 0x80;
    assert_rejected_silently(msg, "response_inbound").await;
}

#[tokio::test]
async fn opcode_notify() {
    let msg = query(1, 4 << 11, &[b"example", b"com"], 6, CLASS_IN);
    assert_rejected_silently(msg, "opcode").await;
}

#[tokio::test]
async fn qdcount_zero() {
    let mut msg = example(1);
    set_count(&mut msg, 4, 0);
    assert_rejected_silently(msg, "qdcount").await;
}

#[tokio::test]
async fn qdcount_two() {
    let mut msg = example(1);
    set_count(&mut msg, 4, 2);
    assert_rejected_silently(msg, "qdcount").await;
}

#[tokio::test]
async fn compression_pointer() {
    let mut msg = example(1);
    msg[12] = 0xC0;
    msg[13] = 0x0C;
    assert_rejected_silently(msg, "compression_pointer").await;
}

#[tokio::test]
async fn bad_label() {
    let mut msg = example(1);
    msg[12] = 0x47;
    assert_rejected_silently(msg, "bad_label").await;
}

#[tokio::test]
async fn name_over_255() {
    let l = [b'a'; 63];
    let last = [b'b'; 62];
    let msg = query(1, 0, &[&l, &l, &l, &last], TYPE_A, CLASS_IN);
    assert_rejected_silently(msg, "name_too_long").await;
}

#[tokio::test]
async fn truncated_qtype() {
    let msg = example(1);
    assert_rejected_silently(msg[..msg.len() - 3].to_vec(), "truncated_question").await;
}

#[tokio::test]
async fn ancount_nonzero() {
    let mut msg = example(1);
    set_count(&mut msg, 6, 1);
    assert_rejected_silently(msg, "answer_or_authority_present").await;
}

#[tokio::test]
async fn nscount_nonzero() {
    let mut msg = example(1);
    set_count(&mut msg, 8, 1);
    assert_rejected_silently(msg, "answer_or_authority_present").await;
}

#[tokio::test]
async fn a_datagram_shorter_than_a_header_gets_no_reply_and_no_event() {
    let server = Server::start().await;
    let client = Client::new().await;
    client.send(server.listeners.udp, &example(1)[..11]).await;
    client.assert_silent(Duration::from_millis(300)).await;
    // A valid query afterwards proves the listener processed the short one first and is alive.
    client.send(server.listeners.udp, &example(2)).await;
    client.recv().await;
    server
        .wait_for("answered", |e| md(e, "query_status") == "answered")
        .await;
    assert_eq!(server.events().len(), 1, "{:?}", server.events());
}

async fn answered_event(msg: &[u8]) -> SensorEvent {
    let server = Server::start().await;
    let client = Client::new().await;
    client.send(server.listeners.udp, msg).await;
    let (reply, _) = client.recv().await;
    assert!(reply.len() <= msg.len());
    assert_eq!(reply[3] & 0x0F, 5, "RCODE REFUSED");
    server
        .wait_for("answered", |e| md(e, "query_status") == "answered")
        .await
}

#[tokio::test]
async fn any_query_carries_amplification_probe() {
    let e = answered_event(&query(1, 0, &[b"example", b"com"], TYPE_ANY, CLASS_IN)).await;
    assert_eq!(signals(&e), vec!["amplification_probe"]);
}

#[tokio::test]
async fn chaos_version_bind_carries_chaos_fingerprint_probe() {
    let e = answered_event(&query(1, 0, &[b"version", b"bind"], TYPE_TXT, CLASS_CH)).await;
    assert_eq!(signals(&e), vec!["chaos_fingerprint_probe"]);
    assert_eq!(md(&e, "qclass_name"), "CH");
    assert_eq!(md(&e, "qname"), "version.bind.");
}

#[tokio::test]
async fn rd_query_carries_open_resolver_probe() {
    let e = answered_event(&example(1)).await;
    assert_eq!(signals(&e), vec!["open_resolver_probe"]);
}

#[tokio::test]
async fn axfr_over_udp_is_refused_and_carries_zone_transfer_probe() {
    let e = answered_event(&query(1, 0, &[b"example", b"com"], TYPE_AXFR, CLASS_IN)).await;
    assert_eq!(signals(&e), vec!["zone_transfer_probe"]);
    assert_eq!(md(&e, "qtype_name"), "AXFR");
}

/// The xorshift generator `sensor-tftp` uses for its fuzz tests.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A valid query with random labels, type, class, flags, optional OPT and trailing junk (the
/// same shape as the parser's property test).
fn generated_query(rng: &mut Rng) -> Vec<u8> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut wire = 1;
    for _ in 0..1 + rng.below(6) {
        let len = 1 + rng.below(20) as usize;
        if wire + 1 + len > 255 {
            break;
        }
        wire += 1 + len;
        labels.push((0..len).map(|_| rng.next() as u8).collect());
    }
    let flags = [FLAG_RD, FLAG_CD, FLAG_AD]
        .iter()
        .filter(|_| rng.below(2) == 0)
        .fold(0, |f, b| f | b);
    let refs: Vec<&[u8]> = labels.iter().map(Vec::as_slice).collect();
    let mut msg = query(
        rng.next() as u16,
        flags,
        &refs,
        rng.next() as u16,
        rng.next() as u16,
    );
    if rng.below(2) == 0 {
        let size = rng.next() as u16;
        msg = with_opt(msg, size, true, &[(10, &[3; 8])]);
    }
    for _ in 0..rng.below(33) {
        msg.push(rng.next() as u8);
    }
    msg
}

#[tokio::test]
async fn replies_never_exceed_queries_over_the_wire() {
    let server = Server::start().await;
    let client = Client::new().await;
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for _ in 0..50 {
        let msg = generated_query(&mut rng);
        client.send(server.listeners.udp, &msg).await;
        let (reply, _) = client.recv().await;
        assert!(reply.len() <= msg.len(), "{} > {}", reply.len(), msg.len());
        assert_eq!(&reply[0..2], &msg[0..2]);
    }
}

#[tokio::test]
async fn malformed_datagram_flood_never_kills_the_listener() {
    let server = Server::start().await;
    let client = Client::new().await;
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..200 {
        let len = rng.below(600) as usize;
        let mut msg: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Never a valid query by accident: QR set means no reply is ever owed.
        if msg.len() > 2 {
            msg[2] |= 0x80;
        }
        client.send(server.listeners.udp, &msg).await;
    }
    client.assert_silent(Duration::from_millis(300)).await;
    let msg = example(0x7777);
    client.send(server.listeners.udp, &msg).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let (reply, _) = client.recv().await;
        if reply[0..2] == [0x77, 0x77] {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
    }
}

#[tokio::test]
async fn wan_ip_is_attributed_from_the_bind_address() {
    let mut wan = HashMap::new();
    wan.insert(
        "127.0.0.1".parse().unwrap(),
        "198.51.100.4".parse().unwrap(),
    );
    let server = Server::start_with(test_bounds(), wan).await;
    let client = Client::new().await;
    client.send(server.listeners.udp, &example(1)).await;
    client.recv().await;
    let e = server
        .wait_for("answered", |e| md(e, "query_status") == "answered")
        .await;
    assert_eq!(e.wan_ip, Some("198.51.100.4".parse().unwrap()));
}

#[tokio::test]
async fn the_mixed_case_qname_is_recorded_verbatim() {
    let e = answered_event(&query(1, 0, &[b"ExAmPlE", b"CoM"], TYPE_A, CLASS_IN)).await;
    assert_eq!(md(&e, "qname"), "ExAmPlE.CoM.");
    assert_eq!(md(&e, "qname_mixed_case"), true);
}

// TCP.

fn framed(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

async fn read_framed(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut prefix = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut prefix))
        .await
        .expect("timed out waiting for a reply prefix")
        .ok()?;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut body))
        .await
        .expect("timed out waiting for a reply body")
        .ok()?;
    Some(body)
}

async fn assert_eof(stream: &mut TcpStream) {
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut rest))
        .await
        .expect("connection must close");
    assert!(read.is_ok() || rest.is_empty());
    assert!(rest.is_empty(), "unexpected bytes before EOF: {rest:?}");
}

#[tokio::test]
async fn tcp_query_gets_a_length_prefixed_refused_echo_and_connection_plus_query_events() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let msg = with_opt(example(0x0102), 1232, false, &[]);
    let end = example(0x0102).len();
    conn.write_all(&framed(&msg)).await.unwrap();
    let reply = read_framed(&mut conn).await.unwrap();
    assert_eq!(reply, expected_reply(&msg, end));
    drop(conn);

    let q = server
        .wait_for("query", |e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .await;
    assert_eq!(q.protocol, PROTO_TCP);
    assert_eq!(md(&q, "command"), "A example.com.");
    assert_eq!(md(&q, "msg_index"), 0);
    assert_eq!(md(&q, "query_len"), msg.len() as u64);
    assert_eq!(md(&q, "transport"), "tcp");
    let c = server
        .wait_for("connection", |e| {
            e.signal_type == SIGNAL_HONEYPOT_CONNECTION
        })
        .await;
    assert_eq!(c.protocol, PROTO_TCP);
    assert_eq!(c.session_id, q.session_id);
}

#[tokio::test]
async fn tcp_pipelined_queries_are_answered_in_order() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let mut batch = Vec::new();
    for id in [11u16, 22, 33] {
        batch.extend(framed(&example(id)));
    }
    conn.write_all(&batch).await.unwrap();
    for id in [11u16, 22, 33] {
        let reply = read_framed(&mut conn).await.unwrap();
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), id);
    }
    drop(conn);
    server.wait_for("third", |e| md(e, "msg_index") == 2).await;
    let indexes: Vec<u64> = server
        .events()
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .map(|e| md(e, "msg_index").as_u64().unwrap())
        .collect();
    assert_eq!(indexes, vec![0, 1, 2]);
}

#[tokio::test]
async fn tcp_oversize_length_prefix_is_rejected_unread_and_closes() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    conn.write_all(&4097u16.to_be_bytes()).await.unwrap();
    assert_eof(&mut conn).await;
    let e = server
        .wait_for("oversize", |e| md(e, "reject_reason") == "oversize")
        .await;
    assert_eq!(md(&e, "declared_len"), 4097);
    assert_eq!(md(&e, "query_len"), 0);
    assert_eq!(md(&e, "command"), "malformed");
}

#[tokio::test]
async fn tcp_short_message_is_rejected_and_closes() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    conn.write_all(&5u16.to_be_bytes()).await.unwrap();
    assert_eof(&mut conn).await;
    let e = server
        .wait_for("short", |e| md(e, "reject_reason") == "short_header")
        .await;
    assert_eq!(md(&e, "declared_len"), 5);
}

#[tokio::test]
async fn tcp_connection_closes_after_64_queries() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let mut batch = Vec::new();
    for id in 0..65u16 {
        batch.extend(framed(&example(id)));
    }
    conn.write_all(&batch).await.unwrap();
    for id in 0..64u16 {
        let reply = read_framed(&mut conn).await.expect("64 replies");
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), id);
    }
    assert_eof(&mut conn).await;
}

#[tokio::test]
async fn tcp_idle_connection_is_closed_within_the_read_timeout() {
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_millis(300),
        ..test_bounds()
    };
    let server = Server::start_with(bounds, HashMap::new()).await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let started = std::time::Instant::now();
    assert_eof(&mut conn).await;
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn tcp_max_captured_bytes_ends_the_connection() {
    let bounds = ConnectionBounds {
        max_captured_bytes: 100,
        ..test_bounds()
    };
    let server = Server::start_with(bounds, HashMap::new()).await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let label = [b'x'; 60];
    // 78 bytes plus the prefix: the first fits in 100, the second would not.
    let first = query(1, 0, &[&label], TYPE_A, CLASS_IN);
    let second = query(2, 0, &[&label], TYPE_A, CLASS_IN);
    assert_eq!(first.len(), 78);
    conn.write_all(&framed(&first)).await.unwrap();
    assert!(read_framed(&mut conn).await.is_some());
    conn.write_all(&framed(&second)).await.unwrap();
    assert_eof(&mut conn).await;
}

#[tokio::test]
async fn axfr_over_tcp_is_captured_and_refused() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let msg = query(5, 0, &[b"example", b"com"], TYPE_AXFR, CLASS_IN);
    conn.write_all(&framed(&msg)).await.unwrap();
    let reply = read_framed(&mut conn).await.unwrap();
    assert_eq!(reply[3] & 0x0F, 5);
    assert_eq!(reply, expected_reply(&msg, msg.len()));
    let e = server
        .wait_for("axfr", |e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .await;
    assert_eq!(md(&e, "command"), "AXFR example.com.");
    assert_eq!(signals(&e), vec!["zone_transfer_probe"]);
}

#[tokio::test]
async fn ixfr_over_tcp_with_an_soa_authority_is_accepted_and_refused() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let mut msg = query(6, 0, &[b"example", b"com"], TYPE_IXFR, CLASS_IN);
    let end = msg.len();
    msg.extend([0xC0, 0x0C]);
    msg.extend(6u16.to_be_bytes());
    msg.extend(1u16.to_be_bytes());
    msg.extend(0u32.to_be_bytes());
    msg.extend(22u16.to_be_bytes());
    msg.extend([0u8; 22]);
    set_count(&mut msg, 8, 1);
    conn.write_all(&framed(&msg)).await.unwrap();
    let reply = read_framed(&mut conn).await.unwrap();
    assert_eq!(reply, expected_reply(&msg, end));
    let e = server
        .wait_for("ixfr", |e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .await;
    assert_eq!(md(&e, "command"), "IXFR example.com.");
    assert_eq!(md(&e, "nscount"), 1);
    assert_eq!(md(&e, "query_status"), "answered");
}

#[tokio::test]
async fn tcp_malformed_question_is_rejected_without_reply_and_closes() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    let mut msg = example(1);
    msg[12] = 0xC0;
    msg[13] = 0x0C;
    conn.write_all(&framed(&msg)).await.unwrap();
    assert_eof(&mut conn).await;
    let e = server
        .wait_for("rejected", |e| md(e, "query_status") == "rejected")
        .await;
    assert_eq!(md(&e, "reject_reason"), "compression_pointer");
    assert_eq!(md(&e, "command"), "malformed");
}

#[tokio::test]
async fn tcp_events_have_no_tls_key() {
    let server = Server::start().await;
    let mut conn = TcpStream::connect(server.listeners.tcp).await.unwrap();
    conn.write_all(&framed(&example(1))).await.unwrap();
    read_framed(&mut conn).await.unwrap();
    drop(conn);
    server
        .wait_for("query", |e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .await;
    let events = server.events();
    assert_eq!(events.len(), 2);
    for e in &events {
        assert!(e.metadata.get("tls").is_none(), "tls key leaked: {e:?}");
    }
}

#[tokio::test]
async fn a_taken_tcp_port_fails_start_and_leaves_no_udp_listener() {
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = held.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = sensor_dns::start_test_server(
        addr,
        dir.path().join("e.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
    )
    .await;
    assert!(result.is_err(), "start must fail when TCP cannot bind");
    UdpSocket::bind(addr)
        .await
        .expect("the UDP socket of a failed start must have been released");
}

#[tokio::test]
async fn a_taken_udp_port_fails_start() {
    let held = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = held.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let result = sensor_dns::start_test_server(
        addr,
        dir.path().join("e.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        test_bounds(),
    )
    .await;
    assert!(result.is_err());
}

// Static checks.

fn non_test_source(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap();
    match text.find("#[cfg(test)]") {
        Some(at) => text[..at].to_string(),
        None => text,
    }
}

fn src_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn never_exec_static_check() {
    let mut found = Vec::new();
    for entry in src_files() {
        let content = std::fs::read_to_string(&entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found.push(entry.display().to_string());
        }
    }
    assert!(
        found.is_empty(),
        "sensor-dns must not spawn processes: {found:?}"
    );
}

/// The reply surface is one `send_to` (in guarded.rs, behind the reply gate) and one framed TCP
/// write (in stream.rs), and nothing dials out.
#[test]
fn never_amplifies_static_check() {
    let mut send_sites = Vec::new();
    let mut write_sites = Vec::new();
    for entry in src_files() {
        let src = non_test_source(&entry);
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        for banned in [
            "TcpStream::connect",
            "UdpSocket::connect",
            ".connect(",
            "TcpListener",
            ".send(",
            ".try_send(",
            ".try_send_to(",
            ".poll_send_to(",
            ".write(",
            ".write_buf(",
            ".write_vectored(",
            ".poll_write(",
        ] {
            assert!(
                !src.contains(banned),
                "{name} must not use {banned}: the only writes are the guarded send and the framed write"
            );
        }
        send_sites.extend(src.match_indices(".send_to(").map(|_| name.clone()));
        write_sites.extend(src.match_indices(".write_all(").map(|_| name.clone()));
        if name != "lib.rs" {
            assert!(
                !src.contains("UdpSocket::bind"),
                "{name} must not bind its own socket"
            );
        }
    }
    assert_eq!(
        send_sites,
        vec!["guarded.rs".to_string()],
        "exactly one UDP send site is allowed, and it is in guarded.rs"
    );
    assert_eq!(
        write_sites,
        vec!["stream.rs".to_string()],
        "exactly one stream write site is allowed, and it is in stream.rs"
    );
}

fn manifest() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap()
}

#[test]
fn sensor_dns_has_no_http_client_dependency() {
    let manifest = manifest();
    for banned in [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
    ] {
        assert!(
            !manifest.contains(banned),
            "sensor-dns must not depend on an HTTP client: {banned}"
        );
    }
}

#[test]
fn tokio_dependency_lacks_process_feature() {
    let manifest = manifest();
    let tokio_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("tokio"))
        .expect("tokio dependency");
    assert!(
        !tokio_line.contains("\"process\""),
        "tokio's process feature must stay off: {tokio_line}"
    );
}
