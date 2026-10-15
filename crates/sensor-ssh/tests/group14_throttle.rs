//! The `diffie-hellman-group14-sha256` throttle (`transport::group14_gate`) seen from the wire.
//!
//! A group14 exchange costs the sensor about 3.5 ms of CPU against curve25519's 1 ms, and a client
//! picks it freely before authenticating. These tests saturate the gate with real sockets and show
//! that the excess is refused with `SSH_MSG_DISCONNECT` within the bounded wait, that the refusal
//! is in the session-end event, and that curve25519 clients do not notice. The gate is per
//! process and these tests share one, so they run one at a time.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_ssh::transport::group14_gate::{GROUP14_PERMITS, GROUP14_WAIT, Group14Gate};
use sensor_ssh::transport::{
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS, SSH_MSG_DISCONNECT, SSH_MSG_KEX_ECDH_REPLY,
    SSH_MSG_KEXINIT, SshPacket, kex, parse_kexinit, read_packet_unencrypted,
    write_packet_unencrypted,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration: Duration::from_secs(120),
        max_captured_bytes: 1_000_000,
        max_concurrent: 256,
    }
}

async fn start(dir: &Path) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.join("events.jsonl"),
        dir.join("spool"),
        dir.join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "OpenSSH_8.9p1".to_string(),
        "test".to_string(),
        dir.join("outbox"),
    )
    .await
    .unwrap()
}

fn kexinit_offering(kex: &str) -> Vec<u8> {
    fn list(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    let mut out = vec![SSH_MSG_KEXINIT];
    out.extend_from_slice(&[0x5a; 16]);
    list(&mut out, kex);
    list(&mut out, "ssh-ed25519");
    list(&mut out, "chacha20-poly1305@openssh.com");
    list(&mut out, "chacha20-poly1305@openssh.com");
    list(&mut out, "hmac-sha2-256");
    list(&mut out, "hmac-sha2-256");
    list(&mut out, "none");
    list(&mut out, "none");
    list(&mut out, "");
    list(&mut out, "");
    out.push(0);
    out.extend_from_slice(&0u32.to_be_bytes());
    out
}

/// Connect and send a KEXINIT offering only `kex`, stopping before the exchange's own message.
async fn connect_offering(addr: SocketAddr, kex: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut line = Vec::new();
    loop {
        let b = stream.read_u8().await.unwrap();
        line.push(b);
        if b == b'\n' {
            break;
        }
    }
    stream.write_all(b"SSH-2.0-OpenSSH_8.9\r\n").await.unwrap();
    let server_kexinit = read_packet_unencrypted(&mut stream).await.unwrap().payload;
    parse_kexinit(&server_kexinit).unwrap();
    write_packet_unencrypted(&mut stream, &kexinit_offering(kex))
        .await
        .unwrap();
    stream
}

/// A group14 client: `e = 2` is inside the range RFC 4253 section 8 allows.
async fn group14_client(addr: SocketAddr) -> SshPacket {
    let mut stream = connect_offering(addr, "diffie-hellman-group14-sha256").await;
    // byte(30) + mpint(2)
    write_packet_unencrypted(&mut stream, &[30, 0, 0, 0, 1, 2])
        .await
        .unwrap();
    tokio::time::timeout(
        GROUP14_WAIT + Duration::from_secs(10),
        read_packet_unencrypted(&mut stream),
    )
    .await
    .expect("the sensor never answered a group14 client")
    .expect("the sensor closed on a group14 client without an answer")
}

async fn curve25519_client(addr: SocketAddr) -> SshPacket {
    let mut stream = connect_offering(addr, "curve25519-sha256").await;
    let (_secret, init) = kex::build_client_ecdh_init();
    write_packet_unencrypted(&mut stream, &init).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), read_packet_unencrypted(&mut stream))
        .await
        .expect("the sensor never answered a curve25519 client")
        .unwrap()
}

fn session_ends(log: &Path) -> Vec<sensor_wire::SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).unwrap())
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_SESSION_END)
        .collect()
}

#[tokio::test]
async fn group14_clients_are_served_when_the_gate_has_room() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;

    // Back to back: the permit is handed back after the pacing hold, not kept.
    for _ in 0..5 {
        let reply = group14_client(addr).await;
        assert_eq!(
            reply.payload[0], SSH_MSG_KEX_ECDH_REPLY,
            "{:?}",
            reply.payload
        );
    }

    // A burst is queued, not refused. Three, because an unoptimized test build runs the modular
    // exponentiation far slower than the release build the sensor ships as, and the queue must
    // still fit inside the wait there.
    let burst: Vec<_> = (0..3).map(|_| tokio::spawn(group14_client(addr))).collect();
    for client in burst {
        let reply = client.await.unwrap();
        assert_eq!(
            reply.payload[0], SSH_MSG_KEX_ECDH_REPLY,
            "{:?}",
            reply.payload
        );
    }
    handle.abort();
}

/// The pacing hold through the real server path: after a group14 reply the permit stays taken for
/// about as long as the exchange took, then frees. Handing it back at once (a plain drop where the
/// server calls `release_after`) would allow a full core and leaves the permit free right after
/// the reply, which this test rejects.
#[tokio::test]
async fn the_server_holds_the_group14_permit_for_the_exchange_cost_after_the_reply() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let gate = Group14Gate::global();

    // A previous test's pacing hold may still be running.
    let settle = Instant::now();
    while gate.available_permits() != GROUP14_PERMITS {
        assert!(
            settle.elapsed() < Duration::from_secs(5),
            "gate never freed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut stream = connect_offering(addr, "diffie-hellman-group14-sha256").await;
    let sent = Instant::now();
    write_packet_unencrypted(&mut stream, &[30, 0, 0, 0, 1, 2])
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(10),
        read_packet_unencrypted(&mut stream),
    )
    .await
    .expect("no reply")
    .unwrap();
    let cost = sent.elapsed();
    assert_eq!(reply.payload[0], SSH_MSG_KEX_ECDH_REPLY);

    let replied = Instant::now();
    assert_eq!(
        gate.available_permits(),
        0,
        "the permit was free as soon as the reply arrived"
    );
    while gate.available_permits() != GROUP14_PERMITS {
        assert!(
            replied.elapsed() < cost * 4 + Duration::from_secs(1),
            "never freed"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let held = replied.elapsed();
    assert!(
        held >= cost / 2,
        "permit held {held:?} after the reply, expected about the exchange cost {cost:?}"
    );
    handle.abort();
}

#[tokio::test]
async fn a_group14_client_that_finds_the_gate_full_is_disconnected_after_the_bounded_wait() {
    let _serial = ONE_AT_A_TIME.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;

    // Saturate the gate the way a flood of group14 exchanges would.
    let held: Vec<_> = {
        let mut held = Vec::new();
        for _ in 0..GROUP14_PERMITS {
            held.push(Group14Gate::global().acquire().await.unwrap());
        }
        held
    };

    let waited = Instant::now();
    let group14 = tokio::spawn(group14_client(addr));

    // While that client waits, curve25519 clients are answered at once.
    tokio::time::sleep(Duration::from_millis(200)).await;
    for _ in 0..3 {
        let began = Instant::now();
        let reply = curve25519_client(addr).await;
        assert_eq!(
            reply.payload[0], SSH_MSG_KEX_ECDH_REPLY,
            "{:?}",
            reply.payload
        );
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "curve25519 took {:?} while group14 was saturated",
            began.elapsed()
        );
    }
    assert!(
        !group14.is_finished(),
        "the group14 client was answered while the gate was full"
    );

    // The group14 client waits its bound, then is told why and let go.
    let packet = group14.await.unwrap();
    let elapsed = waited.elapsed();
    assert_eq!(
        packet.payload[0], SSH_MSG_DISCONNECT,
        "{:?}",
        packet.payload
    );
    let reason = u32::from_be_bytes(packet.payload[1..5].try_into().unwrap());
    assert_eq!(reason, SSH_DISCONNECT_TOO_MANY_CONNECTIONS);
    let text_len = u32::from_be_bytes(packet.payload[5..9].try_into().unwrap()) as usize;
    let text = std::str::from_utf8(&packet.payload[9..9 + text_len]).unwrap();
    assert!(text.contains("diffie-hellman-group14-sha256"), "{text}");
    assert!(
        elapsed >= GROUP14_WAIT && elapsed < GROUP14_WAIT + Duration::from_secs(3),
        "refused after {elapsed:?}, wait is {GROUP14_WAIT:?}"
    );

    // The session-end event records the refusal.
    let log = dir.path().join("events.jsonl");
    let mut refused = None;
    for _ in 0..100 {
        refused = session_ends(&log)
            .into_iter()
            .find(|e| e.metadata.get("kex_refused").is_some());
        if refused.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let refused = refused.expect("no session-end event recorded the refusal");
    assert_eq!(refused.metadata["kex_refused"], "group14_busy");
    assert_eq!(refused.metadata["phase"], "key_exchange");
    assert_eq!(
        refused.metadata["client_kex"]["kex"],
        "diffie-hellman-group14-sha256"
    );

    // Releasing the gate admits the next group14 client.
    drop(held);
    let reply = group14_client(addr).await;
    assert_eq!(
        reply.payload[0], SSH_MSG_KEX_ECDH_REPLY,
        "{:?}",
        reply.payload
    );
    handle.abort();
}
