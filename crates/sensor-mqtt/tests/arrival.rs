//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. The plain and TLS listeners (1883 and 8883 in a
//! deployment) share one log and one capture hand-off.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, TlsServer,
    WanResolver, server_config_from_pem,
};
use sensor_wire::SensorEvent;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

fn lenp(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

/// A 3.1.1 CONNECT with a client id, user name and password.
fn connect_packet() -> Vec<u8> {
    let mut body = lenp(b"MQTT");
    body.extend([4, 0xC2]);
    body.extend(30u16.to_be_bytes());
    body.extend(lenp(b"scanner-01"));
    body.extend(lenp(b"admin"));
    body.extend(lenp(b"secret"));
    let mut packet = vec![0x10, body.len() as u8];
    packet.extend(body);
    packet
}

async fn session<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    stream.write_all(&connect_packet()).await.unwrap();
    let mut connack = [0u8; 4];
    stream.read_exact(&mut connack).await.unwrap();
}

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Distinct sessions per stamped port. A missing stamp counts under port 0.
fn sessions_by_port(events: &[SensorEvent]) -> HashMap<u16, usize> {
    let mut sessions: HashMap<u16, HashSet<_>> = HashMap::new();
    for e in events {
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        sessions.entry(port).or_default().insert(e.session_id);
    }
    sessions.into_iter().map(|(p, s)| (p, s.len())).collect()
}

#[tokio::test]
async fn plain_and_tls_sessions_carry_their_own_listeners_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let handoff = sensor_mqtt::new_capture_handoff(
        log.clone(),
        dir.path().join("spool"),
        "test".into(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .unwrap();
    let any = "127.0.0.1:0".parse().unwrap();
    let (plain, plain_handle) =
        sensor_mqtt::start_plain_listener(any, log.clone(), wan.clone(), bounds(), handoff.clone())
            .await
            .unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server = TlsServer::from_config(
        server_config_from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let (tls, tls_handle) =
        sensor_mqtt::start_tls_listener(any, log.clone(), wan, bounds(), handoff, server)
            .await
            .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    session(TcpStream::connect(plain).await.unwrap()).await;
    for _ in 0..2 {
        let tcp = TcpStream::connect(tls).await.unwrap();
        session(
            connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap(),
        )
        .await;
    }

    let want = HashMap::from([(plain.port(), 1), (tls.port(), 2)]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while sessions_by_port(&events(&log)) != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "sessions per port {:?}, want {want:?}; {:?}",
            sessions_by_port(&events(&log)),
            events(&log)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(events(&log).iter().all(|e| e.protocol == "tcp"));
    plain_handle.abort();
    tls_handle.abort();
}
