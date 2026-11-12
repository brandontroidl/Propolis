//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. DNS serves UDP and TCP on the SAME port and DoT
//! on another, all as one sensor writing one log. Its UDP socket is its own rather than
//! `run_udp_listener`'s, and its rate-limit summaries leave from a separate task (or from the
//! shutdown flush), so those are the paths most likely to lose the stamp.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, Rate, RateLimitConfig, TlsServer, WanResolver};
use sensor_wire::SensorEvent;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 262_144,
        max_concurrent: 100,
    }
}

/// One query per source per burst, so a short flood is mostly summarized.
fn tight(window: Duration) -> RateLimitConfig {
    let nz = |n| NonZeroU32::new(n).unwrap();
    let mut config =
        RateLimitConfig::new(Rate::new(nz(1), nz(1)), Rate::new(nz(100_000), nz(100_000)));
    config.summary_window = window;
    config
}

fn example(id: u16) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend(id.to_be_bytes());
    m.extend(0x0100u16.to_be_bytes());
    m.extend([0, 1, 0, 0, 0, 0, 0, 0]);
    for label in [&b"example"[..], b"com"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label);
    }
    m.push(0);
    m.extend(1u16.to_be_bytes());
    m.extend(1u16.to_be_bytes());
    m
}

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn wait_for(log: &Path, done: impl Fn(&[SensorEvent]) -> bool) -> Vec<SensorEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !done(&events(log)) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out; events so far: {:?}",
            events(log)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    events(log)
}

fn rate_limited(e: &SensorEvent) -> bool {
    e.metadata["query_status"] == "rate_limited"
}

/// One framed query over a stream, and its framed reply.
async fn framed_query<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) {
    let msg = example(7);
    stream
        .write_all(&(msg.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&msg).await.unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut reply).await.unwrap();
}

async fn flood(to: SocketAddr, n: u16) {
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for id in 0..n {
        client.send_to(&example(id), to).await.unwrap();
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn udp_tcp_and_dot_events_and_rate_limit_summaries_carry_their_own_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let plain = sensor_dns::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        wan.clone(),
        bounds(),
        tight(Duration::from_millis(200)),
    )
    .await
    .unwrap();
    assert_eq!(plain.udp.port(), plain.tcp.port());

    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server = sensor_framework::server_config_from_pem(
        cert.pem().as_bytes(),
        signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let (dot, dot_handle) = sensor_dns::start_test_server_tls(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        wan,
        bounds(),
        TlsServer::from_config(server),
    )
    .await
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    flood(plain.udp, 10).await;
    framed_query(TcpStream::connect(plain.tcp).await.unwrap()).await;
    let tcp = TcpStream::connect(dot).await.unwrap();
    framed_query(
        connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap(),
    )
    .await;

    // The summary is written by the summary task once its 200 ms window ends.
    let seen = wait_for(&log, |seen| {
        seen.iter().any(rate_limited)
            && seen.iter().filter(|e| e.metadata["tls"] == true).count() >= 2
    })
    .await;
    let mut kinds = HashMap::new();
    for e in &seen {
        let (protocol, port, kind) = if e.metadata["tls"] == true {
            ("tcp", dot.port(), "dot")
        } else if e.metadata["transport"] == "udp" {
            let kind = if rate_limited(e) { "summary" } else { "udp" };
            ("udp", plain.udp.port(), kind)
        } else {
            ("tcp", plain.tcp.port(), "tcp")
        };
        assert_eq!(e.protocol, protocol, "{e:?}");
        assert_eq!(e.metadata["local_port"], port, "{e:?}");
        *kinds.entry(kind).or_insert(0) += 1;
    }
    for kind in ["udp", "summary", "tcp", "dot"] {
        assert!(kinds.contains_key(kind), "no {kind} event among {seen:?}");
    }
    plain.abort();
    dot_handle.abort();
}

/// The shutdown flush runs on `main`'s task, outside every per-datagram scope.
#[tokio::test]
async fn a_summary_flushed_at_shutdown_carries_the_udp_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let plain = sensor_dns::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        tight(Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    flood(plain.udp, 10).await;
    wait_for(&log, |seen| !seen.is_empty()).await;
    plain.abort();
    plain.flush_rate_limited().await;
    let summaries: Vec<SensorEvent> = events(&log).into_iter().filter(rate_limited).collect();
    assert_eq!(summaries.len(), 1, "{summaries:?}");
    assert_eq!(summaries[0].protocol, "udp");
    assert_eq!(summaries[0].metadata["local_port"], plain.udp.port());
}
