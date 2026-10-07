//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. The plain and TLS listeners (6379 and 6380 in a
//! deployment) write one log, so nothing but this stamp tells their events apart by port.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, server_config_from_pem};
use sensor_wire::SensorEvent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// Waits until `done` holds, then a little longer so a straggling event is read too.
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

#[tokio::test]
async fn plain_and_tls_events_carry_their_own_listeners_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let any = "127.0.0.1:0".parse().unwrap();
    let (plain, plain_handle) =
        sensor_redis::start_test_server(any, log.clone(), wan.clone(), bounds())
            .await
            .unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let tls_server = TlsServer::from_config(
        server_config_from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let (tls, tls_handle) =
        sensor_redis::start_test_server_tls(any, log.clone(), wan, bounds(), tls_server)
            .await
            .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    // One plain session, two TLS sessions.
    let mut conn = TcpStream::connect(plain).await.unwrap();
    conn.write_all(b"PING\r\n").await.unwrap();
    let mut reply = [0u8; 7];
    conn.read_exact(&mut reply).await.unwrap();
    drop(conn);
    for _ in 0..2 {
        let tcp = TcpStream::connect(tls).await.unwrap();
        let mut conn = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        conn.write_all(b"PING\r\n").await.unwrap();
        conn.read_exact(&mut reply).await.unwrap();
    }

    let seen = wait_for(&log, |seen| {
        let tls_n = seen.iter().filter(|e| e.metadata["tls"] == true).count();
        let plain_n = seen.len() - tls_n;
        tls_n >= 2 && plain_n >= 1
    })
    .await;
    for e in &seen {
        assert_eq!(e.protocol, "tcp", "{e:?}");
        let want = if e.metadata["tls"] == true {
            tls.port()
        } else {
            plain.port()
        };
        assert_eq!(e.metadata["local_port"], want, "{e:?}");
    }
    plain_handle.abort();
    tls_handle.abort();
}
