//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. The plain and TLS listeners are one sensor writing
//! one log, the way `main` runs them, so 80 and 443 must not be told apart by anything but this.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, server_config_from_pem};
use sensor_wire::SensorEvent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const GET_ROOT: &[u8] = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
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

async fn wait_for(log: &Path, done: impl Fn(&[SensorEvent]) -> bool) -> Vec<SensorEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let seen = events(log);
        if done(&seen) {
            return seen;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out; events so far: {seen:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Events per `(protocol, local_port)`. An event without the port counts under port 0, which no
/// listener here is bound to, so a missing stamp fails the comparison rather than vanishing.
fn by_listener(events: &[SensorEvent]) -> HashMap<(String, u16), usize> {
    let mut out = HashMap::new();
    for e in events {
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        *out.entry((e.protocol.clone(), port)).or_insert(0) += 1;
    }
    out
}

#[tokio::test]
async fn plain_and_tls_events_carry_their_own_listeners_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let any = "127.0.0.1:0".parse().unwrap();
    let (plain, plain_handle) =
        sensor_http::start_test_server(any, log.clone(), wan.clone(), bounds())
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
        sensor_http::start_test_server_tls(any, log.clone(), wan, bounds(), tls_server)
            .await
            .unwrap();
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert.der().to_vec()))
        .unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    // One request over plain HTTP, two over TLS: different counts per listener, so attributing
    // every event to one port, or swapping them, cannot pass.
    let mut conn = TcpStream::connect(plain).await.unwrap();
    conn.write_all(GET_ROOT).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut Vec::new())).await;
    for _ in 0..2 {
        let tcp = TcpStream::connect(tls).await.unwrap();
        let mut conn = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        conn.write_all(GET_ROOT).await.unwrap();
        let _ =
            tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut Vec::new())).await;
    }

    let seen = wait_for(&log, |seen| {
        let plain_n = seen
            .iter()
            .filter(|e| e.metadata.get("tls").is_none())
            .count();
        let tls_n = seen.iter().filter(|e| e.metadata["tls"] == true).count();
        plain_n >= 2 && tls_n >= 4
    })
    .await;
    let counts = by_listener(&seen);
    let plain_n = seen
        .iter()
        .filter(|e| e.metadata.get("tls").is_none())
        .count();
    let tls_n = seen.len() - plain_n;
    assert_eq!(
        counts,
        HashMap::from([
            (("tcp".to_string(), plain.port()), plain_n),
            (("tcp".to_string(), tls.port()), tls_n),
        ]),
        "{seen:?}"
    );
    for e in &seen {
        let on_tls = e.metadata["local_port"] == tls.port();
        assert_eq!(on_tls, e.metadata["tls"] == true, "{e:?}");
    }
    plain_handle.abort();
    tls_handle.abort();
}
