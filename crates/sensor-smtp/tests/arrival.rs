//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. SMTP runs three listeners as one sensor writing
//! one log (25, 587 and implicit-TLS 465 in a deployment); the two plaintext ones differ in
//! nothing but this stamp.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, server_config_from_pem};
use sensor_smtp::ListenerKind;
use sensor_wire::{SIGNAL_HONEYPOT_CONNECTION, SensorEvent};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

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

fn connections_by_port(events: &[SensorEvent]) -> HashMap<u16, usize> {
    let mut out = HashMap::new();
    for e in events
        .iter()
        .filter(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
    {
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        *out.entry(port).or_insert(0) += 1;
    }
    out
}

/// Reads the banner, then QUITs.
async fn session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: S) {
    let mut reader = BufReader::new(stream);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();
    assert!(banner.starts_with("220"), "{banner}");
    reader.get_mut().write_all(b"QUIT\r\n").await.unwrap();
    let mut bye = String::new();
    let _ = reader.read_line(&mut bye).await;
}

#[tokio::test]
async fn each_of_three_listeners_stamps_its_own_port() {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server = TlsServer::from_config(
        server_config_from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let started = sensor_smtp::start_listeners(
        vec![
            (any, ListenerKind::Plain { tls: None }),
            (any, ListenerKind::Plain { tls: None }),
            (any, ListenerKind::Implicit { tls: server }),
        ],
        log.clone(),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
    )
    .await
    .unwrap();
    let (main, submission, implicit) = (started[0].0, started[1].0, started[2].0);

    // 1, 2 and 3 sessions, so no assignment of events to the wrong listener can match.
    session(TcpStream::connect(main).await.unwrap()).await;
    for _ in 0..2 {
        session(TcpStream::connect(submission).await.unwrap()).await;
    }
    for _ in 0..3 {
        let tcp = TcpStream::connect(implicit).await.unwrap();
        let tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        session(tls).await;
    }

    let want = HashMap::from([
        (main.port(), 1),
        (submission.port(), 2),
        (implicit.port(), 3),
    ]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while connections_by_port(&events(&log)) != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "connection events per port: {:?}, want {want:?}; events: {:?}",
            connections_by_port(&events(&log)),
            events(&log)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for e in events(&log) {
        assert_eq!(e.protocol, "tcp", "{e:?}");
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        assert!(want.contains_key(&port), "{e:?}");
        assert_eq!(port == implicit.port(), e.metadata["tls"] == true, "{e:?}");
    }
    for (_, handle) in started {
        handle.abort();
    }
}
