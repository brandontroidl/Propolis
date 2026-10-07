//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. The plain control listener and implicit FTPS
//! (21 and 990 in a deployment) are one sensor writing one log.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, TlsServer,
    WanResolver, server_config_from_pem,
};
use sensor_ftp::ListenerKind;
use sensor_wire::SensorEvent;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
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

/// Banner, a login, QUIT.
async fn session<S: AsyncRead + AsyncWrite + Unpin>(stream: S) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220"), "{line}");
    for command in ["USER anonymous\r\n", "PASS guest\r\n", "QUIT\r\n"] {
        reader
            .get_mut()
            .write_all(command.as_bytes())
            .await
            .unwrap();
        line.clear();
        let _ = reader.read_line(&mut line).await;
    }
}

#[tokio::test]
async fn plain_and_implicit_tls_events_carry_their_own_listeners_port() {
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
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (started, _handoff) = sensor_ftp::start_listeners(
        vec![
            (any, ListenerKind::Plain { tls: None }),
            (any, ListenerKind::Implicit { tls: server }),
        ],
        log.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "test".into(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .await
    .unwrap();
    let (plain, implicit) = (started[0].0, started[1].0);

    session(TcpStream::connect(plain).await.unwrap()).await;
    for _ in 0..2 {
        let tcp = TcpStream::connect(implicit).await.unwrap();
        session(
            connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap(),
        )
        .await;
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let seen = events(&log);
        let tls_n = seen.iter().filter(|e| e.metadata["tls"] == true).count();
        if tls_n >= 4 && seen.len() - tls_n >= 2 {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{seen:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    for e in events(&log) {
        assert_eq!(e.protocol, "tcp", "{e:?}");
        let want = if e.metadata["tls"] == true {
            implicit.port()
        } else {
            plain.port()
        };
        assert_eq!(e.metadata["local_port"], want, "{e:?}");
    }
    for (_, handle) in started {
        handle.abort();
    }
}
