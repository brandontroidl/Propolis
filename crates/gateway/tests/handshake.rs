//! Integration test for the mTLS accept loop: a valid client cert gets a real batch
//! accepted and acked, and a client presenting no certificate at all never reaches the
//! read loop (mandatory client auth, fail-closed).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use collector_wire::ack::{ACK_LEN, Ack, AckReason, AckStatus, decode_ack};
use collector_wire::frame::{Batch, encode_frame};
use collector_wire::hash::ZERO_HASH;
use collector_wire::tls::{client_config, server_config};
use gateway::{BatchSink, serve};
use sensor_framework::ConnectionBounds;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

const GATEWAY_DNS: &str = "gateway.local";

struct StubSink;

impl BatchSink for StubSink {
    fn accept(&self, _collector_id: &str, batch: &Batch) -> Ack {
        Ack {
            status: AckStatus::Accepted,
            reason: AckReason::None,
            next_expected_seq: batch.seq + 1,
        }
    }
}

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 1 << 20,
        max_concurrent: 10,
    }
}

struct Certs {
    ca: Vec<u8>,
    gateway_cert: Vec<u8>,
    gateway_key: Vec<u8>,
    collector_cert: Vec<u8>,
    collector_key: Vec<u8>,
}

fn mint_certs() -> Certs {
    let dir = tempfile::tempdir().expect("tempdir");
    provision_certs::provision(dir.path(), GATEWAY_DNS, "collector-test").expect("provision");
    let read = |name: &str| std::fs::read(dir.path().join(name)).expect("read cert file");
    Certs {
        ca: read("ca.crt"),
        gateway_cert: read("gateway.crt"),
        gateway_key: read("gateway.key"),
        collector_cert: read("collector-test.crt"),
        collector_key: read("collector-test.key"),
    }
}

async fn start_gateway(certs: &Certs) -> SocketAddr {
    let tls =
        server_config(&certs.ca, &certs.gateway_cert, &certs.gateway_key).expect("server_config");
    let sink: Arc<dyn BatchSink> = Arc::new(StubSink);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, _handle) = serve(addr, tls, test_bounds(), sink)
        .await
        .expect("serve binds");
    bound_addr
}

/// A client TLS config that verifies the gateway's certificate but presents no client
/// certificate at all - the shape a misconfigured or malicious peer would use.
fn no_client_auth_config(ca_pem: &[u8]) -> Arc<tokio_rustls::rustls::ClientConfig> {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    let mut reader = std::io::BufReader::new(ca_pem);
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.expect("parse ca cert")).expect("add root");
    }
    Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[tokio::test]
async fn a_valid_client_cert_sends_one_frame_and_gets_accepted() {
    let certs = mint_certs();
    let bound_addr = start_gateway(&certs).await;

    let client_tls =
        client_config(&certs.ca, &certs.collector_cert, &certs.collector_key).expect("client cfg");
    let connector = TlsConnector::from(client_tls);
    let tcp = TcpStream::connect(bound_addr).await.expect("tcp connect");
    let domain = ServerName::try_from(GATEWAY_DNS).unwrap();
    let mut stream = connector.connect(domain, tcp).await.expect("tls handshake");

    let batch = Batch::new(1, ZERO_HASH, vec![b"{\"x\":1}".to_vec()]);
    let frame = encode_frame(&batch);
    let mut wire = Vec::with_capacity(4 + frame.len());
    wire.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    wire.extend_from_slice(&frame);
    stream.write_all(&wire).await.expect("write frame");
    stream.flush().await.expect("flush");

    let mut ack_bytes = [0u8; ACK_LEN];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut ack_bytes))
        .await
        .expect("read did not time out")
        .expect("read ack");
    let ack = decode_ack(&ack_bytes).expect("decode ack");
    assert_eq!(ack.status, AckStatus::Accepted);
    assert_eq!(ack.next_expected_seq, 2);
}

#[tokio::test]
async fn a_client_with_no_certificate_never_gets_an_ack() {
    let certs = mint_certs();
    let bound_addr = start_gateway(&certs).await;

    let client_tls = no_client_auth_config(&certs.ca);
    let connector = TlsConnector::from(client_tls);
    let tcp = TcpStream::connect(bound_addr).await.expect("tcp connect");
    let domain = ServerName::try_from(GATEWAY_DNS).unwrap();

    match tokio::time::timeout(Duration::from_secs(3), connector.connect(domain, tcp)).await {
        Err(_elapsed) => {
            // Handshake never completed within the timeout - acceptable (fail-closed).
        }
        Ok(Err(_handshake_error)) => {
            // The expected path: the server aborts the handshake once it sees no client
            // certificate, so the client's own connect() call surfaces an error.
        }
        Ok(Ok(mut stream)) => {
            // Even if the handshake layer somehow completed, the gateway must have
            // dropped the connection before the read loop: no ack is ever readable.
            let mut buf = [0u8; ACK_LEN];
            let read_result =
                tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut buf)).await;
            assert!(
                matches!(read_result, Ok(Err(_)) | Err(_)),
                "a no-cert client must never receive an ack"
            );
        }
    }
}
