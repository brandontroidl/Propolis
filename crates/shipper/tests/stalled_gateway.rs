//! A gateway that stops answering must cost the shipper a bounded wait, not the whole ship loop:
//! one stalled dial or one unacked batch is an `io::Error` the loop already handles (log, rewind,
//! retry next pass). Real sockets on both sides; no stubs.

use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, Instant};

use collector_wire::frame::{Batch, encode_frame};
use collector_wire::tls::{client_config, server_config};
use shipper::client::ShipperClient;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const GATEWAY_DNS: &str = "gateway.local";
const COLLECTOR_ID: &str = "collector-test";

/// (ca, gateway cert, gateway key, collector cert, collector key)
fn mint(dir: &Path) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    provision_certs::provision(dir, GATEWAY_DNS, COLLECTOR_ID).expect("provision");
    let read = |name: &str| std::fs::read(dir.join(name)).expect("read cert file");
    (
        read("ca.crt"),
        read("gateway.crt"),
        read("gateway.key"),
        read(&format!("{COLLECTOR_ID}.crt")),
        read(&format!("{COLLECTOR_ID}.key")),
    )
}

#[tokio::test]
async fn a_gateway_that_accepts_tcp_but_never_handshakes_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, _gc, _gk, cc, ck) = mint(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _held = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            held.push(s);
        }
    });
    let tls = client_config(&ca, &cc, &ck).unwrap();

    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(6),
        ShipperClient::connect_within(addr, tls, GATEWAY_DNS, Duration::from_millis(400)),
    )
    .await
    .expect("connect never returned: the dial has no deadline");
    let err = res
        .err()
        .expect("a silent gateway cannot complete a handshake");
    assert_eq!(err.kind(), ErrorKind::TimedOut, "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// Completes mutual TLS like the real gateway, reads what the client sends, and never acks.
#[tokio::test]
async fn a_batch_the_gateway_never_acks_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, gc, gk, cc, ck) = mint(dir.path());
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(&ca, &gc, &gk).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            if let Ok(mut tls) = acceptor.accept(tcp).await {
                let mut sink = vec![0u8; 4096];
                let _ = tls.read(&mut sink).await;
                held.push(tls);
            }
        }
    });
    let mut stream =
        ShipperClient::connect(addr, client_config(&ca, &cc, &ck).unwrap(), GATEWAY_DNS)
            .await
            .unwrap();
    let frame = encode_frame(&Batch::new(1, [0u8; 32], vec![b"one".to_vec()]));

    let started = Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(6),
        ShipperClient::send_batch_within(&mut stream, &frame, Duration::from_millis(500)),
    )
    .await
    .expect("send_batch never returned: the ack wait has no deadline");
    let err = res.err().expect("no ack was sent");
    assert_eq!(err.kind(), ErrorKind::TimedOut, "{err}");
    assert!(started.elapsed() < Duration::from_secs(3));
}
