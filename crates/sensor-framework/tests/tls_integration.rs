use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sensor_framework::bounds::ConnectionBounds;
use sensor_framework::listener::run_tcp_listener;
use sensor_framework::{MaybeTlsStream, TlsServer, run_tls_listener, server_config_from_pem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 4096,
        max_concurrent: 10,
    }
}

fn ephemeral() -> (String, String, Vec<u8>) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (cert.pem(), signing_key.serialize_pem(), cert.der().to_vec())
}

struct Fixture {
    server: TlsServer,
    connector: TlsConnector,
}

fn fixture() -> Fixture {
    let (cert, key, der) = ephemeral();
    let server =
        TlsServer::from_config(server_config_from_pem(cert.as_bytes(), key.as_bytes()).unwrap());
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der)).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Fixture {
        server,
        connector: TlsConnector::from(Arc::new(client)),
    }
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

fn any_local() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

async fn connect_from(source: &str, target: SocketAddr) -> std::io::Result<TcpStream> {
    let socket = TcpSocket::new_v4()?;
    socket.bind(format!("{source}:0").parse().unwrap())?;
    socket.connect(target).await
}

/// True once the peer has closed or reset the connection within `within`. Bytes read on the way
/// (rustls sends a fatal alert before closing on a malformed ClientHello) are drained.
async fn closes_within(stream: &mut TcpStream, within: Duration) -> bool {
    let drain = async {
        let mut buf = [0u8; 64];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(within, drain).await.is_ok()
}

#[tokio::test]
async fn tls_listener_handshakes_and_echoes() {
    let f = fixture();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(1);
    let (addr, handle) = run_tls_listener(any_local(), test_bounds(), None, f.server, {
        move |mut stream, _peer, _local, _id| {
            let tx = tx.clone();
            async move {
                // No client auth: the server never sees a client certificate.
                let no_client_cert = stream.get_ref().1.peer_certificates().is_none();
                let _ = tx.send(no_client_cert).await;
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                stream.write_all(&buf).await.unwrap();
                stream.flush().await.unwrap();
            }
        }
    })
    .await
    .unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut client = f.connector.connect(localhost(), tcp).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
    assert!(rx.recv().await.unwrap());
    handle.abort();
}

#[tokio::test]
async fn handler_receives_pre_handshake_local_addr() {
    let f = fixture();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(SocketAddr, Option<SocketAddr>)>(1);
    let (addr, handle) = run_tls_listener(
        any_local(),
        test_bounds(),
        None,
        f.server,
        move |_stream, peer, local, _id| {
            let tx = tx.clone();
            async move {
                let _ = tx.send((peer, local)).await;
            }
        },
    )
    .await
    .unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let _client = f.connector.connect(localhost(), tcp).await.unwrap();
    let (peer, local) = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local, Some(addr));
    assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    handle.abort();
}

#[tokio::test]
async fn plaintext_to_tls_port_is_dropped_and_handler_not_called() {
    let f = fixture();
    let calls = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&calls);
    let (addr, handle) = run_tls_listener(
        any_local(),
        test_bounds(),
        None,
        f.server,
        move |_stream, _peer, _local, _id| {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        },
    )
    .await
    .unwrap();

    let mut plain = TcpStream::connect(addr).await.unwrap();
    plain.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert!(closes_within(&mut plain, Duration::from_secs(2)).await);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    handle.abort();
}

#[tokio::test]
async fn handshake_stall_is_cut_at_read_timeout() {
    let f = fixture();
    let mut bounds = test_bounds();
    bounds.read_timeout = Duration::from_millis(300);
    let (addr, handle) = run_tls_listener(
        any_local(),
        bounds,
        None,
        f.server,
        |_stream, _peer, _local, _id| async {},
    )
    .await
    .unwrap();

    let mut silent = TcpStream::connect(addr).await.unwrap();
    assert!(closes_within(&mut silent, Duration::from_secs(2)).await);
    handle.abort();
}

#[tokio::test]
async fn per_source_cap_still_applies_to_tls_listener() {
    let f = fixture();
    let hold = Arc::new(tokio::sync::Notify::new());
    let held = Arc::clone(&hold);
    let (addr, handle) = run_tls_listener(
        any_local(),
        test_bounds(),
        Some(1),
        f.server,
        move |_stream, _peer, _local, _id| {
            let held = Arc::clone(&held);
            async move { held.notified().await }
        },
    )
    .await
    .unwrap();

    let a = connect_from("127.0.0.2", addr).await.unwrap();
    let _a = f.connector.connect(localhost(), a).await.unwrap();

    let b = connect_from("127.0.0.2", addr).await.unwrap();
    let refused = tokio::time::timeout(Duration::from_secs(2), f.connector.connect(localhost(), b))
        .await
        .expect("refused source must be closed, not left hanging");
    assert!(refused.is_err());

    let c = connect_from("127.0.0.3", addr).await.unwrap();
    assert!(f.connector.connect(localhost(), c).await.is_ok());
    hold.notify_waiters();
    handle.abort();
}

#[tokio::test]
async fn max_connections_semaphore_still_applies() {
    let f = fixture();
    let mut bounds = test_bounds();
    bounds.max_concurrent = 1;
    let hold = Arc::new(tokio::sync::Notify::new());
    let held = Arc::clone(&hold);
    let (addr, handle) = run_tls_listener(
        any_local(),
        bounds,
        None,
        f.server,
        move |_stream, _peer, _local, _id| {
            let held = Arc::clone(&held);
            async move { held.notified().await }
        },
    )
    .await
    .unwrap();

    let first = TcpStream::connect(addr).await.unwrap();
    let first = f.connector.connect(localhost(), first).await.unwrap();

    let second = TcpStream::connect(addr).await.unwrap();
    let second = tokio::time::timeout(
        Duration::from_secs(2),
        f.connector.connect(localhost(), second),
    )
    .await
    .expect("over-limit connection must be closed, not left hanging");
    assert!(second.is_err());

    hold.notify_waiters();
    drop(first);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let tcp = TcpStream::connect(addr).await.unwrap();
        if f.connector.connect(localhost(), tcp).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "permit was never released"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    handle.abort();
}

#[tokio::test]
async fn max_duration_cuts_a_post_handshake_stalled_handler() {
    let f = fixture();
    let mut bounds = test_bounds();
    bounds.max_duration = Duration::from_millis(500);
    let (addr, handle) = run_tls_listener(
        any_local(),
        bounds,
        None,
        f.server,
        |_stream, _peer, _local, _id| async { tokio::time::sleep(Duration::from_secs(60)).await },
    )
    .await
    .unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut client = f.connector.connect(localhost(), tcp).await.unwrap();
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("max_duration must close the connection");
    assert!(matches!(read, Ok(0) | Err(_)));
    handle.abort();
}

#[tokio::test]
async fn maybe_tls_upgrade_roundtrip() {
    let f = fixture();
    let server = f.server.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(1);
    let (addr, handle) = run_tcp_listener(any_local(), test_bounds(), None, move |tcp, _p, _id| {
        let server = server.clone();
        let tx = tx.clone();
        async move {
            let mut stream = MaybeTlsStream::Plain(tcp);
            let mut line = [0u8; 9];
            stream.read_exact(&mut line).await.unwrap();
            assert_eq!(&line, b"STARTTLS\n");
            stream.write_all(b"OK\n").await.unwrap();
            stream.flush().await.unwrap();
            let mut stream = stream
                .upgrade(&server, std::time::Duration::from_secs(5))
                .await
                .unwrap();
            let _ = tx.send(stream.is_tls()).await;
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            stream.write_all(&buf).await.unwrap();
            stream.flush().await.unwrap();
        }
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"STARTTLS\n").await.unwrap();
    let mut ok = [0u8; 3];
    tcp.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, b"OK\n");
    let mut client = f.connector.connect(localhost(), tcp).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
    assert!(rx.recv().await.unwrap());
    handle.abort();
}

#[tokio::test]
async fn upgrade_buffered_roundtrip_over_a_bufreader() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let f = fixture();
    let server = f.server.clone();
    let (addr, handle) = run_tcp_listener(any_local(), test_bounds(), None, move |tcp, _p, _id| {
        let server = server.clone();
        async move {
            let mut reader = BufReader::new(MaybeTlsStream::Plain(tcp));
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "STARTTLS\n");
            reader.get_mut().write_all(b"OK\n").await.unwrap();
            reader.get_mut().flush().await.unwrap();
            let mut reader =
                sensor_framework::upgrade_buffered(reader, &server, Duration::from_secs(5))
                    .await
                    .unwrap();
            assert!(reader.get_ref().is_tls());
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf).await.unwrap();
            reader.get_mut().write_all(&buf).await.unwrap();
            reader.get_mut().flush().await.unwrap();
        }
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"STARTTLS\n").await.unwrap();
    let mut ok = [0u8; 3];
    tcp.read_exact(&mut ok).await.unwrap();
    assert_eq!(&ok, b"OK\n");
    let mut client = f.connector.connect(localhost(), tcp).await.unwrap();
    client.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
    handle.abort();
}

/// The STARTTLS command-injection shape: plaintext pipelined after STARTTLS in the same segment
/// must refuse the upgrade (naming the byte count), never be read inside the TLS session.
#[tokio::test]
async fn upgrade_buffered_refuses_plaintext_pipelined_after_starttls() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let f = fixture();
    let server = f.server.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Error>(1);
    let (addr, handle) = run_tcp_listener(any_local(), test_bounds(), None, move |tcp, _p, _id| {
        let server = server.clone();
        let tx = tx.clone();
        async move {
            // Let the whole pipelined segment land so one buffer fill holds both lines.
            tokio::time::sleep(Duration::from_millis(150)).await;
            let mut reader = BufReader::new(MaybeTlsStream::Plain(tcp));
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(line, "STARTTLS\n");
            match sensor_framework::upgrade_buffered(reader, &server, Duration::from_secs(5)).await
            {
                Err(err) => {
                    let _ = tx.send(err).await;
                }
                Ok(_) => panic!("pipelined plaintext must refuse the upgrade"),
            }
        }
    })
    .await
    .unwrap();

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"STARTTLS\nQUIT\n").await.unwrap();
    let err = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("server reported")
        .expect("an error was sent");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("5 plaintext bytes"), "{err}");
    handle.abort();
}

/// An established loopback TLS pair: (server-side stream, client-side stream).
async fn tls_pair(
    f: &Fixture,
) -> (
    tokio_rustls::server::TlsStream<TcpStream>,
    tokio_rustls::client::TlsStream<TcpStream>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = f.server.clone();
    let accept = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        server.accept(tcp).await.unwrap()
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let client = f.connector.connect(localhost(), tcp).await.unwrap();
    (accept.await.unwrap(), client)
}

#[tokio::test]
async fn maybe_tls_upgrade_on_tls_stream_is_an_error() {
    let f = fixture();
    let (server_side, _client) = tls_pair(&f).await;
    let stream = MaybeTlsStream::Tls(Box::new(server_side));
    assert!(stream.is_tls());
    match stream
        .upgrade(&f.server, std::time::Duration::from_secs(5))
        .await
    {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        Ok(_) => panic!("upgrading an already-tls stream must fail"),
    }
}

#[tokio::test]
async fn maybe_tls_plain_passthrough() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let client = TcpStream::connect(addr).await.unwrap();
    let mut a = MaybeTlsStream::Plain(client);
    let mut b = MaybeTlsStream::Plain(accept.await.unwrap());
    assert!(!a.is_tls() && !b.is_tls());

    a.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    b.write_all(b"pong").await.unwrap();
    a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
}
