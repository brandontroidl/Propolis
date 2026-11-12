//! `console::server::serve` over real TCP: the connection-level bounds only exist at the socket,
//! so `oneshot` router tests cannot see them. Each test serves a tiny router on an ephemeral
//! loopback port with short limits and drives it with raw sockets.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::{get, post};
use console::server::{STATS, ServeLimits, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

fn test_router() -> Router {
    Router::new()
        .route(
            "/peer",
            get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
        )
        .route("/echo", post(|body: String| async move { body }))
}

struct Server {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    done: tokio::task::JoinHandle<()>,
}

async fn start(limits: ServeLimits) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let done = tokio::spawn(serve(
        listener,
        test_router(),
        limits,
        async move {
            let _ = stopped.await;
        },
        Duration::from_secs(2),
    ));
    Server {
        addr,
        stop: Some(stop),
        done,
    }
}

fn limits() -> ServeLimits {
    ServeLimits {
        max_connections: 8,
        header_read_timeout: Duration::from_millis(300),
        body_read_timeout: Duration::from_millis(300),
        max_body_bytes: 64,
    }
}

/// Reads until the peer closes or `limit` elapses; returns what arrived and whether it closed.
async fn read_until_closed(stream: &mut TcpStream, limit: Duration) -> (String, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let deadline = Instant::now() + limit;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return (String::from_utf8_lossy(&buf).into_owned(), true),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return (String::from_utf8_lossy(&buf).into_owned(), false),
        }
    }
}

#[tokio::test]
async fn handlers_receive_the_peer_address() {
    let server = start(limits()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let (resp, _) = read_until_closed(&mut s, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        resp.ends_with("127.0.0.1"),
        "ConnectInfo must carry the TCP peer: {resp}"
    );
}

#[tokio::test]
async fn a_client_that_never_finishes_its_headers_is_disconnected() {
    let server = start(limits()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let started = Instant::now();
    let (_, closed) = read_until_closed(&mut s, Duration::from_secs(3)).await;
    assert!(
        closed,
        "a partial-header connection must be closed, not held"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn a_client_that_sends_nothing_is_disconnected() {
    let server = start(limits()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    let (_, closed) = read_until_closed(&mut s, Duration::from_secs(3)).await;
    assert!(
        closed,
        "a silent connection must be closed by the header timeout"
    );
}

#[tokio::test]
async fn an_idle_keep_alive_connection_is_closed_after_its_request() {
    let server = start(limits()).await;
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let (resp, closed) = read_until_closed(&mut s, Duration::from_secs(3)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        closed,
        "a kept-alive connection waiting for its next request must still time out"
    );
}

#[tokio::test]
async fn connections_past_the_limit_are_closed_and_counted_then_capacity_returns() {
    let server = start(ServeLimits {
        max_connections: 2,
        header_read_timeout: Duration::from_secs(5),
        ..limits()
    })
    .await;
    let held_a = TcpStream::connect(server.addr).await.unwrap();
    let _held_b = TcpStream::connect(server.addr).await.unwrap();
    // Let the accept loop take both before the third arrives.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let shed_before = STATS.connections_shed.load(Ordering::Relaxed);
    let mut third = TcpStream::connect(server.addr).await.unwrap();
    let (_, closed) = read_until_closed(&mut third, Duration::from_secs(1)).await;
    assert!(closed, "a connection past the limit must be closed at once");
    assert!(STATS.connections_shed.load(Ordering::Relaxed) > shed_before);

    // Closing one held connection frees its slot.
    drop(held_a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut fourth = TcpStream::connect(server.addr).await.unwrap();
    fourth
        .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let (resp, _) = read_until_closed(&mut fourth, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
}

#[tokio::test]
async fn a_body_that_stalls_gets_408_before_the_handler_runs() {
    let server = start(limits()).await;
    let timeouts_before = STATS.body_timeouts.load(Ordering::Relaxed);
    let mut s = TcpStream::connect(server.addr).await.unwrap();
    s.write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")
        .await
        .unwrap();
    let (resp, _) = read_until_closed(&mut s, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 408"), "{resp}");
    assert!(STATS.body_timeouts.load(Ordering::Relaxed) > timeouts_before);
}

#[tokio::test]
async fn an_oversized_body_gets_413_and_a_normal_one_passes_through() {
    let server = start(limits()).await;

    let mut big = TcpStream::connect(server.addr).await.unwrap();
    let body = "x".repeat(65);
    big.write_all(
        format!(
            "POST /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let (resp, _) = read_until_closed(&mut big, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");

    let mut ok = TcpStream::connect(server.addr).await.unwrap();
    ok.write_all(
        b"POST /echo HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello",
    )
    .await
    .unwrap();
    let (resp, _) = read_until_closed(&mut ok, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(resp.ends_with("hello"), "{resp}");
}

#[tokio::test]
async fn shutdown_stops_accepting_and_returns_within_the_grace_period() {
    let mut server = start(limits()).await;
    // An open, idle connection must not hold shutdown past the grace period.
    let _idle = TcpStream::connect(server.addr).await.unwrap();
    server.stop.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(4), &mut server.done)
        .await
        .expect("serve must return after shutdown")
        .unwrap();
    assert!(
        TcpStream::connect(server.addr).await.is_err() || {
            // The port may be briefly connectable on some kernels; nothing may answer on it.
            let mut s = TcpStream::connect(server.addr).await.unwrap();
            read_until_closed(&mut s, Duration::from_millis(500))
                .await
                .1
        }
    );
}
