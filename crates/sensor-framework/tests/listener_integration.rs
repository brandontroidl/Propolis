use sensor_framework::bounds::ConnectionBounds;
use sensor_framework::listener::{run_tcp_listener, run_udp_listener, shutdown_signal};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 4096,
        max_concurrent: 10,
    }
}

#[tokio::test]
async fn tcp_accept_and_handler_called() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, handle) = run_tcp_listener(addr, test_bounds(), move |stream, peer, _id| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(peer).await;
            drop(stream);
        }
    })
    .await
    .unwrap();
    let _conn = TcpStream::connect(bound_addr).await.unwrap();
    let peer = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    handle.abort();
}

#[tokio::test]
async fn udp_receives_and_never_responds() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, handle) = run_udp_listener(addr, test_bounds(), move |data, _peer| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(data.to_vec()).await;
        }
    })
    .await
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"probe", bound_addr).await.unwrap();
    let data = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data, b"probe");
    // Verify zero response bytes: try to receive with a short timeout.
    let mut buf = [0u8; 1024];
    let result = tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await;
    assert!(result.is_err(), "UDP listener must never send a response");
    handle.abort();
}

#[tokio::test]
async fn bind_failure_non_fatal() {
    // Occupy a port, then try to bind the listener on it.
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocker.local_addr().unwrap();
    // run_tcp_listener on the blocked port should return an error for that port
    // but not crash. (If the API binds multiple ports, a single failure is non-fatal.)
    let result = run_tcp_listener(blocked_addr, test_bounds(), |_s, _p, _id| async {}).await;
    assert!(result.is_err());
    drop(blocker);
}

#[tokio::test]
async fn handler_panic_does_not_crash_accept_loop() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = call_count.clone();
    let (bound_addr, handle) = run_tcp_listener(addr, test_bounds(), move |_stream, _peer, _id| {
        let count = count.clone();
        async move {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            panic!("handler panic");
        }
    })
    .await
    .unwrap();
    // Connect twice - both should be handled despite the panic.
    let _c1 = TcpStream::connect(bound_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _c2 = TcpStream::connect(bound_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(call_count.load(std::sync::atomic::Ordering::Relaxed) >= 2);
    handle.abort();
}

// The tests below are not in the task brief's given suite. Each closes a gap the given four tests
// state as a property (in the brief's own guidance text) but do not exercise: the given suite never
// drives more than one connection through a `max_concurrent` cap, never lets a handler outlive
// `max_duration`, never checks UDP's own panic isolation (only TCP's), never bind-fails a UDP
// listener, and never touches `shutdown_signal` at all (every given test tears down via
// `handle.abort()` instead). A naive implementation could pass all four given tests while getting
// every one of these wrong - see each test's own comment for the specific wrong-but-plausible
// implementation it rules out.

#[tokio::test]
async fn udp_bind_failure_non_fatal() {
    // Mirrors `bind_failure_non_fatal` above, but for `run_udp_listener`'s own bind call - a
    // separate code path (`UdpSocket::bind`, not `TcpListener::bind`) that the given suite never
    // exercises at all.
    let blocker = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocker.local_addr().unwrap();
    let result = run_udp_listener(blocked_addr, test_bounds(), |_d, _p| async {}).await;
    assert!(result.is_err());
    drop(blocker);
}

#[tokio::test]
async fn udp_handler_panic_does_not_crash_recv_loop() {
    // The given suite's panic test only drives TCP. A UDP recv loop that calls
    // `handler(data, peer).await` directly inline (no per-datagram spawn) would let the first
    // panic take down the whole recv loop task, and the second datagram would never be observed -
    // this test fails under that plausible-but-wrong implementation and passes under one that
    // isolates each datagram's handler the same way TCP's accept loop does.
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let call_count = Arc::new(AtomicU32::new(0));
    let count = call_count.clone();
    let (bound_addr, handle) = run_udp_listener(addr, test_bounds(), move |_data, _peer| {
        let count = count.clone();
        async move {
            count.fetch_add(1, Ordering::Relaxed);
            panic!("udp handler panic");
        }
    })
    .await
    .unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"one", bound_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.send_to(b"two", bound_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        call_count.load(Ordering::Relaxed) >= 2,
        "recv loop must survive a panicking datagram handler"
    );
    handle.abort();
}

#[tokio::test]
async fn max_concurrent_refuses_excess_connections_immediately() {
    // Discriminates two plausible designs for enforcing `max_concurrent`: (a) refuse a connection
    // immediately when no permit is free (what this framework does - an accepted-but-waiting
    // connection is itself an unbounded resource), versus (b) accept it and queue it until a
    // permit frees up. Under (b) this test's second connection would sit open, never closed,
    // and the read below would time out rather than observe a close - so this fails under (b)
    // and passes only under (a).
    let bounds = ConnectionBounds {
        max_concurrent: 1,
        ..test_bounds()
    };
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let hold = Arc::new(tokio::sync::Notify::new());
    let started2 = started.clone();
    let hold2 = hold.clone();
    let (bound_addr, handle) = run_tcp_listener(addr, bounds, move |stream, _peer, _id| {
        let started = started2.clone();
        let hold = hold2.clone();
        async move {
            started.notify_one();
            hold.notified().await;
            drop(stream);
        }
    })
    .await
    .unwrap();

    let _first = TcpStream::connect(bound_addr).await.unwrap();
    // Wait until the first connection's handler has actually acquired the only permit (it
    // notifies only after the permit is held), so the second connection below is guaranteed to
    // race against a fully-occupied semaphore rather than an in-progress accept.
    started.notified().await;

    let mut second = TcpStream::connect(bound_addr).await.unwrap();
    // A real prober would not necessarily wait passively; write before reading to confirm a
    // refused connection tolerates an incoming write rather than hanging on it.
    let _ = second.write_all(b"probe").await;
    let mut buf = [0u8; 1];
    let read_result = tokio::time::timeout(Duration::from_millis(500), second.read(&mut buf)).await;
    match read_result {
        Ok(Ok(0)) => {}  // graceful close (EOF) - refused.
        Ok(Err(_)) => {} // reset - also acceptable evidence the connection was refused, not queued.
        Ok(Ok(n)) => panic!("refused connection unexpectedly yielded {n} bytes"),
        Err(_) => panic!(
            "refused connection was not closed within the timeout - looks queued, not refused"
        ),
    }

    hold.notify_one();
    handle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn max_concurrent_caps_peak_concurrent_handlers() {
    // Complementary to the refusal test above: proves the cap holds at its configured *number*
    // (not just that at least one refusal ever happens). Multi-threaded flavor so the peak is a
    // real concurrent-execution count, not an artifact of single-threaded cooperative scheduling.
    let bounds = ConnectionBounds {
        max_concurrent: 2,
        max_duration: Duration::from_secs(5),
        ..test_bounds()
    };
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let active = Arc::new(AtomicU32::new(0));
    let peak = Arc::new(AtomicU32::new(0));
    let active2 = active.clone();
    let peak2 = peak.clone();
    let (bound_addr, handle) = run_tcp_listener(addr, bounds, move |stream, _peer, _id| {
        let active = active2.clone();
        let peak = peak2.clone();
        async move {
            let cur = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(cur, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(250)).await;
            active.fetch_sub(1, Ordering::SeqCst);
            drop(stream);
        }
    })
    .await
    .unwrap();

    let mut connect_handles = Vec::new();
    for _ in 0..6 {
        connect_handles.push(tokio::spawn(
            async move { TcpStream::connect(bound_addr).await },
        ));
    }
    let mut conns = Vec::new();
    for h in connect_handles {
        if let Ok(Ok(conn)) = h.await {
            conns.push(conn);
        }
    }

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "peak concurrent handlers ({}) exceeded max_concurrent (2)",
        peak.load(Ordering::SeqCst)
    );
    handle.abort();
}

#[tokio::test]
async fn max_duration_aborts_long_running_handler() {
    // Discriminates "timeout wraps the JoinHandle" (a no-op: dropping a JoinHandle does not abort
    // the task it refers to, so the handler and its connection would run to completion regardless
    // of max_duration) from "timeout wraps the handler future itself" (dropping it on elapse also
    // drops everything the future owns, the connection included, which actually closes the
    // socket). A handler that never finishes on its own is the fixture that tells them apart.
    let bounds = ConnectionBounds {
        max_duration: Duration::from_millis(150),
        ..test_bounds()
    };
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, handle) =
        run_tcp_listener(addr, bounds, move |stream, _peer, _id| async move {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            drop(stream); // never reached within this test's lifetime if max_duration works.
        })
        .await
        .unwrap();

    let mut conn = TcpStream::connect(bound_addr).await.unwrap();
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_millis(600), conn.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) => {}  // closed once max_duration elapsed - expected.
        Ok(Err(_)) => {} // reset - also acceptable evidence of a forced close.
        Ok(Ok(n)) => panic!("connection unexpectedly yielded {n} bytes"),
        Err(_) => panic!("connection was not closed once max_duration elapsed"),
    }
    handle.abort();
}

#[tokio::test]
async fn shutdown_signal_does_not_resolve_without_a_signal() {
    // Guards against a trivially-ready implementation (e.g. one that accidentally returns an
    // already-resolved future): absent an actual SIGINT/SIGTERM, racing shutdown_signal() against
    // a short sleep must never let shutdown_signal() win.
    let result = tokio::time::timeout(Duration::from_millis(150), shutdown_signal()).await;
    assert!(
        result.is_err(),
        "shutdown_signal must not resolve without an actual signal"
    );
}
