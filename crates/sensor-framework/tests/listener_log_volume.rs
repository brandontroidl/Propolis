//! What the TCP listener writes to the journal for connections a scanner can cause at will. One
//! scanner holding connections open past `max_duration`, or filling the concurrency cap, must not
//! produce a WARN line per connection: the journal is the operator's only window into a sensor and
//! `journalctl -p warning` is how they read it.
//!
//! The listener tasks run on the test's current-thread runtime, so a thread-local subscriber sees
//! every event they emit.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sensor_framework::bounds::ConnectionBounds;
use sensor_framework::listener::run_tcp_listener;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Captured {
        self.clone()
    }
}

impl Captured {
    fn lines_at(&self, level: &str, needle: &str) -> usize {
        let text = String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned();
        text.lines()
            .filter(|l| l.contains(level) && l.contains(needle))
            .count()
    }
}

fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let sink = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(sink.clone())
        .finish();
    (sink, tracing::subscriber::set_default(subscriber))
}

fn bounds(max_duration: Duration, max_concurrent: u32) -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration,
        max_captured_bytes: 4096,
        max_concurrent,
    }
}

#[tokio::test]
async fn a_connection_cut_at_max_duration_is_a_debug_line_not_a_warning() {
    let (sink, _guard) = capture();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound, handle) = run_tcp_listener(
        addr,
        bounds(Duration::from_millis(100), 10),
        None,
        |_stream, _peer, _id| async move {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        },
    )
    .await
    .unwrap();

    let mut conn = TcpStream::connect(bound).await.unwrap();
    let mut buf = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await;
    // The log line is written by the task that observed the elapsed timeout, just after the drop
    // that closed the socket.
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    assert_eq!(sink.lines_at("WARN", "max_duration"), 0);
    assert_eq!(sink.lines_at("DEBUG", "max_duration"), 1);
}

#[tokio::test]
async fn a_flood_past_max_concurrent_logs_a_logarithmic_number_of_warnings() {
    let (sink, _guard) = capture();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound, handle) = run_tcp_listener(
        addr,
        bounds(Duration::from_secs(60), 1),
        None,
        |_stream, _peer, _id| async move {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        },
    )
    .await
    .unwrap();

    // One connection holds the only slot; ten more are each refused.
    let mut held = vec![TcpStream::connect(bound).await.unwrap()];
    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in 0..10 {
        held.push(TcpStream::connect(bound).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    handle.abort();

    // Refusal totals 1, 2, 4 and 8 are logged; the other six are not.
    assert_eq!(sink.lines_at("WARN", "max_concurrent"), 4);
    drop(held);
}
