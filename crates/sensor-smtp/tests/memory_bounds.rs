//! Heap a stalled SMTP session holds, measured with a process-global counting allocator while
//! many real sockets sit in the shape an attacker leaves them in. The sensor's unit has
//! `MemoryMax=256M` and each listener admits 256 sessions, so anything a session holds that
//! grows with what the client declares or repeats, rather than with a fixed cap, is an OOM kill
//! for a few source addresses.
//!
//! The tests share the allocator, so they take `SERIAL` and never measure at the same time.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call forwards to `System` with the caller's own layout and pointer.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        CURRENT.fetch_add(layout.size(), Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            CURRENT.fetch_add(new_size - layout.size(), Ordering::SeqCst);
        } else {
            CURRENT.fetch_sub(layout.size() - new_size, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The production defaults that matter here (`max_captured_bytes` 1,000,000), with timeouts
/// long enough that a stalled session is still held when the heap is measured.
fn production_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(30),
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 1_000_000,
        max_concurrent: 256,
    }
}

async fn start() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_smtp::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        production_bounds(),
    )
    .await
    .unwrap();
    (addr, handle, dir)
}

/// Connects and completes the banner and EHLO, so the per-session setup is in the baseline.
async fn greeted(addr: std::net::SocketAddr) -> BufReader<TcpStream> {
    let mut conn = BufReader::new(TcpStream::connect(addr).await.unwrap());
    let mut line = String::new();
    conn.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220"), "{line}");
    conn.get_mut().write_all(b"EHLO x\r\n").await.unwrap();
    loop {
        line.clear();
        conn.read_line(&mut line).await.unwrap();
        if line.starts_with("250 ") {
            break;
        }
    }
    conn
}

/// The audit's other scenario: one source repeating `RCPT TO:` within the byte budget. Every
/// line pushed a String with no count limit, about 4 MB of heap per 1 MB of input, and 64
/// sessions from one address OOM-killed the unit. Past the recipient limit the lines are
/// refused, and only a bounded prefix of the accepted ones is kept for the event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_rcpt_lines_holds_a_bounded_amount() {
    const CONNECTIONS: usize = 16;
    const LINES: usize = 20_000;
    const PER_CONNECTION_LIMIT: usize = 64 * 1024;

    let _serial = SERIAL.lock().await;
    let (addr, handle, _dir) = start().await;
    let mut flood = b"MAIL FROM:<a@evil.test>\r\n".to_vec();
    for _ in 0..LINES {
        flood.extend_from_slice(b"RCPT TO:<victim@example.com>\r\n");
    }
    let flood: Arc<[u8]> = flood.into();

    let mut conns = Vec::new();
    for _ in 0..CONNECTIONS {
        conns.push(greeted(addr).await.into_inner());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = CURRENT.load(Ordering::SeqCst);

    let sessions: Vec<_> = conns
        .into_iter()
        .map(|conn| {
            let flood = flood.clone();
            tokio::spawn(async move {
                let (read, mut write) = conn.into_split();
                let writer = tokio::spawn(async move {
                    write.write_all(&flood).await.unwrap();
                    write
                });
                // Every line is answered; read them all so neither side blocks on a full
                // socket buffer, and so the server has processed the whole flood.
                let mut read = BufReader::new(read);
                let mut line = String::new();
                for _ in 0..=LINES {
                    line.clear();
                    tokio::time::timeout(Duration::from_secs(10), read.read_line(&mut line))
                        .await
                        .expect("a reply per line")
                        .unwrap();
                }
                (read, writer.await.unwrap())
            })
        })
        .collect();
    let mut held = Vec::new();
    for s in sessions {
        held.push(s.await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let grown = CURRENT.load(Ordering::SeqCst).saturating_sub(base);

    assert!(
        grown <= CONNECTIONS * PER_CONNECTION_LIMIT,
        "{CONNECTIONS} sessions of {LINES} RCPT lines grew the heap by {grown} bytes, over \
         {PER_CONNECTION_LIMIT} per connection"
    );
    drop(held);
    handle.abort();
}

/// The audit's scenario: `BDAT 999000 LAST`, then one byte short of the chunk, then silence.
/// The sensor allocated the declared size up front and held it for the idle timeout, about
/// 1 MB per connection; 256 such connections pushed the unit past `MemoryMax`. A stalled chunk
/// must hold no more than the retained body cap plus a read buffer, whatever it declared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_bdat_chunk_holds_a_bounded_amount_not_its_declared_size() {
    const CONNECTIONS: usize = 32;
    const DECLARED: usize = 999_000;
    // 64 KiB retained body + a read piece + slack; the old behaviour held ~1 MB.
    const PER_CONNECTION_LIMIT: usize = 160 * 1024;

    let _serial = SERIAL.lock().await;
    let (addr, handle, _dir) = start().await;
    let filler: Arc<[u8]> = vec![b'x'; DECLARED - 1].into();

    let mut conns = Vec::new();
    for _ in 0..CONNECTIONS {
        conns.push(greeted(addr).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let base = CURRENT.load(Ordering::SeqCst);

    let writers: Vec<_> = conns
        .into_iter()
        .map(|mut conn| {
            let filler = filler.clone();
            tokio::spawn(async move {
                conn.get_mut()
                    .write_all(format!("BDAT {DECLARED} LAST\r\n").as_bytes())
                    .await
                    .unwrap();
                conn.get_mut().write_all(&filler).await.unwrap();
                conn
            })
        })
        .collect();
    let mut held = Vec::new();
    for w in writers {
        held.push(w.await.unwrap());
    }
    // Every byte the clients sent has been written; give the server time to read it all.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let grown = CURRENT.load(Ordering::SeqCst).saturating_sub(base);

    assert!(
        grown <= CONNECTIONS * PER_CONNECTION_LIMIT,
        "{CONNECTIONS} stalled BDAT chunks grew the heap by {grown} bytes, over \
         {PER_CONNECTION_LIMIT} per connection"
    );

    // The chunks were really read, not merely left in socket buffers: the last byte completes
    // each one into a queued message.
    for conn in &mut held {
        conn.get_mut().write_all(b"x").await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(5), conn.read_line(&mut reply))
            .await
            .expect("reply to the completed chunk")
            .unwrap();
        assert!(reply.starts_with("250 2.0.0 Ok: queued as"), "{reply}");
    }
    drop(held);
    handle.abort();
}
