//! What one line of the phone's shell may cost the ADB sensor, through the real listener and the
//! ADB wire protocol: `pm install` read the package it was given, up to 1 MiB, and charged none
//! of it, so a loop over it held the sensor's runtime worker for minutes. Each line must come back
//! to its prompt within [`LINE_TIME`] and grow the process heap by no more than
//! [`LINE_WORKING_SET_BYTES`]. The sensor runs on its own runtime thread, so a line that never
//! returns fails the test at the deadline instead of hanging the suite.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sensor_adb::adb_proto::{self, Header};
use sensor_framework::{ConnectionBounds, LINE_WORKING_SET_BYTES, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The process heap: what is live now and the most that was live since [`Heap::mark`].
struct Heap;

static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

impl Heap {
    fn grew(by: usize) {
        let now = LIVE.fetch_add(by as u64, Ordering::Relaxed) + by as u64;
        PEAK.fetch_max(now, Ordering::Relaxed);
    }

    fn shrank(by: usize) {
        LIVE.fetch_sub(by as u64, Ordering::Relaxed);
    }

    fn mark() -> u64 {
        let now = LIVE.load(Ordering::Relaxed);
        PEAK.store(now, Ordering::Relaxed);
        now
    }

    fn peak() -> u64 {
        PEAK.load(Ordering::Relaxed)
    }
}

// SAFETY: every call is passed to the system allocator unchanged; the counters only observe it.
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            Heap::grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            Heap::grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        Heap::shrank(layout.size());
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            Heap::shrank(layout.size());
            Heap::grew(new_size);
        }
        p
    }
}

#[global_allocator]
static ALLOCATOR: Heap = Heap;

/// How long one line may take, in a debug build on a busy machine.
const LINE_TIME: Duration = Duration::from_secs(20);

/// An ADB sensor on loopback, on a runtime of its own that the test never waits for.
fn sensor(dir: PathBuf) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (addr, handle) = sensor_adb::start_test_server(
                "127.0.0.1:0".parse().unwrap(),
                dir.join("events.jsonl"),
                dir.join("spool"),
                Arc::new(WanResolver::new(HashMap::new())),
                ConnectionBounds {
                    read_timeout: Duration::from_secs(120),
                    idle_timeout: Duration::from_secs(120),
                    max_duration: Duration::from_secs(600),
                    max_captured_bytes: 1_000_000,
                    max_concurrent: 16,
                },
                "test".to_string(),
                dir.join("outbox"),
            )
            .await
            .unwrap();
            tx.send(addr).unwrap();
            let _ = handle.await;
        });
    });
    rx.recv_timeout(Duration::from_secs(10)).unwrap()
}

async fn read_message(stream: &mut TcpStream, deadline: Instant) -> (Header, Vec<u8>) {
    let fut = async {
        let mut header_buf = [0u8; adb_proto::HEADER_LEN];
        stream.read_exact(&mut header_buf).await.expect("header");
        let header = Header::parse(&header_buf).expect("well-formed header");
        let mut data = vec![0u8; header.data_length as usize];
        if header.data_length > 0 {
            stream.read_exact(&mut data).await.expect("payload");
        }
        (header, data)
    };
    tokio::time::timeout_at(deadline.into(), fut)
        .await
        .expect("no reply from the sensor by the line's deadline")
}

/// An interactive `shell:` stream past its first prompt: the connection, our id, the server's.
async fn shell(addr: SocketAddr) -> (TcpStream, u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut conn = TcpStream::connect(addr).await.unwrap();
    conn.write_all(&adb_proto::build_cnxn(&adb_proto::host_banner()))
        .await
        .unwrap();
    let (header, _) = read_message(&mut conn, deadline).await;
    assert_eq!(header.command, adb_proto::A_CNXN);
    conn.write_all(&adb_proto::build_open(7, "shell:"))
        .await
        .unwrap();
    let (okay, _) = read_message(&mut conn, deadline).await;
    assert_eq!(okay.command, adb_proto::A_OKAY);
    let server_id = okay.arg0;
    let (prompt, _) = read_message(&mut conn, deadline).await;
    assert_eq!(prompt.command, adb_proto::A_WRTE);
    conn.write_all(&adb_proto::build_okay(prompt.arg1, prompt.arg0))
        .await
        .unwrap();
    (conn, server_id)
}

/// Run `line` and return its output, asserting the line's time and heap bounds.
async fn run(conn: &mut TcpStream, server_id: u32, line: &str) -> String {
    let base = Heap::mark();
    let started = Instant::now();
    let deadline = started + LINE_TIME;
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    conn.write_all(&adb_proto::build_wrte(7, server_id, &bytes))
        .await
        .unwrap();
    let (ack, _) = read_message(conn, deadline).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let mut output = Vec::new();
    while !(output.ends_with(b"# ") || output.ends_with(b"$ ")) {
        let (wrte, data) = read_message(conn, deadline).await;
        assert_eq!(wrte.command, adb_proto::A_WRTE);
        output.extend_from_slice(&data);
        conn.write_all(&adb_proto::build_okay(wrte.arg1, wrte.arg0))
            .await
            .unwrap();
    }
    let grew = Heap::peak().saturating_sub(base);
    assert!(
        grew <= LINE_WORKING_SET_BYTES,
        "{line:?} grew the heap by {grew} bytes, past {LINE_WORKING_SET_BYTES} (took {:?})",
        started.elapsed()
    );
    String::from_utf8_lossy(&output).into_owned()
}

/// `pm install` reads the whole package to look for its manifest; each read is now charged to
/// the line first, so a loop over a 64 KiB "package" stops where a loop over `cat` of it would
/// instead of running some fourteen thousand trips, each reading and scanning it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pm_install_pays_for_the_package_it_reads() {
    let dir = tempfile::tempdir().unwrap();
    let (mut conn, server_id) = shell(sensor(dir.path().to_path_buf())).await;
    let out = run(
        &mut conn,
        server_id,
        "cd /data/local/tmp; printf '%065536d' 0 > a; ls -l a",
    )
    .await;
    assert!(out.contains(" 65536 "), "{out:?}");
    run(
        &mut conn,
        server_id,
        "while :; do pm install a >/dev/null 2>&1; done",
    )
    .await;
    let out = run(&mut conn, server_id, "pm install a").await;
    assert!(
        out.contains("Failure [INSTALL_PARSE_FAILED_NOT_APK]"),
        "{out:?}"
    );
}
