//! What one line of the fake shell may cost the telnet sensor, through the real listener: every
//! line below once froze the sensor or asked it for hundreds of megabytes, because a handler
//! walked or allocated far past what it charged to the line's work allowance. Each must now come
//! back to its prompt within [`LINE_TIME`] and grow the process heap by no more than
//! [`LINE_WORKING_SET_BYTES`], the most heap the capacity plan allows one running line.
//!
//! The sensor runs on its own runtime in its own thread, so a line that never returns fails its
//! test at the deadline instead of hanging the suite. The heap is the whole test process's,
//! counted by this file's allocator; the tests take turns so no other test's heap is counted.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, LINE_WORKING_SET_BYTES, WanResolver};

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

    /// Start a new peak at what is live now, and return it.
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

/// How long one line may take, in a debug build on a busy machine. Every line here took minutes
/// or never returned before its fix.
const LINE_TIME: Duration = Duration::from_secs(20);

static SERIAL: Mutex<()> = Mutex::new(());

fn one_at_a_time() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A telnet sensor on loopback, on a runtime of its own that the test never waits for.
fn sensor(dir: PathBuf) -> SocketAddr {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let (addr, handle) = sensor_telnet::start_test_server(
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

struct Session {
    conn: TcpStream,
}

impl Session {
    fn login(addr: SocketAddr) -> Self {
        let conn = TcpStream::connect(addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut session = Self { conn };
        session.read_until(b"login: ", Duration::from_secs(10));
        session.conn.write_all(b"root\r\n").unwrap();
        session.read_until(b"Password: ", Duration::from_secs(10));
        session.conn.write_all(b"root\r\n").unwrap();
        session.read_until(b"# ", Duration::from_secs(10));
        session
    }

    /// Everything the sensor sends until `end`, which the caller expects within `within`.
    fn read_until(&mut self, end: &[u8], within: Duration) -> Vec<u8> {
        let deadline = Instant::now() + within;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while !buf.ends_with(end) {
            assert!(
                Instant::now() < deadline,
                "nothing ending in {:?} within {within:?}; the sensor sent {} bytes, ending {:?}",
                String::from_utf8_lossy(end),
                buf.len(),
                String::from_utf8_lossy(&buf[buf.len().saturating_sub(200)..])
            );
            match self.conn.read(&mut chunk) {
                Ok(0) => panic!("the sensor closed the session"),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => panic!("read failed: {e}"),
            }
        }
        buf
    }

    /// Run `line` and return what came back before the next prompt, asserting the line's time
    /// and heap bounds.
    fn run(&mut self, line: &str) -> String {
        let base = Heap::mark();
        let started = Instant::now();
        self.conn
            .write_all(format!("{line}\r\n").as_bytes())
            .unwrap();
        let out = self.read_until(b"# ", LINE_TIME);
        let took = started.elapsed();
        let grew = Heap::peak().saturating_sub(base);
        let shown: String = line.chars().take(80).collect();
        assert!(
            grew <= LINE_WORKING_SET_BYTES,
            "{shown:?} grew the heap by {grew} bytes, past {LINE_WORKING_SET_BYTES} (took {took:?})"
        );
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// `tr` builds its sets and its translation from the constructs it was given: a repeat count of
/// 2^64-2 is one construct, not that many steps. Each of these once spun a worker for longer than
/// the sensor would run, and with it every other session, the accept loop and the watchdog.
#[test]
fn tr_repeat_counts_are_not_walked() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    let n = "18446744073709551614";
    // Room under the most a SET may hold in all for a construct to follow it.
    let m = "18446744073709551000";
    for (line, expect) in [
        (format!("echo hello | tr -s a '[b*{n}]'"), "hello\r\n"),
        (format!("echo hello | tr -d '[a*{n}]'"), "hello\r\n"),
        (format!("echo hello | tr -s '[a*{n}]'"), "hello\r\n"),
        (format!("echo abc | tr -c '[b*{n}]' x"), "xbxx"),
        (
            format!("echo banana | tr '[a*{n}]' '[b*{n}]'"),
            "bbnbnb\r\n",
        ),
        (
            format!("echo banana | tr '[a*{m}]n' '[x*{m}]'"),
            "bxxxxx\r\n",
        ),
        (
            format!("echo banana | tr '[a*{m}]b' '[c*{m}][:upper:]'"),
            "misaligned [:upper:] and/or [:lower:] construct",
        ),
    ] {
        let out = session.run(&line);
        assert!(out.contains(expect), "{line}: {out:?}");
    }
}

/// `tee -` writes a file named `-`, as GNU's does; standard output gets the input once. Every
/// `-` used to add another copy of the input to the output, so a hundred of them over a
/// megabyte asked for 200 MB and the kernel killed the sensor.
#[test]
fn tee_copies_its_input_once_per_file_and_pays_for_each() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    session.run("cd /tmp");
    let dashes = vec!["-"; 100].join(" ");
    session.run(&format!("head -c 1000000 /dev/zero | tee {dashes} | wc -c"));
    let out = session.run("echo hi | tee - - | wc -c");
    assert!(out.contains("\r\n3\r\n"), "{out:?}");
    let out = session.run("cat ./-");
    assert!(out.contains("\r\nhi\r\n"), "{out:?}");
}

/// `cut --output-delimiter` puts the attacker's delimiter before every field: 20,000 fields and a
/// 3,000-byte delimiter made 60 MB (twice over) from 20 KB of input. And a byte list of 65,536
/// spans was searched span by span for each of four million bytes.
#[test]
fn cut_output_is_bounded_by_what_the_line_can_pay() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    let delimiter = "x".repeat(3000);
    session.run(&format!(
        "head -c 20000 /dev/zero | tr '\\0' , | cut -d, -f1- --output-delimiter={delimiter} | wc -c"
    ));
    session.run("l=1; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do l=$l,$l; done");
    session.run("head -c 4000000 /dev/zero | cut -b $l | wc -c");
    let out = session.run("echo a,b,c | cut -d, -f1- --output-delimiter=XYZ");
    assert!(out.contains("\r\naXYZbXYZc\r\n"), "{out:?}");
    let out = session.run("echo abcdef | cut -b 5-,1,2-3 --output-delimiter=:");
    assert!(out.contains("\r\nabc:ef\r\n"), "{out:?}");
}

/// `systemctl` and `crontab` read the files they are pointed at for their own use, up to 1 MiB a
/// time, and charged none of it: `systemctl status` re-read and echoed a 180 KB unit once per
/// operand (200 operands, 72 MB), and a loop of `crontab /bin/busybox` synthesized a megabyte of
/// ELF per trip for some ten minutes of sensor time per line.
#[test]
fn files_a_command_reads_for_itself_are_charged_to_the_line() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    session.run("cd /etc/systemd/system");
    session.run("printf '[Unit]\\nDescription=' > v.service");
    for _ in 0..3 {
        session.run("printf '%060000d' 0 >> v.service");
    }
    let out = session.run("wc -c v.service");
    assert!(out.contains("\r\n180019 v.service\r\n"), "{out:?}");
    let out = session.run("systemctl status v | wc -c");
    assert!(out.contains("\r\n180106\r\n"), "{out:?}");
    let operands = vec!["v"; 200].join(" ");
    session.run(&format!("systemctl status {operands} | wc -c"));

    session.run("while :; do crontab /bin/busybox 2>/dev/null; done");

    session.run("for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do cp /bin/busybox x$i.service; done");
    session.run("while :; do systemctl list-unit-files >/dev/null; done");

    let out = session.run("systemctl is-active cron");
    assert!(out.contains("\r\nactive\r\n"), "{out:?}");
    let out = session.run("printf '* * * * * id\\n' > /tmp/c; crontab /tmp/c; crontab -l");
    assert!(out.contains("\r\n* * * * * id\r\n"), "{out:?}");
}

/// The echo-loader tracker digested a typed assembly twice per `>>` append and again on every
/// `chmod`, and the line was charged for none of it: 15,000 one-byte appends to a 180 KB assembly
/// took six minutes of sensor time in a debug build.
#[test]
fn tracking_a_typed_assembly_is_charged_to_the_line() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    session.run("cd /tmp");
    for _ in 0..3 {
        session.run("printf '%60000s' a >> f");
    }
    let out = session.run("wc -c f");
    assert!(out.contains("\r\n180000 f\r\n"), "{out:?}");
    session.run("while :; do echo -n b >> f; done");
    session.run("while :; do chmod +x f; done");
    let out = session.run("echo ok");
    assert!(out.contains("\r\nok\r\n"), "{out:?}");
}

/// awk's `getline < FILE` and `>>` output, and `dd conv=notrunc`, each read a file of up to a
/// megabyte per trip and charged none of it, so a loop around `close()` or `dd` held the sensor
/// for a minute or more per line.
#[test]
fn awk_and_dd_reads_are_charged_to_the_line() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    session.run("awk 'BEGIN{while(1){getline x < \"/bin/busybox\"; close(\"/bin/busybox\")}}'");
    session.run("awk 'BEGIN{while(1){printf \"\" >> \"/bin/busybox\"; close(\"/bin/busybox\")}}'");
    session.run("while :; do dd if=/dev/null of=/bin/busybox conv=notrunc 2>/dev/null; done");
    let out = session.run("echo ok");
    assert!(out.contains("\r\nok\r\n"), "{out:?}");
}

/// A dense legitimate loader line over a large assembly is charged once per append, not twice,
/// so it reaches its marker.
#[test]
fn a_dense_append_line_over_a_large_assembly_completes() {
    let _turn = one_at_a_time();
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::login(sensor(dir.path().to_path_buf()));
    session.run("cd /tmp");
    for _ in 0..3 {
        session.run("printf '%50000s' a >> g");
    }
    let chunk = format!("echo -ne '{}' >> g; ", "\\x41".repeat(128));
    let out = session.run(&format!("{}echo done", chunk.repeat(15)));
    assert!(out.contains("\r\ndone\r\n"), "{out:?}");
    let out = session.run("wc -c g");
    assert!(out.contains("\r\n151920 g\r\n"), "{out:?}");
}
