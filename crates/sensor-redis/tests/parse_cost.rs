//! What reading one large command costs the sensor, against the same bytes sent as many small
//! commands. The reader parsed the whole buffered command again after every 1 KiB socket read and
//! copied every element it had finished, so one 900-element multi-bulk cost about thirty times the
//! CPU of the same bytes as 900 commands. The sensor and the client share this test's one thread
//! (`#[tokio::test]` runs a current-thread runtime and the listener spawns onto it), so the
//! thread's own CPU time is what the sensor spent, plus a client whose work is the same order in
//! both shapes and larger for the small commands, whose replies it reads back.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const ELEMENTS: usize = 900;
const ELEMENT_BYTES: usize = 1000;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(10),
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 1_000_000,
        max_concurrent: 16,
    }
}

fn bulk(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(format!("${}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// `PING` with 900 arguments of 1000 bytes: one command, answered with an arity error. Returns the
/// request and the whole reply it must get.
fn one_multibulk() -> (Vec<u8>, Vec<u8>) {
    let element = vec![b'A'; ELEMENT_BYTES];
    let mut out = format!("*{}\r\n", ELEMENTS + 1).into_bytes();
    bulk(&mut out, b"PING");
    for _ in 0..ELEMENTS {
        bulk(&mut out, &element);
    }
    (
        out,
        b"-ERR wrong number of arguments for 'ping' command\r\n".to_vec(),
    )
}

/// The same payload as 900 `PING <1000 bytes>` commands, each echoed back.
fn separate_commands() -> (Vec<u8>, Vec<u8>) {
    let element = vec![b'A'; ELEMENT_BYTES];
    let mut out = Vec::new();
    let mut reply = Vec::new();
    for _ in 0..ELEMENTS {
        out.extend_from_slice(b"*2\r\n");
        bulk(&mut out, b"PING");
        bulk(&mut out, &element);
        bulk(&mut reply, &element);
    }
    (out, reply)
}

/// Nanoseconds this thread has run on a CPU, from the scheduler's own accounting.
fn thread_cpu_ns() -> u64 {
    let stat = std::fs::read_to_string("/proc/thread-self/schedstat")
        .expect("/proc/thread-self/schedstat (Linux with scheduler statistics)");
    stat.split_whitespace()
        .next()
        .and_then(|ns| ns.parse().ok())
        .expect("schedstat starts with the run time in nanoseconds")
}

/// Send `payload` on a fresh connection while reading the replies back until as many bytes as
/// `reply` holds have arrived; returns the thread CPU time the exchange took. The replies are
/// compared after the clock stops, so the check costs neither shape anything.
async fn exchange(addr: std::net::SocketAddr, payload: &[u8], reply: &[u8]) -> Duration {
    let start = thread_cpu_ns();
    let wall = Instant::now();
    let conn = TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = conn.into_split();
    let mut got = Vec::with_capacity(reply.len());
    let reader = async {
        let mut chunk = vec![0u8; 64 * 1024];
        while got.len() < reply.len() {
            let n = rd.read(&mut chunk).await.expect("read");
            assert!(
                n > 0,
                "closed after {} of {} reply bytes",
                got.len(),
                reply.len()
            );
            got.extend_from_slice(&chunk[..n]);
        }
    };
    let writer = async {
        wr.write_all(payload).await.expect("write");
    };
    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(reader, writer)
    })
    .await
    .expect("the exchange finished");
    let spent = Duration::from_nanos(thread_cpu_ns() - start);
    assert!(
        got == reply,
        "the replies differ from what the commands must get"
    );
    eprintln!(
        "{} bytes: {spent:?} CPU, {:?} wall",
        payload.len(),
        wall.elapsed()
    );
    spent
}

#[tokio::test]
async fn one_large_multibulk_costs_about_what_the_same_bytes_as_separate_commands_cost() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_redis::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
    )
    .await
    .unwrap();

    let (big, big_reply) = one_multibulk();
    let (small, small_reply) = separate_commands();
    assert!(big.len() > 900_000 && small.len() > big.len());

    // Best of three of each, interleaved, so one noisy moment on a shared machine does not decide.
    let mut big_cost = Duration::MAX;
    let mut small_cost = Duration::MAX;
    for _ in 0..3 {
        big_cost = big_cost.min(exchange(addr, &big, &big_reply).await);
        small_cost = small_cost.min(exchange(addr, &small, &small_reply).await);
    }
    handle.abort();

    eprintln!("one multi-bulk {big_cost:?}, separate commands {small_cost:?}");
    assert!(
        big_cost <= small_cost * 3,
        "one {}-byte multi-bulk cost {big_cost:?} of CPU, the same bytes as {ELEMENTS} commands \
         {small_cost:?}: reading a command must cost about linear time in its size",
        big.len()
    );
}
