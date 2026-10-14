//! What many clients filling their SET stores make the sensor hold, over real sockets.
//!
//! Each session's store and read buffer were bounded per session only (1 MiB of values, about
//! 1 MB of buffered command), and 256 sessions on each of the two listeners held more than the
//! unit's `MemoryMax=256M`: the red team's probe had the kernel kill the sensor at about 230
//! filled sessions. Past a small floor every session now draws on one pool for the process
//! (`sensor_redis::memory`), so what the sessions hold is at most the pool plus their floors.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::{CaptureMemoryBudget, ConnectionBounds, WanResolver};
use sensor_redis::memory::{ENTRY_OVERHEAD, POOL_BYTES, STORE_FLOOR};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Each SET's value: two fit the default 1,000,000-byte capture limit, and one is as large as
/// the per-session store and the bulk length cap let a value be.
const VALUE_BYTES: usize = 490_000;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        // Long enough that a session idle while the others fill is not closed under it.
        read_timeout: Duration::from_secs(120),
        idle_timeout: Duration::from_secs(120),
        max_duration: Duration::from_secs(300),
        max_captured_bytes: 1_000_000,
        // Room for the filling sessions and one more beside them.
        max_concurrent: 512,
    }
}

fn set_command(key: &str, value: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "*3\r\n$3\r\nSET\r\n${}\r\n{key}\r\n${}\r\n",
        key.len(),
        value.len()
    )
    .into_bytes();
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
    out
}

/// The reply to one command: its first line, or `None` when the sensor closed the session first.
async fn reply_line<S: AsyncRead + Unpin>(conn: &mut S) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match tokio::time::timeout(Duration::from_secs(120), conn.read(&mut byte)).await {
            Ok(Ok(1)) => {
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    return Some(line);
                }
            }
            Ok(_) => return None,
            Err(_) => panic!("no reply within 120 s"),
        }
    }
}

/// Send two large SETs and return the keys the sensor acknowledged, or `None` when it closed the
/// session (a closed session holds nothing).
async fn fill<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut S,
    value: &[u8],
) -> Option<Vec<&'static str>> {
    let mut acknowledged = Vec::new();
    for key in ["a", "b"] {
        // A session the pool cannot buffer is closed mid-write; the reply read then sees it.
        let _ = conn.write_all(&set_command(key, value)).await;
        let _ = conn.flush().await;
        match reply_line(conn).await?.as_slice() {
            b"+OK\r\n" => acknowledged.push(key),
            line => assert!(line.starts_with(b"-OOM "), "unexpected reply {line:?}"),
        }
    }
    Some(acknowledged)
}

/// Key and value bytes a session's acknowledged writes hold.
fn held_bytes(keys: &[&str]) -> usize {
    keys.len() * (1 + VALUE_BYTES)
}

async fn connect_from(source: IpAddr, addr: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(source, 0)).unwrap();
    socket.connect(addr).await.unwrap()
}

/// Loopback sources, so a listener's per-source cap (64 of 256) does not stop the fill short.
fn source(i: usize) -> IpAddr {
    IpAddr::from([127, 0, 0, 2 + (i / 64) as u8])
}

/// 64 sessions, each sending two SETs as large as a session may: four times what the pool holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_sessions_filling_set_hold_at_most_the_pool_and_their_floors() {
    const SESSIONS: usize = 64;
    let pool = Arc::new(CaptureMemoryBudget::new(POOL_BYTES));
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_redis::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        pool.clone(),
    )
    .await
    .unwrap();

    let value: Arc<[u8]> = vec![b'v'; VALUE_BYTES].into();
    let mut sessions = tokio::task::JoinSet::new();
    for i in 0..SESSIONS {
        let value = value.clone();
        sessions.spawn(async move {
            let mut conn = connect_from(source(i), addr).await;
            let held = fill(&mut conn, &value).await;
            (held, conn)
        });
    }
    let mut open = Vec::new();
    let mut held_total = 0;
    while let Some(done) = sessions.join_next().await {
        let (held, conn) = done.unwrap();
        if let Some(keys) = held {
            held_total += held_bytes(&keys);
            open.push((keys, conn));
        }
    }

    // The stated bound: past their floors the stores hold only what the pool lends.
    let bound = POOL_BYTES as usize + SESSIONS * STORE_FLOOR;
    eprintln!(
        "{} of {SESSIONS} sessions open, {held_total} value bytes acknowledged and held \
         (bound {bound}), pool high water {}",
        open.len(),
        pool.high_water_bytes()
    );
    assert!(
        held_total <= bound,
        "the open sessions hold {held_total} acknowledged bytes, past the pool plus their \
         floors ({bound})"
    );
    // Once each session is back waiting for its next command, the pool holds the stores alone:
    // every finished command gave its buffer room back.
    let stores = open
        .iter()
        .map(|(keys, _)| {
            (held_bytes(keys) + keys.len() * ENTRY_OVERHEAD).saturating_sub(STORE_FLOOR) as u64
        })
        .sum::<u64>();
    let deadline = Instant::now() + Duration::from_secs(10);
    while pool.current_bytes() != stores {
        assert!(
            Instant::now() < deadline,
            "the pool holds {} bytes, the stores {stores}",
            pool.current_bytes()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A write that was acknowledged reads back whole.
    let (keys, conn) = open
        .iter_mut()
        .find(|(keys, _)| !keys.is_empty())
        .expect("the pool holds some sessions' writes");
    conn.write_all(format!("GET {}\r\n", keys[0]).as_bytes())
        .await
        .unwrap();
    let header = format!("${VALUE_BYTES}\r\n");
    let mut reply = vec![0u8; header.len() + VALUE_BYTES + 2];
    conn.read_exact(&mut reply).await.unwrap();
    assert!(reply.starts_with(header.as_bytes()) && reply.ends_with(b"v\r\n"));

    // With the pool full, an ordinary session is still served from its floors.
    let mut small = TcpStream::connect(addr).await.unwrap();
    small
        .write_all(b"SET k cron-line\r\nGET k\r\n")
        .await
        .unwrap();
    assert_eq!(reply_line(&mut small).await.unwrap(), b"+OK\r\n");
    assert_eq!(reply_line(&mut small).await.unwrap(), b"$9\r\n");

    // Every way a session ends gives its room back.
    drop(open);
    drop(small);
    let deadline = Instant::now() + Duration::from_secs(10);
    while pool.current_bytes() > 0 {
        assert!(
            Instant::now() < deadline,
            "{} bytes still charged after every session closed",
            pool.current_bytes()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    handle.abort();
}

// -------------------------------------------------------------------------------------------
// The real binary, both listeners
// -------------------------------------------------------------------------------------------

/// Two distinct free loopback ports, released for the sensor to bind. Both listeners are held
/// until both ports are chosen, so the pair cannot collide with each other. The gap between
/// release and the sensor's bind remains, as with any port handed to a child by number: the
/// sensor reads its addresses from the environment, not from an inherited socket.
fn free_ports() -> (u16, u16) {
    let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    )
}

/// `VmHWM` (peak resident set) of `pid`, in bytes.
fn peak_rss(pid: u32) -> usize {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status
        .lines()
        .find(|l| l.starts_with("VmHWM:"))
        .expect("VmHWM in /proc/<pid>/status");
    let kib: usize = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap();
    kib * 1024
}

struct Sensor(Child);

impl Drop for Sensor {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_listening(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(addr).await.is_err() {
        assert!(Instant::now() < deadline, "{addr} never started listening");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The unit's `MemoryMax` (deploy/sensor-redis.service).
const MEMORY_MAX: usize = 256 * 1024 * 1024;

/// 256 sessions on each listener of the real binary, at its default bounds, every one sending
/// two SETs as large as a session may: the process's peak resident memory stays under half of
/// `MemoryMax`. Without the pool the same run peaks past `MemoryMax`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_binary_with_both_listeners_full_stays_well_under_memory_max() {
    const PER_LISTENER: usize = 256;
    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.path().join("redis.crt");
    let key_path = dir.path().join("redis.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(
        &key_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let (plain_port, tls_port) = free_ports();
    let plain: SocketAddr = format!("127.0.0.1:{plain_port}").parse().unwrap();
    let tls: SocketAddr = format!("127.0.0.1:{tls_port}").parse().unwrap();
    let sensor = Sensor(
        Command::new(env!("CARGO_BIN_EXE_sensor-redis"))
            .env_clear()
            // Each runtime worker adds its own dispatch copies and allocator arena, so the peak
            // follows the worker count; fixing it keeps the bound the same on every host. The
            // unit's CPUQuota=50% gives it fewer.
            .env("TOKIO_WORKER_THREADS", "4")
            .env("PROPOLIS_REDIS_BIND", plain.to_string())
            .env("PROPOLIS_REDIS_TLS_BIND", tls.to_string())
            .env("PROPOLIS_REDIS_TLS_CERT", &cert_path)
            .env("PROPOLIS_REDIS_TLS_KEY", &key_path)
            .env("PROPOLIS_REDIS_LOG_PATH", dir.path().join("events.jsonl"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_listening(plain).await;
    wait_listening(tls).await;
    let pid = sensor.0.id();
    let before = peak_rss(pid);

    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let value: Arc<[u8]> = vec![b'v'; VALUE_BYTES].into();
    let mut sessions = tokio::task::JoinSet::new();
    for i in 0..PER_LISTENER {
        let plain_value = value.clone();
        sessions.spawn(async move {
            let mut conn = connect_from(source(i), plain).await;
            let held = fill(&mut conn, &plain_value).await;
            (held, Box::new(conn) as Box<dyn Send>)
        });
        let value = value.clone();
        let connector = connector.clone();
        sessions.spawn(async move {
            let tcp = connect_from(source(i), tls).await;
            let mut conn = connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await
                .unwrap();
            let held = fill(&mut conn, &value).await;
            (held, Box::new(conn) as Box<dyn Send>)
        });
    }
    let mut open = Vec::new();
    let mut held_total = 0;
    while let Some(done) = sessions.join_next().await {
        let (held, conn) = done.unwrap();
        if let Some(keys) = held {
            held_total += held_bytes(&keys);
            open.push(conn);
        }
    }
    let peak = peak_rss(pid);
    eprintln!(
        "{} of {} sessions open holding {held_total} acknowledged bytes; sensor peak RSS {} \
         KiB (at start {} KiB)",
        open.len(),
        2 * PER_LISTENER,
        peak / 1024,
        before / 1024
    );
    assert!(
        held_total <= POOL_BYTES as usize + 2 * PER_LISTENER * STORE_FLOOR,
        "{held_total} acknowledged bytes held"
    );
    assert!(
        peak < MEMORY_MAX / 2,
        "the sensor peaked at {} KiB resident, against MemoryMax {} KiB",
        peak / 1024,
        MEMORY_MAX / 1024
    );
    drop(open);
    drop(sensor);
}
