//! The per-source bound on connection and login events, through real sockets: several hundred
//! probes from one address write a bounded number of lines plus one summary carrying the exact
//! totals, and a second source is untouched.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_cred::SummaryFlush;
use sensor_framework::{ConnectionBounds, SourceEventConfig, WanResolver};
use sensor_wire::{
    SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SensorEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinHandle;

/// The documented defaults: ten of each kind per address per window.
const ADDRESS_BUDGET: usize = 10;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

struct Server {
    addr: SocketAddr,
    log: PathBuf,
    flush: SummaryFlush,
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Server {
    async fn start(protocol: &'static str, flood: SourceEventConfig) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events.jsonl");
        let (addr, handle, flush) = sensor_cred::start_listener(
            "127.0.0.1:0".parse().unwrap(),
            log.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds(),
            protocol,
            None,
            flood,
        )
        .await
        .unwrap();
        Server {
            addr,
            log,
            flush,
            handle,
            _dir: dir,
        }
    }

    /// A connection from `from` (an address of 127.0.0.0/8), which stands in for a distinct source.
    async fn connect_from(&self, from: &str) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(format!("{from}:0").parse().unwrap()).unwrap();
        socket.connect(self.addr).await.unwrap()
    }
}

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
        .collect()
}

fn is_summary(e: &SensorEvent) -> bool {
    e.metadata.get("event_summary").is_some()
}

fn count(events: &[SensorEvent], source: &str, signal: &str, summary: bool) -> usize {
    events
        .iter()
        .filter(|e| {
            e.source_ip.to_string() == source && e.signal_type == signal && is_summary(e) == summary
        })
        .count()
}

/// One complete VNC authentication attempt with the given RFB version string.
async fn vnc_attempt(mut conn: TcpStream, version: &[u8; 12]) {
    let mut buf = [0u8; 16];
    conn.read_exact(&mut buf[..12]).await.unwrap();
    conn.write_all(version).await.unwrap();
    conn.read_exact(&mut buf[..2]).await.unwrap();
    conn.write_all(&[2]).await.unwrap();
    conn.read_exact(&mut buf).await.unwrap();
    conn.write_all(&[0xAA; 16]).await.unwrap();
    // The login event is written before the SecurityResult, so this read means it was handled.
    conn.read_exact(&mut buf[..4]).await.unwrap();
}

#[tokio::test]
async fn a_vnc_flood_from_one_source_is_bounded_and_summarized_with_exact_totals() {
    const PROBES: usize = 400;
    let srv = Server::start("vnc", SourceEventConfig::default()).await;
    for i in 0..PROBES {
        let version = if i % 4 == 0 {
            b"RFB 003.003\n"
        } else {
            b"RFB 003.008\n"
        };
        vnc_attempt(srv.connect_from("127.0.0.1").await, version).await;
    }
    // A second source, in another /24, is not charged for the first one's flood.
    for _ in 0..3 {
        vnc_attempt(srv.connect_from("127.0.1.1").await, b"RFB 003.008\n").await;
    }
    srv.flush.flush().await;

    let all = events(&srv.log);
    let (flooder, other) = ("127.0.0.1", "127.0.1.1");
    assert_eq!(
        count(&all, flooder, SIGNAL_HONEYPOT_CONNECTION, false),
        ADDRESS_BUDGET
    );
    assert_eq!(
        count(&all, flooder, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, false),
        ADDRESS_BUDGET
    );
    let flooder_lines: Vec<_> = all
        .iter()
        .filter(|e| e.source_ip.to_string() == flooder)
        .collect();
    assert_eq!(
        flooder_lines.len(),
        2 * ADDRESS_BUDGET + 1,
        "{PROBES} probes (800 events) wrote the budget plus one summary"
    );

    let summary = flooder_lines.iter().find(|e| is_summary(e)).unwrap();
    assert_eq!(summary.signal_type, SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
    assert!(
        summary.authenticated,
        "a folded attempt keeps the login's authenticated flag"
    );
    let md = &summary.metadata;
    assert_eq!(md["suppressed_connections"], PROBES - ADDRESS_BUDGET);
    assert_eq!(md["suppressed_attempts"], PROBES - ADDRESS_BUDGET);
    assert_eq!(md["suppressed_count"], 2 * (PROBES - ADDRESS_BUDGET));
    assert_eq!(md["source_prefix"], "127.0.0.0/24");
    assert_eq!(md["protocol_label"], "vnc");
    let versions: Vec<&str> = md["client_versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        versions.contains(&"RFB 003.003") && versions.contains(&"RFB 003.008"),
        "{versions:?}"
    );
    assert_eq!(md["session_count_capped"], true);

    // Verbatim logins carry the client version too, with no trailing newline.
    let login = flooder_lines
        .iter()
        .find(|e| !is_summary(e) && e.signal_type == SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert!(
        ["RFB 003.003", "RFB 003.008"]
            .contains(&login.metadata["client_version"].as_str().unwrap())
    );

    // The second source wrote all of its events and has nothing summarized.
    assert_eq!(count(&all, other, SIGNAL_HONEYPOT_CONNECTION, false), 3);
    assert_eq!(count(&all, other, SIGNAL_HONEYPOT_LOGIN_ATTEMPT, false), 3);
    assert_eq!(
        all.iter()
            .filter(|e| e.source_ip.to_string() == other && is_summary(e))
            .count(),
        0
    );
    srv.handle.abort();
}

/// What `main` wrote before the bound: the same drive with every budget lifted writes every event.
/// It shows the assertions above can fail, and that the lines are the ones the budget removed.
#[tokio::test]
async fn with_the_budgets_lifted_every_event_is_written() {
    let max = NonZeroU32::MAX;
    let srv = Server::start(
        "vnc",
        SourceEventConfig {
            address_budget: max,
            network_budget: max,
            total_budget: max,
            ..SourceEventConfig::default()
        },
    )
    .await;
    for _ in 0..100 {
        vnc_attempt(srv.connect_from("127.0.0.1").await, b"RFB 003.008\n").await;
    }
    srv.flush.flush().await;
    let all = events(&srv.log);
    assert_eq!(all.len(), 200);
    assert!(all.iter().all(|e| !is_summary(e)));
    srv.handle.abort();
}

/// The writer task, not only the shutdown flush: with a short window the summary of an ended
/// window appears in the log on its own.
#[tokio::test]
async fn the_summary_of_an_ended_window_is_written_without_a_shutdown() {
    let srv = Server::start(
        "vnc",
        SourceEventConfig {
            window: Duration::from_millis(400),
            address_budget: NonZeroU32::new(2).unwrap(),
            ..SourceEventConfig::default()
        },
    )
    .await;
    // Probes finish well inside one window on any machine this runs on; a probe that straddled
    // two windows would still be counted, only split over two summaries, which the sum absorbs.
    for _ in 0..30 {
        vnc_attempt(srv.connect_from("127.0.0.1").await, b"RFB 003.008\n").await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut verbatim, mut folded) = (0, 0);
    while Instant::now() < deadline {
        let all = events(&srv.log);
        verbatim = all.iter().filter(|e| !is_summary(e)).count();
        folded = all
            .iter()
            .filter(|e| is_summary(e))
            .map(|e| e.metadata["suppressed_count"].as_u64().unwrap() as usize)
            .sum();
        if verbatim + folded == 60 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        verbatim + folded,
        60,
        "60 events written or counted, none lost"
    );
    assert!(
        verbatim <= 12 && folded >= 48,
        "verbatim {verbatim}, folded {folded}"
    );
    srv.handle.abort();
}

/// Every other cred protocol writes through the same emitter, so the same bound holds. A bare
/// connect-and-close is enough for the connection event of each.
#[tokio::test]
async fn the_other_cred_protocols_share_the_bound() {
    const PROBES: usize = 60;
    for protocol in ["mysql", "mssql", "postgresql", "mongodb"] {
        let srv = Server::start(protocol, SourceEventConfig::default()).await;
        for _ in 0..PROBES {
            let mut conn = srv.connect_from("127.0.0.1").await;
            let _ = conn.shutdown().await;
        }
        // Handlers run concurrently with the test: wait until all are counted, flushing as the
        // shutdown path does so folded counts reach the log.
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut verbatim, mut folded) = (0usize, 0usize);
        while Instant::now() < deadline {
            srv.flush.flush().await;
            let all = events(&srv.log);
            verbatim = all
                .iter()
                .filter(|e| !is_summary(e) && e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
                .count();
            folded = all
                .iter()
                .filter(|e| is_summary(e))
                .map(|e| e.metadata["suppressed_count"].as_u64().unwrap() as usize)
                .sum();
            if verbatim + folded == PROBES {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(verbatim + folded, PROBES, "{protocol}: none lost");
        assert_eq!(verbatim, ADDRESS_BUDGET, "{protocol}");
        assert!(
            events(&srv.log).iter().all(|e| e.sensor == protocol),
            "{protocol}: summaries carry the protocol's own sensor label"
        );
        srv.handle.abort();
    }
}

/// PostgreSQL's queries are command events. A session may run at most 200 messages, so a flood
/// is many sessions; from one source network they are held to the command-event budget (burst
/// 200) and the rest is one `command_summary`.
#[tokio::test]
async fn postgresql_queries_are_held_to_the_command_event_budget() {
    const SESSIONS: usize = 4;
    const QUERIES_PER_SESSION: usize = 150;
    let srv = Server::start("postgresql", SourceEventConfig::default()).await;
    async fn read_msg(conn: &mut TcpStream) -> u8 {
        let mut t = [0u8; 1];
        conn.read_exact(&mut t).await.unwrap();
        let mut l = [0u8; 4];
        conn.read_exact(&mut l).await.unwrap();
        let mut body = vec![0u8; i32::from_be_bytes(l) as usize - 4];
        conn.read_exact(&mut body).await.unwrap();
        t[0]
    }
    for _ in 0..SESSIONS {
        let mut conn = srv.connect_from("127.0.0.1").await;
        let mut startup = Vec::new();
        startup.extend_from_slice(&196608i32.to_be_bytes());
        startup.extend_from_slice(b"user\0pgadmin\0database\0testdb\0\0");
        let mut msg = ((4 + startup.len()) as i32).to_be_bytes().to_vec();
        msg.extend_from_slice(&startup);
        conn.write_all(&msg).await.unwrap();
        assert_eq!(read_msg(&mut conn).await, b'R'); // password request
        let pw = b"md5fakehashvalue00000000000000000\0";
        let mut pw_msg = vec![b'p'];
        pw_msg.extend_from_slice(&((4 + pw.len()) as i32).to_be_bytes());
        pw_msg.extend_from_slice(pw);
        conn.write_all(&pw_msg).await.unwrap();
        while read_msg(&mut conn).await != b'Z' {}
        let sql = b"SELECT version()\0";
        let mut q = vec![b'Q'];
        q.extend_from_slice(&((4 + sql.len()) as i32).to_be_bytes());
        q.extend_from_slice(sql);
        for _ in 0..QUERIES_PER_SESSION {
            conn.write_all(&q).await.unwrap();
            assert_eq!(read_msg(&mut conn).await, b'E');
            assert_eq!(read_msg(&mut conn).await, b'Z');
        }
    }
    srv.flush.flush().await;

    let all = events(&srv.log);
    let verbatim = all
        .iter()
        .filter(|e| {
            e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC
                && e.metadata.get("command_summary").is_none()
        })
        .count();
    let summaries: Vec<_> = all
        .iter()
        .filter(|e| e.metadata.get("command_summary").is_some())
        .collect();
    assert_eq!(summaries.len(), 1);
    // The burst, plus at most the tokens 12 a minute refills while the test runs.
    assert!((200..=202).contains(&verbatim), "{verbatim}");
    assert_eq!(
        summaries[0].metadata["suppressed_count"],
        SESSIONS * QUERIES_PER_SESSION - verbatim,
        "every query is written or counted"
    );
    srv.handle.abort();
}
