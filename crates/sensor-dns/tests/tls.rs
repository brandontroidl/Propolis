//! DNS over TLS tests. The in-process tests run the real DoT listener against a rustls client;
//! the fail-closed tests spawn the real binary with a cleared environment. Key material is an
//! rcgen key generated per test: the in-process tests hold it in memory, and the binary tests that
//! need a usable pair write it to a runtime tempdir (mode 0600) removed when the test ends. The
//! other files the binary tests write are non-PEM sentinel text.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver};
use sensor_wire::{SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SensorEvent};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsConnector, client::TlsStream};

const SENTINEL: &str = "SENTINEL-NOT-A-KEY-9f3a";

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 262_144,
        max_concurrent: 100,
    }
}

/// Ephemeral self-signed cert for "localhost": the framework's server config built from in-memory
/// PEM (the same parse path the file loader uses) plus a client that trusts exactly that cert.
fn test_tls() -> (TlsServer, Arc<ClientConfig>) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server = sensor_framework::server_config_from_pem(
        cert.pem().as_bytes(),
        signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (TlsServer::from_config(server), Arc::new(client))
}

async fn tls_connect(addr: SocketAddr, client: &Arc<ClientConfig>) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    TlsConnector::from(client.clone())
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

struct Started {
    addr: SocketAddr,
    log: PathBuf,
    handle: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

async fn start_tls(bounds: ConnectionBounds) -> (Started, Arc<ClientConfig>) {
    let (server, client) = test_tls();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let (addr, handle) = sensor_dns::start_test_server_tls(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds,
        server,
    )
    .await
    .unwrap();
    (
        Started {
            addr,
            log,
            handle,
            _dir: dir,
        },
        client,
    )
}

/// Tolerates a missing log file: a session that emitted nothing never creates it.
fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn wait_for(log: &Path, what: &str, pred: impl Fn(&SensorEvent) -> bool) -> SensorEvent {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(e) = events(log).into_iter().find(&pred) {
            return e;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn query(id: u16, labels: &[&[u8]], qtype: u16) -> Vec<u8> {
    let mut m = id.to_be_bytes().to_vec();
    m.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in labels {
        m.push(l.len() as u8);
        m.extend_from_slice(l);
    }
    m.push(0);
    m.extend(qtype.to_be_bytes());
    m.extend(1u16.to_be_bytes());
    m
}

fn framed(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

async fn write_query<S: AsyncWrite + Unpin>(conn: &mut S, msg: &[u8]) {
    conn.write_all(&framed(msg)).await.unwrap();
    conn.flush().await.unwrap();
}

async fn read_framed<S: AsyncRead + Unpin>(conn: &mut S) -> Vec<u8> {
    let mut prefix = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), conn.read_exact(&mut prefix))
        .await
        .expect("timed out waiting for a reply")
        .unwrap();
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    tokio::time::timeout(Duration::from_secs(3), conn.read_exact(&mut body))
        .await
        .expect("timed out waiting for a reply body")
        .unwrap();
    body
}

fn tls_flag(event: &SensorEvent) -> Option<bool> {
    event.metadata.get("tls").and_then(|v| v.as_bool())
}

#[tokio::test]
async fn dot_query_round_trips_and_every_event_is_tagged_tls() {
    let (server, client) = start_tls(test_bounds()).await;
    let mut conn = tls_connect(server.addr, &client).await;
    let msg = query(0x5151, &[b"example", b"com"], 1);
    write_query(&mut conn, &msg).await;
    let reply = read_framed(&mut conn).await;
    assert_eq!(&reply[0..2], &[0x51, 0x51]);
    assert_eq!(u16::from_be_bytes([reply[2], reply[3]]), 0x8105);
    assert_eq!(&reply[12..], &msg[12..]);
    drop(conn);
    // Events are appended before each reply is written, so both are on disk already.
    server.handle.abort();

    let events = events(&server.log);
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(
        events
            .iter()
            .any(|e| e.signal_type == SIGNAL_HONEYPOT_CONNECTION)
    );
    let q = events
        .iter()
        .find(|e| e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("query event");
    assert_eq!(q.metadata["command"], "A example.com.");
    assert_eq!(q.metadata["transport"], "tcp");
    for e in &events {
        assert_eq!(tls_flag(e), Some(true), "untagged event: {e:?}");
    }
}

#[tokio::test]
async fn dot_pipelined_queries_answered_in_order() {
    let (server, client) = start_tls(test_bounds()).await;
    let mut conn = tls_connect(server.addr, &client).await;
    let mut batch = Vec::new();
    for id in [1u16, 2, 3] {
        batch.extend(framed(&query(id, &[b"example", b"com"], 1)));
    }
    conn.write_all(&batch).await.unwrap();
    conn.flush().await.unwrap();
    for id in [1u16, 2, 3] {
        let reply = read_framed(&mut conn).await;
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), id);
    }
    server.handle.abort();
}

#[tokio::test]
async fn plaintext_to_the_dot_port_is_dropped_without_events_and_the_listener_survives() {
    let (server, client) = start_tls(test_bounds()).await;

    let mut raw = TcpStream::connect(server.addr).await.unwrap();
    raw.write_all(&framed(&query(9, &[b"example", b"com"], 1)))
        .await
        .unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut got)).await;
    assert!(
        !got.windows(2).any(|w| w == [0x00, 0x09]),
        "a plaintext query must not be answered: {got:?}"
    );
    assert!(
        events(&server.log).is_empty(),
        "a failed handshake emits no event"
    );

    let mut conn = tls_connect(server.addr, &client).await;
    write_query(&mut conn, &query(10, &[b"example", b"com"], 1)).await;
    let reply = read_framed(&mut conn).await;
    assert_eq!(&reply[0..2], &[0, 10]);
    server.handle.abort();
}

#[tokio::test]
async fn a_stalled_tls_handshake_is_dropped_within_the_read_timeout() {
    let bounds = ConnectionBounds {
        read_timeout: Duration::from_millis(300),
        ..test_bounds()
    };
    let (server, _client) = start_tls(bounds).await;
    let mut tcp = TcpStream::connect(server.addr).await.unwrap();
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut [0u8; 16]))
        .await
        .expect("server must close a stalled handshake well before max_duration");
    assert!(matches!(outcome, Ok(0) | Err(_)));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(events(&server.log).is_empty());
    server.handle.abort();
}

#[tokio::test]
async fn a_rejected_message_over_tls_ends_with_close_notify() {
    let (server, client) = start_tls(test_bounds()).await;
    let mut conn = tls_connect(server.addr, &client).await;
    conn.write_all(&5u16.to_be_bytes()).await.unwrap();
    conn.flush().await.unwrap();
    let mut got = Vec::new();
    // read_to_end errors with UnexpectedEof when the peer drops without close_notify.
    tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut got))
        .await
        .expect("server must close after a rejected message")
        .expect("TLS stream must end with close_notify");
    assert!(got.is_empty(), "{got:?}");
    let e = wait_for(&server.log, "rejected", |e| {
        e.metadata.get("reject_reason").and_then(|v| v.as_str()) == Some("short_header")
    })
    .await;
    assert_eq!(tls_flag(&e), Some(true));
    server.handle.abort();
}

#[tokio::test]
async fn axfr_over_dot_is_captured_and_tagged() {
    let (server, client) = start_tls(test_bounds()).await;
    let mut conn = tls_connect(server.addr, &client).await;
    write_query(&mut conn, &query(4, &[b"example", b"com"], 252)).await;
    let reply = read_framed(&mut conn).await;
    assert_eq!(reply[3] & 0x0F, 5);
    let e = wait_for(&server.log, "axfr", |e| {
        e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC
    })
    .await;
    assert_eq!(e.metadata["command"], "AXFR example.com.");
    assert_eq!(
        e.metadata["probe_signals"],
        serde_json::json!(["zone_transfer_probe"])
    );
    assert_eq!(tls_flag(&e), Some(true));
    server.handle.abort();
}

/// Spawn the binary with a cleared env, wait up to `wait`, kill it if still running. Returns the
/// exit code if it exited on its own and stdout+stderr (tracing writes to stdout).
fn run_binary(envs: &[(&str, &str)], wait: Duration) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-dns"))
        .env_clear()
        // NO_COLOR keeps ANSI escapes out of the log text the tests match on. RUST_LOG is left
        // unset: the warning and info lines asserted below rely on the INFO default.
        .env("NO_COLOR", "1")
        .envs(envs.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + wait;
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = child.wait_with_output().unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (code, text)
}

/// Run with the plain bind and log path plus `extra` (a later entry for the same name wins),
/// assert the process refuses to start.
fn assert_refuses(dir: &Path, extra: &[(&str, &str)]) -> String {
    let log = dir.join("e.jsonl");
    let mut envs = vec![
        ("PROPOLIS_DNS_BIND", "127.0.0.1:0"),
        ("PROPOLIS_DNS_LOG_PATH", log.to_str().unwrap()),
    ];
    envs.extend_from_slice(extra);
    let (code, out) = run_binary(&envs, Duration::from_secs(10));
    assert_eq!(code, Some(1), "expected exit 1, output: {out}");
    assert!(out.contains("refusing to start"), "output: {out}");
    assert!(!out.contains("listening"), "output: {out}");
    out
}

/// A usable cert and a 0600 key written to `dir`.
fn write_pair(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.join("c.pem"), dir.join("k.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (cert_path, key_path)
}

#[test]
fn no_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("e.jsonl");
    let (code, out) = run_binary(
        &[("PROPOLIS_DNS_LOG_PATH", log.to_str().unwrap())],
        Duration::from_secs(10),
    );
    assert_eq!(code, Some(1), "output: {out}");
    assert!(out.contains("refusing to start"), "output: {out}");
    assert!(out.contains("PROPOLIS_DNS_BIND"), "output: {out}");
    assert!(!out.contains("listening"), "output: {out}");
}

#[test]
fn invalid_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    assert_refuses(dir.path(), &[("PROPOLIS_DNS_BIND", "nonsense:53")]);
}

#[test]
fn a_zero_bound_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let out = assert_refuses(dir.path(), &[("PROPOLIS_DNS_MAX_CONCURRENT", "0")]);
    assert!(out.contains("PROPOLIS_DNS_MAX_CONCURRENT"), "output: {out}");
}

#[test]
fn tls_bind_with_no_cert_or_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    assert_refuses(dir.path(), &[("PROPOLIS_DNS_TLS_BIND", "127.0.0.1:0")]);
}

#[test]
fn tls_bind_with_key_unset_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("c.pem");
    assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_DNS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
        ],
    );
}

#[test]
fn exactly_one_of_cert_and_key_without_a_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("c.pem");
    assert_refuses(
        dir.path(),
        &[("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap())],
    );
    let key = dir.path().join("k.pem");
    assert_refuses(
        dir.path(),
        &[("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap())],
    );
}

#[test]
fn cert_and_key_without_a_tls_bind_are_still_validated_and_refuse_when_unusable() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap()),
        ],
    );
}

#[test]
fn a_valid_pair_without_a_tls_bind_starts_no_tls_listener_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_pair(dir.path());
    let log = dir.path().join("e.jsonl");
    let (code, out) = run_binary(
        &[
            ("PROPOLIS_DNS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_LOG_PATH", log.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap()),
        ],
        Duration::from_secs(2),
    );
    assert_eq!(code, None, "sensor must keep running, output: {out}");
    assert!(out.contains("no TLS listener started"), "output: {out}");
    assert!(out.contains("sensor-dns: listening"), "output: {out}");
    assert!(!out.contains("(tls)"), "output: {out}");
}

#[test]
fn tls_cert_and_key_files_missing_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("no.crt"), dir.path().join("no.key"));
    assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_DNS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap()),
        ],
    );
}

#[test]
fn tls_files_that_are_not_pem_refuse_to_start_and_are_not_echoed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert, SENTINEL).unwrap();
    std::fs::write(&key, SENTINEL).unwrap();
    // 0600 so the refusal is about the content, not the key-permission check.
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_DNS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap()),
        ],
    );
    assert!(!out.contains(SENTINEL), "file contents echoed: {out}");
}

#[test]
fn a_group_readable_key_file_refuses_to_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert, SENTINEL).unwrap();
    std::fs::write(&key, SENTINEL).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
    let out = assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_DNS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap()),
        ],
    );
    assert!(out.contains("group/other"), "output: {out}");
}

#[test]
fn invalid_tls_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    assert_refuses(dir.path(), &[("PROPOLIS_DNS_TLS_BIND", "bogus")]);
}

/// The plain pair binds first; a DoT bind that then fails (address in use) must take the whole
/// sensor down with the uniform message, leaving nothing serving on the plain port.
#[test]
fn a_tls_bind_already_in_use_exits_1_and_leaves_the_plain_ports_unserved() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = write_pair(dir.path());
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_addr = taken.local_addr().unwrap().to_string();
    let plain_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let plain_bind = format!("127.0.0.1:{plain_port}");
    let log = dir.path().join("e.jsonl");

    let (code, out) = run_binary(
        &[
            ("PROPOLIS_DNS_BIND", &plain_bind),
            ("PROPOLIS_DNS_LOG_PATH", log.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_BIND", &taken_addr),
            ("PROPOLIS_DNS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_KEY", key.to_str().unwrap()),
        ],
        Duration::from_secs(10),
    );
    assert_eq!(code, Some(1), "expected exit 1, output: {out}");
    assert!(
        out.contains(&format!(
            "sensor-dns: dot: cannot start listener on {taken_addr}: "
        )),
        "output: {out}"
    );
    assert!(out.contains("refusing to start"), "output: {out}");
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", plain_port)).is_err(),
        "the plain TCP listener was left serving after the TLS bind failed"
    );
    drop(taken);
}

#[test]
fn no_tls_vars_keeps_the_plain_sensor_running() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("e.jsonl");
    let (code, out) = run_binary(
        &[
            ("PROPOLIS_DNS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_LOG_PATH", log.to_str().unwrap()),
        ],
        Duration::from_secs(1),
    );
    assert_eq!(code, None, "plain sensor must keep running, output: {out}");
}

/// Blank or whitespace-only TLS vars read as unset, as `deploy/fleet-listeners.sh` reads a blank
/// bind: the plain sensor runs, no TLS listener, no refusal.
#[test]
fn blank_tls_vars_are_unset() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("e.jsonl");
    let (code, out) = run_binary(
        &[
            ("PROPOLIS_DNS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_DNS_LOG_PATH", log.to_str().unwrap()),
            ("PROPOLIS_DNS_TLS_BIND", ""),
            ("PROPOLIS_DNS_TLS_CERT", "  "),
            ("PROPOLIS_DNS_TLS_KEY", "\t"),
        ],
        Duration::from_secs(2),
    );
    assert_eq!(code, None, "sensor must keep running, output: {out}");
    assert!(out.contains("sensor-dns: listening"), "output: {out}");
    assert!(!out.contains("(tls)"), "output: {out}");
}
