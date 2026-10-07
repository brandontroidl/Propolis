//! Implicit-TLS (`rediss://`) tests. The TLS tests run the real listener in-process against a
//! rustls client; the fail-closed tests spawn the real binary with a cleared environment. Key
//! material is an rcgen key generated per test: the in-process tests hold it in memory, and the one
//! binary test that needs a usable pair writes it to a runtime tempdir (mode 0600) that is removed
//! when the test ends. The other files the binary tests write are non-PEM sentinel text.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::{TlsConnector, client::TlsStream};

const PASSWORD: &str = "SuperSecretPassword123";
const SENTINEL: &str = "SENTINEL-NOT-A-KEY-9f3a";

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

fn short_handshake_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_millis(300),
        ..test_bounds()
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

fn wan() -> Arc<WanResolver> {
    Arc::new(WanResolver::new(HashMap::new()))
}

async fn start_tls(bounds: ConnectionBounds) -> (Started, Arc<ClientConfig>) {
    let (server, client) = test_tls();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let (addr, handle) = sensor_redis::start_test_server_tls(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        wan(),
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

async fn start_plain() -> Started {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let (addr, handle) = sensor_redis::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log.clone(),
        wan(),
        test_bounds(),
    )
    .await
    .unwrap();
    Started {
        addr,
        log,
        handle,
        _dir: dir,
    }
}

/// Tolerates a missing log file: a session that emitted nothing never creates it.
fn events(log: &Path) -> Vec<sensor_wire::SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

async fn send_multibulk<S: AsyncWrite + Unpin>(conn: &mut S, parts: &[&str]) {
    let mut buf = format!("*{}\r\n", parts.len()).into_bytes();
    for p in parts {
        buf.extend_from_slice(format!("${}\r\n", p.len()).as_bytes());
        buf.extend_from_slice(p.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    conn.write_all(&buf).await.unwrap();
    conn.flush().await.unwrap();
}

async fn read_until_contains<S: AsyncRead + Unpin>(stream: &mut S, needle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let n = stream.read(&mut chunk).await.expect("read failed");
            assert!(n > 0, "connection closed before {needle:?} was seen");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(needle.len()).any(|w| w == needle) {
                return;
            }
        }
    })
    .await;
    result.unwrap_or_else(|_| panic!("timed out waiting for {needle:?}, got {buf:?}"));
    buf
}

fn tls_flag(event: &sensor_wire::SensorEvent) -> Option<bool> {
    event.metadata.get("tls").and_then(|v| v.as_bool())
}

#[tokio::test]
async fn rediss_session_round_trips_and_every_event_is_tagged_tls() {
    let (server, client) = start_tls(test_bounds()).await;
    let mut conn = tls_connect(server.addr, &client).await;

    send_multibulk(&mut conn, &["AUTH", PASSWORD]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["SET", "foo", "bar"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["GET", "foo"]).await;
    assert_eq!(
        read_until_contains(&mut conn, b"bar\r\n").await,
        b"$3\r\nbar\r\n"
    );
    drop(conn);
    // Events are appended before each reply is written, so all three are on disk already.
    server.handle.abort();

    let events = events(&server.log);
    assert!(
        events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
    );
    let logins: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .collect();
    assert_eq!(logins.len(), 1);
    assert!(logins[0].authenticated);
    assert!(events.iter().any(|e| {
        e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC
            && e.metadata.get("command").and_then(|v| v.as_str()) == Some("SET")
    }));
    for e in &events {
        assert_eq!(tls_flag(e), Some(true), "untagged event: {e:?}");
    }
    let raw = std::fs::read_to_string(&server.log).unwrap();
    assert!(
        !raw.contains(PASSWORD),
        "credential must never be captured, over TLS or otherwise"
    );
}

#[tokio::test]
async fn plain_listener_events_have_no_tls_key() {
    let server = start_plain().await;
    let mut conn = TcpStream::connect(server.addr).await.unwrap();
    send_multibulk(&mut conn, &["AUTH", "x"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    send_multibulk(&mut conn, &["SET", "k", "v"]).await;
    read_until_contains(&mut conn, b"+OK\r\n").await;
    drop(conn);
    server.handle.abort();

    let events = events(&server.log);
    assert!(events.len() >= 3, "connection, login, SET");
    for e in &events {
        assert!(e.metadata.get("tls").is_none(), "tls key leaked: {e:?}");
    }
}

#[tokio::test]
async fn plaintext_to_the_tls_port_is_dropped_without_events_and_the_listener_survives() {
    let (server, client) = start_tls(test_bounds()).await;

    let mut raw = TcpStream::connect(server.addr).await.unwrap();
    raw.write_all(b"PING\r\n").await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut got)).await;
    assert!(
        !got.windows(5).any(|w| w == b"+PONG"),
        "plaintext PING must not be answered: {got:?}"
    );
    assert!(
        events(&server.log).is_empty(),
        "a failed handshake emits no event"
    );

    let mut conn = tls_connect(server.addr, &client).await;
    send_multibulk(&mut conn, &["PING"]).await;
    assert_eq!(
        read_until_contains(&mut conn, b"+PONG\r\n").await,
        b"+PONG\r\n"
    );
    server.handle.abort();
}

#[tokio::test]
async fn a_stalled_tls_handshake_is_dropped_within_the_read_timeout() {
    let (server, _client) = start_tls(short_handshake_bounds()).await;
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
async fn a_protocol_error_over_tls_ends_with_close_notify_not_a_truncated_stream() {
    let (server, client) = start_tls(test_bounds()).await;
    let mut conn = tls_connect(server.addr, &client).await;
    conn.write_all(b"*abc\r\n").await.unwrap();
    conn.flush().await.unwrap();
    let mut got = Vec::new();
    // read_to_end errors with UnexpectedEof when the peer drops without close_notify.
    tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut got))
        .await
        .expect("server must close after a protocol error")
        .expect("TLS stream must end with close_notify");
    assert!(got.starts_with(b"-ERR Protocol error"), "{got:?}");
    server.handle.abort();
}

/// Spawn the binary with a cleared env, wait up to `wait`, kill it if still running. Returns the
/// exit code if it exited on its own and stdout+stderr (tracing writes to stdout).
fn run_binary(envs: &[(&str, &str)], wait: Duration) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-redis"))
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

/// Run with the plain bind and log path plus `extra`, assert the process refuses to start.
fn assert_refuses(dir: &Path, extra: &[(&str, &str)]) -> String {
    let log = dir.join("e.jsonl");
    let mut envs = vec![
        ("PROPOLIS_REDIS_BIND", "127.0.0.1:0"),
        ("PROPOLIS_REDIS_LOG_PATH", log.to_str().unwrap()),
    ];
    envs.extend_from_slice(extra);
    let (code, out) = run_binary(&envs, Duration::from_secs(10));
    assert_eq!(code, Some(1), "expected exit 1, output: {out}");
    assert!(out.contains("refusing to start"), "output: {out}");
    out
}

#[test]
fn tls_bind_with_no_cert_or_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    assert_refuses(dir.path(), &[("PROPOLIS_REDIS_TLS_BIND", "127.0.0.1:0")]);
}

#[test]
fn tls_bind_with_key_unset_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("c.pem");
    assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_REDIS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_TLS_CERT", cert.to_str().unwrap()),
        ],
    );
}

#[test]
fn exactly_one_of_cert_and_key_without_a_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("c.pem");
    assert_refuses(
        dir.path(),
        &[("PROPOLIS_REDIS_TLS_CERT", cert.to_str().unwrap())],
    );
    let key = dir.path().join("k.pem");
    assert_refuses(
        dir.path(),
        &[("PROPOLIS_REDIS_TLS_KEY", key.to_str().unwrap())],
    );
}

#[test]
fn cert_and_key_without_a_tls_bind_are_still_validated_and_refuse_when_unusable() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_REDIS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_KEY", key.to_str().unwrap()),
        ],
    );
}

#[test]
fn a_valid_pair_without_a_tls_bind_starts_no_tls_listener_and_warns() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let log = dir.path().join("e.jsonl");
    let (code, out) = run_binary(
        &[
            ("PROPOLIS_REDIS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_LOG_PATH", log.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_CERT", cert_path.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_KEY", key_path.to_str().unwrap()),
        ],
        Duration::from_secs(2),
    );
    assert_eq!(code, None, "sensor must keep running, output: {out}");
    assert!(out.contains("no TLS listener started"), "output: {out}");
    assert!(out.contains("listening"), "output: {out}");
    assert!(!out.contains("(tls)"), "output: {out}");
}

#[test]
fn tls_cert_and_key_files_missing_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = (dir.path().join("no.crt"), dir.path().join("no.key"));
    assert_refuses(
        dir.path(),
        &[
            ("PROPOLIS_REDIS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_KEY", key.to_str().unwrap()),
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
            ("PROPOLIS_REDIS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_KEY", key.to_str().unwrap()),
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
            ("PROPOLIS_REDIS_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_TLS_CERT", cert.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_KEY", key.to_str().unwrap()),
        ],
    );
    assert!(out.contains("group/other"), "output: {out}");
}

#[test]
fn invalid_tls_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    assert_refuses(dir.path(), &[("PROPOLIS_REDIS_TLS_BIND", "bogus")]);
}

#[test]
fn no_tls_vars_keeps_the_plain_sensor_running() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("e.jsonl");
    let (code, out) = run_binary(
        &[
            ("PROPOLIS_REDIS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_LOG_PATH", log.to_str().unwrap()),
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
            ("PROPOLIS_REDIS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_REDIS_LOG_PATH", log.to_str().unwrap()),
            ("PROPOLIS_REDIS_TLS_BIND", ""),
            ("PROPOLIS_REDIS_TLS_CERT", "  "),
            ("PROPOLIS_REDIS_TLS_KEY", "\t"),
        ],
        Duration::from_secs(2),
    );
    assert_eq!(code, None, "sensor must keep running, output: {out}");
    assert!(out.contains("sensor-redis: listening"), "output: {out}");
    assert!(!out.contains("(tls)"), "output: {out}");
}

/// A non-UTF-8 value on any TLS variable is invalid, never read as unset (which would start the
/// sensor without the TLS the operator configured): exit 1, naming the variable, before any
/// listener binds.
#[test]
fn a_non_utf8_tls_var_exits_1_before_any_listener_binds() {
    use std::os::unix::ffi::OsStrExt;
    let bad = std::ffi::OsStr::from_bytes(b"/etc/propolis/tls/\xff");
    for var in [
        "PROPOLIS_REDIS_TLS_BIND",
        "PROPOLIS_REDIS_TLS_CERT",
        "PROPOLIS_REDIS_TLS_KEY",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-redis"))
            .env_clear()
            .env("NO_COLOR", "1")
            .env("PROPOLIS_REDIS_BIND", "127.0.0.1:0")
            .env("PROPOLIS_REDIS_LOG_PATH", dir.path().join("e.jsonl"))
            .env(var, bad)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let out = child.wait_with_output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.status.code(), Some(1), "{var}: {text}");
        assert!(
            text.contains(var) && text.contains("UTF-8"),
            "{var}: {text}"
        );
        assert!(!text.contains("listening"), "{var}: bound first: {text}");
    }
}
