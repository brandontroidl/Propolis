use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, server_config_from_pem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const GET_ROOT: &str = "GET / HTTP/1.1\r\nHost: test\r\n\r\n";

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

fn short_handshake_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_millis(300),
        ..test_bounds()
    }
}

/// Ephemeral self-signed cert for "localhost": (cert pem, key pem, cert der).
fn ephemeral() -> (String, String, Vec<u8>) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    (cert.pem(), signing_key.serialize_pem(), cert.der().to_vec())
}

fn client_for(der: Vec<u8>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(der)).unwrap();
    TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

async fn tls_connect(addr: SocketAddr, connector: &TlsConnector) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

struct Server {
    addr: SocketAddr,
    log_path: PathBuf,
    handle: JoinHandle<()>,
    connector: TlsConnector,
    _dir: tempfile::TempDir,
}

impl Server {
    async fn start_tls(bounds: ConnectionBounds) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let (cert, key, der) = ephemeral();
        let tls = TlsServer::from_config(
            server_config_from_pem(cert.as_bytes(), key.as_bytes()).unwrap(),
        );
        let (addr, handle) = sensor_http::start_test_server_tls(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds,
            tls,
        )
        .await
        .unwrap();
        Server {
            addr,
            log_path,
            handle,
            connector: client_for(der),
            _dir: dir,
        }
    }

    async fn start_plain() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let (addr, handle) = sensor_http::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            test_bounds(),
        )
        .await
        .unwrap();
        Server {
            addr,
            log_path,
            handle,
            connector: client_for(ephemeral().2),
            _dir: dir,
        }
    }

    async fn events(&self) -> Vec<sensor_wire::SensorEvent> {
        let content = tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event line: {e}: {l}")))
            .collect()
    }

    async fn https_get_root(&self) -> String {
        let mut conn = tls_connect(self.addr, &self.connector).await;
        conn.write_all(GET_ROOT.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        // A clean EOF (Ok) proves the server sent close_notify; an unexpected EOF is an Err.
        tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut buf))
            .await
            .expect("read timed out")
            .expect("server closed without close_notify");
        String::from_utf8_lossy(&buf).into_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[tokio::test]
async fn https_get_root_serves_nginx_page_and_tags_events_tls() {
    let srv = Server::start_tls(test_bounds()).await;
    let response = srv.https_get_root().await;
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("Welcome to nginx!"));

    let events = srv.events().await;
    let conn: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
        .collect();
    let cmd: Vec<_> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .collect();
    assert_eq!((conn.len(), cmd.len(), events.len()), (1, 1, 2));
    for e in &events {
        assert_eq!(e.metadata["tls"], serde_json::Value::Bool(true));
        assert_eq!(e.sensor, "http");
        assert_eq!(e.protocol, sensor_wire::PROTO_TCP);
    }
    assert_eq!(cmd[0].metadata["method"], "GET");
    assert_eq!(cmd[0].metadata["path"], "/");
}

#[tokio::test]
async fn https_post_body_is_captured_over_tls() {
    let srv = Server::start_tls(test_bounds()).await;
    let mut conn = tls_connect(srv.addr, &srv.connector).await;
    conn.write_all(b"POST /login HTTP/1.1\r\nHost: t\r\nContent-Length: 11\r\n\r\nuser=a&p=b!")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut buf)).await;
    let cmd = srv
        .events()
        .await
        .into_iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("request event");
    assert_eq!(cmd.metadata["body_preview"], "user=a&p=b!");
    assert_eq!(cmd.metadata["tls"], serde_json::Value::Bool(true));
}

#[tokio::test]
async fn plain_listener_events_have_no_tls_key() {
    let srv = Server::start_plain().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    conn.write_all(GET_ROOT.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut buf)).await;
    assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200 OK"));

    let events = srv.events().await;
    assert_eq!(events.len(), 2);
    for e in &events {
        assert!(e.metadata.get("tls").is_none(), "{:?}", e.metadata);
    }
}

#[tokio::test]
async fn plaintext_to_the_tls_port_is_dropped_without_events_and_the_listener_survives() {
    let srv = Server::start_tls(test_bounds()).await;
    let mut raw = TcpStream::connect(srv.addr).await.unwrap();
    raw.write_all(GET_ROOT.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut buf)).await;
    assert!(
        !String::from_utf8_lossy(&buf).contains("HTTP/"),
        "plaintext request was answered over a TLS port"
    );
    assert!(srv.events().await.is_empty());

    let response = srv.https_get_root().await;
    assert!(response.starts_with("HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn a_stalled_tls_handshake_is_dropped_within_the_read_timeout() {
    let srv = Server::start_tls(short_handshake_bounds()).await;
    let mut tcp = TcpStream::connect(srv.addr).await.unwrap();
    // Without the handshake timeout the socket stays open until max_duration (30s) and this
    // outer 3s timeout fires.
    let closed = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut [0u8; 16]))
        .await
        .expect("server did not drop a stalled handshake");
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    assert!(srv.events().await.is_empty());
}

// ---- main.rs fail-closed behavior, driven through the real binary ----

/// A spawned sensor-http with a cleared environment; both output streams are collected.
struct Proc {
    child: Child,
    out: Arc<Mutex<String>>,
}

impl Proc {
    fn spawn(envs: &[(&str, &str)]) -> Proc {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-http"))
            .env_clear()
            // NO_COLOR keeps ANSI escapes out of the log text the tests match on.
            .env("NO_COLOR", "1")
            // A workspace build unifies tracing-subscriber's `env-filter` feature on, which makes
            // an unset RUST_LOG mean errors only; the tests match on info lines.
            .env("RUST_LOG", "info")
            .envs(envs.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let out = Arc::new(Mutex::new(String::new()));
        let mut pipes: Vec<Box<dyn Read + Send>> = vec![
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        for mut pipe in pipes.drain(..) {
            let out = out.clone();
            std::thread::spawn(move || {
                let mut chunk = [0u8; 1024];
                while let Ok(n) = pipe.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    out.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&chunk[..n]));
                }
            });
        }
        Proc { child, out }
    }

    fn output(&self) -> String {
        self.out.lock().unwrap().clone()
    }

    /// The exit code if the process exits within `wait`, else None (still running).
    fn exit_code_within(&mut self, wait: Duration) -> Option<i32> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                // Let the reader threads drain the closed pipes.
                std::thread::sleep(Duration::from_millis(100));
                return Some(status.code().unwrap_or(-1));
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn wait_for_output(&self, needle: &str, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        while Instant::now() < deadline {
            if self.output().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn base_env(dir: &Path) -> Vec<(String, String)> {
    vec![
        ("PROPOLIS_HTTP_BIND".into(), "127.0.0.1:0".into()),
        (
            "PROPOLIS_HTTP_LOG_PATH".into(),
            dir.join("e.jsonl").display().to_string(),
        ),
    ]
}

fn refuses(extra: &[(&str, &str)], dir: &Path) -> String {
    let mut envs = base_env(dir);
    envs.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut p = Proc::spawn(&refs);
    let code = p.exit_code_within(Duration::from_secs(10));
    let output = p.output();
    assert_eq!(code, Some(1), "expected exit 1; output: {output}");
    assert!(output.contains("refusing to start"), "output: {output}");
    output
}

fn write_key(path: &Path, pem: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, pem).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).display().to_string()
}

#[test]
fn tls_bind_with_no_cert_or_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(&[("PROPOLIS_HTTP_TLS_BIND", "127.0.0.1:0")], dir.path());
}

#[test]
fn tls_bind_with_key_unset_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[
            ("PROPOLIS_HTTP_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_HTTP_TLS_CERT", &p(dir.path(), "c.pem")),
        ],
        dir.path(),
    );
}

#[test]
fn exactly_one_of_cert_and_key_without_a_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[("PROPOLIS_HTTP_TLS_KEY", &p(dir.path(), "k.pem"))],
        dir.path(),
    );
    refuses(
        &[("PROPOLIS_HTTP_TLS_CERT", &p(dir.path(), "c.pem"))],
        dir.path(),
    );
}

#[test]
fn invalid_tls_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(&[("PROPOLIS_HTTP_TLS_BIND", "bogus")], dir.path());
}

#[test]
fn tls_cert_and_key_files_missing_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[
            ("PROPOLIS_HTTP_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_HTTP_TLS_CERT", &p(dir.path(), "nope.crt")),
            ("PROPOLIS_HTTP_TLS_KEY", &p(dir.path(), "nope.key")),
        ],
        dir.path(),
    );
}

#[test]
fn tls_files_that_are_not_pem_refuse_to_start_and_are_not_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let sentinel = "SENTINEL-NOT-A-KEY-9f3a";
    std::fs::write(dir.path().join("c.pem"), sentinel).unwrap();
    // 0600 so the refusal comes from the content check, not the permission check.
    write_key(&dir.path().join("k.pem"), sentinel, 0o600);
    let output = refuses(
        &[
            ("PROPOLIS_HTTP_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_HTTP_TLS_CERT", &p(dir.path(), "c.pem")),
            ("PROPOLIS_HTTP_TLS_KEY", &p(dir.path(), "k.pem")),
        ],
        dir.path(),
    );
    assert!(!output.contains(sentinel), "file content echoed: {output}");
}

#[test]
fn a_group_readable_valid_key_refuses_to_start_before_any_listener_binds() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = ephemeral();
    std::fs::write(dir.path().join("c.pem"), &cert).unwrap();
    write_key(&dir.path().join("k.pem"), &key, 0o640);
    let output = refuses(
        &[
            ("PROPOLIS_HTTP_TLS_BIND", "127.0.0.1:0"),
            ("PROPOLIS_HTTP_TLS_CERT", &p(dir.path(), "c.pem")),
            ("PROPOLIS_HTTP_TLS_KEY", &p(dir.path(), "k.pem")),
        ],
        dir.path(),
    );
    // The plaintext listener must not have come up first.
    assert!(!output.contains("listening"), "output: {output}");
}

#[test]
fn no_tls_vars_keeps_the_plain_sensor_running() {
    let dir = tempfile::tempdir().unwrap();
    let envs = base_env(dir.path());
    let refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut p = Proc::spawn(&refs);
    assert!(p.wait_for_output("listening", Duration::from_secs(10)));
    assert_eq!(p.exit_code_within(Duration::from_millis(500)), None);
    assert!(!p.output().contains("(tls)"));
}

#[test]
fn a_valid_pair_without_a_tls_bind_starts_no_tls_listener_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, _) = ephemeral();
    std::fs::write(dir.path().join("c.pem"), &cert).unwrap();
    write_key(&dir.path().join("k.pem"), &key, 0o600);
    let mut envs = base_env(dir.path());
    envs.push(("PROPOLIS_HTTP_TLS_CERT".into(), p(dir.path(), "c.pem")));
    envs.push(("PROPOLIS_HTTP_TLS_KEY".into(), p(dir.path(), "k.pem")));
    let refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut proc = Proc::spawn(&refs);
    assert!(
        proc.wait_for_output("no TLS listener started", Duration::from_secs(10)),
        "output: {}",
        proc.output()
    );
    assert!(proc.wait_for_output("listening", Duration::from_secs(10)));
    assert_eq!(proc.exit_code_within(Duration::from_millis(500)), None);
    assert!(!proc.output().contains("(tls)"), "{}", proc.output());
}

#[test]
fn unusable_cert_and_key_without_a_tls_bind_still_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[
            ("PROPOLIS_HTTP_TLS_CERT", &p(dir.path(), "nope.crt")),
            ("PROPOLIS_HTTP_TLS_KEY", &p(dir.path(), "nope.key")),
        ],
        dir.path(),
    );
}

#[tokio::test]
async fn a_valid_private_pair_brings_up_the_tls_listener_in_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key, der) = ephemeral();
    std::fs::write(dir.path().join("c.pem"), &cert).unwrap();
    write_key(&dir.path().join("k.pem"), &key, 0o600);
    let mut envs = base_env(dir.path());
    envs.push(("PROPOLIS_HTTP_TLS_BIND".into(), "127.0.0.1:0".into()));
    envs.push(("PROPOLIS_HTTP_TLS_CERT".into(), p(dir.path(), "c.pem")));
    envs.push(("PROPOLIS_HTTP_TLS_KEY".into(), p(dir.path(), "k.pem")));
    let refs: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let proc = Proc::spawn(&refs);
    assert!(
        proc.wait_for_output("listening (tls)", Duration::from_secs(10)),
        "output: {}",
        proc.output()
    );
    let output = proc.output();
    let line = output
        .lines()
        .find(|l| l.contains("listening (tls)"))
        .unwrap();
    let rest = &line[line.find("127.0.0.1:").expect("bound address in log line")..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ':'))
        .unwrap_or(rest.len());
    let addr: SocketAddr = rest[..end].parse().unwrap();

    let connector = client_for(der);
    let mut conn = tls_connect(addr, &connector).await;
    conn.write_all(GET_ROOT.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 200 OK"));
}
