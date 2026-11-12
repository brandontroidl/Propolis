//! MQTTS (implicit TLS) end to end: the same sessions as the plaintext listener, over TLS, with
//! every event tagged `"tls": true`; plaintext to the TLS port is dropped; a bad TLS
//! configuration refuses to start. All key material is an in-memory rcgen ephemeral.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{
    CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M, TlsServer,
    WanResolver,
};
use sensor_wire::{
    SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SIGNAL_HONEYPOT_SESSION_END, SensorEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsConnector, client::TlsStream};

fn bounds(read_timeout: Duration) -> ConnectionBounds {
    ConnectionBounds {
        read_timeout,
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

/// Ephemeral self-signed cert for "localhost"; the key exists only in this process's memory.
fn test_tls() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

struct TlsServerFixture {
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    handle: JoinHandle<()>,
    handoff: Arc<sensor_framework::CaptureHandoff>,
    client_config: Arc<ClientConfig>,
    _dir: tempfile::TempDir,
}

impl TlsServerFixture {
    async fn start() -> Self {
        Self::start_with(bounds(Duration::from_secs(5))).await
    }

    async fn start_with(bounds: ConnectionBounds) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let (server, client_config) = test_tls();
        let (addr, handle, handoff) = sensor_mqtt::start_test_server_tls_with_handoff(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds,
            "test".to_string(),
            dir.path().join("outbox"),
            Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
            TlsServer::from_config(server),
        )
        .await
        .unwrap();
        Self {
            addr,
            log_path,
            spool_dir,
            handle,
            handoff,
            client_config,
            _dir: dir,
        }
    }

    async fn connect(&self) -> TlsStream<TcpStream> {
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        TlsConnector::from(self.client_config.clone())
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap()
    }

    async fn events(&self) -> Vec<SensorEvent> {
        tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }

    /// Poll until `want` events match `pred` (the session-end event lands after the client has
    /// already seen its last reply, and spooled uploads land off the connection's path).
    async fn wait_for(&self, want: usize, pred: impl Fn(&SensorEvent) -> bool) -> Vec<SensorEvent> {
        for _ in 0..300 {
            let hits: Vec<SensorEvent> = self.events().await.into_iter().filter(&pred).collect();
            if hits.len() >= want {
                return hits;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {want} matching events");
    }
}

fn lenp(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    assert!(body.len() < 128, "test packets use a one-byte length");
    let mut p = vec![first, body.len() as u8];
    p.extend_from_slice(body);
    p
}

/// A long packet: remaining length as a proper varint.
fn long_packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![first];
    let mut v = body.len();
    loop {
        let mut b = (v % 128) as u8;
        v /= 128;
        if v > 0 {
            b |= 0x80;
        }
        p.push(b);
        if v == 0 {
            break;
        }
    }
    p.extend_from_slice(body);
    p
}

fn connect_311() -> Vec<u8> {
    let mut b = lenp(b"MQTT");
    b.extend_from_slice(&[4, 0xC2]);
    b.extend_from_slice(&30u16.to_be_bytes());
    b.extend(lenp(b"scanner-01"));
    b.extend(lenp(b"admin"));
    b.extend(lenp(b"hunter2-secret"));
    packet(0x10, &b)
}

fn connect_v5() -> Vec<u8> {
    let mut b = lenp(b"MQTT");
    b.extend_from_slice(&[5, 0xC2]);
    b.extend_from_slice(&30u16.to_be_bytes());
    b.push(0); // empty properties block
    b.extend(lenp(b"v5-scanner"));
    b.extend(lenp(b"root"));
    b.extend(lenp(b"toor-secret"));
    packet(0x10, &b)
}

async fn read_n<S: tokio::io::AsyncRead + Unpin>(stream: &mut S, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut buf))
        .await
        .expect("timeout")
        .expect("read error");
    buf
}

fn signal(name: &'static str) -> impl Fn(&SensorEvent) -> bool {
    move |e| e.signal_type == name
}

fn command(name: &'static str) -> impl Fn(&SensorEvent) -> bool {
    move |e| {
        e.signal_type == SIGNAL_HONEYPOT_COMMAND_EXEC
            && e.metadata.get("command").and_then(|v| v.as_str()) == Some(name)
    }
}

fn is_tls(e: &SensorEvent) -> bool {
    e.metadata.get("tls").and_then(|v| v.as_bool()) == Some(true)
}

fn assert_all_tagged(events: &[SensorEvent]) {
    assert!(!events.is_empty());
    for e in events {
        assert!(is_tls(e), "event not tagged tls: {e:?}");
        assert_eq!(e.sensor, "mqtt");
    }
}

/// The TLS listener is a separate tracked-listener call from the plaintext one: an open MQTTS
/// connection must be registered so a shutdown `drain` can cut it.
#[tokio::test]
async fn an_open_mqtts_connection_is_tracked_and_cut_by_drain() {
    let srv = TlsServerFixture::start().await;
    let _raw = TcpStream::connect(srv.addr).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while srv.handoff.connections().live() != 1 {
        assert!(std::time::Instant::now() < deadline, "connection untracked");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    srv.handle.abort();
    let report = srv.handoff.drain(Duration::from_secs(2)).await;
    assert_eq!(
        report.connections,
        sensor_framework::QuiesceOutcome::Cancelled(1)
    );
}

#[tokio::test]
async fn mqtt_311_session_over_tls_answers_and_tags_every_event() {
    let srv = TlsServerFixture::start().await;
    let mut c = srv.connect().await;

    c.write_all(&connect_311()).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x20, 0x02, 0x00, 0x00]);

    let mut sub = vec![0x00, 0x01];
    sub.extend(lenp(b"$SYS/#"));
    sub.push(0x01);
    c.write_all(&packet(0x82, &sub)).await.unwrap();
    assert_eq!(read_n(&mut c, 5).await, vec![0x90, 0x03, 0x00, 0x01, 0x01]);

    let mut publish = lenp(b"cmd/exec");
    publish.extend_from_slice(&[0xAB, 0xCD]);
    publish.extend_from_slice(b"hello");
    c.write_all(&packet(0x32, &publish)).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x40, 0x02, 0xAB, 0xCD]);

    c.write_all(&packet(0xE0, &[])).await.unwrap();
    // A clean close_notify, not a truncation.
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut rest))
        .await
        .expect("server held the connection open")
        .expect("unclean TLS close: close_notify was not sent");
    assert!(rest.is_empty());

    srv.wait_for(1, signal(SIGNAL_HONEYPOT_SESSION_END)).await;
    let events = srv.events().await;
    assert_all_tagged(&events);

    let login = srv.wait_for(1, signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT)).await;
    assert_eq!(login[0].metadata["username"], "admin");
    assert_eq!(login[0].metadata["client_id"], "scanner-01");
    let sub = srv.wait_for(1, command("SUBSCRIBE")).await;
    assert_eq!(sub[0].metadata["topics"][0], "$SYS/#");
    let publish = srv.wait_for(1, command("PUBLISH")).await;
    assert_eq!(publish[0].metadata["topic"], "cmd/exec");
    assert_eq!(publish[0].metadata["payload_preview"], "hello");
    let raw = tokio::fs::read_to_string(&srv.log_path).await.unwrap();
    assert!(!raw.contains("hunter2"), "password leaked over TLS: {raw}");
    srv.handle.abort();
}

#[tokio::test]
async fn mqtt_5_session_over_tls_answers_and_tags_every_event() {
    let srv = TlsServerFixture::start().await;
    let mut c = srv.connect().await;

    c.write_all(&connect_v5()).await.unwrap();
    assert_eq!(read_n(&mut c, 5).await, vec![0x20, 0x03, 0x00, 0x00, 0x00]);

    // SUBSCRIBE with an empty properties block.
    let mut sub = vec![0x00, 0x10, 0x00];
    sub.extend(lenp(b"home/+/temp"));
    sub.push(0x02);
    c.write_all(&packet(0x82, &sub)).await.unwrap();
    assert_eq!(
        read_n(&mut c, 6).await,
        vec![0x90, 0x04, 0x00, 0x10, 0x00, 0x01] // qos 2 lowered to 1
    );

    let mut publish = lenp(b"cmd/exec");
    publish.extend_from_slice(&[0x12, 0x34]);
    publish.push(0x00); // empty properties block
    publish.extend_from_slice(b"hello");
    c.write_all(&packet(0x32, &publish)).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x40, 0x02, 0x12, 0x34]);

    c.write_all(&packet(0xC0, &[])).await.unwrap();
    assert_eq!(read_n(&mut c, 2).await, vec![0xD0, 0x00]);
    c.write_all(&packet(0xE0, &[])).await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut rest)).await;

    srv.wait_for(1, signal(SIGNAL_HONEYPOT_SESSION_END)).await;
    assert_all_tagged(&srv.events().await);
    let login = srv.wait_for(1, signal(SIGNAL_HONEYPOT_LOGIN_ATTEMPT)).await;
    assert_eq!(login[0].metadata["protocol_level"], 5);
    assert_eq!(login[0].metadata["username"], "root");
    let publish = srv.wait_for(1, command("PUBLISH")).await;
    assert_eq!(publish[0].metadata["payload_preview"], "hello");
    let raw = tokio::fs::read_to_string(&srv.log_path).await.unwrap();
    assert!(!raw.contains("toor-secret"), "password leaked over TLS");
    srv.handle.abort();
}

fn elf_like(len: usize) -> Vec<u8> {
    let mut b = b"\x7fELF\x02\x01\x01\x00".to_vec();
    b.extend((0..len - b.len()).map(|i| (i % 251) as u8 | 0x80));
    b
}

#[tokio::test]
async fn binary_publish_over_tls_is_spooled_and_the_upload_event_is_tagged() {
    let srv = TlsServerFixture::start().await;
    let mut c = srv.connect().await;
    c.write_all(&connect_311()).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x20, 0x02, 0x00, 0x00]);

    let payload = elf_like(4096);
    let mut b = lenp(b"fw/update");
    b.extend_from_slice(&[0x12, 0x34]);
    b.extend_from_slice(&payload);
    c.write_all(&long_packet(0x32, &b)).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x40, 0x02, 0x12, 0x34]);

    let uploads = srv
        .wait_for(1, signal(SIGNAL_HONEYPOT_MALWARE_UPLOAD))
        .await;
    let up = &uploads[0];
    assert!(is_tls(up), "upload event not tagged tls: {up:?}");
    let sample = up.sample.as_ref().expect("a spooled PUBLISH has a sample");
    assert_eq!(sample.size, payload.len() as u64);
    let on_disk = tokio::fs::read(srv.spool_dir.join(&sample.sha256))
        .await
        .unwrap();
    assert_eq!(on_disk, payload, "the spooled file is exactly the payload");
    assert_eq!(up.metadata["capture_reason"], "binary_publish_payload");
    srv.handle.abort();
}

#[tokio::test]
async fn malformed_first_packet_over_tls_emits_a_tagged_malformed_event() {
    let srv = TlsServerFixture::start().await;
    let mut c = srv.connect().await;
    c.write_all(&packet(0xC0, &[])).await.unwrap(); // first packet is not CONNECT
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut rest)).await;
    assert!(rest.is_empty());

    let malformed = srv
        .wait_for(1, |e| {
            e.signal_type == SIGNAL_HONEYPOT_CONNECTION
                && e.metadata.get("reason").and_then(|v| v.as_str())
                    == Some("first_packet_not_connect")
        })
        .await;
    assert_eq!(malformed[0].metadata["malformed"], true);
    assert!(is_tls(&malformed[0]));
    srv.handle.abort();
}

#[tokio::test]
async fn plaintext_to_the_tls_port_is_dropped_without_events_and_the_listener_survives() {
    let srv = TlsServerFixture::start().await;
    let mut raw = TcpStream::connect(srv.addr).await.unwrap();
    raw.write_all(&connect_311()).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), raw.read_to_end(&mut got)).await;
    assert!(
        !got.starts_with(&[0x20, 0x02]),
        "plaintext got a CONNACK from the TLS port"
    );
    assert!(
        srv.events().await.is_empty(),
        "a failed handshake emits no event"
    );

    let mut c = srv.connect().await;
    c.write_all(&connect_311()).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x20, 0x02, 0x00, 0x00]);
    srv.handle.abort();
}

#[tokio::test]
async fn a_stalled_tls_handshake_is_dropped_within_the_read_timeout() {
    let srv = TlsServerFixture::start_with(bounds(Duration::from_millis(300))).await;
    let mut tcp = TcpStream::connect(srv.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let res = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut buf))
        .await
        .expect("the stalled handshake was not cut at the read timeout");
    assert!(matches!(res, Ok(0) | Err(_)));
    assert!(srv.events().await.is_empty());
    srv.handle.abort();
}

#[tokio::test]
async fn plain_listener_events_have_no_tls_key() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (addr, handle) = sensor_mqtt::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(Duration::from_secs(5)),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(&connect_311()).await.unwrap();
    assert_eq!(read_n(&mut c, 4).await, vec![0x20, 0x02, 0x00, 0x00]);
    c.write_all(&packet(0xE0, &[])).await.unwrap();
    let mut rest = Vec::new();
    let _ = c.read_to_end(&mut rest).await;
    for _ in 0..100 {
        let text = tokio::fs::read_to_string(&log_path)
            .await
            .unwrap_or_default();
        if text.contains(SIGNAL_HONEYPOT_SESSION_END) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let text = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<SensorEvent> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(
        events.len() >= 3,
        "connection, login, session end: {events:?}"
    );
    for e in &events {
        assert!(e.metadata.get("tls").is_none(), "plain event tagged: {e:?}");
    }
    handle.abort();
}

// ---------------------------------------------------------------------------------------------
// Fail-closed configuration, driven through the real binary.
// ---------------------------------------------------------------------------------------------

/// Spawn the binary with a cleared env, wait up to `wait`, kill if still running. Returns the exit
/// code if it exited, plus stdout and stderr (tracing writes to stdout).
fn run_binary(envs: &[(&str, &str)], wait: Duration) -> (Option<i32>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-mqtt"))
        .env_clear()
        // NO_COLOR keeps ANSI escapes out of the log text the tests match on. RUST_LOG is left
        // unset: the warning and info lines asserted below rely on the INFO default.
        .env("NO_COLOR", "1")
        .envs(envs.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + wait;
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status.code().unwrap_or(-1));
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut err);
    }
    (code, format!("{out}{err}"))
}

fn base_env(dir: &std::path::Path) -> Vec<(&'static str, String)> {
    vec![
        ("PROPOLIS_MQTT_BIND", "127.0.0.1:0".to_string()),
        (
            "PROPOLIS_MQTT_LOG_PATH",
            dir.join("e.jsonl").display().to_string(),
        ),
        (
            "PROPOLIS_MQTT_SPOOL_DIR",
            dir.join("spool").display().to_string(),
        ),
        (
            "PROPOLIS_MQTT_OUTBOX_DIR",
            dir.join("outbox").display().to_string(),
        ),
    ]
}

fn refuses(extra: &[(&'static str, String)], dir: &std::path::Path) -> String {
    let mut envs = base_env(dir);
    envs.extend(extra.iter().cloned());
    let borrowed: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (code, out) = run_binary(&borrowed, Duration::from_secs(10));
    assert_eq!(code, Some(1), "expected exit 1, output: {out}");
    assert!(
        out.contains("refusing to start"),
        "no refusal message: {out}"
    );
    out
}

#[test]
fn tls_bind_with_no_cert_or_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[("PROPOLIS_MQTT_TLS_BIND", "127.0.0.1:0".into())],
        dir.path(),
    );
}

#[test]
fn exactly_one_of_cert_and_key_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("c.pem").display().to_string();
    refuses(&[("PROPOLIS_MQTT_TLS_CERT", c.clone())], dir.path());
    refuses(&[("PROPOLIS_MQTT_TLS_KEY", c.clone())], dir.path());
    refuses(
        &[
            ("PROPOLIS_MQTT_TLS_BIND", "127.0.0.1:0".into()),
            ("PROPOLIS_MQTT_TLS_CERT", c),
        ],
        dir.path(),
    );
}

#[test]
fn tls_cert_and_key_files_missing_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[
            ("PROPOLIS_MQTT_TLS_BIND", "127.0.0.1:0".into()),
            (
                "PROPOLIS_MQTT_TLS_CERT",
                dir.path().join("c.pem").display().to_string(),
            ),
            (
                "PROPOLIS_MQTT_TLS_KEY",
                dir.path().join("k.pem").display().to_string(),
            ),
        ],
        dir.path(),
    );
}

#[test]
fn cert_and_key_without_a_bind_still_validate_and_refuse_when_unusable() {
    let dir = tempfile::tempdir().unwrap();
    refuses(
        &[
            (
                "PROPOLIS_MQTT_TLS_CERT",
                dir.path().join("c.pem").display().to_string(),
            ),
            (
                "PROPOLIS_MQTT_TLS_KEY",
                dir.path().join("k.pem").display().to_string(),
            ),
        ],
        dir.path(),
    );
}

#[test]
fn tls_files_that_are_not_pem_refuse_to_start_and_are_not_echoed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    for p in [&c, &k] {
        std::fs::write(p, "SENTINEL-NOT-A-KEY-9f3a").unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let out = refuses(
        &[
            ("PROPOLIS_MQTT_TLS_BIND", "127.0.0.1:0".into()),
            ("PROPOLIS_MQTT_TLS_CERT", c.display().to_string()),
            ("PROPOLIS_MQTT_TLS_KEY", k.display().to_string()),
        ],
        dir.path(),
    );
    assert!(
        !out.contains("SENTINEL-NOT-A-KEY-9f3a"),
        "file content echoed: {out}"
    );
}

#[test]
fn invalid_tls_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    refuses(&[("PROPOLIS_MQTT_TLS_BIND", "bogus".into())], dir.path());
}

/// The plain listener binds first; a TLS bind that then fails (address in use) must take the
/// whole sensor down with the uniform message, leaving nothing serving on the plain port.
#[test]
fn a_tls_bind_already_in_use_exits_1_and_leaves_the_plain_port_unserved() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_addr = taken.local_addr().unwrap().to_string();
    let plain_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let out = refuses(
        &[
            ("PROPOLIS_MQTT_BIND", format!("127.0.0.1:{plain_port}")),
            ("PROPOLIS_MQTT_TLS_BIND", taken_addr.clone()),
            ("PROPOLIS_MQTT_TLS_CERT", cert_path.display().to_string()),
            ("PROPOLIS_MQTT_TLS_KEY", key_path.display().to_string()),
        ],
        dir.path(),
    );
    assert!(
        out.contains(&format!(
            "sensor-mqtt: cannot start listener on {taken_addr}: "
        )),
        "output: {out}"
    );
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", plain_port)).is_err(),
        "the plain listener was left serving after the TLS bind failed"
    );
    drop(taken);
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
    let mut envs = base_env(dir.path());
    envs.push(("PROPOLIS_MQTT_TLS_CERT", cert_path.display().to_string()));
    envs.push(("PROPOLIS_MQTT_TLS_KEY", key_path.display().to_string()));
    let borrowed: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (code, out) = run_binary(&borrowed, Duration::from_secs(2));
    assert_eq!(code, None, "sensor must keep running, output: {out}");
    assert!(out.contains("no TLS listener started"), "output: {out}");
    assert!(out.contains("listening"), "output: {out}");
    assert!(!out.contains("(tls)"), "output: {out}");
}

#[test]
fn no_tls_vars_keeps_the_plain_sensor_running() {
    let dir = tempfile::tempdir().unwrap();
    let envs = base_env(dir.path());
    let borrowed: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (code, out) = run_binary(&borrowed, Duration::from_secs(1));
    assert_eq!(code, None, "plain sensor exited: {out}");
}

/// Blank or whitespace-only TLS vars read as unset, as `deploy/fleet-listeners.sh` reads a blank
/// bind: the plain sensor runs, no TLS listener, no refusal.
#[test]
fn blank_tls_vars_are_unset() {
    let dir = tempfile::tempdir().unwrap();
    let mut envs = base_env(dir.path());
    envs.push(("PROPOLIS_MQTT_TLS_BIND", String::new()));
    envs.push(("PROPOLIS_MQTT_TLS_CERT", "  ".into()));
    envs.push(("PROPOLIS_MQTT_TLS_KEY", "\t".into()));
    let borrowed: Vec<(&str, &str)> = envs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (code, out) = run_binary(&borrowed, Duration::from_secs(2));
    assert_eq!(code, None, "sensor must keep running, output: {out}");
    assert!(out.contains("sensor-mqtt: listening"), "output: {out}");
    assert!(!out.contains("(tls)"), "output: {out}");
}

/// A non-UTF-8 value on any TLS variable is invalid, never read as unset (which would start the
/// sensor without the TLS the operator configured): exit 1, naming the variable, before any
/// listener binds.
#[test]
fn a_non_utf8_tls_var_exits_1_before_any_listener_binds() {
    use std::os::unix::ffi::OsStrExt;
    use std::time::Instant;
    let bad = std::ffi::OsStr::from_bytes(b"/etc/propolis/tls/\xff");
    for var in [
        "PROPOLIS_MQTT_TLS_BIND",
        "PROPOLIS_MQTT_TLS_CERT",
        "PROPOLIS_MQTT_TLS_KEY",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-mqtt"))
            .env_clear()
            .env("NO_COLOR", "1")
            .env("PROPOLIS_MQTT_BIND", "127.0.0.1:0")
            .env("PROPOLIS_MQTT_LOG_PATH", dir.path().join("e.jsonl"))
            .env("PROPOLIS_MQTT_SPOOL_DIR", dir.path().join("spool"))
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
