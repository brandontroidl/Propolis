//! TLS behaviour of the SMTP sensor: SMTPS (implicit), STARTTLS, and the fail-closed startup rules.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, TlsServer, WanResolver, server_config_from_pem};
use sensor_smtp::ListenerKind;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, pki_types::ServerName};

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

/// A fresh in-memory self-signed pair: the server side plus a client that trusts exactly it.
fn ephemeral() -> (TlsServer, TlsConnector) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let server = TlsServer::from_config(
        server_config_from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap(),
    );
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (server, TlsConnector::from(Arc::new(config)))
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

struct TestServer {
    /// Plain listener with STARTTLS enabled.
    plain: SocketAddr,
    /// Implicit-TLS listener.
    implicit: SocketAddr,
    connector: TlsConnector,
    log_path: PathBuf,
    handles: Vec<JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        let (server, connector) = ephemeral();
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let started = sensor_smtp::start_listeners(
            vec![
                (
                    any,
                    ListenerKind::Plain {
                        tls: Some(server.clone()),
                    },
                ),
                (any, ListenerKind::Implicit { tls: server }),
            ],
            log_path.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            test_bounds(),
        )
        .await
        .unwrap();
        TestServer {
            plain: started[0].0,
            implicit: started[1].0,
            connector,
            log_path,
            handles: started.into_iter().map(|(_, h)| h).collect(),
            _dir: dir,
        }
    }

    async fn events(&self) -> Vec<sensor_wire::SensorEvent> {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let content = tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }

    fn stop(self) {
        for h in self.handles {
            h.abort();
        }
    }
}

struct SmtpClient<S> {
    reader: BufReader<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> SmtpClient<S> {
    async fn read_reply(&mut self) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(3), self.reader.read_line(&mut line))
            .await
            .expect("timeout")
            .expect("read error");
        line
    }

    async fn read_multiline_reply(&mut self) -> String {
        let mut result = String::new();
        loop {
            let line = self.read_reply().await;
            let done = line.len() >= 4 && line.as_bytes()[3] == b' ';
            result.push_str(&line);
            if done || line.is_empty() {
                break;
            }
        }
        result
    }

    async fn write_raw(&mut self, bytes: &[u8]) {
        let inner = self.reader.get_mut();
        inner.write_all(bytes).await.unwrap();
        inner.flush().await.unwrap();
    }

    async fn send(&mut self, cmd: &str) -> String {
        self.write_raw(format!("{cmd}\r\n").as_bytes()).await;
        self.read_reply().await
    }

    async fn send_multiline(&mut self, cmd: &str) -> String {
        self.write_raw(format!("{cmd}\r\n").as_bytes()).await;
        self.read_multiline_reply().await
    }

    /// True when the peer ends the connection. Bytes before the close (a TLS alert after a bad
    /// handshake) are drained; the connection must still end within the deadline.
    async fn closes(&mut self) -> bool {
        let mut buf = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match self.reader.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await
        .is_ok()
    }

    /// Sends one message through MAIL/RCPT/DATA and returns the final reply.
    async fn deliver(&mut self, rcpt: &str) -> String {
        let r = self.send(&format!("RCPT TO:<{rcpt}>")).await;
        assert!(r.starts_with("250"), "RCPT: {r}");
        let r = self.send("DATA").await;
        assert!(r.starts_with("354"), "DATA: {r}");
        self.write_raw(b"Subject: s\r\n\r\nbody\r\n.\r\n").await;
        self.read_reply().await
    }
}

impl SmtpClient<TcpStream> {
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut client = SmtpClient {
            reader: BufReader::new(stream),
        };
        let banner = client.read_reply().await;
        assert!(banner.starts_with("220"), "banner: {banner}");
        client
    }

    async fn into_tls(self, connector: &TlsConnector) -> SmtpClient<TlsStream<TcpStream>> {
        // The server sends nothing between its 220 and our ClientHello, so nothing is buffered.
        assert!(self.reader.buffer().is_empty());
        let tls = connector
            .connect(server_name(), self.reader.into_inner())
            .await
            .expect("client handshake");
        SmtpClient {
            reader: BufReader::new(tls),
        }
    }

    async fn connect_implicit(
        addr: SocketAddr,
        connector: &TlsConnector,
    ) -> SmtpClient<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = connector
            .connect(server_name(), tcp)
            .await
            .expect("client handshake");
        let mut client = SmtpClient {
            reader: BufReader::new(tls),
        };
        let banner = client.read_reply().await;
        assert!(banner.starts_with("220"), "banner: {banner}");
        client
    }
}

fn meta_str<'a>(e: &'a sensor_wire::SensorEvent, key: &str) -> Option<&'a str> {
    e.metadata.get(key).and_then(|v| v.as_str())
}

fn is_data_event(e: &sensor_wire::SensorEvent) -> bool {
    meta_str(e, "command") == Some("DATA")
}

#[tokio::test]
async fn implicit_tls_serves_the_banner_and_tags_every_event() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect_implicit(srv.implicit, &srv.connector).await;
    let ehlo = client.send_multiline("EHLO probe").await;
    assert!(ehlo.contains("250-AUTH PLAIN LOGIN"), "{ehlo}");
    // Postfix never offers STARTTLS inside TLS.
    assert!(!ehlo.contains("STARTTLS"), "{ehlo}");
    let r = client.send("AUTH PLAIN AGFkbWluAHNlY3JldA==").await;
    assert!(r.starts_with("235"), "{r}");
    let r = client.send("QUIT").await;
    assert!(r.starts_with("221"), "{r}");
    assert!(
        client.closes().await,
        "QUIT must end the TLS session cleanly"
    );

    let events = srv.events().await;
    assert!(events.len() >= 2);
    for e in &events {
        assert_eq!(
            e.metadata.get("tls"),
            Some(&serde_json::json!(true)),
            "{e:?}"
        );
    }
    let login = events.iter().find(|e| e.authenticated).unwrap();
    assert_eq!(meta_str(login, "username"), Some("admin"));
    assert!(login.metadata.get("password").is_none());
    srv.stop();
}

#[tokio::test]
async fn implicit_banner_impersonates_postfix() {
    let srv = TestServer::start().await;
    let tcp = TcpStream::connect(srv.implicit).await.unwrap();
    let tls = srv
        .connector
        .connect(server_name(), tcp)
        .await
        .expect("client handshake");
    let mut reader = BufReader::new(tls);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();
    assert!(banner.starts_with("220 "), "{banner}");
    assert!(banner.contains("ESMTP Postfix (Ubuntu)"), "{banner}");
    srv.stop();
}

#[tokio::test]
async fn plain_listener_events_carry_no_tls_tag() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.plain).await;
    let r = client.send("AUTH PLAIN AGFkbWluAHNlY3JldA==").await;
    assert!(r.starts_with("235"), "{r}");
    let events = srv.events().await;
    assert!(!events.is_empty());
    for e in &events {
        assert!(e.metadata.get("tls").is_none(), "{e:?}");
    }
    srv.stop();
}

#[tokio::test]
async fn starttls_upgrades_then_forces_a_fresh_ehlo_and_tags_later_events() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.plain).await;
    let ehlo = client.send_multiline("EHLO test.local").await;
    assert!(ehlo.contains("250-STARTTLS"), "{ehlo}");
    let r = client.send("MAIL FROM:<pre@x.test>").await;
    assert!(r.starts_with("250"), "{r}");
    assert_eq!(
        client.send("STARTTLS").await,
        "220 2.0.0 Ready to start TLS\r\n"
    );

    let mut client = client.into_tls(&srv.connector).await;
    let ehlo = client.send_multiline("EHLO again").await;
    assert!(!ehlo.contains("STARTTLS"), "{ehlo}");
    assert!(ehlo.contains("250-AUTH PLAIN LOGIN"), "{ehlo}");
    let r = client.deliver("c@d.test").await;
    assert!(r.starts_with("250 2.0.0 Ok: queued as"), "{r}");

    let events = srv.events().await;
    // The connection event predates the upgrade.
    assert!(events[0].metadata.get("tls").is_none());
    let data = events.iter().find(|e| is_data_event(e)).unwrap();
    // The MAIL FROM given before the upgrade was discarded (RFC 3207 section 4.2).
    assert_eq!(meta_str(data, "mail_from"), Some(""));
    assert_eq!(data.metadata["rcpt_to"], serde_json::json!(["c@d.test"]));
    assert_eq!(data.metadata.get("tls"), Some(&serde_json::json!(true)));
    srv.stop();
}

#[tokio::test]
async fn pipelined_plaintext_after_starttls_is_refused_and_recorded() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.plain).await;
    let injected = b"MAIL FROM:<evil@x.test>\r\n";
    let mut burst = b"STARTTLS\r\n".to_vec();
    burst.extend_from_slice(injected);
    // One 35-byte write is one loopback segment, so the server's single read returns both lines
    // and the injected one is already buffered behind STARTTLS. Two writes would race the
    // server's read and could take the legitimate 220 path.
    client.write_raw(&burst).await;

    let reply = client.read_reply().await;
    assert_eq!(
        reply,
        "554 5.5.1 Error: command pipelining after STARTTLS\r\n"
    );
    assert!(
        client.closes().await,
        "the connection must close after the refusal"
    );

    let events = srv.events().await;
    let refused = events
        .iter()
        .find(|e| meta_str(e, "starttls_refused").is_some())
        .expect("refusal event");
    assert_eq!(
        refused.signal_type,
        sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC
    );
    assert_eq!(meta_str(refused, "command"), Some("STARTTLS"));
    assert_eq!(
        meta_str(refused, "starttls_refused"),
        Some("pipelined_plaintext")
    );
    assert_eq!(refused.metadata["pipelined_bytes"], injected.len());
    assert!(refused.sample.is_none());
    // The injected MAIL FROM was never interpreted as a command.
    assert!(!events.iter().any(is_data_event));
    srv.stop();
}

#[tokio::test]
async fn second_starttls_inside_tls_is_refused_and_ehlo_hides_it() {
    let srv = TestServer::start().await;

    let mut client = SmtpClient::connect(srv.plain).await;
    assert_eq!(
        client.send("STARTTLS").await,
        "220 2.0.0 Ready to start TLS\r\n"
    );
    let mut upgraded = client.into_tls(&srv.connector).await;
    let r = upgraded.send("STARTTLS").await;
    assert!(r.starts_with("503 "), "{r}");
    // The session is still usable.
    assert!(upgraded.send("NOOP").await.starts_with("250"));

    let mut implicit = SmtpClient::connect_implicit(srv.implicit, &srv.connector).await;
    let r = implicit.send("STARTTLS").await;
    assert!(r.starts_with("503 "), "{r}");
    srv.stop();
}

#[tokio::test]
async fn starttls_with_parameters_is_a_syntax_error_when_tls_is_configured() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.plain).await;
    let r = client.send("STARTTLS now").await;
    assert!(r.starts_with("501 5.5.4"), "{r}");
    assert!(client.send("NOOP").await.starts_with("250"));
    srv.stop();
}

#[tokio::test]
async fn implicit_handshake_failure_is_silent_and_the_listener_survives() {
    let srv = TestServer::start().await;
    let mut tcp = TcpStream::connect(srv.implicit).await.unwrap();
    tcp.write_all(&[0x41u8; 2048]).await.unwrap();
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(Duration::from_secs(3), async {
        // A TLS alert may precede the close; no SMTP banner ever may.
        loop {
            match tcp.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => assert!(
                    !buf[..n].starts_with(b"220"),
                    "banner served without a handshake"
                ),
            }
        }
    })
    .await;
    assert!(read.is_ok(), "connection was not closed");
    assert!(
        srv.events().await.is_empty(),
        "a failed handshake must emit no event"
    );

    let mut client = SmtpClient::connect_implicit(srv.implicit, &srv.connector).await;
    assert!(client.send_multiline("EHLO x").await.contains("250"));
    srv.stop();
}

#[tokio::test]
async fn starttls_handshake_failure_ends_the_session() {
    let srv = TestServer::start().await;
    let mut client = SmtpClient::connect(srv.plain).await;
    assert_eq!(
        client.send("STARTTLS").await,
        "220 2.0.0 Ready to start TLS\r\n"
    );
    client.write_raw(&[0x41u8; 2048]).await;
    assert!(client.closes().await);

    let mut fresh = SmtpClient::connect(srv.plain).await;
    assert!(fresh.send_multiline("EHLO x").await.contains("250"));
    srv.stop();
}

#[tokio::test]
async fn starttls_without_tls_configured_keeps_the_454_reply() {
    let dir = tempfile::tempdir().unwrap();
    let wan = Arc::new(WanResolver::new(HashMap::new()));
    let (addr, handle) = sensor_smtp::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        wan,
        test_bounds(),
    )
    .await
    .unwrap();
    let mut client = SmtpClient::connect(addr).await;
    let ehlo = client.send_multiline("EHLO x").await;
    assert!(ehlo.contains("250-STARTTLS"), "{ehlo}");
    let r = client.send("STARTTLS").await;
    assert!(r.starts_with("454 4.7.0 TLS not available"), "{r}");
    let r = client.send("STARTTLS now").await;
    assert!(r.starts_with("454 4.7.0 TLS not available"), "{r}");
    assert!(client.send("NOOP").await.starts_with("250"));
    handle.abort();
}

/// Runs the real binary with a cleared environment plus `env`, returning its exit code, and
/// asserts that the plaintext port was never served. `None` means it was still running at the
/// deadline (killed).
async fn run_binary(env: &[(&str, &str)], plain_port: u16) -> Option<i32> {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_sensor-smtp"));
    cmd.env_clear()
        .env("PROPOLIS_SMTP_BIND", format!("127.0.0.1:{plain_port}"))
        .env("PROPOLIS_SMTP_LOG_PATH", dir.path().join("events.jsonl"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    for _ in 0..100 {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                TcpStream::connect(("127.0.0.1", plain_port)).await.is_err(),
                "a plaintext listener was left serving"
            );
            return status.code();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn invalid_tls_configuration_exits_1_before_binding_anything() {
    let dir = tempfile::tempdir().unwrap();
    let missing_cert = dir.path().join("none.crt");
    let missing_key = dir.path().join("none.key");
    let (mc, mk) = (
        missing_cert.to_str().unwrap(),
        missing_key.to_str().unwrap(),
    );
    // Garbage in both files, key at 0600 so the failure is the content, not the mode.
    let junk_cert = dir.path().join("junk.crt");
    let junk_key = dir.path().join("junk.key");
    std::fs::write(&junk_cert, b"not a certificate").unwrap();
    std::fs::write(&junk_key, b"not a key").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&junk_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (jc, jk) = (junk_cert.to_str().unwrap(), junk_key.to_str().unwrap());

    let cases: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("cert only", vec![("PROPOLIS_SMTP_TLS_CERT", mc)]),
        ("key only", vec![("PROPOLIS_SMTP_TLS_KEY", mk)]),
        (
            "tls bind without cert and key",
            vec![("PROPOLIS_SMTP_TLS_BIND", "127.0.0.1:0")],
        ),
        (
            "tls bind with cert only",
            vec![
                ("PROPOLIS_SMTP_TLS_BIND", "127.0.0.1:0"),
                ("PROPOLIS_SMTP_TLS_CERT", mc),
            ],
        ),
        (
            "unreadable pair",
            vec![
                ("PROPOLIS_SMTP_TLS_CERT", mc),
                ("PROPOLIS_SMTP_TLS_KEY", mk),
            ],
        ),
        (
            "unparseable pair",
            vec![
                ("PROPOLIS_SMTP_TLS_CERT", jc),
                ("PROPOLIS_SMTP_TLS_KEY", jk),
            ],
        ),
        (
            "unparseable pair with tls bind",
            vec![
                ("PROPOLIS_SMTP_TLS_BIND", "127.0.0.1:0"),
                ("PROPOLIS_SMTP_TLS_CERT", jc),
                ("PROPOLIS_SMTP_TLS_KEY", jk),
            ],
        ),
        (
            "malformed submission bind",
            vec![("PROPOLIS_SMTP_SUBMISSION_BIND", "not-an-address")],
        ),
    ];
    for (name, env) in cases {
        let code = run_binary(&env, free_port()).await;
        assert_eq!(code, Some(1), "{name}");
    }
}

#[tokio::test]
async fn a_bind_failure_on_any_listener_exits_1_and_leaves_nothing_serving() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let taken_addr = taken.local_addr().unwrap().to_string();
    let code = run_binary(
        &[("PROPOLIS_SMTP_SUBMISSION_BIND", taken_addr.as_str())],
        free_port(),
    )
    .await;
    assert_eq!(code, Some(1));
    drop(taken);
}

/// Cert and key with no TLS bind and no submission bind: the one plain listener runs, no
/// implicit-TLS listener exists, and STARTTLS is live on it. Key material is written at runtime
/// into a tempdir, key mode 0600.
#[tokio::test]
async fn a_valid_pair_without_a_tls_bind_enables_starttls_on_the_plain_listener_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let port = free_port();

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_sensor-smtp"))
        .env_clear()
        // A workspace build unifies tracing-subscriber's `env-filter` feature on, which makes an
        // unset RUST_LOG mean errors only; the info line asserted below needs info.
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("PROPOLIS_SMTP_BIND", format!("127.0.0.1:{port}"))
        .env("PROPOLIS_SMTP_LOG_PATH", dir.path().join("events.jsonl"))
        .env("PROPOLIS_SMTP_TLS_CERT", &cert_path)
        .env("PROPOLIS_SMTP_TLS_KEY", &key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)).await {
            stream = Some(s);
            break;
        }
        assert!(child.try_wait().unwrap().is_none(), "sensor exited early");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stream = stream.expect("plain listener never came up");

    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let mut client = SmtpClient {
        reader: BufReader::new(stream),
    };
    assert!(client.read_reply().await.starts_with("220"));
    assert!(
        client
            .send_multiline("EHLO x")
            .await
            .contains("250-STARTTLS")
    );
    assert_eq!(
        client.send("STARTTLS").await,
        "220 2.0.0 Ready to start TLS\r\n"
    );
    let mut upgraded = client.into_tls(&connector).await;
    let ehlo = upgraded.send_multiline("EHLO x").await;
    assert!(ehlo.starts_with("250-"), "{ehlo}");
    assert!(!ehlo.contains("STARTTLS"), "{ehlo}");
    drop(upgraded);

    let _ = child.kill();
    let _ = child.wait();
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut s, &mut err);
    }
    let output = format!("{out}{err}");
    // Exactly one listener: the plain one. An implicit-TLS listener would log a second line.
    assert_eq!(
        output.matches("sensor-smtp: listening").count(),
        1,
        "output: {output}"
    );
}
