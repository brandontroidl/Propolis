//! Fail-closed TLS configuration, driven through the real binary: a bad TLS setup must exit 1
//! before any listener (plaintext included) is bound.

use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn sensor(dir: &std::path::Path, extra: &[(&str, &str)]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sensor-ftp"));
    cmd.env_clear()
        .env("PROPOLIS_FTP_BIND", "127.0.0.1:0")
        .env("PROPOLIS_FTP_LOG_PATH", dir.join("events.jsonl"))
        .env("PROPOLIS_FTP_SPOOL_DIR", dir.join("spool"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.spawn().unwrap()
}

fn exit_within(child: &mut Child, wait: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

fn assert_refuses_to_start(extra: &[(&str, &str)]) {
    let dir = tempfile::tempdir().unwrap();
    let mut child = sensor(dir.path(), extra);
    let status = exit_within(&mut child, Duration::from_secs(10))
        .unwrap_or_else(|| panic!("sensor kept running with {extra:?}"));
    assert_eq!(status.code(), Some(1), "{extra:?}");
}

#[test]
fn exactly_one_of_cert_and_key_exits_1() {
    assert_refuses_to_start(&[("PROPOLIS_FTP_TLS_CERT", "/nonexistent/c.crt")]);
    assert_refuses_to_start(&[("PROPOLIS_FTP_TLS_KEY", "/nonexistent/k.key")]);
}

#[test]
fn tls_bind_without_cert_and_key_exits_1() {
    assert_refuses_to_start(&[("PROPOLIS_FTP_TLS_BIND", "127.0.0.1:0")]);
}

#[test]
fn unreadable_cert_and_key_exit_1() {
    assert_refuses_to_start(&[
        ("PROPOLIS_FTP_TLS_CERT", "/nonexistent/c.crt"),
        ("PROPOLIS_FTP_TLS_KEY", "/nonexistent/k.key"),
    ]);
}

#[test]
fn invalid_tls_bind_exits_1() {
    assert_refuses_to_start(&[("PROPOLIS_FTP_TLS_BIND", "not-an-address")]);
}

#[test]
fn no_tls_configuration_keeps_running_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = sensor(dir.path(), &[]);
    assert!(
        exit_within(&mut child, Duration::from_secs(1)).is_none(),
        "a plain config must start and keep running"
    );
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// A valid cert and key with no `PROPOLIS_FTP_TLS_BIND` is meaningful for FTP: it enables AUTH TLS
/// on the plain listener, so the process runs, AUTH TLS completes a handshake on the plain port,
/// and no implicit-TLS listener starts. Key material is written at runtime into a tempdir, key
/// mode 0600.
#[tokio::test]
async fn a_valid_pair_without_a_tls_bind_enables_auth_tls_on_the_plain_listener_only() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    let dir = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let (cert_path, key_path) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let port = free_port();

    let mut child = Command::new(env!("CARGO_BIN_EXE_sensor-ftp"))
        .env_clear()
        // A workspace build unifies tracing-subscriber's `env-filter` feature on, which makes an
        // unset RUST_LOG mean errors only; the info line asserted below needs info.
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env("PROPOLIS_FTP_BIND", format!("127.0.0.1:{port}"))
        .env("PROPOLIS_FTP_LOG_PATH", dir.path().join("events.jsonl"))
        .env("PROPOLIS_FTP_SPOOL_DIR", dir.path().join("spool"))
        .env("PROPOLIS_FTP_TLS_CERT", &cert_path)
        .env("PROPOLIS_FTP_TLS_KEY", &key_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            stream = Some(s);
            break;
        }
        assert!(child.try_wait().unwrap().is_none(), "sensor exited early");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut reader = BufReader::new(stream.expect("plain listener never came up"));

    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("220"), "{line}");
    reader.get_mut().write_all(b"AUTH TLS\r\n").await.unwrap();
    line.clear();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line, "234 Proceed with negotiation.\r\n");

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert.der().to_vec()))
        .unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tls = connector
        .connect(
            ServerName::try_from("localhost").unwrap(),
            reader.into_inner(),
        )
        .await
        .expect("AUTH TLS handshake on the plain port");
    let mut tls = BufReader::new(tls);
    tls.get_mut().write_all(b"PBSZ 0\r\n").await.unwrap();
    line.clear();
    tls.read_line(&mut line).await.unwrap();
    assert_eq!(line, "200 PBSZ set to 0.\r\n");
    drop(tls);

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
        output.matches("sensor-ftp: listening").count(),
        1,
        "output: {output}"
    );
}
