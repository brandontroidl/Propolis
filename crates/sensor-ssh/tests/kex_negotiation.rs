//! Algorithm negotiation (RFC 4253 section 7.1) seen from the wire, the only vantage that cannot
//! share a bug with the server: a hand-rolled client that offers whatever lists a test wants, and
//! the system OpenSSH client restricted to one algorithm at a time.
//!
//! Live evidence the file answers: every PuTTY-banner and Go-banner scanner abandoned key exchange
//! with the sensor and got KEXINIT then silence, because the sensor offered one algorithm per slot
//! and, finding nothing in common with the client's lists, said nothing at all.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_ssh::transport::{
    SSH_MSG_DISCONNECT, SSH_MSG_KEXINIT, SSH_MSG_NEWKEYS, SshPacket, kex, parse_kexinit,
    read_packet_encrypted, read_packet_unencrypted, write_packet_encrypted,
    write_packet_unencrypted,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// RFC 4253 section 11.1, `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`.
const KEY_EXCHANGE_FAILED: u32 = 3;
const SSH_MSG_SERVICE_REQUEST: u8 = 5;
const SSH_MSG_SERVICE_ACCEPT: u8 = 6;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration: Duration::from_secs(120),
        max_captured_bytes: 1_000_000,
        max_concurrent: 64,
    }
}

async fn start(dir: &Path) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    sensor_ssh::serve(
        "127.0.0.1:0".parse().unwrap(),
        dir.join("events.jsonl"),
        dir.join("spool"),
        dir.join("host_key"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "OpenSSH_9.6p1".to_string(),
        "test".to_string(),
        dir.join("outbox"),
    )
    .await
    .unwrap()
}

/// The lists a test client puts in its KEXINIT.
struct Offer {
    kex: &'static str,
    host_key: &'static str,
    cipher: &'static str,
    mac: &'static str,
    compression: &'static str,
    first_kex_packet_follows: bool,
}

impl Offer {
    /// What the sensor itself speaks, so a test varies one list at a time.
    const SENSOR: Offer = Offer {
        kex: "curve25519-sha256",
        host_key: "ssh-ed25519",
        cipher: "chacha20-poly1305@openssh.com",
        mac: "hmac-sha2-256",
        compression: "none",
        first_kex_packet_follows: false,
    };

    fn payload(&self) -> Vec<u8> {
        fn list(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut out = vec![SSH_MSG_KEXINIT];
        out.extend_from_slice(&[0x5a; 16]);
        list(&mut out, self.kex);
        list(&mut out, self.host_key);
        list(&mut out, self.cipher);
        list(&mut out, self.cipher);
        list(&mut out, self.mac);
        list(&mut out, self.mac);
        list(&mut out, self.compression);
        list(&mut out, self.compression);
        list(&mut out, "");
        list(&mut out, "");
        out.push(u8::from(self.first_kex_packet_follows));
        out.extend_from_slice(&0u32.to_be_bytes());
        out
    }
}

/// Connect, exchange identification lines, read the sensor's KEXINIT and send `offer`.
/// Returns the stream, the sensor's KEXINIT payload and the client's own.
async fn handshake_to_kexinit(
    addr: SocketAddr,
    version: &str,
    offer: &Offer,
) -> (TcpStream, Vec<u8>, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut line = Vec::new();
    loop {
        let b = stream.read_u8().await.unwrap();
        line.push(b);
        if b == b'\n' {
            break;
        }
    }
    assert!(line.starts_with(b"SSH-2.0-"), "{line:?}");
    stream
        .write_all(format!("{version}\r\n").as_bytes())
        .await
        .unwrap();
    let server_kexinit = read_packet_unencrypted(&mut stream).await.unwrap().payload;
    parse_kexinit(&server_kexinit).unwrap();
    let client_kexinit = offer.payload();
    write_packet_unencrypted(&mut stream, &client_kexinit)
        .await
        .unwrap();
    (stream, server_kexinit, client_kexinit)
}

fn logged(log: &Path, signal: &str) -> Vec<sensor_wire::SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).unwrap())
        .filter(|e| e.signal_type == signal)
        .collect()
}

async fn session_end(log: &Path) -> sensor_wire::SensorEvent {
    for _ in 0..100 {
        if let Some(end) = logged(log, sensor_wire::SIGNAL_HONEYPOT_SESSION_END)
            .into_iter()
            .next()
        {
            return end;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no honeypot_session_end event was logged");
}

/// Expect the sensor to answer a hopeless offer with SSH_MSG_DISCONNECT, then close.
async fn expect_disconnect(stream: &mut TcpStream) -> SshPacket {
    let packet = tokio::time::timeout(Duration::from_secs(5), read_packet_unencrypted(stream))
        .await
        .expect("the sensor stayed silent after a KEXINIT it could not negotiate")
        .expect("the sensor closed without a DISCONNECT");
    assert_eq!(
        packet.payload[0], SSH_MSG_DISCONNECT,
        "{:?}",
        packet.payload
    );
    let reason = u32::from_be_bytes(packet.payload[1..5].try_into().unwrap());
    assert_eq!(reason, KEY_EXCHANGE_FAILED);
    let mut rest = Vec::new();
    let eof = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
        .await
        .expect("the sensor kept the connection open after its DISCONNECT");
    assert!(eof.is_ok(), "{eof:?}");
    packet
}

#[tokio::test]
async fn a_client_sharing_no_key_exchange_algorithm_gets_a_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let offer = Offer {
        kex: "diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1",
        ..Offer::SENSOR
    };
    let (mut stream, _, _) = handshake_to_kexinit(addr, "SSH-2.0-PuTTY_Release_0.70", &offer).await;
    expect_disconnect(&mut stream).await;
    handle.abort();
}

#[tokio::test]
async fn a_mismatch_in_any_other_list_is_also_a_disconnect() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let cases = [
        Offer {
            host_key: "ssh-dss,ssh-rsa",
            ..Offer::SENSOR
        },
        Offer {
            cipher: "aes128-cbc,3des-cbc",
            ..Offer::SENSOR
        },
        Offer {
            compression: "zlib@openssh.com",
            ..Offer::SENSOR
        },
    ];
    for offer in &cases {
        let (mut stream, _, _) = handshake_to_kexinit(addr, "SSH-2.0-Go", offer).await;
        expect_disconnect(&mut stream).await;
    }
    handle.abort();
}

#[tokio::test]
async fn the_clients_offered_lists_are_logged_when_negotiation_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let offer = Offer {
        kex: "diffie-hellman-group1-sha1",
        host_key: "ssh-rsa,ssh-dss",
        cipher: "aes128-cbc,3des-cbc",
        mac: "hmac-md5",
        ..Offer::SENSOR
    };
    let (mut stream, _, _) = handshake_to_kexinit(addr, "SSH-2.0-PuTTY_Release_0.70", &offer).await;
    expect_disconnect(&mut stream).await;

    let end = session_end(&dir.path().join("events.jsonl")).await;
    handle.abort();
    let offered = &end.metadata["client_kex"];
    assert_eq!(offered["kex"], "diffie-hellman-group1-sha1");
    assert_eq!(offered["host_key"], "ssh-rsa,ssh-dss");
    assert_eq!(offered["cipher_c2s"], "aes128-cbc,3des-cbc");
    assert_eq!(offered["cipher_s2c"], "aes128-cbc,3des-cbc");
    assert_eq!(offered["mac_c2s"], "hmac-md5");
    assert_eq!(offered["mac_s2c"], "hmac-md5");
    assert_eq!(offered["compression_c2s"], "none");
    assert_eq!(end.metadata["negotiation_failed"], "kex");
    assert_eq!(end.metadata["phase"], "key_exchange");
    assert_eq!(end.metadata["client_version"], "SSH-2.0-PuTTY_Release_0.70");
}

#[tokio::test]
async fn an_offered_list_in_the_event_is_sanitized_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let long = "x".repeat(20_000);
    let kex: &'static str = Box::leak(format!("{long},\x1b[31mred").into_boxed_str());
    let offer = Offer {
        kex,
        ..Offer::SENSOR
    };
    let (mut stream, _, _) = handshake_to_kexinit(addr, "SSH-2.0-Go", &offer).await;
    expect_disconnect(&mut stream).await;
    let end = session_end(&dir.path().join("events.jsonl")).await;
    handle.abort();
    let logged = end.metadata["client_kex"]["kex"].as_str().unwrap();
    assert!(logged.len() <= 1024, "{} bytes", logged.len());
    assert!(!logged.contains('\x1b'));
}

/// A wrong guess (the client's first-choice algorithm is not the sensor's) obliges the sensor to
/// drop the packet that follows the KEXINIT unread (RFC 4253 section 7), and the real ECDH_INIT
/// behind it must still complete the exchange.
#[tokio::test]
async fn a_wrongly_guessed_first_kex_packet_is_ignored_and_the_exchange_completes() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let offer = Offer {
        kex: "curve25519-sha256@libssh.org,curve25519-sha256",
        first_kex_packet_follows: true,
        ..Offer::SENSOR
    };
    let (mut stream, server_kexinit, client_kexinit) =
        handshake_to_kexinit(addr, "SSH-2.0-PuTTY_Release_0.82", &offer).await;

    // The guessed packet: well-formed for another algorithm, so a server that wrongly takes it
    // for the ECDH_INIT answers it and derives keys the client never will.
    let (_wrong_secret, wrong_guess) = kex::build_client_ecdh_init();
    write_packet_unencrypted(&mut stream, &wrong_guess)
        .await
        .unwrap();
    complete_exchange(
        &mut stream,
        &server_kexinit,
        &client_kexinit,
        "SSH-2.0-PuTTY_Release_0.82",
    )
    .await;
    handle.abort();
}

/// A right guess is the real ECDH_INIT; dropping it would stall the exchange.
#[tokio::test]
async fn a_correctly_guessed_first_kex_packet_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let offer = Offer {
        first_kex_packet_follows: true,
        ..Offer::SENSOR
    };
    let (mut stream, server_kexinit, client_kexinit) =
        handshake_to_kexinit(addr, "SSH-2.0-Go", &offer).await;
    complete_exchange(&mut stream, &server_kexinit, &client_kexinit, "SSH-2.0-Go").await;
    handle.abort();
}

/// Drive the rest of a curve25519 exchange as a client, then prove both ends derived the same
/// keys by getting a SERVICE_ACCEPT back through the encrypted transport.
async fn complete_exchange(
    stream: &mut TcpStream,
    server_kexinit: &[u8],
    client_kexinit: &[u8],
    client_version: &str,
) {
    let (secret, init) = kex::build_client_ecdh_init();
    write_packet_unencrypted(stream, &init).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), read_packet_unencrypted(stream))
        .await
        .expect("no ECDH_REPLY")
        .unwrap();
    let server_version = "SSH-2.0-OpenSSH_9.6p1";
    let keys = kex::complete_kex_client(
        secret,
        &reply.payload,
        client_kexinit,
        server_kexinit,
        client_version,
        server_version,
    )
    .unwrap();
    let newkeys = read_packet_unencrypted(stream).await.unwrap();
    assert_eq!(newkeys.payload, [SSH_MSG_NEWKEYS]);
    write_packet_unencrypted(stream, &[SSH_MSG_NEWKEYS])
        .await
        .unwrap();

    let mut to_server = keys.client_to_server_cipher();
    let mut from_server = keys.server_to_client_cipher();
    let mut request = vec![SSH_MSG_SERVICE_REQUEST];
    request.extend_from_slice(&12u32.to_be_bytes());
    request.extend_from_slice(b"ssh-userauth");
    write_packet_encrypted(stream, &mut to_server, 3, &request)
        .await
        .unwrap();
    let accept = tokio::time::timeout(
        Duration::from_secs(5),
        read_packet_encrypted(stream, &mut from_server, 3),
    )
    .await
    .expect("no SERVICE_ACCEPT")
    .expect("the sensor and the client derived different keys");
    assert_eq!(accept[0], SSH_MSG_SERVICE_ACCEPT);
}

// ---- the system OpenSSH client, restricted to one algorithm at a time ----

/// Run `ssh` against the sensor with `options` appended and `echo interop-ok` as the command.
/// The password goes through `SSH_ASKPASS`, so no `sshpass` is needed. Fails (not skips) when
/// there is no `ssh` binary: an interop test that silently does not run proves nothing.
async fn openssh_exec(addr: SocketAddr, dir: &Path, options: &[&str]) -> std::process::Output {
    let askpass = dir.join("askpass.sh");
    std::fs::write(&askpass, "#!/bin/sh\necho interop\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let options: Vec<String> = options.iter().map(|s| s.to_string()).collect();
    let port = addr.port().to_string();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new("ssh")
            .args(["-F", "/dev/null", "-p", &port])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "GlobalKnownHostsFile=/dev/null"])
            .args(["-o", "PreferredAuthentications=password"])
            .args(["-o", "PubkeyAuthentication=no"])
            .args(["-o", "NumberOfPasswordPrompts=1"])
            .args(["-o", "ConnectTimeout=10"])
            .args(["-o", "LogLevel=ERROR"])
            .args(&options)
            .args(["root@127.0.0.1", "echo", "interop-ok"])
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the system `ssh` client is required for the interop tests")
    })
    .await
    .unwrap()
}

fn assert_interop(out: &std::process::Output, what: &str) {
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("interop-ok"),
        "{what}: status {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn openssh_connects_with_the_libssh_alias_of_curve25519() {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    let out = openssh_exec(
        addr,
        dir.path(),
        &["-o", "KexAlgorithms=curve25519-sha256@libssh.org"],
    )
    .await;
    handle.abort();
    assert_interop(&out, "curve25519-sha256@libssh.org");
}
