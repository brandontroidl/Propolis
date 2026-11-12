//! The sensor against the system OpenSSH client, restricted to one algorithm at a time.
//!
//! This is the independent oracle for the transport: every other test builds both ends of an
//! exchange from this crate's own code, so a misreading of the RFC (a wrong key letter, an
//! off-by-one in a MAC's input, a wrong prime) is shared by both sides and passes. OpenSSH shares
//! none of that code. Each test restricts the client to one algorithm (`ssh -o Ciphers=...`), so
//! a success cannot be a fallback to something else, and `an_unsupported_...` is the negative
//! control showing the restriction does take effect.
//!
//! Needs the system `ssh` (OpenSSH 8.4 or later, for `SSH_ASKPASS_REQUIRE`) on `PATH`, and fails
//! rather than skips without it. Only the public `serve` entry point and the `ssh` binary are
//! used, so the same file runs unchanged against an older checkout of the sensor, which is how the
//! fails-without evidence for each algorithm was taken.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};

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

/// Connect with each of `options`' sets in turn; every one must complete and run the command.
async fn assert_each_connects(options_sets: &[Vec<String>]) {
    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = start(dir.path()).await;
    for set in options_sets {
        let options: Vec<&str> = set.iter().map(String::as_str).collect();
        let out = openssh_exec(addr, dir.path(), &options).await;
        assert_interop(&out, &set.join(" "));
    }
    handle.abort();
}

fn option(name: &str, value: &str) -> Vec<String> {
    vec!["-o".to_string(), format!("{name}={value}")]
}

#[tokio::test]
async fn openssh_connects_with_the_libssh_alias_of_curve25519() {
    assert_each_connects(&[option("KexAlgorithms", "curve25519-sha256@libssh.org")]).await;
}

/// Each key exchange the sensor offers, with the client restricted to it. The Diffie-Hellman
/// prime and the P-256 point encoding are typed in or hand-assembled here, so a mistake in either
/// shows only against an implementation that did not copy it.
#[tokio::test]
async fn openssh_connects_with_each_key_exchange() {
    let sets: Vec<_> = [
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group14-sha256",
    ]
    .iter()
    .map(|k| option("KexAlgorithms", k))
    .collect();
    assert_each_connects(&sets).await;
}

/// The negative controls: a real client restricted to an algorithm the sensor does not speak
/// fails, and what it asked for is on the sensor's end-of-handshake event. Without these, "the
/// client succeeded" would not show that a restriction took effect.
#[tokio::test]
async fn openssh_restricted_to_an_unsupported_algorithm_is_refused_and_logged() {
    // (ssh option, the list the sensor names as failed, the key of the client's offer to read)
    let cases = [
        ("Ciphers=aes128-cbc", "cipher_c2s", "aes128-cbc"),
        (
            "KexAlgorithms=ecdh-sha2-nistp384",
            "kex",
            "ecdh-sha2-nistp384",
        ),
        (
            "HostKeyAlgorithms=ecdsa-sha2-nistp384",
            "host_key",
            "ecdsa-sha2-nistp384",
        ),
    ];
    for (option, failed, offered) in cases {
        let dir = tempfile::tempdir().unwrap();
        let (addr, handle) = start(dir.path()).await;
        let out = openssh_exec(addr, dir.path(), &["-o", option]).await;
        assert!(!out.status.success(), "{option}: {out:?}");

        let log = dir.path().join("events.jsonl");
        let mut end = None;
        for _ in 0..100 {
            end = std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str::<sensor_wire::SensorEvent>(l).unwrap())
                .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_SESSION_END);
            if end.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        handle.abort();
        let end = end.expect("no honeypot_session_end event was logged");
        assert_eq!(end.metadata["negotiation_failed"], failed, "{option}");
        // The client adds its extension markers (`ext-info-c` and the like) after its own list.
        let listed = end.metadata["client_kex"][failed].as_str().unwrap();
        assert!(listed.starts_with(offered), "{option}: {listed}");
        assert!(
            end.metadata["client_version"]
                .as_str()
                .unwrap()
                .starts_with("SSH-2.0-OpenSSH_")
        );
    }
}

#[tokio::test]
async fn openssh_connects_with_each_aead_cipher() {
    let sets: Vec<_> = [
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    ]
    .iter()
    .map(|c| option("Ciphers", c))
    .collect();
    assert_each_connects(&sets).await;
}

/// Every CTR cipher against every MAC, one pair at a time, so a pair the sensor mishandles cannot
/// be hidden by a fallback.
#[tokio::test]
async fn openssh_connects_with_each_ctr_cipher_and_each_mac() {
    let mut sets = Vec::new();
    for cipher in ["aes128-ctr", "aes192-ctr", "aes256-ctr"] {
        for mac in [
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1",
        ] {
            let mut set = option("Ciphers", cipher);
            set.extend(option("MACs", mac));
            sets.push(set);
        }
    }
    assert_each_connects(&sets).await;
}
