//! A plain-http hop does no TLS, so it must not depend on the system trust store. Building a
//! certificate-verifying client loads and parses that store (on Linux, rustls-platform-verifier
//! reads it through rustls-native-certs), which blocks the async worker on every hop and fails the
//! build outright on a host without one. The fetcher did exactly that for plain http.
//!
//! A test binary of its own because it points the trust store at an empty file through
//! SSL_CERT_FILE, which rustls-native-certs reads in place of the system store, and nothing else in
//! this binary reads the environment.
//!
//! Built only where rustls-platform-verifier loads roots through rustls-native-certs (the same cfg
//! it selects that loader with). On Apple and Windows targets the verifier asks the operating
//! system instead and never reads SSL_CERT_FILE, so there the test could show nothing.
#![cfg(all(unix, not(target_vendor = "apple"), not(target_os = "android")))]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::time::Duration;

use review::fetcher::TransportAuth;
use review::fetcher::guard::{Pinned, Scheme};
use review::fetcher::http::{FetchError, FetchLimits, HttpResult, fetch_http_once};

/// Reserved (RFC 2606) and never resolved, so only the pin reaches anything by it.
const HOST: &str = "malware.test";

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";

fn limits() -> FetchLimits {
    FetchLimits {
        max_bytes: 1024,
        connect_timeout: Duration::from_secs(2),
        read_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(5),
        user_agent: "propolis-fetch-test".to_string(),
        dns_timeout: Duration::from_secs(5),
    }
}

fn pinned(port: u16, scheme: Scheme) -> Pinned {
    Pinned {
        host: HOST.to_string(),
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port,
        scheme,
    }
}

/// A plain TCP listener on 127.0.0.1 answering every request with [`RESPONSE`].
fn spawn_plain() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match tcp.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let _ = tcp.write_all(RESPONSE);
        }
    });
    port
}

#[test]
fn a_plain_http_hop_does_not_need_the_system_trust_store() {
    let empty = tempfile::NamedTempFile::new().unwrap();
    // SAFETY: runs before any runtime or HTTP client exists, and nothing else in this binary
    // reads the environment.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", empty.path());
        std::env::remove_var("SSL_CERT_DIR");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let port = spawn_plain();
        let result = fetch_http_once(
            &pinned(port, Scheme::Http),
            &format!("http://{HOST}:{port}/x"),
            &limits(),
        )
        .await;
        match result {
            Ok(HttpResult::Body(f)) => {
                assert_eq!(f.bytes, b"body");
                assert_eq!(f.transport_auth, TransportAuth::Plaintext);
            }
            other => panic!("plain http must not need a trust store, got {other:?}"),
        }

        // https still needs the store, and this environment really has taken it away: the
        // verifying client cannot even be built. Without that, the result above would prove
        // nothing.
        let result = fetch_http_once(
            &pinned(port, Scheme::Https),
            &format!("https://{HOST}:{port}/x"),
            &limits(),
        )
        .await;
        assert!(
            matches!(&result, Err(FetchError::Client(e)) if e.is_builder()),
            "https with no trust store must fail to build its client, got {result:?}"
        );
    });
}
