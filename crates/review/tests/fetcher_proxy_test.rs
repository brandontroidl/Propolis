//! The malware fetcher must never send an attacker-chosen URL to a proxy named in the daemon's
//! environment. reqwest reads HTTP_PROXY, HTTPS_PROXY and ALL_PROXY when a client is built, and a
//! proxy resolves and dials the URL's host itself, so a proxied fetch would bypass the vetted pin
//! and everything the SSRF guard decided about it.
//!
//! A test binary of its own because it sets process environment variables: the other test here
//! never reads the environment, so setting them cannot race anything.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use review::fetcher::TransportAuth;
use review::fetcher::guard::{Pinned, Scheme};
use review::fetcher::http::{FetchLimits, HttpResult, fetch_http_once};

/// Reserved (RFC 2606) and never resolved, so only the pin, or a proxy, can reach anything by it.
const HOST: &str = "malware.test";

const TARGET_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfrom-target";
const PROXY_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nfrom-proxy";

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

fn read_request_head(stream: &mut impl Read) {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
}

/// A plain TCP listener on 127.0.0.1 answering every request with `response`. The count is
/// taken on accept, before anything is answered, so it is final by the time a client has read a
/// response.
fn spawn_plain(response: &'static [u8]) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            read_request_head(&mut tcp);
            let _ = tcp.write_all(response);
        }
    });
    (port, accepted)
}

/// An HTTPS listener on 127.0.0.1 presenting a self-signed certificate for [`HOST`], so the
/// fetcher's verifying attempt fails and its no-validation retry is the attempt that reads the
/// body. Counts connections the same way as [`spawn_plain`].
fn spawn_self_signed_tls(response: &'static [u8]) -> (u16, Arc<AtomicUsize>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![HOST.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            counter.fetch_add(1, Ordering::SeqCst);
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let mut conn = rustls::ServerConnection::new(config).unwrap();
                while conn.is_handshaking() {
                    if conn.complete_io(&mut tcp).is_err() {
                        return;
                    }
                }
                let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
                read_request_head(&mut stream);
                let _ = stream.write_all(response);
                stream.conn.send_close_notify();
                let _ = stream.flush();
            });
        }
    });
    (port, accepted)
}

#[test]
fn fetches_ignore_proxies_named_in_the_environment() {
    let (proxy_port, proxy_hits) = spawn_plain(PROXY_RESPONSE);
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    // SAFETY: runs before any runtime or HTTP client exists, and the only other test in this
    // binary never reads the environment.
    unsafe {
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            std::env::set_var(name, &proxy);
        }
        // Either would exempt these requests from the proxy whether or not the fetcher refuses
        // it (a NO_PROXY entry, or reqwest's CGI guard), and the test would prove nothing.
        for name in ["NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
            std::env::remove_var(name);
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (port, target_hits) = spawn_plain(TARGET_RESPONSE);
        let result = fetch_http_once(
            &pinned(port, Scheme::Http),
            &format!("http://{HOST}:{port}/x"),
            &limits(),
        )
        .await;
        match result {
            Ok(HttpResult::Body(f)) => assert_eq!(f.bytes, b"from-target"),
            other => panic!("http: expected the pinned target's body, got {other:?}"),
        }
        assert_eq!(target_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            0,
            "http: the proxy must never see a fetch"
        );

        // Both the verifying attempt and the retry without validation must dial the pin.
        let (port, target_hits) = spawn_self_signed_tls(TARGET_RESPONSE);
        let result = fetch_http_once(
            &pinned(port, Scheme::Https),
            &format!("https://{HOST}:{port}/x"),
            &limits(),
        )
        .await;
        match result {
            Ok(HttpResult::Body(f)) => {
                assert_eq!(f.bytes, b"from-target");
                assert!(
                    matches!(f.transport_auth, TransportAuth::Unverified { .. }),
                    "the body must come from the retry, got {:?}",
                    f.transport_auth
                );
            }
            other => panic!("https: expected the pinned target's body, got {other:?}"),
        }
        assert_eq!(
            target_hits.load(Ordering::SeqCst),
            2,
            "https: the verifying attempt and the retry must both reach the pin"
        );
        assert_eq!(
            proxy_hits.load(Ordering::SeqCst),
            0,
            "https: the proxy must never see a fetch"
        );
    });
}

/// Every HTTP client the fetcher uses must come from the one constructor the test above proves
/// refuses proxies. A second construction site would not inherit that refusal.
#[test]
fn the_fetcher_builds_http_clients_in_one_place() {
    const CONSTRUCTORS: [&str; 5] = [
        "Client::builder(",
        "Client::new(",
        "ClientBuilder::new(",
        "reqwest::get(",
        "reqwest::blocking",
    ];
    let mut sites = Vec::new();
    let mut dirs = vec![PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/fetcher"
    ))];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            for (n, line) in source.lines().enumerate() {
                if CONSTRUCTORS.iter().any(|c| line.contains(c)) {
                    let file = path.file_name().unwrap().to_string_lossy();
                    sites.push(format!("{file}:{}", n + 1));
                }
            }
        }
    }
    assert_eq!(
        sites.len(),
        1,
        "expected exactly one HTTP client construction in src/fetcher: {sites:?}"
    );
    assert!(
        sites[0].starts_with("http.rs:"),
        "the construction site moved out of http.rs: {sites:?}"
    );
}
