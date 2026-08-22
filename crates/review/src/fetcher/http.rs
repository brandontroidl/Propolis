//! Pinned HTTP fetch: connects to `Pinned.ip` only (never re-resolves `Pinned.host`), disables
//! reqwest's own redirect handling (a hop is returned as `HttpResult::Redirect` for the caller to
//! re-vet through `guard::vet` before ever following it), and enforces a hard byte cap while the
//! body is still streaming so an oversized response is never buffered in full. See
//! `internal/design/12-malware-fetcher.md` section 6.

use std::net::SocketAddr;
use std::time::Duration;

use futures_util::StreamExt;

use super::guard::Pinned;

/// Bounds for one fetch attempt. Every field is caller-supplied so the review daemon can source
/// them from validated config (`internal/design/12-malware-fetcher.md` section 13) rather than
/// this module hard-coding defaults.
#[derive(Debug, Clone)]
pub struct FetchLimits {
    pub max_bytes: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub total_timeout: Duration,
    pub user_agent: String,
}

/// A successfully captured, under-cap response body.
#[derive(Debug, Clone, PartialEq)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub final_url: String,
}

/// The outcome of one `fetch_http_once` call. `Redirect` is never followed here - the caller
/// re-vets the target through `guard::vet` before any further socket is opened, so a redirect
/// hop can never bypass the SSRF guard.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpResult {
    Body(Fetched),
    Redirect(String),
    Empty,
    TooBig,
}

/// Errors from the HTTP client itself (connect/TLS/protocol failures, and a chunk read error
/// mid-stream) or the independent wall-clock deadline. A byte-cap breach is not an error - it is
/// `Ok(HttpResult::TooBig)`, since it is an expected, handled outcome, not a fetch failure.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("http client error: {0}")]
    Client(#[from] reqwest::Error),
    /// The independent `tokio::time::timeout` oracle fired. In practice reqwest's own
    /// `.timeout()` already bounds the whole send+stream, so this is a defense-in-depth backstop,
    /// not the primary deadline.
    #[error("fetch exceeded the total timeout")]
    Timeout,
}

/// Fetch `url` once against the already-vetted `pinned` target. Connects to `pinned.ip` via a
/// static resolver override (`ClientBuilder::resolve`) so the client can never re-resolve
/// `pinned.host` through DNS - the load-bearing pinning guarantee. A fresh, unpooled client is
/// built per call: attacker-controlled URLs never share a connection pool.
pub async fn fetch_http_once(
    pinned: &Pinned,
    url: &str,
    limits: &FetchLimits,
) -> Result<HttpResult, FetchError> {
    let client = reqwest::Client::builder()
        .resolve(&pinned.host, SocketAddr::new(pinned.ip, pinned.port))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .http1_only()
        .connect_timeout(limits.connect_timeout)
        .read_timeout(limits.read_timeout)
        .timeout(limits.total_timeout)
        .danger_accept_invalid_certs(true) // bytes never execute; SNI/Host still correct
        .build()?;

    let attempt = fetch_once_inner(&client, url, limits);
    match tokio::time::timeout(limits.total_timeout, attempt).await {
        Ok(result) => result,
        Err(_) => Err(FetchError::Timeout),
    }
}

async fn fetch_once_inner(
    client: &reqwest::Client,
    url: &str,
    limits: &FetchLimits,
) -> Result<HttpResult, FetchError> {
    let resp = client
        .get(url)
        .header(reqwest::header::USER_AGENT, &limits.user_agent)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await?;

    if resp.status().is_redirection() {
        return Ok(redirect_target(url, &resp));
    }

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let final_url = resp.url().to_string();

    let mut body = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > limits.max_bytes {
            return Ok(HttpResult::TooBig);
        }
        body.extend_from_slice(&chunk);
    }

    if body.is_empty() {
        Ok(HttpResult::Empty)
    } else {
        Ok(HttpResult::Body(Fetched {
            bytes: body,
            content_type,
            final_url,
        }))
    }
}

/// Resolve a 3xx response's `Location` header into an absolute URL, joining a relative header
/// value against the request URL per RFC 7231 7.1.2. A redirect status with no usable
/// `Location` carries no body and nothing to act on, so it reads as `Empty` rather than an error.
fn redirect_target(request_url: &str, resp: &reqwest::Response) -> HttpResult {
    let Some(loc) = resp.headers().get(reqwest::header::LOCATION) else {
        return HttpResult::Empty;
    };
    let Ok(loc_str) = loc.to_str() else {
        return HttpResult::Empty;
    };
    let resolved = url::Url::parse(request_url)
        .ok()
        .and_then(|base| base.join(loc_str).ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| loc_str.to_string());
    HttpResult::Redirect(resolved)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use axum::Router;
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::get;

    use super::super::guard::Scheme;
    use super::*;

    async fn spawn(app: Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    fn pinned(port: u16) -> Pinned {
        Pinned {
            host: "127.0.0.1".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            scheme: Scheme::Http,
        }
    }

    fn limits(max_bytes: usize) -> FetchLimits {
        FetchLimits {
            max_bytes,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(5),
            user_agent: "propolis-fetch-test".to_string(),
        }
    }

    #[tokio::test]
    async fn body_under_cap_is_captured_whole() {
        const FIVE_MB: usize = 5 * 1024 * 1024;
        let app = Router::new().route("/", get(|| async { vec![7u8; FIVE_MB] }));
        let port = spawn(app).await;

        let result = fetch_http_once(
            &pinned(port),
            &format!("http://127.0.0.1:{port}/"),
            &limits(10 * 1024 * 1024),
        )
        .await
        .unwrap();

        match result {
            HttpResult::Body(fetched) => {
                assert_eq!(fetched.bytes.len(), FIVE_MB);
                assert!(fetched.bytes.iter().all(|&b| b == 7));
            }
            other => panic!("expected Body, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn over_cap_body_aborts_mid_stream() {
        // The handler streams up to 30 x 1 MiB chunks with a real per-chunk delay, so the
        // fastest way to observe all of them is to actually wait through every delay. A cap-check
        // that aborts as soon as the running total exceeds the limit stops after ~11 chunks
        // (~11 MiB > the 10 MiB cap); an implementation that buffers the whole body before
        // checking the cap would have to wait for all 30. The shared counter below records how
        // many chunks the server actually produced before the client dropped the connection -
        // a count well below 30 is direct evidence the abort happened while streaming, not after.
        const CHUNK: usize = 1024 * 1024;
        const TOTAL_CHUNKS: usize = 30;
        const CAP: usize = 10 * 1024 * 1024;

        let produced = Arc::new(AtomicUsize::new(0));
        let produced_in_handler = produced.clone();
        let app = Router::new().route(
            "/big",
            get(move || {
                let produced = produced_in_handler.clone();
                async move {
                    let stream = futures_util::stream::unfold(0usize, move |i| {
                        let produced = produced.clone();
                        async move {
                            if i >= TOTAL_CHUNKS {
                                return None;
                            }
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            produced.fetch_add(1, Ordering::SeqCst);
                            Some((Ok::<_, std::io::Error>(vec![0u8; CHUNK]), i + 1))
                        }
                    });
                    axum::body::Body::from_stream(stream)
                }
            }),
        );
        let port = spawn(app).await;

        let started = Instant::now();
        let result = fetch_http_once(
            &pinned(port),
            &format!("http://127.0.0.1:{port}/big"),
            &limits(CAP),
        )
        .await
        .unwrap();
        let elapsed = started.elapsed();

        assert!(
            matches!(result, HttpResult::TooBig),
            "expected TooBig, got {:?}",
            match result {
                HttpResult::Body(f) => format!("Body({} bytes)", f.bytes.len()),
                other => format!("{other:?}"),
            }
        );
        let seen = produced.load(Ordering::SeqCst);
        assert!(
            seen < TOTAL_CHUNKS,
            "server produced all {TOTAL_CHUNKS} chunks ({seen} seen) - client did not abort mid-stream"
        );
        assert!(
            elapsed < Duration::from_millis(700),
            "took {elapsed:?}, expected an early abort well under the full {}ms stream",
            TOTAL_CHUNKS * 25
        );
    }

    #[tokio::test]
    async fn redirect_status_returns_location_unfollowed() {
        let app = Router::new().route(
            "/",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "http://x/y")]) }),
        );
        let port = spawn(app).await;

        let result = fetch_http_once(
            &pinned(port),
            &format!("http://127.0.0.1:{port}/"),
            &limits(1024),
        )
        .await
        .unwrap();

        assert_eq!(result, HttpResult::Redirect("http://x/y".to_string()));
    }

    #[tokio::test]
    async fn empty_200_body_is_empty() {
        let app = Router::new().route("/", get(|| async { StatusCode::OK.into_response() }));
        let port = spawn(app).await;

        let result = fetch_http_once(
            &pinned(port),
            &format!("http://127.0.0.1:{port}/"),
            &limits(1024),
        )
        .await
        .unwrap();

        assert_eq!(result, HttpResult::Empty);
    }
}
