//! Pinned HTTP fetch: connects to `Pinned.ip` only (never re-resolves `Pinned.host`), disables
//! reqwest's own redirect handling (a hop is returned as `HttpResult::Redirect` for the caller to
//! re-vet through `guard::vet` before ever following it), and enforces a hard byte cap while the
//! body is still streaming so an oversized response is never buffered in full. See
//! `internal/design/12-malware-fetcher.md` section 6.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures_util::StreamExt;

use super::guard::{GuardReject, HostResolver, Pinned, vet};

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
    /// The IP actually dialed for this capture - the abuse-report chain-of-custody IOC (spec
    /// sections 9/10). Always the pin of the hop that produced this body: `fetch_http_once` sets
    /// it from its own `pinned` argument, so a multi-hop `fetch_http` capture carries the LAST
    /// (successful) hop's pin, not the first URL's.
    pub pinned_ip: IpAddr,
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
    /// `url`'s host (or port) does not match `pinned.host`/`pinned.port`. Fails closed before any
    /// client is built - see [`check_host_pin`].
    #[error("pin mismatch: {0}")]
    PinMismatch(String),
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
    check_host_pin(pinned, url)?;

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

    let attempt = fetch_once_inner(&client, url, limits, pinned.ip);
    match tokio::time::timeout(limits.total_timeout, attempt).await {
        Ok(result) => result,
        Err(_) => Err(FetchError::Timeout),
    }
}

/// Fail closed if `url`'s host (and, as secondary defense-in-depth, port) does not match
/// `pinned.host`/`pinned.port`. `ClientBuilder::resolve` below only overrides DNS for the exact
/// host string it is given; a caller that ever passes a `url` whose host differs from
/// `pinned.host` would fall through to real DNS on the url's own host and connect off-pin,
/// silently voiding the SSRF guard `guard::vet` already ran. This function is the sole HTTP
/// egress chokepoint, so the guarantee has to hold here rather than being trusted to every caller.
///
/// Compares parsed [`url::Host`] values, not raw strings: `guard::vet` stores an IPv6-literal
/// `Pinned.host` unbracketed (`Ipv6Addr::to_string()`, e.g. `::1`), while `Url::host()` returns
/// the bracketed form parsed as `Host::Ipv6` - a raw string compare would spuriously reject every
/// IPv6 target. `url::Host::parse` itself does not help here: it errors on an unbracketed IPv6
/// literal (`Host::parse("::1")` -> `Err(IdnaError)`, verified directly against this workspace's
/// vendored `url` crate) since only the bracketed form is recognized as IPv6 by that parser.
/// Instead, `pinned.host` is reconstructed the same way `guard::vet` derived it in the first
/// place: try `IpAddr::from_str` (which does accept bare `::1`) to recover the literal form, and
/// fall back to `Host::Domain` for a real hostname.
fn check_host_pin(pinned: &Pinned, url: &str) -> Result<(), FetchError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| FetchError::PinMismatch(format!("url {url:?} failed to parse: {e}")))?;

    let pinned_host = match pinned.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => url::Host::Ipv4(v4),
        Ok(IpAddr::V6(v6)) => url::Host::Ipv6(v6),
        Err(_) => url::Host::Domain(pinned.host.clone()),
    };
    let url_host = parsed.host().map(|h| h.to_owned());
    if url_host.as_ref() != Some(&pinned_host) {
        return Err(FetchError::PinMismatch(format!(
            "url host {url_host:?} does not match pinned host {:?}",
            pinned.host
        )));
    }

    // Secondary defense-in-depth, not the load-bearing check: `resolve()` is keyed on host, not
    // port, so a port mismatch is a wiring bug rather than an SSRF bypass - still cheap to assert.
    let url_port = parsed.port_or_known_default();
    if url_port != Some(pinned.port) {
        return Err(FetchError::PinMismatch(format!(
            "url port {url_port:?} does not match pinned port {}",
            pinned.port
        )));
    }

    Ok(())
}

async fn fetch_once_inner(
    client: &reqwest::Client,
    url: &str,
    limits: &FetchLimits,
    pinned_ip: IpAddr,
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
            pinned_ip,
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

/// The terminal result of following a fetch through zero or more redirects, every hop re-vetted.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpOutcome {
    Captured(Fetched),
    Rejected(GuardReject),
    Empty,
    TooBig,
    TooManyHops,
}

/// The outcome of a single hop attempt (vet, then fetch-once if accepted) - the seam between the
/// redirect-following loop's control flow and the real guard/network calls. `HttpResult`'s
/// variants map through unchanged except `Redirect`, which absorbs `vet`'s rejection too (a hop
/// either gets a pin and a fetch result, or it doesn't - the loop doesn't need to know which
/// underlying step produced `Rejected`).
#[derive(Debug, Clone, PartialEq)]
enum HopOutcome {
    Body(Fetched),
    Redirect(String),
    Rejected(GuardReject),
    Empty,
    TooBig,
}

/// Performs one hop of a fetch: vet `url`, then fetch it once against the resulting pin if
/// accepted. `fetch_http`'s production path wires this to `guard::vet` + `fetch_http_once`
/// ([`RealHopFetcher`]); tests substitute a mock that returns scripted [`HopOutcome`]s with no
/// socket and no real `vet` call, so the redirect loop's control flow (multi-hop follow,
/// hop-bounding, re-vetting a later hop that goes internal) is hermetically testable - see
/// `follow_redirects`.
trait HopFetcher {
    async fn hop(&self, url: &str) -> Result<HopOutcome, FetchError>;
}

/// The production [`HopFetcher`]: vets `url` with `allow_tftp: false` (a redirect - or even the
/// caller's own initial URL, via `fetch_http`'s entry point - can never reach tftp; that scheme
/// is only ever reachable through a caller that vets with `allow_tftp: true` outside this loop),
/// then fetches it once if accepted. `own`/`resolver`/`limits` are exactly `fetch_http`'s own
/// parameters, borrowed for the duration of one `fetch_http` call.
struct RealHopFetcher<'a> {
    own: &'a HashSet<IpAddr>,
    resolver: &'a dyn HostResolver,
    limits: &'a FetchLimits,
}

impl HopFetcher for RealHopFetcher<'_> {
    async fn hop(&self, url: &str) -> Result<HopOutcome, FetchError> {
        let pinned = match vet(url, self.own, self.resolver, false) {
            Ok(p) => p,
            Err(reject) => return Ok(HopOutcome::Rejected(reject)),
        };
        Ok(match fetch_http_once(&pinned, url, self.limits).await? {
            HttpResult::Body(fetched) => HopOutcome::Body(fetched),
            HttpResult::Redirect(loc) => HopOutcome::Redirect(loc),
            HttpResult::Empty => HopOutcome::Empty,
            HttpResult::TooBig => HopOutcome::TooBig,
        })
    }
}

/// The redirect-following loop, the SSRF-via-redirect defense: every hop - the initial `start_url`
/// and every subsequent `Location` target alike - goes through `hop_fetcher.hop`, which re-vets
/// fresh before ever fetching, so a 302 pointing at an internal/link-local/RFC1918/`::ffff:`-mapped
/// address is caught here rather than blindly followed. Generic over [`HopFetcher`] rather than
/// calling `vet`/`fetch_http_once` directly, so this control flow - multi-hop success, hop
/// bounding, and re-vetting a later hop that turns out internal - is testable against a mock with
/// no sockets and no real `vet` call.
///
/// `HopOutcome::Redirect(loc)` is already an absolute URL (`redirect_target` joins a relative
/// `Location` against the request URL before `RealHopFetcher` ever sees it) - `loc` becomes the
/// next hop's URL directly, never re-joined against the prior hop, since joining an
/// already-absolute URL again would corrupt it.
///
/// `max_hops` bounds redirects *followed*, not hops attempted: the initial hop is never
/// hop-budget-gated (only a `Redirect` response consumes budget), and hitting the bound on a
/// `Redirect` returns `TooManyHops` without ever fetching that redirect's target. A rejected hop
/// (initial or any redirect) captures zero bytes: `Rejected` short-circuits the loop before any
/// further hop - and therefore any further socket - is ever reached.
async fn follow_redirects<H: HopFetcher>(
    start_url: &str,
    max_hops: u8,
    hop_fetcher: &H,
) -> Result<HttpOutcome, FetchError> {
    let mut current = start_url.to_string();
    let mut hops_left = max_hops;

    loop {
        match hop_fetcher.hop(&current).await? {
            HopOutcome::Body(fetched) => return Ok(HttpOutcome::Captured(fetched)),
            HopOutcome::Rejected(reject) => return Ok(HttpOutcome::Rejected(reject)),
            HopOutcome::Empty => return Ok(HttpOutcome::Empty),
            HopOutcome::TooBig => return Ok(HttpOutcome::TooBig),
            HopOutcome::Redirect(loc) => {
                if hops_left == 0 {
                    return Ok(HttpOutcome::TooManyHops);
                }
                hops_left -= 1;
                current = loc;
            }
        }
    }
}

/// Follow `url` through up to `max_hops` redirects, re-vetting every hop through `guard::vet`
/// before it is ever fetched - see `follow_redirects` for the full invariant. Just wires up the
/// production [`RealHopFetcher`] and runs the loop; production behavior is unchanged from before
/// this seam existed.
pub async fn fetch_http(
    url: &str,
    own: &HashSet<IpAddr>,
    r: &dyn HostResolver,
    limits: &FetchLimits,
    max_hops: u8,
) -> Result<HttpOutcome, FetchError> {
    let hop_fetcher = RealHopFetcher {
        own,
        resolver: r,
        limits,
    };
    follow_redirects(url, max_hops, &hop_fetcher).await
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use axum::Router;
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::IntoResponse;
    use axum::routing::get;

    use super::super::guard::{EgressReject, Scheme};
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

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

    // Fix round 1, #3 (important): a captured body must record the IP actually dialed - the
    // abuse-report chain-of-custody IOC (spec sections 9/10). TFTP already recorded this;
    // fetch_http_once had `pinned` in scope the whole time but never carried `pinned.ip` into
    // `Fetched`.
    #[tokio::test]
    async fn captured_body_records_the_dialed_pinned_ip() {
        let app = Router::new().route("/", get(|| async { "malware bytes" }));
        let port = spawn(app).await;
        let p = pinned(port);

        let result = fetch_http_once(&p, &format!("http://127.0.0.1:{port}/"), &limits(1024))
            .await
            .unwrap();

        match result {
            HttpResult::Body(fetched) => assert_eq!(fetched.pinned_ip, p.ip),
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

    #[tokio::test]
    async fn host_mismatch_fails_closed() {
        // The server is real and reachable at 127.0.0.1:port, but Pinned.host names a different
        // host than the url we actually fetch - resolve() would only pin DNS for "other.example",
        // so without the check_host_pin guard the client falls through to real DNS for
        // "other.example" (which fails or, worse, could resolve to something reachable) rather
        // than ever dialing the pinned target. Asserting the specific PinMismatch variant (not
        // just "any Err") proves the guard fired, rather than the request merely failing for an
        // unrelated reason such as a DNS lookup error on the bogus name.
        let app = Router::new().route("/", get(|| async { "ok" }));
        let port = spawn(app).await;

        let mismatched = Pinned {
            host: "other.example".to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            scheme: Scheme::Http,
        };

        let result = fetch_http_once(
            &mismatched,
            &format!("http://127.0.0.1:{port}/"),
            &limits(1024),
        )
        .await;

        assert!(
            matches!(result, Err(FetchError::PinMismatch(_))),
            "expected Err(PinMismatch(_)), got {result:?}"
        );
    }

    #[tokio::test]
    async fn relative_redirect_location_is_joined_absolute() {
        let app = Router::new().route(
            "/start",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/next/path")]) }),
        );
        let port = spawn(app).await;

        let result = fetch_http_once(
            &pinned(port),
            &format!("http://127.0.0.1:{port}/start"),
            &limits(1024),
        )
        .await
        .unwrap();

        assert_eq!(
            result,
            HttpResult::Redirect(format!("http://127.0.0.1:{port}/next/path"))
        );
    }

    #[tokio::test]
    async fn redirect_with_no_location_header_is_empty() {
        let app = Router::new().route("/", get(|| async { StatusCode::FOUND }));
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

    #[tokio::test]
    async fn redirect_with_non_utf8_location_is_empty() {
        let app = Router::new().route(
            "/",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(
                        header::LOCATION,
                        HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
                    )],
                )
            }),
        );
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

    /// A [`HostResolver`] that maps specific hostnames to specific resolved addresses, so a
    /// single test can give the redirect chain's different hosts different (real or forbidden)
    /// classifications without touching real DNS.
    struct MapResolver(std::collections::HashMap<&'static str, IpAddr>);
    impl HostResolver for MapResolver {
        fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            self.0
                .get(host)
                .map(|ip| vec![*ip])
                .ok_or_else(|| std::io::Error::other(format!("unmapped host {host}")))
        }
    }

    #[tokio::test]
    async fn redirect_target_resolving_to_forbidden_address_is_rejected_with_no_bytes_captured() {
        // A real, live server binds to the exact loopback address the mock resolver reports for
        // "attacker-redirect-target.test" - so it WOULD serve a body and increment `hits` if
        // `fetch_http` ever dialed it. This is what makes the zero-hits assertion below load
        // bearing rather than a tautology: mapping the redirect target to an address nothing
        // listens on (e.g. a link-local metadata IP) would leave `hits` at 0 whether the guard
        // fired correctly or was silently bypassed, since the dial attempt fails either way -
        // proving nothing about whether `vet` actually ran. Pointing the mock resolution at the
        // server's own real, reachable loopback address closes that gap: a bypassed/missing
        // guard would connect successfully and increment `hits`; the correct guard (loopback is
        // in `core_scoring`'s reserved-range list) rejects before any socket opens, so it stays
        // at 0. Verified by fails-without/passes-with (see task report) - temporarily letting the
        // rejected branch fall through to fetch_http_once made this exact test fail with
        // `hits == 1` and `Captured(_)`, not just a generic panic.
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_in_handler = hits.clone();
        let app = Router::new().route(
            "/",
            get(move || {
                let hits = hits_in_handler.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    "should never be served"
                }
            }),
        );
        let port = spawn(app).await;

        let own = HashSet::new();
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(
            "attacker-redirect-target.test",
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        );
        let resolver = MapResolver(hosts);

        let result = fetch_http(
            &format!("http://attacker-redirect-target.test:{port}/"),
            &own,
            &resolver,
            &limits(1024),
            3,
        )
        .await
        .unwrap();

        assert!(
            matches!(result, HttpOutcome::Rejected(GuardReject::Forbidden(_))),
            "expected Rejected(Forbidden(_)), got {result:?}"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "handler was reached - fetch_http dialed a hop its own vet() call had rejected"
        );
    }

    #[tokio::test]
    async fn hop_budget_does_not_gate_the_first_attempt() {
        // A subtly-wrong implementation could check `hops_left == 0` before ever calling `vet`,
        // treating max_hops as "attempts remaining" rather than "redirects remaining to follow" -
        // that bug would turn every max_hops=0 call into an unconditional TooManyHops, even one
        // whose target was never actually a redirect. This proves the opposite: vet() runs first
        // on every call including the very first, and TooManyHops is reserved for hop-exhaustion
        // on an *actual* redirect, never substituted for a straightforward rejection.
        let own = HashSet::new();
        let mut hosts = std::collections::HashMap::new();
        hosts.insert("attacker.test", ip("10.0.0.1"));
        let resolver = MapResolver(hosts);

        let result = fetch_http("http://attacker.test/", &own, &resolver, &limits(1024), 0)
            .await
            .unwrap();

        assert!(
            matches!(result, HttpOutcome::Rejected(GuardReject::Forbidden(_))),
            "expected Rejected(Forbidden(_)) even with max_hops=0 (the initial hop isn't a \
             redirect being followed), got {result:?}"
        );
    }

    // --- hermetic redirect-loop tests, driving `follow_redirects` against a mock `HopFetcher` ---
    //
    // These exercise the loop's control flow directly - no sockets, no real `vet` call - which is
    // what makes multi-hop success, hop-bounding, and later-hop re-vetting testable at all: the
    // real-socket tests above can only ever reach a single hop, since no address a hermetic test
    // can bind a listener to also clears `guard::vet`'s forbidden-address check (loopback,
    // RFC1918, RFC5737, link-local, and CGNAT are all covered - see task-5-report.md for the full
    // verification). The mock below is scripted per-URL and records every URL it was called with,
    // in order, so each test can assert not just the final `HttpOutcome` but that the loop
    // actually attempted every hop it claims to have followed.

    /// A [`HopFetcher`] test double: returns a scripted [`HopOutcome`] per URL and records every
    /// URL it was called with, in call order. Panics on a URL with no script entry - a loop bug
    /// that skips, repeats, or corrupts a hop (e.g. double-joining a redirect target) shows up as
    /// an unscripted-URL panic rather than silently passing.
    struct MockHopFetcher {
        script: std::collections::HashMap<&'static str, HopOutcome>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl MockHopFetcher {
        fn new(script: impl IntoIterator<Item = (&'static str, HopOutcome)>) -> Self {
            Self {
                script: script.into_iter().collect(),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl HopFetcher for MockHopFetcher {
        async fn hop(&self, url: &str) -> Result<HopOutcome, FetchError> {
            self.calls.lock().unwrap().push(url.to_string());
            Ok(self
                .script
                .get(url)
                .unwrap_or_else(|| panic!("unscripted hop url: {url}"))
                .clone())
        }
    }

    fn fetched(tag: &str) -> Fetched {
        Fetched {
            bytes: tag.as_bytes().to_vec(),
            content_type: None,
            final_url: tag.to_string(),
            // Arbitrary and irrelevant to what these redirect-loop tests exercise (control flow,
            // not pinned_ip's value) - fixed so every call produces an equal Fetched.
            pinned_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        }
    }

    #[tokio::test]
    async fn loop_zero_redirect_captures_the_first_body() {
        let fetcher = MockHopFetcher::new([("a", HopOutcome::Body(fetched("a-body")))]);

        let result = follow_redirects("a", 3, &fetcher).await.unwrap();

        assert_eq!(result, HttpOutcome::Captured(fetched("a-body")));
        assert_eq!(fetcher.calls(), vec!["a"]);
    }

    #[tokio::test]
    async fn loop_follows_three_hops_to_capture_in_order() {
        let fetcher = MockHopFetcher::new([
            ("a", HopOutcome::Redirect("b".to_string())),
            ("b", HopOutcome::Redirect("c".to_string())),
            ("c", HopOutcome::Body(fetched("c-body"))),
        ]);

        let result = follow_redirects("a", 3, &fetcher).await.unwrap();

        assert_eq!(result, HttpOutcome::Captured(fetched("c-body")));
        assert_eq!(
            fetcher.calls(),
            vec!["a", "b", "c"],
            "every hop must be followed and re-vetted, in order - not just the first"
        );
    }

    #[tokio::test]
    async fn loop_exhausts_hop_budget_on_the_fourth_redirect() {
        // max_hops counts redirects *followed*, not hops attempted (see follow_redirects' doc
        // comment): with max_hops=3, hops 0/1/2 are followed normally (budget 3->2->1->0), and
        // the 4th redirect response - received while budget is already 0 - is what trips
        // TooManyHops, without the loop ever fetching hop 4's target. That is exactly "4 hops
        // with max_hops=3 -> TooManyHops" from the brief, so this test pins the off-by-one by
        // asserting the exact call count (4), not just the outcome.
        let fetcher = MockHopFetcher::new([
            ("h0", HopOutcome::Redirect("h1".to_string())),
            ("h1", HopOutcome::Redirect("h2".to_string())),
            ("h2", HopOutcome::Redirect("h3".to_string())),
            ("h3", HopOutcome::Redirect("h4".to_string())),
        ]);

        let result = follow_redirects("h0", 3, &fetcher).await.unwrap();

        assert_eq!(result, HttpOutcome::TooManyHops);
        assert_eq!(
            fetcher.calls(),
            vec!["h0", "h1", "h2", "h3"],
            "expected exactly 4 hop attempts for max_hops=3 (h4 must never be dialed)"
        );
    }

    #[tokio::test]
    async fn loop_rejects_when_a_later_hop_goes_internal() {
        // The case the real-socket tests above could not reach: the FIRST hop looks completely
        // fine (a real redirect), and it's the SECOND hop's re-vet that catches the SSRF attempt
        // - proving `guard::vet` runs again on the redirect target, not just on the original URL.
        let fetcher = MockHopFetcher::new([
            ("a", HopOutcome::Redirect("b".to_string())),
            (
                "b",
                HopOutcome::Rejected(GuardReject::Forbidden(EgressReject::Reserved)),
            ),
        ]);

        let result = follow_redirects("a", 3, &fetcher).await.unwrap();

        assert!(
            matches!(result, HttpOutcome::Rejected(GuardReject::Forbidden(_))),
            "expected Rejected(Forbidden(_)), got {result:?}"
        );
        assert_eq!(
            fetcher.calls(),
            vec!["a", "b"],
            "hop b must actually have been re-vetted, not short-circuited from hop a's result"
        );
        match result {
            HttpOutcome::Rejected(_) => {}
            HttpOutcome::Captured(f) => {
                panic!("captured {} bytes on a rejected hop", f.bytes.len())
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }
}
