//! Pinned HTTP fetch: connects to `Pinned.ip` only (never re-resolves `Pinned.host`), disables
//! reqwest's own redirect handling (a hop is returned as `HttpResult::Redirect` for the caller to
//! re-vet through `guard::vet` before ever following it), and enforces a hard byte cap while the
//! body is still streaming so an oversized response is never buffered in full. See
//! `internal/design/12-malware-fetcher.md` section 6.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::time::Instant;

use super::TransportAuth;
use super::guard::{GuardReject, HostResolver, Pinned};

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
    /// Independent timeout for the (blocking) DNS resolution step, applied by `guard::vet_async`
    /// so a slow/hostile resolver cannot stall an async worker or hang unbounded.
    pub dns_timeout: Duration,
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
    /// How the transport that delivered this body was authenticated. From `fetch_http_once` it
    /// covers only the hop that returned the body; `fetch_http` folds in every redirect before it.
    pub transport_auth: TransportAuth,
}

/// The outcome of one `fetch_http_once` call. `Redirect` is never followed here - the caller
/// re-vets the target through `guard::vet` before any further socket is opened, so a redirect
/// hop can never bypass the SSRF guard. Its `transport_auth` says how the response carrying the
/// `Location` was authenticated: a redirect an on-path party could rewrite can steer the fetch
/// anywhere, so it weakens whatever body the chain ends in.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpResult {
    Body(Fetched),
    Redirect {
        location: String,
        transport_auth: TransportAuth,
    },
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
    /// The hop's deadline passed: the independent `tokio::time::timeout_at` oracle fired, or a
    /// certificate-failure retry found no time left. In practice reqwest's own `.timeout()`
    /// already bounds the whole send+stream, so this is a defense-in-depth backstop, not the
    /// primary deadline.
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
/// built per attempt: attacker-controlled URLs never share a connection pool.
///
/// An https URL is fetched with its certificate verified against the system trust store, the
/// same verifier every other reqwest client in the workspace uses. Only if that attempt fails
/// because the certificate did not validate is the same pinned address, with the same SNI and
/// Host, fetched again without validation, and the result labeled [`TransportAuth::Unverified`]
/// with the validation error. Malware is routinely served behind self-signed or expired
/// certificates, so refusing would lose the sample; labeling keeps a body whose sender nothing
/// authenticated from reading like one whose sender was. Both attempts share one
/// `limits.total_timeout` deadline, so the retry never stretches the per-hop budget
/// `claim_lease` is sized from.
pub async fn fetch_http_once(
    pinned: &Pinned,
    url: &str,
    limits: &FetchLimits,
) -> Result<HttpResult, FetchError> {
    fetch_http_once_trusting(pinned, url, limits, &[]).await
}

/// [`fetch_http_once`] with `extra_roots` added to the system trust store, never replacing it, so
/// a test can reach the verified path with a CA it minted.
async fn fetch_http_once_trusting(
    pinned: &Pinned,
    url: &str,
    limits: &FetchLimits,
    extra_roots: &[reqwest::Certificate],
) -> Result<HttpResult, FetchError> {
    let parsed = check_host_pin(pinned, url)?;
    let hop = Hop {
        pinned,
        url,
        limits,
        deadline: Instant::now() + limits.total_timeout,
    };
    let verify = Certificates::Verify(extra_roots);

    if parsed.scheme() != "https" {
        return hop.attempt(verify, TransportAuth::Plaintext).await;
    }
    match hop.attempt(verify, TransportAuth::Verified).await {
        Err(err) => match certificate_validation_error(&err) {
            Some(error) => {
                let unverified = TransportAuth::Unverified { error };
                hop.attempt(Certificates::AcceptAny, unverified).await
            }
            None => Err(err),
        },
        verified => verified,
    }
}

/// How one attempt treats the server's certificate.
enum Certificates<'a> {
    /// Validate against the system trust store plus these extra roots.
    Verify(&'a [reqwest::Certificate]),
    /// Accept any certificate. Only ever the retry after a validation failure, whose result is
    /// labeled unverified.
    AcceptAny,
}

/// What every attempt at one hop shares, so a retry cannot reach a different address, send a
/// different SNI or Host, or run past the hop's deadline.
struct Hop<'a> {
    pinned: &'a Pinned,
    url: &'a str,
    limits: &'a FetchLimits,
    deadline: Instant,
}

impl Hop<'_> {
    /// One request, labeled `transport_auth`: how the caller knows this attempt's transport to be
    /// authenticated.
    async fn attempt(
        &self,
        certificates: Certificates<'_>,
        transport_auth: TransportAuth,
    ) -> Result<HttpResult, FetchError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(FetchError::Timeout);
        }
        let pin = SocketAddr::new(self.pinned.ip, self.pinned.port);
        let builder = reqwest::Client::builder()
            .resolve(&self.pinned.host, pin)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .http1_only()
            .connect_timeout(self.limits.connect_timeout)
            .read_timeout(self.limits.read_timeout)
            .timeout(remaining);
        let client = match certificates {
            Certificates::Verify(roots) => builder.tls_certs_merge(roots.iter().cloned()),
            Certificates::AcceptAny => builder.tls_danger_accept_invalid_certs(true),
        }
        .build()?;

        let request = fetch_once_inner(&client, self.url, self.limits, pin.ip(), transport_auth);
        match tokio::time::timeout_at(self.deadline, request).await {
            Ok(result) => result,
            Err(_) => Err(FetchError::Timeout),
        }
    }
}

/// The certificate-validation failure behind `err`, if that is why the attempt failed: the only
/// failure fetching again without validation can get past. Anything else (refused, reset, a peer
/// that does not speak TLS, a protocol error) would fail the same way again, so it is returned
/// as is rather than retried.
///
/// reqwest reports it as `reqwest::Error` -> hyper-util's connect error -> `io::Error` ->
/// `io::Error` -> `rustls::Error`. `io::Error::source()` skips the error it wraps and returns that
/// error's own source, which would step straight past the `rustls::Error`, so an `io::Error` layer
/// is descended with `get_ref` instead.
fn certificate_validation_error(err: &FetchError) -> Option<String> {
    let FetchError::Client(client) = err else {
        return None;
    };
    let mut layer: Option<&(dyn std::error::Error + 'static)> = Some(client);
    while let Some(e) = layer {
        if let Some(tls @ rustls::Error::InvalidCertificate(_)) = e.downcast_ref::<rustls::Error>()
        {
            return Some(tls.to_string());
        }
        layer = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => e.source(),
        };
    }
    None
}

/// Fail closed if `url`'s host (and, as secondary defense-in-depth, port) does not match
/// `pinned.host`/`pinned.port`. `ClientBuilder::resolve` in `Hop::attempt` only overrides DNS
/// for the exact host string it is given; a caller that ever passes a `url` whose host differs
/// from `pinned.host` would fall through to real DNS on the url's own host and connect off-pin,
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
///
/// Returns the parsed `url` so the caller reads its scheme from the same parse that was checked.
fn check_host_pin(pinned: &Pinned, url: &str) -> Result<url::Url, FetchError> {
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

    Ok(parsed)
}

async fn fetch_once_inner(
    client: &reqwest::Client,
    url: &str,
    limits: &FetchLimits,
    pinned_ip: IpAddr,
    transport_auth: TransportAuth,
) -> Result<HttpResult, FetchError> {
    let resp = client
        .get(url)
        .header(reqwest::header::USER_AGENT, &limits.user_agent)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await?;

    if resp.status().is_redirection() {
        return Ok(redirect_target(url, &resp, transport_auth));
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
            transport_auth,
        }))
    }
}

/// Resolve a 3xx response's `Location` header into an absolute URL, joining a relative header
/// value against the request URL per RFC 7231 7.1.2. A redirect status with no usable
/// `Location` carries no body and nothing to act on, so it reads as `Empty` rather than an error.
fn redirect_target(
    request_url: &str,
    resp: &reqwest::Response,
    transport_auth: TransportAuth,
) -> HttpResult {
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
    HttpResult::Redirect {
        location: resolved,
        transport_auth,
    }
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
    Redirect {
        location: String,
        transport_auth: TransportAuth,
    },
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
    resolver: std::sync::Arc<dyn HostResolver + Send + Sync>,
    limits: &'a FetchLimits,
}

impl HopFetcher for RealHopFetcher<'_> {
    async fn hop(&self, url: &str) -> Result<HopOutcome, FetchError> {
        let pinned = match super::guard::vet_async(
            url,
            self.own,
            std::sync::Arc::clone(&self.resolver),
            false,
            self.limits.dns_timeout,
        )
        .await
        {
            Ok(p) => p,
            Err(reject) => return Ok(HopOutcome::Rejected(reject)),
        };
        Ok(match fetch_http_once(&pinned, url, self.limits).await? {
            HttpResult::Body(fetched) => HopOutcome::Body(fetched),
            HttpResult::Redirect {
                location,
                transport_auth,
            } => HopOutcome::Redirect {
                location,
                transport_auth,
            },
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
/// `HopOutcome::Redirect`'s `location` is already an absolute URL (`redirect_target` joins a
/// relative `Location` against the request URL before `RealHopFetcher` ever sees it) - it becomes
/// the next hop's URL directly, never re-joined against the prior hop, since joining an
/// already-absolute URL again would corrupt it.
///
/// `max_hops` bounds redirects *followed*, not hops attempted: the initial hop is never
/// hop-budget-gated (only a `Redirect` response consumes budget), and hitting the bound on a
/// `Redirect` returns `TooManyHops` without ever fetching that redirect's target. A rejected hop
/// (initial or any redirect) captures zero bytes: `Rejected` short-circuits the loop before any
/// further hop - and therefore any further socket - is ever reached.
///
/// A captured body's `transport_auth` is folded over every redirect followed to reach it
/// ([`TransportAuth::followed_by`]), so a verified final hop reached through an unauthenticated
/// redirect is not recorded as verified.
async fn follow_redirects<H: HopFetcher>(
    start_url: &str,
    max_hops: u8,
    hop_fetcher: &H,
) -> Result<HttpOutcome, FetchError> {
    let mut current = start_url.to_string();
    let mut hops_left = max_hops;
    let mut redirects_auth: Option<TransportAuth> = None;

    loop {
        match hop_fetcher.hop(&current).await? {
            HopOutcome::Body(mut fetched) => {
                if let Some(path) = redirects_auth {
                    fetched.transport_auth = path.followed_by(fetched.transport_auth);
                }
                return Ok(HttpOutcome::Captured(fetched));
            }
            HopOutcome::Rejected(reject) => return Ok(HttpOutcome::Rejected(reject)),
            HopOutcome::Empty => return Ok(HttpOutcome::Empty),
            HopOutcome::TooBig => return Ok(HttpOutcome::TooBig),
            HopOutcome::Redirect {
                location,
                transport_auth,
            } => {
                if hops_left == 0 {
                    return Ok(HttpOutcome::TooManyHops);
                }
                hops_left -= 1;
                redirects_auth = Some(match redirects_auth {
                    Some(path) => path.followed_by(transport_auth),
                    None => transport_auth,
                });
                current = location;
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
    resolver: std::sync::Arc<dyn HostResolver + Send + Sync>,
    limits: &FetchLimits,
    max_hops: u8,
) -> Result<HttpOutcome, FetchError> {
    let hop_fetcher = RealHopFetcher {
        own,
        resolver,
        limits,
    };
    follow_redirects(url, max_hops, &hop_fetcher).await
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

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
            dns_timeout: Duration::from_secs(5),
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

        assert_eq!(
            result,
            HttpResult::Redirect {
                location: "http://x/y".to_string(),
                transport_auth: TransportAuth::Plaintext,
            }
        );
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
            HttpResult::Redirect {
                location: format!("http://127.0.0.1:{port}/next/path"),
                transport_auth: TransportAuth::Plaintext,
            }
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
            std::sync::Arc::new(resolver),
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

        let result = fetch_http(
            "http://attacker.test/",
            &own,
            std::sync::Arc::new(resolver),
            &limits(1024),
            0,
        )
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
        fetched_over(tag, TransportAuth::Verified)
    }

    fn fetched_over(tag: &str, transport_auth: TransportAuth) -> Fetched {
        Fetched {
            bytes: tag.as_bytes().to_vec(),
            content_type: None,
            final_url: tag.to_string(),
            // Arbitrary and irrelevant to what these redirect-loop tests exercise (control flow,
            // not pinned_ip's value) - fixed so every call produces an equal Fetched.
            pinned_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            transport_auth,
        }
    }

    fn redirect(location: &str) -> HopOutcome {
        redirect_over(location, TransportAuth::Verified)
    }

    fn redirect_over(location: &str, transport_auth: TransportAuth) -> HopOutcome {
        HopOutcome::Redirect {
            location: location.to_string(),
            transport_auth,
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
            ("a", redirect("b")),
            ("b", redirect("c")),
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
            ("h0", redirect("h1")),
            ("h1", redirect("h2")),
            ("h2", redirect("h3")),
            ("h3", redirect("h4")),
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
            ("a", redirect("b")),
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

    // --- transport authentication over a redirect chain (audit P-08) ---

    #[tokio::test]
    async fn loop_a_plaintext_redirect_leaves_a_verified_body_unauthenticated() {
        // An on-path party can rewrite an http 302 to any https host holding a valid certificate,
        // so a verified final hop proves nothing about where the chain was sent.
        let fetcher = MockHopFetcher::new([
            ("a", redirect_over("b", TransportAuth::Plaintext)),
            ("b", HopOutcome::Body(fetched("b-body"))),
        ]);

        let result = follow_redirects("a", 3, &fetcher).await.unwrap();

        assert_eq!(
            result,
            HttpOutcome::Captured(fetched_over("b-body", TransportAuth::Plaintext))
        );
    }

    #[tokio::test]
    async fn loop_a_body_hop_that_failed_its_certificate_stays_unverified() {
        let failed = TransportAuth::Unverified {
            error: "body hop".into(),
        };
        let fetcher = MockHopFetcher::new([
            ("a", redirect("b")),
            (
                "b",
                HopOutcome::Body(fetched_over("b-body", failed.clone())),
            ),
        ]);

        let result = follow_redirects("a", 3, &fetcher).await.unwrap();

        assert_eq!(
            result,
            HttpOutcome::Captured(fetched_over("b-body", failed))
        );
    }

    #[tokio::test]
    async fn loop_keeps_the_first_certificate_failure_over_later_hops() {
        let first = TransportAuth::Unverified {
            error: "first".into(),
        };
        let fetcher = MockHopFetcher::new([
            ("a", redirect_over("b", first.clone())),
            ("b", redirect_over("c", TransportAuth::Plaintext)),
            (
                "c",
                HopOutcome::Body(fetched_over(
                    "c-body",
                    TransportAuth::Unverified {
                        error: "last".into(),
                    },
                )),
            ),
        ]);

        let result = follow_redirects("a", 3, &fetcher).await.unwrap();

        assert_eq!(result, HttpOutcome::Captured(fetched_over("c-body", first)));
    }

    // --- https against a real TLS server: verify first, then without validation only when the
    // certificate is what failed ---

    /// Reserved (RFC 2606), so a client that ever re-resolved it through DNS would fail rather than
    /// reach the test server: only the pin can.
    const TLS_HOST: &str = "malware.test";

    const TLS_BODY: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nmalware bytes";
    const TLS_REDIRECT: &[u8] =
        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    fn tls_pinned(port: u16) -> Pinned {
        Pinned {
            host: TLS_HOST.to_string(),
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            scheme: Scheme::Https,
        }
    }

    fn tls_url(port: u16) -> String {
        format!("https://{TLS_HOST}:{port}/x")
    }

    struct TestCa {
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
        root: reqwest::Certificate,
    }

    fn mint_ca() -> TestCa {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "propolis fetch test ca");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let root = reqwest::Certificate::from_der(cert.der()).unwrap();
        TestCa { params, key, root }
    }

    /// A server certificate for `name`, signed by `ca`, or self-signed without one.
    fn mint_server_cert(
        name: &str,
        ca: Option<&TestCa>,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        let cert = match ca {
            Some(ca) => params
                .signed_by(&key, &rcgen::Issuer::from_params(&ca.params, &ca.key))
                .unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        (
            cert.der().clone(),
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
    }

    /// One connection to a [`spawn_tls`] server, as the server saw it.
    #[derive(Debug, Clone)]
    struct TlsConn {
        sni: Option<String>,
        handshake_completed: bool,
        host_header: Option<String>,
    }

    #[derive(Clone, Copy, Default)]
    struct Stall {
        /// Before the first connection's ClientHello is read.
        first_handshake: Duration,
        /// Before any request is answered.
        response: Duration,
    }

    /// A blocking HTTPS server on 127.0.0.1 presenting `cert` and answering every request with the
    /// raw `response`, logging each connection it accepts.
    fn spawn_tls(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        response: &'static [u8],
        stall: Stall,
    ) -> (u16, Arc<Mutex<Vec<TlsConn>>>) {
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let server_log = Arc::clone(&log);
        std::thread::spawn(move || {
            for (i, tcp) in listener.incoming().enumerate() {
                let Ok(tcp) = tcp else { continue };
                let (config, log) = (Arc::clone(&config), Arc::clone(&server_log));
                let handshake_delay = if i == 0 {
                    stall.first_handshake
                } else {
                    Duration::ZERO
                };
                std::thread::spawn(move || {
                    serve_tls(tcp, config, handshake_delay, stall.response, response, &log)
                });
            }
        });
        (port, log)
    }

    fn serve_tls(
        mut tcp: std::net::TcpStream,
        config: Arc<rustls::ServerConfig>,
        handshake_delay: Duration,
        response_delay: Duration,
        response: &[u8],
        log: &Mutex<Vec<TlsConn>>,
    ) {
        std::thread::sleep(handshake_delay);
        let mut conn = rustls::ServerConnection::new(config).unwrap();
        while conn.is_handshaking() {
            if conn.complete_io(&mut tcp).is_err() {
                break;
            }
        }
        let mut seen = TlsConn {
            sni: conn.server_name().map(str::to_string),
            handshake_completed: !conn.is_handshaking(),
            host_header: None,
        };
        if !seen.handshake_completed {
            log.lock().unwrap().push(seen);
            return;
        }

        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => request.extend_from_slice(&buf[..n]),
            }
        }
        seen.host_header = String::from_utf8_lossy(&request).lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_string())
        });
        log.lock().unwrap().push(seen);

        std::thread::sleep(response_delay);
        let _ = stream.write_all(response);
        stream.conn.send_close_notify();
        let _ = stream.flush();
    }

    /// The server's log once a failed handshake's entry has had time to land: the server writes
    /// it on its own thread after the client has already moved on to its next attempt.
    async fn settled(log: &Mutex<Vec<TlsConn>>) -> Vec<TlsConn> {
        tokio::time::sleep(Duration::from_millis(200)).await;
        log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn https_with_a_valid_certificate_is_captured_verified_in_one_attempt() {
        let ca = mint_ca();
        let (cert, key) = mint_server_cert(TLS_HOST, Some(&ca));
        let (port, log) = spawn_tls(cert, key, TLS_BODY, Stall::default());

        let result = fetch_http_once_trusting(
            &tls_pinned(port),
            &tls_url(port),
            &limits(1024),
            std::slice::from_ref(&ca.root),
        )
        .await
        .unwrap();

        match result {
            HttpResult::Body(f) => {
                assert_eq!(f.bytes, b"malware bytes");
                assert_eq!(f.transport_auth, TransportAuth::Verified);
            }
            other => panic!("expected Body, got {other:?}"),
        }
        let conns = settled(&log).await;
        assert_eq!(conns.len(), 1, "a verified fetch is one attempt: {conns:?}");
    }

    #[tokio::test]
    async fn https_with_a_self_signed_certificate_is_captured_unverified_from_the_same_pin() {
        let (cert, key) = mint_server_cert(TLS_HOST, None);
        let (port, log) = spawn_tls(cert, key, TLS_BODY, Stall::default());
        let pinned = tls_pinned(port);

        let result = fetch_http_once(&pinned, &tls_url(port), &limits(1024))
            .await
            .unwrap();

        let HttpResult::Body(f) = result else {
            panic!("expected Body, got {result:?}");
        };
        assert_eq!(f.bytes, b"malware bytes");
        assert_eq!(f.pinned_ip, pinned.ip);
        match &f.transport_auth {
            TransportAuth::Unverified { error } => assert!(
                error.contains("invalid peer certificate") && error.contains("UnknownIssuer"),
                "the recorded error must be the validation failure, got {error:?}"
            ),
            other => panic!("a self-signed body must be recorded unverified, got {other:?}"),
        }

        // Only the pin can reach this listener (the name is reserved and never resolves), so two
        // connections logged here are two attempts at the same pinned address.
        let conns = settled(&log).await;
        assert_eq!(
            conns.len(),
            2,
            "verifying attempt then one retry: {conns:?}"
        );
        assert_eq!(
            conns.iter().filter(|c| c.handshake_completed).count(),
            1,
            "only the retry may complete a handshake: {conns:?}"
        );
        for c in &conns {
            assert_eq!(
                c.sni.as_deref(),
                Some(TLS_HOST),
                "same SNI on both: {conns:?}"
            );
        }
        let served = conns.iter().find(|c| c.handshake_completed).unwrap();
        assert_eq!(served.host_header, Some(format!("{TLS_HOST}:{port}")));
    }

    #[tokio::test]
    async fn a_trusted_certificate_for_another_name_is_unverified() {
        let ca = mint_ca();
        let (cert, key) = mint_server_cert("other.test", Some(&ca));
        let (port, _log) = spawn_tls(cert, key, TLS_BODY, Stall::default());

        let result = fetch_http_once_trusting(
            &tls_pinned(port),
            &tls_url(port),
            &limits(1024),
            std::slice::from_ref(&ca.root),
        )
        .await
        .unwrap();

        match result {
            HttpResult::Body(Fetched {
                transport_auth: TransportAuth::Unverified { error },
                ..
            }) => assert!(
                error.contains("not valid for name"),
                "a chain that verifies for a different host is still a failed validation: {error:?}"
            ),
            other => panic!("expected an unverified Body, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_tls_failure_that_is_not_about_the_certificate_is_not_retried() {
        // Answers the ClientHello with plaintext HTTP: the handshake fails on the record layer,
        // and fetching again without certificate validation would fail the same way.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        std::thread::spawn(move || {
            for mut tcp in listener.incoming().flatten() {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = tcp.read(&mut buf);
                let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            }
        });

        let result = fetch_http_once(&tls_pinned(port), &tls_url(port), &limits(1024)).await;

        let err = match result {
            Err(err @ FetchError::Client(_)) => err,
            other => panic!("expected a client error, got {other:?}"),
        };
        assert_eq!(certificate_validation_error(&err), None);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "must not be retried");
    }

    #[tokio::test]
    async fn the_retry_shares_the_hop_deadline_instead_of_starting_a_new_one() {
        // The verifying attempt is held ~700 ms before the self-signed certificate is presented,
        // then the retry meets a server that never answers. Sharing the 1 s deadline ends the hop
        // near 1 s; a fresh deadline for the retry would run to ~1.7 s, past what `claim_lease`
        // budgets per hop.
        let (cert, key) = mint_server_cert(TLS_HOST, None);
        let stall = Stall {
            first_handshake: Duration::from_millis(700),
            response: Duration::from_secs(5),
        };
        let (port, log) = spawn_tls(cert, key, TLS_BODY, stall);
        let mut limits = limits(1024);
        limits.total_timeout = Duration::from_secs(1);

        let started = Instant::now();
        let result = fetch_http_once(&tls_pinned(port), &tls_url(port), &limits).await;
        let elapsed = started.elapsed();

        assert!(
            matches!(&result, Err(FetchError::Timeout))
                || matches!(&result, Err(FetchError::Client(e)) if e.is_timeout()),
            "expected the retry to time out, got {result:?}"
        );
        let conns = settled(&log).await;
        assert_eq!(
            conns.len(),
            2,
            "the retry must have been attempted: {conns:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1400),
            "the hop took {elapsed:?}; both attempts must fit in one 1 s budget"
        );
    }

    #[tokio::test]
    async fn a_redirect_behind_a_failed_certificate_carries_that_state() {
        let (cert, key) = mint_server_cert(TLS_HOST, None);
        let (port, _log) = spawn_tls(cert, key, TLS_REDIRECT, Stall::default());

        let result = fetch_http_once(&tls_pinned(port), &tls_url(port), &limits(1024))
            .await
            .unwrap();

        match result {
            HttpResult::Redirect {
                location,
                transport_auth: TransportAuth::Unverified { .. },
            } => assert_eq!(location, format!("https://{TLS_HOST}:{port}/next")),
            other => panic!("expected an unverified Redirect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_plain_http_body_is_recorded_as_plaintext() {
        let app = Router::new().route("/", get(|| async { "malware bytes" }));
        let port = spawn(app).await;

        let result = fetch_http_once(
            &pinned(port),
            &format!("http://127.0.0.1:{port}/"),
            &limits(1024),
        )
        .await
        .unwrap();

        match result {
            HttpResult::Body(f) => assert_eq!(f.transport_auth, TransportAuth::Plaintext),
            other => panic!("expected Body, got {other:?}"),
        }
    }
}
