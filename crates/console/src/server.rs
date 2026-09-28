//! The console's HTTP accept loop, with the connection-level bounds `axum::serve` does not offer.
//!
//! `axum::serve` gives hyper no timer, and hyper arms its header-read timeout only when it has
//! one, so a client that opens a connection and sends headers a byte at a time - or sends nothing -
//! holds that connection indefinitely. It also accepts without limit. The console is meant to sit
//! on loopback or behind a TLS proxy that enforces its own limits, but it must not depend on that
//! proxy existing.
//!
//! This loop serves HTTP/1.1 only. hyper-util's auto (HTTP/1 + HTTP/2) builder first waits for the
//! protocol preface with no timeout of its own, which would reopen the same hole before any HTTP/1
//! timeout applies, and nothing in the console needs HTTP/2.
//!
//! Bounds ([`ServeLimits`]):
//! - at most `max_connections` at once; a connection accepted past that is closed immediately
//!   rather than queued, since a queued socket is itself the resource being capped;
//! - `header_read_timeout` to deliver a request's headers. hyper re-arms it whenever the
//!   connection waits for its next request, so an idle keep-alive connection is closed too;
//! - `body_read_timeout` and `max_body_bytes` for the body, enforced before the handler runs.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tower::ServiceExt;

/// Connection-level limits for [`serve`].
#[derive(Debug, Clone, Copy)]
pub struct ServeLimits {
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub body_read_timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for ServeLimits {
    /// Sized for one operator's browser plus a scraper: a browser opens about six connections per
    /// origin, so 64 leaves room for several tabs and their polling panels. Ten seconds is far
    /// longer than any real client takes to send headers or a form body. 2 MiB is axum's own
    /// default body limit, which the console relied on before this loop existed.
    fn default() -> Self {
        Self {
            max_connections: 64,
            header_read_timeout: Duration::from_secs(10),
            body_read_timeout: Duration::from_secs(10),
            max_body_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Counters for the connection bounds, exported by `/metrics`. One console server runs per
/// process, so these are process-wide.
#[derive(Debug, Default)]
pub struct ServeStats {
    /// Connections closed on accept because `max_connections` were already open.
    pub connections_shed: AtomicU64,
    /// Requests answered 408 because the body did not arrive within `body_read_timeout`.
    pub body_timeouts: AtomicU64,
}

pub static STATS: ServeStats = ServeStats {
    connections_shed: AtomicU64::new(0),
    body_timeouts: AtomicU64::new(0),
};

/// Serve `router` on `listener` until `shutdown` resolves; then stop accepting, ask every open
/// connection to finish its in-flight request, and wait up to `grace` for them to close. The
/// peer address reaches handlers as `ConnectInfo<SocketAddr>`, as it did under
/// `into_make_service_with_connect_info`.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: ServeLimits,
    shutdown: impl Future<Output = ()>,
    grace: Duration,
) {
    let router = router.layer(axum::middleware::from_fn_with_state(limits, bound_body));
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(e) => {
                    // Out of descriptors and similar: back off instead of spinning on the error.
                    tracing::warn!(error = %e, "console: accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };

        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            STATS.connections_shed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, limit = limits.max_connections, "console: connection limit reached, closing new connection");
            drop(stream);
            continue;
        };

        let service = TowerToHyperService::new(router.clone().map_request(
            move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                req
            },
        ));
        let mut stop_rx = stop_rx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut builder = hyper::server::conn::http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read_timeout);
            let mut conn = std::pin::pin!(builder.serve_connection(TokioIo::new(stream), service));
            let mut stopping = false;
            loop {
                tokio::select! {
                    result = conn.as_mut() => {
                        if let Err(e) = result {
                            tracing::debug!(%peer, error = %e, "console: connection closed with an error");
                        }
                        break;
                    }
                    changed = stop_rx.changed(), if !stopping => {
                        if changed.is_err() || *stop_rx.borrow() {
                            stopping = true;
                            conn.as_mut().graceful_shutdown();
                        }
                    }
                }
            }
        });
    }

    let _ = stop_tx.send(true);
    // Every open connection holds one permit; getting all of them back means all have closed.
    let all = u32::try_from(limits.max_connections).unwrap_or(u32::MAX);
    if tokio::time::timeout(grace, permits.acquire_many(all))
        .await
        .is_err()
    {
        tracing::warn!("console: connections still open after the shutdown grace period");
    }
}

/// Reads the whole request body before the handler runs, within `body_read_timeout` and
/// `max_body_bytes`. A handler's own extractor would otherwise read it at whatever pace the client
/// chooses, bounded only by the connection closing. Every console request body is a small form,
/// so buffering it costs nothing, and a GET's empty body completes at once.
async fn bound_body(
    axum::extract::State(limits): axum::extract::State<ServeLimits>,
    req: Request,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();
    match read_body_within(body, limits.body_read_timeout, limits.max_body_bytes).await {
        Ok(bytes) => {
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await
        }
        Err(BodyError::TimedOut) => {
            STATS.body_timeouts.fetch_add(1, Ordering::Relaxed);
            (
                StatusCode::REQUEST_TIMEOUT,
                "request body not received in time",
            )
                .into_response()
        }
        Err(BodyError::TooLarge) => {
            (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response()
        }
        Err(BodyError::Unreadable) => {
            (StatusCode::BAD_REQUEST, "request body unreadable").into_response()
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum BodyError {
    TimedOut,
    TooLarge,
    Unreadable,
}

async fn read_body_within(
    body: Body,
    timeout: Duration,
    limit: usize,
) -> Result<axum::body::Bytes, BodyError> {
    match tokio::time::timeout(timeout, axum::body::to_bytes(body, limit)).await {
        Err(_) => Err(BodyError::TimedOut),
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(e)) => {
            let too_large = std::error::Error::source(&e)
                .is_some_and(|s| s.is::<http_body_util::LengthLimitError>());
            Err(if too_large {
                BodyError::TooLarge
            } else {
                BodyError::Unreadable
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_body_within_bounds_is_returned_whole() {
        let bytes = read_body_within(Body::from("a=1&b=2"), Duration::from_secs(1), 64)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"a=1&b=2");
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_too_large_not_unreadable() {
        let err = read_body_within(Body::from(vec![b'x'; 65]), Duration::from_secs(1), 64)
            .await
            .unwrap_err();
        assert_eq!(err, BodyError::TooLarge);
    }

    #[tokio::test]
    async fn a_body_that_never_finishes_times_out() {
        let (_tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(1);
        let stalled = Body::from_stream(tokio_stream_from(rx));
        let err = read_body_within(stalled, Duration::from_millis(50), 64)
            .await
            .unwrap_err();
        assert_eq!(err, BodyError::TimedOut);
    }

    fn tokio_stream_from(
        mut rx: tokio::sync::mpsc::Receiver<Result<axum::body::Bytes, std::io::Error>>,
    ) -> impl futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
        futures::stream::poll_fn(move |cx| rx.poll_recv(cx))
    }
}
