//! TCP and UDP listener lifecycle: bind the configured address, run the accept/recv loop, and
//! hand each connection or datagram to the sensor's own handler. See "Listener lifecycle" and
//! "Bounded per-connection resources" in `internal/design/02-sensor-framework.md`.
//!
//! WAN resolution happens inside each sensor's handler, not here: the handler receives the raw
//! `TcpStream`/peer (TCP) or the datagram bytes/peer (UDP) and calls `WanResolver` itself against
//! `local_addr()` (see `wan.rs`), so it can also apply `ConnectionBounds`' `read_timeout` and
//! `max_captured_bytes` to its own reads (see `bounds.rs`'s module doc for why the split sits
//! there). This module owns only what is identical for every sensor regardless of protocol: the
//! loop, panic isolation at the connection/datagram boundary, the concurrency and duration
//! bounds, and never sending a UDP response.
//!
//! A per-port bind failure is non-fatal at the sensor level, but that property is realized by the
//! *caller*: `run_tcp_listener`/`run_udp_listener` each bind exactly one address and return `Err`
//! on failure rather than panicking, so a sensor binding several configured ports in a loop and
//! logging (not propagating) an individual failure is what makes one bad port non-fatal to the
//! rest - see the design doc's "Listener lifecycle" bullet.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::admission::PerSourceLimiter;
use crate::bounds::ConnectionBounds;

/// Maximum size of a single UDP datagram (the IPv4/IPv6 payload ceiling), so `recv_from` never
/// silently truncates a legitimate maximum-size datagram for lack of buffer space.
const UDP_MAX_DATAGRAM: usize = 65536;

/// Backoff between retries after a transient accept/recv error, so a persistent failure (e.g. the
/// process is out of file descriptors) degrades to a slow retry loop instead of spinning a CPU
/// core at 100% retrying an error that will not clear itself instantly.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(20);

/// The error a sensor logs when a listener fails to start after its config validated: names the
/// address and the OS error, keeping the error's kind. Every sensor logs it as
/// `<sensor>: <this error>; refusing to start` (or `; skipping ...` where one failed address is
/// not fatal), so one troubleshooting entry covers every sensor.
pub fn listener_start_error(addr: SocketAddr, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!("cannot start listener on {addr}: {error}"),
    )
}

/// Bind one TCP address and run its accept loop as a spawned task, returning immediately with the
/// actual bound address (useful for an ephemeral `:0` port, as every test in
/// `tests/listener_integration.rs` relies on) and a `JoinHandle` the caller can `.abort()` to stop
/// accepting. A bind failure on this one address is returned as `Err` rather than panicking; see
/// the module doc for why that alone is what makes one bad port non-fatal to a sensor as a whole.
///
/// `handler` receives the raw, unwrapped `TcpStream`, the peer address - not a WAN-resolved
/// address, not a bounded reader (see the module doc and `bounds.rs`) - and a `uuid::Uuid` v7
/// session id minted fresh for this connection, so every event a handler emits over the
/// connection's lifetime can be stamped with a stable, time-ordered identifier. It is called once
/// per accepted connection.
///
/// `per_source_cap`: `Some(n)` admits at most `n` concurrent connections per source IP (IPv4-mapped
/// IPv6 normalized), checked before the global permit so a refused source burns nothing global;
/// `None` disables it (the gateway, whose one trusted shipper opens many connections from one IP).
/// Sensors pass `Some(default_per_source_cap(bounds.max_concurrent))`.
///
/// Two bounds this function enforces directly, without the handler's cooperation:
/// - `max_concurrent`: a `tokio::sync::Semaphore` seeded with `bounds.max_concurrent` permits.
///   Accepting a connection while every permit is held refuses it immediately (the stream is
///   dropped, closing the socket) rather than queuing it - an accepted-but-waiting connection
///   would itself be the unbounded resource this cap exists to prevent.
/// - `max_duration`: the handler future runs inside `tokio::time::timeout`; once it elapses, the
///   future - and everything it owns, the connection included - is dropped in place. Wrapping the
///   future itself (rather than, say, racing a timer against the spawned task's `JoinHandle`)
///   matters: dropping a `JoinHandle` does not abort the task it refers to, so only wrapping the
///   future directly actually reclaims the connection when the bound is hit.
///
/// A handler that panics is isolated at the connection boundary and never reaches this function's
/// caller or any other in-flight connection: tokio's own task harness wraps every spawned task's
/// poll in `std::panic::catch_unwind` and reports the panic through that task's `JoinHandle`
/// rather than unwinding into the scheduler or any other task (`tokio::runtime::Builder`'s
/// `unhandled_panic` doc: "an unhandled panic ... has no impact on the runtime's execution. The
/// panic's error value is forwarded to the task's `JoinHandle` and all other spawned tasks
/// continue running" - confirmed against `tokio` 1.53.1's own `runtime/task/harness.rs`, which
/// wraps every poll in `panic::catch_unwind`). This function spawns the handler in its own task
/// and inspects that `JoinHandle`'s result purely to log the outcome, never to decide whether to
/// keep accepting - the accept loop never awaits a connection's outcome at all.
pub async fn run_tcp_listener<F, Fut>(
    addr: SocketAddr,
    bounds: ConnectionBounds,
    per_source_cap: Option<u32>,
    handler: F,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)>
where
    F: Fn(TcpStream, SocketAddr, uuid::Uuid) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;
    let semaphore = Arc::new(Semaphore::new(bounds.max_concurrent as usize));
    let max_duration = bounds.max_duration;
    let limiter = per_source_cap.map(PerSourceLimiter::new);
    let mut source_refused: u64 = 0;

    let accept_handle = tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(local = %bound_addr, error = %e, "tcp accept error; retrying");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };

            // Per-source check first so a refused source never burns a global permit.
            let source_guard = match &limiter {
                Some(limiter) => match limiter.try_admit(peer) {
                    Some(guard) => Some(guard),
                    None => {
                        source_refused += 1;
                        // Power-of-two totals: a flood must not fill the log it is probing.
                        if source_refused.is_power_of_two() {
                            tracing::warn!(
                                refused_total = source_refused,
                                %peer,
                                local = %bound_addr,
                                "per-source cap reached; refusing connection"
                            );
                        }
                        drop(stream);
                        continue;
                    }
                },
                None => None,
            };

            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!(
                        %peer,
                        local = %bound_addr,
                        "max_concurrent reached; refusing connection"
                    );
                    drop(stream);
                    continue;
                }
            };

            let session_id = uuid::Uuid::now_v7();
            let fut = handler(stream, peer, session_id);
            tokio::spawn(async move {
                // Held for the connection's whole lifetime; dropped (releasing the permit and the
                // per-source slot) when this outer task ends, which happens only once the inner
                // task below has already finished one way or another.
                let _permit = permit;
                let _source_guard = source_guard;
                let inner =
                    tokio::spawn(async move { tokio::time::timeout(max_duration, fut).await });
                match inner.await {
                    Ok(Ok(())) => {}
                    Ok(Err(_elapsed)) => {
                        tracing::warn!(%peer, "handler exceeded max_duration; connection dropped");
                    }
                    Err(join_err) if join_err.is_panic() => {
                        tracing::error!(
                            %peer,
                            error = %join_err,
                            "sensor handler panicked; connection dropped"
                        );
                    }
                    Err(join_err) => {
                        tracing::debug!(%peer, "handler task did not complete: {join_err}");
                    }
                }
            });
        }
    });

    Ok((bound_addr, accept_handle))
}

/// Bind one UDP address and run its receive loop as a spawned task, returning immediately with
/// the actual bound address and a `JoinHandle` the caller can `.abort()`. Mirrors
/// `run_tcp_listener`'s bind-failure and panic-isolation behavior for datagrams; see its doc for
/// both.
///
/// There is no `send_to` call anywhere in this function's body, and the socket it owns is moved
/// into the receive loop alone - `handler` is never given a way to reach it either, since it
/// receives only the datagram bytes and the peer address, not the socket. A UDP sensor therefore
/// cannot answer a probe even by mistake: the capability to respond does not exist in this
/// listener, which is the construction guarantee the design doc's "passive-only" invariant asks
/// for (see `internal/design/02-sensor-framework.md`'s "Catch-all listener": "UDP is log-only ...
/// sends nothing back, by construction").
///
/// `handler` is called once per received datagram, each in its own spawned task (not inline in the
/// receive loop), for the same two reasons `run_tcp_listener` isolates each connection: a
/// panicking handler must not crash the loop that is still supposed to keep draining the socket,
/// and a slow handler must not delay the next `recv_from` call (a UDP socket's kernel receive
/// buffer is finite; not draining it promptly risks silently dropped datagrams under load, the
/// same failure shape the design doc's off-response-path capture hand-off exists to avoid on the
/// emit side).
pub async fn run_udp_listener<F, Fut>(
    addr: SocketAddr,
    bounds: ConnectionBounds,
    per_source_cap: Option<u32>,
    handler: F,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)>
where
    F: Fn(Vec<u8>, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let socket = UdpSocket::bind(addr).await?;
    let bound_addr = socket.local_addr()?;
    // Bound in-flight datagram handlers and their runtime, mirroring run_tcp_listener: without this
    // a datagram flood spawns unbounded tasks (each datagram spawns two) and a wedged handler runs
    // forever. A datagram that cannot get a permit is dropped - UDP is lossy anyway, and the socket
    // keeps draining so its kernel receive buffer does not back up.
    let semaphore = Arc::new(Semaphore::new(bounds.max_concurrent as usize));
    let max_duration = bounds.max_duration;
    let limiter = per_source_cap.map(PerSourceLimiter::new);
    let mut source_refused: u64 = 0;

    let recv_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(local = %bound_addr, error = %e, "udp recv error; retrying");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            let source_guard = match &limiter {
                Some(limiter) => match limiter.try_admit(peer) {
                    Some(guard) => Some(guard),
                    None => {
                        source_refused += 1;
                        if source_refused.is_power_of_two() {
                            tracing::warn!(
                                refused_total = source_refused,
                                local = %bound_addr, %peer,
                                "udp per-source cap reached; dropping datagram"
                            );
                        }
                        continue;
                    }
                },
                None => None,
            };
            let permit = match semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        local = %bound_addr, %peer,
                        "udp max_concurrent reached; dropping datagram"
                    );
                    continue;
                }
            };
            let data = buf[..n].to_vec();
            let fut = handler(data, peer);
            tokio::spawn(async move {
                let _permit = permit; // released when this handler task ends
                let _source_guard = source_guard;
                let inner =
                    tokio::spawn(async move { tokio::time::timeout(max_duration, fut).await });
                match inner.await {
                    Ok(_) => {}
                    Err(join_err) if join_err.is_panic() => {
                        tracing::error!(%peer, error = %join_err, "sensor udp handler panicked");
                    }
                    Err(join_err) => {
                        tracing::debug!(%peer, "udp handler task did not complete: {join_err}");
                    }
                }
            });
        }
    });

    Ok((bound_addr, recv_handle))
}

/// Resolves when the process receives SIGINT (`Ctrl+C`) or, on Unix, SIGTERM (what `systemctl
/// stop` sends - not SIGINT - to the hardened service units `internal/design/02-sensor-framework.
/// md`'s "Isolation and deployment" section ships). A sensor's `main.rs` races this against
/// continued serving, then aborts every listener `JoinHandle` it is holding. A sensor that has a
/// capture worker then calls `CaptureHandoff::drain` so already-queued captures are written before
/// the process exits. In-flight connection tasks are NOT awaited: the runtime cancels them at
/// teardown, so a capture a connection had not yet submitted is lost (see `handoff.rs`'s module
/// doc). This function's only job is to resolve at the right time.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "failed to install SIGTERM handler; shutdown_signal now waits on SIGINT only"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Normalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) down to its plain IPv4 form, port
/// preserved. A dual-stack listener bound to `[::]` reports an IPv4 client's `local_addr()`/
/// `peer_addr()` in this mapped form; left unnormalized, a `WanResolver` map keyed on plain IPv4
/// addresses silently never matches it, since `HashMap<IpAddr, IpAddr>` treats
/// `IpAddr::V4(a.b.c.d)` and `IpAddr::V6(::ffff:a.b.c.d)` as unequal keys even though they name the
/// same host (this is the deferred item recorded against Task 3). A genuine IPv6 address outside
/// the `::ffff:0:0/96` mapped range, and any address already IPv4, pass through unchanged.
///
/// This listener never calls it itself (it hands the handler the raw, un-normalized stream/peer -
/// see the module doc), so it closes the deferred item only as far as this module can own it:
/// every sensor handler that calls `WanResolver::resolve` or stamps `source_ip` from
/// `TcpStream::local_addr()`/`peer_addr()` (or the UDP equivalent's `peer` argument) must route
/// the address through this first, or the mapping gap this function fixes persists in practice
/// despite the fix existing. See the task report's Concerns section.
pub fn normalize_dual_stack(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dual_stack_unmaps_ipv4_mapped_ipv6() {
        let addr: SocketAddr = "[::ffff:203.0.113.7]:4242".parse().unwrap();
        assert_eq!(
            normalize_dual_stack(addr),
            "203.0.113.7:4242".parse().unwrap()
        );
    }

    #[test]
    fn normalize_dual_stack_leaves_plain_ipv4_unchanged() {
        let addr: SocketAddr = "203.0.113.7:4242".parse().unwrap();
        assert_eq!(normalize_dual_stack(addr), addr);
    }

    #[test]
    fn normalize_dual_stack_leaves_genuine_ipv6_unchanged() {
        // 2001:db8::1 is not in the ::ffff:0:0/96 mapped range - must pass through untouched.
        let addr: SocketAddr = "[2001:db8::1]:4242".parse().unwrap();
        assert_eq!(normalize_dual_stack(addr), addr);
    }

    #[tokio::test]
    async fn listener_start_error_names_the_address_and_the_os_error() {
        let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = taken.local_addr().unwrap();
        let os_error = TcpListener::bind(addr).await.unwrap_err();
        let os_text = os_error.to_string();
        let error = listener_start_error(addr, os_error);
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(
            error.to_string(),
            format!("cannot start listener on {addr}: {os_text}")
        );
    }
}
