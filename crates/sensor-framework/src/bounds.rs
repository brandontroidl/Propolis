//! Per-connection resource bounds: the single definition of every numeric bound a sensor
//! connection is held to. See "Bounded per-connection resources" in
//! `internal/design/02-sensor-framework.md`: "these bounds are enforced by the framework, not
//! left to each handler." `run_tcp_listener` (see `listener.rs`) enforces `max_duration` and
//! `max_concurrent` directly, without the handler's cooperation. It cannot enforce
//! `read_timeout`, `idle_timeout`, or `max_captured_bytes` the same way: the listener hands the
//! handler the raw `TcpStream` so the handler can resolve WAN attribution itself (see the
//! `listener` module doc), and once the stream has been handed over there is nothing left for the
//! listener to intercept individual reads through. Those three fields are still defined here, as
//! the framework's one source of truth for the *values* - a sensor's own read loop is built
//! against this same `ConnectionBounds`, not a second set of numbers it invents itself.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ConnectionBounds {
    /// Applied by the handler around each individual read from the stream (see the module doc:
    /// the listener cannot intercept reads it does not perform itself).
    pub read_timeout: Duration,
    /// The maximum gap between successive reads before a session is treated as idle and dropped;
    /// like `read_timeout`, applied by the handler's own read loop.
    pub idle_timeout: Duration,
    /// Enforced by `run_tcp_listener`: the handler future runs inside `tokio::time::timeout` with
    /// this duration. Once it elapses the future - and everything it owns, the connection
    /// included - is dropped in place.
    pub max_duration: Duration,
    /// The per-connection captured-bytes ceiling; applied by the handler's own read loop.
    pub max_captured_bytes: u64,
    /// Enforced by `run_tcp_listener` via a `tokio::sync::Semaphore`: at most this many handler
    /// futures run at once. A connection accepted while every permit is already held is refused
    /// immediately (the socket is closed, not queued) - an accepted-but-waiting connection would
    /// itself be the unbounded resource this cap exists to prevent.
    pub max_concurrent: u32,
}
