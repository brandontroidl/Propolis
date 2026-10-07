//! The listener an event arrived on, stamped onto every event as `metadata.local_port`.
//!
//! WHY. A sensor with several listeners (HTTP on 80 and 443, SMTP on three ports, the catch-all
//! on dozens) reports them all under one `event.sensor` name, and nothing else on the event said
//! which port the connection or datagram landed on. The fleet pane's per-listener activity could
//! only group by sensor, so every port of a sensor showed the sensor's total.
//!
//! HOW. The framework's listeners already know the local address of every accepted connection and
//! bound socket, and every event leaves through [`crate::EventEmitter::append`]. A task-local
//! carries the one into the other: [`scope`] wraps each connection's or datagram's handler future
//! (done by `run_tcp_listener` and `run_udp_listener`, and so by `run_tls_listener`), and
//! `append` stamps whatever [`current`] returns. No sensor builds the key itself, so no sensor
//! can forget it.
//!
//! The transport is NOT stamped: `event.protocol` already carries `tcp` or `udp` and is stored in
//! its own column, in the same spelling the fleet inventory uses. Each sensor's
//! `tests/arrival.rs` proves the two agree for every event it emits.
//!
//! A task-local does not cross `tokio::spawn`. Three paths emit from a task other than the one
//! [`scope`] wrapped, and each re-enters it explicitly: the capture hand-off's worker (the arrival
//! is captured in `CaptureHandoff::submit`), and the two UDP sensors that own their socket instead
//! of using `run_udp_listener` (`sensor-dns`, `sensor-tftp`), which wrap their per-datagram tasks
//! and, for `sensor-dns`, its rate-limit summary task. An event emitted outside any scope simply
//! carries no `local_port`, which the console renders as "port not recorded" rather than
//! attributing it to a guess.

use std::future::Future;

use sensor_wire::SensorEvent;

/// The metadata key the arrival port is stamped under.
pub const LOCAL_PORT_KEY: &str = "local_port";

/// The local port of the listener a connection or datagram arrived on: the accepted socket's
/// local port for TCP, the bound socket's port for UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arrival {
    pub local_port: u16,
}

impl Arrival {
    pub fn new(local_port: u16) -> Self {
        Self { local_port }
    }
}

tokio::task_local! {
    static ARRIVAL: Arrival;
}

/// Run `fut` with `arrival` as the listener every event it emits is stamped with. Dropping the
/// returned future (a `max_duration` timeout, a cancelled task) drops `fut` inside the scope, so an
/// event emitted from a destructor - a capture submitted on cancellation - is stamped too.
pub fn scope<F: Future>(arrival: Arrival, fut: F) -> impl Future<Output = F::Output> {
    ARRIVAL.scope(arrival, fut)
}

/// The arrival of the task this is called from, or `None` outside any [`scope`].
pub fn current() -> Option<Arrival> {
    ARRIVAL.try_with(|a| *a).ok()
}

/// Write `arrival` into `event.metadata`. Overwrites a value the sensor set itself: the listener
/// is the authority on where a connection landed. A `metadata` that is not a JSON object is left
/// alone, since there is no key to add to it.
pub(crate) fn stamp(event: &mut SensorEvent, arrival: Arrival) {
    if let Some(map) = event.metadata.as_object_mut() {
        map.insert(LOCAL_PORT_KEY.into(), arrival.local_port.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn current_is_none_outside_a_scope_and_the_arrival_inside_one() {
        assert_eq!(current(), None);
        let inside = scope(Arrival::new(6380), async { current() }).await;
        assert_eq!(inside, Some(Arrival::new(6380)));
        assert_eq!(current(), None);
    }

    /// Two listeners' handlers running concurrently on one runtime must each see their own port,
    /// not whichever scope was entered last.
    #[tokio::test]
    async fn concurrent_scopes_do_not_leak_into_each_other() {
        let a = scope(Arrival::new(80), async {
            tokio::task::yield_now().await;
            current()
        });
        let b = scope(Arrival::new(443), async {
            tokio::task::yield_now().await;
            current()
        });
        let (a, b) = tokio::join!(a, b);
        assert_eq!(a, Some(Arrival::new(80)));
        assert_eq!(b, Some(Arrival::new(443)));
    }

    /// A destructor that runs when a scoped future is dropped mid-flight still sees the arrival:
    /// `sensor-tftp` submits a capture from `Drop` when `max_duration` cancels its handler.
    #[tokio::test]
    async fn a_future_dropped_mid_flight_is_dropped_inside_the_scope() {
        struct Probe(std::sync::Arc<std::sync::Mutex<Option<Arrival>>>);
        impl Drop for Probe {
            fn drop(&mut self) {
                *self.0.lock().unwrap() = current();
            }
        }
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let probe = Probe(seen.clone());
        let fut = scope(Arrival::new(69), async move {
            let _probe = probe;
            std::future::pending::<()>().await;
        });
        let _ = tokio::time::timeout(std::time::Duration::from_millis(10), fut).await;
        assert_eq!(*seen.lock().unwrap(), Some(Arrival::new(69)));
    }

    #[test]
    fn stamp_writes_an_integer_port_and_leaves_a_non_object_alone() {
        let mut event: SensorEvent = serde_json::from_str(
            r#"{"v":1,"source_ip":"203.0.113.7","sensor":"http","signal_type":"honeypot_connection","protocol":"tcp","authenticated":false,"observed_at":"2026-10-01T00:00:00Z","metadata":{"protocol_label":"http","local_port":1}}"#,
        )
        .unwrap();
        stamp(&mut event, Arrival::new(443));
        assert_eq!(event.metadata[LOCAL_PORT_KEY], serde_json::json!(443));
        assert_eq!(event.metadata["protocol_label"], "http");

        event.metadata = serde_json::Value::Null;
        stamp(&mut event, Arrival::new(443));
        assert_eq!(event.metadata, serde_json::Value::Null);
    }
}
