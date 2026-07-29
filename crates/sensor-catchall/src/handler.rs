//! Per-hit catch-all logic: the passive TCP/UDP capture that emits `catchall_probe` events. See
//! `internal/design/02-sensor-framework.md`'s "Catch-all listener": it "emulates no protocol and
//! presents no service beyond accepting the connection or datagram" - no banner, no prompt, no
//! response of any kind, so what is captured is exactly what a scanner or bot sends unprompted.
//!
//! The catch-all never spools a file body (see `sensor_framework::spool`): everything captured is
//! a small, size-bounded sample carried as hex directly in `metadata`, so it has no use for
//! `QuarantineSpool`/`CaptureHandoff` - see this task's own brief: "catch-all may not need the
//! spool, since it captures no file bodies" and "`CaptureHandoff` (optional for catch-all)".

use std::net::{IpAddr, SocketAddr};

use chrono::Utc;
use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver, to_hex_bounded};
use sensor_wire::{PROTO_TCP, PROTO_UDP, SIGNAL_CATCHALL_PROBE, SensorEvent, WIRE_VERSION};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Ceiling on how many captured bytes are hex-encoded into `metadata.payload_hex`, independent of
/// `bounds.max_captured_bytes` (which bounds how much is actually *read* off the wire - this second
/// cap keeps the event record itself small even if an operator configures a much larger capture
/// budget). Hex is the sole route captured bytes take into an event record, with no separate
/// attempt to also decode/sanitize the payload as text: it is safe by its alphabet alone (no
/// newline, control character, or JSON delimiter is representable in hex), the same reasoning
/// `sensor_framework::spool`'s SHA-256 naming and `sanitize::to_hex_bounded` itself already rest
/// on.
const MAX_HEX_SAMPLE_BYTES: usize = 256;

/// Handle one accepted TCP connection: read up to `bounds.max_captured_bytes`, hex-encode what was
/// captured, and emit one `catchall_probe` event. Never writes a byte back - the catch-all
/// emulates no protocol at all, so there is nothing to send "beyond the TCP handshake itself".
pub async fn handle_tcp(
    mut stream: TcpStream,
    peer: SocketAddr,
    wan_resolver: &WanResolver,
    emitter: &EventEmitter,
    bounds: &ConnectionBounds,
) {
    // `TcpStream::local_addr()` reports the actual local endpoint of THIS accepted connection,
    // correctly even under a wildcard bind (unlike UDP's `recv_from`, which exposes no equivalent
    // - see `handle_udp`'s doc). A failure here is exceptional (the socket would already have to
    // be broken); rather than drop a real observation over a secondary attribution failure, log
    // and continue with `wan_ip = None`, the wire contract's own documented "no mapping" case.
    let wan_ip = match stream.local_addr() {
        Ok(addr) => wan_resolver.resolve(normalize_dual_stack(addr).ip()),
        Err(e) => {
            tracing::warn!(%peer, error = %e, "catchall: tcp local_addr failed; wan_ip will be null");
            None
        }
    };

    let captured = read_bounded(&mut stream, bounds).await;
    drop(stream); // Close after capture. No response of any kind is ever written.

    let event = build_event(peer.ip(), wan_ip, PROTO_TCP, &captured);
    if let Err(e) = emitter.append(&event).await {
        tracing::error!(%peer, error = %e, "catchall: failed to append tcp event");
    }
}

/// Read up to `bounds.max_captured_bytes` from `stream`. `bounds.read_timeout` bounds the wait for
/// the very first byte; `bounds.idle_timeout` bounds the gap between every read after that -
/// matching `ConnectionBounds`' own doc split, since "the maximum gap between successive reads
/// before a session is treated as idle" is only a meaningful, distinct concept once a session has
/// already produced its first byte. Reaching EOF or the byte ceiling ends the read normally; a
/// read error or an elapsed timeout ends it with whatever was captured so far rather than
/// discarding it - a probe that trails off mid-stream is still a real, emittable observation
/// (`internal/design/02-sensor-framework.md`'s "Error handling": "the event still records the
/// sighting and the observed length"), and `run_tcp_listener`'s own `max_duration` remains the
/// independent hard backstop against a connection that never ends at all.
async fn read_bounded(stream: &mut TcpStream, bounds: &ConnectionBounds) -> Vec<u8> {
    let cap = bounds.max_captured_bytes as usize;
    let mut buf = vec![0u8; cap];
    let mut filled = 0usize;
    while filled < cap {
        let per_read_timeout = if filled == 0 {
            bounds.read_timeout
        } else {
            bounds.idle_timeout
        };
        match tokio::time::timeout(per_read_timeout, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) => break, // EOF.
            Ok(Ok(n)) => filled += n,
            Ok(Err(_)) => break, // read error - keep whatever was captured so far.
            Err(_) => break,     // read_timeout/idle_timeout elapsed.
        }
    }
    buf.truncate(filled);
    buf
}

/// Handle one received UDP datagram - already complete, since `run_udp_listener` hands over the
/// whole payload from a single `recv_from` (see its module doc). Sends nothing: the framework's
/// `run_udp_listener` never gives a handler any way to reach the socket at all, so a UDP catch-all
/// cannot answer a probe even by mistake.
///
/// `local_ip` is supplied by the caller rather than discovered here: `run_udp_listener`'s handler
/// signature carries only the datagram bytes and the sender's address, never the local address the
/// datagram arrived on - there is no `local_addr()` equivalent for a UDP receive the way there is
/// for an accepted TCP connection (see `sensor_catchall::start_test_udp_listener`'s doc for the
/// full reasoning and its narrower limitation under a wildcard bind).
pub async fn handle_udp(
    data: Vec<u8>,
    peer: SocketAddr,
    local_ip: IpAddr,
    wan_resolver: &WanResolver,
    emitter: &EventEmitter,
) {
    let wan_ip = wan_resolver.resolve(local_ip);
    let event = build_event(peer.ip(), wan_ip, PROTO_UDP, &data);
    if let Err(e) = emitter.append(&event).await {
        tracing::error!(%peer, error = %e, "catchall: failed to append udp event");
    }
}

/// Build one `catchall_probe` event. `authenticated` is always `false` (the catch-all can never
/// confirm a real client - it never runs a real protocol) and `metadata` deliberately carries no
/// `protocol_label` key at all: the catch-all emulates no protocol, so there is no label to name.
fn build_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    protocol: &str,
    captured: &[u8],
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: "catchall".to_string(),
        signal_type: SIGNAL_CATCHALL_PROBE.to_string(),
        protocol: protocol.to_string(),
        authenticated: false,
        observed_at: Utc::now(),
        metadata: serde_json::json!({
            "payload_hex": to_hex_bounded(captured, MAX_HEX_SAMPLE_BYTES),
            "observed_len": captured.len(),
        }),
        sample: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn build_event_has_no_protocol_label_and_is_never_authenticated() {
        let event = build_event("203.0.113.7".parse().unwrap(), None, PROTO_TCP, b"probe");
        assert!(!event.authenticated);
        assert!(event.metadata.get("protocol_label").is_none());
        assert_eq!(event.sensor, "catchall");
        assert_eq!(event.signal_type, SIGNAL_CATCHALL_PROBE);
        assert_eq!(event.sample, None);
    }

    #[test]
    fn build_event_hex_encodes_payload_and_records_observed_len() {
        let event = build_event(
            "203.0.113.7".parse().unwrap(),
            None,
            PROTO_TCP,
            b"\xde\xad\xbe\xef",
        );
        assert_eq!(event.metadata["payload_hex"], "deadbeef");
        assert_eq!(event.metadata["observed_len"], 4);
    }

    #[test]
    fn build_event_hex_sample_is_bounded_independent_of_true_length() {
        // The hex sample and the observed length are two different numbers once the true capture
        // exceeds MAX_HEX_SAMPLE_BYTES: the record must still show the full observed length.
        let long = vec![0xABu8; 1000];
        let event = build_event("203.0.113.7".parse().unwrap(), None, PROTO_UDP, &long);
        let hex = event.metadata["payload_hex"].as_str().unwrap();
        assert_eq!(hex.len(), MAX_HEX_SAMPLE_BYTES * 2);
        assert_eq!(event.metadata["observed_len"], 1000);
    }

    #[tokio::test]
    async fn read_bounded_stops_at_idle_timeout_after_first_byte_not_read_timeout() {
        // Discriminates "the same timeout is applied to every read" from "read_timeout only
        // governs the wait for the first byte; idle_timeout governs every read after" - the
        // design this function's own doc comment commits to. A long read_timeout (2s) but a short
        // idle_timeout (80ms): under the wrong (same-timeout-throughout) implementation this
        // capture would still be blocked well past idle_timeout; it must actually stop within a
        // few hundred ms of the last byte.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bounds = ConnectionBounds {
            read_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_millis(80),
            max_duration: Duration::from_secs(5),
            max_captured_bytes: 4096,
            max_concurrent: 10,
        };

        let client = tokio::spawn(async move {
            let mut conn = TcpStream::connect(addr).await.unwrap();
            conn.write_all(b"first").await.unwrap();
            // Then go silent - only idle_timeout should end the capture, not read_timeout.
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(conn);
        });

        let (mut server_stream, _peer) = listener.accept().await.unwrap();
        let start = std::time::Instant::now();
        let captured = read_bounded(&mut server_stream, &bounds).await;
        let elapsed = start.elapsed();

        assert_eq!(captured, b"first");
        assert!(
            elapsed < Duration::from_millis(500),
            "must stop at idle_timeout (~80ms) after the first byte, not wait for read_timeout \
             (2s); took {elapsed:?}"
        );
        client.abort();
    }

    #[tokio::test]
    async fn read_bounded_stops_at_max_captured_bytes_even_with_more_data_available() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bounds = ConnectionBounds {
            read_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(2),
            max_duration: Duration::from_secs(5),
            max_captured_bytes: 8,
            max_concurrent: 10,
        };

        let client = tokio::spawn(async move {
            let mut conn = TcpStream::connect(addr).await.unwrap();
            conn.write_all(&[0x41u8; 4096]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(conn);
        });

        let (mut server_stream, _peer) = listener.accept().await.unwrap();
        let captured = read_bounded(&mut server_stream, &bounds).await;
        assert_eq!(
            captured.len(),
            8,
            "must stop at max_captured_bytes, not read everything sent"
        );
        client.abort();
    }
}
