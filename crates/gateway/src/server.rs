//! The gateway's TCP accept loop: wrap each accepted connection in a mandatory-client-auth
//! TLS handshake, derive the collector id from the verified client certificate's CommonName
//! (never from anything the collector sends in the payload - see `collector_wire::tls`'s
//! module doc), then read length-prefixed batch frames off the same connection until it
//! closes. A connection that fails the handshake, presents no usable client cert, or sends a
//! frame length over `MAX_FRAME_LEN` never reaches - or is dropped out of - the read loop; the
//! gateway is a trust boundary and every one of those is a fail-closed path, not an error to
//! recover from.

use std::net::SocketAddr;
use std::sync::Arc;

use collector_wire::ack::{ACK_LEN, Ack, AckReason, AckStatus, encode_ack};
use collector_wire::frame::{Batch, MAX_FRAME_LEN, decode_frame};
use collector_wire::tls::peer_common_name;
use sensor_framework::{ConnectionBounds, run_tcp_listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;

/// What Tasks 7-8 implement: turn one verified batch into an ack. `collector_id` is the
/// CommonName read from the client's verified certificate (see the module doc), never
/// anything from the wire payload itself.
pub trait BatchSink: Send + Sync + 'static {
    fn accept(&self, collector_id: &str, batch: &Batch) -> Ack;
}

/// Bind `addr` and run the gateway's accept loop as a spawned task, returning immediately
/// with the bound address (an ephemeral `:0` port resolves to its actual port) and a
/// `JoinHandle` the caller can `.abort()` to stop accepting - the same shape
/// `sensor_framework::run_tcp_listener` returns, since this function is a thin wrapper
/// around it that adds the TLS handshake and frame protocol in the handler closure.
pub async fn serve(
    addr: SocketAddr,
    tls: Arc<ServerConfig>,
    bounds: ConnectionBounds,
    sink: Arc<dyn BatchSink>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let acceptor = TlsAcceptor::from(tls);
    run_tcp_listener(addr, bounds, move |tcp, peer, _session_id| {
        let acceptor = acceptor.clone();
        let sink = Arc::clone(&sink);
        async move { handle_connection(tcp, peer, acceptor, sink).await }
    })
    .await
}

async fn handle_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    sink: Arc<dyn BatchSink>,
) {
    let mut stream = match acceptor.accept(tcp).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(%peer, %error, "tls handshake failed; dropping connection");
            return;
        }
    };

    let Some(certs) = stream.get_ref().1.peer_certificates() else {
        tracing::warn!(%peer, "no client certificate presented; dropping connection");
        return;
    };
    let Some(collector_id) = peer_common_name(certs) else {
        tracing::warn!(%peer, "client certificate has no usable CommonName; dropping connection");
        return;
    };

    loop {
        let mut len_bytes = [0u8; 4];
        if let Err(error) = stream.read_exact(&mut len_bytes).await {
            tracing::debug!(%peer, %collector_id, %error, "connection closed reading frame length");
            return;
        }
        let frame_len = u32::from_be_bytes(len_bytes) as usize;
        // Bound-check before allocating: an attacker-controlled length must never size an
        // allocation.
        if frame_len > MAX_FRAME_LEN {
            tracing::warn!(
                %peer, %collector_id, frame_len,
                "frame length exceeds MAX_FRAME_LEN; dropping connection"
            );
            return;
        }

        let mut frame_bytes = vec![0u8; frame_len];
        if let Err(error) = stream.read_exact(&mut frame_bytes).await {
            tracing::debug!(%peer, %collector_id, %error, "connection closed reading frame body");
            return;
        }

        let ack = match decode_frame(&frame_bytes) {
            Ok(batch) => sink.accept(&collector_id, &batch),
            Err(error) => {
                tracing::warn!(%peer, %collector_id, %error, "malformed frame; rejecting");
                Ack {
                    status: AckStatus::Reject,
                    reason: AckReason::Malformed,
                    next_expected_seq: 0,
                }
            }
        };
        let malformed = ack.status == AckStatus::Reject && ack.reason == AckReason::Malformed;

        let ack_bytes: [u8; ACK_LEN] = encode_ack(&ack);
        if let Err(error) = stream.write_all(&ack_bytes).await {
            tracing::debug!(%peer, %collector_id, %error, "failed writing ack; dropping connection");
            return;
        }
        if let Err(error) = stream.flush().await {
            tracing::debug!(%peer, %collector_id, %error, "failed flushing ack; dropping connection");
            return;
        }

        if malformed {
            // A malformed frame desyncs the length-prefixed stream (we cannot trust our
            // position); close rather than attempt to keep reading.
            return;
        }
        // Otherwise loop: a shipper may pipeline several batches on one connection.
    }
}
