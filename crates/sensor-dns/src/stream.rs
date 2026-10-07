//! TCP 53 and DoT 853: one handler over any async stream, with RFC 1035 4.2.2 framing (a 2-byte
//! big-endian length before each message). A connection carries at most
//! [`MAX_QUERIES_PER_CONNECTION`] queries of at most [`MAX_TCP_MESSAGE_BYTES`] each; a rejected
//! message ends it. Every exit path shuts the stream down, so a DoT session ends with
//! `close_notify` rather than a truncated stream.

use std::net::SocketAddr;

use sensor_framework::Uuid;
use sensor_framework::listener::normalize_dual_stack;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::Ctx;
use crate::events::{QueryRecord, QueryStatus, connection_event, stream_query_event};
use crate::protocol::{HEADER_LEN, RejectReason, Transport, parse_query, refused_reply};

pub const MAX_TCP_MESSAGE_BYTES: usize = 4096;
pub const MAX_QUERIES_PER_CONNECTION: usize = 64;

/// Serve one TCP or DoT connection. `local` is the raw local address (normalized here) for WAN
/// attribution; `tls` stamps every event this connection emits.
pub async fn handle_connection<S>(
    mut stream: S,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    tls: bool,
    session_id: Uuid,
    ctx: Ctx,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let source_ip = normalize_dual_stack(peer).ip();
    let wan_ip = local
        .map(normalize_dual_stack)
        .and_then(|l| ctx.wan_resolver.resolve(l.ip()));
    let append = |event: sensor_wire::SensorEvent| {
        let ctx: &Ctx = &ctx;
        async move {
            if let Err(e) = ctx.emitter.append(&event).await {
                tracing::error!(error = %e, "dns: failed to append event");
            }
        }
    };
    append(connection_event(source_ip, wan_ip, session_id, tls)).await;

    let bounds = &ctx.bounds;
    let mut bytes_read: u64 = 0;
    for msg_index in 0..MAX_QUERIES_PER_CONNECTION {
        let wait = if msg_index == 0 {
            bounds.read_timeout
        } else {
            bounds.idle_timeout
        };
        let mut prefix = [0u8; 2];
        match timeout(wait, stream.read_exact(&mut prefix)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                tracing::debug!(%peer, error = %e, "dns: connection ended");
                break;
            }
            Err(_) => {
                tracing::debug!(%peer, "dns: connection idle; closing");
                break;
            }
        }
        let len = usize::from(u16::from_be_bytes(prefix));
        let framing_reject = if len < HEADER_LEN {
            Some(RejectReason::ShortHeader)
        } else if len > MAX_TCP_MESSAGE_BYTES {
            Some(RejectReason::Oversize)
        } else {
            None
        };
        if let Some(reason) = framing_reject {
            // The body is never read.
            let record = QueryRecord {
                transport: Transport::Tcp,
                tls,
                status: QueryStatus::Rejected(reason),
                query_len: 0,
                declared_len: Some(len),
                msg_index: Some(msg_index),
                header: None,
                question: None,
                edns: None,
                reply_len: None,
            };
            append(stream_query_event(&record, source_ip, wan_ip, session_id)).await;
            break;
        }
        if bytes_read + 2 + len as u64 > bounds.max_captured_bytes {
            tracing::debug!(%peer, "dns: max_captured_bytes reached; closing");
            break;
        }
        let mut msg = vec![0u8; len];
        match timeout(bounds.read_timeout, stream.read_exact(&mut msg)).await {
            Ok(Ok(_)) => {}
            _ => {
                tracing::debug!(%peer, "dns: message body not read in full; closing");
                break;
            }
        }
        bytes_read += 2 + len as u64;

        match parse_query(&msg, Transport::Tcp) {
            Ok(q) => {
                let reply = refused_reply(&msg, &q);
                let record = QueryRecord {
                    transport: Transport::Tcp,
                    tls,
                    status: QueryStatus::Answered,
                    query_len: len,
                    declared_len: None,
                    msg_index: Some(msg_index),
                    header: Some(&q.header),
                    question: Some(&q.question),
                    edns: Some(&q.edns),
                    reply_len: Some(reply.len()),
                };
                append(stream_query_event(&record, source_ip, wan_ip, session_id)).await;
                if let Err(e) = write_framed(&mut stream, &reply).await {
                    tracing::debug!(%peer, error = %e, "dns: reply write failed");
                    break;
                }
            }
            Err(rejected) => {
                let record = QueryRecord {
                    transport: Transport::Tcp,
                    tls,
                    status: QueryStatus::Rejected(rejected.reason),
                    query_len: len,
                    declared_len: None,
                    msg_index: Some(msg_index),
                    header: rejected.header.as_ref(),
                    question: rejected.question.as_ref(),
                    edns: None,
                    reply_len: None,
                };
                append(stream_query_event(&record, source_ip, wan_ip, session_id)).await;
                break;
            }
        }
    }
    let _ = timeout(bounds.read_timeout, stream.shutdown()).await;
}

/// Length-prefix and write one reply. The crate's only `write_all`. A reply is at most
/// [`MAX_TCP_MESSAGE_BYTES`] long, so its length always fits the u16 prefix.
async fn write_framed<S: AsyncWrite + Unpin>(stream: &mut S, reply: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(2 + reply.len());
    frame.extend((reply.len() as u16).to_be_bytes());
    frame.extend(reply);
    stream.write_all(&frame).await?;
    stream.flush().await
}
