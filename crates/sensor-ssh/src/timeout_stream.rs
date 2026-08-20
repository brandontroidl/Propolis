//! A stream wrapper that applies `ConnectionBounds`' read and idle timeouts to every read of an
//! SSH session.
//!
//! `run_tcp_listener` bounds a session as a whole with `max_duration`, which stops a connection
//! being held forever. It cannot bound the individual reads inside it: the listener hands the
//! handler a raw `TcpStream` and has nothing left to intercept (see `sensor_framework::bounds`).
//! `sensor-telnet` applies its own per-read timeouts in its read loop; this sensor had none, so a
//! peer could sit mid-handshake for the entire `max_duration` window holding a connection slot -
//! bounded, but 600 seconds of it per attempt, for free.
//!
//! Applied here rather than at each call site because every transport function
//! (`read_packet_unencrypted`, `read_packet_encrypted`, `do_version_exchange_server`, ...) is
//! already generic over `AsyncRead`/`AsyncWrite`. Wrapping the stream once means every read in the
//! session inherits the bound, including any added later - a per-call-site timeout only covers the
//! call sites someone remembered.
//!
//! `read_timeout` bounds the wait for the first byte of the session and `idle_timeout` bounds every
//! read after that, matching `sensor-telnet`'s semantics exactly.
//!
//! `max_captured_bytes` is deliberately NOT enforced here, unlike in telnet. This sensor captures
//! SCP/SFTP uploads, and the transfer path already bounds itself at 10 MB per file against the
//! quarantine spool's own per-file and total caps. Enforcing the 1 MB session default at the stream
//! layer would truncate uploads at 1 MB - cutting off precisely the malware captures the sensor
//! exists to collect - so the byte ceiling stays where it can distinguish a capture from a flood.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

/// Wraps a stream so every read is bounded by a timeout that resets on progress.
pub struct TimeoutStream<S> {
    inner: S,
    /// Applied after the first successful read; the initial deadline uses `read_timeout`.
    idle_timeout: Duration,
    /// Boxed so this type stays `Unpin` and needs no unsafe pin projection.
    deadline: Pin<Box<Sleep>>,
}

impl<S> TimeoutStream<S> {
    /// The wrapped stream, for the socket-level queries this wrapper does not itself provide
    /// (`local_addr` for WAN attribution, principally).
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn new(inner: S, read_timeout: Duration, idle_timeout: Duration) -> Self {
        Self {
            inner,
            idle_timeout,
            deadline: Box::pin(tokio::time::sleep(read_timeout)),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TimeoutStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        let before = buf.filled().len();
        match Pin::new(&mut me.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                // Reset on progress, including a zero-byte read (EOF) - the caller sees the EOF
                // and ends the session, so the timer's state past this point does not matter.
                if buf.filled().len() > before {
                    me.deadline.as_mut().reset(Instant::now() + me.idle_timeout);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // Only once the socket has no data to give does the deadline get polled - which is
            // also what registers its waker, so a session that goes quiet is woken to be failed
            // rather than waiting for traffic that never comes.
            Poll::Pending => match Future::poll(me.deadline.as_mut(), cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ssh session exceeded its read/idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TimeoutStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn a_stream_that_never_speaks_fails_at_the_read_timeout() {
        let (client, server) = tokio::io::duplex(64);
        // Hold the far end open but silent - the shape a stalled peer presents.
        let _client = client;

        let mut stream = TimeoutStream::new(
            server,
            Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let mut buf = [0u8; 16];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    }

    #[tokio::test]
    async fn progress_resets_the_deadline_so_a_slow_but_active_peer_survives() {
        // The regression this guards: a deadline that is not reset turns the idle timeout into a
        // hard session cap, disconnecting an attacker who is actively typing.
        let (mut client, server) = tokio::io::duplex(64);
        let mut stream = TimeoutStream::new(
            server,
            Duration::from_millis(300),
            Duration::from_millis(300),
        );

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_millis(150)).await;
                if client.write_all(b"x").await.is_err() {
                    return;
                }
            }
            // Then go quiet, so the read after this must time out.
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let mut buf = [0u8; 1];
        for i in 0..5 {
            let n = stream
                .read(&mut buf)
                .await
                .unwrap_or_else(|e| panic!("read {i} must succeed while the peer is active: {e}"));
            assert_eq!(n, 1);
        }

        // Total elapsed is already well past one timeout window; only the gaps matter.
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    }

    #[tokio::test]
    async fn eof_is_passed_through_rather_than_reported_as_a_timeout() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);

        let mut stream =
            TimeoutStream::new(server, Duration::from_secs(30), Duration::from_secs(30));
        let mut buf = [0u8; 16];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    }
}
