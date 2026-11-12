//! Carries a TLS handshake inside TDS PRELOGIN packets (MS-TDS 2.2.6.5 / 3.3.5.1), then passes raw
//! TLS records through: the server side of SQL Server's "TLS inside TDS" for TDS 7.x.
//!
//! Writes are framed until `finish_handshake()`. Reads are de-framed until the first byte where a
//! TDS header should start is not 0x12, then raw for good. Read de-framing cannot follow a flag:
//! after processing the client Finished, tokio-rustls may issue one more read on the transport
//! before `accept` returns, and a TLS 1.3 client sends its first application record (Login7)
//! without waiting, so that read can land on raw TLS. A raw record never starts with 0x12 (TLS
//! content types are 0x14-0x17), and the consumed bytes are replayed, so nothing is lost.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const TDS_PRELOGIN: u8 = 0x12;
const STATUS_EOM: u8 = 0x01;
const HEADER_LEN: usize = 8;
/// One packet per write, sized to the default negotiated TDS packet size (4096).
const MAX_PAYLOAD: usize = 4096 - HEADER_LEN;

pub(crate) struct TdsTlsAdapter<S> {
    inner: S,
    framing: bool,
    hdr: [u8; HEADER_LEN],
    hdr_len: usize,
    payload_left: usize,
    raw_read: bool,
    pushback: [u8; HEADER_LEN],
    pushback_len: usize,
    pushback_pos: usize,
    out: Vec<u8>,
    out_pos: usize,
    packet_id: u8,
}

impl<S> TdsTlsAdapter<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            framing: true,
            hdr: [0; HEADER_LEN],
            hdr_len: 0,
            payload_left: 0,
            raw_read: false,
            pushback: [0; HEADER_LEN],
            pushback_len: 0,
            pushback_pos: 0,
            out: Vec::new(),
            out_pos: 0,
            packet_id: 0,
        }
    }

    /// An adapter whose transport's first byte was already consumed by the caller (to tell a
    /// plaintext Login7 from a framed handshake). The byte goes through the same framed-or-raw
    /// decision a first read would make.
    pub(crate) fn starting_with(inner: S, first: u8) -> Self {
        let mut adapter = Self::new(inner);
        adapter.hdr[0] = first;
        adapter.hdr_len = 1;
        adapter.classify_header();
        adapter
    }

    /// After header bytes land in `hdr`: a first byte other than PRELOGIN switches reads to raw
    /// for good, replaying the consumed bytes. Returns whether it switched.
    fn classify_header(&mut self) -> bool {
        if self.hdr[0] == TDS_PRELOGIN {
            return false;
        }
        self.pushback[..self.hdr_len].copy_from_slice(&self.hdr[..self.hdr_len]);
        self.pushback_len = self.hdr_len;
        self.pushback_pos = 0;
        self.raw_read = true;
        self.hdr_len = 0;
        true
    }

    /// Stop framing writes. Call only after the TLS stream has been flushed, so any queued
    /// handshake tail (the TLS 1.2 server CCS + Finished) has already left framed.
    pub(crate) fn finish_handshake(&mut self) {
        self.framing = false;
    }
}

impl<S: AsyncWrite + Unpin> TdsTlsAdapter<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TdsTlsAdapter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.pushback_pos < this.pushback_len {
                let n = buf.remaining().min(this.pushback_len - this.pushback_pos);
                buf.put_slice(&this.pushback[this.pushback_pos..this.pushback_pos + n]);
                this.pushback_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.raw_read {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            if this.payload_left > 0 {
                let mut tmp = [0u8; MAX_PAYLOAD];
                let want = buf.remaining().min(this.payload_left).min(MAX_PAYLOAD);
                let mut rb = ReadBuf::new(&mut tmp[..want]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                let got = rb.filled().len();
                if got == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.payload_left -= got;
                buf.put_slice(&tmp[..got]);
                return Poll::Ready(Ok(()));
            }
            let start = this.hdr_len;
            let mut rb = ReadBuf::new(&mut this.hdr[start..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
            let got = rb.filled().len();
            if got == 0 {
                return if start == 0 {
                    // Clean EOF between packets.
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            this.hdr_len += got;
            if this.classify_header() {
                continue;
            }
            if this.hdr_len < HEADER_LEN {
                continue;
            }
            let total = u16::from_be_bytes([this.hdr[2], this.hdr[3]]) as usize;
            if total < HEADER_LEN {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tds packet length below header size",
                )));
            }
            this.payload_left = total - HEADER_LEN;
            this.hdr_len = 0;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TdsTlsAdapter<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        if !this.framing {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_PAYLOAD);
        this.packet_id = this.packet_id.wrapping_add(1);
        this.out.push(TDS_PRELOGIN);
        // EOM on every packet: what real clients send for each TLS write (MS-TDS example header
        // `12 01 ...`). MS-TDS also permits 0x00 on non-final packets; all-EOM is deliberate.
        this.out.push(STATUS_EOM);
        this.out
            .extend_from_slice(&((HEADER_LEN + n) as u16).to_be_bytes());
        this.out.extend_from_slice(&[0, 0]); // SPID
        this.out.push(this.packet_id);
        this.out.push(0); // window
        this.out.extend_from_slice(&data[..n]);
        // The packet is owned by `out` now, so an inner Pending is fine: the next write, flush or
        // shutdown drains it before anything else goes out.
        if let Poll::Ready(Err(e)) = this.drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    /// Read one TDS packet off the raw peer end: (header, payload).
    async fn read_packet(peer: &mut DuplexStream) -> ([u8; 8], Vec<u8>) {
        let mut hdr = [0u8; 8];
        tokio::time::timeout(WAIT, peer.read_exact(&mut hdr))
            .await
            .unwrap()
            .unwrap();
        let total = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
        let mut payload = vec![0u8; total - 8];
        tokio::time::timeout(WAIT, peer.read_exact(&mut payload))
            .await
            .unwrap()
            .unwrap();
        (hdr, payload)
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x12, 0x01];
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0, 1, 0]);
        p.extend_from_slice(payload);
        p
    }

    #[tokio::test]
    async fn write_frames_one_packet() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        adapter.write_all(&[1, 2, 3]).await.unwrap();
        adapter.flush().await.unwrap();
        let mut got = [0u8; 11];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x12, 0x01, 0x00, 0x0B, 0, 0, 0x01, 0, 1, 2, 3]);
        adapter.write_all(&[4]).await.unwrap();
        adapter.flush().await.unwrap();
        let (hdr, payload) = read_packet(&mut peer).await;
        assert_eq!(hdr[6], 0x02, "packet id increments");
        assert_eq!(payload, [4]);
    }

    #[tokio::test]
    async fn write_over_4088_splits_into_packets() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        let input: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let reader = tokio::spawn(async move {
            let first = read_packet(&mut peer).await;
            let second = read_packet(&mut peer).await;
            (first, second)
        });
        adapter.write_all(&input).await.unwrap();
        adapter.flush().await.unwrap();
        let ((h1, p1), (h2, p2)) = reader.await.unwrap();
        assert_eq!(u16::from_be_bytes([h1[2], h1[3]]), 0x1000);
        assert_eq!(u16::from_be_bytes([h2[2], h2[3]]) as usize, 8 + 912);
        assert_eq!((h1[1], h2[1]), (0x01, 0x01));
        assert_eq!([p1, p2].concat(), input);
    }

    #[tokio::test]
    async fn read_unwraps_a_packet_delivered_byte_by_byte() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        let wire = packet(&[7, 8, 9, 10]);
        let writer = tokio::spawn(async move {
            for b in wire {
                peer.write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
            peer
        });
        let mut got = [0u8; 4];
        tokio::time::timeout(WAIT, adapter.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, [7, 8, 9, 10]);
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn read_concatenates_back_to_back_packets() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        peer.write_all(&[packet(&[1, 2, 3]), packet(&[4, 5])].concat())
            .await
            .unwrap();
        let mut got = [0u8; 5];
        adapter.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn non_tds_first_byte_switches_to_raw_and_replays() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        let record = [0x17, 0x03, 0x03, 0x00, 0x02, 0xAA, 0xBB];
        peer.write_all(&record).await.unwrap();
        let mut got = [0u8; 7];
        adapter.read_exact(&mut got).await.unwrap();
        assert_eq!(got, record);
        // A later chunk that happens to start with 0x12 must still come through raw.
        peer.write_all(&[0x12, 0x01, 0x00]).await.unwrap();
        let mut more = [0u8; 3];
        adapter.read_exact(&mut more).await.unwrap();
        assert_eq!(more, [0x12, 0x01, 0x00]);
    }

    #[tokio::test]
    async fn starting_with_a_consumed_byte_decides_as_a_first_read_would() {
        // 0x12 consumed: the rest of the packet still de-frames.
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::starting_with(a, 0x12);
        peer.write_all(&packet(&[5, 6, 7])[1..]).await.unwrap();
        let mut got = [0u8; 3];
        adapter.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [5, 6, 7]);

        // Any other byte consumed: raw from the start, with that byte replayed.
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::starting_with(a, 0x16);
        peer.write_all(&[0x03, 0x01]).await.unwrap();
        let mut got = [0u8; 3];
        adapter.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x16, 0x03, 0x01]);
    }

    #[tokio::test]
    async fn finish_handshake_makes_writes_raw() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        adapter.finish_handshake();
        adapter.write_all(&[9, 9, 9]).await.unwrap();
        adapter.flush().await.unwrap();
        drop(adapter);
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, [9, 9, 9]);
    }

    #[tokio::test]
    async fn header_shorter_than_eight_is_invalid_data() {
        let (a, mut peer) = duplex(64 * 1024);
        let mut adapter = TdsTlsAdapter::new(a);
        peer.write_all(&[0x12, 0x01, 0x00, 0x04, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut got = [0u8; 1];
        let err = adapter.read_exact(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn partial_inner_writes_lose_no_bytes() {
        let (a, mut peer) = duplex(16);
        let mut adapter = TdsTlsAdapter::new(a);
        let input: Vec<u8> = (0..200u8).collect();
        let reader = tokio::spawn(async move {
            let mut wire = Vec::new();
            let mut chunk = [0u8; 5];
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                match peer.read(&mut chunk).await.unwrap() {
                    0 => break,
                    n => wire.extend_from_slice(&chunk[..n]),
                }
            }
            wire
        });
        adapter.write_all(&input).await.unwrap();
        adapter.flush().await.unwrap();
        adapter.shutdown().await.unwrap();
        drop(adapter);
        let wire = reader.await.unwrap();
        // De-frame independently of the adapter.
        let mut payload = Vec::new();
        let mut rest = &wire[..];
        while !rest.is_empty() {
            assert_eq!(rest[0], 0x12);
            let total = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            payload.extend_from_slice(&rest[8..total]);
            rest = &rest[total..];
        }
        assert_eq!(payload, input);
    }
}
