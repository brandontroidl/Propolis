//! SSH binary packet framing and version exchange (RFC 4253 sections 4.2 and 6), the two
//! mechanical layers everything else in this crate's self-authored SSH server builds on (see
//! ADR-0011 and "SSH honeypot" in `internal/design/02-sensor-framework.md`). This module owns:
//!
//! - The unencrypted wire format: `write_packet_unencrypted`/`read_packet_unencrypted`. Key
//!   exchange runs entirely over this framing before any cipher exists; the encrypted variants
//!   that supersede it once `SSH_MSG_NEWKEYS` completes live alongside it
//!   (`write_packet_encrypted`/`read_packet_encrypted`).
//! - The version-string handshake: `do_version_exchange_server`.
//! - KEXINIT: `build_kexinit`/`parse_kexinit`, this server's algorithm offer (rendered from the
//!   tables in `algorithms`, which also negotiates against the client's lists) and the parser for
//!   the client's own KEXINIT. A client with nothing in common with the offer is refused with
//!   `SSH_MSG_DISCONNECT` (`refuse_and_close`), never left waiting.
//! - The SSH message type constants (RFC 4253 section 12) every later task in this crate
//!   dispatches on.
//!
//! Two bounds this module enforces on every unencrypted packet and version line it reads, both
//! because this parses hostile bytes pre-authentication (see "Containment" in the design doc's
//! "Isolation and deployment"): a claimed size (`packet_length`, or a version line's length) is
//! checked against its RFC-derived ceiling *before* a buffer is allocated or a further byte is
//! read, so a forged length field cannot be used to exhaust memory or wedge a read waiting on
//! bytes that will never arrive; and every offset derived from an attacker-controlled field
//! (`padding_length`, KEXINIT's name-list lengths) is computed with checked arithmetic and
//! bounds-checked slicing, never direct indexing, so a malformed message returns an `Err` rather
//! than panicking the connection's task.
//!
//! Callers are expected to layer their own read/idle timeouts (`ConnectionBounds` from
//! `sensor-framework`) around every call here, the same split `sensor_framework::listener`
//! documents for its own reads: this module bounds *sizes*, not *time*, so a peer that trickles
//! bytes one at a time is a caller-side timeout's job to drop, not this module's.

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod algorithms;
pub mod cipher;
pub mod kex;
pub mod keys;
pub mod packet_cipher;

// ---- SSH message type constants (RFC 4253 section 12; channel types are RFC 4254) ----

pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;

/// RFC 4253 section 11.1, `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`: what a server says when the
/// client's algorithm lists leave nothing to negotiate.
pub const SSH_DISCONNECT_KEY_EXCHANGE_FAILED: u32 = 3;

/// RFC 4253 section 6.1's recommended ceiling: "All implementations MUST be able to process
/// packets with ... a total packet size of 35000 bytes." Applied here to the `packet_length`
/// field itself (the 4-byte header value, which excludes only that header) on every read and
/// write, so both ends of this server agree on the same bound and a forged header can be refused
/// before it costs an allocation or a read.
pub(crate) const MAX_PACKET_SIZE: u32 = 35_000;

/// RFC 4253 section 6: `packet_length + padding_length`'s combined field-and-payload-and-padding
/// total must be a multiple of this many bytes (the "none" cipher's block size, the only cipher
/// in play before Task 11's key exchange completes).
const BLOCK_SIZE: usize = 8;

/// RFC 4253 section 6: "There MUST be at least four bytes of padding."
pub(crate) const MIN_PADDING: usize = 4;

/// RFC 4253 section 4.2: "the maximum length of the string is 255 characters, including the
/// Carriage Return and Line Feed."
const MAX_VERSION_LINE_LEN: usize = 255;

/// Default server software-version identifier sent in the version-exchange banner
/// (`SSH-2.0-<this>\r\n`). Deliberately not a known implementation's name or its real default
/// banner (OpenSSH, Dropbear, wolfSSH, ...): "Detectability and anti-fingerprinting" in
/// `internal/design/02-sensor-framework.md` names "not a default-configuration signature match"
/// as the bar this layer clears, and claiming a specific implementation this server does not
/// bug-for-bug replicate (algorithm ordering, extension negotiation, rekey quirks) hands a
/// careful scanner exactly the diff it needs. Use `do_version_exchange_server_with_version` to
/// send a different value; wiring a real operator-facing config knob through to it is a later
/// task's job.
pub const DEFAULT_SERVER_SOFTWARE_VERSION: &str = "netsshd_1.0";

/// One SSH binary packet's payload (RFC 4253 section 6), already stripped of the framing fields
/// (`packet_length`, `padding_length`, the random padding) that exist only to move it over the
/// wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPacket {
    pub payload: Vec<u8>,
}

/// A parsed KEXINIT message (RFC 4253 section 7.1). `languages_*` are consumed while parsing (to
/// validate the message and reach the fields after them) but not retained: nothing in this crate
/// uses them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex_algorithms: String,
    pub server_host_key_algorithms: String,
    pub encryption_client_to_server: String,
    pub encryption_server_to_client: String,
    pub mac_client_to_server: String,
    pub mac_server_to_client: String,
    pub compression_client_to_server: String,
    pub compression_server_to_client: String,
    /// The client sent a key exchange packet right behind this message, betting on its own first
    /// choices; see `algorithms::Negotiated::discard_guess` for what the server does with it.
    pub first_kex_packet_follows: bool,
}

impl KexInit {
    /// The lists `algorithms::negotiate` reads.
    pub fn lists(&self) -> algorithms::ClientLists<'_> {
        algorithms::ClientLists {
            kex_algorithms: &self.kex_algorithms,
            server_host_key_algorithms: &self.server_host_key_algorithms,
            encryption_client_to_server: &self.encryption_client_to_server,
            encryption_server_to_client: &self.encryption_server_to_client,
            mac_client_to_server: &self.mac_client_to_server,
            mac_server_to_client: &self.mac_server_to_client,
            compression_client_to_server: &self.compression_client_to_server,
            compression_server_to_client: &self.compression_server_to_client,
            first_kex_packet_follows: self.first_kex_packet_follows,
        }
    }
}

/// Every error this module's parsing and framing can produce. Every variant is constructed from a
/// checked condition (a size comparison, a bounds check) - never from a caught panic - so each one
/// corresponds to an attacker-controlled input this server rejects instead of trusting.
#[derive(Debug)]
pub enum TransportError {
    /// A claimed size (`packet_length`, or a version line still growing with no terminator)
    /// exceeded its RFC-derived ceiling; rejected before any attempt to allocate or read that many
    /// bytes.
    TooLarge {
        claimed: u32,
        max: u32,
    },
    /// A message's own fields are structurally inconsistent (e.g. `padding_length` would consume
    /// more than `packet_length` provides, a KEXINIT name-list length runs past the end of the
    /// payload, or the message type byte is not the one expected). Never produced by a panic:
    /// every offset derived from an attacker-controlled field is bounds-checked before use.
    Malformed(&'static str),
    /// A KEXINIT name-list was not valid UTF-8. (A malformed version line is not an error - see
    /// `do_version_exchange_server_with_version`'s doc comment for why.)
    InvalidEncoding(&'static str),
    /// The client's KEXINIT lists share no algorithm with the server's, in the list named. Not
    /// malformed input: the client spoke SSH correctly and the server has nothing to say to it
    /// but `SSH_MSG_DISCONNECT`.
    Negotiation(algorithms::NegotiationFailure),
    Io(std::io::Error),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::TooLarge { claimed, max } => {
                write!(
                    f,
                    "claimed size {claimed} exceeds the {max}-byte protocol ceiling"
                )
            }
            TransportError::Malformed(reason) => write!(f, "malformed SSH message: {reason}"),
            TransportError::InvalidEncoding(reason) => write!(f, "invalid encoding: {reason}"),
            TransportError::Negotiation(failure) => {
                write!(f, "algorithm negotiation failed: {failure}")
            }
            TransportError::Io(e) => write!(f, "SSH transport i/o error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        TransportError::Io(e)
    }
}

// ---- Binary packet framing (RFC 4253 section 6) ----

/// Write `payload` as one unencrypted SSH binary packet: `packet_length`, `padding_length`,
/// `payload`, then 4-255 random padding bytes so the total (excluding `packet_length` itself) is
/// an 8-byte multiple. Built up in memory and written with a single `write_all` call, so a caller
/// never observes a torn/partial packet on the wire.
pub async fn write_packet_unencrypted<W>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let packet = encode_packet_unencrypted(payload)?;
    writer.write_all(&packet).await?;
    Ok(())
}

/// Read one unencrypted SSH binary packet. `packet_length` is validated against
/// `MAX_PACKET_SIZE` immediately after the 4-byte header is read and before any further read or
/// allocation - the property that keeps a forged length field from being usable to exhaust memory
/// or to wedge this call waiting on bytes a peer never sends.
pub async fn read_packet_unencrypted<R>(reader: &mut R) -> Result<SshPacket, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let packet_length = u32::from_be_bytes(len_buf);

    if packet_length == 0 {
        return Err(TransportError::Malformed(
            "packet_length is zero; too small to hold padding_length",
        ));
    }
    if packet_length > MAX_PACKET_SIZE {
        return Err(TransportError::TooLarge {
            claimed: packet_length,
            max: MAX_PACKET_SIZE,
        });
    }

    let mut body = vec![0u8; packet_length as usize];
    reader.read_exact(&mut body).await?;

    // body[0] is padding_length; body[1..packet_length] is payload followed by padding. Leniently
    // accepts any padding_length that fits (not just the RFC's >=4 minimum a well-behaved sender
    // always uses): the only real hazard is an out-of-bounds slice, which this checked_sub chain
    // already rules out, and dropping the connection over a padding technicality would lose
    // otherwise-capturable attacker telemetry for no security benefit.
    let padding_length = body[0] as usize;
    let payload_len = (packet_length as usize)
        .checked_sub(1)
        .and_then(|remaining| remaining.checked_sub(padding_length))
        .ok_or(TransportError::Malformed(
            "padding_length exceeds packet_length",
        ))?;

    let payload = body[1..1 + payload_len].to_vec();
    Ok(SshPacket { payload })
}

/// Build the wire bytes for one unencrypted packet. Split out from `write_packet_unencrypted` so
/// the framing math is independently unit-testable without a stream.
fn encode_packet_unencrypted(payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    let padding_length = compute_padding_length_unencrypted(payload.len());
    let packet_length_usize = 1 + payload.len() + padding_length as usize;
    let packet_length: u32 =
        packet_length_usize
            .try_into()
            .map_err(|_| TransportError::TooLarge {
                claimed: u32::MAX,
                max: MAX_PACKET_SIZE,
            })?;
    if packet_length > MAX_PACKET_SIZE {
        return Err(TransportError::TooLarge {
            claimed: packet_length,
            max: MAX_PACKET_SIZE,
        });
    }

    let mut packet = Vec::with_capacity(4 + packet_length_usize);
    packet.extend_from_slice(&packet_length.to_be_bytes());
    packet.push(padding_length);
    packet.extend_from_slice(payload);

    let mut padding = vec![0u8; padding_length as usize];
    rand::rng().fill(&mut padding[..]);
    packet.extend_from_slice(&padding);

    Ok(packet)
}

// ---- Encrypted binary packet framing (RFC 4253 section 6; per-cipher in `packet_cipher`) ----

/// Write `payload` as one encrypted SSH binary packet: frame and encrypt it with `cipher` at
/// sequence number `seq`, and write the result in a single call.
pub async fn write_packet_encrypted<W>(
    writer: &mut W,
    cipher: &mut packet_cipher::PacketCipher,
    seq: u32,
    payload: &[u8],
) -> Result<(), TransportError>
where
    W: AsyncWrite + Unpin,
{
    let wire = cipher.seal(seq, payload);
    writer.write_all(&wire).await?;
    Ok(())
}

/// Read one encrypted SSH binary packet and return its payload. Each cipher reads its own wire
/// format (see `packet_cipher`), bounding the claimed length against `MAX_PACKET_SIZE` before
/// allocating anything from it.
pub async fn read_packet_encrypted<R>(
    reader: &mut R,
    cipher: &mut packet_cipher::PacketCipher,
    seq: u32,
) -> Result<Vec<u8>, TransportError>
where
    R: AsyncRead + Unpin,
{
    cipher.open(reader, seq).await
}

/// Padding for unencrypted packets. RFC 4253 section 6: "the total length of
/// (packet_length || padding_length || payload || random padding) MUST be a multiple of
/// the cipher block size or 8." The 4-byte packet_length prefix is included in the
/// alignment target.
fn compute_padding_length_unencrypted(payload_len: usize) -> u8 {
    packet_cipher::padding_for(4 + 1 + payload_len, BLOCK_SIZE)
}

// ---- Version exchange (RFC 4253 section 4.2) ----

/// Perform the server side of the SSH version exchange using `DEFAULT_SERVER_SOFTWARE_VERSION`.
/// See `do_version_exchange_server_with_version` for the configurable form and the full
/// behavior.
pub async fn do_version_exchange_server<S>(
    stream: &mut S,
) -> Result<(String, String), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    do_version_exchange_server_with_version(stream, DEFAULT_SERVER_SOFTWARE_VERSION).await
}

/// Write `SSH-2.0-<software_version>\r\n`, then read the client's identification line. Returns
/// `(client_version, server_version)`, both with the trailing line terminator stripped.
///
/// The client's line is read up to `MAX_VERSION_LINE_LEN` bytes (RFC 4253 section 4.2's own
/// limit, counting the terminator); a peer that never sends a terminating `\n` within that bound
/// gets `Err`, never an unbounded in-memory buffer. The returned string is whatever bytes the
/// client sent, lossily re-encoded as UTF-8 if they were not valid UTF-8, rather than rejected
/// outright: this is untrusted telemetry a later task logs, and a malformed banner is itself a
/// signal worth capturing, not a reason to drop the only string that carries it. Sanitizing it for
/// a JSON event (control characters, escape sequences) is `sensor_framework::sanitize`'s job at
/// the point it is embedded in an event, same as every other attacker-controlled string reaching
/// this server - this function only performs the wire exchange.
pub async fn do_version_exchange_server_with_version<S>(
    stream: &mut S,
    software_version: &str,
) -> Result<(String, String), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_line = format!("SSH-2.0-{software_version}\r\n");
    stream.write_all(server_line.as_bytes()).await?;

    let client_version = read_version_line(stream).await?;
    let server_version = server_line.trim_end_matches("\r\n").to_string();

    Ok((client_version, server_version))
}

/// Read one CR-LF- or LF-terminated line, up to `MAX_VERSION_LINE_LEN` bytes including the
/// terminator, and strip the terminator. Reads one byte at a time: there is no framing to lean on
/// yet (the version exchange happens before any packet, let alone any cipher, exists), and a
/// banner is a handful of bytes exchanged once per connection, so the per-byte overhead is
/// immaterial.
async fn read_version_line<R>(reader: &mut R) -> Result<String, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(32);
    let mut total_read = 0usize;
    loop {
        if total_read >= MAX_VERSION_LINE_LEN {
            return Err(TransportError::TooLarge {
                claimed: total_read as u32,
                max: MAX_VERSION_LINE_LEN as u32,
            });
        }
        let byte = reader.read_u8().await?;
        total_read += 1;
        if byte == b'\n' {
            break;
        }
        buf.push(byte);
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

// ---- KEXINIT (RFC 4253 section 7.1) ----

/// Build this server's KEXINIT message: the algorithm offer rendered from the `algorithms`
/// tables, a fresh random cookie, no compression and no language preferences.
/// Returns the raw message payload (starting with `SSH_MSG_KEXINIT`) - the same bytes
/// `write_packet_unencrypted`'s `payload` argument expects, and the same bytes a later task feeds
/// to the exchange-hash computation as `I_S`.
pub fn build_kexinit() -> Vec<u8> {
    let mut cookie = [0u8; 16];
    rand::rng().fill(&mut cookie);

    let ciphers = algorithms::name_list::<algorithms::Cipher>();
    let macs = algorithms::name_list::<algorithms::Mac>();
    let mut out = Vec::new();
    out.push(SSH_MSG_KEXINIT);
    out.extend_from_slice(&cookie);
    write_name_list(&mut out, &algorithms::name_list::<algorithms::Kex>());
    write_name_list(
        &mut out,
        &algorithms::name_list::<algorithms::HostKeyAlgorithm>(),
    );
    write_name_list(&mut out, &ciphers); // encryption_algorithms_client_to_server
    write_name_list(&mut out, &ciphers); // encryption_algorithms_server_to_client
    write_name_list(&mut out, &macs); // mac_algorithms_client_to_server
    write_name_list(&mut out, &macs); // mac_algorithms_server_to_client
    write_name_list(&mut out, "none"); // compression_algorithms_client_to_server
    write_name_list(&mut out, "none"); // compression_algorithms_server_to_client
    write_name_list(&mut out, ""); // languages_client_to_server
    write_name_list(&mut out, ""); // languages_server_to_client
    out.push(0); // first_kex_packet_follows = false
    out.extend_from_slice(&0u32.to_be_bytes()); // reserved

    out
}

fn write_name_list(out: &mut Vec<u8>, list: &str) {
    let bytes = list.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Parse a client's (or, in tests, this server's own) KEXINIT payload. Every offset is derived
/// from a length field read out of `payload` itself, so a truncated message or a name-list length
/// that runs past the end of the buffer returns `Err` rather than panicking - this parses bytes an
/// attacker controls, before any authentication has occurred.
pub fn parse_kexinit(payload: &[u8]) -> Result<KexInit, TransportError> {
    let mut cursor = 0usize;

    let msg_type = read_u8(payload, &mut cursor)?;
    if msg_type != SSH_MSG_KEXINIT {
        return Err(TransportError::Malformed("not a KEXINIT message"));
    }

    let cookie_bytes = read_bytes(payload, &mut cursor, 16)?;
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(cookie_bytes);

    let kex_algorithms = read_name_list(payload, &mut cursor)?;
    let server_host_key_algorithms = read_name_list(payload, &mut cursor)?;
    let encryption_client_to_server = read_name_list(payload, &mut cursor)?;
    let encryption_server_to_client = read_name_list(payload, &mut cursor)?;
    let mac_client_to_server = read_name_list(payload, &mut cursor)?;
    let mac_server_to_client = read_name_list(payload, &mut cursor)?;
    let compression_client_to_server = read_name_list(payload, &mut cursor)?;
    let compression_server_to_client = read_name_list(payload, &mut cursor)?;
    let _languages_client_to_server = read_name_list(payload, &mut cursor)?;
    let _languages_server_to_client = read_name_list(payload, &mut cursor)?;
    let first_kex_packet_follows = read_u8(payload, &mut cursor)? != 0;
    let _reserved = read_u32(payload, &mut cursor)?;

    Ok(KexInit {
        cookie,
        kex_algorithms,
        server_host_key_algorithms,
        encryption_client_to_server,
        encryption_server_to_client,
        mac_client_to_server,
        mac_server_to_client,
        compression_client_to_server,
        compression_server_to_client,
        first_kex_packet_follows,
    })
}

// ---- SSH_MSG_DISCONNECT (RFC 4253 section 11.1) ----

/// The payload of an `SSH_MSG_DISCONNECT`: reason code, human-readable description, and an empty
/// language tag.
pub fn build_disconnect(reason: u32, description: &str) -> Vec<u8> {
    let mut out = vec![SSH_MSG_DISCONNECT];
    out.extend_from_slice(&reason.to_be_bytes());
    write_name_list(&mut out, description);
    write_name_list(&mut out, "");
    out
}

/// How long `refuse_and_close` waits for the peer to finish sending before it lets go.
const REFUSAL_DRAIN: std::time::Duration = std::time::Duration::from_secs(1);
/// The most `refuse_and_close` reads and discards from a peer that keeps sending.
const REFUSAL_DRAIN_MAX_BYTES: usize = 64 * 1024;

/// Tell the peer why it is being refused and close, so a client that cannot be served is told
/// rather than left waiting. Sends `SSH_MSG_DISCONNECT`, shuts the write side, then reads and
/// discards whatever the peer already has in flight (bounded in time and bytes): closing a socket
/// with unread data makes the kernel answer with a reset, and a reset can overtake the DISCONNECT
/// so the peer never reads it.
pub async fn refuse_and_close<S>(
    stream: &mut S,
    reason: u32,
    description: &str,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    write_packet_unencrypted(stream, &build_disconnect(reason, description)).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    let drain = async {
        let mut buf = [0u8; 1024];
        let mut total = 0usize;
        while total < REFUSAL_DRAIN_MAX_BYTES {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
    };
    let _ = tokio::time::timeout(REFUSAL_DRAIN, drain).await;
    Ok(())
}

fn read_u8(data: &[u8], cursor: &mut usize) -> Result<u8, TransportError> {
    let byte = *data
        .get(*cursor)
        .ok_or(TransportError::Malformed("truncated: expected a byte"))?;
    *cursor += 1;
    Ok(byte)
}

fn read_u32(data: &[u8], cursor: &mut usize) -> Result<u32, TransportError> {
    let bytes = read_bytes(data, cursor, 4)?;
    Ok(u32::from_be_bytes(bytes.try_into().expect(
        "read_bytes(.., 4) always returns exactly 4 bytes",
    )))
}

fn read_bytes<'a>(
    data: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], TransportError> {
    let end = cursor
        .checked_add(len)
        .ok_or(TransportError::Malformed("length overflow"))?;
    let slice = data
        .get(*cursor..end)
        .ok_or(TransportError::Malformed("truncated: not enough bytes"))?;
    *cursor = end;
    Ok(slice)
}

fn read_name_list(data: &[u8], cursor: &mut usize) -> Result<String, TransportError> {
    let len = read_u32(data, cursor)? as usize;
    let bytes = read_bytes(data, cursor, len)?;
    String::from_utf8(bytes.to_vec())
        .map_err(|_| TransportError::InvalidEncoding("name-list is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn compute_padding_length_unencrypted_aligns_total_frame() {
        for payload_len in 0..=200usize {
            let padding_length = compute_padding_length_unencrypted(payload_len);
            assert!(padding_length as usize >= MIN_PADDING);
            let total = 4 + 1 + payload_len + padding_length as usize;
            assert_eq!(
                total % BLOCK_SIZE,
                0,
                "payload_len={payload_len}: total wire frame {total} not block-aligned"
            );
        }
    }

    #[test]
    fn padding_aligns_the_encrypted_part_to_each_ciphers_block() {
        for block in [8usize, 16] {
            for payload_len in 0..=200usize {
                let padding_length = packet_cipher::padding_for(1 + payload_len, block);
                assert!(padding_length as usize >= MIN_PADDING);
                let body = 1 + payload_len + padding_length as usize;
                assert_eq!(
                    body % block,
                    0,
                    "block={block} payload_len={payload_len}: body {body} not aligned"
                );
                // The least padding that does: one block more would be waste.
                assert!(
                    (padding_length as usize) < MIN_PADDING + block,
                    "block={block} payload_len={payload_len}: {padding_length} is more than needed"
                );
            }
        }
    }

    #[test]
    fn encode_packet_unencrypted_length_prefix_matches_encoded_bytes() {
        let payload = vec![0xABu8; 37];
        let packet = encode_packet_unencrypted(&payload).unwrap();
        let packet_length = u32::from_be_bytes(packet[0..4].try_into().unwrap());
        assert_eq!(packet.len(), 4 + packet_length as usize);
        let padding_length = packet[4] as usize;
        assert!(padding_length >= MIN_PADDING);
        let recovered_payload = &packet[5..5 + payload.len()];
        assert_eq!(recovered_payload, payload.as_slice());
    }

    #[test]
    fn encode_packet_unencrypted_rejects_oversized_payload() {
        let huge_payload = vec![0u8; MAX_PACKET_SIZE as usize + 1];
        let result = encode_packet_unencrypted(&huge_payload);
        assert!(matches!(result, Err(TransportError::TooLarge { .. })));
    }

    #[test]
    fn build_kexinit_cookie_is_random_across_calls() {
        let a = build_kexinit();
        let b = build_kexinit();
        assert_ne!(
            &a[1..17],
            &b[1..17],
            "cookie must not be constant across calls"
        );
    }

    #[test]
    fn parse_kexinit_rejects_wrong_message_type() {
        let mut bogus = build_kexinit();
        bogus[0] = SSH_MSG_IGNORE;
        let result = parse_kexinit(&bogus);
        assert!(matches!(result, Err(TransportError::Malformed(_))));
    }

    #[test]
    fn parse_kexinit_rejects_truncated_payload() {
        let full = build_kexinit();
        // Cut off partway through the first name-list's length prefix (offset 17..21).
        let truncated = &full[..20];
        let result = parse_kexinit(truncated);
        assert!(matches!(result, Err(TransportError::Malformed(_))));
    }

    #[test]
    fn parse_kexinit_rejects_name_list_length_past_end_of_buffer() {
        let mut tampered = build_kexinit();
        // The first name-list's 4-byte length prefix starts right after the 1-byte message type
        // and 16-byte cookie.
        let len_offset = 1 + 16;
        tampered[len_offset..len_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let result = parse_kexinit(&tampered);
        assert!(matches!(result, Err(TransportError::Malformed(_))));
    }

    #[test]
    fn parse_kexinit_rejects_empty_payload() {
        let result = parse_kexinit(&[]);
        assert!(matches!(result, Err(TransportError::Malformed(_))));
    }

    proptest! {
        /// Fuzz-lite guard: `parse_kexinit` parses attacker-controlled bytes pre-authentication,
        /// so no arbitrary, possibly-truncated input may ever panic - it must always resolve to
        /// `Ok` or `Err`.
        #[test]
        fn parse_kexinit_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..=512)
        ) {
            let _ = parse_kexinit(&bytes);
        }

        /// The hand-picked 37-byte case above proves the framing math once; this checks the same
        /// invariant (length prefix matches the encoded bytes, padding within RFC bounds, payload
        /// recoverable at the documented offset) across many payload sizes, not just one.
        #[test]
        fn packet_encode_is_structurally_valid_for_arbitrary_payloads(
            payload in proptest::collection::vec(any::<u8>(), 0..=2000)
        ) {
            let packet = encode_packet_unencrypted(&payload).unwrap();
            let packet_length = u32::from_be_bytes(packet[0..4].try_into().unwrap());
            prop_assert_eq!(packet.len(), 4 + packet_length as usize);
            let padding_length = packet[4] as usize;
            prop_assert!(padding_length >= MIN_PADDING);
            let recovered = &packet[5..5 + payload.len()];
            prop_assert_eq!(recovered, payload.as_slice());
        }
    }
}
