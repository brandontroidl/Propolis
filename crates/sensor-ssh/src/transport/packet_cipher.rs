//! The encrypted binary packet protocol (RFC 4253 section 6) for every negotiated cipher.
//!
//! The ciphers differ in what the packet looks like on the wire, not only in how bytes are
//! scrambled, so each one frames and reads its own packets here:
//!
//! - `chacha20-poly1305@openssh.com` (`cipher::TransportCipher`): the length is encrypted under
//!   its own key, the tag authenticates length and body together.
//! - AES-CTR with a separate MAC: the MAC is over the sequence number and the plaintext packet
//!   (length included) and is checked after the whole packet is decrypted, so the length has to
//!   be decrypted first to know how much to read; with an `-etm` MAC the length stays in the
//!   clear and the MAC is over the ciphertext, checked before anything is decrypted.
//! - AES-GCM (`aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`): the length stays in the clear
//!   as associated data, the tag follows the ciphertext, and the nonce is a fixed field plus an
//!   invocation counter that advances once per packet (RFC 5647 section 7.1).
//!
//! Every length read from the wire is bounded and block-aligned before a buffer is sized from it,
//! and every failure is an `Err`, never a panic: this parses ciphertext a peer chose, after
//! authentication in the sense of "has key material", not in the sense of "is trusted".

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aes::cipher::consts::U12;
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit as _, Nonce, Tag};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac as _};
use rand::RngExt;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::algorithms::{Cipher, Mac};
use super::cipher::{self, TransportCipher};
use super::keys::DirectionKeys;
use super::{MAX_PACKET_SIZE, MIN_PADDING, TransportError};

const GCM_TAG_LEN: usize = 16;
/// AES block size, and so the alignment of every AES-based packet's encrypted part.
const AES_BLOCK: usize = 16;

/// Padding that brings `unaligned` bytes to a multiple of `block`, at least `MIN_PADDING` long
/// (RFC 4253 section 6). `unaligned` counts every byte of the packet that falls under the
/// alignment rule: for an unencrypted length field that is the length too, for the others not.
pub(super) fn padding_for(unaligned: usize, block: usize) -> u8 {
    let remainder = unaligned % block;
    let mut padding = if remainder == 0 { 0 } else { block - remainder };
    if padding < MIN_PADDING {
        padding += block;
    }
    padding as u8
}

fn random_padding(len: u8) -> Vec<u8> {
    let mut padding = vec![0u8; len as usize];
    rand::rng().fill(&mut padding[..]);
    padding
}

/// One direction's packet protection.
pub enum PacketCipher {
    ChaChaPoly(TransportCipher),
    Ctr(Box<CtrCipher>),
    Gcm(GcmCipher),
}

impl PacketCipher {
    /// Build a direction's cipher from the keys `keys::derive_keys` produced for it. The key
    /// sizes are those `Cipher::key_len`, `Cipher::iv_len` and `Mac::key_len` name, which is what
    /// the derivation was asked for, so a mismatch is a programming error and panics.
    pub fn new(cipher: Cipher, mac: Option<Mac>, keys: &DirectionKeys) -> Self {
        let sized = "key material was derived at the negotiated cipher's sizes";
        match cipher {
            Cipher::Chacha20Poly1305 => Self::ChaChaPoly(TransportCipher::new(
                (&keys.key[..32]).try_into().expect(sized),
                (&keys.key[32..]).try_into().expect(sized),
            )),
            Cipher::Aes128Ctr | Cipher::Aes192Ctr | Cipher::Aes256Ctr => {
                let mac = mac.expect("a CTR cipher always has a negotiated MAC");
                Self::Ctr(Box::new(CtrCipher {
                    stream: CtrStream::new(cipher, &keys.key, &keys.iv),
                    mac,
                    mac_key: keys.mac_key.clone(),
                }))
            }
            Cipher::Aes128Gcm | Cipher::Aes256Gcm => Self::Gcm(GcmCipher::new(cipher, keys)),
        }
    }

    /// Frame and encrypt one payload as a wire packet. `seq` is this direction's packet counter.
    pub fn seal(&mut self, seq: u32, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::ChaChaPoly(c) => seal_chacha(c, seq, payload),
            Self::Ctr(c) => c.seal(seq, payload),
            Self::Gcm(c) => c.seal(payload),
        }
    }

    /// Read, authenticate and decrypt one wire packet, returning its payload.
    pub async fn open<R>(&mut self, reader: &mut R, seq: u32) -> Result<Vec<u8>, TransportError>
    where
        R: AsyncRead + Unpin,
    {
        match self {
            Self::ChaChaPoly(c) => open_chacha(c, reader, seq).await,
            Self::Ctr(c) => c.open(reader, seq).await,
            Self::Gcm(c) => c.open(reader).await,
        }
    }
}

impl From<TransportCipher> for PacketCipher {
    fn from(cipher: TransportCipher) -> Self {
        Self::ChaChaPoly(cipher)
    }
}

/// `padding_length || payload || padding`, the part of a packet every scheme encrypts.
fn inner_frame(payload: &[u8], padding_length: u8) -> Vec<u8> {
    let mut inner = Vec::with_capacity(1 + payload.len() + padding_length as usize);
    inner.push(padding_length);
    inner.extend_from_slice(payload);
    inner.extend_from_slice(&random_padding(padding_length));
    inner
}

/// The payload of a decrypted `padding_length || payload || padding`.
fn strip_inner_frame(inner: &[u8]) -> Result<Vec<u8>, TransportError> {
    let (&padding_length, rest) = inner
        .split_first()
        .ok_or(TransportError::Malformed("decrypted packet body is empty"))?;
    let payload_len =
        rest.len()
            .checked_sub(padding_length as usize)
            .ok_or(TransportError::Malformed(
                "padding_length exceeds decrypted packet body",
            ))?;
    Ok(rest[..payload_len].to_vec())
}

/// A packet length read from the wire (in the clear, or decrypted) checked before any buffer is
/// sized from it: bounded by the protocol ceiling and, where the scheme pads to a block, a
/// multiple of it.
fn check_length(packet_length: u32, aligned_to: usize) -> Result<usize, TransportError> {
    if packet_length == 0 {
        return Err(TransportError::Malformed(
            "encrypted packet_length is zero; too small to hold padding_length",
        ));
    }
    if packet_length > MAX_PACKET_SIZE {
        return Err(TransportError::TooLarge {
            claimed: packet_length,
            max: MAX_PACKET_SIZE,
        });
    }
    let len = packet_length as usize;
    if !len.is_multiple_of(aligned_to) {
        return Err(TransportError::Malformed(
            "packet_length is not a multiple of the cipher block size",
        ));
    }
    Ok(len)
}

// ---- chacha20-poly1305@openssh.com ----

fn seal_chacha(cipher: &mut TransportCipher, seq: u32, payload: &[u8]) -> Vec<u8> {
    let padding_length = padding_for(1 + payload.len(), Cipher::Chacha20Poly1305.block_len());
    cipher.encrypt(seq, &inner_frame(payload, padding_length))
}

async fn open_chacha<R>(
    cipher: &mut TransportCipher,
    reader: &mut R,
    seq: u32,
) -> Result<Vec<u8>, TransportError>
where
    R: AsyncRead + Unpin,
{
    let mut enc_len = [0u8; 4];
    reader.read_exact(&mut enc_len).await?;
    let packet_length = cipher.decrypt_length(seq, &enc_len);
    // The length is only authenticated by the tag that follows the body, so it is bounded here
    // (zero and oversize) but its alignment is left to that check.
    let len = check_length(packet_length, 1)?;

    let mut rest = vec![0u8; len + cipher::TAG_LEN];
    reader.read_exact(&mut rest).await?;
    let mut full = Vec::with_capacity(4 + rest.len());
    full.extend_from_slice(&enc_len);
    full.extend_from_slice(&rest);

    let inner = cipher
        .decrypt(seq, &full)
        .map_err(|_| TransportError::Malformed("encrypted packet authentication failed"))?;
    strip_inner_frame(&inner)
}

// ---- AES-CTR with a separate MAC ----

/// AES in CTR mode, one variant per key size.
enum CtrStream {
    A128(Ctr128BE<Aes128>),
    A192(Ctr128BE<Aes192>),
    A256(Ctr128BE<Aes256>),
}

impl CtrStream {
    fn new(cipher: Cipher, key: &[u8], iv: &[u8]) -> Self {
        let sized = "key material was derived at the negotiated cipher's sizes";
        match cipher {
            Cipher::Aes128Ctr => Self::A128(Ctr128BE::new_from_slices(key, iv).expect(sized)),
            Cipher::Aes192Ctr => Self::A192(Ctr128BE::new_from_slices(key, iv).expect(sized)),
            Cipher::Aes256Ctr => Self::A256(Ctr128BE::new_from_slices(key, iv).expect(sized)),
            _ => unreachable!("CtrStream is built only for the CTR ciphers"),
        }
    }

    /// Encrypt or decrypt in place; the keystream continues across calls, as SSH's does across
    /// packets.
    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::A128(s) => s.apply_keystream(buf),
            Self::A192(s) => s.apply_keystream(buf),
            Self::A256(s) => s.apply_keystream(buf),
        }
    }
}

pub struct CtrCipher {
    stream: CtrStream,
    mac: Mac,
    mac_key: Vec<u8>,
}

impl CtrCipher {
    fn tag(&self, parts: &[&[u8]]) -> Vec<u8> {
        mac_tag(self.mac, &self.mac_key, parts)
    }

    fn seal(&mut self, seq: u32, payload: &[u8]) -> Vec<u8> {
        let seq = seq.to_be_bytes();
        if self.mac.is_etm() {
            let padding_length = padding_for(1 + payload.len(), AES_BLOCK);
            let mut body = inner_frame(payload, padding_length);
            self.stream.apply(&mut body);
            let length = (body.len() as u32).to_be_bytes();
            let tag = self.tag(&[&seq, &length, &body]);
            let mut out = Vec::with_capacity(4 + body.len() + tag.len());
            out.extend_from_slice(&length);
            out.extend_from_slice(&body);
            out.extend_from_slice(&tag);
            out
        } else {
            let padding_length = padding_for(4 + 1 + payload.len(), AES_BLOCK);
            let inner = inner_frame(payload, padding_length);
            let mut packet = Vec::with_capacity(4 + inner.len());
            packet.extend_from_slice(&(inner.len() as u32).to_be_bytes());
            packet.extend_from_slice(&inner);
            let tag = self.tag(&[&seq, &packet]);
            self.stream.apply(&mut packet);
            packet.extend_from_slice(&tag);
            packet
        }
    }

    async fn open<R>(&mut self, reader: &mut R, seq: u32) -> Result<Vec<u8>, TransportError>
    where
        R: AsyncRead + Unpin,
    {
        let seq = seq.to_be_bytes();
        let tag_len = self.mac.tag_len();
        if self.mac.is_etm() {
            let mut length = [0u8; 4];
            reader.read_exact(&mut length).await?;
            let len = check_length(u32::from_be_bytes(length), AES_BLOCK)?;
            let mut rest = vec![0u8; len + tag_len];
            reader.read_exact(&mut rest).await?;
            let (body, tag) = rest.split_at_mut(len);
            if !mac_verify(self.mac, &self.mac_key, &[&seq, &length, body], tag) {
                return Err(TransportError::Malformed("packet MAC verification failed"));
            }
            self.stream.apply(body);
            strip_inner_frame(body)
        } else {
            // The length is inside the encrypted packet, so the first block is decrypted to
            // learn it; the keystream carries on from there for the rest.
            let mut first = [0u8; AES_BLOCK];
            reader.read_exact(&mut first).await?;
            self.stream.apply(&mut first);
            let packet_length = u32::from_be_bytes(first[..4].try_into().expect("4 bytes"));
            let len = check_length(packet_length, 1)?;
            // The whole packet, length field included, is a multiple of the block size, and the
            // first block is already read.
            if !(4 + len).is_multiple_of(AES_BLOCK) || 4 + len < AES_BLOCK {
                return Err(TransportError::Malformed(
                    "packet is not a whole number of cipher blocks",
                ));
            }
            let mut packet = Vec::with_capacity(4 + len + tag_len);
            packet.extend_from_slice(&first);
            packet.resize(4 + len, 0);
            reader.read_exact(&mut packet[AES_BLOCK..]).await?;
            self.stream.apply(&mut packet[AES_BLOCK..]);
            let mut tag = vec![0u8; tag_len];
            reader.read_exact(&mut tag).await?;
            if !mac_verify(self.mac, &self.mac_key, &[&seq, &packet], &tag) {
                return Err(TransportError::Malformed("packet MAC verification failed"));
            }
            strip_inner_frame(&packet[4..])
        }
    }
}

macro_rules! hmac_over {
    ($hash:ty, $key:expr, $parts:expr) => {{
        let mut mac = Hmac::<$hash>::new_from_slice($key).expect("HMAC accepts a key of any size");
        for part in $parts {
            mac.update(part);
        }
        mac
    }};
}

/// HMAC of the concatenation of `parts` under `key`, with the hash the MAC algorithm names.
fn mac_tag(alg: Mac, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    match alg {
        Mac::HmacSha256Etm | Mac::HmacSha256 => hmac_over!(Sha256, key, parts)
            .finalize()
            .into_bytes()
            .to_vec(),
        Mac::HmacSha512Etm | Mac::HmacSha512 => hmac_over!(Sha512, key, parts)
            .finalize()
            .into_bytes()
            .to_vec(),
        Mac::HmacSha1Etm | Mac::HmacSha1 => hmac_over!(Sha1, key, parts)
            .finalize()
            .into_bytes()
            .to_vec(),
    }
}

/// Constant-time check of `tag` against the HMAC of `parts`.
fn mac_verify(alg: Mac, key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    match alg {
        Mac::HmacSha256Etm | Mac::HmacSha256 => {
            hmac_over!(Sha256, key, parts).verify_slice(tag).is_ok()
        }
        Mac::HmacSha512Etm | Mac::HmacSha512 => {
            hmac_over!(Sha512, key, parts).verify_slice(tag).is_ok()
        }
        Mac::HmacSha1Etm | Mac::HmacSha1 => hmac_over!(Sha1, key, parts).verify_slice(tag).is_ok(),
    }
}

// ---- aes128-gcm@openssh.com, aes256-gcm@openssh.com ----

enum GcmKey {
    A128(Box<Aes128Gcm>),
    A256(Box<Aes256Gcm>),
}

pub struct GcmCipher {
    key: GcmKey,
    /// The nonce's fixed field: the first four bytes of the derived IV.
    fixed: [u8; 4],
    /// The nonce's invocation counter: the last eight bytes of the derived IV, a big-endian
    /// integer that advances by one for every packet in this direction.
    counter: u64,
}

impl GcmCipher {
    fn new(cipher: Cipher, keys: &DirectionKeys) -> Self {
        let sized = "key material was derived at the negotiated cipher's sizes";
        let key = match cipher {
            Cipher::Aes128Gcm => {
                GcmKey::A128(Box::new(Aes128Gcm::new_from_slice(&keys.key).expect(sized)))
            }
            Cipher::Aes256Gcm => {
                GcmKey::A256(Box::new(Aes256Gcm::new_from_slice(&keys.key).expect(sized)))
            }
            _ => unreachable!("GcmCipher is built only for the GCM ciphers"),
        };
        Self {
            key,
            fixed: keys.iv[..4].try_into().expect(sized),
            counter: u64::from_be_bytes(keys.iv[4..12].try_into().expect(sized)),
        }
    }

    /// The nonce for the packet about to be sent or received; advances the counter.
    fn next_nonce(&mut self) -> Nonce<U12> {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.fixed);
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        Nonce::from(nonce)
    }

    fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
        let padding_length = padding_for(1 + payload.len(), AES_BLOCK);
        let mut body = inner_frame(payload, padding_length);
        let length = (body.len() as u32).to_be_bytes();
        let nonce = self.next_nonce();
        let tag = match &self.key {
            GcmKey::A128(k) => {
                k.encrypt_inout_detached(&nonce, &length, body.as_mut_slice().into())
            }
            GcmKey::A256(k) => {
                k.encrypt_inout_detached(&nonce, &length, body.as_mut_slice().into())
            }
        }
        .expect("a packet is far below the GCM plaintext limit");
        let mut out = Vec::with_capacity(4 + body.len() + GCM_TAG_LEN);
        out.extend_from_slice(&length);
        out.extend_from_slice(&body);
        out.extend_from_slice(tag.as_slice());
        out
    }

    async fn open<R>(&mut self, reader: &mut R) -> Result<Vec<u8>, TransportError>
    where
        R: AsyncRead + Unpin,
    {
        let mut length = [0u8; 4];
        reader.read_exact(&mut length).await?;
        let len = check_length(u32::from_be_bytes(length), AES_BLOCK)?;
        let mut rest = vec![0u8; len + GCM_TAG_LEN];
        reader.read_exact(&mut rest).await?;
        let (body, tag) = rest.split_at_mut(len);
        let tag = Tag::from(<[u8; GCM_TAG_LEN]>::try_from(&*tag).expect("sized above"));
        let nonce = self.next_nonce();
        match &self.key {
            GcmKey::A128(k) => k.decrypt_inout_detached(&nonce, &length, (&mut *body).into(), &tag),
            GcmKey::A256(k) => k.decrypt_inout_detached(&nonce, &length, (&mut *body).into(), &tag),
        }
        .map_err(|_| TransportError::Malformed("encrypted packet authentication failed"))?;
        strip_inner_frame(body)
    }
}
