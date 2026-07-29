//! Curve25519-sha256 key exchange (RFC 8731). Provides the server-side `perform_kex_server`
//! that completes a Diffie-Hellman exchange over X25519, signs the exchange hash with the host
//! key, and derives session keys; and client-side helpers (`build_client_ecdh_init`,
//! `complete_kex_client`) so integration tests can act as a minimal SSH client without pulling
//! in a full third-party SSH implementation for this step.
//!
//! The exchange hash `H` is SHA-256 over the concatenation (RFC 8731 section 3.1):
//!   `V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K`
//! where each component is SSH-string encoded (uint32 length prefix + bytes) except `K`, which
//! is SSH mpint encoded (big-endian, sign-extended with a leading zero byte if the MSB is set).
//! Getting the mpint encoding wrong silently produces a different exchange hash and both sides
//! derive different session keys - the handshake just fails with no useful diagnostic.

use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::keys::{SessionKeys, derive_keys};
use super::{
    SSH_MSG_KEX_ECDH_INIT, SSH_MSG_KEX_ECDH_REPLY, TransportError, write_packet_unencrypted,
};
use crate::hostkey::HostKey;

/// Encode a big-endian byte slice as an SSH mpint (RFC 4251 section 5): strip unnecessary
/// leading zeros, prepend a zero byte if the MSB would make the value look negative, then
/// wrap as an SSH string (uint32 length prefix + value bytes). Zero is encoded as a
/// zero-length string.
pub fn encode_mpint(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros.
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &[], // all zeros
    };

    if stripped.is_empty() {
        // mpint zero: 4-byte length of 0, no value bytes.
        return vec![0, 0, 0, 0];
    }

    let needs_sign_byte = stripped[0] & 0x80 != 0;
    let value_len = stripped.len() + usize::from(needs_sign_byte);

    let mut out = Vec::with_capacity(4 + value_len);
    out.extend_from_slice(&(value_len as u32).to_be_bytes());
    if needs_sign_byte {
        out.push(0);
    }
    out.extend_from_slice(stripped);
    out
}

/// Compute the exchange hash H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
/// with each component SSH-string encoded and K as SSH mpint.
#[allow(clippy::too_many_arguments)]
fn compute_exchange_hash(
    v_c: &str,
    v_s: &str,
    i_c: &[u8],
    i_s: &[u8],
    k_s: &[u8],
    q_c: &[u8; 32],
    q_s: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 32] {
    let k_mpint = encode_mpint(shared_secret);

    let mut hasher = Sha256::new();

    // string V_C (client version, no CR-LF)
    hasher.update((v_c.len() as u32).to_be_bytes());
    hasher.update(v_c.as_bytes());

    // string V_S
    hasher.update((v_s.len() as u32).to_be_bytes());
    hasher.update(v_s.as_bytes());

    // string I_C (client KEXINIT payload, starting with SSH_MSG_KEXINIT)
    hasher.update((i_c.len() as u32).to_be_bytes());
    hasher.update(i_c);

    // string I_S
    hasher.update((i_s.len() as u32).to_be_bytes());
    hasher.update(i_s);

    // string K_S (host key blob)
    hasher.update((k_s.len() as u32).to_be_bytes());
    hasher.update(k_s);

    // string Q_C (client ephemeral public key, 32 bytes)
    hasher.update(32u32.to_be_bytes());
    hasher.update(q_c);

    // string Q_S (server ephemeral public key, 32 bytes)
    hasher.update(32u32.to_be_bytes());
    hasher.update(q_s);

    // mpint K (shared secret, already length-prefixed by encode_mpint)
    hasher.update(&k_mpint);

    hasher.finalize().into()
}

/// Server side of curve25519-sha256 key exchange. Parses the client's `SSH_MSG_KEX_ECDH_INIT`,
/// generates a server ephemeral X25519 keypair, computes the shared secret and exchange hash,
/// signs H with the host key, sends `SSH_MSG_KEX_ECDH_REPLY`, and returns session keys.
///
/// The caller is responsible for the KEXINIT exchange (already happened) and for sending/
/// receiving `SSH_MSG_NEWKEYS` after this returns.
pub async fn perform_kex_server<W>(
    writer: &mut W,
    host_key: &HostKey,
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    client_version: &str,
    server_version: &str,
    client_ecdh_init: &[u8],
) -> Result<SessionKeys, TransportError>
where
    W: AsyncWrite + Unpin,
{
    // Parse SSH_MSG_KEX_ECDH_INIT: byte(30) + string(Q_C)
    if client_ecdh_init.first() != Some(&SSH_MSG_KEX_ECDH_INIT) {
        return Err(TransportError::Malformed("expected SSH_MSG_KEX_ECDH_INIT"));
    }

    let q_c_len = u32::from_be_bytes(
        client_ecdh_init
            .get(1..5)
            .ok_or(TransportError::Malformed("truncated ECDH_INIT"))?
            .try_into()
            .expect("4 bytes"),
    ) as usize;

    if q_c_len != 32 {
        return Err(TransportError::Malformed(
            "Q_C must be exactly 32 bytes for X25519",
        ));
    }

    let q_c_bytes: [u8; 32] = client_ecdh_init
        .get(5..37)
        .ok_or(TransportError::Malformed("truncated Q_C in ECDH_INIT"))?
        .try_into()
        .expect("32 bytes");

    let client_public = PublicKey::from(q_c_bytes);

    // Generate server's ephemeral X25519 keypair.
    let server_secret = EphemeralSecret::random_from_rng(&mut rand::rng());
    let server_public = PublicKey::from(&server_secret);
    let q_s = server_public.to_bytes();

    // Compute shared secret K.
    let shared_secret = server_secret.diffie_hellman(&client_public);
    let k = shared_secret.as_bytes();

    // Host key blob K_S.
    let k_s = host_key.public_key_blob();

    // Exchange hash H.
    let h = compute_exchange_hash(
        client_version,
        server_version,
        client_kexinit,
        server_kexinit,
        &k_s,
        &q_c_bytes,
        &q_s,
        k,
    );

    // Sign H with the host key.
    let signature = host_key.sign(&h);

    // Build SSH_MSG_KEX_ECDH_REPLY: byte(31) + string(K_S) + string(Q_S) + string(signature).
    let mut reply = Vec::new();
    reply.push(SSH_MSG_KEX_ECDH_REPLY);
    write_ssh_string(&mut reply, &k_s);
    write_ssh_string(&mut reply, &q_s);
    write_ssh_string(&mut reply, &signature);

    write_packet_unencrypted(writer, &reply).await?;

    // Session ID = H on first key exchange.
    Ok(derive_keys(k, &h, &h))
}

/// Build a client's `SSH_MSG_KEX_ECDH_INIT` message. Returns the ephemeral secret (caller
/// must pass it to `complete_kex_client` to compute the shared secret) and the wire payload.
pub fn build_client_ecdh_init() -> (EphemeralSecret, Vec<u8>) {
    let secret = EphemeralSecret::random_from_rng(&mut rand::rng());
    let public = PublicKey::from(&secret);
    let q_c = public.to_bytes();

    let mut payload = Vec::with_capacity(1 + 4 + 32);
    payload.push(SSH_MSG_KEX_ECDH_INIT);
    write_ssh_string(&mut payload, &q_c);

    (secret, payload)
}

/// Complete key exchange on the client side: parse the server's `SSH_MSG_KEX_ECDH_REPLY`,
/// compute the shared secret and exchange hash, and derive session keys. Host key signature
/// verification is intentionally omitted - this is a test helper for proving both sides derive
/// the same keys, not a production SSH client.
pub fn complete_kex_client(
    client_ephemeral: EphemeralSecret,
    ecdh_reply_payload: &[u8],
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    client_version: &str,
    server_version: &str,
) -> Result<SessionKeys, TransportError> {
    // Parse SSH_MSG_KEX_ECDH_REPLY: byte(31) + string(K_S) + string(Q_S) + string(signature).
    if ecdh_reply_payload.first() != Some(&SSH_MSG_KEX_ECDH_REPLY) {
        return Err(TransportError::Malformed("expected SSH_MSG_KEX_ECDH_REPLY"));
    }

    let mut cursor = 1usize;

    let k_s = read_ssh_string(ecdh_reply_payload, &mut cursor)?;

    let q_s_bytes = read_ssh_string(ecdh_reply_payload, &mut cursor)?;
    if q_s_bytes.len() != 32 {
        return Err(TransportError::Malformed(
            "Q_S must be exactly 32 bytes for X25519",
        ));
    }
    let q_s: [u8; 32] = q_s_bytes.try_into().expect("32 bytes");

    // Signature is parsed but not verified (test helper only).
    let _signature = read_ssh_string(ecdh_reply_payload, &mut cursor)?;

    // Compute Q_C from the ephemeral secret before consuming it.
    let q_c = PublicKey::from(&client_ephemeral).to_bytes();

    // Shared secret K.
    let server_public = PublicKey::from(q_s);
    let shared_secret = client_ephemeral.diffie_hellman(&server_public);
    let k = shared_secret.as_bytes();

    // Exchange hash H.
    let h = compute_exchange_hash(
        client_version,
        server_version,
        client_kexinit,
        server_kexinit,
        &k_s,
        &q_c,
        &q_s,
        k,
    );

    // Session ID = H on first exchange.
    Ok(derive_keys(k, &h, &h))
}

/// Write `string data` (RFC 4251 section 5: uint32 length prefix + raw bytes) into `out`.
fn write_ssh_string(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
}

/// Read an SSH string (uint32 length + bytes) from `data` at `cursor`.
fn read_ssh_string(data: &[u8], cursor: &mut usize) -> Result<Vec<u8>, TransportError> {
    if *cursor + 4 > data.len() {
        return Err(TransportError::Malformed(
            "truncated string length in ECDH message",
        ));
    }
    let len = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().expect("4 bytes")) as usize;
    *cursor += 4;
    if *cursor + len > data.len() {
        return Err(TransportError::Malformed(
            "truncated string data in ECDH message",
        ));
    }
    let result = data[*cursor..*cursor + len].to_vec();
    *cursor += len;
    Ok(result)
}
