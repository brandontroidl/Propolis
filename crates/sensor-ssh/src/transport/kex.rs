//! Key exchange: `curve25519-sha256` (RFC 8731, also under its pre-standard name
//! `curve25519-sha256@libssh.org`), `ecdh-sha2-nistp256` (RFC 5656) and
//! `diffie-hellman-group14-sha256` (RFC 8268). Provides the server-side `perform_kex_server`,
//! which completes the negotiated exchange, signs the exchange hash with the host key and derives
//! session keys; and client-side helpers (`build_client_ecdh_init`, `complete_kex_client`) so
//! tests can act as a minimal curve25519 SSH client without a third-party SSH implementation.
//! The system OpenSSH client, not those helpers, is what proves the other two exchanges.
//!
//! All three hash with SHA-256. The exchange hash `H` is SHA-256 over
//! `V_C || V_S || I_C || I_S || K_S || <client value> || <server value> || K`, each component
//! SSH-string encoded (uint32 length prefix + bytes) except `K` and, for Diffie-Hellman, the two
//! public values, which are SSH mpints (big-endian, sign-extended with a leading zero byte if the
//! MSB is set). For the elliptic-curve exchanges the two public values are strings (the encoded
//! points, 32 bytes for X25519, SEC1 uncompressed for P-256). Getting an encoding wrong silently
//! produces a different exchange hash and both sides derive different session keys - the
//! handshake just fails with no useful diagnostic.

use num_bigint::BigUint;
use rand::RngExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWrite;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::algorithms::{Kex, Negotiated};
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

/// What both ends have already said to each other before the key exchange proper: the
/// identification strings (`V_C`, `V_S`, without the line terminator) and the KEXINIT payloads
/// (`I_C`, `I_S`). Every exchange hash starts with these four, so a man in the middle who changed
/// an algorithm list or a banner would change the hash and break the signature.
#[derive(Debug, Clone, Copy)]
pub struct Transcript<'a> {
    pub client_version: &'a str,
    pub server_version: &'a str,
    pub client_kexinit: &'a [u8],
    pub server_kexinit: &'a [u8],
}

fn hash_string(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u32).to_be_bytes());
    hasher.update(data);
}

/// The part of every exchange hash that precedes the key-exchange-specific values:
/// `V_C || V_S || I_C || I_S || K_S`, each as an SSH string.
fn hash_prefix(transcript: &Transcript<'_>, k_s: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hash_string(&mut hasher, transcript.client_version.as_bytes());
    hash_string(&mut hasher, transcript.server_version.as_bytes());
    hash_string(&mut hasher, transcript.client_kexinit);
    hash_string(&mut hasher, transcript.server_kexinit);
    hash_string(&mut hasher, k_s);
    hasher
}

/// `H` for the elliptic-curve exchanges: the two ephemeral public keys as strings, then `K`.
fn ecdh_exchange_hash(
    transcript: &Transcript<'_>,
    k_s: &[u8],
    q_c: &[u8],
    q_s: &[u8],
    shared_secret: &[u8],
) -> [u8; 32] {
    let mut hasher = hash_prefix(transcript, k_s);
    hash_string(&mut hasher, q_c);
    hash_string(&mut hasher, q_s);
    hasher.update(encode_mpint(shared_secret));
    hasher.finalize().into()
}

/// `H` for Diffie-Hellman: `e`, `f` and `K` as mpints (RFC 4253 section 8).
fn dh_exchange_hash(
    transcript: &Transcript<'_>,
    k_s: &[u8],
    e: &BigUint,
    f: &BigUint,
    shared_secret: &BigUint,
) -> [u8; 32] {
    let mut hasher = hash_prefix(transcript, k_s);
    hasher.update(encode_mpint(&e.to_bytes_be()));
    hasher.update(encode_mpint(&f.to_bytes_be()));
    hasher.update(encode_mpint(&shared_secret.to_bytes_be()));
    hasher.finalize().into()
}

/// Server side of the negotiated key exchange. Parses the client's `SSH_MSG_KEX_ECDH_INIT` (the
/// same message type, 30, carries the elliptic-curve value and, as `SSH_MSG_KEXDH_INIT`, the
/// Diffie-Hellman `e`), generates the server's ephemeral value, computes the shared secret and
/// exchange hash, signs H with the host key, sends the reply (type 31), and returns session keys.
///
/// The caller is responsible for the KEXINIT exchange (already happened) and for sending/
/// receiving `SSH_MSG_NEWKEYS` after this returns.
pub async fn perform_kex_server<W>(
    writer: &mut W,
    host_key: &HostKey,
    transcript: &Transcript<'_>,
    client_init: &[u8],
    negotiated: &Negotiated,
) -> Result<SessionKeys, TransportError>
where
    W: AsyncWrite + Unpin,
{
    if client_init.first() != Some(&SSH_MSG_KEX_ECDH_INIT) {
        return Err(TransportError::Malformed("expected SSH_MSG_KEX_ECDH_INIT"));
    }
    let mut cursor = 1usize;
    let k_s = host_key.public_key_blob();
    let (reply, k, h) = match negotiated.kex {
        Kex::Curve25519Sha256 | Kex::Curve25519Sha256Libssh => {
            curve25519_server(host_key, transcript, &k_s, client_init, &mut cursor)?
        }
        Kex::EcdhSha2Nistp256 => {
            ecdh_p256_server(host_key, transcript, &k_s, client_init, &mut cursor)?
        }
        // Two 2048-bit exponentiations, about 3 ms: off the async worker (the sensor runs two), so
        // a burst of these cannot stall every other session. How many run at once is the caller's
        // to bound (`group14_gate`).
        Kex::DiffieHellmanGroup14Sha256 => {
            let host_key = host_key.clone();
            let k_s = k_s.clone();
            let client_init = client_init.to_vec();
            let owned = (
                transcript.client_version.to_owned(),
                transcript.server_version.to_owned(),
                transcript.client_kexinit.to_vec(),
                transcript.server_kexinit.to_vec(),
            );
            tokio::task::spawn_blocking(move || {
                let transcript = Transcript {
                    client_version: &owned.0,
                    server_version: &owned.1,
                    client_kexinit: &owned.2,
                    server_kexinit: &owned.3,
                };
                dh_group14_server(&host_key, &transcript, &k_s, &client_init, &mut cursor)
            })
            .await
            .map_err(|e| TransportError::Io(std::io::Error::other(e)))??
        }
    };
    write_packet_unencrypted(writer, &reply).await?;

    // Session ID = H on first key exchange.
    Ok(derive_keys(&k, &h, &h, negotiated))
}

/// What one server-side exchange produces: the reply payload, the shared secret `K` (big-endian
/// bytes) and the exchange hash `H`.
type ServerExchange = (Vec<u8>, Vec<u8>, [u8; 32]);

fn curve25519_server(
    host_key: &HostKey,
    transcript: &Transcript<'_>,
    k_s: &[u8],
    client_init: &[u8],
    cursor: &mut usize,
) -> Result<ServerExchange, TransportError> {
    let q_c = read_ssh_string(client_init, cursor)?;
    let q_c_bytes: [u8; 32] = q_c
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::Malformed("Q_C must be exactly 32 bytes for X25519"))?;
    let client_public = PublicKey::from(q_c_bytes);

    let server_secret = EphemeralSecret::random_from_rng(&mut rand::rng());
    let q_s = PublicKey::from(&server_secret).to_bytes();
    let shared_secret = server_secret.diffie_hellman(&client_public);
    let k = shared_secret.as_bytes();

    let h = ecdh_exchange_hash(transcript, k_s, &q_c_bytes, &q_s, k);
    let reply = ecdh_reply(k_s, &q_s, &host_key.sign(&h));
    Ok((reply, k.to_vec(), h))
}

fn ecdh_p256_server(
    host_key: &HostKey,
    transcript: &Transcript<'_>,
    k_s: &[u8],
    client_init: &[u8],
    cursor: &mut usize,
) -> Result<ServerExchange, TransportError> {
    use p256::elliptic_curve::Generate;

    let q_c = read_ssh_string(client_init, cursor)?;
    // `from_sec1_bytes` refuses a point that is not on the curve, the identity, and a malformed
    // encoding (RFC 5656 section 4: the server must validate the client's public key).
    let client_public = p256::PublicKey::from_sec1_bytes(&q_c)
        .map_err(|_| TransportError::Malformed("Q_C is not a valid P-256 point"))?;

    let server_secret = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
    let q_s = p256::Sec1Point::from(server_secret.public_key());
    let shared_secret = server_secret.diffie_hellman(&client_public);
    let k = shared_secret.raw_secret_bytes();

    let h = ecdh_exchange_hash(transcript, k_s, &q_c, q_s.as_bytes(), k);
    let reply = ecdh_reply(k_s, q_s.as_bytes(), &host_key.sign(&h));
    Ok((reply, k.to_vec(), h))
}

/// `SSH_MSG_KEX_ECDH_REPLY`: byte(31) + string(K_S) + string(Q_S) + string(signature).
fn ecdh_reply(k_s: &[u8], q_s: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut reply = vec![SSH_MSG_KEX_ECDH_REPLY];
    write_ssh_string(&mut reply, k_s);
    write_ssh_string(&mut reply, q_s);
    write_ssh_string(&mut reply, signature);
    reply
}

/// The 2048-bit MODP group 14 prime (RFC 3526 section 3), a safe prime, and its generator 2.
/// `diffie-hellman-group14-sha256` is defined over it (RFC 8268 section 3).
const GROUP14_PRIME_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05",
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
);

fn group14_prime() -> BigUint {
    static PRIME: std::sync::OnceLock<BigUint> = std::sync::OnceLock::new();
    PRIME
        .get_or_init(|| {
            BigUint::parse_bytes(GROUP14_PRIME_HEX.as_bytes(), 16)
                .expect("GROUP14_PRIME_HEX is hexadecimal")
        })
        .clone()
}

/// The server's private exponent size: 256 bits, over twice the roughly 112-bit strength of a
/// 2048-bit group (a short exponent costs a discrete-log attack its square root, so it needs twice
/// the strength in bits) and about half the running time of a 512-bit one. A client picks this
/// exchange at will and each one costs the sensor two modular exponentiations before any
/// authentication, so the time per exchange is worth keeping down.
const DH_EXPONENT_BYTES: usize = 32;

/// Largest encoded `e` accepted: the 2048-bit modulus plus the mpint sign byte.
const DH_MAX_PUBLIC_BYTES: usize = 257;

/// `SSH_MSG_KEXDH_INIT`: byte(30) + mpint(e). Read as non-negative.
fn read_mpint(data: &[u8], cursor: &mut usize) -> Result<BigUint, TransportError> {
    let bytes = read_ssh_string(data, cursor)?;
    if bytes.len() > DH_MAX_PUBLIC_BYTES {
        return Err(TransportError::Malformed("Diffie-Hellman value too large"));
    }
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        return Err(TransportError::Malformed(
            "Diffie-Hellman value is a negative mpint",
        ));
    }
    Ok(BigUint::from_bytes_be(&bytes))
}

fn dh_group14_server(
    host_key: &HostKey,
    transcript: &Transcript<'_>,
    k_s: &[u8],
    client_init: &[u8],
    cursor: &mut usize,
) -> Result<ServerExchange, TransportError> {
    let p = group14_prime();
    let e = read_mpint(client_init, cursor)?;
    // RFC 4253 section 8: e must satisfy 1 < e < p - 1. For 0, 1 and p - 1 the shared secret is
    // 0, 1 or +-1 whatever the server's exponent, a value the client knows without the exchange.
    // p is a safe prime, so 1 and p - 1 are the only elements of small order.
    let one = BigUint::from(1u8);
    if e <= one || e >= &p - &one {
        return Err(TransportError::Malformed(
            "Diffie-Hellman value out of range",
        ));
    }

    // y: a uniformly random DH_EXPONENT_BYTES-byte integer, at least 2. The exponent is secret
    // only for this one exchange and the peer is the other party to it, so `modpow`'s variable
    // running time discloses nothing that peer does not already hold.
    let y = loop {
        let mut bytes = [0u8; DH_EXPONENT_BYTES];
        rand::rng().fill(&mut bytes[..]);
        let y = BigUint::from_bytes_be(&bytes);
        if y > one {
            break y;
        }
    };
    let f = BigUint::from(2u8).modpow(&y, &p);
    let shared_secret = e.modpow(&y, &p);

    let h = dh_exchange_hash(transcript, k_s, &e, &f, &shared_secret);
    // SSH_MSG_KEXDH_REPLY: byte(31) + string(K_S) + mpint(f) + string(signature).
    let mut reply = vec![SSH_MSG_KEX_ECDH_REPLY];
    write_ssh_string(&mut reply, k_s);
    reply.extend_from_slice(&encode_mpint(&f.to_bytes_be()));
    write_ssh_string(&mut reply, &host_key.sign(&h));
    Ok((reply, shared_secret.to_bytes_be(), h))
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

/// Complete a curve25519 key exchange on the client side: parse the server's
/// `SSH_MSG_KEX_ECDH_REPLY`, compute the shared secret and exchange hash, and derive session
/// keys. Host key signature verification is intentionally omitted - this is a test helper for
/// proving both sides derive the same keys, not a production SSH client.
pub fn complete_kex_client(
    client_ephemeral: EphemeralSecret,
    ecdh_reply_payload: &[u8],
    transcript: &Transcript<'_>,
    negotiated: &Negotiated,
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
    let h = ecdh_exchange_hash(transcript, &k_s, &q_c, &q_s, k);

    // Session ID = H on first exchange.
    Ok(derive_keys(k, &h, &h, negotiated))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::algorithms::{Cipher, HostKeyAlgorithm};
    use crate::transport::read_packet_unencrypted;

    fn negotiated(kex: Kex) -> Negotiated {
        Negotiated {
            kex,
            host_key: HostKeyAlgorithm::SshEd25519,
            cipher_client_to_server: Cipher::Chacha20Poly1305,
            cipher_server_to_client: Cipher::Chacha20Poly1305,
            mac_client_to_server: None,
            mac_server_to_client: None,
            discard_guess: false,
        }
    }

    const TRANSCRIPT: Transcript<'static> = Transcript {
        client_version: "SSH-2.0-client",
        server_version: "SSH-2.0-server",
        client_kexinit: b"client kexinit",
        server_kexinit: b"server kexinit",
    };

    /// Miller-Rabin to the given bases. Probabilistic in general; used here to catch a wrong
    /// digit in a constant, where a corrupted prime is composite with overwhelming probability.
    fn passes_miller_rabin(n: &BigUint, bases: &[u32]) -> bool {
        let one = BigUint::from(1u8);
        let n_minus_1 = n - &one;
        let mut d = n_minus_1.clone();
        let mut r = 0u32;
        while !d.bit(0) {
            d >>= 1;
            r += 1;
        }
        'bases: for &a in bases {
            let mut x = BigUint::from(a).modpow(&d, n);
            if x == one || x == n_minus_1 {
                continue;
            }
            for _ in 1..r {
                x = (&x * &x) % n;
                if x == n_minus_1 {
                    continue 'bases;
                }
            }
            return false;
        }
        true
    }

    /// The prime is typed in, so a slipped digit would make `diffie-hellman-group14-sha256`
    /// fail against every client with an error that looks like a wrong password. It is a safe
    /// prime (p and (p - 1) / 2 both prime), 2048 bits, with the all-ones top and bottom 64 bits
    /// RFC 3526 gives it.
    #[test]
    fn the_group14_prime_is_a_2048_bit_safe_prime_of_the_rfc_shape() {
        let p = group14_prime();
        assert_eq!(p.bits(), 2048);
        let bytes = p.to_bytes_be();
        assert!(bytes[..8].iter().all(|&b| b == 0xff));
        assert!(bytes[bytes.len() - 8..].iter().all(|&b| b == 0xff));
        let q = (&p - 1u8) >> 1;
        assert!(passes_miller_rabin(&p, &[2, 3, 5]));
        assert!(passes_miller_rabin(&q, &[2, 3, 5]));
        // A one-digit corruption is caught.
        let corrupted = &p ^ BigUint::from(0x10u8);
        assert!(!passes_miller_rabin(&corrupted, &[2, 3, 5]));
    }

    fn dh_init(e: &[u8]) -> Vec<u8> {
        let mut init = vec![SSH_MSG_KEX_ECDH_INIT];
        write_ssh_string(&mut init, e);
        init
    }

    async fn exchange(
        kex: Kex,
        init: &[u8],
        host_key: &HostKey,
    ) -> Result<Vec<u8>, TransportError> {
        let mut wire = Vec::new();
        perform_kex_server(&mut wire, host_key, &TRANSCRIPT, init, &negotiated(kex)).await?;
        Ok(read_packet_unencrypted(&mut wire.as_slice())
            .await
            .unwrap()
            .payload)
    }

    #[tokio::test]
    async fn dh_group14_agrees_on_a_secret_the_signature_covers() {
        let host_key = HostKey::generate();
        let p = group14_prime();
        let x = BigUint::from(0x1234_5678_9abc_def0u64);
        let e = BigUint::from(2u8).modpow(&x, &p);
        let reply = exchange(
            Kex::DiffieHellmanGroup14Sha256,
            &dh_init(&encode_mpint(&e.to_bytes_be())[4..]),
            &host_key,
        )
        .await
        .unwrap();

        assert_eq!(reply[0], SSH_MSG_KEX_ECDH_REPLY);
        let mut cursor = 1;
        let k_s = read_ssh_string(&reply, &mut cursor).unwrap();
        let f = BigUint::from_bytes_be(&read_ssh_string(&reply, &mut cursor).unwrap());
        let signature = read_ssh_string(&reply, &mut cursor).unwrap();
        assert_eq!(k_s, host_key.public_key_blob());
        // f is a group element, and the client's own K = f^x is what the server signed.
        assert!(f > BigUint::from(1u8) && f < p);
        let k = f.modpow(&x, &p);
        let h = dh_exchange_hash(&TRANSCRIPT, &k_s, &e, &f, &k);
        assert!(host_key.verify(&h, &signature));
        // A client that derived a different K would have hashed something else.
        let wrong = dh_exchange_hash(&TRANSCRIPT, &k_s, &e, &f, &(&k + 1u8));
        assert!(!host_key.verify(&wrong, &signature));
    }

    #[tokio::test]
    async fn dh_group14_refuses_values_outside_one_to_p_minus_one() {
        let host_key = HostKey::generate();
        let p = group14_prime();
        let one = BigUint::from(1u8);
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("0", encode_mpint(&[])[4..].to_vec()),
            ("1", vec![1]),
            (
                "p - 1",
                encode_mpint(&(&p - &one).to_bytes_be())[4..].to_vec(),
            ),
            ("p", encode_mpint(&p.to_bytes_be())[4..].to_vec()),
            (
                "p + 1",
                encode_mpint(&(&p + &one).to_bytes_be())[4..].to_vec(),
            ),
            ("negative", vec![0x80, 1, 2, 3]),
            ("oversize", vec![0x7f; DH_MAX_PUBLIC_BYTES + 1]),
        ];
        cases.push(("truncated", Vec::new()));
        for (what, e) in cases {
            let init = if what == "truncated" {
                vec![SSH_MSG_KEX_ECDH_INIT, 0, 0]
            } else {
                dh_init(&e)
            };
            let got = exchange(Kex::DiffieHellmanGroup14Sha256, &init, &host_key).await;
            assert!(
                matches!(got, Err(TransportError::Malformed(_))),
                "e = {what}: {got:?}"
            );
        }
        // The boundaries just inside are accepted.
        for e in [BigUint::from(2u8), &p - 2u8] {
            let init = dh_init(&encode_mpint(&e.to_bytes_be())[4..]);
            exchange(Kex::DiffieHellmanGroup14Sha256, &init, &host_key)
                .await
                .unwrap_or_else(|err| panic!("e = {e}: {err}"));
        }
    }

    #[tokio::test]
    async fn ecdh_p256_agrees_on_a_secret_the_signature_covers() {
        use p256::elliptic_curve::Generate;
        let host_key = HostKey::generate();
        let client = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let q_c = p256::Sec1Point::from(client.public_key());
        assert_eq!((q_c.as_bytes().len(), q_c.as_bytes()[0]), (65, 0x04));

        let reply = exchange(Kex::EcdhSha2Nistp256, &dh_init(q_c.as_bytes()), &host_key)
            .await
            .unwrap();
        assert_eq!(reply[0], SSH_MSG_KEX_ECDH_REPLY);
        let mut cursor = 1;
        let k_s = read_ssh_string(&reply, &mut cursor).unwrap();
        let q_s = read_ssh_string(&reply, &mut cursor).unwrap();
        let signature = read_ssh_string(&reply, &mut cursor).unwrap();
        assert_eq!((q_s.len(), q_s[0]), (65, 0x04));
        let server_public = p256::PublicKey::from_sec1_bytes(&q_s).unwrap();
        let shared = client.diffie_hellman(&server_public);
        let k = shared.raw_secret_bytes();
        assert_eq!(k.len(), 32);
        let h = ecdh_exchange_hash(&TRANSCRIPT, &k_s, q_c.as_bytes(), &q_s, k);
        assert!(host_key.verify(&h, &signature));
    }

    #[tokio::test]
    async fn ecdh_p256_refuses_a_public_key_that_is_not_a_curve_point() {
        let host_key = HostKey::generate();
        let mut off_curve = vec![0x04];
        off_curve.extend_from_slice(&[0u8; 31]);
        off_curve.push(1); // x = 1
        off_curve.extend_from_slice(&[0u8; 31]);
        off_curve.push(1); // y = 1: 1 != 1 + a + b on P-256
        let cases: [(&str, Vec<u8>); 6] = [
            ("empty", Vec::new()),
            ("identity", vec![0x00]),
            ("all zero", vec![0u8; 65]),
            ("off the curve", off_curve),
            ("truncated", vec![0x04; 40]),
            ("a curve25519-sized value", vec![9u8; 32]),
        ];
        for (what, q_c) in cases {
            let got = exchange(Kex::EcdhSha2Nistp256, &dh_init(&q_c), &host_key).await;
            assert!(
                matches!(got, Err(TransportError::Malformed(_))),
                "{what}: {got:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_exchange_is_chosen_by_the_negotiated_name_not_guessed_from_the_message() {
        // A curve25519 value (32 bytes) is not a valid P-256 point, so it is refused under that
        // method, and is accepted under the one it was made for.
        let host_key = HostKey::generate();
        let (_, init) = build_client_ecdh_init();
        assert!(
            exchange(Kex::EcdhSha2Nistp256, &init, &host_key)
                .await
                .is_err()
        );
        assert!(
            exchange(Kex::Curve25519Sha256, &init, &host_key)
                .await
                .is_ok()
        );
    }
}
