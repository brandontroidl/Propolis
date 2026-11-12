//! Ed25519 host key: generation, disk persistence, and the RFC 8709 wire encodings key
//! exchange (Task 11) signs and verifies the exchange hash with (see "Host key" in
//! `internal/design/02-sensor-framework.md` and ADR-0011's pinned ed25519-dalek primitive).
//!
//! `HostKey` derives `Clone` (`ed25519_dalek::SigningKey` already does) since later tasks hand
//! the same key to multiple concurrent connection-handling async tasks; ed25519 has no
//! per-signature mutable state, so cloning the key is exactly as safe as sharing a reference
//! and avoids threading a lifetime through every connection task.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use std::io;
use std::path::Path;

/// The IANA-registered SSH public key algorithm name for ed25519 (RFC 8709 sections 3-6):
/// both the public key blob and the signature blob are prefixed with this same string.
const SSH_ED25519: &[u8] = b"ssh-ed25519";

/// This server's persistent identity key. Wraps `ed25519_dalek::SigningKey`; every method here
/// exists to produce or consume the RFC 8709 wire encodings rather than raw key bytes, since
/// nothing outside this module should need to touch the ed25519 primitive directly.
#[derive(Clone)]
pub struct HostKey {
    signing_key: SigningKey,
}

impl HostKey {
    /// Generate a fresh key from the OS CSPRNG (`rand::rng()`, periodically reseeded from
    /// the OS - see `rand::rngs::ThreadRng`; this crate's `rand` version renamed the classic
    /// `OsRng` to `SysRng` and dropped the old name entirely, so `rand::rng()` is both the
    /// simplest available source and the one already used elsewhere in this crate for
    /// non-key randomness, e.g. `transport`'s KEXINIT cookie).
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut rand::rng()),
        }
    }

    /// Persist the raw 32-byte secret scalar to `path`, creating it (or truncating an existing
    /// file) with mode 0600 from the moment it exists - never a wider mode later narrowed - and
    /// re-asserting 0600 after writing so re-saving over a file some other process created with
    /// looser permissions still ends at the intended mode. Non-unix targets get plain
    /// create+write (no POSIX permission bits to set).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        use std::io::Write;

        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        file.write_all(&self.signing_key.to_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load a key previously written by `save`: the file is exactly the 32-byte secret scalar,
    /// nothing else.
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "host key file is not 32 bytes")
        })?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&key_bytes),
        })
    }

    /// The RFC 8709 section 4 public key blob: `string "ssh-ed25519"` + `string <32-byte key>`.
    /// This is the exact byte string KEXINIT's `server_host_key_algorithms` negotiation commits
    /// this server to sending as `K_S` during key exchange.
    pub fn public_key_blob(&self) -> Vec<u8> {
        let verifying_key = self.signing_key.verifying_key();
        write_ssh_strings(SSH_ED25519, verifying_key.as_bytes())
    }

    /// The RFC 8709 section 6 signature blob over `data`: `string "ssh-ed25519"` +
    /// `string <64-byte signature>`. `data` is whatever the caller has already hashed/framed
    /// per its own protocol step (the key exchange hash, for Task 11); this method does no
    /// hashing of its own.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(data);
        write_ssh_strings(SSH_ED25519, &signature.to_bytes())
    }

    /// Verify a RFC 8709 signature blob (as produced by `sign`) against `data`, using this
    /// key's own public half. The SSH protocol never requires a server to verify its own host
    /// key signature - the connecting client does that with the public key alone - so this
    /// exists for round-trip testing and for any later task that wants to re-check a signature
    /// generically. `sig_blob` is treated as untrusted: any malformed, truncated, or
    /// wrong-algorithm blob returns `false` rather than panicking.
    pub fn verify(&self, data: &[u8], sig_blob: &[u8]) -> bool {
        let Some((algo, sig_bytes)) = parse_ssh_strings(sig_blob) else {
            return false;
        };
        if algo != SSH_ED25519 {
            return false;
        }
        let Ok(sig_array) = <[u8; 64]>::try_from(sig_bytes) else {
            return false;
        };
        let signature = Signature::from_bytes(&sig_array);
        self.signing_key
            .verifying_key()
            .verify(data, &signature)
            .is_ok()
    }
}

/// Build `string a` + `string b` (RFC 4251 section 5's `string` encoding: a 4-byte big-endian
/// length prefix followed by the raw bytes), the shared shape of both the public key blob and
/// the signature blob.
fn write_ssh_strings(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + a.len() + 4 + b.len());
    out.extend_from_slice(&(a.len() as u32).to_be_bytes());
    out.extend_from_slice(a);
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
    out
}

/// Parse `string a` + `string b` back out. Every offset is derived from a length field read out
/// of `data` itself and checked with `.get(..)` before use, so a truncated buffer or a length
/// prefix that claims more than is actually present returns `None` rather than panicking - this
/// parses a caller-supplied signature blob that, unlike `sign`'s own output, is not guaranteed
/// to be well-formed.
fn parse_ssh_strings(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let a_len = u32::from_be_bytes(data.get(0..4)?.try_into().ok()?) as usize;
    let rest = data.get(4..)?;
    let a = rest.get(..a_len)?;
    let rest = rest.get(a_len..)?;
    let b_len = u32::from_be_bytes(rest.get(0..4)?.try_into().ok()?) as usize;
    let rest = rest.get(4..)?;
    let b = rest.get(..b_len)?;
    Some((a, b))
}
