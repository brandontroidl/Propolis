//! The algorithms this server speaks, in the order it offers them, and the negotiation that
//! picks among them (RFC 4253 section 7.1).
//!
//! One table per KEXINIT slot is the single source of truth: `build_kexinit` renders the offer
//! from it and `negotiate` matches the client's lists against it, so the lists the server sends
//! and the algorithms it will actually run cannot drift apart. Adding an algorithm means adding a
//! variant here and the code that runs it; nothing is advertised that has no implementation.
//!
//! Negotiation follows the RFC to the letter, because a client that is refused silently (the
//! failure this module exists to end) is capture lost: for each list the algorithm is the first
//! one the CLIENT names that the server also supports. When any list has no match the connection
//! cannot proceed, and the caller says so with `SSH_MSG_DISCONNECT` instead of going quiet.

/// A negotiable algorithm: a closed set with a wire name.
pub trait Algorithm: Copy + 'static {
    /// Every algorithm of this kind the server supports, in the order it offers them.
    const ALL: &'static [Self];
    fn name(self) -> &'static str;
    fn from_name(name: &str) -> Option<Self>;
}

macro_rules! algorithms {
    ($(#[$meta:meta])* $ty:ident { $($variant:ident => $name:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $ty {
            $($variant),+
        }

        impl Algorithm for $ty {
            const ALL: &'static [Self] = &[$($ty::$variant),+];

            fn name(self) -> &'static str {
                match self {
                    $($ty::$variant => $name),+
                }
            }

            fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some($ty::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

algorithms! {
    /// Key exchange methods, in OpenSSH 8.9's order. `Curve25519Sha256Libssh` is RFC 8731's
    /// `curve25519-sha256` under the name OpenSSH and PuTTY used before it was standardised: the
    /// same exchange, byte for byte. All hash with SHA-256.
    Kex {
        Curve25519Sha256 => "curve25519-sha256",
        Curve25519Sha256Libssh => "curve25519-sha256@libssh.org",
        EcdhSha2Nistp256 => "ecdh-sha2-nistp256",
        DiffieHellmanGroup14Sha256 => "diffie-hellman-group14-sha256",
    }
}

algorithms! {
    /// Server host key (signature) algorithms.
    HostKeyAlgorithm {
        SshEd25519 => "ssh-ed25519",
    }
}

algorithms! {
    /// Transport ciphers, in OpenSSH 8.9's order. The AEADs (`Chacha20Poly1305`, the GCMs)
    /// authenticate themselves and negotiate no MAC; the CTR modes need one.
    Cipher {
        Chacha20Poly1305 => "chacha20-poly1305@openssh.com",
        Aes128Ctr => "aes128-ctr",
        Aes192Ctr => "aes192-ctr",
        Aes256Ctr => "aes256-ctr",
        Aes128Gcm => "aes128-gcm@openssh.com",
        Aes256Gcm => "aes256-gcm@openssh.com",
    }
}

algorithms! {
    /// Message authentication codes, in OpenSSH 8.9's order (its UMAC entries are not offered).
    /// `*Etm` is encrypt-then-MAC: the MAC covers the ciphertext and the packet length is sent
    /// in the clear.
    Mac {
        HmacSha256Etm => "hmac-sha2-256-etm@openssh.com",
        HmacSha512Etm => "hmac-sha2-512-etm@openssh.com",
        HmacSha1Etm => "hmac-sha1-etm@openssh.com",
        HmacSha256 => "hmac-sha2-256",
        HmacSha512 => "hmac-sha2-512",
        HmacSha1 => "hmac-sha1",
    }
}

impl Cipher {
    /// An AEAD cipher authenticates its own packets, so no MAC is negotiated for its direction.
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            Self::Chacha20Poly1305 | Self::Aes128Gcm | Self::Aes256Gcm
        )
    }

    /// Key bytes derived for one direction (RFC 4253 section 7.2). ChaCha20-Poly1305 takes two
    /// 32-byte keys, one for the payload and one for the length field.
    pub fn key_len(self) -> usize {
        match self {
            Self::Chacha20Poly1305 => 64,
            Self::Aes128Ctr | Self::Aes128Gcm => 16,
            Self::Aes192Ctr => 24,
            Self::Aes256Ctr | Self::Aes256Gcm => 32,
        }
    }

    /// Initial IV bytes derived for one direction: the CTR counter block, or the GCM fixed field
    /// and invocation counter.
    pub fn iv_len(self) -> usize {
        match self {
            Self::Chacha20Poly1305 => 0,
            Self::Aes128Ctr | Self::Aes192Ctr | Self::Aes256Ctr => 16,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
        }
    }

    /// The unit a packet's encrypted part is padded to (RFC 4253 section 6: the larger of 8 and
    /// the cipher's block size).
    pub fn block_len(self) -> usize {
        match self {
            Self::Chacha20Poly1305 => 8,
            _ => 16,
        }
    }
}

impl Mac {
    /// Integrity key bytes derived for one direction; also the length of the MAC's output for the
    /// SHA-2 variants. SHA-1's output (20 bytes) is its key length too.
    pub fn key_len(self) -> usize {
        match self {
            Self::HmacSha256Etm | Self::HmacSha256 => 32,
            Self::HmacSha512Etm | Self::HmacSha512 => 64,
            Self::HmacSha1Etm | Self::HmacSha1 => 20,
        }
    }

    /// Bytes of MAC appended to each packet.
    pub fn tag_len(self) -> usize {
        self.key_len()
    }

    /// Encrypt-then-MAC: the MAC covers the ciphertext and the length field stays in the clear.
    pub fn is_etm(self) -> bool {
        matches!(
            self,
            Self::HmacSha256Etm | Self::HmacSha512Etm | Self::HmacSha1Etm
        )
    }
}

/// The one compression method supported. It must appear in the client's lists: a client that
/// insists on `zlib@openssh.com` cannot be served, and says so by offering nothing else.
const COMPRESSION_NONE: &str = "none";

/// `name1,name2,...` for a KEXINIT name-list.
pub fn name_list<A: Algorithm>() -> String {
    A::ALL
        .iter()
        .map(|a| a.name())
        .collect::<Vec<_>>()
        .join(",")
}

/// The lists of a client's KEXINIT that negotiation reads.
#[derive(Debug, Clone, Copy)]
pub struct ClientLists<'a> {
    pub kex_algorithms: &'a str,
    pub server_host_key_algorithms: &'a str,
    pub encryption_client_to_server: &'a str,
    pub encryption_server_to_client: &'a str,
    pub mac_client_to_server: &'a str,
    pub mac_server_to_client: &'a str,
    pub compression_client_to_server: &'a str,
    pub compression_server_to_client: &'a str,
    pub first_kex_packet_follows: bool,
}

/// What both ends will run. A direction's MAC is `None` when its cipher is an AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub kex: Kex,
    pub host_key: HostKeyAlgorithm,
    pub cipher_client_to_server: Cipher,
    pub cipher_server_to_client: Cipher,
    pub mac_client_to_server: Option<Mac>,
    pub mac_server_to_client: Option<Mac>,
    /// The client sent a key exchange packet right behind its KEXINIT (RFC 4253 section 7,
    /// `first_kex_packet_follows`) and guessed wrong, so that packet is to be dropped unread.
    /// A right guess is the real first packet of the exchange and is used as such.
    pub discard_guess: bool,
}

/// The list that had nothing in common with the client's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationFailure {
    Kex,
    HostKey,
    CipherClientToServer,
    CipherServerToClient,
    MacClientToServer,
    MacServerToClient,
    Compression,
}

impl NegotiationFailure {
    /// Stable key recorded on the `honeypot_session_end` event.
    pub fn label(self) -> &'static str {
        match self {
            Self::Kex => "kex",
            Self::HostKey => "host_key",
            Self::CipherClientToServer => "cipher_c2s",
            Self::CipherServerToClient => "cipher_s2c",
            Self::MacClientToServer => "mac_c2s",
            Self::MacServerToClient => "mac_s2c",
            Self::Compression => "compression",
        }
    }

    /// The `SSH_MSG_DISCONNECT` description, worded as OpenSSH words the same refusals.
    pub fn description(self) -> &'static str {
        match self {
            Self::Kex => "no matching key exchange method found",
            Self::HostKey => "no matching host key type found",
            Self::CipherClientToServer | Self::CipherServerToClient => "no matching cipher found",
            Self::MacClientToServer | Self::MacServerToClient => "no matching MAC found",
            Self::Compression => "no matching compression method found",
        }
    }
}

impl std::fmt::Display for NegotiationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.description())
    }
}

/// The first algorithm in the client's comma-separated list that the server supports.
fn first_supported<A: Algorithm>(client_list: &str) -> Option<A> {
    client_list.split(',').find_map(A::from_name)
}

fn lists_name(client_list: &str, name: &str) -> bool {
    client_list.split(',').any(|candidate| candidate == name)
}

/// Pick the algorithms for a connection from the client's KEXINIT lists, or name the list that
/// shares nothing with the server's.
pub fn negotiate(client: &ClientLists<'_>) -> Result<Negotiated, NegotiationFailure> {
    let kex: Kex = first_supported(client.kex_algorithms).ok_or(NegotiationFailure::Kex)?;
    let host_key: HostKeyAlgorithm =
        first_supported(client.server_host_key_algorithms).ok_or(NegotiationFailure::HostKey)?;
    let cipher_client_to_server: Cipher = first_supported(client.encryption_client_to_server)
        .ok_or(NegotiationFailure::CipherClientToServer)?;
    let cipher_server_to_client: Cipher = first_supported(client.encryption_server_to_client)
        .ok_or(NegotiationFailure::CipherServerToClient)?;
    // An AEAD cipher makes the MAC list irrelevant for its direction (RFC 5647, OpenSSH's
    // PROTOCOL): a client may leave it empty or fill it, and neither is an error.
    let mac_client_to_server = if cipher_client_to_server.is_aead() {
        None
    } else {
        Some(
            first_supported(client.mac_client_to_server)
                .ok_or(NegotiationFailure::MacClientToServer)?,
        )
    };
    let mac_server_to_client = if cipher_server_to_client.is_aead() {
        None
    } else {
        Some(
            first_supported(client.mac_server_to_client)
                .ok_or(NegotiationFailure::MacServerToClient)?,
        )
    };
    if !lists_name(client.compression_client_to_server, COMPRESSION_NONE)
        || !lists_name(client.compression_server_to_client, COMPRESSION_NONE)
    {
        return Err(NegotiationFailure::Compression);
    }

    // RFC 4253 section 7: the guess is right only when the client's first kex algorithm and first
    // host key algorithm are the ones the server would put first as well.
    let first = |list: &str| list.split(',').next().map(str::to_owned);
    let guessed_right = first(client.kex_algorithms).as_deref() == Some(Kex::ALL[0].name())
        && first(client.server_host_key_algorithms).as_deref()
            == Some(HostKeyAlgorithm::ALL[0].name());

    Ok(Negotiated {
        kex,
        host_key,
        cipher_client_to_server,
        cipher_server_to_client,
        mac_client_to_server,
        mac_server_to_client,
        discard_guess: client.first_kex_packet_follows && !guessed_right,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists<'a>(
        kex: &'a str,
        host_key: &'a str,
        cipher: &'a str,
        compression: &'a str,
    ) -> ClientLists<'a> {
        ClientLists {
            kex_algorithms: kex,
            server_host_key_algorithms: host_key,
            encryption_client_to_server: cipher,
            encryption_server_to_client: cipher,
            mac_client_to_server: "hmac-sha2-256",
            mac_server_to_client: "hmac-sha2-256",
            compression_client_to_server: compression,
            compression_server_to_client: compression,
            first_kex_packet_follows: false,
        }
    }

    const CIPHER: &str = "chacha20-poly1305@openssh.com";

    #[test]
    fn a_mac_is_negotiated_only_for_a_direction_without_an_aead() {
        let mut l = lists("curve25519-sha256", "ssh-ed25519", "aes256-ctr", "none");
        l.mac_client_to_server = "hmac-md5,hmac-sha2-512,hmac-sha2-256-etm@openssh.com";
        l.mac_server_to_client = "hmac-sha1";
        let n = negotiate(&l).unwrap();
        assert_eq!(n.mac_client_to_server, Some(Mac::HmacSha512));
        assert_eq!(n.mac_server_to_client, Some(Mac::HmacSha1));

        l.mac_client_to_server = "hmac-md5";
        assert_eq!(
            negotiate(&l).unwrap_err(),
            NegotiationFailure::MacClientToServer
        );
        l.mac_client_to_server = "hmac-sha2-256";
        l.mac_server_to_client = "";
        assert_eq!(
            negotiate(&l).unwrap_err(),
            NegotiationFailure::MacServerToClient
        );

        // Direction by direction: an AEAD one needs no MAC even beside a CTR one that does.
        l.encryption_server_to_client = "aes128-gcm@openssh.com";
        let n = negotiate(&l).unwrap();
        assert_eq!(n.mac_server_to_client, None);
        assert_eq!(n.mac_client_to_server, Some(Mac::HmacSha256));
        l.mac_client_to_server = "";
        l.mac_server_to_client = "";
        l.encryption_client_to_server = "chacha20-poly1305@openssh.com";
        let n = negotiate(&l).unwrap();
        assert_eq!(
            (n.mac_client_to_server, n.mac_server_to_client),
            (None, None)
        );
    }

    #[test]
    fn derived_sizes_follow_the_algorithm() {
        assert_eq!(Cipher::Aes192Ctr.key_len(), 24);
        assert_eq!(Cipher::Aes128Gcm.iv_len(), 12);
        assert_eq!(Cipher::Chacha20Poly1305.iv_len(), 0);
        assert_eq!(Mac::HmacSha1.tag_len(), 20);
        assert!(Mac::HmacSha512Etm.is_etm() && !Mac::HmacSha512.is_etm());
        for c in Cipher::ALL {
            assert_eq!(c.is_aead(), c.iv_len() != 16, "{c:?}");
        }
    }

    #[test]
    fn the_client_orders_the_choice_not_the_server() {
        let n = negotiate(&lists(
            "diffie-hellman-group1-sha1,curve25519-sha256@libssh.org,curve25519-sha256",
            "ssh-rsa,ssh-ed25519",
            CIPHER,
            "zlib,none",
        ))
        .unwrap();
        assert_eq!(n.kex, Kex::Curve25519Sha256Libssh);
        assert_eq!(n.host_key, HostKeyAlgorithm::SshEd25519);
    }

    #[test]
    fn each_list_with_no_common_entry_names_itself() {
        let ok = lists("curve25519-sha256", "ssh-ed25519", CIPHER, "none");
        assert!(negotiate(&ok).is_ok());
        for (bad, want) in [
            (
                lists(
                    "ecdh-sha2-nistp521",
                    ok.server_host_key_algorithms,
                    CIPHER,
                    "none",
                ),
                NegotiationFailure::Kex,
            ),
            (
                lists("curve25519-sha256", "ssh-rsa", CIPHER, "none"),
                NegotiationFailure::HostKey,
            ),
            (
                lists("curve25519-sha256", "ssh-ed25519", "aes256-cbc", "none"),
                NegotiationFailure::CipherClientToServer,
            ),
            (
                lists(
                    "curve25519-sha256",
                    "ssh-ed25519",
                    CIPHER,
                    "zlib@openssh.com",
                ),
                NegotiationFailure::Compression,
            ),
        ] {
            assert_eq!(negotiate(&bad).unwrap_err(), want);
        }
        let mut s2c = ok;
        s2c.encryption_server_to_client = "aes256-cbc";
        assert_eq!(
            negotiate(&s2c).unwrap_err(),
            NegotiationFailure::CipherServerToClient
        );
    }

    #[test]
    fn an_empty_or_padded_list_matches_nothing() {
        assert!(negotiate(&lists("", "ssh-ed25519", CIPHER, "none")).is_err());
        assert!(negotiate(&lists(",,", "ssh-ed25519", CIPHER, "none")).is_err());
        // Names are exact: no trimming, no prefix match.
        assert!(negotiate(&lists(" curve25519-sha256", "ssh-ed25519", CIPHER, "none")).is_err());
        assert!(negotiate(&lists("curve25519-sha2", "ssh-ed25519", CIPHER, "none")).is_err());
    }

    #[test]
    fn only_a_wrong_guess_is_discarded() {
        let mut l = lists("curve25519-sha256", "ssh-ed25519", CIPHER, "none");
        assert!(!negotiate(&l).unwrap().discard_guess, "no guess was sent");
        l.first_kex_packet_follows = true;
        assert!(
            !negotiate(&l).unwrap().discard_guess,
            "a right guess is kept"
        );
        l.kex_algorithms = "curve25519-sha256@libssh.org,curve25519-sha256";
        assert!(negotiate(&l).unwrap().discard_guess);
        l.kex_algorithms = "curve25519-sha256";
        l.server_host_key_algorithms = "ssh-rsa,ssh-ed25519";
        assert!(negotiate(&l).unwrap().discard_guess);
    }

    #[test]
    fn the_rendered_offer_round_trips_through_negotiation() {
        let kex = name_list::<Kex>();
        let host = name_list::<HostKeyAlgorithm>();
        let cipher = name_list::<Cipher>();
        let n = negotiate(&lists(&kex, &host, &cipher, "none")).unwrap();
        assert_eq!(n.kex, Kex::ALL[0]);
        for k in Kex::ALL {
            assert_eq!(Kex::from_name(k.name()), Some(*k));
        }
    }
}
