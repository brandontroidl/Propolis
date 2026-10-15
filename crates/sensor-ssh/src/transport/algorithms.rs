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
    /// Key exchange methods. `Curve25519Sha256Libssh` is RFC 8731's `curve25519-sha256` under the
    /// name OpenSSH and PuTTY used before it was standardised: the same exchange, byte for byte.
    Kex {
        Curve25519Sha256 => "curve25519-sha256",
        Curve25519Sha256Libssh => "curve25519-sha256@libssh.org",
    }
}

algorithms! {
    /// Server host key (signature) algorithms.
    HostKeyAlgorithm {
        SshEd25519 => "ssh-ed25519",
    }
}

algorithms! {
    /// Transport ciphers. Each is an AEAD, so none negotiates a separate MAC.
    Cipher {
        Chacha20Poly1305 => "chacha20-poly1305@openssh.com",
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
    pub compression_client_to_server: &'a str,
    pub compression_server_to_client: &'a str,
    pub first_kex_packet_follows: bool,
}

/// What both ends will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub kex: Kex,
    pub host_key: HostKeyAlgorithm,
    pub cipher_client_to_server: Cipher,
    pub cipher_server_to_client: Cipher,
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
            Self::Compression => "compression",
        }
    }

    /// The `SSH_MSG_DISCONNECT` description, worded as OpenSSH words the same refusals.
    pub fn description(self) -> &'static str {
        match self {
            Self::Kex => "no matching key exchange method found",
            Self::HostKey => "no matching host key type found",
            Self::CipherClientToServer | Self::CipherServerToClient => "no matching cipher found",
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
            compression_client_to_server: compression,
            compression_server_to_client: compression,
            first_kex_packet_follows: false,
        }
    }

    const CIPHER: &str = "chacha20-poly1305@openssh.com";

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
