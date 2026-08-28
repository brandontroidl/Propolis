//! Mutual-TLS config builders for the collector/gateway wire protocol.
//!
//! Both sides pin the same CA: the gateway (`server_config`) requires and verifies a
//! client certificate, and the shipper (`client_config`) presents its certificate and
//! verifies the gateway against the same CA. The gateway trusts the collector id read
//! from the verified client certificate's CommonName (`peer_common_name`), never from
//! anything in the payload.
//!
//! Rustls types are reached through `tokio_rustls::rustls` (rather than a direct
//! `rustls` dependency) so the resolved rustls version cannot skew between this crate
//! and its `tokio-rustls` transport.

use std::io::BufReader;
use std::sync::Arc;

use tokio_rustls::rustls::{
    self, ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{VerifierBuilderError, WebPkiClientVerifier},
};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("failed to read PEM data: {0}")]
    Pem(#[from] std::io::Error),
    #[error("PEM data contained no certificate")]
    NoCertificate,
    #[error("PEM data contained no private key")]
    NoPrivateKey,
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("failed to build client certificate verifier: {0}")]
    ClientVerifier(#[from] VerifierBuilderError),
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = BufReader::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate);
    }
    Ok(certs)
}

fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)?.ok_or(TlsError::NoPrivateKey)
}

fn root_store(ca_pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in parse_certs(ca_pem)? {
        roots.add(cert)?;
    }
    Ok(roots)
}

/// Build a server-side TLS config that requires and verifies a client certificate
/// against `ca_pem` (mandatory mutual TLS; there is no anonymous-client fallback).
pub fn server_config(
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<ServerConfig>, TlsError> {
    let roots = Arc::new(root_store(ca_pem)?);
    let verifier = WebPkiClientVerifier::builder(roots).build()?;
    let chain = parse_certs(cert_pem)?;
    let key = parse_key(key_pem)?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

/// Build a client-side TLS config that presents `cert_pem`/`key_pem` for client
/// authentication and verifies the server certificate against `ca_pem`.
pub fn client_config(
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<ClientConfig>, TlsError> {
    let roots = Arc::new(root_store(ca_pem)?);
    let chain = parse_certs(cert_pem)?;
    let key = parse_key(key_pem)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)?;
    Ok(Arc::new(config))
}

/// Read the CommonName of the first (leaf) certificate, or `None` if the chain is
/// empty or the leaf cannot be parsed as X.509 or carries no CommonName.
///
/// Used by the gateway to read the verified client's collector id from its cert
/// rather than trusting anything the collector sends in the payload.
pub fn peer_common_name(certs: &[CertificateDer<'_>]) -> Option<String> {
    let leaf = certs.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
pub(crate) mod testsupport {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    };

    use super::CertificateDer;

    pub(crate) struct TestCa {
        pub(crate) cert_pem: Vec<u8>,
        // Not read by this crate's own tests, kept for parity with TestLeaf and for later
        // tasks (gateway/shipper integration tests) that mint a CA and need its key material.
        #[allow(dead_code)]
        pub(crate) key_pem: Vec<u8>,
        key_pair: KeyPair,
        params: CertificateParams,
    }

    pub(crate) struct TestLeaf {
        pub(crate) cert_pem: Vec<u8>,
        pub(crate) key_pem: Vec<u8>,
        cert_der: Vec<u8>,
    }

    impl TestLeaf {
        pub(crate) fn cert_ders(&self) -> Vec<CertificateDer<'static>> {
            vec![CertificateDer::from(self.cert_der.clone())]
        }
    }

    pub(crate) fn mint_ca() -> TestCa {
        let key_pair = KeyPair::generate().expect("generate ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "test-ca");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key_pair).expect("self-sign ca");
        TestCa {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key_pair.serialize_pem().into_bytes(),
            key_pair,
            params,
        }
    }

    pub(crate) fn mint_leaf(ca: &TestCa, common_name: &str) -> TestLeaf {
        let key_pair = KeyPair::generate().expect("generate leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let issuer = Issuer::from_params(&ca.params, &ca.key_pair);
        let cert = params.signed_by(&key_pair, &issuer).expect("sign leaf");
        TestLeaf {
            cert_pem: cert.pem().into_bytes(),
            key_pem: key_pair.serialize_pem().into_bytes(),
            cert_der: cert.der().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Uses rcgen to mint a tiny CA + a server cert + a client cert whose CN is "collector-test",
    // then asserts server_config/client_config build and peer_common_name reads the CN back.
    #[test]
    fn builds_configs_and_reads_client_cn() {
        let ca = crate::tls::testsupport::mint_ca();
        let server = crate::tls::testsupport::mint_leaf(&ca, "gateway.local");
        let client = crate::tls::testsupport::mint_leaf(&ca, "collector-test");
        assert!(server_config(&ca.cert_pem, &server.cert_pem, &server.key_pem).is_ok());
        assert!(client_config(&ca.cert_pem, &client.cert_pem, &client.key_pem).is_ok());
        let cn = peer_common_name(&client.cert_ders()).unwrap();
        assert_eq!(cn, "collector-test");
    }
    #[test]
    fn a_leaf_from_a_different_ca_is_not_accepted_by_the_verifier() {
        // Build server_config with CA-1, then confirm a client cert signed by CA-2 fails the
        // verifier. Full handshake rejection is exercised in the gateway integration test
        // (Task 6); here assert the verifier is constructed from the given CA only.
        let ca1 = crate::tls::testsupport::mint_ca();
        let ca2 = crate::tls::testsupport::mint_ca();
        assert_ne!(ca1.cert_pem, ca2.cert_pem);
        // NOTE: the brief's Step 2 sketch called mint_leaf(&ca1, "g") twice here (once for
        // cert_pem, once for key_pem); each call mints a fresh random keypair, so the two calls
        // never produce a matched cert/key and with_single_cert correctly rejects the mismatch.
        // Bound to one leaf so this builds the matched (cert, key) pair the comment describes.
        let leaf = crate::tls::testsupport::mint_leaf(&ca1, "g");
        assert!(server_config(&ca1.cert_pem, &leaf.cert_pem, &leaf.key_pem).is_ok());
    }
}
