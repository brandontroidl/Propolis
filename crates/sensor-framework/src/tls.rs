//! Per-sensor server-side TLS: no client authentication, fail-closed config loading, an
//! implicit-TLS listener that reuses `run_tcp_listener`, and a plaintext-to-TLS stream type for
//! STARTTLS-style in-protocol upgrades. Rustls types come through `tokio_rustls::rustls` so the
//! resolved rustls version cannot skew from the transport's.

use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::{
    self, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::bounds::ConnectionBounds;
use crate::listener::run_tcp_listener;

/// Upper bound on a cert or key PEM file read. A real chain/key is a few KiB; a larger file is a
/// misconfiguration (or a wrong path such as a device or log), refused rather than slurped.
const MAX_PEM_FILE_BYTES: u64 = 1024 * 1024;

/// Why a TLS config could not be built. No variant carries file content: a PEM failure is
/// reduced to a fixed description (see [`pem_error_kind`]), and `Io` and `Rustls` errors hold
/// only the OS or rustls error, never the bytes read.
#[derive(Debug)]
pub enum TlsConfigError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    NotRegularFile {
        path: PathBuf,
    },
    TooLarge {
        path: PathBuf,
    },
    /// Key file mode has any group/other bit set. `mode` is the permission bits only (`& 0o777`).
    KeyPermissions {
        path: PathBuf,
        mode: u32,
    },
    /// `kind` is a constant, never the parser's error: `pem::Error`'s Display prints the offending
    /// line or section label as raw bytes, which for a one-line PEM is the whole key.
    Pem {
        path: PathBuf,
        kind: &'static str,
    },
    NoCertificate {
        path: PathBuf,
    },
    NoPrivateKey {
        path: PathBuf,
    },
    /// rustls rejected the pair (unsupported key type, cert/key mismatch, bad cert).
    Rustls(rustls::Error),
}

impl fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            Self::NotRegularFile { path } => {
                write!(f, "{} is not a regular file", path.display())
            }
            Self::TooLarge { path } => write!(
                f,
                "{} is larger than {MAX_PEM_FILE_BYTES} bytes",
                path.display()
            ),
            Self::KeyPermissions { path, mode } => write!(
                f,
                "private key {} has mode {mode:04o}; group/other access must be removed (chmod 0600)",
                path.display()
            ),
            Self::Pem { path, kind } => {
                write!(f, "malformed PEM in {}: {kind}", path.display())
            }
            Self::NoCertificate { path } => {
                write!(f, "no certificate found in {}", path.display())
            }
            Self::NoPrivateKey { path } => {
                write!(f, "no private key found in {}", path.display())
            }
            Self::Rustls(error) => write!(f, "tls configuration rejected: {error}"),
        }
    }
}

impl std::error::Error for TlsConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Rustls(error) => Some(error),
            _ => None,
        }
    }
}

/// Total over `pem::Error`; the wildcard arm exists because the enum is `#[non_exhaustive]`.
fn pem_error_kind(error: &rustls_pki_types::pem::Error) -> &'static str {
    use rustls_pki_types::pem::Error;
    match error {
        Error::MissingSectionEnd { .. } => "missing section end marker",
        Error::IllegalSectionStart { .. } => "illegal section start",
        Error::Base64Decode(_) => "base64 decode error",
        Error::Io(_) => "I/O error",
        Error::NoItemsFound => "no items found",
        Error::SectionTooLarge => "section too large",
        _ => "malformed PEM",
    }
}

fn pem_error(path: &Path) -> impl FnOnce(rustls_pki_types::pem::Error) -> TlsConfigError + '_ {
    move |error| TlsConfigError::Pem {
        path: path.to_path_buf(),
        kind: pem_error_kind(&error),
    }
}

fn build(
    cert_pem: &[u8],
    cert_path: &Path,
    key_pem: &[u8],
    key_path: &Path,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(pem_error(cert_path))?;
    if certs.is_empty() {
        return Err(TlsConfigError::NoCertificate {
            path: cert_path.to_path_buf(),
        });
    }
    let key = PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .transpose()
        .map_err(pem_error(key_path))?
        .ok_or_else(|| TlsConfigError::NoPrivateKey {
            path: key_path.to_path_buf(),
        })?;
    // No ALPN (the http sensor serves HTTP/1.1 and must not advertise h2) and no early data.
    // `with_single_cert` runs rustls' own cert/key match check.
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(TlsConfigError::Rustls)?;
    Ok(Arc::new(config))
}

/// Build a no-client-auth server config from in-memory PEM (tests and callers that already hold bytes).
pub fn server_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let memory = Path::new("<memory>");
    build(cert_pem, memory, key_pem, memory)
}

fn read_pem_file(path: &Path, require_private_mode: bool) -> Result<Vec<u8>, TlsConfigError> {
    let io_err = |source| TlsConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    // Follows symlinks on purpose: /etc/propolis/tls may point at an operator's real cert dir.
    let file = File::open(path).map_err(io_err)?;
    // fstat on the open descriptor, so the checks below cannot race a path swap.
    let meta = file.metadata().map_err(io_err)?;
    if !meta.is_file() {
        return Err(TlsConfigError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    if meta.len() > MAX_PEM_FILE_BYTES {
        return Err(TlsConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    if require_private_mode {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(TlsConfigError::KeyPermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    let mut buf = Vec::new();
    file.take(MAX_PEM_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(io_err)?;
    if buf.len() as u64 > MAX_PEM_FILE_BYTES {
        buf.fill(0);
        return Err(TlsConfigError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    Ok(buf)
}

/// Read `cert_path` and `key_path` and build a no-client-auth server config. Fail-closed: a
/// missing, unreadable, oversized, non-regular, or malformed file, a mismatched pair, or a key
/// with any group/other permission bit set is an error, never a default or insecure config.
/// Synchronous `std::fs`; call once at sensor startup before any listener binds.
pub fn load_server_config(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let mut cert_pem = read_pem_file(cert_path, false)?;
    let mut key_pem = read_pem_file(key_path, true)?;
    let result = build(&cert_pem, cert_path, &key_pem, key_path);
    // Best-effort scrub (plain overwrite; no zeroize dependency), on the error path too. cert_pem is
    // scrubbed as well: an operator may point both _TLS_CERT and _TLS_KEY at one combined PEM, so
    // the cert buffer can hold the private-key section too.
    key_pem.fill(0);
    cert_pem.fill(0);
    result
}

/// Cheaply cloneable TLS acceptor (an `Arc<ServerConfig>` inside).
#[derive(Clone)]
pub struct TlsServer {
    acceptor: TlsAcceptor,
}

impl TlsServer {
    pub fn from_config(config: Arc<ServerConfig>) -> Self {
        Self {
            acceptor: TlsAcceptor::from(config),
        }
    }

    /// Handshake on any async stream (an accepted socket, or a data-channel socket for FTPS PROT P).
    pub async fn accept<IO>(&self, io: IO) -> io::Result<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.acceptor.accept(io).await
    }
}

/// Implicit-TLS listener. Delegates to `run_tcp_listener`, so the per-source cap, the global
/// semaphore, and `max_duration` apply unchanged and the handshake runs inside the bounded
/// future. The handshake itself is cut at `bounds.read_timeout`, so a stalled ClientHello cannot
/// hold a permit for the full `max_duration`.
///
/// The handler receives the established stream, the peer, the local address (raw, captured from
/// the socket before the handshake because a `TlsStream` has no `local_addr()`; the handler
/// applies `normalize_dual_stack` itself), and the session id. Handshake failures log at `debug`:
/// scanners sending plaintext to a TLS port are the common case and must not flood the log.
pub async fn run_tls_listener<F, Fut>(
    addr: SocketAddr,
    bounds: ConnectionBounds,
    per_source_cap: Option<u32>,
    tls: TlsServer,
    handler: F,
) -> io::Result<(SocketAddr, JoinHandle<()>)>
where
    F: Fn(TlsStream<TcpStream>, SocketAddr, Option<SocketAddr>, uuid::Uuid) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(handler);
    let handshake_timeout = bounds.read_timeout;
    run_tcp_listener(
        addr,
        bounds,
        per_source_cap,
        move |tcp, peer, session_id| {
            let local = tcp.local_addr().ok();
            let tls = tls.clone();
            let handler = Arc::clone(&handler);
            async move {
                let stream = match tokio::time::timeout(handshake_timeout, tls.accept(tcp)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        tracing::debug!(%peer, %error, "tls handshake failed; dropping connection");
                        return;
                    }
                    Err(_elapsed) => {
                        tracing::debug!(%peer, "tls handshake timed out; dropping connection");
                        return;
                    }
                };
                handler(stream, peer, local, session_id).await
            }
        },
    )
    .await
}

/// A connection that starts plaintext and may switch to TLS in place (STARTTLS, FTP AUTH TLS,
/// postgres SSLRequest, ...). A handler generic over a bare stream type cannot change that type
/// mid-connection, so STARTTLS handlers take this concrete two-state type instead.
pub enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl MaybeTlsStream {
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// Run the server handshake in place, cut at `timeout` so a stalled STARTTLS ClientHello cannot
    /// hold the connection open (parity with the implicit-TLS path in `run_tls_listener`; callers
    /// pass `bounds.read_timeout`). `Err` on an already-TLS stream (`InvalidInput`), a timeout
    /// (`TimedOut`), or a handshake failure; after `Err` the stream is consumed and the connection
    /// MUST be dropped (no plaintext fallback).
    ///
    /// A handler that reads through a `BufReader` must not call this directly: use
    /// [`upgrade_buffered`], which enforces the buffered-plaintext rule.
    pub async fn upgrade(
        self,
        tls: &TlsServer,
        timeout: std::time::Duration,
    ) -> io::Result<MaybeTlsStream> {
        match self {
            Self::Plain(tcp) => {
                let accepted = tokio::time::timeout(timeout, tls.accept(tcp))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "tls upgrade handshake timed out")
                    })??;
                Ok(Self::Tls(Box::new(accepted)))
            }
            Self::Tls(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream is already tls",
            )),
        }
    }
}

/// STARTTLS / AUTH TLS for a session read through a `BufReader`: the one path smtp and ftp use.
///
/// Bytes already buffered past the STARTTLS command were sent in plaintext before the handshake
/// (the CVE-2011-0411 command-injection shape); interpreting them inside the TLS session would
/// let a man-in-the-middle prepend commands. This refuses the upgrade with `InvalidData` naming the
/// byte count instead of discarding them silently, so the caller drops the connection and can
/// record the attempt. A caller that wants to answer with an error reply instead of the go-ahead
/// checks `reader.buffer().is_empty()` before writing it. Otherwise the result is a fresh
/// `BufReader` over the upgraded stream, so no pre-handshake state survives. Errors as
/// [`MaybeTlsStream::upgrade`]; on any `Err` the connection MUST be dropped.
pub async fn upgrade_buffered(
    reader: tokio::io::BufReader<MaybeTlsStream>,
    tls: &TlsServer,
    timeout: std::time::Duration,
) -> io::Result<tokio::io::BufReader<MaybeTlsStream>> {
    let pipelined = reader.buffer().len();
    if pipelined > 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{pipelined} plaintext bytes pipelined after STARTTLS"),
        ));
    }
    let upgraded = reader.into_inner().upgrade(tls, timeout).await?;
    Ok(tokio::io::BufReader::new(upgraded))
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn ephemeral() -> (String, String, Vec<u8>) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (cert.pem(), signing_key.serialize_pem(), cert.der().to_vec())
    }

    fn write_with_mode(path: &Path, contents: &[u8], mode: u32) {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A tempdir holding a valid pair, key at `key_mode`.
    fn files(key_mode: u32) -> (tempfile::TempDir, PathBuf, PathBuf, String) {
        let (cert, key, _) = ephemeral();
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = (dir.path().join("c.crt"), dir.path().join("k.key"));
        write_with_mode(&c, cert.as_bytes(), 0o644);
        write_with_mode(&k, key.as_bytes(), key_mode);
        (dir, c, k, key)
    }

    #[test]
    fn from_pem_builds_a_config() {
        let (cert, key, _) = ephemeral();
        assert!(server_config_from_pem(cert.as_bytes(), key.as_bytes()).is_ok());
    }

    #[test]
    fn empty_cert_pem_is_no_certificate() {
        let (_, key, _) = ephemeral();
        assert!(matches!(
            server_config_from_pem(b"", key.as_bytes()),
            Err(TlsConfigError::NoCertificate { .. })
        ));
    }

    #[test]
    fn empty_key_pem_is_no_private_key() {
        let (cert, _, _) = ephemeral();
        assert!(matches!(
            server_config_from_pem(cert.as_bytes(), b""),
            Err(TlsConfigError::NoPrivateKey { .. })
        ));
    }

    #[test]
    fn garbage_pem_is_rejected() {
        let (_, key, _) = ephemeral();
        let bad = b"-----BEGIN CERTIFICATE-----\n!!!notbase64\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            server_config_from_pem(bad, key.as_bytes()),
            Err(TlsConfigError::Pem { .. } | TlsConfigError::NoCertificate { .. })
        ));
    }

    #[test]
    fn mismatched_cert_and_key_is_rejected() {
        let (cert, _, _) = ephemeral();
        let (_, other_key, _) = ephemeral();
        assert!(matches!(
            server_config_from_pem(cert.as_bytes(), other_key.as_bytes()),
            Err(TlsConfigError::Rustls(_))
        ));
    }

    #[test]
    fn load_from_files_ok() {
        let (_dir, c, k, _) = files(0o600);
        assert!(load_server_config(&c, &k).is_ok());
    }

    #[test]
    fn group_readable_key_is_refused() {
        // 0o640 passes a naive "other bits only" mask; 0o604 passes a "group bits only" one.
        for mode in [0o640, 0o604] {
            let (_dir, c, k, _) = files(mode);
            match load_server_config(&c, &k) {
                Err(TlsConfigError::KeyPermissions { mode: got, .. }) => assert_eq!(got, mode),
                other => panic!("mode {mode:o}: {other:?}"),
            }
        }
    }

    #[test]
    fn world_readable_key_is_refused() {
        let (_dir, c, k, _) = files(0o644);
        assert!(matches!(
            load_server_config(&c, &k),
            Err(TlsConfigError::KeyPermissions { .. })
        ));
    }

    #[test]
    fn missing_key_file_is_io_error() {
        let (_dir, c, k, _) = files(0o600);
        std::fs::remove_file(&k).unwrap();
        match load_server_config(&c, &k) {
            Err(TlsConfigError::Io { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::NotFound)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn missing_cert_file_is_io_error() {
        let (_dir, c, k, _) = files(0o600);
        std::fs::remove_file(&c).unwrap();
        match load_server_config(&c, &k) {
            Err(TlsConfigError::Io { source, .. }) => {
                assert_eq!(source.kind(), io::ErrorKind::NotFound)
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn directory_as_key_is_not_regular_file() {
        let (dir, c, _, _) = files(0o600);
        assert!(matches!(
            load_server_config(&c, dir.path()),
            Err(TlsConfigError::NotRegularFile { .. })
        ));
    }

    #[test]
    fn oversize_file_is_too_large() {
        let (_dir, c, k, _) = files(0o600);
        write_with_mode(&k, &vec![b'a'; MAX_PEM_FILE_BYTES as usize + 1], 0o600);
        assert!(matches!(
            load_server_config(&c, &k),
            Err(TlsConfigError::TooLarge { .. })
        ));
    }

    #[test]
    fn permission_check_runs_before_read() {
        let (_dir, c, k, _) = files(0o600);
        write_with_mode(&k, b"not a key at all", 0o644);
        assert!(matches!(
            load_server_config(&c, &k),
            Err(TlsConfigError::KeyPermissions { .. })
        ));
    }

    /// `e` and every error in its `source()` chain, each through Display and Debug.
    fn renderings(e: &TlsConfigError) -> Vec<String> {
        let mut out = vec![format!("{e}"), format!("{e:?}")];
        let mut next = std::error::Error::source(e);
        while let Some(source) = next {
            out.push(format!("{source}"));
            out.push(format!("{source:?}"));
            next = source.source();
        }
        out
    }

    /// No rendering of `e` may hold any 8 consecutive bytes of `body`: as text, as a decimal byte
    /// list (how `{:?}` prints a `Vec<u8>`), or as lowercase or uppercase hex (packed, or a
    /// `{:02x?}` list).
    fn assert_no_leak(e: &TlsConfigError, body: &[u8]) {
        assert!(body.len() >= 8, "fixture body too short to test");
        for text in renderings(e) {
            for w in body.windows(8) {
                let hex: Vec<String> = w.iter().map(|b| format!("{b:02x}")).collect();
                let needles = [
                    String::from_utf8_lossy(w).into_owned(),
                    w.iter().map(u8::to_string).collect::<Vec<_>>().join(", "),
                    hex.concat(),
                    hex.concat().to_uppercase(),
                    hex.join(", "),
                    hex.join(", ").to_uppercase(),
                ];
                for needle in needles {
                    assert!(
                        !text.contains(&needle),
                        "body bytes {needle:?} leaked into error: {text}"
                    );
                }
            }
        }
    }

    /// The base64 body of a freshly generated key, every line joined, headers dropped.
    fn key_body(key_pem: &str) -> String {
        key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect()
    }

    // A key written header, body and footer on ONE line parses as a section whose label runs to
    // the last five dashes, so the parser's MissingSectionEnd carries the whole key as its
    // end marker. The Pem variant must not pass that on, from the key slot or the cert slot (an
    // operator may point both env vars at one combined PEM).
    #[test]
    fn malformed_pem_errors_never_carry_body_bytes() {
        let (cert, key, _) = ephemeral();
        let body = key_body(&key);
        let kw = ["PRI", "VATE"].concat();
        let (begin, end) = (
            format!("-----BEGIN {kw} KEY-----"),
            format!("-----END {kw} KEY-----"),
        );
        let shapes = [
            format!("{begin}{body}{end}"),
            format!("{begin}{body}{end}\n"),
            format!("{begin}{body}\n{end}\n"),
            format!("{begin}\n{body}\n"),
            format!("{begin}\n{body}!!\n{end}\n"),
        ];
        for shape in &shapes {
            for err in [
                server_config_from_pem(cert.as_bytes(), shape.as_bytes()).unwrap_err(),
                server_config_from_pem(shape.as_bytes(), key.as_bytes()).unwrap_err(),
            ] {
                assert_no_leak(&err, body.as_bytes());
            }
        }
        let one_line = shapes[0].as_bytes();
        assert!(matches!(
            server_config_from_pem(cert.as_bytes(), one_line),
            Err(TlsConfigError::Pem { .. })
        ));

        // Through the file loader too, with the one-line key in both the key and the cert file.
        let dir = tempfile::tempdir().unwrap();
        let (c, k) = (dir.path().join("c.crt"), dir.path().join("k.key"));
        write_with_mode(&c, cert.as_bytes(), 0o644);
        write_with_mode(&k, one_line, 0o600);
        let err = load_server_config(&c, &k).unwrap_err();
        assert!(matches!(err, TlsConfigError::Pem { .. }), "{err:?}");
        assert_no_leak(&err, body.as_bytes());
        write_with_mode(&c, one_line, 0o644);
        write_with_mode(&k, key.as_bytes(), 0o600);
        let err = load_server_config(&c, &k).unwrap_err();
        assert!(matches!(err, TlsConfigError::Pem { .. }), "{err:?}");
        assert_no_leak(&err, body.as_bytes());
    }

    #[test]
    fn error_display_never_contains_key_material() {
        let (cert, key, _) = ephemeral();
        let (_, other_key, _) = ephemeral();
        let body = key_body(&key);
        let (_dir, c, k, _) = files(0o644);
        let errors = [
            server_config_from_pem(b"", key.as_bytes()).unwrap_err(),
            server_config_from_pem(
                b"-----BEGIN CERTIFICATE-----\n!!!notbase64\n-----END CERTIFICATE-----\n",
                key.as_bytes(),
            )
            .unwrap_err(),
            server_config_from_pem(cert.as_bytes(), other_key.as_bytes()).unwrap_err(),
            load_server_config(&c, &k).unwrap_err(),
        ];
        let header = format!("{} KEY", ["PRI", "VATE"].concat());
        for e in errors {
            assert_no_leak(&e, body.as_bytes());
            for text in renderings(&e) {
                assert!(!text.contains(&header), "{text}");
            }
        }
    }

    // Guards the key-parse error branch specifically: a key whose body is malformed must never
    // route its bytes into any error variant, so a future vendored-parser bump that started
    // carrying the offending bytes is caught here rather than silently leaking a real key.
    #[test]
    fn error_from_a_garbage_key_body_never_leaks_it() {
        let (cert, _key, _) = ephemeral();
        // Keyword assembled at runtime so no key-shaped PEM literal sits in the source.
        let kw = ["PRI", "VATE"].concat();
        let marker = "ZZmarkerZZbodyZZmustZZnotZZleakZZ";
        let garbage_key =
            format!("-----BEGIN {kw} KEY-----\n{marker}!!!notbase64\n-----END {kw} KEY-----\n");
        let err = server_config_from_pem(cert.as_bytes(), garbage_key.as_bytes()).unwrap_err();
        let header = format!("{kw} KEY");
        assert_no_leak(&err, marker.as_bytes());
        for text in renderings(&err) {
            assert!(!text.contains(&header), "{text}");
        }
    }
}
