pub mod mongodb;
pub mod mssql;
pub mod mysql;
pub mod postgresql;
mod tds_tls;
pub mod vnc;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    ConnectionBounds, EventEmitter, MaybeTlsStream, TlsConfigError, TlsServer, WanResolver,
    load_server_config_from_env, run_tcp_listener, server_config_from_pem,
};
use sensor_wire::SensorEvent;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

/// The cred sensor's TLS servers, built from its one certificate. postgresql and mysql upgrade
/// in-band and mongodb sniffs a ClientHello on its plaintext port, all with `inband`; mssql gets
/// its own copy of the config with TLS 1.3 session tickets switched off. A ticket is a record the
/// server writes right after the handshake, and inside TDS the client has stopped de-framing by
/// then, so it would read the framed ticket as raw TLS (see `tds_tls.rs`).
#[derive(Clone)]
pub struct CredTls {
    inband: TlsServer,
    mssql: TlsServer,
}

impl CredTls {
    /// Fail-closed load from the two env vars naming the cert and key files.
    pub fn from_env(cert_var: &str, key_var: &str) -> Result<Self, TlsConfigError> {
        let config = load_server_config_from_env(cert_var, key_var)?;
        let mut mssql = (*config).clone();
        mssql.send_tls13_tickets = 0;
        Ok(Self {
            inband: TlsServer::from_config(config),
            mssql: TlsServer::from_config(Arc::new(mssql)),
        })
    }

    /// From in-memory PEM (tests, and callers that already hold the bytes).
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsConfigError> {
        let config = server_config_from_pem(cert_pem, key_pem)?;
        let mut mssql = (*config).clone();
        mssql.send_tls13_tickets = 0;
        Ok(Self {
            inband: TlsServer::from_config(config),
            mssql: TlsServer::from_config(Arc::new(mssql)),
        })
    }
}

/// One protocol's listener on its plaintext port. With `tls` set, postgresql (SSLRequest), mysql
/// (CLIENT_SSL) and mssql (PRELOGIN ENCRYPTION) negotiate TLS in-band and mongodb accepts a TLS
/// ClientHello on the same port; vnc ignores it. `None` is the plaintext-only behavior.
pub async fn start_listener(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    protocol: &'static str,
    tls: Option<CredTls>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));

    match protocol {
        "vnc" => {
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                vnc::handle_connection::<tokio::net::TcpStream>,
            )
            .await
        }
        "mysql" => {
            let starttls = tls.map(|t| t.inband);
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                move |tcp, peer, local, id, em, wan, b| {
                    mysql::handle_connection(
                        MaybeTlsStream::Plain(tcp),
                        peer,
                        local,
                        id,
                        em,
                        wan,
                        b,
                        starttls.clone(),
                    )
                },
            )
            .await
        }
        "mssql" => {
            let starttls = tls.map(|t| t.mssql);
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                move |tcp, peer, local, id, em, wan, b| {
                    mssql::handle_connection(tcp, peer, local, id, em, wan, b, starttls.clone())
                },
            )
            .await
        }
        "postgresql" => {
            let starttls = tls.map(|t| t.inband);
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                move |tcp, peer, local, id, em, wan, b| {
                    postgresql::handle_connection(
                        MaybeTlsStream::Plain(tcp),
                        peer,
                        local,
                        id,
                        em,
                        wan,
                        b,
                        starttls.clone(),
                    )
                },
            )
            .await
        }
        "mongodb" => {
            let sniff = tls.map(|t| t.inband);
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                move |tcp, peer, local, id, em, wan, b| {
                    mongodb::handle_sniffed(tcp, peer, local, id, em, wan, b, sniff.clone())
                },
            )
            .await
        }
        _ => panic!("unknown protocol: {protocol}"),
    }
}

/// Mark an event as carried over TLS. The key is ABSENT (not `false`) on a plaintext session so
/// existing event shapes and consumers are unchanged.
pub(crate) fn with_tls(mut event: SensorEvent, tls: bool) -> SensorEvent {
    if tls && let Some(metadata) = event.metadata.as_object_mut() {
        metadata.insert("tls".to_string(), serde_json::Value::Bool(true));
    }
    event
}

/// Write and flush. A `TlsStream` accepts plaintext into rustls and returns once the socket
/// pushes back, so under backpressure `write_all` alone can leave the tail of a reply inside
/// rustls when the handler returns; every reply on a possibly-TLS stream goes through this.
pub(crate) async fn write_flush<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> std::io::Result<()> {
    writer.write_all(bytes).await?;
    writer.flush().await
}

async fn start_with<F, Fut>(
    addr: SocketAddr,
    bounds: ConnectionBounds,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    handler: F,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)>
where
    F: Fn(
            tokio::net::TcpStream,
            SocketAddr,
            Option<SocketAddr>,
            sensor_framework::Uuid,
            Arc<EventEmitter>,
            Arc<WanResolver>,
            ConnectionBounds,
        ) -> Fut
        + Send
        + Sync
        + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    run_tcp_listener(
        addr,
        bounds.clone(),
        per_source_cap,
        move |stream, peer, session_id| {
            let local_addr = stream.local_addr().ok();
            let emitter = emitter.clone();
            let wan_resolver = wan_resolver.clone();
            let bounds = bounds.clone();
            handler(
                stream,
                peer,
                local_addr,
                session_id,
                emitter,
                wan_resolver,
                bounds,
            )
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_tls_adds_key_only_when_true() {
        let event = SensorEvent {
            v: sensor_wire::WIRE_VERSION,
            source_ip: "192.0.2.1".parse().unwrap(),
            wan_ip: None,
            sensor: "x".to_string(),
            signal_type: sensor_wire::SIGNAL_HONEYPOT_CONNECTION.to_string(),
            protocol: sensor_wire::PROTO_TCP.to_string(),
            authenticated: false,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({ "protocol_label": "x" }),
            sample: None,
            session_id: None,
            occurrence_id: None,
        };
        let plain = with_tls(event.clone(), false);
        assert_eq!(plain.metadata, event.metadata);
        assert!(plain.metadata.get("tls").is_none());
        let tls = with_tls(event, true);
        assert_eq!(tls.metadata["tls"], serde_json::Value::Bool(true));
        assert_eq!(tls.metadata["protocol_label"], "x");
    }

    #[tokio::test]
    async fn write_flush_delivers_a_reply_queued_behind_backpressure() {
        use tokio::io::AsyncReadExt;
        use tokio_rustls::TlsConnector;
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let tls = CredTls::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .unwrap();
        let client = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // A 64-byte pipe: the 1000-byte reply cannot leave in one poll_write.
        let (server_io, client_io) = tokio::io::duplex(64);
        let reply = vec![0x5Au8; 1000];
        let expected = reply.clone();
        let server = tokio::spawn(async move {
            let mut stream = tls.inband.accept(server_io).await.unwrap();
            write_flush(&mut stream, &reply).await.unwrap();
            // Dropped without shutdown, as a handler that returns: anything still inside rustls
            // is lost here.
        });
        let mut conn = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
            .await
            .unwrap();
        let mut got = Vec::new();
        let mut chunk = [0u8; 256];
        while let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_secs(5), conn.read(&mut chunk)).await
        {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&chunk[..n]);
        }
        server.await.unwrap();
        assert_eq!(got, expected);
    }
}
