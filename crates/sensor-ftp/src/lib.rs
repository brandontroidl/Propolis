pub mod handler;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    CaptureHandoff, CaptureMemoryBudget, ConnectionBounds, DEFAULT_CAPTURE_BUDGET_BYTES_256M,
    EventEmitter, MaybeTlsStream, OutboxManifest, QuarantineSpool, TlsServer, WanResolver,
    run_tcp_listener, run_tls_listener,
};
use tokio::task::JoinHandle;

const SPOOL_MAX_FILE_SIZE: u64 = 10_000_000;
const SPOOL_GLOBAL_BUDGET: u64 = 100_000_000;
const CAPTURE_QUEUE_SIZE: usize = 64;

pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let (bound, handle, _handoff) = start_test_server_with_handoff(
        addr,
        log_path,
        spool_dir,
        wan_resolver,
        bounds,
        collector_id,
        outbox_dir,
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
    )
    .await?;
    Ok((bound, handle))
}

/// How one listener treats TLS.
#[derive(Clone)]
pub enum ListenerKind {
    /// Plaintext control channel. AUTH TLS (and PBSZ/PROT) are honoured iff `tls` is `Some`.
    Plain { tls: Option<TlsServer> },
    /// Implicit FTPS (990): the handshake happens before the banner.
    Implicit { tls: TlsServer },
}

/// The listeners a sensor runs: `bind` always (plain, AUTH TLS iff `tls` is loaded) plus an
/// implicit-TLS listener when `tls_bind` is set. A TLS bind with no server config is an error.
pub fn plan_listeners(
    bind: SocketAddr,
    tls_bind: Option<SocketAddr>,
    tls: Option<TlsServer>,
) -> Result<Vec<(SocketAddr, ListenerKind)>, &'static str> {
    let mut plan = vec![(bind, ListenerKind::Plain { tls: tls.clone() })];
    if let Some(addr) = tls_bind {
        let Some(tls) = tls else {
            return Err("a TLS bind is configured but no certificate and key were loaded");
        };
        plan.push((addr, ListenerKind::Implicit { tls }));
    }
    Ok(plan)
}

/// `start_test_server` plus the capture hand-off, so `main` can `drain` it on shutdown, and the
/// process-wide capture memory budget `main` built from its configured ceiling. A separate
/// function rather than a wider return type so the many callers that never shut down (every
/// integration test) are unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn start_test_server_with_handoff(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
) -> std::io::Result<(SocketAddr, JoinHandle<()>, Arc<CaptureHandoff>)> {
    let (mut started, handoff) = start_listeners(
        vec![(addr, ListenerKind::Plain { tls: None })],
        log_path,
        spool_dir,
        wan_resolver,
        bounds,
        collector_id,
        outbox_dir,
        capture_budget,
    )
    .await?;
    let (bound, handle) = started.remove(0);
    Ok((bound, handle, handoff))
}

/// Starts every listener over ONE emitter, spool, capture hand-off and capture budget. A bind
/// failure on any listener aborts the ones already started and returns the error, so a half-bound
/// sensor never runs.
#[allow(clippy::too_many_arguments)]
pub async fn start_listeners(
    listeners: Vec<(SocketAddr, ListenerKind)>,
    log_path: PathBuf,
    spool_dir: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
) -> std::io::Result<(Vec<(SocketAddr, JoinHandle<()>)>, Arc<CaptureHandoff>)> {
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let spool = QuarantineSpool::new(spool_dir, SPOOL_MAX_FILE_SIZE, SPOOL_GLOBAL_BUDGET);
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        CAPTURE_QUEUE_SIZE,
        collector_id,
        OutboxManifest::new(outbox_dir),
        capture_budget,
    ));
    handoff.start_worker();

    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    let mut started: Vec<(SocketAddr, JoinHandle<()>)> = Vec::new();
    for (addr, kind) in listeners {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let conn_bounds = bounds.clone();
        let handoff = handoff.clone();
        let result = match kind {
            ListenerKind::Plain { tls } => {
                run_tcp_listener(
                    addr,
                    bounds.clone(),
                    per_source_cap,
                    move |stream, peer, session_id| {
                        let local_addr = stream.local_addr().ok();
                        let (emitter, wan_resolver) = (emitter.clone(), wan_resolver.clone());
                        let (conn_bounds, handoff, tls) =
                            (conn_bounds.clone(), handoff.clone(), tls.clone());
                        async move {
                            handler::handle_connection(
                                MaybeTlsStream::Plain(stream),
                                peer,
                                local_addr,
                                session_id,
                                emitter,
                                wan_resolver,
                                conn_bounds,
                                handoff,
                                tls,
                            )
                            .await;
                        }
                    },
                )
                .await
            }
            ListenerKind::Implicit { tls } => {
                let session_tls = tls.clone();
                run_tls_listener(
                    addr,
                    bounds.clone(),
                    per_source_cap,
                    tls,
                    move |stream, peer, local_addr, session_id| {
                        let (emitter, wan_resolver) = (emitter.clone(), wan_resolver.clone());
                        let (conn_bounds, handoff, tls) =
                            (conn_bounds.clone(), handoff.clone(), session_tls.clone());
                        async move {
                            handler::handle_connection(
                                MaybeTlsStream::Tls(Box::new(stream)),
                                peer,
                                local_addr,
                                session_id,
                                emitter,
                                wan_resolver,
                                conn_bounds,
                                handoff,
                                Some(tls),
                            )
                            .await;
                        }
                    },
                )
                .await
            }
        };
        match result {
            Ok(pair) => started.push(pair),
            Err(e) => {
                for (_, h) in &started {
                    h.abort();
                }
                return Err(e);
            }
        }
    }
    Ok((started, handoff))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server() -> TlsServer {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        TlsServer::from_config(
            sensor_framework::server_config_from_pem(
                cert.pem().as_bytes(),
                signing_key.serialize_pem().as_bytes(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn plan_listeners_requires_a_server_config_for_the_tls_bind() {
        let bind: SocketAddr = "127.0.0.1:21".parse().unwrap();
        let tls_bind: SocketAddr = "127.0.0.1:990".parse().unwrap();

        let plan = plan_listeners(bind, None, None).unwrap();
        assert_eq!(plan.len(), 1);
        assert!(matches!(plan[0].1, ListenerKind::Plain { tls: None }));

        let plan = plan_listeners(bind, Some(tls_bind), Some(test_server())).unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!((plan[0].0, plan[1].0), (bind, tls_bind));
        assert!(matches!(plan[0].1, ListenerKind::Plain { tls: Some(_) }));
        assert!(matches!(plan[1].1, ListenerKind::Implicit { .. }));

        assert!(plan_listeners(bind, Some(tls_bind), None).is_err());

        let plan = plan_listeners(bind, None, Some(test_server())).unwrap();
        assert_eq!(plan.len(), 1);
        assert!(matches!(plan[0].1, ListenerKind::Plain { tls: Some(_) }));
    }
}
