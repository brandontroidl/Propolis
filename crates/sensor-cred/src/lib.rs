pub mod mongodb;
pub mod mssql;
pub mod mysql;
pub mod postgresql;
pub mod vnc;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver, run_tcp_listener};
use tokio::task::JoinHandle;

pub async fn start_listener(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    protocol: &'static str,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let emitter = Arc::new(EventEmitter::new(log_path));

    match protocol {
        "vnc" => start_with(addr, bounds, emitter, wan_resolver, vnc::handle_connection).await,
        "mysql" => {
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                mysql::handle_connection,
            )
            .await
        }
        "mssql" => {
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                mssql::handle_connection,
            )
            .await
        }
        "postgresql" => {
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                postgresql::handle_connection,
            )
            .await
        }
        "mongodb" => {
            start_with(
                addr,
                bounds,
                emitter,
                wan_resolver,
                mongodb::handle_connection,
            )
            .await
        }
        _ => panic!("unknown protocol: {protocol}"),
    }
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
    run_tcp_listener(addr, bounds.clone(), move |stream, peer, session_id| {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let bounds = bounds.clone();
        handler(stream, peer, session_id, emitter, wan_resolver, bounds)
    })
    .await
}
