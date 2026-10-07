pub mod handler;

use std::env::VarError;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use sensor_framework::{
    ConnectionBounds, EventEmitter, MaybeTlsStream, TlsServer, WanResolver,
    load_server_config_with_env, run_tcp_listener, run_tls_listener,
};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub enum ListenerKind {
    /// Plaintext listener (25, 587). STARTTLS upgrades the session iff `tls` is `Some`; without a
    /// certificate it gets the unchanged `454` reply.
    Plain { tls: Option<TlsServer> },
    /// SMTPS (465): the TLS handshake happens before the banner.
    Implicit { tls: TlsServer },
}

/// The listeners to start, in bind order: the main port, the optional submission port, the
/// optional implicit-TLS port. A TLS bind without a loaded certificate is refused here, so no
/// path can serve implicit TLS (or any listener) without a config that already validated.
pub fn plan_listeners(
    bind: SocketAddr,
    submission: Option<SocketAddr>,
    tls_bind: Option<SocketAddr>,
    tls: Option<TlsServer>,
) -> Result<Vec<(SocketAddr, ListenerKind)>, &'static str> {
    let mut plan = vec![(bind, ListenerKind::Plain { tls: tls.clone() })];
    if let Some(addr) = submission {
        plan.push((addr, ListenerKind::Plain { tls: tls.clone() }));
    }
    if let Some(addr) = tls_bind {
        let Some(tls) = tls else {
            return Err("a TLS bind is configured but no certificate and key were loaded");
        };
        plan.push((addr, ListenerKind::Implicit { tls }));
    }
    Ok(plan)
}

/// Resolve the TLS configuration from the environment, fail-closed. `lookup` is `std::env::var`
/// in production. TLS is on iff BOTH the cert and key variables are set (a blank value counts as
/// unset). A non-UTF-8 value on either variable, exactly one set, an unreadable or invalid pair,
/// or a TLS bind with neither set is an error the caller must treat as fatal before binding
/// anything.
pub fn tls_from_env(
    cert_var: &str,
    key_var: &str,
    tls_bind_configured: bool,
    lookup: impl Fn(&str) -> Result<String, VarError>,
) -> Result<Option<TlsServer>, String> {
    let is_set = |var: &str| match lookup(var) {
        Ok(value) => Ok(!value.trim().is_empty()),
        Err(VarError::NotPresent) => Ok(false),
        Err(VarError::NotUnicode(_)) => Err(format!("{var} is set but is not valid UTF-8")),
    };
    match (is_set(cert_var)?, is_set(key_var)?) {
        (false, false) if tls_bind_configured => Err(format!(
            "a TLS bind is configured but {cert_var} and {key_var} are not set"
        )),
        (false, false) => Ok(None),
        (true, false) => Err(format!("{cert_var} is set but {key_var} is not")),
        (false, true) => Err(format!("{key_var} is set but {cert_var} is not")),
        (true, true) => load_server_config_with_env(cert_var, key_var, &lookup)
            .map(|config| Some(TlsServer::from_config(config)))
            .map_err(|e| e.to_string()),
    }
}

/// Single plaintext listener, no TLS. Kept for the integration tests; production goes through
/// [`start_listeners`].
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
    let mut started = start_listeners(
        vec![(addr, ListenerKind::Plain { tls: None })],
        log_path,
        wan_resolver,
        bounds,
    )
    .await?;
    Ok(started.remove(0))
}

/// Bind every listener in order, sharing one event emitter. If any bind fails the listeners
/// already started are aborted and the error is returned: a half-bound sensor would make the
/// derived fleet inventory claim ports that are not served. Each listener keeps its own
/// connection cap and per-source cap (`run_tcp_listener` owns them per bind).
pub async fn start_listeners(
    listeners: Vec<(SocketAddr, ListenerKind)>,
    log_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) -> std::io::Result<Vec<(SocketAddr, JoinHandle<()>)>> {
    let emitter = Arc::new(EventEmitter::new(log_path));
    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    let mut started: Vec<(SocketAddr, JoinHandle<()>)> = Vec::new();
    for (addr, kind) in listeners {
        let emitter = emitter.clone();
        let wan_resolver = wan_resolver.clone();
        let session_bounds = bounds.clone();
        let result = match kind {
            ListenerKind::Plain { tls } => {
                run_tcp_listener(
                    addr,
                    bounds.clone(),
                    per_source_cap,
                    move |stream, peer, session_id| {
                        // Taken here, before any handshake can consume the stream.
                        let local_addr = stream.local_addr().ok();
                        let emitter = emitter.clone();
                        let wan_resolver = wan_resolver.clone();
                        let bounds = session_bounds.clone();
                        let tls = tls.clone();
                        async move {
                            handler::handle_connection(
                                MaybeTlsStream::Plain(stream),
                                peer,
                                local_addr,
                                session_id,
                                emitter,
                                wan_resolver,
                                bounds,
                                tls,
                            )
                            .await;
                        }
                    },
                )
                .await
            }
            ListenerKind::Implicit { tls } => {
                let acceptor = tls.clone();
                run_tls_listener(
                    addr,
                    bounds.clone(),
                    per_source_cap,
                    acceptor,
                    move |stream, peer, local_addr, session_id| {
                        let emitter = emitter.clone();
                        let wan_resolver = wan_resolver.clone();
                        let bounds = session_bounds.clone();
                        let tls = tls.clone();
                        async move {
                            handler::handle_connection(
                                MaybeTlsStream::Tls(Box::new(stream)),
                                peer,
                                local_addr,
                                session_id,
                                emitter,
                                wan_resolver,
                                bounds,
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
                for (_, handle) in &started {
                    handle.abort();
                }
                return Err(e);
            }
        }
    }
    Ok(started)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn server() -> TlsServer {
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
    fn plan_listeners_orders_and_requires_tls_for_the_tls_bind() {
        let plan = plan_listeners(addr(25), None, None, None).unwrap();
        assert_eq!(plan.len(), 1);
        assert!(matches!(plan[0].1, ListenerKind::Plain { tls: None }));

        let plan =
            plan_listeners(addr(25), Some(addr(587)), Some(addr(465)), Some(server())).unwrap();
        let addrs: Vec<_> = plan.iter().map(|(a, _)| a.port()).collect();
        assert_eq!(addrs, [25, 587, 465]);
        assert!(matches!(plan[0].1, ListenerKind::Plain { tls: Some(_) }));
        assert!(matches!(plan[1].1, ListenerKind::Plain { tls: Some(_) }));
        assert!(matches!(plan[2].1, ListenerKind::Implicit { .. }));

        assert!(plan_listeners(addr(25), None, Some(addr(465)), None).is_err());
        assert!(plan_listeners(addr(25), Some(addr(587)), Some(addr(465)), None).is_err());

        let plan = plan_listeners(addr(25), None, None, Some(server())).unwrap();
        assert_eq!(plan.len(), 1);
        assert!(matches!(plan[0].1, ListenerKind::Plain { tls: Some(_) }));
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name| map.get(name).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn tls_from_env_decision_table() {
        let none = |bind| tls_from_env("C", "K", bind, env_of(&[]));
        assert!(matches!(none(false), Ok(None)));
        assert!(none(true).is_err());

        // Blank counts as unset.
        assert!(matches!(
            tls_from_env("C", "K", false, env_of(&[("C", ""), ("K", "  ")])),
            Ok(None)
        ));

        // Exactly one of the pair is an error with or without a TLS bind.
        for bind in [false, true] {
            assert!(tls_from_env("C", "K", bind, env_of(&[("C", "/x")])).is_err());
            assert!(tls_from_env("C", "K", bind, env_of(&[("K", "/x")])).is_err());
        }
        // A blank partner does not rescue a lone value.
        assert!(tls_from_env("C", "K", false, env_of(&[("C", "/x"), ("K", " ")])).is_err());

        // Both set but unreadable: an error, never Ok(None).
        assert!(
            tls_from_env(
                "C",
                "K",
                false,
                env_of(&[("C", "/nonexistent/c"), ("K", "/nonexistent/k")])
            )
            .is_err()
        );
    }

    #[test]
    fn tls_from_env_not_unicode_is_an_error_not_off() {
        for bad in ["C", "K"] {
            let lookup = |name: &str| {
                if name == bad {
                    Err(VarError::NotUnicode(std::ffi::OsString::new()))
                } else {
                    Err(VarError::NotPresent)
                }
            };
            let err = tls_from_env("C", "K", false, lookup)
                .err()
                .expect("a non-UTF-8 TLS variable must be an error, never TLS off");
            assert!(err.contains(bad) && err.contains("UTF-8"), "{err}");
        }
    }
}
