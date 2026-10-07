//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. Two listeners write one log here (22 and 2222 in
//! a deployment that binds both), and each real-client session's events must carry its own port.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::SensorEvent;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(30),
        idle_timeout: Duration::from_secs(60),
        max_duration: Duration::from_secs(120),
        max_captured_bytes: 1_000_000,
        max_concurrent: 64,
    }
}

/// Accepts any host key: this is our own honeypot, not a third party.
struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn sessions_by_port(events: &[SensorEvent]) -> HashMap<u16, usize> {
    let mut sessions: HashMap<u16, HashSet<_>> = HashMap::new();
    for e in events {
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        sessions.entry(port).or_default().insert(e.session_id);
    }
    sessions.into_iter().map(|(p, s)| (p, s.len())).collect()
}

#[tokio::test]
async fn each_listeners_sessions_carry_its_own_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let mut listeners = Vec::new();
    for n in 1..=2usize {
        let (addr, handle) = sensor_ssh::serve(
            "127.0.0.1:0".parse().unwrap(),
            log.clone(),
            dir.path().join(format!("spool{n}")),
            dir.path().join(format!("host_key{n}")),
            Arc::new(WanResolver::new(HashMap::new())),
            bounds(),
            "OpenSSH_9.6p1".to_string(),
            "test".to_string(),
            dir.path().join(format!("outbox{n}")),
        )
        .await
        .unwrap();
        for _ in 0..n {
            let config = Arc::new(russh::client::Config::default());
            let mut session = russh::client::connect(config, addr, TestHandler)
                .await
                .unwrap();
            let auth = session
                .authenticate_password("root", "123456")
                .await
                .unwrap();
            assert!(auth.success());
            let channel = session.channel_open_session().await.unwrap();
            channel.exec(true, &b"uname -a"[..]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        listeners.push((addr, handle));
    }

    let want = HashMap::from([(listeners[0].0.port(), 1), (listeners[1].0.port(), 2)]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let seen = events(&log);
        let execs = seen
            .iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
            .count();
        if execs >= 3 && sessions_by_port(&seen) == want {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sessions per port {:?}, want {want:?}; {seen:?}",
            sessions_by_port(&seen)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(events(&log).iter().all(|e| e.protocol == "tcp"));
    for (_, handle) in listeners {
        handle.abort();
    }
}
