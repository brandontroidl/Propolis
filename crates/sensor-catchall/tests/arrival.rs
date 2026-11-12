//! Every event names the listener it arrived on (`sensor_framework::arrival`): `protocol` the
//! transport and `metadata.local_port` the port. The catch-all binds many ports under one sensor
//! name and one log, over both transports, so a TCP and a UDP listener on the SAME port number are
//! a real deployment shape that only the pair (`protocol`, `local_port`) separates.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use sensor_framework::ConnectionBounds;
use sensor_wire::SensorEvent;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

fn events(log: &Path) -> Vec<SensorEvent> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn by_listener(events: &[SensorEvent]) -> HashMap<(String, u16), usize> {
    let mut out = HashMap::new();
    for e in events {
        let port = e.metadata["local_port"].as_u64().unwrap_or(0) as u16;
        *out.entry((e.protocol.clone(), port)).or_insert(0) += 1;
    }
    out
}

#[tokio::test]
async fn tcp_and_udp_listeners_on_many_ports_stamp_their_own_port() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("events.jsonl");
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (tcp_a, handle_a) = sensor_catchall::start_test_listener(any, log.clone())
        .await
        .unwrap();
    let (tcp_b, handle_b) = sensor_catchall::start_test_listener(any, log.clone())
        .await
        .unwrap();
    // UDP on the same port NUMBER as the first TCP listener: the separate port spaces make this
    // bindable, and it is the case grouping by port alone would merge.
    let udp_bounds = ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 4096,
        max_concurrent: 10,
    };
    let (udp, handle_udp) =
        sensor_catchall::start_test_udp_listener(tcp_a, udp_bounds, log.clone())
            .await
            .unwrap();
    assert_eq!(udp.port(), tcp_a.port());

    // 1 probe to tcp_a, 2 to tcp_b, 3 datagrams to udp.
    for (target, n) in [(tcp_a, 1), (tcp_b, 2)] {
        for _ in 0..n {
            let mut conn = TcpStream::connect(target).await.unwrap();
            conn.write_all(b"probe").await.unwrap();
            conn.shutdown().await.unwrap();
        }
    }
    // One at a time: concurrent datagrams from one source are capped, and a dropped one would
    // make the count wrong for a reason this test is not about.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for sent in 1..=3 {
        client.send_to(b"probe", udp).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while events(&log).iter().filter(|e| e.protocol == "udp").count() < sent {
            assert!(
                tokio::time::Instant::now() < deadline,
                "datagram {sent} not logged"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    let want = HashMap::from([
        (("tcp".to_string(), tcp_a.port()), 1),
        (("tcp".to_string(), tcp_b.port()), 2),
        (("udp".to_string(), udp.port()), 3),
    ]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while by_listener(&events(&log)) != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "events per listener: {:?}, want {want:?}",
            by_listener(&events(&log))
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    handle_a.abort();
    handle_b.abort();
    handle_udp.abort();
}
