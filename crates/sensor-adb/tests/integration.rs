//! Real-client integration tests: connects a plain `tokio::net::TcpStream` to this crate's own
//! honeypot and speaks the ADB wire protocol directly (via `sensor_adb::adb_proto`'s public
//! builders/parsers - the same functions the server itself uses, so a test failure here reflects
//! a real protocol-shape mismatch, not a divergent hand-rolled test-side implementation) to
//! verify events, protocol_label, and the "authenticated=false on everything" invariant end to
//! end.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sensor_adb::adb_proto::{self, Header, SyncHeader};
use sensor_framework::{ConnectionBounds, WanResolver};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(30),
        max_captured_bytes: 5_000_000,
        max_concurrent: 100,
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start() -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_adb::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            wan_resolver,
            test_bounds(),
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
            spool_dir,
            handle,
            _dir: dir,
        }
    }

    async fn events(&self) -> Vec<sensor_wire::SensorEvent> {
        let content = tokio::fs::read_to_string(&self.log_path)
            .await
            .unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event line: {e}: {l}")))
            .collect()
    }
}

/// Read exactly one ADB message off `stream`, with a generous timeout so a hung/broken server
/// fails the test loudly instead of hanging the suite.
async fn read_message(stream: &mut TcpStream) -> (Header, Vec<u8>) {
    let fut = async {
        let mut header_buf = [0u8; adb_proto::HEADER_LEN];
        stream
            .read_exact(&mut header_buf)
            .await
            .expect("read header");
        let header = Header::parse(&header_buf).expect("well-formed header (magic must match)");
        let mut data = vec![0u8; header.data_length as usize];
        if header.data_length > 0 {
            stream.read_exact(&mut data).await.expect("read payload");
        }
        (header, data)
    };
    tokio::time::timeout(Duration::from_secs(3), fut)
        .await
        .expect("timed out waiting for a message")
}

async fn cnxn_handshake(stream: &mut TcpStream) -> String {
    stream
        .write_all(&adb_proto::build_cnxn(&adb_proto::host_banner()))
        .await
        .unwrap();
    let (header, data) = read_message(stream).await;
    assert_eq!(header.command, adb_proto::A_CNXN);
    String::from_utf8_lossy(&data).into_owned()
}

/// `OPEN` a stream and consume the server's `OKAY`, returning the server-minted stream id.
async fn open_stream(stream: &mut TcpStream, local_id: u32, dest: &str) -> u32 {
    stream
        .write_all(&adb_proto::build_open(local_id, dest))
        .await
        .unwrap();
    let (header, _data) = read_message(stream).await;
    assert_eq!(
        header.command,
        adb_proto::A_OKAY,
        "OPEN {dest} was not accepted"
    );
    assert_eq!(header.arg1, local_id);
    header.arg0
}

/// Send one line of shell input and read back the outer OKAY ack plus the WRTE-wrapped output.
async fn send_shell_line(
    stream: &mut TcpStream,
    local_id: u32,
    server_id: u32,
    line: &str,
) -> String {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    stream
        .write_all(&adb_proto::build_wrte(local_id, server_id, &bytes))
        .await
        .unwrap();
    let (ack, _) = read_message(stream).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let (wrte, data) = read_message(stream).await;
    assert_eq!(wrte.command, adb_proto::A_WRTE);
    String::from_utf8_lossy(&data).into_owned()
}

/// Drive a full `sync:` `SEND` (push) as separate WRTE-per-sync-submessage writes, exactly as a
/// real client trickling a file across several writes would - this exercises the sync
/// reassembly buffer's cross-call persistence, not just the single-WRTE-batched shape.
async fn sync_push(stream: &mut TcpStream, local_id: u32, server_id: u32, path: &str, body: &[u8]) {
    let send_payload = format!("{path},33188");
    stream
        .write_all(&adb_proto::build_wrte(
            local_id,
            server_id,
            &adb_proto::build_sync_message(adb_proto::SYNC_SEND, send_payload.as_bytes()),
        ))
        .await
        .unwrap();
    let (h, _) = read_message(stream).await;
    assert_eq!(h.command, adb_proto::A_OKAY, "SEND header not acked");

    stream
        .write_all(&adb_proto::build_wrte(
            local_id,
            server_id,
            &adb_proto::build_sync_message(adb_proto::SYNC_DATA, body),
        ))
        .await
        .unwrap();
    let (h, _) = read_message(stream).await;
    assert_eq!(h.command, adb_proto::A_OKAY, "DATA chunk not acked");

    stream
        .write_all(&adb_proto::build_wrte(
            local_id,
            server_id,
            &adb_proto::build_sync_done(1_700_000_000),
        ))
        .await
        .unwrap();
    let (h, _) = read_message(stream).await;
    assert_eq!(h.command, adb_proto::A_OKAY, "DONE not acked");
    let (h2, data2) = read_message(stream).await;
    assert_eq!(h2.command, adb_proto::A_WRTE);
    let sync_reply = SyncHeader::parse(&data2).expect("sync sub-header");
    assert_eq!(
        sync_reply.id,
        adb_proto::SYNC_OKAY,
        "expected sync OKAY once SEND completes"
    );
    // outer flow-control ack for the server's WRTE
    stream
        .write_all(&adb_proto::build_okay(local_id, server_id))
        .await
        .unwrap();
}

// -------------------------------------------------------------------------------------------
// given suite (task brief): CNXN handshake, shell command capture, push file capture in spool,
// pull refused, protocol_label="adb"/authenticated=false on all events, never-exec, no outbound
// connection, malformed input doesn't crash.
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn cnxn_handshake_completes() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    let banner = cnxn_handshake(&mut conn).await;
    assert!(banner.starts_with("device::"), "banner: {banner}");
    assert!(banner.contains("ro.product.model"));
    srv.handle.abort();
}

#[tokio::test]
async fn shell_command_capture_via_fakeshell() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 7, "shell:").await;

    // interactive shell: OPEN is immediately followed by an initial prompt WRTE.
    let (prompt_hdr, prompt_data) = read_message(&mut conn).await;
    assert_eq!(prompt_hdr.command, adb_proto::A_WRTE);
    assert!(!prompt_data.is_empty());

    let output = send_shell_line(&mut conn, 7, server_id, "whoami").await;
    assert!(output.contains("root"), "output: {output}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .expect("honeypot_command_exec event");
    assert_eq!(
        cmd_event.metadata.get("command").and_then(|v| v.as_str()),
        Some("whoami")
    );
    assert!(!cmd_event.authenticated);
    assert_eq!(cmd_event.sensor, "adb");
    srv.handle.abort();
}

#[tokio::test]
async fn push_file_captured_to_spool() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "sync:").await;

    let body = b"MZ-fake-payload-bytes-not-real-malware";
    sync_push(&mut conn, 1, server_id, "/data/local/tmp/evil.bin", body).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = srv.events().await;
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("honeypot_malware_upload event");
    assert!(
        !upload.authenticated,
        "ADB events are always authenticated=false"
    );
    let sample = upload.sample.as_ref().expect("sample ref");
    assert_eq!(sample.size, body.len() as u64);
    assert_eq!(sample.orig_name, "/data/local/tmp/evil.bin");

    // `sha2`'s digest output is a `hybrid-array` `Array<u8, U32>`, which does not implement
    // `LowerHex` in the version this workspace resolves (see sensor_framework::spool's own doc
    // comment on this) - hex-encode via the crate's shared helper instead of `{:x}`.
    use sha2::{Digest, Sha256};
    let expected_hash = sensor_framework::to_hex_bounded(&Sha256::digest(body), 32);
    assert_eq!(sample.sha256, expected_hash);

    let spooled_path = srv.spool_dir.join(&sample.sha256);
    let on_disk = tokio::fs::read(&spooled_path)
        .await
        .expect("spooled file must exist on disk under its sha256 name");
    assert_eq!(on_disk, body);

    srv.handle.abort();
}

#[tokio::test]
async fn pull_refused() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "sync:").await;

    stream_recv_and_expect_fail(&mut conn, 1, server_id, "/data/local/tmp/secret_keys.db").await;

    // No malware_download-shaped event exists in the wire contract for adb; the load-bearing
    // property is simply that no file content is ever served back and the sensor stays up.
    let mut probe = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut probe).await;
    srv.handle.abort();
}

async fn stream_recv_and_expect_fail(
    stream: &mut TcpStream,
    local_id: u32,
    server_id: u32,
    path: &str,
) {
    stream
        .write_all(&adb_proto::build_wrte(
            local_id,
            server_id,
            &adb_proto::build_sync_message(adb_proto::SYNC_RECV, path.as_bytes()),
        ))
        .await
        .unwrap();
    let (h, _) = read_message(stream).await;
    assert_eq!(h.command, adb_proto::A_OKAY);
    let (h2, data2) = read_message(stream).await;
    assert_eq!(h2.command, adb_proto::A_WRTE);
    let sync_reply = SyncHeader::parse(&data2).unwrap();
    assert_eq!(
        sync_reply.id,
        adb_proto::SYNC_FAIL,
        "RECV/pull must be refused, never served"
    );
    assert!(!data2[adb_proto::SYNC_HEADER_LEN..].is_empty());
}

#[tokio::test]
async fn protocol_label_and_authenticated_false_on_all_events() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;

    let shell_id = open_stream(&mut conn, 2, "shell:").await;
    let _ = read_message(&mut conn).await; // initial prompt
    send_shell_line(&mut conn, 2, shell_id, "id").await;

    let sync_id = open_stream(&mut conn, 3, "sync:").await;
    sync_push(&mut conn, 3, sync_id, "/tmp/x.bin", b"payload-bytes").await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = srv.events().await;
    assert!(
        events.len() >= 3,
        "expected connection+command+upload events, got {events:?}"
    );
    for event in &events {
        assert_eq!(event.sensor, "adb");
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
        assert!(
            !event.authenticated,
            "ADB has no authentication; every event must be authenticated=false, got: {event:?}"
        );
        let label = event
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str());
        assert_eq!(label, Some("adb"), "protocol_label must be 'adb'");
    }
    srv.handle.abort();
}

#[test]
fn never_exec_static_check() {
    // Mirrors sensor-telnet's / sensor-redis's tests/integration.rs::never_exec_static_check,
    // scoped to sensor-adb's own source. sensor-framework (where FakeFs/FakeShell/CaptureHandoff
    // actually live) is already covered by sensor-ssh's copy of this same check.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = walkdir_or_manual(&src_dir);
    assert!(
        !files.is_empty(),
        "expected to find sensor-adb source files at {}",
        src_dir.display()
    );

    let mut found_exec = Vec::new();
    for entry in &files {
        let content = std::fs::read_to_string(entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found_exec.push(entry.display().to_string());
        }
    }
    assert!(
        found_exec.is_empty(),
        "sensor-adb must not contain process-spawning code: {found_exec:?}"
    );
}

#[tokio::test]
async fn no_outbound_connections_from_wget_in_shell() {
    // Mirrors sensor-telnet's own `no_outbound_connections_from_wget_in_shell` test: the shared
    // FakeShell's wget/curl handlers must perform zero real network I/O regardless of which
    // sensor drives them, and a sync `RECV` refusal must never dial anywhere either.
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = connection_count.clone();
    let target_task = tokio::spawn(async move {
        loop {
            if let Ok((_stream, _addr)) = target_listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "shell:").await;
    let _ = read_message(&mut conn).await; // initial prompt

    let cmd = format!("wget http://127.0.0.1:{}/malware.bin", target_addr.port());
    send_shell_line(&mut conn, 1, server_id, &cmd).await;

    let sync_id = open_stream(&mut conn, 2, "sync:").await;
    stream_recv_and_expect_fail(&mut conn, 2, sync_id, "/data/local/tmp/anything").await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    srv.handle.abort();
    target_task.abort();

    assert_eq!(
        connection_count.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sensor-adb must open ZERO outbound connections"
    );
}

#[tokio::test]
async fn malformed_random_bytes_drop_connection_without_crashing_listener() {
    let srv = TestServer::start().await;

    for seed in 0..5u8 {
        if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
            let garbage: Vec<u8> = (0..2048u32)
                .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
                .collect();
            let _ = conn.write_all(&garbage).await;
            drop(conn);
        }
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The listener must still be accepting new connections, and a real handshake still works.
    let mut conn = TcpStream::connect(srv.addr)
        .await
        .expect("accept loop must survive garbage");
    let banner = cnxn_handshake(&mut conn).await;
    assert!(banner.starts_with("device::"));
    srv.handle.abort();
}

#[tokio::test]
async fn cnxn_with_truncated_header_drops_connection_without_crashing_listener() {
    // A partial header (fewer than 24 bytes, then the connection is abandoned) must never hang
    // or crash the listener - it should simply time out/EOF the session.
    let srv = TestServer::start().await;
    {
        let mut conn = TcpStream::connect(srv.addr).await.unwrap();
        conn.write_all(&[0x43, 0x4e, 0x58]).await.unwrap(); // 3 bytes of "CNXN", then nothing
        drop(conn);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut conn = TcpStream::connect(srv.addr)
        .await
        .expect("listener must still accept");
    let banner = cnxn_handshake(&mut conn).await;
    assert!(banner.starts_with("device::"));
    srv.handle.abort();
}

// -------------------------------------------------------------------------------------------
// additional coverage, not in the brief's given suite - see each test's comment for the
// wrong-but-plausible implementation it rules out, mirroring how sensor-telnet/sensor-redis's
// own reports documented their added coverage.
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn connection_event_emitted_and_unauthenticated_even_when_client_never_sends_cnxn() {
    // Proves the connection event is not gated on protocol completion: a bare TCP connect that
    // never speaks ADB at all must still be logged, since the accept itself is the observation.
    let srv = TestServer::start().await;
    {
        let _conn = TcpStream::connect(srv.addr).await.unwrap();
        // never write anything; just drop
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let conn_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
        .expect("honeypot_connection event even with no CNXN sent");
    assert!(!conn_event.authenticated);
    srv.handle.abort();
}

#[tokio::test]
async fn shell_one_shot_exec_runs_once_and_closes_stream() {
    // `shell:<command>` (a destination with a command embedded) must run exactly once and close
    // the stream itself, mirroring real adb's `adb shell <cmd>` semantics and sensor-ssh's
    // `ChannelAction::Exec` one-shot pattern - distinct from the bare `shell:` interactive case,
    // which stays open and never sends an unsolicited CLSE.
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;

    conn.write_all(&adb_proto::build_open(9, "shell:id"))
        .await
        .unwrap();
    let (okay, _) = read_message(&mut conn).await;
    assert_eq!(okay.command, adb_proto::A_OKAY);
    let server_id = okay.arg0;

    let (wrte, data) = read_message(&mut conn).await;
    assert_eq!(wrte.command, adb_proto::A_WRTE);
    assert!(String::from_utf8_lossy(&data).contains("uid=0"));
    conn.write_all(&adb_proto::build_okay(9, server_id))
        .await
        .unwrap();

    let (clse, _) = read_message(&mut conn).await;
    assert_eq!(
        clse.command,
        adb_proto::A_CLSE,
        "one-shot shell:<command> must close the stream once the command completes"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let cmd_event = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .unwrap();
    assert_eq!(
        cmd_event.metadata.get("command").and_then(|v| v.as_str()),
        Some("id")
    );
    srv.handle.abort();
}

#[tokio::test]
async fn multiple_shell_commands_each_captured_as_separate_events_in_order() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "shell:").await;
    let _ = read_message(&mut conn).await; // initial prompt

    send_shell_line(&mut conn, 1, server_id, "whoami").await;
    send_shell_line(&mut conn, 1, server_id, "id").await;
    send_shell_line(&mut conn, 1, server_id, "pwd").await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let commands: Vec<&str> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .filter_map(|e| e.metadata.get("command").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(commands, vec!["whoami", "id", "pwd"]);
    srv.handle.abort();
}

#[tokio::test]
async fn orig_name_is_sanitized_in_malware_upload_event() {
    // Mirrors sensor_framework::handoff's own `orig_name_is_sanitized_before_reaching_the_event`
    // test, end to end through this sensor: an attacker-chosen path carrying a CR/LF must never
    // reach the NDJSON log unsanitized (the log-injection threat ADR-0010/sanitize.rs exist to
    // close), even though the raw bytes traveled through this crate's own SEND-path parsing
    // first, not sensor-ssh's.
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "sync:").await;

    let evil_path = "/data/local/tmp/evil\r\nname.bin";
    sync_push(&mut conn, 1, server_id, evil_path, b"x").await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let content = tokio::fs::read_to_string(&srv.log_path).await.unwrap();
    assert!(!content.contains('\r'), "raw CR must never reach the log");
    let events = srv.events().await;
    let upload = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .unwrap();
    let sample = upload.sample.as_ref().unwrap();
    assert!(!sample.orig_name.contains('\r'));
    assert!(!sample.orig_name.contains('\n'));
    srv.handle.abort();
}

#[tokio::test]
async fn concurrent_shell_and_sync_streams_on_one_connection() {
    // Real adb multiplexes multiple logical streams over one TCP connection (see handler.rs's
    // module doc); a bot or a real adb client can have a shell session and a sync push open at
    // once. Interleaving them here proves the per-stream id table routes WRTE/OKAY correctly
    // rather than assuming a single active stream per connection.
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;

    let shell_server_id = open_stream(&mut conn, 10, "shell:").await;
    let _ = read_message(&mut conn).await; // initial prompt
    let sync_server_id = open_stream(&mut conn, 20, "sync:").await;
    assert_ne!(shell_server_id, sync_server_id);

    let out = send_shell_line(&mut conn, 10, shell_server_id, "whoami").await;
    assert!(out.contains("root"));

    sync_push(
        &mut conn,
        20,
        sync_server_id,
        "/tmp/concurrent.bin",
        b"concurrent-body",
    )
    .await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let events = srv.events().await;
    assert!(
        events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
    );
    assert!(
        events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
    );
    srv.handle.abort();
}

#[tokio::test]
async fn open_flood_is_capped_with_close_not_unbounded_streams() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;

    // Fill the per-connection stream table (MAX_STREAMS_PER_CONN = 32) with sync streams.
    for local_id in 1..=32u32 {
        let _ = open_stream(&mut conn, local_id, "sync:").await;
    }
    // The next OPEN must be refused with a CLSE (not OKAY) rather than allocating another
    // FakeShell/FakeFs - the guard against an OPEN-flood OOM.
    conn.write_all(&adb_proto::build_open(33, "sync:"))
        .await
        .unwrap();
    let (header, _) = read_message(&mut conn).await;
    assert_eq!(
        header.command,
        adb_proto::A_CLSE,
        "the 33rd concurrent OPEN must be refused with CLSE, got {:#x}",
        header.command
    );
    srv.handle.abort();
}

#[tokio::test]
async fn unsupported_open_destination_is_refused_with_close_not_okay() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;

    conn.write_all(&adb_proto::build_open(5, "tcp:9999"))
        .await
        .unwrap();
    let (header, _data) = read_message(&mut conn).await;
    assert_eq!(
        header.command,
        adb_proto::A_CLSE,
        "an unsupported destination must be refused via CLSE, not accepted with OKAY"
    );
    assert_eq!(header.arg1, 5);
    srv.handle.abort();
}

fn walkdir_or_manual(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    fn walk(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, files);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    files.push(path);
                }
            }
        }
    }
    walk(dir, &mut files);
    files
}
