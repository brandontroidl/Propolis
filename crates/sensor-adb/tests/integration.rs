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
        TestServer::start_with(test_bounds()).await
    }

    async fn start_with(bounds: ConnectionBounds) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_adb::start_test_server(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            wan_resolver,
            bounds,
            "test".to_string(),
            dir.path().join("outbox"),
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

    /// A server whose per-source command-event budget is `rate` per second after a burst of
    /// `burst`.
    async fn start_with_command_budget(rate: u32, burst: u32) -> TestServer {
        use sensor_framework::{
            CaptureMemoryBudget, CommandEventConfig, CommandEventGate,
            DEFAULT_CAPTURE_BUDGET_BYTES_256M, Rate,
        };
        use std::num::NonZeroU32;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool_dir = dir.path().join("spool");
        let gate = CommandEventGate::new(CommandEventConfig {
            rate: Rate::new(
                NonZeroU32::new(rate).unwrap(),
                NonZeroU32::new(burst).unwrap(),
            ),
            ..CommandEventConfig::default()
        });
        let (addr, handle, _handoff) = sensor_adb::start_test_server_with_handoff(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            spool_dir.clone(),
            Arc::new(WanResolver::new(HashMap::new())),
            test_bounds(),
            "test".to_string(),
            dir.path().join("outbox"),
            Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
            Arc::new(gate),
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

async fn acknowledge_wrte(stream: &mut TcpStream, header: &Header) {
    assert_eq!(header.command, adb_proto::A_WRTE);
    stream
        .write_all(&adb_proto::build_okay(header.arg1, header.arg0))
        .await
        .unwrap();
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
    let mut output = Vec::new();
    loop {
        let (wrte, data) = read_message(stream).await;
        assert_eq!(wrte.command, adb_proto::A_WRTE);
        output.extend_from_slice(&data);
        acknowledge_wrte(stream, &wrte).await;
        if output.ends_with(b"# ") || output.ends_with(b"$ ") {
            break;
        }
    }
    String::from_utf8_lossy(&output).into_owned()
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
async fn shell_output_obeys_peer_maxdata_and_waits_for_each_okay() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    conn.write_all(&adb_proto::build_message(
        adb_proto::A_CNXN,
        adb_proto::OUR_VERSION,
        7,
        adb_proto::host_banner().as_bytes(),
    ))
    .await
    .unwrap();
    let (cnxn, _) = read_message(&mut conn).await;
    assert_eq!(cnxn.command, adb_proto::A_CNXN);

    conn.write_all(&adb_proto::build_open(4, "shell:id"))
        .await
        .unwrap();
    let (okay, _) = read_message(&mut conn).await;
    assert_eq!(okay.command, adb_proto::A_OKAY);
    let server_id = okay.arg0;

    let (first, first_data) = read_message(&mut conn).await;
    assert_eq!(first.command, adb_proto::A_WRTE);
    assert_eq!(first_data.len(), 7);
    let mut probe = [0u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), conn.peek(&mut probe))
            .await
            .is_err(),
        "the server sent a second WRTE before the first was acknowledged"
    );

    let mut output = first_data;
    conn.write_all(&adb_proto::build_okay(4, server_id))
        .await
        .unwrap();
    loop {
        let (header, data) = read_message(&mut conn).await;
        match header.command {
            adb_proto::A_WRTE => {
                assert!(data.len() <= 7, "WRTE exceeded peer maxdata");
                output.extend_from_slice(&data);
                conn.write_all(&adb_proto::build_okay(4, server_id))
                    .await
                    .unwrap();
            }
            adb_proto::A_CLSE => break,
            other => panic!("unexpected ADB command {other:#x}"),
        }
    }
    assert!(String::from_utf8_lossy(&output).contains("uid=0"));
    assert!(output.windows(2).any(|pair| pair == b"\r\n"));
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
    acknowledge_wrte(&mut conn, &prompt_hdr).await;

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
async fn interactive_shell_closes_only_after_the_outer_android_shell_exits() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let local_id = 8;
    let server_id = open_stream(&mut conn, local_id, "shell:").await;

    let (prompt, prompt_data) = read_message(&mut conn).await;
    assert_eq!(prompt.command, adb_proto::A_WRTE);
    assert_eq!(
        String::from_utf8_lossy(&prompt_data),
        sensor_framework::persona::android_root_prompt("/")
    );
    acknowledge_wrte(&mut conn, &prompt).await;

    let blank = send_shell_line(&mut conn, local_id, server_id, "").await;
    assert_eq!(
        blank,
        format!(
            "\r\n{}",
            sensor_framework::persona::android_root_prompt("/")
        ),
        "empty Enter echoes a newline and reprints the prompt"
    );

    let nested = send_shell_line(&mut conn, local_id, server_id, "sh").await;
    assert_eq!(
        nested,
        format!(
            "sh\r\n{}",
            sensor_framework::persona::android_root_prompt("/")
        ),
        "opening a nested Android shell keeps the stream open"
    );
    let returned = send_shell_line(&mut conn, local_id, server_id, "exit").await;
    assert_eq!(
        returned,
        format!(
            "exit\r\n{}",
            sensor_framework::persona::android_root_prompt("/")
        ),
        "the first exit returns to the outer shell"
    );

    conn.write_all(&adb_proto::build_wrte(local_id, server_id, b"exit\n"))
        .await
        .unwrap();
    let (ack, _) = read_message(&mut conn).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let (final_output, final_data) = read_message(&mut conn).await;
    assert_eq!(final_data, b"exit\r\n");
    acknowledge_wrte(&mut conn, &final_output).await;
    let (close, _) = read_message(&mut conn).await;
    assert_eq!(close.command, adb_proto::A_CLSE);
    assert_eq!(close.arg0, server_id);
    assert_eq!(close.arg1, local_id);
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

    wait_for_upload_event(&srv.log_path).await;
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

/// Poll `spool_dir` for a capture rather than sleeping a fixed time: the hand-off worker runs off
/// the connection's response path, so there is no synchronous point at which it is observably
/// done. Returns false if nothing arrives, which is what the negative test asserts - and absence
/// here settles the event log too, since `handoff::process_job` writes the body before it appends
/// the event. A test asserting an event is PRESENT must wait on `wait_for_upload_event` instead,
/// for the same ordering read the other way.
async fn wait_for_spooled_file(spool_dir: &std::path::Path) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while std::time::Instant::now() < deadline {
        if !spooled_files(spool_dir).is_empty() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Poll the event log for the capture's own `honeypot_malware_upload` line. The spooled body is
/// written first and the event appended only after the outbox manifest row is fsynced
/// (`handoff::process_job`), so waiting on the body can return before the event a caller then
/// asserts on exists - a window that stays shut on an idle machine and opens on a loaded CI
/// runner. Waiting on the event covers the body too, which lands strictly earlier.
async fn wait_for_upload_event(log_path: &std::path::Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let content = tokio::fs::read_to_string(log_path)
            .await
            .unwrap_or_default();
        let recorded = content.lines().any(|line| {
            serde_json::from_str::<sensor_wire::SensorEvent>(line)
                .is_ok_and(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        });
        if recorded {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a honeypot_malware_upload event in {log_path:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Drive one unterminated binary payload at an interactive `adb shell` stream and return the
/// upload event plus the bytes that reached the spool. `close_stream` sends the client's own CLSE
/// instead of leaving the session to end on its own, which is the difference between a transfer
/// the peer finished and one that was cut off.
async fn shell_payload_session(
    bounds: ConnectionBounds,
    payload: &[u8],
    close_stream: bool,
) -> (sensor_wire::SensorEvent, Vec<u8>) {
    let srv = TestServer::start_with(bounds).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "shell:").await;
    // The server sends its prompt as a WRTE once the interactive stream is open.
    let (prompt, _) = read_message(&mut conn).await;
    assert_eq!(prompt.command, adb_proto::A_WRTE);
    acknowledge_wrte(&mut conn, &prompt).await;

    conn.write_all(&adb_proto::build_wrte(1, server_id, payload))
        .await
        .unwrap();
    let (ack, _) = read_message(&mut conn).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);

    if close_stream {
        conn.write_all(&adb_proto::build_clse(1, server_id))
            .await
            .unwrap();
    }

    wait_for_upload_event(&srv.log_path).await;
    let spooled = spooled_files(&srv.spool_dir);
    assert_eq!(
        spooled.len(),
        1,
        "exactly one capture must reach the spool however the session ended"
    );
    let stored = std::fs::read(&spooled[0]).unwrap();

    let events = srv.events().await;
    let upload = events
        .into_iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("the binary shell capture must be recorded");
    drop(conn);
    srv.handle.abort();
    (upload, stored)
}

/// The gap this capture closes: a dropper that streams its payload over `adb shell` used to leave
/// a flood event and no sample at all, while the same payload over telnet or SSH was kept. Nothing
/// here tells the sensor the bytes are binary - the payload never completes a line, so the shell's
/// per-line flood detector never fires and the raw bytes are the only evidence there is.
#[tokio::test]
async fn a_binary_payload_streamed_at_the_adb_shell_is_captured_as_malware_upload() {
    let bounds = ConnectionBounds {
        idle_timeout: Duration::from_millis(600),
        ..test_bounds()
    };
    // Every byte high-bit set, so none is CR or LF: no line ever reaches the shell.
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let (upload, stored) = shell_payload_session(bounds, &payload, false).await;

    assert_eq!(stored, payload, "the stored bytes are what the client sent");
    assert_eq!(
        upload.metadata["capture_reason"], "binary_shell_payload",
        "{:?}",
        upload.metadata
    );
    assert_eq!(
        upload.metadata["end_reason"], "idle_timeout",
        "{:?}",
        upload.metadata
    );
    assert_eq!(
        upload.metadata["complete"], false,
        "an idle timeout cut the transfer short: {:?}",
        upload.metadata
    );
    assert_eq!(upload.metadata["size"], payload.len() as u64);
    assert_eq!(upload.metadata["wire_size"], payload.len() as u64);
    assert_eq!(upload.metadata["truncated"], false);
    assert_eq!(
        upload.sample.as_ref().unwrap().size,
        payload.len() as u64,
        "the sample the console reads points at the stored bytes"
    );
}

/// The listener enforces `max_duration` by dropping the whole handler future, so nothing written
/// after the message loop runs - and a dropper streaming a payload is exactly the long session
/// that hits it. Only the capture's destructor still runs, which is why it submits from there.
#[tokio::test]
async fn a_binary_payload_is_still_captured_when_the_listener_cancels_the_session() {
    let bounds = ConnectionBounds {
        // Shorter than idle_timeout, so cancellation is what ends this session.
        max_duration: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(20),
        ..test_bounds()
    };
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let (upload, stored) = shell_payload_session(bounds, &payload, false).await;

    assert_eq!(stored, payload);
    assert_eq!(
        upload.metadata["end_reason"], "session_cancelled",
        "{:?}",
        upload.metadata
    );
    assert_eq!(
        upload.metadata["complete"], false,
        "a capture handed over by a cancelled handler is a fragment: {:?}",
        upload.metadata
    );
}

/// The other side of the distinction, and the case that stops the rule from being "label
/// everything incomplete": the client closed the stream itself, so what it streamed is what it
/// meant to send.
#[tokio::test]
async fn a_binary_payload_whose_stream_the_client_closes_is_recorded_as_complete() {
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80u8 | (i & 0x3f)).collect();
    let (upload, stored) = shell_payload_session(test_bounds(), &payload, true).await;

    assert_eq!(stored, payload);
    assert_eq!(
        upload.metadata["end_reason"], "peer_closed",
        "{:?}",
        upload.metadata
    );
    assert_eq!(
        upload.metadata["complete"], true,
        "the client closed the stream itself: {:?}",
        upload.metadata
    );
}

/// How a `sync:` push under test ends.
#[derive(Clone, Copy)]
enum PushEnding {
    /// SEND, DATA, DONE: the push finishes.
    Done,
    /// SEND and DATA, then the client's CLSE on the sync stream with no DONE.
    CloseStream,
    /// SEND and DATA, then silence until the session ends on its own.
    GoQuiet,
}

/// Push one body over a `sync:` stream ended by `ending` and return the upload event. Every
/// caller pushes the same body, so a difference in the recorded end can only come from the ending.
async fn sync_push_session(
    bounds: ConnectionBounds,
    ending: PushEnding,
) -> sensor_wire::SensorEvent {
    let srv = TestServer::start_with(bounds).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "sync:").await;
    let body = b"\x7fELF-adb-push-7731";
    if matches!(ending, PushEnding::Done) {
        sync_push(&mut conn, 1, server_id, "/data/local/tmp/bot", body).await;
    } else {
        for message in [
            adb_proto::build_sync_message(adb_proto::SYNC_SEND, b"/data/local/tmp/bot,33188"),
            adb_proto::build_sync_message(adb_proto::SYNC_DATA, body),
        ] {
            conn.write_all(&adb_proto::build_wrte(1, server_id, &message))
                .await
                .unwrap();
            let (ack, _) = read_message(&mut conn).await;
            assert_eq!(ack.command, adb_proto::A_OKAY);
        }
        if matches!(ending, PushEnding::CloseStream) {
            conn.write_all(&adb_proto::build_clse(1, server_id))
                .await
                .unwrap();
        }
    }
    wait_for_upload_event(&srv.log_path).await;
    let upload = srv
        .events()
        .await
        .into_iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
        .expect("the push must be recorded however it ended");
    drop(conn);
    srv.handle.abort();
    assert_eq!(upload.metadata["wire_size"], body.len() as u64);
    upload
}

#[tokio::test]
async fn a_finished_push_is_recorded_as_a_complete_transfer() {
    let upload = sync_push_session(test_bounds(), PushEnding::Done).await;
    assert_eq!(upload.metadata["end_reason"], "transfer_complete");
    assert_eq!(upload.metadata["complete"], true);
}

/// The client closing the stream is what makes a shell capture whole; a push it closes before
/// DONE is still a fragment, and the reason says the peer closed it.
#[tokio::test]
async fn a_push_whose_stream_the_client_closes_before_done_is_a_peer_closed_fragment() {
    let upload = sync_push_session(test_bounds(), PushEnding::CloseStream).await;
    assert_eq!(upload.metadata["end_reason"], "peer_closed");
    assert_eq!(upload.metadata["complete"], false);
}

#[tokio::test]
async fn a_push_abandoned_mid_transfer_is_recorded_as_cut_short_by_the_idle_timeout() {
    let bounds = ConnectionBounds {
        idle_timeout: Duration::from_millis(600),
        ..test_bounds()
    };
    let upload = sync_push_session(bounds, PushEnding::GoQuiet).await;
    assert_eq!(upload.metadata["end_reason"], "idle_timeout");
    assert_eq!(upload.metadata["complete"], false);
}

#[tokio::test]
async fn a_push_cut_off_by_max_duration_is_recorded_as_session_cancelled() {
    let bounds = ConnectionBounds {
        max_duration: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(20),
        ..test_bounds()
    };
    let upload = sync_push_session(bounds, PushEnding::GoQuiet).await;
    assert_eq!(upload.metadata["end_reason"], "session_cancelled");
    assert_eq!(upload.metadata["complete"], false);
}

/// An ordinary interactive session must never be spooled: the capture triggers on the bytes
/// looking binary, and normal typed commands do not.
#[tokio::test]
async fn a_plaintext_adb_shell_session_is_never_captured() {
    let srv = TestServer::start_with(ConnectionBounds {
        idle_timeout: Duration::from_millis(600),
        ..test_bounds()
    })
    .await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "shell:").await;
    let (prompt, _) = read_message(&mut conn).await;
    assert_eq!(prompt.command, adb_proto::A_WRTE);
    acknowledge_wrte(&mut conn, &prompt).await;

    send_shell_line(&mut conn, 1, server_id, "uname -a").await;
    send_shell_line(&mut conn, 1, server_id, "cat /proc/mounts").await;

    assert!(
        !wait_for_spooled_file(&srv.spool_dir).await,
        "plain typed commands are not a payload and must not be spooled"
    );
    let events = srv.events().await;
    assert!(
        !events
            .iter()
            .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD),
        "a plaintext session must produce no malware upload event"
    );

    drop(conn);
    srv.handle.abort();
}

#[tokio::test]
async fn pull_refused() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "sync:").await;

    stream_recv_and_expect_fail(&mut conn, 1, server_id, "/data/local/tmp/secret_keys.db").await;

    // No malware_download-shaped event exists in the wire contract for adb; what must hold is
    // simply that no file content is ever served back and the sensor stays up.
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
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;
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
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;

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
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;

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

    // Wait for the upload event before reading the log: on an empty log the CR assertion below
    // passes without ever seeing the sanitized line it exists to check.
    wait_for_upload_event(&srv.log_path).await;
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
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;
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
async fn shell_streams_of_one_connection_share_one_command_ceiling() {
    // The source's own command-event budget is set past the connection's ceiling, so only the
    // ceiling decides here.
    let srv = TestServer::start_with_command_budget(1_000, 1_000).await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;

    let mut streams = Vec::new();
    for local_id in 1..=4u32 {
        let server_id = open_stream(&mut conn, local_id, "shell:").await;
        let (prompt, _) = read_message(&mut conn).await;
        acknowledge_wrte(&mut conn, &prompt).await;
        streams.push((local_id, server_id));
    }
    // Four streams of 64 lines are the connection's 256 command events.
    for &(local_id, server_id) in &streams {
        for _ in 0..64 {
            send_shell_line(&mut conn, local_id, server_id, "true").await;
        }
    }
    // Past it, no stream gets an event of its own, and the connection gets one marker in total.
    for &(local_id, server_id) in &streams {
        for _ in 0..3 {
            send_shell_line(&mut conn, local_id, server_id, "true").await;
        }
    }

    let events = srv.events().await;
    fn flood(e: &sensor_wire::SensorEvent) -> Option<&str> {
        e.metadata.get("flood").and_then(|v| v.as_str())
    }
    let commands = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .filter(|e| flood(e).is_none())
        .count();
    let markers = events
        .iter()
        .filter(|e| flood(e) == Some("command_cap"))
        .count();
    assert_eq!(commands, 256, "the streams share one ceiling");
    assert_eq!(markers, 1, "and one marker");
    srv.handle.abort();
}

/// Connect, handshake and open one interactive shell, consuming its prompt.
async fn connect_shell(srv: &TestServer, local_id: u32) -> (TcpStream, u32) {
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, local_id, "shell:").await;
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;
    (conn, server_id)
}

#[tokio::test]
async fn shell_streams_of_one_connection_share_a_written_file() {
    let srv = TestServer::start().await;
    let (mut conn, first_id) = connect_shell(&srv, 1).await;
    let second_id = open_stream(&mut conn, 2, "shell:").await;
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;

    send_shell_line(
        &mut conn,
        1,
        first_id,
        "echo adb-marker-6149 > /data/local/tmp/shared_x",
    )
    .await;
    let seen = send_shell_line(&mut conn, 2, second_id, "cat /data/local/tmp/shared_x").await;
    assert!(
        seen.contains("adb-marker-6149"),
        "second stream saw: {seen:?}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn a_new_adb_connection_does_not_see_files_written_by_an_earlier_one() {
    let srv = TestServer::start().await;
    let (mut first, first_id) = connect_shell(&srv, 1).await;
    send_shell_line(
        &mut first,
        1,
        first_id,
        "echo adb-leak-2706 > /data/local/tmp/leak_x",
    )
    .await;
    let own = send_shell_line(&mut first, 1, first_id, "cat /data/local/tmp/leak_x").await;
    assert!(own.contains("adb-leak-2706"), "own connection saw: {own:?}");

    let (mut second, second_id) = connect_shell(&srv, 1).await;
    let seen = send_shell_line(&mut second, 1, second_id, "cat /data/local/tmp/leak_x").await;
    assert!(
        !seen.contains("adb-leak-2706"),
        "a new connection saw the previous connection's file: {seen:?}"
    );
    srv.handle.abort();
}

/// Past the source's command-event budget a repeated command keeps its exact reply but no longer
/// gets an event of its own; the connection event stays.
#[tokio::test]
async fn a_repeated_command_past_the_source_budget_is_answered_but_not_logged_each_time() {
    let srv = TestServer::start_with_command_budget(1, 3).await;
    let started = std::time::Instant::now();
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 10, "shell:").await;
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;
    let first = send_shell_line(&mut conn, 10, server_id, "getprop ro.product.model").await;
    for _ in 0..19 {
        let again = send_shell_line(&mut conn, 10, server_id, "getprop ro.product.model").await;
        assert_eq!(again, first, "the reply never changes");
    }
    let refill = started.elapsed().as_secs() as usize + 1;
    let events = srv.events().await;
    let commands = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .count();
    assert!(
        (3..=3 + refill).contains(&commands),
        "{commands} command events for 20 commands"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION)
            .count(),
        1
    );
    srv.handle.abort();
}

#[tokio::test]
async fn a_connection_that_has_spent_its_egress_allowance_is_dropped_after_that_reply() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 10, "shell:").await;
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;

    // Each `cat /dev/zero` answers with one MiB and a prompt; the connection may write 16 MiB.
    // The 16th reply is the one that reaches the cap, and it arrives whole.
    for reply in 1..=16 {
        let out = send_shell_line(&mut conn, 10, server_id, "cat /dev/zero").await;
        assert!(out.len() >= 1 << 20, "reply {reply} was cut short");
    }
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut byte))
        .await
        .expect("the connection was not dropped after the allowance was spent");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "nothing follows the reply that spent the allowance: {read:?}"
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

/// Every `honeypot_malware_upload` event once `count` of them are in the log.
async fn uploads(srv: &TestServer, count: usize) -> Vec<sensor_wire::SensorEvent> {
    for _ in 0..200 {
        let found: Vec<sensor_wire::SensorEvent> = srv
            .events()
            .await
            .into_iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .collect();
        if found.len() >= count {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fewer than {count} uploads were recorded");
}

/// The interactive `adb shell` runs the same terminal as SSH and telnet: `cat > f` takes the
/// lines typed after it until Ctrl-D, the file holds them, and they are captured once as
/// `shell_stdin`.
#[tokio::test]
async fn cat_at_the_adb_shell_takes_typed_lines_until_ctrl_d_and_captures_them() {
    let srv = TestServer::start().await;
    let (mut conn, server_id) = connect_shell(&srv, 1).await;
    conn.write_all(&adb_proto::build_wrte(
        1,
        server_id,
        b"cat > /data/local/tmp/typed\nhello\nworld\n\x04",
    ))
    .await
    .unwrap();
    let (ack, _) = read_message(&mut conn).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let mut output = Vec::new();
    while !output.ends_with(b"# ") {
        let (wrte, data) = read_message(&mut conn).await;
        output.extend_from_slice(&data);
        acknowledge_wrte(&mut conn, &wrte).await;
    }
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("hello\r\nworld\r\n"), "{output:?}");
    let seen = send_shell_line(&mut conn, 1, server_id, "cat /data/local/tmp/typed").await;
    assert!(seen.contains("hello\r\nworld\r\n"), "{seen:?}");

    conn.write_all(&adb_proto::build_clse(1, server_id))
        .await
        .unwrap();
    drop(conn);
    let events = uploads(&srv, 1).await;
    let metadata = &events[0].metadata;
    assert_eq!(metadata["capture_reason"], "shell_stdin");
    assert_eq!(metadata["end_reason"], "transfer_complete");
    assert_eq!(metadata["destination"], "/data/local/tmp/typed");
    assert_eq!(metadata["size"], 12);
    assert!(!events[0].authenticated);
    srv.handle.abort();
}

/// A `shell:<command>` that reads its input stays open and takes the stream's data, as a device
/// does. Legacy ADB has no end-of-input message, so the client's CLSE is what ends it: the file
/// holds what arrived, and the capture says the close cut it.
#[tokio::test]
async fn an_adb_shell_command_that_reads_its_input_holds_the_stream_until_the_client_closes_it() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let server_id = open_stream(&mut conn, 1, "shell:cat > /data/local/tmp/piped").await;
    conn.write_all(&adb_proto::build_wrte(1, server_id, b"\x7fELF-adb-stdin"))
        .await
        .unwrap();
    let (ack, _) = read_message(&mut conn).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let mut header = [0u8; adb_proto::HEADER_LEN];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), conn.read_exact(&mut header))
            .await
            .is_err(),
        "nothing is sent while the command waits for its input"
    );
    conn.write_all(&adb_proto::build_clse(1, server_id))
        .await
        .unwrap();
    let (clse, _) = read_message(&mut conn).await;
    assert_eq!(clse.command, adb_proto::A_CLSE);

    let shell_id = open_stream(&mut conn, 2, "shell:").await;
    let (prompt, _) = read_message(&mut conn).await;
    acknowledge_wrte(&mut conn, &prompt).await;
    let seen = send_shell_line(&mut conn, 2, shell_id, "cat /data/local/tmp/piped").await;
    assert!(seen.contains("ELF-adb-stdin"), "{seen:?}");
    drop(conn);
    let events = uploads(&srv, 1).await;
    let metadata = &events[0].metadata;
    assert_eq!(metadata["capture_reason"], "exec_stdin");
    assert_eq!(metadata["end_reason"], "peer_closed");
    assert_eq!(metadata["complete"], false);
    assert_eq!(metadata["destination"], "/data/local/tmp/piped");
    srv.handle.abort();
}

/// A binary payload a typed `cat > f` consumed is captured once, as that command's input: the
/// shell capture, which keeps what was typed at the shell itself, never sees it.
#[tokio::test]
async fn bytes_a_typed_adb_command_consumed_are_not_also_captured_as_a_shell_payload() {
    let srv = TestServer::start().await;
    let (mut conn, server_id) = connect_shell(&srv, 1).await;
    // High-bit bytes and no line ending until the Ctrl-D: a binary flood if the shell saw them.
    let payload: Vec<u8> = (0u8..200).map(|i| 0x80 | (i & 0x3f)).collect();
    let mut typed = b"cat > /data/local/tmp/bin\n".to_vec();
    typed.extend_from_slice(&payload);
    typed.extend_from_slice(b"\x04\x04");
    conn.write_all(&adb_proto::build_wrte(1, server_id, &typed))
        .await
        .unwrap();
    let (ack, _) = read_message(&mut conn).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let mut output = Vec::new();
    while !output.ends_with(b"# ") {
        let (wrte, data) = read_message(&mut conn).await;
        output.extend_from_slice(&data);
        acknowledge_wrte(&mut conn, &wrte).await;
    }
    conn.write_all(&adb_proto::build_clse(1, server_id))
        .await
        .unwrap();
    drop(conn);
    uploads(&srv, 1).await;
    // Both captures are submitted as the session ends; give a second one time to appear.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let events = uploads(&srv, 1).await;
    assert_eq!(events.len(), 1, "one capture of the bytes: {events:?}");
    assert_eq!(events[0].metadata["capture_reason"], "shell_stdin");
    assert_eq!(events[0].metadata["size"], payload.len());
    srv.handle.abort();
}

/// The captures stored in `dir`: files named by the SHA-256 of their content. The spool also holds a
/// `.staging/` directory, where a body is written before it is published under that name.
fn spooled_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| {
                    sensor_framework::spool::is_canonical_sha256_hex(
                        &e.file_name().to_string_lossy(),
                    )
                })
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default()
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

// ---- pushed files land in the connection's fake filesystem ----

/// `sync_push` with the body split across several DATA chunks, for a body over one chunk's limit.
async fn sync_push_chunked(
    stream: &mut TcpStream,
    local_id: u32,
    server_id: u32,
    path: &str,
    body: &[u8],
) {
    let send_payload = format!("{path},33188");
    let mut messages = vec![adb_proto::build_sync_message(
        adb_proto::SYNC_SEND,
        send_payload.as_bytes(),
    )];
    for chunk in body.chunks(100_000) {
        messages.push(adb_proto::build_sync_message(adb_proto::SYNC_DATA, chunk));
    }
    messages.push(adb_proto::build_sync_done(1_700_000_000));
    for message in &messages {
        stream
            .write_all(&adb_proto::build_wrte(local_id, server_id, message))
            .await
            .unwrap();
        let (h, _) = read_message(stream).await;
        assert_eq!(h.command, adb_proto::A_OKAY);
    }
    let (reply, data) = read_message(stream).await;
    assert_eq!(reply.command, adb_proto::A_WRTE);
    assert_eq!(SyncHeader::parse(&data).unwrap().id, adb_proto::SYNC_OKAY);
    stream
        .write_all(&adb_proto::build_okay(local_id, server_id))
        .await
        .unwrap();
}

/// Open an interactive shell stream on an existing connection and swallow its prompt.
async fn open_shell_stream(conn: &mut TcpStream, local_id: u32) -> u32 {
    let server_id = open_stream(conn, local_id, "shell:").await;
    let (prompt, _) = read_message(conn).await;
    acknowledge_wrte(conn, &prompt).await;
    server_id
}

#[tokio::test]
async fn a_pushed_file_is_read_by_a_shell_of_the_same_connection_and_still_captured() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let sync_id = open_stream(&mut conn, 1, "sync:").await;

    let body = b"#!/system/bin/sh\necho adb-dropper-marker-9047\n";
    sync_push(&mut conn, 1, sync_id, "/data/local/tmp/pushed_x", body).await;

    let shell_id = open_shell_stream(&mut conn, 2).await;
    let seen = send_shell_line(&mut conn, 2, shell_id, "cat /data/local/tmp/pushed_x").await;
    assert!(
        seen.contains("adb-dropper-marker-9047"),
        "shell saw: {seen:?}"
    );
    let listing = send_shell_line(&mut conn, 2, shell_id, "ls /data/local/tmp").await;
    assert!(listing.contains("pushed_x"), "ls saw: {listing:?}");

    wait_for_upload_event(&srv.log_path).await;
    let spooled = spooled_files(&srv.spool_dir);
    assert_eq!(spooled.len(), 1, "the capture path is unchanged");
    assert_eq!(std::fs::read(&spooled[0]).unwrap(), body);
    srv.handle.abort();
}

#[tokio::test]
async fn a_new_adb_connection_does_not_see_a_file_pushed_on_an_earlier_one() {
    let srv = TestServer::start().await;
    let mut first = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut first).await;
    let sync_id = open_stream(&mut first, 1, "sync:").await;
    sync_push(
        &mut first,
        1,
        sync_id,
        "/data/local/tmp/pushed_leak",
        b"adb-push-leak-3318",
    )
    .await;

    let (mut second, second_id) = connect_shell(&srv, 1).await;
    let seen = send_shell_line(&mut second, 1, second_id, "cat /data/local/tmp/pushed_leak").await;
    assert!(
        !seen.contains("adb-push-leak-3318"),
        "a new connection saw the earlier connection's push: {seen:?}"
    );
    srv.handle.abort();
}

#[tokio::test]
async fn a_push_larger_than_the_connection_budget_is_bounded_but_still_captured() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let sync_id = open_stream(&mut conn, 1, "sync:").await;

    // Over the connection's 196608-byte owned-bytes ceiling, under the 10 MB capture cap.
    let body: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    sync_push_chunked(&mut conn, 1, sync_id, "/data/local/tmp/huge_push", &body).await;

    let shell_id = open_shell_stream(&mut conn, 2).await;
    let seen = send_shell_line(&mut conn, 2, shell_id, "cat /data/local/tmp/huge_push").await;
    assert!(
        seen.len() < body.len(),
        "the over-budget push must not be stored whole ({} bytes read back)",
        seen.len()
    );

    wait_for_upload_event(&srv.log_path).await;
    let spooled = spooled_files(&srv.spool_dir);
    assert_eq!(spooled.len(), 1);
    assert_eq!(std::fs::read(&spooled[0]).unwrap(), body);
    srv.handle.abort();
}

/// One sync `STAT` round trip. The reply layout is parsed by hand (id, then mode, size, time with
/// no length field) so a framing error in the server's builder is not mirrored here.
async fn sync_stat(
    stream: &mut TcpStream,
    local_id: u32,
    server_id: u32,
    path: &str,
) -> (u32, u32, u32) {
    let request = adb_proto::build_sync_message(adb_proto::SYNC_STAT, path.as_bytes());
    stream
        .write_all(&adb_proto::build_wrte(local_id, server_id, &request))
        .await
        .unwrap();
    let (ack, _) = read_message(stream).await;
    assert_eq!(ack.command, adb_proto::A_OKAY);
    let (wrte, data) = read_message(stream).await;
    assert_eq!(wrte.command, adb_proto::A_WRTE);
    assert_eq!(data.len(), 16, "STAT is id + mode + size + time");
    assert_eq!(&data[..4], b"STAT");
    let word = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    let reply = (word(4), word(8), word(12));
    stream
        .write_all(&adb_proto::build_okay(local_id, server_id))
        .await
        .unwrap();
    reply
}

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;

/// What `adb push <local> <dest>` does: STAT the destination and, when it is a directory, append
/// the local file's basename before the SEND.
async fn adb_push(
    stream: &mut TcpStream,
    local_id: u32,
    server_id: u32,
    dest: &str,
    local_name: &str,
    body: &[u8],
) -> String {
    let (mode, _, _) = sync_stat(stream, local_id, server_id, dest).await;
    let target = if mode & S_IFMT == S_IFDIR {
        format!("{}/{local_name}", dest.trim_end_matches('/'))
    } else {
        dest.to_string()
    };
    sync_push(stream, local_id, server_id, &target, body).await;
    target
}

#[tokio::test]
async fn an_adb_push_to_a_directory_without_a_trailing_slash_lands_inside_it() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let sync_id = open_stream(&mut conn, 1, "sync:").await;

    let (dir_mode, _, _) = sync_stat(&mut conn, 1, sync_id, "/data/local/tmp").await;
    assert_eq!(
        dir_mode & S_IFMT,
        S_IFDIR,
        "STAT of a directory is not not-found"
    );

    let body = b"#!/system/bin/sh\necho adb-dir-push-7711\n";
    let target = adb_push(&mut conn, 1, sync_id, "/data/local/tmp", "dropper", body).await;
    assert_eq!(target, "/data/local/tmp/dropper");

    let shell_id = open_shell_stream(&mut conn, 2).await;
    let seen = send_shell_line(&mut conn, 2, shell_id, "cat /data/local/tmp/dropper").await;
    assert!(seen.contains("adb-dir-push-7711"), "shell saw: {seen:?}");

    // The same connection: a push to a brand-new file path still STATs as absent and lands there.
    let (absent, size, mtime) = sync_stat(&mut conn, 1, sync_id, "/data/local/tmp/fresh.bin").await;
    assert_eq!((absent, size, mtime), (0, 0, 0));
    let target = adb_push(
        &mut conn,
        1,
        sync_id,
        "/data/local/tmp/fresh.bin",
        "ignored",
        b"adb-fresh-push-2290",
    )
    .await;
    assert_eq!(target, "/data/local/tmp/fresh.bin");
    let seen = send_shell_line(&mut conn, 2, shell_id, "cat /data/local/tmp/fresh.bin").await;
    assert!(seen.contains("adb-fresh-push-2290"), "shell saw: {seen:?}");

    // STAT of an existing file now reports it.
    let (file_mode, file_size, _) =
        sync_stat(&mut conn, 1, sync_id, "/data/local/tmp/dropper").await;
    assert_eq!(file_mode & S_IFMT, 0o100_000, "a regular file");
    assert_eq!(file_size as usize, body.len());
    srv.handle.abort();
}

/// An upload and a shell write on one connection spend ONE owned-bytes allowance. The push leaves
/// less than the shell's next write needs; that write is refused only if the push was charged to
/// the budget the shell charges. Without the connection's budget on the base filesystem the push
/// goes to a private budget and the write succeeds.
#[tokio::test]
async fn an_adb_push_and_a_later_shell_write_share_one_owned_bytes_budget() {
    let srv = TestServer::start().await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();
    cnxn_handshake(&mut conn).await;
    let sync_id = open_stream(&mut conn, 1, "sync:").await;

    // 190000 of the 196608-byte ceiling, as an in-budget push.
    let body: Vec<u8> = (0..190_000u32).map(|i| (i % 251) as u8).collect();
    sync_push_chunked(&mut conn, 1, sync_id, "/data/local/tmp/big_push", &body).await;

    let shell_id = open_shell_stream(&mut conn, 2).await;
    let stored = send_shell_line(&mut conn, 2, shell_id, "ls /data/local/tmp").await;
    assert!(
        stored.contains("big_push"),
        "the push itself fits: {stored:?}"
    );

    let fill = "A".repeat(7_500);
    let line = format!("echo {fill} > /data/local/tmp/shell_fill");
    let out = send_shell_line(&mut conn, 2, shell_id, &line).await;
    assert!(
        out.contains("No space left on device"),
        "the shell write must hit the budget the push already spent, got {} bytes of output",
        out.len()
    );
    srv.handle.abort();
}
