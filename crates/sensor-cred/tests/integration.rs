use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
    handle: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl TestServer {
    async fn start(protocol: &'static str) -> TestServer {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let wan_resolver = Arc::new(WanResolver::new(HashMap::new()));
        let (addr, handle) = sensor_cred::start_listener(
            "127.0.0.1:0".parse().unwrap(),
            log_path.clone(),
            wan_resolver,
            test_bounds(),
            protocol,
        )
        .await
        .unwrap();
        TestServer {
            addr,
            log_path,
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
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad event: {e}: {l}")))
            .collect()
    }
}

// ---- VNC ----

#[tokio::test]
async fn vnc_auth_attempt_emits_login_event() {
    let srv = TestServer::start("vnc").await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();

    // Read server version
    let mut version = [0u8; 12];
    conn.read_exact(&mut version).await.unwrap();
    assert_eq!(&version, b"RFB 003.008\n");

    // Send client version
    conn.write_all(b"RFB 003.008\n").await.unwrap();

    // Read security types
    let mut sec = [0u8; 2];
    conn.read_exact(&mut sec).await.unwrap();
    assert_eq!(sec[0], 1); // 1 type offered
    assert_eq!(sec[1], 2); // VNC Auth

    // Select VNC Auth
    conn.write_all(&[2]).await.unwrap();

    // Read challenge
    let mut challenge = [0u8; 16];
    conn.read_exact(&mut challenge).await.unwrap();

    // Send response (fake - honeypot accepts anything)
    conn.write_all(&[0xAA; 16]).await.unwrap();

    // Read SecurityResult
    let mut result = [0u8; 4];
    conn.read_exact(&mut result).await.unwrap();
    assert_eq!(result, [0, 0, 0, 0]); // OK

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert!(login.authenticated);
    assert_eq!(
        login
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("vnc")
    );
    srv.handle.abort();
}

// ---- MySQL ----

#[tokio::test]
async fn mysql_handshake_captures_username() {
    let srv = TestServer::start("mysql").await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();

    // Read greeting
    let mut header = [0u8; 4];
    conn.read_exact(&mut header).await.unwrap();
    let pkt_len = (header[0] as usize) | ((header[1] as usize) << 8) | ((header[2] as usize) << 16);
    let mut greeting = vec![0u8; pkt_len];
    conn.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting[0], 0x0a); // protocol version 10

    // Build HandshakeResponse41
    let mut response = Vec::new();
    // capability flags (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION)
    response.extend_from_slice(&0x0000_f7ffu32.to_le_bytes());
    // max packet size
    response.extend_from_slice(&16777216u32.to_le_bytes());
    // charset
    response.push(0x21);
    // reserved
    response.extend_from_slice(&[0u8; 23]);
    // username
    response.extend_from_slice(b"testuser\0");
    // auth response length + data
    response.push(20); // length
    response.extend_from_slice(&[0xBB; 20]); // fake auth response

    // Wrap as MySQL packet (seq=1)
    let len = response.len() as u32;
    let mut packet = Vec::new();
    packet.extend_from_slice(&len.to_le_bytes()[..3]);
    packet.push(1); // seq
    packet.extend_from_slice(&response);

    conn.write_all(&packet).await.unwrap();

    // Read OK
    let mut ok_header = [0u8; 4];
    conn.read_exact(&mut ok_header).await.unwrap();
    let ok_len =
        (ok_header[0] as usize) | ((ok_header[1] as usize) << 8) | ((ok_header[2] as usize) << 16);
    let mut ok_body = vec![0u8; ok_len];
    conn.read_exact(&mut ok_body).await.unwrap();
    assert_eq!(ok_body[0], 0x00); // OK packet

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login.metadata.get("username").and_then(|v| v.as_str()),
        Some("testuser")
    );
    assert_eq!(
        login
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("mysql")
    );
    assert!(login.metadata.get("password").is_none());
    srv.handle.abort();
}

// ---- MSSQL ----

#[tokio::test]
async fn mssql_login7_captures_username() {
    let srv = TestServer::start("mssql").await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();

    // Send PreLogin packet
    let mut prelogin_payload = Vec::new();
    prelogin_payload.push(0x00); // VERSION token
    prelogin_payload.extend_from_slice(&6u16.to_be_bytes()); // offset
    prelogin_payload.extend_from_slice(&6u16.to_be_bytes()); // length
    prelogin_payload.push(0xFF); // terminator
    prelogin_payload.extend_from_slice(&[15, 0, 0, 1, 0, 0]); // version

    let prelogin = wrap_tds(0x12, &prelogin_payload);
    conn.write_all(&prelogin).await.unwrap();

    // Read PreLogin response
    let mut resp_header = [0u8; 8];
    conn.read_exact(&mut resp_header).await.unwrap();
    let resp_len = u16::from_be_bytes([resp_header[2], resp_header[3]]) as usize;
    if resp_len > 8 {
        let mut resp_body = vec![0u8; resp_len - 8];
        conn.read_exact(&mut resp_body).await.unwrap();
    }

    // Build Login7 packet with username "sa" at offset 94
    let mut login7 = vec![0u8; 200];
    login7[0..4].copy_from_slice(&200u32.to_le_bytes()); // total length
    // TDS version at offset 4
    login7[4..8].copy_from_slice(&0x74000004u32.to_le_bytes());
    // Username offset at 48-49: offset 94 within login7 body
    login7[48..50].copy_from_slice(&94u16.to_le_bytes());
    // Username length at 50-51: 2 chars
    login7[50..52].copy_from_slice(&2u16.to_le_bytes());
    // "sa" as UTF-16LE at offset 94
    login7[94] = b's';
    login7[95] = 0;
    login7[96] = b'a';
    login7[97] = 0;

    let login7_pkt = wrap_tds(0x10, &login7);
    conn.write_all(&login7_pkt).await.unwrap();

    // Read LOGINACK response
    let mut ack_header = [0u8; 8];
    conn.read_exact(&mut ack_header).await.unwrap();
    let ack_len = u16::from_be_bytes([ack_header[2], ack_header[3]]) as usize;
    if ack_len > 8 {
        let mut ack_body = vec![0u8; ack_len - 8];
        conn.read_exact(&mut ack_body).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login.metadata.get("username").and_then(|v| v.as_str()),
        Some("sa")
    );
    assert_eq!(
        login
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("mssql")
    );
    srv.handle.abort();
}

fn wrap_tds(pkt_type: u8, payload: &[u8]) -> Vec<u8> {
    let total = 8 + payload.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.push(pkt_type);
    pkt.push(0x01); // EOM
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // SPID
    pkt.push(0x01); // packet ID
    pkt.push(0x00); // window
    pkt.extend_from_slice(payload);
    pkt
}

// ---- PostgreSQL ----

#[tokio::test]
async fn postgresql_captures_username() {
    let srv = TestServer::start("postgresql").await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();

    // Build StartupMessage: length(4) + protocol(4) + params + NUL terminator
    let mut params = Vec::new();
    params.extend_from_slice(&196608i32.to_be_bytes()); // protocol 3.0
    params.extend_from_slice(b"user\0pgadmin\0database\0testdb\0\0");

    let msg_len = (4 + params.len()) as i32;
    let mut startup = Vec::new();
    startup.extend_from_slice(&msg_len.to_be_bytes());
    startup.extend_from_slice(&params);
    conn.write_all(&startup).await.unwrap();

    // Read AuthenticationMD5Password
    let mut auth_type = [0u8; 1];
    conn.read_exact(&mut auth_type).await.unwrap();
    assert_eq!(auth_type[0], b'R');
    let mut auth_len = [0u8; 4];
    conn.read_exact(&mut auth_len).await.unwrap();
    let body_len = i32::from_be_bytes(auth_len) as usize - 4;
    let mut auth_body = vec![0u8; body_len];
    conn.read_exact(&mut auth_body).await.unwrap();
    assert_eq!(
        i32::from_be_bytes([auth_body[0], auth_body[1], auth_body[2], auth_body[3]]),
        5
    ); // MD5

    // Send PasswordMessage
    let pw = b"md5fakehashvalue00000000000000000\0";
    let pw_len = (4 + pw.len()) as i32;
    let mut pw_msg = Vec::new();
    pw_msg.push(b'p');
    pw_msg.extend_from_slice(&pw_len.to_be_bytes());
    pw_msg.extend_from_slice(pw);
    conn.write_all(&pw_msg).await.unwrap();

    // Read AuthenticationOk, the ParameterStatus set, BackendKeyData, then ReadyForQuery. The
    // handler used to close right after AuthenticationOk, so a client never got to send its
    // first statement and nothing the attacker meant to run was ever observed.
    async fn read_msg(conn: &mut TcpStream) -> (u8, Vec<u8>) {
        let mut t = [0u8; 1];
        conn.read_exact(&mut t).await.unwrap();
        let mut l = [0u8; 4];
        conn.read_exact(&mut l).await.unwrap();
        let mut body = vec![0u8; i32::from_be_bytes(l) as usize - 4];
        conn.read_exact(&mut body).await.unwrap();
        (t[0], body)
    }
    let (t, body) = read_msg(&mut conn).await;
    assert_eq!(t, b'R');
    assert_eq!(
        i32::from_be_bytes(body[..4].try_into().unwrap()),
        0,
        "AuthenticationOk"
    );
    let mut saw_version = false;
    let mut saw_key_data = false;
    loop {
        let (t, body) = read_msg(&mut conn).await;
        match t {
            b'S' => {
                if body.starts_with(b"server_version\0") {
                    saw_version = true;
                }
            }
            b'K' => saw_key_data = true,
            b'Z' => {
                assert_eq!(body, b"I", "ReadyForQuery must report idle");
                break;
            }
            other => panic!("unexpected message type {other:?} before ReadyForQuery"),
        }
    }
    assert!(
        saw_version && saw_key_data,
        "a client library expects both before it will send"
    );

    // Send a simple query; it must be recorded and answered, and the session must stay open.
    let sql = b"SELECT version()\0";
    let mut q = vec![b'Q'];
    q.extend_from_slice(&((4 + sql.len()) as i32).to_be_bytes());
    q.extend_from_slice(sql);
    conn.write_all(&q).await.unwrap();
    let (t, body) = read_msg(&mut conn).await;
    assert_eq!(t, b'E', "a query is refused, not ignored");
    assert!(
        body.windows(6).any(|w| w == b"C42501"),
        "SQLSTATE in the error: {body:?}"
    );
    let (t, _) = read_msg(&mut conn).await;
    assert_eq!(t, b'Z', "ReadyForQuery again: the session is still open");
    // A second statement proves the loop.
    conn.write_all(&q).await.unwrap();
    assert_eq!(read_msg(&mut conn).await.0, b'E');
    assert_eq!(read_msg(&mut conn).await.0, b'Z');

    // The extended protocol, as a client library sends it: Parse then Flush must yield
    // ParseComplete at once (a Flush with no reply stalled such clients), then Bind, Execute
    // and Sync yield BindComplete, the refusal, and ReadyForQuery. The SQL is recorded from
    // Parse.
    let ext_sql = b"SELECT 42 AS extended_probe\0";
    let mut parse = vec![b'P'];
    let parse_body_len = 4 + 1 + ext_sql.len() + 2; // len, empty name, query, 0 param types
    parse.extend_from_slice(&(parse_body_len as i32).to_be_bytes());
    parse.push(0);
    parse.extend_from_slice(ext_sql);
    parse.extend_from_slice(&0i16.to_be_bytes());
    parse.extend_from_slice(&[b'H', 0, 0, 0, 4]); // Flush
    conn.write_all(&parse).await.unwrap();
    assert_eq!(read_msg(&mut conn).await.0, b'1', "ParseComplete on Flush");
    // Bind (empty portal, empty statement, no formats, no params, no result formats), Execute
    // (empty portal, no row limit), Sync.
    let mut rest = vec![b'B'];
    let bind_body = [0u8, 0, 0, 0, 0, 0, 0, 0];
    rest.extend_from_slice(&((4 + bind_body.len()) as i32).to_be_bytes());
    rest.extend_from_slice(&bind_body);
    rest.push(b'E');
    rest.extend_from_slice(&9i32.to_be_bytes());
    rest.push(0);
    rest.extend_from_slice(&0i32.to_be_bytes());
    rest.extend_from_slice(&[b'S', 0, 0, 0, 4]);
    conn.write_all(&rest).await.unwrap();
    assert_eq!(read_msg(&mut conn).await.0, b'2', "BindComplete");
    assert_eq!(read_msg(&mut conn).await.0, b'E', "Execute is refused");
    assert_eq!(
        read_msg(&mut conn).await.0,
        b'Z',
        "Sync ends the error state"
    );
    conn.write_all(&[b'X', 0, 0, 0, 4]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login.metadata.get("username").and_then(|v| v.as_str()),
        Some("pgadmin")
    );
    let queries: Vec<&sensor_wire::SensorEvent> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC)
        .collect();
    assert_eq!(
        queries.len(),
        3,
        "one command event per statement: {events:?}"
    );
    assert_eq!(
        queries[0].metadata.get("command").and_then(|v| v.as_str()),
        Some("SELECT version()")
    );
    assert_eq!(
        queries[2].metadata.get("command").and_then(|v| v.as_str()),
        Some("SELECT 42 AS extended_probe"),
        "extended-protocol SQL is recorded from Parse"
    );
    assert_eq!(
        login
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("postgresql")
    );
    srv.handle.abort();
}

// ---- MongoDB ----

#[tokio::test]
async fn mongodb_saslstart_captures_username() {
    let srv = TestServer::start("mongodb").await;
    let mut conn = TcpStream::connect(srv.addr).await.unwrap();

    // Send isMaster OP_MSG
    let ismaster_bson = build_test_bson(&[("isMaster", "1"), ("$db", "admin")]);
    let ismaster_msg = build_op_msg(1, &ismaster_bson);
    conn.write_all(&ismaster_msg).await.unwrap();

    let _ = read_mongo_response(&mut conn).await;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"n,,n=mongouser,r=somerandomnonce");
    let sasl_bson = build_test_bson_with_binary("saslStart", "admin", "SCRAM-SHA-1", &payload);
    let sasl_msg = build_op_msg(2, &sasl_bson);
    conn.write_all(&sasl_msg).await.unwrap();

    let _ = read_mongo_response(&mut conn).await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let events = srv.events().await;
    let login = events
        .iter()
        .find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT)
        .unwrap();
    assert_eq!(
        login
            .metadata
            .get("protocol_label")
            .and_then(|v| v.as_str()),
        Some("mongodb")
    );
    assert!(login.authenticated);
    srv.handle.abort();
}

fn build_op_msg(request_id: i32, body_bson: &[u8]) -> Vec<u8> {
    // OP_MSG: flagBits(4) + kind0(1) + body BSON
    let mut op_body = Vec::new();
    op_body.extend_from_slice(&0u32.to_le_bytes()); // flagBits
    op_body.push(0); // section kind 0
    op_body.extend_from_slice(body_bson);

    let msg_len = (16 + op_body.len()) as i32;
    let mut msg = Vec::new();
    msg.extend_from_slice(&msg_len.to_le_bytes());
    msg.extend_from_slice(&request_id.to_le_bytes());
    msg.extend_from_slice(&0i32.to_le_bytes()); // responseTo
    msg.extend_from_slice(&2013u32.to_le_bytes()); // OP_MSG
    msg.extend_from_slice(&op_body);
    msg
}

fn build_test_bson(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(&[0u8; 4]); // length placeholder
    for (key, value) in fields {
        doc.push(0x02); // type: string
        doc.extend_from_slice(key.as_bytes());
        doc.push(0x00);
        let val_len = (value.len() + 1) as i32;
        doc.extend_from_slice(&val_len.to_le_bytes());
        doc.extend_from_slice(value.as_bytes());
        doc.push(0x00);
    }
    doc.push(0x00); // terminator
    let total = doc.len() as i32;
    doc[..4].copy_from_slice(&total.to_le_bytes());
    doc
}

fn build_test_bson_with_binary(cmd: &str, db: &str, mechanism: &str, payload: &[u8]) -> Vec<u8> {
    let mut doc = Vec::new();
    doc.extend_from_slice(&[0u8; 4]);

    // command: int32 = 1
    doc.push(0x10); // int32
    doc.extend_from_slice(cmd.as_bytes());
    doc.push(0x00);
    doc.extend_from_slice(&1i32.to_le_bytes());

    // mechanism: string
    doc.push(0x02);
    doc.extend_from_slice(b"mechanism\0");
    let mech_len = (mechanism.len() + 1) as i32;
    doc.extend_from_slice(&mech_len.to_le_bytes());
    doc.extend_from_slice(mechanism.as_bytes());
    doc.push(0x00);

    // payload: binary
    doc.push(0x05); // binary type
    doc.extend_from_slice(b"payload\0");
    doc.extend_from_slice(&(payload.len() as i32).to_le_bytes());
    doc.push(0x00); // subtype
    doc.extend_from_slice(payload);

    // $db: string
    doc.push(0x02);
    doc.extend_from_slice(b"$db\0");
    let db_len = (db.len() + 1) as i32;
    doc.extend_from_slice(&db_len.to_le_bytes());
    doc.extend_from_slice(db.as_bytes());
    doc.push(0x00);

    doc.push(0x00); // terminator
    let total = doc.len() as i32;
    doc[..4].copy_from_slice(&total.to_le_bytes());
    doc
}

async fn read_mongo_response(conn: &mut TcpStream) -> Vec<u8> {
    let mut header = [0u8; 16];
    tokio::time::timeout(Duration::from_secs(3), conn.read_exact(&mut header))
        .await
        .expect("timeout reading mongo response")
        .expect("read error");
    let msg_len = i32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if msg_len > 16 {
        let mut body = vec![0u8; msg_len - 16];
        conn.read_exact(&mut body).await.expect("read body");
        body
    } else {
        Vec::new()
    }
}

// ---- Cross-protocol ----

#[tokio::test]
async fn connection_event_emitted_on_bare_connect() {
    for proto in &["vnc", "mysql", "mssql", "postgresql", "mongodb"] {
        let srv = TestServer::start(proto).await;
        {
            let _conn = TcpStream::connect(srv.addr).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let events = srv.events().await;
        assert!(
            events
                .iter()
                .any(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION),
            "{proto}: connection event missing"
        );
        srv.handle.abort();
    }
}

#[test]
fn never_exec_static_check() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for entry in walk_rs(&src_dir) {
        let content = std::fs::read_to_string(&entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
        {
            found.push(entry.display().to_string());
        }
    }
    assert!(
        found.is_empty(),
        "sensor-cred must not spawn processes: {found:?}"
    );
}

#[tokio::test]
async fn malformed_input_does_not_crash_listeners() {
    for proto in &["vnc", "mysql", "mssql", "postgresql", "mongodb"] {
        let srv = TestServer::start(proto).await;
        for seed in 0..3u8 {
            if let Ok(mut conn) = TcpStream::connect(srv.addr).await {
                let garbage: Vec<u8> = (0..1024u32)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                    .collect();
                let _ = conn.write_all(&garbage).await;
                drop(conn);
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Verify listener still accepts
        let probe = TcpStream::connect(srv.addr).await;
        assert!(probe.is_ok(), "{proto}: listener died after garbage");
        srv.handle.abort();
    }
}

fn walk_rs(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
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
