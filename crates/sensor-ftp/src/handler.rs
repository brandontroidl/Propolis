use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{
    CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, Uuid, WanResolver, upload_metadata,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "ftp";
const MAX_LINE_LEN: usize = 8192;
const MAX_USERNAME_LEN: usize = 255;
const MAX_STOR_BODY: usize = 10_000_000;
/// How far past `MAX_STOR_BODY` a STOR is drained without being stored, only to measure the real
/// upload size for the event's `wire_size`/`truncated`. Bounded so an attacker trickling bytes
/// cannot hold the data connection open indefinitely once nothing more is being kept.
const MAX_STOR_DRAIN: usize = 10_000_000;

// Impersonate vsFTPd 3.0.5 end to end: the banner, the FEAT block, and every response string below
// are that daemon's real output. A banner that matches no daemon - or a banner and FEAT that do not
// belong to the same daemon - is itself the fingerprint.
const BANNER: &[u8] = b"220 (vsFTPd 3.0.5)\r\n";

/// The one advertised regular file, kept consistent across LIST, SIZE and MDTM (an epoch mtime and a
/// listing size that disagreed with SIZE were tells). vsftpd renders numeric uid/gid by default and,
/// for a file older than six months, the year form of the date.
const CANNED_FILE: &str = "readme.txt";
const CANNED_FILE_SIZE: u64 = 4096;
const CANNED_FILE_MDTM: &str = "20240116102430"; // YYYYMMDDHHMMSS, == the LIST date
const CANNED_LIST: &str = "\
-rw-r--r--    1 0        0            4096 Jan 16  2024 readme.txt\r\n\
drwxr-xr-x    2 0        0            4096 Jan 16  2024 pub\r\n";
/// NLST is bare names only (LIST is the long form above); serving the long listing for NLST was a tell.
const CANNED_NLST: &str = "readme.txt\r\npub\r\n";

/// Whether a passive data connection may be trusted as belonging to this control session.
///
/// A real FTP server (vsftpd's default `pasv_promiscuous=NO`) refuses a passive data connection
/// whose source IP differs from the control connection's. Without this check an off-path attacker
/// can race the ephemeral passive port, connect first, and have their upload captured and attributed
/// to the CONTROL connection's `source_ip` - poisoning threat-intel attribution, which is the whole
/// point of the platform. The data connection's source PORT always differs, so compare the
/// normalized IP only.
fn data_peer_matches(control_ip: IpAddr, data_peer: SocketAddr) -> bool {
    normalize_dual_stack(data_peer).ip() == control_ip
}

/// How a STOR data transfer ended. In stream mode the client closing the data connection is the
/// end of the file; anything else is not, and the control reply has to say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorOutcome {
    /// The client closed the data connection: the whole file arrived.
    Complete,
    /// The data connection went quiet or failed part way: what arrived is a fragment.
    NetworkFailure,
    /// The sensor stopped reading at `MAX_STOR_BODY + MAX_STOR_DRAIN`, the way a server stops
    /// when it cannot write any more of the file.
    DrainCapReached,
}

/// Read a STOR upload from its data connection. Returns the retained body (at most
/// `MAX_STOR_BODY`), the bytes the client sent whether retained or not, and how the transfer
/// ended. Past the cap the read keeps draining (bounded by `MAX_STOR_DRAIN`, so a slow trickle
/// cannot hold the data connection open forever) purely to measure the real size.
async fn receive_stor(
    mut data: TcpStream,
    idle_timeout: std::time::Duration,
) -> (Vec<u8>, u64, StorOutcome) {
    let mut body = Vec::new();
    let mut wire_bytes: u64 = 0;
    let mut chunk = [0u8; 4096];
    let outcome = loop {
        match tokio::time::timeout(idle_timeout, data.read(&mut chunk)).await {
            Ok(Ok(0)) => break StorOutcome::Complete,
            Ok(Err(_)) | Err(_) => break StorOutcome::NetworkFailure,
            Ok(Ok(n)) => {
                let take = MAX_STOR_BODY.saturating_sub(body.len()).min(n);
                body.extend_from_slice(&chunk[..take]);
                wire_bytes += n as u64;
                if wire_bytes >= (MAX_STOR_BODY + MAX_STOR_DRAIN) as u64 {
                    break StorOutcome::DrainCapReached;
                }
            }
        }
    };
    drop(data);
    (body, wire_bytes, outcome)
}

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
) {
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    // The interface the control connection arrived on: the passive data listener binds here (not
    // loopback) so a remote client can reach it. Captured before `stream` is consumed by the reader.
    let control_local_ip = stream
        .local_addr()
        .ok()
        .map(|a| normalize_dual_stack(a).ip());

    let _ = emitter
        .append(&connection_event(source_ip, wan_ip, session_id))
        .await;

    let mut reader = BufReader::new(stream);
    if write_line(&mut reader, BANNER).await.is_err() {
        return;
    }

    let mut username = String::new();
    let mut logged_in = false;
    let mut total_read: u64 = 0;
    let mut pasv_listener: Option<TcpListener> = None;

    loop {
        let Some(line) = read_line_bounded(&mut reader, &bounds, &mut total_read).await else {
            return;
        };
        let (cmd, arg) = split_ftp_command(&line);

        // RFC 959 commands are case-insensitive and real vsftpd uppercases the verb internally, so a
        // lowercase `syst`/`user` must dispatch like its uppercase form rather than falling through
        // to "500 Unknown command" - a one-command tell that a lowercase probe would out. Only the
        // verb is normalized; `arg` (e.g. a filename) keeps its case, matching the TYPE arm below.
        match cmd.to_ascii_uppercase().as_str() {
            "USER" => {
                username = sanitize_value(arg, MAX_USERNAME_LEN);
                let _ = write_line(&mut reader, b"331 Please specify the password.\r\n").await;
            }
            "PASS" => {
                // Password read to advance protocol; immediately dropped.
                logged_in = true;
                let _ = emitter
                    .append(&login_event(source_ip, wan_ip, &username, session_id))
                    .await;
                let _ = write_line(&mut reader, b"230 Login successful.\r\n").await;
            }
            "SYST" => {
                let _ = write_line(&mut reader, b"215 UNIX Type: L8\r\n").await;
            }
            "FEAT" => {
                // vsftpd 3.0.5's FEAT, limited to what this sensor actually backs (SIZE/MDTM/REST
                // are implemented below; EPRT is omitted since active mode is not supported).
                let _ = write_line(
                    &mut reader,
                    b"211-Features:\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n",
                )
                .await;
            }
            "PWD" | "XPWD" => {
                let _ = write_line(&mut reader, b"257 \"/\" is the current directory\r\n").await;
            }
            "CWD" | "XCWD" => {
                let _ = write_line(&mut reader, b"250 Directory successfully changed.\r\n").await;
            }
            "TYPE" => {
                // vsftpd validates the type argument rather than blindly accepting it.
                let reply: &[u8] = match arg.to_ascii_uppercase().as_str() {
                    "I" | "L 8" | "L8" => b"200 Switching to Binary mode.\r\n",
                    "A" | "A N" => b"200 Switching to ASCII mode.\r\n",
                    _ => b"500 Unrecognised TYPE command.\r\n",
                };
                let _ = write_line(&mut reader, reply).await;
            }
            "SIZE" => {
                let reply = if sanitize_value(arg, 255) == CANNED_FILE {
                    format!("213 {CANNED_FILE_SIZE}\r\n")
                } else {
                    "550 Could not get file size.\r\n".to_string()
                };
                let _ = write_line(&mut reader, reply.as_bytes()).await;
            }
            "MDTM" => {
                let reply = if sanitize_value(arg, 255) == CANNED_FILE {
                    format!("213 {CANNED_FILE_MDTM}\r\n")
                } else {
                    "550 Could not get file modification time.\r\n".to_string()
                };
                let _ = write_line(&mut reader, reply.as_bytes()).await;
            }
            "REST" => {
                let _ = write_line(&mut reader, b"350 Restart position accepted (0).\r\n").await;
            }
            "PASV" | "EPSV" => {
                // Bind the data listener on the interface the control connection arrived on (not
                // loopback), so a remote client can actually connect to it, and advertise the
                // address the client should dial: the mapped WAN IP if this node is behind NAT, else
                // the control-local IP. The operator must allow the ephemeral passive data-port
                // range inbound (and forward it, if NATed) for the data channel to complete.
                let bind_ip =
                    control_local_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                match TcpListener::bind((bind_ip, 0)).await {
                    Ok(listener) => {
                        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
                        let resp = if cmd == "PASV" {
                            // 227 must carry an IPv4 host to dial: prefer the WAN IPv4, else the
                            // bound IPv4; if neither is a usable IPv4 (IPv6-only control), refuse
                            // rather than advertise an unreachable address.
                            let advertise_v4 = match wan_ip {
                                Some(IpAddr::V4(v4)) => Some(v4),
                                _ => match bind_ip {
                                    IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
                                    _ => None,
                                },
                            };
                            match advertise_v4 {
                                Some(v4) => {
                                    let o = v4.octets();
                                    format!(
                                        "227 Entering Passive Mode ({},{},{},{},{},{}).\r\n",
                                        o[0],
                                        o[1],
                                        o[2],
                                        o[3],
                                        port >> 8,
                                        port & 0xFF
                                    )
                                }
                                None => {
                                    "522 Use EPSV; PASV requires an IPv4 address.\r\n".to_string()
                                }
                            }
                        } else {
                            format!("229 Entering Extended Passive Mode (|||{port}|)\r\n")
                        };
                        // Only arm the listener when a passive reply actually opened it.
                        if resp.starts_with("227") || resp.starts_with("229") {
                            pasv_listener = Some(listener);
                        }
                        let _ = write_line(&mut reader, resp.as_bytes()).await;
                    }
                    Err(_) => {
                        let _ =
                            write_line(&mut reader, b"425 Cannot open data connection\r\n").await;
                    }
                }
            }
            "LIST" | "NLST" => {
                if let Some(ref listener) = pasv_listener {
                    let _ =
                        write_line(&mut reader, b"150 Here comes the directory listing.\r\n").await;
                    let reply: &[u8] =
                        match tokio::time::timeout(bounds.idle_timeout, listener.accept()).await {
                            Ok(Ok((mut data, data_peer))) => {
                                if data_peer_matches(source_ip, data_peer) {
                                    // LIST is the long ls -l form; NLST is bare names only.
                                    let payload = if cmd == "NLST" {
                                        CANNED_NLST
                                    } else {
                                        CANNED_LIST
                                    };
                                    let _ = data.write_all(payload.as_bytes()).await;
                                    drop(data);
                                    b"226 Directory send OK.\r\n"
                                } else {
                                    drop(data);
                                    b"425 Security: bad IP connecting.\r\n"
                                }
                            }
                            // No data connection arrived: nothing was sent, so "send OK" would
                            // report a transfer that never happened.
                            _ => b"425 Failed to establish connection.\r\n",
                        };
                    let _ = write_line(&mut reader, reply).await;
                } else {
                    let _ = write_line(&mut reader, b"425 Use PORT or PASV first.\r\n").await;
                }
            }
            "STOR" => {
                let filename = sanitize_value(arg, 255);
                if let Some(ref listener) = pasv_listener {
                    let _ = write_line(&mut reader, b"150 Ok to send data.\r\n").await;
                    let (data, data_peer) =
                        match tokio::time::timeout(bounds.idle_timeout, listener.accept()).await {
                            Ok(Ok(accepted)) => accepted,
                            // No data connection: no transfer happened, and "Transfer complete"
                            // used to be the answer anyway.
                            _ => {
                                let _ = write_line(
                                    &mut reader,
                                    b"425 Failed to establish connection.\r\n",
                                )
                                .await;
                                continue;
                            }
                        };
                    // Refuse a data connection whose source IP is not the control peer's: it is
                    // an off-path hijacker racing the passive port, and capturing its upload
                    // would attribute the sample to the control connection's source_ip.
                    if !data_peer_matches(source_ip, data_peer) {
                        drop(data);
                        let _ =
                            write_line(&mut reader, b"425 Security: bad IP connecting.\r\n").await;
                        continue;
                    }
                    let (body, wire_bytes, outcome) = receive_stor(data, bounds.idle_timeout).await;
                    let complete = outcome == StorOutcome::Complete;

                    let orig_name = filename.clone();
                    let job = CaptureJob {
                        body,
                        orig_name,
                        event_builder: Box::new(move |sample: SampleRef| {
                            let mut metadata = upload_metadata(PROTOCOL_LABEL, &sample, wire_bytes);
                            metadata["complete"] = serde_json::Value::Bool(complete);
                            SensorEvent {
                                v: WIRE_VERSION,
                                source_ip,
                                wan_ip,
                                sensor: PROTOCOL_LABEL.to_string(),
                                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.to_string(),
                                protocol: PROTO_TCP.to_string(),
                                authenticated: logged_in,
                                observed_at: chrono::Utc::now(),
                                metadata,
                                sample: Some(sample),
                                session_id: Some(session_id),
                                occurrence_id: None,
                            }
                        }),
                    };
                    let _ = handoff.submit(job);
                    let reply: &[u8] = match outcome {
                        StorOutcome::Complete => b"226 Transfer complete.\r\n",
                        StorOutcome::NetworkFailure => b"426 Failure reading network stream.\r\n",
                        StorOutcome::DrainCapReached => b"451 Failure writing to local file.\r\n",
                    };
                    let _ = write_line(&mut reader, reply).await;
                } else {
                    let _ = write_line(&mut reader, b"425 Use PORT or PASV first.\r\n").await;
                }
            }
            "RETR" => {
                let _ = write_line(&mut reader, b"550 Failed to open file.\r\n").await;
            }
            "PORT" | "EPRT" => {
                // Known commands, but active mode is unimplemented -> 502 (not 500, which is for an
                // unrecognized verb). This also keeps the sensor from ever dialing out.
                let _ = write_line(&mut reader, b"502 Command not implemented.\r\n").await;
            }
            "QUIT" => {
                let _ = write_line(&mut reader, b"221 Goodbye.\r\n").await;
                return;
            }
            "NOOP" => {
                let _ = write_line(&mut reader, b"200 NOOP ok.\r\n").await;
            }
            _ => {
                let _ = write_line(&mut reader, b"500 Unknown command.\r\n").await;
            }
        }
    }
}

fn connection_event(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

fn login_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    username: &str,
    session_id: Uuid,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "username": username,
        }),
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

fn split_ftp_command(line: &str) -> (&str, &str) {
    let trimmed = line.trim();
    if let Some(idx) = trimmed.find(' ') {
        let cmd = &trimmed[..idx];
        let arg = trimmed[idx + 1..].trim();
        (cmd, arg)
    } else {
        (trimmed, "")
    }
}

async fn write_line(reader: &mut BufReader<TcpStream>, data: &[u8]) -> Result<(), ()> {
    reader.get_mut().write_all(data).await.map_err(|_| ())
}

async fn read_line_bounded(
    reader: &mut BufReader<TcpStream>,
    bounds: &ConnectionBounds,
    total: &mut u64,
) -> Option<String> {
    if *total >= bounds.max_captured_bytes {
        return None;
    }
    let timeout = if *total == 0 {
        bounds.read_timeout
    } else {
        bounds.idle_timeout
    };

    // Bound the bytes buffered for ONE line: a client that never sends a newline would otherwise
    // make `read_line` grow the buffer to the whole line before any cap applied (unbounded
    // allocation -> OOM), and this is pre-auth. Read through a `take` limited to MAX_LINE_LEN and
    // never past the remaining capture budget, so an over-long line is chopped, not buffered whole.
    let remaining = bounds.max_captured_bytes.saturating_sub(*total);
    let cap = (MAX_LINE_LEN as u64).min(remaining).max(1);
    let mut buf = Vec::new();
    let mut limited = (&mut *reader).take(cap);
    match tokio::time::timeout(timeout, limited.read_until(b'\n', &mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => None,
        Ok(Ok(n)) => {
            *total += n as u64;
            Some(
                String::from_utf8_lossy(&buf)
                    .trim_end_matches(['\r', '\n'])
                    .to_string(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_event_is_unauthenticated_with_ftp_label() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7());
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "ftp");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
    }

    #[test]
    fn login_event_is_authenticated_and_carries_username() {
        let event = login_event(
            "203.0.113.7".parse().unwrap(),
            None,
            "admin",
            Uuid::now_v7(),
        );
        assert!(event.authenticated);
        assert_eq!(event.sensor, "ftp");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
        assert_eq!(
            event.metadata.get("username").and_then(|v| v.as_str()),
            Some("admin")
        );
        assert!(event.metadata.get("password").is_none());
    }

    #[test]
    fn split_ftp_command_splits_correctly() {
        assert_eq!(split_ftp_command("USER admin"), ("USER", "admin"));
        assert_eq!(split_ftp_command("QUIT"), ("QUIT", ""));
        assert_eq!(
            split_ftp_command("STOR /tmp/file name.bin"),
            ("STOR", "/tmp/file name.bin")
        );
    }

    #[test]
    fn data_peer_must_match_control_ip() {
        let control: IpAddr = "203.0.113.7".parse().unwrap();

        // Same host, different source port on the data channel: allowed.
        assert!(data_peer_matches(
            control,
            "203.0.113.7:51000".parse().unwrap()
        ));

        // A different host racing the passive port: refused (this is the hijack we block).
        assert!(!data_peer_matches(
            control,
            "198.51.100.9:51000".parse().unwrap()
        ));

        // The same host arriving as an IPv4-mapped IPv6 peer must still match after normalization.
        assert!(data_peer_matches(
            control,
            "[::ffff:203.0.113.7]:51000".parse().unwrap()
        ));
    }
}
