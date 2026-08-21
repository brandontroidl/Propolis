use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{
    CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, Uuid, WanResolver,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_CONNECTION, SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
    SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

const PROTOCOL_LABEL: &str = "ftp";
const MAX_LINE_LEN: usize = 8192;
const MAX_USERNAME_LEN: usize = 255;
const MAX_STOR_BODY: usize = 10_000_000;

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

        match cmd {
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
                    if let Ok(Ok((mut data, _))) =
                        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                            .await
                    {
                        // LIST is the long ls -l form; NLST is bare names only.
                        let payload = if cmd == "NLST" {
                            CANNED_NLST
                        } else {
                            CANNED_LIST
                        };
                        let _ = data.write_all(payload.as_bytes()).await;
                        drop(data);
                    }
                    let _ = write_line(&mut reader, b"226 Directory send OK.\r\n").await;
                } else {
                    let _ = write_line(&mut reader, b"425 Use PORT or PASV first.\r\n").await;
                }
            }
            "STOR" => {
                let filename = sanitize_value(arg, 255);
                if let Some(ref listener) = pasv_listener {
                    let _ = write_line(&mut reader, b"150 Ok to send data.\r\n").await;
                    if let Ok(Ok((mut data, _))) =
                        tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                            .await
                    {
                        let mut body = Vec::new();
                        let mut chunk = [0u8; 4096];
                        loop {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                data.read(&mut chunk),
                            )
                            .await
                            {
                                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                                Ok(Ok(n)) => {
                                    let take = MAX_STOR_BODY.saturating_sub(body.len()).min(n);
                                    body.extend_from_slice(&chunk[..take]);
                                    if body.len() >= MAX_STOR_BODY {
                                        break;
                                    }
                                }
                            }
                        }
                        drop(data);

                        let orig_name = filename.clone();
                        let job = CaptureJob {
                            body,
                            orig_name,
                            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                                v: WIRE_VERSION,
                                source_ip,
                                wan_ip,
                                sensor: PROTOCOL_LABEL.to_string(),
                                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.to_string(),
                                protocol: PROTO_TCP.to_string(),
                                authenticated: logged_in,
                                observed_at: chrono::Utc::now(),
                                metadata: serde_json::json!({
                                    "protocol_label": PROTOCOL_LABEL,
                                    "sha256": sample.sha256,
                                    "size": sample.size,
                                    "orig_name": sample.orig_name,
                                }),
                                sample: Some(sample),
                                session_id: Some(session_id),
                            }),
                        };
                        let _ = handoff.submit(job);
                    }
                    let _ = write_line(&mut reader, b"226 Transfer complete.\r\n").await;
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
}
