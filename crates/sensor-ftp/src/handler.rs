use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{
    CaptureBody, CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, MaybeTlsStream,
    TlsServer, Uuid, WanResolver, upgrade_buffered, upload_metadata,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION,
    SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent,
    WIRE_VERSION,
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

// vsftpd 3.0.5's FEAT, limited to what this sensor actually backs (SIZE/MDTM/REST are implemented
// below; EPRT is omitted since active mode is not supported). With ssl_enable vsftpd also lists the
// TLS verbs, so they appear only when this sensor really answers them.
const FEAT_PLAIN: &[u8] =
    b"211-Features:\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n";
const FEAT_TLS: &[u8] = b"211-Features:\r\n AUTH SSL\r\n AUTH TLS\r\n EPSV\r\n MDTM\r\n PASV\r\n PBSZ\r\n PROT\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n";

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

/// Inserts `"tls": true` into event metadata. The key is present only for TLS sessions (never
/// `false`), so a consumer cannot mistake an absent tag for a recorded "not TLS".
fn tag_tls(metadata: &mut serde_json::Value) {
    if let Some(object) = metadata.as_object_mut() {
        object.insert("tls".to_string(), serde_json::Value::Bool(true));
    }
}

/// The data connection as the client's PROT level requires. `None` means the TLS handshake the
/// client owed on an accepted PROT P connection failed or timed out. Called only AFTER
/// `data_peer_matches` accepted the peer, so an off-path hijacker never reaches the handshake.
async fn protect_data(
    data: TcpStream,
    prot_private: bool,
    tls: Option<&TlsServer>,
    timeout: std::time::Duration,
) -> Option<MaybeTlsStream> {
    if !prot_private {
        return Some(MaybeTlsStream::Plain(data));
    }
    // PROT P is only reachable once TLS is configured (the PROT arm is gated on it); a missing
    // server here is a bug, refused rather than downgraded to cleartext.
    let tls = tls?;
    match tokio::time::timeout(timeout, tls.accept(data)).await {
        Ok(Ok(stream)) => Some(MaybeTlsStream::Tls(Box::new(stream))),
        Ok(Err(error)) => {
            tracing::debug!(%error, "ftps data channel handshake failed");
            None
        }
        Err(_) => {
            tracing::debug!("ftps data channel handshake timed out");
            None
        }
    }
}

async fn send_and_close<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_all(payload).await?;
    writer.flush().await?;
    // close_notify on TLS, FIN on plain.
    writer.shutdown().await
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
    /// The process-wide capture memory budget had no room for more of the file. What was already
    /// buffered is kept as a prefix; the reply is the same one a full disk gets.
    CaptureBudgetExhausted,
}

/// A STOR upload being received: the retained body (at most `MAX_STOR_BODY`), the bytes the
/// client sent whether retained or not, and what the event needs. Submitted through `finish`
/// with the outcome, or from `Drop` as incomplete if the handler is cancelled mid-transfer (the
/// listener's `max_duration` drops the whole future, so no code after the read would run).
struct StorCapture {
    body: CaptureBody,
    wire_bytes: u64,
    submitted: bool,
    orig_name: String,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    logged_in: bool,
    /// The control channel was TLS; tags the upload event.
    tls: bool,
    session_id: Uuid,
    handoff: Arc<CaptureHandoff>,
}

impl StorCapture {
    /// Read the upload from its data connection and return how it ended. Past the cap the read
    /// keeps draining (bounded by `MAX_STOR_DRAIN`, so a slow trickle cannot hold the data
    /// connection open forever) purely to measure the real size.
    async fn receive<D: AsyncRead + Unpin>(
        &mut self,
        mut data: D,
        idle_timeout: std::time::Duration,
    ) -> StorOutcome {
        let mut chunk = [0u8; 4096];
        loop {
            match tokio::time::timeout(idle_timeout, data.read(&mut chunk)).await {
                Ok(Ok(0)) => return StorOutcome::Complete,
                // A TLS client that just closes the data connection (no close_notify) surfaces as
                // UnexpectedEof. vsftpd tolerates that by default (strict_ssl_read_eof=NO) and FTPS
                // clients routinely do it, so it is the end of the file. A plain TcpStream read
                // never yields this kind.
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return StorOutcome::Complete;
                }
                Ok(Err(_)) | Err(_) => return StorOutcome::NetworkFailure,
                Ok(Ok(n)) => {
                    let take = MAX_STOR_BODY.saturating_sub(self.body.len()).min(n);
                    let kept = self.body.extend_from_slice(&chunk[..take]);
                    self.wire_bytes += n as u64;
                    if kept.is_err() {
                        return StorOutcome::CaptureBudgetExhausted;
                    }
                    if self.wire_bytes >= (MAX_STOR_BODY + MAX_STOR_DRAIN) as u64 {
                        return StorOutcome::DrainCapReached;
                    }
                }
            }
        }
    }

    fn finish(&mut self, complete: bool) {
        if self.submitted {
            return;
        }
        self.submitted = true;
        let body = std::mem::replace(&mut self.body, self.handoff.new_capture_body());
        let orig_name = self.orig_name.clone();
        let (source_ip, wan_ip, logged_in, tls, session_id, wire_bytes) = (
            self.source_ip,
            self.wan_ip,
            self.logged_in,
            self.tls,
            self.session_id,
            self.wire_bytes,
        );
        let job = CaptureJob {
            body,
            orig_name,
            event_builder: Box::new(move |sample: SampleRef| {
                let mut metadata = upload_metadata(PROTOCOL_LABEL, &sample, wire_bytes, complete);
                if tls {
                    tag_tls(&mut metadata);
                }
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
        let _ = self.handoff.submit(job);
    }
}

impl Drop for StorCapture {
    fn drop(&mut self) {
        if self.wire_bytes > 0 {
            self.finish(false);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection(
    stream: MaybeTlsStream,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    handoff: Arc<CaptureHandoff>,
    tls: Option<TlsServer>,
) {
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = local_addr
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    // The interface the control connection arrived on: the passive data listener binds here (not
    // loopback) so a remote client can reach it. From the caller-supplied `local_addr`.
    let control_local_ip = local_addr.map(|a| normalize_dual_stack(a).ip());

    let _ = emitter
        .append(&connection_event(
            source_ip,
            wan_ip,
            session_id,
            stream.is_tls(),
        ))
        .await;

    let mut reader = BufReader::new(stream);
    if write_line(&mut reader, BANNER).await.is_err() {
        return;
    }

    let mut username = String::new();
    let mut logged_in = false;
    // RFC 4217 data-channel state: PBSZ must precede PROT, and only PROT P protects the data.
    let mut pbsz_done = false;
    let mut prot_private = false;
    // Not reset by an AUTH TLS upgrade: the capture cap is per connection.
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
                    .append(&login_event(
                        source_ip,
                        wan_ip,
                        &username,
                        session_id,
                        reader.get_ref().is_tls(),
                    ))
                    .await;
                let _ = write_line(&mut reader, b"230 Login successful.\r\n").await;
            }
            "SYST" => {
                let _ = write_line(&mut reader, b"215 UNIX Type: L8\r\n").await;
            }
            "AUTH" => match tls.as_ref() {
                // No TLS configured: AUTH is an unknown verb, as before TLS support existed.
                None => {
                    let _ = write_line(&mut reader, b"500 Unknown command.\r\n").await;
                }
                Some(tls_server) => {
                    let mechanism = arg.to_ascii_uppercase();
                    if reader.get_ref().is_tls() {
                        let _ = write_line(&mut reader, b"503 Bad sequence of commands.\r\n").await;
                    } else if !matches!(mechanism.as_str(), "TLS" | "TLS-C" | "SSL" | "TLS-P") {
                        let _ = write_line(&mut reader, b"504 Unknown AUTH type.\r\n").await;
                    } else {
                        // Bytes already buffered behind the AUTH line were sent in plaintext
                        // before the handshake: a man-in-the-middle prepending commands to the
                        // TLS session (CVE-2011-0411 shape). Refuse, record, and close rather
                        // than answer 234. Checked before the 234 so the client never gets a
                        // go-ahead for an upgrade that will not happen.
                        let pipelined = reader.buffer().len();
                        if pipelined > 0 {
                            let _ = emitter
                                .append(&auth_refused_event(
                                    source_ip, wan_ip, logged_in, session_id, pipelined,
                                ))
                                .await;
                            let _ = write_line(
                                &mut reader,
                                b"504 Pipelined commands after AUTH TLS refused.\r\n",
                            )
                            .await;
                            let _ = reader.get_mut().shutdown().await;
                            return;
                        }
                        if write_line(&mut reader, b"234 Proceed with negotiation.\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        match upgrade_buffered(reader, tls_server, bounds.read_timeout).await {
                            Ok(upgraded) => reader = upgraded,
                            Err(error) => {
                                tracing::debug!(%peer_addr, %error, "auth tls upgrade failed; closing");
                                return;
                            }
                        }
                        // RFC 4217 section 4: the upgrade resets the session as if REIN, so a
                        // USER sent in cleartext does not carry into the protected session.
                        username.clear();
                        logged_in = false;
                        pbsz_done = false;
                        prot_private = false;
                        pasv_listener = None;
                    }
                }
            },
            // With no TLS configured these fall through to the 500 arm, unchanged.
            "PBSZ" if tls.is_some() => {
                let reply: &[u8] = if reader.get_ref().is_tls() {
                    pbsz_done = true;
                    b"200 PBSZ set to 0.\r\n"
                } else {
                    b"503 Bad sequence of commands.\r\n"
                };
                let _ = write_line(&mut reader, reply).await;
            }
            "PROT" if tls.is_some() => {
                let reply: &[u8] = if !reader.get_ref().is_tls() || !pbsz_done {
                    b"503 Bad sequence of commands.\r\n"
                } else {
                    match arg.to_ascii_uppercase().as_str() {
                        "C" => {
                            prot_private = false;
                            b"200 PROT now Clear.\r\n"
                        }
                        "P" => {
                            prot_private = true;
                            b"200 PROT now Private.\r\n"
                        }
                        "S" | "E" => b"536 PROT not supported.\r\n",
                        _ => b"504 Bad PROT command.\r\n",
                    }
                };
                let _ = write_line(&mut reader, reply).await;
            }
            "FEAT" => {
                let feat = if tls.is_some() { FEAT_TLS } else { FEAT_PLAIN };
                let _ = write_line(&mut reader, feat).await;
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
                            Ok(Ok((data, data_peer))) => {
                                if data_peer_matches(source_ip, data_peer) {
                                    match protect_data(
                                        data,
                                        prot_private,
                                        tls.as_ref(),
                                        bounds.read_timeout,
                                    )
                                    .await
                                    {
                                        Some(mut data) => {
                                            // LIST is the long ls -l form; NLST is bare names only.
                                            let payload = if cmd == "NLST" {
                                                CANNED_NLST
                                            } else {
                                                CANNED_LIST
                                            };
                                            if send_and_close(&mut data, payload.as_bytes())
                                                .await
                                                .is_ok()
                                            {
                                                b"226 Directory send OK.\r\n"
                                            } else {
                                                b"426 Failure writing network stream.\r\n"
                                            }
                                        }
                                        None => b"425 Failed to establish connection.\r\n",
                                    }
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
                    let Some(data) =
                        protect_data(data, prot_private, tls.as_ref(), bounds.read_timeout).await
                    else {
                        let _ = write_line(&mut reader, b"425 Failed to establish connection.\r\n")
                            .await;
                        continue;
                    };
                    let mut capture = StorCapture {
                        body: handoff.new_capture_body(),
                        wire_bytes: 0,
                        submitted: false,
                        orig_name: filename.clone(),
                        source_ip,
                        wan_ip,
                        logged_in,
                        tls: reader.get_ref().is_tls(),
                        session_id,
                        handoff: handoff.clone(),
                    };
                    let outcome = capture.receive(data, bounds.idle_timeout).await;
                    capture.finish(outcome == StorOutcome::Complete);
                    let reply: &[u8] = match outcome {
                        StorOutcome::Complete => b"226 Transfer complete.\r\n",
                        StorOutcome::NetworkFailure => b"426 Failure reading network stream.\r\n",
                        StorOutcome::DrainCapReached | StorOutcome::CaptureBudgetExhausted => {
                            b"451 Failure writing to local file.\r\n"
                        }
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
                // close_notify on a TLS control channel, FIN on plain.
                let _ = reader.get_mut().shutdown().await;
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

fn connection_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    tls: bool,
) -> SensorEvent {
    let mut metadata = serde_json::json!({ "protocol_label": PROTOCOL_LABEL });
    if tls {
        tag_tls(&mut metadata);
    }
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata,
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
    tls: bool,
) -> SensorEvent {
    let mut metadata = serde_json::json!({
        "protocol_label": PROTOCOL_LABEL,
        "username": username,
    });
    if tls {
        tag_tls(&mut metadata);
    }
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated: true,
        observed_at: chrono::Utc::now(),
        metadata,
        sample: None,
        session_id: Some(session_id),
        occurrence_id: None,
    }
}

/// An AUTH TLS refused because the client pipelined plaintext behind it. Always plaintext-phase,
/// so it carries no `tls` tag.
fn auth_refused_event(
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    authenticated: bool,
    session_id: Uuid,
    pipelined_bytes: usize,
) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip,
        wan_ip,
        sensor: PROTOCOL_LABEL.to_string(),
        signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.to_string(),
        protocol: PROTO_TCP.to_string(),
        authenticated,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({
            "protocol_label": PROTOCOL_LABEL,
            "command": "AUTH",
            "starttls_refused": "pipelined_plaintext",
            "pipelined_bytes": pipelined_bytes,
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

async fn write_line<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    data: &[u8],
) -> Result<(), ()> {
    let inner = reader.get_mut();
    inner.write_all(data).await.map_err(|_| ())?;
    // A TLS stream can hold written records until flushed.
    inner.flush().await.map_err(|_| ())
}

async fn read_line_bounded<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
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

    /// A hand-off with one queue slot and no worker: a second `submit` is refused, which is how
    /// a test proves the first happened.
    fn one_slot_handoff() -> Arc<CaptureHandoff> {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let outbox_dir = dir.path().join("outbox");
        let spool =
            sensor_framework::QuarantineSpool::new(spool_dir, MAX_STOR_BODY as u64, 100_000_000);
        let emitter = sensor_framework::EventEmitter::new(dir.path().join("events.jsonl"));
        std::mem::forget(dir);
        Arc::new(CaptureHandoff::new(
            spool,
            emitter,
            1,
            "test".to_string(),
            sensor_framework::OutboxManifest::new(outbox_dir),
            Arc::new(sensor_framework::CaptureMemoryBudget::new(u64::MAX)),
        ))
    }

    fn body_of(bytes: &[u8]) -> CaptureBody {
        let mut body = CaptureBody::unbudgeted();
        body.extend_from_slice(bytes).unwrap();
        body
    }

    fn probe_job() -> CaptureJob {
        CaptureJob {
            body: body_of(&[1]),
            orig_name: "probe".into(),
            event_builder: Box::new(|_sample| unreachable!("never built")),
        }
    }

    /// The listener cancels a handler at `max_duration` by dropping its future mid-read; the
    /// bytes already received must still reach the hand-off, as an incomplete capture, and a
    /// finished capture must not be submitted twice by the same mechanism.
    #[tokio::test]
    async fn stor_capture_is_submitted_when_the_handler_is_cancelled() {
        let handoff = one_slot_handoff();
        let capture = StorCapture {
            body: body_of(b"MZ-part"),
            wire_bytes: 7,
            submitted: false,
            orig_name: "x.bin".into(),
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            logged_in: true,
            tls: false,
            session_id: Uuid::now_v7(),
            handoff: handoff.clone(),
        };
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            let _keep = &capture;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(cancelled.is_err());
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the one slot holds the abandoned STOR fragment"
        );

        let handoff = one_slot_handoff();
        let mut finished = StorCapture {
            body: body_of(b"whole"),
            wire_bytes: 5,
            submitted: false,
            orig_name: "y.bin".into(),
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            logged_in: true,
            tls: false,
            session_id: Uuid::now_v7(),
            handoff: handoff.clone(),
        };
        finished.finish(true);
        drop(finished);
        assert!(
            handoff.submit(probe_job()).is_err(),
            "exactly one submission: finish, not finish plus drop"
        );
        let empty = StorCapture {
            body: CaptureBody::unbudgeted(),
            wire_bytes: 0,
            submitted: false,
            orig_name: "z.bin".into(),
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            logged_in: true,
            tls: false,
            session_id: Uuid::now_v7(),
            handoff: one_slot_handoff(),
        };
        let handoff = empty.handoff.clone();
        drop(empty);
        assert!(
            handoff.submit(probe_job()).is_ok(),
            "nothing received, nothing submitted"
        );
    }

    #[test]
    fn connection_event_is_unauthenticated_with_ftp_label() {
        let event = connection_event("203.0.113.7".parse().unwrap(), None, Uuid::now_v7(), false);
        assert!(event.metadata.get("tls").is_none());
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
            false,
        );
        assert!(event.metadata.get("tls").is_none());
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
    fn tls_tag_present_only_when_true() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let conn = connection_event(ip, None, Uuid::now_v7(), true);
        let login = login_event(ip, None, "a", Uuid::now_v7(), true);
        assert_eq!(conn.metadata["tls"], true);
        assert_eq!(login.metadata["tls"], true);
    }

    #[test]
    fn auth_refused_event_shape() {
        let event = auth_refused_event(
            "203.0.113.7".parse().unwrap(),
            None,
            false,
            Uuid::now_v7(),
            17,
        );
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(event.metadata["command"], "AUTH");
        assert_eq!(event.metadata["starttls_refused"], "pipelined_plaintext");
        assert_eq!(event.metadata["pipelined_bytes"], 17);
        assert!(event.metadata.get("tls").is_none());
    }

    /// Yields three bytes, then a configured error.
    struct ThenError {
        sent: bool,
        kind: std::io::ErrorKind,
    }

    impl AsyncRead for ThenError {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.sent {
                return std::task::Poll::Ready(Err(self.kind.into()));
            }
            self.sent = true;
            buf.put_slice(b"abc");
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn capture_for_receive() -> StorCapture {
        StorCapture {
            body: CaptureBody::unbudgeted(),
            wire_bytes: 0,
            submitted: false,
            orig_name: "r.bin".into(),
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            logged_in: true,
            tls: true,
            session_id: Uuid::now_v7(),
            handoff: one_slot_handoff(),
        }
    }

    #[tokio::test]
    async fn receive_treats_unexpected_eof_as_complete_but_other_errors_as_failure() {
        let idle = std::time::Duration::from_secs(1);
        let mut c = capture_for_receive();
        let eof = ThenError {
            sent: false,
            kind: std::io::ErrorKind::UnexpectedEof,
        };
        assert_eq!(c.receive(eof, idle).await, StorOutcome::Complete);
        assert_eq!(c.wire_bytes, 3);

        let mut c = capture_for_receive();
        let reset = ThenError {
            sent: false,
            kind: std::io::ErrorKind::ConnectionReset,
        };
        assert_eq!(c.receive(reset, idle).await, StorOutcome::NetworkFailure);
        assert_eq!(c.wire_bytes, 3);
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
