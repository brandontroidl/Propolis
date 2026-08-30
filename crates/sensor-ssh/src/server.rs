//! SSH session composition (Task 14): wires transport, key exchange, authentication, channel
//! management, the fake shell, and SCP/SFTP capture into a complete honeypot SSH server. The
//! entry point is [`serve`], which binds a listener through the framework's
//! `run_tcp_listener` and spawns a per-connection `handle_session` task. Each session performs
//! the full SSH handshake using this crate's own primitives (see ADR-0011), then dispatches
//! channel data to the appropriate handler.
//!
//! [`serve`] was named `start_test_server` until it was noticed that the production binary calls
//! it - the name had stopped describing what it was for, and it read as though the internet-facing
//! honeypot were a test fixture. Renamed rather than aliased so there is one name for one thing.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use sensor_framework::listener::{normalize_dual_stack, run_tcp_listener};
use sensor_framework::persona;
use sensor_framework::{
    CaptureHandoff, CaptureJob, ConnectionBounds, EventEmitter, QuarantineSpool, WanResolver,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

use crate::auth::AuthState;
use crate::channel::{ChannelAction, handle_channel_open, handle_channel_request};
use crate::fakefs::FakeFs;
use crate::hostkey::HostKey;
use crate::shell::{EmitContext, FakeShell};
use crate::timeout_stream::TimeoutStream;
use crate::transfer::{ScpReceiver, SftpHandler};
use crate::transport::cipher::TransportCipher;
use crate::transport::kex::perform_kex_server;
use crate::transport::{
    self, SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_OPEN,
    SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_WINDOW_ADJUST,
    SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_NEWKEYS, SSH_MSG_SERVICE_ACCEPT,
    SSH_MSG_SERVICE_REQUEST, SSH_MSG_UNIMPLEMENTED, SSH_MSG_USERAUTH_REQUEST,
};

/// Cap on the shell line buffer: if an attacker sends a continuous stream of non-newline bytes,
/// the buffer is flushed as a partial line once it hits this limit. Typing is still captured but
/// memory stays bounded. 8 KiB is generous for any real command line.
const MAX_LINE_LEN: usize = 8192;

/// The handler active on a given channel.
enum ChannelHandler {
    /// Awaiting a channel request to determine the handler type.
    Pending,
    /// Interactive fake shell with a line buffer for incremental input.
    Shell(FakeShell, Vec<u8>),
    /// SCP server-mode file receiver.
    Scp(ScpReceiver),
    /// SFTP subsystem handler.
    Sftp(SftpHandler),
}

/// Start the SSH honeypot server on `addr` (use `:0` for ephemeral). Returns the bound
/// address and a join handle for the listener task.
///
/// `wan_resolver` maps the listener's local address to the operator's WAN IP (see
/// `sensor_framework::WanResolver`). Tests that do not need WAN attribution pass an empty
/// resolver; production passes the operator-configured map.
///
/// `bounds` is enforced by `sensor_framework::listener::run_tcp_listener`, the same accept loop
/// every other sensor uses. This function used to hand-roll its own loop and consequently had
/// none of it: no concurrency cap, no session-duration cap, and a bare `continue` on accept
/// errors. Nothing in `handle_session` below imposes a deadline either - every phase awaits a
/// socket read with no timeout - so a peer that completed the handshake and then went quiet held
/// its connection, and its file descriptor, indefinitely. Confirmed against the live sensor: a
/// connection left idle after KEXINIT was still open 75 seconds later, where telnet closes an
/// idle session in 30.
///
/// That combination is monotonic: connections accumulate, and once descriptors run out `accept`
/// fails immediately and repeatedly, which the old loop retried with no backoff - a busy-spin at
/// the exact moment the service is already failing. `run_tcp_listener` caps concurrency with a
/// semaphore, runs each session inside `tokio::time::timeout(max_duration, ...)`, and backs off
/// on accept errors.
pub async fn serve(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    host_key_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    banner: String,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    // The software-version this server sends in `SSH-2.0-<banner>`. Shared read-only across all
    // sessions, so one `Arc` rather than a clone per connection.
    let banner = Arc::new(banner);
    // Load or generate the host key.
    let host_key = if host_key_path.exists() {
        HostKey::load(&host_key_path)?
    } else {
        let key = HostKey::generate();
        if let Some(parent) = host_key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        key.save(&host_key_path)?;
        key
    };

    // Ensure the spool directory exists.
    std::fs::create_dir_all(&spool_dir)?;

    let emitter = Arc::new(EventEmitter::new(log_path.clone()));
    let spool = QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000);
    // The handoff's emitter writes to the same log file. EventEmitter opens with O_APPEND
    // on each write so concurrent emitters to the same path are safe.
    let handoff = Arc::new(CaptureHandoff::new(spool, EventEmitter::new(log_path), 64));
    let _worker = handoff.start_worker();

    let read_timeout = bounds.read_timeout;
    let idle_timeout = bounds.idle_timeout;
    // Extracted before `bounds` is moved into `run_tcp_listener` below. This bounds only the
    // shell-channel evidence capture buffer (see `handle_session`'s Shell branch) - a separate,
    // much narrower ceiling than SCP/SFTP's own 10 MB per-file cap (see `transfer.rs` and
    // `timeout_stream.rs`'s module doc for why the two are not the same budget).
    let max_captured_bytes = bounds.max_captured_bytes;
    let (bound_addr, handle) =
        run_tcp_listener(addr, bounds, move |stream, peer_addr, session_id| {
            let host_key = host_key.clone();
            let emitter = emitter.clone();
            let handoff = handoff.clone();
            let wan_resolver = wan_resolver.clone();
            let banner = banner.clone();
            // Wrapped once here rather than at each read: every transport function is generic over
            // AsyncRead/AsyncWrite, so the whole session inherits the per-read bound - including
            // any read added later, which a per-call-site timeout would miss.
            let stream = TimeoutStream::new(stream, read_timeout, idle_timeout);
            async move {
                if let Err(e) = handle_session(
                    stream,
                    peer_addr,
                    session_id,
                    host_key,
                    emitter,
                    handoff,
                    wan_resolver,
                    banner,
                    max_captured_bytes,
                )
                .await
                {
                    tracing::debug!(error = %e, peer = %peer_addr, "SSH session ended");
                }
            }
        })
        .await?;

    Ok((bound_addr, handle))
}

/// Handle one SSH connection end to end: version exchange, key exchange, authentication,
/// channel management, and data dispatch.
#[allow(clippy::too_many_arguments)]
async fn handle_session(
    mut stream: TimeoutStream<TcpStream>,
    peer_addr: SocketAddr,
    session_id: sensor_framework::Uuid,
    host_key: HostKey,
    emitter: Arc<EventEmitter>,
    handoff: Arc<CaptureHandoff>,
    wan_resolver: Arc<WanResolver>,
    banner: Arc<String>,
    max_captured_bytes: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ---- Phase 1: version exchange ----
    let (client_version, server_version) =
        transport::do_version_exchange_server_with_version(&mut stream, &banner).await?;

    // ---- Phase 2: key exchange ----

    // Server sends KEXINIT (s2c packet #0).
    let server_kexinit = transport::build_kexinit();
    transport::write_packet_unencrypted(&mut stream, &server_kexinit).await?;

    // Read client's KEXINIT (c2s packet #0).
    let client_kexinit_pkt = transport::read_packet_unencrypted(&mut stream).await?;
    let _client_kexinit = transport::parse_kexinit(&client_kexinit_pkt.payload)?;

    // Read client's ECDH_INIT (c2s packet #1).
    let client_ecdh_init = transport::read_packet_unencrypted(&mut stream).await?;

    // Perform key exchange: computes shared secret, signs exchange hash, sends ECDH_REPLY
    // (s2c packet #1).
    let session_keys = perform_kex_server(
        &mut stream,
        &host_key,
        &client_kexinit_pkt.payload,
        &server_kexinit,
        &client_version,
        &server_version,
        &client_ecdh_init.payload,
    )
    .await?;

    // Server sends NEWKEYS (s2c packet #2).
    transport::write_packet_unencrypted(&mut stream, &[SSH_MSG_NEWKEYS]).await?;

    // Read client's NEWKEYS (c2s packet #2).
    let newkeys_pkt = transport::read_packet_unencrypted(&mut stream).await?;
    if newkeys_pkt.payload.first() != Some(&SSH_MSG_NEWKEYS) {
        return Err("expected SSH_MSG_NEWKEYS".into());
    }

    // ---- Phase 3: encrypted transport ----

    // Create directional ciphers. c2s for reading client packets, s2c for writing.
    let mut c2s_cipher = session_keys.client_to_server_cipher();
    let mut s2c_cipher = session_keys.server_to_client_cipher();

    // Sequence numbers: 3 unencrypted packets sent/received per direction (KEXINIT,
    // ECDH_INIT/REPLY, NEWKEYS), so the first encrypted packet is seq 3.
    let mut c2s_seq: u32 = 3;
    let mut s2c_seq: u32 = 3;

    // Normalize dual-stack mapped addresses before resolving WAN, so an IPv4-mapped
    // IPv6 address (::ffff:a.b.c.d from a dual-stack listener) matches the operator's
    // plain-IPv4 WAN map entry.
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let local_addr = stream.get_ref().local_addr().map(normalize_dual_stack).ok();
    let wan_ip = local_addr.and_then(|la| wan_resolver.resolve(la.ip()));
    let mut auth_state = AuthState::new(source_ip, wan_ip, session_id);

    // Emit honeypot_connection (authenticated=false, pre-auth).
    let conn_event = auth_state.emit_connection_event();
    emitter.append(&conn_event).await?;

    // Per-channel state. Only one channel is typical, but we track by id.
    let mut channel_id: Option<u32> = None;
    let mut handler: ChannelHandler = ChannelHandler::Pending;

    // Raw shell-channel bytes accumulated for evidence capture, and whether the shared FakeShell
    // ever flagged one as a binary flood (see the Shell arm of SSH_MSG_CHANNEL_DATA below and the
    // submission after the packet loop). SSH authentication happens in USERAUTH_REQUEST packets,
    // never in channel data, so the shell channel - which exists only post-auth - can never carry
    // the login password; no phase-gating is needed here the way telnet's LineReader needs
    // `start_capture` to exclude its pre-auth login prompt.
    let mut shell_capture: Vec<u8> = Vec::new();
    let mut binary_seen = false;

    // ---- Main encrypted packet loop ----
    loop {
        let payload =
            match transport::read_packet_encrypted(&mut stream, &mut c2s_cipher, c2s_seq).await {
                Ok(p) => p,
                Err(_) => break, // connection closed or error
            };
        c2s_seq = c2s_seq.wrapping_add(1);

        if payload.is_empty() {
            continue;
        }

        let msg_type = payload[0];

        match msg_type {
            SSH_MSG_DISCONNECT => break,
            SSH_MSG_IGNORE | SSH_MSG_UNIMPLEMENTED => continue,

            SSH_MSG_SERVICE_REQUEST => {
                // Respond with SERVICE_ACCEPT for "ssh-userauth".
                let accept = build_service_accept(b"ssh-userauth");
                write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &accept).await?;
            }

            SSH_MSG_USERAUTH_REQUEST => {
                let (response, events) = match auth_state.handle_userauth(&payload) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(error = %e, "malformed userauth");
                        continue;
                    }
                };
                for event in &events {
                    emitter.append(event).await?;
                }
                write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &response).await?;
            }

            SSH_MSG_CHANNEL_OPEN => {
                let (ch_id, response) = match handle_channel_open(&payload) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::debug!(error = %e, "malformed channel open");
                        continue;
                    }
                };
                channel_id = Some(ch_id);
                handler = ChannelHandler::Pending;
                write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &response).await?;
            }

            SSH_MSG_CHANNEL_REQUEST => {
                let Some(ch_id) = channel_id else { continue };
                let action = match handle_channel_request(&payload, ch_id) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::debug!(error = %e, "malformed channel request");
                        continue;
                    }
                };

                // Always send CHANNEL_SUCCESS so the client knows we accepted.
                let success = build_channel_success(ch_id);
                write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &success).await?;

                match action {
                    ChannelAction::PtyReq => {
                        // Acknowledged above; no state change.
                    }
                    ChannelAction::Shell => {
                        let ctx = EmitContext {
                            source_ip,
                            wan_ip,
                            authenticated: auth_state.is_authenticated(),
                            protocol_label: "ssh".to_string(),
                            session_id: Some(session_id),
                        };
                        let shell = FakeShell::new(FakeFs::new(), ctx);
                        handler = ChannelHandler::Shell(shell, Vec::new());
                        // Send an initial prompt, hostname from the shared persona so it matches
                        // uname / the fake filesystem / the other sensors.
                        let prompt = persona::root_prompt(&persona::hostname());
                        let data_pkt = build_channel_data(ch_id, prompt.as_bytes());
                        write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &data_pkt)
                            .await?;
                    }
                    ChannelAction::Exec(cmd) => {
                        // Emit a command_exec event for the exec command itself.
                        let shell_ctx = EmitContext {
                            source_ip,
                            wan_ip,
                            authenticated: auth_state.is_authenticated(),
                            protocol_label: "ssh".to_string(),
                            session_id: Some(session_id),
                        };
                        let mut shell = FakeShell::new(FakeFs::new(), shell_ctx);
                        let (output, events) = shell.handle_input(&cmd);
                        for event in &events {
                            emitter.append(event).await?;
                        }

                        if cmd.starts_with("scp -t ") {
                            // SCP server mode.
                            let (scp, initial) =
                                ScpReceiver::new(source_ip, wan_ip, session_id, handoff.clone());
                            handler = ChannelHandler::Scp(scp);
                            let data_pkt = build_channel_data(ch_id, &initial);
                            write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &data_pkt)
                                .await?;
                        } else {
                            // One-shot exec: send output and close.
                            if !output.is_empty() {
                                let data_pkt = build_channel_data(ch_id, output.as_bytes());
                                write_encrypted(
                                    &mut stream,
                                    &mut s2c_cipher,
                                    &mut s2c_seq,
                                    &data_pkt,
                                )
                                .await?;
                            }
                        }
                    }
                    ChannelAction::Subsystem(name) => {
                        if name == "sftp" {
                            let sftp =
                                SftpHandler::new(source_ip, wan_ip, session_id, handoff.clone());
                            handler = ChannelHandler::Sftp(sftp);
                        }
                    }
                    ChannelAction::Other => {}
                }
            }

            SSH_MSG_CHANNEL_DATA => {
                let Some(ch_id) = channel_id else { continue };
                // Parse: byte(94) + uint32(channel) + string(data)
                if payload.len() < 9 {
                    continue;
                }
                let data_len = u32::from_be_bytes(payload[5..9].try_into().unwrap()) as usize;
                if payload.len() < 9 + data_len {
                    continue;
                }
                let data = &payload[9..9 + data_len];

                match &mut handler {
                    ChannelHandler::Shell(shell, line_buf) => {
                        // Accumulate the raw bytes as evidence before any line-buffering or echo
                        // logic below touches them, bounded so a captured session can never grow
                        // past `max_captured_bytes` - the operator-configured ceiling this crate's
                        // own `ConnectionBounds` defines. Whether the buffer is ever submitted
                        // depends on `binary_seen`, set below when the shared FakeShell flags a
                        // binary flood; a plaintext-only session accumulates here but the buffer is
                        // discarded, never spooled, once the loop ends.
                        let room =
                            max_captured_bytes.saturating_sub(shell_capture.len() as u64) as usize;
                        if room > 0 {
                            let take = data.len().min(room);
                            shell_capture.extend_from_slice(&data[..take]);
                        }

                        // A real interactive session runs the client terminal in raw mode and relies
                        // on the SERVER to echo keystrokes. Without that echo the attacker types into
                        // a blank screen and the session looks frozen (and no-echo is itself a tell,
                        // since every real shell echoes). So each printable byte is echoed as it
                        // arrives, backspace erases on screen, and Enter echoes CR-LF and shows a
                        // fresh prompt - even for an empty line, as a real shell does.
                        let mut responses = Vec::new();
                        let mut prev_cr = false;
                        for &byte in data {
                            match byte {
                                b'\r' | b'\n' => {
                                    // Swallow the LF of a CR-LF pair so Enter is one line, not two.
                                    if byte == b'\n' && prev_cr {
                                        prev_cr = false;
                                        continue;
                                    }
                                    prev_cr = byte == b'\r';
                                    responses.extend_from_slice(b"\r\n");
                                    if !line_buf.is_empty() {
                                        let line = String::from_utf8_lossy(line_buf).to_string();
                                        line_buf.clear();
                                        let (output, events) = shell.handle_input(&line);
                                        for event in &events {
                                            if event.metadata.get("flood").and_then(|v| v.as_str())
                                                == Some("binary")
                                            {
                                                binary_seen = true;
                                            }
                                            if emitter.append(event).await.is_err() {
                                                tracing::error!(%peer_addr, "ssh: failed to append command event");
                                            }
                                        }
                                        if !output.is_empty() {
                                            // The shared shell emits bare LF; a raw-mode client
                                            // terminal needs CR-LF or each line renders indented
                                            // (the cursor never returns to column 0). The Enter echo
                                            // and prompt above already use \r\n; match them.
                                            responses.extend_from_slice(
                                                output.replace('\n', "\r\n").as_bytes(),
                                            );
                                        }
                                    }
                                    responses.extend_from_slice(
                                        persona::root_prompt(&persona::hostname()).as_bytes(),
                                    );
                                }
                                // Backspace / DEL: erase the last char on screen too.
                                0x7f | 0x08 => {
                                    prev_cr = false;
                                    if line_buf.pop().is_some() {
                                        responses.extend_from_slice(b"\x08 \x08");
                                    }
                                }
                                // Printable byte: buffer and echo it.
                                b if b >= 0x20 => {
                                    prev_cr = false;
                                    line_buf.push(b);
                                    responses.push(b);
                                    // Flush a too-long line so a stream of non-newline bytes cannot
                                    // grow memory without bound.
                                    if line_buf.len() >= MAX_LINE_LEN {
                                        let line = String::from_utf8_lossy(line_buf).to_string();
                                        line_buf.clear();
                                        let (_output, events) = shell.handle_input(&line);
                                        for event in &events {
                                            if event.metadata.get("flood").and_then(|v| v.as_str())
                                                == Some("binary")
                                            {
                                                binary_seen = true;
                                            }
                                            if emitter.append(event).await.is_err() {
                                                tracing::error!(%peer_addr, "ssh: failed to append command event");
                                            }
                                        }
                                    }
                                }
                                // Other control bytes (tab, Ctrl-*, escape sequences): consume
                                // without echo, matching a shell in a minimal cooked-ish mode.
                                _ => prev_cr = false,
                            }
                        }
                        if !responses.is_empty() {
                            let data_pkt = build_channel_data(ch_id, &responses);
                            write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &data_pkt)
                                .await?;
                        }
                    }
                    ChannelHandler::Scp(scp) => {
                        let response = scp.feed(data);
                        if !response.is_empty() {
                            let data_pkt = build_channel_data(ch_id, &response);
                            write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &data_pkt)
                                .await?;
                        }
                    }
                    ChannelHandler::Sftp(sftp) => {
                        let response = sftp.feed(data);
                        if !response.is_empty() {
                            let data_pkt = build_channel_data(ch_id, &response);
                            write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &data_pkt)
                                .await?;
                        }
                    }
                    ChannelHandler::Pending => {}
                }
            }

            SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                // Ignore flow control - we write as much as we need.
            }

            SSH_MSG_CHANNEL_EOF | SSH_MSG_CHANNEL_CLOSE => {
                // Client is done with this channel.
                if let Some(ch_id) = channel_id {
                    // Send CHANNEL_CLOSE if we received CLOSE.
                    if msg_type == SSH_MSG_CHANNEL_CLOSE {
                        let close = build_channel_close(ch_id);
                        let _ = write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &close)
                            .await;
                    }
                }
                break;
            }

            _ => {
                // Send UNIMPLEMENTED for anything we do not handle.
                let unimpl = build_unimplemented(c2s_seq.wrapping_sub(1));
                let _ = write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &unimpl).await;
            }
        }
    }

    // A binary payload was seen somewhere in the shell phase (a Mirai/Gafgyt dropper streamed
    // over the "shell" - never a real interactive command, since FakeShell's binary-flood
    // detector only trips on a line that is mostly non-printable). Preserve the raw bytes as
    // evidence, reusing the same handoff SCP/SFTP already submit through. Plaintext-only sessions
    // never set `binary_seen`, so ordinary interactive commands are never spooled.
    if binary_seen && !shell_capture.is_empty() {
        let orig_name = format!("ssh-session-{session_id}");
        let _ = handoff.submit(CaptureJob {
            body: shell_capture,
            orig_name,
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: "ssh".into(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
                protocol: PROTO_TCP.into(),
                authenticated: true,
                observed_at: chrono::Utc::now(),
                metadata: serde_json::json!({
                    "protocol_label": "ssh",
                    "capture_reason": "binary_shell_payload",
                }),
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        });
    }

    Ok(())
}

// ---- Helpers ----

/// Write one encrypted packet and increment the sequence number.
async fn write_encrypted<W: tokio::io::AsyncWrite + Unpin>(
    stream: &mut W,
    cipher: &mut TransportCipher,
    seq: &mut u32,
    payload: &[u8],
) -> Result<(), transport::TransportError> {
    transport::write_packet_encrypted(stream, cipher, *seq, payload).await?;
    *seq = seq.wrapping_add(1);
    Ok(())
}

/// Build `SSH_MSG_SERVICE_ACCEPT` payload.
fn build_service_accept(service: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + service.len());
    out.push(SSH_MSG_SERVICE_ACCEPT);
    out.extend_from_slice(&(service.len() as u32).to_be_bytes());
    out.extend_from_slice(service);
    out
}

/// Build `SSH_MSG_CHANNEL_DATA` payload.
fn build_channel_data(channel: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 4 + data.len());
    out.push(SSH_MSG_CHANNEL_DATA);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Build `SSH_MSG_CHANNEL_SUCCESS` payload.
fn build_channel_success(channel: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(SSH_MSG_CHANNEL_SUCCESS);
    out.extend_from_slice(&channel.to_be_bytes());
    out
}

/// Build `SSH_MSG_CHANNEL_CLOSE` payload.
fn build_channel_close(channel: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(SSH_MSG_CHANNEL_CLOSE);
    out.extend_from_slice(&channel.to_be_bytes());
    out
}

/// Build `SSH_MSG_UNIMPLEMENTED` payload.
fn build_unimplemented(seq: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(SSH_MSG_UNIMPLEMENTED);
    out.extend_from_slice(&seq.to_be_bytes());
    out
}
