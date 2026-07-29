//! SSH session composition (Task 14): wires transport, key exchange, authentication, channel
//! management, the fake shell, and SCP/SFTP capture into a complete honeypot SSH server. The
//! entry point is `start_test_server`, which binds a listener, accepts connections, and spawns
//! a per-connection `handle_session` task. Each session performs the full SSH handshake using
//! this crate's own primitives (see ADR-0011), then dispatches channel data to the appropriate
//! handler.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use sensor_framework::{CaptureHandoff, EventEmitter, QuarantineSpool};

use crate::auth::AuthState;
use crate::channel::{ChannelAction, handle_channel_open, handle_channel_request};
use crate::fakefs::FakeFs;
use crate::hostkey::HostKey;
use crate::shell::{EmitContext, FakeShell};
use crate::transfer::{ScpReceiver, SftpHandler};
use crate::transport::cipher::TransportCipher;
use crate::transport::kex::perform_kex_server;
use crate::transport::{
    self, SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA, SSH_MSG_CHANNEL_EOF, SSH_MSG_CHANNEL_OPEN,
    SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_CHANNEL_WINDOW_ADJUST,
    SSH_MSG_DISCONNECT, SSH_MSG_IGNORE, SSH_MSG_NEWKEYS, SSH_MSG_SERVICE_ACCEPT,
    SSH_MSG_SERVICE_REQUEST, SSH_MSG_UNIMPLEMENTED, SSH_MSG_USERAUTH_REQUEST,
};

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
pub async fn start_test_server(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    host_key_path: PathBuf,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
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

    let listener = TcpListener::bind(addr).await?;
    let bound_addr = listener.local_addr()?;

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, peer_addr)) = listener.accept().await else {
                continue;
            };
            let host_key = host_key.clone();
            let emitter = emitter.clone();
            let handoff = handoff.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_session(stream, peer_addr, host_key, emitter, handoff).await
                {
                    tracing::debug!(error = %e, peer = %peer_addr, "SSH session ended");
                }
            });
        }
    });

    Ok((bound_addr, handle))
}

/// Handle one SSH connection end to end: version exchange, key exchange, authentication,
/// channel management, and data dispatch.
async fn handle_session(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    host_key: HostKey,
    emitter: Arc<EventEmitter>,
    handoff: Arc<CaptureHandoff>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ---- Phase 1: version exchange ----
    let (client_version, server_version) =
        transport::do_version_exchange_server(&mut stream).await?;

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

    let source_ip: IpAddr = peer_addr.ip();
    let mut auth_state = AuthState::new(source_ip, None);

    // Emit honeypot_connection (authenticated=false, pre-auth).
    let conn_event = auth_state.emit_connection_event();
    emitter.append(&conn_event).await?;

    // Per-channel state. Only one channel is typical, but we track by id.
    let mut channel_id: Option<u32> = None;
    let mut handler: ChannelHandler = ChannelHandler::Pending;

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
                            wan_ip: None,
                            authenticated: auth_state.is_authenticated(),
                        };
                        let shell = FakeShell::new(FakeFs::new(), ctx);
                        handler = ChannelHandler::Shell(shell, Vec::new());
                        // Send an initial prompt.
                        let prompt = b"root@server01:~# ";
                        let data_pkt = build_channel_data(ch_id, prompt);
                        write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &data_pkt)
                            .await?;
                    }
                    ChannelAction::Exec(cmd) => {
                        // Emit a command_exec event for the exec command itself.
                        let shell_ctx = EmitContext {
                            source_ip,
                            wan_ip: None,
                            authenticated: auth_state.is_authenticated(),
                        };
                        let mut shell = FakeShell::new(FakeFs::new(), shell_ctx);
                        let (output, events) = shell.handle_input(&cmd);
                        for event in &events {
                            emitter.append(event).await?;
                        }

                        if cmd.starts_with("scp -t ") {
                            // SCP server mode.
                            let (scp, initial) = ScpReceiver::new(source_ip, None, handoff.clone());
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
                            let sftp = SftpHandler::new(source_ip, None, handoff.clone());
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
                        let mut responses = Vec::new();
                        for &byte in data {
                            if byte == b'\n' || byte == b'\r' {
                                if !line_buf.is_empty() {
                                    let line = String::from_utf8_lossy(line_buf).to_string();
                                    line_buf.clear();
                                    let (output, events) = shell.handle_input(&line);
                                    for event in &events {
                                        let _ = emitter.append(event).await;
                                    }
                                    if !output.is_empty() {
                                        responses.extend_from_slice(output.as_bytes());
                                    }
                                    // Send next prompt.
                                    responses.extend_from_slice(b"root@server01:~# ");
                                }
                            } else {
                                line_buf.push(byte);
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

    Ok(())
}

// ---- Helpers ----

/// Write one encrypted packet and increment the sequence number.
async fn write_encrypted(
    stream: &mut TcpStream,
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
