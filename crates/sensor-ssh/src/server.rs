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

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use sensor_framework::listener::{normalize_dual_stack, run_tcp_listener};
use sensor_framework::{
    BudgetLimits, CAPTURE_REASON_EXEC_STDIN, CAPTURE_REASON_SHELL_STDIN, CaptureBody, CaptureEnd,
    CaptureHandoff, CaptureJob, CaptureMemoryBudget, CaptureSource, ConnectionBounds,
    ConnectionBudget, EgressState, EventEmitter, HeldEnd, HeldInput, InputMode, OutboxManifest,
    QuarantineSpool, StdinCaptures, UploadEnd, WanResolver, default_capture_budget_bytes,
    limits_from,
};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_MALWARE_UPLOAD, SampleRef, SensorEvent, WIRE_VERSION,
};

use crate::auth::AuthState;
use crate::channel::{
    CHANNEL_MAX_PACKET_SIZE, ChannelAction, build_channel_open_resource_shortage,
    handle_channel_open, handle_channel_request,
};
use crate::fakefs::FakeFs;
use crate::hostkey::HostKey;
use crate::shell::{CommandResult, EmitContext, FakeShell, LineStep, OutputFd, onlcr};
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

const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
const SSH_MSG_CHANNEL_FAILURE: u8 = 100;
const SSH_EXTENDED_DATA_STDERR: u32 = 1;
const MAX_CHANNELS_PER_CONNECTION: usize = 10;

/// The handler active on a given channel.
enum ChannelHandler {
    /// Awaiting a channel request to determine the handler type.
    Pending,
    /// Interactive fake shell with a line buffer for incremental input, and the input of a typed
    /// line that reads it (`cat > f` takes the lines after it until Ctrl-D). Boxed: the shell owns
    /// a whole filesystem snapshot and dwarfs the other variants, so an unboxed one would make
    /// every `ChannelHandler` that size.
    Shell(Box<FakeShell>, Vec<u8>, Option<HeldInput>),
    /// An exec command that reads its standard input, held until the input ends: the channel's
    /// EOF, its CLOSE, the capture ceiling, or the session's end. Commands that do not read it
    /// complete at the request and never get here.
    Exec(Box<FakeShell>, Option<HeldInput>),
    /// SCP server-mode file receiver.
    Scp(ScpReceiver),
    /// SFTP subsystem handler.
    Sftp(SftpHandler),
}

impl ChannelHandler {
    /// The channel is going away, ended by `end`: a file transfer still open on it is submitted
    /// as cut off by that, rather than by the `Cancelled` its `Drop` would have to assume, and a
    /// command still reading its input ends with what arrived, killed by the hangup.
    fn cut_off(&mut self, end: CaptureEnd) {
        match self {
            Self::Scp(scp) => scp.cut_off(end),
            Self::Sftp(sftp) => sftp.cut_off(end),
            Self::Shell(shell, _, held) | Self::Exec(shell, held) => {
                if let Some(input) = held.take() {
                    let _ = input.finish(shell, HeldEnd::Cut(end));
                }
            }
            Self::Pending => {}
        }
    }
}

struct ChannelState {
    handler: ChannelHandler,
    flow: ChannelFlow,
}

struct QueuedChannelData {
    fd: OutputFd,
    bytes: Vec<u8>,
    offset: usize,
}

struct ChannelFrame {
    packet: Vec<u8>,
    egress_bytes: usize,
}

/// Flow-control and lifecycle state for the currently open channel. The original server wrote a
/// whole reply as one SSH packet, which made a 2 MiB `/proc/self/exe` response invalid on the wire.
/// Keeping unsent bytes here lets the packet loop stop at the peer window and resume only after a
/// WINDOW_ADJUST arrives.
struct ChannelFlow {
    peer_window: u64,
    peer_max_packet: usize,
    local_consumed: u32,
    pty: bool,
    outbound: VecDeque<QueuedChannelData>,
    finish_status: Option<u8>,
    eof_pending: bool,
    close_pending: bool,
    close_sent: bool,
    drop_after_drain: bool,
}

impl ChannelFlow {
    fn new(peer_window: u32, peer_max_packet: u32) -> Self {
        Self {
            peer_window: u64::from(peer_window),
            peer_max_packet: usize::try_from(peer_max_packet)
                .unwrap_or(1)
                .clamp(1, CHANNEL_MAX_PACKET_SIZE as usize),
            local_consumed: 0,
            pty: false,
            outbound: VecDeque::new(),
            finish_status: None,
            eof_pending: false,
            close_pending: false,
            close_sent: false,
            drop_after_drain: false,
        }
    }

    fn queue(&mut self, fd: OutputFd, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.outbound.push_back(QueuedChannelData {
                fd,
                bytes,
                offset: 0,
            });
        }
    }

    /// Advance one pure flow-control transition. No socket or budget is touched here, which makes
    /// window exhaustion, packet chunking, stream selection and lifecycle ordering testable as a
    /// deterministic state machine.
    fn next_frame(&mut self, channel: u32) -> Option<ChannelFrame> {
        while self.peer_window > 0 {
            let Some(front) = self.outbound.front_mut() else {
                break;
            };
            let remaining = front.bytes.len().saturating_sub(front.offset);
            if remaining == 0 {
                self.outbound.pop_front();
                continue;
            }
            let take = remaining
                .min(self.peer_max_packet)
                .min(usize::try_from(self.peer_window).unwrap_or(usize::MAX));
            if take == 0 {
                break;
            }
            let end = front.offset.saturating_add(take);
            let bytes = &front.bytes[front.offset..end];
            let packet = if self.pty || front.fd == OutputFd::Stdout {
                build_channel_data(channel, bytes)
            } else {
                build_channel_extended_data(channel, SSH_EXTENDED_DATA_STDERR, bytes)
            };
            front.offset = end;
            self.peer_window = self.peer_window.saturating_sub(take as u64);
            if front.offset == front.bytes.len() {
                self.outbound.pop_front();
            }
            return Some(ChannelFrame {
                packet,
                egress_bytes: take,
            });
        }

        if !self.outbound.is_empty() {
            return None;
        }
        if let Some(status) = self.finish_status.take() {
            self.eof_pending = true;
            return Some(ChannelFrame {
                packet: build_exit_status(channel, status),
                egress_bytes: 0,
            });
        }
        if self.eof_pending {
            self.eof_pending = false;
            self.close_pending = true;
            return Some(ChannelFrame {
                packet: build_channel_eof(channel),
                egress_bytes: 0,
            });
        }
        if self.close_pending {
            self.close_pending = false;
            self.close_sent = true;
            return Some(ChannelFrame {
                packet: build_channel_close(channel),
                egress_bytes: 0,
            });
        }
        None
    }
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
///
/// `collector_id`/`outbox_dir` (SP-B-1b) are the two arguments `handle_session` below does not
/// need but the capture hand-off does - see `CaptureHandoff::new`'s doc for what they mean.
///
/// The capture memory budget is the default for this unit's `MemoryMax`
/// ([`DEFAULT_CAPTURE_BUDGET_BYTES`]); `serve_with_handoff` takes an explicit one.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    host_key_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    banner: String,
    collector_id: String,
    outbox_dir: PathBuf,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let (bound, handle, _handoff) = serve_with_handoff(
        addr,
        log_path,
        spool_dir,
        host_key_path,
        wan_resolver,
        bounds,
        banner,
        collector_id,
        outbox_dir,
        Arc::new(CaptureMemoryBudget::new(DEFAULT_CAPTURE_BUDGET_BYTES)),
    )
    .await?;
    Ok((bound, handle))
}

/// `MemoryMax` in `deploy/sensor-ssh.service`, which the default capture budget is derived from.
pub const UNIT_MEMORY_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// The capture memory ceiling used when none is configured: 40% of [`UNIT_MEMORY_MAX_BYTES`].
pub const DEFAULT_CAPTURE_BUDGET_BYTES: u64 = default_capture_budget_bytes(UNIT_MEMORY_MAX_BYTES);

/// `serve` plus the capture hand-off, so `main` can `drain` it on shutdown, and the process-wide
/// capture memory budget `main` built from its configured ceiling. A separate function rather than
/// a wider return type so the many callers that never shut down (every integration test) are
/// unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn serve_with_handoff(
    addr: SocketAddr,
    log_path: PathBuf,
    spool_dir: PathBuf,
    host_key_path: PathBuf,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
    banner: String,
    collector_id: String,
    outbox_dir: PathBuf,
    capture_budget: Arc<CaptureMemoryBudget>,
) -> Result<
    (SocketAddr, JoinHandle<()>, Arc<CaptureHandoff>),
    Box<dyn std::error::Error + Send + Sync>,
> {
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
    let outbox = OutboxManifest::new(outbox_dir);
    let handoff = Arc::new(CaptureHandoff::new(
        spool,
        EventEmitter::new(log_path),
        64,
        collector_id,
        outbox,
        capture_budget,
    ));
    handoff.start_worker();
    let drain_handle = handoff.clone();

    let read_timeout = bounds.read_timeout;
    let idle_timeout = bounds.idle_timeout;
    // Extracted before `bounds` is moved into `run_tcp_listener` below. This bounds only the
    // shell-channel evidence capture buffer (see `handle_session`'s Shell branch) - a separate,
    // much narrower ceiling than SCP/SFTP's own 10 MB per-file cap (see `transfer.rs` and
    // `timeout_stream.rs`'s module doc for why the two are not the same budget).
    let max_captured_bytes = bounds.max_captured_bytes;
    // Each connection builds its own budget from these limits: one ceiling for every shell and exec
    // channel it opens.
    let budget_limits = limits_from(&bounds);
    let per_source_cap = Some(sensor_framework::default_per_source_cap(
        bounds.max_concurrent,
    ));
    let (bound_addr, handle) = run_tcp_listener(
        addr,
        bounds,
        per_source_cap,
        move |stream, peer_addr, session_id| {
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
                    budget_limits,
                )
                .await
                {
                    tracing::debug!(error = %e, peer = %peer_addr, "SSH session ended");
                }
            }
        },
    )
    .await?;

    Ok((bound_addr, handle, drain_handle))
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
    budget_limits: BudgetLimits,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = std::time::Instant::now();
    // Normalize dual-stack mapped addresses before resolving WAN, so an IPv4-mapped
    // IPv6 address (::ffff:a.b.c.d from a dual-stack listener) matches the operator's
    // plain-IPv4 WAN map entry.
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let local_addr = stream.get_ref().local_addr().map(normalize_dual_stack).ok();
    let wan_ip = local_addr.and_then(|la| wan_resolver.resolve(la.ip()));
    let mut auth_state = AuthState::new(source_ip, wan_ip, session_id);

    // The accept is the observation: emitted before the version exchange so a scanner that reads
    // the banner and leaves, a client that sends garbage, and a bare TCP probe are recorded like
    // every other sensor's connect. Exactly once per connection; nothing later emits another.
    let conn_event = auth_state.emit_connection_event();
    emitter.append(&conn_event).await?;

    // Phases 1 and 2 run as a block so a connection that ends inside them still gets its end
    // event below, with the client version if it got that far.
    let mut handshake_phase = HandshakePhase::VersionExchange;
    let mut client_version_seen: Option<String> = None;
    let handshake: Result<_, transport::TransportError> = async {
        // ---- Phase 1: version exchange ----
        let (client_version, server_version) =
            transport::do_version_exchange_server_with_version(&mut stream, &banner).await?;
        client_version_seen = Some(client_version.clone());
        handshake_phase = HandshakePhase::KeyExchange;

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
            return Err(transport::TransportError::Malformed(
                "expected SSH_MSG_NEWKEYS",
            ));
        }
        Ok(session_keys)
    }
    .await;
    let session_keys = match handshake {
        Ok(keys) => keys,
        Err(e) => {
            let end = auth_state.handshake_end_event(
                classify_read_failure(&e),
                handshake_phase.label(),
                client_version_seen.as_deref(),
                started.elapsed(),
            );
            if let Err(append_err) = emitter.append(&end).await {
                tracing::error!(error = %append_err, "ssh: failed to append handshake end event");
            }
            return Err(e.into());
        }
    };

    // ---- Phase 3: encrypted transport ----

    // Create directional ciphers. c2s for reading client packets, s2c for writing.
    let mut c2s_cipher = session_keys.client_to_server_cipher();
    let mut s2c_cipher = session_keys.server_to_client_cipher();

    // Sequence numbers: 3 unencrypted packets sent/received per direction (KEXINIT,
    // ECDH_INIT/REPLY, NEWKEYS), so the first encrypted packet is seq 3.
    let mut c2s_seq: u32 = 3;
    let mut s2c_seq: u32 = 3;

    // The one budget of this connection, cloned into every shell it opens.
    let budget = ConnectionBudget::new(budget_limits);
    // The one filesystem of this connection: every shell and exec opens a share of it, so a file
    // written on one channel is readable on the next, and a new connection starts clean.
    let base_fs = FakeFs::new().with_budget(budget.clone());

    // RFC 4254 permits several channels on one connection. Keep their handlers and independent
    // flow-control windows separate, with a hard cap so OPEN floods cannot pin unbounded shells.
    let mut channels: HashMap<u32, ChannelState> = HashMap::new();

    // Raw shell-channel bytes accumulated for evidence capture, and whether the shared FakeShell
    // ever flagged one as a binary flood (see the Shell arm of SSH_MSG_CHANNEL_DATA below and the
    // submission after the packet loop). SSH authentication happens in USERAUTH_REQUEST packets,
    // never in channel data, so the shell channel - which exists only post-auth - can never carry
    // the login password; no phase-gating is needed here the way telnet's LineReader needs
    // `start_capture` to exclude its pre-auth login prompt.
    let mut shell_capture = ShellCapture {
        body: handoff.new_capture_body(),
        wire_bytes: 0,
        binary_seen: false,
        session_end: CaptureEnd::Cancelled,
        max_bytes: max_captured_bytes,
        handoff: handoff.clone(),
        source_ip,
        wan_ip,
        session_id,
    };

    // What commands on this connection read from their standard input: an exec channel's stream
    // up to its EOF, or lines typed at the shell after `cat > f`. Submitted when the last handle
    // goes, the held inputs' own included, so a cancelled session keeps them too.
    let stdin_captures = StdinCaptures::new(
        handoff.clone(),
        CaptureSource {
            sensor: "ssh",
            source_ip,
            wan_ip,
            session_id,
            authenticated: true,
        },
    );

    // ---- Main encrypted packet loop ----
    // Run as a block so that however the loop ends (clean close, read error, a failed write
    // propagating with `?`) the evidence held in `handler` and `shell_capture` is still
    // submitted below. A write error used to return straight out of this function and take a
    // half-received SCP or SFTP file with it.
    let loop_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
        loop {
            let payload =
                match transport::read_packet_encrypted(&mut stream, &mut c2s_cipher, c2s_seq).await
                {
                    Ok(p) => p,
                    // These are four different endings, and a capture cannot say whether its bytes
                    // are whole unless they stay apart. A closed connection means the peer finished
                    // sending; a timeout or a socket error means it did not.
                    Err(e) => {
                        shell_capture.mark_session_end(classify_read_failure(&e));
                        break;
                    }
                };
            c2s_seq = c2s_seq.wrapping_add(1);

            if payload.is_empty() {
                continue;
            }

            let msg_type = payload[0];

            match msg_type {
                SSH_MSG_DISCONNECT => {
                    shell_capture.mark_session_end(CaptureEnd::ClientLogout);
                    break;
                }
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
                    let opened = match handle_channel_open(&payload) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!(error = %e, "malformed channel open");
                            continue;
                        }
                    };
                    let response = if opened.accepted
                        && (channels.len() >= MAX_CHANNELS_PER_CONNECTION
                            || channels.contains_key(&opened.recipient_channel))
                    {
                        build_channel_open_resource_shortage(opened.recipient_channel)
                    } else {
                        opened.response
                    };
                    let accepted = opened.accepted
                        && channels.len() < MAX_CHANNELS_PER_CONNECTION
                        && !channels.contains_key(&opened.recipient_channel);
                    write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &response).await?;
                    if accepted {
                        channels.insert(
                            opened.recipient_channel,
                            ChannelState {
                                handler: ChannelHandler::Pending,
                                flow: ChannelFlow::new(opened.peer_window, opened.peer_max_packet),
                            },
                        );
                    }
                }

                SSH_MSG_CHANNEL_REQUEST => {
                    let Some(ch_id) = channel_recipient(&payload, SSH_MSG_CHANNEL_REQUEST) else {
                        continue;
                    };
                    let Some(state) = channels.get_mut(&ch_id) else {
                        continue;
                    };
                    let request = match handle_channel_request(&payload, ch_id) {
                        Ok(a) => a,
                        Err(e) => {
                            tracing::debug!(error = %e, "malformed channel request");
                            continue;
                        }
                    };

                    let accepted = match &request.action {
                        ChannelAction::PtyReq => {
                            matches!(state.handler, ChannelHandler::Pending)
                                && !state.flow.close_sent
                        }
                        ChannelAction::Shell | ChannelAction::Exec(_) => {
                            matches!(state.handler, ChannelHandler::Pending)
                                && !state.flow.close_sent
                        }
                        ChannelAction::Subsystem(name) => {
                            name == "sftp"
                                && matches!(state.handler, ChannelHandler::Pending)
                                && !state.flow.close_sent
                        }
                        ChannelAction::Other => false,
                    };
                    if request.want_reply {
                        let response = if accepted {
                            build_channel_success(ch_id)
                        } else {
                            build_channel_failure(ch_id)
                        };
                        write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &response)
                            .await?;
                    }

                    if !accepted {
                        continue;
                    }

                    match request.action {
                        ChannelAction::PtyReq => {
                            state.flow.pty = true;
                        }
                        ChannelAction::Shell => {
                            let ctx = EmitContext {
                                source_ip,
                                wan_ip,
                                authenticated: auth_state.is_authenticated(),
                                protocol_label: "ssh".to_string(),
                                session_id: Some(session_id),
                            };
                            let shell = FakeShell::new(base_fs.share(), ctx)
                                .with_budget(budget.clone())
                                .with_captures(stdin_captures.clone());
                            let prompt = shell.prompt();
                            state.handler =
                                ChannelHandler::Shell(Box::new(shell), Vec::new(), None);
                            if state.flow.pty {
                                state.flow.queue(OutputFd::Stdout, prompt.into_bytes());
                                flush_channel_output(
                                    &mut stream,
                                    &mut s2c_cipher,
                                    &mut s2c_seq,
                                    ch_id,
                                    &mut state.flow,
                                    &budget,
                                )
                                .await?;
                            }
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
                            let mut shell = FakeShell::exec(base_fs.share(), shell_ctx)
                                .with_budget(budget.clone())
                                .with_terminal_input(state.flow.pty)
                                .with_captures(stdin_captures.clone());
                            let is_scp = cmd.starts_with("scp -t ");
                            // The shell decides whether the command reads its standard input (see
                            // `FakeShell::start_line`); scp's input is the transfer, read below.
                            let (step, events) = if is_scp {
                                let (output, events) = shell.handle_input(&cmd);
                                (LineStep::Ran(output), events)
                            } else {
                                shell.start_line(&cmd)
                            };
                            for event in &events {
                                emitter.append(event).await?;
                            }

                            if is_scp {
                                // SCP server mode.
                                let (scp, initial) = ScpReceiver::new(
                                    source_ip,
                                    wan_ip,
                                    session_id,
                                    handoff.clone(),
                                    base_fs.share(),
                                    &cmd,
                                );
                                state.handler = ChannelHandler::Scp(scp);
                                state.flow.queue(OutputFd::Stdout, initial);
                                flush_channel_output(
                                    &mut stream,
                                    &mut s2c_cipher,
                                    &mut s2c_seq,
                                    ch_id,
                                    &mut state.flow,
                                    &budget,
                                )
                                .await?;
                            } else {
                                match step {
                                    LineStep::Ran(output) => {
                                        // One-shot exec: queue stream-aware output, then exit-status,
                                        // EOF and CLOSE. Large output remains queued until the peer
                                        // replenishes its window instead of being emitted as one
                                        // invalid SSH packet.
                                        finish_exec(&mut state.flow, output);
                                        flush_channel_output(
                                            &mut stream,
                                            &mut s2c_cipher,
                                            &mut s2c_seq,
                                            ch_id,
                                            &mut state.flow,
                                            &budget,
                                        )
                                        .await?;
                                    }
                                    LineStep::AwaitingInput => {
                                        // Nothing is sent: the channel stays open, as it does while a
                                        // real command waits in `read`, and the data the client sends
                                        // next is the command's input.
                                        let mode = if state.flow.pty {
                                            InputMode::Terminal
                                        } else {
                                            InputMode::Pipe
                                        };
                                        let input = HeldInput::new(
                                            &shell,
                                            mode,
                                            &stdin_captures,
                                            CAPTURE_REASON_EXEC_STDIN,
                                            max_captured_bytes,
                                        );
                                        state.handler =
                                            ChannelHandler::Exec(Box::new(shell), Some(input));
                                    }
                                }
                            }
                        }
                        ChannelAction::Subsystem(name) => {
                            if name == "sftp" {
                                let sftp = SftpHandler::new(
                                    source_ip,
                                    wan_ip,
                                    session_id,
                                    handoff.clone(),
                                    base_fs.share(),
                                );
                                state.handler = ChannelHandler::Sftp(sftp);
                            }
                        }
                        ChannelAction::Other => {}
                    }
                }

                SSH_MSG_CHANNEL_DATA => {
                    // Parse: byte(94) + uint32(channel) + string(data)
                    if payload.len() < 9 {
                        continue;
                    }
                    let ch_id = u32::from_be_bytes(payload[1..5].try_into().unwrap());
                    let Some(state) = channels.get_mut(&ch_id) else {
                        continue;
                    };
                    if state.flow.close_sent {
                        continue;
                    }
                    let data_len = u32::from_be_bytes(payload[5..9].try_into().unwrap()) as usize;
                    if data_len > CHANNEL_MAX_PACKET_SIZE as usize || payload.len() < 9 + data_len {
                        continue;
                    }
                    let data = &payload[9..9 + data_len];
                    let pty = state.flow.pty;
                    let mut nonpty_segments = Vec::new();

                    match &mut state.handler {
                        ChannelHandler::Shell(shell, line_buf, held) => {
                            // A real interactive session runs the client terminal in raw mode and relies
                            // on the SERVER to echo keystrokes. Without that echo the attacker types into
                            // a blank screen and the session looks frozen (and no-echo is itself a tell,
                            // since every real shell echoes). So each printable byte is echoed as it
                            // arrives, backspace erases on screen, and Enter echoes CR-LF and shows a
                            // fresh prompt - even for an empty line, as a real shell does.
                            //
                            // While a typed line waits for its input (`cat > f`), the bytes are that
                            // command's, until the input ends (Ctrl-D, Ctrl-C), and the rest of the
                            // packet is the shell's again.
                            let mut responses = Vec::new();
                            // The bytes the shell itself was typed, kept as evidence in case they turn
                            // out to be a binary flood. Input a held command consumed is captured as
                            // that command's input instead, so no byte is captured twice.
                            let mut typed = Vec::new();
                            let mut prev_cr = false;
                            let mut close_shell = false;
                            let mut at = 0;
                            while at < data.len() && !close_shell {
                                if let Some(input) = held.as_mut() {
                                    let fed = input.feed(&data[at..]);
                                    at += fed.taken;
                                    if pty {
                                        responses.extend_from_slice(&fed.echo);
                                    }
                                    if let Some(end) = fed.ended
                                        && let Some(input) = held.take()
                                    {
                                        let output = input.finish(shell, end);
                                        close_shell = deliver_output(
                                            output,
                                            pty,
                                            &mut responses,
                                            &mut nonpty_segments,
                                        );
                                        if !close_shell && pty {
                                            responses.extend_from_slice(shell.prompt().as_bytes());
                                        }
                                    }
                                    continue;
                                }
                                let byte = data[at];
                                at += 1;
                                typed.push(byte);
                                match byte {
                                    b'\r' | b'\n' => {
                                        // Swallow the LF of a CR-LF pair so Enter is one line, not two.
                                        if byte == b'\n' && prev_cr {
                                            prev_cr = false;
                                            continue;
                                        }
                                        prev_cr = byte == b'\r';
                                        if pty {
                                            responses.extend_from_slice(b"\r\n");
                                        }
                                        if !line_buf.is_empty() {
                                            let line =
                                                String::from_utf8_lossy(line_buf).to_string();
                                            line_buf.clear();
                                            match run_typed_line(
                                                shell,
                                                &line,
                                                held,
                                                prev_cr,
                                                pty,
                                                &stdin_captures,
                                                max_captured_bytes,
                                                &emitter,
                                                &mut shell_capture,
                                                peer_addr,
                                            )
                                            .await
                                            {
                                                Some(output) => {
                                                    close_shell = deliver_output(
                                                        output,
                                                        pty,
                                                        &mut responses,
                                                        &mut nonpty_segments,
                                                    );
                                                }
                                                // The held input took over the rest of this
                                                // Enter. The prompt comes back when the command
                                                // ends.
                                                None => {
                                                    prev_cr = false;
                                                    continue;
                                                }
                                            }
                                        }
                                        if close_shell {
                                            break;
                                        }
                                        if pty {
                                            responses.extend_from_slice(shell.prompt().as_bytes());
                                        }
                                    }
                                    // Backspace / DEL: erase the last char on screen too.
                                    0x7f | 0x08 => {
                                        prev_cr = false;
                                        if line_buf.pop().is_some() && pty {
                                            responses.extend_from_slice(b"\x08 \x08");
                                        }
                                    }
                                    // Printable byte: buffer and echo it.
                                    b if b >= 0x20 => {
                                        prev_cr = false;
                                        line_buf.push(b);
                                        if pty {
                                            responses.push(b);
                                        }
                                        // Flush a too-long line so a stream of non-newline bytes cannot
                                        // grow memory without bound.
                                        if line_buf.len() >= MAX_LINE_LEN {
                                            let line =
                                                String::from_utf8_lossy(line_buf).to_string();
                                            line_buf.clear();
                                            if let Some(output) = run_typed_line(
                                                shell,
                                                &line,
                                                held,
                                                false,
                                                pty,
                                                &stdin_captures,
                                                max_captured_bytes,
                                                &emitter,
                                                &mut shell_capture,
                                                peer_addr,
                                            )
                                            .await
                                            {
                                                close_shell = output.close_session;
                                            }
                                        }
                                    }
                                    // Other control bytes (tab, Ctrl-*, escape sequences): consume
                                    // without echo, matching a shell in a minimal cooked-ish mode.
                                    _ => prev_cr = false,
                                }
                            }
                            // Bounded so a captured session can never grow past `max_captured_bytes`,
                            // the operator-configured ceiling this crate's own `ConnectionBounds`
                            // defines. Whether the buffer is ever submitted depends on `binary_seen`,
                            // set when the shared FakeShell flags a binary flood; a plaintext-only
                            // session accumulates here but the buffer is discarded, never spooled,
                            // once the loop ends.
                            shell_capture.push(&typed);
                            state.flow.queue(OutputFd::Stdout, responses);
                            for segment in nonpty_segments {
                                state.flow.queue(segment.fd, segment.bytes);
                            }
                            if close_shell {
                                state.flow.finish_status = Some(0);
                            }
                            flush_channel_output(
                                &mut stream,
                                &mut s2c_cipher,
                                &mut s2c_seq,
                                ch_id,
                                &mut state.flow,
                                &budget,
                            )
                            .await?;
                        }
                        ChannelHandler::Exec(shell, held) => {
                            if let Some(input) = held.as_mut() {
                                let fed = input.feed(data);
                                state.flow.queue(OutputFd::Stdout, fed.echo);
                                if let Some(end) = fed.ended
                                    && let Some(input) = held.take()
                                {
                                    finish_exec(&mut state.flow, input.finish(shell, end));
                                }
                                flush_channel_output(
                                    &mut stream,
                                    &mut s2c_cipher,
                                    &mut s2c_seq,
                                    ch_id,
                                    &mut state.flow,
                                    &budget,
                                )
                                .await?;
                            }
                        }
                        ChannelHandler::Scp(scp) => {
                            let response = scp.feed(data);
                            state.flow.queue(OutputFd::Stdout, response);
                            flush_channel_output(
                                &mut stream,
                                &mut s2c_cipher,
                                &mut s2c_seq,
                                ch_id,
                                &mut state.flow,
                                &budget,
                            )
                            .await?;
                        }
                        ChannelHandler::Sftp(sftp) => {
                            let response = sftp.feed(data);
                            state.flow.queue(OutputFd::Stdout, response);
                            flush_channel_output(
                                &mut stream,
                                &mut s2c_cipher,
                                &mut s2c_seq,
                                ch_id,
                                &mut state.flow,
                                &budget,
                            )
                            .await?;
                        }
                        ChannelHandler::Pending => {}
                    }
                    state.flow.local_consumed =
                        state.flow.local_consumed.saturating_add(data_len as u32);
                    if state.flow.local_consumed >= crate::channel::INITIAL_WINDOW_SIZE / 2 {
                        let adjust = build_channel_window_adjust(ch_id, state.flow.local_consumed);
                        write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &adjust)
                            .await?;
                        state.flow.local_consumed = 0;
                    }
                }

                SSH_MSG_CHANNEL_WINDOW_ADJUST => {
                    if payload.len() >= 9 {
                        let ch_id = u32::from_be_bytes(payload[1..5].try_into().unwrap());
                        let Some(state) = channels.get_mut(&ch_id) else {
                            continue;
                        };
                        let add = u32::from_be_bytes(payload[5..9].try_into().unwrap());
                        state.flow.peer_window =
                            state.flow.peer_window.saturating_add(u64::from(add));
                        flush_channel_output(
                            &mut stream,
                            &mut s2c_cipher,
                            &mut s2c_seq,
                            ch_id,
                            &mut state.flow,
                            &budget,
                        )
                        .await?;
                    }
                }

                SSH_MSG_CHANNEL_EOF => {
                    // Half-close: the peer will send no more channel data, but queued server output
                    // and the channel's own EOF/CLOSE lifecycle still have to drain. A command still
                    // reading its input sees end of file now, runs to its end and the channel closes
                    // with its exit status, as `cat > f` does when its stdin pipe closes.
                    let Some(ch_id) = channel_recipient(&payload, SSH_MSG_CHANNEL_EOF) else {
                        continue;
                    };
                    let Some(state) = channels.get_mut(&ch_id) else {
                        continue;
                    };
                    let pty = state.flow.pty;
                    let mut nonpty_segments = Vec::new();
                    match &mut state.handler {
                        ChannelHandler::Exec(shell, held) => {
                            if let Some(input) = held.take() {
                                finish_exec(&mut state.flow, input.finish(shell, HeldEnd::Eof));
                            }
                        }
                        ChannelHandler::Shell(shell, _, held) => {
                            if let Some(input) = held.take() {
                                let output = input.finish(shell, HeldEnd::Eof);
                                let mut responses = Vec::new();
                                let close_shell = deliver_output(
                                    output,
                                    pty,
                                    &mut responses,
                                    &mut nonpty_segments,
                                );
                                if !close_shell && pty {
                                    responses.extend_from_slice(shell.prompt().as_bytes());
                                }
                                state.flow.queue(OutputFd::Stdout, responses);
                                for segment in nonpty_segments {
                                    state.flow.queue(segment.fd, segment.bytes);
                                }
                                if close_shell {
                                    state.flow.finish_status = Some(0);
                                }
                            }
                        }
                        ChannelHandler::Pending
                        | ChannelHandler::Scp(_)
                        | ChannelHandler::Sftp(_) => {}
                    }
                    flush_channel_output(
                        &mut stream,
                        &mut s2c_cipher,
                        &mut s2c_seq,
                        ch_id,
                        &mut state.flow,
                        &budget,
                    )
                    .await?;
                }

                SSH_MSG_CHANNEL_CLOSE => {
                    let Some(ch_id) = channel_recipient(&payload, SSH_MSG_CHANNEL_CLOSE) else {
                        continue;
                    };
                    if let Some(mut state) = channels.remove(&ch_id) {
                        // The peer closed this channel itself, whatever later becomes of the session.
                        state.handler.cut_off(CaptureEnd::PeerClosed);
                        if !state.flow.close_sent {
                            let close = build_channel_close(ch_id);
                            let _ =
                                write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &close)
                                    .await;
                        }
                    }
                }

                _ => {
                    // Send UNIMPLEMENTED for anything we do not handle.
                    let unimpl = build_unimplemented(c2s_seq.wrapping_sub(1));
                    let _ =
                        write_encrypted(&mut stream, &mut s2c_cipher, &mut s2c_seq, &unimpl).await;
                }
            }
        }
        Ok(())
    }
    .await;

    // A binary payload was seen somewhere in the shell phase (a Mirai/Gafgyt dropper streamed
    // over the "shell" - never a real interactive command, since FakeShell's binary-flood
    // detector only trips on a line that is mostly non-printable). Preserve the raw bytes as
    // evidence, reusing the same handoff SCP/SFTP already submit through. Plaintext-only sessions
    // never set `binary_seen`, so ordinary interactive commands are never spooled.
    // Each `break` above named its own ending, because they do not mean the same thing. What is
    // left here is the error path: a write that failed, or any other `?` out of the loop, which
    // cut the session with a payload still arriving.
    if loop_result.is_err() {
        shell_capture.mark_session_end(CaptureEnd::TransportError);
    }

    // A transfer still open when the session ends is kept as an incomplete capture cut off by
    // that ending. When the listener cancels this future at `max_duration` none of this runs, and
    // the SCP and SFTP handlers' `Drop` submits it as cancelled instead (see `transfer.rs`).
    for state in channels.values_mut() {
        state.handler.cut_off(shell_capture.session_end);
    }
    // A file a shell saw assembled from typed `echo` chunks and never ran is captured as the
    // session leaves it, ended this way.
    stdin_captures.end_session(shell_capture.session_end);

    loop_result
}

/// The raw shell-channel bytes of one session, submitted from `Drop`.
///
/// It has to be a guard rather than a local buffer flushed after the packet loop: the listener
/// enforces `max_duration` by dropping this handler's future, so nothing written after the loop
/// runs for a session that hits the bound - and a dropper streaming a payload over the shell
/// channel is exactly the long session that does. `CaptureHandoff::submit` never blocks, so
/// submitting from a destructor is safe.
struct ShellCapture {
    body: CaptureBody,
    /// Channel bytes the client sent, retained or dropped past the ceiling, so the event can
    /// report the real size and whether the stored copy is a prefix.
    wire_bytes: u64,
    /// Set when the shared FakeShell flags a binary flood. A plaintext session is never spooled.
    binary_seen: bool,
    /// How the session ended, set at the exit path that ended it. Starts `Cancelled` because that
    /// is the one ending no code can record: the listener drops this whole future at
    /// `max_duration`. Only a peer-chosen end makes the capture complete - see `CaptureEnd`.
    session_end: CaptureEnd,
    max_bytes: u64,
    handoff: Arc<CaptureHandoff>,
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: sensor_framework::Uuid,
}

impl ShellCapture {
    /// Accumulate raw channel bytes, bounded by the operator-configured session ceiling. Bytes
    /// past it are counted but not kept, so `truncated` and the real size stay honest.
    fn push(&mut self, data: &[u8]) {
        self.wire_bytes += data.len() as u64;
        let room = self.max_bytes.saturating_sub(self.body.len() as u64) as usize;
        if room > 0 {
            // A refusal keeps the prefix already held; the body remembers it was cut, and the
            // hand-off marks the capture truncated. The session itself carries on regardless.
            let _ = self.body.extend_from_slice(&data[..data.len().min(room)]);
        }
    }

    fn flag_binary(&mut self) {
        self.binary_seen = true;
    }

    /// Record how the session ended. Called at the exit path that ended it, never after the loop:
    /// a peer's DISCONNECT and a mid-transfer socket error both end the loop, and the whole point
    /// of the distinction is that they leave different evidence.
    fn mark_session_end(&mut self, end: CaptureEnd) {
        self.session_end = end;
    }
}

impl Drop for ShellCapture {
    fn drop(&mut self) {
        // An empty body that was starved by the budget still goes to `submit`, which counts it as
        // a refusal; a merely empty one has nothing to report.
        if self.body.is_empty() && !self.body.is_exhausted() {
            return;
        }
        // The flood flag is only raised once a complete line reached the shell, so a payload
        // still mid-line when the session was cancelled never got one. The bytes themselves are
        // the fallback test; without it that capture reads as ordinary typing and is discarded.
        if !self.binary_seen && !sensor_framework::shell::looks_binary(self.body.as_slice()) {
            return;
        }
        let body = std::mem::replace(&mut self.body, self.handoff.new_capture_body());
        let (wire_size, end) = (self.wire_bytes, self.session_end);
        let (source_ip, wan_ip, session_id) = (self.source_ip, self.wan_ip, self.session_id);
        let _ = self.handoff.submit(CaptureJob {
            body,
            orig_name: format!("ssh-session-{session_id}"),
            event_builder: Box::new(move |sample: SampleRef| SensorEvent {
                v: WIRE_VERSION,
                source_ip,
                wan_ip,
                sensor: "ssh".into(),
                signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
                protocol: PROTO_TCP.into(),
                authenticated: true,
                observed_at: chrono::Utc::now(),
                // Through `upload_metadata` like every other capture, so this one also carries
                // size, wire_size, truncated, complete and end_reason. Hand-rolling the object
                // here left `complete` absent, and the console reads a missing `complete` as true
                // - so a fragment from a cancelled session displayed as a whole sample.
                metadata: {
                    let mut m = sensor_framework::upload_metadata(
                        "ssh",
                        &sample,
                        wire_size,
                        UploadEnd::Session(end),
                    );
                    m["capture_reason"] = serde_json::json!("binary_shell_payload");
                    m
                },
                sample: Some(sample),
                session_id: Some(session_id),
                occurrence_id: None,
            }),
        });
    }
}

// ---- Helpers ----

/// Queue an exec command's output, then its exit status, which the flow follows with EOF and
/// CLOSE once the output has drained.
fn finish_exec(flow: &mut ChannelFlow, output: CommandResult) {
    let pty = flow.pty;
    for segment in output.output {
        let bytes = if pty {
            onlcr(&segment.bytes)
        } else {
            segment.bytes
        };
        flow.queue(segment.fd, bytes);
    }
    flow.finish_status = Some(output.status);
}

/// Add what an interactive line printed to the reply: one CR-LF-translated stream on a pty,
/// whose client terminal is in raw mode and would otherwise render each line indented, or the
/// separate streams without one. Returns whether the line ended the session.
fn deliver_output(
    output: CommandResult,
    pty: bool,
    responses: &mut Vec<u8>,
    segments: &mut Vec<crate::shell::OutputSegment>,
) -> bool {
    if pty {
        responses.extend_from_slice(&onlcr(output.bytes()));
    } else {
        segments.extend(output.output.iter().cloned());
    }
    output.close_session
}

/// Run one line typed at an interactive shell and append its events. Returns what it printed,
/// or `None` when it waits for its input (see `FakeShell::start_line`), which `held` then
/// collects. `after_cr` says the line ended with a CR, so an LF right after it is not input.
#[allow(clippy::too_many_arguments)]
async fn run_typed_line(
    shell: &mut FakeShell,
    line: &str,
    held: &mut Option<HeldInput>,
    after_cr: bool,
    pty: bool,
    stdin_captures: &StdinCaptures,
    max_captured_bytes: u64,
    emitter: &EventEmitter,
    shell_capture: &mut ShellCapture,
    peer_addr: SocketAddr,
) -> Option<CommandResult> {
    let (step, events) = shell.start_line(line);
    for event in &events {
        if event.metadata.get("flood").and_then(|v| v.as_str()) == Some("binary") {
            shell_capture.flag_binary();
        }
        if emitter.append(event).await.is_err() {
            tracing::error!(%peer_addr, "ssh: failed to append command event");
        }
    }
    match step {
        LineStep::Ran(output) => Some(output),
        LineStep::AwaitingInput => {
            let mode = if pty {
                InputMode::Terminal
            } else {
                InputMode::Pipe
            };
            let mut input = HeldInput::new(
                shell,
                mode,
                stdin_captures,
                CAPTURE_REASON_SHELL_STDIN,
                max_captured_bytes,
            );
            if after_cr {
                input.follow_cr();
            }
            *held = Some(input);
            None
        }
    }
}

/// Where in the pre-encryption handshake a connection was when it ended, recorded as the `phase`
/// of its `honeypot_session_end` event.
#[derive(Clone, Copy)]
enum HandshakePhase {
    VersionExchange,
    KeyExchange,
}

impl HandshakePhase {
    fn label(self) -> &'static str {
        match self {
            Self::VersionExchange => "version_exchange",
            Self::KeyExchange => "key_exchange",
        }
    }
}

/// What a failed packet read says about the session's ending. `read_exact` on a socket the peer
/// closed reports `UnexpectedEof`, which is the peer finishing rather than anything going wrong;
/// `TimeoutStream` reports an elapsed `idle_timeout` as `TimedOut`; and a packet this transport
/// cannot parse is the peer sending garbage, not a transport fault.
fn classify_read_failure(err: &transport::TransportError) -> CaptureEnd {
    match err {
        transport::TransportError::Io(e) => match e.kind() {
            std::io::ErrorKind::UnexpectedEof => CaptureEnd::PeerClosed,
            std::io::ErrorKind::TimedOut => CaptureEnd::IdleTimeout,
            _ => CaptureEnd::TransportError,
        },
        transport::TransportError::TooLarge { .. }
        | transport::TransportError::Malformed(_)
        | transport::TransportError::InvalidEncoding(_) => CaptureEnd::MalformedInput,
    }
}

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

fn channel_recipient(payload: &[u8], expected_type: u8) -> Option<u32> {
    if payload.len() < 5 || payload[0] != expected_type {
        return None;
    }
    Some(u32::from_be_bytes(payload[1..5].try_into().ok()?))
}

async fn flush_channel_output(
    stream: &mut TimeoutStream<TcpStream>,
    cipher: &mut TransportCipher,
    seq: &mut u32,
    channel: u32,
    flow: &mut ChannelFlow,
    budget: &ConnectionBudget,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    while let Some(frame) = flow.next_frame(channel) {
        write_encrypted(stream, cipher, seq, &frame.packet).await?;
        if frame.egress_bytes > 0
            && budget.charge_egress(frame.egress_bytes as u64) == EgressState::Spent
        {
            flow.drop_after_drain = true;
        }
    }
    if flow.drop_after_drain && flow.outbound.is_empty() {
        return Err("SSH connection egress budget spent".into());
    }
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

fn build_channel_extended_data(channel: u32, data_type: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + data.len());
    out.push(SSH_MSG_CHANNEL_EXTENDED_DATA);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&data_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn build_channel_window_adjust(channel: u32, bytes: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(SSH_MSG_CHANNEL_WINDOW_ADJUST);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&bytes.to_be_bytes());
    out
}

fn build_exit_status(channel: u32, status: u8) -> Vec<u8> {
    let request = b"exit-status";
    let mut out = Vec::with_capacity(1 + 4 + 4 + request.len() + 1 + 4);
    out.push(SSH_MSG_CHANNEL_REQUEST);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(request.len() as u32).to_be_bytes());
    out.extend_from_slice(request);
    out.push(0); // want_reply = false
    out.extend_from_slice(&u32::from(status).to_be_bytes());
    out
}

fn build_channel_eof(channel: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(SSH_MSG_CHANNEL_EOF);
    out.extend_from_slice(&channel.to_be_bytes());
    out
}

/// Build `SSH_MSG_CHANNEL_SUCCESS` payload.
fn build_channel_success(channel: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(SSH_MSG_CHANNEL_SUCCESS);
    out.extend_from_slice(&channel.to_be_bytes());
    out
}

fn build_channel_failure(channel: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    out.push(SSH_MSG_CHANNEL_FAILURE);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-off with one queue slot and no worker: a second `submit` is refused, which is how
    /// these tests prove the first one happened.
    fn one_slot_handoff() -> Arc<CaptureHandoff> {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let outbox_dir = dir.path().join("outbox");
        let spool = QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000);
        let emitter = EventEmitter::new(dir.path().join("events.jsonl"));
        std::mem::forget(dir);
        Arc::new(CaptureHandoff::new(
            spool,
            emitter,
            1,
            "test".to_string(),
            OutboxManifest::new(outbox_dir),
            Arc::new(CaptureMemoryBudget::new(u64::MAX)),
        ))
    }

    fn probe_job() -> CaptureJob {
        let mut body = CaptureBody::unbudgeted();
        body.extend_from_slice(&[1]).unwrap();
        CaptureJob {
            body,
            orig_name: "probe".into(),
            event_builder: Box::new(|_sample| unreachable!("never built")),
        }
    }

    fn capture(handoff: Arc<CaptureHandoff>) -> ShellCapture {
        ShellCapture {
            body: handoff.new_capture_body(),
            wire_bytes: 0,
            binary_seen: false,
            session_end: CaptureEnd::Cancelled,
            max_bytes: 65_536,
            handoff,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            session_id: sensor_framework::Uuid::now_v7(),
        }
    }

    #[test]
    fn channel_flow_chunks_at_both_limits_and_orders_exec_lifecycle() {
        let mut flow = ChannelFlow::new(5, 3);
        flow.queue(OutputFd::Stdout, b"abcdef".to_vec());
        flow.finish_status = Some(7);

        let first = flow.next_frame(9).unwrap();
        assert_eq!(first.packet[0], SSH_MSG_CHANNEL_DATA);
        assert_eq!(&first.packet[9..], b"abc");
        let second = flow.next_frame(9).unwrap();
        assert_eq!(&second.packet[9..], b"de");
        assert!(flow.next_frame(9).is_none(), "peer window is exhausted");

        flow.peer_window += 4;
        assert_eq!(&flow.next_frame(9).unwrap().packet[9..], b"f");
        let status = flow.next_frame(9).unwrap().packet;
        assert_eq!(status[0], SSH_MSG_CHANNEL_REQUEST);
        assert!(
            status
                .windows(b"exit-status".len())
                .any(|w| w == b"exit-status")
        );
        assert_eq!(flow.next_frame(9).unwrap().packet[0], SSH_MSG_CHANNEL_EOF);
        assert_eq!(flow.next_frame(9).unwrap().packet[0], SSH_MSG_CHANNEL_CLOSE);
        assert!(flow.close_sent);
        assert!(flow.next_frame(9).is_none());
    }

    #[test]
    fn channel_flow_separates_stderr_without_a_pty_and_merges_it_with_one() {
        let mut plain = ChannelFlow::new(100, 100);
        plain.queue(OutputFd::Stderr, b"err".to_vec());
        let frame = plain.next_frame(2).unwrap();
        assert_eq!(frame.packet[0], SSH_MSG_CHANNEL_EXTENDED_DATA);
        assert_eq!(
            u32::from_be_bytes(frame.packet[5..9].try_into().unwrap()),
            1
        );
        assert_eq!(&frame.packet[13..], b"err");

        let mut pty = ChannelFlow::new(100, 100);
        pty.pty = true;
        pty.queue(OutputFd::Stderr, b"err".to_vec());
        let frame = pty.next_frame(2).unwrap();
        assert_eq!(frame.packet[0], SSH_MSG_CHANNEL_DATA);
        assert_eq!(&frame.packet[9..], b"err");
    }

    /// The read that ends an SSH session fails whether the peer closed cleanly, stalled, or sent
    /// garbage, and the capture's completeness turns on telling those apart. The end-to-end tests
    /// drive the timeout and the explicit DISCONNECT; these are the branches a client cannot
    /// easily produce on demand. `UnexpectedEof` is the one that reads backwards: it is an error
    /// type, but it means the peer finished and hung up.
    #[test]
    fn a_failed_read_says_whether_the_peer_finished_or_the_session_broke() {
        use std::io::{Error, ErrorKind};
        let io = |kind| transport::TransportError::Io(Error::new(kind, "test"));

        assert_eq!(
            classify_read_failure(&io(ErrorKind::UnexpectedEof)),
            CaptureEnd::PeerClosed
        );
        assert_eq!(
            classify_read_failure(&io(ErrorKind::TimedOut)),
            CaptureEnd::IdleTimeout
        );
        assert_eq!(
            classify_read_failure(&io(ErrorKind::ConnectionReset)),
            CaptureEnd::TransportError
        );
        assert_eq!(
            classify_read_failure(&transport::TransportError::Malformed("bad padding")),
            CaptureEnd::MalformedInput
        );
        assert_eq!(
            classify_read_failure(&transport::TransportError::TooLarge {
                claimed: 1 << 30,
                max: 65536
            }),
            CaptureEnd::MalformedInput
        );

        assert!(CaptureEnd::PeerClosed.is_complete());
        for cut_short in [
            CaptureEnd::IdleTimeout,
            CaptureEnd::TransportError,
            CaptureEnd::MalformedInput,
            CaptureEnd::Cancelled,
            CaptureEnd::CaptureBudget,
        ] {
            assert!(!cut_short.is_complete(), "{cut_short:?}");
        }
    }

    /// The listener enforces `max_duration` by dropping this handler's future, so the submit
    /// that used to sit after the packet loop never ran for a session that hit the bound - and a
    /// dropper streaming a payload over the shell channel is exactly the long session that does.
    #[tokio::test]
    async fn the_binary_shell_capture_survives_a_cancelled_session() {
        let handoff = one_slot_handoff();
        let mut shell_capture = capture(handoff.clone());
        shell_capture.push(b"\x7fELF-payload-bytes");
        shell_capture.flag_binary();

        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(10), async move {
            let _held = &shell_capture;
            std::future::pending::<()>().await;
        })
        .await;
        assert!(
            cancelled.is_err(),
            "the future was cancelled, not completed"
        );
        assert!(
            handoff.submit(probe_job()).is_err(),
            "the one slot holds the capture the cancelled session had accumulated"
        );
    }

    /// A shell capture the budget starved to zero bytes is a refusal the operator must see: it
    /// reaches the hand-off (which counts it) and yields neither a queued job nor a sample.
    #[tokio::test]
    async fn a_shell_capture_starved_to_zero_bytes_counts_a_refusal_and_stores_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let budget = Arc::new(CaptureMemoryBudget::new(
            sensor_framework::CAPTURE_CHUNK_BYTES,
        ));
        let handoff = Arc::new(CaptureHandoff::new(
            QuarantineSpool::new(spool_dir, 10_000_000, 100_000_000),
            EventEmitter::new(dir.path().join("events.jsonl")),
            1,
            "test".to_string(),
            OutboxManifest::new(dir.path().join("outbox")),
            budget.clone(),
        ));
        let _hog = budget
            .try_reserve(sensor_framework::CAPTURE_CHUNK_BYTES)
            .unwrap();

        let mut shell_capture = capture(handoff.clone());
        shell_capture.push(b"\x7fELF-payload-bytes");
        shell_capture.flag_binary();
        assert!(shell_capture.body.is_empty() && shell_capture.body.is_exhausted());
        drop(shell_capture);

        assert_eq!(handoff.refused_capture_count(), 1);
        assert_eq!(handoff.truncated_capture_count(), 0);
        assert_eq!(handoff.dropped_count(), 0);
        assert!(
            handoff.submit(probe_job()).is_ok(),
            "nothing was queued, so the one slot is still free"
        );
    }

    /// An ordinary interactive session is never spooled, and the capture stays inside the
    /// operator-configured ceiling.
    #[tokio::test]
    async fn a_plaintext_session_submits_nothing_and_the_buffer_is_bounded() {
        let handoff = one_slot_handoff();
        let mut shell_capture = capture(handoff.clone());
        shell_capture.push(b"uname -a\n");
        drop(shell_capture);
        assert!(
            handoff.submit(probe_job()).is_ok(),
            "no binary flood, so nothing was submitted"
        );

        let mut bounded = capture(one_slot_handoff());
        bounded.max_bytes = 8;
        bounded.push(b"0123456789abcdef");
        assert_eq!(bounded.body.len(), 8, "the ceiling bounds the buffer");
    }
}
