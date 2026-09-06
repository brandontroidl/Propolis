//! Per-connection Redis session handler: dispatches parsed RESP commands to canned responses,
//! captures credentials and suspicious commands as indicators, and drives the socket I/O loop.
//! See `internal/design/08-remaining-sensors.md`'s "sensor-redis" section for the protocol flow
//! this composes and `resp.rs` for the wire parsing/encoding it drives.
//!
//! Split mirrors sensor-telnet's `handler.rs` and sensor-ssh's `auth.rs`: [`Session::dispatch`]
//! and its per-command handlers are pure functions of `(state, args) -> (reply bytes, events)`
//! with no `TcpStream` of their own, so they are unit-tested directly below with no live socket.
//! [`handle_connection`] is the only function in this crate that touches an actual `TcpStream`;
//! it is exercised end-to-end by `tests/integration.rs` instead.
//!
//! **This sensor never actually authenticates or persists anything.** `AUTH` always succeeds (a
//! real unauthenticated Redis instance behaves the same way - the point is to let the attacker
//! proceed and reveal intent, matching sensor-ssh/telnet's own "accept everything" convention).
//! `SET` stores the value in a small per-session map and `GET` reads it back, so the ordinary
//! write-then-read check an attacker's tooling makes (`SET foo bar` / `GET foo`) sees a
//! consistent server; it used to answer nil to every GET, which contradicted the `+OK` two
//! commands earlier. The map is session-scoped and capped (`MAX_KEYS`); nothing persists between
//! connections and nothing behind it is real.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, Uuid, WanResolver, persona};
use sensor_wire::{
    PROTO_TCP, SIGNAL_HONEYPOT_COMMAND_EXEC, SIGNAL_HONEYPOT_CONNECTION,
    SIGNAL_HONEYPOT_LOGIN_ATTEMPT, SensorEvent, WIRE_VERSION,
};

use crate::resp;

/// This sensor's identity on both the wire `sensor` field and every event's
/// `metadata.protocol_label` - see the design spec's "protocol_label: redis" / "sensor name:
/// redis".
const PROTOCOL_LABEL: &str = "redis";

/// Cap applied to a short attacker-controlled field embedded in metadata (a key name, a CONFIG
/// param, a SLAVEOF host/port token) - matches sensor-ssh's `auth::MAX_METADATA_STRING_LEN` /
/// sensor-telnet's `handler::MAX_USERNAME_LEN` convention.
const MAX_METADATA_STRING_LEN: usize = 255;

/// Cap applied to a longer attacker-controlled value (a SET value, an EVAL script) - matches
/// `sensor_framework::shell::MAX_COMMAND_LEN`'s convention of a generous, fixed bound on a value
/// that isn't just a short identifier.
const MAX_VALUE_LEN: usize = 1024;

/// Size of each individual raw socket read, matching sensor-telnet's `READ_CHUNK_SIZE`
/// convention: deliberately small and fixed, unrelated to `bounds.max_captured_bytes` (which
/// bounds the whole session).
const READ_CHUNK_SIZE: usize = 1024;

/// The `honeypot_connection` event: emitted once, immediately after accept, before any RESP
/// command is read - `authenticated = false` unconditionally, regardless of what an `AUTH` later
/// in the session does.
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

/// Redis's exact unknown-command error: the ORIGINAL-case command name, then each following
/// argument quoted, e.g. `unknown command 'FoO', with args beginning with: 'a', 'b', `. The old
/// reply uppercased the name and dropped the args clause entirely, which is a one-probe tell. Args
/// are sanitized and length-bounded so an attacker-controlled arg cannot break RESP error framing.
fn unknown_command_error(args: &[String]) -> String {
    let mut msg = format!(
        "ERR unknown command '{}', with args beginning with: ",
        sanitize_value(&args[0], 128)
    );
    for a in args.iter().skip(1).take(20) {
        msg.push('\'');
        msg.push_str(&sanitize_value(a, 128));
        msg.push_str("', ");
    }
    msg
}

/// A fresh 40-hex id, as Redis mints for `run_id` / `master_replid` on every boot.
fn random_hex40() -> String {
    let bytes: [u8; 20] = rand::random();
    let mut s = String::with_capacity(40);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// Minted ONCE per process. A real Redis assigns run_id/master_replid a random 40-hex value at
// startup that is then stable for the life of the process; the old canned INFO had no run_id at
// all (and every other value frozen), which a one-line INFO probe flags instantly. Process start
// is captured so uptime advances instead of sitting at a constant 3600.
static RUN_ID: LazyLock<String> = LazyLock::new(random_hex40);
static REPL_ID: LazyLock<String> = LazyLock::new(random_hex40);
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// `INFO` reply body: a Redis 7.2.4 standalone master formatted as INFO's real `# Section` /
/// `key:value` layout. The identity/liveness fields that a scanner keys on are dynamic - a
/// per-process `run_id`/`master_replid`, an advancing `uptime`, the real `process_id`, and the OS
/// line sourced from the shared persona - so the reply is not the byte-identical frozen stub the
/// audit flagged. The remaining counters are plausible constants (this trap holds no real data).
fn canned_info() -> String {
    let uptime = PROCESS_START.elapsed().as_secs();
    let uptime_days = uptime / 86_400;
    let pid = std::process::id();
    let now_usec = chrono::Utc::now().timestamp_micros();
    let save_time = chrono::Utc::now().timestamp();
    let os = format!("Linux {} {}", persona::KERNEL_RELEASE, persona::ARCH);
    let run_id = &*RUN_ID;
    let repl_id = &*REPL_ID;
    format!(
        "# Server\r\n\
         redis_version:7.2.4\r\n\
         redis_git_sha1:00000000\r\n\
         redis_git_dirty:0\r\n\
         redis_build_id:a5f6e8c0b3d21947\r\n\
         redis_mode:standalone\r\n\
         os:{os}\r\n\
         arch_bits:64\r\n\
         monotonic_clock:POSIX clock_gettime\r\n\
         multiplexing_api:epoll\r\n\
         atomicvar_api:c11-builtin\r\n\
         process_id:{pid}\r\n\
         process_supervised:no\r\n\
         run_id:{run_id}\r\n\
         tcp_port:6379\r\n\
         server_time_usec:{now_usec}\r\n\
         uptime_in_seconds:{uptime}\r\n\
         uptime_in_days:{uptime_days}\r\n\
         hz:10\r\n\
         configured_hz:10\r\n\
         lru_clock:0\r\n\
         executable:/usr/bin/redis-server\r\n\
         config_file:/etc/redis/redis.conf\r\n\
         io_threads_active:0\r\n\
         \r\n\
         # Clients\r\n\
         connected_clients:1\r\n\
         cluster_connections:0\r\n\
         maxclients:10000\r\n\
         client_recent_max_input_buffer:20480\r\n\
         client_recent_max_output_buffer:0\r\n\
         blocked_clients:0\r\n\
         tracking_clients:0\r\n\
         pubsub_clients:0\r\n\
         watching_clients:0\r\n\
         clients_in_timeout_table:0\r\n\
         total_blocking_keys:0\r\n\
         \r\n\
         # Memory\r\n\
         used_memory:1048576\r\n\
         used_memory_human:1.00M\r\n\
         used_memory_rss:12582912\r\n\
         used_memory_rss_human:12.00M\r\n\
         used_memory_peak:1150976\r\n\
         used_memory_peak_human:1.10M\r\n\
         used_memory_lua:0\r\n\
         used_memory_scripts:0\r\n\
         number_of_cached_scripts:0\r\n\
         maxmemory:0\r\n\
         maxmemory_human:0B\r\n\
         maxmemory_policy:noeviction\r\n\
         mem_fragmentation_ratio:12.00\r\n\
         mem_allocator:jemalloc-5.3.0\r\n\
         \r\n\
         # Persistence\r\n\
         loading:0\r\n\
         async_loading:0\r\n\
         rdb_changes_since_last_save:0\r\n\
         rdb_bgsave_in_progress:0\r\n\
         rdb_last_save_time:{save_time}\r\n\
         rdb_last_bgsave_status:ok\r\n\
         aof_enabled:0\r\n\
         aof_last_bgrewrite_status:ok\r\n\
         aof_last_write_status:ok\r\n\
         \r\n\
         # Stats\r\n\
         total_connections_received:1\r\n\
         total_commands_processed:1\r\n\
         instantaneous_ops_per_sec:0\r\n\
         total_net_input_bytes:31\r\n\
         total_net_output_bytes:0\r\n\
         rejected_connections:0\r\n\
         sync_full:0\r\n\
         expired_keys:0\r\n\
         evicted_keys:0\r\n\
         keyspace_hits:0\r\n\
         keyspace_misses:0\r\n\
         pubsub_channels:0\r\n\
         pubsub_patterns:0\r\n\
         latest_fork_usec:0\r\n\
         total_forks:0\r\n\
         \r\n\
         # Replication\r\n\
         role:master\r\n\
         connected_slaves:0\r\n\
         master_failover_state:no-failover\r\n\
         master_replid:{repl_id}\r\n\
         master_replid2:0000000000000000000000000000000000000000\r\n\
         master_repl_offset:0\r\n\
         second_repl_offset:-1\r\n\
         repl_backlog_active:0\r\n\
         repl_backlog_size:1048576\r\n\
         \r\n\
         # CPU\r\n\
         used_cpu_sys:0.100000\r\n\
         used_cpu_user:0.080000\r\n\
         used_cpu_sys_children:0.000000\r\n\
         used_cpu_user_children:0.000000\r\n\
         \r\n\
         # Cluster\r\n\
         cluster_enabled:0\r\n\
         \r\n\
         # Keyspace\r\n"
    )
}

/// Canned `CONFIG GET *` reply: a small, plausible flat key/value array (real Redis returns
/// alternating parameter-name/value bulk strings for a `CONFIG GET` match).
fn canned_config_get() -> Vec<u8> {
    resp::array_of_bulk_strings(&[
        "maxmemory",
        "0",
        "maxmemory-policy",
        "noeviction",
        "save",
        "3600 1 300 100 60 10000",
        "appendonly",
        "no",
    ])
}

/// Per-connection RESP session state: just enough to track whether this connection has issued a
/// (always-accepted) `AUTH` yet, and the connection attributes every emitted event carries. See
/// the module doc for why there is no real credential or key/value store behind any of this.
pub struct Session {
    source_ip: IpAddr,
    wan_ip: Option<IpAddr>,
    session_id: Uuid,
    authenticated: bool,
    /// Values SET this session, read back by GET, stored whole. Bounded by `MAX_KEYS` entries
    /// and `MAX_STORE_BYTES` in total, so a connection cannot grow the process without limit.
    keys: HashMap<String, String>,
    /// Bytes of keys and values currently held, against `MAX_STORE_BYTES`.
    store_bytes: usize,
}

/// Distinct keys, and total key+value bytes, one session may hold. A SET that would exceed
/// either is refused with the error a real instance gives when it is out of memory under its
/// `noeviction` policy; acknowledging the write and then dropping or cutting it was the same
/// contradiction as the old always-nil GET, just moved to the limit.
const MAX_KEYS: usize = 256;
const MAX_STORE_BYTES: usize = 1024 * 1024;
const OOM_REPLY: &str = "OOM command not allowed when used memory > 'maxmemory'.";

impl Session {
    /// `source_ip`/`wan_ip` are this connection's real attributes; every event this type ever
    /// emits carries them verbatim, matching sensor-ssh's `AuthState::new` convention.
    pub fn new(source_ip: IpAddr, wan_ip: Option<IpAddr>, session_id: Uuid) -> Self {
        Self {
            source_ip,
            wan_ip,
            session_id,
            authenticated: false,
            keys: HashMap::new(),
            store_bytes: 0,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Build one event carrying this session's connection attributes. `authenticated` is passed
    /// explicitly rather than always reading `self.authenticated`: `AUTH`'s own login-attempt
    /// event must be `true` (the fact just happened, regardless of what `self.authenticated` was
    /// a moment ago), while every other event mirrors the session's current state, matching the
    /// wire contract's signal-type mapping table ("Command captured -> authenticated: true (or
    /// false if no auth)").
    fn build_event(
        &self,
        signal_type: &str,
        authenticated: bool,
        metadata: serde_json::Value,
    ) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.source_ip,
            wan_ip: self.wan_ip,
            sensor: PROTOCOL_LABEL.to_string(),
            signal_type: signal_type.to_string(),
            protocol: PROTO_TCP.to_string(),
            authenticated,
            observed_at: chrono::Utc::now(),
            metadata,
            sample: None,
            session_id: Some(self.session_id),
            occurrence_id: None,
        }
    }

    /// Dispatch one already-parsed, non-empty command to its handler, returning the raw RESP
    /// reply bytes to write back to the socket and any events to emit. The command name is
    /// matched case-insensitively (real Redis clients send both `PING` and `ping`). Panics if
    /// `args` is empty - the only caller, `RespReader::read_command`'s loop, already filters
    /// empty parses out before returning `ReadOutcome::Command`.
    pub fn dispatch(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        let cmd = args[0].to_ascii_uppercase();
        match cmd.as_str() {
            // Real Redis PING echoes its optional message (as a bulk string) and errors on excess
            // arity; a bare PING is +PONG.
            "PING" => match args.len() {
                1 => (resp::simple_string("PONG"), vec![]),
                2 => (resp::bulk_string(&args[1]), vec![]),
                _ => (
                    resp::error_reply("ERR wrong number of arguments for 'ping' command"),
                    vec![],
                ),
            },
            "AUTH" => self.handle_auth(args),
            "INFO" => (resp::bulk_string(&canned_info()), vec![]),
            "CONFIG" => self.handle_config(args),
            "SET" => self.handle_set(args),
            "GET" => self.handle_get(args),
            "SLAVEOF" | "REPLICAOF" => self.handle_replicaof(&cmd, args),
            "EVAL" | "SCRIPT" => self.handle_eval(&cmd, args),
            _ => (resp::error_reply(&unknown_command_error(args)), vec![]),
        }
    }

    /// `AUTH <password>` or the Redis 6+ ACL form `AUTH <username> <password>`. Every offered
    /// credential is accepted - see the module doc for why - and neither argument is ever placed
    /// in `metadata` or anywhere else: they live only in this call's local `args` slice, owned by
    /// the read loop's per-command buffer, and are dropped when this function returns. Mirrors
    /// sensor-telnet's `_password` / sensor-ssh's `_password` local-binding convention.
    fn handle_auth(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        if args.len() != 2 && args.len() != 3 {
            return (
                resp::error_reply("ERR wrong number of arguments for 'auth' command"),
                vec![],
            );
        }
        self.authenticated = true;
        let event = self.build_event(
            SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
            true,
            serde_json::json!({ "protocol_label": PROTOCOL_LABEL }),
        );
        (resp::simple_string("OK"), vec![event])
    }

    /// `CONFIG GET ...` / `CONFIG SET ...`. Only these two subcommands are emulated, matching the
    /// design spec's enumerated command set; anything else is refused like a real unrecognized
    /// subcommand would be.
    fn handle_config(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        let Some(sub) = args.get(1) else {
            return (
                resp::error_reply("ERR wrong number of arguments for 'config' command"),
                vec![],
            );
        };
        match sub.to_ascii_uppercase().as_str() {
            "GET" => (canned_config_get(), vec![]),
            "SET" => self.handle_config_set(args),
            other => (
                resp::error_reply(&format!("ERR Unknown CONFIG subcommand '{other}'")),
                vec![],
            ),
        }
    }

    /// `CONFIG SET <param> <value>`. Always replies `+OK` (this sensor has no real config to
    /// mutate), but only `dir`/`dbfilename` emit an indicator event: those two are the classic
    /// Redis RCE staging primitive (point the RDB save directory and filename at a web root, then
    /// `SET` a payload and `SAVE`) - see the design spec's "log as indicator (filesystem write
    /// attempt)". Any other param is accepted silently, matching real Redis's own breadth of
    /// harmless `CONFIG SET` targets.
    fn handle_config_set(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        if args.len() < 4 {
            return (
                resp::error_reply("ERR wrong number of arguments for 'config|set' command"),
                vec![],
            );
        }
        let param_lower = args[2].to_ascii_lowercase();
        let mut events = Vec::new();
        if param_lower == "dir" || param_lower == "dbfilename" {
            let param = sanitize_value(&args[2], MAX_METADATA_STRING_LEN);
            let value = sanitize_value(&args[3], MAX_VALUE_LEN);
            events.push(self.build_event(
                SIGNAL_HONEYPOT_COMMAND_EXEC,
                self.authenticated,
                serde_json::json!({
                    "protocol_label": PROTOCOL_LABEL,
                    "command": "CONFIG SET",
                    "param": param,
                    "value": value,
                }),
            ));
        }
        (resp::simple_string("OK"), events)
    }

    /// `SET <key> <value>`. Always replies `+OK` without actually storing anything (see the
    /// module doc); the key and value are captured as indicators, sanitized through
    /// `sanitize_value` before they can reach the event record.
    fn handle_set(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        if args.len() < 3 {
            return (
                resp::error_reply("ERR wrong number of arguments for 'set' command"),
                vec![],
            );
        }
        let key = sanitize_value(&args[1], MAX_METADATA_STRING_LEN);
        let value = sanitize_value(&args[2], MAX_VALUE_LEN);
        let event = self.build_event(
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            self.authenticated,
            serde_json::json!({
                "protocol_label": PROTOCOL_LABEL,
                "command": "SET",
                "key": key,
                "value": value,
            }),
        );
        // Keep the raw value whole so GET hands back exactly what was SET; the sanitized copy
        // above is for the ledger only. A write the store cannot hold is refused, never cut or
        // silently dropped behind an +OK. The attempt is still evidence, so the event stands.
        let previous = self
            .keys
            .get(&args[1])
            .map_or(0, |v| args[1].len() + v.len());
        let incoming = args[1].len() + args[2].len();
        let new_key = !self.keys.contains_key(&args[1]);
        let after = self.store_bytes - previous + incoming;
        if (new_key && self.keys.len() >= MAX_KEYS) || after > MAX_STORE_BYTES {
            return (resp::error_reply(OOM_REPLY), vec![event]);
        }
        self.keys.insert(args[1].clone(), args[2].clone());
        self.store_bytes = after;
        (resp::simple_string("OK"), vec![event])
    }

    /// `GET <key>`: the value SET earlier this session, else nil. No event: the design spec lists
    /// an event only for the write side (`SET`), not this read side.
    fn handle_get(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        if args.len() != 2 {
            return (
                resp::error_reply("ERR wrong number of arguments for 'get' command"),
                vec![],
            );
        }
        let reply = match self.keys.get(&args[1]) {
            Some(value) => resp::bulk_string(value),
            None => resp::nil_bulk_string(),
        };
        (reply, vec![])
    }

    /// `SLAVEOF <host> <port>` / `REPLICAOF <host> <port>` (or `REPLICAOF NO ONE` to detach).
    /// Always replies `+OK`; every trailing argument is captured as a sanitized indicator - an
    /// attacker pointing this instance at a host they control is the signal, regardless of the
    /// specific host/port offered.
    fn handle_replicaof(&mut self, cmd: &str, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        let captured_args: Vec<String> = args[1..]
            .iter()
            .map(|a| sanitize_value(a, MAX_METADATA_STRING_LEN))
            .collect();
        let event = self.build_event(
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            self.authenticated,
            serde_json::json!({
                "protocol_label": PROTOCOL_LABEL,
                "command": cmd,
                "args": captured_args,
            }),
        );
        (resp::simple_string("OK"), vec![event])
    }

    /// `EVAL <script> <numkeys> [keys...] [args...]` / `SCRIPT <subcommand> ...`. Never actually
    /// runs any Lua (this sensor executes nothing - see the crate-wide `never_exec_static_check`
    /// in `tests/integration.rs`); replies a plausible compile-style error while capturing every
    /// trailing argument (the script body included) as a sanitized indicator.
    fn handle_eval(&mut self, cmd: &str, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        let captured_args: Vec<String> = args[1..]
            .iter()
            .map(|a| sanitize_value(a, MAX_VALUE_LEN))
            .collect();
        let event = self.build_event(
            SIGNAL_HONEYPOT_COMMAND_EXEC,
            self.authenticated,
            serde_json::json!({
                "protocol_label": PROTOCOL_LABEL,
                "command": cmd,
                "args": captured_args,
            }),
        );
        let response = resp::error_reply(
            "ERR Error compiling script (new function): user_script:1: unexpected symbol",
        );
        (response, vec![event])
    }
}

/// Handle one accepted Redis connection end to end: emit `honeypot_connection`, then read and
/// dispatch RESP commands in a loop until the peer disconnects, times out, exceeds its capture
/// budget, or sends a structurally invalid command. Never panics and never propagates an I/O
/// error to the caller - matches `sensor_framework::run_tcp_listener`'s per-connection isolation
/// contract (see sensor-telnet's `handle_connection` doc for the same guarantee).
pub async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    session_id: Uuid,
    emitter: Arc<EventEmitter>,
    wan_resolver: Arc<WanResolver>,
    bounds: ConnectionBounds,
) {
    let norm_peer = normalize_dual_stack(peer_addr);
    let source_ip: IpAddr = norm_peer.ip();
    let wan_ip = stream
        .local_addr()
        .ok()
        .map(normalize_dual_stack)
        .and_then(|local| wan_resolver.resolve(local.ip()));

    let conn_event = connection_event(source_ip, wan_ip, session_id);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "redis: failed to append connection event");
    }

    let mut session = Session::new(source_ip, wan_ip, session_id);
    let mut reader = RespReader::new(bounds);

    loop {
        match reader.read_command(&mut stream).await {
            ReadOutcome::Command(args) => {
                let (response, events) = session.dispatch(&args);
                for event in &events {
                    if emitter.append(event).await.is_err() {
                        tracing::error!(%peer_addr, "redis: failed to append command event");
                    }
                }
                if stream.write_all(&response).await.is_err() {
                    return;
                }
            }
            ReadOutcome::ProtocolError => {
                let _ = stream
                    .write_all(&resp::error_reply("ERR Protocol error"))
                    .await;
                return;
            }
            ReadOutcome::Closed => return,
        }
    }
}

/// Outcome of one [`RespReader::read_command`] call.
enum ReadOutcome {
    /// One non-empty command, ready to dispatch.
    Command(Vec<String>),
    /// The buffered bytes could never be valid RESP - `handle_connection` writes a protocol-error
    /// reply and ends the session.
    ProtocolError,
    /// EOF, a read error, a timeout, or the session's `max_captured_bytes` budget was exhausted -
    /// any of which end the session with no further reply.
    Closed,
}

/// Buffered RESP command reader. One instance per connection; `bounds` governs every individual
/// socket read the same way `sensor_telnet::handler::LineReader` does: `read_timeout` bounds the
/// wait for the very first byte of the whole session, `idle_timeout` bounds every read after
/// that, and a running total checked against `max_captured_bytes` bounds the whole session's
/// captured input regardless of how many commands it spans.
struct RespReader {
    /// Bytes read off the socket but not yet consumed by a complete, dispatched command.
    buf: Vec<u8>,
    bounds: ConnectionBounds,
    first_read: bool,
    total_captured: u64,
}

impl RespReader {
    fn new(bounds: ConnectionBounds) -> Self {
        Self {
            buf: Vec::new(),
            bounds,
            first_read: true,
            total_captured: 0,
        }
    }

    async fn read_command(&mut self, stream: &mut TcpStream) -> ReadOutcome {
        loop {
            match resp::parse_command(&self.buf) {
                Ok(resp::ParseOutcome::Complete { args, consumed }) => {
                    self.buf.drain(..consumed);
                    if args.is_empty() {
                        continue; // blank inline line / zero-count array: not a command.
                    }
                    return ReadOutcome::Command(args);
                }
                Ok(resp::ParseOutcome::Incomplete) => {}
                Err(resp::RespError::Protocol(_)) => return ReadOutcome::ProtocolError,
            }

            if self.total_captured >= self.bounds.max_captured_bytes {
                return ReadOutcome::Closed;
            }

            let per_read_timeout = if self.first_read {
                self.bounds.read_timeout
            } else {
                self.bounds.idle_timeout
            };

            let mut chunk = [0u8; READ_CHUNK_SIZE];
            let n = match tokio::time::timeout(per_read_timeout, stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return ReadOutcome::Closed,
                Ok(Ok(n)) => n,
            };
            self.first_read = false;
            self.total_captured += n as u64;
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    fn metadata_object(event: &SensorEvent) -> &serde_json::Map<String, serde_json::Value> {
        event
            .metadata
            .as_object()
            .expect("metadata must be an object")
    }

    // ---------------------------------------------------------------------------------------
    // connection_event
    // ---------------------------------------------------------------------------------------

    #[test]
    fn connection_event_is_unauthenticated_with_redis_label() {
        let event = connection_event(ip("203.0.113.7"), None, Uuid::now_v7());
        assert!(!event.authenticated);
        assert_eq!(event.sensor, "redis");
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_CONNECTION);
        assert_eq!(event.protocol, PROTO_TCP);
        assert_eq!(event.v, WIRE_VERSION);
        assert_eq!(event.sample, None);
        assert_eq!(
            event
                .metadata
                .get("protocol_label")
                .and_then(|v| v.as_str()),
            Some("redis")
        );
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - PING
    // ---------------------------------------------------------------------------------------

    #[test]
    fn ping_replies_pong_with_no_events() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["PING"]));
        assert_eq!(response, resp::simple_string("PONG"));
        assert!(events.is_empty());
    }

    #[test]
    fn command_dispatch_is_case_insensitive() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, _events) = session.dispatch(&args(&["ping"]));
        assert_eq!(response, resp::simple_string("PONG"));
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - AUTH
    // ---------------------------------------------------------------------------------------

    #[test]
    fn auth_replies_ok_and_sets_authenticated() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        assert!(!session.is_authenticated());
        let (response, events) = session.dispatch(&args(&["AUTH", "hunter2"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert!(session.is_authenticated());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signal_type, SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
        assert!(events[0].authenticated);
        assert_eq!(events[0].sensor, "redis");
    }

    #[test]
    fn auth_password_never_appears_in_event_metadata() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (_response, events) = session.dispatch(&args(&["AUTH", "SuperSecretPassword123"]));
        let event_json = serde_json::to_string(&events[0]).unwrap();
        assert!(!event_json.contains("SuperSecretPassword123"));
        // Stronger than a substring check: no key in metadata even names a credential field, so a
        // future field addition to `SensorEvent` cannot silently reintroduce a captured value.
        let obj = metadata_object(&events[0]);
        assert!(!obj.contains_key("password"));
        assert!(!obj.contains_key("credential"));
    }

    #[test]
    fn auth_missing_password_argument_is_error_and_no_event() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["AUTH"]));
        assert!(response.starts_with(b"-"), "expected an error reply");
        assert!(events.is_empty());
        assert!(!session.is_authenticated());
    }

    #[test]
    fn auth_accepts_acl_style_username_and_password() {
        // Redis 6+'s `AUTH <username> <password>` form - both dropped identically to the
        // single-password form.
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["AUTH", "default", "hunter2"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert_eq!(events.len(), 1);
        let obj = metadata_object(&events[0]);
        assert!(!obj.contains_key("password"));
        assert!(!obj.contains_key("username"));
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - INFO / CONFIG GET
    // ---------------------------------------------------------------------------------------

    #[test]
    fn info_returns_canned_bulk_string_with_no_events() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["INFO"]));
        assert!(response.starts_with(b"$"), "INFO must reply a bulk string");
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("redis_version"));
        assert!(text.contains("Linux"));
        assert!(events.is_empty());
    }

    #[test]
    fn config_get_returns_array_with_no_events() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["CONFIG", "GET", "*"]));
        assert!(response.starts_with(b"*"), "CONFIG GET must reply an array");
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - SET / GET
    // ---------------------------------------------------------------------------------------

    #[test]
    fn set_replies_ok_and_emits_command_exec_with_key_and_value() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["SET", "foo", "bar"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(
            event.metadata.get("command").and_then(|v| v.as_str()),
            Some("SET")
        );
        assert_eq!(
            event.metadata.get("key").and_then(|v| v.as_str()),
            Some("foo")
        );
        assert_eq!(
            event.metadata.get("value").and_then(|v| v.as_str()),
            Some("bar")
        );
    }

    #[test]
    fn set_command_exec_authenticated_field_reflects_session_state() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (_r, events) = session.dispatch(&args(&["SET", "foo", "bar"]));
        assert!(
            !events[0].authenticated,
            "SET before AUTH must be authenticated=false"
        );

        session.dispatch(&args(&["AUTH", "pw"]));
        let (_r, events) = session.dispatch(&args(&["SET", "foo", "bar"]));
        assert!(
            events[0].authenticated,
            "SET after AUTH must be authenticated=true"
        );
    }

    #[test]
    fn set_wrong_arity_is_error_and_no_event() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["SET", "onlykey"]));
        assert!(response.starts_with(b"-"));
        assert!(events.is_empty());
    }

    #[test]
    fn set_value_containing_crlf_is_sanitized_in_metadata() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (_response, events) = session.dispatch(&args(&[
            "SET",
            "key",
            "evil\r\n{\"signal_type\":\"forged\"}",
        ]));
        let value = events[0]
            .metadata
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(!value.contains('\r'));
        assert!(!value.contains('\n'));
    }

    #[test]
    fn get_of_a_key_never_set_is_nil_and_emits_nothing() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["GET", "foo"]));
        assert_eq!(response, resp::nil_bulk_string());
        assert!(
            events.is_empty(),
            "GET must never emit an event per the design spec"
        );
    }

    /// `SET foo bar` then `GET foo` is the ordinary write-then-read check; answering `+OK` and
    /// then nil two commands later contradicted the server within one session.
    #[test]
    fn get_after_set_returns_the_value_within_the_session() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        session.dispatch(&args(&["SET", "foo", "bar"]));
        let (response, _events) = session.dispatch(&args(&["GET", "foo"]));
        assert_eq!(response, resp::bulk_string("bar"));
        // Overwrite is visible too.
        session.dispatch(&args(&["SET", "foo", "baz"]));
        assert_eq!(
            session.dispatch(&args(&["GET", "foo"])).0,
            resp::bulk_string("baz")
        );
        // Nothing persists across connections: a new session starts empty.
        let mut fresh = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        assert_eq!(
            fresh.dispatch(&args(&["GET", "foo"])).0,
            resp::nil_bulk_string()
        );
    }

    /// A write the store cannot hold is refused with Redis's own out-of-memory error, never
    /// acknowledged and then dropped or cut: the reply and a later GET must agree.
    #[test]
    fn a_set_past_the_key_cap_is_refused_not_silently_dropped() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        for i in 0..MAX_KEYS {
            let key = format!("k{i}");
            assert_eq!(
                session.dispatch(&args(&["SET", &key, "v"])).0,
                resp::simple_string("OK")
            );
        }
        let (reply, events) = session.dispatch(&args(&["SET", "one-too-many", "v"]));
        assert_eq!(reply, resp::error_reply(OOM_REPLY));
        assert_eq!(events.len(), 1, "the attempt is still recorded");
        assert_eq!(
            session.dispatch(&args(&["GET", "one-too-many"])).0,
            resp::nil_bulk_string()
        );
        // A key already held can still be overwritten at the cap.
        assert_eq!(
            session.dispatch(&args(&["SET", "k0", "new"])).0,
            resp::simple_string("OK")
        );
        assert_eq!(
            session.dispatch(&args(&["GET", "k0"])).0,
            resp::bulk_string("new")
        );
    }

    #[test]
    fn a_value_is_stored_whole_and_a_write_past_the_byte_budget_is_refused() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let big = "x".repeat(1025);
        assert_eq!(
            session.dispatch(&args(&["SET", "big", &big])).0,
            resp::simple_string("OK")
        );
        assert_eq!(
            session.dispatch(&args(&["GET", "big"])).0,
            resp::bulk_string(&big),
            "GET returns all 1025 bytes, not a cut copy"
        );
        let huge = "y".repeat(MAX_STORE_BYTES);
        assert_eq!(
            session.dispatch(&args(&["SET", "huge", &huge])).0,
            resp::error_reply(OOM_REPLY)
        );
        assert_eq!(
            session.dispatch(&args(&["GET", "huge"])).0,
            resp::nil_bulk_string()
        );
        // The refused write did not disturb what was already held.
        assert_eq!(
            session.dispatch(&args(&["GET", "big"])).0,
            resp::bulk_string(&big)
        );
    }

    #[test]
    fn get_wrong_arity_is_error() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, _events) = session.dispatch(&args(&["GET"]));
        assert!(response.starts_with(b"-"));
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - CONFIG SET dir/dbfilename (filesystem-write indicator)
    // ---------------------------------------------------------------------------------------

    #[test]
    fn config_set_dir_is_logged_as_indicator() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["CONFIG", "SET", "dir", "/etc/cron.d"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(
            event.metadata.get("command").and_then(|v| v.as_str()),
            Some("CONFIG SET")
        );
        assert_eq!(
            event.metadata.get("param").and_then(|v| v.as_str()),
            Some("dir")
        );
        assert_eq!(
            event.metadata.get("value").and_then(|v| v.as_str()),
            Some("/etc/cron.d")
        );
    }

    #[test]
    fn config_set_dbfilename_is_logged_as_indicator() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (_response, events) =
            session.dispatch(&args(&["CONFIG", "SET", "dbfilename", "shell.php"]));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].metadata.get("param").and_then(|v| v.as_str()),
            Some("dbfilename")
        );
    }

    #[test]
    fn config_set_dir_param_match_is_case_insensitive() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (_response, events) = session.dispatch(&args(&["CONFIG", "SET", "DIR", "/tmp/x"]));
        assert_eq!(
            events.len(),
            1,
            "CONFIG SET DIR (uppercase) must still be logged"
        );
    }

    #[test]
    fn config_set_other_param_replies_ok_without_event() {
        // Only dir/dbfilename are named as filesystem-write indicators by the design spec; a
        // benign CONFIG SET must still succeed (this sensor never really persists config either
        // way) but must not manufacture an indicator event for it.
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["CONFIG", "SET", "maxmemory", "100mb"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert!(events.is_empty());
    }

    #[test]
    fn config_unknown_subcommand_is_error() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["CONFIG", "RESETSTAT"]));
        assert!(response.starts_with(b"-"));
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - SLAVEOF / REPLICAOF
    // ---------------------------------------------------------------------------------------

    #[test]
    fn slaveof_is_logged_as_indicator() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["SLAVEOF", "198.51.100.50", "6379"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.signal_type, SIGNAL_HONEYPOT_COMMAND_EXEC);
        assert_eq!(
            event.metadata.get("command").and_then(|v| v.as_str()),
            Some("SLAVEOF")
        );
        let recorded_args: Vec<&str> = event.metadata["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(recorded_args, vec!["198.51.100.50", "6379"]);
    }

    #[test]
    fn replicaof_no_one_is_logged_with_command_name_preserved() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["REPLICAOF", "NO", "ONE"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("REPLICAOF")
        );
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - EVAL / SCRIPT
    // ---------------------------------------------------------------------------------------

    #[test]
    fn eval_replies_error_and_emits_command_exec() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&[
            "EVAL",
            "return redis.call('set', KEYS[1], ARGV[1])",
            "1",
            "k",
            "v",
        ]));
        assert!(response.starts_with(b"-"), "EVAL must reply an error");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("EVAL")
        );
    }

    #[test]
    fn script_replies_error_and_emits_command_exec() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["SCRIPT", "LOAD", "return 1"]));
        assert!(response.starts_with(b"-"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].metadata.get("command").and_then(|v| v.as_str()),
            Some("SCRIPT")
        );
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - unknown commands
    // ---------------------------------------------------------------------------------------

    #[test]
    fn unknown_command_replies_error_with_no_events() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (response, events) = session.dispatch(&args(&["FOOBARBAZ"]));
        assert!(response.starts_with(b"-ERR"));
        let text = String::from_utf8_lossy(&response);
        assert!(text.to_uppercase().contains("UNKNOWN COMMAND"));
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // protocol_label on every event kind this module can emit
    // ---------------------------------------------------------------------------------------

    #[test]
    fn every_emitted_event_carries_redis_protocol_label_and_sensor() {
        let mut session = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let mut all_events = vec![connection_event(ip("203.0.113.7"), None, Uuid::now_v7())];
        all_events.extend(session.dispatch(&args(&["AUTH", "pw"])).1);
        all_events.extend(session.dispatch(&args(&["SET", "k", "v"])).1);
        all_events.extend(session.dispatch(&args(&["CONFIG", "SET", "dir", "/tmp"])).1);
        all_events.extend(
            session
                .dispatch(&args(&["SLAVEOF", "198.51.100.50", "6379"]))
                .1,
        );
        all_events.extend(session.dispatch(&args(&["EVAL", "return 1", "0"])).1);

        assert!(!all_events.is_empty());
        for event in &all_events {
            assert_eq!(event.sensor, "redis");
            assert_eq!(event.protocol, PROTO_TCP);
            assert_eq!(
                event
                    .metadata
                    .get("protocol_label")
                    .and_then(|v| v.as_str()),
                Some("redis")
            );
        }
    }

    #[test]
    fn ping_echoes_its_argument() {
        let mut s = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        assert_eq!(
            s.dispatch(&args(&["PING"])).0,
            crate::resp::simple_string("PONG")
        );
        assert_eq!(
            s.dispatch(&args(&["PING", "hello"])).0,
            crate::resp::bulk_string("hello")
        );
    }

    #[test]
    fn unknown_command_error_keeps_case_and_lists_args() {
        // The old reply uppercased the command and dropped the args clause - both one-probe tells.
        let msg = unknown_command_error(&args(&["FooBar", "alpha", "beta"]));
        assert!(msg.contains("unknown command 'FooBar'"), "{msg}");
        assert!(
            msg.contains("with args beginning with: 'alpha', 'beta', "),
            "{msg}"
        );
    }

    #[test]
    fn info_is_live_not_a_frozen_stub() {
        let mut s = Session::new(ip("203.0.113.7"), None, Uuid::now_v7());
        let (reply, _) = s.dispatch(&args(&["INFO"]));
        let text = String::from_utf8_lossy(&reply);
        // A per-process run_id/master_replid and the real pid replace the old frozen stub, which
        // had no run_id and baked in process_id:1 / uptime_in_seconds:3600.
        assert!(text.contains("run_id:"), "INFO missing run_id");
        assert!(
            text.contains("master_replid:"),
            "INFO missing master_replid"
        );
        assert!(
            text.contains(&format!("process_id:{}", std::process::id())),
            "INFO process_id is not the real pid"
        );
    }
}
