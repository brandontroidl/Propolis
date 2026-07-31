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
//! `SET` always replies `+OK` without storing the value; `GET` always replies with a nil bulk
//! string regardless of any prior `SET` in the same session - a deliberate simplification (see
//! `get_after_set_still_returns_nil` below), not a bug: this honeypot has nothing real behind it
//! worth emulating statefully.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use sensor_framework::listener::normalize_dual_stack;
use sensor_framework::sanitize_value;
use sensor_framework::{ConnectionBounds, EventEmitter, WanResolver};
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
fn connection_event(source_ip: IpAddr, wan_ip: Option<IpAddr>) -> SensorEvent {
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
    }
}

/// Canned `INFO` reply body (see the design spec's "INFO -> canned server info"): a fake Redis
/// 7.x server on Linux with plausible memory/replication stats, formatted as INFO's real
/// `# Section` / `key:value` text layout so the reply is indistinguishable in shape from a real
/// server's.
fn canned_info() -> String {
    concat!(
        "# Server\r\n",
        "redis_version:7.2.4\r\n",
        "redis_mode:standalone\r\n",
        "os:Linux 5.15.0-91-generic x86_64\r\n",
        "arch_bits:64\r\n",
        "process_id:1\r\n",
        "tcp_port:6379\r\n",
        "uptime_in_seconds:3600\r\n",
        "\r\n",
        "# Memory\r\n",
        "used_memory:1048576\r\n",
        "used_memory_human:1.00M\r\n",
        "maxmemory:0\r\n",
        "maxmemory_policy:noeviction\r\n",
        "\r\n",
        "# Replication\r\n",
        "role:master\r\n",
        "connected_slaves:0\r\n",
        "\r\n",
        "# Clients\r\n",
        "connected_clients:1\r\n",
    )
    .to_string()
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
    authenticated: bool,
}

impl Session {
    /// `source_ip`/`wan_ip` are this connection's real attributes; every event this type ever
    /// emits carries them verbatim, matching sensor-ssh's `AuthState::new` convention.
    pub fn new(source_ip: IpAddr, wan_ip: Option<IpAddr>) -> Self {
        Self {
            source_ip,
            wan_ip,
            authenticated: false,
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
            "PING" => (resp::simple_string("PONG"), vec![]),
            "AUTH" => self.handle_auth(args),
            "INFO" => (resp::bulk_string(&canned_info()), vec![]),
            "CONFIG" => self.handle_config(args),
            "SET" => self.handle_set(args),
            "GET" => self.handle_get(args),
            "SLAVEOF" | "REPLICAOF" => self.handle_replicaof(&cmd, args),
            "EVAL" | "SCRIPT" => self.handle_eval(&cmd, args),
            _ => (
                resp::error_reply(&format!("ERR unknown command '{cmd}'")),
                vec![],
            ),
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
        (resp::simple_string("OK"), vec![event])
    }

    /// `GET <key>`. Always replies nil - see the module doc for why this is a deliberate
    /// simplification, not a bug. No event: the design spec lists an event only for the write
    /// side (`SET`), not this read side.
    fn handle_get(&mut self, args: &[String]) -> (Vec<u8>, Vec<SensorEvent>) {
        if args.len() != 2 {
            return (
                resp::error_reply("ERR wrong number of arguments for 'get' command"),
                vec![],
            );
        }
        (resp::nil_bulk_string(), vec![])
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

    let conn_event = connection_event(source_ip, wan_ip);
    if emitter.append(&conn_event).await.is_err() {
        tracing::error!(%peer_addr, "redis: failed to append connection event");
    }

    let mut session = Session::new(source_ip, wan_ip);
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
        let event = connection_event(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["PING"]));
        assert_eq!(response, resp::simple_string("PONG"));
        assert!(events.is_empty());
    }

    #[test]
    fn command_dispatch_is_case_insensitive() {
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, _events) = session.dispatch(&args(&["ping"]));
        assert_eq!(response, resp::simple_string("PONG"));
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - AUTH
    // ---------------------------------------------------------------------------------------

    #[test]
    fn auth_replies_ok_and_sets_authenticated() {
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["AUTH"]));
        assert!(response.starts_with(b"-"), "expected an error reply");
        assert!(events.is_empty());
        assert!(!session.is_authenticated());
    }

    #[test]
    fn auth_accepts_acl_style_username_and_password() {
        // Redis 6+'s `AUTH <username> <password>` form - both dropped identically to the
        // single-password form.
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["INFO"]));
        assert!(response.starts_with(b"$"), "INFO must reply a bulk string");
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("redis_version"));
        assert!(text.contains("Linux"));
        assert!(events.is_empty());
    }

    #[test]
    fn config_get_returns_array_with_no_events() {
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["CONFIG", "GET", "*"]));
        assert!(response.starts_with(b"*"), "CONFIG GET must reply an array");
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - SET / GET
    // ---------------------------------------------------------------------------------------

    #[test]
    fn set_replies_ok_and_emits_command_exec_with_key_and_value() {
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["SET", "onlykey"]));
        assert!(response.starts_with(b"-"));
        assert!(events.is_empty());
    }

    #[test]
    fn set_value_containing_crlf_is_sanitized_in_metadata() {
        let mut session = Session::new(ip("203.0.113.7"), None);
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
    fn get_always_replies_nil() {
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["GET", "foo"]));
        assert_eq!(response, resp::nil_bulk_string());
        assert!(
            events.is_empty(),
            "GET must never emit an event per the design spec"
        );
    }

    #[test]
    fn get_after_set_still_returns_nil() {
        // Deliberate simplification (see the module doc): this honeypot never actually stores
        // anything, so GET is unconditionally nil even immediately after a SET of the same key.
        let mut session = Session::new(ip("203.0.113.7"), None);
        session.dispatch(&args(&["SET", "foo", "bar"]));
        let (response, _events) = session.dispatch(&args(&["GET", "foo"]));
        assert_eq!(response, resp::nil_bulk_string());
    }

    #[test]
    fn get_wrong_arity_is_error() {
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, _events) = session.dispatch(&args(&["GET"]));
        assert!(response.starts_with(b"-"));
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - CONFIG SET dir/dbfilename (filesystem-write indicator)
    // ---------------------------------------------------------------------------------------

    #[test]
    fn config_set_dir_is_logged_as_indicator() {
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["CONFIG", "SET", "maxmemory", "100mb"]));
        assert_eq!(response, resp::simple_string("OK"));
        assert!(events.is_empty());
    }

    #[test]
    fn config_unknown_subcommand_is_error() {
        let mut session = Session::new(ip("203.0.113.7"), None);
        let (response, events) = session.dispatch(&args(&["CONFIG", "RESETSTAT"]));
        assert!(response.starts_with(b"-"));
        assert!(events.is_empty());
    }

    // ---------------------------------------------------------------------------------------
    // Session::dispatch - SLAVEOF / REPLICAOF
    // ---------------------------------------------------------------------------------------

    #[test]
    fn slaveof_is_logged_as_indicator() {
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
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
        let mut session = Session::new(ip("203.0.113.7"), None);
        let mut all_events = vec![connection_event(ip("203.0.113.7"), None)];
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
}
